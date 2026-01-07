import asyncio
import json
import os
import sys
import threading
import urllib.parse
import websockets

from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Coroutine, Self, TextIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from merkle_tree import MerkleTree

import aiosqlite
import platformdirs


class HookLogs(TextIO):
    def __init__(
        self,
        hook: Callable[[Self, str, int], Coroutine[None, None, None]],
        loop: asyncio.AbstractEventLoop,
        capture: TextIO,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        if not (capture.readable() and capture.writable()):
            raise ValueError("Capture stream must be readable and writable")
        self.capture = capture
        self.loop = loop
        self.on_write = hook
        self.write_lock = threading.Lock()
        if on_close is not None:
            self.on_close = on_close

    def write(self, data: str) -> int:
        with self.write_lock:
            self.capture.seek(0, os.SEEK_END)
            pos = self.capture.tell()
            asyncio.run_coroutine_threadsafe(self.on_write(self, data, pos), self.loop)
            return self.capture.write(data)

    def flush(self) -> None:
        with self.write_lock:
            return self.capture.flush()

    def read(self, size=-1, /) -> str:
        return self.capture.read(size)

    def close(self) -> None:
        if hasattr(self, "on_close"):
            self.on_close()
        return self.capture.close()

    def seek(self, pos: int, whence: int = 0, /):
        return self.capture.seek(pos, whence)

    def __getattr__(self, name: str):
        return getattr(self.capture, name)

    def unhook(self) -> None:
        if hasattr(self, "on_close"):
            self.on_close()


@dataclass
class LogData:
    begin_offset: int
    length: int
    nonce: bytes


def hook_logs(capture: TextIO) -> TextIO:
    ws_url = os.getenv("MERKLIN_URL")
    if ws_url is None:
        raise RuntimeError("Merklin server endpoint not configured")

    loop = asyncio.new_event_loop()

    queue: asyncio.Queue[tuple[str, LogData]] = asyncio.Queue()
    shutdown_event: asyncio.Event | None = None

    async def on_write(hook: HookLogs, data: str, pos: int) -> None:
        await queue.put((data, LogData(pos, len(data), os.urandom(12))))

    hook = HookLogs(on_write, loop, capture)

    def run_loop() -> None:
        nonlocal shutdown_event
        asyncio.set_event_loop(loop)
        shutdown_event = asyncio.Event()
        loop.run_until_complete(send_logs(queue, ws_url, hook, shutdown_event))

    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()

    def on_close() -> None:
        if shutdown_event is not None:
            loop.call_soon_threadsafe(shutdown_event.set)

    hook.on_close = on_close
    return hook


async def send_logs(
    queue: asyncio.Queue[tuple[str, LogData]],
    ws_url: str,
    hook: HookLogs,
    shutdown_event: asyncio.Event,
) -> None:

    data: list[LogData] = []
    data_lock = asyncio.Lock()
    challenge_lock = asyncio.Lock()

    aes_key = AESGCM.generate_key(bit_length=256)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()

    pem: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    base_url = f"ws://{ws_url}/log"
    query_params: dict[str, str] = {
        "token": os.environ["MERKLIN_TOKEN"],
        "public_key": pem.hex(),
    }
    encoded_params = urllib.parse.urlencode(query_params)
    complete_url = f"{base_url}?{encoded_params}"

    listener: asyncio.Task[None] | None = None

    conn: aiosqlite.Connection = await aiosqlite.connect(platformdirs.user_data_path("arthur") / "sessions.db")
    cursor = await conn.cursor()
    try:
        async with websockets.connect(complete_url) as websocket:
            listener = asyncio.create_task(
                handle_challenge(
                    websocket, hook, data, aes_key, data_lock, challenge_lock
                )
            )

            session_data = json.loads(await websocket.recv())
            if session_data.get("type") != "session_id":
                raise RuntimeError("Failed to obtain session ID from Merklin server")

            session_id: int = session_data.get("session_id")
            await cursor.execute(
                "INSERT INTO session_key (session_id, aes_key) VALUES (?, ?)",
                (session_id, aes_key),
            )
            await conn.commit()

            while True:  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
                if shutdown_event.is_set() and queue.empty():
                    break

                if challenge_lock.locked():
                    await asyncio.sleep(0.1)
                    continue

                try:
                    # Use wait_for with a timeout to check shutdown event periodically
                    log_entry, log_data = await asyncio.wait_for(
                        queue.get(), timeout=0.1
                    )
                except asyncio.TimeoutError:
                    continue

                async with data_lock:
                    data.append(log_data)
                enc_log = encrypt(aes_key, log_data.nonce, log_entry.encode())

                await cursor.execute(  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
                    "INSERT INTO log_nonce (session_id, log_id, nonce) VALUES (?, ?, ?)",
                    (session_id, len(data) - 1, log_data.nonce),
                )
                await conn.commit()

                signature = private_key.sign(
                    enc_log,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                message: dict[str, str | int] = {
                    "type": "log",
                    "data": enc_log.hex(),
                    "signature": signature.hex(),
                }
                await websocket.send(json.dumps(message))

    except websockets.exceptions.ConnectionClosed:
        print("Connection to Merklin server closed", file=sys.stderr)
        raise
    except asyncio.CancelledError:
        print("Log sending task cancelled", file=sys.stderr)
        raise
    except Exception:
        raise
    finally:
        if listener:
            listener.cancel()
        hook.unhook()


@lru_cache(maxsize=2**18)
def encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.encrypt(nonce, data, None)


async def grab_logs(
    data: list[LogData], hook: HookLogs, aes_key: bytes, data_lock: asyncio.Lock
) -> MerkleTree:
    mtree = MerkleTree()
    async with data_lock:
        data = data.copy()

    with hook.write_lock:
        for log_data in data:
            hook.seek(log_data.begin_offset)
            log = hook.read(log_data.length)
            enc_log = encrypt(aes_key, log_data.nonce, log.encode())
            mtree.add_log(enc_log)
    return mtree


async def handle_challenge(
    websocket: websockets.ClientConnection,
    hook: HookLogs,
    log_data: list[LogData],
    aes_key: bytes,
    data_lock: asyncio.Lock,
    challenge_lock: asyncio.Lock,
) -> None:
    async for message in websocket:
        data = json.loads(message)

        if data.get("type") == "error":
            description = data.get("error")

            if description is not None:
                print(f"Merklin server error: {description}", file=sys.stderr)
            else:
                print("Merklin server sent an unknown error", file=sys.stderr)

        elif data.get("type") == "challenge":
            async with challenge_lock:
                try:
                    proof: dict[str, str | list[str] | list[int] | dict[int, str]]
                    mtree = await grab_logs(log_data, hook, aes_key, data_lock)
                    if data.get("challenge_type") == "membership":
                        index = data.get("log_index")
                        membership_proof = mtree.membership_proof(index)
                        proof = {
                            "type": "proof",
                            "proof_type": "membership",
                            "proof": membership_proof,
                            "indices": [index],
                        }
                    elif data.get("challenge_type") == "consistency":
                        point1 = data.get("previous_size")
                        point2 = data.get("current_size")
                        consistency_proof = mtree.consistency_proof(point1, point2)
                        proof = {
                            "type": "proof",
                            "proof_type": "consistency",
                            "proof": consistency_proof,
                            "indices": [point1, point2],
                        }
                    else:
                        raise ValueError("Unknown challenge type")

                    await websocket.send(json.dumps(proof))
                except Exception as e:
                    await websocket.send(
                        json.dumps({"type": "error", "description": f"{e}"})
                    )
                    raise
