import asyncio
import json
import logging
import os
import sys
import threading
import urllib.parse
import websockets

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable, Coroutine, Self, TextIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from dotenv import load_dotenv

from merkle_tree import MerkleTree

import aiosqlite
import platformdirs

# Module logger - configure with logging.getLogger("arthur").setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class HookLogs(TextIO):
    def __init__(
        self,
        hook: Callable[[Self, str, int], Coroutine[None, None, None]],
        loop: asyncio.AbstractEventLoop,
        capture: TextIO,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        logger.debug("Initializing HookLogs with capture stream: %s", type(capture).__name__)
        if not (capture.readable() and capture.writable()):
            raise ValueError("Capture stream must be readable and writable")
        self.capture = capture
        self.loop = loop
        self.on_write = hook
        self.write_lock = threading.Lock()
        if on_close is not None:
            self.on_close = on_close
        logger.debug("HookLogs initialized successfully")

    def write(self, data: str) -> int:
        with self.write_lock:
            self.capture.seek(0, os.SEEK_END)
            pos = self.capture.tell()
            logger.debug("HookLogs.write: pos=%d, data_len=%d", pos, len(data))
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
        logger.debug("HookLogs.unhook called")
        if hasattr(self, "on_close"):
            self.on_close()


@dataclass
class LogData:
    begin_offset: int
    length: int
    nonce: bytes


def hook_logs(capture: TextIO) -> TextIO:
    logger.debug("hook_logs: Starting log hook setup")
    load_dotenv()
    ws_url = os.getenv("MERKLIN_URL")
    if ws_url is None:
        logger.error("MERKLIN_URL environment variable not set")
        raise RuntimeError("Merklin server endpoint not configured")
    logger.debug("hook_logs: Using Merklin URL: %s", ws_url)

    loop = asyncio.new_event_loop()
    logger.debug("hook_logs: Created new event loop")

    queue: asyncio.Queue[tuple[str, LogData]] = asyncio.Queue()
    shutdown_event: asyncio.Event | None = None

    async def on_write(hook: HookLogs, data: str, pos: int) -> None:
        logger.debug("on_write: Queueing log entry at pos=%d, len=%d", pos, len(data))
        await queue.put((data, LogData(pos, len(data), os.urandom(12))))

    hook = HookLogs(on_write, loop, capture)

    def run_loop() -> None:
        nonlocal shutdown_event
        logger.debug("run_loop: Starting event loop thread")
        asyncio.set_event_loop(loop)
        shutdown_event = asyncio.Event()
        loop.run_until_complete(send_logs(queue, ws_url, hook, shutdown_event))
        logger.debug("run_loop: Event loop completed")

    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()
    logger.debug("hook_logs: Background thread started")

    def on_close() -> None:
        logger.debug("on_close: Initiating shutdown")
        if shutdown_event is not None:
            loop.call_soon_threadsafe(shutdown_event.set)

    hook.on_close = on_close
    logger.debug("hook_logs: Hook setup complete")
    return hook


async def send_logs(
    queue: asyncio.Queue[tuple[str, LogData]],
    ws_url: str,
    hook: HookLogs,
    shutdown_event: asyncio.Event,
) -> None:
    logger.debug("send_logs: Initializing log sender")

    data: list[LogData] = []
    data_lock = asyncio.Lock()
    challenge_lock = asyncio.Lock()

    logger.debug("send_logs: Generating AES-256 key")
    aes_key = AESGCM.generate_key(bit_length=256)
    logger.debug("send_logs: Generating RSA-2048 key pair")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()

    pem: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    logger.debug("send_logs: Keys generated successfully")

    base_url = f"ws://{ws_url}/log"
    query_params: dict[str, str] = {
        "token": os.environ["MERKLIN_TOKEN"],
        "public_key": pem.hex(),
    }
    encoded_params = urllib.parse.urlencode(query_params)
    complete_url = f"{base_url}?{encoded_params}"
    logger.debug("send_logs: WebSocket URL constructed: %s", base_url)

    listener: asyncio.Task[None] | None = None

    db_data_path = platformdirs.user_data_path("arthur")
    db_data_path.mkdir(exist_ok=True, parents=True)
    logger.debug("send_logs: Database path: %s", db_data_path)

    conn: aiosqlite.Connection = await aiosqlite.connect(db_data_path / "sessions.db")
    cursor = await conn.cursor()
    await cursor.executescript((Path(__file__).parent / "init.sql").read_text())
    logger.debug("send_logs: Database initialized")
    try:
        logger.debug("send_logs: Connecting to WebSocket server")
        async with websockets.connect(complete_url) as websocket:
            logger.debug("send_logs: WebSocket connection established")

            session_data = json.loads(await websocket.recv())
            if session_data.get("type") != "session_id":
                logger.error("send_logs: Failed to obtain session ID, received: %s", session_data)
                raise RuntimeError("Failed to obtain session ID from Merklin server")

            session_id: int = session_data.get("session_id")
            logger.debug("send_logs: Received session_id=%d", session_id)

            listener = asyncio.create_task(
                handle_challenge(
                    websocket, hook, data, aes_key, data_lock, challenge_lock
                )
            )
            logger.debug("send_logs: Challenge handler task created")
            logger.debug("send_logs: Received session_id=%d", session_id)
            await cursor.execute(
                "INSERT INTO session_key (session_id, aes_key) VALUES (?, ?)",
                (session_id, aes_key),
            )
            await conn.commit()
            logger.debug("send_logs: Session key stored in database")

            logger.debug("send_logs: Entering main log processing loop")
            while True:
                if shutdown_event.is_set() and queue.empty():
                    logger.debug("send_logs: Shutdown event set and queue empty, exiting loop")
                    break

                if challenge_lock.locked():
                    logger.debug("send_logs: Challenge lock held, waiting...")
                    await asyncio.sleep(0.1)
                    continue

                try:
                    # Use wait_for with a timeout to check shutdown event periodically
                    log_entry, log_data = await asyncio.wait_for(
                        queue.get(), timeout=0.1
                    )
                except asyncio.TimeoutError:
                    continue

                logger.debug("send_logs: Processing log entry, offset=%d, len=%d", 
                            log_data.begin_offset, log_data.length)
                async with data_lock:
                    data.append(log_data)
                enc_log = encrypt(aes_key, log_data.nonce, log_entry.encode())

                await cursor.execute(
                    "INSERT INTO log_nonce (session_id, log_id, nonce) VALUES (?, ?, ?)",
                    (session_id, len(data) - 1, log_data.nonce),
                )
                await conn.commit()
                logger.debug("send_logs: Log nonce stored, log_id=%d", len(data) - 1)

                signature = private_key.sign(
                    enc_log,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                logger.debug("send_logs: Log signed, sending to server")

                message: dict[str, str | int] = {
                    "type": "log",
                    "data": enc_log.hex(),
                    "signature": signature.hex(),
                }
                await websocket.send(json.dumps(message))
                logger.debug("send_logs: Log message sent successfully")

    except websockets.exceptions.ConnectionClosed as e:
        logger.warning("send_logs: WebSocket connection closed: %s", e)
        print("Connection to Merklin server closed", file=sys.stderr)
        raise
    except asyncio.CancelledError:
        logger.debug("send_logs: Task cancelled")
        print("Log sending task cancelled", file=sys.stderr)
        raise
    except Exception as e:
        logger.exception("send_logs: Unexpected error: %s", e)
        raise
    finally:
        logger.debug("send_logs: Cleaning up resources")
        if listener:
            listener.cancel()
            logger.debug("send_logs: Challenge listener cancelled")
        hook.unhook()
        logger.debug("send_logs: Cleanup complete")


@lru_cache(maxsize=2**18)
def encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.encrypt(nonce, data, None)


async def grab_logs(
    data: list[LogData], hook: HookLogs, aes_key: bytes, data_lock: asyncio.Lock
) -> MerkleTree:
    logger.debug("grab_logs: Building Merkle tree from %d log entries", len(data))
    mtree = MerkleTree()
    async with data_lock:
        data = data.copy()

    with hook.write_lock:
        for i, log_data in enumerate(data):
            hook.seek(log_data.begin_offset)
            log = hook.read(log_data.length)
            enc_log = encrypt(aes_key, log_data.nonce, log.encode())
            mtree.add_log(enc_log)
            logger.debug("grab_logs: Added log %d to tree", i)
    logger.debug("grab_logs: Merkle tree built with %d entries", len(data))
    return mtree


async def handle_challenge(
    websocket: websockets.ClientConnection,
    hook: HookLogs,
    log_data: list[LogData],
    aes_key: bytes,
    data_lock: asyncio.Lock,
    challenge_lock: asyncio.Lock,
) -> None:
    logger.debug("handle_challenge: Starting challenge handler")
    async for message in websocket:
        data = json.loads(message)
        logger.debug("handle_challenge: Received message type=%s", data.get("type"))

        if data.get("type") == "error":
            description = data.get("error")
            logger.warning("handle_challenge: Server error: %s", description)

            if description is not None:
                print(f"Merklin server error: {description}", file=sys.stderr)
            else:
                print("Merklin server sent an unknown error", file=sys.stderr)

        elif data.get("type") == "challenge":
            challenge_type = data.get("challenge_type")
            logger.debug("handle_challenge: Processing %s challenge", challenge_type)
            async with challenge_lock:
                try:
                    proof: dict[str, str | list[str] | list[int] | dict[int, str]]
                    mtree = await grab_logs(log_data, hook, aes_key, data_lock)
                    if challenge_type == "membership":
                        index = data.get("log_index")
                        logger.debug("handle_challenge: Membership proof for index=%d", index)
                        membership_proof = mtree.membership_proof(index)
                        proof = {
                            "type": "proof",
                            "proof_type": "membership",
                            "proof": membership_proof,
                            "indices": [index],
                        }
                    elif challenge_type == "consistency":
                        point1 = data.get("previous_size")
                        point2 = data.get("current_size")
                        logger.debug("handle_challenge: Consistency proof for range [%d, %d]", 
                                    point1, point2)
                        consistency_proof = mtree.consistency_proof(point1, point2)
                        proof = {
                            "type": "proof",
                            "proof_type": "consistency",
                            "proof": consistency_proof,
                            "indices": [point1, point2],
                        }
                    else:
                        logger.error("handle_challenge: Unknown challenge type: %s", challenge_type)
                        raise ValueError("Unknown challenge type")

                    await websocket.send(json.dumps(proof))
                    logger.debug("handle_challenge: Proof sent successfully")
                except Exception as e:
                    logger.exception("handle_challenge: Error processing challenge: %s", e)
                    await websocket.send(
                        json.dumps({"type": "error", "description": f"{e}"})
                    )
                    raise
