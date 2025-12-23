import asyncio
import json
import os
import sys
import threading
from asyncio import Queue
from typing import Callable, Coroutine, Literal
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import urllib.parse
import websockets


class HookLogs:
    def __init__(
        self,
        hook: Callable[[str], Coroutine[None, None, None]],
        loop: asyncio.AbstractEventLoop,
        capture: Literal["stdout", "stderr"] = "stdout",
    ) -> None:
        self.capture = capture
        self.loop = loop
        self.on_write = hook
        self.original_stream = sys.stdout if capture == "stdout" else sys.stderr

    def hook(self) -> None:
        original = self.original_stream
        loop = self.loop
        on_write = self.on_write

        class AsyncCapture:
            def write(self, data: str) -> int:
                asyncio.run_coroutine_threadsafe(on_write(data), loop)
                return original.write(data)

            def flush(self):
                return original.flush()

            def __getattr__(self, name: str):
                return getattr(original, name)

        if self.capture == "stdout":
            sys.stdout = AsyncCapture()
        else:
            sys.stderr = AsyncCapture()

    def unhook(self) -> None:
        if self.capture == "stdout":
            sys.stdout = self.original_stream
        else:
            sys.stderr = self.original_stream


def hook_logs(
    capture: Literal["stdout", "stderr"] = "stdout",
) -> Callable[[], None]:
    ws_url = os.getenv("MERKLIN_URL")
    if ws_url is None:
        raise RuntimeError("Merklin server endpoint not configured")

    loop = asyncio.new_event_loop()
    queue: Queue[str] = Queue()
    shutdown_event = asyncio.Event()

    async def on_write(data: str) -> None:
        await queue.put(data)

    hook = HookLogs(on_write, loop, capture)
    hook.hook()

    def run_loop() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_logs(queue, ws_url, hook, shutdown_event))

    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()

    def close() -> None:
        loop.call_soon_threadsafe(shutdown_event.set)
        thread.join()

    return close


async def send_logs(
    queue: Queue[str],
    ws_url: str,
    hook: HookLogs,
    shutdown_event: asyncio.Event,
) -> None:

    aes_key = AESGCM.generate_key(bit_length=256)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    base_url = f"{ws_url}/log"
    query_params = {"token": "firebase jwt", "public_key": pem.hex()}
    encoded_params = urllib.parse.urlencode(query_params)
    complete_url = f"{base_url}?{encoded_params}"

    listener: asyncio.Task[None] | None = None

    try:
        async with websockets.connect(f"{complete_url}/log") as websocket:
            listener = asyncio.create_task(handle_challenge(websocket))

            while True:
                # Check if shutdown was requested
                if shutdown_event.is_set() and queue.empty():
                    break

                try:
                    # Use wait_for with a timeout to check shutdown event periodically
                    log_entry = await asyncio.wait_for(queue.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    continue

                # AES Encryption
                aes = AESGCM(aes_key)
                nonce = os.urandom(12)
                enc_log = aes.encrypt(nonce, log_entry.encode(), None)

                # signature
                signature = private_key.sign(
                    enc_log,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                message = {
                    "type": "log",
                    "data": enc_log.hex(),
                    "signature": signature.hex(),
                }

                await websocket.send(json.dumps(message))

    except websockets.exceptions.ConnectionClosed:
        # WebSocket closed by server or network
        # TODO: decide policy (halt, escalate, etc.)
        pass

    except asyncio.CancelledError:
        # Task was cancelled during shutdown
        raise

    except Exception:
        # Any unexpected failure
        # TODO: escalate
        pass

    finally:
        if listener:
            listener.cancel()
        hook.unhook()


async def handle_challenge(websocket: websockets.ClientConnection) -> None:
    async for message in websocket:
        data = json.loads(message)

        if data.get("type") == "error":
            # TODO: handle error
            pass

        elif data.get("type") == "challenge":
            # TODO: generate proof and send to server
            pass
