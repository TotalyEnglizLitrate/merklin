import asyncio
import json
import websockets
import os
from asyncio import Queue


def hook_logs(ws_url=None):
    queue: Queue = Queue(maxsize=1)

    ws_url = os.getenv("LOGGER_WS_URL")

    if ws_url is None:
        raise RuntimeError("WebSocket endpoint not configured")

    asyncio.create_task(process_logs(queue))
    asyncio.create_task(send_logs(queue, ws_url))


async def process_logs(queue: Queue):
    while True:
        log = None
        # TODO: grab logs

        # TODO: put logs into Queue
        await queue.put(log)


async def send_logs(queue: Queue, ws_url):
    try:
        async with websockets.connect(ws_url) as websocket:

            asyncio.create_task(handle_challenge(websocket))

            while True:
                log_entry = await queue.get()

                try:
                    message = {"type": "log", "data": log_entry}

                    await websocket.send(json.dumps(message))

                except (TypeError, ValueError):
                    # JSON serialization failed
                    # TODO: decide policy (drop / halt / alert)
                    break

    except websockets.exceptions.ConnectionClosed:
        # WebSocket closed by server or network
        # TODO: decide policy (halt, escalate, etc.)
        pass

    except asyncio.CancelledError:
        # Task was cancelled during shutdown
        raise

    except Exception as e:
        # Any unexpected failure
        # TODO: escalate
        pass


async def handle_challenge(websocket):
    async for message in websocket:

        # TODO: listen for challange

        # TODO: generate proof and send to server
        pass
