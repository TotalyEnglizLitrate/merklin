from fastapi import FastAPI, WebSocket, WebSocketDisconnect, WebSocketException, Depends
from merkle_tree import MerkleTree

import asyncio
import json
import random

from typing import cast

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, tuple[WebSocket, MerkleTree]] = {}

    def add_connection(self, token: str, websocket: WebSocket) -> None:
        # TODO: Check if the logger is registered
        self.active_connections[token] = (websocket, MerkleTree())

    def remove_connection(self, token: str) -> None:
        self.active_connections.pop(token, None)

    def get_tree(self, token: str) -> MerkleTree | None:
        connection = self.active_connections.get(token)
        if connection:
            return connection[1]
        return None
    
    def get_websocket(self, token: str) -> WebSocket | None:
        connection = self.active_connections.get(token)
        if connection:
            return connection[0]
        return None
    
    def is_connected(self, token: str) -> bool:
        return token in self.active_connections
    


app = FastAPI(connection_manager=ConnectionManager())

async def verify_token(websocket: WebSocket) -> str:
    token = websocket.query_params.get("token")
    # TODO: Implement token verification logic with firebase
    raise NotImplementedError("Token verification not implemented")

@app.websocket("/log")
async def log_ws_endpoint(websocket: WebSocket, token: str = Depends(verify_token)):
    await websocket.accept()
    asyncio.create_task(challenge_subroutine(websocket))
    conn_manager = cast(ConnectionManager, app.connection_manager)
    conn_manager.add_connection(token, websocket)
    try:
        async for message in websocket.iter_json():
            msg_type = message.get("type")
            if msg_type == "log":
                # TODO: Handle log message
                ...
            elif msg_type == "proof":
                # TODO: verify outstanding proof
                ...
            else:
                await websocket.send_json({"error": "Unknown message type"})
    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except WebSocketException as e:
        print(f"WebSocket error: {e}")
    except json.JSONDecodeError:
        await websocket.send_json({"error": "Invalid JSON format"})



async def challenge_subroutine(websocket: WebSocket):
    while True:
        await asyncio.sleep(random.randrange(600, 1200))
        challenge_type = random.choice(["membership", "consistency"])
        challenge: dict[str, int | str]
        if challenge_type == "membership":
            # Dummy challenge for membership proof - implement random log selection
            challenge = {
                "type": "challenge",
                "challenge_type": "membership",
                "log_index": 1
            }
        else:
            # Dummy challenge for consistency proof - implement random tree size selection
            challenge = {
                "type": "challenge",
                "challenge_type": "consistency",
                "previous_size": 1,
                "current_size": 2
            }
        await websocket.send_json(challenge)