from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import cryptography.exceptions

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, WebSocketException, Depends
from merkle_tree import MerkleTree

import asyncio
import json
import random

from dataclasses import dataclass
from typing import cast

from firestore_services import add_log, get_log_by_merkle_index
from firebase_admin import auth


@dataclass
class Connection:
    websocket: WebSocket
    tree: MerkleTree
    public_key: rsa.RSAPublicKey


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, Connection] = {}

    def add_connection(
        self, websocket: WebSocket, token: str, public_key: rsa.RSAPublicKey
    ) -> Connection:
        # TODO: Check if the logger is registered
        self.active_connections[token] = Connection(websocket, MerkleTree(), public_key)
        return self.active_connections[token]

    def remove_connection(self, token: str) -> None:
        self.active_connections.pop(token, None)

    def is_connected(self, token: str) -> bool:
        return token in self.active_connections


app = FastAPI(connection_manager=ConnectionManager())


async def verify_token(websocket: WebSocket) -> str:
    token = websocket.query_params.get("token")
    # TODO: Implement token verification logic with firebase
    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token["uid"]
        return uid
    except Exception as e:
        print(f"Token Verification error: {e}")


@app.websocket("/log")
async def log_ws_endpoint(
    websocket: WebSocket, public_key: str, token: str = Depends(verify_token)
):
    await websocket.accept()
    challenger = asyncio.create_task(challenge_subroutine(websocket))
    conn_manager: ConnectionManager = websocket.app.connection_manager
    connection = conn_manager.add_connection(
        websocket,
        token,
        cast(
            rsa.RSAPublicKey,
            serialization.load_pem_public_key(bytes.fromhex(public_key)),
        ),
    )
    uid = verify_token(websocket)
    counter = 0
    try:
        async for message in websocket.iter_json():
            msg_type = message.get("type")
            if msg_type == "log":
                data = message.get("log")
                signature = message.get("signature")
                if data is None or signature is None:
                    await websocket.send_json(
                        {"error": "Missing log data or signature"}
                    )
                    continue
                process_log(bytes.fromhex(data), bytes.fromhex(signature), connection)
                add_log(data.hex(), counter, uid)
                counter += 1
            elif msg_type == "proof":
                # TODO: verify outstanding proof
                # enc_log = get_log_by_merkle_index(idx)["encrypted_message"]
                ...
            else:
                await websocket.send_json({"error": "Unknown message type"})
    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except WebSocketException as e:
        print(f"WebSocket error: {e}")
    except json.JSONDecodeError:
        await websocket.send_json({"error": "Invalid JSON format"})
    except cryptography.exceptions.InvalidSignature:
        await websocket.send_json({"error": "Invalid log signature"})
    except Exception as e:
        await websocket.send_json({"error": f"Internal server error: {e}"})
    finally:
        conn_manager.remove_connection(token)
        challenger.cancel()
        try:
            await challenger
        except asyncio.CancelledError:
            pass


def process_log(data: bytes, signature: bytes, conn: Connection) -> None:
    conn.public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    conn.tree.add_log(data.hex())


async def challenge_subroutine(websocket: WebSocket):
    try:
        while True:
            await asyncio.sleep(random.randrange(600, 1200))
            challenge_type = random.choice(["membership", "consistency"])
            challenge: dict[str, int | str]
            if challenge_type == "membership":
                # Dummy challenge for membership proof - implement random log selection
                challenge = {
                    "type": "challenge",
                    "challenge_type": "membership",
                    "log_index": 1,
                }
            else:
                # Dummy challenge for consistency proof - implement random tree size selection
                challenge = {
                    "type": "challenge",
                    "challenge_type": "consistency",
                    "previous_size": 1,
                    "current_size": 2,
                }
            try:
                await websocket.send_json(challenge)
            except (WebSocketDisconnect, WebSocketException):
                break
    except asyncio.CancelledError:
        pass
