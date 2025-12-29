from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import cryptography.exceptions

import firebase_admin.auth as auth
import firebase_admin.credentials as credentials
import firebase_admin.firestore_async as firestore_async

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, WebSocketException, Depends
from fastapi.responses import HTMLResponse
from firebase_admin import initialize_app
from google.cloud.firestore_v1.async_client import AsyncClient


from merkle_tree import MerkleTree
from .firestore_services import add_log

import asyncio
import json
import random

from dataclasses import dataclass
from pathlib import Path
from typing import cast

import secrets


@dataclass
class Connection:
    websocket: WebSocket
    tree: MerkleTree
    public_key: rsa.RSAPublicKey
    outstanding_challenge: int | tuple[int, int] | None = None


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, Connection] = {}

    def add_connection(
        self, websocket: WebSocket, uid: str, public_key: rsa.RSAPublicKey
    ) -> Connection:
        # TODO: Check if the logger is registered
        self.active_connections[uid] = Connection(websocket, MerkleTree(), public_key)
        return self.active_connections[uid]

    async def remove_connection(self, uid: str) -> None:
        conn = self.active_connections.pop(uid, None)
        if conn is not None:
            await conn.websocket.close()

    def is_connected(self, uid: str) -> bool:
        return uid in self.active_connections


app = FastAPI(connection_manager=ConnectionManager())


async def verify_token(websocket: WebSocket) -> str:
    token = websocket.query_params.get("token")
    if token is None:
        raise WebSocketException(code=4401, reason="Unauthorized: Missing token")
    try:
        decoded_token = auth.verify_id_token(token)  # type: ignore
        uid = cast(str, decoded_token["uid"])
        return uid
    except Exception as e:
        print(f"Token Verification error: {e}")
        raise


@app.websocket("/log")
async def log_ws_endpoint(
    websocket: WebSocket, public_key: str, uid: str = Depends(verify_token)
):
    await websocket.accept()
    conn_manager: ConnectionManager = websocket.app.connection_manager
    connection = conn_manager.add_connection(
        websocket,
        uid,
        cast(
            rsa.RSAPublicKey,
            serialization.load_pem_public_key(bytes.fromhex(public_key)),
        ),
    )
    challenger = asyncio.create_task(challenge_subroutine(connection))
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
                await add_log(db, data.hex(), counter, uid)
                counter += 1
            elif msg_type == "proof":
                # TODO: verify outstanding proof
                # enc_log = get_log_by_merkle_index(idx)["encrypted_message"]
                proof_type = message.get("proof_type")
                proof = message.get("proof")
                outstanding_proof = None
                if proof_type == "membership":
                    assert isinstance(connection.outstanding_challenge, int)
                    outstanding_proof = connection.tree.membership_proof(connection.outstanding_challenge)
                elif proof_type == "consistency":
                    assert isinstance(connection.outstanding_challenge, tuple)
                    size1, size2 = connection.outstanding_challenge
                    outstanding_proof = connection.tree.consistency_proof(size1, size2)
                if proof != outstanding_proof:
                    print(
                        f"Tampering detected! Challenge: {connection.outstanding_challenge}"
                    )
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
        await conn_manager.remove_connection(uid)
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

    conn.tree.add_log(data)


async def challenge_subroutine(connection: Connection):
    try:
        while True:
            await asyncio.sleep(random.randrange(600, 1200))
            challenge_type = random.choice(["membership", "consistency"])
            challenge: dict[str, int | str]
            if challenge_type == "membership":
                # Dummy challenge for membership proof - implement random log selection
                log_index = secrets.randbelow(len(connection.tree.leaves))
                challenge = {
                    "type": "challenge",
                    "challenge_type": "membership",
                    "log_index": log_index,
                }
                connection.outstanding_challenge = log_index
            else:
                # Dummy challenge for consistency proof - implement random tree size selection
                size2 = secrets.randbelow(len(connection.tree.leaves) - 1) + 1
                size1 = secrets.randbelow(size2)
                challenge = {
                    "type": "challenge",
                    "challenge_type": "consistency",
                    "previous_size": size1,
                    "current_size": size2,
                }
                connection.outstanding_challenge = (size1, size2)
            try:
                await connection.websocket.send_json(challenge)
            except (WebSocketDisconnect, WebSocketException):
                break
    except asyncio.CancelledError:
        pass

@app.get("/signin")
async def signin() -> HTMLResponse:
    html_content = (Path(__file__).parent / "signin.html").read_text()
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn

    cred = credentials.Certificate("firebase-key.json")
    firebase_app = initialize_app(cred)
    db = cast(
        AsyncClient,
        firestore_async.client(  # pyright: ignore[reportUnknownMemberType]
            firebase_app, "logs"
        ),
    )
    uvicorn.run(app, host="0.0.0.0", port=8000)
