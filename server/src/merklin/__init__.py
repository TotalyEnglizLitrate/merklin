from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import cryptography.exceptions
import uvicorn

import firebase_admin.auth as auth
import firebase_admin.credentials as credentials
import firebase_admin.firestore_async as firestore_async

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, WebSocketException, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from firebase_admin import initialize_app
from google.cloud.firestore_v1.async_client import AsyncClient


from merkle_tree import MerkleTree
from .firestore_services import add_log, get_session, get_logs_by_session
from .alerts import alert, make_alert, make_session_alert

import asyncio
import json
import logging
import random

from contextlib import asynccontextmanager
from dataclasses import dataclass
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path
from typing import cast

import secrets

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cred = credentials.Certificate(
        Path(__file__).parent.parent.parent / "merklin-id-firebase.json"
    )
    app.state.firebase_app = initialize_app(cred)
    logger.info("Firebase app initialized")
    app.state.conn_manager = ConnectionManager()
    app.state.db = cast(
        AsyncClient,
        firestore_async.client(  # pyright: ignore[reportUnknownMemberType]
            app.state.firebase_app
        ),
    )
    logger.info("Firestore client initialized")
    alert_email_queue: asyncio.Queue[EmailMessage] = asyncio.Queue()
    session_alert_email_queue: asyncio.Queue[EmailMessage] = asyncio.Queue()
    app.state.alert_email_queue = alert_email_queue
    app.state.session_alert_email_queue = session_alert_email_queue
    alert_email_task = asyncio.create_task(alert(alert_email_queue))
    session_email_task = asyncio.create_task(alert(session_alert_email_queue))
    logger.info("Email alert task started")
    yield
    logger.info("Shutting down application")
    app.state.db.close()
    alert_email_task.cancel()
    session_email_task.cancel()
    try:
        await alert_email_task
        await session_email_task
    except asyncio.CancelledError:
        pass
    logger.info("Application shutdown complete")


app = FastAPI(lifespan=lifespan)


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
        self.active_connections[uid] = Connection(websocket, MerkleTree(), public_key)
        return self.active_connections[uid]

    async def remove_connection(self, uid: str) -> None:
        conn = self.active_connections.pop(uid, None)
        if conn is not None:
            await conn.websocket.close()

    def is_connected(self, uid: str) -> bool:
        return uid in self.active_connections


async def verify_token(websocket: WebSocket) -> dict[str, str]:
    token = websocket.query_params.get("token")
    if token is None:
        logger.warning("WebSocket connection attempted without token")
        raise WebSocketException(code=4401, reason="Unauthorized: Missing token")
    try:
        return cast(dict[str, str], auth.verify_id_token(token))  # type: ignore
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise


@app.websocket("/log")
async def log_ws_endpoint(
    websocket: WebSocket,
    public_key: str,
    decoded_token: dict[str, str] = Depends(verify_token),
):
    await websocket.accept()

    conn_manager: ConnectionManager = websocket.app.state.conn_manager
    uid = decoded_token["uid"]
    client_email = decoded_token["email"]

    logger.info(f"WebSocket connection established for user {uid}")

    session = await get_session(websocket.app.state.db, uid)
    session_alert_email_queue: asyncio.Queue[EmailMessage] = (
        websocket.app.state.session_alert_email_queue
    )
    logger.info(f"Starting session {session} for user {uid}")

    await session_alert_email_queue.put(make_session_alert(client_email, session))
    logger.info(f"Session alert email sent for user {uid}, session {session}")

    connection = conn_manager.add_connection(
        websocket,
        uid,
        cast(
            rsa.RSAPublicKey,
            serialization.load_pem_public_key(bytes.fromhex(public_key)),
        ),
    )
    logger.debug(f"Connection added for user {uid}")
    challenger = asyncio.create_task(challenge_subroutine(connection))

    alert_email_queue: asyncio.Queue[EmailMessage] = (
        websocket.app.state.alert_email_queue
    )
    counter = 0
    try:
        async for message in websocket.iter_json():
            msg_type = message.get("type")

            if msg_type == "log":
                data = message.get("data")
                signature = message.get("signature")

                if data is None or signature is None:
                    logger.warning(f"Log message from {uid} missing data or signature")
                    await websocket.send_json(
                        {"type": "error", "error": "Missing log data or signature"}
                    )
                    continue

                logger.debug(f"Processing log {counter} from user {uid}")
                process_log(bytes.fromhex(data), bytes.fromhex(signature), connection)
                await add_log(websocket.app.state.db, data, counter, uid, session)
                logger.debug(f"Log {counter} stored successfully for user {uid}")
                counter += 1

            elif msg_type == "proof":
                # Access logs: enc_log = get_log_by_merkle_index(idx)["encrypted_message"]
                proof_type = message.get("proof_type")
                proof = message.get("proof")
                outstanding_proof = None
                disconnect = False

                if proof_type == "membership":
                    assert isinstance(connection.outstanding_challenge, int)
                    logger.debug(
                        f"Verifying membership proof for user {uid}, challenge index: {connection.outstanding_challenge}"
                    )
                    outstanding_proof = connection.tree.membership_proof(
                        connection.outstanding_challenge
                    )

                    for idx, (client, srv) in enumerate(zip(proof, outstanding_proof)):
                        if client != srv:
                            logger.error(
                                f"Tampering detected in membership proof for user {uid}"
                            )
                            disconnect = True

                            warning = (
                                f"Tampering detected! Challenge: {connection.outstanding_challenge}\n"
                                f"Expected {srv} at {idx=}, got {client}\n"
                                f"Expected: {outstanding_proof}\n"
                                f"Got: {proof}\n"
                            )

                            await alert_email_queue.put(
                                make_alert(client_email, proof_type, warning, session)
                            )
                            logger.info(
                                f"Alert email sent for {uid=}, {session=} regarding membership proof tampering"
                            )
                            break
                    else:
                        logger.debug(
                            f"Membership proof verified successfully for user {uid}"
                        )

                elif proof_type == "consistency":
                    assert isinstance(connection.outstanding_challenge, tuple)
                    size1, size2 = connection.outstanding_challenge
                    logger.debug(
                        f"Verifying consistency proof for user {uid}, sizes: {size1} -> {size2}"
                    )
                    outstanding_proof = connection.tree.consistency_proof(size1, size2)

                    for idx, hash in outstanding_proof.items():
                        client_proof = proof.get(
                            str(idx)
                        )  # convert to string - json stores keys as strings
                        if client_proof != hash:
                            logger.error(
                                f"Tampering detected in consistency proof for user {uid}"
                            )
                            disconnect = True

                            warning = f"Tampering detected! Challenge: {connection.outstanding_challenge}\n"

                            if client_proof is None:
                                warning += f"Expected proof to include {idx=}\n"
                            else:
                                warning += (
                                    f"Expected {hash} at {idx=}, got {client_proof}\n"
                                )
                            warning += f"Expected: {outstanding_proof}\nGot: {proof}\n"

                            await alert_email_queue.put(
                                make_alert(client_email, proof_type, warning, session)
                            )
                            break

                        logger.info(
                            f"Alert email sent for {uid=}, {session=} regarding consistency proof tampering"
                        )
                    else:
                        logger.debug(
                            f"Consistency proof verified successfully for user {uid}"
                        )

                    if disconnect:
                        await websocket.close()
                        logger.info(f"Disconnected user {uid} due to proof tampering")
                else:
                    logger.error(
                        f"Invalid proof type received from user {uid}: {proof_type}"
                    )
                    raise ValueError("Invalid proof type")

            else:
                logger.warning(f"Unknown message type from user {uid}: {msg_type}")
                await websocket.send_json(
                    {"type": "error", "error": "Unknown message type"}
                )
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for user {uid}")
    except WebSocketException as e:
        logger.error(f"WebSocket error for user {uid}: {e}")
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON format received from user {uid}")
        await websocket.send_json({"type": "error", "error": "Invalid JSON format"})
    except cryptography.exceptions.InvalidSignature:
        logger.warning(f"Invalid signature on log from user {uid}")
        await websocket.send_json({"type": "error", "error": "Invalid log signature"})
    except Exception as e:
        logger.exception(f"Unexpected error for user {uid}")
        await websocket.send_json(
            {"type": "error", "error": f"Internal server error: {e}"}
        )
    finally:
        logger.info(f"Closing connection for user {uid}")
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
            await asyncio.sleep(random.randrange(10, 15))
            challenge_type = random.choice(["membership", "consistency"])
            challenge: dict[str, int | str]
            if challenge_type == "membership":
                log_index = secrets.randbelow(len(connection.tree.leaves))
                challenge = {
                    "type": "challenge",
                    "challenge_type": "membership",
                    "log_index": log_index,
                }
                connection.outstanding_challenge = log_index
                logger.debug(f"Sending membership challenge for index {log_index}")
            else:
                size2 = secrets.randbelow(len(connection.tree.leaves) - 1) + 1
                size1 = secrets.randbelow(size2)
                size1, size2 = sorted((size2, size1))
                challenge = {
                    "type": "challenge",
                    "challenge_type": "consistency",
                    "previous_size": size1,
                    "current_size": size2,
                }
                connection.outstanding_challenge = (size1, size2)
                logger.debug(
                    f"Sending consistency challenge for sizes {size1} -> {size2}"
                )
            try:
                await connection.websocket.send_json(challenge)
            except (WebSocketDisconnect, WebSocketException) as e:
                logger.debug(f"Challenge subroutine stopped: {e.__class__.__name__}")
                break
    except asyncio.CancelledError:
        logger.debug("Challenge subroutine cancelled")
        pass


@app.get("/signin")
async def signin() -> HTMLResponse:
    html_content = (Path(__file__).parent / "signin.html").read_text()
    return HTMLResponse(content=html_content)


@app.get("/session-logs/{session_id}")
async def get_session_logs(
    session_id: int, decoded_token: dict[str, str] = Depends(verify_token)
) -> StreamingResponse:
    uid = decoded_token["uid"]
    db: AsyncClient = app.state.db
    logs: list[str] = [
        message async for message, _ in get_logs_by_session(db, uid, session_id)
    ]

    return StreamingResponse(
        content=BytesIO(json.dumps(logs).encode()),
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{session_id}_logs.json"'
        },
    )


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger.info("Starting Merklin server on 0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
