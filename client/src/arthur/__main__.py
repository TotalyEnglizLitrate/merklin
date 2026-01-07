from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import httpx
import aiosqlite
import platformdirs

from pathlib import Path
from io import StringIO

import asyncio
import os
import json
import urllib.parse


async def download_logs(token: str, session_id: int, path: Path, decrypt: bool = False):
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"The path {path} is not a directory.")
    else:
        path.mkdir(parents=True, exist_ok=True)

    url = os.getenv("MERKLIN_URL")
    if url is None:
        raise RuntimeError("Merklin server endpoint not configured")
    encoded_params = urllib.parse.urlencode({"token": token})
    async with httpx.AsyncClient() as client:
        async with client.stream(
            "GET",
            f"http://{url}/session-logs/{session_id}?{encoded_params}",
        ) as response:
            response.raise_for_status()
            filename = (
                response.headers["Content-Disposition"].split("filename=")[1].strip('"')
            )
            file_bytes = await response.aread()
            (path / filename).write_bytes(file_bytes)
            if decrypt:
                buf = StringIO(file_bytes.decode())
                await decrypt_logs(session_id, buf, path / f"{filename}.decrypted")


async def decrypt_logs(session_id: int, buf: StringIO, out: Path):
    conn: aiosqlite.Connection = await aiosqlite.connect(
        platformdirs.user_data_path("arthur") / "sessions.db"
    )
    cursor = await conn.cursor()

    key_result = await cursor.execute("SELECT AES_KEY FROM SESSION_KEY WHERE SESSION_ID = ?;", (session_id,))
    key_row = await key_result.fetchone()
    if key_row is None:
        raise RuntimeError("Unkown session")
    aes_key: bytes = key_row[0]
    aes = AESGCM(aes_key)

    enc_logs = [bytes.fromhex(x) for x in json.load(buf)]
    nonces_result = await cursor.execute("SELECT NONCE FROM LOG_NONCE WHERE SESSION_ID = ? ORDER BY LOG_ID ASC;", (session_id,))
    nonces = [row[0] for row in await nonces_result.fetchall()]
    out.write_text("".join(aes.decrypt(nonce, log, None).decode() for nonce, log in zip(nonces, enc_logs, strict=True)))


def main():
    token = input("Enter token: ")
    session_id = int(input("Enter session id to retrieve: "))
    path = Path(input("Enter path for storing file (directory): "))
    decrypt = input("Do you want to decrypt the logs? [Y/n]").strip().lower()
    if decrypt == "":
        decrypt = "y"

    asyncio.run(download_logs(token, session_id, path, decrypt == "y"))

main()