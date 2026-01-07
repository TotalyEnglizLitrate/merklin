import httpx

from pathlib import Path
import os


async def download_logs(token: str, session_id: int, path: Path):
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"The path {path} is not a directory.")
    else:
        path.mkdir(parents=True, exist_ok=True)

    ws_url = os.getenv("MERKLIN_URL")
    if ws_url is None:
        raise RuntimeError("Merklin server endpoint not configured")

    async with httpx.AsyncClient() as client:
        async with client.stream(
            "GET",
            f"http://{ws_url}/session-logs/{session_id}",
            headers={"Authorization": f"Bearer {token}"},
        ) as response:
            response.raise_for_status()
            filename = (
                response.headers["Content-Disposition"].split("filename=")[1].strip('"')
            )
            (path / filename).write_bytes(await response.aread())
