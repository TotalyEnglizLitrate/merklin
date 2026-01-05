import logging
from google.cloud.firestore_v1.async_client import AsyncClient

logger = logging.getLogger(__name__)


async def add_log(
    db: AsyncClient, encrypted_data: str, log_index: int, uid: str
) -> None:
    try:
        await db.collection(
            "logs"
        ).document().set(  # pyright: ignore[reportUnknownMemberType]
            {
                "uid": uid,
                "encrypted_message": encrypted_data,
                "log_index": log_index,
            }
        )
        logger.debug(f"Log stored for user {uid} at index {log_index}")
    except Exception as e:
        logger.error(f"Failed to store log for user {uid}: {e}")
        raise


async def get_log_by_index(
    db: AsyncClient, uid: str, log_index: int
) -> dict[str, str | int | bytes] | None:
    query = (
        db.collection("logs")
        .where("uid", "==", uid)  # pyright: ignore[reportUnknownMemberType]
        .where("merkle_index", "==", log_index)
        .limit(1)
    )
    try:
        result = (await anext(query.stream())).to_dict()
        logger.debug(f"Log retrieved for user {uid} at index {log_index}")
        return result
    except StopAsyncIteration as e:
        logger.warning(f"No log found for user {uid} at index {log_index}")
        raise RuntimeError("No matching log found")
    except Exception as e:
        logger.error(f"Failed to retrieve log for user {uid} at index {log_index}: {e}")
        raise
