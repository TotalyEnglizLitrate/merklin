from google.cloud.firestore_v1.async_client import AsyncClient

import logging

from typing import cast

logger = logging.getLogger(__name__)


async def add_log(
    db: AsyncClient, encrypted_data: str, log_index: int, uid: str, session: int
) -> None:
    try:
        await db.collection(
            "logs"
        ).document().set(  # pyright: ignore[reportUnknownMemberType]
            {
                "uid": uid,
                "encrypted_message": encrypted_data,
                "log_index": log_index,
                "session": session,
            }
        )
        logger.debug(f"Log stored for user {uid} at index {log_index}")
    except Exception as e:
        logger.error(f"Failed to store log for user {uid}: {e}")
        raise


async def get_log_by_index(
    db: AsyncClient, uid: str, log_index: int, session: int
) -> dict[str, str | int] | None:
    query = (
        db.collection("logs")
        .where("uid", "==", uid)  # pyright: ignore[reportUnknownMemberType]
        .where("log_index", "==", log_index)
        .where("session", "==", session)
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


async def get_logs_by_session(
    db: AsyncClient, uid: str, session: int
) -> list[dict[str, str | int]]:
    query = (
        db.collection("logs")
        .where("uid", "==", uid)  # pyright: ignore[reportUnknownMemberType]
        .where("session", "==", session)
    )

    return cast(
        list[dict[str, str | int]], [doc.to_dict() async for doc in query.stream()]
    )


async def get_session(db: AsyncClient, uid: str) -> int:
    query = (
        db.collection("logs")
        .where("uid", "==", uid)  # pyright: ignore[reportUnknownMemberType]
        .where("is_session", "==", True)
        .limit(1)
    )
    try:
        result = (await anext(query.stream())).to_dict()
        if result is None:
            ret = 1
        else:
            ret = result["last_session"] + 1
        logger.debug(f"Session retrieved for user {uid}")
        logger.debug(f"Current session for user {uid} is {ret}")
    except StopAsyncIteration as e:
        ret = 1
        logger.debug(f"No session found for user {uid}, defaulting to 1")
    except Exception as e:
        logger.error(f"Failed to retrieve session for user {uid}: {e}")
        raise

    await db.collection(
        "logs"
    ).document().set(  # pyright: ignore[reportUnknownMemberType]
        {
            "uid": uid,
            "is_session": True,
            "last_session": ret,
        },
        merge=ret != 1,
    )

    return ret
