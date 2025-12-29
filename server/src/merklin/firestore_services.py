from google.cloud.firestore_v1.async_client import AsyncClient


async def add_log(
    db: AsyncClient, encrypted_data: str, log_index: int, uid: str
) -> None:
    await db.collection(
        "logs"
    ).document().set(  # pyright: ignore[reportUnknownMemberType]
        {
            "uid": uid,
            "encrypted_message": encrypted_data,
            "log_index": log_index,
        }
    )


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
        return (await anext(query.stream())).to_dict()
    except StopAsyncIteration:
        return None
