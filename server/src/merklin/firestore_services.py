from firebase_admin import firestore
from firebase_init import init_firebase

init_firebase()
db = firestore.client()


def add_log(encrypted_data: str, merkle_index: int, uid) -> None:
    db.collection("logs").document().set(
        {
            "uid": uid,
            "encrypted_message": encrypted_data,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "merkle_index": merkle_index,  # logical order
        }
    )


def get_log_by_merkle_index(uid, merkle_index: int):
    query = (
        db.collection("logs")
        .where("uid", "==", uid)
        .where("merkle_index", "==", merkle_index)
        .limit(1)
    )

    docs = list(query.stream())
    if not docs:
        return None

    return docs[0].to_dict()
