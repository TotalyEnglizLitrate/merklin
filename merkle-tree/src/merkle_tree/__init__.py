from hashlib import sha256


class LogNode:
    def __init__(self, log: str) -> None:
        self.log = sha256(log.encode()).hexdigest()


class MerkleTree:
    def __init__(self) -> None:
        self.leaves: list[LogNode] = []
        self.root: str | None = None

    def add_log(self, log: str) -> None:
        node = LogNode(log)
        self.leaves.append(node)

    def membership_proof(self, log: str) -> list[str]:
        raise NotImplementedError("Membership proof not implemented")

    def consistency_proof(self, p1: int, p2: int) -> list[str]:
        raise NotImplementedError("Consistency proof not implemented")
