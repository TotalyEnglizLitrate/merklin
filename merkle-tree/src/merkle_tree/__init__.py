from hashlib import sha256
import functools


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
        # retun membership proof with 0th idx as reqd hash
        leaf_hash = sha256(log.encode()).hexdigest()
        try:
            index = next(
                i for i, node in enumerate(self.leaves) if node.log == leaf_hash
            )
        except StopIteration:
            raise ValueError("Log not found in tree")

        proof = []
        current_level = [node.log for node in self.leaves]
        n = len(current_level)
        while n > 1:
            if n % 2:
                current_level.append(current_level[-1])
                n += 1

            sibling_idx = index ^ 1
            proof.append(current_level[sibling_idx])

            next_level = [
                MerkleTree.compute_hash(current_level[i], current_level[i + 1])
                for i in range(0, n, 2)
            ]

            index = index // 2
            current_level = next_level
            n = len(current_level)

        self.root = current_level[0]
        return [leaf_hash] + proof
    def consistency_proof(
        self, p1: int, p2: int
    ) -> dict[int:str]:  # p1 and p2 are sizes
        if not (0 < p1 <= p2 <= len(self.leaves)):
            raise ValueError("Invalid tree sizes for consistency proof")
    @functools.lru_cache()
    def compute_hash(hash1: str, hash2: str) -> str:
        combined = (hash1 + hash2).encode()
        return sha256(combined).hexdigest()
