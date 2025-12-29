from hashlib import sha256
import functools
import math


class LogNode:
    def __init__(self, log: bytes) -> None:
        self.log = sha256(log).hexdigest()


class MerkleTree:
    def __init__(self) -> None:
        self.leaves: list[LogNode] = []
        self.root: str | None = None

    def add_log(self, log: bytes) -> None:
        node = LogNode(log)
        self.leaves.append(node)

    def membership_proof(self, log_idx: int) -> list[str]:
        if not (0 <= log_idx < len(self.leaves)):
            raise ValueError("Invalid tree sizes for consistency proof")
        
        index = log_idx
        proof = [self.leaves[index].log]
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
        return proof

    def consistency_proof(
        self, point1: int, point2: int
    ) -> dict[int, str]:
        if not (0 < point1 <= point2 <= len(self.leaves)):
            raise ValueError("Invalid tree sizes for consistency proof")

        current_level = [node.log for node in self.leaves[:point2]]
        n = len(current_level)
        level = math.ceil(math.log2(n))
        first_node_idx = 2**level - 1

        proof: dict[int, str] = {}
        proof[first_node_idx + point2 - 1] = current_level[point2 - 1]
        index = point2 - 1
        while n > 1:
            if n % 2:
                current_level.append(current_level[-1])
                n += 1

            sibling_idx = index ^ 1
            proof[first_node_idx + sibling_idx] = current_level[sibling_idx]

            next_level = [
                MerkleTree.compute_hash(current_level[i], current_level[i + 1])
                for i in range(0, n, 2)
            ]

            index = index // 2
            current_level = next_level
            n = len(current_level)
            level = math.ceil(math.log2(n))
            first_node_idx = 2**level - 1

        current_level = [node.log for node in self.leaves[:point2]]
        n = len(current_level)
        level = math.ceil(math.log2(n))
        first_node_idx: int = 2**level - 1

        t_p1: dict[int, str] = {}
        t_p1[first_node_idx + point1 - 1] = current_level[point1 - 1]
        index = point1 - 1
        while n > 1:
            if n % 2:
                current_level.append(current_level[-1])
                n += 1

            if proof.get(first_node_idx + index) is not None:
                proof.pop(first_node_idx + index)
                break

            sibling_idx = index ^ 1
            t_p1[first_node_idx + sibling_idx] = current_level[sibling_idx]

            next_level = [
                MerkleTree.compute_hash(current_level[i], current_level[i + 1])
                for i in range(0, n, 2)
            ]
            parent_idx = index // 2
            new_level = math.ceil(math.log2(len(next_level)))

            index = parent_idx
            current_level = next_level
            n = len(current_level)
            level = new_level
            first_node_idx = 2**level - 1

        proof.update(t_p1)

        return proof

    @staticmethod
    @functools.lru_cache()
    def compute_hash(hash1: str, hash2: str) -> str:
        combined = (hash1 + hash2).encode()
        return sha256(combined).hexdigest()
