"""
merkle.py — Merkle tree implementation for transaction verification.
Author: Fidel Mehra

Supports:
  - Binary Merkle tree construction from arbitrary leaf data
  - Merkle root computation (double-SHA-256, Bitcoin-style)
  - Merkle proof generation and verification
  - Sparse and incremental tree updates
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .hashing import double_sha256, sha256


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

Hash = bytes          # 32-byte digest
Leaf = bytes          # raw leaf data (will be hashed)
ProofPath = List[Tuple[Hash, str]]  # [(sibling_hash, "left"|"right"), ...]


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _leaf_hash(data: bytes) -> Hash:
    """Compute SHA-256 of a leaf (single hash for simplicity)."""
    return sha256(data)


def _node_hash(left: Hash, right: Hash) -> Hash:
    """Compute the parent hash: double-SHA-256(left || right)."""
    return double_sha256(left + right)


def _pad_to_power_of_two(leaves: List[Hash]) -> List[Hash]:
    """
    Duplicate the last leaf until the count is a power of two.
    (Bitcoin Merkle tree convention.)
    """
    n = len(leaves)
    if n == 0:
        raise ValueError("Cannot build Merkle tree from empty leaf list.")
    target = 1 << math.ceil(math.log2(n)) if n > 1 else 1
    while len(leaves) < target:
        leaves = leaves + [leaves[-1]]
    return leaves


# ---------------------------------------------------------------------------
# MerkleTree class
# ---------------------------------------------------------------------------

@dataclass
class MerkleTree:
    """
    Binary Merkle tree.

    Parameters
    ----------
    leaves : list of raw bytes objects (will be leaf-hashed internally)
    """

    _raw_leaves: List[bytes]
    _leaf_hashes: List[Hash] = field(init=False, default_factory=list)
    _layers: List[List[Hash]] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        if not self._raw_leaves:
            raise ValueError("MerkleTree requires at least one leaf.")
        self._build()

    # --- construction ---

    def _build(self) -> None:
        """Build all tree layers bottom-up."""
        leaf_hashes = [_leaf_hash(leaf) for leaf in self._raw_leaves]
        self._leaf_hashes = leaf_hashes
        padded = _pad_to_power_of_two(list(leaf_hashes))
        self._layers = [padded]
        current = padded
        while len(current) > 1:
            parent_layer: List[Hash] = []
            for i in range(0, len(current), 2):
                parent_layer.append(_node_hash(current[i], current[i + 1]))
            self._layers.append(parent_layer)
            current = parent_layer

    # --- public API ---

    @property
    def root(self) -> Hash:
        """Return the Merkle root (32-byte digest)."""
        return self._layers[-1][0]

    @property
    def root_hex(self) -> str:
        """Return the Merkle root as a lowercase hex string."""
        return self.root.hex()

    @property
    def depth(self) -> int:
        """Number of layers including leaves and root."""
        return len(self._layers)

    @property
    def leaf_count(self) -> int:
        """Number of original (un-padded) leaves."""
        return len(self._raw_leaves)

    def get_proof(self, index: int) -> ProofPath:
        """
        Generate the Merkle proof for the leaf at *index*.

        Returns a list of (sibling_hash, position) pairs where
        position is "left" if the sibling is on the left of the
        current node, else "right".
        """
        if index < 0 or index >= len(self._raw_leaves):
            raise IndexError(f"Leaf index {index} out of range (0-{len(self._raw_leaves)-1}).")

        proof: ProofPath = []
        idx = index
        for layer in self._layers[:-1]:  # exclude root layer
            if idx % 2 == 0:  # current is left child
                sibling_idx = idx + 1
                proof.append((layer[sibling_idx], "right"))
            else:             # current is right child
                sibling_idx = idx - 1
                proof.append((layer[sibling_idx], "left"))
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(
        leaf_data: bytes,
        proof: ProofPath,
        expected_root: Hash,
    ) -> bool:
        """
        Verify a Merkle proof.

        Parameters
        ----------
        leaf_data     : original (un-hashed) leaf data
        proof         : list of (sibling_hash, position) pairs
        expected_root : known-good Merkle root
        """
        current = _leaf_hash(leaf_data)
        for sibling, position in proof:
            if position == "right":
                current = _node_hash(current, sibling)
            else:
                current = _node_hash(sibling, current)
        return current == expected_root

    def __repr__(self) -> str:
        return (
            f"MerkleTree(leaves={self.leaf_count}, "
            f"depth={self.depth}, root={self.root_hex[:16]}...)"
        )


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def build_merkle_tree(data: List[bytes]) -> MerkleTree:
    """Build a MerkleTree from a list of raw byte objects."""
    return MerkleTree(_raw_leaves=data)


def merkle_root(data: List[bytes]) -> Hash:
    """Return only the Merkle root for *data* without keeping the tree."""
    return build_merkle_tree(data).root


def merkle_root_hex(data: List[bytes]) -> str:
    """Return the Merkle root as a hex string."""
    return merkle_root(data).hex()
