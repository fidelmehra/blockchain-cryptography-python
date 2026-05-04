"""
block.py — Block data structure and proof-of-work mining.
Author: Fidel Mehra

Each Block contains:
  - index, timestamp, previous_hash, nonce
  - list of Transaction objects
  - Merkle root of those transactions
  - SHA-256 block hash (mined to a difficulty target)
"""
from __future__ import annotations

import time
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from ..crypto.hashing import double_sha256, sha256_hex
from ..crypto.merkle import merkle_root_hex


# ---------------------------------------------------------------------------
# Transaction (lightweight)
# ---------------------------------------------------------------------------

@dataclass
class Transaction:
    """A minimal transaction record stored inside a block."""
    sender: str
    recipient: str
    amount: float
    fee: float = 0.0
    tx_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        payload = f"{self.sender}{self.recipient}{self.amount}{self.fee}"
        self.tx_id = sha256_hex(payload.encode())

    def serialise(self) -> bytes:
        """Return canonical bytes representation for Merkle hashing."""
        return json.dumps(
            {"sender": self.sender, "recipient": self.recipient,
             "amount": self.amount, "fee": self.fee, "tx_id": self.tx_id},
            sort_keys=True,
        ).encode()

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

@dataclass
class Block:
    """
    A single block in the chain.

    Parameters
    ----------
    index         : position in the chain (0-based)
    transactions  : list of Transaction objects
    previous_hash : hash of the immediately preceding block
    difficulty    : number of leading zero bytes required (PoW)
    """

    index: int
    transactions: List[Transaction]
    previous_hash: str
    difficulty: int = 4
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    merkle_root: str = field(default="", init=False)
    hash: str = field(default="", init=False)

    def __post_init__(self) -> None:
        self.merkle_root = self._compute_merkle_root()

    # --- hashing ---

    def _compute_merkle_root(self) -> str:
        if not self.transactions:
            return sha256_hex(b"")
        return merkle_root_hex([tx.serialise() for tx in self.transactions])

    def _block_header(self) -> bytes:
        """Canonical bytes used as PoW input."""
        header = (
            f"{self.index}"
            f"{self.timestamp}"
            f"{self.previous_hash}"
            f"{self.merkle_root}"
            f"{self.nonce}"
        )
        return header.encode()

    def compute_hash(self) -> str:
        """Return double-SHA-256 of the block header as hex."""
        return double_sha256(self._block_header()).hex()

    # --- mining ---

    def mine(self) -> str:
        """
        Proof-of-Work: increment nonce until hash has *difficulty* leading zeros.

        Returns the winning hash and sets self.hash.
        """
        target = "0" * self.difficulty
        self.nonce = 0
        candidate = self.compute_hash()
        while not candidate.startswith(target):
            self.nonce += 1
            candidate = self.compute_hash()
        self.hash = candidate
        return self.hash

    # --- validation ---

    def is_valid_hash(self) -> bool:
        """Check that the stored hash satisfies the difficulty target."""
        return (
            self.hash == self.compute_hash()
            and self.hash.startswith("0" * self.difficulty)
        )

    # --- serialisation ---

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "hash": self.hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        txs = [Transaction(**t) for t in data.get("transactions", [])]
        block = cls(
            index=data["index"],
            transactions=txs,
            previous_hash=data["previous_hash"],
            difficulty=data.get("difficulty", 4),
            timestamp=data["timestamp"],
        )
        block.nonce = data["nonce"]
        block.hash = data["hash"]
        block.merkle_root = data["merkle_root"]
        return block

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, txs={len(self.transactions)}, "
            f"hash={self.hash[:16]}...)"
        )


# ---------------------------------------------------------------------------
# Genesis block helper
# ---------------------------------------------------------------------------

def create_genesis_block(difficulty: int = 4) -> Block:
    """Create and mine the genesis (index-0) block."""
    genesis_tx = Transaction(
        sender="0" * 64,
        recipient="genesis",
        amount=0.0,
    )
    block = Block(
        index=0,
        transactions=[genesis_tx],
        previous_hash="0" * 64,
        difficulty=difficulty,
    )
    block.mine()
    return block
