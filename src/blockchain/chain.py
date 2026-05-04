"""
chain.py — Blockchain (chain of blocks) management.
Author: Fidel Mehra

Manages the full chain: appending blocks, validating integrity,
adjusting difficulty, and serialising/deserialising the chain.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import List, Optional

from .block import Block, Transaction, create_genesis_block


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------

@dataclass
class Blockchain:
    """
    A full blockchain.

    Parameters
    ----------
    difficulty          : initial PoW difficulty (leading zeros)
    retarget_interval   : number of blocks between difficulty adjustments
    target_block_time   : desired seconds per block
    """

    difficulty: int = 4
    retarget_interval: int = 10
    target_block_time: float = 10.0  # seconds

    chain: List[Block] = field(default_factory=list, init=False)
    pending_transactions: List[Transaction] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        # Create and append genesis block
        genesis = create_genesis_block(self.difficulty)
        self.chain.append(genesis)

    # --- properties ---

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    @property
    def height(self) -> int:
        return len(self.chain)

    # --- pending transactions ---

    def add_transaction(self, tx: Transaction) -> None:
        """Add a transaction to the pending pool."""
        self.pending_transactions.append(tx)

    # --- block mining ---

    def mine_pending_transactions(
        self,
        miner_reward_address: str,
        reward: float = 50.0,
    ) -> Block:
        """
        Mine all pending transactions into a new block.

        Adds a coinbase reward transaction for the miner.
        Returns the newly mined block.
        """
        # Coinbase
        coinbase = Transaction(
            sender="0" * 64,
            recipient=miner_reward_address,
            amount=reward,
        )
        txs = [coinbase] + list(self.pending_transactions)
        self.pending_transactions = []

        block = Block(
            index=self.height,
            transactions=txs,
            previous_hash=self.last_block.hash,
            difficulty=self.difficulty,
        )
        block.mine()
        self.chain.append(block)

        # Difficulty retargeting
        if self.height % self.retarget_interval == 0:
            self._retarget_difficulty()

        return block

    # --- validation ---

    def is_valid(self) -> bool:
        """
        Validate the entire chain.

        Checks:
          1. Each block's stored hash equals its recomputed hash.
          2. Each block's previous_hash matches the preceding block's hash.
          3. The genesis block has index 0.
        """
        for i, block in enumerate(self.chain):
            # Hash integrity
            if block.hash != block.compute_hash():
                return False
            # PoW target
            if not block.hash.startswith("0" * block.difficulty):
                return False
            # Chain linkage
            if i > 0 and block.previous_hash != self.chain[i - 1].hash:
                return False
        return True

    def validate_block(self, block: Block) -> bool:
        """Validate a single block before appending."""
        if block.previous_hash != self.last_block.hash:
            return False
        if block.hash != block.compute_hash():
            return False
        if not block.hash.startswith("0" * block.difficulty):
            return False
        return True

    # --- difficulty retargeting ---

    def _retarget_difficulty(self) -> None:
        """
        Adjust difficulty based on actual vs target block time over the
        last *retarget_interval* blocks (simplified Bitcoin-style).
        """
        if self.height < self.retarget_interval:
            return
        recent = self.chain[-self.retarget_interval:]
        actual_time = recent[-1].timestamp - recent[0].timestamp
        if actual_time == 0:
            return
        expected_time = self.target_block_time * self.retarget_interval
        ratio = actual_time / expected_time
        if ratio < 0.5:
            self.difficulty += 1
        elif ratio > 2.0 and self.difficulty > 1:
            self.difficulty -= 1

    # --- serialisation ---

    def to_dict(self) -> dict:
        return {
            "difficulty": self.difficulty,
            "height": self.height,
            "chain": [block.to_dict() for block in self.chain],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "Blockchain":
        bc = cls.__new__(cls)
        bc.difficulty = data["difficulty"]
        bc.retarget_interval = 10
        bc.target_block_time = 10.0
        bc.pending_transactions = []
        bc.chain = [Block.from_dict(b) for b in data["chain"]]
        return bc

    @classmethod
    def from_json(cls, json_str: str) -> "Blockchain":
        return cls.from_dict(json.loads(json_str))

    def __repr__(self) -> str:
        return f"Blockchain(height={self.height}, difficulty={self.difficulty})"
