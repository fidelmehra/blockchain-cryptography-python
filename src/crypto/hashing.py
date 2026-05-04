"""
hashing.py — Cryptographic hashing primitives for the blockchain.
Author: Fidel Mehra
"""
from __future__ import annotations
import hashlib
import hmac
import struct
from enum import Enum, auto
from typing import Union


class HashAlgorithm(Enum):
    SHA256 = auto()
    SHA3_256 = auto()
    KECCAK256 = auto()
    RIPEMD160 = auto()
    BLAKE2B = auto()
    DOUBLE_SHA256 = auto()


def sha256(data: bytes) -> bytes:
    """SHA-256 digest."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def double_sha256(data: bytes) -> bytes:
    """Bitcoin-style hash256: SHA-256(SHA-256(data))."""
    return sha256(sha256(data))


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def keccak256(data: bytes) -> bytes:
    """Ethereum-style Keccak-256."""
    try:
        import sha3  # pysha3
        k = hashlib.new("keccak_256")
        k.update(data)
        return k.digest()
    except (ImportError, ValueError):
        return sha3_256(data)  # graceful fallback to SHA3-256


def ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def hash160(data: bytes) -> bytes:
    """Bitcoin HASH160: RIPEMD-160(SHA-256(data))."""
    return ripemd160(sha256(data))


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


class HashEngine:
    """
    Unified hashing interface.

    Parameters
    ----------
    algorithm : HashAlgorithm
        The hashing algorithm to use (default: SHA-256).
    """

    _DISPATCH = {
        HashAlgorithm.SHA256: sha256,
        HashAlgorithm.SHA3_256: sha3_256,
        HashAlgorithm.KECCAK256: keccak256,
        HashAlgorithm.RIPEMD160: ripemd160,
        HashAlgorithm.BLAKE2B: blake2b_256,
        HashAlgorithm.DOUBLE_SHA256: double_sha256,
    }

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> None:
        self.algorithm = algorithm
        self._fn = self._DISPATCH[algorithm]

    def hash(self, data: Union[bytes, str]) -> bytes:
        if isinstance(data, str):
            data = data.encode()
        return self._fn(data)

    def hash_hex(self, data: Union[bytes, str]) -> str:
        return self.hash(data).hex()

    def hash_many(self, items: list) -> list:
        return [self.hash(item) for item in items]


# Convenience: default engine
default_engine = HashEngine(HashAlgorithm.SHA256)
