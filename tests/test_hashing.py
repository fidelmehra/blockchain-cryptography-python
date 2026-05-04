"""
test_hashing.py — Unit tests for src/crypto/hashing.py
Author: Fidel Mehra
"""
import hashlib
import pytest
from src.crypto.hashing import (
    HashAlgorithm,
    HashEngine,
    blake2b_256,
    double_sha256,
    hash160,
    hmac_sha256,
    ripemd160,
    sha256,
    sha256_hex,
    sha3_256,
)


# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------

class TestSHA256:
    KNOWN = {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"hello": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        b"abc": "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f492006b3c9b2a9e0",  # NIST
    }

    @pytest.mark.parametrize("data,expected", list(KNOWN.items()))
    def test_known_vectors(self, data, expected):
        assert sha256_hex(data) == expected

    def test_returns_bytes(self):
        result = sha256(b"test")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_idempotent(self):
        assert sha256(b"x") == sha256(b"x")

    def test_empty_input(self):
        assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# Double-SHA-256
# ---------------------------------------------------------------------------

class TestDoubleSHA256:
    def test_double_sha256_is_two_rounds(self):
        data = b"block header bytes"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        assert double_sha256(data) == expected

    def test_length(self):
        assert len(double_sha256(b"any")) == 32


# ---------------------------------------------------------------------------
# SHA-3 / Keccak
# ---------------------------------------------------------------------------

class TestSHA3:
    def test_sha3_256_length(self):
        assert len(sha3_256(b"data")) == 32

    def test_sha3_differs_from_sha2(self):
        data = b"hello"
        assert sha3_256(data) != sha256(data)


# ---------------------------------------------------------------------------
# RIPEMD-160
# ---------------------------------------------------------------------------

class TestRIPEMD160:
    def test_length(self):
        h = ripemd160(b"hello")
        assert len(h) == 20

    def test_known_vector(self):
        # RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        expected = bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")
        assert ripemd160(b"") == expected


# ---------------------------------------------------------------------------
# BLAKE2b
# ---------------------------------------------------------------------------

class TestBLAKE2b:
    def test_length(self):
        assert len(blake2b_256(b"hello")) == 32

    def test_different_from_sha256(self):
        assert blake2b_256(b"hello") != sha256(b"hello")


# ---------------------------------------------------------------------------
# HASH160
# ---------------------------------------------------------------------------

class TestHASH160:
    def test_length(self):
        assert len(hash160(b"pubkey")) == 20

    def test_equals_ripemd160_of_sha256(self):
        data = b"some public key"
        expected = ripemd160(sha256(data))
        assert hash160(data) == expected


# ---------------------------------------------------------------------------
# HMAC-SHA256
# ---------------------------------------------------------------------------

class TestHMACSHA256:
    def test_length(self):
        assert len(hmac_sha256(b"key", b"message")) == 32

    def test_different_keys_differ(self):
        assert hmac_sha256(b"key1", b"msg") != hmac_sha256(b"key2", b"msg")


# ---------------------------------------------------------------------------
# HashEngine
# ---------------------------------------------------------------------------

class TestHashEngine:
    @pytest.mark.parametrize("algo", list(HashAlgorithm))
    def test_all_algorithms_produce_bytes(self, algo):
        engine = HashEngine(algo)
        result = engine.hash(b"test data")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_hash_string_input(self):
        engine = HashEngine(HashAlgorithm.SHA256)
        assert engine.hash("hello") == engine.hash(b"hello")

    def test_hash_hex_is_string(self):
        engine = HashEngine(HashAlgorithm.SHA256)
        result = engine.hash_hex(b"data")
        assert isinstance(result, str)
        assert len(result) == 64  # 32 bytes hex-encoded

    def test_hash_many(self):
        engine = HashEngine(HashAlgorithm.SHA256)
        items = [b"a", b"b", b"c"]
        results = engine.hash_many(items)
        assert len(results) == 3
        assert all(isinstance(r, bytes) for r in results)

    def test_default_is_sha256(self):
        engine = HashEngine()
        assert engine.algorithm == HashAlgorithm.SHA256

    def test_double_sha256_engine(self):
        engine = HashEngine(HashAlgorithm.DOUBLE_SHA256)
        data = b"blockchain"
        assert engine.hash(data) == double_sha256(data)
