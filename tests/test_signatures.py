"""
test_signatures.py — Unit tests for src/crypto/signatures.py
Author: Fidel Mehra
"""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from src.crypto.signatures import (
    KeyPair,
    SECP256K1,
    P256,
    generate_keypair,
    load_keypair_pem,
    sign,
    sign_digest,
    verify,
    verify_digest,
    signature_to_rs,
    rs_to_signature,
)
from src.crypto.hashing import sha256


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypair_secp256k1() -> KeyPair:
    return generate_keypair(SECP256K1)


@pytest.fixture(scope="module")
def keypair_p256() -> KeyPair:
    return generate_keypair(P256)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class TestKeyGeneration:
    def test_generate_secp256k1(self, keypair_secp256k1):
        kp = keypair_secp256k1
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_generate_p256(self, keypair_p256):
        kp = keypair_p256
        assert kp.private_key is not None

    def test_keypairs_are_unique(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.public_bytes_compressed() != kp2.public_bytes_compressed()

    def test_public_key_compressed_length(self, keypair_secp256k1):
        pub = keypair_secp256k1.public_bytes_compressed()
        assert len(pub) == 33

    def test_public_key_uncompressed_length(self, keypair_secp256k1):
        pub = keypair_secp256k1.public_bytes_uncompressed()
        assert len(pub) == 65
        assert pub[0] == 0x04


# ---------------------------------------------------------------------------
# PEM serialisation round-trip
# ---------------------------------------------------------------------------

class TestPEMSerialisation:
    def test_private_pem_roundtrip(self, keypair_secp256k1):
        pem = keypair_secp256k1.private_bytes_pem()
        assert b"BEGIN" in pem
        restored = load_keypair_pem(pem)
        assert (
            restored.public_bytes_compressed()
            == keypair_secp256k1.public_bytes_compressed()
        )

    def test_public_pem_contains_key(self, keypair_secp256k1):
        pem = keypair_secp256k1.public_bytes_pem()
        assert b"PUBLIC KEY" in pem


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------

class TestAddresses:
    def test_bitcoin_address_not_empty(self, keypair_secp256k1):
        addr = keypair_secp256k1.bitcoin_address()
        assert isinstance(addr, str)
        assert len(addr) > 20

    def test_ethereum_address_format(self, keypair_secp256k1):
        addr = keypair_secp256k1.ethereum_address()
        assert addr.startswith("0x")
        assert len(addr) == 42  # 0x + 40 hex chars

    def test_different_keys_different_addresses(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.bitcoin_address() != kp2.bitcoin_address()


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------

class TestSignVerify:
    MESSAGE = b"The quick brown fox jumps over the lazy dog"

    def test_sign_and_verify(self, keypair_secp256k1):
        sig = sign(self.MESSAGE, keypair_secp256k1)
        assert verify(self.MESSAGE, sig, keypair_secp256k1.public_key)

    def test_wrong_message_fails(self, keypair_secp256k1):
        sig = sign(self.MESSAGE, keypair_secp256k1)
        assert not verify(b"wrong message", sig, keypair_secp256k1.public_key)

    def test_wrong_key_fails(self, keypair_secp256k1):
        sig = sign(self.MESSAGE, keypair_secp256k1)
        other = generate_keypair()
        assert not verify(self.MESSAGE, sig, other.public_key)

    def test_sign_digest(self, keypair_secp256k1):
        digest = sha256(self.MESSAGE)
        sig = sign_digest(digest, keypair_secp256k1)
        assert verify_digest(digest, sig, keypair_secp256k1.public_key)

    def test_corrupted_signature_fails(self, keypair_secp256k1):
        sig = sign(self.MESSAGE, keypair_secp256k1)
        corrupted = bytearray(sig)
        corrupted[-1] ^= 0xFF
        assert not verify(self.MESSAGE, bytes(corrupted), keypair_secp256k1.public_key)

    def test_p256_sign_verify(self, keypair_p256):
        sig = sign(self.MESSAGE, keypair_p256)
        assert verify(self.MESSAGE, sig, keypair_p256.public_key)


# ---------------------------------------------------------------------------
# DER <-> (r, s) round-trip
# ---------------------------------------------------------------------------

class TestDERConversion:
    def test_rs_roundtrip(self, keypair_secp256k1):
        sig = sign(b"data", keypair_secp256k1)
        r, s = signature_to_rs(sig)
        rebuilt = rs_to_signature(r, s)
        # Rebuilt DER should verify correctly
        assert verify(b"data", rebuilt, keypair_secp256k1.public_key)

    def test_r_and_s_are_positive_ints(self, keypair_secp256k1):
        sig = sign(b"data", keypair_secp256k1)
        r, s = signature_to_rs(sig)
        assert isinstance(r, int) and r > 0
        assert isinstance(s, int) and s > 0
