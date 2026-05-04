"""
signatures.py — ECDSA digital signature operations.
Author: Fidel Mehra

Covers secp256k1 (Bitcoin/Ethereum) and NIST P-256 curves.
Provides key generation, signing, verification, and DER/PEM serialisation.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

from .hashing import sha256, double_sha256


# ---------------------------------------------------------------------------
# Supported curves
# ---------------------------------------------------------------------------

SECP256K1 = ec.SECP256K1()  # Bitcoin / Ethereum
P256 = ec.SECP256R1()       # NIST P-256


# ---------------------------------------------------------------------------
# Key-pair dataclass
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """An ECDSA private/public key pair."""
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey = field(init=False)

    def __post_init__(self) -> None:
        self.public_key = self.private_key.public_key()

    # --- serialisation ---

    def private_bytes_pem(self) -> bytes:
        """Return PEM-encoded private key (unencrypted)."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_bytes_pem(self) -> bytes:
        """Return PEM-encoded public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_bytes_uncompressed(self) -> bytes:
        """Return 65-byte uncompressed public key (0x04 || x || y)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def public_bytes_compressed(self) -> bytes:
        """Return 33-byte compressed public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

    def bitcoin_address(self) -> str:
        """Derive a simplified Base58Check-style address (educational use)."""
        pub = self.public_bytes_compressed()
        # HASH160 = RIPEMD160(SHA256(pub))
        h = hashlib.new("ripemd160", sha256(pub)).digest()
        # Version byte 0x00 (mainnet P2PKH)
        versioned = b"\x00" + h
        checksum = double_sha256(versioned)[:4]
        return _base58_encode(versioned + checksum)

    def ethereum_address(self) -> str:
        """Derive Ethereum-style address (last 20 bytes of Keccak-256(pubkey))."""
        from .hashing import keccak256
        pub_uncompressed = self.public_bytes_uncompressed()[1:]  # strip 0x04
        return "0x" + keccak256(pub_uncompressed)[-20:].hex()


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair(curve: ec.EllipticCurve = SECP256K1) -> KeyPair:
    """Generate a fresh ECDSA key pair on *curve*."""
    private_key = ec.generate_private_key(curve)
    return KeyPair(private_key=private_key)


def load_keypair_pem(pem: bytes) -> KeyPair:
    """Load a KeyPair from a PEM-encoded private key."""
    private_key = serialization.load_pem_private_key(pem, password=None)
    return KeyPair(private_key=private_key)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign(message: bytes, keypair: KeyPair, prehash: bool = True) -> bytes:
    """
    Sign *message* and return a DER-encoded signature.

    Parameters
    ----------
    message  : raw bytes to sign (will be SHA-256 hashed unless prehash=False)
    keypair  : KeyPair whose private key will sign
    prehash  : if True (default), apply SHA-256 before signing
    """
    if prehash:
        message = sha256(message)
    signature = keypair.private_key.sign(message, ec.ECDSA(hashes.Prehashed()))
    return signature


def sign_digest(digest: bytes, keypair: KeyPair) -> bytes:
    """Sign a pre-computed 32-byte digest directly."""
    return keypair.private_key.sign(digest, ec.ECDSA(hashes.Prehashed()))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(
    message: bytes,
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey,
    prehash: bool = True,
) -> bool:
    """
    Verify a DER-encoded *signature* over *message*.

    Returns True on success, False on failure.
    """
    try:
        if prehash:
            message = sha256(message)
        public_key.verify(signature, message, ec.ECDSA(hashes.Prehashed()))
        return True
    except InvalidSignature:
        return False


def verify_digest(
    digest: bytes,
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey,
) -> bool:
    """Verify a signature over a pre-computed digest."""
    try:
        public_key.verify(signature, digest, ec.ECDSA(hashes.Prehashed()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# DER <-> (r, s) conversion helpers
# ---------------------------------------------------------------------------

def signature_to_rs(der_sig: bytes) -> Tuple[int, int]:
    """Decode DER signature to (r, s) integers."""
    return decode_dss_signature(der_sig)


def rs_to_signature(r: int, s: int) -> bytes:
    """Encode (r, s) integers to DER signature bytes."""
    return encode_dss_signature(r, s)


# ---------------------------------------------------------------------------
# Base58 encoding (Bitcoin address)
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode *data* bytes to a Base58 string."""
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break
    num = int.from_bytes(data, "big")
    chars = []
    while num > 0:
        num, remainder = divmod(num, 58)
        chars.append(_BASE58_ALPHABET[remainder:remainder + 1])
    result = b"1" * count + b"".join(reversed(chars))
    return result.decode("ascii")
