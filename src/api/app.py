"""
app.py — FastAPI REST interface for the blockchain node.
Author: Fidel Mehra

Endpoints:
  GET  /                        — health check
  GET  /chain                   — full chain dump
  GET  /chain/height            — current height
  GET  /chain/validate          — chain integrity check
  GET  /blocks/{index}          — single block by index
  POST /transactions            — submit a new transaction
  POST /mine                    — mine pending transactions
  GET  /transactions/pending    — pending transaction pool
  POST /crypto/hash             — hash arbitrary data
  POST /crypto/keypair          — generate ECDSA key pair
  POST /crypto/sign             — sign a message
  POST /crypto/verify           — verify a signature
  POST /crypto/merkle           — compute Merkle root
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from ..blockchain.block import Transaction
from ..blockchain.chain import Blockchain
from ..crypto.hashing import HashAlgorithm, HashEngine
from ..crypto.merkle import merkle_root_hex
from ..crypto.signatures import generate_keypair, sign, verify


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Blockchain Cryptography API",
    description="Educational blockchain node exposing cryptographic primitives via REST.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Shared in-memory blockchain state
_blockchain: Blockchain = Blockchain(difficulty=3)


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    height: int
    difficulty: int


class TransactionRequest(BaseModel):
    sender: str = Field(..., description="Sender address or public key hex")
    recipient: str = Field(..., description="Recipient address")
    amount: float = Field(..., gt=0, description="Transfer amount (> 0)")
    fee: float = Field(0.0, ge=0, description="Optional transaction fee")


class MineRequest(BaseModel):
    miner_address: str = Field(..., description="Address to receive the block reward")
    reward: float = Field(50.0, gt=0)


class HashRequest(BaseModel):
    data: str = Field(..., description="UTF-8 string to hash")
    algorithm: str = Field("sha256", description="sha256 | sha3_256 | blake2b | double_sha256")


class HashResponse(BaseModel):
    algorithm: str
    hex: str


class KeypairResponse(BaseModel):
    private_key_pem: str
    public_key_pem: str
    public_key_compressed_hex: str
    bitcoin_address: str
    ethereum_address: str


class SignRequest(BaseModel):
    message: str
    private_key_pem: str


class SignResponse(BaseModel):
    signature_hex: str
    message: str


class VerifyRequest(BaseModel):
    message: str
    signature_hex: str
    public_key_pem: str


class VerifyResponse(BaseModel):
    valid: bool


class MerkleRequest(BaseModel):
    leaves: List[str] = Field(..., description="List of UTF-8 strings to build tree from")


class MerkleResponse(BaseModel):
    root_hex: str
    leaf_count: int


# ---------------------------------------------------------------------------
# Health / chain endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_model=HealthResponse, tags=["Health"])
def health() -> HealthResponse:
    """Return node status."""
    return HealthResponse(
        status="ok",
        height=_blockchain.height,
        difficulty=_blockchain.difficulty,
    )


@app.get("/chain", tags=["Chain"])
def get_chain() -> Dict[str, Any]:
    """Return the full chain as JSON."""
    return _blockchain.to_dict()


@app.get("/chain/height", tags=["Chain"])
def get_height() -> Dict[str, int]:
    return {"height": _blockchain.height}


@app.get("/chain/validate", tags=["Chain"])
def validate_chain() -> Dict[str, bool]:
    """Validate chain integrity."""
    return {"valid": _blockchain.is_valid()}


@app.get("/blocks/{index}", tags=["Chain"])
def get_block(index: int) -> Dict[str, Any]:
    """Return the block at *index*."""
    if index < 0 or index >= _blockchain.height:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Block {index} not found (height={_blockchain.height}).",
        )
    return _blockchain.chain[index].to_dict()


# ---------------------------------------------------------------------------
# Transaction endpoints
# ---------------------------------------------------------------------------

@app.post("/transactions", status_code=status.HTTP_201_CREATED, tags=["Transactions"])
def submit_transaction(req: TransactionRequest) -> Dict[str, str]:
    """Add a transaction to the pending pool."""
    tx = Transaction(
        sender=req.sender,
        recipient=req.recipient,
        amount=req.amount,
        fee=req.fee,
    )
    _blockchain.add_transaction(tx)
    return {"tx_id": tx.tx_id, "status": "pending"}


@app.get("/transactions/pending", tags=["Transactions"])
def get_pending() -> Dict[str, Any]:
    """Return the current pending transaction pool."""
    return {
        "count": len(_blockchain.pending_transactions),
        "transactions": [tx.to_dict() for tx in _blockchain.pending_transactions],
    }


@app.post("/mine", tags=["Mining"])
def mine_block(req: MineRequest) -> Dict[str, Any]:
    """Mine pending transactions into a new block."""
    if not _blockchain.pending_transactions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending transactions to mine.",
        )
    block = _blockchain.mine_pending_transactions(
        miner_reward_address=req.miner_address,
        reward=req.reward,
    )
    return {"mined": True, "block": block.to_dict()}


# ---------------------------------------------------------------------------
# Cryptography endpoints
# ---------------------------------------------------------------------------

_ALGO_MAP = {
    "sha256": HashAlgorithm.SHA256,
    "sha3_256": HashAlgorithm.SHA3_256,
    "blake2b": HashAlgorithm.BLAKE2B,
    "double_sha256": HashAlgorithm.DOUBLE_SHA256,
    "keccak256": HashAlgorithm.KECCAK256,
}


@app.post("/crypto/hash", response_model=HashResponse, tags=["Crypto"])
def hash_data(req: HashRequest) -> HashResponse:
    """Hash arbitrary UTF-8 data with the requested algorithm."""
    algo = _ALGO_MAP.get(req.algorithm.lower())
    if algo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm '{req.algorithm}'. Choose from: {list(_ALGO_MAP)}.",
        )
    engine = HashEngine(algo)
    return HashResponse(algorithm=req.algorithm, hex=engine.hash_hex(req.data))


@app.post("/crypto/keypair", response_model=KeypairResponse, tags=["Crypto"])
def new_keypair() -> KeypairResponse:
    """Generate a fresh secp256k1 key pair."""
    kp = generate_keypair()
    return KeypairResponse(
        private_key_pem=kp.private_bytes_pem().decode(),
        public_key_pem=kp.public_bytes_pem().decode(),
        public_key_compressed_hex=kp.public_bytes_compressed().hex(),
        bitcoin_address=kp.bitcoin_address(),
        ethereum_address=kp.ethereum_address(),
    )


@app.post("/crypto/sign", response_model=SignResponse, tags=["Crypto"])
def sign_message(req: SignRequest) -> SignResponse:
    """Sign a UTF-8 message with the provided PEM private key."""
    from ..crypto.signatures import load_keypair_pem
    try:
        kp = load_keypair_pem(req.private_key_pem.encode())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid PEM key: {exc}")
    sig = sign(req.message.encode(), kp)
    return SignResponse(signature_hex=sig.hex(), message=req.message)


@app.post("/crypto/verify", response_model=VerifyResponse, tags=["Crypto"])
def verify_signature(req: VerifyRequest) -> VerifyResponse:
    """Verify an ECDSA signature."""
    from cryptography.hazmat.primitives import serialization
    try:
        pub_key = serialization.load_pem_public_key(req.public_key_pem.encode())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid PEM key: {exc}")
    sig_bytes = bytes.fromhex(req.signature_hex)
    ok = verify(req.message.encode(), sig_bytes, pub_key)
    return VerifyResponse(valid=ok)


@app.post("/crypto/merkle", response_model=MerkleResponse, tags=["Crypto"])
def compute_merkle(req: MerkleRequest) -> MerkleResponse:
    """Build a Merkle tree from a list of strings and return the root."""
    if not req.leaves:
        raise HTTPException(status_code=400, detail="Leaf list must not be empty.")
    leaves_bytes = [leaf.encode() for leaf in req.leaves]
    return MerkleResponse(
        root_hex=merkle_root_hex(leaves_bytes),
        leaf_count=len(req.leaves),
    )
