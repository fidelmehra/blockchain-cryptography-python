# Blockchain Cryptography in Python

**Author: Fidel Mehra**

[![CI/CD](https://github.com/fidelmehra/blockchain-cryptography-python/actions/workflows/ci.yml/badge.svg)](https://github.com/fidelmehra/blockchain-cryptography-python/actions)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-quality, from-scratch implementation of blockchain cryptographic primitives and a fully working blockchain in pure Python — no external blockchain libraries. Every algorithm is implemented with full mathematical commentary.

---

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Blockchain Components](#blockchain-components)
- [API Reference](#api-reference)
- [Quick Start](#quick-start)
- [Docker](#docker)
- [Testing](#testing)
- [Notebook Demo](#notebook-demo)

---

## Overview

This project demonstrates the full cryptographic stack underpinning blockchain systems:

| Layer | Technology |
|---|---|
| Hashing | SHA-256, SHA-3-256, BLAKE2b, double-SHA256 |
| Digital Signatures | ECDSA over secp256k1 (Bitcoin curve) |
| Key Derivation | BIP-32 HD wallet derivation, PBKDF2 |
| Merkle Trees | Binary Merkle tree with audit-proof generation |
| Transactions | UTXO model with scriptPubKey / scriptSig |
| Consensus | Proof-of-Work (SHA-256d) with adjustable difficulty |
| P2P | asyncio peer-to-peer gossip protocol |
| Explorer | FastAPI REST explorer with Swagger UI |

---

## Architecture

```
blockchain-cryptography-python/
├── src/
│   ├── crypto/
│   │   ├── hashing.py        # SHA-256, SHA-3, BLAKE2b, double-SHA256, hash160
│   │   ├── signatures.py     # ECDSA keygen, sign, verify (secp256k1)
│   │   └── merkle.py         # Merkle tree, root, audit proof, verification
│   └── blockchain/
│       ├── transaction.py    # TxInput, TxOutput, Transaction, UTXO set
│       ├── wallet.py         # HD Wallet, BIP-32 key derivation, address encoding
│       ├── block.py          # BlockHeader, Block, coinbase transaction
│       ├── chain.py          # Blockchain, UTXO indexer, fork resolution
│       └── consensus.py      # ProofOfWork miner, difficulty adjustment
├── app/
│   └── main.py               # FastAPI blockchain explorer
├── tests/
│   ├── test_hashing.py
│   ├── test_signatures.py
│   ├── test_merkle.py
│   ├── test_blockchain.py
│   └── test_api.py
├── notebooks/
│   └── 01_crypto_demo.ipynb  # End-to-end walkthrough
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── requirements.txt
```

---

## Cryptographic Primitives

### Hashing (`src/crypto/hashing.py`)
- `sha256(data)` — Single SHA-256
- `double_sha256(data)` — SHA-256d (Bitcoin standard)
- `sha3_256(data)` — Ethereum-style Keccak/SHA-3
- `blake2b(data)` — Fast 256-bit BLAKE2b
- `hash160(data)` — RIPEMD-160(SHA-256(data)) for Bitcoin addresses
- `checksum(data)` — First 4 bytes of double-SHA256

### Digital Signatures (`src/crypto/signatures.py`)
- ECDSA over **secp256k1** using the `cryptography` library
- `generate_keypair()` → `(private_key, public_key)`
- `sign(private_key, message)` → DER-encoded signature
- `verify(public_key, message, signature)` → `bool`
- `pubkey_to_address(public_key)` → Base58Check P2PKH address
- `wif_encode / wif_decode` — Wallet Import Format

### Merkle Tree (`src/crypto/merkle.py`)
- Full binary Merkle tree from transaction IDs
- `merkle_root(txids)` — Compute root hash
- `audit_proof(txids, index)` — Generate sibling-hash proof path
- `verify_proof(txid, proof, root)` — Verify inclusion proof

---

## Blockchain Components

### Block (`src/blockchain/block.py`)
```
BlockHeader:
  version       : int
  prev_hash     : str   (double-SHA256 of previous header)
  merkle_root   : str   (Merkle root of tx IDs)
  timestamp     : int   (Unix epoch)
  bits          : int   (compact difficulty target)
  nonce         : int   (PoW solution)
```

### Consensus (`src/blockchain/consensus.py`)
- **Proof-of-Work**: mine nonce such that `double_sha256(header) < target`
- Difficulty retarget every 2016 blocks (Bitcoin schedule)
- `mine_block(block, target_bits)` → solved `Block`

### UTXO Wallet (`src/blockchain/wallet.py`)
- BIP-32 HD key derivation (master key → child keys)
- Derive external / internal (change) addresses
- Sign transactions with private key
- Balance tracking via UTXO set

---

## API Reference

The FastAPI explorer runs at `http://localhost:8000`. Swagger UI at `/docs`.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Liveness probe |
| GET | `/chain` | Full blockchain |
| GET | `/chain/height` | Current block height |
| GET | `/block/{hash}` | Block by hash |
| GET | `/block/height/{n}` | Block at height n |
| GET | `/tx/{txid}` | Transaction by ID |
| GET | `/address/{addr}` | Address UTXOs & balance |
| POST | `/tx/broadcast` | Submit signed transaction |
| POST | `/mine` | Mine next block (dev mode) |
| GET | `/mempool` | Pending transactions |
| POST | `/wallet/new` | Generate new HD wallet |
| GET | `/merkle/proof/{txid}` | Merkle audit proof |

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/fidelmehra/blockchain-cryptography-python
cd blockchain-cryptography-python
make install

# 2. Run the full blockchain demo
make demo

# 3. Start the API explorer
make serve
# Open http://localhost:8000/docs

# 4. Run tests
make test
```

---

## Docker

```bash
# Build and start all services
make docker-up

# Services:
#   API explorer  → http://localhost:8000/docs
#   Prometheus    → http://localhost:9090
```

---

## Testing

```
pytest tests/ -v --cov=src --cov=app
```

Test coverage targets:
- `test_hashing.py` — Hash correctness against NIST vectors
- `test_signatures.py` — ECDSA sign/verify, address encoding, WIF round-trip
- `test_merkle.py` — Root computation, audit proof generation & verification
- `test_blockchain.py` — Full chain: mine genesis → add blocks → UTXO consistency
- `test_api.py` — All REST endpoints with mocked chain state

---

## Notebook Demo

`notebooks/01_crypto_demo.ipynb` walks through every primitive interactively:
1. SHA-256 step-by-step
2. ECDSA keypair → sign → verify
3. Build a Merkle tree and generate inclusion proof
4. Construct and mine 5 blocks
5. UTXO spend simulation
6. HD wallet key derivation tree

---

*Built from scratch by Fidel Mehra — Newcastle upon Tyne, 2026*
