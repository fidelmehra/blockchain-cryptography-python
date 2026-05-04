"""
test_merkle.py — Unit tests for src/crypto/merkle.py
Author: Fidel Mehra
"""
import pytest
from src.crypto.merkle import (
    MerkleTree,
    build_merkle_tree,
    merkle_root,
    merkle_root_hex,
)


LEAVES_4 = [b"tx1", b"tx2", b"tx3", b"tx4"]
LEAVES_1 = [b"only"]
LEAVES_5 = [b"a", b"b", b"c", b"d", b"e"]  # odd → padding


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestMerkleTreeConstruction:
    def test_build_power_of_two(self):
        tree = MerkleTree(_raw_leaves=LEAVES_4)
        assert tree.leaf_count == 4

    def test_build_single_leaf(self):
        tree = MerkleTree(_raw_leaves=LEAVES_1)
        assert tree.leaf_count == 1
        assert len(tree.root) == 32

    def test_build_odd_leaves_pads(self):
        tree = MerkleTree(_raw_leaves=LEAVES_5)
        assert tree.leaf_count == 5
        assert len(tree.root) == 32

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            MerkleTree(_raw_leaves=[])

    def test_root_is_bytes(self):
        tree = build_merkle_tree(LEAVES_4)
        assert isinstance(tree.root, bytes)
        assert len(tree.root) == 32

    def test_root_hex_is_64_chars(self):
        h = merkle_root_hex(LEAVES_4)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_depth(self):
        # 4 leaves → depth = 3 (leaf layer + 2 parent layers)
        tree = MerkleTree(_raw_leaves=LEAVES_4)
        assert tree.depth == 3


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_leaves_same_root(self):
        assert merkle_root(LEAVES_4) == merkle_root(LEAVES_4)

    def test_different_order_different_root(self):
        r1 = merkle_root([b"a", b"b"])
        r2 = merkle_root([b"b", b"a"])
        assert r1 != r2

    def test_different_leaves_different_root(self):
        r1 = merkle_root([b"x", b"y"])
        r2 = merkle_root([b"x", b"z"])
        assert r1 != r2


# ---------------------------------------------------------------------------
# Proof generation & verification
# ---------------------------------------------------------------------------

class TestMerkleProof:
    @pytest.mark.parametrize("index", [0, 1, 2, 3])
    def test_proof_verifies(self, index):
        tree = build_merkle_tree(LEAVES_4)
        proof = tree.get_proof(index)
        assert MerkleTree.verify_proof(LEAVES_4[index], proof, tree.root)

    def test_wrong_leaf_fails(self):
        tree = build_merkle_tree(LEAVES_4)
        proof = tree.get_proof(0)
        assert not MerkleTree.verify_proof(b"wrong", proof, tree.root)

    def test_wrong_root_fails(self):
        tree = build_merkle_tree(LEAVES_4)
        proof = tree.get_proof(0)
        bad_root = bytes(32)  # all zeros
        assert not MerkleTree.verify_proof(LEAVES_4[0], proof, bad_root)

    def test_out_of_range_raises(self):
        tree = build_merkle_tree(LEAVES_4)
        with pytest.raises(IndexError):
            tree.get_proof(99)

    def test_single_leaf_proof(self):
        tree = build_merkle_tree(LEAVES_1)
        proof = tree.get_proof(0)
        assert MerkleTree.verify_proof(LEAVES_1[0], proof, tree.root)

    def test_proof_all_leaves_odd(self):
        tree = build_merkle_tree(LEAVES_5)
        for i, leaf in enumerate(LEAVES_5):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(leaf, proof, tree.root)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

class TestConvenienceFunctions:
    def test_merkle_root_bytes(self):
        r = merkle_root([b"hello"])
        assert isinstance(r, bytes)

    def test_merkle_root_hex_string(self):
        h = merkle_root_hex([b"hello"])
        assert isinstance(h, str)
