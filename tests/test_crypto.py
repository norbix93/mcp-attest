"""Tests for crypto primitives (spec §6.2 / §8.2)."""

from __future__ import annotations

import pytest

from mcp_attest import crypto


class TestKeypair:
    def test_keypair_byte_lengths(self):
        priv, pub = crypto.generate_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_keypairs_are_distinct_per_call(self):
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()
        assert priv_a != priv_b
        assert pub_a != pub_b

    def test_public_key_from_private_matches_generation(self):
        priv, pub = crypto.generate_keypair()
        assert crypto.public_key_from_private(priv) == pub

    def test_public_key_from_private_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="private_key must be 32 bytes"):
            crypto.public_key_from_private(b"too-short")


class TestSignVerify:
    def test_sign_produces_64_byte_signature(self):
        priv, _ = crypto.generate_keypair()
        sig = crypto.sign(priv, b"message")
        assert len(sig) == 64

    def test_sign_then_verify_succeeds(self):
        priv, pub = crypto.generate_keypair()
        msg = b"the quick brown fox"
        sig = crypto.sign(priv, msg)
        assert crypto.verify(pub, msg, sig) is True

    def test_verify_with_wrong_pubkey_returns_false(self):
        priv, _ = crypto.generate_keypair()
        _, other_pub = crypto.generate_keypair()
        sig = crypto.sign(priv, b"hello")
        assert crypto.verify(other_pub, b"hello", sig) is False

    def test_verify_with_mutated_message_returns_false(self):
        priv, pub = crypto.generate_keypair()
        sig = crypto.sign(priv, b"hello")
        assert crypto.verify(pub, b"hallo", sig) is False

    def test_verify_with_mutated_signature_returns_false(self):
        priv, pub = crypto.generate_keypair()
        sig = bytearray(crypto.sign(priv, b"hello"))
        sig[0] ^= 0xFF
        assert crypto.verify(pub, b"hello", bytes(sig)) is False

    def test_verify_never_raises_on_malformed_inputs(self):
        # Verify is documented to return False rather than raise.
        _, pub = crypto.generate_keypair()
        assert crypto.verify(b"", b"msg", b"") is False
        # Wrong-length pubkey / sig should also yield False without raising.
        assert crypto.verify(b"\x00" * 31, b"msg", b"\x00" * 64) is False
        assert crypto.verify(pub, b"msg", b"\x00" * 63) is False
        # Real-length but garbage signature must not raise either.
        assert crypto.verify(pub, b"msg", b"\xff" * 64) is False

    def test_sign_is_deterministic(self):
        """Ed25519 is deterministic — same key + message must yield same sig."""
        priv, _ = crypto.generate_keypair()
        assert crypto.sign(priv, b"x") == crypto.sign(priv, b"x")

    def test_sign_rejects_wrong_length_key(self):
        with pytest.raises(ValueError, match="private_key must be 32 bytes"):
            crypto.sign(b"too-short", b"msg")


class TestHashBytes:
    def test_hash_is_32_bytes(self):
        assert len(crypto.hash_bytes(b"anything")) == 32

    def test_hash_distinguishes_inputs(self):
        assert crypto.hash_bytes(b"") != crypto.hash_bytes(b"x")
        assert crypto.hash_bytes(b"a") != crypto.hash_bytes(b"b")

    def test_hash_is_stable(self):
        assert crypto.hash_bytes(b"repeat me") == crypto.hash_bytes(b"repeat me")
