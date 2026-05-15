"""Tests for verifier: receipts, chain integrity, STH (spec §6.6 / §8.5)."""

from __future__ import annotations

import pytest

from mcp_attest import crypto
from mcp_attest.errors import (
    HashMismatchError,
    SignatureInvalidError,
)
from mcp_attest.log import AttestationLog
from mcp_attest.verifier import (
    detect_equivocation,
    verify_chain,
    verify_receipt,
    verify_sth,
)


class TestVerifyChain:
    def test_valid_chain_passes(self, populated_log: AttestationLog, keypair):
        _, pub = keypair
        result = verify_chain(populated_log, pub)
        assert result.ok is True
        assert result.first_failure_index is None
        assert result.reason is None
        assert result.chain_length == 3

    def test_empty_log_passes(self, writable_log: AttestationLog, keypair):
        _, pub = keypair
        result = verify_chain(writable_log, pub)
        assert result.ok is True
        assert result.chain_length == 0

    def test_wrong_pubkey_fails_at_first_record(
        self, populated_log: AttestationLog
    ):
        _, other_pub = crypto.generate_keypair()
        result = verify_chain(populated_log, other_pub)
        assert result.ok is False
        assert result.first_failure_index == 0
        assert result.reason is not None
        assert "signature invalid" in result.reason

    def test_three_record_chain_walks_in_order(
        self, populated_log: AttestationLog, keypair
    ):
        _, pub = keypair
        result = verify_chain(populated_log, pub)
        assert result.ok is True
        assert result.chain_length == 3


class TestVerifyReceipt:
    def test_receipt_for_recorded_call_succeeds(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        params = {"name": "add", "arguments": {"a": 1, "b": 2}}
        result_obj = {"content": [{"type": "text", "text": "3"}]}
        _, receipt = writable_log.append(
            method="tools/call",
            request_id="r",
            params=params,
            result_or_error=result_obj,
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        # Returns None on success.
        assert (
            verify_receipt(
                receipt=receipt,
                params=params,
                result_or_error=result_obj,
                server_public_key=pub,
                log=writable_log,
            )
            is None
        )

    def test_mutated_params_raises_hash_mismatch(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        params = {"name": "add", "arguments": {"a": 1, "b": 2}}
        result_obj = {"content": "3"}
        _, receipt = writable_log.append(
            method="tools/call",
            request_id="r",
            params=params,
            result_or_error=result_obj,
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        # Claim a different params blob.
        with pytest.raises(HashMismatchError, match="params_hash"):
            verify_receipt(
                receipt=receipt,
                params={"name": "add", "arguments": {"a": 1, "b": 99}},
                result_or_error=result_obj,
                server_public_key=pub,
                log=writable_log,
            )

    def test_mutated_result_raises_hash_mismatch(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        params = {"name": "echo", "arguments": {"text": "hi"}}
        result_obj = {"content": "hi"}
        _, receipt = writable_log.append(
            method="tools/call",
            request_id="r",
            params=params,
            result_or_error=result_obj,
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        with pytest.raises(HashMismatchError, match="result_hash"):
            verify_receipt(
                receipt=receipt,
                params=params,
                result_or_error={"content": "DIFFERENT"},
                server_public_key=pub,
                log=writable_log,
            )

    def test_wrong_pubkey_raises_signature_invalid(
        self, writable_log: AttestationLog, keypair
    ):
        params = {"name": "echo", "arguments": {"text": "hi"}}
        result_obj = {"content": "hi"}
        _, receipt = writable_log.append(
            method="tools/call",
            request_id="r",
            params=params,
            result_or_error=result_obj,
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        _, other_pub = crypto.generate_keypair()
        with pytest.raises(SignatureInvalidError):
            verify_receipt(
                receipt=receipt,
                params=params,
                result_or_error=result_obj,
                server_public_key=other_pub,
                log=writable_log,
            )

    def test_tampered_receipt_entry_hash_raises(
        self, writable_log: AttestationLog, keypair
    ):
        from mcp_attest.entry import Receipt

        _, pub = keypair
        params = {"name": "echo", "arguments": {"text": "hi"}}
        result_obj = {"content": "hi"}
        _, receipt = writable_log.append(
            method="tools/call",
            request_id="r",
            params=params,
            result_or_error=result_obj,
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        forged = Receipt(
            seq=receipt.seq,
            entry_hash="00" * 32,
            signature=receipt.signature,
            server_id=receipt.server_id,
        )
        with pytest.raises(HashMismatchError, match="entry_hash"):
            verify_receipt(
                receipt=forged,
                params=params,
                result_or_error=result_obj,
                server_public_key=pub,
                log=writable_log,
            )


class TestVerifySTH:
    def test_valid_sth(self, populated_log: AttestationLog, keypair):
        _, pub = keypair
        sth = populated_log.emit_sth(timestamp=100.0)
        assert verify_sth(sth, pub) is True

    def test_sth_signed_by_other_key_rejected(
        self, populated_log: AttestationLog
    ):
        sth = populated_log.emit_sth(timestamp=100.0)
        _, other_pub = crypto.generate_keypair()
        assert verify_sth(sth, other_pub) is False


class TestDetectEquivocation:
    def test_identical_sth_is_not_equivocation(
        self, populated_log: AttestationLog, keypair
    ):
        _, pub = keypair
        sth = populated_log.emit_sth(timestamp=100.0)
        # Same STH twice — same chain_length and head_hash → no fork.
        assert detect_equivocation(sth, sth, pub) is False

    def test_different_length_is_not_equivocation(
        self, populated_log: AttestationLog, keypair
    ):
        _, pub = keypair
        sth1 = populated_log.emit_sth(timestamp=100.0)
        populated_log.append(
            method="ping",
            request_id="z",
            params=None,
            result_or_error={"ok": True},
            status="ok",
            ts_request=200.0,
            ts_response=201.0,
        )
        sth2 = populated_log.emit_sth(timestamp=300.0)
        assert sth1.chain_length != sth2.chain_length
        assert detect_equivocation(sth1, sth2, pub) is False

    def test_one_invalid_sth_blocks_proof(
        self, populated_log: AttestationLog, keypair
    ):
        from mcp_attest.entry import SignedTreeHead

        _, pub = keypair
        good = populated_log.emit_sth(timestamp=100.0)
        # Construct a "valid-looking" but signature-broken STH.
        forged = SignedTreeHead(
            chain_length=good.chain_length,
            head_hash="ff" * 32,
            timestamp=100.0,
            signature="00" * 64,
        )
        # Same chain_length and differing head_hash — but we can't *prove* the
        # server minted the forgery, so the check must return False.
        assert detect_equivocation(good, forged, pub) is False
