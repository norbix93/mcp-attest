"""Adversarial tamper-detection tests (spec §8.7).

Each test models a specific on-disk attack and asserts that the verifier
catches it at the first opportunity. Together they cover the four documented
attack patterns plus the "with the key, you can forge anything" sanity check
that pins our security model to key custody.

The attacks operate by rewriting the JSONL file in place — that is exactly
what an attacker with disk access would do, and what makes the chain
detection interesting.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_attest import crypto
from mcp_attest.entry import (
    ZERO_HASH_HEX,
    AttestationEntry,
    SignedRecord,
)
from mcp_attest.errors import HashMismatchError, SignatureInvalidError
from mcp_attest.log import AttestationLog
from mcp_attest.verifier import verify_chain, verify_receipt


def _rewrite_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _read_lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


def _populate(log: AttestationLog, n: int = 5) -> list:
    """Append ``n`` deterministic records and return the receipts in order."""
    receipts = []
    for i in range(n):
        _, receipt = log.append(
            method="tools/call",
            request_id=f"r{i}",
            params={"name": "echo", "arguments": {"text": f"hi-{i}"}},
            result_or_error={"content": [{"type": "text", "text": f"hi-{i}"}]},
            status="ok",
            ts_request=float(i),
            ts_response=float(i) + 0.1,
        )
        receipts.append(receipt)
    return receipts


class TestTamperResult:
    """Attack 1: mutate the result_hash field of a record in place."""

    def test_mutated_result_hash_is_caught_by_chain_verification(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        _populate(writable_log, n=5)
        lines = _read_lines(writable_log.path)
        record = json.loads(lines[2])
        # Flip one hex char in result_hash. This invalidates BOTH the signature
        # (since result_hash is in the signed payload) AND the chain linkage
        # (since the next record's prev_hash covers this record's entry_hash).
        original = record["entry"]["result_hash"]
        record["entry"]["result_hash"] = ("0" if original[0] != "0" else "1") + original[1:]
        lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        _rewrite_lines(writable_log.path, lines)

        result = verify_chain(writable_log, pub)
        assert result.ok is False
        assert result.first_failure_index == 2


class TestSwapEntries:
    """Attack 2: swap two adjacent records on disk."""

    def test_swap_breaks_chain_at_first_swapped_index(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        _populate(writable_log, n=5)
        lines = _read_lines(writable_log.path)
        lines[1], lines[2] = lines[2], lines[1]
        _rewrite_lines(writable_log.path, lines)
        result = verify_chain(writable_log, pub)
        assert result.ok is False
        # Whichever check fires first (seq or prev_hash), it must blame index 1
        # — that's the first record observably out of place.
        assert result.first_failure_index == 1


class TestDeleteEntry:
    """Attack 3: drop a record entirely."""

    def test_delete_middle_record_breaks_prev_hash_linkage(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        _populate(writable_log, n=5)
        lines = _read_lines(writable_log.path)
        del lines[2]  # remove what was originally seq=2
        _rewrite_lines(writable_log.path, lines)
        result = verify_chain(writable_log, pub)
        assert result.ok is False
        # After deleting seq=2, the line at index 2 is now the former seq=3 —
        # so the seq check (3 != 2) fires before prev_hash gets compared.
        assert result.first_failure_index == 2


class TestInsertForgedEntry:
    """Attack 4: insert a record signed by a *different* key."""

    def test_forged_entry_under_attacker_key_fails_signature_check(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        _populate(writable_log, n=5)
        # Mint a fresh attacker keypair and craft a valid-looking record at
        # position 2 — same seq/prev_hash as the original.
        attacker_priv, _ = crypto.generate_keypair()
        original_lines = _read_lines(writable_log.path)
        original_at_2 = SignedRecord.from_dict(json.loads(original_lines[2]))

        forged_entry = AttestationEntry(
            seq=2,
            prev_hash=original_at_2.entry.prev_hash,
            ts_request=999.0,
            ts_response=1000.0,
            server_id=writable_log.server_id,
            request_id="attacker-injected",
            method="tools/call",
            tool_name="echo",
            params_hash="aa" * 32,
            result_hash="bb" * 32,
            status="ok",
        )
        forged_sig = crypto.sign(attacker_priv, forged_entry.to_canonical_bytes())
        forged_record = SignedRecord(entry=forged_entry, signature=forged_sig.hex())
        original_lines[2] = forged_record.to_json_line()
        _rewrite_lines(writable_log.path, original_lines)

        result = verify_chain(writable_log, pub)
        assert result.ok is False
        assert result.first_failure_index == 2
        assert "signature invalid" in (result.reason or "")


class TestReceiptVerificationCatchesTamper:
    """A receipt is portable evidence — auditors don't need the whole log."""

    def test_receipt_verification_catches_mutated_result(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        receipts = _populate(writable_log, n=3)

        # Tamper with seq=1's result_hash in place.
        lines = _read_lines(writable_log.path)
        record = json.loads(lines[1])
        record["entry"]["result_hash"] = "ff" * 32
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        _rewrite_lines(writable_log.path, lines)

        # The auditor presents the receipt + the ORIGINAL params/result they
        # saw. Either the recomputed hash won't match the (tampered) record,
        # OR the signature won't match — either way it's a verification error.
        original_params = {"name": "echo", "arguments": {"text": "hi-1"}}
        original_result = {"content": [{"type": "text", "text": "hi-1"}]}
        with pytest.raises((SignatureInvalidError, HashMismatchError)):
            verify_receipt(
                receipt=receipts[1],
                params=original_params,
                result_or_error=original_result,
                server_public_key=pub,
                log=writable_log,
            )


class TestKeyCustodyBoundary:
    """Sanity-check the security model: with the key, you CAN forge a chain.

    This isn't a vulnerability — it's the load-bearing assumption of the
    threat model, and we pin it explicitly so future reviewers see what is
    and isn't in scope. mcp-attest defends against tamper, not key leak.
    """

    def test_with_correct_key_an_alternative_chain_is_internally_valid(
        self, tmp_path: Path, keypair
    ):
        priv, pub = keypair
        # Build TWO independent logs with the same key.
        legitimate = AttestationLog(
            tmp_path / "real.jsonl", server_id="srv", private_key=priv
        )
        legitimate.append(
            method="ping",
            request_id="r1",
            params={"a": 1},
            result_or_error={"ok": True},
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        forged = AttestationLog(
            tmp_path / "forged.jsonl", server_id="srv", private_key=priv
        )
        forged.append(
            method="ping",
            request_id="r1",
            params={"a": 999},  # different params, same key
            result_or_error={"ok": True},
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        # Both verify internally — chain detection cannot tell them apart.
        assert verify_chain(legitimate, pub).ok is True
        assert verify_chain(forged, pub).ok is True
        # But their head hashes diverge — this is exactly what equivocation
        # detection via STHs is designed to catch.
        assert legitimate.head_hash != forged.head_hash
        assert legitimate.read_record(0).entry.prev_hash == ZERO_HASH_HEX
