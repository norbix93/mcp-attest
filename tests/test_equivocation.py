"""Adversarial equivocation-detection tests (spec §8.8).

Equivocation is the multi-auditor attack: the server presents one history to
auditor A and a different history of the same length to auditor B. With STHs
this is unforgeable evidence — *any* two valid STHs with the same chain_length
and different head_hash are proof that the server signed two histories.
"""

from __future__ import annotations

from pathlib import Path

from mcp_attest import crypto
from mcp_attest.entry import SignedTreeHead
from mcp_attest.log import AttestationLog
from mcp_attest.verifier import detect_equivocation


def _build_forked_logs(tmp_path: Path, priv: bytes, fork_at: int = 5) -> tuple[AttestationLog, AttestationLog]:
    """Two logs that share the first ``fork_at`` entries, then diverge.

    Same private key on both sides — the attacker is the server itself, so
    of course it can sign for both forks.
    """
    log_a = AttestationLog(tmp_path / "a.jsonl", server_id="srv", private_key=priv)
    log_b = AttestationLog(tmp_path / "b.jsonl", server_id="srv", private_key=priv)
    for i in range(fork_at):
        for log_ in (log_a, log_b):
            log_.append(
                method="ping",
                request_id=f"shared-{i}",
                params={"i": i},
                result_or_error={"ok": True},
                status="ok",
                ts_request=float(i),
                ts_response=float(i) + 0.1,
            )
    # Divergence — same seq, different params payloads.
    log_a.append(
        method="ping",
        request_id="fork-a",
        params={"branch": "a"},
        result_or_error={"ok": True},
        status="ok",
        ts_request=99.0,
        ts_response=100.0,
    )
    log_b.append(
        method="ping",
        request_id="fork-b",
        params={"branch": "b"},
        result_or_error={"ok": True},
        status="ok",
        ts_request=99.0,
        ts_response=100.0,
    )
    return log_a, log_b


class TestNotEquivocation:
    def test_same_log_two_sths_identical(self, populated_log: AttestationLog, keypair):
        _, pub = keypair
        sth1 = populated_log.emit_sth(timestamp=10.0)
        sth2 = populated_log.emit_sth(timestamp=20.0)
        # Different timestamps, same head — not a fork.
        assert sth1.head_hash == sth2.head_hash
        assert detect_equivocation(sth1, sth2, pub) is False

    def test_different_lengths_are_not_evidence(
        self, populated_log: AttestationLog, keypair
    ):
        _, pub = keypair
        sth_short = populated_log.emit_sth(timestamp=10.0)
        populated_log.append(
            method="ping",
            request_id="extra",
            params={"more": True},
            result_or_error={"ok": True},
            status="ok",
            ts_request=20.0,
            ts_response=21.0,
        )
        sth_long = populated_log.emit_sth(timestamp=22.0)
        assert sth_short.chain_length != sth_long.chain_length
        assert detect_equivocation(sth_short, sth_long, pub) is False


class TestEquivocationDetected:
    def test_forked_chains_yield_unforgeable_evidence(
        self, tmp_path: Path, keypair
    ):
        priv, pub = keypair
        log_a, log_b = _build_forked_logs(tmp_path, priv, fork_at=5)
        assert log_a.chain_length == log_b.chain_length == 6
        assert log_a.head_hash != log_b.head_hash

        sth_a = log_a.emit_sth(timestamp=100.0)
        sth_b = log_b.emit_sth(timestamp=101.0)

        # Same length, different heads, both signatures valid → proven fork.
        assert detect_equivocation(sth_a, sth_b, pub) is True


class TestInvalidSTHBlocksProof:
    def test_invalid_signature_means_no_proof(
        self, tmp_path: Path, keypair
    ):
        priv, pub = keypair
        log_a, _log_b = _build_forked_logs(tmp_path, priv, fork_at=3)
        good = log_a.emit_sth(timestamp=100.0)
        # Construct a head-mismatched STH but with garbage signature.
        forged = SignedTreeHead(
            chain_length=good.chain_length,
            head_hash="ee" * 32,
            timestamp=200.0,
            signature="00" * 64,
        )
        # We can't *prove* the server minted the forged STH, so the function
        # must return False — bad-faith auditors shouldn't be able to claim
        # equivocation by waving an unsigned STH around.
        assert detect_equivocation(good, forged, pub) is False

    def test_wrong_key_means_no_proof(
        self, tmp_path: Path, keypair
    ):
        priv, _real_pub = keypair
        log_a, log_b = _build_forked_logs(tmp_path, priv, fork_at=3)
        sth_a = log_a.emit_sth(timestamp=100.0)
        sth_b = log_b.emit_sth(timestamp=101.0)
        # Check against the wrong server's key.
        _, wrong_pub = crypto.generate_keypair()
        assert detect_equivocation(sth_a, sth_b, wrong_pub) is False
