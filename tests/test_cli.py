"""Tests for the ``mcp-attest`` CLI (spec §6.8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_attest import crypto
from mcp_attest.cli import main
from mcp_attest.log import AttestationLog


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestHelp:
    def test_top_level_help_lists_all_subcommands(self, runner: CliRunner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        for cmd in ["keygen", "verify", "inspect", "sth", "compare-sth", "demo"]:
            assert cmd in result.output


class TestKeygen:
    def test_keygen_produces_priv_and_pub(self, runner: CliRunner, tmp_path: Path):
        prefix = tmp_path / "srv"
        result = runner.invoke(main, ["keygen", "--out", str(prefix)])
        assert result.exit_code == 0, result.output

        priv_path = prefix.with_suffix(".priv")
        pub_path = prefix.with_suffix(".pub")
        assert priv_path.exists()
        assert pub_path.exists()
        assert priv_path.stat().st_size == 32
        assert pub_path.stat().st_size == 32
        # Derived pubkey must match the file on disk.
        assert crypto.public_key_from_private(priv_path.read_bytes()) == pub_path.read_bytes()


class TestVerify:
    def test_verify_passing_chain_exits_zero(
        self,
        runner: CliRunner,
        tmp_path: Path,
        populated_log: AttestationLog,
        keypair,
    ):
        _, pub = keypair
        pub_path = tmp_path / "srv.pub"
        pub_path.write_bytes(pub)
        result = runner.invoke(main, ["verify", str(populated_log.path), "--pubkey", str(pub_path)])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_verify_wrong_pubkey_exits_one(
        self,
        runner: CliRunner,
        tmp_path: Path,
        populated_log: AttestationLog,
    ):
        _, other_pub = crypto.generate_keypair()
        pub_path = tmp_path / "other.pub"
        pub_path.write_bytes(other_pub)
        result = runner.invoke(main, ["verify", str(populated_log.path), "--pubkey", str(pub_path)])
        assert result.exit_code == 1
        assert "tamper" in result.output.lower()

    def test_verify_bad_pubkey_length_exits_two(
        self,
        runner: CliRunner,
        tmp_path: Path,
        populated_log: AttestationLog,
    ):
        pub_path = tmp_path / "bad.pub"
        pub_path.write_bytes(b"too short")
        result = runner.invoke(main, ["verify", str(populated_log.path), "--pubkey", str(pub_path)])
        assert result.exit_code == 2


class TestInspect:
    def test_inspect_full_log(
        self, runner: CliRunner, populated_log: AttestationLog
    ):
        result = runner.invoke(main, ["inspect", str(populated_log.path)])
        assert result.exit_code == 0
        # Three records → three "---" separators.
        assert result.output.count("---") == 3
        # Each record has an entry block.
        assert '"entry"' in result.output

    def test_inspect_single_seq(
        self, runner: CliRunner, populated_log: AttestationLog
    ):
        result = runner.invoke(main, ["inspect", str(populated_log.path), "--seq", "1"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["entry"]["seq"] == 1

    def test_inspect_out_of_range_exits_two(
        self, runner: CliRunner, populated_log: AttestationLog
    ):
        result = runner.invoke(main, ["inspect", str(populated_log.path), "--seq", "99"])
        assert result.exit_code == 2


class TestSTH:
    def test_sth_emits_valid_signature(
        self,
        runner: CliRunner,
        tmp_path: Path,
        populated_log: AttestationLog,
        keypair,
    ):
        priv, pub = keypair
        priv_path = tmp_path / "srv.priv"
        priv_path.write_bytes(priv)
        pub_path = tmp_path / "srv.pub"
        pub_path.write_bytes(pub)
        result = runner.invoke(
            main,
            [
                "sth",
                str(populated_log.path),
                "--pubkey",
                str(pub_path),
                "--privkey",
                str(priv_path),
            ],
        )
        assert result.exit_code == 0, result.output
        sth_dict = json.loads(result.output)
        assert sth_dict["chain_length"] == 3
        assert "signature" in sth_dict

    def test_sth_rejects_mismatched_keypair(
        self,
        runner: CliRunner,
        tmp_path: Path,
        populated_log: AttestationLog,
        keypair,
    ):
        priv, _ = keypair
        # Use a DIFFERENT pubkey than the privkey derives.
        _, other_pub = crypto.generate_keypair()
        priv_path = tmp_path / "srv.priv"
        priv_path.write_bytes(priv)
        pub_path = tmp_path / "wrong.pub"
        pub_path.write_bytes(other_pub)
        result = runner.invoke(
            main,
            [
                "sth",
                str(populated_log.path),
                "--pubkey",
                str(pub_path),
                "--privkey",
                str(priv_path),
            ],
        )
        assert result.exit_code == 2


class TestCompareSTH:
    def _write_sth(self, log: AttestationLog, path: Path) -> None:
        sth = log.emit_sth()
        path.write_text(json.dumps(sth.to_dict()))

    def test_identical_sths_not_equivocation(
        self,
        runner: CliRunner,
        tmp_path: Path,
        populated_log: AttestationLog,
        keypair,
    ):
        _, pub = keypair
        pub_path = tmp_path / "srv.pub"
        pub_path.write_bytes(pub)
        sth_a = tmp_path / "a.json"
        sth_b = tmp_path / "b.json"
        self._write_sth(populated_log, sth_a)
        self._write_sth(populated_log, sth_b)
        result = runner.invoke(
            main, ["compare-sth", str(sth_a), str(sth_b), "--pubkey", str(pub_path)]
        )
        assert result.exit_code == 0
        assert "not equivocation" in result.output.lower()

    def test_forked_logs_proved_equivocation(
        self,
        runner: CliRunner,
        tmp_path: Path,
        keypair,
    ):
        priv, pub = keypair
        pub_path = tmp_path / "srv.pub"
        pub_path.write_bytes(pub)

        # Build two logs of the same length but with one differing entry.
        log_a = AttestationLog(tmp_path / "a.jsonl", server_id="srv", private_key=priv)
        log_b = AttestationLog(tmp_path / "b.jsonl", server_id="srv", private_key=priv)
        for log_ in (log_a, log_b):
            log_.append(
                method="ping",
                request_id="r1",
                params={"i": 1},
                result_or_error={"ok": True},
                status="ok",
                ts_request=1.0,
                ts_response=2.0,
            )
        # Now branch — different params at index 1.
        log_a.append(
            method="ping",
            request_id="r2",
            params={"i": 2},
            result_or_error={"ok": True},
            status="ok",
            ts_request=3.0,
            ts_response=4.0,
        )
        log_b.append(
            method="ping",
            request_id="r2",
            params={"i": "two"},
            result_or_error={"ok": True},
            status="ok",
            ts_request=3.0,
            ts_response=4.0,
        )
        sth_a_path = tmp_path / "a.sth.json"
        sth_b_path = tmp_path / "b.sth.json"
        sth_a_path.write_text(json.dumps(log_a.emit_sth().to_dict()))
        sth_b_path.write_text(json.dumps(log_b.emit_sth().to_dict()))

        result = runner.invoke(
            main,
            [
                "compare-sth",
                str(sth_a_path),
                str(sth_b_path),
                "--pubkey",
                str(pub_path),
            ],
        )
        assert result.exit_code == 1
        assert "equivocation" in result.output.lower()
