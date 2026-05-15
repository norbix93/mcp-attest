"""Tests for AttestationLog append, chain linkage, persistence, concurrency (§8.4)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from mcp_attest import crypto
from mcp_attest.entry import ZERO_HASH_HEX
from mcp_attest.log import AttestationLog


class TestEmptyLog:
    def test_empty_log_chain_length_zero(self, writable_log: AttestationLog):
        assert writable_log.chain_length == 0

    def test_empty_log_head_hash_is_zero(self, writable_log: AttestationLog):
        assert writable_log.head_hash == ZERO_HASH_HEX

    def test_empty_log_iter_yields_nothing(self, writable_log: AttestationLog):
        assert list(writable_log.iter_records()) == []


class TestAppendAndChain:
    def test_single_append_seq_zero_prev_zero(self, writable_log: AttestationLog):
        record, receipt = writable_log.append(
            method="tools/call",
            request_id="x",
            params={"name": "add", "arguments": {"a": 1, "b": 2}},
            result_or_error={"content": "3"},
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        assert record.entry.seq == 0
        assert record.entry.prev_hash == ZERO_HASH_HEX
        assert receipt.seq == 0
        assert receipt.entry_hash == record.entry_hash()
        assert receipt.signature == record.signature

    def test_n_appends_yields_n_records(self, writable_log: AttestationLog):
        for i in range(5):
            writable_log.append(
                method="ping",
                request_id=f"r{i}",
                params={"i": i},
                result_or_error={"ok": True},
                status="ok",
                ts_request=float(i),
                ts_response=float(i) + 0.1,
            )
        assert writable_log.chain_length == 5
        records = list(writable_log.iter_records())
        assert [r.entry.seq for r in records] == [0, 1, 2, 3, 4]

    def test_prev_hash_links_to_previous_entry_hash(self, populated_log: AttestationLog):
        records = list(populated_log.iter_records())
        assert records[0].entry.prev_hash == ZERO_HASH_HEX
        for i in range(1, len(records)):
            assert records[i].entry.prev_hash == records[i - 1].entry_hash()

    def test_head_hash_tracks_last_entry(self, populated_log: AttestationLog):
        last = list(populated_log.iter_records())[-1]
        assert populated_log.head_hash == last.entry_hash()

    def test_signature_verifies_under_pubkey(
        self,
        populated_log: AttestationLog,
        keypair: tuple[bytes, bytes],
    ):
        _, pub = keypair
        for record in populated_log.iter_records():
            assert crypto.verify(
                pub,
                record.entry.to_canonical_bytes(),
                bytes.fromhex(record.signature),
            )


class TestToolNameExtraction:
    def test_tools_call_extracts_name(self, writable_log: AttestationLog):
        record, _ = writable_log.append(
            method="tools/call",
            request_id="r",
            params={"name": "echo", "arguments": {"text": "hi"}},
            result_or_error={"content": "hi"},
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        assert record.entry.tool_name == "echo"

    def test_non_tools_call_method_yields_null_tool_name(
        self, writable_log: AttestationLog
    ):
        record, _ = writable_log.append(
            method="initialize",
            request_id="r",
            params={"protocolVersion": "2024-11-05"},
            result_or_error={"capabilities": {}},
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        assert record.entry.tool_name is None

    def test_tools_list_method_yields_null_tool_name(
        self, writable_log: AttestationLog
    ):
        record, _ = writable_log.append(
            method="tools/list",
            request_id="r",
            params=None,
            result_or_error={"tools": []},
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        assert record.entry.tool_name is None

    def test_tools_call_missing_name_yields_null(self, writable_log: AttestationLog):
        record, _ = writable_log.append(
            method="tools/call",
            request_id="r",
            params={"arguments": {}},
            result_or_error={"content": ""},
            status="ok",
            ts_request=1.0,
            ts_response=2.0,
        )
        assert record.entry.tool_name is None


class TestPersistence:
    def test_log_persists_across_reopen(
        self,
        populated_log: AttestationLog,
        reopened_log_factory,
    ):
        before = list(populated_log.iter_records())
        reopened = reopened_log_factory(read_only=False)
        after = list(reopened.iter_records())
        assert before == after
        assert reopened.chain_length == 3
        assert reopened.head_hash == before[-1].entry_hash()

    def test_append_after_reopen_continues_chain(
        self,
        populated_log: AttestationLog,
        reopened_log_factory,
    ):
        original_head = populated_log.head_hash
        reopened = reopened_log_factory(read_only=False)
        record, _ = reopened.append(
            method="ping",
            request_id="post-reopen",
            params=None,
            result_or_error={"ok": True},
            status="ok",
            ts_request=99.0,
            ts_response=100.0,
        )
        assert record.entry.seq == 3
        assert record.entry.prev_hash == original_head

    def test_read_only_log_rejects_append(
        self, populated_log: AttestationLog, reopened_log_factory
    ):
        read_only = reopened_log_factory(read_only=True)
        with pytest.raises(RuntimeError, match="read-only"):
            read_only.append(
                method="x",
                request_id="x",
                params=None,
                result_or_error=None,
                status="ok",
                ts_request=1.0,
                ts_response=2.0,
            )

    def test_read_only_log_can_iter(
        self, populated_log: AttestationLog, reopened_log_factory
    ):
        ro = reopened_log_factory(read_only=True)
        assert ro.chain_length == 3


class TestReadRecord:
    def test_read_by_seq(self, populated_log: AttestationLog):
        all_records = list(populated_log.iter_records())
        for i, expected in enumerate(all_records):
            assert populated_log.read_record(i) == expected

    def test_read_out_of_range_raises(self, populated_log: AttestationLog):
        with pytest.raises(IndexError):
            populated_log.read_record(99)

    def test_read_negative_raises(self, populated_log: AttestationLog):
        with pytest.raises(ValueError, match="non-negative"):
            populated_log.read_record(-1)


class TestEmitSTH:
    def test_empty_log_sth(self, writable_log: AttestationLog, keypair):
        _, pub = keypair
        sth = writable_log.emit_sth(timestamp=1234.0)
        assert sth.chain_length == 0
        assert sth.head_hash == ZERO_HASH_HEX
        assert crypto.verify(pub, sth.to_canonical_payload(), bytes.fromhex(sth.signature))

    def test_populated_log_sth(self, populated_log: AttestationLog, keypair):
        _, pub = keypair
        sth = populated_log.emit_sth(timestamp=4242.0)
        assert sth.chain_length == 3
        assert sth.head_hash == populated_log.head_hash
        assert crypto.verify(pub, sth.to_canonical_payload(), bytes.fromhex(sth.signature))

    def test_emit_sth_requires_private_key(
        self, populated_log: AttestationLog, reopened_log_factory
    ):
        ro = reopened_log_factory(read_only=True)
        with pytest.raises(RuntimeError, match="read-only"):
            ro.emit_sth()


class TestConcurrentAppend:
    def test_two_threads_one_hundred_appends_each(self, log_path: Path, keypair):
        """Spec §8.4: 200 appends from two threads produce a valid chain."""
        priv, pub = keypair
        log = AttestationLog(log_path, server_id="t", private_key=priv)

        per_thread = 100

        def worker(tag: str) -> None:
            for i in range(per_thread):
                log.append(
                    method="ping",
                    request_id=f"{tag}-{i}",
                    params={"i": i},
                    result_or_error={"ok": True},
                    status="ok",
                    ts_request=float(i),
                    ts_response=float(i) + 0.1,
                )

        threads = [threading.Thread(target=worker, args=(t,)) for t in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert log.chain_length == 2 * per_thread

        # Linkage must hold across whatever interleaving happened.
        records = list(log.iter_records())
        assert records[0].entry.prev_hash == ZERO_HASH_HEX
        for i in range(1, len(records)):
            assert records[i].entry.seq == i
            assert records[i].entry.prev_hash == records[i - 1].entry_hash()
            assert crypto.verify(
                pub,
                records[i].entry.to_canonical_bytes(),
                bytes.fromhex(records[i].signature),
            )
