"""Tests for wire-format dataclasses (spec §4.3-§4.7 / §8.3)."""

from __future__ import annotations

import pytest

from mcp_attest.entry import (
    ZERO_HASH_HEX,
    AttestationEntry,
    Receipt,
    SignedRecord,
    SignedTreeHead,
)


def _make_entry(**overrides) -> AttestationEntry:
    base = {
        "seq": 0,
        "prev_hash": ZERO_HASH_HEX,
        "ts_request": 1_000_000.0,
        "ts_response": 1_000_001.0,
        "server_id": "tools.example.com",
        "request_id": "req-1",
        "method": "tools/call",
        "tool_name": "add",
        "params_hash": "ab" * 32,
        "result_hash": "cd" * 32,
        "status": "ok",
    }
    base.update(overrides)
    return AttestationEntry(**base)


class TestAttestationEntryRoundTrip:
    def test_to_dict_from_dict_round_trip(self):
        entry = _make_entry()
        assert AttestationEntry.from_dict(entry.to_dict()) == entry

    def test_from_dict_rejects_extra_keys(self):
        entry = _make_entry()
        d = entry.to_dict()
        d["smuggled"] = "bad"
        with pytest.raises(ValueError, match="unexpected keys"):
            AttestationEntry.from_dict(d)

    def test_from_dict_rejects_missing_keys(self):
        entry = _make_entry()
        d = entry.to_dict()
        del d["status"]
        with pytest.raises(ValueError, match="missing keys"):
            AttestationEntry.from_dict(d)

    def test_from_dict_rejects_bad_status(self):
        entry = _make_entry()
        d = entry.to_dict()
        d["status"] = "weird"
        with pytest.raises(ValueError, match="status must be"):
            AttestationEntry.from_dict(d)

    def test_tool_name_can_be_null(self):
        entry = _make_entry(method="initialize", tool_name=None)
        round_tripped = AttestationEntry.from_dict(entry.to_dict())
        assert round_tripped.tool_name is None


class TestCanonicalBytes:
    def test_canonical_bytes_stable_across_field_order(self):
        """Building from a shuffled dict must produce identical canonical bytes."""
        entry = _make_entry()
        d = entry.to_dict()
        shuffled = {k: d[k] for k in reversed(list(d.keys()))}
        reconstructed = AttestationEntry.from_dict(shuffled)
        assert reconstructed.to_canonical_bytes() == entry.to_canonical_bytes()


class TestSignedRecord:
    def test_entry_hash_is_64_hex_chars(self):
        record = SignedRecord(entry=_make_entry(), signature="aa" * 64)
        h = record.entry_hash()
        assert len(h) == 64
        bytes.fromhex(h)  # raises if not hex

    def test_entry_hash_is_stable_across_reserialization(self):
        record = SignedRecord(entry=_make_entry(), signature="aa" * 64)
        round_tripped = SignedRecord.from_dict(record.to_dict())
        assert round_tripped.entry_hash() == record.entry_hash()

    def test_entry_hash_covers_signature(self):
        """Mutating the signature must change entry_hash (spec §4.5)."""
        e = _make_entry()
        a = SignedRecord(entry=e, signature="aa" * 64)
        b = SignedRecord(entry=e, signature="bb" * 64)
        assert a.entry_hash() != b.entry_hash()

    def test_entry_hash_covers_entry_data(self):
        sig = "aa" * 64
        a = SignedRecord(entry=_make_entry(seq=0), signature=sig)
        b = SignedRecord(entry=_make_entry(seq=1), signature=sig)
        assert a.entry_hash() != b.entry_hash()

    def test_from_dict_rejects_extras(self):
        record = SignedRecord(entry=_make_entry(), signature="aa" * 64)
        d = record.to_dict()
        d["bogus"] = 1
        with pytest.raises(ValueError, match="unexpected keys"):
            SignedRecord.from_dict(d)

    def test_from_dict_rejects_missing(self):
        with pytest.raises(ValueError, match="requires"):
            SignedRecord.from_dict({"entry": _make_entry().to_dict()})

    def test_to_json_line_has_no_newline(self):
        record = SignedRecord(entry=_make_entry(), signature="aa" * 64)
        line = record.to_json_line()
        assert "\n" not in line


class TestReceipt:
    def test_receipt_round_trip(self):
        r = Receipt(seq=12, entry_hash="ff" * 32, signature="aa" * 64, server_id="srv")
        assert Receipt.from_dict(r.to_dict()) == r

    def test_from_dict_rejects_extras(self):
        r = Receipt(seq=1, entry_hash="ff" * 32, signature="aa" * 64, server_id="srv")
        d = r.to_dict()
        d["bogus"] = "junk"
        with pytest.raises(ValueError, match="unexpected keys"):
            Receipt.from_dict(d)

    def test_from_dict_rejects_missing(self):
        with pytest.raises(ValueError, match="missing keys"):
            Receipt.from_dict({"seq": 1, "entry_hash": "ff" * 32})


class TestSignedTreeHead:
    def test_to_canonical_payload_excludes_signature(self):
        """The signed payload must not include the signature itself (spec §4.7)."""
        sth = SignedTreeHead(
            chain_length=10,
            head_hash="aa" * 32,
            timestamp=1234.5,
            signature="bb" * 64,
        )
        payload = sth.to_canonical_payload()
        assert b"signature" not in payload
        # And it must include the three signed fields.
        assert b"chain_length" in payload
        assert b"head_hash" in payload
        assert b"timestamp" in payload

    def test_round_trip(self):
        sth = SignedTreeHead(
            chain_length=10,
            head_hash="aa" * 32,
            timestamp=1234.5,
            signature="bb" * 64,
        )
        assert SignedTreeHead.from_dict(sth.to_dict()) == sth

    def test_from_dict_rejects_extras(self):
        sth = SignedTreeHead(
            chain_length=1,
            head_hash="aa" * 32,
            timestamp=0.0,
            signature="bb" * 64,
        )
        d = sth.to_dict()
        d["smuggled"] = "field"
        with pytest.raises(ValueError, match="unexpected keys"):
            SignedTreeHead.from_dict(d)

    def test_from_dict_rejects_missing(self):
        with pytest.raises(ValueError, match="missing keys"):
            SignedTreeHead.from_dict({"chain_length": 1, "head_hash": "aa" * 32})


class TestZeroHashConstant:
    def test_zero_hash_is_64_hex_chars_of_zero(self):
        assert ZERO_HASH_HEX == "0" * 64
        assert bytes.fromhex(ZERO_HASH_HEX) == b"\x00" * 32
