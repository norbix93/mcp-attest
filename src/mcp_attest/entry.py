"""Wire-format dataclasses: AttestationEntry, SignedRecord, Receipt, STH.

These types are the *normative* schema for everything that hits disk or the
network. They are intentionally frozen dataclasses with explicit ``to_dict`` /
``from_dict`` boundaries so the JSON shape is reviewable in one place — no
hidden ``asdict`` magic that quietly serializes private fields.

Hex strings (not raw bytes) are used for hashes and signatures because the log
is a JSONL file meant to be human-inspectable; the canonicalizer never sees
``bytes`` so there's no encoding ambiguity.

Spec references: §4.3 (AttestationEntry), §4.4 (SignedRecord), §4.5 (entry
hash), §4.6 (Receipt), §4.7 (Signed Tree Head).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from mcp_attest import canonical, crypto

EntryStatus = Literal["ok", "error"]

# The hex form of 32 zero bytes — used as the genesis prev_hash and as the
# head_hash of an empty log per spec §4.3 and §4.7.
ZERO_HASH_HEX: str = "00" * 32


@dataclass(frozen=True)
class AttestationEntry:
    """Per-tool-call attestation record, pre-signature.

    Field order in this dataclass matches spec §4.3 for readability; canonical
    byte form sorts keys lexicographically, so on-disk order is independent of
    this declaration order.
    """

    seq: int
    prev_hash: str
    ts_request: float
    ts_response: float
    server_id: str
    request_id: str
    method: str
    tool_name: str | None
    params_hash: str
    result_hash: str
    status: EntryStatus

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable dict form used in the on-disk record."""
        return {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "ts_request": self.ts_request,
            "ts_response": self.ts_response,
            "server_id": self.server_id,
            "request_id": self.request_id,
            "method": self.method,
            "tool_name": self.tool_name,
            "params_hash": self.params_hash,
            "result_hash": self.result_hash,
            "status": self.status,
        }

    def to_canonical_bytes(self) -> bytes:
        """Return canonical JSON bytes — the input to ``Ed25519_sign``."""
        return canonical.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AttestationEntry:
        """Reconstruct an entry from its dict form.

        Unknown extra keys are rejected so accidental schema drift surfaces
        immediately rather than getting silently dropped on round-trip.
        """
        expected = {
            "seq",
            "prev_hash",
            "ts_request",
            "ts_response",
            "server_id",
            "request_id",
            "method",
            "tool_name",
            "params_hash",
            "result_hash",
            "status",
        }
        extra = set(d.keys()) - expected
        if extra:
            raise ValueError(f"unexpected keys in AttestationEntry: {sorted(extra)}")
        missing = expected - set(d.keys())
        if missing:
            raise ValueError(f"missing keys in AttestationEntry: {sorted(missing)}")
        status = d["status"]
        if status not in ("ok", "error"):
            raise ValueError(f"status must be 'ok' or 'error', got {status!r}")
        return cls(
            seq=int(d["seq"]),
            prev_hash=str(d["prev_hash"]),
            ts_request=float(d["ts_request"]),
            ts_response=float(d["ts_response"]),
            server_id=str(d["server_id"]),
            request_id=str(d["request_id"]),
            method=str(d["method"]),
            tool_name=None if d["tool_name"] is None else str(d["tool_name"]),
            params_hash=str(d["params_hash"]),
            result_hash=str(d["result_hash"]),
            status=status,
        )


@dataclass(frozen=True)
class SignedRecord:
    """An :class:`AttestationEntry` paired with an Ed25519 signature.

    One per JSONL line in the on-disk log. ``entry_hash()`` covers BOTH the
    entry data and the signature (spec §4.5), so tampering with either
    invalidates the chain linkage.
    """

    entry: AttestationEntry
    signature: str

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable dict form (one line in the on-disk JSONL)."""
        return {
            "entry": self.entry.to_dict(),
            "signature": self.signature,
        }

    def to_canonical_bytes(self) -> bytes:
        """Return canonical JSON bytes — input to :meth:`entry_hash`."""
        return canonical.dumps(self.to_dict())

    def to_json_line(self) -> str:
        """Return the JSONL representation (no trailing newline)."""
        return self.to_canonical_bytes().decode("utf-8")

    def entry_hash(self) -> str:
        """Return hex of ``blake2b(canonical(self.to_dict()))`` (spec §4.5)."""
        return crypto.hash_bytes(self.to_canonical_bytes()).hex()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignedRecord:
        """Reconstruct a :class:`SignedRecord` from its dict form, rejecting extras."""
        extra = set(d.keys()) - {"entry", "signature"}
        if extra:
            raise ValueError(f"unexpected keys in SignedRecord: {sorted(extra)}")
        if "entry" not in d or "signature" not in d:
            raise ValueError("SignedRecord requires 'entry' and 'signature' fields")
        return cls(
            entry=AttestationEntry.from_dict(d["entry"]),
            signature=str(d["signature"]),
        )


@dataclass(frozen=True)
class Receipt:
    """Per-call cryptographic receipt handed back to the caller.

    A caller holding (receipt, params, result, server_pubkey) can verify the
    specific tool call without seeing any other log entry — that's the
    independent-verification property called out in spec §4.6 / §6.6.
    """

    seq: int
    entry_hash: str
    signature: str
    server_id: str

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable dict form."""
        return {
            "seq": self.seq,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "server_id": self.server_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Receipt:
        """Reconstruct a :class:`Receipt` from its dict form.

        Like :meth:`AttestationEntry.from_dict`, this rejects both extra and
        missing keys so a malformed receipt fails with a typed ``ValueError``
        instead of a confusing ``KeyError`` deep inside verification.
        """
        expected = {"seq", "entry_hash", "signature", "server_id"}
        extra = set(d.keys()) - expected
        if extra:
            raise ValueError(f"unexpected keys in Receipt: {sorted(extra)}")
        missing = expected - set(d.keys())
        if missing:
            raise ValueError(f"missing keys in Receipt: {sorted(missing)}")
        return cls(
            seq=int(d["seq"]),
            entry_hash=str(d["entry_hash"]),
            signature=str(d["signature"]),
            server_id=str(d["server_id"]),
        )


@dataclass(frozen=True)
class SignedTreeHead:
    """Periodic commitment to log state, used for equivocation detection.

    Two valid STHs from the same server with identical ``chain_length`` but
    different ``head_hash`` is unforgeable proof of misbehavior — see
    :func:`mcp_attest.verifier.detect_equivocation`.
    """

    chain_length: int
    head_hash: str
    timestamp: float
    signature: str

    def to_canonical_payload(self) -> bytes:
        """Return canonical bytes of the *signed portion* (everything but the sig).

        This is the input fed to ``Ed25519_sign`` when minting the STH and to
        ``Ed25519_verify`` when checking one.
        """
        return canonical.dumps(
            {
                "chain_length": self.chain_length,
                "head_hash": self.head_hash,
                "timestamp": self.timestamp,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable dict form (signed payload + signature)."""
        return {
            "chain_length": self.chain_length,
            "head_hash": self.head_hash,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignedTreeHead:
        """Reconstruct a :class:`SignedTreeHead` from its dict form.

        Rejects both extra and missing keys so a malformed STH JSON (e.g.,
        from a peer or stale tooling) surfaces as a clean ``ValueError`` at
        the CLI / library boundary instead of a ``KeyError`` deep inside
        signature verification.
        """
        expected = {"chain_length", "head_hash", "timestamp", "signature"}
        extra = set(d.keys()) - expected
        if extra:
            raise ValueError(f"unexpected keys in SignedTreeHead: {sorted(extra)}")
        missing = expected - set(d.keys())
        if missing:
            raise ValueError(f"missing keys in SignedTreeHead: {sorted(missing)}")
        return cls(
            chain_length=int(d["chain_length"]),
            head_hash=str(d["head_hash"]),
            timestamp=float(d["timestamp"]),
            signature=str(d["signature"]),
        )
