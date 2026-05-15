"""Verification routines: receipts, chain integrity, STH, equivocation (§4.9 / §6.6).

These are the *only* functions a relying party needs. They are intentionally
small and pure: given a log path (or open AttestationLog), a public key, and
the receipt/STH being checked, they answer yes/no plus the specific reason on
failure. No global state, no caching — re-running a verification is the same
work twice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp_attest import canonical, crypto
from mcp_attest.entry import (
    ZERO_HASH_HEX,
    Receipt,
    SignedRecord,
    SignedTreeHead,
)
from mcp_attest.errors import (
    ChainBrokenError,
    HashMismatchError,
    SignatureInvalidError,
)
from mcp_attest.log import AttestationLog


@dataclass(frozen=True)
class ChainVerificationResult:
    """Outcome of :func:`verify_chain`.

    ``ok`` is the headline answer; on ``ok=False`` the other fields point a
    human at the exact record that broke.
    """

    ok: bool
    chain_length: int
    first_failure_index: int | None
    reason: str | None


def verify_receipt(
    receipt: Receipt,
    params: Any,
    result_or_error: Any,
    server_public_key: bytes,
    log: AttestationLog,
) -> None:
    """Verify a single receipt against the (params, result) the caller observed.

    Each of the five checks (spec §4.9.2) maps to a distinct exception so a
    failed verification tells you *which* property broke, not just "something":

    1. Signature validates under the server's public key.
    2. ``params_hash`` recomputed from ``params`` matches the entry.
    3. ``result_hash`` recomputed from ``result_or_error`` matches the entry.
    4. ``entry_hash(record)`` matches the receipt's ``entry_hash``.
    5. ``receipt.signature`` matches the record's signature.

    Returns ``None`` on success. Raises a :class:`VerificationError` subclass
    on failure — callers can ``except VerificationError`` to handle generically
    or pattern-match on the specific subclass.
    """
    record = log.read_record(receipt.seq)

    if not crypto.verify(
        server_public_key,
        record.entry.to_canonical_bytes(),
        bytes.fromhex(record.signature),
    ):
        raise SignatureInvalidError(
            f"signature on record seq={receipt.seq} is invalid under given pubkey"
        )

    expected_params = crypto.hash_bytes(canonical.dumps(params)).hex()
    if expected_params != record.entry.params_hash:
        raise HashMismatchError(
            f"params_hash mismatch at seq={receipt.seq}: "
            f"recomputed {expected_params}, stored {record.entry.params_hash}"
        )

    expected_result = crypto.hash_bytes(canonical.dumps(result_or_error)).hex()
    if expected_result != record.entry.result_hash:
        raise HashMismatchError(
            f"result_hash mismatch at seq={receipt.seq}: "
            f"recomputed {expected_result}, stored {record.entry.result_hash}"
        )

    if record.entry_hash() != receipt.entry_hash:
        raise HashMismatchError(
            f"entry_hash mismatch at seq={receipt.seq}: "
            f"computed {record.entry_hash()}, receipt {receipt.entry_hash}"
        )

    if record.signature != receipt.signature:
        raise HashMismatchError(
            f"signature in receipt does not match record at seq={receipt.seq}"
        )


def verify_chain(
    log: AttestationLog,
    server_public_key: bytes,
) -> ChainVerificationResult:
    """Walk the entire log, checking signatures and hash-chain linkage.

    Returns a :class:`ChainVerificationResult` rather than raising — callers
    typically want the failure *index* for diagnostics, not just an exception.
    The first failure short-circuits; later breaks are unreported (you'd fix
    the first one and re-run anyway).
    """
    expected_prev = ZERO_HASH_HEX
    count = 0

    for i, record in enumerate(log.iter_records()):
        count = i + 1

        if record.entry.seq != i:
            return ChainVerificationResult(
                ok=False,
                chain_length=count,
                first_failure_index=i,
                reason=f"seq mismatch at line {i}: entry.seq={record.entry.seq}",
            )

        if record.entry.prev_hash != expected_prev:
            return ChainVerificationResult(
                ok=False,
                chain_length=count,
                first_failure_index=i,
                reason=(
                    f"prev_hash mismatch at seq={i}: "
                    f"expected {expected_prev}, got {record.entry.prev_hash}"
                ),
            )

        if not crypto.verify(
            server_public_key,
            record.entry.to_canonical_bytes(),
            bytes.fromhex(record.signature),
        ):
            return ChainVerificationResult(
                ok=False,
                chain_length=count,
                first_failure_index=i,
                reason=f"signature invalid at seq={i}",
            )

        expected_prev = record.entry_hash()

    return ChainVerificationResult(
        ok=True,
        chain_length=count,
        first_failure_index=None,
        reason=None,
    )


def verify_sth(
    sth: SignedTreeHead,
    server_public_key: bytes,
) -> bool:
    """Return True iff ``sth`` is signed by the given public key."""
    return crypto.verify(
        server_public_key,
        sth.to_canonical_payload(),
        bytes.fromhex(sth.signature),
    )


def detect_equivocation(
    sth_a: SignedTreeHead,
    sth_b: SignedTreeHead,
    server_public_key: bytes,
) -> bool:
    """Return True iff the two STHs are unforgeable equivocation evidence.

    Equivocation requires that both STHs are individually valid (so the server
    cannot deny minting either), have the same ``chain_length`` (so they're
    making claims about the same log position), but disagree on ``head_hash``
    (so they're claiming two histories). All three conditions must hold; if
    either signature is bad, the function returns False because we can't
    *prove* the server minted both.
    """
    if not verify_sth(sth_a, server_public_key):
        return False
    if not verify_sth(sth_b, server_public_key):
        return False
    if sth_a.chain_length != sth_b.chain_length:
        return False
    return sth_a.head_hash != sth_b.head_hash


# Re-export so callers can use ``except`` on these without re-importing errors.
__all__ = [
    "ChainBrokenError",
    "ChainVerificationResult",
    "HashMismatchError",
    "SignatureInvalidError",
    "detect_equivocation",
    "verify_chain",
    "verify_receipt",
    "verify_sth",
]
