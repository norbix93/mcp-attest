r"""Append-only, signed, hash-chained log on disk (spec §4.8 / §6.4).

Storage format is JSON Lines: one :class:`SignedRecord` per line. New records
are appended under an ``fcntl.flock`` exclusive lock on the log file so two
proxies sharing a log can't interleave half-written lines. The chain head is
re-read from disk under the same lock, so even crash-and-reopen flows pick up
the correct ``prev_hash`` without needing a separate index file.

Why ``flock`` instead of write-temp-and-rename: append semantics matter more
than atomic file replacement. Renaming a fresh copy of the file every append
would (a) be O(n) per call and (b) defeat any external "tail -f" auditor. The
write itself is a single ``writelines([line + "\n"])`` call, which on POSIX is
atomic for sub-PIPE_BUF-sized writes; the lock guards the head-hash read +
append sequence, not the byte-level write.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import time
import warnings
from collections.abc import Iterator
from pathlib import Path
from threading import Lock
from typing import Any, Literal

from mcp_attest import canonical, crypto
from mcp_attest.entry import (
    ZERO_HASH_HEX,
    AttestationEntry,
    Receipt,
    SignedRecord,
    SignedTreeHead,
)

_logger = logging.getLogger(__name__)


class AttestationLog:
    """Append-only signed log on disk in JSONL format.

    The log can be opened read-only (no private key) for verification, or
    read-write (with a private key) for the proxy's append path. Construction
    creates the file if it doesn't exist; an empty file is a valid empty log.

    Thread safety: an in-process :class:`threading.Lock` plus a process-level
    :func:`fcntl.flock` together make ``append()`` safe under both threaded
    and multi-process concurrent writers.
    """

    def __init__(
        self,
        path: Path,
        server_id: str,
        private_key: bytes | None = None,
    ) -> None:
        """Open (or create) the log at ``path``.

        Args:
            path: Filesystem path to the JSONL log.
            server_id: Identifier written into each entry's ``server_id`` field
                (e.g., ``"tools.example.com"``). Read-only callers can pass
                anything informative; it's only used on append.
            private_key: 32-byte Ed25519 private key. Required to call
                :meth:`append` or :meth:`emit_sth`; may be ``None`` for
                read/verify-only access.
        """
        self._path = Path(path)
        self._server_id = server_id
        self._private_key = private_key
        # In-process write lock — guards the read-head-then-append sequence so
        # threaded appends produce a valid chain. Cross-process safety is
        # provided by fcntl.flock inside the lock.
        self._write_lock = Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    @property
    def path(self) -> Path:
        """Return the on-disk path of the log."""
        return self._path

    @property
    def server_id(self) -> str:
        """Return the server identifier this log is bound to."""
        return self._server_id

    @property
    def chain_length(self) -> int:
        """Return the number of entries currently in the log."""
        return sum(1 for _ in self._iter_lines())

    @property
    def head_hash(self) -> str:
        """Return the entry_hash of the last record, or ZERO_HASH_HEX if empty."""
        last = self._last_record()
        return last.entry_hash() if last is not None else ZERO_HASH_HEX

    def append(
        self,
        method: str,
        request_id: str,
        params: Any,
        result_or_error: Any,
        status: Literal["ok", "error"],
        ts_request: float,
        ts_response: float,
    ) -> tuple[SignedRecord, Receipt]:
        """Atomically append a signed attestation record.

        Args:
            method: JSON-RPC method name (e.g., ``"tools/call"``).
            request_id: JSON-RPC request id, copied verbatim from the inbound call.
            params: Whatever was in the ``params`` field; ``None`` if absent.
            result_or_error: The ``result`` or ``error`` object from the response.
            status: ``"ok"`` for ``result`` responses, ``"error"`` for ``error`` ones.
            ts_request: Unix seconds when the request arrived at the proxy.
            ts_response: Unix seconds when the response came back from upstream.

        Returns:
            Tuple of the freshly written :class:`SignedRecord` and the
            corresponding :class:`Receipt` to hand back to the caller.

        Raises:
            RuntimeError: If the log was opened without a private key.
        """
        if self._private_key is None:
            raise RuntimeError(
                "AttestationLog opened read-only (no private_key) — cannot append"
            )

        tool_name = self._extract_tool_name(method, params)
        params_hash = crypto.hash_bytes(self._canonical_bytes(params))
        result_hash = crypto.hash_bytes(self._canonical_bytes(result_or_error))

        with self._write_lock, self._path.open("a+b") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                # Recompute seq + prev_hash under the lock so concurrent
                # writers in different processes can't both claim the same seq.
                fh.seek(0)
                last_record = _scan_last_record(fh)
                seq = 0 if last_record is None else last_record.entry.seq + 1
                prev_hash = (
                    ZERO_HASH_HEX if last_record is None else last_record.entry_hash()
                )

                entry = AttestationEntry(
                    seq=seq,
                    prev_hash=prev_hash,
                    ts_request=ts_request,
                    ts_response=ts_response,
                    server_id=self._server_id,
                    request_id=request_id,
                    method=method,
                    tool_name=tool_name,
                    params_hash=params_hash.hex(),
                    result_hash=result_hash.hex(),
                    status=status,
                )
                signature = crypto.sign(self._private_key, entry.to_canonical_bytes())
                record = SignedRecord(entry=entry, signature=signature.hex())

                fh.seek(0, 2)  # explicit seek-to-end belt-and-suspenders
                fh.write(record.to_json_line().encode("utf-8") + b"\n")
                fh.flush()
                # fsync isn't strictly required for log correctness (the chain
                # itself catches truncation), but enterprise auditors expect it.
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        receipt = Receipt(
            seq=record.entry.seq,
            entry_hash=record.entry_hash(),
            signature=record.signature,
            server_id=self._server_id,
        )
        _logger.debug("appended record seq=%d to %s", record.entry.seq, self._path)
        return record, receipt

    def emit_sth(self, *, timestamp: float | None = None) -> SignedTreeHead:
        """Produce a Signed Tree Head for the current log state (spec §4.7)."""
        if self._private_key is None:
            raise RuntimeError(
                "AttestationLog opened read-only (no private_key) — cannot emit STH"
            )
        chain_length = self.chain_length
        head = self.head_hash
        ts = time.time() if timestamp is None else timestamp
        payload = {
            "chain_length": chain_length,
            "head_hash": head,
            "timestamp": ts,
        }
        signature = crypto.sign(self._private_key, canonical.dumps(payload))
        return SignedTreeHead(
            chain_length=chain_length,
            head_hash=head,
            timestamp=ts,
            signature=signature.hex(),
        )

    def iter_records(self) -> Iterator[SignedRecord]:
        """Yield every :class:`SignedRecord` in the log in on-disk order."""
        for line in self._iter_lines():
            yield SignedRecord.from_dict(json.loads(line))

    def read_record(self, seq: int) -> SignedRecord:
        """Return the record at sequence ``seq``.

        Raises:
            IndexError: If ``seq`` is out of range.
            ValueError: If ``seq`` is negative.
        """
        if seq < 0:
            raise ValueError(f"seq must be non-negative, got {seq}")
        for i, line in enumerate(self._iter_lines()):
            if i == seq:
                return SignedRecord.from_dict(json.loads(line))
        raise IndexError(f"seq {seq} out of range (chain length: {self.chain_length})")

    def _iter_lines(self) -> Iterator[str]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line:
                    yield line

    def _last_record(self) -> SignedRecord | None:
        last: SignedRecord | None = None
        for record in self.iter_records():
            last = record
        return last

    @staticmethod
    def _canonical_bytes(value: Any) -> bytes:
        return canonical.dumps(value)

    @staticmethod
    def _extract_tool_name(method: str, params: Any) -> str | None:
        """Pull out ``params.name`` if method is ``tools/call``, else ``None``.

        Spec §4.3 binds ``tool_name`` to the JSON-RPC method semantics; this
        function is the only place that decoding lives, so the proxy and any
        future transport adapter use the same rule.
        """
        if method != "tools/call":
            return None
        if isinstance(params, dict):
            name = params.get("name")
            return str(name) if name is not None else None
        return None


def _scan_last_record(fh: Any) -> SignedRecord | None:
    """Stream the open file handle and return the last record, or ``None``.

    The handle is left at end-of-file; callers should ``seek(0, 2)`` before
    appending if they care about the explicit position.
    """
    last: SignedRecord | None = None
    fh.seek(0)
    for raw in fh:
        # ``raw`` is bytes because fh was opened in "a+b" mode.
        line = raw.decode("utf-8").strip()
        if not line:
            continue
        try:
            last = SignedRecord.from_dict(json.loads(line))
        except (ValueError, json.JSONDecodeError) as exc:
            # Don't silently skip — but don't crash an append either; warn
            # so operators can investigate while the writer remains live.
            warnings.warn(
                f"skipping malformed log line: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )
    return last
