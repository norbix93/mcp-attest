"""Shared fixtures used across the test suite."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from mcp_attest import crypto
from mcp_attest.log import AttestationLog


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    """Fresh Ed25519 keypair per test."""
    return crypto.generate_keypair()


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    """Path to a not-yet-created log file inside the test's tmp directory."""
    return tmp_path / "attest.jsonl"


@pytest.fixture
def writable_log(log_path: Path, keypair: tuple[bytes, bytes]) -> AttestationLog:
    """An AttestationLog opened with a private key, ready for appends."""
    priv, _ = keypair
    return AttestationLog(log_path, server_id="test.example", private_key=priv)


@pytest.fixture
def populated_log(writable_log: AttestationLog) -> AttestationLog:
    """A log with three diverse entries: an ``add`` call, an ``echo`` call, and an error."""
    writable_log.append(
        method="tools/call",
        request_id="r1",
        params={"name": "add", "arguments": {"a": 2, "b": 3}},
        result_or_error={"content": [{"type": "text", "text": "5"}]},
        status="ok",
        ts_request=1.0,
        ts_response=2.0,
    )
    writable_log.append(
        method="tools/call",
        request_id="r2",
        params={"name": "echo", "arguments": {"text": "hi"}},
        result_or_error={"content": [{"type": "text", "text": "hi"}]},
        status="ok",
        ts_request=3.0,
        ts_response=4.0,
    )
    writable_log.append(
        method="tools/call",
        request_id="r3",
        params={"name": "fail", "arguments": {}},
        result_or_error={"code": -32000, "message": "tool error"},
        status="error",
        ts_request=5.0,
        ts_response=6.0,
    )
    return writable_log


@pytest.fixture
def reopened_log_factory(log_path: Path, keypair: tuple[bytes, bytes]):
    """Factory that re-instantiates the log at ``log_path`` with the same key."""
    priv, _ = keypair

    def _open(read_only: bool = False) -> AttestationLog:
        return AttestationLog(
            log_path,
            server_id="test.example",
            private_key=None if read_only else priv,
        )

    return _open


@pytest.fixture
def event_loop_policy() -> Iterator[None]:
    """Disable any asyncio policy customization to avoid bleed between tests."""
    return
