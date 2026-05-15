"""Tests for AttestingProxy (spec §6.5 / §8.6)."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_attest.log import AttestationLog
from mcp_attest.proxy import AttestingProxy


def _make_upstream(responses: list[dict[str, Any]]):
    """Build an async handler that returns ``responses`` in order, advancing the index per call."""
    calls: list[dict[str, Any]] = []
    iterator = iter(responses)

    async def handler(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        return next(iterator)

    handler.calls = calls  # type: ignore[attr-defined]
    return handler


class TestProxyForwarding:
    async def test_request_forwarded_unchanged(self, writable_log: AttestationLog):
        upstream = _make_upstream(
            [{"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}]
        )
        proxy = AttestingProxy(upstream=upstream, log=writable_log)

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 1, "b": 2}},
        }
        response, _ = await proxy.handle(request)

        # Upstream received the request verbatim.
        assert upstream.calls == [request]  # type: ignore[attr-defined]
        # Response returned verbatim.
        assert response == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}

    async def test_each_call_adds_one_entry(self, writable_log: AttestationLog):
        upstream = _make_upstream(
            [
                {"jsonrpc": "2.0", "id": i, "result": {"i": i}}
                for i in range(3)
            ]
        )
        proxy = AttestingProxy(upstream=upstream, log=writable_log)

        for i in range(3):
            await proxy.handle(
                {
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": {"name": "x", "arguments": {}},
                }
            )
        assert writable_log.chain_length == 3


class TestToolNameExtractionViaProxy:
    async def test_tools_call_captures_tool_name(self, writable_log: AttestationLog):
        upstream = _make_upstream([{"jsonrpc": "2.0", "id": 1, "result": {}}])
        proxy = AttestingProxy(upstream=upstream, log=writable_log)
        await proxy.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "hi"}},
            }
        )
        record = writable_log.read_record(0)
        assert record.entry.tool_name == "echo"

    async def test_other_methods_have_null_tool_name(
        self, writable_log: AttestationLog
    ):
        upstream = _make_upstream(
            [
                {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}},
            ]
        )
        proxy = AttestingProxy(upstream=upstream, log=writable_log)
        await proxy.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": None}
        )
        record = writable_log.read_record(0)
        assert record.entry.tool_name is None


class TestErrorAttestation:
    async def test_error_response_attested_with_status_error(
        self, writable_log: AttestationLog
    ):
        upstream = _make_upstream(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32000, "message": "tool failed"},
                }
            ]
        )
        proxy = AttestingProxy(upstream=upstream, log=writable_log)
        response, receipt = await proxy.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "fail", "arguments": {}},
            }
        )
        assert "error" in response
        record = writable_log.read_record(receipt.seq)
        assert record.entry.status == "error"


class TestRequestIdCoercion:
    async def test_int_id_coerced_to_string(self, writable_log: AttestationLog):
        upstream = _make_upstream([{"jsonrpc": "2.0", "id": 42, "result": {}}])
        proxy = AttestingProxy(upstream=upstream, log=writable_log)
        await proxy.handle(
            {"jsonrpc": "2.0", "id": 42, "method": "ping", "params": None}
        )
        record = writable_log.read_record(0)
        assert record.entry.request_id == "42"

    async def test_missing_id_falls_back_to_sentinel(
        self, writable_log: AttestationLog
    ):
        upstream = _make_upstream([{"jsonrpc": "2.0", "result": {}}])
        proxy = AttestingProxy(upstream=upstream, log=writable_log)
        await proxy.handle({"jsonrpc": "2.0", "method": "ping", "params": None})
        record = writable_log.read_record(0)
        assert record.entry.request_id == "<missing>"


class TestProxyDoesNotAttestProxyLevelFailures:
    async def test_upstream_exception_is_not_attested(
        self, writable_log: AttestationLog
    ):
        async def crashing(_req: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("upstream crashed")

        proxy = AttestingProxy(upstream=crashing, log=writable_log)
        with pytest.raises(RuntimeError, match="upstream crashed"):
            await proxy.handle(
                {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": None}
            )
        assert writable_log.chain_length == 0
