"""End-to-end tests of the mock MCP server through the AttestingProxy.

These verify that the entire stack — mock server, proxy, log, verifier —
agrees on a single audit trail when wired together. If a future refactor
breaks the proxy → log → verifier contract, these tests fail loudly.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the examples/ tree importable for the test runner.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from mcp_attest import AttestingProxy, verify_chain, verify_receipt
from mcp_attest.log import AttestationLog
from mock_mcp_client import call_http, call_through_proxy
from mock_mcp_server import handle_request, run_http_server


class TestInProcessProxy:
    async def test_add_round_trip(self, writable_log: AttestationLog, keypair):
        _, pub = keypair
        proxy = AttestingProxy(upstream=handle_request, log=writable_log)
        response, receipt = await call_through_proxy(
            proxy,
            "tools/call",
            {"name": "add", "arguments": {"a": 2, "b": 3}},
        )
        assert response["result"]["content"][0]["text"] == "5"

        verify_receipt(
            receipt=receipt,
            params={"name": "add", "arguments": {"a": 2, "b": 3}},
            result_or_error=response["result"],
            server_public_key=pub,
            log=writable_log,
        )

    async def test_full_session_chain_valid(
        self, writable_log: AttestationLog, keypair
    ):
        _, pub = keypair
        proxy = AttestingProxy(upstream=handle_request, log=writable_log)

        await call_through_proxy(proxy, "initialize", {}, 1)
        await call_through_proxy(proxy, "tools/list", None, 2)
        await call_through_proxy(
            proxy, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 1}}, 3
        )
        await call_through_proxy(
            proxy, "tools/call", {"name": "fail", "arguments": {}}, 4
        )

        result = verify_chain(writable_log, pub)
        assert result.ok is True
        assert result.chain_length == 4

        # The fail call must be attested with status="error".
        fail_record = writable_log.read_record(3)
        assert fail_record.entry.status == "error"


class TestOverHTTP:
    def test_http_smoke_round_trip(self):
        server, thread = run_http_server(port=0)
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            resp = call_http(
                url,
                "tools/call",
                {"name": "echo", "arguments": {"text": "ping"}},
                request_id=99,
            )
            assert resp["result"]["content"][0]["text"] == "ping"
            assert resp["id"] == 99
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)
