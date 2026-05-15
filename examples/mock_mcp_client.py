"""Tiny JSON-RPC client used by the demo and integration tests.

The demo calls :func:`call_through_proxy` to exercise the proxy in-process.
A separate HTTP-flavored helper is also provided for the optional over-the-wire
smoke test, which uses httpx so the runtime dep is the same one declared in
pyproject.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from mcp_attest.entry import Receipt
from mcp_attest.proxy import AttestingProxy


async def call_through_proxy(
    proxy: AttestingProxy,
    method: str,
    params: dict[str, Any] | None,
    request_id: int | str = 1,
) -> tuple[dict[str, Any], Receipt]:
    """Send a single JSON-RPC request through the proxy and return ``(response, receipt)``."""
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }
    return await proxy.handle(request)


def call_http(url: str, method: str, params: dict[str, Any] | None, request_id: int | str = 1) -> dict[str, Any]:
    """Issue a single JSON-RPC POST against ``url`` and return the response dict.

    Synchronous wrapper around httpx; used only by the optional HTTP smoke
    test where async ergonomics aren't worth the asyncio boilerplate.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }
    resp = httpx.post(url, content=json.dumps(payload), timeout=5.0)
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]
