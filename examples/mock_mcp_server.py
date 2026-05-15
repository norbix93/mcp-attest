"""Minimal MCP-shaped JSON-RPC server for the demo and tests.

This is intentionally NOT a real MCP SDK integration — it just speaks the
subset of the JSON-RPC shape that the proxy and demo exercise. Three tools:

* ``add(a, b) -> a + b``
* ``echo(text) -> text``
* ``fail()`` — always returns a JSON-RPC error

Plus ``initialize`` and ``tools/list`` so a client can do a realistic
handshake. The whole file is < 150 lines per spec §7.

The handler is exposed two ways:

* :func:`handle_request` as an async callable suitable for direct attachment
  to :class:`mcp_attest.AttestingProxy`.
* :func:`run_http_server` runs it on a free localhost port using stdlib
  ``http.server`` so the demo and integration tests can talk to it over the
  wire without pulling in a full HTTP framework.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

_logger = logging.getLogger(__name__)

_TOOLS = [
    {
        "name": "add",
        "description": "Return a + b for two integers.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
            "required": ["a", "b"],
        },
    },
    {
        "name": "echo",
        "description": "Return the text argument unchanged.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "fail",
        "description": "Always returns a JSON-RPC error (for testing error attestation).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _ok(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _err(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tools_call(request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments", {}) or {}
    if name == "add":
        a, b = int(arguments["a"]), int(arguments["b"])
        return _ok(request_id, {"content": [{"type": "text", "text": str(a + b)}]})
    if name == "echo":
        text = str(arguments.get("text", ""))
        return _ok(request_id, {"content": [{"type": "text", "text": text}]})
    if name == "fail":
        return _err(request_id, -32000, "tool 'fail' always fails (this is by design)")
    return _err(request_id, -32601, f"unknown tool: {name!r}")


async def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a JSON-RPC request to the right mock handler."""
    method = request.get("method")
    request_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return _ok(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-server", "version": "0.1.0"},
            },
        )
    if method == "tools/list":
        return _ok(request_id, {"tools": _TOOLS})
    if method == "tools/call":
        return _tools_call(request_id, params)
    return _err(request_id, -32601, f"method not found: {method!r}")


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON body")
            return
        import asyncio

        response = asyncio.run(handle_request(request))
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: Any) -> None:
        """Silence the default per-request stderr log."""


def run_http_server(host: str = "127.0.0.1", port: int = 0) -> tuple[HTTPServer, threading.Thread]:
    """Spin up the mock server in a background thread; return ``(server, thread)``.

    Caller is responsible for ``server.shutdown()`` when done. Pass ``port=0``
    to let the OS pick a free port (read it back via ``server.server_port``).
    """
    server = HTTPServer((host, port), _Handler)
    thread = threading.Thread(target=server.serve_forever, name="mock-mcp", daemon=True)
    thread.start()
    _logger.info("mock MCP server listening on %s:%d", host, server.server_port)
    return server, thread
