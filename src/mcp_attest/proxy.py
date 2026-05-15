"""Transport-agnostic attesting proxy (spec §6.5).

The proxy sits between an MCP client and an MCP server. It forwards JSON-RPC
requests verbatim, captures the response, and synchronously appends a signed
attestation record before handing the response back. Callers get the response
they would have gotten plus a :class:`Receipt`.

The wrapped upstream is a callable ``async (dict) -> dict`` so this same proxy
can sit behind an HTTP route, a stdio shim, or be called directly in tests.
There is no HTTP code in this file by design.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from mcp_attest.entry import Receipt
from mcp_attest.log import AttestationLog

_logger = logging.getLogger(__name__)

UpstreamHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class AttestingProxy:
    """Wrap an MCP-shaped JSON-RPC handler with append-only attestation.

    The wrapped ``upstream`` must implement::

        async def __call__(request: dict) -> dict: ...

    where ``request`` is a JSON-RPC 2.0 request object and the return value is
    the matching response. Errors from upstream (responses with an ``error``
    member) are still attested with ``status="error"`` — they are observable
    behavior the auditor will want a record of. Proxy-level failures (e.g.,
    the upstream raises an exception or returns a non-dict) are NOT attested,
    because there is no upstream response to commit to; the exception
    propagates and the caller sees no receipt.
    """

    def __init__(self, upstream: UpstreamHandler, log: AttestationLog) -> None:
        """Bind to an upstream handler and a writable :class:`AttestationLog`."""
        self._upstream = upstream
        self._log = log

    @property
    def log(self) -> AttestationLog:
        """Return the underlying log (useful for the demo to inspect state)."""
        return self._log

    async def handle(
        self, request: dict[str, Any]
    ) -> tuple[dict[str, Any], Receipt]:
        """Forward ``request``, attest the response, return ``(response, receipt)``.

        The request id, method, and params are read defensively — a malformed
        request that the upstream is willing to entertain still gets logged
        with whatever fields were present, so the audit trail reflects exactly
        what was sent. Missing ``id`` is logged as the literal string
        ``"<missing>"`` to keep the field non-nullable in the entry schema.
        """
        method = str(request.get("method", ""))
        request_id = self._stringify_request_id(request.get("id"))
        params = request.get("params")

        ts_request = time.time()
        response = await self._upstream(request)
        ts_response = time.time()

        status: str = "ok" if "result" in response else "error"
        attested_payload = response.get("result", response.get("error"))

        _, receipt = self._log.append(
            method=method,
            request_id=request_id,
            params=params,
            result_or_error=attested_payload,
            status=status,  # type: ignore[arg-type]
            ts_request=ts_request,
            ts_response=ts_response,
        )
        _logger.debug(
            "attested method=%s id=%s status=%s seq=%d",
            method,
            request_id,
            status,
            receipt.seq,
        )
        return response, receipt

    @staticmethod
    def _stringify_request_id(value: Any) -> str:
        """JSON-RPC allows int / str / null ids; the entry schema is str-only.

        We coerce ints to their string form and replace ``None`` with the
        sentinel ``"<missing>"`` so audit-log consumers can rely on the field
        always being present and non-empty.
        """
        if value is None:
            return "<missing>"
        return str(value)
