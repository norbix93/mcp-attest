"""End-to-end mcp-attest demo (spec §9): make calls, verify, tamper, equivocate."""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

# Make sibling example modules importable when the script is run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mock_mcp_client import call_through_proxy  # noqa: E402
from mock_mcp_server import handle_request  # noqa: E402

from mcp_attest import (  # noqa: E402
    AttestingProxy,
    crypto,
    detect_equivocation,
    verify_chain,
)
from mcp_attest.log import AttestationLog  # noqa: E402

GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
RESET = "\033[0m"
CHECK = f"{GREEN}✓{RESET}"
CROSS = f"{RED}✗{RESET}"


def _ok(msg: str) -> None:
    print(f"{CHECK} {msg}")


def _bad(msg: str) -> None:
    print(f"{CROSS} {msg}")


def _info(msg: str) -> None:
    print(f"{DIM}  {msg}{RESET}")


async def _make_calls(proxy: AttestingProxy) -> list:
    """Issue the five varied calls from spec §9 and return the receipts."""
    receipts = []
    calls = [
        ("tools/call", {"name": "add", "arguments": {"a": 2, "b": 3}}),
        ("tools/call", {"name": "echo", "arguments": {"text": "hello"}}),
        ("tools/list", None),
        ("tools/call", {"name": "fail", "arguments": {}}),
        ("tools/call", {"name": "add", "arguments": {"a": 100, "b": 200}}),
    ]
    for i, (method, params) in enumerate(calls, start=1):
        response, receipt = await call_through_proxy(proxy, method, params, request_id=i)
        receipts.append(receipt)
        status = "ok" if "result" in response else "error"
        _info(
            f"seq={receipt.seq} {method:<11} status={status} "
            f"entry_hash={receipt.entry_hash[:12]}…"
        )
    return receipts


def _tamper_entry_two(log_path: Path) -> None:
    """Replace the result_hash on entry 2 — exactly the attack in spec §9 step 8."""
    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[2])
    record["entry"]["result_hash"] = "ba" * 32
    lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_forked_log(path: Path, priv: bytes) -> AttestationLog:
    """Build a log of the same length as the main log but with one differing entry."""
    forked = AttestationLog(path, server_id="srv.demo", private_key=priv)
    # Mirror the first three calls verbatim, then diverge on call 4.
    forked.append(
        method="tools/call",
        request_id="1",
        params={"name": "add", "arguments": {"a": 2, "b": 3}},
        result_or_error={"content": [{"type": "text", "text": "5"}]},
        status="ok",
        ts_request=1.0,
        ts_response=1.1,
    )
    forked.append(
        method="tools/call",
        request_id="2",
        params={"name": "echo", "arguments": {"text": "hello"}},
        result_or_error={"content": [{"type": "text", "text": "hello"}]},
        status="ok",
        ts_request=2.0,
        ts_response=2.1,
    )
    forked.append(
        method="tools/list",
        request_id="3",
        params=None,
        result_or_error={"tools": []},
        status="ok",
        ts_request=3.0,
        ts_response=3.1,
    )
    # Divergence: same seq, different (params, result).
    forked.append(
        method="tools/call",
        request_id="4-FORK",
        params={"name": "echo", "arguments": {"text": "alternate-history"}},
        result_or_error={"content": [{"type": "text", "text": "alternate-history"}]},
        status="ok",
        ts_request=4.0,
        ts_response=4.1,
    )
    forked.append(
        method="tools/call",
        request_id="5",
        params={"name": "add", "arguments": {"a": 100, "b": 200}},
        result_or_error={"content": [{"type": "text", "text": "300"}]},
        status="ok",
        ts_request=5.0,
        ts_response=5.1,
    )
    return forked


def main() -> int:
    """Run the demo. Returns 0 on success."""
    workdir = Path(tempfile.mkdtemp(prefix="mcp-attest-demo-"))
    try:
        log_path = workdir / "attest.jsonl"
        forked_path = workdir / "attest-fork.jsonl"

        priv, pub = crypto.generate_keypair()
        log = AttestationLog(log_path, server_id="srv.demo", private_key=priv)
        proxy = AttestingProxy(upstream=handle_request, log=log)

        print(f"{DIM}mcp-attest demo — working dir: {workdir}{RESET}\n")

        print("1) Making 5 tool calls through the attesting proxy:")
        asyncio.run(_make_calls(proxy))

        print("\n2) Emitting a Signed Tree Head:")
        sth = log.emit_sth()
        _info(
            f"chain_length={sth.chain_length} head={sth.head_hash[:12]}… "
            f"sig={sth.signature[:12]}…"
        )

        print("\n3) Verifying the chain:")
        result = verify_chain(log, pub)
        if result.ok:
            _ok(f"chain verified ({result.chain_length} entries)")
        else:
            _bad(f"unexpected: clean chain failed verification: {result.reason}")
            return 1

        print("\n4) Tamper demonstration — modifying entry 2 in place:")
        _tamper_entry_two(log_path)
        after = verify_chain(log, pub)
        if after.ok:
            _bad("PROTOCOL REGRESSION: tamper went undetected!")
            return 1
        _bad(
            f"tamper detected at index {after.first_failure_index}: {after.reason}"
        )

        print("\n5) Equivocation demonstration — building a forked log:")
        forked = _build_forked_log(forked_path, priv)
        # Re-open the original log (post-tamper) with the key so we can mint an
        # STH against current disk state — the in-memory ``log`` object holds
        # no stale cache, but reopening makes the intent obvious.
        original_for_sth = AttestationLog(log_path, server_id="srv.demo", private_key=priv)
        sth_original = original_for_sth.emit_sth()
        sth_forked = forked.emit_sth()
        if detect_equivocation(sth_original, sth_forked, pub):
            _bad(
                f"equivocation proven: server forked at length "
                f"{sth_original.chain_length}"
            )
        else:
            _bad("equivocation NOT detected — STH state inconsistent")
            return 1

        print(f"\n{DIM}done.{RESET}")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
