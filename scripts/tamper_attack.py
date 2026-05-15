"""Reproducible attack scenario: mutate a log on disk and prove detection.

Run as ``python scripts/tamper_attack.py``. Useful for demos and for newcomers
reading the codebase to *see* a tamper getting caught instead of just trusting
the test names.

Exit code is 0 if detection works (which is the *intended* outcome — the
script's job is to demonstrate that the protocol catches the attack), 1 if
verification erroneously passes (i.e., the protocol has regressed).
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

from mcp_attest import crypto
from mcp_attest.log import AttestationLog
from mcp_attest.verifier import verify_chain


def _populate(log: AttestationLog) -> None:
    log.append(
        method="tools/call",
        request_id="r-1",
        params={"name": "echo", "arguments": {"text": "alpha"}},
        result_or_error={"content": "alpha"},
        status="ok",
        ts_request=1.0,
        ts_response=1.1,
    )
    log.append(
        method="tools/call",
        request_id="r-2",
        params={"name": "echo", "arguments": {"text": "bravo"}},
        result_or_error={"content": "bravo"},
        status="ok",
        ts_request=2.0,
        ts_response=2.1,
    )
    log.append(
        method="tools/call",
        request_id="r-3",
        params={"name": "echo", "arguments": {"text": "charlie"}},
        result_or_error={"content": "charlie"},
        status="ok",
        ts_request=3.0,
        ts_response=3.1,
    )


def _mutate_middle_record(log_path: Path) -> None:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["entry"]["result_hash"] = "deadbeef" * 8  # 32 bytes hex
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    """Build a small log, tamper with it, and verify detection. Return 0 if detected."""
    workdir = Path(tempfile.mkdtemp(prefix="mcp-attest-tamper-"))
    try:
        log_path = workdir / "attack.jsonl"
        priv, pub = crypto.generate_keypair()
        log = AttestationLog(log_path, server_id="srv.example", private_key=priv)
        _populate(log)

        clean = verify_chain(log, pub)
        if not clean.ok:
            print(f"PRE-CHECK FAILED: untampered chain did not verify: {clean.reason}")
            return 1
        print(f"baseline OK: {clean.chain_length} entries, chain valid")

        _mutate_middle_record(log_path)
        after = verify_chain(log, pub)
        if after.ok:
            print("PROTOCOL REGRESSION: tamper went undetected!")
            return 1

        print(
            f"tamper detected at seq={after.first_failure_index}: {after.reason}"
        )
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
