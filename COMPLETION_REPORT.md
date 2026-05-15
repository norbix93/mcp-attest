# mcp-attest v0.1 — completion report

## Summary

Built a working, pip-installable Python package implementing the MCP-Attest
Protocol per the spec. The package wraps any MCP-shaped JSON-RPC server with
a transparent attesting proxy that produces an append-only, BLAKE2b
hash-chained, Ed25519-signed JSONL audit log. Per-call cryptographic
receipts allow independent verification without disclosing the rest of the
log; Signed Tree Heads enable cross-auditor equivocation detection. The CLI
exposes `keygen`, `verify`, `inspect`, `sth`, `compare-sth`, and `demo`
subcommands; the end-to-end demo runs in one terminal screen and
demonstrates clean verification, tamper detection, and equivocation proof.

## Decisions made under ambiguity

See [`DECISIONS.md`](DECISIONS.md) for the full eleven-entry list. Highlights:

1. Append-atomicity uses `fcntl.flock` (preserves append semantics, O(1) per
   call) rather than write-temp-and-rename.
2. JSON-RPC `id` values are string-coerced; absent/null becomes `"<missing>"`.
3. `chain_length` / `head_hash` re-walk the file each read (no cached
   index) — correctness over performance in v0.1.
4. `entry_hash` covers the signature (per spec §4.5), so chain verification
   alone catches both entry and signature tampering.
5. `fsync` on every append — matches enterprise auditor expectations.
6. CLI exit codes: 0 = success, 1 = verification failure, 2 = user error.
7. `sth` subcommand cross-checks the supplied keypair before minting, so a
   fat-fingered key path fails at operator time, not audit time.
8. `verify_receipt` raises typed exceptions; `verify_chain` returns a
   result dataclass (the failure *index* is load-bearing diagnostic data).
9. Mock server uses stdlib `http.server` for the wire-mode smoke test;
   `httpx` is the client (httpx has no server).
10. `crypto.verify` always returns False on bad input — structured failure
    reporting belongs at the verifier layer.
11. `examples/__init__.py` is empty; only there so test discovery and the
    CLI's `demo` subcommand can import sibling modules.

## Test results

* 157 tests collected, 157 passed, 0 failed.
* Coverage: 94% (target: ≥ 90%).
* `mypy --strict src/mcp_attest/` — clean, 9 files.
* `ruff check src/ tests/ examples/ scripts/` — clean.

Per-module coverage:

| Module        | Stmts | Cover |
|---------------|-------|-------|
| __init__.py   |     8 | 100%  |
| canonical.py  |    30 | 100%  |
| crypto.py     |    42 | 100%  |
| entry.py      |    80 | 100%  |
| errors.py     |     7 | 100%  |
| log.py        |   114 |  94%  |
| proxy.py      |    33 |  97%  |
| verifier.py   |    51 |  95%  |
| cli.py        |   114 |  83%  |
| **TOTAL**     |   479 |  94%  |

The uncovered lines are defensive paths: the malformed-log-line warning in
`log.py`, the self-verification fallback in the CLI's `sth` subcommand, and
the relative-path discovery branch of the CLI's `demo` subcommand (since
the demo is exercised directly in `test_demo.py`).

## `mcp-attest demo` output (captured verbatim, color codes stripped)

```
mcp-attest demo — working dir: /var/folders/.../mcp-attest-demo-x1pppk4l

1) Making 5 tool calls through the attesting proxy:
  seq=0 tools/call  status=ok    entry_hash=9b79fdaed2e9…
  seq=1 tools/call  status=ok    entry_hash=f140c5c32148…
  seq=2 tools/list  status=ok    entry_hash=0846f35607ff…
  seq=3 tools/call  status=error entry_hash=601b3fcdd5a8…
  seq=4 tools/call  status=ok    entry_hash=b8d2d2540445…

2) Emitting a Signed Tree Head:
  chain_length=5 head=b8d2d2540445… sig=7810f3a8bc94…

3) Verifying the chain:
✓ chain verified (5 entries)

4) Tamper demonstration — modifying entry 2 in place:
✗ tamper detected at index 2: signature invalid at seq=2

5) Equivocation demonstration — building a forked log:
✗ equivocation proven: server forked at length 5

done.
```

## Deviations from the spec

None of substance. Two minor notes:

* The `LICENSE` file is a stub pointing to the canonical Apache-2.0 text URL,
  with a TODO marker, as called out in spec §10.
* The `verify` CLI subcommand prints the `OK: ...` line on stdout (success)
  but error messages on stderr; the spec's wording allowed either.

## Suggested v0.2 next steps

From spec §13 plus observations during the build:

1. **Witness verification helper.** A small `mcp_attest.witness` module that
   fetches STHs from a server on a schedule and persists them to disk, à la
   CT log monitors. Enables real-world equivocation detection.
2. **Merkle-tree upgrade for inclusion proofs.** Replace the linear chain
   with a binary Merkle tree to support O(log n) inclusion proofs without
   replaying the whole log. Wire format already accommodates an extra
   top-level field (see PROTOCOL.md §10).
3. **Real MCP SDK integration.** A thin adapter wrapping `mcp` Python SDK
   servers with `AttestingProxy`. The proxy is already transport-agnostic;
   this is glue code, not protocol work.
4. **Performance benchmark.** Append throughput on a laptop CPU. Target
   from the spec: > 5,000 attested calls/sec.
5. **Cached chain head index.** A sidecar `attest.jsonl.head` file with the
   last record's hash + offset, so `chain_length` and `head_hash` become
   O(1) instead of O(n). Correctness is currently bought via re-scan
   (see DECISIONS.md #3).
6. **Key rotation ceremony.** v0.1 assumes one long-lived key per server.
   A documented procedure for key rotation — signed key-rotation entries in
   the log itself — would unblock production deployments past the first
   key's natural lifecycle.
