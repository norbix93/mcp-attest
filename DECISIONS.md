# Design decisions

This file captures non-obvious choices made during the v0.1 build, both to
document the spec ambiguities resolved (§0.5 of the brief asks for this) and
to leave breadcrumbs for future contributors.

## 1. Log persistence — flock, not write-rename

The spec leaves the choice of atomic-append mechanism open ("write to temp +
fsync + rename, or use file lock — either is acceptable"). We chose
`fcntl.flock(LOCK_EX)` because:

* It preserves append semantics that external auditors expect (`tail -f`
  works against a live log).
* It is O(1) per call rather than O(n) (a rename-the-whole-file approach
  would copy the entire log on every write).
* It composes with an in-process `threading.Lock`, giving correctness under
  both threaded and multi-process writers.

The single `writelines` call after canonicalization is sub-`PIPE_BUF` for
realistic entry sizes (typical entry: a few hundred bytes), so the kernel
treats the byte-level write as atomic; the lock guards the *head read +
append* sequence, not the write itself.

## 2. JSON-RPC request id — string-coerced with `"<missing>"` sentinel

JSON-RPC 2.0 allows ids to be int / str / null. The entry schema declares
`request_id: str`, so the proxy coerces ints to their string form and
substitutes the literal `"<missing>"` for null/absent. Audit-log consumers
can then rely on the field always being a present, non-empty string.

## 3. STH does not cache; chain length re-walks the file

`AttestationLog.chain_length` and `head_hash` re-scan the file on every
read. For v0.1 this keeps the code obvious and avoids a class of bugs where
a stale cache lies about state after a concurrent writer extends the log.
v0.2 may add a small cached index alongside the JSONL for O(1) reads —
that's a performance optimization, not a correctness one.

## 4. Entry hash covers the signature

Spec §4.5 specifies `entry_hash = BLAKE2b(canonical(signed_record))`, i.e.,
the hash includes the signature bytes. This is the slightly less obvious of
the two reasonable choices (the other being to hash only the entry payload
and rely on the signature standing alone). We followed the spec — covering
the signature means a tamper to *either* the entry data OR the signature
propagates into the next record's `prev_hash`, so chain verification on its
own is sufficient to detect both attacks.

## 5. fsync on every append

We call `os.fsync()` after every append. This is slower than batching but
matches enterprise auditor expectations: a power-cycle should never leave
the log with attested records in the page cache but not on disk.

## 6. CLI exit codes are application-specific, not BSD `sysexits.h`

We use:
* 0 — success
* 1 — verification failed
* 2 — user error

This deliberately differs from `sysexits.h` (where 1 is "general failure")
because the distinction between "you gave me bad arguments" (2) and "the
verifier ran and said no" (1) is the load-bearing signal for CI workflows
gating on attestation health.

## 7. CLI `sth` cross-checks the keypair

The `sth` subcommand verifies that the supplied `--privkey` derives to the
supplied `--pubkey` before emitting. A fat-fingered key path would
otherwise mint an STH nobody can verify — caught at operator time instead
of audit time.

## 8. Receipt verification raises; chain verification returns a result

`verify_receipt` raises `VerificationError` subclasses, while `verify_chain`
returns a `ChainVerificationResult`. The asymmetry is deliberate:

* A bad receipt is a binary "this call wasn't attested" — callers almost
  always want to abort, so exceptions are ergonomic.
* A bad chain has a *failure index* that's load-bearing diagnostic data for
  the CLI's "tamper at index N" output. Recovering it from an exception
  would be awkward.

## 9. Mock server uses stdlib `http.server`, not httpx-server

httpx is a *client* library; there is no httpx server. We use stdlib
`http.server.HTTPServer` for the demo's wire-mode smoke test. The proxy
itself remains transport-agnostic; nothing in `mcp_attest` depends on this
choice.

## 10. Public verify() never raises on malformed inputs

`crypto.verify` is documented to return `False` on any malformed signature,
public key, or message — never to raise. Structured failure reporting is
the verifier layer's responsibility, where the call site has enough context
to choose between `SignatureInvalidError`, `HashMismatchError`, etc.

## 11. Examples package has an empty `__init__.py`

This is purely to let `pytest` and the CLI's `demo` subcommand import sibling
modules from `examples/`. It is not part of the installable wheel.
