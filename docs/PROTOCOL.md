# MCP-Attest Protocol — v0.1

This is the normative protocol specification, extracted from the project
brief §4. Implementations conforming to this document must reproduce every
byte described here exactly — the hashes and signatures are over canonical
serializations, so even seemingly cosmetic deviations break verification.

## 1. Cryptographic primitives

| Primitive | Choice                            | Output size  |
|-----------|-----------------------------------|--------------|
| Hash      | BLAKE2b with `digest_size=32`     | 32 bytes     |
| Signature | Ed25519 (RFC 8032)                | 64 bytes     |
| Key       | Ed25519 public / private key      | 32 bytes each|

Ed25519 was chosen for its deterministic signatures (no nonce-reuse hazard) and
its small constant-time implementation. BLAKE2b at 32-byte output gives
SHA-256-equivalent collision resistance without the SHA-256 length-extension
caveats.

## 2. Canonical JSON

All hashing and signing operates on canonical JSON bytes:

* UTF-8 encoded.
* Object keys sorted lexicographically (Unicode code-point order).
* No insignificant whitespace; separators are `","` and `":"`.
* Numbers in their Python-default shortest round-trip form.
* `null` for missing values; never omit a key declared by the schema.
* `NaN`, `Infinity`, `-Infinity` are rejected.

Reference implementation: `mcp_attest.canonical.dumps`.

## 3. AttestationEntry

One record per attested tool call:

```json
{
  "seq":          12,
  "prev_hash":    "<hex of 32 bytes>",
  "ts_request":   1715000000.123,
  "ts_response":  1715000000.456,
  "server_id":    "tools.example.com",
  "request_id":   "req-abc-123",
  "method":       "tools/call",
  "tool_name":    "search_docs",
  "params_hash":  "<hex of 32 bytes>",
  "result_hash":  "<hex of 32 bytes>",
  "status":       "ok"
}
```

Rules:

* `seq` is monotonic, starts at 0, increases by exactly 1.
* `prev_hash` is the hash of the previous signed record (§5). For `seq=0`
  (genesis), it is 32 zero bytes encoded as `"00" * 32` hex.
* `tool_name` is `params.name` when `method == "tools/call"`; otherwise `null`.
* `params_hash = BLAKE2b(canonical(params))`. Absent `params` is hashed as
  `canonical(null)`.
* `result_hash = BLAKE2b(canonical(result_or_error))`.
* `status` is `"ok"` if the JSON-RPC response carries `result`, `"error"` if
  it carries `error`.
* Timestamps are Unix seconds as float. They are not required to be strictly
  monotonic across entries.

## 4. Signed log record

```json
{
  "entry":     { ...AttestationEntry... },
  "signature": "<hex of 64 bytes>"
}
```

Where `signature = Ed25519_sign(server_priv_key, canonical(entry))`.

## 5. Entry hash

For chain linkage:

```
entry_hash = BLAKE2b(canonical(signed_record))
```

The hash covers both the entry data and the signature, so tampering with
either is detected by the chain check on the next record.

## 6. Receipt

Returned to the caller alongside the tool result:

```json
{
  "seq":        12,
  "entry_hash": "<hex of 32 bytes>",
  "signature":  "<hex of 64 bytes>",
  "server_id":  "tools.example.com"
}
```

A caller holding `(receipt, params, result, server_pubkey)` can independently
verify that the server signed this exact transaction at position 12 without
seeing any other log entry.

## 7. Signed Tree Head

```json
{
  "chain_length": 1337,
  "head_hash":    "<hex of 32 bytes>",
  "timestamp":    1715000999.0,
  "signature":    "<hex of 64 bytes>"
}
```

Where:

* `chain_length` is the number of entries.
* `head_hash` is `entry_hash` of the last signed record, or `"00" * 32` if
  empty.
* `signature = Ed25519_sign(server_priv_key, canonical({chain_length, head_hash, timestamp}))`.

**Equivocation detection:** two valid STHs from the same server with the same
`chain_length` but different `head_hash` is unforgeable proof of misbehavior.

## 8. Log format on disk

JSON Lines (`.jsonl`):

* One signed record per line.
* Appends are atomic under `fcntl.flock(LOCK_EX)`.
* By convention the file is append-only; the protocol enforces this via the
  hash chain rather than via filesystem permissions.

## 9. Procedures

### 9.1 Append

Given an incoming MCP request/response pair on the proxy:

1. Capture `params`, `request_id`, `method`, `ts_request`.
2. Forward to upstream; await response; capture `ts_response`,
   `result_or_error`, `status`.
3. Compute `params_hash`, `result_hash`.
4. Under the file lock, read the last record's `entry_hash`; that becomes
   `prev_hash`. Use `"00" * 32` if the log is empty.
5. Construct `AttestationEntry`. Sign canonical bytes with the server's
   private key.
6. Append the signed record to the log file and fsync.
7. Return `Receipt` to the caller.

### 9.2 VerifyReceipt

Given `(receipt, params, result, server_pubkey, log)`:

1. Read the record at index `receipt.seq` from the log.
2. Verify `Ed25519_verify(pubkey, canonical(record.entry), record.signature)`.
3. Recompute `params_hash` and `result_hash` from the provided payloads;
   check they match the entry.
4. Recompute `entry_hash` from the record; check it equals
   `receipt.entry_hash`.
5. Return success, or raise a `VerificationError` subclass on the specific
   mismatch.

### 9.3 VerifyChain

Given `(log, server_pubkey)`:

1. Stream records line by line, maintaining `expected_prev_hash` (starting at
   `"00" * 32`).
2. For each record at line `i`:
   * Check `record.entry.seq == i`.
   * Check `record.entry.prev_hash == expected_prev_hash`.
   * Verify the signature.
   * Update `expected_prev_hash` to the record's `entry_hash`.
3. Return `(ok, first_failure_index, reason)`.

### 9.4 EmitSTH

Given the current log state:

1. Read the current chain length and last entry hash.
2. Build the STH dict, sign canonical bytes, return.

## 10. Forward compatibility

A v0.2 may upgrade the chain to a Merkle tree (preserving the same on-disk
record format) to support O(log n) inclusion proofs. v0.1 verifiers should
ignore any extra top-level fields they don't recognize *in records they
emit*, but MUST NOT accept records whose `entry` block contains unknown
fields — schema drift inside the signed payload is a verification error.
