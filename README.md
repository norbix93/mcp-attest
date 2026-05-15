# mcp-attest

Tamper-evident cryptographic attestation for Model Context Protocol (MCP)
tool calls. A transparent proxy sits between an MCP client and an MCP server
and produces an append-only, hash-chained, Ed25519-signed audit log of every
call. Each call returns a small receipt sufficient to prove later that the
server signed exactly that response for exactly that request.

## Threat model

* **Tamper:** an operator with disk access mutates a historical entry.
  Detected by chain verification — any byte change invalidates the next
  record's `prev_hash` or the entry's own signature.
* **Forge:** a third party tries to insert a fake record. Detected at the
  signature check — only the server's private key produces valid signatures
  under its declared public key.
* **Equivocate:** a compromised server presents two different histories to
  two different auditors. Detected by Signed Tree Heads — any two valid STHs
  of the same chain length with different head hashes are unforgeable proof.

Out of scope: confidentiality (combine with TLS), key compromise (rotate
keys via the standard PKI playbook), and denial of service.

## Install

```sh
git clone https://github.com/norbix93/mcp-attest
cd mcp-attest
pip install -e ".[dev]"
```

Requires Python 3.11+. Runtime dependencies: `cryptography`, `click`,
`httpx`. No others.

## Quick start

```python
import asyncio
from pathlib import Path

from mcp_attest import AttestingProxy, generate_keypair
from mcp_attest.log import AttestationLog


async def my_mcp_server_handler(request: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request["id"], "result": {"ok": True}}


priv, pub = generate_keypair()
log = AttestationLog(Path("./attest.jsonl"), server_id="my-server", private_key=priv)
proxy = AttestingProxy(upstream=my_mcp_server_handler, log=log)

response, receipt = asyncio.run(
    proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})
)
print(receipt)
```

## See it work

```sh
mcp-attest demo
```

Sample output (color codes omitted):

```
1) Making 5 tool calls through the attesting proxy:
  seq=0 tools/call  status=ok    entry_hash=10fcc5b32602…
  seq=1 tools/call  status=ok    entry_hash=c27bd0cfe734…
  seq=2 tools/list  status=ok    entry_hash=6072f6014e7c…
  seq=3 tools/call  status=error entry_hash=1ceba4681dc5…
  seq=4 tools/call  status=ok    entry_hash=33a08dd996f3…

2) Emitting a Signed Tree Head:
  chain_length=5 head=33a08dd996f3… sig=55d54c48428e…

3) Verifying the chain:
✓ chain verified (5 entries)

4) Tamper demonstration — modifying entry 2 in place:
✗ tamper detected at index 2: signature invalid at seq=2

5) Equivocation demonstration — building a forked log:
✗ equivocation proven: server forked at length 5
```

## CLI reference

```sh
mcp-attest keygen --out ./srv                       # → ./srv.priv + ./srv.pub
mcp-attest verify ./attest.jsonl --pubkey ./srv.pub # exit 0 ok / 1 tampered
mcp-attest inspect ./attest.jsonl [--seq 3]         # pretty-print
mcp-attest sth ./attest.jsonl --pubkey ./srv.pub --privkey ./srv.priv  # emit STH
mcp-attest compare-sth a.json b.json --pubkey ./srv.pub  # equivocation check
mcp-attest demo                                     # the demo above
```

Exit codes: 0 success, 1 verification failure, 2 user error.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│ MCP client  │ ──▶ │  AttestingProxy  │ ──▶ │ MCP server  │
└─────────────┘     │                  │     └─────────────┘
       ▲            │ append-only      │
       │ Receipt    │ hash chain       │
       └────────────│ JSONL log        │
                    └──────────────────┘
```

The proxy is transport-agnostic — it operates on parsed JSON-RPC dicts. The
demo wires it to HTTP via `httpx`, but the same proxy slots into stdio,
WebSocket, or any other MCP transport.

## Limitations

* **Not a replacement for TLS.** mcp-attest attests; it does not hide.
* **Trusted key custody required.** Anyone with the private key can forge
  an internally-valid chain. Equivocation detection via STHs is the answer
  to compromised servers.
* **Linear chain only in v0.1.** Verification is O(n). A Merkle-tree upgrade
  for inclusion proofs is on the v0.2 roadmap.
* **No automatic key rotation.** v0.1 assumes a single long-lived key per
  server.

## Documentation

* [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the wire format and procedures.
* [`docs/PATENT_NOTES.md`](docs/PATENT_NOTES.md) — claims for the defensive
  patent draft.
* [`DECISIONS.md`](DECISIONS.md) — design decisions and spec ambiguities
  resolved during the build.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
