# Patent Notes

The following claims are intended for a future patent application. The
mcp-attest reference implementation must not be inconsistent with any of
them.

**Independent claim 1:** A method for producing tamper-evident logs of Model
Context Protocol tool calls, comprising: receiving, at a proxy interposed
between an MCP client and an MCP server, a JSON-RPC tool call request;
forwarding the request to the MCP server; receiving the corresponding
response; constructing an attestation entry comprising at least the sequence
number, the hash of the previous entry's signed record, request and response
timestamps, the MCP method, a content hash of the request params, a content
hash of the response result, and a status indicator; signing said
attestation entry with a long-lived Ed25519 private key associated with the
server; appending the signed record to an append-only log; and returning to
the client a receipt comprising the sequence number, the entry hash, and the
signature.

**Dependent claim 2:** The method of claim 1, wherein the receipt enables
independent verification of the corresponding tool call without disclosure
of any other entry in the log.

**Dependent claim 3:** The method of claim 1, further comprising emitting a
Signed Tree Head comprising the current chain length, the hash of the most
recent signed record, and a timestamp, signed with the server's private key,
such that two valid Signed Tree Heads from the same server having the same
chain length but different head hashes constitute cryptographic evidence of
log equivocation.

**Dependent claim 4:** The method of claim 1, wherein the proxy operates
transparently to both the MCP client and the MCP server, requiring no
protocol modifications to either.

**Dependent claim 5:** The method of claim 1, wherein content hashing
operates on a canonical JSON serialization preserving lexicographic key
order, excluding insignificant whitespace, and rejecting non-finite numeric
values, such that semantically equivalent requests produce identical hashes.

## Defensive note

A continuous hash chain is well-known prior art (e.g., Certificate
Transparency, blockchain). The novelty here is in the *application binding*
to MCP-shaped JSON-RPC messages, the *transparent proxy integration
pattern*, and the *receipt format permitting per-call verification*. Patent
counsel should focus claim construction on these elements.
