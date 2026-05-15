"""mcp-attest: Tamper-evident cryptographic attestation for MCP tool calls.

Importable surface: everything a typical caller needs is re-exported here so
that ``from mcp_attest import AttestationLog, AttestingProxy, verify_chain``
works without reaching into submodules.
"""

from mcp_attest.crypto import (
    generate_keypair,
    hash_bytes,
    public_key_from_private,
    sign,
    verify,
)
from mcp_attest.entry import (
    ZERO_HASH_HEX,
    AttestationEntry,
    Receipt,
    SignedRecord,
    SignedTreeHead,
)
from mcp_attest.errors import (
    CanonicalizationError,
    ChainBrokenError,
    HashMismatchError,
    MCPAttestError,
    SignatureInvalidError,
    VerificationError,
)
from mcp_attest.log import AttestationLog
from mcp_attest.proxy import AttestingProxy
from mcp_attest.verifier import (
    ChainVerificationResult,
    detect_equivocation,
    verify_chain,
    verify_receipt,
    verify_sth,
)

__version__ = "0.1.0"

__all__ = [
    "ZERO_HASH_HEX",
    "AttestationEntry",
    "AttestationLog",
    "AttestingProxy",
    "CanonicalizationError",
    "ChainBrokenError",
    "ChainVerificationResult",
    "HashMismatchError",
    "MCPAttestError",
    "Receipt",
    "SignatureInvalidError",
    "SignedRecord",
    "SignedTreeHead",
    "VerificationError",
    "__version__",
    "detect_equivocation",
    "generate_keypair",
    "hash_bytes",
    "public_key_from_private",
    "sign",
    "verify",
    "verify_chain",
    "verify_receipt",
    "verify_sth",
]
