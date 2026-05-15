"""mcp-attest: Tamper-evident cryptographic attestation for MCP tool calls.

Public API entry points are re-exported from this module so callers can write
``from mcp_attest import AttestationLog`` without reaching into submodules.
The re-export surface grows as feature modules land; see ``__all__`` for the
current public API.
"""

from mcp_attest.errors import (
    CanonicalizationError,
    ChainBrokenError,
    HashMismatchError,
    MCPAttestError,
    SignatureInvalidError,
    VerificationError,
)

__version__ = "0.1.0"

__all__ = [
    "CanonicalizationError",
    "ChainBrokenError",
    "HashMismatchError",
    "MCPAttestError",
    "SignatureInvalidError",
    "VerificationError",
    "__version__",
]
