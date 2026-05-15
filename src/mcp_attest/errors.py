"""Exception hierarchy for mcp-attest.

Every named failure mode in the protocol maps to a distinct exception so callers
can pattern-match precisely (e.g., ``except SignatureInvalidError``) without
relying on string inspection of generic ``ValueError`` messages.
"""

from __future__ import annotations


class MCPAttestError(Exception):
    """Base class for every exception raised by this package."""


class CanonicalizationError(MCPAttestError):
    """Raised when an object cannot be canonicalized (e.g., NaN, Infinity)."""


class VerificationError(MCPAttestError):
    """Base class for cryptographic verification failures.

    Catch this to handle any verification failure generically; catch one of its
    subclasses to distinguish *why* verification failed.
    """


class SignatureInvalidError(VerificationError):
    """An Ed25519 signature did not validate for the given message and key."""


class HashMismatchError(VerificationError):
    """A recomputed content hash did not match the value recorded in the log."""


class ChainBrokenError(VerificationError):
    """The hash-chain linkage between two consecutive records is broken.

    This includes out-of-order sequence numbers, mismatched ``prev_hash``, or
    a deleted/inserted record.
    """
