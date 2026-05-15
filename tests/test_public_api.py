"""Pin the public ``from mcp_attest import ...`` surface.

If anything in ``__all__`` is renamed or removed, this test fails — keeping
downstream breakages visible at the package boundary instead of deep in
caller code.
"""

from __future__ import annotations

import mcp_attest


def test_version_string_present():
    assert isinstance(mcp_attest.__version__, str)
    assert mcp_attest.__version__.count(".") >= 1


def test_all_names_are_importable():
    for name in mcp_attest.__all__:
        assert hasattr(mcp_attest, name), f"missing public export: {name}"


def test_core_classes_directly_importable():
    from mcp_attest import (
        AttestationEntry,
        AttestationLog,
        AttestingProxy,
        Receipt,
        SignedRecord,
        SignedTreeHead,
    )

    assert all(
        cls is not None
        for cls in [
            AttestationEntry,
            AttestationLog,
            AttestingProxy,
            Receipt,
            SignedRecord,
            SignedTreeHead,
        ]
    )


def test_verifier_functions_directly_importable():
    from mcp_attest import (
        ChainVerificationResult,
        detect_equivocation,
        verify_chain,
        verify_receipt,
        verify_sth,
    )

    assert callable(verify_chain)
    assert callable(verify_receipt)
    assert callable(verify_sth)
    assert callable(detect_equivocation)
    assert ChainVerificationResult is not None


def test_error_hierarchy_importable():
    from mcp_attest import (
        ChainBrokenError,
        HashMismatchError,
        MCPAttestError,
        SignatureInvalidError,
        VerificationError,
    )

    assert issubclass(SignatureInvalidError, VerificationError)
    assert issubclass(HashMismatchError, VerificationError)
    assert issubclass(ChainBrokenError, VerificationError)
    assert issubclass(VerificationError, MCPAttestError)
