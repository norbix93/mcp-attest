"""Smoke tests for the exception hierarchy.

These tests don't aim to exercise behavior — they pin the inheritance shape so
that downstream ``except`` clauses in user code stay valid across refactors.
"""

from __future__ import annotations

import pytest

from mcp_attest.errors import (
    CanonicalizationError,
    ChainBrokenError,
    HashMismatchError,
    MCPAttestError,
    SignatureInvalidError,
    VerificationError,
)


def test_base_exception_is_exception():
    assert issubclass(MCPAttestError, Exception)


@pytest.mark.parametrize(
    "subclass",
    [VerificationError, CanonicalizationError],
)
def test_top_level_subclasses_inherit_from_base(subclass: type[Exception]) -> None:
    assert issubclass(subclass, MCPAttestError)


@pytest.mark.parametrize(
    "subclass",
    [SignatureInvalidError, HashMismatchError, ChainBrokenError],
)
def test_verification_subclasses_inherit_from_verification_error(
    subclass: type[Exception],
) -> None:
    assert issubclass(subclass, VerificationError)
    assert issubclass(subclass, MCPAttestError)


def test_exceptions_are_distinct():
    assert SignatureInvalidError is not HashMismatchError
    assert HashMismatchError is not ChainBrokenError


def test_exceptions_can_be_raised_and_caught():
    with pytest.raises(VerificationError):
        raise SignatureInvalidError("bad sig")

    with pytest.raises(MCPAttestError):
        raise CanonicalizationError("nan not allowed")
