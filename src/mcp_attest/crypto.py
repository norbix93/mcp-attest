"""Cryptographic primitives: Ed25519 signatures and BLAKE2b hashing.

This module is the only place in the package that touches the ``cryptography``
library. Everything else handles 32-byte public keys and 64-byte signatures as
opaque ``bytes`` so substituting a different backend (HSM, KMS) is a localized
change.

Per spec §4.1:
* Ed25519 — 32-byte public keys, 64-byte signatures, deterministic (RFC 8032).
* BLAKE2b — ``digest_size=32`` (32-byte output), from stdlib ``hashlib``.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

_DIGEST_SIZE = 32
_PRIVATE_KEY_BYTES = 32
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64

_RAW_FORMAT = serialization.PublicFormat.Raw
_RAW_PRIVATE_FORMAT = serialization.PrivateFormat.Raw
_NO_ENCRYPTION = serialization.NoEncryption()
_RAW_ENCODING = serialization.Encoding.Raw


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair.

    Returns:
        A tuple ``(private_key, public_key)``. Both are raw 32-byte values
        suitable for storage with no further encoding.
    """
    private = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=_RAW_ENCODING,
        format=_RAW_PRIVATE_FORMAT,
        encryption_algorithm=_NO_ENCRYPTION,
    )
    public_bytes = private.public_key().public_bytes(
        encoding=_RAW_ENCODING,
        format=_RAW_FORMAT,
    )
    return private_bytes, public_bytes


def public_key_from_private(private_key: bytes) -> bytes:
    """Derive the public key for a stored private key.

    Used by tooling that only has the ``.priv`` file on disk and needs the
    matching ``.pub`` (e.g., the CLI ``keygen`` round-trip test).
    """
    _check_length("private_key", private_key, _PRIVATE_KEY_BYTES)
    private = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return private.public_key().public_bytes(
        encoding=_RAW_ENCODING,
        format=_RAW_FORMAT,
    )


def sign(private_key: bytes, message: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature over ``message``.

    Args:
        private_key: 32 raw bytes.
        message: Arbitrary bytes to sign.

    Returns:
        64-byte signature.
    """
    _check_length("private_key", private_key, _PRIVATE_KEY_BYTES)
    private = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return private.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff ``signature`` is a valid Ed25519 signature.

    Per spec §6.2 this function never raises on a malformed signature — it
    returns ``False``. Callers that want a specific exception should wrap with
    ``SignatureInvalidError`` at the call site (the verifier does this).

    A wrong-length public key or signature still returns ``False`` rather than
    raising, since the function's contract is binary verification.
    """
    if len(public_key) != _PUBLIC_KEY_BYTES:
        return False
    if len(signature) != _SIGNATURE_BYTES:
        return False
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        public.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def hash_bytes(data: bytes) -> bytes:
    """Return BLAKE2b 32-byte digest of ``data``.

    Provided so callers don't have to repeat the ``digest_size=32`` argument
    or remember to use BLAKE2b over the more common SHA-256.
    """
    return hashlib.blake2b(data, digest_size=_DIGEST_SIZE).digest()


def _check_length(name: str, value: bytes, expected: int) -> None:
    """Raise ``ValueError`` with a useful message if ``value`` is the wrong length."""
    if len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(value)}")
