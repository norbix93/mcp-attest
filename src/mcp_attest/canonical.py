"""Canonical JSON serialization for deterministic hashing and signing.

Per spec §4.2, every byte that flows into a hash or a signature is produced by
this module so that two parties computing the hash of "the same object" obtain
the same digest. The rules:

* UTF-8 encoded bytes.
* Object keys sorted lexicographically by Unicode code point.
* No insignificant whitespace (compact separators).
* ``NaN``/``Infinity``/``-Infinity`` are rejected with :class:`CanonicalizationError`.
* Container element ordering is preserved for lists (they are sequences, not
  sets), and only dict keys are reordered.

The module exposes :func:`dumps`, :func:`loads`, and a convenience
:func:`hash` that wraps ``blake2b(dumps(obj), digest_size=32)``.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from mcp_attest.errors import CanonicalizationError

_DIGEST_SIZE = 32
_SEPARATORS = (",", ":")


def _reject_non_finite(obj: Any) -> None:
    """Walk ``obj`` and raise :class:`CanonicalizationError` for any non-finite float.

    ``json.dumps`` silently emits ``NaN`` / ``Infinity`` / ``-Infinity`` tokens
    which are valid in JavaScript but not in RFC 8259 JSON, and definitely not
    in a hash-stable canonical form. We pre-walk so the error blames the input,
    not the encoder.
    """
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise CanonicalizationError(
                f"non-finite float not permitted in canonical JSON: {obj!r}"
            )
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _reject_non_finite(v)
        return
    if isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_non_finite(v)


def dumps(obj: Any) -> bytes:
    """Encode ``obj`` to canonical JSON bytes per spec §4.2.

    Args:
        obj: Any JSON-serializable Python value (``dict``, ``list``, ``str``,
            ``int``, ``float``, ``bool``, ``None``).

    Returns:
        UTF-8 bytes with sorted dict keys and compact separators.

    Raises:
        CanonicalizationError: If ``obj`` (or any nested value) is non-finite,
            or if ``json.dumps`` rejects an unsupported type.
    """
    _reject_non_finite(obj)
    try:
        return json.dumps(
            obj,
            ensure_ascii=False,
            sort_keys=True,
            separators=_SEPARATORS,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def loads(data: bytes) -> Any:
    """Decode canonical JSON bytes back into Python objects.

    This is a thin wrapper over :func:`json.loads` provided for symmetry with
    :func:`dumps` — there is no special "canonical" decoding step, since any
    well-formed JSON parses the same way regardless of how it was serialized.
    """
    return json.loads(data.decode("utf-8"))


def hash(obj: Any) -> bytes:  # noqa: A001 — intentional public name; matches spec §6.1
    """Return ``blake2b(canonical(obj), digest_size=32)``.

    Convenience wrapper used pervasively when computing ``params_hash`` /
    ``result_hash`` and entry / STH digests.
    """
    return hashlib.blake2b(dumps(obj), digest_size=_DIGEST_SIZE).digest()
