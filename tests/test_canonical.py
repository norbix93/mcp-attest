"""Tests for canonical JSON serialization (spec §4.2 / §8.1)."""

from __future__ import annotations

import math

import pytest

from mcp_attest import canonical
from mcp_attest.errors import CanonicalizationError


class TestDumpsDeterminism:
    def test_key_order_independent(self):
        a = {"b": 1, "a": 2, "c": 3}
        b = {"c": 3, "a": 2, "b": 1}
        assert canonical.dumps(a) == canonical.dumps(b)

    def test_nested_key_order_independent(self):
        a = {"outer": {"z": 1, "a": 2}, "items": [{"k2": "v2", "k1": "v1"}]}
        b = {"items": [{"k1": "v1", "k2": "v2"}], "outer": {"a": 2, "z": 1}}
        assert canonical.dumps(a) == canonical.dumps(b)

    def test_list_order_preserved(self):
        assert canonical.dumps([3, 1, 2]) == b"[3,1,2]"
        assert canonical.dumps([1, 2, 3]) != canonical.dumps([3, 2, 1])

    def test_no_insignificant_whitespace(self):
        assert canonical.dumps({"a": 1, "b": 2}) == b'{"a":1,"b":2}'


class TestDumpsGolden:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, b"null"),
            (True, b"true"),
            (False, b"false"),
            (0, b"0"),
            (-1, b"-1"),
            (1.5, b"1.5"),
            ("hello", b'"hello"'),
            ([], b"[]"),
            ({}, b"{}"),
            ({"a": 1}, b'{"a":1}'),
            ({"a": [1, 2, 3]}, b'{"a":[1,2,3]}'),
            (["x", None, True], b'["x",null,true]'),
        ],
    )
    def test_canonical_form_is_stable(self, value, expected):
        assert canonical.dumps(value) == expected

    def test_unicode_is_emitted_directly_not_escaped(self):
        """Spec §4.2 says UTF-8 encoded; non-ASCII should not be \\u-escaped.

        This pins the choice so the byte form stays stable across Python
        versions where ``json.dumps`` defaults to ``ensure_ascii=True``.
        """
        assert canonical.dumps({"name": "café"}) == '{"name":"café"}'.encode()


class TestDumpsRejectsNonFinite:
    @pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
    def test_top_level_non_finite_raises(self, value):
        with pytest.raises(CanonicalizationError):
            canonical.dumps(value)

    def test_non_finite_in_nested_list_raises(self):
        with pytest.raises(CanonicalizationError):
            canonical.dumps([1, 2, math.inf])

    def test_non_finite_in_nested_dict_raises(self):
        with pytest.raises(CanonicalizationError):
            canonical.dumps({"a": {"b": math.nan}})


class TestDumpsRejectsUnsupportedTypes:
    def test_set_raises(self):
        with pytest.raises(CanonicalizationError):
            canonical.dumps({1, 2, 3})

    def test_bytes_raises(self):
        with pytest.raises(CanonicalizationError):
            canonical.dumps(b"raw")


class TestRoundTrip:
    @pytest.mark.parametrize(
        "value",
        [
            None,
            True,
            False,
            0,
            -1,
            1.5,
            "string",
            "café",
            [],
            {},
            [1, "two", None, True, False],
            {"a": 1, "b": [2, 3], "c": {"d": None}},
        ],
    )
    def test_loads_dumps_round_trip(self, value):
        assert canonical.loads(canonical.dumps(value)) == value


class TestHash:
    def test_hash_is_32_bytes(self):
        assert len(canonical.hash({})) == 32

    def test_hash_is_stable(self):
        assert canonical.hash({"a": 1, "b": 2}) == canonical.hash({"b": 2, "a": 1})

    def test_hash_changes_with_value(self):
        assert canonical.hash({"a": 1}) != canonical.hash({"a": 2})

    def test_hash_of_null_is_well_defined(self):
        """Spec §4.3: missing ``params`` is hashed as canonical(None)."""
        h = canonical.hash(None)
        assert isinstance(h, bytes)
        assert len(h) == 32
