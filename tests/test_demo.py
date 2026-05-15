"""Smoke test that the demo script runs end-to-end and exits 0."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

import demo  # noqa: E402 — must come after path injection


def test_demo_runs_and_exits_zero(capsys):
    exit_code = demo.main()
    captured = capsys.readouterr()
    assert exit_code == 0, captured.out
    # Sanity-check the load-bearing strings appear so a future regression
    # that silently changes wording still flags here.
    assert "chain verified" in captured.out
    assert "tamper detected" in captured.out
    assert "equivocation proven" in captured.out
