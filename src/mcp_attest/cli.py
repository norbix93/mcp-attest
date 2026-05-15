"""``mcp-attest`` command-line entry point (spec §6.8).

Subcommands:

* ``keygen``       — generate an Ed25519 keypair to disk.
* ``verify``       — walk a log and report pass/fail with first-failure index.
* ``inspect``      — pretty-print log contents (whole log or a single record).
* ``sth``          — emit a Signed Tree Head for the log's current state.
* ``compare-sth``  — given two STH JSON files, report whether they prove equivocation.
* ``demo``         — run the end-to-end demo (see ``examples/demo.py``).

Exit codes (consistent across commands):

* ``0`` — success.
* ``1`` — verification failed (signature, hash, chain).
* ``2`` — user error (bad arguments, missing files).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from mcp_attest import crypto
from mcp_attest.entry import SignedTreeHead
from mcp_attest.log import AttestationLog
from mcp_attest.verifier import detect_equivocation, verify_chain, verify_sth

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USER_ERROR = 2
# compare-sth is unusual: detecting equivocation is a *successful* run that
# happens to find evidence. We surface that as a distinct exit code so CI
# pipelines can tell "I proved misbehavior" apart from "verifier itself
# failed". 0 = no evidence, 3 = evidence proven, 2 = bad inputs.
EXIT_EVIDENCE_FOUND = 3


@click.group()
@click.version_option()
def main() -> None:
    """mcp-attest: tamper-evident attestation for MCP tool calls."""


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--out",
    "out_prefix",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    required=True,
    help="Prefix path; writes <out>.priv and <out>.pub.",
)
def keygen(out_prefix: Path) -> None:
    """Generate an Ed25519 keypair and write the raw 32-byte halves to disk."""
    priv, pub = crypto.generate_keypair()
    priv_path = out_prefix.with_suffix(out_prefix.suffix + ".priv")
    pub_path = out_prefix.with_suffix(out_prefix.suffix + ".pub")
    priv_path.write_bytes(priv)
    # Private key files should not be world-readable.
    priv_path.chmod(0o600)
    pub_path.write_bytes(pub)
    click.echo(f"wrote {priv_path}")
    click.echo(f"wrote {pub_path}")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@main.command()
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--pubkey",
    "pubkey_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the 32-byte raw public key file.",
)
def verify(log_path: Path, pubkey_path: Path) -> None:
    """Verify the full chain of LOG_PATH under the given public key."""
    pubkey = _read_pubkey(pubkey_path)
    log = AttestationLog(log_path, server_id="-")
    result = verify_chain(log, pubkey)
    if result.ok:
        click.echo(f"OK: chain verified ({result.chain_length} entries)")
        sys.exit(EXIT_OK)
    click.echo(
        f"FAIL: tamper at index {result.first_failure_index}: {result.reason}",
        err=True,
    )
    sys.exit(EXIT_VERIFICATION_FAILED)


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


@main.command()
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--seq",
    type=int,
    default=None,
    help="If given, print just the record at this sequence number.",
)
def inspect(log_path: Path, seq: int | None) -> None:
    """Pretty-print the log (or one record) as indented JSON."""
    log = AttestationLog(log_path, server_id="-")
    if seq is not None:
        try:
            record = log.read_record(seq)
        except (IndexError, ValueError) as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(EXIT_USER_ERROR)
        click.echo(json.dumps(record.to_dict(), indent=2, sort_keys=True))
        return
    for record in log.iter_records():
        click.echo(json.dumps(record.to_dict(), indent=2, sort_keys=True))
        click.echo("---")


# ---------------------------------------------------------------------------
# sth
# ---------------------------------------------------------------------------


@main.command()
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--pubkey",
    "pubkey_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--privkey",
    "privkey_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the matching 32-byte raw private key file.",
)
def sth(log_path: Path, pubkey_path: Path, privkey_path: Path) -> None:
    """Emit a Signed Tree Head for the log's current state, as JSON on stdout."""
    pubkey = _read_pubkey(pubkey_path)
    privkey = _read_privkey(privkey_path)
    # Cross-check: refuse to mint an STH with a key pair that doesn't match.
    if crypto.public_key_from_private(privkey) != pubkey:
        click.echo("error: privkey does not match pubkey", err=True)
        sys.exit(EXIT_USER_ERROR)
    log = AttestationLog(log_path, server_id="-", private_key=privkey)
    sth_value = log.emit_sth()
    if not verify_sth(sth_value, pubkey):
        # Defensive — shouldn't happen given we just signed it, but catch any
        # accidental key-pair mismatch we missed above.
        click.echo("error: freshly emitted STH failed self-verification", err=True)
        sys.exit(EXIT_VERIFICATION_FAILED)
    click.echo(json.dumps(sth_value.to_dict(), indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# compare-sth
# ---------------------------------------------------------------------------


@main.command("compare-sth")
@click.argument("sth_a_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("sth_b_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--pubkey",
    "pubkey_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def compare_sth(sth_a_path: Path, sth_b_path: Path, pubkey_path: Path) -> None:
    """Report whether the two STHs prove log equivocation.

    Exit codes for this command:

      0  the two STHs are NOT equivocation evidence (no fork detected)
      2  one or both STH files are malformed
      3  EVIDENCE FOUND — the server signed two histories of the same length

    The 0/3 split is intentional: detecting equivocation is a *successful*
    run that happens to find misbehavior, so CI pipelines can tell it apart
    from a verifier-itself failure (which would be exit 1 in this CLI). Use
    ``exit_code != 0`` if you want either case to be alarming.
    """
    pubkey = _read_pubkey(pubkey_path)
    try:
        sth_a = _load_sth(sth_a_path)
        sth_b = _load_sth(sth_b_path)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        click.echo(f"error: malformed STH file: {exc}", err=True)
        sys.exit(EXIT_USER_ERROR)
    if detect_equivocation(sth_a, sth_b, pubkey):
        click.echo(
            f"EQUIVOCATION: server presented two histories at length {sth_a.chain_length}"
        )
        sys.exit(EXIT_EVIDENCE_FOUND)
    click.echo("OK: STHs are not equivocation evidence")
    sys.exit(EXIT_OK)


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


@main.command()
def demo() -> None:
    """Run the end-to-end demo (see examples/demo.py)."""
    # The demo lives in the examples/ tree, which isn't on sys.path when the
    # package is installed. Locate it relative to the repo root or fall back
    # to running it as a script so editable installs and source checkouts
    # both work.
    import importlib.util

    candidate_paths = [
        Path(__file__).resolve().parents[2] / "examples" / "demo.py",
        Path.cwd() / "examples" / "demo.py",
    ]
    demo_path = next((p for p in candidate_paths if p.exists()), None)
    if demo_path is None:
        click.echo(
            "error: examples/demo.py not found relative to install or cwd",
            err=True,
        )
        sys.exit(EXIT_USER_ERROR)
    spec = importlib.util.spec_from_file_location("mcp_attest_demo", demo_path)
    if spec is None or spec.loader is None:
        click.echo("error: could not load demo module", err=True)
        sys.exit(EXIT_USER_ERROR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.exit(module.main())


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _read_pubkey(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) != 32:
        click.echo(f"error: pubkey at {path} must be 32 bytes, got {len(data)}", err=True)
        sys.exit(EXIT_USER_ERROR)
    return data


def _read_privkey(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) != 32:
        click.echo(f"error: privkey at {path} must be 32 bytes, got {len(data)}", err=True)
        sys.exit(EXIT_USER_ERROR)
    return data


def _load_sth(path: Path) -> SignedTreeHead:
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return SignedTreeHead.from_dict(payload)


if __name__ == "__main__":  # pragma: no cover
    main()
