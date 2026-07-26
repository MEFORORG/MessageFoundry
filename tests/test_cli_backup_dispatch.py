# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CLI dispatch for the DR ``backup`` / ``restore-verify`` subcommands (ADR 0049, #60) — the argparse
layer over the runner primitives (``test_backup_runner`` / ``test_restore_verify`` cover those). Drives
``main(argv)`` end-to-end through the parser + ``_DISPATCH`` on a SQLite-backed store: JSON/human
summaries, flag plumbing (``--no-verify`` / ``--full-verify`` / ``--config-only``), the no-destination /
not-leader / ``BackupError`` failure branches with their exit codes, a real backup -> restore-verify
round-trip (PASS / missing / KEY_MISMATCH / FAIL), and the PHI-safe-stdout invariant. No failover rig —
single-node CLI only; the defensive not-leader branch is exercised by stubbing ``run_once`` -> ``None``."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.pipeline.dr_backup import BackupError
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher

# Synthetic body + summary planted in the seeded store; asserted to NEVER surface on stdout.
_RAW_BODY = "MSH|^~\\&|raw-body"
_SUMMARY = "MRN001 DOE^JOHN"


# --- fixtures / helpers ------------------------------------------------------


@pytest.fixture
def key_b64() -> str:
    return generate_key()


async def _seed_store(db: Path, key_b64: str | None) -> None:
    """Create a store at ``db`` with one enqueued (encrypted) row carrying synthetic PHI, then close it."""
    cipher = make_cipher(key_b64) if key_b64 else None
    store = await MessageStore.open(db, cipher=cipher)
    await store.enqueue_message(
        channel_id="c1",
        raw=_RAW_BODY,
        deliveries=[("d1", "OUT|delivered-body")],
        control_id="CID-1",
        message_type="ADT^A01",
        summary=_SUMMARY,
        now=1.0,
    )
    await store.close()


def _config_dir(tmp_path: Path) -> str:
    """A minimal config bundle (one module) so the archive carries a real config fingerprint."""
    d = tmp_path / "config"
    d.mkdir()
    (d / "feed.py").write_text("# a router lives here\n", encoding="utf-8")
    return str(d)


def _service_toml(tmp_path: Path, *, key_b64: str | None, destination: str | None = None) -> str:
    """Write a messagefoundry.toml carrying [store].encryption_key (+ optional [backup].destination)."""
    lines = ["[store]"]
    if key_b64 is not None:
        lines.append(f'encryption_key = "{key_b64}"')
    if destination is not None:
        lines += ["", "[backup]", f'destination = "{_toml_str(destination)}"']
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(toml)


def _toml_str(value: str) -> str:
    # Windows paths carry backslashes; escape them for a valid TOML basic string.
    return value.replace("\\", "\\\\")


def _json_line(out: str) -> dict:
    """Parse the last ``{``-leading line of captured stdout (the compact JSON payload)."""
    lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
    assert lines, f"no JSON object on stdout: {out!r}"
    return json.loads(lines[-1])


def _assert_phi_free(out: str) -> None:
    assert "raw-body" not in out, "raw HL7 body leaked to stdout"
    assert "DOE^JOHN" not in out, "PHI summary leaked to stdout"


# --- (1) backup: JSON summary of a real, verified round-trip -----------------


def test_backup_json_summary_writes_verified_archive(tmp_path, key_b64, capsys) -> None:
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    dest = tmp_path / "backups"
    toml = _service_toml(tmp_path, key_b64=key_b64)

    rc = main(
        [
            "backup",
            "--config",
            _config_dir(tmp_path),
            "--service-config",
            toml,
            "--db",
            str(db),
            "--destination",
            str(dest),
            "--json",
        ]
    )
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    # The archive named in the payload exists on disk and verified clean.
    assert Path(payload["archive"]).exists()
    assert payload["verify"] == "PASS"
    assert payload["encrypted"] is True
    # The PHI-free metadata the CLI promises is all present.
    for field in ("archive", "key_id", "config_fingerprint", "row_counts", "snapshot_sha256"):
        assert field in payload
    assert payload["key_id"]  # a real fingerprint, not None
    assert payload["row_counts"].get("queue", 0) >= 1


# --- (2) flag plumbing: --config-only / --no-verify / --full-verify ----------


def test_backup_config_only_flag(tmp_path, key_b64, capsys) -> None:
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, destination=str(tmp_path / "b"))
    rc = main(
        [
            "backup",
            "--config",
            _config_dir(tmp_path),
            "--service-config",
            toml,
            "--db",
            str(db),
            "--config-only",
            "--json",
        ]
    )
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["config_only"] is True
    assert payload["snapshot_sha256"] == ""  # no DB snapshot taken


def test_backup_no_verify_flag(tmp_path, key_b64, capsys) -> None:
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, destination=str(tmp_path / "b"))
    rc = main(
        [
            "backup",
            "--config",
            _config_dir(tmp_path),
            "--service-config",
            toml,
            "--db",
            str(db),
            "--no-verify",
            "--json",
        ]
    )
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["verify"] == "skipped"


def test_backup_full_verify_flag(tmp_path, key_b64, capsys) -> None:
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, destination=str(tmp_path / "b"))
    rc = main(
        [
            "backup",
            "--config",
            _config_dir(tmp_path),
            "--service-config",
            toml,
            "--db",
            str(db),
            "--full-verify",
            "--json",
        ]
    )
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["verify"] == "PASS"  # the heavier full restore-verify path still passes


# --- (3) no-destination error -------------------------------------------------


def test_backup_no_destination_errors(tmp_path, key_b64, capsys) -> None:
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64)  # no [backup].destination, no --destination
    rc = main(
        ["backup", "--config", _config_dir(tmp_path), "--service-config", toml, "--db", str(db)]
    )
    assert rc == 1
    out = capsys.readouterr().out
    # No destination -> non-zero with a destination-naming error. Because _backup forces
    # [backup].enabled=true for the on-demand run, the settings validator ("enabled=true requires a
    # non-empty [backup].destination") fires at load_settings BEFORE _backup's own empty-destination
    # guard at __main__.py:2611 — either way the operator is told the destination is missing.
    assert "destination" in out.lower()


# --- (4) not-leader defensive branch -----------------------------------------


def test_backup_not_leader_returns_error(tmp_path, key_b64, capsys, monkeypatch) -> None:
    # The leader-gated no-op (run_once -> None) is unreachable on the single-node CLI path; drive the
    # defensive branch by stubbing run_once rather than standing up a coordinator.
    async def _no_leader(self, *a, **k):
        return None

    monkeypatch.setattr("messagefoundry.pipeline.dr_backup.BackupRunner.run_once", _no_leader)
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, destination=str(tmp_path / "b"))
    rc = main(
        ["backup", "--config", _config_dir(tmp_path), "--service-config", toml, "--db", str(db)]
    )
    assert rc == 1
    assert "backup did not run (not leader)" in capsys.readouterr().out


# --- (5) BackupError surfaces as exit 1 with the failing kind ----------------


def test_backup_error_maps_to_exit_1(tmp_path, key_b64, capsys, monkeypatch) -> None:
    async def _boom(self, *a, **k):
        raise BackupError("encrypt", "synthetic failure")

    monkeypatch.setattr("messagefoundry.pipeline.dr_backup.BackupRunner.run_once", _boom)
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, destination=str(tmp_path / "b"))
    rc = main(
        ["backup", "--config", _config_dir(tmp_path), "--service-config", toml, "--db", str(db)]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "backup failed (encrypt)" in out


# --- (6) restore-verify: PASS / missing / KEY_MISMATCH / FAIL ----------------


def _make_archive(tmp_path: Path, key_b64: str, capsys) -> tuple[str, str]:
    """Run a real backup and return (archive_path, service_toml_path)."""
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    dest = tmp_path / "backups"
    toml = _service_toml(tmp_path, key_b64=key_b64)
    rc = main(
        [
            "backup",
            "--config",
            _config_dir(tmp_path),
            "--service-config",
            toml,
            "--db",
            str(db),
            "--destination",
            str(dest),
            "--json",
        ]
    )
    assert rc == 0
    archive = _json_line(capsys.readouterr().out)["archive"]
    return archive, toml


def test_restore_verify_pass(tmp_path, key_b64, capsys) -> None:
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    rc = main(["restore-verify", archive, "--service-config", toml, "--json"])
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["status"] == "PASS"
    assert payload["integrity_ok"] is True
    assert payload["row_counts"] == payload["manifest_counts"]


def test_restore_verify_missing_archive(tmp_path, key_b64, capsys) -> None:
    toml = _service_toml(tmp_path, key_b64=key_b64)
    missing = str(tmp_path / "nope.mfbak")
    rc = main(["restore-verify", missing, "--service-config", toml, "--json"])
    assert rc == 1
    assert "no archive at" in capsys.readouterr().out


def test_restore_verify_key_mismatch(tmp_path, key_b64, capsys) -> None:
    archive, _ = _make_archive(tmp_path, key_b64, capsys)
    # A service config whose store key does not match the archive DEK -> clean KEY_MISMATCH, exit 1.
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    wrong_toml = _service_toml(other_dir, key_b64=generate_key())
    rc = main(["restore-verify", archive, "--service-config", wrong_toml, "--json"])
    assert rc == 1
    payload = _json_line(capsys.readouterr().out)
    assert payload["status"] == "KEY_MISMATCH"


def test_restore_verify_corrupted_archive_fails(tmp_path, key_b64, capsys) -> None:
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    # Flip a ciphertext byte so the GCM tag fails -> FAIL, exit 1.
    blob = bytearray(Path(archive).read_bytes())
    blob[-40] ^= 0x01
    corrupt = Path(archive).with_suffix(".corrupt.mfbak")
    corrupt.write_bytes(bytes(blob))
    rc = main(["restore-verify", str(corrupt), "--service-config", toml, "--json"])
    assert rc == 1
    payload = _json_line(capsys.readouterr().out)
    assert payload["status"] == "FAIL"


# --- (7) PHI-safe stdout for both subcommands, JSON and human ----------------


@pytest.mark.parametrize("as_json", [True, False])
def test_backup_stdout_is_phi_free(tmp_path, key_b64, capsys, as_json) -> None:
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, destination=str(tmp_path / "b"))
    argv = ["backup", "--config", _config_dir(tmp_path), "--service-config", toml, "--db", str(db)]
    if as_json:
        argv.append("--json")
    assert main(argv) == 0
    _assert_phi_free(capsys.readouterr().out)


@pytest.mark.parametrize("as_json", [True, False])
def test_restore_verify_stdout_is_phi_free(tmp_path, key_b64, capsys, as_json) -> None:
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    argv = ["restore-verify", archive, "--service-config", toml]
    if as_json:
        argv.append("--json")
    assert main(argv) == 0
    _assert_phi_free(capsys.readouterr().out)
