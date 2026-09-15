# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CLI dispatch for the DR ``restore`` subcommand (ADR 0049, #60) — the half that was missing.

The engine could write a ``.mfbak`` archive and verify one, and had no way to RESTORE one. These drive
``main(argv)`` end-to-end through the parser + ``_DISPATCH`` on a SQLite-backed store, in the shape of
tests/test_cli_backup_dispatch.py: the REAL round trip (back up -> restore -> reopen the restored store
and read the rows back), the overwrite refusal, the encrypted-archive path, ``--config-to``, and the
PHI-safe-stdout invariant.

The round trip is the one that matters. A restore command tested only for argument parsing would leave
the actual defect in place."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.pipeline import dr_backup
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher

# Synthetic body + summary planted in the seeded store; asserted to NEVER surface on stdout.
_RAW_BODY = "MSH|^~\\&|raw-body"
_SUMMARY = "MRN001 DOE^JOHN"
_CONTROL_ID = "CID-1"


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
        control_id=_CONTROL_ID,
        message_type="ADT^A01",
        summary=_SUMMARY,
        now=1.0,
    )
    await store.close()


def _config_dir(tmp_path: Path) -> str:
    """A minimal config bundle (one module) so the archive carries a real config member."""
    d = tmp_path / "config"
    d.mkdir()
    (d / "feed.py").write_text("# a router lives here\n", encoding="utf-8")
    (d / "codesets").mkdir()
    (d / "codesets" / "sex.csv").write_text("M,Male\n", encoding="utf-8")
    return str(d)


def _service_toml(
    tmp_path: Path, *, key_b64: str | None, allow_unencrypted: bool = False, name: str = "svc.toml"
) -> str:
    lines = ["[store]"]
    if key_b64 is not None:
        lines.append(f'encryption_key = "{key_b64}"')
    if allow_unencrypted:
        lines += ["", "[backup]", "allow_unencrypted = true"]
    toml = tmp_path / name
    toml.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(toml)


def _no_hard_links(src, dst) -> None:
    """Stand in for os.link on a volume that has none (FAT, some SMB shares), forcing the
    exclusive-create copy fallback in _place_restored_store."""
    raise OSError("hard links are unavailable on this volume")


def _json_line(out: str) -> dict:
    lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
    assert lines, f"no JSON object on stdout: {out!r}"
    return json.loads(lines[-1])


def _assert_phi_free(out: str) -> None:
    assert "raw-body" not in out, "raw HL7 body leaked to stdout"
    assert "DOE^JOHN" not in out, "PHI summary leaked to stdout"


def _make_archive(
    tmp_path: Path, key_b64: str | None, capsys, *, config: bool = True
) -> tuple[str, str]:
    """Run a real backup and return ``(archive_path, service_toml_path)``."""
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, allow_unencrypted=key_b64 is None)
    argv = [
        "backup",
        "--config",
        _config_dir(tmp_path) if config else str(tmp_path / "empty-config"),
        "--service-config",
        toml,
        "--db",
        str(db),
        "--destination",
        str(tmp_path / "backups"),
        "--json",
    ]
    if not config:
        (tmp_path / "empty-config").mkdir()
    assert main(argv) == 0
    return _json_line(capsys.readouterr().out)["archive"], toml


async def _read_back(db: Path, key_b64: str | None) -> tuple[int, str | None]:
    """Open a restored store through the real path and report (message count, the row's raw body)."""
    cipher = make_cipher(key_b64) if key_b64 else None
    store = await MessageStore.open(db, cipher=cipher)
    try:
        count = await store.count_messages()
        rows = await store.list_messages(limit=10)
        raw: str | None = None
        if rows:
            msg = await store.get_message(rows[0]["id"])
            raw = None if msg is None else msg.get("raw")
        return count, raw
    finally:
        await store.close()


# --- (1) the round trip: back up -> restore -> the restored store carries the rows ----


def test_restore_round_trip_reopens_with_the_expected_rows(tmp_path, key_b64, capsys) -> None:
    # THE test for #1717: a .mfbak archive can actually be restored, and the restored store opens
    # through the real MessageStore path carrying the row the backup captured.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"

    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml, "--json"])
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["store"] == str(dest)
    assert payload["encrypted"] is True
    assert payload["key_id"]  # a real one-way fingerprint, not None
    assert payload["store_bytes"] > 0
    assert payload["row_counts"].get("messages", 0) >= 1

    assert dest.is_file()
    count, raw = asyncio.run(_read_back(dest, key_b64))
    assert count == 1
    assert raw == _RAW_BODY  # the restored store decrypts under the same DEK and carries the body


def test_restore_round_trip_unencrypted_archive(tmp_path, capsys) -> None:
    # The keyless/[backup].allow_unencrypted path restores too (a plaintext tar, no codec header).
    archive, toml = _make_archive(tmp_path, None, capsys)
    dest = tmp_path / "restored" / "msg.db"
    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml, "--json"])
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["encrypted"] is False and payload["key_id"] is None
    count, raw = asyncio.run(_read_back(dest, None))
    assert count == 1 and raw == _RAW_BODY


# --- (2) it refuses to overwrite ---------------------------------------------


def test_restore_refuses_existing_destination(tmp_path, key_b64, capsys) -> None:
    # Restoring over a live store is unrecoverable and the CLI cannot ask, so an existing --to is
    # refused with the path named, and the existing bytes are left exactly as they were.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "occupied.db"
    dest.write_bytes(b"not-a-store-but-mine")

    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    assert rc == 1
    out = capsys.readouterr().out
    assert "refusing to overwrite" in out
    assert str(dest) in out  # the message names the path
    assert dest.read_bytes() == b"not-a-store-but-mine"  # untouched


def test_restore_refuses_existing_wal_sidecar(tmp_path, key_b64, capsys) -> None:
    # A WAL-mode store is three files. Restoring store.db beside a leftover store.db-wal from a
    # DIFFERENT database would let SQLite replay that stale WAL over the restored pages.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored.db"
    sidecar = tmp_path / "restored.db-wal"
    sidecar.write_bytes(b"stale wal")

    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    assert rc == 1
    out = capsys.readouterr().out
    assert "refusing to overwrite" in out and "-wal" in out
    assert not dest.exists()  # nothing was written next to the sidecar


# --- (3) the archive must verify before anything lands -----------------------


def test_restore_refuses_wrong_key(tmp_path, key_b64, capsys) -> None:
    archive, _ = _make_archive(tmp_path, key_b64, capsys)
    other = tmp_path / "other"
    other.mkdir()
    wrong_toml = _service_toml(other, key_b64=generate_key())
    dest = tmp_path / "restored.db"
    rc = main(["restore", archive, "--to", str(dest), "--service-config", wrong_toml])
    assert rc == 1
    assert "KEY_MISMATCH" in capsys.readouterr().out
    assert not dest.exists()


def test_restore_refuses_corrupt_archive(tmp_path, key_b64, capsys) -> None:
    # A flipped ciphertext byte fails the GCM tag: the verify gate fires BEFORE anything is written,
    # so a corrupt archive never lands on the destination as a store an operator believes is good.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    blob = bytearray(Path(archive).read_bytes())
    blob[-40] ^= 0x01
    corrupt = Path(archive).with_suffix(".corrupt.mfbak")
    corrupt.write_bytes(bytes(blob))
    dest = tmp_path / "restored.db"
    rc = main(["restore", str(corrupt), "--to", str(dest), "--service-config", toml])
    assert rc == 1
    out = capsys.readouterr().out
    assert "did not verify" in out
    assert not dest.exists()
    # The refusal must keep BOTH halves of what the codec can tell: a failed tag means bad bytes OR the
    # wrong key. These two substrings come from backup_codec, deliberately -- an operator told only
    # "corrupt" goes hunting for bad media when the archive is intact and the DEK is not, so if a codec
    # reword ever drops the distinction, this is the assertion that should notice.
    assert "wrong key" in out
    assert "corrupt" in out


def test_restore_refuses_an_archive_whose_header_will_not_parse(tmp_path, key_b64, capsys) -> None:
    # The magic survives but the format-version byte does not, so the failure lands in the header read
    # (archive_key_id) rather than in the decrypt -- one step earlier, and the same refusal. Before the
    # fix this escaped as a raw BackupCodecError, exactly as the flipped-ciphertext case did.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    blob = bytearray(Path(archive).read_bytes())
    blob[6] = 99  # the version byte, immediately after the 6-byte magic
    bad = Path(archive).with_suffix(".badversion.mfbak")
    bad.write_bytes(bytes(blob))
    dest = tmp_path / "restored.db"

    rc = main(["restore", str(bad), "--to", str(dest), "--service-config", toml])
    assert rc == 1
    assert "did not verify" in capsys.readouterr().out
    assert not dest.exists()


def test_restore_key_mismatch_from_the_decrypt_is_not_reported_as_a_bad_archive(
    tmp_path, key_b64, capsys, monkeypatch
) -> None:
    # BackupKeyMismatch is a SUBCLASS of BackupCodecError, so a single catch would report it as a
    # generic bad archive and point the operator at the bytes when the key is the subject. It survives
    # the fingerprint precheck through a real window: archive_key_id reads the header, decrypt_stream
    # re-reads it, and an archive swapped between those two reads is approved by a precheck that ran
    # against the old header. Standing in for that window by handing the decrypt a key the precheck
    # approved and the header does not.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    rival = generate_key()
    monkeypatch.setattr(dr_backup, "_select_decrypt_key", lambda keys, kid: base64.b64decode(rival))
    dest = tmp_path / "restored.db"

    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    assert rc == 1
    out = capsys.readouterr().out
    assert "KEY_MISMATCH" in out
    assert "did not verify" not in out  # NOT relabelled as a corrupt archive
    assert not dest.exists()


# --- (3b) a failed WRITE leaves nothing behind either -------------------------


def test_restore_leaves_no_partial_store_when_the_copy_dies(
    tmp_path, key_b64, capsys, monkeypatch
) -> None:
    # The non-hardlink path (FAT, some SMB shares) copies into an exclusively-created file. A copy that
    # dies mid-stream would otherwise leave a TRUNCATED store at --to: a plausible-looking SQLite file
    # an operator could activate, and debris that would then fail the retry's own never-overwrite check.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored.db"

    def _die_mid_copy(fsrc, fdst, length=0) -> None:
        fdst.write(b"SQLite format 3\x00")  # enough to look like a real store to a casual reader
        raise OSError("no space left on device")

    monkeypatch.setattr(os, "link", _no_hard_links)
    # Patching copyfileobj globally reaches only _place_restored_store on this path: _extract_member
    # uses its own read loop, and the plaintext branch is skipped for an encrypted archive.
    monkeypatch.setattr(shutil, "copyfileobj", _die_mid_copy)

    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    assert rc == 1
    assert "restore failed" in capsys.readouterr().out
    assert not dest.exists()  # the truncated bytes were removed, not left to be activated


def test_restore_does_not_delete_the_winner_of_a_create_race(
    tmp_path, key_b64, capsys, monkeypatch
) -> None:
    # The mirror of the test above, and the reason the exclusive create sits OUTSIDE the cleanup guard:
    # losing the create race is a REFUSAL, so the file already at --to belongs to the winner. Removing
    # it would turn the refusal into the unrecoverable overwrite the refusal exists to prevent.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored.db"
    real_verify = dr_backup._verify_extracted_store

    def _plant_a_rival(snap, manifest):
        # The rival's file must appear AFTER the up-front destination check and before the create --
        # the only window in which the create race can be lost.
        counts = real_verify(snap, manifest)
        dest.write_bytes(b"the winner's store")
        return counts

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(dr_backup, "_verify_extracted_store", _plant_a_rival)

    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    assert rc == 1
    assert "refusing to overwrite" in capsys.readouterr().out
    assert dest.read_bytes() == b"the winner's store"  # untouched by the loser's cleanup


def test_restore_missing_archive(tmp_path, key_b64, capsys) -> None:
    toml = _service_toml(tmp_path, key_b64=key_b64)
    rc = main(
        [
            "restore",
            str(tmp_path / "nope.mfbak"),
            "--to",
            str(tmp_path / "restored.db"),
            "--service-config",
            toml,
        ]
    )
    assert rc == 1
    assert "no archive at" in capsys.readouterr().out


# --- (4) --config-to ----------------------------------------------------------


def test_restore_config_to_writes_the_bundle(tmp_path, key_b64, capsys) -> None:
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored.db"
    cfg = tmp_path / "restored-config"
    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(dest),
            "--config-to",
            str(cfg),
            "--service-config",
            toml,
            "--json",
        ]
    )
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["config_files"] == 2
    assert (cfg / "feed.py").read_text(encoding="utf-8") == "# a router lives here\n"
    # The bundle keeps its relative layout (a nested codesets/ file lands nested, not flattened).
    assert (cfg / "codesets" / "sex.csv").read_text(encoding="utf-8") == "M,Male\n"


def test_restore_config_to_refuses_non_empty_dir(tmp_path, key_b64, capsys) -> None:
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    cfg = tmp_path / "restored-config"
    cfg.mkdir()
    (cfg / "mine.py").write_text("# already here\n", encoding="utf-8")
    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(tmp_path / "restored.db"),
            "--config-to",
            str(cfg),
            "--service-config",
            toml,
        ]
    )
    assert rc == 1
    assert "non-empty" in capsys.readouterr().out
    assert (cfg / "mine.py").exists()


def test_restore_config_to_refuses_when_archive_has_no_config(tmp_path, key_b64, capsys) -> None:
    # OPEN QUESTION, decided as a REFUSAL: an operator who asked for the config back and silently got
    # an empty directory would believe the config was restored. The store is still restored -- the
    # refusal names the missing bundle -- so this asserts the error, not a rollback of the store.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config=False)
    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(tmp_path / "restored.db"),
            "--config-to",
            str(tmp_path / "restored-config"),
            "--service-config",
            toml,
        ]
    )
    assert rc == 1
    assert "no config bundle" in capsys.readouterr().out


# --- (5) config-only archive has no store to restore -------------------------


def test_restore_refuses_config_only_archive(tmp_path, key_b64, capsys) -> None:
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64)
    assert (
        main(
            [
                "backup",
                "--config",
                _config_dir(tmp_path),
                "--service-config",
                toml,
                "--db",
                str(db),
                "--destination",
                str(tmp_path / "backups"),
                "--config-only",
                "--json",
            ]
        )
        == 0
    )
    archive = _json_line(capsys.readouterr().out)["archive"]
    dest = tmp_path / "restored.db"
    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    assert rc == 1
    assert "CONFIG-ONLY" in capsys.readouterr().out
    assert not dest.exists()


# --- (6) PHI-safe stdout, JSON and human -------------------------------------


@pytest.mark.parametrize("as_json", [True, False])
def test_restore_stdout_is_phi_free(tmp_path, key_b64, capsys, as_json) -> None:
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    argv = [
        "restore",
        archive,
        "--to",
        str(tmp_path / "restored.db"),
        "--config-to",
        str(tmp_path / "restored-config"),
        "--service-config",
        toml,
    ]
    if as_json:
        argv.append("--json")
    assert main(argv) == 0
    _assert_phi_free(capsys.readouterr().out)
