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
from messagefoundry.store.backup_codec import decrypt_stream
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


def _config_dir(tmp_path: Path, *, plant: dict[str, bytes] | None = None) -> str:
    """A minimal config bundle (one module) so the archive carries a real config member.

    ``plant`` adds extra files under the config dir, which the backup writer includes verbatim
    (`_add_config_dir` takes every regular file) -- used to build a member that collides with a restore
    destination."""
    d = tmp_path / "config"
    d.mkdir()
    (d / "feed.py").write_text("# a router lives here\n", encoding="utf-8")
    (d / "codesets").mkdir()
    (d / "codesets" / "sex.csv").write_text("M,Male\n", encoding="utf-8")
    for rel, body in (plant or {}).items():
        target = d / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
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


def _refusal(capsys) -> str:
    """The stream a refusal actually lands on, named once here rather than at each assertion.

    ``_emit_error`` sends human-readable failures to **stderr** (BACKLOG #1673), so that a shell
    redirect of a command's output cannot swallow the reason the command failed into the file it was
    writing. Under ``--json`` the error object IS the machine-readable output and stays on stdout, so
    those cases are read with :func:`_json_line` instead -- do not route them through here.

    ``readouterr()`` CLEARS both buffers, so this is one call and the stdout half is deliberately
    dropped: every caller is a refusal case, where stdout is empty by design."""
    return capsys.readouterr().err


def _assert_phi_free(out: str, err: str = "") -> None:
    """Neither stream carries PHI. ``err`` is checked too because refusals moved there (BACKLOG
    #1673): a guard that named only stdout would stop covering the whole error path the day that
    landed, while still reading like a complete PHI check."""
    for stream, text in (("stdout", out), ("stderr", err)):
        assert "raw-body" not in text, f"raw HL7 body leaked to {stream}"
        assert "DOE^JOHN" not in text, f"PHI summary leaked to {stream}"


def _make_archive(
    tmp_path: Path,
    key_b64: str | None,
    capsys,
    *,
    config: bool = True,
    plant: dict[str, bytes] | None = None,
) -> tuple[str, str]:
    """Run a real backup and return ``(archive_path, service_toml_path)``."""
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, allow_unencrypted=key_b64 is None)
    argv = [
        "backup",
        "--config",
        _config_dir(tmp_path, plant=plant) if config else str(tmp_path / "empty-config"),
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
    err = _refusal(capsys)
    assert "refusing to overwrite" in err
    assert str(dest) in err  # the message names the path
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
    err = _refusal(capsys)
    assert "refusing to overwrite" in err and "-wal" in err
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
    assert "KEY_MISMATCH" in _refusal(capsys)
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
    err = _refusal(capsys)
    assert "did not verify" in err
    assert not dest.exists()
    # The refusal must keep BOTH halves of what the codec can tell: a failed tag means bad bytes OR the
    # wrong key. These two substrings come from backup_codec, deliberately -- an operator told only
    # "corrupt" goes hunting for bad media when the archive is intact and the DEK is not, so if a codec
    # reword ever drops the distinction, this is the assertion that should notice.
    assert "wrong key" in err
    assert "corrupt" in err


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
    assert "did not verify" in _refusal(capsys)
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
    err = _refusal(capsys)
    assert "KEY_MISMATCH" in err
    assert "did not verify" not in err  # NOT relabelled as a corrupt archive
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
    assert "restore failed" in _refusal(capsys)
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
    assert "refusing to overwrite" in _refusal(capsys)
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
    assert "no archive at" in _refusal(capsys)


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
    assert "non-empty" in _refusal(capsys)
    assert (cfg / "mine.py").exists()


def test_restore_refuses_a_config_member_aimed_at_the_restored_store(
    tmp_path, key_b64, capsys
) -> None:
    # P1 (BACKLOG #1717): `--to D/store.db --config-to D` passed every emptiness check, because both
    # destinations really were absent when they were read. The restore then published the verified
    # store at D/store.db and extracted the config bundle over the top of it, so the archive's own
    # `config/store.db` member -- a plain file in the operator's config dir, which the backup writer
    # includes like any other -- replaced the database that had just passed integrity_check and the
    # row-count compare, and the summary still reported the pre-overwrite counts.
    #
    # Measured at 85c77e398 before the fix: rc 0, row_counts {"messages": 1, ...}, store_bytes 372736,
    # and 28 bytes of `CONFIG-MEMBER-NOT-A-DATABASE` at the --to path.
    planted = b"CONFIG-MEMBER-NOT-A-DATABASE"
    archive, toml = _make_archive(tmp_path, key_b64, capsys, plant={"store.db": planted})
    newdir = tmp_path / "restored"
    dest = newdir / "store.db"

    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(dest),
            "--config-to",
            str(newdir),
            "--service-config",
            toml,
        ]
    )
    assert rc == 1
    # Human output, not --json: the paths are compared verbatim, and JSON would escape the separators.
    err = _refusal(capsys)
    assert "where this restore publishes the store" in err
    assert str(dest) in err  # the colliding path is named
    # Refused BEFORE the store was extracted, so nothing was published and nothing was clobbered: no
    # store at the --to path, and no half-written config bundle beside it.
    assert not dest.exists()
    assert list(newdir.iterdir()) == []


def test_restore_refuses_a_colliding_config_member_whatever_the_case(
    tmp_path, key_b64, capsys
) -> None:
    # The same collision spelled in a different case. os.path.normcase is the identity function on
    # POSIX, so folding case with it would miss case-insensitive macOS and every case-insensitive
    # mount. The refusal folds case unconditionally instead, and this asserts the same answer on every
    # platform rather than branching on one that cannot be read from normcase.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, plant={"store.db": b"planted"})
    dest = tmp_path / "restored" / "store.db"
    shouted = tmp_path / "RESTORED"

    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(dest),
            "--config-to",
            str(shouted),
            "--service-config",
            toml,
        ]
    )
    assert rc == 1
    assert "where this restore publishes the store" in _refusal(capsys)
    assert not dest.exists()


def test_restore_allows_one_directory_for_the_store_and_the_config(
    tmp_path, key_b64, capsys
) -> None:
    # The false-refusal guard on the fix above. `--to D/store.db --config-to D` is the one-directory
    # form the early-adopter drill documents, and it is perfectly safe for an ordinary archive whose
    # bundle is feed.py plus codesets. The refusal asks whether a MEMBER collides, not the much broader
    # "does --config-to contain --to", so this must still succeed and the store must still read back.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    newdir = tmp_path / "restored"
    dest = newdir / "store.db"

    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(dest),
            "--config-to",
            str(newdir),
            "--service-config",
            toml,
            "--json",
        ]
    )
    assert rc == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["config_files"] == 2
    assert (newdir / "feed.py").read_text(encoding="utf-8") == "# a router lives here\n"
    count, raw = asyncio.run(_read_back(dest, key_b64))
    assert count == 1 and raw == _RAW_BODY  # the store survived the bundle landing beside it


def test_restore_refuses_a_config_dest_under_the_store_path(tmp_path, key_b64, capsys) -> None:
    # The mirror shape: `--to D --config-to D/cfg`. Both destinations are absent, so the emptiness
    # checks pass; the store is then published as the regular FILE D, and the bundle's
    # mkdir(parents=True) cannot create a directory beneath it. Before the fix that was an uncaught
    # FileExistsError -- a CLI traceback with a restored store already sitting at D, and a retry
    # blocked by the never-overwrite refusal. No legitimate invocation has this shape.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored"
    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(dest),
            "--config-to",
            str(dest / "cfg"),
            "--service-config",
            toml,
        ]
    )
    assert rc == 1
    assert "sits under the restored store's own path" in _refusal(capsys)
    assert not dest.exists()  # refused before any decrypt


def test_restore_refuses_a_config_dest_that_is_an_existing_file(tmp_path, key_b64, capsys) -> None:
    # `any(config_dest.iterdir())` on a FILE raises NotADirectoryError, which is not a BackupError and
    # so escaped the CLI handler as a traceback. An operator who types a file path where a directory
    # belongs gets the refusal the check exists to produce.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    not_a_dir = tmp_path / "typo.toml"
    not_a_dir.write_text("# a file, not a directory\n", encoding="utf-8")

    rc = main(
        [
            "restore",
            archive,
            "--to",
            str(tmp_path / "restored.db"),
            "--config-to",
            str(not_a_dir),
            "--service-config",
            toml,
        ]
    )
    assert rc == 1
    assert "names an existing file" in _refusal(capsys)
    assert not_a_dir.read_text(encoding="utf-8") == "# a file, not a directory\n"


def test_restore_config_bundle_never_overwrites_an_existing_file(tmp_path, key_b64, capsys) -> None:
    # The backstop under the refusals above, exercised directly on the extractor: a config member must
    # not land on a file that is already there, whatever route put it there. Drives
    # _restore_config_members rather than the CLI, because the up-front refusals make the collision
    # unreachable from the command line by design -- which is the point of them.
    archive, _toml = _make_archive(tmp_path, key_b64, capsys)
    cfg = tmp_path / "bundle"
    cfg.mkdir()
    (cfg / "feed.py").write_bytes(b"mine, and older")

    # Decrypt the real archive to the plain tar the extractor consumes, under the same DEK.
    tar = tmp_path / "plain.tar"
    with open(archive, "rb") as src, open(tar, "wb") as dst:
        decrypt_stream(src, dst, base64.b64decode(key_b64))

    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_config_members(tar, cfg)
    assert excinfo.value.kind == "restore"
    assert "refusing to overwrite the existing file" in str(excinfo.value)
    assert (cfg / "feed.py").read_bytes() == b"mine, and older"  # untouched


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
    assert "no config bundle" in _refusal(capsys)


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
    assert "CONFIG-ONLY" in _refusal(capsys)
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
    captured = capsys.readouterr()
    _assert_phi_free(captured.out, captured.err)


# --- (7) the pre-publish row-count compare -----------------------------------


def _snap_with(tmp_path: Path, messages: int) -> Path:
    """A minimal two-table SQLite file standing in for an extracted ``store.db``."""
    import sqlite3

    snap = tmp_path / "store.db"
    conn = sqlite3.connect(snap)
    try:
        conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE queue (id INTEGER PRIMARY KEY)")
        conn.executemany(
            "INSERT INTO messages (id) VALUES (?)", [(i,) for i in range(1, messages + 1)]
        )
        conn.commit()
    finally:
        conn.close()
    return snap


@pytest.mark.parametrize(
    ("label", "manifest_counts", "raises"),
    [
        # The compare is keyed off the MANIFEST's keys, not dict equality, because `_count_tables`
        # derives its table set from the snapshot's own sqlite_master (BACKLOG #1722). These pin both
        # directions of that: what must still refuse, and what must no longer refuse.
        ("exact match", {"messages": 3, "queue": 0}, False),
        # Real data loss, which is the whole point of the check.
        ("torn: manifest declares more rows than survived", {"messages": 5, "queue": 0}, True),
        # A table the manifest tracked that the snapshot's schema lacks reads as 0, so a NONZERO
        # manifest count for it is still loss and still refuses.
        ("dropped table the manifest counted", {"messages": 3, "audit_log": 7}, True),
        # ...and a zero one is the documented convention for a table absent from the schema.
        ("absent table the manifest recorded as 0", {"messages": 3, "audit_log": 0}, False),
        # The case dict equality got wrong: an archive whose manifest predates the widened table set
        # is the ORDINARY thing to restore, and equality would have refused every one of them.
        ("older, narrower manifest", {"messages": 3}, False),
        ("manifest carrying no row_counts at all", None, False),
    ],
)
def test_restore_row_count_compare(tmp_path, label, manifest_counts, raises) -> None:
    snap = _snap_with(tmp_path, messages=3)
    manifest: dict[str, object] = {} if manifest_counts is None else {"row_counts": manifest_counts}
    if raises:
        with pytest.raises(dr_backup.BackupError, match="row-count mismatch"):
            dr_backup._verify_extracted_store(snap, manifest)
    else:
        assert dr_backup._verify_extracted_store(snap, manifest) == {"messages": 3, "queue": 0}
