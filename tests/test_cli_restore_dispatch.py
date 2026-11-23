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
import contextlib
import ctypes
import inspect
import io
import json
import logging
import os
import shutil
import sys
import tarfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.pipeline import dr_backup
from messagefoundry.restore_notice import RESTORE_ROLLBACK_NOTICE
from messagefoundry.store import MessageStore
from messagefoundry.store.backup_codec import decrypt_stream
from messagefoundry.store.crypto import generate_key, make_cipher
from tests._phi_gate_provisions import AT_REST_OPT_OUT_TOML

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
    # A keyless box takes the audited at-rest opt-out, which BACKLOG #1916 requires of every command
    # that opens a fresh store with no key. Dotted keys, so they precede the first table.
    lines = [AT_REST_OPT_OUT_TOML.rstrip("\n")] if key_b64 is None else []
    lines.append("[store]")
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

    ``readouterr()`` CLEARS both buffers, so this is one call. Both halves are checked before the
    stderr half is returned:

    * **stdout must be EMPTY.** That is the half of #1673 a stderr assertion cannot see -- a refusal
      that printed to both streams would satisfy every caller below while still poisoning a redirect.
    * **neither half may carry PHI.** Checking it HERE rather than in one test is deliberate: it puts
      every refusal path in this module under the PHI guard, which is where the risk actually is. The
      success-path test drives :func:`_assert_phi_free` directly; before this, no refusal's output was
      PHI-checked at all, and #1673 had just moved every refusal onto a stream nothing examined."""
    captured = capsys.readouterr()
    assert captured.out == "", (
        "a refusal wrote to STDOUT as well as stderr; BACKLOG #1673 moved human-readable failures to "
        f"stderr precisely so a redirect of results cannot swallow them. Saw: {captured.out!r}"
    )
    _assert_phi_free(captured.out, captured.err)
    return captured.err


def _assert_phi_free(out: str, err: str) -> None:
    """Neither stream carries PHI.

    ``err`` has NO default on purpose. With one, a caller that passes only ``out`` checks half the
    surface while reading as a complete guard -- which is the exact defect #1673 created and this
    signature closes. Omitting it is a ``TypeError``, not a quiet half-check."""
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
    config_only: bool = False,
    config_dir: Path | None = None,
) -> tuple[str, str]:
    """Run a real backup and return ``(archive_path, service_toml_path)``. ``config_only`` passes
    ``--config-only``; ``config_dir`` backs up a config dir the caller already built."""
    db = tmp_path / "msg.db"
    asyncio.run(_seed_store(db, key_b64))
    toml = _service_toml(tmp_path, key_b64=key_b64, allow_unencrypted=key_b64 is None)
    if config_dir is not None:
        config_arg = str(config_dir)
    elif config:
        config_arg = _config_dir(tmp_path, plant=plant)
    else:
        config_arg = str(tmp_path / "empty-config")
    argv = [
        "backup",
        "--config",
        config_arg,
        "--service-config",
        toml,
        "--db",
        str(db),
        "--destination",
        str(tmp_path / "backups"),
        "--json",
        *(["--config-only"] if config_only else []),
    ]
    if config_dir is None and not config:
        (tmp_path / "empty-config").mkdir()
    assert main(argv) == 0
    return _json_line(capsys.readouterr().out)["archive"], toml


async def _read_back(db: Path, key_b64: str | None) -> tuple[int, str | None]:
    """Open a restored store through the real path and report (message count, the row's raw body)."""
    cipher = make_cipher(key_b64) if key_b64 else None
    store = await MessageStore.open(db, cipher=cipher)
    try:
        count = await store.count_messages(allowed_channels=None)
        rows = await store.list_messages(limit=10, allowed_channels=None)
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


def test_restore_refuses_a_dangling_wal_symlink(tmp_path, key_b64, capsys) -> None:
    # `Path.exists()` follows a link, so a dangling store.db-wal symlink read as free, and SQLite
    # would write the new store's WAL through it. Any name at a sidecar path is refused, links too.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dr = tmp_path / "dr"
    dr.mkdir()
    link = dr / "restored.db-wal"
    try:
        os.symlink(dr / "nowhere", link)
    except OSError as exc:  # Windows without the symlink privilege or developer mode
        pytest.skip(f"this platform cannot create a symlink here: {exc}")

    rc = main(["restore", archive, "--to", str(dr / "restored.db"), "--service-config", toml])
    assert rc == 1
    err = _refusal(capsys)
    assert "refusing to overwrite" in err and "-wal" in err
    assert sorted(p.name for p in dr.iterdir()) == ["restored.db-wal"]  # nothing written
    assert link.is_symlink() and not (dr / "nowhere").exists()  # the link is left as it was


@pytest.mark.parametrize(
    "suffix",
    [
        pytest.param(
            ".", marks=pytest.mark.skipif(sys.platform != "win32", reason="Win32 strips it")
        ),
        pytest.param(
            " ", marks=pytest.mark.skipif(sys.platform != "win32", reason="Win32 strips it")
        ),
        # Refused on every host, so one --to means the same everywhere.
        "::$DATA",
    ],
)
def test_restore_refuses_a_to_that_windows_opens_as_another_name(
    tmp_path, key_b64, capsys, suffix
) -> None:
    # `store.db.`, `store.db ` and `store.db::$DATA` all open `store.db` on Windows, but the sidecar
    # names derived from them (`store.db.-wal` and so on) are not the ones SQLite will use, so a stale
    # `store.db-wal` passed the never-overwrite check, beside a store SQLite would replay it over.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dr = tmp_path / "dr"
    dr.mkdir()
    stale = dr / "restored.db-wal"
    stale.write_bytes(b"stale wal")

    rc = main(
        ["restore", archive, "--to", str(dr / "restored.db") + suffix, "--service-config", toml]
    )
    assert rc == 1
    err = _refusal(capsys)
    assert "refusing --to" in err and "plain file name" in err
    assert sorted(p.name for p in dr.iterdir()) == ["restored.db-wal"]  # nothing written
    assert stale.read_bytes() == b"stale wal"


@pytest.mark.parametrize("sidecar", ["-wal", "-shm", "-journal"])
def test_restore_refuses_a_sidecar_planted_before_the_placement(
    tmp_path, key_b64, capsys, monkeypatch, sidecar
) -> None:
    # The up-front check runs before the decrypt; the exclusive create covers only the store's own
    # name. A sidecar that appears in between is caught by the second read just before placement.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dr = tmp_path / "dr"
    dr.mkdir()
    dest = dr / "restored.db"
    planted = dr / f"restored.db{sidecar}"
    real_verify = dr_backup._verify_extracted_store

    def _plant_a_sidecar(snap, manifest):
        counts = real_verify(snap, manifest)
        planted.write_bytes(b"planted sidecar")
        return counts

    monkeypatch.setattr(dr_backup, "_verify_extracted_store", _plant_a_sidecar)

    rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    assert rc == 1
    err = _refusal(capsys)
    assert "refusing to overwrite" in err and sidecar in err
    # nothing placed, and the staging directory is gone
    assert sorted(p.name for p in dr.iterdir()) == [planted.name]
    assert planted.read_bytes() == b"planted sidecar"


def test_a_fault_reading_a_sidecar_name_is_a_refusal_not_a_free_name(tmp_path, monkeypatch) -> None:
    # `os.path.lexists` answers False for every OSError, so a fault would read as a free name. Only a
    # name proven absent is free.
    real_lstat = os.lstat

    def _denied(path, *args, **kwargs):
        if str(path).endswith("-shm"):
            raise PermissionError(13, "denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", _denied)
    with pytest.raises(dr_backup.BackupError, match="cannot tell whether"):
        dr_backup._refuse_existing_destination(tmp_path / "restored.db", None)


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
    # store at the --to path, and no half-written config bundle beside it. The directory the restore
    # made to stage in goes too, since it was absent before (vault BACKLOG #5233).
    assert not dest.exists()
    assert not newdir.exists()


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
    # an empty directory would believe the config was restored.
    #
    # This test used to say "the store is still restored" and assert only the error. That WAS the
    # behaviour and it was the defect: the config bundle is written after the store, so every way it
    # can fail left a reported failure beside a published PHI-bearing store -- and the retry then met
    # the never-overwrite refusal, leaving a manual delete as the only way forward. The rollback
    # assertion and the retry below are the pin; this is the cheapest reachable arm that gets past
    # `_place_restored_store` and then fails.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config=False)
    dest = tmp_path / "restored.db"
    config_dest = tmp_path / "restored-config"
    argv = [
        "restore",
        archive,
        "--to",
        str(dest),
        "--config-to",
        str(config_dest),
        "--service-config",
        toml,
    ]
    assert main(argv) == 1
    assert "no config bundle" in _refusal(capsys)
    assert not dest.exists(), "a failed restore left the store it had already published"
    for sidecar in ("-wal", "-shm"):
        assert not dest.with_name(dest.name + sidecar).exists()

    # The payoff, and the half an existence assertion alone would miss: the SAME command now runs
    # again. Before the rollback it met the never-overwrite refusal on the store it had just left.
    assert main(argv) == 1
    assert "no config bundle" in _refusal(capsys)


def _restore_argv(archive: str, toml: str, dest: Path, config_dest: Path) -> list[str]:
    return [
        "restore",
        archive,
        "--to",
        str(dest),
        "--config-to",
        str(config_dest),
        "--service-config",
        toml,
    ]


def test_restore_rollback_removes_the_partial_config_bundle_too(tmp_path, key_b64, capsys) -> None:
    # The other half of the rollback: files the bundle DID write before it failed. The member-count
    # cap is the cheapest lever that fails PART-WAY THROUGH rather than before the first write, so
    # one member lands and the next refuses.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    config_dest = tmp_path / "bundle"
    argv = _restore_argv(archive, toml, dest, config_dest)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(argv) == 1
    assert "member-count cap" in _refusal(capsys)
    assert not dest.exists(), "the published store survived a mid-bundle failure"
    # What the bundle wrote must be gone, and the directory with it: it was absent before, and the
    # directories a failed restore made go too (vault BACKLOG #5233). The parent of --to as well.
    assert not config_dest.exists(), (
        "a partially written config bundle survived, which blocks the retry's empty-dir check"
    )
    assert not dest.parent.exists()
    # The control: with the shipped cap the SAME command restores, so the rollback left a destination
    # the retry can use. Without this arm a rollback that deleted too much would pass the asserts above.
    assert main(argv) == 0
    assert dest.is_file() and any(config_dest.iterdir())


def test_restore_rollback_in_the_one_directory_form_never_reaches_the_staging_dir(
    tmp_path, key_b64, capsys
) -> None:
    # `--to D/msg.db --config-to D` is the one-directory form `_refuse_colliding_config_members`
    # defends by name, and it puts the STAGING directory (`D/mefor-restore-*`) inside `--config-to`.
    # A rollback that empties `--config-to` on the strength of the emptiness check -- which ran
    # before the staging directory existed -- deletes the live staging directory out from under the
    # restore. The rollback must therefore run only after the staging directory is gone, and must
    # delete only what the restore recorded writing. Both are observed AT THE CALL, through a spy,
    # because the end state alone cannot tell the two designs apart: the teardown tolerates
    # its directory having been removed from under it, so the wrong design leaves the same tree.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    d = tmp_path / "dr"
    dest = d / "msg.db"
    argv = _restore_argv(archive, toml, dest, d)
    calls: list[tuple[list[str], list[Path]]] = []
    real_discard = dr_backup._discard_partial_restore

    def spy(dest_store_path: Path, written: list[Path]) -> None:
        calls.append((sorted(p.name for p in d.iterdir()), list(written)))
        real_discard(dest_store_path, written)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        mp.setattr(dr_backup, "_discard_partial_restore", spy)
        assert main(argv) == 1
    assert "member-count cap" in _refusal(capsys)

    # Exactly one rollback, and when it ran the staging directory no longer existed: the cleanup runs
    # AFTER the staging teardown has removed it, so it could not have been the thing that removed it.
    assert len(calls) == 1, calls
    names_at_call, ledger = calls[0]
    assert not any(n.startswith("mefor-restore-") for n in names_at_call), names_at_call
    # The ledger names only paths under `--config-to` that the bundle created -- one member landed
    # before the cap -- and never the staging directory or the store.
    assert ledger and all(p.is_relative_to(d.resolve()) for p in ledger), ledger
    assert not any(p.name.startswith("mefor-restore-") for p in ledger), ledger
    assert dest.resolve() not in ledger

    # End state: the directory is back as the restore found it, absent, so no staging leftover and
    # no store either (vault BACKLOG #5233: the directories a failed restore made go too).
    assert not d.exists(), sorted(p.name for p in d.rglob("*"))
    # And the control: the same command, with the shipped cap, restores into that directory.
    assert main(argv) == 0
    assert dest.is_file() and (d / "feed.py").is_file()


def test_discard_partial_restore_removes_only_the_recorded_paths(tmp_path) -> None:
    # The unit contract under the two tests above, with the counter-case they cannot plant: a
    # BYSTANDER in the same directory that the restore did not record. The one-directory form makes
    # the staging directory exactly such a bystander, so it is shaped like one here.
    d = tmp_path / "dr"
    store = d / "msg.db"
    recorded_dir = d / "codesets"
    recorded_file = recorded_dir / "sex.csv"
    top_file = d / "feed.py"
    shared_dir = d / "shared"
    shared_recorded = shared_dir / "ours.toml"
    stranger_in_shared = shared_dir / "theirs.toml"
    bystander_dir = d / "mefor-restore-bystander"
    bystander_file = bystander_dir / "archive.tar"
    for path in (
        store,
        recorded_file,
        top_file,
        shared_recorded,
        stranger_in_shared,
        bystander_file,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
    ledger = [top_file, recorded_dir, recorded_file, shared_dir, shared_recorded]

    dr_backup._discard_partial_restore(store, ledger)

    gone = [
        p for p in (store, top_file, recorded_file, recorded_dir, shared_recorded) if not p.exists()
    ]
    assert len(gone) == 5, f"recorded paths that survived: {[p for p in ledger if p.exists()]}"
    # Kept: the bystander directory and its file, the stranger's file, and the directory holding it
    # (recorded, but no longer empty -- so it is not this restore's to remove), and the root itself.
    assert bystander_file.is_file() and bystander_dir.is_dir()
    assert stranger_in_shared.is_file() and shared_dir.is_dir()
    assert d.is_dir()
    assert sorted(p.name for p in d.iterdir()) == ["mefor-restore-bystander", "shared"]


def _restore_staging_that_cannot_be_removed(mp: pytest.MonkeyPatch) -> None:
    """Make every removal of a RESTORE staging directory fail, as a scanner holding a file open in it
    does on Windows, with the retry schedule cut to nothing. The backup that builds the fixture
    archive stages under ``mefor-backup-`` and is not touched.

    The refused removal takes the lock file and marker first, as ``rmtree`` does on NTFS where the
    dot-names list first, so a leftover the sweep can still find proves the teardown re-marked it."""
    real_remove = dr_backup._remove_tree

    def refuse(path: Path) -> bool:
        if path.name.startswith("mefor-restore-"):
            for name in (".lock", ".lock-held"):
                (path / name).unlink(missing_ok=True)
            return False
        return real_remove(path)

    mp.setattr(dr_backup, "_remove_tree", refuse)
    mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())


def test_restore_keeps_a_whole_restore_when_its_staging_teardown_fails(
    tmp_path, key_b64, capsys
) -> None:
    # The regression the rollback brought in. `completed` flipped AFTER the staging block closed, so
    # the one thing between "config bundle written" and "completed" was the staging directory's own
    # teardown -- and when that raised, the rollback read a whole restore as a failed one and deleted
    # the placed, verified store. Before the rollback existed the same event left the store in place.
    # The operator was then left with no store, no bundle, a traceback instead of a refusal line (an
    # OSError, which the CLI does not translate), and the plaintext staging directory still on disk,
    # because the thing that failed was its remover.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    config_dest = tmp_path / "bundle"
    rollbacks: list[list[Path]] = []
    real_discard = dr_backup._discard_partial_restore

    def spy(dest_store_path: Path, written: list[Path]) -> None:
        rollbacks.append(list(written))
        real_discard(dest_store_path, written)

    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        # A staged file that could be neither removed nor emptied, so the leftover is reported.
        mp.setattr(dr_backup, "_empty_files_in_place", lambda staging: ["archive.tar"])
        mp.setattr(dr_backup, "_discard_partial_restore", spy)
        rc = main(_restore_argv(archive, toml, dest, config_dest))
    # Reported, as a refusal line and not a traceback, under a kind that does not say the restore
    # failed -- because it did not.
    assert rc == 1
    err = _refusal(capsys)
    assert "restore failed (cleanup)" in err and "staging directory" in err, err
    # The restore is whole, and no rollback ran. Two detectors on one event: the spy records a
    # rollback whether or not it deleted anything, and the file check catches one the spy missed.
    assert dest.is_file() and (config_dest / "feed.py").is_file()
    assert rollbacks == [], "a whole restore was rolled back over its staging teardown"
    # The leftover is named, so the operator can find and remove it. It survived because the thing
    # that failed was its remover. The staged store is not in it: that name went at placement.
    leftovers = [p for p in dest.parent.iterdir() if p.name.startswith("mefor-restore-")]
    assert len(leftovers) == 1, sorted(p.name for p in dest.parent.iterdir())
    assert leftovers[0].name in err and str(dest) in err, err
    assert not (leftovers[0] / "extracted_store.db").exists()
    # And the retry is refused for the RIGHT reason now: the destination holds a good store.
    assert main(_restore_argv(archive, toml, dest, config_dest)) == 1
    assert "restore failed (destination)" in _refusal(capsys)
    assert dest.is_file()


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


# --- (5a) vault BACKLOG #5233 item 6: a config-only archive's bundle has a restore route ----------
#
# The refusal above told the operator to "use --config-to for the config bundle", but --config-to is
# an option of this same command beside an argparse-required --to, so every run reached that refusal
# first and the bundle of a config-only archive, the default on both server backends, could not be
# restored at all. `--config-to <dir>` with no `--to` is now that route.


def _config_only_argv(archive: str, toml: str, config_dest: Path) -> list[str]:
    return ["restore", archive, "--config-to", str(config_dest), "--service-config", toml]


def _no_staging_left(parent: Path) -> None:
    leftovers = [p.name for p in parent.iterdir() if p.name.startswith("mefor-restore-")]
    assert leftovers == [], f"a restore staging directory survived: {leftovers}"


def test_restore_config_only_archive_bundle_with_config_to_alone(tmp_path, key_b64, capsys) -> None:
    # The subject: on the unfixed code argparse refuses this argv (--to is required) before any
    # restore code runs.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config_only=True)
    cfg = tmp_path / "restored-config"
    assert main([*_config_only_argv(archive, toml, cfg), "--json"]) == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["store"] is None and payload["store_bytes"] == 0
    assert payload["row_counts"] == {}
    # Carried whole: the store restored by other means rolls back what the notice says.
    assert payload["rollback_notice"] == RESTORE_ROLLBACK_NOTICE
    assert payload["encrypted"] is True and payload["key_id"]
    assert payload["config_dir"] == str(cfg) and payload["config_files"] == 2
    assert (cfg / "feed.py").read_text(encoding="utf-8") == "# a router lives here\n"
    assert (cfg / "codesets" / "sex.csv").read_text(encoding="utf-8") == "M,Male\n"
    # Nothing but the bundle: no store file anywhere, and the staging directory is gone.
    assert sorted(p.name for p in cfg.rglob("*")) == ["codesets", "feed.py", "sex.csv"]
    _no_staging_left(tmp_path)


def test_restore_config_only_text_summary_names_the_route(tmp_path, key_b64, capsys) -> None:
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config_only=True)
    cfg = tmp_path / "restored-config"
    assert main(_config_only_argv(archive, toml, cfg)) == 0
    captured = capsys.readouterr()
    _assert_phi_free(captured.out, captured.err)
    assert "CONFIG-ONLY" in captured.out and "2 file(s)" in captured.out, captured.out
    assert "DBA's own backup" in captured.out, captured.out


def test_restore_config_to_alone_refuses_an_archive_that_carries_a_store(
    tmp_path, key_b64, capsys
) -> None:
    # The control for the route above: --config-to alone is the CONFIG-ONLY route, and a whole-store
    # archive is refused on it rather than having its config extracted and its store dropped. It is
    # refused at the first tar header, which names the store, so the decrypt stops there and the
    # manifest is never reached: the spy records any read of it.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    cfg = tmp_path / "restored-config"
    manifest_reads: list[Path] = []
    real_read = dr_backup._read_manifest_from_tar

    def spy(tar_path: Path) -> dict[str, object]:
        manifest_reads.append(tar_path)
        return real_read(tar_path)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_read_manifest_from_tar", spy)
        assert main(_config_only_argv(archive, toml, cfg)) == 1
    assert manifest_reads == [], "the store-carrying archive was decrypted whole before refusal"
    err = _refusal(capsys)
    assert "restore failed (destination)" in err and "needs --to" in err, err
    assert not cfg.exists(), "a refused config-only route left the config directory behind"
    _no_staging_left(tmp_path)


def test_restore_refuses_a_run_with_neither_to_nor_config_to(tmp_path, capsys) -> None:
    # The CLI refuses it before it loads any settings, so a service config that does not exist
    # cannot hide this usage error behind its own.
    argv = ["restore", str(tmp_path / "never-read.mfbak"), "--service-config", str(tmp_path / "no")]
    assert main(argv) == 1
    err = _refusal(capsys)
    assert "restore failed (destination)" in err and "--config-to <dir> alone" in err, err
    # And the primitive refuses it for every other caller, before the archive is opened.
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_blocking(
            archive_path=str(tmp_path / "never-read.mfbak"),
            dest_store_path=None,
            config_dest=None,
            keys=[],
            max_age_seconds=None,
        )
    assert excinfo.value.kind == "destination"
    assert str(excinfo.value) == dr_backup.RESTORE_NEEDS_A_DESTINATION


def _undated_config_only_tar(tmp_path: Path) -> Path:
    """A plaintext config-only archive whose manifest says nothing of when it was taken."""
    return _plain_tar(
        tmp_path / "undated.tar",
        [("config/feed.py", b"# a router\n"), ("manifest.json", b'{"config_only": true}')],
    )


def test_restore_config_only_route_keeps_the_age_refusal(tmp_path, capsys) -> None:
    # --max-age-days and --allow-old-archive mean what they say on this route too: an undated
    # archive is refused, and nothing is written.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    cfg = tmp_path / "cfg"
    assert main(_config_only_argv(str(tar), toml, cfg)) == 1
    assert "restore failed (age_undated)" in _refusal(capsys)
    assert not cfg.exists()
    # The control: the override restores it.
    assert main([*_config_only_argv(str(tar), toml, cfg), "--allow-old-archive"]) == 0
    assert (cfg / "feed.py").read_bytes() == b"# a router\n"


def test_restore_refuses_when_the_staging_directory_cannot_be_made(tmp_path, capsys) -> None:
    # The staging directory goes beside the destination. A parent that cannot be made (here a path
    # under a regular file) is a refusal line, not a traceback, and nothing is written.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    blocker = tmp_path / "a-file"
    blocker.write_bytes(b"not a directory")
    cfg = blocker / "sub" / "cfg"
    argv = [*_config_only_argv(str(tar), toml, cfg), "--allow-old-archive"]
    assert main(argv) == 1
    err = _refusal(capsys)
    assert "restore failed (destination)" in err and "staging directory" in err, err
    assert blocker.read_bytes() == b"not a directory"


def test_restore_config_only_refusal_names_a_route_that_exists(tmp_path, key_b64, capsys) -> None:
    # The refusal a config-only archive meets with --to now names the route the test above runs,
    # and following it word for word restores the bundle.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config_only=True)
    assert main(["restore", archive, "--to", str(tmp_path / "x.db"), "--service-config", toml]) == 1
    err = _refusal(capsys)
    assert "--config-to <dir> and no --to" in err, err
    assert main(_config_only_argv(archive, toml, tmp_path / "cfg")) == 0


def test_restore_config_only_route_rolls_back_a_partial_bundle(tmp_path, key_b64, capsys) -> None:
    # The config-only route writes only the bundle, so a mid-bundle failure must leave the
    # destination as it found it, and the same command must then run again.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config_only=True)
    cfg = tmp_path / "bundle"
    argv = _config_only_argv(archive, toml, cfg)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(argv) == 1
    assert "member-count cap" in _refusal(capsys)
    # Absent before, so absent again: the directory a failed restore made goes too.
    assert not cfg.exists(), sorted(p.name for p in cfg.rglob("*"))
    _no_staging_left(tmp_path)
    # The control: with the shipped cap the same command restores.
    assert main(argv) == 0
    assert (cfg / "feed.py").is_file() and (cfg / "codesets" / "sex.csv").is_file()


# --- (5b-bis) vault BACKLOG #5233 item 2: a hard-link member is restored or refused, never skipped --


def _hard_link(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.LNKTYPE
    info.linkname = target
    return info


def test_restore_config_bundle_restores_a_hard_linked_name(tmp_path, key_b64, capsys) -> None:
    # End to end, from a real config dir: `tar.add` stores the second name of a hard-linked file as
    # a LNKTYPE member, and the extractor took regular members alone, so that name was not
    # restored. The first assertion is the control that the archive really carries that shape.
    config = Path(_config_dir(tmp_path))
    try:
        os.link(config / "feed.py", config / "feed_alias.py")
    except OSError as exc:
        pytest.skip(f"hard links unavailable on this volume: {exc}")
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config_dir=config)
    plain = tmp_path / "plain.tar"
    with open(archive, "rb") as src, open(plain, "wb") as dst:
        decrypt_stream(src, dst, base64.b64decode(key_b64))
    with tarfile.open(plain, "r:") as tar:
        links = [m.name for m in tar.getmembers() if m.islnk()]
    assert len(links) == 1 and links[0].startswith("config/feed"), links

    dest = tmp_path / "restored.db"
    cfg = tmp_path / "restored-config"
    assert main([*_restore_argv(archive, toml, dest, cfg), "--json"]) == 0
    payload = _json_line(capsys.readouterr().out)
    assert payload["config_files"] == 3
    for name in ("feed.py", "feed_alias.py"):
        assert (cfg / name).read_text(encoding="utf-8") == "# a router lives here\n", name
    # A copy, not an OS link: the restored names are independent files.
    assert (cfg / "feed_alias.py").stat().st_nlink == 1


def test_restore_config_bundle_restores_a_link_member_from_its_earlier_target(tmp_path) -> None:
    # The control at the extractor: a link member naming a regular config member already extracted
    # lands as its own file carrying that member's bytes.
    tar = _plain_tar(
        tmp_path / "linked.tar",
        [("config/a.toml", b"[a]\n"), _hard_link("config/sub/b.toml", "config/a.toml")],
    )
    cfg = tmp_path / "bundle"
    written: list[Path] = []
    assert dr_backup._restore_config_members(tar, cfg, written=written) == 2
    assert (cfg / "sub" / "b.toml").read_bytes() == b"[a]\n"
    assert (cfg / "sub" / "b.toml").resolve() in written  # in the rollback ledger like any file


@pytest.mark.parametrize(
    ("label", "linkname"),
    [
        ("the store", "store.db"),
        ("the manifest", "manifest.json"),
        ("a later member", "config/later.toml"),
        ("a name not in the archive", "config/absent.toml"),
        ("a normalized spelling of an extracted member", "config/./a.toml"),
    ],
)
def test_restore_refuses_a_link_member_that_names_no_extracted_config_file(
    tmp_path, label, linkname
) -> None:
    # The subject: on the unfixed code each of these was skipped without a word and the call
    # returned the count of the regular members. Now each refuses, naming the member.
    tar = _plain_tar(
        tmp_path / "forged.tar",
        [
            ("manifest.json", b"{}"),
            ("store.db", b"SQLite format 3\x00"),
            ("config/a.toml", b"[a]\n"),
            _hard_link("config/link.toml", linkname),
            ("config/later.toml", b"[later]\n"),
        ],
    )
    cfg = tmp_path / "bundle"
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_config_members(tar, cfg)
    assert excinfo.value.kind == "restore", label
    message = str(excinfo.value)
    assert "config/link.toml" in message and "hard link" in message, (label, message)
    assert not (cfg / "link.toml").exists(), label


def test_restore_refuses_a_link_member_with_an_unsafe_name(tmp_path) -> None:
    # The link member's OWN name passes the same gate as a regular member's.
    tar = _plain_tar(
        tmp_path / "forged.tar",
        [("config/a.toml", b"[a]\n"), _hard_link("config/../escape.toml", "config/a.toml")],
    )
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_config_members(tar, tmp_path / "bundle")
    assert "unsafe config member name" in str(excinfo.value)
    assert not (tmp_path / "escape.toml").exists()


def test_restore_refuses_a_link_member_aimed_at_the_restored_store(tmp_path) -> None:
    # The pre-extract collision check reads link members too, since one now lands as a file.
    tar = _plain_tar(
        tmp_path / "forged.tar",
        [("config/a.toml", b"[a]\n"), _hard_link("config/msg.db", "config/a.toml")],
    )
    d = tmp_path / "dr"
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "msg.db", d)
    assert excinfo.value.kind == "destination"
    # The control: the same archive with the link renamed off the store path passes the check.
    ok = _plain_tar(
        tmp_path / "ok.tar",
        [("config/a.toml", b"[a]\n"), _hard_link("config/b.toml", "config/a.toml")],
    )
    dr_backup._refuse_colliding_config_members(ok, d / "msg.db", d)


@pytest.mark.parametrize("first", ["store.db", "config/feed.py"])
def test_store_member_guard_refuses_only_a_store_led_tar(tmp_path, first) -> None:
    # The config-only route's early refusal (vault BACKLOG #5233), read through `tarfile` so a PAX
    # extended header ahead of the member cannot hide its name. The body runs past the guard's head,
    # so the check runs on the first write, as the decrypt makes it.
    body = b"x" * (2 * dr_backup._GUARD_HEAD_BYTES)
    tar = _plain_tar(tmp_path / "led.tar", [(first, body), ("manifest.json", b"{}")])
    out = io.BytesIO()
    guard = dr_backup._StoreMemberGuard(out)
    data = tar.read_bytes()
    if first == "store.db":
        with pytest.raises(dr_backup.BackupError) as excinfo:
            guard.write(data)
        assert excinfo.value.kind == "destination" and "needs --to" in str(excinfo.value)
        assert out.getvalue() == b"", "the store-led frame was written before the refusal"
    else:  # the control: a config-led tar passes through byte for byte
        guard.write(data)
        assert out.getvalue() == data


@pytest.mark.parametrize("first", ["store.db", "config/feed.py"])
def test_store_member_guard_holds_small_frames_until_it_has_checked(tmp_path, first) -> None:
    # An archive sealed with a small frame size reaches the guard in pieces. Nothing may land
    # before the check, and a stream shorter than the head is checked at `finish`.
    for size in (4096, 2 * dr_backup._GUARD_HEAD_BYTES):
        body = b"x" * size
        data = _plain_tar(tmp_path / f"{size}.tar", [(first, body)]).read_bytes()
        out = io.BytesIO()
        guard = dr_backup._StoreMemberGuard(out)
        try:
            for i in range(0, len(data), 4096):
                guard.write(data[i : i + 4096])
            guard.finish()
        except dr_backup.BackupError:
            assert first == "store.db", size
            assert out.getvalue() == b"", (size, "store bytes landed before the refusal")
        else:
            assert first != "store.db", (size, "a store-led tar was let through")
            assert out.getvalue() == data, size


@pytest.mark.parametrize("store", ["regular", "directory"])
@pytest.mark.parametrize("route", ["--to", "--config-to"])
def test_a_store_under_a_config_only_manifest_meets_one_refusal_on_both_routes(
    tmp_path, capsys, route, store
) -> None:
    # A manifest that says config-only over an archive that carries a store member (here after the
    # config, so the early guard passes it) is malformed. Each route used to send the operator to
    # the other: `--to` trusted the manifest and offered `--config-to`, and `--config-to` saw the
    # member and offered `--to` (vault BACKLOG #5233). Now both refuse it as malformed, naming
    # neither. A store member that is a directory is a store member to both routes as well.
    body: bytes | object = b"SQLite format 3\x00" if store == "regular" else _DIRECTORY_MEMBER
    tar = _plain_tar(
        tmp_path / "liar.tar",
        [
            ("config/feed.py", b"# a router\n"),
            ("store.db", body),
            ("manifest.json", b'{"config_only": true}'),
        ],
    )
    toml = _service_toml(tmp_path, key_b64=None)
    dest = tmp_path / "restored.db"
    cfg = tmp_path / "cfg"
    if route == "--to":
        argv = ["restore", str(tar), "--to", str(dest), "--service-config", toml]
    else:
        argv = _config_only_argv(str(tar), toml, cfg)
    assert main([*argv, "--allow-old-archive"]) == 1
    err = _refusal(capsys)
    assert "restore failed (restore)" in err and "malformed" in err, err
    assert dr_backup._CARRIES_A_STORE_REFUSAL not in err, err
    assert "--config-to <dir> and no --to" not in err, err
    assert not dest.exists() and not cfg.exists()
    _no_staging_left(tmp_path)


def test_a_store_led_config_only_archive_ends_in_the_malformed_refusal(tmp_path, capsys) -> None:
    # The early guard on the config-only route meets a store that leads the tar before it can
    # read the manifest, so it sends the operator to `--to`. Following that word for word must end
    # in the malformed refusal, not send them back.
    tar = _plain_tar(
        tmp_path / "led.tar",
        [
            ("store.db", b"SQLite format 3\x00"),
            ("config/feed.py", b"# a router\n"),
            ("manifest.json", b'{"config_only": true}'),
        ],
    )
    toml = _service_toml(tmp_path, key_b64=None)
    assert main([*_config_only_argv(str(tar), toml, tmp_path / "cfg"), "--allow-old-archive"]) == 1
    assert "needs --to" in _refusal(capsys)
    to = ["restore", str(tar), "--to", str(tmp_path / "x.db"), "--service-config", toml]
    assert main([*to, "--allow-old-archive"]) == 1
    err = _refusal(capsys)
    assert "malformed" in err and "--config-to <dir> and no --to" not in err, err


@pytest.mark.parametrize("store", ["directory", "regular"])
def test_a_directory_store_member_is_present_to_both_lookups(tmp_path, store) -> None:
    # `_tar_has_member` and `_extract_member` agree on a store member that is not a file: present,
    # and refused by the extractor rather than read as absent (vault BACKLOG #5233). The regular
    # member is the control.
    body = _DIRECTORY_MEMBER if store == "directory" else b"SQLite format 3\x00"
    tar = _plain_tar(tmp_path / "store.tar", [("store.db", body)])
    assert dr_backup._tar_has_member(tar, "store.db")
    if store == "directory":
        with pytest.raises(tarfile.TarError, match="not a regular file"):
            dr_backup._extract_member(tar, "store.db", tmp_path)
    else:
        out = dr_backup._extract_member(tar, "store.db", tmp_path)
        assert out is not None and out.read_bytes() == body


def test_a_link_store_member_is_refused_not_followed(tmp_path) -> None:
    # A store member that is a link to another member used to be followed by `extractfile`, so a
    # config file's bytes were extracted as the store. It is refused as not a regular file.
    tar = _plain_tar(
        tmp_path / "link.tar",
        [("config/feed.py", b"# a router\n"), _hard_link("store.db", "config/feed.py")],
    )
    with pytest.raises(tarfile.TarError, match="not a regular file"):
        dr_backup._extract_member(tar, "store.db", tmp_path)
    assert not (tmp_path / "extracted_store.db").exists()


def test_a_directory_store_member_is_refused_on_the_store_route(tmp_path, capsys) -> None:
    # With no config-only word, the store route refuses a store member that is not a file as such,
    # where it once called the archive store-less.
    tar = _plain_tar(
        tmp_path / "dir.tar", [("store.db", _DIRECTORY_MEMBER), ("manifest.json", b"{}")]
    )
    toml = _service_toml(tmp_path, key_b64=None)
    dest = tmp_path / "restored.db"
    argv = ["restore", str(tar), "--to", str(dest), "--service-config", toml]
    assert main([*argv, "--allow-old-archive"]) == 1
    err = _refusal(capsys)
    assert "not a regular file" in err and "no store.db member" not in err, err
    assert not dest.exists()


def test_restore_config_only_route_stages_beside_a_dot_config_to(
    tmp_path, capsys, monkeypatch
) -> None:
    # `--config-to .` is its own unresolved parent, so staging there would put the decrypted
    # archive inside the bundle's own directory. It stages in the resolved parent instead.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    here = tmp_path / "empty-here"
    here.mkdir()
    monkeypatch.chdir(here)
    staged_in: list[Path] = []
    real = dr_backup._open_staging

    def spy(root: Path, prefix: str, *, secure: bool):
        if prefix == "mefor-restore-":
            staged_in.append(Path(root).resolve())
        return real(root, prefix, secure=secure)

    monkeypatch.setattr(dr_backup, "_open_staging", spy)
    assert main([*_config_only_argv(str(tar), toml, Path(".")), "--allow-old-archive"]) == 0
    assert staged_in == [tmp_path.resolve()], staged_in
    assert sorted(p.name for p in here.iterdir()) == ["feed.py"]


def test_restore_refuses_a_dangling_link_member_before_the_store_is_extracted(tmp_path) -> None:
    # The pre-extract scan refuses the link the extractor would refuse, so a whole-store restore
    # does not extract, verify and place the store only to roll it back.
    tar = _plain_tar(
        tmp_path / "dangling.tar",
        [("config/a.toml", b"[a]\n"), _hard_link("config/b.toml", "config/absent.toml")],
    )
    d = tmp_path / "dr"
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "msg.db", tmp_path / "cfg")
    assert excinfo.value.kind == "restore" and "config/b.toml" in str(excinfo.value)
    # The whole restore is refused, and the refusal names the way to the store alone.
    assert "The store alone restores: run the same command without --config-to" in str(
        excinfo.value
    ), str(excinfo.value)
    # The control: a link to the member before it passes the scan.
    ok = _plain_tar(
        tmp_path / "ok.tar",
        [("config/a.toml", b"[a]\n"), _hard_link("config/b.toml", "config/a.toml")],
    )
    dr_backup._refuse_colliding_config_members(ok, d / "msg.db", tmp_path / "cfg")


# --- A config member that reaches a store path by a Win32 spelling ----------------------------------


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ("D:\\dr\\store.db-wal", ("d", "dr", "store.db-wal")),
        ("D:/DR/STORE.DB-WAL", ("d", "dr", "store.db-wal")),
        ("D:\\dr\\store.db-wal.", ("d", "dr", "store.db-wal")),
        ("D:\\dr\\store.db-wal ", ("d", "dr", "store.db-wal")),
        ("D:\\dr\\store.db-wal . .", ("d", "dr", "store.db-wal")),
        ("D:\\dr\\store.db-wal::$DATA", ("d", "dr", "store.db-wal")),
        ("D:\\dr\\store.db-wal:x", ("d", "dr", "store.db-wal")),
        ("D:\\dr\\store.db-wal./x.toml", ("d", "dr", "store.db-wal", "x.toml")),
        ("D:\\dr\\sub\\..\\store.db-wal.", ("d", "dr", "store.db-wal")),
        # Measured: a dots-only or spaces-only component stays a component of its own on Windows,
        # so it must not vanish from the key and fuse its neighbours.
        ("D:\\dr\\...\\store.db-wal", ("d", "dr", "...", "store.db-wal")),
        ("D:\\dr\\ \\store.db-wal", ("d", "dr", " ", "store.db-wal")),
        # Controls: names that are not the protected one keep their own key.
        ("D:\\dr\\store.db-walnut.toml", ("d", "dr", "store.db-walnut.toml")),
        ("D:\\dr\\aux.py", ("d", "dr", "aux.py")),
    ],
)
def test_win32_path_key_is_pure_and_matches_win32_naming(path, key) -> None:
    # Runs on every platform: the normalizer reads no filesystem and no host state.
    assert dr_backup._win32_path_key(path) == key


def test_win32_path_key_does_not_pick_final_sigma_by_context() -> None:
    # `str.lower` on the whole name would give U+03C2 here, a key U+03C3 could not match.
    assert dr_backup._win32_path_key("data\u03a3-wal") == dr_backup._win32_path_key(
        "data\u03c3-wal"
    )


_WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Win32 path aliasing")


@_WINDOWS_ONLY
@pytest.mark.parametrize(
    "name",
    [
        "store.db-wal.",
        "store.db-wal ",
        "store.db-shm.",
        "STORE.DB-WAL",
        "store.db-wal::$DATA",
        "store.db-wal/x.toml",
        "store.db-wal./x.toml",
        "store.db",
        "store.db.",
        "store.db/x.toml",
    ],
)
def test_restore_refuses_a_config_member_aliasing_a_store_path(tmp_path, name) -> None:
    tar = _plain_tar(tmp_path / "forged.tar", [(f"config/{name}", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "store.db", d)
    assert excinfo.value.kind == "destination"
    assert list(d.iterdir()) == []


@_WINDOWS_ONLY
@pytest.mark.parametrize(
    "name",
    ["feed.py", "aux.py", "handler.py.", "store.db-walnut.toml", "sub/store.db-wal", "a.db-wal."],
)
def test_restore_passes_a_config_member_that_only_resembles_a_store_path(tmp_path, name) -> None:
    # The control: a name that does not resolve to a protected path is not refused by this check.
    tar = _plain_tar(tmp_path / "ok.tar", [(f"config/{name}", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    dr_backup._refuse_colliding_config_members(tar, d / "store.db", d)


@_WINDOWS_ONLY
def test_restore_refuses_an_alias_of_a_store_nested_below_config_to(tmp_path) -> None:
    tar = _plain_tar(tmp_path / "forged.tar", [("config/sub/store.db-wal.", b"x")])
    d = tmp_path / "dr"
    (d / "sub").mkdir(parents=True)
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "sub" / "store.db", d)
    assert excinfo.value.kind == "destination"


@_WINDOWS_ONLY
def test_restore_refuses_an_alias_through_a_short_name_parent(tmp_path) -> None:
    d = tmp_path / "dr"
    parent = d / "restored-store-longname"
    parent.mkdir(parents=True)
    buf = ctypes.create_unicode_buffer(600)
    size = ctypes.windll.kernel32.GetShortPathNameW(str(parent), buf, 600)  # type: ignore[attr-defined]
    short = Path(buf.value).name
    if not size or short == parent.name:
        pytest.skip("this volume has no 8.3 name for the directory")
    tar = _plain_tar(tmp_path / "forged.tar", [(f"config/{short}/store.db-wal.", b"x")])
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, parent / "store.db", d)
    assert excinfo.value.kind == "destination"


@_WINDOWS_ONLY
def test_restore_protects_the_sidecar_of_a_to_path_with_a_trailing_dot(tmp_path) -> None:
    tar = _plain_tar(tmp_path / "forged.tar", [("config/store.db-wal", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "store.db.", d)
    assert excinfo.value.kind == "destination"


@_WINDOWS_ONLY
def test_alias_refusal_does_not_echo_the_member_name(tmp_path) -> None:
    tar = _plain_tar(tmp_path / "forged.tar", [("config/store.db-wal:\x1b[2Jforged\nERROR", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "store.db", d)
    message = str(excinfo.value)
    assert excinfo.value.kind == "destination"
    assert "\x1b" not in message and "forged" not in message and "\n" not in message


@pytest.mark.parametrize(
    ("planted", "refused"),
    [("msg.db-journal", True), ("msg.db-journalnotes.toml", False)],
)
def test_restore_refuses_a_planted_rollback_journal_end_to_end(
    tmp_path, key_b64, capsys, planted, refused
) -> None:
    # On every platform: SQLite replays a hot `<store>-journal` on first open, after the restore's
    # integrity_check and row-count compare. The near-miss name is the control.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, plant={planted: b"journal-bytes"})
    capsys.readouterr()
    d = tmp_path / "dr"
    dest = d / "msg.db"
    assert main(_restore_argv(archive, toml, dest, d)) == (1 if refused else 0)
    if refused:
        assert "restore failed (destination)" in _refusal(capsys)
        assert not dest.exists() and not (d / planted).exists()
    else:
        assert dest.is_file() and (d / planted).read_bytes() == b"journal-bytes"


def test_restore_refuses_a_destination_holding_a_stale_journal(tmp_path) -> None:
    d = tmp_path / "dr"
    d.mkdir()
    (d / "msg.db-journal").write_bytes(b"stale")
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_existing_destination(d / "msg.db", None)
    assert excinfo.value.kind == "destination"


def test_alias_check_leaves_posix_names_alone(tmp_path, monkeypatch) -> None:
    # The `sys.platform` branch, forced off: a Win32 spelling is an ordinary, distinct POSIX name.
    monkeypatch.setattr(sys, "platform", "linux")
    names = ["store.db-wal.", "store.db-wal ", "store.db-wal/x.toml", "RESTOR~1.DB:x"]
    tar = _plain_tar(tmp_path / "posix.tar", [(f"config/{n}", b"x") for n in names])
    d = tmp_path / "dr"
    d.mkdir()
    dr_backup._refuse_colliding_config_members(tar, d / "store.db", d)


@_WINDOWS_ONLY
@pytest.mark.parametrize("name", ["store.db-wal /x.toml", "store.db-wal.:x"])
def test_alias_key_deliberately_over_refuses_a_forged_looking_name(tmp_path, name) -> None:
    # Each names a path other than the sidecar on NTFS. Refused on purpose: see `_win32_path_key`.
    tar = _plain_tar(tmp_path / "forged.tar", [(f"config/{name}", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "store.db", d)
    assert excinfo.value.kind == "destination"


@_WINDOWS_ONLY
@pytest.mark.parametrize("name", ["RESTOR~1.DB:x", "RESTOR~1.DB::$DATA", "RESTOR~2.DB:x/y.toml"])
def test_restore_refuses_a_stream_on_the_stores_future_short_name(tmp_path, name) -> None:
    # The short name does not exist until the store is placed, so it cannot be resolved here.
    tar = _plain_tar(tmp_path / "forged.tar", [(f"config/{name}", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._refuse_colliding_config_members(tar, d / "restored-store.db", d)
    assert excinfo.value.kind == "destination"


@_WINDOWS_ONLY
@pytest.mark.parametrize("name", ["notes~1.toml", "sub/RESTOR~1.DB:x"])
def test_short_name_stream_refusal_stays_in_the_stores_directory(tmp_path, name) -> None:
    # The controls: a tilde with no stream, and a tilde stream in another directory.
    tar = _plain_tar(tmp_path / "ok.tar", [(f"config/{name}", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    dr_backup._refuse_colliding_config_members(tar, d / "restored-store.db", d)


@_WINDOWS_ONLY
def test_alias_check_exempts_the_operators_own_config_to_path(tmp_path) -> None:
    # The exemption's control: this member adds nothing protected, and `--config-to` at a sidecar
    # path is the operator's spelling, which this archive-name check leaves as `main` has it.
    tar = _plain_tar(tmp_path / "ok.tar", [("config/a.toml", b"x")])
    d = tmp_path / "dr"
    d.mkdir()
    dr_backup._refuse_colliding_config_members(tar, d / "store.db", d / "store.db-wal")


# --- (5b-ter) vault BACKLOG #5233 item 3: the no-config refusal is not a closed list --------------


def test_no_config_refusal_names_a_walk_that_added_nothing(tmp_path) -> None:
    # The shape a whole-store backup of an EMPTY config dir writes, a store and no config member
    # (`test_restore_config_to_refuses_when_archive_has_no_config` drives it end to end). Neither
    # cause the refusal named is true of that backup (include_config is on, and a config dir was
    # loaded), so it must say "at least" and name the walk that added no regular file.
    tar = _plain_tar(
        tmp_path / "no-config.tar",
        [("manifest.json", b"{}"), ("store.db", b"SQLite format 3\x00")],
    )
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_config_members(tar, tmp_path / "cfg")
    err = str(excinfo.value)
    assert "At least" in err, err
    assert "added no regular file" in err and "holds only symbolic links" in err, err
    # The control: the two causes it named before are still named.
    assert "[backup].include_config=false" in err and "no config dir loaded" in err, err


# --- (5b-quater) vault BACKLOG #5233, the round-3 review's repairs ---------------------------------


@pytest.mark.parametrize("name", ["writelines", "tell", "flush", "seek"])
def test_store_member_guard_offers_nothing_but_write(name) -> None:
    # The raw file would answer any of these without the held bytes: `writelines` would land bytes
    # past the check, and `tell` would report a position short of what was written. So the guard
    # does not forward them.
    out = io.BytesIO()
    # `Any`: the methods the guard does not declare are the subject.
    guard: Any = dr_backup._StoreMemberGuard(out)
    guard.write(b"x" * 512)
    with pytest.raises(AttributeError):
        getattr(guard, name)
    assert out.getvalue() == b"", "a held byte reached the file"
    # The control: `finish` releases the head, which then lands whole.
    guard.finish()
    assert out.getvalue() == b"x" * 512


def test_first_member_name_logs_a_head_that_does_not_parse(caplog) -> None:
    # A head that does not parse is left to the checks after the decrypt, and says so in the log,
    # by exception type only: the head is decrypted archive content.
    head = b"\xff" * 1024
    with caplog.at_level("DEBUG", logger=dr_backup.__name__):
        assert dr_backup._first_member_name(head) is None
    records = [r for r in caplog.records if "first member" in r.getMessage()]
    assert len(records) == 1, [r.getMessage() for r in caplog.records]
    assert "\\xff" not in records[0].getMessage() and "\xff" not in records[0].getMessage()


@pytest.mark.parametrize("case", ["carries a store", "undated"])
def test_config_only_refusal_leaves_no_new_ancestor_of_config_to(tmp_path, capsys, case) -> None:
    # The staging directory is made beside --config-to, so a missing ancestor of it is created
    # first. A refusal after that ("Nothing was written", for the age refusal) must not leave
    # that ancestor behind.
    if case == "undated":
        tar = _undated_config_only_tar(tmp_path)
        expect = "restore failed (age_undated)"
    else:
        tar = _plain_tar(
            tmp_path / "store.tar",
            [("store.db", b"SQLite format 3\x00"), ("manifest.json", b"{}")],
        )
        expect = "carries a store"
    toml = _service_toml(tmp_path, key_b64=None)
    new = tmp_path / "new"
    cfg = new / "deeper" / "cfg"
    assert main(_config_only_argv(str(tar), toml, cfg)) == 1
    err = _refusal(capsys)
    assert expect in err, err
    assert not new.exists(), sorted(str(p.relative_to(tmp_path)) for p in new.rglob("*"))
    # The control: the same command restores once it may, and keeps the directories it made.
    if case == "undated":
        assert main([*_config_only_argv(str(tar), toml, cfg), "--allow-old-archive"]) == 0
        assert (cfg / "feed.py").is_file()


def test_store_route_refusal_leaves_no_new_ancestor_of_to(tmp_path, capsys) -> None:
    # The same rule on the store route, where the staging directory goes beside --to: a config-only
    # archive is refused there after its decrypt, and the new ancestor of --to goes with it.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    new = tmp_path / "new"
    dest = new / "deeper" / "restored.db"
    argv = ["restore", str(tar), "--to", str(dest), "--service-config", toml, "--allow-old-archive"]
    assert main(argv) == 1
    assert "CONFIG-ONLY" in _refusal(capsys)
    assert not new.exists()


def test_config_only_age_refusal_speaks_of_the_config_bundle(tmp_path, capsys) -> None:
    # The config-only route places no store, so its age refusal names no audit row and no account
    # change to undo; what an old bundle brings back is old config.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    assert main(_config_only_argv(str(tar), toml, tmp_path / "cfg")) == 1
    err = _refusal(capsys)
    assert "restore failed (age_undated)" in err, err
    assert "Nothing was written" in err and "config bundle brings back" in err, err
    assert "audit row" not in err and "A restore undoes" not in err, err


def _failing_extract():
    """An extractor that writes one file into the ledger, then fails the way a revoked ACL would."""

    def boom(tar_path: Path, config_dest: Path, *, written: list[Path] | None = None) -> int:
        config_dest.mkdir(parents=True, exist_ok=True)
        partial = config_dest / "partial.py"
        partial.write_bytes(b"# half a bundle\n")
        if written is not None:
            written.append(partial)
        raise PermissionError(13, "Access is denied", str(config_dest / "sub"))

    return boom


@pytest.mark.parametrize("prepared", [False, True])
def test_config_only_route_refuses_a_failure_the_extractor_does_not_word(
    tmp_path, key_b64, capsys, prepared
) -> None:
    # A PermissionError from inside the bundle's extraction escaped as a traceback. It is now a
    # refusal line, and the partial bundle is rolled back.
    archive, toml = _make_archive(tmp_path, key_b64, capsys, config_only=True)
    cfg = tmp_path / "bundle"
    if prepared:
        cfg.mkdir()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_extract_config_members", _failing_extract())
        assert main(_config_only_argv(archive, toml, cfg)) == 1
    err = _refusal(capsys)
    assert "restore failed (restore)" in err and "could not restore the config bundle" in err, err
    assert "Traceback" not in err, err
    assert not (cfg / "partial.py").exists(), "the partial bundle was not rolled back"
    # A --config-to the operator prepared stays, empty; one the restore made goes.
    assert cfg.exists() is prepared
    _no_staging_left(tmp_path)


def test_store_route_refuses_a_failure_the_extractor_does_not_word(
    tmp_path, key_b64, capsys
) -> None:
    # The store route had the same gap, and the same wrapper closes it: a refusal line, with the
    # placed store and the partial bundle rolled back.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored.db"
    cfg = tmp_path / "bundle"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_extract_config_members", _failing_extract())
        assert main(_restore_argv(archive, toml, dest, cfg)) == 1
    err = _refusal(capsys)
    assert "restore failed (restore)" in err and "could not restore the config bundle" in err, err
    assert not dest.exists(), "the placed store was not rolled back"
    assert not (cfg / "partial.py").exists()


def test_restore_config_members_refuses_a_member_that_ends_early(tmp_path) -> None:
    # A tarfile.TarError from a truncated member is a refusal, not a traceback.
    tar = _plain_tar(tmp_path / "whole.tar", [("config/a.toml", b"[a]\n" * 4096)])
    data = tar.read_bytes()
    cut = tmp_path / "cut.tar"
    cut.write_bytes(data[: 512 + 1024])  # the header and the first two blocks of the body
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_config_members(cut, tmp_path / "cfg")
    assert excinfo.value.kind == "restore", excinfo.value
    assert "could not restore the config bundle" in str(excinfo.value)
    # The control: the whole tar restores.
    assert dr_backup._restore_config_members(tar, tmp_path / "cfg-whole") == 1


@pytest.mark.skipif(os.name != "nt", reason="only Windows refuses to delete an open file")
def test_a_refusal_survives_a_real_held_open_staging_file(tmp_path, capsys, monkeypatch) -> None:
    # The real shape, not a stand-in: a handle on the staged archive makes the teardown's rmtree
    # fail. The refusal stands, and the archive the handle holds is emptied in place (BACKLOG #5617):
    # Python's own `open` shares write access, so the truncate succeeds where the unlink cannot.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    handles: list = []
    real_read = dr_backup._read_manifest_from_tar

    def hold(tar_path: Path) -> dict[str, object]:
        handles.append(open(tar_path, "rb"))  # noqa: SIM115 -- held on purpose, closed below
        return real_read(tar_path)

    monkeypatch.setattr(dr_backup, "_read_manifest_from_tar", hold)
    monkeypatch.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
    try:
        assert main(_config_only_argv(str(tar), toml, tmp_path / "cfg")) == 1
    finally:
        for fh in handles:
            fh.close()
    err = _refusal(capsys)
    assert "restore failed (age_undated)" in err and "Traceback" not in err, err
    (leftover,) = tmp_path.glob("mefor-restore-*")
    assert (leftover / "archive.tar").stat().st_size == 0
    shutil.rmtree(leftover)


def test_a_restore_staging_leftover_has_its_archive_emptied_and_is_swept(
    tmp_path, key_b64, capsys
) -> None:
    # BACKLOG #5617. The restore staged the decrypted archive and the extracted store in a
    # `TemporaryDirectory`, outside the lock-and-sweep the backup and verify stage under. When its
    # teardown failed, the whole decrypted archive stayed on the destination volume at full size,
    # and no later run would ever remove it. It now stages like a verify: a failed teardown empties
    # what it can, keeps the directory marked, and the next run's sweep removes it.
    #
    # The staged store's name is removed as soon as the store is placed, so the teardown is never
    # handed a second name for the restored store: on a volume that hard-links and reports one
    # link, its fail-safe would otherwise truncate the restore itself. With the archive emptied,
    # nothing in the leftover holds plaintext, and the restore succeeds.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 0
    capsys.readouterr()
    leftovers = [p for p in dest.parent.iterdir() if p.name.startswith("mefor-restore-")]
    assert len(leftovers) == 1, sorted(p.name for p in dest.parent.iterdir())
    assert not (leftovers[0] / "extracted_store.db").exists()
    assert (leftovers[0] / "archive.tar").stat().st_size == 0
    # The restore is whole: the store opens and carries its row.
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)
    # Re-marked for the sweep after the refused removal took its marks, and swept by the next
    # restore that stages beside it, here through a relative --to.
    assert (leftovers[0] / ".lock").exists() and (leftovers[0] / ".lock-held").exists()
    with pytest.MonkeyPatch.context() as mp:
        mp.chdir(tmp_path)
        argv = ["restore", archive, "--to", "restored/again.db", "--service-config", toml]
        assert main(argv) == 0
    capsys.readouterr()
    _no_staging_left(dest.parent)
    # The sweep removed a name, never the placed store's bytes.
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)


def test_a_refused_restore_whose_staging_survives_keeps_its_refusal(tmp_path, capsys) -> None:
    # The refusal in flight is the one reported, and the leftover holds no plaintext: every file in
    # it was emptied, so there is nothing for the refusal to add.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        assert main(_config_only_argv(str(tar), toml, tmp_path / "cfg")) == 1
    err = _refusal(capsys)
    assert "restore failed (age_undated)" in err and "Nothing was written" in err, err
    assert "Separately" not in err and "Traceback" not in err, err
    (leftover,) = tmp_path.glob("mefor-restore-*")
    assert (leftover / "archive.tar").stat().st_size == 0
    assert not (tmp_path / "cfg").exists()
    # The next run sweeps it.
    assert main([*_config_only_argv(str(tar), toml, tmp_path / "cfg"), "--allow-old-archive"]) == 0
    _no_staging_left(tmp_path)


def test_a_refusal_names_a_staging_leftover_that_still_holds_plaintext(tmp_path, capsys) -> None:
    # Where a staged file could be neither removed nor emptied, the refusal stands and names the
    # directory after it, rather than being replaced by the teardown's error.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        mp.setattr(dr_backup, "_empty_files_in_place", lambda staging: ["archive.tar"])
        assert main(_config_only_argv(str(tar), toml, tmp_path / "cfg")) == 1
    err = _refusal(capsys)
    assert err.startswith("error: restore failed (age_undated): Nothing was written"), err
    assert "Separately, the plaintext staging directory" in err and "archive.tar" in err, err
    # The leftover sentence ends before the CLI's own age remedy starts.
    assert "open. Choose a newer archive" in err, err
    (leftover,) = tmp_path.glob("mefor-restore-*")
    assert leftover.name in err and "Traceback" not in err, err
    shutil.rmtree(leftover)


def test_a_refusal_behind_an_os_error_on_its_way_out_is_the_one_reported(
    tmp_path, capsys, monkeypatch
) -> None:
    # A refusal raised inside the decrypt's `with` block can meet an OSError as it leaves it, such
    # as the archive's close-time flush on a full volume. The refusal is the one reported.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    monkeypatch.setattr(dr_backup, "_MAX_RESTORE_PLAINTEXT_BYTES", 1)
    real_open = open

    class FlushFails(io.FileIO):
        def close(self) -> None:
            super().close()
            raise OSError(28, "No space left on device")

    def opener(path, mode="r", *args, **kwargs):
        if mode == "wb" and Path(path).name == "archive.tar":
            return FlushFails(path, "wb")
        return real_open(path, mode, *args, **kwargs)

    # Shadowed in the module alone, so nothing else's `open` changes.
    monkeypatch.setattr(dr_backup, "open", opener, raising=False)
    assert main([*_config_only_argv(str(tar), toml, tmp_path / "cfg"), "--allow-old-archive"]) == 1
    err = _refusal(capsys)
    assert "restore failed (verify)" in err and "staging cap" in err, err
    assert "No space left" not in err, err
    _no_staging_left(tmp_path)


def test_a_failed_restore_empties_the_staged_store_its_rollback_unlinked(
    tmp_path, key_b64, capsys
) -> None:
    # A restore that fails after placing its store leaves no copy of it in its staging leftover:
    # the staged name went at placement, and the placed store goes in the rollback.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    err = _refusal(capsys)
    assert "member-count cap" in err and "Separately" not in err, err
    assert not dest.exists()
    (leftover,) = dest.parent.glob("mefor-restore-*")
    assert not (leftover / "extracted_store.db").exists()
    assert (leftover / "archive.tar").stat().st_size == 0
    shutil.rmtree(leftover)


def test_a_whole_restore_whose_staged_name_survives_is_never_truncated(
    tmp_path, key_b64, capsys
) -> None:
    # Where the staged store's name cannot be removed after a link placement, it is still the
    # restored store's own file. A volume that hard-links but reports one link would let the
    # teardown's fail-safe truncate it, emptying the restore it just reported whole. The seam
    # stands in for that volume: a truncate that ignores the link count.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        _hold(mp, _is_staged_store)
        mp.setattr(dr_backup, "_truncate_unfollowed", _truncate_ignoring_links)
        rc = main(["restore", archive, "--to", str(dest), "--service-config", toml])
    err = _refusal(capsys)
    assert rc == 1 and "restore failed (cleanup)" in err, err
    assert "extracted_store.db (the restored store, not truncated)" in err, err
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)
    (leftover,) = dest.parent.glob("mefor-restore-*")
    assert (leftover / "archive.tar").stat().st_size == 0
    shutil.rmtree(leftover)


def _hold(mp: pytest.MonkeyPatch, held: Callable[[Path], bool]) -> None:
    """Refuse ``Path.unlink`` on every path ``held`` names, as a scanner holding the file open does
    on Windows; every other unlink is real."""
    real_unlink = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if held(self):
            raise PermissionError(13, "held open by a scanner", str(self))
        real_unlink(self, missing_ok=missing_ok)

    mp.setattr(Path, "unlink", unlink)


def _is_staged_store(path: Path) -> bool:
    return path.name == "extracted_store.db" and path.parent.name.startswith("mefor-restore-")


def _truncate_ignoring_links(entry: Path, dir_fd: object, here: object) -> None:
    """The fail-safe's truncate on a volume that hard-links but reports one link."""
    os.truncate(entry, 0)


@pytest.mark.parametrize("still_held", [True, False], ids=["still-held", "released"])
def test_a_later_sweep_never_touches_a_staged_store_an_earlier_restore_spared(
    tmp_path, key_b64, capsys, still_held
) -> None:
    # BACKLOG #5617, review finding A. A restore whose staged store's name could not be removed
    # after a link placement spares it at its own teardown, since it is still the restored store's
    # own file. That decision used to live in memory for that run alone, so the next run's sweep of
    # the re-marked leftover handed the name to the fail-safe: on a volume that reports one link
    # it truncated the restored store through it ("still-held"), or it removed the name its own
    # run had refused to ("released"). The decision is now a marker beside the file, and every
    # later teardown reads it. With the marker both ids take the one path, which never reaches
    # `_remove_tree`; each id pins the way the in-memory design failed.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        _hold(mp, _is_staged_store)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 1
    assert "restore failed (cleanup)" in _refusal(capsys)
    (leftover,) = dest.parent.glob("mefor-restore-*")
    staged = leftover / "extracted_store.db"
    size = staged.stat().st_size
    assert size > 0
    assert (leftover / ".lock-held").exists(), "the leftover was not marked for the next sweep"

    # A separate run, whose sweep of this root finds the leftover abandoned.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_truncate_unfollowed", _truncate_ignoring_links)
        mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
        if still_held:
            real_remove = dr_backup._remove_tree
            mp.setattr(
                dr_backup, "_remove_tree", lambda p: False if p == leftover else real_remove(p)
            )
        again = dest.parent / "again.db"
        assert main(["restore", archive, "--to", str(again), "--service-config", toml]) == 0
    capsys.readouterr()
    assert staged.stat().st_size == size, "a later sweep touched the spared staged store"
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)
    # Once the operator deletes the spared file, its marker spares nothing, and the next sweep
    # removes the rest of the directory.
    staged.unlink()
    owner = dr_backup._owner_of(leftover)
    assert dr_backup._sweep_abandoned_staging(dest.parent, owner=owner, own=dest) == 1
    _no_staging_left(dest.parent)
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)


class _ErrorRecords(logging.Handler):
    """The ERROR records one logger emits, read off a handler on that logger itself: the CLI's own
    logging setup replaces the root's handlers, and with them the one ``caplog`` reads."""

    def __init__(self) -> None:
        super().__init__(logging.ERROR)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())

    @contextlib.contextmanager
    def on(self, logger: logging.Logger) -> Iterator[None]:
        logger.addHandler(self)
        try:
            yield
        finally:
            logger.removeHandler(self)


def test_a_failed_rollback_leaves_its_spared_staged_store_reported_and_unswept(
    tmp_path, key_b64, capsys
) -> None:
    # BACKLOG #5617, review finding B. A restore fails after placing its store, its staged store's
    # name cannot be removed, and neither can the placed store, so the rollback fails. The staged
    # name is then a second name for a store the operator must delete by hand, and once that is
    # done it is the only decrypted copy, at one link. That state is logged at ERROR and recorded
    # in its marker, the restore reports failure, and no later sweep removes or empties it.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    errors = _ErrorRecords()
    with pytest.MonkeyPatch.context() as mp, errors.on(dr_backup.log):
        _restore_staging_that_cannot_be_removed(mp)
        _hold(
            mp, lambda p: _is_staged_store(p) or (p.name, p.parent.name) == ("msg.db", "restored")
        )
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        rc = main(_restore_argv(archive, toml, dest, tmp_path / "bundle"))
    err = _refusal(capsys)
    assert rc == 1 and "member-count cap" in err, err
    assert "extracted_store.db (a second name for the placed store" in err, err
    assert dest.is_file(), "the rollback was meant to fail here"
    (leftover,) = dest.parent.glob("mefor-restore-*")
    staged = leftover / "extracted_store.db"
    marker = leftover / "extracted_store.db.mefor-spared"
    assert marker.read_bytes() == b"rollback-failed"
    assert any("rollback could not remove" in m and str(staged) in m for m in errors.messages), (
        errors.messages
    )

    # The operator deletes the placed store; the staged copy is now the only one, at one link, so
    # even a fail-safe that reads the link count would empty it. The next sweep reports it instead.
    dest.unlink()
    size = staged.stat().st_size
    errors = _ErrorRecords()
    with errors.on(dr_backup.log):
        dr_backup._sweep_abandoned_staging(
            dest.parent, owner=dr_backup._owner_of(leftover), own=tmp_path / "not-this-one"
        )
    assert staged.stat().st_size == size and marker.exists()
    found = [m for m in errors.messages if "a second name for the placed store" in m]
    assert any(leftover.name in m for m in found), errors.messages
    shutil.rmtree(leftover)


def test_a_rollback_that_removes_the_store_only_after_the_teardown_reports_the_lone_copy(
    tmp_path, key_b64, capsys
) -> None:
    # The placed store refuses only the failed restore's first unlink, so the teardown spares the
    # staged name as a name for it, and the rollback's second attempt then removes the store. The
    # staged name is now the only decrypted copy: its marker says so, it is logged at ERROR, and it
    # is never emptied, rather than left labelled as a second name for a store that is gone.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    store_refusals: list[Path] = []

    def held(path: Path) -> bool:
        if (path.name, path.parent.name) == ("msg.db", "restored") and not store_refusals:
            store_refusals.append(path)
            return True
        return _is_staged_store(path)

    errors = _ErrorRecords()
    with pytest.MonkeyPatch.context() as mp, errors.on(dr_backup.log):
        _restore_staging_that_cannot_be_removed(mp)
        _hold(mp, held)
        mp.setattr(dr_backup, "_truncate_unfollowed", _truncate_ignoring_links)
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        rc = main(_restore_argv(archive, toml, dest, tmp_path / "bundle"))
    assert rc == 1 and "member-count cap" in _refusal(capsys)
    assert len(store_refusals) == 1 and not dest.exists()
    (leftover,) = dest.parent.glob("mefor-restore-*")
    staged = leftover / "extracted_store.db"
    assert staged.stat().st_size > 0
    assert (leftover / "extracted_store.db.mefor-spared").read_bytes() == b"rolled-back"
    assert any("only decrypted copy" in m and str(staged) in m for m in errors.messages), (
        errors.messages
    )
    shutil.rmtree(leftover)


def test_a_spare_marker_that_cannot_be_written_refuses_the_placement(
    tmp_path, key_b64, capsys
) -> None:
    # The marker is written just before the placement's link. Where it cannot be, the restore
    # refuses while nothing is placed, rather than place a second name for the restored store
    # that a crash could leave unmarked, or withhold a directory that a crash would then leave
    # holding the whole decrypted archive where no sweep could ever prove it abandoned.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_write_spare_marker", lambda item, reason: False)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 1
    err = _refusal(capsys)
    assert "restore failed (destination)" in err and "nothing was placed" in err, err
    # The restore removes the directory it made for --to only once it is empty, so its absence
    # shows no store was placed and the staging directory went too.
    assert not dest.parent.exists()


def test_a_relabel_that_cannot_be_recorded_keeps_its_directory_from_every_sweep(
    tmp_path, key_b64, capsys
) -> None:
    # Where a spare's relabel to `rollback-failed` cannot be written, the marker still reads
    # `restored-store`, so the directory loses the mark a sweep needs before the run lets go of
    # its lock, and no later sweep touches the staged name, even on a volume that reports one
    # link. The teardown used to ask only whether a marker existed, and re-marked the directory.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    real_release = dr_backup._Staging.release
    marked_at_release: list[bool] = []

    def release(self, **kwargs):
        # Read while the run still holds the lock: a sweep could act the moment it lets go.
        marked_at_release.append((self.path / ".lock-held").exists())
        return real_release(self, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        _hold(
            mp, lambda p: _is_staged_store(p) or (p.name, p.parent.name) == ("msg.db", "restored")
        )
        _refuse_marker_reason(mp, "rollback-failed")
        mp.setattr(dr_backup._Staging, "release", release)
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    err = _refusal(capsys)
    # The refusal names the file and asks for its deletion by hand, and predicts no sweep.
    (refusal,) = [line for line in err.splitlines() if line.startswith("error:")]
    _assert_neutral_spare_refusal(refusal)
    assert marked_at_release and not any(marked_at_release), marked_at_release
    (leftover,) = dest.parent.glob("mefor-restore-*")
    staged = leftover / "extracted_store.db"
    size = staged.stat().st_size
    assert (leftover / "extracted_store.db.mefor-spared").read_bytes() == b"restored-store"
    assert not (leftover / ".lock-held").exists(), "the teardown undid the withholding"
    # The lock file stays, so a config walk still prunes the directory as staging.
    assert dr_backup._is_staging_dir(leftover)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_truncate_unfollowed", _truncate_ignoring_links)
        owner = dr_backup._owner_of(leftover)
        assert dr_backup._sweep_abandoned_staging(dest.parent, owner=owner, own=dest) == 0
        # The sweep skips it before its teardown runs, so the marker is shown to spare the file
        # by a teardown run on it directly.
        dr_backup._teardown_staging(leftover)
    assert staged.stat().st_size == size
    shutil.rmtree(leftover)


def _hold_markers(mp: pytest.MonkeyPatch) -> None:
    """Refuse ``os.unlink`` on every spare marker, as a scanner holding it open does on Windows;
    the marker can still be written in place, as such a holder shares write access."""
    real_unlink = os.unlink

    def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if os.fspath(path).endswith(dr_backup._SPARE_SUFFIX):
            raise PermissionError(13, "held open by a scanner", os.fspath(path))
        real_unlink(path, *args, **kwargs)

    mp.setattr(os, "unlink", unlink)


def test_a_rolled_back_staged_copy_is_emptied_even_when_its_marker_will_not_clear(
    tmp_path, key_b64, capsys
) -> None:
    # The failed restore removes its placed store, so the staged copy is the only one left and is
    # no longer spared. A marker that will not clear must not keep it full: the restore records
    # the unspare in the marker itself, and the teardown empties the copy. The decision used to
    # live in memory alone, and the teardown then emptied the marker too, so every later sweep
    # read it as a spare for a reason it could not read and kept the directory for good.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    with pytest.MonkeyPatch.context() as mp:
        _restore_staging_that_cannot_be_removed(mp)
        _hold(mp, _is_staged_store)
        _hold_markers(mp)
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    err = _refusal(capsys)
    assert "member-count cap" in err and "not truncated" not in err, err
    assert not dest.exists()
    (leftover,) = dest.parent.glob("mefor-restore-*")
    assert (leftover / "extracted_store.db.mefor-spared").read_bytes() == b"released"
    assert (leftover / "extracted_store.db").stat().st_size == 0
    # A later sweep, once nothing holds anything, reads the marker as sparing nothing.
    owner = dr_backup._owner_of(leftover)
    assert dr_backup._sweep_abandoned_staging(dest.parent, owner=owner, own=tmp_path / "x") == 1
    _no_staging_left(dest.parent)


def test_a_staged_store_is_marked_before_its_second_name_exists(tmp_path, key_b64, capsys) -> None:
    # A crash between the placement's link and the marker's write used to leave the staged store a
    # second name for the restored store with no marker, which a later sweep hands to the
    # fail-safe. The marker now lands first, so no crash point leaves that name unmarked.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    real_link = os.link
    at_link: list[bytes | None] = []

    def link(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        marker = Path(os.fspath(src) + dr_backup._SPARE_SUFFIX)
        at_link.append(marker.read_bytes() if marker.exists() else None)
        real_link(src, dst, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(os, "link", link)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 0
    capsys.readouterr()
    assert at_link == [b"restored-store"], at_link
    _no_staging_left(dest.parent)
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)


def test_a_placement_that_fails_leaves_no_spare_on_the_staged_copy(
    tmp_path, key_b64, capsys
) -> None:
    # The marker written before the placement spares nothing once the placement fails: the staged
    # store is then no second name for anything, and the teardown removes it with the rest.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"

    real_place = dr_backup._place_restored_store

    def refuse(src: Path, dest: Path, **kwargs: Any) -> tuple[int, bool]:
        # The marker lands as the real placement writes it, then the link fails.
        def link(*args: Any) -> None:
            raise OSError(28, "No space left on device")

        with pytest.MonkeyPatch.context() as inner:
            inner.setattr(os, "link", link)
            inner.setattr(shutil, "copyfileobj", link)
            return real_place(src, dest, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_place_restored_store", refuse)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 1
    assert "restore failed (destination)" in _refusal(capsys)
    # The restore removes the directory it made for --to only once it is empty, so its absence
    # shows the staging directory went too.
    assert not dest.parent.exists()


def test_a_lost_create_race_leaves_the_winner_alone_and_no_spare(tmp_path, key_b64, capsys) -> None:
    # Another restore wins the exclusive create at --to between the checks and the link. The
    # marker this restore wrote spares nothing then, and the winner's store is untouched. The
    # staged store is held, so the rollback's own retry cannot remove it: only the unspare at the
    # failed placement lets the teardown take it.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"

    def link(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        with open(dst, "xb") as fh:
            fh.write(b"the other restore's store")
        raise FileExistsError(17, "File exists", os.fspath(dst))

    with pytest.MonkeyPatch.context() as mp:
        _hold(mp, _is_staged_store)
        mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
        mp.setattr(os, "link", link)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 1
    assert "restore failed (destination)" in _refusal(capsys)
    assert dest.read_bytes() == b"the other restore's store"
    _no_staging_left(dest.parent)


def test_a_copy_placement_unspares_the_staged_store_before_the_copy(
    tmp_path, key_b64, capsys
) -> None:
    # Where links are unavailable the store is placed by a copy, which never makes the staged
    # store a second name for it. The marker goes before the copy starts, so a crash mid-copy
    # leaves no marker keeping a full decrypted store from every later sweep.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    real_copy = shutil.copyfileobj
    marked_at_copy: list[bool] = []

    def no_link(*args: Any, **kwargs: Any) -> None:
        raise OSError(1, "Operation not permitted")

    def copy(src: Any, dst: Any, *args: Any) -> None:
        name = getattr(src, "name", "")
        if isinstance(name, str) and name.endswith("extracted_store.db"):
            marked_at_copy.append(Path(name + dr_backup._SPARE_SUFFIX).exists())
        real_copy(src, dst, *args)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(os, "link", no_link)
        mp.setattr(shutil, "copyfileobj", copy)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 0
    capsys.readouterr()
    assert marked_at_copy == [False], marked_at_copy
    _no_staging_left(dest.parent)
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)


def _refuse_marker_reason(mp: pytest.MonkeyPatch, refused: str) -> None:
    """Fail every spare marker write of the reason ``refused``; every other write is real."""
    real_write = dr_backup._write_spare_marker
    mp.setattr(
        dr_backup,
        "_write_spare_marker",
        lambda item, reason: False if reason == refused else real_write(item, reason),
    )


@pytest.mark.parametrize("refused", ["open", "ftruncate"])
def test_a_release_that_does_not_land_leaves_the_spare_and_says_so(
    tmp_path, caplog, refused
) -> None:
    # Neither the unlink nor the in-place rewrite lands, or the rewrite cannot be cut to length
    # (it then reads `released-store`, a reason nobody wrote). Either way the marker still
    # spares the file, never reads empty, and the release reports failure at ERROR.
    staging = tmp_path / "mefor-restore-x"
    staging.mkdir()
    item = staging / "extracted_store.db"
    item.write_bytes(b"synthetic")
    assert dr_backup._write_spare_marker(item, "restored-store")

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError(13, "held open by a scanner")

    with pytest.MonkeyPatch.context() as mp, caplog.at_level(logging.ERROR, dr_backup.log.name):
        _hold_markers(mp)
        if refused == "open":
            mp.setattr(dr_backup, "_open_unfollowed", refuse)
        else:
            mp.setattr(os, "ftruncate", refuse)
        assert dr_backup._release_spare_marker(item) is False
    marker = dr_backup._spare_marker(item).read_bytes()
    assert marker == (b"restored-store" if refused == "open" else b"released-store"), marker
    assert any("spared no longer" in r.getMessage() for r in caplog.records)
    assert "extracted_store.db" in (dr_backup._spared_items(staging, None) or {})


def test_a_marker_gone_after_its_refused_unlink_counts_as_released(tmp_path) -> None:
    item = tmp_path / "extracted_store.db"
    item.write_bytes(b"synthetic")
    assert dr_backup._write_spare_marker(item, "restored-store")

    def gone(*args: Any) -> int:
        raise FileNotFoundError(2, "No such file or directory")

    with pytest.MonkeyPatch.context() as mp:
        _hold_markers(mp)
        mp.setattr(dr_backup, "_open_unfollowed", gone)
        assert dr_backup._release_spare_marker(item) is True


def test_a_marker_unreadable_at_the_teardown_is_not_taken_as_unrecorded(tmp_path) -> None:
    # A marker there that cannot be read at that moment is unknown, not missing: the teardown must
    # not withhold its directory for good on a transient sharing violation.
    item = tmp_path / "extracted_store.db"
    item.write_bytes(b"synthetic")
    assert dr_backup._records_another_reason(item, "restored-store") is True  # no marker yet
    assert dr_backup._write_spare_marker(item, "restored-store")
    assert dr_backup._records_another_reason(item, "restored-store") is False
    assert dr_backup._records_another_reason(item, "rollback-failed") is True
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_read_spare_marker", lambda marker: None)
        assert dr_backup._records_another_reason(item, "rollback-failed") is False


def test_a_placement_interrupted_after_its_link_removes_what_it_placed(tmp_path) -> None:
    from messagefoundry.store import store as store_mod

    src = tmp_path / "extracted_store.db"
    src.write_bytes(b"synthetic store")
    dest = tmp_path / "msg.db"

    def interrupted(path: Path, *, dir_grants: object) -> None:
        raise KeyboardInterrupt

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(store_mod, "_secure_store_file", interrupted)
        with pytest.raises(KeyboardInterrupt):
            dr_backup._place_restored_store(src, dest)
    assert not dest.exists() and src.read_bytes() == b"synthetic store"


def test_a_placement_that_fails_after_its_link_is_rolled_back_by_the_restore(
    tmp_path, key_b64, capsys
) -> None:
    # The link lands, then the placement raises, and the first unlink of --to is refused. The
    # store at --to is this restore's own file, so the restore rolls it back; it used to leave it
    # unpublished, never rolled back, behind a retry the never-overwrite refusal blocks.
    from messagefoundry.store import store as store_mod

    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    store_refusals: list[Path] = []

    def held(path: Path) -> bool:
        if path == dest and not store_refusals:
            store_refusals.append(path)
            return True
        return False

    def fails(path: Path, *, dir_grants: object) -> None:
        raise RuntimeError("synthetic failure after the link")

    with pytest.MonkeyPatch.context() as mp:
        _hold(mp, held)
        mp.setattr(store_mod, "_secure_store_file", fails)
        mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) != 0
    capsys.readouterr()
    assert store_refusals == [dest]
    assert not dest.exists(), "the store this restore placed was left at --to"
    # The restore removes the directory it made for --to only once it is empty, so its absence
    # shows the staging directory went too.
    assert not dest.parent.exists()


@pytest.mark.parametrize("held_for", ["one unlink", "every unlink"])
def test_a_copy_that_fails_keeps_its_own_error_when_its_partial_file_will_not_go(
    tmp_path, key_b64, capsys, held_for
) -> None:
    # A copy placement dies mid-stream, and the unlink of its partial file is refused. That
    # unlink's error used to replace the copy's own, so the refusal named the wrong cause; it is
    # logged at ERROR instead. The partial file is this restore's, so its rollback tries again:
    # it goes where the hold lifts, and the refusal names it where it does not.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    refusals: list[Path] = []

    def no_link(*args: Any, **kwargs: Any) -> None:
        raise OSError(1, "Operation not permitted")

    def full(*args: Any) -> None:
        raise OSError(28, "No space left on device")

    def held(path: Path) -> bool:
        if path == dest and (held_for == "every unlink" or not refusals):
            refusals.append(path)
            return True
        return False

    errors = _ErrorRecords()
    with pytest.MonkeyPatch.context() as mp, errors.on(dr_backup.log):
        _hold(mp, held)
        mp.setattr(os, "link", no_link)
        mp.setattr(shutil, "copyfileobj", full)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 1
    (refusal,) = [line for line in _refusal(capsys).splitlines() if line.startswith("error:")]
    assert "No space left" in refusal and "held open" not in refusal, refusal
    assert any("partial copy" in m and str(dest) in m for m in errors.messages), errors.messages
    if held_for == "one unlink":
        assert not dest.exists(), "the rollback did not retry the partial copy at --to"
    else:
        assert dest.exists()
        assert f"partially restored store at {dest} could not be removed" in refusal, refusal


def test_fsync_dir_never_turns_a_failed_close_into_a_raise(caplog) -> None:
    # A marker that landed must never be reported as a failed write because the directory's
    # handle would not close after its flush.
    import types

    def refuse_close(fd: int) -> None:
        raise OSError(5, "Input/output error")

    with pytest.MonkeyPatch.context() as mp, caplog.at_level(logging.WARNING, dr_backup.log.name):
        mp.setattr(dr_backup, "sys", types.SimpleNamespace(platform="linux"))
        mp.setattr(os, "open", lambda *args, **kwargs: 12345)
        mp.setattr(os, "fsync", lambda fd: None)
        mp.setattr(os, "close", refuse_close)
        dr_backup._fsync_dir(Path("synthetic-dir"))
    assert any("could not close" in r.getMessage() for r in caplog.records), caplog.records


def test_a_placement_cleans_up_when_on_placed_did_not_return(tmp_path) -> None:
    # The caller owns the rollback of --to only once `on_placed` has returned; an interrupt inside
    # it, before the caller recorded that it owns the file, must not leave the file with nobody.
    src = tmp_path / "extracted_store.db"
    src.write_bytes(b"synthetic store")
    dest = tmp_path / "msg.db"

    def interrupted() -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        dr_backup._place_restored_store(src, dest, on_placed=interrupted)
    assert not dest.exists() and src.read_bytes() == b"synthetic store"


def test_a_released_marker_that_cannot_be_read_is_never_emptied(tmp_path) -> None:
    # Emptied, a `released` marker would read as a spare for a reason that could not be read, and
    # every later sweep would keep its directory. One the fail-safe cannot read at that moment is
    # kept and reported, never emptied.
    staging = tmp_path / "mefor-restore-x"
    staging.mkdir()
    item = staging / "extracted_store.db"
    item.write_bytes(b"synthetic")
    assert dr_backup._write_spare_marker(item, "released")

    def unreadable(marker: Path) -> str | None:
        raise PermissionError(13, "held open without read sharing")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_not_a_plain_marker", unreadable)
        unproven = dr_backup._empty_files_in_place(staging)
    assert dr_backup._spare_marker(item).read_bytes() == b"released"
    assert any("could not be read" in u for u in unproven), unproven
    assert item.stat().st_size == 0


def test_a_spare_marker_rename_is_flushed_before_it_counts_as_written(tmp_path) -> None:
    item = tmp_path / "extracted_store.db"
    item.write_bytes(b"synthetic")
    flushed: list[Path] = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_fsync_dir", flushed.append)
        assert dr_backup._write_spare_marker(item, "restored-store")
    assert flushed == [tmp_path]


def test_a_late_relabel_that_fails_withholds_the_directory_and_says_so(
    tmp_path, key_b64, capsys
) -> None:
    # As the rollback-after-the-teardown test above, but the marker cannot be relabelled
    # `rolled-back`: it keeps its older reason, so the restore withholds the directory from every
    # sweep and logs at ERROR that the marker could not be relabelled.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    store_refusals: list[Path] = []

    def held(path: Path) -> bool:
        if (path.name, path.parent.name) == ("msg.db", "restored") and not store_refusals:
            store_refusals.append(path)
            return True
        return _is_staged_store(path)

    errors = _ErrorRecords()
    with pytest.MonkeyPatch.context() as mp, errors.on(dr_backup.log):
        _restore_staging_that_cannot_be_removed(mp)
        _hold(mp, held)
        _refuse_marker_reason(mp, "rolled-back")
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    err = _refusal(capsys)
    assert "member-count cap" in err, err
    assert len(store_refusals) == 1 and not dest.exists()
    (leftover,) = dest.parent.glob("mefor-restore-*")
    staged = leftover / "extracted_store.db"
    assert (leftover / "extracted_store.db.mefor-spared").read_bytes() == b"rollback-failed"
    assert not (leftover / ".lock-held").exists()
    assert any("could not be relabelled" in m and str(staged) in m for m in errors.messages), (
        errors.messages
    )
    (refusal,) = [line for line in err.splitlines() if line.startswith("error:")]
    _assert_neutral_spare_refusal(refusal)
    shutil.rmtree(leftover)


#: Wordings that predict what a sweep will or can do with a restore's spared file. A race can make
#: any of them false, so no refusal on the spare path may carry one.
_SWEEP_PREDICTIONS = ("no sweep removes", "next sweep removes", "sweep can", "kept from sweeps")


def _assert_neutral_spare_refusal(refusal: str) -> None:
    """The refusal names the spared staged store and asks for its deletion by hand, and predicts
    nothing a sweep will or can do."""
    assert "extracted_store.db (" in refusal and "delete it by hand" in refusal, refusal
    found = [p for p in _SWEEP_PREDICTIONS if p in refusal]
    assert not found, (found, refusal)


def _hold_held_marker(mp: pytest.MonkeyPatch) -> None:
    """Refuse ``os.unlink`` on every staging directory's ``.lock-held``, so no withholding lands."""
    real_unlink = os.unlink

    def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if os.path.basename(os.fspath(path)) == ".lock-held":
            raise PermissionError(13, "held open by a scanner", os.fspath(path))
        real_unlink(path, *args, **kwargs)

    mp.setattr(os, "unlink", unlink)


@pytest.mark.parametrize("relabel", ["rollback-failed", "rolled-back"])
def test_a_withholding_that_fails_is_never_reported_as_landed(
    tmp_path, key_b64, capsys, relabel
) -> None:
    # A relabel does not land, so the restore tries to remove the directory's `.lock-held`, and
    # that removal is refused too. The refusal used to say no sweep removes the directory whatever
    # the removal did. It now predicts no sweep at all, and the failed removal is logged at ERROR.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    store_refusals: list[Path] = []

    def held(path: Path) -> bool:
        if (path.name, path.parent.name) == ("msg.db", "restored") and (
            relabel == "rollback-failed" or not store_refusals
        ):
            store_refusals.append(path)
            return True
        return _is_staged_store(path)

    errors = _ErrorRecords()
    with pytest.MonkeyPatch.context() as mp, errors.on(dr_backup.log):
        _hold(mp, held)
        _hold_held_marker(mp)
        _refuse_marker_reason(mp, relabel)
        mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    err = _refusal(capsys)
    (refusal,) = [line for line in err.splitlines() if line.startswith("error:")]
    assert "member-count cap" in refusal, refusal
    _assert_neutral_spare_refusal(refusal)
    (leftover,) = dest.parent.glob("mefor-restore-*")
    assert (leftover / ".lock-held").exists()
    assert any(
        "could not remove the .lock-held marker" in m and str(leftover) in m
        for m in errors.messages
    ), errors.messages
    shutil.rmtree(leftover)


def test_a_withholding_retried_under_the_lock_decides_the_refusal(
    tmp_path, key_b64, capsys
) -> None:
    # The relabel to `rollback-failed` does not land, and the first attempt to withhold the
    # directory is refused. The second attempt must run while the restore still holds its lock,
    # so no sweep can take the directory in between, and its result, here a removal that lands,
    # decides the refusal. It used to run after the lock dropped.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    real_unlink = os.unlink
    refused: list[str] = []

    def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if os.path.basename(os.fspath(path)) == ".lock-held" and not refused:
            refused.append(os.fspath(path))
            raise PermissionError(13, "held open by a scanner", os.fspath(path))
        real_unlink(path, *args, **kwargs)

    real_unlock = dr_backup._unlock_and_close
    held_at_unlock: list[list[bool]] = []

    def unlock(fd: int) -> None:
        held_at_unlock.append(
            [(d / ".lock-held").exists() for d in dest.parent.glob("mefor-restore-*")]
        )
        real_unlock(fd)

    with pytest.MonkeyPatch.context() as mp:
        _hold(
            mp, lambda p: _is_staged_store(p) or (p.name, p.parent.name) == ("msg.db", "restored")
        )
        mp.setattr(os, "unlink", unlink)
        mp.setattr(dr_backup, "_unlock_and_close", unlock)
        _refuse_marker_reason(mp, "rollback-failed")
        mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    (refusal,) = [line for line in _refusal(capsys).splitlines() if line.startswith("error:")]
    assert len(refused) == 1, refused
    assert held_at_unlock and held_at_unlock[-1] == [False], held_at_unlock
    _assert_neutral_spare_refusal(refusal)
    (leftover,) = dest.parent.glob("mefor-restore-*")
    assert not (leftover / ".lock-held").exists()
    shutil.rmtree(leftover)


def _rollback_failed_relabel_refused(
    tmp_path: Path, key_b64: str, capsys: Any, unreadable: Callable[[bool, bool], bool]
) -> tuple[str, Path, list[str]]:
    """Run a restore whose rollback cannot remove --to and whose relabel to `rollback-failed`
    does not land, with every spare-marker read returning "cannot be read" wherever
    ``unreadable(in_release, unlocked)`` says so. Returns the refusal line, the leftover and the
    ERROR messages."""
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    state = {"in_release": False, "unlocked": False}
    real_read = dr_backup._read_spare_marker
    real_release = dr_backup._Staging.release
    real_unlock = dr_backup._unlock_and_close

    def read(marker: Path) -> str | None:
        if unreadable(state["in_release"], state["unlocked"]):
            return None
        return real_read(marker)

    def release(self: Any, **kwargs: Any) -> str | None:
        state["in_release"] = True
        try:
            return real_release(self, **kwargs)
        finally:
            state["in_release"] = False

    def unlock(fd: int) -> None:
        if state["in_release"]:
            state["unlocked"] = True
        real_unlock(fd)

    errors = _ErrorRecords()
    with pytest.MonkeyPatch.context() as mp, errors.on(dr_backup.log):
        _hold(
            mp, lambda p: _is_staged_store(p) or (p.name, p.parent.name) == ("msg.db", "restored")
        )
        _refuse_marker_reason(mp, "rollback-failed")
        mp.setattr(dr_backup, "_read_spare_marker", read)
        mp.setattr(dr_backup._Staging, "release", release)
        mp.setattr(dr_backup, "_unlock_and_close", unlock)
        mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    (refusal,) = [line for line in _refusal(capsys).splitlines() if line.startswith("error:")]
    (leftover,) = dest.parent.glob("mefor-restore-*")
    return refusal, leftover, errors.messages


def test_a_teardown_never_rereads_and_remarks_what_the_release_withheld(
    tmp_path, key_b64, capsys
) -> None:
    # The release finds the spare unrecorded and withholds the directory under the lock. Every
    # marker read after the unlock then fails, as under a scanner without read sharing. The
    # teardown used to read the spare again, take it as recorded, and re-mark the directory,
    # undoing the withholding.
    refusal, leftover, _ = _rollback_failed_relabel_refused(
        tmp_path, key_b64, capsys, lambda in_release, unlocked: unlocked
    )
    assert not (leftover / ".lock-held").exists(), "the teardown re-marked a withheld directory"
    _assert_neutral_spare_refusal(refusal)
    shutil.rmtree(leftover)


def test_a_withholding_made_after_the_lock_dropped_promises_no_outcome(
    tmp_path, key_b64, capsys
) -> None:
    # The release cannot read the marker while it holds the lock, so it withholds nothing; the
    # teardown's later read finds the spare unrecorded and withholds after the unlock, when a
    # sweep can have taken the directory first. The refusal must predict no sweep outcome.
    refusal, leftover, _ = _rollback_failed_relabel_refused(
        tmp_path, key_b64, capsys, lambda in_release, unlocked: in_release and not unlocked
    )
    _assert_neutral_spare_refusal(refusal)
    shutil.rmtree(leftover)


def test_a_release_whose_spare_check_raises_still_unlocks_and_tears_down(
    tmp_path, key_b64, capsys
) -> None:
    def fails(path: Path, spared: object) -> object:
        raise RuntimeError("synthetic failure checking the spares")

    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    errors = _ErrorRecords()
    with pytest.MonkeyPatch.context() as mp, errors.on(dr_backup.log):
        _hold(mp, _is_staged_store)
        mp.setattr(dr_backup, "_spare_records", fails)
        mp.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 1
    assert "restore failed (cleanup)" in _refusal(capsys)
    assert any("could not check its spares" in m for m in errors.messages), errors.messages
    (leftover,) = dest.parent.glob("mefor-restore-*")
    # The teardown ran: the archive was emptied and the directory re-marked for the next sweep.
    assert (leftover / "archive.tar").stat().st_size == 0
    assert (leftover / ".lock-held").exists()
    shutil.rmtree(leftover)


def test_an_unreadable_spare_marker_is_logged(tmp_path, caplog) -> None:
    marker = tmp_path / "x.db.mefor-spared"
    marker.write_bytes(b"\xff\xfe")
    with caplog.at_level(logging.WARNING, logger=dr_backup.log.name):
        assert dr_backup._read_spare_reason(marker) == ""
    assert any(str(marker) in r.getMessage() for r in caplog.records), caplog.records


def test_a_spare_marker_temp_file_that_will_not_go_is_logged(tmp_path, caplog) -> None:
    item = tmp_path / "x.db"
    item.write_bytes(b"synthetic")

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise PermissionError(13, "refused")

    with pytest.MonkeyPatch.context() as mp, caplog.at_level(logging.WARNING, dr_backup.log.name):
        mp.setattr(os, "replace", refuse)
        mp.setattr(os, "unlink", refuse)
        assert dr_backup._write_spare_marker(item, "restored-store") is False
    assert any("temporary" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]


def test_a_staged_store_whose_hold_lifts_before_the_teardown_leaves_no_leftover(
    tmp_path, key_b64, capsys
) -> None:
    # The control for the two above: a staged name whose first unlink is refused but whose hold
    # lifts before the teardown is removed then, with its marker, and the restore succeeds clean.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    refused: list[Path] = []

    def first_only(path: Path) -> bool:
        if _is_staged_store(path) and not refused:
            refused.append(path)
            return True
        return False

    with pytest.MonkeyPatch.context() as mp:
        _hold(mp, first_only)
        assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 0
    capsys.readouterr()
    assert len(refused) == 1
    _no_staging_left(dest.parent)
    assert asyncio.run(_read_back(dest, key_b64)) == (1, _RAW_BODY)


def test_a_failed_restore_never_unlinks_a_store_another_restore_placed(
    tmp_path, key_b64, capsys
) -> None:
    # The failed restore removes its placed store before its staging teardown, which leaves --to
    # free for as long as that teardown runs. A second restore can win the exclusive create there
    # in that window. The rollback after the teardown must not unlink that path again, or it would
    # delete the second restore's store while that restore reports success.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    real_release = dr_backup._Staging.release
    winners: list[Path] = []

    def release_while_another_restore_wins(self, **kwargs):
        if not dest.exists() and not winners:
            # The other restore's exclusive create, inside the window.
            with open(dest, "xb") as fh:
                fh.write(b"the other restore's store")
            winners.append(dest)
        return real_release(self, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_MAX_CONFIG_MEMBERS", 1)
        mp.setattr(dr_backup._Staging, "release", release_while_another_restore_wins)
        assert main(_restore_argv(archive, toml, dest, tmp_path / "bundle")) == 1
    assert "member-count cap" in _refusal(capsys)
    assert winners == [dest]
    assert dest.read_bytes() == b"the other restore's store"


def test_refusal_in_flight_reads_past_more_than_one_link() -> None:
    # Nested `with` exits can each raise on the way out, so the refusal can sit two links down.
    refusal = dr_backup.BackupError("verify", "the cap")
    try:
        try:
            try:
                raise refusal
            except dr_backup.BackupError:
                raise OSError(28, "first close") from None
        except OSError:
            raise OSError(28, "second close") from None
    except OSError as exc:
        outer = exc
    assert dr_backup._refusal_in_flight(outer) is refusal
    assert dr_backup._refusal_in_flight(OSError(28, "alone")) is None


def test_restore_refuses_a_staging_directory_that_is_not_owner_only(tmp_path, capsys) -> None:
    # The restore's staging directory gets the backup's and verify's owner-only check
    # (BACKLOG #5617): on a volume that ignores the requested mode or ACL nothing is staged.
    tar = _undated_config_only_tar(tmp_path)
    toml = _service_toml(tmp_path, key_b64=None)
    argv = [*_config_only_argv(str(tar), toml, tmp_path / "cfg"), "--allow-old-archive"]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_staging_is_private", lambda path: False)
        assert main(argv) == 1
    err = _refusal(capsys)
    assert "restore failed (destination)" in err and "did not come out owner-only" in err, err
    assert "[backup].destination" not in err, err
    _no_staging_left(tmp_path)
    assert not (tmp_path / "cfg").exists()
    # The control: the same command stages and restores.
    assert main(argv) == 0


def test_a_restore_staging_leftover_is_pruned_from_a_config_walk(tmp_path) -> None:
    # A marked restore leftover inside a config directory is staging, not config, as a backup's
    # or verify's is; a same-prefix directory with no lock file stays config.
    marked = tmp_path / "mefor-restore-abc"
    marked.mkdir()
    (marked / ".lock").write_bytes(b"")
    unmarked = tmp_path / "mefor-restore-maps"
    unmarked.mkdir()
    assert dr_backup._is_staging_dir(marked)
    assert not dr_backup._is_staging_dir(unmarked)


def test_an_os_error_mid_restore_is_a_refusal(tmp_path, key_b64, capsys) -> None:
    # A full volume mid-decrypt, or any OSError with no refusal behind it, is a refusal line, not a
    # traceback, on both routes.
    archive, toml = _make_archive(tmp_path, key_b64, capsys)

    def full(*args: object, **kwargs: object) -> object:
        raise OSError(28, "No space left on device")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "decrypt_stream", full)
        assert (
            main(["restore", archive, "--to", str(tmp_path / "x.db"), "--service-config", toml])
            == 1
        )
    err = _refusal(capsys)
    assert "restore failed (restore)" in err and "No space left" in err, err
    assert not (tmp_path / "x.db").exists()
    _no_staging_left(tmp_path)


def test_config_only_route_refuses_an_archive_marked_neither_way(tmp_path, capsys) -> None:
    # No store member, and a manifest that does not say config-only: `--to` would refuse it as
    # having no store, so this route must not send the operator there.
    tar = _plain_tar(
        tmp_path / "neither.tar", [("config/feed.py", b"# a\n"), ("manifest.json", b"{}")]
    )
    toml = _service_toml(tmp_path, key_b64=None)
    assert main([*_config_only_argv(str(tar), toml, tmp_path / "cfg"), "--allow-old-archive"]) == 1
    err = _refusal(capsys)
    assert "does not mark it CONFIG-ONLY" in err and "needs --to" not in err, err
    assert not (tmp_path / "cfg").exists()


def test_config_only_dangling_link_refusal_does_not_offer_dropping_config_to(tmp_path) -> None:
    # The pre-check's advice is for the store route. The extractor, which the config-only route
    # runs, refuses the same link without it: dropping --config-to there restores nothing.
    tar = _plain_tar(
        tmp_path / "dangling.tar",
        [("config/a.toml", b"[a]\n"), _hard_link("config/b.toml", "config/absent.toml")],
    )
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_config_members(tar, tmp_path / "cfg")
    assert "hard link" in str(excinfo.value)
    assert "without --config-to" not in str(excinfo.value)


# --- (5b) a corrupt or forged archive refuses, it does not traceback ----------


_DIRECTORY_MEMBER = object()  # a tar member that is a directory wearing the given name


def _plain_tar(path: Path, members: Sequence[tuple[str, bytes | object] | tarfile.TarInfo]) -> Path:
    """An uncompressed tar carrying exactly ``members``, in order -- the plaintext shape
    ``_restore_blocking`` consumes on a no-key box, and the one a forged archive would have. A body
    of ``_DIRECTORY_MEMBER`` adds a directory under that name instead of a file, and a bare
    ``TarInfo`` (a hard-link member, say) is added as it stands, with no body."""
    with tarfile.open(path, "w") as tar:
        for m in members:
            if isinstance(m, tarfile.TarInfo):
                tar.addfile(m)
                continue
            name, body = m
            info = tarfile.TarInfo(name)
            if body is _DIRECTORY_MEMBER:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
                continue
            assert isinstance(body, bytes)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return path


def _archive_with_manifest(tmp_path: Path, payload: bytes | object | None) -> Path:
    """A plaintext archive whose manifest is ``payload``: absent when ``None``, a directory member
    when ``_DIRECTORY_MEMBER``, else exactly those bytes. The store member is always present, so the
    manifest is the only thing wrong with the archive."""
    members: list[tuple[str, bytes | object]] = []
    if payload is not None:
        members.append((dr_backup._MANIFEST_MEMBER, payload))
    members.append(("store.db", b"SQLite format 3\x00"))
    return _plain_tar(tmp_path / "manifest-case.tar", members)


# Every shape of manifest that is not one, each labelled by the limb it exercises. Absent is the
# `KeyError` limb; the next two are the two `ValueError`s `json.loads` raises -- a `JSONDecodeError`
# on bytes that decode and then fail to parse, and a `UnicodeDecodeError` on bytes that fail to
# DECODE one step earlier, which is a `ValueError` but NOT a `JSONDecodeError` (so a guard naming
# only the latter let it through; an all-ASCII body can never reach that limb). The last three are
# the shapes that used to fold to `{}` and RESTORE with no manifest check at all, while an absent
# manifest refused: valid JSON that is not an object, and a directory wearing the member's name.
_UNUSABLE_MANIFESTS = [
    ("absent", None),
    ("not json", b"{not json at all"),
    ("not utf-8", b"{\xff"),
    ("a list", b"[]"),
    ("null", b"null"),
    ("a directory", _DIRECTORY_MEMBER),
]


def test_restore_refuses_an_archive_with_no_manifest(tmp_path, capsys) -> None:
    # `_read_manifest_from_tar` used to raise KeyError when the manifest member was absent, and at
    # this call site nothing caught it, so it escaped the CLI's BackupError handler as a traceback
    # from the last-resort excepthook while every other archive fault on this path refuses cleanly.
    # Driven through the CLI so the observable IS the refusal (rc 1 and a reason on stderr) rather
    # than an exception type a caller might or might not translate. The reason names the member, so
    # an operator reading the line knows what the archive lacks.
    tar = _archive_with_manifest(tmp_path, None)
    toml = _service_toml(tmp_path, key_b64=None)
    dest = tmp_path / "out" / "msg.db"
    assert main(["restore", str(tar), "--to", str(dest), "--service-config", toml]) == 1
    err = _refusal(capsys)
    assert "restore failed (restore)" in err and "no manifest.json member" in err
    assert not dest.exists()


@pytest.mark.parametrize(("label", "payload"), _UNUSABLE_MANIFESTS)
def test_restore_refuses_an_archive_whose_manifest_is_unusable(
    tmp_path, capsys, label, payload
) -> None:
    tar = _archive_with_manifest(tmp_path, payload)
    toml = _service_toml(tmp_path, key_b64=None)
    dest = tmp_path / "out" / "msg.db"
    assert main(["restore", str(tar), "--to", str(dest), "--service-config", toml]) == 1, label
    err = _refusal(capsys)
    assert "restore failed (restore)" in err and "manifest could not be read" in err, (label, err)
    assert not dest.exists()


@pytest.mark.parametrize(("label", "payload"), _UNUSABLE_MANIFESTS)
def test_restore_verify_fails_an_archive_whose_manifest_is_unusable(
    tmp_path, capsys, label, payload
) -> None:
    # The SAME archives through `restore-verify`, which is the command the runbook tells an operator
    # to run FIRST to triage. The translation for these shapes used to live at the restore call site
    # alone, so `restore` refused a forged manifest-less archive cleanly while `restore-verify` on the
    # identical file raised a traceback (`_verify_archive_blocking` caught neither the KeyError nor
    # the ValueError, and the CLI calls it outside any try). Normalised inside
    # `_read_manifest_from_tar`, both commands now see one `TarError` and both refuse: here as a
    # FAIL verdict with a reason that names the manifest, on the same stream a good verify reports on.
    tar = _archive_with_manifest(tmp_path, payload)
    toml = _service_toml(tmp_path, key_b64=None)
    assert main(["restore-verify", str(tar), "--service-config", toml, "--json"]) == 1, label
    verdict = _json_line(capsys.readouterr().out)
    assert verdict["status"] == "FAIL", (label, verdict)
    assert "manifest.json" in verdict["reason"], (label, verdict)


def test_restore_refuses_a_config_member_landing_on_a_directory(tmp_path) -> None:
    # The mirror image of the parent-mkdir collision the extractor already refuses. A forged archive
    # carrying `config/a/b` and then `config/a` asks the exclusive create to make a FILE where the
    # first member just made a DIRECTORY. Windows reports that as EACCES, not EEXIST, so the
    # FileExistsError arm written to refuse exactly this collision did not catch it and it escaped as
    # a traceback.
    tar = _plain_tar(
        tmp_path / "collide.tar",
        [("config/a/b", b"inner"), ("config/a", b"outer")],
    )
    cfg = tmp_path / "bundle"
    with pytest.raises(dr_backup.BackupError) as excinfo:
        dr_backup._restore_config_members(tar, cfg)
    assert excinfo.value.kind == "restore"
    assert str(cfg / "a") in str(excinfo.value)


def test_restore_caps_the_plaintext_staging_copy(tmp_path, capsys) -> None:
    # The plaintext limb had no cap under a constant whose own rationale said it "moves the bound to
    # the first write". It is the limb that needs the bound MOST: there is no AEAD tag to fail on, so
    # a forged archive is simply copied onto the destination volume. The cap is lowered rather than a
    # multi-GiB file written; the bound under test is the counting, not the number.
    archive, toml = _make_archive(tmp_path, None, capsys)  # keyless box -> a plaintext .mfbak.plain
    dest = tmp_path / "restored" / "msg.db"
    argv = ["restore", archive, "--to", str(dest), "--service-config", toml]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(dr_backup, "_MAX_RESTORE_PLAINTEXT_BYTES", 64)
        assert main(argv) == 1
    err = _refusal(capsys)
    assert "restore failed (verify)" in err and "exceeds the restore staging cap" in err
    assert not dest.exists()

    # The control: the same archive, the same command, the shipped cap -- it must RESTORE. Without
    # this the test above would pass against a path that refuses everything.
    assert main(argv) == 0
    assert dest.is_file()


def test_restore_downgrade_refusal_does_not_prescribe_a_setting_it_ignores(
    tmp_path, key_b64, capsys
) -> None:
    # A plaintext archive on a box that HAS a store key is a downgrade signal and is refused. The
    # refusal used to end "Set [backup].allow_unencrypted to accept it." -- and `run_restore` never
    # read that setting: its parameter existed, the CLI documented in a comment that it withheld it on
    # purpose, and nothing else called it. So the remedy named a knob an operator could set and watch
    # do nothing. The parameter is gone and the message now says the true thing.
    plain, _keyless_toml = _make_archive(tmp_path, None, capsys)  # a plaintext archive...
    keyed_toml = _service_toml(tmp_path, key_b64=key_b64, name="keyed.toml")  # ...on a keyed box
    dest = tmp_path / "restored" / "msg.db"
    assert main(["restore", plain, "--to", str(dest), "--service-config", keyed_toml]) == 1
    message = _refusal(capsys)
    assert "KEY_MISMATCH" in message and "possible downgrade" in message
    assert "allow_unencrypted" not in message
    assert not dest.exists()
    assert "allow_unencrypted" not in inspect.signature(dr_backup.run_restore).parameters


def test_restore_secures_every_staged_file_before_its_first_byte(tmp_path, key_b64, capsys) -> None:
    # The staging directory sits on the DESTINATION volume, where a directory could inherit the
    # parent's ACL on Windows, and the files staged in it are the whole decrypted archive and the
    # whole store. Locking each to its owner AFTER its write completes leaves a multi-GB write of PHI
    # under the inherited ACL for as long as the write takes; the contract is that the lock lands on
    # the EMPTY file. The spy records each file's size at the moment it is secured, which is the
    # observable that separates "secured" from "secured in time".
    archive, toml = _make_archive(tmp_path, key_b64, capsys)
    dest = tmp_path / "restored" / "msg.db"
    config_dest = tmp_path / "bundle"
    seen: list[tuple[str, int]] = []

    def spy(path: Path, **_kw: object) -> None:
        seen.append((path.name, path.stat().st_size))

    from messagefoundry.store import store as store_module

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(store_module, "_secure_file", spy)
        assert main(_restore_argv(archive, toml, dest, config_dest)) == 0
    # The control that the spy did not break the path: a real store and a real bundle landed.
    assert dest.is_file() and (config_dest / "feed.py").is_file()

    secured_empty = sorted(name for name, size in seen if size == 0)
    # Both staged files and both config members, each at size 0 -- four sightings, no more.
    assert secured_empty == ["archive.tar", "extracted_store.db", "feed.py", "sex.csv"], seen
    # The published store is secured too (by `_place_restored_store`, on the full file it links).
    assert any(name == "msg.db" and size > 0 for name, size in seen), seen


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


_MISMATCH = "row-count mismatch"
_NO_MANIFEST_COUNTS = "the manifest records no row counts"
_MALFORMED = "are not non-negative integers"


@pytest.mark.parametrize(
    ("label", "manifest_counts", "refusal"),
    [
        # The compare is keyed off the MANIFEST's keys, not dict equality, because `_count_tables`
        # derives its table set from the snapshot's own sqlite_master (BACKLOG #1722). These pin both
        # directions of that: what must still refuse, and what must no longer refuse.
        ("exact match", {"messages": 3, "queue": 0}, None),
        # Real data loss, which is the whole point of the check.
        ("torn: manifest declares more rows than survived", {"messages": 5, "queue": 0}, _MISMATCH),
        # A table the manifest tracked that the snapshot's schema lacks reads as 0, so a NONZERO
        # manifest count for it is still loss and still refuses.
        ("dropped table the manifest counted", {"messages": 3, "audit_log": 7}, _MISMATCH),
        # ...and a zero one is the documented convention for a table absent from the schema.
        ("absent table the manifest recorded as 0", {"messages": 3, "audit_log": 0}, None),
        # The case dict equality got wrong: an archive whose manifest predates the widened table set
        # is the ORDINARY thing to restore, and equality would have refused every one of them.
        ("older, narrower manifest", {"messages": 3}, None),
        # BACKLOG #5056: a manifest with no counts has no key to mismatch, so these once returned
        # the snapshot's counts as if compared. Both now refuse, because nothing was compared.
        ("manifest carrying no row_counts at all", None, _NO_MANIFEST_COUNTS),
        ("manifest carrying an empty row_counts", {}, _NO_MANIFEST_COUNTS),
        ("manifest whose row_counts is not a mapping", [["messages", 3]], "not a mapping"),
        # Every manifest key reads as 0 against a schema it shares no table with, so an all-zero
        # manifest agreed with a snapshot it never compared.
        ("manifest sharing no table with the snapshot", {"zzz": 0}, "share none with"),
        # A count that is not a non-negative integer refuses, rather than coercing 3.9 to 3 (which
        # agreed with 3 rows) or raising a ValueError out of the verify.
        ("a float count", {"messages": 3.9, "queue": 0}, _MALFORMED),
        ("a string count", {"messages": "3", "queue": 0}, _MALFORMED),
        ("a boolean count", {"messages": 3, "queue": False}, _MALFORMED),
        ("a null count", {"messages": None, "queue": 0}, _MALFORMED),
        ("a negative count", {"messages": 3, "queue": -1}, _MALFORMED),
    ],
)
def test_restore_row_count_compare(tmp_path, label, manifest_counts, refusal) -> None:
    snap = _snap_with(tmp_path, messages=3)
    manifest: dict[str, object] = {} if manifest_counts is None else {"row_counts": manifest_counts}
    if refusal is not None:
        with pytest.raises(dr_backup.BackupError, match=refusal):
            dr_backup._verify_extracted_store(snap, manifest)
    else:
        assert dr_backup._verify_extracted_store(snap, manifest) == {"messages": 3, "queue": 0}


def test_restore_refuses_a_snapshot_with_no_table(tmp_path: Path) -> None:
    """BACKLOG #5056, the other side: a ``store.db`` whose schema holds no table reads every
    manifest count as 0, so an all-zero manifest would agree with a file that holds nothing."""
    import sqlite3

    snap = tmp_path / "store.db"
    sqlite3.connect(snap).close()
    assert dr_backup._count_tables(snap) == {}
    with pytest.raises(dr_backup.BackupError, match="share none with"):
        dr_backup._verify_extracted_store(snap, {"row_counts": {"messages": 0, "queue": 0}})
    # Against nonzero counts the same file is data loss, and the reason must still say so.
    with pytest.raises(dr_backup.BackupError, match=_MISMATCH):
        dr_backup._verify_extracted_store(snap, {"row_counts": {"messages": 5, "queue": 0}})
