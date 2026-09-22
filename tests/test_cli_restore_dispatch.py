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
import errno
import inspect
import io
import json
import os
import shutil
import tarfile
import tempfile
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
    # The directory is kept (a retry re-creates or reuses it); what it held must be gone.
    assert config_dest.is_dir()
    assert not any(config_dest.iterdir()), (
        "a partially written config bundle survived, which blocks the retry's empty-dir check"
    )
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
    # because the end state alone cannot tell the two designs apart: `TemporaryDirectory` tolerates
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
    # AFTER `TemporaryDirectory` has unlinked it, so it could not have been the thing that removed it.
    assert len(calls) == 1, calls
    names_at_call, ledger = calls[0]
    assert not any(n.startswith("mefor-restore-") for n in names_at_call), names_at_call
    # The ledger names only paths under `--config-to` that the bundle created -- one member landed
    # before the cap -- and never the staging directory or the store.
    assert ledger and all(p.is_relative_to(d.resolve()) for p in ledger), ledger
    assert not any(p.name.startswith("mefor-restore-") for p in ledger), ledger
    assert dest.resolve() not in ledger

    # End state: the directory is back to empty, with no staging leftover and no store.
    assert d.is_dir() and not any(d.iterdir()), sorted(p.name for p in d.iterdir())
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


_REAL_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory


class _StagingWhoseTeardownFails:
    """The restore's staging directory, with the teardown that fails on Windows whenever a scanner or
    the indexer still holds the just-extracted store open: the directory is created and handed out as
    usual, and on exit its removal raises ``PermissionError`` and leaves it behind, exactly as a real
    ``TemporaryDirectory`` does when ``rmtree`` cannot delete an open file. Holding a handle would
    reproduce that on Windows alone; raising from the exit reproduces it everywhere."""

    def __init__(self, *, prefix: str, dir: Path) -> None:
        self.name = tempfile.mkdtemp(prefix=prefix, dir=dir)

    def __enter__(self) -> str:
        return self.name

    def __exit__(self, *exc: object) -> None:
        raise PermissionError(errno.EACCES, "another process holds a file in it open", self.name)


def _staging_that_cannot_be_removed(*args, **kwargs):
    """Intercept the RESTORE's staging directory only, by its prefix; every other caller (the backup
    that builds the fixture archive stages under ``mefor-backup-``) gets the real class."""
    if kwargs.get("prefix") == "mefor-restore-":
        return _StagingWhoseTeardownFails(**kwargs)
    return _REAL_TEMPORARY_DIRECTORY(*args, **kwargs)


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
        mp.setattr(tempfile, "TemporaryDirectory", _staging_that_cannot_be_removed)
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
    # that failed was its remover, and it still holds the decrypted store.
    leftovers = [p for p in dest.parent.iterdir() if p.name.startswith("mefor-restore-")]
    assert len(leftovers) == 1, sorted(p.name for p in dest.parent.iterdir())
    assert leftovers[0].name in err and str(dest) in err, err
    assert (leftovers[0] / "extracted_store.db").is_file()
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


# --- (5b) a corrupt or forged archive refuses, it does not traceback ----------


_DIRECTORY_MEMBER = object()  # a tar member that is a directory wearing the given name


def _plain_tar(path: Path, members: list[tuple[str, bytes | object]]) -> Path:
    """An uncompressed tar carrying exactly ``members``, in order -- the plaintext shape
    ``_restore_blocking`` consumes on a no-key box, and the one a forged archive would have. A body
    of ``_DIRECTORY_MEMBER`` adds a directory under that name instead of a file."""
    with tarfile.open(path, "w") as tar:
        for name, body in members:
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
    # The staging directory sits on the DESTINATION volume, where `TemporaryDirectory` inherits the
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
