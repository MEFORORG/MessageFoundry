# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The config-bundle restore's member names, file locks and rollback ledger (BACKLOG #5618).

A Windows restore must not write a member as an alternate data stream of another member. A restored
config file takes the grants of a hardened destination, so the service account keeps its access. A
lock that did not land refuses the restore. A directory is in the rollback ledger from the moment it
is created, so a failure part way down a chain leaves the destination retryable."""

from __future__ import annotations

import io
import os
import stat
import sys
import tarfile
from pathlib import Path

import pytest

from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupError
from messagefoundry.store import store as store_mod

_SERVICE = "S-1-5-80-1-2-3-4-5"
_GRANTS = ("S-1-5-18", "S-1-5-32-544", _SERVICE)
_EXACT_SDDL = f"O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;{_SERVICE})"


def _tar(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with tarfile.open(path, "w") as tar:
        for name, body in members:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return path


def _leave_unlocked(path: Path, **_kw: object) -> None:
    """A lock that failed and only logged: on POSIX the file is left group- and world-readable."""
    if os.name != "nt":
        os.chmod(path, 0o644)


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS alternate data streams are Windows-only")
def test_a_stream_member_on_a_restored_file_is_refused(tmp_path: Path) -> None:
    tar = _tar(
        tmp_path / "forged.tar",
        [("config/a.toml", b"[a]\n"), ("config/a.toml:evil", b"hidden\n")],
    )
    cfg = tmp_path / "bundle"
    written: list[Path] = []
    with pytest.raises(BackupError, match="unsafe config member name") as excinfo:
        dr_backup._restore_config_members(tar, cfg, written=written)
    assert "a.toml:evil" in str(excinfo.value)  # the operator is told which member
    with pytest.raises(OSError):
        (cfg / "a.toml:evil").read_bytes()
    dr_backup._discard_partial_restore(None, written)
    assert list(cfg.iterdir()) == []


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows name gate runs on Windows")
@pytest.mark.parametrize("name", ["config/con.toml", "config/sub/aux.py", "config/trailing."])
def test_a_windows_special_name_refuses_on_windows(tmp_path: Path, name: str) -> None:
    tar = _tar(tmp_path / "forged.tar", [(name, b"x")])
    with pytest.raises(BackupError, match="unsafe config member name"):
        dr_backup._restore_config_members(tar, tmp_path / "bundle")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX opens each of these names as itself")
@pytest.mark.parametrize("rel", ["con.toml", "sub/aux.py", "trailing.", "a:b.toml"])
def test_a_posix_restore_still_lands_the_names_only_windows_reads_specially(
    tmp_path: Path, rel: str
) -> None:
    # The destination is this host, so a POSIX backup's legal file name stays restorable.
    tar = _tar(tmp_path / "bundle.tar", [(f"config/{rel}", b"x")])
    assert dr_backup._restore_config_members(tar, tmp_path / "bundle") == 1
    assert (tmp_path / "bundle" / rel).read_bytes() == b"x"


@pytest.mark.parametrize("dest_exists", [True, False])
def test_every_restored_file_takes_the_destination_grants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dest_exists: bool
) -> None:
    # Read once from the nearest directory that already exists, because one this restore creates
    # only inherits and would read as not hardened, locking the service account out.
    tar = _tar(tmp_path / "b.tar", [("config/a.toml", b"a"), ("config/sub/b.toml", b"b")])
    cfg = tmp_path / "bundle"
    if dest_exists:
        cfg.mkdir()
    asked: list[Path] = []
    secured: list[tuple[str, object]] = []

    def grants(directory: Path) -> tuple[str, ...]:
        asked.append(directory)
        return _GRANTS

    def secure(path: Path, *, dir_grants: object) -> None:
        secured.append((path.name, dir_grants))

    monkeypatch.setattr(store_mod, "_store_dir_grants", grants)
    monkeypatch.setattr(store_mod, "_secure_store_file", secure)
    monkeypatch.setattr(dr_backup, "_config_lock_problem", lambda path, dir_grants: None)
    assert dr_backup._restore_config_members(tar, cfg) == 2
    assert asked == [cfg if dest_exists else tmp_path]
    assert secured == [("a.toml", _GRANTS), ("b.toml", _GRANTS)]


def test_a_lock_that_did_not_land_refuses_and_the_retry_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tar = _tar(tmp_path / "b.tar", [("config/a.toml", b"a"), ("config/sub/b.toml", b"secret")])
    cfg = tmp_path / "bundle"
    written: list[Path] = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(store_mod, "_secure_file", _leave_unlocked)
        with pytest.raises(BackupError, match="could not lock"):
            dr_backup._restore_config_members(tar, cfg, written=written)
    # Refused on the empty file, before the first byte of the member.
    assert written and written[-1].stat().st_size == 0
    dr_backup._discard_partial_restore(None, written)
    assert list(cfg.iterdir()) == []
    dr_backup._refuse_existing_destination(None, cfg)  # the retry's own precondition
    assert dr_backup._restore_config_members(tar, cfg) == 2


def test_a_real_restore_passes_its_own_lock_check(tmp_path: Path) -> None:
    # The control for the refusal above: the real lock, on this host, satisfies the real check.
    tar = _tar(tmp_path / "b.tar", [("config/sub/a.toml", b"a")])
    cfg = tmp_path / "bundle"
    assert dr_backup._restore_config_members(tar, cfg) == 1
    assert dr_backup._config_lock_problem(cfg / "sub" / "a.toml", None) is None


@pytest.mark.parametrize(
    ("sddl", "locked"),
    [
        (_EXACT_SDDL, True),
        # A broader right for the service account, an extra principal, an inheriting list, and an
        # owner outside the grants, who could give itself access back.
        (f"O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{_SERVICE})", False),
        (_EXACT_SDDL + "(A;;FR;;;BU)", False),
        (_EXACT_SDDL.replace("D:PAI", "D:AI"), False),
        (_EXACT_SDDL.replace("O:BA", "O:S-1-5-21-1-2-3-1001"), False),
    ],
)
def test_the_grant_check_accepts_only_the_exact_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sddl: str, locked: bool
) -> None:
    monkeypatch.setattr(store_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(store_mod, "_read_dacl_sddl", lambda path, owner=False: sddl)
    problem = dr_backup._config_lock_problem(tmp_path / "a.toml", _GRANTS)
    assert (problem is None) is locked, problem


def test_an_unreadable_access_list_is_not_a_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(store_mod, "_read_dacl_sddl", lambda path, owner=False: None)
    assert dr_backup._config_lock_problem(tmp_path / "a.toml", None) is not None


@pytest.mark.skipif(sys.platform != "win32", reason="SDDL aliases resolve through Windows")
@pytest.mark.parametrize(
    ("sddl", "locked"),
    [
        # NETWORK SERVICE is written as an alias, and is still this account.
        ("O:NSD:PAI(A;;FA;;;NS)", True),
        ("O:NSD:PAI(A;;FA;;;NS)(A;;FA;;;SY)(A;;FA;;;BA)", True),  # explicit entries that survive
        ("O:NSD:PAI(A;;FA;;;SY)", False),  # this account is not on it
        ("O:NSD:PAI(A;;FA;;;NS)(D;;FA;;;SY)", False),  # a deny entry is not the lock's shape
        ("O:NSD:PAI(A;;FA;;;LS)", False),  # another account
        ("O:NSD:PAI(A;;FA;;;NS)(A;;FR;;;BU)", False),  # a second entry
        ("O:NSD:AI(A;;FA;;;NS)", False),  # still inheriting
        ("O:NSD:PAI(A;;FR;;;NS)", False),  # not the right the lock writes
    ],
)
def test_the_owner_only_check_reads_an_alias_as_its_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sddl: str, locked: bool
) -> None:
    monkeypatch.setattr(store_mod, "_read_dacl_sddl", lambda path, owner=False: sddl)
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: "S-1-5-20")
    problem = dr_backup._config_lock_problem(tmp_path / "a.toml", None)
    assert (problem is None) is locked, problem


@pytest.mark.skipif(os.name == "nt", reason="the POSIX arm of the lock check")
def test_the_posix_check_reads_the_mode(tmp_path: Path) -> None:
    path = tmp_path / "a.toml"
    path.write_bytes(b"")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    assert dr_backup._config_lock_problem(path, None) is None
    os.chmod(path, 0o640)
    assert dr_backup._config_lock_problem(path, None) is not None


def test_a_chain_that_fails_part_way_leaves_nothing_behind(tmp_path: Path) -> None:
    # The second directory's name is longer than any file system takes, so the first is created
    # and the second is not. It must be in the ledger, or it blocks the retry as a non-empty dir.
    tar = _tar(tmp_path / "long.tar", [(f"config/ok/{'n' * 300}/a.toml", b"a")])
    cfg = tmp_path / "bundle"
    written: list[Path] = []
    with pytest.raises(BackupError):
        dr_backup._restore_config_members(tar, cfg, written=written)
    assert [p.name for p in written] == ["ok"]
    dr_backup._discard_partial_restore(None, written)
    assert list(cfg.iterdir()) == []
    dr_backup._refuse_existing_destination(None, cfg)


def test_a_directory_already_there_stays_out_of_the_ledger(tmp_path: Path) -> None:
    tar = _tar(tmp_path / "b.tar", [("config/sub/a.toml", b"a"), ("config/sub/deep/b.toml", b"b")])
    cfg = tmp_path / "bundle"
    (cfg / "sub").mkdir(parents=True)
    written: list[Path] = []
    assert dr_backup._restore_config_members(tar, cfg, written=written) == 2
    root = cfg.resolve()
    assert written == [
        root / "sub" / "a.toml",
        root / "sub" / "deep",
        root / "sub" / "deep" / "b.toml",
    ]


@pytest.mark.parametrize(
    "members",
    [
        [("config/a", b"file"), ("config/a/b.toml", b"x")],
        [("config/a", b"file"), ("config/a/b/c.toml", b"x")],
    ],
)
def test_a_member_under_a_file_is_still_the_collision_refusal(
    tmp_path: Path, members: list[tuple[str, bytes]]
) -> None:
    tar = _tar(tmp_path / "forged.tar", members)
    with pytest.raises(BackupError, match="collides with a member already extracted"):
        dr_backup._restore_config_members(tar, tmp_path / "bundle")
