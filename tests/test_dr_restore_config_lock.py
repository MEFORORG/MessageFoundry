# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The config-bundle restore's stream-name refusal and its directory ledger (BACKLOG #5618).

A Windows restore must not write a member as an NTFS alternate data stream of another member. A
directory is in the rollback ledger from the moment it is created, so a failure part way down a
chain leaves the destination retryable."""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

import pytest

from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupError

_TOO_LONG = "c" * 300


def _tar(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with tarfile.open(path, "w") as tar:
        for name, body in members:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return path


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS alternate data streams are Windows-only")
@pytest.mark.parametrize(
    "stream",
    ["config/a.toml:evil", "config/a.toml::$DATA", "config/sub:x/b.toml", "config/sub/b:x.toml"],
)
def test_a_colon_member_is_refused_and_rolls_back_empty(tmp_path: Path, stream: str) -> None:
    tar = _tar(tmp_path / "forged.tar", [("config/a.toml", b"[a]\n"), (stream, b"hidden\n")])
    cfg = tmp_path / "bundle"
    written: list[Path] = []
    with pytest.raises(BackupError, match="unsafe config member name"):
        dr_backup._restore_config_members(tar, cfg, written=written)
    # Only the member before it was written, so the refusal came before this member's first write.
    assert written == [cfg.resolve() / "a.toml"]
    assert (cfg / "a.toml").read_bytes() == b"[a]\n"
    with pytest.raises(OSError):
        (cfg / "a.toml:evil").read_bytes()
    dr_backup._discard_partial_restore(None, written)
    assert list(cfg.iterdir()) == []


@pytest.mark.skipif(sys.platform != "win32", reason="the colon refusal runs on Windows only")
def test_a_hard_link_member_with_a_colon_is_refused(tmp_path: Path) -> None:
    tar_path = tmp_path / "forged.tar"
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo("config/a.toml")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"[a]\n"))
        link = tarfile.TarInfo("config/a.toml:evil")
        link.type = tarfile.LNKTYPE
        link.linkname = "config/a.toml"
        tar.addfile(link)
    with pytest.raises(BackupError, match="unsafe config member name"):
        dr_backup._restore_config_members(tar_path, tmp_path / "bundle")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX opens a colon name as itself")
def test_a_posix_restore_still_lands_a_colon_name(tmp_path: Path) -> None:
    tar = _tar(tmp_path / "bundle.tar", [("config/a:b.toml", b"x"), ("config/s:t/c.toml", b"y")])
    assert dr_backup._restore_config_members(tar, tmp_path / "bundle") == 2
    assert (tmp_path / "bundle" / "a:b.toml").read_bytes() == b"x"
    assert (tmp_path / "bundle" / "s:t" / "c.toml").read_bytes() == b"y"


@pytest.mark.parametrize("rel", ["aux.py", "con.toml", "com1.txt", "sub/aux.py", "dot.", "sp "])
def test_names_outside_the_colon_rule_behave_as_the_platform_does(tmp_path: Path, rel: str) -> None:
    # This change refuses colons alone. Whatever the host does with these, it is not this refusal.
    tar = _tar(tmp_path / "bundle.tar", [(f"config/{rel}", b"x")])
    try:
        dr_backup._restore_config_members(tar, tmp_path / "bundle")
    except BackupError as exc:
        assert "unsafe config member name" not in str(exc)


def test_a_failed_mkdir_chain_rolls_back_and_the_retry_runs(tmp_path: Path) -> None:
    bad = _tar(
        tmp_path / "bad.tar",
        [("config/ok.toml", b"ok"), (f"config/a/b/{_TOO_LONG}/x.toml", b"x")],
    )
    cfg = tmp_path / "bundle"
    written: list[Path] = []
    with pytest.raises(BackupError):
        dr_backup._restore_config_members(bad, cfg, written=written)
    root = cfg.resolve()
    assert written == [root / "ok.toml", root / "a", root / "a" / "b"]  # creation order
    dr_backup._discard_partial_restore(None, written)
    assert list(cfg.iterdir()) == []

    dr_backup._refuse_existing_destination(None, cfg)  # the retry's own non-empty refusal
    good = _tar(tmp_path / "good.tar", [("config/a/b/x.toml", b"x")])
    assert dr_backup._restore_config_members(good, cfg) == 1


def test_a_directory_already_there_is_not_recorded(tmp_path: Path) -> None:
    cfg = tmp_path / "bundle"
    (cfg / "kept").mkdir(parents=True)
    bad = _tar(tmp_path / "bad.tar", [(f"config/kept/new/{_TOO_LONG}/x.toml", b"x")])
    written: list[Path] = []
    with pytest.raises(BackupError):
        dr_backup._restore_config_members(bad, cfg, written=written)
    assert written == [cfg.resolve() / "kept" / "new"]
    dr_backup._discard_partial_restore(None, written)
    assert [p.name for p in cfg.iterdir()] == ["kept"]
    assert list((cfg / "kept").iterdir()) == []


@pytest.mark.parametrize("child", ["a/b.toml", "a/b/c/d.toml"])
def test_a_parent_that_is_a_file_keeps_its_collision_refusal(tmp_path: Path, child: str) -> None:
    tar = _tar(tmp_path / "forged.tar", [("config/a", b"file"), (f"config/{child}", b"x")])
    written: list[Path] = []
    with pytest.raises(BackupError, match="collides with a member already extracted"):
        dr_backup._restore_config_members(tar, tmp_path / "bundle", written=written)
    assert written == [(tmp_path / "bundle").resolve() / "a"]
