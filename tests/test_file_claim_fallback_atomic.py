# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``_claim_unique`` copy fallback publishes only a finished file (BACKLOG #1622).

Where hard links are unavailable (FAT/exFAT, many SMB mounts), the fallback used to claim the FINAL
name with an empty ``O_EXCL`` file and then fill it in place. A downstream poller watching the drop
directory could pick up an empty or partial file under the final name, on exactly the filesystems
the fallback exists for. It now copies to a staging temp in the target directory and publishes that
finished file: by ``os.rename`` on Windows, by a second ``os.link`` where only the first was
cross-filesystem, and on POSIX-without-links by a placeholder renamed over at once.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import errno
import os
import shutil
from pathlib import Path
from typing import BinaryIO

import pytest

from messagefoundry.transports import file as file_mod
from messagefoundry.transports.file import _claim_unique

_PAYLOAD = bytes(range(256)) * 400  # 100 KiB, several copy chunks


def _no_hard_links(*_a: object, **_k: object) -> None:
    raise OSError("hard links unsupported on this filesystem")


def _drop(tmp_path: Path) -> tuple[Path, Path]:
    """A source file in its own directory, and the target directory it is published into."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    source = src_dir / "tmp.part"
    source.write_bytes(_PAYLOAD)
    return source, out_dir


@pytest.mark.parametrize("rename_refuses_overwrite", [True, False], ids=["windows", "posix"])
def test_the_final_name_does_not_exist_while_the_bytes_are_copied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rename_refuses_overwrite: bool
) -> None:
    """The measurement the finding made, kept as the regression test.

    A spy on ``copyfileobj`` looks at the final name as the copy begins. The pre-fix code had
    already created it there, empty (measured: size 0 at copy start, 100,000 bytes after).

    The Windows arm is driven only where ``os.rename`` really refuses to overwrite.

    Mutation: restore the ``O_EXCL`` create at the final name followed by the copy. Red: the final
    name exists at size 0 when the copy begins."""
    if rename_refuses_overwrite and os.name != "nt":
        pytest.skip("os.rename replaces silently off Windows")
    source, out_dir = _drop(tmp_path)
    final = out_dir / "msg.hl7"
    seen_at_copy_start: list[bool] = []
    real_copy = shutil.copyfileobj

    def spy(src: BinaryIO, dst: BinaryIO, *a: object, **k: object) -> None:
        seen_at_copy_start.append(final.exists())
        real_copy(src, dst, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(shutil, "copyfileobj", spy)
    monkeypatch.setattr(file_mod, "_RENAME_REFUSES_OVERWRITE", rename_refuses_overwrite)

    claimed = _claim_unique(source, final)

    assert seen_at_copy_start == [False], "the final name existed before its bytes were copied"
    assert claimed == final
    assert final.read_bytes() == _PAYLOAD
    assert sorted(p.name for p in out_dir.iterdir()) == ["msg.hl7"], "a staging temp was left"
    assert source.read_bytes() == _PAYLOAD  # the claim never consumes its source


@pytest.mark.skipif(os.name != "nt", reason="the rename arm is the Windows publish")
def test_the_windows_arm_never_opens_the_final_name_as_a_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows the file appears whole or not at all: no ``O_EXCL`` create at a final name.

    ``mkstemp`` itself opens its ``.part`` temp with ``O_EXCL``, so only non-temp names count.

    Mutation: route Windows through the POSIX placeholder arm. Red: ``msg.hl7`` is opened."""
    source, out_dir = _drop(tmp_path)
    exclusive_opens: list[str] = []
    real_open = os.open

    def spy(path: str | os.PathLike[str], flags: int, *a: object, **k: object) -> int:
        if flags & os.O_EXCL and not str(path).endswith(".part"):
            exclusive_opens.append(Path(path).name)
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(os, "open", spy)

    _claim_unique(source, out_dir / "msg.hl7")

    assert exclusive_opens == []


def test_the_posix_arm_bumps_past_taken_names_and_clobbers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The placeholder arm (POSIX without hard links) keeps the no-clobber claim: two taken names
    are stepped over, both survive, and neither a placeholder nor a staging temp is left.

    Driven on every platform through the module switch; ``os.replace`` over a placeholder we just
    created behaves the same on Windows.

    Mutation: rename the staged file with ``os.replace`` and no placeholder. Red: ``msg.hl7`` is
    overwritten."""
    source, out_dir = _drop(tmp_path)
    (out_dir / "msg.hl7").write_bytes(b"first winner")
    (out_dir / "msg-1.hl7").write_bytes(b"second winner")
    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(file_mod, "_RENAME_REFUSES_OVERWRITE", False)

    claimed = _claim_unique(source, out_dir / "msg.hl7")

    assert claimed.name == "msg-2.hl7"
    assert claimed.read_bytes() == _PAYLOAD
    assert (out_dir / "msg.hl7").read_bytes() == b"first winner"
    assert (out_dir / "msg-1.hl7").read_bytes() == b"second winner"
    assert sorted(p.name for p in out_dir.iterdir()) == ["msg-1.hl7", "msg-2.hl7", "msg.hl7"]


def test_a_failed_publish_removes_its_own_placeholder_and_staging_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the rename over the placeholder fails, the empty placeholder is ours: it must not stay at
    the final name, where a poller would take it for a delivered file.

    Mutation: drop the cleanup around ``os.replace``. Red: an empty ``msg.hl7`` is left behind."""
    source, out_dir = _drop(tmp_path)

    def _replace_fails(*_a: object, **_k: object) -> None:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(os, "replace", _replace_fails)
    monkeypatch.setattr(file_mod, "_RENAME_REFUSES_OVERWRITE", False)

    with pytest.raises(OSError, match="I/O error"):
        _claim_unique(source, out_dir / "msg.hl7")

    assert list(out_dir.iterdir()) == []


def test_a_cross_filesystem_source_is_published_by_link_from_the_staged_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The archive move across volumes: ``os.link`` fails only because the source is on another
    filesystem (EXDEV). The staged copy shares the target's directory, so a link from it succeeds
    and the publish stays a single atomic step on POSIX too.

    Mutation: skip the second link attempt. Red: the placeholder arm runs (``os.open`` sees an
    ``O_EXCL`` create at ``msg.hl7``)."""
    source, out_dir = _drop(tmp_path)
    real_link = os.link
    real_open = os.open
    exclusive_opens: list[str] = []

    def link_only_within_out(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if Path(src).parent != out_dir:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        real_link(src, dst)

    def spy(path: str | os.PathLike[str], flags: int, *a: object, **k: object) -> int:
        if flags & os.O_EXCL and not str(path).endswith(".part"):
            exclusive_opens.append(Path(path).name)
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "link", link_only_within_out)
    monkeypatch.setattr(os, "open", spy)
    monkeypatch.setattr(file_mod, "_RENAME_REFUSES_OVERWRITE", False)

    claimed = _claim_unique(source, out_dir / "msg.hl7")

    assert claimed == out_dir / "msg.hl7"
    assert claimed.read_bytes() == _PAYLOAD
    assert exclusive_opens == []
    assert sorted(p.name for p in out_dir.iterdir()) == ["msg.hl7"]
