# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a failed ``--out`` write leaves behind, as ``_write_owner_only``'s docstring states it
(vault BACKLOG #3166, PR 2390 note 18).

The docstring said "A failed write leaves no temp file". That holds only while removing the temp
file works. When the removal fails too, the temp file stays beside the target, and these tests pin
that, with a control where the removal works. Nothing here is a capture: the text is made up.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

import tee.__main__ as tee_main


def _fail_the_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("replace refused")

    # The writer calls os.replace through the module object, so patching it there reaches it.
    monkeypatch.setattr(os, "replace", refuse)


def _temps(folder: Path, name: str) -> list[Path]:
    return sorted(folder.glob(f".{name}.*.tmp"))


def test_a_failed_removal_leaves_the_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.txt"
    _fail_the_replace(monkeypatch)

    def refuse_unlink(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(f"unlink refused: {self.name}")

    monkeypatch.setattr(Path, "unlink", refuse_unlink)
    with pytest.raises(OSError):
        # False takes os.replace on every platform, so one failure point serves both.
        tee_main._write_owner_only(str(target), "made-up\n", in_place_on_windows=False)
    monkeypatch.undo()
    left = _temps(tmp_path, target.name)
    assert len(left) == 1, left
    assert not target.exists()


def test_control_a_failed_write_whose_removal_works_leaves_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.txt"
    _fail_the_replace(monkeypatch)
    with pytest.raises(OSError, match="replace refused"):
        tee_main._write_owner_only(str(target), "made-up\n", in_place_on_windows=False)
    monkeypatch.undo()
    assert _temps(tmp_path, target.name) == []
    assert not target.exists()


def test_the_docstring_states_the_leftover() -> None:
    doc = " ".join((inspect.getdoc(tee_main._write_owner_only) or "").split())
    assert "leaves no temp file" not in doc
    assert "unless that removal fails too" in doc
