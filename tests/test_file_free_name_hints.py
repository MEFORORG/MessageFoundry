# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2766: claiming a free name for a recurring file name stays linear.

``_free_names`` used to walk ``name-1``, ``name-2`` and on from 1 on every claim, so the Nth claim of
one name paid N failed links or renames. It now starts above the highest suffix a claim has found
taken for that target. These tests count the filesystem attempts per claim, and check the claim stays unique when
something else holds the name the hint points at.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.transports import file as file_mod
from messagefoundry.transports.file import (
    _claim_staged,
    _free_names,
    _link_free_name,
    _publish_staged,
)

_CLAIMS = 40


@pytest.fixture(autouse=True)
def _fresh_hints(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts with no remembered suffixes and leaves none behind for other tests."""
    monkeypatch.setattr(file_mod, "_free_name_hints", type(file_mod._free_name_hints)())


def _count_links(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    real = os.link

    def counting(src: Any, dst: Any, **kw: Any) -> None:
        calls.append(os.fspath(dst))
        real(src, dst, **kw)

    monkeypatch.setattr(os, "link", counting)
    return calls


def test_each_link_claim_of_a_recurring_name_costs_a_bounded_number_of_tries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src.hl7"
    source.write_bytes(b"MSH|")
    out = tmp_path / "out"
    out.mkdir()
    target = out / "ADT.hl7"
    calls = _count_links(monkeypatch)
    claimed: list[str] = []
    for _ in range(_CLAIMS):
        before = len(calls)
        got = _link_free_name(source, target)
        assert got is not None
        claimed.append(got.name)
        # The bare name, the suffix the last claim took, the next one: never a walk over them all.
        assert len(calls) - before <= 3
    assert len(set(claimed)) == _CLAIMS  # every claim got its own name
    assert claimed[:3] == ["ADT.hl7", "ADT-1.hl7", "ADT-2.hl7"]  # numbering is unchanged
    assert claimed[-1] == f"ADT-{_CLAIMS - 1}.hl7"


def test_each_publish_of_a_recurring_name_costs_a_bounded_number_of_tries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rename and placeholder path, which delivery takes where links are unusable."""
    target = tmp_path / "message.hl7.hl7"
    offered: list[Path] = []
    real = file_mod._free_names

    def recording(t: Path) -> Any:
        for candidate in real(t):
            offered.append(candidate)
            yield candidate

    monkeypatch.setattr(file_mod, "_free_names", recording)
    for n in range(_CLAIMS):
        staged = tmp_path / f"staged{n}.part"
        staged.write_bytes(b"x")
        before = len(offered)
        _publish_staged(staged, target)
        assert len(offered) - before <= 3
    assert len(list(tmp_path.glob("message.hl7*.hl7"))) == _CLAIMS


def test_a_name_taken_behind_the_hint_is_skipped_never_clobbered(tmp_path: Path) -> None:
    """The hint is only where the walk starts. Another writer holding the next suffix costs one more
    try, and its file is left as it was."""
    source = tmp_path / "src.hl7"
    source.write_bytes(b"ours")
    target = tmp_path / "out.hl7"
    assert _link_free_name(source, target) == target
    assert _link_free_name(source, target) == tmp_path / "out-1.hl7"
    (tmp_path / "out-2.hl7").write_bytes(b"someone else")
    assert _link_free_name(source, target) == tmp_path / "out-3.hl7"
    assert (tmp_path / "out-2.hl7").read_bytes() == b"someone else"


def test_a_freed_bare_name_is_claimed_again(tmp_path: Path) -> None:
    """The bare name is always tried first, whatever the hint says."""
    target = tmp_path / "out.hl7"
    target.write_bytes(b"x")
    names = _free_names(target)
    assert next(names) == target
    assert next(names) == tmp_path / "out-1.hl7"
    target.unlink()
    assert next(_free_names(target)) == target


def test_the_hint_memory_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_mod, "_FREE_NAME_HINTS_MAX", 3)
    for n in range(10):
        names = _free_names(tmp_path / f"n{n}.hl7")
        next(names)
        next(names)
        next(names)  # resuming past name-1 is what records it as taken
    assert len(file_mod._free_name_hints) == 3


def test_a_suffix_offered_but_not_found_taken_is_not_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where a hard link cannot be made (vfat, exFAT, another volume), the link path gives up on a
    free suffix and the copy fallback walks again. Only a suffix found TAKEN advances the hint, so
    the fallback claims the suffix the link path gave up on, and the numbering has no gaps."""

    def link_unusable(src: Any, dst: Any, **kw: Any) -> None:
        if os.path.lexists(dst):
            raise FileExistsError(dst)  # Linux checks the target before the filesystem's support
        raise PermissionError("links are not supported here")

    monkeypatch.setattr(os, "link", link_unusable)
    target = tmp_path / "ADT.hl7"
    claimed = []
    for n in range(5):
        staged = tmp_path / f"staged{n}.part"
        staged.write_bytes(b"x")
        claimed.append(_claim_staged(staged, target).name)
    assert claimed == ["ADT.hl7", "ADT-1.hl7", "ADT-2.hl7", "ADT-3.hl7", "ADT-4.hl7"]


def test_an_overtaken_walk_jumps_to_the_shared_hint(tmp_path: Path) -> None:
    """A claim re-reads the hint before each try, so one that other claims overtook does not walk
    through every suffix they took."""
    target = tmp_path / "out.hl7"
    slow = _free_names(target)
    assert next(slow) == target
    assert next(slow) == tmp_path / "out-1.hl7"
    with file_mod._free_name_hints_lock:
        file_mod._free_name_hints[str(target)] = 50  # other claims took up to out-50 meanwhile
    assert next(slow) == tmp_path / "out-51.hl7"
