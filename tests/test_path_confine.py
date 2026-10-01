# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The two-line confinement of a request-supplied path (vault BACKLOG #2581).

``confine`` is the check on ``POST /config/reload`` and ``POST /dr/activate``. Its first line is
``lexically_within``. These tests pin which strings the first line places under a root, that it
reaches that answer without a filesystem call on the string it was handed, and what only the
second line can see.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from messagefoundry.pipeline.path_confine import confine, lexical_roots, lexically_within
from tests import _fs_spy

_SHARE = _fs_spy.SHARE


def _confine(candidate: str | Path, root: Path) -> Path | None:
    """``confine`` against one root, given as the test made it and as it resolves."""
    resolved = root.resolve()
    return confine(
        candidate, lexical=lexical_roots([root, resolved]), resolved=[resolved], what="test path"
    )


def test_a_path_at_or_under_a_root_is_within(tmp_path: Path) -> None:
    root = tmp_path / "root"
    roots = lexical_roots([root])
    assert lexically_within(root, roots)
    assert lexically_within(root / "sub", roots)
    assert lexically_within(str(root / "sub" / "deeper"), roots)


def test_a_relative_path_is_anchored_at_the_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The same anchor the resolve that follows uses, so the two lines judge one path.
    roots = lexical_roots([tmp_path / "root"])
    monkeypatch.chdir(tmp_path)
    assert lexically_within(os.path.join("root", "sub"), roots)
    assert not lexically_within(os.path.join("elsewhere", "sub"), roots)
    assert not lexically_within(os.path.join("root", "..", "elsewhere"), roots)


def test_a_path_outside_every_root_is_not_within(tmp_path: Path) -> None:
    root = tmp_path / "root"
    roots = lexical_roots([root])
    assert not lexically_within(tmp_path / "elsewhere", roots)
    assert not lexically_within(tmp_path, roots)  # the parent of a root is not under it
    # A sibling that shares the root's text as a prefix is a different directory.
    assert not lexically_within(str(root) + "-sibling", roots)
    # `..` is collapsed before the comparison, so a climb out of the root is seen as outside.
    assert not lexically_within(root / "sub" / ".." / ".." / "elsewhere", roots)
    # The control for the climb: one that lands back inside the root is still within.
    assert lexically_within(root / "sub" / ".." / "other", roots)


def test_no_root_means_nothing_is_within(tmp_path: Path) -> None:
    assert not lexically_within(tmp_path, lexical_roots([]))


def test_any_one_of_several_roots_admits_a_path(tmp_path: Path) -> None:
    roots = lexical_roots([tmp_path / "a", tmp_path / "b"])
    assert lexically_within(tmp_path / "b" / "sub", roots)
    assert not lexically_within(tmp_path / "c" / "sub", roots)


@pytest.mark.parametrize("shape", _fs_spy.NON_LOCAL_SHAPES)
def test_a_share_or_device_path_is_not_within_a_local_root(tmp_path: Path, shape: str) -> None:
    assert not lexically_within(shape, lexical_roots([tmp_path / "root"]))


@pytest.mark.parametrize("shape", _fs_spy.NT_OBJECT_SHAPES)
def test_an_nt_object_path_is_never_within(shape: str) -> None:
    # Even a root spelled the same way admits nothing: the text and the open would disagree about
    # where this spelling points, so it is refused before any comparison.
    assert not lexically_within(shape, lexical_roots([shape]))
    assert not lexically_within(shape + "\\sub", lexical_roots([shape]))


@pytest.mark.parametrize("shape", _fs_spy.DEVICE_SHAPES)
def test_a_device_path_is_within_a_root_the_operator_spelled_that_way(shape: str) -> None:
    # The engine's own resolved startup dir can carry this prefix, and it must stay reloadable.
    # The row above is the other half: no ordinary root admits one.
    assert lexically_within(shape, lexical_roots([shape]))


@pytest.mark.skipif(os.name != "nt", reason="a share is a path anchor on Windows only")
def test_a_network_share_is_within_only_the_same_configured_share() -> None:
    roots = lexical_roots([_SHARE])
    assert lexically_within(_SHARE + "\\sub", roots)
    assert lexically_within(_SHARE.upper().replace("\\", "/") + "/sub", roots)  # case, separator
    other_share = _SHARE.replace("share", "share2")
    other_host = _SHARE.replace(_fs_spy.UNREACHABLE_HOST, "other." + _fs_spy.UNREACHABLE_HOST)
    assert not lexically_within(other_share + "\\sub", roots)
    assert not lexically_within(other_host + "\\sub", roots)
    # A climb cannot leave the share, and it does leave the configured directory.
    assert not lexically_within(_SHARE + "\\..\\other", roots)


@pytest.mark.skipif(os.name != "nt", reason="Windows folds case and accepts either separator")
def test_windows_case_and_separator_do_not_matter(tmp_path: Path) -> None:
    root = tmp_path / "Root"
    roots = lexical_roots([root])
    assert lexically_within(str(root / "Sub").upper(), roots)
    assert lexically_within(str(root / "sub").replace("\\", "/"), roots)


def test_a_refused_path_is_not_touched_and_an_admitted_one_is_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    (root / "probe-inside").mkdir(parents=True)
    calls = _fs_spy.install(monkeypatch)

    assert _confine(tmp_path / "probe-outside", root) is None
    for shape in _fs_spy.NON_LOCAL_SHAPES:
        assert _confine(shape, root) is None
    assert _fs_spy.naming(calls, "probe") == []

    # The control: the spy is armed. The admitted path IS resolved and recorded, so the empty list
    # above means the refused paths were not touched, not that the spy saw nothing.
    assert _confine(root / "probe-inside", root) == root.resolve() / "probe-inside"
    assert _fs_spy.naming(calls, "probe-inside")


def test_the_second_line_admits_a_root_and_what_resolves_under_it(tmp_path: Path) -> None:
    root = (tmp_path / "root").resolve()
    (root / "sub").mkdir(parents=True)
    assert _confine(root, root) == root
    assert _confine(root / "sub" / ".." / "sub", root) == root / "sub"
    assert _confine(root / "not-there-yet", root) == root / "not-there-yet"
    assert _confine(tmp_path / "elsewhere", root) is None


def test_only_the_second_line_sees_a_link_that_leaves_the_root(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = (tmp_path / "root").resolve()
    outside = (tmp_path / "outside").resolve()
    root.mkdir()
    outside.mkdir()
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create a symbolic link")
    assert lexically_within(link, lexical_roots([root]))  # the text is under the root
    with caplog.at_level("WARNING", logger="messagefoundry.pipeline.path_confine"):
        assert _confine(link, root) is None  # the target is not
    # The server-side log is the one place that says where the link led.
    assert str(outside) in caplog.text


def test_a_link_to_a_root_is_admitted_in_either_spelling(tmp_path: Path) -> None:
    # A root reached through a link: a request may spell it as configured or as it resolves.
    real = (tmp_path / "real").resolve()
    (real / "sub").mkdir(parents=True)
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create a symbolic link")
    assert _confine(alias / "sub", alias) == real / "sub"
    assert _confine(real / "sub", alias) == real / "sub"
