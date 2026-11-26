# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which paths the config-source trust checks read (vault BACKLOG #2626 step 3, #2596 step 4).

The checks used to read the config directory and its ``*.py`` alone. A load also runs a matching
``__pycache__`` file in place of the source, and reads ``connections.toml`` and the code-set
tables, so a writer of any of those changed what ran while every vetted path stayed clean. These
tests pin the wider list and show a write grant on each new member refuses the load, on both arms.

The Windows tests replace the ctypes readers only, as ``tests/test_config_source_trust.py`` tier 3
does, so they run on every host. On win32 the suite's session fixture replaces the gate's own
call, so this module asks for it back.
"""

from __future__ import annotations

import errno
import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config import wiring
from messagefoundry.config.settings import (
    INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
    SECURITY_ENFORCEMENT_ENV,
)
from messagefoundry.config.wiring import WiringError, config_source_trust_paths, load_config

#: Everyone, the principal the ``fake_windows_readers`` fixture grants write to.
_EVERYONE = "S-1-1-0"

#: The ``fake_windows_readers`` fixture: a predicate naming the writable paths in, paths read out.
FakeReaders = Callable[[Callable[[Path], bool]], list[Path]]

pytestmark = pytest.mark.usefixtures("real_config_source_readers")

_CACHE_FILE = f"cfg.{sys.implementation.cache_tag}.pyc"

#: The trust-list members that are folders, so a link to one is a directory link.
_FOLDERS = frozenset({"codesets", "__pycache__"})


def _write_tree(directory: Path) -> None:
    """A config directory with every member the trust list names, and one it must not."""
    (directory / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    cache = directory / "__pycache__"
    cache.mkdir()
    (cache / _CACHE_FILE).write_bytes(b"")
    (directory / "connections.toml").write_text("", encoding="utf-8")
    codesets = directory / "codesets"
    codesets.mkdir()
    (codesets / "a.csv").write_text("code,display\n", encoding="utf-8")
    (codesets / "b.TOML").write_text("", encoding="utf-8")
    # The loader reads only .csv and .toml, so a note beside the tables is not on the list.
    (codesets / "README.md").write_text("notes\n", encoding="utf-8")


def test_the_list_names_the_cache_connections_and_code_sets(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    assert config_source_trust_paths(tmp_path) == [
        tmp_path,
        tmp_path / "cfg.py",
        tmp_path / "__pycache__",
        tmp_path / "__pycache__" / _CACHE_FILE,
        tmp_path / "connections.toml",
        tmp_path / "codesets",
        tmp_path / "codesets" / "a.csv",
        tmp_path / "codesets" / "b.TOML",
    ]


def test_a_bare_directory_lists_only_itself_and_its_modules(tmp_path: Path) -> None:
    """Control for the test above: the optional members appear only when they exist."""
    (tmp_path / "cfg.py").write_text("", encoding="utf-8")
    assert config_source_trust_paths(tmp_path) == [tmp_path, tmp_path / "cfg.py"]


def test_windows_reads_every_listed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    """Positive control for the refusals below: a clean read of the whole tree loads."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_tree(tmp_path)
    expected = config_source_trust_paths(tmp_path)
    seen = fake_windows_readers(lambda _path: False)
    # The empty cache file is not a valid .pyc, so the source loader recompiles cfg.py.
    assert "o" in load_config(tmp_path).outbound
    assert seen == expected


@pytest.mark.parametrize(
    "member", ["__pycache__", _CACHE_FILE, "connections.toml", "codesets", "a.csv"]
)
def test_windows_refuses_a_writable_member(
    member: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_windows_readers: FakeReaders,
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_tree(tmp_path)
    fake_windows_readers(lambda path: path.name == member)
    with pytest.raises(WiringError, match="writable-by-others path") as excinfo:
        load_config(tmp_path)
    assert member in str(excinfo.value)
    assert _EVERYONE in str(excinfo.value)


def test_the_escape_downgrades_a_writable_cache_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fake_windows_readers: FakeReaders,
) -> None:
    """The new members go through the same refusal, so the clamped escape covers them too."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "warn")
    _write_tree(tmp_path)
    fake_windows_readers(lambda path: path.name == _CACHE_FILE)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        assert "o" in load_config(tmp_path).outbound
    assert any(
        _CACHE_FILE in r.getMessage() and "dev/test override" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
@pytest.mark.parametrize(
    "relative",
    [Path("__pycache__") / _CACHE_FILE, Path("connections.toml"), Path("codesets") / "a.csv"],
)
def test_posix_refuses_a_group_writable_member(
    relative: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_tree(tmp_path)
    (tmp_path / relative).chmod(0o664)
    with pytest.raises(WiringError, match="group/world-writable path") as excinfo:
        load_config(tmp_path)
    assert str(tmp_path / relative) in str(excinfo.value)


# --- a module that is a link (vault BACKLOG #2596 added item 2) ------------------------------------


def _link_module_into(cfg: Path, shared: Path) -> Path:
    """``cfg/cfg.py`` as a symbolic link to ``shared/cfg.py``; skips where links cannot be made."""
    cfg.mkdir()
    shared.mkdir()
    target = shared / "cfg.py"
    target.write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    try:
        (cfg / "cfg.py").symlink_to(target)
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    return target


def test_a_linked_module_lists_its_target_and_the_target_folder(tmp_path: Path) -> None:
    cfg, shared = tmp_path / "cfg", tmp_path / "shared"
    target = _link_module_into(cfg, shared)
    listed = config_source_trust_paths(cfg)
    assert listed[:2] == [cfg, cfg / "cfg.py"]
    assert target.resolve() in listed
    assert target.resolve().parent in listed
    assert len(listed) == len(set(listed))


def test_windows_refuses_a_module_linked_into_a_writable_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg, shared = tmp_path / "cfg", tmp_path / "shared"
    target = _link_module_into(cfg, shared)
    writable = target.resolve().parent
    fake_windows_readers(lambda path: path == writable)
    with pytest.raises(WiringError, match="writable-by-others path") as excinfo:
        load_config(cfg)
    assert str(writable) in str(excinfo.value)


def test_windows_loads_a_linked_module_when_every_path_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    """Control for the test above: the link alone does not refuse."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg, shared = tmp_path / "cfg", tmp_path / "shared"
    target = _link_module_into(cfg, shared)
    seen = fake_windows_readers(lambda _path: False)
    assert "o" in load_config(cfg).outbound
    assert target.resolve() in seen


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_posix_refuses_a_module_linked_into_a_group_writable_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg, shared = tmp_path / "cfg", tmp_path / "shared"
    target = _link_module_into(cfg, shared)
    shared.chmod(0o775)
    with pytest.raises(WiringError, match="group/world-writable path") as excinfo:
        load_config(cfg)
    assert str(target.resolve().parent) in str(excinfo.value)


def _link_module_through_a_link(tmp_path: Path) -> tuple[Path, Path, Path]:
    """``cfg/cfg.py`` -> ``mid/cfg.py`` -> ``shared/cfg.py``: a link to a link. Returns the
    config directory, the folder holding the link in between, and the real module."""
    cfg, mid = tmp_path / "cfg", tmp_path / "mid"
    target = _link_module_into(cfg, tmp_path / "shared")
    mid.mkdir()
    (cfg / "cfg.py").unlink()
    try:
        (mid / "cfg.py").symlink_to(target)
        (cfg / "cfg.py").symlink_to(mid / "cfg.py")
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    return cfg, mid, target


def test_a_link_to_a_link_lists_the_folder_holding_the_link_in_between(tmp_path: Path) -> None:
    """Whoever can write ``mid`` can re-point the link in between, so it is vetted (vault BACKLOG
    #2596, step 4: the full link walk). A resolve() of the member skipped it."""
    cfg, mid, target = _link_module_through_a_link(tmp_path)
    listed = config_source_trust_paths(cfg)
    assert mid.resolve() in listed
    assert target.resolve() in listed and target.resolve().parent in listed
    if sys.platform == "win32":  # GetNamedSecurityInfoW reads a link's own list there
        assert mid.resolve() / "cfg.py" in listed


def test_windows_refuses_a_module_whose_link_in_between_sits_in_a_writable_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg, mid, _target = _link_module_through_a_link(tmp_path)
    writable = mid.resolve()
    fake_windows_readers(lambda path: path == writable)
    with pytest.raises(WiringError, match="writable-by-others path") as excinfo:
        load_config(cfg)
    assert str(writable) in str(excinfo.value)


def test_a_member_link_the_walk_cannot_follow_refuses_the_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    """A layout the link walk refuses, here one it cannot stat, refuses the load, and the dev/test
    escape does not downgrade it: nothing past that link was vetted."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg, _mid, _target = _link_module_through_a_link(tmp_path)
    fake_windows_readers(lambda _path: False)

    def unwalkable(path: Path) -> tuple[list[Path], Path | None]:
        raise OSError(errno.EIO, "synthetic: a name in the path could not be read")

    monkeypatch.setattr(wiring, "_link_chain", unwalkable)
    with pytest.raises(WiringError, match="could not be walked"):
        load_config(cfg)


def test_a_linked_config_directory_lists_the_real_directory(tmp_path: Path) -> None:
    """The real directory, and the folder holding the link to it, whose writer could re-point the
    link (vault BACKLOG #2596 step 4: the full link walk). The folder holding the real directory is
    not added, as the folders above the config directory are not."""
    real = tmp_path / "elsewhere" / "real"
    real.mkdir(parents=True)
    (real / "cfg.py").write_text("", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    link = home / "cfg"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    listed = config_source_trust_paths(link)
    assert listed[0] == link
    assert real.resolve() in listed
    assert home.resolve() in listed
    assert real.resolve().parent not in listed


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions")
def test_a_junction_member_lists_the_real_folder(tmp_path: Path) -> None:
    import _winapi

    cfg, shared = tmp_path / "cfg", tmp_path / "shared"
    cfg.mkdir()
    shared.mkdir()
    (cfg / "cfg.py").write_text("", encoding="utf-8")
    (shared / "a.csv").write_text("code,display\n", encoding="utf-8")
    vars(_winapi)["CreateJunction"](str(shared), str(cfg / "codesets"))  # not in linux stubs
    listed = config_source_trust_paths(cfg)
    assert cfg / "codesets" in listed
    assert shared.resolve() in listed


def test_a_link_that_cannot_be_resolved_refuses_the_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg, shared = tmp_path / "cfg", tmp_path / "shared"
    _link_module_into(cfg, shared)
    fake_windows_readers(lambda _path: False)
    real = Path.resolve

    def refusing(self: Path, strict: bool = False) -> Path:
        if self.name == "cfg.py" and self.parent.name == "cfg":
            raise ValueError("embedded null byte")
        return real(self, strict)

    monkeypatch.setattr(Path, "resolve", refusing)
    with pytest.raises(OSError, match="could not be resolved"):
        config_source_trust_paths(cfg)
    with pytest.raises(WiringError, match="could not be resolved"):
        load_config(cfg)


def test_a_dangling_module_link_refuses_the_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    # A writer of the folder it points into could create the missing file before the read.
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    try:
        (cfg / "cfg.py").symlink_to(tmp_path / "gone.py")
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    fake_windows_readers(lambda _path: False)
    with pytest.raises(OSError, match="leads to nothing"):
        config_source_trust_paths(cfg)
    with pytest.raises(WiringError, match="leads to nothing"):
        load_config(cfg)
    # Control: once the target exists, the same link loads.
    (tmp_path / "gone.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    assert "o" in load_config(cfg).outbound


@pytest.mark.parametrize(
    "member", ["connections.toml", "codesets", "codesets/a.csv", "__pycache__"]
)
def test_a_dangling_data_link_refuses_the_load(
    member: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_windows_readers: FakeReaders,
) -> None:
    # As for a module link: a writer of the folder it points into could create the missing name
    # before the read, so it is listed and refused rather than left off the list.
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    link = cfg / member
    link.parent.mkdir(exist_ok=True)
    target = tmp_path / "shared" / Path(member).name
    try:
        link.symlink_to(target, target_is_directory=member in _FOLDERS)
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    fake_windows_readers(lambda _path: False)
    with pytest.raises(OSError, match="leads to nothing"):
        config_source_trust_paths(cfg)
    # The refusal's text is cut to a length, so a long temporary path can hide the name.
    with pytest.raises(WiringError, match="leads to nothing"):
        load_config(cfg)
    # Control: once the target exists, the same link loads.
    target.parent.mkdir(exist_ok=True)
    if member in _FOLDERS:
        target.mkdir()
    elif member == "connections.toml":
        target.write_text("", encoding="utf-8")
    else:
        target.write_text("code,display\n", encoding="utf-8")
    assert "o" in load_config(cfg).outbound


@pytest.mark.parametrize(
    "member", ["connections.toml", "codesets", "codesets/a.csv", "__pycache__", "mod.py"]
)
def test_the_escape_does_not_downgrade_a_dangling_link(
    member: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fake_windows_readers: FakeReaders,
) -> None:
    """Nothing about what a dangling trust-list link leads to was vetted, so the honoured dev/test
    escape still refuses the load, as the serve start check does for a chain it cannot walk
    (Manager decision d20261121T195422910-02289f)."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "warn")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    link = cfg / member
    link.parent.mkdir(exist_ok=True)
    try:
        link.symlink_to(tmp_path / "gone", target_is_directory=member in _FOLDERS)
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    fake_windows_readers(lambda _path: False)
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"),
        pytest.raises(WiringError, match="leads to nothing"),
    ):
        load_config(cfg)
    assert not any(
        "leads to nothing" in r.getMessage() and "dev/test override" in r.getMessage()
        for r in caplog.records
    )


def test_a_dangling_link_refuses_under_enforce_with_the_escape_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    """Control for the test above: under enforce the escape is inert, and the link still refuses."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "enforce")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "cfg.py").write_text("", encoding="utf-8")
    try:
        (cfg / "connections.toml").symlink_to(tmp_path / "gone.toml")
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    fake_windows_readers(lambda _path: False)
    with pytest.raises(WiringError, match="leads to nothing"):
        load_config(cfg, allow_empty=True)


def test_a_dangling_config_directory_link_raises_whatever_refuse_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lax read lists the directory again and refuses one that is gone as missing, so the
    directory's own fault is raised rather than handed to the escape. The module listing is
    stubbed, as if the link lost its target after it ran."""
    link = tmp_path / "cfg"
    try:
        link.symlink_to(tmp_path / "gone", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    monkeypatch.setattr(wiring, "config_py_files", lambda _directory: [])
    handed: list[str] = []
    with pytest.raises(OSError, match="leads to nothing"):
        config_source_trust_paths(link, refuse=handed.append)
    assert handed == []
