# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The serve start check on the files outside the config tree (vault BACKLOG #2626 step 3).

``serve`` reads a settings file and a value file from outside the config directory, and runs code
from an interpreter and a package nothing checked. The settings file and the value file now get
the config-source policy at start, and a start whose file another account could write is refused,
with the same clamped escape as a config refusal. The interpreter and the package are read by the
same policy and reported, never refused: ``wiring.untrusted_install_paths`` says why.

The unit tests hand the Windows arm fake readers, as ``tests/test_config_source_trust.py`` tier 3
does, so they run on every host. The ``serve`` tests change a real permission: a mode on POSIX,
an ``icacls`` grant on Windows.
"""

from __future__ import annotations

import errno
import functools
import logging
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import (
    INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
    SECURITY_ENFORCEMENT_ENV,
)
from messagefoundry.config.wiring import (
    WiringError,
    _file_and_folder,
    assert_trusted_start_paths,
    install_trust_paths,
    untrusted_install_paths,
)

#: The ``fake_windows_readers`` fixture: a predicate naming the writable paths in, paths read out.
FakeReaders = Callable[[Callable[[Path], bool]], list[Path]]

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


@pytest.fixture
def no_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)


def _two_files(tmp_path: Path) -> tuple[Path, Path]:
    settings = tmp_path / "messagefoundry.toml"
    settings.write_text("", encoding="utf-8")
    values = tmp_path / "environments" / "dev.toml"
    values.parent.mkdir()
    values.write_text("", encoding="utf-8")
    return settings, values


def test_each_file_is_read_with_its_folder_and_a_missing_one_is_skipped(tmp_path: Path) -> None:
    settings, values = _two_files(tmp_path)
    assert _file_and_folder([settings, values, tmp_path / "absent.toml"]) == [
        settings,
        tmp_path,
        values,
        values.parent,
    ]


@pytest.mark.usefixtures("no_escape")
def test_a_clean_read_passes_and_reads_every_path(
    tmp_path: Path, fake_windows_readers: FakeReaders
) -> None:
    """Positive control for the refusals below."""
    settings, values = _two_files(tmp_path)
    seen = fake_windows_readers(lambda _path: False)
    assert_trusted_start_paths([settings, values])
    assert seen == [settings, tmp_path, values, values.parent]


@pytest.mark.usefixtures("no_escape")
@pytest.mark.parametrize("which", ["settings", "settings folder", "values", "values folder"])
def test_a_writable_file_or_folder_refuses_the_start(
    which: str, tmp_path: Path, fake_windows_readers: FakeReaders
) -> None:
    settings, values = _two_files(tmp_path)
    writable = {
        "settings": settings,
        "settings folder": tmp_path,
        "values": values,
        "values folder": values.parent,
    }[which]
    fake_windows_readers(lambda path: path == writable)
    with pytest.raises(WiringError, match="refusing to start from writable-by-others path") as exc:
        assert_trusted_start_paths([settings, values])
    assert str(writable) in str(exc.value)


def test_the_escape_downgrades_the_refusal_under_warn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fake_windows_readers: FakeReaders,
) -> None:
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "warn")
    settings, values = _two_files(tmp_path)
    fake_windows_readers(lambda path: path == values)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        assert_trusted_start_paths([settings, values])
    assert any(str(values) in r.getMessage() for r in caplog.records)


def test_the_escape_is_refused_under_enforce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)
    settings, values = _two_files(tmp_path)
    fake_windows_readers(lambda path: path == values)
    with pytest.raises(WiringError, match="is set but not honoured"):
        assert_trusted_start_paths([settings, values])


def test_the_install_list_names_the_interpreter_and_the_package() -> None:
    import messagefoundry

    paths = install_trust_paths()
    package = Path(messagefoundry.__file__).resolve().parent
    assert Path(sys.executable) in paths
    assert Path(sys.executable).parent in paths
    assert package in paths
    assert package / "__init__.py" in paths


@pytest.mark.usefixtures("no_escape")
def test_a_writable_install_is_reported_and_never_refused(
    fake_windows_readers: FakeReaders,
) -> None:
    """Under enforce, with no escape, the reading still returns rather than raising."""
    import messagefoundry

    package = Path(messagefoundry.__file__).resolve().parent
    fake_windows_readers(lambda path: path == package)
    reasons = untrusted_install_paths()
    assert len(reasons) == 1
    assert str(package) in reasons[0]
    assert reasons[0].startswith("the engine runs code from writable-by-others path")


@pytest.mark.usefixtures("no_escape")
def test_a_clean_install_reports_nothing(fake_windows_readers: FakeReaders) -> None:
    fake_windows_readers(lambda _path: False)
    assert untrusted_install_paths() == []


# --- serve ---------------------------------------------------------------------------------------

#: What a real refusal at start says. Each platform's arm names the defect in its own words: the
#: Windows arm reads an access list, and the POSIX arm reads a mode, which it prints.
_START_REFUSAL = "refusing to start from " + (
    "writable-by-others path" if sys.platform == "win32" else "group/world-writable path"
)


def _grant_others_write(path: Path) -> None:
    """Give a broad principal write on ``path`` for real, by the platform's own means."""
    if sys.platform != "win32":
        path.chmod(0o666)
        return
    # *S-1-5-11 = Authenticated Users; M = Modify.
    proc = subprocess.run(
        ["icacls", str(path), "/grant", "*S-1-5-11:M"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"icacls grant failed: {proc.stdout}{proc.stderr}"


def _start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    *extra: str,
) -> int:
    """Run ``command`` (``serve`` or ``supervise``) over the sample config with nothing served."""
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    # The start-up code reading is not under test here; the dev venv may carry unrecorded items.
    monkeypatch.setattr("messagefoundry.startupcode.startup_refusal", lambda _posture: None)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main([command, "--config", str(_SAMPLES_CONFIG), "--env", "dev", *extra])


def _serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> int:
    return _start(tmp_path, monkeypatch, "serve", *extra)


@pytest.mark.usefixtures("no_escape", "real_config_source_readers")
def test_serve_refuses_a_value_file_others_can_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _settings, values = _two_files(tmp_path)
    (tmp_path / "messagefoundry.toml").unlink()
    _grant_others_write(values)
    assert _serve(tmp_path, monkeypatch) == 2
    err = capsys.readouterr().err
    assert _START_REFUSAL in err
    assert str(values) in err
    # Before any side effect: nothing was minted or opened in the working directory.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["environments"]


@pytest.mark.usefixtures("no_escape", "real_config_source_readers")
def test_serve_refuses_a_settings_file_others_can_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings_dir = tmp_path / "settings"
    settings_dir.mkdir()
    settings = settings_dir / "service.toml"
    settings.write_text("", encoding="utf-8")
    _grant_others_write(settings)
    assert _serve(tmp_path, monkeypatch, "--service-config", str(settings)) == 2
    err = capsys.readouterr().err
    assert _START_REFUSAL in err
    assert str(settings) in err


@pytest.mark.usefixtures("no_escape")
def test_serve_does_not_refuse_a_clean_value_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control for the refusals above: the same start with a clean file. It may stop at some
    later gate; it must not stop at this one."""
    _two_files(tmp_path)
    _serve(tmp_path, monkeypatch)
    assert "refusing to start from" not in capsys.readouterr().err


@pytest.mark.usefixtures("no_escape", "real_config_source_readers")
def test_serve_vets_the_default_settings_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With no --service-config, the file checked is the ./messagefoundry.toml the load read."""
    settings = tmp_path / "messagefoundry.toml"
    settings.write_text("", encoding="utf-8")
    _grant_others_write(settings)
    assert _serve(tmp_path, monkeypatch) == 2
    err = capsys.readouterr().err
    assert _START_REFUSAL in err
    assert str(settings) in err


@pytest.mark.usefixtures("no_escape", "real_config_source_readers")
def test_supervise_refuses_a_value_file_others_can_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``supervise`` makes the same check before it spawns, so a file that would refuse every
    engine shard does not leave the supervisor restarting them."""
    _settings, values = _two_files(tmp_path)
    (tmp_path / "messagefoundry.toml").unlink()
    _grant_others_write(values)
    assert _start(tmp_path, monkeypatch, "supervise") == 2
    err = capsys.readouterr().err
    assert _START_REFUSAL in err
    assert str(values) in err
    assert "refusing to start the fleet" in err


@pytest.mark.usefixtures("no_escape", "real_config_source_readers")
def test_each_read_of_the_value_file_vets_it_again(tmp_path: Path) -> None:
    """``serve``'s value provider runs again on every reload, so each read checks the file again.
    A file made writable after a clean start is refused at its next read, as a WiringError, which
    the reload route answers in its audited arm."""
    from messagefoundry.__main__ import _read_environment_values

    _settings, values = _two_files(tmp_path)
    read = functools.partial(
        _read_environment_values,
        base_dir=tmp_path,
        dir_name="environments",
        environment="dev",
    )
    assert read() == {}  # control: the same read, before the grant, passes

    _grant_others_write(values)
    with pytest.raises(WiringError, match="refusing to read environment values from") as exc:
        read()
    assert str(values) in str(exc.value)


# --- a stat fault, and the links a value file is reached through (vault BACKLOG #6654) -----------


def _stat_fault(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make every stat of ``target`` fail with access denied, as a folder this account cannot
    traverse does: ``os.stat`` raises, and ``os.path.isdir`` and ``os.path.isfile``, which
    ``Path.is_dir`` and ``Path.is_file`` call, answer ``False`` as they do for that fault."""

    def _same(path: Any) -> bool:
        return os.path.normcase(os.fspath(path)) == os.path.normcase(os.fspath(target))

    real_stat = os.stat

    def _stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if _same(path):
            raise PermissionError(errno.EACCES, "access denied", os.fspath(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _stat)
    for name in ("isdir", "isfile"):
        real = getattr(os.path, name)
        monkeypatch.setattr(os.path, name, lambda p, _real=real: False if _same(p) else _real(p))


@pytest.mark.usefixtures("no_escape")
@pytest.mark.parametrize("kind", ["folder", "file"])
def test_a_path_a_stat_cannot_reach_refuses_rather_than_vetting_nothing(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    """Items 2 and 17: ``Path.is_dir`` and ``Path.is_file`` answer ``False`` for a path they cannot
    stat, so the start check vetted nothing there, though the read that followed could reach it."""
    settings, values = _two_files(tmp_path)
    seen = fake_windows_readers(lambda _path: False)
    files, folders = ([settings], [values.parent]) if kind == "folder" else ([values], [])
    faulted = values.parent if kind == "folder" else values
    assert_trusted_start_paths(files, folders=folders)  # control: reachable, it is vetted
    assert faulted in seen

    _stat_fault(monkeypatch, faulted)
    with pytest.raises(WiringError, match="could not vet it") as exc:
        assert_trusted_start_paths(files, folders=folders)
    assert str(faulted) in str(exc.value)


def test_an_absent_file_or_folder_is_still_skipped(tmp_path: Path) -> None:
    """The control for the refusal above: nothing there is no fault, because nothing is read."""
    assert _file_and_folder([tmp_path / "absent.toml"], [tmp_path / "gone"]) == []


def _link(link: Path, target: Path, *, folder: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=folder)
    except OSError:
        pytest.skip("this account cannot create a link")


def _norm(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _same_paths(paths: list[Path]) -> set[str]:
    return {_norm(p) for p in paths}


@pytest.mark.usefixtures("no_escape")
def test_a_value_file_link_vets_the_folder_and_file_it_leads_to(
    tmp_path: Path, fake_windows_readers: FakeReaders
) -> None:
    """Item 5: a value file in ``environments/`` that is a link was vetted as the link and its
    folder only, so the folder the bytes came from was never vetted."""
    values = tmp_path / "cfg" / "environments" / "dev.toml"
    values.parent.mkdir(parents=True)
    real = tmp_path / "elsewhere" / "dev.toml"
    real.parent.mkdir()
    real.write_text("", encoding="utf-8")
    _link(values, real)
    seen = fake_windows_readers(lambda _path: False)
    assert_trusted_start_paths([values], folders=[values.parent])
    vetted = _same_paths(seen)
    assert _norm(real.parent) in vetted
    assert _norm(real) in vetted
    assert {_norm(values), _norm(values.parent)} <= vetted

    fake_windows_readers(lambda path: _norm(path) == _norm(real.parent))
    with pytest.raises(WiringError, match="writable-by-others path"):
        assert_trusted_start_paths([values], folders=[values.parent])


@pytest.mark.usefixtures("no_escape")
def test_a_folder_link_in_the_path_vets_the_folder_holding_it(
    tmp_path: Path, fake_windows_readers: FakeReaders
) -> None:
    """Item 5: a folder link in the value file's path was resolved, not walked, so whoever could
    write the folder holding it could re-point it unvetted; on Windows the link itself too."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    store = tmp_path / "store" / "envs"
    store.mkdir(parents=True)
    (store / "dev.toml").write_text("", encoding="utf-8")
    linked = cfg / "environments"
    _link(linked, store, folder=True)
    values = linked / "dev.toml"
    seen = fake_windows_readers(lambda _path: False)
    assert_trusted_start_paths([values], folders=[values.parent])
    vetted = _same_paths(seen)
    assert {_norm(cfg), _norm(linked), _norm(store), _norm(store / "dev.toml")} <= vetted
    assert _norm(tmp_path) not in vetted  # a folder above, holding no link, is not

    fake_windows_readers(lambda path: _norm(path) == _norm(cfg))
    with pytest.raises(WiringError, match="writable-by-others path"):
        assert_trusted_start_paths([values])


@pytest.mark.usefixtures("no_escape")
def test_a_relative_link_reached_through_a_folder_link_names_the_real_folder(
    tmp_path: Path,
) -> None:
    """A relative link target names a path from the real folder holding the link. Joined as text
    to a folder reached through a folder link, its ``..`` collapses on Windows to a decoy folder
    beside that folder link, so the real folder would go unvetted."""
    from messagefoundry.config.wiring import _link_chain

    real = tmp_path / "real" / "c"
    real.mkdir(parents=True)
    hop_dir = tmp_path / "real" / "x"
    hop_dir.mkdir()
    final = tmp_path / "final" / "values.toml"
    final.parent.mkdir()
    final.write_text("", encoding="utf-8")
    decoy = tmp_path / "a" / "x"
    decoy.mkdir(parents=True)
    (decoy / "g.toml").write_text("", encoding="utf-8")
    linked = tmp_path / "a" / "b"
    _link(linked, real, folder=True)
    _link(real / "f.toml", Path("..") / "x" / "g.toml")
    _link(hop_dir / "g.toml", final)
    chain, end = _link_chain(linked / "f.toml")
    names = _same_paths(chain)
    assert {_norm(linked.parent), _norm(real), _norm(hop_dir)} <= names
    assert _norm(decoy) not in names
    assert end is not None and _norm(end) == _norm(final)


def test_a_link_the_walk_cannot_stat_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item 5: ``os.path.islink`` answers ``False`` for a path it cannot stat, so a fault ended the
    walk early and left the folders past it unvetted."""
    values = tmp_path / "environments" / "dev.toml"
    values.parent.mkdir()
    real = tmp_path / "elsewhere" / "dev.toml"
    real.parent.mkdir()
    real.write_text("", encoding="utf-8")
    _link(values, real)
    real_lstat = os.lstat

    def _lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if _norm(Path(path)) == _norm(values):
            raise PermissionError(errno.EACCES, "access denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", _lstat)
    with pytest.raises(WiringError, match="could not vet it"):
        _file_and_folder([values])


def _linked_value_file(tmp_path: Path) -> tuple[Path, Path]:
    """``environments/dev.toml``, a link to ``elsewhere/dev.toml``, which is created."""
    values = tmp_path / "environments" / "dev.toml"
    values.parent.mkdir()
    real = tmp_path / "elsewhere" / "dev.toml"
    real.parent.mkdir()
    real.write_text("", encoding="utf-8")
    _link(values, real)
    return values, real


def test_a_dangling_value_file_link_vets_the_folder_it_leads_to(tmp_path: Path) -> None:
    """Whoever can write the folder a dangling link leads to can create the file before a read.
    The removed reload walk vetted that folder; a start check skipping the absent file must too."""
    values, real = _linked_value_file(tmp_path)
    real.unlink()
    vetted = _same_paths(_file_and_folder([values]))
    assert {_norm(real.parent), _norm(values.parent)} <= vetted
    # The control: an absent file no link leads to adds nothing, its folder included.
    assert _file_and_folder([tmp_path / "environments" / "absent.toml"]) == []


def test_a_link_past_the_hop_limit_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import messagefoundry.config.wiring as wiring

    values, real = _linked_value_file(tmp_path)
    middle = tmp_path / "elsewhere" / "middle.toml"
    _link(middle, real)
    values.unlink()
    _link(values, middle)
    assert _norm(real.parent) in _same_paths(_file_and_folder([values]))  # control: two hops pass
    monkeypatch.setattr(wiring, "_LINK_HOPS", 1)
    with pytest.raises(WiringError, match="more than 1 links"):
        _file_and_folder([values])


def test_the_hop_bound_is_past_every_platform_s_own() -> None:
    """A chain the open follows is never refused for its length alone: Windows follows 63 links,
    and the bound was 40, anchor_path's, before (#6654 review)."""
    import messagefoundry.config.wiring as wiring

    assert wiring._LINK_HOPS >= 63


@pytest.mark.parametrize(
    "target",
    [
        r"\\.\C:\real",  # a normalized device prefix: Win32 rewrites the rest before the open
        r"\\.\C:\..\UNC\host\share",  # its ``..`` climbs out of the drive, onto a share
        "//?/C:/real",  # a verbatim prefix written with forward slashes is not verbatim
        r"\\?/C:\real",  # nor is one with a single forward slash in it
        r"\\?\C:/real",  # a verbatim path holding a ``/``
    ],
)
def test_a_link_target_the_anchor_walk_refuses_is_refused_by_the_config_walk(target: str) -> None:
    """A link target the anchor walk refuses as a device path (``anchor_path._strip_nt_target``)
    is refused here too, rather than normalized and walked as a local path the open may not reach
    (BACKLOG #5515, engine PR 2999's left list). Pure text, so it runs on every leg."""
    from messagefoundry.config.wiring import _windows_link_target

    with pytest.raises(OSError, match="device path"):
        _windows_link_target(target)


@pytest.mark.parametrize(
    ("target", "plain"),
    [
        (r"\??\C:\real", r"C:\real"),
        (r"\\?\C:\real", r"C:\real"),
        (r"\\?\UNC\host\share\x", r"\\host\share\x"),
        (r"C:\real", r"C:\real"),
    ],
)
def test_a_plain_verbatim_link_target_is_still_walked(target: str, plain: str) -> None:
    """The control for the test above: an all-backslash verbatim target naming no ``.`` or ``..``
    is the same object as its stripped spelling, and is walked as before."""
    from messagefoundry.config.wiring import _windows_link_target

    assert _windows_link_target(target) == plain


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 strips a trailing dot or space")
@pytest.mark.parametrize("suffix", [".", " "])
def test_a_link_target_ending_in_a_dot_or_space_refuses(suffix: str, tmp_path: Path) -> None:
    """Win32 strips a trailing dot or space where a link's target, opened as written, keeps it, so
    the walk vetted ``vals`` while the open read ``vals.`` (round-531bdffe4b finding 1)."""
    data = tmp_path / "data"
    data.mkdir()
    (data / "vals").write_text("", encoding="utf-8")
    values = tmp_path / "dev.toml"
    try:
        os.symlink(f"data\\vals{suffix}", values)
    except OSError:
        pytest.skip("this account cannot create a file link")
    with pytest.raises(WiringError, match="ends in a space or a dot"):
        _file_and_folder([values])


@pytest.mark.skipif(sys.platform != "win32", reason="a drive-like name restarts an ntpath join")
def test_a_name_holding_a_colon_after_a_folder_link_refuses(tmp_path: Path) -> None:
    """``os.path.join(target, "a:b")`` restarts at ``a:``, so the walk vetted ``a:\\`` and never
    the folder the open reads a stream from (round-531bdffe4b finding 2)."""
    real = tmp_path / "realdir"
    real.mkdir()
    (real / "a").write_text("", encoding="utf-8")
    flink = tmp_path / "flink"
    _link(flink, real, folder=True)
    with pytest.raises(WiringError, match="holds a colon"):
        _file_and_folder([Path(f"{flink}\\a:b")])


def test_a_reparse_point_the_walk_cannot_follow_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A name surrogate other than a symbolic link or a junction stands for another path the walk
    cannot read, so the folders around that path would go unvetted."""
    import stat as stat_module
    from types import SimpleNamespace

    values, _real = _linked_value_file(tmp_path)
    real_lstat = os.lstat

    def _lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if _norm(Path(path)) == _norm(values.parent):
            # A WSL symbolic link's tag: a name surrogate (bit 0x20000000).
            return SimpleNamespace(st_mode=stat_module.S_IFDIR, st_reparse_tag=0xA000001D)
        return real_lstat(path, *args, **kwargs)

    _file_and_folder([values])  # control: the real walk passes
    monkeypatch.setattr(os, "lstat", _lstat)
    with pytest.raises(WiringError, match="reparse point"):
        _file_and_folder([values])


@pytest.mark.skipif(sys.platform != "win32", reason="a junction is a Windows link")
def test_a_junction_in_the_path_vets_the_folder_holding_it(tmp_path: Path) -> None:
    """``mklink /J`` needs no privilege, so a junction is the commonest Windows folder link; it
    takes the reparse-tag arm, not the symbolic-link one."""
    import _winapi

    winapi: Any = _winapi  # typeshed declares CreateJunction for win32 only

    cfg = tmp_path / "cfg"
    cfg.mkdir()
    store = tmp_path / "store" / "envs"
    store.mkdir(parents=True)
    (store / "dev.toml").write_text("", encoding="utf-8")
    junction = cfg / "environments"
    winapi.CreateJunction(str(store), str(junction))
    vetted = _same_paths(_file_and_folder([junction / "dev.toml"]))
    assert {_norm(cfg), _norm(junction), _norm(store), _norm(store / "dev.toml")} <= vetted


def _junction_decoy_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    """``a\\b`` a junction to ``real\\c``, holding ``f.toml``, a link to ``..\\x\\g.toml``: the walk
    reads it as ``real\\x\\g.toml`` and the open as ``a\\x\\g.toml`` (measured). Both folders are
    made, neither file. Returns the path opened, the walk's file and the open's file."""
    import _winapi

    winapi: Any = _winapi  # typeshed declares CreateJunction for win32 only
    real_c = tmp_path / "real" / "c"
    real_c.mkdir(parents=True)
    (tmp_path / "real" / "x").mkdir()
    (tmp_path / "a" / "x").mkdir(parents=True)
    winapi.CreateJunction(str(real_c), str(tmp_path / "a" / "b"))
    _link(real_c / "f.toml", Path("..") / "x" / "g.toml")
    return (
        tmp_path / "a" / "b" / "f.toml",
        tmp_path / "real" / "x" / "g.toml",
        tmp_path / "a" / "x" / "g.toml",
    )


@pytest.mark.skipif(sys.platform != "win32", reason="a junction is a Windows link")
@pytest.mark.parametrize("state", ["neither", "open-only", "walk-only", "two-files", "hard-link"])
def test_a_relative_link_climbing_behind_a_junction_refuses(state: str, tmp_path: Path) -> None:
    """Measured: a relative link reached through a junction resolves its ``..`` against the path
    through the junction, so the open takes a route the walk never vets (``a\\x``), whichever of
    the two ends reaches a file: with neither, a writer of ``a\\x`` can plant the file there
    before the next read; with a hard link, both reach one file and ``a\\x`` can be swapped (round-e90390621c finding 1, the
    lander hold on fba252d79f, and round-556c3e48 and round-c42c8e77 findings 1)."""
    opened, walked, decoy = _junction_decoy_layout(tmp_path)
    real_c = walked.parent.parent / "c"
    (real_c / "plain.toml").write_text("", encoding="utf-8")
    _link(real_c / "rel.toml", Path("plain.toml"))
    # Control: a relative link with no ``..`` behind the same junction reaches the same folder
    # either way, and passes.
    _file_and_folder([opened.parent / "rel.toml"])
    if state in ("walk-only", "two-files", "hard-link"):
        walked.write_text("", encoding="utf-8")
    if state in ("open-only", "two-files"):
        decoy.write_text("", encoding="utf-8")
    if state == "hard-link":
        os.link(walked, decoy)
    with pytest.raises(WiringError, match="a relative link climbing with '..' follows a junction"):
        _file_and_folder([opened])


def test_a_link_target_ending_in_a_separator_refuses(tmp_path: Path) -> None:
    """The open refuses a file named with a trailing separator (ENOTDIR) and the walk's split
    drops it, so the walk reaches the file where the open reaches nothing. That is refused as its
    own cause, not read as a missing file, though no read could open it (round-544ebb5d
    findings 3 and 4)."""
    real = tmp_path / "elsewhere" / "dev.toml"
    real.parent.mkdir()
    real.write_text("", encoding="utf-8")
    values = tmp_path / "dev.toml"
    plain = tmp_path / "plain.toml"
    try:
        os.symlink(str(real), plain)
        os.symlink(str(real) + os.sep, values)
    except OSError:
        pytest.skip("this account cannot create a file link")
    _file_and_folder([plain])  # control: the same target with no separator passes
    with pytest.raises(WiringError, match="the walk reaches an object where the open reaches none"):
        _file_and_folder([values])


def test_the_escape_does_not_downgrade_a_walk_and_open_disagreement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    """The disagreement vetted nothing the open reads, so the clamped escape, which downgrades a
    policy refusal under warn, leaves it a refusal (round-544ebb5d finding 8)."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "warn")
    settings, values = _two_files(tmp_path)
    fake_windows_readers(lambda path: path == values)
    assert_trusted_start_paths([settings, values])  # control: a policy refusal is downgraded
    linked = tmp_path / "linked.toml"
    try:
        os.symlink(str(values) + os.sep, linked)
    except OSError:
        pytest.skip("this account cannot create a file link")
    with pytest.raises(WiringError, match="could not vet it: .*the walk reaches an object"):
        assert_trusted_start_paths([settings, linked])


@pytest.mark.parametrize("folder", [False, True], ids=["file", "folder"])
@pytest.mark.parametrize(
    ("reached_by", "refusal"),
    [
        ("open", "the open reaches an object where the walk reaches none"),
        ("walk", "the walk reaches an object where the open reaches none"),
    ],
)
def test_an_open_and_a_walk_that_disagree_on_presence_refuse(
    reached_by: str,
    refusal: str,
    folder: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both arms of the presence check on every host, with the walk replaced, for a file and for
    a folder, as a reload passes the value file's folder."""
    import messagefoundry.config.wiring as wiring

    values = tmp_path / "dev"
    other = tmp_path / "other"
    for made in [other, values] if reached_by == "open" else [other]:
        if folder:
            made.mkdir()
        else:
            made.write_text("", encoding="utf-8")

    def check() -> list[Path]:
        return _file_and_folder([], [values]) if folder else _file_and_folder([values])

    check()  # control: the real walk agrees with the open
    walk_end: list[Path | None] = [values if reached_by == "open" else None]
    monkeypatch.setattr(wiring, "_link_chain", lambda _path: ([tmp_path], walk_end[0]))
    check()  # control: a replaced walk that agrees with the open passes
    walk_end[0] = None if reached_by == "open" else other
    with pytest.raises(WiringError, match=refusal):
        check()


@pytest.mark.parametrize("folder", [False, True], ids=["file", "folder"])
def test_an_open_and_a_walk_that_reach_two_objects_refuse(
    folder: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The samefile arm on every host, with the walk replaced: the junction test no longer reaches
    it, because the walk refuses that layout first (round-3f4ddc7f finding 2)."""
    import messagefoundry.config.wiring as wiring

    values = tmp_path / "dev"
    other = tmp_path / "other"
    for made in (values, other):
        if folder:
            made.mkdir()
        else:
            made.write_text("", encoding="utf-8")

    def check() -> list[Path]:
        return _file_and_folder([], [values]) if folder else _file_and_folder([values])

    walk_end = [values]
    monkeypatch.setattr(wiring, "_link_chain", lambda _path: ([tmp_path], walk_end[0]))
    check()  # control: a replaced walk ending where the open does passes
    walk_end[0] = other
    with pytest.raises(WiringError, match="another object than the walk"):
        check()


def test_a_link_into_a_file_where_a_folder_belongs_vets_that_file_s_folder(tmp_path: Path) -> None:
    """A link whose target runs through a regular file reads nothing (ENOTDIR), but whoever can
    write the folder holding that file can replace it with a folder holding the target."""
    values = tmp_path / "environments" / "dev.toml"
    values.parent.mkdir()
    blob = tmp_path / "store" / "blob"
    blob.parent.mkdir()
    blob.write_text("", encoding="utf-8")
    _link(values, blob / "dev.toml")
    assert _norm(blob.parent) in _same_paths(_file_and_folder([values]))


@pytest.mark.skipif(sys.platform == "win32", reason="a Windows link's own access list is read")
def test_a_posix_link_itself_is_not_vetted(tmp_path: Path) -> None:
    """A POSIX link's own mode means nothing, and the policy's stat follows it: listing a folder
    link above the file's own folder vetted that folder's target, an ancestor, such as a
    world-writable /private/tmp behind macOS's /tmp."""
    from messagefoundry.config.wiring import _link_chain

    store = tmp_path / "store" / "envs"
    store.mkdir(parents=True)
    (store / "dev.toml").write_text("", encoding="utf-8")
    linked = tmp_path / "linked"
    _link(linked, tmp_path / "store", folder=True)
    chain, _end = _link_chain(linked / "envs" / "dev.toml")
    names = _same_paths(chain)
    assert _norm(tmp_path) in names  # control: the folder holding the link is listed
    assert _norm(linked) not in names
