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

import functools
import logging
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

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
    assert "refusing to start from writable-by-others path" in err
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
    assert "refusing to start from writable-by-others path" in err
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
    assert "refusing to start from writable-by-others path" in err
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
    assert "refusing to start from writable-by-others path" in err
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
        values,
        base_dir=tmp_path,
        dir_name="environments",
        environment="dev",
    )
    assert read() == {}  # control: the same read, before the grant, passes

    _grant_others_write(values)
    with pytest.raises(WiringError, match="refusing to read environment values from") as exc:
        read()
    assert str(values) in str(exc.value)
