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

import inspect
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
    SECURITY_ENFORCEMENT_ENV,
)
from messagefoundry.config.wiring import (
    WiringError,
    _file_and_folder,
    _WinConfigSourceProbes,
    _WinPathSecurity,
    assert_trusted_start_paths,
    install_trust_paths,
    untrusted_install_paths,
)

_SELF = "S-1-5-21-1-2-3-2002"
_EVERYONE = "S-1-1-0"
_ALLOW = 0x00
_FULL = 0x10000000 | 0x40000000 | 0x1FF
_MODIFY = 0x00000002 | 0x00000004 | 0x00000010 | 0x00010000

_CLEAN = _WinPathSecurity(owner_sid=_SELF, aces=((_ALLOW, _FULL, _SELF),))
_EVERYONE_WRITES = _WinPathSecurity(owner_sid=_SELF, aces=((_ALLOW, _MODIFY, _EVERYONE),))

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


@pytest.fixture
def no_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)


def _windows_readers(monkeypatch: pytest.MonkeyPatch, writable: Path | None) -> list[Path]:
    """Route the check down the Windows branch with fake readers. ``writable`` grants Everyone
    write; every other path reads clean. Returns the paths read."""
    import messagefoundry.config.wiring as wiring

    seen: list[Path] = []

    def _read_path(path: Path) -> _WinPathSecurity:
        seen.append(path)
        return _EVERYONE_WRITES if path == writable else _CLEAN

    probes = _WinConfigSourceProbes(
        self_sid=_SELF, read_path=_read_path, owner_in_admins=lambda _sid: False
    )
    monkeypatch.setattr(wiring, "_win32_config_source_probes", lambda: probes)
    monkeypatch.setattr("messagefoundry.config.wiring.sys.platform", "win32")
    # The suites replace this seam with clean readers on win32; put the real one back.
    monkeypatch.setattr(
        wiring,
        "_assert_trusted_paths_windows",
        inspect.unwrap(wiring._assert_trusted_paths_windows),
    )
    return seen


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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control for the refusals below."""
    settings, values = _two_files(tmp_path)
    seen = _windows_readers(monkeypatch, writable=None)
    assert_trusted_start_paths([settings, values])
    assert seen == [settings, tmp_path, values, values.parent]


@pytest.mark.usefixtures("no_escape")
@pytest.mark.parametrize("which", ["settings", "settings folder", "values", "values folder"])
def test_a_writable_file_or_folder_refuses_the_start(
    which: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, values = _two_files(tmp_path)
    writable = {
        "settings": settings,
        "settings folder": tmp_path,
        "values": values,
        "values folder": values.parent,
    }[which]
    _windows_readers(monkeypatch, writable=writable)
    with pytest.raises(WiringError, match="refusing to start from writable-by-others path") as exc:
        assert_trusted_start_paths([settings, values])
    assert str(writable) in str(exc.value)


def test_the_escape_downgrades_the_refusal_under_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "warn")
    settings, values = _two_files(tmp_path)
    _windows_readers(monkeypatch, writable=values)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        assert_trusted_start_paths([settings, values])
    assert any(str(values) in r.getMessage() for r in caplog.records)


def test_the_escape_is_refused_under_enforce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.delenv(SECURITY_ENFORCEMENT_ENV, raising=False)
    settings, values = _two_files(tmp_path)
    _windows_readers(monkeypatch, writable=values)
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under enforce, with no escape, the reading still returns rather than raising."""
    import messagefoundry

    package = Path(messagefoundry.__file__).resolve().parent
    _windows_readers(monkeypatch, writable=package)
    reasons = untrusted_install_paths()
    assert len(reasons) == 1
    assert str(package) in reasons[0]
    assert reasons[0].startswith("the engine runs code from writable-by-others path")


@pytest.mark.usefixtures("no_escape")
def test_a_clean_install_reports_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows_readers(monkeypatch, writable=None)
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


def _serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> int:
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    # The start-up code reading is not under test here; the dev venv may carry unrecorded items.
    monkeypatch.setattr("messagefoundry.startupcode.startup_refusal", lambda _posture: None)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev", *extra])


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
