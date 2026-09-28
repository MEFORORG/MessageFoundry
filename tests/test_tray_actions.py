# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tray actions (ADR 0113 §5/§7) — resolution logic is pure; shells are injected/captured."""

from __future__ import annotations

import logging
import os
import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.tray.actions import (
    ConsoleUrlRefused,
    LogPathRefused,
    console_url,
    log_available,
    open_console,
    open_log,
    open_repo,
    repo_open_available,
    resolve_vscode,
)


def test_console_url_appends_ui_and_strips_slash() -> None:
    assert console_url("http://127.0.0.1:8765") == "http://127.0.0.1:8765/ui"
    assert console_url("http://127.0.0.1:8765/") == "http://127.0.0.1:8765/ui"


def test_resolve_vscode_prefers_path() -> None:
    assert resolve_vscode(which=lambda _n: "C:\\path\\code.cmd") == "C:\\path\\code.cmd"


def test_resolve_vscode_falls_back_to_install_dir() -> None:
    seen: list[str] = []

    def is_file(path: str) -> bool:
        seen.append(path)
        return path.endswith("code.cmd")  # pretend the first expanded fallback exists

    result = resolve_vscode(
        which=lambda _n: None,
        is_file=is_file,
        expandvars=lambda t: t.replace("%LOCALAPPDATA%", "C:\\Users\\me\\AppData\\Local"),
    )
    assert result == "C:\\Users\\me\\AppData\\Local\\Programs\\Microsoft VS Code\\bin\\code.cmd"


def test_resolve_vscode_skips_unexpanded_vars() -> None:
    # If a var doesn't expand (still has %...%), that candidate is skipped, not probed as a path.
    resolved = resolve_vscode(
        which=lambda _n: None, expandvars=lambda t: t, is_file=lambda _p: True
    )
    assert resolved is None


def test_resolve_vscode_none_when_absent() -> None:
    assert resolve_vscode(which=lambda _n: None, is_file=lambda _p: False) is None


def test_repo_open_available() -> None:
    assert repo_open_available("C:\\repo", "code.cmd", is_dir=lambda _p: True) is True
    assert repo_open_available("C:\\repo", None, is_dir=lambda _p: True) is False  # no code CLI
    assert (
        repo_open_available("C:\\repo", "code.cmd", is_dir=lambda _p: False) is False
    )  # not a dir
    assert repo_open_available(None, "code.cmd", is_dir=lambda _p: True) is False  # no path


def test_log_available() -> None:
    assert log_available("C:\\log.txt", is_file=lambda _p: True) is True
    assert log_available("C:\\log.txt", is_file=lambda _p: False) is False
    assert log_available(None, is_file=lambda _p: True) is False


def test_open_console_opens_ui_url() -> None:
    opened: list[str] = []
    open_console("http://127.0.0.1:8765", opener=opened.append)
    assert opened == ["http://127.0.0.1:8765/ui"]


# BACKLOG #1993 (ASVS 1.2.2): `engine_url` comes from tray.toml, and on Windows the default opener
# reaches `os.startfile`, which launches whatever handler owns the scheme. Only http and https are
# engine URLs, so nothing else may reach the opener.
@pytest.mark.parametrize(
    ("engine_url", "expected"),
    [
        ("https://127.0.0.1:8765", "https://127.0.0.1:8765/ui"),
        ("http://127.0.0.1:8765", "http://127.0.0.1:8765/ui"),
        ("HTTPS://127.0.0.1:8765/", "HTTPS://127.0.0.1:8765/ui"),
        ("https://engine.example.org:8765", "https://engine.example.org:8765/ui"),
        ("https://[::1]:8765", "https://[::1]:8765/ui"),
        ("https://gw.example.org/mefor", "https://gw.example.org/mefor/ui"),
        # httpx accepts both of these, so Open Console must too.
        ("https://engine.ex\u00e4mple.org", "https://engine.ex\u00e4mple.org/ui"),
        ("https://[fe80::1%25eth0]:8765", "https://[fe80::1%25eth0]:8765/ui"),
    ],
)
def test_open_console_opens_http_and_https(engine_url: str, expected: str) -> None:
    opened: list[str] = []
    open_console(engine_url, opener=opened.append)
    assert opened == [expected]


@pytest.mark.parametrize(
    "engine_url",
    [
        # Each row has a host and nothing else wrong, so only the scheme check stops it.
        "file://server/share",
        "ftp://127.0.0.1:8765",
        "search-ms://host",
        "ms-msdt://x",
        "javascript://127.0.0.1/%0aalert(1)",
        # The schemes the item names, which also lack a host.
        "file:///x/y",
        "javascript:void0",
        "data:text/plain,hi",
        "ms-msdt:/id PCWDiagnostic",
        "shell:startup",
        # No scheme at all.
        "127.0.0.1:8765",
        "",
    ],
)
def test_open_console_refuses_a_non_engine_scheme(engine_url: str) -> None:
    opened: list[str] = []
    with pytest.raises(ConsoleUrlRefused):
        open_console(engine_url, opener=opened.append)
    assert opened == []


@pytest.mark.parametrize(
    "engine_url",
    [
        # The parser strips these and reads https; the OS handler would see the raw string.
        " https://127.0.0.1:8765",
        "ht\ttps://127.0.0.1:8765",
        "https://127.0.0.1:8765\n",
        "https://127.0.0.1:8765/\x00x",
        "https://127.0.0.1 :8765",
        "\ufeffhttps://127.0.0.1:8765",
        # A browser reads a backslash as a slash, so the host it visits is not the one checked.
        "https://127.0.0.1\\@evil.example",
        # An http(s) scheme with no host is not an engine URL.
        "https:127.0.0.1",
        "https:///ui",
        # An unparseable authority.
        "https://[::1:8765",
    ],
)
def test_open_console_refuses_a_malformed_engine_url(engine_url: str) -> None:
    opened: list[str] = []
    with pytest.raises(ConsoleUrlRefused):
        open_console(engine_url, opener=opened.append)
    assert opened == []


@pytest.mark.parametrize(
    "engine_url",
    ["file:///D:/share/token=s3cr3t", "admin:s3cr3t@127.0.0.1:8765"],
)
def test_console_url_refusal_never_echoes_the_url(engine_url: str) -> None:
    # The second row parses as scheme "admin", so even the scheme can be operator data.
    with pytest.raises(ConsoleUrlRefused) as excinfo:
        open_console(engine_url, opener=lambda _u: None)
    text = str(excinfo.value)
    assert "http or https" in text
    for fragment in ("s3cr3t", "admin", "D:/share", "file"):
        assert fragment not in text


def test_open_repo_runs_code_with_list_argv() -> None:
    calls: list[list[str]] = []
    open_repo("C:\\repo", "code.cmd", runner=calls.append)
    assert calls == [["code.cmd", "C:\\repo"]]


def _identity(path: str) -> str:
    return path


def _exists(_path: str) -> bool:
    return True


def _never_remote(_path: str) -> bool:
    return False


# BACKLOG #2086: `log_path` comes from tray.toml or the NSSM AppStdout registry value, and on
# Windows the opener is `os.startfile`, which launches whatever handler owns the suffix. Only a
# .log or .txt file may reach it.
@pytest.mark.parametrize(
    "log_path",
    [
        "C:\\ProgramData\\MessageFoundry\\logs\\service.out.log",
        "C:\\logs\\service.txt",
        "C:\\logs\\SERVICE.OUT.LOG",
        "C:\\logs\\service.Txt",
        "C:/logs/service.log",
        "d:\\logs\\service.log",
        # A folder named DavWWWRoot on a local drive is only a folder name.
        "C:\\logs\\DavWWWRoot\\service.log",
        # The last suffix decides it, so a .bat earlier in the name is only text.
        "C:\\logs\\x.bat.log",
    ],
)
def test_open_log_opens_a_log_or_txt_file(log_path: str) -> None:
    opened: list[str] = []
    open_log(
        log_path,
        opener=opened.append,
        resolve=_identity,
        is_file=_exists,
        is_remote_drive=_never_remote,
    )
    assert opened == [log_path]


class _Probes:
    """Records every call that could touch the file system or the network."""

    def __init__(self, *, remote: bool = False, target: str | None = None) -> None:
        self.calls: list[str] = []
        self._remote = remote
        self._target = target

    def resolve(self, path: str) -> str:
        self.calls.append("resolve")
        return self._target if self._target is not None else path

    def is_file(self, _path: str) -> bool:
        self.calls.append("is_file")
        return True

    def is_remote_drive(self, _path: str) -> bool:
        self.calls.append("is_remote_drive")
        return self._remote


# BACKLOG #2086: a remote target is refused on the configured string alone, so no probe runs and
# nothing reaches the host. Opening one would send the user's NTLM credentials to it, and open
# content that host controls.
@pytest.mark.parametrize(
    "log_path",
    [
        # UNC, both separators and mixed.
        "\\\\host\\share\\service.log",
        "//host/share/service.log",
        "\\/host/share/service.log",
        "/\\host\\share\\service.log",
        "\\\\192.0.2.10\\share\\service.log",
        # WebDAV through the redirector.
        "\\\\host@SSL\\DavWWWRoot\\service.log",
        "\\\\host@SSL@443\\DavWWWRoot\\service.log",
        "\\\\host\\DavWWWRoot\\service.log",
        "\\\\host@80\\share\\service.log",
        # Extended-length and device paths, remote and local alike.
        "\\\\?\\UNC\\host\\share\\service.log",
        "\\\\?\\C:\\logs\\service.log",
        "\\\\.\\C:\\logs\\service.log",
        "\\\\.\\UNC\\host\\share\\service.log",
        "\\\\.\\pipe\\service.log",
        "//?/UNC/host/share/service.log",
    ],
)
def test_open_log_refuses_a_remote_target_before_any_probe(log_path: str) -> None:
    probes = _Probes()
    opened: list[str] = []
    with pytest.raises(LogPathRefused):
        open_log(
            log_path,
            opener=opened.append,
            resolve=probes.resolve,
            is_file=probes.is_file,
            is_remote_drive=probes.is_remote_drive,
        )
    assert opened == []
    assert probes.calls == []


def test_open_log_refuses_a_mapped_network_drive_before_resolving_it() -> None:
    probes = _Probes(remote=True)
    opened: list[str] = []
    with pytest.raises(LogPathRefused):
        open_log(
            "Z:\\logs\\service.log",
            opener=opened.append,
            resolve=probes.resolve,
            is_file=probes.is_file,
            is_remote_drive=probes.is_remote_drive,
        )
    assert opened == []
    assert probes.calls == ["is_remote_drive"]


@pytest.mark.parametrize(
    ("target", "remote"),
    [
        ("\\\\evil\\share\\service.log", False),
        ("\\\\?\\UNC\\evil\\share\\service.log", False),
        ("Z:\\logs\\service.log", True),
    ],
)
def test_open_log_refuses_a_local_name_that_resolves_to_a_remote_target(
    target: str, remote: bool
) -> None:
    # A symlink on a local drive that points at a share is judged by where it points.
    def is_remote_drive(path: str) -> bool:
        return remote and path == target

    opened: list[str] = []
    with pytest.raises(LogPathRefused):
        open_log(
            "C:\\logs\\service.log",
            opener=opened.append,
            resolve=lambda _p: target,
            is_file=_exists,
            is_remote_drive=is_remote_drive,
        )
    assert opened == []


@pytest.mark.skipif(sys.platform != "win32", reason="GetDriveTypeW is Windows-only")
def test_the_real_drive_probe_names_a_mapped_drive_remote() -> None:
    # Positive control for the default probe, on whatever mapped drive this host has. The local
    # system drive is the negative control.
    from messagefoundry.tray.actions import _is_remote_drive

    system_drive = os.environ.get("SYSTEMDRIVE", "C:") + "\\"
    assert _is_remote_drive(system_drive) is False
    mapped = [f"{c}:\\" for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if _is_remote_drive(f"{c}:\\")]
    if not mapped:
        pytest.skip("this host has no mapped network drive to test against")
    probes = _Probes()
    with pytest.raises(LogPathRefused):
        open_log(
            mapped[0] + "logs\\service.log",
            opener=lambda _p: None,
            resolve=probes.resolve,
            is_file=probes.is_file,
        )
    assert probes.calls == []


@pytest.mark.parametrize(
    "log_path",
    [
        # A suffix whose default handler runs the file, in the item's four and their neighbours.
        "C:\\logs\\x.bat",
        "C:\\logs\\x.Bat",
        "C:\\logs\\x.BAT",
        "C:\\logs\\x.cmd",
        "C:\\logs\\x.exe",
        "C:\\logs\\x.lnk",
        "C:\\logs\\x.hta",
        "C:\\logs\\x.url",
        "C:\\logs\\x.ps1",
        "C:\\logs\\x.vbs",
        "C:\\logs\\x.js",
        "C:\\logs\\x.scr",
        "C:\\logs\\x.msc",
        "C:\\logs\\x",
        # Windows strips a trailing dot or space, so x.bat. runs as x.bat.
        "C:\\logs\\x.bat.",
        "C:\\logs\\x.bat ",
        "C:\\logs\\x.bat. ",
        # The same strip turns these into a .log, but the string is not one and it is refused.
        "C:\\logs\\x.log.",
        "C:\\logs\\x.log ",
        # An alternate data stream: the named file is a .log, the opened stream is not.
        "C:\\logs\\x.log:evil.bat",
        "C:\\logs\\x.log::$DATA",
        # A stream whose own name ends .log, on a .bat. Only the colon rule refuses this one.
        "C:\\logs\\run.bat:notes.log",
        # A double suffix keeps its last one.
        "C:\\logs\\x.log.bat",
        "C:\\logs\\x.txt.lnk",
        # A directory, not a file name.
        "C:\\logs\\",
        # Not absolute. The OS opener would launch a shell folder or a URL for these.
        "service.log",
        "logs\\service.log",
        "C:service.log",
        "\\logs\\service.log",
        "shell:startup\\x.log",
        "https://evil.example/x.log",
        "file:///C:/logs/x.log",
        "",
    ],
)
def test_open_log_refuses_a_path_that_is_not_a_log_file(log_path: str) -> None:
    opened: list[str] = []
    with pytest.raises(LogPathRefused):
        open_log(log_path, opener=opened.append, resolve=_identity, is_file=_exists)
    assert opened == []


def test_open_log_judges_the_resolved_target_and_opens_it() -> None:
    # A symlink or junction named x.log that points at a batch file is judged by its target.
    targets = {
        "C:\\logs\\x.log": "C:\\Users\\me\\evil.bat",
        "C:\\logs\\y.log": "D:\\real\\service.out.log",
    }
    opened: list[str] = []
    with pytest.raises(LogPathRefused):
        open_log(
            "C:\\logs\\x.log", opener=opened.append, resolve=targets.__getitem__, is_file=_exists
        )
    assert opened == []
    # The opener gets the path the check approved, not the configured string.
    open_log("C:\\logs\\y.log", opener=opened.append, resolve=targets.__getitem__, is_file=_exists)
    assert opened == ["D:\\real\\service.out.log"]


def test_open_log_refuses_a_configured_name_even_when_the_target_is_a_log() -> None:
    # Both ends must pass, not only the target. This is the one test where the configured name
    # alone decides it: each target here is a .log, so a check on the target alone would open it.
    opened: list[str] = []
    for path in ("C:\\logs\\x.lnk", "C:\\logs\\x.bat", "C:\\logs\\x.log."):
        with pytest.raises(LogPathRefused):
            open_log(
                path,
                opener=opened.append,
                resolve=lambda _p: "C:\\logs\\service.log",
                is_file=_exists,
            )
    assert opened == []


def test_open_log_refuses_a_missing_file_or_a_failed_resolve() -> None:
    opened: list[str] = []
    with pytest.raises(LogPathRefused):
        open_log(
            "C:\\logs\\gone.log", opener=opened.append, resolve=_identity, is_file=lambda _p: False
        )

    def _broken(_path: str) -> str:
        raise OSError("resolve failed")

    with pytest.raises(LogPathRefused):
        open_log("C:\\logs\\x.log", opener=opened.append, resolve=_broken, is_file=_exists)
    assert opened == []


@pytest.mark.parametrize(
    "log_path", ["C:\\op\\s3cr3t\\token=abc.bat", "https://admin:s3cr3t@evil.example/x.log"]
)
def test_log_path_refusal_never_echoes_the_path(log_path: str) -> None:
    with pytest.raises(LogPathRefused) as excinfo:
        open_log(log_path, opener=lambda _p: None, resolve=_identity, is_file=_exists)
    text = str(excinfo.value)
    assert ".log or .txt" in text
    for fragment in ("s3cr3t", "admin", "token", "op\\", "evil", ".bat"):
        assert fragment not in text


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path resolution")
def test_open_log_against_real_files(tmp_path: Path) -> None:
    # The default resolve and is_file, on real files: the .log opens and the .bat does not.
    log_file = tmp_path / "service.out.log"
    bat_file = tmp_path / "service.bat"
    log_file.write_text("synthetic\n", encoding="utf-8")
    bat_file.write_text("rem synthetic\n", encoding="utf-8")
    opened: list[str] = []
    open_log(str(log_file), opener=opened.append)
    assert [os.path.normcase(p) for p in opened] == [os.path.normcase(os.path.realpath(log_file))]
    with pytest.raises(LogPathRefused):
        open_log(str(bat_file), opener=opened.append)
    # Windows resolves "service.bat." to service.bat; the raw string is refused before that.
    with pytest.raises(LogPathRefused):
        open_log(str(bat_file) + ".", opener=opened.append)
    assert len(opened) == 1

    link = tmp_path / "linked.log"
    try:
        link.symlink_to(bat_file)
    except OSError:
        pytest.skip("creating a symlink needs Developer Mode or elevation on this host")
    with pytest.raises(LogPathRefused):
        open_log(str(link), opener=opened.append)
    assert len(opened) == 1


def _refused_action_report(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    act: Callable[[object], None],
    config: object,
) -> tuple[str, str, str]:
    """Run one refused tray action; return the toast title, toast body and logged line.

    The engine's PHI filter chain goes in front of caplog on purpose. The chain rewrites the shared
    record in place, so caplog reads the redacted text whenever an earlier test left a filtered
    root handler behind. That made the console test pass alone and fail under the full suite on
    all three CI legs, when its old wording read as a name run. Installing the chain here makes the
    result the same in either order (BACKLOG #1993).
    """
    from messagefoundry import logging_setup
    from messagefoundry.tray import app as tray_app

    notes: list[tuple[str, str]] = []

    class _Shell:
        def request_notify(self, title: str, body: str) -> None:
            notes.append((title, body))

    tray = tray_app.TrayApp.__new__(tray_app.TrayApp)
    monkeypatch.setattr(tray, "_config", config, raising=False)
    monkeypatch.setattr(tray, "_shell", _Shell(), raising=False)

    logger = logging.getLogger("messagefoundry.tray.app")
    filtered = logging_setup.build_stderr_handler()
    logger.addHandler(filtered)
    try:
        with caplog.at_level("WARNING", logger="messagefoundry.tray.app"):
            act(tray)
    finally:
        logger.removeHandler(filtered)
        filtered.close()

    assert len(notes) == 1, notes
    records = [r for r in caplog.records if r.name == "messagefoundry.tray.app"]
    assert len(records) == 1, records
    title, body = notes[0]
    return title, body, records[0].getMessage()


def test_tray_app_reports_a_refused_log_path_as_a_toast(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The refused View Log reports the way the refused Open Console does: a fixed toast and log line.
    from messagefoundry.redaction import redact
    from messagefoundry.tray import actions as tray_actions
    from messagefoundry.tray.config import TrayConfig

    # The opener is captured so a regressed check shows up here instead of launching a file.
    opened: list[str] = []
    real_open_log = tray_actions.open_log
    monkeypatch.setattr(
        tray_actions,
        "open_log",
        lambda path: real_open_log(path, opener=opened.append, is_file=_exists),
    )
    title, body, logged = _refused_action_report(
        monkeypatch,
        caplog,
        lambda tray: tray._view_log(),  # type: ignore[attr-defined]
        TrayConfig(log_path="C:\\op\\s3cr3t\\run.bat"),
    )

    assert opened == []
    assert body.startswith("Service log not opened: ")
    assert logged == body
    assert redact(logged) == logged
    assert "s3cr3t" not in title + body + caplog.text


def test_tray_app_reports_a_refused_console_url_as_a_toast(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The tray reports a failed action as a balloon, the way `control.outcome_toast` does. The
    # balloon and the log line are fixed text and never echo the URL, which could carry a secret.
    from messagefoundry.redaction import redact
    from messagefoundry.tray.config import TrayConfig

    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", opened.append)
    title, body, logged = _refused_action_report(
        monkeypatch,
        caplog,
        lambda tray: tray._open_console(),  # type: ignore[attr-defined]
        TrayConfig(engine_url="file:///C:/op/s3cr3t"),
    )

    assert opened == []
    assert body.startswith("Console not opened: ")
    assert logged == body
    # The line must pass the redactor unchanged, so a future redactor rule that eats it fails here
    # by name rather than turning the operator's only clue into "[redacted]".
    assert redact(logged) == logged
    assert "s3cr3t" not in title + body + caplog.text


def test_tray_app_reports_a_viewer_failure_without_the_path(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The check passed and the viewer then failed. Its OSError quotes the path, so it is not echoed.
    from messagefoundry.tray import actions as tray_actions
    from messagefoundry.tray.config import TrayConfig

    def _viewer_fails(path: str) -> None:
        raise FileNotFoundError(2, "The system cannot find the file specified", path)

    real_open_log = tray_actions.open_log
    monkeypatch.setattr(
        tray_actions,
        "open_log",
        lambda path: real_open_log(path, opener=_viewer_fails, resolve=_identity, is_file=_exists),
    )
    title, body, logged = _refused_action_report(
        monkeypatch,
        caplog,
        lambda tray: tray._view_log(),  # type: ignore[attr-defined]
        TrayConfig(log_path="C:\\op\\s3cr3t\\service.log"),
    )
    assert body == "Service log not opened: the viewer failed"
    assert logged == "Service log not opened: the viewer failed (FileNotFoundError)"
    assert "s3cr3t" not in title + body + caplog.text
