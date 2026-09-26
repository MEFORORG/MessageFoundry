# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tray actions (ADR 0113 §5/§7) — resolution logic is pure; shells are injected/captured."""

from __future__ import annotations

import logging
import webbrowser

import pytest

from messagefoundry.tray.actions import (
    ConsoleUrlRefused,
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


def test_open_log_opens_path() -> None:
    opened: list[str] = []
    open_log("C:\\ProgramData\\MessageFoundry\\logs\\service.out.log", opener=opened.append)
    assert opened == ["C:\\ProgramData\\MessageFoundry\\logs\\service.out.log"]


def test_tray_app_reports_a_refused_console_url_as_a_toast(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The tray reports a failed action as a balloon, the way `control.outcome_toast` does. The
    # balloon and the log line are fixed text and never echo the URL, which could carry a secret.
    from messagefoundry import logging_setup
    from messagefoundry.redaction import redact
    from messagefoundry.tray import app as tray_app
    from messagefoundry.tray.config import TrayConfig

    notes: list[tuple[str, str]] = []

    class _Shell:
        def request_notify(self, title: str, body: str) -> None:
            notes.append((title, body))

    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", opened.append)
    tray = tray_app.TrayApp.__new__(tray_app.TrayApp)
    monkeypatch.setattr(
        tray, "_config", TrayConfig(engine_url="file:///C:/op/s3cr3t"), raising=False
    )
    monkeypatch.setattr(tray, "_shell", _Shell(), raising=False)

    # Put the engine's PHI filter chain in front of caplog on purpose. The chain rewrites the
    # shared record in place, so caplog reads the redacted text whenever an earlier test left a
    # filtered root handler behind. That made this assertion pass alone and fail under the full
    # suite on all three CI legs, when the old wording "Open Console refused" read as a name run.
    # Installing the chain here makes the result the same in either order (BACKLOG #1993).
    logger = logging.getLogger("messagefoundry.tray.app")
    filtered = logging_setup.build_stderr_handler()
    logger.addHandler(filtered)
    try:
        with caplog.at_level("WARNING", logger="messagefoundry.tray.app"):
            tray._open_console()
    finally:
        logger.removeHandler(filtered)
        filtered.close()

    assert opened == []
    assert len(notes) == 1
    title, body = notes[0]
    assert body.startswith("Console not opened: ")
    records = [r for r in caplog.records if r.name == "messagefoundry.tray.app"]
    assert len(records) == 1, records
    logged = records[0].getMessage()
    assert logged == body
    # The line must pass the redactor unchanged, so a future redactor rule that eats it fails here
    # by name rather than turning the operator's only clue into "[redacted]".
    assert redact(logged) == logged
    assert "s3cr3t" not in title + body + caplog.text
