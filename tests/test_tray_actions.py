# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tray actions (ADR 0113 §5/§7) — resolution logic is pure; shells are injected/captured."""

from __future__ import annotations

from messagefoundry.tray.actions import (
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


def test_open_repo_runs_code_with_list_argv() -> None:
    calls: list[list[str]] = []
    open_repo("C:\\repo", "code.cmd", runner=calls.append)
    assert calls == [["code.cmd", "C:\\repo"]]


def test_open_log_opens_path() -> None:
    opened: list[str] = []
    open_log("C:\\ProgramData\\MessageFoundry\\logs\\service.out.log", opener=opened.append)
    assert opened == ["C:\\ProgramData\\MessageFoundry\\logs\\service.out.log"]
