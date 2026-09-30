# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``messagefoundry-toolkit`` command (ADR 0201 slice 2, BACKLOG #1192, ASVS 15.2.3).

Two acceptance criteria live here. AC-4: an installed toolkit refuses to run beside an engine of
another version. AC-9: tests import ``messagefoundry_toolkit`` from this checkout, never from an
installed copy, because an installed copy of a force-included tree is frozen at install time.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Callable
from importlib import metadata
from pathlib import Path

import pytest

import messagefoundry.cli_common as cli_common
import messagefoundry_toolkit
import messagefoundry_toolkit.__main__ as toolkit_cli

_REPO = Path(__file__).resolve().parents[1]


# --- AC-9: the checkout, not an installed copy ---------------------------------------------------


def test_the_toolkit_imports_from_the_repository_checkout() -> None:
    """The engine's editable ``.pth`` adds the repository root AFTER ``site-packages``, so an
    installed toolkit would win the import and every test would run a frozen copy. ADR 0201 section
    1 measured that on the web console. Dev and CI install no toolkit, so the checkout answers."""
    package = Path(messagefoundry_toolkit.__file__).resolve().parent
    assert package == _REPO / "messagefoundry_toolkit", (
        f"messagefoundry_toolkit resolved to {package}, not this checkout. Uninstall the "
        f"messagefoundry-toolkit distribution from this environment; ADR 0201 section 1 says why."
    )


# --- AC-4: the installed pair must match ---------------------------------------------------------


def _metadata(versions: dict[str, str]) -> Callable[[str], str]:
    def version_of(name: str) -> str:
        try:
            return versions[name]
        except KeyError:
            raise metadata.PackageNotFoundError(name) from None

    return version_of


def test_no_toolkit_metadata_skips_the_check() -> None:
    # Every dev and CI environment: the toolkit comes from the checkout beside the engine.
    assert toolkit_cli.version_mismatch(_metadata({"messagefoundry": "0.4.0"})) is None
    assert toolkit_cli.version_mismatch(_metadata({})) is None


def test_a_matching_pair_passes() -> None:
    versions = {"messagefoundry": "0.4.0", "messagefoundry-toolkit": "0.4.0"}
    assert toolkit_cli.version_mismatch(_metadata(versions)) is None


def test_a_mismatched_pair_is_refused_naming_both_versions() -> None:
    versions = {"messagefoundry": "0.5.0", "messagefoundry-toolkit": "0.4.0"}
    line = toolkit_cli.version_mismatch(_metadata(versions))
    assert line is not None
    assert "0.4.0" in line and "0.5.0" in line
    assert "\n" not in line


def test_a_toolkit_without_an_installed_engine_is_refused() -> None:
    line = toolkit_cli.version_mismatch(_metadata({"messagefoundry-toolkit": "0.4.0"}))
    assert line is not None and "not installed" in line


def _run_toolkit(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    """Run the toolkit's ``main()`` without leaking its process-wide changes into later tests."""
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    monkeypatch.setattr(toolkit_cli, "harden_console_streams", lambda **_kw: None)
    monkeypatch.setattr(cli_common, "harden_console_streams", lambda **_kw: None)
    return toolkit_cli.main(argv)


def _mismatched(monkeypatch: pytest.MonkeyPatch) -> None:
    versions = {"messagefoundry": "0.5.0", "messagefoundry-toolkit": "0.4.0"}
    monkeypatch.setattr(toolkit_cli.metadata, "version", _metadata(versions))


def test_main_refuses_a_mismatched_pair_before_any_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _mismatched(monkeypatch)
    # A command that would otherwise run and exit 2 on its own (an absent corpus), so the assertion
    # on the text, not the code, is what shows the version check answered.
    assert _run_toolkit(monkeypatch, ["adr-analyze", "--adr-dir", str(tmp_path / "none")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1, captured.err
    assert "0.4.0" in captured.err and "0.5.0" in captured.err


def test_main_refuses_a_mismatched_pair_as_json_under_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mismatched(monkeypatch)
    assert _run_toolkit(monkeypatch, ["adr-analyze", "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "0.5.0" in json.loads(captured.out)["error"]


def test_main_runs_when_the_pair_matches(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control for the two refusals above: the same command, a matching pair, and it runs."""
    versions = {"messagefoundry": "0.4.0", "messagefoundry-toolkit": "0.4.0"}
    monkeypatch.setattr(toolkit_cli.metadata, "version", _metadata(versions))
    adr_dir = _REPO / "docs" / "adr"
    assert _run_toolkit(monkeypatch, ["adr-analyze", "--adr-dir", str(adr_dir), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["adrs"]


# --- The command itself ------------------------------------------------------------------------


def test_toolkit_help_names_its_commands_and_encodes_on_a_legacy_codepage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The twin of tests/test_cli.py's engine help test. adr-analyze's help once carried the U+2192
    arrow that crashed ``--help`` on a cp1252 console, and it now lives here."""
    parser, _dispatch = toolkit_cli._build_parser()
    help_text = parser.format_help()
    assert "adr-analyze" in help_text
    try:
        help_text.encode("cp1252")
    except UnicodeEncodeError as exc:
        bad = help_text[exc.start]
        pytest.fail(f"toolkit --help is not cp1252-encodable: U+{ord(bad):04X} {bad!r}")


def test_python_dash_m_runs_the_toolkit() -> None:
    """``python -m messagefoundry_toolkit`` is how dev and CI run it, since neither installs the
    distribution and so neither has the console script."""
    proc = subprocess.run(
        [sys.executable, "-m", "messagefoundry_toolkit", "--help"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=_REPO,
    )
    assert proc.returncode == 0, proc.stderr
    assert "messagefoundry-toolkit" in proc.stdout and "adr-analyze" in proc.stdout


def test_the_toolkit_never_imports_the_engine_cli_module() -> None:
    """ADR 0201 section 2: the shared helpers live in ``messagefoundry.cli_common`` so the toolkit
    never imports ``messagefoundry.__main__``. A fresh process, because this test process has
    already imported it through other tests."""
    probe = (
        "import sys, messagefoundry_toolkit.__main__\n"
        "print('messagefoundry.__main__' in sys.modules, 'messagefoundry.cli_common' in sys.modules)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True, timeout=120
    ).stdout.split()
    # The second value is the control: the probe does see the modules the toolkit really imports.
    assert out == ["False", "True"]
