# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How a bad ``anon.toml`` overlay is reported (BACKLOG #3003, parts 1 to 4).

1. A path the system refuses to open is reported as the path's fault. The read and the parse
   used to share one ``try``, so that error was reported as a value the TOML parser refused.
2. TOML that stops early names the last line of the file. The parser reports the line after the
   final newline, which no editor shows.
3. ``python -m tee anonymize-captures`` checks the salt and loads the overlay before it reads
   the store, so a bad overlay refuses the run whatever the store holds.
4. Both packages export ``kept_defaults``.

Every value here is synthetic.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import ModuleType

import pytest

import messagefoundry.anon
import messagefoundry.anon.rules as engine_rules
import tee.anon
import tee.anon.rules as tee_rules
from tee.__main__ import main as tee_main
from tee.store import RelayStore

_BOTH = pytest.mark.parametrize("rules_module", (engine_rules, tee_rules), ids=("engine", "tee"))
_SALT = "b254-3003-salt-0123456789abcdef"
_PARSER_REFUSED = "the file holds a value the TOML parser refused"
_PATH_REFUSED = "the path is not one the system can open"


def _overlay(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "anon.toml"
    path.write_text(body, encoding="utf-8", newline="\n")
    return path


def _refusal(rules_module: ModuleType, overlay: Path) -> str:
    with pytest.raises(rules_module.RuleError) as exc:
        rules_module.load_rules(overlay)
    # The pattern BACKLOG #2310 set: no other exception rides on the refusal.
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    return str(exc.value)


# --- part 1: a path error is not blamed on the file's content -------------------------------------


@_BOTH
def test_a_path_the_system_refuses_is_reported_as_the_path(rules_module: ModuleType) -> None:
    """An embedded NUL is refused before any byte is read, with a plain ``ValueError``."""
    message = _refusal(rules_module, Path("no\x00such.toml"))

    assert message.startswith("cannot read anon overlay ")
    assert message.endswith(_PATH_REFUSED)
    assert "TOML" not in message


@_BOTH
def test_the_parser_arm_still_reports_a_value_the_parser_refused(
    rules_module: ModuleType, tmp_path: Path
) -> None:
    """The control for part 1: a plain ``ValueError`` from the PARSE keeps its own wording. An
    integer past ``int()``'s digit limit is the one such value measured."""
    message = _refusal(rules_module, _overlay(tmp_path, "big = " + "9" * 5000 + "\n"))

    assert message.endswith(_PARSER_REFUSED)
    assert _PATH_REFUSED not in message


@_BOTH
def test_a_missing_file_and_bad_bytes_keep_their_own_reasons(
    rules_module: ModuleType, tmp_path: Path
) -> None:
    missing = _refusal(rules_module, tmp_path / "absent.toml")
    assert _PATH_REFUSED not in missing
    assert _PARSER_REFUSED not in missing

    not_text = tmp_path / "bytes.toml"
    not_text.write_bytes(b"[hl7]\n# \xff\xfe\n")
    assert _refusal(rules_module, not_text).endswith("the file is not UTF-8 text")


# --- part 2: TOML that stops early names the last line --------------------------------------------


@_BOTH
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # Two lines, ending in a newline: the parser's own answer is line 3, column 1.
        ('[hl7]\nkeep = ["PID-5"\n', "invalid TOML at the end of the file, line 2"),
        # No final newline: the parser already named line 2.
        ('[hl7]\nkeep = ["PID-5"', "invalid TOML at the end of the file, line 2"),
        ("[hl7]\nkeep = [\n\n\n", "invalid TOML at the end of the file, line 4"),
        ("[hl7", "invalid TOML at the end of the file, line 1"),
        # The control: an error inside the file keeps the parser's line and column.
        ("[hl7]\nkeep = = 1\ndrop = []\n", "invalid TOML at line 2, column 8"),
    ],
    ids=["trailing-newline", "no-trailing-newline", "blank-tail", "one-line", "mid-file"],
)
def test_toml_that_stops_early_names_the_last_line(
    rules_module: ModuleType, body: str, expected: str, tmp_path: Path
) -> None:
    overlay = _overlay(tmp_path, body)

    assert _refusal(rules_module, overlay) == f"cannot read anon overlay {overlay}: {expected}"


# --- part 3: the tee checks the overlay before it reads the store ---------------------------------


@pytest.fixture(autouse=True)
def _no_process_logging_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    """An in-process tee run must not reconfigure logging for the whole pytest session."""
    monkeypatch.setattr("tee.__main__._configure_logging", lambda level: None)


@pytest.fixture
def empty_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A relay store with no captured bodies, and a good salt set."""
    path = str(tmp_path / "tee.db")

    async def create() -> None:
        store = await RelayStore.open(path)
        await store.close()

    asyncio.run(create())
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    return path


def _errors(db: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> list[str]:
    out = tmp_path / "ds.jsonl"
    assert tee_main(["anonymize-captures", "--db", db, "--out", str(out), *extra]) == 1
    assert not out.exists()
    err = capsys.readouterr().err
    return [line for line in err.splitlines() if line.startswith("error:")]


def test_a_bad_overlay_refuses_a_run_with_no_captured_bodies(
    empty_db: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    overlay = _overlay(tmp_path, "[fhir]\n")

    (error,) = _errors(empty_db, tmp_path, capsys, "--overlay", str(overlay))

    assert "fhir" in error
    assert "no captured bodies" not in error


def test_a_good_overlay_still_reports_the_empty_store(
    empty_db: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: with nothing wrong in the overlay, the empty store is the one error."""
    overlay = _overlay(tmp_path, '[hl7]\ndrop = ["PID-8"]\n')

    (error,) = _errors(empty_db, tmp_path, capsys, "--overlay", str(overlay))

    assert "no captured bodies" in error


def test_a_weak_salt_refuses_a_run_with_no_captured_bodies(
    empty_db: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The salt check sits beside the overlay load and moved with it."""
    monkeypatch.setenv("MEFOR_ANON_SALT", "short")

    (error,) = _errors(empty_db, tmp_path, capsys)

    assert "anonymizer salt" in error
    assert "no captured bodies" not in error


# --- part 4: kept_defaults is exported ------------------------------------------------------------


@pytest.mark.parametrize(
    ("package", "rules_module"),
    [(messagefoundry.anon, engine_rules), (tee.anon, tee_rules)],
    ids=("engine", "tee"),
)
def test_kept_defaults_is_exported(package: ModuleType, rules_module: ModuleType) -> None:
    assert "kept_defaults" in package.__all__
    assert package.kept_defaults is rules_module.kept_defaults
    # The control: the name that was already exported.
    assert "load_rules" in package.__all__
