# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the throughput counter — the gauge that reports items CLOSED.

**What these pin, and why each one exists.** This counter was written because a 30-item wave closed
zero overnight while every other gauge reported health. A gauge that replaces that silence with a
*wrong* number is worse than the silence, so the tests below are weighted toward the ways a counter
lies rather than toward the happy path:

- it must report zero when nothing closed, and NOT treat zero as an error (a nagging gauge is muted)
- it must refuse to report at all when a source did not resolve (the false-zero guard)
- it must not count a filing as a closure, or a vanishing as a closure
- its own self-test must fail if the detector is broken
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "coord" / "throughput.py"

_OPEN_BANNER = "> \U0001f522 prioritized"
_CLOSED_BANNER = "> ✅ shipped"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("coord_throughput", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod() -> ModuleType:
    return _load()


def _ledger(*items: tuple[int, str]) -> str:
    return "\n".join(f"## {n}. item {n}\n{banner}\n\nbody\n" for n, banner in items)


def _read(mod: ModuleType, ref: str, text: str) -> object:
    read = mod.RefRead(ref)
    read.sources.append("synthetic")
    for item in mod.parse_items(text):
        read.items[item.num] = item
    return read


def test_self_test_passes(mod: ModuleType) -> None:
    """The built-in positive control must pass. If it cannot, no number the tool prints is evidence."""
    assert mod._self_test() == 0


def test_a_closure_is_counted(mod: ModuleType) -> None:
    before = _read(mod, "a", _ledger((1, _OPEN_BANNER), (2, _OPEN_BANNER)))
    after = _read(mod, "b", _ledger((1, _CLOSED_BANNER), (2, _OPEN_BANNER)))
    assert mod.compare(before, after)["closed"] == [1]


def test_nothing_closing_reports_zero_not_an_error(mod: ModuleType) -> None:
    """Zero is a finding, not a fault.

    The whole failure this tool addresses is a zero nobody saw. If zero were an error the tool would
    be muted within a day, and the gauge would be back to reporting nothing.
    """
    same = _ledger((1, _OPEN_BANNER), (2, _OPEN_BANNER))
    before, after = _read(mod, "a", same), _read(mod, "b", same)
    assert mod.compare(before, after)["closed"] == []


def test_a_newly_filed_item_is_not_a_closure(mod: ModuleType) -> None:
    before = _read(mod, "a", _ledger((1, _OPEN_BANNER)))
    after = _read(mod, "b", _ledger((1, _OPEN_BANNER), (2, _CLOSED_BANNER)))
    moved = mod.compare(before, after)
    assert moved["closed"] == []
    assert moved["filed_closed"] == [2]


def test_a_vanished_item_is_reported_as_loss_not_closure(mod: ModuleType) -> None:
    """An item that disappears is a loss. Counting it as a closure would reward deleting the ledger."""
    before = _read(mod, "a", _ledger((1, _OPEN_BANNER), (2, _OPEN_BANNER)))
    after = _read(mod, "b", _ledger((1, _OPEN_BANNER)))
    moved = mod.compare(before, after)
    assert moved["closed"] == []
    assert moved["vanished"] == [2]


def test_a_reopening_is_not_a_negative_closure(mod: ModuleType) -> None:
    before = _read(mod, "a", _ledger((1, _CLOSED_BANNER)))
    after = _read(mod, "b", _ledger((1, _OPEN_BANNER)))
    moved = mod.compare(before, after)
    assert moved["closed"] == []
    assert moved["reopened"] == [1]


def test_below_the_floor_refuses_to_report(
    mod: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A source that stopped resolving must be an error, never a quiet zero.

    This is the failure the counter exists to avoid reproducing: an instrument that scanned a
    fraction of the corpus and reported success over what was left.
    """
    rc = mod.main(["HEAD", "HEAD", "--min-items", "99999"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "INSTRUMENT ERROR" in err
    assert "Refusing to report" in err


def test_headline_states_the_count_first(
    mod: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """The number must be the first thing on the page. That it was not is why the night was lost."""
    rc = mod.main(["HEAD", "HEAD", "--quiet"])
    assert rc == 0
    first = capsys.readouterr().out.splitlines()[0]
    assert first.startswith("items closed: ")


def test_status_alphabet_is_imported_not_redefined(mod: ModuleType) -> None:
    """The banner alphabet has exactly one definition, and this tool must not carry a second.

    `CLAUDE.md` section 11 states the rule: import `parse_items`, never re-derive it. A second scan
    is a second, silently different definition of what "closed" means.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    assert "from backlog_status_check import" in source
    for token in ("_CLOSED =", "_OPEN =", "_BANNER =", "_HEADING ="):
        assert token not in source, f"{token} redefines the status alphabet; import it instead"


def test_a_ref_git_would_read_as_an_option_is_refused(mod: ModuleType, tmp_path: Path) -> None:
    """A leading dash makes git parse the argument as an option, not a revision.

    There is no shell here, so this is an argument-parsing guard rather than an injection one. It
    exists so the `nosec` justification on the subprocess call is true rather than conventional.
    """
    with pytest.raises(ValueError, match="parse as an option"):
        mod._git_show("--upload-pack=x", "docs/BACKLOG.md", tmp_path)
