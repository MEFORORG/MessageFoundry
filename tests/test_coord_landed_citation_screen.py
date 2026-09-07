# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the landed-citation screen -- the tool that asks the tree instead of the banner.

**THE WEIGHT HERE IS ON THE CONTROLS, NOT ON THE ROWS.** A screen of this shape has two degenerate
failures that both produce a confident, uniform, plausible answer:

* it matches NOTHING -- a broken pattern, an unfetched ref, a mistyped path list -- and every row
  comes back clear, which reads as *"nothing is built"*;
* it matches EVERYTHING, and every row comes back cited, which reads as *"it is all built"*.

Neither is visible in a listing of the rows. Only a pinned pair separates them, so the tests that
matter most below drive both degenerate sweeps and assert the controls REDDEN. A screen whose
controls cannot fail is decoration, and its numbers are worth nothing.

The second theme is that this test file and the module it tests both live INSIDE the paths the
sweep searches. A source line writing a control number in the joined citation form would be found
by the very sweep it is a control for, and the negative arm would flip the day it landed.
:func:`test_no_control_number_is_written_as_a_citation` pins that against this change's own files.
It deliberately does not sweep the whole repository: a builder legitimately working the pinned
negative row would then be blocked by an unrelated test, and the run-time control already reports
that case with a message naming the fix.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCREEN = _ROOT / "scripts" / "coord" / "landed_citation_screen.py"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def screen_mod() -> ModuleType:
    return _load(_SCREEN, "landed_citation_screen")


@pytest.fixture(scope="module")
def live_ref(screen_mod: ModuleType) -> str:
    """A real tree to ask.

    ``origin/main`` is the subject, and the fallbacks exist so this never SKIPS: a control that
    quietly does not run is the same nothing as a control that cannot fail. The pinned answers hold
    on any of these trees, because neither control number is written into this change.
    """
    for ref in (screen_mod.DEFAULT_REF, "main", "HEAD"):
        done = subprocess.run(
            ["git", "-C", str(_ROOT), "rev-parse", "--verify", f"{ref}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode == 0:
            return str(ref)
    pytest.fail("no git ref resolved, so nothing below could have measured a tree")


def _sight(screen_mod: ModuleType, num: int, *, strict: bool) -> object:
    return screen_mod.Sighting(num=num, path="scripts/x.py", line=1, strict=strict)


def test_the_modules_own_self_test_passes(screen_mod: ModuleType) -> None:
    """It carries the degenerate-sweep arms, so a green here is the first thing to trust."""
    assert screen_mod._self_test() == 0


def test_a_sweep_that_found_nothing_fails_the_controls(screen_mod: ModuleType) -> None:
    """THE FALSE ZERO, WHICH THE ROW SAYS HAS FIRED TWICE IN ONE SESSION.

    An empty sweep is exactly what a broken needle, an unfetched ref or a wrong path list produces,
    and every row under it reports clear. Without the positive arm that report is indistinguishable
    from a tree where genuinely nothing is cited.
    """
    failures = screen_mod.check_controls({})
    assert failures, "an empty sweep must be refused, never reported as a clean ledger"
    positives = [c.num for c in screen_mod.CONTROLS if c.expect_cited]
    assert positives, "there must BE a positive arm; a control set of only negatives cannot detect"
    joined = " ".join(failures)
    for num in positives:
        assert str(num) in joined, f"the refusal must name the arm that failed; got {joined!r}"


def test_a_sweep_that_matched_every_row_fails_the_controls(screen_mod: ModuleType) -> None:
    """The mirror failure, and the reason a positive arm alone is not enough.

    A needle that matches any line at all reports the whole ledger as cited. That answer is uniform
    and confident and would flag every row in a wave, which at this tool's real flag rate is
    indistinguishable from a bad day.
    """
    everything = {c.num: [_sight(screen_mod, c.num, strict=True)] for c in screen_mod.CONTROLS}
    failures = screen_mod.check_controls(everything)
    assert failures, "a sweep matching every control must be refused"
    negatives = [c.num for c in screen_mod.CONTROLS if not c.expect_cited]
    assert negatives, "there must BE a negative arm; a control set of only positives cannot detect"
    joined = " ".join(failures)
    assert any(str(num) in joined for num in negatives)


def test_a_bare_needle_that_reached_the_sentinel_fails_the_controls(screen_mod: ModuleType) -> None:
    """The same flood one level down, where no rate-shaped guard can see it.

    Measured 2026-09-03 against ``origin/main``: widening the bare extractor to plain digits moves
    the corpus from 130 to 138 flagged of 275 open rows. A guard watching the flag rate, or watching
    that some rows stay clear, sees eight rows move and stays green. The weaker level therefore has
    exactly one control -- the sentinel, whose number no item and no pull request can hold -- and
    this is the test that says so out loud.
    """
    graded = [c for c in screen_mod.CONTROLS if c.expect_bare is not None]
    assert graded, "the MENTIONED level would have NO control at all without one of these"

    flooded = {
        c.num: [_sight(screen_mod, c.num, strict=True)]
        for c in screen_mod.CONTROLS
        if c.expect_cited
    }
    for control in graded:
        flooded[control.num] = [_sight(screen_mod, control.num, strict=False)]

    failures = screen_mod.check_controls(flooded)
    assert failures, "a bare needle reaching the sentinel must be refused"
    assert any("bare form" in f for f in failures)


def test_a_correct_sweep_passes_the_controls(screen_mod: ModuleType) -> None:
    """The untouched baseline. Without it the two arms above are satisfied by a check that always
    fails, which detects nothing and refuses everything."""
    healthy = {
        c.num: [_sight(screen_mod, c.num, strict=True)]
        for c in screen_mod.CONTROLS
        if c.expect_cited
    }
    assert screen_mod.check_controls(healthy) == []


def test_the_joined_and_bare_forms_stay_apart(screen_mod: ModuleType) -> None:
    """A bare ``#N`` may name a pull request, so it must never be reported at the joined form's
    strength. Row #1375 is why the weaker level exists at all and why it is still weaker: the two
    bare hits it has on main assert a fix that the row refutes from source."""
    joined = screen_mod.screen([7], {7: [_sight(screen_mod, 7, strict=True)]})[0]
    bare = screen_mod.screen([7], {7: [_sight(screen_mod, 7, strict=False)]})[0]
    none = screen_mod.screen([7], {})[0]

    assert joined.level == screen_mod.CITED
    assert bare.level == screen_mod.MENTIONED
    assert none.level == screen_mod.CLEAR
    assert joined.level != bare.level, "collapsing the two levels is the whole defect"
    assert joined.flagged and bare.flagged and not none.flagged


def test_one_joined_hit_outranks_any_number_of_bare_ones(screen_mod: ModuleType) -> None:
    both = {
        7: [
            _sight(screen_mod, 7, strict=False),
            _sight(screen_mod, 7, strict=False),
            _sight(screen_mod, 7, strict=True),
        ]
    }
    assert screen_mod.screen([7], both)[0].level == screen_mod.CITED


def test_an_unresolvable_ref_is_an_instrument_error_not_an_empty_result(
    screen_mod: ModuleType,
) -> None:
    """The failure mode that looks most like data. A ref that does not exist yields no lines, and a
    caller that did not check would print a clean ledger over a tree it never read."""
    with pytest.raises(screen_mod.InstrumentError) as caught:
        screen_mod.resolve_ref(_ROOT, "refs/heads/no-such-ref-for-this-test")
    assert "resolve" in str(caught.value)


def test_the_pinned_controls_hold_against_a_real_tree(
    screen_mod: ModuleType, live_ref: str
) -> None:
    """THE CONTROL PAIR THE ROW NAMES, run against real git rather than a fixture.

    A known-built row must come back cited and a known-unbuilt one must come back clear. If this
    reddens, read the ledger before reading the module: a pinned negative row can be built for real,
    and then the control is reporting that the corpus moved.
    """
    sightings = screen_mod.sweep(_ROOT, live_ref)
    assert screen_mod.check_controls(sightings) == []


def test_the_one_pass_sweep_agrees_with_the_rows_own_per_number_command(
    screen_mod: ModuleType, live_ref: str
) -> None:
    """CONFIRM THE INSTRUMENT ANSWERS THE QUESTION THAT WAS ASKED.

    The row publishes a per-candidate ``git grep -l`` as the workaround. This module replaces it
    with one sweep plus a Python regex, and those are two different programs that could disagree on
    a word boundary. Substituting a faster instrument is only safe if the substitution is checked.
    """
    sightings = screen_mod.sweep(_ROOT, live_ref)
    assert screen_mod.check_agreement(_ROOT, live_ref, sightings) == []


def test_the_real_tree_splits_the_open_rows_rather_than_answering_uniformly(
    screen_mod: ModuleType, live_ref: str
) -> None:
    """A corpus-level control that cannot go stale the way a pinned number can.

    No exact flag rate is pinned, because it moves with every merge and a pinned count would go red
    on honest work. What must hold is that the answer DISCRIMINATES: some open rows flag and some do
    not. All-clear and all-flagged are the two ways this tool dies silently.
    """
    sightings = screen_mod.sweep(_ROOT, live_ref)
    findings = screen_mod.screen(screen_mod.open_rows(_ROOT), sightings)
    assert len(findings) >= screen_mod.MIN_ITEMS
    flagged = sum(1 for f in findings if f.flagged)
    assert 0 < flagged < len(findings), (
        f"the screen answered uniformly over {len(findings)} open rows ({flagged} flagged), which "
        f"is what both degenerate sweeps look like"
    )


def test_a_flagged_row_still_exits_zero(
    screen_mod: ModuleType, live_ref: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST BE READ, NEVER A VERDICT, and the exit code is where that promise is kept.

    Measured on this corpus, roughly two open rows in five flag. A tool that exited non-zero on a
    finding would refuse most waves it was pointed at, and would be switched off within a day.
    """
    cited = next(c.num for c in screen_mod.CONTROLS if c.expect_cited)
    code = screen_mod.main([str(cited), "--ref", live_ref, "--root", str(_ROOT)])
    out = capsys.readouterr().out
    assert code == 0, "a flagged row is a reason to read the row, not a refusal"
    assert screen_mod.CITED in out
    assert "MUST BE READ, NOT A VERDICT" in out
    assert "is not a completion" in out, (
        "the caveat has to travel with the finding, not sit in docs"
    )


def test_a_failed_control_prints_no_row_result_at_all(
    screen_mod: ModuleType,
    live_ref: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """THE CAVEAT DOES NOT SURVIVE THE LISTING, SO THERE MUST BE NO LISTING.

    A reader handed plausible rows under a failed control keeps the rows and forgets the warning.
    So a broken instrument reports nothing about any row and exits 1, which is the only non-zero
    exit this tool has.
    """
    inverted = tuple(
        screen_mod.Control(c.num, not c.expect_cited, c.why) for c in screen_mod.CONTROLS
    )
    monkeypatch.setattr(screen_mod, "CONTROLS", inverted)
    cited = next(c.num for c in screen_mod.CONTROLS if not c.expect_cited)

    code = screen_mod.main([str(cited), "--ref", live_ref, "--root", str(_ROOT)])
    captured = capsys.readouterr()

    assert code == 1
    assert "INSTRUMENT ERROR" in captured.err
    assert screen_mod.CITED not in captured.out
    assert screen_mod.CLEAR not in captured.out


def test_no_control_number_is_written_as_a_citation() -> None:
    """THE INSTRUMENT MUST NOT ENTER ITS OWN DATA.

    This module and this test both live under ``scripts/`` and ``tests/``, which the sweep searches.
    Writing a control number in the joined citation form here would make the file answer the
    question it is asking: the positive arm would pass for the wrong reason, and the negative arm
    would flip the moment this change landed. The needle is therefore built from the number at run
    time, and this pins that it stayed that way.
    """
    screen_mod = _load(_SCREEN, "landed_citation_screen_contamination")
    for path in (_SCREEN, Path(__file__)):
        text = path.read_text(encoding="utf-8")
        for control in screen_mod.CONTROLS:
            joined = f"{screen_mod._STRICT_PREFIX}{control.num}"
            assert joined not in text, (
                f"{path.name} writes the joined citation form for control #{control.num}, so the "
                f"sweep would find this very file and the control would measure itself"
            )
