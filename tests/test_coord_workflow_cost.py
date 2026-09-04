# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the workflow cost estimator (BACKLOG #1400).

**What these pin, and why the negative controls carry the weight.** The tool exists because
``grep -c 'agent('`` under-reported a fan-out by 4.3x. A replacement that merely *returns a bigger
number* would satisfy a naive test while being just as wrong, so the suite is built around cases
that discriminate:

- the item's own worked example must price at **13**, where the naive instrument returns 3
- a script with **no fan-out** must price at exactly the naive count, so a pass is not explained by
  "this tool always reports more"
- a script whose width is **computed at runtime** must report an UNPRICED TERM, never a quiet low
  number -- an estimator that under-reports silently reproduces #1400 one layer down
- the width multiplication itself is **mutation-proved**: break it and the worked example collapses
  back to 3, which is the very failure the item measured

**Several cases are regressions from defects found while building the tool, all of the same
silent-under-report class it exists to refuse** -- and they are the tests most worth keeping,
because each one passed review as correct before it was measured:

- an array of string literals counted one element short, because masking blanks string content and
  made the last element indistinguishable from a trailing comma
- an inline ``[...].map()`` fan read as a list of thunks and priced at zero
- ``Promise.all(ROWS.map(...))`` priced at 1 and reported EXACT, because ``.map()`` was recognised
  only as a direct argument of ``parallel()``
- one space after ``parallel(`` turned a known array into a runtime width
- a ``for (const x of ROWS)`` fan reported as an unknown loop

The residue check that catches the general case is itself mutation-proved, since an honesty guard
nobody can see fail is not a guard.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "coord" / "workflow_cost.py"


def _load(source: str | None = None, name: str = "coord_workflow_cost") -> ModuleType:
    """Import the tool, optionally from MUTATED source, so a mutant can be driven like the real one."""
    if source is None:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        return mod
    mod = ModuleType(name)
    mod.__file__ = str(_SCRIPT)
    # Register BEFORE exec: the tool uses `from __future__ import annotations`, so @dataclass
    # resolves its field annotations as strings by looking the module up in sys.modules. Without
    # this the mutant dies in dataclasses rather than in the assertion under test.
    sys.modules[name] = mod
    exec(compile(source, str(_SCRIPT), "exec"), mod.__dict__)  # noqa: S102
    return mod


@pytest.fixture(scope="module")
def mod() -> ModuleType:
    return _load()


# ------------------------------------------------------------------------------------------------
# The item's worked example
# ------------------------------------------------------------------------------------------------


def test_the_worked_example_prices_at_thirteen_not_three(mod: ModuleType) -> None:
    """BACKLOG #1400's own measurement: 3 call sites, a 6-element array, 13 agents started.

    The original script is not in this repository and was not recoverable, so ``SELF_TEST_SCRIPT``
    reconstructs the SHAPE its three published numbers force: two six-wide fans plus a lone
    synthesis agent. Every figure asserted here is quoted from the item.
    """
    cost = mod.price_script(mod.SELF_TEST_SCRIPT)
    assert cost.agents == 13
    assert mod.naive_agent_grep(mod.SELF_TEST_SCRIPT) == 3
    assert cost.exact, "every width in the worked example is a literal, so the total is a count"


def test_the_under_report_ratio_is_the_one_the_item_measured(mod: ModuleType) -> None:
    naive = mod.naive_agent_grep(mod.SELF_TEST_SCRIPT)
    priced = mod.price_script(mod.SELF_TEST_SCRIPT).agents
    assert round(priced / naive, 1) == 4.3


def test_the_fan_width_comes_from_the_array_not_the_call_site(mod: ModuleType) -> None:
    """The two six-wide fans must be reported at the ``.map()`` lines, not at ``const ROWS``.

    This is the property the naive instrument lacks: it reads the call site and never reaches the
    declaration that multiplies it. Asserted on ``width``/``depth``, which are structured data --
    ``form`` is display prose and pinning a sentence would redden this leg on a wording change.
    """
    script = mod.SELF_TEST_SCRIPT
    decl_line = script[: script.index("const ROWS")].count("\n") + 1

    fans = [s for s in mod.price_script(script).sites if s.width > 1]
    assert [s.width for s in fans] == [6, 6]
    assert all(s.depth == 1 for s in fans)
    assert all(s.line > decl_line for s in fans), (
        "the fan is reported where the agents start, while the width comes from a declaration "
        "further up -- the separation the naive instrument cannot cross"
    )


# ------------------------------------------------------------------------------------------------
# The discriminating control -- a pass must not be explained by "always reports more"
# ------------------------------------------------------------------------------------------------


def test_with_no_fan_out_the_naive_count_is_correct_and_this_tool_agrees(mod: ModuleType) -> None:
    """The negative control. Without it, a tool that always inflates would pass every other test."""
    cost = mod.price_script(mod.SELF_TEST_FLAT)
    assert cost.agents == mod.naive_agent_grep(mod.SELF_TEST_FLAT) == 2
    assert cost.exact


def test_a_comment_or_a_prompt_string_is_not_a_call_site(mod: ModuleType) -> None:
    """The naive grep counts both. This tool must not, or it trades one wrong number for another."""
    script = (
        "export const meta = { name: 'x', description: 'y' }\n"
        "// a comment mentioning agent( which starts nothing\n"
        "const note = 'a prompt mentioning agent( which starts nothing'\n"
        "const only = await agent('the one real call')\n"
    )
    assert mod.naive_agent_grep(script) == 3
    assert mod.price_script(script).agents == 1


# ------------------------------------------------------------------------------------------------
# pipeline() -- width times depth, said out loud
# ------------------------------------------------------------------------------------------------


def test_a_pipeline_costs_items_times_stages(mod: ModuleType) -> None:
    """Every item runs every stage, so BOTH factors sit outside the ``agent()`` calls."""
    script = (
        "const ROWS = [1, 2, 3, 4, 5, 6]\n"
        "const out = await pipeline(ROWS, r => agent('one'), r => agent('two'), r => agent('three'))\n"
    )
    cost = mod.price_script(script)
    assert cost.agents == 18
    assert mod.naive_agent_grep(script) == 1
    site = cost.sites[0]
    assert (site.width, site.depth) == (6, 3)


def test_a_nested_fan_multiplies_rather_than_adds(mod: ModuleType) -> None:
    """A 3-lens panel inside a 4-wide fan is 12 agents, not 7."""
    script = (
        "const ITEMS = [1, 2, 3, 4]\n"
        "const LENSES = ['a', 'b', 'c']\n"
        "await parallel(ITEMS.map(i => () => parallel(LENSES.map(l => () => agent('judge')))))\n"
    )
    assert mod.price_script(script).agents == 12


# ------------------------------------------------------------------------------------------------
# The two silent under-reports found while building this
# ------------------------------------------------------------------------------------------------


def test_an_array_of_string_literals_counts_every_element(mod: ModuleType) -> None:
    """Regression: masking blanks string CONTENT, so ``['a','b','c']`` becomes ``[   ,   ,   ]``.

    Testing the masked text for a trailing element cannot tell the third string from a trailing
    comma, and the width came back 2. The count must be taken from the raw text.
    """
    script = "const DIMS = ['a', 'b', 'c']\nawait parallel(DIMS.map(d => () => agent(d)))\n"
    assert mod.price_script(script).agents == 3


def test_a_trailing_comma_does_not_invent_an_element(mod: ModuleType) -> None:
    """The other side of that fix: reading the raw text must not turn ``[1, 2, 3,]`` into four."""
    script = "const ROWS = [1, 2, 3,]\nawait parallel(ROWS.map(r => () => agent(r)))\n"
    assert mod.price_script(script).agents == 3


def test_an_inline_literal_fanned_by_map_is_not_read_as_a_thunk_list(mod: ModuleType) -> None:
    """Regression: ``parallel(['a','b','c'].map(cb))`` was priced at 0.

    Reading only the leading ``[`` classified it as a literal list of three THUNKS, each of which
    contains no ``agent()`` call because the real call lives in the map callback. It reported zero
    and said nothing, which is the exact failure mode this tool exists to refuse.
    """
    script = "await parallel(['correctness', 'security', 'repro'].map(l => () => agent(l)))\n"
    cost = mod.price_script(script)
    assert cost.agents == 3
    assert cost.exact


def test_a_map_fan_is_priced_wherever_it_appears_not_only_inside_parallel(
    mod: ModuleType,
) -> None:
    """Regression: ``Promise.all(ROWS.map(r => agent(r)))`` priced at 1 and reported EXACT.

    ``.map()`` was recognised only as the direct argument of ``parallel()``, so the most ordinary
    plain-JavaScript fan-out reproduced this tool's own headline failure with a straight face. The
    fix scans ``.map`` as a construct in its own right and resolves its receiver by walking left.
    """
    script = "const ROWS = [1, 2, 3, 4, 5, 6]\nawait Promise.all(ROWS.map(r => agent(r)))\n"
    cost = mod.price_script(script)
    assert cost.agents == 6
    assert cost.exact
    assert mod.naive_agent_grep(script) == 1


def test_whitespace_before_the_receiver_does_not_lose_the_width(mod: ModuleType) -> None:
    """Regression: one space after ``parallel(`` made a known array read as a runtime width.

    The old resolver added the argument's leading whitespace twice while computing the callback
    offset, so it worked only when there was none.
    """
    script = "const ROWS = [1, 2, 3]\nawait parallel( ROWS.map(r => () => agent(r)))\n"
    cost = mod.price_script(script)
    assert cost.agents == 3
    assert cost.exact


def test_a_for_of_over_a_literal_array_is_a_fan_not_an_unknown(mod: ModuleType) -> None:
    """A loop over a known array has a known width; calling it unknown buries the real findings."""
    script = "const ROWS = [1, 2, 3, 4]\nfor (const r of ROWS) { await agent(r) }\n"
    cost = mod.price_script(script)
    assert cost.agents == 4
    assert cost.exact


def test_array_from_supplies_a_width(mod: ModuleType) -> None:
    """The refuter-panel shape from the workflow docs: N identical agents, width in the spec."""
    script = "await parallel(Array.from({length: 3}, () => () => agent('refute')))\n"
    cost = mod.price_script(script)
    assert cost.agents == 3
    assert cost.exact


def test_a_literal_list_of_thunks_sums_rather_than_multiplies(mod: ModuleType) -> None:
    """``parallel([t1, t2])`` is two distinct bodies, not one body twice."""
    script = "await parallel([() => agent('a'), () => agent('b'), () => agent('c')])\n"
    cost = mod.price_script(script)
    assert cost.agents == 3
    assert cost.exact


def test_a_filtered_chain_is_unknown_because_a_filter_changes_the_count(mod: ModuleType) -> None:
    """The receiver walk must not mistake ``fresh.filter(f).map(cb)`` for a known-width fan."""
    script = "const R = [1, 2, 3]\nawait parallel(R.filter(x => x.ok).map(b => () => agent(b)))\n"
    cost = mod.price_script(script)
    assert not cost.exact
    assert [u.kind for u in cost.unknowns] == ["dynamic-width"]


# ------------------------------------------------------------------------------------------------
# Honesty about what a static read cannot see
# ------------------------------------------------------------------------------------------------


def test_an_agent_no_priced_call_accounts_for_is_reported(mod: ModuleType) -> None:
    """The catch-all. Without it, "unrecognised construct" and "costs nothing" are one state.

    ``ROWS.map(agent)`` passes the hook as a VALUE, so it matches no call pattern anywhere in the
    scanner. An enumeration of known shapes cannot catch it by construction; only a residue check
    over what the pricer failed to attribute can.
    """
    script = "const ROWS = [1, 2, 3]\nconst handles = ROWS.map(agent)\n"
    cost = mod.price_script(script)
    assert not cost.exact
    assert [u.kind for u in cost.unknowns] == ["unattributed"]


def test_an_unbalanced_call_stops_the_scan_loudly(mod: ModuleType) -> None:
    """A truncated read must never render as a clean one.

    If an unreadable construct were skipped silently, one mask desync would cut the scan short
    while the report still said "exact" over a file it never finished.
    """
    script = "await parallel(ROWS.map(r => () => agent(r))\n"
    cost = mod.price_script(script)
    assert not cost.exact
    assert "unreadable" in {u.kind for u in cost.unknowns}


def test_every_priced_agent_is_attributed_so_the_residue_stays_quiet(mod: ModuleType) -> None:
    """The catch-all's negative control: it must not fire on scripts the pricer fully understood.

    A residue check that always fires is a residue check nobody reads.
    """
    for script in (mod.SELF_TEST_SCRIPT, mod.SELF_TEST_FLAT):
        assert not [u for u in mod.price_script(script).unknowns if u.kind == "unattributed"]


def test_a_runtime_width_is_named_rather_than_silently_priced_low(mod: ModuleType) -> None:
    script = "await parallel(discovered.map(d => () => agent('work ' + d)))\n"
    cost = mod.price_script(script)
    assert not cost.exact
    assert [u.kind for u in cost.unknowns] == ["dynamic-width"]
    assert cost.unknowns[0].per_unit == 1, "the per-item cost IS known and must be reported"


def test_a_loop_is_named_with_its_per_iteration_cost(mod: ModuleType) -> None:
    script = (
        "const FINDERS = [1, 2, 3, 4]\n"
        "while (dry < 2) {\n"
        "  await parallel(FINDERS.map(f => () => agent('find')))\n"
        "}\n"
    )
    cost = mod.price_script(script)
    assert not cost.exact
    loops = [u for u in cost.unknowns if u.kind == "loop"]
    assert len(loops) == 1
    assert loops[0].per_unit == 4


def test_a_loop_that_starts_no_agents_is_not_reported(mod: ModuleType) -> None:
    """Ordinary loops must stay silent, or the real findings drown in noise and get ignored."""
    script = "for (const x of xs) { total += x }\nawait agent('one')\n"
    cost = mod.price_script(script)
    assert cost.agents == 1
    assert cost.exact


def test_a_nested_workflow_is_named_as_living_in_another_script(mod: ModuleType) -> None:
    script = "const r = await workflow('some-other-workflow', {x: 1})\n"
    cost = mod.price_script(script)
    assert [u.kind for u in cost.unknowns] == ["nested-workflow"]
    assert cost.agents == 0


def test_a_floor_is_never_presented_as_a_count(mod: ModuleType) -> None:
    """The rendered report must say FLOOR, and must not claim the naive count was right.

    A floor of 0 against a naive count of 1 would otherwise print "the naive count is correct
    here" -- an instrument reassuring a launcher with a number it cannot back, which is #1400
    verbatim.
    """
    script = "await parallel(discovered.map(d => () => agent('work')))\n"
    text = mod.render(mod.price_script(script), script, "<test>")
    assert "FLOOR" in text
    assert "UNPRICED TERMS (1)" in text
    assert "the naive count is correct here" not in text


def test_an_exact_read_says_so(mod: ModuleType) -> None:
    text = mod.render(mod.price_script(mod.SELF_TEST_SCRIPT), mod.SELF_TEST_SCRIPT, "<test>")
    assert "TOTAL (exact)" in text
    assert "UNPRICED TERMS: none" in text
    assert "FLOOR" not in text


# ------------------------------------------------------------------------------------------------
# Mutation proof -- the multiplication is the whole tool, so breaking it must go red
# ------------------------------------------------------------------------------------------------


def _mutate(pattern: str, replacement: str, name: str) -> ModuleType:
    """Load the tool with one expression rewritten, refusing to run if the seam moved.

    Matched by REGEX rather than by an indented literal, so a re-indent or a move between functions
    does not silently turn a negative control into a no-op. The count assertion is the guard: a
    pattern matching zero times, or more than once, fails here with a message naming the cause
    instead of failing later as a confusing arithmetic mismatch.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    mutant_source, count = re.subn(pattern, replacement, source)
    assert count == 1, f"the mutation seam {pattern!r} matched {count} times; re-point this test"
    return _load(mutant_source, name=name)


def test_breaking_the_width_multiplication_collapses_the_example_to_the_naive_count(
    mod: ModuleType,
) -> None:
    """Drop the ``* width`` and the worked example prices at 3 -- the failure the item measured.

    This is the negative control for every assertion above. Without it, "13" is a number the suite
    asserts rather than a number the arithmetic produces.
    """
    mutant = _mutate(r"self\.agents \* width", "self.agents", "coord_workflow_cost_mutant")
    assert mutant.price_script(mutant.SELF_TEST_SCRIPT).agents == 3, (
        "a mutant that ignores fan width must reproduce the 4.3x under-report"
    )
    assert mutant._self_test() == 1, "the tool's own self-test must fail on this mutant"
    assert mod.price_script(mod.SELF_TEST_SCRIPT).agents == 13


def test_breaking_the_array_element_count_is_caught(mod: ModuleType) -> None:
    """The other half of the arithmetic: the width itself must come from the literal's length."""
    mutant = _mutate(
        r'return len\(_split_top_level\(ctx, lead \+ 1, close\)\), "inline array"',
        'return 1, "inline array"',
        "coord_workflow_cost_mutant2",
    )
    script = "await parallel(['a', 'b', 'c'].map(l => () => agent(l)))\n"
    assert mutant.price_script(script).agents == 1
    assert mod.price_script(script).agents == 3


def test_disabling_the_residue_check_is_caught(mod: ModuleType) -> None:
    """The catch-all is itself mutation-proved, because a silent honesty guard is no guard.

    If ``_residue`` returned nothing, an unrecognised construct would price at zero and the report
    would call it exact -- which is the failure BACKLOG #1400 describes, one layer down.
    """
    mutant = _mutate(r"cost\.unknowns \+ _residue\(ctx\)", "cost.unknowns", "cwc_mutant3")
    script = "const ROWS = [1, 2, 3]\nconst handles = ROWS.map(agent)\n"
    assert mutant.price_script(script).exact, "the mutant must go quiet, or this proves nothing"
    assert not mod.price_script(script).exact


# ------------------------------------------------------------------------------------------------
# The tool as a process -- what a launcher actually runs
# ------------------------------------------------------------------------------------------------


def test_self_test_passes_as_a_subprocess() -> None:
    """If the built-in positive control cannot pass, no number this tool prints is evidence."""
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--self-test"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    # Both numbers, and NOT `"3" in stdout` -- that is a substring of "13" and would pass on the
    # priced figure alone, reading as a two-sided check while testing one side.
    assert "priced 13" in proc.stdout
    assert "naive grep 3" in proc.stdout


def test_strict_exits_non_zero_only_when_a_term_is_unpriced(
    mod: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Driven in-process: ``main`` returns the code and only ``__main__`` raises SystemExit.

    Four subprocesses cost 3.6 seconds here and measured almost entirely as interpreter startup.
    The one process-level control above is what proves the entry point works when spawned.
    """
    exact = tmp_path / "exact.js"
    exact.write_text("const R = [1, 2]\nawait parallel(R.map(r => () => agent(r)))\n", "utf-8")
    fuzzy = tmp_path / "fuzzy.js"
    fuzzy.write_text("await parallel(found.map(r => () => agent(r)))\n", encoding="utf-8")

    assert mod.main([str(exact)]) == 0
    assert mod.main([str(exact), "--strict"]) == 0
    assert mod.main([str(fuzzy)]) == 0, "a report is not a gate -- an unpriced term must not fail"
    assert mod.main([str(fuzzy), "--strict"]) == 1
    capsys.readouterr()


def test_json_output_carries_the_floor_flag(mod: ModuleType, tmp_path: Path) -> None:
    """``to_json`` is a public entry point for a programmatic caller and must pin its contract."""
    payload = mod.to_json(mod.price_script(mod.SELF_TEST_SCRIPT), mod.SELF_TEST_SCRIPT, "<t>")
    assert payload["agents"] == 13
    assert payload["exact"] is True
    assert payload["naive_agent_grep"] == 3
    assert payload["unpriced"] == []

    script = "await parallel(found.map(r => () => agent(r)))\n"
    fuzzy = mod.to_json(mod.price_script(script), script, "<t>")
    assert fuzzy["exact"] is False
    assert [u["kind"] for u in fuzzy["unpriced"]] == ["dynamic-width"]
