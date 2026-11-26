# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import io
import json
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


# ------------------------------------------------------------------------------------------------
# BACKLOG #5601: a literal's length is a width only while nothing else can change it
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "script"),
    [
        (
            "spread",
            "const A = [1, 2]\nconst R = [...A, ...found]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "push after an empty declaration",
            "const R = []\nfor (const x of found) R.push(x)\n"
            "await parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "reassigned",
            "let R = [1]\nR = found\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "declared twice",
            "function f() { const R = [1, 2, 3, 4, 5] }\nconst R = [1]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "index-assigned",
            "const R = [1]\nR[found] = 2\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "length-assigned",
            "const R = [1, 2]\nR.length = n\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "inline spread",
            "await parallel([...found, 1].map(r => () => agent(r)))\n",
        ),
        (
            "for-of over a pushed array",
            "const R = []\nR.unshift(x)\nfor (const r of R) { await agent(r) }\n",
        ),
    ],
)
def test_a_literal_whose_length_can_change_is_not_an_exact_width(
    mod: ModuleType, label: str, script: str
) -> None:
    """Regression (BACKLOG #5601): each of these shapes recorded the literal's own length.

    ``const R = []`` filled by ``push`` priced at ZERO and said exact, so ``--strict`` passed the
    very dynamic-width fan it exists to flag. A width is only a count while no other line in the
    file can change it.
    """
    cost = mod.price_script(script)
    assert not cost.exact, f"{label}: priced {cost.agents} and called it exact"
    # A for...of whose width is unknown falls back to the loop term, which says the same thing.
    assert {"dynamic-width", "loop"} & {u.kind for u in cost.unknowns}, label


def test_a_literal_nothing_changes_keeps_its_exact_width(mod: ModuleType) -> None:
    """The negative control for #5601: provable reads of the name keep the width exact."""
    script = (
        "const R = [1, 2, 3]\n"
        "if (R.length == 3) { log(R[0], R?.join(', '), [...R]) }\n"
        "for (const x of R) { log(x) }\n"
        "const f = R => 1\n"
        "await parallel(R.filter(Boolean) && R.map(r => () => agent(r)))\n"
    )
    cost = mod.price_script(script)
    assert cost.agents == 3
    assert cost.exact


# ------------------------------------------------------------------------------------------------
# BACKLOG #5602: an agent inside a named helper costs what its callers multiply it by
# ------------------------------------------------------------------------------------------------


def test_a_helper_called_from_a_fan_is_multiplied_by_the_fan(mod: ModuleType) -> None:
    """Regression (BACKLOG #5602): the helper's one ``agent()`` priced at 1 and reported exact.

    The linear scan attributed the call inside the body and never saw ``review(r)`` as a cost,
    so a six-wide fan over the helper priced at one agent with an empty residue.
    """
    script = (
        "const R = [1, 2, 3, 4, 5, 6]\n"
        "async function review(r) {\n  return agent(r)\n}\n"
        "await parallel(R.map(r => () => review(r)))\n"
    )
    cost = mod.price_script(script)
    assert cost.agents == 6
    assert cost.exact


@pytest.mark.parametrize(
    "definition",
    [
        "function review(r) { return agent(r) }",
        "const review = async (r) => { return agent(r) }",
        "const review = r => agent(r)",
        "let review = async function (r) { return agent(r) }",
    ],
)
def test_every_helper_binding_form_is_resolved_at_its_call_sites(
    mod: ModuleType, definition: str
) -> None:
    script = (
        f"{definition}\n"
        "const R = [1, 2, 3]\n"
        "await parallel(R.map(r => () => review(r)))\n"
        "await review('one more')\n"
    )
    cost = mod.price_script(script)
    assert cost.agents == 4, definition
    assert cost.exact, definition


def test_a_helper_calling_a_helper_multiplies_through(mod: ModuleType) -> None:
    script = (
        "const LENSES = ['a', 'b']\n"
        "const one = l => agent(l)\n"
        "async function panel() { return parallel(LENSES.map(l => () => one(l))) }\n"
        "const R = [1, 2, 3]\n"
        "await parallel(R.map(r => () => panel()))\n"
    )
    cost = mod.price_script(script)
    assert cost.agents == 6
    assert cost.exact


@pytest.mark.parametrize(
    ("label", "script", "agents"),
    [
        (
            "a prompt-builder arrow whose body is a template",
            "const prompt = r => `Review ${r}`\nconst R = [1, 2, 3]\n"
            "await parallel(R.map(r => () => agent(prompt(r))))\nawait agent('one more')\n",
            4,
        ),
        (
            "a string constant just before a helper",
            "const SYSTEM = `You review rows.`\n"
            "async function review(r) { return agent(SYSTEM + r) }\n"
            "const R = [1, 2, 3]\nawait parallel(R.map(r => () => review(r)))\n",
            3,
        ),
        (
            "a named function expression used in place",
            "const R = [1, 2, 3]\nawait Promise.all(R.map(function review(r) { return agent(r) }))\n",
            3,
        ),
        (
            "a comment between a helper's head and its body",
            "const R = [1, 2, 3]\nasync function review(r) /* one row */ { return agent(r) }\n"
            "await parallel(R.map(r => () => review(r)))\n",
            3,
        ),
        (
            "a documented helper",
            "const R = [1, 2, 3]\n/** Review one row. */\nfunction review(r) { return agent(r) }\n"
            "await parallel(R.map(r => () => review(r)))\n",
            3,
        ),
        (
            "a multi-line template inside an expression-bodied helper",
            "const R = [1, 2, 3]\nconst review = r => skip(r) ? `nothing\nto do` : agent(r)\n"
            "await parallel(R.map(r => () => review(r)))\n",
            3,
        ),
        (
            "a trailing comment ending in a continuation character",
            "const fmt = r => `row ${r}` // format one row.\nawait agent('synthesise')\n",
            1,
        ),
        (
            "a named function expression bound to the same name",
            "const R = [1, 2, 3]\nconst review = function review(r) { return agent(r) }\n"
            "await parallel(R.map(r => () => review(r)))\n",
            3,
        ),
        (
            "an immediately invoked arrow",
            "await (async () => { const R = [1, 2, 3]; await parallel(R.map(r => () => agent(r))) })()\n",
            3,
        ),
        (
            "an export default entry point",
            "export default async function main() {\n  const R = [1, 2, 3]\n"
            "  await parallel(R.map(r => () => agent(r)))\n}\n",
            3,
        ),
        (
            "an array length read inside an interpolation",
            "const R = [1, 2]\nawait parallel(R.map(r => () => agent(`${R.length} rows`)))\n",
            2,
        ),
        (
            "a helper that starts nothing, passed as a value",
            "const fmt = x => x + 1\nconst show = r => fmt(r)\nlog([1].map(show))\nawait agent(1)\n",
            1,
        ),
        (
            "an entry point written as an export default arrow",
            "export default async () => {\n  const R = [1, 2, 3]\n"
            "  await parallel(R.map(r => () => agent(r)))\n}\n",
            3,
        ),
        ("an export default expression arrow", "export default () => agent(1)\n", 1),
        ("a module.exports arrow", "module.exports = async (args) => { await agent(1) }\n", 1),
        (
            "a local named function expression inside a fan callback",
            "const R = [1, 2, 3, 4, 5, 6]\nawait parallel(R.map(r => () => {\n"
            "  const review = function review(x) { return agent(x) }\n  return review(r)\n}))\n",
            6,
        ),
        (
            "a named function expression in place sharing a helper's name",
            "function review(r) { return agent(r) }\nconst R = [1, 2, 3, 4, 5, 6]\n"
            "await Promise.all(R.map(function review(r) { return agent(r) }))\n"
            "await review(1)\n",
            7,
        ),
        (
            "an object method sharing a helper's name",
            "function review(r) { return agent(r) }\nconst api = { review(r) { return 1 } }\n"
            "await review(1)\n",
            1,
        ),
        (
            "a class getter sharing a helper's name",
            "function review(r) { return agent(r) }\nclass A { get review() { return 1 } }\n"
            "await review(1)\n",
            1,
        ),
        (
            "a postfix increment divided inside an interpolation",
            "const s = `${ i++ / 2 }`; const t = a / b\nconst R = [1, 2, 3]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
            3,
        ),
        (
            "a postfix decrement divided inside an interpolation",
            "log(`${ n-- / total }`, x.split(/,/))\nconst R = [1, 2, 3]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
            3,
        ),
        (
            "a regex after a postfix increment and a plus",
            "const y = a++ + /`/.source\nconst R = [1, 2, 3]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
            3,
        ),
        (
            "an expression-bodied helper ending in a postfix increment",
            "let n = 0\nconst nextId = () => n++\nconst first = await agent('first')\n"
            "nextId()\nnextId()\n",
            1,
        ),
        (
            "an expression-bodied helper ending in a postfix decrement",
            "const dec = r => r.n--\nconst first = await agent('first')\n"
            "const R = [1, 2, 3, 4, 5, 6]\nR.forEach(r => dec(r))\n",
            1,
        ),
        (
            "a regex after a line comment ending in dashes",
            "const CODE_SPAN =\n  // ----------------\n  /`([^`]+)`/g\nconst R = [1, 2, 3]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
            3,
        ),
        (
            "a regex after a line comment ending in C++",
            "const x = [ // C, C++\n /'/g, await agent(1) ]\n",
            1,
        ),
        (
            "a block comment between a postfix decrement and a division",
            "const s = `${ a-- /* c */ / b }`; const q = c / d\nawait agent(1)\n",
            1,
        ),
        (
            "an unspaced regex after a postfix increment and a plus",
            "const y = a+++/`/.source\nconst R = [1, 2, 3]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
            3,
        ),
        (
            "a postfix helper followed by a line starting with a bracket",
            "let n = 0\nconst nextId = () => n++\n[1, 2, 3].forEach(x => agent(x))\n"
            "nextId()\nnextId()\n",
            3,
        ),
        (
            "a postfix increment then a binary plus continues the line",
            "let n = 0\nconst g = () => n+++\nagent(1)\ng()\ng()\n",
            2,
        ),
        (
            "a trailing prefix increment continues the line",
            "const g = (o) => 1 + ++\no[agent(1)]\ng(o)\ng(o)\n",
            2,
        ),
        (
            "a helper called in a class heritage clause",
            "function mixin(B) { agent(1); return B }\nmixin(Object)\n"
            "class A extends mixin(Object) {\n  run() { return 1 }\n}\n",
            2,
        ),
        (
            "an unclosed regex class at the end of an interpolation",
            "await agent(1)\nconst s = `${ /[abc",
            1,
        ),
        # A line that opens with a binary operator continues the one before, a postfix tail
        # included; a line ending in an operator continues whatever the next line opens with.
        (
            "a postfix tail continued by a division",
            "let n = 0\nconst g = () => n++\n / agent(1)\ng()\ng()\n",
            2,
        ),
        ("a postfix tail continued by a caret", "const g = () => n++\n ^ agent(1)\ng()\ng()\n", 2),
        ("a postfix tail continued by !=", "const g = () => n++\n != agent(1)\ng()\ng()\n", 2),
        ("a postfix tail continued by !==", "const g = () => n++\n !== agent(1)\ng()\ng()\n", 2),
        (
            "a postfix tail continued by in",
            "const g = (o) => n++\n in o[agent(1)]\ng(o)\ng(o)\n",
            2,
        ),
        (
            "a postfix tail continued by instanceof",
            "const g = (o) => n--\n instanceof o[agent(1)]\ng(o)\ng(o)\n",
            2,
        ),
        ("a value continued by a division", "const g = () => k\n / agent(1)\ng()\ng()\n", 2),
        ("a value continued by in", "const g = (o) => k\n in o[agent(1)]\ng(o)\ng(o)\n", 2),
        ("a line opening with a bare !", "const g = () => k\n!agent(1)\ng()\ng()\n", 1),
        (
            "a line opening with a word starting in",
            "const g = () => k\ninner(agent(1))\ng()\ng()\n",
            1,
        ),
        (
            "a division ending the line before ++",
            "const g = () => a /\n++n + agent(1)\ng()\ng()\n",
            2,
        ),
        ("a caret ending the line before ++", "const g = () => a ^\n++n + agent(1)\ng()\ng()\n", 2),
        (
            "a division ending the line before --",
            "const g = () => a /\n--n + agent(1)\ng()\ng()\n",
            2,
        ),
        ("a regex ending the line before ++", "const g = () => /a/\n++n + agent(1)\ng()\ng()\n", 1),
        (
            "a comment after a division ending the line",
            "const g = () => a /* c */ /\n++n + agent(1)\ng()\ng()\n",
            2,
        ),
        ("typeof ending the line", "const g = () => typeof\nagent(1)\ng()\ng()\n", 2),
        ("a property named in ending the line", "const g = () => o.in\n!agent(1)\ng()\ng()\n", 1),
        (
            "a prefix increment after typeof ending the line",
            "const g = (o) => typeof ++\no[agent(1)]\ng(o)\ng(o)\n",
            2,
        ),
        (
            "a prefix increment after in ending the line",
            "const g = (o) => k in ++\no[agent(1)]\ng(o)\ng(o)\n",
            2,
        ),
        (
            "a long comment in a class heritage clause",
            "function mixin(B) { agent(1); return B }\nmixin(Object)\n"
            "class A extends /* a comment long enough to pass any window */ mixin(Object) {\n"
            "  run() { return 1 }\n}\n",
            2,
        ),
        (
            "a deeply indented class heritage call",
            "function mixin(B) { agent(1); return B }\nmixin(Object)\nclass A extends\n"
            + " " * 48
            + "mixin(Object) {\n  run() { return 1 }\n}\n",
            2,
        ),
        (
            "an Allman object method sharing a helper's name",
            "function review(r) { return agent(r) }\nconst api = {\n  review(r)\n  {\n"
            "    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "an Allman object method after a comma",
            "function review(r) { return agent(r) }\nconst api = { a: 1,\n  review(r)\n  {\n"
            "    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "an Allman class getter sharing a helper's name",
            "function review(r) { return agent(r) }\nclass A {\n  get review()\n  {\n"
            "    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "an Allman object method in a conditional's branch",
            "function review(r) { return agent(r) }\nconst api = c ? 1 : {\n  review(r)\n  {\n"
            "    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "an Allman class method after a field",
            "function review(r) { return agent(r) }\nclass A\n{\n  x = 1\n  review(r)\n  {\n"
            "    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "an Allman class method under a heritage clause",
            "function review(r) { return agent(r) }\nclass A extends Object {\n  run() {}\n"
            "  review(r)\n  {\n    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "a call then a bare block in a block",
            "function review(r) { return agent(r) }\nif (x) {\n  review(1)\n  {\n"
            "    log(2)\n  }\n}\n",
            1,
        ),
        (
            "a helper in the heritage of a class held in a class field",
            "function review(r) { return agent(r) }\nawait review(0)\nclass Outer {\n"
            "  Inner = class extends review(Object) {}\n}\n",
            2,
        ),
        (
            "a call then a bare block in a block after an array",
            "function review(r) { return agent(r) }\nawait review(0)\nlet q = [1, 2]\n{\n"
            "  review(1)\n  {\n    log(2)\n  }\n}\n",
            2,
        ),
        (
            "a call then a bare block in a block after a regex",
            "function review(r) { return agent(r) }\nawait review(0)\nlet q = /a/\n{\n"
            "  review(1)\n  {\n    log(2)\n  }\n}\n",
            2,
        ),
        (
            "a call then a bare block in a block after a postfix increment",
            "function review(r) { return agent(r) }\nawait review(0)\nn++\n{\n"
            "  review(1)\n  {\n    log(2)\n  }\n}\n",
            2,
        ),
        (
            "a case clause after a conditional in an earlier clause",
            "function review(r) { return agent(r) }\nawait review(0)\nswitch (x) {\n"
            "  case 1:\n    y = a ? b : c\n    break\n  case 2: {\n    review(1)\n    {\n"
            "      log(2)\n    }\n  }\n}\n",
            2,
        ),
        (
            "a label after a conditional statement",
            "function review(r) { return agent(r) }\nawait review(0)\nconst v = a ? b : c\n"
            "outer: {\n  review(1)\n  {\n    log(2)\n  }\n}\n",
            2,
        ),
        (
            "a bare block after a property named default",
            "function review(r) { return agent(r) }\nawait review(0)\nconst Base = mod.default\n"
            "{\n  review(1)\n  {\n    log(2)\n  }\n}\n",
            2,
        ),
        (
            "a bare block after yield and a line break",
            "function review(r) { return agent(r) }\nawait review(0)\nfunction* f() { yield\n"
            "  {\n    review(1)\n    {\n      log(2)\n    }\n  }\n}\nf()\n",
            2,
        ),
        (
            "a class method under a heritage ending in a keyword-named method",
            "function review(r) { return agent(r) }\nclass A extends mix(B).with(M) {\n"
            "  review(r) { return 1 }\n}\nawait review(1)\n",
            1,
        ),
        (
            "a class method under a heritage ending in a keyword-named property",
            "function review(r) { return agent(r) }\nclass A extends mod.default {\n  x = 1\n"
            "  review(r) { return 1 }\n}\nawait review(1)\n",
            1,
        ),
        (
            "a class method under an optionally chained heritage",
            "function review(r) { return agent(r) }\nclass A extends ns?.Base {\n"
            "  review(r) { return 1 }\n}\nawait review(1)\n",
            1,
        ),
        (
            "an Allman object method in a conditional with a leading-dot number",
            "function review(r) { return agent(r) }\nconst api = c ?.5 : {\n  review(r)\n  {\n"
            "    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "a postfix private field named like a keyword",
            "const g = () => this.#in++\n agent(1)\ng()\ng()\n",
            1,
        ),
        (
            "a case label holding a conditional",
            "function review(r) { return agent(r) }\nawait review(0)\nswitch (x) {\n"
            "  case a ? 1 : 2: {\n    review(1)\n    {\n      log(2)\n    }\n  }\n}\n",
            2,
        ),
        (
            "an Allman object method in a nested conditional",
            "function review(r) { return agent(r) }\nconst api = c ? d ? 1 : 2 : {\n  review(r)\n"
            "  {\n    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "an Allman object method in a multi-line conditional",
            "function review(r) { return agent(r) }\nconst api = c\n  ? 1\n  : {\n  review(r)\n"
            "  {\n    return 1\n  }\n}\nawait review(1)\n",
            1,
        ),
        (
            "a class method after a regex field",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n"
            "  pat = /a+/\n  review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a class method after a postfix field",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n"
            "  n = k++\n  review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a postfix property named like a keyword, spaced from its dot",
            "const g = () => o. typeof++\n agent(1)\ng()\ng()\n",
            1,
        ),
        (
            "a property named in, spaced from its dot, ending the line",
            "const g = () => o. in\n!agent(1)\ng()\ng()\n",
            1,
        ),
        (
            "a call then a bare block in a case clause",
            "function review(r) { return agent(r) }\nswitch (x) {\n  case 1: {\n"
            "    review(1)\n    {\n      log(2)\n    }\n  }\n}\n",
            1,
        ),
        # Read by the one forward lexer: each of these was a regression of a back-scanning reader.
        (
            "a method named class, its body scanned where it is invoked",
            "function review(r) { return agent(r) }\nawait review(0)\n"
            "await parallel([() => ({ class() {\n  review(1)\n  {\n    log(2)\n  }\n} }).class()])\n",
            2,
        ),
        (
            "of used as a variable before a bare block",
            "function review(r) { return agent(r) }\nawait review(0)\nlet of = 1\nof\n{\n"
            "  review(1)\n  {\n    log(2)\n  }\n}\n",
            2,
        ),
        (
            "a class field whose value is get",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n  x = get\n"
            "  review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a class field whose value is async",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n  x = async\n"
            "  review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a heritage ending in a class expression",
            "function review(r) { return agent(r) }\nawait review(0)\n"
            "class A extends class {} {\n  review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a heritage ending in a template",
            "function review(r) { return agent(r) }\nawait review(0)\n"
            "class A extends tag`x` {\n  review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a helper under new in the heritage of a class held in a class field",
            "function review(r) { return agent(r) }\nawait review(0)\nclass Outer {\n"
            "  Inner = class extends new review(Object) {}\n}\n",
            2,
        ),
        (
            "a regex after in, then a prefix increment on the next line",
            "const g = (s) => s in /a/\n++n + agent(1)\ng(s)\ng(s)\n",
            1,
        ),
        (
            "a regex after if and return",
            "function review(r) { if (r) return /[(]/.test(r); return agent(r) }\n"
            "await review(1)\nawait review(2)\n",
            2,
        ),
        (
            "a block comment holding a line break ends the line",
            "const g = () => k /*\n*/ !agent(1)\ng()\ng()\n",
            1,
        ),
        (
            "a comment between function and the name of a local function expression",
            "const R = [1, 2, 3, 4, 5, 6]\nawait parallel(R.map(r => () => {\n"
            "  const review = function /* one row */ review(x) { return agent(x) }\n"
            "  return review(r)\n}))\n",
            6,
        ),
        (
            "a generator method after a class field with no initializer",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n  x\n"
            "  *review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a generator method after a class field holding an arrow block",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n"
            "  h = () => {}\n  *review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a function declared after return and a line break",
            "export default async function main() {\n  const R = [1, 2, 3]\n"
            "  await parallel(R.map(r => () => review(r)))\n  return\n"
            "  function review(r) { return agent(r) }\n}\n",
            3,
        ),
        (
            "a regex after a function declared under return",
            "if (x) return\nfunction g() {}\n/'/.test(s) && await agent(1)\n",
            1,
        ),
        (
            "a function declared after a case label",
            "switch (x) {\n  case 1: function g() {}\n  /'/.test(s) && await agent(1)\n}\n",
            1,
        ),
        (
            "an object method named async on the next line",
            "function review(r) { return agent(r) }\nawait review(0)\n"
            "const o = { async\n, review(r) { return 1 } }\n",
            1,
        ),
        (
            "an arrow block body is not called by the next line",
            "const g = r => () => { return 1 }\n[1, 2].forEach(x => agent(x))\ng(1)\ng(2)\n",
            2,
        ),
        (
            "a regex after an arrow block body",
            "const f = () => {}\n/'/.test(s) && await agent(1)\n",
            1,
        ),
        (
            "a conditional continued after an arrow block body",
            "const f = r => c ? () => {}\n  : agent(r)\nconst R = [1, 2, 3]\n"
            "await parallel(R.map(r => () => f(r)))\n",
            3,
        ),
        (
            "an object after a conditional continued past an arrow block body",
            "function review(r) { return agent(r) }\nawait review(0)\nconst o = c\n"
            "  ? () => {}\n  : { review(r) { return 1 } }\n",
            1,
        ),
        (
            "an object leading an interpolation, then a division",
            "const s = `${ {} / 2 } x / y`\nconst R = [1, 2]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
            2,
        ),
        (
            "a decorated class method",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n"
            "  @dec review(r) { return 1 }\n  @ns.dec(1) go(r) { return 1 }\n}\n",
            1,
        ),
        (
            "a method under a parenthesized decorator",
            "function review(r) { return agent(r) }\nawait review(0)\nclass A {\n"
            "  @(dec) review(r) { return 1 }\n}\n",
            1,
        ),
        (
            "an async function declared under a default label",
            "switch (k) { default: async function review(r) { return agent(r) } }\n"
            "await review(1)\nawait review(2)\n",
            2,
        ),
        (
            "an object method named agent",
            "const o = { agent(r) { return 1 } }\nawait agent(1)\n",
            1,
        ),
        (
            "a regex flag named like an array",
            "const g = [1, 2, 3]\nconst ok = /x/g.test(s)\nawait parallel(g.map(r => () => agent(r)))\n",
            3,
        ),
    ],
)
def test_shapes_the_helper_rules_must_not_misread(
    mod: ModuleType, label: str, script: str, agents: int
) -> None:
    """Regressions from review: the mask blanks literals, so body-finding reads the RAW text."""
    cost = mod.price_script(script)
    assert (cost.agents, cost.exact) == (agents, True), label


@pytest.mark.parametrize(
    ("label", "interp"),
    [
        ("a single-quoted brace", "${x ? '{' : ''}"),
        ("a double-quoted brace", '${x ? "{" : ""}'),
        ("a closing brace in a string", "${x ? '}' : ''}"),
        ("an escaped quote before a brace", "${x ? '\\'{' : ''}"),
        ("a nested template holding a brace", "${x ? `{` : ''}"),
        ("a nested template with its own interpolation", "${x ? `a${'{'}b` : ''}"),
        ("a quote inside a regex", '${JSON.stringify(x).replace(/"/g, "\'")}'),
        ("an escaped brace inside a regex", "${s.replace(/\\{\\{/g, '')}"),
        ("a brace in a regex class", "${s.replace(/[{]/g, '')}"),
        ("a brace in a block comment", "${x /* { */}"),
    ],
)
def test_a_brace_inside_a_string_in_an_interpolation_does_not_mask_the_rest(
    mod: ModuleType, label: str, interp: str
) -> None:
    """Regression from review: a brace in a string inside ``${}`` must not move the depth count.

    Counted as code, ``'{'`` never closes, the template runs to end of file, and every fan after
    it is masked, so the script prices an exact 0.
    """
    script = f"const s = `a {interp} b`\nconst R = [1, 2, 3]\nawait parallel(R.map(r => () => agent(r)))\n"
    cost = mod.price_script(script)
    assert (cost.agents, cost.exact) == (3, True), label


@pytest.mark.parametrize(
    ("label", "script"),
    [
        (
            "an object property",
            "const R = [1, 2, 3]\nconst h = { review: r => agent(r) }\n"
            "await parallel(R.map(r => () => h.review(r)))\n",
        ),
        (
            "a wrapped arrow",
            "const R = [1, 2, 3]\nconst review = once(r => agent(r))\n"
            "await parallel(R.map(r => () => review(r)))\n",
        ),
        (
            "a method",
            "const R = [1, 2, 3]\nclass X { review(r) { return agent(r) } }\n"
            "await parallel(R.map(r => () => x.review(r)))\n",
        ),
        (
            "a helper called inside a template interpolation",
            "async function review(r) { return agent(r) }\nawait review(0)\n"
            "const s = `${await review(1)} ${await review(2)}`\n",
        ),
        (
            "an array filled through push.apply",
            "const R = []\nR.push.apply(R, found)\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "an array filled through an alias",
            "const R = []\nconst T = R\nT.push(1)\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "a workflow inside an object property",
            "const h = { sub: () => workflow('other') }\nawait h.sub()\n",
        ),
        (
            "an agent after an object literal inside an interpolation",
            "const s = `${fmt({ a: 1 }) + await agent(1)}`\n",
        ),
        (
            "an array computed from its literal",
            "const R = [1].concat(found)\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "an array pushed inside an interpolation",
            "const R = [1, 2]\nlog(`${R.push(3)}`)\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "an array spliced under a spread",
            "const R = [1]\nconst copy = [...R.splice(0, 0, 2, 3)]\n"
            "await parallel(R.map(r => () => agent(r)))\n",
        ),
        (
            "a decorated method nothing calls",
            "class A {\n  @dec go(r) { return agent(r) }\n}\n",
        ),
        (
            "a method under a parenthesized decorator nothing calls",
            "class A {\n  @(dec) go(r) { return agent(r) }\n}\n",
        ),
        (
            "an array handed to a function",
            "const R = []\nfill(R)\nawait parallel(R.map(r => () => agent(r)))\n",
        ),
    ],
)
def test_a_function_value_or_array_this_read_cannot_trace_is_a_floor(
    mod: ModuleType, label: str, script: str
) -> None:
    """Regressions from review: each of these priced exact and too low before the fix."""
    assert not mod.price_script(script).exact, label


@pytest.mark.parametrize(
    ("script", "agents", "flagged"),
    [
        pytest.param("const s = `${await agent(1)}`\n", 1, {1}, id="plain"),
        pytest.param(
            "const R = [1, 2, 3]\nconst s = `${await parallel(R.map(r => () => agent(r)))}`\n",
            3,
            {2},
            id="parallel",
        ),
        pytest.param(
            "const R = [1, 2, 3]\nconst s = `${Promise.all(R.map(r => agent(r)))}`\n",
            3,
            {2},
            id="promise-all",
        ),
        pytest.param("const R = [1, 2]\nconst s = `${R.map(agent)}`\n", 2, {2}, id="hook-value"),
        pytest.param("const s = `a ${`b ${await agent(1)}`}`\n", 1, {1}, id="nested-template"),
        pytest.param("const s = `${(await agent(1)) + `${agent(2)}`}`\n", 2, {1}, id="two-agents"),
        pytest.param("const s = `x${ /* c */ agent?.(1)}`\n", 1, {1}, id="comment-optional"),
        pytest.param("const s = tag`${agent(1)}`\n", 1, {1}, id="tagged"),
        pytest.param("const s = `${[...agent(1)]}`\n", 1, {1}, id="spread"),
        pytest.param(
            "function two() { return [agent(1), agent(2)] }\nawait Promise.all(two())\n"
            "const s = `${(await Promise.all([...two()])).join()}`\n",
            4,
            {3},
            id="spread-helper",
        ),
        pytest.param(
            "const R = [1, 2, 3]\nconst f = r => `${agent(r)}`\n"
            "await parallel(R.map(r => () => f(r)))\n",
            3,
            {2},
            id="helper-fanned",
        ),
        pytest.param("const t = [...agent(1)]\n", 1, {1}, id="bare-spread"),
    ],
)
def test_an_agent_inside_a_template_interpolation_is_never_an_exact_low_count(
    mod: ModuleType, script: str, agents: int, flagged: set[int]
) -> None:
    """BACKLOG #7599: the mask blanks a template whole, ``${...}`` included, so no pricer sees a
    call there. Before PR 2982 the plain cases priced 0 agents as EXACT, and before this change
    the three spread cases still priced EXACT and low. Each case states its true agent count, so
    a lexer that prices interpolation code exactly passes too; until one does, the unattributed
    terms fall on exactly the lines in ``flagged``. At least these shapes are pinned; the
    residue's guarantee is the reach of its word pattern, not this list."""
    cost = mod.price_script(script)
    assert cost.agents >= agents or not cost.exact, script
    if not cost.exact:
        assert flagged == {u.line for u in cost.unknowns if u.kind == "unattributed"}, script


def test_a_helper_that_is_never_called_is_reported_not_priced(mod: ModuleType) -> None:
    """An agent in a body nobody calls by name may still run, passed as a value: say so."""
    script = "function review(r) { return agent(r) }\n"
    cost = mod.price_script(script)
    assert cost.agents == 0
    assert not cost.exact
    assert [u.kind for u in cost.unknowns] == ["unattributed"]


def test_a_helper_passed_as_a_value_is_reported(mod: ModuleType) -> None:
    """``R.map(review)`` calls the helper six times without ever writing ``review(``."""
    script = (
        "const R = [1, 2, 3, 4, 5, 6]\n"
        "function review(r) { return agent(r) }\n"
        "await Promise.all(R.map(review))\n"
    )
    cost = mod.price_script(script)
    assert not cost.exact
    assert "unattributed" in {u.kind for u in cost.unknowns}


def test_a_helper_defined_twice_is_not_resolved(mod: ModuleType) -> None:
    script = (
        "function review(r) { return agent(r) }\n"
        "function review(r) { return parallel([() => agent(r), () => agent(r)]) }\n"
        "await review(1)\n"
    )
    cost = mod.price_script(script)
    assert not cost.exact
    assert "helper" in {u.kind for u in cost.unknowns}


def test_a_recursive_helper_is_reported_rather_than_looping(mod: ModuleType) -> None:
    script = "async function go(n) { await agent(n); if (n) await go(n - 1) }\nawait go(3)\n"
    cost = mod.price_script(script)
    assert not cost.exact
    assert "recursion" in {u.kind for u in cost.unknowns}


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
        r'return len\(parts\), "inline array"',
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


def test_dropping_the_unstable_width_check_is_caught(mod: ModuleType) -> None:
    """BACKLOG #5601's guard, mutation-proved: without it a pushed array prices at exact zero."""
    mutant = _mutate(
        r"return \{k: v for k, v in widths\.items\(\) if k not in unstable\}, unstable",
        "return widths, {}",
        "cwc_mutant4",
    )
    script = "const R = []\nR.push(x)\nawait parallel(R.map(r => () => agent(r)))\n"
    priced = mutant.price_script(script)
    assert (priced.agents, priced.exact) == (0, True), "the mutant must reproduce the defect"
    assert not mod.price_script(script).exact


def test_dropping_helper_resolution_is_caught(mod: ModuleType) -> None:
    """BACKLOG #5602's count, mutation-proved: without call-site pricing the six agents are lost.

    The function-value skip still leaves the body to the residue, so the mutant reads as a floor
    rather than as exact; what it loses is the number, which is what resolution exists to give.
    """
    mutant = _mutate(r"    _collect_helpers\(ctx\)\n", "", "cwc_mutant5")
    script = (
        "const R = [1, 2, 3, 4, 5, 6]\n"
        "function review(r) { return agent(r) }\n"
        "await parallel(R.map(r => () => review(r)))\n"
    )
    priced = mutant.price_script(script)
    assert (priced.agents, priced.exact) == (0, False)
    real = mod.price_script(script)
    assert (real.agents, real.exact) == (6, True)


def test_dropping_the_function_value_skip_is_caught(mod: ModuleType) -> None:
    """BACKLOG #5602's residue guarantee, mutation-proved, for a function no helper rule names.

    Without the skip an agent inside an object property is counted once where it is written and
    marked attributed, so the six-wide fan that calls it reads as one agent, exact.
    """
    mutant = _mutate(
        r"pos = m\.end\(\) if invoked else max\(m\.end\(\), _function_value_end\(ctx, m\)\)",
        "pos = m.end()",
        "cwc_mutant6",
    )
    script = (
        "const R = [1, 2, 3, 4, 5, 6]\n"
        "const h = { review: r => agent(r) }\n"
        "await parallel(R.map(r => () => h.review(r)))\n"
    )
    priced = mutant.price_script(script)
    assert (priced.agents, priced.exact) == (1, True), "the mutant must reproduce the defect"
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

    # BACKLOG #5601 and #5602: both shapes used to exit 0 under --strict with an exact label.
    pushed = tmp_path / "pushed.js"
    pushed.write_text(
        "const R = []\nR.push(x)\nawait parallel(R.map(r => () => agent(r)))\n", "utf-8"
    )
    helper = tmp_path / "helper.js"
    helper.write_text(
        "function review(r) { return agent(r) }\nawait Promise.all(found.map(review))\n", "utf-8"
    )
    assert mod.main([str(pushed), "--strict"]) == 1
    assert mod.main([str(helper), "--strict"]) == 1
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


# BACKLOG #7600: `_loop_head` read every `while` as a loop (a `do`'s tail included), missed the
# head of `for await (...)`, and ended a brace-less body at the first `;` anywhere. Each shape
# below priced EXACT and wrong before the fix.
@pytest.mark.parametrize(
    "source",
    [
        # the first `;` sat inside the `if` block: the agent priced once, outside the loop
        "for (const x of rows) if (x) { y(); await agent('a') }\n",
        # `for await` had no head, so its body ended at the block's inner `;`
        "for await (const x of rows) { const r = 1; await agent('a') }\n",
        # the `else` branch after the `;` was priced once, outside the loop
        "for (const x of rows) if (x) y(); else await agent('a');\n",
    ],
)
def test_a_loop_body_is_not_cut_short_into_an_exact_count(mod: ModuleType, source: str) -> None:
    cost = mod.price_script(source)
    assert not cost.exact, f"priced {cost.agents} EXACT for a loop of unknown length"
    assert [u.kind for u in cost.unknowns] == ["loop"]
    assert cost.unknowns[0].per_unit == 1


@pytest.mark.parametrize(
    ("source", "agents"),
    [
        # `for await` over a literal is a fan of known width like `for`
        ("for await (const x of [1, 2, 3]) { const r = 1; await agent('a') }\n", 3),
        # ASI ends the brace-less body at the line break: was 4 EXACT, the next line in the loop
        ("for (const x of [1, 2])\n  await agent('a')\nawait agent('b')\n", 3),
        ("for (const x of [1, 2]) for (const y of [1, 2, 3]) await agent('a');\n", 6),
        # a `do`'s `while (...)` is its tail, not a loop swallowing the next statement
        ("let i = 0\ndo { i++ } while (i < 3)\nawait agent('b')\n", 1),
        ("do { i++ } while (i < 3)\nfor (const x of [1, 2]) await agent('b')\n", 2),
        ("do i++; while (i < 3)\nawait agent('b')\n", 1),
    ],
)
def test_a_loop_shape_prices_exactly(mod: ModuleType, source: str, agents: int) -> None:
    cost = mod.price_script(source)
    assert (cost.agents, cost.exact) == (agents, True), cost.unknowns


def test_a_do_while_tail_is_not_a_second_loop(mod: ModuleType) -> None:
    cost = mod.price_script("do {\n  await agent('a')\n} while (more())\nawait agent('b')\n")
    assert [(u.kind, u.form) for u in cost.unknowns] == [("loop", "do loop, repetitions unknown")]
    assert cost.agents == 1, "the agent after the loop runs once and belongs in the floor"


@pytest.mark.parametrize(
    ("source", "agents"),
    [
        # `if (c)`, a line break, then the branch: the next line after it runs once
        ("for (const x of [1, 2])\n  if (c)\n    await agent('a')\nawait agent('b')\n", 3),
        ("for (const r of [1, 2]) if (r) a(); else await agent('a');\nawait agent('b')\n", 3),
        (
            "for (const r of [1, 2, 3]) switch (r) { case 1: await agent('a'); break }\n"
            "await agent('b')\nawait agent('c')\n",
            5,
        ),
        ("for (const r of [1, 2]) try { await agent('a') } catch (e) {}\nawait agent('b')\n", 3),
        (
            "for (const x of [1, 2]) inner: for (const y of [1, 2, 3]) await agent('a')\n"
            "await agent('b')\n",
            7,
        ),
        # a `do` whose body is compound still ends at its own `while (...)`
        ("do if (x) { a() } while (c)\nawait agent('b')\n", 1),
        ("do try { a() } catch (e) {} while (c)\nawait agent('b')\n", 1),
    ],
)
def test_a_compound_brace_less_body_is_read_to_its_end(
    mod: ModuleType, source: str, agents: int
) -> None:
    """Each was a guess to the end of the file in round 1 of the fix; now each is read through."""
    cost = mod.price_script(source)
    assert (cost.agents, cost.exact) == (agents, True), cost.unknowns


# BACKLOG #7601: `--stdin` decoded in the locale encoding while a path decoded UTF-8, and an
# undecodable file escaped as a UnicodeDecodeError traceback.
_UTF8_SCRIPT = "const q = rows.map(agent) // \u00c1\n".encode()


def _stdin(monkeypatch: pytest.MonkeyPatch, data: bytes) -> None:
    # The Windows default: a cp1252 text layer over the bytes, as a stock console gives.
    wrapper = io.TextIOWrapper(io.BytesIO(data), encoding="cp1252", errors="surrogateescape")
    monkeypatch.setattr(sys, "stdin", wrapper)


def test_stdin_and_a_path_read_the_same_text(
    mod: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "u8.js"
    path.write_bytes(_UTF8_SCRIPT)
    assert mod.main([str(path), "--json"]) == 0
    from_path = json.loads(capsys.readouterr().out)
    _stdin(monkeypatch, _UTF8_SCRIPT)
    assert mod.main(["--stdin", "--json"]) == 0
    from_stdin = json.loads(capsys.readouterr().out)
    assert from_stdin["unpriced"] == from_path["unpriced"]
    assert "\u00c1" in from_stdin["unpriced"][0]["form"]


@pytest.mark.parametrize("route", ["path", "stdin"])
def test_undecodable_input_is_reported_not_raised(
    mod: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    route: str,
) -> None:
    bad = b"\xff\xfeawait agent('a')\n"
    if route == "path":
        path = tmp_path / "bad.js"
        path.write_bytes(bad)
        argv = [str(path)]
    else:
        _stdin(monkeypatch, bad)
        argv = ["--stdin"]
    assert mod.main(argv) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cannot read" in captured.err and "utf-8" in captured.err


@pytest.mark.parametrize(
    ("source", "agents", "exact"),
    [
        # `while (k in R)` tests membership: it has no width, whatever R's length
        ("const R = [1, 2, 3]\nwhile ('k' in R) await agent('a')\n", 0, False),
        # a string statement is the body; the next line runs once
        ("for (const r of [1, 2]) 'x'\nawait agent('b')\n", 1, True),
        # `for$` is a name, not the keyword
        ("const r = for$(await agent('a'))\n", 1, True),
    ],
)
def test_a_loop_keyword_is_read_only_where_it_is_one(
    mod: ModuleType, source: str, agents: int, exact: bool
) -> None:
    cost = mod.price_script(source)
    assert (cost.agents, cost.exact) == (agents, exact), cost.unknowns


def test_a_do_while_condition_is_priced_per_iteration(mod: ModuleType) -> None:
    cost = mod.price_script("do { await agent('a') } while (await agent('c'))\n")
    assert [(u.kind, u.per_unit) for u in cost.unknowns] == [("loop", 2)]


def test_an_unsettled_body_says_why_it_has_no_width(mod: ModuleType) -> None:
    cost = mod.price_script("for (const x of [1, 2]) if (x) { await agent('a')\n")
    assert [u.form for u in cost.unknowns] == [
        "for loop, body extent not read, so no width is trusted"
    ]


def test_a_bom_does_not_change_the_price(
    mod: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = (
        "function review(r) { return agent(r) }\nconst ROWS = [1, 2, 3]\n"
        "await parallel(ROWS.map(r => () => review(r)))\n"
    )
    plain, bom = tmp_path / "plain.js", tmp_path / "bom.js"
    plain.write_bytes(text.encode())
    bom.write_bytes(b"\xef\xbb\xbf" + text.encode())
    payloads = []
    for path in (plain, bom):
        assert mod.main([str(path), "--json"]) == 0
        payloads.append(json.loads(capsys.readouterr().out))
    assert [(p["agents"], p["exact"]) for p in payloads] == [(3, True), (3, True)]


def test_a_text_stdin_without_a_buffer_still_reads(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("await agent('a')\n"))
    assert mod.main(["--stdin", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["agents"] == 1
    monkeypatch.setattr(sys, "stdin", None)
    assert mod.main(["--stdin"]) == 1
    assert "cannot read <stdin>" in capsys.readouterr().err


def test_a_snippet_the_console_cannot_encode_is_escaped(
    mod: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "arrow.js"
    path.write_bytes("const q = rows.map(agent) // \u2192 report\n".encode())
    sink = io.BytesIO()
    console = io.TextIOWrapper(sink, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", console)
    assert mod.main([str(path)]) == 0
    console.flush()
    assert b"\\u2192" in sink.getvalue()


def test_a_byte_order_mark_anywhere_is_whitespace(mod: ModuleType) -> None:
    body = (
        "function review(r) { return agent(r) }\nconst ROWS = [1, 2, 3]\n"
        "await parallel(ROWS.map(r => () => review(r)))\n"
    )
    for source in ("\ufeff" + body, "await agent('a')\n\ufeff" + body):
        cost = mod.price_script(source)
        assert cost.exact and cost.agents == 3 + source.count("agent('a')")


# BACKLOG #7600, repair round 3. Each shape priced EXACT and wrong at 878a7bda.
@pytest.mark.parametrize(
    "source",
    [
        # a string subject: the mask blanks it, and blank read as an empty array of width 0
        "for (const ch of 'abc') await agent('a')\n",
        "for await (const ch of 'abc') await agent('a')\n",
        "for (const ch of `abc`) { await agent('a') }\n",
        # an unclosed bracket in a brace-less body: the rest of the file was a known extent
        "for (const r of [1, 2]) x = f(\nawait agent('a')\nawait agent('b')\n",
        "for (const r of [1, 2]) x = [1,\nawait agent('a')\n",
        # the same unclosed `f(`, closed by an enclosing block's `}`
        "{ for (const r of [1, 2]) x = f(\nawait agent('a') }\nawait agent('b')\n",
    ],
)
def test_an_unread_loop_shape_is_a_floor_not_a_count(mod: ModuleType, source: str) -> None:
    cost = mod.price_script(source)
    assert not cost.exact, f"priced {cost.agents} EXACT"
    assert [u.kind for u in cost.unknowns] == ["loop"]


@pytest.mark.parametrize(
    "then",
    [
        # the branch's `;` sits past the line break ASI was offered, then the `else`
        "a()\n;",
        # a do-while's `;` past its `)`
        "do a(); while (c)\n;",
        "do { a() } while (c) ;",
    ],
)
def test_an_else_after_a_branch_ended_past_its_line_is_in_the_loop(
    mod: ModuleType, then: str
) -> None:
    source = f"for (const r of [1, 2]) if (r) {then}\nelse await agent('a')\nawait agent('b')\n"
    cost = mod.price_script(source)
    assert (cost.agents, cost.exact) == (3, True), cost.unknowns


def test_the_module_source_holds_no_invisible_byte_order_mark() -> None:
    """A literal U+FEFF in the source is invisible in review: it is written as an escape."""
    assert b"\xef\xbb\xbf" not in _SCRIPT.read_bytes()


# BACKLOG #7600, repair round 5. Each shape below was misread at af3c3c51.
def test_a_mismatched_closer_does_not_swallow_the_rest_of_the_file(mod: ModuleType) -> None:
    """`read and opened.pop()` skipped the pop once read was False, so the next `(` never closed."""
    cost = mod.price_script("const g = r => f(r }.y(1)\nawait agent('a')\n")
    assert cost.agents == 1, "the next line was read into the arrow's body"
    assert "unattributed" not in [u.kind for u in cost.unknowns]
    loop = mod.price_script("for (const r of [1, 2]) x = f(r }.y(1)\nawait agent('a')\n")
    assert not loop.exact
    assert [(u.kind, u.per_unit) for u in loop.unknowns] == [("loop", 0)]
    assert loop.agents == 1, "the line after the loop runs once and belongs in the floor"


@pytest.mark.parametrize(
    "source",
    [
        # a `do` with no `while (...)` tail: its extent is a guess, so no agent count is exact
        "do { i++ }\nawait agent('a')\n",
        "do i++\n",
    ],
)
def test_a_guessed_loop_extent_with_no_agent_is_still_a_floor(mod: ModuleType, source: str) -> None:
    cost = mod.price_script(source)
    assert not cost.exact, f"priced {cost.agents} EXACT for a loop whose extent was a guess"
    assert [u.kind for u in cost.unknowns] == ["loop"]


@pytest.mark.parametrize(
    ("source", "agents"),
    [
        # a key named like a loop keyword is a name: an unsettled `do` here cost the exact label
        ("for (const r of [1, 2]) { const o = { do: 1 }; await agent('a') }\n", 2),
        ("const opts = { retries: 2, do: 'x' }\nfor (const r of [1, 2]) await agent('a')\n", 2),
        ("const o = { while: agent('x') }\nawait agent('b')\n", 2),
        ("x.do(1)\nawait agent('b')\n", 1),
    ],
)
def test_a_loop_keyword_used_as_a_name_is_not_a_loop(
    mod: ModuleType, source: str, agents: int
) -> None:
    cost = mod.price_script(source)
    assert (cost.agents, cost.exact) == (agents, True), cost.unknowns


@pytest.mark.parametrize(
    "receiver",
    ["rows?", "R!", "R !", ""],
)
def test_a_receiver_the_walk_cannot_read_is_not_an_empty_array(
    mod: ModuleType, receiver: str
) -> None:
    source = f"const R = [1, 2]\nawait parallel({receiver}.map(r => () => agent(r)))\n"
    cost = mod.price_script(source)
    assert not cost.exact, f"priced {cost.agents} EXACT from an unread receiver"
    assert [(u.kind, u.form, u.per_unit) for u in cost.unknowns] == [
        ("dynamic-width", ".map(...): receiver not read", 1)
    ]


# BACKLOG #5602, #8251 group J items 38 and 39: an Allman `function (x)` with its `{` on the next
# line, in an expression, keeps its conditional and its class field; and an `export default`
# function or class DECLARATION ends a statement, not a value. Each misread priced a real agent
# call at 0, or a regex's text as a call, and called the total exact.
@pytest.mark.parametrize(
    ("source", "agents"),
    [
        ("const c = 1, g = 2\nconst h = c ? function (x)\n{ return 1 } : {}\n/agent(1)/g\n", 1),
        ("const g = 2\nclass A {\n  f = function (x)\n  { return 1 }\n  /agent(1)/g\n}\n", 1),
        ("export default function main() { }\n/`/.test(s)\nagent(1)\n// `\n", 1),
        ("export default async function () { }\n/agent(1)/.test(s)\nagent(2)\n", 1),
        ("export default class X { }\n/agent(1)/.test(s)\nagent(2)\n", 1),
        # the controls: an export default EXPRESSION still ends a value, so the `/` divides
        ("const g = 2\nexport default (function () { })\n/agent(1)/g\n", 1),
        ("const g = 2\nexport default { }\n/agent(1)/g\n", 1),
        # the entry point's body is still priced where it is written, not as a helper
        (
            "export default async function main() {\n"
            "  await parallel([1, 2, 3].map(r => agent(r)))\n}\n",
            3,
        ),
    ],
    ids=[
        "allman-conditional",
        "allman-class-field",
        "export-default-function",
        "export-default-async-function",
        "export-default-class",
        "export-default-parenthesized",
        "export-default-object",
        "export-default-entry-point",
    ],
)
def test_a_function_ends_a_value_only_where_it_is_one(
    mod: ModuleType, source: str, agents: int
) -> None:
    cost = mod.price_script(source)
    assert (cost.agents, cost.exact) == (agents, True), (cost.sites, cost.unknowns)
