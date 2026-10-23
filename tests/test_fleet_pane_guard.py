# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The /fleet pane mod stays read-only and makes no model call.

``scripts/coord/fleet-pane`` is a Claude Code mod. Its own ``claude plugin test`` checks the same
promise at run time, but CI has no Claude Code, and the host refuses some calls (a
``$.prompt.submit`` from a ``command.run`` hook) before any test hook sees them. So this reads the
source: no module may reach ``$.model``, ``$.agent``, ``$.prompt.submit`` or ``$.tool.register``,
nor hand ``$`` to anything that could, by aliasing it or indexing it by a computed name.

It also holds every path literal to forward slashes: in a JS string ``C:\\Users`` turns ``\\U`` into
an escape, the path silently breaks, and tsc does not catch it.

Each rule is paired with a sample it must catch, because a pattern that matches nothing passes
against any source.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "scripts" / "coord" / "fleet-pane"

FORBIDDEN = {
    "model": re.compile(r"\$\s*\.\s*model\b"),
    "agent": re.compile(r"\$\s*\.\s*agent\b"),
    "prompt.submit": re.compile(r"\$\s*\.\s*prompt\s*\.\s*submit\b"),
    "tool.register": re.compile(r"\$\s*\.\s*tool\s*\.\s*register\b"),
    # `$['model']`, or `$` copied into another name or destructured, would slip past the four above.
    "indexing $": re.compile(r"\$\s*\["),
    "aliasing $": re.compile(r"=\s*\$\s*(?:[;,)\n]|$)", re.MULTILINE),
}

BACKSLASH_PATH = re.compile(r"[A-Za-z]:\\")

SHOULD_CATCH = {
    "model": "await $.model.complete({ model, prompt })",
    "agent": "$ .agent.spawn({ subagentType })",
    "prompt.submit": "void $.prompt.submit({ text })",
    "tool.register": "await $.tool.register(spec)",
    "indexing $": "const m = $['model']",
    "aliasing $": "const { model } = $\n",
}

# Lines the rules must leave alone: the module's real calls.
SHOULD_PASS = [
    "await $.process.run(['git'], { cwd })",
    "text = await $.fs.read(path)",
    "await $.ui.open({ id: PANE, title: TITLE })",
    "await update($, seats, old => applied(old, t, o))",
]


def _sources() -> list[Path]:
    return sorted(
        p for p in (MOD / "hooks").rglob("*") if p.suffix in {".ts", ".tsx", ".js", ".mjs", ".jsx"}
    )


def test_the_mod_has_sources_to_scan() -> None:
    files = _sources()
    names = {p.name for p in files}
    assert "register.tsx" in names, f"scanned {[str(p) for p in files]}"


@pytest.mark.parametrize("rule", sorted(FORBIDDEN))
def test_each_rule_catches_its_sample(rule: str) -> None:
    assert FORBIDDEN[rule].search(SHOULD_CATCH[rule]), rule


@pytest.mark.parametrize("line", SHOULD_PASS)
def test_the_rules_leave_real_calls_alone(line: str) -> None:
    assert not [r for r, pat in FORBIDDEN.items() if pat.search(line)], line


def test_no_module_reaches_a_model_agent_prompt_or_tool() -> None:
    hits = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for rule, pat in FORBIDDEN.items():
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(f"{path.relative_to(MOD)}:{line}: {rule}")
    assert hits == []


def test_path_literals_use_forward_slashes() -> None:
    assert BACKSLASH_PATH.search("'C:\\Users\\Scott'")
    hits = [
        f"{p.relative_to(MOD)}:{n}"
        for p in _sources()
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if BACKSLASH_PATH.search(line)
    ]
    assert hits == []
