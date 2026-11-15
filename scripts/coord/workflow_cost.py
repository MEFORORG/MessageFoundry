#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Workflow cost estimator -- price a fan-out BEFORE launching it (BACKLOG #1400).

**The failure this exists to prevent, measured.** A launcher sizing its own fan-out reaches for
``grep -c 'agent('`` because that is the call that starts an agent. It under-reports, because **fan
width lives in the array, not at the call site.** From the filing session's own run::

    verify-six-rows-by-their-own-instrument
      grep -c 'agent('        ->  3   call sites, at lines 83, 100 and 130
      const ROWS = [...]      ->  6   at line 76, nowhere near any of them
      agents actually started -> 13

**A 4.3x under-report from the instrument a launcher would reach for first.** The rule this tool
implements is the one that example forces: read every ``parallel()`` and ``.map()``, multiply by the
array length, sum across phases -- **a phase's cost is fan width times depth, and neither number
appears at the ``agent()`` call.**

``pipeline(items, s1, s2, s3)`` is the same arithmetic said out loud: every item runs through every
stage, so its cost is ``len(items) * stages`` and BOTH factors sit outside the ``agent()`` calls.

**WHAT MULTIPLIES, and each is scanned as a construct in its own right rather than as an argument of
``parallel()``:** ``EXPR.map()`` / ``.flatMap()`` / ``.forEach()``, ``Array.from({length: N}, cb)``,
``pipeline(items, ...stages)``, and ``for (const x of EXPR)``. Recognising ``.map()`` only inside
``parallel()`` priced ``Promise.all(ROWS.map(r => agent(r)))`` at one agent and called it exact,
which is this tool's own headline failure committed by the tool. ``parallel()`` itself multiplies
nothing -- it reports what its argument costs.

**A NAMED HELPER COSTS WHERE IT IS CALLED, NOT WHERE IT IS WRITTEN** (BACKLOG #5602). The body of
``function review(r) {...}`` or ``const review = r => ...`` is skipped by the linear scan and priced
at each ``review(...)`` call, so a fan over the helper multiplies it. A helper defined twice or
reassigned, a recursive call, and a helper passed as a value are unpriced terms. **An array's
literal length is its width only while nothing can change it** (BACKLOG #5601): a spread element, a
``push``, an index or ``.length`` assignment, a reassignment, or a second declaration of the name
makes the fan over it an unpriced term.

**WHAT THIS IS NOT.** It is not the 90-percent Workflow gate, which lives in another repository and
answers a different question -- *is the pool low enough for MY launch* -- correctly, per launcher.
This prices one script. It has no view of what any other seat is doing, so it cannot and does not
speak to the aggregate. See BACKLOG #1400 for that limb and for why lowering a per-launcher
threshold cannot fix a failure that is in the sum.

**IT REPORTS A FLOOR AND SAYS SO.** A static read cannot see a width computed at runtime, a
``while`` loop that runs until it goes dry, or a ``workflow()`` whose body is another file. Every one
of those is printed as an UNPRICED TERM with its per-unit cost, and the total is labelled a FLOOR
rather than a count whenever any exist. **A cost estimator that under-reports silently reproduces
#1400 one layer down**, which is the whole reason that item exists -- so the one thing this must
never do is return a small number with a straight face.

**THE HONESTY GUARANTEE IS A RESIDUE, NOT AN ENUMERATION.** After pricing, every ``agent`` token the
pricer did not attribute to a site is reported as ``unattributed``. Without that catch-all,
*unrecognised construct* and *costs nothing* are the same state, and the floor would be trustworthy
only for the shapes this author happened to think of -- ``ROWS.map(agent)`` passes the hook as a
value and matches no call pattern anywhere in the scanner.

Usage::

    python scripts/coord/workflow_cost.py path/to/script.js
    python scripts/coord/workflow_cost.py --stdin < script.js
    python scripts/coord/workflow_cost.py path/to/script.js --json
    python scripts/coord/workflow_cost.py --self-test

Exit 0 when the read completes -- **a large number is a finding, not an error**, and a tool that
exits non-zero on one gets muted. Exit 1 on a broken instrument (unreadable source, failed
self-test) or, with ``--strict``, when any term could not be priced.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

# The script hooks that can start an agent. `log` and `phase` cost nothing and are not read.
# `workflow()` is priced as unpriceable on purpose: it shares this run's agent counter, but its body
# is a different file that this tool was not handed. STATED ONCE -- `_TOKEN_PATTERN` is built from this
# tuple, and a hook added here with no pricer becomes a loud `unknown-hook` rather than a silent
# mis-price.
_HOOKS = ("agent", "parallel", "pipeline", "workflow")

# The array methods that fan a callback across a receiver. These carry the multiplier, and they are
# scanned as first-class constructs rather than only as arguments of `parallel()`.
_FAN_METHODS = ("map", "flatMap", "forEach")

# `(?<![\w$.])` keeps the token from matching inside `obj.agent(` or `myagent(`. `\b` alone cannot:
# a dot is a non-word character, so `\bagent` matches happily after one.
_TOKEN_PATTERN = (
    r"(?<![\w$.])(?P<hook>" + "|".join(_HOOKS) + r")\s*\("
    r"|(?<![\w$.])(?P<from>Array\s*\.\s*from)\s*\("
    r"|\.\s*(?P<fan>" + "|".join(_FAN_METHODS) + r")\s*\("
    r"|(?<![\w$.])(?P<loop>while|for|do)\b"
)
_AGENT_WORD_RE = re.compile(r"(?<![\w$.])agent\b")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_OF_RE = re.compile(r"\b(?:of|in)\b")
_ARRAY_FROM_RE = re.compile(r"^\s*Array\s*\.\s*from\s*\(")
_LENGTH_RE = re.compile(r"^\s*\{\s*length\s*:\s*(\d+)\s*\}\s*$")
_DECL_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[")
# An assignment operator, compound forms included, that is not `==`, `===` or an arrow `=>`.
_ASSIGN = r"(?:\*\*|\?\?|\|\||&&|>>>|>>|<<|[-+*/%&|^])?=(?![=>])"
# Ending in a declaration keyword: the name that follows is being DECLARED, not assigned.
_DECLARED_BEFORE_RE = re.compile(r"(?<![\w$.])(?:const|let|var|function\s*\*?)\s*$")
_FUNCTION_DECL_RE = re.compile(r"(?<![\w$.])function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(")
_BINDING_RE = re.compile(r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?![=>])\s*")
_FUNCTION_EXPR_RE = re.compile(r"(?:async\s+)?function\b\s*\*?\s*(?:[A-Za-z_$][\w$]*)?\s*\(")
_ASYNC_RE = re.compile(r"async\b\s*")
_NONSPACE_RE = re.compile(r"\S")
# A line ending, or the next line starting, with one of these continues an expression-bodied arrow.
_CONTINUES = "?:.+-*/%|&=<>,(["
_META_NAME_RE = re.compile(r"name\s*:\s*['\"]([^'\"]+)['\"]")

_PAIRS = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = ")]}"


# --------------------------------------------------------------------------------------------
# The cost model
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Unknown:
    """One term a static read cannot price, carried so it can be PRINTED rather than dropped.

    ``per_unit`` is what one iteration or one item costs where that much IS known -- a loop whose
    body starts two agents is worth reporting as "2 per iteration, iterations unknown" rather than
    as a bare shrug. It is scaled when the enclosing fan is scaled, so a dynamic loop inside a
    six-wide fan reports 6 per round, not 1.
    """

    kind: str
    line: int
    form: str
    per_unit: int = 0

    def scaled(self, width: int) -> Unknown:
        return replace(self, per_unit=self.per_unit * width)


@dataclass(frozen=True)
class Site:
    """One place in the script that starts agents, priced as width times depth."""

    line: int
    form: str
    width: int
    depth: int  # agents one unit of the fan starts; width x depth == agents
    agents: int


@dataclass(frozen=True)
class Cost:
    agents: int = 0
    sites: tuple[Site, ...] = ()
    unknowns: tuple[Unknown, ...] = ()

    @property
    def exact(self) -> bool:
        """True when nothing was left unpriced, so ``agents`` is a count and not a floor."""
        return not self.unknowns

    def __add__(self, other: Cost) -> Cost:
        return Cost(
            self.agents + other.agents,
            self.sites + other.sites,
            self.unknowns + other.unknowns,
        )

    def scaled(self, width: int) -> Cost:
        """Multiply this cost by a fan width -- the arithmetic the naive count omits.

        Sites are dropped rather than scaled: the caller replaces them with one aggregate Site for
        the whole fan, so a scaled copy was built and thrown away on every fan.
        """
        return Cost(self.agents * width, (), tuple(u.scaled(width) for u in self.unknowns))


@dataclass(frozen=True)
class _Helper:
    """A named function whose body costs nothing where it is written, only where it is called."""

    name: str
    def_at: int  # offset of the name in its definition, which is not a reference
    body_start: int
    body_end: int


@dataclass
class _Ctx:
    raw: str
    masked: str
    widths: dict[str, int] = field(default_factory=dict)
    # Array names whose literal length is NOT their width, with the reason (BACKLOG #5601).
    unstable: dict[str, str] = field(default_factory=dict)
    # Named helpers, and the names a static read cannot pin to one body (BACKLOG #5602).
    helpers: dict[str, _Helper] = field(default_factory=dict)
    ambiguous: dict[str, str] = field(default_factory=dict)
    bodies: tuple[tuple[int, int], ...] = ()
    def_names: set[int] = field(default_factory=set)
    helper_cache: dict[str, Cost] = field(default_factory=dict)
    helper_stack: list[str] = field(default_factory=list)
    token_re: re.Pattern[str] = field(
        default_factory=lambda: re.compile(_TOKEN_PATTERN + r"|(?P<helper>(?!))")
    )
    # Offsets of every `agent` token, and every helper call, the pricer actually attributed to a
    # site. `_residue` reports the rest, so an unrecognised construct cannot contribute zero in
    # silence.
    attributed: set[int] = field(default_factory=set)

    def line_of(self, index: int) -> int:
        return self.masked.count("\n", 0, index) + 1

    def snippet(self, start: int, end: int, limit: int = 46) -> str:
        text = " ".join(self.raw[start:end].split())
        return text if len(text) <= limit else text[: limit - 3] + "..."


# --------------------------------------------------------------------------------------------
# Lexical masking -- so `agent(` inside a prompt string or a comment is not a call site
# --------------------------------------------------------------------------------------------


def _is_regex_position(prev: str) -> bool:
    """Decide whether a `/` opens a regex literal or divides.

    The standard heuristic: a `/` following a VALUE (identifier, literal, closing bracket) is
    division; anywhere else it opens a regex. Imperfect at the margins -- `return /x/` is right,
    a keyword like `typeof` ending in a letter reads as a value -- so `_mask` additionally refuses
    any "regex" that does not close on its own line, which keeps a misread from desynchronising
    the rest of the scan.
    """
    return prev == "" or not (prev.isalnum() or prev in "_$)]}")


def _mask(src: str) -> str:
    """Blank out comments, strings, template literals and regexes, PRESERVING length and newlines.

    Positions and line numbers in the masked text therefore address the original file exactly, so
    findings can be reported against real line numbers without a second mapping.
    """
    out = list(src)
    n = len(src)
    i = 0
    prev = ""

    def blank(start: int, stop: int) -> None:
        for k in range(start, min(stop, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]

        if c == "/" and i + 1 < n and src[i + 1] == "/":
            end = src.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue

        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            end = n if end == -1 else end + 2
            blank(i, end)
            i = end
            continue

        if c in "'\"":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == c or src[j] == "\n":
                    break
                j += 1
            end = min(j + 1, n)
            blank(i, end)
            i, prev = end, "x"
            continue

        if c == "`":
            # A template literal masks whole, `${...}` interpolations included. A hook call inside
            # an interpolation would be missed; none has ever been written and the alternative is
            # re-entering code mode mid-string, which desynchronises far more often than it helps.
            j = i + 1
            depth = 0
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "$" and j + 1 < n and src[j + 1] == "{":
                    depth += 1
                    j += 2
                    continue
                if src[j] == "}" and depth:
                    depth -= 1
                    j += 1
                    continue
                if src[j] == "`" and depth == 0:
                    break
                j += 1
            end = min(j + 1, n)
            blank(i, end)
            i, prev = end, "x"
            continue

        if c == "/" and _is_regex_position(prev):
            j = i + 1
            closed = -1
            while j < n and src[j] != "\n":
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "[":
                    while j < n and src[j] != "]" and src[j] != "\n":
                        j += 2 if src[j] == "\\" else 1
                if src[j] == "/":
                    closed = j
                    break
                j += 1
            if closed != -1:
                blank(i, closed + 1)
                i, prev = closed + 1, "x"
                continue
            # Did not close on its line: treat as division and keep the scan in sync.

        if not c.isspace():
            prev = c
        i += 1

    return "".join(out)


# --------------------------------------------------------------------------------------------
# Bracket walking
# --------------------------------------------------------------------------------------------


def _match_bracket(masked: str, open_idx: int) -> int:
    """Index of the bracket closing the one at ``open_idx``, or -1 if the source is unbalanced."""
    stack: list[str] = []
    for i in range(open_idx, len(masked)):
        c = masked[i]
        if c in _PAIRS:
            stack.append(_PAIRS[c])
        elif c in _CLOSERS:
            if not stack or stack[-1] != c:
                return -1
            stack.pop()
            if not stack:
                return i
    return -1


def _split_top_level(ctx: _Ctx, start: int, end: int) -> list[tuple[int, int]]:
    """Split ``[start, end)`` on commas at bracket depth zero.

    Depth is read from the MASKED text, so a comma inside a prompt string is not a separator. The
    final segment's emptiness is read from the RAW text, and that asymmetry is load-bearing: a
    masked ``['a','b','c']`` is ``[   ,   ,   ]``, whose last element is indistinguishable from a
    trailing comma. Testing the mask there counted three strings as two -- a silent under-report of
    exactly the kind this tool exists to refuse.
    """
    parts: list[tuple[int, int]] = []
    depth = 0
    cur = start
    for i in range(start, end):
        c = ctx.masked[i]
        if c in _PAIRS:
            depth += 1
        elif c in _CLOSERS:
            depth -= 1
        elif c == "," and depth == 0:
            parts.append((cur, i))
            cur = i + 1
    if ctx.raw[cur:end].strip():
        parts.append((cur, end))
    return parts


def _has_spread(ctx: _Ctx, parts: list[tuple[int, int]]) -> bool:
    """Whether any element of a split array literal is a ``...spread``."""
    return any(ctx.masked[lo:hi].lstrip().startswith("...") for lo, hi in parts)


def _is_declared_at(ctx: _Ctx, i: int) -> bool:
    """Whether the name at ``i`` is being DECLARED there rather than referenced."""
    return _DECLARED_BEFORE_RE.search(ctx.masked, max(0, i - 16), i) is not None


def _word_re(name: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")


def _declaration_count(ctx: _Ctx, name: str) -> int:
    """How many times ``name`` is declared with ``const``/``let``/``var``/``function`` anywhere."""
    return sum(1 for m in _word_re(name).finditer(ctx.masked) if _is_declared_at(ctx, m.start()))


def _first_assignment(ctx: _Ctx, name: str, mutators: bool) -> int | None:
    """Offset of the first line that can change what ``name`` holds, or None.

    Its own declaration is not one. ``mutators`` adds the in-place array methods that change a
    length, and index or ``.length`` assignment -- the shapes that make a literal's count a guess.
    """
    alts = [_ASSIGN]
    if mutators:
        alts += [
            r"\.\s*(?:push|unshift|splice|pop|shift)\s*\(",
            r"\.\s*length\s*" + _ASSIGN,
            r"\[[^\]]*\]\s*" + _ASSIGN,
        ]
    pattern = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*(?:" + "|".join(alts) + ")")
    for m in pattern.finditer(ctx.masked):
        if not _is_declared_at(ctx, m.start()):
            return m.start()
    return None


def _collect_array_widths(ctx: _Ctx) -> tuple[dict[str, int], dict[str, str]]:
    """Record the element count of every array literal bound to a name, and which counts lie.

    This is the number the naive instrument never reaches: ``const ROWS = [...]`` sits at line 76
    and the ``agent()`` calls it multiplies are at 83, 100 and 130.

    **A literal's length is a width only while nothing else can change it** (BACKLOG #5601). A
    spread element, a later ``push``, a reassignment, or a second declaration of the same name
    elsewhere in the file each make the literal's count wrong, and ``const R = []`` filled by
    ``push`` priced a whole fan at an exact zero. Those names go to ``unstable`` with the reason,
    so the fan over them is an unpriced term rather than a confident small number.
    """
    widths: dict[str, int] = {}
    unstable: dict[str, str] = {}
    for m in _DECL_RE.finditer(ctx.masked):
        open_idx = ctx.masked.index("[", m.start())
        close = _match_bracket(ctx.masked, open_idx)
        if close == -1:
            continue
        name = m.group(1)
        parts = _split_top_level(ctx, open_idx + 1, close)
        if _has_spread(ctx, parts):
            unstable[name] = "is built by spread"
        widths[name] = len(parts)
    for name in widths:
        if name in unstable:
            continue
        if _declaration_count(ctx, name) > 1:
            unstable[name] = "is declared more than once in this file"
            continue
        changed = _first_assignment(ctx, name, mutators=True)
        if changed is not None:
            unstable[name] = f"is changed after its declaration, at line {ctx.line_of(changed)}"
    return {k: v for k, v in widths.items() if k not in unstable}, unstable


def _skip_space(masked: str, i: int) -> int:
    while i < len(masked) and masked[i].isspace():
        i += 1
    return i


def _expr_end(masked: str, i: int) -> int:
    """End of an expression-bodied arrow starting at ``i``: a top-level ``;``/``,``/closer, or a
    line break that neither the line before nor the line after continues."""
    depth = 0
    for j in range(i, len(masked)):
        c = masked[j]
        if c in _PAIRS:
            depth += 1
        elif c in _CLOSERS:
            if depth == 0:
                return j
            depth -= 1
        elif depth == 0 and c in ";,":
            return j
        elif depth == 0 and c == "\n" and masked[i:j].strip():
            nxt = _NONSPACE_RE.search(masked, j)
            if masked[i:j].rstrip()[-1] not in _CONTINUES and (
                nxt is None or nxt.group() not in _CONTINUES
            ):
                return j
    return len(masked)


def _function_body(masked: str, open_paren: int) -> tuple[int, int] | None:
    """The block body of ``function NAME(params) {...}`` given its parameter ``(``."""
    close = _match_bracket(masked, open_paren)
    if close == -1:
        return None
    brace = _skip_space(masked, close + 1)
    if brace >= len(masked) or masked[brace] != "{":
        return None
    end = _match_bracket(masked, brace)
    return None if end == -1 else (brace + 1, end)


def _bound_function_body(masked: str, i: int) -> tuple[int, int] | None:
    """The body of the function expression or arrow starting at ``i``, if one starts there."""
    fn = _FUNCTION_EXPR_RE.match(masked, i)
    if fn:
        return _function_body(masked, fn.end() - 1)
    asynk = _ASYNC_RE.match(masked, i)
    if asynk and not masked.startswith("=>", asynk.end()):  # `async => x` names a parameter
        i = asynk.end()
    if i < len(masked) and masked[i] == "(":
        close = _match_bracket(masked, i)
        if close == -1:
            return None
        arrow = _skip_space(masked, close + 1)
    else:
        ident = _IDENT_RE.match(masked, i)
        if not ident:
            return None
        arrow = _skip_space(masked, ident.end())
    if not masked.startswith("=>", arrow):
        return None
    body = _skip_space(masked, arrow + 2)
    if body < len(masked) and masked[body] == "{":
        end = _match_bracket(masked, body)
        return None if end == -1 else (body + 1, end)
    return body, _expr_end(masked, body)


def _collect_helpers(ctx: _Ctx) -> None:
    """Find every named function, so its body is priced where it is CALLED (BACKLOG #5602).

    The linear scan used to price an ``agent()`` inside ``function review(r) {...}`` once, where
    it is written, and mark it attributed -- so ``parallel(ROWS.map(r => () => review(r)))``
    priced at one agent with an empty residue. A name declared twice, or assigned again, cannot be
    pinned to one body, so its calls become unpriced terms instead.
    """
    found: dict[str, list[_Helper]] = {}
    bodies: list[tuple[int, int]] = []
    for m in _FUNCTION_DECL_RE.finditer(ctx.masked):
        span = _function_body(ctx.masked, m.end() - 1)
        if span:
            found.setdefault(m.group(1), []).append(_Helper(m.group(1), m.start(1), *span))
    for m in _BINDING_RE.finditer(ctx.masked):
        span = _bound_function_body(ctx.masked, m.end())
        if span:
            found.setdefault(m.group(1), []).append(_Helper(m.group(1), m.start(1), *span))

    for name, defs in found.items():
        if name in _HOOKS:
            continue
        ctx.def_names.update(h.def_at for h in defs)
        # `const review = function review(r) {...}` names one body twice; that is one definition.
        spans = {(h.body_start, h.body_end) for h in defs}
        double_named = len(defs) - len(spans)
        if len(spans) > 1 or _declaration_count(ctx, name) - double_named > 1:
            ctx.ambiguous[name] = "is defined more than once in this file"
        elif (at := _first_assignment(ctx, name, mutators=False)) is not None:
            ctx.ambiguous[name] = f"is reassigned at line {ctx.line_of(at)}"
        ctx.helpers[name] = defs[0]
        bodies.extend(spans)
    ctx.bodies = tuple(bodies)
    if ctx.helpers:
        names = "|".join(re.escape(n) for n in sorted(ctx.helpers, key=len, reverse=True))
        ctx.token_re = re.compile(_TOKEN_PATTERN + r"|(?<![\w$.])(?P<helper>" + names + r")\s*\(")


# --------------------------------------------------------------------------------------------
# Width resolution -- the single authority on "how many"
# --------------------------------------------------------------------------------------------


def _width_of(ctx: _Ctx, start: int, end: int) -> tuple[int | None, str]:
    """How many elements the expression in ``[start, end)`` has, and why we believe it.

    ONE authority, called from every construct that multiplies. Two readers of "how wide is this"
    drift: an earlier draft had a second copy that resolved bare identifiers while the first did
    not, so the same array read as 6 in a ``pipeline()`` and as unknown in a ``parallel()``.
    """
    seg = ctx.masked[start:end]
    if not seg.strip():
        return 0, "empty"
    lead = start + (len(seg) - len(seg.lstrip()))

    if ctx.masked[lead] == "[":
        close = _match_bracket(ctx.masked, lead)
        if close != -1 and not ctx.masked[close + 1 : end].strip():
            if _has_spread(ctx, _split_top_level(ctx, lead + 1, close)):
                return None, "inline array built by spread"
            return len(_split_top_level(ctx, lead + 1, close)), "inline array"

    m = _ARRAY_FROM_RE.match(seg)
    if m:
        open_idx = lead + (m.end() - m.start()) - 1
        close = _match_bracket(ctx.masked, open_idx)
        if close != -1:
            args = _split_top_level(ctx, open_idx + 1, close)
            if args:
                spec = _LENGTH_RE.match(ctx.masked[args[0][0] : args[0][1]])
                if spec:
                    return int(spec.group(1)), "Array.from length"
        return None, "Array.from length is not a literal"

    name = ctx.raw[start:end].strip()
    if name in ctx.unstable:
        return None, f"{name} {ctx.unstable[name]}"
    if name in ctx.widths:
        return ctx.widths[name], f"len({name})"
    if _IDENT_RE.fullmatch(name):
        return None, f"{name} is not a literal array in this file"
    return None, "width is computed at runtime"


def _receiver_span(ctx: _Ctx, dot_idx: int, floor: int) -> tuple[int, int]:
    """Span of the expression a ``.map(`` hangs off, found by walking LEFT from the dot.

    The receiver carries the multiplier, and it sits to the left of the token the scan matched --
    which is the whole reason a launcher's forward-reading grep never reaches it.
    """
    i = dot_idx - 1
    while i >= floor and ctx.masked[i].isspace():
        i -= 1
    if i < floor:
        return dot_idx, dot_idx
    end = i + 1

    if ctx.masked[i] in _CLOSERS:
        opener = _match_bracket_back(ctx.masked, i, floor)
        if opener == -1:
            return dot_idx, dot_idx
        i = opener - 1
        while i >= floor and ctx.masked[i].isspace():
            i -= 1
        # A bracketed receiver may itself hang off a chain (`fresh.filter(x)`), so keep walking
        # back through identifier and dot characters to take the whole chain, which resolves to an
        # unknown width -- correctly, because a filter can change the count.
        while i >= floor and (ctx.masked[i].isalnum() or ctx.masked[i] in "_$."):
            i -= 1
        return i + 1, end

    while i >= floor and (ctx.masked[i].isalnum() or ctx.masked[i] in "_$"):
        i -= 1
    return i + 1, end


def _match_bracket_back(masked: str, close_idx: int, floor: int) -> int:
    """Index of the bracket opening the one at ``close_idx``, or -1."""
    stack: list[str] = []
    for i in range(close_idx, floor - 1, -1):
        c = masked[i]
        if c in _CLOSERS:
            stack.append(c)
        elif c in _PAIRS:
            if not stack or stack[-1] != _PAIRS[c]:
                return -1
            stack.pop()
            if not stack:
                return i
    return -1


# --------------------------------------------------------------------------------------------
# The pricer
# --------------------------------------------------------------------------------------------


def _loop_head(ctx: _Ctx, after_kw: int) -> tuple[tuple[int, int] | None, int, int, int]:
    """Split a loop into (of-expression, body start, body end, resume index).

    The of-expression is the span after ``of``/``in`` in a ``for (const x of ROWS)``, which is a
    real multiplier and must be resolved rather than shrugged at.
    """
    masked = ctx.masked
    i, n = after_kw, len(masked)
    while i < n and masked[i].isspace():
        i += 1
    subject: tuple[int, int] | None = None
    if i < n and masked[i] == "(":
        close = _match_bracket(masked, i)
        if close == -1:
            return None, after_kw, after_kw, n
        head = _OF_RE.search(masked, i + 1, close)
        if head:
            subject = (head.end(), close)
        i = close + 1
    while i < n and masked[i].isspace():
        i += 1
    if i < n and masked[i] == "{":
        close = _match_bracket(masked, i)
        if close == -1:
            return subject, i, n, n
        return subject, i + 1, close, close + 1
    stop = masked.find(";", i)
    stop = n if stop == -1 else stop
    return subject, i, stop, stop


def _price(ctx: _Ctx, start: int, end: int) -> Cost:
    """Price every agent-starting construct in ``[start, end)``.

    Nested constructs are consumed by the recursion, so nothing is counted twice: a ``.map()``
    inside a ``parallel()`` is priced once, by the ``.map()``, and ``parallel()`` merely reports
    what its argument costs.
    """
    total = Cost()
    pos = start
    while pos < end:
        m = ctx.token_re.search(ctx.masked, pos, end)
        if not m:
            break

        # A helper body nested in this region costs nothing here; its calls price it.
        skip = max(
            (
                be
                for bs, be in ctx.bodies
                if bs <= m.start() < be and start <= bs and be <= end and (bs, be) != (start, end)
            ),
            default=None,
        )
        if skip is not None:
            pos = skip
            continue

        helper, hook = m.group("helper"), m.group("hook")
        if helper and m.start() in ctx.def_names:  # `function review(` names it, not a call
            pos = m.end()
            continue
        if helper or hook:
            open_idx = m.end() - 1
            close = _match_bracket(ctx.masked, open_idx)
            if close == -1 or close > end:
                # Unreadable rather than absent. Skipping it silently would let one mask desync
                # truncate the scan while the report still said "exact".
                total = total + Cost(unknowns=(_unreadable(ctx, m.start(), helper or hook),))
                pos = m.end()
                continue
            pricer = _price_helper_call if helper else _price_hook
            total = total + pricer(ctx, helper or hook, m.start(), open_idx, close)
            pos = close + 1
            continue

        if m.group("fan") or m.group("from"):
            total = total + _price_fan_call(ctx, m, start, end)
            pos = _resume_after_call(ctx, m.end() - 1, end)
            continue

        total = total + _price_loop(ctx, m)
        pos = _loop_head(ctx, m.end())[3]
    return total


def _resume_after_call(ctx: _Ctx, open_idx: int, end: int) -> int:
    close = _match_bracket(ctx.masked, open_idx)
    return open_idx + 1 if close == -1 or close > end else close + 1


def _unreadable(ctx: _Ctx, at: int, form: str) -> Unknown:
    return Unknown(
        kind="unreadable",
        line=ctx.line_of(at),
        form=f"{form}(...) does not close -- the scan could not read past it",
    )


def _fan_cost(line: int, width: int | None, why: str, inner: Cost, label: str) -> Cost:
    """Turn a per-unit cost and a fan width into either a priced Site or a named unpriced term.

    ONE tail for every multiplying construct. Written out per construct it was three near-identical
    blocks that grew by one with each new shape, and the branch that must never be got wrong -- the
    unknown-width one, which decides whether a number is a count or a floor -- was the part being
    copied.
    """
    if not inner.agents and not inner.unknowns:
        return Cost()
    if width is None:
        return Cost(
            unknowns=(
                Unknown(
                    kind="dynamic-width", line=line, form=f"{label}: {why}", per_unit=inner.agents
                ),
            )
            + inner.unknowns
        )
    scaled = inner.scaled(width)
    site = Site(line, f"{label} ({why})", width, inner.agents, scaled.agents)
    return Cost(agents=scaled.agents, sites=(site,), unknowns=scaled.unknowns)


def _price_fan_call(ctx: _Ctx, m: re.Match[str], region_start: int, region_end: int) -> Cost:
    """Price ``EXPR.map(cb)`` and ``Array.from(spec, cb)`` -- the constructs carrying fan width.

    A ``.map()`` is priced HERE rather than only as an argument of ``parallel()``, because
    ``Promise.all(ROWS.map(r => agent(r)))`` is an equally ordinary fan-out and an earlier draft
    priced it at 1 agent and called the answer exact.
    """
    open_idx = m.end() - 1
    line = ctx.line_of(m.start())
    is_map = m.group("fan") is not None
    label = f".{m.group('fan')}(...)" if is_map else "Array.from(...)"

    close = _match_bracket(ctx.masked, open_idx)
    if close == -1 or close > region_end:
        return Cost(unknowns=(_unreadable(ctx, m.start(), label),))
    args = _split_top_level(ctx, open_idx + 1, close)

    if is_map:
        # The `fan` alternative of _TOKEN_PATTERN begins with `\.`, so the match already starts AT the
        # dot -- no search needed.
        width, why = _width_of(ctx, *_receiver_span(ctx, m.start(), region_start))
        body = args[0] if args else (open_idx + 1, close)
    else:
        spec = _LENGTH_RE.match(ctx.masked[args[0][0] : args[0][1]]) if args else None
        width = int(spec.group(1)) if spec else None
        why = "length" if spec else "length is not a literal"
        body = args[1] if len(args) > 1 else (open_idx + 1, close)

    return _fan_cost(line, width, why, _price(ctx, body[0], body[1]), label)


def _price_loop(ctx: _Ctx, m: re.Match[str]) -> Cost:
    """Price a loop, resolving ``for (const x of ROWS)`` rather than calling every loop unknown.

    A loop over a literal array IS a fan of known width. Reporting it as unknown put real fan-out
    in the unpriced list, which trains a reader to skim the list that matters most.
    """
    subject, body_start, body_end, _ = _loop_head(ctx, m.end())
    inner = _price(ctx, body_start, body_end)
    if not inner.agents and not inner.unknowns:
        return Cost()

    line = ctx.line_of(m.start())
    keyword = m.group("loop")
    if subject is not None:
        width, why = _width_of(ctx, subject[0], subject[1])
        if width is not None:
            return _fan_cost(line, width, why, inner, f"{keyword}...of")

    return Cost(
        unknowns=(
            Unknown(
                kind="loop",
                line=line,
                form=f"{keyword} loop, repetitions unknown",
                per_unit=inner.agents,
            ),
        )
        + inner.unknowns
    )


def _price_hook(ctx: _Ctx, hook: str, name_start: int, open_idx: int, close: int) -> Cost:
    if hook == "agent":
        ctx.attributed.add(name_start)
        return Cost(agents=1, sites=(Site(ctx.line_of(name_start), "agent(...)", 1, 1, 1),))

    if hook == "workflow":
        # Shares this run's agent counter, but its body is another file. Naming it is the only
        # honest answer; returning zero and staying quiet is the #1400 failure one layer down.
        return Cost(
            unknowns=(
                Unknown(
                    kind="nested-workflow",
                    line=ctx.line_of(name_start),
                    form=ctx.snippet(name_start, min(close + 1, len(ctx.raw))),
                ),
            )
        )

    if hook == "parallel":
        # No multiplier of its own. Its argument is either a `.map()` (priced by _price_map) or a
        # literal list of thunks (priced element by element by the ordinary scan), so parallel()
        # simply reports what its argument costs. Multiplying here as well would double-count.
        return _price(ctx, open_idx + 1, close)

    if hook == "pipeline":
        return _price_pipeline(ctx, name_start, open_idx, close)

    return Cost(
        unknowns=(
            Unknown(
                kind="unknown-hook",
                line=ctx.line_of(name_start),
                form=f"{hook}(...) has no pricer registered",
            ),
        )
    )


def _price_pipeline(ctx: _Ctx, name_start: int, open_idx: int, close: int) -> Cost:
    """``pipeline(items, s1, s2, s3)`` -- every item runs every stage.

    The multiplication is in the call's SEMANTICS rather than written as a ``.map()``, so both
    factors sit outside the ``agent()`` calls just as the item describes.
    """
    args = _split_top_level(ctx, open_idx + 1, close)
    if not args:
        return Cost()
    width, why = _width_of(ctx, args[0][0], args[0][1])
    per_item = Cost()
    for lo, hi in args[1:]:
        per_item = per_item + _price(ctx, lo, hi)
    label = f"pipeline(...) x {len(args) - 1} stages"
    return _fan_cost(ctx.line_of(name_start), width, why, per_item, label)


def _price_helper_call(ctx: _Ctx, name: str, name_start: int, open_idx: int, close: int) -> Cost:
    """``review(r)`` -- what the helper's body costs, once per call, plus what its arguments cost.

    The body is priced once and cached, so a helper called from a six-wide fan costs six times its
    body through the ordinary fan arithmetic, and nothing is counted where the body is written.
    """
    ctx.attributed.add(name_start)
    args = _price(ctx, open_idx + 1, close)
    line = ctx.line_of(name_start)
    if name in ctx.ambiguous:
        reason = ctx.ambiguous[name]
        return args + Cost(unknowns=(Unknown("helper", line, f"{name}(...) {reason}"),))
    if name in ctx.helper_stack:
        return args + Cost(
            unknowns=(Unknown("recursion", line, f"{name}(...) calls itself; depth unknown"),)
        )
    body = ctx.helper_cache.get(name)
    if body is None:
        helper = ctx.helpers[name]
        ctx.helper_stack.append(name)
        body = _price(ctx, helper.body_start, helper.body_end)
        ctx.helper_stack.pop()
        ctx.helper_cache[name] = body
    if not body.agents:
        return args + Cost(unknowns=body.unknowns)
    site = Site(line, f"{name}(...) helper", 1, body.agents, body.agents)
    return args + Cost(body.agents, (site,), body.unknowns)


def _residue(ctx: _Ctx) -> tuple[Unknown, ...]:
    """Every ``agent``, or agent-starting helper, the scan did NOT attribute to a site.

    THE CATCH-ALL IS THE HONESTY GUARANTEE. Without it, "unrecognised construct" and "costs
    nothing" are the same state, and the tool's floor is only trustworthy for the shapes its author
    happened to enumerate. ``ROWS.map(agent)`` passes the hook as a VALUE and matches no call
    pattern at all; this is what catches it, and ``ROWS.map(review)`` over a helper likewise.
    """
    starters = "|".join(re.escape(n) for n in ("agent", "workflow", *ctx.helpers))
    starts_agents = re.compile(r"(?<![\w$.])(?:" + starters + r")(?![\w$])")
    words = [_AGENT_WORD_RE]
    words += [
        _word_re(name)
        for name, h in ctx.helpers.items()
        if starts_agents.search(ctx.masked, h.body_start, h.body_end)
    ]
    hits = sorted((m for word in words for m in word.finditer(ctx.masked)), key=lambda m: m.start())
    out: list[Unknown] = []
    for m in hits:
        if m.start() in ctx.attributed or m.start() in ctx.def_names:
            continue
        line_end = ctx.raw.find("\n", m.start())
        out.append(
            Unknown(
                kind="unattributed",
                line=ctx.line_of(m.start()),
                form=ctx.snippet(m.start(), len(ctx.raw) if line_end == -1 else line_end),
            )
        )
    return tuple(out)


# --------------------------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------------------------


def naive_agent_grep(source: str) -> int:
    """What ``grep -c 'agent('`` returns: matching LINES of the raw file, blind to everything.

    Reproduced exactly, comments and strings included, because it is the instrument being compared
    against -- not a better version of it.
    """
    return sum(1 for line in source.split("\n") if "agent(" in line)


def workflow_name(source: str) -> str | None:
    idx = source.find("export const meta")
    if idx == -1:
        return None
    m = _META_NAME_RE.search(source, idx, idx + 2000)
    return m.group(1) if m else None


def price_script(source: str) -> Cost:
    """Price one workflow script. The returned cost is EXACT only when ``.exact`` is true."""
    ctx = _Ctx(raw=source, masked=_mask(source))
    ctx.widths, ctx.unstable = _collect_array_widths(ctx)
    _collect_helpers(ctx)
    cost = _price(ctx, 0, len(ctx.masked))
    # The residue is appended LAST, after every pricer has had its chance to attribute an `agent`.
    # It is what turns "the shapes this author enumerated" into "everything", which is the
    # difference between an honest floor and a confident one.
    return Cost(cost.agents, cost.sites, cost.unknowns + _residue(ctx))


# --------------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------------


def render(cost: Cost, source: str, label: str) -> str:
    naive = naive_agent_grep(source)
    name = workflow_name(source)
    out: list[str] = []
    out.append(f"workflow cost: {name or '(no meta.name)'}")
    out.append(f"  source: {label}")
    out.append(f"  scanned: {len(source.splitlines())} lines")
    out.append("")

    if cost.sites:
        out.append("  LINE  FAN                                              WIDTH x DEPTH  AGENTS")
        for site in sorted(cost.sites, key=lambda s: s.line):
            out.append(
                f"  {site.line:>4}  {site.form:<48} {site.width:>5} x {site.depth:<5} {site.agents:>6}"
            )
        out.append(f"  {'':>4}  {'':<48} {'':>5}   {'':<5} {'------':>6}")
    label_total = "known floor" if cost.unknowns else "TOTAL (exact)"
    out.append(f"  {'':>4}  {label_total:<48} {'':>5}   {'':<5} {cost.agents:>6}")
    out.append("")

    out.append(f"  naive `grep -c 'agent('`  ->  {naive}")
    if cost.unknowns:
        # Never compare a floor against the naive count as though it were a total. A floor BELOW
        # the naive count would otherwise print as "the naive count is correct here", which is the
        # #1400 failure verbatim: an instrument reassuring a launcher with a number it cannot back.
        note = "a FLOOR -- see the unpriced terms below"
    elif naive and cost.agents > naive:
        note = f"{cost.agents / naive:.1f}x the naive count"
    elif cost.agents == naive:
        note = "the naive count is correct here -- no fan-out to miss"
    else:
        note = "exact"
    out.append(f"  this read                 ->  {cost.agents}   ({note})")
    out.append("")

    if cost.unknowns:
        out.append(
            f"  UNPRICED TERMS ({len(cost.unknowns)}) -- THE TOTAL ABOVE IS A FLOOR, NOT A COUNT:"
        )
        for u in sorted(cost.unknowns, key=lambda x: x.line):
            if u.kind == "nested-workflow":
                per = "the whole cost is in another script"
            elif u.kind == "unattributed":
                per = "an `agent` or helper reference no priced call accounts for"
            elif u.kind == "unreadable":
                per = "the scan stopped here, so anything past it is uncounted"
            elif u.per_unit:
                per = f"{u.per_unit} agents per unit, multiplier unknown"
            else:
                per = "neither the per-unit cost nor the multiplier is statically known"
            out.append(f"    line {u.line:<5} {u.kind:<16} {u.form}")
            out.append(f"    {'':<10} {'':<16} {per}")
        out.append("")
        out.append("  A static read cannot resolve these. Price them by hand before you launch.")
    else:
        out.append("  UNPRICED TERMS: none. Every fan width in this script is a literal.")
    return "\n".join(out)


def to_json(cost: Cost, source: str, label: str) -> dict[str, object]:
    return {
        "source": label,
        "name": workflow_name(source),
        "agents": cost.agents,
        "exact": cost.exact,
        "naive_agent_grep": naive_agent_grep(source),
        "sites": [
            {
                "line": s.line,
                "form": s.form,
                "width": s.width,
                "depth": s.depth,
                "agents": s.agents,
            }
            for s in sorted(cost.sites, key=lambda s: s.line)
        ],
        "unpriced": [
            {"line": u.line, "kind": u.kind, "form": u.form, "per_unit": u.per_unit}
            for u in sorted(cost.unknowns, key=lambda u: u.line)
        ],
    }


# --------------------------------------------------------------------------------------------
# Self-test -- the positive control, printed rather than assumed
# --------------------------------------------------------------------------------------------

# The item's worked example, reconstructed. The original script is not in this repository and was
# not recoverable, so this is the SHAPE its three measured numbers force: three `agent(` call
# sites, a six-element `const ROWS` declared far above them, and 13 agents actually started
# (6 + 6 + 1). Every figure below is from BACKLOG #1400.
SELF_TEST_SCRIPT = """
export const meta = {
  name: 'verify-six-rows-by-their-own-instrument',
  description: 'Verify six rows, then synthesise',
  phases: [{ title: 'Read' }, { title: 'Refute' }, { title: 'Synthesise' }],
}

const ROWS = [
  { id: 1301 }, { id: 1302 }, { id: 1303 },
  { id: 1304 }, { id: 1305 }, { id: 1306 },
]

phase('Read')
const reads = await parallel(ROWS.map(r => () => agent(`read row ${r.id}`)))

phase('Refute')
const refutes = await parallel(ROWS.map(r => () => agent(`refute row ${r.id}`)))

phase('Synthesise')
return await agent('synthesise the two passes')
"""

# The discriminating control: a script with no fan-out at all, where the naive count is RIGHT.
# Without it, "this tool reports a bigger number" is satisfied by a tool that always reports a
# bigger number, and a pass would prove nothing about the arithmetic.
SELF_TEST_FLAT = """
export const meta = { name: 'flat', description: 'no fan-out' }
phase('One')
const a = await agent('first')
const b = await agent('second')
return [a, b]
"""


def _self_test() -> int:
    failures: list[str] = []

    fan = price_script(SELF_TEST_SCRIPT)
    naive = naive_agent_grep(SELF_TEST_SCRIPT)
    print(f"SELF-TEST fan-out script: priced {fan.agents}, naive grep {naive}, exact={fan.exact}")
    if fan.agents != 13:
        failures.append(f"the worked example must price at 13 agents, got {fan.agents}")
    if naive != 3:
        failures.append(f"the naive grep control must return 3, got {naive}")
    if not fan.exact:
        failures.append("the worked example has only literal widths and must price exactly")

    flat = price_script(SELF_TEST_FLAT)
    naive_flat = naive_agent_grep(SELF_TEST_FLAT)
    print(f"SELF-TEST flat script:    priced {flat.agents}, naive grep {naive_flat}")
    if flat.agents != naive_flat:
        failures.append(
            f"with no fan-out the two instruments must AGREE: {flat.agents} vs {naive_flat}"
        )

    for problem in failures:
        print(f"SELF-TEST FAILED: {problem}", file=sys.stderr)
    if failures:
        return 1
    print("SELF-TEST OK: the 4.3x under-report is reproduced and the flat case still agrees.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="workflow_cost.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("script", nargs="?", help="path to the workflow script (.js)")
    parser.add_argument("--stdin", action="store_true", help="read the script from stdin")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when any term could not be priced statically",
    )
    parser.add_argument("--self-test", action="store_true", help="prove the tool can see a fan-out")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.stdin:
        source, label = sys.stdin.read(), "<stdin>"
    elif args.script:
        path = Path(args.script)
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"cannot read {path}: {exc}", file=sys.stderr)
            return 1
        label = str(path)
    else:
        parser.error("give a script path, --stdin, or --self-test")

    cost = price_script(source)
    if args.json:
        print(json.dumps(to_json(cost, source, label), indent=2))
    else:
        print(render(cost, source, label))

    return 1 if args.strict and cost.unknowns else 0


if __name__ == "__main__":
    raise SystemExit(main())
