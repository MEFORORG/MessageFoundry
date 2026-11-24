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
reassigned, a recursive call, and a helper passed as a value are unpriced terms. Any other function
value -- an object property, a wrapped arrow, a method -- is skipped unless a fan, ``parallel()`` or
``pipeline()`` invokes it, so its agents fall to the residue. **An array's literal length is its
width only while nothing can change it** (BACKLOG #5601): a spread element, a second declaration, or
any use of the name other than a provable read (an allowlist, not a list of mutators) makes the fan
over it an unpriced term.

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
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NamedTuple

# The script hooks that can start an agent. `log` and `phase` cost nothing and are not read.
# `workflow()` is priced as unpriceable on purpose: it shares this run's agent counter, but its body
# is a different file that this tool was not handed. STATED ONCE -- `_TOKEN_PATTERN` is built from this
# tuple, and a hook added here with no pricer becomes a loud `unknown-hook` rather than a silent
# mis-price.
_HOOKS = ("agent", "parallel", "pipeline", "workflow")

# The array methods that fan a callback across a receiver. These carry the multiplier, and they are
# scanned as first-class constructs rather than only as arguments of `parallel()`.
_FAN_METHODS = ("map", "flatMap", "forEach")
_LOOPS = ("while", "for", "do")

# `(?<![\w$.])` keeps the token from matching inside `obj.agent(` or `myagent(`. `\b` alone cannot:
# a dot is a non-word character, so `\bagent` matches happily after one.
_TOKEN_PATTERN = (
    r"(?<![\w$.])(?P<hook>" + "|".join(_HOOKS) + r")\s*\("
    r"|(?<![\w$.])(?P<from>Array\s*\.\s*from)\s*\("
    r"|\.\s*(?P<fan>" + "|".join(_FAN_METHODS) + r")\s*\("
    r"|(?<![\w$.])(?P<loop>" + "|".join(_LOOPS) + r")(?![\w$])"
)
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_OF_RE = re.compile(r"\b(?:of|in)\b")
_ARRAY_FROM_RE = re.compile(r"^\s*Array\s*\.\s*from\s*\(")
_LENGTH_RE = re.compile(r"^\s*\{\s*length\s*:\s*(\d+)\s*\}\s*$")
_DECL_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[")
# An assignment operator, compound forms included, that is not `==`, `===` or an arrow `=>`.
_ASSIGN = r"(?:\*\*|\?\?|\|\||&&|>>>|>>|<<|[-+*/%&|^])?=(?![=>])"
_FUNCTION_DECL_RE = re.compile(r"(?<![\w$.])function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(")
_BINDING_RE = re.compile(r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?![=>])")
_FUNCTION_EXPR_RE = re.compile(r"(?:async\s+)?function\b\s*\*?\s*(?:[A-Za-z_$][\w$]*)?\s*\(")
_ASYNC_RE = re.compile(r"async\b\s*")
_NONSPACE_RE = re.compile(r"\S")
_EXPORT_DEFAULT_RE = re.compile(r"(?<![\w$.])export\s+default\s+(?:async\s+)?$")
# The same entry point written as an arrow, read up to its `=>`: the runtime calls it too.
_ENTRY_ARROW_RE = re.compile(
    r"(?:(?<![\w$.])export\s+default|(?<![\w$.])module\.exports\s*=)\s*(?:async\s+)?"
    r"(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*$"
)
# `for (x of R)`, and `pipeline(R, ...)`, whose first argument is only ever iterated.
_READ_PREFIX_RE = re.compile(r"(?:(?<![\w$.])(?:of|in)|(?<![\w$.])pipeline\s*\()\s*$")
_CHANGES_RE = re.compile(r"\s*(?:" + _ASSIGN + r"|\+\+|--)")
# Methods that read an array and cannot change its length. Any other use of the name -- passing
# it to a function, aliasing it, a mutating method -- may change it (BACKLOG #5601), so the
# literal's count stops being a width. An allowlist, because a list of mutators is never complete.
_READS = frozenset(
    [
        "map",
        "flatMap",
        "forEach",
        "filter",
        "slice",
        "join",
        "includes",
        "indexOf",
        "lastIndexOf",
        "find",
        "findIndex",
        "findLast",
        "findLastIndex",
        "some",
        "every",
        "reduce",
        "reduceRight",
        "concat",
        "at",
        "entries",
        "keys",
        "values",
        "flat",
        "toSorted",
        "toReversed",
        "toSpliced",
        "with",
        "toString",
    ]
)
# Function values. Where nothing visible invokes them, their agents are left to the residue.
_TAIL_PATTERN = (
    r"|(?P<arrow>=>)"
    r"|(?<![\w$.])(?P<fn>function)\b"
    r"|(?<![\w$.])(?P<method>[A-Za-z_$][\w$]*)\s*\("
)


def _token_re(helpers: list[str]) -> re.Pattern[str]:
    names = "|".join(re.escape(n) for n in sorted(helpers, key=len, reverse=True)) or "(?!)"
    return re.compile(
        _TOKEN_PATTERN + r"|(?<![\w$.])(?P<helper>" + names + r")\s*\(" + _TAIL_PATTERN
    )


# Characters that carry an expression on past a value: after an array literal's `]`, the name is
# bound to something computed from the literal rather than the literal.
_CONTINUES = "?:.+-*%|&=<>,(["
_POSTFIX = ("++", "--")
# A line opening with a binary operator continues the line before: no `;` is inserted ahead of one.
# A bare `!` and a `++`/`--` open a new statement instead.
_LEADS_ON_RE = re.compile("[" + re.escape(_CONTINUES + "/^") + r"]|!==?|(?:in|instanceof)(?![\w$])")
_META_NAME_RE = re.compile(r"name\s*:\s*['\"]([^'\"]+)['\"]")

_PAIRS = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = ")]}"
_OPENERS = {v: k for k, v in _PAIRS.items()}


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
    token_re: re.Pattern[str] = field(default_factory=lambda: _token_re([]))
    interps: list[tuple[int, int]] = field(default_factory=list)
    held_newlines: set[int] = field(default_factory=set)
    # What the lexer read: each code token's category by its last offset, the method heads, and
    # the names being declared.
    ends: dict[int, str] = field(default_factory=dict)
    method_heads: set[int] = field(default_factory=set)
    declared: dict[int, str] = field(default_factory=dict)
    # The raw text with only COMMENTS blanked: literals intact, so "is there code here" and "what
    # is the last character of this line" can be read without a comment deciding the answer.
    code: str = ""
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


# ---- what a token leaves the expression wanting ----------------------------------------------
# THE ONE ANSWER to "does an operand follow this token?". The forward lexer gives every token one of
# these, and every reader asks it rather than scanning back: whether a `/` opens a regex, whether a
# `++` is postfix, whether a line break ends an expression, and whether a `{` opens a block, an
# object or a class body.
_VALUE = "value"  # an operand is complete: a name, a literal, a value's closing bracket
_OPERAND = "operand"  # an operator or keyword still waiting for its operand
_RESTRICTED = "restricted"  # `return`, `throw`, `yield`: an operand on its line, a `;` at a break
_AFTER_POSTFIX = "postfix"  # a postfix `++`/`--`: a value that cannot be called, indexed or dotted
_END = "end"  # a statement's end or a block's start: `;`, `{`, a block's `}`, an `if (...)`'s `)`
_VALUES = (_VALUE, _AFTER_POSTFIX)  # a `/` after either divides, and a `{` after either is a block

# Reserved words. Each is a keyword only where the lexer reads one: after a member dot it names a
# property, and as a class or object member's name it is a key, so `class() {}` defines a method.
_RESERVED = frozenset(
    ["break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete"]
    + ["do", "else", "enum", "export", "extends", "finally", "for", "function", "if", "import"]
    + ["in", "instanceof", "let", "new", "return", "switch", "throw", "try", "typeof", "var"]
    + ["void", "while", "with", "yield", "await"]
)
# A line break after one of these takes a `;`, so it awaits an operand only on its own line.
_RESTRICTED_WORDS = frozenset(["return", "throw", "yield", "break", "continue", "debugger"])
# Keywords after which a `{` opens an object literal; any other keyword before one opens a block.
_EXPRESSION_WORDS = frozenset(
    ["in", "instanceof", "typeof", "void", "delete", "new", "await", "yield", "return", "throw"]
    + ["case", "default", "of"]
)
# Keywords whose `( ... )` is a statement's head, so what follows its `)` is a statement.
_STATEMENT_HEADS = frozenset(["if", "for", "while", "with", "switch", "catch"])
# Words that modify the member name after them; anywhere else each is an ordinary identifier.
_MODIFIERS = {"class": frozenset(["get", "set", "static", "async"])}
_MODIFIERS["object"] = _MODIFIERS["class"] - {"static"}
# Tokens that can name a class or object member.
_KEY_KINDS = frozenset(["word", "private", "string", "number"])
_WORD_RE = re.compile(r"(?:[^\W\d]|\$)[\w$]*")
_FLAGS_RE = re.compile(r"[A-Za-z]*")  # a regex literal's flags, part of the literal
_NUMBER_RE = re.compile(
    r"(?:0[xXoObB][\da-fA-F_]+|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d+)?)n?"
)
_PUNCT_RE = re.compile(
    r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\||\?\?"
    r"|\?\.(?!\d)|\+\+|--|\*\*|<<|>>|[-+*/%&|^]=|.",
    re.S,
)


def _continues(cat: str, text: str, nxt: int) -> bool:
    """Whether an expression whose line ends in a token of category ``cat`` goes on at ``nxt``.

    THE ONE CONTINUATION TEST. A line ending a statement or opening a block goes on only to a
    conditional's ``:``, which no ``;`` is inserted ahead of. A line ending in an operator awaits
    its operand, whatever the next line opens with. Otherwise the next line continues it only by
    opening with a binary operator: a ``++``/``--`` there is a prefix operator after an inserted
    ``;``, and a postfix result cannot be called, indexed or dotted, so ASI splits before ``(``,
    ``[`` and ``.`` after one.
    """
    if cat == _END:  # only a conditional's `:` goes on past an arrow body or a bare `yield`
        return text.startswith(":", nxt)
    leads = not text.startswith(_POSTFIX, nxt) and _LEADS_ON_RE.match(text, nxt) is not None
    if cat == _AFTER_POSTFIX:
        return leads and text[nxt] not in "([."
    return cat == _OPERAND or leads


@dataclass
class _MaskNotes:
    """What ``_mask`` saw while blanking, for the readers that need more than the masked text."""

    interps: list[tuple[int, int]] = field(default_factory=list)  # each top-level `${...}` inside
    comments: list[tuple[int, int]] = field(default_factory=list)
    # Newlines inside a blanked literal. Not a comment's: a block comment holding a line break is
    # one, for ASI as for any other reader.
    held_newlines: set[int] = field(default_factory=set)
    # The category of every code token, keyed by the offset of its last character.
    ends: dict[int, str] = field(default_factory=dict)
    # The offset of every name that heads a method definition: a function value, not a call.
    method_heads: set[int] = field(default_factory=set)
    # Every name being declared, by offset: "binding" after `const`/`let`/`var`, "function" for a
    # declaration, "expression" for a named function expression, which names only its own body.
    declared: dict[int, str] = field(default_factory=dict)


@dataclass(eq=False)
class _Frame:
    """One open bracket, and for a ``{`` what it opened."""

    char: str  # "(", "[" or "{"; "" for the outermost frame
    kind: str = ""  # "{": "class", "object" or "block"; "(": "head", "for", "params" or ""
    closes_value: bool = True  # whether the closing bracket ends a value
    member: str = ""  # a class or object body's member state; "" in any other frame
    name: int = -1  # where the member being read names itself, when an identifier does
    modifier: str = ""
    owner: _Frame | None = None  # a method body's class or object, or a static block's class
    conditionals: int = 0  # `?` still awaiting their `:` in this frame


@dataclass
class _Scan:
    """One forward read's state: the open brackets and what the last token left wanting."""

    stack: list[_Frame]
    cat: str = _END  # the previous token's category; the start reads as a statement's end
    text: str = ";"
    kw: str = ""  # the previous token's text when it acted as a keyword
    cat2: str = _END  # the category, text and keyword before that
    text2: str = ";"
    kw2: str = ""
    newline: bool = False  # a line break since the previous token, a block comment's included
    colon: str = ""  # what the last `:` was: "key", "cond" or "label"
    classes: list[tuple[int, bool]] = field(default_factory=list)  # (depth, expression) per head
    fn: int = 0  # 1 after `function`, 2 after its name: the next `(` opens parameters
    fn_value: bool = False
    params: _Frame | None = None  # a parameter list that just closed: a `{` next is its body


class _Lexer:
    """THE ONE FORWARD READ: blank literals and comments, and classify every token as it passes.

    It replaces four readers that each answered "does an operand follow here?" by scanning back,
    each in its own way, so that every repair to one opened a new misread in another. Reading
    forward, a keyword is known to be a keyword (not a property, not a member's name), a brace's
    kind is known when it opens, and a method head is known from the member state of the class or
    object body around it -- so no reader has to reconstruct any of it from the text behind it.
    """

    def __init__(self, src: str, notes: _MaskNotes) -> None:
        self.src = src
        self.notes = notes
        self.out = list(src)
        self.record = True  # off inside a template: its interpolations are masked whole

    def blank(self, start: int, stop: int, comment: bool = False) -> None:
        if not self.record:
            return
        stop = min(stop, len(self.src))
        if comment:
            self.notes.comments.append((start, stop))
        for k in range(start, stop):
            if self.out[k] != "\n":
                self.out[k] = " "
            elif not comment:
                self.notes.held_newlines.add(k)

    def template(self, start: int) -> int:
        """Index just past the template literal whose opening backtick is at ``start``.

        Each ``${...}`` is lexed as code, so a quote or brace in a string, comment, nested
        template or regex inside one is text and moves neither the scan nor the depth.
        """
        src, n = self.src, len(self.src)
        record, self.record = self.record, False
        try:
            j = start + 1
            while j < n:
                c = src[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "`":
                    return j + 1
                if c == "$" and src.startswith("{", j + 1):
                    close = self.code(j + 2, nested=True)
                    if record and close < n:
                        self.notes.interps.append((j + 2, close))
                    j = close + 1
                    continue
                j += 1
            return n
        finally:
            self.record = record

    def code(self, i: int, nested: bool = False) -> int:
        """Lex code from ``i``; ``nested`` stops at the ``}`` closing an interpolation."""
        src, n = self.src, len(self.src)
        # An interpolation is an operand position, where a `{` opens an object.
        st = _Scan([_Frame("", "block")], _OPERAND if nested else _END)
        while i < n:
            c = src[i]
            if c.isspace():
                st.newline = st.newline or c == "\n"
                i += 1
                continue
            if src.startswith("//", i):
                end = src.find("\n", i)
                end = n if end == -1 else end
                self.blank(i, end, comment=True)
                i = end
                continue
            if src.startswith("/*", i):
                end = src.find("*/", i + 2)
                end = n if end == -1 else end + 2
                st.newline = st.newline or "\n" in src[i:end]
                self.blank(i, end, comment=True)
                i = end
                continue
            if c in "'\"":
                j = i + 1
                while j < n and src[j] != c and src[j] != "\n":
                    j += 2 if src[j] == "\\" else 1
                end, kind = min(j + 1, n), "string"
            elif c == "`":
                end, kind = self.template(i), "template"
            # A regex that does not close on its line is division, which keeps the scan in sync.
            elif c == "/" and st.cat not in _VALUES and (closed := _regex_close(src, i)) != -1:
                flags = _FLAGS_RE.match(src, closed + 1)
                end, kind = (flags.end() if flags else closed + 1), "regex"
            elif m := _WORD_RE.match(src, i):
                end, kind = m.end(), "word"
            elif c == "#" and (m := _WORD_RE.match(src, i + 1)):
                end, kind = m.end(), "private"
            elif (c.isdigit() or (c == "." and src[i + 1 : i + 2].isdigit())) and (
                m := _NUMBER_RE.match(src, i)
            ):
                end, kind = m.end(), "number"
            else:
                m = _PUNCT_RE.match(src, i)
                end, kind = (m.end() if m else i + 1), "punct"
                if nested and c == "}" and not any(f.char == "{" for f in st.stack[1:]):
                    return i
            if kind in ("string", "template", "regex"):
                self.blank(i, end)
            self.token(st, i, end, kind)
            i = end
        return n

    def token(self, st: _Scan, start: int, end: int, kind: str) -> None:
        """Classify one token and move the bracket and member state past it."""
        text = self.src[start:end]
        top = st.stack[-1]
        if st.newline and st.cat == _RESTRICTED:
            st.cat = _END  # `return`, `throw`, `yield` take a `;` at a line break
        brk = st.newline and not _continues(st.cat, self.src, start)
        if brk:
            top.conditionals = 0  # an inserted `;` ends the statement and its conditionals
        role = self.member(st, top, kind, text, start, brk) if top.member else ""
        kw = ""
        if kind != "punct":
            cat = _VALUE
            if kind == "word" and not role and st.text not in (".", "?."):
                kw = self.keyword(st, top, text)
                if kw in _RESTRICTED_WORDS:
                    cat = _RESTRICTED
                elif kw:
                    cat = _OPERAND
                elif self.record and st.fn == 1:
                    self.notes.declared[start] = "expression" if st.fn_value else "function"
                elif self.record and st.kw in ("const", "let", "var"):
                    self.notes.declared[start] = "binding"
            if kw == "class":
                st.classes.append((len(st.stack), self.expression(st)))
            elif kw == "function":
                st.fn, st.fn_value = 1, self.expression(st)
        elif text in _PAIRS:
            cat = _END if text == "{" else _OPERAND
            st.stack.append(self.open(st, top, text, role))
        elif text in _CLOSERS:
            cat = self.close(st, text)
        elif text in _POSTFIX:
            # A postfix only straight after a value: across a line break it is a prefix operator.
            cat = _AFTER_POSTFIX if st.cat == _VALUE and not st.newline else _OPERAND
        elif text == ";":
            cat, top.conditionals = _END, 0
            st.classes = [h for h in st.classes if h[0] < len(st.stack)]
        else:
            cat = _OPERAND
            if text == "?":
                top.conditionals += 1
            elif text == ":":
                if role == "colon":
                    st.colon = "key"
                elif top.conditionals:
                    st.colon, top.conditionals = "cond", top.conditionals - 1
                else:
                    st.colon = "label"  # a label, or a `case` or `default`
        if self.record:
            self.notes.ends[end - 1] = cat
        if st.fn and not (kw == "function" or text == "*" or (st.fn == 1 and kind == "word")):
            st.fn = 0
        elif st.fn == 1 and kind == "word" and not kw:
            st.fn = 2
        if text != ")":
            st.params = None
        st.cat2, st.text2, st.kw2 = st.cat, st.text, st.kw
        st.cat, st.text, st.kw, st.newline = cat, text, kw, False

    @staticmethod
    def keyword(st: _Scan, top: _Frame, word: str) -> str:
        """``word`` if it acts as a keyword here, else "" for an identifier or a value word."""
        if word == "of":  # a keyword only between a for-of head's binding and its iterable
            return word if top.kind == "for" and st.cat == _VALUE else ""
        return word if word in _RESERVED else ""

    @staticmethod
    def expression(st: _Scan) -> bool:
        """Whether a ``class`` or ``function`` keyword here starts an expression."""
        # `async function` reads what precedes `async`, unless a line break ends `async` first.
        prefixed = st.text == "async" and not st.newline
        cat, text, kw = (st.cat2, st.text2, st.kw2) if prefixed else (st.cat, st.text, st.kw)
        if text == ":" and st.colon == "label":  # a labelled or `case` declaration
            return False
        return cat in (_OPERAND, _RESTRICTED) and kw not in ("export", "else", "do")

    def open(self, st: _Scan, top: _Frame, text: str, role: str) -> _Frame:
        """The frame a bracket opens; ``role`` is what ``member`` said the bracket starts."""
        if text == "[":
            return _Frame("[")
        if text == "(":
            if role == "method":  # a method's parameters: its body ends a value in an object
                return _Frame("(", "params", top.kind == "object", owner=top)
            if st.fn:
                return _Frame("(", "params", st.fn_value)
            if st.kw == "for" or (st.kw == "await" and st.kw2 == "for"):
                return _Frame("(", "for")
            return _Frame("(", "head" if st.kw in _STATEMENT_HEADS else "")
        if st.params is not None:  # a function or method body
            owner = st.params.owner
            if owner is not None and owner.name >= 0 and self.record:
                self.notes.method_heads.add(owner.name)  # a method head only once its body opens
            return _Frame("{", "block", st.params.closes_value, owner=owner)
        if role == "static":
            return _Frame("{", "block", False, owner=top)
        if st.text == "=>":  # nothing calls, indexes or operates on an arrow function
            return _Frame("{", "block", False)
        heads = st.classes
        if heads and heads[-1][0] == len(st.stack) and (st.kw == "class" or st.cat == _VALUE):
            return _Frame("{", "class", heads.pop()[1], member="start")
        kind = self.brace_kind(st)
        return _Frame("{", kind, kind == "object", member="start" if kind == "object" else "")

    @staticmethod
    def brace_kind(st: _Scan) -> str:
        """Whether a ``{`` that opens neither a body nor a class opens an object or a block.

        After a statement's end, a ``)`` or a value it opens a block -- a ``;`` is inserted ahead
        of it after a value -- and after an operator it opens an object. After a ``:`` it takes
        the colon's kind: an object key's or a conditional's value, or a label's or ``case``'s
        statement. ``return`` and ``yield`` take a ``;`` at a line break, which ``token`` reads
        as a statement's end, so a ``{`` on the next line opens a block.
        """
        if st.cat == _END:
            return "block"
        if st.text == ":":
            return "object" if st.colon in ("key", "cond") else "block"
        if st.kw:
            return "object" if st.kw in _EXPRESSION_WORDS else "block"
        return "block" if st.cat in _VALUES else "object"

    def close(self, st: _Scan, text: str) -> str:
        opener = _OPENERS[text]
        at = next((k for k in range(len(st.stack) - 1, 0, -1) if st.stack[k].char == opener), 0)
        if not at:
            return _VALUE  # unbalanced: `_match_bracket` reports it where a pricer needs it
        fr = st.stack[at]
        del st.stack[at:]
        st.classes = [h for h in st.classes if h[0] <= len(st.stack)]
        st.params = fr if fr.kind == "params" else None
        if fr.kind in ("head", "for"):
            return _END
        if text in ")]":
            return _VALUE
        if fr.owner is not None:  # a method body or static block ends; the next member starts
            fr.owner.member = "start" if fr.owner.kind == "class" else "after"
        return _VALUE if fr.closes_value else _END

    def member(self, st: _Scan, fr: _Frame, kind: str, text: str, start: int, brk: bool) -> str:
        """Move a class or object body's member state past a token directly inside it.

        Returns "key" for a token that names a member -- a reserved word there is a name --
        "colon" for an object key's ``:``, "method" for a method's ``(`` and "static" for a static
        block's ``{``. A name followed by ``(`` heads a method, which is
        recorded; ``get``/``set``/``static``/``async`` modify the name after them, and are the
        name themselves when ``(``, ``=``, ``:`` or the member's end follows.
        """
        cls = fr.kind == "class"
        name = start + 1 if kind == "private" else start if kind == "word" else -1
        while True:
            state = fr.member
            if state == "init":  # a field's initializer or a property's value
                if not ((cls and (text == ";" or brk)) or (not cls and text == ",")):
                    return ""
                fr.member = "start"
                if text in ";,":
                    return ""
                continue  # a line break ended the field: this token starts the next member
            if state == "after":  # an object method's body has closed
                if text == ",":
                    fr.member = "start"
                return ""
            if state == "method":  # the parameter list closed; the body opens next
                if text == "{":
                    return ""
                fr.member = "init"
                continue
            if state == "deco":  # `@` or a dot: a decorator's next name, or `@(expr)`
                named = kind in ("word", "private") or text == "("
                fr.member = "decorated" if named else "init"
                return ""
            if state == "decorated":  # a decorator's name or call has been read
                if text in (".", "("):
                    fr.member = "deco" if text == "." else "decorated"
                    return ""
                fr.member = "start"  # the decorated member itself starts here
                continue
            if state == "start":
                if text in (";", "}"):
                    return ""
                if text == "@" and cls:
                    fr.member = "deco"
                    return ""
                if text == "*":
                    fr.member = "star"
                    return ""
                if text == "[":
                    fr.member, fr.name = "named", -1
                    return ""
                if kind not in _KEY_KINDS:
                    fr.member = "init"  # a spread or other expression
                    return ""
                mods = _MODIFIERS[fr.kind]
                fr.member = "mod" if kind == "word" and text in mods else "named"
                fr.name, fr.modifier = name, text
                return "key"
            if state == "star":  # a generator's `*`: its name comes next
                if kind in _KEY_KINDS:
                    fr.member, fr.name = "named", name
                    return "key"
                fr.member, fr.name = ("named", -1) if text == "[" else ("init", fr.name)
                return ""
            if state == "mod":
                if fr.modifier == "async" and st.newline:
                    fr.member = "named"  # no modifier across a line break: `async` is the name
                    continue
                if kind == "word" and text in _MODIFIERS[fr.kind]:
                    fr.name, fr.modifier = name, text
                    return "key"
                if kind in _KEY_KINDS:
                    fr.member, fr.name = "named", name
                    return "key"
                if text == "[":
                    fr.member, fr.name = "named", -1
                    return ""
                if text == "*":
                    fr.member = "star"
                    return ""
                if cls and fr.modifier == "static" and text == "{":
                    fr.member = "method"
                    return "static"
                fr.member = "named"  # the modifier word names the member itself
                continue
            # "named": the member's name has been read
            if text == "(":
                fr.member = "method"
                return "method"
            if text == ":" and not cls:
                fr.member = "init"
                return "colon"
            if text == "=":
                fr.member = "init"
                return ""
            if text == ("," if not cls else ";"):
                fr.member = "start"
                return ""
            if text == "}":
                return ""
            if cls and st.newline:  # a field with no initializer: a line break ends it
                fr.member = "start"
                continue
            fr.member = "init"
            return ""


def _regex_close(src: str, start: int) -> int:
    """Index of the `/` closing a regex literal opened at ``start``, or -1 if none on its line."""
    n = len(src)
    j = start + 1
    while j < n and src[j] != "\n":
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == "[":
            while j < n and src[j] != "]" and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            if j >= n:  # an unclosed class at end of input
                return -1
        if src[j] == "/":
            return j
        j += 1
    return -1


def _mask(src: str, notes: _MaskNotes | None = None) -> str:
    """Blank out comments, strings, template literals and regexes, PRESERVING length and newlines.

    Positions and line numbers in the masked text therefore address the original file exactly, so
    findings can be reported against real line numbers without a second mapping. ``notes``, when
    given, collects interpolation and comment spans, the newlines a blanked literal holds, and what
    the lexer read of every token: its category and the method heads.
    """
    lexer = _Lexer(src, notes if notes is not None else _MaskNotes())
    lexer.code(0)
    return "".join(lexer.out)


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
    return i in ctx.declared


def _word_re(*names: str) -> re.Pattern[str]:
    """A reference to any of ``names``: not a member (``x.name``), but a spread (``...name``)
    counts."""
    alternatives = "|".join(map(re.escape, names))
    return re.compile(r"(?:(?<=\.\.\.)|(?<![\w$.]))(?:" + alternatives + r")(?![\w$])")


def _declaration_count(ctx: _Ctx, name: str) -> int:
    """How many times ``name`` is declared with ``const``/``let``/``var``/``function`` anywhere.

    A named function EXPRESSION (``const review = function review(r) {...}``) names its own body
    rather than declaring a second binding, so ``function NAME`` counts only in statement position.
    """
    found = (ctx.declared.get(m.start()) for m in _word_re(name).finditer(ctx.masked))
    return sum(1 for kind in found if kind in ("binding", "function"))


def _first_assignment(ctx: _Ctx, name: str) -> int | None:
    """Offset of the first assignment to ``name`` other than its declaration, or None."""
    pattern = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*" + _ASSIGN)
    for m in pattern.finditer(ctx.masked):
        if not _is_declared_at(ctx, m.start()):
            return m.start()
    return None


def _is_read(masked: str, i: int, end: int) -> bool:
    """Whether the reference to an array name in ``[i, end)`` provably leaves its length alone.

    ``masked`` is the masked text, or the raw text for a reference inside an interpolation.
    """
    before = masked[max(0, i - 24) : i]
    # `...R`, `of R` and `pipeline(R` iterate the name -- but only when nothing hangs off it, or
    # `[...R.splice(0, 0, x)]` would pass as a read.
    bare_read = before.rstrip().endswith("...") or _READ_PREFIX_RE.search(before) is not None
    j = _skip_space(masked, end)
    if masked.startswith("=>", j):  # a parameter of the same name: another binding
        return True
    if masked.startswith("?.", j):
        j += 2
    elif masked.startswith(".", j):
        j += 1
    elif masked.startswith("[", j):
        close = _match_bracket(masked, j)
        return close != -1 and not _CHANGES_RE.match(masked, close + 1)
    else:
        return bare_read
    method = _IDENT_RE.match(masked, _skip_space(masked, j))
    if method is None:
        return False
    if method.group() == "length":
        return not _CHANGES_RE.match(masked, method.end())
    return method.group() in _READS and not masked.startswith(
        ".", _skip_space(masked, method.end())
    )


def _first_unsafe_use(ctx: _Ctx, name: str) -> int | None:
    """Offset of the first reference to ``name`` that is not a provable read, or None.

    A reference inside a template interpolation is invisible in the masked text, so those spans
    are read in the raw text: ``${R.push(3)}`` changes the length as surely as a statement does.
    """
    word = _word_re(name)
    for m in word.finditer(ctx.masked):
        if not _is_declared_at(ctx, m.start()) and not _is_read(ctx.masked, m.start(), m.end()):
            return m.start()
    for lo, hi in ctx.interps:
        for m in word.finditer(ctx.raw, lo, hi):
            if not _is_read(ctx.raw, m.start(), m.end()):
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
        after = _skip_space(ctx.masked, close + 1)
        if after < len(ctx.masked) and ctx.masked[after] in _CONTINUES + "!/":
            unstable[name] = "is computed from its literal, not the literal itself"
        elif _has_spread(ctx, parts):
            unstable[name] = "is built by spread"
        widths[name] = len(parts)
    for name in widths:
        if name in unstable:
            continue
        if _declaration_count(ctx, name) > 1:
            unstable[name] = "is declared more than once in this file"
            continue
        changed = _first_unsafe_use(ctx, name)
        if changed is not None:
            unstable[name] = (
                f"is used at line {ctx.line_of(changed)} in a way that may change its length"
            )
    return {k: v for k, v in widths.items() if k not in unstable}, unstable


def _skip_space(text: str, i: int) -> int:
    """First index at or after ``i`` that is not whitespace in ``text``.

    Called with the RAW text wherever the question is "is there code here": the mask blanks a
    string, template or regex to spaces, so skipping masked space would step over a literal body
    and bind the next line of code to it.
    """
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _expr_end(ctx: _Ctx, i: int, stops: str = ";,") -> int:
    """End of an expression-bodied arrow starting at ``i``: a top-level ``;``/``,``/closer, or a
    line break that neither the line before nor the line after continues, a line break held in a
    block comment included. A statement passes ``stops=";"``: a top-level ``,`` does not end one."""
    return _read_expr_end(ctx, i, stops)[0]


def _read_expr_end(ctx: _Ctx, i: int, stops: str) -> tuple[int, bool]:
    """:func:`_expr_end`, and whether that end was read: False where a bracket opened in the
    expression is never closed, so the end of the file is a guess rather than its end."""
    masked, raw = ctx.masked, ctx.code
    depth = 0
    for j in range(i, len(masked)):
        c = masked[j]
        if c in _PAIRS:
            depth += 1
        elif c in _CLOSERS:
            if depth == 0:
                return j, True
            depth -= 1
        elif depth == 0 and c in stops:
            return j, True
        elif depth == 0 and c == "\n" and j not in ctx.held_newlines and raw[i:j].strip():
            nxt = _NONSPACE_RE.search(raw, j)
            last = i + len(raw[i:j].rstrip()) - 1
            if nxt is None or not _continues(ctx.ends.get(last, _VALUE), raw, nxt.start()):
                return j, True
    return len(masked), depth == 0


def _function_body(ctx: _Ctx, open_paren: int) -> tuple[int, int] | None:
    """The block body of ``function NAME(params) {...}`` given its parameter ``(``."""
    close = _match_bracket(ctx.masked, open_paren)
    if close == -1:
        return None
    return _block_body(ctx, close + 1)


def _block_body(ctx: _Ctx, i: int) -> tuple[int, int] | None:
    """The inside of the ``{...}`` block starting at the first code at or after ``i``."""
    brace = _skip_space(ctx.code, i)
    if brace >= len(ctx.masked) or ctx.masked[brace] != "{":
        return None
    end = _match_bracket(ctx.masked, brace)
    return None if end == -1 else (brace + 1, end)


def _arrow_body(ctx: _Ctx, after_arrow: int) -> tuple[int, int]:
    """The body of an arrow whose ``=>`` ends at ``after_arrow``: a block, or an expression."""
    block = _block_body(ctx, after_arrow)
    if block is not None:
        return block
    body = _skip_space(ctx.code, after_arrow)
    return body, _expr_end(ctx, body)


def _bound_function_body(ctx: _Ctx, i: int) -> tuple[int, int] | None:
    """The body of the function expression or arrow starting at ``i``, if one starts there."""
    masked = ctx.masked
    i = _skip_space(ctx.code, i)
    fn = _FUNCTION_EXPR_RE.match(masked, i)
    if fn:
        return _function_body(ctx, fn.end() - 1)
    asynk = _ASYNC_RE.match(masked, i)
    if asynk and not masked.startswith("=>", asynk.end()):  # `async => x` names a parameter
        i = asynk.end()
    if i < len(masked) and masked[i] == "(":
        close = _match_bracket(masked, i)
        if close == -1:
            return None
        arrow = _skip_space(ctx.code, close + 1)
    else:
        ident = _IDENT_RE.match(masked, i)
        if not ident:
            return None
        arrow = _skip_space(ctx.code, ident.end())
    if not masked.startswith("=>", arrow):
        return None
    return _arrow_body(ctx, arrow + 2)


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
        # `R.map(function review(r) {...})` names a function it never calls by name; registering
        # it as a helper would skip its body and price the fan at zero. The lexer reads
        # `export default function main`, the entry point the runtime calls, as an expression too.
        statement = ctx.declared.get(m.start(1)) == "function"
        span = _function_body(ctx, m.end() - 1) if statement else None
        if span:
            found.setdefault(m.group(1), []).append(_Helper(m.start(1), *span))
    for m in _BINDING_RE.finditer(ctx.masked):
        span = _bound_function_body(ctx, m.end())
        if span:
            found.setdefault(m.group(1), []).append(_Helper(m.start(1), *span))

    for name, defs in found.items():
        if name in _HOOKS:
            continue
        ctx.def_names.update(h.def_at for h in defs)
        # `const review = function review(r) {...}` names one body twice; that is one definition.
        spans = {(h.body_start, h.body_end) for h in defs}
        double_named = len(defs) - len(spans)
        if len(spans) > 1 or _declaration_count(ctx, name) - double_named > 1:
            ctx.ambiguous[name] = "is defined more than once in this file"
        elif (at := _first_assignment(ctx, name)) is not None:
            ctx.ambiguous[name] = f"is reassigned at line {ctx.line_of(at)}"
        ctx.helpers[name] = defs[0]
        bodies.extend(spans)
    ctx.bodies = tuple(bodies)
    ctx.token_re = _token_re(list(ctx.helpers))


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
        # The mask blanks a string, template or regex literal: blank there is not empty source.
        if ctx.code[start:end].strip():
            return None, "a literal whose length is not read"
        return 0, "empty"
    lead = start + (len(seg) - len(seg.lstrip()))

    if ctx.masked[lead] == "[":
        close = _match_bracket(ctx.masked, lead)
        if close != -1 and not ctx.masked[close + 1 : end].strip():
            parts = _split_top_level(ctx, lead + 1, close)
            if _has_spread(ctx, parts):
                return None, "inline array built by spread"
            return len(parts), "inline array"

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


class _LoopSpan(NamedTuple):
    """One loop's parts. ``settled`` is False where the body's extent is a guess (BACKLOG #7600)."""

    subject: tuple[int, int] | None  # the span after `of`/`in` in `for (const x of ROWS)`
    body_start: int
    body_end: int
    resume: int  # where the scan goes on: past the body, and past a `do`'s `while (...)` tail
    settled: bool
    cond: tuple[int, int] | None = None  # a `do`'s condition, which runs every iteration too


# The statements a brace-less body can open with whose end is not the end of a line: each is read
# through its parts. A label prefixes another statement.
_COMPOUND_RE = re.compile(r"(if|switch|try|with)(?![\w$])|[A-Za-z_$][\w$]*\s*:(?!:)")
_AWAIT_RE = _word_re("await")
_LOOP_RE = _word_re(*_LOOPS)
_ELSE_RE = re.compile(r"\s*else(?![\w$])")
_CATCH_RE = re.compile(r"\s*catch(?![\w$])")
_FINALLY_RE = re.compile(r"\s*finally(?![\w$])")
_WHILE_RE = re.compile(r"\s*;?\s*while\s*(?=\()")


def _loop_head(ctx: _Ctx, after_kw: int, keyword: str) -> _LoopSpan:
    """Split the loop whose ``keyword`` ends at ``after_kw`` into its parts.

    The of-expression is a real multiplier and must be resolved rather than shrugged at. A ``do``
    has no head and ends with ``while (cond)``, which is its tail and not a second loop; a
    ``for await (... of ROWS)`` is a ``for`` like any other.
    """
    masked = ctx.masked
    n = len(masked)
    # Skipped over the RAW text: a body that is a string statement is code, not masked space.
    i = _skip_space(ctx.code, after_kw)
    if keyword == "for" and _AWAIT_RE.match(masked, i):
        i = _skip_space(ctx.code, i + len("await"))
    subject: tuple[int, int] | None = None
    if keyword != "do" and i < n and masked[i] == "(":
        close = _match_bracket(masked, i)
        if close == -1:
            return _LoopSpan(None, after_kw, after_kw, n, False)
        # Only a `for` head iterates: `while (k in R)` tests membership and has no width.
        head = _OF_RE.search(masked, i + 1, close) if keyword == "for" else None
        if head:
            subject = (head.end(), close)
        i = _skip_space(ctx.code, close + 1)
    if i < n and masked[i] == "{":
        body_start = i + 1
        resume, settled = _statement_end(ctx, i)
        body_end = resume - 1 if settled else resume
    else:
        body_start = i
        body_end, settled = _statement_end(ctx, i)
        resume = body_end
    cond: tuple[int, int] | None = None
    if keyword == "do":
        tail = _WHILE_RE.match(masked, resume)
        close = -1 if tail is None else _match_bracket(masked, tail.end())
        if tail is None or close == -1:
            settled = False
        else:
            cond = (tail.end() + 1, close)
            resume = close + 1
    return _LoopSpan(subject, body_start, body_end, resume, settled, cond)


def _statement_end(ctx: _Ctx, i: int) -> tuple[int, bool]:
    """Where the statement at ``i`` ends, and whether that end was read rather than guessed.

    A block ends past its ``}``; a simple statement at a top-level ``;`` (returned, so the caller
    can look past it), the enclosing closer, or a line break ASI ends it at -- never at the first
    ``;`` anywhere, which cut a body inside a nested block short and priced the rest once, exact,
    outside the loop. ``if``/``else``, ``try``/``catch``/``finally``, ``switch``, ``with``, a
    label and a nested loop are read through their parts. Only unbalanced source is a guess.
    """
    masked = ctx.masked
    n = len(masked)
    i = _skip_space(ctx.code, i)
    if i >= n:
        return n, False
    if masked[i] == "{":
        close = _match_bracket(masked, i)
        return (n, False) if close == -1 else (close + 1, True)
    loop = _LOOP_RE.match(masked, i)
    if loop:
        span = _loop_head(ctx, loop.end(), loop.group(0))
        return span.resume, span.settled
    head = _COMPOUND_RE.match(masked, i)
    if head is None:
        return _read_expr_end(ctx, i, ";")
    keyword = head.group(1)
    if keyword is None:  # a label
        return _statement_end(ctx, head.end())
    j = _skip_space(ctx.code, head.end())
    if keyword == "try":
        end, settled = _statement_end(ctx, j)
        for clause in (_CATCH_RE, _FINALLY_RE):
            found = clause.match(masked, end)
            if found is None:
                continue
            k = _skip_space(ctx.code, found.end())
            if masked[k : k + 1] == "(":
                close = _match_bracket(masked, k)
                if close == -1:
                    return n, False
                k = close + 1
            end, ok = _statement_end(ctx, k)
            settled = settled and ok
        return end, settled
    close = _match_bracket(masked, j) if masked[j : j + 1] == "(" else -1
    if close == -1:
        return n, False
    end, settled = _statement_end(ctx, close + 1)
    if keyword == "if":
        # The branch's own `;` may sit past the line break ASI was offered or a do-while's `)`:
        # `a()\n;` and `do a(); while (c)\n;` each end at that `;`, and the `else` follows it.
        k = _skip_space(ctx.code, end)
        found = _ELSE_RE.match(masked, k + 1 if masked[k : k + 1] == ";" else end)
        if found is not None:
            end, ok = _statement_end(ctx, found.end())
            settled = settled and ok
    return end, settled


def _price(ctx: _Ctx, start: int, end: int, invoked: bool = False) -> Cost:
    """Price every agent-starting construct in ``[start, end)``.

    Nested constructs are consumed by the recursion, so nothing is counted twice: a ``.map()``
    inside a ``parallel()`` is priced once, by the ``.map()``, and ``parallel()`` merely reports
    what its argument costs. ``invoked`` says the construct owning this region calls the function
    values written in it -- a fan callback, a ``parallel()`` thunk, a ``pipeline()`` stage.
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
        if helper and (m.start() in ctx.def_names or _is_declared_at(ctx, m.start())):
            pos = m.end()  # `function review(` names a function, registered or not; not a call
            continue
        # `{ review(r) {...} }` or `get review() {` defines a method of the same name: a function
        # value, not a call. The lexer read which names head a method.
        method_head = m.start() in ctx.method_heads
        if (helper or hook) and not method_head:
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

        # A method head falls through to here on purpose: it is a function value like these.
        if method_head or m.group("arrow") or m.group("fn") or m.group("method"):
            pos = m.end() if invoked else max(m.end(), _function_value_end(ctx, m))
            continue

        total = total + _price_loop(ctx, m)
        pos = _loop_head(ctx, m.end(), m.group("loop")).resume
    return total


def _invoked_in_place(ctx: _Ctx, body_end: int) -> bool:
    """Whether the function whose body ends at ``body_end`` is called right there: ``(...)()``."""
    i = body_end + 1 if ctx.masked[body_end : body_end + 1] == "}" else body_end
    i = _skip_space(ctx.code, i)
    if ctx.masked[i : i + 1] != ")":
        return False
    return ctx.masked[_skip_space(ctx.code, i + 1) : _skip_space(ctx.code, i + 1) + 1] == "("


def _function_value_end(ctx: _Ctx, m: re.Match[str]) -> int:
    """Where the scan resumes past a function value nothing in view invokes (BACKLOG #5602).

    An ``agent()`` inside ``{ review: r => agent(r) }``, ``once(r => agent(r))`` or a method used
    to be counted once where it was written and marked attributed, so a fan calling it read as
    exact. Skipping the body leaves those agents to the residue, which names them; a named helper
    is priced at its calls instead, and a fan callback or ``parallel()`` argument is scanned with
    ``invoked`` set, because the construct itself calls it.
    """
    if m.group("arrow"):
        if _ENTRY_ARROW_RE.search(ctx.code, max(0, m.start() - 200), m.start()):
            return m.end()  # the module's entry point: the runtime calls it
        end = _arrow_body(ctx, m.end())[1]
        return m.end() if _invoked_in_place(ctx, end) else end
    if m.group("fn"):
        if _EXPORT_DEFAULT_RE.search(ctx.code, max(0, m.start() - 32), m.start()):
            return m.end()  # the module's entry point: the runtime calls it
        fn = _FUNCTION_EXPR_RE.match(ctx.masked, m.start())
        span = _function_body(ctx, fn.end() - 1) if fn else None
        if span is None or _invoked_in_place(ctx, span[1]):
            return m.end()
        return span[1]
    if m.start() not in ctx.method_heads:
        return m.end()  # a call; `function main(` was already judged at its `function` keyword
    close = _match_bracket(ctx.masked, ctx.masked.find("(", m.end() - 1))
    span = _block_body(ctx, close + 1) if close != -1 else None  # `review(r) { ... }`
    return span[1] if span else m.end()


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

    return _fan_cost(line, width, why, _price(ctx, body[0], body[1], invoked=True), label)


def _price_loop(ctx: _Ctx, m: re.Match[str]) -> Cost:
    """Price a loop, resolving ``for (const x of ROWS)`` rather than calling every loop unknown.

    A loop over a literal array IS a fan of known width. Reporting it as unknown put real fan-out
    in the unpriced list, which trains a reader to skim the list that matters most.
    """
    keyword = m.group("loop")
    span = _loop_head(ctx, m.end(), keyword)
    inner = _price(ctx, span.body_start, span.body_end)
    if span.cond is not None:
        inner = inner + _price(ctx, span.cond[0], span.cond[1])
    if not inner.agents and not inner.unknowns:
        return Cost()

    line = ctx.line_of(m.start())
    # A body whose extent is a guess may hold code that runs once, so its count is no width.
    if span.subject is not None and span.settled:
        width, why = _width_of(ctx, span.subject[0], span.subject[1])
        if width is not None:
            return _fan_cost(line, width, why, inner, f"{keyword}...of")

    return Cost(
        unknowns=(
            Unknown(
                kind="loop",
                line=line,
                form=(
                    f"{keyword} loop, repetitions unknown"
                    if span.settled
                    else f"{keyword} loop, body extent not read, so no width is trusted"
                ),
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
        ctx.attributed.add(name_start)
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
        return _price(ctx, open_idx + 1, close, invoked=True)

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
        per_item = per_item + _price(ctx, lo, hi, invoked=True)
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

    # The mask blanks a template literal whole, so a call inside `${...}` is invisible to every
    # pricer. Read the raw text there, for the reach as for the references (BACKLOG #7599); an
    # `agent` in a string inside one reads as a false hit, which costs a floor label rather than a
    # silent under-count.
    def found(word: re.Pattern[str], lo: int, hi: int) -> Iterator[re.Match[str]]:
        yield from word.finditer(ctx.masked, lo, hi)
        for a, b in ctx.interps:
            if a < hi and b > lo:
                yield from word.finditer(ctx.raw, max(a, lo), min(b, hi))

    # The helpers that can reach an agent, through any chain of helpers. A helper that starts
    # nothing may be passed around freely; flagging it would bury the terms that matter.
    reach = {"agent", "workflow"}
    while True:
        word = _word_re(*reach)
        grown = {
            n
            for n, h in ctx.helpers.items()
            if n not in reach and next(found(word, h.body_start, h.body_end), None)
        }
        if not grown:
            break
        reach |= grown
    out: list[Unknown] = []
    for m in sorted(found(word, 0, len(ctx.raw)), key=lambda m: m.start()):
        if (
            m.start() in ctx.attributed
            or m.start() in ctx.def_names
            or m.start() in ctx.method_heads  # names a method, wherever the scan reached
            or _is_declared_at(ctx, m.start())
        ):
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
    # U+FEFF is whitespace to JavaScript, anywhere, but a token to the lexer: a BOM'd copy of a
    # file priced differently. Same length, so every offset holds.
    source = source.replace("\ufeff", " ")
    notes = _MaskNotes()
    masked = _mask(source, notes)
    chars = list(source)
    for lo, hi in notes.comments:
        for k in range(lo, hi):
            if chars[k] != "\n":
                chars[k] = " "
    ctx = _Ctx(
        raw=source,
        masked=masked,
        interps=notes.interps,
        held_newlines=notes.held_newlines,
        ends=notes.ends,
        method_heads=notes.method_heads,
        declared=notes.declared,
        code="".join(chars),
    )
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

    if not (args.stdin or args.script):
        parser.error("give a script path, --stdin, or --self-test")
    label = "<stdin>" if args.stdin else str(Path(args.script))
    # Bytes, decoded as UTF-8 on both routes (BACKLOG #7601): `sys.stdin.read()` decoded in the
    # locale encoding, cp1252 on Windows, so one file priced from two different texts. Undecodable
    # input is a broken instrument, reported, never a traceback or a guess at the text. Line ends
    # are translated as the text-mode reads both routes made before did. A BOM is kept here:
    # `price_script` reads every U+FEFF as the space it is to JavaScript.
    try:
        if not args.stdin:
            data = Path(args.script).read_bytes()
        elif sys.stdin is None:  # pythonw, or a service with no console
            raise OSError("there is no standard input")
        elif hasattr(sys.stdin, "buffer"):
            data = sys.stdin.buffer.read()
        else:  # a text stream an embedding caller set: its text is already decoded
            data = sys.stdin.read().encode("utf-8")
        source = data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeError) as exc:
        print(f"cannot read {label}: {exc}", file=sys.stderr)
        return 1

    cost = price_script(source)
    if args.json:
        report = json.dumps(to_json(cost, source, label), indent=2)
    else:
        report = render(cost, source, label)
    # A snippet of UTF-8 source can hold a character the console encoding (cp1252) cannot print:
    # escape it, for this report only, rather than end the report in a traceback.
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(report.encode(encoding, "backslashreplace").decode(encoding))

    return 1 if args.strict and cost.unknowns else 0


if __name__ == "__main__":
    raise SystemExit(main())
