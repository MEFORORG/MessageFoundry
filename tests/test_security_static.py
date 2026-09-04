# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-L3-01 (ASVS 1.3.12, 1.5.3): static guards so the ReDoS posture and the single-parser-per-type
invariants can't silently regress.

* **No catastrophic regex.** No regex pattern reaching ``re.*`` in the walked packages uses a nested
  *unbounded* quantifier (the ``(a+)+`` / ``(\\d*)*`` shape that backtracks exponentially). Inbound
  HL7/X12 is size-capped *before* any regex runs (``peek.py`` / ``validate.py`` / ``x12/peek.py``) —
  **and, since ASVS 1.3.3, the value a regex actually sees is bounded too**: ``peek.py``'s aggregate
  escape-expansion budget (``enforce_expansion_budget``, backed by
  ``_builtin_hl7.escape_expansion_estimate``) rejects a message before parsing when its HL7 escapes
  could expand by more than a **fixed** 16 MiB (``DEFAULT_MAX_MESSAGE_BYTES``, whatever the
  connection's ``max_message_bytes``). Before that budget, the raw cap bounded the *raw* while an
  unescaped leaf could still grow ~256x, so a pattern ran over a value orders of magnitude larger
  than the cap suggested. Routing patterns come from the trusted code-first Handler author — but a
  planted catastrophic pattern would still be a latent CPU-DoS, so the shape is forbidden outright.
* **One parser per type.** stdlib ``json`` is the sole JSON parser and ``urllib.parse.urlsplit`` the
  sole URL parser, so an SSRF/egress host check can never disagree with the request it guards about a
  URL's host. Importing an alternate JSON parser (orjson/ujson/...) or the inconsistent ``urlparse``
  is forbidden. **XML has four parsers** (defusedxml, ``xml.sax``, lxml, xmlschema), each hardened at
  its own construction site, so a new XML parse surface reached via any **statically imported** parser
  module in the walked packages is a build failure until it is added to
  :data:`_XML_PARSER_ALLOWLIST` with a recorded rationale — and
  ``tests/test_xml_parser_consistency.py`` holds the four to one hostile corpus.

**What the scanners cannot see** (stated so the guard is not read as more than it is):

* **Patterns the ReDoS scanner cannot resolve.** :data:`_UNSCANNABLE_RE_PATTERNS` is the checked-in
  set of every ``re.*`` call in the walked roots whose pattern argument does not resolve statically —
  pinned **as the expressions**, so both a new blind spot and a *changed* one red the build. (1) A
  pattern *composed at runtime* — ``re.escape``/``'|'.join(...)`` interpolation in
  ``config/impact.py``, ``logging_setup.py`` and ``parsing/_builtin_hl7.py``. (2) A pattern passed
  through a *wrapper parameter*. Of the two wrappers, only ``messagefoundry/parsing/consistency.py``'s
  ``matches(msg, path, pattern)`` is genuinely uncovered, and deliberately: its pattern is
  author-supplied and outside the target of evaluation per
  ``docs/security/HANDLER-CODE-SHARED-RESPONSIBILITY.md``. ``messagefoundry_webconsole/_auth.py``'s
  ``register_ui_action(pattern, …)`` is read **at its call sites** via :data:`_PATTERN_WRAPPERS`, so
  all 25 console route patterns are scanned; only its own ``re.compile(pattern)`` is unresolvable, by
  construction. None of the five is a catastrophic shape by inspection. A constant **imported from
  another module** would land in the same set: the scan is per-file, so it resolves module-,
  function- and class-scope constants and string collections in the file it is reading, but never
  across an import.
* **Catastrophic shapes the matcher does not model.** It detects an unbounded quantifier (``+``,
  ``*``, ``{n,}``) applied to a group that contains an unbounded quantifier at **any** nesting depth.
  It does **not** detect overlapping alternation (``(a|a)*``), nor a catastrophic interaction spread
  across two *sibling* groups (``\\d+\\s*\\d+…`` styles), nor anything about the *input* a pattern is
  applied to. Those are **not** mitigated by the bounded-input precondition above: catastrophic
  backtracking is exponential in the length of the matched prefix and detonates on inputs of tens of
  characters, so no size or expansion cap bounds it. They are the accepted residual on ASVS 1.3.12
  (residual 4 of the current L3 assessment under ``docs/security/``, which is deny-listed from the
  public mirror and so is not named here), and they are the reason the shapes this matcher *can* see
  are forbidden outright rather than merely reviewed.
* **Parsers the single-parser clauses cannot see.** The JSON/URL/XML clauses match *statically
  imported* module names against a fixed set, so a parser pulled in dynamically
  (``importlib.import_module("lxml.etree")``, ``__import__``) is invisible, as is any parser module
  outside :data:`_XML_PARSER_MODULES`. The one *import-free* route that exists in this tree —
  ``parsing/xml/_deps.py``'s lazy loaders — is covered by its own clause
  (:data:`_XML_DEPS_CONSUMERS`) rather than left to the module-name matcher. Separately,
  ``transports/soap.py`` triages SOAP faults with regexes over the XML response body
  (``_FAULT_RE``/``_FAULTCODE_RE``/``_CODEVALUE_RE``) — an ad-hoc same-type extraction that is
  deliberately out of the clause's scope, because it drives only retry-vs-dead-letter classification,
  never a security decision.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

# --- the walked roots (pinned identical with the ASVS 11.1.3 crypto-discovery gate) --------------
#
# One registry with PER-CLAUSE root tuples — deliberately not one flat list, so the two items that
# share this edit cannot silently diverge and the differences are recorded rather than rediscovered:
#
# * ``_SOURCE_ROOTS`` — messagefoundry/ + messagefoundry_webconsole/ + harness/ + tee/, the
#   first-party Python the ReDoS and single-parser clauses walk. ``tee/`` belongs here on the same
#   footing as the rest: it parses untrusted HL7 off the wire (``tee/mllp.py``'s segment split over
#   decoded MLLP frames, ``tee/anon/*`` over message fields), which is exactly the class these clauses
#   score. Measured before adding: zero nested-quantifier offenders, zero unscannable patterns, no
#   alternate JSON/URL/XML parser — so the coverage is free.
# * ``_CRYPTO_ROOTS`` — those four plus ``scripts/``, the target of evaluation for the ASVS 11.1.3
#   cryptographic-discovery gate. Unchanged as a TUPLE (tee/ simply moved into the shared prefix):
#   ``harness/`` and ``scripts/`` carry no crypto call site today and are walked pre-emptively, so a
#   new one cannot appear outside the inventory — which ``test_crypto_roots_carry_no_unrecorded_call_site``
#   below is what makes true (it runs the gate's own discover() over EVERY root in this tuple; the
#   shipped ``crypto_inventory_check.py`` CLI still defaults to messagefoundry/ alone, and widening it
#   is BACKLOG #282's edit — this tuple is the pin it consumes).
# * ``_XML_ROOTS`` — every root above. The XML clause is a pure IMPORT matcher, so the false positive
#   that keeps ``scripts/`` out of the ReDoS clause has no bearing on it and there is no reason to
#   leave a root unwalked for XML.
#
# ``ide/`` is in none of them because it is TypeScript — it contains zero ``.py`` files, so these
# Python-AST clauses have nothing to read there. That is a fact about the LANGUAGE, not a finding that
# ``ide/`` is free of the things these clauses look for: it ships first-party crypto in TypeScript
# (``ide/src/cspNonce.ts`` draws CSPRNG bytes from ``node:crypto``; ``ide/src/engineClient.ts`` pins a
# TLS floor), none of which any Python walker can see. BACKLOG #1164 owns the TypeScript arm; this
# comment previously stated the exclusion as a property of the tree and that was the wrong fact.
#
# ``scripts/`` is walked by neither the ReDoS nor the single-JSON/URL-parser clause: it is
# build/release tooling not reachable from untrusted input, and the retired release-sync checker
# carries a release-version parser (``(\d+(?:\.\d+)*)(.*)$``) that matches the nested-quantifier shape
# while backtracking linearly. The scanner has no suppression mechanism, so walking it there would red
# the build on a measured false positive instead of finding a real defect.
#
# ``tests/`` is walked by no clause, for three MEASURED reasons (each verified by running the clause
# over the tree, not assumed): (a) ``tests/test_secret_rotation_inventory.py`` carries
# ``\bMEFOR_[A-Z0-9]+(?:_[A-Z0-9]+)*\b`` — nested-quantifier-SHAPED but linearly backtracking, the same
# false-positive class as scripts/; (b) ``tests/test_auth_oidc.py`` makes a genuine
# ``urllib.parse.urlparse`` call (asserting on a redirect URL) that the single-URL-parser clause would
# flag; (c) ``test_payload_agnostic_ingress.py``, ``test_soap_body_secrets.py`` and
# ``test_xml_parser_consistency.py`` import XML parsers directly and would red the XML allowlist. Note
# what is NOT a reason: THIS file's planted catastrophic patterns are string constants handed to
# ``find_nested_quantifiers``, never to an ``re.*`` call, so the ReDoS clause resolves nothing here and
# would not fire on it — that rationale was measured false and removed.
_REPO = Path(__file__).resolve().parent.parent
_PKG = _REPO / "messagefoundry"
_SOURCE_ROOTS = (_PKG, _REPO / "messagefoundry_webconsole", _REPO / "harness", _REPO / "tee")
_CRYPTO_ROOTS = (*_SOURCE_ROOTS, _REPO / "scripts")
_XML_ROOTS = _CRYPTO_ROOTS
_CRYPTO_GATE = _REPO / "scripts" / "security" / "crypto_inventory_check.py"

# A greedy *unbounded* quantifier inside a group that is itself greedy-unbounded-quantified — the
# classic catastrophic-backtracking shape: (a+)+, (a*)*, (\d+)*, (a{1,}){1,}, ((a+)x)+.
#
# This is a small hand-rolled scanner rather than a regex-over-regexes, because the regex form was
# wrong in two families that are just as catastrophic and just as statically visible:
#
# * BRACE quantifiers. `{n,}` with no upper bound is semantically identical to `+`/`*`, so
#   `(a{1,}){1,}`, `(a+){1,}` and `(a{2,})+` all backtrack exponentially — and a `[+*]`-only matcher
#   saw none of them. `{n}` and `{n,m}` are bounded and correctly ignored.
# * NESTED groups. The old form fenced the group body with `[^()]*`, so ANY group containing
#   parentheses was invisible: `((a+)x)+` and `((\d+)|x)+` both passed. Tracking the group stack
#   removes the fence entirely.
#
# Possessive (`*+`, `{1,}+`) and lazy (`*?`, `{1,}?`) suffixes are the ReDoS *mitigation*, not the
# shape, and are excluded — e.g. redaction.py's `*+`. Escapes (`\(`) and character classes (`[({]`)
# are skipped so a literal paren or brace is never read as structure. Applied to actual regex literals
# (re.* call args) only, so docstring prose like "(+ SOAPAction) +" and arithmetic like `(a + b) * c`
# are never misread as a regex.
#
# Measured before shipping: over every resolved pattern in every walked root (99 of them, including
# the 25 console route patterns the wrapper table below newly resolves), the stricter matcher finds
# exactly the same offender set as the old one — empty. So this is added coverage, not a re-baseline.
_UNBOUNDED_BRACE = re.compile(r"\{\d*(,(\d+)?)?\}")


def _quantifier_at(pattern: str, i: int) -> tuple[bool, int] | None:
    """``(is_unbounded, end_index)`` for a quantifier token at ``i``, or ``None`` if there is none."""
    if i >= len(pattern):
        return None
    char = pattern[i]
    if char in "+*":
        end = i + 1
        if end < len(pattern) and pattern[end] in "+?":
            return (False, end + 1)  # possessive / lazy: the mitigation, not the shape
        return (True, end)
    if char == "?":  # `?` quantifier, or the marker in `(?:`/`(?<!` — bounded either way
        end = i + 1
        return (False, end + 1 if end < len(pattern) and pattern[end] in "+?" else end)
    if char == "{":
        match = _UNBOUNDED_BRACE.match(pattern, i)
        if match is None:
            return None  # a literal brace, not a quantifier
        end = match.end()
        if end < len(pattern) and pattern[end] in "+?":
            return (False, end + 1)
        # `{n,}` (a comma with nothing after it) is unbounded; `{n}` and `{n,m}` are not.
        return (match.group(1) is not None and match.group(2) is None, end)
    return None


def _pattern_structure(pattern: str) -> tuple[list[tuple[int, int]], list[int]]:
    """``(group (open, close) index pairs, indices of unbounded quantifiers)`` for ``pattern``."""
    groups: list[tuple[int, int]] = []
    unbounded: list[int] = []
    stack: list[int] = []
    i = 0
    in_class = False
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":  # an escaped char is data, never structure
            i += 2
            continue
        if in_class:
            in_class = char != "]"
            i += 1
            continue
        if char == "[":
            in_class = True
        elif char == "(":
            stack.append(i)
        elif char == ")":
            if stack:
                groups.append((stack.pop(), i))
        else:
            quantifier = _quantifier_at(pattern, i)
            if quantifier is not None:
                if quantifier[0]:
                    unbounded.append(i)
                i = quantifier[1]
                continue
        i += 1
    return groups, unbounded


def _has_nested_quantifier(pattern: str) -> bool:
    """True if ``pattern`` unbounded-quantifies a group that itself contains an unbounded quantifier."""
    groups, unbounded = _pattern_structure(pattern)
    for open_i, close_i in groups:
        after = close_i + 1
        while after < len(pattern) and pattern[after].isspace():  # re.VERBOSE spacing
            after += 1
        quantifier = _quantifier_at(pattern, after)
        # `any(...)`: an unbounded quantifier at ANY nesting depth inside the group counts, which is
        # what the old `[^()]*` group fence could not express.
        if (
            quantifier is not None
            and quantifier[0]
            and any(open_i < pos < close_i for pos in unbounded)
        ):
            return True
    return False


# The re module functions whose first positional argument is a regex pattern.
_RE_FUNCS = frozenset(
    {"compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
)

#: First-party functions that COMPILE a pattern handed to them, mapped to the positional index of
#: that pattern — read exactly like an ``re.*`` call, at the CALL SITE.
#:
#: Without this the widened walk was vacuous for ``messagefoundry_webconsole/``: the scanner resolved
#: ZERO patterns anywhere in that package, because its entire regex inventory is the 25 route patterns
#: passed to ``register_ui_action(...)``, which ``_auth.py`` compiles and then ``fullmatch``es against
#: the attacker-supplied ``next`` path (``is_safe_ui_action`` / ``lookup_ui_action`` /
#: ``is_unlock_action``). The console's untrusted-facing patterns had gone from "not walked" to
#: "walked, unresolvable, pinned" — a reclassification, not coverage. All 25 arguments are static
#: string literals inside the walked tree, so this was a scanner choice, never a static-analysis limit.
#:
#: ``parsing/consistency.py``'s ``matches(msg, path, pattern)`` is deliberately NOT here: its pattern
#: is supplied by the code-first Handler author and is outside the target of evaluation per
#: ``docs/security/HANDLER-CODE-SHARED-RESPONSIBILITY.md``. That is the one wrapper blind spot the
#: owner scoping decision already accepts, and it stays recorded below rather than silently covered.
_PATTERN_WRAPPERS = {"register_ui_action": 0}


def _assign_targets(node: ast.AST) -> tuple[ast.Name, ast.expr] | None:
    """``(name, value)`` for a single-target ``NAME = value`` / ``NAME: T = value``, else ``None``."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target: ast.expr = node.targets[0]
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        target = node.target
    else:
        return None
    value = node.value
    if not isinstance(target, ast.Name) or value is None:
        return None
    return target, value


def _string_constants(tree: ast.Module) -> dict[str, str]:
    """Pass 1: ``NAME = "literal"`` string constants **in every scope** (composed ones included).

    Not just ``tree.body``: a pattern hoisted to a *function-local* constant or a *class attribute* is
    exactly as invisible to an inline-literal scanner as a module-level one, and dropping it silently
    is how a catastrophic pattern would pass. A name bound to two different literals in the same file
    is discarded as ambiguous rather than resolved to whichever won — reporting the wrong literal
    would be a fabricated finding.
    """
    names: dict[str, str] = {}
    ambiguous: set[str] = set()
    for node in ast.walk(tree):
        assignment = _assign_targets(node)
        if assignment is None:
            continue
        target, value = assignment
        resolved = _static_str(value, names)
        if resolved is None:
            continue
        if names.get(target.id, resolved) != resolved:
            ambiguous.add(target.id)
        names[target.id] = resolved
    for name in ambiguous:
        names.pop(name, None)
    return names


def _string_collections(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """``NAME = [...]`` / ``(...)`` / ``{...}`` tables whose every element (dict: value) is a literal.

    A pattern *table* is a real authoring shape: ``PATTERNS = ["…", "…"]`` then ``re.compile(p)`` in a
    loop, or ``re.compile(PATTERNS["x"])``. Every element is scanned when one of them reaches ``re.*``.
    """
    out: dict[str, tuple[str, ...]] = {}
    for node in ast.walk(tree):
        assignment = _assign_targets(node)
        if assignment is None:
            continue
        target, value = assignment
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            elements: list[ast.expr] = list(value.elts)
        elif isinstance(value, ast.Dict):
            elements = [v for v in value.values if v is not None]
            if len(elements) != len(value.values):  # a ``**other`` splat: contents unknown
                continue
        else:
            continue
        strings = [s for s in (_static_str(e, {}) for e in elements) if s is not None]
        if elements and len(strings) == len(elements):
            out[target.id] = tuple(strings)
    return out


def _iteration_bindings(
    tree: ast.Module, collections: dict[str, tuple[str, ...]]
) -> dict[str, str]:
    """Loop/comprehension variables bound to a known string table -> that table's name."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            continue
        target, iterated = node.target, node.iter
        if (
            isinstance(target, ast.Name)
            and isinstance(iterated, ast.Name)
            and iterated.id in collections
        ):
            out[target.id] = iterated.id
    return out


def _static_str(node: ast.expr, names: dict[str, str]) -> str | None:
    """The string ``node`` evaluates to using only literals and already-known constants.

    Handles the composition shapes that occur in this tree — a bare name, a class-attribute reference,
    ``a + b``, and an f-string interpolating constants — and gives up (``None``) on anything
    runtime-dependent, so a pattern built from a function argument or a ``'|'.join(...)`` is reported
    as unscannable rather than mis-scanned.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return names.get(node.id)
    if isinstance(node, ast.Attribute):
        # ``C.PATTERN`` — the class body's assignment is in the name map under ``PATTERN``. Loose (an
        # unrelated object with a same-named attribute resolves to it too), but it can only ADD a
        # pattern to the scan, never hide one.
        return names.get(node.attr)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_str(node.left, names)
        right = _static_str(node.right, names)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                resolved = _static_str(value.value, names)
                if resolved is None:
                    return None
                parts.append(resolved)
            else:  # pragma: no cover - JoinedStr holds only these two node types
                return None
        return "".join(parts)
    return None


def _re_bindings(tree: ast.Module) -> tuple[set[str], set[str]]:
    """``(local names bound to the re MODULE, local names bound to an re FUNCTION)``.

    Resolved per file because ``import re as _re`` and ``from re import compile`` are ordinary Python:
    a matcher hardcoded to the attribute shape ``re.<func>`` walks past both, which is a forward-looking
    hole in a regression gate even when the tree contains no instance today.
    """
    modules: set[str] = set()
    functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {a.asname or "re" for a in node.names if a.name == "re"}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "re":
            functions |= {a.asname or a.name for a in node.names if a.name in _RE_FUNCS}
    return modules, functions


def _pattern_argument(node: ast.Call, index: int = 0) -> ast.expr | None:
    """The pattern argument of an ``re.*``/wrapper call — positional **or** ``pattern=`` keyword."""
    if len(node.args) > index:
        return node.args[index]
    for keyword in node.keywords:
        if keyword.arg == "pattern":
            return keyword.value
    return None


def _pattern_call_index(node: ast.Call, modules: set[str], functions: set[str]) -> int | None:
    """The positional index of ``node``'s pattern argument, or ``None`` if it takes no pattern."""
    fn = node.func
    if isinstance(fn, ast.Attribute) and fn.attr in _RE_FUNCS:
        return 0 if isinstance(fn.value, ast.Name) and fn.value.id in modules else None
    if isinstance(fn, ast.Name):
        if fn.id in functions:
            return 0
        return _PATTERN_WRAPPERS.get(fn.id)
    return None


def _regex_scan(source: str) -> tuple[list[str], list[str]]:
    """``(resolved patterns, unparsed arguments that could not be resolved)`` for every ``re.*`` call.

    Excludes docstrings/prose/arithmetic — only real ``re.*`` arguments are read. The second element
    is what :data:`_UNSCANNABLE_RE_PATTERNS` pins, so the guard's blind spot is enumerated instead of
    described.
    """
    tree = ast.parse(source)
    names = _string_constants(tree)
    collections = _string_collections(tree)
    iterated = _iteration_bindings(tree, collections)
    modules, functions = _re_bindings(tree)
    resolved: list[str] = []
    unresolved: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        index = _pattern_call_index(node, modules, functions)
        if index is None:
            continue
        argument = _pattern_argument(node, index)
        if argument is None:  # e.g. re.compile(**kwargs): no pattern expression to read at all
            unresolved.append(ast.unparse(node))
            continue
        patterns = _pattern_strings(argument, names, collections, iterated)
        if patterns:
            resolved.extend(patterns)
        else:
            unresolved.append(ast.unparse(argument))
    return resolved, unresolved


def _pattern_strings(
    node: ast.expr,
    names: dict[str, str],
    collections: dict[str, tuple[str, ...]],
    iterated: dict[str, str],
) -> list[str]:
    """Every string the pattern argument ``node`` can evaluate to (empty = unresolvable)."""
    single = _static_str(node, names)
    if single is not None:
        return [single]
    if isinstance(node, ast.Name):
        if node.id in collections:
            return list(collections[node.id])
        if node.id in iterated:
            return list(collections[iterated[node.id]])
    # ``PATTERNS["x"]`` / ``PATTERNS[0]``: the index may be runtime, so scan the whole table.
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id in collections
    ):
        return list(collections[node.value.id])
    return []


def _regex_literals(source: str) -> list[str]:
    """Every statically resolvable ``re.*`` pattern in ``source``."""
    return _regex_scan(source)[0]


def find_nested_quantifiers(source: str) -> list[str]:
    """The catastrophic-shape regex patterns in ``source`` (empty list = clean)."""
    return [s for s in _regex_literals(source) if _has_nested_quantifier(s)]


def _py_files(*roots: Path) -> list[Path]:
    """Every first-party ``.py`` under ``roots`` (default :data:`_SOURCE_ROOTS`).

    Never point this at the repo root — ``.venv/`` lives there.
    """
    return sorted(
        p
        for root in (roots or _SOURCE_ROOTS)
        for p in root.rglob("*.py")
        if "__pycache__" not in p.parts
    )


#: Every ``re.*`` call in the walked roots whose pattern this scanner CANNOT resolve, as
#: ``repo-relative path -> the exact unresolvable EXPRESSIONS``. Two classes, both explained in the
#: module docstring: a wrapper parameter, and a pattern composed at runtime. None is a catastrophic
#: shape by inspection.
#:
#: The expressions, not a count. A ``path -> how many`` pin only detects a change in ARITY: swapping
#: one unscannable pattern source for a different and more dangerous one in the same file kept the
#: count and the gate stayed green (``re.fullmatch(pattern, value)`` becoming
#: ``re.fullmatch(build_pattern(untrusted), value)``, or logging_setup's join-composed redaction
#: pattern being rebuilt from a runtime source). Pinning WHERE each blind spot comes from is the
#: property the docstring's honesty clause actually claims.
_UNSCANNABLE_RE_PATTERNS = {
    # composed at runtime (each value is `ast.unparse` of the argument, i.e. its source text):
    "messagefoundry/config/impact.py": (
        r"""'^(?P<pre>\\s*' + re.escape(key) + '\\s*=\\s*)(?P<lit>(?P<q>[\\"\'])' + re.escape(old) + '(?P=q))'""",
    ),
    "messagefoundry/logging_setup.py": (
        r"""'(?i)\\b(' + '|'.join(_CREDENTIAL_QUERY_KEYS) + ')=[^&\\s\\"\']+'""",
    ),
    "messagefoundry/parsing/_builtin_hl7.py": ("f'{e}\\\\.({prefixes})(?!{e})'",),  # ASVS 1.3.3
    # ADR 0030 §4h: the site-code prefix is no longer a literal in the anonymizer — it is EXTERNALIZED
    # and loaded at runtime, so the detector is composed from the loaded value rather than written out.
    # That is the POINT of §4h (the prefix is customer data and must not sit in tracked source), and it
    # necessarily makes the expression unresolvable to this static scanner. The shape is bounded and
    # non-catastrophic by inspection: an alternation of digit literals followed by a fixed ``\d{4}`` —
    # no nested quantifier, no overlapping alternation.
    "messagefoundry/anon/surrogates.py": ("f'(?:{alt})\\\\d{{4}}'",),
    "tee/anon/surrogates.py": ("f'(?:{alt})\\\\d{{4}}'",),
    # a wrapper's parameter. NOTE: register_ui_action's own re.compile(pattern) stays here BY
    # CONSTRUCTION — its argument is the function's parameter — but every one of its 25 call sites is
    # now resolved through _PATTERN_WRAPPERS, so no console route pattern is unscanned. consistency.py
    # is the one genuinely-uncovered wrapper: an author-supplied pattern, out of ToE.
    "messagefoundry/parsing/consistency.py": ("pattern",),
    "messagefoundry_webconsole/_auth.py": ("pattern",),
}


def test_no_catastrophic_regex_in_source() -> None:
    offenders: list[str] = []
    for path in _py_files():
        for pat in find_nested_quantifiers(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(_REPO)}: {pat!r}")
    assert not offenders, "nested-quantifier (ReDoS) regex(es) found:\n" + "\n".join(offenders)


def test_the_scanners_blind_spots_are_the_recorded_ones() -> None:
    # The honesty clause, made checkable. Every re.* argument the scanner cannot resolve is recorded
    # per file AS THE EXPRESSION and compared to the pin above, so both a new blind spot and a CHANGED
    # one red the build rather than leaving a silently stale docstring.
    actual: dict[str, tuple[str, ...]] = {}
    for path in _py_files():
        _resolved, unresolved = _regex_scan(path.read_text(encoding="utf-8"))
        if unresolved:
            actual[path.relative_to(_REPO).as_posix()] = tuple(unresolved)
    assert actual == _UNSCANNABLE_RE_PATTERNS


def test_the_blind_spot_pin_records_expressions_not_just_counts() -> None:
    # A `path -> how many` pin only ever detects a change in ARITY: swapping one unscannable pattern
    # source for a different and more dangerous one in the same file keeps the count and the gate
    # stays green. That is the weaker property, and it is the only thing standing between the
    # docstring's honesty clause and drift. Demonstrated on the exact substitution that would slip
    # past, then asserted structurally against the real pin.
    before = "import re\ndef f(p, v):\n    return re.fullmatch(p, v)\n"
    after = "import re\ndef f(p, v):\n    return re.fullmatch(build_pattern(untrusted), v)\n"
    assert len(_regex_scan(before)[1]) == len(_regex_scan(after)[1])  # a count pin sees nothing...
    assert _regex_scan(before)[1] != _regex_scan(after)[1]  # ...an expression pin reds the build
    assert all(isinstance(v, tuple) for v in _UNSCANNABLE_RE_PATTERNS.values())


def test_a_wrapper_that_compiles_its_argument_is_read_at_the_call_site() -> None:
    # The clause that makes the webconsole walk non-vacuous. Planted, so it demonstrably bites.
    planted = 'from x import register_ui_action\nregister_ui_action("(a+)+$", None)\n'
    assert find_nested_quantifiers(planted) == ["(a+)+$"]
    # ...and the same shape hoisted to a constant, since that is how a route table would grow.
    hoisted = 'from x import register_ui_action\nP = "(a+)+$"\nregister_ui_action(P, None)\n'
    assert find_nested_quantifiers(hoisted) == ["(a+)+$"]
    # Anti-vacuity for the real tree: the console's route patterns are actually REACHED, not merely
    # walked past. Before the wrapper table the scanner resolved ZERO patterns in that whole package.
    resolved: list[str] = []
    for path in _py_files(_REPO / "messagefoundry_webconsole"):
        resolved += _regex_scan(path.read_text(encoding="utf-8"))[0]
    assert len(resolved) >= 25, f"the console route table stopped resolving: {len(resolved)}"
    assert any(p.startswith("^/ui/") for p in resolved), resolved


def test_the_walk_actually_covers_the_widened_roots() -> None:
    # Anti-vacuity: a typo'd root would make every clause below pass over an empty file list.
    walked = _py_files()
    for root in _SOURCE_ROOTS:
        assert any(p.is_relative_to(root) for p in walked), f"walked nothing under {root}"
    assert not any(".venv" in p.parts or "__pycache__" in p.parts for p in walked)
    # The clauses only bite because the widening happened, so the two root sets are pinned to explicit
    # basenames: a later narrowing has to edit a literal here rather than satisfy a tautology. (The
    # previous form, `_CRYPTO_ROOTS[:len(_SOURCE_ROOTS)] == _SOURCE_ROOTS`, was true by construction —
    # _CRYPTO_ROOTS is defined as `(*_SOURCE_ROOTS, …)` a few lines above it.)
    assert tuple(p.name for p in _SOURCE_ROOTS) == (
        "messagefoundry",
        "messagefoundry_webconsole",
        "harness",
        "tee",
    )
    # Unchanged as a tuple across the tee/ move, which is what BACKLOG #282's gate widening consumes.
    assert tuple(p.name for p in _CRYPTO_ROOTS) == (
        "messagefoundry",
        "messagefoundry_webconsole",
        "harness",
        "tee",
        "scripts",
    )
    assert all(p.is_dir() for p in _CRYPTO_ROOTS)
    assert _XML_ROOTS == _CRYPTO_ROOTS  # the XML clause walks everything; see the registry comment
    for root in _XML_ROOTS:
        assert any(p.is_relative_to(root) for p in _py_files(*_XML_ROOTS)), f"nothing under {root}"


def test_scanner_flags_a_planted_pattern() -> None:
    # The guard must actually catch the shape it claims to, so a real regression can't pass silently.
    planted = 'import re\nBAD = re.compile("(a+)+$")\nOK = re.compile("^[a-z]+$")\n'
    assert find_nested_quantifiers(planted) == ["(a+)+$"]


def test_scanner_flags_a_constant_passed_pattern() -> None:
    # The inline-literal scanner was blind to the shape below: hoist the pattern to a module constant
    # and it vanished from the guard. Pass 1 resolves it, so the same shape is caught by name...
    by_name = 'import re\nBAD = "(a+)+$"\nOK = "^[a-z]+$"\nre.compile(BAD)\nre.match(OK, "x")\n'
    assert find_nested_quantifiers(by_name) == ["(a+)+$"]
    # ...composed with `+`...
    concat = 'import re\n_P = "(a+)"\nre.compile(_P + "+$")\n'
    assert find_nested_quantifiers(concat) == ["(a+)+$"]
    # ...and interpolated into an f-string (the shape this tree actually uses for shared fragments).
    interpolated = 'import re\n_P = "(a+)"\nre.compile(f"^{_P}+$")\n'
    assert find_nested_quantifiers(interpolated) == ["^(a+)+$"]


@pytest.mark.parametrize(
    "source",
    [
        # The re module reached through a NON-literal binding: both forms are ordinary Python, and
        # an attribute-only matcher hardcoded to the name `re` walked past every one of them.
        'import re as _re\n_re.compile("(a+)+$")\n',
        'from re import compile\ncompile("(a+)+$")\n',
        'from re import compile as rc\nrc("(a+)+$")\n',
        'from re import sub\nsub("(a+)+$", "x", "y")\n',
        # The pattern passed by KEYWORD: the old loop skipped any call with no positional args.
        'import re\nre.compile(pattern="(a+)+$")\n',
        'import re\nre.sub(pattern="(a+)+$", repl="x", string="y")\n',
        # Constants outside the module top level — the only scope the old resolver looked at.
        'import re\ndef f():\n    P = "(a+)+$"\n    return re.compile(P)\n',
        'import re\nclass C:\n    P = "(a+)+$"\nre.compile(C.P)\n',
        # A pattern TABLE, reached by iteration or by subscript.
        'import re\nPATS = ["(a+)+$"]\nfor p in PATS:\n    re.compile(p)\n',
        'import re\nPATS = {"x": "(a+)+$"}\nre.compile(PATS["x"])\n',
        'import re\nPATS = ("(a+)+$",)\nCOMPILED = [re.compile(p) for p in PATS]\n',
        # A first-party wrapper that compiles what it is handed (the console's route table).
        'from x import register_ui_action\nregister_ui_action("(a+)+$", None)\n',
    ],
    ids=[
        "aliased-module",
        "from-import",
        "from-import-aliased",
        "from-import-sub",
        "keyword-pattern",
        "keyword-pattern-sub",
        "function-local-constant",
        "class-attribute",
        "table-iterated",
        "table-subscripted",
        "table-comprehension",
        "pattern-wrapper",
    ],
)
def test_scanner_flags_every_binding_and_scope_a_pattern_can_arrive_through(source: str) -> None:
    assert find_nested_quantifiers(source) == ["(a+)+$"], source


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+$",  # the classic, kept as the control
        "(a*)*$",
        "(\\d+)*$",
        "( a+ )+",  # re.VERBOSE spacing between the group and its quantifier
        # BRACE quantifiers: `{n,}` is unbounded and identical in effect to `+`/`*`. The previous
        # `[+*]`-only matcher saw NONE of these three.
        "(a{1,}){1,}",
        "(a+){1,}",
        "(a{2,})+",
        # NESTED groups: the previous `[^()]*` fence made any group containing parens invisible.
        "((a+)x)+",
        "((\\d+)|x)+",
        "(?P<name>a+)+",
    ],
)
def test_scanner_flags_every_catastrophic_shape_not_just_the_classic_one(pattern: str) -> None:
    assert _has_nested_quantifier(pattern), pattern


@pytest.mark.parametrize(
    "pattern",
    [
        "^[a-z]+$",
        "(abc)+",  # quantified group, nothing unbounded inside
        "(a+)",  # unbounded inside, group not quantified
        "(a{1,3}){1,3}",  # both quantifiers BOUNDED
        "(a+){2}",
        "(a+){2,5}",
        "(a+)?",
        "(a*+)*+",  # possessive: the ReDoS mitigation, e.g. redaction.py
        "(a+?)+?",  # lazy
        "\\(a+\\)+",  # ESCAPED parens: literal text, not a group
        "[({]+)+",  # a character class holding a paren/brace, not structure
        "(?:ab)+",  # non-capturing group, nothing unbounded inside
    ],
)
def test_scanner_does_not_flag_shapes_that_are_not_catastrophic(pattern: str) -> None:
    # The over-flagging half. A guard that reds on `(abc)+` or on a possessive quantifier would be
    # turned off, and the escaped-paren/character-class cases are where a naive matcher invents
    # structure that is not there.
    assert not _has_nested_quantifier(pattern), pattern


def test_scanner_does_not_guess_at_runtime_patterns() -> None:
    # A wrapper's parameter is unknowable statically; reporting it as a literal would be a fabricated
    # finding (and, worse, a fabricated clean bill of health when it resolved to something benign).
    runtime = "import re\ndef f(p):\n    return re.compile(p)\n"
    resolved, unresolved = _regex_scan(runtime)
    assert resolved == []
    assert unresolved == ["p"]  # ...but it IS counted, so the blind spot stays enumerated
    # A name bound to two different literals is ambiguous, not "whichever won".
    ambiguous = 'import re\nP = "(a+)+$"\ndef f():\n    P = "^ok$"\n    return re.compile(P)\n'
    assert _regex_scan(ambiguous)[0] == []
    # Nothing that merely LOOKS like an re call is read: a same-named method on another object, and
    # an re function name that was never imported from re.
    for benign in (
        'import re\nclass X:\n    def compile(self, p): ...\nX().compile("(a+)+$")\n',
        'from mymod import compile\ncompile("(a+)+$")\n',
    ):
        assert _regex_scan(benign) == ([], []), benign


def test_single_json_parser() -> None:
    forbidden = re.compile(
        r"^\s*(?:import|from)\s+(?:orjson|ujson|simplejson|rapidjson|cjson)\b", re.M
    )
    offenders = [
        str(p.relative_to(_REPO))
        for p in _py_files()
        if forbidden.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"alternate JSON parser imported (use stdlib json) in: {offenders}"


def test_single_url_parser() -> None:
    # urlparse splits params differently from urlsplit and is a classic SSRF parser-confusion source;
    # keep urlsplit as the one URL parser so the egress check and the request stay consistent.
    forbidden = re.compile(r"\burlparse\b")
    offenders = [
        str(p.relative_to(_REPO))
        for p in _py_files()
        if forbidden.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"urlparse used (use urllib.parse.urlsplit) in: {offenders}"


# --- ASVS 1.5.3: the XML parse-surface allowlist -----------------------------
#
# XML is the one data type this codebase parses with FOUR libraries. 1.5.1 is Pass because each is
# hardened at its own construction site — but nothing bound them together, so a fifth surface (or an
# unhardened re-use of an existing library) could land on review alone. This clause makes any NEW XML
# parse surface in the walked packages a build failure.

#: Top-level modules that parse XML. ``signxml`` is here because it parses XML through lxml — a new
#: module importing it would otherwise slip a whole XML surface past the gate — and ``openpyxl`` and
#: its siblings because OOXML/ODF *are* XML: ``load_workbook`` parses the package's XML parts with no
#: defusing at all. openpyxl is imported in a walked root TODAY (``harness/acceptance/report.py``), so
#: leaving it out while listing five libraries that appear nowhere in the tree was the gate
#: under-stating itself; ``tests/test_csv_formula_consistency.py``'s ``_SPREADSHEET_LIBS`` already
#: enumerated the same family. The remaining names are absent from the tree and listed
#: **pre-emptively**: stdlib ``pyexpat`` is directly importable and the others are one ``uv add`` away,
#: so naming them now means an added dependency trips the gate instead of sliding past. The clause
#: still matches *statically imported* module names only — see the docstring's blind-spot section.
_XML_PARSER_MODULES = frozenset(
    {
        "xml",
        "lxml",
        "defusedxml",
        "xmlschema",
        "signxml",
        "pyexpat",
        "xmltodict",
        "bs4",
        "untangle",
        "xmlsec",
        "zeep",
        # OOXML / ODF readers and writers — XML under the wrapper. Kept in step with
        # tests/test_csv_formula_consistency.py's _SPREADSHEET_LIBS.
        "openpyxl",
        "xlsxwriter",
        "xlwt",
        "odf",
        "odfpy",
        "pyexcel",
    }
)

#: The sanctioned XML parse surfaces, each with the hardening that makes it safe. Written against
#: ACTUAL import statements: a module that reaches a parser only through ``parsing/xml/_deps.py``
#: (``harden.py``, ``schema.py``, ``signature.py``, ``wsdl.py``, ``parsing/xml/message.py``) is NOT
#: listed — listing it would record a parse surface where there is none and make the stale-entry
#: check below unenforceable.
_XML_PARSER_ALLOWLIST = {
    "messagefoundry/parsing/message.py": (
        "defusedxml.ElementTree.fromstring with forbid_dtd/forbid_entities/forbid_external in "
        "RawMessage.xml(); the xml.etree import beside it is TYPE_CHECKING-only (Element, for hints)"
    ),
    "messagefoundry/corepoint_import.py": (
        "defusedxml.ElementTree.fromstring with forbid_dtd/forbid_entities/forbid_external, isolated "
        "in _hardened_fromstring() so tests/test_xml_parser_consistency.py drives THAT surface "
        "directly rather than the whole import (a structural 'no <ActionList>' refusal would make the "
        "hostile-corpus leg vacuous); the xml.etree import beside it is the ParseError type plus a "
        "TYPE_CHECKING-only Element hint. A Corepoint <Package> export is untrusted operator-supplied "
        "data (ADR 0086 §2(a'))"
    ),
    "messagefoundry/parsing/xml/_deps.py": (
        "the single lazy loader for the [xml] extra (lxml, xmlschema, signxml) — every consumer in "
        "parsing/xml/ goes through it, and lxml parsing is hardened once in harden.py"
    ),
    "messagefoundry/transports/soap.py": (
        "xml.sax well-formedness gate with external general/parameter entities off; it has no "
        "extraction API (a no-op ContentHandler), so it accepts or refuses and returns nothing"
    ),
    "harness/acceptance/runner.py": (
        "xml.etree over pytest's junit.xml, which the harness generates itself into its own "
        "TemporaryDirectory moments earlier — trusted, locally-produced input that never leaves the "
        "harness process. It is a HARNESS surface: no engine data reaches it"
    ),
    "harness/acceptance/report.py": (
        "openpyxl load_workbook over the operator's own acceptance spreadsheet, opened from a path "
        "the operator passes on the harness command line — trusted, locally-supplied input, and a "
        "HARNESS surface no engine data reaches. The formula-injection half of this write-back is "
        "ASVS 1.2.10's, held by tests/test_csv_formula_consistency.py"
    ),
    "scripts/ci/tooling_receipt.py": (
        "defusedxml.ElementTree.parse over pytest's junit.xml, written by the `tooling` job's own "
        "pytest invocation seconds earlier in the same runner workspace — the same shape as "
        "harness/acceptance/runner.py above, and a CI surface no engine data reaches. defusedxml "
        "rather than the stdlib parser that entry uses: its parse() forbids entity expansion and "
        "external references by default, so the XXE class is closed at the construction site even "
        "though the input is locally produced. Trusted-input arguments are the ones that rot when a "
        "file is later reused, so the safe parser is the entry's justification and the provenance is "
        "only why the residual risk is nil"
    ),
}

#: Modules allowed to reach lxml through ``parsing/xml/_deps.py``'s lazy loaders. The import clause
#: above matches XML *module names*, and the canonical in-tree route to lxml imports none:
#: ``from messagefoundry.parsing.xml._deps import load_lxml``. A new file could therefore call
#: ``load_lxml().fromstring(untrusted_body)`` — lxml's permissive defaults, no DOCTYPE refusal — and
#: the module-name clause would stay green, which is exactly the "unhardened re-use of an existing
#: library" the allowlist claims to catch. Five files already reach lxml this way, so the pattern is
#: established rather than hypothetical.
_XML_DEPS_CONSUMERS = frozenset(
    {
        "messagefoundry/parsing/xml/harden.py",
        "messagefoundry/parsing/xml/message.py",
        "messagefoundry/parsing/xml/schema.py",
        "messagefoundry/parsing/xml/signature.py",
        "messagefoundry/parsing/xml/wsdl.py",
    }
)

#: The lxml entry points that construct or run a parser. They must appear in ``harden.py`` ONLY —
#: that is the allowlist's own recorded rationale for the ``_deps.py`` entry ("lxml parsing is
#: hardened once in harden.py"), turned into a checked fact instead of a comment.
_LXML_PARSE_CALLS = frozenset({"XMLParser", "fromstring", "parse", "XML"})
_LXML_PARSE_HOME = "messagefoundry/parsing/xml/harden.py"


def _xml_parser_imports(source: str) -> set[str]:
    """Top-level XML-parser modules imported by ``source`` (AST, so indentation is irrelevant).

    An AST walk rather than a line-anchored regex on purpose: four of this tree's ten XML imports are
    indented — one inside ``if TYPE_CHECKING:`` and three inside function-local ``try`` blocks — and a
    ``^(?:import|from)`` matcher would miss every ``_deps.py`` loader while still reporting green.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found & _XML_PARSER_MODULES


def test_xml_parsers_are_confined_to_the_allowlist() -> None:
    offenders = sorted(
        f"{path.relative_to(_REPO).as_posix()}: {sorted(mods)}"
        for path in _py_files(*_XML_ROOTS)
        if (mods := _xml_parser_imports(path.read_text(encoding="utf-8")))
        and path.relative_to(_REPO).as_posix() not in _XML_PARSER_ALLOWLIST
    )
    assert not offenders, (
        "new XML parse surface(s) outside the ASVS 1.5.3 allowlist. Harden the parser at its "
        "construction site, add it to tests/test_xml_parser_consistency.py's corpus, and record it "
        f"in _XML_PARSER_ALLOWLIST: {offenders}"
    )


_XML_DEPS_LOADERS = frozenset({"load_lxml", "load_xmlschema", "load_signxml"})


def _deps_loader_users(source: str) -> set[str]:
    """References to ``parsing/xml/_deps``'s lazy loaders — the import-free route to a raw parser.

    Matches all three spellings: the ``from … import load_lxml`` (absolute or relative), a bare
    ``load_lxml`` name, and the ``_deps.load_lxml`` attribute form.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("_deps"):
            found |= {a.name for a in node.names if a.name in _XML_DEPS_LOADERS}
        elif isinstance(node, ast.Name) and node.id in _XML_DEPS_LOADERS:
            found.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in _XML_DEPS_LOADERS:
            found.add(node.attr)
    return found


def test_the_deps_loader_route_to_a_raw_parser_is_confined_too() -> None:
    # The bypass the module-name clause structurally cannot see: `from ..._deps import load_lxml`
    # imports no XML module, so `load_lxml().fromstring(untrusted)` would keep the gate green.
    offenders = sorted(
        f"{rel}: {sorted(names)}"
        for path in _py_files(*_XML_ROOTS)
        if (names := _deps_loader_users(path.read_text(encoding="utf-8")))
        and (rel := path.relative_to(_REPO).as_posix()) not in _XML_DEPS_CONSUMERS
    )
    assert not offenders, (
        "a module outside parsing/xml/ reaches an XML parser through the _deps lazy loaders, "
        "bypassing the import allowlist. Parse through messagefoundry.parsing.xml.harden instead, or "
        f"record it in _XML_DEPS_CONSUMERS: {offenders}"
    )
    # Anti-vacuity: the matcher really does see the shape, in every spelling it could arrive in.
    for planted in (
        "from messagefoundry.parsing.xml._deps import load_lxml\nx = load_lxml()\n",
        "from ._deps import load_lxml\nx = load_lxml().fromstring(body)\n",
        "from messagefoundry.parsing.xml import _deps\nx = _deps.load_lxml()\n",
    ):
        assert _deps_loader_users(planted) == {"load_lxml"}, planted
    assert _deps_loader_users("import os\nload_config()\n") == set()


def _lxml_parse_call_sites(source: str) -> set[str]:
    """``etree.<parse-entry-point>`` attribute calls in ``source``."""
    return {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _LXML_PARSE_CALLS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "etree"
    }


def test_lxml_parsing_really_is_hardened_in_exactly_one_place() -> None:
    # _XML_PARSER_ALLOWLIST's rationale for the _deps.py entry is "lxml parsing is hardened once in
    # harden.py". That was a comment; this makes it a fact. Every consumer resolves the module as
    # `etree`, so an `etree.fromstring(...)` anywhere else is an unhardened parse.
    offenders = sorted(
        f"{rel}: {sorted(calls)}"
        for path in _py_files(*_XML_ROOTS)
        if (calls := _lxml_parse_call_sites(path.read_text(encoding="utf-8")))
        and (rel := path.relative_to(_REPO).as_posix()) != _LXML_PARSE_HOME
    )
    assert not offenders, (
        f"lxml parsed outside {_LXML_PARSE_HOME} (its hardened parser is the only sanctioned "
        f"construction site): {offenders}"
    )
    # Anti-vacuity in both directions: harden.py really does hold them, and the matcher really bites.
    home = (_REPO / _LXML_PARSE_HOME).read_text(encoding="utf-8")
    assert {"XMLParser", "fromstring"} <= _lxml_parse_call_sites(home)
    assert _lxml_parse_call_sites("etree = load_lxml()\nr = etree.fromstring(body)\n") == {
        "fromstring"
    }


def test_xml_allowlist_has_no_stale_entries() -> None:
    # An entry for a file that no longer imports a parser is a false record of where XML is parsed.
    stale = sorted(
        rel
        for rel in _XML_PARSER_ALLOWLIST
        if not (_REPO / rel).is_file()
        or not _xml_parser_imports((_REPO / rel).read_text(encoding="utf-8"))
    )
    assert not stale, f"allowlisted file(s) no longer import an XML parser: {stale}"
    stale_deps = sorted(
        rel
        for rel in _XML_DEPS_CONSUMERS
        if not (_REPO / rel).is_file()
        or not _deps_loader_users((_REPO / rel).read_text(encoding="utf-8"))
    )
    assert not stale_deps, f"recorded _deps consumer(s) no longer use a loader: {stale_deps}"


def test_xml_import_scanner_sees_indented_imports() -> None:
    # The failure mode a line-anchored matcher would ship green with: _deps.py's three loaders are all
    # function-local, and parsing/message.py's xml.etree import sits inside `if TYPE_CHECKING:`.
    nested = (
        "def load():\n"
        "    try:\n"
        "        import lxml.etree as etree\n"
        "    except ImportError:\n"
        "        raise\n"
        "    return etree\n"
        "if TYPE_CHECKING:\n"
        "    from xml.etree.ElementTree import Element\n"
    )
    assert _xml_parser_imports(nested) == {"lxml", "xml"}
    assert _xml_parser_imports("from html import escape\nimport htmlmin\n") == set()


# --- WP-L3-02 (ASVS 11.1.3): cryptographic-discovery gate --------------------

#: Crypto call sites in :data:`_CRYPTO_ROOTS` that live OUTSIDE ``messagefoundry/``, kept as a
#: hand-maintained duplicate of the corresponding slice of ``crypto_inventory_check.py``'s own
#: ``INVENTORY`` so drift between the two is caught rather than assumed.
#:
#: STALE CLAIM CORRECTED (measured 2026-08-25): this docstring used to say the gate's own INVENTORY
#: "does not cover" these paths "because the shipped CLI still defaults to" messagefoundry/ alone,
#: and that BACKLOG #282 widening the walk would make this set redundant. #282 already landed --
#: WALK_ROOTS is ``("messagefoundry", "messagefoundry_webconsole", "harness", "tee", "scripts")``
#: today, and every entry below already has a matching entry in the gate's own INVENTORY (confirmed
#: by grep, not assumed). So this set is not filling a gap the gate misses; it is a second,
#: independently-maintained copy of one slice of it -- the same redundant-check shape #1301's and
#: #1338's banner guards use elsewhere in this ledger. Left as a TODO rather than deleted here: doing
#: that properly means confirming every remaining entry really is duplicated (not just the one this
#: commit is adding) and is a separate, larger cleanup from the fix this commit is landing.
_CRYPTO_SITES_OUTSIDE_THE_PACKAGE = {
    # ADR 0156: SHA-256 over the ASVS corpus FILE to pin it to the tagged release. No key.
    "scripts/asvs/scorecard.py": frozenset({"hashlib"}),
    # ADR 0156: SHA-256 over the ASVS SCORECARD file, printed truncated so a --prove-absences run
    # states which revision of the record it read. No key.
    "scripts/asvs/prove_report.py": frozenset({"hashlib"}),
    # BACKLOG #1405: SHA-256 over the ASVS SCORECARD file, printed truncated so an anchor report
    # states which revision of the record it read. The record is in another repository, so a commit
    # ref would name something the reader cannot resolve. No key.
    "scripts/asvs/anchor_report.py": frozenset({"hashlib"}),
    "messagefoundry_webconsole/_security.py": frozenset({"secrets"}),
    # BACKLOG #1276 part A: the harness supplies its own TLS certificate for a spawned engine rather
    # than chasing the one the engine mints -- see crypto_inventory_check.py's INVENTORY entry for
    # the same file, which this duplicates.
    "harness/load/tlsmat.py": frozenset({"ssl"}),
    "tee/__main__.py": frozenset({"ssl"}),
    "tee/anon/keying.py": frozenset({"hashlib"}),
    "tee/mefor_api.py": frozenset({"ssl"}),
    # ADR 0155: the DAST scan target mints a throwaway per-run password for the two ephemeral scan
    # identities it provisions into a temp-directory store it destroys with the run.
    "scripts/security/dast_target.py": frozenset({"secrets"}),
    # BACKLOG #1220: SHA-256 over the discovered engine/console seam surface, giving ENGINE_UI_SEAM an
    # identity nobody picks by hand. A change detector over public type signatures and field names --
    # no key, no secret, nothing user- or PHI-derived.
    "scripts/webconsole_seam_snapshot.py": frozenset({"hashlib"}),
    # BACKLOG #1433: SHA-256 over the shipped common-password corpus, recorded in the generated
    # block of its .NOTICE so the notice cannot describe a file that no longer exists. A change
    # detector over a published third-party wordlist -- no key, no secret, nothing PHI-derived.
    "scripts/security/build_password_corpus.py": frozenset({"hashlib"}),
}


def _crypto_gate_module() -> ModuleType:
    """Import ``scripts/security/crypto_inventory_check.py`` (not on ``sys.path``) by file path.

    Reusing the gate's OWN ``discover()`` rather than re-implementing the matcher here is the point:
    the two cannot disagree about what counts as a crypto call site.
    """
    spec = importlib.util.spec_from_file_location("mf_crypto_inventory_check", _CRYPTO_GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_crypto_roots_carry_no_unrecorded_call_site() -> None:
    # What makes _CRYPTO_ROOTS load-bearing instead of decorative: every root in the tuple is actually
    # walked here, so adding or removing one changes what is scanned. A `hashlib`/`ssl`/`secrets`
    # import appearing in harness/ or scripts/ — which carry none today — reds this.
    gate = _crypto_gate_module()
    discovered: dict[str, frozenset[str]] = {}
    for root in _CRYPTO_ROOTS:
        assert root.is_dir(), f"walk root does not exist: {root}"
        discovered |= gate.discover(root)
    documented = set(gate.INVENTORY) | set(_CRYPTO_SITES_OUTSIDE_THE_PACKAGE)
    undocumented = sorted(set(discovered) - documented)
    assert not undocumented, (
        "crypto call site(s) in the walked roots that no inventory covers — document them in "
        f"scripts/security/crypto_inventory_check.py (or here, for non-package roots): {undocumented}"
    )
    outside = {
        path: mods for path, mods in discovered.items() if not path.startswith("messagefoundry/")
    }
    assert outside == _CRYPTO_SITES_OUTSIDE_THE_PACKAGE


def test_the_crypto_seam_set_is_not_confined_to_one_package() -> None:
    """A single-package seam set is blind BY CONSTRUCTION to seams anywhere else (BACKLOG #1323).

    Before this pin, all five first-party seams were ``messagefoundry.store.*``, so no import made by
    a first-party TLS seam in another package could trigger a review — and a required, merge-blocking
    gate reported the same green whether that surface was sound or not.

    This asserts the SHAPE rather than a membership list, so it keeps biting as seams are added: a
    future narrowing back to one package reds it without anyone having to remember why.
    """
    gate = _crypto_gate_module()
    first_party = {s for s in gate.CRYPTO_SEAM_MODULES if s.startswith("messagefoundry.")}
    assert first_party, "no first-party seams at all — CRYPTO_SEAM_MODULES parse drifted"
    packages = {s.split(".")[1] for s in first_party}
    assert len(packages) > 1, (
        "every first-party crypto seam lives under messagefoundry."
        f"{next(iter(packages))}, so the gate cannot see a delegated-crypto seam in any other "
        f"package: {sorted(first_party)}"
    )


def test_the_alert_smtp_tls_seam_is_visible_to_the_gate() -> None:
    """BACKLOG #1323's worked example, pinned so the widening cannot silently revert.

    ``pipeline/alert_sinks.py`` imports ``smtplib`` and ``config.tls_policy`` and none of the six
    stdlib crypto modules. MEASURED before the fix: the gate reported GREEN over 64 sites with this
    file INVISIBLE — not undocumented, UNSEEN, which is the state a green cannot report. Adding the
    TLS-policy seam made it and ten siblings visible, taking the gate to 75 sites, still green.

    Asserts BOTH limbs on purpose: discovered (the gate can see it) and inventoried (it is accounted
    for). Either alone can hold while the other fails, and they fail for opposite reasons.
    """
    gate = _crypto_gate_module()
    discovered: dict[str, frozenset[str]] = {}
    for root in _CRYPTO_ROOTS:
        discovered |= gate.discover(root)

    target = "messagefoundry/pipeline/alert_sinks.py"
    assert (_REPO / target).is_file(), f"{target} has moved — re-derive this pin from the symbol"
    assert target in discovered, (
        f"{target} is a first-party TLS seam the crypto gate cannot SEE. It imports smtplib and "
        "messagefoundry.config.tls_policy but no stdlib crypto module, so it is only reachable "
        "through the seam set — check that messagefoundry.config.tls_policy is still in "
        "CRYPTO_SEAM_MODULES."
    )
    assert target in gate.INVENTORY, f"{target} is seen by the gate but carries no inventory row"


def test_crypto_inventory_gate_clean_on_real_tree() -> None:
    # The maintained inventory matches the actual crypto call sites — no drift.
    r = subprocess.run(
        [sys.executable, str(_CRYPTO_GATE)], capture_output=True, text=True, check=False
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_crypto_inventory_gate_flags_undocumented(tmp_path: Path) -> None:
    # A new module that imports crypto but isn't in the inventory trips the gate (a real regression
    # would too). Mirrors the WP-L3-02 acceptance: "a planted import hashlib trips the gate".
    pkg = tmp_path / "plantpkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "sneaky.py").write_text("import hashlib\n", encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(_CRYPTO_GATE), "--package", str(pkg)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1
    assert "sneaky.py" in r.stdout and "hashlib" in r.stdout
