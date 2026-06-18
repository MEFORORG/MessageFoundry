# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-L3-01 (ASVS 1.3.12, 1.5.3): static guards so the ReDoS posture and the single-parser-per-type
invariants can't silently regress.

* **No catastrophic regex.** No string literal in ``messagefoundry/`` uses a nested *unbounded*
  quantifier (the ``(a+)+`` / ``(\\d*)*`` shape that backtracks exponentially). Inbound HL7/X12 is
  size-capped *before* any regex runs (``peek.py`` / ``validate.py`` / ``x12/peek.py``), and routing
  patterns come from the trusted code-first Handler author — but a planted catastrophic pattern would
  still be a latent CPU-DoS, so the shape is forbidden outright. (This catches nested unbounded
  quantifiers; overlapping-alternation ReDoS like ``(a|a)*`` is not statically detected here.)
* **One parser per type.** stdlib ``json`` is the sole JSON parser and ``urllib.parse.urlsplit`` the
  sole URL parser, so an SSRF/egress host check can never disagree with the request it guards about a
  URL's host. Importing an alternate JSON parser (orjson/ujson/...) or the inconsistent ``urlparse``
  is forbidden.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent / "messagefoundry"
_CRYPTO_GATE = _PKG.parent / "scripts" / "security" / "crypto_inventory_check.py"

# A *greedy* unbounded quantifier inside a group that is itself *greedy*-unbounded-quantified — the
# classic catastrophic-backtracking shape: (a+)+, (a*)*, (\d+)*. A greedy unbounded quantifier is `+`
# or `*` that is NOT preceded by `+`/`*`/`?` (so the possessive/lazy suffix in `*+`/`*?` isn't read as
# its own quantifier) and NOT followed by `+` (possessive — the ReDoS *mitigation*, e.g. redaction.py's
# `*+`) or `?` (lazy). Applied to actual regex literals (re.* call args) only, so docstring prose like
# "(+ SOAPAction) +" and arithmetic like ``(a + b) * c`` are never misread as a regex.
_GREEDY = r"(?<![+*?])[+*](?![+?])"
_NESTED_QUANTIFIER = re.compile(rf"\([^()]*{_GREEDY}[^()]*\)\s*{_GREEDY}")

# The re module functions whose first positional argument is a regex pattern.
_RE_FUNCS = frozenset(
    {"compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
)


def _regex_literals(source: str) -> list[str]:
    """Every string literal passed as the *pattern* (first positional arg) to an ``re.<func>(...)``
    call — the real regex literals, excluding docstrings/prose/arithmetic."""
    out: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        fn = node.func
        if (
            isinstance(fn, ast.Attribute)
            and fn.attr in _RE_FUNCS
            and isinstance(fn.value, ast.Name)
            and fn.value.id == "re"
        ):
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                out.append(first.value)
    return out


def find_nested_quantifiers(source: str) -> list[str]:
    """The catastrophic-shape regex literals in ``source`` (empty list = clean)."""
    return [s for s in _regex_literals(source) if _NESTED_QUANTIFIER.search(s)]


def _py_files() -> list[Path]:
    return [p for p in _PKG.rglob("*.py") if "__pycache__" not in p.parts]


def test_no_catastrophic_regex_in_source() -> None:
    offenders: list[str] = []
    for path in _py_files():
        for pat in find_nested_quantifiers(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(_PKG.parent)}: {pat!r}")
    assert not offenders, "nested-quantifier (ReDoS) regex(es) found:\n" + "\n".join(offenders)


def test_scanner_flags_a_planted_pattern() -> None:
    # The guard must actually catch the shape it claims to, so a real regression can't pass silently.
    planted = 'import re\nBAD = re.compile("(a+)+$")\nOK = re.compile("^[a-z]+$")\n'
    assert find_nested_quantifiers(planted) == ["(a+)+$"]


def test_single_json_parser() -> None:
    forbidden = re.compile(
        r"^\s*(?:import|from)\s+(?:orjson|ujson|simplejson|rapidjson|cjson)\b", re.M
    )
    offenders = [
        str(p.relative_to(_PKG.parent))
        for p in _py_files()
        if forbidden.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"alternate JSON parser imported (use stdlib json) in: {offenders}"


def test_single_url_parser() -> None:
    # urlparse splits params differently from urlsplit and is a classic SSRF parser-confusion source;
    # keep urlsplit as the one URL parser so the egress check and the request stay consistent.
    forbidden = re.compile(r"\burlparse\b")
    offenders = [
        str(p.relative_to(_PKG.parent))
        for p in _py_files()
        if forbidden.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"urlparse used (use urllib.parse.urlsplit) in: {offenders}"


# --- WP-L3-02 (ASVS 11.1.3): cryptographic-discovery gate --------------------


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
