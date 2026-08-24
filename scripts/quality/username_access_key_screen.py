#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A reassignable username used as an ACCESS KEY lets a recycled account inherit objects.

``Identity`` carries an immutable ``user_id`` and a reassignable ``username``. A username is
freed by delete-and-recreate, so anywhere it scopes a RESOURCE -- a WHERE clause, a dict key, an
equality against a stored owner field, a store method's scoping parameter -- a recreated account
name inherits the previous holder's objects. Where it merely LABELS an audit row it is correct
and wanted: an audit trail should say who, in the form a human reads.

**THIS IS A SCREEN, NOT A SWEEP, AND THAT IS THE WHOLE POINT (BACKLOG #1226).** A sweep fixes
today's instances; a screen catches the next one. The justification is not the count: this class
was found three times by accident, in three subsystems, by sessions that were not looking for it
(BACKLOG #1015, #1152, #1225), and zero times on purpose. A class found only by accident is one
nothing is watching for.

**IT EMITS CANDIDATES FOR JUDGEMENT AND NEVER VERDICTS**, because an AST sees SHAPE and
*correctly keyed* is SEMANTICS. Some reported sites are correct code -- ``save(uploader=...)``
passes the username deliberately as a display label while a sibling ``uploader_id`` carries the
access key. A screen that auto-classified would be wrong on its own author's code, so this one
exits 0 whatever it finds and leaves the adjudication to a reader.

**IT PRINTS WHAT IT MATCHED, NOT A COUNT.** ``13`` looks identical whether it caught the write
key or missed it.

**IT MUST SEE WRITE SITES, NOT ONLY READ SCOPING**, and that is a measured requirement rather
than a nicety: BACKLOG #1225 was filed enumerating three preset sites when there were four, and
the missed one was the WRITE that sets what the other three read. A fix to only the readers would
not have held. The search that produced it was read-shaped and returned read-shaped results.

Keys are ``callee`` + ``argument``, deliberately, never a line number: the same defect site is
``create_search_preset`` or ``upsert_search_preset`` depending on where you stand, at two
different line numbers depending on your base.

Usage:
  username_access_key_screen.py FILE [FILE ...]   # screen the given files
  username_access_key_screen.py                   # screen the default API scope

Exit: 0 always when it ran (candidates are not failures), 2 on a usage error.
"""

from __future__ import annotations

import ast
import io
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

#: Screened by default: the modules that turn an authenticated caller into a resource query.
DEFAULT_SCOPE: tuple[str, ...] = (
    "messagefoundry/api/app.py",
    "messagefoundry/api/auth_routes.py",
)

#: Attribute whose use is being screened. The defect is about this one name.
_USERNAME_ATTR = "username"

#: Parameter/field names where a username is a LABEL -- it names who acted, for a human reader.
#: These are excluded, and the exclusion is reported so a silent narrowing is visible.
LABEL_NAMES: frozenset[str] = frozenset(
    {
        "actor",
        "acting_user",
        "acting_username",
        "actor_username",
        "approver",
        "by",
        "changed_by",
        "created_by_username",
        "display_name",
        "performed_by",
        "requester",
        "subject_username",
    }
)

#: Parameter/field names where a username SCOPES A RESOURCE. Membership makes a site a candidate.
#:
#: ``username`` IS DELIBERATELY ABSENT, and this is the one exclusion worth arguing for. A
#: ``username=`` parameter is overwhelmingly the shape where the username IS the subject rather
#: than a scope over someone else's resource: building a response DTO, creating an account,
#: authenticating, checking a password policy. Including it reported all of those and buried the
#: sites that matter. The class this screen exists for is a username scoping a RESOURCE, and that
#: arrives as ``owner``/``uploader``/``user``/``key`` -- which is where all three known instances
#: were found. A lookup keyed on the username of the very account being looked up is still
#: reachable through the positional rule below, so the shape is not dropped, only demoted.
ACCESS_KEY_NAMES: frozenset[str] = frozenset(
    {
        "owner",
        "owner_username",
        "uploader",
        "user",
        "key",
        "user_key",
        "scope",
        "for_user",
        "principal",
    }
)

#: A positional username is only a candidate when the CALLEE looks like it scopes or mutates a
#: stored resource. Without this the screen reported every audit-note and log call that takes a
#: username positionally, which is the noise that gets a screen switched off. ``security_events_for``
#: -- the unjudged candidate BACKLOG #1226 names -- matches on the ``_for`` suffix.
_SCOPING_CALLEE_PREFIXES: tuple[str, ...] = (
    "get_",
    "list_",
    "fetch_",
    "load_",
    "read_",
    "delete_",
    "remove_",
    "purge_",
    "upsert_",
    "create_",
    "insert_",
    "update_",
    "set_",
    "save_",
    "count_",
    "search_",
)
_SCOPING_CALLEE_SUFFIXES: tuple[str, ...] = ("_for", "_of", "_by_username", "_owned_by")


def _is_scoping_callee(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(_SCOPING_CALLEE_PREFIXES) or lowered.endswith(
        _SCOPING_CALLEE_SUFFIXES
    )


class Candidate:
    """One screened site. ``key`` is stable across rebases; ``line`` is for navigation only."""

    def __init__(self, path: str, line: int, callee: str, slot: str, kind: str, text: str) -> None:
        self.path = path
        self.line = line
        self.callee = callee
        self.slot = slot
        self.kind = kind
        self.text = text

    @property
    def key(self) -> str:
        return f"{self.callee}::{self.slot}"

    def render(self) -> str:
        return (
            f"{self.path}:{self.line}: [{self.kind}] {self.callee}({self.slot}=...) -- {self.text}"
        )


def _is_username_expr(node: ast.expr) -> bool:
    """True for ``<anything>.username``. Kept deliberately broad.

    Narrowing this to the literal receiver ``identity`` would make the screen blind the moment a
    route binds the same object to another name, which is the shape every instance of this class
    has arrived in.
    """
    return isinstance(node, ast.Attribute) and node.attr == _USERNAME_ATTR


def _callee_name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return "<expr>"


def _src(node: ast.AST, lines: list[str]) -> str:
    line = getattr(node, "lineno", 0)
    return lines[line - 1].strip()[:120] if 0 < line <= len(lines) else ""


def screen_source(path: str, source: str) -> tuple[list[Candidate], list[Candidate]]:
    """Return ``(candidates, excluded_labels)`` for one module."""
    tree = ast.parse(source, filename=path)
    lines = source.splitlines()
    candidates: list[Candidate] = []
    labels: list[Candidate] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = _callee_name(node.func)
            for kw in node.keywords:
                if kw.arg is None or not _is_username_expr(kw.value):
                    continue
                found = Candidate(
                    path, kw.value.lineno, callee, kw.arg, "call-keyword", _src(kw.value, lines)
                )
                if kw.arg in LABEL_NAMES:
                    labels.append(found)
                elif kw.arg in ACCESS_KEY_NAMES:
                    candidates.append(found)
                else:
                    found.kind = "call-keyword-unclassified"
                    candidates.append(found)
            for index, arg in enumerate(node.args):
                if not _is_username_expr(arg):
                    continue
                found = Candidate(
                    path, arg.lineno, callee, f"arg{index}", "call-positional", _src(arg, lines)
                )
                if _is_scoping_callee(callee):
                    candidates.append(found)
                else:
                    labels.append(found)
        elif isinstance(node, ast.Compare):
            for side in (node.left, *node.comparators):
                if _is_username_expr(side) and any(
                    isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops
                ):
                    other = node.comparators[0] if side is node.left else node.left
                    candidates.append(
                        Candidate(
                            path,
                            side.lineno,
                            _callee_name(other),
                            "==",
                            "equality",
                            _src(side, lines),
                        )
                    )
                    break
        elif isinstance(node, ast.Subscript) and _is_username_expr(node.slice):
            candidates.append(
                Candidate(
                    path,
                    node.slice.lineno,
                    _callee_name(node.value),
                    "[]",
                    "subscript-key",
                    _src(node, lines),
                )
            )

    return candidates, labels


#: Judged sites, one ``file::callee::slot`` per line. A key records that a HUMAN HAS LOOKED, never
#: that the site is correct -- several judged entries are deliberately correct code, and one is a
#: known defect awaiting its own item. Keys carry NO LINE NUMBER on purpose: the same site is
#: `create_search_preset` or `upsert_search_preset` depending where you stand, at different lines
#: depending on your base, which is why ``Candidate.key`` was built stable and unused until now.
DEFAULT_BASELINE = _ROOT / "scripts" / "quality" / "username_access_key_baseline.txt"


def load_baseline(path: Path) -> set[str]:
    out: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def main(argv: list[str]) -> int:
    # --baseline turns the screen from an advisory report into a step that can FAIL, WITHOUT making
    # it a verdict-emitter. It fails only on a key nobody has judged yet. Wiring it without this
    # would install a CI step that cannot fail for the reason it exists -- decoration that reads as
    # coverage, which is the class this screen was written to catch.
    baseline_path: Path | None = None
    if "--baseline" in argv:
        i = argv.index("--baseline")
        baseline_path = Path(argv[i + 1]) if i + 1 < len(argv) else DEFAULT_BASELINE
        argv = argv[:i] + argv[i + 2 :] if i + 1 < len(argv) else argv[:i]

    paths = argv or [str(_ROOT / p) for p in DEFAULT_SCOPE]
    all_candidates: list[Candidate] = []
    label_total = 0

    for raw in paths:
        path = Path(raw)
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"username-access-key: cannot read {raw}: {exc}\n")
            return 2
        rel = path.name if not path.is_absolute() else path.name
        candidates, labels = screen_source(rel, source)
        all_candidates.extend(candidates)
        label_total += len(labels)

    for candidate in sorted(all_candidates, key=lambda c: (c.path, c.line)):
        print(candidate.render())

    # Both halves are stated on every run. An exclusion nobody prints is a narrowing nobody can
    # review, and "no candidates" over an unstated scope is the silence this screen exists to end.
    print(
        f"username-access-key: {len(all_candidates)} candidate(s) FOR JUDGEMENT across "
        f"{len(paths)} file(s); {label_total} audit-label site(s) excluded as correct."
    )
    print(
        "  These are CANDIDATES, not defects. A username is correct as a label on an audit row "
        "and wrong as a key that scopes a resource; only a reader can tell which this is."
    )

    if baseline_path is None:
        return 0

    judged = load_baseline(baseline_path)
    seen = {f"{c.path}::{c.key}" for c in all_candidates}
    unjudged = sorted(seen - judged)
    resolved = sorted(judged - seen)

    # STATED EVEN WHEN EMPTY. A baseline entry that no longer matches is either a fixed site or a
    # screen that stopped seeing it, and those are opposite facts; printing the count is what lets a
    # reader notice the second one.
    print(f"  baseline: {len(judged)} judged, {len(seen)} seen, {len(resolved)} no longer reported")
    for key in resolved:
        print(f"    NO LONGER REPORTED (fixed, or the screen stopped seeing it): {key}")
    if not unjudged:
        return 0
    print("")
    print(
        "username-access-key: NEW UNJUDGED SITE(S) -- read each, then add its key to the baseline:"
    )
    for key in unjudged:
        print(f"    {key}")
    print(f"  baseline file: {baseline_path}")
    return 1


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    raise SystemExit(main(sys.argv[1:]))
