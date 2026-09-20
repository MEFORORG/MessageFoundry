# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1361: an operator-facing message must not name a config key the loader REJECTS.

ADR 0118 moved fifteen posture keys into ``[security]`` and ``_reject_relocated_keys`` REFUSES the old
spellings as file or env input. So a refusal, warning or ``--help`` string that tells an operator to set
one hands out a remediation that dies at load with "unrecognized config key(s)" -- authoritative-looking,
because it came from the gate itself, and only discoverable by spending a restart.

THE BUDGET IS A MECHANISM, AND IT IS CURRENTLY EMPTY -- so today this file bans the class outright. That
is a measured state, not a rule change: #1361 graded every budgeted site and every one of them was
reworded, so there is nothing left to tolerate. See ``_BUDGET`` for what each retired row was.

Naming a relocated key is still not AUTOMATICALLY wrong, which is why the mechanism stays. A message may
name one to explain WHY a check fired while prescribing a key that did not move. Grade such a site on what
an operator would DO with the sentence: a description of state can be re-budgeted with its reason, an
instruction to set a rejected key cannot.

SCANNED WITH ``ast``, NOT ``grep``. These messages are multi-line implicit concatenations: "requires " ends
one line and "[api].public_origin" starts the next, so a line-based scan matches neither and reports a clean
zero. ``ast`` joins them before the comparison. That exact false zero cost two sessions real time on #1026.
"""

from __future__ import annotations

import ast
import collections
import pathlib

from _ast_sites import find_funcs

from messagefoundry.config.settings import _RELOCATED_TO_SECURITY, _REMOVED_KEYS

_ENGINE = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry"

# Sites tolerated today, keyed by (path, old spelling) with the count as a CEILING. A ceiling rather than an
# equality so a fix that REMOVES one does not red the test -- PR 593 removes two from __main__.py.
_BUDGET: dict[tuple[str, str], int] = {}
# EMPTY ON PURPOSE, AND THAT IS THE WHOLE OF BACKLOG #1361's REMAINING LIMB. It is not an accident,
# and it is not a claim that the scanner stopped working -- test_the_census_examined_a_population and
# test_the_scanner_actually_detects_a_violation exist to tell those apart, so read their result
# before reading this dict's emptiness as good news.
#
# What each retired row was, so nobody re-adds one thinking it was tolerated on merit:
#
#   ([ai].data_class, 2) left with BACKLOG #1279 -- the key was REMOVED rather than relocated, so it
#   dropped out of the relocation map and the scanner can no longer produce that key at all.
#
#   The [api]/[ai] rows (12 budgeted, 10 live) were graded REWORD under #1361, because none of them
#   merely described state. Four were outright instructions that die at load: `--host` help named
#   [api].host as the file key the flag overrides, the DEBUG refusal said "set [ai].production=
#   false", the /ui refusal said "Bind [api].host to a loopback address", and api/app.py said "set
#   [api].serve_ui=false". The rest named [api].public_origin as the SUBJECT of a value complaint,
#   which sends an operator to a key they cannot have set -- the only file route to that value is
#   [security].web_console_public_address, which desugars into the internal field.
#
#   The [egress] six (reference_sync + wiring_runner) named the relocated SWITCH to explain a
#   refusal while prescribing [egress].allowed_db / allowed_http, keys that did NOT move. The
#   remediation always worked, so the FIX was never the defect and is unchanged. The EXPLANATION
#   was, and worse here than anywhere else in the budget: [egress].deny_by_default sat in one
#   sentence beside two live keys of that same real section, so it reads as equally settable. An
#   operator adding it to their [egress] block gets "unrecognized config key(s)" at next start.
#   They now name [security].block_unlisted_outbound, which is already how __main__.py spells this
#   switch in the warning fifteen lines above the DEBUG gate.
#
# Re-budgeting a site is still allowed -- add the row with the reason it DESCRIBES state rather than
# prescribing a fix. The bar is what an operator would DO with the sentence, not whether it is
# accurate about the internal field (docstrings, which do name the internal field, are excluded
# above for exactly that reason).

_PLANTED_VIOLATION = "\n".join(
    [
        "def f():",
        '    """A docstring naming [api].public_origin, which must NOT count."""',
        "    print(",
        '        "error: serving this requires "',
        '        "[api].public_origin -- set it and restart"',
        "    )",
    ]
)


def _old_spellings() -> set[str]:
    return {f"[{section}].{key}" for (section, key) in _RELOCATED_TO_SECURITY}


def _operator_facing_hits(source: str) -> list[str]:
    """Old spellings inside operator-facing literals of ``source``: print, raised errors, argparse help.

    Docstrings are excluded deliberately -- they describe the INTERNAL field, which really is spelled that
    way, and the field did not move even though the operator-facing key did.
    """
    tree = ast.parse(source)
    docstrings: set[int] = set()
    operator_facing: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name in {"print", "add_argument"} or (name and name.endswith("Error")):
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        operator_facing.add(id(child))
    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in docstrings or id(node) not in operator_facing:
            continue
        hits.extend(spelling for spelling in _old_spellings() if spelling in node.value)
    return hits


def _corpus() -> list[pathlib.Path]:
    return sorted(_ENGINE.rglob("*.py"))


def _census() -> collections.Counter[tuple[str, str]]:
    counts: collections.Counter[tuple[str, str]] = collections.Counter()
    for path in _corpus():
        rel = path.relative_to(_ENGINE.parent).as_posix()
        for spelling in _operator_facing_hits(path.read_text(encoding="utf-8")):
            counts[(rel, spelling)] += 1
    return counts


def test_the_census_examined_a_population() -> None:
    """THE DENOMINATOR. `found 0 of 24 examined` is a reading; `found 0 of 0 examined` is a failure,
    and the two print the same number.

    Without this, a wrong ``_ENGINE`` path makes both census tests below pass over ZERO files, and the
    positive control above does NOT catch it -- that one feeds the scanner a string and never touches
    the tree. So a clean census and an empty census are indistinguishable, in exactly the direction
    that reads as "nothing is wrong".
    """
    examined = len(_corpus())
    assert examined > 100, (
        f"the census examined {examined} files under {_ENGINE}; that is an empty or wrong corpus, not "
        "a clean one, and every other assertion in this file is vacuous when it happens"
    )


def test_the_scanner_actually_detects_a_violation() -> None:
    """POSITIVE CONTROL. A scanner that quietly stops matching passes this file forever, and a green run
    over a real corpus is exactly what that failure looks like. So prove it fires, on the multi-line
    concatenation shape a line-based grep cannot see, and prove the docstring beside it does NOT count."""
    assert _operator_facing_hits(_PLANTED_VIOLATION) == ["[api].public_origin"], (
        "the scanner missed a planted violation, so a clean census means nothing"
    )


def test_no_new_file_or_key_names_a_relocated_spelling() -> None:
    unbudgeted = sorted(k for k in _census() if k not in _BUDGET)
    assert not unbudgeted, (
        "operator-facing message(s) name a config key the loader REJECTS as file/env input "
        f"(ADR 0118): {unbudgeted}. Name the [security] key from _RELOCATED_TO_SECURITY instead, "
        "or add the site to _BUDGET with the reason it is describing state rather than prescribing a fix."
    )


def test_no_file_grows_its_share_of_the_class() -> None:
    """DORMANT WHILE ``_BUDGET`` IS EMPTY -- it iterates the budget, so an empty one makes it vacuous.

    Say so rather than let it read as the guard that is holding: with no budgeted sites the weight is
    entirely on test_no_new_file_or_key_names_a_relocated_spelling above, which reds on ANY hit. This
    one wakes up again the moment a site is legitimately re-budgeted, and it is kept for that.
    """
    counts = _census()
    grown = {k: (counts[k], ceiling) for k, ceiling in _BUDGET.items() if counts[k] > ceiling}
    assert not grown, f"more sites than budgeted (actual, ceiling): {grown}"


def test_the_two_fixed_refusals_name_the_key_the_loader_accepts() -> None:
    """Pinned against the relocation map, not a literal: the next relocation must red here rather than
    drift. These are the two #1361 fixed, and a revert of either reds this."""
    expected_origin = _RELOCATED_TO_SECURITY[("api", "public_origin")]
    settings_src = (_ENGINE / "config" / "settings.py").read_text(encoding="utf-8")

    # READ THE RAISED MESSAGE, NOT A CHARACTER WINDOW AROUND THE FUNCTION. A window swallows the
    # docstring, which names the [security] key to explain the rule -- so a window-based assertion is
    # satisfied by the docstring alone and stays green after the MESSAGE is reverted. Mutation-testing
    # caught exactly that: reverting the fix left this test passing and only the count ceiling red.
    raised: list[str] = []
    for node in find_funcs(ast.parse(settings_src), "_oidc_requires_public_origin"):
        for child in ast.walk(node):
            if isinstance(child, ast.Raise):
                raised.extend(
                    c.value
                    for c in ast.walk(child)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)
                )
    assert raised, "the OIDC validator no longer raises with a literal message; re-anchor this test"
    message = "".join(raised)
    assert expected_origin in message, (
        f"the OIDC refusal must name [security].{expected_origin}, the key the loader accepts; it says: "
        f"{message!r}"
    )
    assert "[api].public_origin" not in message, (
        "the OIDC refusal still names the relocated spelling, which the loader REFUSES as file/env input"
    )

    scaffold_src = (_ENGINE / "scaffold.py").read_text(encoding="utf-8")
    for (section, key), replacement in _RELOCATED_TO_SECURITY.items():
        if section == "ai":
            assert f"[{section}].{key}" not in scaffold_src, (
                f"the scaffolded README tells a new operator to set [{section}].{key}, which the loader "
                f"REFUSES; the config file it generates alongside says so. Name [security].{replacement}."
            )

    # BACKLOG #1279: the loop above reads the RELOCATED map, so it is blind to a key that was
    # REMOVED -- and a removed key is worse to scaffold, because the refusal cannot name a
    # replacement spelling to redirect the operator to.
    #
    # It matches the BARE key, not the `[section].key` form the loop above uses, because the
    # scaffolder emits a `messagefoundry.toml` as well as a README: a commented
    # `# handles_real_patient_data = true` line under a `[security]` header is an instruction, and
    # uncommenting it fails the next start. That is how two such lines survived the first pass.
    for _section, removed_key in _REMOVED_KEYS:
        assert removed_key not in scaffold_src, (
            f"the scaffolder emits {removed_key!r}, which the loader REFUSES outright. It was removed "
            "rather than relocated, so there is no replacement spelling to point at -- say what the "
            "operator should do instead."
        )
