# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1361: an operator-facing message must not name a config key the loader REJECTS.

ADR 0118 moved the posture keys into ``[security]`` and ``_reject_relocated_keys`` REFUSES the old
spellings as file or env input. So a refusal, warning or ``--help`` string that tells an operator to set
one hands out a remediation that dies at load with "unrecognized config key(s)" -- authoritative-looking,
because it came from the gate itself, and only discoverable by spending a restart.
``_RELOCATED_TO_SECURITY`` is the roster of those keys, and this file reads it at run time rather than
restating its size here. A hand-written count is a second definition of the same fact, and it goes stale
the day a key is relocated or retired -- tests/test_docs_cite_no_refused_config_keys.py dropped one for
exactly that reason. One key, ``[ai].data_class``, was REMOVED rather than relocated (BACKLOG #1279), so
it left that map for ``_REMOVED_KEYS``.

THE BUDGET IS A MECHANISM, AND IT IS CURRENTLY EMPTY: across both corpus roots every relocated spelling
now reds. That is a measured state, not a rule change -- #1361 graded and reworded every engine site, and
#1365 did the same for the three web console ones. See ``_BUDGET`` for what each retired row was.

DO NOT READ THAT EMPTY BUDGET AS "THE PRODUCT IS CLEAN". It says the two roots below are clean under the
aperture below, and nothing wider. The harness, the IDE extension, ``scripts/`` and the docs are not
scanned, and a message written in any of them can name a rejected key just as easily.

Naming a relocated key is still not AUTOMATICALLY wrong, which is why the budget mechanism stays. A
message may name one to explain WHY a check fired while prescribing a key that did not move. Grade such a
site on what an operator would DO with the sentence: a description of state can be re-budgeted with its
reason, an instruction to set a rejected key cannot.

THE REPLACEMENT SPELLING NEEDS ITS OWN GUARD, which is
``test_every_security_key_named_in_a_message_is_a_real_field``. Every check above asks whether a message
names an OLD key; none asks whether the NEW one it was reworded to exists. A typo there reproduces the
exact defect this file was written against -- ``[security].blok_unlisted_outbound`` is refused at load
with "unrecognized config key(s)" just as the relocated spelling is -- and nothing else in this
repository looks.

SCANNED WITH ``ast``, NOT ``grep``. These messages are multi-line implicit concatenations: "requires " ends
one line and "[api].public_origin" starts the next, so a line-based scan matches neither and reports a clean
zero. ``ast`` joins them before the comparison. That exact false zero cost two sessions real time on #1026.

THE CORPUS IS THE ENGINE **AND** THE WEB CONSOLE, AND THE APERTURE HAD TO WIDEN WITH IT. The web console is
where an operator reads most of these messages -- it is the sole operator console -- so scanning the engine
alone graded the quieter half of the surface. Widening the corpus ALONE catches nothing, which is why both
axes moved in one change: measured over ``messagefoundry_webconsole/`` before the #1361 fix, the print /
``add_argument`` / ``*Error`` aperture returned 0 rows across 35 files while the three real violations sat
there. None of the three is a ``print`` or a raise, and one is not a CALL at all:

- **logging methods** (``_log.warning`` and siblings) -- a runtime posture failure is diagnosed from the
  service log, so that string has the same audience as a refusal, just later;
- **``el(...)``** -- the web console's HTML element renderer, which is how a notice reaches the PAGE. A
  string handed to ``el`` is read by a signed-in operator, which is as operator-facing as text gets;
- **module-level UPPER_CASE assignments** -- ``WEBAUTHN_RP_MISSING_NOTICE`` is a shared constant rendered
  on three separate surfaces, and NO call-based arm reaches its definition. The constant rule is what makes
  that site visible, not a nicety on top of the call arms. It claims every string reached from the
  assignment, a table of notices included, rather than a lone literal only.

BLAST RADIUS OF THE WIDENING WAS MEASURED, NOT ASSUMED. Over the PRE-rework engine tree the census returns
the same 8 (path, spelling) rows under the old aperture and the new one, so widening found nothing in the
engine the narrow aperture had been missing. In the web console it found everything: ALL THREE sites were
invisible to the old aperture, not two of them -- none is a ``print`` or a raise, so the number of missed
sites equals the number of sites. An earlier draft of this docstring said two, counting the ``el`` render
as though it were already reachable; re-measured 2026-09-20 with a positive control, the narrow aperture
returns zero rows over that tree.

So no budget row was added for either root -- a widening that needed one would have been a finding, not
paperwork. Re-measured on THIS tree, after both reworks, each root returns zero, which is why
:data:`_BUDGET` is empty rather than merely shorter.
"""

from __future__ import annotations

import ast
import collections
import pathlib
import re

from _ast_sites import find_funcs

from messagefoundry.config.settings import (
    _RELOCATED_TO_SECURITY,
    _REMOVED_KEYS,
    SecuritySettings,
)

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_ENGINE = _ROOT / "messagefoundry"
#: The operator console (ADR 0065). Second corpus root, not a replacement -- see the module docstring.
_WEBCONSOLE = _ROOT / "messagefoundry_webconsole"

#: Each corpus root with the floor its denominator check uses, and the ONE structure both the census and
#: that check read -- a second list of roots could drift out of step with this one in silence. Adding a
#: root without a floor is a loud ``KeyError``, which is the failure you want here.
#:
#: The floors differ because the roots do (275 files against 35), and collapsing them to one number costs
#: real coverage in whichever direction it is set: 100 reds the web console on a healthy tree, and 10
#: stops the engine check from catching a path that resolved to a SUBDIRECTORY rather than to nothing.
#: So the engine keeps the 100 it always had.
_CORPUS_FLOOR: dict[pathlib.Path, int] = {_ENGINE: 100, _WEBCONSOLE: 10}
_CORPORA = tuple(_CORPUS_FLOOR)

#: Per-root floor for the ``[security].X`` MENTION denominator, keyed like :data:`_CORPUS_FLOOR` so a
#: new root without a floor is the same loud ``KeyError``. Separate from that dict because it counts
#: mentions, not files.
#:
#: PER ROOT for the reason :func:`test_the_census_examined_a_population` gives about its own denominator.
#: Measured 2026-09-20 the engine carries 123 of the 128 mentions and the web console 5, so ONE aggregate
#: floor is cleared by the engine alone -- a ``_WEBCONSOLE`` that resolved to nothing would scan zero
#: files and the total would still pass. The console's floor is 0 rather than a headcount because what
#: this catches is an EMPTY root; pinning its handful of mentions would red on an ordinary reword.
_MENTION_FLOOR: dict[pathlib.Path, int] = {_ENGINE: 50, _WEBCONSOLE: 0}

#: Calls whose string arguments an operator reads. ``print``/``add_argument``/``*Error`` are the original
#: three; the rest arrived with the web console corpus.
#:
#: The logging arm takes the METHOD name off the receiver, so ``_log.warning(...)``, ``log.warning(...)``
#: and ``self._log.warning(...)`` all match and no logger-naming convention has to be pinned here.
_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "critical", "exception", "log"})
#: ``el`` is the web console's HTML element renderer: a string passed to it is rendered into the page.
_OPERATOR_FACING_CALLS = frozenset({"print", "add_argument", "el"}) | _LOG_METHODS

# Sites tolerated today, keyed by (path, old spelling) with the count as a CEILING. A ceiling rather than an
# equality so a fix that REMOVES one does not red the test -- PR 593 removes two from __main__.py.
_BUDGET: dict[tuple[str, str], int] = {}
# EMPTY ON PURPOSE, AND THAT IS THE WHOLE OF BACKLOG #1361's REMAINING LIMB. It is not an accident,
# and it is not a claim that the scanner stopped working -- test_the_census_examined_a_population,
# test_the_scanner_actually_detects_a_violation and test_every_aperture_arm_still_fires exist to tell
# those apart, so read their result before reading this dict's emptiness as good news. The third
# matters most now that the aperture has several arms: one arm going quiet empties this dict too.
#
# What each retired row was, so nobody re-adds one thinking it was tolerated on merit:
#
#   ([ai].data_class, 2) left with BACKLOG #1279 -- the key was REMOVED rather than relocated, so it
#   dropped out of the relocation map and the scanner can no longer produce that key at all.
#
#   The [api]/[ai] rows were graded REWORD under #1361, because none of them merely described state.
#   17 BUDGETED, 13 LIVE -- re-counted 2026-09-20 by running the census over the pre-rework tree,
#   which is the only way to read the live figure, since the budget is a CEILING and never had to
#   match. (A first pass reported 12 and 10 from memory rather than from the scanner. The ceilings
#   sum to 2+3+6+3+1+2 = 17; the census found [ai].production 1, [api].host 3, [api].public_origin 4
#   + 2, [api].serve_ui 2 + 1 = 13.) Both figures re-verified on the rebase under the WIDENED aperture
#   and are unchanged: the engine carried nothing that only the new arms can see. Four sites were
#   outright instructions that die at load: `--host`
#   help named [api].host as the file key the flag overrides, the DEBUG refusal said "set
#   [ai].production=false", the /ui refusal said "Bind [api].host to a loopback address", and
#   api/app.py said "set [api].serve_ui=false". The rest named [api].public_origin as the SUBJECT of
#   a value complaint, which sends an operator to a key they cannot have set -- the only file route
#   to that value is [security].web_console_public_address, which desugars into the internal field.
#
#   The [egress] six (reference_sync + wiring_runner) named the relocated SWITCH to explain a
#   refusal while prescribing [egress].allowed_db / allowed_http, keys that did NOT move. The
#   remediation always worked, so the FIX was never the defect and is unchanged. The EXPLANATION
#   was, and worse here than anywhere else in the budget: [egress].deny_by_default sat in one
#   sentence beside two live keys of that same real section, so it reads as equally settable. An
#   operator adding it to their [egress] block gets "unrecognized config key(s)" at next start.
#   All six now share settings.BLOCK_UNLISTED_OUTBOUND_IN_FORCE, one constant beside the field.
#   The first rework gave each its own copy reading "[security].block_unlisted_outbound is set",
#   which is FALSE on the common path: __main__ flips the switch on for any PHI instance that left
#   it unset (announced there as "defaulted ON"), so the usual way this refusal fires is an operator
#   who set nothing being told they set something. Six copies is also how five stay right while the
#   sixth goes stale, which is the duplication class this whole row is about.
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

#: One planted case PER APERTURE ARM. An arm with no control is an arm that can silently stop matching,
#: and the whole file stays green while it does -- which is indistinguishable from a clean corpus. Each
#: is written in the multi-line implicit-concatenation shape the real sites use, and each carries a
#: docstring naming the same spelling to prove the docstring exclusion is still load-bearing per arm.
#:
#: ``print`` is the one arm NOT here: :data:`_PLANTED_VIOLATION` above is its control and predates this
#: table. The other two pre-existing arms, ``add_argument`` and ``*Error``, had none at all -- they were
#: added with the #1361 widening rather than left uncovered, so the name of the test that reads this
#: table is true rather than nearly true.
_PLANTED_BY_ARM: dict[str, str] = {
    "add_argument help": "\n".join(
        [
            "def f(p):",
            '    """A docstring naming [api].public_origin, which must NOT count."""',
            "    p.add_argument(",
            '        "--public-origin",',
            '        help="overrides [api].public_origin "',
            '        "for this run",',
            "    )",
        ]
    ),
    "raised *Error": "\n".join(
        [
            "def f():",
            '    """A docstring naming [api].public_origin, which must NOT count."""',
            "    raise ConfigError(",
            '        "serving this requires "',
            '        "[api].public_origin -- set it and restart"',
            "    )",
        ]
    ),
    "logger call": "\n".join(
        [
            "def f():",
            '    """A docstring naming [api].public_origin, which must NOT count."""',
            "    _log.warning(",
            '        "federated sign-in unavailable: "',
            '        "[api].public_origin is not set"',
            "    )",
        ]
    ),
    "el() render": "\n".join(
        [
            "def f():",
            '    """A docstring naming [api].public_origin, which must NOT count."""',
            "    return el(",
            '        "p",',
            '        "Changing [api].public_origin "',
            '        "invalidates enrolled passkeys.",',
            "    )",
        ]
    ),
    "module-level UPPER_CASE constant": "\n".join(
        [
            '"""A MODULE docstring naming [api].public_origin, which must NOT count."""',
            "",
            "NOTICE = (",
            '    "Passkeys are unavailable: [api].public_origin "',
            '    "is not set -- contact your administrator."',
            ")",
        ]
    ),
}

#: NEGATIVE control for the constant arm alone. Its scope -- module level, UPPER_CASE -- is the novel
#: part of the widening, and a rule that quietly matched every assignment would claim ordinary local
#: strings and still pass every positive case above. So prove the narrowing is real, in both directions.
_PLANTED_NOT_A_CONSTANT = "\n".join(
    [
        "notice = 'a lowercase module global naming [api].public_origin'",
        "",
        "",
        "class C:",
        "    NOTICE = 'a CLASS attribute naming [api].public_origin'",
        "",
        "",
        "def f():",
        "    NOTICE = 'a function LOCAL naming [api].public_origin'",
        "    return NOTICE",
    ]
)


def _old_spellings() -> set[str]:
    return {f"[{section}].{key}" for (section, key) in _RELOCATED_TO_SECURITY}


def _operator_facing_literals(source: str) -> list[str]:
    """The string literals of ``source`` that reach an operator.

    Three kinds of site: a call an operator reads (:data:`_OPERATOR_FACING_CALLS`), anything raised as
    ``*Error``, and any string reached from a module-level UPPER_CASE assignment -- a bare constant, or
    one nested in a dict, tuple or list of them, since a notice table is as much a notice as a lone
    string is. Every matcher carries its own planted case below, because an arm with no control can stop
    matching in silence.

    The constant kind is not a call at all, and that is the point of it: a shared notice is DEFINED once
    and rendered somewhere else entirely, so every call-based arm looks at the render site and finds a
    bare name there.

    Docstrings are excluded deliberately -- they describe the INTERNAL field, which really is spelled that
    way, and the field did not move even though the operator-facing key did.
    """
    tree = ast.parse(source)
    docstrings: set[int] = set()
    operator_facing: set[int] = set()

    def claim(node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                operator_facing.add(id(child))

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
            if name in _OPERATOR_FACING_CALLS or (name and name.endswith("Error")):
                claim(node)

    # MODULE LEVEL ONLY, and UPPER_CASE only. Walking every assignment would claim ordinary local strings
    # and turn this guard into a grep with extra steps; the narrow rule targets the shape a shared notice
    # actually has. `tree.body` rather than `ast.walk` is what makes "module level" true rather than
    # approximate -- a class attribute or a function local is not a shared operator notice.
    for stmt in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets, value = list(stmt.targets), stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            # `NOTICE: Final = "..."` is the same declaration with an annotation, and an AnnAssign's
            # value is genuinely optional (`NOTICE: str` declares without assigning), hence the guard.
            targets, value = [stmt.target], stmt.value
        if value is not None and any(isinstance(t, ast.Name) and t.id.isupper() for t in targets):
            claim(value)

    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
        and id(node) in operator_facing
    ]


def _operator_facing_hits(source: str) -> list[str]:
    """Old spellings inside the operator-facing literals of ``source``."""
    return [
        spelling
        for text in _operator_facing_literals(source)
        for spelling in _old_spellings()
        if spelling in text
    ]


def _corpus(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(root.rglob("*.py"))


def _census() -> collections.Counter[tuple[str, str]]:
    counts: collections.Counter[tuple[str, str]] = collections.Counter()
    for root in _CORPORA:
        for path in _corpus(root):
            # Relative to the REPO root, so a key reads "messagefoundry/x.py" or
            # "messagefoundry_webconsole/y.py" and _BUDGET keys stay unambiguous across the two roots.
            rel = path.relative_to(_ROOT).as_posix()
            for spelling in _operator_facing_hits(path.read_text(encoding="utf-8")):
                counts[(rel, spelling)] += 1
    return counts


def test_the_census_examined_a_population() -> None:
    """THE DENOMINATOR. `found 0 of 24 examined` is a reading; `found 0 of 0 examined` is a failure,
    and the two print the same number.

    Without this, a wrong corpus path makes both census tests below pass over ZERO files, and the
    positive control above does NOT catch it -- that one feeds the scanner a string and never touches
    the tree. So a clean census and an empty census are indistinguishable, in exactly the direction
    that reads as "nothing is wrong".

    PER ROOT, NOT OVER THE TOTAL, and the reason is the SDS-3.8 shape this file already worries about.
    The engine carries 275 files and the web console 35, so a single ``total > 100`` is satisfied by the
    engine alone: a broken ``_WEBCONSOLE`` path would hide behind it and the assertion would still pass,
    while every web console row silently left the census. So each root is asserted separately, against
    its own floor (:data:`_CORPUS_FLOOR`), and the failure NAMES which root came back empty.
    """
    for root in _CORPORA:
        examined = len(_corpus(root))
        floor = _CORPUS_FLOOR[root]
        assert examined > floor, (
            f"the census examined {examined} files under {root}, at or below the floor of {floor}; "
            f"that is an empty or wrong corpus root ({root.name}), not a clean one, and every other "
            "assertion in this file is vacuous for that root when it happens"
        )


def test_the_scanner_actually_detects_a_violation() -> None:
    """POSITIVE CONTROL. A scanner that quietly stops matching passes this file forever, and a green run
    over a real corpus is exactly what that failure looks like. So prove it fires, on the multi-line
    concatenation shape a line-based grep cannot see, and prove the docstring beside it does NOT count."""
    assert _operator_facing_hits(_PLANTED_VIOLATION) == ["[api].public_origin"], (
        "the scanner missed a planted violation, so a clean census means nothing"
    )


def test_every_aperture_arm_still_fires() -> None:
    """ONE CONTROL PER ARM. The widening for the web console corpus added three ways a string reaches an
    operator, and a green census proves nothing about an arm that stopped matching -- it looks identical
    to that arm having nothing to find. Each planted case is the shape of a real #1361 site.

    Covers the two pre-existing arms that had no control either (``add_argument``, ``*Error``); ``print``
    keeps its own, :func:`test_the_scanner_actually_detects_a_violation`. So every matcher this scanner
    applies is exercised by something, which is what makes this test's NAME true."""
    for arm, planted in _PLANTED_BY_ARM.items():
        assert _operator_facing_hits(planted) == ["[api].public_origin"], (
            f"the {arm} aperture arm missed its planted violation, so every clean census over that "
            "shape means nothing. Do not budget around this -- re-derive what the arm matches."
        )


def test_the_constant_arm_does_not_claim_every_assignment() -> None:
    """NEGATIVE CONTROL for the arm whose SCOPE is the novel part. Module-level and UPPER_CASE is the
    whole rule; a lowercase global, a class attribute and a function local must all stay unclaimed. An
    arm widened past its stated scope passes every positive control above while turning this guard into
    a grep -- and the first thing that breaks is the docstring exclusion the engine census depends on."""
    assert _operator_facing_hits(_PLANTED_NOT_A_CONSTANT) == [], (
        "the module-level UPPER_CASE arm claimed a string outside its stated scope, so it is matching "
        "assignments generally rather than shared operator notices"
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


# `[security].name`, plus the ` / name` tail that `--host` help uses for the two keys that together
# replace one relocated key ("[security].local_access_only / listen_address"). Without the tail group
# the second name goes unchecked, which is the quiet direction.
_SECURITY_KEY = re.compile(r"\[security\]\.([a-z_][a-z0-9_]*)((?:\s*/\s*[a-z_][a-z0-9_]*)+)?")

_PLANTED_TYPO = '"error: fail-closed egress requires [security].blok_unlisted_outbound=true"'


def _security_keys_named(source: str) -> collections.Counter[str]:
    """Every ``[security].X`` name in ``source``, across ALL string literals.

    NOT scoped to ``_operator_facing_literals``, unlike every other check here, and the widening is
    deliberate twice over. The exclusions that function makes are both wrong for this question:

    * Its docstring carve-out exists because a docstring may legitimately name the INTERNAL field that
      a relocated key desugars into. There is no such excuse under ``[security]`` -- that section IS
      the operator-facing spelling, so a bad name there is wrong in a docstring too.
    * Its aperture is a fixed set of call shapes plus module-level constants, which is the right
      question for "did a message name an OLD key" and the wrong one here. Measured on this tree,
      scoping to it drops 38 of the 128 ``[security].X`` mentions and loses ``organization_domains``
      from view entirely. A key named somewhere the aperture does not reach still has to EXIST.

    An earlier draft gave a different second reason -- that the aperture would miss
    ``settings.BLOCK_UNLISTED_OUTBOUND_IN_FORCE``, the module-level constant six refusals interpolate.
    That stopped being true when the web console widening added the constant arm, which now reaches 9
    of that constant's 10 mentions. The widening above is still right, for the reason now given.
    """
    found: collections.Counter[str] = collections.Counter()
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        for head, tail in _SECURITY_KEY.findall(node.value):
            found[head] += 1
            found.update(part.strip() for part in tail.split("/") if part.strip())
    return found


def _nameable_security_keys() -> set[str]:
    """Read from the settings models at RUN TIME -- never a list copied into this file.

    A hand-copied roster is a second definition of the same fact, which is the defect class #1361
    exists for: it would stay green through a rename and go stale exactly when it mattered.

    ``_REMOVED_KEYS`` is unioned in because the refusal machinery has to SAY the retired name to
    redirect the operator off it. Measured 2026-09-20 that is one key,
    ``[security].handles_real_patient_data`` (BACKLOG #1279), named at three sites -- two docstrings
    and the ``_REMOVED_KEYS`` message itself.
    """
    return set(SecuritySettings.model_fields) | {
        key for (section, key) in _REMOVED_KEYS if section == "security"
    }


def test_the_security_key_scanner_actually_detects_a_typo() -> None:
    """POSITIVE CONTROL for the test below, which is an ABSENCE check over a corpus it also chooses.

    A regex that quietly stops matching reports a clean engine forever, and that is indistinguishable
    from a real clean run. So prove it names a planted typo before believing a green one.
    """
    found = _security_keys_named(_PLANTED_TYPO)
    assert set(found) - _nameable_security_keys() == {"blok_unlisted_outbound"}, (
        f"the scanner missed a planted typo, so a clean scan means nothing: {dict(found)}"
    )


def test_every_security_key_named_in_a_message_is_a_real_field() -> None:
    """BACKLOG #1361: the REPLACEMENT spelling must exist, or the rework recreates the defect it fixed.

    Every other check in this file asks whether a message names an OLD key. None asks whether the NEW
    one is real -- so a typo in a replacement passed ruff, mypy, the census above and every gate in
    this repository, while handing an operator a key the loader refuses with "unrecognized config
    key(s)": the same dead remediation, same restart to discover, arrived by the fix rather than by
    the drift.
    """
    named: collections.Counter[str] = collections.Counter()
    where: dict[str, set[str]] = collections.defaultdict(set)
    per_root: dict[pathlib.Path, int] = {}
    for root in _CORPORA:
        seen = 0
        for path in _corpus(root):
            rel = path.relative_to(_ROOT).as_posix()
            for key, count in _security_keys_named(path.read_text(encoding="utf-8")).items():
                named[key] += count
                where[key].add(rel)
                seen += count
        per_root[root] = seen

    # THE DENOMINATOR, for the reason test_the_census_examined_a_population gives: "no bad keys in 128
    # mentions" and "no bad keys in 0 mentions" print the same green. PER ROOT for that test's OTHER
    # reason -- see _MENTION_FLOOR, where the split and the two numbers are justified.
    for root in _CORPORA:
        floor = _MENTION_FLOOR[root]
        assert per_root[root] > floor, (
            f"only {per_root[root]} [security].X mentions under {root.name} across "
            f"{len(_corpus(root))} files, at or below its floor of {floor}; that is a broken scan of "
            "that root, not a clean one, and the assertion below is vacuous for it when it happens"
        )

    unknown = {k: sorted(where[k]) for k in sorted(set(named) - _nameable_security_keys())}
    assert not unknown, (
        f"message(s) name a [security] key that is not a field on SecuritySettings: {unknown}. The "
        "loader REFUSES an unrecognized key rather than ignoring it, so this is a remediation that "
        "dies at load -- fix the spelling, or add the field."
    )


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
