# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pin the tooling partition against the tree, and against ci.yml.

``tests/tooling_manifest.txt`` decides which tests run on the engine legs and which move to the
path-gated ``tooling`` job. Nothing else does -- there is no filename pattern and no directory. That
makes the manifest load-bearing in a way a list of names usually is not, and it can rot in two
directions with opposite costs:

* A NEW HARNESS TEST NOBODY LISTS runs on every engine leg forever. Costs wall-clock on the critical
  path, which is the whole thing the partition exists to remove. Merely wasteful.
* A LISTED TEST WHOSE SUBJECT IS ENGINE SOURCE stops running on engine PRs. It goes on passing in the
  tooling job -- on a `scripts/**` path gate that an engine PR never trips -- so nothing reports a
  gap. That is a gate resting on a false premise (CLAUDE.md section 11), and it is why the rule for a
  new entry is "when ambiguous, leave it off".

The second is why ``_STAYS_WITHOUT_IMPORTING`` is an explicit list rather than an ``and not
name.startswith(...)`` escape hatch: every file that looks like harness but is not gets named here,
once, with the reason visible in review.

Three regex classifiers were tried before this file existed and each got a different obvious case
wrong. Relocating the tier into ``tests/tooling/`` was tried next and reverted -- the files are
coupled to their location in at least five ways. This test is the residue of both: keep the list
honest, and let the mechanism stay boring.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_TESTS = _ROOT / "tests"
_MANIFEST = _TESTS / "tooling_manifest.txt"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"

# `messagefoundry_webconsole` MUST be named explicitly. `\b` does not end the alternation after
# `messagefoundry`, because `_` is a word character and there is no boundary between them -- so a bare
# `(messagefoundry|...)\b` does NOT match `from messagefoundry_webconsole...`. That is not a passive
# hole. This pattern is used in BOTH directions: test_no_listed_test_imports_the_engine stays green on
# a listed test that imports the shipped console, and test_every_non_engine_test_is_classified runs it
# in reverse and therefore DEMANDS every console-importing test be listed as tooling. It admitted
# test_webconsole_monitoring_fips.py to the manifest, where it then ran in no CI job at all.
#
# The console is shipped product source (packaging/messagefoundry-webconsole, mounted in-process at
# /ui), so a test importing it is an engine test by subject. Keep the `_webconsole` arm explicit
# rather than widening to `messagefoundry\w*`: the point is to name what counts as the product, and a
# wildcard would silently absorb any future `messagefoundry_`-prefixed helper that is not.
_ENGINE_IMPORT = re.compile(
    r"^\s*(from|import)\s+(messagefoundry(?:_webconsole)?|harness|tee)\b", re.M
)

# Tests that do NOT import the engine and nonetheless belong on the engine legs, because their
# SUBJECT is engine source: they read messagefoundry/** off disk and assert something about it. A
# scanner is still a guard on the thing it scans.
_STAYS_WITHOUT_IMPORTING = frozenset(
    {
        "test_asvs_apply.py",
        "test_asvs_residual_lint.py",
        "test_c901_delta.py",
        # NOT engine source, so this entry WIDENS the list's stated rule and the claim is spelled out
        # for review. Its subject is the TEST TREES: it scans both `testpaths` roots for a bare
        # `import conftest`, which binds to whichever root pytest loaded first (BACKLOG #1255). The
        # gating argument is the one that keeps test_control_char_check.py here, applied to a
        # different scanned population: what it guards is `tests/**` and
        # `packaging/messagefoundry-webconsole/tests/**`, and a change to either sets `code=true` (a
        # .py path) but NOT `tooling=true` -- that gate names only three tests/ files (conftest.py,
        # tooling_manifest.txt, test_tooling_partition.py). Listed as tooling it would be deselected
        # by `-m 'not tooling'` on the engine legs AND unreached by the tooling job's path gate, so
        # the PR that adds the offending import would face nothing.
        "test_conftest_name_collision_guard.py",
        "test_cp1252_console_safety.py",
        # Arrived with #421 while this branch was in flight. Same shape as cp1252_console_safety and
        # licence_header_gate above: a repo-wide scanner over TRACKED TEXT, which includes
        # messagefoundry/**. A control byte landing in engine source is caught by this gate and no
        # other, so gating it behind scripts/** would leave the engine change that introduced one
        # facing nothing. It builds most cases in tmp_path, but test_list_reports_scope_and_exits_zero
        # reads the real `git ls-files` scope -- which is the half that makes it engine-subject.
        "test_control_char_check.py",
        "test_crypto_inventory_scanner.py",
        "test_dependency_boundaries.py",
        "test_ech_record_premise.py",
        # Same shape as control_char_check and licence_header_gate above, and listed for the same
        # reason: a repo-wide scanner over TRACKED SOURCE, which includes messagefoundry/**. An
        # invalid escape landing in engine source becomes a SyntaxError on a future Python and takes
        # that whole module at COLLECTION -- so it surfaces as FEWER TESTS, not as a failure, and
        # this gate is the only thing that catches it. Gating it behind scripts/** would leave the
        # engine change that introduced one facing nothing. Most arms build in tmp_path, but
        # test_the_tracked_tree_is_clean and test_list_reports_scope_and_exits_clean read the real
        # `git ls-files` scope -- which is the half that makes it engine-subject.
        "test_escape_sequence_check.py",
        "test_external_link_interstitial.py",
        "test_licence_header_gate.py",
        "test_packaging.py",
        "test_release_pipeline.py",
        "test_sandbox_worker_logging.py",
        "test_scan_forbidden.py",
        "test_scan_tokens_source.py",
        "test_seam_discovery.py",
        "test_security_static.py",
        # Engine-subject for the same reason as control_char_check and escape_sequence_check above,
        # and the reason is the one arm that does not use tmp_path: the screen's DEFAULT SCOPE is
        # messagefoundry/api/app.py and auth_routes.py, so test_the_live_api_scope_still_surfaces_the
        # _unjudged_candidate parses real engine source. A username re-appearing as an access key
        # arrives in an API route -- an engine diff -- and the tooling job's path gate (scripts/**,
        # .github/**, the ledger) is not tripped by one, so gating this behind scripts/** would
        # leave exactly the change that reintroduces the defect facing nothing.
        "test_username_access_key_screen.py",
        # The four below were WRONGLY LISTED as tooling in the first cut of the manifest and were
        # caught by adversarial review, not by any guard here. Each reads real engine source without
        # importing it, so the marker took them off every engine leg while the tooling job's path gate
        # (scripts/**, .github/**, the ledger) is not tripped by an engine diff -- they ran on ZERO
        # legs for the change that would break them. Named individually, with what each reads, because
        # the whole point of this list is that a reviewer can check the claim:
        #   sqlserver_encrypt_pass_tables -> messagefoundry/store/sqlserver.py. Its own docstring is
        #     the reason it cannot move: every SQL Server CI step runs keyless, so the encrypt loop is
        #     unreachable at runtime and source-reading on the plain leg is the ONLY coverage there is.
        "test_sqlserver_encrypt_pass_tables.py",
        #   reply_hint_thread_affinity -> messagefoundry/pipeline/wiring_runner.py
        "test_reply_hint_thread_affinity.py",
        #   adr0071_statement_rt_inventory -> drives a real SqlServerStore through its bench module
        "test_adr0071_statement_rt_inventory.py",
        #   install_instruction_provenance -> globs messagefoundry/**/*.py
        "test_install_instruction_provenance.py",
        #   sds_rule_ids_are_stable -> :397 rglobs messagefoundry/**/*.py. Milder than the four above
        #     (it catches a dangling SDS-N.N citation in an engine docstring, not a correctness bug),
        #     and it is listed here anyway: the value of this list is that it is exhaustive for its
        #     stated rule, and "same class but it does not matter much" is how the next exception gets
        #     argued in.
        "test_sds_rule_ids_are_stable.py",
        # this file: it guards the partition, so it must run wherever the partition matters
        "test_tooling_partition.py",
    }
)


def _manifest_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _names_from(text: str) -> list[str]:
    """THIS FILE's manifest parser, over arbitrary text rather than over the file.

    Split out so ``test_the_gate_offers_a_line_the_manifest_parser_accepts`` can feed the example
    line the failure message hands out straight back through it. A message that recommends a shape
    nothing checks is the compensating-control-on-a-false-premise defect (CLAUDE.md 11).

    IT IS NOT THE ONLY PARSER, AND SAYING SO WOULD BE THE SAME DEFECT ONE LEVEL UP. The copy that
    actually applies the ``tooling`` marker is ``_tooling_basenames`` in tests/conftest.py, and a
    third lives in ``_manifest_paths`` in tests/test_ci_tooling_gate.py. All three implement the
    same rule -- strip, drop blanks and ``#`` comments, rsplit on ``/`` -- and NOTHING pins them
    against each other. Extracting one shared ``tests/_tooling_manifest.py`` is the real fix and it
    is not this change's job; until then, what the arm below proves is that the recommended line
    survives THIS parser.
    """
    return [line.rsplit("/", 1)[-1] for line in _manifest_lines(text)]


def _manifest_entries() -> list[str]:
    """The manifest's full lines -- ``tests/<name>.py``, which is what ci.yml's path gate matches."""
    return _manifest_lines(_MANIFEST.read_text(encoding="utf-8"))


def _manifest_names() -> list[str]:
    return [line.rsplit("/", 1)[-1] for line in _manifest_entries()]


def _unclassified_remedy(names: list[str]) -> str:
    """The text ``test_every_non_engine_test_is_classified`` fails with.

    WRITTEN TO BE ACTIONABLE FROM A CI LOG ALONE, because its reader usually cannot ask. Measured
    2026-09-03: this assertion reds all three required ``test`` legs, and the two Builders who
    tripped it that night had each exited before any leg reported. The message is therefore the
    whole remedy, and its predecessor named the offending file and stopped -- so both of them left
    a red branch nobody was on.

    Line one carries the two registry paths and the file list, because that is the line a truncated
    summary keeps. NOTHING HERE IS A HAND-WRITTEN PATH: the example is built from a real offender,
    and both registries are rendered from ``_MANIFEST`` and ``__file__``, so a rename moves the
    message with the file instead of leaving it pointing at a path that no longer exists.
    """
    example = names[0] if names else "test_example.py"
    manifest = _MANIFEST.relative_to(_ROOT).as_posix()
    here = Path(__file__).resolve().relative_to(_ROOT).as_posix()
    return (
        f"UNCLASSIFIED TEST FILE(S) -- add each to {manifest} or to "
        f"_STAYS_WITHOUT_IMPORTING in {here}: {names}\n"
        "They import no engine module, so nothing decides which CI legs run them. Choose one, per "
        "file, in the SAME pull request:\n"
        f"  (a) HARNESS subject (scripts/**, .github/**, the ledger) -> append `tests/{example}` "
        f"to {manifest}, keeping the `tests/` prefix (ci.yml matches whole changed paths against "
        "these lines).\n"
        f'  (b) ENGINE subject it READS off disk without importing -> add `"{example}"` to '
        f"_STAYS_WITHOUT_IMPORTING in {here}, with a comment naming the messagefoundry/** file it "
        "reads.\n"
        "  A test that IMPORTS the engine needs neither entry -- which is why most files here sit "
        "in no list at all.\n"
        "WHEN AMBIGUOUS CHOOSE (b). (a) is the answer that loses coverage silently: a wrongly "
        "listed engine test leaves the engine legs, and the tooling job's scripts/** path gate is "
        "not tripped by an engine diff, so it runs on NO leg for the change that would break it."
    )


def test_every_manifest_entry_resolves_as_written() -> None:
    """A stale entry silently un-marks a test back onto the engine legs.

    RESOLVED AS WRITTEN, not by basename, and that is the strengthening. The predecessor read this
    file through ``_manifest_names``, which rsplits the directory away -- so it proved a file of
    that NAME exists somewhere in tests/ and was blind to the path actually written down. That
    blindness matters because ci.yml's ``changes`` job summons the tooling job by matching WHOLE
    changed paths against these lines (``grep -qxFf`` over ``git diff --name-only``). A bare
    ``test_x.py``, a ``./tests/`` prefix or a backslash separator all still MARK the test -- this
    file's parser and tests/conftest.py both rsplit on ``/`` -- so the test leaves the engine legs
    by ``-m 'not tooling'``, and then a later pull request editing only that test matches no arm of
    the gate and summons no tooling job. Deselected everywhere, green.

    Two clauses, because one does not cover it: the entry must name a real file, AND it must be
    spelled the way git spells it. ``./tests/test_x.py`` satisfies the first and fails the second.
    """
    bad: list[str] = []
    for line in _manifest_entries():
        target = _ROOT / line
        if not target.is_file():
            bad.append(f"{line} (names no file)")
        elif line != target.resolve().relative_to(_ROOT).as_posix():
            bad.append(f"{line} (not the repo-relative path git reports for it)")
    assert not bad, (
        "tooling_manifest.txt entries must be repo-relative paths naming a real file, exactly as "
        "`git diff --name-only` spells them, or ci.yml's path gate cannot match the changed file "
        f"and the tier stops being summoned by an edit to it: {bad}"
    )


def test_manifest_has_no_duplicates() -> None:
    names = _manifest_names()
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"tooling_manifest.txt lists the same file twice: {dupes}"


def test_no_listed_test_imports_the_engine() -> None:
    """Importing the engine is sufficient proof the subject is the engine, so it cannot be harness."""
    wrong = sorted(
        n
        for n in _manifest_names()
        if _ENGINE_IMPORT.search((_TESTS / n).read_text(encoding="utf-8", errors="replace"))
    )
    assert not wrong, (
        "these are listed as tooling but import the engine, so they would stop running on the "
        f"engine legs that exercise what they test: {wrong}"
    )


def _assert_every_test_is_classified(
    tests_dir: Path, listed: set[str], stays: frozenset[str]
) -> None:
    """The gate itself, over a NAMED directory rather than the real one.

    Parameterised for one reason: so ``test_the_gate_raises_the_remedy_and_not_a_bare_list`` can
    drive this exact assertion into failure against a tmp_path and read the message it actually
    raises. Asserting on ``_unclassified_remedy``'s return value instead was tried and MEASURED
    VACUOUS -- reverting the call site below to the predecessor string left all the content arms
    green, because they never touched the call site. The instrument was answering "does the helper
    return good text" while the question is "does the gate FAIL with good text" (CLAUDE.md 11,
    SDS-3.8).
    """
    unclassified = sorted(
        p.name
        for p in tests_dir.glob("test_*.py")
        if p.name not in listed
        and p.name not in stays
        and not _ENGINE_IMPORT.search(p.read_text(encoding="utf-8", errors="replace"))
    )
    assert not unclassified, _unclassified_remedy(unclassified)


def test_every_non_engine_test_is_classified() -> None:
    """The drift guard: a NEW harness test must land in the manifest or be named as staying.

    Without this, a new worktree-gate test quietly joins the engine legs and the tier grows back.
    """
    _assert_every_test_is_classified(_TESTS, set(_manifest_names()), _STAYS_WITHOUT_IMPORTING)


#: The offender the two arms below fabricate. One spelling, so renaming it cannot leave an
#: assertion comparing against a stale literal.
_SENTINEL = "test_made_up_harness_thing.py"


def _raised_remedy(tmp_path: Path) -> str:
    """Drive the real gate into failure over one unclassified file and hand back its message.

    Doubles as the mechanism's positive control: a gate that cannot be made to fire here would
    satisfy every arm below while reporting nothing on the real tree.

    The empty lists are deliberate rather than incidental -- they keep this arm hermetic against
    someone later adding ``_SENTINEL`` to the real manifest or stay list.
    """
    (tmp_path / _SENTINEL).write_text("def test_x() -> None:\n    assert True\n", encoding="utf-8")
    with pytest.raises(AssertionError) as caught:
        _assert_every_test_is_classified(tmp_path, set(), frozenset())
    return str(caught.value)


def test_the_gate_offers_a_line_the_manifest_parser_accepts(tmp_path: Path) -> None:
    """The message hands out a manifest line; this file's parser must read it back.

    Taken off the RAISED message, so it cannot drift from the assertion that issues it, and fed
    through ``_names_from``, so it cannot drift from the reader that consumes it.
    """
    rendered = _raised_remedy(tmp_path)
    recommended = f"tests/{_SENTINEL}"
    assert f"`{recommended}`" in rendered, rendered
    assert _names_from(recommended) == [_SENTINEL], (
        "the manifest parser does not read back the line the failure message recommends"
    )


def test_the_gate_raises_the_remedy_and_not_a_bare_list(tmp_path: Path) -> None:
    """A reader who only ever sees this string must be able to act on it.

    Both Builders who tripped this gate on 2026-09-03 had exited before any leg reported, so there
    was nobody to ask what the remedy was.

    THE PATHS ARE RESOLVED, NOT MATCHED. A literal needle for ``tests/tooling_manifest.txt`` here
    would be a literal checked against a literal: rename or move either registry and the message and
    the test go stale together, green. So every ``tests/...`` path the message offers is pulled out
    of the rendered string and required to name a real file, and the stay list is required to be
    defined in the file the message sends the reader to.

    Read off the RAISED message, so reverting the call site to the predecessor (which named the
    offending file and stopped) turns this red. Reading ``_unclassified_remedy`` directly did NOT --
    measured, and it is the whole reason this arm is shaped this way.
    """
    rendered = _raised_remedy(tmp_path)

    offered = set(re.findall(r"tests/[A-Za-z0-9_./-]+\.(?:py|txt)", rendered))
    named_files = {p for p in offered if not p.endswith(f"/{_SENTINEL}")}
    assert len(named_files) >= 2, f"the message offers fewer than two registry paths: {offered}"
    unresolvable = sorted(p for p in named_files if not (_ROOT / p).is_file())
    assert not unresolvable, (
        f"the failure message sends its reader to paths that do not exist: {unresolvable}"
    )
    assert _MANIFEST.relative_to(_ROOT).as_posix() in named_files, (
        f"the message never names the manifest itself: {sorted(named_files)}"
    )

    stay_list_home = next(p for p in named_files if p.endswith(".py"))
    assert "_STAYS_WITHOUT_IMPORTING" in (_ROOT / stay_list_home).read_text(encoding="utf-8"), (
        f"the message sends the reader to {stay_list_home} for _STAYS_WITHOUT_IMPORTING, and it is "
        "not defined there"
    )

    # The prose half. These carry no path to resolve, so they are needles -- and they are the three
    # claims that make the message a remedy rather than a report.
    for needle, why in (
        ("HARNESS subject", "the criterion is the test's SUBJECT, not its location"),
        ("ENGINE subject", "the other half of that criterion"),
        ("WHEN AMBIGUOUS", "the tie-break, without which a hurried reader picks (a)"),
    ):
        assert needle in rendered, f"the failure message no longer states {why}: {needle!r}"

    assert rendered.splitlines()[0].endswith(f"['{_SENTINEL}']"), (
        "line one must still end with the offending files -- it is the line a truncated CI summary "
        "keeps, and it must name both the registries and the files at once"
    )


def test_stay_list_holds_only_real_files() -> None:
    missing = sorted(n for n in _STAYS_WITHOUT_IMPORTING if not (_TESTS / n).is_file())
    assert not missing, f"_STAYS_WITHOUT_IMPORTING names files that do not exist: {missing}"


def test_the_two_lists_are_disjoint() -> None:
    """The stay list must have POWER over the manifest, not merely opinions about it.

    Without this the stay list is inert: ``test_every_non_engine_test_is_classified`` skips anything
    already in the manifest, so a file can sit in BOTH and the manifest silently wins. Mutation-
    verified before this assertion existed -- appending ``tests/test_dependency_boundaries.py`` to the
    manifest left the whole pin file at 8 passed, while ``-m tooling`` then collected its 3 tests. That
    file is the engine's one-way import rule, and it is the case the commit history records a regex
    classifier nearly shipping. The one artifact naming the files that must not move had no way to stop
    them moving -- including this file, despite the comment above asserting it must run wherever the
    partition matters.

    Disjointness is the whole guarantee: a name in both lists is a contradiction the author has to
    resolve, not a precedence rule to be quietly applied in the manifest's favour.
    """
    both = sorted(set(_manifest_names()) & _STAYS_WITHOUT_IMPORTING)
    assert not both, (
        "these files are in BOTH tests/tooling_manifest.txt and _STAYS_WITHOUT_IMPORTING; the manifest "
        "would win silently and the file would leave the engine legs. Decide which list it belongs in: "
        f"{both}"
    )


def test_marker_is_registered() -> None:
    """An unregistered marker is a warning, not an error -- and `-m tooling` would still select 0."""
    cfg = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    markers = cfg["tool"]["pytest"]["ini_options"]["markers"]
    assert any(m.startswith("tooling:") for m in markers), (
        "the `tooling` marker must be declared in pyproject markers, or --strict-markers runs and "
        "typo'd selections fail open"
    )


@pytest.mark.parametrize(
    ("needle", "why"),
    [
        (
            "-m 'not tooling'",
            "the engine legs must DESELECT the harness tier -- without it the partition buys nothing",
        ),
        (
            "-m tooling",
            "the tooling job must SELECT it -- without it the tier stops running anywhere",
        ),
    ],
)
def test_ci_wires_both_halves(needle: str, why: str) -> None:
    """Both spellings must appear. Either one alone is a silent half-failure."""
    assert needle in _CI.read_text(encoding="utf-8"), f"{needle!r} missing from ci.yml: {why}"
