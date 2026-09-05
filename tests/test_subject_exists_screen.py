# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The subject-exists screen (BACKLOG #1426).

EVERY TEST HERE RUNS AGAINST A FAKE REPOSITORY, and that is a decision rather than convenience. The
screen's job is to answer "is this subject on `origin/main`", so a test driving real git would assert
facts about whichever clone happens to run it -- facts that change under every merge and vanish under
a shallow fetch. The fake pins the SCREEN's behaviour; the live probes are pinned separately by the
tool's own structural control, which runs on every invocation and has a negative arm.

TWO CONTROL LAYERS ARE TESTED, NOT ONE. A screen that finds nothing must be distinguishable from a
screen that is broken, so it is not enough that the controls pass on good code -- they must FAIL on
broken code. `test_the_probe_control_fails_against_a_broken_probe` and
`test_the_extractor_control_fails_when_a_subject_kind_is_lost` are those negative arms. Without them
the controls are one-sided instruments, which is the failure mode this repository has recorded
repeatedly.

THE TWO KNOWN-TRUE CASES ARE FIXTURES HERE, ABRIDGED FROM THE REAL ROWS. #1229 and #1040 were each
dispatched as a build on 2026-09-03 and each was already complete. Their shapes are pinned so a
change that stops matching one of them reds here rather than showing up as a shorter candidate list
nobody can tell from a cleaner ledger.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "_subject_exists_screen",
    Path(__file__).resolve().parents[1] / "scripts" / "docs" / "subject_exists_screen.py",
)
assert _SPEC is not None and _SPEC.loader is not None
ses = importlib.util.module_from_spec(_SPEC)
# REGISTERED BEFORE EXECUTION, and it is not optional here as it is in the sibling loaders. A
# `@dataclass` in the loaded module sends `dataclasses._is_type` to `sys.modules[cls.__module__]`
# while the class body is being processed; an unregistered module makes that None and collection
# dies with `AttributeError: 'NoneType' object has no attribute '__dict__'`, which names neither
# this file nor the real cause.
sys.modules[_SPEC.name] = ses
_SPEC.loader.exec_module(ses)


# --- a fake repository ----------------------------------------------------------------------------


class FakeRepo:
    """A `RepoReader` whose every answer is declared, so a test asserts the SCREEN, not a clone."""

    def __init__(
        self,
        *,
        shallow: bool = False,
        commits: set[str] | None = None,
        ancestors: set[str] | None = None,
        tree: set[str] | None = None,
        added: dict[str, str] | None = None,
        changed: dict[str, str] | None = None,
        prs: dict[str, tuple[str, str]] | None = None,
        symbols: set[str] | None = None,
    ) -> None:
        self._shallow = shallow
        self._commits = commits or set()
        self._ancestors = ancestors or set()
        self._tree = tree or set()
        self._added = added or {}
        self._changed = changed or {}
        self._prs = prs or {}
        self._symbols = symbols or set()

    def is_shallow(self) -> bool:
        return self._shallow

    def is_commit(self, sha: str) -> bool:
        return sha in self._commits or sha in self._ancestors

    def is_ancestor(self, sha: str) -> bool:
        return sha in self._ancestors

    def path_on_main(self, path: str) -> str | None:
        if path in self._tree:
            return path
        if "/" in path:
            return None
        matches = [p for p in self._tree if p.rsplit("/", 1)[-1] == path]
        return matches[0] if len(matches) == 1 else None

    def path_added(self, path: str) -> str | None:
        return self._added.get(path)

    def path_last_changed(self, path: str) -> str | None:
        return self._changed.get(path)

    def pr_merged(self, number: str) -> tuple[str, str] | None:
        return self._prs.get(number)

    def symbol_on_main(self, symbol: str) -> bool:
        return symbol in self._symbols


def _values(body: str, kind: str) -> set[str]:
    return {s.value for s in ses.subjects_in(body) if s.kind == kind}


def _codes(report: object) -> set[str]:
    return {s.code for s in report.signals}  # type: ignore[attr-defined]


# --- what a subject IS ----------------------------------------------------------------------------


def test_a_sha_is_found() -> None:
    assert _values("landed in c7f0e308 today", "sha") == {"c7f0e308"}


def test_a_full_length_sha_is_found() -> None:
    sha = "889dd9409" + "a" * 31
    assert _values(f"see {sha}", "sha") == {sha}


def test_a_path_with_directories_is_found() -> None:
    assert "messagefoundry/store/store.py" in _values("see messagefoundry/store/store.py", "path")


def test_a_path_inside_a_code_span_is_found_WHOLE() -> None:
    """REGRESSION, and it was found by running the tool rather than predicted.

    The first lookbehind refused a backtick, so a path written the way this ledger usually writes one
    could not match at its start and the regex matched a SUFFIX instead: the #1229 row's
    `scripts/hooks/worktree_gate.ps1` came out `hooks/worktree_gate.ps1`. That resolves against
    nothing and reported as ABSENT -- a truncation rendering as a confident negative, which is the
    worst of the three outcomes.
    """
    got = _values("the gate is `scripts/hooks/worktree_gate.ps1:382-383` today", "path")
    assert "scripts/hooks/worktree_gate.ps1" in got
    assert "hooks/worktree_gate.ps1" not in got


def test_a_hyphenated_filename_is_not_truncated_at_its_hyphen() -> None:
    """Same defect one character along: `install-git-hooks.ps1` must not yield `git-hooks.ps1`."""
    got = _values("install-git-hooks.ps1 copies them", "path")
    assert "install-git-hooks.ps1" in got
    assert "git-hooks.ps1" not in got


def test_a_markdown_link_path_loses_its_relative_prefix() -> None:
    body = "see [`store.py`](../messagefoundry/store/store.py) for it"
    assert "messagefoundry/store/store.py" in _values(body, "path")


def test_a_bare_filename_with_a_line_range_is_found() -> None:
    """`worktree_gate.ps1:347-388` is how the #1229 row names its own subject."""
    assert "worktree_gate.ps1" in _values("blanks at worktree_gate.ps1:347-388", "path")


def test_a_bare_filename_is_not_repeated_when_a_full_path_on_the_line_covers_it() -> None:
    got = _values("messagefoundry/store/store.py is the file", "path")
    assert got == {"messagefoundry/store/store.py"}


def test_a_backticked_snake_case_symbol_is_found() -> None:
    assert _values("the reader is `reset_stale_inflight` here", "symbol") == {
        "reset_stale_inflight"
    }


def test_a_powershell_verb_noun_symbol_is_found() -> None:
    assert _values("calls `Remove-QuotedSpans` first", "symbol") == {"Remove-QuotedSpans"}


def test_a_symbol_keeps_one_identity_with_or_without_call_parens() -> None:
    assert _values("`parse_items()` and `parse_items`", "symbol") == {"parse_items"}


# --- what a subject IS NOT ------------------------------------------------------------------------


def test_a_bare_hash_number_is_never_a_pull_request() -> None:
    """`#N` spells a pull request and a backlog item identically.

    A security record entry reading "the build is #156" resolved to a pull request while backlog #156
    was unrelated work. Guessing is what produced that, so neither form is guessed."""
    assert _values("see #547 and #1229 for context", "pr") == set()


def test_a_backlog_cross_reference_is_never_a_pull_request() -> None:
    assert _values("closes BACKLOG #547 eventually", "pr") == set()


def test_only_the_literal_pr_form_resolves_a_pull_request() -> None:
    assert _values("landed in PR #547 and pull request #560", "pr") == {"547", "560"}


def test_a_cross_reference_is_reported_as_context_and_not_as_a_subject() -> None:
    body = "blocked on BACKLOG #1268 and BACKLOG #1229"
    assert ses.crossrefs_in(body) == [1229, 1268]
    assert _values(body, "sha") == set()


def test_a_decimal_run_is_not_read_as_a_sha() -> None:
    assert _values("the count was 12345678 rows", "sha") == set()


def test_an_item_heading_does_not_name_itself_as_a_file() -> None:
    assert _values("## 1229. the worktree gate blanks spans", "path") == set()


def test_a_short_identifier_is_not_a_symbol() -> None:
    """Under eight characters an identifier is too common for its presence on main to mean anything."""
    assert _values("`db_read` and `x_y`", "symbol") == set()


def test_a_backticked_command_is_not_a_symbol() -> None:
    assert _values("run `git merge-base --is-ancestor`", "symbol") == set()


def test_prose_naming_nothing_yields_no_subject() -> None:
    """The extractor's negative arm. A probe validated on one input is not validated."""
    assert ses.subjects_in("this row is entirely prose and names no code at all") == []


# --- wording, dates -------------------------------------------------------------------------------


def test_landing_wording_is_recognised() -> None:
    (subject,) = ses.subjects_in("that LANDED on 2026-08-23 in c7f0e308")
    assert subject.wording == "landing"


def test_measurement_wording_is_recognised() -> None:
    (subject,) = ses.subjects_in("Measured at efe061a3f on this branch")
    assert subject.wording == "measurement"


def test_landing_wins_a_line_that_carries_both() -> None:
    """Ranking "measured after it landed" as a base ref would drop the strongest signal there is."""
    (subject,) = ses.subjects_in("measured after it landed in c7f0e308")
    assert subject.wording == "landing"


def test_a_later_landing_mention_upgrades_an_earlier_neutral_one() -> None:
    body = "the base is c7f0e308\nand c7f0e308 landed last week"
    (subject,) = [s for s in ses.subjects_in(body) if s.kind == "sha"]
    assert subject.wording == "landing"


def test_the_newest_date_in_the_row_is_taken() -> None:
    assert ses.newest_date_in("filed 2026-08-12, re-scored 2026-08-20") == "2026-08-20"


def test_a_row_with_no_date_reports_none() -> None:
    assert ses.newest_date_in("no dates at all here") is None


# --- screening ------------------------------------------------------------------------------------


def test_an_ancestor_sha_on_a_landing_line_is_a_strong_signal() -> None:
    repo = FakeRepo(ancestors={"c7f0e308"})
    report = ses.screen_item(1, "h", "it landed in c7f0e308 on 2026-08-20", repo)
    assert report.verdict == "candidate"
    assert "sha-ancestor-landing" in _codes(report)


def test_an_ancestor_sha_cited_as_a_base_ref_is_only_medium() -> None:
    """ "Measured at `efe061a3f`" is an ordinary citation of an ancestor and must not read as news."""
    repo = FakeRepo(ancestors={"efe061a3f"})
    report = ses.screen_item(1, "h", "Measured at efe061a3f on 2026-08-20", repo)
    assert report.verdict == "weak-candidate"
    assert "sha-ancestor" in _codes(report)


def test_a_merged_pull_request_on_a_landing_line_is_a_strong_signal() -> None:
    repo = FakeRepo(prs={"547": ("889dd9409", "2026-08-23T12:56:57Z")})
    report = ses.screen_item(1, "h", "That LANDED in PR #547 on 2026-08-20", repo)
    assert "pr-merged-landing" in _codes(report)
    assert report.verdict == "candidate"


def test_an_unmerged_pull_request_produces_no_signal() -> None:
    repo = FakeRepo()
    report = ses.screen_item(1, "h", "opened as PR #999 on 2026-08-20", repo)
    assert report.verdict == "no-signal"
    assert any("PR #999" in u for u in report.unresolved)


def test_a_path_added_after_the_rows_newest_date_is_a_strong_signal() -> None:
    """The sharpest shape there is: the file did not exist when anyone last read the row."""
    repo = FakeRepo(
        tree={"tests/test_conftest_name_collision_guard.py"},
        added={"tests/test_conftest_name_collision_guard.py": "2026-08-26T10:00:00Z"},
    )
    body = "re-scored 2026-08-25; the fix needs tests/test_conftest_name_collision_guard.py"
    report = ses.screen_item(1, "h", body, repo)
    assert "path-added-after" in _codes(report)
    assert report.verdict == "candidate"


def test_a_path_added_before_the_rows_newest_date_is_not_that_signal() -> None:
    repo = FakeRepo(
        tree={"tests/test_thing.py"},
        added={"tests/test_thing.py": "2026-08-01T10:00:00Z"},
        changed={"tests/test_thing.py": "2026-08-01T10:00:00Z"},
    )
    report = ses.screen_item(1, "h", "re-scored 2026-08-25; see tests/test_thing.py", repo)
    assert "path-added-after" not in _codes(report)


def test_one_file_named_two_ways_yields_one_signal() -> None:
    """`scripts/hooks/worktree_gate.ps1` and a bare `worktree_gate.ps1:654` are ONE piece of evidence.

    Deduplicating on the raw text instead of the resolved path reported the file's date twice, which
    renders as two independent findings for a single fact."""
    repo = FakeRepo(
        tree={"scripts/hooks/worktree_gate.ps1"},
        changed={"scripts/hooks/worktree_gate.ps1": "2026-09-01T00:00:00Z"},
    )
    body = (
        "re-scored 2026-08-20; `scripts/hooks/worktree_gate.ps1` is called at worktree_gate.ps1:654"
    )
    report = ses.screen_item(1, "h", body, repo)
    assert [s.code for s in report.signals].count("path-changed-after") == 1


def test_a_row_with_no_date_is_surfaced_rather_than_skipped() -> None:
    """No date means the date comparisons cannot run, and silence is the under-firing direction."""
    report = ses.screen_item(1, "h", "a row naming no date whatsoever", FakeRepo())
    assert "no-date-anchor" in _codes(report)
    assert report.verdict == "weak-candidate"


def test_a_symbol_present_on_the_ref_is_only_a_weak_signal() -> None:
    repo = FakeRepo(symbols={"reset_stale_inflight"})
    report = ses.screen_item(1, "h", "on 2026-08-20 `reset_stale_inflight` matters", repo)
    assert "symbol-on-main" in _codes(report)
    assert report.verdict == "no-signal"


def test_symbol_probing_can_be_switched_off() -> None:
    repo = FakeRepo(symbols={"reset_stale_inflight"})
    report = ses.screen_item(
        1, "h", "on 2026-08-20 `reset_stale_inflight` matters", repo, probe_symbols=False
    )
    assert "symbol-on-main" not in _codes(report)


# --- the shallow-clone trap -----------------------------------------------------------------------


def test_under_a_shallow_clone_an_unresolvable_sha_is_UNKNOWN_not_absent() -> None:
    """Constraint 7. This clone really is shallow -- 16 graft points, measured 2026-09-03 -- so a
    walk that stops at a boundary must not render as "not on main"."""
    repo = FakeRepo(shallow=True)
    report = ses.screen_item(1, "h", "it landed in abc1234 on 2026-08-20", repo)
    assert "sha-unverifiable-shallow" in _codes(report)
    assert report.unresolved == []


def test_under_a_shallow_clone_a_false_ancestry_answer_is_UNKNOWN() -> None:
    """A TRUE ancestry answer is sound under a graft; a FALSE one may only mean the walk stopped."""
    repo = FakeRepo(shallow=True, commits={"abc1234"})
    report = ses.screen_item(1, "h", "it landed in abc1234 on 2026-08-20", repo)
    assert "sha-unverifiable-shallow" in _codes(report)


def test_in_a_COMPLETE_clone_the_same_sha_is_reported_as_absent() -> None:
    """The other arm. Without it, "unknown" would be indistinguishable from a screen that never
    reports a negative at all."""
    repo = FakeRepo(shallow=False, commits={"abc1234"})
    report = ses.screen_item(1, "h", "it landed in abc1234 on 2026-08-20", repo)
    assert "sha-unverifiable-shallow" not in _codes(report)
    assert any("abc1234" in u for u in report.unresolved)


# --- the two known-true cases, as fixtures --------------------------------------------------------

#: Abridged from the real row. The escape limb shipped 2026-08-22 in `3c5cb9885`, whose subject names
#: BACKLOG #1268 rather than #1229, so a search keyed on the item number never finds it.
CASE_1229 = """## 1229. the worktree gate blanks double-quoted spans FIRST

> Re-scored 2026-08-20 -> P2. The ORDERING limb is genuinely shipped: Remove-QuotedSpans
> (worktree_gate.ps1:347-388) is CALLED on the scan path at :654. Landed in c7f0e308 naming #1229.
> The TEST limbs are shipped too -- tests/test_worktree_gate_quote_straddle.py asserts it, and it is
> registered in tests/tooling_manifest.txt:109.
> Filed 2026-08-12 -- a LIVE FAIL-OPEN in `scripts/hooks/worktree_gate.ps1:382-383`.
"""

#: Abridged from the real row. It stayed open behind a note saying the banner was left for an archive
#: pass, while an older re-score beneath it still described the landed work as outstanding.
CASE_1040 = """## 1040. Hook deny text is attacker-influenceable output

> BOTH REMAINING SURFACES ARE CLOSED 2026-08-27; banner left open for the archive pass.
> THIS ROW'S OWN COORDINATES WERE STALE. It still pointed at the `claim_check.py` site as
> outstanding. That LANDED on 2026-08-23 in `889dd9409` (PR #547).
"""


def test_the_1229_case_comes_out_a_candidate() -> None:
    repo = FakeRepo(
        ancestors={"c7f0e308"},
        tree={
            "scripts/hooks/worktree_gate.ps1",
            "tests/test_worktree_gate_quote_straddle.py",
            "tests/tooling_manifest.txt",
        },
        changed={"scripts/hooks/worktree_gate.ps1": "2026-09-01T00:00:00Z"},
        symbols={"Remove-QuotedSpans"},
    )
    report = ses.screen_item(1229, "h", CASE_1229, repo)
    assert report.verdict == "candidate"
    assert "sha-ancestor-landing" in _codes(report)


def test_the_1040_case_comes_out_a_candidate() -> None:
    repo = FakeRepo(
        ancestors={"889dd9409"},
        tree={"scripts/hooks/claim_check.py"},
        prs={"547": ("889dd9409", "2026-08-23T12:56:57Z")},
    )
    report = ses.screen_item(1040, "h", CASE_1040, repo)
    assert report.verdict == "candidate"
    assert {"sha-ancestor-landing", "pr-merged-landing"} <= _codes(report)


@pytest.mark.parametrize("case", [CASE_1229, CASE_1040])
def test_neither_case_fires_against_a_ref_that_carries_none_of_it(case: str) -> None:
    """The negative arm on the fixtures themselves.

    Both rows come out candidates above. If they came out candidates here too, the fixtures would be
    proving that the screen fires, not that it fires ON THE RIGHT THING."""
    report = ses.screen_item(1, "h", case, FakeRepo())
    assert report.verdict == "no-signal"


# --- the controls, in BOTH directions -------------------------------------------------------------


def test_the_extractor_control_passes_on_the_shipped_extractor() -> None:
    assert ses.extractor_control() == []


def test_the_extractor_control_fails_when_a_subject_kind_is_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control's own negative arm.

    A control that has never failed is indistinguishable from one that cannot. Neutering the symbol
    reader must red the control rather than quietly shrinking every future report."""
    monkeypatch.setattr(ses, "_symbol_from_span", lambda span: None)
    failures = ses.extractor_control()
    assert failures, "the extractor control passed with the symbol reader neutered"
    assert any("symbol" in f for f in failures)


def test_the_probe_control_passes_against_a_sound_fake() -> None:
    repo = FakeRepo(
        ancestors={"deadbee"},
        tree={"docs/BACKLOG.md"},
        changed={"docs/BACKLOG.md": "2026-09-02T00:00:00Z"},
        symbols={"parse_items"},
    )
    assert ses.probe_control(repo, "deadbee", probe_symbols=True) == []


def test_the_probe_control_fails_against_a_probe_that_cannot_say_no() -> None:
    """A probe validated on one input is not validated. This one answers TRUE to everything, which
    is exactly the shape that makes a screen report a clean ledger forever."""

    class AlwaysYes(FakeRepo):
        def is_commit(self, sha: str) -> bool:
            return True

        def path_on_main(self, path: str) -> str | None:
            return path

        def symbol_on_main(self, symbol: str) -> bool:
            return True

    repo = AlwaysYes(ancestors={"deadbee"}, changed={"docs/BACKLOG.md": "2026-09-02T00:00:00Z"})
    failures = ses.probe_control(repo, "deadbee", probe_symbols=True)
    assert len(failures) >= 3, failures
    assert any("cannot say no" in f for f in failures)


def test_the_probe_control_fails_against_a_probe_that_cannot_say_yes() -> None:
    failures = ses.probe_control(FakeRepo(), "deadbee", probe_symbols=True)
    assert failures
    assert any("is not an ancestor" in f for f in failures)


def test_the_named_ledger_controls_are_the_two_measured_cases() -> None:
    """Pinned so that dropping one is a visible edit rather than a quietly weaker screen."""
    assert ses.LEDGER_CONTROLS == (1229, 1040)


# --- reading the ledger ---------------------------------------------------------------------------


def test_open_items_uses_parse_items_and_carries_each_body() -> None:
    """`parse_items` DEFINES item status; a hand-rolled scan is a second, silently different
    definition (CLAUDE.md section 11). This asserts the screen goes through it."""
    status_check = ses._load_status_check()
    text = (
        "# Backlog\n\n"
        "## 10. an open one\n\n"
        "> \N{INPUT SYMBOL FOR NUMBERS} **Re-scored 2026-08-20.**\n\n"
        "body naming messagefoundry/store/store.py\n\n"
        "## 11. a closed one\n\n"
        "> \N{WHITE HEAVY CHECK MARK} **SHIPPED.**\n\n"
        "other body\n"
    )
    items = ses.open_items([("docs/BACKLOG.md", text)], status_check)
    assert [i.num for i in items] == [10]
    assert "messagefoundry/store/store.py" in items[0].body
    assert items[0].source == "docs/BACKLOG.md"


def test_the_live_ledger_still_parses_and_still_has_open_items() -> None:
    """The corpus control. Every assertion above is satisfied just as well by an empty ledger."""
    root = Path(__file__).resolve().parents[1]
    status_check = ses._load_status_check()
    text = (root / "docs" / "BACKLOG.md").read_text(encoding="utf-8")
    items = ses.open_items([("docs/BACKLOG.md", text)], status_check)
    print(f"open items in the live ledger: {len(items)}")
    assert len(items) >= 50, (
        "the live ledger yielded almost no open items -- the reader is narrowing"
    )
    assert any(ses.subjects_in(i.body) for i in items), "no open row names any code-side subject"
