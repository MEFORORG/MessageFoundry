# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the backlog CITATION gate (``scripts/docs/backlog_citation_check.py``).

The gate answers a question no link checker can: ``docs/BACKLOG.md`` always resolves, so a citation
naming it for an item that has been archived is a link that works and a claim that is false.

**The test that carries the design is** ``test_a_citation_resolves_identically_wherever_its_item
_lives``. Retiring an item moves it between the two ledger files, so the same citation must flip from
correct to wrong purely because the item moved -- with no edit to the citing document and no edit to
the checker. Anything the module encoded about where a number lives would break that test, which is
why it is the one to keep pointed at.

The rest are the ordinary obligations: every construct is exercised, the shape that must NOT be read
as a citation is pinned, the diff scope is proved to ignore an untouched violation *and* catch an
added one, and the whole thing is fired against the real ledger so a green run is evidence rather
than a regex that stopped matching.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "docs" / "backlog_citation_check.py"

_LIVE = "docs/BACKLOG.md"
_ARCHIVE = "docs/archive/backlog/BACKLOG-CLOSED.md"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("backlog_citation_check", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


bcc = _load()


def _item(num: int, title: str = "A thing") -> str:
    """One well-formed item, exactly as ``parse_items`` defines the shape."""
    return f"## {num}. {title}\n\n> \U0001f522 **Filed.** Value **1/10**.\n\nBody.\n"


def _homes(live: list[int], archived: list[int]) -> dict[int, str]:
    return bcc.item_homes(
        [
            (_LIVE, "".join(_item(n) for n in live)),
            (_ARCHIVE, "".join(_item(n) for n in archived)),
        ]
    )


def _verdict(citing_file: str, body: str, homes: dict[int, str]) -> tuple[list[str], list[str]]:
    citations = bcc.find_citations(citing_file, body, [_LIVE, _ARCHIVE])
    return bcc.check(citations, homes)


# --- the property the whole design rests on -------------------------------------------------------


def test_a_citation_resolves_identically_wherever_its_item_lives() -> None:
    """Move the item; the verdicts swap. Nothing else changes.

    This is the guard against the one bug that would quietly ruin the gate: a number-to-file
    assumption baked in anywhere. The archive move is routine and batched, so a number that is live
    today is archived tomorrow -- the checker must be indifferent to which, and the only way to show
    that is to run the SAME citation against both arrangements of the SAME namespace.
    """
    doc = (
        "cites the live ledger: [#900](BACKLOG.md)\n"
        "cites the archive: [#900](archive/backlog/BACKLOG-CLOSED.md)\n"
    )

    while_live = _verdict("docs/X.md", doc, _homes(live=[900], archived=[901]))
    assert len(while_live[0]) == 1, while_live
    assert "docs/X.md:2" in while_live[0][0], (
        f"with #900 LIVE, the archive-naming citation on line 2 is the wrong one: {while_live[0]}"
    )

    while_archived = _verdict("docs/X.md", doc, _homes(live=[901], archived=[900]))
    assert len(while_archived[0]) == 1, while_archived
    assert "docs/X.md:1" in while_archived[0][0], (
        f"with #900 ARCHIVED, the live-naming citation on line 1 is the wrong one: "
        f"{while_archived[0]}"
    )

    # Same document, same namespace, opposite verdicts -- the whole point.
    assert while_live[0] != while_archived[0]


def test_the_checker_carries_no_item_count_and_no_number_to_file_table() -> None:
    """A count or a per-file total in this module would be wrong the next time items are archived.

    Wave 1 moved 41 items in one pass while the branch was unmerged, so any figure written here
    would have been stale before it landed. The namespace is derived at run time from the same
    sources the status gate uses, and that is asserted by construct rather than trusted.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    assert "DEFAULT_SOURCES" in source, (
        "the ledger source list must be IMPORTED from backlog_status_check, so adding an archive "
        "file stays the single edit that module documents"
    )
    assert tuple(str(p).replace("\\", "/") for p in bcc.LEDGER_SOURCES) == (_LIVE, _ARCHIVE), (
        f"LEDGER_SOURCES is {bcc.LEDGER_SOURCES!r}; it must come from backlog_status_check."
        "DEFAULT_SOURCES unchanged"
    )


# --- what counts as a citation --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "construct"),
    [
        ("[#900](BACKLOG.md)\n", "link text"),
        ("[BACKLOG #900](BACKLOG.md)\n", "link text"),
        ("[#900](BACKLOG.md#900-a-thing)\n", "fragment"),
        ("[BACKLOG](BACKLOG.md#900-a-thing)\n", "fragment"),
        ("[BACKLOG](BACKLOG.md) #900\n", "adjacent"),
        ("[BACKLOG](BACKLOG.md), #900 is closed\n", "adjacent"),
    ],
)
def test_every_construct_binds_the_number_to_the_path(body: str, construct: str) -> None:
    """Each shape below appears in this repo's real docs and each must be caught."""
    errors, _ = _verdict("docs/X.md", body, _homes(live=[], archived=[900]))
    assert len(errors) == 1, f"{construct} citation not detected in {body!r}: {errors}"
    assert construct in errors[0]


def test_one_number_bound_by_two_constructs_is_one_finding() -> None:
    """``[#75](...#75-slug)`` is the repo's normal idiom and binds through text AND fragment.

    Reported twice it doubles the count of a single defect, and a count that overstates is how a
    remediation gets sized wrong. Both constructs are still named, because which one carried the
    number is what tells the reader where to edit.
    """
    errors, _ = _verdict("docs/X.md", "[#900](BACKLOG.md#900-a-thing)\n", _homes([], [900]))
    assert len(errors) == 1, errors
    assert "link text+fragment" in errors[0], errors[0]


def test_a_ledger_link_with_no_number_attached_is_not_a_citation() -> None:
    """The false positive that a same-line rule produces, pinned so it cannot come back.

    This is the real shape from ``docs/BACKLOG.md``: prose naming both ledger files generically,
    on a line that also mentions an unrelated item. A proximity rule reports it; binding the number
    to the path does not. Measured on this repo, the same-line rule flagged this and several like it.
    """
    body = (
        "Retiring an item moves it from [`BACKLOG.md`](BACKLOG.md) into "
        "[`archive/backlog/BACKLOG-CLOSED.md`](archive/backlog/BACKLOG-CLOSED.md), and "
        "**#900** fixed two such markers.\n"
    )
    errors, warnings = _verdict("docs/X.md", body, _homes(live=[], archived=[900]))
    assert errors == [], f"generic ledger prose was read as a citation of #900: {errors}"
    assert warnings == []


def test_a_number_separated_from_the_link_by_words_is_not_a_citation() -> None:
    """There is no distance to tune: the number abuts the link or it is not bound to it."""
    body = "See [the ledger](BACKLOG.md) for the details, and also read #900 while you are there\n"
    errors, _ = _verdict("docs/X.md", body, _homes(live=[], archived=[900]))
    assert errors == []


def test_fenced_and_inline_code_are_not_followed() -> None:
    """A path in a transcript is output being shown; a link in backticks is displayed, not offered.

    Both halves matter. The dominant repo idiom ``[`BACKLOG.md`](BACKLOG.md)`` closes its code span
    before the ``]``, so it is still checked -- a shape-based rule would stop checking most of the
    docs while staying green. The discriminator is POSITION, as in ``link_check.py``.
    """
    homes = _homes(live=[], archived=[900])
    fenced = "```\n[#900](BACKLOG.md)\n```\n"
    assert _verdict("docs/X.md", fenced, homes)[0] == []

    inline = "the regex `[#900](BACKLOG.md)` matches a link\n"
    assert _verdict("docs/X.md", inline, homes)[0] == []

    idiom = "[`#900`](BACKLOG.md)\n"
    assert len(_verdict("docs/X.md", idiom, homes)[0]) == 1, (
        "the [`x`](x) idiom closes its code span before the ']' and MUST still be checked"
    )


def test_relative_depth_is_resolved_not_matched_on_the_href() -> None:
    """An ADR two directories down writes ``../BACKLOG.md``; that is the same target."""
    errors, _ = _verdict("docs/adr/0113-x.md", "[#900](../BACKLOG.md)\n", _homes([], [900]))
    assert len(errors) == 1 and "docs/BACKLOG.md" in errors[0]


def test_a_non_ledger_link_is_ignored_however_it_is_numbered() -> None:
    body = "[#900](adr/0113-x.md) and [#900](https://example.invalid/BACKLOG.md)\n"
    assert _verdict("docs/X.md", body, _homes([], [900]))[0] == []


# --- the publishing boundary ----------------------------------------------------------------------


def test_a_number_the_namespace_does_not_carry_warns_and_does_not_fail() -> None:
    """``docs/BACKLOG.md`` says of itself that it is a published baseline of a fuller ledger.

    Measured 2026-08-10, the unresolvable citations in this repo are #13, #270 and #287 -- real
    items behind that boundary, not broken citations. A gate red on them is red for a reason no
    contributor can fix, which is how a gate gets deleted rather than obeyed. Still reported,
    because the same class catches a mistyped number.
    """
    errors, warnings = _verdict("docs/X.md", "[#4242](BACKLOG.md)\n", _homes([900], [901]))
    assert errors == []
    assert len(warnings) == 1 and "#4242" in warnings[0]


# --- diff scoping, end to end through main() -------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout


def _plant_repo(tmp_path: Path) -> Path:
    """A throwaway repo whose ledger holds #900 in the ARCHIVE, plus one pre-existing violation."""
    repo = tmp_path / "r"
    (repo / "docs" / "archive" / "backlog").mkdir(parents=True)
    (repo / _LIVE).write_text(_item(901, "Still open"), encoding="utf-8")
    (repo / _ARCHIVE).write_text(_item(900, "Retired"), encoding="utf-8")
    (repo / "docs" / "OLD.md").write_text("pre-existing: [#900](BACKLOG.md)\n", encoding="utf-8")
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_diff_scope_ignores_a_violation_on_a_line_the_change_did_not_touch(tmp_path: Path) -> None:
    """The binding constraint from PR #271: a gate red on pre-existing breakage gets suppressed.

    ``docs/OLD.md`` carries a violation from before the base commit. A change that adds an innocent
    line elsewhere must stay green, or no PR can merge until the whole corpus is repaired.
    """
    repo = _plant_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "docs" / "NEW.md").write_text("[#900](archive/backlog/BACKLOG-CLOSED.md)\n", "utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add a correct citation")
    head = _git(repo, "rev-parse", "HEAD").strip()

    done = _run(repo, "--base", base, "--head", head)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "docs/OLD.md" not in done.stdout, (
        "a pre-existing violation on an untouched line reached the gate:\n" + done.stdout
    )
    # The gate must SAY what it read, not only that it passed.
    assert "added-line scope: docs/NEW.md (+1)" in done.stdout, done.stdout
    assert "ledger citations in scope: 1" in done.stdout, done.stdout


def test_diff_scope_catches_a_violation_on_a_line_the_change_added(tmp_path: Path) -> None:
    """The gate can go RED. Without this the test above is satisfied by a checker that finds
    nothing, which is the same green and a very different control."""
    repo = _plant_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "docs" / "NEW.md").write_text("new: [#900](BACKLOG.md)\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add a stale citation")
    head = _git(repo, "rev-parse", "HEAD").strip()

    done = _run(repo, "--base", base, "--head", head)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "docs/NEW.md:1" in done.stdout and "#900" in done.stdout, done.stdout
    assert "docs/OLD.md" not in done.stdout, done.stdout


def test_editing_an_existing_line_brings_it_into_scope(tmp_path: Path) -> None:
    """A modified line is an ADDED line to git, so touching a stale citation must surface it.

    Otherwise the gate rewards editing around a violation rather than fixing it.
    """
    repo = _plant_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "docs" / "OLD.md").write_text("reworded: [#900](BACKLOG.md)\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "reword the line carrying the stale citation")
    head = _git(repo, "rev-parse", "HEAD").strip()

    done = _run(repo, "--base", base, "--head", head)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "docs/OLD.md:1" in done.stdout, done.stdout


def test_diff_scope_reads_the_file_at_head_not_the_working_tree(tmp_path: Path) -> None:
    """Line numbers come from ``--head``, so the content must too, or they index a different file.

    On a ``pull_request`` event ``actions/checkout`` lands the MERGE ref, not the head commit, so
    the checked-out file can legitimately differ from the one the diff measured. This reproduces the
    divergence in the cheapest available way -- five lines prepended in the working tree after the
    commit -- and pins the direction that matters: reading the tree would look for line 1 in a file
    where the citation is now on line 6, find nothing, and report GREEN over a real violation.
    """
    repo = _plant_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "docs" / "NEW.md").write_text("new: [#900](BACKLOG.md)\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add a stale citation")
    head = _git(repo, "rev-parse", "HEAD").strip()

    (repo / "docs" / "NEW.md").write_text(
        "pad\npad\npad\npad\npad\nnew: [#900](BACKLOG.md)\n", encoding="utf-8"
    )

    done = _run(repo, "--base", base, "--head", head)
    assert done.returncode == 1, (
        "the gate went green over a real violation -- it read the working tree, where the citation "
        "has moved to line 6, instead of the head commit the line numbers came from:\n"
        + done.stdout
        + done.stderr
    )
    assert "docs/NEW.md:1" in done.stdout, done.stdout


def test_an_unreadable_ledger_refuses_rather_than_reporting_the_whole_corpus(
    tmp_path: Path,
) -> None:
    """Anti-narrowing, the loud direction.

    ``backlog_status_check`` needs a ``--min-items`` floor because narrowing there goes GREEN. Here
    it goes red everywhere at once, which is worse to read: thousands of findings whose real cause
    is one unreadable path. An empty namespace is refused by name instead.
    """
    repo = _plant_repo(tmp_path)
    (repo / _LIVE).unlink()
    (repo / _ARCHIVE).unlink()
    done = _run(repo)
    assert done.returncode == 1
    assert "no items parsed" in done.stderr, done.stderr + done.stdout


# --- fired against the real corpus ------------------------------------------------------------------


def test_the_real_ledger_parses_into_one_namespace_holding_both_files() -> None:
    """No count is asserted -- only that BOTH files contributed, which is what a per-file scan
    would break. The numbers are read at run time and printed, never pinned."""
    sources = [(p.as_posix(), (_ROOT / p).read_text(encoding="utf-8")) for p in bcc.LEDGER_SOURCES]
    homes = bcc.item_homes(sources)
    per_file = {label: sum(1 for n in homes if homes[n] == label) for label, _ in sources}
    print(f"[citation-gate] namespace: {len(homes)} items -> {per_file}")
    assert len(sources) == 2, f"expected both ledger files, got {[s[0] for s in sources]}"
    assert all(v > 0 for v in per_file.values()), (
        f"one ledger file contributed no items: {per_file}. Either it stopped being parsed or it "
        "stopped being read -- both make every citation of its items resolve to nothing."
    )


def test_the_citation_regex_sees_every_ledger_LINK_the_link_checker_sees() -> None:
    """An absence claim needs a positive control, and this is the one that matters here.

    The two checkers use different regexes on purpose: ``link_check`` starts at ``](`` because it
    only needs the href, while this one must capture the display TEXT to read a number out of it --
    so it additionally requires a well-formed ``[text]`` and would silently skip any ledger link
    whose text carries a bracket. "No citation defects found" would then be a statement about the
    regex, not about the docs. Measured 2026-08-10 the two see the SAME 191 ledger links repo-wide,
    with zero seen by one and missed by the other, and this asserts it keeps being zero.
    """
    lc_spec = importlib.util.spec_from_file_location(
        "_link_check_for_parity", _ROOT / "scripts" / "docs" / "link_check.py"
    )
    assert lc_spec is not None and lc_spec.loader is not None
    link_check = importlib.util.module_from_spec(lc_spec)
    lc_spec.loader.exec_module(link_check)

    ledgers = {_LIVE, _ARCHIVE}
    files = subprocess.run(
        ["git", "-C", str(_ROOT), "ls-files", "*.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout.split()

    theirs = 0
    missed: list[str] = []
    for rel in sorted(files):
        here = Path(rel).parent.as_posix()
        base = bcc.PurePosixPath(here)
        in_fence = False
        for lineno, line in enumerate((_ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            if bcc._FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            mine = {
                m.start("href")
                for m in bcc._LINK.finditer(line)
                if bcc._normalise(base, m.group("href")) in ledgers
            }
            for m in link_check._LINK.finditer(line):
                if bcc._normalise(base, m.group("href")) not in ledgers:
                    continue
                theirs += 1
                if m.start("href") not in mine:
                    missed.append(f"{rel}:{lineno}: {m.group('href')}")

    print(f"[citation-gate] {theirs} ledger links repo-wide, {len(missed)} invisible to the gate")
    assert theirs > 100, (
        f"only {theirs} ledger links found repo-wide; the scan itself is broken, and a parity "
        "assertion over nothing proves nothing"
    )
    assert missed == [], (
        "ledger links the link checker sees and the citation gate does not -- any citation on these "
        "lines is unguarded:\n  " + "\n  ".join(missed)
    )


def test_a_deliberately_wrong_citation_against_the_REAL_ledger_is_caught() -> None:
    """Live positive control. The item is chosen from the real archive at run time, so this cannot
    rot into a citation of a number that has since moved -- and no number is written down here."""
    sources = [(p.as_posix(), (_ROOT / p).read_text(encoding="utf-8")) for p in bcc.LEDGER_SOURCES]
    homes = bcc.item_homes(sources)
    archived = sorted(n for n, home in homes.items() if home == _ARCHIVE)
    assert archived, "the real archive holds no items; this control cannot run"
    num = archived[-1]

    wrong, _ = _verdict("docs/X.md", f"[#{num}](BACKLOG.md)\n", homes)
    right, _ = _verdict("docs/X.md", f"[#{num}](archive/backlog/BACKLOG-CLOSED.md)\n", homes)
    print(f"[citation-gate] positive control used archived item #{num}")
    assert len(wrong) == 1, (
        f"the checker did not catch a stale citation of the real #{num}: {wrong}"
    )
    assert right == [], f"the checker flagged a CORRECT citation of the real #{num}: {right}"
