# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The owed-ledger-acts report must print an ask the vault ledger has not acted on.

The unsafe direction is a false DONE or a silently dropped ask: an owed flip that drops off the
report is the 2026-10-28 failure this script exists to prevent (rows #3844 and #3025, asked on
engine PRs 2545 and 2546, were skipped by a ledger pass briefed from memory).
``test_regression_3844_and_3025_print_as_owed`` is that case. These drive the real functions and
``main()`` with a canned gh and an in-memory ledger; the ``GitLedger`` tests drive a throwaway git
repository, and one proves no code the vault holds is run.
"""

from __future__ import annotations

import ast
import importlib.util
import itertools
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests._ast_sites import calls_to

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "coord" / "owed_ledger_acts.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("owed_ledger_acts_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


oa = _load()
ENGINE = oa.ENGINE_REPO
NOW = datetime(2026, 10, 28, 20, 0, tzinfo=UTC)
# The ledger's status glyphs, built from code points: this repository forbids new glyphs in source.
SHIPPED_GLYPH, OPEN_GLYPH, WIP_GLYPH = chr(0x2705), chr(0x1F522), chr(0x1F6A7)
VS16 = chr(0xFE0F)


def _dt(s: str) -> datetime:
    parsed: datetime = oa.pr_state.parse_iso(s)
    return parsed


_URL_IDS = itertools.count()
_CLOSED_WORDS = ("SHIPPED", "CLOSED")


def _block(text: str) -> Any:
    """A test block. A banner line here is a ``> `` line that is not a NOTE or HELD note, and its
    first word stands in for the status glyph the real ledger carries."""
    banners = tuple(
        ln
        for ln in text.split("\n")
        if ln.startswith("> ") and not ln.startswith(("> NOTE", "> HELD"))
    )
    status = frozenset(b[2:].split()[0].rstrip(":.") for b in banners)
    closed = bool(status) and all(s in _CLOSED_WORDS for s in status)
    return oa.Block(text, banners, closed, status)


class FakeLedger:
    """Commits as ``(time, sha, {row: block text})``, oldest first; the last is the ref's tip."""

    def __init__(self, commits: list[tuple[str, str, dict[int, str]]]) -> None:
        self.commits = [
            (_dt(t), sha, {n: _block(b) for n, b in blocks.items()}) for t, sha, blocks in commits
        ]

    def tip(self) -> tuple[str, str]:
        when, sha, _ = self.commits[-1]
        return sha, when.isoformat()

    def sha_before(self, when: datetime) -> str | None:
        found = [sha for t, sha, _ in self.commits if t <= when]
        return found[-1] if found else None

    def blocks(self, sha: str) -> dict[int, Any]:
        return next(b for _, s, b in self.commits if s == sha)


def _comment(body: str, at: str, assoc: str = "MEMBER", **kw: Any) -> dict[str, Any]:
    return {
        "body": body,
        "createdAt": at,
        "authorAssociation": assoc,
        "isMinimized": False,
        "url": f"https://example.invalid/c/{next(_URL_IDS)}",
        **kw,
    }


def _pr(
    number: int,
    merged: str,
    comments: list[dict[str, Any]],
    *,
    title: str = "",
    createdAt: str = "2026-10-26T00:00:00Z",  # noqa: N803 - the gh field name
    body: str = "",
) -> dict[str, Any]:
    return {
        "number": number,
        "title": title or f"PR {number}",
        "url": f"https://github.com/{ENGINE}/pull/{number}",
        "createdAt": createdAt,
        "mergedAt": merged,
        "body": body,
        "comments": comments,
    }


def _gh(prs: dict[str, list[dict[str, Any]]]) -> Any:
    def gh(args: list[str], stdin: str | None) -> str:
        repo = args[args.index("--repo") + 1]
        if repo not in prs:
            raise oa.pr_state.GhError(f"no such repo {repo}")
        return json.dumps(prs[repo])

    return gh


def _run(
    prs: dict[str, list[dict[str, Any]]],
    ledger: FakeLedger,
    capsys: pytest.CaptureFixture[str],
    *argv: str,
) -> str:
    rc = oa.main(list(argv), gh=_gh(prs), ledger=ledger, now=lambda: NOW)
    assert rc == 0
    return str(capsys.readouterr().out)


OPEN_3844 = "## 3844. reconciler gap\n\n> Filed 2026-10-18 -- OPEN, not started."
PARTIAL_3025 = "## 3025. TOTP enrolment\n\n> PARTIAL 2026-10-18 -- engine PR 2358. STAYS OPEN."

# The two asks of 2026-10-27T23:59Z, cut to the sentences that carry them.
ASK_2545 = (
    "Batch 433 Manager, 2026-10-27 ~23:50Z. For the Lander: this PR merged at 04:55Z, and vault "
    '`origin/main` still carries the "Filed 2026-10-18 ... OPEN, not started" banner on '
    "BACKLOG #3844. Please flip it. Proposed banner, from the last commit on the branch:\n\n"
    "> SHIPPED. `_reconcile_unanswered` carries referred accounts across passes.\n"
)
ASK_2546 = (
    "Batch 433 Manager, 2026-10-27 ~23:50Z. For the Lander: this PR merged at 21:49Z as "
    '`7f8d2445d6`. BACKLOG #3025 still carries its "PARTIAL 2026-10-18" banner at vault '
    "`origin/main`. Please flip it. Its open findings are already filed as #4567 and #4568 "
    "(ledger pass O, vault PR 2724)."
)
# The batch 433 Manager's 18:12Z comment on PR 2546, verbatim: it carries #3844's ask for PR 2545
# and names the already-landed #4567 and #4568 in a sentence with no ask word.
NOTE_2546 = (
    "Batch 433 Manager, 2026-10-27 ~18:12Z. For the Lander:\n\n"
    "- Rows #4567 and #4568 for this PR landed in ledger pass O (vault PR 2724), the condition "
    "your 13:20Z comment set before enqueue. Head is still "
    "`fca85d06a75f973aa0d01c790bee3b8a34186fc6`, unchanged since your covering review.\n"
    "- Not yet in the merge queue as of 18:12Z.\n"
    "- Separately: engine PR 2545 (BACKLOG #3844) merged 04:55Z, and the vault row #3844 still "
    "reads OPEN at vault `origin/main`. That banner flip is owed; a note is also on PR 2545.\n"
)
PRS_433 = {
    ENGINE: [
        _pr(2545, "2026-10-27T04:55:16Z", [_comment(ASK_2545, "2026-10-27T23:59:46Z")]),
        _pr(
            2546,
            "2026-10-27T21:49:45Z",
            [
                _comment(NOTE_2546, "2026-10-27T18:12:21Z"),
                _comment(ASK_2546, "2026-10-27T23:59:48Z"),
            ],
        ),
    ]
}


def _ledger_433(*later: tuple[str, str, dict[int, str]]) -> FakeLedger:
    base = {3844: OPEN_3844, 3025: PARTIAL_3025, 4567: "## 4567. x\n\n> engine PR 2546"}
    return FakeLedger([("2026-10-20T00:00:00Z", "a" * 40, base), *later])


def test_regression_3844_and_3025_print_as_owed(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(PRS_433, _ledger_433(), capsys, "--repo", ENGINE)
    assert "PR 2545" in out and "row #3844" in out
    assert "PR 2546" in out and "row #3025" in out
    # The 18:12Z comment on PR 2546 also asks #3844's flip (for PR 2545): an over-report, by design.
    assert out.count("OWED") == 3, out
    # The already-filed rows in the same paragraph are not asked for.
    assert "#4567" not in out and "#4568" not in out


def test_flip_citing_the_pr_is_done(capsys: pytest.CaptureFixture[str]) -> None:
    flipped = {
        3844: "## 3844. reconciler gap\n\n> SHIPPED 2026-10-28 by engine PR 2545.",
        3025: "## 3025. TOTP enrolment\n\n> SHIPPED 2026-10-28 by engine PR 2546; PR 2358 before.",
    }
    ledger = _ledger_433(("2026-10-28T19:00:00Z", "b" * 40, flipped))
    assert "nothing owed" in _run(PRS_433, ledger, capsys, "--repo", ENGINE)
    out = _run(PRS_433, ledger, capsys, "--repo", ENGINE, "--all")
    assert out.count("DONE") == 3


def test_an_edit_that_does_not_cite_the_pr_leaves_it_owed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    noted = {
        3844: OPEN_3844 + "\n> NOTE 2026-10-28 -- re-read, status unchanged.",
        3025: PARTIAL_3025,
    }
    out = _run(
        PRS_433, _ledger_433(("2026-10-28T19:00:00Z", "b" * 40, noted)), capsys, "--repo", ENGINE
    )
    assert "row #3844" in out and "OWED" in out


def test_a_change_before_the_ask_is_not_the_act(capsys: pytest.CaptureFixture[str]) -> None:
    # Cites PR 2545 but landed before the 23:59Z ask, so the ask's baseline already holds it.
    early = {3844: OPEN_3844 + "\n> IN REVIEW: engine PR 2545 is in the queue.", 3025: PARTIAL_3025}
    ledger = _ledger_433(("2026-10-27T10:00:00Z", "b" * 40, early))
    assert "row #3844" in _run(PRS_433, ledger, capsys, "--repo", ENGINE)


def test_marker_is_primary_and_skips_prose(capsys: pytest.CaptureFixture[str]) -> None:
    body = "<!-- lander-ledger-ask rows=#3844 -->\nLander: please flip #9999 too."
    prs = {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", [_comment(body, "2026-10-27T05:00:00Z")])]}
    out = _run(prs, _ledger_433(), capsys, "--repo", ENGINE)
    assert "row #3844" in out and "[marker]" in out
    assert "#9999" not in out


def test_marker_in_the_pr_body_and_a_file_ask(capsys: pytest.CaptureFixture[str]) -> None:
    pr = _pr(
        2600,
        "2026-10-28T10:00:00Z",
        [],
        body="Summary.\n<!-- lander-ledger-ask file=2 -->",
        createdAt="2026-10-28T01:00:00Z",
    )
    # One row filed citing the PR BEFORE the merge still counts: filing precedes the merge.
    one = {
        3844: OPEN_3844,
        4800: "## 4800. finding\n\n> Filed from engine PR 2600.",
    }
    ledger = _ledger_433(("2026-10-28T05:00:00Z", "b" * 40, one))
    out = _run({ENGINE: [pr]}, ledger, capsys, "--repo", ENGINE)
    assert "file 2 row(s)" in out and "OWED" in out and "#4800" in out
    two = {**one, 4801: "## 4801. finding\n\n> Filed from engine PR 2600."}
    ledger = _ledger_433(
        ("2026-10-28T05:00:00Z", "b" * 40, one), ("2026-10-28T12:00:00Z", "c" * 40, two)
    )
    assert "nothing owed" in _run({ENGINE: [pr]}, ledger, capsys, "--repo", ENGINE)


def test_untrusted_minimized_and_landers_own_comments_are_ignored(
    capsys: pytest.CaptureFixture[str],
) -> None:
    comments = [
        _comment("For the Lander: please flip #3844.", "2026-10-27T06:00:00Z", assoc="NONE"),
        _comment("For the Lander: please flip #3844.", "2026-10-27T06:00:01Z", isMinimized=True),
        _comment("Lander (session ab12), flip of #3844 is owed.", "2026-10-27T06:00:02Z"),
        _comment("<!-- lander-hold -->\nLander: held; flip #3844 is owed.", "2026-10-27T06:00:03Z"),
    ]
    prs = {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", comments)]}
    assert "nothing owed" in _run(prs, _ledger_433(), capsys, "--repo", ENGINE)


def test_handover_without_a_row_falls_back_to_the_title(
    capsys: pytest.CaptureFixture[str],
) -> None:
    body = "Lander: batch 458 hands this to you. Banner text is in the body."
    titled = _pr(
        2612,
        "2026-10-27T04:55:16Z",
        [_comment(body, "2026-10-27T03:00:00Z")],
        title="Fix it (BACKLOG #3844)",
    )
    untitled = _pr(2613, "2026-10-27T04:55:16Z", [_comment(body, "2026-10-27T03:00:00Z")])
    out = _run({ENGINE: [titled, untitled]}, _ledger_433(), capsys, "--repo", ENGINE)
    assert "PR 2612" in out and "row #3844" in out
    assert "READ" in out and "PR 2613" in out


def test_pr_numbers_are_not_rows_and_missing_rows_say_so(
    capsys: pytest.CaptureFixture[str],
) -> None:
    body = "For the Lander: flip #4999 now that PR #2545 merged."
    prs = {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", [_comment(body, "2026-10-27T06:00:00Z")])]}
    out = _run(prs, _ledger_433(), capsys, "--repo", ENGINE)
    assert "MISSING" in out and "row #4999" in out and "row #2545" not in out


def test_a_bare_pr_citation_has_no_repository_unless_one_is_given() -> None:
    text = "engine PR 246, PR 246, korus PR 246, vault PR 7"
    assert oa.cited_prs(text) == [
        (ENGINE, 246),
        (None, 246),
        (oa.KORUS_REPO, 246),
        (oa.VAULT_REPO, 7),
    ]
    assert oa.cited_prs("PR 246", oa.KORUS_REPO) == [(oa.KORUS_REPO, 246)]
    assert oa.cited_prs("https://github.com/MEFORORG/korus/pull/9") == [(oa.KORUS_REPO, 9)]


def test_asks_for_one_act_read_as_one(capsys: pytest.CaptureFixture[str]) -> None:
    comments = [
        _comment("For the Lander: the banner on #3844 is owed.", "2026-10-27T18:12:23Z"),
        _comment(ASK_2545, "2026-10-27T23:59:46Z"),
    ]
    prs = {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", comments)]}
    out = _run(prs, _ledger_433(), capsys, "--repo", ENGINE)
    assert out.count("row #3844") == 1


def test_a_failed_read_is_an_error_line_and_exit_0(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run({}, _ledger_433(), capsys, "--repo", ENGINE)
    assert out.splitlines()[1].startswith("ERROR") and "read failed" in out
    assert "nothing owed" not in out


def test_no_vault_is_an_error_not_an_empty_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert oa.main([], gh=_gh({}), now=lambda: NOW) == 0
    out = capsys.readouterr().out
    assert out.startswith("ERROR") and "--vault" in out


def test_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    doc = json.loads(_run(PRS_433, _ledger_433(), capsys, "--repo", ENGINE, "--json"))
    assert doc["scannedPullRequests"] == 2 and doc["ledger"].startswith("origin/main ")
    owed = {(r["pr"], r["what"]) for r in doc["rows"] if r["status"] == "OWED"}
    assert owed == {(2545, "row #3844"), (2546, "row #3025"), (2546, "row #3844")}


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout


def _vault(tmp_path: Path) -> tuple[Path, Any]:
    """A throwaway vault repository, and ``commit(text, when) -> sha`` writing its BACKLOG.md."""
    repo = tmp_path / "vault"
    (repo / "docs").mkdir(parents=True)
    ledger_file = repo / "docs" / "BACKLOG.md"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    # Isolate the commits from the runner's global config.
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "core.hooksPath", str(tmp_path / "no-hooks"))

    def commit(text: str, when: str) -> str:
        ledger_file.write_text(text, encoding="utf-8")
        _git(repo, "add", "-A")
        env = {**os.environ, "GIT_COMMITTER_DATE": when, "GIT_AUTHOR_DATE": when}
        _git(repo, "commit", "-q", "-m", "x", env=env)
        return _git(repo, "rev-parse", "HEAD").strip()

    return repo, commit


def test_git_ledger_reads_blocks_at_a_commit_before_a_time(tmp_path: Path) -> None:
    repo, commit = _vault(tmp_path)
    opened = f"> {OPEN_GLYPH} OPEN"
    shipped = f"> {SHIPPED_GLYPH}{VS16} SHIPPED by engine PR 2545"
    first = commit(f"## 3844. gap\n\n{opened}\n\nbody text\n", "2026-10-20T00:00:00+00:00")
    second = commit(f"## 3844. gap\n\n{shipped}\n\nbody text\n", "2026-10-28T19:00:00+00:00")
    ledger = oa.GitLedger(repo, "main")
    assert ledger.tip()[0] == second
    assert ledger.sha_before(_dt("2026-10-27T23:59:46Z")) == first
    assert ledger.sha_before(_dt("2026-10-01T00:00:00Z")) is None
    assert ledger.blocks(first)[3844] == (
        f"## 3844. gap\n\n{opened}\n",
        (opened,),
        False,
        frozenset({OPEN_GLYPH}),
    )
    assert "body text" not in ledger.blocks(second)[3844].text
    assert ledger.blocks(second)[3844].banners == (shipped,)
    assert ledger.blocks(second)[3844].closed


def test_no_code_the_vault_holds_is_run(tmp_path: Path) -> None:
    """Finding A: whoever can push the vault must not run code as the reader. The cbc1d0cf script
    exec'd the vault's parser at the ref; a booby-trapped parser there must stay inert."""
    repo, commit = _vault(tmp_path)
    sentinel = tmp_path / "vault-code-ran"
    (repo / "scripts" / "docs").mkdir(parents=True)
    (repo / "scripts" / "docs" / "backlog_status_check.py").write_text(
        f"open({str(sentinel)!r}, 'w').write('ran')\n", encoding="utf-8"
    )
    sha = commit(f"## 3844. gap\n\n> {OPEN_GLYPH} OPEN\n", "2026-10-20T00:00:00+00:00")
    blocks = oa.GitLedger(repo, "main").blocks(sha)
    assert not sentinel.exists()
    assert 3844 in blocks


def test_the_script_has_no_dynamic_code_execution() -> None:
    tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
    assert not calls_to(tree, {"exec", "eval", "compile"}, bare_only=True)


def test_parse_ledger_reads_the_vault_grammar() -> None:
    text = (
        "# Backlog\n\n"
        f"## 1. shipped\n\n> {SHIPPED_GLYPH}{VS16} SHIPPED by engine PR 5.\n> NOTE prose\n\nScope.\n"
        f"## 2. both\n\n> {SHIPPED_GLYPH} SHIPPED\n> {WIP_GLYPH} PARTIAL\n\nScope.\n"
        "## 3. no banner\n\n> NOTE only\n\nScope.\n"
        "## 30 not a heading\n"
        f"## 4. open\n> {OPEN_GLYPH} Filed\n"
    )
    rows = oa.parse_ledger(text)
    assert sorted(rows) == [1, 2, 3, 4]
    assert rows[1].closed and rows[1].banners == (
        f"> {SHIPPED_GLYPH}{VS16} SHIPPED by engine PR 5.",
    )
    assert "> NOTE prose" in rows[1].text and "Scope." not in rows[1].text
    assert not rows[2].closed and rows[2].status == frozenset({SHIPPED_GLYPH, WIP_GLYPH})
    assert rows[3].banners == () and not rows[3].closed
    assert not rows[4].closed and rows[4].status == frozenset({OPEN_GLYPH})
    # A row listed twice (mid-move between the files) is OPEN if either copy is.
    dup = oa.parse_ledger(f"## 9. a\n> {SHIPPED_GLYPH} x\n## 9. a\n> {WIP_GLYPH} y\n")
    assert not dup[9].closed
    with pytest.raises(oa.ReadError, match="conflict marker"):
        oa.parse_ledger("## 1. x\n<<<<<<< HEAD\n> a\n=======\n> b\n>>>>>>> other\n")


@pytest.mark.parametrize(
    "marker",
    [
        "<!-- lander-ledger-ask -->",
        "<!-- lander-ledger-ask flips=3844 -->",
        "<!-- lander-ledger-ask rows=#3844",
    ],
)
def test_a_marker_naming_nothing_prints_read(
    marker: str, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _run(
        _one(marker + "\nFor the Lander: please flip #3844."),
        _ledger_433(),
        capsys,
        "--repo",
        ENGINE,
    )
    assert "READ" in out and "nothing owed" not in out


def _one(
    body: str, at: str = "2026-10-27T06:00:00Z", number: int = 2545, **kw: Any
) -> dict[str, list[dict[str, Any]]]:
    return {ENGINE: [_pr(number, "2026-10-27T04:55:16Z", [_comment(body, at)], **kw)]}


@pytest.mark.parametrize(
    "rows", ["#3844 #3025", "#3844;#3025", "3844, 3025", " #3844 , #3025", "#3844 and #3025"]
)
def test_marker_rows_take_any_separator(rows: str) -> None:
    assert oa.parse_marker(f"<!-- lander-ledger-ask rows={rows} file=1 -->") == [
        oa.Marker((3844, 3025), 1)
    ]
    assert oa.parse_marker(f"<!-- lander-ledger-ask row={rows} -->") == [oa.Marker((3844, 3025), 0)]


def test_a_held_note_citing_the_pr_is_not_the_act(capsys: pytest.CaptureFixture[str]) -> None:
    held = {3844: OPEN_3844 + "\n> HELD 2026-10-28: flip for engine PR 2545 waits on a ruling."}
    ledger = _ledger_433(("2026-10-28T19:00:00Z", "b" * 40, held))
    assert "OWED" in _run(PRS_433, ledger, capsys, "--repo", ENGINE)


def test_a_flip_replacing_an_existing_citation_is_done(capsys: pytest.CaptureFixture[str]) -> None:
    review = {3844: "## 3844. gap\n\n> IN REVIEW: engine PR 2545"}
    shipped = {3844: "## 3844. gap\n\n> SHIPPED by engine PR 2545"}
    ledger = FakeLedger(
        [("2026-10-20T00:00:00Z", "a" * 40, review), ("2026-10-28T10:00:00Z", "b" * 40, shipped)]
    )
    assert "nothing owed" in _run(
        _one("For the Lander: flip #3844."), ledger, capsys, "--repo", ENGINE
    )


def test_a_later_acknowledgement_does_not_reopen_the_act(
    capsys: pytest.CaptureFixture[str],
) -> None:
    comments = [
        _comment("For the Lander: please flip #3844.", "2026-10-27T06:00:00Z"),
        _comment("Lander: flipped #3844 in vault PR 2730; done.", "2026-10-28T11:00:00Z"),
    ]
    prs = {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", comments)]}
    shipped = {3844: "## 3844. gap\n\n> SHIPPED by engine PR 2545"}
    ledger = _ledger_433(("2026-10-28T10:00:00Z", "b" * 40, shipped))
    assert "nothing owed" in _run(prs, ledger, capsys, "--repo", ENGINE)


def test_plural_pr_citations() -> None:
    assert oa.cited_prs("engine PRs 2545 and 2546") == [(ENGINE, 2545), (ENGINE, 2546)]
    assert oa.cited_prs("PRs 1, 2 and 3", ENGINE) == [(ENGINE, 1), (ENGINE, 2), (ENGINE, 3)]
    assert oa.row_refs("flip #3844 (engine PRs #2545 and #2546)") == [3844]


def test_prose_row_word_and_split_sentences() -> None:
    title = "Fix it (BACKLOG #1611)"
    assert oa.parse_prose("For the Lander: please flip row 3844.", title).rows == (3844,)
    assert oa.parse_prose("Lander: BACKLOG #3844 ships here. Please flip it.", title).rows == (
        3844,
    )


def test_a_reminder_does_not_shrink_a_marker_file_count(
    capsys: pytest.CaptureFixture[str],
) -> None:
    comments = [
        _comment("<!-- lander-ledger-ask file=2 -->", "2026-10-27T06:00:00Z"),
        _comment("Lander: reminder, please file the rows for this PR.", "2026-10-27T08:00:00Z"),
    ]
    prs = {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", comments)]}
    one = {3844: OPEN_3844, 4800: "## 4800. f\n\n> Filed from engine PR 2545."}
    ledger = _ledger_433(("2026-10-27T07:00:00Z", "b" * 40, one))
    out = _run(prs, ledger, capsys, "--repo", ENGINE)
    assert "file at least 2 row(s)" in out and "OWED" in out


def test_a_closed_row_is_done_whatever_it_cites(capsys: pytest.CaptureFixture[str]) -> None:
    closed = {3844: "## 3844. gap\n\n> SHIPPED by engine PR 2585", 3025: PARTIAL_3025}
    ledger = _ledger_433(("2026-10-28T19:00:00Z", "b" * 40, closed))
    out = _run(PRS_433, ledger, capsys, "--repo", ENGINE)
    assert "row #3844" not in out and "row #3025" in out


def test_an_in_place_edit_of_a_citing_banner_is_not_the_act(
    capsys: pytest.CaptureFixture[str],
) -> None:
    review = {3844: "## 3844. gap\n\n> IN REVIEW: engine PR 2545"}
    annotated = {3844: "## 3844. gap\n\n> IN REVIEW [stale 2026-10-28]: engine PR 2545"}
    ledger = FakeLedger(
        [("2026-10-20T00:00:00Z", "a" * 40, review), ("2026-10-28T10:00:00Z", "b" * 40, annotated)]
    )
    assert "OWED" in _run(_one("For the Lander: flip #3844."), ledger, capsys, "--repo", ENGINE)


def test_no_ledger_commit_before_the_baseline_is_an_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    review = {3844: "## 3844. gap\n\n> IN REVIEW: engine PR 2545"}
    ledger = FakeLedger([("2026-10-28T10:00:00Z", "b" * 40, review)])
    out = _run(_one("For the Lander: flip #3844."), ledger, capsys, "--repo", ENGINE)
    assert "ERROR" in out and "shallow" in out


def test_row_extraction_skips_repo_refs_and_pr_lists() -> None:
    assert oa.row_refs("see korus#232 and owner/repo#9; flip #3844") == [3844]
    assert oa.row_refs("Lander: PR 2546 and #3025 can close now") == [3025]
    assert oa.cited_prs("SHIPPED by engine PR 2545, 2026-10-28") == [(ENGINE, 2545)]


@pytest.mark.parametrize(
    ("text", "count"),
    [
        ("Eight NEW ledger rows to file.", 8),
        ("Please file 3 rows.", 3),
        ("File a row.", 1),
        ("The 13 open findings from round 2 are to file as rows.", 13),
    ],
)
def test_a_prose_file_ask_takes_its_count(text: str, count: int) -> None:
    parsed = oa.parse_prose("For the Lander. " + text)
    assert parsed is not None and parsed.file_count == count and not parsed.file_unknown


# ---- Regressions for the round-9bbedb3bd9 findings, each red on cbc1d0cf. -------------------------


def test_b1_a_row_closed_before_the_ask_is_not_done(capsys: pytest.CaptureFixture[str]) -> None:
    """CLOSED at the ref is not the act when it was already CLOSED at the baseline."""
    shipped = {3844: "## 3844. gap\n\n> SHIPPED by engine PR 2500", 3025: PARTIAL_3025}
    ledger = FakeLedger([("2026-10-20T00:00:00Z", "a" * 40, shipped)])
    out = _run(_one("For the Lander: please flip #3844."), ledger, capsys, "--repo", ENGINE)
    assert "row #3844" in out and "OWED" in out and "already CLOSED" in out


def test_b2_a_new_citing_banner_without_a_status_change_is_not_done(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A banner line that merely cites the PR ("merged; flip owed") is not a flip."""
    same_status = {3025: PARTIAL_3025 + "\n> PARTIAL: engine PR 2546 merged; flip owed."}
    ledger = _ledger_433(("2026-10-28T19:00:00Z", "b" * 40, same_status))
    out = _run(
        _one("For the Lander: please flip #3025.", number=2546), ledger, capsys, "--repo", ENGINE
    )
    assert "row #3025" in out and "OWED" in out
    # A status change whose new banner still says the act is owed is not the act either...
    owed_words = {3844: OPEN_3844 + "\n> PARTIAL: engine PR 2545 merged; flip owed."}
    ledger = _ledger_433(("2026-10-28T19:00:00Z", "b" * 40, owed_words))
    assert "OWED" in _run(
        _one("For the Lander: please flip #3844."), ledger, capsys, "--repo", ENGINE
    )
    # ...while one that records the act is.
    recorded = {3844: OPEN_3844 + "\n> PARTIAL: slice A shipped by engine PR 2545."}
    ledger = _ledger_433(("2026-10-28T19:00:00Z", "b" * 40, recorded))
    assert "nothing owed" in _run(
        _one("For the Lander: please flip #3844."), ledger, capsys, "--repo", ENGINE
    )


def _statuses(out: str) -> list[str]:
    """The status word of each report line, the header skipped."""
    return [line.split()[0] for line in out.splitlines()[1:] if line.strip()]


def test_b3_two_filing_markers_count_against_their_sum(capsys: pytest.CaptureFixture[str]) -> None:
    comments = [
        _comment("<!-- lander-ledger-ask file=2 -->", "2026-10-27T06:00:00Z"),
        _comment("<!-- lander-ledger-ask file=3 -->", "2026-10-27T07:00:00Z"),
    ]
    prs = {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", comments)]}
    three = {n: f"## {n}. f\n\n> Filed from engine PR 2545." for n in (4800, 4801, 4802)}
    ledger = _ledger_433(("2026-10-27T12:00:00Z", "b" * 40, three))
    out = _run(prs, ledger, capsys, "--repo", ENGINE)
    assert "file 5 row(s)" in out and "OWED" in out
    assert oa.DONE not in _statuses(_run(prs, ledger, capsys, "--repo", ENGINE, "--all"))


def test_b4_an_unstated_file_count_is_never_done(capsys: pytest.CaptureFixture[str]) -> None:
    prose = oa.parse_prose("For the Lander: the open findings above still need filing as rows.")
    assert prose is not None and prose.file_unknown
    body = "For the Lander: please file the review's open findings as rows."
    filed = {3844: OPEN_3844, 4800: "## 4800. f\n\n> Filed from engine PR 2545."}
    ledger = _ledger_433(("2026-10-27T12:00:00Z", "b" * 40, filed))
    out = _run(_one(body), ledger, capsys, "--repo", ENGINE, "--all")
    assert "count unknown" in out and _statuses(out) == ["OWED"]


def test_b5_a_bare_ledger_citation_is_not_this_pr(capsys: pytest.CaptureFixture[str]) -> None:
    """The vault writes a bare "PR N" for its own pull requests, so it cannot stand for engine N."""
    pr = _pr(2600, "2026-10-28T10:00:00Z", [], body="<!-- lander-ledger-ask file=1 -->")
    filed = {3844: OPEN_3844, 4800: "## 4800. f\n\n> Filed in PR 2600."}
    ledger = _ledger_433(("2026-10-28T12:00:00Z", "b" * 40, filed))
    out = _run({ENGINE: [pr]}, ledger, capsys, "--repo", ENGINE)
    assert "file 1 row(s)" in out and "OWED" in out
    assert oa.cite_count("> SHIPPED by PR 2600", [(ENGINE, 2600)]) == 0


@pytest.mark.parametrize("who", ["FOR THE LANDER", "for the lander", "LANDER"])
def test_b6_the_lander_is_named_in_any_case(who: str) -> None:
    parsed = oa.parse_prose(f"{who}: please flip #3844.")
    assert parsed is not None and parsed.rows == (3844,)


def test_b7_a_second_ask_in_another_sentence_is_kept() -> None:
    text = "Lander: BACKLOG #3844 ships here. Please flip it. Also #3025 needs its banner."
    parsed = oa.parse_prose(text)
    assert parsed is not None and set(parsed.rows) == {3844, 3025}


def test_b8_only_the_landers_exact_shapes_are_its_own() -> None:
    assert oa.parse_prose("Lander (8a04c9f3): flip #3844.") is not None
    assert oa.parse_prose("Lander b58f86: flip #3844 is owed.") is not None
    assert oa.parse_prose("Lander (session 8a04c9f3), 2026-10-28: flip #3844 is owed.") is None
    assert oa.parse_prose("<!-- lander-hold head=abc -->\nLander: flip #3844 is owed.") is None


@pytest.mark.parametrize(
    "marker",
    [
        "<!-- lander-ledger-ask rows=#3844 files=2 -->",
        "<!-- lander-ledger-ask rows=#3844 file=two -->",
        "<!-- lander-ledger-ask rows=#3844 flie=2 -->",
    ],
)
def test_b9_an_unreadable_marker_key_prints_read(
    marker: str, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _run(_one(marker), _ledger_433(), capsys, "--repo", ENGINE)
    assert "READ" in out and "row #3844" in out


def test_b10_lists_of_rows_and_a_singular_pr() -> None:
    assert oa.row_refs("Lander: flip rows 3844 and 3025") == [3844, 3025]
    assert oa.row_refs("Lander: flip rows 3844, 3025 and 3026") == [3844, 3025, 3026]
    assert oa.row_refs("Lander: PR #2546 and #3025 can close now") == [3025]
    assert oa.cited_prs("PR #2546 and #3025", ENGINE) == [(ENGINE, 2546)]


@pytest.mark.parametrize(
    "text",
    [
        "Lander: please mark #3844 SHIPPED.",
        "Lander: #3844 needs to re-open.",
        "Lander: please reopen #3844.",
        "Lander: update the status of #3844.",
        "Lander: #3844 can be retired.",
        "Lander: #3844 is declined by the owner.",
    ],
)
def test_b11_wider_ask_words(text: str) -> None:
    parsed = oa.parse_prose(text)
    assert parsed is not None and parsed.rows == (3844,)


def test_b12_the_title_fallback_takes_every_backlog_row() -> None:
    parsed = oa.parse_prose("Lander: please flip it.", "Fix (BACKLOG #3844 and #3025, slice A)")
    assert parsed is not None and parsed.rows == (3844, 3025)
    parsed = oa.parse_prose("Lander: please flip it.", "Fix (BACKLOG #3844, #3025)")
    assert parsed is not None and parsed.rows == (3844, 3025)


@pytest.mark.parametrize(
    "body",
    [
        "Put `<!-- lander-ledger-ask rows=#3844 -->` on the PR.",
        "Example:\n\n```\n<!-- lander-ledger-ask rows=#3844 -->\n```\n",
        "> <!-- lander-ledger-ask rows=#3844 -->",
    ],
)
def test_c_a_marker_in_code_or_a_quote_is_an_example(
    body: str, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(2545, "2026-10-27T04:55:16Z", [], body=body)
    assert oa.parse_marker(body) == []
    assert "nothing owed" in _run({ENGINE: [pr]}, _ledger_433(), capsys, "--repo", ENGINE)


def test_a_status_glyph_the_grammar_does_not_know_is_never_closed() -> None:
    """Grammar drift: a glyph the vault adds later must not let a row read CLOSED."""
    new_glyph = chr(0x1F6D1)
    rows = oa.parse_ledger(f"## 7. x\n> {SHIPPED_GLYPH} SHIPPED\n> {new_glyph} NEW STATUS\n")
    assert not rows[7].closed
    plain = oa.parse_ledger(f"## 8. x\n> {SHIPPED_GLYPH} SHIPPED\n> Note: plain prose\n")
    assert plain[8].closed


def test_git_ledger_baselines_match_rev_list(tmp_path: Path) -> None:
    repo, commit = _vault(tmp_path)
    times = ["2026-10-20T00:00:00+00:00", "2026-10-22T00:00:00+00:00", "2026-10-24T00:00:00+00:00"]
    shas = [commit(f"## 1. x\n\n> {OPEN_GLYPH} n={i}\n", when) for i, when in enumerate(times)]
    ledger = oa.GitLedger(repo, "main")
    probes = ["2026-10-19T00:00:00Z", "2026-10-22T00:00:00Z", "2026-10-23T12:00:00Z"]
    for when in [*map(_dt, probes), NOW]:
        expected = _git(
            repo, "rev-list", "-1", "--first-parent", f"--before={oa.pr_state.iso(when)}", "main"
        ).strip()
        assert ledger.sha_before(when) == (expected or None)
    # A commit that leaves the ledger untouched shares the earlier parse.
    (repo / "other.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "y")
    later = _git(repo, "rev-parse", "HEAD").strip()
    assert ledger.blocks(later) is ledger.blocks(shas[-1])
