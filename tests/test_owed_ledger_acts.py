# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The owed-ledger-acts report must print an ask the vault ledger has not acted on.

The unsafe direction is a false DONE: an owed flip that drops off the report is the 2026-10-28
failure this script exists to prevent (rows #3844 and #3025, asked on engine PRs 2545 and 2546,
were skipped by a ledger pass briefed from memory). ``test_regression_3844_and_3025_print_as_owed``
is that case. These drive the real functions and ``main()`` with a canned gh and an in-memory
ledger; one test drives ``GitLedger`` against a throwaway git repository.
"""

from __future__ import annotations

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


def _dt(s: str) -> datetime:
    parsed: datetime = oa.pr_state.parse_iso(s)
    return parsed


_URL_IDS = itertools.count()


def _block(text: str) -> Any:
    """A test block. A banner line here is a ``> `` line that is not a NOTE or HELD note; the real
    ledger marks one with a status glyph, which this file may not carry."""
    banners = tuple(
        ln
        for ln in text.split("\n")
        if ln.startswith("> ") and not ln.startswith(("> NOTE", "> HELD"))
    )
    return oa.Block(text, banners)


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
PRS_433 = {
    ENGINE: [
        _pr(2545, "2026-10-27T04:55:16Z", [_comment(ASK_2545, "2026-10-27T23:59:46Z")]),
        _pr(2546, "2026-10-27T21:49:45Z", [_comment(ASK_2546, "2026-10-27T23:59:48Z")]),
    ]
}


def _ledger_433(*later: tuple[str, str, dict[int, str]]) -> FakeLedger:
    base = {3844: OPEN_3844, 3025: PARTIAL_3025, 4567: "## 4567. x\n\n> engine PR 2546"}
    return FakeLedger([("2026-10-20T00:00:00Z", "a" * 40, base), *later])


def test_regression_3844_and_3025_print_as_owed(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(PRS_433, _ledger_433(), capsys, "--repo", ENGINE)
    assert "PR 2545" in out and "row #3844" in out
    assert "PR 2546" in out and "row #3025" in out
    assert out.count("OWED") == 2, out
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
    assert out.count("DONE") == 2


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
    two = {**one, 4801: "## 4801. finding\n\n> Filed from PR 2600."}
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
        _comment("Lander (session ab), flip of #3844 is owed.", "2026-10-27T06:00:02Z"),
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


def test_a_bare_pr_citation_is_the_engine_not_korus() -> None:
    assert oa.cited_prs("engine PR 246, PR 246, korus PR 246, vault PR 7") == [
        (ENGINE, 246),
        (ENGINE, 246),
        (oa.KORUS_REPO, 246),
        (oa.VAULT_REPO, 7),
    ]
    assert oa.cited_prs("https://github.com/MEFORORG/korus/pull/9") == [(oa.KORUS_REPO, 9)]


def test_the_latest_ask_for_one_act_wins(capsys: pytest.CaptureFixture[str]) -> None:
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
    assert owed == {(2545, "row #3844"), (2546, "row #3025")}


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout


def test_git_ledger_reads_blocks_at_a_commit_before_a_time(tmp_path: Path) -> None:
    repo = tmp_path / "vault"
    (repo / "scripts" / "docs").mkdir(parents=True)
    (repo / "docs").mkdir()
    # A stand-in for the vault's parser: the same Item fields GitLedger reads.
    (repo / "scripts" / "docs" / "backlog_status_check.py").write_text(
        "from pathlib import Path\n"
        "import re\n"
        "_BANNER = re.compile(r'^>\\s(?:OPEN|SHIPPED)')\n"
        "LEDGER_SOURCES = (Path('docs/BACKLOG.md'), Path('docs/archive/CLOSED.md'))\n"
        "class Item:\n"
        "    def __init__(self, num, line, body_line):\n"
        "        self.num, self.line, self.body_line = num, line, body_line\n"
        "def parse_items(text):\n"
        "    lines = text.split('\\n'); out = []\n"
        "    for i, l in enumerate(lines):\n"
        "        m = re.match(r'^## (\\d+)\\. ', l)\n"
        "        if m:\n"
        "            j = i + 1\n"
        "            while j < len(lines) and (not lines[j].strip() or lines[j].startswith('>')):\n"
        "                j += 1\n"
        "            out.append(Item(int(m.group(1)), i + 1, j + 1))\n"
        "    return out\n",
        encoding="utf-8",
    )
    ledger_file = repo / "docs" / "BACKLOG.md"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")

    def commit(text: str, when: str) -> str:
        ledger_file.write_text(text, encoding="utf-8")
        _git(repo, "add", "-A")
        env = {**os.environ, "GIT_COMMITTER_DATE": when, "GIT_AUTHOR_DATE": when}
        _git(repo, "commit", "-q", "-m", "x", env=env)
        return _git(repo, "rev-parse", "HEAD").strip()

    first = commit("## 3844. gap\n\n> OPEN\n\nbody text\n", "2026-10-20T00:00:00+00:00")
    second = commit(
        "## 3844. gap\n\n> SHIPPED by engine PR 2545\n\nbody text\n", "2026-10-28T19:00:00+00:00"
    )
    ledger = oa.GitLedger(repo, "main")
    assert ledger.tip()[0] == second
    assert ledger.sha_before(_dt("2026-10-27T23:59:46Z")) == first
    assert ledger.sha_before(_dt("2026-10-01T00:00:00Z")) is None
    assert ledger.blocks(first)[3844] == ("## 3844. gap\n\n> OPEN\n", ("> OPEN",))
    assert "body text" not in ledger.blocks(second)[3844].text
    assert ledger.blocks(second)[3844].banners == ("> SHIPPED by engine PR 2545",)


def _one(body: str, at: str = "2026-10-27T06:00:00Z", **kw: Any) -> dict[str, list[dict[str, Any]]]:
    return {ENGINE: [_pr(2545, "2026-10-27T04:55:16Z", [_comment(body, at)], **kw)]}


@pytest.mark.parametrize(
    "marker", ["<!-- lander-ledger-ask -->", "<!-- lander-ledger-ask flips=3844 -->"]
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


@pytest.mark.parametrize("rows", ["#3844 #3025", "#3844;#3025", "3844, 3025", " #3844 , #3025"])
def test_marker_rows_take_any_separator(rows: str) -> None:
    assert oa.parse_marker(f"<!-- lander-ledger-ask rows={rows} file=1 -->") == [((3844, 3025), 1)]
    assert oa.parse_marker(f"<!-- lander-ledger-ask row={rows} -->") == [((3844, 3025), 0)]


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
    assert oa.cited_prs("PR 1, 2 and 3") == [(ENGINE, 1), (ENGINE, 2), (ENGINE, 3)]
    assert oa.row_refs("flip #3844 (engine PRs #2545 and #2546)") == [3844]


def test_prose_row_word_and_split_sentences(capsys: pytest.CaptureFixture[str]) -> None:
    title = "Fix it (BACKLOG #1611)"
    assert oa.parse_prose("For the Lander: please flip row 3844.", title)[0] == (3844,)
    assert oa.parse_prose("Lander: BACKLOG #3844 ships here. Please flip it.", title)[0] == (3844,)


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
    assert "file 2 row(s)" in out and "OWED" in out


@pytest.mark.parametrize(
    "body", ["Lander b58f86: flip #3844 is owed.", "Lander (local_7289): flip #3844 is owed."]
)
def test_the_landers_own_prefixes_are_skipped(body: str) -> None:
    assert oa.parse_prose(body) is None
