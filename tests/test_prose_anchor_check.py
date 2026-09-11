# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A new bare ``path:line`` in the ledger must be refused, and a located one must not be (#1315).

Every test here is one half of a PAIR, and for this gate the pairing is not a style: a rule that
refused every ``path:line`` would be satisfied by banning line numbers, which is not what the row
asks for. The row's criterion GRADES a citation -- *"can something else in the sentence find the line
again"* -- and applying it across five seats turned raw counts of 68, 8 and 3 into naked counts of
24, 1 and 1. So each must-fire arm below has a twin that differs only in the locator.

THE DIFF SCOPE IS TESTED THROUGH A REAL REPO WITH REAL COMMITS, not a stubbed diff. The property
being pinned is "this can only be red about a line the change WROTE", and a fake diff would test the
parser instead of that property -- the shape BACKLOG #1525 records as a fixture that structurally
cannot hold the defect.

THE MEASUREMENT RULES THE ROW BOUGHT THE HARD WAY ARE OBSERVED HERE TOO. A zero needs a POSITIVE
control, and the control must sit in the SAME CORPUS as the test: every must-not-fire arm below runs
against a ledger whose twin arm has already been shown to fire.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CHECK = _ROOT / "scripts" / "docs" / "prose_anchor_check.py"


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("_prose_anchor_check", _CHECK)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------------------------------------
# The criterion.
# ------------------------------------------------------------------------------------------------


def test_a_bare_path_line_is_naked() -> None:
    """MUST FIRE. The row's own example of the shape that outlives nothing."""
    examined, naked = _load().scan_text("`durability_push.sh:80` also carries the bare form.\n")
    assert examined == 1
    assert len(naked) == 1
    assert naked[0].citation.strip("`") == "durability_push.sh:80"


def test_a_citation_whose_sentence_names_a_symbol_is_located() -> None:
    """MUST NOT FIRE -- the twin, differing only by the backticked symbol. A symbol survives the line
    moving, and stops resolving when the code changes under it, which is the right failure."""
    examined, naked = _load().scan_text(
        "`messagefoundry/config/settings.py:1520` requires `require_time_sync`.\n"
    )
    assert examined == 1
    assert naked == []


def test_a_citation_whose_sentence_pins_a_commit_is_located() -> None:
    """MUST NOT FIRE -- the other twin. The WHEN half: pin the base you read against."""
    examined, naked = _load().scan_text("Read `pkg/mod.py:80` at `817db9651`.\n")
    assert examined == 1
    assert naked == []


def test_a_prose_word_near_a_citation_does_not_count_as_a_locator() -> None:
    """MUST FIRE. `client` is prose as often as it is a symbol, and admitting it would let any
    backticked word satisfy the gate -- the naive matcher the sibling detector already rejected.

    This is why the symbol test is IMPORTED from citation_line_check rather than written again: two
    definitions of "a symbol" would let a citation satisfy this gate with a token the drift detector
    will not associate with it."""
    _, naked = _load().scan_text("The `client` reads `pkg/mod.py:80` on startup.\n")
    assert len(naked) == 1


def test_a_line_carrying_no_citation_is_not_examined() -> None:
    """MUST NOT FIRE, and the denominator must say so. A gate that examined nothing and one that
    examined everything cleanly must not render alike."""
    examined, naked = _load().scan_text(
        "An ordinary sentence about `settings.py` and nothing else.\n"
    )
    assert (examined, naked) == (0, [])


def test_the_scope_limits_findings_to_the_lines_a_change_added() -> None:
    """The whole reason this can be wired at all. Line 1 is naked and out of scope; line 3 is naked
    and in it. A gate that ignored scope would be red on day one over thousands of pre-existing
    citations and would be deleted, which is the failure backlog_citation_check.py records."""
    text = "Old `a/one.py:10` here.\n\nNew `a/two.py:20` here.\n"
    examined, naked = _load().scan_text(text, scope={3})
    assert examined == 1
    assert [hit.citation.strip("`") for hit in naked] == ["a/two.py:20"]


# ------------------------------------------------------------------------------------------------
# The gate, driven end to end through a real repository.
# ------------------------------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, timeout=60
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway repo whose ledger already carries a naked citation on its BASE commit.

    THE PRE-EXISTING NAKED CITATION IS THE POINT OF THE FIXTURE, not scenery: without one, "the gate
    passed" and "the gate only looks at added lines" are indistinguishable.
    """
    r = tmp_path / "r"
    (r / "docs").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    (r / "docs" / "BACKLOG.md").write_text(
        "## 1. a row\n\nInherited `pkg/old.py:11` with nothing to find it by.\n", encoding="utf-8"
    )
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


def _amend_ledger(repo: Path, added: str) -> tuple[str, str]:
    base = _git(repo, "rev-parse", "HEAD").strip()
    ledger = repo / "docs" / "BACKLOG.md"
    ledger.write_text(ledger.read_text(encoding="utf-8") + added, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "change")
    return base, _git(repo, "rev-parse", "HEAD").strip()


def test_the_gate_refuses_a_bare_citation_the_change_added(repo: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """MUST FIRE, end to end. This is the deliberate-failure proof: without it, a green leg is
    indistinguishable from a leg that cannot see the class it was wired for."""
    base, head = _amend_ledger(repo, "\nA new claim at `pkg/new.py:42`.\n")
    rc = _load().main(["--base", base, "--head", head, "--root", str(repo)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "pkg/new.py:42" in out
    assert "carries no locator" in out


def test_the_gate_passes_the_same_citation_with_a_symbol(repo: Path) -> None:
    """MUST NOT FIRE -- the twin of the arm above, one fixture, one variable: the added sentence."""
    base, head = _amend_ledger(repo, "\nA new claim at `pkg/new.py:42` about `_do_the_thing`.\n")
    assert _load().main(["--base", base, "--head", head, "--root", str(repo)]) == 0


def test_the_gate_is_silent_about_the_naked_citation_it_inherited(repo: Path) -> None:
    """MUST NOT FIRE, and this is the arm that makes the gate deployable at all.

    The base commit's ledger carries a naked citation. A change that touches an unrelated line must
    not be refused for it -- diff scope is what stops 3,001 pre-existing occurrences from making this
    red for everyone on day one.
    """
    base, head = _amend_ledger(repo, "\nAn unrelated sentence with no citation in it.\n")
    assert _load().main(["--base", base, "--head", head, "--root", str(repo)]) == 0


def test_a_change_touching_no_ledger_line_is_out_of_scope(repo: Path) -> None:
    """MUST NOT FIRE. Most changes never touch the ledger, and the gate must cost them nothing."""
    base = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "unrelated.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "elsewhere")
    head = _git(repo, "rev-parse", "HEAD").strip()
    assert _load().main(["--base", base, "--head", head, "--root", str(repo)]) == 0


# ------------------------------------------------------------------------------------------------
# It cannot report clean for the wrong reason.
# ------------------------------------------------------------------------------------------------


def test_one_side_of_the_diff_scope_alone_is_refused() -> None:
    """`--base` with no `--head` would otherwise silently fall through to the census, which exits 0.
    A gate that turns a mistyped invocation into a pass is the class this repository keeps finding."""
    assert _load().main(["--base", "HEAD"]) == 2


def test_an_unreadable_ledger_refuses_rather_than_reporting_clean(tmp_path: Path) -> None:
    """A census over a root with no ledger must not print a reassuring zero -- the same refusal
    citation_line_check and banner_sha_check make, for the same reason."""
    assert _load().main(["--root", str(tmp_path)]) == 2


def test_the_census_never_gates_and_says_so(capsys) -> None:  # type: ignore[no-untyped-def]
    """Over the real ledger, which carries thousands of naked citations. The census reports and
    exits 0 on purpose: the corpus retrofit is explicitly NOT what this gate does, and an exit code
    that implied otherwise would invite exactly the bulk rewrite BACKLOG #1315 bounds away."""
    rc = _load().main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "census over docs/BACKLOG.md" in out
    assert "not a gate" in out
    # POSITIVE CONTROL, in the same corpus as the assertion: a run that parsed nothing would also
    # print a census line, and its zero would read exactly like a clean one.
    occurrences = int(out.split("--")[1].split("path:line")[0].strip())
    assert occurrences > 100, (
        f"the census found only {occurrences} citations in the real ledger, so its counts are not "
        "measuring the corpus this gate is about"
    )


# ------------------------------------------------------------------------------------------------
# The wiring. A working detector that runs nowhere is BACKLOG #1525's whole subject, and this file
# is not going to add a fourth.
# ------------------------------------------------------------------------------------------------

_WORKFLOW = "backlog-hygiene.yml"
_JOB = "prose-anchor"
_SCRIPT = "scripts/docs/prose_anchor_check.py"


def test_the_checker_is_actually_invoked_by_a_workflow() -> None:
    """Naming a tool's TEST in ci.yml is not wiring the TOOL -- the distinction BACKLOG #1525 is
    about. Assert the `run:` line, in the job, not the string anywhere in the file."""
    from tests._workflow_contexts import jobs_of  # noqa: PLC0415

    jobs = jobs_of(_WORKFLOW)
    assert _JOB in jobs, f"{_WORKFLOW} has no {_JOB!r} job"
    invocations = [
        line
        for step in jobs[_JOB]["steps"]
        for line in (step.get("run") or "").splitlines()
        if _SCRIPT in line
    ]
    assert len(invocations) == 1, f"expected one line running {_SCRIPT}, found {invocations}"
    assert "--base" in invocations[0] and "--head" in invocations[0], (
        f"{_JOB} must invoke the checker in DIFF SCOPE. Without --base/--head it falls through to "
        f"the census, which exits 0 over a corpus of thousands: {invocations[0].strip()!r}"
    )


def test_the_job_reports_its_own_context_and_does_not_ride_the_required_one() -> None:
    """THE DECISION THIS TEST EXISTS TO HOLD. The sibling job's `name:` is a required status-check
    context, so a step added there blocks a merge the moment it lands -- and making a check BLOCK is
    the owner's call, not a Builder's. Keep this in its own job with its own context.
    """
    from tests._workflow_contexts import context_of, jobs_of, required_contexts  # noqa: PLC0415

    jobs = jobs_of(_WORKFLOW)
    required = set(required_contexts())
    assert "a PR that implements BACKLOG #N must update BACKLOG.md" in required, (
        "positive control failed: the required set no longer names the sibling hygiene context, so "
        "this test is not reading the file it believes it is"
    )
    for key, job in jobs.items():
        if key == _JOB:
            continue
        bodies = "\n".join(step.get("run") or "" for step in job["steps"])
        assert _SCRIPT not in bodies, (
            f"{_SCRIPT} also runs in job {key!r}, whose context is {context_of(key, job)!r}. If that "
            "context is required, this check began gating merges without anyone deciding it should."
        )
    assert context_of(_JOB, jobs[_JOB]) not in required, (
        "this job is not in branch protection, so naming it in .github/required-contexts.txt is the "
        "lie that file exists to prevent. Add it to the server FIRST (BACKLOG #1315)."
    )


def test_the_job_can_actually_go_red() -> None:
    """A finding here is actionable by the author in the diff under review -- name a symbol or pin a
    commit -- which is what separates a check worth reddening from one that must be advisory. A
    `continue-on-error` or a `|| true` would leave a job that reports success whatever it finds."""
    from tests._workflow_contexts import jobs_of  # noqa: PLC0415

    for step in jobs_of(_WORKFLOW)[_JOB]["steps"]:
        assert step.get("continue-on-error") is not True, f"{step.get('name')!r} cannot fail"
        assert "|| true" not in (step.get("run") or ""), f"{step.get('name')!r} swallows its status"
