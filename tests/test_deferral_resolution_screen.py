# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The deferral screen must fire on a settled-but-still-declared row and on nothing else (#1527).

Every behaviour test is one half of a PAIR. The clause words this screen keys on -- ``gated on``,
``pending``, ``awaiting`` -- are ordinary English in a ledger that is largely ABOUT deferrals, so a
suite of must-fire arms alone would be satisfied by the bare-word version the region narrowing exists
to replace.

**The false-positive arms are measured, not imagined.** Each was found on the live ledger while
building the screen:

* #1527 -- the item that FILED this defect -- quotes the defect's own shape in its body.
* #1242's ``**Severity:**`` sentence reads *"the loss is pending on the next routine operation"*, and
  it sits on the line directly after that row's Verdict. A paragraph-wide capture pulled it in and
  reported the row as deferred.
* #1494's banner block QUOTES its own Verdict while closing the row out. Reading the banner's prose
  would make every closed-out deferral fire on its own obituary.

The wiring half of this file pins that the screen REPORTS and cannot GATE. Making a check run is a
Builder's call; making one block a merge is the owner's (CLAUDE.md section 5). Each absence assertion
there carries a POSITIVE CONTROL first -- "this string is not in that list" and "that list is empty
because the parser broke" produce the identical green, and a test whose only reachable outcome is
success is not a test.

ONE FILE, WHERE THE SIBLING VERDICT CHECK USES TWO. The behaviour arms and the wiring arms are kept
together because ``tests/tooling_manifest.txt`` must list every new tooling test by name in the same
commit, and a second file is a second chance to forget that. The section rule below is the
substitute: the two halves never share a fixture.
"""

from __future__ import annotations

import datetime
import functools
import importlib.util
from pathlib import Path

from tests._workflow_contexts import context_of, jobs_of, required_contexts

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = "scripts/docs/deferral_resolution_screen.py"
_CHECK = _ROOT / _SCRIPT
_REGISTER_DOC = _ROOT / "docs" / "DEFERRAL-RESOLUTIONS.md"
_WORKFLOW_NAME = "quality-advisory.yml"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_PRE_COMMIT = _ROOT / ".pre-commit-config.yaml"

#: The job key added by BACKLOG #1527.
_JOB = "deferral-resolution"

#: The four measurement jobs the liveness meta-gate rules on. No ledger-hygiene job is among them.
_LIVENESS_MEASUREMENT_JOBS = {"complexity", "clone", "coverage", "mutation"}

OPEN = "\U0001f522"  # the OPEN status banner glyph, quoted as a token per CLAUDE.md section 11
CLOSED = "\u2705"  # and the CLOSED one, escaped for the same reason

TODAY = datetime.date(2026, 9, 10)


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("_deferral_resolution_screen", _CHECK)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ledger(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "LEDGER.md"
    p.write_text(body, encoding="utf-8", newline="")
    return p


def _register(tmp_path: Path, *rows: str) -> Path:
    p = tmp_path / "REGISTER.md"
    head = "| date | key | resolution | authority | sources |\n| --- | --- | --- | --- | --- |\n"
    p.write_text(head + "".join(row + "\n" for row in rows), encoding="utf-8", newline="")
    return p


def _seeded(tmp_path: Path) -> Path:
    """A register carrying the one ruling this item was filed from."""
    return _register(
        tmp_path,
        "| 2026-09-10 | adr-0056-privileged-helper | the pause is lifted | owner | #1494 |",
    )


# --------------------------------------------------------------------------------------------
# The needle: what a deferral IS.
# --------------------------------------------------------------------------------------------


def test_a_prose_verdict_deferring_to_a_condition_is_reported(tmp_path: Path) -> None:
    """MUST FIRE. The measured shape, quoted from #1494's Verdict verbatim."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.** Value 6/10.\r\n\r\n"
        "**Cluster:** ha. **Priority:** P2. **Verdict:** build slice 1;\r\n"
        "leave the VIP mechanism gated on the owner's privileged-helper decision.\r\n"
        "**Severity:** no deployment axis.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert len(r.deferrals) == 1, r
    d = r.deferrals[0]
    assert d.item == 500
    assert d.clause == "gated on"
    assert d.source == "prose verdict"
    assert d.ruling is None, "no ruling key, so nothing to join"


def test_the_SEVERITY_sentence_after_a_verdict_is_not_read_as_the_verdict(tmp_path: Path) -> None:
    """MUST NOT FIRE, AND THIS ARM IS A MEASURED REGRESSION.

    #1242's Verdict is the single word ``build``. The line directly after it reads *"the loss is
    **pending on** the next routine operation"* -- correct prose in a ``**Severity:**`` sentence. A
    paragraph-wide capture pulled it into the verdict and reported a plain build row as deferred.
    """
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.** Value 6/10.\r\n\r\n"
        "**Cluster:** vault. **Priority:** P1. **Verdict:** build.\r\n"
        "**Severity:** no deployment axis. P1 because the loss is pending on the next routine "
        "operation.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert r.deferrals == [], "the region must end at the next bold key, not at the paragraph"
    assert r.with_verdict == 1, "the row must still be COUNTED -- it carries a Verdict"


def test_an_item_DOCUMENTING_the_deferral_shape_does_not_fire(tmp_path: Path) -> None:
    """MUST NOT FIRE, AND THE LIVE INSTANCE IS THIS ITEM ITSELF.

    #1527 filed the defect and quotes its shape in its own body -- *"leave X gated on the owner's
    decision about Y"*. To a bare-word matcher the row that DOCUMENTS the pattern reads as governed
    by it, which is the same landmine the sibling verdict check records.
    """
    led = _ledger(
        tmp_path,
        f"## 500. a Verdict that defers records the condition and never the resolution\r\n\r\n"
        f"> {OPEN} **Filed 2026-09-10.** Value 6/10.\r\n\r\n"
        "**Cluster:** ledger hygiene. **Priority:** P2. **Verdict:** build.\r\n\r\n"
        "A row whose Verdict defers to an owner decision -- *\"leave X gated on the owner's "
        'decision about Y"* -- records the CONDITION and nothing records the RESOLUTION.\r\n',
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert r.deferrals == [], "a clause in the body is prose; only the Verdict statement declares"


def test_a_banner_block_QUOTING_its_own_verdict_does_not_fire(tmp_path: Path) -> None:
    """MUST NOT FIRE. #1494's closing banner quotes the Verdict it is closing out. Reading the
    banner's prose would make every settled deferral fire on its own obituary."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n"
        f'> {OPEN} **Filed 2026-09-01.** The Verdict says *"leave the VIP mechanism gated on the '
        "owner's privileged-helper decision\"*, and that deferral has no pending condition left.\r\n"
        "> Verdict: build\r\n\r\n"
        "**Cluster:** ha. **Priority:** P2. **Verdict:** build.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert r.deferrals == []


def test_a_banner_verdict_of_owner_ruling_is_itself_a_deferral(tmp_path: Path) -> None:
    """MUST FIRE. ``Verdict: owner-ruling`` says the whole row waits on a decision. That is the
    machine-readable half of the population, and it needs no clause."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-08-31.** Value 4/10.\r\n"
        "> Verdict: owner-ruling\r\n\r\n**Cluster:** x. **Priority:** P3.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert len(r.deferrals) == 1
    assert r.deferrals[0].source == "banner verdict"
    assert r.deferrals[0].clause == "owner-ruling"


def test_a_closing_act_of_owner_ruling_is_a_DIFFERENT_population(tmp_path: Path) -> None:
    """MUST NOT FIRE, AND IT IS THE ANSWER TO THE ITEM'S THIRD QUESTION.

    ``Closing-act: owner-ruling`` says the act that CLOSES the row is a ruling. It does not say the
    row is waiting: 33 open rows carry it against 8 carrying ``Verdict: owner-ruling``, and one of
    them (#3) is a perfectly workable demand-gate row. Folding the two together would put 33 rows in
    a report whose defect class holds a handful.
    """
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-08-31.** Value 4/10.\r\n"
        "> Verdict: demand-gate\r\n> Closing-act: owner-ruling\r\n\r\n"
        "**Cluster:** x. **Priority:** P3. **Verdict:** demand-gate.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert r.deferrals == []


def test_a_CLOSED_row_declaring_a_deferral_is_not_compared(tmp_path: Path) -> None:
    """MUST NOT FIRE. A closed row's deferral is settled by the closure; reporting it would flood
    the screen with resolved history and train its reader to skim."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {CLOSED} **CLOSED 2026-09-05.**\r\n\r\n"
        "**Cluster:** ha. **Verdict:** leave it gated on the owner's decision.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert r.deferrals == [] and r.open_items == 0


# --------------------------------------------------------------------------------------------
# The join, and the age.
# --------------------------------------------------------------------------------------------


def test_a_deferral_whose_key_the_register_records_is_reported_as_settled(tmp_path: Path) -> None:
    """MUST FIRE. THE WHOLE POINT: the condition is settled and the row still says it is waiting."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.** Value 6/10.\r\n\r\n"
        "**Cluster:** ha. **Verdict:** build slice 1; leave the VIP mechanism gated on the owner's "
        "privileged-helper decision [ruling-key: adr-0056-privileged-helper].\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert len(r.stale) == 1, r
    assert r.stale[0].key == "adr-0056-privileged-helper"
    assert r.stale[0].ruling is not None
    assert r.stale[0].ruling.date == "2026-09-10"


def test_a_banner_verdict_ANNOTATED_with_a_key_is_still_read_as_owner_ruling(
    tmp_path: Path,
) -> None:
    """MUST FIRE, AND WITHOUT THIS THE BANNER POPULATION IS UNJOINABLE.

    ``backlog_status_check._FIELD`` captures the whole rest of the banner line, so the value comes
    back as ``owner-ruling [ruling-key: x]``. Compared raw that fails the vocabulary equality and
    the row is not seen as a deferral AT ALL -- which is worse than merely failing to join, because
    the key search sitting next to it would look like it handled the case.
    """
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-08-31.** Value 4/10.\r\n"
        "> Verdict: owner-ruling [ruling-key: adr-0056-privileged-helper]\r\n\r\n"
        "**Cluster:** x. **Priority:** P3.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert len(r.deferrals) == 1, r
    assert r.deferrals[0].source == "banner verdict"
    assert len(r.stale) == 1, "the annotated banner row must reach the join"


def test_a_key_the_register_does_not_record_stays_merely_OPEN(tmp_path: Path) -> None:
    """MUST NOT FIRE -- the twin of the arm above, differing only in the key.

    A pair, because either arm alone is satisfiable by the wrong implementation: a join that always
    matches passes the first, a join that never matches passes the second.
    """
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.** Value 6/10.\r\n\r\n"
        "**Cluster:** ha. **Verdict:** leave it gated on the owner's decision "
        "[ruling-key: some-condition-nobody-has-ruled-on].\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert len(r.deferrals) == 1 and len(r.keyed) == 1
    assert r.stale == [], "an unrecorded condition is still genuinely pending"


def test_the_age_is_a_floor_from_the_banners_earliest_date(tmp_path: Path) -> None:
    """The Verdict statement carries no date, so the age is the FILING floor -- the row has declared
    this deferral for at least that long. The earliest banner date wins, not the newest re-score."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Re-scored 2026-09-08.** Value 6/10.\r\n"
        f"> **Filed 2026-08-01.**\r\n\r\n"
        "**Cluster:** ha. **Verdict:** leave it gated on the owner's decision.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert r.deferrals[0].since == "2026-08-01"
    assert r.deferrals[0].age_days == 40


def test_an_undated_banner_is_reported_as_undated_not_dropped(tmp_path: Path) -> None:
    """A deferral with no date is still a deferral. Dropping it would narrow the population with
    nothing saying so, which is this item's own defect reproduced inside its fix."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed.** Value 6/10.\r\n\r\n"
        "**Cluster:** ha. **Verdict:** leave it gated on the owner's decision.\r\n",
    )
    r = _load().scan(led, _seeded(tmp_path), TODAY)
    assert len(r.deferrals) == 1
    assert r.deferrals[0].since is None and r.deferrals[0].age_days is None


def test_a_register_row_with_a_broken_date_is_reported_not_dropped(tmp_path: Path) -> None:
    """Same reasoning one level down: a silently dropped register row takes a real resolution out of
    the join, so the screen would report a settled condition as pending and look correct doing it."""
    reg = _register(
        tmp_path,
        "| 2026-09-10 | good-key | settled | owner | #1494 |",
        "| last tuesday | bad-key | settled | owner | #1494 |",
    )
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.**\r\n\r\n"
        "**Cluster:** ha. **Verdict:** gated on x [ruling-key: bad-key].\r\n",
    )
    r = _load().scan(led, reg, TODAY)
    assert r.rulings == 1
    assert len(r.malformed_register_rows) == 1
    assert r.stale == [], "the malformed row must not silently resolve anything"


def test_the_shipped_register_parses_and_carries_the_seed_ruling() -> None:
    """The register ships seeded, and the screen REFUSES an empty one. If this file stops parsing,
    the advisory job goes red rather than reporting a clean tree over a dead join."""
    rulings, malformed = _load().read_register(_REGISTER_DOC)
    assert malformed == [], f"the shipped register has malformed rows: {malformed}"
    assert [r.key for r in rulings] == ["adr-0056-privileged-helper"], rulings


# --------------------------------------------------------------------------------------------
# Exit codes: a FINDING is suppressible, a MALFUNCTION is not.
# --------------------------------------------------------------------------------------------


def test_a_settled_row_exits_1_by_default_and_0_under_advisory(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """BOTH ARMS ON ONE LEDGER, because either alone is satisfiable by the wrong implementation.

    A flag that always returns 0 passes the advisory arm; a flag that is never read passes the
    default arm. Only the pair pins that ``--advisory`` is what moved the code.
    """
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.**\r\n\r\n"
        "**Cluster:** ha. **Verdict:** gated on the helper decision "
        "[ruling-key: adr-0056-privileged-helper].\r\n",
    )
    args = ["--backlog", str(led), "--register", str(_seeded(tmp_path)), "--today", "2026-09-10"]
    mod = _load()

    assert mod.main(args) == 1, "the default must still fail on a settled-but-declared row"
    default_out = capsys.readouterr().out

    assert mod.main([*args, "--advisory"]) == 0, "--advisory must report, not fail"
    advisory_out = capsys.readouterr().out

    # The finding is REPORTED either way. A flag that quiets the output as well as the exit code
    # would make an advisory job green AND silent, which is the failure the wiring exists to avoid.
    for out in (default_out, advisory_out):
        assert "SETTLED CONDITIONS STILL DECLARED AS PENDING" in out
        assert "#500" in out
        # ONE ROW, ONE CLASS. A settled row listed under OPEN DEFERRALS as well would make a reader
        # counting findings count it twice, and conflates the two classes the module separates.
        assert "OPEN DEFERRALS" not in out, (
            "the only deferral here is settled, so the open list must not be printed at all"
        )


def test_a_ledger_with_no_verdict_statements_is_refused_in_BOTH_modes(
    tmp_path: Path, capsys
) -> None:  # type: ignore[no-untyped-def]
    """A parse that yields nothing must not render as agreement, and ``--advisory`` must not hide it.

    ``0 open items ... 0 deferrals`` is what a broken ``parse_items``, a renamed statement marker or
    the wrong file looks like, and it exits 0 printing OK. That green is a statement about the
    INSTRUMENT, not the ledger.

    THE SECOND ARM IS THE PROPERTY THE ADVISORY WIRING RESTS ON. ``--advisory`` downgrades a FINDING;
    if it also downgraded a malfunction, the workflow's re-raised status could never be non-zero and
    the job could not tell a clean scan from one that read nothing.
    """
    led = _ledger(tmp_path, "no headings here, so no items at all\r\n")
    reg = str(_seeded(tmp_path))
    mod = _load()

    assert mod.main(["--backlog", str(led), "--register", reg]) == 2
    assert "refusing" in capsys.readouterr().err.lower()
    assert mod.main(["--backlog", str(led), "--register", reg, "--advisory"]) == 2, (
        "--advisory suppresses a finding, never a malfunction"
    )


def test_an_empty_register_is_refused_rather_than_reported_clean(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """With nothing to join against, every deferral reads as unresolved and the screen prints OK
    forever -- a green describing the parse rather than the ledger. Refuse instead."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.**\r\n\r\n"
        "**Cluster:** ha. **Verdict:** gated on x.\r\n",
    )
    empty = _register(tmp_path)
    assert _load().main(["--backlog", str(led), "--register", str(empty), "--advisory"]) == 2
    assert "empty register" in capsys.readouterr().err.lower()


def test_a_missing_file_on_either_side_is_refused_under_advisory_too(tmp_path: Path) -> None:
    """Reporting nothing must never render as reporting no findings -- on either input."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.**\r\n\r\n**Verdict:** build.\r\n",
    )
    mod = _load()
    assert mod.main(["--backlog", str(tmp_path / "nope.md"), "--advisory"]) == 2
    assert (
        mod.main(["--backlog", str(led), "--register", str(tmp_path / "nope.md"), "--advisory"])
        == 2
    )


def test_the_summary_reports_every_denominator(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """A clean run must say how many rows it examined, aged and JOINED. Without the keyed count a
    run that joined nothing reads exactly like one that joined everything and found nothing."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {OPEN} **Filed 2026-09-01.**\r\n\r\n"
        "**Cluster:** ha. **Verdict:** gated on x.\r\n",
    )
    rc = _load().main(
        ["--backlog", str(led), "--register", str(_seeded(tmp_path)), "--today", "2026-09-10"]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 open item(s)" in out
    assert "DECLARE A DEFERRAL and were aged" in out
    assert "name a ruling key" in out
    assert "none of the 1 deferral(s) names a ruling key" in out, (
        "zero adoption makes the join inert and must be said out loud, not left to the OK line"
    )


# --------------------------------------------------------------------------------------------
# The wiring: it RUNS, and it cannot GATE.
# --------------------------------------------------------------------------------------------


@functools.cache
def _jobs() -> dict:
    """The workflow's jobs, parsed ONCE per module.

    ``_workflow_contexts.load_workflow`` is not memoised -- only ``_reportable_contexts`` is -- and
    ``yaml.safe_load`` on this 75 KB file measures 23 ms, which the wiring arms below would pay
    seven times over. Nothing in this suite writes into ``.github/workflows``, so the cache cannot
    serve a stale answer. Callers must not mutate what they get back.
    """
    return jobs_of(_WORKFLOW_NAME)


def _analysis_step() -> dict:
    """The one step in the deferral job that invokes the screen."""
    jobs = _jobs()
    assert _JOB in jobs, (
        f"{_WORKFLOW_NAME} has no {_JOB!r} job -- re-point this guard rather than letting it pass"
    )
    steps = [step for step in jobs[_JOB]["steps"] if _SCRIPT in (step.get("run") or "")]
    assert len(steps) == 1, (
        f"expected exactly 1 step in {_JOB!r} invoking {_SCRIPT}, found {len(steps)}"
    )
    return steps[0]


def test_the_screen_exists_at_the_path_the_workflow_names() -> None:
    """A workflow naming a script that is not in the repo fails at run time, not at review time."""
    assert _CHECK.is_file(), f"{_WORKFLOW_NAME} references a missing script: {_SCRIPT}"
    assert _REGISTER_DOC.is_file(), "the register the screen joins against is not in the repo"


def test_exactly_one_workflow_invokes_the_screen_and_it_is_the_advisory_one() -> None:
    """Pin WHERE it runs, not merely THAT it runs. Added to a workflow holding a required context,
    this screen would begin failing merges on a question nobody has ruled on.

    THE CONTROL GUARDS A CASE THE EQUALITY CANNOT. An EMPTY result already fails loudly. What passes
    silently is a TRUNCATED corpus: a glob resolving to this one file alone satisfies the equality
    having examined nothing else.
    """
    texts = {path.name: path.read_text(encoding="utf-8") for path in _WORKFLOWS.glob("*.yml")}
    control = sorted(n for n, t in texts.items() if "scripts/quality/liveness.py" in t)
    assert _WORKFLOW_NAME in control and len(control) > 1, (
        f"positive control failed: scripts/quality/liveness.py resolves to {control}. It must "
        f"include {_WORKFLOW_NAME} AND at least one other workflow, or this probe is reading a "
        "truncated corpus and the equality below means nothing."
    )
    invoking = sorted(name for name, text in texts.items() if _SCRIPT in text)
    print(f"[deferral-resolution] workflows invoking {_SCRIPT}: {invoking}")
    assert invoking == [_WORKFLOW_NAME], (
        f"{_SCRIPT} must be invoked by {_WORKFLOW_NAME} alone (it holds no required context); "
        f"found it in {invoking}. Wiring it into another workflow is an owner decision."
    )


def test_the_screen_is_not_in_a_commit_refusing_hook() -> None:
    """A pre-commit hook REFUSES the commit, which is blocking by another name."""
    text = _PRE_COMMIT.read_text(encoding="utf-8")
    assert "scripts/hooks/ledger_check.py" in text, (
        "positive control failed: .pre-commit-config.yaml no longer names the ledger gate, so this "
        "file is not the hook config this test believes it is reading"
    )
    assert _SCRIPT not in text, (
        f"{_SCRIPT} is wired into .pre-commit-config.yaml, which refuses a commit. Promoting this "
        f"screen to blocking is an owner decision (BACKLOG #1527)."
    )


def test_the_analysis_step_cannot_fail_its_job() -> None:
    """Without this, the screen's empty-population refusal -- what a dead ``parse_items`` looks like
    -- would fail the job, and the job would be a gate nobody approved."""
    step = _analysis_step()
    assert step.get("continue-on-error") is True, (
        f"{_JOB}/{step.get('name')!r} runs the screen without continue-on-error: true"
    )


def test_the_screen_is_invoked_in_advisory_mode() -> None:
    """ASSERTED ON THE INVOCATION LINE, NOT ANYWHERE IN THE BODY. The sibling citation guard learned
    this the expensive way: its first version asked whether ``--advisory`` appeared in the step at
    all, and it DID -- in the step's own warning message -- so deleting the flag left it green."""
    body = _analysis_step()["run"]
    invocations = [line for line in body.splitlines() if _SCRIPT in line]
    assert len(invocations) == 1, (
        f"expected one line invoking {_SCRIPT} in {_JOB}, found {len(invocations)}: {invocations}"
    )
    assert "--advisory" in invocations[0], (
        f"{_JOB} invokes {_SCRIPT} without --advisory on the command itself, so a finding would "
        f"exit 1 and this job would gate: {invocations[0].strip()!r}"
    )


def test_a_broken_scan_stays_visible_rather_than_being_swallowed() -> None:
    """``|| true`` on the invocation would make a REFUSAL and a CLEAN SCAN render identically."""
    body = _analysis_step()["run"]
    invocation = next(line for line in body.splitlines() if _SCRIPT in line)
    assert "|| true" not in invocation, (
        "swallowing the exit code makes a scan that read nothing look like a clean one"
    )
    assert 'exit "$TOOL_STATUS"' in body, (
        "the step must re-raise the screen's status so a malfunction shows as a red step inside "
        "the green job"
    )


def test_the_job_cannot_redden_the_liveness_meta_gate() -> None:
    """``liveness`` is the one job in this workflow built to go red."""
    liveness = _jobs()["liveness"]
    needs = set(liveness["needs"])
    assert needs == _LIVENESS_MEASUREMENT_JOBS, (
        f"liveness needs {sorted(needs)}; expected {sorted(_LIVENESS_MEASUREMENT_JOBS)}"
    )
    assert _JOB not in needs


def test_no_job_in_this_workflow_is_a_claimed_required_context() -> None:
    """HONEST LIMIT: branch protection lives on the server and this asserts the CLAIM, not the
    server. The positive control makes the absence meaningful."""
    required = required_contexts()
    assert "cla" in required and len(required) >= 10, (
        f"positive control failed: required_contexts() returned {len(required)} entries and did not "
        "include the known-required 'cla', so its absence findings prove nothing"
    )
    jobs = _jobs()
    assert _JOB in jobs, f"{_WORKFLOW_NAME} no longer declares {_JOB!r}"
    declared = {context_of(key, job) for key, job in jobs.items()}
    overlap = declared & set(required)
    print(
        f"[deferral-resolution] {len(declared)} contexts in {_WORKFLOW_NAME}, "
        f"{len(required)} required"
    )
    assert not overlap, (
        f"{_WORKFLOW_NAME} is advisory by design and must never be promoted, but "
        f"{sorted(overlap)} appears in .github/required-contexts.txt"
    )


def test_the_job_needs_no_git_history() -> None:
    """THE DEAD-GATE SHAPE THIS WORKFLOW HAS PRODUCED THREE TIMES, pinned from the other side.

    diff-coverage died for months because a shallow clone destroyed its merge base and the empty
    report looked clean. This screen reads two TRACKED FILES and no history, so the default shallow
    checkout is correct -- but "correct" and "nobody checked" render the same, so the claim is
    asserted: no git command in the step body, and no fetch-depth on its checkout.
    """
    job = _jobs()[_JOB]
    body = _analysis_step()["run"]
    assert "git " not in body and "git\n" not in body, (
        "this screen must read tracked files only -- a git command here would need fetch-depth: 0"
    )
    checkout = next(s for s in job["steps"] if "checkout" in (s.get("uses") or ""))
    assert "fetch-depth" not in (checkout.get("with") or {}), (
        "no history is read, so requesting a full clone would buy nothing and slow every run"
    )
