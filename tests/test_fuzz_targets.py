# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The fuzz-target harness (ADR 0191), driven under plain pytest rather than under Atheris.

Atheris ships Linux x86-64 wheels only and the fuzz job is one advisory Linux leg, so without this
file the harness would be exercised on exactly one platform by exactly one job that is allowed to
fail. That is the shape where a broken detector and a clean run look identical. These tests run on
every leg, Windows included, because ``fuzz/targets.py`` imports no Atheris.

The load-bearing tests here are the two fault-injection ones plus the accessor-coverage pin. A fuzz
harness that has never been shown to catch anything measures nothing, so instead of trusting that a
raised exception would be noticed, the injection tests raise one and assert it escapes -- including
the case that a narrowed known-finding carve-out must **not** swallow. Both of those fault
``Peek.routing``, so between them they pinned ``routing()`` and nothing else;
``test_the_hl7_target_reads_every_named_routing_property`` covers the eleven named routing accessors
the sweep drives, which the rest of this file could not see the loss of. A third injection test pins
the carve-out's exception TYPE, which the first two could not reach.

**"The eleven pre-ACK accessors" was the old wording here and it was wrong** -- seven of the eleven
are read pre-ACK, three are unique to this sweep, and the pre-ACK path reads several the list does
not name. ``fuzz/targets.py``'s module docstring carries the measured accounting; this file does not
restate it.
"""

from __future__ import annotations

import inspect
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Never

import pytest

from fuzz.targets import (
    _HL7_ROUTING_PROPERTIES,
    _X12_ISA_PROPERTIES,
    DEFAULT_MAX_LEN,
    KNOWN_FINDINGS,
    TARGETS,
    TARGETS_BY_NAME,
    WORK_DIR_ENV,
    FuzzTarget,
    HarnessRefusal,
    libfuzzer_argv,
    work_paths,
    work_root,
    write_seed_corpus,
)
from messagefoundry.parsing import Peek
from messagefoundry.parsing.x12 import X12Peek
from tests._workflow_contexts import jobs_of

#: A conformant synthetic message with no blank segment -- the negative control for the carve-out.
CLEAN_ADT = (
    "MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\rPID|1||100001^^^HOSP^MR||DOE^JANE\r"
)

#: The routing accessors ``_hl7_peek`` must sweep, written out HERE rather than imported.
#:
#: **An independent copy is the whole point.** A test that imports the constant its subject iterates
#: cannot see that constant shrink: behaviour and expectation move together, and emptying it makes
#: the assertion pass over nothing. Measured -- see
#: ``test_the_hl7_target_reads_every_named_routing_property``. Changing the accessor tier is now a
#: deliberate two-file edit, which is the point rather than an inconvenience.
_EXPECTED_ROUTING_PROPERTIES = (
    "message_code",
    "trigger_event",
    "message_structure",
    "message_type",
    "control_id",
    "version",
    "sending_app",
    "sending_facility",
    "receiving_app",
    "receiving_facility",
    "timestamp",
)

#: The X12 ISA identity accessors ``_x12_peek`` must sweep. Own literal, same reasoning as above --
#: the HL7 sweep had no pin at all until recently and the X12 one had none either, so closing only
#: HL7 would leave a half-shut hole that reads as a shut one.
_EXPECTED_ISA_PROPERTIES = (
    "sender_qual",
    "sender_id",
    "receiver_qual",
    "receiver_id",
    "date",
    "time",
    "version",
    "control_number",
    "usage",
    "is_test",
)

#: Inputs a tolerant parser must survive without breaking its contract. Not a corpus -- just the
#: degenerate shapes that are cheapest to get wrong.
GARBAGE = (
    b"",
    b"\x00",
    b"\r\r\r",
    b"MSH",
    b"MSH|",
    b"MSH|^~\\&|",
    b"\xff\xfe\xfd\xfc",
    b"ISA*",
    b"DICM",
    b"MSH|^~\\&|A|B|C|D|1||ADT^A01|1|P|2.5\r" + b"\r" * 50,
)


def _boom(exc: BaseException) -> Callable[..., Never]:
    """A replacement accessor that raises ``exc`` -- the injected fault."""

    def raiser(*_args: object, **_kwargs: object) -> Never:
        raise exc

    return raiser


def test_the_registry_is_coherent() -> None:
    names = [target.name for target in TARGETS]
    assert names, "no fuzz targets registered"
    assert len(names) == len(set(names)), f"duplicate target names: {names}"
    assert set(TARGETS_BY_NAME) == set(names)
    for target in TARGETS:
        assert target.seeds, f"target {target.name} has no seeds to start libFuzzer from"
        assert target.summary, f"target {target.name} has no summary"


#: Targets that need no optional extra, so they can never be legitimately skipped.
#:
#: The two sweeps below ``continue`` past an unavailable target, which is right -- ``dicom_peek``
#: needs ``[dicom]`` and refusing to run the rest without it would be worse. But a bare ``continue``
#: makes "every target passed" and "no target ran" the same green, which is the exact confusion this
#: whole harness exists to remove. Asserting this floor was reached keeps the skip honest without
#: making an optional extra mandatory.
_ALWAYS_AVAILABLE = ("hl7_peek", "hl7_tree", "x12_peek")


def _exercise(run: Callable[[FuzzTarget], None]) -> None:
    """Drive ``run`` over every available target, then prove the sweep was not vacuous."""
    exercised: list[str] = []
    for target in TARGETS:
        if not target.available():
            continue
        run(target)
        exercised.append(target.name)

    missing = [name for name in _ALWAYS_AVAILABLE if name not in exercised]
    assert not missing, (
        f"{missing} reported themselves unavailable, but they need no optional extra. Read that as "
        "a broken import or a broken `available()` probe -- not as a legitimate skip. Without this "
        "check a run that exercised NOTHING would report the same green as a run that passed."
    )


def test_every_available_target_accepts_its_own_seeds() -> None:
    def _run(target: FuzzTarget) -> None:
        for seed in target.seeds:
            target.run(seed)  # must not raise: these are conformant synthetic inputs

    _exercise(_run)


def test_every_available_target_survives_degenerate_input() -> None:
    def _run(target: FuzzTarget) -> None:
        for data in GARBAGE:
            target.run(data)

    _exercise(_run)


def test_an_injected_non_contract_exception_escapes_the_hl7_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The detector works: a fault on an accessor propagates out of the target.

    This is the demonstration the harness rests on. libFuzzer records a crash when the target
    raises, so "does the harness notice a broken parser" reduces to "does an exception escape
    ``run``" -- which is exactly what this asserts, with no Atheris needed.
    """
    monkeypatch.setattr(Peek, "routing", _boom(KeyError("injected")))
    with pytest.raises(KeyError, match="injected"):
        TARGETS_BY_NAME["hl7_peek"].run(CLEAN_ADT.encode())


def test_an_index_error_without_a_blank_segment_is_not_suppressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The known-finding carve-out is narrow enough to still catch its own siblings.

    ``_hl7_peek`` swallows ``IndexError`` when the parsed message carries a blank segment, because
    that case is a filed, unfixed defect and an advisory job that is red on arrival gets ignored.
    The risk of any such carve-out is that it grows into a blanket suppression of the exception
    type. So: same exception, same target, message with **no** blank segment -- it must escape.
    """
    monkeypatch.setattr(Peek, "routing", _boom(IndexError("injected")))
    with pytest.raises(IndexError, match="injected"):
        TARGETS_BY_NAME["hl7_peek"].run(CLEAN_ADT.encode())


def test_the_carve_out_does_not_swallow_a_different_type_on_a_blank_segment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The carve-out is gated on the exception TYPE too, and nothing pinned that half.

    Both anti-vacuity tests above drive ``CLEAN_ADT``, which has no blank segment, so both exercise
    the *structural* arm and neither reaches the type. Measured before this test existed: widening
    ``except IndexError`` to ``except Exception`` in ``_hl7_peek`` left all fourteen tests green --
    a suppression the whole carve-out design was supposed to make impossible.

    So drive the discriminator PRESENT and plant a fault of a different type. With ``IndexError`` the
    fault escapes; with ``Exception`` the carve-out catches it, sees a blank segment, and returns
    quietly -- which reds here.
    """
    findings = [f for f in KNOWN_FINDINGS if f.target == "hl7_peek"]
    assert findings, "the blank-segment finding is no longer registered"
    reproducer = findings[0].reproducer
    assert any(not s for s in Peek.parse(reproducer).segments()), (
        "reproducer lost its blank segment"
    )

    # The FIRST property in the sweep, so the planted fault is reached before the natural IndexError
    # this message provokes on every one of them. From the test's OWN literal, so emptying the
    # source constant reds this test rather than quietly removing what it patches.
    monkeypatch.setattr(
        Peek, _EXPECTED_ROUTING_PROPERTIES[0], property(_boom(TypeError("injected")))
    )
    with pytest.raises(TypeError, match="injected"):
        TARGETS_BY_NAME["hl7_peek"].run(reproducer)


def test_the_hl7_target_reads_every_named_routing_property(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The accessor sweep is the harness's whole point, and nothing else pinned it.

    ADR 0191 calls the eleven pre-ACK routing properties the load-bearing tier: a Router reads them
    before the sender is answered, and the one finding this harness has produced lives entirely
    there -- fuzzing ``parse`` alone would have measured nothing. Yet deleting the
    ``for name in _HL7_ROUTING_PROPERTIES`` loop from ``_hl7_peek`` left every other test in this
    file passing, because the two fault-injection tests both fault ``Peek.routing`` and so pin
    ``routing()`` and nothing else. The loop could be dropped or shortened in a later edit and the
    job would go on reporting that every target survived its budget while never touching the tier it
    was built for.

    WHY THIS TEST CAN SEE THE DIFFERENCE, stated because most of the obvious versions cannot.
    ``Peek.routing()`` is a second reader of eight of the eleven -- everything except the three
    MSH-9 components (``message_code``, ``trigger_event``, ``message_structure``). A test that
    faulted any of those eight would still pass with the loop gone, via ``routing()``. So the
    assertion is on the SET of properties the target actually read: drop the loop and the three
    MSH-9 components go unread, the set comes back short, and the failure names them.

    Recording rather than faulting, deliberately. An injected exception would prove one property is
    read; the recorder proves all eleven are, which is the invariant ADR 0191 states, and it leaves
    the target's real behaviour untouched while doing so.

    **It iterates its OWN literal, and the first draft's failure is why.** That draft iterated
    ``_HL7_ROUTING_PROPERTIES`` -- the same constant ``_hl7_peek`` iterates -- so the behaviour and
    the expectation moved together. Measured: setting that constant to ``()`` at source patched
    nothing, recorded nothing, computed an empty ``missing`` and passed, reaching the identical end
    state this test exists to prevent. Dropping ``message_code`` from the constant passed too. The
    loop-level arms were all red, which is what made the hole invisible: mutating a call site while
    leaving its data untouched tests half the mechanism.
    """
    assert _HL7_ROUTING_PROPERTIES == _EXPECTED_ROUTING_PROPERTIES, (
        "fuzz/targets.py changed the routing-property list. The target's loop and this test's "
        "expectation both read it, so shortening it silently shortens what is checked. Update "
        "_EXPECTED_ROUTING_PROPERTIES only alongside a deliberate change to the accessor tier."
    )
    seen: list[str] = []
    for name in _EXPECTED_ROUTING_PROPERTIES:
        descriptor = inspect.getattr_static(Peek, name)
        assert isinstance(descriptor, property), (
            f"Peek.{name} is no longer a property, so this recorder cannot wrap it. Read that as a "
            "change in the accessor tier, not as a failure of this test."
        )
        fget = descriptor.fget
        assert fget is not None, f"Peek.{name} is a property with no getter"

        def _record(
            peek: Peek,
            _name: str = name,
            _fget: Callable[[Peek], object] = fget,
        ) -> object:
            seen.append(_name)
            return _fget(peek)

        monkeypatch.setattr(Peek, name, property(_record))

    TARGETS_BY_NAME["hl7_peek"].run(CLEAN_ADT.encode())

    missing = [name for name in _EXPECTED_ROUTING_PROPERTIES if name not in seen]
    assert not missing, (
        f"the hl7_peek target never read {missing} off the parsed Peek. Seven of the eleven run on "
        "the pre-ACK path and the three MSH-9 components are reachable only through this sweep, so "
        "a target that does not touch them cannot find a contract break there. Restore the accessor "
        "sweep in `_hl7_peek` -- do not relax this list."
    )


def test_the_x12_target_reads_every_named_isa_property(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same pin for X12, because fixing HL7 alone leaves the pattern live next door.

    ``_x12_peek`` sweeps ``_X12_ISA_PROPERTIES`` and nothing asserted it did. Deleting that loop, or
    emptying the constant, leaves the target reading no identity fields while the advisory job goes
    on reporting that every target survived its budget -- the identical end state the HL7 pin exists
    to prevent.

    Structured like its HL7 sibling and for the same reason: its own literal, asserted against the
    source constant first, so shrinking the constant is a deliberate two-file edit rather than a
    silent narrowing of what is checked.
    """
    assert _X12_ISA_PROPERTIES == _EXPECTED_ISA_PROPERTIES, (
        "fuzz/targets.py changed the ISA property list. The target's loop and this test's "
        "expectation both read it, so shortening it silently shortens what is checked. Update "
        "_EXPECTED_ISA_PROPERTIES only alongside a deliberate change to the accessor tier."
    )
    target = TARGETS_BY_NAME["x12_peek"]
    seed = next((s for s in target.seeds if s.startswith(b"ISA") and len(s) > 106), None)
    assert seed is not None, "no conformant ISA seed to drive the accessor sweep with"

    seen: list[str] = []
    for name in _EXPECTED_ISA_PROPERTIES:
        descriptor = inspect.getattr_static(X12Peek, name)
        assert isinstance(descriptor, property), (
            f"X12Peek.{name} is no longer a property, so this recorder cannot wrap it. Read that "
            "as a change in the accessor tier, not as a failure of this test."
        )
        fget = descriptor.fget
        assert fget is not None, f"X12Peek.{name} is a property with no getter"

        def _record(
            peek: X12Peek,
            _name: str = name,
            _fget: Callable[[X12Peek], object] = fget,
        ) -> object:
            seen.append(_name)
            return _fget(peek)

        monkeypatch.setattr(X12Peek, name, property(_record))

    target.run(seed)

    missing = [name for name in _EXPECTED_ISA_PROPERTIES if name not in seen]
    assert not missing, (
        f"the x12_peek target never read {missing} off the parsed X12Peek. Restore the accessor "
        "sweep in `_x12_peek` -- do not relax this list."
    )


def test_every_known_finding_is_still_recognised_by_its_target() -> None:
    """A registered known finding must still be suppressed by the target that registered it."""
    for finding in KNOWN_FINDINGS:
        TARGETS_BY_NAME[finding.target].run(finding.reproducer)


def test_the_blank_segment_finding_still_reproduces_through_the_raw_parser() -> None:
    """The filed defect is still live, and this test is how the carve-out gets removed.

    When the tolerant tier stops raising a non-``ValueError`` here, this test fails. That failure
    is the instruction: drop the entry from ``KNOWN_FINDINGS`` and the branch in ``_hl7_peek``. A
    carve-out that outlives its defect is a suppression, so it is pinned from the outside rather
    than trusted to be cleaned up.
    """
    findings = [f for f in KNOWN_FINDINGS if f.target == "hl7_peek"]
    assert findings, "the blank-segment finding is no longer registered"
    for finding in findings:
        peek = Peek.parse(finding.reproducer)
        assert any(not segment for segment in peek.segments()), "reproducer lost its blank segment"
        with pytest.raises(IndexError):
            peek.routing()


def test_write_seed_corpus_materialises_every_seed(tmp_path: Path) -> None:
    target = TARGETS_BY_NAME["hl7_peek"]
    written = write_seed_corpus(target, tmp_path / "corpus")
    assert written == len(target.seeds)
    files = sorted((tmp_path / "corpus").iterdir())
    assert len(files) == len(target.seeds)
    assert {f.read_bytes() for f in files} == set(target.seeds)


def test_rerunning_the_seed_writer_does_not_grow_the_corpus(tmp_path: Path) -> None:
    """Seeds are named by index, so a second run overwrites rather than accumulating."""
    target = TARGETS_BY_NAME["hl7_peek"]
    corpus = tmp_path / "corpus"
    write_seed_corpus(target, corpus)
    write_seed_corpus(target, corpus)
    assert len(list(corpus.iterdir())) == len(target.seeds)


def test_a_target_whose_module_is_missing_reports_itself_unavailable() -> None:
    """The availability probe actually probes.

    Asserting only that the no-dependency targets are available would pass even if
    ``available()`` were ``return True``, which is the arm that matters: the runner refuses an
    unavailable target rather than passing over it, so a probe stuck on True would fuzz nothing and
    report success. Drive the real branch with a module name that cannot exist.
    """
    probe = FuzzTarget(
        name="probe",
        summary="availability probe",
        run=lambda _data: None,
        seeds=(b"",),
        requires_module="mefor_no_such_module_0191",
    )
    assert not probe.available()
    assert TARGETS_BY_NAME["hl7_peek"].available(), "a target with no optional dependency"


def test_every_target_in_the_fuzz_workflow_exists_in_the_registry() -> None:
    """The advisory job's target list must match the registry exactly.

    A renamed or added target leaves the workflow fuzzing a subset while still reporting success
    per target it does know, and the entrypoint exits for an unknown name -- inside a step that is
    deliberately ``continue-on-error``. So a drifted list degrades silently, which is the one
    failure mode this whole harness is built to avoid.
    """
    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "fuzz.yml"
    text = workflow.read_text(encoding="utf-8")
    match = re.search(r"for target in ([a-z0-9_ ]+); do", text)
    assert match, f"no target loop found in {workflow.name}; did the job shape change?"
    assert sorted(match.group(1).split()) == sorted(TARGETS_BY_NAME)


def _fuzz_job_steps() -> list[dict[str, object]]:
    """The advisory job's steps, parsed.

    Parsed rather than grepped, because the property under test is *which step* does what, and a
    whole-file text search cannot tell two steps apart.
    """
    jobs = jobs_of("fuzz.yml")
    assert "parsers" in jobs, f"fuzz.yml declares no job 'parsers' (it has: {sorted(jobs)})"
    steps = jobs["parsers"].get("steps") or []
    assert steps, "fuzz.yml:parsers parsed to no steps; read that as a parse failure, not a pass"
    return [step or {} for step in steps]


def test_a_finding_reaches_a_step_that_writes_the_job_summary() -> None:
    """A finding must leave the softened step through a channel something downstream reads.

    THE DEFECT THIS PINS IS MEASURED, not imagined. On run 35761703252 the fuzz step found a real
    contract violation, annotated it and exited 1 -- and ``continue-on-error`` rewrote that step's
    conclusion to ``success``, leaving an ``outcome`` no workflow in this repository reads. The job
    went green and PR 1423 merged with the finding unread (run finished 17:39:41Z, merge 18:16:20Z).

    So this asserts the three links of the chain separately: the producing step WRITES the findings
    variable, a DIFFERENT step READS it, and that reader writes the job summary. Producer and
    consumer being distinct is the load-bearing half -- a step that hands a value to itself is the
    arrangement that failed, and it satisfies any check that only looks for both strings somewhere
    in the file.
    """
    steps = _fuzz_job_steps()
    producers = [s for s in steps if "MEFOR_FUZZ_FINDINGS=" in str(s.get("run", ""))]
    assert len(producers) == 1, (
        f"expected exactly one step to WRITE MEFOR_FUZZ_FINDINGS, found {len(producers)}. Without "
        "it a finding leaves the fuzz step only through `exit 1`, which `continue-on-error` "
        "discards -- the measured defect this channel exists to fix."
    )
    assert "GITHUB_ENV" in str(producers[0].get("run", "")), (
        "the findings variable is written but not into $GITHUB_ENV, so no later step can read it"
    )

    consumers = [
        s
        for s in steps
        if s is not producers[0]
        and "MEFOR_FUZZ_FINDINGS" in str(s.get("run", ""))
        and "GITHUB_STEP_SUMMARY" in str(s.get("run", ""))
    ]
    assert len(consumers) == 1, (
        f"expected exactly one step OTHER THAN the producer to read MEFOR_FUZZ_FINDINGS and write "
        f"$GITHUB_STEP_SUMMARY, found {len(consumers)}. A finding that is handed from a step to "
        "itself reaches nobody, which is precisely what happened on run 35761703252."
    )


def test_the_finding_reporter_carries_the_reproducer_and_gates_nothing() -> None:
    """The reporter must be readable, actionable, and incapable of blocking a merge.

    Three properties, and dropping any one of them re-creates a different half of the defect.
    Without the reproducer the summary says a defect exists and leaves the reader to re-derive the
    input from a log line among half a million. With a ``continue-on-error`` of its own the reporter
    could die silently and report nothing, which is the failure mode the fuzz step already has. With
    an ``exit 1`` it would red an advisory job on a budget-and-seed-dependent result, which ADR 0191
    option 6 rejected and which this change does not reopen.
    """
    steps = _fuzz_job_steps()
    reporters = [
        s
        for s in steps
        if "MEFOR_FUZZ_FINDINGS" in str(s.get("run", ""))
        and "GITHUB_STEP_SUMMARY" in str(s.get("run", ""))
    ]
    assert len(reporters) == 1, f"expected one reporting step, found {len(reporters)}"
    reporter = reporters[0]
    body = str(reporter.get("run", ""))

    assert "Base64: " in body, (
        "the reporter does not lift libFuzzer's `Base64:` line out of the captured log, so the "
        "summary would name a defect without carrying the input that provokes it. Verified against "
        "run 35761703252: that line decodes to the 155-byte unit, and it reproduces."
    )
    assert reporter.get("continue-on-error") in (None, False), (
        "the reporting step must not be softened. A softened reporter can fail silently, which is "
        "the same defect one layer up -- and it would also red "
        "test_step_advisory_jobs_soften_only_their_named_step."
    )
    assert not re.search(r"^\s*exit [1-9]", body, re.MULTILINE), (
        "the reporting step exits non-zero somewhere. A finding must not red this advisory job "
        "(ADR 0191 option 6); only the refusal step is allowed to."
    )


def test_the_work_root_is_outside_the_repository_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A corpus that cannot be staged beats one that is merely git-ignored.

    Every file the fuzzer writes is message-shaped and a corpus grows without bound, so the default
    location sits outside the work tree: ``git add -A`` cannot reach it. Pinned here because moving
    the default back inside the repository would be an easy, quiet way to reintroduce the risk.
    """
    monkeypatch.delenv(WORK_DIR_ENV, raising=False)
    repo_root = Path(__file__).resolve().parent.parent
    assert not work_root().is_relative_to(repo_root)


def test_the_work_root_honours_its_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(WORK_DIR_ENV, str(tmp_path / "corpora"))
    # Compared resolved: ``work_root`` resolves the override now, and a Windows temp directory can
    # arrive as an 8.3 short name that only resolution normalises.
    assert work_root() == (tmp_path / "corpora").resolve()
    corpus, artifacts = work_paths(TARGETS_BY_NAME["hl7_peek"])
    assert corpus.is_relative_to((tmp_path / "corpora").resolve())
    assert artifacts.is_relative_to((tmp_path / "corpora").resolve())
    assert corpus != artifacts


def test_the_work_root_refuses_an_override_inside_the_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A RELATIVE override lands in the work tree, and no test could see it before this one.

    ``work_root`` returned ``Path(override)`` unexamined, so a relative value resolved against the
    working directory -- and ``fuzz/README.md`` tells the operator to run the module from the
    repository root. The corpus is message-shaped by construction, so that put fuzzer-minimised HL7,
    X12 and DICOM bodies where ``git add -A`` reaches them (CLAUDE.md section 9). No shell quirk is
    needed for this arm: a plain relative path does it.

    **Why three reviews missed it:** every existing override test passes an absolute ``tmp_path``,
    which is structurally incapable of showing a relative-path leak. A refusal an operator sees beats
    a leak nobody notices, so the fence raises rather than silently relocating.
    """
    monkeypatch.setenv(WORK_DIR_ENV, "mefor-fuzz-corpus")
    with pytest.raises(HarnessRefusal, match="inside the repository"):
        work_root()


def test_the_work_root_expands_a_tilde_override_instead_of_writing_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The README's own recipe is the one that carries a tilde, so it gets its own arm.

    ``fuzz/README.md`` hands out ``MEFOR_FUZZ_WORK_DIR=~/mefor-fuzz``. A POSIX shell expands the
    tilde before Python sees it, so on an interactive bash line the value arrives absolute. **The
    expansion belongs to the shell, not to the value**, and anything that sets the variable without
    one passes the tilde through: a quoted assignment, a Dockerfile ``ENV``, a systemd unit, a CI
    ``env:`` block, or PowerShell. Measured on PowerShell 7, 2026-09-22 -- which is where the
    non-expansion is easiest to demonstrate, not where the fuzzer runs; Atheris has no Windows
    wheel. Unexpanded, ``Path("~/mefor-fuzz")`` is *relative* and resolves inside the repository.

    ``expanduser`` makes the recipe mean the same thing however the value arrived. Without it this
    override hits the fence above -- a refusal rather than a leak, which is safe but turns a
    documented recipe into an error, so both belong together.
    """
    monkeypatch.setenv(WORK_DIR_ENV, "~/mefor-fuzz")
    root = work_root()
    assert root == (Path.home() / "mefor-fuzz").resolve()
    assert not root.is_relative_to(Path(__file__).resolve().parent.parent)
    assert "~" not in root.parts


def test_libfuzzer_argv_supplies_the_defaults_this_harness_needs(tmp_path: Path) -> None:
    corpus, artifacts = tmp_path / "corpus", tmp_path / "artifacts"
    argv = libfuzzer_argv(["prog"], corpus, artifacts)
    assert argv[0] == "prog"
    assert f"-artifact_prefix={artifacts}{os.sep}" in argv
    assert f"-max_len={DEFAULT_MAX_LEN}" in argv
    assert str(corpus) in argv


def test_libfuzzer_argv_never_overrides_what_the_caller_passed(tmp_path: Path) -> None:
    """libFuzzer takes the LAST occurrence of a repeated flag, so appending blindly would clobber.

    The ``-artifact_prefix`` arm is the one that matters: silently overriding a caller's choice
    would redirect a minimised, message-shaped crash input somewhere they did not ask for.
    """
    corpus, artifacts = tmp_path / "corpus", tmp_path / "artifacts"
    mine = str(tmp_path / "mine") + os.sep
    argv = libfuzzer_argv(
        ["prog", f"-artifact_prefix={mine}", "-max_len=16", str(tmp_path / "own")],
        corpus,
        artifacts,
    )
    assert argv.count("-max_len=16") == 1
    assert not any(arg.startswith(f"-max_len={DEFAULT_MAX_LEN}") for arg in argv)
    assert [a for a in argv if a.startswith("-artifact_prefix=")] == [f"-artifact_prefix={mine}"]
    # The caller's positional is the corpus; ours must not be appended as a second one.
    assert str(corpus) not in argv
