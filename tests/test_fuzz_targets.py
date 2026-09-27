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
on the blank-segment seed, which a known-finding carve-out used to swallow until BACKLOG #1594
fixed the defect behind it. ``test_the_hl7_target_reads_every_named_routing_property`` covers the
eleven named routing accessors the sweep drives, which a fault on ``Peek.routing`` alone could not
see the loss of.

**"The eleven pre-ACK accessors" was the old wording here and it was wrong** -- seven of the eleven
are read pre-ACK, three are unique to this sweep, and the pre-ACK path reads several the list does
not name. ``fuzz/targets.py``'s module docstring carries the measured accounting; this file does not
restate it.
"""

from __future__ import annotations

import inspect
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Never

import pytest

from fuzz.targets import (
    _HL7_ROUTING_PROPERTIES,
    _X12_ISA_PROPERTIES,
    BLANK_SEGMENT_HL7,
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
from messagefoundry.parsing._backend import backend
from messagefoundry.parsing.x12 import X12Peek
from tests._bash_resolver import (
    BASH_HARNESS_FAILURE,
    explain_returncode,
    probe_env,
    require_bash,
)
from tests._workflow_contexts import jobs_of

#: A conformant synthetic message with no blank segment.
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


@pytest.mark.parametrize("fault", [IndexError, TypeError], ids=["IndexError", "TypeError"])
def test_an_injected_fault_escapes_on_the_blank_segment_seed(
    fault: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No carve-out outlives the BACKLOG #1594 fix, whatever its shape.

    ``_hl7_peek`` used to swallow ``IndexError`` on a message carrying an empty segment: the one
    registered known finding. The defect is fixed and the carve-out is gone, so the blank-segment
    seed must now behave like any other input. A leftover carve-out keyed on the exception type
    reds the ``IndexError`` arm; one keyed on ``Exception`` plus the blank-segment discriminator
    reds both arms. The fault goes on the FIRST property of the sweep, taken from this test's own
    literal, so emptying the source constant reds this test rather than removing what it patches.
    """
    assert b"\r\r" in BLANK_SEGMENT_HL7, "the seed lost its blank segment"
    monkeypatch.setattr(Peek, _EXPECTED_ROUTING_PROPERTIES[0], property(_boom(fault("injected"))))
    with pytest.raises(fault, match="injected"):
        TARGETS_BY_NAME["hl7_peek"].run(BLANK_SEGMENT_HL7)


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


@pytest.mark.parametrize("builtin", [True, False], ids=["builtins", "python-hl7"])
def test_the_blank_segment_seed_reads_cleanly_on_both_backends(builtin: bool) -> None:
    """BACKLOG #1594 regression: the old finding's reproducer now parses AND reads.

    This replaced the test that pinned the defect as live. It ran the reproducer through the raw
    parser and asserted ``IndexError``, so the fix turned it red, which was its instruction to drop
    the carve-out. What is pinned now is the fixed behaviour, on both parser backends.
    """
    with backend(builtin=builtin):
        peek = Peek.parse(BLANK_SEGMENT_HL7)
        assert peek.control_id == "MSG1"
        assert peek.routing()["message_type"] == "ADT^A01"
        assert "" not in peek.segments()
        TARGETS_BY_NAME["hl7_peek"].run(BLANK_SEGMENT_HL7)


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


#: A libFuzzer-shaped crash log: the lines the reporter extracts, in the order CI emits them.
#:
#: Trimmed from the real output of run 35761703252 rather than invented, so the patterns are tested
#: against the shape they will actually meet. `_REPRO_B64` is that run's real 155-byte crash unit.
_REPRO_B64 = (
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "RElDTQAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABESUNNAgAAAAAAAAAAAP//AABESUNNAgAAAPz/"
    "//8AAAAAAAAA//////////8="
)
#: The exception line is kept WHOLE, including the ``repr()`` of the offending bytes.
#:
#: An earlier draft trimmed it at "per value." -- which is precisely where pydicom embeds the value
#: it choked on (``pydicom/values.py`` reprs any value of 256 bytes or fewer). That trim removed the
#: one property worth exercising: the exception line is itself message-shaped, so it is a PHI sink
#: as much as the base64 is, and `.github/workflows/fuzz.yml`'s header now says so. A fixture that
#: drops the bytes cannot show the reporter carrying them.
_CRASH_EXC = (
    "BytesLengthException: Expected total bytes to be an even multiple of bytes per value. "
    "Instead received b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff"
    "\\xff' with length 15 and struct format 'L' which corresponds to bytes per value of 4."
)
_CRASH_LOG = (
    "#8214\tNEW    cov: 341 ft: 513 corp: 22/3240b lim: 167 exec/s: 0 rss: 82Mb\n"
    " === Uncaught Python exception: ===\n"
    f"{_CRASH_EXC}\n"
    "Traceback (most recent call last):\n"
    '  File "fuzz/targets.py", line 290, in _dicom_peek\n'
    "==2305== ERROR: libFuzzer: fuzz target exited\n"
    f"Base64: {_REPRO_B64}\n"
    "stat::number_of_executed_units: 8326\n"
)


def _step_body(prefix: str) -> str:
    """The SHIPPED `run:` body of the one step whose name starts with ``prefix``.

    Asserts the body interpolates no Actions expression. Running it verbatim is only sound while
    that holds: a ``${{ }}`` is substituted by Actions and would be left literal here, so this
    harness would silently stop executing what CI executes. Borrowed from
    ``tests/test_nightly_notice.py``, which makes the same argument for the same reason.
    """
    named = [s for s in _fuzz_job_steps() if str(s.get("name", "")).startswith(prefix)]
    assert len(named) == 1, f"expected one step named {prefix!r}, found {len(named)}"
    body = str(named[0].get("run", ""))
    assert body, f"step {prefix!r} has an empty run body"
    assert "${{" not in body, (
        f"step {prefix!r} interpolates an Actions expression, so this harness is no longer "
        "executing what CI executes"
    )
    return body


def _run_reporter(
    tmp_path: Path,
    findings: str,
    refusals: str,
    log_dir: Path,
    complete: str = "1",
) -> tuple[int, str]:
    """Execute the shipped reporting step verbatim and return its exit code and the summary."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    bash = require_bash(tmp_path)
    script = tmp_path / "report.sh"
    script.write_text(_step_body("Report any finding"), encoding="utf-8", newline="\n")
    summary = tmp_path / "summary.md"
    summary.write_text("", encoding="utf-8")
    env = probe_env(Path(bash), dict(os.environ))
    env.update(
        {
            "MEFOR_FUZZ_FINDINGS": findings,
            "MEFOR_FUZZ_REFUSALS": refusals,
            "MEFOR_FUZZ_LOG_DIR": log_dir.as_posix(),
            "MEFOR_FUZZ_COMPLETE": complete,
            "GITHUB_STEP_SUMMARY": summary.as_posix(),
        }
    )
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [bash, script.as_posix()],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert proc.returncode != BASH_HARNESS_FAILURE, explain_returncode(
        proc.returncode, "the fuzz reporting step"
    )
    return proc.returncode, summary.read_text(encoding="utf-8")


def test_the_reporter_really_extracts_the_reproducer_from_a_crash_log(tmp_path: Path) -> None:
    """Run the shipped reporting step against a crash log and assert the base64 lands.

    **A SUBSTRING CHECK OVER THE YAML CANNOT SEE THIS BREAK, WHICH IS WHY THIS RUNS THE BODY.**
    `test_the_finding_reporter_carries_the_reproducer_and_gates_nothing` asserts the step *mentions*
    libFuzzer's `Base64:` line, and that assertion passes just as happily against a `sed` expression
    that matches nothing. A typo in the pattern, a `head`/`tail` picking the wrong line, or an
    upstream change to libFuzzer's output would all leave the summary announcing a defect with no
    input attached -- which is most of the defect this whole step was added to fix.

    It also closes the `${log_dir}/${target}.log` path round trip: the writer and the reader spell
    that filename separately, so nothing else would notice if one of them changed.
    """
    log_dir = tmp_path / "fuzz-logs"
    log_dir.mkdir()
    (log_dir / "dicom_peek.log").write_text(_CRASH_LOG, encoding="utf-8")

    code, summary = _run_reporter(tmp_path, " dicom_peek", "", log_dir)

    assert code == 0, f"the reporter must never red this advisory job; it exited {code}"
    assert _REPRO_B64 in summary, (
        "the reporter did not carry libFuzzer's base64 reproducer into the job summary. The "
        "summary would name a defect and leave the reader to re-derive its input from the step "
        f"log. Summary was:\n{summary}"
    )
    assert _CRASH_EXC in summary, (
        "the escaped exception did not reach the summary WHOLE. The tail of that line is where "
        "pydicom embeds a repr of the bytes it choked on, so truncating it would drop the part a "
        "reader needs and the part the PHI note in the workflow header accounts for."
    )
    assert "8326" in summary, "the execution count did not reach the summary"
    assert "### dicom_peek" in summary, "the finding is not attributed to a named target"


def test_the_two_steps_name_the_same_log_directory_variable() -> None:
    """The capture path is spelled in two steps and nothing else would notice them diverging.

    The reporter half is covered by execution -- a renamed read there makes the round-trip test
    report "No captured output". The WRITE half is not: the fuzz step could rename what it exports
    and every other test would stay green while every summary lost its reproducer, which is the
    drift the workflow comment beside that export names.
    """
    producer = _step_body("Fuzz the tolerant parsers")
    reporter = _step_body("Report any finding")
    assert "MEFOR_FUZZ_LOG_DIR" in producer, "the fuzz step no longer exports the log directory"
    assert "MEFOR_FUZZ_LOG_DIR" in reporter, "the reporter no longer reads the log directory"


def test_the_reporter_never_reds_the_job_and_never_claims_a_clean_run_it_cannot_claim(
    tmp_path: Path,
) -> None:
    """Four outcomes, none of which may red the job or overstate what ran.

    The refusal-plus-finding row is here because the first draft got it wrong. That draft reported
    refusals only on the no-findings path, so a run with both took the findings arm, said nothing
    about the refusal, and asserted the check beside it was green -- while the refusal step was
    redding the job. A reporter that contradicts its own check is the defect this step exists to
    fix, one level up.
    """
    log_dir = tmp_path / "fuzz-logs"
    log_dir.mkdir()
    (log_dir / "dicom_peek.log").write_text(_CRASH_LOG, encoding="utf-8")

    clean_code, clean = _run_reporter(tmp_path / "a", "", "", log_dir)
    assert clean_code == 0
    assert "Every target survived its budget" in clean
    assert _REPRO_B64 not in clean, "a clean run must not carry a reproducer"

    refused_code, refused = _run_reporter(tmp_path / "b", "", " dicom_peek", log_dir)
    assert refused_code == 0
    assert "never ran" in refused
    assert "Every target survived its budget" not in refused, (
        "a run where a target never started must not be reported as every target surviving"
    )

    both_code, both = _run_reporter(tmp_path / "c", " dicom_peek", " x12_peek", log_dir)
    assert both_code == 0
    assert "never ran" in both and "x12_peek" in both, (
        "a run with BOTH a refusal and a finding dropped the refusal. That is the first draft's "
        f"defect. Summary was:\n{both}"
    )
    assert _REPRO_B64 in both, (
        "the finding's reproducer was dropped when a refusal was also present"
    )

    missing_code, missing = _run_reporter(tmp_path / "d", " dicom_peek", "", tmp_path / "gone")
    assert missing_code == 0, "a missing capture must degrade, never red the job"
    assert "No captured output" in missing


def test_the_completion_sentinel_is_written_last_and_is_checked_by_the_refusal_step() -> None:
    """Both ends of the sentinel, because each is useless without the other.

    The reporter's handling of a MISSING sentinel is covered by executing it. What that cannot see
    is the producing end: if the fuzz step stopped writing the sentinel, or wrote it before the
    work it certifies, the reporter's guard would still behave correctly and certify nothing.

    ORDER IS THE PROPERTY, not presence. A sentinel written before the loop says only "this step
    started", which is what its `continue-on-error` conclusion already says.
    """
    fuzz_body = _step_body("Fuzz the tolerant parsers")
    assert "MEFOR_FUZZ_COMPLETE=1" in fuzz_body, (
        "the fuzz step no longer writes the completion sentinel, so a step that dies partway is "
        "indistinguishable from one that ran clean"
    )
    assert fuzz_body.index("MEFOR_FUZZ_COMPLETE=1") > fuzz_body.index("MEFOR_FUZZ_FINDINGS="), (
        "the completion sentinel is written BEFORE the findings channel. It must be written last, "
        "or it certifies a step that had not yet reported its result."
    )


def _run_refusal_step(tmp_path: Path, refusals: str, complete: str) -> int:
    """Execute the shipped refusal step verbatim and return its exit code."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    bash = require_bash(tmp_path)
    script = tmp_path / "refusal.sh"
    script.write_text(_step_body("Fail if the harness never ran"), encoding="utf-8", newline="\n")
    env = probe_env(Path(bash), dict(os.environ))
    env.update({"MEFOR_FUZZ_REFUSALS": refusals, "MEFOR_FUZZ_COMPLETE": complete})
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [bash, script.as_posix()],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert proc.returncode != BASH_HARNESS_FAILURE, explain_returncode(
        proc.returncode, "the fuzz refusal step"
    )
    return proc.returncode


def test_the_refusal_step_reds_on_a_missing_sentinel_and_on_a_refusal(tmp_path: Path) -> None:
    """Execute the gate rather than grep it, because grepping it measured the wrong thing.

    **THIS TEST REPLACES A SUBSTRING CHECK THAT A MUTATION ARM CAUGHT PASSING.** The first draft
    asserted ``"MEFOR_FUZZ_COMPLETE" in refusal_body``. Replacing the step's actual condition with
    ``if false; then`` left that assertion green, because the variable is still named in the
    comment above the condition -- so the guard certified a gate that had stopped gating. Running
    the body cannot be satisfied by a comment.

    A missing sentinel must red for the same reason a refusal does: both mean the harness did not
    do what it was asked, which is a fault rather than a fuzz result.
    """
    assert _run_refusal_step(tmp_path / "ok", "", "1") == 0, (
        "a completed run with no refusals must pass the gate"
    )
    assert _run_refusal_step(tmp_path / "dead", "", "") != 0, (
        "the refusal step passed a run whose fuzz step never finished. `continue-on-error` already "
        "rewrote that step's own conclusion to success, so this gate is the only thing left that "
        "can report it."
    )
    assert _run_refusal_step(tmp_path / "refused", " dicom_peek", "1") != 0, (
        "the refusal step passed a run where a target never executed"
    )


def test_the_reporter_claims_nothing_when_the_fuzz_step_did_not_finish(tmp_path: Path) -> None:
    """An empty findings list is not evidence of a clean run, and must not be reported as one.

    **THE SENTINEL IS THE WHOLE POINT AND THIS IS THE ONLY TEST THAT CAN SEE IT.** The fuzz step
    carries ``continue-on-error``, so if it dies partway -- under ``set -e``, in the ``mkdir``, in
    a ``cat`` on an unwritable log -- its conclusion is rewritten to ``success`` and it writes no
    channel variables at all. The reporter then sees an empty findings list, which is exactly what
    a genuinely clean run also produces. Guessing "clean" there turns a harness fault into an
    affirmative all-clear on the run page: strictly worse than the silence it replaced, because a
    reader now has a sentence telling them the parsers are fine.

    ``MEFOR_FUZZ_COMPLETE`` is written LAST by the fuzz step, so its absence means "did not
    finish". Every other test in this file passes it, which is why none of them would notice its
    removal.
    """
    log_dir = tmp_path / "fuzz-logs"
    log_dir.mkdir()

    code, summary = _run_reporter(tmp_path / "e", "", "", log_dir, complete="")

    assert code == 0, "the reporter still must not red the job, even on a harness fault"
    assert "did not finish" in summary, (
        f"the reporter did not say the fuzz step failed to finish. Summary was:\n{summary}"
    )
    assert "Every target survived its budget" not in summary, (
        "the reporter claimed a clean run from a fuzz step that never reported one. An empty "
        "findings list means EITHER nothing was found OR the step died before it could say, and "
        "this step cannot tell those apart without the sentinel."
    )


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
    # The two halves MATCHED ON ONE LINE, not merely both present in the body. The producer writes
    # three variables to $GITHUB_ENV, so a bare `"GITHUB_ENV" in body` is satisfied by the other
    # two: redirect the findings line to /dev/null and that check stays green while its own failure
    # message claims to catch exactly that. Answering the adjacent question is the defect this file
    # keeps finding elsewhere (CLAUDE.md section 11, SDS-3.8).
    assert re.search(
        r"MEFOR_FUZZ_FINDINGS=[^\n]*>>[^\n]*GITHUB_ENV", str(producers[0].get("run", ""))
    ), (
        "the findings variable is not written into $GITHUB_ENV on its own line, so no later step "
        "can read it. A finding would then leave the fuzz step only through `exit 1`, which "
        "`continue-on-error` discards."
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
