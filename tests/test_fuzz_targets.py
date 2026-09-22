# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The fuzz-target harness (ADR 0191), driven under plain pytest rather than under Atheris.

Atheris ships Linux x86-64 wheels only and the fuzz job is one advisory Linux leg, so without this
file the harness would be exercised on exactly one platform by exactly one job that is allowed to
fail. That is the shape where a broken detector and a clean run look identical. These tests run on
every leg, Windows included, because ``fuzz/targets.py`` imports no Atheris.

The load-bearing tests here are the two fault-injection ones. A fuzz harness that has never been
shown to catch anything measures nothing, so instead of trusting that a raised exception would be
noticed, they inject one and assert it escapes -- including the case that a narrowed known-finding
carve-out must **not** swallow.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Never

import pytest

from fuzz.targets import (
    DEFAULT_MAX_LEN,
    KNOWN_FINDINGS,
    TARGETS,
    TARGETS_BY_NAME,
    WORK_DIR_ENV,
    FuzzTarget,
    libfuzzer_argv,
    work_paths,
    work_root,
    write_seed_corpus,
)
from messagefoundry.parsing import Peek

#: A conformant synthetic message with no blank segment -- the negative control for the carve-out.
CLEAN_ADT = (
    "MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\rPID|1||100001^^^HOSP^MR||DOE^JANE\r"
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


def test_every_available_target_accepts_its_own_seeds() -> None:
    for target in TARGETS:
        if not target.available():
            continue
        for seed in target.seeds:
            target.run(seed)  # must not raise: these are conformant synthetic inputs


def test_every_available_target_survives_degenerate_input() -> None:
    for target in TARGETS:
        if not target.available():
            continue
        for data in GARBAGE:
            target.run(data)


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
    assert work_root() == tmp_path / "corpora"
    corpus, artifacts = work_paths(TARGETS_BY_NAME["hl7_peek"])
    assert corpus.is_relative_to(tmp_path / "corpora")
    assert artifacts.is_relative_to(tmp_path / "corpora")
    assert corpus != artifacts


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
