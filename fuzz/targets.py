# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fuzz targets for the tolerant HL7 v2 / X12 / DICOM parsers (ADR 0191).

This module is deliberately **Atheris-free**, so it imports and runs on every platform the engine
supports -- including Windows, where Atheris has no wheel at all. ``fuzz/fuzz_parsers.py`` is the
only Atheris entrypoint and it imports this registry; ``tests/test_fuzz_targets.py`` drives the same
targets under plain pytest, so the harness itself is regression-tested on every CI leg rather than
only on the one advisory job that fuzzes.

**The invariant every target asserts.** Each codec writes its contract down in its own error module:
a malformed or hostile body raises that codec's :class:`ValueError` subclass -- ``HL7PeekError``,
``X12Error``, ``DicomError`` -- so a Router or Handler that already routes ``ValueError`` to the
error/dead-letter path catches it without special-casing the format, and the count-and-log invariant
holds for free. A **missing optional extra** raises ``RuntimeError`` instead, deliberately, so a
deploy/config error is not swallowed as a data error.

A target therefore feeds a parser arbitrary bytes and lets **every other exception propagate**. An
escaping ``IndexError``, ``KeyError``, ``AttributeError`` or ``RecursionError`` is a finding: the
parser accepted a body and then broke its own contract on a path a Router already relies on.

**Parse is not the whole surface, and that is the point.** A Router does not stop at ``parse``; it
reads routing fields off the result. So each target parses *and then* sweeps the accessor tier.
Fuzzing ``parse`` alone would have missed the one finding this harness has produced (an empty
segment, fixed under BACKLOG #1594; see :data:`KNOWN_FINDINGS`).

**What that sweep is, stated accurately, because the first draft justified it wrongly.** It claimed
these are "the accessors the inbound path actually touches". They are not, in both directions, and a
later reader pruning the list by that reason would prune the wrong entries. Measured 2026-09-22
against ``pipeline/wiring_runner.py``, ``transports/`` and ``api/``:

* ``Peek.routing()`` and ``Peek.segments()`` are read **nowhere in the message path** -- zero hits
  across ``pipeline/``, ``transports/`` and ``api/``, against 13 for ``control_id`` on the same
  instrument. (``segments()`` does have one caller elsewhere, ``generators/adt.py``, which is a test
  generator and not the inbound path; the scope of the claim is the three packages named.) The
  sweep drives them anyway, and that is defensible: they are public surface on a pure library, so a
  contract break there is a finding whether or not today's pipeline calls it.
* The pre-ACK path reads **more** than the eleven named properties: ``control_id``,
  ``message_type`` and ``summarize(peek)`` at the ingress commit, then ``build_ack``
  (``transports/mllp.py``) reads eight further accessors before the ACK frame goes out.
* ``Peek.field()`` is the widest input-dependent surface of all -- ``summarize`` alone calls it up
  to seven times, for ``PID-3.1``, ``PID-5.1``, ``PID-5.2`` and, on an ORM/ORU only, ``ORC-2.1``,
  ``OBR-2.1``, ``OBR-3.1`` and ``ORC-3.1`` -- and **no target calls it directly.** The named
  properties reach it internally, which is how that finding surfaced at all; a direct
  ``field()`` target is the obvious next addition and is deliberately not in this change.

**PHI (CLAUDE.md section 9).** Seeds are the repository's committed synthetic samples plus small
inline literals -- no new message-shaped files, and never real PHI. No target prints a body, and the
runner keeps its corpus and crash artifacts **outside the work tree** (see :func:`work_root`), so a
fuzzer-minimised input cannot be staged even by ``git add -A``. That last clause is only true because
:func:`work_root` **refuses** an override resolving inside the repository; it was false for the
override path until the fence landed, and the docstring there records what went wrong.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.parsing import HL7PeekError, Peek, TreeNode, parse_tree
from messagefoundry.parsing.dicom import DicomError, DicomPeek
from messagefoundry.parsing.x12 import X12Error, X12Peek

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SAMPLES = _REPO_ROOT / "samples" / "messages"

#: Override to keep a persistent corpus somewhere of your own choosing. Refused if it resolves inside
#: the repository -- see :func:`work_root`.
WORK_DIR_ENV = "MEFOR_FUZZ_WORK_DIR"

#: Process exit code for a harness REFUSAL: a misconfiguration that stopped the run before any input
#: was fuzzed. Distinct from 1 because ``.github/workflows/fuzz.yml`` reads every other non-zero exit
#: as "this parser broke its exception contract", so a refusal exiting 1 publishes a parser finding
#: that never happened. It cannot collide with a libFuzzer exit code: every refusal is raised before
#: ``atheris.Setup``, so libFuzzer has not started and will never choose this process's status.
REFUSAL_EXIT = 3


class HarnessRefusal(ValueError):
    """The harness refused to run because its configuration would do something unsafe or vacuous.

    A ``ValueError`` because it reports a bad *value* in the environment, and a distinct class so the
    entrypoint can map it to :data:`REFUSAL_EXIT` without also catching a parser's contract error.
    """


#: Inputs longer than this are not interesting here: a parse bug reachable at all is reachable in a
#: few kilobytes, and libFuzzer spends its budget on shape rather than on length.
#:
#: **The rationale this comment used to give was backwards.** It said each parser enforces a size
#: ceiling "well below" 8192, making a larger ``max_len`` redundant. Measured 2026-09-22, the
#: ceilings are 16 MiB -- ``DEFAULT_MAX_MESSAGE_BYTES`` (``parsing/peek.py``),
#: ``DEFAULT_MAX_INTERCHANGE_BYTES`` (``parsing/x12/delimiters.py``) and, bounding the *inflated*
#: stream rather than the input, ``DEFAULT_MAX_INFLATED_BYTES`` (``parsing/dicom/_inflate.py``).
#: That is 2048x **above** this value, not below it, so those guards are **unreachable** at this
#: ``max_len``, not redundant. The choice stands on the budget argument alone; nothing here fuzzes a
#: size ceiling, and a run that should exercise one has to raise ``-max_len`` past 16 MiB.
DEFAULT_MAX_LEN = 8192


def _sample(name: str) -> tuple[bytes, ...]:
    """The committed synthetic sample ``name`` as a one-tuple, or empty if it is not present.

    Reusing ``samples/messages/`` keeps the seed corpus synthetic and commits no new
    message-shaped file. Absence is tolerated rather than fatal so a sparse checkout still fuzzes.
    """
    path = _SAMPLES / name
    return (path.read_bytes(),) if path.is_file() else ()


# A bare MSH, an ISA fragment that stops mid-header, and the Part-10 magic with nothing after it.
# Each sits on a different early branch (accepted / truncated envelope / magic-only), which is where
# a mutator gets the most leverage from a tiny seed.
#
# MEASURED for the DICOM one, in CI run 35761703252: from these 132 bytes and nothing else, the
# mutator produced a real contract violation at execution unit 8,326, through pydicom's file-meta
# reader, inside a 60-second budget. A magic-only seed reaching a tier that can report was an open
# question when these were chosen; it is no longer one, so do not shrink this seed on the theory
# that it cannot get anywhere.
#
# An earlier draft also pinned "reached the file-meta reader" to exec #4495. That pairs the wrong
# two facts: #4495's coverage jump follows a warning from `filereader.py:487`, which is the
# end-of-file handler inside `read_dataset`, while the finding's own traceback enters
# `_read_file_meta_info` at `filereader.py:686`. The tier attribution is right and the exec number
# belonged to a different event, so the number is dropped rather than re-pointed.
_MINIMAL_HL7 = b"MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\r"
#: The reproducer of the one finding this harness produced (BACKLOG #1594), kept as a seed so a
#: regression is found from the first input rather than rediscovered by mutation.
BLANK_SEGMENT_HL7 = b"MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\rPID|1||X\r\rPV1|1|I\r"
_TRUNCATED_X12 = b"ISA*00*          *00*"
_MAGIC_ONLY_DICOM = b"\x00" * 128 + b"DICM"

#: The HL7 routing properties this harness sweeps off a ``Peek``.
#:
#: **Not "every one is on the pre-ACK path", which is what this comment used to claim.** Measured
#: 2026-09-22: six are read pre-ACK by ``build_ack`` (``sending_app``, ``sending_facility``,
#: ``receiving_app``, ``receiving_facility``, ``version``, ``control_id``), ``message_type`` is read
#: at the ingress commit, and ``message_code`` is reached pre-ACK inside ``summarize`` (it selects
#: the ORM/ORU branch). That leaves ``trigger_event``, ``message_structure`` and ``timestamp`` with
#: no pre-ACK reader found.
#:
#: **"Unique to this sweep" is a separate question from "pre-ACK", and the two must not be read as
#: one.** ``Peek.routing()`` independently reads eight of the eleven, so a fault injected on any of
#: those eight is still caught with this loop deleted; only the three MSH-9 components --
#: ``message_code``, ``trigger_event``, ``message_structure`` -- are reachable *solely* through this
#: loop, which is what makes the loop earn its place and what the pinning test keys on. See the
#: module docstring for the full accounting, including what the pre-ACK path reads that is NOT
#: listed here.
_HL7_ROUTING_PROPERTIES = (
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

#: The X12 interchange-identity properties, read by fixed ISA offset.
_X12_ISA_PROPERTIES = (
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


@dataclass(frozen=True)
class KnownFinding:
    """A contract violation this harness has already produced, filed rather than fixed here.

    Registered for one reason: an advisory job that is red the day it lands gets ignored, and an
    ignored fuzzer is indistinguishable from no fuzzer. So a found-but-unfixed defect is recorded
    with a **narrow** discriminator -- one named structural condition, never a bare exception type --
    and ``tests/test_fuzz_targets.py`` asserts both halves: that ``reproducer`` still provokes the
    violation through the raw parser, and that the target recognises it. The day the underlying
    defect is fixed, that test fails and this entry comes out. It cannot rot silently into a
    suppression that hides its successors.
    """

    target: str
    #: What the parser does, in the conditional -- there are no deployments (CLAUDE.md section 0).
    summary: str
    #: The narrow structural condition the target matches on, in words.
    discriminator: str
    reproducer: bytes


#: Empty today. The one finding this harness produced -- an empty segment (a ``\r\r`` run) parsed,
#: then every named routing property raised ``IndexError`` -- was fixed under BACKLOG #1594, and its
#: entry and the carve-out in :func:`_hl7_peek` came out with it. Its reproducer stays on as the
#: :data:`BLANK_SEGMENT_HL7` seed, and ``tests/test_fuzz_targets.py`` drives it, so the fix cannot
#: quietly regress.
KNOWN_FINDINGS: tuple[KnownFinding, ...] = ()


def _hl7_peek(data: bytes) -> None:
    """``Peek.parse`` plus a sweep of the accessor tier (see the module docstring for which).

    There is no carve-out: every exception other than the contracted ``HL7PeekError`` escapes, and
    ``tests/test_fuzz_targets.py`` pins that with injected faults.
    """
    try:
        peek = Peek.parse(data)
    except HL7PeekError:
        return  # The contract: these bytes are not an HL7 message at all.
    for name in _HL7_ROUTING_PROPERTIES:
        getattr(peek, name)
    peek.routing()
    peek.segments()


def _walk_tree(node: TreeNode) -> None:
    """Touch every label and value in a parsed tree.

    HL7 nesting is bounded at segment/field/repetition/component/subcomponent, so a plain recursive
    walk cannot run away on a mutated input.
    """
    _ = (node.label, node.value)
    for child in node.children:
        _walk_tree(child)


def _hl7_tree(data: bytes) -> None:
    """``parse_tree`` -- the tolerant structural view the harness's parse-tree pane renders."""
    try:
        nodes = parse_tree(data)
    except HL7PeekError:
        return
    for node in nodes:
        _walk_tree(node)


def _x12_peek(data: bytes) -> None:
    """``X12Peek.parse`` plus the ISA identity properties and the segment/group walk."""
    try:
        peek = X12Peek.parse(data)
    except X12Error:
        return
    for name in _X12_ISA_PROPERTIES:
        getattr(peek, name)
    peek.groups()
    peek.transaction_ids()
    peek.segment_ids()


def _dicom_peek(data: bytes) -> None:
    """``DicomPeek.parse``.

    The result is a frozen dataclass of already-materialised strings, so there is no accessor tier
    to exercise -- unlike HL7 and X12, ``parse`` really is the whole surface here. The property
    under test is whether the ``except parse_error_types()`` wrap in ``dicom/peek.py`` covers what
    ``pydicom`` throws at it. It does not cover everything by construction: the tuple is a list of
    the classes found so far, and this target found one it missed (BACKLOG #1893). A gap surfaces
    as a non-``DicomError`` escaping here.
    """
    try:
        DicomPeek.parse(data)
    except DicomError:
        return


@dataclass(frozen=True)
class FuzzTarget:
    """One named fuzz target: a callable over arbitrary bytes, plus its seeds.

    ``run`` returns normally when the parser behaved to contract -- whether it accepted the input or
    rejected it with its own ``ValueError`` subclass -- and raises otherwise. libFuzzer needs no
    more than that: a raised exception is the crash it records and minimises.
    """

    name: str
    summary: str
    run: Callable[[bytes], None]
    seeds: tuple[bytes, ...]
    #: The optional extra this target's parser needs, if any. A target whose extra is absent is
    #: **refused**, never silently skipped -- see :meth:`available`.
    requires_module: str | None = None

    def available(self) -> bool:
        """Whether this target's optional dependency is importable.

        The runner refuses to fuzz an unavailable target rather than passing over it, because a
        target that silently does nothing is the failure this whole harness exists to avoid: a
        clean run and a run that never executed look identical from the outside.
        """
        if self.requires_module is None:
            return True
        return importlib.util.find_spec(self.requires_module) is not None


TARGETS: tuple[FuzzTarget, ...] = (
    FuzzTarget(
        name="hl7_peek",
        summary="tolerant HL7 v2 peek (python-hl7 / built-ins) plus the pre-ACK routing accessors",
        run=_hl7_peek,
        seeds=_sample("adt_a01.hl7") + _sample("adt_batch.hl7") + (_MINIMAL_HL7, BLANK_SEGMENT_HL7),
    ),
    FuzzTarget(
        name="hl7_tree",
        summary="tolerant HL7 v2 structural tree (parsing/tree.py)",
        run=_hl7_tree,
        seeds=_sample("adt_a01.hl7") + (_MINIMAL_HL7,),
    ),
    FuzzTarget(
        name="x12_peek",
        summary="tolerant X12 interchange peek plus the ISA identity and segment walk",
        run=_x12_peek,
        seeds=_sample("x12_270_eligibility.edi") + (_TRUNCATED_X12,),
    ),
    FuzzTarget(
        name="dicom_peek",
        summary="tolerant DICOM Part-10 peek (needs the [dicom] extra)",
        run=_dicom_peek,
        seeds=(_MAGIC_ONLY_DICOM,),
        requires_module="pydicom",
    ),
)

TARGETS_BY_NAME = {target.name: target for target in TARGETS}


def write_seed_corpus(target: FuzzTarget, directory: Path) -> int:
    """Materialise ``target``'s seeds into ``directory`` and return how many were written.

    libFuzzer takes a corpus as a directory of files, and the seeds live in this module as literals
    and committed-sample reads, so somebody has to put them on disk. Each file is named by index
    rather than by content, so a re-run overwrites in place instead of growing the directory.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for index, seed in enumerate(target.seeds):
        (directory / f"seed_{index:03d}").write_bytes(seed)
    return len(target.seeds)


def work_root() -> Path:
    """Base directory for seed corpora and crash artifacts, from :data:`WORK_DIR_ENV` or a temp dir.

    **Outside the repository, and that is the control rather than a convenience.** Every file the
    fuzzer writes here is message-shaped -- a minimised HL7, X12 or DICOM body -- and a corpus grows
    without bound as the fuzzer finds branches, so an overnight run leaves thousands of generated
    message files. Ignoring them would rely on a pattern staying correct; keeping them outside the
    work tree means ``git add -A`` cannot reach them at all, which is how the PHI rule (CLAUDE.md
    section 9) holds by construction instead of by a reviewer noticing.

    **The override is fenced, and "by construction" was false without the fence.** This function
    previously returned ``Path(override)`` unexamined, so the guarantee above held for the default
    and for an absolute path pointing elsewhere -- but a **relative** override resolves against the
    working directory, and ``fuzz/README.md`` tells the operator to run the module from the
    repository root. So ``MEFOR_FUZZ_WORK_DIR=corpus`` put fuzzer-minimised message bodies inside
    the work tree, reachable by ``git add -A``, while this docstring said that could not happen.

    A leading ``~`` is the same fault wearing a disguise, and it is the one the README hands out.
    ``Path("~/mefor-fuzz")`` is *relative*: measured 2026-09-22, it resolves to
    ``<repo root>/~/mefor-fuzz``. A POSIX shell expands the tilde before the value is ever set, so
    the README's recipe is safe on an interactive bash line -- but the expansion belongs to the
    shell, not to the value, and every mechanism that sets an environment variable **without** a
    shell passes the tilde through intact: a quoted assignment, a Dockerfile ``ENV``, a systemd
    unit, a CI ``env:`` block, or a non-POSIX shell such as PowerShell.

    Both halves are fixed: ``expanduser`` first, so the tilde means the same thing however the value
    arrived, then a refusal if the result still lands inside :data:`_REPO_ROOT`. Refusing loudly
    beats writing there quietly. Three reviews checked this function and all three passed an
    absolute path, which is the one shape that cannot show either fault.

    That is also why sharing a seed by committing it is the wrong move: a seed belongs in this
    module, as a committed synthetic sample path or a small inline literal.

    :raises HarnessRefusal: if the override resolves to the repository root or anywhere beneath it.
    """
    override = os.environ.get(WORK_DIR_ENV)
    if override:
        resolved = Path(override).expanduser().resolve()
        if resolved == _REPO_ROOT or _REPO_ROOT in resolved.parents:
            raise HarnessRefusal(
                f"{WORK_DIR_ENV}={override!r} resolves to {resolved}, which is inside the "
                f"repository at {_REPO_ROOT}. The fuzzer writes minimised message bodies there and "
                f"`git add -A` would stage them (CLAUDE.md section 9). Point it outside the work "
                f"tree; note that PowerShell does not expand a leading `~` the way bash does, so "
                f"give an absolute path or use $HOME/mefor-fuzz."
            )
        return resolved
    return Path(tempfile.gettempdir()) / "messagefoundry-fuzz"


def work_paths(target: FuzzTarget) -> tuple[Path, Path]:
    """``(corpus, artifacts)`` for ``target``, both under :func:`work_root`."""
    base = work_root() / target.name
    return base / "corpus", base / "artifacts"


def libfuzzer_argv(argv: Sequence[str], corpus: Path, artifacts: Path) -> list[str]:
    """``argv`` with this harness's defaults appended, never overriding what a caller passed.

    Kept here, beside the targets, rather than in the Atheris entrypoint: that entrypoint cannot be
    imported off Linux, so logic living there would be untestable on most of the CI matrix. The
    defaulting is load-bearing enough to want a test -- if ``-artifact_prefix`` goes missing,
    libFuzzer writes a minimised, message-shaped crash input into the current working directory,
    which is how such a file ends up staged (CLAUDE.md section 9).

    Each default is supplied **only when absent**, because libFuzzer takes the last occurrence of a
    repeated flag: appending unconditionally would silently clobber a caller's own choice.
    """
    result = list(argv)
    supplied = result[1:]
    if not any(arg.startswith("-artifact_prefix=") for arg in supplied):
        # The trailing separator is required -- libFuzzer concatenates prefix and filename.
        result.append(f"-artifact_prefix={artifacts}{os.sep}")
    if not any(arg.startswith("-max_len=") for arg in supplied):
        result.append(f"-max_len={DEFAULT_MAX_LEN}")
    if all(arg.startswith("-") for arg in supplied):
        # libFuzzer's one positional is the corpus directory it reads and grows.
        result.append(str(corpus))
    return result
