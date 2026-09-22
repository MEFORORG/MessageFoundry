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
reads routing fields off the result. So each target parses *and then* exercises the accessors the
inbound path actually touches. Fuzzing ``parse`` alone would have missed the one finding this
harness has already produced (see :data:`KNOWN_FINDINGS`).

**PHI (CLAUDE.md section 9).** Seeds are the repository's committed synthetic samples plus small
inline literals -- no new message-shaped files, and never real PHI. No target prints a body, and the
runner keeps its corpus and crash artifacts **outside the work tree** (see :func:`work_root`), so a
fuzzer-minimised input cannot be staged even by ``git add -A``.
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

#: Override to keep a persistent corpus somewhere of your own choosing.
WORK_DIR_ENV = "MEFOR_FUZZ_WORK_DIR"

#: Inputs longer than this are not interesting here. Every tolerant parser enforces its own size
#: ceiling well below it and rejects past that with its contract error, so a larger ``max_len`` just
#: spends the budget re-confirming the ceiling instead of exploring parse branches.
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
_MINIMAL_HL7 = b"MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\r"
_TRUNCATED_X12 = b"ISA*00*          *00*"
_MAGIC_ONLY_DICOM = b"\x00" * 128 + b"DICM"

#: The HL7 routing properties the inbound path reads off a ``Peek``. Every one of these is on the
#: pre-ACK path, so an exception here is an exception before the sender is answered.
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


#: An empty segment -- a bare separator run such as ``\\r\\r`` -- parses, and then every named
#: routing property raises ``IndexError``. ``_resolve_builtin`` calls
#: ``_builtin_hl7.raise_if_blank_segment_scan`` OUTSIDE its own ``except (IndexError, ValueError)``,
#: deliberately, so that a blank segment errors the way the legacy python-hl7 path errors. The
#: consequence is that the escaping exception is not a ``ValueError``, so the documented
#: ``except ValueError`` dead-letter route does not catch it. ``_peek_for_loopback``
#: (``pipeline/wiring_runner.py``) catches ``HL7PeekError`` only and then reads ``control_id`` and
#: ``message_type``, so on first deployment a loopback re-ingress of such a message would raise
#: through the worker instead of recording the intended ``peek_failed`` / RECEIVED-to-ERROR
#: disposition. Reported with the branch; not fixed here, because changing which exception the
#: tolerant tier raises is a semantics decision beyond this harness.
_HL7_BLANK_SEGMENT = KnownFinding(
    target="hl7_peek",
    summary=(
        "a message carrying an empty segment parses, then every named routing property raises "
        "IndexError rather than the contracted HL7PeekError"
    ),
    discriminator="the parsed message has a segment whose id is the empty string",
    reproducer=b"MSH|^~\\&|APP|FAC|R|RF|20260101||ADT^A01|MSG1|P|2.5\rPID|1||X\r\rPV1|1|I\r",
)

KNOWN_FINDINGS: tuple[KnownFinding, ...] = (_HL7_BLANK_SEGMENT,)


def _hl7_has_blank_segment(peek: Peek) -> bool:
    """Whether the parsed message carries a segment with an empty id.

    The discriminator for :data:`_HL7_BLANK_SEGMENT`. ``Peek.segments()`` returns segment ids, so an
    empty string in that list is a blank segment and nothing else is.
    """
    return any(not segment for segment in peek.segments())


def _hl7_peek(data: bytes) -> None:
    """``Peek.parse`` plus the routing accessors the inbound path reads before the ACK."""
    try:
        peek = Peek.parse(data)
    except HL7PeekError:
        return  # The contract: these bytes are not an HL7 message at all.
    try:
        for name in _HL7_ROUTING_PROPERTIES:
            getattr(peek, name)
        peek.routing()
        peek.segments()
    except IndexError:
        if _hl7_has_blank_segment(peek):
            return  # KNOWN_FINDINGS: _HL7_BLANK_SEGMENT.
        raise


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
    to exercise -- unlike HL7 and X12, ``parse`` really is the whole surface here. The interesting
    property is that the ``except parse_error_types()`` wrap in ``dicom/peek.py`` covers everything
    ``pydicom`` can throw at it: that tuple names ``AttributeError``, ``KeyError``, ``IndexError``
    and ``struct.error`` explicitly, and a gap in it surfaces as a non-``DicomError`` escaping here.
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
        seeds=_sample("adt_a01.hl7") + _sample("adt_batch.hl7") + (_MINIMAL_HL7,),
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

    **Outside the repository by default, and that is the control rather than a convenience.** Every
    file the fuzzer writes here is message-shaped -- a minimised HL7, X12 or DICOM body -- and a
    corpus grows without bound as the fuzzer finds branches, so an overnight run leaves thousands of
    generated message files. Ignoring them would rely on a pattern staying correct; putting them
    outside the work tree means ``git add -A`` cannot reach them at all, which is how the PHI rule
    (CLAUDE.md section 9) holds by construction instead of by a reviewer noticing.

    That is also why sharing a seed by committing it is the wrong move: a seed belongs in this
    module, as a committed synthetic sample path or a small inline literal.
    """
    override = os.environ.get(WORK_DIR_ENV)
    if override:
        return Path(override)
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
