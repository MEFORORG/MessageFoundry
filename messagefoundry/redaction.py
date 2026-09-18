# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""PHI redaction for the exception/logging path (WP-6c; ASVS 16.2.5, PHI.md P1-3).

Inbound HL7 is attacker-/PHI-bearing, and a Router/Handler is user code that can do
``raise ValueError(f"bad value in {raw}")`` — which would otherwise carry the full message body into
the stored ``last_error``/``message_events.detail`` and any log line built from it. :func:`safe_exc`
is the **chokepoint**: every exception rendered into a stored disposition or a log is routed through
it, so HL7-structured content is scrubbed while the exception **type** (the useful, non-PHI part) is
kept.

This is a conservative *redaction* of HL7-shaped content — **not** de-identification (that is a
separate, centralized framework; see PHI.md §9). It errs toward over-redaction. Beyond HL7-shaped
spans it also applies a **conservative free-text heuristic** (date/DOB runs + multi-token name runs;
see :func:`redact`), so a delimiter-free leak like ``raise ValueError("patient DOE JANE dob 1980-05-05
not found")`` is narrowed too. The residual is now an adversarially-crafted *single-token* or non-name-
shaped identifier, for which the "never put PHI in an exception message" convention remains the control.

A **file name is exactly that residual**, which is why :func:`safe_name` exists beside the heuristic
rather than inside it: a partner names a drop ``MRN123456789_ADT.hl7`` or ``DOE_JANE_19800505_ADT.hl7``
and every pattern below misses it, because :data:`_NAME_RUN` needs whitespace between the tokens and
:data:`_DATE_RUN` needs a word boundary that ``_`` does not give. A name is derived at the call site
instead of pattern-matched after the fact (BACKLOG #1748).

Pure stdlib (``re`` + ``hashlib``), so it can be used from any engine package.
"""

from __future__ import annotations

import hashlib
import re

__all__ = ["redact", "safe_error", "safe_exc", "safe_name", "safe_text"]

_REDACTED = "[redacted]"
#: Max characters of a (redacted) exception message to keep — a raw HL7 body is long, so bound what
#: reaches a stored ``last_error`` or a log line even after redaction.
_DEFAULT_LIMIT = 200

#: An HL7 **segment** span: a 3-char segment ID (``MSH``/``PID``/``OBX``/…) immediately followed by the
#: field separator and field data to end-of-line. Catches a raw message (or fragment) embedded in an
#: exception — the realistic vector. The segment ID is kept (not PHI, useful); the field data is cut.
_HL7_SEGMENT = re.compile(r"\b([A-Z][A-Z0-9]{2})\|[^\r\n]*")
#: A run carrying **≥2 HL7 delimiters** (``| ^ ~ &``) — a field/component dump like ``100^^^H^MR`` or
#: ``DOE^JANE^M`` that may be PHI even without a segment header.
#:
#: **Two guards, and the possessive one alone did not deliver what it claimed (BACKLOG #1437).** The
#: non-delimiter runs use **possessive** quantifiers (``*+``, Python 3.11+): the char classes are
#: disjoint from the delimiters, so possessive matching cannot change *what* matches, and it removes
#: backtracking inside a single match attempt. That saving is real but small, about 2x, and it does
#: **not** make the scan linear, because the cost here was never backtracking. The leading
#: ``[^\s|^~&]*+`` can match empty, so the engine RESTARTS the pattern at every offset, and inside one
#: long delimiter-free run each restart re-scans the rest of the run. That is quadratic either way.
#: Measured 2026-09-03: a 20,000-character run cost **1.05 s** possessive and **2.09 s** greedy.
#:
#: The leading ``(?<![^\s|^~&])`` is what makes it linear. It admits a match only where the previous
#: character is whitespace, a delimiter, or start-of-string, so a delimiter-free run gets ONE attempt
#: instead of one per character and every other offset fails the lookbehind in constant time. Same
#: input, same box: **0.37 ms**, about 2,800x faster. It is the exact complement of the character class
#: that follows it, so it cannot change what matches — verified against the pre-guard pattern over
#: 200,000 randomized delimiter-heavy strings with zero disagreements. ``\b`` would NOT do: ``-``,
#: ``.`` and ``:`` are word boundaries but are also inside ``[^\s|^~&]``, so ``\b`` would drop them
#: from the front of a redacted span.
#:
#: This matters because the input is not bounded. :func:`safe_text` truncates *after* :func:`redact`
#: has run, and the logging handler filter in :mod:`messagefoundry.logging_setup` redacts whole
#: rendered tracebacks with no bound at all — on whatever thread emitted the record, which for the
#: engine is the asyncio event loop.
_HL7_FIELD_RUN = re.compile(r"(?<![^\s|^~&])[^\s|^~&]*+[|^~&][^\s|^~&]*+(?:[|^~&][^\s|^~&]*+)+")

#: A **date / birthdate run** in free text: an ISO ``YYYY-MM-DD`` / US ``MM-DD-YYYY`` (``-`` or ``/``
#: separator) or a bare HL7 8-digit ``YYYYMMDD``. A DOB is a direct identifier, and a free-text leak like
#: ``"... dob 1980-05-05 ..."`` carries no HL7 delimiter, so :func:`_HL7_FIELD_RUN` misses it. The
#: alternatives use fixed-width digit runs (no unbounded repetition), so the scan stays linear.
_DATE_RUN = re.compile(
    r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b|\b\d{1,2}[-/]\d{1,2}[-/]\d{4}\b|\b(?:19|20)\d{6}\b"
)
#: A **multi-token name run**: 2–4 adjacent ``Capitalized`` (a capital then lowercase) *or* ``ALLCAPS``
#: tokens — e.g. ``DOE JANE`` / ``Doe Jane``. Requiring **≥2** adjacent tokens is deliberate: a single
#: capitalized operational word (``Connection``, ``Timeout``, ``ValueError``, a logger/class name) is
#: NOT touched, so ordinary ops text survives; CamelCase-without-a-space is likewise untouched. Bounded
#: ``{1,3}`` repetition over disjoint char classes keeps the scan linear (no catastrophic backtracking),
#: mirroring the linear-scan rationale on :data:`_HL7_FIELD_RUN`. The literal ``[redacted]`` token can
#: never re-match (its lowercase-led ``[redacted]`` is a single token wrapped in brackets, not a ≥2-token
#: run), so :func:`redact` stays a fixed point.
_NAME_RUN = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b|\b[A-Z]{2,}(?:\s+[A-Z]{2,}){1,3}\b")

#: Hex characters of the :func:`safe_name` digest kept. Long enough that two names in one directory do
#: not collide in practice, short enough to read in a log line.
_NAME_DIGEST_CHARS = 12
#: The **complete** set of trailing extensions :func:`safe_name` may keep — matched case-insensitively
#: and emitted lower-cased, so the label's suffix is drawn from this fixed list of literals and nothing
#: partner-chosen passes through at all.
#:
#: **A LENGTH BOUND WAS THE WRONG SHAPE, AND THE PROSE BESIDE IT CLAIMED A DEFENCE IT DID NOT GIVE
#: (BACKLOG #1748).** This was ``re.compile(r"\.[A-Za-z0-9]{1,8}\Z")``, described as *"the bound is
#: what makes the extension safe to pass through — a partner-chosen ``patient.MRN123456789`` fails it
#: and contributes nothing"*. That is true of the one example and false of the shapes a partner
#: actually names a drop, because any segment of eight-or-fewer alphanumerics qualified and a dotted
#: identifier is exactly that. Measured on the pre-fix code, with the kept segment in **bold**:
#: ``ACC.12345678.hl7`` kept **.12345678** (an accession), ``patient.MRN12345.hl7`` kept **.MRN12345**
#: (an MRN token), ``DOE.19800505.hl7`` kept **.19800505** and ``A.87654321.txt`` kept **.87654321**.
#: Nine characters failed the bound and eight passed it, so the bound never separated an extension
#: from an identifier — it separated a long identifier from a short one. The birthdate case is the
#: sharpest: :data:`_DATE_RUN` exists to catch a bare ``YYYYMMDD`` and the extension arm routed one
#: straight past it. A control whose stated reason does not hold is a defect in the prose as much as
#: in the code (CLAUDE.md §11, SDS-3.7), so both are replaced here.
#:
#: An allowlist says what the bound was reaching for and closes the hole instead of moving it: a
#: segment is kept only when it **is** a format marker this product reads or writes. Every entry is
#: derived from engine code rather than from a list of plausible extensions:
#:
#: * ``parsing/sniff.py`` ``_EXTENSION_CONTENT_TYPE`` — the engine's own extension-to-``ContentType``
#:   map for archive-member admission (ASVS 5.2.2): ``.hl7 .json .fhir .xml .dcm .edi .x12``.
#: * ``parsing/sniff.py`` ``_EXTENSION_MAGIC`` — the container/attachment formats it admits by leading
#:   magic bytes: ``.pdf .png .jpg .jpeg .gif .tif .tiff .zip .gz``.
#: * ``uploads.py`` ``_ALLOWED_UPLOAD_EXTENSIONS`` / ``content_type_for`` — ``.hl7v2`` and ``.txt``.
#:
#: ``.gz`` earns its place twice over: the FILE destination's gzip mode appends it to the rendered
#: name itself (``transports/file.py``), which is where ``.hl7.gz`` comes from.
#:
#: Deliberately **not** imported from those modules. This module is pure stdlib on purpose (see the
#: module docstring) so any engine package can use it, and importing ``parsing`` here would put the
#: parser underneath the logging chokepoint. What is duplicated is a list of literals, not logic, and
#: ``tests/test_redaction.py`` asserts each source map is a subset of this set, so the two cannot
#: drift apart silently.
#:
#: A marker this list does not carry is simply dropped, which costs a log line some legibility and
#: nothing else — :func:`safe_name` feeds log text and :func:`safe_exc`, never a filesystem or
#: routing decision — and the label stays stable and distinguishing either way.
_SAFE_SUFFIXES = frozenset(
    {
        ".hl7",
        ".hl7v2",
        ".json",
        ".fhir",
        ".xml",
        ".dcm",
        ".edi",
        ".x12",
        ".txt",
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".tif",
        ".tiff",
        ".zip",
        ".gz",
    }
)
#: How many trailing extensions :func:`safe_name` keeps. Two, so the gzip mode's ``.hl7.gz`` — a name
#: the File destination itself builds — stays legible instead of collapsing to ``.gz``.
_SAFE_SUFFIX_MAX = 2


def _basename(name: str) -> str:
    """The last path component of ``name``, taking either separator. Callers pass a basename already;
    this makes the name helpers total rather than trusting that."""
    return name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _safe_suffixes(base: str) -> str:
    """The trailing extension(s) of ``base``, taken right to left and kept while each is a known format
    marker (:data:`_SAFE_SUFFIXES`, case-insensitive). Stops at the first segment that is not one, so
    the result is always a concatenation of at most :data:`_SAFE_SUFFIX_MAX` literals from that set —
    no part of a partner's name is ever carried through.

    A dot at position 0 is not an extension (``.hl7`` names a dotfile, it does not extend one), which
    is the same convention ``parsing/sniff.py`` ``_member_extension`` applies to an archive member."""
    kept: list[str] = []
    stem = base
    while len(kept) < _SAFE_SUFFIX_MAX:
        dot = stem.rfind(".")
        if dot <= 0:
            break
        suffix = stem[dot:].lower()
        if suffix not in _SAFE_SUFFIXES:
            break
        kept.append(suffix)
        stem = stem[:dot]
    return "".join(reversed(kept))


def redact(text: str) -> str:
    """Scrub HL7 segment/field content (potential PHI) from free text, keeping segment IDs, then apply a
    conservative free-text heuristic for delimiter-free identifiers. Conservative (errs toward over-
    redaction); the goal is that a raw HL7 body — or a free-text name/DOB — embedded in an exception
    message can't reach a log or the stored ``last_error``/``detail``. NOT de-identification (PHI.md §9).

    Order matters: HL7-shaped content (:data:`_HL7_SEGMENT`, then :data:`_HL7_FIELD_RUN`) is handled
    first, so the free-text passes (:data:`_DATE_RUN`, then :data:`_NAME_RUN`) only see delimiter-free
    text. The free-text heuristic narrows the prior residual to adversarial *single-token* identifiers
    (a lone name with no second token, no date) — for which the "never put PHI in an exception message"
    convention remains the control. Idempotent: the literal ``[redacted]`` substituted in never re-
    matches any pattern, so ``redact(redact(x)) == redact(x)``."""
    if not text:
        return text
    scrubbed = _HL7_SEGMENT.sub(lambda m: f"{m.group(1)}|{_REDACTED}", text)
    scrubbed = _HL7_FIELD_RUN.sub(_REDACTED, scrubbed)
    scrubbed = _DATE_RUN.sub(_REDACTED, scrubbed)
    return _NAME_RUN.sub(_REDACTED, scrubbed)


def safe_text(text: str, *, limit: int = _DEFAULT_LIMIT) -> str:
    """A PHI-redacted, length-bounded rendering of a free-text diagnostic string — the string analog of
    :func:`safe_exc`, for error/detail text that isn't an exception object (joined strict-validation
    errors, a ``last_error`` built at the store layer, a connector's reply-parse note). HL7-shaped content
    is scrubbed (:func:`redact`) and the result truncated. Idempotent on already-:func:`safe_text`'d
    input (``redact`` is a fixed point once delimiter runs are gone), so it is safe to re-apply as a
    store-layer chokepoint over values a caller may already have scrubbed."""
    message = redact(text).strip()
    if len(message) > limit:
        message = f"{message[:limit]}…(+{len(message) - limit} chars)"
    return message


def safe_error(error: str | None, *, show_phi: bool = False) -> str | None:
    """A PHI-redacted rendering of an **optional** diagnostic string, for a caller that may hold a
    ``--show-phi``-style opt-in. ``None`` passes through as ``None`` (an absent error is not a value to
    redact, and the CLIs emit it as JSON ``null``); otherwise the text goes through :func:`safe_text`
    unless ``show_phi`` says the caller may see it.

    **Why this exists rather than the guard being written at each call site (BACKLOG #1668).** The
    ``error`` of a :class:`~messagefoundry.pipeline.dryrun.DryRunResult` is the one field every consumer
    has to make the same decision about, and that decision was previously made nowhere: ``dryrun``,
    ``dryrun --trace`` and the ``check`` gate each emitted it verbatim. It carries a Router/Handler's own
    ``raise``, and ``raise ValueError(f"bad MRN {msg['PID-3']}")`` is the commonest debugging idiom, so
    it can quote field values.

    **:func:`safe_text`, not a whole-string drop.** The stage prefix (``"router/handler error: "``,
    ``"parse error: "``) and the author's own prose are the diagnostic somebody ran the tool to read;
    only the HL7-shaped runs inside them are PHI. Dropping the string wholesale would close the leak by
    removing the feature. :func:`safe_exc` is not reachable at these call sites — a consumer holds a
    string that was already built, never the exception object.

    **``show_phi`` defaults to closed, and a surface that must never open is expected to omit it.** The
    ``check`` gate passes no keyword at all: its stdout goes to a commit hook and a CI log by design, so
    an opt-in there would put PHI in that log on request — the opposite of the control."""
    if error is None or show_phi:
        return error
    return safe_text(error)


def safe_name(name: str) -> str:
    """A PHI-safe stand-in for a **partner-chosen file name**, for a log line: a short SHA-256 prefix
    over the basename plus its extension, wrapped so it can never be mistaken for a real name — e.g.
    ``[name:9f2c41a0be77.hl7]``.

    **Why a name needs its own helper rather than :func:`redact` (BACKLOG #1748).** A drop named
    ``MRN123456789_ADT.hl7`` or ``DOE_JANE_19800505_ADT.hl7`` passes every pattern in this module
    unchanged: :data:`_NAME_RUN` requires ``\\s+`` between its tokens and :data:`_DATE_RUN` requires a
    word boundary before the digits, and a file name supplies neither. The fix is therefore at the call
    site — derive a safe label instead of hoping a heuristic catches the name after the fact.

    **It identifies, it does not de-identify.** The digest lets an operator tell two files apart and
    recognise the same stuck file across polls; it is not reversible in practice, but a caller must not
    treat it as a de-identification primitive (that is the separate framework, PHI.md §9).

    **Deliberately NOT built from a source's ``_file_key``.** That key folds the relative/remote path
    plus mtime+size because a dedup ledger must never collide two distinct files. This label folds the
    **basename only**, so two same-named files in different subdirectories share a label — harmless in a
    log, wrong in a ledger. Keeping them separate also means no log call has to ``stat()`` a file on the
    very error arm that is reporting the file went missing. A byte length, where the caller has one
    already, belongs beside this label as its own log argument rather than folded in here.

    The only thing kept beside the digest is up to two trailing **known format markers** — an
    allowlist, not a shape (:data:`_SAFE_SUFFIXES`, which records why a length bound was not enough and
    what each entry is derived from). Two of them, so ``.hl7.gz`` survives the gzip mode intact. A
    ``patient.MRN12345`` therefore contributes nothing: its trailing segment is not a format marker,
    whatever its length."""
    base = _basename(name)
    digest = hashlib.sha256(base.encode("utf-8", "surrogatepass")).hexdigest()
    return f"[name:{digest[:_NAME_DIGEST_CHARS]}{_safe_suffixes(base)}]"


def safe_exc(
    exc: BaseException, *, limit: int = _DEFAULT_LIMIT, file_name: str | None = None
) -> str:
    """A PHI-redacted, length-bounded rendering of ``exc`` for a stored ``last_error``/``detail`` or a
    log line. Always keeps the exception **type** (safe + most useful); the message is redacted
    (:func:`redact`) and truncated — so a Router/Handler that did ``raise ValueError(f"...{raw}")``
    can't leak the HL7 body into the store or logs.

    ``file_name`` is the partner-chosen name the exception is **about**, for a caller that has one. An
    ``OSError`` renders its path INTO its message — Windows gives ``[WinError 32] The process cannot
    access the file because it is being used by another process:
    'C:\\\\drops\\\\MRN123456789_ADT.hl7'`` — and :func:`redact` is measured blind to a file name
    (BACKLOG #1748), so swapping :func:`safe_name` in has to happen where the name is known. Without
    it, routing a file source's error arm through this function would keep the OS diagnostic and leak
    the name anyway: a control that reports success while the hole stays open. The basename is
    replaced wherever it appears, so a full path is covered; the directory part is operator
    configuration, not partner-chosen, and stays."""
    name = type(exc).__name__
    raw = str(exc)
    if file_name and (base := _basename(file_name)):
        raw = raw.replace(base, safe_name(file_name))
    message = safe_text(raw, limit=limit)
    return f"{name}: {message}" if message else name
