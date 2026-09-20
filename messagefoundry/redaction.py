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
not found")`` is narrowed too. The delimiters are **read from MSH** rather than assumed, so a feed
declaring ``*`` and ``$`` is covered too (:func:`_sniff_delimiters`, BACKLOG #1572).

Two residuals, and this module claims no completeness beyond them: an adversarially-crafted
*single-token* or non-name-shaped identifier, and a **headerless** custom-delimiter fragment (no MSH,
so nothing declares its delimiters). For both, the "never put PHI in an exception message" convention
remains the control.

A **file name is exactly the first of those residuals**, which is why :func:`safe_name` exists beside
the heuristic rather than inside it: a partner names a drop ``MRN123456789_ADT.hl7`` or
``DOE_JANE_19800505_ADT.hl7`` and every pattern below misses it, because :data:`_NAME_RUN` needs
whitespace between the tokens and :data:`_DATE_RUN` needs a word boundary that ``_`` does not give. A
name is derived at the call site instead of pattern-matched after the fact (BACKLOG #1748).

**THE INPUT IS BOUNDED BEFORE IT IS SCANNED, AND THE CUT IS THE WHOLE DIFFICULTY (BACKLOG #1576).** A
remote peer chooses the length: an MLLP negative acknowledgment's MSA-3 runs to the frame cap, and a
Router that quotes the received body raises a message the body's size. The scan is linear (BACKLOG
#1437) and linear is not free — measured on a 16 MiB input, 0.29 s of segment-shaped text and 0.78 s
of delimiter-free prose, every millisecond of it on the asyncio event loop. :func:`clamp_untrusted`
cuts an over-long string to :data:`_REDACT_WINDOW` first.

**Redacting ``text[:limit]`` is the obvious form of that and it leaks.** A cut lands mid-run, strands
the surviving fragment below the two-delimiter threshold :data:`_HL7_FIELD_RUN` needs or the two-token
threshold :data:`_NAME_RUN` needs, and the patient name the pattern existed to catch walks through
into the log. So the cut is made where no pattern here can straddle it and the tokens it could have
split are dropped whole — never emitted in part. Over-redaction at the boundary is the deliberate
price.

Pure stdlib (``re``, ``hashlib``, ``string``), so it can be used from any engine package.
"""

from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from string import ascii_lowercase, ascii_uppercase, whitespace

__all__ = [
    "clamp_untrusted",
    "redact",
    "redact_untrusted",
    "safe_error",
    "safe_exc",
    "safe_name",
    "safe_text",
]

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
#: This matters because the scan runs on whatever thread emitted the record, which for the engine is
#: the asyncio event loop.
#:
#: **The input is no longer unbounded, and that does not retire the guard (BACKLOG #1576).** It used to
#: be: :func:`safe_text` truncated *after* this pattern had run, and the logging handler filter in
#: :mod:`messagefoundry.logging_setup` redacted whole rendered tracebacks with no bound at all.
#: :func:`clamp_untrusted` now cuts both to :data:`_REDACT_WINDOW` first. But that window is three
#: orders of magnitude above what a diagnostic needs, deliberately, so a quadratic scan across it
#: would still stall the loop. **Linear is what makes a window that generous affordable**, and the
#: bound is what keeps a linear scan from being charged 16 MiB of a peer's choosing.
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

#: The delimiters every pattern above hardcodes — field ``|``, component ``^``, repetition ``~``,
#: subcomponent ``&``. **HL7 does not fix these; MSH declares them per message** (see the "read
#: encoding characters from MSH" rule), so a feed using ``*`` and ``$`` walked its identifiers straight
#: through this module. BACKLOG #1572. The escape character (``\`` by default) is deliberately absent:
#: it is not a field boundary, and it is ordinary in a Windows path.
_DEFAULT_DELIMITERS = frozenset("|^~&")

#: Characters that may never be adopted as a sniffed delimiter. A run holding two of them would match
#: :data:`_REDACTED` itself, which would break the fixed-point property :func:`safe_text` relies on when
#: it re-applies :func:`redact` at the store-layer chokepoint. Derived from the placeholder so the two
#: cannot drift apart. Letters and digits are already excluded by :data:`_MSH_DELIMITERS`.
_UNSAFE_DELIMITERS = frozenset(_REDACTED)

#: MSH-1 and MSH-2 at the offsets HL7 declares them: the **field separator** is the single character
#: immediately after ``MSH``, and the **encoding characters** are the field that follows it. So one
#: bounded regex recovers a message's real delimiter set with no parser and no import — and
#: ``messagefoundry.parsing`` is deliberately not imported here, even though its
#: ``_extract_separators`` does the same O(1) read: this module is pure stdlib by design, and 21
#: engine modules depend on that (measured 2026-09-15).
#:
#: ``[^\w\s]`` holds the sniff to punctuation. HL7 wants non-alphanumeric delimiters, and the
#: restriction also bounds the blast radius of a hostile header: a message declaring ``e`` as its field
#: separator would otherwise turn every word in a rendered traceback into a redactable run.
#:
#: **``{4,5}`` is a detector's threshold, not a parser's, and it is deliberately stricter than
#: ``parsing._builtin_hl7._extract_separators``.** That function reads a line already known to be an
#: MSH; this one has to tell an MSH apart from prose that merely mentions one. Measured while building
#: this: a looser bound read a delimiter set out of this module's OWN docstrings wherever a segment id
#: sat inside markdown emphasis or backticks, adopting an asterisk or a backtick as the field separator
#: and over-redacting the source lines a traceback quotes. Four encoding characters is what every
#: conformant message carries (five since 2.7, with the truncation character); a message with a SHORT
#: MSH-2 and a custom field separator is not sniffed, which is a further stated residual.
#:
#: It is still a heuristic. A punctuation-dense string of exactly the right shape can fool it, and the
#: cost of being fooled is over-redaction of that text, never a leak.
#:
#: ``BHS``/``FHS`` carry the same declaration at the same offsets and open a batch file, so they are
#: read too.
_MSH_DELIMITERS = re.compile(r"(?:MSH|BHS|FHS)(?P<fs>[^\w\s])(?P<enc>[^\w\s]{4,5})(?P=fs)")

#: Offsets inside MSH-2: component, repetition, escape, subcomponent, truncation. Index 2 — the escape
#: character — is skipped for the reason given on :data:`_DEFAULT_DELIMITERS`, and index 4 because the
#: truncation character is not a field boundary either.
_ENCODING_OFFSETS = (0, 1, 3)


def _sniff_delimiters(text: str) -> frozenset[str]:
    """The HL7 delimiters ``text`` actually declares, unioned over every MSH header it carries.

    Returns an empty set for text with no MSH header, which is the accepted residual: a headerless
    custom-delimiter fragment declares nothing, so there is nothing to recover and it passes through
    (``mrn MRN123$$$H$MR here`` still survives). This claims no completeness — the "never put PHI in an
    exception message" convention remains the control there, as it does for a single-token identifier."""
    found: set[str] = set()
    for match in _MSH_DELIMITERS.finditer(text):
        encoding = match.group("enc")
        found.add(match.group("fs"))
        found.update(encoding[i] for i in _ENCODING_OFFSETS if i < len(encoding))
    return frozenset(found - _UNSAFE_DELIMITERS)


@lru_cache(maxsize=16)
def _delimiter_patterns(delimiters: frozenset[str]) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Segment and field-run patterns over ``delimiters`` — the separator-aware analogues of
    :data:`_HL7_SEGMENT` and :data:`_HL7_FIELD_RUN`, compiled once per delimiter set.

    The field run carries the same lookbehind guard and possessive quantifiers as the hardcoded
    one, so the linear-scan property BACKLOG #1437 bought is not given back on this path: the
    lookbehind is the exact complement of the class that follows it, so a delimiter-free run gets one
    match attempt rather than one per character."""
    chars = "".join(re.escape(delimiter) for delimiter in sorted(delimiters))
    segment = re.compile(rf"\b([A-Z][A-Z0-9]{{2}})([{chars}])[^\r\n]*")
    field_run = re.compile(
        rf"(?<![^\s{chars}])[^\s{chars}]*+[{chars}][^\s{chars}]*+(?:[{chars}][^\s{chars}]*+)+"
    )
    return segment, field_run


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


# --- bounding the input (BACKLOG #1576) --------------------------------------

#: How much of an over-long string :func:`clamp_untrusted` lets the scan see. Three orders of magnitude
#: above :data:`_DEFAULT_LIMIT`, so no diagnostic anybody writes on purpose is ever cut, and small
#: enough that the worst-shaped input costs the event loop single-digit milliseconds: measured on this
#: module's own patterns, 64 KiB is 1.6 ms of segment-shaped text and about 3 ms of delimiter-free
#: prose, against 0.29 s and 0.78 s for the same shapes at a 16 MiB MLLP frame cap.
#:
#: The number bounds the SCAN, not the answer: :func:`safe_text` still cuts its result to
#: :data:`_DEFAULT_LIMIT`, and a caller that keeps the whole redacted text (the logging handler filter)
#: keeps a window's worth of it.
_REDACT_WINDOW = 64 * 1024

#: The most tokens :data:`_NAME_RUN` can join into one match (``X(\s+X){1,3}``). The cut consumes one
#: of them — whatever the window split — so the walk below drops at most three more, and three is
#: exactly enough: a run straddling the cut has at least one token past it, so at most three of its
#: tokens are on the kept side.
_NAME_RUN_MAX_TOKENS = 4

#: The characters :func:`_clamp` may cut at. Whitespace is the boundary because it is the one place
#: three of the four patterns provably cannot cross: :data:`_HL7_FIELD_RUN` and :data:`_DATE_RUN` are
#: built from classes that exclude ``\s`` outright, and :data:`_HL7_SEGMENT` goes on matching from its
#: own header whatever is cut off its tail. Only :data:`_NAME_RUN` spans whitespace, and the token walk
#: in :func:`_clamp` is there for that one pattern.
#:
#: ``string.whitespace`` searched with :meth:`str.rfind`, rather than ``\s`` through the regex engine:
#: a right-to-left search is what this needs and ``re`` only scans left to right. The stdlib name is
#: also the claim — ASCII whitespace, a strict subset of ``\s``, which is the direction that stays
#: safe: every character in it is one the patterns cannot cross, and a Unicode space it misses only
#: means the cut falls further back and drops more.
_CUT_CHARS = whitespace


def _clamp_marker(dropped: int) -> str:
    """The note put in place of what :func:`_clamp` dropped.

    Written so :func:`redact` passes it through untouched, which keeps the fixed-point property
    :func:`safe_text` relies on: no ``|^~&`` pair, no capitalized token that could pair into a
    :data:`_NAME_RUN`, and the count carries ``_`` separators so an eight-digit one can never be read
    as a bare ``YYYYMMDD`` by :data:`_DATE_RUN`.

    **No leading separator, because the right one differs by caller and one of them is not a space.**
    :func:`clamp_untrusted` hands its result to :func:`redact`, and :data:`_HL7_SEGMENT` matches
    ``[^\\r\\n]*`` — to end of LINE, not to end of token — so a clamped head that opens a segment-like
    line swallows a space-joined note into its own ``[redacted]``. Measured while building this, on a
    record of unbroken ``PID|…`` text: an 8 MiB message rendered as ``PID|[redacted]`` with no sign it
    had been cut. A newline is outside that class and ends the match. :func:`safe_text` appends AFTER
    redaction, where nothing can reach the note, and uses a space so a stored ``last_error`` stays one
    line."""
    return f"[redaction bound: dropped {dropped:_d} more chars unscanned]"


#: Room reserved for :func:`_clamp_marker` and its joiner inside the window, so a clamped string is
#: never longer than the window that produced it and re-clamping it is a no-op. **Idempotence is
#: load-bearing, not tidiness:** ``_install_phi_filters`` attaches one filter chain per handler, so a
#: record going to both stdout and the off-box forwarder is scrubbed twice and the two sinks must not
#: disagree.
#:
#: **Derived, not hand-tuned.** The widest note this can produce carries the largest count a string
#: length can be, so build that one and measure it. A literal here would state a rule the code did not
#: perform, and re-wording the note could overrun it silently.
_CLAMP_MARKER_BUDGET = len(_clamp_marker(2**63 - 1)) + 1  # + the newline joiner


def _ends_with_name_token(token: str) -> bool:
    """Whether ``token`` ends with something :data:`_NAME_RUN` could join to a *following* token across
    the whitespace after it — ``[A-Z][a-z]+`` or ``[A-Z]{2,}`` sitting at the token's end.

    The token's END is the question because the whitespace that follows it is where the cut fell. It
    asks about a trailing shape rather than the whole token so a run that starts mid-token is still
    seen: ``(DOE JANE`` is a name run to :data:`_NAME_RUN` (``\\b`` sits after the bracket), and a
    whole-token test would have kept ``(DOE`` behind at the cut.

    **Not the one-line regex that says the same thing.** Anchored
    ``(?:[A-Z][a-z]+|[A-Z]{2,})\\Z`` is retried at every offset in the token, which is quadratic in the
    token length — the exact cost this whole change exists to bound, reintroduced inside the fix for
    it. :meth:`str.rstrip` is the right-to-left scan this wants and it reads each character once."""
    stem = token.rstrip(ascii_lowercase)
    if len(stem) < len(token):  # a trailing [a-z]+ run, so the shape can only be [A-Z][a-z]+
        return bool(stem) and stem[-1] in ascii_uppercase
    return len(token) >= 2 and token[-1] in ascii_uppercase and token[-2] in ascii_uppercase


def _last_cut(text: str, end: int) -> int:
    """Index of the last :data:`_CUT_CHARS` character in ``text[:end]``, or ``-1`` if there is none."""
    return max(text.rfind(char, 0, end) for char in _CUT_CHARS)


def _clamp(text: str, window: int) -> tuple[str, int]:
    """``(head, dropped)`` — ``text`` cut to at most ``window`` characters at a boundary no pattern in
    this module can straddle, and how many characters that cost.

    ``dropped == 0`` means the text fit and ``head is text``, so every caller is byte-identical to its
    pre-#1576 self on everything short enough to read.

    **The cut ALWAYS lands on whitespace or on zero, and never at an arbitrary offset.** A whitespace
    cut is what covers :data:`_HL7_SEGMENT`, :data:`_HL7_FIELD_RUN` and :data:`_DATE_RUN`: none of them
    can contain whitespace, and the segment goes on matching from its header however much of its tail
    is gone. Cut anywhere else and a run carrying two delimiters can lose one of them and fall under
    :data:`_HL7_FIELD_RUN`'s threshold — which is the leak this whole change exists to avoid, rebuilt
    inside the fix for it. A window holding no whitespace at all therefore yields nothing rather than a
    fragment.

    **Then the walk, which is there for :data:`_NAME_RUN` alone** — the one pattern that spans
    whitespace, so the one a whitespace cut can still split. A bare cut through ``DOE JANE`` leaves
    ``DOE`` standing under its two-token threshold. Up to :data:`_NAME_RUN_MAX_TOKENS` - 1 further
    name-shaped tokens are dropped whole; the cost is over-redaction of a few tokens at a boundary
    64 KiB into a string nobody is reading that far down."""
    if len(text) <= window:
        return text, 0
    # -1 when the window held no whitespace at all, which must yield nothing rather than text[:-1].
    cut = max(_last_cut(text, window), 0)
    # The window split a token unless it happened to land on whitespace. Either way that token is
    # already gone, and it counts against the run budget: a straddling _NAME_RUN has at least one
    # token past the cut, so at most _NAME_RUN_MAX_TOKENS - 1 of it can remain on this side.
    for _ in range(_NAME_RUN_MAX_TOKENS - 1):
        if not cut:
            break
        # Step over a whitespace RUN, or the walk stops on the empty token inside one. `rstrip` and
        # not a character loop for the same reason as _ends_with_name_token: the run's length is the
        # peer's to choose, so an interpreter-level walk over it is a second unbounded cost inside the
        # fix for the first. Measured on a 64 KiB run of spaces: 1.89 ms stepping, 0.23 ms stripping.
        end = len(text[:cut].rstrip(_CUT_CHARS))
        start = _last_cut(text, end) + 1
        if not _ends_with_name_token(text[start:end]):
            break
        cut = start
    return text[:cut], len(text) - cut


def clamp_untrusted(text: str, *, window: int = _REDACT_WINDOW) -> str:
    """``text`` bounded to ``window`` characters for a scan, with a note naming what was dropped.

    **Call this on anything a remote peer sizes before handing it to :func:`redact`** — a rendered
    traceback, a reply field, a Router's own ``raise``. :func:`redact` is linear but not free, and it
    runs synchronously on whatever thread emitted the record, which for the engine is the asyncio event
    loop. A negative acknowledgment at a 16 MiB frame cap would otherwise charge the loop the better
    part of a second (module docstring), for a diagnostic whose useful part is its first line.

    Idempotent: the result is never longer than ``window`` (:data:`_CLAMP_MARKER_BUDGET` is reserved
    for the note), so clamping it again returns it unchanged. That matters because a record dispatched
    to two handlers is filtered twice and the two sinks must agree. Deliberately NOT done by
    recognising the note in the text — a peer can write that literal into its payload, and a bypass a
    peer controls is not a bound."""
    if len(text) <= window:
        return text
    # The budget comes off the CUT, never off this guard. A result is head + note, so it fits `window`
    # and the guard hands it back untouched on the next pass. Cutting straight to `window` instead
    # would leave every result in the `window - budget` to `window` band -- above its own cut, below
    # its own guard -- and re-cut it on every pass, which is what the first version of this shipped.
    head, dropped = _clamp(text, max(window - _CLAMP_MARKER_BUDGET, 0))
    return f"{head}\n{_clamp_marker(dropped)}"  # newline, not space: see _clamp_marker


def redact_untrusted(text: str, *, window: int = _REDACT_WINDOW) -> str:
    """:func:`redact` over :func:`clamp_untrusted` — bound the input, then scrub it.

    **The pairing has a name so a call site cannot hold half of it.** The two halves are separately
    useful (the MLLP outbound clamps a reply field it does not scrub), but every caller that scans
    peer-sized text wants both, and ``redact(text)`` alone is a silent reopening of BACKLOG #1576 that
    reads like ordinary code. One name is what makes the bound reviewable at the call site."""
    return redact(clamp_untrusted(text, window=window))


def redact(text: str) -> str:
    """Scrub HL7 segment/field content (potential PHI) from free text, keeping segment IDs, then apply a
    conservative free-text heuristic for delimiter-free identifiers. Conservative (errs toward over-
    redaction); the goal is that a raw HL7 body — or a free-text name/DOB — embedded in an exception
    message can't reach a log or the stored ``last_error``/``detail``. NOT de-identification (PHI.md §9).

    Order matters: HL7-shaped content (:data:`_HL7_SEGMENT`, then :data:`_HL7_FIELD_RUN`, then the
    separator-aware pass for a message that declares delimiters outside the defaults) is handled first,
    so the free-text passes (:data:`_DATE_RUN`, then :data:`_NAME_RUN`) only see delimiter-free
    text. The free-text heuristic narrows the prior residual to adversarial *single-token* identifiers
    (a lone name with no second token, no date) — for which the "never put PHI in an exception message"
    convention remains the control. Idempotent: the literal ``[redacted]`` substituted in never re-
    matches any pattern, so ``redact(redact(x)) == redact(x)``."""
    if not text:
        return text
    scrubbed = _HL7_SEGMENT.sub(lambda m: f"{m.group(1)}|{_REDACTED}", text)
    scrubbed = _HL7_FIELD_RUN.sub(_REDACTED, scrubbed)
    # BACKLOG #1572. The passes above assume `| ^ ~ &`; MSH DECLARES the real set per message, so a
    # feed using `*` and `$` kept its identifiers. Sniff, and run a separator-aware pass only when the
    # declared set reaches outside the defaults — widening the hardcoded class instead would have been
    # the obvious move and is the wrong one: it scrubs timestamps, `C:/` paths, URLs and `host:port` out
    # of ordinary operational text, which is most of what the support bundle and the forwarded log
    # stream carry. Sniffing `text` and not `scrubbed` is load-bearing: on a custom FIELD separator with
    # default encoding characters, `_HL7_FIELD_RUN` has already eaten the MSH line (and the delimiter
    # declaration with it) by this point.
    declared = _sniff_delimiters(text)
    if not declared <= _DEFAULT_DELIMITERS:
        segment, field_run = _delimiter_patterns(declared | _DEFAULT_DELIMITERS)
        scrubbed = segment.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", scrubbed)
        scrubbed = field_run.sub(_REDACTED, scrubbed)
    scrubbed = _DATE_RUN.sub(_REDACTED, scrubbed)
    return _NAME_RUN.sub(_REDACTED, scrubbed)


def safe_text(text: str, *, limit: int = _DEFAULT_LIMIT) -> str:
    """A PHI-redacted, length-bounded rendering of a free-text diagnostic string — the string analog of
    :func:`safe_exc`, for error/detail text that isn't an exception object (joined strict-validation
    errors, a ``last_error`` built at the store layer, a connector's reply-parse note). HL7-shaped content
    is scrubbed (:func:`redact`) and the result truncated. Idempotent on already-:func:`safe_text`'d
    input (``redact`` is a fixed point once delimiter runs are gone), so it is safe to re-apply as a
    store-layer chokepoint over values a caller may already have scrubbed.

    **``limit`` bounds the ANSWER; :data:`_REDACT_WINDOW` bounds the WORK (BACKLOG #1576).** That was
    one number's job before and it could only do half of it: the truncation runs *after*
    :func:`redact`, so a remote peer sizing the input bought an unbounded scan on the event loop for a
    200-character result. :func:`_clamp` cuts the input first. It is emphatically **not**
    ``redact(text[:limit])`` — the module docstring says why that form leaks the name it was meant to
    catch.

    The two counts stay separate and each is exactly true: ``(+N chars)`` is redacted text this call
    held back, and the bound note is raw characters no pattern ever looked at. One total would add a
    redacted length to an unredacted one and report a number that is neither. Nothing is dropped in the
    ordinary case, so the ordinary result is byte-identical to its pre-#1576 self."""
    head, dropped = _clamp(text, _REDACT_WINDOW)
    message = redact(head).strip()
    if len(message) > limit:
        message = f"{message[:limit]}…(+{len(message) - limit} chars)"
    if dropped:
        message = f"{message} {_clamp_marker(dropped)}"
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
