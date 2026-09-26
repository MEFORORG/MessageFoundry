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
declaring ``*`` and ``$`` is covered too (:func:`_sniff_delimiters`, BACKLOG #1572). Three
**structured** shapes get label-anchored passes of their own, because they hand every pattern above
single tokens by construction: FHIR (or any) JSON keyed ``family``/``given``/``name``/``birthDate``/
``identifier``/``telecom``/``address``, DICOM ``(0010,00xx)`` tag dumps and ``PatientName=``-style
labels, and XML elements with the same vocabulary (:func:`_redact_structured`, BACKLOG #1711).

Residuals, at least these, and this module claims no completeness: an adversarially-crafted
*single-token* or non-name-shaped identifier, a **headerless** custom-delimiter fragment (no MSH, so
nothing declares its delimiters), and the structured shapes the section comment above
:func:`_redact_structured` lists. For all of them, the "never put PHI in an exception message"
convention remains the control.

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
into the log. So the cut is made at whitespace, and the spans a whitespace cut can still break are
dropped whole — never emitted in part. At least two patterns need that, each with a walk of its own:
:data:`_NAME_RUN` under :func:`_drop_trailing_name_tokens`, and :data:`_INVALID_URL_USERINFO` under
:func:`_drop_truncated_userinfo`. Over-redaction at the boundary is the deliberate price.
:data:`_CUT_CHARS` carries the per-pattern argument: which patterns a whitespace cut covers, which it
does not, and the test to apply to the next one added. **"At least" rather than a count**, because a
count here went stale the first time this module grew a pattern and nothing reported it, and because
the register is a register of SPANS -- a dependency on the whole text rather than on a span is a
different shape it cannot hold (:func:`_sniff_delimiters`, below).

Pure stdlib, so it can be used from any engine package.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from string import ascii_lowercase, ascii_uppercase, whitespace
from typing import Any

__all__ = [
    "clamp_untrusted",
    "json_loads_or_refusal",
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


#: The literal ``http.client`` opens that message with, and the longest tail the pattern walks past it.
#: **Named because the CLAMP needs both numbers**: it has to know how far back of a cut a span could
#: have started (:data:`_USERINFO_SPAN`) and what to search for there
#: (:func:`_first_truncated_userinfo`).
#:
#: **The pattern below SPELLS BOTH OUT again rather than interpolating them, and that is a gate's
#: requirement rather than a style choice.** ``tests/test_security_static.py`` statically resolves
#: every ``re.compile`` argument in this tree and pins the ones it cannot read as recorded blind
#: spots. An f-string here makes the scanner blind to the one pattern in this module that matches a
#: CREDENTIAL, which is the last one to hide from it. So the duplication is deliberate, and
#: ``tests/test_redaction.py`` pins the two spellings against each other so they cannot drift --
#: the same trade :data:`_SAFE_SUFFIXES` takes, for the same reason.
_USERINFO_OPENER = "nonnumeric port: '"
_USERINFO_TAIL_MAX = 256

#: The password ``http.client`` quotes as a "port" when an endpoint URL carries userinfo: its
#: ``InvalidURL("nonnumeric port: 'PW@host'")`` (BACKLOG #1793; the mechanism is on
#: ``transports/rest.py`` ``refuse_url_credentials``). It is a CREDENTIAL, not PHI. It lives here
#: because :func:`redact` is the one pass that the stored error, the log chain and the support bundle
#: all run.
#:
#: The span runs to the LAST ``@`` because a decoded ``%40`` puts an ``@`` inside the password, and it
#: admits quotes and spaces because ``http.client`` formats with ``'%s'``, not ``repr``. The host after
#: the ``@`` is kept so the diagnostic still says where. The bound is load-bearing on
#: attacker-influenceable log text; the literal prefix limits it to one bounded walk per occurrence.
#: A password tail longer than the bound is NOT matched -- the construction-time refusal in
#: ``transports/rest.py`` ``refuse_url_credentials`` is the primary control, and this is its backstop.
_INVALID_URL_USERINFO = re.compile(r"(nonnumeric port: ')[^\r\n]{1,256}@")

#: The widest match :data:`_INVALID_URL_USERINFO` can make: the opener, the longest tail it admits,
#: and the ``@`` that closes it. An opener further back of a cut than this has its whole span inside
#: the kept head, so the cut cannot have broken it -- which is what bounds the backward search in
#: :func:`_first_truncated_userinfo` to a fixed region instead of the whole window.
_USERINFO_SPAN = len(_USERINFO_OPENER) + _USERINFO_TAIL_MAX + 1


# --- bounding the input (BACKLOG #1576) --------------------------------------

#: How much of an over-long string :func:`clamp_untrusted` lets the scan see. Three orders of magnitude
#: above :data:`_DEFAULT_LIMIT`, so no diagnostic anybody writes on purpose is ever cut, and small
#: enough that the worst-shaped input costs the event loop single-digit milliseconds: measured on this
#: module's own patterns, 64 KiB is 1.6 ms of segment-shaped text and about 3 ms of delimiter-free
#: prose, against 0.29 s and 0.78 s for the same shapes at a 16 MiB MLLP frame cap.
#:
#: **Those figures predate the structured passes of BACKLOG #1711, which walk tokens in Python and
#: cost more.** Measured when they landed: about 30 ms on a realistic 64 KiB FHIR Bundle and 50 to
#: 65 ms on the worst shapes in ``tests/test_redaction_structured_shapes.py`` (which pins a linear-
#: growth ratio and a 0.5 s ceiling per window), against about 5 ms for the HL7 passes alone. A line
#: carrying no structured shape pays a few microseconds for their prefilters and nothing more.
#:
#: The number bounds the SCAN, not the answer: :func:`safe_text` still cuts its result to
#: :data:`_DEFAULT_LIMIT`, and a caller that keeps the whole redacted text (the logging handler filter)
#: keeps a window's worth of it.
_REDACT_WINDOW = 64 * 1024

#: The characters :func:`_clamp` may cut at. Whitespace is the boundary because a pattern survives a
#: cut when it either cannot contain whitespace at all or still matches with its tail gone:
#: :data:`_HL7_FIELD_RUN` and :data:`_DATE_RUN` are built from classes that exclude ``\s`` outright,
#: and :data:`_HL7_SEGMENT` goes on matching from its own header whatever is cut off its tail.
#: :data:`_NAME_RUN` has neither property, and the token walk in :func:`_clamp` is there for it.
#:
#: **A pattern with a REQUIRED tail past a space has neither property, and this module has one.**
#: :data:`_INVALID_URL_USERINFO` (BACKLOG #1793) landed after this cut was designed. It is head-anchored
#: like :data:`_HL7_SEGMENT`, but its trailing ``@`` is required rather than optional, so a cut inside
#: its span does not shorten the match — it kills it, and the password head before the cut is written
#: out. Reproduced on this module: in a 64 KiB-plus string whose last whitespace before the window falls
#: between two space-separated halves of the quoted password, the first half survives, where an
#: unclamped :func:`redact` would have scrubbed it and a clamped one does not.
#:
#: **That paragraph ended "the walk below does not cover it" and recorded a live leak. It is covered
#: now: :func:`_drop_truncated_userinfo` runs after the name walk and drops a span the cut broke.**
#: The retracted half is kept because the SHAPE recurs — the walk really does not cover it, since
#: :func:`_ends_with_name_token` asks a name-shaped question, and the fix is a second walk rather than
#: a wider one. For an ENDPOINT URL the construction-time refusal in ``transports/rest.py``
#: ``refuse_url_credentials`` is the primary control and is untouched; that refusal deliberately does
#: not screen a ``proxy_url``, which legitimately carries its own credentials, so do not read it as
#: covering every arm.
#:
#: **The test a new pattern has to pass, which is a property and not a count:** if a cut at a space
#: falls inside your span, does what is left still MATCH you? Answer it, and pin the answer beside the
#: other properties of this cut in ``tests/test_redaction.py`` under *bounding the input*. A count of
#: how many patterns are covered went stale here the first time the module grew one, and nothing
#: reported it.
#:
#: **Answer "no" and you need a walk of your own, not a wider :func:`_ends_with_name_token`.** The two
#: walks ask different questions: the name one asks whether the head's last TOKEN could have paired
#: rightward, and the userinfo one asks whether an opener inside the head has lost the ``@`` that
#: completes it. A pattern whose span is head-anchored and bounded can copy
#: :func:`_drop_truncated_userinfo` by naming its own opener and its own widest span; one that is
#: neither needs a different argument about how far back to look.
#:
#: **A THIRD SHAPE IS OUT OF THIS REGISTER'S REACH ENTIRELY, and adding a walk for it would not
#: work.** :func:`_sniff_delimiters` reads the WHOLE text, so a clamp that drops the ``MSH`` declaring
#: a feed's real delimiters leaves the separator-aware pass nothing to read, and a run inside the head
#: that :func:`redact` scrubs unclamped survives. The dependency is not on a span, so no amount of
#: looking back from the cut finds it. It is a known open gap, recorded here and on the corpus arm in
#: ``tests/test_redaction.py`` that also cannot reach it -- not a pattern this register covers.
#:
#: **The structured passes (BACKLOG #1711) mostly answer "yes", and need no walk.** Each is
#: label-anchored and treats a region that never closes as running to the end of the text, so a cut
#: inside a JSON string, a quoted XML attribute, a DICOM tag value or a ``PatientName=`` value leaves a
#: head that still matches from its own label and is scrubbed to its end. The "no" answers are XML
#: text a placeholder test reads as prose -- at least text opening with whitespace or punctuation --
#: and there the fragment before the cut survives (:func:`_redact_xml_elements`). Both answers are
#: pinned in ``tests/test_redaction.py`` under *a structured span the cut broke*.
#:
#: ``string.whitespace`` searched with :meth:`str.rfind`, rather than ``\s`` through the regex engine:
#: a right-to-left search is what this needs and ``re`` only scans left to right. The stdlib name is
#: also the claim — ASCII whitespace, a strict subset of ``\s``, which is the direction that stays
#: safe: a narrower cut set only means the cut falls further back and drops more, so a Unicode space it
#: misses costs over-redaction and never coverage.
_CUT_CHARS = whitespace

#: :data:`_CUT_CHARS` as a set, for the single-character membership tests the walk in
#: :func:`_drop_trailing_name_tokens` makes. Derived from the same name, so the two can never disagree
#: about what a boundary is.
_CUT_CHAR_SET = frozenset(_CUT_CHARS)


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


def _token_start(text: str, end: int) -> int:
    """Index where the token ending at ``end`` begins — the first position after the :data:`_CUT_CHARS`
    character before it, or ``0``.

    **One spelling, because both walks in this module need it and what counts as a boundary may
    move.** :data:`_CUT_CHARS` contemplates admitting a Unicode space; two copies of this loop sixty
    lines apart would be two places to change and one place to forget.

    An index walk rather than :meth:`str.rsplit` or a slice: the callers are walking backwards through
    a region they are about to drop, and a slice copies from index 0 on every step, which is the
    quadratic cost :func:`_drop_trailing_name_tokens` exists to avoid."""
    while end and text[end - 1] not in _CUT_CHAR_SET:
        end -= 1
    return end


def _last_cut(text: str, end: int) -> int:
    """Index of the last :data:`_CUT_CHARS` character in ``text[:end]``, or ``-1`` if there is none."""
    return max(text.rfind(char, 0, end) for char in _CUT_CHARS)


def _drop_trailing_name_tokens(text: str, cut: int) -> int:
    """``cut`` moved back past **every** whole token :data:`_NAME_RUN` could have joined across it.

    The walk runs while :func:`_ends_with_name_token` holds and stops at the first token that fails
    it. **A fixed number of steps is wrong, and three was the number this shipped with.** Dropping a
    token strands *its* own left partner — the one that was only over :data:`_NAME_RUN`'s two-token
    threshold because of the token just dropped — so any fixed budget leaves the run one token short
    at the boundary. Reproduced at the shipped window on ``SMITH DOE JANE ROE`` cut after ``ROE``: the
    three-step walk dropped ``ROE``, ``JANE`` and ``DOE``, and ``SMITH`` then stood alone under the
    threshold and survived a scrub the **unbounded** redactor performed. That is the leak class
    BACKLOG #1576 exists to close, reopened inside the fix for it.

    **What makes stopping here safe is a property, not a count:** the last token of the kept head is
    not name-shaped at its end, so no :data:`_NAME_RUN` match can span the cut at all. Every match the
    unbounded scan would have made therefore lies wholly inside the head, where it still matches, or
    wholly inside what was dropped. Pairings to that token's *left* are untouched — the cut cannot
    reach them.

    **And the work is still bounded by the window, which is the whole point of BACKLOG #1576.** The
    walk visits each character of what it drops a constant number of times and never revisits one:
    each iteration consumes ``text[start:cut]`` and the next begins at ``start``, so the regions are
    disjoint and ``cut`` strictly decreases. The total is one backward pass over the dropped suffix
    plus the single token it stops on — linear in the window, the same class as the scan it protects,
    and it cannot exceed it because the window bounds the input.

    **So the loop body must not scan from the string's start, and the obvious spelling does — both
    halves of it.** The shipped three-step version paired ``text[:cut].rstrip(...)`` with
    :func:`_last_cut`. That slice copies ``cut`` characters, and ``_last_cut`` is six
    :meth:`str.rfind` calls that run to index 0 whenever the text holds no tab or newline — ordinary
    for a peer's one-line field. Three of each is a constant; one per token is quadratic in the
    window, which is exactly the cost class this change exists to bound. Index walking keeps both
    inside the region being dropped. Measured best-of-3 on a 64 KiB window of nothing but ``AA``
    tokens — 21,820 of them, the most a window can hold — the two walks agree on the answer and cost
    **6.2 ms here against 630 ms spelled with ``_last_cut``**.

    **That overturns one earlier decision, on its own measurement.** Stepping over a whitespace run a
    character at a time was rejected for :meth:`str.rstrip`, and on a 64 KiB run of spaces stepping
    does cost 1.6 ms against 0.2 ms. It is taken anyway: ``rstrip`` needs the ``text[:cut]`` slice,
    which is the quadratic half above, and 1.4 ms inside a bounded window buys away a cost that grows
    with the peer's input.

    **The price is over-redaction, and the ceiling on it moved.** A fixed budget dropped at most three
    tokens; this drops a contiguous name-shaped run of any length, so a window that is nothing but
    such tokens is dropped whole and the answer is the note alone. That is the same trade
    :data:`_CUT_CHARS` already takes at the boundary, and it loses no diagnostic: a run long enough to
    trigger it is a run the unbounded redactor would have scrubbed to :data:`_REDACTED` anyway. The
    walk stops at the first token that fails the test, so ordinary prose behind the cut is untouched."""
    while cut:
        end = cut
        while end and text[end - 1] in _CUT_CHAR_SET:
            end -= 1  # step over a whitespace RUN: _NAME_RUN joins its tokens with `\s+`
        if not end:
            return cut  # nothing but whitespace behind the cut, so no token to judge
        start = _token_start(text, end)
        if not _ends_with_name_token(text[start:end]):
            return cut
        cut = start
    return cut


def _first_truncated_userinfo(text: str, cut: int) -> int:
    """Index of the leftmost :data:`_INVALID_URL_USERINFO` opener in ``text[:cut]`` whose match runs
    past ``cut``, or ``-1`` when the cut broke none.

    **Leftmost, because one match can cover several openers.** The tail is ``[^\\r\\n]``, which spans
    whitespace and spans a second opener, so the span that starts first is the one whose loss takes the
    most text with it; cutting back before it removes the later ones as well.

    **Only a fixed region is searched, and that is what keeps this affordable.** A span is at most
    :data:`_USERINFO_SPAN` characters, so an opener further back than that ends inside the head, where
    the head's bytes are the text's bytes and the match still stands. Everything the cut can have
    broken therefore sits in one bounded region behind it, whatever the peer's input is.

    The question asked of each candidate is the shipping pattern's own, against the WHOLE text: a
    candidate that does not match there is one :func:`redact` would not have scrubbed unclamped either,
    so dropping it would buy nothing."""
    pos = max(cut - _USERINFO_SPAN, 0)
    while (start := text.find(_USERINFO_OPENER, pos, cut)) >= 0:
        match = _INVALID_URL_USERINFO.match(text, start)
        if match is not None and match.end() > cut:
            return start
        pos = start + 1
    return -1


def _drop_truncated_userinfo(text: str, cut: int) -> int:
    """``cut`` moved back past every :data:`_INVALID_URL_USERINFO` span the cut would have broken.

    **This is the second of the two walks :data:`_CUT_CHARS` describes, and it exists because a
    whitespace cut is not enough for a pattern whose tail is required.** A password quoted with a space
    in it puts a cut candidate inside the credential: the head keeps ``nonnumeric port: '`` and the
    first half of the password, the ``@`` that completes the match is past the cut, and the pattern
    that exists to scrub exactly that string no longer fires. Unclamped, :func:`redact` scrubs it. That
    is the leak class BACKLOG #1576 exists to close, in the one pattern that arrived after the cut was
    designed.

    **A broken span is dropped whole rather than repaired**, and the cut goes back to the whitespace
    boundary before the opener's own token, so the head still ends where :func:`_clamp` promises. The
    name walk is re-run from there, because moving a cut back is exactly what can strand a
    :data:`_NAME_RUN` partner, and re-running it is cheaper than reasoning that it cannot.

    **The loop is necessary, not defensive.** A greedy tail reaches the last ``@`` in range, so an
    EARLIER opener can own a span that swallows the one just dropped and still runs past the cut:
    ``nonnumeric port: 'A nonnumeric port: 'B`` with the ``@`` past the window is one match unclamped,
    covering both halves. Dropping only the rightmost opener would leave ``A`` standing.

    **And it is bounded by the window, but NOT by the disjointness argument the walk above it uses,
    and that distinction is the part to keep.** Two costs here, and only one of them is disjoint.
    ``cut`` strictly decreases, so the backward scans for a token boundary do run over regions strictly
    below the previous pass's and visit no character twice -- one pass over the dropped suffix in
    total. The SEARCH does not: a pass that steps back past a single opener leaves the next pass's
    :data:`_USERINFO_SPAN`-wide region overlapping this one by nearly all of it, so the search cost is
    passes times the span rather than one pass over the window.

    **That is still bounded, because both factors are.** The span is a constant, and a pass consumes
    at least one opener, so the passes cannot exceed the openers a window holds. Measured over a sweep
    of the gap between opener and terminator, in steps of 5 from 0 to 125, on 64 KiB of nothing but
    credential spans: the worst is a 75-character gap at **348 passes and 1.6 ms**, against the 50 ms
    the #1437 arms budget. A gap of 120 or more takes ONE pass -- past that the span cannot reach an
    ``@`` beyond the cut at all -- so the cost is not monotone in the gap and a single sample of it
    measures nothing. Pinned in ``tests/test_redaction.py`` under *bounding the input*."""
    while cut:
        start = _first_truncated_userinfo(text, cut)
        if start < 0:
            return cut
        # Back to the start of the token the opener sits in, then one more: that index is the
        # whitespace before it, which is the `_last_cut` convention -- the head ends just before it.
        # A zero means no boundary at all behind the opener, so the answer is nothing.
        cut = _drop_trailing_name_tokens(text, max(_token_start(text, start) - 1, 0))
    return cut


def _clamp(text: str, window: int) -> tuple[str, int]:
    """``(head, dropped)`` — ``text`` cut to at most ``window`` characters at a whitespace boundary,
    and how many characters that cost. See :data:`_CUT_CHARS` for which patterns that boundary covers
    and which it does not.

    ``dropped == 0`` means the text fit and ``head is text``, so every caller is byte-identical to its
    pre-#1576 self on everything short enough to read.

    **The cut ALWAYS lands on whitespace or on zero, and never at an arbitrary offset.** Cut anywhere
    else and a run carrying two delimiters can lose one of them and fall under
    :data:`_HL7_FIELD_RUN`'s threshold — which is the leak this whole change exists to avoid, rebuilt
    inside the fix for it. A window holding no whitespace at all therefore yields nothing rather than a
    fragment. :data:`_CUT_CHARS` carries the per-pattern argument for what a whitespace cut covers.

    **Then the walk, which is there for :data:`_NAME_RUN`** — a pattern a whitespace cut can split
    while leaving a match-killing remainder behind. A bare cut through ``DOE JANE`` leaves ``DOE``
    standing under its two-token threshold, so the neighbouring name-shaped tokens are dropped whole.
    :func:`_drop_trailing_name_tokens` carries how far that walk goes and why it is still bounded; the
    cost is over-redaction of a few tokens at a boundary 64 KiB into a string nobody is reading that
    far down.

    **Then the second walk, which is there for :data:`_INVALID_URL_USERINFO`** — a pattern a whitespace
    cut can split while leaving a match-KILLING remainder behind, because its trailing ``@`` is
    required rather than optional. A password quoted with a space in it is the case, and the head would
    otherwise keep its first half. :func:`_drop_truncated_userinfo` drops the broken span whole."""
    if len(text) <= window:
        return text, 0
    # -1 when the window held no whitespace at all, which must yield nothing rather than text[:-1].
    cut = max(_last_cut(text, window), 0)
    # The window split a token unless it happened to land on whitespace. Either way that token is
    # already gone; the walk continues from there through the rest of the run it belonged to.
    cut = _drop_trailing_name_tokens(text, cut)
    # After the name walk, not before it: that walk only ever moves the cut back, and moving it back
    # is what breaks a span. This one re-runs the name walk itself wherever it moves the cut again.
    cut = _drop_truncated_userinfo(text, cut)
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


# --- structured payload shapes: FHIR JSON, DICOM tag dumps, XML (BACKLOG #1711) ------------------
#
# Every pass above is HL7-shaped, and a structured payload hands them single tokens by construction:
# ``"family": "DOE"`` carries no delimiter, no date and no second capitalized token, so it walked
# through all of them, and so did an MRN in ``<value value="..."/>`` and a patient id in a DICOM tag
# dump. The engine is payload-agnostic, the FHIR and DICOM transports raise with peer-supplied text,
# and the bundle and ``GET /logs/tail`` delegate here, so these three shapes are ordinary input.
#
# The passes are LABEL-ANCHORED and deliberately narrow. Each fires only on a key, tag or element
# from a small PHI vocabulary and scrubs the value that label introduces, never the label, so an
# operator can still read WHICH field was withheld. This is not a JSON, XML or DICOM parser and does
# not try to be one: a text that merely mentions ``<name>`` or ``PatientID`` in prose must come
# through byte-identical, because a structural pass that eats prose damages every log line the engine
# writes. ``tests/test_redaction_structured_shapes.py`` pins both directions.
#
# **They run AFTER the HL7 passes, and the order was measured, not chosen for tidiness.** Run first,
# scrubbing a labelled value removed the delimiters a whitespace-free token needed to stay over
# :data:`_HL7_FIELD_RUN`'s two-delimiter threshold: ``{"mrn":"M1^H","name":[{"family":"D^J"}]}`` was
# scrubbed whole before these passes existed and then kept the unlabelled MRN. Scrubbing a single
# unquoted token after ``"name":`` likewise split a two-token name :data:`_NAME_RUN` used to catch.
# After them, every pass here only ever sees what the HL7 passes left, so it can add redaction and
# never take any away. The cost is legibility: a field run can swallow a label with its value.
#
# **Fail-closed at the edge, which is also this family's answer to the cut register on
# :data:`_CUT_CHARS`.** A region that never closes -- an unterminated string, array, object, quoted
# attribute or element -- runs to the end of the text (a DICOM value to the end of its line) rather than
# stopping short. So a whitespace cut inside a span leaves a head that still matches from its own
# label and is still scrubbed to its end. The exceptions are XML text a placeholder test reads as
# prose; :func:`_redact_xml_elements` states them.
#
# **Residuals, at least these, and the "never put PHI in an exception message" convention remains
# the control for them:** JSON or XML quoted INSIDE a JSON string (``\"family\"`` escapes defeat the
# key and attribute patterns); a structure that uses PHI as its KEYS, since keys are always kept; a
# single-token STRING under a JSON ``name`` or ``address`` (:data:`_PHI_STRUCTURE_ONLY_KEYS` says
# why); DICOM identifiers outside ``(0010,00xx)`` (Other Patient IDs ``(0010,1000)``, Patient's
# Address ``(0010,1040)``); and XML or JSON vocabularies other than this one (CDA's ``<id
# extension>``, ``<addr>``, a FHIR ``display`` or narrative ``div``). The vocabulary is the one
# BACKLOG #1711 set; widening it is a separate decision, because every word added also over-redacts
# the operator text that happens to use it as a key.
#
# Not :mod:`messagefoundry.anon`. That framework de-identifies a whole HL7 v2 message by FIELD ADDRESS
# (``PID-5``) into keyed surrogates, loads its token denylist from ``scripts/`` in a source checkout,
# and has no FHIR, XML or DICOM vocabulary at all. This module is the one redaction chokepoint, pure
# stdlib by design, so the shapes are added here beside the passes they complement.

#: Keys and elements whose ENTIRE value is PHI: every scalar under them is scrubbed.
_PHI_LEAF_KEYS = frozenset({"family", "given", "name", "birthDate", "address"})
#: The two leaf words that are also ordinary operator vocabulary. In JSON a STRING under one of them
#: is kept and only a structure is scrubbed: FHIR's ``HumanName`` and ``Address`` are always objects
#: or arrays of them, while ``{"name": "IB_ACME_ADT"}``, ``{"address": "10.1.2.3"}`` and the audit
#: detail ``{"name": "<preset>"}`` the off-box tee copies are diagnostics. A single-token string name in
#: non-FHIR JSON is therefore a residual (a two-token one is still caught by :data:`_NAME_RUN`). An XML
#: element carries no such ambiguity, so there both stay full leaf words.
_PHI_STRUCTURE_ONLY_KEYS = frozenset({"name", "address"})
#: Keys and elements whose PHI is the ``value`` member (FHIR ``Identifier.value``,
#: ``ContactPoint.value``). The siblings -- ``system``, ``use``, ``type`` -- say which identifier it
#: was, which is the diagnostic, so they are kept. A scalar value under one of these is scrubbed whole.
_PHI_VALUE_KEYS = frozenset({"identifier", "telecom"})
#: The member of a :data:`_PHI_VALUE_KEYS` structure that carries the identifier itself.
_VALUE_MEMBER = "value"

#: How a value is treated, decided by the key or element that introduces it.
_LEAF = 0  # every scalar under it is scrubbed
_VALUE_TOP = 1  # a scalar is scrubbed; a structure is searched for its ``value`` member
_INHERIT = 2  # kept, but a structure under it is still searched
_STRUCTURE_ONLY = 3  # a scalar is kept; a structure is scrubbed whole (JSON ``name``/``address``)

#: A JSON (or Python-repr) key from the vocabulary, with its colon: ``"family": `` or ``'given':``.
#: ``001000xx`` is the DICOM JSON model's key for a ``(0010,00xx)`` attribute (PS3.18 F.2), the same
#: tag the dump pass below reads in its other spelling.
#:
#: The literals are spelled out rather than joined from :data:`_PHI_LEAF_KEYS`: the static ReDoS scan
#: in ``tests/test_security_static.py`` resolves every ``re.compile`` argument and records one it
#: cannot read as a blind spot. ``tests/test_redaction_structured_shapes.py`` pins the two spellings
#: against each other so they cannot drift.
_JSON_PHI_KEY = re.compile(
    r"""(["'])(family|given|name|birthDate|address|identifier|telecom|001000[0-9A-Fa-f]{2})\1"""
    r"""\s*+:[ \t]*+"""
)
#: One JSON token: whitespace, a structural character, a double- or single-quoted string, or a bare
#: run (a number, a literal, or anything else). Parentheses are structure too, so a Python tuple or a
#: call such as ``datetime.date(1980, 5, 5)`` is walked as a container rather than ending at its first
#: token. A string may carry a Python prefix (``b'..'``), and its closer is optional, so an
#: unterminated string is still one token, ending at the line. An escape consumes ANY next character,
#: a line end included, and a lone trailing backslash stays inside the string: split off as a bare
#: token, it re-read differently on a second pass and broke the fixed point :func:`safe_text` relies
#: on. The alternatives are disjoint on their first character, so the scan has one parse and every
#: character belongs to exactly one token.
_JSON_TOKEN = re.compile(
    r"""(?P<ws>\s++)|(?P<punct>[{}\[\](),:])"""
    r"""|(?P<pre>[bBrRuUfF]{1,2}(?=["']))?"""
    r"""(?:"(?:[^"\\\r\n]|\\[\s\S])*+\\?(?P<dq>"?)|'(?:[^'\\\r\n]|\\[\s\S])*+\\?(?P<sq>'?))"""
    r"""|(?P<bare>[^\s{}\[\](),:"']++)"""
)
#: Whether the string just read is a KEY: a colon follows it.
_JSON_COLON_AHEAD = re.compile(r"\s*+:")
#: A DICOM JSON attribute key for group 0010, element 00xx, read in nested position.
_DICOM_JSON_PHI_TAG = re.compile(r"001000[0-9A-Fa-f]{2}")
#: Bare tokens that are JSON or Python literals, not data, and so are kept even under a leaf key.
#: ``redacted`` is here because a scrubbed bare token becomes ``[redacted]``, which a second pass reads
#: as an array holding that word, and must leave alone.
_JSON_LITERALS = frozenset({"true", "false", "null", "True", "False", "None", "redacted"})
#: A bare run continuing a top-level value on the same line: ``"birthDate": 5 May 1980``. It stops
#: before a callable's name, so ``"given": x frozenset({..})`` still walks the call.
_JSON_BARE_CONTINUATION = re.compile(r"""(?:[ \t]++[^\s{}\[\](),:"']++(?!\())*+""")

#: The bound note :func:`_clamp_marker` writes, joined by a newline (:func:`clamp_untrusted`) or a
#: space (:func:`safe_text`). The structured passes run on the text BEFORE it, because an unterminated
#: region runs to the end of the text and would otherwise scrub the note -- and :func:`safe_text` is
#: re-applied to its own output at the store chokepoint, where that would erase the only sign the text
#: was cut. Anchored at ``\Z`` so only a note last in the text is spared: a peer that writes the
#: literal mid-payload ends nothing early, and a trailing one carries no PHI. :func:`safe_text`'s
#: ``…(+N chars)`` count is not here because a second :func:`safe_text` re-truncates past it anyway.
_TRAILING_NOTES = re.compile(r"[\n ]\[redaction bound: dropped [0-9_]+ more chars unscanned\]\Z")


def _vocabulary_policy(local: str) -> int:
    """How a value is treated when a key or element named ``local`` introduces it, outside a region
    already scrubbed whole. One function for JSON and XML, so the two passes cannot disagree about what
    a word means; XML reads :data:`_STRUCTURE_ONLY` as :data:`_LEAF`."""
    if local in _PHI_STRUCTURE_ONLY_KEYS:
        return _STRUCTURE_ONLY
    if local == _VALUE_MEMBER or local in _PHI_LEAF_KEYS or _DICOM_JSON_PHI_TAG.fullmatch(local):
        return _LEAF
    return _VALUE_TOP if local in _PHI_VALUE_KEYS else _INHERIT


def _json_scalar(match: re.Match[str], policy: int) -> str:
    """The token ``match`` read, scrubbed under ``policy``. A string keeps its prefix and quotes, so
    the text still reads as the structure it was; any other data token becomes the bare placeholder,
    which a second pass reads as an array holding a literal and leaves alone (the fixed point
    :func:`safe_text` relies on)."""
    token = match.group()
    if policy in (_INHERIT, _STRUCTURE_ONLY):
        return token
    if match.group("bare") is not None:
        return token if token in _JSON_LITERALS else _REDACTED
    prefix = match.group("pre") or ""
    quote = token[len(prefix)]
    closer = quote if match.group("dq") or match.group("sq") else ""
    return f"{prefix}{quote}{_REDACTED}{closer}"


def _scrub_json_value(text: str, pos: int, policy: int) -> tuple[str, int]:
    """``(replacement, end)`` for the JSON value starting at ``pos``, scrubbed under ``policy``.

    An explicit stack rather than recursion, because the nesting depth is the peer's choice. The walk
    visits each character once. A structure that never closes runs to the end of the text, so a cut
    inside it strands nothing (the fail-closed rule on the section comment above).

    **Object KEYS are always kept**, which is what keeps the output legible, so a structure that uses
    PHI as its keys (``{"name": {"DOE": 1}}``) is a residual. A bare token straight before ``(`` is a
    callable's name (``date(``, ``frozenset(``) and is kept too; its arguments are the value."""
    out: list[str] = []
    #: One frame per open container: ``(is_object, policy)``. An object's policy is LEAF or INHERIT
    #: (searched); an array's or a call's is the policy its elements take.
    frames: list[tuple[bool, int]] = []
    pending = policy
    n = len(text)
    while pos < n:
        match = _JSON_TOKEN.match(text, pos)
        if match is None:  # unreachable: every character starts one alternative
            break
        token = match.group()
        if match.group("ws") is not None:
            if not frames and ("\n" in token or "\r" in token):
                break  # the key ends its line with no value: the next line is not this key's
            out.append(token)
            pos = match.end()
            continue
        punct = match.group("punct")
        if punct is not None:
            if not frames and punct in ",}]):":
                break  # the key had no value: nothing to scrub, and nothing consumed
            pos = match.end()
            out.append(token)
            if punct == "{":
                leaf = pending in (_LEAF, _STRUCTURE_ONLY)
                frames.append((True, _LEAF if leaf else _INHERIT))
                pending = frames[-1][1]
            elif punct in "[(":
                frames.append((False, _LEAF if pending == _STRUCTURE_ONLY else pending))
                pending = frames[-1][1]
            elif punct in "}])":
                frames.pop()
                if not frames:
                    return "".join(out), pos
                pending = frames[-1][1]
            elif punct == ",":
                pending = frames[-1][1]
            continue
        pos = match.end()
        bare = match.group("bare") is not None
        if bare and text.startswith("(", pos):
            out.append(token)  # a callable's name; the call's parentheses hold the value
            continue
        if not bare and frames and frames[-1][0] and _JSON_COLON_AHEAD.match(text, pos):
            out.append(token)  # a key: kept, and it decides how its value is treated
            if frames[-1][1] == _LEAF:
                pending = _LEAF
            else:
                closed = bool(match.group("dq") or match.group("sq"))
                start = len(match.group("pre") or "") + 1
                pending = _vocabulary_policy(token[start : -1 if closed else None])
            continue
        if bare and not frames:
            # A top-level bare value can be prose running on after a key-shaped label, such as
            # `"birthDate": 5 May 1980`, so the rest of the run on its line goes with it.
            run = _JSON_BARE_CONTINUATION.match(text, pos)
            if run is not None and run.end() > pos:
                pos = run.end()
                keep = pending in (_INHERIT, _STRUCTURE_ONLY)
                out.append(text[match.start() : pos] if keep else _REDACTED)
                return "".join(out), pos
        out.append(_json_scalar(match, pending))
        if not frames:
            return "".join(out), pos
    return "".join(out), pos


def _redact_json_fields(text: str) -> str:
    """Scrub the value of every vocabulary key in a JSON or Python dict/list repr.

    Leaf keys (:data:`_PHI_LEAF_KEYS` and the DICOM JSON ``001000xx`` tags) lose every scalar under
    them; :data:`_PHI_VALUE_KEYS` lose their ``value`` member and keep ``system``/``use``/``type``;
    :data:`_PHI_STRUCTURE_ONLY_KEYS` lose a structure and keep a plain string. Keys stay, so
    ``{"family": "[redacted]"}`` still says what was withheld. A key nested inside a region is handled
    by the walk, so the search resumes after the region."""
    out: list[str] = []
    pos = 0
    while (match := _JSON_PHI_KEY.search(text, pos)) is not None:
        replacement, end = _scrub_json_value(text, match.end(), _vocabulary_policy(match.group(2)))
        out.append(text[pos : match.end()])
        out.append(replacement)
        pos = end
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


#: Any DICOM tag as a dump prints it, ``(gggg,eeee)`` -- pydicom 2 wrote a space after the comma. Read
#: as a whole so the value of a PHI tag can end at the NEXT tag on the same line.
_DICOM_TAG = re.compile(r"\(([0-9A-Fa-f]{4}), ?([0-9A-Fa-f]{4})\)")
#: A line ending, for where a tag's value stops when no further tag follows it on the line.
_LINE_END = re.compile(r"[\r\n]")
#: The keyword labels of the ``(0010,00xx)`` identifiers, as ``PatientName=...``, ``PatientID: ...``,
#: a dict key ``'PatientName': ...`` or an attribute ``ds.PatientID='...'`` -- which is what the
#: f-string debug form ``f"{ds.PatientID=}"`` renders, so a traceback's quoted source line
#: ``ds.PatientID = raw_id`` is scrubbed too: over-redaction of source text, in the safe direction.
#: Only spaces and tabs around the separator: a label that ends its line has no value, and the next
#: line of a traceback is not one.
_DICOM_PHI_LABEL = re.compile(
    r"""(?<!\w)(?:PatientName|PatientID|IssuerOfPatientID|PatientBirthDate|PatientBirthTime)"""
    r"""['"]?[ \t]*+[=:][ \t]*+"""
)
#: A quoted label value, to its closing quote or the end of the line.
_DICOM_QUOTED_VALUE = re.compile(r"""'[^'\r\n]*+'?|"[^"\r\n]*+"?""")
#: Where an unquoted label value ends: a ``;``, a line end, or whitespace before the next ``Label=``,
#: the next PHI label with a colon, or the next tag. A name with spaces or a comma in it therefore
#: stays one value (``PatientName: Doe, Jane``; a list ``['A', 'B']``). A bare ``word:`` does NOT end
#: it -- ``PatientName=doe jane: no match`` would otherwise strand ``jane`` -- so a following
#: ``Modality: CT`` is scrubbed with the name, which is over-redaction in the safe direction.
_DICOM_LABEL_VALUE_END = re.compile(
    r"""[;\r\n]|\s(?=[A-Za-z][A-Za-z0-9_]*+['"]?[ \t]*+=)"""
    r"""|\s(?=(?:PatientName|PatientID|IssuerOfPatientID|PatientBirthDate|PatientBirthTime)"""
    r"""['"]?[ \t]*+:)|\s(?=\([0-9A-Fa-f]{4},)"""
)


def _redact_dicom_tags(text: str) -> str:
    """Scrub the value of every ``(0010,00xx)`` tag in a DICOM dump -- dcmdump's ``PN [..]``, pydicom's
    ``Patient's Name  PN: '..'`` -- keeping the tag, which names the attribute. The value runs to the
    next tag on its line or to the line's end, so the VR, the element name and dcmdump's trailing
    ``#`` comment go with it: over-redaction in the safe direction, and the tag still says what it
    was."""
    if "(0010," not in text:
        return text
    out: list[str] = []
    pos = 0
    line_end = -1
    tags = _DICOM_TAG.finditer(text)
    current = next(tags, None)
    while current is not None:
        following = next(tags, None)
        if current.group(1) == "0010" and current.group(2).startswith("00"):
            start = current.end()
            if line_end < start:  # cached: tags arrive in order, so each line end is found once
                found = _LINE_END.search(text, start)
                line_end = found.start() if found is not None else len(text)
            stop = line_end
            if following is not None and following.start() < line_end:
                stop = following.start()
            bounded = stop != line_end
            if text[start:stop].strip():
                out.append(text[pos:start])
                out.append(f" {_REDACTED} " if bounded else f" {_REDACTED}")
                pos = stop
        current = following
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def _redact_dicom_labels(text: str) -> str:
    """Scrub the value after a ``PatientName=`` / ``PatientID=`` (and the other ``(0010,00xx)``
    identifier keywords) label, keeping the label. A quoted value runs to its closing quote, an
    unquoted one to the next label, separator or line end."""
    if "Patient" not in text:  # every label carries it; skips the search on an ordinary line
        return text
    out: list[str] = []
    pos = 0
    n = len(text)
    while (match := _DICOM_PHI_LABEL.search(text, pos)) is not None:
        start = match.end()
        quoted = _DICOM_QUOTED_VALUE.match(text, start)
        if quoted is not None:
            value = quoted.group()
            closed = len(value) > 1 and value[-1] == value[0]
            replacement = f"{value[0]}{_REDACTED}{value[0] if closed else ''}"
            stop = quoted.end()
        else:
            found = _DICOM_LABEL_VALUE_END.search(text, start)
            stop = found.start() if found is not None else n
            value = text[start:stop]
            kept = value.rstrip()
            replacement = f"{_REDACTED}{value[len(kept) :]}" if kept else value
        out.append(text[pos:start])
        out.append(replacement)
        pos = max(stop, start)
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


#: A start tag whose local name is in the vocabulary, with or without a namespace prefix.
_XML_PHI_ELEMENT = re.compile(
    r"<((?:[A-Za-z_][\w.-]*+:)?(family|given|name|birthDate|address|identifier|telecom))(?=[\s/>])"
)
#: Any start or end tag, for the walk through an element's content.
_XML_TAG = re.compile(r"<(/?)((?:[A-Za-z_][\w.-]*+:)?([A-Za-z_][\w.-]*+))")
#: The rest of an end tag, up to its ``>``.
_XML_END_TAG_REST = re.compile(r"[^<>]*+>?")
#: One part of a start tag after its name: whitespace, the tag's end, an attribute and the opening of
#: its quoted value (the value itself is read by :data:`_XML_ATTR_VALUE`), or anything else.
#:
#: **The last alternative is what keeps the walk linear.** Without it a run that is not a quoted
#: attribute -- ``<name aaaa...`` or an unquoted ``data=QUJD...`` -- failed to match, the walk stepped
#: ONE character and retried, and the possessive ``attr`` alternative re-read the rest of the run on
#: every retry: about 10 s on a 64 KiB window, on the event loop. The junk alternative consumes the
#: whole failing run at once instead. Only ``<`` is left unmatched, which is where an unterminated tag
#: ends. An UNQUOTED value (``value=Janex``, SGML and hand-built diagnostics) is its own alternative,
#: so a leaf element loses it too rather than passing it through as junk.
_XML_TAG_PART = re.compile(
    r"""(?P<ws>\s++)|(?P<end>/?>)"""
    r"""|(?P<attr>[^\s=<>/"']++)\s*+=\s*+(?:(?P<q>["'])|(?P<unquoted>[^\s<>"'/]++))"""
    r"""|(?P<junk>[^\s=<>/"']++|[^<])"""
)
#: A quoted attribute value after its opening quote, to the closer, the next ``<`` or the end of the
#: text. XML forbids ``<`` in an attribute value, and stopping there matters: a KEPT value with no
#: closer otherwise ran to the next quote in the text, swallowed the following tag, and walked the
#: ``<value value="..."/>`` inside it through as part of the kept value.
_XML_ATTR_VALUE = {'"': re.compile(r'[^"<]*+"?'), "'": re.compile(r"[^'<]*+'?")}
#: The start of an element's content that says "this is markup, not a placeholder in prose": a child
#: tag straight after the ``>`` or on a following line, or text that begins at once with a word
#: character (any script's letters, so ``<family>Ødegaard`` counts). A child tag after a SPACE is not
#: evidence: ``usage: tool <name> <address>`` is prose.
_XML_CONTENT_EVIDENCE = re.compile(r"<|[ \t]*+\r?\n\s*+<|\w")
#: Every end tag of a vocabulary element, located once per call so a placeholder that never closes
#: costs a lookup rather than a search to the end of the text.
_XML_PHI_END = re.compile(
    r"</(?:[A-Za-z_][\w.-]*+:)?(family|given|name|birthDate|address|identifier|telecom)\s*+>"
)

#: How a start tag ended: ``>``, ``/>``, or not at all.
_TAG_OPEN, _TAG_SELF_CLOSED, _TAG_UNTERMINATED = 0, 1, 2


def _walk_xml_tag(text: str, pos: int, policy: int, out: list[str]) -> tuple[int, int, bool]:
    """Walk a start tag's attributes from ``pos``, scrubbing each value ``policy`` says to. Returns
    ``(end, how it ended, whether it carried an attribute)``. A leaf element loses every attribute
    value; a :data:`_VALUE_TOP` one only ``value="..."``. An unterminated quoted value runs to the next
    ``<`` or the end of the text, the fail-closed edge."""
    n = len(text)
    attributed = False
    while pos < n:
        part = _XML_TAG_PART.match(text, pos)
        if part is None:  # only `<`: the tag never closed and the next one starts here
            return pos, _TAG_UNTERMINATED, attributed
        if part.group("end") is not None:
            out.append(part.group())
            how = _TAG_SELF_CLOSED if part.group("end") == "/>" else _TAG_OPEN
            return part.end(), how, attributed
        if part.group("attr") is None:
            out.append(part.group())
            pos = part.end()
            continue
        attributed = True
        local = part.group("attr").rpartition(":")[2]
        scrub = policy == _LEAF or (policy == _VALUE_TOP and local == _VALUE_MEMBER)
        if part.group("unquoted") is not None:
            out.append(text[part.start() : part.start("unquoted")])
            out.append(_REDACTED if scrub else part.group("unquoted"))
            pos = part.end()
            continue
        out.append(part.group())
        pos = part.end()
        quote = part.group("q")
        value = _XML_ATTR_VALUE[quote].match(text, pos)
        if value is None:  # unreachable: both patterns match the empty string
            continue
        if scrub:
            out.append(f"{_REDACTED}{quote if value.group().endswith(quote) else ''}")
        else:
            out.append(value.group())
        pos = value.end()
    return pos, _TAG_UNTERMINATED, attributed


def _xml_text(chunk: str, policy: int) -> str:
    """A text node scrubbed under ``policy``, keeping the whitespace around it so indentation stays."""
    if policy == _INHERIT or not chunk.strip():
        return chunk
    lead = len(chunk) - len(chunk.lstrip())
    return f"{chunk[:lead]}{_REDACTED}{chunk[len(chunk.rstrip()) :]}"


def _scrub_xml_element(
    text: str, match: re.Match[str], last_close: dict[str, int]
) -> tuple[str, int]:
    """``(replacement, end)`` for the vocabulary element starting at ``match``."""
    out = [match.group()]
    policy = _VALUE_TOP if match.group(2) in _PHI_VALUE_KEYS else _LEAF
    pos, how, attributed = _walk_xml_tag(text, match.end(), policy, out)
    if how != _TAG_OPEN:
        return "".join(out), pos
    if not (
        last_close.get(match.group(2), -1) >= pos
        or attributed
        or _XML_CONTENT_EVIDENCE.match(text, pos)
    ):
        # A bare `<name>` that never closes and is followed by prose: a placeholder, not markup.
        return "".join(out), pos
    stack = [(match.group(1), policy)]
    open_names = {match.group(1): 1}
    n = len(text)
    while stack:
        tag = _XML_TAG.search(text, pos)
        stop = tag.start() if tag is not None else n
        if stop > pos:
            out.append(_xml_text(text[pos:stop], stack[-1][1]))
        if tag is None:
            return "".join(out), n
        qname = tag.group(2)
        if tag.group(1):  # an end tag: close back to the element it names, if it is open at all
            rest = _XML_END_TAG_REST.match(text, tag.end())
            pos = rest.end() if rest is not None else tag.end()
            out.append(text[tag.start() : pos])
            if open_names.get(qname):
                while stack:
                    name, _ = stack.pop()
                    open_names[name] -= 1
                    if name == qname:
                        break
            continue
        out.append(tag.group())
        parent = stack[-1][1]
        child = _LEAF if parent == _LEAF else _vocabulary_policy(tag.group(3))
        child = _LEAF if child == _STRUCTURE_ONLY else child  # no string/structure split in XML
        pos, how, _ = _walk_xml_tag(text, tag.end(), child, out)
        if how == _TAG_OPEN:
            stack.append((qname, child))
            open_names[qname] = open_names.get(qname, 0) + 1
    return "".join(out), pos


def _redact_xml_elements(text: str) -> str:
    """Scrub the content and attribute values of every vocabulary element in an XML payload -- FHIR's
    ``<family value="..."/>``, a text-content ``<family>...</family>``, with or without a namespace
    prefix -- keeping every tag name, and inside ``<identifier>``/``<telecom>`` keeping everything but
    the ``<value>``.

    **An element that never closes needs a judgment, and the judgment favours prose.** Operator text
    carries placeholders -- the provision-admin hint in ``api/app.py`` reads ``--username <name>
    --email <address>`` -- and reading one as an open element would scrub the rest of the message. So
    an unclosed element is treated as markup only on evidence (:data:`_XML_CONTENT_EVIDENCE`): it
    carries an attribute, or its content opens with a child tag or a word character. That is where the
    fail-closed rule has exceptions, at least these: a cut that strands ``<family> Van`` (text opening
    with whitespace) or ``<family>(Van`` (opening with punctuation) reads as prose, and the fragment
    before the cut survives. A closed element is always scrubbed, whatever its text opens with."""
    if "<" not in text:
        return text
    out: list[str] = []
    pos = 0
    #: Where the LAST end tag of each vocabulary name starts, built on the first match: whether an
    #: element closes anywhere later is then one lookup, not a search to the end of the text.
    last_close: dict[str, int] | None = None
    while (match := _XML_PHI_ELEMENT.search(text, pos)) is not None:
        if last_close is None:
            last_close = {close.group(1): close.start() for close in _XML_PHI_END.finditer(text)}
        replacement, end = _scrub_xml_element(text, match, last_close)
        out.append(text[pos : match.start()])
        out.append(replacement)
        pos = end
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def _redact_structured(text: str) -> str:
    """The structured-shape passes, run on everything but this module's own trailing notes
    (:data:`_TRAILING_NOTES`)."""
    body, tail = text, ""
    if text.endswith("unscanned]"):  # a cheap test before a search of the whole text
        note = _TRAILING_NOTES.search(text)
        if note is not None:
            body, tail = text[: note.start()], note.group()
    body = _redact_json_fields(body)
    body = _redact_dicom_tags(body)
    body = _redact_dicom_labels(body)
    return _redact_xml_elements(body) + tail


def redact(text: str) -> str:
    """Scrub HL7 segment/field content (potential PHI) from free text, keeping segment IDs, then apply a
    conservative free-text heuristic for delimiter-free identifiers. Conservative (errs toward over-
    redaction); the goal is that a raw HL7 body — or a free-text name/DOB — embedded in an exception
    message can't reach a log or the stored ``last_error``/``detail``. NOT de-identification (PHI.md §9).

    Order matters: HL7-shaped content (:data:`_HL7_SEGMENT`, then :data:`_HL7_FIELD_RUN`, then the
    separator-aware pass for a message that declares delimiters outside the defaults) is handled first,
    so the free-text passes (:data:`_DATE_RUN`, then :data:`_NAME_RUN`) only see delimiter-free
    text. The structured-shape passes (:func:`_redact_structured`: JSON keys, DICOM tags and labels,
    XML elements) run LAST, so they can only add redaction to what the others left (the section
    comment above them says what running them first cost). The free-text heuristic narrows the prior
    residual to adversarial *single-token* identifiers (a lone name with no second token, no date) — for which the "never put PHI in an exception message"
    convention remains the control. Idempotent: the literal ``[redacted]`` substituted in never re-
    matches any pattern, so ``redact(redact(x)) == redact(x)``.

    **The structured passes can expose work for a pass that already ran, so they repeat until they
    change nothing (BACKLOG #1711).** Scrubbing ``"a b"`` to ``"[redacted]"`` inside a token can join
    two one-delimiter halves into a field run, and scrubbing a quoted label value can uncover a key.
    A fuzz over those fragments broke the fixed point above on its first run. So when the structured
    passes change the text, the whole redaction runs again on the result; text they leave alone takes
    exactly one round, byte-identical and at the cost it had before them. If the rounds run out, the
    flat passes run once more, so a run the last structured round joined is still caught."""
    for _ in range(_STRUCTURED_ROUNDS):
        if not text:
            return text
        flat = _redact_flat(text)
        text = _redact_structured(flat)
        if text == flat:
            return text
    return _redact_flat(text)


#: The most rounds :func:`redact` takes. Measured over 200,000 fuzzed inputs from the alphabet of
#: ``test_redact_is_a_fixed_point_over_random_structure``: none needed more than 3, the last of them
#: the round that confirms nothing changed. The cap is set well above that so a peer has to build
#: many nested layers of uncovering to reach it; an input that does gets one last flat round, and
#: keeps what that produced, which is at least as redacted as every round before it.
_STRUCTURED_ROUNDS = 8


def _redact_flat(text: str) -> str:
    """Every pass but the structured ones: the credential backstop, the HL7 shapes, dates and
    names. :func:`redact` is this plus :func:`_redact_structured`, repeated to a fixed point."""
    text = _INVALID_URL_USERINFO.sub(lambda m: f"{m.group(1)}{_REDACTED}@", text)
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


def json_loads_or_refusal(raw: str | bytes) -> tuple[Any, str | None]:
    """``json.loads(raw)`` as ``(value, None)``, or ``(None, hint)`` when it fails, never raising.

    Test the hint, never the value: a JSON ``null`` is ``(None, None)``.

    The hint is content-free: the line and column for a decode error, else the class name (a
    ``UnicodeDecodeError`` on bytes, or json's depth-limit ``RecursionError``, which is a
    ``RuntimeError`` a ``ValueError`` arm does not reach -- BACKLOG #1600).

    It returns rather than raises so a caller's refusal is raised outside any handler (BACKLOG
    #2048). The decode error holds the WHOLE input (``JSONDecodeError.doc``,
    ``UnicodeDecodeError.object``): ``from exc`` puts it on ``__cause__``, and ``from None`` still
    leaves it on ``__context__``. See ``encode_wire_body`` in transports/base.py. Frame locals are
    out of reach of this: the raised error's traceback still holds the caller's frame."""
    refusal: str | None = None
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        refusal = f"JSONDecodeError at line {exc.lineno}, column {exc.colno}"
    except (ValueError, RecursionError) as exc:
        refusal = type(exc).__name__
    return None, refusal
