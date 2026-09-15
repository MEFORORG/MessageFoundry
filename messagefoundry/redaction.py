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
remains the control. Pure stdlib (``re`` only), so it can be used from any engine package.
"""

from __future__ import annotations

import re
from functools import lru_cache

__all__ = ["redact", "safe_exc", "safe_text"]

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
    store-layer chokepoint over values a caller may already have scrubbed."""
    message = redact(text).strip()
    if len(message) > limit:
        message = f"{message[:limit]}…(+{len(message) - limit} chars)"
    return message


def safe_exc(exc: BaseException, *, limit: int = _DEFAULT_LIMIT) -> str:
    """A PHI-redacted, length-bounded rendering of ``exc`` for a stored ``last_error``/``detail`` or a
    log line. Always keeps the exception **type** (safe + most useful); the message is redacted
    (:func:`redact`) and truncated — so a Router/Handler that did ``raise ValueError(f"...{raw}")``
    can't leak the HL7 body into the store or logs."""
    name = type(exc).__name__
    message = safe_text(str(exc), limit=limit)
    return f"{name}: {message}" if message else name
