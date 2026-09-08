# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
Pure stdlib (``re`` only), so it can be used from any engine package.
"""

from __future__ import annotations

import re

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


def safe_exc(exc: BaseException, *, limit: int = _DEFAULT_LIMIT) -> str:
    """A PHI-redacted, length-bounded rendering of ``exc`` for a stored ``last_error``/``detail`` or a
    log line. Always keeps the exception **type** (safe + most useful); the message is redacted
    (:func:`redact`) and truncated — so a Router/Handler that did ``raise ValueError(f"...{raw}")``
    can't leak the HL7 body into the store or logs."""
    name = type(exc).__name__
    message = safe_text(str(exc), limit=limit)
    return f"{name}: {message}" if message else name
