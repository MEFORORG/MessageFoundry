# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Lightweight, PHI/secret-aware redaction for support-bundle log lines (#49).

The support bundle ships a tail of the app log. Even though MessageFoundry never logs full message
bodies at INFO+ (PHI.md §1), a log line can still carry a stray HL7 fragment, a bearer token, a
``MEFOR_*`` secret value, or an embedded base64/``mfb64:`` blob — none of which belong in a file an
operator emails to support. This module scrubs those **patterns** out of each line.

It is deliberately a small regex pass, **not** the full HL7-shaped :mod:`messagefoundry.anon` engine:
the goal is "don't leak a secret or a body into the support zip", not deterministic de-identification.
Stdlib ``re`` only — no dependency, no engine state — so it stays usable from the offline CLI.

The PHI pass is **delegated to the shared engine redactor** (:func:`messagefoundry.redaction.redact`, also
pure stdlib ``re``) so bundled logs get exactly the same HL7-segment / field-run / DOB / multi-token-name
coverage as stored ``last_error``/log lines — instead of a second, narrower copy that drifts out of sync
(DELTA-07). That includes the structured-shape passes for FHIR JSON, DICOM tag dumps and XML (BACKLOG
#1711). They run per LINE here, so a pretty-printed structure split across lines is scrubbed only
where a line carries its own label; the write-time filter in ``logging_setup.py`` sees the whole
record and is the primary control for a log this engine wrote. This module adds the **secret** markers the engine redactor does not carry — at least
``mfb64:`` bodies, ``MEFOR_*`` values, bearer/authorization tokens, ``password=``/``PWD=``/``secret=``
pairs, key material (``private_key=``, ``encryption_key=``), an inline DSN password, and a long base64
run as the backstop.

**The credential-label passes are not stated here.** They are
:func:`messagefoundry.secretscrub.scrub_credentials`, the same pass the write-time log filters run
(BACKLOG #2694). This module calls it with its own ``[REDACTED]`` placeholder and keeps only the three
markers that belong to this surface rather than to the vocabulary: ``_MFB64``, ``_LONG_B64`` and
``_LEADING_TS``. ``secretscrub``'s docstring says why each of those three stays out. So a word added to
that vocabulary reaches the support archive and ``GET /logs/tail`` with no second edit.

**The credential VOCABULARY is derived from the engine, not hand-chosen here.**
``tests/test_log_redaction_secret_domain.py`` reads the engine's own registry of credential settings —
``config/wiring.py::_SECRET_SETTING_KEYS`` and ``config/settings.py::_FILE_SECRET_KEYS`` — and requires
every name in it to be either redacted by this module or listed in that file's exclusion table with a
stated reason. A credential setting added to the engine that this module cannot see therefore reds the
suite rather than shipping as a silent hole (BACKLOG #1475).

**Which patterns exist is not a claim to be read off this docstring.** Every pattern
:func:`redact_log_line` applies, here and one call down in ``secretscrub``, is derived by AST in
``tests/test_log_redaction_secret_domain.py`` and must be claimed by a named secret family there, so
adding one without a fixture reds the suite. That
guard exists because this module shipped a redactor that redacted nothing while the suite was green
(BACKLOG #1183): ``_BEARER`` consumed the word ``Bearer`` as its own value match and emitted the token
after it, and the one assertion covering it passed only because its chosen token was pure alphanumeric
and the unrelated long-base64 sweep caught it. Every fixture token now carries a hyphen and an
underscore so it cannot be reached by that sweep.
"""

from __future__ import annotations

import re

from messagefoundry.redaction import redact as _redact_phi
from messagefoundry.secretscrub import scrub_credentials

__all__ = [
    "redact_log_line",
    "redact_log_record",
    "redact_log_text",
    "split_log_lines",
    "REDACTION_PLACEHOLDER",
]

#: What every scrubbed span is replaced with (so a reviewer sees redaction happened, not a blank).
REDACTION_PLACEHOLDER = "[REDACTED]"

# A base64 binary-carriage marker (ADR 0028) and the embedded blob that follows it: definitely a body.
_MFB64 = re.compile(r"mfb64:v1:[A-Za-z0-9+/=]+")

# A long base64-ish run (>= 24 chars) that isn't otherwise matched — likely a key/token/encoded body.
_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")

# A leading log timestamp (ISO date, optional time). Protected from the shared engine PHI pass so the
# useful line timestamp survives that pass's DOB/date-run redaction — while a date *inside* the message
# body (a likely DOB) is still redacted. A non-ISO timestamp simply isn't protected here (over-redacted,
# the safe direction).
_LEADING_TS = re.compile(r"^\s*\d{4}[-/]\d{2}[-/]\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)?")

# WHAT COMPOSING ``scrub_credentials`` COST THIS SURFACE, AND WHAT IT BOUGHT (BACKLOG #2694). Until
# then this module held its own hand-kept copy of the six credential patterns. That copy scoped its
# case fold to each keyword alternation, ``(?i:...)``, which made each pattern 18 to 30 percent
# cheaper than ``secretscrub``'s global ``(?i)``, because a global fold also folds the scanned
# ``_LABEL_PREFIX`` class. The copy ran UNGATED: all six passes scanned every line.
#
# THE GLOBAL FOLD WAS KEPT, ON PURPOSE. It is not only slower. ``(?i)[A-Za-z0-9]`` also admits U+0130,
# U+017F and U+212A. So ``X_password=<v>``, with X spelled as U+212A (KELVIN SIGN), is redacted under
# the global fold and printed in full under the scoped one. The old comment here said the scoped fold
# "changes no match", and that held for ASCII only. Moving ``secretscrub`` to the scoped fold would buy
# time by narrowing the write-time pass, the trade its own docstring refuses.
# ``test_the_global_fold_reaches_a_label_the_scoped_fold_missed`` pins it.
#
# Measured 2026-10-04, min of 25 interleaved rounds, old copy against the composed call, the credential
# stage alone and then the whole ``redact_log_line``: a plain 65-char line 8.3 to 0.7 us (whole line -45
# percent); a credential line 9.7 to 5.0 us (-23); 6 KB of realistic log text 671 to 14 us (-63); 6 KB
# base64url naming one word 61 to 32 us (-45); a 6 KB hyphen-and-dot run naming no word 2.84 ms to
# 0.01 ms (-87). The admission gate buys those. ONE SHAPE GOT SLOWER: a 6 KB hyphen-and-dot run naming
# EVERY family, 1.44 to 2.14 ms for the stage and +26 percent end to end. That is the global fold paid
# on a line every gate admits, and it is the adversarial ceiling ``secretscrub``'s docstring states.
#
# THE GATE NARROWS NOTHING HERE, and that was measured before the swap. Over 12,574 lines -- every
# string literal in the redaction test files in five case spellings, plus the built fixtures -- the
# gated and ungated ``secretscrub`` passes agreed on every line. The old copy and the composed call
# disagreed on 8, all of them the non-ASCII fold lines added to the corpus to probe exactly this, and
# the composed call redacted MORE on each. No existing fixture differed.
# ``test_the_hint_gate_admits_every_bundle_fixture`` keeps the gate half of that live.


def redact_log_line(line: str) -> str:
    """Return ``line`` with PHI/secret patterns replaced by a redaction placeholder.

    Two layers: (1) the **secret** markers the engine redactor does not carry -- ``mfb64:`` bodies,
    then the shared credential-label pass (:func:`messagefoundry.secretscrub.scrub_credentials`:
    ``MEFOR_*`` values, bearer/session tokens, ``password=``-style pairs, key material, DSN
    passwords); then (2) the shared engine **PHI**
    redactor (:func:`messagefoundry.redaction.redact`) for HL7-shaped spans (any segment id, not a
    fixed allowlist), free-text DOB/date runs, multi-token name runs, and the labelled values of FHIR
    JSON, DICOM tag dumps and XML (BACKLOG #1711) — so bundled logs match the
    stored-error PHI coverage (DELTA-07). A final long-base64 sweep catches any residual key/token run.
    The leading log timestamp is carved off first so the engine's date pass doesn't scrub it. This errs
    toward over-redaction (e.g. a capitalized two-word phrase in ordinary log text may be scrubbed) —
    the correct trade-off for a file that leaves the box."""
    ts = _LEADING_TS.match(line)
    prefix, body = (line[: ts.end()], line[ts.end() :]) if ts else ("", line)
    body = _MFB64.sub(REDACTION_PLACEHOLDER, body)
    body = scrub_credentials(body, placeholder=REDACTION_PLACEHOLDER)
    body = _redact_phi(
        body
    )  # shared engine PHI pass: generic HL7 segments/field runs + DOB + names
    body = _LONG_B64.sub(REDACTION_PLACEHOLDER, body)
    return prefix + body


def split_log_lines(text: str) -> list[str]:
    """``text`` split into log lines at LF, CR and CRLF, and nowhere else (vault BACKLOG #2563).

    ``str.splitlines`` also ends a line at VT, FF, U+001C to U+001E, U+0085, U+2028 and U+2029. The
    write-time scrub (:func:`~messagefoundry.controlchars.scrub_control_chars`) escapes the C0 ones but
    deliberately not the last three, so a logged value holding one of them would read back as two
    records. The three endings kept are the ones a universal-newline file read recognises, so on those
    the result equals ``text.splitlines()`` exactly. At least both log tail readers split here, the
    web console viewer and the support bundle; a new reader should too."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()  # a final line ending closes the last line; it does not open an empty one
    return lines


#: The code points ``str.splitlines`` breaks at beyond CR and LF: VT, FF, U+001C to U+001E,
#: U+0085, U+2028 and U+2029. Written as escapes so no editor shows one as a line break.
_SPLITLINES_ONLY_BREAK = re.compile(r"([\x0b\x0c\x1c-\x1e\x85\u2028\u2029])")


def redact_log_record(line: str) -> str:
    """:func:`redact_log_line` over one line from :func:`split_log_lines`, piece by piece.

    The line stays whole, but each run between the code points in ``_SPLITLINES_ONLY_BREAK`` is
    redacted on its own, which is what the readers did while they split there. Redacting the joined
    line instead would let a pattern span the break and redact LESS: the name-run pattern caps its
    token count, so ``DOE JANE`` + U+2028 + ``ROE RICHARD SMITH`` leaves ``SMITH`` behind as one run,
    where the two pieces each redact in full."""
    parts = _SPLITLINES_ONLY_BREAK.split(line)
    parts[::2] = [redact_log_line(part) for part in parts[::2]]
    return "".join(parts)


def redact_log_text(text: str) -> str:
    """Redact every line of a multi-line block (the log tail), preserving line breaks."""
    return "\n".join(redact_log_record(ln) for ln in split_log_lines(text))
