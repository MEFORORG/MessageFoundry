# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
(DELTA-07). This module adds only the **secret** markers the engine redactor does not carry
(``mfb64:`` bodies, ``MEFOR_*`` values, bearer/session tokens, long base64 runs).
"""

from __future__ import annotations

import re

from messagefoundry.redaction import redact as _redact_phi

__all__ = ["redact_log_line", "redact_log_text", "REDACTION_PLACEHOLDER"]

#: What every scrubbed span is replaced with (so a reviewer sees redaction happened, not a blank).
REDACTION_PLACEHOLDER = "[REDACTED]"

# A base64 binary-carriage marker (ADR 0028) and the embedded blob that follows it: definitely a body.
_MFB64 = re.compile(r"mfb64:v1:[A-Za-z0-9+/=]+")

# A bearer/authorization token or an opaque session token in a header-ish or "token=" shape.
_BEARER = re.compile(r"(?i)\b(bearer|authorization|token|session|api[_-]?key)\b\s*[:=]\s*\S+")

# A MEFOR_* secret echoed as "MEFOR_FOO=value" or "MEFOR_FOO: value": never carry the value.
_MEFOR_SECRET = re.compile(r"\bMEFOR_[A-Z0-9_]+\s*[:=]\s*\S+")

# A long base64-ish run (>= 24 chars) that isn't otherwise matched — likely a key/token/encoded body.
_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")

# A leading log timestamp (ISO date, optional time). Protected from the shared engine PHI pass so the
# useful line timestamp survives that pass's DOB/date-run redaction — while a date *inside* the message
# body (a likely DOB) is still redacted. A non-ISO timestamp simply isn't protected here (over-redacted,
# the safe direction).
_LEADING_TS = re.compile(r"^\s*\d{4}[-/]\d{2}[-/]\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)?")


def redact_log_line(line: str) -> str:
    """Return ``line`` with PHI/secret patterns replaced by a redaction placeholder.

    Two layers: (1) the bundle-specific **secret** markers (``mfb64:`` bodies, ``MEFOR_*`` values,
    bearer/session tokens) the engine redactor does not carry; then (2) the shared engine **PHI**
    redactor (:func:`messagefoundry.redaction.redact`) for HL7-shaped spans (any segment id, not a
    fixed allowlist), free-text DOB/date runs, and multi-token name runs — so bundled logs match the
    stored-error PHI coverage (DELTA-07). A final long-base64 sweep catches any residual key/token run.
    The leading log timestamp is carved off first so the engine's date pass doesn't scrub it. This errs
    toward over-redaction (e.g. a capitalized two-word phrase in ordinary log text may be scrubbed) —
    the correct trade-off for a file that leaves the box."""
    ts = _LEADING_TS.match(line)
    prefix, body = (line[: ts.end()], line[ts.end() :]) if ts else ("", line)
    body = _MFB64.sub(REDACTION_PLACEHOLDER, body)
    body = _MEFOR_SECRET.sub(_keep_key("=" if "=" in body else ":"), body)
    body = _BEARER.sub(_keep_token_key, body)
    body = _redact_phi(
        body
    )  # shared engine PHI pass: generic HL7 segments/field runs + DOB + names
    body = _LONG_B64.sub(REDACTION_PLACEHOLDER, body)
    return prefix + body


def redact_log_text(text: str) -> str:
    """Redact every line of a multi-line block (the log tail), preserving line breaks."""
    return "\n".join(redact_log_line(ln) for ln in text.splitlines())


def _keep_key(_sep: str):  # type: ignore[no-untyped-def]
    """Replace a ``MEFOR_NAME=value`` match, keeping the NAME so a reviewer sees WHICH var leaked but
    not its value."""

    def repl(m: re.Match[str]) -> str:
        head = m.group(0).split("=", 1)[0] if "=" in m.group(0) else m.group(0).split(":", 1)[0]
        return f"{head.rstrip()}={REDACTION_PLACEHOLDER}"

    return repl


def _keep_token_key(m: re.Match[str]) -> str:
    """Replace a ``bearer <tok>`` / ``token: <tok>`` match, keeping the label and hiding the value."""
    return f"{m.group(1)}={REDACTION_PLACEHOLDER}"
