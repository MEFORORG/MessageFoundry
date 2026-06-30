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
"""

from __future__ import annotations

import re

__all__ = ["redact_log_line", "redact_log_text", "REDACTION_PLACEHOLDER"]

#: What every scrubbed span is replaced with (so a reviewer sees redaction happened, not a blank).
REDACTION_PLACEHOLDER = "[REDACTED]"

# An HL7 v2 segment is a 3-char uppercase/digit segment id followed by the field separator and the
# rest of the line. A stray segment in a log line (e.g. an echoed message fragment) is PHI; collapse
# the whole segment to a placeholder rather than trying to field-walk it.
_HL7_SEGMENT = re.compile(
    r"\b(MSH|PID|PV1|OBX|OBR|EVN|NK1|ORC|IN1|AL1|DG1|GT1|SPM|MSA|ERR|ED)\|\S.*"
)

# A base64 binary-carriage marker (ADR 0028) and the embedded blob that follows it: definitely a body.
_MFB64 = re.compile(r"mfb64:v1:[A-Za-z0-9+/=]+")

# A bearer/authorization token or an opaque session token in a header-ish or "token=" shape.
_BEARER = re.compile(r"(?i)\b(bearer|authorization|token|session|api[_-]?key)\b\s*[:=]\s*\S+")

# A MEFOR_* secret echoed as "MEFOR_FOO=value" or "MEFOR_FOO: value": never carry the value.
_MEFOR_SECRET = re.compile(r"\bMEFOR_[A-Z0-9_]+\s*[:=]\s*\S+")

# A long base64-ish run (>= 24 chars) that isn't otherwise matched — likely a key/token/encoded body.
_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def redact_log_line(line: str) -> str:
    """Return ``line`` with PHI/secret patterns replaced by :data:`REDACTION_PLACEHOLDER`.

    Order matters: the most specific markers (``mfb64:``, ``MEFOR_*=``, bearer tokens, HL7 segments)
    run before the catch-all long-base64 sweep so they get a descriptive replacement first."""
    line = _MFB64.sub(REDACTION_PLACEHOLDER, line)
    line = _MEFOR_SECRET.sub(_keep_key("=" if "=" in line else ":"), line)
    line = _BEARER.sub(_keep_token_key, line)
    line = _HL7_SEGMENT.sub(lambda m: f"{m.group(1)}|{REDACTION_PLACEHOLDER}", line)
    line = _LONG_B64.sub(REDACTION_PLACEHOLDER, line)
    return line


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
