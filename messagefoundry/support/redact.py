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
(DELTA-07). This module adds the **secret** markers the engine redactor does not carry — at least
``mfb64:`` bodies, ``MEFOR_*`` values, bearer/authorization tokens, ``password=``/``PWD=``/``secret=``
pairs, an inline DSN password, and a long base64 run as the backstop.

**Which patterns exist is not a claim to be read off this docstring.** Every pattern
:func:`redact_log_line` applies is derived by AST in ``tests/test_log_redaction_secret_domain.py`` and
must be claimed by a named secret family there, so adding one without a fixture reds the suite. That
guard exists because this module shipped a redactor that redacted nothing while the suite was green
(BACKLOG #1183): ``_BEARER`` consumed the word ``Bearer`` as its own value match and emitted the token
after it, and the one assertion covering it passed only because its chosen token was pure alphanumeric
and the unrelated long-base64 sweep caught it. Every fixture token now carries a hyphen and an
underscore so it cannot be reached by that sweep.
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
#
# The ``(?:bearer|basic|digest)\s+`` group is load-bearing, not decoration: without it ``\S+`` matches
# the AUTH SCHEME rather than the credential, so "Authorization: Bearer <tok>" redacted the word
# "Bearer" and emitted <tok> verbatim. Making the group optional keeps the plain "token=<tok>" shape
# working, and the value class excludes quotes so a quoted credential loses the value, not the quote.
_BEARER = re.compile(
    r"(?i)\b(bearer|authorization|token|session|api[_-]?key)\b"
    r"\s*[:=]\s*(?:(?:bearer|basic|digest)\s+)?['\"]?[^\s'\"]+"
)

# A bare auth scheme carrying its credential with no preceding header label — "Bearer <tok>" as it
# appears in a WWW-Authenticate echo or a client retry line. ``_BEARER`` cannot reach this: it requires
# a ":" or "=" after the label, and there is none here. The scheme word is kept so a reviewer sees what
# leaked.
#
# "bearer" ONLY, deliberately, even though ``_BEARER`` above accepts basic and digest as scheme words.
# There the header label guarantees the line is an authorization header; here nothing does, and both
# other words are ordinary configuration vocabulary in this codebase — ``transports/http_auth.py``
# raises "oauth2_auth_style must be 'basic' or 'post'" and ``transports/soap.py`` raises
# "ws_password_type must be 'text' or 'digest'". A token that is also ordinary vocabulary discriminates
# nothing, so matching on it would redact operator diagnostics and buy no confidentiality: a labelled
# "Authorization: Basic <cred>" is already carried by ``_BEARER``.
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer)\s+['\"]?[^\s'\",;]{4,}")

# A MEFOR_* secret echoed as "MEFOR_FOO=value" or "MEFOR_FOO: value": never carry the value. The
# optional quotes match the shape an error string produces — "(env 'MEFOR_VALUE_PW'='<value>')" — which
# the unquoted form missed entirely.
_MEFOR_SECRET = re.compile(r"\b(MEFOR_[A-Z0-9_]+)\b['\"]?\s*[:=]\s*['\"]?[^\s'\"]+['\"]?")

# A credential in a "<label>=<value>" pair: an ODBC "PWD=", a "password=" in a connection error, a
# provider "secret=". The value class stops at the separators these actually appear inside (";" in an
# ODBC string, "," and "&" in a query), so a redaction cannot swallow the rest of the line.
#
# "key" is deliberately ABSENT from the label set. It is ordinary vocabulary here — code-set keys,
# cache keys, dictionary keys all appear as "key=" in log text — so it would discriminate nothing. The
# credential-bearing spelling "api_key" is carried by ``_BEARER`` instead.
_CREDENTIAL_KV = re.compile(
    r"(?i)\b(pass(?:word|wd|phrase)?|pwd|secret|credential)\b['\"]?\s*[:=]\s*['\"]?[^\s'\";,&]+"
)

# An inline password in a URL-shaped DSN: "postgres://user:<pw>@host/db". The scheme and the user
# survive so an operator can still tell which connection failed.
_DSN_PASSWORD = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@")

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
    body = _MEFOR_SECRET.sub(_keep_label, body)
    body = _BEARER.sub(_keep_label, body)
    body = _AUTH_SCHEME.sub(_keep_scheme, body)
    body = _CREDENTIAL_KV.sub(_keep_label, body)
    body = _DSN_PASSWORD.sub(_keep_dsn_user, body)
    body = _redact_phi(
        body
    )  # shared engine PHI pass: generic HL7 segments/field runs + DOB + names
    body = _LONG_B64.sub(REDACTION_PLACEHOLDER, body)
    return prefix + body


def redact_log_text(text: str) -> str:
    """Redact every line of a multi-line block (the log tail), preserving line breaks."""
    return "\n".join(redact_log_line(ln) for ln in text.splitlines())


def _keep_label(m: re.Match[str]) -> str:
    """Replace a ``<label>=<value>`` match, keeping the label so a reviewer sees WHICH credential
    leaked, and never the value. Group 1 is the label in every pattern that uses this."""
    return f"{m.group(1)}={REDACTION_PLACEHOLDER}"


def _keep_scheme(m: re.Match[str]) -> str:
    """Replace a bare ``Bearer <tok>`` match, keeping the scheme word and hiding the credential."""
    return f"{m.group(1)} {REDACTION_PLACEHOLDER}"


def _keep_dsn_user(m: re.Match[str]) -> str:
    """Replace the password span of a URL-shaped DSN, keeping ``scheme://user`` and the ``@``."""
    return f"{m.group(1)}:{REDACTION_PLACEHOLDER}@"
