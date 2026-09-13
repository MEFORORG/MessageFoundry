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
(DELTA-07). This module adds the **secret** markers the engine redactor does not carry — at least
``mfb64:`` bodies, ``MEFOR_*`` values, bearer/authorization tokens, ``password=``/``PWD=``/``secret=``
pairs, key material (``private_key=``, ``encryption_key=``), an inline DSN password, and a long base64
run as the backstop. A credential label may carry a dotted/underscored/hyphenated prefix
(``client_secret=``, ``bearer_token=``) — see ``_LABEL_PREFIX``.

**The credential VOCABULARY is derived from the engine, not hand-chosen here.**
``tests/test_log_redaction_secret_domain.py`` reads the engine's own registry of credential settings —
``config/wiring.py::_SECRET_SETTING_KEYS`` and ``config/settings.py::_FILE_SECRET_KEYS`` — and requires
every name in it to be either redacted by this module or listed in that file's exclusion table with a
stated reason. A credential setting added to the engine that this module cannot see therefore reds the
suite rather than shipping as a silent hole (BACKLOG #1475).

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

# An optional dotted / underscored / hyphenated PREFIX on a credential label, so a snake_case label
# reaches the keyword at its tail.
#
# ``\b`` DOES NOT FIRE AFTER AN UNDERSCORE, because ``_`` is a word character. Without this prefix the
# label patterns below could only ever match a credential word standing alone — which is not how this
# engine names its credentials. ``client_secret``, ``bearer_token``, ``basic_password``,
# ``ad_bind_password`` and ``tls_key_password`` are all real identifiers in this tree, and every one of
# them survived the redactor verbatim (BACKLOG #1183, re-verified 2026-09-06). The engine's own setting
# vocabulary was the shape its log redactor could not see.
#
# Each segment must END in a separator, so the prefix cannot cross a space, a ";" in an ODBC string or
# any other delimiter — it widens the LABEL only, never the value span. It is spliced into group 1 of
# both patterns below so ``_keep_label`` still prints the whole label a reviewer needs to see.
#
# THE REPETITION BOUND IS LOAD-BEARING AND IT IS NOT TASTE. Unbounded (``*``) this is QUADRATIC in line
# length, on log text an attacker can influence. ``_`` suppresses ``\b``, but "." and "-" do not, so an
# N-segment dotted or hyphenated run offers N word-boundary start positions and the group re-walks the
# remaining O(N) segments from each one. Measured on this interpreter over 20 passes of one ~6 KB
# hyphen-and-dot run: 1.5 ms for the pre-change pattern, 827 ms unbounded, 11 ms at ``{0,6}``. **Base64url
# uses "-", so a JWT echoed in an upstream error is exactly the bad shape**, which makes this reachable
# rather than theoretical on ``GET /logs/tail`` and in the support bundle. Cost grows LINEARLY with the
# bound (8 ms at 4, 11 at 6, 14 at 8), so six is bought cheaply.
#
# WHAT THE BOUND COSTS, stated because it fails SILENTLY in one direction: a label with more than six
# prefix segments joined by UNDERSCORES is not matched, since ``_`` offers no later start position to
# retry from. A dotted or hyphenated label of any depth still matches, for the same ``\b`` reason that
# makes it expensive. Six is 3x the longest real label this fixes (``ad_bind_password``,
# ``tls_key_password`` — two prefix segments each) and nothing in this tree comes close.
_LABEL_PREFIX = r"(?:[A-Za-z0-9]+[._-]){0,6}"

# WHY THE CASE FOLD IS SCOPED TO THE ALTERNATION, HERE AND IN THE TWO PATTERNS BELOW. Stated once,
# because all three share it. A global ``(?i)`` folds the SCANNED CHARACTER CLASS as well as the
# keywords, and the scanned class is ``_LABEL_PREFIX``. Only the credential KEYWORDS have a case to
# fold: ``[A-Za-z0-9]`` already spans both cases, and the separators, quotes and value classes have no
# case at all. ``(?i:...)`` around the alternation therefore changes no match and stops paying for the
# fold on the hot scan.
#
# THE MECHANISM IS THE CHARACTER CLASS, NOT A PREFIX OPTIMIZATION, and an earlier draft of this comment
# had it wrong. Measured on this interpreter: ``[A-Za-z0-9]`` compiles to 28 code words plain and 99
# under IGNORECASE, because the fold turns a small CHARSET into a Unicode-folding BIGCHARSET walked at
# every start position — ``_LABEL_PREFIX`` alone costs 74 percent more folded (0.69 ms against 1.20 ms
# on a 6 KB hyphen run). ``_compile_info`` contributes NOTHING here: all three patterns start with
# ``\b``, so its INFO flags word reads 0 both before and after, measured. The distinction is load
# bearing rather than pedantic — it is what says WHICH patterns this trick pays on. A pattern with no
# scanned class under the fold gains nothing, which is why ``_AUTH_SCHEME`` is left alone below.
#
# Measured 2026-09-06, min of 25 interleaved rounds of 20 passes over 6 KB inputs, noise floor +/- 1.2
# percent (the same pattern benched against itself). Realistic log text and a 6 KB base64url line, the
# two ends of the range: ``_BEARER`` 21.8 and 30.1 percent, ``_CREDENTIAL_KV`` 18.7 and 30.5,
# ``_KEY_MATERIAL`` 21.4 and 27.6. Through ``redact_log_line`` end to end, 9.1 percent. Interleaved
# because this box is shared: a sequential layout swung 30 points between two runs of one pair.
#
# THE OTHER TWO PATTERNS CARRYING A GLOBAL ``(?i)`` ARE LEFT ALONE, FOR DIFFERENT REASONS. Scoping
# ``_AUTH_SCHEME`` is worth ZERO and should stay unscoped: its only case-bearing part IS the span that
# would be scoped, and the two spellings compile to the same program. ``_DSN_PASSWORD`` would pay --
# it scans two classes under its fold -- but its ``[a-z]`` classes depend on the global fold, so
# scoping it means rewriting them, and it has a larger and separate problem: ``[a-z0-9+.\-]*`` is
# unbounded over "." and "-", which is the quadratic shape ``_LABEL_PREFIX``'s ``{0,6}`` bound exists
# to stop. Measured on a hyphen run, 4.00x the time for 2x the length at every step from 512 B to
# 8 KB: 0.30, 1.18, 4.72, 18.75, 74.96 ms. That is a fix with its own reasoning and its own test, not
# a line to fold into this one.
#
# EVERY ALTERNATION OF LITERAL WORDS NEEDS ITS OWN ``(?i:...)``, AND THIS PATTERN HAS TWO. Scope only
# the first and the optional ``(?:bearer|basic|digest)\s+`` scheme group goes case-SENSITIVE: it stops
# matching "Bearer", the value class takes that word instead, and the token prints -- BACKLOG #1183's
# original defect, re-introduced silently. Measured: 151 differing inputs against the shipped pattern.
# THE SHIPPED SUITE CANNOT SEE IT, because ``_AUTH_SCHEME`` covers the same line and the family goes
# green on the other pattern's work. ``test_the_bearer_pattern_folds_case_on_the_auth_scheme_word``
# disables ``_AUTH_SCHEME`` and pins this group on its own.
#
# A bearer/authorization token or an opaque session token in a header-ish or "token=" shape.
#
# The ``(?:bearer|basic|digest)\s+`` group is load-bearing, not decoration: without it ``\S+`` matches
# the AUTH SCHEME rather than the credential, so "Authorization: Bearer <tok>" redacted the word
# "Bearer" and emitted <tok> verbatim. Making the group optional keeps the plain "token=<tok>" shape
# working, and the value class excludes quotes so a quoted credential loses the value, not the quote.
_BEARER = re.compile(
    r"\b(" + _LABEL_PREFIX + r"(?i:bearer|authorization|token|session|api[_-]?key))\b"
    r"\s*[:=]\s*(?:(?i:bearer|basic|digest)\s+)?['\"]?[^\s'\"]+"
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
# "ws_password_type must be 'text'". A token that is also ordinary vocabulary discriminates
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
#
# The case fold is scoped to the alternation; the reason and the numbers are on ``_BEARER``.
_CREDENTIAL_KV = re.compile(
    r"\b(" + _LABEL_PREFIX + r"(?i:pass(?:word|wd|phrase)?|pwd|secret|credential))\b"
    r"['\"]?\s*[:=]\s*['\"]?[^\s'\";,&]+"
)

# Key MATERIAL in a "<label>=<value>" pair, where the label ends in a credential word neither pattern
# above can reach. Measured 2026-09-06 against the engine's own credential registry: five settings it
# classifies as secrets survived every pattern in this module verbatim — ``private_key``,
# ``smart_private_key``, ``encryption_key``, ``encryption_keys_retired`` and ``intake_api_key_next``
# (BACKLOG #1475). ``smart_private_key`` needs no alternate of its own: ``_LABEL_PREFIX`` reaches it.
#
# LITERAL ALTERNATES, BECAUSE THE TWO GENERAL RULES FAIL IN OPPOSITE DIRECTIONS. Measured 2026-09-06,
# both spliced onto ``_LABEL_PREFIX`` with this pattern's own trailing ``\b``:
#
#   a SUFFIX rule ("the label ENDS in a key word") reaches 3 of the 5. It cannot reach
#   ``encryption_keys_retired`` or ``intake_api_key_next`` at all, because neither ends in a key word.
#
#   a CONTAINS rule ("a key word ANYWHERE in the label") reaches all 5 and eats
#   ``intake_api_key_header``, ``private_key_file`` and ``encryption_key_ref`` -- plus the ordinary
#   vocabulary. Censused over ``messagefoundry/`` by tokenizing, so comments and strings are excluded
#   and this comment cannot count itself: 78 distinct identifiers ending ``_key``/``_keys``, 577
#   occurrences, led by ``file_key`` 59 and ``idempotency_key`` 58 against ``private_key`` 22.
#   ``idempotency_key`` is how an operator traces a message through the staged pipeline, so a contains
#   rule would blind the reader the support bundle exists for.
#
# ``intake_api_key_header`` is the sharpest of those: this engine classifies it NON-SECRET on purpose,
# being the header NAME an intake credential arrives in rather than the credential (``config/wiring.py``,
# pinned by name in ``tests/test_connection_api.py``). Bare ``key`` stays out for the reason already
# stated at ``_CREDENTIAL_KV``.
#
# The alternates are NOT derived from ``_SECRET_SETTING_KEYS`` at runtime, though the import would now
# be free: that registry is ``/metadata``'s redaction policy, so a name dropped from it for a display
# reason would silently stop being scrubbed here, and it carries the six usernames this module
# deliberately does not redact. A literal list cannot be weakened by a registry edit; the derived guard
# in ``tests/test_log_redaction_secret_domain.py`` catches the drift loudly instead.
#
# The alternate must END the label — the trailing ``\b`` cannot fire before "_" — so a PATH or a name
# keeps its value: ``private_key_file=``, ``encryption_key_ref=`` and ``intake_api_key_header=`` all
# survive this pattern intact.
#
# WHY THE VALUE CLASS ADMITS A COMMA, unlike ``_CREDENTIAL_KV``: ``encryption_keys_retired`` ships as a
# COMMA-JOINED LIST (``store/keyprovider.py::_split_retired``), so a comma terminator would redact the
# first retired key and print the rest. Whitespace, quotes, ";" and "&" still terminate, so a redaction
# cannot swallow the rest of a log line. RESIDUAL, stated because this pattern does not cover it: a list
# written with a SPACE after the comma leaves its later elements to the ``_LONG_B64`` sweep.
#
# The case fold is scoped to the alternation; the reason and the numbers are on ``_BEARER``.
#
# ``encryption_keys_retired`` AND ``encryption_key`` ARE WRITTEN AS ONE FACTORED ALTERNATE, so neither
# setting name appears in the pattern as a literal — grep the comments above for them, not the regex.
# CPython does not factor a common prefix out of an alternation, so as two branches the first walks the
# shared 14 characters, fails at "s", and the second re-walks them. The greedy ``?`` still tries the
# long form first, so the two forms match identically: proved over 135,115 inputs, zero differences.
# WORTH LESS THAN THE REVIEW THAT PROPOSED IT CLAIMED, and the corrected number is recorded here so
# nobody re-derives the larger one: 3.3 percent on realistic log text and 4.5 on an ``encryption_key-``
# run, against a claimed 15 and 17. It clears the +/- 1.2 percent noise floor on four of five corpora
# and is inside it on the fifth, which carries no key label at all. The prefix repetition dominates the
# alternation walk, which is why factoring the alternation moves so little.
#
# MERGING THIS PATTERN WITH ``_CREDENTIAL_KV`` WAS MEASURED, COSTED AND DECLINED (2026-09-06). One
# combined two-branch pass is worth 12.3 percent on realistic log text and 30.6 on a base64url line
# (and nothing at all on the two adversarial runs). THAT IS WORTH MORE THAN THE FACTORING ACCEPTED
# JUST ABOVE, WHICH IS NOT AN INCONSISTENCY -- the two are refused and accepted on different grounds.
# The factoring costs a grep hop that the comment above repairs. This costs a test property that no
# comment can restore. It is refused on the guard, not on the number:
# ``tests/test_log_redaction_secret_domain.py`` derives the applied pattern set by AST, five families
# name ``_KEY_MATERIAL``, and ``test_each_family_survives_when_its_own_patterns_are_disabled`` proves
# a family's own pattern does the work by disabling it. One pattern cannot be disabled without the
# other, so the merge trades away exactly the discrimination between the two credential classes that
# the file exists to hold. The price is not worth paying on a path that is not the bottleneck: on one
# 6 KB line this pattern runs 0.150 ms against 33.8 ms for the shared PHI pass beside it in the same
# call — 225x. Do not re-derive this and take it.
_KEY_MATERIAL = re.compile(
    r"\b(" + _LABEL_PREFIX + r"(?i:encryption_key(?:s_retired)?|private_key"
    r"|intake_api_key_next))\b['\"]?\s*[:=]\s*['\"]?[^\s'\";&]+"
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
    body = _KEY_MATERIAL.sub(_keep_label, body)
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
