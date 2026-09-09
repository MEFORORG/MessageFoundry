# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The credential-label vocabulary every log sink scrubs by, stated once (BACKLOG #1478).

A **neutral leaf**: stdlib ``re`` only, no engine, config, FastAPI or Qt imports, so both the
write-time log handler filters (``logging_setup``) and the read-time support-bundle redactor
(``support/redact.py``) can depend on it. It lives at the package root beside the other neutral leaves
(``redaction``, ``controlchars``, ``credential``, ``netaddr``) for the reason ``credential``'s docstring
already gives, and ``logging_setup`` imports it the way it imports ``controlchars`` -- **for its
DEFINITION rather than its behaviour**.

WHY IT EXISTS. The three filters ``logging_setup._install_phi_filters`` puts on every handler carried
no credential vocabulary at all. Measured 2026-09-06 by driving all three in sequence over a
``LogRecord``: ``encryption_key=``, ``vault_token=``, ``client_secret=``, ``ad_bind_password=``,
``tls_key_password=``, ``private_key=`` and ``Authorization: Bearer <tok>`` all passed **verbatim**,
with the OIDC ``code=``/``state=`` control scrubbing in the same run. Those filters run at WRITE time,
on the stdout handler NSSM captures **and on the off-box syslog forwarder** -- streams 1 and 4 of
``docs/PHI.md`` section 7, which owns that inventory and is not restated here. ``support/redact.py``
is a **second** pass, over the support archive and ``GET /logs/tail``; it reads a log already
written, so it can never reach a record on its way to a collector.

WHAT IS HERE AND WHAT IS DELIBERATELY NOT. This module carries the **credential-label** patterns and
nothing else. Three markers that ``support/redact.py`` applies stay there, because they are properties
of *that* surface rather than of the vocabulary:

* ``_MFB64`` -- an ADR 0028 base64 body carriage. A message body is PHI, owned by
  :mod:`messagefoundry.redaction` and by the "never log full bodies at INFO+" rule (PHI.md section 1),
  not by a credential vocabulary.
* ``_LONG_B64`` -- a >= 24-char base64 run, redacted as a backstop. Over-redaction is the right
  direction for a file that leaves the box; it is the wrong direction for the operator's live console,
  where it would eat an ``idempotency_key`` (58 occurrences in this tree against ``private_key``'s 22,
  censused under BACKLOG #1475) -- the identifier an operator traces a message through the staged
  pipeline by.
* ``_LEADING_TS`` -- carves a log-FILE line's leading timestamp off before the PHI date pass. A
  ``LogRecord`` carries its timestamp in ``record.created``, not in the message, so there is nothing to
  carve.

AND THE OTHER BOUNDARY, because it looks like a duplicate and is not.
``logging_setup.CredentialQueryScrubFilter`` keeps its own short list -- ``code``, ``state``,
``id_token``, ``access_token``, ``token``, ``session_state`` -- and is NOT folded in here. Its words are
safe only *because* they are scoped to a URL query string: ``code`` and ``state`` are ordinary
operational vocabulary (``code=404``, ``state=RUNNING``), so admitting them to a general
``label=value`` rule would redact operator diagnostics and buy nothing. That list also carries a ruling
about two names deliberately absent from it (docs/PHI.md section 7, BACKLOG #1184), which a merge would
disturb. Two vocabularies with a stated boundary, not one vocabulary stated twice.

COST, because this runs on EVERY record and the read-time pass does not. Measured 2026-09-06 as the
MINIMUM single-call time over interleaved samples -- a minimum is the one statistic the load of a
fleet-shared box cannot inflate. What this module ADDS to the four-filter chain, per record:

=====================================================  =============
line                                                   added
=====================================================  =============
plain 65-char operational line                          **0.9 us**
a real credential line (``ad_bind_password=...``)        **3.7 us**
6 KB hyphen-and-dot run, naming no credential word         15 us
6 KB base64url, naming one credential word               0.49 ms
6 KB hyphen-and-dot run naming EVERY family             **21 ms**
=====================================================  =============

The first two are the cost that is actually paid, and they are the numbers this module is shaped by.

The last is the adversarial ceiling, stated rather than hidden: log text is attacker-influenceable, and
:data:`_LABEL_PREFIX`'s bounded repetition is O(6N) per word-boundary start position, so a long
dotted-or-hyphenated run that names every family defeats every admission gate. It is not a NEW class of
hazard -- :func:`messagefoundry.redaction.redact` costs **33 ms** on the same 6 KB line, before this
module runs at all, and ``support/redact.py`` has the identical property on ``GET /logs/tail`` today.
It was NOT bought down further: the obvious lever, a bounded lookahead requiring a separator near the
label, would silently stop scrubbing a credential whose label is longer than the bound. Trading a
silent security narrowing for time on a synthetic input, against a cost this module does not dominate,
is the wrong direction.

WHAT KEEPS THE REAL NUMBERS SMALL is the admission gating described below -- a casefolded substring
test, not a compiled alternation, and one per pass rather than one shared. Between them they took the
plain line from 4.4 us to 0.9 us and the credential line from 7.8 us to 3.7 us; the 6 KB run naming no
credential word went from 0.39 ms to 15 us.
"""

from __future__ import annotations

import re

__all__ = ["CREDENTIAL_PLACEHOLDER", "scrub_credentials"]

#: What a scrubbed credential VALUE is replaced with. Matches
#: :class:`logging_setup.CredentialQueryScrubFilter`, so one log line cannot carry two spellings of
#: "a credential was here". A caller wanting a different marker passes ``placeholder=`` --
#: ``support/redact.py``'s ``[REDACTED]`` is the one that will.
CREDENTIAL_PLACEHOLDER = "<redacted>"

#: Label tails that mean "a credential value follows". Bare ``key`` is deliberately absent: it is
#: ordinary vocabulary here (code-set keys, cache keys, dictionary keys all appear as ``key=`` in log
#: text), so it would discriminate nothing. The credential-bearing spellings are carried by
#: :data:`_TOKEN_WORDS` and :data:`_KEY_MATERIAL_WORDS` instead.
_CREDENTIAL_WORDS = ("password", "passwd", "passphrase", "pass", "pwd", "secret", "credential")

#: Label tails naming a bearer/session/API credential.
_TOKEN_WORDS = ("authorization", "bearer", "token", "session", "api_key", "api-key", "apikey")

#: Key MATERIAL labels, as LITERAL alternates rather than a general rule.
#:
#: This list is BACKLOG #1475's measurement, reused rather than re-derived: those four names are the
#: engine credential settings that no suffix rule and no general ``key`` rule can safely reach.
#: ``encryption_keys_retired`` and ``intake_api_key_next`` do not END in a key word, so a suffix rule
#: misses them; a "key word anywhere in the label" rule reaches them and also eats
#: ``intake_api_key_header`` (a header NAME the engine classifies non-secret on purpose),
#: ``private_key_file`` (a path) and ``encryption_key_ref`` (a reference), plus the ordinary
#: ``_key``/``_keys`` vocabulary. ``smart_private_key`` needs no alternate: :data:`_LABEL_PREFIX`
#: reaches it.
#:
#: NOT DERIVED FROM THE ENGINE REGISTRIES AT RUNTIME, and that is a decision rather than a limitation.
#: ``config/settings.py`` imports ``LOG_LEVELS`` from ``logging_setup``, so a ``logging_setup`` that
#: imported the registries back would close a cycle. Even without that, BACKLOG #1475 already refused
#: the runtime read on its own ground: ``_SECRET_SETTING_KEYS`` is ``/metadata``'s redaction policy, so
#: a name dropped from it for a display reason would silently stop being scrubbed. A literal list
#: cannot be weakened by a registry edit; the derived guard in
#: ``tests/test_log_redaction_secret_domain.py`` catches the drift loudly instead.
_KEY_MATERIAL_WORDS = (
    "encryption_keys_retired",
    "encryption_key",
    "private_key",
    "intake_api_key_next",
)

#: The environment-variable prefix every MessageFoundry secret arrives under. ``resolve_env_settings``
#: echoes the NAME and the VALUE together on a cast failure -- ``setting 'password' (env
#: 'MEFOR_VALUE_PW'='<value>')`` -- and that error text reaches the general log.
_ENV_PREFIX = "MEFOR_"

#: The literal substring a URL-shaped DSN must contain, so its admission gate can see
#: :data:`_DSN_PASSWORD`.
_DSN_MARKER = "://"


def _alternation(words: tuple[str, ...]) -> str:
    """Escaped alternation over ``words``, longest first.

    Longest-first is not correctness -- every pattern below ends its label group with ``\\b``, so a
    short alternate matching inside a longer word backtracks and retries. It is cost: without it
    ``pass`` matches inside ``password`` on every credential label and the engine walks back."""
    return "|".join(re.escape(word) for word in sorted(words, key=len, reverse=True))


# An optional dotted / underscored / hyphenated PREFIX on a credential label, so a snake_case label
# reaches the keyword at its tail.
#
# ``\b`` DOES NOT FIRE AFTER AN UNDERSCORE, because "_" is a word character. Without this prefix the
# label patterns below could only match a credential word standing alone -- which is not how this
# engine names its credentials. ``client_secret``, ``bearer_token``, ``basic_password``,
# ``ad_bind_password``, ``tls_key_password`` and ``vault_token`` are all real identifiers in this tree,
# and every one of them survived the write-time filter chain verbatim (measured 2026-09-06).
#
# Each segment must END in a separator, so the prefix cannot cross a space, a ";" in an ODBC string or
# any other delimiter -- it widens the LABEL only, never the value span.
#
# THE REPETITION BOUND IS LOAD-BEARING. Unbounded ("*") this is QUADRATIC in line length, on log text
# an attacker can influence, and this module runs on EVERY record. "_" suppresses ``\b``, but "." and
# "-" do not, so an N-segment dotted or hyphenated run offers N word-boundary start positions and the
# group re-walks the remaining O(N) segments from each one. Base64url uses "-", so a JWT echoed in an
# upstream error is exactly the bad shape. Measured under BACKLOG #1475 over 20 passes of one ~6 KB
# hyphen-and-dot run: 1.5 ms unwidened, 827 ms unbounded, 11 ms at ``{0,6}``.
#
# WHAT THE BOUND COSTS, stated because it fails SILENTLY in one direction: a label with more than six
# prefix segments joined by UNDERSCORES is not matched, since "_" offers no later start position to
# retry from. A dotted or hyphenated label of any depth still matches, for the same ``\b`` reason that
# makes it expensive. Six is 3x the longest real label this reaches (``ad_bind_password``,
# ``tls_key_password`` -- two prefix segments each) and nothing in this tree comes close.
_LABEL_PREFIX = r"(?:[A-Za-z0-9]+[._-]){0,6}"

# A bearer/authorization token or an opaque session token in a header-ish or "token=" shape.
#
# The ``(?:bearer|basic|digest)\s+`` group is load-bearing, not decoration: without it the value class
# matches the AUTH SCHEME rather than the credential, so "Authorization: Bearer <tok>" redacts the word
# "Bearer" and emits <tok> verbatim. That exact defect shipped green on the sibling surface for months
# (BACKLOG #1183). Making the group optional keeps the plain "token=<tok>" shape working, and the value
# class excludes quotes so a quoted credential loses the value, not the quote.
_BEARER = re.compile(
    r"(?i)\b(" + _LABEL_PREFIX + r"(?:" + _alternation(_TOKEN_WORDS) + r"))\b"
    r"\s*[:=]\s*(?:(?:bearer|basic|digest)\s+)?['\"]?[^\s'\"]+"
)

# A bare auth scheme carrying its credential with no preceding header label -- "Bearer <tok>" as it
# appears in a WWW-Authenticate echo or a client retry line. ``_BEARER`` cannot reach this: it requires
# a ":" or "=" after the label, and there is none here. The scheme word is kept so a reviewer sees what
# leaked.
#
# "bearer" ONLY, deliberately, even though ``_BEARER`` accepts basic and digest as scheme words. There
# the header label guarantees the line is an authorization header; here nothing does, and both other
# words are ordinary configuration vocabulary in this codebase -- ``transports/http_auth.py`` raises
# "oauth2_auth_style must be 'basic' or 'post'" and ``transports/soap.py`` raises "ws_password_type
# must be 'text'". A token that is also ordinary vocabulary discriminates nothing, so matching on it
# would redact operator diagnostics and buy no confidentiality: a labelled "Authorization: Basic
# <cred>" is already carried by ``_BEARER``.
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer)\s+['\"]?[^\s'\",;]{4,}")

# A MEFOR_* secret echoed as "MEFOR_FOO=value" or "MEFOR_FOO: value": never carry the value. The
# optional quotes match the shape ``resolve_env_settings`` produces -- "(env 'MEFOR_VALUE_PW'='<value>')"
# -- which an unquoted form misses entirely.
_MEFOR_SECRET = re.compile(
    r"\b(" + re.escape(_ENV_PREFIX) + r"[A-Z0-9_]+)\b['\"]?\s*[:=]\s*['\"]?[^\s'\"]+['\"]?"
)

# A credential in a "<label>=<value>" pair: an ODBC "PWD=", a "password=" in a connection error, a
# provider "secret=". The value class stops at the separators these actually appear inside (";" in an
# ODBC string, "," and "&" in a query), so a redaction cannot swallow the rest of the line.
_CREDENTIAL_KV = re.compile(
    r"(?i)\b(" + _LABEL_PREFIX + r"(?:" + _alternation(_CREDENTIAL_WORDS) + r"))\b"
    r"['\"]?\s*[:=]\s*['\"]?[^\s'\";,&]+"
)

# Key MATERIAL in a "<label>=<value>" pair, where the label ends in a credential word neither pattern
# above can reach. The alternate must END the label -- the trailing ``\b`` cannot fire before "_" -- so
# a PATH or a name keeps its value: ``private_key_file=``, ``encryption_key_ref=`` and
# ``intake_api_key_header=`` all survive this pattern intact.
#
# WHY THE VALUE CLASS ADMITS A COMMA, unlike ``_CREDENTIAL_KV``: ``encryption_keys_retired`` ships as a
# COMMA-JOINED LIST (``store/keyprovider.py::_split_retired``), so a comma terminator would redact the
# first retired key and print the rest. Whitespace, quotes, ";" and "&" still terminate, so a redaction
# cannot swallow the rest of a log line. RESIDUAL, stated because this pattern does not cover it: a
# list written with a SPACE after the comma leaves its later elements unmatched -- and unlike the
# support-bundle surface there is no long-base64 sweep behind this one to catch them.
_KEY_MATERIAL = re.compile(
    r"(?i)\b(" + _LABEL_PREFIX + r"(?:" + _alternation(_KEY_MATERIAL_WORDS) + r"))\b"
    r"['\"]?\s*[:=]\s*['\"]?[^\s'\";&]+"
)

# An inline password in a URL-shaped DSN: "postgres://user:<pw>@host/db". The scheme and the user
# survive so an operator can still tell which connection failed.
_DSN_PASSWORD = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@")


def _keep_label(m: re.Match[str], placeholder: str) -> str:
    """Replace a ``<label>=<value>`` match, keeping the label so a reader sees WHICH credential was
    there, and never the value. Group 1 is the label in every pattern that uses this."""
    return f"{m.group(1)}={placeholder}"


# --- ADMISSION GATING: what makes a per-record credential pass affordable --------------------------
#
# THE INVARIANT, and it is what makes gating safe rather than merely fast: a pattern whose label
# alternates come from tuple W cannot match text containing none of W's members. So skipping that
# pattern when no member is present cannot narrow what the pass sees. That is a property of building
# the gate and the pattern from ONE tuple, not a claim about the regexes, and
# ``test_the_hint_gates_never_change_the_result`` compares the gated and ungated passes over every
# fixture rather than trusting the argument.
#
# A CASEFOLDED SUBSTRING TEST, NOT A COMPILED ALTERNATION, and the difference is the whole cost of
# this module. A ``(?i)`` alternation defeats sre's literal-prefix optimisation, so the engine
# trial-matches every branch at every start position: measured on a plain 67-char line, the union
# alternation cost 5.07 us and was 100 percent of what this module added, while one ``casefold()``
# plus ``in`` tests costs 0.40 us. On a real credential line, folding ONCE and reusing the folded
# string for all six per-pass gates took the pass from 8.21 us to 2.93 us.
#
# ``casefold`` RATHER THAN ``lower``, AND IT IS THE TEXT SIDE THAT CARRIES THAT. The patterns are
# ``(?i)`` and Python's case-insensitive matching folds beyond ASCII -- measured on this interpreter,
# ``(?i)s`` matches U+017F and ``(?i)k`` matches U+212A -- while ``lower()`` leaves both alone. So a
# ``lower()``-folded TEXT does not admit a line the pattern behind it would have matched, which is the
# one direction a gate must never fail in. ``test_the_gate_folds_the_way_the_patterns_match_not_the_way
# _str_lower_does`` pins it with the leaked credential as the control.
#
# FOLDING THE WORDS IS A NO-OP TODAY and is written as ``casefold`` only so the two sides cannot
# diverge: every member of every tuple above is ASCII, so ``lower`` and ``casefold`` agree on all of
# them. Stated because a mutation run scored the word-side fold as unkillable, which is correct and
# would otherwise read as missing coverage.
#
# ``_MEFOR_SECRET`` is the exception in the other direction: it is case-SENSITIVE, so a folded gate
# merely admits lines it will not match, which is free.


def _folded(words: tuple[str, ...]) -> tuple[str, ...]:
    """``words`` casefolded, for substring admission against casefolded text."""
    return tuple(w.casefold() for w in words)


_CREDENTIAL_HINT = _folded(_CREDENTIAL_WORDS)
_TOKEN_HINT = _folded(_TOKEN_WORDS)
_KEY_MATERIAL_HINT = _folded(_KEY_MATERIAL_WORDS)
_SCHEME_HINT = ("bearer",)
_ENV_HINT = (_ENV_PREFIX.casefold(),)
_DSN_HINT = (_DSN_MARKER,)

#: The union of every per-pass gate, reduced by SUBSUMPTION: a word containing another word of the set
#: is dropped, because any text holding it holds the shorter one too. Derived, so it cannot drift from
#: the tuples above -- ``pass`` subsumes ``password``/``passwd``/``passphrase``, ``encryption_key``
#: subsumes ``encryption_keys_retired``, ``api_key`` subsumes ``intake_api_key_next``. One scan of 15
#: members instead of 20, and it rejects the overwhelmingly common record: the one carrying no
#: credential word at all.
_ANY_HINT = tuple(
    sorted(
        {
            word
            for word in {
                *_CREDENTIAL_HINT,
                *_TOKEN_HINT,
                *_KEY_MATERIAL_HINT,
                *_ENV_HINT,
                *_DSN_HINT,
            }
            if not any(
                other != word and other in word
                for other in {
                    *_CREDENTIAL_HINT,
                    *_TOKEN_HINT,
                    *_KEY_MATERIAL_HINT,
                    *_ENV_HINT,
                    *_DSN_HINT,
                }
            )
        }
    )
)


def _admits(folded: str | None, words: tuple[str, ...]) -> bool:
    """Whether the pass over ``words`` may match. ``folded is None`` bypasses gating entirely, which
    is how the suite compares the gated and ungated results."""
    return folded is None or any(word in folded for word in words)


def scrub_credentials(text: str, *, placeholder: str = CREDENTIAL_PLACEHOLDER) -> str:
    """Return ``text`` with credential VALUES replaced by ``placeholder``, keeping every label.

    The label survives on purpose: an operator reading a scrubbed line must still be able to tell WHICH
    credential the failing code was handling. Nothing else about the line is touched -- this is a
    credential pass, not a PHI pass (:mod:`messagefoundry.redaction` owns that) and not a control-char
    pass (:func:`logging_setup.scrub_control_chars` owns that).

    Idempotent, because a record dispatched to stdout *and* the off-box forwarder is filtered once per
    handler: the placeholder carries no credential word, no ``MEFOR_`` prefix and no ``://``, so a
    second pass finds a label whose value is already the placeholder and rewrites it to itself. The
    reject path returns the SAME object, so a caller's ``scrubbed != message`` takes CPython's
    pointer-identity fast path."""
    folded = text.casefold()
    if not _admits(folded, _ANY_HINT):
        return text
    return _run(text, placeholder, folded)


def _run(text: str, placeholder: str, folded: str | None) -> str:
    """The pass itself. Straight-line rather than a table, so a test monkeypatching one pattern on this
    module reaches the object this function reads -- a table would hold the pre-patch pattern by
    value and the mutation fixture would silently mutate nothing."""
    if _admits(folded, _ENV_HINT):
        text = _MEFOR_SECRET.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _TOKEN_HINT):
        text = _BEARER.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _SCHEME_HINT):
        text = _AUTH_SCHEME.sub(lambda m: f"{m.group(1)} {placeholder}", text)
    if _admits(folded, _CREDENTIAL_HINT):
        text = _CREDENTIAL_KV.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _KEY_MATERIAL_HINT):
        text = _KEY_MATERIAL.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _DSN_HINT):
        text = _DSN_PASSWORD.sub(lambda m: f"{m.group(1)}:{placeholder}@", text)
    return text
