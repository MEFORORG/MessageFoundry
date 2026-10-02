# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
THE CEILING IS A ``_LABEL_PREFIX`` NUMBER AND IT IS THE WHOLE CEILING, which is a claim only since
BACKLOG #1547: :data:`_DSN_PASSWORD`'s scheme class was reachable from every word boundary in the same
"." and "-" run, so the same run carrying a ``://`` cost 302 ms at 16 KB rather than 21 ms. That one is
anchored now, and the reasoning and the numbers live on the pattern rather than here. Deliberately no
figure at this site: it was restated as 0.18 ms and went stale against the pattern's own the first time
that pattern was touched. No magnitude claim either -- the ratio differs depending on whether you read
the pattern alone or this module's ceiling, and a summary that picks one silently is how the last
restatement went wrong.
It was NOT bought down further: the obvious lever, a bounded lookahead requiring a separator near the
label, would silently stop scrubbing a credential whose label is longer than the bound. Trading a
silent security narrowing for time on a synthetic input, against a cost this module does not dominate,
is the wrong direction.

WHAT KEEPS THE REAL NUMBERS SMALL is the admission gating described below -- a casefolded substring
test, not a compiled alternation, and one per pass rather than one shared. Between them they took the
plain line from 4.4 us to 0.9 us and the credential line from 7.8 us to 3.7 us; the 6 KB run naming no
credential word went from 0.39 ms to 15 us.

WHAT BACKLOG #1685's QUOTED-VALUE ALTERNATES COST, measured 2026-09-14. **A DIFFERENT INSTRUMENT FROM
THE TABLE ABOVE, and the numbers are not comparable to it:** that table is what the whole MODULE adds
to the four-filter chain per record, while these are one ``_CREDENTIAL_KV.sub`` call against a
reconstruction of the pre-#1685 pattern, minimum over 25 interleaved rounds of 20 passes. Every shape
that occurs in real log text got FASTER or stayed level -- plain line 2.18 against 2.27 us, credential
line 1.35 against 1.39, a quoted value with a space 1.37 against 2.34, a well-formed braced password
4.10 against 4.61, a 400-character braced password 6.77 against 40.00 (the old pattern made many small
matches where this makes one), and the 6 KB adversarial run naming every family level within noise at
359 against 357 us.

ONE SHAPE GOT SLOWER AND IT IS STATED RATHER THAN HIDDEN: a 6 KB line whose credential value opens "{"
and never closes costs **83 us against 25 us**. The walk is linear and runs twice -- once for
:data:`_ODBC_BRACED`, which fails at end of line, then once for :data:`_ODBC_BRACED_OVERRUN`, which
succeeds. It is 3x a number that was already 250x below this module's own adversarial ceiling, and the
sibling shape with many such labels went the other way, 64 us against 141. Not bought down further: a
``{0,N}`` bound measured 32 us on that line and costs correctness elsewhere, for the reason
:data:`_ODBC_BRACED` records.
"""

from __future__ import annotations

import re

__all__ = [
    "CREDENTIAL_PLACEHOLDER",
    "credential_query_params",
    "credential_value_spans",
    "mask_credential_query",
    "scrub_credentials",
]

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

# A QUOTED value span, for the two quoting forms a credential value actually arrives in (BACKLOG
# #1685). Both exist for one reason: a value is quoted PRECISELY so it may carry the characters that
# would otherwise end it -- ";", "=" and spaces -- and those are exactly what the plain value class
# below stops at. So the shipped pattern replaced the HEAD of a quoted password and printed the tail.
#
# Measured at 1aa2d6a1b, both shapes, on both credential surfaces:
#
#   PWD={wt-A;B}                     ->  PWD=<redacted>;B}
#   ad_bind_password='wt-A wt-B'     ->  ad_bind_password=<redacted> wt-B'
#
# THE SECOND IS THE MORE REACHABLE ONE. Brace-quoting is a connection-string form, so it rides in on
# the SQL Server store; a password with a SPACE in it reaches every backend, and ``ad_bind_password``
# and ``tls_key_password`` are real settings here.
#
# THE DOUBLED BRACE IS THE PART A NAIVE FIX GETS WRONG. ODBC ends a braced value at the first "}" that
# is NOT doubled; an interior literal "}" is written "}}". So ``\{[^}]*\}`` -- the obvious pattern --
# stops at the first "}" and leaks the tail of any password containing one. The repetition walks
# non-"}" characters and doubled "}}" pairs, and the trailing ``(?!\})`` refuses a closer that is
# really the first half of an escape.
#
# POSSESSIVE, AND NOT BOUNDED, WHICH IS THE OPPOSITE OF WHAT :data:`_LABEL_PREFIX` NEEDED. That bound
# exists because "." and "-" leave ``\b`` firing, so an N-segment run offers N start positions and the
# group re-walks from each -- genuinely quadratic. None of that applies here. The two brace branches
# cannot both match at one position (``[^}]`` excludes the one character ``\}\}`` needs), and the
# quoted classes exclude their own closer, so every repetition below is DETERMINISTIC: there is one
# parse of any prefix and nothing to re-walk. ``*+`` then says so to the engine, which also costs
# nothing in reach -- a shorter brace parse could only end at a "}" that is followed by another "}",
# and ``(?!\})`` rejects exactly that. A ``{0,N}`` bound would buy no safety and would silently stop
# matching a password longer than N, which is the one direction this module must not fail in.
_ODBC_BRACED = r"\{(?:[^}]|\}\})*+\}(?!\})"
_QUOTED_VALUE = "'[^'\r\n]*+'|\"[^\"\r\n]*+\""

# The fallback for a "{" this module cannot close: take the rest of the physical line and nothing more.
#
# IT IS REQUIRED INDEPENDENTLY OF ANY BOUND, which is why it is not merely a safety net for one. A
# driver error string is cut off wherever the driver cut it, so a truncated connection string reaches
# this pass with an opening "{" and no closer anywhere. Dropping back to the plain value class there
# would print the password; running to end of line over-redacts, and over-redaction is the direction
# this module is allowed to fail in.
#
# STOPPING AT THE LINE IS THE LOAD-BEARING HALF, and a record CAN be multi-line here: ``exc_text``
# carries a whole rendered traceback, so a run that crossed "\n" would redact every later frame of it
# and hand the operator a traceback with no stack. ``[^\r\n]`` rather than "." adds only the CR --
# "." stops at "\n" on its own, but still matches "\r", so on CRLF text a bare ".*" would pull the
# carriage return into the redacted span and leave the line ending broken.
_ODBC_BRACED_OVERRUN = r"\{[^\r\n]*"

# A credential in a "<label>=<value>" pair: an ODBC "PWD=", a "password=" in a connection error, a
# provider "secret=". The value class stops at the separators these actually appear inside (";" in an
# ODBC string, "," and "&" in a query), so a redaction cannot swallow the rest of the line.
#
# THE QUOTED ALTERNATES COME FIRST because they and the plain class overlap and the first alternate
# wins; the plain class keeps its own leading ``['\"]?`` so a value whose quote does not CLOSE on this
# line still loses its head exactly as it did before.
#
# TWO RESIDUALS, WRITTEN DOWN RATHER THAN IMPLIED.
#
# * An UNCLOSED quote falls back to the plain class, so ``password='wt-A wt-B`` (no closing quote)
#   still prints " wt-B". The brace form gets an overrun and this does not, deliberately: a "{" after
#   a credential label is unambiguous, while an apostrophe is ordinary prose, and a quote overrun
#   would eat the rest of any line whose value merely CONTAINS one.
# * The other three label=value patterns keep their own plain classes, so a quoted or braced value
#   under THEIR labels leaks the same way. ``_MEFOR_SECRET`` is the most exposed of the three -- it
#   runs first and its class stops at whitespace, and a ``MEFOR_*`` variable holding a connection
#   string is exactly the echo shape its own comment cites. ``_BEARER`` is the one with a REASON to
#   stay narrow rather than merely a lack of evidence: ``session=`` and ``token=`` legitimately carry
#   a "{"-opening dict or JSON repr in this engine's log text, and the overrun would eat those lines.
_CREDENTIAL_KV = re.compile(
    r"(?i)\b(" + _LABEL_PREFIX + r"(?:" + _alternation(_CREDENTIAL_WORDS) + r"))\b"
    r"['\"]?\s*[:=]\s*"
    r"(?:"
    + _ODBC_BRACED
    + r"|"
    + _QUOTED_VALUE
    + r"|"
    + _ODBC_BRACED_OVERRUN
    + r"|['\"]?[^\s'\";,&]+)"
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
#
# THE HEAD ANCHOR IS WHAT KEEPS THIS SCAN LINEAR, AND A REPETITION BOUND IS NOT. Both halves are
# measured, and the second one shipped briefly as a defect, so the whole reasoning is kept here rather
# than reduced to its conclusion (BACKLOG #1547).
#
# THE QUADRATIC IS A START-POSITION PROBLEM. "." and "-" are both in the scheme class and neither
# suppresses ``\b``, so under a ``\b`` head an N-segment dotted or hyphenated run offers O(N) start
# positions and each one re-walks O(N) characters looking for a "://" it never reaches. Log text is
# attacker-influenceable and this pass runs on EVERY record, so one long delimiter-free run would hang
# a worker on first deployment. Measured on this interpreter, min of 5 passes over one hyphen-and-dot
# run: ``\b([a-z][a-z0-9+.\-]*`` cost 4.8 ms at 2 KB and 302 ms at 16 KB -- 63x the time for 8x the
# length, which is the quadratic.
#
# BOUNDING THE WALK FIXED THE CLOCK AND BROKE THE SCRUB. A ``{0,63}`` on the repetition caps what each
# start position re-walks and is genuinely linear (0.34 ms and 2.7 ms, 7.8x for 8x) -- but ``\b``
# anchors at the head of the whole unbroken run the scheme sits in, NOT at the scheme, so a DSN glued
# to any 64-character run of ``[A-Za-z0-9+.\-]`` stopped matching at all and the password was published
# in full. That is a credential surviving redaction, not a narrowed label: measured at the 65th
# character, and reached by a base64url token, a long dotted name or a hyphenated id sitting in front
# of the DSN. ``tests/test_log_write_guard.py``'s straddling-diagnostic fixture is exactly that shape
# and leaked its password on both copies of this pattern while the bound stood.
#
# SO THE ANCHOR CARRIES IT INSTEAD, AND NOTHING IS CAPPED. ``(?<![a-z0-9+.\-])`` forbids a match from
# STARTING inside such a run, which leaves the run one start position rather than O(N); walks from
# distinct start positions then cannot overlap, because every character the repetition consumes is one
# the lookbehind excludes. Linear with no ceiling on the scheme -- 0.022 ms at 2 KB and 0.17 ms at
# 16 KB, 7.8x for 8x the length, and 15x FASTER at 16 KB than the bound it replaces.
#
# THE FIRST SPELLING OF THAT ANCHOR KEPT A ``[a-z]`` HEAD ON THE SCHEME, AND IT LOST MATCHES. The
# sentence that stood here -- that it "matches strictly MORE than the pre-#1547 pattern" -- was FALSE,
# and it was the load-bearing reason a reader would not look again. In
# ``(?<![a-z0-9+.\-])([a-z]...`` a start needs the preceding character OUTSIDE the class and the first
# character INSIDE it and a letter. Both hold only at the head of the run, so a run whose head is a
# digit, "+", "." or "-" had EVERY start position refused and the password went through untouched.
# Measured on both surfaces, before this correction: ``9-postgres://``, ``2024-01-01-postgres://``,
# ``8f3a-postgres://``, ``.postgres://``, ``-postgres://`` and ``+postgres://`` each published a
# synthetic password in full, and the pre-#1547 ``\b`` head matched all six -- "-" and "." are NON-word
# characters, so ``\b`` placed a start exactly where the letter head refused one. A redaction narrowing
# shipped in the name of a faster scan, which is the same trade the ``{0,63}`` bound made one paragraph
# up. That is twice on one pattern, by two different mechanisms.
#
# THE HEAD CLASS IS THE LOOKBEHIND'S OWN CLASS NOW, which is what makes the containment argument above
# read off the pattern instead of having to be derived: the two classes are the same set, so a match
# starts at the first character of a maximal run of it and nowhere else, and the walks TILE the line.
# Dropping the ``[a-z]`` changes no redacted OUTPUT at a match site the ``\b`` head reached -- the
# leading run sat before the old match and sits inside group 1 now, and group 1 is kept verbatim, so
# both spellings emit the same characters. The differential arm named below rewrites every line of its
# corpus under each earlier head and under this one and requires the results to be equal: no narrowing,
# and no output difference. The counts live there rather than here, so they cannot go stale in a file
# that does not run them. The "strictly more" claim is finally true, of BOTH earlier spellings --
# AT LEAST every match the ``\b`` head made, plus ``_postgres://user:pw@host``, which ``\b`` could not
# reach because an underscore is a word character and offers no boundary to anchor on. "At least"
# rather than an enumeration: the head now admits ANY run head, so ``9postgres://``, ``123://`` and
# ``...://`` match here and matched under neither earlier spelling. Over-redaction is the safe
# direction for a credential pass and group 1 is kept, so a reader loses nothing to it.
#
# Pinned five ways in ``tests/test_log_redaction_secret_domain.py``, which guards BOTH copies of this
# vocabulary: the anchor structurally, the growth with a stopwatch against the pre-#1547 pattern as its
# control, a COUNT of which patterns one ``scrub_credentials`` call actually applies -- which was a
# share of wall-clock cost until that share went red on a hosted runner for a reason that was not a
# regression here, recorded in full beside the test's ``_PATTERN_APPLICATIONS`` -- the shapes that must
# still redact BY VALUE --
# including the glued run above and the non-letter leading runs, so neither narrowing can come back
# without a red -- and a differential arm that fails if either earlier head ever redacts something this
# one does not.
_DSN_PASSWORD = re.compile(r"(?i)(?<![a-z0-9+.\-])([a-z0-9+.\-]+://[^\s:/@]+):[^\s/@]+@")


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
    pass (:func:`messagefoundry.controlchars.scrub_control_chars` owns that).

    Idempotent, because a record dispatched to stdout *and* the off-box forwarder is filtered once per
    handler: the placeholder carries no credential word, no ``MEFOR_`` prefix and no ``://``, so a
    second pass finds a label whose value is already the placeholder and rewrites it to itself. The
    reject path returns the SAME object, so a caller's ``scrubbed != message`` takes CPython's
    pointer-identity fast path."""
    folded = text.casefold()
    if not _admits(folded, _ANY_HINT):
        return text
    return _run(text, placeholder, folded)


#: Query-parameter NAMES that carry a credential in a URL and in nothing else here. Each is too
#: ordinary for :data:`_CREDENTIAL_WORDS` -- ``key=`` is a cache key in log text, which is why that
#: list leaves it out -- but a query parameter is a narrower place, and these are how common partner
#: APIs spell a credential there: an API ``key=`` or ``subscription-key=``, a shared access ``sig=``,
#: a signed URL's ``X-Amz-Signature=``, and a bare ``auth=`` or ``jwt=``.
_QUERY_CREDENTIAL_WORDS = ("key", "sig", "signature", "auth", "jwt")

#: Words matched only as a whole name or after a separator, never as a camelCase tail: as a tail they
#: name ordinary flags (``requireAuth``, ``useOAuth``, ``useJwt``).
_QUERY_NO_CAMEL_WORDS = frozenset({"auth", "jwt"})

#: Credential names written as ONE word with no separator, such as ``accesstoken`` or
#: ``sessionid``. Matched at the end of the name with every separator removed, so ``x_accesstoken``
#: matches too. Kept to compounds, because a bare tail such as ``token`` with no separator would
#: also match ``pagetoken``-style words.
_QUERY_CREDENTIAL_COMPOUNDS = (
    "accesstoken",
    "authtoken",
    "apitoken",
    "idtoken",
    "refreshtoken",
    "sessiontoken",
    "sessionid",
    "authkey",
    "accesskey",
    "secretkey",
    "clientsecret",
)

#: The words a credential parameter NAME may end in, casefolded. Plain string tests rather than a
#: regex composed from these tuples: a composed pattern is one more blind spot for the ReDoS scanner
#: in ``tests/test_security_static.py``, and this needs none of what a regex buys.
_QUERY_CREDENTIAL_TAILS = tuple(
    word.casefold() for word in _CREDENTIAL_WORDS + _TOKEN_WORDS + _QUERY_CREDENTIAL_WORDS
)

#: The separators a parameter name is split on. A space is one because ``parse_qsl`` decodes ``+``
#: to a space, so ``api+key`` reaches the test as ``api key``.
_QUERY_NAME_SEPARATORS = ("_", "-", ".", " ")

#: Every ``<separator><word>`` a name may end in, built once rather than per call.
_QUERY_CREDENTIAL_SUFFIXES = tuple(
    f"{sep}{word}" for word in _QUERY_CREDENTIAL_TAILS for sep in _QUERY_NAME_SEPARATORS
)

#: Key-material names, matched as the whole name. Most of them already end in ``_key``, which the
#: ``key`` tail reaches; ``encryption_keys_retired`` and ``intake_api_key_next`` do not, and this set
#: is what names those two.
_QUERY_KEY_MATERIAL = frozenset(word.casefold() for word in _KEY_MATERIAL_WORDS)

#: Names that END in a credential word and are not credentials: pagination cursors, sort,
#: partition, row and routing keys, idempotency keys and public keys. Compared with every separator
#: removed, so ``pageToken``, ``page_token`` and ``next-page-token`` all match. A short list on
#: purpose: each entry is a name a partner API is known to use for something that is not a secret,
#: and widening it narrows the detector. ``primaryKey`` is NOT here: Azure names a storage account
#: secret that way, beside ``secondaryKey``.
_QUERY_NOT_CREDENTIAL_TAILS = (
    "pagetoken",
    "nexttoken",
    "continuationtoken",
    "publickey",
    "sortkey",
    "partitionkey",
    "rowkey",
    "routingkey",
    "idempotencykey",
)


def _camel_tail(name: str, word: str) -> bool:
    """Whether ``name`` ends in ``word`` as a camelCase segment, as ``accessToken`` ends in token.

    The segment must open with a capital, after a lower-case letter or a digit (``accessToken``), or
    after a capital when the segment itself is Title-case (``SASToken``, ``HMACSignature``). So
    ``monkey`` is not ``key`` and an all-capitals ``MONKEY`` is not split at all."""
    n = len(word)
    if len(name) <= n or name[-n:].casefold() != word:
        return False
    head, before, rest = name[-n], name[-n - 1], name[-n + 1 :]
    if not head.isupper():
        return False
    return before.islower() or before.isdigit() or (before.isupper() and rest.islower())


def _base_name(name: str) -> str:
    """``name`` without tab, CR or LF (which ``urlsplit`` drops, so the detector never sees them),
    without a trailing index such as ``[]`` or ``[0]``, and without trailing digits. So
    ``token[]``, ``token[0]``, ``key1`` and ``apiKey2`` are judged as ``token``, ``token``, ``key``
    and ``apiKey``."""
    base = name.replace("\t", "").replace("\r", "").replace("\n", "").strip()
    if base.endswith("]") and "[" in base:
        base = base[: base.rfind("[")]
    return base.rstrip("0123456789") or base


def _is_credential_param(name: str) -> bool:
    base = _base_name(name)
    folded = base.casefold()
    if folded in _QUERY_KEY_MATERIAL or folded in _QUERY_CREDENTIAL_TAILS:
        return True
    joined = folded
    for sep in _QUERY_NAME_SEPARATORS:
        joined = joined.replace(sep, "")
    if joined.endswith(_QUERY_NOT_CREDENTIAL_TAILS):
        return False
    if joined.endswith(_QUERY_CREDENTIAL_COMPOUNDS) or folded.endswith(_QUERY_CREDENTIAL_SUFFIXES):
        return True
    return any(
        _camel_tail(base, word)
        for word in _QUERY_CREDENTIAL_TAILS
        if word not in _QUERY_NO_CAMEL_WORDS
    )


#: A parameter name shown as written. Anything else is shown by ``repr``.
_PLAIN_NAME = re.compile(r"[A-Za-z0-9._~-]+")


def _display_name(name: str) -> str:
    """A parameter name safe to put in a log line or a ``check`` list. ``parse_qsl`` percent-decodes
    names, so a URL can carry a newline, or a ``); `` that reads as the end of one entry and the
    start of another. A name outside the plain URL-token characters is quoted by ``repr``."""
    return name if _PLAIN_NAME.fullmatch(name) else repr(name)


def credential_query_params(url: str) -> list[str]:
    """The query-parameter NAMES in ``url`` that look like a credential, sorted and unique.

    For the ASVS 14.2.1 check on an endpoint URL: a credential in a query string rides the request
    line, so it lands in the server's and every proxy's access log. Returns names only, never a
    value, so a caller can log what it returns. Total: an unparseable URL returns ``[]`` rather than
    raising, because a parser error would quote the URL.

    A heuristic over names, from this module's own vocabulary plus :data:`_QUERY_CREDENTIAL_WORDS`.
    A name is judged after dropping a trailing index (``[0]``) and trailing digits. It matches as a
    whole word, as its last segment after ``.``, ``_``, ``-`` or a space (a decoded ``+``), as a
    one-word compound (:data:`_QUERY_CREDENTIAL_COMPOUNDS`), or as a camelCase tail
    (``accessToken``), unless it is a known non-secret (:data:`_QUERY_NOT_CREDENTIAL_TAILS`). It
    misses a credential under a name it does not know, and it can name a parameter that only looks
    like one. Its callers WARN rather than refuse for that reason.

    Not :class:`logging_setup.CredentialQueryScrubFilter`'s list. That one scrubs VALUES out of log
    text and carries ``code`` and ``state`` for the OIDC callback; neither is a credential name on a
    partner endpoint, and naming them here would flag ordinary query strings."""
    # Imported here, not at module scope: this leaf is imported by every log handler at startup on
    # ``re`` alone, and only configuration checks call this.
    import urllib.parse  # noqa: PLC0415

    try:
        query = urllib.parse.urlsplit(url).query
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return []
    return sorted({_display_name(name) for name, _ in pairs if _is_credential_param(name)})


def credential_value_spans(text: str) -> list[tuple[int, int]]:
    """The ``[start, end)`` span of the VALUE of every credential-like ``name=value`` segment in
    ``text``, wherever it sits.

    A segment starts after any ``?``, ``&``, ``#`` or ``;`` (a path parameter such as
    ``;jsessionid=``, or a server that splits its query on ``;``) and ends at the next ``&`` or
    ``#``. It does not care where a URL parser would put the query, which is the point:
    ``config.wiring._mask_url`` unions these with password spans so that at least the misreadings
    tested there cannot hide a credential. A segment in a fragment or a path that looks like a
    credential is masked too; that is the safe direction. A name is judged after dropping tab, CR
    and LF, which ``urlsplit`` drops before ``parse_qsl`` decodes it, then by the same test as
    :func:`credential_query_params`. An empty value has no span. One pass, linear in ``text``."""
    import urllib.parse  # noqa: PLC0415 -- see credential_query_params

    n = len(text)
    # next_end[i]: the first "&" or "#" at or after i, else n. Built right to left, once.
    next_end = [n] * (n + 1)
    for i in range(n - 1, -1, -1):
        next_end[i] = i if text[i] in "&#" else next_end[i + 1]
    spans: list[tuple[int, int]] = []
    for i, ch in enumerate(text):
        if ch not in "?&#;":
            continue
        seg_start = i + 1
        seg_end = next_end[seg_start]
        equals = text.find("=", seg_start, seg_end)
        if equals < 0 or equals + 1 >= seg_end:
            continue
        name = text[seg_start:equals].replace("\t", "").replace("\r", "").replace("\n", "")
        if _is_credential_param(urllib.parse.unquote_plus(name)):
            spans.append((equals + 1, seg_end))
    return spans


def mask_credential_query(url: str, *, placeholder: str = "***") -> str:
    """``url`` with every span :func:`credential_value_spans` finds replaced by ``placeholder``.

    The query-credential half of the settings-view mask. ``config.wiring._mask_url`` does NOT call
    this: it unions these spans with userinfo password spans and replaces them together, so that one
    mask cannot cut the string the other reads. Use this alone only for a URL known to carry no
    userinfo. Everything that is not a span is kept as written."""
    out: list[str] = []
    cursor = 0
    for start, end in credential_value_spans(url):
        if start < cursor:
            continue
        out.append(url[cursor:start])
        out.append(placeholder)
        cursor = end
    out.append(url[cursor:])
    return "".join(out)


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
