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

WHAT KEEPS THE REAL NUMBERS SMALL is the admission gating described below -- a folded substring
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

WHAT THE STOP BEFORE A QUOTED LABEL COSTS, measured 2026-10-04. A THIRD INSTRUMENT, comparable to
neither paragraph above: one whole ``scrub_credentials`` call against the module as it stood at
``50a4a3dccb``, minimum over interleaved rounds. The table above still holds, because every shape it
names is level: the plain line 0.58 against 0.57 us, the credential line 3.37 against 3.44, a quoted
credential line 3.21 against 3.21, and each 6 KB run ending at the end of the line within 3 percent.
That is :data:`_NO_QUOTED_LABEL_AFTER`'s fast path; without it the credential line cost 41 percent
more. A line where the stop actually runs pays for it: a two-label line 5.70 against 7.12 us, and it
now redacts the second password. The costliest shape measured that day was a 6 KB value whose run
ends on a quote, which forces the token walk: 24 against 764 us, linear at 7.6x to 8.0x for 8x the
length over four adversarial shapes, a quoted run of spaces among them. IT IS NOT THE CEILING. A
review on 2026-10-05 measured costlier ones, because the underscored-prefix check walks at every run
start: ``token=x`` then ``;a_a_a_a_a_a_a`` repeated, ending on a quote, cost 0.41 ms at 2 KB,
1.2 ms at 6 KB and 3.3 ms at 16 KB, about 8x for the 8x from 2 KB to 16 KB. That is linear and
under this module's 21 ms ceiling above, and under the 33 ms the PHI pass spends on such a line.

WHAT :data:`_KV_QUOTED_VALUE` COSTS, measured 2026-10-05 the same way, against the plain quoted form in
the same pattern. The paragraph above predates it. An ordinary quoted credential line is level, 4.05
against 4.04 us, because its fast path is the plain form. A quoted value whose last character is ":",
"=" or a space takes the walk. Measured on "=" and a space: 3.95 against 4.54 us, and 44 against
572 us for a 6 KB one. Linear, and under the ceiling above.

WHAT :data:`_BRACED_RUN_ON` COSTS (BACKLOG #2966), measured 2026-11-06 the third paragraph's way,
one whole ``scrub_credentials`` call against the module before it. The plain line and the credential
line are level, 1.29 against 1.26 us and 5.08 against 4.97, inside this box's noise. A value whose run
holds a "{" now walks rather than taking the fast path: a token value then a braced ``PWD=``, the line
the change is for, costs 7.5 against 6.1 us, and a ``MEFOR_STORE_DSN`` holding one 7.8 against 5.0.
Three 6 KB runs built to make every check walk are level within 6 percent: braced runs, unclosed
``PWD={`` labels, and closed spaced ones, the last 1.21 against 1.15 ms. Those figures were measured
before the braced tail began checking for a label and the fold characters became tokens of their own
(BACKLOG #3114); the growth tests in ``tests/test_log_redaction_secret_domain.py`` still bound both.
"""

from __future__ import annotations

import re

__all__ = [
    "CREDENTIAL_PLACEHOLDER",
    "credential_query_params",
    "has_credential_like_segment",
    "scrub_credentials",
]

#: What a scrubbed credential VALUE is replaced with. Matches
#: :class:`logging_setup.CredentialQueryScrubFilter`, so one log line cannot carry two spellings of
#: "a credential was here". A caller wanting a different marker passes ``placeholder=`` --
#: ``support/redact.py`` passes its ``[REDACTED]``, since it calls this pass (BACKLOG #2694).
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

# Where a label may start: at a word boundary, or right after a percent-encoded character (BACKLOG
# #2999). A ``%XX`` escape ends in a hex digit, and a hex digit is a word character, so ``\b`` does
# not fire between it and a label. A label glued to an encoded separator, as in ``a=1%2Cpassword=x``
# or ``x%3Bbearer <tok>``, was therefore never read, and its value printed. The lookbehind is fixed
# width, so it adds a start position only right after a ``%XX`` triplet and keeps the scan linear.
# The cost is over-redaction where the escape decodes to a letter or digit, as in ``%41token=x``,
# which is the direction this module may fail in. ``_LABEL_PREFIX`` is not changed: a prefixed label
# such as ``%2Cclient_secret`` was already read, because "2Cclient_" is one prefix segment.
# ``messagefoundry.redaction._CREDENTIAL_AHEAD`` deliberately does NOT take this start, because
# taking it printed PHI; its comment gives the measurement and the credential shape that costs.
#
# FOUR PATTERNS TAKE IT, AND ``_MEFOR_SECRET`` DOES NOT. That pattern runs first and its value takes a
# trailing quote, so with this start it read a ``MEFOR_`` label glued by an escape INSIDE another
# label's quoted value and ate that value's closer: ``password='pq1 pq2%20MEFOR_X=v' rest`` printed
# "pq2", which the patterns before hid (found by code review, 17,989 of 200,000 nested shapes).
# An engine secret echoes as ``(env 'MEFOR_X'='<value>')``, never glued by an escape, so it keeps
# ``\b``. A ``MEFOR_`` label right after an escape is therefore still not read; that is a residual.
#
# THE START IS A TRADE, NOT ONLY A WIDENING, because the passes run one after another and each reads
# what the last one wrote (the OPEN DEFECTS list below). A label read now that was not read before
# can end an earlier value where it used to run on. Measured over 40,000 seeded label-dense lines
# with escape glue, against the patterns before #2999: 577 lines print a value they hid, and 9,012
# hide one they printed. The structured differential in
# ``tests/test_log_redaction_secret_domain.py`` reads 0 printed.
_LABEL_START = r"(?:\b|(?<=%[0-9A-Fa-f]{2}))"

# A QUOTED value span, for the two quoting forms a credential value actually arrives in (BACKLOG
# #1685). Both exist for one reason: a value is quoted PRECISELY so it may carry the characters that
# would otherwise end it -- ";", "=" and spaces -- and those are exactly what a plain value class
# stops at. So the shipped pattern replaced the HEAD of a quoted password and printed the tail.
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
#
# ``_CREDENTIAL_KV`` ALONE TAKES THIS BRACED FORM. Its quoted value is :data:`_KV_QUOTED_VALUE`,
# which runs on past a later label's opening quote. The plain quoted form, ``'[^'\r\n]*+'`` and its
# double-quoted twin, is no longer a constant here: no pattern uses it, and it lives on only as the
# fast path at the head of :data:`_KV_QUOTED_VALUE`. The other label patterns take a quoted or braced
# value too since BACKLOG #1685's remainder, but through the GUARDED forms below,
# :data:`_GUARDED_QUOTED_VALUE` and :data:`_GUARDED_BRACED_VALUE`, which say why the plain forms were
# not safe to reuse.
_ODBC_BRACED = r"\{(?:[^}]|\}\})*+\}(?!\})"

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

# Where an UNQUOTED value must stop early: just before a credential label whose value opens with a
# quote. Every plain value class below checks for one, in the way described under "CHECKED ONCE PER
# RUN" further down.
#
# THE DEFECT IT CLOSES. A plain value ran on across a separator into a LATER label and ended at that
# label's opening quote. So the later pattern never saw its label, and the quoted value printed.
# Measured on both copies at 50a4a3dccb, plain ASCII:
#
#   api_token=x;password="v w"    ->  api_token=<redacted>"v w"
#   session=1;private_key="pk"    ->  session=<redacted>"pk"
#   pwd=a:password="v w"          ->  pwd=<redacted>"v w"
#
# WHY IT STOPS ONLY BEFORE A CLOSED, GUARDED QUOTE. That is what keeps the stop from printing anything
# a value class used to hide. Every plain class here excludes both quote characters, so a value
# already ended at or just past that quote. The text between the stop and the quote is a separator,
# the label and its ":" or "=". The stop also requires :data:`_GUARDED_QUOTED_VALUE` to match the
# whole quoted value, so the label's own pattern is sure to take it, and to take it past where the old
# value ended. So, WITHIN ONE PASS, a stop newly prints label text, and a value only in the one trade
# written down further down this comment. The braced stop of BACKLOG #2966 is different: its run-on
# takes text out of what its own pass still scans, so it CAN newly print a value within one pass, and
# the conditions on :data:`_BRACED_RUN_ON` are what refuse each shape measured doing so. ACROSS PASSES
# IT CAN, and the differential test measures how often: the text a stop leaves behind is not the text
# the old class left, so a later pass over it can end somewhere else. A stray quote or a later label
# used to cut a later pass short, and now does not. It is rare. Four of the eight shapes on the OPEN
# DEFECTS list below also hide a value the old patterns printed, and four do not. The differential
# measures the count on its corpus, in
# ``test_the_change_prints_no_value_the_pre_change_patterns_hid``, and the known shapes are pinned in
# ``test_the_open_cascade_defects_still_print``. With only an OPENING quote
# required, ``token=x;password="private_key: pk`` printed "pk": the exposed label's plain class then
# swallowed the next label instead. A label followed by a plain value gets no stop, and neither does
# one followed by a BRACE, because the class used to run on past those, and stopping there would print
# what it used to hide. The one exception is a braced value holding white space, under a
# ``_CREDENTIAL_KV`` label, inside which the old class stopped; :data:`_BRACED_RUN_ON` takes it.
#
# NOT BEFORE A LABEL WHOSE VALUE IS UNQUOTED, EVEN WHERE THE OLD CLASS ENDED INSIDE THAT LABEL'S HEAD,
# though that looks safe and was tried. A label head may hold whitespace and still get a stop, as in
# ``token=x;password= 'v w'``; what decides it is the quote. In
# ``token=x;password= hunter2`` the old class ends at the space, so a stop there would print only
# label text, and "hunter2" would be hidden. Within one pass that holds. Across passes it does not:
# the later label's own plain class then runs on over a label after it, which the old text had cut
# short. Measured 2026-10-05 over 68,000 structured lines: 502 value atoms newly printed, against 4
# without it. So ``token=x;password= hunter2`` still prints "hunter2", as it did before this change.
#
# WHERE IN THE LABEL IT STOPS, which decides whose text a stop can print. A label may carry a prefix
# (``_LABEL_PREFIX``), and a prefix joined by "." or "-" is just as much the tail of the value in front
# of it -- ``fv-A_1.password`` could be either. So the stop lands at one of two places:
#
# * At the start of an UNDERSCORED prefix, such as ``client_secret``, but only right after a hard
#   separator: a character that cannot belong to a label, so not a letter, a digit, ".", "-" or "_".
#   Stopping at the keyword there would leave the pass unable to resume: it restarts at the keyword,
#   and its own ``\b`` cannot fire after "_". Measured, that left 956 of 20,412 two-label lines
#   printing, ``client_secret`` and ``ad_bind_password`` among them. After a hard separator the whole
#   underscored run is the label, by the same grammar every label pattern here uses.
# * At the KEYWORD in every other case: right after a separator, or after a dotted, hyphenated or
#   underscored run that follows "." or "-". Such a run then stays inside the redacted span, and the
#   keyword sits right after the placeholder, where a later pattern finds it. The prefix branch once
#   fired after "." and "-" too, and that printed value text: a JWT signature glued by "_" onto a
#   ``password=`` label came out as label.
#
# CHECKED ONCE PER RUN OF LETTERS AND DIGITS, NOT PER CHARACTER. Each plain class below walks its value
# as tokens -- a whole run of letters and digits, or one other character -- and checks the stop only in
# front of a run. Every branch of the stop starts on a letter or digit that follows some other
# character, which is exactly the start of a run, so the two agree; and for the same reason no
# lookbehind is needed in front of the keyword. Per run is cheaper than per character, but not by
# much on a hyphen-and-dot run, where every run is one character long. What keeps ordinary lines
# level is the fast path at ``_NO_QUOTED_LABEL_AFTER``, which skips the walk entirely.
#
# THE MEFOR_ BRANCH KEEPS THE ``\b`` ITS OWN PATTERN HAS, and so does the prefix branch. That is a cost
# decision. ``\b`` cannot fire inside a word, so a long MEFOR_MEFOR_... or a_a_a_... run offers one
# walk rather than one per "_", which would be quadratic.
#
# LINEAR, for three reasons that together bound how often any character is read.
#
# * A value walk checks the stop only at the start of a run, and one pattern's matches never overlap,
#   so each run start is checked a fixed number of times per pattern: once on the walk, and once more
#   where the fast path read the run first and failed.
# * One check is a fixed-length keyword test plus walks that each start at only one place in a run.
#   The underscored-prefix walk needs a hard separator behind it, so it starts only at the head of a
#   run of label characters, and its segments are possessive and at most six. The MEFOR_ walk needs a
#   ``\b``, which inside a run of word characters fires only at its head. A check that starts anywhere
#   else fails on its first character or on its keyword.
# * A guarded quote walk starts after one label's opening quote and stops at the next quote or "{".
#   A later label's quote therefore ends any earlier walk, so walks from two labels do not overlap, and
#   one label's walk is started by at most two checks: one at its keyword and one at its prefix head.
#
# The whitespace walks are possessive, so nothing re-walks a run. The growth tests time the result
# against a quadratic control.
#
# RESIDUALS. A value glued by "_" onto a label of the SAME family, with no hard separator before the
# run or at the very start of the value, still prints the quoted value: ``pwd=a_password="v w"``,
# ``password=x.client_secret="v w"`` and ``token=bearer_token="v w"``. The stop lands on the keyword
# and the pass cannot resume there. A label of a later family is caught, because it sees the keyword
# right after the placeholder.
#
# A KEYWORD SPELLED WITH A FOLD CHARACTER AS ITS FIRST LETTER IS CHECKED TOO (BACKLOG #3114), such
# as U+017F in ``secret`` or U+0130 and U+0131 in ``intake_api_key_next``. Where a pattern does not
# fold globally, ``_MEFOR_SECRET`` here and in ``support/redact.py`` every stopped pattern but
# ``_AUTH_SCHEME``, the walk read that character as a separator and checked the stop only from the
# next run, so ``MEFOR_X=a;<U+017F>ecret='v w'`` printed "v w'" on both copies. The walk now takes
# each of the four characters in :data:`_WALK_FOLD_CHARS` that STARTS A WORD, with no letter, digit
# or fold character before it, as a token of its own, and checks the stop in front of it as it does
# in front of a run. One INSIDE a word it takes unchecked, as part of that word: a first form
# checked it there too, so ``b2<U+017F>ecret=`` stopped a value where ``b2secret=`` does not. Either
# way the run after it is still checked, as it was while the character read as a separator, so
# ``MEFOR_X=b2<U+017F>token=`` stops in front of ``token``, and ``MEFOR_X=b2stoken=`` does not stop
# at all. FOLDING THE RUN CLASS INSTEAD WAS BUILT FIRST AND PRINTED VALUES the old walk hid: it
# joined a fold character onto the run before it, so the run after it was no longer checked, and
# ``MEFOR_X=b2<U+017F>token='c3 d4'`` printed "c3 d4'", U+212A included. Folding the stop as well
# let its underscored-prefix branch read a run holding a fold character as a later label's prefix:
# in ``MEFOR_B_PW=a:b_<U+0130>_passwd: "c d"`` the "b" printed. The stop keeps its own pattern's
# fold.
#
# SO A LINE HOLDING A FOLD CHARACTER DOES NOT IN GENERAL READ AS ITS ASCII SPELLING: the keyword
# glued on behind one, above, is checked where the ASCII run is not. What was measured is narrower.
# A label whose FIRST letter is a fold character takes part in the cascade shapes under OPEN DEFECTS
# as the ASCII label does, and prints there what the ASCII spelling prints; a fold-headed spelling
# of each shape is pinned beside the ASCII one. A shape grid and seeded random lines found no other
# line where such a label printed a value its ASCII spelling hid. That is a sample, not a proof.
#
# AND ONE DELIBERATE TRADE, which is the one place a single pass prints text the old class hid. After a
# hard separator, an underscored run in front of a keyword is read as the later label's prefix, so in
# ``token=a;b_password="v w"`` the "b" prints as part of the label ``b_password`` and "v w" no longer
# does. That is how ``_CREDENTIAL_KV`` already reads the same text, since its own value stops at ";".
# Every character outside letters, digits, ".", "-" and "_" is a hard separator, "+", "@", "/" and "("
# among them. So the run that prints can be the tail of a value such as ``token=abc+def_password='x y'``,
# where "def" prints. ":" and "=" count too, so the printed run can be the TAIL OF A VALUE written as
# ``label=value``: in ``MEFOR_B_PW = vq0:vq1_session = 'vq2:vq3'`` it is "vq1" that prints, and the
# quoted "vq2:vq3" that no longer does. Taken because the quoted value is the one a label names for
# certain; the run in front of the keyword is a value only by one of two readings.
#
# OPEN DEFECTS, NOT TRADES: VALUES THIS CHANGE PRINTS THAT THE PATTERNS BEFORE IT HID. Found by code
# review on 2026-10-05, on both copies and every surface, and not fixed here. THE MECHANISM: the
# passes run one after another, and each judges where its value stops on text that earlier passes
# already rewrote. A stop, a guarded quoted value or a braced one leaves a quote, or takes one, where
# the old classes did the other. So a later pass reads different text, and its value closes or stops
# somewhere else. A ``MEFOR_`` label inside an earlier label's quoted value is one way in, and it is
# not the only one: the same cascade lands in ``_KEY_MATERIAL`` on lines with no ``MEFOR_`` label at
# all, after ``_CREDENTIAL_KV`` rewrote them. Four of these lines also hide a value the old patterns
# printed, each named below. That is by accident, so they belong here and not with the trade above.
# At least these shapes:
#
# * a stop before a later quoted label whose value the run-on refuses, for a non-ASCII character or a
#   label in it: ``password='pw-A1 MEFOR_A=x;private_key='pk<e-acute>-B1 pk-B2'`` prints both pk
#   values;
# * a later ``MEFOR_`` label the old class swallowed now matching, and taking its own closer:
#   ``password='pw-A1 pw-A2;MEFOR_A=x;MEFOR_B='pw-B1'`` prints " pw-A2";
# * a stop that splits one ``MEFOR_`` value, so a later ``MEFOR_`` label eats the space that ended an
#   earlier plain value: ``secret=pw-A0@MEFOR_B_PW=pw-A2;MEFOR_X = 'pw-A4'@x.password='pw-A6``
#   prints "pw-A6", and hides "pw-A4", which the old patterns printed;
# * ``_KEY_MATERIAL`` running over a later key label, with no ``MEFOR_`` label on the line.
#   ``_CREDENTIAL_KV`` now takes a quoted value whole, closer and all, where an old pass left a quote
#   that ended ``_KEY_MATERIAL``'s plain value. That value now runs on over the later key label, which
#   gets no stop because its own value is not a closed, guarded quote.
#   ``connect failed encryption_key=token=password='hunter2',private_key='abc def=='`` prints
#   "abc def==". The old patterns printed "hunter2" and " def==", so "abc" is new and "hunter2" is
#   now hidden. ``cfg private_key=pass=credential="c1"|private_key'=pk-SECRET-9`` prints
#   "pk-SECRET-9" and hides "c1", which the old patterns printed. And
#   ``private_key=password='vq0 token=''|encryption_key='vq2`` prints "vq2";
# * a stop that takes a ``MEFOR_`` match away: ``pass='MEFOR_1:pass'="vq4"'`` prints "vq4". The old
#   ``_MEFOR_SECRET`` ate ``pass'``, so the outer quoted value closed on the last quote. Now that
#   value's first run is a quoted label, ``_MEFOR_SECRET`` does not match, and the outer value closes
#   on the quote it left;
# * ``_MEFOR_SECRET``'s guarded quoted value matching where the old class did not:
#   ``pass=",pw-IN-3 MEFOR_A"=' mv-4'`` prints ",pw-IN-3" and hides " mv-4", which the old patterns
#   printed. The label takes the double quote that closed the outer value, so that value has no
#   closer and nothing matches it.
#
# ``tests/test_log_redaction_secret_domain.py`` pins each one as still printing, so a fix must
# update that pin and this list together.

# A quoted value for the patterns that only took a plain one before BACKLOG #1685's remainder:
# ``_MEFOR_SECRET``, ``_BEARER`` and ``_KEY_MATERIAL``. ``_CREDENTIAL_KV`` keeps the plain quoted
# form it shipped with, widened only where its closer opens a later label's value; that form is
# :data:`_KV_QUOTED_VALUE`.
#
# GUARDED, BECAUSE AN UNGUARDED QUOTE CAN CLOSE ON SOMEBODY ELSE'S QUOTE. The plain class it replaces
# stopped at the first quote or space, and this alternate runs on to the closer. Wherever that closer
# really belongs to a later label, the later label's value printed where the old class hid it:
#
#   token='abc (truncated), password='p w'   ->  token=<redacted>p w'
#
# So the walk refuses at least these five shapes, and a refused value falls back to the plain class:
#
# * a closer right after a run of ":", "=" and spaces. That closer is a label's OPENING quote, after
#   ``password='``, ``password = '`` or ``authorization: Bearer '``. It also refuses a value that
#   merely ends in "=" or a space, base64 padding for one, which then gets the plain treatment.
# * a closer followed by ":" or "=". That closer is the quote of a ``'label'=`` echo.
# * the OTHER quote character inside. Without this, ``api_key="k1' x"`` inside a single-quoted
#   password took the password's closer, an earlier pass stealing a later pass's quote.
# * a "{" inside, for the same reason: a braced value under a later label may close after this
#   value's closer, and ``_CREDENTIAL_KV``'s overrun may run past it to the end of the line.
# * a "://" inside. A URL's password may hold an apostrophe, so ``token='a postgres://u:p'w@h``
#   closed on it, ``_DSN_PASSWORD`` no longer matched, and "w@h" printed. Found by the second review
#   round; the plain class stops at the space and leaves the DSN whole.
#
# These are the ways measured so far that a closer can belong to someone else, not a proof there are
# no more.
#
# THE CLOSER IS LEFT IN THE TEXT, by a lookahead, and that is load-bearing. The plain classes always
# stopped AT a quote, so a later pass found it there: as the closer of an earlier value it had opened
# (``password='a b token='c'`` hid all of "a b" only because "'" was still after "c"), and as the
# terminator of a plain value running up to it. Consuming the closer took both away and printed
# values the old patterns hid. ``_MEFOR_SECRET`` alone consumes it, and only on a non-empty value with
# no space in it, where its old trailing quote did. That holds only where the old pattern matched the
# label at all. Where an earlier old value had swallowed the label, consuming the closer can print a
# value; the OPEN DEFECTS list, in the comment on the stop above, gives the measured shapes.
#
# THE WALK TAKES AT LEAST ONE TOKEN, so an empty ``''`` or ``""`` is refused, as the old plain class
# refused it. Accepting it let ``token=`` take a line break and an empty quote on the next line, and
# an earlier quoted credential then ran on past where the old line ended. Found by the second review
# round of 2026-10-05.
#
# DETERMINISTIC AND POSSESSIVE, so linear: the two branches of the walk cannot match the same
# character, and each takes a whole run, so a long run of spaces is walked once.
_GUARDED_QUOTED_VALUE = (
    "'(?:[^'\"{\\s:=]++|(?::(?!//)|=|[^\\S\r\n])++(?!'))++(?='(?!\\s*+[:=]))"
    '|"(?:[^\'"{\\s:=]++|(?::(?!//)|=|[^\\S\r\n])++(?!"))++(?="(?!\\s*+[:=]))'
)

# The braced value for ``_MEFOR_SECRET`` and ``_KEY_MATERIAL``, guarded the same way and for the same
# reason: no quote inside, so it cannot close on a later label's quoted value, as in
# ``MEFOR_X={a password='b} c'``, and no line break, which the plain class it falls back to never
# crossed. Each user adds its own guard after the closer: the closer must END the value, at a
# character the pattern's plain class stops at, or ``MEFOR_X={a}bc`` would print "bc".
_GUARDED_BRACED_VALUE = r"\{(?:[^}'\"\r\n]|\}\})*+\}(?!\})"
#: The same, holding no whitespace at all: the one braced shape the old plain class took whole.
_GUARDED_BRACED_NO_SPACE = r"\{(?:[^}'\"\s]|\}\})*+\}(?!\})"

#: The first letters of every label keyword. A one-character gate in front of the keyword alternation:
#: a case-folded alternation is tried branch by branch, and most runs start with none of these.
_KEYWORD_INITIALS = "".join(
    sorted({word[0] for word in _CREDENTIAL_WORDS + _KEY_MATERIAL_WORDS + _TOKEN_WORDS})
)
#: A label up to where its value starts: the keyword, an optional quote, the ":" or "=", and an auth
#: scheme word after a token label. A token label takes the quote only before ":"; ``_BEARER`` says
#: why.
_LABEL_HEAD = (
    r"(?=(?i:[" + _KEYWORD_INITIALS + r"]))"
    r"(?:(?i:" + _alternation(_CREDENTIAL_WORDS + _KEY_MATERIAL_WORDS) + r")\b['\"]?\s*+[:=]\s*+"
    r"|(?i:" + _alternation(_TOKEN_WORDS) + r")\b(?:['\"]\s*+:|\s*+[:=])\s*+"
    r"(?:(?i:bearer|basic|digest)\s++)?"
    r")"
)
_MEFOR_LABEL_HEAD = r"\b(?-i:" + re.escape(_ENV_PREFIX) + r"[A-Z0-9_]++)\b['\"]?\s*+[:=]\s*+"
_QUOTED_LABEL = _LABEL_HEAD + r"(?:" + _GUARDED_QUOTED_VALUE + r")"
_MEFOR_QUOTED_LABEL = _MEFOR_LABEL_HEAD + r"(?:" + _GUARDED_QUOTED_VALUE + r")"

#: A label of any family up to where its value starts, for :data:`_KV_QUOTED_VALUE`. Unlike
#: :data:`_LABEL_HEAD` it takes no quote after the keyword and no line break, so a run-on can never
#: cross a line or end on a ``'label'=`` echo's own quote.
_RUN_ON_LABEL = (
    r"(?:(?=(?i:[" + _KEYWORD_INITIALS + r"]))"
    r"(?:(?i:" + _alternation(_CREDENTIAL_WORDS + _KEY_MATERIAL_WORDS) + r")\b"
    r"[^\S\r\n]*+[:=][^\S\r\n]*+"
    r"|(?i:" + _alternation(_TOKEN_WORDS) + r")\b[^\S\r\n]*+[:=][^\S\r\n]*+"
    r"(?:(?i:bearer|basic|digest)[^\S\r\n]++)?)"
    r"|\b(?-i:" + re.escape(_ENV_PREFIX) + r"[A-Z0-9_]++)\b[^\S\r\n]*+[:=][^\S\r\n]*+)"
)

# A LATER ``_CREDENTIAL_KV`` LABEL WHOSE VALUE IS BRACED AND HOLDS WHITE SPACE (BACKLOG #2966). The
# plain class ran on over such a label and stopped at the space inside its braces, so the tail of the
# braced value printed, under every label whose class is :data:`_PLAIN_VALUE` or one of its siblings:
#
#   MEFOR_X=a;PWD={pp ww}                ->  MEFOR_X=<redacted> ww}
#   MEFOR_STORE_DSN=Server=h;PWD={pp ww} ->  MEFOR_STORE_DSN=<redacted> ww}
#   token=a;PWD={pp ww}                  ->  token=<redacted> ww}
#
# THE VALUE STOPS IN FRONT OF THE LABEL AND THEN TAKES IT, THROUGH THE BRACED VALUE, UP TO THE CLOSER.
# What the old class printed, from the first white space in the braces to the closer, is written back
# MASKED rather than dropped, by :func:`_mask_member_value`, the connection-string member mask, and the
# closer stays. So ``MEFOR_X=a;PWD={pp ww}`` becomes ``MEFOR_X=<redacted> xx}``, the old
# ``MEFOR_X=<redacted> ww}`` with its letters masked, and the label is hidden with the value, as it was
# before. That mask keeps each word's length and the class of each character, and keeps whole what a
# later pass reads: a placeholder an earlier pass wrote, the bundle's ``mfb64:v1:`` marker, and a scheme
# word such as ``Bearer`` before a space. So every later pass reads text of the shape the old class
# left. A first form masked every letter and digit to "x" and printed values the old class hid: in
# ``token=a;PWD={pp Bearer abcdefgh}ijkl`` the later bearer pass no longer saw ``Bearer`` and "}ijkl"
# printed, and a placeholder in the tail stopped being one. Both simpler forms were built first and
# measured printing values the old class hid, by changing that shape:
#
# * Leaving the label to ``_CREDENTIAL_KV`` let it take the closer, so a braced value under an EARLIER
#   label, which the old text closed on that "}", ran to the end of the line and fell back to its plain
#   class instead: in ``private_key"={a b}} token={c;d};PWD={e f}``, " b}}" printed.
# * Taking the braced value up to the closer and writing nothing back dropped the white space, so an
#   EARLIER label's plain value, which the old text stopped there, ran on over a later label and printed
#   that label's value: ``K_pwd'='a{b:MEFOR_Y'=c@Password = { d}.PWD={e f}} g`` printed " f}} g".
#
# WHAT THE BRACES MUST HOLD, each condition a measured reason:
#
# * White space. Every plain class stops at white space, so only then did the old class end INSIDE
#   the braces. A braced value with no white space it took whole and ran on past, and taking less there
#   would print what followed the closer.
# * No quote and no line break, as :data:`_GUARDED_BRACED_VALUE` refuses them, so the walk cannot end
#   on another label's quote or cross a line the old class never crossed.
# * No ";", "," or "&" anywhere in the braces. Those end the value class of ``_CREDENTIAL_KV``,
#   ``_KEY_MATERIAL`` or ``_AUTH_SCHEME``, so a run-on through one took text that class never took:
#   in ``x_pwd='a/PWD:{b;password=c=Bearer d }e`` the ``;password=`` the connection-string member pass
#   reads was gone, and "e" printed.
# * No label, of any family, after the first white space, no scheme word before white space, no "%",
#   and no character outside ASCII there. The old class stopped at that white space, so the rest of
#   the line, a label in the braces included, was still in front of the pass that wrote the
#   placeholder and of every pass after it. A run-on takes the label out of the text that pass still
#   scans: in ``MEFOR_X=a;PWD={pp token=abc}def``, ``api_key=a&passwd={b session=c}d`` and
#   ``retry Bearer abcd.PWD={c Bearer dd-dd}ef-gh`` the later label's value ran on past the closer,
#   which the old text hid and the run-on printed. A "%" is refused because a label may start right
#   after a percent escape, as in ``%3Bpassword=``, where the check in front of each run does not look;
#   a character outside ASCII, so a label spelled with a fold character cannot slip past it.
# * The first white space a space or a tab, and no line break of any kind after it: none of VT, FF,
#   U+001C to U+001E, U+0085, U+2028 or U+2029, which the log and bundle readers split a record at.
# * No "{", which keeps the scan linear. A walk from one label's "{" ends at the next "{" at the
#   latest, so walks started by two labels cannot overlap, and a line of unclosed ``PWD={`` labels costs
#   one walk per label, not one per pair.
#
# AND WHAT THE LABEL MUST BE: a credential word, with a ``\b`` in front of it, no quote after it,
# and the "{" right after its ":" or "=", with nothing but spaces and tabs before them. Not a line
# break, nor any of the record breaks listed above or other white space, because the run-on deletes
# what is between the keyword and the "{": a line break would join the lines of a multi-line record,
# and ``PWD<U+2028>={pp ww}`` lost its U+2028. White space after the separator, because the fast
# path below ends a run there and never checks the stop, so with it the two paths disagreed and
# ``token=a;PWD= {b c}`` printed or not by whether a "{" came earlier in the value; that shape now
# prints as it did before, on both paths. The ``\b``, because a keyword glued on by "_", as in
# ``x-client_secret={a b}``, is one no pass can resume at, and stopping there printed the whole
# braced value. No underscored prefix after a hard separator, unlike the quoted stop, because in
# ``x_pwd: a:b_pwd={c d}`` that prints "b", which the old class hid. No quote, because in
# ``PWD'='a:b|MEFOR_Y={c;d}:pwd'={e f}'`` the quote the old class ate was the one an earlier quoted
# value would otherwise close on. Each of those shapes still prints the braced value's tail, as it
# did before; that is a residual. Whatever the conditions refuse gets the old behaviour.
_BRACED_HEAD = (
    r"\b(?=(?i:[" + "".join(sorted({word[0] for word in _CREDENTIAL_WORDS})) + r"]))"
    r"(?i:" + _alternation(_CREDENTIAL_WORDS) + r")\b[ \t]*+[:=]"
)
#: The braced value up to its first white space, then the rest up to its closer. :data:`_BRACED_LABEL`
#: adds the closer and its guard, and is what the stop checks for; :data:`_BRACED_RUN_ON` is what the
#: value then takes, the part from the white space on in the group ``braced_tail``. One walk, so the
#: two agree at every position.
_SPACED_BRACED_HEAD = r"\{(?:[^{}'\"\s;,&]|\}\})*+"
_SPACED_BRACED_TAIL = (
    r"[ \t](?:[^{}'\"%;,&\r\n\v\f\x1c-\x1eA-Za-z0-9\x80-\U0010ffff]|\}\}"
    + r"|(?!"
    + _RUN_ON_LABEL
    + r"|(?i:bearer|basic|digest)\s)(?-i:[A-Za-z0-9])++)*+"
)
_BRACED_LABEL = _BRACED_HEAD + _SPACED_BRACED_HEAD + _SPACED_BRACED_TAIL + r"\}(?!\})"
_BRACED_RUN_ON = (
    _BRACED_HEAD
    + _SPACED_BRACED_HEAD
    + r"(?P<braced_tail>"
    + _SPACED_BRACED_TAIL
    + r")(?=\}(?!\}))"
)
#: Checked before a value's FIRST run.
_NOT_AT_QUOTED_LABEL = (
    r"(?!" + _QUOTED_LABEL + r"|" + _BRACED_LABEL + r"|" + _MEFOR_QUOTED_LABEL + r")"
)
#: A hard separator behind: a character no label can hold, so the prefix branch cannot start
#: inside a dotted, hyphenated or underscored run.
_HARD_SEPARATOR_BEHIND = r"(?<![A-Za-z0-9._\-])"
#: Checked before every LATER run: the same, plus the underscored prefix after a hard separator.
_NOT_BEFORE_QUOTED_LABEL = (
    r"(?!(?:"
    + _HARD_SEPARATOR_BEHIND
    + r"\b(?:[A-Za-z0-9]++_){1,6})?"
    + _QUOTED_LABEL
    + r"|"
    + _BRACED_LABEL
    + r"|"
    + _MEFOR_QUOTED_LABEL
    + r")"
)

#: Every character outside ASCII that Python's case-insensitive matching reads as an ASCII letter:
#: U+0130, U+0131, U+017F and U+212A, the set :data:`_GATE_FOLDS` measures (BACKLOG #3114). In a
#: pattern compiled without a global fold, a value walk read such a character as a separator and
#: checked the stop only from the next run, so a keyword it headed was never checked. The walks take
#: each one as a token of its own: :data:`_FOLD_HEAD`, with the stop checked in front of it, where
#: it starts a word, and :data:`_FOLD_INSIDE`, unchecked, inside one. They still check the run after
#: it. :data:`_LABEL_HEAD` and :data:`_RUN_ON_LABEL` have no ``\b`` in front of a keyword, so the
#: lookbehinds are what keep the stop from firing inside a word. In a pattern that folds globally
#: the walk's run class already holds these characters, so those branches are never reached there
#: and the walk is the one it was. Built with ``chr()`` so no encoding layer between here and disk
#: can change a character. The support bundle restates both as literals, so the regex scanner can
#: read its copy; a test holds both copies to the measured set.
_WALK_FOLD_CHARS = "".join(map(chr, (0x0130, 0x0131, 0x017F, 0x212A)))
_FOLD_CLASS = "[" + _WALK_FOLD_CHARS + "]"
_FOLD_HEAD = "(?<![A-Za-z0-9" + _WALK_FOLD_CHARS + "])" + _FOLD_CLASS
_FOLD_INSIDE = "(?<=[A-Za-z0-9" + _WALK_FOLD_CHARS + "])" + _FOLD_CLASS


#: The outer walk: up to the next quote of one kind, or to a label whose value opens with one.
_SQ_RUN_ON_WALK = (
    r"(?:[^'\r\nA-Za-z0-9"
    + _WALK_FOLD_CHARS
    + r"]|"
    + _FOLD_INSIDE
    + r"|(?!"
    + _RUN_ON_LABEL
    + r"')"
    + r"(?:[A-Za-z0-9]++|"
    + _FOLD_HEAD
    + r"))*+"
)
_DQ_RUN_ON_WALK = (
    r"(?:[^\"\r\nA-Za-z0-9"
    + _WALK_FOLD_CHARS
    + r"]|"
    + _FOLD_INSIDE
    + r"|(?!"
    + _RUN_ON_LABEL
    + r"\")"
    + r"(?:[A-Za-z0-9]++|"
    + _FOLD_HEAD
    + r"))*+"
)
#: The inner walk, over the later label's value. It stops at anything a later pass could read past
#: the closer: either quote, a "{", a "://", any label at all, and any character outside ASCII, so
#: a keyword spelled with a fold character stops it in both copies alike.
_RUN_ON_INNER = (
    r"(?:[^'\"{:\r\nA-Za-z0-9\x80-\U0010ffff]|:(?!//)"
    r"|(?!" + _RUN_ON_LABEL + r")(?-i:[A-Za-z0-9])++)*+"
)

# ``_CREDENTIAL_KV``'s quoted value: the plain quoted form ``'[^'\r\n]*+'``, except where the quote that
# would close it OPENS A LATER LABEL'S VALUE. There it takes that label and its value as well, through
# the value's own closer. The plain form closed on the later label's opening quote, so that label was
# eaten and its value printed. ``password='abc, private_key='p w q'`` printed "p w q'" on both copies
# at the merge base, and still does under the plain form. A stop then made it worse, in a whole
# family of shapes and not one: in ``pass='a b+MEFOR_B_PW: c,private_key='pk1 pk2'`` the old
# ``_MEFOR_SECRET`` class ate the inner opening quote, so the outer value closed at the end of the
# line and hid everything. With the stop that quote stayed, the outer value closed on it, and
# "pk1 pk2" printed. The run-on below closes that only when the later value is plain ASCII with no
# label in it. WHEN IT FALLS BACK AFTER A STOP, IT DOES NOT REPEAT THE OLD BEHAVIOUR: the quote it
# closes on is one the old ``_MEFOR_SECRET`` class had eaten, so the value after it prints where the
# old patterns hid it. The OPEN DEFECTS list, in the comment on the stop above, gives the measured
# shapes.
#
# WHEN IT RUNS ON, AND WHEN IT FALLS BACK. Where no label opens with the closing quote, it takes the
# same span as the plain form. Where one does, it runs on to the later value's closer only when
# that value is plain: :data:`_RUN_ON_INNER` must reach the closer without meeting another quote, a
# "{", a "://", any label or a character outside ASCII, and the closer must not be followed by ":" or
# "=", the quote of a ``'label'=`` echo. Otherwise it closes on the later label's opening quote, as
# the plain form did, and leaves the rest to the passes after it. Every guard was measured, in
# two review rounds: without them the run-on carried on over text a later pass used to read past the
# closer -- a third label, a braced or other-quoted value holding the quote, an unclosed "{", a DSN
# password holding an apostrophe, a keyword spelled with a fold character -- and printed its tail.
# Only ``_CREDENTIAL_KV`` takes it: the GUARDED forms refuse a closer right after a ":" or "=".
#
# THE FAST PATH IS THE PLAIN FORM, and the two agree wherever it is taken. A run-on needs a label
# head ending right before the first quote after the opening one, and every head ends in ":", "=" or
# a space. So when the character before that quote is none of those, the plain span is the answer
# and no walk runs. Without it an ordinary quoted credential line cost 45 percent more, measured by
# the second review round.
#
# LINEAR. Each walk is a run or one other character at a time, with the label check in front of each
# run only. The outer walk ends at the first quote after the opening one; the inner walk ends at the
# next quote after that. So walks from two labels cannot share more than the span of three quotes.
_KV_QUOTED_VALUE = (
    r"'[^'\r\n]*+(?<![:=\s])'"
    + r"|'"
    + _SQ_RUN_ON_WALK
    + r"(?:"
    + _RUN_ON_LABEL
    + r"(?=')(?:'"
    + _RUN_ON_INNER
    + r"(?='(?!\s*+[:=])))?+)?+'"
    + r"|\"[^\"\r\n]*+(?<![:=\s])\""
    + r"|\""
    + _DQ_RUN_ON_WALK
    + r"(?:"
    + _RUN_ON_LABEL
    + r"(?=\")(?:\""
    + _RUN_ON_INNER
    + r"(?=\"(?!\s*+[:=])))?+)?+\""
)

# THE FAST PATH, which is what keeps an ordinary credential line near its old cost. A stop needs label
# syntax that runs from inside the value to a quote, so the value's natural run must end on that
# syntax: on a quote, or on whitespace followed by ":", "=", a quote, or an auth scheme word.
# ``_NO_QUOTED_LABEL_AFTER`` rules all of those out, and when it holds the whole run is taken with no
# check at all; only otherwise does the value walk token by token. The two paths give the same result,
# because a stop is impossible whenever this lookahead passes. What it saves an ordinary credential
# line is measured once, in the module docstring. A run holding a "{", or followed by one, never takes
# it, because the stop before a braced label (BACKLOG #2966) needs a "{" right after a ":" or "=" in the
# run, or after white space that the lookahead already refuses; such a run walks, which the run-on
# walk tests time.
_NO_QUOTED_LABEL_AFTER = r"(?!\s*+[:='\"]|\s++(?i:bearer|basic|digest)\s)"

# The plain value classes. Each pattern keeps the terminator set it always had, stated once here and
# spliced into all three places a class needs it: the fast path, the first run and every later run.
# After the walk, or in place of it, a value takes a braced label it stopped at, up to the closer;
# :data:`_BRACED_RUN_ON` says why.
_PLAIN_TERMINATORS = r"\s'\""  # _MEFOR_SECRET, _BEARER
_KV_TERMINATORS = r"\s'\";,&"  # _CREDENTIAL_KV
_KEY_TERMINATORS = r"\s'\";&"  # _KEY_MATERIAL
_SCHEME_TERMINATORS = r"\s'\",;"  # _AUTH_SCHEME
_PLAIN_VALUE = (
    rf"['\"]?(?:[^{_PLAIN_TERMINATORS}{{]++(?!\{{){_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:(?:{_FOLD_INSIDE}|{_NOT_AT_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_PLAIN_TERMINATORS}])"
    rf"(?:{_FOLD_INSIDE}|{_NOT_BEFORE_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_PLAIN_TERMINATORS}])*+"
    rf"|(?={_BRACED_LABEL}))(?:{_BRACED_RUN_ON})?+)"
)
_PLAIN_KV_VALUE = (
    rf"['\"]?(?:[^{_KV_TERMINATORS}{{]++(?!\{{){_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:(?:{_FOLD_INSIDE}|{_NOT_AT_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_KV_TERMINATORS}])"
    rf"(?:{_FOLD_INSIDE}|{_NOT_BEFORE_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_KV_TERMINATORS}])*+"
    rf"|(?={_BRACED_LABEL}))(?:{_BRACED_RUN_ON})?+)"
)
_PLAIN_KEY_VALUE = (
    rf"['\"]?(?:[^{_KEY_TERMINATORS}{{]++(?!\{{){_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:(?:{_FOLD_INSIDE}|{_NOT_AT_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_KEY_TERMINATORS}])"
    rf"(?:{_FOLD_INSIDE}|{_NOT_BEFORE_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_KEY_TERMINATORS}])*+"
    rf"|(?={_BRACED_LABEL}))(?:{_BRACED_RUN_ON})?+)"
)
_PLAIN_SCHEME_VALUE = (
    rf"['\"]?(?:[^{_SCHEME_TERMINATORS}{{]++(?!\{{){_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:(?:{_FOLD_INSIDE}|{_NOT_AT_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_SCHEME_TERMINATORS}])"
    rf"(?:{_FOLD_INSIDE}|{_NOT_BEFORE_QUOTED_LABEL}(?:[A-Za-z0-9]++|{_FOLD_HEAD})|[^A-Za-z0-9{_WALK_FOLD_CHARS}{_SCHEME_TERMINATORS}])*+"
    rf"|(?={_BRACED_LABEL}))(?:{_BRACED_RUN_ON})?+)"
)

# A bearer/authorization token or an opaque session token in a header-ish or "token=" shape.
#
# The ``(?:bearer|basic|digest)\s+`` group is load-bearing, not decoration: without it the value class
# matches the AUTH SCHEME rather than the credential, so "Authorization: Bearer <tok>" redacts the word
# "Bearer" and emits <tok> verbatim. That exact defect shipped green on the sibling surface for months
# (BACKLOG #1183). Making the group optional keeps the plain "token=<tok>" shape working.
#
# A QUOTED value is taken whole when :data:`_GUARDED_QUOTED_VALUE` allows it, and a BRACED one never;
# the reason is on ``_CREDENTIAL_KV``. Otherwise the plain class takes the value up to its first quote.
#
# A QUOTED KEY IS A LABEL (BACKLOG #3038). A quote after the label, then a colon, reads a JSON or dict
# key, ``{"access_token": "v"}``; without it the closing quote stopped the match and the value
# printed. ONLY BEFORE A COLON, unlike the other families, which take a quote before "=" too. Taking
# ``'=`` here as well printed 147 value atoms the patterns before it hid, in
# ``test_the_change_prints_no_value_the_pre_change_patterns_hid``: a token label in a ``'label'=``
# echo then ran its plain value over a later key-material label. JSON and dict keys end in a colon,
# so the colon form is the whole of #3038. :data:`_LABEL_HEAD` takes the same form, so a later quoted
# token key still stops a plain value. The match is rewritten as ``label=<placeholder>``, as every
# family's is, so the JSON shape is not kept. It takes no braced value: ``{"session": {"u": 1}}``
# loses only its "{", exactly as ``session={"u": 1}`` does.
_BEARER = re.compile(
    r"(?i)" + _LABEL_START + r"(" + _LABEL_PREFIX + r"(?:" + _alternation(_TOKEN_WORDS) + r"))\b"
    r"(?:['\"]\s*:|\s*[:=])\s*(?:(?:bearer|basic|digest)\s+)?"
    r"(?:" + _GUARDED_QUOTED_VALUE + r"|" + _PLAIN_VALUE + r")"
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
#
# THE FOUR-CHARACTER FLOOR IS A LOOKAHEAD, so it is judged on the text before any stop: a stop that
# shortens the run cannot push it under the floor. Asked of the stopped run instead,
# ``Bearer ab:password="v w"`` would fail the floor and print "ab", which the unstopped pattern
# redacted. The stop CAN still take a match away, on purpose: when the value's first run is itself a
# quoted label, as in ``Bearer password="v w"``, this pattern does not match, and the label's own
# pattern takes its value. The pattern before the stop redacted the word "password" there, so no
# later pass saw the label, and "v w" printed.
_AUTH_SCHEME = re.compile(
    r"(?i)" + _LABEL_START + r"(bearer)\s+(?=['\"]?[^\s'\",;]{4})" + _PLAIN_SCHEME_VALUE
)

# A MEFOR_* secret echoed as "MEFOR_FOO=value" or "MEFOR_FOO: value": never carry the value. The
# optional quotes match the shape ``resolve_env_settings`` produces -- "(env 'MEFOR_VALUE_PW'='<value>')"
# -- which an unquoted form misses entirely.
#
# A quoted value is taken whole, and so is a braced one when its closer ends the value; the guard is
# on ``_CREDENTIAL_KV``'s residuals.
#
# A BRACED VALUE WITH NO SPACE IN IT TAKES ONE QUOTE AFTER ITS CLOSER, as the old plain class's
# trailing ``['\"]?`` did. Without it ``password='vq0 MEFOR_X={vq1}' vq2'`` printed " vq2'": the old
# class ate the quote after "}", so the password's quoted value closed on the last quote and hid the
# line, but the braced form left that quote behind and the password closed on it. A braced value WITH
# a space leaves the quote, because the old class stopped at the space and left it too: taking it
# there made ``password="hunter;two MEFOR_DB={x y}" mode`` print ";two", found by the second review
# round of 2026-10-05.
_MEFOR_SECRET = re.compile(
    r"\b(" + re.escape(_ENV_PREFIX) + r"[A-Z0-9_]+)\b['\"]?\s*[:=]\s*"
    r"(?:"
    + _GUARDED_BRACED_NO_SPACE
    + rf"(?![^{_PLAIN_TERMINATORS}])"
    + r"['\"]?|"
    + _GUARDED_BRACED_VALUE
    + rf"(?![^{_PLAIN_TERMINATORS}])"
    # A quoted value with no space in it and at least one character, closer and all. With the braced
    # branch above, it takes exactly the span the old plain class and its trailing quote took, so later
    # passes see the same text they always did, wherever the old pattern matched this label at all.
    # An empty value is refused, as the old class refused it.
    + r"|(?="
    + _GUARDED_QUOTED_VALUE
    + r")['\"][^\s'\"]++['\"]|"
    + _GUARDED_QUOTED_VALUE
    + r"|"
    + _PLAIN_VALUE
    + r"['\"]?)"
)

# A credential in a "<label>=<value>" pair: an ODBC "PWD=", a "password=" in a connection error, a
# provider "secret=". The value class stops at the separators these actually appear inside (";" in an
# ODBC string, "," and "&" in a query), so a redaction cannot swallow the rest of the line.
#
# THE QUOTED ALTERNATES COME FIRST because they and the plain class overlap and the first alternate
# wins; the plain class keeps its own leading ``['\"]?`` so a value whose quote does not CLOSE on this
# line still loses its head exactly as it did before.
#
# WHAT THE OTHER LABEL PATTERNS TAKE, AND WHAT IS STILL LEFT OPEN. Decided under BACKLOG #1685's
# remainder; each choice keeps a pattern from printing anything its plain class used to hide.
#
# * ``_MEFOR_SECRET`` and ``_KEY_MATERIAL`` take a quoted value whole, and a braced one whole when the
#   closing "}" ENDS the value -- that is, when the next character is one their plain class stops at.
#   Without that guard, ``MEFOR_X={a}bc`` would redact ``{a}`` and print "bc", which the plain class
#   used to hide. Both forms are the GUARDED ones. A value either refuses falls back to the plain
#   class, which now carries the stop before a quoted label and is otherwise the old class.
# * ``_BEARER`` takes a quoted value and NOT a braced one. ``session=`` and ``token=`` legitimately
#   carry a "{"-opening dict or JSON repr in this engine's log text, and taking braces would change
#   those lines for no credential.
# * An UNCLOSED quote falls back to the plain class in every pattern, so ``password='wt-A wt-B`` (no
#   closing quote) still prints " wt-B". Only ``_CREDENTIAL_KV``'s brace form gets an overrun, and
#   that is deliberate: a "{" after a credential label is unambiguous, while an apostrophe is ordinary
#   prose, and a quote overrun would eat the rest of any line whose value merely CONTAINS one. An
#   unclosed "{" under ``_MEFOR_SECRET`` or ``_KEY_MATERIAL`` falls back to the plain class too.
# * A list under ``_KEY_MATERIAL`` written with a SPACE after each comma still prints its later
#   elements; the reason is on that pattern.
# * A quoted value the guard refuses still prints its tail under the three guarded patterns. At least
#   these: one that holds the other quote, a "{" or a "://", one that ends in ":", "=" or a space, and
#   one whose closer is followed by ":" or "=". ``MEFOR_STORE_PW="it's a secret"`` prints
#   "s a secret"" and ``private_key='ab cd=='`` prints " cd=='". The guard is what stops a value
#   closing on a later label's quote, so loosening it is a trade to measure, not a free edit.
# * A plain value running on into a later braced value is CLOSED for a ``_CREDENTIAL_KV`` label whose
#   braced value holds white space (BACKLOG #2966): ``MEFOR_STORE_DSN=Server=h;PWD={p w}`` and
#   ``token=a;PWD={p w}`` print nothing now. A label or braced value that :data:`_BRACED_RUN_ON`'s
#   conditions refuse still prints all or part of the braced value, as before, and so does a
#   key-material or token label with one, as in ``token=a;session={p w}``. At least these shapes are
#   among them: ``PWD= {p w}`` with white space after the separator, a URL-encoded separator as in
#   ``%3BPWD={p w}``, and braces holding a label or a character outside ASCII after their first
#   white space. On the installed log chain a ``token=`` line still prints the tail, because the query
#   filter runs first and takes the head of the braced value before this pass sees it.
# Each of the residuals above, from the unclosed quote on, printed the same text before BACKLOG
# #1685's remainder; none is new.
_CREDENTIAL_KV = re.compile(
    r"(?i)"
    + _LABEL_START
    + r"("
    + _LABEL_PREFIX
    + r"(?:"
    + _alternation(_CREDENTIAL_WORDS)
    + r"))\b"
    r"['\"]?\s*[:=]\s*"
    r"(?:"
    + _ODBC_BRACED
    + r"|"
    + _KV_QUOTED_VALUE
    + r"|"
    + _ODBC_BRACED_OVERRUN
    + r"|"
    + _PLAIN_KV_VALUE
    + r")"
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
# support-bundle surface there is no long-base64 sweep behind this one to catch them. It stays open
# on purpose: after ", " the next element looks exactly like the next word of an ordinary sentence,
# so running on past the space would eat operator prose on every line that names a key.
#
# A quoted value is taken whole, and so is a braced one when its closer ends the value; the guard is
# on ``_CREDENTIAL_KV``'s residuals.
_KEY_MATERIAL = re.compile(
    r"(?i)"
    + _LABEL_START
    + r"("
    + _LABEL_PREFIX
    + r"(?:"
    + _alternation(_KEY_MATERIAL_WORDS)
    + r"))\b"
    r"['\"]?\s*[:=]\s*"
    r"(?:"
    + _GUARDED_BRACED_VALUE
    + rf"(?![^{_KEY_TERMINATORS}])|"
    + _GUARDED_QUOTED_VALUE
    + r"|"
    + _PLAIN_KEY_VALUE
    + r")"
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

#: Words a connection-string member's KEY may end in besides :data:`_CREDENTIAL_WORDS` (BACKLOG
#: #5030), so ``;AccessToken=`` is read as ``;sslpassword=`` is. Its own gate,
#: :data:`_MEMBER_EXTRA_HINT`, admits the member pass beside :data:`_CREDENTIAL_HINT`.
_MEMBER_EXTRA_WORDS = ("token",)

# A connection-string member whose KEY ends in a credential word, its value taken to the next ";"
# (BACKLOG #5030). A credential an ODBC connection string sends WITHOUT braces may hold a space, ",",
# "&" or "=": the generic dialect sends a password plain for a driver it has not measured, and every
# ``odbc_params`` value plain, ``sslpassword`` among them. ``_CREDENTIAL_KV``'s plain value class
# stops at the first three, so an echoed ``;PWD=Zq7 kx,Pw&mv=Ty9;`` printed " kx,Pw&mv=Ty9", and
# ``;sslpassword=...`` printed whole: "ssl" glued to "password" leaves no ``\b`` for a label.
#
# IT IS ITS OWN PASS, AND IT RUNS LAST in :func:`_run`, over the text every other pass left. Its
# first draft was a branch of ``_CREDENTIAL_KV``, tried at the label's own position, and a review of
# that draft found at least four shapes where it printed a value the label pattern hid: a later label
# written with a quoted key, a "}" or "@" that ``_KEY_MATERIAL`` or ``_DSN_PASSWORD`` needed later,
# and a value of only spaces before a line break. Run last, a value an earlier pass hid is already
# the placeholder when this pass reads it.
#
# THE VALUE IS MASKED WORD BY WORD, NOT REPLACED WHOLE (:func:`_mask_member_value`), BECAUSE THE
# SAME TEXT IS REDACTED AGAIN. A record that two or three handlers filter is rewritten in place, so
# each later handler's chain reads the text the one before it left. Store error text is redacted by
# :func:`messagefoundry.support.redact.redact_log_line`, then by the write-time chain, then by the
# bundle. A log line the chain wrote is redacted again when the bundle or ``GET /logs/tail`` reads it.
# A draft that replaced the whole value with the placeholder took characters a later pass reads, and
# that pass then printed values ``origin/main`` hid. A review measured 11 store-path and 5
# two-handler lines of a 20,000-line fuzz, and this rewrite's own differential measured 124 to
# 145 lines of 320,000 on each of the second handler, the third handler, a chain line the bundle
# reads back, and the store path. What it took, at least these: the "&", "^" or "%5E" a later PHI
# pass counts to judge a token an HL7 field run, so a token it hid whole then printed; a later label
# inside the value, such as ``Token=`` or ``?code=``, whose value a later pass reads past the ";" or
# across a line break the control-character filter wrote as text; a segment ID such as ``PID``
# before its "|"; and a long base64 run whose length let the bundle's sweep take a label behind it.
#
# So the mask changes only WORDS, a run of letters, digits, "_", "." and "-", and it masks each
# CHARACTER FOR A CHARACTER (:func:`_masked_word`): an ASCII letter becomes ``x`` and a digit ``0``,
# any other character but "_", "." and "-" becomes "_", and those three stay; right after a "%" the
# two characters of a hex escape stay hex. Every character outside a word stays in place too, the
# separators a PHI pass counts and the spaces that end a token among them. So the text keeps its
# length, and each character keeps its class in every alphabet a later pass counts: a word
# character or not, a digit or not, in the bundle's base64 alphabets or not. A digit masked to a
# letter printed too: under a JSON ``name`` the PHI pass keeps a value holding a digit as an
# operator's, and a value it then hid at once left the text after it for no pass. A mask of another length
# printed values ``origin/main`` hid: ``redacted`` for every word grew ``%5E05/05/1980/`` into a run
# the bundle's long-base64 sweep took with the ``5E`` of the ``%5E``, and a mask shorter than its
# word let a run that the control-character filter later joined fall under the sweep's length. A
# piece of a word between "." or "-" in either token shape of the PHI pass's name run keeps its
# capitals as ``X`` (``Jane`` is ``Xxxx``): in lower case, ``Jane Doe`` was no name run, so the
# bundle's PHI pass no longer replaced it, and on ``origin/main`` that replacement joined the tokens
# either side into one field run the pass hid whole. A second redaction leaves the mask as it is.
# The mask also keeps what a later pass reads in a word, at least these:
#
# * a word that holds one of :data:`_MEMBER_KEEP_WORDS` anywhere inside it, the label and anchor
#   words of the credential passes, the query filter, the support bundle and the PHI pass, stays
#   whole when a ":" or "=" follows the word (after an optional quote and spaces), or a "#" and
#   the word ends in "MRN", and so does a word ending in a scheme word or "MRN" when a space
#   follows it, a "#" after that space included. The whole word stays, not only the anchor, so
#   ``a1qkey=`` keeps ``a1qkey``. Anywhere else it is masked, so a password such as
#   ``Passw0rd!2024`` or a token holding ``sig`` is masked like any other;
# * a percent-encoded HL7 separator, a DICOM tag ``(gggg,eeee)``, the ``nonnumeric port: `` opener
#   of the PHI pass's userinfo backstop, and the support bundle's ``mfb64:v1:`` marker stay whole,
#   and a word stops where the opener or the marker starts;
# * a three-character segment ID before a "|" stays, and a prefix glued on by "." or "-" is masked.
#
# ``tests/test_connection_string_member_scrub.py`` switches each of those rules off in turn, and
# swaps the mask for a longer, a shorter and a digit-blind one, and shows a shape that then prints a value
# ``origin/main`` hid. A placeholder an earlier pass wrote also stays whole, so a second redaction
# does not respell ``[REDACTED]``. An XML tag, and an MSH header before a delimiter other than "|",
# are masked like any other text: a probe of 336 XML shapes and the fuzz found no later pass that
# reads either across the member's span.
#
# THE MEASUREMENT, a fuzz result over its corpus and not a proof. The differential feeds random
# lines of labels, separators, HL7, DICOM, userinfo and bundle-marker shapes and planted values
# through nine paths: each surface once, the chain once, twice and three times, a chain line the
# bundle reads back once and twice, and store error text through one and two handlers. It counts a
# line where a planted value prints and does not print with the member pass off, and, run against
# an ``origin/main`` tree, where it does not print there. On its last run, seeds 101 to 110 and
# 201 to 210, 3,000,000 random lines of which 1,215,761 hold a ";" and 807,717 a marker shape, it
# printed no line on any path, against the member pass off and against an ``origin/main`` tree
# alike. The word mask before it, ``redacted`` for every word, printed 1 line on a chain line the
# bundle read back on the first ten seeds, and the "#" rule before its fix printed on five later
# paths.
#
# THE COST, at least these. The value's spaces and punctuation print, so a reader sees that a
# password held a space, a "," and an "&", and how many words. The mask prints each word's LENGTH,
# where its digits, "_", "." and "-" sat, and where a name-shaped piece had its capitals. A word that holds
# a kept word anywhere inside it prints whole when a ":" or "=" follows it, such as the ``pass`` of
# ``pass=word`` or the ``a1qkey`` of ``a1qkey=``, and so does a three-character segment ID before a
# "|". Each of those printed on ``origin/main`` too, which hid at most the first word. Redacting a
# record ONCE, so a later handler reads nothing this pass wrote, was measured and not taken:
# ``origin/main``'s own second handler hides a value its first prints on 313 to 584 lines per
# 20,000, so a record redacted once would print each of them on every handler after the first.
# ``tests/test_connection_string_member_scrub.py`` holds a seeded sample of the differential, and
# the whole-value draft fails it.
#
# THE ";" IN FRONT IS THE DISCRIMINATOR. Every member after the first follows one, and the generic
# dialect's string never opens with a credential (``transports/database.py`` writes ``DRIVER`` and
# ``SERVER`` first). The "=" must follow the key directly, as the builder writes it.
#
# THE KEY IS A RUN OF LETTERS, DIGITS AND "_" THAT ENDS IN ONE OF THE WORDS. ``sslpassword``,
# ``SSLPassword`` and ``KeyStorePwd`` glue a word on with no separator, and only the fixed-width
# lookbehinds below read that. ``;Bypass=1`` is a member too, and its value is masked.
#
# THE VALUE RUNS TO THE NEXT ";", QUOTE OR LINE BREAK, OR THE END OF THE TEXT, over spaces, ",",
# "&", "=" and "://" alike. Spaces and then one quote may open it. Stopping at a later quote costs
# nothing the builder sends, since a plain password and every ``odbc_params`` value refuse quotes,
# and it keeps the rest of a quoted echo (``'...;PWD=a b' refused``) readable. A braced value is
# taken by ``_ODBC_BRACED`` with its body kept to one line, and then on to the same stops, so
# ``;sslpassword={a;b} c`` is masked whole, and a "{" not closed on its line takes the rest of the
# line, as ``_ODBC_BRACED_OVERRUN`` does for the label pattern. A brace may not cross a line: a
# traceback keeps its frames, and an unclosed "{" on one line cannot walk the rest of a long record
# from every later ";<key>={". An empty value, or one of spaces only, is no match.
#
# LINEAR. A match starts only AT a ";", which group 1 takes with the key so the replacement keeps it,
# so the key run cannot be entered mid-word. The key run and the braced and plain walks are
# possessive, the overrun has nothing after it to retry, and the lookbehinds are a fixed set of fixed
# widths. Every walk stays on its line. A plain walk stops at the next ";", so walks from two starts
# never overlap; a braced walk may cross a ";" on its line, and then ends the match there, or fails
# and the overrun takes that line, so no later start re-reads it. The mask walks its value once.
# ``tests/test_connection_string_member_scrub.py`` pins the time on a long line and on many lines.
#
# WHAT IT LEAVES, at least these:
#
# * a credential that is the FIRST member, with no ";" before it (``Password=a b;Server=h``).
#   ``_CREDENTIAL_KV`` reads it as before, so its tail after a space still prints;
# * a key that holds a credential word but does not END in one, such as ``ClientSecretValue``. The
#   builder's own ``_ODBC_SECRET_KEY_RE`` matches a word anywhere in a key, this pass only at its end;
# * a key holding "." or "-", or a space before its "=" (``;PWD =x``), left to ``_CREDENTIAL_KV``;
# * on the write-time chain, a member glued to a percent-encoded HL7 run in one token
#   (``a%7Cb%7Cc;sslpassword=x y``). :mod:`messagefoundry.redaction` runs first and replaces the
#   whole token, ";" and all, so the value's tail after a space prints, as it did before #5030;
# * a quoted value that holds a ";" (``;sslpassword="a;b c"``), which the value stops at, so the text
#   after the ";" prints, as it did before #5030. The builder refuses a quote and a ";" in such a
#   value.
#
# The key words are :data:`_CREDENTIAL_WORDS` and :data:`_MEMBER_EXTRA_WORDS`: the builder's own
# secret keywords, ``transports/database.py`` ``_ODBC_SECRET_KEY_RE``, plus a bare ``pass``, which
# that set lacks and which is why ``;Bypass=1`` is masked. They and the two brace fragments are
# spelled literally, so the regex scanner in ``tests/test_security_static.py`` reads the pattern;
# ``tests/test_connection_string_member_scrub.py`` holds the words to the tuples and the fragments
# to ``_ODBC_BRACED`` and ``_ODBC_BRACED_OVERRUN``. ``support/redact.py`` imports this one object
# and :func:`_mask_member`, and runs them last of its credential passes, so the bundle has no copy to
# drift.
_CONNECTION_STRING_MEMBER = re.compile(
    r"(?i)(;[A-Za-z0-9_]++(?:(?<=password)|(?<=passwd)|(?<=passphrase)|(?<=pass)|(?<=pwd)"
    r"|(?<=secret)|(?<=credential)|(?<=token)))="
    r"(\{(?:[^}\r\n]|\}\})*+\}(?!\})[^;'\"\r\n]*+|\{[^\r\n]*|[ \t]*+['\"]?[^;'\"\r\n]++)"
)

#: Words a member value keeps where a word holds one, matched as a substring ignoring case, and a
#: later pass reads the word there (:func:`_kept_word`; BACKLOG #5030). Each is a word some pass
#: after the member pass reads, so masking it would change what that pass does on a second redaction. At least: this module's credential, token and key-material
#: words and its ``MEFOR_`` prefix; its URL query-credential words (``key``, ``sig``, ``auth``,
#: ``jwt``; ``signature`` holds ``sig``); the write-time query filter's keys
#: (``logging_setup._CREDENTIAL_QUERY_KEYS``: ``code`` and ``state``, the rest hold ``token`` or
#: ``session``); the support bundle's ``mfb64`` marker and ``basic``/``digest`` scheme words; and the
#: PHI pass's anchors: ``mrn``, its JSON key words (``redaction._JSON_PHI_KEY``: ``family``,
#: ``given``, ``birthDate``, ``identifier``, ``telecom`` beside ``name`` and ``address``) and the
#: DICOM label words.
#: ``tests/test_connection_string_member_scrub.py`` holds this to those sources.
_MEMBER_KEEP_WORDS = (
    *_CREDENTIAL_WORDS,
    *_TOKEN_WORDS,
    *_KEY_MATERIAL_WORDS,
    *_MEMBER_EXTRA_WORDS,
    _ENV_PREFIX,
    "key",
    "sig",
    "auth",
    "jwt",
    "code",
    "state",
    "mfb64",
    "basic",
    "digest",
    "mrn",
    "name",
    "address",
    "family",
    "given",
    "birthdate",
    "identifier",
    "telecom",
    "0010",
    "patient",
    "medicalrecordlocator",
    "responsibleperson",
)
#: :data:`_MEMBER_KEEP_WORDS` as one search, reduced by subsumption (``pass`` holds ``password``,
#: ``key`` holds ``api_key``, ``auth`` holds ``authorization``). Spelled literally, so the regex
#: scanner in ``tests/test_security_static.py`` reads it; the member test holds it to the tuple.
_MEMBER_KEEP = re.compile(
    r"(?i)medicalrecordlocator|responsibleperson|identifier|credential|birthdate|address|patient"
    r"|session|telecom|mefor_|bearer|family|secret|digest|given|state|token|basic|mfb64|pass|code"
    r"|name|0010|auth|pwd|key|sig|jwt|mrn"
)

#: One unit of a member value. Group 1 is a WORD, which the mask may replace; every other
#: alternative is kept whole, and a character no alternative takes is kept too: a placeholder an
#: earlier pass wrote, a percent-encoded HL7 separator (``%7C``, ``%7E``, ``%5E``, ``%26``), the
#: PHI pass's userinfo opener, the support bundle's ``mfb64:v1:`` marker and a DICOM tag.
#:
#: The marker is spelled as ``support/redact.py`` ``_MFB64`` spells it, case and all, and a word
#: ends where the marker or the userinfo opener starts, so a word glued on before either
#: (``amfb64:v1:``, ``xnonnumeric port: ``) cannot take its head: neither reader has a word
#: boundary. Masking the marker's ``v1`` printed, on a chain line the bundle read back, the body
#: ``origin/main`` hid (BACKLOG #5030). :func:`_masked_word` keeps where the marker's base64 run
#: ends, since it keeps the class of each character.
_MEMBER_VALUE_UNIT = re.compile(
    r"<redacted>|\[(?:REDACTED|redacted)\]|%(?:7[CcEe]|5[Ee]|26)|nonnumeric port: |mfb64:v1:"
    r"|\([0-9A-Fa-f]{4}, ?[0-9A-Fa-f]{4}\)|((?:(?!mfb64:v1:|nonnumeric port: )[\w.\-])++)"
)
#: What must follow a word that holds a kept word anywhere inside it for the mask to keep the whole
#: word: an optional quote, spaces, and a ":" or "=", or a "#" (group 1) after a word ending in MRN. Read in the whole text, past
#: the value's end, since a value that opens with a quote ends at the quote that closes a JSON key
#: (``;Token="name": ...``). A "#" keeps only a word that ends in ``mrn``
#: (:data:`_MEMBER_MRN_WORD`), since the PHI pass's MRN label is the only reader of a "#" after a
#: word; ``Passw0rd#2024`` printed ``Passw0rd`` while any kept word kept a word before a "#".
_MEMBER_LABEL_TAIL = re.compile(r"""['"]?[ \t]*+([:=#])""")
_MEMBER_MRN_WORD = re.compile(r"(?i)mrn\Z")
#: Kept words a later pass reads before a space instead: the bearer passes' scheme words and the PHI
#: pass's MRN label. Each reads the word at the END of a word, so only a word that ends in one is
#: kept; a substring search kept ``Basic123`` of a passphrase.
_MEMBER_SPACED_WORD = re.compile(r"(?i)(?:bearer|basic|digest|mrn)\Z")
#: A word that ends in an HL7 segment ID at a word boundary, as ``redaction._HL7_SEGMENT`` reads it
#: before its "|". Group 1 is the ID.
_MEMBER_SEGMENT_ID = re.compile(r"(?:\A|[.\-])([A-Z][A-Z0-9]{2})\Z")
#: The two token shapes of ``redaction._NAME_RUN``, a capital then lower case, or all capitals.
_MEMBER_NAME_TOKEN = re.compile(r"[A-Z][a-z]+|[A-Z]{2,}")
#: What :func:`_masked_word` writes for an ASCII letter, a digit, and a hex escape's two
#: characters after a "%".
_MEMBER_MASK = "x"
_MEMBER_PIECE = re.compile(r"([.\-])")
_MEMBER_NON_ASCII = re.compile(r"[^\x00-\x7f]")
_MEMBER_HEX_ESCAPE = re.compile(r"[0-9A-Fa-f]{2}")
_ASCII_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_MEMBER_ALNUM_MASK = str.maketrans(_ASCII_LETTERS + "0123456789", "x" * 52 + "0" * 10)
_MEMBER_HEX_MASK = str.maketrans("ABCDEFabcdef0123456789", "A" * 12 + "0" * 10)


def _masked_word(word: str, after_percent: bool = False) -> str:
    """``word`` masked character for character: each ASCII letter becomes ``x`` and each digit
    ``0``, any other character but "_", "." and "-" becomes "_", and those three stay. A piece
    between "." or "-" in either token shape of the PHI pass's name run keeps its capitals as ``X``.
    Right after a "%", the two characters of a hex escape stay hex (``%3B`` is ``%0A``), so the
    escape a label start reads after stays one.

    A digit stays a digit because the PHI pass reads one: under a JSON ``name`` a value holding a
    digit is kept as an operator's, so ``"name":;sslpassword=%3B`` masked to ``%xx`` was hidden by
    the write-time chain where ``origin/main`` left it whole for the bundle, which then hid the
    text after it too.

    The mask keeps the word's LENGTH and the class of each character, so every later pass that
    counts or classes characters reads it as it read the word. Each of these printed a value
    ``origin/main`` hid (BACKLOG #5030): a mask longer than the word (``05`` as ``redacted``) made
    ``%5E05/05/1980/`` a run the bundle's long-base64 sweep took, with the ``5E`` of ``%5E`` that a
    later PHI pass counts; a mask shorter than the word let a run that the control-character
    filter later joined (the escape it writes for a form feed, before it) fall under the sweep's 24 characters; a word
    whose "_" or non-ASCII letter ended the bundle marker's base64 run, masked to letters, let the
    bundle's ``_MFB64`` read on over the next marker; and ``Jane Doe`` in lower case was no name
    run, so the PHI pass no longer replaced it and joined the tokens either side into one field
    run it hid whole."""
    escape = _MEMBER_HEX_ESCAPE.match(word) if after_percent else None
    head = escape.group().translate(_MEMBER_HEX_MASK) if escape is not None else ""
    pieces = _MEMBER_PIECE.split(_MEMBER_NON_ASCII.sub("_", word[len(head) :]))
    for i in range(0, len(pieces), 2):
        piece = pieces[i]
        if _MEMBER_NAME_TOKEN.fullmatch(piece) is not None:
            pieces[i] = "".join("X" if c.isupper() else _MEMBER_MASK for c in piece)
        else:
            pieces[i] = piece.translate(_MEMBER_ALNUM_MASK)
    return head + "".join(pieces)


def _kept_word(text: str, word: str, end: int) -> bool:
    """Whether a later pass reads ``word``, which ends at ``end`` in ``text``, as a label or a scheme
    word, so the mask must leave it."""
    if _MEMBER_KEEP.search(word) is None:
        return False
    tail = _MEMBER_LABEL_TAIL.match(text, end)
    if tail is not None and (tail.group(1) != "#" or _MEMBER_MRN_WORD.search(word) is not None):
        return True
    # A "#" after spaces does not end the scheme-word rule: ``Bearer #`` is still a scheme word
    # before a space, and a later bearer pass reads it there.
    return text[end : end + 1].isspace() and _MEMBER_SPACED_WORD.search(word) is not None


def _mask_member_value(text: str, start: int, end: int) -> str:
    """``text[start:end]``, a member's value, with each WORD masked by :func:`_masked_word` except
    what a later pass reads, and every other character kept in place. See
    :data:`_CONNECTION_STRING_MEMBER` for why. The tests for what follows a word read the whole
    text, past the value's end."""
    out: list[str] = []
    pos = start
    for m in _MEMBER_VALUE_UNIT.finditer(text, start, end):
        word = m.group(1)
        if word is None:
            continue
        word_start, word_end = m.span()
        out.append(text[pos:word_start])
        pos = word_end
        segment = _MEMBER_SEGMENT_ID.search(word)
        if _kept_word(text, word, word_end):
            out.append(word)
        elif segment is not None and text.startswith("|", word_end):
            # The ID stays for the segment pattern; a prefix before its "." or "-" is masked.
            out.append(_masked_word(word[: segment.start(1)]) + segment.group(1))
        else:
            out.append(_masked_word(word, word_start > 0 and text[word_start - 1] == "%"))
    out.append(text[pos:end])
    return "".join(out)


def _mask_member(m: re.Match[str]) -> str:
    """The replacement for a :data:`_CONNECTION_STRING_MEMBER` match: the ``;<key>=`` kept, and the
    value's words masked (BACKLOG #5030). The support bundle runs this one function with this one
    pattern, so the two surfaces cannot drift apart."""
    start, end = m.span(2)
    return f"{m.group(1)}={_mask_member_value(m.string, start, end)}"


def _keep_label(m: re.Match[str], placeholder: str) -> str:
    """Replace a ``<label>=<value>`` match, keeping the label so a reader sees WHICH credential was
    there, and never the value. Group 1 is the label in every pattern that uses this."""
    return f"{m.group(1)}={placeholder}{_braced_tail(m)}"


def _braced_tail(m: re.Match[str]) -> str:
    """The ``braced_tail`` of a match that took a braced label after its value, masked by
    :func:`_mask_member_value`, or "" when it took none. :data:`_BRACED_RUN_ON` says why the tail is
    written back masked rather than dropped, and why with that mask. A pattern without the group
    gets "", so a rebuilt pattern without the run-on still works here."""
    try:
        start, end = m.span("braced_tail")
    except IndexError:
        return ""
    return "" if start < 0 else _mask_member_value(m.string, start, end)


# --- ADMISSION GATING: what makes a per-record credential pass affordable --------------------------
#
# THE INVARIANT, and it is what makes gating safe rather than merely fast: a pattern whose label
# alternates come from tuple W cannot match text whose :func:`_gate_fold` contains none of W's
# members. So skipping that pattern when no member is present cannot narrow what the pass sees. That
# is a property of building the gate and the pattern from ONE tuple, PLUS one claim about the regex
# engine: that :data:`_GATE_FOLDS` holds every character ``(?i)`` reads as an ASCII letter. That
# claim is measured, not argued; see the table. ``test_the_hint_gates_never_change_the_result``
# compares the gated and ungated passes over every fixture rather than trusting either half.
#
# A FOLDED SUBSTRING TEST, NOT A COMPILED ALTERNATION, and the difference is the whole cost of
# this module. A ``(?i)`` alternation defeats sre's literal-prefix optimisation, so the engine
# trial-matches every branch at every start position: measured on a plain 67-char line, the union
# alternation cost 5.07 us and was 100 percent of what this module added, while one ``casefold()``
# plus ``in`` tests costs 0.40 us. On a real credential line, folding ONCE and reusing the folded
# string for all six per-pass gates took the pass from 8.21 us to 2.93 us.
#
# NEITHER ``lower`` NOR ``casefold`` IS ENOUGH ON ITS OWN, AND IT IS THE TEXT SIDE THAT CARRIES
# THAT. The patterns are ``(?i)`` and Python's case-insensitive matching folds beyond ASCII. ``lower``
# leaves U+017F and U+212A alone, though ``(?i)s`` and ``(?i)k`` match them;
# ``test_the_gate_folds_the_way_the_patterns_match_not_the_way_str_lower_does`` pins that with the
# leaked credential as the control. ``casefold`` handles those two but not U+0130 or U+0131. So
# :data:`_GATE_FOLDS` maps the characters first, and ``casefold`` after it is now defence in depth
# for the two the table also carries. The characters and the leak they closed are stated on the table.
#
# FOLDING THE WORDS IS A NO-OP TODAY and goes through :func:`_gate_fold` only so the two sides cannot
# diverge: every member of every tuple above is ASCII, so ``lower``, ``casefold`` and the gate fold
# agree on all of them. Stated because a mutation run scored the word-side fold as unkillable, which
# is correct and would otherwise read as missing coverage.
#
# ``_MEFOR_SECRET`` is the exception in the other direction: it is case-SENSITIVE, so a folded gate
# merely admits lines it will not match, which is free.


#: Non-ASCII characters that Python's case-insensitive matching treats as an ASCII letter, with that
#: letter: at least every one the scan below finds on the interpreter the suite runs on.
#: :func:`_gate_fold` maps each to its letter before ``casefold``, so the folded text holds a keyword
#: wherever a ``(?i)`` pattern could match one.
#:
#: WHY ``casefold`` NEEDS THIS. ``(?i)i`` matches U+0130 and U+0131, but ``casefold`` turns U+0130
#: into "i" plus a combining dot (U+0307) and leaves U+0131 alone. Neither gives a plain "i", so a
#: label such as ``API_KEY=`` spelled with either one was refused by the gate before any pattern ran.
#: Its value then passed the write-time filters verbatim, which would print the credential on first
#: deployment. ``test_the_old_gate_fails_the_fold_character_test`` reproduces the leak with this table
#: emptied.
#:
#: MEASURED, NOT RECALLED. Scanning every code point above ASCII against ``(?i)[a-z]`` on this
#: interpreter finds at least these four, and
#: ``test_the_gate_fold_table_holds_every_character_case_insensitive_matching_reads_as_a_letter``
#: re-runs that scan and fails on any character this table lacks. That check covers the interpreter
#: the suite runs on; a newer Unicode database is checked only when the suite runs under it. Two of
#: the four ``casefold`` already handles (U+017F and U+212A fold to "s" and "k"). They are listed
#: anyway, so the table is the whole measured set rather than the part one fold happens to miss.
#:
#: Built with ``chr()`` so no encoding layer between here and disk can change a character.
_GATE_FOLDS: tuple[tuple[str, str], ...] = (
    (chr(0x0130), "i"),  # LATIN CAPITAL LETTER I WITH DOT ABOVE: casefolds to "i" + U+0307
    (chr(0x0131), "i"),  # LATIN SMALL LETTER DOTLESS I: casefold leaves it unchanged
    (chr(0x017F), "s"),  # LATIN SMALL LETTER LONG S
    (chr(0x212A), "k"),  # KELVIN SIGN
)


def _gate_fold(text: str) -> str:
    """``text`` folded for the admission gate: each :data:`_GATE_FOLDS` character mapped to its ASCII
    letter, then ``casefold``. An ASCII line skips the mapping, and ``str.isascii`` is a flag read in
    CPython, so the common record pays nothing for it."""
    if not text.isascii():
        for char, letter in _GATE_FOLDS:
            text = text.replace(char, letter)
    return text.casefold()


def _folded(words: tuple[str, ...]) -> tuple[str, ...]:
    """``words`` through :func:`_gate_fold`, for substring admission against gate-folded text."""
    return tuple(_gate_fold(w) for w in words)


_CREDENTIAL_HINT = _folded(_CREDENTIAL_WORDS)
_TOKEN_HINT = _folded(_TOKEN_WORDS)
_MEMBER_EXTRA_HINT = _folded(_MEMBER_EXTRA_WORDS)
_KEY_MATERIAL_HINT = _folded(_KEY_MATERIAL_WORDS)
_SCHEME_HINT = _folded(("bearer",))
_ENV_HINT = _folded((_ENV_PREFIX,))
_DSN_HINT = (_DSN_MARKER,)

#: The union of every per-pass gate, reduced by SUBSUMPTION: a word containing another word of the set
#: is dropped, because any text holding it holds the shorter one too. Derived, so it cannot drift from
#: the tuples above -- ``pass`` subsumes ``password``/``passwd``/``passphrase``, ``encryption_key``
#: subsumes ``encryption_keys_retired``, ``api_key`` subsumes ``intake_api_key_next``. One scan of 15
#: members instead of 20, and it rejects the overwhelmingly common record: the one carrying no
#: credential word at all. The member pass's own words (:data:`_MEMBER_EXTRA_HINT`) are in it too,
#: so a word added there and nowhere else still admits the record (BACKLOG #5030).
_ANY_HINT = tuple(
    sorted(
        {
            word
            for word in {
                *_CREDENTIAL_HINT,
                *_TOKEN_HINT,
                *_MEMBER_EXTRA_HINT,
                *_KEY_MATERIAL_HINT,
                *_ENV_HINT,
                *_DSN_HINT,
            }
            if not any(
                other != word and other in word
                for other in {
                    *_CREDENTIAL_HINT,
                    *_TOKEN_HINT,
                    *_MEMBER_EXTRA_HINT,
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

    Idempotent on ordinary lines, which matters because a record dispatched to stdout *and* the off-box
    forwarder is filtered once per handler: the placeholder carries no credential word, no ``MEFOR_``
    prefix and no ``://``, so a second pass finds a label whose value is already the placeholder and
    rewrites it to itself. NOT ON EVERY LINE, and it never was. Where one label's value runs into
    another, a second pass can hide more of the line than the first did. Re-measured 2026-10-05 over
    the 40,000 seeded lines of ``_structured_lines(40000)`` in
    ``tests/test_log_redaction_secret_domain.py``, a corpus dense with labels: 5,350 changed on a
    second pass, against 4,394 under that file's ``_pre_change_patterns``. A second pass can only
    replace text, never restore it, so two handlers can differ only in how much one hides. The reject
    path returns the SAME object, so a caller's ``scrubbed != message`` takes CPython's
    pointer-identity fast path."""
    folded = _gate_fold(text)
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
    like one. Some callers WARN rather than refuse for that reason. At least the HTTP family's
    ``verify_tls = false`` and off-box cleartext credential rules refuse on a match, with no escape,
    and accept that a name that only looks like one refuses too (vault BACKLOG #3230, #3533).

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


#: The characters that start a ``name=value`` segment for :func:`has_credential_like_segment`: a
#: query (``?``, ``&``), a fragment (``#``), and ``;``, which Rack, servlet path parameters
#: (``;jsessionid=``) and JDBC strings (``;password=``) all split on.
_SEGMENT_SEPARATORS = re.compile(r"[?&#;]")


def has_credential_like_segment(text: str) -> bool:
    """Whether any ``name=value`` segment of ``text``, split at every ``?``, ``&``, ``#`` and ``;``,
    has a name that looks like a credential, by the same name test as :func:`credential_query_params`.

    A deliberately coarser reading than the detector's, for a display rule that must fail closed:
    it also reads a fragment, a second ``?``, a ``;``-split segment and the first segment of a value
    with no separator at all (``token=...``). The detector, which feeds the construction warning,
    ``check`` and the posture entry, is unchanged by decision and reads only the ``&``-split query
    ``urlsplit`` finds; so a ``;`` or second-``?`` credential is withheld in the views and is NOT
    warned about. That gap is recorded rather than closed here.

    A name drops tab, CR and LF BEFORE it is percent-decoded, as ``urlsplit`` drops them before
    ``parse_qsl`` decodes: ``api%5<TAB>Fkey`` decodes to ``api_key``. Linear in ``text``; it walks
    the separators lazily and returns at the first match."""
    import itertools  # noqa: PLC0415 -- see credential_query_params
    import urllib.parse  # noqa: PLC0415 -- see credential_query_params

    start = 0
    for match in itertools.chain(_SEGMENT_SEPARATORS.finditer(text), (None,)):
        end = len(text) if match is None else match.start()
        name, equals, _value = text[start:end].partition("=")
        if equals:
            name = name.replace("\t", "").replace("\r", "").replace("\n", "")
            if _is_credential_param(urllib.parse.unquote_plus(name)):
                return True
        if match is not None:
            start = match.end()
    return False


def _run(text: str, placeholder: str, folded: str | None) -> str:
    """The pass itself. Straight-line rather than a table, so a test monkeypatching one pattern on this
    module reaches the object this function reads -- a table would hold the pre-patch pattern by
    value and the mutation fixture would silently mutate nothing."""
    if _admits(folded, _ENV_HINT):
        text = _MEFOR_SECRET.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _TOKEN_HINT):
        text = _BEARER.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _SCHEME_HINT):
        text = _AUTH_SCHEME.sub(lambda m: f"{m.group(1)} {placeholder}{_braced_tail(m)}", text)
    if _admits(folded, _CREDENTIAL_HINT):
        text = _CREDENTIAL_KV.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _KEY_MATERIAL_HINT):
        text = _KEY_MATERIAL.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _DSN_HINT):
        text = _DSN_PASSWORD.sub(lambda m: f"{m.group(1)}:{placeholder}@", text)
    # LAST, over what every pass above left, masking words only (BACKLOG #5030; see the pattern).
    if ";" in text and (_admits(folded, _CREDENTIAL_HINT) or _admits(folded, _MEMBER_EXTRA_HINT)):
        text = _CONNECTION_STRING_MEMBER.sub(_mask_member, text)
    return text
