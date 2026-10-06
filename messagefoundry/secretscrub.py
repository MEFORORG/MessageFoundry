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
# written down at the end of this comment. ACROSS PASSES
# IT CAN, and the differential test measures how often: the text a stop leaves behind is not the text
# the old class left, so a later pass over it can end somewhere else. A stray quote or a later label
# used to cut a later pass short, and now does not. It is rare, and most such lines also hide a value
# the old patterns printed, but not all of them; the count and the shapes are on
# ``test_the_change_prints_no_value_the_pre_change_patterns_hid``. With only an OPENING quote
# required, ``token=x;password="private_key: pk`` printed "pk": the exposed label's plain class then
# swallowed the next label instead. A label followed by a BRACE or a plain value gets no stop, because
# the class used to run on past those, and stopping there would print what it used to hide.
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
# right after the placeholder. And a keyword spelled with a fold character such as U+017F as its FIRST
# letter is not checked where the run class does not fold, because the walk reads that character as a
# separator and checks only from the next letter. That is ``_MEFOR_SECRET`` here, the one pattern in
# this module compiled without ``(?i)``, and in ``support/redact.py`` every stopped pattern but
# ``_AUTH_SCHEME``: there ``_MEFOR_SECRET`` has no fold, and ``_BEARER``, ``_CREDENTIAL_KV`` and
# ``_KEY_MATERIAL`` fold their keywords alone. Both copies of ``_AUTH_SCHEME`` fold globally, so their
# run class folds and the check runs.
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
# not the only one: the same cascade lands in ``_KEY_MATERIAL`` and ``_CREDENTIAL_KV`` on lines with
# no ``MEFOR_`` label at all. Some of these lines also hide a value the old patterns printed, but by
# accident, so they belong here and not with the trade above. At least these shapes:
#
# * a stop before a later quoted label whose value the run-on refuses, for a non-ASCII character or a
#   label in it: ``password='pw-A1 MEFOR_A=x;private_key='pk<e-acute>-B1 pk-B2'`` prints both pk
#   values;
# * a later ``MEFOR_`` label the old class swallowed now matching, and taking its own closer:
#   ``password='pw-A1 pw-A2;MEFOR_A=x;MEFOR_B='pw-B1'`` prints " pw-A2";
# * a stop that splits one ``MEFOR_`` value, so a later ``MEFOR_`` label eats the space that ended an
#   earlier plain value: ``secret=pw-A0@MEFOR_B_PW=pw-A2;MEFOR_X = 'pw-A4'@x.password='pw-A6``
#   prints "pw-A6";
# * ``_KEY_MATERIAL`` running over a later key label, with no ``MEFOR_`` label on the line.
#   ``_CREDENTIAL_KV`` now takes a quoted value whole, closer and all, where an old pass left a quote
#   that ended ``_KEY_MATERIAL``'s plain value. That value now runs on over the later key label, which
#   gets no stop because its own value is not a closed, guarded quote.
#   ``connect failed encryption_key=token=password='hunter2',private_key='abc def=='`` prints
#   "abc def==", where the old patterns printed " def==";
#   ``cfg private_key=pass=credential="c1"|private_key'=pk-SECRET-9`` prints "pk-SECRET-9"; and
#   ``private_key=password='vq0 token=''|encryption_key='vq2`` prints "vq2";
# * a stop that takes a ``MEFOR_`` match away: ``pass='MEFOR_1:pass'="vq4"'`` prints "vq4". The old
#   ``_MEFOR_SECRET`` ate ``pass'``, so the outer quoted value closed on the last quote. Now that
#   value's first run is a quoted label, ``_MEFOR_SECRET`` does not match, and the outer value closes
#   on the quote it left;
# * ``_MEFOR_SECRET``'s guarded quoted value matching where the old class did not:
#   ``pass=",pw-IN-3 MEFOR_A"=' mv-4'`` prints ",pw-IN-3". The label takes the double quote that
#   closed the outer value, so that value has no closer and nothing matches it.
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
# value; the residuals at ``_NOT_BEFORE_QUOTED_LABEL`` give the measured shapes.
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
#: scheme word after a token label.
_LABEL_HEAD = (
    r"(?=(?i:[" + _KEYWORD_INITIALS + r"]))"
    r"(?:(?i:" + _alternation(_CREDENTIAL_WORDS + _KEY_MATERIAL_WORDS) + r")\b['\"]?\s*+[:=]\s*+"
    r"|(?i:" + _alternation(_TOKEN_WORDS) + r")\b\s*+[:=]\s*+(?:(?i:bearer|basic|digest)\s++)?"
    r")"
)
_MEFOR_LABEL_HEAD = r"\b(?-i:" + re.escape(_ENV_PREFIX) + r"[A-Z0-9_]++)\b['\"]?\s*+[:=]\s*+"
_QUOTED_LABEL = _LABEL_HEAD + r"(?:" + _GUARDED_QUOTED_VALUE + r")"
_MEFOR_QUOTED_LABEL = _MEFOR_LABEL_HEAD + r"(?:" + _GUARDED_QUOTED_VALUE + r")"
#: Checked before a value's FIRST run.
_NOT_AT_QUOTED_LABEL = r"(?!" + _QUOTED_LABEL + r"|" + _MEFOR_QUOTED_LABEL + r")"
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
    + _MEFOR_QUOTED_LABEL
    + r")"
)


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
#: The outer walk: up to the next quote of one kind, or to a label whose value opens with one.
_SQ_RUN_ON_WALK = r"(?:[^'\r\nA-Za-z0-9]|(?!" + _RUN_ON_LABEL + r"')[A-Za-z0-9]++)*+"
_DQ_RUN_ON_WALK = r"(?:[^\"\r\nA-Za-z0-9]|(?!" + _RUN_ON_LABEL + r"\")[A-Za-z0-9]++)*+"
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
# old patterns hid it. The residuals at ``_NOT_BEFORE_QUOTED_LABEL`` give the measured shapes.
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
# line is measured once, in the module docstring.
_NO_QUOTED_LABEL_AFTER = r"(?!\s*+[:='\"]|\s++(?i:bearer|basic|digest)\s)"

# The plain value classes. Each pattern keeps the terminator set it always had, stated once here and
# spliced into all three places a class needs it: the fast path, the first run and every later run.
_PLAIN_TERMINATORS = r"\s'\""  # _MEFOR_SECRET, _BEARER
_KV_TERMINATORS = r"\s'\";,&"  # _CREDENTIAL_KV
_KEY_TERMINATORS = r"\s'\";&"  # _KEY_MATERIAL
_SCHEME_TERMINATORS = r"\s'\",;"  # _AUTH_SCHEME
_PLAIN_VALUE = (
    rf"['\"]?(?:[^{_PLAIN_TERMINATORS}]++{_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:{_NOT_AT_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_PLAIN_TERMINATORS}])"
    rf"(?:{_NOT_BEFORE_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_PLAIN_TERMINATORS}])*+)"
)
_PLAIN_KV_VALUE = (
    rf"['\"]?(?:[^{_KV_TERMINATORS}]++{_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:{_NOT_AT_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_KV_TERMINATORS}])"
    rf"(?:{_NOT_BEFORE_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_KV_TERMINATORS}])*+)"
)
_PLAIN_KEY_VALUE = (
    rf"['\"]?(?:[^{_KEY_TERMINATORS}]++{_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:{_NOT_AT_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_KEY_TERMINATORS}])"
    rf"(?:{_NOT_BEFORE_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_KEY_TERMINATORS}])*+)"
)
_PLAIN_SCHEME_VALUE = (
    rf"['\"]?(?:[^{_SCHEME_TERMINATORS}]++{_NO_QUOTED_LABEL_AFTER}"
    rf"|(?:{_NOT_AT_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_SCHEME_TERMINATORS}])"
    rf"(?:{_NOT_BEFORE_QUOTED_LABEL}[A-Za-z0-9]++|[^A-Za-z0-9{_SCHEME_TERMINATORS}])*+)"
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
_BEARER = re.compile(
    r"(?i)\b(" + _LABEL_PREFIX + r"(?:" + _alternation(_TOKEN_WORDS) + r"))\b"
    r"\s*[:=]\s*(?:(?:bearer|basic|digest)\s+)?"
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
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer)\s+(?=['\"]?[^\s'\",;]{4})" + _PLAIN_SCHEME_VALUE)

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
# * A ``MEFOR_*`` value holding a connection string with a braced password, as in
#   ``MEFOR_STORE_DSN=Server=h;PWD={p w}``, still prints " w}". The stop does not fire before a
#   braced value, for the reason given at :data:`_NOT_BEFORE_QUOTED_LABEL`.
# Each of the four residuals above, from the unclosed quote on, printed the same text before BACKLOG
# #1685's remainder; none is new.
_CREDENTIAL_KV = re.compile(
    r"(?i)\b(" + _LABEL_PREFIX + r"(?:" + _alternation(_CREDENTIAL_WORDS) + r"))\b"
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
    r"(?i)\b(" + _LABEL_PREFIX + r"(?:" + _alternation(_KEY_MATERIAL_WORDS) + r"))\b"
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


def _keep_label(m: re.Match[str], placeholder: str) -> str:
    """Replace a ``<label>=<value>`` match, keeping the label so a reader sees WHICH credential was
    there, and never the value. Group 1 is the label in every pattern that uses this."""
    return f"{m.group(1)}={placeholder}"


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
_KEY_MATERIAL_HINT = _folded(_KEY_MATERIAL_WORDS)
_SCHEME_HINT = _folded(("bearer",))
_ENV_HINT = _folded((_ENV_PREFIX,))
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
        text = _AUTH_SCHEME.sub(lambda m: f"{m.group(1)} {placeholder}", text)
    if _admits(folded, _CREDENTIAL_HINT):
        text = _CREDENTIAL_KV.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _KEY_MATERIAL_HINT):
        text = _KEY_MATERIAL.sub(lambda m: _keep_label(m, placeholder), text)
    if _admits(folded, _DSN_HINT):
        text = _DSN_PASSWORD.sub(lambda m: f"{m.group(1)}:{placeholder}@", text)
    return text
