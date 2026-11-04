# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A credential the generic ODBC dialect sends WITHOUT braces is hidden whole on every log surface
(BACKLOG #5030).

``transports/database.py`` sends a password plain for a driver it has not measured, and every
``odbc_params`` value plain, ``sslpassword`` among them. Such a value may hold a space, ",", "&" and,
for a password, "=". The plain value class of the log scrubbers stopped at the first three, so an
echoed connection string printed the tail of the password, and ``sslpassword`` printed whole, since
"ssl" glued to "password" leaves no word boundary for the label. The connection string here is the
builder's own output, so the shape tested is the shape the engine would send."""

from __future__ import annotations

import logging
import random
import re
import time
from collections.abc import Callable

import pytest

from messagefoundry import logging_setup, redaction, secretscrub
from messagefoundry.logging_setup import CredentialScrubFilter, _install_phi_filters
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support import redact as bundle_redact
from messagefoundry.support.redact import redact_log_line
from messagefoundry.transports.database import _build_odbc_dsn
from tests._phi_log_capture import filtered_sink

# Synthetic. The password holds a space, ",", "&" and "="; an odbc_params value may not hold "=".
_PASSWORD = "Qv7m kX4r,Pw9z&mT3y=Yb8n"
_SSL_PASSWORD = "Sp4q wR2t,Lk8d&Hn6c"
_FRAGMENTS = ("Qv7m", "kX4r", "Pw9z", "mT3y", "Yb8n", "Sp4q", "wR2t", "Lk8d", "Hn6c")


def _dsn() -> str:
    return _build_odbc_dsn(
        {
            "dialect": "generic",
            "odbc_driver": "Acme Synthetic ODBC Driver",
            "server": "db1.example",
            "database": "mf",
            "username": "svc",
            "password": _PASSWORD,
            "odbc_params": {"sslmode": "require", "sslpassword": _SSL_PASSWORD},
        },
        connection="OB_SYNTH_DB",
    )


_LOGGER = "mefor.test.connection_string_member"


def _through_a_configured_handler(line: str) -> str:
    """``line`` logged through a sink carrying the production filters and formatter."""
    with filtered_sink(_LOGGER) as sink:
        logging.getLogger(_LOGGER).error("connect failed: %s", line)
    return sink.text


def _in_a_traceback(line: str) -> str:
    """``line`` as the message of an exception logged with its traceback, the realistic vector."""
    with filtered_sink(_LOGGER) as sink:
        try:
            raise RuntimeError(f"[08001] driver could not connect with '{line}'")
        except RuntimeError:
            logging.getLogger(_LOGGER).exception("database connect failed")
    return sink.text


def _credential_filter_alone(line: str) -> str:
    record = logging.LogRecord("mefor.test", logging.ERROR, __file__, 1, "%s", (line,), None)
    CredentialScrubFilter().filter(record)
    return record.getMessage()


_SURFACES: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("scrub_credentials", scrub_credentials),
    ("CredentialScrubFilter", _credential_filter_alone),
    ("configured handler", _through_a_configured_handler),
    ("traceback", _in_a_traceback),
    ("redact_log_line", redact_log_line),
)


def test_the_builder_sends_both_credentials_unbraced() -> None:
    """The precondition. Were either braced, the braced forms would hide it and the tests below would
    pass on them, proving nothing about the plain value."""
    dsn = _dsn()
    assert f";PWD={_PASSWORD};" in dsn + ";"
    assert f";sslpassword={_SSL_PASSWORD}" in dsn


@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=[name for name, _ in _SURFACES])
def test_no_fragment_of_an_unbraced_credential_reaches_a_log_surface(
    surface: str, apply: Callable[[str], str]
) -> None:
    out = apply(_dsn())
    survivors = [fragment for fragment in _FRAGMENTS if fragment in out]
    assert not survivors, f"{surface}: {survivors} survived -- {out!r}"
    # The labels stay, so a reader still sees which credential it was, and the members around them
    # are not swallowed.
    for kept in ("PWD=", "sslpassword=", "SERVER=db1.example", "DATABASE=mf", "UID=svc"):
        assert kept in out, f"{surface}: {kept!r} was lost -- {out!r}"


@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=[name for name, _ in _SURFACES])
def test_a_password_last_in_a_quoted_echo_stops_at_the_closing_quote(
    surface: str, apply: Callable[[str], str]
) -> None:
    """With no member after it, the value ends at the quote that closes the echo, so the rest of the
    line keeps its text."""
    line = f"'DRIVER={{Acme}};SERVER=db1.example;PWD={_PASSWORD}' refused, retry in 5s"
    out = apply(line)
    assert not [fragment for fragment in _FRAGMENTS if fragment in out], out
    assert "retry in 5s" in out, out


#: Shapes a review of the first draft measured printing a value ``origin/main`` hid, when the member
#: rule was a branch of ``_CREDENTIAL_KV`` tried at the label's own position. Each planted fragment
#: is ``<letter><digit>q``. As its own pass, run last, the rule only adds redaction to what the
#: other passes left, so none of these may print anywhere.
_SHAPES_THE_FIRST_DRAFT_PRINTED = (
    # A later label written with a quoted key.
    ";PWD=a1q,password'=b2q c3q tail",
    ';PWD=a1q,password":"b2q c3q;d4q" tail',
    ";sslpassword=a1q,private_key'='b2q c3q' tail",
    ";pwd=a1q password' :'b2q c3q'",
    # A "}" that _KEY_MATERIAL needs, and an "@" that _DSN_PASSWORD needs, after the ";".
    "encryption_key={a1q b2q;xpass=c3q} done",
    "dial postgres://svc:a1q;sslpwd=b2q@db.example/mf failed",
    # A value of only spaces before a line break, which the label pattern's \s* crosses.
    "SERVER=h;PWD= \nb2q rest",
    "SERVER=h;Password=\t\r\nc3q",
    ";pwd=a1q password=\nb2q",
    # A "://" inside a value the builder sends plain.
    "DRIVER={X};SERVER=h;PWD=a1q b2q://c3q;sslmode=require;sslpassword=d4q e5q://f6q;",
    # A brace the walk would stop inside.
    ";sslpassword={a1q;b2q} c3q;PORT=1",
)


def _planted(line: str) -> list[str]:
    return re.findall(r"[a-f][0-9]q", line)


@pytest.mark.parametrize("line", _SHAPES_THE_FIRST_DRAFT_PRINTED)
def test_no_planted_value_reaches_a_log_surface(line: str) -> None:
    for surface, apply in _SURFACES:
        out = apply(line)
        printed = [f for f in _planted(line) if f in out]
        assert not printed, f"{surface}: {printed} printed -- {out!r}"


@pytest.mark.parametrize(
    "line",
    [
        # The bundle's own credential copy runs before its PHI pass. Had this rule run there, it
        # would take the "&" and leave the token one separator short of a field run.
        "connect failed: DOE^JOHN;pwd=a1q&b2q",
        # An encoded HL7 run is switched off by a credential shape; ";Bypass=" must not be one.
        "lookup DOE%5EJOHN%5EQ%5EMRN12345 failed;Bypass=1",
    ],
)
def test_the_phi_passes_see_the_text_they_saw_before(line: str) -> None:
    for surface, apply in (
        ("configured handler", _through_a_configured_handler),
        ("redact_log_line", redact_log_line),
    ):
        out = apply(line)
        assert "DOE" not in out and "JOHN" not in out, f"{surface}: {out!r}"


#: Lines a review measured printing, on a SECOND redaction, a value ``origin/main`` hid, while the
#: member pass replaced a whole value with the placeholder (BACKLOG #5030). Each loses something a
#: later pass reads: a separator the PHI pass counts ("&", "^", "%5E", "%26"), a later label
#: (``state=``, ``?code=``, ``Token=``, ``MEFOR_X=``), a segment ID, a DICOM element, the userinfo
#: opener, or the length of a base64 run. The word mask keeps each, so none may print.
_SHAPES_A_SECOND_PASS_PRINTED = (
    ";sslpassword=%2Cpassword=&state=,;f6q",
    'password":;xpass=&state=[REDACTED];}%7Cb2q',
    ";xpass=&state=postgres://svc:;c3qc3q;Token=",
    ";xpass=:?code=;xpass=;f6q",
    ";xpass=MEFOR_X=b2q^;Token='\"e5qa1q:",
    "|\n<redacted>d4q;sslpassword=e5qDOE^JOHN};Token=;PWD=f6q",
    'c3q@db^\na1q;PWD=private_key={&state="',
    ".d4q%26\n;xpass=%5E",
    ";sslpassword=\\Token='\r\nc3q",
    "a1q;xpass=PID|1||\n&state=' d4q%7C{b2qpassword=19800505",
    "&<redacted>19800505;xpass=nonnumeric port: '\nc3q%5E.@hpassword=MEFOR_X=",
    "&b2qf6q;AccessToken=%5E,QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB/secret: xprivate_key=",
)

_NEVER = re.compile(r"(?!)")
_UNIT = secretscrub._MEMBER_VALUE_UNIT.pattern


def _keep_without(*words: str) -> re.Pattern[str]:
    kept = [w for w in secretscrub._MEMBER_KEEP_WORDS if w not in words]
    return re.compile("|".join(re.escape(w) for w in kept), re.IGNORECASE)


#: Each rule of the word mask, switched off, with a shape that then prints a value the baseline hid
#: on some later redaction. So every rule is there for a measured reason, and a test that passes
#: with the rule on is evidence.
_RULE_CONTROLS = (
    ("kept credential and query words", "_MEMBER_KEEP", _NEVER, ";xpass=:?code=;xpass=;f6q"),
    (
        "kept PHI words",
        "_MEMBER_KEEP",
        _keep_without(
            "mrn", "name", "address", "0010", "patient", "medicalrecordlocator",
            "responsibleperson",
        ),
        'e5q;AccessToken="name": %26\na1qcode=d4qe5q123-45-6789[redacted]',
    ),
    (
        "label tail",
        "_MEMBER_LABEL_TAIL",
        _NEVER,
        ';sslpassword=postgres://svc:id_token="\r\n~e5q',
    ),
    (
        "scheme word before a space",
        "_MEMBER_SPACED_WORD",
        _NEVER,
        ";AccessToken=Bearer <redacted>\na1qencryption_key={ x%26session=DOE^JOHN",
    ),
    (
        "long base64 run",
        "_MEMBER_LONG_B64",
        _NEVER,
        "&b2qf6q;AccessToken=%5E,QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB/secret: xprivate_key=",
    ),
    (
        "segment ID",
        "_MEMBER_SEGMENT_ID",
        _NEVER,
        "a1q;xpass=PID|1||\n&state=' d4q%7C{b2qpassword=19800505",
    ),
    (
        "DICOM tag",
        "_MEMBER_VALUE_UNIT",
        re.compile(_UNIT.replace(r"|\([0-9A-Fa-f]{4}, ?[0-9A-Fa-f]{4}\)", "")),
        ",a1q;AccessToken=(0010,1000)=\na1qb2qMRN\t",
    ),
    (
        "userinfo opener",
        "_MEMBER_VALUE_UNIT",
        re.compile(_UNIT.replace("|nonnumeric port: ", "")),
        "&<redacted>19800505;xpass=nonnumeric port: '\nc3q%5E.@hpassword=MEFOR_X=",
    ),
    (
        "encoded HL7 separator",
        "_MEMBER_VALUE_UNIT",
        re.compile(_UNIT.replace("|%(?:7[CcEe]|5[Ee]|26)", "")),
        ".d4q%26\n;xpass=%5E",
    ),
)  # fmt: skip

#: Fragments for the seeded differential below: the labels and separators of every pass, the
#: HL7, DICOM and userinfo shapes a later PHI pass reads, and planted values ``<letter><digit>q``.
_DIFFERENTIAL_PIECES = (
    ";PWD=", ";sslpassword=", ";xpass=", ";AccessToken=", ";Token=", "password=", "password'=",
    'password":', "secret=", "secret: ", "api_token=", "token=", "private_key=", "encryption_key={",
    "MEFOR_X=", "postgres://svc:", "@db", "%2Cpassword=", "Bearer ", "?code=", "&state=",
    "nonnumeric port: '", "PID|1||", "(0010,1000)", "MRN", "DOE^JOHN", "Jane Doe", "19800505",
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", "'", '"', "{", "}", ";", ",", "&", "=", " ", ":", "\n",
    "\t", "%7C", "%5E", "%26", "|", "^", "/", "a1q", "b2q", "c3q", "d4q", "e5q", "f6q",
    "[REDACTED]", "<redacted>",
)  # fmt: skip


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.out: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.out.append(record.getMessage())


def _through_three_handlers(line: str) -> list[str]:
    """``line`` logged once to three handlers that each carry the production chain. They rewrite the
    one record in place, so the second handler filters what the first left, and the third what the
    second left: the chain applied once, twice and three times."""
    logger = logging.getLogger(f"{_LOGGER}.three")
    propagate, level = logger.propagate, logger.level
    logger.propagate = False
    logger.setLevel(logging.INFO)
    captures = [_Capture() for _ in range(3)]
    for capture in captures:
        _install_phi_filters(capture)
        logger.addHandler(capture)
    try:
        logger.error("%s", line)
    finally:
        for capture in captures:
            logger.removeHandler(capture)
        logger.propagate, logger.level = propagate, level
    return [capture.out[0] for capture in captures]


def _every_redaction_path(line: str) -> dict[str, str]:
    """``line`` through each path that redacts text once or more: a single pass of each surface, the
    chain once, twice and three times, a chain line the bundle reads back from the log, and store
    error text (the bundle's redaction, logged through the chain, read back by the bundle)."""
    once, twice, thrice = _through_three_handlers(line)
    stored = _through_three_handlers(redact_log_line(line))
    return {
        "scrub_credentials": scrub_credentials(line),
        "redact_log_line": redact_log_line(line),
        "chain once": once,
        "chain twice": twice,
        "chain three times": thrice,
        "chain, then bundle": redact_log_line(once),
        "chain twice, then bundle": redact_log_line(twice),
        "store path": redact_log_line(stored[0]),
        "store path, two handlers": redact_log_line(stored[1]),
    }


def _without_member_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take the member pass out of both surfaces, which is what ``origin/main`` runs: the pass is the
    only change these modules carry for BACKLOG #5030."""
    monkeypatch.setattr(secretscrub, "_CONNECTION_STRING_MEMBER", _NEVER)
    monkeypatch.setattr(bundle_redact, "_CONNECTION_STRING_MEMBER", _NEVER)


def _printed_where_the_baseline_hid(
    lines: list[str], with_member: list[dict[str, str]], baseline: list[dict[str, str]]
) -> list[tuple[str, str, str]]:
    found = []
    for line, new, old in zip(lines, with_member, baseline, strict=True):
        for path, out in new.items():
            if any(f in out and f not in old[path] for f in _planted(line)):
                found.append((path, line, out))
    return found


def test_a_second_or_third_redaction_prints_nothing_the_baseline_hid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A differential over every redaction path: each planted value printed WITH the member pass is
    printed without it too, on one pass and on two or three. A draft that replaced the whole value
    passed the one-pass half of this and failed the rest (the shapes above, and 124 to 145 random
    lines of 320,000 on each later path). The commit records the full measurement."""
    rng = random.Random(5030)
    lines = [
        *_SHAPES_THE_FIRST_DRAFT_PRINTED,
        *_SHAPES_A_SECOND_PASS_PRINTED,
        *(shape for *_, shape in _RULE_CONTROLS),
        *(
            "".join(rng.choice(_DIFFERENTIAL_PIECES) for _ in range(rng.randint(3, 14)))
            for _ in range(1500)
        ),
    ]
    with_member = [_every_redaction_path(line) for line in lines]
    with monkeypatch.context() as patched:
        _without_member_pass(patched)
        baseline = [_every_redaction_path(line) for line in lines]
    assert _printed_where_the_baseline_hid(lines, with_member, baseline) == []


def test_the_differential_fails_on_the_whole_value_draft(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the differential above: with each value replaced whole by the placeholder, as
    the draft did, it finds the second-pass shapes, so a pass of the test is evidence."""
    lines = list(_SHAPES_A_SECOND_PASS_PRINTED)
    with monkeypatch.context() as patched:
        _without_member_pass(patched)
        baseline = [_every_redaction_path(line) for line in lines]
    monkeypatch.setattr(secretscrub, "_mask_member_value", lambda _text, _s, _e: "<redacted>")
    whole_value = [_every_redaction_path(line) for line in lines]
    printed = _printed_where_the_baseline_hid(lines, whole_value, baseline)
    # Every shape is in the list because the draft printed it on at least one later path.
    assert {line for _, line, _ in printed} == set(lines)
    assert not [path for path, _, _ in printed if path in ("scrub_credentials", "redact_log_line")]


@pytest.mark.parametrize(
    ("attr", "off", "shape"),
    [control[1:] for control in _RULE_CONTROLS],
    ids=[control[0] for control in _RULE_CONTROLS],
)
def test_each_mask_rule_is_needed(
    monkeypatch: pytest.MonkeyPatch, attr: str, off: re.Pattern[str], shape: str
) -> None:
    """With one rule of the word mask off, its shape prints a value the baseline hid on a later
    redaction; with every rule on, it does not."""
    assert getattr(secretscrub, attr).pattern != off.pattern  # the switch is not a no-op
    with monkeypatch.context() as patched:
        _without_member_pass(patched)
        baseline = [_every_redaction_path(shape)]
    assert _printed_where_the_baseline_hid([shape], [_every_redaction_path(shape)], baseline) == []
    monkeypatch.setattr(secretscrub, attr, off)
    assert _printed_where_the_baseline_hid([shape], [_every_redaction_path(shape)], baseline)


def test_the_member_pattern_spells_the_word_tuples_and_brace_fragments() -> None:
    """The pattern is a literal so the static regex scanner reads it; this holds the literal to its
    sources, and the bundle to the same function, so neither can drift."""
    pattern = secretscrub._CONNECTION_STRING_MEMBER.pattern
    words = re.findall(r"\(\?<=([a-z]+)\)", pattern)
    assert sorted(words) == sorted(secretscrub._CREDENTIAL_WORDS + secretscrub._MEMBER_EXTRA_WORDS)
    # The braced body is kept to one line here; the label pattern's may cross one.
    assert secretscrub._ODBC_BRACED.replace("[^}]", r"[^}\r\n]") in pattern
    assert secretscrub._ODBC_BRACED_OVERRUN in pattern
    assert vars(bundle_redact)["_CONNECTION_STRING_MEMBER"] is secretscrub._CONNECTION_STRING_MEMBER
    assert vars(bundle_redact)["_mask_member"] is secretscrub._mask_member


def test_the_kept_words_and_shapes_cover_what_later_passes_read() -> None:
    """The mask keeps a word where a later pass reads it. This holds each kept word and shape to the
    pass it is for, so a word added there and not here goes red."""

    def kept(word: str) -> bool:
        return secretscrub._MEMBER_KEEP.search(word) is not None

    sources = {
        "secretscrub credential words": secretscrub._CREDENTIAL_WORDS,
        "secretscrub token words": secretscrub._TOKEN_WORDS,
        "secretscrub key-material words": secretscrub._KEY_MATERIAL_WORDS,
        "secretscrub query-credential words": secretscrub._QUERY_CREDENTIAL_WORDS,
        "secretscrub query-credential compounds": secretscrub._QUERY_CREDENTIAL_COMPOUNDS,
        "secretscrub env prefix": (secretscrub._ENV_PREFIX,),
        "logging_setup query keys": logging_setup._CREDENTIAL_QUERY_KEYS,
        "logging_setup query stop words": logging_setup._QUERY_STOP_WORDS,
        "redaction credential-ahead words": tuple(
            word
            for alternation in re.findall(
                r"\(\?:((?:[a-z_\-]+\|)+[a-z_\-]+)\)", redaction._CREDENTIAL_AHEAD.pattern
            )
            for word in alternation.split("|")
        ),
        "redaction glued credential words": redaction._GLUED_CREDENTIAL_WORDS,
        "redaction DICOM label words": redaction._DICOM_LABEL_WORDS,
        "redaction widened key words": redaction._WIDENED_KEY_WORDS,
        "redaction MRN": ("mrn",),
        "bundle scheme words": ("bearer", "basic", "digest", "mfb64"),
    }
    missing = {name: [w for w in words if not kept(w)] for name, words in sources.items()}
    assert not {name: words for name, words in missing.items() if words}
    # The literal search is the tuple, reduced by subsumption and nothing else.
    alternatives = secretscrub._MEMBER_KEEP.pattern.removeprefix("(?i)").split("|")
    assert set(alternatives) <= {word.lower() for word in secretscrub._MEMBER_KEEP_WORDS}
    assert all(kept(word) for word in secretscrub._MEMBER_KEEP_WORDS)
    # Shapes kept whole, each spelled as its pass spells it.
    assert redaction._USERINFO_OPENER == "nonnumeric port: '"
    assert "nonnumeric port: " in secretscrub._MEMBER_VALUE_UNIT.pattern
    assert secretscrub._MEMBER_LONG_B64.pattern == bundle_redact._LONG_B64.pattern
    assert redaction._HL7_SEGMENT.pattern.startswith(r"\b([A-Z][A-Z0-9]{2})")
    assert redaction._ENCODED_SEPARATOR.pattern == r"%(?:7[CcEe]|5[Ee]|26)"
    assert redaction._ENCODED_SEPARATOR.pattern in secretscrub._MEMBER_VALUE_UNIT.pattern


@pytest.mark.parametrize(
    ("line", "masked"),
    [
        # A word for a word: the separators a later pass counts stay where they were.
        (";PWD=Qv7m kX4r,Pw9z&mT3y=Yb8n;", ";PWD=<redacted> redacted,redacted&redacted=redacted;"),
        (";xpass=a1q%5E", ";xpass=redacted%5E"),
        # A later pass's label, segment ID, DICOM tag and userinfo opener stay whole.
        (";xpass=&state=b2q;", ";xpass=&state=redacted;"),
        (";xpass=x.PID|1||", ";xpass=redacted.PID|redacted||"),
        (";xpass=(0010,1000)c3q", ";xpass=(0010,1000)redacted"),
        (";xpass=nonnumeric port: 'd4q@h'", ";xpass=nonnumeric port: 'd4q@h'"),
        # A base64 run stays long enough for the bundle's sweep.
        (";xpass=a1q QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", ";xpass=redacted " + "redacted" * 4),
        # A kept word only stays where a later pass reads it: here it is a password or a token.
        (";sslpassword=Passw0rd!2024;", ";sslpassword=redacted!redacted;"),
        (";AccessToken=aaa.sig-key_jwt.aaa;", ";AccessToken=redacted;"),
        (";xpass=Monkey123 Codename9;", ";xpass=redacted redacted;"),
        # A segment ID stays only before a "|", and never with a prefix.
        (";sslpassword=Hunter.AB1,xyz;", ";sslpassword=redacted,redacted;"),
        (";sslpassword=XY9&Qz7;", ";sslpassword=redacted&redacted;"),
        # Spaces before the quote that opens a value.
        (";sslpassword= 'Zq7 kx';PORT=1", ";sslpassword= 'redacted redacted';PORT=1"),
    ],
)
def test_the_mask_replaces_words_and_keeps_what_a_later_pass_reads(line: str, masked: str) -> None:
    assert scrub_credentials(line) == masked


def test_a_masked_member_is_masked_the_same_on_a_second_pass() -> None:
    """The mask keeps the placeholders it and the earlier passes wrote, so a second pass changes
    nothing it wrote."""
    once = scrub_credentials(_dsn())
    assert scrub_credentials(once) == once
    bundled = redact_log_line(_dsn())
    assert redact_log_line(bundled) == bundled


@pytest.mark.parametrize(
    "unit",
    [
        *(
            ";",
            ";pwd=",
            ";pwd=a b",
            ";pwd={",
            ";pwd={a}}",
            ";sslpassword=x",
            ";Xpass",
            ";a=b c,d&e",
            # Words inside long base64 runs, each found by bisection.
            ";pwd=QUFBQUFBQUFBQUFBQUFBQUFBQUFB a ",
        ),
        # Many lines, each with a "{" it never closes: a brace walk that crossed lines re-read the
        # rest of the record from every one (a review measured 5 s on 64 KB).
        *("x;sslpwd={\n", "partner said;AccessToken={\n", ";pwd={a\n}"),
    ],
)
def test_a_long_semicolon_dense_line_scrubs_in_linear_time(unit: str) -> None:
    """About 400 KB of one unit. Linear work is milliseconds; a quadratic walk over this many ";"
    would take minutes, so the generous bound still tells them apart under load."""
    line = "DRIVER={X}" + unit * (400_000 // len(unit))
    started = time.perf_counter()
    scrub_credentials(line)
    redact_log_line(line)
    assert time.perf_counter() - started < 10.0


def test_one_long_member_value_masks_in_linear_time() -> None:
    """One value of about 400 KB, words and base64 runs alternating: the mask walks it once and
    finds the run under each word by bisection, where a scan of every run per word was quadratic."""
    line = "DRIVER={X};pwd=" + "QUFBQUFBQUFBQUFBQUFBQUFBQUFB a b " * 12_000
    started = time.perf_counter()
    scrub_credentials(line)
    redact_log_line(line)
    assert time.perf_counter() - started < 10.0


@pytest.mark.parametrize(
    "line",
    [
        # Each holds a credential word, so the gate admits the member pass and the pattern itself must
        # refuse: a key that holds the word but ends in another, a word after "; " in prose, and a
        # key that ends in "ive".
        "DRIVER={Acme};SERVER=db1.example;PasswordPolicy=strict;TokenEndpoint=https://idp.example/t",
        "reload done; secret rotation scheduled; token cache warmed",
        "matrix /fhir;version=4;passive=true;format=json",
    ],
)
def test_a_connection_string_with_no_credential_member_is_unchanged(line: str) -> None:
    assert secretscrub._admits(secretscrub._gate_fold(line), secretscrub._CREDENTIAL_HINT)
    assert scrub_credentials(line) == line
    assert _credential_filter_alone(line) == line
    assert redact_log_line(line) == line


@pytest.mark.parametrize(("surface", "apply"), _SURFACES, ids=[name for name, _ in _SURFACES])
def test_a_token_keyword_glued_or_bare_is_hidden_whole(
    surface: str, apply: Callable[[str], str]
) -> None:
    """``token`` is a secret keyword to the builder (``_ODBC_SECRET_KEY_RE``), so a member whose key
    ends in it is read as ``sslpassword`` is: glued, as in ``AccessToken``, or bare."""
    line = "DRIVER={Acme};SERVER=db1.example;AccessToken=Qv7m kX4r,Pw9z;Token=mT3y Yb8n;PORT=1"
    out = apply(line)
    assert not [f for f in ("Qv7m", "kX4r", "Pw9z", "mT3y", "Yb8n") if f in out], out
    assert "AccessToken=" in out and "PORT=1" in out, out


def test_a_brace_left_open_on_one_line_keeps_the_frames_below_it() -> None:
    """A traceback's later frames stay readable: the braced walk stops at its line."""
    text = 'connect failed;sslpwd={a1q b2q\n  File "x.py", line 3, in f\n    d = {"k": 1}\n'
    out = scrub_credentials(text)
    assert "a1q" not in out and "b2q" not in out, out
    assert 'File "x.py", line 3, in f' in out and 'd = {"k": 1}' in out, out


def test_the_bundle_runs_the_member_pass_after_its_second_layer() -> None:
    """Run before ``scrub_credentials``, the member pass swallowed a later label whose quoted value
    that layer hid, and the bundle printed it (round 2 of the review)."""
    out = redact_log_line(";KeyStorePwd=Authorization: Bearer api_token='a1q b2q'")
    assert "a1q" not in out and "b2q" not in out, out
