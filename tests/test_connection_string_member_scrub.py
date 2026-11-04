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

from messagefoundry import secretscrub
from messagefoundry.logging_setup import CredentialScrubFilter
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


def test_the_member_pass_only_adds_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """A differential: every planted value the scrubbers print WITH the member pass, they print
    without it too. Run against the first draft's branch form, a fuzz of this kind found values it
    printed that the scrubbers hid without it (1144 lines of 80,000, recorded in the commit)."""
    pieces = (
        ";PWD=",
        ";sslpassword=",
        "password'=",
        'password":',
        "private_key'=",
        "encryption_key={",
        ";xpass=",
        "postgres://svc:",
        "@db",
        " \n",
        "DOE^JOHN",
        " :",
        "'",
        '"',
        "{",
        "}",
        ";",
        ",",
        "&",
        "=",
        " ",
        "%7C",
        "Token=",
        "a1q",
        "b2q",
        "c3q",
        "d4q",
        "[REDACTED]",
        "secret=",
    )
    rng = random.Random(5030)
    lines = list(_SHAPES_THE_FIRST_DRAFT_PRINTED) + [
        "".join(rng.choice(pieces) for _ in range(rng.randint(3, 14))) for _ in range(3000)
    ]
    with_member = [(scrub_credentials(line), redact_log_line(line)) for line in lines]
    never = re.compile(r"(?!)")  # matches nowhere
    monkeypatch.setattr(secretscrub, "_CONNECTION_STRING_MEMBER", never)
    monkeypatch.setattr(bundle_redact, "_CONNECTION_STRING_MEMBER", never)
    for line, (scrubbed, bundled) in zip(lines, with_member, strict=True):
        base_scrubbed, base_bundled = scrub_credentials(line), redact_log_line(line)
        for fragment in _planted(line):
            assert fragment not in scrubbed or fragment in base_scrubbed, (line, scrubbed)
            assert fragment not in bundled or fragment in base_bundled, (line, bundled)


def test_the_member_pattern_spells_the_word_tuples_and_brace_fragments() -> None:
    """The pattern is a literal so the static regex scanner reads it; this holds the literal to its
    sources, and the bundle to the same object, so neither can drift."""
    pattern = secretscrub._CONNECTION_STRING_MEMBER.pattern
    words = re.findall(r"\(\?<=([a-z]+)\)", pattern)
    assert sorted(words) == sorted(secretscrub._CREDENTIAL_WORDS + secretscrub._MEMBER_EXTRA_WORDS)
    # The braced body is kept to one line here; the label pattern's may cross one.
    assert secretscrub._ODBC_BRACED.replace("[^}]", r"[^}\r\n]") in pattern
    assert secretscrub._ODBC_BRACED_OVERRUN in pattern
    in_bundle = vars(bundle_redact)["_CONNECTION_STRING_MEMBER"]
    assert in_bundle is secretscrub._CONNECTION_STRING_MEMBER


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


@pytest.mark.parametrize(
    "line",
    [
        "DRIVER={Acme};SERVER=db1.example;DATABASE=mf;sslmode=require;PORT=5432",
        "reload done; 3 outbounds rebuilt; 0 failed",
        "matrix /fhir;version=4;format=json",
    ],
)
def test_a_connection_string_with_no_credential_member_is_unchanged(line: str) -> None:
    assert scrub_credentials(line) == line
    assert _credential_filter_alone(line) == line


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
