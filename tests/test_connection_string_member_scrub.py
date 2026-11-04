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
from collections.abc import Callable

import pytest

from messagefoundry.logging_setup import CredentialScrubFilter
from messagefoundry.secretscrub import scrub_credentials
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


@pytest.mark.parametrize(
    ("line", "later"),
    [
        # A later label's quoted value: running up to its quote would print it.
        (";PWD=Qv7m,password='kX4r Pw9z' tail", ("kX4r", "Pw9z")),
        # A later label's braced value holding the ";" the walk stops at.
        (";PWD=Qv7m,password={Pw9z;mT3y} tail", ("Pw9z", "mT3y")),
        # A DSN password holding a ";".
        (";PWD=Qv7m postgres://u:kX4r;Pw9z@h tail", ("kX4r", "Pw9z")),
    ],
)
def test_the_guards_fall_back_to_the_label_branch_and_print_no_later_value(
    line: str, later: tuple[str, ...]
) -> None:
    """Where a guard refuses, the label branch reads the line as before; this pins that the later
    label's value stays hidden, not that the first value's own tail does."""
    for surface, apply in _SURFACES:
        out = apply(line)
        printed = [f for f in later if f in out]
        assert not printed, f"{surface}: {printed} printed -- {out!r}"


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
