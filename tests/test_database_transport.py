# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DATABASE destination connector (ADR 0003): param binding, error classification, DSN/TLS, egress.

The aioodbc/pyodbc driver is never imported — the pool is faked, and error classification is duck-typed
on the SQLSTATE, so the full logic is unit-tested without a real SQL Server. The live aioodbc round-trip
is exercised separately by the gated integration suite (test_database_connector_integration.py).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from decimal import Decimal
from typing import Any, NoReturn

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Database, DatabasePoll, WiringError
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports import database as database_module
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.database import (
    _ODBC_PARAM_ALLOWLIST,
    _ODBC_TLS_MODE_KEYWORDS,
    DatabaseDestination,
    DatabaseSource,
    _bind_params,
    _build_connection,
    _build_dsn,
    _build_odbc_dsn,
    _classify_db_error,
    _driver_code,
    _is_tls_keyword,
    _is_transient,
    _parse_named_params,
    _sqlstate,
    generic_odbc_no_tls_params,
    generic_odbc_tls_unenforced,
)
from messagefoundry.transports.egress import check_egress_allowed, check_source_allowed

INSERT = "INSERT INTO obs (mrn, val) VALUES (:mrn, :val)"


def _dest(**over: Any) -> DatabaseDestination:
    base: dict[str, Any] = dict(server="sql.example.com", database="MFDB", statement=INSERT)  # noqa: C408
    base.update(over)
    d = build_destination(
        Destination(name="OB_DB", type=ConnectorType.DATABASE, settings=Database(**base).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, DatabaseDestination)
    return d


# --- pure helpers ------------------------------------------------------------


def test_parse_named_params_translates_to_positional() -> None:
    sql, names = _parse_named_params(INSERT)
    assert sql == "INSERT INTO obs (mrn, val) VALUES (?, ?)"
    assert names == ["mrn", "val"]


def test_parse_named_params_skips_literals_and_casts() -> None:
    # A time literal '12:30' and a ::cast must NOT be mistaken for parameters.
    sql, names = _parse_named_params("SELECT x::int WHERE t = '12:30' AND id = :id")
    assert sql == "SELECT x::int WHERE t = '12:30' AND id = ?"
    assert names == ["id"]


def test_bind_params_orders_values() -> None:
    assert _bind_params('{"mrn": "1", "val": "x"}', ["mrn", "val"]) == ("1", "x")


@pytest.mark.parametrize("payload", ["not json", "[1, 2]", '{"mrn": "1"}'])
def test_bind_params_bad_payload_is_permanent(payload: str) -> None:
    with pytest.raises(NegativeAckError) as ei:
        _bind_params(payload, ["mrn", "val"])
    assert ei.value.permanent is True


def test_is_transient_by_sqlstate() -> None:
    assert _is_transient("08S01") and _is_transient("40001") and _is_transient("HYT00")
    assert not _is_transient("23000") and not _is_transient("42000")


def test_classify_db_error() -> None:
    assert type(_classify_db_error("08S01", "x")) is DeliveryError  # transient → retry
    permanent = _classify_db_error("23000", "constraint")
    assert isinstance(permanent, NegativeAckError) and permanent.permanent is True


# The two driver texts BACKLOG #1661 measured, with a synthetic identifier standing in for the
# offending column value. 424242 is six digits on purpose: that is the longest a native error code
# can be, so an extractor that is not anchored on the driver's own `(SQLFunctionName)` suffix would
# lift it and report it as the error number.
_SYNTHETIC_ID = "424242"
_SQLSERVER_DUP = (
    "[23000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Violation of PRIMARY KEY "
    "constraint 'PK_obs'. Cannot insert duplicate key in object 'dbo.obs'. The duplicate key "
    f"value is ({_SYNTHETIC_ID}). (2627) (SQLExecDirectW)"
)
_POSTGRES_DUP = (
    '[23505] ERROR: duplicate key value violates unique constraint "ix_obs_mrn";\n'
    f"Error while executing the query: Key (mrn)=({_SYNTHETIC_ID}) already exists. (7) "
    "(SQLExecDirectW)"
)


def _driver_exc(sqlstate: str, message: str) -> Exception:
    """A pyodbc-shaped error: ``args == (sqlstate, message)``, so ``str(exc)`` is the tuple repr the
    connector's call sites actually hand to :func:`_classify_db_error`."""
    return Exception(sqlstate, message)


@pytest.mark.parametrize(
    ("state", "message"), [("23000", _SQLSERVER_DUP), ("23505", _POSTGRES_DUP)]
)
def test_classify_db_error_never_carries_the_driver_message(state: str, message: str) -> None:
    """BACKLOG #1661: the driver's text, and the value it embeds, stay out of the delivery error.

    Both shapes here keep their identifier through ``safe_exc`` — it is neither HL7-delimited nor
    name-shaped, and it sits well inside the 200-character truncation — so redaction downstream is
    not a control for this. The only control is not interpolating the message in the first place.

    Red mutation: restore the ``: {message}`` suffix on either branch. Both arms red.
    """
    err = _classify_db_error(state, str(_driver_exc(state, message)))
    assert _SYNTHETIC_ID not in str(err)
    assert "duplicate key" not in str(err).lower()
    assert "Key (mrn)" not in str(err)


def test_classify_db_error_keeps_the_sqlstate_and_the_driver_error_number() -> None:
    """The extraction the row asks for: enough to tell 2627 from 2601 under one generic SQLSTATE.

    Red mutation: drop ``_driver_code`` from the detail — the second assertion reds while the
    PHI-freedom tests above stay green, so the two properties are pinned independently.
    """
    permanent = _classify_db_error("23000", str(_driver_exc("23000", _SQLSERVER_DUP)))
    assert "[23000]" in str(permanent)
    assert "driver error 2627" in str(permanent)
    link_down = str(_driver_exc("08S01", "[08S01] link failure (10054) (SQLDriverConnect)"))
    transient = _classify_db_error("08S01", link_down)
    assert isinstance(transient, DeliveryError) and "driver error 10054" in str(transient)


def test_driver_code_will_not_lift_a_parenthesised_column_value() -> None:
    """The anchor, not the digit bound, is what makes the extraction safe.

    ``The duplicate key value is (424242).`` is indistinguishable from a native error code by shape
    alone; only the driver's trailing ``(SQLFunctionName)`` separates them, and the driver always
    writes its own suffix last.

    Red mutation: relax ``_DRIVER_CODE_RE`` to a bare ``\\((\\d+)\\)`` — the first assertion reds
    with the synthetic identifier reported as the error number.
    """
    assert _driver_code(_SQLSERVER_DUP) == "2627"  # the suffix, not the embedded value
    assert _driver_code(_POSTGRES_DUP) == "7"
    assert _driver_code(f"The duplicate key value is ({_SYNTHETIC_ID}).") is None
    assert _driver_code("no driver code here at all") is None


def test_sqlstate_extraction() -> None:
    assert _sqlstate(Exception("08S01", "msg")) == "08S01"
    assert (
        _sqlstate(ValueError("some bug")) is None
    )  # not SQLSTATE-shaped → propagates as a code bug
    assert _sqlstate(Exception("123", "x")) is None  # wrong length


def test_build_dsn_secure_defaults() -> None:
    dsn = _build_dsn(
        {"server": "sql.example.com", "database": "MFDB", "username": "u", "password": "p"}
    )
    # SERVER is emitted UNBRACED (validated, not brace-quoted) so the driver parses the ",port" suffix
    # and the TLS handshake resolves the host — a brace-quoted "SERVER={host},port" is malformed ODBC
    # and breaks certificate handling against a real SQL Server (mirrors the store's connection_string).
    assert "SERVER=sql.example.com,1433" in dsn
    assert "SERVER={" not in dsn  # never brace the host
    assert "DATABASE={MFDB}" in dsn
    assert "UID={u}" in dsn and "PWD={p}" in dsn
    assert dsn.rstrip(";").endswith("Encrypt=yes;TrustServerCertificate=no")  # security flags last


def test_build_dsn_braces_neutralize_injection() -> None:
    dsn = _build_dsn({"server": "s", "database": "MFDB", "password": "p};DROP", "username": "u"})
    assert "PWD={p}};DROP}" in dsn  # the inner } is doubled, so it can't close the brace early


@pytest.mark.parametrize("bad", ["host;DROP", "host}xx", "host{xx", "a=b", "host\nx"])
def test_build_dsn_rejects_server_injection(bad: str) -> None:
    # The SERVER value is unbraced, so it is *validated* (not brace-quoted) to carry no ODBC
    # connection-string metacharacters — an attacker-influenced host can't inject extra keywords.
    with pytest.raises(ValueError, match="server must not contain"):
        _build_dsn({"server": bad, "database": "d", "username": "u", "password": "p"})


def test_build_dsn_an_explicit_none_encrypt_takes_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vault BACKLOG #3230: ``encrypt = None`` read as off, so without the escape this build was
    refused as a weakened hop. It now takes the default, as absence does."""
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dsn = _build_dsn({"server": "s", "database": "d", "encrypt": None})
    assert dsn.rstrip(";").endswith("Encrypt=yes;TrustServerCertificate=no")


def test_build_dsn_weak_tls_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        _build_dsn({"server": "s", "database": "d", "encrypt": False})


def test_build_dsn_weak_tls_allowed_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # The escape needs a known non-enforcing posture (vault BACKLOG #2354).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(HopPosture(enforcing=False)):
        assert "Encrypt=no" in _build_dsn({"server": "s", "database": "d", "encrypt": False})


def test_build_dsn_bad_auth() -> None:
    with pytest.raises(ValueError):
        _build_dsn({"server": "s", "database": "d", "auth": "kerberos"})


# --- generic ODBC dialect (#66) ---------------------------------------------


def test_build_connection_sqlserver_is_byte_identical() -> None:
    # The default dialect must be byte-identical to the SQL Server preset (_build_dsn) + report weakened.
    s = {"server": "sql.example.com", "database": "MFDB", "username": "u", "password": "p"}
    dsn, weakened = _build_connection(dict(s))
    assert dsn == _build_dsn(dict(s))
    assert weakened is False


def test_build_connection_dispatches_generic() -> None:
    s = {"dialect": "generic", "odbc_driver": "PostgreSQL Unicode", "server": "db.example"}
    dsn, weakened = _build_connection(dict(s))
    assert dsn == _build_odbc_dsn(dict(s))
    # Generic path never reports weakened — TLS is the operator's responsibility on this path.
    assert weakened is False


def test_build_connection_rejects_unknown_dialect() -> None:
    with pytest.raises(ValueError, match="dialect must be"):
        _build_connection({"dialect": "mongo", "server": "s"})


def test_build_odbc_dsn_postgres_shape() -> None:
    dsn = _build_odbc_dsn(
        {
            "odbc_driver": "PostgreSQL Unicode",
            "server": "db.example",
            "database": "mefor",
            "username": "svc",
            "password": "pw",
            "odbc_params": {"PORT": 5432, "SSLmode": "verify-full"},
        }
    )
    assert "DRIVER={PostgreSQL Unicode}" in dsn
    assert "SERVER=db.example" in dsn and "SERVER={" not in dsn  # host unbraced, like the SS preset
    assert "DATABASE={mefor}" in dsn
    assert "UID={svc}" in dsn and "PWD={pw}" in dsn  # default credential keywords
    assert "PORT={5432}" in dsn and "SSLmode={verify-full}" in dsn
    # No SQL-Server TLS keywords are forced onto the generic path.
    assert "Encrypt=" not in dsn and "TrustServerCertificate=" not in dsn


def test_build_odbc_dsn_no_weak_tls_refusal() -> None:
    # A generic DSN with no TLS keyword is NOT refused (unlike the SQL Server preset with encrypt=false)
    # — MessageFoundry cannot introspect an arbitrary driver's TLS posture; the operator owns it.
    dsn = _build_odbc_dsn({"odbc_driver": "MySQL ODBC 8.0 Unicode Driver", "server": "db.example"})
    assert dsn.startswith("DRIVER={MySQL ODBC 8.0 Unicode Driver};SERVER=db.example")


def test_generic_dsn_warns_when_no_tls_keyword(caplog: pytest.LogCaptureFixture) -> None:
    # Fail-safe visibility (#66 review): the generic path can't enforce/introspect TLS, so with no
    # ssl/tls/encrypt keyword in odbc_params it must WARN loudly rather than silently cross in plaintext.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        _build_odbc_dsn({"odbc_driver": "PostgreSQL Unicode", "server": "db.example"})
    assert any("TLS verification is NOT enforced" in r.getMessage() for r in caplog.records)


def test_generic_dsn_no_warn_when_tls_keyword_present(caplog: pytest.LogCaptureFixture) -> None:
    # An operator who set a TLS keyword AT A VERIFYING VALUE has taken ownership → no WARNING (DEBUG).
    # The other half of the pair is below: a TLS keyword at a NO-TLS value must still WARN. Before #333
    # the detector matched the regex against KEYS ONLY, so this test passed for `disable` too — which is
    # why the pair, not this test alone, is the control.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        _build_odbc_dsn(
            {
                "odbc_driver": "PostgreSQL Unicode",
                "server": "db.example",
                "odbc_params": {"SSLmode": "verify-full"},
            }
        )
    assert not any("TLS verification is NOT enforced" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("SSLmode", "disable"),  # psqlODBC: explicit NO TLS
        ("SSLmode", "allow"),  # psqlODBC: plaintext first, TLS only on refusal
        ("SSLmode", "prefer"),  # psqlODBC: opportunistic, silently falls back to plaintext
        ("SSLMODE", "DISABLED"),  # MySQL Connector/ODBC
        ("SSLMODE", "PREFERRED"),  # MySQL Connector/ODBC: opportunistic
        ("Encrypt", "no"),
        ("Encrypt", "0"),
        ("Encrypt", "false"),
        ("Encrypt", "  Off  "),  # value classification tolerates case + surrounding whitespace
    ],
)
def test_generic_dsn_warns_when_tls_keyword_is_at_a_no_tls_value(
    key: str, value: str, caplog: pytest.LogCaptureFixture
) -> None:
    """#333 step 1 — the detector must read the VALUE, not just the key.

    ``_ODBC_TLS_HINT_RE`` matched against ``params`` KEYS only, so ``odbc_params={"SSLmode": "disable"}``
    — psqlODBC's explicit *no TLS* spelling — was read as "the operator has taken TLS ownership" and the
    reminder dropped to DEBUG. That is the worst real case reported as the quiet one, and every surface
    built on top of it inherits the false negative."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        _build_odbc_dsn(
            {
                "odbc_driver": "PostgreSQL Unicode",
                "server": "db.example",
                "odbc_params": {key: value},
            }
        )
    warned = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("TLS verification is NOT enforced" in m for m in warned), warned
    # It must name the offending keyword AND its value: "a TLS keyword is set to a no-TLS value" is not
    # actionable when several are set, and the remedy is per-keyword. The value is the lower-case
    # constant it matched, never the supplied text (BACKLOG #1352: no config value reaches a report).
    assert any(f"{key}={value.strip().lower()}" in m for m in warned), warned


def test_build_odbc_dsn_custom_credential_keywords() -> None:
    dsn = _build_odbc_dsn(
        {
            "odbc_driver": "MySQL ODBC 8.0 Unicode Driver",
            "server": "db.example",
            "username": "svc",
            "password": "pw",
            "odbc_user_key": "USER",
            "odbc_password_key": "PASSWORD",
        }
    )
    assert "USER={svc}" in dsn and "PASSWORD={pw}" in dsn


def test_build_odbc_dsn_requires_driver() -> None:
    with pytest.raises(ValueError, match="requires an 'odbc_driver'"):
        _build_odbc_dsn({"server": "db.example"})


def test_build_odbc_dsn_brace_quotes_values() -> None:
    # An injection attempt in a password can't close the brace early (the inner } is doubled).
    dsn = _build_odbc_dsn(
        {"odbc_driver": "PostgreSQL Unicode", "server": "db.example", "password": "p};DROP"}
    )
    assert "PWD={p}};DROP}" in dsn


@pytest.mark.parametrize("bad", ["host;x", "host{x", "host=x", "host\nx"])
def test_build_odbc_dsn_rejects_server_injection(bad: str) -> None:
    with pytest.raises(ValueError, match="server must not contain"):
        _build_odbc_dsn({"odbc_driver": "PostgreSQL Unicode", "server": bad})


@pytest.mark.parametrize("bad_key", ["a;b", "a=b", "a{b", "1abc", "a\nb"])
def test_build_odbc_dsn_rejects_bad_param_key(bad_key: str) -> None:
    with pytest.raises(ValueError, match="not a valid ODBC keyword"):
        _build_odbc_dsn(
            {"odbc_driver": "PostgreSQL Unicode", "server": "s", "odbc_params": {bad_key: "v"}}
        )


@pytest.mark.parametrize("reserved", ["DRIVER", "server", "Database"])
def test_build_odbc_dsn_rejects_reserved_param_key(reserved: str) -> None:
    with pytest.raises(ValueError, match="must not set"):
        _build_odbc_dsn(
            {"odbc_driver": "PostgreSQL Unicode", "server": "s", "odbc_params": {reserved: "v"}}
        )


def test_generic_destination_builds_without_database() -> None:
    # The generic dialect may omit `database` (not every driver takes one) — the destination still builds.
    d = build_destination(
        Destination(
            name="OB_DB_GEN",
            type=ConnectorType.DATABASE,
            settings=Database(
                server="db.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                statement=INSERT,
                odbc_params={"PORT": "5432"},
            ).settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, DatabaseDestination)
    assert d._dialect == "generic"
    assert d._weakened_tls is False  # generic never crosses the weakened-TLS machinery


def test_generic_destination_warning_names_the_connection(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """#333 step 2 — with several generic DB connections an anonymous line is not actionable."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        build_destination(
            Destination(
                name="OB_DB_GEN",
                type=ConnectorType.DATABASE,
                settings=Database(
                    server="db.example",
                    dialect="generic",
                    odbc_driver="PostgreSQL Unicode",
                    statement=INSERT,
                    odbc_params={"SSLmode": "disable"},
                ).settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    warned = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("'OB_DB_GEN'" in m and "SSLmode=disable" in m for m in warned), warned


_NO_TLS_WORDS = ("disable", "disabled", "allow", "prefer", "preferred", "no", "off", "false", "0")


def _generic_dsn_logs(params: dict[str, str], caplog: pytest.LogCaptureFixture) -> str:
    settings = {
        "dialect": "generic",
        "odbc_driver": "PostgreSQL Unicode",
        "server": "db.test",
        "odbc_params": params,
    }
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.transports.database"):
        _build_odbc_dsn(settings, connection="OB_DB_GEN")
    return " | ".join(r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("word", _NO_TLS_WORDS)
def test_an_sslpassword_spelled_like_a_no_tls_value_never_reaches_a_report(
    caplog: pytest.LogCaptureFixture, word: str
) -> None:
    """BACKLOG #1352, CodeQL py/clear-text-logging-sensitive-data. `sslpassword` matched the TLS
    keyword hint, so a passphrase spelled like a no-TLS value was rendered as `sslpassword=<value>`
    into the warning, the refusal text and the posture reports. SSLmode=disable is the control: the
    classifier still names a real no-TLS keyword beside it."""
    params = {"SSLmode": "disable", "sslpassword": word}
    assert generic_odbc_no_tls_params(params) == ["SSLmode=disable"]
    assert generic_odbc_tls_unenforced(params) == "TLS is explicitly not required: SSLmode=disable"
    logged = _generic_dsn_logs(params, caplog)
    assert "SSLmode=disable" in logged
    assert "sslpassword" not in logged.lower()


def test_a_sentinel_sslpassword_never_appears_in_the_captured_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sentinel = "Sentinel-PW-8c1e"  # a fixture value, not a secret
    for params in (
        {"SSLmode": "disable", "sslpassword": sentinel},
        {"sslpassword": sentinel},
    ):
        logged = _generic_dsn_logs(dict(params), caplog)
        reason = generic_odbc_tls_unenforced(params) or ""
        assert caplog.records, "the probe logged nothing, so an absence would prove nothing"
        assert sentinel not in logged and sentinel not in reason
    # The classifier alone. `PWD_SSL` is not an accepted odbc_params keyword, so the builder refuses
    # it before anything is logged (vault BACKLOG #2577) and only the classifier can be handed it.
    reason = generic_odbc_tls_unenforced({"PWD_SSL": "off", "Encrypt": "no"}) or ""
    assert "PWD_SSL" not in reason and "Encrypt=no" in reason


@pytest.mark.parametrize("password", ["0", "off", "hunter2-fixture"])
def test_a_lone_sslpassword_is_not_tls_ownership(password: str) -> None:
    # A passphrase keyword sets no TLS mode, so on its own the hop reads as "no TLS keyword": it is
    # still reported and gated. SSLmode=verify-full beside it is the control that clears the hop.
    assert generic_odbc_tls_unenforced({"sslpassword": password}) == (
        "no TLS keyword is set in odbc_params"
    )
    assert generic_odbc_tls_unenforced({"sslpassword": password, "SSLmode": "verify-full"}) is None


#: Every accepted keyword named like TLS that can set no mode. Read from the allowlist, so a TLS
#: keyword added there later is held to this rule without anyone listing it here.
_TLS_KEYWORDS_WITH_NO_MODE = sorted(
    keyword
    for keyword in _ODBC_PARAM_ALLOWLIST - _ODBC_TLS_MODE_KEYWORDS
    if _is_tls_keyword(keyword)
)
_NO_MODE_REASON = "a TLS keyword is set in odbc_params, but neither sslmode nor encrypt has a value"


def test_the_no_mode_table_is_not_empty_and_every_mode_keyword_is_accepted() -> None:
    # Positive control: an empty table would pass every test below. A mode keyword the build refuses
    # would leave no accepted way to clear a hop.
    assert {"sslca", "sslcapath", "sslcert", "sslcipher", "sslkey"} <= set(
        _TLS_KEYWORDS_WITH_NO_MODE
    )
    assert _ODBC_TLS_MODE_KEYWORDS <= _ODBC_PARAM_ALLOWLIST


@pytest.mark.parametrize("keyword", _TLS_KEYWORDS_WITH_NO_MODE)
def test_a_lone_tls_keyword_that_sets_no_mode_is_not_tls_ownership(keyword: str) -> None:
    """BACKLOG #2483. libpq defaults to ``sslmode=prefer``, so a key or certificate path with no
    mode beside it could still fall back to plaintext. A real mode beside it is the control."""
    for spelling in (keyword, keyword.upper()):
        assert generic_odbc_tls_unenforced({spelling: "fixture"}) == _NO_MODE_REASON
    assert generic_odbc_tls_unenforced({keyword: "fixture", "sslmode": "require"}) is None
    assert generic_odbc_tls_unenforced({keyword: "fixture", "SSLmode": "verify-full"}) is None
    assert generic_odbc_tls_unenforced({keyword: "fixture", "sslmode": "prefer"}) == (
        "TLS is explicitly not required: sslmode=prefer"
    )


def test_a_lone_sslrootcert_is_not_ownership() -> None:
    # The ledger row names this keyword. The build refuses it (it is not on the allowlist), so the
    # table above never reads it and only the classifier can be handed it.
    assert generic_odbc_tls_unenforced({"sslrootcert": "ca.pem"}) == _NO_MODE_REASON


@pytest.mark.parametrize(
    "params",
    [
        {"sslmode": ""},
        {"sslmode": "   "},
        {"Encrypt": ""},
        {"sslmode": None},
        {"SSLmode": "", "sslcert": "c.pem"},
        {"sslmode": "", "Encrypt": "  "},
    ],
)
def test_a_blank_mode_keyword_sets_no_mode(params: dict[str, str | None]) -> None:
    assert generic_odbc_tls_unenforced(params) == _NO_MODE_REASON


def test_one_blank_mode_keyword_does_not_void_the_other() -> None:
    assert generic_odbc_tls_unenforced({"sslmode": "", "Encrypt": "yes"}) is None
    assert generic_odbc_tls_unenforced({"sslmode": "verify-full", "Encrypt": ""}) is None


@pytest.mark.parametrize("value", ["bogus", "1", "VERIFY_IDENTITY"])
def test_a_mode_value_the_deny_list_does_not_name_stays_delegated(value: str) -> None:
    # A deny-list on purpose (see the comment above _ODBC_NO_TLS_VALUES): demanding a known good value
    # would warn on every legitimate driver this path exists to support.
    assert generic_odbc_tls_unenforced({"sslmode": value}) is None


def test_a_lone_certificate_keyword_warns_and_names_the_remedy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logged = _generic_dsn_logs({"sslcert": "client.pem"}, caplog)
    assert "TLS verification is NOT enforced" in logged and _NO_MODE_REASON in logged


@pytest.mark.parametrize(
    "params",
    [
        {"SSLmode": "require", "sslpassword": "0"},
        {"SSLmode": "verify-full", "sslpassword": "off"},
        {"Encrypt": "yes", "SSL_PWD": "no"},
        {"Encrypt": "yes", "ssl_token": "false"},
    ],
)
def test_a_passphrase_spelling_no_longer_decides_the_hop(params: dict[str, str]) -> None:
    # Deliberate, and the one place this change clears a hop the earlier code refused: the refusal
    # was keyed on how a SECRET was spelled, which both leaked it and gated on it. The TLS-mode
    # keyword beside it now decides, exactly as it does for any other passphrase.
    assert generic_odbc_tls_unenforced(params) is None


def test_a_no_tls_value_is_rendered_as_the_constant_it_matched() -> None:
    assert generic_odbc_no_tls_params({"SSLMODE": " DISABLED "}) == ["SSLMODE=disabled"]
    assert generic_odbc_no_tls_params({"SSLmode": "verify-full"}) == []


def test_generic_source_warning_names_the_connection(caplog: pytest.LogCaptureFixture) -> None:
    """The inbound half. `Source` carries no name of its own until the runner fills it (#333), so this
    also pins that the model field exists and reaches the connector — without it the poll link would
    warn anonymously while the destination named itself, which is the drift that makes a report
    untrustworthy."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        build_source(
            Source(
                name="IB_DB_GEN",
                type=ConnectorType.DATABASE,
                settings=DatabasePoll(
                    server="db.example",
                    dialect="generic",
                    odbc_driver="PostgreSQL Unicode",
                    poll_statement="SELECT 1",
                ).settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    warned = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    # `inbound:` prefixed, as every inbound record and the loosening reports spell it.
    assert any("'inbound:IB_DB_GEN'" in m and "no TLS keyword" in m for m in warned), warned


def test_sqlserver_destination_still_requires_database() -> None:
    with pytest.raises(ValueError, match="requires a 'database'"):
        build_destination(
            Destination(
                name="OB_DB_SS",
                type=ConnectorType.DATABASE,
                settings=Database(server="db.example", statement=INSERT).settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )


def test_generic_destination_dsn_has_no_sqlserver_tls() -> None:
    d = _dest(dialect="generic", odbc_driver="PostgreSQL Unicode", database="mefor")
    assert "Encrypt=" not in d._dsn and "DRIVER={PostgreSQL Unicode}" in d._dsn


def test_database_odbc_params_reject_envref() -> None:
    from messagefoundry.config.wiring import env

    with pytest.raises(WiringError, match="may not use env"):
        Database(
            server="db.example",
            dialect="generic",
            odbc_driver="PostgreSQL Unicode",
            statement=INSERT,
            odbc_params={"SSLmode": env("pg_sslmode")},
        )


@pytest.mark.parametrize("missing", ["server", "database", "statement"])
def test_requires_core_settings(missing: str) -> None:
    base: dict[str, Any] = dict(server="s", database="d", statement=INSERT)  # noqa: C408
    base[missing] = ""
    with pytest.raises(ValueError):
        build_destination(
            Destination(name="OB", type=ConnectorType.DATABASE, settings=Database(**base).settings),
            egress=EgressSettings(deny_by_default=False),
        )


# --- send() with a faked pool (no driver) ------------------------------------


class _FakeCursor:
    def __init__(self, exc: Exception | None = None) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self._exc = exc

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.executed.append((sql, params))
        if self._exc is not None:
            raise self._exc


class _FakeConn:
    def __init__(self, cur: _FakeCursor) -> None:
        self._cur = cur
        self.committed = False
        self.rolledback = False

    async def cursor(self) -> _FakeCursor:
        return self._cur

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolledback = True


class _FakePool:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self.released: list[_FakeConn] = []

    async def acquire(self) -> _FakeConn:
        return self._conn

    async def release(self, conn: _FakeConn) -> None:
        self.released.append(conn)


async def test_send_executes_and_commits() -> None:
    cur = _FakeCursor()
    conn = _FakeConn(cur)
    dest = _dest()
    dest._pool = _FakePool(conn)
    await dest.send('{"mrn": "1", "val": "x"}')
    assert cur.executed == [("INSERT INTO obs (mrn, val) VALUES (?, ?)", ("1", "x"))]
    assert conn.committed and not conn.rolledback


async def test_send_permanent_db_error_dead_letters() -> None:
    conn = _FakeConn(_FakeCursor(Exception("23000", "constraint violation")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError) as ei:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert ei.value.permanent is True
    assert conn.rolledback


async def test_send_transient_db_error_retries() -> None:
    conn = _FakeConn(_FakeCursor(Exception("08S01", "connection lost")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(DeliveryError) as ei:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert not isinstance(ei.value, NegativeAckError)  # transient → retry, not dead-letter
    assert conn.rolledback


async def test_send_dead_letter_text_carries_no_driver_value() -> None:
    """BACKLOG #1661, the delivery path end to end: a duplicate-key rejection is the routine failure
    on an MRN-keyed index, and its text reaches ``queue.last_error``, ``message_events.detail`` and
    the ``connection_error`` alert. On a first deployment it would carry the partner's identifier
    into all three.

    Red mutation: interpolate ``str(exc)`` at the ``send`` call site again. Reds here while the
    helper-level test above stays green, so the call site is pinned separately from the helper.
    """
    conn = _FakeConn(_FakeCursor(_driver_exc("23000", _SQLSERVER_DUP)))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError) as ei:
        await dest.send('{"mrn": "1", "val": "x"}')
    text = str(ei.value)
    assert _SYNTHETIC_ID not in text
    assert "duplicate key" not in text.lower()
    assert "[23000]" in text and "driver error 2627" in text  # still diagnosable
    assert conn.rolledback


async def test_send_non_db_error_propagates() -> None:
    conn = _FakeConn(_FakeCursor(ValueError("a real bug")))  # args[0] not SQLSTATE-shaped
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(ValueError):
        await dest.send('{"mrn": "1", "val": "x"}')
    assert conn.rolledback


class _HangingPool:
    """A pool whose acquire never returns — stands in for an exhausted pool / unresponsive DB."""

    async def acquire(self) -> NoReturn:
        await asyncio.Event().wait()
        raise AssertionError("unreachable: the event is never set")


async def test_send_pool_acquire_timeout_is_transient() -> None:
    # WP-L3-07 (ASVS 13.1.2/13.2.6): a borrow that can't be satisfied within acquire_timeout fails as a
    # transient DeliveryError (retry) instead of blocking the delivery worker forever.
    dest = _dest(acquire_timeout=0.05)
    dest._pool = _HangingPool()
    with pytest.raises(DeliveryError, match="pool acquire timed out"):
        await dest.send('{"mrn": "1", "val": "x"}')


async def test_lookup_pool_acquire_timeout_is_db_lookup_error() -> None:
    # The handler-callable lookup maps the same timeout onto its PHI-free DbLookupError type.
    from messagefoundry.config.db_lookup import DbLookupError
    from messagefoundry.transports.database import DatabaseLookupExecutor

    ex = DatabaseLookupExecutor(
        {"clarity": {"server": "s", "database": "d", "acquire_timeout": 0.05}},
        egress=EgressSettings(deny_by_default=False),
    )
    ex._pools["clarity"] = _HangingPool()
    with pytest.raises(DbLookupError, match="pool acquire timed out"):
        await ex.query("clarity", "SELECT 1", None)


# --- test_connection() reachability probe (SELECT 1) -------------------------


async def test_probe_runs_select_1() -> None:
    cur = _FakeCursor()
    pool = _FakePool(_FakeConn(cur))
    dest = _dest()
    dest._pool = pool
    await dest.test_connection()  # no raise = reachable
    assert ("SELECT 1", ()) in cur.executed  # a no-param read, never a write
    assert pool.released  # the connection was returned to the pool


async def test_probe_transient_error_is_delivery_error() -> None:
    dest = _dest()
    dest._pool = _FakePool(_FakeConn(_FakeCursor(Exception("08S01", "connection lost"))))
    with pytest.raises(DeliveryError) as ei:
        await dest.test_connection()
    assert not isinstance(ei.value, NegativeAckError)  # transient → reachability fail


async def test_probe_auth_error_is_permanent() -> None:
    dest = _dest()
    dest._pool = _FakePool(_FakeConn(_FakeCursor(Exception("28000", "login failed"))))
    with pytest.raises(NegativeAckError):  # bad credentials → permanent (still a test failure)
        await dest.test_connection()


async def test_send_bad_payload_is_permanent_before_any_connection() -> None:
    dest = _dest()  # no pool injected — a bad payload fails before _get_pool is reached
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("not json")
    assert ei.value.permanent is True


# --- egress allowlist --------------------------------------------------------


def _db_dest(server: str, port: int = 1433) -> Destination:
    return Destination(
        name="OB",
        type=ConnectorType.DATABASE,
        settings=Database(server=server, database="d", statement=INSERT, port=port).settings,
    )


def test_egress_blocks_unlisted_server() -> None:
    with pytest.raises(WiringError):
        check_egress_allowed(
            _db_dest("other.example.com"), EgressSettings(allowed_db=["sql.example.com"])
        )


def test_egress_permits_listed_server() -> None:
    check_egress_allowed(
        _db_dest("sql.example.com"), EgressSettings(allowed_db=["sql.example.com"])
    )


def test_egress_host_port_match() -> None:
    egress = EgressSettings(allowed_db=["sql.example.com:1433"])
    check_egress_allowed(_db_dest("sql.example.com", 1433), egress)  # ok
    with pytest.raises(WiringError):
        check_egress_allowed(_db_dest("sql.example.com", 1434), egress)  # wrong port


def test_egress_unrestricted_when_empty() -> None:
    check_egress_allowed(
        _db_dest("anywhere.example"), EgressSettings(deny_by_default=False)
    )  # empty = unrestricted


# === DATABASE source (poll) ==================================================
# Like the destination tests, the driver is never imported — a fake pool/cursor stands in, so the
# poll/mark/body logic is unit-tested without a real SQL Server.

POLL = "SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id"
MARK = "UPDATE mf_inbox SET status='DONE' WHERE id=:id"


def _src(**over: Any) -> DatabaseSource:
    base: dict[str, Any] = dict(  # noqa: C408
        server="sql.example.com", database="MFDB", poll_statement=POLL, mark_statement=MARK
    )
    base.update(over)
    s = build_source(
        Source(type=ConnectorType.DATABASE, settings=DatabasePoll(**base).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(s, DatabaseSource)
    return s


class _RecordingHandler:
    def __init__(self, exc: Exception | None = None) -> None:
        self.bodies: list[bytes] = []
        self._exc = exc

    async def __call__(self, raw: bytes) -> str | None:
        self.bodies.append(raw)
        if self._exc is not None:
            raise self._exc
        return None


class _SrcCursor:
    def __init__(
        self,
        columns: list[str],
        rows: list[tuple[Any, ...]],
        *,
        poll_exc: Exception | None = None,
        mark_exc: Exception | None = None,
    ) -> None:
        self.description = [(c,) for c in columns]
        self._rows = rows
        self._poll_exc = poll_exc
        self._mark_exc = mark_exc
        self._position = 0  # DB-API cursor position, so fetchmany/fetchall consume the same set
        self.marks: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        if params is None:  # the poll SELECT
            if self._poll_exc is not None:
                raise self._poll_exc
        else:  # a per-row mark
            self.marks.append((sql, params))
            if self._mark_exc is not None:
                raise self._mark_exc

    async def fetchall(self) -> list[tuple[Any, ...]]:
        rows = self._rows[self._position :]
        self._position = len(self._rows)
        return list(rows)

    async def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        """DB-API 2.0 ``fetchmany``: at most ``size`` rows from the current position, advancing it.

        The source's poll path fetches through here whenever ``poll_max_rows`` is on (the shipped
        default), so a fake carrying only ``fetchall`` would model a cursor the connector no longer
        uses."""
        rows = self._rows[self._position : self._position + size]
        self._position += len(rows)
        return list(rows)


class _SrcConn:
    def __init__(self, cur: _SrcCursor) -> None:
        self._cur = cur

    async def cursor(self) -> _SrcCursor:
        return self._cur


class _SrcPool:
    def __init__(self, conn: _SrcConn) -> None:
        self._conn = conn
        self.closed = False

    async def acquire(self) -> _SrcConn:
        return self._conn

    async def release(self, conn: _SrcConn) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


async def _run_poll(
    src: DatabaseSource,
    columns: list[str],
    rows: list[tuple[Any, ...]],
    handler: _RecordingHandler,
    **cur_kw: Any,
) -> _SrcCursor:
    cur = _SrcCursor(columns, rows, **cur_kw)
    src._pool = _SrcPool(_SrcConn(cur))
    src._handler = handler
    await src._poll_once()
    return cur


async def test_source_polls_each_row_and_marks_processed() -> None:
    src = _src(body_column="payload")
    h = _RecordingHandler()
    cur = await _run_poll(src, ["id", "payload"], [(1, "AAA"), (2, "BBB")], h)
    assert h.bodies == [b"AAA", b"BBB"]  # one body per row, verbatim (body_column)
    assert (
        cur.marks
        == [  # :id translated to ?, bound from each row — only AFTER the handler returned
            ("UPDATE mf_inbox SET status='DONE' WHERE id=?", (1,)),
            ("UPDATE mf_inbox SET status='DONE' WHERE id=?", (2,)),
        ]
    )


async def test_source_json_body_is_whole_row() -> None:
    src = _src(body_column=None, mark_statement=None)
    h = _RecordingHandler()
    await _run_poll(src, ["id", "val"], [(1, "x")], h)
    assert json.loads(h.bodies[0]) == {"id": 1, "val": "x"}


async def test_source_json_serializes_dates_decimal_bytes() -> None:
    src = _src(body_column=None, mark_statement=None)
    h = _RecordingHandler()
    await _run_poll(
        src, ["t", "amt", "blob"], [(datetime(2026, 6, 12, 8, 30), Decimal("1.50"), b"\x00\x01")], h
    )
    obj = json.loads(h.bodies[0])
    assert obj["t"] == "2026-06-12T08:30:00"
    assert obj["amt"] == "1.50"  # Decimal → str (no float rounding)
    assert obj["blob"] == base64.b64encode(b"\x00\x01").decode("ascii")


async def test_source_body_column_decodes_bytes_verbatim() -> None:
    src = _src(body_column="payload", mark_statement=None)
    h = _RecordingHandler()
    hl7 = b"MSH|^~\\&|A|B"
    await _run_poll(src, ["id", "payload"], [(1, hl7)], h)
    assert h.bodies[0] == hl7  # a column holding an HL7 message round-trips byte-for-byte


async def test_source_handler_failure_leaves_row_unmarked() -> None:
    src = _src(body_column="payload")
    h = _RecordingHandler(exc=RuntimeError("store write failed"))
    cur = await _run_poll(src, ["id", "payload"], [(1, "AAA")], h)
    assert h.bodies == [b"AAA"]  # handler was attempted
    assert cur.marks == []  # but the row is NOT marked → it re-emits next poll (at-least-once)


async def test_source_mark_failure_does_not_abort_batch_tail() -> None:
    src = _src(body_column="payload")
    h = _RecordingHandler()
    cur = await _run_poll(
        src, ["id", "payload"], [(1, "A"), (2, "B")], h, mark_exc=Exception("08S01", "deadlock")
    )
    assert h.bodies == [b"A", b"B"]  # both rows handled despite the first mark erroring
    assert len(cur.marks) == 2  # both marks attempted (the error is logged, not fatal)


async def test_source_without_mark_statement_does_not_mark() -> None:
    src = _src(body_column="payload", mark_statement=None)
    h = _RecordingHandler()
    cur = await _run_poll(src, ["id", "payload"], [(1, "A")], h)
    assert h.bodies == [b"A"]
    assert cur.marks == []


async def test_source_missing_body_column_skips_row() -> None:
    src = _src(body_column="nope")
    h = _RecordingHandler()
    cur = await _run_poll(src, ["id", "payload"], [(1, "A")], h)
    assert h.bodies == []  # no body could be built → row skipped, not delivered
    assert cur.marks == []


async def test_source_mark_failure_log_carries_no_driver_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #1661, the source's log limb: a mark is an ``UPDATE`` bound from the row's own
    columns, so the driver quotes the bound value straight back at a rejection.

    Redaction IS applied to this record — ``logging_setup.RedactionFilter`` is a HANDLER filter and
    runs on every record process-wide — and it DOES NOT CATCH THIS: ``redact`` rewrites HL7-delimited
    spans and whitespace-separated name runs, and a bare identifier is neither. So the control has to
    be at the call site, which is what this pins.

    Red mutation: pass the bare ``exc`` to the mark-failure log again. Reds here.
    """
    src = _src(body_column="payload")
    h = _RecordingHandler()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        await _run_poll(
            src,
            ["id", "payload"],
            [(1, "A")],
            h,
            mark_exc=_driver_exc("23000", _SQLSERVER_DUP),
        )
    assert "mark failed" in caplog.text  # the instrument fired
    assert _SYNTHETIC_ID not in caplog.text
    assert "duplicate key" not in caplog.text.lower()


async def test_source_handler_failure_log_is_scrubbed_and_bounded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The handler-failure limb of the same line. The handler is pipeline code that can raise with a
    message built from the body, so an HL7-shaped span in it must not reach the log — and the whole
    rendering is length-bounded whatever its shape.

    ``safe_exc`` is a bound plus HL7-shaped redaction, NOT a guarantee that every identifier is gone.
    This asserts what it really provides — the type is kept, an HL7 span is scrubbed, the line is
    bounded — rather than a stronger claim it would not survive.

    Red mutation: pass the bare ``exc`` to the handler-failure log again. Both assertions red.
    """
    leaky = "PID|1||" + "9" * 400 + "^^^MF|" + "|DOE^JANE"
    src = _src(body_column="payload")
    h = _RecordingHandler(exc=RuntimeError(leaky))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        await _run_poll(src, ["id", "payload"], [(1, "A")], h)
    assert "handler failed" in caplog.text  # the instrument fired
    assert "RuntimeError" in caplog.text  # the TYPE survives; safe_exc keeps it deliberately
    assert leaky not in caplog.text
    assert "9" * 400 not in caplog.text  # bounded, so the raw run cannot be reassembled


async def test_source_run_loop_survives_a_poll_error() -> None:
    src = _src(body_column="payload")
    calls: list[int] = []

    async def boom() -> None:
        calls.append(1)
        src._stop.set()  # exit the loop after this one iteration
        raise RuntimeError("poll blew up")

    src._poll_once = boom  # type: ignore[method-assign]
    src._poll_seconds = 0.0
    await src._run()  # must NOT propagate — a bad poll never kills the poller
    assert calls == [1]


# --- source: leader-gating (Track B Step 4b) --------------------------------


def test_source_declares_polls_shared_resource() -> None:
    # A polled DB table is a shared external resource — the runner reads this flag to leader-gate it.
    assert DatabaseSource.polls_shared_resource is True


async def test_source_run_loop_skips_poll_when_gate_false() -> None:
    # A follower (leader_gate() -> False) must NOT execute poll_statement nor mark any rows: the loop
    # ticks but _poll_once is never reached, so the shared table is untouched (no duplicate intake).
    src = _src(body_column="payload")
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0
    polled = {"n": 0}

    async def spy() -> None:  # would run poll_statement + marks if reached
        polled["n"] += 1
        src._stop.set()
        raise AssertionError("a follower must not poll")

    src._poll_once = spy  # type: ignore[method-assign]
    # Let the loop spin a few ticks, then stop it (a follower never sets _stop itself via the spy).
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)
    src._stop.set()
    await runner
    assert polled["n"] == 0  # poll_once was gated out every tick


async def test_source_follower_real_poll_issues_no_sql() -> None:
    # Higher-fidelity follower test (matches the FILE source's end-to-end check): let the REAL
    # _poll_once run under a False gate against a pool that counts and refuses every acquire. The
    # gate must short-circuit before any acquire/SELECT/mark, so a regression where _may_poll
    # returns True but _poll_once is reached shows up as a nonzero acquire count.
    #
    # THE COUNT IS THE ASSERTION, and the raise on its own asserts nothing (BACKLOG #1667): _run
    # deliberately catches every Exception so that a poll error cannot kill the poller, and
    # AssertionError is an Exception, so a poisoned acquire is swallowed and logged like any other
    # poll failure. `await runner` returns cleanly whether the gate holds or not.
    acquires = {"n": 0}

    class _PoisonPool:
        async def acquire(self) -> object:
            acquires["n"] += 1
            raise AssertionError("a follower must not acquire a connection / issue any SQL")

    src = _src(body_column="payload")
    src._pool = _PoisonPool()  # already-built pool → _get_pool returns it without reconnecting
    src._handler = _RecordingHandler()
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)  # several ticks — each must skip the poison pool
    src._stop.set()
    await runner  # must not raise: the gate kept the real _poll_once away from the pool
    assert acquires["n"] == 0  # the gate short-circuited every tick before any SQL was issued


async def test_source_run_loop_polls_when_gate_true() -> None:
    # A leader (leader_gate() -> True) polls exactly as the un-gated default does.
    src = _src(body_column="payload")
    src._leader_gate = lambda: True
    src._poll_seconds = 0.0
    calls: list[int] = []

    async def spy() -> None:
        calls.append(1)
        src._stop.set()  # one iteration then exit

    src._poll_once = spy  # type: ignore[method-assign]
    await src._run()
    assert calls == [1]  # the gate was True → poll_once ran


async def test_source_may_poll_logs_transition_once_then_resumes() -> None:
    # _may_poll is the gate check: False while a follower, True once leader, and it flips its
    # transition flag so it logs once per transition rather than every skipped tick.
    src = _src(body_column="payload")
    leader = {"on": False}
    src._leader_gate = lambda: leader["on"]
    assert src._may_poll() is False and src._skipping is True
    assert src._may_poll() is False and src._skipping is True  # still a follower (no re-flip)
    leader["on"] = True
    assert src._may_poll() is True and src._skipping is False  # became leader → resume


async def test_source_stop_closes_the_pool() -> None:
    src = _src(body_column="payload")
    pool = _SrcPool(_SrcConn(_SrcCursor(["id", "payload"], [])))
    src._pool = pool

    async def handler(raw: bytes) -> str | None:
        return None

    await src.start(handler)
    await src.stop()
    assert src._task is None
    assert pool.closed  # aclose drained the pool


_MARKED_1 = [("UPDATE mf_inbox SET status='DONE' WHERE id=?", (1,))]


class _StepCursor(_SrcCursor):
    """A source cursor that can hold a mark open, hold the cursor close that follows a mark, or hang
    every select from the ``hang_from``-th on, so a test can cancel stop() at a chosen point of the
    poll."""

    def __init__(
        self,
        columns: list[str],
        rows: list[tuple[Any, ...]],
        *,
        mark_gate: asyncio.Event | None = None,
        close_gate: asyncio.Event | None = None,
        hang_from: int | None = None,
    ) -> None:
        super().__init__(columns, rows)
        self.mark_gate = mark_gate
        self.close_gate = close_gate
        self.hang_from = hang_from
        self.selects = 0
        self.in_mark = asyncio.Event()
        self.in_select = asyncio.Event()
        self.in_close = asyncio.Event()
        self.marking = False

    async def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        if params is None:
            self.selects += 1
            if self.hang_from is not None and self.selects >= self.hang_from:
                self.in_select.set()
                await asyncio.Event().wait()
        else:
            self.in_mark.set()
            self.marking = True  # until the close that follows this mark
            if self.mark_gate is not None:
                await self.mark_gate.wait()
        await super().execute(sql, params)

    async def close(self) -> None:
        marking, self.marking = self.marking, False
        if self.close_gate is not None and marking:
            self.in_close.set()
            await self.close_gate.wait()  # a driver close on an executor thread, held


class _CountingPool(_SrcPool):
    """Counts the connections in use and, as aioodbc's ``wait_closed`` does, closes only once every
    one is back, so a skipped ``release`` hangs the close instead of passing unseen."""

    def __init__(self, conn: _SrcConn) -> None:
        super().__init__(conn)
        self.in_use = 0
        self._all_back = asyncio.Event()
        self._all_back.set()

    async def acquire(self) -> _SrcConn:
        self.in_use += 1
        self._all_back.clear()
        return self._conn

    async def release(self, conn: _SrcConn) -> None:
        self.in_use -= 1
        if self.in_use == 0:
            self._all_back.set()

    async def wait_closed(self) -> None:
        await self._all_back.wait()


async def _started(
    cur: _StepCursor,
    handler: Callable[[bytes], Awaitable[str | None]],
    *,
    leader_gate: Callable[[], bool] | None = None,
) -> tuple[DatabaseSource, asyncio.Task[None]]:
    src = _src(body_column="payload")
    src._pool = _CountingPool(_SrcConn(cur))
    src._poll_seconds = 0.0
    await src.start(handler, leader_gate=leader_gate)
    assert src._task is not None
    return src, src._task


async def _cancelled_stop(src: DatabaseSource) -> asyncio.Task[None]:
    stop = asyncio.create_task(src.stop())
    await asyncio.sleep(0)  # stop() is now waiting on the poll task
    stop.cancel()
    await asyncio.sleep(0)
    return stop


async def test_a_cancelled_stop_lets_the_row_in_hand_off_mark_itself() -> None:
    """BACKLOG #1620, ADR 0157 Amendment B: a teardown cancelled from outside cuts every inbound
    stop still running after its grace. Cutting a Database poll between the store commit and the
    mark re-emits that row, a duplicate. So a cancelled stop() first lets the row step finish.
    Mutation: join the task with a cancelling ``gather`` again (head 030780600). Red: the
    handler is cut and the row is never marked."""
    cur = _StepCursor(["id", "payload"], [(1, "AAA"), (2, "BBB")])
    entered = asyncio.Event()
    release = asyncio.Event()
    bodies: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        bodies.append(raw)
        entered.set()
        await release.wait()  # the durable store commit, in flight
        return None

    src, poll = await _started(cur, handler)
    pool = src._pool
    await asyncio.wait_for(entered.wait(), 5.0)
    stop = await _cancelled_stop(src)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    assert poll.done() and not poll.cancelled()  # joined, and it ended on its own
    assert bodies == [b"AAA"]  # the stop check kept the second row back
    assert cur.marks == _MARKED_1
    assert src._task is None and pool.closed  # a popped source leaks no pool


async def test_a_cancelled_stop_lets_a_mark_in_flight_finish() -> None:
    """The protected step covers the mark, not only the hand-off. Mutation: set the flag around the
    handler call alone. Red: the mark is cut and the committed row re-emits."""
    gate = asyncio.Event()
    cur = _StepCursor(["id", "payload"], [(1, "AAA")], mark_gate=gate)

    async def handler(raw: bytes) -> str | None:
        return None

    src, poll = await _started(cur, handler)
    await asyncio.wait_for(cur.in_mark.wait(), 5.0)
    stop = await _cancelled_stop(src)
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    assert not poll.cancelled()
    assert cur.marks == _MARKED_1


async def test_a_hung_row_step_is_cut_after_the_row_grace(monkeypatch: pytest.MonkeyPatch) -> None:
    """The wait for a row step is bounded, so a hung store write or mark cannot make the poll task
    uncuttable. Mutation: wait for the step with no timeout. Red: wait_for times out."""
    monkeypatch.setattr(database_module, "_ROW_STEP_GRACE_S", 0.05)
    entered = asyncio.Event()

    async def handler(raw: bytes) -> str | None:
        entered.set()
        await asyncio.Event().wait()
        return None

    cur = _StepCursor(["id", "payload"], [(1, "AAA")])
    src, poll = await _started(cur, handler)
    await asyncio.wait_for(entered.wait(), 5.0)
    stop = await _cancelled_stop(src)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    assert poll.cancelled()  # cut, and joined before the cancel was re-raised
    assert cur.marks == []
    assert src._task is None


async def test_a_second_cancel_cuts_the_row_step_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second cancel to the stop task, after the first, does not wait out the row grace.
    Mutation: suppress CancelledError around the row-grace wait. Red: wait_for times out."""
    monkeypatch.setattr(database_module, "_ROW_STEP_GRACE_S", 60.0)
    entered = asyncio.Event()

    async def handler(raw: bytes) -> str | None:
        entered.set()
        await asyncio.Event().wait()
        return None

    src, poll = await _started(_StepCursor(["id", "payload"], [(1, "AAA")]), handler)
    await asyncio.wait_for(entered.wait(), 5.0)
    stop = await _cancelled_stop(src)
    stop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    assert poll.cancelled()


async def test_two_coalesced_cancels_cut_the_row_step_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two cancels in one loop turn reach stop() as one CancelledError; the cancelling() baseline
    still reads them as a second cancel. Mutation: drop the ``again`` check. Red: wait_for times
    out on the row grace."""
    monkeypatch.setattr(database_module, "_ROW_STEP_GRACE_S", 60.0)
    entered = asyncio.Event()

    async def handler(raw: bytes) -> str | None:
        entered.set()
        await asyncio.Event().wait()
        return None

    src, poll = await _started(_StepCursor(["id", "payload"], [(1, "AAA")]), handler)
    pool = src._pool
    await asyncio.wait_for(entered.wait(), 5.0)
    stop = asyncio.create_task(src.stop())
    await asyncio.sleep(0)
    stop.cancel()
    stop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    assert poll.cancelled()
    assert pool.closed  # the cancel path still closes the pool


async def test_control_a_cancelled_stop_cuts_a_select_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: outside the row step a cancelled stop() cuts at once, with nothing handed off. One
    row is fully handled first, so this also turns red if the flag is not reset after a row
    (mutation: drop the reset), because the cut would then wait out the row grace."""
    monkeypatch.setattr(database_module, "_ROW_STEP_GRACE_S", 60.0)
    cur = _StepCursor(["id", "payload"], [(1, "AAA")], hang_from=2)
    bodies: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        bodies.append(raw)
        return None

    src, poll = await _started(cur, handler)
    pool = src._pool
    await asyncio.wait_for(cur.in_select.wait(), 5.0)
    assert bodies == [b"AAA"] and cur.marks == _MARKED_1
    stop = await _cancelled_stop(src)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    assert poll.cancelled()
    assert pool.closed and src._task is None


async def test_a_cancel_in_a_cursor_close_still_releases_the_connection() -> None:
    """BACKLOG #1620: ``_close_cursor`` catches ``Exception`` only, so a cancel that lands in the
    close used to skip the ``pool.release`` after it, and the pool then waited for that connection
    forever. The release now waits for the close, which the cancel does not interrupt, so the
    connection never goes back to the pool busy. Red on head 9a719f564: the connection is still
    counted in use after the close has finished."""
    close_gate = asyncio.Event()
    cur = _StepCursor(["id", "payload"], [], close_gate=close_gate)
    src = _src(body_column="payload")
    pool = _CountingPool(_SrcConn(cur))
    src._pool = pool
    mark = asyncio.create_task(src._mark({"id": 1, "payload": "AAA"}))
    await asyncio.wait_for(cur.in_close.wait(), 5.0)
    mark.cancel()
    with pytest.raises(asyncio.CancelledError):
        await mark
    assert pool.in_use == 1  # the close is still running on its driver thread
    close_gate.set()
    await asyncio.wait_for(pool.wait_closed(), 5.0)
    assert pool.in_use == 0


async def _noop(raw: bytes) -> str | None:
    return None


async def _cancelled_in_a_held_mark(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[DatabaseSource, asyncio.Task[None], _CountingPool, asyncio.Task[None], _StepCursor]:
    """Start a poll whose mark never returns and whose cursor close is held on ``close_gate``, then
    cancel stop() once, so the row grace runs out and the cut lands in the mark."""
    monkeypatch.setattr(database_module, "_ROW_STEP_GRACE_S", 0.05)
    monkeypatch.setattr(database_module, "_POOL_CLOSE_TIMEOUT_S", 0.05, raising=False)
    cur = _StepCursor(
        ["id", "payload"], [(1, "AAA")], mark_gate=asyncio.Event(), close_gate=asyncio.Event()
    )
    src, poll = await _started(cur, _noop)
    pool = src._pool
    await asyncio.wait_for(cur.in_mark.wait(), 5.0)
    return src, poll, pool, await _cancelled_stop(src), cur


async def test_a_further_cancel_during_the_cut_cannot_hang_the_pool_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancel to stop() while the cut poll task is in its cursor close is not forwarded into the
    task. stop() returns with the task still registered and the pool closed under it; the held
    connection goes back once its close finishes, and the next stop() joins the task. Red on head
    9a719f564, whose cancelling ``gather`` forwarded the cancel into the close, skipped the
    release, and hung in ``wait_closed``."""
    src, poll, pool, stop, cur = await _cancelled_in_a_held_mark(monkeypatch)
    assert cur.close_gate is not None
    await asyncio.wait_for(cur.in_close.wait(), 5.0)  # the grace ran out and the mark was cut
    stop.cancel()
    done, _ = await asyncio.wait({stop}, timeout=5.0)  # wait: see the next test
    assert done and stop.cancelled()
    assert src._task is poll and not poll.done() and pool.closed and src._pool is None
    cur.close_gate.set()
    await asyncio.wait_for(src.stop(), 5.0)
    assert poll.cancelled() and pool.in_use == 0 and src._task is None
    assert cur.marks == []


async def test_a_cut_task_a_driver_call_holds_does_not_hold_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The join of the cut task is bounded: a cursor close held on a driver thread keeps the task
    alive past the cut, and stop() still returns, with the pool closed so a source nobody stops
    again leaks no connection. Red on head 9a719f564: stop() never returns. ``raising=False`` lets
    the test run, and fail on time, against a head without the bounds."""
    monkeypatch.setattr(database_module, "_CUT_JOIN_TIMEOUT_S", 0.05, raising=False)
    src, poll, pool, stop, cur = await _cancelled_in_a_held_mark(monkeypatch)
    assert cur.close_gate is not None
    try:
        # wait, not wait_for: on a head without the bound, wait_for's own cancel of the hung stop
        # would hang the test instead of failing it.
        done, _ = await asyncio.wait({stop}, timeout=5.0)
        assert done, "a cancelled stop() did not return behind a held driver call"
        assert stop.cancelled()
        assert src._task is poll and not poll.done() and pool.closed
    finally:
        cur.close_gate.set()
        await asyncio.wait_for(asyncio.gather(poll, return_exceptions=True), 5.0)
    await asyncio.wait_for(pool.wait_closed(), 5.0)
    assert pool.in_use == 0


async def test_the_pool_close_is_bounded() -> None:
    """aclose() given a timeout waits for the pool no longer, and drops the pool either way, so a
    connection a hung driver call holds cannot hold a cancelled stop(). Red on head 9a719f564,
    whose aclose() takes no bound."""
    src = _src(body_column="payload")
    pool = _CountingPool(_SrcConn(_SrcCursor([], [])))
    src._pool = pool
    await pool.acquire()  # held, never released
    await asyncio.wait_for(src.aclose(timeout=0.05), 5.0)
    assert pool.closed and src._pool is None


async def test_a_failed_unbounded_pool_close_is_retried_by_the_next_stop() -> None:
    """An uncancelled stop() keeps the pool until its close succeeds, so a retried stop() finishes
    the close. Mutation: drop the reference before the unbounded wait. Red: the retry sees no pool
    and the close is never finished."""

    class _FailOnce(_SrcPool):
        def __init__(self, conn: _SrcConn) -> None:
            super().__init__(conn)
            self.attempts = 0

        async def wait_closed(self) -> None:
            self.attempts += 1
            if self.attempts == 1:
                raise RuntimeError("close failed")

    src = _src(body_column="payload")
    pool = _FailOnce(_SrcConn(_SrcCursor([], [])))
    src._pool = pool
    with pytest.raises(RuntimeError):
        await src.stop()
    assert src._pool is pool
    await src.stop()
    assert pool.attempts == 2 and src._pool is None


@pytest.mark.parametrize("leader", [True, False])
async def test_the_row_grace_is_fenced_on_leadership(
    monkeypatch: pytest.MonkeyPatch, leader: bool
) -> None:
    """ADR 0157: a demoted node must not keep writing to the shared poll table, so a cancelled
    stop() gives the row step its grace only while this node leads; a non-leader cuts at once. The
    leader case is the control. Red on head 9a719f564 (leader=False): wait_for times out on the
    row grace."""
    monkeypatch.setattr(database_module, "_ROW_STEP_GRACE_S", 60.0)
    leads = [True]
    entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(raw: bytes) -> str | None:
        entered.set()
        await release.wait()  # the durable store commit, in flight
        return None

    cur = _StepCursor(["id", "payload"], [(1, "AAA")])
    src, poll = await _started(cur, handler, leader_gate=lambda: leads[0])
    await asyncio.wait_for(entered.wait(), 5.0)
    leads[0] = leader  # a demotion clears the cached gate before the teardown runs
    stop = await _cancelled_stop(src)
    if leader:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    if leader:
        assert not poll.cancelled() and cur.marks == _MARKED_1
    else:
        assert poll.cancelled() and cur.marks == []


async def test_a_demotion_during_the_row_grace_ends_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """Leadership is re-read during the grace, not only when the cancel lands. Mutation: read it
    once. Red: wait_for times out on the row grace."""
    monkeypatch.setattr(database_module, "_ROW_STEP_GRACE_S", 60.0)
    leads = [True]
    entered = asyncio.Event()

    async def handler(raw: bytes) -> str | None:
        entered.set()
        await asyncio.Event().wait()
        return None

    cur = _StepCursor(["id", "payload"], [(1, "AAA")])
    src, poll = await _started(cur, handler, leader_gate=lambda: leads[0])
    await asyncio.wait_for(entered.wait(), 5.0)
    stop = await _cancelled_stop(src)
    await asyncio.sleep(0.1)  # inside the grace, still the leader
    assert not stop.done()
    leads[0] = False
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stop, 5.0)
    assert poll.cancelled() and cur.marks == []


@pytest.mark.parametrize("missing", ["server", "database", "poll_statement"])
def test_source_requires_core_settings(missing: str) -> None:
    base: dict[str, Any] = dict(server="s", database="d", poll_statement=POLL)  # noqa: C408
    base[missing] = ""
    with pytest.raises(ValueError):
        build_source(
            Source(type=ConnectorType.DATABASE, settings=DatabasePoll(**base).settings),
            egress=EgressSettings(deny_by_default=False),
        )


# --- source connect-allowlist ([egress].allowed_db) --------------------------


def _src_cfg(server: str, port: int = 1433) -> Source:
    return Source(
        type=ConnectorType.DATABASE,
        settings=DatabasePoll(server=server, database="d", poll_statement=POLL, port=port).settings,
    )


def test_source_connect_blocks_unlisted_server() -> None:
    with pytest.raises(WiringError):
        check_source_allowed(
            _src_cfg("other.example.com"), "IB_DB", EgressSettings(allowed_db=["sql.example.com"])
        )


def test_source_connect_permits_listed_server() -> None:
    check_source_allowed(
        _src_cfg("sql.example.com"), "IB_DB", EgressSettings(allowed_db=["sql.example.com"])
    )


def test_source_connect_unrestricted_when_empty() -> None:
    check_source_allowed(
        _src_cfg("anywhere.example"), "IB_DB", EgressSettings(deny_by_default=False)
    )


def test_source_connect_ignores_non_database_source() -> None:
    mllp = Source(type=ConnectorType.MLLP, settings={"port": 2575})
    check_source_allowed(mllp, "IB_MLLP", EgressSettings(allowed_db=["sql.example.com"]))
