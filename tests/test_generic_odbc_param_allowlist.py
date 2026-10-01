# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The generic ODBC dialect takes its connection target from ``server`` alone (vault BACKLOG #2577).

``[egress].allowed_db`` is checked against the ``server`` setting, so ``server`` has to be the only
setting that can tell the driver where to connect. The generic dialect also takes free driver
keywords in ``odbc_params``, and the name of the keyword each credential is sent under. Those are the
other places a keyword can come from, so this file pins all three:

* ``odbc_params`` accepts a fixed list of keywords. Anything else is refused when the connection is
  built, with the keyword and the connection named. The list is an allowlist on purpose: every ODBC
  driver has its own spellings for a host, an address, a data source name or a socket, so a list of
  refused names would always trail the drivers.
* ``odbc_user_key`` and ``odbc_password_key`` accept the credential keywords and nothing else.
* Every value must be printable ASCII. An ``odbc_params`` value, the driver, the database and the
  user name also refuse the characters that end a connection-string value. A password keeps the
  ODBC escape, so it may hold any printable ASCII character.
* A keyword given twice is refused, and a file keyword must be a plain local path.

Each refusal is paired with a control that must still build, and the control uses the same builder
and the same settings. Nothing here opens a connection: the refusal is in the string builder, which
runs before any driver is loaded.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    Database,
    DatabasePoll,
    Registry,
    WiringError,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import build_check_registry
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import build_destination, build_source
from messagefoundry.transports.database import (
    _ODBC_PARAM_ALLOWLIST,
    _ODBC_PASSWORD_KEYS,
    _ODBC_PATH_KEYS,
    _ODBC_USER_KEYS,
    DatabaseDestination,
    DatabaseSource,
    _build_odbc_dsn,
    _odbc_keyword_name,
)

_CONNECTION = "OB_DB_GEN"
# A value no refusal may repeat: a refusal names the keyword, never what it was set to.
_VALUE = "value-that-must-not-be-echoed"


def _settings(**overrides: Any) -> dict[str, Any]:
    settings: dict[str, Any] = {
        "dialect": "generic",
        "odbc_driver": "PostgreSQL Unicode",
        "server": "db.test",
    }
    settings.update(overrides)
    return settings


def _build(**overrides: Any) -> str:
    return _build_odbc_dsn(_settings(**overrides), connection=_CONNECTION)


# --- odbc_params keywords ----------------------------------------------------------------------

# Keywords that are not on the list. The first group are other names for where to connect, taken
# from the Microsoft, PostgreSQL, MySQL and Oracle ODBC drivers. The second group pass a whole
# option string, a file or SQL to the driver. The third are the connector's own typed settings.
# The last is a name no driver has, which is the case the allowlist exists for.
_REFUSED_KEYWORDS = [
    "Address",
    "Addr",
    "addr",
    "ADDRESS",
    "Network Address",
    "Servername",
    "Host",
    "HostAddr",
    "DBQ",
    "DSN",
    "FILEDSN",
    "SAVEFILE",
    "Failover_Partner",
    "Failover Partner",
    "ServerSPN",
    "Socket",
    "MULTI_HOST",
    "ENABLE_DNS_SRV",
    "pqopt",
    "ConnSettings",
    "INITSTMT",
    "PLUGIN_DIR",
    "DRIVER",
    "server",
    "Database",
    "UID",
    "PWD",
    "TrustServerCertificate",
    "SomeFutureKeyword",
]


@pytest.mark.parametrize("keyword", _REFUSED_KEYWORDS)
def test_a_keyword_off_the_list_is_refused(keyword: str) -> None:
    with pytest.raises(ValueError, match="must not set") as refused:
        _build(odbc_params={"SSLmode": "verify-full", keyword: _VALUE})
    message = str(refused.value)
    named = f"'{_odbc_keyword_name(keyword)}'"
    assert named in message
    assert _CONNECTION in message
    assert _VALUE not in message
    # The log scrub reads `<credential word>: x` as a credential pair, and a refused keyword may end
    # in such a word, so the refusal must not put either separator after the keyword.
    assert f"{named}:" not in message
    assert f"{named}=" not in message
    # A failed lane stores the scrubbed, shortened form. It must still say which keyword to remove
    # and where the list is.
    stored = safe_exc(refused.value)
    assert named in stored
    assert "docs/CONNECTIONS.md" in stored


# `sslkey` names a file the builder opens to check its passphrase wrap, so a placeholder value cannot
# stand in for it. tests/test_keywrap.py builds it with a real key file.
@pytest.mark.parametrize("keyword", sorted(_ODBC_PARAM_ALLOWLIST - {"sslkey"}))
def test_every_listed_keyword_still_builds(keyword: str) -> None:
    dsn = _build(odbc_params={keyword: "1"})
    assert dsn.endswith(f"{keyword}={{1}};")


@pytest.mark.parametrize("spelling", ["PORT", "Port", "port", "pOrT"])
def test_a_listed_keyword_matches_in_any_case(spelling: str) -> None:
    assert f"{spelling}={{5432}}" in _build(odbc_params={spelling: 5432})


def test_every_path_keyword_is_a_listed_keyword() -> None:
    assert _ODBC_PATH_KEYS <= _ODBC_PARAM_ALLOWLIST


def test_the_list_holds_no_keyword_the_connector_emits_itself() -> None:
    # `server`, `database`, the driver and the two credentials each have a typed setting. A second
    # copy in odbc_params would leave the driver to choose between the two.
    own = {"driver", "server", "database"} | _ODBC_USER_KEYS | _ODBC_PASSWORD_KEYS
    assert not own & _ODBC_PARAM_ALLOWLIST


def test_the_list_is_stored_in_the_form_keywords_are_compared_in() -> None:
    for keyword in _ODBC_PARAM_ALLOWLIST | _ODBC_USER_KEYS | _ODBC_PASSWORD_KEYS:
        assert keyword == _odbc_keyword_name(keyword)


# The keyword is sent as spelled and not every driver trims it, so a spelling that needs trimming
# is refused: the engine must not judge a keyword the driver would then ignore.
@pytest.mark.parametrize(
    "keyword", ["PORT\n", " PORT", "PORT ", "SSLmode  ", "Network  Address", "SSL-MODE"]
)
def test_a_keyword_of_the_wrong_shape_is_refused_and_names_the_connection(keyword: str) -> None:
    with pytest.raises(ValueError, match="not a valid ODBC keyword") as refused:
        _build(odbc_params={keyword: "5432"})
    assert _CONNECTION in str(refused.value)


@pytest.mark.parametrize(
    "params",
    [
        {"PORT": 5432, "port": 5433},
        {"SSLmode": "verify-full", "sslmode": "verify-ca"},
        {"Fetch": 1, "FETCH": 1},
    ],
)
def test_a_keyword_given_twice_is_refused(params: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="more than once") as refused:
        _build(odbc_params=params)
    assert _CONNECTION in str(refused.value)
    # Control: either copy alone builds.
    for keyword, value in params.items():
        assert f"{keyword}={{{value}}}" in _build(odbc_params={keyword: value})


# --- the keyword each credential is sent under ---------------------------------------------------


@pytest.mark.parametrize("setting", ["odbc_user_key", "odbc_password_key"])
@pytest.mark.parametrize("keyword", ["Servername", "Address", "DBQ", "DSN", "PORT", "SSLmode"])
def test_a_credential_keyword_off_its_list_is_refused(setting: str, keyword: str) -> None:
    with pytest.raises(ValueError, match=f"{setting} must be one of") as refused:
        _build(username=_VALUE, password=_VALUE, **{setting: keyword})
    message = str(refused.value)
    assert f"'{_odbc_keyword_name(keyword)}'" in message
    assert _CONNECTION in message
    assert _VALUE not in message


@pytest.mark.parametrize(
    ("user_key", "password_key"),
    [("UID", "PWD"), ("USER", "PASSWORD"), ("Username", "Password"), ("User ID", "pwd")],
)
def test_the_credential_keywords_drivers_use_still_build(user_key: str, password_key: str) -> None:
    dsn = _build(
        username="svc", password="pw", odbc_user_key=user_key, odbc_password_key=password_key
    )
    assert f"{user_key}={{svc}}" in dsn
    assert f"{password_key}={{pw}}" in dsn


# --- values --------------------------------------------------------------------------------------

# A value is sent inside braces. The first three are the characters that could end it early in a
# driver that reads the braces differently from the ODBC rule. Then the control characters. The rest
# are not ASCII: a driver manager that converts the string for a narrow-interface driver can turn
# such a character into an ASCII delimiter, and which ones depends on the platform and code page,
# so every non-ASCII character is refused. The samples are a fullwidth form, a character whose low
# byte is a delimiter, and an ordinary accented letter.
_NON_ASCII = ["\uff1b", "\uff5d", "\u017d", "\u013b", "\u00e9"]
_REFUSED_VALUE_CHARACTERS = [";", "{", "}", "\n", "\r", "\x00", "\x7f", *_NON_ASCII]


@pytest.mark.parametrize("character", _REFUSED_VALUE_CHARACTERS)
def test_a_value_holding_a_connection_string_delimiter_is_refused(character: str) -> None:
    value = f"{_VALUE}{character}{_VALUE}"
    with pytest.raises(
        ValueError, match="odbc_params value for 'sslmode' must hold only printable ASCII"
    ) as refused:
        _build(odbc_params={"SSLmode": value})
    message = str(refused.value)
    assert _CONNECTION in message
    assert _VALUE not in message


@pytest.mark.parametrize("setting", ["odbc_driver", "database", "username"])
@pytest.mark.parametrize("character", [";", "{", "}", "\n", *_NON_ASCII])
def test_a_typed_setting_holding_a_delimiter_is_refused(setting: str, character: str) -> None:
    with pytest.raises(ValueError, match=f"DATABASE {setting} must hold only printable") as refused:
        _build(**{setting: f"{_VALUE}{character}{_VALUE}"})
    message = str(refused.value)
    assert _CONNECTION in message
    assert _VALUE not in message


@pytest.mark.parametrize("character", ["\n", "\x00", *_NON_ASCII])
def test_a_password_must_be_printable_ascii(character: str) -> None:
    with pytest.raises(ValueError, match="DATABASE password must hold only printable") as refused:
        _build(username="svc", password=f"{_VALUE}{character}{_VALUE}")
    message = str(refused.value)
    assert _CONNECTION in message
    assert _VALUE not in message
    assert "none of" not in message


def test_a_password_may_hold_any_printable_ascii_character() -> None:
    # A password cannot be restricted the way the other values are, so it keeps the ODBC escape:
    # a closing brace is doubled, and the other delimiters sit inside the braces.
    assert "PWD={p;w{d=1 x}}y}" in _build(username="svc", password="p;w{d=1 x}y")


@pytest.mark.parametrize("character", [";", "{", "}", "=", "\n", "\t", *_NON_ASCII])
def test_a_server_holding_a_delimiter_is_refused(character: str) -> None:
    with pytest.raises(ValueError, match="server must not contain") as refused:
        _build(server=f"db.test{character}x")
    assert _CONNECTION in str(refused.value)


# --- file keywords -------------------------------------------------------------------------------


@pytest.mark.parametrize("keyword", ["sslca", "SSLCAPATH", "sslcert", "SSLKEY"])
@pytest.mark.parametrize(
    "path",
    [
        r"\\files.test\share\ca.pem",
        "//files.test/share/ca.pem",
        r" \\files.test\share\ca.pem",
        r"\??\UNC\files.test\share\ca.pem",
        r"\\?\UNC\files.test\share\ca.pem",
    ],
)
def test_a_file_keyword_must_be_a_plain_local_path(keyword: str, path: str) -> None:
    with pytest.raises(ValueError, match="must be a plain local path") as refused:
        _build(odbc_params={keyword: path})
    message = str(refused.value)
    assert _CONNECTION in message
    assert "files.test" not in message


@pytest.mark.parametrize(
    "value",
    [r"C:\ProgramData\certs\root ca.crt", "/etc/ssl/certs/ca=1.pem", "TLSv1.2,TLSv1.3", 5432, True],
)
def test_an_ordinary_value_still_builds(value: object) -> None:
    assert f"sslca={{{value}}}" in _build(odbc_params={"sslca": value})


# --- the connector seams, and the documented example ---------------------------------------------

_INSERT = "INSERT INTO obs (mrn, value) VALUES (:mrn, :value)"


def _documented_destination(odbc_params: dict[str, Any]) -> Destination:
    """The generic example in docs/CONNECTIONS.md, with literals where it uses ``env()``."""
    return Destination(
        name="DB-OUT_ACME_PG",
        type=ConnectorType.DATABASE,
        settings=Database(
            dialect="generic",
            odbc_driver="PostgreSQL Unicode",
            server="pg.test",
            database="results",
            username="svc",
            password="pw",
            odbc_params=odbc_params,
            statement=_INSERT,
        ).settings,
    )


def _documented_source(odbc_params: dict[str, Any]) -> Source:
    return Source(
        name="DB-IN_ACME_PG",
        type=ConnectorType.DATABASE,
        settings=DatabasePoll(
            dialect="generic",
            odbc_driver="PostgreSQL Unicode",
            server="pg.test",
            database="results",
            username="svc",
            password="pw",
            odbc_params=odbc_params,
            poll_statement="SELECT id, payload FROM mf_inbox",
        ).settings,
    )


_DOCUMENTED_PARAMS: dict[str, Any] = {"PORT": 5432, "SSLmode": "verify-full"}
_DOCUMENTED_DSN = (
    "DRIVER={PostgreSQL Unicode};SERVER=pg.test;DATABASE={results};UID={svc};PWD={pw};"
    "PORT={5432};SSLmode={verify-full};"
)


def test_the_documented_generic_example_builds_as_a_destination() -> None:
    connector = build_destination(_documented_destination(dict(_DOCUMENTED_PARAMS)))
    assert isinstance(connector, DatabaseDestination)
    assert connector._dsn == _DOCUMENTED_DSN


def test_the_documented_generic_example_builds_as_a_poll_source() -> None:
    connector = build_source(_documented_source(dict(_DOCUMENTED_PARAMS)))
    assert isinstance(connector, DatabaseSource)
    assert connector._dsn == _DOCUMENTED_DSN


def test_the_destination_seam_refuses_a_keyword_off_the_list() -> None:
    config = _documented_destination(_DOCUMENTED_PARAMS | {"Servername": _VALUE})
    with pytest.raises(ValueError, match="must not set 'servername'") as refused:
        build_destination(config)
    assert "DB-OUT_ACME_PG" in str(refused.value)
    assert _VALUE not in str(refused.value)


def test_the_poll_source_seam_refuses_a_keyword_off_the_list() -> None:
    config = _documented_source(_DOCUMENTED_PARAMS | {"Servername": _VALUE})
    with pytest.raises(ValueError, match="must not set 'servername'") as refused:
        build_source(config)
    assert "DB-IN_ACME_PG" in str(refused.value)
    assert _VALUE not in str(refused.value)


def _check_build(params: dict[str, Any]) -> None:
    """The construct-and-discard pass `messagefoundry check`, a reload and the `connection` edit all
    run, over a registry holding the documented example."""
    registry = Registry()
    registry.add_outbound(
        build_outbound_connection(
            "DB-OUT_ACME_PG",
            Database(
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                server="pg.test",
                database="results",
                username="svc",
                password="pw",
                odbc_params=params,
                statement=_INSERT,
            ),
        )
    )
    build_check_registry(
        registry, inbound_bind_host="127.0.0.1", env_values={}, egress=EgressSettings()
    )


def test_the_build_check_refuses_a_keyword_off_the_list() -> None:
    with pytest.raises(WiringError, match="must not set 'servername'") as refused:
        _check_build(_DOCUMENTED_PARAMS | {"Servername": _VALUE})
    assert "DB-OUT_ACME_PG" in str(refused.value)
    assert _VALUE not in str(refused.value)


def test_the_build_check_passes_the_documented_generic_example() -> None:
    _check_build(dict(_DOCUMENTED_PARAMS))


def test_the_sql_server_preset_never_reads_odbc_params() -> None:
    # The preset builds its own string from typed settings, so a keyword here cannot reach the driver
    # and there is nothing for the list to refuse.
    settings = Database(
        server="sql.test",
        database="results",
        username="svc",
        password="pw",
        odbc_params={"Servername": _VALUE},
        statement=_INSERT,
    ).settings
    connector = build_destination(
        Destination(name="DB-OUT_ACME_SQL", type=ConnectorType.DATABASE, settings=settings)
    )
    assert isinstance(connector, DatabaseDestination)
    assert _VALUE not in connector._dsn
    assert "Servername" not in connector._dsn


# --- the operator doc names the same list ------------------------------------------------------


def test_the_operator_doc_names_every_listed_keyword_and_no_other() -> None:
    """docs/CONNECTIONS.md prints the list, so a keyword added here without the doc, or the reverse,
    fails rather than drifting."""
    doc = (Path(__file__).resolve().parent.parent / "docs" / "CONNECTIONS.md").read_text(
        encoding="utf-8"
    )
    marker = re.search(
        r"<!-- odbc-params-allowlist:start -->(.*?)<!-- odbc-params-allowlist:end -->", doc, re.S
    )
    assert marker is not None, "the generic ODBC section lost its keyword-list markers"
    named = {name.lower() for name in re.findall(r"`([^`]+)`", marker.group(1))}
    assert named == set(_ODBC_PARAM_ALLOWLIST)
