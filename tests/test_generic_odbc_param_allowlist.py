# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The generic ODBC dialect's keyword lists cover keywords only (vault BACKLOG #2577).

``[egress].allowed_db`` reads the host from the ``server`` setting, so the list is hand-chosen, no
keyword is on it in order to name a host, and a file keyword's value is screened
separately by spelling. The lists rely on at least a driver named on the escape list reading the
``}}`` escape in a braced password, and the driver reading ``SERVER`` as its target
(docs/CONNECTIONS.md, *Accepted ``odbc_params`` keywords*). The generic dialect also takes free driver keywords in ``odbc_params``, and the name of
the keyword each credential is sent under. Those are the other places a keyword can come from, so
this file pins all three:

* ``odbc_params`` accepts a fixed list of keywords. Anything else is refused when the connection is
  built, with the keyword and the connection named. The list is an allowlist on purpose: every ODBC
  driver has its own spellings for a host, an address, a data source name or a socket, so a list of
  refused names would always trail the drivers.
* ``odbc_user_key`` and ``odbc_password_key`` accept the credential keywords and nothing else.
* Every value must be printable ASCII. An ``odbc_params`` value, the database and the user name are
  sent without braces (BACKLOG #2705), so they refuse ``;``, ``{``, ``}`` and ``=``, and an empty,
  blank or padded value, and ``None``. The driver name stays braced and refuses ``;``, ``{`` and
  ``}``. A password is always braced with the ODBC escape for a driver on the escape list, and for
  any other driver sent plain when it can be and refused when it cannot.
* A keyword given twice is refused, and a file keyword must be a plain local path.

Each refusal is paired with a control that must still build, and the control uses the same builder
and the same settings. Nothing here opens a connection: the refusal is in the string builder, which
runs before any driver is loaded.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.anchor_path import DIRECTORY, FILE, LINK
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
from messagefoundry.transports import database
from messagefoundry.transports.base import build_destination, build_source
from messagefoundry.transports.database import (
    _ODBC_PARAM_ALLOWLIST,
    _ODBC_PASSWORD_KEYS,
    _ODBC_PATH_KEYS,
    _ODBC_USER_KEYS,
    DatabaseDestination,
    DatabaseSource,
    _build_odbc_dsn,
)
from messagefoundry.transports.db_endpoint import odbc_keyword_name

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
    named = f"'{odbc_keyword_name(keyword)}'"
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
    # sslmode takes a libpq mode for this psqlODBC driver (BACKLOG #2705); every other keyword "1".
    value = "require" if keyword == "sslmode" else "1"
    dsn = _build(odbc_params={keyword: value})
    assert dsn.endswith(f"{keyword}={value};")


@pytest.mark.parametrize("spelling", ["PORT", "Port", "port", "pOrT"])
def test_a_listed_keyword_matches_in_any_case(spelling: str) -> None:
    assert f"{spelling}=5432;" in _build(odbc_params={spelling: 5432})


def test_every_path_keyword_is_a_listed_keyword() -> None:
    assert _ODBC_PATH_KEYS <= _ODBC_PARAM_ALLOWLIST


def test_the_list_holds_no_keyword_the_connector_emits_itself() -> None:
    # `server`, `database`, the driver and the two credentials each have a typed setting. A second
    # copy in odbc_params would leave the driver to choose between the two.
    own = {"driver", "server", "database"} | _ODBC_USER_KEYS | _ODBC_PASSWORD_KEYS
    assert not own & _ODBC_PARAM_ALLOWLIST


def test_the_list_is_stored_in_the_form_keywords_are_compared_in() -> None:
    for keyword in _ODBC_PARAM_ALLOWLIST | _ODBC_USER_KEYS | _ODBC_PASSWORD_KEYS:
        assert keyword == odbc_keyword_name(keyword)


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
        assert f"{keyword}={value};" in _build(odbc_params={keyword: value})


# --- the keyword each credential is sent under ---------------------------------------------------


@pytest.mark.parametrize("setting", ["odbc_user_key", "odbc_password_key"])
@pytest.mark.parametrize("keyword", ["Servername", "Address", "DBQ", "DSN", "PORT", "SSLmode"])
def test_a_credential_keyword_off_its_list_is_refused(setting: str, keyword: str) -> None:
    with pytest.raises(ValueError, match=f"{setting} must be one of") as refused:
        _build(username=_VALUE, password=_VALUE, **{setting: keyword})
    message = str(refused.value)
    assert f"'{odbc_keyword_name(keyword)}'" in message
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
    assert f"{user_key}=svc;" in dsn
    # The default driver is psqlODBC, so the password is braced (BACKLOG #2705).
    assert f"{password_key}={{pw}};" in dsn


# --- values --------------------------------------------------------------------------------------

# A value is sent WITHOUT braces (BACKLOG #2705). The first four are the characters that could end
# it early or start another keyword. Then the control characters. The rest
# are not ASCII: a driver manager that converts the string for a narrow-interface driver can turn
# such a character into an ASCII delimiter, and which ones depends on the platform and code page,
# so every non-ASCII character is refused. The samples are a fullwidth form, a character whose low
# byte is a delimiter, and an ordinary accented letter.
_NON_ASCII = ["\uff1b", "\uff5d", "\u017d", "\u013b", "\u00e9"]
# The two quote characters are refused too: on main they sat inside braces, and how a driver reads
# one in a plain value is unmeasured. Red on the previous head, which sent them plain.
_QUOTES = ['"', "'"]
_REFUSED_VALUE_CHARACTERS = [";", "{", "}", "=", *_QUOTES, "\n", "\r", "\x00", "\x7f", *_NON_ASCII]


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


@pytest.mark.parametrize(
    ("setting", "character"),
    [
        (setting, character)
        for setting in ("odbc_driver", "database", "username")
        for character in [";", "{", "}", "=", *_QUOTES, "\n", *_NON_ASCII]
        # The driver name stays braced, so `=` and the quotes are refused only in the values sent
        # without braces.
        if setting != "odbc_driver" or character not in ["=", *_QUOTES]
    ],
)
def test_a_typed_setting_holding_a_delimiter_is_refused(setting: str, character: str) -> None:
    with pytest.raises(ValueError, match=f"DATABASE {setting} must hold only printable") as refused:
        _build(**{setting: f"{_VALUE}{character}{_VALUE}"})
    message = str(refused.value)
    assert _CONNECTION in message
    assert _VALUE not in message


# --- values sent without braces (BACKLOG #2705) ---------------------------------------------------

_PADDING = "must not be empty, blank, or start or end with a space"


def test_the_built_psqlodbc_string_sends_every_checked_value_unbraced() -> None:
    """psqlODBC did not honour ``SSLmode={verify-full}`` (2026-10-30 probe: it connected with no
    TLS), kept braces on UID and DATABASE, and refused a braced port. Red before #2705. The
    password alone stays braced: psqlODBC URL-decodes an unbraced one."""
    dsn = _build(
        database="results",
        username="svc",
        password="pw",
        odbc_params={"port": 5432, "SSLmode": "verify-full"},
    )
    assert dsn == (
        "DRIVER={PostgreSQL Unicode};SERVER=db.test;DATABASE=results;UID=svc;PWD={pw};"
        "port=5432;SSLmode=verify-full;"
    )


@pytest.mark.parametrize("value", ["", " ", "  ", " verify-full", "verify-full "])
def test_an_empty_blank_or_padded_odbc_params_value_is_refused(value: str) -> None:
    """An unbraced empty ``sslmode`` is the driver's default, and libpq's default ``prefer`` falls
    back to plaintext. The build refuses it; ``generic_odbc_tls_unenforced`` is left alone, since
    no connection reaches the driver with such a value. A padded value may be trimmed by one
    driver and kept by another. Red before #2705, which sent ``SSLmode={}``."""
    with pytest.raises(ValueError, match=f"odbc_params value for 'sslmode' {_PADDING}") as refused:
        _build(odbc_params={"SSLmode": value})
    assert _CONNECTION in str(refused.value)
    # The control: the same keyword with a plain value builds.
    assert "SSLmode=verify-full;" in _build(odbc_params={"SSLmode": "verify-full"})


@pytest.mark.parametrize("setting", ["database", "username"])
@pytest.mark.parametrize("value", [" ", " name", "name "])
def test_a_blank_or_padded_typed_setting_is_refused(setting: str, value: str) -> None:
    with pytest.raises(ValueError, match=f"DATABASE {setting} {_PADDING}") as refused:
        _build(**{setting: value})
    assert _CONNECTION in str(refused.value)


# --- the password (BACKLOG #2705) ------------------------------------------------------------------

_ESCAPE_DRIVERS = [
    # The bare section name RHEL registers psqlODBC under. Red on the previous head.
    "PostgreSQL",
    "postgresql",
    "PostgreSQL Unicode",
    "PostgreSQL ANSI",
    "PostgreSQL ANSI(x64)",
    "postgresql unicode",
    "MySQL ODBC 9.1 Unicode Driver",
    "MySQL ODBC 8.0 ANSI Driver",
    "PostgreSQL Unicode(x64)",
    "ODBC Driver 18 for SQL Server",
]
_OTHER_DRIVERS = [
    # The legacy name: on Linux commonly a FreeTDS alias, which has not been measured.
    "SQL Server",
    "Microsoft Access Driver (*.mdb, *.accdb)",
    "SQLite3 ODBC Driver",
    "Oracle in OraClient19Home1",
    "MariaDB ODBC 3.2 Driver",
    # Another registered name that only folds to a measured one.
    "PostgreSQL  Unicode",
    # An older psqlODBC name on Windows, not on the list, and a near miss of the bare name.
    "PostgreSQL35W",
    "PostgreSQL(x64)",
    # A vendor driver for a measured database, and a library path, are unmeasured.
    "Devart ODBC Driver for PostgreSQL",
    "CData ODBC Driver for MySQL",
    "/usr/lib/x86_64-linux-gnu/odbc/psqlodbcw.so",
    "/opt/microsoft/msodbcsql18/lib64/libmsodbcsql-18.so",
]
_NEEDS_BRACES = ["p}w", "p;w", "p{w", 'p"w', "p'w", " pw", "pw ", "a};DBQ=C:\\x.accdb;X=}"]


@pytest.mark.parametrize("driver", _OTHER_DRIVERS)
@pytest.mark.parametrize("password", ["pw", "p=w", "p w", "a+b%41c"])
def test_a_password_with_no_delimiter_is_sent_unbraced_to_any_other_driver(
    driver: str, password: str
) -> None:
    """ACE rejects any braced password, even one with no brace in it (2026-10-30 probe), so for a
    driver off the escape list a password that needs no braces is sent without them."""
    assert f"PWD={password};" in _build(odbc_driver=driver, username="svc", password=password)


@pytest.mark.parametrize("driver", _ESCAPE_DRIVERS)
@pytest.mark.parametrize("password", ["pw", "p=w", "p w", "a+b%41c", *_NEEDS_BRACES])
def test_a_password_is_always_braced_for_a_driver_on_the_escape_list(
    driver: str, password: str
) -> None:
    """psqlODBC URL-decodes an unbraced ``PWD`` (``+`` becomes a space, ``%41`` an ``A``) and takes a
    braced one literally, and psqlODBC and MySQL honoured the ``}}`` escape on 2026-10-30. So for a
    driver on the list every password is braced, as main always did. Red on the previous head,
    which sent ``pw`` and ``a+b%41c`` plain."""
    escaped = "{" + password.replace("}", "}}") + "}"
    assert f"PWD={escaped};" in _build(odbc_driver=driver, username="svc", password=password)


def test_a_psqlodbc_password_holding_url_escapes_is_built_braced() -> None:
    dsn = _build(username="svc", password="a+b%41c")
    assert dsn == "DRIVER={PostgreSQL Unicode};SERVER=db.test;UID=svc;PWD={a+b%41c};"


@pytest.mark.parametrize("driver", _OTHER_DRIVERS)
@pytest.mark.parametrize("password", _NEEDS_BRACES)
def test_a_password_needing_braces_is_refused_for_any_other_driver(
    driver: str, password: str
) -> None:
    """ACE did not read the escape: ``PWD={a}};DBQ=...;X=}`` opened the file the password named
    (2026-10-30 probe). An unmeasured driver is refused the same way, and the legacy ``SQL Server``
    name with it. The refusal says only that the driver cannot carry the password."""
    with pytest.raises(ValueError, match="password cannot be carried by this odbc_driver") as r:
        _build(odbc_driver=driver, username="svc", password=password)
    message = str(r.value)
    assert _CONNECTION in message
    assert password.strip() not in message
    # Nothing about what the password holds.
    assert "brace" not in message and "space" not in message and "';'" not in message


# --- None is refused, never sent as text (BACKLOG #2705) ------------------------------------------


@pytest.mark.parametrize("keyword", ["SSLmode", "PORT", "SSLCA"])
def test_a_none_odbc_params_value_is_refused(keyword: str) -> None:
    """``str(None)`` would send the four letters ``None``. Red on the previous head, which sent
    ``SSLmode=None``."""
    name = odbc_keyword_name(keyword)
    with pytest.raises(ValueError, match=f"odbc_params value for '{name}' must not be None") as r:
        _build(odbc_params={keyword: None})
    assert _CONNECTION in str(r.value)


def test_a_none_server_is_refused() -> None:
    with pytest.raises(ValueError, match="DATABASE server must not be None") as refused:
        _build(server=None)
    assert _CONNECTION in str(refused.value)


@pytest.mark.parametrize("setting", ["database", "username", "password"])
def test_an_unset_typed_setting_is_left_out_not_sent_as_none(setting: str) -> None:
    # The control: an unset optional setting is omitted, as it always was.
    assert "None" not in _build(**{setting: None})


@pytest.mark.parametrize("character", ["\n", "\x00", *_NON_ASCII])
def test_a_password_must_be_printable_ascii(character: str) -> None:
    with pytest.raises(ValueError, match="DATABASE password must hold only printable") as refused:
        _build(username="svc", password=f"{_VALUE}{character}{_VALUE}")
    message = str(refused.value)
    assert _CONNECTION in message
    assert _VALUE not in message
    assert "none of" not in message


def test_a_password_may_hold_any_printable_ascii_character_for_a_measured_driver() -> None:
    # For a driver measured to read the ODBC escape, a closing brace is doubled and the other
    # delimiters sit inside the braces.
    dsn = _build(odbc_driver="PostgreSQL Unicode", username="svc", password="p;w{d=1 x}y")
    assert "PWD={p;w{d=1 x}}y}" in dsn


@pytest.mark.parametrize("character", [";", "{", "}", "=", *_QUOTES, "\n", "\t", *_NON_ASCII])
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


@pytest.mark.parametrize("verdict", [True, None])
def test_a_file_keyword_that_leads_off_the_host_or_cannot_be_cleared_is_refused(
    monkeypatch: pytest.MonkeyPatch, verdict: bool | None
) -> None:
    """BACKLOG #2705, limb 4: a mapped drive or a link passes the spelling check, so where the path
    leads is judged too, and a path the walk cannot clear is refused. No check opens it either. The
    cases of that judgement are pinned against the walk below. Red with ``names_another_host``
    back on the spelling alone."""
    sent = r"Z:\certs\ca.pem"
    monkeypatch.setattr(database, "_path_verdict", lambda p: verdict)
    with pytest.raises(ValueError, match="must be a plain local path") as refused:
        _build(odbc_params={"sslca": sent})
    assert "Z:" not in str(refused.value)
    assert database.driver_file_spellings(sent) == ()


def test_a_padded_spelling_the_walk_cannot_clear_is_read_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A padded spelling whose verdict is ``None``, beside a trimmed spelling whose verdict is
    ``False``, is kept by ``driver_file_spellings``, and the build reads it and refuses the value
    when that read fails. With the padded spelling's verdict ``True``, the build refuses the value.
    Red with ``driver_file_spellings`` keeping only the spellings whose verdict is ``False``."""
    sent = r" C:\certs\ca.pem"
    verdicts: dict[str, bool | None] = {sent: None, sent.strip(): False}
    monkeypatch.setattr(database, "_path_verdict", lambda p: verdicts[p])
    assert database.driver_file_spellings(sent) == (sent, sent.strip())

    read: list[str] = []

    def reading(path: str, _limit: int) -> bytes:
        read.append(path)
        if path == sent:
            raise PermissionError(5, "denied")  # what a walk stopped on, met again by the read
        return b"-----BEGIN CERTIFICATE-----\n"

    monkeypatch.setattr(database, "read_if_regular", reading)
    monkeypatch.setattr(os.path, "isdir", lambda _p: False)
    with pytest.raises(ValueError, match="could not be read"):
        _build(odbc_params={"sslca": sent})
    assert read == [sent]
    verdicts[sent] = True
    with pytest.raises(ValueError, match="must be a plain local path"):
        _build(odbc_params={"sslca": sent})


# The walk, against an injected file system, so every platform runs it. A drive answers its
# GetDriveTypeW number: 3 is a fixed disk, 4 a mapped network drive, 1 no such volume, 0 unknown.
_FIXED, _REMOTE, _NO_ROOT, _UNKNOWN = 3, 4, 1, 0


def _walk(
    path: str,
    links: dict[str, str] | None = None,
    *,
    drives: dict[str, int] | None = None,
    substs: dict[str, str] | None = None,
    failing: Mapping[str, OSError] | None = None,
) -> bool | None:
    """``_windows_path_verdict`` over a file system where every name is a folder or a file, except
    the ``links`` (path to stored target) and the ``failing`` paths (path to the error its probe
    raises). ``substs`` maps a ``subst`` drive to the folder it stands for."""
    links = {k.lower(): v for k, v in (links or {}).items()}
    failing = {k.lower(): v for k, v in (failing or {}).items()}

    def probe(part: str) -> tuple[str, str | None]:
        key = part.lower()
        if key in failing:
            raise failing[key]
        if key in links:
            return LINK, links[key]
        return (FILE if key.endswith(".pem") else DIRECTORY), None

    return database._windows_path_verdict(
        path,
        probe=probe,
        drive_type=lambda root: (drives or {}).get(root.upper(), _FIXED),
        drive_target=lambda drive: (substs or {}).get(drive.upper()),
        cwd=r"C:\work",
    )


def _winerror(winerror: int) -> FileNotFoundError:
    exc = FileNotFoundError(2, "not reached")
    exc.winerror = winerror  # type: ignore[attr-defined]
    return exc


def test_the_walk_clears_a_local_path() -> None:
    """A missing folder, or a drive letter with no volume on this host, is left to the driver."""
    assert _walk(r"C:\certs\ca.pem") is False
    assert _walk("ca.pem") is False  # relative: joined to the working directory
    missing = {r"C:\certs": FileNotFoundError(2, "not there")}
    assert _walk(r"C:\certs\ca.pem", failing=missing) is False
    assert _walk(r"Q:\certs\ca.pem", drives={"Q:\\": _NO_ROOT}) is False


def test_the_walk_refuses_a_mapped_network_drive_up_or_down() -> None:
    """The drive is judged by its type, read locally, so its server is never opened, and a server
    that is down at the build changes nothing."""
    assert _walk(r"Z:\certs\ca.pem", drives={"Z:\\": _REMOTE}) is True
    assert _walk(r"Y:\certs\ca.pem", drives={"Y:\\": _UNKNOWN}) is None


@pytest.mark.parametrize(
    "target",
    [
        r"\\files.test\share\ca.pem",
        r"\\?\UNC\files.test\share\ca.pem",
        r"\\?\Global\UNC\files.test\share\ca.pem",
        r"Z:\ca.pem",  # a link onto a mapped drive
    ],
)
def test_the_walk_refuses_a_link_that_leads_off_the_host(target: str) -> None:
    links = {r"C:\certs\ca.pem": target}
    assert _walk(r"C:\certs\ca.pem", links, drives={"Z:\\": _REMOTE}) is True


def test_the_walk_follows_a_chain_of_links_and_a_subst_drive_to_its_end() -> None:
    """Two hops, the first relative, a folder link above the file, and a ``subst`` drive whose
    folder holds a link: each is spliced in, so the share at the end is reached. A one-hop reader
    judges each of these local. Red with ``drive_target`` left out of the walk: the subst case."""
    share = r"\\files.test\share"
    assert _walk(r"C:\a\ca.pem", {r"C:\a\ca.pem": "hop.pem", r"C:\a\hop.pem": share}) is True
    assert _walk(r"C:\d1\ca.pem", {r"C:\d1": r"C:\d2", r"C:\d2": share}) is True
    assert _walk(r"S:\ca.pem", {r"C:\certlink": share}, substs={"S:": r"C:\certlink"}) is True
    # The control: a chain that ends on the local disk is cleared.
    assert _walk(r"C:\a\ca.pem", {r"C:\a\ca.pem": "hop.pem", r"C:\a\hop.pem": r"C:\b"}) is False


@pytest.mark.parametrize("winerror", [53, 67])
def test_the_walk_refuses_a_share_windows_could_not_reach(winerror: int) -> None:
    """A probe that reaches a share whose server is down fails as a missing name, with winerror 53
    or 67. That is not a missing folder: it leads off the host."""
    failing = {r"C:\certs\ca.pem": _winerror(winerror)}
    assert _walk(r"C:\certs\ca.pem", failing=failing) is True


def test_the_walk_cannot_clear_a_path_it_cannot_read() -> None:
    """The walk's verdict is ``None`` for a folder whose probe raises ``PermissionError``, and for a
    link whose target is ``\\Device\\Mup\\...``."""
    denied = {r"C:\locked": PermissionError(5, "denied")}
    assert _walk(r"C:\locked\ca.pem", failing=denied) is None
    nt = {r"C:\certs\ca.pem": r"\Device\Mup\files.test\share\ca.pem"}
    assert _walk(r"C:\certs\ca.pem", nt) is None


def test_the_walk_cannot_clear_a_drive_whose_subst_target_it_cannot_read() -> None:
    """A failed ``QueryDosDeviceW`` other than "no such device" is not read as a real volume: a
    subst drive the walk could not read would hide the links behind it."""

    def unreadable(_drive: str) -> str | None:
        raise OSError("the drive S: could not be read (winerror 122)")

    verdict = database._windows_path_verdict(
        r"S:\ca.pem",
        probe=lambda _p: (FILE, None),
        drive_type=lambda _r: _FIXED,
        drive_target=unreadable,
        cwd=r"C:\work",
    )
    assert verdict is None


def test_each_file_keyword_is_walked_once_per_build(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #2705: the refusal and the checks that read the files share one judgement. A second
    walk could disagree with the first, and an empty answer then skipped the key-wrap, certificate
    and CA checks while the connection string kept the path. Here the second walk of each value
    would say off-host: the build reads the files the first walk cleared, and the walk runs once
    per spelling. Red with ``driver_file_spellings`` walking again inside the checks."""
    walked: list[str] = []

    def once(path: str) -> bool | None:
        walked.append(path)
        return walked.count(path) > 1  # a second look at the same path flips to off-host

    read: list[str] = []

    def reading(path: str, _limit: int) -> bytes:
        read.append(path)
        return b"-----BEGIN CERTIFICATE-----\n"

    monkeypatch.setattr(database, "_path_verdict", once)
    monkeypatch.setattr(database, "read_if_regular", reading)
    params = {"sslca": r"C:\certs\ca.pem", "sslkey": r"C:\certs\k.pem", "sslpassword": "pw"}
    _build(odbc_params=params)
    assert sorted(walked) == [r"C:\certs\ca.pem", r"C:\certs\k.pem"]
    assert sorted(set(read)) == [r"C:\certs\ca.pem", r"C:\certs\k.pem"]  # both checks ran


def test_a_direct_check_refuses_a_set_value_its_own_walk_does_not_clear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A check called without the build's verdicts walks the path itself, and refuses a set value
    that walk does not clear, rather than reading nothing and passing."""
    monkeypatch.setattr(database, "_path_verdict", lambda _p: True)
    with pytest.raises(ValueError, match="not a plain local path"):
        database._refuse_encrypted_driver_ca({"sslca": r"Z:\certs\ca.pem"}, connection=_CONNECTION)


def test_a_direct_check_walks_each_spelling_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A check called without the build's verdicts judges the path once and reads from that one
    judgement, so a second walk cannot disagree with the first. Red with the refusal and the
    spellings each walking the path on their own."""
    walked: list[str] = []

    def once(path: str) -> bool | None:
        walked.append(path)
        return walked.count(path) > 1  # a second look at the same path flips to off-host

    read: list[str] = []

    def reading(path: str, _limit: int) -> bytes:
        read.append(path)
        return b"-----BEGIN CERTIFICATE-----\n"

    monkeypatch.setattr(database, "_path_verdict", once)
    monkeypatch.setattr(database, "read_if_regular", reading)
    database._refuse_encrypted_driver_ca({"sslca": r"C:\certs\ca.pem"}, connection=_CONNECTION)
    assert walked == [r"C:\certs\ca.pem"]
    assert read == [r"C:\certs\ca.pem"]


def test_a_verdicts_map_without_the_keyword_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A verdicts map that lacks a set keyword is a caller's bug. Read as no verdicts, it would
    leave the file unread and unrefused, so it raises. Red with the lookup back on a default."""
    monkeypatch.setattr(database, "read_if_regular", lambda *_a: b"")
    with pytest.raises(KeyError):
        database._refuse_encrypted_driver_ca(
            {"sslca": r"C:\certs\ca.pem"}, connection=_CONNECTION, verdicts={}
        )


@pytest.mark.parametrize("mode", ["disable", "DISABLED", "verify-full"])
@pytest.mark.parametrize(
    ("keyword", "path"), [("sslca", r"Z:\certs\ca.pem"), ("sslcapath", r"Z:\certs")]
)
def test_a_ca_the_walk_finds_off_the_host_is_refused_in_every_mode(
    monkeypatch: pytest.MonkeyPatch, mode: str, keyword: str, path: str
) -> None:
    """With TLS off the driver reads no CA, but an ``sslca`` or ``sslcapath`` on a mapped drive,
    which only the walk finds off the host, is refused all the same, as with TLS on and as a client
    key is: the build never hands the driver a path to another host, and nothing reads it. Red
    with the TLS-off leniency back, which built it unread under ``disable``."""

    def never(*_args: object) -> bytes:
        raise AssertionError("a path refused as off the host must not be read")

    monkeypatch.setattr(database, "_path_verdict", lambda p: p.startswith("Z:"))
    monkeypatch.setattr(database, "read_if_regular", never)
    with pytest.raises(ValueError, match="must be a plain local path") as refused:
        _build(odbc_params={"SSLmode": mode, keyword: path})
    assert "Z:" not in str(refused.value)
    with pytest.raises(ValueError, match="must be a plain local path"):
        _build(odbc_params={"SSLmode": mode, "sslkey": r"Z:\certs\k.pem"})


def test_a_ca_on_the_local_disk_still_builds_with_tls_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the refusal above: with TLS off a local CA still builds."""
    monkeypatch.setattr(database, "_path_verdict", lambda _p: False)
    monkeypatch.setattr(database, "read_if_regular", lambda *_a: b"-----BEGIN CERTIFICATE-----\n")
    ca = r"C:\certs\ca.pem"
    assert f"sslca={{{ca}}}" in _build(odbc_params={"SSLmode": "disable", "sslca": ca})


@pytest.mark.parametrize("keyword", ["sslca", "sslcapath"])
@pytest.mark.parametrize(
    "path", [r"\\files.test\share\ca.pem", r"\\?\UNC\files.test\share\ca.pem", "//files.test/ca"]
)
def test_a_ca_share_spelling_is_refused_even_with_tls_off(
    monkeypatch: pytest.MonkeyPatch, keyword: str, path: str
) -> None:
    """A share spelling was refused in every mode before the walk existed, and still is. Red with
    the remote refusal skipped for a CA keyword under ``disable``."""

    def never(*_args: object) -> bytes:
        raise AssertionError("a path refused as off the host must not be read")

    monkeypatch.setattr(database, "_path_verdict", lambda p: p.startswith("Z:"))
    monkeypatch.setattr(database, "read_if_regular", never)
    with pytest.raises(ValueError, match="must be a plain local path") as refused:
        _build(odbc_params={"SSLmode": "disable", keyword: path})
    assert "files.test" not in str(refused.value)


def test_a_ca_the_walk_cannot_clear_is_refused_even_with_tls_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With TLS off the CA check reads nothing it is not given, so a trimmed path the walk could
    not clear is refused rather than reaching the driver both unread and unrefused."""
    monkeypatch.setattr(database, "_path_verdict", lambda _p: None)
    with pytest.raises(ValueError, match="must be a plain local path"):
        _build(odbc_params={"SSLmode": "disable", "sslca": r"C:\locked\ca.pem"})


def _symlink_or_skip(target: str, link: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:  # Windows without the symlink privilege or developer mode
        pytest.skip(f"cannot create a symbolic link here: {exc}")


@pytest.mark.skipif(sys.platform != "win32", reason="a share path is a Windows spelling")
@pytest.mark.parametrize("shape", ["file", "folder", "chain"])
def test_a_real_link_to_a_share_is_refused(tmp_path: Path, shape: str) -> None:
    """Real links on this host, read by the real probe. ``.invalid`` never resolves, so nothing
    reaches a host whatever the walk does. Red with ``names_another_host`` back on the spelling
    alone."""
    share = r"\\files.invalid\share"
    if shape == "file":
        _symlink_or_skip(share + r"\ca.pem", tmp_path / "ca.pem")
    elif shape == "folder":
        _symlink_or_skip(share, tmp_path / "certs", directory=True)
    else:
        _symlink_or_skip(share + r"\ca.pem", tmp_path / "hop.pem")
        _symlink_or_skip("hop.pem", tmp_path / "ca.pem")
    sent = str(tmp_path / "certs" / "ca.pem") if shape == "folder" else str(tmp_path / "ca.pem")
    with pytest.raises(ValueError, match="must be a plain local path"):
        _build(odbc_params={"sslca": sent})


def test_a_link_to_a_local_file_still_builds(tmp_path: Path) -> None:
    """The control: a link that resolves to a local file builds, with the link's own path sent."""
    target = tmp_path / "real.pem"
    target.write_text("x", encoding="ascii")
    _symlink_or_skip(str(target), tmp_path / "ca.pem")
    sent = str(tmp_path / "ca.pem")
    assert f"sslca={{{sent}}}" in _build(odbc_params={"sslca": sent})


@pytest.mark.parametrize(
    "value",
    [r"C:\ProgramData\certs\root ca.crt", "/etc/ssl/certs/ca-1.pem", "TLSv1.2,TLSv1.3", 5432],
)
def test_an_ordinary_value_still_builds(value: object) -> None:
    # Sent without braces since BACKLOG #2705; an inner space is kept, as a driver reads it.
    assert f"sslca={value};" in _build(odbc_params={"sslca": value})


# --- booleans and the sslmode spelling (BACKLOG #2705) --------------------------------------------


@pytest.mark.parametrize("keyword", ["SSLmode", "readonly", "sslca"])
@pytest.mark.parametrize("value", [True, False])
def test_a_boolean_odbc_params_value_is_refused(keyword: str, value: bool) -> None:
    """``str(True)`` would send the text ``True``, which psqlODBC reads as ``disable``. Red on the
    previous head, which sent it. A TOML ``true`` arrives as this same ``bool``."""
    name = odbc_keyword_name(keyword)
    with pytest.raises(ValueError, match=f"'{name}' must not be a boolean") as refused:
        _build(odbc_params={keyword: value})
    message = str(refused.value)
    assert _CONNECTION in message
    assert "driver's own spelling as a string" in message
    # The control: the same keyword with a string spelling builds.
    spelled = "require" if name == "sslmode" else "1"
    assert f"{keyword}={spelled};" in _build(odbc_params={keyword: spelled})


_LIBPQ_MODES = ["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]
# psqlODBC reads SSLmode by its first lower case byte, so each of these means disable to it, while
# generic_odbc_tls_unenforced counts each as TLS addressed. `True` is the text a TOML `true` became.
_UNREAD_MODES = ["Require", "VERIFY-FULL", "Verify-full", "REQUIRED", "on", "1", "True", "yes"]


@pytest.mark.parametrize(
    "driver", ["PostgreSQL Unicode", "PostgreSQL", "/usr/lib/psqlodbcw.so", "SQLite3 ODBC Driver"]
)
@pytest.mark.parametrize("spelling", ["SSLmode", "sslmode", "SSLMODE"])
@pytest.mark.parametrize("mode", _UNREAD_MODES)
def test_an_sslmode_off_the_libpq_spellings_is_refused(
    driver: str, spelling: str, mode: str
) -> None:
    """Red on the previous head, which sent each of these. The keyword matches in any case; the
    value must be one of libpq's six modes exactly, for every driver but MySQL Connector/ODBC."""
    with pytest.raises(ValueError, match="'sslmode' must be one of disable, allow") as refused:
        _build(odbc_driver=driver, odbc_params={spelling: mode})
    message = str(refused.value)
    assert _CONNECTION in message
    assert "verify-full, in lower case" in message
    assert f"={mode}" not in message


@pytest.mark.parametrize("driver", ["PostgreSQL Unicode", "PostgreSQL", "/usr/lib/psqlodbcw.so"])
@pytest.mark.parametrize("mode", _LIBPQ_MODES)
def test_an_sslmode_in_the_libpq_spellings_builds(driver: str, mode: str) -> None:
    assert f"SSLmode={mode};" in _build(odbc_driver=driver, odbc_params={"SSLmode": mode})


def test_a_psqlodbc_sslmode_verify_full_builds() -> None:
    dsn = _build(odbc_params={"SSLmode": "verify-full"})
    assert dsn == "DRIVER={PostgreSQL Unicode};SERVER=db.test;SSLmode=verify-full;"


@pytest.mark.parametrize("driver", ["MySQL ODBC 8.0 Unicode Driver", "mysql odbc 9.1 ansi driver"])
@pytest.mark.parametrize(
    "mode", ["DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY", "required"]
)
def test_a_mysql_driver_keeps_its_own_sslmode_spellings(driver: str, mode: str) -> None:
    """MySQL Connector/ODBC sends the same keyword with its own values, so a MySQL driver name keeps
    them. The control for the refusal above: same keyword, the rule chosen by the driver name."""
    assert f"SSLMODE={mode};" in _build(odbc_driver=driver, odbc_params={"SSLMODE": mode})


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
    "DRIVER={PostgreSQL Unicode};SERVER=pg.test;DATABASE=results;UID=svc;PWD={pw};"
    "PORT=5432;SSLmode=verify-full;"
)


def test_the_documented_generic_example_builds_as_a_destination() -> None:
    connector = build_destination(
        _documented_destination(dict(_DOCUMENTED_PARAMS)),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(connector, DatabaseDestination)
    assert connector._dsn == _DOCUMENTED_DSN


def test_the_documented_generic_example_builds_as_a_poll_source() -> None:
    connector = build_source(
        _documented_source(dict(_DOCUMENTED_PARAMS)), egress=EgressSettings(deny_by_default=False)
    )
    assert isinstance(connector, DatabaseSource)
    assert connector._dsn == _DOCUMENTED_DSN


def test_the_destination_seam_refuses_a_keyword_off_the_list() -> None:
    config = _documented_destination(_DOCUMENTED_PARAMS | {"Servername": _VALUE})
    with pytest.raises(ValueError, match="must not set 'servername'") as refused:
        build_destination(config, egress=EgressSettings(deny_by_default=False))
    assert "DB-OUT_ACME_PG" in str(refused.value)
    assert _VALUE not in str(refused.value)


def test_the_poll_source_seam_refuses_a_keyword_off_the_list() -> None:
    config = _documented_source(_DOCUMENTED_PARAMS | {"Servername": _VALUE})
    with pytest.raises(ValueError, match="must not set 'servername'") as refused:
        build_source(config, egress=EgressSettings(deny_by_default=False))
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
        registry,
        inbound_bind_host="127.0.0.1",
        env_values={},
        egress=EgressSettings(deny_by_default=False),
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
        Destination(name="DB-OUT_ACME_SQL", type=ConnectorType.DATABASE, settings=settings),
        egress=EgressSettings(deny_by_default=False),
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
