# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared ODBC quoting and TLS tail (``messagefoundry.odbc_dsn``, BACKLOG #3714).

The SQL Server store and the DATABASE connector each used to build their own brace quoting and TLS
tail. Both now call one helper. These tests pin three things:

* the helper's own output, shape by shape;
* both builders' strings, byte for byte, as the code before the move built them. The expected
  strings were taken from that code;
* that no engine or harness module writes the ``}}`` escape or the TLS keywords itself again.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from messagefoundry import odbc_dsn
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    SqlAuth,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.odbc_dsn import odbc_brace, odbc_connection_string
from messagefoundry.store.sqlserver import connection_string
from messagefoundry.transports.database import _build_dsn

_WARN = HopPosture(enforcing=False)
_REPO = Path(__file__).resolve().parents[1]


# --- the helper ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "quoted"),
    [
        pytest.param("plain", "{plain}", id="plain"),
        pytest.param("", "{}", id="empty"),
        pytest.param("p};DROP", "{p}};DROP}", id="close-brace-then-keyword"),
        pytest.param("a;b=c{d", "{a;b=c{d}", id="semicolon-equals-open-brace-kept"),
        pytest.param("}}x}", "{}}}}x}}}", id="every-close-brace-doubled"),
    ],
)
def test_odbc_brace(value: str, quoted: str) -> None:
    assert odbc_brace(value) == quoted


@pytest.mark.parametrize(
    ("encrypt", "trust", "tail"),
    [
        (True, False, "Encrypt=yes;TrustServerCertificate=no;"),
        (True, True, "Encrypt=yes;TrustServerCertificate=yes;"),
        (False, False, "Encrypt=no;TrustServerCertificate=no;"),
        (False, True, "Encrypt=no;TrustServerCertificate=yes;"),
    ],
)
def test_the_tail_without_a_pin(encrypt: bool, trust: bool, tail: str) -> None:
    built = odbc_connection_string(
        ["A=1", "B={2}"], encrypt=encrypt, trust_server_certificate=trust
    )
    assert built == "A=1;B={2};" + tail


def test_a_pin_goes_out_quoted_with_strict_at_the_end() -> None:
    built = odbc_connection_string(
        ["A=1"], encrypt=True, trust_server_certificate=False, pin="C:\\p}x;y=z{.pem"
    )
    assert built == (
        "A=1;ServerCertificate={C:\\p}}x;y=z{.pem};Encrypt=strict;TrustServerCertificate=no;"
    )


def test_an_empty_pin_sends_no_server_certificate() -> None:
    built = odbc_connection_string(["A=1"], encrypt=True, trust_server_certificate=False, pin="")
    assert built == "A=1;Encrypt=yes;TrustServerCertificate=no;"


@pytest.mark.parametrize(
    ("encrypt", "trust"),
    [
        pytest.param(False, False, id="plaintext"),
        pytest.param(True, True, id="verify-off"),
        pytest.param(False, True, id="both"),
    ],
)
def test_a_pin_beside_a_weakened_posture_is_refused(encrypt: bool, trust: bool) -> None:
    with pytest.raises(ValueError, match="ServerCertificate pin needs encrypt on"):
        odbc_connection_string(
            ["A=1"], encrypt=encrypt, trust_server_certificate=trust, pin="C:\\p.pem"
        )


# --- the store's string, byte for byte as before -------------------------------------------------


def _store(**update: object) -> StoreSettings:
    """SQL Server store settings. ``model_copy`` skips validation, so a pin path need not exist:
    ``connection_string`` reads no file."""
    base = StoreSettings(
        backend=StoreBackend.SQLSERVER, server="db.example", database="mefor", username="mefor"
    )
    return base.model_copy(update={"application_name": "app}x", **update})


@pytest.mark.parametrize(
    ("update", "expected"),
    [
        pytest.param(
            {"password": "a;b=c{d}", "database": "d}}b;x"},
            "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.example,1433;DATABASE={d}}}}b;x};"
            "APP={app}}x};UID={mefor};PWD={a;b=c{d}}};Encrypt=yes;TrustServerCertificate=no;",
            id="secure-no-pin-braces",
        ),
        pytest.param(
            {"password": "p};DROP", "ssl_root_cert": "C:\\pins\\ca}x;y=z{.pem"},
            "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.example,1433;DATABASE={mefor};"
            "APP={app}}x};UID={mefor};PWD={p}};DROP};ServerCertificate={C:\\pins\\ca}}x;y=z{.pem};"
            "Encrypt=strict;TrustServerCertificate=no;",
            id="pin-strict",
        ),
        pytest.param(
            {
                "auth": SqlAuth.INTEGRATED,
                "multi_subnet_failover": True,
                "trust_server_certificate": True,
                "ssl_root_cert": "C:\\pins\\db.pem",
            },
            "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.example,1433;DATABASE={mefor};"
            "APP={app}}x};Trusted_Connection=yes;MultiSubnetFailover=Yes;Encrypt=yes;"
            "TrustServerCertificate=yes;",
            id="escaped-verify-off-drops-pin",
        ),
        pytest.param(
            {"auth": SqlAuth.ENTRA, "encrypt": False, "ssl_root_cert": "C:\\pins\\db.pem"},
            "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.example,1433;DATABASE={mefor};"
            "APP={app}}x};Authentication=ActiveDirectoryDefault;Encrypt=no;"
            "TrustServerCertificate=no;",
            id="escaped-plaintext-drops-pin",
        ),
    ],
)
def test_the_store_string_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, update: dict[str, object], expected: str
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    assert connection_string(_store(**update), posture=_WARN) == expected


# --- the DATABASE connector's string, byte for byte as before ------------------------------------

_DB: dict[str, object] = {
    "server": "db.example",
    "port": 14330,
    "database": "d}b;x",
    "username": "u}",
    "app_name": "a;p}p",
}


@pytest.mark.parametrize(
    ("update", "read_only", "expected"),
    [
        pytest.param(
            {"password": "p};DROP", "auth": "sql", "encrypt": True},
            False,
            "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.example,14330;DATABASE={d}}b;x};"
            "APP={a;p}}p};UID={u}}};PWD={p}};DROP};Encrypt=yes;TrustServerCertificate=no;",
            id="secure-sql-braces",
        ),
        pytest.param(
            {"auth": "integrated", "encrypt": True, "odbc_driver": "x}y"},
            True,
            "DRIVER={x}}y};SERVER=db.example,14330;DATABASE={d}}b;x};APP={a;p}}p};"
            "Trusted_Connection=yes;ApplicationIntent=ReadOnly;Encrypt=yes;"
            "TrustServerCertificate=no;",
            id="read-only-before-the-tail",
        ),
        pytest.param(
            {"auth": "entra", "encrypt": False},
            False,
            "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.example,14330;DATABASE={d}}b;x};"
            "APP={a;p}}p};Authentication=ActiveDirectoryDefault;Encrypt=no;"
            "TrustServerCertificate=no;",
            id="attested-plaintext",
        ),
        pytest.param(
            {
                "auth": "SQL",
                "encrypt": "yes",
                "trust_server_certificate": True,
                "password": "}}x}",
                "odbc_driver": "ODBC Driver 17 for SQL Server",
            },
            False,
            "DRIVER={ODBC Driver 17 for SQL Server};SERVER=db.example,14330;DATABASE={d}}b;x};"
            "APP={a;p}}p};UID={u}}};PWD={}}}}x}}};Encrypt=yes;TrustServerCertificate=yes;",
            id="attested-verify-off",
        ),
    ],
)
def test_the_connector_string_is_unchanged(
    update: dict[str, object], read_only: bool, expected: str
) -> None:
    settings = {**_DB, **update}
    assert _build_dsn(settings, read_only=read_only, attested=True) == expected


def test_the_harness_string_is_unchanged() -> None:
    from harness.drivers import _database

    t = _database.Target("db.example", 1433, "har}ness", "u}x", "p;w}d=1")
    assert _database.build_dsn(t) == (
        "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.example,1433;DATABASE={har}}ness};"
        "APP={messagefoundry-harness};UID={u}}x};PWD={p;w}}d=1};Encrypt=yes;"
        "TrustServerCertificate=no;"
    )


# --- no second copy ---------------------------------------------------------------------------------


#: A string constant holding a TLS keyword at its start or right after a ``;`` is a connection-string
#: part. ODBC keywords ignore case, so this does too. Prose that names a keyword mid-sentence, such
#: as a refusal message, does not match.
_TLS_PART = re.compile(r"(?:^|;)\s*(?:trustservercertificate|servercertificate|encrypt)\s*=", re.I)


def _copies(path: Path) -> list[str]:
    """Where ``path`` writes the ``}}`` escape or a TLS keyword part itself.

    Only a file whose text holds ``}}`` or a keyword name is parsed, which keeps the scan fast. A
    copy built from escapes or split literals would pass unseen."""
    text = path.read_text(encoding="utf-8")
    lowered = text.lower()
    if "}}" not in text and "encrypt" not in lowered and "servercertificate" not in lowered:
        return []
    found: list[str] = []
    for node in ast.walk(ast.parse(text)):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if node.value == "}}":
            found.append(f"{path.name}:{node.lineno} the }}}} escape")
        elif _TLS_PART.search(node.value):
            found.append(f"{path.name}:{node.lineno} {node.value!r}")
    return found


def test_the_scan_sees_each_shape_of_copy(tmp_path: Path) -> None:
    module = tmp_path / "copy.py"
    module.write_text(
        'a = v.replace("}", "}}")\n'
        'b = re.sub("}", "}}", v)\n'
        'c = "encrypt=no"\n'
        'd = f"APP={x};Encrypt={e}"\n'
        'e = "TrustServerCertificate = yes"\n'
        'f = "a pin sends Encrypt=strict"\n',  # prose: not a part
        encoding="utf-8",
    )
    lines = sorted(int(hit.split()[0].split(":")[1]) for hit in _copies(module))
    assert lines == [1, 2, 3, 4, 5]


def test_the_helper_is_the_only_module_that_writes_them() -> None:
    """The engine and the harness, which may import this leaf module, build no copy of their own."""
    helper = Path(odbc_dsn.__file__).resolve()
    # POSITIVE CONTROL: the scan finds the helper's own escape and keywords, so a clean verdict
    # elsewhere is not a scan that matches nothing.
    assert len(_copies(helper)) >= 4
    paths = [
        p
        for tree in ("messagefoundry", "harness")
        for p in sorted((_REPO / tree).rglob("*.py"))
        if p.resolve() != helper
    ]
    # The walk reaches both trees, and every caller among the files it reads.
    assert len(paths) >= 100
    assert {"sqlserver.py", "database.py", "_database.py"} <= {p.name for p in paths}
    others = [hit for path in paths for hit in _copies(path)]
    assert others == []
