# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-5 store/file robustness: ODBC injection (STORE-5), filename traversal (FILE-1), and
atomic non-clobbering writes (FILE-5)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import SqlAuth, StoreBackend, StoreSettings
from messagefoundry.store.sqlserver import connection_string
from messagefoundry.transports import build_destination
from messagefoundry.transports.file import render_filename

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"


def _adt(control_id: str) -> str:
    return f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|{control_id}|P|2.5.1\r"


# --- STORE-5: ODBC connection-string injection -------------------------------


@pytest.mark.parametrize("bad", ["db;Encrypt=no", "db{x", "a=b", "db\nx"])
def test_store_settings_rejects_odbc_metacharacters(bad: str) -> None:
    with pytest.raises(ValidationError):
        StoreSettings(server=bad)


def test_store_settings_accepts_clean_identity_fields() -> None:
    s = StoreSettings(server="db.hospital.local", database="mf", username="svc")
    assert s.server == "db.hospital.local"


def test_connection_string_neutralizes_password_injection() -> None:
    s = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="db",
        database="mf",
        username="svc",
        password="p}a;Encrypt=no",  # tries to break out and downgrade TLS; also has a brace
        auth=SqlAuth.SQL,
        encrypt=True,
    )
    dsn = connection_string(s)
    assert "PWD={p}}a;Encrypt=no}" in dsn  # brace-quoted, internal } doubled — no breakout
    # The real security flags are emitted last (ODBC last-wins), so the injected one can't win.
    assert dsn.rstrip(";").endswith("TrustServerCertificate=no")
    assert "Encrypt=yes" in dsn


# --- BACKLOG #100: AOAG multi-subnet fast failover ---------------------------


def _sqlserver_settings(**over: object) -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="db",
        database="mf",
        username="svc",
        password="pw",
        auth=SqlAuth.SQL,
        encrypt=True,
        **over,
    )


def test_multi_subnet_failover_default_off() -> None:
    dsn = connection_string(_sqlserver_settings())
    assert "MultiSubnetFailover" not in dsn


def test_multi_subnet_failover_emitted_when_enabled() -> None:
    dsn = connection_string(_sqlserver_settings(multi_subnet_failover=True))
    assert "MultiSubnetFailover=Yes" in dsn
    # It must sit BEFORE the TLS tail so ODBC last-wins keeps the secure Encrypt/Trust flags final.
    assert dsn.index("MultiSubnetFailover=Yes") < dsn.index("Encrypt=yes")
    assert dsn.rstrip(";").endswith("TrustServerCertificate=no")


# --- FILE-1: filename path traversal -----------------------------------------


def test_render_filename_rejects_dotdot() -> None:
    assert render_filename("{MSH-10}", _adt(".."), fallback="fb") == "fb"


def test_render_filename_rejects_reserved_device_name() -> None:
    assert render_filename("{MSH-10}.hl7", _adt("CON"), fallback="fb.hl7") == "fb.hl7"


def test_render_filename_strips_leading_dots() -> None:
    # ".ssh" must not become a dotfile, and must never start with '.'
    assert not render_filename("{MSH-10}", _adt(".hidden"), fallback="fb").startswith(".")


def test_render_filename_strips_path_separators() -> None:
    # A field with separators can't introduce a directory component.
    out = render_filename("{MSH-10}", _adt("a/b\\c"), fallback="fb")
    assert "/" not in out and "\\" not in out


# --- FILE-5: atomic, non-clobbering concurrent writes ------------------------


async def test_concurrent_writes_do_not_clobber(tmp_path: Path) -> None:
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "fixed.hl7"},
        )
    )
    await asyncio.gather(*[dest.send(ADT) for _ in range(5)])
    written = sorted(p.name for p in tmp_path.iterdir() if p.suffix == ".hl7")
    assert len(written) == 5  # five distinct files, none overwritten by a racing writer
    assert not list(tmp_path.glob("*.part"))  # temp files cleaned up
