# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Store TLS: the ``[store].ssl_root_cert`` private-CA / server-cert pin (EF-2, #45).

Pure unit tests (no DB, no asyncpg / aioodbc required) — always run in CI. They assert:
  * Postgres ``_build_ssl`` honors a private CA file (asyncpg SSLContext, still fully verifying).
  * SQL Server ``connection_string`` emits the ODBC Driver 18.1+ ``ServerCertificate`` keyword on the
    secure posture, and NOT on a weakened / escaped posture.
  * ``ssl_root_cert`` is accepted for both server-DB backends but rejected for SQLite (no TLS) and when
    the path does not exist (fail loud at load, #45).
"""

from __future__ import annotations

import ssl

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.postgres import _build_ssl
from messagefoundry.store.sqlserver import connection_string


def _ca_file(tmp_path: object) -> str:
    """A real (empty) file to satisfy the load-time existence validator; contents are never read here."""
    p = tmp_path / "db-ca.pem"  # type: ignore[operator]
    p.write_text("-----BEGIN CERTIFICATE-----\n")
    return str(p)


def _pg(**kw: object) -> StoreSettings:
    """A minimal valid Postgres StoreSettings (server/database/username satisfy the server-DB validator)."""
    base: dict[str, object] = {
        "backend": StoreBackend.POSTGRES,
        "server": "db.example",
        "database": "mefor",
        "username": "mefor",
    }
    base.update(kw)
    return StoreSettings(**base)


def _ss(**kw: object) -> StoreSettings:
    """A minimal valid SQL Server StoreSettings."""
    base: dict[str, object] = {
        "backend": StoreBackend.SQLSERVER,
        "server": "db.example",
        "database": "mefor",
        "username": "mefor",
    }
    base.update(kw)
    return StoreSettings(**base)


# --- Postgres (the already-shipped half) -------------------------------------


def test_build_ssl_default_is_verifying_true() -> None:
    # No ssl_root_cert + the secure posture → the default verifying value (asyncpg: system trust store).
    assert _build_ssl(_pg()) is True


def test_build_ssl_pins_ssl_root_cert(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    ca = _ca_file(tmp_path)
    captured: dict[str, object] = {}
    real = ssl.create_default_context

    def fake(*args: object, **kwargs: object) -> ssl.SSLContext:
        captured["cafile"] = kwargs.get("cafile")
        return real()  # a real, fully-verifying context

    monkeypatch.setattr(ssl, "create_default_context", fake)
    result = _build_ssl(_pg(ssl_root_cert=ca))

    assert captured["cafile"] == ca  # the private CA was pinned
    assert isinstance(result, ssl.SSLContext)
    # A pinned CA stays a FULLY-verifying posture (create_default_context defaults), not a downgrade.
    assert result.verify_mode is ssl.CERT_REQUIRED
    assert result.check_hostname is True


# --- SQL Server (the #45 slice) ----------------------------------------------


def test_connection_string_emits_server_certificate_on_secure_posture(tmp_path: object) -> None:
    ca = _ca_file(tmp_path)
    dsn = connection_string(_ss(ssl_root_cert=ca))
    # The ODBC Driver 18.1+ ServerCertificate keyword pins the cert by file, brace-quoted (STORE-5).
    # Match the standalone keyword (a leading ';') so it isn't confused with TrustServerCertificate.
    assert f";ServerCertificate={{{ca}}}" in dsn
    # It only tightens verification — the last-wins secure tail is unchanged.
    assert dsn.rstrip(";").endswith("Encrypt=yes;TrustServerCertificate=no")


def test_connection_string_no_server_certificate_when_unset() -> None:
    # Byte-identical to before #45 when ssl_root_cert is unset (the standalone keyword is absent;
    # TrustServerCertificate= is a different keyword and stays).
    assert ";ServerCertificate=" not in connection_string(_ss())


def test_connection_string_server_certificate_brace_neutralizes_injection(tmp_path: object) -> None:
    # A cracked path with a stray brace can't inject extra keywords (the inner } is doubled).
    d = tmp_path / "ca}x.pem"  # type: ignore[operator]
    d.write_text("x")
    dsn = connection_string(_ss(ssl_root_cert=str(d)))
    assert "ca}}x.pem}" in dsn


# --- backend / existence gating ----------------------------------------------


def test_ssl_root_cert_accepted_for_postgres(tmp_path: object) -> None:
    ca = _ca_file(tmp_path)
    assert _pg(ssl_root_cert=ca).ssl_root_cert == ca


def test_ssl_root_cert_accepted_for_sqlserver(tmp_path: object) -> None:
    ca = _ca_file(tmp_path)
    assert _ss(ssl_root_cert=ca).ssl_root_cert == ca


def test_ssl_root_cert_rejected_for_sqlite(tmp_path: object) -> None:
    # SQLite uses no TLS at all → fail loud, not a silent no-op.
    ca = _ca_file(tmp_path)
    with pytest.raises(ValidationError, match="ssl_root_cert"):
        StoreSettings(backend=StoreBackend.SQLITE, ssl_root_cert=ca)


def test_ssl_root_cert_missing_file_rejected() -> None:
    # A path that does not exist fails loud at load (#45), not confusingly at connect.
    with pytest.raises(ValidationError, match="does not exist"):
        StoreSettings(
            backend=StoreBackend.POSTGRES,
            server="db.example",
            database="mefor",
            username="mefor",
            ssl_root_cert="/no/such/db-ca.pem",
        )
