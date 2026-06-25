# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Store TLS: the ``[store].ssl_root_cert`` private-CA pin (EF-2).

Pure unit tests (no DB, no asyncpg required) — always run in CI. They assert the Postgres ``_build_ssl``
honors a private CA file and that ``ssl_root_cert`` is rejected for the backends that cannot apply it:
SQL Server's ODBC Driver 18 has no connection-string CA-file keyword (it validates against the OS trust
store) and SQLite uses no TLS, so setting it there would be a silent no-op.
"""

from __future__ import annotations

import ssl

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.postgres import _build_ssl


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


def test_build_ssl_default_is_verifying_true() -> None:
    # No ssl_root_cert + the secure posture → the default verifying value (asyncpg: system trust store).
    assert _build_ssl(_pg()) is True


def test_build_ssl_pins_ssl_root_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    real = ssl.create_default_context

    def fake(*args: object, **kwargs: object) -> ssl.SSLContext:
        captured["cafile"] = kwargs.get("cafile")
        return real()  # a real, fully-verifying context

    monkeypatch.setattr(ssl, "create_default_context", fake)
    result = _build_ssl(_pg(ssl_root_cert="/etc/mefor/db-ca.pem"))

    assert captured["cafile"] == "/etc/mefor/db-ca.pem"  # the private CA was pinned
    assert isinstance(result, ssl.SSLContext)
    # A pinned CA stays a FULLY-verifying posture (create_default_context defaults), not a downgrade.
    assert result.verify_mode is ssl.CERT_REQUIRED
    assert result.check_hostname is True


def test_ssl_root_cert_rejected_for_sqlserver() -> None:
    # ODBC Driver 18 has no connection-string CA-file keyword → fail loud, not a silent no-op.
    with pytest.raises(ValidationError, match="ssl_root_cert"):
        StoreSettings(
            backend=StoreBackend.SQLSERVER,
            server="db.example",
            database="mefor",
            username="mefor",
            ssl_root_cert="/etc/mefor/db-ca.pem",
        )


def test_ssl_root_cert_rejected_for_sqlite() -> None:
    # SQLite uses no TLS at all.
    with pytest.raises(ValidationError, match="ssl_root_cert"):
        StoreSettings(backend=StoreBackend.SQLITE, ssl_root_cert="/etc/mefor/db-ca.pem")


def test_ssl_root_cert_accepted_for_postgres() -> None:
    assert _pg(ssl_root_cert="/etc/mefor/db-ca.pem").ssl_root_cert == "/etc/mefor/db-ca.pem"
