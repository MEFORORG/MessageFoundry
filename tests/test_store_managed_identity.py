# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Delegated-identity precondition on the store (#203, ASVS 13.2.1 / 13.3.2).

``[store].require_managed_identity`` makes "the store authenticates via a managed/delegated identity"
a checked precondition: ``serve`` refuses (production) / warns (non-production) when it is violated.
The policy itself is the pure ``StoreSettings.managed_identity_precondition()`` tested here."""

from __future__ import annotations

from messagefoundry.config.settings import SqlAuth, StoreBackend, StoreSettings


def _server(**kw: object) -> StoreSettings:
    return StoreSettings(server="db.example", database="mefor", username="svc", **kw)  # type: ignore[arg-type]


def test_off_by_default_never_violates() -> None:
    assert StoreSettings().managed_identity_precondition() is None
    # A static SQL Server login is fine while the flag is off (byte-identical default posture).
    assert _server(backend=StoreBackend.SQLSERVER).managed_identity_precondition() is None


def test_sqlite_is_exempt() -> None:
    # A local file has no network credential to delegate → satisfied even with the flag on.
    assert StoreSettings(require_managed_identity=True).managed_identity_precondition() is None


def test_sqlserver_static_login_violates() -> None:
    s = _server(backend=StoreBackend.SQLSERVER, auth=SqlAuth.SQL, require_managed_identity=True)
    reason = s.managed_identity_precondition()
    assert reason is not None and "integrated" in reason


def test_sqlserver_managed_auth_satisfies() -> None:
    for mode in (SqlAuth.INTEGRATED, SqlAuth.ENTRA):
        s = _server(backend=StoreBackend.SQLSERVER, auth=mode, require_managed_identity=True)
        assert s.managed_identity_precondition() is None


def test_postgres_cannot_satisfy() -> None:
    s = _server(backend=StoreBackend.POSTGRES, require_managed_identity=True)
    reason = s.managed_identity_precondition()
    assert reason is not None and "Postgres" in reason
