# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``db_lookup`` / ``DatabaseRef`` login role probe against a real SQL Server (BACKLOG #2617).

The probe's verdicts are unit-tested with a faked driver in ``tests/test_lookup_login_role_probe.py``.
Its SQL is not: ``IS_SRVROLEMEMBER`` and ``IS_ROLEMEMBER`` with bound role names run against a real
server or nowhere, and a probe that read nothing would look the same as a clean one to a fake.

* **The positive control.** CI connects as ``sa``, a ``sysadmin`` login by construction, so the probe
  must name ``server role sysadmin``. Gated on the CONFIGURED login name, so a site pointing this leg
  at a least-privileged login is not failed for being correct.
* **Both directions on a purpose-made login.** A scratch login granted ``db_datareader`` alone reads
  clean, then reads over-granted once ``db_datawriter`` is added. The fixture skips, never fails,
  when the configured principal cannot create logins.

Two pool shapes are probed: the ``db_lookup`` executor's own pool, and the ``DatabaseRef`` sync's
pool, built the way ``pipeline/reference_sync.py`` ``_load_database_source`` builds it (a read-intent
``_build_dsn`` and an autocommit ``_make_pool``). That module is not imported here, because the
``serverdb`` path gate in ``.github/workflows/ci.yml`` does not admit it, and
``tests/test_serverdb_ci_coverage.py`` refuses a server-DB suite that imports a source the gate does
not admit.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*``). Synthetic names
only; every scratch login is unique per call and dropped afterwards.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, StoreSettings, load_settings
from messagefoundry.transports.database import (
    DatabaseLookupExecutor,
    LoginRoleVerdict,
    _build_dsn,
    _close_pool_bounded,
    _login_timeout,
    _make_pool,
    probe_login_roles,
)
from tests._live_scratch import (
    SqlServerStoreAdmin,
    bounded,
    scratch_name,
    sqlserver_store_admin,
    throwaway_password,
)

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run the login role probe",
)

_EGRESS = EgressSettings(deny_by_default=False)


def _conn(**over: Any) -> dict[str, Any]:
    """Connector settings for the CI mssql container, from the store job's ``MEFOR_STORE_*``.
    ``trust_server_certificate`` is permitted only because the job also sets
    ``MEFOR_ALLOW_INSECURE_TLS``."""
    settings: dict[str, Any] = {
        "server": os.environ.get("MEFOR_STORE_SERVER", "localhost"),
        "port": int(os.environ.get("MEFOR_STORE_PORT", "1433")),
        "database": os.environ.get("MEFOR_STORE_DATABASE", "MessageFoundry"),
        "username": os.environ.get("MEFOR_STORE_USERNAME", "sa"),
        "password": os.environ.get("MEFOR_STORE_PASSWORD", ""),
        "trust_server_certificate": True,
    }
    settings.update(over)
    return settings


async def _lookup_reading(settings: dict[str, Any]) -> Any:
    """The probe's reading when a ``db_lookup`` connection's pool first opens."""
    executor = DatabaseLookupExecutor({"live": settings}, egress=_EGRESS)
    try:
        await executor._get_pool("live")
        return executor.role_readings["live"]
    finally:
        await executor.aclose()


async def _reference_reading(settings: dict[str, Any]) -> Any:
    """The probe's reading on a pool built as a ``DatabaseRef`` sync builds its own."""
    pool = await _make_pool(
        _build_dsn(dict(settings), read_only=True),
        1,
        autocommit=True,
        login_timeout=_login_timeout(settings, "DATABASE reference source"),
    )
    try:
        return await probe_login_roles(pool, label="reference:live", acquire_timeout=30.0)
    finally:
        await _close_pool_bounded(pool, "DATABASE reference source")


@pytest.mark.parametrize("read", [_lookup_reading, _reference_reading], ids=["lookup", "reference"])
async def test_the_probe_reads_the_configured_login(read: Any) -> None:
    reading = await read(_conn())
    # A working server answers every name, so neither "cannot judge" nor "did not run" is right.
    assert reading.verdict in (LoginRoleVerdict.CLEAN, LoginRoleVerdict.OVER_GRANTED), reading
    if os.environ.get("MEFOR_STORE_USERNAME", "sa").lower() == "sa":
        # THE POSITIVE CONTROL: a probe that has quietly stopped seeing an over-grant (a mis-bound
        # parameter, a driver answering True where 1 is expected) reds here rather than reporting a
        # sysadmin as clean.
        assert reading.verdict is LoginRoleVerdict.OVER_GRANTED, reading
        assert "server role sysadmin" in reading.held, reading


@pytest.fixture
async def reader_login() -> AsyncIterator[tuple[SqlServerStoreAdmin, str, str]]:
    """A login and database user made for ONE test with ``db_datareader`` alone, dropped afterwards
    even when the test fails. The shape is ``tests/test_store_privilege_preflight.py``'s fixture."""
    base: StoreSettings = load_settings(environ=os.environ).store
    login = scratch_name("mefor_lookupprobe")
    password = throwaway_password()
    async with sqlserver_store_admin(base) as admin:
        try:
            try:
                await bounded(
                    base,
                    "create the login",
                    admin.run(
                        f"CREATE LOGIN [{login}] WITH PASSWORD='{password}', CHECK_POLICY=OFF"
                    ),
                )
                await bounded(
                    base, "create the user", admin.run(f"CREATE USER [{login}] FOR LOGIN [{login}]")
                )
                await bounded(
                    base,
                    "grant db_datareader",
                    admin.run(f"ALTER ROLE db_datareader ADD MEMBER [{login}]"),
                )
            except TimeoutError:
                raise  # a stall is a finding; only a refusal is a fixture limit
            except Exception as exc:  # noqa: BLE001 - a fixture-setup limit, not a probe failure
                pytest.skip(f"cannot create a test login with this store principal: {exc}")
            yield admin, login, password
        finally:
            await admin.teardown(users=[login], logins=[login])


async def test_the_probe_sees_both_directions_on_a_purpose_made_login(
    reader_login: tuple[SqlServerStoreAdmin, str, str],
) -> None:
    admin, login, password = reader_login
    settings = _conn(username=login, password=password)

    for read in (_lookup_reading, _reference_reading):
        clean = await bounded(admin.settings, "probe as the reader", read(settings))
        assert clean.verdict is LoginRoleVerdict.CLEAN, clean

    await bounded(
        admin.settings,
        "grant db_datawriter",
        admin.run(f"ALTER ROLE db_datawriter ADD MEMBER [{login}]"),
    )
    for read in (_lookup_reading, _reference_reading):
        over = await bounded(admin.settings, "probe as the writer", read(settings))
        assert over.verdict is LoginRoleVerdict.OVER_GRANTED, over
        assert over.held == ("database role db_datawriter",), over
