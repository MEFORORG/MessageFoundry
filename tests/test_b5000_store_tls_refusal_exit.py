# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5000: the store open's refusals of the hop's own TLS settings are typed, so
``audit-verify`` reports each as could not start, exit 2, and keeps exit 1 for a broken chain.

Three refusals were bare ``ValueError``s: a weakened PostgreSQL hop, a weakened SQL Server hop, and
a SQL Server ``[store].ssl_root_cert`` pin the engine must not send. ``_open_store_or_refuse`` did
not catch them, so they reached the CLI's dispatch floor and exited 1, the code ``audit-verify``
spends on a broken chain. Each is now ``StoreTlsRefused``, an ``InsecureHopRefused``. Severity is
conditional (CLAUDE.md section 0): this is what a first deployment would have read.

Each refusal is driven through ``main`` to the real store open; only the driver module is a
stand-in, and it records whether anything dialled. The broken-chain control runs the same command
on a SQLite store whose audit row was edited, and still exits 1.
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import types
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from messagefoundry.config.tls_policy import InsecureHopRefused, StoreTlsRefused
from tests._phi_gate_provisions import setenv_at_rest_opt_out

# The shell and driver stand-in that file drives each command with, shared rather than copied.
from tests.test_cli_store_hop_posture import _RefusingAsyncpg
from tests.test_cli_store_hop_posture import asyncpg as asyncpg  # noqa: F401
from tests.test_cli_store_hop_posture import shell as shell  # noqa: F401
from tests.test_store_ssl import _ca_cert_file, _pg, _ss

_REMOTE = "db.example.invalid"


@pytest.fixture
def aioodbc(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """A stand-in SQL Server driver that records each dial and refuses it. The open imports the
    module before it builds the connection string, so without one a shell lacking the extra would
    stop on the import and never reach the refusal under test."""
    dialled: list[object] = []

    async def refuse(**kwargs: object) -> object:
        dialled.append(kwargs)
        raise ConnectionRefusedError("no server in this test")

    monkeypatch.setitem(
        sys.modules,
        "aioodbc",
        types.SimpleNamespace(create_pool=refuse, connect=refuse),
    )
    return dialled


def _settings_file(tmp: Path, store: str) -> Path:
    settings = tmp / "service.toml"
    settings.write_text(
        f'[store]\n{store}\n[security]\nenforcement = "enforce"\n', encoding="utf-8"
    )
    return settings


def _audit_verify(settings: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = main(["audit-verify", "--service-config", str(settings)])
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_a_weakened_postgres_hop_is_could_not_start(
    shell: Path,
    asyncpg: _RefusingAsyncpg,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Mutation: raise ``ValueError`` again in ``postgres._build_ssl``; the exit is then 1."""
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")  # inert at enforce, so it still refuses
    settings = _settings_file(
        shell,
        f'backend = "postgres"\nserver = "{_REMOTE}"\ndatabase = "mefor"\nusername = "mefor"\n'
        "trust_server_certificate = true\n",
    )
    code, out = _audit_verify(settings, capsys)
    assert not asyncpg.pool_kwargs, "the command dialled a weakened hop"
    assert code == 2, out
    assert "Postgres TLS is weakened" in out, out
    assert "FAIL" not in out and "Traceback" not in out, out


def test_a_weakened_sqlserver_hop_is_could_not_start(
    shell: Path,
    aioodbc: list[object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Mutation: raise ``ValueError`` again in ``sqlserver.connection_string``; the exit is 1."""
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    settings = _settings_file(
        shell,
        f'backend = "sqlserver"\nserver = "{_REMOTE}"\ndatabase = "mefor"\nauth = "integrated"\n'
        "trust_server_certificate = true\n",
    )
    code, out = _audit_verify(settings, capsys)
    assert not aioodbc, "the command dialled a weakened hop"
    assert code == 2, out
    assert "SQL Server TLS is weakened" in out, out
    assert "FAIL" not in out and "Traceback" not in out, out


def test_a_sqlserver_pin_refusal_is_could_not_start(
    shell: Path,
    aioodbc: list[object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An expired pin: the settings load accepts it, and the open's own pin check refuses it.

    Mutation: raise ``ValueError`` again for an expired pin in
    ``sqlserver.check_pinned_certificate``; the exit is then 1."""
    pin = _ca_cert_file(shell, signs=False, not_after_days=-1)
    settings = _settings_file(
        shell,
        f'backend = "sqlserver"\nserver = "{_REMOTE}"\ndatabase = "mefor"\nauth = "integrated"\n'
        f"ssl_root_cert = '{pin}'\n",
    )
    code, out = _audit_verify(settings, capsys)
    assert not aioodbc, "the command dialled with a pin it refused"
    assert code == 2, out
    assert "[store].ssl_root_cert" in out and "expired at" in out, out
    assert "FAIL" not in out and "Traceback" not in out, out


def test_a_broken_chain_still_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: exit 1 still means a broken chain, so the three tests above are not passing
    because every failure now exits 2. A keyless chain under the audited opt-out, as
    ``tests/test_audit_integrity.py`` verifies one, with one row edited out of band."""
    from messagefoundry.store import MessageStore

    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "chain.db"

    async def seed() -> None:
        store = await MessageStore.open(db)
        try:
            await store.record_audit("login", actor="ops")
            await store.record_audit("view", actor="ops")
        finally:
            await store.close()

    asyncio.run(seed())
    assert main(["audit-verify", "--db", str(db)]) == 0, "the control store must verify first"
    capsys.readouterr()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET action = 'edited' WHERE id = 1")
    conn.close()
    assert main(["audit-verify", "--db", str(db)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_each_refusal_is_typed_and_still_a_value_error(tmp_path: Path) -> None:
    """Each refusal raises ``StoreTlsRefused``, which every handler of a refused hop catches, and
    which a caller that caught the bare ``ValueError`` still catches. The later ones are a
    PostgreSQL pin file gone since the settings load and a CRL file that cannot be judged, refused
    by the context builder ``_build_ssl`` calls at the open."""
    from messagefoundry.config.tls_policy import HopPosture
    from messagefoundry.store.postgres import _build_ssl
    from messagefoundry.store.sqlserver import check_pinned_certificate, connection_string

    assert issubclass(StoreTlsRefused, InsecureHopRefused)
    assert issubclass(StoreTlsRefused, ValueError)
    enforcing = HopPosture(enforcing=True)
    pin = _ca_cert_file(tmp_path, signs=False, not_after_days=-1)
    gone = _pg(ssl_root_cert=pin).model_copy(update={"ssl_root_cert": str(tmp_path / "gone.pem")})
    crl = tmp_path / "unjudgeable.crl"
    crl.write_text("not a CRL\n", encoding="utf-8")
    bad_crl = _pg().model_copy(update={"ssl_crl_file": str(crl)})
    for refuse in (
        lambda: _build_ssl(_pg(trust_server_certificate=True), posture=enforcing),
        lambda: connection_string(_ss(trust_server_certificate=True), posture=enforcing),
        lambda: check_pinned_certificate(_ss(ssl_root_cert=pin), posture=enforcing),
        lambda: _build_ssl(gone, posture=enforcing),
        # Any refusal the context builder makes is typed at the open, a CRL that cannot be judged
        # among them.
        lambda: _build_ssl(bad_crl, posture=enforcing),
    ):
        with pytest.raises(StoreTlsRefused):
            refuse()
