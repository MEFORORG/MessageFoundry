# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
from messagefoundry.config.tls_policy import HopPosture
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


def test_build_ssl_default_is_an_engine_built_verifying_context() -> None:
    """No ssl_root_cert and the secure posture give a verifying context on the system trust store.

    This pinned ``is True`` until BACKLOG #300. ``True`` left asyncpg to build the context, so the
    engine could not narrow its suites or load a CRL onto it. The engine now builds it with the same
    ``ssl.create_default_context()`` call asyncpg makes for ``ssl=True``, then narrows it. So the test
    asserts the verification axes asyncpg's own context had, plus the approved suite list."""
    from messagefoundry.config.tls_policy import APPROVED_TLS12_SUITES

    result = _build_ssl(_pg())
    assert isinstance(result, ssl.SSLContext)
    assert result.verify_mode is ssl.CERT_REQUIRED
    assert result.check_hostname is True
    # The trust store is pinned by the next test, through the call that loads it: a Linux OpenSSL may
    # read the system store lazily, so an anchor count here could read zero on a correct context.
    tls12 = {str(c["name"]) for c in result.get_ciphers() if c["protocol"] != "TLSv1.3"}
    assert tls12 <= set(APPROVED_TLS12_SUITES)
    assert tls12, "narrowing must leave at least one approved suite"


def test_build_ssl_default_uses_the_same_call_asyncpg_makes_for_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """asyncpg 0.31.0 turns ``ssl=True`` into ``ssl.create_default_context()`` with NO arguments
    (connect_utils.py:811-813). The default path must make that same call, so its trust store and
    verification defaults cannot drift weaker than what asyncpg built before BACKLOG #300."""
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    real = ssl.create_default_context

    def spy(*args: object, **kwargs: object) -> ssl.SSLContext:
        calls.append((args, kwargs))
        return real()

    monkeypatch.setattr(ssl, "create_default_context", spy)
    _build_ssl(_pg())
    assert calls == [((), {})]


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


def test_default_context_is_at_least_as_strict_as_asyncpg_ssl_true() -> None:
    """The default-branch context against the one asyncpg built for ``ssl=True``, axis by axis.

    BACKLOG #300 replaced ``ssl=True`` with an engine-built context. This pins that the replacement
    is no weaker on any axis a context carries: verify mode, hostname check, protocol floor and
    ceiling, verify flags, options, security level, trust store and suites. The reference is the
    exact call asyncpg 0.31.0 makes for ``ssl=True`` (connect_utils.py:811-812). Trust-store
    FRESHNESS is not a property of one context; the pool-hook tests below pin that."""
    from messagefoundry.store.postgres import _verifying_context

    ours = _verifying_context(_pg())
    ref = ssl.create_default_context()

    assert ours.verify_mode is ref.verify_mode is ssl.CERT_REQUIRED
    assert ours.check_hostname is ref.check_hostname is True
    assert ours.minimum_version >= ref.minimum_version
    assert ours.maximum_version == ref.maximum_version
    assert ours.verify_flags & ref.verify_flags == ref.verify_flags  # every reference flag kept
    assert ours.options & ref.options == ref.options  # every reference option kept
    assert ours.security_level >= ref.security_level
    # The same trust store. The SOURCE is pinned by the test above: the same no-argument call loads
    # it. These counts compare what was loaded, and they only discriminate where the store loads
    # eagerly (Windows); a lazy hashed-directory OpenSSL reads zero on both sides.
    assert ours.cert_store_stats() == ref.cert_store_stats()
    assert ours.get_ca_certs() == ref.get_ca_certs()
    # Suites: only ever removed, and TLS 1.2 is held to the approved list. Whether the interpreter
    # default had anything to remove depends on the build, so no strict-subset claim is made.
    from messagefoundry.config.tls_policy import APPROVED_TLS12_SUITES

    ours_suites = {str(c["name"]) for c in ours.get_ciphers()}
    ref_suites = {str(c["name"]) for c in ref.get_ciphers()}
    assert ours_suites <= ref_suites
    ours_tls12 = {str(c["name"]) for c in ours.get_ciphers() if c["protocol"] != "TLSv1.3"}
    assert ours_tls12 and ours_tls12 <= set(APPROVED_TLS12_SUITES)


class _FakeAsyncpg:
    """Stands in for the asyncpg module: records create_pool's kwargs and each connect's ``ssl``."""

    def __init__(self) -> None:
        self.pool_kwargs: dict[str, object] = {}
        self.connect_ssl: list[object] = []

    async def create_pool(self, **kwargs: object) -> object:
        self.pool_kwargs = kwargs
        return object()

    async def connect(self, *args: object, **kwargs: object) -> object:
        self.connect_ssl.append(kwargs["ssl"])
        return object()


async def _pool_with_fake_asyncpg(
    monkeypatch: pytest.MonkeyPatch, settings: StoreSettings, *, posture: HopPosture | None = None
) -> _FakeAsyncpg:
    """Open the store's pool against :class:`_FakeAsyncpg`. Shared with the revocation tests, so the
    two files test one stand-in for the asyncpg contract, not two."""
    import sys

    from messagefoundry.store.postgres import PostgresStore

    fake = _FakeAsyncpg()
    monkeypatch.setitem(sys.modules, "asyncpg", fake)
    await PostgresStore._create_pool(settings, posture=posture, max_size=2)
    return fake


async def test_pool_connect_hook_builds_a_fresh_verifying_context_per_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """asyncpg's ``ssl=True`` called ``ssl.create_default_context()`` on EVERY connect, so each new
    pool connection read the OS trust store afresh. One engine context per pool would freeze that
    store at pool open. The ``connect`` hook restores the per-connect read (BACKLOG #300).

    Pinned two ways: each connection gets a DISTINCT context, and each one comes from its own
    ``create_default_context()`` call. The ``ssl`` value the pool was opened with is never used."""
    fake = await _pool_with_fake_asyncpg(monkeypatch, _pg())
    hook = fake.pool_kwargs["connect"]
    assert callable(hook)
    opened_with = fake.pool_kwargs["ssl"]

    calls: list[object] = []
    real = ssl.create_default_context

    def spy(*args: object, **kwargs: object) -> ssl.SSLContext:
        calls.append((args, kwargs))
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ssl, "create_default_context", spy)
    await hook(ssl=opened_with)
    await hook(ssl=opened_with)

    assert len(calls) == 2, "each connection must build its own context"
    first, second = fake.connect_ssl
    assert isinstance(first, ssl.SSLContext) and isinstance(second, ssl.SSLContext)
    assert first is not second
    assert first is not opened_with and second is not opened_with
    # Each connection's context matches the one the refusals graded at open. The guard and the
    # suite tests read `_build_ssl`'s context, so a hook that drifted from it would pass them.
    assert isinstance(opened_with, ssl.SSLContext)
    for ctx in (first, second):
        assert ctx.verify_mode is opened_with.verify_mode is ssl.CERT_REQUIRED
        assert ctx.check_hostname is opened_with.check_hostname is True
        assert ctx.verify_flags == opened_with.verify_flags
        assert ctx.minimum_version == opened_with.minimum_version
        assert ctx.get_ciphers() == opened_with.get_ciphers()


async def test_pool_connect_hook_names_a_slow_build_without_posing_as_pool_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TLS build that outlasts ``connect_timeout`` raises a ConnectionError naming the cause. Not a
    TimeoutError: the store's pool borrow reports every TimeoutError as pool exhaustion
    (``acquire_pooled``), which would send the operator to ``acquire_timeout``. CONTROL: the same
    hook with a fast build connects, so the refusal is the slow build's doing."""
    import time

    import messagefoundry.store.postgres as pg

    fake = await _pool_with_fake_asyncpg(monkeypatch, _pg(connect_timeout=1))
    hook = fake.pool_kwargs["connect"]
    assert callable(hook)
    await hook()
    assert len(fake.connect_ssl) == 1

    real = pg._verifying_context

    def slow(settings: StoreSettings) -> ssl.SSLContext:
        time.sleep(1.5)
        return real(settings)

    monkeypatch.setattr(pg, "_verifying_context", slow)
    with pytest.raises(ConnectionError, match=r"connect_timeout.*OS certificate store") as exc:
        await hook()
    assert not isinstance(exc.value, TimeoutError)
    assert len(fake.connect_ssl) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"trust_server_certificate": True}, id="verify-off"),
        pytest.param({"encrypt": False}, id="plaintext"),
    ],
)
async def test_pool_connect_hook_is_absent_on_the_weakened_escapes(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    """The hook is for VERIFYING hops. The dev escapes keep the plain ``ssl=`` value: a verify-off
    context reads no trust store, and plaintext has no context at all.

    POSITIVE CONTROL: the verifying hop in the test above does get a hook, so this ``None`` is the
    branch's doing and not a fake that never records one."""
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    fake = await _pool_with_fake_asyncpg(monkeypatch, _pg(**overrides))
    assert fake.pool_kwargs["connect"] is None


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
