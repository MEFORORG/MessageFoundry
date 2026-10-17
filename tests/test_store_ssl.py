# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Store TLS: the ``[store].ssl_root_cert`` private-CA / server-cert pin (EF-2, #45).

Pure unit tests (no DB, no asyncpg / aioodbc required) — always run in CI. They assert:
  * Postgres ``_build_ssl`` honors a private CA file (asyncpg SSLContext, still fully verifying).
  * SQL Server ``connection_string`` emits the ODBC Driver 18.1+ ``ServerCertificate`` keyword with
    ``Encrypt=strict`` on the secure posture, and neither on a weakened / escaped posture.
  * ``ssl_root_cert`` is accepted for both server-DB backends but rejected for SQLite (no TLS) and when
    the path does not exist (fail loud at load, #45).
"""

from __future__ import annotations

import ssl
import sys

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.store.postgres import _build_ssl
from messagefoundry.store.sqlserver import check_pinned_certificate, connection_string


def _ca_file(tmp_path: object) -> str:
    """A real (empty) file to satisfy the load-time existence validator; contents are never read here."""
    p = tmp_path / "db-ca.pem"  # type: ignore[operator]
    p.write_text("-----BEGIN CERTIFICATE-----\n")
    return str(p)


def _leaf_file(tmp_path: object, name: str = "db-server.pem", *, der: bool = False) -> str:
    """A real server certificate (basicConstraints CA:FALSE), valid from a minute ago for 30 days:
    what a SQL Server pin names (vault BACKLOG #2223). ``der`` writes it DER-encoded."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from messagefoundry import pki

    pem = pki.make_self_signed("db.example", [], 30)[0]
    p = tmp_path / name  # type: ignore[operator]
    if der:
        p.write_bytes(x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER))
    else:
        p.write_bytes(pem)
    return str(p)


def _ca_cert_file(tmp_path: object, *, signs: bool = True, not_after_days: float = 30) -> str:
    """A self-signed CA:TRUE certificate. With ``signs`` it is an issuer (keyUsage keyCertSign),
    which a SQL Server pin can never match; without, it is the shape ``openssl req -x509`` gives a
    server by default, which a server can present."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mf-test-db-ca")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=60))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=signs,
                crl_sign=signs,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / "db-ca-cert.pem"  # type: ignore[operator]
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
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
    escape_at_warn: None, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
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
    """The pin travels with ``Encrypt=strict``: Driver 18 enforced ``ServerCertificate`` with strict
    and did not with ``Encrypt=yes``, where a pin naming the wrong certificate still connected (vault
    BACKLOG #2223; measured under #3009)."""
    pin = _leaf_file(tmp_path)
    dsn = connection_string(_ss(ssl_root_cert=pin))
    # The ODBC Driver 18.1+ ServerCertificate keyword pins the cert by file, brace-quoted (STORE-5).
    # Match the standalone keyword (a leading ';') so it isn't confused with TrustServerCertificate.
    assert f";ServerCertificate={{{pin}}}" in dsn
    # The TLS keywords stay the last-wins tail, and Encrypt=yes appears nowhere in the string.
    assert dsn.rstrip(";").endswith("Encrypt=strict;TrustServerCertificate=no")
    assert "Encrypt=yes" not in dsn
    assert dsn.index(";ServerCertificate=") < dsn.index(";Encrypt=strict")


def test_connection_string_no_server_certificate_when_unset() -> None:
    # Unchanged when ssl_root_cert is unset: Encrypt=yes, and no standalone ServerCertificate keyword
    # (TrustServerCertificate= is a different keyword and stays).
    dsn = connection_string(_ss())
    assert ";ServerCertificate=" not in dsn
    assert "Encrypt=strict" not in dsn
    assert dsn.rstrip(";").endswith("Encrypt=yes;TrustServerCertificate=no")


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"trust_server_certificate": True}, id="verify-off"),
        pytest.param({"encrypt": False}, id="plaintext"),
    ],
)
def test_connection_string_pin_does_not_lift_the_weakened_refusal(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    """A pin is no way around the weakened-TLS refusal: with no escape the string is still refused."""
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with pytest.raises(ValueError, match="SQL Server TLS is weakened"):
        connection_string(_ss(ssl_root_cert=_leaf_file(tmp_path), **overrides))


@pytest.mark.parametrize(
    ("overrides", "tail"),
    [
        pytest.param(
            {"trust_server_certificate": True},
            "Encrypt=yes;TrustServerCertificate=yes",
            id="verify-off",
        ),
        pytest.param({"encrypt": False}, "Encrypt=no;TrustServerCertificate=no", id="plaintext"),
    ],
)
def test_connection_string_escaped_posture_sends_no_pin_and_no_strict(
    tmp_path: object, escape_at_warn: None, overrides: dict[str, object], tail: str
) -> None:
    """On an escaped dev posture the pin is dropped and strict is not sent. Microsoft documents that
    strict ignores ``TrustServerCertificate``, so sending it would quietly re-enable verification the
    operator switched off, and plaintext cannot be strict at all."""
    dsn = connection_string(_ss(ssl_root_cert=_leaf_file(tmp_path), **overrides))
    assert ";ServerCertificate=" not in dsn
    assert "Encrypt=strict" not in dsn
    assert dsn.rstrip(";").endswith(tail)


def test_connection_string_server_certificate_brace_neutralizes_injection(tmp_path: object) -> None:
    # A cracked path with a stray brace can't inject extra keywords (the inner } is doubled).
    dsn = connection_string(_ss(ssl_root_cert=_leaf_file(tmp_path, "ca}x.pem")))
    assert "ca}}x.pem}" in dsn


# --- vault BACKLOG #2223: the engine checks the SQL Server pin itself --------------------------
#
# Under Encrypt=strict a pin match stands in for the driver's own chain, host-name and expiry checks,
# so the engine refuses a pin outside its validity period, and refuses at load a file that can never
# match the server's certificate.

_DAY = 86_400.0


def test_an_expired_pin_is_refused_naming_the_setting_and_not_after(tmp_path: object) -> None:
    import time

    pin = _leaf_file(tmp_path)
    settings = _ss(ssl_root_cert=pin)
    # POSITIVE CONTROL: the same pin, checked now, builds a string.
    assert ";ServerCertificate=" in connection_string(settings)
    with pytest.raises(
        ValueError, match=r"\[store\]\.ssl_root_cert .*expired at \d{2} \w{3} \d{4}"
    ) as exc:
        check_pinned_certificate(settings, now=time.time() + 60 * _DAY)
    assert "BEGIN CERTIFICATE" not in str(exc.value)


def test_a_pin_not_yet_valid_is_refused(tmp_path: object) -> None:
    import time

    settings = _ss(ssl_root_cert=_leaf_file(tmp_path))
    with pytest.raises(ValueError, match=r"\[store\]\.ssl_root_cert .*not valid until .*notAfter"):
        check_pinned_certificate(settings, now=time.time() - _DAY)


def test_a_der_pin_is_accepted(tmp_path: object) -> None:
    pin = _leaf_file(tmp_path, "db-server.cer", der=True)
    assert f";ServerCertificate={{{pin}}}" in connection_string(_ss(ssl_root_cert=pin))


def test_a_ca_certificate_is_refused_as_a_sqlserver_pin_at_load(tmp_path: object) -> None:
    ca = _ca_cert_file(tmp_path)
    with pytest.raises(ValidationError, match=r"ssl_root_cert .*CA certificate"):
        _ss(ssl_root_cert=ca)
    # The same file stays a valid PostgreSQL CA bundle: the refusal is SQL Server's alone.
    assert _pg(ssl_root_cert=ca).ssl_root_cert == ca


def test_a_two_certificate_bundle_is_refused_as_a_sqlserver_pin_at_load(tmp_path: object) -> None:
    from messagefoundry import pki

    bundle = tmp_path / "two.pem"  # type: ignore[operator]
    bundle.write_bytes(
        pki.make_self_signed("db1.example", [], 30)[0]
        + pki.make_self_signed("db2.example", [], 30)[0]
    )
    with pytest.raises(ValidationError, match="holds 2 certificates"):
        _ss(ssl_root_cert=str(bundle))


def test_a_file_that_is_not_a_certificate_is_refused_as_a_sqlserver_pin_at_load(
    tmp_path: object,
) -> None:
    with pytest.raises(ValidationError, match="not a usable SQL Server pin"):
        _ss(ssl_root_cert=_ca_file(tmp_path))


# --- backend / existence gating ----------------------------------------------


def test_ssl_root_cert_accepted_for_postgres(tmp_path: object) -> None:
    ca = _ca_file(tmp_path)
    assert _pg(ssl_root_cert=ca).ssl_root_cert == ca


def test_ssl_root_cert_accepted_for_sqlserver(tmp_path: object) -> None:
    pin = _leaf_file(tmp_path)
    assert _ss(ssl_root_cert=pin).ssl_root_cert == pin


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


# --- vault BACKLOG #2223: the pin is a trust anchor, so it takes the anchor ACL and path checks ---


def _writable_by_others(path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``path`` writable by a broad principal. POSIX sets the real bit, so the Linux leg runs
    the real DACL check; Windows answers the check's own question, as tests/test_trust_anchors.py does."""
    import os
    import stat

    if sys.platform == "win32":
        from messagefoundry.auth import trust_anchors

        monkeypatch.setattr(trust_anchors, "dacl_is_owner_only", lambda _p: False)
    else:
        os.chmod(path, os.stat(path).st_mode | stat.S_IWOTH)


def test_a_pin_others_can_write_is_refused_while_enforcing(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = _leaf_file(tmp_path)
    settings = _ss(ssl_root_cert=pin)
    # POSITIVE CONTROL: the same file, owner-written, builds a string under enforce.
    check_pinned_certificate(settings, posture=HopPosture(enforcing=True))
    _writable_by_others(pin, monkeypatch)
    with pytest.raises(ValueError, match=r"\[store\]\.ssl_root_cert: the trust anchor"):
        check_pinned_certificate(settings, posture=HopPosture(enforcing=True))
    # No posture counts as enforcing.
    with pytest.raises(ValueError, match="the trust anchor"):
        check_pinned_certificate(settings)


def test_a_pin_others_can_write_warns_and_connects_at_warn(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    pin = _leaf_file(tmp_path)
    _writable_by_others(pin, monkeypatch)
    with caplog.at_level(logging.WARNING):
        check_pinned_certificate(_ss(ssl_root_cert=pin), posture=HopPosture(enforcing=False))
    assert "[store].ssl_root_cert: the trust anchor" in caplog.text


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="conftest answers the path check on win32, because %TEMP%'s own DACL refuses it",
)
def test_a_pin_in_a_folder_others_can_write_is_refused_while_enforcing(tmp_path: object) -> None:
    import os
    import stat

    folder = tmp_path / "open"  # type: ignore[operator]
    folder.mkdir()
    pin = _leaf_file(folder)
    # POSITIVE CONTROL: the folder as created passes.
    check_pinned_certificate(_ss(ssl_root_cert=pin), posture=HopPosture(enforcing=True))
    os.chmod(folder, os.stat(folder).st_mode | stat.S_IWOTH)  # world-writable, no sticky bit
    with pytest.raises(ValueError, match=r"\[store\]\.ssl_root_cert"):
        check_pinned_certificate(_ss(ssl_root_cert=pin), posture=HopPosture(enforcing=True))


def test_a_self_signed_ca_true_server_certificate_is_accepted(tmp_path: object) -> None:
    """``openssl req -x509`` marks a server's self-signed certificate CA:TRUE by default, with no
    keyCertSign. A server can present it, so the pin accepts it."""
    pin = _ca_cert_file(tmp_path, signs=False)
    assert _ss(ssl_root_cert=pin).ssl_root_cert == pin
    check_pinned_certificate(_ss(ssl_root_cert=pin))


def test_the_escaped_posture_does_not_validate_a_pin_it_never_sends(
    tmp_path: object, escape_at_warn: None
) -> None:
    ca = _ca_cert_file(tmp_path)
    settings = _ss(ssl_root_cert=ca, trust_server_certificate=True)  # no refusal at load
    check_pinned_certificate(settings)  # and none at open


async def test_store_open_refuses_an_expired_pin_before_any_connect(tmp_path: object) -> None:
    """The check runs at :meth:`SqlServerStore.open`, ahead of the driver import and every connect,
    so it holds without a SQL Server or the extra."""
    from messagefoundry.store.sqlserver import SqlServerStore

    pin = _ca_cert_file(tmp_path, signs=False, not_after_days=-1)
    settings = _ss(ssl_root_cert=pin)
    with pytest.raises(ValueError, match="expired at"):
        await SqlServerStore.open(settings)
    with pytest.raises(ValueError, match="expired at"):
        await SqlServerStore.provision_schema(settings)
