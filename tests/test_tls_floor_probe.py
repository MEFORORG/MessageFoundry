# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 12.1.1 — the startup TLS-floor probe, exercised against REAL handshakes.

These tests stand up an actual TLS server on loopback with a throwaway self-signed cert and point the
probe at it. A mocked `ssl` would test the mock: the whole value of this control is that it performs a
genuine ClientHello at a withdrawn version and reports what came back, and only a real socket can show
that OpenSSL let us make the offer at all.

Deliberately covered, because each was a way the probe could have been born useless:

* a server that **accepts** TLS 1.0 must be detected (the finding is a SUCCESSFUL handshake)
* a server that **refuses** it must read as clean, not as unreachable
* an **unreachable** door must be distinguishable from a refusing one
* the deprecated `TLSVersion` enum must **raise**, never skip
"""

from __future__ import annotations

import contextlib
import enum
import socket
import ssl
import threading
from collections.abc import Iterator

import pytest

from messagefoundry.config.tls_probe import (
    LEGACY_TLS_VERSIONS,
    TlsProbeUnavailable,
    probe_tls_floor,
)


def _self_signed(tmp_path) -> tuple[str, str]:
    """A throwaway cert/key pair for a loopback listener. Not trust material — the probe runs with
    verification off by design (it measures the protocol floor, not the chain)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=2040))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "c.pem"
    key_file = tmp_path / "k.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)


@contextlib.contextmanager
def _tls_server(cert: str, key: str, *, minimum: ssl.TLSVersion) -> Iterator[int]:
    """A loopback TLS listener whose floor is ``minimum``. Yields its port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = minimum
    if minimum < ssl.TLSVersion.TLSv1_2:
        # Matching the probe: OpenSSL will not even negotiate a withdrawn version at the default
        # security level, so a server meant to ACCEPT one has to lower it too.
        ctx.set_ciphers("ALL:@SECLEVEL=0")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                raw, _ = srv.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with ctx.wrap_socket(raw, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass  # a refused handshake is the point of half these cases
            finally:
                with contextlib.suppress(OSError):
                    raw.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        t.join(timeout=3)
        srv.close()


@pytest.fixture(scope="module")
def certs(tmp_path_factory) -> tuple[str, str]:
    return _self_signed(tmp_path_factory.mktemp("tlsprobe"))


def test_a_front_door_that_accepts_tls10_is_detected(certs: tuple[str, str]) -> None:
    """The finding is a SUCCESSFUL handshake at a withdrawn version.

    This is the case the whole control exists for, and the one a mocked probe would never catch: it
    requires OpenSSL to actually complete a TLS 1.0 negotiation with a real peer.

    Mutation: invert the `if completed` test in `probe_tls_floor`. Red — `legacy_accepted` empties and
    a permissive door reads as clean.
    """
    with _tls_server(*certs, minimum=ssl.TLSVersion.TLSv1) as port:
        probe = probe_tls_floor(f"https://127.0.0.1:{port}")
    assert probe.reachable, f"probe could not reach its own test server: {probe.error}"
    assert probe.legacy_accepted, (
        f"a server with minimum_version=TLSv1 was not detected as accepting it — {probe.describe()}"
    )
    assert not probe.ok
    assert "ACCEPTS withdrawn" in probe.describe()


def test_a_modern_front_door_reads_clean(certs: tuple[str, str]) -> None:
    """The positive control. Without it the probe could report every door as failing and look correct.

    Mutation: make `_offer_context` ignore the version pin. Red — the legacy offers succeed against a
    1.3-only server and this asserts they did not.
    """
    with _tls_server(*certs, minimum=ssl.TLSVersion.TLSv1_3) as port:
        probe = probe_tls_floor(f"https://127.0.0.1:{port}")
    assert probe.reachable, f"unreachable: {probe.error}"
    assert probe.legacy_accepted == (), f"modern server misread: {probe.describe()}"
    assert probe.negotiated == "TLSv1.3", probe.describe()
    assert probe.ok


def test_a_tls12_floor_is_refused_because_the_cell_requires_13(certs: tuple[str, str]) -> None:
    """A 1.2 floor refuses the withdrawn versions but does not *prefer* 1.3.

    The default-capability handshake is what distinguishes support from preference — a 1.3-only probe
    would have passed this server, which is why the probe makes a full offer.
    """
    with _tls_server(*certs, minimum=ssl.TLSVersion.TLSv1_2) as port:
        probe = probe_tls_floor(f"https://127.0.0.1:{port}")
    assert probe.reachable
    assert probe.legacy_accepted == ()
    # The server permits 1.2 and 1.3; a default client should still land on 1.3.
    assert probe.negotiated in {"TLSv1.2", "TLSv1.3"}
    assert probe.ok is (probe.negotiated == "TLSv1.3")


def test_an_unreachable_door_is_distinguishable_from_a_refusing_one() -> None:
    """`reachable=False` must not be confused with "refused TLS 1.0" — they demand different operator
    action, and conflating them would let a down proxy read as a hardened one.

    Mutation: return `reachable=True` on connection failure. Red — `ok` becomes True for a door that
    does not exist.
    """
    with socket.socket() as s:  # bind and close to get a port nothing listens on
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    probe = probe_tls_floor(f"https://127.0.0.1:{dead}")
    assert not probe.reachable
    assert not probe.ok
    assert probe.negotiated is None
    assert "unreachable" in probe.describe()


class _TLSVersionMissing(enum.IntEnum):
    """A stand-in for a future `ssl.TLSVersion` that has DROPPED the deprecated members.

    Enum members cannot be deleted or reassigned (`AttributeError: cannot reassign member`), so the
    only way to simulate the removal this guard exists for is to substitute the whole type. Kept
    faithful in shape — an IntEnum with the surviving members — so `getattr(..., "TLSv1", None)`
    returns None exactly as it would on that future interpreter.
    """

    TLSv1_2 = 771
    TLSv1_3 = 772


def test_a_missing_tlsversion_enum_raises_rather_than_skipping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The `harden_kex_groups` failure mode, refused on purpose.

    That helper pins nothing on this interpreter because `SSLContext.set_groups` does not exist and it
    returns silently — six call sites, zero effect, green tests. A probe that skipped when a
    deprecated `TLSVersion` disappeared would become a gate that cannot fail, and would report success
    forever afterwards.

    Mutation: change the `_legacy_version` raise into `return None` + a skip. Red: DID NOT RAISE.
    """
    assert not hasattr(_TLSVersionMissing, LEGACY_TLS_VERSIONS[0]), "the stand-in still has it"
    monkeypatch.setattr(ssl, "TLSVersion", _TLSVersionMissing)
    with pytest.raises(TlsProbeUnavailable, match="must be rebuilt"):
        probe_tls_floor("https://127.0.0.1:1")


def test_the_probe_fails_before_dialling_when_the_enum_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolution happens up front so a build defect never looks like a proxy problem.

    Mutation: move `_legacy_version` resolution inside the per-version loop. Red — the connection is
    attempted first and the error names the operator's door instead of our build.
    """
    dialled: list[tuple[str, int]] = []
    real = socket.create_connection

    def spy(addr, *a, **kw):  # type: ignore[no-untyped-def]
        dialled.append(addr)
        return real(addr, *a, **kw)

    monkeypatch.setattr(socket, "create_connection", spy)
    monkeypatch.setattr(ssl, "TLSVersion", _TLSVersionMissing)
    with pytest.raises(TlsProbeUnavailable):
        probe_tls_floor("https://127.0.0.1:1")
    assert dialled == [], f"the probe dialled before checking its own preconditions: {dialled}"
