# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The SSH (SFTP) algorithm floor -- BACKLOG #178, policy half.

**Why these tests drive a real key exchange.** The engine's other transport hops assert their cipher
floor on an ``SSLContext``, and the TLS suite's own master-test-plan entry records the weakness in
testing that by attribute: the floor is proven by construction, never observed. A floor tested that
way would pass identically if ``disabled_algorithms`` never reached the connect call, or if paramiko
ignored it. So the negotiation tests here stand up a live paramiko SSH server on loopback, restrict
what it will speak, and observe what the engine's own ``_SftpClient`` does about it.

**Red-first evidence.** Measured 2026-08-10 against this same harness, on the code before the floor
(origin/main d5ff1804), the engine CONNECTED to a server offering only ``hmac-md5`` (negotiating
``mac=hmac-md5``), only ``hmac-sha1``, and only ``3des-cbc`` (negotiating ``cipher=3des-cbc``). Every
one of those is below what the shipped TLS contexts already negotiate. The three refusal cases below
are exactly those three; each connected before the change and is refused after it.

**Skip posture.** The pure-policy tests import no SSH library and always run -- that is the same
property that keeps the ``[sftp]`` extra lazily importable. Only the live-negotiation tests need
paramiko, and they SKIP without it; a run reporting green with those skipped has not tested the
enforcement, only the policy. State which ones ran when reporting on this file.

No PHI is involved: the server serves nothing, the client never opens a file, and the host key is
generated per run.
"""

from __future__ import annotations

import importlib.util
import logging
import socket
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.ssh_policy import (
    SSH_ALGORITHM_CATEGORIES,
    FloorVerdict,
    ssh_algorithm_verdict,
    ssh_disabled_algorithms,
    ssh_floor_refusal,
)
from messagefoundry.transports.remotefile import _RemoteError, _SftpClient

_HAS_PARAMIKO = importlib.util.find_spec("paramiko") is not None
needs_paramiko = pytest.mark.skipif(
    not _HAS_PARAMIKO, reason="the [sftp] extra is not installed, so no negotiation can be driven"
)


# === the pure policy: no SSH library required ================================


@pytest.mark.parametrize(
    ("category", "name", "expected"),
    [
        # kex: the forward-secrecy cell (TLS Kx=ECDH/DH)
        ("kex", "curve25519-sha256@libssh.org", FloorVerdict.ABOVE),
        ("kex", "ecdh-sha2-nistp521", FloorVerdict.ABOVE),
        ("kex", "diffie-hellman-group16-sha512", FloorVerdict.ABOVE),
        ("kex", "sntrup761x25519-sha512@openssh.com", FloorVerdict.ABOVE),
        # RFC 4432 RSA key TRANSPORT: no ephemeral DH at all, the SSH static-RSA analogue
        ("kex", "rsa2048-sha256", FloorVerdict.BELOW),
        ("kex", "rsa1024-sha1", FloorVerdict.BELOW),
        # forward-secret family, SHA-1 exchange hash: below the same cell that bars a SHA-1 TLS MAC
        ("kex", "diffie-hellman-group14-sha1", FloorVerdict.BELOW),
        ("kex", "diffie-hellman-group1-sha1", FloorVerdict.BELOW),
        ("kex", "some-future-kex-sha256", FloorVerdict.UNKNOWN),
        # ciphers: the bulk-encryption cell (TLS Enc=AES/AESGCM/CHACHA20)
        ("ciphers", "aes256-gcm@openssh.com", FloorVerdict.ABOVE),
        ("ciphers", "aes128-cbc", FloorVerdict.ABOVE),
        ("ciphers", "chacha20-poly1305@openssh.com", FloorVerdict.ABOVE),
        ("ciphers", "3des-cbc", FloorVerdict.BELOW),
        ("ciphers", "arcfour256", FloorVerdict.BELOW),
        ("ciphers", "none", FloorVerdict.BELOW),
        ("ciphers", "kuznyechik-ctr", FloorVerdict.UNKNOWN),
        # macs: the integrity cell (TLS Mac=AEAD/SHA256/SHA384)
        ("macs", "hmac-sha2-256", FloorVerdict.ABOVE),
        ("macs", "hmac-sha2-512-etm@openssh.com", FloorVerdict.ABOVE),
        ("macs", "umac-128-etm@openssh.com", FloorVerdict.ABOVE),
        ("macs", "hmac-md5", FloorVerdict.BELOW),
        ("macs", "hmac-md5-96", FloorVerdict.BELOW),
        ("macs", "hmac-sha1", FloorVerdict.BELOW),
        ("macs", "hmac-sha1-96", FloorVerdict.BELOW),
        ("macs", "hmac-ripemd160", FloorVerdict.BELOW),
        ("macs", "umac-64@openssh.com", FloorVerdict.BELOW),
        ("macs", "hmac-blake3", FloorVerdict.UNKNOWN),
        # an unclassified CATEGORY is unknown, not silently admitted
        ("compression", "zlib", FloorVerdict.UNKNOWN),
    ],
)
def test_algorithm_verdicts(category: str, name: str, expected: FloorVerdict) -> None:
    assert ssh_algorithm_verdict(category, name) is expected


def test_a_below_floor_token_beats_an_above_floor_prefix() -> None:
    """Order inside ``_mac_verdict`` is load-bearing and easy to invert while every other test stays
    green: a name that starts ``hmac-sha2-256`` must still be refused if it carries an MD5 token."""
    assert ssh_algorithm_verdict("macs", "hmac-sha2-256-md5@example.com") is FloorVerdict.BELOW


def test_an_unrecognised_survivor_raises_rather_than_being_offered() -> None:
    """The assertion half. An algorithm nobody classified is precisely the inherited-never-checked
    state this item is about, so it must be loud -- and it must name the algorithm and the
    connection, or an operator cannot act on it."""
    offer = {
        "kex": ["curve25519-sha256@libssh.org", "quantum-widget-kex"],
        "ciphers": ["aes256-ctr"],
        "macs": ["hmac-sha2-256"],
    }
    with pytest.raises(ValueError, match="quantum-widget-kex") as ei:
        ssh_disabled_algorithms(offer, connector="REMOTEFILE sftp p.example.org")
    assert "REMOTEFILE sftp p.example.org" in str(ei.value)


def test_a_missing_category_raises_rather_than_going_unfloored() -> None:
    """Fail closed on a library that stops exposing a list. Skipping the category would leave the hop
    negotiating an unchecked cipher while every test still passed -- a control that silently stops
    covering something is worse than one that was never built."""
    with pytest.raises(ValueError, match="macs"):
        ssh_disabled_algorithms(
            {"kex": ["curve25519-sha256@libssh.org"], "ciphers": ["aes256-ctr"]},
            connector="test",
        )


def test_a_category_the_floor_would_empty_raises_and_blames_the_policy_not_the_partner() -> None:
    with pytest.raises(ValueError, match="library/policy mismatch") as ei:
        ssh_disabled_algorithms(
            {"kex": ["rsa2048-sha256"], "ciphers": ["aes256-ctr"], "macs": ["hmac-sha2-256"]},
            connector="test",
        )
    assert "rsa2048-sha256" in str(ei.value)


def test_the_refusal_explains_only_failures_the_floor_could_have_caused() -> None:
    """A floor that explained every negotiation failure as its own doing would send operators to
    edit their MACs list over a host-key mismatch. ``None`` means keep the generic message."""
    offered = {"macs": ["hmac-sha2-256", "hmac-md5"]}
    assert (
        ssh_floor_refusal(
            "Incompatible ssh peer (no acceptable host key)",
            connector="c",
            host="h",
            port=22,
            disabled={"macs": ["hmac-md5"]},
            offered=offered,
        )
        is None
    )
    assert (
        ssh_floor_refusal(
            "Incompatible ssh server (no acceptable macs)",
            connector="c",
            host="h",
            port=22,
            disabled={},  # the floor pruned no MAC, so it is not the cause
            offered=offered,
        )
        is None
    )
    explained = ssh_floor_refusal(
        "Incompatible ssh server (no acceptable macs)",
        connector="REMOTEFILE sftp h",
        host="h",
        port=2222,
        disabled={"macs": ["hmac-md5"]},
        offered=offered,
    )
    assert explained is not None
    assert "hmac-md5" in explained  # what was refused
    assert "hmac-sha2-256" in explained  # what the partner could enable instead
    assert "h:2222" in explained  # which partner


def test_every_governed_category_has_an_operator_label() -> None:
    """Liveness receipt for the refusal text: a category added to the floor with no label would raise
    a KeyError inside an error path, replacing an actionable refusal with a crash."""
    from messagefoundry.config import ssh_policy

    assert set(ssh_policy._CATEGORY_LABELS) == set(SSH_ALGORITHM_CATEGORIES)
    assert set(ssh_policy._PEER_MESSAGE_TOKENS) == set(SSH_ALGORITHM_CATEGORIES)


# === the floor's effect on the SHIPPED library ===============================


def _paramiko_offer() -> dict[str, list[str]]:
    import paramiko

    return {
        "kex": list(paramiko.Transport._preferred_kex),
        "ciphers": list(paramiko.Transport._preferred_ciphers),
        "macs": list(paramiko.Transport._preferred_macs),
    }


@needs_paramiko
def test_the_default_offer_is_pruned_exactly_where_the_tls_floor_would_prune_it() -> None:
    """The floor is the TLS floor re-expressed, so its effect on the shipped library must be the
    measured set and no more.

    Pinned as an EQUALITY, not a membership: a floor that quietly grew to refuse ``aes128-cbc`` would
    still satisfy "refuses 3des-cbc", and would break ordinary partners with nothing going red.
    """
    disabled = ssh_disabled_algorithms(_paramiko_offer(), connector="test")
    assert disabled.get("kex", []) == [], (
        "paramiko's default kex list is already forward-secret end to end; a non-empty prune here "
        "means either paramiko regressed or the kex predicate did"
    )
    assert set(disabled.get("ciphers", [])) == {"3des-cbc"}
    assert set(disabled.get("macs", [])) == {
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-md5",
        "hmac-md5-96",
    }


@needs_paramiko
def test_the_offer_left_standing_is_what_a_modern_ssh_server_speaks() -> None:
    """Constraint check on the floor itself: it must not be set so high that ordinary partners fail.

    ``hmac-sha2-256`` and ``aes*-ctr``/``aes*-gcm`` are in the default MACs/Ciphers of every OpenSSH
    release still supported, so an intersection containing them is the evidence that this asserts a
    floor rather than maximising strictness. AES-CBC surviving is deliberate and mirrors the TLS
    side's measured decision not to drop the CBC-SHA2 suites hospital peers still speak.
    """
    offer = _paramiko_offer()
    disabled = ssh_disabled_algorithms(offer, connector="test")
    surviving = {c: [n for n in offer[c] if n not in disabled.get(c, [])] for c in offer}
    assert "hmac-sha2-256" in surviving["macs"]
    assert "hmac-sha2-512" in surviving["macs"]
    assert "aes256-ctr" in surviving["ciphers"]
    assert "aes256-gcm@openssh.com" in surviving["ciphers"]
    assert "aes128-cbc" in surviving["ciphers"], (
        "AES-CBC must survive: dropping it re-introduces on the SSH hop the interop regression "
        "harden_cipher_suites measured and declined to take on the TLS hop"
    )
    assert "curve25519-sha256@libssh.org" in surviving["kex"]


# === live negotiation against a real paramiko SSH server =====================


@pytest.fixture(scope="module")
def host_key() -> Any:
    """A throwaway server host key. ECDSA rather than RSA purely for generation speed (measured
    instant vs. hundreds of milliseconds); the key type is not what these tests are about."""
    paramiko = pytest.importorskip("paramiko")
    return paramiko.ECDSAKey.generate()


@pytest.fixture(autouse=True)
def _quiet_paramiko() -> Iterator[None]:
    """paramiko logs a full traceback from its transport thread on every negotiation failure. These
    tests CAUSE such failures deliberately, so that noise is expected output, not a signal."""
    log = logging.getLogger("paramiko")
    before = log.level
    log.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        log.setLevel(before)


def _accept_any_password(paramiko: Any) -> Any:
    """The narrowest server that gets a client through key exchange and authentication. It offers no
    channels, so a test can observe the negotiated transport without an SFTP subsystem existing.

    Built inside a function so this module imports with no SSH library present."""

    class _AcceptAnyPassword(paramiko.ServerInterface):  # type: ignore[misc]
        def check_auth_password(self, username: str, password: str) -> int:
            return int(paramiko.AUTH_SUCCESSFUL)

        def get_allowed_auths(self, username: str) -> str:
            return "password"

    return _AcceptAnyPassword()


def _serve_one(listener: socket.socket, host_key: Any, prefs: dict[str, Sequence[str]]) -> None:
    """Accept ONE connection and speak SSH with the algorithm lists in ``prefs``.

    The ``_preferred_*`` overrides are set on the instance after construction, which is where
    paramiko reads them during ``_parse_kex_init`` -- that is how a test stands up a partner which
    speaks only a legacy algorithm."""
    import paramiko

    try:
        conn, _addr = listener.accept()
    except OSError:  # pragma: no cover - listener closed before a client arrived
        return
    transport = paramiko.Transport(conn)
    for category, names in prefs.items():
        setattr(transport, f"_preferred_{category}", tuple(names))
    transport.add_server_key(host_key)
    try:
        transport.start_server(server=_accept_any_password(paramiko))
        transport.join(timeout=10)
    except paramiko.SSHException:
        pass  # the refusal under test, seen from the far end
    finally:
        transport.close()


@contextmanager
def _partner(tmp_path: Path, host_key: Any, **prefs: Sequence[str]) -> Iterator[tuple[Any, int]]:
    """Start a one-shot SSH server on loopback and yield ``(_SftpClient, port)`` pointed at it.

    The server's host key is written into a ``known_hosts`` the client is configured with, so the
    connector's default RejectPolicy is satisfied and host-key verification is NOT what these tests
    accidentally end up measuring."""
    import paramiko

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    thread = threading.Thread(
        target=_serve_one, args=(listener, host_key, dict(prefs)), daemon=True
    )
    thread.start()

    known_hosts = tmp_path / f"known_hosts_{port}"
    keys = paramiko.HostKeys()
    keys.add(f"[127.0.0.1]:{port}", host_key.get_name(), host_key)
    keys.save(str(known_hosts))

    client = _SftpClient(
        {
            "host": "127.0.0.1",
            "port": port,
            "username": "u",
            "password": "p",
            "known_hosts": str(known_hosts),
            "connect_timeout": 15.0,
        }
    )
    try:
        yield client, port
    finally:
        listener.close()
        thread.join(timeout=10)


@needs_paramiko
@pytest.mark.parametrize(
    ("label", "prefs", "refused"),
    [
        # Each of these CONNECTED before the floor; measured 2026-08-10 on origin/main d5ff1804.
        ("md5 mac", {"macs": ["hmac-md5"], "ciphers": ["aes128-ctr"]}, "hmac-md5"),
        ("sha1 mac", {"macs": ["hmac-sha1"], "ciphers": ["aes128-ctr"]}, "hmac-sha1"),
        ("3des", {"ciphers": ["3des-cbc"], "macs": ["hmac-sha2-256"]}, "3des-cbc"),
    ],
)
def test_a_below_floor_partner_is_refused_with_an_actionable_message(
    tmp_path: Path, host_key: Any, label: str, prefs: dict[str, Sequence[str]], refused: str
) -> None:
    """Fail closed, but not silently.

    The assertion is on the MESSAGE, not merely on the raise: a timeout or a bare
    ``Incompatible ssh server (no acceptable macs)`` would also "refuse", and would leave an operator
    with a broken feed and no sign the engine did it deliberately. The refusal must name the
    algorithm refused, say why, and name something the partner can enable instead.
    """
    with (
        _partner(tmp_path, host_key, **prefs) as (client, port),
        pytest.raises(_RemoteError) as ei,
    ):
        client.list_dir("/in")
    message = str(ei.value)
    assert refused in message, f"{label}: refusal does not name what was refused: {message}"
    assert "algorithm floor" in message
    assert f"127.0.0.1:{port}" in message  # which partner
    assert "Enable one of" in message  # what to do about it
    assert "hmac-sha2-256" in message or "aes256-ctr" in message  # a concrete alternative
    assert ei.value.permanent is True, "a floor refusal cannot be fixed by retrying"


@needs_paramiko
def test_an_ordinary_modern_partner_still_negotiates(tmp_path: Path, host_key: Any) -> None:
    """The floor must not break reachability for a partner anyone actually runs.

    ``aes256-gcm`` + ``hmac-sha2-256`` is inside the default offer of every supported OpenSSH.
    Asserted on the NEGOTIATED algorithm from the live transport, so this cannot pass by the connect
    silently not happening."""
    with _partner(
        tmp_path, host_key, ciphers=["aes256-gcm@openssh.com"], macs=["hmac-sha2-256"]
    ) as (client, _port):
        connected = client._connect()
        try:
            transport = connected.get_transport()
            assert transport is not None and transport.is_active()
            assert transport.local_cipher == "aes256-gcm@openssh.com"
        finally:
            connected.close()


@needs_paramiko
def test_a_partner_on_the_libraries_own_defaults_still_negotiates(
    tmp_path: Path, host_key: Any
) -> None:
    """The unrestricted case: a server speaking everything paramiko does must still connect, and must
    land ABOVE the floor rather than on one of the algorithms the floor refuses."""
    with _partner(tmp_path, host_key) as (client, _port):
        connected = client._connect()
        try:
            transport = connected.get_transport()
            assert transport is not None and transport.is_active()
            assert transport.local_cipher != "3des-cbc"
            assert transport.local_mac not in {"hmac-md5", "hmac-md5-96", "hmac-sha1"}
        finally:
            connected.close()


@needs_paramiko
def test_the_connect_call_actually_carries_the_floor(
    tmp_path: Path, host_key: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wiring receipt. The negotiation tests prove the floor takes effect; this proves WHERE, so a
    refactor that moved the derivation somewhere the connect call no longer sees goes red here and
    not only in the slower live tests."""
    import paramiko

    seen: dict[str, Any] = {}
    real_connect = paramiko.SSHClient.connect

    def spy(self: Any, *args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        return real_connect(self, *args, **kwargs)

    monkeypatch.setattr(paramiko.SSHClient, "connect", spy)
    with _partner(tmp_path, host_key) as (client, _port):
        connected = client._connect()
        connected.close()
    assert "disabled_algorithms" in seen, "the connect call was made without the floor"
    assert "3des-cbc" in seen["disabled_algorithms"]["ciphers"]
    assert "hmac-md5" in seen["disabled_algorithms"]["macs"]
