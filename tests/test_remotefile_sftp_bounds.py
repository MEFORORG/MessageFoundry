# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SFTP thread-parking bounds (BACKLOG #1195, ASVS 15.4.4).

paramiko's ``connect(timeout=...)`` bounds the TCP connect. It does not bound the banner exchange,
authentication, or any read on the channel once the transport is up -- at that point the channel is a
blocking socket again. Every REMOTEFILE operation runs on a worker thread, so a partner share that
accepts a connection and then goes silent would hold one thread per stuck operation, and on a first
deployment enough of them would delay unrelated work that shares the same pool.

Between the two sits opening the SFTP session, which BACKLOG #1936 bounds. What paramiko does and
does not bound there is stated once, in ``remotefile._open_sftp_within``'s docstring.

These tests live in their own file rather than in ``test_remotefile_transport.py`` because they are
about the socket the connector makes, not about the transfer semantics that file covers.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.transports import remotefile
from messagefoundry.transports.remotefile import (
    SFTP_CHANNEL_READ_TIMEOUT_SECONDS,
    _RemoteError,
    _SftpClient,
)

#: A short synthetic body. Content is irrelevant here -- these tests assert about the socket timeout
#: and the connect keywords, never about parsing.
_BODY = b"SYNTHETIC-REMOTE-FILE-BODY"


class _StubFile:
    """A paramiko ``SFTPFile`` stand-in serving ``_BODY`` in chunks."""

    def __init__(self, body: bytes = _BODY) -> None:
        self.body = body
        self.read_total = 0

    def read(self, size: int) -> bytes:
        chunk = self.body[self.read_total : self.read_total + size]
        self.read_total += len(chunk)
        return chunk

    def stat(self) -> SimpleNamespace:
        # BACKLOG #116: the retrieve reads the handle's size on each side of the transfer.
        return SimpleNamespace(st_size=len(self.body))

    def __enter__(self) -> _StubFile:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _RecordingChannel:
    """A paramiko ``Channel`` stand-in recording the timeout the connector puts on it."""

    def __init__(self) -> None:
        self.timeout: float | None = None
        self.calls = 0

    def settimeout(self, value: float) -> None:
        self.timeout = value
        self.calls += 1


class _StubSftp:
    """A paramiko ``SFTPClient`` stand-in, optionally backed by a channel."""

    def __init__(self, channel: _RecordingChannel | None, fh: _StubFile | None = None) -> None:
        self._channel = channel
        self._fh = fh or _StubFile()

    def get_channel(self) -> _RecordingChannel | None:
        return self._channel

    def open(self, path: str, mode: str) -> _StubFile:
        return self._fh

    def close(self) -> None:
        return None


class _StubSshClient:
    """Enough of ``paramiko.SSHClient`` for ``_op`` to reach ``fn(sftp)`` and close cleanly."""

    def __init__(self, sftp: Any) -> None:
        self._sftp = sftp

    def open_sftp(self) -> Any:
        return self._sftp

    def close(self) -> None:
        return None


class _FakeSshException(Exception):
    pass


class _FakeAuthException(_FakeSshException):
    """Subclasses the SSH exception, as ``paramiko.AuthenticationException`` does."""


class _FakeParamiko:
    """The two exception classes ``_op`` catches by attribute off the lazily imported module."""

    SSHException = _FakeSshException
    AuthenticationException = _FakeAuthException


class _UnconnectedSshClient:
    """Enough of ``paramiko.SSHClient`` for the real ``_SftpClient._connect`` to run; ``connect`` is
    what each test overrides."""

    def load_system_host_keys(self) -> None:
        return None

    def load_host_keys(self, path: str) -> None:
        return None

    def set_missing_host_key_policy(self, policy: Any) -> None:
        return None

    def connect(self, **kw: Any) -> None:
        return None

    def get_transport(self) -> Any:
        return None

    def close(self) -> None:
        return None


def _use_fake_paramiko(client_cls: type, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``_import_paramiko`` return a fake whose ``SSHClient`` is ``client_cls``."""

    class _Policy:
        pass

    class _Transport:
        _preferred_macs: tuple[str, ...] = ()
        _preferred_ciphers: tuple[str, ...] = ()

    class _Paramiko(_FakeParamiko):
        SSHClient = client_cls
        RejectPolicy = _Policy
        AutoAddPolicy = _Policy
        Transport = _Transport

    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _Paramiko)


def _client_with_ssh(ssh: Any, monkeypatch: pytest.MonkeyPatch) -> _SftpClient:
    """An ``_SftpClient`` whose ``_connect`` hands back ``ssh``, a fake connected SSH client."""
    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _FakeParamiko)
    monkeypatch.setattr(_SftpClient, "_connect", lambda self: ssh)
    return _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})


def _client_over(sftp: Any, monkeypatch: pytest.MonkeyPatch) -> _SftpClient:
    """An ``_SftpClient`` whose ``_connect`` hands back a fake SSH client serving ``sftp``."""
    return _client_with_ssh(_StubSshClient(sftp), monkeypatch)


def test_the_shipped_bound_is_finite_and_positive() -> None:
    """The constant itself, asserted before anything reads it.

    THIS IS THE CONTROL FOR EVERY TEST BELOW. ``None`` and ``0`` are both paramiko spellings for
    "wait indefinitely", and either would satisfy a was-settimeout-called check while restoring the
    exact defect the bound exists to remove. Pinning the value's shape here means the tests that
    compare against it cannot pass vacuously.
    """
    assert isinstance(SFTP_CHANNEL_READ_TIMEOUT_SECONDS, float)
    assert 0 < SFTP_CHANNEL_READ_TIMEOUT_SECONDS < float("inf"), (
        f"{SFTP_CHANNEL_READ_TIMEOUT_SECONDS!r} does not bound anything"
    )


def test_reads_on_the_established_channel_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A silent peer must not park the worker thread forever.

    The assertion is on the VALUE, not on the call: see the control above for why.
    """
    channel = _RecordingChannel()
    client = _client_over(_StubSftp(channel), monkeypatch)

    assert client.retrieve("/in/a.hl7") == _BODY

    assert channel.calls == 1, (
        f"settimeout was called {channel.calls} times; the connector should bound the channel "
        "exactly once per operation"
    )
    assert channel.timeout == SFTP_CHANNEL_READ_TIMEOUT_SECONDS


def test_a_client_with_no_channel_still_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    """An absent channel is a no-op, not a refusal.

    ``get_channel`` is documented to return ``None`` for a client with no channel behind it.
    Refusing a transfer over that would be a worse failure than the unbounded read it replaced.
    """
    client = _client_over(_StubSftp(None), monkeypatch)

    assert client.retrieve("/in/a.hl7") == _BODY


def test_a_read_timeout_is_classified_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the bound fires, the caller must retry rather than dead-letter.

    A silent peer is a live-again-later peer. Classifying the expiry permanent would quarantine a
    file that a first deployment's operator could not have done anything about.
    """

    class _StallingSftp(_StubSftp):
        def open(self, path: str, mode: str) -> _StubFile:
            raise TimeoutError("timed out")

    client = _client_over(_StallingSftp(_RecordingChannel()), monkeypatch)

    with pytest.raises(_RemoteError) as caught:
        client.retrieve("/in/a.hl7")

    assert caught.value.permanent is False, "a silent peer is transient, not a dead-letter"
    assert "timed out" in str(caught.value).lower()


def test_connect_bounds_the_banner_and_auth_phases(monkeypatch: pytest.MonkeyPatch) -> None:
    """``timeout`` covers the TCP connect only; the other two phases need their own keywords.

    Left unset, paramiko applies its own defaults. Pinning all three at the call that makes the
    socket keeps the bound readable where it matters, and this test fails if one is dropped.

    Each is asserted finite and positive for the same reason as the channel bound: paramiko reads
    ``None`` as "wait indefinitely", which a merely-present check would accept.
    """
    captured: dict[str, Any] = {}

    class _CapturingClient(_UnconnectedSshClient):
        def connect(self, **kw: Any) -> None:
            captured.update(kw)

    _use_fake_paramiko(_CapturingClient, monkeypatch)
    _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})._connect()

    for key in ("timeout", "banner_timeout", "auth_timeout"):
        assert key in captured, (
            f"connect() was called without {key}, so that phase falls back to paramiko's default "
            f"or blocks. passed={sorted(captured)}"
        )
        value = captured[key]
        assert isinstance(value, (int, float)) and 0 < float(value) < float("inf"), (
            f"{key}={value!r} does not bound anything"
        )


# --- opening the SFTP session (BACKLOG #1936) --------------------------------

#: The bound the tests give the open, patched over ``SFTP_CHANNEL_READ_TIMEOUT_SECONDS``. Short, so a
#: pass is quick, but long enough that a descheduled thread on a loaded runner does not trip it. The
#: assertions allow generous slack above it: what they test is "returns", not "returns on the dot".
_OPEN_BOUND = 0.5

#: How long a stub or a test thread waits before declaring the worker PARKED. This is the harness
#: ceiling that stops a regression from hanging the test run itself: without the fix the open never
#: returns, and each test below fails at this ceiling with a message that says so.
_PARKED_AFTER = 10.0


class _SilentOpenSshClient:
    """``paramiko.SSHClient`` after authentication, facing a peer that never answers the session open.

    ``open_sftp`` blocks until ``close`` is called, then raises ``SSHException("Channel closed.")``,
    which is the paramiko behaviour ``remotefile._open_sftp_within`` describes. The real-paramiko test
    further down checks this model against the library.
    """

    def __init__(self) -> None:
        self._closed = threading.Event()
        self.close_calls = 0

    def open_sftp(self) -> Any:
        if not self._closed.wait(_PARKED_AFTER):
            raise AssertionError(
                f"open_sftp was still parked after {_PARKED_AFTER:g}s: nothing closed the client, "
                "so on a real silent peer this worker thread would never come back"
            )
        raise _FakeSshException("Channel closed.")

    def close(self) -> None:
        self.close_calls += 1
        self._closed.set()


def _sftp_client_with(ssh: Any, monkeypatch: pytest.MonkeyPatch) -> _SftpClient:
    """:func:`_client_with_ssh`, with the open bound shortened to :data:`_OPEN_BOUND`."""
    monkeypatch.setattr(remotefile, "SFTP_CHANNEL_READ_TIMEOUT_SECONDS", _OPEN_BOUND)
    return _client_with_ssh(ssh, monkeypatch)


def test_a_silent_session_open_is_refused_transient_within_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A peer that authenticates and then never answers the open must not park the worker.

    Before #1936 ``open_sftp`` ran with no bound, so this test fails at the harness ceiling rather
    than passing: the stub waits for a close that nothing sends.
    """
    ssh = _SilentOpenSshClient()
    client = _sftp_client_with(ssh, monkeypatch)

    started = time.monotonic()
    with pytest.raises(_RemoteError) as caught:
        client.list_dir("/in")
    elapsed = time.monotonic() - started

    assert caught.value.permanent is False, "a silent peer is transient, not a dead-letter"
    assert "session open timed out" in str(caught.value), (
        f"the refusal must name the open, not a read: {caught.value}"
    )
    assert elapsed < _OPEN_BOUND + 5.0, (
        f"the open took {elapsed:.2f}s against a {_OPEN_BOUND}s bound"
    )
    assert ssh.close_calls >= 1


def test_a_transfer_longer_than_the_bound_still_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bound covers the open only, never the work done on the session after it.

    CONTROL for the test above: a bound that also wrapped the transfer, or that closed the client
    regardless of the outcome, would pass that test and break every transfer longer than the bound.
    Here the transfer outlasts the bound, still returns its body, and the only close is ``_op``'s own.
    """

    class _SlowFile(_StubFile):
        def read(self, size: int) -> bytes:
            if self.read_total == 0:
                time.sleep(_OPEN_BOUND * 1.5)
            return super().read(size)

    class _CountingSsh(_StubSshClient):
        def __init__(self, sftp: Any) -> None:
            super().__init__(sftp)
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    ssh = _CountingSsh(_StubSftp(_RecordingChannel(), _SlowFile()))
    client = _sftp_client_with(ssh, monkeypatch)

    assert client.retrieve("/in/a.hl7") == _BODY
    assert ssh.close_calls == 1, (
        f"the client was closed {ssh.close_calls} times; only _op's finally should close it"
    )


def test_a_fast_open_failure_keeps_its_own_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """A refusal inside the bound is reported as itself, not relabelled as a timeout.

    Its classification is whatever ``_op`` gave it before #1936; this test does not pin it.
    """

    class _RejectingSsh(_StubSshClient):
        def open_sftp(self) -> Any:
            raise _FakeSshException("administratively prohibited")

    client = _sftp_client_with(_RejectingSsh(None), monkeypatch)

    with pytest.raises(_RemoteError) as caught:
        client.list_dir("/in")

    assert "administratively prohibited" in str(caught.value)
    assert "timed out" not in str(caught.value)


@pytest.fixture(scope="module")
def host_key() -> Any:
    """One RSA host key for every real-paramiko server in this file; generating one is slow.

    Requesting it SKIPS the test where the ``[sftp]`` extra is not installed; a skip claims nothing.
    """
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    return paramiko.RSAKey.generate(2048)


@contextlib.contextmanager
def _ssh_server(
    server: Any, host_key: Any, tmp_path: Path, *, trust_key: bool = True
) -> Iterator[tuple[int, Path]]:
    """A real in-process paramiko SSH server on loopback, serving one connection with ``server``.

    Yields the port and a ``known_hosts`` file that trusts ``host_key`` for it, or is empty when
    ``trust_key`` is false. Every server transport and the listener are closed on exit.
    """
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    transports: list[Any] = []
    listener = socket.create_server(("127.0.0.1", 0))
    try:
        port = listener.getsockname()[1]
        known_hosts = tmp_path / "known_hosts"
        keys = paramiko.HostKeys()
        if trust_key:
            keys.add(f"[127.0.0.1]:{port}", host_key.get_name(), host_key)
        keys.save(str(known_hosts))

        def _serve() -> None:
            try:
                conn, _ = listener.accept()
            except OSError:  # the listener closed first: the client never got that far
                return
            transport = paramiko.Transport(conn)
            transports.append(transport)
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=server)
            except (paramiko.SSHException, EOFError, OSError):
                # The client dropped the connection mid-negotiation, for example after rejecting
                # the host key. That is what some tests set out to cause, not a failure.
                return

        threading.Thread(target=_serve, daemon=True).start()
        yield port, known_hosts
    finally:
        for transport in transports:
            transport.close()
        listener.close()


def _sftp_settings(
    port: int, known_hosts: Path, connect_timeout: float | None = None
) -> dict[str, Any]:
    """Settings for an ``_SftpClient`` against a loopback test server. ``connect_timeout`` left
    ``None`` keeps the connector's own 30 s default."""
    settings: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port,
        "remote_dir": "/in",
        "username": "synthetic",
        "password": "synthetic-test-password",
        "known_hosts": str(known_hosts),
    }
    if connect_timeout is not None:
        settings["connect_timeout"] = connect_timeout
    return settings


def _list_on_a_thread(client: _SftpClient) -> tuple[object, float]:
    """Run ``list_dir`` on a daemon thread joined at the harness ceiling; return outcome, seconds.

    The ceiling is what turns a regression into a failure instead of a hung run.
    """
    outcome: list[object] = []

    def _poll() -> None:
        try:
            outcome.append(client.list_dir("/in"))
        except BaseException as exc:  # recorded for the caller's assertions
            outcome.append(exc)

    worker = threading.Thread(target=_poll, daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(_PARKED_AFTER)
    assert not worker.is_alive(), f"list_dir was still parked after {_PARKED_AFTER:g}s"
    (result,) = outcome
    return result, time.monotonic() - started


@pytest.mark.parametrize("silent_at", ["channel-open", "subsystem", "version"])
def test_real_paramiko_silent_session_open_is_bounded(
    silent_at: str, host_key: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same property against the real library and a real in-process SSH server.

    The server authenticates, then goes silent at one of the three steps of opening the session: it
    never answers the channel open, never answers the ``sftp`` subsystem request, or accepts that
    request and never sends the SFTP VERSION packet. This is what checks the stub model above.

    SKIPS where the ``[sftp]`` extra is not installed, which is the default here and in CI; a skip
    claims nothing. The operation runs on a daemon thread joined with a ceiling, so a regression
    fails this test instead of hanging the run.
    """
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")

    release = threading.Event()
    server_interface: Any = paramiko.ServerInterface

    class _SilentServer(server_interface):  # type: ignore[misc]
        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_auth_password(self, username: str, password: str) -> int:
            return int(paramiko.AUTH_SUCCESSFUL)

        def check_channel_request(self, kind: str, chanid: int) -> int:
            if silent_at == "channel-open":
                release.wait(_PARKED_AFTER * 2)
            return int(paramiko.OPEN_SUCCEEDED)

        def check_channel_subsystem_request(self, channel: Any, name: str) -> bool:
            if silent_at == "subsystem":
                release.wait(_PARKED_AFTER * 2)
            # Accepted with no SFTP server behind it, so no VERSION packet ever follows.
            return True

    # Only the open bound is shortened. The connect timeout keeps its 30 s default, so a slow key
    # exchange on a loaded runner cannot time out before the test reaches the session open.
    bound = 2.0
    monkeypatch.setattr(remotefile, "SFTP_CHANNEL_READ_TIMEOUT_SECONDS", bound)
    with _ssh_server(_SilentServer(), host_key, tmp_path) as (port, known_hosts):
        try:
            result, elapsed = _list_on_a_thread(_SftpClient(_sftp_settings(port, known_hosts)))
        finally:
            release.set()

    assert isinstance(result, _RemoteError), f"expected a refusal, got {result!r}"
    assert result.permanent is False
    assert "session open timed out" in str(result), str(result)
    assert elapsed < bound + 5.0


# --- connect timeouts are transient (BACKLOG #1999) --------------------------
#
# A peer that is slow in the banner exchange or in authentication is live-again-later, not refusing.
# Before #1999 both were permanent: a banner or key-exchange timeout would dead-letter on first
# deployment, and an authentication timeout would stop the lane as an ADR 0095 credential fault.
# What paramiko raises in each case, and why each discriminator is the one used, is stated once, in
# ``remotefile._sftp_slow_peer``'s docstring.


class _NegTransport:
    """A paramiko ``Transport`` as the connector finds it after a failed ``connect``."""

    def __init__(self, *, kex_done: bool, active: bool, saved: BaseException | None = None) -> None:
        self.initial_kex_done = kex_done
        self._active = active
        self._saved = saved

    def is_active(self) -> bool:
        return self._active

    def get_exception(self) -> BaseException | None:
        saved, self._saved = self._saved, None
        return saved


def _chained_from(message: str, cause: BaseException) -> _FakeSshException:
    """An SSH exception raised while handling ``cause``, as paramiko's banner read raises one: the
    chain is implicit, on ``__context__``, not an explicit ``from``."""
    exc = _FakeSshException(message)
    exc.__context__ = cause
    return exc


def _chained_from_timeout(message: str) -> _FakeSshException:
    return _chained_from(message, TimeoutError())


def _sftp_client_failing_with(
    exc: BaseException,
    transport: _NegTransport,
    monkeypatch: pytest.MonkeyPatch,
    *,
    connect_timeout: float = 0.0,
) -> tuple[_SftpClient, list[int]]:
    """An ``_SftpClient`` whose real ``_connect`` runs against a paramiko whose ``connect`` raises
    ``exc`` and leaves ``transport`` behind. Returns the client and a list counting closes.

    The stub fails at once, so ``connect_timeout`` defaults to 0: the connect has then "waited the
    full bound", as a real banner timeout has. Pass a long one to model an early failure."""
    closes: list[int] = []

    class _FailingClient(_UnconnectedSshClient):
        def connect(self, **kw: Any) -> None:
            raise exc

        def get_transport(self) -> _NegTransport:
            return transport

        def close(self) -> None:
            closes.append(1)

    _use_fake_paramiko(_FailingClient, monkeypatch)
    settings = {"host": "h", "port": 22, "remote_dir": "/in", "connect_timeout": connect_timeout}
    return _SftpClient(settings), closes


#: Each case is a FACTORY, not a built pair: ``_NegTransport.get_exception`` clears what it returns,
#: so a shared instance would pass once and then fail on any re-run of the same item.
_Case = Callable[[], tuple[BaseException, _NegTransport]]


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        pytest.param(
            # What a silent peer produces with the shipped settings: start_client's own wait runs
            # out first and get_remote_server_key refuses on a transport still awaiting the banner.
            lambda: (
                _FakeSshException("No existing session"),
                _NegTransport(kex_done=False, active=True),
            ),
            "timed out",
            id="start_client gave up",
        ),
        pytest.param(
            # The same, but the thread finished the key exchange between the raise and the read.
            lambda: (
                _FakeSshException("No existing session"),
                _NegTransport(kex_done=True, active=True),
            ),
            "timed out",
            id="the exchange finished just after the deadline",
        ),
        pytest.param(
            lambda: (
                _chained_from_timeout("Error reading SSH protocol banner"),
                _NegTransport(kex_done=False, active=False),
            ),
            "timed out",
            id="the banner read timed out first",
        ),
        pytest.param(
            # The thread died of the banner timeout between start_client returning and the check.
            lambda: (
                _FakeSshException("No existing session"),
                _NegTransport(
                    kex_done=False,
                    active=False,
                    saved=_chained_from_timeout("Error reading SSH protocol banner"),
                ),
            ),
            "timed out",
            id="the banner read timed out in the gap",
        ),
        pytest.param(
            # A peer that closes before its banner, as a throttling or restarting sshd does.
            lambda: (
                _chained_from("Error reading SSH protocol banner", EOFError()),
                _NegTransport(kex_done=False, active=False),
            ),
            "dropped the connection",
            id="the peer closed before the banner",
        ),
        pytest.param(
            lambda: (
                _chained_from("Error reading SSH protocol banner", ConnectionResetError()),
                _NegTransport(kex_done=False, active=False),
            ),
            "dropped the connection",
            id="the peer reset before the banner",
        ),
        pytest.param(
            lambda: (
                _FakeAuthException("Authentication timeout."),
                _NegTransport(kex_done=True, active=True),
            ),
            "timed out",
            id="authentication got no answer",
        ),
    ],
)
def test_a_slow_or_dropped_peer_at_connect_is_transient(
    make: _Case, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every way a slow or dropped peer surfaces at connect is a retry, never a dead-letter or a
    lane stop."""
    exc, transport = make()
    client, closes = _sftp_client_failing_with(exc, transport, monkeypatch)

    with pytest.raises(_RemoteError) as caught:
        client.list_dir("/in")

    assert caught.value.permanent is False, "a slow peer is transient, not a dead-letter"
    assert caught.value.credential_fault is False, "no credential caused this"
    assert reason in str(caught.value), str(caught.value)
    assert caught.value.__cause__ is exc, "the paramiko exception must stay on the chain"
    assert closes == [1], f"the half-open client was closed {len(closes)} times"


@pytest.mark.parametrize(
    ("make", "credential_fault"),
    [
        pytest.param(
            lambda: (
                _FakeSshException("Server '[h]:22' not found in known_hosts"),
                _NegTransport(kex_done=True, active=True),
            ),
            False,
            id="a host-key rejection",
        ),
        pytest.param(
            lambda: (
                _FakeAuthException("Authentication failed."),
                _NegTransport(kex_done=True, active=True),
            ),
            True,
            id="an authentication refusal",
        ),
        pytest.param(
            # Left a credential fault on purpose: a server that refuses and then disconnects
            # produces this message too.
            lambda: (
                _FakeAuthException("Authentication failed: transport shut down or saw EOF"),
                _NegTransport(kex_done=True, active=False),
            ),
            True,
            id="the transport died during authentication",
        ),
        pytest.param(
            # A key-exchange mismatch kills the thread before the exchange completes, with no
            # socket fault anywhere on its chain. It is a configuration fault, not a slow peer.
            lambda: (
                _FakeSshException("Incompatible ssh peer (no acceptable kex algorithm)"),
                _NegTransport(kex_done=False, active=False),
            ),
            False,
            id="a key-exchange mismatch",
        ),
        pytest.param(
            # A negotiated transport rules out the negotiation arm even with a timeout on the chain.
            lambda: (
                _chained_from_timeout("a post-exchange failure"),
                _NegTransport(kex_done=True, active=True),
            ),
            False,
            id="a post-exchange failure chained from a timeout",
        ),
        pytest.param(
            # A socket fault on the chain of anything but paramiko's banner-read wrapper is whatever
            # the calling thread was handling, and says nothing about the peer.
            lambda: (
                _chained_from("Negotiation failed.", ConnectionResetError()),
                _NegTransport(kex_done=False, active=False),
            ),
            False,
            id="an unrelated socket fault on the chain",
        ),
    ],
)
def test_a_refusal_at_connect_stays_permanent(
    make: _Case, credential_fault: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CONTROL for the test above: the transient arm must not swallow a real refusal.

    A host-key rejection is a security stop the operator must resolve. An authentication refusal must
    keep its ADR 0095 credential marker, so the lane stops instead of retrying into a lockout.
    """
    exc, transport = make()
    client, closes = _sftp_client_failing_with(exc, transport, monkeypatch)

    with pytest.raises(_RemoteError) as caught:
        client.list_dir("/in")

    assert caught.value.permanent is True, f"must stay permanent: {caught.value}"
    assert caught.value.credential_fault is credential_fault
    assert "timed out" not in str(caught.value), str(caught.value)
    assert closes == [1], f"the half-open client was closed {len(closes)} times"


def test_a_refusal_found_on_the_transport_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exception the transport thread left behind is read destructively, so it must reach the
    message: otherwise the operator sees only "No existing session" and not why."""
    late = _FakeSshException("Incompatible ssh peer (no acceptable kex algorithm)")
    exc = _FakeSshException("No existing session")
    client, _ = _sftp_client_failing_with(
        exc, _NegTransport(kex_done=False, active=False, saved=late), monkeypatch
    )

    with pytest.raises(_RemoteError) as caught:
        client.list_dir("/in")

    assert caught.value.permanent is True
    assert "no acceptable kex algorithm" in str(caught.value), str(caught.value)


def test_a_banner_read_timeout_before_the_bound_stays_permanent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A banner-read timeout well inside the connect timeout is a non-SSH service on the port.

    paramiko waits only 2 s for each line after a first line that is not an SSH banner, so such a
    service fails with the same chained timeout as a silent peer, but early. CONTROL for the
    "the banner read timed out first" case above, which differs from this only in the bound.
    """
    client, closes = _sftp_client_failing_with(
        _chained_from_timeout("Error reading SSH protocol banner"),
        _NegTransport(kex_done=False, active=False),
        monkeypatch,
        connect_timeout=30.0,
    )

    with pytest.raises(_RemoteError) as caught:
        client.list_dir("/in")

    assert caught.value.permanent is True, str(caught.value)
    assert "timed out" not in str(caught.value), str(caught.value)
    assert closes == [1]


def test_the_client_is_closed_whatever_the_connect_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failure outside the mapped classes, and one inside the classifier, both still close.

    Either would otherwise leave a connected socket, and possibly a live transport thread, behind.
    """

    class _Unmapped(Exception):
        pass

    client, closes = _sftp_client_failing_with(
        _Unmapped("not an SSH fault"), _NegTransport(kex_done=True, active=True), monkeypatch
    )
    with pytest.raises(_Unmapped):
        client.list_dir("/in")
    assert closes == [1]

    class _BrokenTransport(_NegTransport):
        def is_active(self) -> bool:
            raise RuntimeError("transport state unreadable")

    client, closes = _sftp_client_failing_with(
        _FakeSshException("No existing session"),
        _BrokenTransport(kex_done=False, active=True),
        monkeypatch,
    )
    with pytest.raises(RuntimeError):
        client.list_dir("/in")
    assert closes == [1]


@pytest.mark.parametrize("peer", ["stays silent", "closes at once"])
def test_real_paramiko_peer_without_a_banner_is_transient(peer: str, tmp_path: Path) -> None:
    """A peer that accepts the connection and never sends a banner, against the real library: one
    stays silent, the other closes straight away, as a throttling or restarting sshd does.

    This is what checks the stub model above. Which exception wins the race between the banner read
    and ``start_client``'s own wait is paramiko's business, and the test passes whichever wins.
    SKIPS where the ``[sftp]`` extra is not installed; a skip claims nothing.
    """
    pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")

    held: list[socket.socket] = []
    listener = socket.create_server(("127.0.0.1", 0))
    try:
        port = listener.getsockname()[1]

        def _accept_and_say_nothing() -> None:
            try:
                conn, _ = listener.accept()
            except OSError:  # the listener closed first: the connect never got that far
                return
            if peer == "closes at once":
                conn.close()
            else:
                held.append(conn)

        threading.Thread(target=_accept_and_say_nothing, daemon=True).start()
        # The peer never reaches a host key, so an empty known_hosts is enough; it must exist.
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text("", encoding="utf-8")
        bound = 1.0

        result, elapsed = _list_on_a_thread(
            _SftpClient(_sftp_settings(port, known_hosts, connect_timeout=bound))
        )
    finally:
        for conn in held:
            conn.close()
        listener.close()

    assert isinstance(result, _RemoteError), f"expected a refusal, got {result!r}"
    assert result.permanent is False, (
        f"a peer with no banner is transient, not a dead-letter: {result}"
    )
    assert result.credential_fault is False
    if peer == "stays silent":
        # A closing peer's wording depends on where the close lands; a silent one's does not.
        assert "banner and key exchange timed out" in str(result), str(result)
    assert elapsed < bound + 5.0


def test_real_paramiko_non_ssh_service_stays_permanent(tmp_path: Path) -> None:
    """A service on the port that greets in another protocol and then waits, as an FTP server does.

    paramiko gives up about 2 s after a first line that is not an SSH banner, with the same chained
    timeout a silent peer produces. CONTROL for the silent-peer test above: the connect timeout here
    is long, so a classifier that ignored how long the connect ran would call this transient.
    SKIPS where the ``[sftp]`` extra is not installed.
    """
    pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")

    held: list[socket.socket] = []
    listener = socket.create_server(("127.0.0.1", 0))
    try:
        port = listener.getsockname()[1]

        def _greet_as_ftp() -> None:
            try:
                conn, _ = listener.accept()
                conn.sendall(b"220 synthetic FTP service ready\r\n")
            except OSError:  # the listener closed first, or the client already hung up
                return
            held.append(conn)

        threading.Thread(target=_greet_as_ftp, daemon=True).start()
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text("", encoding="utf-8")

        result, _ = _list_on_a_thread(
            _SftpClient(_sftp_settings(port, known_hosts, connect_timeout=8.0))
        )
    finally:
        for conn in held:
            conn.close()
        listener.close()

    assert isinstance(result, _RemoteError), f"expected a refusal, got {result!r}"
    assert result.permanent is True, f"a non-SSH service is a misconfiguration: {result}"
    assert "timed out" not in str(result), str(result)


@pytest.mark.parametrize(
    ("server_stalls", "permanent", "credential_fault"),
    [
        pytest.param(True, False, False, id="the server never answers"),
        # CONTROL: an implementation that made every authentication failure transient would pass
        # the stall arm alone.
        pytest.param(False, True, True, id="the server refuses"),
    ],
)
def test_real_paramiko_authentication_timeout_vs_refusal(
    server_stalls: bool,
    permanent: bool,
    credential_fault: bool,
    host_key: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An authentication the server never answers is transient; one it refuses is a credential fault.

    Both arms run against the real library and a real in-process SSH server, because paramiko raises
    the same class for both and only the message differs.
    """
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)

    release = threading.Event()
    server_interface: Any = paramiko.ServerInterface

    class _AuthServer(server_interface):  # type: ignore[misc]
        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_auth_password(self, username: str, password: str) -> int:
            if server_stalls:
                release.wait(_PARKED_AFTER * 2)
            return int(paramiko.AUTH_FAILED)

    # The connect timeout is also the key-exchange bound, so only the stall arm, which needs it to
    # fire, shortens it; the refusal arm keeps the 30 s default so a slow runner cannot time out
    # its key exchange and turn the control into a transient.
    bound = 5.0 if server_stalls else None
    with _ssh_server(_AuthServer(), host_key, tmp_path) as (port, known_hosts):
        try:
            result, elapsed = _list_on_a_thread(
                _SftpClient(_sftp_settings(port, known_hosts, connect_timeout=bound))
            )
        finally:
            release.set()

    assert isinstance(result, _RemoteError), f"expected a refusal, got {result!r}"
    assert result.permanent is permanent, str(result)
    assert result.credential_fault is credential_fault, str(result)
    assert ("timed out" in str(result)) is server_stalls, str(result)
    if bound is not None:
        assert elapsed < bound + 5.0


def test_real_paramiko_unknown_host_key_stays_permanent(
    host_key: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A host-key rejection is still a permanent, non-credential stop against the real library.

    CONTROL for the negotiation arm: this refusal is also a plain ``SSHException``, so a classifier
    reading the exception type alone would have made it transient.
    """
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)

    # trust_key=False: an EMPTY known_hosts, so RejectPolicy refuses the server's key.
    with _ssh_server(paramiko.ServerInterface(), host_key, tmp_path, trust_key=False) as (
        port,
        known_hosts,
    ):
        result, _ = _list_on_a_thread(_SftpClient(_sftp_settings(port, known_hosts)))

    assert isinstance(result, _RemoteError), f"expected a refusal, got {result!r}"
    assert result.permanent is True, f"a rejected host key is a security stop: {result}"
    assert result.credential_fault is False
    assert "known_hosts" in str(result), str(result)
