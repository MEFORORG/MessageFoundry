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

import socket
import threading
import time
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


class _FakeAuthException(Exception):
    pass


class _FakeParamiko:
    """The two exception classes ``_op`` catches by attribute off the lazily imported module."""

    SSHException = _FakeSshException
    AuthenticationException = _FakeAuthException


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

    class _CapturingClient:
        def load_system_host_keys(self) -> None:
            return None

        def load_host_keys(self, path: str) -> None:
            return None

        def set_missing_host_key_policy(self, policy: Any) -> None:
            return None

        def connect(self, **kw: Any) -> None:
            captured.update(kw)

    class _Policy:
        pass

    class _Transport:
        _preferred_macs: tuple[str, ...] = ()
        _preferred_ciphers: tuple[str, ...] = ()

    class _Paramiko(_FakeParamiko):
        SSHClient = _CapturingClient
        RejectPolicy = _Policy
        AutoAddPolicy = _Policy
        Transport = _Transport

    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _Paramiko)
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


@pytest.mark.parametrize("silent_at", ["channel-open", "subsystem", "version"])
def test_real_paramiko_silent_session_open_is_bounded(
    silent_at: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    host_key = paramiko.RSAKey.generate(2048)
    server_transports: list[Any] = []
    listener = socket.create_server(("127.0.0.1", 0))
    try:
        port = listener.getsockname()[1]
        known_hosts = tmp_path / "known_hosts"
        keys = paramiko.HostKeys()
        keys.add(f"[127.0.0.1]:{port}", host_key.get_name(), host_key)
        keys.save(str(known_hosts))

        def _serve() -> None:
            conn, _ = listener.accept()
            transport = paramiko.Transport(conn)
            server_transports.append(transport)
            transport.add_server_key(host_key)
            transport.start_server(server=_SilentServer())

        threading.Thread(target=_serve, daemon=True).start()

        client = _SftpClient(
            {
                "host": "127.0.0.1",
                "port": port,
                "remote_dir": "/in",
                "username": "synthetic",
                "password": "synthetic-test-password",
                "known_hosts": str(known_hosts),
            }
        )
        outcome: list[object] = []

        def _poll() -> None:
            try:
                outcome.append(client.list_dir("/in"))
            except BaseException as exc:  # recorded for the assertions below
                outcome.append(exc)

        worker = threading.Thread(target=_poll, daemon=True)
        started = time.monotonic()
        worker.start()
        worker.join(_PARKED_AFTER)
        elapsed = time.monotonic() - started

        assert not worker.is_alive(), (
            f"list_dir was still parked after {_PARKED_AFTER:g}s with the server silent at "
            f"{silent_at}: the session open is unbounded"
        )
        (result,) = outcome
        assert isinstance(result, _RemoteError), f"expected a refusal, got {result!r}"
        assert result.permanent is False
        assert "session open timed out" in str(result), str(result)
        assert elapsed < bound + 5.0
    finally:
        release.set()
        for transport in server_transports:
            transport.close()
        listener.close()
