# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SFTP thread-parking bounds (BACKLOG #1195, ASVS 15.4.4).

paramiko's ``connect(timeout=...)`` bounds the TCP connect. It does not bound the banner exchange,
authentication, or any read on the channel once the transport is up -- at that point the channel is a
blocking socket again. Every REMOTEFILE operation runs on a worker thread, so a partner share that
accepts a connection and then goes silent would hold one thread per stuck operation, and on a first
deployment enough of them would delay unrelated work that shares the same pool.

These tests live in their own file rather than in ``test_remotefile_transport.py`` because they are
about the socket the connector makes, not about the transfer semantics that file covers.
"""

from __future__ import annotations

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


def _client_over(sftp: Any, monkeypatch: pytest.MonkeyPatch) -> _SftpClient:
    """An ``_SftpClient`` whose ``_connect`` hands back a fake SSH client serving ``sftp``."""
    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _FakeParamiko)
    monkeypatch.setattr(_SftpClient, "_connect", lambda self: _StubSshClient(sftp))
    return _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})


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
