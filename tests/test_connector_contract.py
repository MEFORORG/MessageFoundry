# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connector contract in ``transports/base.py``, checked across every registered connector.

Three parts (BACKLOG #1624, review finding P2-10):

* **The registry refuses a silent overwrite.** ``register_source(ConnectorType.MLLP, <other>)`` used
  to replace the built-in with no error, and ``build_source`` then returned the stand-in. It now
  raises unless the caller passes ``replace=True``.
* **``SourceConnector.stop()`` is idempotent.** Every registered source is built and stopped twice
  before it ever starts, each call under a timeout. Every source that can start without dialing
  out is also started, run past its first tick, and stopped twice. That is every source except
  DATABASE and REMOTEFILE, whose start dials a server. The settings table must name every
  registered source, so a new connector is pulled into this check rather than skipping it.
* **A listener closes an established peer on ``stop()``.** The four asyncio listeners are started on
  an ephemeral loopback port with one idle peer attached. The peer must see the connection close
  well inside the listeners' 5-second grace, so a ``stop()`` that waits out the grace fails.

What this does NOT check: ``stop()`` staying bounded while a peer, a share call or the handler is
stuck. That needs a per-connector stall, and the per-connector suites own it. The negative
controls at the end prove the idempotence check can fail.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.transports  # noqa: F401 - the import runs every register_source(...)
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.transports import base as transport_base
from messagefoundry.transports.base import (
    DestinationConnector,
    InboundHandler,
    SourceConnector,
    build_destination,
    build_source,
    register_destination,
    register_source,
)
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource

#: Per-call timeout for the idempotence check. A generous ceiling, not a performance bound: a
#: stop() before start() has nothing to wait for, so anything near this is a hang.
_STOP_TIMEOUT = 5.0

#: The minimum settings each registered source builds with. No builder here dials or binds; a
#: build only validates settings. Keyed by the registry, so a new source must add a row.
_SOURCE_SETTINGS: dict[ConnectorType, dict[str, Any]] = {
    ConnectorType.MLLP: {"port": 2575},
    ConnectorType.TCP: {"port": 2575, "framing": "mllp"},
    ConnectorType.X12: {"port": 2575},
    ConnectorType.HTTP: {"port": 8080},
    ConnectorType.FILE: {},  # "directory" comes from tmp_path
    ConnectorType.DATABASE: {
        "server": "db.example",
        "database": "feeds",
        "poll_statement": "SELECT id, payload FROM inbox",
        "mark_statement": "UPDATE inbox SET done = 1 WHERE id = :id",
        "body_column": "payload",
    },
    ConnectorType.REMOTEFILE: {
        "host": "sftp.example",
        "protocol": "sftp",
        "username": "feed",
        "password": "synthetic",
        "remote_dir": "/in",
    },
    ConnectorType.TIMER: {"body": "MSH|^~\\&|TIMER", "interval_seconds": 60},
    ConnectorType.LOOPBACK: {},
    ConnectorType.PT: {},
    ConnectorType.DIMSE: {"port": 104, "ae_title": "MEFOR"},
}

#: The asyncio listeners. Started on 127.0.0.1 port 0, so they bind but dial nothing.
_LISTENERS = (ConnectorType.MLLP, ConnectorType.TCP, ConnectorType.X12, ConnectorType.HTTP)

#: DIMSE's start() imports pynetdicom, which only the [dicom] extra installs.
_DIMSE = pytest.param(
    ConnectorType.DIMSE,
    id="dimse",
    marks=pytest.mark.skipif(
        importlib.util.find_spec("pynetdicom") is None, reason="needs the [dicom] extra"
    ),
)

#: The sources whose start() dials nothing: inert, a local timer, a poll of tmp_path, a listener.
_STARTABLE_WITHOUT_DIALING = (
    *[
        pytest.param(kind, id=kind.value)
        for kind in (
            ConnectorType.LOOPBACK,
            ConnectorType.PT,
            ConnectorType.TIMER,
            ConnectorType.FILE,
            *_LISTENERS,
        )
    ],
    _DIMSE,
)

#: The sources whose loop calls the handler on its own once started, so the test can wait for the
#: first call and know the loop is running before it stops the source.
_CALLS_HANDLER_ON_START = (ConnectorType.TIMER, ConnectorType.FILE)

#: How long an idle peer may wait for its close. Well inside the listeners' 5-second grace, so a
#: stop() that waits out the grace instead of closing the peer fails here.
_PEER_CLOSE_BOUND = 3.0


def _ids(kinds: Any) -> list[str]:
    return [kind.value for kind in kinds]


def _build(kind: ConnectorType, tmp_path: Path) -> SourceConnector:
    settings = dict(_SOURCE_SETTINGS[kind])
    if kind is ConnectorType.FILE:
        settings["directory"] = str(tmp_path)
    if kind in _LISTENERS or kind is ConnectorType.DIMSE:
        settings["port"] = 0
    name = f"IB_CONTRACT_{kind.value.upper()}"
    return build_source(Source(type=kind, name=name, settings=settings))


async def _assert_stop_idempotent(source: SourceConnector, timeout: float = _STOP_TIMEOUT) -> None:
    """Call ``stop()`` twice. Each call must return within ``timeout`` and must not raise."""
    for call in ("first", "second"):
        try:
            await asyncio.wait_for(source.stop(), timeout)
        except TimeoutError:
            raise AssertionError(
                f"{type(source).__name__}.stop() {call} call did not return in {timeout}s"
            ) from None
        except Exception as exc:
            raise AssertionError(
                f"{type(source).__name__}.stop() {call} call raised {type(exc).__name__}: {exc}"
            ) from exc


def _recording_handler() -> tuple[InboundHandler, asyncio.Event]:
    called = asyncio.Event()

    async def _handler(_raw: bytes) -> str | None:
        called.set()
        return None

    return _handler, called


# --- the registry ---------------------------------------------------------------------------------


def test_the_settings_table_names_every_registered_source() -> None:
    """Coverage. Without it, a new source would skip the idempotence check and stay green."""
    assert set(_SOURCE_SETTINGS) == set(transport_base._SOURCES)


def test_re_registering_a_built_in_source_raises_and_keeps_the_original() -> None:
    """The finding's own run, inverted: the stand-in is refused and MLLP still builds MLLP."""

    def _impostor(config: Source) -> SourceConnector:
        raise AssertionError("the impostor builder must never be installed")

    with pytest.raises(ValueError, match="already registered for 'mllp'"):
        register_source(ConnectorType.MLLP, _impostor)
    built = build_source(Source(type=ConnectorType.MLLP, settings={"port": 2575}))
    assert isinstance(built, MLLPSource)


def test_re_registering_a_built_in_destination_raises_and_keeps_the_original() -> None:
    def _impostor(config: Destination) -> DestinationConnector:
        raise AssertionError("the impostor builder must never be installed")

    with pytest.raises(ValueError, match="already registered for 'mllp'"):
        register_destination(ConnectorType.MLLP, _impostor)
    built = build_destination(
        Destination(name="OB_MLLP", type=ConnectorType.MLLP, settings={"host": "h", "port": 2575})
    )
    assert isinstance(built, MLLPDestination)


def test_replace_true_replaces_and_a_first_registration_needs_no_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Controls for the refusal: it is about a DUPLICATE, not a registry that refuses everything.
    Runs against copies of the tables, so the real registry is untouched."""
    sources = dict(transport_base._SOURCES)
    destinations = dict(transport_base._DESTINATIONS)
    monkeypatch.setattr(transport_base, "_SOURCES", sources)
    monkeypatch.setattr(transport_base, "_DESTINATIONS", destinations)

    def _source_builder(config: Source) -> SourceConnector:
        raise NotImplementedError

    def _destination_builder(config: Destination) -> DestinationConnector:
        raise NotImplementedError

    sources.pop(ConnectorType.TCP)
    register_source(ConnectorType.TCP, _source_builder)
    assert sources[ConnectorType.TCP] is _source_builder

    register_source(ConnectorType.MLLP, _source_builder, replace=True)
    assert sources[ConnectorType.MLLP] is _source_builder

    destinations.pop(ConnectorType.TCP)
    register_destination(ConnectorType.TCP, _destination_builder)
    assert destinations[ConnectorType.TCP] is _destination_builder

    register_destination(ConnectorType.MLLP, _destination_builder, replace=True)
    assert destinations[ConnectorType.MLLP] is _destination_builder


# --- stop() is idempotent --------------------------------------------------------------------------


_ALL_SOURCES = sorted(_SOURCE_SETTINGS, key=lambda k: k.value)


@pytest.mark.parametrize("kind", _ALL_SOURCES, ids=_ids(_ALL_SOURCES))
async def test_stop_before_start_is_idempotent(kind: ConnectorType, tmp_path: Path) -> None:
    await _assert_stop_idempotent(_build(kind, tmp_path))


async def _stop_quietly(source: SourceConnector) -> None:
    """Best-effort teardown, so a failed test never leaves a live source on the shared loop."""
    # Teardown only: the test body has already reported the real failure, if there was one.
    with contextlib.suppress(Exception):
        await asyncio.wait_for(source.stop(), _STOP_TIMEOUT)


@pytest.mark.parametrize("kind", _STARTABLE_WITHOUT_DIALING)
async def test_stop_after_start_is_idempotent(kind: ConnectorType, tmp_path: Path) -> None:
    source = _build(kind, tmp_path)
    if kind is ConnectorType.FILE:
        (tmp_path / "contract.hl7").write_bytes(b"MSH|^~\\&|CONTRACT\r")
    handler, called = _recording_handler()
    await source.start(handler)
    try:
        if kind in _CALLS_HANDLER_ON_START:
            # Run the loop past its first stop check, so stop() meets a RUNNING task.
            await asyncio.wait_for(called.wait(), _STOP_TIMEOUT)
        else:
            await asyncio.sleep(0)
        await _assert_stop_idempotent(source)
    finally:
        await _stop_quietly(source)


async def _read_to_close(reader: asyncio.StreamReader) -> bytes:
    try:
        return await reader.read()
    except ConnectionError:
        return b""  # a reset is a close too


@pytest.mark.parametrize("kind", _LISTENERS, ids=_ids(_LISTENERS))
async def test_stop_closes_an_established_idle_peer(kind: ConnectorType, tmp_path: Path) -> None:
    """Times the PEER'S close, not stop()'s return. stop() may still spend its own bounded grace on
    ``server.wait_closed()`` (a known Windows Proactor wedge), which is not this obligation."""
    source = _build(kind, tmp_path)
    handler, _called = _recording_handler()
    await source.start(handler)
    writer: asyncio.StreamWriter | None = None
    try:
        server: asyncio.Server = source._server  # type: ignore[attr-defined]
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)  # let the listener accept and register the peer
        read = asyncio.create_task(_read_to_close(reader))
        loop = asyncio.get_running_loop()
        started = loop.time()
        stop = asyncio.create_task(source.stop())
        tail = await asyncio.wait_for(read, _STOP_TIMEOUT * 2)
        closed_after = loop.time() - started
        await asyncio.wait_for(stop, _STOP_TIMEOUT * 2)
        assert tail == b"", f"the peer read {tail!r} instead of the close"
        assert closed_after < _PEER_CLOSE_BOUND, (
            f"{type(source).__name__}.stop() closed its idle peer after {closed_after:.2f}s; it "
            "should close the peer, not wait out the grace"
        )
        await _assert_stop_idempotent(source)
    finally:
        if writer is not None:
            writer.close()
        await _stop_quietly(source)


class _HangsOnSecondStop(SourceConnector):
    def __init__(self) -> None:
        self._stopped = False

    async def start(self, handler: InboundHandler, *, leader_gate: Any = None) -> None:
        return None

    async def stop(self) -> None:
        if self._stopped:
            await asyncio.Event().wait()
        self._stopped = True


class _RaisesOnSecondStop(_HangsOnSecondStop):
    async def stop(self) -> None:
        if self._stopped:
            raise RuntimeError("already stopped")
        self._stopped = True


async def test_the_idempotence_check_fails_on_a_second_stop_that_hangs() -> None:
    """Negative control: a check that cannot fail proves nothing."""
    with pytest.raises(AssertionError, match="second call did not return"):
        await _assert_stop_idempotent(_HangsOnSecondStop(), timeout=0.05)


async def test_the_idempotence_check_fails_on_a_second_stop_that_raises() -> None:
    with pytest.raises(AssertionError, match="second call raised RuntimeError"):
        await _assert_stop_idempotent(_RaisesOnSecondStop(), timeout=0.05)
