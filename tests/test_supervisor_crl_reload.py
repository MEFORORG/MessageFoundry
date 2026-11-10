# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The supervisor's own TLS log forwarder picks up a replaced CRL without a restart (BACKLOG #3314).

An engine process applies a replaced CRL file to its running TLS contexts through its
``CrlReloadRunner``. The supervisor builds no engine, so before this nothing in it ran one, and on
a first deployment a collector certificate revoked after the start would have stayed trusted by
its forwarder until a restart. ``supervise`` now runs the same runner while the engine shards run.
The revocation is refused at the forwarder's next handshake; nothing here cuts a connection it
already holds.

The forwarder's context here is the real one, from ``_build_tls_context``, and the handshake is
in memory, so no test opens a socket. The engine shards are a fake ``Supervisor``.
"""

from __future__ import annotations

import asyncio
import signal
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend
from messagefoundry.logging_setup import SyslogForward, _build_tls_context
from messagefoundry.pipeline import crl_reload
from messagefoundry.pipeline import supervisor as supervisor_module
from messagefoundry.pipeline.supervisor import ShardSpec, supervise
from tests.test_crl_reload import _accepts, _fresh_registry, _fresher, _make_pki, _Pki

__all__ = ["_fresh_registry"]  # the autouse fixture: no held copies or refusals from other tests

#: How long the fake fleet waits for the forwarder to refuse, against a 50 ms reload interval.
_DEADLINE_SECONDS = 10.0


@pytest.fixture
def pki(tmp_path: Path) -> _Pki:
    return _make_pki(tmp_path, "mefor-3314-collector-ca")


def _forwarder_context(pki: _Pki) -> ssl.SSLContext:
    """The context the supervisor's forwarder wraps its socket with, built from its settings."""
    return _build_tls_context(
        SyslogForward(
            host="localhost",
            port=6514,
            protocol="tls",
            tls_ca_file=str(pki.ca_file),
            tls_crl_file=str(pki.crl),
        )
    )


@dataclass
class _Fleet:
    """Stands in for the engine shards. While it "runs", it revokes the collector's certificate
    and waits for the forwarder's next handshake to be refused."""

    forwarder: ssl.SSLContext
    pki: _Pki
    seen: dict[str, bool] = field(default_factory=dict)
    crash_looped: set[str] = field(default_factory=set)

    async def run(self) -> None:
        # CONTROL: before the revocation, the forwarder accepts the collector.
        self.seen["before"] = _accepts(self.forwarder, self.pki.server())
        self.pki.crl.write_bytes(_fresher(self.pki))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _DEADLINE_SECONDS
        refused = False
        while not refused and loop.time() < deadline:
            await asyncio.sleep(0.05)
            refused = not _accepts(self.forwarder, self.pki.server())
        self.seen["refused_after"] = refused


class _StopRecordingRunner(crl_reload.CrlReloadRunner):
    """The real runner, on a short interval so the test does not wait out a minute, recording
    its stop: it lives only as long as ``supervise``, and a loop left running would outlive the
    process's event loop."""

    stops = 0

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**{**kwargs, "interval_seconds": 0.05})

    async def stop(self) -> None:
        await super().stop()
        type(self).stops += 1


def _fake_fleet(monkeypatch: pytest.MonkeyPatch, fleet: Any) -> None:
    spec = ShardSpec(shard="default", db_path="mefor.db", port=8765, argv=("serve",))

    async def no_refusal(config: str) -> None:
        return None

    monkeypatch.setattr(supervisor_module, "discover_shard_specs", lambda *a, **k: [spec])
    monkeypatch.setattr(supervisor_module, "preflight_shard_config", no_refusal)
    monkeypatch.setattr(supervisor_module, "Supervisor", lambda specs: fleet)


async def _supervise(*, install_signal_handlers: bool) -> int:
    return await supervise(
        "config",
        store_backend=StoreBackend.SQLITE,
        db_base="mefor.db",
        base_port=8765,
        install_signal_handlers=install_signal_handlers,
    )


def _run_supervise(monkeypatch: pytest.MonkeyPatch, fleet: _Fleet) -> int:
    _fake_fleet(monkeypatch, fleet)
    monkeypatch.setattr(_StopRecordingRunner, "stops", 0)
    monkeypatch.setattr(crl_reload, "CrlReloadRunner", _StopRecordingRunner)
    return asyncio.run(_supervise(install_signal_handlers=False))


def test_the_supervisor_forwarder_refuses_a_collector_revoked_after_start(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _Fleet(_forwarder_context(pki), pki)

    assert _run_supervise(monkeypatch, fleet) == 0
    assert fleet.seen["before"] is True, "control: the clean CRL should admit the collector"
    assert fleet.seen["refused_after"] is True, (
        "the supervisor's forwarder still accepted a collector whose certificate the replaced "
        "CRL revokes, so nothing in the supervisor reloaded it"
    )
    assert _StopRecordingRunner.stops == 1, "the runner must stop when the fleet does"


def test_the_supervisor_refused_reload_line_names_its_process(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The supervisor raises no [alerts] alert, and the shared remedy speaks of "the engine", so
    its line says which process wrote it and where the ERROR line is."""
    sink = supervisor_module._supervisor_crl_alert_sink()
    with caplog.at_level("WARNING", logger=supervisor_module.logger.name):
        sink.crl_reload_refused(
            "crl_reload:/etc/pki/c.pem@supervisor",
            path="/etc/pki/c.pem",
            remedy_class="restart",
            stale_contexts=1,
            remedy=crl_reload.RESTART,
        )
    [record] = [r for r in caplog.records if "ALERT crl_reload_refused" in r.getMessage()]
    message = record.getMessage()
    assert record.levelname == "WARNING"
    # CONTROL: the shared detail is still there, so the note is added to it, not in place of it.
    assert crl_reload.RESTART in message and "engine log gives the reason" in message
    assert supervisor_module.SUPERVISOR_CRL_REFUSED_NOTE in message


#: When the blocked pass is let go on its own. The cut must end the stop well before this.
_PASS_RELEASE_SECONDS = 4.0


class _BlockedPassRunner(crl_reload.CrlReloadRunner):
    """A runner whose pass blocks in its worker thread, as a CRL read on a hung share would, until
    ``release`` is set. It runs a pass with no CRL held, so the pass starts at once."""

    entered = threading.Event()
    release = threading.Event()

    def __init__(self, **kwargs: Any) -> None:
        def blocked_reload() -> list[object]:
            type(self).entered.set()
            type(self).release.wait(_PASS_RELEASE_SECONDS * 4)
            return []

        super().__init__(
            **{
                **kwargs,
                "interval_seconds": 0.01,
                "skip_when_idle": False,
                "reload": blocked_reload,
            }
        )


@dataclass
class _SignalledFleet:
    """Stands in for the engine shards. It takes over the loop's signal handlers, so the test can
    send a signal on any platform; it waits for the reload pass to block, drains, and sends
    SIGTERM a moment into the supervisor's stop."""

    handlers: dict[int, Callable[[], object]] = field(default_factory=dict)
    crash_looped: set[str] = field(default_factory=set)
    signalled_at: list[float] = field(default_factory=list)

    def take_over_signals(self, loop: asyncio.AbstractEventLoop) -> None:
        def add(sig: int, callback: Callable[[], object], *args: object) -> None:
            self.handlers[sig] = callback

        def remove(sig: int) -> bool:
            return self.handlers.pop(sig, None) is not None

        loop.add_signal_handler = add  # type: ignore[method-assign]
        loop.remove_signal_handler = remove  # type: ignore[method-assign]

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        while not _BlockedPassRunner.entered.is_set():
            await asyncio.sleep(0.01)

        def send_sigterm() -> None:
            self.signalled_at.append(loop.time())
            self.handlers[signal.SIGTERM]()

        loop.call_later(0.2, send_sigterm)


def test_a_shutdown_signal_cuts_the_wait_on_a_blocked_crl_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fleet = _SignalledFleet()
    _fake_fleet(monkeypatch, fleet)
    monkeypatch.setattr(_BlockedPassRunner, "entered", threading.Event())
    monkeypatch.setattr(_BlockedPassRunner, "release", threading.Event())
    monkeypatch.setattr(crl_reload, "CrlReloadRunner", _BlockedPassRunner)
    # Lets the pass go on its own, so its worker thread ends and asyncio.run is not held at exit.
    releaser = threading.Timer(_PASS_RELEASE_SECONDS, _BlockedPassRunner.release.set)

    async def main() -> tuple[int, float, bool]:
        loop = asyncio.get_running_loop()
        fleet.take_over_signals(loop)
        releaser.start()
        code = await _supervise(install_signal_handlers=True)
        return code, loop.time(), _BlockedPassRunner.release.is_set()

    try:
        code, returned_at, released = asyncio.run(main())
    finally:
        _BlockedPassRunner.release.set()
        releaser.cancel()
    assert code == 0
    assert fleet.signalled_at, "control: the fake fleet never sent the signal"
    # CONTROL: the pass was still blocked when supervise returned, so the stop did not end because
    # the pass did.
    assert not released, "the blocked pass was released before supervise returned"
    assert returned_at - fleet.signalled_at[0] < 1.0, (
        "SIGTERM during the CRL reload's stop did not cut the wait on its blocked pass"
    )
    assert fleet.handlers == {}, "the stop's signal handlers must be removed once it ends"
