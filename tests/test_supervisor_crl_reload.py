# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The supervisor's own TLS log forwarder picks up a replaced CRL without a restart (BACKLOG #3314).

An engine process applies a replaced CRL file to its running TLS contexts through its
``CrlReloadRunner``. The supervisor builds no engine, so before this nothing in it ran one, and a
collector certificate revoked after the start stayed trusted by its forwarder until a restart.
``supervise`` now runs the same runner while the engine shards run.

The forwarder's context here is the real one, from ``_build_tls_context``, and the handshake is
in memory, so no test opens a socket. The engine shards are a fake ``Supervisor``.
"""

from __future__ import annotations

import asyncio
import ssl
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


def _run_supervise(monkeypatch: pytest.MonkeyPatch, fleet: _Fleet) -> int:
    spec = ShardSpec(shard="default", db_path="mefor.db", port=8765, argv=("serve",))

    async def no_refusal(config: str) -> None:
        return None

    monkeypatch.setattr(supervisor_module, "discover_shard_specs", lambda *a, **k: [spec])
    monkeypatch.setattr(supervisor_module, "preflight_shard_config", no_refusal)
    monkeypatch.setattr(supervisor_module, "Supervisor", lambda specs: fleet)
    monkeypatch.setattr(_StopRecordingRunner, "stops", 0)
    monkeypatch.setattr(crl_reload, "CrlReloadRunner", _StopRecordingRunner)
    return asyncio.run(
        supervise(
            "config",
            store_backend=StoreBackend.SQLITE,
            db_base="mefor.db",
            base_port=8765,
            install_signal_handlers=False,
        )
    )


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
