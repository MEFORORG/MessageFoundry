# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ingress probe runs a signed-in ``serve`` and stops it before it returns (ADR 0203).

One short, low-rate run on SQLite in a temp dir. It does not grade the measurement: the probe
asserts nothing about rates, and neither does this. It shows the probe still prints its RESULT
line, that the engine it started refused a read with no session, and that the engine is gone once
the repeat returns.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

import pytest

import harness.load.ingress_probe as ingress_probe
from harness.load import rigadmin
from harness.load.failover import EngineNode


@pytest.fixture
def fresh_rig(monkeypatch: pytest.MonkeyPatch) -> None:
    """Own credential and session holders, put back after (as ``tests/test_rig_admin.py`` does)."""
    monkeypatch.setattr(rigadmin, "_credential", rigadmin._HeldAdmin())
    monkeypatch.setattr(rigadmin, "_held", rigadmin._HeldSession())
    # Set, then deleted: `rig_admin` publishes a drawn password into the environment itself, and
    # monkeypatch can only undo a variable it has seen.
    for name in (rigadmin.ADMIN_PASS_ENV, rigadmin.ADMIN_NAME_ENV):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


# A provisioning child, a `serve` start, one short load phase with its drain, and a graceful stop.
@pytest.mark.timeout(240)
@pytest.mark.usefixtures("fresh_rig")
def test_one_repeat_signs_in_and_stops_its_engine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    nodes: list[EngineNode] = []
    unsigned_status: list[int] = []

    class _Recorded(EngineNode):
        async def start(self, *, provision: bool = True) -> None:
            nodes.append(self)
            await super().start(provision=provision)

        async def stop(self) -> None:
            # Read before the stop: a request with no session must be refused by this engine. The
            # stop runs whatever the read does, so a failed read cannot leave the engine running.
            try:
                with urllib.request.urlopen(
                    f"{self.url}/stats",
                    context=ssl.create_default_context(cafile=self.cacert),
                    timeout=5.0,
                ) as reply:
                    unsigned_status.append(int(reply.status))
            except urllib.error.HTTPError as exc:
                unsigned_status.append(exc.code)
            except Exception:  # noqa: BLE001 - any other failure is recorded and judged below
                unsigned_status.append(-1)
            finally:
                await super().stop()

    monkeypatch.setattr(ingress_probe, "EngineNode", _Recorded)

    assert ingress_probe.main(["20", "--duration", "0.5"]) == 0

    out = capsys.readouterr().out
    results = [line for line in out.splitlines() if line.startswith("RESULT ")]
    assert len(results) == 1, out
    assert "ERROR=" not in results[0], results[0]
    assert " ok=" in results[0] and " sent=" in results[0], results[0]
    assert len(nodes) == 1
    assert unsigned_status == [401], "the probe's engine answered /stats with no session"
    assert not nodes[0].alive, "the probe returned with its engine still running"
