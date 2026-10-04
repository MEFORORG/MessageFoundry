# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ingress probe runs a signed-in ``serve`` and stops it before it returns (ADR 0203).

One short, low-rate run on SQLite in a temp dir. It does not grade the measurement: the probe
asserts nothing about rates, and neither does this. It shows the probe still prints its RESULT
line, that the engine it started refused a read with no session, and that the engine is gone once
the repeat returns.
"""

from __future__ import annotations

import ast
import importlib.util
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType

import pytest

import harness.load.ingress_probe as ingress_probe
from harness.load import rigadmin
from harness.load.failover import EngineNode

_SUMMARY_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "ci" / "ingress_probe_summary.py"
)


def _load_summary() -> ModuleType:
    """The workflow's RESULT parser, imported by path -- ``scripts/`` is not a package."""
    spec = importlib.util.spec_from_file_location(
        "ingress_probe_summary_engine_leg", _SUMMARY_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs: @dataclass resolves the module's namespace through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_summary = _load_summary()


def test_the_setup_failure_line_is_one_the_workflow_parser_accepts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Round trip of the probe's ERROR shape through ``ingress-rate-probe.yml``'s parser."""
    assert ingress_probe._setup_failed(20.0, "provision_failed", OSError("boom")) == 2
    result = _summary.summarise(capsys.readouterr().out, rate=20.0, repeat=3)
    assert result.errors == [] and len(result.rows) == 1 and result.measured == 0, result


def test_every_setup_failure_reason_matches_the_workflow_parser() -> None:
    """Each reason the probe can print must pass the parser's ERROR pattern, or a real setup
    failure on a runner would read as a broken pipeline. Read from the probe's call sites."""
    tree = ast.parse(Path(ingress_probe.__file__).read_text(encoding="utf-8"))
    reasons = [
        node.args[1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_setup_failed"
        and isinstance(node.args[1], ast.Constant)
    ]
    assert len(reasons) >= 4, reasons  # positive control: the four call sites read on 2026-10-03
    for reason in reasons:
        assert _summary._REASON.fullmatch(reason), reason


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
    # The line the workflow's parser must accept: a drift in the probe's RESULT grammar reds here,
    # on the engine leg that a change to the probe runs.
    result = _summary.summarise(out, rate=20.0, repeat=1)
    assert result.errors == [] and result.measured == 1, (result, out)
