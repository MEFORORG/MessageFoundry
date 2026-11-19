# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness A5 probe reads a held port as the verifier's ``host.ports`` row does (BACKLOG #5389).

The harness kept its own copy of the old probe, which bound 127.0.0.1 with ``SO_REUSEADDR``: on
Windows it read a wildcard or a non-exclusive listener as free."""

from __future__ import annotations

import socket
import sys

import pytest

from harness.acceptance import probes
from harness.acceptance.matrix import Status


def _evidence_for(monkeypatch: pytest.MonkeyPatch, port: int) -> str:
    monkeypatch.setattr(probes, "_DEFAULT_PORTS", {"P": port})
    result = probes.probe_firewall_ports()
    assert result.status is Status.MANUAL
    return result.evidence.removeprefix(f"P {port}: ")


def test_a5_reads_a_wildcard_listener_as_in_use(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("0.0.0.0", 0))  # nosec B104 -- bound and never listened on
        if sys.platform.startswith("linux"):
            held.listen()
        assert _evidence_for(monkeypatch, held.getsockname()[1]) == "in use/bound"


@pytest.mark.skipif(sys.platform != "win32", reason="SO_REUSEADDR port sharing is Windows-only")
def test_a5_reads_a_non_exclusive_windows_listener_as_in_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        held.bind(("127.0.0.1", 0))
        held.listen()
        assert _evidence_for(monkeypatch, held.getsockname()[1]) == "in use/bound"


def test_a5_reads_a_released_port_as_free(monkeypatch: pytest.MonkeyPatch) -> None:
    # Positive control: a probe that reads every port as in use would pass the tests above. Another
    # process can take a released port before the probe runs, so a few fresh ports are tried.
    seen: list[str] = []
    for _ in range(5):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind(("127.0.0.1", 0))
            port = held.getsockname()[1]
        seen.append(_evidence_for(monkeypatch, port))
        if seen[-1] == "free":
            break
    assert seen[-1] == "free", seen


_ISOLATION_PROBE = """
import sys
import harness.acceptance.probes as probes
probes.probe_firewall_ports()
probes.run_probe("writable_dirs")
# The error arms import the scrub at call time, so run one: a probe that raises.
PLANTED = "pw-Isolat_Ion-1"
def _raises():
    raise RuntimeError("password=" + PLANTED)
probes.PROBES["raises"] = _raises
result = probes.run_probe("raises")
assert PLANTED not in result.detail, result.detail
assert "RuntimeError" in result.detail and "withheld" not in result.detail, result.detail
loaded = sorted(m for m in sys.modules if m.split(".")[:2] in (
    ["messagefoundry", "transports"], ["messagefoundry", "config"],
    ["messagefoundry", "verify"], ["messagefoundry", "pipeline"], ["messagefoundry", "store"]))
print("LOADED=" + ",".join(loaded))
print("LEAF=" + str("messagefoundry.verify_leaf" in sys.modules))
"""


def test_the_harness_probes_load_no_engine_runtime_package() -> None:
    # The A5 probe once imported messagefoundry.verify.checks, which loads the verify runner and,
    # through it, transports and config (136 modules). The leaf must keep that from coming back.
    import subprocess
    from pathlib import Path

    proc = subprocess.run(
        [sys.executable, "-c", _ISOLATION_PROBE],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"isolation probe exited {proc.returncode}:\n{proc.stderr}"
    out = proc.stdout
    assert "LEAF=True" in out, out  # positive control: the probes did reach the leaf
    assert "LOADED=\n" in out, out
