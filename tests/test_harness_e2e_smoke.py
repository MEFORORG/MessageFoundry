# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``python -m harness.e2e_smoke`` against a real engine, with negative controls.

Each test starts a real ``serve`` subprocess, so each costs an engine start (about 10 to 20 s).

The configs here are written per test with a free MLLP port, so parallel workers and other
checkouts on the same box never contend for the sample's fixed 2575. The sample config itself is
what ``.claude/skills/verify/SKILL.md`` runs; its graph is the one mirrored below.

The controls prove the script can fail, and that it names the step that did:

* an inbound bound to a router nothing registers: the engine refuses the graph, so ``serve`` fails;
* a router that selects no handler: the message is ACKed and ends UNROUTED, so ``disposition``
  fails. This is the control for the claim that the script reads the final disposition and does
  not stop at the ACK.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

from harness import e2e_smoke
from tests._harness_engine import free_port

#: Above the subprocess cap below, so a hung engine fails as that timeout, with its output.
pytestmark = pytest.mark.timeout(300)

_REPO = Path(__file__).resolve().parents[1]

_ARCHIVE_GRAPH = """\
from messagefoundry import MLLP, File, Send, handler, inbound, outbound, router

inbound("IB_E2E_ADT", MLLP(port={port}), router="e2e_router")
outbound("FILE-OUT_E2E_ADT", File(directory="./out/adt", filename="{{MSH-10}}.hl7"))


@router("e2e_router")
def route(msg):  # type: ignore[no-untyped-def]
    return {handlers}


@handler("archive")
def archive(msg):  # type: ignore[no-untyped-def]
    return Send("FILE-OUT_E2E_ADT", msg)
"""

_DANGLING_ROUTER = """\
from messagefoundry import MLLP, inbound

inbound("IB_E2E_ADT", MLLP(port={port}), router="no_such_router")
"""


def _smoke(config: Path, port: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "harness.e2e_smoke",
            "--config",
            str(config),
            "--inbound",
            "IB_E2E_ADT",
            "--mllp-port",
            str(port),
            "--api-port",
            str(free_port()),
        ],
        cwd=_REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
        check=False,
    )


def _config(tmp_path: Path, template: str, **values: object) -> tuple[Path, int]:
    port = free_port()
    config = tmp_path / "config"
    config.mkdir()
    (config / "e2e_graph.py").write_text(template.format(port=port, **values), encoding="utf-8")
    return config, port


def test_a_routed_message_ends_processed(tmp_path: Path) -> None:
    config, port = _config(tmp_path, _ARCHIVE_GRAPH, handlers='["archive"]')
    done = _smoke(config, port)
    assert done.returncode == 0, done.stderr + done.stdout
    assert "step disposition: PROCESSED" in done.stdout
    assert "PASS e2e smoke" in done.stdout


def test_an_unrouted_message_fails_the_disposition_step(tmp_path: Path) -> None:
    config, port = _config(tmp_path, _ARCHIVE_GRAPH, handlers="[]")
    done = _smoke(config, port)
    assert done.returncode == 1, done.stderr + done.stdout
    # The ACK passed, so the failure is the disposition the API reported, not an earlier step.
    assert "step mllp: AA" in done.stdout
    assert "FAIL disposition:" in done.stderr
    assert "UNROUTED, expected PROCESSED" in done.stderr


def test_a_router_nothing_registers_fails_the_serve_step(tmp_path: Path) -> None:
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    done = _smoke(config, port)
    assert done.returncode == 1, done.stderr + done.stdout
    assert "FAIL serve:" in done.stderr
    assert "step mllp" not in done.stdout


def test_a_taken_mllp_port_fails_before_any_engine_starts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, port = _config(tmp_path, _DANGLING_ROUTER)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        holder.bind(("127.0.0.1", port))
        holder.listen()
        code = e2e_smoke.main(["--config", str(config), "--mllp-port", str(port)])
    out = capsys.readouterr()
    assert code == 1, out.err + out.out
    assert f"FAIL ports: MLLP port {port} is already in use" in out.err
    assert "step serve" not in out.out


def test_the_command_line_parses(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        e2e_smoke.main(["--help"])
    assert exited.value.code == 0
    assert "--mllp-port" in capsys.readouterr().out
