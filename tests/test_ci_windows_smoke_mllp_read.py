# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The windows-service-smoke MLLP step fails a failed send and an unrouted message (BACKLOG #5473).

The step used to run ``samples/send_mllp.py`` with no exit check and count ``/messages`` total,
whatever the disposition. A pwsh step does not stop on a native command's non-zero exit unless
``$PSNativeCommandUseErrorActionPreference`` is on, and ``$LASTEXITCODE`` was then overwritten by
the read, so a refused connection passed on any recorded message, and so did a NAKed or stuck one.

The job runs only on hosted Windows, in the merge queue, nightly and on dispatch, so this module
EXECUTES the real step body under pwsh, wrapped the way GitHub wraps a ``shell: pwsh`` step, with
a ``python`` function standing in for the two programs it calls: a pwsh function wins over an
application of the same name. Each bad case is also run against the pre-fix body, frozen below as
the control, to show it is one the old step passed. Each bad case leaves the other guards
satisfied, so it fails only if its own guard fires.

The row's unadjudicated item S31-27 (the smoke installs with uv, not the docs' hash-locked
``requirements.lock``) is settled by tests/test_windows_lock_install.py, which pins the Windows
hash-locked install on every pull request; it is not restated here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._workflow_contexts import step_script

_STEP = "Send an MLLP message and confirm it was recorded"

#: The step body before BACKLOG #5473, comment lines removed: the control.
_OLD_BODY = r"""
$cert = "C:\ProgramData\MessageFoundry\api-generated-cert.pem"
python samples\send_mllp.py samples\messages\adt_a01.hl7
$total = & python -m harness.load.rigadmin get --engine https://127.0.0.1:8765 --cacert $cert --field total --at-least 1 --timeout 10 /messages
if ($LASTEXITCODE -eq 4) { throw "the rig could not sign in to the service, or the service answered /messages with no session" }
if ($LASTEXITCODE -ne 0) { throw "message was not recorded by the engine (messages.total = '$total')" }
"messages.total = $total"
"""

#: The stand-in for `python`. A scenario names the send's exit and ACK code, the rig's exit, and
#: the count per status. The rig answers `--at-least 1` the way rigadmin does: it prints the count
#: and exits 0 when reached, else 1; `api_refused` prints nothing and exits 1, as a non-200 does.
_STUB = r"""
$scenario = Get-Content -Raw -LiteralPath $env:SCENARIO | ConvertFrom-Json
function python {
  if ($args[0] -like '*send_mllp.py') {
    "--- ACK ---"
    "MSH|^~\&|RECEIVINGAPP|RECEIVINGFAC|SENDINGAPP|SENDINGFAC|20260101000000||ACK|MSG00001|P|2.5.1"
    "MSA|$($scenario.ack)|MSG00001"
    $global:LASTEXITCODE = [int]$scenario.send_exit
    return
  }
  if ([int]$scenario.rig_exit -ne 0) { $global:LASTEXITCODE = [int]$scenario.rig_exit; return }
  if ($scenario.api_refused) { $global:LASTEXITCODE = 1; return }
  $path = [string]$args[-1]
  $status = if ($path -match 'status=(\w+)') { $Matches[1] } else { 'total' }
  $count = [int]$scenario.counts.$status
  $count
  $global:LASTEXITCODE = if ($count -ge 1) { 0 } else { 1 }
}
"""

_PWSH = shutil.which("pwsh")
_needs_pwsh = pytest.mark.skipif(_PWSH is None, reason="pwsh not on PATH")


def _new_body() -> str:
    _, body = step_script("ci.yml", "windows-service-smoke", _STEP)
    return body


def _run(
    body: str, scenario: dict[str, object], tmp_path: Path, account: str = "virtual"
) -> subprocess.CompletedProcess[str]:
    """Run ``body`` as GitHub runs a ``shell: pwsh`` step: Stop preference, then exit on the code."""
    scenario_file = tmp_path / "scenario.json"
    scenario_file.write_text(json.dumps(scenario), encoding="utf-8")
    script = tmp_path / "step.ps1"
    script.write_text(
        "$ErrorActionPreference = 'stop'\n"
        + _STUB
        + body
        + "\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }\n",
        encoding="utf-8",
    )
    assert _PWSH is not None
    return subprocess.run(  # noqa: S603  # nosec B603 - resolved pwsh, fixed argv, tmp paths
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "SCENARIO": str(scenario_file), "SMOKE_ACCOUNT": account},
    )


def _scenario(
    *,
    send_exit: int = 0,
    ack: str = "AA",
    rig_exit: int = 0,
    api_refused: bool = False,
    **counts: int,
) -> dict[str, object]:
    full = {"total": 0, "processed": 0, "routed": 0} | counts
    return {
        "send_exit": send_exit,
        "ack": ack,
        "rig_exit": rig_exit,
        "api_refused": api_refused,
        "counts": full,
    }


#: Cases the old step PASSED and the new one must FAIL. The first two leave a processed message
#: in the store, so only the send guard or the ACK guard can fail them.
_BAD = [
    pytest.param(_scenario(send_exit=1, total=1, processed=1), id="send-failed"),
    pytest.param(_scenario(ack="AE", total=1, processed=1), id="nak"),
    pytest.param(_scenario(total=1), id="stuck-at-received"),
    pytest.param(_scenario(total=1, api_refused=True), id="api-refused-the-filtered-read"),
]


@_needs_pwsh
@pytest.mark.parametrize("scenario", _BAD)
def test_the_old_step_passed_this_case(scenario: dict[str, object], tmp_path: Path) -> None:
    """The control: each bad case is one the pre-fix body reported green."""
    scenario = {**scenario, "api_refused": False}  # the old read was unfiltered
    proc = _run(_OLD_BODY, scenario, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@_needs_pwsh
@pytest.mark.parametrize(
    ("scenario", "says"),
    [
        (_BAD[0].values[0], "send_mllp.py exited 1"),
        (_BAD[1].values[0], "carries no MSA|AA"),
        (_BAD[2].values[0], "did not reach processed or routed"),
        (_BAD[3].values[0], "with no count"),
    ],
    ids=["send-failed", "nak", "stuck-at-received", "api-refused-the-filtered-read"],
)
def test_the_step_fails_this_case(scenario: dict[str, object], says: str, tmp_path: Path) -> None:
    proc = _run(_new_body(), scenario, tmp_path)
    assert proc.returncode != 0, f"the step passed a case it must refuse:\n{proc.stdout}"
    assert says in proc.stdout + proc.stderr, proc.stdout + proc.stderr


@_needs_pwsh
@pytest.mark.parametrize(
    ("scenario", "found"),
    [
        pytest.param(_scenario(total=1, processed=1), "processed", id="processed"),
        pytest.param(_scenario(total=1, routed=1), "routed", id="routed-delivery-pending"),
    ],
)
def test_a_virtual_leg_passes_a_routed_message(
    scenario: dict[str, object], found: str, tmp_path: Path
) -> None:
    proc = _run(_new_body(), scenario, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"IB_Test_ADT messages {found} = 1" in proc.stdout


@_needs_pwsh
def test_the_localsystem_leg_must_reach_processed(tmp_path: Path) -> None:
    """LocalSystem can write the install root, so ROUTED is not enough there."""
    routed = _run(_new_body(), _scenario(total=1, routed=1), tmp_path, account="localsystem")
    assert routed.returncode != 0, routed.stdout
    processed = _run(_new_body(), _scenario(total=1, processed=1), tmp_path, account="localsystem")
    assert processed.returncode == 0, processed.stdout + processed.stderr


@_needs_pwsh
def test_the_step_fails_when_the_rig_cannot_sign_in(tmp_path: Path) -> None:
    proc = _run(_new_body(), _scenario(rig_exit=4, processed=1), tmp_path)
    assert proc.returncode != 0
    assert "could not sign in" in proc.stdout + proc.stderr


def test_the_read_is_scoped_to_the_listener_and_reads_no_bare_total() -> None:
    body = _new_body()
    assert "channel_id=IB_Test_ADT" in body
    assert "--timeout 10 /messages" not in body, "the step reads /messages unfiltered again"
