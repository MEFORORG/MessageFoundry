# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SMB sharing-violation retry: ``Move-CoordFileReplace`` and ``Read-CoordText`` in
``scripts/coord/coord-root.ps1``, and the read twin ``read_text`` in ``coord_root.py``.

The share's failures are in docs/COORD-SHARED-ROOT.md, *What MEFORDEV01 measured*. A local disk raises
the same errors when another process holds the file open with no sharing, so each timed arm here holds the target that way from a second process, and pairs the helper
with a control: the plain .NET or Python call, in the same setup, must fail. Without the control a
pass could mean the hold never landed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
PS = ROOT / "scripts" / "coord" / "coord-root.ps1"
PY = ROOT / "scripts" / "coord" / "coord_root.py"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="share modes are enforced across processes on Windows only",
)

# The holder waits for the other side to say it is ready, holds the file with no sharing, says so,
# then lets go after HoldMs. The handshake is what keeps pwsh's startup time out of the hold.
HOLDER = r"""
param([string]$Target, [string]$Sync, [int]$HoldMs)
$deadline = [DateTime]::UtcNow.AddSeconds(60)
while (-not (Test-Path -LiteralPath (Join-Path $Sync 'ready'))) {
    if ([DateTime]::UtcNow -gt $deadline) { exit 3 }
    Start-Sleep -Milliseconds 5
}
$h = [System.IO.File]::Open($Target, 'Open', 'Read', 'None')
[System.IO.File]::WriteAllText((Join-Path $Sync 'held'), 'x')
Start-Sleep -Milliseconds $HoldMs
$h.Dispose()
"""

# The other side: say ready, wait until the file is held, then run one action and report.
ACTOR = r"""
param([string]$Sync, [string]$Action, [string]$Source, [string]$Target)
. '__PS__'
[System.IO.File]::WriteAllText((Join-Path $Sync 'ready'), 'x')
$deadline = [DateTime]::UtcNow.AddSeconds(60)
while (-not (Test-Path -LiteralPath (Join-Path $Sync 'held'))) {
    if ([DateTime]::UtcNow -gt $deadline) { exit 3 }
    Start-Sleep -Milliseconds 2
}
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$out = [ordered]@{ ok = $false; text = $null; type = $null; hresult = $null; ms = 0 }
try {
    switch ($Action) {
        'move'       { Move-CoordFileReplace -Source $Source -Destination $Target }
        'plain-move' { [System.IO.File]::Move($Source, $Target, $true) }
        'read'       { $out.text = Read-CoordText $Target }
        'plain-read' { $out.text = [System.IO.File]::ReadAllText($Target) }
    }
    $out.ok = $true
} catch {
    $e = Get-CoordInnerException $_.Exception
    $out.type = $e.GetType().FullName
    $out.hresult = $e.HResult
}
$out.ms = $sw.ElapsedMilliseconds
$out | ConvertTo-Json -Compress
"""

SHARING_VIOLATION = -2147024864  # 0x80070020


def _load_py() -> ModuleType:
    spec = importlib.util.spec_from_file_location("coord_root_smb_under_test", PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


coord_root = _load_py()


def _script(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body.replace("__PS__", str(PS)), encoding="utf-8")
    return p


def _holder(tmp_path: Path, target: Path, sync: Path, hold_ms: int) -> subprocess.Popen[str]:
    script = _script(tmp_path, "holder.ps1", HOLDER)
    return subprocess.Popen(
        [
            "pwsh", "-NoProfile", "-NonInteractive", "-File", str(script),
            "-Target", str(target), "-Sync", str(sync), "-HoldMs", str(hold_ms),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )  # fmt: skip


def _held(tmp_path: Path, action: str, hold_ms: int = 500) -> dict[str, Any]:
    """Run one PowerShell action while a second process holds the target with no sharing."""
    sync = tmp_path / f"sync-{action}"
    sync.mkdir()
    target = tmp_path / f"{action}.json"
    target.write_text('{"v": "old"}', encoding="utf-8")
    source = tmp_path / f"{action}.tmp"
    source.write_text('{"v": "new"}', encoding="utf-8")
    holder = _holder(tmp_path, target, sync, hold_ms)
    try:
        actor = _script(tmp_path, "actor.ps1", ACTOR)
        proc = subprocess.run(
            [
                "pwsh", "-NoProfile", "-NonInteractive", "-File", str(actor),
                "-Sync", str(sync), "-Action", action, "-Source", str(source), "-Target", str(target),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )  # fmt: skip
        _, holder_err = holder.communicate(timeout=60)
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.communicate()
    assert proc.returncode == 0 and holder.returncode == 0, (proc.stderr, holder_err)
    out: dict[str, Any] = json.loads(proc.stdout)
    out["target"] = target.read_text(encoding="utf-8")
    out["source_left"] = source.exists()
    return out


def test_move_succeeds_after_the_hold_ends(tmp_path: Path) -> None:
    out = _held(tmp_path, "move")
    assert out["ok"], out
    assert json.loads(out["target"]) == {"v": "new"}
    assert not out["source_left"]
    # It waited for the hold rather than finding the file free.
    assert out["ms"] >= 100, out


def test_control_a_plain_move_fails_while_held(tmp_path: Path) -> None:
    out = _held(tmp_path, "plain-move")
    assert not out["ok"], f"the hold did not land, so the retry arm proves nothing: {out}"
    assert out["type"] == "System.UnauthorizedAccessException", out
    assert json.loads(out["target"]) == {"v": "old"}


def test_read_succeeds_after_the_hold_ends(tmp_path: Path) -> None:
    out = _held(tmp_path, "read")
    assert out["ok"], out
    assert json.loads(out["text"]) == {"v": "old"}
    assert out["ms"] >= 100, out


def test_control_a_plain_read_fails_while_held(tmp_path: Path) -> None:
    out = _held(tmp_path, "plain-read")
    assert not out["ok"], f"the hold did not land, so the retry arm proves nothing: {out}"
    assert out["type"] == "System.IO.IOException" and out["hresult"] == SHARING_VIOLATION, out


def test_a_hold_longer_than_the_retries_surfaces_the_original_error(tmp_path: Path) -> None:
    out = _held(tmp_path, "read", hold_ms=8000)
    assert not out["ok"], out
    assert out["type"] == "System.IO.IOException" and out["hresult"] == SHARING_VIOLATION, out
    # Bounded: the sleeps alone set the floor, and the hold outlasts the ceiling by a wide margin.
    assert 900 <= out["ms"] < 6000, out


def _ps(body: str) -> dict[str, Any]:
    script = f". '{PS}'\n{body}"
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out: dict[str, Any] = json.loads(proc.stdout)
    return out


def test_a_missing_file_is_not_retried(tmp_path: Path) -> None:
    missing = tmp_path / "gone.json"
    src = tmp_path / "also-gone.tmp"
    # A first sleep of 5 s makes any retry unmistakable, without a tight bound on a slow runner.
    out = _ps(
        f"""
$script:CoordRetryFirstMs = 5000
$r = [ordered]@{{}}
foreach ($a in 'read', 'move') {{
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {{
        if ($a -eq 'read') {{ Read-CoordText '{missing}' | Out-Null }}
        else {{ Move-CoordFileReplace -Source '{src}' -Destination '{missing}' }}
        $r[$a] = @{{ type = 'none'; ms = $sw.ElapsedMilliseconds }}
    }} catch [System.IO.FileNotFoundException] {{
        $r[$a] = @{{ type = 'FileNotFound'; ms = $sw.ElapsedMilliseconds }}
    }}
}}
$r | ConvertTo-Json -Compress
"""
    )
    for action in ("read", "move"):
        assert out[action]["type"] == "FileNotFound", out
        assert out[action]["ms"] < 2500, out


def test_a_silenced_caller_still_fails_fast(tmp_path: Path) -> None:
    """Under SilentlyContinue, with no try, a caller would suppress the rethrow and the loop would
    retry a missing file. The helper runs under Stop itself, so it ends at once."""
    out = _ps(
        f"""
$script:CoordRetryFirstMs = 5000
$ErrorActionPreference = 'SilentlyContinue'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$x = Read-CoordText '{tmp_path / "gone.json"}'
[ordered]@{{ ms = $sw.ElapsedMilliseconds; empty = ($null -eq $x) }} | ConvertTo-Json -Compress
"""
    )
    assert out["empty"] is True and out["ms"] < 2500, out


def test_a_reader_shares_with_a_writer(tmp_path: Path) -> None:
    """A file another process holds open for writing still reads, as it did with Get-Content."""
    f = tmp_path / "rec.json"
    f.write_text('{"v": "old"}', encoding="utf-8")
    out = _ps(
        f"""
$r = [ordered]@{{}}
$w = [System.IO.File]::Open('{f}', 'Open', 'ReadWrite', 'ReadWrite')
try {{ $r.helper = Read-CoordText '{f}' }} catch {{ $r.helper = 'FAILED' }}
try {{ [void][System.IO.File]::ReadAllText('{f}'); $r.control = 'read' }} catch {{ $r.control = 'FAILED' }}
$w.Dispose()
$r | ConvertTo-Json -Compress
"""
    )
    assert out["control"] == "FAILED", (
        f"the writer's handle did not conflict, so this proves nothing: {out}"
    )
    assert json.loads(out["helper"]) == {"v": "old"}, out


def _move_onto_read_only(
    tmp_path: Path, flags: str, setup: str = ""
) -> tuple[dict[str, Any], Path, Path]:
    dst = tmp_path / "rec.json"
    dst.write_text('{"v": "old"}', encoding="utf-8")
    src = tmp_path / "rec.tmp"
    src.write_text('{"v": "new"}', encoding="utf-8")
    out = _ps(
        f"""
{setup}
[System.IO.File]::SetAttributes('{dst}', 'ReadOnly')
$r = [ordered]@{{ ok = $false; type = $null; ms = 0 }}
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {{ Move-CoordFileReplace -Source '{src}' -Destination '{dst}' {flags}; $r.ok = $true }}
catch {{ $r.type = (Get-CoordInnerException $_.Exception).GetType().FullName }}
$r.ms = $sw.ElapsedMilliseconds
$r.readOnly = [bool]([System.IO.File]::GetAttributes('{dst}') -band [System.IO.FileAttributes]::ReadOnly)
[System.IO.File]::SetAttributes('{dst}', 'Normal')
$r | ConvertTo-Json -Compress
"""
    )
    return out, dst, src


def test_a_read_only_destination_is_refused_at_once(tmp_path: Path) -> None:
    # File.Move refuses a read-only destination, which handoff.ps1 -Replace and the claim refresh
    # relied on before the helper. The helper refuses it too, before any retry: a read-only mark is
    # not a transient error, so 8 tries over about 1.1 s would only delay the same answer.
    # A first sleep of 5 s makes any retry unmistakable, as in test_a_missing_file_is_not_retried.
    out, dst, src = _move_onto_read_only(tmp_path, "", "$script:CoordRetryFirstMs = 5000")
    assert out["ok"] is False, out
    assert out["type"] == "System.UnauthorizedAccessException", out
    assert out["ms"] < 2500, f"a read-only destination was retried: {out}"
    assert out["readOnly"] is True, out
    assert json.loads(dst.read_text(encoding="utf-8")) == {"v": "old"}
    assert src.exists()


def test_replace_read_only_replaces_as_move_item_did(tmp_path: Path) -> None:
    # The opt-in for lane.ps1 and seat.ps1, whose old `Move-Item -Force` replaced a read-only file.
    out, dst, src = _move_onto_read_only(tmp_path, "-ReplaceReadOnly")
    assert out["ok"] is True, out
    assert json.loads(dst.read_text(encoding="utf-8")) == {"v": "new"}
    assert not src.exists()


def test_an_empty_file_reads_as_nothing_like_get_content(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    out = _ps(
        f"""
$a = @(Get-Content -LiteralPath '{empty}' -Raw | ConvertFrom-Json)
$b = @(Read-CoordText '{empty}' | ConvertFrom-Json)
[ordered]@{{ gc = $a.Count; rct = $b.Count }} | ConvertTo-Json -Compress
"""
    )
    assert out == {"gc": 0, "rct": 0}


# --- the Python twin ------------------------------------------------------------------------------


def _py_held(tmp_path: Path, hold_ms: int, read: Any) -> tuple[object, float]:
    sync = tmp_path / "sync-py"
    sync.mkdir()
    target = tmp_path / "py.json"
    target.write_text('{"v": "old"}', encoding="utf-8")
    holder = _holder(tmp_path, target, sync, hold_ms)
    try:
        (sync / "ready").write_text("x", encoding="utf-8")
        deadline = time.monotonic() + 60
        while not (sync / "held").exists():
            assert time.monotonic() < deadline, "the holder never took the file"
            time.sleep(0.002)
        start = time.monotonic()
        try:
            result: object = read(target)
        except OSError as exc:
            result = exc
        elapsed = time.monotonic() - start
        _, holder_err = holder.communicate(timeout=60)
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.communicate()
    assert holder.returncode == 0, holder_err
    return result, elapsed


def test_twin_read_succeeds_after_the_hold_ends(tmp_path: Path) -> None:
    result, elapsed = _py_held(tmp_path, 500, coord_root.read_text)
    assert isinstance(result, str) and json.loads(result) == {"v": "old"}, result
    assert elapsed >= 0.1


def test_twin_control_a_plain_read_fails_while_held(tmp_path: Path) -> None:
    result, _ = _py_held(tmp_path, 500, lambda p: Path(p).read_text(encoding="utf-8"))
    # Python's open() reports the sharing violation through the C runtime: errno 13, no winerror.
    assert isinstance(result, PermissionError) and coord_root.transient_io_error(result), result


def test_twin_a_hold_longer_than_the_retries_surfaces_the_original_error(tmp_path: Path) -> None:
    result, elapsed = _py_held(tmp_path, 8000, coord_root.read_text)
    assert isinstance(result, PermissionError), result
    assert 0.9 <= elapsed < 6.0, elapsed


def test_twin_a_missing_file_is_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A first sleep of 5 s makes any retry unmistakable, as in the PowerShell arm.
    monkeypatch.setattr(coord_root, "RETRY_FIRST_SECONDS", 5.0)
    start = time.monotonic()
    with pytest.raises(FileNotFoundError):
        coord_root.read_text(tmp_path / "gone.json")
    assert time.monotonic() - start < 2.5


def test_twin_carries_the_same_retry_numbers() -> None:
    text = PS.read_text(encoding="utf-8")

    def ps_int(name: str) -> int:
        m = re.search(rf"^\$script:{name} = (\d+)\s*$", text, re.MULTILINE)
        assert m, name
        return int(m.group(1))

    assert ps_int("CoordRetryTries") == coord_root.RETRY_TRIES
    assert ps_int("CoordRetryFirstMs") == round(coord_root.RETRY_FIRST_SECONDS * 1000)
    assert ps_int("CoordRetryMaxSleepMs") == round(coord_root.RETRY_MAX_SLEEP_SECONDS * 1000)
