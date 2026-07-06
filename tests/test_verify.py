# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the wheel-only deployment verifier (`messagefoundry verify`).

These run in CI from the dev repo even though the tool ships in the wheel: they prove no host check
raises, the smoke/store paths behave, the report renders, and the CLI wires up + exits correctly.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.base import open_store
from messagefoundry.store.store import MessageStatus
from messagefoundry.verify import checks, smoke
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.report import exit_code, render_console, render_json, render_markdown
from messagefoundry.verify.runner import ALL_SECTIONS, run_verify


# ---- host checks ------------------------------------------------------------------------------


def test_run_host_checks_never_errors(tmp_path: Path) -> None:
    results = checks.run_host_checks(ports={"MLLP": 2575}, writable_dir=tmp_path)
    assert results, "no host checks produced"
    for r in results:
        assert isinstance(r, CheckResult)
        assert isinstance(r.status, Status)
        assert r.detail
        assert r.status is not Status.ERROR, f"{r.id} errored: {r.detail}"


def test_python_runtime_passes() -> None:
    r = checks.check_python_runtime()
    assert r.status is Status.PASS
    assert "messagefoundry" in r.detail


def test_writable_dir_pass_and_fail(tmp_path: Path) -> None:
    ok = checks.check_writable_dir(tmp_path)
    assert ok.status is Status.MANUAL  # writable -> MANUAL (ACLs still need a human)
    # A path under a file can't be created -> FAIL, not a crash.
    afile = tmp_path / "afile"
    afile.write_text("x", encoding="utf-8")
    bad = checks.check_writable_dir(afile / "subdir")
    assert bad.status is Status.FAIL


def test_listener_ports_is_manual_with_evidence() -> None:
    r = checks.check_listener_ports({"MLLP": 2575, "API": 8765})
    assert r.status is Status.MANUAL
    assert "MLLP" in r.evidence and "API" in r.evidence


def test_console_no_window_detects_flag() -> None:
    # PySide6 is a dev dep, so service_control is importable here and carries CREATE_NO_WINDOW.
    r = checks.check_console_no_window()
    assert r.status in (Status.MANUAL, Status.SKIP)
    assert r.status is not Status.FAIL


class _HttpxBlocker:
    """A meta_path finder that makes httpx un-importable (simulates a no-[console] install)."""

    def find_spec(self, name: str, path: object = None, target: object = None) -> None:
        if name == "httpx" or name.startswith("httpx."):
            raise ModuleNotFoundError("No module named 'httpx'")
        return None


@pytest.fixture
def httpx_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Evict cached httpx + console modules so find_spec re-runs the parent __init__ (a cached spec
    # would otherwise mask the crash), then block httpx at import time.
    import sys

    for mod in list(sys.modules):
        if mod == "httpx" or mod.startswith("httpx.") or mod.startswith("messagefoundry.console"):
            monkeypatch.delitem(sys.modules, mod, raising=False)
    monkeypatch.setattr(sys, "meta_path", [_HttpxBlocker(), *sys.meta_path])


def test_console_no_window_no_crash_without_httpx(httpx_absent: None) -> None:
    # Regression (Bug B): on a [sqlserver]-only box (no [console] extra, so no httpx) this crashed
    # the whole `verify --section host` run with ModuleNotFoundError. After the lazy-console fix the
    # source still ships, so the check completes honestly (MANUAL or SKIP) rather than raising.
    r = checks.check_console_no_window()
    assert r.id == "host.noflash"
    assert r.status in (Status.MANUAL, Status.SKIP)
    assert r.status is not Status.FAIL


def test_run_host_checks_never_errors_without_httpx(httpx_absent: None, tmp_path: Path) -> None:
    # The whole host suite must still complete (no raise, no ERROR) on a non-[console] box.
    results = checks.run_host_checks(ports={"MLLP": 2575}, writable_dir=tmp_path)
    assert results
    for r in results:
        assert r.status is not Status.ERROR, f"{r.id} errored: {r.detail}"


# ---- self smoke -------------------------------------------------------------------------------


def test_self_smoke_missing_config_skips() -> None:
    r = smoke.smoke_self("no/such/config/dir")
    assert r.status is Status.SKIP


def test_self_smoke_ambiguous_inbound_skips() -> None:
    # samples/config has several inbounds; with none chosen, the smoke skips and lists them.
    r = smoke.smoke_self("samples/config")
    assert r.status is Status.SKIP
    assert "inbound" in r.detail.lower()


def test_self_smoke_routes_synthetic_adt() -> None:
    r = smoke.smoke_self("samples/config", inbound="IB_ACME_ADT")
    assert r.status is Status.PASS, r.detail
    assert "deliveries=" in r.detail


def test_synthetic_message_is_hl7() -> None:
    msg = smoke.synthetic_message()
    assert msg.startswith("MSH|")


# ---- live smoke (ACK parsing + a fake MLLP server) --------------------------------------------


def test_ack_code_parses_msa() -> None:
    aa = b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AA|1\r"
    assert smoke._ack_code(aa) == "AA"
    ae = b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AE|1|bad\r"
    assert smoke._ack_code(ae) == "AE"
    assert smoke._ack_code(b"not hl7") is None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _serve_one(ack: bytes) -> int:
    """Start a one-shot MLLP server that replies with `ack`; return its port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = int(srv.getsockname()[1])

    def handle() -> None:
        try:
            conn, _ = srv.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(b"\x0b" + ack + b"\x1c\x0d")
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def test_live_smoke_passes_on_aa() -> None:
    port = _serve_one(b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AA|1\r")
    r = smoke.smoke_live(
        host="127.0.0.1", port=port, message=smoke.synthetic_message(), timeout=5.0
    )
    assert r.status is Status.PASS, r.detail


def test_live_smoke_fails_on_nak() -> None:
    port = _serve_one(b"MSH|^~\\&|R|R|S|S|20260101||ACK|1|P|2.5.1\rMSA|AR|1\r")
    r = smoke.smoke_live(
        host="127.0.0.1", port=port, message=smoke.synthetic_message(), timeout=5.0
    )
    assert r.status is Status.FAIL
    assert "AR" in r.detail


def test_live_smoke_fails_when_unreachable() -> None:
    r = smoke.smoke_live(host="127.0.0.1", port=_free_port(), message="MSH|x", timeout=2.0)
    assert r.status is Status.FAIL


# ---- store connectivity -----------------------------------------------------------------------


def test_store_connectivity_sqlite(tmp_path: Path) -> None:
    settings = StoreSettings(path=str(tmp_path / "verify.db"))
    r = smoke.check_store_connectivity(settings)
    assert r.status is Status.PASS, r.detail


# ---- report -----------------------------------------------------------------------------------


def test_report_render_and_exit_code() -> None:
    rows = [
        CheckResult("a", "alpha", Status.PASS, "ok"),
        CheckResult("b", "beta", Status.MANUAL, "later"),
        CheckResult("c", "gamma", Status.SKIP, "n/a"),
    ]
    assert exit_code(rows) == 0
    assert exit_code(rows + [CheckResult("d", "delta", Status.FAIL, "boom")]) == 1
    assert exit_code(rows + [CheckResult("e", "eps", Status.ERROR, "broke")]) == 1

    console = render_console(rows)
    assert "alpha" in console and "exit 0" in console
    md = render_markdown(rows)
    assert "| a | alpha |" in md
    import json

    parsed = json.loads(render_json(rows))
    assert parsed["exit_code"] == 0
    assert parsed["tally"]["PASS"] == 1
    assert {r["id"] for r in parsed["results"]} == {"a", "b", "c"}


# ---- runner + CLI -----------------------------------------------------------------------------


def test_run_verify_sections_and_manual() -> None:
    results = run_verify(sections=["host", "manual"], smoke_mode="none")
    ids = {r.id for r in results}
    assert any(i.startswith("host.") for i in ids)
    assert "manual.nssm" in ids
    assert not any(i.startswith("smoke.") for i in ids)  # smoke not selected
    assert all(r.status is not Status.ERROR for r in results)


def test_run_verify_manual_only() -> None:
    results = run_verify(sections=["manual"], smoke_mode="none")
    assert results and all(r.id.startswith("manual.") for r in results)


def test_cli_verify_runs_and_exits_zero() -> None:
    assert main(["verify", "--section", "host,manual", "--smoke", "none"]) == 0


def test_cli_verify_rejects_unknown_section(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", "--section", "bogus", "--smoke", "none"]) == 2
    assert "unknown section" in capsys.readouterr().err


def test_all_sections_constant() -> None:
    assert set(ALL_SECTIONS) == {"host", "store", "smoke", "manual"}


# ---- disposition (--check-disposition) --------------------------------------------------------

_RAW_ADT = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X|P|2.5.1\rEVN|A01|20260101\rPID|1||1^^^H^MR||DOE^J\r"
)


async def _seed_message(settings: StoreSettings, *, control_id: str, status: MessageStatus) -> str:
    handle = await open_store(settings)
    try:
        return await handle.record_received(
            channel_id="verify-test", raw=_RAW_ADT, status=status, control_id=control_id
        )
    finally:
        await handle.close()


def test_classify_disposition() -> None:
    ok = smoke._classify_disposition("processed", control_id="X", timeout=5)
    assert ok.status is Status.PASS and ok.id == "smoke.disposition"
    err = smoke._classify_disposition("error", control_id="X", timeout=5)
    assert err.status is Status.FAIL and "ERROR" in err.detail
    assert smoke._classify_disposition("unrouted", control_id="X", timeout=5).status is Status.FAIL
    assert smoke._classify_disposition("filtered", control_id="X", timeout=5).status is Status.FAIL
    inflight = smoke._classify_disposition("routed", control_id="X", timeout=5)
    assert (
        inflight.status is Status.FAIL and "ROUTED" in inflight.detail
    )  # still in flight at timeout
    none = smoke._classify_disposition(None, control_id="X", timeout=5)
    assert none.status is Status.FAIL and "no NEW stored message" in none.detail


def test_store_connectivity_detail_names_calling_user(tmp_path: Path) -> None:
    settings = StoreSettings(path=str(tmp_path / "verify.db"))
    r = smoke.check_store_connectivity(settings)
    assert r.status is Status.PASS
    assert "calling user" in r.detail and "service account" in r.detail


def test_check_smoke_disposition_processed(tmp_path: Path) -> None:
    settings = StoreSettings(path=str(tmp_path / "d.db"))
    asyncio.run(_seed_message(settings, control_id="CID-OK", status=MessageStatus.PROCESSED))
    r = smoke.check_smoke_disposition(settings, control_id="CID-OK", baseline_id=None, timeout=3)
    assert r.status is Status.PASS and r.id == "smoke.disposition"


def test_check_smoke_disposition_dead_letter_fails(tmp_path: Path) -> None:
    settings = StoreSettings(path=str(tmp_path / "d.db"))
    asyncio.run(_seed_message(settings, control_id="CID-BAD", status=MessageStatus.ERROR))
    r = smoke.check_smoke_disposition(settings, control_id="CID-BAD", baseline_id=None, timeout=3)
    assert r.status is Status.FAIL and "ERROR" in r.detail


def test_check_smoke_disposition_ignores_baseline(tmp_path: Path) -> None:
    # A pre-existing message with the same control id (the baseline) must NOT satisfy the check — only
    # a NEWER message counts, so a re-used synthetic id can't pass on a prior run's result.
    settings = StoreSettings(path=str(tmp_path / "d.db"))
    old = asyncio.run(_seed_message(settings, control_id="CID-DUP", status=MessageStatus.PROCESSED))
    r = smoke.check_smoke_disposition(settings, control_id="CID-DUP", baseline_id=old, timeout=1)
    assert r.status is Status.FAIL and "no NEW stored message" in r.detail


def test_run_verify_check_disposition_skips_without_settings() -> None:
    # check_disposition with no --service-config: the disposition row SKIPs (no store to poll).
    results = run_verify(
        sections=["smoke"], smoke_mode="live", mllp_port=59999, check_disposition=True
    )
    disp = [r for r in results if r.id == "smoke.disposition"]
    assert disp and disp[0].status is Status.SKIP
