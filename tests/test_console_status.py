# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console Engine-Status page and its off-thread plumbing (Workstream G).

Covers: the :class:`AsyncRunner` worker→main-thread contract, the leader/cluster view rendering, the
non-blocking refresh (the engine read runs off the Qt main thread), and that the shell health poll still
treats a 401 as session-expired (review M-26) after being moved off-thread.
"""

from __future__ import annotations

import os
import threading

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.api.models import (  # noqa: E402
    ClusterNode,
    ClusterNodeList,
    ClusterStatus,
    ConfigProvenance,
    DbInfo,
    EngineInfo,
    IntegrityResult,
    SystemStatus,
)
from messagefoundry.console import shell as shell_mod  # noqa: E402
from messagefoundry.console import status as status_mod  # noqa: E402
from messagefoundry.console._async import AsyncRunner  # noqa: E402
from messagefoundry.console.client import ApiError  # noqa: E402
from messagefoundry.console.status import EngineStatusPage  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _drain(qapp) -> None:
    # Deliver the queued worker→main signal(s) after waitForDone has let the worker finish.
    for _ in range(5):
        qapp.processEvents()


def _status(*, free: int = 100 * 1024**3) -> SystemStatus:
    return SystemStatus(
        engine=EngineInfo(
            version="0.1.0",
            uptime_seconds=3661,
            pid=4242,
            channels_total=3,
            channels_running=2,
            channels_stopped=1,
            outbox_by_status={"PENDING": 5},
        ),
        db=DbInfo(
            path="/srv/mf.db",
            size_bytes=2 * 1024**2,
            disk_free_bytes=free,
            journal_mode="wal",
            messages=10,
            events=20,
            audit=30,
        ),
    )


def _cluster_status(*, clustered: bool, role: str) -> ClusterStatus:
    return ClusterStatus(
        node_id="nodeA",
        clustered=clustered,
        is_leader=role != "standby",
        role=role,
        config_version=7,
    )


def _nodes() -> ClusterNodeList:
    return ClusterNodeList(
        nodes=[
            ClusterNode(
                node_id="nodeA",
                host="hostA",
                pid=4242,
                status="leader",
                started_at=1000.0,
                last_seen=2000.0,
                is_leader=True,
            ),
            ClusterNode(
                node_id="nodeB",
                host="hostB",
                pid=None,
                status="standby",
                started_at=1001.0,
                last_seen=None,
                is_leader=False,
            ),
        ],
        leader_node_id="nodeA",
        lease_owner="nodeA",
        lease_expires_at=9_999_999_999.0,
    )


class FakeStatusClient:
    """Minimal EngineClient stand-in: records the thread its reads ran on so tests can prove off-thread."""

    def __init__(
        self,
        *,
        status_error: ApiError | None = None,
        cluster_error: ApiError | None = None,
        clustered: bool = True,
        provenance: ConfigProvenance | None = None,
        provenance_error: ApiError | None = None,
    ) -> None:
        self._status_error = status_error
        self._cluster_error = cluster_error
        self._clustered = clustered
        self._provenance = provenance
        self._provenance_error = provenance_error
        self.status_thread: int | None = None
        self.integrity_thread: int | None = None
        self.current_user = None  # AppWindow: skip the account menu branch

    def can(self, _perm: str) -> bool:
        return False

    def status(self) -> SystemStatus:
        self.status_thread = threading.get_ident()
        if self._status_error is not None:
            raise self._status_error
        return _status()

    def cluster_status(self) -> ClusterStatus:
        if self._cluster_error is not None:
            raise self._cluster_error
        return _cluster_status(
            clustered=self._clustered, role="primary" if self._clustered else "single-node"
        )

    def cluster_nodes(self) -> ClusterNodeList:
        if self._cluster_error is not None:
            raise self._cluster_error
        return _nodes()

    def integrity_check(self) -> IntegrityResult:
        self.integrity_thread = threading.get_ident()
        return IntegrityResult(ok=True, detail="")

    def config_provenance(self) -> ConfigProvenance:
        if self._provenance_error is not None:
            raise self._provenance_error
        return self._provenance or ConfigProvenance(loaded=True, git_head="a" * 40, drift=False)


# --- AsyncRunner: the worker→main-thread contract ----------------------------


def test_async_runner_runs_off_thread_delivers_on_main(qapp) -> None:
    runner = AsyncRunner()
    main = threading.get_ident()
    seen: dict[str, int | str] = {}

    def work() -> str:
        seen["worker"] = threading.get_ident()
        return "ok"

    def on_done(result: str) -> None:
        seen["done"] = threading.get_ident()
        seen["result"] = result

    runner.submit(work, on_done=on_done)
    runner._pool.waitForDone(5000)
    _drain(qapp)
    assert seen["worker"] != main  # the blocking call ran OFF the main thread
    assert seen["done"] == main  # ...but the callback was delivered ON the main thread
    assert seen["result"] == "ok"
    runner.stop()


def test_async_runner_routes_errors_to_on_error(qapp) -> None:
    runner = AsyncRunner()
    errors: list[BaseException] = []

    def boom() -> None:
        raise ValueError("nope")

    runner.submit(
        boom,
        on_done=lambda _r: errors.append(RuntimeError("should not happen")),
        on_error=errors.append,
    )
    runner._pool.waitForDone(5000)
    _drain(qapp)
    assert len(errors) == 1 and isinstance(errors[0], ValueError)
    runner.stop()


def test_async_runner_stop_drops_late_result(qapp) -> None:
    runner = AsyncRunner()
    delivered: list[object] = []
    runner.submit(lambda: 1, on_done=delivered.append)
    runner.stop()  # waits for the worker, marks stopped, clears pending callbacks
    _drain(qapp)
    assert delivered == []  # the in-flight result is dropped, never delivered to a torn-down widget


# --- EngineStatusPage rendering (deterministic: drive _fetch/_apply directly) ---


def test_status_page_renders_engine_db_and_cluster(qapp, monkeypatch) -> None:
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "running")
    page = EngineStatusPage(FakeStatusClient())  # type: ignore[arg-type]
    page._apply(page._fetch())
    assert page._engine["Reachable"].text() == "yes"
    assert page._engine["Channels"].text() == "2 running / 3 total"
    assert page._engine["Config"].text() == "aaaaaaa — clean"  # default clean provenance
    assert page._db["Messages"].text() == "10"
    # Cluster (leader view) is shown with the role + live leader + node roster. (isHidden, not
    # isVisible: the page is never .show()n in an offscreen test, so isVisible is always False —
    # isHidden reflects the explicit setVisible flag we toggle.)
    assert not page._cluster_box.isHidden()
    assert page._cl_mode.text() == "clustered"
    assert "primary" in page._cl_role.text() and "nodeA" in page._cl_role.text()
    assert page._cl_leader.text() == "nodeA"
    assert "nodeA" in page._cl_lease.text()
    assert page._nodes.topLevelItemCount() == 2
    assert page._nodes.topLevelItem(0).text(5) == "✓ leader"  # leader marked
    assert page._nodes.topLevelItem(1).text(2) == "—"  # standby pid is None -> placeholder
    page.stop()


def test_status_page_hides_cluster_when_endpoints_unavailable(qapp, monkeypatch) -> None:
    # Older engine / not permitted: /cluster reads 404/403 -> hide the box rather than error.
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "running")
    client = FakeStatusClient(cluster_error=ApiError("not found", status=404))
    page = EngineStatusPage(client)  # type: ignore[arg-type]
    page._apply(page._fetch())
    assert page._engine["Reachable"].text() == "yes"
    assert page._cluster_box.isHidden()
    page.stop()


def test_status_page_engine_unreachable_emits_error(qapp, monkeypatch) -> None:
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "not installed")
    client = FakeStatusClient(status_error=ApiError("down", status=503))
    page = EngineStatusPage(client)  # type: ignore[arg-type]
    emitted: list[str] = []
    page.error.connect(emitted.append)
    page._apply(page._fetch())
    assert page._engine["Reachable"].text() == "no"
    assert page._cluster_box.isHidden()
    assert emitted == ["down"]
    page.stop()


def test_status_page_shows_config_drift(qapp, monkeypatch) -> None:
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "running")
    prov = ConfigProvenance(loaded=True, git_head="deadbeef" + "0" * 32, drift=True)
    page = EngineStatusPage(FakeStatusClient(provenance=prov))  # type: ignore[arg-type]
    page._apply(page._fetch())
    assert page._engine["Config"].text() == "deadbee — DRIFTED"
    page.stop()


def test_status_page_config_blank_when_provenance_unavailable(qapp, monkeypatch) -> None:
    # Older engine / not permitted: /config/provenance 404/403 -> the Config row stays '—', no error.
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "running")
    client = FakeStatusClient(provenance_error=ApiError("not found", status=404))
    page = EngineStatusPage(client)  # type: ignore[arg-type]
    page._apply(page._fetch())
    assert page._engine["Reachable"].text() == "yes"
    assert page._engine["Config"].text() == "—"
    page.stop()


def test_provenance_text_formats() -> None:
    assert status_mod._provenance_text(None) == "—"
    assert status_mod._provenance_text(ConfigProvenance(loaded=False)) == "—"
    assert (
        status_mod._provenance_text(ConfigProvenance(loaded=True, git_head="a" * 40, drift=False))
        == "aaaaaaa — clean"
    )
    assert (
        status_mod._provenance_text(ConfigProvenance(loaded=True, git_head="b" * 40, drift=True))
        == "bbbbbbb — DRIFTED"
    )
    assert (
        status_mod._provenance_text(
            ConfigProvenance(loaded=True, fingerprint="c" * 64, drift=False)
        )
        == "cccccccccccc — clean"
    )


def test_status_refresh_reads_off_main_thread(qapp, monkeypatch) -> None:
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "running")
    client = FakeStatusClient()
    page = EngineStatusPage(client)  # type: ignore[arg-type]
    main = threading.get_ident()
    page.refresh()
    page._runner._pool.waitForDone(5000)
    _drain(qapp)
    assert client.status_thread is not None and client.status_thread != main  # ran off-thread
    assert page._engine["Reachable"].text() == "yes"  # ...and the result applied on the main thread
    page.stop()


def test_status_integrity_runs_off_main_thread(qapp, monkeypatch) -> None:
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "running")
    client = FakeStatusClient()
    page = EngineStatusPage(client)  # type: ignore[arg-type]
    main = threading.get_ident()
    page._run_integrity()
    assert not page._integrity_btn.isEnabled()  # disabled while running
    page._runner._pool.waitForDone(5000)
    _drain(qapp)
    assert client.integrity_thread is not None and client.integrity_thread != main
    assert page._integrity_result.text() == "✓ ok"
    assert page._integrity_btn.isEnabled()  # re-enabled after
    page.stop()


# --- Shell health poll: 401 still means session-expired after going off-thread (M-26) ---


def test_health_poll_401_emits_session_expired(qapp, monkeypatch) -> None:
    monkeypatch.setattr(shell_mod.service_control, "service_state", lambda _n: "not installed")
    window = shell_mod.AppWindow(FakeStatusClient())  # type: ignore[arg-type]
    expired: list[bool] = []
    window.session_expired.connect(lambda: expired.append(True))
    # Drive the apply step directly with a 401 — the off-thread fetch already returned it.
    window._apply_health(("not installed", None, ApiError("expired", status=401), None))
    assert expired == [True]  # M-26: 401 -> session_expired, not a generic "unreachable"
    window.close()


def test_health_poll_reads_off_main_thread(qapp, monkeypatch) -> None:
    monkeypatch.setattr(shell_mod.service_control, "service_state", lambda _n: "not installed")
    client = FakeStatusClient()
    window = shell_mod.AppWindow(client)  # type: ignore[arg-type]
    main = threading.get_ident()
    # The constructor kicks an INITIAL poll (shell.py: self._poll_health() at the end of __init__)
    # that arms the single-flight guard (_health_loading=True). Fully drain it FIRST — waitForDone
    # lets worker #1 finish and _drain delivers its queued _apply_health, which clears the guard — so
    # OUR poll below is guaranteed to submit a fresh worker instead of being coalesced away.
    window._health_runner._pool.waitForDone(5000)
    _drain(qapp)
    # guard now cleared, so our _poll_health() below submits a fresh worker (not coalesced)
    assert window._health_loading is False
    client.status_thread = None  # reset AFTER the initial poll is fully settled
    window._poll_health()
    window._health_runner._pool.waitForDone(5000)
    # Wait on the fetch ACTUALLY completing (bounded condition-poll, no fixed sleep): _apply_health is
    # delivered via a queued signal, so pump events until the worker's status() write lands.
    for _ in range(50):
        _drain(qapp)
        if client.status_thread is not None:
            break
    assert client.status_thread is not None and client.status_thread != main
    window.close()


# --- #38: a problem engine connection must not wedge the console — it recovers cleanly -------------
# The console reaches the engine ONLY over HTTP (no WebSocket — it polls /stats); these assert the
# "(c) reconnects/recovers cleanly once the engine returns" clause, which the other console tests
# (which cover the single-error half: unreachable/401/malformed-body/off-thread) don't exercise.


def test_health_poll_recovers_after_engine_returns(qapp, monkeypatch) -> None:
    # A transient unreachable poll turns the nav heart red and the shell owns the reachability error;
    # the very NEXT routine poll, once the engine is back, clears both with no operator action.
    monkeypatch.setattr(shell_mod.service_control, "service_state", lambda _n: "not installed")
    client = FakeStatusClient()
    window = shell_mod.AppWindow(client)  # type: ignore[arg-type]

    window._apply_health(window._fetch_health())  # engine healthy
    assert window._heart._state == "green"

    client._status_error = ApiError("connection refused", status=503)  # engine drops mid-session
    window._apply_health(window._fetch_health())
    assert window._heart._state == "red"
    assert "connection refused" in window._status.text()
    assert window._health_error  # the poll owns this reachability error

    client._status_error = None  # engine returns
    window._apply_health(window._fetch_health())  # the next routine poll auto-recovers
    assert window._heart._state == "green"
    assert window._status.text() == "" and window._health_error == ""  # error auto-cleared
    window.close()


def test_status_page_recovers_after_engine_returns(qapp, monkeypatch) -> None:
    # Page layer: an unreachable poll renders "Reachable: no" + emits the error (a visible, recoverable
    # state — not a crash); once the engine returns the next fetch renders healthy again.
    monkeypatch.setattr(status_mod.service_control, "service_state", lambda _n: "running")
    client = FakeStatusClient(status_error=ApiError("down", status=503))
    page = EngineStatusPage(client)  # type: ignore[arg-type]
    errs: list[str] = []
    page.error.connect(errs.append)

    page._apply(page._fetch())
    assert page._engine["Reachable"].text() == "no" and errs == ["down"]

    client._status_error = None  # engine returns
    page._apply(page._fetch())
    assert page._engine["Reachable"].text() == "yes"  # recovered cleanly, no leftover error state
    page.stop()
