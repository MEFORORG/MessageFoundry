# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for multi-shard support: the QSettings-backed ShardRegistry and the AppWindow
shard selector / switch wiring. Runs Qt offscreen against stub clients (no display, no server)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import QSettings  # noqa: E402

from messagefoundry.console.shards import (  # noqa: E402
    ACTIVE_KEY,
    REGISTRY_KEY,
    Shard,
    ShardRegistry,
)

# Reuse the StubClient that the rest of the console suite uses for AppWindow tests.
from tests.test_console_widgets import StubClient  # noqa: E402


@pytest.fixture
def settings() -> QSettings:
    # NOT in-memory, despite what this comment used to claim. QSettings(IniFormat, UserScope, ...) writes
    # a REAL file — %APPDATA%\<org>\ShardTest.ini — and this fixture .clear()s it. With a fixed org, two
    # concurrent pytest runs wiped each other's settings mid-test. The org is therefore per-PROCESS
    # (tests/conftest.py claims a slot); it still never touches the developer's real Console settings.
    org = os.environ.get("MEFOR_TEST_QSETTINGS_ORG", "MEFOR-Test")
    s = QSettings(QSettings.Format.IniFormat, QSettings.Scope.UserScope, org, "ShardTest")
    s.clear()
    return s


# --- ShardRegistry ----------------------------------------------------------


def test_default_seeded_when_empty(settings: QSettings) -> None:
    reg = ShardRegistry(settings)
    assert reg.is_empty()
    shard = reg.ensure_default("http://127.0.0.1:8765")
    assert not reg.is_empty()
    assert shard.base_url == "http://127.0.0.1:8765"
    assert reg.active_id == shard.id
    assert reg.active() == shard
    assert [s.base_url for s in reg.list()] == ["http://127.0.0.1:8765"]


def test_ensure_default_idempotent_and_no_duplicate(settings: QSettings) -> None:
    reg = ShardRegistry(settings)
    first = reg.ensure_default("http://127.0.0.1:8765/")  # trailing slash normalised away
    again = reg.ensure_default("http://127.0.0.1:8765")
    assert first.id == again.id
    assert len(reg.list()) == 1  # not duplicated


def test_add_and_set_active(settings: QSettings) -> None:
    reg = ShardRegistry(settings)
    a = reg.add(name="Site A", base_url="http://10.0.0.1:8765")
    b = reg.add(name="Site B", base_url="http://10.0.0.2:8765")
    assert reg.active_id == a.id  # first added is active
    assert reg.set_active(b.id) is True
    assert reg.active_id == b.id
    assert reg.set_active("nope") is False  # unknown id is a no-op
    assert reg.active_id == b.id


def test_persistence_round_trip(settings: QSettings) -> None:
    reg = ShardRegistry(settings)
    a = reg.add(name="Site A", base_url="http://10.0.0.1:8765")
    b = reg.add(name="Site B", base_url="http://10.0.0.2:8765")
    reg.set_active(b.id)

    # A fresh registry over the SAME settings must reload identical state.
    reloaded = ShardRegistry(settings)
    assert [(s.id, s.name, s.base_url) for s in reloaded.list()] == [
        (a.id, "Site A", "http://10.0.0.1:8765"),
        (b.id, "Site B", "http://10.0.0.2:8765"),
    ]
    assert reloaded.active_id == b.id
    assert reloaded.active() == b


def test_remove_reassigns_active(settings: QSettings) -> None:
    reg = ShardRegistry(settings)
    a = reg.add(name="A", base_url="http://10.0.0.1:8765")
    b = reg.add(name="B", base_url="http://10.0.0.2:8765")
    reg.set_active(a.id)
    assert reg.remove(a.id) is True  # removing the active shard moves active to the survivor
    assert reg.active_id == b.id
    assert reg.remove(b.id) is True  # emptying clears active
    assert reg.active_id is None
    assert reg.is_empty()


def test_corrupt_registry_blob_is_ignored(settings: QSettings) -> None:
    settings.setValue(REGISTRY_KEY, "{not json")
    settings.setValue(ACTIVE_KEY, "ghost")
    reg = ShardRegistry(settings)  # must not raise
    assert reg.is_empty()
    assert reg.active_id is None
    # ...and a default re-seeds cleanly, exactly like a first run.
    shard = reg.ensure_default("http://127.0.0.1:8765")
    assert reg.active() == shard


def test_stale_active_falls_back_to_first(settings: QSettings) -> None:
    a = Shard(id="aaa", name="A", base_url="http://10.0.0.1:8765")
    b = Shard(id="bbb", name="B", base_url="http://10.0.0.2:8765")
    import json

    settings.setValue(REGISTRY_KEY, json.dumps([a.to_dict(), b.to_dict()]))
    settings.setValue(ACTIVE_KEY, "deleted-id")  # points at a shard that no longer exists
    reg = ShardRegistry(settings)
    assert reg.active_id == "aaa"  # falls back to the first registered shard


def test_malformed_entries_skipped(settings: QSettings) -> None:
    import json

    settings.setValue(
        REGISTRY_KEY,
        json.dumps(
            [
                {"id": "good", "name": "Good", "base_url": "http://10.0.0.1:8765"},
                {"id": "", "base_url": "http://10.0.0.2:8765"},  # missing id
                {"id": "nourl", "name": "NoUrl"},  # missing base_url
                "garbage",  # not even an object
            ]
        ),
    )
    reg = ShardRegistry(settings)
    assert [s.id for s in reg.list()] == ["good"]


# --- AppWindow shard wiring -------------------------------------------------


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _settle(qapp, *runners) -> None:  # type: ignore[no-untyped-def]
    for runner in runners:
        runner._pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()


def test_single_shard_hides_selector_and_default_path_unchanged(qapp, settings) -> None:  # type: ignore[no-untyped-def]
    # Backward compatible: with one configured shard the selector is hidden and the window behaves
    # exactly as the legacy single-client path (the default page still renders).
    from messagefoundry.console.shell import AppWindow

    reg = ShardRegistry(settings)
    reg.ensure_default("http://127.0.0.1:8765")
    window = AppWindow(StubClient(), registry=reg)  # no factory: single shard never needs one
    assert window._shard_combo.count() == 1
    assert window._shard_combo.isHidden()  # nothing to switch to
    _settle(qapp, window.connections._runner)
    assert window.connections._table.rowCount() == 2  # default page rendered as before
    window.close()


def test_no_registry_behaves_as_legacy(qapp) -> None:  # type: ignore[no-untyped-def]
    # No registry at all (the bare embedding-style construction every existing test uses): the
    # selector is hidden and set_active_shard is an inert no-op.
    from messagefoundry.console.shell import AppWindow

    window = AppWindow(StubClient())
    assert window._shard_combo.count() == 0
    assert window._shard_combo.isHidden()
    assert window.set_active_shard("anything") is False
    window.close()


def test_selector_lists_multiple_and_switch_repoints_client(qapp, settings) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console.shell import AppWindow

    reg = ShardRegistry(settings)
    a = reg.add(name="Site A", base_url="http://10.0.0.1:8765")
    b = reg.add(name="Site B", base_url="http://10.0.0.2:8765")
    reg.set_active(a.id)

    launch_client = StubClient()
    b_client = StubClient()
    built: list[str] = []

    def factory(shard_id: str) -> tuple[object, object]:
        built.append(shard_id)
        return b_client, b_client  # a fresh client pair for the selected shard

    window = AppWindow(launch_client, registry=reg, client_factory=factory)  # type: ignore[arg-type]
    assert window._shard_combo.count() == 2
    assert not window._shard_combo.isHidden()  # >1 shard -> selector shown
    # The active shard (A) is bound to the launch client (no factory call yet).
    assert window._client is launch_client
    assert built == []

    # Switch to B: the factory builds B's client and every page is re-pointed at it.
    assert window.set_active_shard(b.id) is True
    assert built == [b.id]
    assert window._client is b_client
    assert window.connections._client is b_client
    assert reg.active_id == b.id  # persisted
    assert window._shard_combo.currentData() == b.id  # selector reflects the switch
    _settle(qapp, window.connections._runner)

    # Switching back to A reuses the cached launch client (no second factory build for it).
    assert window.set_active_shard(a.id) is True
    assert window._client is launch_client
    assert built == [b.id]  # A was cached, never (re)built
    window.close()


def test_switch_emits_shard_changed(qapp, settings) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console.shell import AppWindow

    reg = ShardRegistry(settings)
    a = reg.add(name="A", base_url="http://10.0.0.1:8765")
    b = reg.add(name="B", base_url="http://10.0.0.2:8765")
    reg.set_active(a.id)
    window = AppWindow(
        StubClient(), registry=reg, client_factory=lambda _id: (StubClient(), StubClient())
    )  # type: ignore[arg-type]
    seen: list[str] = []
    window.shard_changed.connect(seen.append)
    window.set_active_shard(b.id)
    assert seen == [b.id]
    window.close()


def test_factory_failure_keeps_active_shard(qapp, settings) -> None:  # type: ignore[no-untyped-def]
    # A factory raising (e.g. the operator cancels sign-in for the new shard) must not switch, not
    # crash, and snap the selector back to the still-active shard.
    from messagefoundry.console.shell import AppWindow

    reg = ShardRegistry(settings)
    a = reg.add(name="A", base_url="http://10.0.0.1:8765")
    b = reg.add(name="B", base_url="http://10.0.0.2:8765")
    reg.set_active(a.id)

    def boom(_shard_id: str) -> tuple[object, object]:
        raise RuntimeError("sign-in cancelled")

    window = AppWindow(StubClient(), registry=reg, client_factory=boom)  # type: ignore[arg-type]
    assert window.set_active_shard(b.id) is False
    assert window._active_shard_id == a.id  # unchanged
    assert reg.active_id == a.id
    assert window._shard_combo.currentData() == a.id  # snapped back
    window.close()
