# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0041 D3 — startup self-attestation of the installed engine wheel (BACKLOG #54).

The engine hashes its loaded ``messagefoundry`` module files against the installed wheel's
``*.dist-info/RECORD`` baseline at startup. These tests cover the four D3 EARS criteria:

- AC-9  — attests loaded modules against RECORD on a (simulated) non-editable wheel install.
- AC-10 — drift ALERTS + records a ``startup_integrity`` audit row by default (engine still starts).
- AC-11 — drift FAILS-CLOSED (``IntegrityError``) when ``[integrity].fail_closed_on_drift``.
- AC-12 — an EDITABLE install is a NO-OP (no fail, no alert) so dev is never bricked.

The attestation logic is exercised against a fabricated install root (a fake ``mfengine`` package +
its ``*.dist-info/RECORD``) so the test never depends on how *this* repo happens to be installed.
``messagefoundry.integrity`` is parameterized only by the dist name + the loaded-files lookup, both
monkeypatched here.
"""

from __future__ import annotations

import base64
import hashlib
from importlib.metadata import PathDistribution
from pathlib import Path

import pytest

import messagefoundry.integrity as integ
from messagefoundry.integrity import (
    AttestationResult,
    IntegrityError,
    attest_engine,
    run_startup_attestation,
)
from messagefoundry.pipeline.alerts import AlertSink
from messagefoundry.store import open_store, sqlite_settings


def _record_hash(data: bytes) -> str:
    """RECORD ``sha256=<b64url-nopad>`` token for ``data`` (the format the engine compares against)."""
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _build_wheel_install(
    root: Path,
    *,
    pkg: str = "mfengine",
    files: dict[str, bytes],
    editable: bool = False,
    extra_record_rows: tuple[str, ...] = (),
) -> tuple[PathDistribution, list[Path]]:
    """Lay out a fake site-packages install: the package source + a ``*.dist-info/RECORD`` baseline.

    Returns the ``PathDistribution`` for the dist-info and the list of on-disk package ``.py`` paths
    (the "loaded module files"). When ``editable`` the RECORD lists only a ``.pth`` finder (no package
    source rows) and a ``direct_url.json`` with ``dir_info.editable=true`` — exactly what pip writes.
    """
    root.mkdir(parents=True, exist_ok=True)
    pkg_dir = root / pkg
    pkg_dir.mkdir(parents=True, exist_ok=True)
    loaded: list[Path] = []
    record_rows: list[str] = []
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        loaded.append(p.resolve())
        if not editable:
            record_rows.append(f"{rel},{_record_hash(data)},{len(data)}")

    dist_info = root / f"{pkg}-1.0.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)
    if editable:
        (root / f"__editable__.{pkg}.pth").write_text(str(root), encoding="utf-8")
        record_rows.append(f"__editable__.{pkg}.pth,,")
        (dist_info / "direct_url.json").write_text(
            '{"dir_info": {"editable": true}, "url": "file:///x"}', encoding="utf-8"
        )
    record_rows.extend(extra_record_rows)
    record_rows.append(f"{pkg}-1.0.dist-info/RECORD,,")
    (dist_info / "RECORD").write_text("\n".join(record_rows) + "\n", encoding="utf-8")
    (dist_info / "METADATA").write_text(f"Name: {pkg}\nVersion: 1.0\n", encoding="utf-8")
    return PathDistribution(dist_info), loaded


def _patch(
    monkeypatch: pytest.MonkeyPatch, dist: PathDistribution, loaded: list[Path], pkg: str
) -> None:
    """Point the integrity module at the fabricated install (dist name + loaded-files lookup)."""
    monkeypatch.setattr(integ, "_DIST_NAME", pkg)

    def _fake_distribution(name: str) -> PathDistribution:
        assert name == pkg
        return dist

    monkeypatch.setattr(integ.metadata, "distribution", _fake_distribution)
    monkeypatch.setattr(integ, "_loaded_module_files", lambda: sorted(loaded))


class _RecordingSink(AlertSink):
    """An AlertSink that records integrity_drift events (the dedicated tamper channel, #54)."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, int]] = []

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        self.events.append((name, reason, drift_count))

    def connection_stopped(self, name: str, *, detail: str) -> None: ...
    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None: ...
    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None: ...
    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None: ...
    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None: ...
    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None: ...
    def secret_rotation_due(
        self, name: str, *, secret: str, last_rotated: str, days_overdue: int
    ) -> None: ...


# --- AC-9: attests loaded modules against RECORD (clean wheel) ----------------


def test_attests_loaded_modules_against_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg = "mfengine"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"def go():\n    return 1\n",
        f"{pkg}/sub/mod.py": b"X = 2\n",
    }
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files)
    _patch(monkeypatch, dist, loaded, pkg)

    result = attest_engine()
    assert isinstance(result, AttestationResult)
    assert result.attested is True  # a real RECORD baseline was compared
    assert result.editable is False and result.no_record is False
    assert result.checked == 3  # every loaded .py compared to its RECORD row
    assert result.ok and result.drift == []  # untampered -> clean


# --- AC-10: drift ALERTS + records a startup_integrity row by default ---------


async def test_drift_alerts_and_records_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg = "mfengine"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"def go():\n    return 1\n",
    }
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files)
    _patch(monkeypatch, dist, loaded, pkg)

    # Tamper: rewrite a loaded module in place AFTER the RECORD baseline was sealed.
    (tmp_path / f"{pkg}/core.py").write_bytes(b"def go():\n    return 999  # backdoor\n")
    assert attest_engine().drift  # the tamper is detected

    store = await open_store(sqlite_settings(str(tmp_path / "attest.db")))
    sink = _RecordingSink()
    try:
        # Default posture (alert-only): records + alerts, but DOES NOT raise (engine starts).
        result = await run_startup_attestation(store, sink, fail_closed_on_drift=False)
        assert result.drift and not result.ok
        rows = [a for a in await store.list_audit() if a["action"] == "startup_integrity"]
        assert rows, "expected a startup_integrity audit row"
        import json

        detail = json.loads(rows[-1]["detail"])
        assert detail["drift_count"] >= 1 and detail["fail_closed"] is False
        assert f"{pkg}/core.py" in detail["drift"]
        # the dedicated integrity_drift AlertSink channel fired (#54), carrying the label + count
        assert sink.events and sink.events[0][0] == "engine-integrity"
        assert sink.events[0][2] == detail["drift_count"]  # drift_count is forwarded to the alert
    finally:
        await store.close()


# --- AC-11: drift FAILS-CLOSED when opted in ----------------------------------


async def test_drift_fails_closed_when_opted_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg = "mfengine"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"SAFE = True\n",
    }
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files)
    _patch(monkeypatch, dist, loaded, pkg)
    (tmp_path / f"{pkg}/core.py").write_bytes(b"SAFE = False  # neutered\n")

    store = await open_store(sqlite_settings(str(tmp_path / "fc.db")))
    sink = _RecordingSink()
    try:
        # Opt-in fail-closed: it STILL records + alerts, THEN raises so no listener binds.
        with pytest.raises(IntegrityError):
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        rows = [a for a in await store.list_audit() if a["action"] == "startup_integrity"]
        assert rows, "fail-closed must still record the audit row before refusing to start"
        assert sink.events, "fail-closed must still fire the alert before refusing to start"
    finally:
        await store.close()


# --- AC-12: an editable install is a NO-OP ------------------------------------


async def test_editable_install_is_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg = "mfengine"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"def go():\n    return 1\n",
    }
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files, editable=True)
    _patch(monkeypatch, dist, loaded, pkg)

    # Even though the on-disk file differs from any baseline, an editable install has no RECORD
    # source rows to attest against — so it is a no-op: editable=True, no drift, no fail, no alert.
    (tmp_path / f"{pkg}/core.py").write_bytes(b"def go():\n    return 2  # dev edit\n")
    result = attest_engine()
    assert result.editable is True and result.attested is False
    assert result.drift == [] and result.ok

    store = await open_store(sqlite_settings(str(tmp_path / "ed.db")))
    sink = _RecordingSink()
    try:
        # fail_closed_on_drift=True must STILL not brick a dev editable install.
        out = await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert out.editable is True and out.ok
        assert [a for a in await store.list_audit() if a["action"] == "startup_integrity"] == []
        assert sink.events == []  # no alert on a dev install
    finally:
        await store.close()


# --- extra coverage: a missing (in-place-added) module is drift; no-RECORD no-op --


def test_added_module_without_record_entry_is_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg = "mfengine"
    files = {f"{pkg}/__init__.py": b"VERSION = '1.0'\n"}
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files)
    # A planted module with NO RECORD row, loaded by the package — must be flagged "missing".
    planted = tmp_path / pkg / "backdoor.py"
    planted.write_bytes(b"import os  # exfil\n")
    loaded.append(planted.resolve())
    _patch(monkeypatch, dist, loaded, pkg)

    result = attest_engine()
    assert any(d.reason == "missing" and d.path.endswith("backdoor.py") for d in result.drift)
