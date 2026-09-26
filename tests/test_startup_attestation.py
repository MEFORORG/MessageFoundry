# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0041 D3 — startup self-attestation of the installed engine wheel (BACKLOG #54).

The engine hashes its loaded ``messagefoundry`` module files against the installed wheel's
``*.dist-info/RECORD`` baseline at startup. These tests cover the four D3 EARS criteria:

- AC-9  — attests loaded modules against RECORD on a (simulated) non-editable wheel install.
- AC-10 — drift ALERTS + records a ``startup_integrity`` audit row by default (engine still starts).
- AC-11 — drift FAILS-CLOSED (``IntegrityError``) when ``[integrity].fail_closed_on_drift``.
- AC-12 — an install that DECLARES itself editable is a NO-OP (no fail, no alert) so dev is never bricked.
- AC-13 — a pass that compared NOTHING (no baseline, a stripped baseline, a shadowed package) warns,
  records and alerts, and fails closed when opted in (BACKLOG #1679).

The same rules also cover the web console's own distribution when the process has loaded it (BACKLOG
#1802); that arm's tests are the last block in this file.

The attestation logic is exercised against a fabricated install root (a fake ``mfengine`` package +
its ``*.dist-info/RECORD``) so the test never depends on how *this* repo happens to be installed.
``messagefoundry.integrity`` is parameterized only by the dist name + the loaded-files lookup, both
monkeypatched here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
import types
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, PathDistribution
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
from messagefoundry.security import handler_semgrep_rules
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
    assets: dict[str, bytes] | None = None,
) -> tuple[PathDistribution, list[Path]]:
    """Lay out a fake site-packages install: the package source + a ``*.dist-info/RECORD`` baseline.

    Returns the ``PathDistribution`` for the dist-info and the list of on-disk package ``.py`` paths
    (the "loaded module files"). When ``editable`` the RECORD lists only a ``.pth`` finder (no package
    source rows) and a ``direct_url.json`` with ``dir_info.editable=true`` — exactly what pip writes.

    ``assets`` are shipped **data** files (BACKLOG #1432): written and RECORDed exactly like source,
    but deliberately kept OUT of the returned ``loaded`` list, because the engine reaches them through
    the separate :func:`~messagefoundry.integrity._attested_asset_files` seam. A test that wants them
    attested passes them to ``_patch(..., assets=...)``; that split is what lets a test isolate the
    asset half from the module half.
    """
    root.mkdir(parents=True, exist_ok=True)
    pkg_dir = root / pkg
    pkg_dir.mkdir(parents=True, exist_ok=True)
    record_rows: list[str] = []
    for rel, data in {**files, **(assets or {})}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if not editable:
            record_rows.append(f"{rel},{_record_hash(data)},{len(data)}")
    loaded = [(root / rel).resolve() for rel in files]

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
    monkeypatch: pytest.MonkeyPatch,
    dist: PathDistribution,
    loaded: list[Path],
    pkg: str,
    *,
    assets: Sequence[Path] = (),
) -> None:
    """Point the integrity module at the fabricated install (dist name + the two file lookups).

    ``assets`` defaults to **none declared**, so a test that says nothing about assets attests only
    modules — the pre-#1432 behaviour — and cannot be accidentally passed or failed by the real
    engine's own shipped assets leaking into a fabricated install root.
    """
    monkeypatch.setattr(integ, "_DIST_NAME", pkg)

    def _fake_distribution(name: str) -> PathDistribution:
        assert name == pkg
        return dist

    monkeypatch.setattr(integ.metadata, "distribution", _fake_distribution)
    monkeypatch.setattr(integ, "_loaded_module_files", lambda: sorted(loaded))
    monkeypatch.setattr(integ, "_attested_asset_files", lambda: list(assets))
    # The web console arm (BACKLOG #1802) reads `sys.modules`, and whether the real console is imported
    # depends on which tests ran first in this process. Every engine-arm test says "not loaded", so it
    # attests exactly the fabricated engine and nothing else. The console block below opts back in.
    monkeypatch.setattr(integ, "_console_loaded_files", lambda: None)


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


async def _assert_startup_attestation_tamper_evidence(
    store: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RBAC-16 shared per-backend contract: on a real backend (SQL Server / Postgres), engine
    tampering must drive :func:`run_startup_attestation` to durably capture the tamper into
    tamper-evidence — a hash-chained, off-box-teed ``startup_integrity`` audit row (``actor=None``) —
    and then **fail closed**, never silently pass. Reused by the gated SQL Server + Postgres suites so
    the live-server CI legs actually catch a backend regression in the NULL-actor row hashing / tee.

    Proven by the NEGATIVE, not by construction: the guard is made to REFUSE (``IntegrityError``) and
    the tamper is asserted present + chain-verified + teed, so a store that swallowed the drift row or
    mis-hashed the NULL-actor row would fail this test.
    """
    import json
    import logging

    pkg = "mfengine"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"SAFE = True\n",
    }
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files)
    _patch(monkeypatch, dist, loaded, pkg)
    # Tamper a loaded module in place AFTER the RECORD baseline was sealed (a simulated host compromise).
    (tmp_path / f"{pkg}/core.py").write_bytes(b"SAFE = False  # neutered\n")
    assert attest_engine().drift  # the tamper is detected

    sink = _RecordingSink()

    # (1) Default alert-only posture: it records the tamper row + alerts, engine still starts (no raise).
    result = await run_startup_attestation(store, sink, fail_closed_on_drift=False)  # type: ignore[arg-type]
    assert result.drift and not result.ok
    landed = [a for a in await store.list_audit() if a["action"] == "startup_integrity"]  # type: ignore[attr-defined]
    assert landed, (
        "alert-only posture must STILL record the startup_integrity tamper row on this backend"
    )

    # (2) Opt-in fail-closed posture: capture the off-box tee, and assert the guard REFUSES to start.
    captured: list[str] = []

    class _Cap(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record.getMessage())

    handler = _Cap()
    audit_log = logging.getLogger("messagefoundry.audit")
    audit_log.addHandler(handler)
    try:
        with pytest.raises(IntegrityError):
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)  # type: ignore[arg-type]
    finally:
        audit_log.removeHandler(handler)

    # NEGATIVE assertions — the tamper is durably captured into tamper-evidence, not silently passed:
    rows = [a for a in await store.list_audit() if a["action"] == "startup_integrity"]  # type: ignore[attr-defined]
    assert rows, "fail-closed must STILL record the startup_integrity row BEFORE refusing to start"
    row = rows[0]  # newest first
    # A machine attestation, not a user action: the NULL-actor row must persist + hash correctly here.
    assert row["actor"] is None
    detail = json.loads(row["detail"])
    assert detail["drift_count"] >= 1 and detail["fail_closed"] is True
    assert f"{pkg}/core.py" in detail["drift"]

    # The NULL-actor startup_integrity row is correctly hash-chained on THIS backend (incl. None-actor
    # row hashing) — a tamper of the row itself would break verification.
    ok, msg = await store.verify_audit_chain()  # type: ignore[attr-defined]
    assert ok is True, f"startup_integrity row must chain-verify on this backend: {msg}"

    # An off-box tee line for action=startup_integrity was emitted (redacted, metadata-only) so the
    # tamper evidence survives a host/DB compromise — same shared emit_audit_tee path as every backend.
    teed = [json.loads(line) for line in captured]
    integ_teed = [r for r in teed if r.get("action") == "startup_integrity"]
    assert integ_teed, (
        "the startup_integrity tamper row must tee off-box for host-compromise survival"
    )
    assert integ_teed[0]["event"] == "audit" and integ_teed[0]["actor"] is None  # PHI-free metadata

    # The dedicated integrity_drift AlertSink channel fired (the tamper page), carrying the count.
    assert sink.events and sink.events[-1][0] == "engine-integrity"
    assert sink.events[-1][2] == detail["drift_count"]


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

    store = await open_store(sqlite_settings(str(tmp_path / "attest.db")), create=True)
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

    store = await open_store(sqlite_settings(str(tmp_path / "fc.db")), create=True)
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
    """AC-12, and the PAIRED ARM for the #1679 refusals below.

    This install DECLARES itself editable (a PEP 610 ``direct_url.json`` plus an ``__editable__`` finder
    row in RECORD) and compares nothing, exactly like the four shapes in the #1679 block. It must still
    start silently. So what causes those refusals is the MISSING declaration, not ``checked == 0``,
    which no single-arm test could establish.
    """
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
    assert result.drift == []
    # It compared nothing, so it is NOT `ok` (#1679) — `ok` now means VERIFIED clean. What keeps it
    # from being refused is the declaration.
    assert result.attested_nothing is True and result.ok is False
    assert result.declared_editable is True
    assert result.unattested_reason == "declared_editable"

    store = await open_store(sqlite_settings(str(tmp_path / "ed.db")), create=True)
    sink = _RecordingSink()
    try:
        # fail_closed_on_drift=True must STILL not brick a dev editable install.
        out = await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert out.editable is True and out.declared_editable is True
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


# --- BACKLOG #1432: shipped security DATA assets are attested too --------------
#
# Attesting only ``.py`` left a control that a non-``.py`` file decides. Truncating the bundled
# common-password corpus to zero bytes makes ``_common_passwords()`` an empty set, so
# ``PasswordPolicy.violations`` stops emitting "not be a common or breached password" — breach
# screening becomes a silent no-op with no engine module touched, and attestation said clean.

#: The corpus relpath inside the fake install; the same *shape* as the real shipped asset.
_ASSET = "mfengine/auth/data/common_passwords.txt"
_CORPUS = b"password\nqwerty\nhunter2\n"


def _install_with_asset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, declare_asset: bool
) -> Path:
    """Fake wheel install carrying one data asset. ``declare_asset`` is the single variable under
    test: it decides whether the asset is in the attested set, and nothing else differs."""
    pkg = "mfengine"
    dist, loaded = _build_wheel_install(
        tmp_path,
        pkg=pkg,
        files={f"{pkg}/__init__.py": b"VERSION = '1.0'\n"},
        assets={_ASSET: _CORPUS},
    )
    asset = (tmp_path / _ASSET).resolve()
    _patch(monkeypatch, dist, loaded, pkg, assets=(asset,) if declare_asset else ())
    return asset


def test_declared_asset_is_attested_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An untampered declared asset is compared against RECORD and counted — not skipped."""
    _install_with_asset(tmp_path, monkeypatch, declare_asset=True)

    result = attest_engine()
    assert result.attested is True and result.ok and result.drift == []
    # 2 = the one module + the one asset. A skipped asset would leave this at 1, so the count is
    # what proves the asset was actually hashed rather than merely not drifting.
    assert result.checked == 2


def test_truncated_security_asset_is_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """POSITIVE CONTROL — the #1432 attack itself: the corpus is truncated to zero bytes in place
    after the RECORD baseline was sealed, and attestation MUST report it."""
    asset = _install_with_asset(tmp_path, monkeypatch, declare_asset=True)
    asset.write_bytes(b"")  # neutered: an empty corpus screens nothing

    result = attest_engine()
    assert not result.ok
    assert [(d.path, d.reason) for d in result.drift] == [(_ASSET, "hash_mismatch")]


def test_truncated_asset_is_INVISIBLE_when_not_declared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The paired arm. Identical install, identical truncation, one variable changed: the asset is not
    in the attested set. Attestation reports CLEAN.

    Two things it establishes, and one it does not.

    It shows **declaring** the asset is what causes the detection above: the fixture writes the file
    and gives it a RECORD row in both arms, so nothing else can account for the difference. It also
    pins that ``attest_engine`` attests what the two lookups hand it and never walks the install root
    on its own — the asset has a RECORD row here and is still not compared, which is what stops the
    tripwire quietly growing into "everything pip installed".

    It is NOT a control on the composition in ``attest_engine``, and it cannot be one: both lookups
    are monkeypatched, so no production enumeration runs. It passes with the widening reverted. That
    control is run by hand — reverting the composed loop fails the four tests around this one.
    """
    asset = _install_with_asset(tmp_path, monkeypatch, declare_asset=False)
    asset.write_bytes(b"")

    result = attest_engine()
    assert result.ok and result.drift == []
    assert result.checked == 1  # the module only


def test_deleted_security_asset_is_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Deleting a declared asset is tampering too. It must not read as clean just because the file
    the walk would have hashed is no longer there."""
    asset = _install_with_asset(tmp_path, monkeypatch, declare_asset=True)
    asset.unlink()

    result = attest_engine()
    assert not result.ok
    assert [(d.path, d.reason) for d in result.drift] == [(_ASSET, "missing")]


async def test_asset_drift_alerts_and_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Asset drift runs the same audit + alert + fail-closed path as module drift — the tripwire is
    widened, not forked."""
    import json

    asset = _install_with_asset(tmp_path, monkeypatch, declare_asset=True)
    asset.write_bytes(b"")

    store = await open_store(sqlite_settings(str(tmp_path / "asset.db")), create=True)
    sink = _RecordingSink()
    try:
        with pytest.raises(IntegrityError):
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        rows = [a for a in await store.list_audit() if a["action"] == "startup_integrity"]
        assert rows, "asset drift must record the startup_integrity row before refusing to start"
        detail = json.loads(rows[0]["detail"])
        assert detail["drift"] == [_ASSET] and detail["drift_reasons"] == ["hash_mismatch"]
        assert sink.events and sink.events[-1][0] == "engine-integrity"
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("label", "corpus"),
    [("lf", b"password\nqwerty\nhunter2\n"), ("crlf", b"password\r\nqwerty\r\nhunter2\r\n")],
)
def test_line_endings_alone_never_report_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str, corpus: bytes
) -> None:
    """A line-ending difference in a declared asset must NOT read as tampering.

    ``messagefoundry/auth/data/common_passwords.txt`` has no ``.gitattributes`` byte policy, so under
    ``core.autocrlf=true`` a Windows checkout holds CRLF where the committed blob holds LF. Four
    sessions independently read that as a false-alarm hazard for this tripwire. **It is not**, and the
    reason is worth pinning rather than re-deriving: ``RECORD`` is written by the *installer* from the
    bytes it unpacked, so the baseline and the installed file are the same bytes on the same host
    whatever git did upstream. A CRLF wheel carries CRLF content AND a CRLF-derived digest.

    Both arms attest clean, which is the property. The missing ``-text`` pin is a real
    reproducible-builds defect -- two platforms build byte-different wheels from one commit -- but it
    is a separate one, and this tripwire cannot be the thing that reports it.
    """
    pkg = "mfengine"
    asset = f"{pkg}/auth/data/common_passwords.txt"
    dist, loaded = _build_wheel_install(
        tmp_path,
        pkg=pkg,
        files={f"{pkg}/__init__.py": b"VERSION = '1.0'\n"},
        assets={asset: corpus},
    )
    _patch(monkeypatch, dist, loaded, pkg, assets=((tmp_path / asset).resolve(),))

    result = attest_engine()
    assert result.ok and result.drift == [], f"{label} install must attest clean"
    assert result.checked == 2


def test_a_swap_of_line_endings_AFTER_install_is_still_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control on the test above, and the arm that keeps it from being vacuous.

    The pair only means something if the digest is genuinely byte-exact. Here the RECORD baseline is
    sealed over LF and the on-disk file is then rewritten as CRLF -- a state ``pip`` cannot produce,
    since it writes RECORD from what it unpacked, but one an in-place editor can. That MUST drift.

    So both readings are pinned at once: identical-by-construction line endings are clean, and a
    post-install rewrite is caught even when it changes nothing a human would call content.
    """
    pkg = "mfengine"
    asset = f"{pkg}/auth/data/common_passwords.txt"
    dist, loaded = _build_wheel_install(
        tmp_path,
        pkg=pkg,
        files={f"{pkg}/__init__.py": b"VERSION = '1.0'\n"},
        assets={asset: b"password\nqwerty\nhunter2\n"},
    )
    path = (tmp_path / asset).resolve()
    _patch(monkeypatch, dist, loaded, pkg, assets=(path,))
    path.write_bytes(b"password\r\nqwerty\r\nhunter2\r\n")

    result = attest_engine()
    assert [(d.path, d.reason) for d in result.drift] == [(asset, "hash_mismatch")]


def test_a_corpus_that_SHIPPED_empty_is_not_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE BOUNDARY OF THIS CONTROL, asserted rather than left to be discovered.

    This tripwire compares an installed file to the wheel it came from, so it catches tampering
    **after** install and nothing else. A wheel BUILT with an already-truncated corpus ships an empty
    file and a RECORD row describing an empty file. They match. Attestation is silent, and is right to
    be: nothing drifted.

    So a poisoned *build* is invisible here by construction, and no amount of widening
    :data:`_ATTESTED_ASSETS` reaches it. That case belongs to the consumer, which grades the parsed
    result rather than the bytes -- an empty corpus screens nothing however faithfully it was shipped.
    The two controls are complements: this one sees a post-install edit that leaves a plausible corpus
    behind, the consumer sees an implausible corpus however it arrived, and neither subsumes the other.

    Asserting ``clean`` here also pins the layering. A future editor who adds "the corpus must be
    non-empty" to this module fails this test, which is the intended answer: that check belongs where
    the corpus is read, not where wheels are attested.
    """
    pkg = "mfengine"
    asset = f"{pkg}/auth/data/common_passwords.txt"
    dist, loaded = _build_wheel_install(
        tmp_path,
        pkg=pkg,
        files={f"{pkg}/__init__.py": b"VERSION = '1.0'\n"},
        assets={asset: b""},  # the wheel itself carries a neutered corpus
    )
    _patch(monkeypatch, dist, loaded, pkg, assets=((tmp_path / asset).resolve(),))

    result = attest_engine()
    assert result.ok and result.drift == []
    assert result.checked == 2, (
        "the empty asset is still HASHED, it simply matches its own baseline"
    )


def test_declared_assets_exist_in_the_shipped_package() -> None:
    """THE ROT GUARD, and the one test here that runs against the REAL package.

    Every entry in ``_ATTESTED_ASSETS`` is resolved the way the engine resolves it. A renamed or moved
    asset would otherwise leave a declaration that resolves to nothing: attestation would keep
    reporting clean, forever, over a file it is no longer looking at. That failure is invisible by
    construction, so it needs a test that must fail when it happens.
    """
    declared = integ._ATTESTED_ASSETS
    assert declared, "the attested-asset set must not be empty"
    # Both assets #1432 names are still declared. Extending the tuple is expected; dropping one is
    # the regression. The Semgrep entry is checked against its OWNING accessor rather than a second
    # hand-typed literal, so moving the rules file breaks this here instead of silently in a year.
    assert "auth/data/common_passwords.txt" in declared
    rules = handler_semgrep_rules()
    assert f"security/semgrep/{rules.name}" in declared

    # `strict=True` is what asserts the two sequences are the same length; no separate len() check.
    for rel, path in zip(declared, integ._attested_asset_files(), strict=True):
        assert path.as_posix().endswith(rel), f"{rel} resolved to {path}"
        assert path.is_file(), f"declared attested asset does not exist: {rel} ({path})"
        # A zero-byte asset in the shipped tree is the very state this tripwire exists to catch.
        assert path.stat().st_size > 0, f"declared attested asset is empty: {rel}"


# --- BACKLOG #1679: fail-closed must refuse when attestation verified NOTHING ---
#
# `fail_closed_on_drift` used to branch on `result.drift` alone, and three shapes reach the caller with
# `drift == []` having compared ZERO files: an absent or empty RECORD, a RECORD stripped of its package
# rows on an install that declares no editable marker, and a package imported from outside the install
# root (the #1677 shadow, which needs no venv write at all). A site that opted into hard enforcement
# would start cleanly on first deployment with its tripwire disarmed, and the INFO line said clean.
#
# The adversary this module names holds venv-write + restart rights, so it can strip the baseline as
# easily as it can edit a module. Verifying nothing is therefore the expected end state of a competent
# in-place edit, not an exotic packaging accident.

#: One arm per shape the row measured. `record_deleted`/`record_empty` are the two ways a baseline goes
#: absent; the other two are the stripped and shadowed shapes.
_ATTESTS_NOTHING_SHAPES = ("record_deleted", "record_empty", "record_rowless", "shadowed_package")


def _build_install_that_attests_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """Fabricate a NON-editable install whose attestation compares nothing.

    Every arm starts from the same clean wheel fixture as ``test_attests_loaded_modules_against_record``
    and keeps the package source on disk; none writes a ``direct_url.json`` or an ``__editable__``/
    ``.pth`` RECORD row, so no arm declares itself editable. What differs is only the baseline's reach,
    which is what makes ``test_editable_install_is_noop`` a usable paired arm.

    The install root is a ``site-packages`` subdirectory rather than ``tmp_path`` itself, because the
    shadow arm needs a package tree OUTSIDE that root — see its comment.
    """
    pkg = "mfengine"
    root = tmp_path / "site-packages"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"SAFE = True\n",
    }
    dist, loaded = _build_wheel_install(root, pkg=pkg, files=files)
    record = root / f"{pkg}-1.0.dist-info" / "RECORD"
    if shape == "record_deleted":
        record.unlink()
    elif shape == "record_empty":
        record.write_text("", encoding="utf-8")
    elif shape == "record_rowless":
        # RECORD stripped of its package source rows. The one row left carries no hash, so the parsed
        # baseline is empty — which is also what a real editable install looks like to the "no package
        # rows" signal. That collision is the defect: the signal cannot tell the two apart, so it must
        # not be read as a declaration.
        record.write_text(f"{pkg}-1.0.dist-info/RECORD,,\n", encoding="utf-8")
    elif shape == "shadowed_package":
        # #1677 seen from this control's side: the package is imported from a directory resolved BEFORE
        # site-packages, so no loaded file is under the install root and every one is skipped as
        # unattestable. RECORD is untouched and correct; it is simply about a different tree.
        #
        # OUTSIDE the install root is the whole shape, and it is worth stating because the first cut of
        # this fixture got it wrong: a shadow tree planted INSIDE the root is relpath-able against
        # RECORD, finds no row, and is reported as `missing` drift — which the control already handles.
        # Only a tree the install root cannot reach produces the silent `checked == 0`.
        shadow = tmp_path / "shadow"
        for rel, data in files.items():
            path = shadow / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        loaded = [(shadow / rel).resolve() for rel in files]
    else:  # pragma: no cover — a typo in the parametrize list
        raise AssertionError(f"unknown shape: {shape}")
    _patch(monkeypatch, dist, loaded, pkg)


@pytest.mark.parametrize("shape", _ATTESTS_NOTHING_SHAPES)
def test_an_install_that_compared_nothing_is_not_reported_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """A pass that compared zero files must not report ``ok``. It proves nothing either way."""
    _build_install_that_attests_nothing(tmp_path, monkeypatch, shape)

    result = attest_engine()
    assert result.drift == []  # the hole: no drift, and nothing was looked at
    assert result.checked == 0
    assert result.ok is False, "a pass that compared NOTHING must not report ok"
    assert result.attested_nothing is True
    assert result.declared_editable is False, "no arm here declares an editable install"
    assert result.unattested_reason is not None, (
        "the shape that disarmed the tripwire must be named"
    )


@pytest.mark.parametrize("shape", _ATTESTS_NOTHING_SHAPES)
async def test_attested_nothing_fails_closed_when_opted_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """Under ``fail_closed_on_drift`` the engine must refuse to start when it verified nothing, and it
    must record + alert BEFORE refusing (the same order the drift path uses)."""
    import json

    _build_install_that_attests_nothing(tmp_path, monkeypatch, shape)

    store = await open_store(sqlite_settings(str(tmp_path / f"{shape}.db")), create=True)
    sink = _RecordingSink()
    try:
        with pytest.raises(IntegrityError):
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        rows = [a for a in await store.list_audit() if a["action"] == "startup_integrity"]
        assert rows, "the attested-nothing posture must be recorded BEFORE refusing to start"
        detail = json.loads(rows[0]["detail"])
        assert detail["checked"] == 0 and detail["drift_count"] == 0
        assert detail["fail_closed"] is True
        assert detail["unattested_reason"], (
            "the audit row must name which shape disarmed the tripwire"
        )
        assert sink.events, "the posture must page off-box, not only log"
        # A distinct subject from the drift label so the two resolve as separate alert instances.
        assert sink.events[-1][0] == "engine-unattested"
        assert sink.events[-1][2] == 0  # nothing drifted; nothing was compared either
    finally:
        await store.close()


async def test_attested_nothing_warns_records_and_alerts_under_alert_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The default posture: the engine still starts, and the signal is still WARNING + audited +
    alerted. The refusal is in ADDITION to those, never instead of them — an operator who has not
    opted into hard enforcement must still be able to see that attestation proved nothing.

    WARNING, not the DEBUG line this used to emit: a DEBUG line in a service running at INFO is not a
    signal, it is silence.
    """
    import json
    import logging

    _build_install_that_attests_nothing(tmp_path, monkeypatch, "record_deleted")

    store = await open_store(sqlite_settings(str(tmp_path / "alert_only.db")), create=True)
    sink = _RecordingSink()
    try:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.integrity"):
            result = await run_startup_attestation(store, sink, fail_closed_on_drift=False)
        assert result.attested_nothing is True and result.ok is False
        assert any("verified NOTHING" in message for message in caplog.messages), caplog.messages
        rows = [a for a in await store.list_audit() if a["action"] == "startup_integrity"]
        assert rows, "alert-only must STILL record the attested-nothing row"
        assert json.loads(rows[0]["detail"])["fail_closed"] is False
        assert sink.events, "alert-only must STILL fire the alert"
    finally:
        await store.close()


async def test_a_verified_clean_install_still_starts_silently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE NEGATIVE CONTROL on the four arms above, and on the widened refusal.

    An ordinary non-editable wheel install with an intact baseline compares its files, reports ``ok``,
    records nothing and alerts nothing — under ``fail_closed_on_drift=true``. Without this arm the
    #1679 change could be satisfied by refusing every install, which would brick the shape the control
    exists to serve.
    """
    pkg = "mfengine"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"SAFE = True\n",
    }
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files)
    _patch(monkeypatch, dist, loaded, pkg)

    store = await open_store(sqlite_settings(str(tmp_path / "clean.db")), create=True)
    sink = _RecordingSink()
    try:
        result = await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert result.ok is True and result.checked == 2 and result.attested_nothing is False
        assert result.unattested_reason is None
        assert [a for a in await store.list_audit() if a["action"] == "startup_integrity"] == []
        assert sink.events == []
    finally:
        await store.close()


# --- BACKLOG #1679 act 5: an editable install under an opted-in fail-closed posture ---


def _editable_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A fabricated install that DECLARES itself editable — the AC-12 no-op shape."""
    pkg = "mfengine"
    files = {
        f"{pkg}/__init__.py": b"VERSION = '1.0'\n",
        f"{pkg}/core.py": b"def go():\n    return 1\n",
    }
    dist, loaded = _build_wheel_install(tmp_path, pkg=pkg, files=files, editable=True)
    _patch(monkeypatch, dist, loaded, pkg)


async def test_declared_editable_under_fail_closed_warns_and_names_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An operator who set ``[integrity].fail_closed_on_drift`` on an editable install WOULD start
    with the tripwire disarmed, and before this change with zero signal (BACKLOG #1679 act 5).

    AC-12 keeps the exemption — a declared-editable install is still never refused, never audited and
    never alerted, so a dev checkout is not bricked. What was missing is the operator's side of it:
    the posture readout said nothing at all, so the opt-in looked honoured.

    This is a MISCONFIGURATION control and nothing more. It closes no hole: an adversary with
    venv-write plants a ``direct_url.json`` or rewrites this module in the same single write.
    """
    import logging

    _editable_install(tmp_path, monkeypatch)

    store = await open_store(sqlite_settings(str(tmp_path / "ed_fc.db")), create=True)
    sink = _RecordingSink()
    try:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.integrity"):
            out = await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert out.declared_editable is True and out.attested_nothing is True
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert warnings, "a fail-closed opt-in on an editable install must not start silently"
        assert any("DISARMED" in m for m in warnings), warnings
        # The reason token is what carries the cause into the boot-log posture readout.
        assert any("declared_editable" in m for m in warnings), warnings
        # AC-12 is untouched: still no refusal, no audit row, no alert.
        assert [a for a in await store.list_audit() if a["action"] == "startup_integrity"] == []
        assert sink.events == []
    finally:
        await store.close()


async def test_declared_editable_under_the_default_posture_stays_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """THE PAIRED ARM. The warning above is keyed on the fail-closed OPT-IN, not on editability.

    Off the default alert-only posture an editable install is an ordinary dev checkout and there is no
    misconfiguration to report, so it must stay silent. Without this arm the change could be satisfied
    by warning on every dev run, which is how a warning stops being read.
    """
    import logging

    _editable_install(tmp_path, monkeypatch)

    store = await open_store(sqlite_settings(str(tmp_path / "ed_default.db")), create=True)
    sink = _RecordingSink()
    try:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.integrity"):
            out = await run_startup_attestation(store, sink, fail_closed_on_drift=False)
        assert out.declared_editable is True
        assert [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING] == []
        assert [a for a in await store.list_audit() if a["action"] == "startup_integrity"] == []
        assert sink.events == []
    finally:
        await store.close()


# --- BACKLOG #1802: the web console arm -----------------------------------------------------------
#
# The console is its own distribution, so the engine's RECORD never listed its files. These tests
# fabricate a clean engine install beside a console install and point both arms at them. The console
# uses its REAL import name, because the arm keys on it.

_REAL_CONSOLE_LOADED_FILES = integ._console_loaded_files
_CONSOLE_PKG = integ._CONSOLE_PACKAGE
_CONSOLE_FILES = {
    f"{_CONSOLE_PKG}/__init__.py": b"__version__ = '1.0'\n",
    f"{_CONSOLE_PKG}/mount.py": b"def mount_ui(app, deps):\n    return None\n",
    f"{_CONSOLE_PKG}/static/app.js": b"'use strict';\n",
    f"{_CONSOLE_PKG}/static/app.css": b"body { margin: 0; }\n",
}


def _install_engine_and_console(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    console_installed: bool = True,
    console_editable: bool = False,
    console_loaded: bool = True,
) -> Path:
    """A clean fabricated engine plus a fabricated console, both wired in. Returns the console root.

    ``console_installed=False`` leaves the console importable but with no distribution metadata, the
    shape of a source tree on ``sys.path``. ``console_loaded=False`` is the JSON-only engine.
    """
    engine_pkg = "mfengine"
    engine_dist, engine_loaded = _build_wheel_install(
        tmp_path / "engine",
        pkg=engine_pkg,
        files={
            f"{engine_pkg}/__init__.py": b"VERSION = '1.0'\n",
            f"{engine_pkg}/core.py": b"SAFE = True\n",
        },
    )
    _patch(monkeypatch, engine_dist, engine_loaded, engine_pkg)

    console_root = tmp_path / "console"
    console_dist, console_files = _build_wheel_install(
        console_root, pkg=_CONSOLE_PKG, files=_CONSOLE_FILES, editable=console_editable
    )

    def _distribution(name: str) -> PathDistribution:
        if name == engine_pkg:
            return engine_dist
        assert name == "messagefoundry-webconsole", name
        if not console_installed:
            raise PackageNotFoundError(name)
        return console_dist

    monkeypatch.setattr(integ.metadata, "distribution", _distribution)
    if console_loaded:
        monkeypatch.setattr(integ, "_console_loaded_files", lambda: sorted(console_files))
    return console_root


def _startup_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [r for r in rows if r["action"] == "startup_integrity"]


def test_console_not_loaded_is_not_attested(monkeypatch: pytest.MonkeyPatch) -> None:
    """The REAL lookup, not a stub: with the console absent from ``sys.modules`` there is nothing
    loaded to attest, and the arm must say so rather than import the console to look."""
    monkeypatch.delitem(sys.modules, _CONSOLE_PKG, raising=False)
    monkeypatch.setattr(integ, "_console_loaded_files", _REAL_CONSOLE_LOADED_FILES)
    assert integ._console_loaded_files() is None
    assert integ.attest_console() is None
    assert _CONSOLE_PKG not in sys.modules, "the arm must never import the console to attest it"


async def test_console_absent_changes_nothing_even_under_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Not installed, or installed and never imported: the console arm stays out of the way. No
    refusal, no audit row, no alert and no warning, with the opt-in set."""
    _install_engine_and_console(tmp_path, monkeypatch, console_loaded=False)

    store = await open_store(sqlite_settings(str(tmp_path / "absent.db")), create=True)
    sink = _RecordingSink()
    try:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.integrity"):
            result = await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert result.ok is True and result.checked == 2
        assert [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING] == []
        assert _startup_rows(await store.list_audit()) == []
        assert sink.events == []
    finally:
        await store.close()


async def test_console_loaded_and_clean_is_attested_silently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative control for the refusals below: a clean console install compares every file,
    source AND static, and starts silently under fail-closed."""
    _install_engine_and_console(tmp_path, monkeypatch)

    console = integ.attest_console()
    assert console is not None
    assert console.ok is True and console.attested is True
    assert console.checked == len(_CONSOLE_FILES)

    store = await open_store(sqlite_settings(str(tmp_path / "clean.db")), create=True)
    sink = _RecordingSink()
    try:
        await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert _startup_rows(await store.list_audit()) == []
        assert sink.events == []
    finally:
        await store.close()


@pytest.mark.parametrize("tampered", [f"{_CONSOLE_PKG}/mount.py", f"{_CONSOLE_PKG}/static/app.js"])
async def test_console_tamper_is_detected_recorded_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tampered: str
) -> None:
    """The limb BACKLOG #1802 filed: a console file edited in place after install. Source and the
    browser code it serves are both covered. Alert-only records and alerts; fail-closed also refuses."""
    console_root = _install_engine_and_console(tmp_path, monkeypatch)
    (console_root / tampered).write_bytes(b"// neutered\n")

    console = integ.attest_console()
    assert console is not None
    assert [(d.path, d.reason) for d in console.drift] == [(tampered, "hash_mismatch")]

    store = await open_store(sqlite_settings(str(tmp_path / "tamper.db")), create=True)
    sink = _RecordingSink()
    try:
        result = await run_startup_attestation(store, sink, fail_closed_on_drift=False)
        assert result.ok is True, "the engine's own result is returned, and the engine is clean"
        rows = _startup_rows(await store.list_audit())
        assert len(rows) == 1
        detail = json.loads(str(rows[0]["detail"]))
        assert detail["distribution"] == "messagefoundry-webconsole"
        assert detail["drift"] == [tampered] and detail["fail_closed"] is False
        assert sink.events == [
            (
                "webconsole-integrity",
                "1 web console file(s) drifted from the installed messagefoundry-webconsole "
                "wheel RECORD",
                1,
            )
        ]

        with pytest.raises(IntegrityError, match=r"^web console integrity attestation failed: 1 "):
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert len(_startup_rows(await store.list_audit())) == 2, "recorded BEFORE refusing"
    finally:
        await store.close()


def _load_fake_console(monkeypatch: pytest.MonkeyPatch, package_dir: Path) -> None:
    """Put a stand-in for the console into ``sys.modules`` and restore the REAL file lookup, so the
    walk over ``__path__`` is what runs."""
    fake = types.ModuleType(_CONSOLE_PKG)
    fake.__path__ = [str(package_dir)]
    monkeypatch.setitem(sys.modules, _CONSOLE_PKG, fake)
    monkeypatch.setattr(integ, "_console_loaded_files", _REAL_CONSOLE_LOADED_FILES)


def test_every_file_planted_in_the_loaded_console_is_missing_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The REAL walk: any file dropped into the package has no RECORD row, so it is drift, whatever its
    suffix. A native module is the sharp case, because the import system loads it INSTEAD of the
    untouched ``.py`` beside it. The bytecode cache directory is the one place skipped."""
    console_root = _install_engine_and_console(tmp_path, monkeypatch)
    package_dir = console_root / _CONSOLE_PKG
    (package_dir / "static" / "extra.js").write_bytes(b"fetch('/steal');\n")
    (package_dir / "mount.cp314-win_amd64.pyd").write_bytes(b"MZ not really\n")
    (package_dir / "static" / "evil.JS").write_bytes(b"fetch('/steal');\n")
    (package_dir / "__pycache__").mkdir()
    (package_dir / "__pycache__" / "mount.cpython-314.pyc").write_bytes(b"cache\n")
    _load_fake_console(monkeypatch, package_dir)

    console = integ.attest_console()
    assert console is not None
    assert sorted((d.path, d.reason) for d in console.drift) == [
        (f"{_CONSOLE_PKG}/mount.cp314-win_amd64.pyd", "missing"),
        (f"{_CONSOLE_PKG}/static/evil.JS", "missing"),
        (f"{_CONSOLE_PKG}/static/extra.js", "missing"),
    ]
    assert console.checked == len(_CONSOLE_FILES)


def test_a_deleted_console_file_is_missing_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deleting a shipped file is tampering too (the csp-probe script is the example: without it the
    'CSP not enforced' banner never shows). The console's own RECORD names it, so its absence is
    drift."""
    console_root = _install_engine_and_console(tmp_path, monkeypatch)
    package_dir = console_root / _CONSOLE_PKG
    (package_dir / "static" / "app.js").unlink()
    _load_fake_console(monkeypatch, package_dir)

    console = integ.attest_console()
    assert console is not None
    assert [(d.path, d.reason) for d in console.drift] == [
        (f"{_CONSOLE_PKG}/static/app.js", "missing")
    ]
    assert console.checked == len(_CONSOLE_FILES) - 1


def test_a_console_file_swapped_for_a_symlink_is_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A symlink to a file outside the install root is what an import follows, so the arm must hash
    the target in the file's own place rather than skip it as out-of-root."""
    console_root = _install_engine_and_console(tmp_path, monkeypatch)
    package_dir = console_root / _CONSOLE_PKG
    evil = tmp_path / "outside" / "evil.py"
    evil.parent.mkdir()
    evil.write_bytes(b"def mount_ui(app, deps):\n    raise SystemExit\n")
    target = package_dir / "mount.py"
    target.unlink()
    try:
        target.symlink_to(evil)
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    _load_fake_console(monkeypatch, package_dir)

    console = integ.attest_console()
    assert console is not None
    assert [(d.path, d.reason) for d in console.drift] == [
        (f"{_CONSOLE_PKG}/mount.py", "hash_mismatch")
    ]


def test_a_single_file_module_shadowing_the_console_is_unattestable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A module with no ``__path__`` under the console's name, outside the install root: nothing is
    compared, and that is attested-nothing, never clean."""
    _install_engine_and_console(tmp_path, monkeypatch)
    shadow = tmp_path / "elsewhere" / f"{_CONSOLE_PKG}.py"
    shadow.parent.mkdir(parents=True)
    shadow.write_bytes(b"def mount_ui(app, deps):\n    return None\n")
    fake = types.ModuleType(_CONSOLE_PKG)
    fake.__file__ = str(shadow)
    monkeypatch.setitem(sys.modules, _CONSOLE_PKG, fake)
    monkeypatch.setattr(integ, "_console_loaded_files", _REAL_CONSOLE_LOADED_FILES)

    assert integ._console_loaded_files() == [shadow.resolve()]
    console = integ.attest_console()
    assert console is not None
    assert console.ok is False and console.attested_nothing is True
    assert console.unattested_reason == "no_attested_file_under_install_root"


@pytest.mark.parametrize("shape", ["not_installed", "record_rowless"])
async def test_a_loaded_console_that_cannot_be_attested_fails_like_the_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """Loaded but unattestable is the engine's AC-13, applied to the console: warn, record, alert under
    its own subject, and refuse under fail-closed. Absent is the only shape the arm skips."""
    console_root = _install_engine_and_console(
        tmp_path, monkeypatch, console_installed=shape != "not_installed"
    )
    if shape == "record_rowless":
        record = console_root / f"{_CONSOLE_PKG}-1.0.dist-info" / "RECORD"
        record.write_text(f"{_CONSOLE_PKG}-1.0.dist-info/RECORD,,\n", encoding="utf-8")
    expected_reason = {
        "not_installed": "not_an_installed_distribution",
        "record_rowless": "record_has_no_package_rows",
    }[shape]

    store = await open_store(sqlite_settings(str(tmp_path / f"{shape}.db")), create=True)
    sink = _RecordingSink()
    try:
        with pytest.raises(IntegrityError) as refused:
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert str(refused.value).startswith(
            f"web console integrity attestation verified nothing ({expected_reason})"
        )
        rows = _startup_rows(await store.list_audit())
        assert len(rows) == 1
        detail = json.loads(str(rows[0]["detail"]))
        assert detail["distribution"] == "messagefoundry-webconsole"
        assert detail["unattested_reason"] == expected_reason and detail["checked"] == 0
        assert [event[0] for event in sink.events] == ["webconsole-unattested"]
    finally:
        await store.close()


@pytest.mark.parametrize("fail_closed", [False, True])
async def test_a_console_arm_that_raises_is_attested_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_closed: bool
) -> None:
    """A console pass that raises (a non-UTF-8 console RECORD is one way) must neither crash an
    alert-only start nor replace the engine's refusal. It is attested-nothing: recorded and alerted
    after the engine's evidence, and refused only under the opt-in, with the engine's text first."""
    _install_engine_and_console(tmp_path, monkeypatch)
    (tmp_path / "engine" / "mfengine" / "core.py").write_bytes(b"SAFE = False\n")

    def _console_arm_breaks() -> None:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(integ, "attest_console", _console_arm_breaks)

    store = await open_store(
        sqlite_settings(str(tmp_path / f"raises-{fail_closed}.db")), create=True
    )
    sink = _RecordingSink()
    try:
        if fail_closed:
            with pytest.raises(IntegrityError) as refused:
                await run_startup_attestation(store, sink, fail_closed_on_drift=True)
            assert str(refused.value).startswith("engine integrity attestation failed: 1 ")
            assert "(console_attestation_raised)" in str(refused.value)
        else:
            await run_startup_attestation(store, sink, fail_closed_on_drift=False)
        rows = _startup_rows(await store.list_audit())
        assert len(rows) == 2
        assert [event[0] for event in sink.events] == ["engine-integrity", "webconsole-unattested"]
    finally:
        await store.close()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_at_a_record_path_is_drift_and_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading a FIFO blocks forever, which would hang startup. The walk leaves special files out, and
    the RECORD row it leaves unmatched is reported as missing drift instead."""
    console_root = _install_engine_and_console(tmp_path, monkeypatch)
    package_dir = console_root / _CONSOLE_PKG
    target = package_dir / "static" / "app.js"
    target.unlink()
    os.mkfifo(target)
    _load_fake_console(monkeypatch, package_dir)

    console = integ.attest_console()
    assert console is not None
    assert [(d.path, d.reason) for d in console.drift] == [
        (f"{_CONSOLE_PKG}/static/app.js", "missing")
    ]


@pytest.mark.parametrize("engine_editable", [True, False])
async def test_a_dev_checkout_console_inherits_the_engine_editable_exemption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    engine_editable: bool,
) -> None:
    """``pip install -e .`` alone leaves the console importable from the checkout with no distribution
    of its own. Beside a declared-editable engine that is a dev checkout, and it must not be refused.
    THE PAIRED ARM: beside a wheel-installed engine the same console is unattestable and refused."""
    engine_pkg = "mfengine"
    engine_dist, engine_loaded = _build_wheel_install(
        tmp_path / "engine",
        pkg=engine_pkg,
        files={f"{engine_pkg}/__init__.py": b"VERSION = '1.0'\n"},
        editable=engine_editable,
    )
    _patch(monkeypatch, engine_dist, engine_loaded, engine_pkg)

    def _distribution(name: str) -> PathDistribution:
        if name == engine_pkg:
            return engine_dist
        raise PackageNotFoundError(name)

    monkeypatch.setattr(integ.metadata, "distribution", _distribution)
    loose = tmp_path / "checkout" / _CONSOLE_PKG / "__init__.py"
    loose.parent.mkdir(parents=True)
    loose.write_bytes(b"__version__ = '1.0'\n")
    monkeypatch.setattr(integ, "_console_loaded_files", lambda: [loose.resolve()])

    store = await open_store(sqlite_settings(str(tmp_path / "devcheckout.db")), create=True)
    sink = _RecordingSink()
    try:
        if engine_editable:
            with caplog.at_level(logging.WARNING, logger="messagefoundry.integrity"):
                await run_startup_attestation(store, sink, fail_closed_on_drift=True)
            assert _startup_rows(await store.list_audit()) == []
            assert sink.events == []
            warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
            # Only the ENGINE's AC-14 warning: no console install exists to name.
            assert len(warnings) == 1 and "this install DECLARES" in warnings[0], warnings
        else:
            with pytest.raises(IntegrityError, match="not_an_installed_distribution"):
                await run_startup_attestation(store, sink, fail_closed_on_drift=True)
            assert [event[0] for event in sink.events] == ["webconsole-unattested"]
    finally:
        await store.close()


async def test_a_console_that_declares_itself_editable_is_the_ac12_no_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A dev checkout's console is never bricked, never audited and never alerted. Under the opt-in it
    warns, naming the console as the install that disarmed it."""
    console_root = _install_engine_and_console(tmp_path, monkeypatch, console_editable=True)
    (console_root / f"{_CONSOLE_PKG}/mount.py").write_bytes(b"# dev edit\n")

    store = await open_store(sqlite_settings(str(tmp_path / "editable.db")), create=True)
    sink = _RecordingSink()
    try:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.integrity"):
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "the messagefoundry-webconsole install DECLARES itself editable" in warnings[0]
        assert _startup_rows(await store.list_audit()) == []
        assert sink.events == []
    finally:
        await store.close()


async def test_both_arms_record_before_either_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Engine drift and console drift at once: two audit rows, two alerts under their own subjects, and
    one refusal naming both. The engine's refusal text stays first and unchanged."""
    console_root = _install_engine_and_console(tmp_path, monkeypatch)
    (tmp_path / "engine" / "mfengine" / "core.py").write_bytes(b"SAFE = False\n")
    (console_root / f"{_CONSOLE_PKG}/mount.py").write_bytes(b"# neutered\n")

    store = await open_store(sqlite_settings(str(tmp_path / "both.db")), create=True)
    sink = _RecordingSink()
    try:
        with pytest.raises(IntegrityError) as refused:
            await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        message = str(refused.value)
        assert message.startswith("engine integrity attestation failed: 1 attested file(s)")
        assert "; web console integrity attestation failed: 1 attested file(s)" in message
        assert len(_startup_rows(await store.list_audit())) == 2
        assert [event[0] for event in sink.events] == ["engine-integrity", "webconsole-integrity"]
    finally:
        await store.close()


# The engine arm's operator-facing text, pinned WORD FOR WORD. The console arm reuses the handler that
# emits it, so this is the proof that extending the check changed nothing an engine operator reads.
# These strings were the module's output before BACKLOG #1802; edit them only on purpose.
_ENGINE_TEXT = {
    "drift_log": (
        "startup integrity DRIFT: 1 engine file(s) do not match the installed wheel RECORD "
        "(fail_closed=True) — possible in-place engine tampering"
    ),
    "drift_reason": "1 engine file(s) drifted from the installed wheel RECORD",
    "drift_refusal": (
        "engine integrity attestation failed: 1 attested file(s) do not match the installed wheel "
        "RECORD ([integrity].fail_closed_on_drift=true; refusing to start)"
    ),
    "nothing_log": (
        "startup integrity: attestation verified NOTHING (record_absent_or_empty) — no engine file "
        "was compared against a RECORD baseline (fail_closed=True), so an in-place edit would go "
        "undetected"
    ),
    "nothing_reason": (
        "startup attestation compared no engine file against a baseline (record_absent_or_empty)"
    ),
    "nothing_refusal": (
        "engine integrity attestation verified nothing (record_absent_or_empty): no engine file was "
        "compared against the installed wheel RECORD ([integrity].fail_closed_on_drift=true; refusing "
        "to start on an unattested install)"
    ),
    "editable_log": (
        "startup integrity: [integrity].fail_closed_on_drift is set, but this install DECLARES itself "
        "editable (declared_editable), so attestation compared no file and the tripwire is DISARMED — "
        "the hard enforcement you opted into is NOT in effect. Install the non-editable wheel to get "
        "it. This reports a misconfiguration, not a tamper: an actor who can write the venv can plant "
        "the editable marker itself."
    ),
    "clean_log": "startup integrity: 2 engine file(s) attested clean",
}


@pytest.mark.parametrize("shape", ["drift", "nothing", "editable", "clean"])
async def test_the_engine_arm_text_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, shape: str
) -> None:
    pkg = "mfengine"
    files = {f"{pkg}/__init__.py": b"VERSION = '1.0'\n", f"{pkg}/core.py": b"SAFE = True\n"}
    dist, loaded = _build_wheel_install(
        tmp_path, pkg=pkg, files=files, editable=shape == "editable"
    )
    _patch(monkeypatch, dist, loaded, pkg)
    if shape == "drift":
        (tmp_path / f"{pkg}/core.py").write_bytes(b"SAFE = False\n")
    elif shape == "nothing":
        (tmp_path / f"{pkg}-1.0.dist-info" / "RECORD").unlink()

    store = await open_store(sqlite_settings(str(tmp_path / f"{shape}.db")), create=True)
    sink = _RecordingSink()
    try:
        with caplog.at_level(logging.INFO, logger="messagefoundry.integrity"):
            if shape in {"drift", "nothing"}:
                with pytest.raises(IntegrityError) as refused:
                    await run_startup_attestation(store, sink, fail_closed_on_drift=True)
                assert str(refused.value) == _ENGINE_TEXT[f"{shape}_refusal"]
                assert [event[1] for event in sink.events] == [_ENGINE_TEXT[f"{shape}_reason"]]
                detail = json.loads(str(_startup_rows(await store.list_audit())[0]["detail"]))
                assert "distribution" not in detail, "the engine's audit detail keeps its old keys"
            else:
                await run_startup_attestation(store, sink, fail_closed_on_drift=True)
        assert _ENGINE_TEXT[f"{shape}_log"] in caplog.messages, caplog.messages
    finally:
        await store.close()
