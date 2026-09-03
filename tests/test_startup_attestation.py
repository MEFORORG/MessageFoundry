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
from collections.abc import Sequence
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

    store = await open_store(sqlite_settings(str(tmp_path / "asset.db")))
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
