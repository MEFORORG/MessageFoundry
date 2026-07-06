# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Startup self-attestation of the installed engine wheel — a runtime tamper tripwire.

ADR 0041 (D3). ADR 0036 guards the **config dir** (an unauthorized writer can't drop a ``.py`` that
the loader executes); nothing checked that the installed ``messagefoundry`` **site-packages** still
match the attested wheel. An admin with venv-write + restart rights could edit engine code in place
(neuter ``field_authz`` redaction, the off-box audit tee, …) and it would run with **no audit row at
all**. This module closes that gap: at startup (and on demand) it hashes every **loaded** first-party
``messagefoundry`` module file against the wheel's ``*.dist-info/RECORD`` baseline (a zero-new-artifact
manifest already shipped in the wheel) and, on drift, records a hash-chained ``startup_integrity``
audit row and fires the :class:`~messagefoundry.pipeline.alerts.AlertSink`.

Posture (ADR 0017 amendment, 2026-06-27):

- **Default = alert-only.** Drift records + alerts but the engine still starts. A legitimate, reviewed
  in-place security hotfix (e.g. the documented vendored-patch contingency for the dormant
  ``python-hl7``/``hl7apy`` parsers) would itself trip a ``RECORD`` mismatch, so fail-closed-by-default
  would brick a legitimate patch at the worst moment.
- **Opt-in ``[integrity].fail_closed_on_drift``** raises :class:`IntegrityError` before listeners bind
  — refuse to run unattested engine bytes.
- **No-op on an editable install** (``pip install -e .`` — detected via ``direct_url.json``
  ``dir_info.editable``, an ``__editable__``/``.pth`` finder in ``RECORD``, or an absent/empty
  ``RECORD`` baseline). A dev co-development checkout is **never** bricked or alerted.

Pure + offline: it hashes file *bytes* and reads packaging metadata only — no subprocess, no network,
no config import. The on-disk hashing is blocking, so the async entry point runs it off the event loop
(``asyncio.to_thread``), exactly like ``load_config`` / the config fingerprint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from messagefoundry.pipeline.alerts import AlertSink
    from messagefoundry.store.base import Store

__all__ = [
    "IntegrityError",
    "AttestationResult",
    "DriftEntry",
    "attest_engine",
    "run_startup_attestation",
]

log = logging.getLogger(__name__)

#: The installed distribution whose wheel ``RECORD`` is the integrity baseline.
_DIST_NAME = "messagefoundry"

#: Only first-party engine *source* is attested. A ``.pyc`` is a build artifact, not reviewed bytes,
#: and ``RECORD`` lists ``.py`` (not the compiled cache), so attesting ``.py`` is the right anchor.
_ATTESTED_SUFFIX = ".py"


class IntegrityError(RuntimeError):
    """Startup attestation detected drift AND ``[integrity].fail_closed_on_drift`` is set — the engine
    must refuse to start rather than run unattested bytes (raised before any listener binds)."""


@dataclass(frozen=True)
class DriftEntry:
    """One attested module file that does not match its ``RECORD`` baseline.

    ``reason`` is ``"hash_mismatch"`` (on-disk bytes differ from the recorded sha256) or ``"missing"``
    (a loaded module file has no ``RECORD`` entry at all — e.g. a file added in place after install).
    No file content is carried — only the relpath + reason (no PHI, nothing sensitive).
    """

    path: str
    reason: str


@dataclass(frozen=True)
class AttestationResult:
    """Outcome of one attestation pass. ``editable``/``no_record`` mark the no-op posture (an editable
    or RECORD-less install — attestation is advisory and never drifts). ``checked`` counts the loaded
    module files compared; ``drift`` is the (possibly empty) list of mismatches."""

    attested: bool  # True only when a real RECORD baseline was compared against
    editable: bool
    no_record: bool
    checked: int
    drift: list[DriftEntry] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether the engine bytes are clean: either nothing to attest (no-op) or zero drift."""
        return not self.drift

    def audit_detail(self) -> dict[str, object]:
        """A PHI-free JSON-able summary for the ``startup_integrity`` audit detail / alert payload."""
        detail: dict[str, object] = {
            "attested": self.attested,
            "checked": self.checked,
            "drift_count": len(self.drift),
        }
        if self.editable:
            detail["editable"] = True
        if self.no_record:
            detail["no_record"] = True
        if self.drift:
            # Bound the listed paths so a wholesale mismatch can't bloat the audit row; the count is
            # authoritative. Sorted for a stable, diffable detail.
            paths = sorted(d.path for d in self.drift)
            detail["drift"] = paths[:50]
            detail["drift_reasons"] = sorted({d.reason for d in self.drift})
        return detail


def _decode_record_hash(token: str) -> bytes | None:
    """Decode a RECORD ``hash`` token ``"sha256=<b64url-nopad>"`` to raw digest bytes.

    Returns ``None`` for an empty token (RECORD permits a blank hash, e.g. the ``RECORD`` file itself)
    or any non-sha256 / unparseable algorithm, so such an entry is simply not attested."""
    token = token.strip()
    if not token:
        return None
    algo, _, b64 = token.partition("=")
    if algo != "sha256" or not b64:
        return None
    # RECORD uses urlsafe base64 WITHOUT padding; restore the padding before decoding.
    pad = "=" * (-len(b64) % 4)
    try:
        return base64.urlsafe_b64decode(b64 + pad)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None


def _parse_record(record_text: str) -> dict[str, bytes]:
    """Map ``posix-relpath -> sha256-digest`` for every sha256 RECORD row, keyed by the relpath as
    written. RECORD rows are ``path,hash,size``; ``path`` may itself be quoted/contain commas, so the
    hash + size are split from the **right**. A row without a usable sha256 is skipped."""
    out: dict[str, bytes] = {}
    for raw in record_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # rsplit from the right: path,<sha256=...>,<size>. A path with an embedded comma stays intact.
        parts = line.rsplit(",", 2)
        if len(parts) != 3:
            continue
        path, hash_token, _size = parts
        digest = _decode_record_hash(hash_token)
        if digest is not None:
            out[path.strip().replace("\\", "/")] = digest
    return out


def _is_editable_install(dist: metadata.Distribution, record: dict[str, bytes]) -> bool:
    """Whether the installed distribution is an editable (``pip install -e .``) install — robustly,
    via three independent signals (any one is conclusive):

    1. ``direct_url.json`` with ``dir_info.editable == true`` (PEP 660 / PEP 610).
    2. A RECORD entry naming an editable finder / path hook — ``__editable__.*`` or a ``*.pth``.
    3. No first-party ``messagefoundry/*.py`` rows in RECORD at all (an editable install lists only
       the finder + dist-info, never the package source) — so there is no baseline to attest against.
    """
    try:
        raw = dist.read_text("direct_url.json")
    except (OSError, KeyError):
        raw = None
    if raw:
        try:
            info = json.loads(raw)
            if bool(info.get("dir_info", {}).get("editable", False)):
                return True
        except (json.JSONDecodeError, AttributeError):
            pass
    for relpath in record:
        name = relpath.rsplit("/", 1)[-1]
        if name.startswith("__editable__") or name.endswith(".pth") or "_editable_impl" in name:
            return True
    # A wheel install records the package source; an editable one records none of it.
    if not any(
        rel.startswith(f"{_DIST_NAME}/") and rel.endswith(_ATTESTED_SUFFIX) for rel in record
    ):
        return True
    return False


def _loaded_module_files() -> list[Path]:
    """The on-disk ``.py`` files of the loaded first-party ``messagefoundry`` package, sorted.

    Sourced from ``messagefoundry.__path__`` so it attests exactly the bytes Python imported this
    process from this install (the integrity question is "do the loaded files match the wheel"). A
    ``.pyc`` cache, vendored ``tee/``, and any non-``.py`` are excluded.
    """
    import messagefoundry

    files: set[Path] = set()
    for root in messagefoundry.__path__:
        base = Path(root)
        for path in base.rglob(f"*{_ATTESTED_SUFFIX}"):
            if path.is_file():
                files.add(path.resolve())
    return sorted(files)


def _record_relpath(file: Path, install_root: Path) -> str | None:
    """The RECORD-relative posix path for ``file`` (relative to the site-packages install root), or
    ``None`` when the file is not under the install root (a defensive guard — a loaded module from an
    unexpected location is treated as unattestable, not silently matched)."""
    try:
        return file.relative_to(install_root).as_posix()
    except ValueError:
        return None


def _install_root(dist: metadata.Distribution) -> Path | None:
    """The site-packages root the RECORD relpaths are anchored to (the parent of the ``*.dist-info``
    dir). ``dist.locate_file('')`` resolves it across importlib backends; fall back to the dist-info
    parent."""
    try:
        located = dist.locate_file("")
        if located is not None:
            return Path(str(located)).resolve()
    except (AttributeError, OSError):
        pass
    path = getattr(dist, "_path", None)  # e.g. .../site-packages/messagefoundry-X.dist-info
    if path is not None:
        return Path(str(path)).parent.resolve()
    return None


def attest_engine() -> AttestationResult:
    """Hash every loaded first-party ``messagefoundry`` module file against the installed wheel's
    ``*.dist-info/RECORD`` baseline. Pure + offline + synchronous (blocking file reads) — callers on
    the event loop must wrap it in ``asyncio.to_thread``.

    Never raises for a missing/editable install (it returns a no-op result); a true I/O failure
    reading a module file marks that file as drift (``missing``) rather than crashing startup.
    """
    try:
        dist = metadata.distribution(_DIST_NAME)
    except metadata.PackageNotFoundError:
        # Run from a source tree without an installed dist (e.g. `python -m messagefoundry` in the
        # repo): no baseline exists, so attestation is a no-op/advisory — never fail or alert.
        log.debug("integrity: %s is not an installed distribution; attestation skipped", _DIST_NAME)
        return AttestationResult(attested=False, editable=False, no_record=True, checked=0)

    try:
        record_text = dist.read_text("RECORD")
    except (OSError, KeyError):
        record_text = None
    if not record_text:
        log.debug("integrity: no RECORD baseline; attestation is a no-op (advisory)")
        return AttestationResult(attested=False, editable=False, no_record=True, checked=0)

    record = _parse_record(record_text)
    if _is_editable_install(dist, record):
        log.debug(
            "integrity: editable install detected; attestation is a no-op (dev never bricked)"
        )
        return AttestationResult(attested=False, editable=True, no_record=False, checked=0)

    install_root = _install_root(dist)
    if install_root is None:
        log.debug("integrity: could not resolve the install root; attestation skipped")
        return AttestationResult(attested=False, editable=False, no_record=True, checked=0)

    drift: list[DriftEntry] = []
    checked = 0
    for file in _loaded_module_files():
        rel = _record_relpath(file, install_root)
        if rel is None:
            continue  # loaded from outside the install root — not attestable against this RECORD
        expected = record.get(rel)
        if expected is None:
            # A loaded engine module with no RECORD row — an in-place-added file (a planted backdoor
            # module is exactly this) is drift, not a silent pass.
            drift.append(DriftEntry(path=rel, reason="missing"))
            continue
        checked += 1
        try:
            actual = hashlib.sha256(file.read_bytes()).digest()
        except OSError:
            drift.append(DriftEntry(path=rel, reason="missing"))
            continue
        if actual != expected:
            drift.append(DriftEntry(path=rel, reason="hash_mismatch"))
    return AttestationResult(
        attested=True, editable=False, no_record=False, checked=checked, drift=drift
    )


async def run_startup_attestation(
    store: "Store",
    alert_sink: "AlertSink",
    *,
    fail_closed_on_drift: bool,
) -> AttestationResult:
    """Run :func:`attest_engine` off the event loop and act on drift (ADR 0041 D3):

    - clean / no-op (editable, no RECORD): nothing recorded, nothing alerted;
    - drift: write a hash-chained ``startup_integrity`` audit row (so it survives a host compromise
      via the off-box tee) and fire :meth:`AlertSink.integrity_drift`;
    - drift **and** ``fail_closed_on_drift``: after recording + alerting, raise :class:`IntegrityError`
      so the caller refuses to start before any listener binds.

    Wire it into the engine/serve startup *before* listeners bind. The audit/alert are best-effort:
    an audit-write failure is logged but does not mask the drift signal (the raise still happens under
    fail-closed).
    """
    import asyncio

    result = await asyncio.to_thread(attest_engine)
    if not result.drift:
        if result.attested:
            log.info("startup integrity: %d engine module(s) attested clean", result.checked)
        return result

    drift_count = len(result.drift)
    log.error(
        "startup integrity DRIFT: %d engine module(s) do not match the installed wheel RECORD "
        "(fail_closed=%s) — possible in-place engine tampering",
        drift_count,
        fail_closed_on_drift,
    )
    detail = result.audit_detail()
    detail["fail_closed"] = fail_closed_on_drift
    try:
        await store.record_audit("startup_integrity", actor=None, detail=json.dumps(detail))
    except Exception:  # noqa: BLE001 — audit is best-effort; never mask the drift signal
        log.exception("startup integrity: failed to record the startup_integrity audit row")
    # Fire the dedicated integrity_drift channel (#54, PHI-free: a label + reason + count) so the
    # off-box notifier (webhook/email) pages on the tamper signal — and an operator can route/triage
    # it independently of a stalled delivery lane (connection_stopped).
    try:
        alert_sink.integrity_drift(
            "engine-integrity",
            reason=f"{drift_count} engine module(s) drifted from the installed wheel RECORD",
            drift_count=drift_count,
        )
    except Exception:  # noqa: BLE001 — alerting is best-effort and must never break startup
        log.exception("startup integrity: AlertSink failed")

    if fail_closed_on_drift:
        raise IntegrityError(
            f"engine integrity attestation failed: {drift_count} loaded module(s) do not match the "
            "installed wheel RECORD ([integrity].fail_closed_on_drift=true; refusing to start)"
        )
    return result
