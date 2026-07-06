# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Assemble the offline support bundle zip (#49).

:func:`build_bundle` writes a single ``.zip`` from purely **local** inputs — it touches no network and
starts no server. Contents (each a small text/JSON member):

* ``version.txt`` / ``manifest.json`` — the engine :data:`messagefoundry.__version__` + generation
  timestamp + a content listing.
* ``config-summary.json`` — a **secret-free** summary of the wired graph: registry COUNTS only
  (inbound/outbound/router/handler counts + the connection NAMES + transport TYPE), never a settings
  value, host, path, credential, or any ``env()``-resolved data.
* ``status.json`` — a ``/status`` snapshot built from the REAL status models
  (:class:`~messagefoundry.api.models.SystemStatus` / ``EngineInfo`` / ``DbInfo``), populated offline
  from the store. PHI-free (counts + sizes only).
* ``app-log.txt`` — a **redacted** tail of the configured app log (see
  :mod:`messagefoundry.support.redact`); omitted when no ``[logging].log_dir`` is configured.

HARD RULE (do not break): no raw message bodies and no secrets. The config summary emits counts/names
only; the status snapshot is the metadata-only status models; the log tail is run through the redaction
pass; and ``.env`` / ``*.db`` / ``MEFOR_*`` are never read into the bundle.
"""

from __future__ import annotations

import asyncio
import io
import json
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from messagefoundry import __version__

if TYPE_CHECKING:
    from messagefoundry.config.settings import ServiceSettings, StoreBackend

__all__ = ["BundleResult", "build_bundle", "config_summary", "status_snapshot"]

#: Default number of trailing app-log lines to carry (redacted). A tail, not the whole file, so the
#: bundle stays small and the blast radius of any redaction miss is bounded.
DEFAULT_LOG_TAIL_LINES = 500


@dataclass(frozen=True)
class BundleResult:
    """What :func:`build_bundle` wrote — the zip path + the member names (for the CLI summary/tests)."""

    path: str
    members: tuple[str, ...]


def config_summary(config_dir: str | Path) -> dict[str, Any]:
    """A **secret-free** summary of the wired graph: COUNTS + connection names + transport types only.

    Deliberately omits every settings value (hosts, ports, paths, credentials, ``env()`` data) — only
    the shape of the graph is carried, so the summary can never leak a connection string or secret. A
    config that fails to load is reported as an ``error`` string rather than raising, so a bundle is
    still produced for a broken config (which is exactly when support is wanted)."""
    from messagefoundry.config.wiring import WiringError, load_config

    try:
        reg = load_config(config_dir)
    except WiringError as exc:
        return {"error": str(exc), "loaded": False}
    except Exception as exc:  # never let a config problem abort the whole bundle
        return {"error": f"{type(exc).__name__}: {exc}", "loaded": False}

    return {
        "loaded": True,
        "counts": {
            "inbound": len(reg.inbound),
            "outbound": len(reg.outbound),
            "routers": len(reg.routers),
            "handlers": len(reg.handlers),
        },
        # NAMES + transport TYPE only — never the per-connector settings (which carry hosts/paths/
        # credentials). The connection name is operator-authored ([TYPE]_[PARTNER]_[MESSAGE]) and is
        # not PHI; the transport type is an enum value (MLLP/File/...). Nothing else is included.
        "inbound": [
            {"name": name, "type": c.spec.type.value} for name, c in sorted(reg.inbound.items())
        ],
        "outbound": [
            {"name": name, "type": c.spec.type.value} for name, c in sorted(reg.outbound.items())
        ],
        "routers": sorted(reg.routers),
        "handlers": sorted(reg.handlers),
    }


def status_snapshot(settings: ServiceSettings | None) -> dict[str, Any]:
    """A ``/status`` snapshot built from the REAL status models, populated offline from the store.

    The engine isn't running under the CLI, so ``EngineInfo`` carries the version with a zero uptime /
    no live channel counts; ``DbInfo`` is read from the store the settings point at (when reachable).
    PHI-free — the status models are metadata/counts/sizes only. Returns an ``error`` member instead of
    raising if the store can't be opened (e.g. the DB is missing or in use), so the bundle still builds."""
    import os

    from messagefoundry.api.models import EngineInfo, SystemStatus

    engine = EngineInfo(
        version=__version__,
        uptime_seconds=0.0,  # the CLI bundle is taken with the engine not running in-process
        pid=os.getpid(),
        channels_total=0,
        channels_running=0,
        channels_stopped=0,
        outbox_by_status={},
    )
    if settings is None:
        return {"engine": engine.model_dump(), "db": None}

    try:
        db_info = asyncio.run(_db_info(settings))
    except Exception as exc:  # a missing/locked DB must not abort the bundle
        return {
            "engine": engine.model_dump(),
            "db": None,
            "db_error": f"{type(exc).__name__}: {exc}",
        }
    status = SystemStatus(engine=engine, db=db_info, logs=None)
    return status.model_dump()


def _redact_store_path(path: str, backend: StoreBackend) -> str:
    """A non-identifying store descriptor for the bundle. A server-DB ``path`` is ``"<server>/<database>"``
    (``store/sqlserver.py``, ``store/postgres.py``), so carrying it verbatim leaks the DB **host and
    database name** into the off-box bundle (DELTA-05) — a breach of the bundle's stated no-host/no-path
    contract. Return only the backend kind for a server backend, and only the file **basename** for SQLite
    (dropping any directory, which can carry a username or deployment path)."""
    import os

    from messagefoundry.config.settings import StoreBackend

    if backend is StoreBackend.SQLITE:
        return os.path.basename(path) or path
    return f"<{backend.value}>"


async def _db_info(settings: ServiceSettings) -> Any:
    from messagefoundry.api.models import DbInfo
    from messagefoundry.store.base import open_store

    store = await open_store(settings.store)
    try:
        db = await store.db_status()
    finally:
        await store.close()
    return DbInfo(
        path=_redact_store_path(db.path, settings.store.backend),
        size_bytes=db.size_bytes,
        disk_free_bytes=db.disk_free_bytes,
        journal_mode=db.journal_mode,
        messages=db.messages,
        events=db.events,
        audit=db.audit,
        synchronous=db.synchronous,
    )


def _log_tail(log_dir: str | None, *, lines: int) -> str | None:
    """A redacted tail of the newest app-log file under ``log_dir`` (one level). ``None`` when no log
    dir is configured or it holds no readable log file. **Never** raises — a log read problem is logged
    into the tail text, not propagated."""
    from messagefoundry.support.redact import redact_log_text

    if not log_dir:
        return None
    directory = Path(log_dir)
    try:
        files = [p for p in directory.iterdir() if p.is_file() and p.suffix in (".log", ".txt")]
    except OSError as exc:
        return f"(could not list log dir {log_dir!r}: {exc})"
    if not files:
        return None
    newest = max(files, key=lambda p: p.stat().st_mtime)
    try:
        # Read tolerant of a legacy codepage; the redaction pass runs on the decoded text.
        text = newest.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"(could not read {newest.name!r}: {exc})"
    tail = text.splitlines()[-lines:]
    return redact_log_text("\n".join(tail))


def build_bundle(
    out_path: str | Path,
    *,
    config_dir: str | Path | None = None,
    settings: ServiceSettings | None = None,
    log_tail_lines: int = DEFAULT_LOG_TAIL_LINES,
    now: float | None = None,
) -> BundleResult:
    """Write the support-bundle zip to ``out_path`` from local inputs only (no network, no server).

    ``config_dir`` (optional) drives the secret-free config summary; ``settings`` (optional) drives the
    status snapshot + the redacted log tail. Each member is best-effort — a failure in one section is
    recorded in that member, never aborting the bundle — because support is most wanted when something
    is already broken.

    Returns a :class:`BundleResult` (the path + member names). The caller is responsible for picking a
    PHI-safe destination; this function never reads ``.env`` / ``*.db`` content into the bundle nor any
    secret value."""
    now = time.time() if now is None else now
    members: dict[str, str] = {}

    members["version.txt"] = f"{__version__}\n"

    cfg = (
        config_summary(config_dir) if config_dir is not None else {"loaded": False, "skipped": True}
    )
    members["config-summary.json"] = json.dumps(cfg, indent=2, sort_keys=True)

    status = status_snapshot(settings)
    members["status.json"] = json.dumps(status, indent=2, sort_keys=True, default=str)

    log_dir = settings.logging.log_dir if settings is not None else None
    log_tail = _log_tail(log_dir, lines=log_tail_lines)
    if log_tail is not None:
        members["app-log.txt"] = log_tail

    manifest = {
        "tool": "messagefoundry support-bundle",
        "version": __version__,
        "generated_at": now,
        "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "members": sorted(members),
        # An explicit, auditable statement of what is and isn't in the bundle (the PHI contract).
        "phi_contract": (
            "no raw message bodies, no secrets; config summary is counts/names only; status is the "
            "metadata-only status models; the app-log tail is redacted"
        ),
    }
    members["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True)

    out = Path(out_path)
    if out.parent and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(members):
            zf.writestr(name, members[name])
    out.write_bytes(buffer.getvalue())
    return BundleResult(path=str(out), members=tuple(sorted(members)))
