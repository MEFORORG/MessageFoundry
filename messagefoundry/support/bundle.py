# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Assemble the offline support bundle zip (#49).

:func:`build_bundle` writes a single ``.zip``; it starts no server. Contents (each a small text/JSON
member):

* ``version.txt`` / ``manifest.json`` — the engine :data:`messagefoundry.__version__` + generation
  timestamp + a content listing.
* ``config-summary.json`` — a summary of the wired graph that holds no secret: registry COUNTS only
  (inbound/outbound/router/handler counts + the connection NAMES + transport TYPE), never a settings
  value, host, path, credential, or any ``env()``-resolved data.
* ``status.json`` — a ``/status`` snapshot built from the REAL status models
  (:class:`~messagefoundry.api.models.SystemStatus` / ``EngineInfo`` / ``DbInfo``), populated offline
  from the store. Metadata-only, the term the manifest's ``phi_contract`` uses;
  :func:`status_snapshot` says what it holds.
* ``app-log.txt`` — when written, a **redacted** app-log tail or an ``MF-BUNDLE-LOG-*`` code in its place (see
  :mod:`messagefoundry.support.redact` and :func:`_log_tail`).

HARD RULE (do not break): no member this module builds reads a message body from the store, and only
the app-log tail can carry a secret or a body into the archive. The config summary loads the config but
emits counts/names only; the status snapshot opens the store read-only, with its credentials, and emits
only the metadata-only status models; and ``.env`` / ``*.db`` / ``MEFOR_*`` are never read into the
bundle. **The app-log tail is the exception.** It reads the app log, which can hold a residual secret
the redaction pass does not read, and, on a non-production instance running at ``DEBUG``, a full
message body (``docs/PHI.md`` §7, the prod-``DEBUG`` refusal), so the redacted tail can still carry
either. The manifest's ``phi_contract`` states what the archive does and does not hold (BACKLOG
#5385), the ``support-bundle`` CLI help repeats its log-tail residual in the same terms, and
``docs/PHI.md`` stream 14 is the record.

That rule reaches the FAILURE branches too, which is where it used to fail (BACKLOG #1571). A caught
exception's **message** never enters the bundle: config loading wraps text raised by arbitrary operator
modules, a store failure quotes the DSN, and a filesystem error quotes the deployment path, so the
string is deployment- and attacker-shaped. Each branch emits :func:`_diagnostic` instead -- a fixed
code plus the exception TYPE. Late heuristic redaction over the assembled JSON is deliberately NOT the
answer here: the content is already known to be arbitrary, so no pattern set can be argued complete.
"""

from __future__ import annotations

import io
import json
import os
import stat
import time
import zipfile
from dataclasses import dataclass
from errno import ELOOP
from pathlib import Path
from typing import TYPE_CHECKING, Any

from messagefoundry import __version__
from messagefoundry.last_resort import run_guarded

if TYPE_CHECKING:
    from messagefoundry.config.settings import ServiceSettings, StoreBackend

__all__ = ["BundleResult", "build_bundle", "config_summary", "status_snapshot"]

#: Default number of trailing app-log lines to carry (redacted). A tail, not the whole file, so the
#: bundle stays small and the blast radius of any redaction miss is bounded.
DEFAULT_LOG_TAIL_LINES = 500


def _diagnostic(code: str, exc: BaseException) -> str:
    """What a failed bundle section reports: a fixed ``code`` plus the exception TYPE, never its text.

    The codes are stable strings a support reader can look up, and they name the branch precisely
    enough that dropping the message costs no triage:

    * ``MF-BUNDLE-CFG-001`` -- the config did not wire up (``WiringError``).
    * ``MF-BUNDLE-CFG-002`` -- loading the config raised something else.
    * ``MF-BUNDLE-DB-001`` -- the store could not be opened or queried. With ``StoreNotFoundError``
      no store exists at the configured path, and the bundle did not create one (BACKLOG #1780).
    * ``MF-BUNDLE-LOG-001`` -- the configured ``[logging].log_dir`` could not be listed, or a log
      file in it could not be stat'd.
    * ``MF-BUNDLE-LOG-002`` -- the newest app-log file could not be read. With ``_LogFileRefused``
      it was, twice, no longer the plain regular file the listing saw when it was opened
      (BACKLOG #5383). With ``_LogLineTooLong`` no whole line fit in the bytes the read takes
      from the end of the file (BACKLOG #5385).

    A type name is a class defined in this project or the standard library, so it is bounded input; an
    exception's ``str()`` is not, and the bundle is a file an operator hands outside the environment."""
    return f"{code} {type(exc).__name__}"


@dataclass(frozen=True)
class BundleResult:
    """What :func:`build_bundle` wrote — the zip path + the member names (for the CLI summary/tests)."""

    path: str
    members: tuple[str, ...]


def config_summary(config_dir: str | Path) -> dict[str, Any]:
    """A summary of the wired graph that holds no secret, the manifest ``phi_contract``'s term:
    COUNTS + connection names + transport types only.

    Deliberately omits every settings value (hosts, ports, paths, credentials, ``env()`` data) — only
    the shape of the graph is carried, so the summary can never leak a connection string or secret. A
    config that fails to load is reported as an ``error`` diagnostic rather than raising, so a bundle is
    still produced for a broken config (which is exactly when support is wanted). That diagnostic
    carries no exception text: the config dir holds arbitrary operator Python, so whatever it raised is
    arbitrary too (BACKLOG #1571)."""
    from messagefoundry.config.wiring import WiringError, load_config

    try:
        # allow_empty: the bundle REPORTS a graph, it does not gate one (BACKLOG #1648). Letting the
        # empty-graph refusal through here would return `loaded: False` for a config that loads
        # perfectly, sending support after an import error that does not exist — and the emptiness is
        # already visible, and more honestly, in the zero counts below.
        reg = load_config(config_dir, allow_empty=True)
    except WiringError as exc:
        return {"error": _diagnostic("MF-BUNDLE-CFG-001", exc), "loaded": False}
    except Exception as exc:  # never let a config problem abort the whole bundle
        return {"error": _diagnostic("MF-BUNDLE-CFG-002", exc), "loaded": False}

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
    Metadata-only, the manifest ``phi_contract``'s term. ``db`` is null when ``settings`` is None
    or the store cannot be opened or read; in the second case a ``db_error`` member holds a code instead of
    raising (e.g. the DB is missing or in use), so the bundle still builds."""
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
        db_info = run_guarded(_db_info(settings))
    except Exception as exc:  # a missing/locked DB must not abort the bundle
        # No driver text: a store failure routinely quotes the whole DSN, host and login (#1571).
        return {
            "engine": engine.model_dump(),
            "db": None,
            "db_error": _diagnostic("MF-BUNDLE-DB-001", exc),
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

    # Read-only (db_status), so it cannot start an audit chain (BACKLOG #1916). Opened read-only
    # (BACKLOG #1780): a bundle is collected when something is already wrong, so it must report the
    # store as it is, neither migrating it nor refusing one this build does not match.
    store = await open_store(settings.store, read_only=True, keyless_chain_refusal=None)
    try:
        db = await store.db_status()
    finally:
        await store.close()
    return DbInfo(
        path=_redact_store_path(db.path, settings.store.backend),
        size_bytes=db.size_bytes,
        disk_free_bytes=db.disk_free_bytes,
        disk_free_status=db.disk_free_status.value,
        journal_mode=db.journal_mode,
        messages=db.messages,
        events=db.events,
        audit=db.audit,
        synchronous=db.synchronous,
    )


#: The suffixes that count as an app-log file in ``log_dir``.
_LOG_SUFFIXES = (".log", ".txt")

#: The name-surrogate bit of a Windows reparse tag: set on a symbolic link and a junction, the
#: reparse points that name another file. A file with another reparse tag, such as a OneDrive
#: placeholder or a deduplicated file, holds its own content and is still read.
_IO_REPARSE_TAG_NAME_SURROGATE = 0x20000000

#: How many times the newest log is listed and opened. A second pass covers a rotation that
#: replaced the file between listing and opening, which reads as a swap to the identity check.
_LOG_READ_ATTEMPTS = 2

#: The most bytes from the end of the app-log file the tail is taken from; the read takes one
#: byte more, to find where a line starts. The whole file used to be read, so a
#: large enough log raised ``MemoryError`` and no zip was written (BACKLOG #5385).
_LOG_TAIL_MAX_BYTES = 4 * 1024 * 1024


class _LogFileRefused(OSError):
    """The newest app-log file was not, once opened, the plain regular file the listing saw: a
    different file or a special file swapped in at its name (BACKLOG #5383). A type of this
    module, so :func:`_diagnostic` reports it by its bounded name."""


class _LogLineTooLong(OSError):
    """No whole line of the app-log file fit in the bytes the read takes from its end, so the
    tail would be empty although the file is not (BACKLOG #5385)."""


def _is_plain_file(st: os.stat_result) -> bool:
    """A regular file with one name, that is not a symbolic link or junction.

    ``st`` comes from a call that did not follow links, so a link reads as a link here. A second
    hard link is refused because it can name a file outside ``log_dir`` with nothing to show it."""
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return False
    return not getattr(st, "st_reparse_tag", 0) & _IO_REPARSE_TAG_NAME_SURROGATE


def _log_candidates(directory: Path) -> list[tuple[Path, os.stat_result]]:
    """The app-log files directly under ``directory``, each with its own (not followed) stat. A
    symbolic link, a junction, a hard link, a FIFO, a device, a socket or a directory with a log
    suffix is left out, so the bundle copies no file through a link from outside ``log_dir``
    (BACKLOG #5383). Raises :class:`OSError` when the directory cannot be listed or a candidate
    cannot be read; one that is gone by then is left out."""
    out: list[tuple[Path, os.stat_result]] = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if os.path.splitext(entry.name)[1] not in _LOG_SUFFIXES:
                continue
            try:
                # os.lstat, not entry.stat: on Windows a DirEntry's stat leaves st_dev, st_ino and
                # st_nlink zero, and they are what is checked here and in _read_log_file.
                st = os.lstat(entry.path)
            except FileNotFoundError:
                continue  # gone between listing and stat; it is not the newest log any more
            if _is_plain_file(st):
                out.append((Path(entry.path), st))
    return out


def _read_log_file(path: Path, listed: os.stat_result) -> str:
    """The text of at most the last ``_LOG_TAIL_MAX_BYTES`` bytes of ``path``, less the line the
    bound cuts into, checked after the open to be the same plain regular file that was listed
    (BACKLOG #5383): ``fstat`` on the new descriptor must report a regular file with the device
    and file id the listing saw. The descriptor is closed on every path out.

    On POSIX, ``O_NOFOLLOW`` makes the open fail with ``ELOOP`` when a symbolic link has been put
    at the name, so the open never reaches another file through one. ``O_NONBLOCK`` makes the open
    of a FIFO put at the name return at once instead of waiting for a writer; the descriptor is
    made blocking again before the read. A directory put at the name opens there, and the check
    after the open refuses it as :class:`_LogFileRefused`; on Windows its open fails with
    :class:`PermissionError`.

    Windows has neither flag. There the open follows a symbolic link or junction put at the name
    after the listing, so the open itself reaches whatever the link names, and any effect of
    opening that target happens: connecting to a named pipe the link points at, for one. What the
    check after the open prevents is only the read: a target with another id is refused, and
    none of its content enters the bundle. Raises :class:`OSError`, the identity refusal as
    :class:`_LogFileRefused`."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | nonblocking
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            listed.st_dev,
            listed.st_ino,
        ):
            raise _LogFileRefused("the app-log file changed between listing and opening")
        if nonblocking:
            os.set_blocking(fd, True)
        # One byte before the bound is read too, so the line the bound cuts into can be told
        # from one it starts exactly at: that byte is a line break only in the second case.
        truncated = opened.st_size > _LOG_TAIL_MAX_BYTES
        start = max(0, opened.st_size - _LOG_TAIL_MAX_BYTES - 1)
        os.lseek(fd, start, os.SEEK_SET)
        want = opened.st_size - start
        chunks: list[bytes] = []
        while want > 0:
            chunk = os.read(fd, want)
            if not chunk:
                break  # truncated since the fstat, as a rotation can
            chunks.append(chunk)
            want -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if truncated:
        # Drop through the first line break: what precedes it is the cut line, or nothing when
        # the bound starts exactly after it. A CRLF counts as one break.
        lf = data.find(b"\n")
        cr = data.find(b"\r", 0, lf if lf >= 0 else len(data))
        cut = (cr if cr >= 0 else lf) + 1
        if cut == 0 or not data[cut:].strip(b"\r\n"):
            raise _LogLineTooLong("no whole app-log line fits in the read bound")
        if data[cut - 1 : cut + 1] == b"\r\n":
            cut += 1
        data = data[cut:]
    # Read tolerant of a legacy codepage; the redaction pass runs on the decoded text.
    return data.decode("utf-8", errors="replace")


def _log_tail(log_dir: str | None, *, lines: int) -> str | None:
    """A redacted tail of an app-log file under ``log_dir``. ``None`` at least when no log dir is
    configured or ``lines`` is not positive (BACKLOG #5384: a slice by zero or a negative count
    would carry the whole file, or most of it). An :class:`OSError` from the listing or the read is
    not propagated.

    Only a plain regular file with one name is read: a link, a hard link or a special file with a
    log suffix is passed over (BACKLOG #5383), see :func:`_log_candidates` and
    :func:`_read_log_file`. A file replaced between listing and opening, as a rotation does, is
    listed and opened again once before the refusal is reported.

    EVERY returned string leaves through ``redact_log_text``, and that is what makes the manifest's
    ``phi_contract`` claim about this member true. The two failure branches used to ``return`` ahead of
    the redactor with the configured path, the file name and the OS error text inline, so a bundle's
    ``app-log.txt`` could carry an unredacted deployment path (BACKLOG #1571). They now report the
    branch, not the circumstances: the operator knows their own ``log_dir``, and the code says which
    step failed."""
    from messagefoundry.support.redact import redact_log_text, split_log_lines

    if not log_dir or lines <= 0:
        return None
    text = ""
    for attempt in range(_LOG_READ_ATTEMPTS):
        try:
            files = _log_candidates(Path(log_dir))
        except OSError as exc:
            return redact_log_text(_diagnostic("MF-BUNDLE-LOG-001", exc))
        if not files:
            return None
        newest, listed = max(files, key=lambda item: item[1].st_mtime)
        try:
            text = _read_log_file(newest, listed)
        except OSError as exc:
            # A refusal, a file gone, or (POSIX) a link put at its name: each is what a rotation or
            # a swap between listing and opening leaves, so list again once before reporting it.
            changed = isinstance(exc, (_LogFileRefused, FileNotFoundError)) or exc.errno == ELOOP
            if changed and attempt + 1 < _LOG_READ_ATTEMPTS:
                continue
            return redact_log_text(_diagnostic("MF-BUNDLE-LOG-002", exc))
        break
    tail = split_log_lines(text)[-lines:]
    return redact_log_text("\n".join(tail))


def build_bundle(
    out_path: str | Path,
    *,
    config_dir: str | Path | None = None,
    settings: ServiceSettings | None = None,
    log_tail_lines: int = DEFAULT_LOG_TAIL_LINES,
    now: float | None = None,
) -> BundleResult:
    """Write the support-bundle zip to ``out_path``; it starts no server.

    ``config_dir`` (optional) drives the config summary, which holds no secret; ``settings``
    (optional) drives the status snapshot + the redacted log tail. Each member is best-effort — a
    failure in one section is recorded in that member, never aborting the bundle — because support
    is most wanted when something is already broken.

    Returns a :class:`BundleResult` (the path + member names). The caller is responsible for picking a
    PHI-safe destination. This function never copies ``.env`` / ``*.db`` content into the bundle, but
    the bundle is neither secret-free nor PHI-free: the app-log tail is only best-effort redacted,
    and the manifest's ``phi_contract`` names at least what survives it (BACKLOG #5385)."""
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
        # An explicit, auditable statement of what is and isn't in the bundle (the PHI contract). It
        # is machine-readable and a reviewer may rely on it, so it claims no more than every member
        # meets. The CLI help repeats its log-tail residual (BACKLOG #1475, #5385), and
        # tests/test_support_bundle.py holds the two to the same terms, so change both together.
        "phi_contract": (
            "no member reads a message body from the store; config summary is counts/names only and "
            "holds no secret; status is the metadata-only status models; the app-log tail is a "
            "BEST-EFFORT redacted copy of the app log, and values survive it, at least a single-token "
            "identifier such as an operator username and, on a non-production instance logging at "
            "DEBUG, a message body the log recorded in a shape the redaction does not read, so the bundle is to be handled as a copy of the app log, "
            "not as secret-free or PHI-free; a section that failed reports a fixed MF-BUNDLE-* code plus "
            "the exception type, never the exception message"
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
