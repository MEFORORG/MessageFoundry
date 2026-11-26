# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Data-retention + store-maintenance worker (PHI.md §8, ASVS 14.2.x).

Without enforcement, PHI accumulates in the message store indefinitely — including dead-lettered
raw bodies. :class:`RetentionRunner` is the single background task that enforces the ``[retention]``
service settings: past the configured windows it **nulls message/dead-letter bodies while keeping
the message ROW** (the Mirth Data-Pruner pattern — counts, disposition, and the audit trail stay
intact; the row survives, its PHI columns — ``metadata`` included, ASVS 14.2.7 — do not). Tiers that
carry nothing BUT PHI and back no count (transform state, connection events, saved-search presets) are
DELETEd outright rather than blanked. It also checkpoints the WAL and ``VACUUM``s on a daily off-peak
schedule. A
pass writes a ``retention_purge`` ``audit_log`` entry recording the cutoffs + counts (never any
message content); which passes write one, and when one can still be missing, is stated once, in
:meth:`RetentionRunner.run_once`. When the store outgrows ``max_db_mb`` it raises an advisory ``storage_threshold``
alert. On a SQLite store it also logs a WARNING each pass while free space on the store's volume is
below ``min_free_disk_mb`` (BACKLOG #290); ``serve`` refuses to start below that same floor, through
:func:`read_disk_floor`. On every backend it logs a WARNING each pass while ``audit_log`` holds more
rows than ``audit_log_warn_rows`` (BACKLOG #1421), because nothing prunes that table.

It is owned by the :class:`~messagefoundry.pipeline.engine.Engine` (started in ``start``, cancelled in
``stop``) rather than the per-graph runner, so it is independent of config reloads and runs once per
process. The clock is injected so the windows and the daily VACUUM time are deterministically testable
(``run_once`` performs a full pass for a given ``now``); the loop only governs cadence.

Engine-side and dependency-light (stdlib + the store/alert seams only), so it never pulls the API or
console into the engine.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import functools
import json
import logging
import os
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from messagefoundry.config.settings import RetentionSettings, StoreBackend
from messagefoundry.config.wiring import Registry
from messagefoundry.parsing.compression import CompressionError, gzip_compress, gzip_decompress
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import safe_exc
from messagefoundry.store import DeadLetterPurge, Store, StripResult
from messagefoundry.transports.base import (
    ArchiveGuard,
    ProcessedArchive,
    archive_dir_key,
    build_archive_guard,
)

__all__ = [
    "DiskFloorReading",
    "RetentionRunner",
    "RetentionPass",
    "read_disk_floor",
    "sqlite_store_file",
]

log = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86_400
# How long a pass that ended partway waits for a retention_purge audit row still being written
# (BACKLOG #6526), so a store that cannot take the write does not hold up the pass's exception. A
# row still unwritten then is logged at ERROR.
_AUDIT_WRITE_WAIT_SECONDS = 5.0
# The one budget stop() spends in all on the loop's exit and audit rows still being written when it
# is handed none (BACKLOG #6526). Shutdown must not hang on a store that cannot take the write;
# engine.stop() hands stop() a shorter budget to fit its own.
_STOP_WAIT_SECONDS = 5.0
# Phases that change no data. A pass that ends in one of these with nothing else done writes no
# interrupted audit row (BACKLOG #6526): one failing every interval would otherwise add a row of
# zeros each time. Any phase not named here is treated as one that may have changed data.
_PHASES_THAT_CHANGE_NO_DATA = frozenset({"wal_checkpoint", "vacuum", "size_check"})
# Purge phases that run in one store transaction on every backend. One that raises an error is
# taken to have rolled back, so a pass that ends on an error in one with nothing else done writes no
# interrupted audit row (BACKLOG #6526): one failing every interval would otherwise add a row of
# zeros each time and hold each pass for its audit write. The error goes on to the caller, which
# logs it. A cancellation can land while the COMMIT is in flight, so a pass cancelled in one still
# writes its row. An error out of the COMMIT itself, a dropped connection say, can leave it unknown
# whether the COMMIT landed; such a pass writes a row only when it had done other work. The
# reference-snapshot purge is not named: on Postgres it deletes one set at a time.
_SINGLE_TRANSACTION_PHASES = frozenset(
    {"messages", "dead_letters", "state", "connection_events", "alert_instances", "search_presets"}
)
_BYTES_PER_MB = 1_000_000
#: The low-disk floor (`min_free_disk_mb`, BACKLOG #290) counts in MiB, not the decimal MB that
#: `max_db_mb` uses, so its 1024 default is exactly the 1 GiB the DR-backup preflight already treats
#: as low space (`dr_backup._preflight_destination`).
_BYTES_PER_MIB = 1 << 20

#: What counts as an "application log file" in ``[logging].log_dir`` — the same notion the ``/status``
#: metering and the support-bundle tail use. Shared by the #120 delete sweep and the #119 compressor.
_APP_LOG_SUFFIXES = (".log", ".txt")
#: Suffix of the #119 gzip artifact, and of the temp file it is staged through (never a swept suffix,
#: so a crash mid-write can't leave a half-file that a later pass mistakes for a finished archive).
_GZ_SUFFIX = ".gz"
_GZ_TMP_SUFFIX = ".gz.mftmp"
#: Suffix of an archive claimed for removal, ``<name>.gz.<pid>-<ns>.mfclaim`` (#6805,
#: :func:`_drop_redundant_archive`). It holds a whole archive, so log content; which sweep removes it
#: is stated once, on :func:`_is_app_log_name`.
_CLAIM_SUFFIX = ".mfclaim"
#: Prefix of the staging file. The rest of the name is RANDOM (:func:`tempfile.mkstemp`), never derived
#: from the source: a predictable staging path in a directory a second process (or an attacker) can write
#: is an arbitrary-file-overwrite / log-destruction primitive — see :meth:`RetentionRunner._stage_archive`.
_GZ_TMP_PREFIX = "mfgz-"
#: Free-space precheck margin (#119): the peak on-disk cost of compressing a file is the source PLUS the
#: archive, and gzip's worst case (incompressible input) is marginally LARGER than the source — so the
#: requirement is ``size + max(10% of size, 1 MiB)``. Below that the file is skipped and logged rather
#: than attempted, so a maintenance pass can never be what fills the volume.
_COMPRESS_FREE_MARGIN_RATIO = 10  # divisor: size // 10 == 10%
_COMPRESS_FREE_MIN_MARGIN_BYTES = 1 << 20  # 1 MiB
#: Per-file ceiling (#119). The codec is bytes-in/bytes-out, so one file costs ~2x its size in RAM
#: (source + archive) plus the round-trip buffer during validation. NSSM rotates at ~10 MB, so 64 MiB is
#: ample headroom while bounding a maintenance pass's memory. A larger file is skipped and logged.
_COMPRESS_MAX_FILE_BYTES = 64 << 20  # 64 MiB

#: Per-connection "keep forever" (#34, ADR 0027): a cutoff of -inf makes ``received_at < cutoff`` always
#: false, so that connection's bodies are never purged even while the global window prunes others.
_KEEP_FOREVER = float("-inf")


def _is_app_log_name(name: str, *, include_archives: bool) -> bool:
    """Is ``name`` an application-log file this runner owns? ``.log``/``.txt`` always; the ``.log.gz``/
    ``.txt.gz`` archives the #119 compressor produces only when ``include_archives`` (so an unrelated
    ``.gz`` parked in the log directory is never swept, and neither is any ``.gz`` at all on a deployment
    that has not enabled compression).

    Under the same ``include_archives`` gate it also owns a claimed archive,
    ``<archive>.<pid>-<ns>`` plus :data:`_CLAIM_SUFFIX`, where ``<archive>`` is one of those archive
    names (#6805). A claim keeps the mtime of the archive it was renamed from (inherited from the
    source), so the sweep removes a claim only when it would remove that archive."""
    lowered = name.lower()
    stem, ext = os.path.splitext(lowered)
    if ext in _APP_LOG_SUFFIXES:
        return True
    if include_archives and ext == _GZ_SUFFIX:
        return os.path.splitext(stem)[1] in _APP_LOG_SUFFIXES
    if include_archives and ext == _CLAIM_SUFFIX:
        archive, tag = os.path.splitext(stem)
        pid, sep, ns = tag[1:].partition("-")
        return (
            sep == "-"
            and all(part.isascii() and part.isdigit() for part in (pid, ns))
            and archive.endswith(_GZ_SUFFIX)
            and _is_app_log_name(archive, include_archives=True)
        )
    return False


def _verify_archive(path: str, original: bytes, *, name: str) -> bool:
    """Integrity-validate a written gzip archive: re-read it **off disk**, decompress it, and compare it
    **byte-for-byte** with the source bytes. Only a True here may be followed by deleting the original.

    The original's length is the exact expected output size, so it doubles as the decompression-bomb
    ceiling (:func:`~messagefoundry.parsing.compression.gzip_decompress` refuses incrementally past it —
    a corrupt archive claiming to expand to gigabytes is rejected, not materialized). Every failure is
    logged with the file NAME and byte counts only; the round-tripped bytes are never logged (an
    application log is operational text, PHI.md §7)."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        log.warning(
            "app-log archive for %r could not be re-read for validation; original kept", name
        )
        return False
    try:
        round_trip = gzip_decompress(blob, max_output_bytes=len(original))
    except CompressionError:
        log.warning(
            "app-log archive for %r failed integrity validation (corrupt/truncated); original kept",
            name,
        )
        return False
    if round_trip != original:
        log.warning(
            "app-log archive for %r failed integrity validation (%d bytes round-tripped, %d expected); "
            "original kept",
            name,
            len(round_trip),
            len(original),
        )
        return False
    return True


# Opening a log to read or re-check it does not follow a symlink, or block on a FIFO, swapped in at
# the path, where the platform has O_NOFOLLOW and O_NONBLOCK. Windows has neither, so there the open
# does follow a symlink; the flags a platform lacks are simply absent.
_SOURCE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _same_file_state(a: os.stat_result, b: os.stat_result) -> bool:
    """Whether two ``fstat`` results describe one unchanged file: the same device and file id
    (:func:`os.path.samestat`), size, mtime and ctime (ns). ctime is the change time on both POSIX and,
    through ``fstat``, Windows, and ``os.utime`` cannot set it back. Both sides must come from
    ``fstat``: on Windows ``os.stat`` reports the creation time as ctime, so a mixed pair never agrees."""
    return os.path.samestat(a, b) and (a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (
        b.st_size,
        b.st_mtime_ns,
        b.st_ctime_ns,
    )


def _source_change(source: str, read_st: os.stat_result) -> str | None:
    """``None`` when ``source`` is still the file described by ``read_st`` (the ``fstat`` taken on the
    handle its bytes were read through), else why not: ``"vanished"`` or ``"changed"``, or the error a
    re-open raised. Every non-``None`` answer blocks the act it gates, so it fails closed. The path is
    re-opened and ``fstat``-ed (:data:`_SOURCE_OPEN_FLAGS`) so both sides of the compare are alike.

    This does not make the check and the act atomic: at least a change landing between this check and
    the ``remove`` or rename that follows it, and an in-place same-size rewrite with the mtime put back
    inside one ctime tick of the file's last change, still pass it (#6805)."""
    try:
        fd = os.open(source, _SOURCE_OPEN_FLAGS)
    except FileNotFoundError:
        return "vanished"
    except OSError as exc:
        return f"could not be re-read ({type(exc).__name__})"
    try:
        now_st = os.fstat(fd)
    except OSError as exc:
        return f"could not be re-read ({type(exc).__name__})"
    finally:
        try:
            os.close(fd)
        except OSError:
            log.debug("could not close a re-check descriptor", exc_info=True)
    return None if _same_file_state(now_st, read_st) else "changed"


def _source_still_holds(source: str, read_st: os.stat_result, data: bytes) -> bool:
    """Whether ``source`` is still the same regular file as ``read_st`` (device and file id) and its
    content still starts with ``data``, so an archive of ``data`` is redundant beside it. Any error is
    False: the answer gates removing an archive, so it fails closed and keeps the archive."""
    try:
        fd = os.open(source, _SOURCE_OPEN_FLAGS)
    except OSError:
        return False
    try:
        now_st = os.fstat(fd)
        if not stat.S_ISREG(now_st.st_mode) or not os.path.samestat(now_st, read_st):
            return False
        if hasattr(os, "O_NONBLOCK"):
            os.set_blocking(fd, True)
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(len(data)) == data
    except OSError:
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            log.debug("could not close a re-check descriptor", exc_info=True)


def _drop_redundant_archive(
    source: str, read_st: os.stat_result, data: bytes, dest: str, *, name: str
) -> bool:
    """Remove the archive of ``data`` at ``dest`` when the kept ``source`` still holds every byte of it.
    Returns True only once the claim was removed. A failed removal is logged and returns False,
    leaving the ``.mfclaim`` file in place (#6805). A claim already gone (removed by a peer's
    ``app_log_days`` sweep, say) counts as removed.

    ``dest`` is first CLAIMED by renaming it to a unique sibling name, so a peer compressor cannot act
    on it, and only then are the claimed bytes re-validated and the source re-checked. If either fails
    (the source went or changed meanwhile, or the claimed file is a peer's different archive), the
    claim is linked back to ``dest``, which never replaces a file that appeared there; if that fails
    too, the claim is kept under its name and a WARNING names it, unless the claim is already gone
    (a WARNING says so). A claim name ends
    :data:`_CLAIM_SUFFIX`, which no compression pass touches; :func:`_is_app_log_name` says when the
    ``app_log_days`` sweep removes one.

    What this closes: a source removed between the first check and the claim. What it does NOT
    close, so a copy can still be lost: at least a source truncated or removed after the post-claim
    re-check and before the claim is removed. Two windows in the caller remain open as well: a
    peer's archive placed between its ``exists(dest)`` check and ``os.replace`` is renamed over, and
    an append or rotation between its last :func:`_source_change` and ``os.remove(source)`` is
    deleted."""
    if not (_source_still_holds(source, read_st, data) and _verify_archive(dest, data, name=name)):
        return False
    claim = f"{dest}.{os.getpid()}-{time.monotonic_ns()}{_CLAIM_SUFFIX}"
    try:
        os.rename(dest, claim)
    except OSError as exc:
        if isinstance(exc, FileNotFoundError) and not os.path.lexists(dest):
            # Gone since it was validated (a peer's `app_log_days` sweep, say), so nothing is kept.
            # Returns False, the value an archive already gone at the read above returns: no claim was
            # taken, and a peer compressor holding it under its own claim may yet put it back.
            # `lexists` because Windows also raises FileNotFoundError for a claim path too long, with
            # `dest` still there; an `lstat` that fails too (a lost share, say) still reads as gone.
            log.debug(
                "app-log %r: the archive %r could not be found when it was to be claimed (already "
                "gone, or its directory unreachable); this pass does not remove it",
                name,
                os.path.basename(dest),
            )
            return False
        log.warning(
            "app-log %r: the redundant archive %r could not be claimed for removal; it is kept",
            name,
            os.path.basename(dest),
        )
        return False
    if _verify_archive(claim, data, name=name) and _source_still_holds(source, read_st, data):
        try:
            os.remove(claim)
        except FileNotFoundError:
            # Already gone (a peer's `app_log_days` sweep, say), so removed: nothing is left under
            # the claim name, and the source still holds every archived byte.
            log.debug("app-log %r: the claim %r was already gone", name, os.path.basename(claim))
        except OSError:
            log.warning(
                "app-log %r: the redundant archive, claimed as %r, could not be removed",
                name,
                os.path.basename(claim),
            )
            return False
        return True
    try:
        os.link(claim, dest)
    except FileNotFoundError:
        log.warning(
            "app-log %r: the claimed archive %r could not be found to put it back (removed "
            "meanwhile by a peer's app_log_days sweep, say, or its directory unreachable); if it "
            "remains, it is KEPT under that name until an operator acts or, while app_log_days is "
            "set and compression is on, its sweep ages it out",
            name,
            os.path.basename(claim),
        )
        return False
    except OSError:
        log.warning(
            "app-log %r: the source or the claimed archive changed while the archive was being "
            "removed, and the archive could not be put back; it is KEPT as %r until an operator acts "
            "or, while app_log_days is set and compression is on, its sweep ages it out",
            name,
            os.path.basename(claim),
        )
        return False
    try:
        os.remove(claim)
    except FileNotFoundError:
        # Already gone; the linked-back `dest` holds the archive.
        log.debug("app-log %r: the claim %r was already gone", name, os.path.basename(claim))
    except OSError:
        log.warning(
            "app-log %r: the claimed archive %r was linked back but could not be removed; it is KEPT "
            "until an operator acts or, while app_log_days is set and compression is on, its sweep "
            "ages it out",
            name,
            os.path.basename(claim),
        )
    return False


def _unlink_quietly(path: str) -> None:
    """Best-effort removal of a staging file. A leftover ``*.gz.mftmp`` is inert (never a swept suffix,
    never mistaken for an archive), so a failure here is logged at debug and otherwise ignored."""
    try:
        os.remove(path)
    except OSError:
        log.debug("could not remove the staging file %r", path, exc_info=True)


@dataclass(frozen=True)
class DiskFloorReading:
    """One measurement of free space against the low-disk floor (BACKLOG #290).

    ``probed`` is the directory actually measured. It is the store file's own directory, or its
    nearest existing ancestor when that directory does not exist yet, because a directory created
    later lands on the ancestor's volume. ``free_bytes`` is ``None`` when the probe failed. That is
    not a low disk, and nothing may treat it as one: ``None`` carries no claim about the drive."""

    probed: str
    free_bytes: int | None
    floor_bytes: int

    @property
    def below(self) -> bool:
        """True only for a MEASURED shortfall. A failed probe is never below the floor."""
        return self.free_bytes is not None and self.free_bytes < self.floor_bytes

    @property
    def free_mib(self) -> int | None:
        """``None`` when the probe failed, never 0: 0 would read as a measured empty drive."""
        return None if self.free_bytes is None else self.free_bytes // _BYTES_PER_MIB

    @property
    def floor_mib(self) -> int:
        return self.floor_bytes // _BYTES_PER_MIB


def sqlite_store_file(store: object) -> str | None:
    """The absolute path of a file-backed SQLite store, or ``None`` when the low-disk floor cannot
    apply to ``store``. Shared by the retention warning and the runtime intake pause (BACKLOG #290),
    so those two cannot disagree. ``serve``'s startup refusal works from settings rather than an
    open store and keeps its own backend check in ``__main__``.

    On SQL Server and Postgres the store's disk belongs to the database server, not to this process,
    so there is nothing here to stat; ``:memory:`` has no disk at all. A store with no ``backend``
    attribute is SQLite, as in ``store/privilege.py``. Made absolute NOW, because a relative path
    means whatever the working directory is at probe time."""
    if getattr(store, "backend", StoreBackend.SQLITE) is not StoreBackend.SQLITE:
        return None
    store_path = str(getattr(store, "path", ":memory:"))
    return None if store_path == ":memory:" else os.path.abspath(store_path)


def read_disk_floor(store_path: str, min_free_disk_mb: int) -> DiskFloorReading | None:
    """Measure free space on the volume that holds (or will hold) the SQLite store at ``store_path``
    against ``min_free_disk_mb`` MiB. Returns ``None`` when the floor is off (``<= 0``).

    Blocking (``stat`` + ``disk_usage``), so an async caller runs it off the event loop. The caller
    decides what a shortfall means: ``serve`` refuses to start, the retention pass warns. The floor
    applies to SQLite only, and checking the backend is the caller's job too."""
    if min_free_disk_mb <= 0:
        return None
    floor_bytes = min_free_disk_mb * _BYTES_PER_MIB
    probe = Path(store_path).parent
    free: int | None = None
    try:
        # Resolve the FILE, not just its directory, so a store file that is a symlink to another
        # volume is measured where its bytes land. Same shape as MessageStore._disk_free_bytes.
        probe = Path(store_path).resolve().parent
        # A store whose directory does not exist yet: measure the nearest ancestor that does. The
        # root always exists on a real volume; the guard only stops a loop on a path whose root
        # does not (an unmapped drive letter, a dead UNC share).
        while not probe.exists():
            if probe.parent == probe:
                break
            probe = probe.parent
        else:
            free = shutil.disk_usage(probe).free
    except OSError:
        log.debug("disk_usage failed for %s", probe, exc_info=True)
    return DiskFloorReading(probed=str(probe), free_bytes=free, floor_bytes=floor_bytes)


@dataclass(frozen=True)
class RetentionPass:
    """What one :meth:`RetentionRunner.run_once` pass did — returned for the audit entry + tests."""

    messages_purged: int
    dead_purged: int
    state_purged: int
    conn_events_purged: int
    wal_checkpointed: bool
    vacuumed: bool
    size_bytes: int
    over_limit: bool
    # Per-connection retention overrides resolved this pass (#34, ADR 0027): inbound name -> messages_days
    # and outbound name -> dead_letter_days (0 = keep forever). Recorded in the audit detail (cutoffs,
    # metadata-only — no message content). Empty in a global-only deployment (byte-identical audit).
    messages_overrides: Mapping[str, int] = field(default_factory=dict)
    dead_letter_overrides: Mapping[str, int] = field(default_factory=dict)
    # Embedded-document pruning this pass (#47, ADR 0042): how many messages had >=1 embedded document
    # stripped, the total documents stripped, the on-disk base64 bytes reclaimed, and the per-connection
    # windows applied (inbound name -> prune_documents_after days). Metadata only — no message content.
    documents_messages_stripped: int = 0
    documents_stripped: int = 0
    documents_bytes_reclaimed: int = 0
    # BACKLOG #5651: the strip phase ended before its last batch, for one of three causes; the
    # counts above are what it had committed, and the strip logs the early end at WARNING each way.
    # The third, batch writes failing in a row, is a store-wide write fault, recorded through
    # `documents_strip_write_failed` as below.
    # A key-service outage is recorded in the audit row when the pass writes one, but is not itself
    # work: an outage pass must not send an audit row through the failing key service. A failed
    # batch read is a database fault, so it is work (`documents_strip_read_failed`), and the pass
    # writes an audit row recording it. A batch write that failed and rolled back
    # (`documents_strip_write_failed`) is recorded in the audit row when the pass writes one, but is
    # not itself work: on a read-only store or a full disk that row's insert would fail too, and
    # raise out of the pass every interval.
    documents_strip_ended_early: bool = False
    documents_strip_read_failed: bool = False
    documents_strip_write_failed: bool = False
    document_prune_overrides: Mapping[str, int] = field(default_factory=dict)
    # Resolved operator-alert instances pruned this pass (#56, ADR 0044) — metadata-only, on the same
    # window as connection events. Never an open/acknowledged instance.
    alert_instances_purged: int = 0
    # `DeadLetterPurge.errors_cleared` (BACKLOG #4996): `dead_purged` counts bodies only, so a pass
    # whose sole change was clearing dead-letter error text still needs this to count as work.
    dead_errors_cleared: int = 0
    # Application log FILES deleted this pass (#120): app-log files past the `app_log_days` window
    # removed from `[logging].log_dir`. Metadata only (mtime) — file content is never read. 0 when the
    # window/log_dir is unset (byte-identical audit for a deployment that doesn't use it).
    app_logs_deleted: int = 0
    # Application log FILES gzipped this pass (#119) and the on-disk bytes reclaimed (source size minus
    # archive size, summed over the files that compressed AND passed integrity validation). A file that
    # was skipped (no free space, oversized, already archived) or whose archive failed validation counts
    # in neither. Metadata only (names/sizes/mtimes) — file content is never logged or audited. Both 0
    # when the window/log_dir is unset, so a deployment that doesn't use it has a byte-identical audit.
    app_logs_compressed: int = 0
    app_log_bytes_reclaimed: int = 0
    # Saved-search presets DELETEd this pass (ADR 0136, ASVS 14.2.7): rows whose `updated_at` is past
    # the `search_preset_days` window. Metadata only — the count, never a needle. 0 when the window is
    # unset (the default), so a deployment that doesn't use it has a byte-identical audit detail.
    search_presets_purged: int = 0
    # Orphaned reference-snapshot ROWS deleted (ADR 0006, ASVS 14.2.7) — sets config no longer
    # declares. Metadata only: a count, never a key or a value. 0 when the window is unset, when no
    # registry is wired, or when the registry declares no reference sets (the positive-signal skip).
    reference_snapshots_purged: int = 0
    # Archived copies DELETEd from running File inbounds' `.processed` directories this pass, past
    # `processed_archive_days` (owner ruling A2 of 2026-10-08, BACKLOG #1188). A count only, never a
    # file or connection name. 0 when the window is unset or no File inbound is bound.
    processed_archives_deleted: int = 0
    # This pass hit the `max_pass_seconds` between-phase duration cap (#121, ADR 0137) and SKIPPED its
    # remaining phases — the skipped tail (incl. any due WAL-checkpoint/VACUUM) re-runs next interval with
    # its last-run marker unadvanced. Always False when the cap is off (`max_pass_seconds<=0`, the
    # default), so a deployment that doesn't use the cap is byte-identical.
    capped: bool = False
    # Free space on the SQLite store's volume was MEASURED below `[retention].min_free_disk_mb` this
    # pass (BACKLOG #290), and a WARNING was logged. Deliberately NOT part of `did_work`: it changes
    # nothing in the store, so it adds no audit row, and a disk that stays low would otherwise write
    # one every pass. False when the floor is off, on a server backend, or when the probe failed.
    below_disk_floor: bool = False
    # The pass ran its WAL truncate and it did NOT finish (vault BACKLOG #2619): a reader or a DR
    # snapshot copy held the WAL, so the -wal file keeps its frames, and a WARNING was logged. Not
    # part of `did_work`, for the reason `below_disk_floor` is not, but a pass that is audited
    # records it, so its purge row says the purge may survive in the -wal file. False when no
    # truncate ran.
    wal_left_untruncated: bool = False
    # `audit_log` held more rows than `[retention].audit_log_warn_rows` this pass (BACKLOG #1421), and
    # a WARNING was logged. NOT part of `did_work`, and that matters more here than for the disk
    # floor: the audit row a did-work pass writes would land in the very table this warns about, so
    # the warning would grow the table by one row every pass. False when the warning is off, when
    # the read failed, or on a follower, which never reads the table.
    audit_log_over_warn: bool = False
    # The pass ended on an exception or a cancellation (`stop()`) partway (BACKLOG #6526, S07-44).
    # Its audit row records exactly what the phases that finished did. None of these flags is part
    # of `did_work`: each only says how a pass ended.
    interrupted: bool = False
    # When `interrupted`, the phase that was working when the pass ended; None if it ended outside
    # any phase's work, before the first or between two. What that running call itself changed is
    # not in the row's counts: a phase that works in steps (the embedded-document strip's batches,
    # the `.processed` sweep, the app-log sweep and compression) may have changed part of its set,
    # and a single-transaction purge cancelled while its COMMIT was in flight may have committed. A
    # strip threshold call that finished before the one that ended the pass is counted.
    interrupted_phase: str | None = None
    # Leadership was lost during the pass (BACKLOG #6526, S07-45), so the shared-store phases after
    # the one that was running were skipped and left for the new leader.
    leadership_lost: bool = False
    # The pass ran on a cluster standby (BACKLOG #6526, S07-46): only the host-local app-log sweep
    # and compression ran, and nothing in the shared store was read or purged. A standby writes its
    # audit row on the same rule as the leader, so at least for a pass that deleted or compressed a
    # file, a capped pass, and one that ended partway.
    standby: bool = False

    @property
    def did_work(self) -> bool:
        """Whether the pass changed anything worth an audit row (a routine WAL checkpoint alone
        isn't — it leaves no data trace and would otherwise spam the audit log every pass).

        A ``capped`` pass counts as work worth recording: an operator needs to see that maintenance ran
        out of its time budget and deferred phases (#121). With the cap off this is always False, so the
        audit cadence is unchanged."""
        return (
            self.messages_purged > 0
            or self.dead_purged > 0
            or self.dead_errors_cleared > 0
            or self.state_purged > 0
            or self.conn_events_purged > 0
            or self.documents_messages_stripped > 0
            or self.documents_strip_read_failed
            or self.alert_instances_purged > 0
            or self.app_logs_deleted > 0
            or self.app_logs_compressed > 0
            or self.search_presets_purged > 0
            or self.reference_snapshots_purged > 0
            or self.processed_archives_deleted > 0
            or self.vacuumed
            or self.over_limit
            or self.capped
        )


def _thread_until_cancelled[R](
    func: Callable[[Callable[[], bool]], R], also_stop: Callable[[], bool] = lambda: False
) -> Awaitable[R]:
    """Run ``func(stop)`` on a worker thread. ``stop()`` turns True once the awaiting task is
    cancelled (or ``also_stop()`` does), so a file loop ends at its next file rather than running
    on after the engine has stopped, as the `.processed` sweep's does (BACKLOG #6526)."""
    cancelled = threading.Event()

    async def run() -> R:
        try:
            return await asyncio.to_thread(func, lambda: cancelled.is_set() or also_stop())
        except asyncio.CancelledError:
            cancelled.set()
            raise

    return run()


# The stop signal of the loop running the current pass, which `_run` sets in its own task's
# context (BACKLOG #6526). A pass that run_once() runs outside the loop has none: no stop() ends it,
# and it always waits for its own interrupted row.
_LOOP_STOP: contextvars.ContextVar[asyncio.Event | None] = contextvars.ContextVar(
    "retention_loop_stop", default=None
)


def _loop_stopped() -> bool:
    """Whether the loop running this pass has been told to stop."""
    stop = _LOOP_STOP.get()
    return stop is not None and stop.is_set()


def _raise_if_stopped() -> None:
    """Re-deliver a stop to a pass that absorbed its cancellation (a store call that swallowed
    it, say), so it starts no further phase once :meth:`RetentionRunner.stop` may have returned
    and the store may be closing (BACKLOG #6526)."""
    if _loop_stopped():
        raise asyncio.CancelledError


def _log_joined_stop_cut(bound: float, *, cancelled: bool) -> None:
    """Log that a stop() call which joined a stop already under way returned within its own bound
    with that stop unfinished (BACKLOG #6526)."""
    log.warning(
        "retention: stop() joined a stop already under way%s and returned after its own %gs; the "
        "retention pass may still be running and its interrupted audit row may not be written",
        ", was cancelled," if cancelled else "",
        bound,
    )


def _retrieve_logged_result(task: asyncio.Task[None]) -> None:
    """Mark an audit task's failure retrieved: ``_audit_logged`` has already logged it, and a
    writer that stopped waiting would otherwise leave asyncio to report it as never retrieved."""
    if not task.cancelled():
        task.exception()


class _PassCap:
    """The #121 between-phase duration cap of one pass. :meth:`hit` reads the monotonic clock and
    LATCHES :attr:`capped` the first time the elapsed pass time reaches ``cap``; ``cap <= 0`` never
    hits. Construction takes the pass's start reading."""

    def __init__(self, monotonic: Callable[[], float], cap: float) -> None:
        self._monotonic = monotonic
        self._cap = cap
        self._start = monotonic()
        self.capped = False

    def hit(self) -> bool:
        if not self.capped and self._cap > 0 and self._monotonic() - self._start >= self._cap:
            self.capped = True
        return self.capped


class RetentionRunner:
    """Enforces ``[retention]`` on the message store: body-purge + WAL checkpoint + VACUUM + a size
    alert, audited per pass. Construct with the store + settings; call :meth:`start`/:meth:`stop` for
    the supervised loop, or :meth:`run_once` to perform a single deterministic pass (tests)."""

    def __init__(
        self,
        store: Store,
        settings: RetentionSettings,
        *,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        coordinator: ClusterCoordinator | None = None,
        registry_source: Callable[[], Registry | None] | None = None,
        log_dir: str | None = None,
        archive_source: Callable[[], Sequence[ProcessedArchive]] | None = None,
        guard_source: Callable[[], Iterable[Path] | None] | None = None,
        engine_dirs: Iterable[Path] = (),
        engine_trees: Iterable[Path] = (),
    ) -> None:
        self._store = store
        # The engine's own directories (store, keys, TLS pair, config) and trees (backup destination,
        # log directory), which no archive sweep may reach either (BACKLOG #1188): an archive that is
        # or holds one is refused, and so is one inside a tree.
        self._engine_dirs = tuple(engine_dirs)
        self._engine_trees = tuple(engine_trees)
        # The bound inbounds whose `.processed` archive the `processed_archive_days` sweep ages out
        # (BACKLOG #1188), read from the LIVE graph each pass like the registry. None (embedding,
        # tests) = nothing to sweep.
        self._archive_source = archive_source
        # Every inbound's watch and `.error` directories across all engine shards, and every File
        # outbound's target directory, bound or not, which no archive sweep may reach. Returning None
        # means one could not be resolved, so the sweep deletes nothing.
        self._guard_source = guard_source
        self._settings = settings
        # The SQLite store file the low-disk floor measures (BACKLOG #290); None when the floor
        # cannot apply to this store. See sqlite_store_file for the rule.
        self._floor_path: str | None = sqlite_store_file(store)
        # The configured `[logging].log_dir` for application-log-file retention (#120). None (the
        # default; embedding/tests, or a stdout-only deployment) → the app-log sweep is a no-op.
        self._log_dir = log_dir
        # Per-connection retention overrides (#34, ADR 0027) are read from the LIVE registry each pass, so
        # a reload that changes an override takes effect on the next pass. None (the default) = no registry
        # wired → no overrides → a single global cutoff, byte-identical to the prior behaviour.
        self._registry_source = registry_source
        # Default to the logging sink so an over-limit store is at least visible without a notifier.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._clock = clock
        # A monotonic clock for the #121 between-phase duration cap and the WAL truncate cadence
        # (BACKLOG #6526) — SEPARATE from `clock` (which is the wall clock feeding the retention
        # *window* cutoffs and is often frozen in tests). Elapsed time measured on a frozen window
        # clock never advances, and on a wall clock stepped backward it goes negative and holds the
        # truncate past its cadence; monotonic can't go backwards.
        self._monotonic = monotonic
        # Retention's store phases are a leader-only WRITE singleton (they purge PHI bodies), so in a
        # cluster they run on exactly one node; a standby runs only its own host's app-log phases and
        # audits those (BACKLOG #6526). Default NullCoordinator → always leader → always runs, so an
        # existing caller/test that passes no coordinator is byte-identical (Track B Step 4).
        self._coordinator: ClusterCoordinator = coordinator or NullCoordinator()
        # The current loop's stop signal. start() makes a new one and the loop keeps the one it was
        # started with, so nothing can clear the signal of a loop already told to stop: one that
        # outlived a stop cut by its timeout still ends at its next check (BACKLOG #6526).
        self._stop = asyncio.Event()
        # Ends the current between-pass sleep early: set by stop(), and by wake() after a config
        # reload. wake() sets it only while the loop is idle, so a window a reload sets is enforced at
        # once only when the loop was idle; on an active loop it waits for the next scheduled pass.
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # Audit row writes in flight, each its own task so a cancellation cannot abort one; stop()
        # waits for them, bounded (BACKLOG #6526).
        self._audit_tasks: set[asyncio.Task[None]] = set()
        # The stop in progress, shared by concurrent stop() calls: a second one waits for it,
        # within its own timeout, rather than taking no loop and returning at once (BACKLOG #6526).
        self._stopping: asyncio.Task[None] | None = None
        # Whether the last check of `enabled` found something to do; the loop logs when it flips.
        self._active = False
        # Maintenance cadence state (loop-driven; only read/written on the single task). The WAL
        # marker is a `monotonic` reading. It starts as None, not 0.0, so the first pass truncates
        # whatever the monotonic clock reads, which can be under the cadence just after boot.
        self._last_wal: float | None = None
        self._last_vacuum_day: str | None = None

    @property
    def enabled(self) -> bool:
        """True when any window/threshold/maintenance knob is configured. When False, a pass does
        nothing worth running, so the loop skips it (and :meth:`start` spawns no loop at all when no
        registry is wired, since nothing can change the answer then). Every purge window is off by
        default, but the low-disk floor (``min_free_disk_mb``, BACKLOG #290) and the hourly WAL
        truncate (``wal_checkpoint_seconds``, vault BACKLOG #2619) ship ON, so on a file-backed
        SQLite store stock settings give the runner passes to run for those two. The audit-log
        growth warning (``audit_log_warn_rows``, BACKLOG #1421) ships ON as well and applies to every
        backend, so stock settings give it passes on SQL Server and Postgres too. It purges nothing
        unless a window is set.

        Embedded-document pruning (#47, ADR 0042) has no ``[retention]`` setting — it is a purely
        per-connection knob — so this is also True when any inbound sets ``prune_documents_after``
        even if no global window is configured. So must a per-connection ``messages_days`` or
        ``dead_letter_days`` window above 0 (0 keeps forever, which no pass acts on). The registry is
        consulted via ``_registry_source`` (None when no registry is wired) and read live, because a
        config reload can set or clear these (BACKLOG #6804)."""
        s = self._settings
        if (
            s.messages_days
            or s.dead_letter_days
            or s.state_max_age_days
            or s.connection_event_retention_hours
            or s.search_preset_days
            or s.reference_snapshot_days
            or s.processed_archive_days
            or s.max_db_mb
            or s.audit_log_warn_rows
            or self._wal_truncate_applies()
            or s.vacuum_time() is not None
            or self._disk_floor_applies()
        ):
            return True
        # Application log-file retention (#120 delete, #119 compress) needs BOTH a window and a log_dir
        # to do anything, so it counts only when both are present (avoids a no-op pass for a configured
        # window on a stdout-only deployment).
        if (s.app_log_days > 0 or s.app_log_compress_days > 0) and self._log_dir:
            return True
        registry = self._registry_source() if self._registry_source is not None else None
        if registry is None:
            return False
        # A connection's own window gives a pass something to do even with every global knob off.
        return any(
            ic.prune_documents_after is not None or (ic.messages_days or 0) > 0
            for ic in registry.inbound.values()
        ) or any((oc.dead_letter_days or 0) > 0 for oc in registry.outbound.values())

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised purge/maintenance loop (idempotent).

        With a registry wired the loop is spawned even when nothing is configured yet, and idles:
        each interval it re-reads :attr:`enabled` and runs a pass only when that is True. A config
        reload can set a per-connection window on a graph that started with none, and a loop decided
        once here would leave that window unenforced until a restart (BACKLOG #6804). With no
        registry nothing can change :attr:`enabled`, so a disabled runner spawns no loop."""
        if self._task is not None:
            return
        active = self.enabled
        if not active and self._registry_source is None:
            log.debug("retention disabled (nothing configured); not starting")
            return
        self._stop = asyncio.Event()
        self._wake.clear()
        self._active = active
        self._task = asyncio.create_task(self._run(self._stop))
        if not active:
            log.debug(
                "retention idle: nothing configured yet; re-checked every %gs, so a config reload "
                "that sets a per-connection window takes effect without a restart",
                self._settings.purge_interval_seconds,
            )
            return
        log.info(
            "retention enabled: messages_days=%d dead_letter_days=%d max_db_mb=%d "
            "min_free_disk_mb=%d audit_log_warn_rows=%d wal_checkpoint_seconds=%g vacuum_at=%r "
            "app_log_days=%d app_log_compress_days=%d processed_archive_days=%d "
            "max_pass_seconds=%g (every %gs)",
            self._settings.messages_days,
            self._settings.dead_letter_days,
            self._settings.max_db_mb,
            self._settings.min_free_disk_mb,
            self._settings.audit_log_warn_rows,
            self._settings.wal_checkpoint_seconds,
            self._settings.vacuum_at,
            self._settings.app_log_days,
            self._settings.app_log_compress_days,
            self._settings.processed_archive_days,
            self._settings.max_pass_seconds,
            self._settings.purge_interval_seconds,
        )

    def wake(self) -> None:
        """End an IDLE loop's sleep, so it re-reads :attr:`enabled` now and runs a pass if a config
        reload just gave it something to do (BACKLOG #6804). The engine calls this after every
        reload. An active loop keeps its interval: waking it would add a pass per reload, each with
        its own alerts and audit row, for a change that it picks up on its next pass anyway."""
        if not self._active:
            self._wake.set()

    @property
    def stop_timeout_seconds(self) -> float:
        """The bound :meth:`stop` uses when it is handed none; engine.stop() shortens it to fit its
        stop budget (BACKLOG #6526)."""
        return _STOP_WAIT_SECONDS

    async def stop(self, *, timeout: float | None = None) -> None:
        """Signal the loop, await its exit, and wait for audit rows still being written.

        The loop's exit and those rows share one budget, ``timeout`` or
        :attr:`stop_timeout_seconds` when it is None, so a store that cannot take the write does
        not hold up shutdown (BACKLOG #6526). The budget wins over the work it cuts (owner ruling
        2026-11-22): a stop that runs out of it returns with the loop possibly still running, and
        logs that the pass's interrupted audit row may not be written. Concurrent calls share one
        stop. A call that joins a stop already under way waits for it within its own budget, and
        the shared stop runs on for the earlier caller. A call that finds a loop started after that
        stop took the old one stops the new loop as well, and waits for the earlier stop too, within
        its own budget. A cancellation of the caller still waits for the stop, within the same
        bound, before it goes on."""
        self._stop.set()
        self._wake.set()
        bound = self.stop_timeout_seconds if timeout is None else timeout
        # Taken here, not in the stop's task, so a second call before that task runs cannot take
        # the same loop, and a loop start() spawned during a stop is never left to that stop.
        task, self._task = self._task, None
        stopping = self._stopping
        if stopping is not None and stopping.done():
            stopping = None
        loop = asyncio.get_running_loop()
        deadline: float | None = None
        if stopping is None or task is not None:
            # This stop's own task is bounded by `bound`, so its caller waits for it to end.
            stopping = self._stopping = asyncio.create_task(
                self._stop_and_drain(task, bound, earlier=stopping)
            )
        else:
            deadline = loop.time() + bound

        def left() -> float | None:
            return None if deadline is None else max(0.0, deadline - loop.time())

        # asyncio.wait, not wait_for: neither this caller's timeout nor its cancellation cancels
        # the shared stop, which an earlier caller may still be waiting on.
        try:
            await asyncio.wait({stopping}, timeout=left())
        except asyncio.CancelledError:
            await asyncio.wait({stopping}, timeout=left())
            if not stopping.done():
                # Only a call that joined a stop under way gets here: one that started its own
                # waits for it, and that stop is bounded by `bound`.
                _log_joined_stop_cut(bound, cancelled=True)
            elif not stopping.cancelled() and (exc := stopping.exception()) is not None:
                log.error(
                    "retention: the loop failed (%s); stop()'s caller was cancelled, so it is "
                    "logged here",
                    safe_exc(exc),
                )
            raise
        if not stopping.done():
            _log_joined_stop_cut(bound, cancelled=False)
            return
        stopping.result()  # a loop that failed raises to the caller of stop(), as before

    async def _stop_and_drain(
        self,
        task: asyncio.Task[None] | None,
        timeout: float,
        earlier: asyncio.Task[None] | None,
    ) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        try:
            if task is not None:
                task.cancel()
                await asyncio.wait({task}, timeout=timeout)
        finally:
            # In a finally so a cancellation of this stop still tries the drain.
            await self._drain_audits(max(0.0, deadline - loop.time()))
            if earlier is not None:
                # Within this stop's budget; the earlier stop's outcome is its own callers'.
                await asyncio.wait({earlier}, timeout=max(0.0, deadline - loop.time()))
                if not earlier.done():
                    _log_joined_stop_cut(timeout, cancelled=False)
        if task is None:
            return
        if not task.done():
            # The budget wins over the work it cuts (owner ruling 2026-11-22): the loop is left to
            # end on its own, and can outlive the store's close.
            log.error(
                "retention: the loop had not ended %gs after stop(); the retention pass may still "
                "be running when the store closes, and its interrupted audit row may not be written",
                timeout,
            )
        elif not task.cancelled():
            task.result()  # a loop that failed raises to the caller of stop(), as before

    async def _drain_audits(self, timeout: float) -> None:
        """Wait up to ``timeout`` for audit rows still being written (BACKLOG #6526)."""
        if not self._audit_tasks:
            return
        _done, pending = await asyncio.wait(set(self._audit_tasks), timeout=timeout)
        if pending:
            log.error(
                "retention: stop() waited %.2fs for %d retention_purge audit row write(s), which "
                "had not finished; a purge they record may have no audit row",
                timeout,
                len(pending),
            )

    async def _run(self, stop: asyncio.Event) -> None:
        # One isolated pass per interval; an error in a pass is logged and the loop continues (a
        # retention hiccup must never take the engine down). Cooperatively cancellable via `stop`,
        # the signal this loop was started with, which its passes read through `_LOOP_STOP`.
        _LOOP_STOP.set(stop)
        while not stop.is_set():
            # Cleared here, before this iteration reads `enabled`, so a wake() that landed before
            # this read (say between start() and the first iteration) is answered by this pass and
            # cannot also cut the sleep after it short into a second, back-to-back pass.
            self._wake.clear()
            try:
                active = self._refresh_active()
            except Exception:
                log.exception(
                    "retention could not read its configuration; will retry next interval"
                )
                active = False
            try:
                if active:
                    await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("retention pass failed; will retry next interval")
            # Checked before the sleep as well: a start() since this loop's stop cleared the wake
            # that stop set, and this loop must not sleep out an interval it should end in.
            if not stop.is_set():
                await self._sleep(self._settings.purge_interval_seconds)

    def _refresh_active(self) -> bool:
        """Re-read :attr:`enabled` for this interval and log a change, so an operator can see a
        reload turn retention on or off (BACKLOG #6804)."""
        active = self.enabled
        if active != self._active:
            self._active = active
            if active:
                log.info(
                    "retention active: the configuration now sets something for it to do "
                    "(a pass every %gs)",
                    self._settings.purge_interval_seconds,
                )
            else:
                log.info("retention idle: the configuration no longer sets anything for it to do")
        return active

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)
        or on :meth:`wake`."""
        try:  # noqa: SIM105
            await asyncio.wait_for(self._wake.wait(), delay)
        except TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    async def run_once(self, now: float | None = None) -> RetentionPass:
        """Run a full retention pass for ``now`` (default: the injected clock): purge bodies past the
        configured windows, checkpoint the WAL / VACUUM if due, check the size threshold, and write a
        single ``audit_log`` entry when the pass did real work. Returns a :class:`RetentionPass`.
        ``now`` does not decide whether the WAL truncate is due: that cadence reads the injected
        ``monotonic`` clock (BACKLOG #6526).

        Leader-gated (Track B Step 4): a non-leader node purges nothing in the shared store, so in a
        cluster exactly one node purges. A standby still runs the app-log sweep and compression (#120,
        #119) on ``[logging].log_dir``, its own host's directory, and audits a pass that deleted or
        compressed a file, as the leader does (:meth:`_standby_pass`, BACKLOG #6526, S07-46). The loop
        keeps ticking on followers (reactive-by-polling), so when a follower becomes leader the very
        next pass acts. A follower never advances its WAL/VACUUM cadence state, so a newly-promoted
        leader runs any due WAL checkpoint / daily VACUUM on its first acting pass — which is the
        correct behavior (the new leader picks up the maintenance the cluster owes). Single-node (the
        NullCoordinator default) is always leader, so none of this changes a pass there.

        Leadership is read again before every shared-store phase, because each phase awaits the store
        and a node can be demoted (a self-fence) during any of those awaits (BACKLOG #6526, S07-45). A
        node that finds itself demoted skips the shared-store phases left, audits what it had already
        purged, and reports ``leadership_lost``. The read is the coordinator's cached flag, not a
        fence: it is only as current as the coordinator's last lease check.

        Each purge phase commits in its own store transaction, so a pass that raises or is cancelled
        (``stop()``) partway writes its audit row for the phases that finished, marked
        ``interrupted`` (BACKLOG #6526, S07-44). A pass that ends inside a phase that changes its
        set in steps writes the row even with nothing else done, naming that phase in
        ``interrupted_phase``, since its count is lost, unless that phase changes no data
        (``_PHASES_THAT_CHANGE_NO_DATA``), which is logged instead. A purge that runs in one
        transaction and raises an error is taken to have rolled back, so a pass that ends on one
        with nothing else done writes no row (``_SINGLE_TRANSACTION_PHASES``); one cancelled inside
        it does, since its COMMIT may have been in flight. The audit writes are shielded
        from a further cancellation. A row can still be missing at least when the audit write itself
        fails (the same store fault that ended the pass, say), when it is still unfinished
        ``_AUDIT_WRITE_WAIT_SECONDS`` after the pass ends or once :meth:`stop`'s budget runs out
        (both logged at ERROR), or when the process dies first.

        The low-disk floor check (BACKLOG #290) runs FIRST, before the leader gate and outside the
        #121 duration cap: it is read-only, it measures this host's own volume, and a pass that ran
        out of time must still say the disk is nearly full."""
        below_disk_floor = await self._check_disk_floor()
        now = self._clock() if now is None else now
        if not self._coordinator.is_leader():
            return await self._standby_pass(now, below_disk_floor)
        s = self._settings

        # The audit-log growth check (BACKLOG #1421) runs after the leader gate, unlike the disk
        # floor: audit_log is the shared store's table, not this host's volume, so in a cluster only
        # the leader warns. (Each engine shard runs its own retention, so each one warns.) It runs
        # before the duration cap, like the floor: it is one index seek, and a pass that ran out of
        # time must still say the table is large.
        audit_log_over_warn = await self._check_audit_growth()

        # Between-phase duration cap (#121, ADR 0137): bound the wall time one maintenance pass may spend
        # so a long pass can't run unbounded into the next window. `cap <= 0` (the default) disables it —
        # byte-identical to the pre-#121 pass. `_deadline_hit()` reads a MONOTONIC clock (not `now`, the
        # window wall-clock, which is often frozen in tests) and LATCHES `capped` the first time the elapsed
        # pass time reaches the cap; each phase below runs only while the deadline is NOT yet hit. The check
        # sits strictly BETWEEN phases — a phase that has already started always runs to completion, so a
        # running VACUUM is never interrupted (its deadline check happens only BEFORE it is dispatched).
        # Once the cap is hit the remaining phases are skipped and re-run next interval; a skipped
        # WAL-checkpoint/VACUUM leaves its last-run marker unadvanced, so it stays due (defer, don't drop).
        pass_cap = _PassCap(self._monotonic, s.max_pass_seconds)
        _deadline_hit = pass_cap.hit

        # The shared-store phases run only while `_halt()` is False: the cap above, or leadership
        # lost since the gate (S07-45), latched like the cap. The host-local app-log phases take the
        # cap alone, because a standby runs those too. A node demoted mid-pass still writes the
        # audit row for the purges it had already committed: an unaudited purge is the worse
        # outcome, and the row is not a leader-only write the way a purge is.
        leadership_lost = False

        def _demoted(*, seen: bool = False) -> bool:
            # On the event loop only, the one place the loss is latched and logged, so the log line
            # and the row's `leadership_lost` are one value. `seen` is a demotion the `.processed`
            # sweep's worker read.
            nonlocal leadership_lost
            if not leadership_lost and (seen or not self._coordinator.is_leader()):
                leadership_lost = True
                log.warning(
                    "retention: this node lost cluster leadership during the pass; it starts no "
                    "further store phase"
                )
            return leadership_lost

        def _halt() -> bool:
            hit = _deadline_hit()
            return _demoted() or hit

        # The `.processed` archive sweep reads this per file on a worker thread, which runs on after
        # a cancel of the pass, so it only reads: a demotion it sees is latched and logged by
        # `_demoted` once the sweep returns, and a late one cannot log a loss the interrupted row
        # does not record. `is_leader()` is a cached attribute read.
        archive_saw_demotion = False

        def _archive_halt() -> bool:
            nonlocal archive_saw_demotion
            if not archive_saw_demotion and not self._coordinator.is_leader():
                archive_saw_demotion = True
            return archive_saw_demotion or _deadline_hit()

        # The phase now working, so an interrupted pass can name it (S07-44): set as a phase starts
        # its work, after its own checks, and cleared when it ends, so a fault between two phases
        # names none.
        running_phase: str | None = None

        @contextlib.contextmanager
        def _running(phase: str) -> Iterator[None]:
            nonlocal running_phase
            _raise_if_stopped()
            running_phase = phase
            yield  # an exception out of the phase leaves it named
            running_phase = None

        # Every count starts at "nothing done", so a pass that ends partway can audit exactly the
        # phases that finished (S07-44).
        msg_days_overrides: dict[str, int] = {}
        dead_days_overrides: dict[str, int] = {}
        doc_overrides: dict[str, int] = {}
        messages_purged = 0
        dead = DeadLetterPurge()
        strip = StripResult()
        state_purged = 0
        conn_events_purged = 0
        alert_instances_purged = 0
        search_presets_purged = 0
        reference_snapshots_purged = 0
        app_logs_deleted = 0
        app_logs_compressed = 0
        app_log_bytes_reclaimed = 0
        processed_archives_deleted = 0
        wal_checkpointed = False
        wal_left_untruncated = False
        vacuumed = False
        size_bytes, over_limit = 0, False

        def _tally(*, interrupted: bool = False) -> RetentionPass:
            return RetentionPass(
                messages_purged=messages_purged,
                dead_purged=dead.bodies,
                dead_errors_cleared=dead.errors_cleared,
                state_purged=state_purged,
                conn_events_purged=conn_events_purged,
                wal_checkpointed=wal_checkpointed,
                vacuumed=vacuumed,
                size_bytes=size_bytes,
                over_limit=over_limit,
                messages_overrides=msg_days_overrides,
                dead_letter_overrides=dead_days_overrides,
                documents_messages_stripped=strip.messages_stripped,
                documents_stripped=strip.documents_stripped,
                documents_bytes_reclaimed=strip.bytes_reclaimed,
                documents_strip_ended_early=strip.ended_early,
                documents_strip_read_failed=strip.read_failed,
                documents_strip_write_failed=strip.write_failed,
                document_prune_overrides=doc_overrides,
                alert_instances_purged=alert_instances_purged,
                app_logs_deleted=app_logs_deleted,
                app_logs_compressed=app_logs_compressed,
                app_log_bytes_reclaimed=app_log_bytes_reclaimed,
                search_presets_purged=search_presets_purged,
                reference_snapshots_purged=reference_snapshots_purged,
                processed_archives_deleted=processed_archives_deleted,
                capped=pass_cap.capped,
                below_disk_floor=below_disk_floor,
                wal_left_untruncated=wal_left_untruncated,
                audit_log_over_warn=audit_log_over_warn,
                interrupted=interrupted,
                interrupted_phase=running_phase if interrupted else None,
                leadership_lost=leadership_lost,
            )

        try:
            # Per-connection retention overrides (#34, ADR 0027), resolved once per pass from the LIVE
            # registry: inbound name -> messages_days, outbound name -> dead_letter_days (0 = keep
            # forever, None = inherit the global window so the connection is omitted from the cutoff map
            # → it uses the global cutoff). Empty when no registry/overrides → byte-identical single
            # global cutoff.
            msg_days_overrides, dead_days_overrides = self._resolve_overrides()
            # A per-connection purge can run even when the GLOBAL window is off (a connection sets its
            # own window while the global default is keep-forever). Run the purge whenever the global
            # window is set OR any connection overrides it.
            if not _halt() and (s.messages_days > 0 or msg_days_overrides):
                with _running("messages"):
                    messages_purged = await self._store.purge_message_bodies(
                        older_than=self._global_cutoff(now, s.messages_days),
                        now=now,
                        connection_cutoffs=self._cutoff_map(now, msg_days_overrides),
                    )
            if not _halt() and (s.dead_letter_days > 0 or dead_days_overrides):
                with _running("dead_letters"):
                    dead = await self._store.purge_dead_letters(
                        older_than=self._global_cutoff(now, s.dead_letter_days),
                        now=now,
                        connection_cutoffs=self._cutoff_map(now, dead_days_overrides),
                    )
            # Embedded-document pruning (#47, ADR 0042): an in-place strip of bulky base64 attachments
            # on a per-connection window, layered over NO global default (it never runs unless a
            # connection sets prune_documents_after). Driven in the same pass; the cutoff map is the
            # per-connection windows mapped to cutoffs, the global ELSE is keep-forever (nothing without
            # an override is stripped). Each connection may set its OWN size threshold, so the strip is
            # run once per distinct min_bytes value with the connections sharing it (a single call
            # carries one threshold).
            doc_overrides, doc_min_bytes, doc_content_types = self._resolve_document_prune()
            # The whole embedded-document strip is one phase: skip it (empty threshold set) if the pass
            # halted before it; otherwise strip once per distinct min_bytes threshold.
            doc_thresholds: list[int] = [] if _halt() else sorted(set(doc_min_bytes.values()))
            for i, threshold in enumerate(doc_thresholds):
                # Each threshold is its own store call of many batches, so leadership is read again
                # between them (S07-45); the cap stays a whole-phase check.
                if i and _demoted():
                    break
                group = {n: d for n, d in doc_overrides.items() if doc_min_bytes[n] == threshold}
                with _running("documents_strip"):
                    part = await self._store.strip_embedded_documents(
                        older_than=_KEEP_FOREVER,  # no global document-prune default → keep-forever
                        now=now,
                        connection_cutoffs=self._cutoff_map(now, group),
                        min_bytes=threshold,
                        content_types={
                            n: doc_content_types[n] for n in group if n in doc_content_types
                        },
                    )
                strip = StripResult(
                    messages_stripped=strip.messages_stripped + part.messages_stripped,
                    documents_stripped=strip.documents_stripped + part.documents_stripped,
                    bytes_reclaimed=strip.bytes_reclaimed + part.bytes_reclaimed,
                    ended_early=part.ended_early,
                    read_failed=part.read_failed,
                    write_failed=strip.write_failed or part.write_failed,
                )
                if part.ended_early:
                    # BACKLOG #5651: a key-service outage, a failed batch read, or batch writes
                    # failing in a row. End only this phase; the rest of the pass still runs.
                    break
            if not _halt() and s.state_max_age_days > 0:
                with _running("state"):
                    state_purged = await self._store.purge_state(
                        older_than=now - s.state_max_age_days * _SECONDS_PER_DAY, now=now
                    )
            # Connection events (#46): the dedicated `connection_event_retention_hours` window if set,
            # else inherit the message-body window (the ADR 0021 §7.5 default — bound the log alongside
            # the bodies). A positive hours value can keep events longer OR shorter than message bodies.
            if s.connection_event_retention_hours > 0:
                event_cutoff: float | None = now - s.connection_event_retention_hours * 3600.0
            elif s.messages_days > 0:
                event_cutoff = now - s.messages_days * _SECONDS_PER_DAY
            else:
                event_cutoff = None
            if not _halt() and event_cutoff is not None:
                with _running("connection_events"):
                    conn_events_purged = await self._store.purge_connection_events(
                        older_than=event_cutoff, now=now
                    )

            # Resolved operator-alert instances (#56, ADR 0044): pruned on the SAME window as connection
            # events (metadata-only, one pass). Only RESOLVED instances are eligible — an
            # open/acknowledged condition is never aged out from under an operator. No window set ⇒
            # inherit the body window.
            if not _halt() and event_cutoff is not None:
                with _running("alert_instances"):
                    alert_instances_purged = await self._store.purge_alert_instances(
                        older_than=event_cutoff, now=now
                    )

            # Saved-search presets (ADR 0136, ASVS 14.2.7): the stored `criteria` is a PHI-shaped
            # needle, so it gets a window like every other PHI tier. A PLAIN window with NO inheritance
            # — unlike connection events above, an unset `search_preset_days` does NOT fall back to the
            # body window. A preset is a user-authored artifact whose `updated_at` only moves on a SAVE,
            # so inheriting a body window would silently delete every preset not re-saved inside it on
            # the first pass after upgrade (a PHI instance always has a bounded body window). Opt-in
            # only. BACKLOG #306 softened this further — the purge now keys on MAX(updated_at,
            # last_used_at), so a preset merely RECALLED inside the window survives; the argument above
            # still holds for the first pass after upgrade, where every pre-#306 row's `last_used_at` is
            # NULL and the key degrades to `updated_at`.
            if not _halt() and s.search_preset_days > 0:
                with _running("search_presets"):
                    search_presets_purged = await self._store.purge_search_presets(
                        older_than=now - s.search_preset_days * _SECONDS_PER_DAY, now=now
                    )

            # Orphaned reference snapshots (ADR 0006, ASVS 14.2.7): `reference.value` is PL-2 and had NO
            # purge path at all — a set dropped from config kept its decryptable rows forever, because
            # the only thing that ever replaced them was the next sync's build-new-then-flip, which never
            # comes for a set nobody declares.
            #
            # THE GUARD IS POSITIVE-SIGNAL, and that is the whole design. `declared` is the keep-set, so
            # an EMPTY one reads as "every set is abandoned" and would purge the entire store. `registry
            # is None` does not cover it: a registry that LOADS FINE while declaring zero reference sets
            # — a subset `--config`, a per-team config split, a harness-redirect run pointed at the real
            # DB — yields `references == {}`. Absence-based guards fail open by construction, so this
            # one requires a POSITIVE signal: at least one declared set, or the phase does not run at
            # all. A registry declaring zero reference sets can never authorize purging any.
            #
            # The store ALSO raises on an empty `declared` rather than trusting this check — belt and
            # braces, because the cost of one refactor dropping this line is every snapshot in the store.
            #
            # Worse without it: ReferenceSyncRunner deliberately does NOT advance `synced_at` when a
            # source fetch fails, so the rows most likely to look "stale" belong to a still-wired set
            # whose source is merely down — precisely the last-good copy an operator would want kept.
            if not _halt() and s.reference_snapshot_days > 0:
                registry = self._registry_source() if self._registry_source is not None else None
                declared = frozenset(registry.references) if registry is not None else frozenset()
                if declared:
                    with _running("reference_snapshots"):
                        reference_snapshots_purged = await self._store.purge_reference_snapshots(
                            older_than=now - s.reference_snapshot_days * _SECONDS_PER_DAY,
                            declared=declared,
                            now=now,
                        )
                else:
                    log.warning(
                        "reference-snapshot retention skipped: the loaded registry declares no "
                        "reference sets, so there is no keep-set and a purge would delete every "
                        "snapshot in the store. Set [retention].reference_snapshot_days=0 to silence "
                        "this, or check that --config points at the configuration this store belongs to."
                    )

            # Application log files (#120, then #119): host-local, so they take the cap alone and
            # run on a standby and after a demotion too. Each count lands as its phase ends, so an
            # interrupted pass still audits a sweep that finished.
            # Each awaits nothing when it is off, so naming it here names no phase that never ran.
            with _running("app_log_sweep"):
                app_logs_deleted = await self._sweep_app_log_phase(now, _deadline_hit)
            with _running("app_log_compress"):
                (
                    app_logs_compressed,
                    app_log_bytes_reclaimed,
                ) = await self._compress_app_log_phase(now, _deadline_hit)

            # The File source's `.processed` archive (owner ruling A2 of 2026-10-08, BACKLOG #1188): a
            # clear-text copy of every inbound payload, aged out on ARCHIVE time at the body window.
            # Each source does its own blocking I/O off the loop and under its own credential, re-reading
            # `_archive_halt` per file, so a large directory releases the pass like the compressor
            # does.
            if not _halt() and s.processed_archive_days > 0:
                with _running("processed_archives"):
                    processed_archives_deleted = await self._prune_processed_archives(
                        now - s.processed_archive_days * _SECONDS_PER_DAY, _archive_halt
                    )
                if archive_saw_demotion:
                    _demoted(seen=True)

            # Maintenance phases (WAL-checkpoint, then daily VACUUM). Their cadence markers advance ONLY
            # when the phase actually runs, so a phase SKIPPED by the cap stays due for the next pass
            # (#121). A running VACUUM is non-interruptible: the deadline is checked only BEFORE it is
            # dispatched.
            # The cadence reads `self._monotonic`, not `now` (see __init__).
            if not _halt() and self._wal_truncate_applies():
                wal_at = self._monotonic()
                if self._last_wal is None or wal_at - self._last_wal >= s.wal_checkpoint_seconds:
                    # `is False`: None is a backend with no -wal file, which `_wal_truncate_applies`
                    # skips.
                    with _running("wal_checkpoint"):
                        wal_left_untruncated = await self._store.wal_checkpoint() is False
                    # The marker advances either way, so a reader that pins the WAL costs writers one
                    # busy timeout per cadence rather than one per pass.
                    self._last_wal = wal_at
                    wal_checkpointed = True
                    if wal_left_untruncated:
                        # Vault BACKLOG #2619: a purged body can still sit in the -wal frames. Names the
                        # file and the cause only; no message content reaches this line.
                        log.warning(
                            "retention: the WAL truncate did not finish -- another connection (one of "
                            "the engine's own reads, a DR snapshot copy, or another process on this "
                            "store) still held %s-wal, so frames written before this pass, purged "
                            "bodies among them, stay in that file until a later truncate (the first "
                            "retention pass at least %gs from now)",
                            self._floor_path,
                            s.wal_checkpoint_seconds,
                        )

            if not _halt() and self._vacuum_due(now):
                with _running("vacuum"):
                    await self._store.vacuum()
                self._last_vacuum_day = self._day_key(now)
                vacuumed = True

            if not _halt():
                with _running("size_check"):
                    size_bytes, over_limit = await self._check_size()
        except (Exception, asyncio.CancelledError) as exc:
            await self._audit_interrupted(_tally(interrupted=True), exc)
            raise

        result = _tally()
        if result.did_work:
            await self._audit_shielded(result)
        return result

    def _start_audit(self, result: RetentionPass) -> asyncio.Task[None]:
        """Write ``result``'s audit row in its own task, tracked so :meth:`stop` can wait for it: a
        cancellation of the pass cancels only the wait for the row, never the write."""
        task = asyncio.create_task(self._audit_logged(result))
        self._audit_tasks.add(task)
        task.add_done_callback(self._audit_tasks.discard)
        task.add_done_callback(_retrieve_logged_result)
        return task

    async def _audit_logged(self, result: RetentionPass) -> None:
        try:
            await self._audit(result)
        except Exception as exc:
            # Logged here because a writer whose pass was cancelled is no longer waiting for it.
            log.error(
                "retention: a retention_purge audit row could not be written (%s)", safe_exc(exc)
            )
            raise

    async def _audit_shielded(self, result: RetentionPass) -> None:
        await asyncio.shield(self._start_audit(result))

    async def _audit_interrupted(self, partial: RetentionPass, cause: BaseException) -> None:
        """Write the row for a pass that ended partway (S07-44). A cancellation was delivered once,
        so this await still runs. Written when the pass did work or ended inside a phase that may
        have changed part of its set; a pass that ended in a phase that changes no data, with
        nothing else done, is logged instead, and one ``_SINGLE_TRANSACTION_PHASES`` exempts
        writes none. The wait is bounded by ``_AUDIT_WRITE_WAIT_SECONDS``, so a store that cannot
        take the write does not hold up the exception, and is skipped once :meth:`stop` has told
        the loop running the pass to stop, since that stop's own drain waits for the row within
        its one budget. A failed write is logged, so ``cause`` is what propagates."""
        phase = partial.interrupted_phase
        if not partial.did_work:
            if phase is None:
                return
            if phase in _PHASES_THAT_CHANGE_NO_DATA:
                log.warning(
                    "retention: a pass ended in its %s phase, which changes no data, with nothing "
                    "else done (%s); no audit row written",
                    phase,
                    safe_exc(cause),
                )
                return
            if phase in _SINGLE_TRANSACTION_PHASES and not isinstance(
                cause, asyncio.CancelledError
            ):
                return  # rolled back; `cause` goes on to the caller, which logs it
        task = self._start_audit(partial)
        if _loop_stopped():
            return
        try:
            done, _pending = await asyncio.wait({task}, timeout=_AUDIT_WRITE_WAIT_SECONDS)
        except asyncio.CancelledError:
            if not isinstance(cause, asyncio.CancelledError):
                # The cancellation replaces `cause`, and `_run` logs no CancelledError: name it here.
                log.error(
                    "retention: a pass that ended on an error was cancelled while writing its audit "
                    "row (%s)",
                    safe_exc(cause),
                )
            raise
        if not done:
            log.error(
                "retention: the audit row for a pass that ended partway had not been written after "
                "%gs; it may land later or not at all",
                _AUDIT_WRITE_WAIT_SECONDS,
            )

    async def _standby_pass(self, now: float, below_disk_floor: bool) -> RetentionPass:
        """A cluster standby's pass (BACKLOG #6526, S07-46): only the app-log sweep and compression,
        on this host's own ``[logging].log_dir``. Nothing in the shared store is read or purged, and
        the audit-log growth check is the leader's. A pass that deleted or compressed a file writes
        its audit row, as the leader's does, as does at least a capped pass, and one that ends partway
        writes it as :meth:`run_once` does."""
        pass_cap = _PassCap(self._monotonic, self._settings.max_pass_seconds)
        deleted = compressed = reclaimed = 0
        running_phase: str | None = "app_log_sweep"

        def _tally(*, interrupted: bool = False) -> RetentionPass:
            return RetentionPass(
                messages_purged=0,
                dead_purged=0,
                state_purged=0,
                conn_events_purged=0,
                wal_checkpointed=False,
                vacuumed=False,
                size_bytes=0,
                over_limit=False,
                app_logs_deleted=deleted,
                app_logs_compressed=compressed,
                app_log_bytes_reclaimed=reclaimed,
                capped=pass_cap.capped,
                below_disk_floor=below_disk_floor,
                interrupted=interrupted,
                interrupted_phase=running_phase if interrupted else None,
                standby=True,
            )

        try:
            deleted = await self._sweep_app_log_phase(now, pass_cap.hit)
            running_phase = None
            _raise_if_stopped()
            running_phase = "app_log_compress"
            compressed, reclaimed = await self._compress_app_log_phase(now, pass_cap.hit)
        except (Exception, asyncio.CancelledError) as exc:
            await self._audit_interrupted(_tally(interrupted=True), exc)
            raise
        result = _tally()
        if result.did_work:
            await self._audit_shielded(result)
        return result

    async def _sweep_app_log_phase(self, now: float, deadline_hit: Callable[[], bool]) -> int:
        """The #120 app-log sweep phase, host-local, so the leader and a standby both run it."""
        # Application log-file retention (#120): delete app-log FILES older than `app_log_days` from
        # `[logging].log_dir`. Filesystem I/O (scandir/stat/unlink is blocking), so it runs off the
        # event loop; metadata only (mtime) — file content is never read (no PHI). A no-op unless the
        # window and a log_dir are both set, so a deployment that doesn't use it is byte-identical.
        if deadline_hit() or self._settings.app_log_days <= 0 or not self._log_dir:
            return 0
        # The cap stays a before-the-phase check here; only a cancellation stops the worker early.
        return await _thread_until_cancelled(functools.partial(self._sweep_app_logs, now))

    async def _compress_app_log_phase(
        self, now: float, deadline_hit: Callable[[], bool]
    ) -> tuple[int, int]:
        """The #119 app-log compression phase, host-local like the sweep. Returns
        ``(compressed, bytes_reclaimed)``."""
        # Application log-file compression (#119): gzip app-log FILES older than `app_log_compress_days`
        # in place, free-space-prechecked and integrity-validated before the original is removed. Its own
        # phase beside the #120 sweep and deliberately AFTER it, so a file the delete window has already
        # aged out is never compressed first (wasted I/O on a file about to vanish). Blocking file I/O
        # (scandir/read/write/fsync/unlink), so it runs off the event loop exactly as the sweep does. It
        # is the one phase that takes the deadline INSIDE itself (`deadline_hit` is handed to the worker
        # and re-read PER FILE): it is a loop over an unbounded directory of up-to-64 MiB files, so
        # checking only before dispatch would let one dispatch run the whole directory and blow straight
        # through `max_pass_seconds` (#121). Per-file granularity is the natural interruption point — a
        # file is compressed whole or not at all, and whatever is left is simply still there next pass. A
        # no-op unless the window and a log_dir are both set → byte-identical for a deployment that's off.
        if deadline_hit() or self._settings.app_log_compress_days <= 0 or not self._log_dir:
            return 0, 0
        return await _thread_until_cancelled(
            functools.partial(self._compress_app_logs, now), deadline_hit
        )

    async def _prune_processed_archives(
        self, older_than: float, deadline_hit: Callable[[], bool]
    ) -> int:
        """Run each bound archive's sweep, and return how many files went in all (BACKLOG #1188).

        Every archive is handed the watch and ``.error`` directories of every inbound in the
        deployment, on every engine shard, and every File outbound's target directory, bound or not,
        so one whose archive directory overlaps any connection's drops, quarantine or deliveries
        deletes nothing. When a connection's directories cannot be read from its configuration the
        whole sweep is skipped: the guard is only as good as its list. A guarded directory whose
        identity cannot be read is read again by each archive under its own identity, and an archive
        that still cannot read it is not swept (:class:`ArchiveGuard`), nor is one whose opened
        directory has no readable identity. A directory two connections share is swept once. A
        fault in one connection is logged and the others still run, because a sweep must never stop
        the pass: a pass that raised here would skip its later phases, and its audit row would record
        an interrupted pass."""
        # Everything up to the sweep itself is contained: a fault here, a connector's declared
        # directories raising say, must not escape the pass and end it early.
        try:
            archives = list(self._archive_source()) if self._archive_source is not None else []
            if not any(a.archiving for a in archives):
                return 0
            guarded: list[Path] = [p for a in archives for p in (a.directory, a.error_dir)]
            if self._guard_source is not None:
                extra = self._guard_source()
                if extra is None:
                    log.warning(
                        "the [retention].processed_archive_days sweep deleted nothing this pass: a "
                        "connection's directories could not be resolved from its configuration, so "
                        "the sweep cannot tell what it must not reach"
                    )
                    return 0
                guarded.extend(extra)
            guarded.extend(self._engine_dirs)
            guarded.extend(self._engine_trees)
            protected, keys = await asyncio.to_thread(
                _archive_keys, guarded, [a.processed_dir for a in archives], self._engine_trees
            )
        except (OSError, ValueError, TypeError, KeyError) as exc:
            log.warning(
                "the [retention].processed_archive_days sweep deleted nothing this pass: the "
                "directories it must not reach could not be listed (%s)",
                safe_exc(exc),
            )
            return 0
        # Set when this task is cancelled, so a sweep already running on a worker thread stops at its
        # next file instead of deleting on after the engine has stopped.
        cancelled = threading.Event()

        def stop_hit() -> bool:
            return cancelled.is_set() or deadline_hit()

        swept: set[str] = set()
        deleted = 0
        for archive, key in zip(archives, keys, strict=True):
            if stop_hit():
                break
            # Only a source that archives is swept, and only it claims the directory, so a leave
            # source sharing a directory with a move source does not shadow it.
            if not archive.archiving or key in swept:
                continue
            try:
                outcome = await archive.prune_processed_archive(
                    older_than, protected=protected, deadline_hit=stop_hit
                )
            except asyncio.CancelledError:
                cancelled.set()
                raise
            except OSError as exc:
                # A file fault is the sweep's own to absorb; this catches what escapes it, the
                # alternate credential failing say, which the protocol raises as an OSError.
                # safe_exc, because an OSError renders its path and below the archive directory a
                # path is a partner's file name.
                log.warning(
                    "the [retention].processed_archive_days sweep failed for the archive directory "
                    "%s (%s); nothing more was deleted there this pass",
                    archive.processed_dir.name,
                    safe_exc(exc),
                )
                continue
            # Only a sweep that ran claims the directory: one refused (an unreadable guarded
            # directory under its identity, say) or failed leaves it to a sibling that shares it.
            if outcome is not None:
                swept.add(key)
                deleted += outcome
        return deleted

    # --- per-connection retention overrides (#34, ADR 0027) ------------------

    def _resolve_overrides(self) -> tuple[dict[str, int], dict[str, int]]:
        """Read the LIVE registry and return ``(messages_overrides, dead_letter_overrides)`` — the
        per-connection retention windows that DIFFER from "inherit the global window" (i.e. an explicit
        ``messages_days``/``dead_letter_days`` on the connection). ``None`` (inherit) connections are
        omitted so they fall back to the global cutoff; ``0`` (keep forever) and ``>0`` (days) are kept.

        Resolved each pass so a reload that changes an override takes effect on the next pass. Returns
        empty maps when no registry is wired (single global cutoff, byte-identical to the prior
        behaviour). The inbound map spans every engine shard (:meth:`Registry.inbound_messages_days`,
        BACKLOG #5889)."""
        registry = self._registry_source() if self._registry_source is not None else None
        if registry is None:
            return {}, {}
        messages = dict(registry.inbound_messages_days())
        dead = {
            oc.name: oc.dead_letter_days
            for oc in registry.outbound.values()
            if oc.dead_letter_days is not None
        }
        return messages, dead

    def _resolve_document_prune(
        self,
    ) -> tuple[dict[str, int], dict[str, int], dict[str, str]]:
        """Read the LIVE registry and return ``(windows, min_bytes, content_types)`` for the inbounds that
        set ``prune_documents_after`` (#47, ADR 0042): ``windows`` is ``{inbound -> prune_documents_after
        days}`` (only the connections that opt in — there is NO global default, so an inbound without the
        field never strips), ``min_bytes`` is ``{inbound -> threshold}`` (0 when the connection omits it),
        and ``content_types`` is ``{inbound -> declared content_type}`` used to label a bare-mfb64
        tombstone. Resolved each pass so a reload takes effect next pass; empty when no registry is
        wired."""
        registry = self._registry_source() if self._registry_source is not None else None
        if registry is None:
            return {}, {}, {}
        windows: dict[str, int] = {}
        min_bytes: dict[str, int] = {}
        content_types: dict[str, str] = {}
        for ic in registry.inbound.values():
            if ic.prune_documents_after is None:
                continue
            windows[ic.name] = ic.prune_documents_after
            min_bytes[ic.name] = ic.prune_documents_min_bytes or 0
            content_types[ic.name] = ic.content_type.value
        return windows, min_bytes, content_types

    @staticmethod
    def _global_cutoff(now: float, days: int) -> float:
        """The global ``older_than`` cutoff for a window of ``days`` (the ELSE branch of the per-connection
        CASE — connections with no override use this). ``days <= 0`` means the global default is
        keep-forever, so the global cutoff is ``-inf`` (nothing without an override is purged)."""
        return now - days * _SECONDS_PER_DAY if days > 0 else _KEEP_FOREVER

    @staticmethod
    def _cutoff_map(now: float, day_overrides: Mapping[str, int]) -> dict[str, float]:
        """Turn a ``{connection -> days}`` override map into the ``{connection -> cutoff}`` the store
        purge takes: ``0`` = keep forever (``-inf`` → never purged), ``>0`` = ``now - days``. Empty in,
        empty out (so the purge SQL stays byte-identical to the single global cutoff)."""
        return {
            name: (now - days * _SECONDS_PER_DAY if days > 0 else _KEEP_FOREVER)
            for name, days in day_overrides.items()
        }

    def _disk_floor_applies(self) -> bool:
        """The low-disk floor (BACKLOG #290) is on AND this is a file-backed SQLite store
        (:func:`sqlite_store_file` decides the second half)."""
        return self._settings.min_free_disk_mb > 0 and self._floor_path is not None

    def _wal_truncate_applies(self) -> bool:
        """The WAL truncate is on AND this store has a ``-wal`` file to truncate, which is the same
        file-backed SQLite test as the disk floor's. It ships ON (vault BACKLOG #2619), so both
        ``enabled`` and the pass ask this, and neither runs it where ``wal_checkpoint`` is a no-op."""
        return self._settings.wal_checkpoint_seconds > 0 and self._floor_path is not None

    async def _check_disk_floor(self) -> bool:
        """Log a WARNING when free space on the SQLite store's volume is below
        ``min_free_disk_mb``. Returns True only for a measured shortfall.

        Advisory, by scope: this check warns and changes nothing, and never drops, NAKs or deletes a
        message. The startup refusal lives in ``serve``, and the runtime intake pause on the same
        floor lives in ``pipeline/intake_bound.py`` (slice 2), which measures far more often than
        a retention pass runs. A failed
        probe logs at DEBUG and returns False, because an unmeasured disk is not a low one.

        This check runs before every purge in the pass, so it must never be what stops one. It
        catches ``Exception`` on purpose, logs it, and lets the pass go on: an advisory probe that
        raised would otherwise fail every pass and PHI bodies would never be purged."""
        if not self._disk_floor_applies() or self._floor_path is None:
            return False
        try:
            reading = await asyncio.to_thread(
                read_disk_floor, self._floor_path, self._settings.min_free_disk_mb
            )
        except Exception:
            log.warning("low-disk floor probe failed; the pass continues", exc_info=True)
            return False
        if reading is None or not reading.below:
            return False
        log.warning(
            "low disk: %s MiB free on the volume holding the SQLite store (%s), below the "
            "[retention].min_free_disk_mb floor of %d MiB. A restart will be REFUSED until space is "
            "freed. Free disk space or move the store to a larger volume. Do not reach for VACUUM "
            "here: it needs free space close to the store's own size to run.",
            reading.free_mib,
            reading.probed,
            reading.floor_mib,
        )
        return True

    async def _check_size(self) -> tuple[int, bool]:
        """Return ``(db_size_bytes, over_limit)``, emitting the advisory alert when over. Skips the
        size query entirely when ``max_db_mb`` is off."""
        if self._settings.max_db_mb <= 0:
            return 0, False
        size_bytes = (await self._store.db_status()).size_bytes
        limit_bytes = self._settings.max_db_mb * _BYTES_PER_MB
        over = size_bytes > limit_bytes
        if over:
            # The sink never raises (contract), but be defensive — an alert failure must not abort
            # the purge pass that produced it.
            try:
                self._alert_sink.storage_threshold(
                    self._store.path, size_bytes=size_bytes, limit_bytes=limit_bytes
                )
            except Exception:
                log.warning("storage_threshold alert sink failed", exc_info=True)
        return size_bytes, over

    async def _check_audit_growth(self) -> bool:
        """Log a WARNING when ``audit_log`` holds more rows than ``audit_log_warn_rows`` (BACKLOG
        #1421). Returns True only for a measured count above the threshold.

        Advisory, by scope, like the disk floor: it changes nothing and writes no audit row. The
        line carries two numbers and setting names only, never a row's contents.

        The measure is the newest row's sequence number, read through the store's own
        ``audit_anchor``: one awaited seek on the UNIQUE ``seq`` index, so it never blocks the event
        loop and, on an intact chain, costs the same at any table size. A full ``COUNT(*)`` would
        scan a table that only grows, every pass. (SQLite's ``audit_anchor`` falls back to a full
        count when the newest ``seq`` is not a positive integer.) On an intact chain the newest
        ``seq`` IS the row count. On a chain someone renumbered, it can read high or low on any
        backend. The warning is a size signal, not a tamper control; the audit verify is what
        reports a renumbered row.

        A read that fails logs a WARNING with its reason and returns False, so a backend that
        cannot answer degrades visibly rather than silently. It never stops the pass."""
        threshold = self._settings.audit_log_warn_rows
        if threshold <= 0:
            return False
        try:
            rows, _head = await self._store.audit_anchor()
        except Exception:
            log.warning(
                "audit_log growth check skipped: reading the newest audit row failed; the pass "
                "continues",
                exc_info=True,
            )
            return False
        if rows <= threshold:
            return False
        log.warning(
            "audit_log holds about %d rows (its newest sequence number), above the "
            "[retention].audit_log_warn_rows threshold of %d. "
            "Nothing prunes audit_log: [retention].audit_days is not enforced, and no engine "
            "feature deletes audit rows. Plan storage for its growth, then raise the threshold to "
            "acknowledge this size.",
            rows,
            threshold,
        )
        return True

    def _sweep_app_logs(self, now: float, stop_hit: Callable[[], bool] = lambda: False) -> int:
        """Delete application-log FILES older than ``app_log_days`` from ``[logging].log_dir`` — one
        level, non-recursive, only ``.log``/``.txt`` regular files (the same notion of "app-log file"
        the ``/status`` metering and support-bundle tail use), by **mtime** so the currently-written
        file is never eligible. **Metadata only** — file content is never read (no PHI). Blocking
        (``scandir``/``stat``/``unlink``), so the caller runs it off the event loop. Never raises: a
        locked/vanished/permission-denied entry is skipped, not fatal — a log-retention hiccup must
        never take a purge pass down. Returns the number of files deleted.

        When (and ONLY when) compression is enabled (#119) the sweep also covers the archives it
        produces — ``*.log.gz``/``*.txt.gz`` — on the same window, so compressing a file does not make
        it immortal (the archive inherits the source's mtime, so it ages out on the original's clock).
        It covers a claimed archive left behind by :func:`_drop_redundant_archive` too (#6805; the
        names and the clock are on :func:`_is_app_log_name`).
        With ``app_log_compress_days = 0`` the eligible set is exactly the pre-#119 one, so a deployment
        that hasn't opted into compression is byte-identical."""
        days = self._settings.app_log_days
        if days <= 0 or not self._log_dir:
            return 0
        include_archives = self._settings.app_log_compress_days > 0
        cutoff = now - days * _SECONDS_PER_DAY
        deleted = 0
        try:
            entries = list(os.scandir(self._log_dir))
        except OSError:
            return 0  # directory absent/unreadable → nothing swept, never raise
        for entry in entries:
            if stop_hit():
                break  # the pass was cancelled: stop at the next file, not after the directory
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                if not _is_app_log_name(entry.name, include_archives=include_archives):
                    continue
                if entry.stat(follow_symlinks=False).st_mtime >= cutoff:
                    continue
                os.remove(entry.path)
                deleted += 1
            except OSError:
                continue  # locked/vanished/denied file → skip, never fatal
        return deleted

    # --- application log-file compression (#119) -----------------------------

    def _compress_app_logs(self, now: float, deadline_hit: Callable[[], bool]) -> tuple[int, int]:
        """Gzip application-log FILES older than ``app_log_compress_days`` in ``[logging].log_dir`` to
        ``<name>.gz``, returning ``(files_compressed, bytes_reclaimed)``.

        Same file selection as the #120 sweep (one level, non-recursive, ``.log``/``.txt`` regular files,
        by **mtime** so the currently-written file is never eligible) — archives are never re-compressed.
        Five safety rules, in order, per file:

        0. **Stop at the pass deadline.** ``deadline_hit`` (the caller's ``max_pass_seconds`` latch, #121)
           is re-read **before every file**, so the phase releases the pass between files instead of
           running the whole directory in one uninterruptible call. Whatever is left is untouched and is
           simply picked up by the next pass — nothing is dropped, only deferred.
        1. **Never clobber.** An existing ``<name>.gz`` means the file is already archived, or at least
           that a crash landed the archive but not the unlink, or that the source changed after its
           archive was placed (#6805); it is skipped, and only an ``app_log_days`` delete window, where
           one is set, cleans up.
        2. **Free-space precheck.** ``shutil.disk_usage`` must show room for the source *plus* its
           archive plus a margin, else the file is skipped and logged — a maintenance pass must never be
           what fills the volume. Re-read per file, since each compression changes what is free.
        3. **Never grow.** An archive that is not SMALLER than its source (an empty or already-compressed
           log) is discarded and the original left alone — compressing must not cost disk.
        4. **Integrity validation before deletion.** The archive is staged to an exclusively created,
           unpredictably named temp file (:meth:`_stage_archive`), ``fsync``ed, validated, renamed into
           place, and then **re-validated at ``dest``**. Removing the original takes that check, on the
           bytes actually sitting at ``dest``, and a re-check that the source path is still the same
           file (device, file id, size, mtime, ctime) it was read from, so a log appended to or rotated
           during compression is kept in most cases (#6805; :func:`_source_change` names at least the
           window that remains). Any failure leaves the original **untouched** and is logged
           (:meth:`_compress_one`).

        The archive inherits the source's mtime so the ``app_log_days`` delete window keeps applying to
        it. Blocking I/O throughout, so the caller runs it off the event loop. Never raises — a
        locked/vanished/denied entry is skipped, not fatal. Names, counts and sizes are logged; file
        **content** never is (an application log is itself operational text, PHI.md §7)."""
        days = self._settings.app_log_compress_days
        if days <= 0 or not self._log_dir:
            return 0, 0
        cutoff = now - days * _SECONDS_PER_DAY
        compressed = 0
        reclaimed = 0
        try:
            entries = list(os.scandir(self._log_dir))
        except OSError:
            return 0, 0  # directory absent/unreadable → nothing compressed, never raise
        for entry in entries:
            # Per-file, not per-phase: one dispatch must not be able to overrun the whole pass budget.
            # Checked BETWEEN files, so a file already being compressed always finishes (the same
            # "never interrupt a started unit of work" rule the sibling phases follow).
            if deadline_hit():
                log.info(
                    "app-log compression stopped at the pass cap or an engine stop after %d file(s); "
                    "the rest are left for the next pass",
                    compressed,
                )
                break
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                # include_archives=False: an existing `.gz` is the OUTPUT of this phase, never its input.
                if not _is_app_log_name(entry.name, include_archives=False):
                    continue
                st = entry.stat(follow_symlinks=False)
                if st.st_mtime >= cutoff:
                    continue
                dest = entry.path + _GZ_SUFFIX
                if os.path.exists(dest):
                    continue  # already archived — never clobber an existing artifact
                if st.st_size > _COMPRESS_MAX_FILE_BYTES:
                    log.warning(
                        "app-log compression skipped %r: %d bytes exceeds the %d-byte per-file ceiling",
                        entry.name,
                        st.st_size,
                        _COMPRESS_MAX_FILE_BYTES,
                    )
                    continue
                if not self._has_free_space(st.st_size, name=entry.name):
                    continue
                saved = self._compress_one(entry.path, dest, atime=st.st_atime, mtime=st.st_mtime)
                if saved is None:
                    # Not compressed by this call. The source path may still hold the original, or
                    # may now hold changed content or nothing at all (see `_compress_one`).
                    continue
                compressed += 1
                reclaimed += saved
            except OSError:
                # Locked/vanished/denied entry → skip, never fatal. Name only, never content.
                log.warning("app-log compression skipped %r (filesystem error)", entry.name)
                continue
        return compressed, reclaimed

    def _has_free_space(self, size: int, *, name: str) -> bool:
        """Free-space precheck: is there room to write ``size``'s archive **beside** it?

        Peak cost is the source plus the archive, and gzip's worst case (incompressible input) is
        marginally larger than the source — so the bar is ``size + max(10% of size, 1 MiB)``. Under it,
        the file is skipped and logged rather than attempted, so compression can never be what fills the
        volume. A free-space read that itself fails is treated as "no room" (fail closed)."""
        assert self._log_dir is not None  # guarded by the caller
        try:
            free = self._free_bytes(self._log_dir)
        except OSError:
            log.warning("app-log compression skipped %r: free space could not be read", name)
            return False
        required = size + max(size // _COMPRESS_FREE_MARGIN_RATIO, _COMPRESS_FREE_MIN_MARGIN_BYTES)
        if free < required:
            log.warning(
                "app-log compression skipped %r: %d bytes free on %r, %d required for a %d-byte source",
                name,
                free,
                self._log_dir,
                required,
                size,
            )
            return False
        return True

    @staticmethod
    def _free_bytes(path: str) -> int:
        """Bytes free on the filesystem holding ``path``. Split out from :meth:`_has_free_space` so the
        precheck is directly testable — a full volume cannot otherwise be simulated."""
        return shutil.disk_usage(path).free

    def _compress_one(self, source: str, dest: str, *, atime: float, mtime: float) -> int | None:
        """Gzip ``source`` → ``dest``, **validating the bytes at ``dest`` before removing the original**.

        Returns the bytes reclaimed, or ``None`` when this call did not remove the original (read/codec/
        write failure, a failed integrity check, an archive that would not be SMALLER than the source, or
        a source that changed or vanished during compression; in the vanished case it is already gone).

        **What authorizes the unlink** is a read-back of ``dest`` *after* the rename — never a check
        against the staging path. Validating the staged file and then renaming "whatever is at that
        path" is a TOCTOU: any process that rewrites the staging file inside that window puts UNVALIDATED
        bytes at ``dest`` while the source is unlinked anyway, which destroys the only copy of the log and
        reports it as a success. Both checks are kept — the staged one so an unvalidated artifact is never
        placed at ``dest`` at all, the ``dest`` one because it is the only one that describes the bytes
        the delete is traded for. (The staging file itself is unpredictable and exclusively created, see
        :meth:`_stage_archive`, so that window is closed from the other side too.)

        The ``dest`` read-back proves the archive holds the bytes read at the START; it says nothing
        about the source since. So the source is pinned at the read (two ``fstat`` calls on the read
        handle must agree with each other, with the bytes read and with the scan's mtime), and
        :func:`_source_change` is checked again before the archive is placed and before the unlink. A
        source appended to, truncated or replaced at the same path during compression is kept (#6805);
        :func:`_source_change` names what that still misses."""
        name = os.path.basename(source)
        try:
            fd = os.open(source, _SOURCE_OPEN_FLAGS)
        except OSError:
            log.warning("app-log compression skipped %r: unreadable", name)
            return None
        try:
            # The identity of the file these bytes come from, taken on the SAME descriptor before and
            # after the read, so a change during the read is caught here and the checks below can
            # refuse a path that no longer holds exactly these bytes (#6805). Checked on the raw
            # descriptor first: `os.fdopen` raises on a directory without closing the descriptor.
            try:
                before_st = os.fstat(fd)
                aged_file = stat.S_ISREG(before_st.st_mode) and before_st.st_mtime == mtime
                if aged_file and hasattr(os, "O_NONBLOCK"):
                    # Opened O_NONBLOCK only so the open cannot hang; a buffered read of a
                    # non-blocking descriptor may return None, so blocking mode is restored first.
                    os.set_blocking(fd, True)
            except OSError:
                os.close(fd)
                raise
            if not aged_file:
                # Not the regular file the scan aged: rotated in after the scan, or (Windows) the
                # directory entry's mtime is stale because a writer still has it open. Read nothing.
                os.close(fd)
                log.debug("app-log compression skipped %r: not the file the scan aged", name)
                return None
            with os.fdopen(fd, "rb") as fh:
                # Bounded by the size pinned above: a longer read is a change and is refused below.
                data = fh.read(before_st.st_size + 1)
                read_st = os.fstat(fh.fileno())
        except OSError:
            log.warning("app-log compression skipped %r: unreadable", name)
            return None
        if not _same_file_state(before_st, read_st) or read_st.st_size != len(data):
            # Changed during the read. Nothing is staged, so nothing is left behind; the next pass
            # looks again.
            log.warning("app-log compression skipped %r: it changed while being read", name)
            return None
        try:
            blob = gzip_compress(data)
        except CompressionError:
            # Message names the codec only — never content (parsing/compression.py contract).
            log.warning("app-log compression failed for %r: codec error; original kept", name)
            return None
        if len(blob) >= len(data):
            # Compressing would COST disk, not save it — an empty log (NSSM's `service.err.log` is
            # routinely 0 bytes, and a gzip member still carries an 18-byte header/trailer) or already-
            # compressed content. Leave the original alone rather than swap it for something bigger.
            # Re-evaluated each pass, which is the right trade: a few reads beat a permanent marker file.
            log.debug("app-log compression skipped %r: the archive would not be smaller", name)
            return None
        tmp = self._stage_archive(blob, os.path.dirname(source) or ".", name=name)
        if tmp is None:
            return None
        if not _verify_archive(tmp, data, name=name):
            _unlink_quietly(tmp)
            return None
        change = _source_change(source, read_st)
        if change is not None:
            # Checked before placing too, so a source that changed while it was compressed leaves no
            # stale partial archive at `dest` to block its later compression, and a source a peer
            # compressor already archived AND removed is not followed by a rename over that archive.
            log.warning(
                "app-log compression skipped %r: the source %s during compression; nothing placed",
                name,
                change,
            )
            _unlink_quietly(tmp)
            return None
        if os.path.exists(dest):
            # A peer compressor placed `<name>.gz` since the scan. Never rename over it: it may be the
            # only copy of a longer read whose source the peer is about to remove. This narrows, and
            # does not close, the window before the rename below.
            log.warning("app-log compression skipped %r: an archive appeared meanwhile", name)
            _unlink_quietly(tmp)
            return None
        try:
            # Inherit the source's timestamps so the `app_log_days` delete window still ages the archive
            # out on the ORIGINAL file's clock (compressing a log must not reset its retention clock).
            os.utime(tmp, (atime, mtime))
            os.replace(tmp, dest)
        except OSError:
            log.warning(
                "app-log compression failed for %r: archive rename failed; original kept", name
            )
            _unlink_quietly(tmp)
            return None
        if not _verify_archive(dest, data, name=name):
            # One of the two gates on the unlink below (with `_source_change`), and it did not pass:
            # whatever is at `dest` is not this log. Keep the original (it is still the only good
            # copy) and do not count it as compressed.
            # The artifact at `dest` is deliberately NOT removed: under a concurrent compressor it may be
            # a VALID archive of a longer read of the same log whose source is already gone, and deleting
            # that would be the very data loss this check exists to prevent. It is inert (the next pass
            # skips a source whose `<name>.gz` exists), and only an `app_log_days` window, where one
            # is set, ages it out.
            log.warning(
                "app-log %r: the archive did not validate AFTER being renamed into place; the original "
                "is kept and NOT counted as compressed. The unvalidated %r needs an operator's review.",
                name,
                os.path.basename(dest),
            )
            return None
        change = _source_change(source, read_st)
        if change is not None:
            # The archive validates against the bytes read at the START; the source path no longer
            # matches them (appended to, a metadata-only change, truncated, replaced by a rotation, or
            # gone). Removing it would destroy whatever was written since, so the path is left alone.
            # Not counted as compressed. A `<name>.gz` left here would make every later pass skip this
            # path silently, forever with no `app_log_days` window, so the archive THIS pass placed is
            # removed whenever the kept source still holds every archived byte (same file, `data` as
            # its prefix): it is then redundant and the next pass retries. Otherwise it is kept,
            # because under a replace it may be the only copy of the old content.
            if _drop_redundant_archive(source, read_st, data, dest, name=name):
                log.warning(
                    "app-log %r: the source %s after its archive was placed; the source is kept "
                    "and holds every archived byte, so the archive is redundant and was removed or "
                    "could not be found to remove; the next pass retries",
                    name,
                    change,
                )
                return None
            log.warning(
                "app-log %r: the source %s after its archive was placed; the source path is left "
                "alone and NOT counted as compressed. The bytes read before that may remain in the "
                "source, at %r, or under a claim name logged above.",
                name,
                change,
                os.path.basename(dest),
            )
            return None
        try:
            os.remove(source)
        except OSError:
            # The VALIDATED archive is in place but the original could not be removed (locked). Not
            # counted as compressed — the next pass sees `dest` and skips, and the delete window (or the
            # operator) clears the leftover. Both the archive and the original remain here.
            log.warning("app-log %r archived but the original could not be removed", name)
            return None
        # Measured against the bytes actually archived, the figure that describes what happened.
        return len(data) - len(blob)

    @staticmethod
    def _stage_archive(blob: bytes, directory: str, *, name: str) -> str | None:
        """Write ``blob`` to a **freshly created, unpredictably named** staging file in ``directory``
        (the log directory, so the later :func:`os.replace` is a same-filesystem atomic rename), returning
        its path — or ``None``, with the failure logged, if it could not be written.

        :func:`tempfile.mkstemp` is what makes this safe, and both halves matter:

        * **Unpredictable.** The old name was ``<source>.gz.mftmp`` — derived from the source, so every
          process (and anything else able to write to the log directory) could compute it in advance and
          plant or rewrite the file the compressor is about to validate-and-rename. Predictability is
          what turns the rename into an attack primitive rather than a race one has to win blind.
        * **Exclusive.** ``mkstemp`` opens ``O_CREAT|O_EXCL`` (plus ``O_NOFOLLOW`` where the platform has
          it), so it **creates** the file or fails — it never truncates an existing file and never follows
          a symlink to one (CWE-59/CWE-377). Plain ``open(path, "wb")`` does both, which made the staging
          write an arbitrary-file-overwrite: a symlink at the predictable path pointed the compressor's
          write at any file the service account could touch, including other logs.

        This also makes concurrent compressors safe by construction — every shard runs its own
        RetentionRunner over the SAME ``[logging].log_dir`` (each shard is its own leader under
        ``NullCoordinator``), so a shared staging path was guaranteed collision, not a rare race."""
        fd = -1
        tmp = ""
        try:
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=_GZ_TMP_PREFIX, suffix=_GZ_TMP_SUFFIX)
            with os.fdopen(fd, "wb") as out:
                fd = -1  # ownership handed to the file object; don't double-close in the handler
                out.write(blob)
                out.flush()
                # fsync so the validation reads what actually reached the disk, not the page cache —
                # the whole point is to prove the artifact before deleting the only other copy.
                os.fsync(out.fileno())
        except OSError:
            log.warning(
                "app-log compression failed for %r: archive write failed; original kept", name
            )
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    log.debug("could not close the staging descriptor for %r", name, exc_info=True)
            if tmp:
                _unlink_quietly(tmp)
            return None
        return tmp

    async def _audit(self, result: RetentionPass) -> None:
        """Append one audit row recording the cutoffs + counts (no message content — no PHI)."""
        detail = json.dumps(
            {
                "messages_days": self._settings.messages_days,
                "messages_purged": result.messages_purged,
                "dead_letter_days": self._settings.dead_letter_days,
                "dead_purged": result.dead_purged,
                "dead_errors_cleared": result.dead_errors_cleared,
                "state_max_age_days": self._settings.state_max_age_days,
                "state_purged": result.state_purged,
                "connection_event_retention_hours": self._settings.connection_event_retention_hours,
                "conn_events_purged": result.conn_events_purged,
                # Per-connection retention overrides applied this pass (#34, ADR 0027): the per-connection
                # cutoffs (connection name -> days; 0 = keep forever) alongside the global windows + the
                # aggregate purged counts above. Metadata only — never any message content (no PHI).
                # Empty in a global-only deployment (the audit detail stays byte-identical there).
                "messages_overrides": dict(result.messages_overrides),
                "dead_letter_overrides": dict(result.dead_letter_overrides),
                # Embedded-document pruning this pass (#47, ADR 0042): the per-connection windows
                # (inbound -> prune_documents_after days) + aggregate counts/bytes. Metadata only — no
                # message content. Empty when no connection sets a document-pruning window.
                "document_prune_overrides": dict(result.document_prune_overrides),
                "documents_messages_stripped": result.documents_messages_stripped,
                "documents_stripped": result.documents_stripped,
                "documents_bytes_reclaimed": result.documents_bytes_reclaimed,
                "documents_strip_ended_early": result.documents_strip_ended_early,
                "documents_strip_read_failed": result.documents_strip_read_failed,
                "documents_strip_write_failed": result.documents_strip_write_failed,
                # Resolved operator-alert instances pruned this pass (#56, ADR 0044) — metadata only.
                "alert_instances_purged": result.alert_instances_purged,
                # Application log files deleted this pass (#120) + the window — metadata only, no PHI.
                "app_log_days": self._settings.app_log_days,
                "app_logs_deleted": result.app_logs_deleted,
                # Application log files gzipped this pass (#119) + the window + bytes reclaimed. Counts
                # and sizes only — never a file name and never any file content (no PHI).
                "app_log_compress_days": self._settings.app_log_compress_days,
                "app_logs_compressed": result.app_logs_compressed,
                "app_log_bytes_reclaimed": result.app_log_bytes_reclaimed,
                # Saved-search presets DELETEd this pass (ADR 0136, ASVS 14.2.7) + the window. The COUNT
                # only — a preset's criteria is a PHI-shaped needle and never enters the audit detail.
                "search_preset_days": self._settings.search_preset_days,
                "search_presets_purged": result.search_presets_purged,
                # Orphaned reference-snapshot ROWS deleted (ADR 0006, ASVS 14.2.7) + the window. The
                # COUNT only — never a set name, key or value. A set name is operator-authored config
                # rather than PHI, but the ROWS are PL-2 and naming the set in a durable audit row would
                # narrow which patient cohort was dropped; the count is what an assessor needs.
                "reference_snapshot_days": self._settings.reference_snapshot_days,
                "reference_snapshots_purged": result.reference_snapshots_purged,
                # `.processed` archive copies deleted (BACKLOG #1188) + the window. The COUNT only:
                # never a file name, which can carry an identifier, nor a connection name.
                "processed_archive_days": self._settings.processed_archive_days,
                "processed_archives_deleted": result.processed_archives_deleted,
                # Between-phase duration cap (#121, ADR 0137): the configured ceiling + whether THIS pass
                # hit it and skipped its remaining phases. Timing metadata only — no PHI.
                "max_pass_seconds": self._settings.max_pass_seconds,
                "capped": result.capped,
                # How the pass ended (BACKLOG #6526): partway on an exception or a stop, after a
                # leadership loss, or on a standby that only touched its own app logs.
                "interrupted": result.interrupted,
                "interrupted_phase": result.interrupted_phase,
                "leadership_lost": result.leadership_lost,
                "standby": result.standby,
                "vacuumed": result.vacuumed,
                # Vault BACKLOG #2619: a purge this row records may still sit in the -wal frames.
                # null when this pass ran no truncate, so "never tried" cannot read as "truncated".
                "wal_left_untruncated": (
                    result.wal_left_untruncated if result.wal_checkpointed else None
                ),
                "db_size_bytes": result.size_bytes,
                "max_db_mb": self._settings.max_db_mb,
                "over_limit": result.over_limit,
            },
            sort_keys=True,
        )
        await self._store.record_audit("retention_purge", actor="system", detail=detail)

    # --- daily VACUUM schedule ----------------------------------------------

    def _vacuum_due(self, now: float) -> bool:
        """True when a daily VACUUM time is configured, the local clock has reached it, and we haven't
        already vacuumed today. (At-most-once per local day; a late start that day still catches up.)"""
        target = self._settings.vacuum_time()
        if target is None:
            return False
        lt = time.localtime(now)
        reached = (lt.tm_hour, lt.tm_min) >= target
        return reached and self._last_vacuum_day != self._day_key(now)

    @staticmethod
    def _day_key(now: float) -> str:
        lt = time.localtime(now)
        return f"{lt.tm_year:04d}-{lt.tm_mon:02d}-{lt.tm_mday:02d}"


def _archive_keys(
    guarded: Iterable[Path], archives: Sequence[Path], trees: Iterable[Path] = ()
) -> tuple[ArchiveGuard, list[str]]:
    """Build the guard over the protected directories once per pass, and each archive directory's
    key for sweeping a shared directory once (BACKLOG #1188). Blocking: run off the loop.

    The once-only key is resolved but NOT case-folded: two directories that differ only in case on a
    case-sensitive volume are two archives, and folding would leave the second unswept."""
    keys = []
    for path in archives:
        try:
            keys.append(os.path.normcase(os.path.realpath(path)))
        except (OSError, ValueError):
            keys.append(os.path.normcase(os.path.abspath(path)))
    tree_keys = set()
    for tree in trees:
        try:
            tree_keys.add(archive_dir_key(tree))
        except (OSError, ValueError):
            tree_keys.add(os.path.normcase(os.path.abspath(tree)).casefold())
    guard = build_archive_guard(guarded)
    return replace(guard, trees=frozenset(tree_keys)), keys
