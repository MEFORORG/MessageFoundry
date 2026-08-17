# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""File transport: directory destination + directory-polling source.

**Destination** writes each payload to a file in a directory. The filename may contain
``{HL7-path}`` placeholders (e.g. ``{MSH-10}.hl7``) resolved by peeking the payload, so
archived files are named by control id / message type. Writes are atomic (write to a
temp name, then ``rename``) so a reader watching the directory never sees a partial file.

**Source** polls a directory for files, hands each to the pipeline handler, then moves the
file into a ``.processed`` subdirectory (or ``.error`` if the handler raised). Files have
no reply channel, so the handler's return value is ignored.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any, TypeVar

from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    Source,
    WindowsCredential,
)
from messagefoundry.parsing.compression import CompressionError, gzip_compress, gzip_decompress
from messagefoundry.parsing.peek import HL7PeekError, Peek
from messagefoundry.parsing.sniff import _content_matches_declared, _looks_like_hl7
from messagefoundry.parsing.split import split_batch
from messagefoundry.transports import wincred
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    DestinationStartupError,
    InboundHandler,
    SourceConnector,
    SourceStartupError,
    encode_wire_body,
    register_destination,
    register_source,
)

__all__ = [
    "FileDestination",
    "FileSource",
    "render_filename",
    "DEFAULT_MAX_FILE_BYTES",
    "LEAVE_SEEN_CACHE_MAX",
    # Re-exported from parsing.sniff (ASVS 5.2.2) so remotefile.py + existing tests import them here.
    "_content_matches_declared",
    "_looks_like_hl7",
    "DEFAULT_MAX_DECOMPRESSED_BYTES",
]

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# Cap a single inbound file read so a multi-GB drop can't OOM the engine (DoS guard). A
# falsy value (None/0) in settings disables the cap; see docs/CONNECTIONS.md.
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB — matches the MLLP frame cap

# Cap the leave-in-place (#142) in-memory dedup fast-path so it can't outgrow the durable
# processed_files ledger's count cap (PROCESSED_FILE_LEDGER_KEEP_MAX in pipeline/wiring_runner.py). It
# is only a cache in front of the AUTHORITATIVE, bounded durable read: an evicted key falls through to
# ledger.is_processed(), so eviction never causes a false re-ingest. Shared by RemoteFileSource.
LEAVE_SEEN_CACHE_MAX = 100_000

# When `decompress=` is set, this bounds the *decompressed* output (ADR 0123): `max_file_bytes` only
# caps the COMPRESSED input (`st_size`), so a small gzip can expand to gigabytes (a decompression bomb).
# Because the batch split, the sniff, and every downstream stage run on the decompressed bytes, bounding
# the decompressed output also bounds post-split expansion. A falsy value (None/0) disables the cap.
DEFAULT_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024  # 64 MiB

# Compression algorithms the FILE connector supports on its compress=/decompress= option. The connector
# is restricted to single-stream gzip (ADR 0123); multi-entry zip / raw deflate stay Handler-composed
# via messagefoundry.parsing.compression.
_SUPPORTED_COMPRESSION = frozenset({"gzip"})

_PLACEHOLDER = re.compile(r"\{([A-Z][A-Z0-9]{2}-\d+(?:\.\d+){0,2})\}")
# Strip characters that are unsafe in filenames on Windows and POSIX alike (path separators
# included, so a resolved value can never introduce a directory component).
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
# Windows reserved device names (case-insensitive, optionally with an extension) — never usable.
_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def render_filename(template: str, payload: str, *, fallback: str) -> str:
    """Resolve ``{HL7-path}`` placeholders in ``template`` against ``payload``, producing a single
    safe filename (never a path).

    Unresolvable placeholders (missing field, or an unparseable payload) fall back to ``fallback``
    so a delivery never fails merely because a name couldn't be built. The result is constrained to
    one path component: unsafe characters are stripped, leading dots removed, and ``.``/``..``/empty
    or a reserved device name falls back — so an attacker-controlled field can't write outside the
    target directory or shadow ``.processed``/``.error`` (FILE-1)."""
    try:
        peek: Peek | None = Peek.parse(payload)
    except HL7PeekError:
        peek = None

    def repl(match: re.Match[str]) -> str:
        value = peek.field(match.group(1)) if peek else None
        return _sanitize(value) if value else fallback

    name = _sanitize(_PLACEHOLDER.sub(repl, template))
    stem = name.split(".", 1)[0].upper()
    if not name or name in (".", "..") or stem in _RESERVED:
        return fallback
    return name


def _sanitize(value: str) -> str:
    """Reduce ``value`` to a safe single-component filename: drop unsafe chars and leading dots
    (which would create hidden files or ``.``/``..`` traversal)."""
    return _UNSAFE.sub("_", value).lstrip(".")


def _validate_compression(value: object, knob: str) -> str | None:
    """Validate a FILE ``compress``/``decompress`` setting: ``None`` (off) or ``"gzip"`` only.

    The connector is restricted to single-stream gzip (ADR 0123) — a ``zip``/``deflate`` value is
    rejected at construction with a clear error rather than silently ignored, so a config typo or an
    unsupported request is caught at wiring / ``messagefoundry check``. Multi-entry zip and raw deflate
    are Handler-composed via :mod:`messagefoundry.parsing.compression`."""
    if value is None:
        return None
    if isinstance(value, str) and value in _SUPPORTED_COMPRESSION:
        return value
    supported = ", ".join(sorted(_SUPPORTED_COMPRESSION))
    raise ValueError(
        f"file connector {knob}={value!r} is not supported (allowed: {supported}, or omit for none)"
    )


def _probe_dir_writable(directory: Path) -> None:
    """Reachability probe shared by the FILE connectors: ensure ``directory`` exists and accepts a
    write — a destination writes messages there and a source moves processed files into its subdirs,
    so writability is the meaningful check for both. Creates and removes a temp file; raises ``OSError``
    if the directory is missing or unwritable."""
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".probe")
    os.close(fd)
    os.unlink(tmp)


def _probe_dir_startup(directory: Path, *, require_write: bool) -> None:
    """The **no-mkdir** sibling of :func:`_probe_dir_writable` for the opt-in at-start check (#114).

    Unlike ``_probe_dir_writable`` — whose first line ``mkdir(parents=True, exist_ok=True)`` **creates**
    a missing directory before probing, so reusing it verbatim would silently fabricate a merely-missing
    dir and PASS — this **never creates** anything: a missing path (or a non-directory) raises
    ``FileNotFoundError``, so ``validate_directory=true`` reports the connection ``failed`` at start.

    ``require_write`` adds a temp-file write probe (a ``move``/``delete`` source moves processed files
    into its subdirs, so it needs write); a ``leave``-in-place source (#142) never writes to the poll
    dir, so it only needs to **list** (read) — letting a genuinely read-only share validate cleanly.
    Raises ``OSError`` on any failure (the caller wraps it into :class:`SourceStartupError`)."""
    if not directory.is_dir():
        raise FileNotFoundError(f"{directory} does not exist or is not a directory")
    if require_write:
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".probe")
        os.close(fd)
        os.unlink(tmp)
    else:
        os.listdir(directory)  # readability probe — no write on a read-only share


def _build_credential_context(settings: Mapping[str, Any]) -> wincred.CredentialContext | None:
    """Build the alternate-Windows-credential context (ADR 0132, #111) from a File connector's
    ``credential_*`` settings, or ``None`` when none is configured (byte-identical — the connector then
    uses the engine's service-account identity via the shared :func:`asyncio.to_thread` pool).

    Constructed **at connector build**, so a credential configured on a **non-Windows host raises a clear
    :class:`~messagefoundry.transports.wincred.CredentialUnsupportedError` here** (a ``ValueError``,
    surfaced as a build/wiring failure) — never a silent no-op."""
    cred: WindowsCredential | None = WindowsCredential.from_settings(settings)
    if cred is None:
        return None
    return wincred.CredentialContext(
        username=cred.username, password=cred.password, domain=cred.domain
    )


class FileDestination(DestinationConnector):
    def __init__(self, config: Destination) -> None:
        s = config.settings
        if "directory" not in s:
            raise ValueError("file destination requires a 'directory' setting")
        self.directory = Path(s["directory"])
        # Opt-in at-start directory validation (#114, ADR 0031 amendment). Default off = the historical
        # run-time deferral, which on an outbound means the target dir is created on the first write.
        # When on, the directory must already exist at start AND `_write` never creates it — an operator
        # who said "never invent this path" gets that at delivery time too, not only at start.
        self.validate_directory: bool = bool(s.get("validate_directory", False))
        self.filename_template: str = s.get("filename", "{MSH-10}.hl7")
        # When two messages resolve to the same name, append a counter rather than clobber.
        self._overwrite: bool = bool(s.get("overwrite", False))
        self.encoding: str = s.get("encoding", "utf-8")
        # Alternate Windows/UNC credential (ADR 0132, #111). None (the default) => the ambient
        # service-account identity, byte-identical. On a non-Windows host a configured credential
        # raises CredentialUnsupportedError here (a build error), never a silent no-op.
        self._cred_ctx = _build_credential_context(s)
        # Optional outbound compression (ADR 0123): "gzip" gzips the encoded body and appends `.gz` to
        # the rendered name; None (default) is byte-identical to before. Single-stream gzip only.
        self.compress: str | None = _validate_compression(s.get("compress"), "compress")

    async def _run_fs(self, fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
        """Run a blocking filesystem callable off the event loop — under the alternate credential (on a
        dedicated impersonated thread) when one is configured, else via the shared
        :func:`asyncio.to_thread` pool (byte-identical to before #111)."""
        if self._cred_ctx is not None:
            return await self._cred_ctx.run(fn, *args, **kwargs)
        return await asyncio.to_thread(fn, *args, **kwargs)

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> None:  # metadata (#68): unused — no per-message header knob here
        try:
            await self._run_fs(self._write, payload)
        except OSError as exc:
            raise DeliveryError(f"file write failed: {exc}") from exc

    async def validate_startup(self) -> None:
        """Opt-in at-start directory validation (#114) — the outbound mirror of
        :meth:`FileSource.validate_startup`. No-op unless ``validate_directory`` is set; then the target
        directory must already exist (no mkdir — a merely-missing dir FAILS) and accept a write, since a
        delivery writes there. A failure raises :class:`DestinationStartupError` so the runner isolates
        the lane as ADR-0031 ``failed``: no live connector, the delivery worker still spawned, routed
        rows retried rather than delivered into a directory the engine invented.

        The probe runs under the alternate credential when one is configured (#111), so it validates the
        share under the same identity the delivery will use."""
        if not self.validate_directory:
            return
        try:
            await self._run_fs(_probe_dir_startup, self.directory, require_write=True)
        except OSError as exc:
            raise DestinationStartupError(
                f"file destination directory {self.directory} failed startup validation: {exc}"
            ) from exc

    async def test_connection(self) -> None:
        # Under validate_directory the probe must NOT create either: otherwise POST
        # /connections/{name}/test would silently repair the very typo the toggle exists to catch, and
        # the next restart would then validate clean with nobody the wiser.
        try:
            if self.validate_directory:
                await self._run_fs(_probe_dir_startup, self.directory, require_write=True)
            else:
                await self._run_fs(_probe_dir_writable, self.directory)
        except OSError as exc:
            raise DeliveryError(f"file directory {self.directory} not writable: {exc}") from exc

    async def aclose(self) -> None:
        # Release the alternate-credential context (worker thread + any token) on stop/reload, so no
        # identity leaks across a reconfigure. No-op when no credential is configured.
        if self._cred_ctx is not None:
            await self._cred_ctx.close()

    def _ensure_directory(self) -> None:
        """Make the target directory usable for this write — and make a CREATION observable (#114).

        Default (``validate_directory`` off): the unchanged create-if-missing, except that a directory
        this call actually created now logs a WARNING naming it. That silence is the defect: a typo'd
        ``directory`` would otherwise be created on the first delivery and every message counted and
        logged as delivered — because it was — into a path nobody is watching, with no error anywhere.

        ``validate_directory`` on: never create. The directory was validated at start; if it has since
        vanished the write raises, and ``send`` maps that to a retryable :class:`DeliveryError`, so the
        lane backs off and self-heals when the share returns instead of fabricating a local directory at
        the mount point and delivering into it.

        The syscall count on the default path is unchanged: ``mkdir(parents=True, exist_ok=True)``
        already probed ``is_dir()`` on its ``FileExistsError`` branch, which is the common one."""
        if self.validate_directory:
            if not self.directory.is_dir():
                raise FileNotFoundError(
                    f"destination directory {self.directory} does not exist and validate_directory is "
                    "on, so it is never created on write"
                )
            return
        try:
            self.directory.mkdir(parents=True)
        except FileExistsError:
            if not self.directory.is_dir():
                raise  # a non-directory sits at the configured path — the same OSError as before
        else:
            logger.warning(
                "file destination CREATED missing directory %s — this delivery is landing in a "
                "directory the engine just made; verify the configured path is the intended one",
                self.directory,
            )

    def _write(self, payload: str) -> None:
        self._ensure_directory()
        name = render_filename(self.filename_template, payload, fallback="message.hl7")
        if self.compress == "gzip" and not name.endswith(".gz"):
            # Signal the on-disk format so a downstream reader (or a gunzip source) knows to unpack.
            name = f"{name}.gz"
        target = self.directory / name
        # Defence in depth atop the filename sanitization (FILE-1): never write outside the
        # configured directory even if a name somehow carried a path component.
        if self.directory.resolve() not in target.resolve().parents:
            raise DeliveryError(f"refusing to write outside the destination directory: {name!r}")
        data = encode_wire_body(payload, self.encoding, transport="file")
        if self.compress == "gzip":
            # Deterministic (mtime=0) so a re-delivery of the same body writes identical bytes.
            data = gzip_compress(data)
        # Write to a uniquely-named temp (mkstemp — no shared counter, no name race), then publish
        # atomically. For no-overwrite, claim the final name by exclusive create so two concurrent
        # deliveries can't clobber each other (FILE-5: replaces the TOCTOU exists()-then-rename).
        fd, tmp_name = tempfile.mkstemp(dir=self.directory, suffix=".part")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            if self._overwrite:
                os.replace(tmp, target)  # atomic overwrite; consumes tmp
            else:
                _claim_unique(tmp, target)  # hard-links tmp → a free name
        finally:
            # Remove the temp; after a successful os.replace it's already gone (suppressed).
            with suppress(OSError):
                os.unlink(tmp)


class FileSource(SourceConnector):
    """Poll a directory for files and feed each to the pipeline handler."""

    polls_shared_resource = True  # a directory is a shared external resource — leader-gate it

    def __init__(self, config: Source) -> None:
        s = config.settings
        if "directory" not in s:
            raise ValueError("file source requires a 'directory' setting")
        self.directory = Path(s["directory"])
        # Resolved watch root for path-confinement: a recursive scan must not be walked out of the
        # configured directory via a symlinked file/subdir (see _within_root). resolve() is
        # non-strict, so it's fine that the directory is created later in start().
        self._root_real = self.directory.resolve()
        self.pattern: str = s.get("pattern", "*")
        self.poll_seconds: float = float(s.get("poll_seconds", 1.0))
        self.min_age_seconds: float = float(s.get("min_age_seconds", 0.0))
        self.after_read: str = s.get("after_read", "move")  # "move" | "delete" | "leave" (#142)
        if self.after_read not in ("move", "delete", "leave"):
            raise ValueError(
                f"file source after_read must be 'move', 'delete', or 'leave', got "
                f"{self.after_read!r}"
            )
        # #142 leave-in-place: HASHED file_keys (never a cleartext name) this connection has ingested —
        # a BOUNDED LRU fast-path (cap LEAVE_SEEN_CACHE_MAX) in front of the authoritative durable
        # ledger, so it can't outgrow the ledger's own count cap. A miss falls through to the durable
        # is_processed() read, so an eviction never causes a false re-ingest.
        self._processed_seen: OrderedDict[str, None] = OrderedDict()
        # Opt-in at-start directory validation (#114, ADR 0031 amendment). Default off = the historical
        # run-time deferral (a missing dir is logged-and-retried each poll, never fails start).
        self.validate_directory: bool = bool(s.get("validate_directory", False))
        self.sort: str = s.get("sort", "name")  # "name" | "mtime"
        self.recursive: bool = bool(s.get("recursive", False))
        # Encoding used to re-encode split batch messages back to bytes for the handler. A single
        # (non-batch) message is handed off verbatim, so its bytes never round-trip through this.
        self.encoding: str = s.get("encoding", "utf-8")
        mfb = s.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
        self.max_file_bytes: int | None = int(mfb) if mfb else None
        # Optional inbound decompression (ADR 0123): "gzip" gunzips each file's bytes BEFORE the sniff /
        # AV scan / batch split (they must see the real HL7). None (default) is byte-identical to before.
        self.decompress: str | None = _validate_compression(s.get("decompress"), "decompress")
        # Bounds the DECOMPRESSED output (a bomb guard `max_file_bytes` — a compressed-`st_size` cap —
        # cannot provide). A falsy value disables it. Only consulted when `decompress` is set.
        mdb = s.get("max_decompressed_bytes", DEFAULT_MAX_DECOMPRESSED_BYTES)
        self.max_decompressed_bytes: int | None = int(mdb) if mdb else None
        self.processed_dir = self.directory / s.get("processed_subdir", ".processed")
        self.error_dir = self.directory / s.get("error_subdir", ".error")
        self._handler: InboundHandler | None = None
        # Leader-gate (Track B Step 4b): when set, this directory (a shared external resource) is
        # polled only while the gate returns True, so in a cluster exactly one node ingests its
        # files. None = always poll (single-node / direct callers / tests) — byte-identical.
        self._leader_gate: Callable[[], bool] | None = None
        self._skipping = False  # whether the last tick was gated out (for a single transition log)
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # Alternate Windows/UNC credential (ADR 0132, #111). None (the default) => the ambient
        # service-account identity, byte-identical. On a non-Windows host a configured credential
        # raises CredentialUnsupportedError here (a build error), never a silent no-op.
        self._cred_ctx = _build_credential_context(s)

    async def _run_fs(self, fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
        """Run a blocking filesystem callable off the event loop — under the alternate credential (on a
        dedicated impersonated thread) when one is configured, else via the shared
        :func:`asyncio.to_thread` pool (byte-identical to before #111). Every share touch (list, stat,
        read, move/delete, the startup probe) goes through here, so the whole poll cycle runs under the
        endpoint's identity."""
        if self._cred_ctx is not None:
            return await self._cred_ctx.run(fn, *args, **kwargs)
        return await asyncio.to_thread(fn, *args, **kwargs)

    def _prepare_subdirs(self) -> None:
        """Create the ``.processed``/``.error`` subdirs (runs on the credentialed thread when a
        credential is set). In ``leave`` mode both are best-effort (a read-only share can't create them
        and must not fail start); otherwise both are required."""
        if self.after_read == "leave":
            # Leave-in-place (#142) never moves/deletes a source file, so it needs no .processed dir — and
            # a genuinely read-only share can't create either subdir anyway. Best-effort: a quarantine
            # move still has a target where the dir IS writable, but a read-only share doesn't fail start.
            for d in (self.processed_dir, self.error_dir):
                with suppress(OSError):
                    d.mkdir(parents=True, exist_ok=True)
        else:
            self.processed_dir.mkdir(parents=True, exist_ok=True)
            self.error_dir.mkdir(parents=True, exist_ok=True)

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        """Begin polling in the background. Returns once the source is set up so the
        caller can rely on it being live (consistent with the TCP sources)."""
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        # Create the subdirs under the endpoint's identity when a credential is configured (a UNC share
        # the service account can't touch); otherwise inline, byte-identical to before #111.
        if self._cred_ctx is None:
            self._prepare_subdirs()
        else:
            await self._cred_ctx.run(self._prepare_subdirs)
        self._task = asyncio.create_task(self._run())

    async def test_connection(self) -> None:
        try:
            await self._run_fs(_probe_dir_writable, self.directory)
        except OSError as exc:
            raise DeliveryError(f"file directory {self.directory} not writable: {exc}") from exc

    async def validate_startup(self) -> None:
        """Opt-in at-start directory validation (#114). No-op unless ``validate_directory`` is set; then
        the poll directory must already exist (no mkdir) — and be writable unless in ``leave`` mode,
        where only read/list is required (a read-only share). A failure raises
        :class:`SourceStartupError` so the runner isolates the connection as ADR-0031 ``failed``.

        The probe runs under the alternate credential when one is configured (#111), so it validates the
        share under the same identity the poll will use — and a bad credential surfaces here (a
        :class:`~messagefoundry.transports.wincred.CredentialLogonError` is an ``OSError``) as a clean
        startup failure rather than a per-poll retry."""
        if not self.validate_directory:
            return
        require_write = self.after_read != "leave"
        try:
            await self._run_fs(_probe_dir_startup, self.directory, require_write=require_write)
        except OSError as exc:
            raise SourceStartupError(
                f"file source directory {self.directory} failed startup validation: {exc}"
            ) from exc

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._may_poll():
                    await self._scan_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A scan error (watch dir vanished/unreadable, a bad glob, a move/read failure) must
                # NOT kill the poller — that would silently stop the connection from receiving while
                # it still reports running, and re-raise inside stop()/reload (review H-4). Log and
                # retry on the next interval.
                logger.exception(
                    "file source scan failed for %s; retrying next poll", self.directory
                )
            try:  # noqa: SIM105
                await asyncio.wait_for(self._stop.wait(), self.poll_seconds)
            except TimeoutError:
                pass  # poll interval elapsed; scan again

    def _may_poll(self) -> bool:
        """Whether this tick may scan the directory. False on a follower (leader-gated, Step 4b):
        a non-leader must NOT read or move/delete files, since the directory is shared and two
        nodes ingesting it would duplicate intake. The loop still ticks, so a node that becomes
        leader scans on its next tick (reactive-by-polling, no restart). When the gate is None or
        True, behaves exactly as before. Logged once on each transition (never per skipped tick —
        that would spam a follower's log every poll interval)."""
        if self._leader_gate is None or self._leader_gate():
            if self._skipping:
                self._skipping = False
                logger.debug("file source resuming polling of %s (now leader)", self.directory)
            return True
        if not self._skipping:
            self._skipping = True
            logger.debug(
                "file source skipping polling of %s (not leader; another node ingests it)",
                self.directory,
            )
        return False

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            # return_exceptions: a faulted poll task must not re-raise here — stop() runs during
            # reload quiesce, outside its rollback (review H-4). _run already guards scans; this is
            # the belt-and-suspenders.
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        # Release the alternate-credential context (worker thread + any token) AFTER the poll task has
        # quiesced, so no identity leaks across a stop/reload. No-op when no credential is configured.
        if self._cred_ctx is not None:
            await self._cred_ctx.close()

    async def _scan_once(self) -> None:
        assert self._handler is not None
        newly_recorded = (
            0  # #142: files marked processed THIS tick — gates a single end-of-tick prune
        )
        for path in await self._run_fs(self._candidates):
            # #142 leave-in-place dedup: skip a file this connection already ingested. In-memory set
            # first (no I/O), then the durable ledger (survives restart / a fresh process). Keyed on a
            # HASHED file id (name+mtime+size) — never a cleartext filename, never logged at INFO+.
            file_key: str | None = None
            if self.after_read == "leave":
                try:
                    file_key = await self._run_fs(self._file_key, path)
                except OSError:
                    continue  # vanished/locked mid-scan — retry next poll (never a drop)
                if await self._leave_already_ingested(file_key):
                    continue
            if await self._run_fs(self._oversize, path):
                # Transport-level reject *before* any message is read — parallels MLLP dropping an
                # over-cap frame. It never became a "received message", so (like MLLP) there's no
                # store disposition to record; preserve the file in .error for the operator and log it.
                logger.warning(
                    "file %s exceeds max_file_bytes (%s); routing to error dir",
                    path.name,
                    self.max_file_bytes,
                )
                await self._run_fs(self._move, path, self.error_dir)
                continue
            try:
                raw = await self._run_fs(path.read_bytes)
            except OSError as exc:
                # Transient (file locked / vanished mid-scan): leave it in place to retry next scan
                # rather than quarantining a healthy file. Logged, never silently swallowed.
                logger.warning("could not read %s (will retry next scan): %s", path.name, exc)
                continue
            if self.decompress == "gzip":
                # Decompress BEFORE the sniff, the AV/ICAP scan, and the batch split (ADR 0123): each
                # must see the REAL bytes, not the gzip container. The ceiling bounds the decompressed
                # output (and therefore post-split expansion) — the compressed-`st_size` `_oversize`
                # cap above cannot. A corrupt / oversized archive is quarantined like an oversize /
                # non-HL7 reject: it never became a received message, so there is no store disposition;
                # move the ORIGINAL compressed file to .error and log the CODEC message only (never the
                # decompressed body — it is PHI).
                try:
                    raw = await asyncio.to_thread(
                        gzip_decompress, raw, max_output_bytes=self.max_decompressed_bytes
                    )
                except CompressionError as exc:
                    logger.warning(
                        "file %s failed to gunzip (%s); routing to error dir", path.name, exc
                    )
                    await self._run_fs(self._move, path, self.error_dir)
                    continue
            if not _content_matches_declared(self.content_type, raw):
                # Content doesn't match the declared content_type (a PDF on a json inbound, a non-ISA
                # body on an x12 inbound, a headerless HL7 drop, …) — quarantine before its bytes reach
                # the pipeline (ASVS 5.2.2). Like the oversize reject above it never became a "received
                # message", so there's no store disposition; preserve it in .error and log it (never a
                # silent drop). Gated by content_type inside the helper: binary/text carry no reliable
                # signature and pass unchecked (fhir uses the json {/[ sniff); None keeps the historical hl7v2 sniff
                # (None→hl7v2), byte-identical to before; a conformant x12/json/xml/dicom drop matches
                # its magic bytes and flows on to the content_type-aware pipeline (carried NUL-safely via
                # RawMessage.from_bytes / mfb64, ADR 0028). Only a genuine content-vs-type mismatch is
                # newly quarantined (the 5.2.2 hardening over the prior hl7v2-only sniff).
                logger.warning(
                    "file %s does not match its declared content type %r (no matching magic bytes); "
                    "routing to error dir",
                    path.name,
                    (self.content_type or ContentType.HL7V2).value,
                )
                await self._run_fs(self._move, path, self.error_dir)
                continue
            try:
                # The scan hook operates on already-read bytes (it may itself dial an AV/ICAP service),
                # so it runs on the SHARED pool, NOT under the share credential — impersonating the
                # endpoint's SMB identity for an unrelated scanner call would be wrong (#111).
                await asyncio.to_thread(scan_inbound_file, raw, path.name)
            except ScanRejected as exc:
                # A configured pre-ingest scanner (AV/ICAP/plugin) rejected the content before it
                # entered the pipeline (ASVS 5.4.3). Like the oversize / non-HL7 rejects above, it
                # never became a "received message", so there's no store disposition; quarantine + log.
                logger.warning(
                    "file %s rejected by the pre-ingest scan hook (%s); routing to error dir",
                    path.name,
                    exc,
                )
                await self._run_fs(self._move, path, self.error_dir)
                continue
            except Exception as exc:  # noqa: BLE001 - operator scan hook: any failure fails closed
                # The scan hook MALFUNCTIONED (AV/ICAP unreachable, a plugin bug) — NOT a content
                # rejection. Fail closed (ASVS 5.4.3): never emit unscanned content. Unlike a
                # ScanRejected we don't quarantine a possibly-healthy file on a scanner outage — leave
                # it in place so the next scan re-runs the scan once the scanner recovers (at-least-once,
                # mirroring the transient-read path). Logged, never a silent pass-through, and scoped to
                # THIS file so a scanner hiccup can't abort the whole tick's remaining candidates.
                logger.warning(
                    "file %s: pre-ingest scan hook errored (%s); leaving in place, will retry next scan",
                    path.name,
                    exc,
                )
                continue
            try:
                await self._emit(raw)
            except Exception as exc:
                # The handler records every message-level outcome (parse/validation/routing → ERROR)
                # itself and returns, so an exception escaping here is an infrastructure failure: the
                # durable store write failed (DB locked, disk full). Leave the file in place so the
                # next scan retries once the store recovers (at-least-once) — moving it to .error would
                # drop a *received* message that was never recorded, an accept-and-drop (review M-15).
                #
                # CRITICAL (Tier 2.2 batch split): a batch is split into N hand-offs (_emit), and the
                # file is moved/deleted ONLY after ALL of them succeed (below). If hand-off K fails,
                # we `continue` WITHOUT moving the file, so the next scan re-reads the WHOLE file and
                # re-emits every message 1..N. That is at-least-once: messages 1..K-1 may be re-emitted
                # (duplicates, acceptable — handlers are idempotent), but the file is NEVER moved with
                # only some of its messages emitted (no accept-and-drop of the tail).
                logger.warning("handler failed for %s (will retry next scan): %s", path.name, exc)
                continue
            await self._run_fs(self._after_processing, path)
            if self.after_read == "leave" and file_key is not None:
                # Record AFTER emit success (the FILE — not each split message — is the dedup unit), so a
                # partial-emit crash re-reads and re-emits the whole file (at-least-once), never dropping.
                await self._leave_record(file_key)
                newly_recorded += 1
        if newly_recorded and self.processed_ledger is not None:
            # Bound the ledger's growth (age + count); only when this tick recorded something, so a stable
            # read-only share (nothing new) never churns the store.
            await self.processed_ledger.prune()

    def _file_key(self, path: Path) -> str:
        """A stable, HASHED identity for a source file, for the leave-in-place dedup ledger (#142).

        The identity folds the file's path **relative to the watch root** (not just the basename) +
        mtime + size, so that under ``recursive=True`` two DISTINCT files that share a basename in
        different subdirectories — and, on a timestamp-preserving copy over a coarse-mtime share, also
        share mtime+size — hash to DIFFERENT keys and are BOTH ingested (never one silently deduped away,
        which would be an accept-and-drop of a received file, count-and-log invariant). SHA-256 so the
        relative path — which, like a filename, can embed an MRN — is never stored or logged in the clear
        (the ledger holds this derived id only; never log the relative path). Folding mtime+size in means
        an UPDATED file (new mtime/size → new key) is re-ingested, while an unchanged file is skipped. May
        raise ``OSError`` if the file vanished mid-scan (the caller treats that as transient)."""
        st = path.stat()
        rel = path.relative_to(self.directory).as_posix()
        ident = f"{rel}\x00{st.st_mtime_ns}\x00{st.st_size}"
        return hashlib.sha256(ident.encode("utf-8", "surrogatepass")).hexdigest()

    def _seen_touch(self, file_key: str) -> bool:
        """True if ``file_key`` is in the bounded in-memory fast-path (and refresh its LRU recency)."""
        if file_key in self._processed_seen:
            self._processed_seen.move_to_end(file_key)
            return True
        return False

    def _seen_add(self, file_key: str) -> None:
        """Add ``file_key`` to the bounded LRU, evicting the oldest on overflow. Eviction is safe: a
        later miss falls through to the authoritative durable ``ledger.is_processed()`` read."""
        self._processed_seen[file_key] = None
        self._processed_seen.move_to_end(file_key)
        while len(self._processed_seen) > LEAVE_SEEN_CACHE_MAX:
            self._processed_seen.popitem(last=False)

    async def _leave_already_ingested(self, file_key: str) -> bool:
        """True if this leave-in-place file was already ingested — the bounded in-process cache first (no
        I/O), then, on a miss, the AUTHORITATIVE durable ledger (covers a restart / a fresh process /
        a cache eviction). A durable hit is re-cached, so eviction never causes a false re-ingest."""
        if self._seen_touch(file_key):
            return True
        ledger = self.processed_ledger
        if ledger is not None and await ledger.is_processed(file_key):
            self._seen_add(file_key)
            return True
        return False

    async def _leave_record(self, file_key: str) -> None:
        """Mark a leave-in-place file ingested: the durable ledger (a HASHED key, no cleartext filename)
        plus the bounded in-process cache. Idempotent on the store side."""
        self._seen_add(file_key)
        if self.processed_ledger is not None:
            await self.processed_ledger.mark_processed(file_key)

    async def _emit(self, raw: bytes) -> None:
        """Hand every HL7 message in ``raw`` to the pipeline handler, in file order (FIFO).

        **Non-hl7v2 ingress** (ADR 0004): when the inbound declares a non-HL7 ``content_type``
        (binary/x12/dicom/text/json) the raw file bytes are handed off **verbatim** with no batch
        split — the split below is HL7-specific (it text-decodes to find MSH boundaries) and would
        corrupt a binary payload (a PDF's non-text bytes) or split on a false MSH boundary, so a
        non-HL7 drop bypasses it entirely and its exact bytes reach the content_type-aware pipeline
        (carried NUL-safely via ``RawMessage.from_bytes`` / mfb64, ADR 0028). This mirrors
        RemoteFileSource, which hands raw bytes straight to the handler. ``content_type`` is None only
        for a direct caller/test that never had it injected — that path falls through to the HL7 split
        below, byte-identical to before this gate existed.

        Corepoint-style **batch split** (Tier 2.2-A): a dropped file may hold several MSH-delimited
        messages (a batch, or an FHS/BHS envelope). Each becomes one pipeline hand-off — the same
        per-message split a dry-run / ``messagefoundry check`` sees, via the shared
        :func:`~messagefoundry.parsing.split.split_batch`.

        Splitting must decode the bytes to find the MSH boundaries, so we decode with the
        connection's **declared encoding** (``errors="strict"``) — never UTF-8 by accident — so a
        non-UTF-8 batch (e.g. latin-1) splits without mojibake. If the file isn't decodable in that
        encoding, or it holds a single message, the **original bytes are handed off verbatim** (one
        hand-off): a single-message file is then byte-for-byte identical to before the split existed,
        and an undecodable file flows to the pipeline unchanged so its ``normalize(errors="strict")``
        records the proper ``ERROR`` disposition exactly as today (we don't pre-empt that here). A
        true batch is split and each message **re-encoded with the same declared encoding**, so the
        handler still receives ``bytes`` exactly as in the un-split path.

        Any exception (a durable-store failure on hand-off K) propagates to the caller, which then
        leaves the whole file in place for the next scan — preserving at-least-once with no partial
        move (see :meth:`_scan_once`)."""
        assert self._handler is not None
        if self.content_type is not None and self.content_type is not ContentType.HL7V2:
            # Non-hl7v2: hand the file's RAW BYTES off verbatim — no text-decode, no HL7 batch split
            # (see the docstring). A binary payload's exact bytes survive to RawMessage.from_bytes.
            await self._handler(raw)
            return
        try:
            text = raw.decode(self.encoding)
        except (UnicodeDecodeError, LookupError):
            # Not decodable in the declared encoding (or an unknown codec name): can't safely find MSH
            # boundaries, so hand the raw bytes off unchanged — the pipeline's strict-decode then
            # records ERROR for it, exactly as in the pre-split single-hand-off path. Never a drop.
            await self._handler(raw)
            return
        messages = split_batch(
            text
        )  # str in → no UTF-8 re-decode (normalize only fixes line endings)
        if len(messages) == 1:
            # Fast path / strict back-compat: a lone message is handed off verbatim (its original
            # bytes), so a non-batch file behaves byte-for-byte as before the split was introduced.
            await self._handler(raw)
            return
        for message in messages:
            # FIFO per connection: emit in file order, awaiting each so a slow/failing hand-off
            # back-pressures the rest (and a failure stops the file from being moved — see above).
            await self._handler(message.encode(self.encoding))

    def _oversize(self, path: Path) -> bool:
        """True if ``path`` is larger than the configured cap (checked before reading it)."""
        if self.max_file_bytes is None:
            return False
        try:
            return path.stat().st_size > self.max_file_bytes
        except OSError:
            return False  # vanished/locked — let the read path handle it

    def _candidates(self) -> list[Path]:
        """Files ready to process, honoring recursion, min-age, and sort order."""
        globber = self.directory.rglob if self.recursive else self.directory.glob
        try:
            matched = list(globber(self.pattern))
        except (OSError, ValueError) as exc:
            # Watch dir vanished/unreadable, or an invalid glob pattern: treat as "nothing this
            # scan" (logged) rather than letting it propagate and kill the poller (review H-4).
            logger.warning(
                "file source could not list %s (pattern %r): %s", self.directory, self.pattern, exc
            )
            return []
        files = [
            p
            for p in matched
            if p.is_file()
            and self.processed_dir not in p.parents
            and self.error_dir not in p.parents
            and self._within_root(p)
        ]
        if self.min_age_seconds > 0:
            cutoff = time.time() - self.min_age_seconds
            files = [p for p in files if _mtime(p) <= cutoff]  # skip files still being written
        if self.sort == "mtime":
            files.sort(key=_mtime)
        else:
            files.sort(key=lambda p: p.name)
        return files

    def _within_root(self, path: Path) -> bool:
        """True if ``path`` resolves inside the configured watch root.

        A symlinked file or subdirectory that points outside the root (e.g. ``in/link -> /etc``)
        resolves elsewhere and is skipped, so a recursive scan can't be walked out of its directory
        to read arbitrary files (path-confinement / symlink-escape guard)."""
        try:
            resolved = path.resolve()
        except OSError:
            return False
        if resolved == self._root_real or self._root_real in resolved.parents:
            return True
        logger.warning(
            "file source: skipping %s — it resolves outside the watch root (symlink escape?)",
            path.name,
        )
        return False

    def _after_processing(self, path: Path) -> None:
        if self.after_read == "delete":
            try:
                path.unlink()
            except OSError as exc:
                # A processed file we can't delete will be re-read (duplicate); surface it (FILE-4).
                logger.warning("could not delete processed file %s: %s", path.name, exc)
        elif self.after_read == "leave":
            # #142 process-in-place: never move or delete the source file — the durable dedup ledger
            # (recorded by _scan_once AFTER this returns) is what stops it being re-ingested next poll.
            return
        else:
            self._move(path, self.processed_dir)

    @staticmethod
    def _move(path: Path, dest_dir: Path) -> None:
        """Archive ``path`` into ``dest_dir`` under a name claimed ATOMICALLY (BACKLOG #1046).

        This used to be ``path.replace(_unique(...))`` — a check-then-act pair, where ``_unique``
        asked ``exists()`` and ``replace`` then overwrote whatever was at the name it chose. Two
        pollers sharing one ``processed_dir`` (a non-default config; the default is one poller over
        an engine-owned dir) could both be handed the same free name and the second would silently
        clobber the first's archived copy. The delivery path had already replaced exactly that
        pattern with :func:`_claim_unique`'s ``O_EXCL``/``os.link`` claim (FILE-5); the archive move
        was the one caller left on the racy form.

        Claim-then-unlink rather than a single ``replace``: the claim is the whole point, and it
        cannot be expressed as a rename (renaming a file over its own hard link is a POSIX no-op, so
        the original would survive). If the unlink fails after the claim the file is archived AND
        left in place to be re-read — the same duplicate-read outcome the pre-existing failure arm
        already had, and logged the same way."""
        try:
            _claim_unique(path, dest_dir / path.name)
        except OSError as exc:
            # A stuck file (locked / dest unwritable) stays and is re-read; log it (FILE-4).
            logger.warning("could not move %s to %s: %s", path.name, dest_dir.name, exc)
            return
        try:
            path.unlink()
        except OSError as exc:
            logger.warning(
                "archived %s to %s but could not remove the original (it will be re-read): %s",
                path.name,
                dest_dir.name,
                exc,
            )


# --- helpers -----------------------------------------------------------------
# The pure magic-byte sniffers (_looks_like_hl7 / _lstrip_bom_ws / _content_matches_declared) were hoisted
# to parsing/sniff.py (ASVS 5.2.2) so the leaf uploads.py can reuse them without importing a transport;
# they are re-imported at the top of this module and re-exported (see __all__) so remotefile.py and the
# existing tests that import them from here are unchanged.


class ScanRejected(Exception):
    """Raised by a pre-ingest scan hook to reject malicious/disallowed inbound file content (ASVS
    5.4.3). The connector quarantines the file to its error dir and never emits it."""


#: Pre-ingest content-scan hook: ``(raw_bytes, source_label) -> None``; raise :class:`ScanRejected`
#: to reject. ``(bytes, str)`` so an operator scanner can label its logs. Default = no-op.
ScanHook = Callable[[bytes, str], None]


def _no_scan(raw: bytes, source: str) -> None:
    return None


_scan_hook: ScanHook = _no_scan


def set_scan_hook(hook: ScanHook | None) -> None:
    """Install (or clear, with ``None``) the pre-ingest content-scan hook (ASVS 5.4.3).

    MessageFoundry ships **no** built-in antivirus/malware scan: the supported model trusts the drop
    directory, and a less-trusted or remote source should be fronted by an AV/ICAP gateway (see
    docs/CONNECTIONS.md). This seam lets an operator/plugin install an in-process scanner that runs over
    the raw bytes of every inbound file — both the local FILE source and the remote SFTP/FTP(S) source —
    *before* they enter the pipeline. Format-agnostic (it sees raw bytes), so it works for HL7, X12, or
    any payload.

    **Enforced precondition, fail-closed (ASVS 5.4.3, BACKLOG #204).** When a hook is installed it is a
    *precondition on ingest*, not an advisory pass: the connector runs it on **every** file and unscanned
    content can never reach the pipeline on either failure axis —

    * a **content rejection** (the hook raises :class:`ScanRejected`) quarantines the file to the
      connector's error dir and never emits it;
    * a **scanner malfunction** (the hook raises **any other** exception — AV/ICAP unreachable, a plugin
      bug) is fail-closed too: the file is **not emitted** and is left in place to be re-scanned on the
      next poll once the scanner recovers (at-least-once), never passed through unscanned.

    The seam stays **off by default** (:func:`_no_scan` no-op); with no hook installed the drop directory
    itself is the trust boundary and an operator-fronted AV/ICAP gateway is the supported control."""
    global _scan_hook
    _scan_hook = hook or _no_scan


def scan_inbound_file(raw: bytes, source: str) -> None:
    """Run the configured pre-ingest scan hook over ``raw`` (default no-op); raise :class:`ScanRejected`
    to reject — the caller quarantines and never emits. Run off the event loop (it may do blocking I/O
    to an AV/ICAP service)."""
    _scan_hook(raw, source)


def _claim_unique(tmp: Path, target: Path) -> Path:
    """Claim ``target`` (or ``name-1.ext``, ``name-2.ext``, … if taken) for ``tmp``, atomically.

    Prefers ``os.link`` (the target becomes a hard link to ``tmp``); ``FileExistsError`` means the
    name is taken, so claiming a free name is a single atomic step — no check-then-act window where
    a concurrent writer could clobber us. Where hard links aren't supported (FAT/exFAT, many SMB/NAS
    mounts) ``os.link`` raises a different ``OSError``; fall back to an exclusive-create copy
    (``O_CREAT | O_EXCL``), which is also atomic no-clobber but works cross-filesystem (review low-5)."""
    stem, suffix = target.stem, target.suffix
    candidate, n = target, 0
    linkable = True
    while True:
        if linkable:
            try:
                os.link(tmp, candidate)
                return candidate
            except FileExistsError:
                n += 1
                candidate = target.with_name(f"{stem}-{n}{suffix}")
                continue
            except OSError:
                linkable = False  # hard links unusable on this filesystem — copy instead
        try:
            # 0o600 (owner-only), matching the mkstemp temp this delivers and the os.link / os.replace
            # paths that inherit its mode: delivered files can carry PHI, so the rare cross-filesystem
            # copy fallback must not be the one path that leaves them world-readable.
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            n += 1
            candidate = target.with_name(f"{stem}-{n}{suffix}")
            continue
        # Streamed, not read_bytes(): the archive move claims through here too (#1046), and an
        # inbound file is only as small as the operator's max_file_bytes (unset by default), so
        # buffering the whole thing to claim a name would put an arbitrarily large inbound payload
        # in memory on exactly the filesystems that already can't hard-link.
        with open(tmp, "rb") as source, os.fdopen(fd, "wb") as handle:
            shutil.copyfileobj(source, handle)
        return candidate


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


register_destination(ConnectorType.FILE, FileDestination)
register_source(ConnectorType.FILE, FileSource)
