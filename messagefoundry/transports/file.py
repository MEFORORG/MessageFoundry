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
import logging
import os
import re
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.parsing.peek import HL7PeekError, Peek
from messagefoundry.parsing.split import split_batch
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    InboundHandler,
    SourceConnector,
    register_destination,
    register_source,
)

__all__ = ["FileDestination", "FileSource", "render_filename", "DEFAULT_MAX_FILE_BYTES"]

logger = logging.getLogger(__name__)

# Cap a single inbound file read so a multi-GB drop can't OOM the engine (DoS guard). A
# falsy value (None/0) in settings disables the cap; see docs/CONNECTIONS.md.
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB — matches the MLLP frame cap

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


def _probe_dir_writable(directory: Path) -> None:
    """Reachability probe shared by the FILE connectors: ensure ``directory`` exists and accepts a
    write — a destination writes messages there and a source moves processed files into its subdirs,
    so writability is the meaningful check for both. Creates and removes a temp file; raises ``OSError``
    if the directory is missing or unwritable."""
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".probe")
    os.close(fd)
    os.unlink(tmp)


class FileDestination(DestinationConnector):
    def __init__(self, config: Destination) -> None:
        s = config.settings
        if "directory" not in s:
            raise ValueError("file destination requires a 'directory' setting")
        self.directory = Path(s["directory"])
        self.filename_template: str = s.get("filename", "{MSH-10}.hl7")
        # When two messages resolve to the same name, append a counter rather than clobber.
        self._overwrite: bool = bool(s.get("overwrite", False))
        self.encoding: str = s.get("encoding", "utf-8")

    async def send(self, payload: str) -> None:
        try:
            await asyncio.to_thread(self._write, payload)
        except OSError as exc:
            raise DeliveryError(f"file write failed: {exc}") from exc

    async def test_connection(self) -> None:
        try:
            await asyncio.to_thread(_probe_dir_writable, self.directory)
        except OSError as exc:
            raise DeliveryError(f"file directory {self.directory} not writable: {exc}") from exc

    def _write(self, payload: str) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        name = render_filename(self.filename_template, payload, fallback="message.hl7")
        target = self.directory / name
        # Defence in depth atop the filename sanitization (FILE-1): never write outside the
        # configured directory even if a name somehow carried a path component.
        if self.directory.resolve() not in target.resolve().parents:
            raise DeliveryError(f"refusing to write outside the destination directory: {name!r}")
        data = payload.encode(self.encoding)
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
        self.after_read: str = s.get("after_read", "move")  # "move" | "delete"
        self.sort: str = s.get("sort", "name")  # "name" | "mtime"
        self.recursive: bool = bool(s.get("recursive", False))
        # Encoding used to re-encode split batch messages back to bytes for the handler. A single
        # (non-batch) message is handed off verbatim, so its bytes never round-trip through this.
        self.encoding: str = s.get("encoding", "utf-8")
        mfb = s.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
        self.max_file_bytes: int | None = int(mfb) if mfb else None
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

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        """Begin polling in the background. Returns once the source is set up so the
        caller can rely on it being live (consistent with the TCP sources)."""
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.error_dir.mkdir(parents=True, exist_ok=True)
        self._task = asyncio.create_task(self._run())

    async def test_connection(self) -> None:
        try:
            await asyncio.to_thread(_probe_dir_writable, self.directory)
        except OSError as exc:
            raise DeliveryError(f"file directory {self.directory} not writable: {exc}") from exc

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
            try:
                await asyncio.wait_for(self._stop.wait(), self.poll_seconds)
            except asyncio.TimeoutError:
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

    async def _scan_once(self) -> None:
        assert self._handler is not None
        for path in await asyncio.to_thread(self._candidates):
            if await asyncio.to_thread(self._oversize, path):
                # Transport-level reject *before* any message is read — parallels MLLP dropping an
                # over-cap frame. It never became a "received message", so (like MLLP) there's no
                # store disposition to record; preserve the file in .error for the operator and log it.
                logger.warning(
                    "file %s exceeds max_file_bytes (%s); routing to error dir",
                    path.name,
                    self.max_file_bytes,
                )
                await asyncio.to_thread(self._move, path, self.error_dir)
                continue
            try:
                raw = await asyncio.to_thread(path.read_bytes)
            except OSError as exc:
                # Transient (file locked / vanished mid-scan): leave it in place to retry next scan
                # rather than quarantining a healthy file. Logged, never silently swallowed.
                logger.warning("could not read %s (will retry next scan): %s", path.name, exc)
                continue
            if not _looks_like_hl7(raw):
                # Content doesn't match the declared .hl7 type (binary / non-HL7 text) — quarantine
                # before its bytes reach the pipeline (ASVS 5.2.2). Like the oversize reject above, it
                # never became a "received message", so there's no store disposition; preserve it in
                # .error and log it (never a silent drop).
                logger.warning(
                    "file %s is not HL7 (no MSH/FHS/BHS header); routing to error dir", path.name
                )
                await asyncio.to_thread(self._move, path, self.error_dir)
                continue
            try:
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
                await asyncio.to_thread(self._move, path, self.error_dir)
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
            await asyncio.to_thread(self._after_processing, path)

    async def _emit(self, raw: bytes) -> None:
        """Hand every HL7 message in ``raw`` to the pipeline handler, in file order (FIFO).

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
        else:
            self._move(path, self.processed_dir)

    @staticmethod
    def _move(path: Path, dest_dir: Path) -> None:
        try:
            path.replace(_unique(dest_dir / path.name))
        except OSError as exc:
            # A stuck file (locked / dest unwritable) stays and is re-read; log it (FILE-4).
            logger.warning("could not move %s to %s: %s", path.name, dest_dir.name, exc)


# --- helpers -----------------------------------------------------------------


# Segment ids a valid HL7 v2 payload (single message or batch file) may start with.
_HL7_LEADING_SEGMENTS = (b"MSH", b"FHS", b"BHS")


def _looks_like_hl7(raw: bytes) -> bool:
    """Cheap content sniff: does ``raw`` start with an HL7 v2 header segment (ASVS 5.2.2)?

    Mirrors what the tolerant parser accepts at the very start — an optional UTF-8 BOM, an MLLP
    start byte, and leading whitespace — then requires the first segment id to be MSH (message), FHS
    (file) or BHS (batch). This rejects a binary or non-HL7 file that merely carries the ``.hl7``
    extension before its bytes enter the pipeline, without rejecting a structurally-odd-but-textual
    HL7 message (which still flows through and is recorded as ``ERROR`` by the parser)."""
    head = raw.lstrip(b"\x0b\r\n \t")
    if head.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM
        head = head[3:].lstrip(b"\x0b\r\n \t")
    return head[:3] in _HL7_LEADING_SEGMENTS


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
    *before* they enter the pipeline; it must raise :class:`ScanRejected` to reject content, which the
    connector then quarantines to its error dir (never emitted). Format-agnostic (it sees raw bytes), so
    it works for HL7, X12, or any payload."""
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
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            n += 1
            candidate = target.with_name(f"{stem}-{n}{suffix}")
            continue
        with os.fdopen(fd, "wb") as handle:
            handle.write(tmp.read_bytes())
        return candidate


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def _unique(target: Path) -> Path:
    """Return ``target`` or, if it exists, ``name-1.ext``, ``name-2.ext``, …"""
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    n = 1
    while True:
        candidate = target.with_name(f"{stem}-{n}{suffix}")
        if not candidate.exists():
            return candidate
        n += 1


register_destination(ConnectorType.FILE, FileDestination)
register_source(ConnectorType.FILE, FileSource)
