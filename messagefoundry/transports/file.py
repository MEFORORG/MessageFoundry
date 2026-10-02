# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File transport: directory destination + directory-polling source.

**Destination** writes each payload to a file in a directory. The filename may contain
``{HL7-path}`` placeholders (e.g. ``{MSH-10}.hl7``) resolved by peeking the payload, so
archived files are named by control id / message type. Writes are atomic (write to a
temp name, flush it, then ``rename``/``link``) so a reader watching the directory never sees a partial
file. The one residual is a POSIX filesystem with no hard links, where a reader can briefly see an
EMPTY file at the final name (see ``_publish_staged``, BACKLOG #1622).

**Source** polls a directory for files, hands each to the pipeline handler, then moves the
file into a ``.processed`` subdirectory (or ``.error`` if the handler raised). Files have
no reply channel, so the *pipeline* handler's return value is ignored here. That is not a statement
about a config **Handler**: its return is routed like any other (and an inadmissible one raises).
"""

from __future__ import annotations

import asyncio
import ctypes
import errno
import functools
import hashlib
import logging
import ntpath
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import traceback
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, BinaryIO, Self, TypeVar

from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    Source,
    WindowsCredential,
)
from messagefoundry.parsing.compression import CompressionError, gzip_compress, gzip_decompress
from messagefoundry.parsing.peek import PEEK_READ_FAULTS, HL7PeekError, Peek
from messagefoundry.parsing.sniff import _content_matches_declared, _looks_like_hl7
from messagefoundry.parsing.split import split_batch
from messagefoundry.redaction import safe_exc, safe_name
from messagefoundry.transports import wincred
from messagefoundry.transports.base import (
    DEFAULT_MAX_ITEMS_PER_POLL,
    DeliveryError,
    DestinationConnector,
    DestinationStartupError,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    SourceStartupError,
    encode_wire_body,
    intake_open,
    positive_cap,
    register_destination,
    register_source,
    resolve_poll_ceiling,
)

__all__ = [
    "FileDestination",
    "FileSource",
    "render_filename",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_ITEMS_PER_POLL",
    "LEAVE_SEEN_CACHE_MAX",
    # Re-exported from parsing.sniff (ASVS 5.2.2) so remotefile.py + existing tests import them here.
    "_content_matches_declared",
    "_looks_like_hl7",
    "DEFAULT_MAX_DECOMPRESSED_BYTES",
]

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: ``(size, mtime_ns)``: what the partial-write guard compares (BACKLOG #116).
_FileSig = tuple[int, int]
#: ``(st_dev, st_ino)``: which file a handle or a name leads to. On Windows ``os.stat`` fills them from
#: the volume serial number and the file ID, so the compare works the same there (BACKLOG #2535).
_FileId = tuple[int, int]

# Cap a single inbound file read so a multi-GB drop can't OOM the engine (DoS guard). None/0 in
# settings, in any spelling, disables the cap; see docs/CONNECTIONS.md.
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB — matches the MLLP frame cap

# Cap the leave-in-place (#142) in-memory dedup fast-path so it can't outgrow the durable
# processed_files ledger's count cap (PROCESSED_FILE_LEDGER_KEEP_MAX in pipeline/wiring_runner.py). It
# is only a cache in front of the AUTHORITATIVE, bounded durable read: an evicted key falls through to
# ledger.is_processed(), so eviction never causes a false re-ingest. Shared by RemoteFileSource.
LEAVE_SEEN_CACHE_MAX = 100_000

# Bound the settle gate's poll-to-poll memory (BACKLOG #1811). Each scan also forgets files it has not
# listed for SETTLE_MISS_LIMIT scans in a row, so in practice it holds one entry per unsettled file in
# the drop directory; this cap only matters for a directory with more unsettled files than this. At the
# cap a NEW file is not recorded, so it waits; nothing already recorded is evicted. Evicting would let
# unsettled files push each other out on every scan so that none of them ever settled, while refusing
# new entries lets the recorded ones settle, be admitted and make room.
SETTLE_SEEN_MAX = 100_000

# How many scans in a row may fail to list a file before the settle gate forgets it. More than one, so a
# listing that fails now and then (a share that drops out, a recursive subtree that is briefly
# unreadable, a transient stat error that makes is_file() False) does not wipe a sighting and restart
# the wait; a failed listing returns no candidates rather than raising.
SETTLE_MISS_LIMIT = 3

# When `decompress=` is set, this bounds the *decompressed* output (ADR 0123): `max_file_bytes` only
# caps the COMPRESSED input (`st_size`), so a small gzip can expand to gigabytes (a decompression bomb).
# Because the batch split, the sniff, and every downstream stage run on the decompressed bytes, bounding
# the decompressed output also bounds post-split expansion. None/0 (in any spelling) disables the cap.
DEFAULT_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024  # 64 MiB

# How long FileSource.stop() waits for the poll task before it gives up on a blocked share call
# (BACKLOG #1620). A dead SMB/UNC share blocks each call for the OS redirector's timeout, tens of
# seconds, and nothing engine-side can interrupt the thread. Matches the credential context's own
# drain bound (wincred._CLOSE_DRAIN_TIMEOUT_S), the other "give up on a wedged share" arm.
_STOP_GRACE_S = 5.0

# Compression algorithms the FILE connector supports on its compress=/decompress= option. The connector
# is restricted to single-stream gzip (ADR 0123); multi-entry zip / raw deflate stay Handler-composed
# via messagefoundry.parsing.compression.
_SUPPORTED_COMPRESSION = frozenset({"gzip"})

_PLACEHOLDER = re.compile(r"\{([A-Z][A-Z0-9]{2}-\d+(?:\.\d+){0,2})\}")
# Strip characters that are unsafe in filenames on Windows and POSIX alike (path separators
# included, so a resolved value can never introduce a directory component). A lone surrogate is
# unsafe too: it has no encoding, so a POSIX write of it would raise outside the DeliveryError
# contract (ADR 0204).
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f\ud800-\udfff]')
#: The longest final file name a destination writes, in UTF-8 bytes, suffix included (ADR 0204).
#: The common per-component limit is 255: bytes on ext4 and XFS, UTF-16 units on NTFS. A UTF-8 byte
#: count is never below the UTF-16 unit count, so one byte cap holds on both. The 55 bytes left under
#: 255 cover the names a destination derives from this one: the remote upload's temp,
#: ``.{name}.{32 hex}.part``, adds 39, and a collision counter ``-N`` adds a few more.
FILENAME_MAX_BYTES = 200

#: Room a local destination keeps in its path budget for a derived name: the ``-N`` collision
#: counter, or the ``mkstemp`` temp ``tmpXXXXXXXX.part``, which is 16 characters.
_DERIVED_NAME_HEADROOM = 16

#: The name a destination falls back to when a rendered name is unusable.
_FALLBACK_NAME = "message.hl7"

#: The longest usable path, in the platform's path units, when nothing better is known. Each is the
#: platform constant less its terminating NUL: Windows ``MAX_PATH`` 260, macOS 1024, Linux 4096.
_WIN_MAX_PATH = 259
_WIN_LONG_PATH = 32766
_DARWIN_PATH_MAX = 1023
_POSIX_PATH_MAX = 4095


def _name_bytes(name: str) -> int:
    """The length of ``name`` in UTF-8 bytes. ``surrogatepass`` so a measure never raises."""
    return len(name.encode("utf-8", "surrogatepass"))


@functools.cache
def _windows_long_paths_enabled() -> bool:
    """Whether Windows lets this process open a path past ``MAX_PATH`` without the long-path prefix.

    Two things decide it: the ``LongPathsEnabled`` registry value, and whether the host executable
    declares itself long-path aware. ``RtlAreLongPathsEnabled`` answers for both, which the registry
    value alone does not. Asked once: Windows fixes the answer at process start. A failed call counts
    as off, which only makes the name budget smaller."""
    if sys.platform != "win32":
        return False
    try:
        query = ctypes.WinDLL("ntdll").RtlAreLongPathsEnabled
    except (OSError, AttributeError):
        return False
    query.restype = ctypes.c_ubyte
    query.argtypes = []
    return bool(query())


def _path_limit(absolute: str) -> int:
    """The longest path this platform opens, in its own path units, for a path like ``absolute``."""
    if sys.platform == "win32":
        if absolute.startswith("\\\\?\\") or _windows_long_paths_enabled():
            return _WIN_LONG_PATH
        return _WIN_MAX_PATH
    if sys.platform == "darwin":
        return _DARWIN_PATH_MAX
    return _POSIX_PATH_MAX


def _path_units(path: str) -> int:
    """The length of ``path`` in the units the platform limit counts: UTF-16 on Windows, bytes else."""
    if sys.platform == "win32":
        return len(path.encode("utf-16-le", "surrogatepass")) // 2
    return _name_bytes(path)


def _name_budget(directory: Path, suffix: str) -> int:
    """The byte cap for a file name written into ``directory`` (ADR 0204, rules 2 and 4).

    It is :data:`FILENAME_MAX_BYTES`, made smaller when the directory's absolute path leaves less room
    under the platform path limit. A directory that leaves no room for the fallback name with
    ``suffix`` raises ``ValueError``: every message would fail there, so the configuration is
    refused when the connector is built, not retried at delivery."""
    needs = _FALLBACK_NAME + suffix
    absolute = os.path.abspath(directory)
    room = _path_limit(absolute) - _path_units(absolute) - 1 - _DERIVED_NAME_HEADROOM
    budget = min(FILENAME_MAX_BYTES, room)
    if budget < _name_bytes(needs):
        raise ValueError(
            f"file destination directory {directory} is too deep for this platform's path limit: "
            f"it leaves {max(budget, 0)} bytes for a file name, fewer than the "
            f"{_name_bytes(needs)} the fallback name {needs!r} needs"
        )
    return budget


def _with_suffix(base: str, suffix: str) -> str:
    """``base`` with ``suffix`` appended, unless it already ends with it."""
    return base if base.endswith(suffix) else base + suffix


def _check_template_fits(template: str, suffix: str, max_bytes: int) -> None:
    """Refuse a template whose fixed text alone, with ``suffix``, is over ``max_bytes``: every message
    would fall back, so the configuration is refused when the connector is built (ADR 0204)."""
    fixed = _with_suffix(_sanitize(_PLACEHOLDER.sub("", template)).rstrip(". "), suffix)
    if _name_bytes(fixed) > max_bytes:
        raise ValueError(
            f"filename template's fixed text is {_name_bytes(fixed)} bytes, over the "
            f"{max_bytes}-byte cap for its directory, so every message would fall back"
        )


def render_filename(
    template: str,
    payload: str,
    *,
    fallback: str,
    suffix: str = "",
    max_bytes: int = FILENAME_MAX_BYTES,
) -> str:
    """Resolve ``{HL7-path}`` placeholders in ``template`` against ``payload``, producing a single
    safe filename (never a path).

    Unresolvable placeholders (missing field, or an unparseable payload) fall back to ``fallback``
    so a delivery never fails merely because a name couldn't be built. The result is constrained to
    one path component: unsafe characters are stripped, leading dots removed, and ``.``/``..``/empty
    or a reserved device name falls back — so an attacker-controlled field can't write outside the
    target directory or shadow ``.processed``/``.error`` (FILE-1).

    ADR 0204 adds three things. Trailing dots and spaces are stripped before the reserved-name test,
    because Windows strips them when it opens a name, so ``NUL .hl7`` would open the device. The
    test is :func:`ntpath.isreserved`, which also knows ``CONIN$`` and the superscript-digit ports.
    ``suffix`` is appended here, not by the caller, so the length test sees the final name. And a
    final name longer than ``max_bytes`` UTF-8 bytes falls back, so a long field never reaches the
    filesystem. The caller keeps ``fallback`` plus ``suffix`` within ``max_bytes``."""
    try:
        peek: Peek | None = Peek.parse(payload)
    except HL7PeekError:
        peek = None

    def repl(match: re.Match[str]) -> str:
        if peek is None:
            return fallback
        try:
            value = peek.field(match.group(1))
        except PEEK_READ_FAULTS as exc:
            # A read on an accepted peek is not expected to raise. A blank segment once made it raise
            # IndexError, and uncaught that escaped send() outside the DeliveryError contract
            # (BACKLOG #1623). BACKLOG #1594 fixed the blank segment at the parse; this catch stays
            # for any other parser fault, the same family the pre-ACK callers catch. A name that
            # cannot be read takes the fallback, and the log says so, because a silent fallback
            # hides a parser fault. The path comes from operator config; no field value is logged.
            logger.warning(
                "FILE filename placeholder {%s} read raised %s; using the fallback name",
                match.group(1),
                type(exc).__name__,
            )
            value = None
        return _sanitize(value) if value else fallback

    # Rule 3: strip the trailing dots and spaces Windows would drop, then test what is left.
    name = _sanitize(_PLACEHOLDER.sub(repl, template)).rstrip(". ")
    if not name or ntpath.isreserved(name):
        return _with_suffix(fallback, suffix)
    name = _with_suffix(name, suffix)
    size = _name_bytes(name)
    if size > max_bytes:
        # Rule 2: the final name, suffix included, is judged in encoded bytes before any write. The
        # length is logged and the value is not: a template may name a field that carries PHI.
        logger.warning(
            "rendered output filename is %d bytes, over the %d-byte cap; using the fallback name",
            size,
            max_bytes,
        )
        return _with_suffix(fallback, suffix)
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
        # ADR 0204: the name cap for this directory, judged once here where the platform path limit is
        # known. A directory too deep for even the fallback name is refused now (rule 4).
        self._suffix = ".gz" if self.compress == "gzip" else ""
        self._name_max_bytes = _name_budget(self.directory, self._suffix)
        _check_template_fits(self.filename_template, self._suffix, self._name_max_bytes)
        if self._name_max_bytes < FILENAME_MAX_BYTES:
            # Said once, here, because a smaller cap makes ordinary names fall back, and with
            # overwrite on each fallback replaces the last.
            logger.warning(
                "file destination %s: the directory path leaves %d bytes for a file name, under the "
                "usual %d; longer names fall back to %r%s",
                self.directory,
                self._name_max_bytes,
                FILENAME_MAX_BYTES,
                _FALLBACK_NAME + self._suffix,
                ", and overwrite is on, so each fallback replaces the last"
                if self._overwrite
                else "",
            )
        # Set once a directory fsync has failed here, so it is logged once and not retried (#1618).
        self._dir_fsync_unsupported = False

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
        # The `.gz` suffix signals the on-disk format to a downstream reader (or a gunzip source). It
        # is passed in, not appended after, so the length cap sees the final name (ADR 0204).
        name = render_filename(
            self.filename_template,
            payload,
            fallback=_FALLBACK_NAME,
            suffix=self._suffix,
            max_bytes=self._name_max_bytes,
        )
        target = self.directory / name
        # Defence in depth atop the filename sanitization (FILE-1): never write outside the
        # configured directory even if a name somehow carried a path component. A name that itself
        # carries a separator or is a dot name came from the message, and a retry renders it again:
        # permanent (ADR 0204, rule 1). A resolve that lands outside for any other reason, such as a
        # link at the name or a share that changed form between the two resolves, is the
        # environment, and stays transient. Neither error quotes the name, which reaches the store's
        # last_error and may carry PHI.
        if "/" in name or "\\" in name or name in (".", ".."):
            raise NegativeAckError(
                "file: refusing a file name that is not a single path component",
                code="filename",
                permanent=True,
            )
        if self.directory.resolve() not in target.resolve().parents:
            raise DeliveryError("file: refusing to write outside the destination directory")
        data = encode_wire_body(payload, self.encoding, transport="file")
        if self.compress == "gzip":
            # Deterministic (mtime=0) so a re-delivery of the same body writes identical bytes.
            data = gzip_compress(data)
        # Write to a uniquely-named temp (mkstemp — no shared counter, no name race), then publish
        # atomically. For no-overwrite, claim the final name by exclusive create so two concurrent
        # deliveries can't clobber each other (FILE-5: replaces the TOCTOU exists()-then-rename).
        fd, tmp_name = tempfile.mkstemp(dir=self.directory, suffix=".part")
        tmp = Path(tmp_name)
        consumed = False
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                # Durable BEFORE it is published (BACKLOG #1618). The delivery worker marks the row
                # delivered, durably, the moment send() returns. Without this the bytes could still
                # sit in the page cache then, and a power loss would leave an empty file at the final
                # name that nothing re-delivers. The rename below is atomic for visibility only.
                _flush_to_disk(handle, self.directory)
            if self._overwrite:
                os.replace(tmp, target)  # atomic overwrite; consumes tmp
                consumed = True
            else:
                _claim_unique(tmp, target)  # hard-links (or copies) tmp to a free name
            # The new directory entry belongs to the directory, not the file, so the published NAME
            # needs its own flush to survive a crash as well as the bytes.
            self._fsync_directory()
        finally:
            if not consumed:
                self._remove_temp(tmp)

    @staticmethod
    def _remove_temp(tmp: Path) -> None:
        """Remove the ``.part`` temp, best-effort, and log a WARNING if it stays (BACKLOG #1862).

        Only called while the temp should still exist, so ``FileNotFoundError`` is not treated as
        success: on Windows a dropped UNC share also surfaces as ``FileNotFoundError``, and the
        orphan is still there when the share returns. This never raises. After a claim the target
        is already published, so the delivery must not fail. After a failure, the real error must
        not be replaced by a cleanup error. The temp's name is random from ``mkstemp``, not chosen
        by a partner, so it needs no ``safe_name``."""
        try:
            tmp.unlink()
        except OSError as exc:
            logger.warning(
                "file destination could not remove its temp file %s: %s; a .part file may be left "
                "in the destination directory",
                tmp,
                safe_exc(exc),
            )

    def _fsync_directory(self) -> None:
        """Flush the destination directory's entries after a publish, on POSIX (BACKLOG #1618).

        POSIX makes a rename or a link durable only once the DIRECTORY is fsync'd. Windows exposes no
        directory handle through :func:`os.open`, so there is nothing to call there and this returns.

        A failure is logged rather than raised. The file is already published under its final name
        with its bytes flushed, so failing the delivery now would make the worker retry and publish a
        duplicate beside it. A filesystem that does not SUPPORT a directory fsync (some network mounts
        refuse it outright) is logged once and not asked again, since a WARNING on every delivery there
        would be noise. Any other failure is taken as transient: it is logged and the next publish
        tries again, so one hiccup cannot switch the flush off for the life of the process."""
        if os.name != "posix" or self._dir_fsync_unsupported:
            return
        try:
            dir_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            # A permission refusal on opening the directory (a write-only drop box) is as permanent
            # as an unsupported fsync, and would otherwise warn on every delivery.
            unsupported = exc.errno in _FSYNC_UNSUPPORTED_ERRNOS | {errno.EACCES, errno.EPERM}
            self._dir_fsync_unsupported = unsupported
            logger.warning(
                "file destination %s: the directory could not be fsync'd after a publish (%s); each "
                "file's bytes are still flushed, but a crash may lose a just-published name.%s",
                self.directory,
                safe_exc(exc),
                " Not retried for this destination." if unsupported else "",
            )


class FileSource(SourceConnector):
    """Poll a directory for files and feed each to the pipeline handler."""

    polls_shared_resource = True  # a directory is a shared external resource — leader-gate it

    def __init__(self, config: Source) -> None:
        s = config.settings
        if "directory" not in s:
            raise ValueError("file source requires a 'directory' setting")
        self.directory = Path(s["directory"])
        # Resolved watch root for path-confinement: every read and move walks down from it, so a
        # recursive scan cannot be walked out of the configured directory through a link (BACKLOG
        # #2507, #2535). resolve() is non-strict, so it's fine that the directory is created later.
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
        # BACKLOG #1811 settle gate: the (size, mtime_ns) each not-yet-admitted file showed at the poll
        # that last saw it, and how many scans in a row have since failed to list it, keyed by path. In
        # memory only and never logged. See _settled.
        self._settle_seen: dict[str, tuple[_FileSig, int]] = {}
        # BACKLOG #2507: paths already refused as links, so each is warned about once. See
        # _log_unconfined. In memory only and never logged.
        self._refused: set[str] = set()
        # Opt-in at-start directory validation (#114, ADR 0031 amendment). Default off = the historical
        # run-time deferral (a missing dir is logged-and-retried each poll, never fails start).
        self.validate_directory: bool = bool(s.get("validate_directory", False))
        self.sort: str = s.get("sort", "name")
        if self.sort not in ("name", "mtime"):
            raise ValueError(f"file source sort must be 'name' or 'mtime', got {self.sort!r}")
        self.recursive: bool = bool(s.get("recursive", False))
        # Encoding used to re-encode split batch messages back to bytes for the handler. A single
        # (non-batch) message is handed off verbatim, so its bytes never round-trip through this.
        self.encoding: str = s.get("encoding", "utf-8")
        self.max_file_bytes: int | None = positive_cap(
            s.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES),
            int,
            knob="max_file_bytes",
            transport="file source",
        )
        # Per-tick intake ceiling, SHIPPED ON (DEFAULT_MAX_ITEMS_PER_POLL — the number and the reason a
        # poll source may default this on are stated once, in transports/base.py). Caps how many files
        # ONE scan disposes of; the rest stay in the drop directory and the next scan takes them.
        # None/0 (in any spelling) disables the cap, matching max_file_bytes above.
        self.poll_max_files: int | None = resolve_poll_ceiling(
            s.get("poll_max_files", DEFAULT_MAX_ITEMS_PER_POLL),
            knob="poll_max_files",
            transport="file source",
        )
        # Optional inbound decompression (ADR 0123): "gzip" gunzips each file's bytes BEFORE the sniff /
        # AV scan / batch split (they must see the real HL7). None (default) is byte-identical to before.
        self.decompress: str | None = _validate_compression(s.get("decompress"), "decompress")
        # Bounds the DECOMPRESSED output (a bomb guard `max_file_bytes` — a compressed-`st_size` cap —
        # cannot provide). None/0 disables it. Only consulted when `decompress` is set.
        self.max_decompressed_bytes: int | None = positive_cap(
            s.get("max_decompressed_bytes", DEFAULT_MAX_DECOMPRESSED_BYTES),
            int,
            knob="max_decompressed_bytes",
            transport="file source",
        )
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
        # True while the poll task is inside a store call (a pipeline hand-off or a leave-mode ledger
        # read or write), which stop() never cancels, and when the last one ended, so stop() gives the
        # task a full grace after it (#1620).
        self._in_store_call = False
        self._store_call_ended = 0.0
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
            # Every move opens its archive directory through no link (BACKLOG #2535). One that is
            # already a link at start would refuse every move, so each processed file would be read
            # and handed off again on every other poll. Fail the start instead, naming the fix.
            for dest in (self.processed_dir, self.error_dir):
                try:
                    _open_dest(dest, self.directory, self._root_real).close()
                except _Unconfined:
                    refused = dest.name
                else:
                    continue
                raise SourceStartupError(
                    f"file source archive directory {refused!r} under {self.directory} is a link or a "
                    "junction, and every move would be refused; make it a real directory, or set "
                    "processed_subdir/error_subdir to an absolute path outside the watch directory"
                )

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
                # BACKLOG #290 slice 2: a paused engine skips the whole tick, so no file is listed,
                # read, moved or deleted; it stays in the drop directory for the next open tick.
                if intake_open(self.intake_gate) and self._may_poll():
                    await self._scan_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A scan error (watch dir vanished/unreadable, a bad glob, a move/read failure) must
                # NOT kill the poller — that would silently stop the connection from receiving while
                # it still reports running, and re-raise inside stop()/reload (review H-4). Log and
                # retry on the next interval.
                #
                # Scrubbed, as MLLP's last-resort arm is (BACKLOG #1625): a traceback at ERROR prints
                # the exception text unredacted, and that text can carry a partner-chosen file name.
                # safe_exc redacts and bounds it but cannot swap a name it does not know, so this arm
                # is safer than before, not proven clean. The raising frame's location is kept at
                # ERROR, so a programming error is still findable without DEBUG; the full traceback
                # stays available at DEBUG.
                logger.error(
                    "file source scan failed for %s at %s; retrying next poll: %s",
                    self.directory,
                    _raise_site(exc),
                    safe_exc(exc),
                )
                logger.debug("file source scan failure traceback", exc_info=True)
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
        """Stop polling, bounded even when a share call is blocked (BACKLOG #1620).

        The poll task sees the stop signal between files and between a batch file's hand-offs, so in
        the ordinary case it returns at once. What it cannot do is leave a share call early: every
        list, stat, read and move runs on a thread, and a dead SMB/UNC share holds that thread for the
        OS timeout. So after :data:`_STOP_GRACE_S` the task is cancelled and the abandonment is logged.
        The thread finishes on its own; nothing waits for it.

        **A store call is never cancelled.** That covers a pipeline hand-off (the durable commit) and
        the leave-mode ledger read, write and prune. While the task is inside one, stop() keeps
        waiting in grace-sized steps, as it did before this bound existed: cutting a store call would
        leave its outcome to the backend's cancellation handling, and on a pooled server connection
        possibly the connection's state too. Cancelling anywhere else is safe for count-and-log: a
        file is moved only after every one of its messages is handed off, so an interrupted file is
        re-read whole on the next start (at-least-once, the same shape as a failed hand-off). The
        grace restarts when a store call ends, so the task always gets a full one to reach its next
        stop check before it is cut. The wait is therefore bounded for a blocked SHARE call, and
        only as bounded as the store for a store call.

        The task stays referenced until it has finished, so a second stop() that overlaps the first
        (shutdown during a reload) waits for the same task instead of closing the credential context
        under it."""
        self._stop.set()
        task = self._task
        if task is not None:
            deadline = time.monotonic() + _STOP_GRACE_S
            try:
                while True:
                    timeout = max(0.0, deadline - time.monotonic())
                    done, _pending = await asyncio.wait({task}, timeout=timeout)
                    if done:
                        break
                    if self._in_store_call:
                        # A store call is finishing: never cut it; look again in a grace.
                        deadline = time.monotonic() + _STOP_GRACE_S
                        continue
                    deadline = max(deadline, self._store_call_ended + _STOP_GRACE_S)
                    if time.monotonic() < deadline:
                        continue
                    task.cancel()
                    logger.warning(
                        "file source %s: the poll task did not stop within %.1fs, most likely a share "
                        "call blocked on an unreachable directory; cancelled it. The blocked call "
                        "finishes on its own thread, and any file it was working on is left in place "
                        "and re-read on the next start.",
                        self.directory,
                        _STOP_GRACE_S,
                    )
                    break
            except asyncio.CancelledError:
                # Our caller gave up on this stop. Do not leave the poll task running, but do not cut
                # a store call either: _stop is set, so the task exits at its next stop check.
                if not self._in_store_call:
                    task.cancel()
                raise
            # return_exceptions: a faulted poll task must not re-raise here — stop() runs during
            # reload quiesce, outside its rollback (review H-4). _run already guards scans; this is
            # the belt-and-suspenders. It also collects the cancellation from the arm above.
            await asyncio.gather(task, return_exceptions=True)
            if self._task is task:
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
        candidates = await self._run_fs(self._candidates)
        self._prune_settle(candidates)
        if self._refused:
            self._refused.intersection_update(str(p) for p in candidates)
        disposed = 0  # files this tick finished with — the per-tick ceiling's budget (_at_ceiling)
        for position, path in enumerate(candidates):
            if self._stop.is_set():
                break  # shutting down — leave the rest for the next start (at-least-once)
            if self._at_ceiling(disposed, len(candidates) - position):
                break
            # One stat serves the leave-mode key, the settle gate and the before-read side of the #116
            # partial-write check, so the key recorded below describes the bytes actually read. The size
            # cap is NOT charged here: it is charged on the handle the read opens (BACKLOG #2507).
            try:
                before = await self._run_fs(_file_sig, path)
            except OSError as exc:
                self._log_unreadable(path, exc)
                continue
            # #142 leave-in-place dedup: skip a file this connection already ingested. In-memory set
            # first (no I/O), then the durable ledger (survives restart / a fresh process). Keyed on a
            # HASHED file id (name+mtime+size) — never a cleartext filename, never logged at INFO+.
            file_key: str | None = None
            if self.after_read == "leave":
                file_key = self._file_key(path, before)
                with self._store_call():
                    already = await self._leave_already_ingested(file_key)
                if already:
                    continue
            if not self._settled(path, before):
                # BACKLOG #1811: first sighting, or the file changed since the last poll. Nothing is
                # read, moved or charged against the per-tick budget, the same as #116's skip below.
                continue
            try:
                raw, read_sig, read_id = await self._run_fs(self._read_settled, path)
            except _Unconfined:
                # BACKLOG #2507: left in place, unread and unmoved, and not charged (a stay arm).
                self._log_unconfined(path)
                continue
            except _OverCap as exc:
                # Transport-level reject *before* any message is emitted — parallels MLLP dropping an
                # over-cap frame. It never became a "received message", so (like MLLP) there's no
                # store disposition to record; preserve the file in .error for the operator, log it,
                # and record a connection event as MLLP does (#1621). Charged on the handle (#2507).
                logger.warning(
                    "file %s exceeds max_file_bytes (%s); routing to error dir",
                    safe_name(path.name),
                    self.max_file_bytes,
                )
                archived = await self._run_fs(self._move, path, self.error_dir, exc.file_id)
                if archived:  # a failed move is logged by _move; nothing to record
                    await self._emit_event(
                        "file_oversize",
                        reason=f"{exc} exceeds max_file_bytes {self.max_file_bytes}",
                    )
                disposed += 1
                continue
            except OSError as exc:
                self._log_unreadable(path, exc)
                continue
            self._refused.discard(str(path))  # read cleanly, so a later refusal warns again
            if before != read_sig or len(raw) != read_sig[0]:
                # BACKLOG #116: a partner is still writing this file in place. Emitting what was read
                # would pass a cut-off message as a complete one, so leave it for the next scan. Not
                # charged against the per-tick budget: nothing was handed off and nothing moved.
                logger.warning(
                    "file source %s: %s changed while it was read (%d bytes before, %d read, %d "
                    "after); not emitted, left in place for the next scan",
                    self.directory,
                    safe_name(path.name),
                    before[0],
                    len(raw),
                    read_sig[0],
                )
                # The file is still moving, so it must settle again from its latest stat (#1811).
                self._remember_sig(path, read_sig)
                continue
            if self.decompress == "gzip":
                # Decompress BEFORE the sniff, the AV/ICAP scan, and the batch split (ADR 0123): each
                # must see the REAL bytes, not the gzip container. The ceiling bounds the decompressed
                # output (and therefore post-split expansion) — the compressed-`st_size`
                # `max_file_bytes` cap above cannot. A corrupt / oversized archive is quarantined like an oversize /
                # non-HL7 reject: it never became a received message, so there is no store disposition;
                # move the ORIGINAL compressed file to .error and log the CODEC message only (never the
                # decompressed body — it is PHI).
                try:
                    raw = await asyncio.to_thread(
                        gzip_decompress, raw, max_output_bytes=self.max_decompressed_bytes
                    )
                except CompressionError as exc:
                    logger.warning(
                        "file %s failed to gunzip (%s); routing to error dir",
                        safe_name(path.name),
                        safe_exc(exc, file_name=path.name),
                    )
                    archived = await self._run_fs(self._move, path, self.error_dir, read_id)
                    if archived:  # a failed move is logged by _move; nothing to record
                        await self._emit_event(
                            "file_decompress_failed", reason=safe_exc(exc, file_name=path.name)
                        )
                    disposed += 1
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
                declared = (self.content_type or ContentType.HL7V2).value
                logger.warning(
                    "file %s does not match its declared content type %r (no matching magic bytes); "
                    "routing to error dir",
                    safe_name(path.name),
                    declared,
                )
                archived = await self._run_fs(self._move, path, self.error_dir, read_id)
                if archived:  # a failed move is logged by _move; nothing to record
                    await self._emit_event(
                        "file_content_mismatch",
                        reason=f"does not match declared content type {declared}",
                    )
                disposed += 1
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
                    safe_name(path.name),
                    safe_exc(exc, file_name=path.name),
                )
                archived = await self._run_fs(self._move, path, self.error_dir, read_id)
                if archived:  # a failed move is logged by _move; nothing to record
                    await self._emit_event(
                        "file_scan_rejected", reason=safe_exc(exc, file_name=path.name)
                    )
                disposed += 1
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
                    safe_name(path.name),
                    safe_exc(exc, file_name=path.name),
                )
                continue
            try:
                with self._store_call():
                    completed = await self._emit(raw)
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
                logger.warning(
                    "handler failed for %s (will retry next scan): %s",
                    safe_name(path.name),
                    safe_exc(exc, file_name=path.name),
                )
                continue
            if not completed:
                # Stopped between a batch file's hand-offs (#1620). The file stays put, so the next
                # start re-reads it whole and re-emits every message (at-least-once, no dropped tail).
                logger.info(
                    "file source %s: stopping mid-batch; %s left in place to be re-read on the next "
                    "start",
                    self.directory,
                    safe_name(path.name),
                )
                break
            await self._run_fs(self._after_processing, path, read_sig, read_id)
            disposed += 1
            if self.after_read == "leave" and file_key is not None:
                # Record AFTER emit success (the FILE — not each split message — is the dedup unit), so a
                # partial-emit crash re-reads and re-emits the whole file (at-least-once), never dropping.
                with self._store_call():
                    await self._leave_record(file_key)
                newly_recorded += 1
        if newly_recorded and self.processed_ledger is not None and not self._stop.is_set():
            # Bound the ledger's growth (age + count); only when this tick recorded something, so a stable
            # read-only share (nothing new) never churns the store.
            with self._store_call():
                await self.processed_ledger.prune()

    async def _emit_event(self, kind: str, *, reason: str | None = None) -> None:
        """Record a quarantine in the connection-event log (BACKLOG #1621), **fail-soft**.

        A quarantined file never became a received message, so there is no disposition to record; it
        was preserved in ``.error`` and logged. What was missing is a STORE record an operator watching
        the console can see, which the MLLP over-cap arm has always written (``frame_oversize``). The
        reason carries a size, a content type or a scrubbed codec or scanner message, and never the
        file name, which a partner may build from an MRN.

        An emit problem must never wedge the poll loop (pure observer). A no-op when the runner has not
        injected the sink. No ``peer_host``: a directory has no peer, so the column stays ``NULL``,
        as for the DATABASE poll source."""
        sink = self.on_connection_event
        if sink is None:
            return
        try:
            await sink(kind, None, reason)
        except Exception as exc:  # noqa: BLE001 - observer only; a capture bug can't stop ingest
            logger.warning("file source connection-event emit failed: %s", safe_exc(exc))

    @contextmanager
    def _store_call(self) -> Iterator[None]:
        """Mark the poll task as inside a store call, which :meth:`stop` never cancels (#1620)."""
        self._in_store_call = True
        try:
            yield
        finally:
            self._in_store_call = False
            self._store_call_ended = time.monotonic()

    def _at_ceiling(self, disposed: int, remaining: int) -> bool:
        """True when this scan has spent its per-tick budget (``poll_max_files``) and must stop, leaving
        ``remaining`` candidates for the next scan.

        **Nothing is dropped.** A file this scan does not reach is still in the drop directory, so the
        next scan takes it — the same at-least-once deferral a transient read failure already produces.
        No message was received, so there is no disposition to record and the count-and-log invariant is
        untouched.

        **What charges the budget, and why the exceptions are not an oversight.** Only a file this scan
        FINISHED with charges: one handed to the pipeline, or one quarantined to ``.error`` (oversize,
        a failed gunzip, a content-vs-type mismatch, a scanner rejection). Each of those leaves the
        candidate set, so the next scan starts on new work. The arms that leave a file **in place** to be
        retried — a file not yet settled (#1811) or changed during the read (#116), a locked/vanished
        file, a malfunctioning scan hook, a handler failure — deliberately do
        NOT charge. If they did, a permanently stuck file that sorts early would eat the whole budget on
        every scan and the healthy files behind it would never be ingested. A budget can only be charged
        by something that makes progress.

        This bounds the INGEST, not the listing: ``_candidates`` still globs and sorts the whole
        directory, because picking the first N in name/mtime order requires seeing all of them. The
        per-file cost the ceiling removes is the read, the scan hook, the pipeline hand-off and the
        durable commit — not the stat."""
        if self.poll_max_files is None or disposed < self.poll_max_files:
            return False
        logger.info(
            "file source %s reached poll_max_files (%s) this scan; %d candidate(s) left for the next "
            "poll (deferred, not dropped)",
            self.directory,
            self.poll_max_files,
            remaining,
        )
        return True

    def _file_key(self, path: Path, sig: _FileSig | None = None) -> str:
        """A stable, HASHED identity for a source file, for the leave-in-place dedup ledger (#142).

        The identity folds the file's path **relative to the watch root** (not just the basename) +
        mtime + size, so that under ``recursive=True`` two DISTINCT files that share a basename in
        different subdirectories — and, on a timestamp-preserving copy over a coarse-mtime share, also
        share mtime+size — hash to DIFFERENT keys and are BOTH ingested (never one silently deduped away,
        which would be an accept-and-drop of a received file, count-and-log invariant). SHA-256 so the
        relative path — which, like a filename, can embed an MRN — is never stored or logged in the clear
        (the ledger holds this derived id only; never log the relative path). Folding mtime+size in means
        an UPDATED file (new mtime/size → new key) is re-ingested, while an unchanged file is skipped.
        ``sig`` is a stat the caller already holds; without one this stats the file, and may raise
        ``OSError`` if it vanished mid-scan (the caller treats that as transient)."""
        size, mtime_ns = _file_sig(path) if sig is None else sig
        rel = path.relative_to(self.directory).as_posix()
        ident = f"{rel}\x00{mtime_ns}\x00{size}"
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

    def _settled(self, path: Path, sig: _FileSig) -> bool:
        """True when ``path`` shows the same ``(size, mtime_ns)`` it showed at the last poll that looked
        at it, which admits it for reading (BACKLOG #1811). Otherwise remember ``sig`` and return False,
        so the file waits for a later poll. "The last poll that looked at it" is usually the previous
        one; a file past the per-tick ceiling's break keeps an older sighting, which is only ever
        compared as "unchanged since then" and so is still safe.

        **Why this and not #116 alone.** #116 compares a stat before and after the read inside ONE scan,
        so it only sees a write that lands during the read. A partner that writes, pauses, then writes
        again leaves a file that is still for the length of the read, and #116 passes the first part
        as a complete message. This gate compares across polls, so a pause shorter than
        ``poll_seconds`` is seen.

        **Always on, with no setting.** The failure it prevents is a truncated clinical message that is
        accepted and indistinguishable downstream from a complete one, so an off switch would only be a
        way to reopen it. The cost is one poll of latency per file, which ``poll_seconds`` controls.
        ``min_age_seconds`` is not this gate: it defaults to 0, and even when set it compares the mtime
        with the clock rather than with an earlier sighting.

        **What it cannot see.** At least these three:

        - a writer that pauses for longer than ``poll_seconds``. The window is ``poll_seconds`` wide,
          so a very small ``poll_seconds`` narrows it to almost nothing;
        - a same-length rewrite inside the share's mtime resolution;
        - a copier that sets the final size first and holds the mtime fixed while it fills the file
          in, which leaves both size and mtime unchanged between polls.

        The partner's write-then-rename covers all of them. A ``min_age_seconds`` longer than the
        partner's pause covers the first.

        An admitted file leaves the map. If it is then left in place for a retry, it settles again
        before the next attempt, which is the safe reading of a file nobody finished with. It also
        means a retry after a read, scan-hook or hand-off failure waits one extra poll. A file that
        changed during the read (#116) is re-recorded from its post-read stat instead, so it can be
        admitted on the very next poll."""
        key = str(path)
        seen = self._settle_seen.get(key)
        if seen is not None and seen[0] == sig:
            del self._settle_seen[key]
            return True
        recorded = self._remember_sig(path, sig)
        # safe_name hashes the name, so skip it when nobody reads the line.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "file source %s: %s not yet settled (%d bytes); %s",
                self.directory,
                safe_name(path.name),
                sig[0],
                "waiting for the next poll to agree"
                if recorded
                else f"settle memory is full ({SETTLE_SEEN_MAX}), so it waits for room",
            )
        return False

    def _remember_sig(self, path: Path, sig: _FileSig) -> bool:
        """Record ``sig`` as this poll's sighting of ``path`` and return True. At ``SETTLE_SEEN_MAX`` a
        path not already recorded is left out and this returns False, so it waits for room (see that
        constant for why this is not eviction)."""
        key = str(path)
        if key in self._settle_seen or len(self._settle_seen) < SETTLE_SEEN_MAX:
            self._settle_seen[key] = (sig, 0)
            return True
        return False

    def _prune_settle(self, candidates: list[Path]) -> None:
        """Forget a file once ``SETTLE_MISS_LIMIT`` scans in a row have not listed it (moved, deleted,
        renamed away), so the settle map is bounded by the drop directory rather than by every name it
        ever held. A file listed again has its count reset. Waiting for several misses, rather than
        forgetting on the first, keeps a listing that fails now and then from restarting every wait."""
        if not self._settle_seen:
            return
        listed = {str(p) for p in candidates}
        for key, (sig, missed) in list(self._settle_seen.items()):
            if key in listed:
                if missed:
                    self._settle_seen[key] = (sig, 0)
            elif missed + 1 >= SETTLE_MISS_LIMIT:
                del self._settle_seen[key]
            else:
                self._settle_seen[key] = (sig, missed + 1)

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

    async def _emit(self, raw: bytes) -> bool:
        """Hand every HL7 message in ``raw`` to the pipeline handler, in file order (FIFO). Returns
        ``False`` when a stop arrived between a batch's hand-offs and the rest were not handed off
        (BACKLOG #1620): the caller then leaves the file in place, so the next start re-emits it whole.

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
            return True
        try:
            text = raw.decode(self.encoding)
        except (UnicodeDecodeError, LookupError):
            # Not decodable in the declared encoding (or an unknown codec name): can't safely find MSH
            # boundaries, so hand the raw bytes off unchanged — the pipeline's strict-decode then
            # records ERROR for it, exactly as in the pre-split single-hand-off path. Never a drop.
            await self._handler(raw)
            return True
        messages = split_batch(
            text
        )  # str in → no UTF-8 re-decode (normalize only fixes line endings)
        if len(messages) == 1:
            # Fast path / strict back-compat: a lone message is handed off verbatim (its original
            # bytes), so a non-batch file behaves byte-for-byte as before the split was introduced.
            await self._handler(raw)
            return True
        for message in messages:
            if self._stop.is_set():
                return False  # stopping: the rest are re-emitted with the whole file next start
            # FIFO per connection: emit in file order, awaiting each so a slow/failing hand-off
            # back-pressures the rest (and a failure stops the file from being moved — see above).
            await self._handler(message.encode(self.encoding))
        return True

    def _candidates(self) -> list[Path]:
        """Files ready to process, honoring recursion, min-age, and sort order.

        **The per-tick ceiling bounds the INGEST, not this listing, and the asymmetry is real rather
        than an oversight.** Selecting the first N in name or mtime order requires knowing the whole
        candidate set, so the glob and the per-candidate screens below are paid every tick regardless
        of the ceiling. In steady state that is unchanged from before the ceiling existed. Draining a
        LARGE backlog is where it bites: the ceiling turns one expensive tick into many, so this
        listing is now paid once per tick over a shrinking set instead of once in total.

        Bounding it properly is a separate change and a real one -- deferring the ``lstat`` screen
        into the scan loop so they are paid only for candidates actually reached,
        which is available under ``sort="name"`` because that key needs no syscall, and not under
        ``sort="mtime"`` because the key IS the syscall. It also costs the accurate ``remaining``
        count the ceiling's log line carries. Not folded in here: it changes what the screens mean
        for the ceiling's budget, and this method's contract is worth keeping simple."""
        globber = self.directory.rglob if self.recursive else self.directory.glob
        try:
            matched = list(globber(self.pattern))
        except (OSError, ValueError) as exc:
            # Watch dir vanished/unreadable, or an invalid glob pattern: treat as "nothing this
            # scan" (logged) rather than letting it propagate and kill the poller (review H-4).
            logger.warning(
                "file source could not list %s (pattern %r): %s",
                self.directory,
                self.pattern,
                _describe_os_error(exc),
            )
            return []
        files = [
            p
            for p in matched
            if self.processed_dir not in p.parents
            and self.error_dir not in p.parents
            and self._listable(p)
        ]
        # Decorate-sort-undecorate under `sort="mtime"`: the min-age filter and the sort key are the
        # SAME stat, and reading it twice per candidate doubled the syscalls on the one path that
        # already pays the most. That cost is charged on every tick, and the per-tick ceiling means a
        # backlog is now drained over many ticks rather than one, so a redundant stat is multiplied
        # by the number of ticks it takes to drain. Under `sort="name"` the key is pure and no stat
        # is needed at all.
        if self.sort == "mtime":
            cutoff = time.time() - self.min_age_seconds if self.min_age_seconds > 0 else None
            dated = [(_mtime(p), p) for p in files]
            if cutoff is not None:
                dated = [pair for pair in dated if pair[0] <= cutoff]  # still being written
            dated.sort(key=lambda pair: pair[0])
            return [p for _, p in dated]
        if self.min_age_seconds > 0:
            cutoff_name = time.time() - self.min_age_seconds
            files = [p for p in files if _mtime(p) <= cutoff_name]  # skip files still being written
        files.sort(key=lambda p: p.name)
        return files

    def _listable(self, path: Path) -> bool:
        """Whether a listed name is a candidate, judged without following a link at that name
        (BACKLOG #2535).

        Nothing here resolves a name: a listed name is confined when it is OPENED
        (:func:`_open_confined`), which refuses one reached through any link below the root. A
        ``resolve()`` here used to screen it first, and that opened whatever a link at the name
        named, so on Windows a link to a UNC path or a pipe reached its server before any refusal.

        A link at the name is kept UNRESOLVED, so the read refuses it and says so once. A link to a
        directory is dropped on Windows, which marks one, as any directory is. A POSIX link carries no
        such mark, so every POSIX link is kept and refused at the read."""
        try:
            st = path.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode) or _names_another_path(st):
            return not getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_DIRECTORY
        return stat.S_ISREG(st.st_mode)

    def _read_settled(self, path: Path) -> tuple[bytes, _FileSig, _FileId]:
        """Read ``path``, then stat it, in one hop off the event loop (BACKLOG #116).

        The caller compares that stat and the bytes read with the stat it took before the read, so a
        file a partner is still writing in place is caught before it is emitted. The read is
        :func:`_read_confined` (BACKLOG #2507), a module function so tests can patch it to stand in
        for a locked or growing file. The third item is the identity of the file the read handle
        held, which the move or delete checks against (BACKLOG #2535)."""
        raw, file_id = _read_confined(path, self.directory, self._root_real, self.max_file_bytes)
        return raw, _file_sig(path), file_id

    def _log_unconfined(self, path: Path) -> None:
        """WARNING the first time a path is refused, DEBUG after, so a link left in the drop directory
        does not write one WARNING per poll for as long as it stays. The memory is bounded like the
        settle map's and forgets a path once a scan no longer lists it."""
        key = str(path)
        if key in self._refused:
            logger.debug("file source: still refusing %s", safe_name(path.name))
            return
        if len(self._refused) < SETTLE_SEEN_MAX:
            self._refused.add(key)
        logger.warning(
            "file source: refusing %s; it is a symbolic link, is reached through a link or a "
            "junction, or is not a regular file. Left in place; not read, moved or deleted",
            safe_name(path.name),
        )

    def _pinned(self, path: Path, read_id: _FileId | None) -> _Pin | None:
        """:func:`_pin_confined` for a move or delete, or None when it refuses or cannot check, logged
        (BACKLOG #2507). The read's check does not carry over: the hand-off, the scan hook and a thread
        hop sit between it and the move. The caller closes the pin.

        ``read_id`` is the identity of the file the read handle held. The pin must hold that same
        file, so a file renamed over the name after the read is left for the next scan to read
        rather than archived or deleted unread (BACKLOG #2535). None skips that compare; only a
        direct caller with no read passes it.

        A check that fails for an ordinary reason also leaves the file in place: moving a file that
        cannot be checked is not known to be safe."""
        try:
            return _pin_confined(path, self.directory, self._root_real, read_id)
        except _Unconfined:
            self._log_unconfined(path)
        except _Replaced:
            logger.warning(
                "file source: %s was replaced after it was read; left in place for the next scan to "
                "read",
                safe_name(path.name),
            )
        except OSError as exc:
            logger.warning(
                "could not check %s before moving or deleting it (left in place for the next scan): %s",
                safe_name(path.name),
                _describe_os_error(exc, file_name=path.name),
            )
        return None

    @staticmethod
    def _log_unreadable(path: Path, exc: OSError) -> None:
        """Transient (file locked / vanished mid-scan): the caller leaves it in place to retry next
        scan rather than quarantining a healthy file. Logged, never silently swallowed."""
        logger.warning(
            "could not read %s (will retry next scan): %s",
            safe_name(path.name),
            safe_exc(exc, file_name=path.name),
        )

    def _changed_since_read(self, path: Path, read_sig: _FileSig) -> bool:
        """True, with a WARNING, when ``path`` no longer matches the stat taken as it was read (#116).

        The message is already handed off by then and cannot be recalled. What this stops is the move
        or delete that would carry the unread tail away as processed. The file stays put and the next
        scan reads it whole; under ``leave`` its dedup key has changed with it, so the same holds. A file
        that is gone, or cannot be stat'd, is not reported as changed: the move or delete reports it."""
        try:
            now = _file_sig(path)
        except OSError:
            return False
        if now == read_sig:
            return False
        logger.warning(
            "file source %s: %s changed after it was read (%d bytes read, %d now); the message emitted "
            "from it may be incomplete, so the file is left in place for the next scan to read whole",
            self.directory,
            safe_name(path.name),
            read_sig[0],
            now[0],
        )
        return True

    def _after_processing(
        self, path: Path, read_sig: _FileSig | None = None, read_id: _FileId | None = None
    ) -> None:
        # ``read_sig`` and ``read_id`` None are a direct caller with no read to compare against:
        # dispose as before.
        if read_sig is not None and self._changed_since_read(path, read_sig):
            return
        if self.after_read == "leave":
            # #142 process-in-place: never move or delete the source file — the durable dedup ledger
            # (recorded by _scan_once AFTER this returns) is what stops it being re-ingested next poll.
            return
        if self.after_read == "delete":
            pin = self._pinned(path, read_id)
            if pin is None:
                return
            with pin:
                try:
                    _remove_pinned(pin)
                except OSError as exc:
                    # A processed file we can't delete will be re-read (duplicate); surface it (FILE-4).
                    logger.warning(
                        "could not delete processed file %s: %s",
                        safe_name(path.name),
                        safe_exc(exc, file_name=path.name),
                    )
        else:
            self._move(path, self.processed_dir, read_id)

    def _move(self, path: Path, dest_dir: Path, read_id: _FileId | None = None) -> bool:
        """Archive ``path`` into ``dest_dir`` under a name claimed ATOMICALLY (BACKLOG #1046). Returns
        whether a copy now sits in ``dest_dir``. A quarantine is recorded only then (BACKLOG #1621): a
        file that could not be archived at all is logged here and examined again next scan.

        Only a file :meth:`_pinned` passes is moved, and only if it is the file that was read
        (``read_id``, BACKLOG #2535). On POSIX the claim and the unlink name it relative to its checked
        parent directory (BACKLOG #2507), and the claimed name is checked to be that same file. On
        Windows the move acts on the checked handle itself: one rename by handle, or a copy from the
        handle and a delete by handle where the archive is on another volume. So every archive and
        quarantine refuses a link swapped in since the read, on either platform. The archive directory
        itself is opened afresh for each move through no link (:func:`_open_dest`), so a link put in
        place of ``.processed`` or ``.error`` after start is refused too and nothing is written through
        it.

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
        already had, and logged the same way. A Windows rename by handle moves the file in one step,
        so there the original cannot stay behind."""
        pin = self._pinned(path, read_id)
        if pin is None:
            return False
        with pin:
            try:
                with _open_dest(dest_dir, self.directory, self._root_real) as dest:
                    gone = _archive(pin, dest, path.name)
            except OSError as exc:
                # A stuck file (locked / dest unwritable) stays and is re-read; log it (FILE-4).
                # No path in the log: the claim may fail on a BUMPED name (``name-1.ext``), which
                # safe_exc's file_name swap does not match, so the OS text stands in for the message.
                logger.warning(
                    "could not move %s to %s: %s",
                    safe_name(path.name),
                    dest_dir.name,
                    _describe_os_error(exc, file_name=path.name),
                )
                return False
            if not gone:
                try:
                    _remove_pinned(pin)
                except OSError as exc:
                    logger.warning(
                        "archived %s to %s but could not remove the original (it will be re-read): "
                        "%s",
                        safe_name(path.name),
                        dest_dir.name,
                        safe_exc(exc, file_name=path.name),
                    )
        return True  # archived, even if the original stayed and will be re-read


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


#: ``os.rename`` on Windows refuses to replace an existing file (``FileExistsError``) and is atomic, so
#: it can publish a finished file under a free name with no placeholder. POSIX ``rename`` silently
#: replaces instead, so that arm claims the name first (see :func:`_publish_staged`). Module-level so a
#: test can drive the POSIX arm on a Windows runner; it is never reassigned at run time.
_RENAME_REFUSES_OVERWRITE = os.name == "nt"


#: errno values meaning "this filesystem does not support fsync here", not "the flush failed". Some
#: FUSE, WebDAV and network mounts answer an fsync this way; a failed flush (EIO, ENOSPC) never does.
_FSYNC_UNSUPPORTED_ERRNOS = frozenset(
    {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, getattr(errno, "ENOSYS", errno.EINVAL)}
)

#: Directories where a file fsync has been refused as unsupported, so each is logged once.
_fsync_unsupported_dirs: set[Path] = set()


def _flush_to_disk(handle: BinaryIO, directory: Path) -> None:
    """Flush ``handle`` and fsync it, before its file is published anywhere (BACKLOG #1618).

    A filesystem that does not SUPPORT fsync is logged once and not treated as a failure: the write
    worked before this flush existed, and turning an unsupported flush into a delivery error would
    make such a destination fail forever on a lane that retries. A real flush failure (EIO, ENOSPC)
    still raises, because then the bytes are not known to be on disk."""
    handle.flush()
    try:
        os.fsync(handle.fileno())
    except OSError as exc:
        if exc.errno not in _FSYNC_UNSUPPORTED_ERRNOS:
            raise
        if directory not in _fsync_unsupported_dirs:
            _fsync_unsupported_dirs.add(directory)
            logger.warning(
                "file transport: the filesystem under %s does not support fsync (%s); files written "
                "there are placed without a durable flush, so a crash may leave one empty. Logged "
                "once per directory.",
                directory,
                safe_exc(exc),
            )


def _claim_unique(
    tmp: Path,
    target: Path,
    *,
    src_dir_fd: int | None = None,
    expect: _FileId | None = None,
    dst_dir_fd: int | None = None,
) -> Path:
    """Publish ``tmp``'s bytes at ``target`` (or ``name-1.ext``, ``name-2.ext``, … if taken), never
    clobbering an existing file and never consuming ``tmp``.

    Prefers ``os.link`` (the target becomes a hard link to ``tmp``); ``FileExistsError`` means the
    name is taken, so claiming a free name is a single atomic step — no check-then-act window where
    a concurrent writer could clobber us.

    Where hard links aren't usable from ``tmp`` (FAT/exFAT, many SMB/NAS mounts, or ``tmp`` on another
    filesystem), the bytes are first copied to a staging temp INSIDE the target directory and flushed,
    and only that finished file is published (BACKLOG #1622). The fallback used to claim the final name
    with an empty ``O_EXCL`` file and fill it in place, so a reader polling the directory could pick up
    an empty or partial file under the final name on exactly the filesystems the fallback exists for
    (review low-5). The staged copy is published by a second ``os.link`` where the first failed only
    for being cross-filesystem, else by :func:`_publish_staged`.

    ``src_dir_fd`` names ``tmp`` relative to that directory descriptor (the archive move, #2507).
    ``expect`` is the identity of the file that was read: the claim then publishes only that file,
    and raises :class:`_Replaced` if the name now leads to another (BACKLOG #2535). ``dst_dir_fd`` is
    the archive directory, opened through no link: every name the claim makes is then made relative
    to it, so a link put where the directory was cannot redirect the claim (BACKLOG #2535)."""
    claimed = _link_free_name(
        tmp, target, src_dir_fd=src_dir_fd, expect=expect, dst_dir_fd=dst_dir_fd
    )
    if claimed is not None:
        return claimed
    with open(
        tmp, "rb", opener=lambda name, flags: _open_regular(name, flags, src_dir_fd, expect)
    ) as reader:
        staged = _stage_copy(reader, target.parent, dst_dir_fd)
    return _claim_staged(staged, target, dst_dir_fd)


def _claim_staged(staged: Path, target: Path, dir_fd: int | None = None) -> Path:
    """Publish a finished ``staged`` copy at the first free name from ``target``, and remove it if
    that fails: by a second ``os.link`` where one is possible, else by :func:`_publish_staged`. With
    ``dir_fd`` both names are relative to that directory."""
    consumed = False
    try:
        claimed = _link_free_name(_at(staged, dir_fd), target, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        if claimed is None:
            claimed = _publish_staged(staged, target, dir_fd)
            consumed = True  # renamed onto the final name, so there is no staged file left
        return claimed
    finally:
        # After a link the staged name is a second link to the published file, and after a failure
        # it is a full copy. Either way it must go, and a failure to remove it must be heard.
        if not consumed:
            _discard(staged, dir_fd)


def _free_names(target: Path) -> Iterator[Path]:
    """``target``, then ``name-1.ext``, ``name-2.ext``, … — the order every claim walks."""
    yield target
    n = 0
    while True:
        n += 1
        yield target.with_name(f"{target.stem}-{n}{target.suffix}")


def _at(path: Path, dir_fd: int | None) -> Path:
    """``path`` as a call should name it: its bare name when it is relative to ``dir_fd``."""
    return Path(path.name) if dir_fd is not None else path


def _link_free_name(
    source: Path,
    target: Path,
    *,
    src_dir_fd: int | None = None,
    expect: _FileId | None = None,
    dst_dir_fd: int | None = None,
) -> Path | None:
    """Hard-link ``source`` to the first free name from ``target``, or return ``None`` when a hard link
    cannot be made here at all (unsupported filesystem, or ``source`` on another one).

    A link at ``source`` is linked as itself, never followed to its target (BACKLOG #2507): the
    archive move passes a partner-writable name, and following it could put an outside file in
    ``.error`` or ``.processed``. With ``expect``, the new name must be that file: whatever sat at
    ``source`` when the link was made is what it names, so a file or link swapped in after the
    caller's check is caught here, its link removed and :class:`_Replaced` raised (BACKLOG #2535).
    With ``dst_dir_fd`` the new name is made in that directory."""
    for candidate in _free_names(target):
        name = _at(candidate, dst_dir_fd)
        try:
            # Windows refuses the keyword even as True, so it is passed only where it is listed.
            if _LINK_TAKES_NOFOLLOW:
                os.link(
                    source,
                    name,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=False,
                )
            else:
                os.link(source, name)
        except FileExistsError:
            continue
        except OSError:
            return None  # not a taken name: links are unusable here, so the caller copies instead
        if expect is not None:
            try:
                same = _file_id(os.stat(name, dir_fd=dst_dir_fd, follow_symlinks=False)) == expect
            except OSError:
                same = False  # cannot show it is the file read, so it must not stay archived
            if not same:
                _discard(candidate, dst_dir_fd)
                raise _Replaced("not the file that was read")
        return candidate
    raise AssertionError("unreachable: _free_names never ends")  # pragma: no cover


def _stage_copy(reader: BinaryIO, directory: Path, dir_fd: int | None = None) -> Path:
    """Copy ``reader`` to a new private temp in ``directory`` and flush it, returning the temp.

    ``mkstemp`` creates it 0o600 (owner-only): delivered files can carry PHI, so the copy fallback
    must not be the one path that leaves them world-readable. Streamed, not ``read_bytes()``: the
    archive move claims through here too (#1046), and an inbound file is only as small as the
    operator's ``max_file_bytes`` (unset by default).

    A copy that dies mid-stream (a full volume, a dropped share) removes its temp and re-raises, so a
    failure never leaves a truncated, PHI-bearing file behind. The cleanup is a ``finally`` rather
    than an ``except`` so nothing is caught or relabelled; it runs after the ``with`` has closed the
    handle, which Windows requires before an unlink. Deliberately not the ``except BaseException``
    the persistent-connection connectors use: this function is sync, so no ``CancelledError`` can
    arrive mid-copy, and a wider catch would breach section 6 of CLAUDE.md for nothing.

    The caller opens ``reader``: by name through :func:`_open_regular` (BACKLOG #2507, #2535), or,
    on Windows, from the checked handle itself, so the copy reads only the file that was checked.
    With ``dir_fd`` the temp is made in that directory, 0o600 the same way."""
    if dir_fd is None:
        fd, name = tempfile.mkstemp(dir=directory, suffix=".part")
        staged = Path(name)
    else:
        fd, staged = _mkstemp_at(directory, dir_fd)
    placed = False
    try:
        with os.fdopen(fd, "wb") as handle:
            shutil.copyfileobj(reader, handle)
            _flush_to_disk(
                handle, directory
            )  # durable before anyone can see it under the final name (#1618)
        placed = True
    finally:
        if not placed:
            _discard(staged, dir_fd)
    return staged


def _mkstemp_at(directory: Path, dir_fd: int) -> tuple[int, Path]:
    """``tempfile.mkstemp`` relative to ``dir_fd``, which ``mkstemp`` cannot take: a new 0o600 file
    under a fresh ``.part`` name, created exclusively. Returns its descriptor and its path.

    The name needs to be unused, not secret: ``O_EXCL`` refuses one that exists, link or not, and the
    loop then takes the next."""
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    while True:
        name = f"tmp{os.getpid():x}-{time.monotonic_ns():x}.part"
        try:
            return os.open(name, flags, 0o600, dir_fd=dir_fd), directory / name
        except FileExistsError:
            continue


def _publish_staged(staged: Path, target: Path, dir_fd: int | None = None) -> Path:
    """Move a finished ``staged`` file to the first free name from ``target``, never clobbering. With
    ``dir_fd`` both names are relative to that directory.

    **Windows:** ``os.rename`` is atomic and refuses an existing name, so the file appears whole or not
    at all.

    **POSIX without hard links** (a vfat or exFAT mount, some CIFS and FUSE mounts): the standard
    library has no rename that refuses to replace, so the name is claimed with an empty ``O_EXCL``
    placeholder and the finished file is renamed over it at once. A reader polling the directory can
    therefore see an EMPTY file at the final name for the moment between those two calls. No bytes are
    copied in that window, so it is far narrower than the in-place fill this replaced, and never a
    partial file, but it is not zero. That residual is stated rather than claimed away."""
    for candidate in _free_names(target):
        if _RENAME_REFUSES_OVERWRITE:
            try:
                os.rename(staged, candidate)
            except FileExistsError:
                continue
            return candidate
        try:
            placeholder = os.open(
                _at(candidate, dir_fd), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=dir_fd
            )
        except FileExistsError:
            continue
        try:
            os.close(placeholder)  # a deferred write error can surface here on a network mount
            # Over our OWN placeholder, never someone else's file.
            os.replace(
                _at(staged, dir_fd), _at(candidate, dir_fd), src_dir_fd=dir_fd, dst_dir_fd=dir_fd
            )
        except OSError:
            _discard(candidate, dir_fd)  # the placeholder is ours and empty; do not leave it there
            raise
        return candidate
    raise AssertionError("unreachable: _free_names never ends")  # pragma: no cover


def _discard(path: Path, dir_fd: int | None = None) -> None:
    """Remove a staging temp or an unused placeholder, logging rather than raising if it cannot go.
    With ``dir_fd`` the name is removed relative to that directory.

    Cleanup must never DISPLACE the failure that caused it. A drop directory is one other processes
    watch by design, so a scanner or a reader holding the file open is ordinary here, and an escaping
    unlink error would hide the full volume or dropped share behind a cleanup message.

    Only called while the file should still exist, so ``FileNotFoundError`` is not taken as success:
    on Windows a dropped UNC share surfaces as ``FileNotFoundError`` too, and the copy is still there
    when the share returns (the same reading as ``FileDestination._remove_temp``, BACKLOG #1862).

    The name is logged as a safe label (BACKLOG #1625): on the archive move a placeholder carries the
    partner's own file name, and the ``OSError`` renders that path into its message too."""
    try:
        if dir_fd is None:
            path.unlink()
        else:
            os.unlink(path.name, dir_fd=dir_fd)
    except OSError as exc:
        logger.warning(
            "could not remove the file %s after a failed claim: %s",
            safe_name(path.name),
            safe_exc(exc, file_name=path.name),
        )


def _raise_site(exc: BaseException) -> str:
    """Where in THIS module ``exc`` came from, as ``file.py:line in function``: code coordinates,
    never data. The innermost frame is usually inside ``os`` or ``pathlib`` after a thread hop, which
    locates nothing, so the deepest frame of this module wins. No source line is read (no linecache
    I/O on the event loop)."""
    site = None
    for frame, lineno in traceback.walk_tb(exc.__traceback__):
        if frame.f_code.co_filename == __file__:
            site = (lineno, frame.f_code.co_name)
    if site is None:
        return "an unknown location in file.py"
    return f"file.py:{site[0]} in {site[1]}"


def _describe_os_error(exc: OSError | ValueError, *, file_name: str | None = None) -> str:
    """A log-safe account of a filesystem error whose path may be partner-chosen (BACKLOG #1625).

    Used where the path is not known here to swap for a label: a failed directory listing, whose path
    under ``recursive`` can be a partner-created SUBDIRECTORY, and a failed archive claim, whose path
    can be a bumped ``name-1.ext``. An ``OSError`` is reported by its type, errno and OS text, never
    its path. A ``ValueError`` from a listing is an invalid glob pattern, which is operator
    configuration."""
    if isinstance(exc, OSError) and exc.errno is not None:
        return f"{type(exc).__name__}: [Errno {exc.errno}] {exc.strerror or ''}".rstrip()
    # A message-only OSError keeps its message, redacted, with the known name swapped for a label.
    return safe_exc(exc, file_name=file_name)


class _Unconfined(OSError):
    """The listed name no longer leads to a regular file inside the watch root (BACKLOG #2507): it is
    a symbolic link, it is reached through a link or a junction, or it is not a regular file.

    The caller leaves the entry in place and never reads or moves it. An ``OSError``, so a caller that
    only has the ordinary failure arm still fails closed. The message never carries a file name."""


class _Replaced(OSError):
    """The listed name now leads to a different file from the one the read handle held (BACKLOG
    #2535): a file renamed over it, or a link swapped in, after the read.

    The caller leaves the name in place, so the next scan reads whatever is there now. An ``OSError``
    for the same reason as :class:`_Unconfined`, and its message never carries a file name."""


class _OverCap(Exception):
    """The file read from the handle is larger than ``max_file_bytes`` (BACKLOG #2507). Its message is
    a size ("<n> bytes" or "more than <cap> bytes"), never a name. ``file_id`` is the identity of the
    file the handle held, so the quarantine moves that file and no other (BACKLOG #2535)."""

    def __init__(self, size: str, file_id: _FileId) -> None:
        super().__init__(size)
        self.file_id = file_id


def _file_id(st: os.stat_result) -> _FileId:
    return st.st_dev, st.st_ino


def _names_another_path(st: os.stat_result) -> bool:
    """True for a Windows reparse point that names another path: a symbolic link, a junction, a WSL
    link. Always False on POSIX, which has no reparse tag."""
    return bool(getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE)


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
#: POSIX opens a candidate one component at a time below the root, each relative to its parent's
#: descriptor and none followed if it is a link. Windows has no ``dir_fd``; see :func:`_open_confined`.
#: The move and delete act relative to the checked parent too, so every call they make must take it.
#: ``os.rename`` stands for ``renameat``, which ``os.replace`` uses too but is not listed under.
_WALK_BY_DIR_FD = (
    bool(_O_NOFOLLOW and _O_DIRECTORY)
    and {os.open, os.stat, os.link, os.unlink, os.rename} <= os.supports_dir_fd
    and {os.stat, os.link} <= os.supports_follow_symlinks
)
#: ``O_NOFOLLOW`` refuses a link with ELOOP (Linux, macOS) or EMLINK (FreeBSD), and with
#: ``O_DIRECTORY`` a link to a directory with ENOTDIR (Linux).
_LINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK, errno.ENOTDIR})
#: POSIX ``os.link`` follows a link at its source unless told not to. Windows ``CreateHardLinkW`` links
#: the link itself already, and Windows ``os.link`` does not list the flag.
_LINK_TAKES_NOFOLLOW = os.link in os.supports_follow_symlinks

# Win32 values for the Windows walk and the handle-based move (BACKLOG #2535), from the Windows SDK.
_GENERIC_READ = 0x80000000
_DELETE = 0x00010000
_FILE_LIST_DIRECTORY = 0x0001
_SHARE_ALL = 0x7  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
#: Held on each directory the walk passes, so nobody can rename that directory until the file is open.
_SHARE_NO_DELETE = 0x3
_OPEN_EXISTING = 3
_FLAG_OPEN_REPARSE_POINT = 0x00200000
#: Needed to open a directory at all. The engine enables no backup privilege, so it grants nothing.
_FLAG_BACKUP_SEMANTICS = 0x02000000
#: IsReparseTagNameSurrogate: the tag names another path, as a symbolic link or a junction does.
_NAME_SURROGATE = 0x20000000
_FILE_RENAME_INFO = 3
_FILE_DISPOSITION_INFO = 4
_FILE_ATTRIBUTE_TAG_INFO = 9
_FILE_DISPOSITION_INFO_EX = 21
_DISPOSITION_DELETE_POSIX = 0x1 | 0x2  # FILE_DISPOSITION_FLAG_DELETE | ..._POSIX_SEMANTICS
#: ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, ERROR_INVALID_PARAMETER: "this volume does not do
#: that", not "that failed". They send a POSIX-semantics delete to the classic one.
_WIN_UNSUPPORTED = frozenset({1, 50, 87})
#: ERROR_NOT_SAME_DEVICE (the archive is on another volume) and ERROR_NOT_SUPPORTED send a rename
#: to the copy. Any other failure is reported, so a bad request cannot quietly become a copy.
_RENAME_COPIES = frozenset({17, 50})
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _AttributeTag(ctypes.Structure):
    """``FILE_ATTRIBUTE_TAG_INFO``."""

    _fields_ = (("attributes", ctypes.c_uint32), ("tag", ctypes.c_uint32))


def _open_confined(
    path: Path, directory: Path, root_real: Path, *, for_move: bool = False
) -> tuple[int, os.stat_result]:
    """Open ``path`` to read only if it is a regular file inside the watch root reached through no link
    (BACKLOG #2507). Returns the descriptor and its ``fstat``; the caller closes the descriptor.

    The listing screens a NAME, without following it; the read and the move come later. This check
    is on what was OPENED, so a link swapped in between is caught.

    **POSIX** opens each component below the root relative to its parent's descriptor with
    ``O_NOFOLLOW``, so no component can be a link and nothing is resolved by name after the check. The
    last is opened ``O_NONBLOCK``, so a FIFO swapped in fails the regular-file check instead of
    blocking. **Windows** walks the same way with handles (:func:`_win_open_confined`), so no link or
    junction below the root is followed, not even to be refused (BACKLOG #2535). The handle's final
    path, every link and junction resolved, must then still equal the root joined with the listed
    name. A volume that cannot report a normalized final path fails that check, which leaves the file
    in place.

    ``for_move`` asks Windows for a handle that can also rename and delete the file, which the move and
    the delete then act on. POSIX ignores it: there they act relative to the parent's descriptor.

    Either way a link that stays inside the root is refused too. A hard link is not: see
    :func:`_pin_confined` for why."""
    parts = _listed_parts(path, directory)
    if _WALK_BY_DIR_FD:
        parent = _open_dir(root_real, parts[:-1])
        try:
            fd = _open_no_link(parts[-1], os.O_RDONLY | _O_NONBLOCK, parent)
        finally:
            os.close(parent)
    elif sys.platform == "win32":
        fd = _win_open_confined(root_real, parts, _GENERIC_READ | (_DELETE if for_move else 0))
    else:  # pragma: no cover - no supported platform lands here, and failing closed is the safe arm
        raise _Unconfined("this platform cannot confine a read to the watch root")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _Unconfined("not a regular file")
        if not _WALK_BY_DIR_FD:
            expected = os.path.normcase(_plain(str(root_real.joinpath(*parts))))
            if os.path.normcase(_plain(_final_path(fd))) != expected:
                raise _Unconfined("reached through a link or a junction")
    except OSError:
        os.close(fd)
        raise
    return fd, st


def _listed_parts(path: Path, directory: Path) -> tuple[str, ...]:
    """``path``'s components below the watch directory, refusing anything but plain names. The refusal
    is raised outside the handler, so it carries no ``ValueError`` naming both paths."""
    try:
        parts = path.relative_to(directory).parts
    except ValueError:
        parts = ()
    if not parts or any(part in (".", "..") for part in parts):
        raise _Unconfined("not a plain name under the watch directory")
    return parts


def _open_dir(root: Path, dirs: tuple[str, ...]) -> int:
    """POSIX: open the directory ``root/dirs...``, one component at a time, following no link below
    ``root``. The caller closes the descriptor."""
    dir_fd = os.open(root, os.O_RDONLY | _O_DIRECTORY)
    try:
        for part in dirs:
            parent = dir_fd
            dir_fd = _open_no_link(part, os.O_RDONLY | _O_DIRECTORY, parent)
            os.close(parent)
    except OSError:
        os.close(dir_fd)
        raise
    return dir_fd


class _Held:
    """A context manager that calls ``close()`` on exit."""

    __slots__ = ()

    def close(self) -> None:  # pragma: no cover - every subclass defines it
        raise NotImplementedError

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class _Pin(_Held):
    """A file checked just before it is moved or deleted, held for that act (BACKLOG #2507, #2535).

    POSIX holds the parent directory's descriptor (``dir_fd``) and the bare ``name``. Windows holds a
    descriptor on the file itself (``fd``), opened for rename and delete, so the act names nothing.
    ``file_id`` is the identity of the file checked. Closing the pin closes whichever it holds."""

    __slots__ = ("dir_fd", "fd", "file_id", "name")

    def __init__(
        self, name: Path, file_id: _FileId, *, dir_fd: int | None = None, fd: int | None = None
    ) -> None:
        self.name = name
        self.file_id = file_id
        self.dir_fd = dir_fd
        self.fd = fd

    def close(self) -> None:
        for held in (self.dir_fd, self.fd):
            if held is not None:
                os.close(held)
        self.dir_fd = self.fd = None


def _pin_confined(
    path: Path, directory: Path, root_real: Path, expect: _FileId | None = None
) -> _Pin:
    """Check ``path`` is still the confined regular file just before it is moved or deleted, and hold
    it for that act (BACKLOG #2507). Raises as :func:`_open_confined` does, and :class:`_Replaced`
    when ``expect`` is given and the name now leads to another file (BACKLOG #2535).

    **POSIX** holds the parent directory's descriptor and the bare name. Acting on the name relative
    to that descriptor (``os.link`` with ``src_dir_fd``, ``os.unlink`` with ``dir_fd``) means no
    directory swapped for a link after the check can redirect the act, and neither call follows a
    link at the last name. What POSIX cannot close is the moment between this check and the act: it
    has no call that unlinks a name only if it is still a given file. The archive's new name is
    checked after it is made (:func:`_link_free_name`), so a move never archives a file swapped in
    then. An unlink cannot be checked afterwards, so a file renamed over the name in that moment, two
    system calls wide, is the one deleted. Renaming over a name needs the same permission on the
    directory as deleting it, so this gives nobody a power they lack.

    **Windows** holds a handle on the file itself, opened for rename and delete. The move renames that
    handle and the delete marks that handle, so neither resolves a name: what was checked is exactly
    what is acted on.

    **A hard link is not refused.** It is the same file as every other name for it, so no handle can
    tell an outside file hard-linked into the drop directory from a drop. Refusing a link count above
    one would refuse what ordinary producers make: this engine's own delivery links a file to its
    final name before removing the temp, and if that removal fails the count stays at two, so the file
    would be refused forever. A hard link can only name a file on the same volume, and Linux's
    ``fs.protected_hardlinks`` (on by default in most distributions) stops a user linking a file they
    cannot write. The control is the volume: keep the drop directory on one that holds no file a
    partner may not read."""
    if not _WALK_BY_DIR_FD:
        fd, st = _open_confined(path, directory, root_real, for_move=True)
        pin = _Pin(path, _file_id(st), fd=fd)
    else:
        parts = _listed_parts(path, directory)
        parent = _open_dir(root_real, parts[:-1])
        try:
            st = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                raise _Unconfined("not a regular file")
        except OSError:
            os.close(parent)
            raise
        pin = _Pin(Path(parts[-1]), _file_id(st), dir_fd=parent)
    if expect is not None and pin.file_id != expect:
        pin.close()
        raise _Replaced("not the file that was read")
    return pin


class _Dest(_Held):
    """An archive directory (``.processed`` or ``.error``) opened for one move, so a link put where it
    was cannot redirect the move (BACKLOG #2535).

    ``path`` is the directory as the move names it. POSIX holds a descriptor on it (``fd``) and makes
    every name relative to that. Windows holds a handle on it and on each directory between it and the
    watch root (``held``), none of which can then be renamed, so the path resolves to them alone.
    Closing it releases whichever it holds."""

    __slots__ = ("fd", "held", "path")

    def __init__(self, path: Path, *, fd: int | None = None, held: list[int] | None = None) -> None:
        self.path = path
        self.fd = fd
        self.held = held or []

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.held:
            _win_release(self.held)
            self.held = []


def _open_dest(dest_dir: Path, directory: Path, root_real: Path) -> _Dest:
    """Open the archive directory ``dest_dir`` for a move, through no link below the watch root
    (BACKLOG #2535). Raises :class:`_Unconfined` when a component is a link or a junction.

    ``.processed`` and ``.error`` sit in the watch directory by default, so whoever writes drops there
    can also rename either one and put a link in its place, after the engine made it at start. Each
    move therefore opens the directory again, the same way the read opens a drop: POSIX walks from the
    root with ``O_NOFOLLOW`` to a descriptor, and Windows walks with handles it holds.

    A directory configured OUTSIDE the watch directory is the operator's, not a partner's, so it is
    used as configured, links and all; POSIX still names everything relative to a descriptor on it."""
    dirs = _dirs_below(dest_dir, directory)
    if _WALK_BY_DIR_FD:
        if dirs is None:
            return _Dest(dest_dir, fd=os.open(dest_dir, os.O_RDONLY | _O_DIRECTORY))
        return _Dest(dest_dir, fd=_open_dir(root_real, dirs))
    if dirs is None:
        return _Dest(dest_dir)
    return _Dest(root_real.joinpath(*dirs), held=_win_hold_dirs(root_real, dirs))


def _dirs_below(dest_dir: Path, directory: Path) -> tuple[str, ...] | None:
    """``dest_dir``'s components below the watch directory, or None when it is not below it."""
    try:
        rel = Path(os.path.relpath(os.path.normpath(dest_dir), os.path.normpath(directory)))
    except ValueError:
        return None  # on another Windows drive
    parts = rel.parts
    return None if parts[:1] == ("..",) else parts


def _archive(pin: _Pin, dest: _Dest, name: str) -> bool:
    """Claim the first free name from ``name`` in ``dest`` for the pinned file (BACKLOG #2535). True
    when that moved it, so the original is already gone; False when it was linked or copied, and the
    caller removes the original with :func:`_remove_pinned`.

    POSIX claims through :func:`_claim_unique`, relative to the checked source directory and to the
    opened archive directory, and against the pinned identity. Windows renames the checked handle
    (:func:`_rename_free_name`) into the held archive directory."""
    target = dest.path / name
    if pin.fd is None:
        _claim_unique(
            pin.name, target, src_dir_fd=pin.dir_fd, expect=pin.file_id, dst_dir_fd=dest.fd
        )
        return False
    return _rename_free_name(pin.fd, target)


def _remove_pinned(pin: _Pin) -> None:
    """Remove the pinned original, after an archive linked or copied it, or for
    ``after_read="delete"``. POSIX unlinks the bare name relative to the checked directory; Windows
    deletes through the checked handle, so it removes exactly the file checked.

    POSIX checks the name is still that file just before the unlink: after an archive's copy that
    is a whole copy, flush and publish since the pin, time enough for a resend by rename. It has no
    call that unlinks a name only if it is still a given file, so the moment between this check and
    the unlink stays open (see :func:`_pin_confined`)."""
    if pin.fd is None:
        if _file_id(os.stat(pin.name, dir_fd=pin.dir_fd, follow_symlinks=False)) != pin.file_id:
            raise _Replaced("not the file that was read")
        os.unlink(pin.name, dir_fd=pin.dir_fd)
    else:
        _delete_by_handle(pin.fd)


def _rename_free_name(fd: int, target: Path) -> bool:
    """Windows: rename the file open on ``fd`` to the first free name from ``target``, and return True.
    The rename refuses an existing name, so the claim is one atomic step, as the link is on POSIX, and
    the file is never in both places.

    Where the volume cannot rename it there (the archive is on another volume), copy from ``fd`` and
    publish the copy instead, and return False: the caller then deletes the original through the same
    handle. Either way the bytes come from the checked handle, never from a name (BACKLOG #2535)."""
    for candidate in _free_names(target):
        try:
            _rename_by_handle(fd, candidate)
        except FileExistsError:
            continue
        except OSError as exc:
            if getattr(exc, "winerror", None) not in _RENAME_COPIES:
                raise
            break  # this volume cannot rename it there: copy instead, below
        return True
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(fd, "rb", closefd=False) as reader:
        staged = _stage_copy(reader, target.parent)
    _claim_staged(staged, target)
    return False


def _win_open_confined(root_real: Path, parts: tuple[str, ...], access: int) -> int:
    """Windows: open ``root_real/parts...`` for ``access`` through no link or junction below the root
    (BACKLOG #2535). Returns a descriptor the caller closes.

    Each directory below the root is opened as itself (``FILE_FLAG_OPEN_REPARSE_POINT``) and refused
    if it names another path. Its handle is held, shared for reading and writing but not for delete,
    until the file is open, so nobody can rename it, and so none can be swapped for a junction, while
    the walk is below it. The file is then opened as itself too (:func:`_win_open_file`). So nothing
    below the root is followed, and a link to a UNC path or a pipe is refused before anything is sent
    to it. Once the file is open, NTFS refuses to rename a directory above it."""
    held = _win_hold_dirs(root_real, parts[:-1])
    try:
        return _win_open_file(root_real.joinpath(*parts), access)
    finally:
        _win_release(held)


def _win_hold_dirs(root: Path, dirs: tuple[str, ...]) -> list[int]:
    """Windows: open each directory ``root/dirs...`` as itself, refuse one that is not a plain
    directory, and return their handles, held so that none can be renamed (BACKLOG #2535). The caller
    passes them to :func:`_win_release`."""
    held: list[int] = []
    try:
        where = root
        for part in dirs:
            where = where / part
            handle = _win_create(
                where,
                _FILE_LIST_DIRECTORY,
                _SHARE_NO_DELETE,
                _FLAG_OPEN_REPARSE_POINT | _FLAG_BACKUP_SEMANTICS,
            )
            held.append(handle)
            attributes, tag = _attribute_tag(handle)
            if not attributes & stat.FILE_ATTRIBUTE_DIRECTORY or tag & _NAME_SURROGATE:
                raise _Unconfined("reached through a link or a junction")
    except OSError:
        _win_release(held)
        raise
    return held


def _win_release(held: list[int]) -> None:
    for handle in held:
        _kernel32().CloseHandle(handle)


def _win_open_file(path: Path, access: int) -> int:
    """Windows: open the file at ``path`` as itself, and refuse it if it names another path (a symbolic
    link, a junction). Returns a descriptor the caller closes.

    A reparse point that names no path (a deduplicated, cloud or tiered file) serves its data only to
    an open that lets its filter act, so it is opened again that way and must still be the same file.
    That second open is the one open here that would follow a link swapped in between the two; the
    identity compare then refuses what it reached."""
    fd = _fd_for(_win_create(path, access, _SHARE_ALL, _FLAG_OPEN_REPARSE_POINT))
    try:
        attributes, tag = _attribute_tag(_os_handle(fd))
        if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            if tag & _NAME_SURROGATE:
                raise _Unconfined("a symbolic link or a junction")
            first = _file_id(os.fstat(fd))
            os.close(fd)
            fd = -1
            fd = _fd_for(_win_create(path, access, _SHARE_ALL, 0))
            if _file_id(os.fstat(fd)) != first:
                raise _Replaced("not the file first opened")
    except OSError:
        if fd >= 0:
            os.close(fd)
        raise
    return fd


def _win_error(code: int | None = None) -> OSError:
    """The ``OSError`` for a failed Win32 call: ``code``, else the thread's last error. It carries the
    Windows code and text, never a path."""
    if sys.platform != "win32":  # pragma: no cover - only the Windows arm calls this; narrows mypy
        return _Unconfined("no Windows errors on this platform")
    return ctypes.WinError(ctypes.get_last_error() if code is None else code)


def _win_create(path: Path, access: int, share: int, flags: int) -> int:
    """``CreateFileW`` on an existing ``path``. Its error carries the Windows code and text, never the
    path."""
    handle = _kernel32().CreateFileW(str(path), access, share, None, _OPEN_EXISTING, flags, None)
    if handle is None or handle == _INVALID_HANDLE:
        raise _win_error()
    return int(handle)


def _fd_for(handle: int) -> int:
    """Windows: a descriptor that owns ``handle``, so closing the descriptor closes the handle."""
    if sys.platform != "win32":  # pragma: no cover - narrows mypy
        raise _Unconfined("no OS handles on this platform")
    import msvcrt

    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY)
    except OSError:
        _kernel32().CloseHandle(handle)
        raise


def _os_handle(fd: int) -> int:
    if sys.platform != "win32":  # pragma: no cover - narrows mypy
        raise _Unconfined("no OS handles on this platform")
    import msvcrt

    return msvcrt.get_osfhandle(fd)


def _attribute_tag(handle: int) -> tuple[int, int]:
    """Windows: the attributes and the reparse tag of the file open on ``handle``."""
    info = _AttributeTag()
    if not _kernel32().GetFileInformationByHandleEx(
        handle, _FILE_ATTRIBUTE_TAG_INFO, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise _win_error()
    return int(info.attributes), int(info.tag)


def _rename_by_handle(fd: int, target: Path) -> None:
    """Windows: rename the file open on ``fd`` to ``target``, refusing an existing name with
    ``FileExistsError``. ``SetFileInformationByHandle(FileRenameInfo)``, which is what ``MoveFileExW``
    does after it opens the source by name."""
    name = os.path.abspath(target)
    units = len(name.encode("utf-16-le", "surrogatepass")) // 2

    class _RenameInfo(ctypes.Structure):
        _fields_ = (
            ("replace_if_exists", ctypes.c_uint32),
            ("root_directory", ctypes.c_void_p),
            ("file_name_length", ctypes.c_uint32),
            ("file_name", ctypes.c_wchar * (units + 1)),
        )

    info = _RenameInfo(0, None, units * 2, name)
    if not _kernel32().SetFileInformationByHandle(
        _os_handle(fd), _FILE_RENAME_INFO, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise _win_error()


def _delete_by_handle(fd: int) -> None:
    """Windows: delete the file open on ``fd``. POSIX semantics first, so the name goes at once even
    while another process holds the file open; the classic disposition where the volume has no such
    thing, which removes the name when the last handle closes."""
    k32 = _kernel32()
    handle = _os_handle(fd)
    flags = ctypes.c_uint32(_DISPOSITION_DELETE_POSIX)
    if k32.SetFileInformationByHandle(
        handle, _FILE_DISPOSITION_INFO_EX, ctypes.byref(flags), ctypes.sizeof(flags)
    ):
        return
    error = _win_error()
    if getattr(error, "winerror", None) not in _WIN_UNSUPPORTED:
        raise error
    delete = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile
    if not k32.SetFileInformationByHandle(
        handle, _FILE_DISPOSITION_INFO, ctypes.byref(delete), ctypes.sizeof(delete)
    ):
        raise _win_error()


def _open_no_link(name: str, flags: int, dir_fd: int) -> int:
    """``os.open`` relative to ``dir_fd`` with ``O_NOFOLLOW``. The error drops the component's name:
    under ``recursive`` it can be a partner-made subdirectory, which ``safe_exc`` cannot swap out. So
    it is raised outside the handler, keeping only the errno and its text: ``from None`` would leave
    the named error on ``__context__``."""
    try:
        return os.open(name, flags | _O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        code, text = exc.errno, exc.strerror
    if code in _LINK_ERRNOS:
        raise _Unconfined("a symbolic link")
    raise OSError(code, text)


def _final_path(fd: int) -> str:
    """Windows: the final path of the file open on ``fd``, every link and junction resolved."""
    handle = _os_handle(fd)
    query = _kernel32().GetFinalPathNameByHandleW
    size = 512
    while True:
        buf = ctypes.create_unicode_buffer(size)
        needed = query(handle, buf, size, 0)
        if needed == 0:
            raise _win_error()
        if needed < size:
            return str(buf.value)
        size = needed  # too small: the return is the size needed, terminator included


@functools.cache
def _kernel32() -> Any:
    """``kernel32``, with the argument and return types of every call this module makes declared."""
    if sys.platform != "win32":  # pragma: no cover - narrows mypy
        raise _Unconfined("no kernel32 on this platform")
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    k32.CloseHandle.restype = wintypes.BOOL
    for info_call in (k32.GetFileInformationByHandleEx, k32.SetFileInformationByHandle):
        info_call.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        info_call.restype = wintypes.BOOL
    k32.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    return k32


def _plain(path: str) -> str:
    """Drop the verbatim prefix a final path carries (``//?/`` or ``//?/UNC/``, with backslashes), so
    it compares with a plain one."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _read_confined(
    path: Path, directory: Path, root_real: Path, cap: int | None
) -> tuple[bytes, _FileId]:
    """Read ``path`` through :func:`_open_confined`, and at most ``cap + 1`` bytes (BACKLOG #2507).
    Returns the bytes and the identity of the file the handle held (BACKLOG #2535).

    The cap is charged on the handle, never on an earlier stat: the handle's size refuses an oversize
    file without reading it, and the bounded read refuses one that grew after that, or whose size
    attribute lags what it serves. Either raises :class:`_OverCap`. ``cap`` None reads it whole.

    The first read asks for the handle's size plus one, not ``cap + 1``: a buffered ``read(n)``
    allocates ``n`` up front, so asking for the cap would reserve 16 MiB for every small drop.

    The move or delete that follows opens the file a second time. The read's handle is not kept for
    it: the hand-off, the scan hook and a store retry sit between them, and keeping a handle that can
    delete the file open that long would refuse a partner's own rename or delete meanwhile. The
    identity returned here binds the two opens instead, so the second must reach the same file."""
    fd, st = _open_confined(path, directory, root_real)
    file_id = _file_id(st)
    with os.fdopen(fd, "rb") as handle:
        if cap is None:
            return handle.read(), file_id
        if st.st_size > cap:
            raise _OverCap(f"{st.st_size} bytes", file_id)
        want = st.st_size + 1
        raw = handle.read(want)
        if len(raw) == want and want <= cap:  # it grew past its own size: keep going, to the cap
            raw += handle.read(cap + 1 - want)
    if len(raw) > cap:
        raise _OverCap(f"more than {cap} bytes", file_id)
    return raw, file_id


def _open_regular(path: str, flags: int, dir_fd: int | None, expect: _FileId | None) -> int:
    """An ``open()`` opener for the claim's copy fallback. It refuses a link at the last name where the
    platform can (#2507), and opens ``O_NONBLOCK`` so a FIFO swapped in fails the regular-file check
    below rather than holding a worker thread until a writer appears (BACKLOG #2535). That flag
    changes nothing for a regular file. With ``expect`` it must also be the file that was read."""
    fd = os.open(path, flags | _O_NOFOLLOW | _O_NONBLOCK, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _Unconfined("not a regular file")
        if expect is not None and _file_id(st) != expect:
            raise _Replaced("not the file that was read")
    except OSError:
        os.close(fd)
        raise
    return fd


def _mtime(p: Path) -> float:
    try:
        return p.lstat().st_mtime
    except OSError:
        return 0.0


def _file_sig(path: Path) -> _FileSig:
    """The file's size and modification time. The size alone would miss a rewrite that keeps the
    length; the modification time still moves. May raise ``OSError`` if the file is gone.

    It does not follow a link at the name (BACKLOG #2535): for a regular file that is the same stat,
    and a link is left for the read to refuse rather than opened here."""
    st = path.lstat()
    return st.st_size, st.st_mtime_ns


register_destination(ConnectorType.FILE, FileDestination)
register_source(ConnectorType.FILE, FileSource)
