# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""REMOTEFILE transport connector (SFTP / FTP / FTPS): upload, poll, error mapping, security, egress.

The remote client is faked (``_make_client`` is monkeypatched, or the ``_SftpClient`` host-key policy
is exercised against a fake paramiko module), so nothing hits the network or SSH — exactly like the
DATABASE driver fake and the REST opener fake. paramiko need not be installed.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import posixpath
import ssl
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Ftp, Sftp, WiringError
from messagefoundry.pipeline.wiring_runner import check_egress_allowed, check_source_allowed
from messagefoundry.transports import build_destination, build_source, remotefile
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationStartupError,
    NegativeAckError,
)
from messagefoundry.transports.file import DEFAULT_MAX_FILE_BYTES
from messagefoundry.transports.remotefile import (
    _APPROVED_SFTP_CIPHERS,
    _APPROVED_SFTP_MACS,
    RETRIEVE_CHUNK_BYTES,
    RemoteFileDestination,
    RemoteFileSource,
    _BoundedSink,
    _FtpClient,
    _ftps_ssl_context,
    _is_contained_name,
    _RemoteClient,
    _RemoteError,
    _RemoteOversize,
    _SftpClient,
)

#: Small chunk for the fake client, so a test body is delivered in several pieces without needing a
#: multi-MiB fixture. The shipped chunk size is asserted separately, below.
_CHUNK = 4

# --- a fake remote client ----------------------------------------------------


class _FakeClient(_RemoteClient):
    """In-memory remote-file client. Records the operation order so a test can assert that a store
    happened before its rename (atomic publish)."""

    def __init__(
        self,
        files: dict[str, bytes] | None = None,
        *,
        sizes: dict[str, int] | None = None,
        store_exc: _RemoteError | None = None,
        rename_exc: _RemoteError | None = None,
        retrieve_exc: _RemoteError | None = None,
        list_exc: _RemoteError | None = None,
    ) -> None:
        self.files: dict[str, bytes] = dict(files or {})
        self._sizes = sizes or {}
        self.ops: list[tuple[str, str]] = []  # (op, path)
        self.dirs: list[str] = []
        self._existing_dirs: set[str] = set()  # #114: which dirs ensure_dir has already created
        self._store_exc = store_exc
        self._rename_exc = rename_exc
        self._retrieve_exc = retrieve_exc
        self._list_exc = list_exc  # #114: an unreachable/missing remote_dir

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        if self._list_exc is not None:
            raise self._list_exc
        out: list[tuple[str, int]] = []
        for path, data in self.files.items():
            if posixpath.dirname(path) == remote_dir:
                name = posixpath.basename(path)
                out.append((name, self._sizes.get(path, len(data))))
        return out

    def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
        self.ops.append(("retrieve", path))
        if self._retrieve_exc is not None:
            raise self._retrieve_exc
        # Stream through the SHIPPED sink rather than a re-implementation, so the fake enforces the
        # real budget on the real code path (#1191). Chunked, so a body is refused part-way in.
        sink = _BoundedSink(max_bytes)
        body = self.files[path]
        for start in range(0, max(len(body), 1), _CHUNK):
            sink.write(body[start : start + _CHUNK])
        return sink.value()

    def store(self, path: str, data: bytes) -> None:
        self.ops.append(("store", path))
        if self._store_exc is not None:
            raise self._store_exc
        self.files[path] = data

    def rename(self, src: str, dst: str) -> None:
        self.ops.append(("rename", f"{src}->{dst}"))
        if self._rename_exc is not None:
            raise self._rename_exc
        self.files[dst] = self.files.pop(src)

    def remove(self, path: str) -> None:
        self.ops.append(("remove", path))
        self.files.pop(path, None)

    def ensure_dir(self, remote_dir: str) -> bool:
        # #114: the contract now reports whether THIS call created the directory, so the caller can log
        # a delivery that landed in a directory the engine just invented.
        self.dirs.append(remote_dir)
        if remote_dir in self._existing_dirs:
            return False
        self._existing_dirs.add(remote_dir)
        return True


def _install_client(monkeypatch: pytest.MonkeyPatch, client: _FakeClient) -> None:
    # _make_client gained a keyword-only trust_anchor_policy= (#190, ADR 0093); accept + ignore it.
    monkeypatch.setattr(remotefile, "_make_client", lambda settings, **_: client)


def _dest(
    monkeypatch: pytest.MonkeyPatch, client: _FakeClient, **over: Any
) -> RemoteFileDestination:
    _install_client(monkeypatch, client)
    base: dict[str, Any] = dict(host="sftp.example.com", remote_dir="/in")  # noqa: C408
    base.update(over)
    d = build_destination(
        Destination(name="OB_REMOTE", type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings)
    )
    assert isinstance(d, RemoteFileDestination)
    return d


def _src(monkeypatch: pytest.MonkeyPatch, client: _FakeClient, **over: Any) -> RemoteFileSource:
    _install_client(monkeypatch, client)
    base: dict[str, Any] = dict(host="sftp.example.com", remote_dir="/in")  # noqa: C408
    base.update(over)
    s = build_source(Source(type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings))
    assert isinstance(s, RemoteFileSource)
    return s


class _RecordingHandler:
    def __init__(self, exc: Exception | None = None) -> None:
        self.bodies: list[bytes] = []
        self._exc = exc

    async def __call__(self, raw: bytes) -> str | None:
        self.bodies.append(raw)
        if self._exc is not None:
            raise self._exc
        return None


class _FakeLedger:
    """In-memory ProcessedFileLedger stand-in (#142) — records a HASHED key, skips a seen key, prunes."""

    def __init__(self) -> None:
        self.keys: set[str] = set()
        self.pruned = 0

    async def is_processed(self, file_key: str) -> bool:
        return file_key in self.keys

    async def mark_processed(self, file_key: str) -> None:
        self.keys.add(file_key)

    async def prune(self) -> None:
        self.pruned += 1


# === destination =============================================================


async def test_destination_uploads_store_then_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    await dest.send("MSH|^~\\&|A|B")
    # The final file exists with the payload, and store happened BEFORE the rename (atomic publish).
    assert client.files["/in/msg.hl7"] == b"MSH|^~\\&|A|B"
    op_names = [op for op, _ in client.ops]
    assert op_names.index("store") < op_names.index("rename")
    # The stored path was a .part temp, renamed to the final name.
    store_path = next(p for op, p in client.ops if op == "store")
    assert store_path.endswith(".part") and "/in/" in store_path


async def test_destination_filename_templating(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    dest = _dest(monkeypatch, client, filename="{MSH-10}.hl7")
    await dest.send("MSH|^~\\&|A|B|C|D|20260613||ADT^A01|CTRL123|P|2.5")
    assert "/in/CTRL123.hl7" in client.files


async def test_destination_no_silent_clobber(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/msg.hl7": b"existing"})
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=False)
    await dest.send("new")
    assert client.files["/in/msg.hl7"] == b"existing"  # original untouched
    assert client.files["/in/msg-1.hl7"] == b"new"  # uniquified, not clobbered


async def test_destination_overwrite_replaces(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/msg.hl7": b"existing"})
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=True)
    await dest.send("new")
    assert client.files["/in/msg.hl7"] == b"new"


async def test_destination_transient_error_is_delivery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(store_exc=_RemoteError("connection reset", permanent=False))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(DeliveryError) as ei:
        await dest.send("x")
    assert not isinstance(ei.value, NegativeAckError)  # transient → retry


async def test_destination_permanent_error_is_negative_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(store_exc=_RemoteError("no such directory", permanent=True))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("x")
    assert ei.value.permanent is True
    # #109 (ADR 0095): a CONTENT-permanent failure (no-such-dir) is NOT a credential fault.
    assert ei.value.credential_fault is False


async def test_destination_credential_fault_flag_threads_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #109 (ADR 0095): an auth-refusal _RemoteError(credential_fault=True) threads its marker onto the
    # NegativeAckError so the delivery worker can STOP-and-retain instead of dead-lettering the backlog.
    client = _FakeClient(
        store_exc=_RemoteError("auth failed", permanent=True, credential_fault=True)
    )
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("x")
    assert ei.value.permanent is True
    assert ei.value.credential_fault is True


async def test_destination_cleans_temp_on_failed_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(rename_exc=_RemoteError("rename failed", permanent=False))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(DeliveryError):
        await dest.send("x")
    assert any(op == "remove" for op, _ in client.ops)  # temp cleaned up
    assert not client.files  # nothing left behind


# === source ==================================================================


async def test_source_polls_retrieves_and_moves_to_processed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # HL7-shaped bodies: content_type is unset (None), which now sniffs as hl7v2 (the None-skips-sniff
    # carve-out was removed, ASVS 5.2.2), so the mechanics under test need a body the sniff accepts.
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A", "/in/b.hl7": b"MSH|^~\\&|B"})
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A", b"MSH|^~\\&|B"]  # both delivered, in sorted order
    # Moved to the processed dir (only after the handler returned), not left in /in.
    assert "/in/.processed/a.hl7" in client.files
    assert "/in/.processed/b.hl7" in client.files
    assert "/in/a.hl7" not in client.files


async def test_source_pattern_filters_non_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A", "/in/skip.txt": b"nope"})
    src = _src(monkeypatch, client, pattern="*.hl7")
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A"]  # the .txt is ignored (pattern), the .hl7 sniffs as HL7


async def test_source_after_read_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client, after_read="delete")
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A"]
    assert "/in/a.hl7" not in client.files  # deleted, not moved
    assert not any(p.startswith("/in/.processed") for p in client.files)


async def test_source_handler_failure_leaves_file(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client)
    h = _RecordingHandler(exc=RuntimeError("store write failed"))
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A"]  # handler attempted
    assert "/in/a.hl7" in client.files  # left in place → re-emits next poll (at-least-once)
    assert "/in/.processed/a.hl7" not in client.files


async def test_source_after_read_leave_keeps_file_and_dedups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #142: after_read='leave' never moves/deletes the remote file, and the ledger dedups across polls.
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client, after_read="leave")
    ledger = _FakeLedger()
    src.processed_ledger = ledger
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A"]  # ingested once
    assert "/in/a.hl7" in client.files  # left in place
    assert not any(p.startswith("/in/.processed") for p in client.files)  # never moved
    assert len(ledger.keys) == 1  # a HASHED key recorded
    (key,) = ledger.keys
    assert len(key) == 64 and "a.hl7" not in key  # sha256 hex, no cleartext filename
    await src._poll_once()  # a second poll must NOT re-ingest
    assert h.bodies == [b"MSH|^~\\&|A"]


async def test_source_leave_durable_ledger_read_is_the_dedup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #142 Finding-3 (remote): with an EMPTY in-memory cache, a file already in the DURABLE ledger is
    # skipped with ZERO emits — exercising ledger.is_processed() in isolation.
    client = _FakeClient(files={"/in/a.hl7": b"AAA"})
    src = _src(monkeypatch, client, after_read="leave")
    ledger = _FakeLedger()
    ledger.keys.add(
        src._file_key("a.hl7", 3)
    )  # pre-seed durable (full remote path folded); cache empty
    src.processed_ledger = ledger
    assert len(src._processed_seen) == 0
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == []  # ZERO emits — the durable read decided
    assert "/in/a.hl7" in client.files  # left in place


async def test_source_leave_distinct_remote_paths_get_distinct_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #142 Finding-1 (remote): the key folds the FULL REMOTE PATH, so the same basename under a different
    # remote_dir yields a DISTINCT hash (never collapsed to one).
    c1 = _FakeClient(files={"/in/m.hl7": b"AAA"})
    c2 = _FakeClient(files={"/other/m.hl7": b"AAA"})  # same name+size, different base
    s1 = _src(monkeypatch, c1, after_read="leave", remote_dir="/in")
    k1 = s1._file_key("m.hl7", 3)
    s2 = _src(monkeypatch, c2, after_read="leave", remote_dir="/other")
    k2 = s2._file_key("m.hl7", 3)
    assert k1 != k2  # distinct remote paths → distinct hashed keys


async def test_source_oversize_moves_to_error_without_retrieving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={"/in/big.hl7": b"x" * 10}, sizes={"/in/big.hl7": 10})
    src = _src(monkeypatch, client, max_file_bytes=5)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == []  # never delivered
    assert not any(op == "retrieve" for op, _ in client.ops)  # never retrieved
    assert "/in/.error/big.hl7" in client.files  # quarantined


# --- #1191: the bound is charged against BYTES READ, not against the listed size ----------------


class _StubSftpFile:
    """A paramiko ``SFTPFile`` stand-in. Records how much was ACTUALLY read, which is the only way to
    tell a bounded chunked read from a whole-file read that is checked afterwards."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read_total = 0

    def read(self, size: int) -> bytes:
        chunk = self.body[self.read_total : self.read_total + size]
        self.read_total += len(chunk)
        return chunk

    def __enter__(self) -> _StubSftpFile:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _StubSftp:
    def __init__(self, fh: _StubSftpFile) -> None:
        self._fh = fh

    def open(self, path: str, mode: str) -> _StubSftpFile:
        return self._fh


class _StubFtp:
    """An ``ftplib.FTP`` stand-in whose ``retrbinary`` feeds the callback in blocks and records how
    many bytes it managed to hand over before the callback raised."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.written = 0
        self.blocksize: int | None = None

    def retrbinary(self, cmd: str, callback: Any, blocksize: int = 8192) -> None:
        self.blocksize = blocksize
        for start in range(0, len(self.body), blocksize):
            chunk = self.body[start : start + blocksize]
            self.written += len(chunk)
            callback(chunk)


def test_bounded_sink_charges_the_bytes_it_is_handed() -> None:
    sink = _BoundedSink(10)
    sink.write(b"x" * 6)
    assert sink.value() == b"x" * 6
    with pytest.raises(_RemoteOversize) as caught:
        sink.write(b"x" * 5)  # 11 > 10 — refused at the first byte past the budget
    assert caught.value.limit == 10


def test_bounded_sink_with_no_limit_never_refuses() -> None:
    """``max_file_bytes=0`` is an explicit operator opt-out; the read then stays unbounded."""
    sink = _BoundedSink(None)
    sink.write(b"x" * 10_000)
    assert len(sink.value()) == 10_000


def test_the_default_bound_is_the_shipped_non_zero_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bound is the operator's OWN ``max_file_bytes``, not a number invented for this guard — so
    it ships non-zero without adding a new dead-letter cause (#1191)."""
    src = _src(monkeypatch, _FakeClient())
    assert src._max_file_bytes == DEFAULT_MAX_FILE_BYTES
    assert DEFAULT_MAX_FILE_BYTES > 0


async def test_source_refuses_a_body_bigger_than_the_size_the_server_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE CASE THE PRE-RETRIEVE GATE CANNOT SEE. The share lists 4 bytes and delivers 100. The
    listing gate passes it; the read-side budget refuses it and quarantines it."""
    client = _FakeClient(files={"/in/lie.hl7": b"M" * 100}, sizes={"/in/lie.hl7": 4})
    src = _src(monkeypatch, client, max_file_bytes=10)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert any(op == "retrieve" for op, _ in client.ops)  # it DID pass the listing gate
    assert h.bodies == []  # nothing partial reached the pipeline
    assert "/in/.error/lie.hl7" in client.files  # quarantined with a disposition
    # NOT the transient arm: leaving it in place would re-pull the same oversized body every poll.
    assert "/in/lie.hl7" not in client.files


async def test_source_logs_the_lying_size_refusal(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Count-and-log: the refusal is logged, never silently swallowed."""
    client = _FakeClient(files={"/in/lie.hl7": b"M" * 100}, sizes={"/in/lie.hl7": 4})
    src = _src(monkeypatch, client, max_file_bytes=10)
    src._handler = _RecordingHandler()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.remotefile"):
        await src._poll_once()
    assert any("delivered more than max_file_bytes" in r.getMessage() for r in caplog.records)


async def test_source_zero_max_file_bytes_keeps_the_retrieve_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={"/in/big.hl7": b"MSH|^~\\&|" + b"x" * 5_000})
    src = _src(monkeypatch, client, max_file_bytes=0)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert len(h.bodies) == 1  # delivered whole — the operator disabled the cap


def test_sftp_retrieve_stops_reading_past_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """The SFTP backend reads in chunks and refuses mid-transfer, so a hostile body is never
    buffered whole. ``read_total`` proves the bytes were never pulled."""
    monkeypatch.setattr(remotefile, "RETRIEVE_CHUNK_BYTES", 4)
    fh = _StubSftpFile(b"x" * 400)
    monkeypatch.setattr(_SftpClient, "_op", lambda self, fn: fn(_StubSftp(fh)))
    client = _SftpClient({"host": "sftp.example.com"})
    with pytest.raises(_RemoteOversize):
        client.retrieve("/in/big.hl7", max_bytes=10)
    assert fh.read_total <= 10 + 4  # at most one chunk past the budget
    assert fh.read_total < len(fh.body)  # and nothing like the whole body


def test_sftp_retrieve_returns_a_body_inside_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remotefile, "RETRIEVE_CHUNK_BYTES", 4)
    fh = _StubSftpFile(b"MSH|^~\\&|A")
    monkeypatch.setattr(_SftpClient, "_op", lambda self, fn: fn(_StubSftp(fh)))
    client = _SftpClient({"host": "sftp.example.com"})
    assert client.retrieve("/in/a.hl7", max_bytes=1024) == b"MSH|^~\\&|A"


def test_ftp_retrieve_stops_reading_past_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """The FTP/FTPS backend has the same shape and the same fix — the sink raises out of the
    ``retrbinary`` callback, aborting the transfer."""
    monkeypatch.setattr(remotefile, "RETRIEVE_CHUNK_BYTES", 4)
    ftp = _StubFtp(b"x" * 400)
    monkeypatch.setattr(_FtpClient, "_op", lambda self, fn: fn(ftp))
    client = _FtpClient({"host": "ftp.example.com"}, tls=False)
    with pytest.raises(_RemoteOversize):
        client.retrieve("/in/big.hl7", max_bytes=10)
    assert ftp.blocksize == 4  # streamed, not slurped
    assert ftp.written <= 10 + 4
    assert ftp.written < len(ftp.body)


def test_ftp_retrieve_returns_a_body_inside_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    ftp = _StubFtp(b"MSH|^~\\&|A")
    monkeypatch.setattr(_FtpClient, "_op", lambda self, fn: fn(ftp))
    client = _FtpClient({"host": "ftp.example.com"}, tls=False)
    assert client.retrieve("/in/a.hl7", max_bytes=1024) == b"MSH|^~\\&|A"
    assert ftp.blocksize == RETRIEVE_CHUNK_BYTES


async def test_source_retrieve_failure_leaves_file(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(
        files={"/in/a.hl7": b"AAA"}, retrieve_exc=_RemoteError("locked", permanent=False)
    )
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == []  # nothing delivered
    assert "/in/a.hl7" in client.files  # left in place to retry


async def test_source_run_loop_survives_a_poll_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    src = _src(monkeypatch, client)
    calls: list[int] = []

    async def boom() -> None:
        calls.append(1)
        src._stop.set()
        raise RuntimeError("poll blew up")

    src._poll_once = boom  # type: ignore[method-assign]
    src._poll_seconds = 0.0
    await src._run()  # must NOT propagate — a bad poll never kills the poller
    assert calls == [1]


async def test_source_start_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    src = _src(monkeypatch, client)

    async def handler(raw: bytes) -> str | None:
        return None

    await src.start(handler)
    await src.stop()
    assert src._task is None


# --- source: leader-gating (Track B Step 4b) --------------------------------


def test_source_declares_polls_shared_resource() -> None:
    # A remote directory is a shared external resource — the runner reads this flag to leader-gate it.
    assert RemoteFileSource.polls_shared_resource is True


async def test_source_run_loop_skips_poll_when_gate_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A follower (leader_gate() -> False) must NOT list/download/move the remote dir: the loop ticks
    # but _poll_once is never reached, so the shared dir is untouched (no duplicate intake).
    client = _FakeClient(files={"/in/a.hl7": b"AAA"})
    src = _src(monkeypatch, client)
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0

    async def spy() -> None:
        raise AssertionError("a follower must not poll the remote dir")

    src._poll_once = spy  # type: ignore[method-assign]
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)
    src._stop.set()
    await runner
    assert client.ops == []  # never listed/retrieved/moved
    assert "/in/a.hl7" in client.files  # left in place


async def test_source_follower_real_poll_lists_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    # Higher-fidelity follower test (matches the FILE source's end-to-end check): let the REAL
    # _poll_once run under a False gate. The gate must short-circuit before list_dir/retrieve/move —
    # so the handler gets no body, the client records no retrieve/store/rename/remove ops, and the
    # remote file is left in place. A regression where _may_poll returns True would surface here.
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A|B"})
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)  # several ticks — each gated out before any remote op
    src._stop.set()
    await runner
    assert h.bodies == []  # never handed a body
    assert client.ops == []  # no retrieve / store / rename / remove
    assert "/in/a.hl7" in client.files  # left in place (not moved to .processed)


async def test_source_run_loop_polls_when_gate_true(monkeypatch: pytest.MonkeyPatch) -> None:
    # A leader (leader_gate() -> True) polls exactly as the un-gated default does.
    client = _FakeClient()
    src = _src(monkeypatch, client)
    src._leader_gate = lambda: True
    src._poll_seconds = 0.0
    calls: list[int] = []

    async def spy() -> None:
        calls.append(1)
        src._stop.set()

    src._poll_once = spy  # type: ignore[method-assign]
    await src._run()
    assert calls == [1]  # the gate was True → poll_once ran


def test_source_may_poll_logs_transition_once_then_resumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    src = _src(monkeypatch, client)
    leader = {"on": False}
    src._leader_gate = lambda: leader["on"]
    assert src._may_poll() is False and src._skipping is True
    assert src._may_poll() is False and src._skipping is True  # no re-flip while still a follower
    leader["on"] = True
    assert src._may_poll() is True and src._skipping is False  # became leader → resume


# === security: pre-ingest content scan hook (ASVS 5.4.3) =====================


async def test_source_quarantines_content_rejected_by_scan_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An operator/plugin AV scan-hook runs over every inbound REMOTE file before it enters the pipeline
    # (the control that matters most for a remote/less-trusted drop source); rejected content is
    # quarantined to .error and never handed to the handler.
    from messagefoundry.transports.file import ScanRejected, set_scan_hook

    def _reject_eicar(raw: bytes, source: str) -> None:
        if b"EICAR" in raw:
            raise ScanRejected("malware signature")

    set_scan_hook(_reject_eicar)
    try:
        client = _FakeClient(files={"/in/bad.hl7": b"MSH|EICAR", "/in/ok.hl7": b"MSH|clean"})
        src = _src(monkeypatch, client)
        h = _RecordingHandler()
        src._handler = h
        await src._poll_once()
    finally:
        set_scan_hook(None)  # restore the default no-op
    assert h.bodies == [b"MSH|clean"]  # only the clean file was delivered
    assert "/in/.error/bad.hl7" in client.files  # the flagged file was quarantined
    assert "/in/.processed/bad.hl7" not in client.files


async def test_source_content_sniff_quarantines_non_hl7_when_hl7v2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 5.2.2: a remote drop declared content_type=hl7v2 gets the same MSH/FHS/BHS header sniff the
    # local File source does — a binary/non-HL7 file that merely matches *.hl7 is quarantined to .error
    # before its bytes reach the pipeline, never handed to the handler.
    client = _FakeClient(
        files={"/in/bad.hl7": b"\x00\x01not an hl7 message", "/in/ok.hl7": b"MSH|^~\\&|A|B"}
    )
    src = _src(monkeypatch, client)
    src.content_type = ContentType.HL7V2  # runner injects this; set it directly here
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A|B"]  # only the real HL7 message was delivered
    assert "/in/.error/bad.hl7" in client.files  # the non-HL7 file was quarantined
    assert "/in/.processed/bad.hl7" not in client.files


async def test_source_content_sniff_active_for_x12_quarantines_non_isa(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 5.2.2: the sniff is content_type-SPECIFIC, not hl7v2-only. A remote x12 inbound sniffs the ISA
    # magic — a conformant ISA body flows verbatim (no MSH header, by X12 design), while a non-ISA body on
    # the SAME inbound is quarantined, proving the x12 sniff is genuinely active. (This replaces the stale
    # "sniff disabled for non-hl7" test, whose ISA payload passed because it MATCHED, not because sniff was off.)
    x12_body = b"ISA*00*          *00*          *ZZ*SENDER"
    client = _FakeClient(
        files={"/in/claim.hl7": x12_body, "/in/bogus.hl7": b"%PDF not an x12 body"}
    )
    src = _src(monkeypatch, client, pattern="*.hl7")
    src.content_type = ContentType.X12  # x12 inbound → ISA sniff stays ON
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [x12_body]  # only the conformant ISA body delivered
    assert "/in/.error/claim.hl7" not in client.files  # NOT quarantined
    assert "/in/.error/bogus.hl7" in client.files  # non-ISA quarantined (sniff active)


async def test_source_content_sniff_quarantines_non_fhir_when_fhir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 5.2.2 (WP245 follow-up): a remote drop declared content_type=fhir gets the JSON magic sniff
    # (FHIR is HL7 FHIR JSON) — a PDF that merely matches the glob is quarantined to .error before its
    # bytes reach the pipeline, while a JSON-shaped FHIR resource is delivered.
    resource = b'{"resourceType":"Patient","id":"1"}'
    client = _FakeClient(files={"/in/bad.fhir": b"%PDF-1.7 not fhir", "/in/ok.fhir": resource})
    src = _src(monkeypatch, client, pattern="*.fhir")
    src.content_type = ContentType.FHIR  # fhir inbound → JSON {/[ sniff ON
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [resource]  # only the JSON-shaped FHIR resource delivered
    assert "/in/.error/bad.fhir" in client.files  # the PDF was quarantined
    assert "/in/.error/ok.fhir" not in client.files


async def test_source_content_sniff_active_when_content_type_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 5.2.2: the former None-skips-sniff carve-out was REMOVED. content_type=None now converges onto
    # the local File source's None→hl7v2 semantics, so a non-HL7 drop is quarantined to .error even when
    # the inbound never had a content_type injected — while a real HL7 body still flows through.
    client = _FakeClient(files={"/in/bad.hl7": b"not-hl7", "/in/ok.hl7": b"MSH|^~\\&|A|B"})
    src = _src(monkeypatch, client)
    assert src.content_type is None  # default: unset
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A|B"]  # only the HL7 body delivered
    assert (
        "/in/.error/bad.hl7" in client.files
    )  # the non-HL7 drop is now quarantined (sniff active)
    assert "/in/.processed/bad.hl7" not in client.files
    assert "/in/.error/ok.hl7" not in client.files


def test_scan_hook_seam_defaults_to_noop_and_is_settable() -> None:
    from messagefoundry.transports.file import ScanRejected, scan_inbound_file, set_scan_hook

    scan_inbound_file(b"anything", "src")  # default no-op: does not raise
    try:
        captured: list[tuple[bytes, str]] = []

        def _hook(raw: bytes, source: str) -> None:
            captured.append((raw, source))
            raise ScanRejected("nope")

        set_scan_hook(_hook)
        with pytest.raises(ScanRejected):
            scan_inbound_file(b"x", "lbl")
        assert captured == [(b"x", "lbl")]
    finally:
        set_scan_hook(None)
    scan_inbound_file(b"x", "lbl")  # cleared → no-op again


# === security: cleartext-ftp credential guard ================================


def _ftp_dest(**over: Any) -> Destination:
    base: dict[str, Any] = dict(host="ftp.example.com", remote_dir="/in")  # noqa: C408
    base.update(over)
    return Destination(name="OB", type=ConnectorType.REMOTEFILE, settings=Ftp(**base).settings)


def test_plain_ftp_with_credentials_refused_without_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="CLEARTEXT"):
        build_destination(_ftp_dest(username="u", password="p"))


def test_plain_ftp_with_credentials_allowed_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    dest = build_destination(_ftp_dest(username="u", password="p"))
    assert isinstance(dest, RemoteFileDestination)  # builds (warns), not refused


def test_plain_ftp_without_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(_ftp_dest())  # anonymous — nothing to leak
    assert isinstance(dest, RemoteFileDestination)


def test_ftps_with_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(_ftp_dest(tls=True, username="u", password="p"))  # TLS → fine
    assert isinstance(dest, RemoteFileDestination)


# === security: FTPS TLS certificate verification (SEC-001) ===================


def test_ftps_context_verifies_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # The FTPS client builds a VERIFYING SSLContext (not ftplib's no-verify stdlib fallback): the server
    # certificate and hostname are validated. This is the core of the fix.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    client = _FtpClient({"host": "ftp.example.com", "remote_dir": "/in"}, tls=True)
    assert client._context is not None
    assert client._context.verify_mode == ssl.CERT_REQUIRED
    assert client._context.check_hostname is True


def test_plain_ftp_has_no_tls_context() -> None:
    # Plain ftp builds no TLS context (ftplib.FTP, no FTP_TLS) — guards the tls-branch boundary.
    client = _FtpClient({"host": "ftp.example.com", "remote_dir": "/in"}, tls=False)
    assert client._context is None


def test_ftps_insecure_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # tls_verify=false without the explicit escape is refused at construction (build_check), exactly like
    # the MLLP outbound path — never silently insecure.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="tls_verify=false"):
        _FtpClient({"host": "ftp.example.com", "remote_dir": "/in", "tls_verify": False}, tls=True)


def test_ftps_insecure_allowed_with_escape(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.remotefile"):
        client = _FtpClient(
            {"host": "ftp.example.com", "remote_dir": "/in", "tls_verify": False}, tls=True
        )
    assert client._context is not None
    assert client._context.verify_mode == ssl.CERT_NONE
    assert client._context.check_hostname is False
    assert any("verification is DISABLED" in r.message for r in caplog.records)


def test_ftps_connect_passes_context(monkeypatch: pytest.MonkeyPatch) -> None:
    # FTP_TLS is constructed with the built verifying context= kwarg (not the no-verify default).
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    recorded: dict[str, Any] = {}

    class _RecordingFTPTLS:
        def __init__(self, *, context: Any = None, timeout: float | None = None) -> None:
            recorded["context"] = context
            recorded["timeout"] = timeout

        def connect(self, host: str, port: int) -> None:
            pass

        def login(self, *, user: str, passwd: str) -> None:
            pass

        def prot_p(self) -> None:
            pass

        def quit(self) -> None:
            pass

        def close(self) -> None:
            pass

    import ftplib as _ftplib

    monkeypatch.setattr(_ftplib, "FTP_TLS", _RecordingFTPTLS)
    client = _FtpClient({"host": "ftp.example.com", "remote_dir": "/in"}, tls=True)
    ftp = client._connect()
    assert isinstance(ftp, _RecordingFTPTLS)
    assert isinstance(recorded["context"], ssl.SSLContext)
    assert recorded["context"].verify_mode == ssl.CERT_REQUIRED


def test_sftp_with_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.REMOTEFILE,
            settings=Sftp(host="h", remote_dir="/in", username="u", password="p").settings,
        )
    )
    assert isinstance(dest, RemoteFileDestination)  # SSH → credentials fine


# === security: SFTP host-key verification ====================================


class _FakePolicyError(Exception):
    pass


class _FakeSSHClient:
    """Minimal paramiko.SSHClient stand-in recording the missing-host-key policy chosen."""

    last_policy: Any = None

    def __init__(self) -> None:
        self.policy: Any = None

    def load_system_host_keys(self) -> None:
        pass

    def load_host_keys(self, path: str) -> None:
        pass

    def set_missing_host_key_policy(self, policy: Any) -> None:
        self.policy = policy
        type(self).last_policy = policy

    def connect(self, **kw: Any) -> None:
        if isinstance(self.policy, _RejectPolicy):
            # An unknown host key under RejectPolicy raises SSHException, as paramiko does.
            raise _SSHException("Server host key not found in known_hosts")

    def open_sftp(self) -> Any:
        raise AssertionError("connect should have raised before open_sftp under RejectPolicy")

    def close(self) -> None:
        pass


class _RejectPolicy:
    pass


class _AutoAddPolicy:
    pass


class _SSHException(Exception):
    pass


class _AuthException(Exception):
    pass


class _FakeTransport:
    """Stands in for ``paramiko.Transport``, carrying the real preferred-MAC and preferred-cipher lists.

    The connector reads these to derive its ``disabled_algorithms`` (BACKLOG #1171), so the fake has
    to HAVE them. Production deliberately does not tolerate their absence: a missing attribute there
    would yield an empty deny list, which silently restores the weak proposals -- the unsafe
    direction. A fake that omitted one would push the code toward that tolerance.

    Both tuples are copied from paramiko 5.0.0, the version ``constraints.lock`` pins. A copy can go
    stale against the real library, so ``test_fake_paramiko_algorithm_lists_match_the_installed_library``
    compares them where the ``[sftp]`` extra is installed -- and SKIPS, loudly, where it is not.
    """

    _preferred_macs = (
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1",
        "hmac-md5",
        "hmac-sha1-96",
        "hmac-md5-96",
    )

    _preferred_ciphers = (
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "3des-cbc",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    )


class _FakeParamiko:
    SSHClient = _FakeSSHClient
    Transport = _FakeTransport
    RejectPolicy = _RejectPolicy
    AutoAddPolicy = _AutoAddPolicy
    SSHException = _SSHException
    AuthenticationException = _AuthException

    class RSAKey:
        @staticmethod
        def from_private_key(*a: Any, **k: Any) -> Any:
            return object()


def test_sftp_unknown_host_key_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _FakeParamiko)
    client = _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})
    assert client._accept_unknown is False
    with pytest.raises(_RemoteError) as ei:
        client.list_dir("/in")
    assert ei.value.permanent is True  # a rejected host key is a permanent security stop


def test_sftp_unknown_host_key_accepted_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _FakeParamiko)
    client = _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})
    assert client._accept_unknown is True  # AutoAddPolicy will be selected (logged loudly)


def _sftp_connect_kwargs(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Drive ``_SftpClient._connect`` against the fake paramiko and return what it passed to connect.

    One capture path for every negotiation test: each one asserts about a different key of the same
    ``disabled_algorithms`` argument, and a per-test copy of the plumbing is a place for them to
    diverge without anyone noticing.
    """
    captured: dict[str, Any] = {}

    class _CapturingClient(_FakeSSHClient):
        def connect(self, **kw: Any) -> None:
            captured.update(kw)

    class _Paramiko(_FakeParamiko):
        SSHClient = _CapturingClient

    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: _Paramiko)
    _SftpClient({"host": "h", "port": 22, "remote_dir": "/in"})._connect()
    return captured


def test_sftp_proposes_no_weak_mac_and_the_check_cannot_pass_vacuously(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SFTP connector must not OFFER an HMAC over a disallowed hash (BACKLOG #1171, ASVS 11.4.1).

    paramiko's preferred MAC list carries ``hmac-md5``, ``hmac-sha1`` and their -96 truncations.
    Appendix C marks HMAC-MD5 **D** and SHA-1 **L** ("not suitable for HMAC"), and with no
    restriction a server that selects one gets it. The connector now subtracts an approved allow-list
    from whatever the installed library offers and disables the remainder.

    TWO ASSERTIONS, AND THE SECOND IS WHY THE FIRST MEANS ANYTHING. "No weak member survives" passes
    trivially against an EMPTY effective set -- which is exactly what a broken subtraction (or a
    paramiko that renamed ``_preferred_macs``) would produce. So the surviving set is asserted
    NON-EMPTY first. A connector that proposes nothing is a different defect, not a pass.
    """
    # _FakeTransport carries the real paramiko preferred list, weak members INCLUDED -- that fixture
    # is the thing under test, so the subtraction has to remove them rather than the fixture omitting
    # them. Referenced rather than re-declared here: two copies of the list would drift, and the copy
    # that drifted would be the one asserting safety.
    offered = _FakeTransport._preferred_macs

    disabled = _sftp_connect_kwargs(monkeypatch)["disabled_algorithms"]["macs"]
    effective = [m for m in offered if m not in disabled]

    # POSITIVE CONTROL FIRST: the connector still proposes something.
    assert effective, (
        "every MAC was disabled -- the connector would propose none and negotiation would fail. "
        "A 'no weak MAC' assertion passes vacuously against this state, which is why it is checked "
        f"first. disabled={disabled}"
    )
    weak = [m for m in effective if "md5" in m.lower() or "sha1" in m.lower()]
    assert not weak, f"the SFTP connector still proposes a disallowed-hash MAC: {weak}"
    # And the allow-list itself cannot acquire one without this reddening.
    assert not [m for m in _APPROVED_SFTP_MACS if "md5" in m.lower() or "sha1" in m.lower()]


def test_sftp_proposes_only_encrypt_then_mac(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every MAC the connector still proposes must be an ``-etm@openssh.com`` name.

    Encrypt-then-MAC is the composition order ASVS 11.3.5 asks about. The plain ``hmac-sha2-256`` /
    ``hmac-sha2-512`` names are SSH's Encrypt-and-MAC: the tag covers the PLAINTEXT, so a receiver
    decrypts attacker-chosen ciphertext before it can authenticate it. Same hash, wrong order -- a
    sound hash is why the two are easy to leave in, not a reason to.

    THE CONTROLS COME FIRST, AND ONLY THE LAST ASSERTION IS THE CLAIM. "No Encrypt-and-MAC name
    survives" passes for free against an empty surviving set, and equally for free against a fixture
    that offered no Encrypt-and-MAC name to begin with; both are checked before the claim is read.
    The empty-deny-list check between them is not a vacuity guard -- an empty deny list would make
    the claim FAIL -- it is there so that failure names the broken subtraction rather than making a
    reader infer it from a list of survivors.
    """
    offered = _FakeTransport._preferred_macs
    disabled = _sftp_connect_kwargs(monkeypatch)["disabled_algorithms"]["macs"]
    effective = [m for m in offered if m not in disabled]

    # CONTROL 1: the fixture really does offer a non-ETM name for the subtraction to remove.
    assert [m for m in offered if not m.endswith("-etm@openssh.com")], (
        "the fake's preferred-MAC list carries no Encrypt-and-MAC name, so this test would pass "
        "without the connector doing anything. Restore the real paramiko list."
    )
    # CONTROL 2: the subtraction found something. An empty deny list would redden the claim below
    # rather than hiding it, so this assertion is for the message a reader gets, not for the coverage.
    assert disabled, (
        "the derived MAC deny list is EMPTY -- the allow-list subtracted nothing, which is what a "
        "renamed paramiko attribute looks like. Every Encrypt-and-MAC name would be proposed."
    )
    # CONTROL 3: the connector still proposes something.
    assert effective, (
        "every MAC was disabled -- the connector would propose none and negotiation would fail. "
        f"disabled={disabled}"
    )
    encrypt_and_mac = [m for m in effective if not m.endswith("-etm@openssh.com")]
    assert not encrypt_and_mac, (
        f"the SFTP connector still proposes an Encrypt-and-MAC name: {encrypt_and_mac}"
    )
    # And the allow-list itself cannot acquire one without this reddening.
    assert all(m.endswith("-etm@openssh.com") for m in _APPROVED_SFTP_MACS)


def test_sftp_proposes_no_cbc_or_undersized_cipher_and_the_check_cannot_pass_vacuously(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connector must constrain the CIPHER proposal too, not just the MAC.

    paramiko 5.0.0's preferred cipher list carries ``aes128-cbc``, ``aes192-cbc``, ``aes256-cbc`` and
    ``3des-cbc``. CBC in SSH is what the chosen-ciphertext plaintext-recovery attack of CVE-2008-5161
    targets; 3DES adds a 64-bit block (Sweet32) and roughly 112 bits of effective strength, under the
    128-bit floor. With no cipher deny list the shipped connector OFFERS all four, and a server that
    selects one gets it -- the same defect the MAC arm above fixes, one key over in the same argument.

    The FIRST assertion is that the ``cipher`` key exists at all. Reading a missing key would raise,
    which is a red test, but the message a reader gets should name the control that is absent rather
    than a KeyError.
    """
    offered = _FakeTransport._preferred_ciphers
    disabled_algorithms = _sftp_connect_kwargs(monkeypatch)["disabled_algorithms"]

    assert "ciphers" in disabled_algorithms, (
        "the connector passed no cipher deny list, so paramiko's full default proposal -- CBC and "
        f"3DES included -- would go on the wire. keys passed: {sorted(disabled_algorithms)}"
    )
    disabled = disabled_algorithms["ciphers"]
    effective = [c for c in offered if c not in disabled]

    # CONTROL 1: the fixture really does offer a weak cipher for the subtraction to remove. Against a
    # fixture that offered none, the claim below passes without the connector doing anything.
    assert [c for c in offered if c.endswith("-cbc") or c.startswith("3des")], (
        "the fake's preferred-cipher list carries no CBC or 3DES name, so this test would pass for "
        "free. Restore the real paramiko list."
    )
    # CONTROL 2: the subtraction found something. An empty deny list is what a renamed paramiko
    # attribute produces. It would redden the claim below rather than hiding it, so this assertion is
    # for the message a reader gets, not for the coverage.
    assert disabled, (
        "the derived cipher deny list is EMPTY -- the allow-list subtracted nothing, which is what a "
        "renamed paramiko attribute looks like. Every weak cipher would be proposed."
    )
    # CONTROL 3: the connector still proposes something.
    assert effective, (
        "every cipher was disabled -- the connector would propose none and negotiation would fail. "
        f"disabled={disabled}"
    )
    weak = [c for c in effective if c.endswith("-cbc") or c.startswith("3des")]
    assert not weak, f"the SFTP connector still proposes a CBC or undersized cipher: {weak}"
    # And the allow-list itself cannot acquire one without this reddening.
    assert not [c for c in _APPROVED_SFTP_CIPHERS if c.endswith("-cbc") or c.startswith("3des")]


def test_fake_paramiko_algorithm_lists_match_the_installed_library() -> None:
    """The fake's copies of paramiko's preferred lists are the real ones -- checked, where it can be.

    The negotiation tests above subtract the allow-lists from a HARDCODED copy of paramiko 5.0.0's
    ``_preferred_macs`` and ``_preferred_ciphers``. A copy can go stale, and a stale copy would let
    those tests stay green while the real library proposed something nobody had graded.

    This test SKIPS where the ``[sftp]`` extra is not installed, which is the default: the extra is
    not in the dev install and CI's test legs do not add it. A skip is reported as a skip and not as
    a pass, which is the honest reading -- the comparison did not happen, so it claims nothing.
    """
    try:
        import paramiko
    except ImportError:
        pytest.skip(
            "the [sftp] extra is not installed, so paramiko's real preferred lists cannot be read "
            "here and the fake's copies go unverified. Install 'messagefoundry[sftp]' to check them."
        )

    assert tuple(paramiko.Transport._preferred_macs) == _FakeTransport._preferred_macs
    assert tuple(paramiko.Transport._preferred_ciphers) == _FakeTransport._preferred_ciphers


# === egress allowlist ([egress].allowed_remote) ==============================


def _remote_dest(host: str, port: int = 22) -> Destination:
    return Destination(
        name="OB",
        type=ConnectorType.REMOTEFILE,
        settings=Sftp(host=host, port=port, remote_dir="/in").settings,
    )


def test_egress_blocks_unlisted_host() -> None:
    with pytest.raises(WiringError):
        check_egress_allowed(
            _remote_dest("other.example.com"), EgressSettings(allowed_remote=["sftp.example.com"])
        )


def test_egress_permits_listed_host() -> None:
    check_egress_allowed(
        _remote_dest("sftp.example.com"), EgressSettings(allowed_remote=["sftp.example.com"])
    )


def test_egress_host_port_match() -> None:
    egress = EgressSettings(allowed_remote=["sftp.example.com:22"])
    check_egress_allowed(_remote_dest("sftp.example.com", 22), egress)  # ok
    with pytest.raises(WiringError):
        check_egress_allowed(_remote_dest("sftp.example.com", 23), egress)  # wrong port


def test_egress_unrestricted_when_empty() -> None:
    check_egress_allowed(_remote_dest("anywhere.example"), EgressSettings())


def _remote_src_cfg(host: str, port: int = 22) -> Source:
    return Source(
        type=ConnectorType.REMOTEFILE,
        settings=Sftp(host=host, port=port, remote_dir="/in").settings,
    )


def test_source_connect_blocks_unlisted_host() -> None:
    with pytest.raises(WiringError):
        check_source_allowed(
            _remote_src_cfg("other.example.com"),
            "IB_REMOTE",
            EgressSettings(allowed_remote=["sftp.example.com"]),
        )


def test_source_connect_permits_listed_host() -> None:
    check_source_allowed(
        _remote_src_cfg("sftp.example.com"),
        "IB_REMOTE",
        EgressSettings(allowed_remote=["sftp.example.com"]),
    )


def test_source_connect_unrestricted_when_empty() -> None:
    check_source_allowed(_remote_src_cfg("anywhere.example"), "IB_REMOTE", EgressSettings())


# === factory smoke ===========================================================


def test_sftp_factory_protocol_and_settings() -> None:
    spec = Sftp(host="h", remote_dir="/in", username="u")
    assert spec.type is ConnectorType.REMOTEFILE
    assert spec.settings["protocol"] == "sftp"
    assert spec.settings["port"] == 22
    assert spec.settings["host"] == "h"


def test_ftp_factory_plain_vs_tls() -> None:
    assert Ftp(host="h", remote_dir="/in").settings["protocol"] == "ftp"
    assert Ftp(host="h", remote_dir="/in", tls=True).settings["protocol"] == "ftps"
    assert Ftp(host="h", remote_dir="/in").settings["port"] == 21


@pytest.mark.parametrize("missing", ["host", "remote_dir"])
def test_requires_core_settings(missing: str) -> None:
    base: dict[str, Any] = dict(host="h", remote_dir="/in")  # noqa: C408
    base[missing] = ""
    with pytest.raises(ValueError):
        build_destination(
            Destination(name="OB", type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings)
        )


# === test_connection() reachability probe ====================================


async def test_dest_probe_ensures_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    dest = _dest(monkeypatch, client)
    await dest.test_connection()  # connect + ensure the upload dir; no file written
    assert "/in" in client.dirs
    assert not client.files


async def test_dest_probe_permanent_error_is_negative_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()

    def _boom(remote_dir: str) -> None:
        raise _RemoteError("auth failed", permanent=True)

    client.ensure_dir = _boom  # type: ignore[method-assign]
    dest = _dest(monkeypatch, client)
    with pytest.raises(NegativeAckError):
        await dest.test_connection()


async def test_src_probe_lists_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"AAA"})
    src = _src(monkeypatch, client)
    await src.test_connection()  # read-only list of the poll dir; nothing moved/removed
    assert not client.ops


async def test_src_probe_transient_error_is_delivery_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()

    def _boom(remote_dir: str) -> list[tuple[str, int]]:
        raise _RemoteError("connection reset", permanent=False)

    client.list_dir = _boom  # type: ignore[method-assign]
    src = _src(monkeypatch, client)
    with pytest.raises(DeliveryError) as ei:
        await src.test_connection()
    assert not isinstance(ei.value, NegativeAckError)


def test_sftp_ftp_exported_from_top_level_package() -> None:
    # Sftp/Ftp must be on the public `messagefoundry` surface like the other connectors
    # (Tcp/Soap/Rest/File/Database*), so feeds import them the same way — not from
    # messagefoundry.config.wiring. (Surfaced by an SFTP migration rework.)
    import messagefoundry
    from messagefoundry import Ftp as PublicFtp
    from messagefoundry import Sftp as PublicSftp

    assert PublicSftp is Sftp and PublicFtp is Ftp
    assert "Sftp" in messagefoundry.__all__ and "Ftp" in messagefoundry.__all__


# === security: FTPS mTLS encrypted client-key passphrase (FILE-19) ============
#
# The FTPS client-identity path in _ftps_ssl_context (remotefile.py:206-207) uses an empty-bytes
# password callback — `pw_arg = key_password if key_password is not None else (lambda: b"")` — so an
# encrypted client key with NO tls_key_password fails deterministically (ssl.SSLError) instead of
# falling back to OpenSSL's blocking TTY prompt. There is no TTY under a service account / container,
# so the prompt would hang the process forever. This is remotefile.py's own copy of the guard (the
# MLLP twin _mllp_ssl_context has a separate copy); the coverage does not transfer.


def _encrypted_client_cert(tmp_path: Path, passphrase: str) -> tuple[str, str]:
    """A self-signed EC cert + a private key PEM **encrypted** with ``passphrase`` (PKCS#8), for the
    FTPS client-identity (mTLS) path. Mirrors test_mllp_tls.py's ``_encrypted_cert`` helper."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cp, kp = tmp_path / "ftps-enc-c.pem", tmp_path / "ftps-enc-k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
    )
    return str(cp), str(kp)


def test_ftps_encrypted_client_key_missing_password_raises_not_prompts(tmp_path: Path) -> None:
    # LOAD-BEARING security assertion (FILE-19): an encrypted client key with NO tls_key_password must
    # fail deterministically (ssl.SSLError) via the empty-bytes callback, NOT fall back to OpenSSL's
    # blocking TTY prompt (there is no TTY under a service account). Without the guard at
    # remotefile.py:206 this test would HANG on the prompt instead of raising.
    cert, key = _encrypted_client_cert(tmp_path, "s3cr3t-pass")
    with pytest.raises(ssl.SSLError):
        _ftps_ssl_context({"host": "h", "tls_cert_file": cert, "tls_key_file": key})


def test_ftps_encrypted_client_key_with_password_loads(tmp_path: Path) -> None:
    # Positive companion: the correct tls_key_password decrypts the client key and yields a context —
    # proving the passphrase is actually applied (not merely that the empty callback always fails).
    cert, key = _encrypted_client_cert(tmp_path, "s3cr3t-pass")
    ctx = _ftps_ssl_context(
        {
            "host": "h",
            "tls_cert_file": cert,
            "tls_key_file": key,
            "tls_key_password": "s3cr3t-pass",
        }
    )
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_ftps_encrypted_client_key_wrong_password_raises(tmp_path: Path) -> None:
    # Negative companion: a WRONG tls_key_password can't decrypt the client key → ssl.SSLError. Proves
    # the passphrase is enforced, not ignored.
    cert, key = _encrypted_client_cert(tmp_path, "s3cr3t-pass")
    with pytest.raises(ssl.SSLError):
        _ftps_ssl_context(
            {"host": "h", "tls_cert_file": cert, "tls_key_file": key, "tls_key_password": "WRONG"}
        )


# --- #114 opt-in startup directory validation: the OUTBOUND half -------------

_UPLOAD_BODY = "MSH|^~\\&|A|B|C|D|20260810||ADT^A01|MSGX|P|2.5"


async def test_remote_destination_test_probe_creates_the_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The REMOTEFILE half of the same measured claim as the File sibling: the on-demand probe ENSURES
    # (creates) remote_dir, so it cannot answer the question a startup-validation toggle asks.
    client = _FakeClient()
    await _dest(monkeypatch, client).test_connection()
    assert client.dirs == ["/in"]  # ensure_dir, not a listing — the probe creates


async def test_remote_destination_validate_directory_off_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The item's own trigger: an intermittently-available remote directory (a listing fails right now)
    # must NOT fail startup with the toggle off. Default = defer to run time, exactly as before.
    client = _FakeClient(list_exc=_RemoteError("no such dir", permanent=True))
    await _dest(monkeypatch, client).validate_startup()  # no raise
    assert client.dirs == []  # and the hook created nothing


async def test_remote_destination_intermittent_dir_starts_and_then_delivers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The item's trigger end to end, on the default (lenient) setting: remote_dir is unreachable at
    # start, so startup validation must NOT refuse the lane — and once the share comes back the upload
    # goes through. This is why the toggle is opt-in rather than the default.
    client = _FakeClient(list_exc=_RemoteError("share is down", permanent=False))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    await dest.validate_startup()  # start is not blocked by a share that is down right now
    client._list_exc = None  # the mount returns
    await dest.send(_UPLOAD_BODY)
    assert client.files["/in/msg.hl7"] == _UPLOAD_BODY.encode("utf-8")


async def test_remote_destination_validate_directory_refuses_unreachable_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(list_exc=_RemoteError("no such dir", permanent=True))
    dest = _dest(monkeypatch, client, validate_directory=True)
    with pytest.raises(DestinationStartupError):
        await dest.validate_startup()
    assert client.dirs == []  # LIST is the no-create probe — ensure_dir is never called


async def test_remote_destination_validate_directory_passes_when_listable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    await _dest(monkeypatch, client, validate_directory=True).validate_startup()
    assert client.dirs == []


async def test_remote_destination_created_directory_is_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Default arm, unchanged except that a CREATED upload directory is now loud.
    client = _FakeClient()
    dest = _dest(monkeypatch, client)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.remotefile"):
        await dest.send(_UPLOAD_BODY)
    assert "CREATED missing directory" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.remotefile"):
        await dest.send(_UPLOAD_BODY)
    assert "CREATED missing directory" not in caplog.text  # only a real creation is loud


async def test_remote_destination_validate_directory_upload_never_creates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Under the toggle the upload directory is never created at delivery time either, and the failure is
    # deliberately RECLASSIFIED as transient: an SFTP/FTP no-such-dir is a PERMANENT error, so letting
    # the upload fail naturally would dead-letter live traffic over a merely-unmounted share.
    client = _FakeClient(list_exc=_RemoteError("no such dir", permanent=True))
    dest = _dest(monkeypatch, client, validate_directory=True)
    with pytest.raises(DeliveryError) as exc:
        await dest.send(_UPLOAD_BODY)
    assert not isinstance(exc.value, NegativeAckError)  # retried, never dead-lettered
    assert client.dirs == []  # never created
    assert client.ops == []  # and nothing was stored


async def test_remote_destination_validate_directory_test_probe_never_creates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(list_exc=_RemoteError("no such dir", permanent=True))
    dest = _dest(monkeypatch, client, validate_directory=True)
    with pytest.raises(DeliveryError):
        await dest.test_connection()
    assert client.dirs == []


# --- #1238 (ASVS 5.3.2): a server-chosen listing name is REJECTED, never rewritten ---------------


class _HostileListingClient(_FakeClient):
    """A client whose listing returns names the SERVER chose, verbatim.

    ``_FakeClient.list_dir`` derives names with ``posixpath.basename`` off its ``files`` keys, so it
    structurally cannot produce a traversal name -- it would sanitize the very input under test. This
    subclass returns the raw listing instead, which is what a hostile partner server does.
    """

    def __init__(self, names: list[str], **kw: Any) -> None:
        super().__init__(**kw)
        self._names = names

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        return [(n, 10) for n in self._names]


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd.hl7",  # traversal, and the default *.hl7 pattern MATCHES it
        "/etc/passwd.hl7",  # absolute
        r"..\..\etc\passwd.hl7",  # Windows separators -- posixpath.basename is a NO-OP on this
        "sub/dir.hl7",  # a subdirectory component
        ".",
        "..",
        "",
        "a\x00b.hl7",  # NUL
        "a\nb.hl7",  # newline
        "C:evil.hl7",  # drive-relative: NO separator at all, so a separator-only check misses it
    ],
)
def test_unsafe_listing_names_are_refused(name: str) -> None:  # #1238
    assert _is_contained_name(name) is False


@pytest.mark.parametrize(
    "name",
    ["a.hl7", "adt_20260812.hl7", "A-1.2_3.hl7", "file with spaces.hl7", "unicode-\u00e9.hl7"],
)
def test_legitimate_listing_names_are_accepted(name: str) -> None:  # #1238
    # The refusal must not be so broad that it rejects ordinary partner filenames -- a check that
    # refuses everything is not a control either.
    assert _is_contained_name(name) is True


async def test_traversal_entry_is_never_retrieved(monkeypatch: pytest.MonkeyPatch) -> None:  # #1238
    """The whole point: a hostile listing entry reaches NO consumer.

    Asserted on the client's recorded ops, not on the handler alone, because the raw name reaches at
    least four consumers (retrieve, the error/oversize move, the after_read disposition, and the
    leave-mode dedup key). Checking only "the handler was not called" would pass even if the engine
    had already moved or deleted at the hostile path.
    """
    client = _HostileListingClient(["../../etc/passwd.hl7"])
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == []  # nothing ingested
    assert client.ops == []  # and NOTHING was retrieved, moved, renamed or removed


async def test_a_safe_entry_beside_a_hostile_one_still_flows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # #1238
    # Refusing one entry must not abort the poll -- the legitimate file beside it is still delivered.
    # Without this, a hostile server could suppress a real feed by planting one bad name.
    client = _HostileListingClient(["../../etc/passwd.hl7", "good.hl7"])
    client.files["/in/good.hl7"] = rb"MSH|^~\&|A"
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    assert h.bodies == [rb"MSH|^~\&|A"]


# --- the key names ARE the control -------------------------------------------------------------
#
# This pair exists because the shipped control was INERT and every test in this file stayed green.
# `disabled_algorithms` was passed as {"mac": ...}; paramiko reads "macs". `_filter_algorithm` does
# `self.disabled_algorithms.get(type_, [])`, so a singular key returns the empty default and every
# weak algorithm stays on the wire. paramiko neither validates the keys nor warns about an unknown
# one, so nothing anywhere reported a problem.
#
# The old tests could not catch it because they READ THE SAME WRONG KEY the production code wrote,
# then recomputed the subtraction by hand against the fake. Test and code agreed on a fiction. Their
# "cannot pass vacuously" guard fired on an EMPTY deny list -- the renamed-attribute failure -- while
# a WRONG KEY yields a fully populated deny list that paramiko silently ignores.
#
# So the first test below pins the literal key names and runs EVERYWHERE, including where paramiko
# is absent, which is the environment this repository's CI test legs actually use. The second checks
# those literals against the installed library when there is one. Neither alone is enough: the first
# cannot know the names are right, and the second does not run often enough to rely on.

_PARAMIKO_DISABLED_ALGORITHM_KEYS = frozenset(
    {"ciphers", "macs", "keys", "pubkeys", "kex", "compression"}
)


def test_disabled_algorithms_uses_plural_keys_and_this_test_runs_without_paramiko(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regression guard for an inert control. Asserts the EXACT key set the connector passes."""
    passed = _sftp_connect_kwargs(monkeypatch)["disabled_algorithms"]
    assert set(passed) == {"macs", "ciphers"}, (
        f"the connector passed {sorted(passed)}. paramiko reads {sorted(_PARAMIKO_DISABLED_ALGORITHM_KEYS)}; "
        "a key outside that set disables NOTHING and the weak algorithms stay on the wire."
    )
    # Belt and braces: every key must be one paramiko actually consults, so a future third arm
    # ("kex", say) cannot be added under a singular name and go quietly inert the same way.
    assert set(passed) <= _PARAMIKO_DISABLED_ALGORITHM_KEYS
    # CONTROL: the deny lists must be non-empty, or the right key would be carrying nothing.
    assert passed["macs"] and passed["ciphers"]


def test_the_pinned_key_names_match_the_installed_paramiko() -> None:
    """Check the literals above against the real library when it is importable.

    Skips honestly where the ``[sftp]`` extra is absent -- which is most environments here -- rather
    than asserting a comparison it did not make. The test above is the one that always runs.
    """
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    import inspect
    import re

    src = inspect.getsource(paramiko.transport)
    called_with = set(re.findall(r"""_filter_algorithm\(\s*["']([a-z]+)["']""", src))
    assert called_with, "control: found no _filter_algorithm call sites, so this proves nothing"
    assert {"macs", "ciphers"} <= called_with, (
        f"installed paramiko {paramiko.__version__} filters on {sorted(called_with)}; the connector's "
        "keys are no longer the ones it reads, so the control is inert again."
    )
