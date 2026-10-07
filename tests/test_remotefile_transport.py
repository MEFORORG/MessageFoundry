# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""REMOTEFILE transport connector (SFTP / FTP / FTPS): upload, poll, error mapping, security, egress.

The remote client is faked (``_make_client`` is monkeypatched, or the ``_SftpClient`` host-key policy
is exercised against a fake paramiko module), so nothing hits the network or SSH — exactly like the
DATABASE driver fake and the REST opener fake. paramiko need not be installed.

One exception: where paramiko IS installed, the real-handshake tests near the cipher tests start a
loopback SSH server on 127.0.0.1 and handshake with it. They skip where it is not.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import posixpath
import ssl
import traceback
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _phi_log_capture import (
    IDENTIFIER_SHAPE,
    IDENTIFIER_SHAPED_NAMES,
    SAFE_NAME_LABEL,
    filtered_sink,
    strip_safe_labels,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Ftp, Sftp, WiringError
from messagefoundry.keywrap import KeyWrapRefused
from messagefoundry.redaction import safe_exc
from messagefoundry.transports import build_destination, build_source, remotefile
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationStartupError,
    NegativeAckError,
)
from messagefoundry.transports.egress import check_egress_allowed, check_source_allowed
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
from tests._approved_key_wrap import approved_pkcs8_pem
from tests.test_encode_wire_body import (
    CJK_CHAR,
    PAYLOAD,
    SECRET_CHAR,
    _assert_content_free,
    _escapes,
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
        self.list_calls = 0  # #1936: lets a test prove a path never listed

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        self.list_calls += 1
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
        for start in range(0, len(body), _CHUNK):
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

    def publish(self, src: str, candidates: Sequence[str]) -> str | None:
        # BACKLOG #2553: the overwrite-off publish. Refuses a taken name, as the SFTP RENAME does,
        # and records each try as a publish, so a test can tell it from the replacing rename. It
        # takes the injected rename failure, since it is the rename on this path.
        for dst in candidates:
            self.ops.append(("publish", f"{src}->{dst}"))
            if self._rename_exc is not None:
                raise self._rename_exc
            if dst not in self.files:
                self.files[dst] = self.files.pop(src)
                return dst
        return None

    def remove(self, path: str) -> None:
        self.ops.append(("remove", path))
        self.files.pop(path, None)

    def dispose_unless_changed(self, path: str, expected_size: int, dest: str | None) -> int | None:
        # #116: a real client stats then renames/removes on one connection. The stored body's length
        # is what a stat reports; the listing's `sizes` override models a lying LISTING, not a stat.
        # Delegates to rename/remove so their recorded ops and injected failures stay as they were.
        if path in self.files and len(self.files[path]) != expected_size:
            return len(self.files[path])
        if dest is None:
            self.remove(path)
        else:
            self.rename(path, dest)
        return None

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
    monkeypatch: pytest.MonkeyPatch, client: _FakeClient, *, protocol: str = "sftp", **over: Any
) -> RemoteFileDestination:
    """``protocol`` is ``sftp``, ``ftps`` or ``ftp``. The client is faked, so it only changes which
    factory builds the settings."""
    _install_client(monkeypatch, client)
    base: dict[str, Any] = dict(host="sftp.example.com", remote_dir="/in")  # noqa: C408
    base.update(over)
    spec = Sftp(**base) if protocol == "sftp" else Ftp(tls=protocol == "ftps", **base)
    assert spec.settings["protocol"] == protocol
    d = build_destination(
        Destination(name="OB_REMOTE", type=ConnectorType.REMOTEFILE, settings=spec.settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, RemoteFileDestination)
    return d


def _src(monkeypatch: pytest.MonkeyPatch, client: _FakeClient, **over: Any) -> RemoteFileSource:
    _install_client(monkeypatch, client)
    base: dict[str, Any] = dict(host="sftp.example.com", remote_dir="/in")  # noqa: C408
    base.update(over)
    s = build_source(
        Source(type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings),
        egress=EgressSettings(deny_by_default=False),
    )
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


async def _settle(src: RemoteFileSource) -> None:
    """Take the settle poll (BACKLOG #2071): a first sighting of a file only records its listed size,
    so a test that expects a file to be read takes this poll first. It reads, moves and emits
    nothing."""
    await src._poll_once()


# === destination =============================================================


async def test_destination_uploads_store_then_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    await dest.send("MSH|^~\\&|A|B")
    # The final file exists with the payload, and store happened BEFORE the publish (atomic). With
    # overwrite off that is the refusing publish, never the replacing rename (BACKLOG #2553).
    assert client.files["/in/msg.hl7"] == b"MSH|^~\\&|A|B"
    op_names = [op for op, _ in client.ops]
    assert op_names.index("store") < op_names.index("publish")
    assert "rename" not in op_names
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


@pytest.mark.parametrize(
    "list_exc",
    [
        # The motivating case (BACKLOG #1936): a bounded SFTP session open that gave up after 120 s.
        _RemoteError("SFTP session open timed out", permanent=False),
        # A permanent listing refusal (an FTP 550 on a write-only drop box, a vanished dir) is retried
        # too: the name cannot be checked, which is a reason to wait, not a verdict on the message.
        _RemoteError("FTP rejected the operation: 550 permission denied", permanent=True),
    ],
    ids=["transient", "permanent"],
)
async def test_destination_unlistable_dir_fails_closed_without_writing(
    monkeypatch: pytest.MonkeyPatch, list_exc: _RemoteError
) -> None:
    # Before #1936's follow-on, _unique swallowed a failed listing and returned the unsuffixed name, so
    # the store + rename that followed would clobber a partner file already there on first deployment.
    # overwrite=False must never write blind: the delivery fails retryably and nothing is written.
    client = _FakeClient(files={"/in/msg.hl7": b"partner file"}, list_exc=list_exc)
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=False)
    with pytest.raises(DeliveryError) as ei:
        await dest.send("new")
    assert not isinstance(ei.value, NegativeAckError)  # transient -> the row retries
    assert client.ops == []  # no store, no rename, no remove
    assert client.files == {"/in/msg.hl7": b"partner file"}  # the partner file is untouched


@pytest.mark.parametrize("validate_directory", [False, True])
async def test_destination_unlistable_dir_keeps_the_credential_stop(
    monkeypatch: pytest.MonkeyPatch, validate_directory: bool
) -> None:
    # A credential refusal on a send-path listing keeps its ADR 0095 marker, so the delivery worker
    # still STOPs and retains rather than retrying into an account lockout. Both listings count: the
    # collision check, and the validate_directory pre-flight that runs before it. Nothing is written.
    client = _FakeClient(
        list_exc=_RemoteError("auth failed", permanent=True, credential_fault=True)
    )
    dest = _dest(
        monkeypatch,
        client,
        filename="msg.hl7",
        overwrite=False,
        validate_directory=validate_directory,
    )
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("new")
    assert ei.value.credential_fault is True
    assert client.ops == []


async def test_destination_overwrite_true_never_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    # Control: overwrite=True asks for no collision check, so an unlistable dir does not block it.
    client = _FakeClient(list_exc=_RemoteError("no list permission", permanent=True))
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=True)
    await dest.send("new")
    assert client.files["/in/msg.hl7"] == b"new"
    assert client.list_calls == 0


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


async def test_destination_cleans_temp_on_failed_store(monkeypatch: pytest.MonkeyPatch) -> None:
    # #2082: a store cut off part-way (the SFTP stall bound, a dropped connection) can leave a partial
    # temp on the partner's server, one more on every retry. It is removed before the retry.
    client = _FakeClient(store_exc=_RemoteError("SFTP upload stalled", permanent=False))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(DeliveryError):
        await dest.send("x")
    (stored,) = [p for op, p in client.ops if op == "store"]
    assert ("remove", stored) in client.ops


async def test_destination_keeps_temp_after_a_credential_fault_on_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # CONTROL: after a refused credential, removing the temp would be one more login attempt against
    # the partner account, and nothing was written anyway.
    client = _FakeClient(
        store_exc=_RemoteError("auth failed", permanent=True, credential_fault=True)
    )
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(NegativeAckError):
        await dest.send("x")
    assert not any(op == "remove" for op, _ in client.ops)


async def test_destination_cleans_temp_on_failed_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(rename_exc=_RemoteError("rename failed", permanent=False))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(DeliveryError):
        await dest.send("x")
    assert any(op == "remove" for op, _ in client.ops)  # temp cleaned up
    assert not client.files  # nothing left behind


@pytest.mark.parametrize(
    "marker", [{"credential_fault": True}, {"config_fault": True}], ids=["credential", "config"]
)
async def test_destination_cleans_temp_after_a_connection_fault_on_rename(
    monkeypatch: pytest.MonkeyPatch, marker: dict[str, bool]
) -> None:
    # BACKLOG #2083 fix round 4: unlike the store branch, the rename branch still removes the temp
    # after a connection fault. The store succeeded, so the temp holds a whole message; the lane
    # stops right after, so the cleanup costs one more login at most.
    client = _FakeClient(rename_exc=_RemoteError("refused", permanent=True, **marker))
    dest = _dest(monkeypatch, client, filename="msg.hl7")
    with pytest.raises(NegativeAckError):
        await dest.send("x")
    assert any(op == "remove" for op, _ in client.ops)


# --- an unencodable payload fails content-free (see encode_wire_body) ------------------------------

#: Synthetic. The marker must not be reachable from the raised error by the routes tested below.
_BODY_MARKER = "ZZSYNTHMARKER42"
_NON_ASCII_BODY = f"{PAYLOAD}NTE|1||{_BODY_MARKER}\r"
_LONE_SURROGATE = "\ud800"
#: At least the three outbound protocols shipped today. They share one _upload, and the client is
#: faked, so the protocol only changes which settings build the destination.
_PROTOCOLS = ["sftp", "ftps", "ftp"]


@pytest.mark.parametrize("protocol", _PROTOCOLS)
@pytest.mark.parametrize(
    ("encoding", "payload"),
    [
        ("us-ascii", _NON_ASCII_BODY),
        ("latin-1", _NON_ASCII_BODY),
        # The shipped default: utf-8 refuses only a lone surrogate. This pins the helper on the
        # default codec; it does not claim such a payload can reach send() past the store.
        ("utf-8", _NON_ASCII_BODY + _LONE_SURROGATE),
    ],
    ids=["us-ascii", "latin-1", "utf-8-lone-surrogate"],
)
async def test_an_unencodable_payload_is_a_permanent_content_free_refusal(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    protocol: str,
    encoding: str,
    payload: str,
) -> None:
    """Classified as Direct classifies it. The refusal crosses ``asyncio.to_thread`` and
    ``send``'s ``_RemoteError`` arm unchanged. Nothing of the message reaches the text, the repr,
    ``safe_exc`` (what the delivery worker stores in ``queue.last_error`` and
    ``message_events.detail``), the formatted traceback, the chain read by attribute, or a log
    record. Frame LOCALS still hold the payload, as on every connector; this does not test them.

    Before the fix ``_upload`` raised a bare UnicodeEncodeError: its text named the offending
    character and its ``.object`` held the whole payload. It escaped as itself, so the raises
    fails."""
    client = _FakeClient()
    dest = _dest(monkeypatch, client, protocol=protocol, filename="msg.hl7", encoding=encoding)
    with caplog.at_level(logging.DEBUG), pytest.raises(NegativeAckError) as ei:
        await dest.send(payload)
    exc = ei.value
    _assert_content_free(exc, encoding=encoding)
    # One line at a time, minus the File lines: a checkout path may itself hold "e9" or an accent.
    frames = "".join(traceback.format_exception(exc)).splitlines()
    surfaces = {
        "str": str(exc),
        "repr": repr(exc),
        "stored error": safe_exc(exc),
        "traceback": "\n".join(line for line in frames if not line.lstrip().startswith("File ")),
        "log": caplog.text,
    }
    for where, text in surfaces.items():
        assert _BODY_MARKER not in text, f"message content reached the {where}"
        for ch in (SECRET_CHAR, CJK_CHAR, _LONE_SURROGATE):
            for form in _escapes(ch):
                assert form not in text, f"a message character reached the {where} as {form!r}"
    # The same bytes never encode on a retry, so the row dead-letters on the first attempt. A bad
    # MESSAGE, so neither flag may stop the whole lane.
    assert exc.permanent is True and exc.code == "encoding"
    assert exc.credential_fault is False and exc.config_fault is False
    # Refused before any I/O: nothing listed, created, stored or left behind on the partner.
    assert client.ops == [] and client.dirs == [] and client.list_calls == 0
    assert client.files == {}


@pytest.mark.parametrize("protocol", _PROTOCOLS)
@pytest.mark.parametrize(
    ("encoding", "payload"),
    [
        ("utf-8", _NON_ASCII_BODY),
        ("latin-1", _NON_ASCII_BODY.replace(CJK_CHAR, "")),
    ],
    ids=["utf-8", "latin-1"],
)
async def test_an_encodable_payload_still_uploads(
    monkeypatch: pytest.MonkeyPatch, protocol: str, encoding: str, payload: str
) -> None:
    """POSITIVE CONTROL. A guard that refused every non-ASCII payload would pass the test above. The
    guard keys on the codec: latin-1 carries the e-acute it can encode."""
    client = _FakeClient()
    dest = _dest(monkeypatch, client, protocol=protocol, filename="msg.hl7", encoding=encoding)
    await dest.send(payload)
    assert client.files == {"/in/msg.hl7": payload.encode(encoding)}


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
    await _settle(src)
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
    await _settle(src)
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A"]  # the .txt is ignored (pattern), the .hl7 sniffs as HL7


async def test_source_after_read_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client, after_read="delete")
    h = _RecordingHandler()
    src._handler = h
    await _settle(src)
    await src._poll_once()
    assert h.bodies == [b"MSH|^~\\&|A"]
    assert "/in/a.hl7" not in client.files  # deleted, not moved
    assert not any(p.startswith("/in/.processed") for p in client.files)


async def test_source_handler_failure_leaves_file(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client)
    h = _RecordingHandler(exc=RuntimeError("store write failed"))
    src._handler = h
    await _settle(src)
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
    await _settle(src)
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
        src._file_key("a.hl7", 3, None)
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
    k1 = s1._file_key("m.hl7", 3, None)
    s2 = _src(monkeypatch, c2, after_read="leave", remote_dir="/other")
    k2 = s2._file_key("m.hl7", 3, None)
    assert k1 != k2  # distinct remote paths → distinct hashed keys


async def test_source_oversize_moves_to_error_without_retrieving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={"/in/big.hl7": b"x" * 10}, sizes={"/in/big.hl7": 10})
    src = _src(monkeypatch, client, max_file_bytes=5)
    h = _RecordingHandler()
    src._handler = h
    await _settle(src)
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

    def stat(self) -> SimpleNamespace:
        # #116: the retrieve reads the handle's size on each side of the transfer.
        return SimpleNamespace(st_size=len(self.body))

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

    def voidcmd(self, cmd: str) -> str:
        return "200 OK"

    def size(self, path: str) -> int:
        # #116: the retrieve reads SIZE on each side of the transfer.
        return len(self.body)

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
    await _settle(src)
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
    await _settle(src)
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
    await _settle(src)
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
    await _settle(src)
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
        await _settle(src)
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
    await _settle(src)
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
    await _settle(src)
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
    await _settle(src)
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
    await _settle(src)
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
        build_destination(
            _ftp_dest(username="u", password="p"), egress=EgressSettings(deny_by_default=False)
        )


def test_plain_ftp_with_credentials_allowed_with_escape(
    escape_at_warn: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    dest = build_destination(
        _ftp_dest(username="u", password="p"), egress=EgressSettings(deny_by_default=False)
    )
    assert isinstance(dest, RemoteFileDestination)  # builds (warns), not refused


def test_plain_ftp_without_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(
        _ftp_dest(), egress=EgressSettings(deny_by_default=False)
    )  # anonymous — nothing to leak
    assert isinstance(dest, RemoteFileDestination)


def test_ftps_with_credentials_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest = build_destination(
        _ftp_dest(tls=True, username="u", password="p"),
        egress=EgressSettings(deny_by_default=False),
    )  # TLS → fine
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
    escape_at_warn: None, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
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

        def auth(self) -> None:
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
        ),
        egress=EgressSettings(deny_by_default=False),
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

    def get_transport(self) -> Any:
        # A host-key rejection arrives on a negotiated transport; why that matters to the connector
        # is stated in remotefile._sftp_slow_peer's docstring (BACKLOG #1999).
        return SimpleNamespace(initial_kex_done=True, is_active=lambda: True)

    def close(self) -> None:
        pass


class _RejectPolicy:
    pass


class _AutoAddPolicy:
    pass


class _SSHException(Exception):
    pass


class _AuthException(_SSHException):
    """Subclasses the SSH exception, as ``paramiko.AuthenticationException`` does."""


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
    SFTPError = type("SFTPError", (Exception,), {})

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


def test_sftp_unknown_host_key_accepted_with_escape(
    escape_at_warn: None, monkeypatch: pytest.MonkeyPatch
) -> None:
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

    This test SKIPS where the ``[sftp]`` extra is not installed. Where it must run is
    ``tests/test_sftp_extra_on_ci_leg.py``'s to say. A skip is reported as a skip and not as a pass, which is the honest reading -- the comparison did
    not happen, so it claims nothing.
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


def test_sftp_proposes_no_ctr_or_aes128_cipher(monkeypatch: pytest.MonkeyPatch) -> None:
    """CTR and AES-128 are out of the cipher proposal (BACKLOG #2041 and #2044).

    ASVS Appendix C gives CTR status D (disallowed), and owner ruling R4 of 2026-09-26 (BACKLOG
    #2042) withdrew ``aes128-gcm@openssh.com``. What survives is ``aes256-gcm@openssh.com`` alone.

    The controls come first, for the reason the CBC test above gives: the fixture must offer the
    names for the subtraction to remove, and the surviving set must be non-empty.
    """
    offered = _FakeTransport._preferred_ciphers
    disabled = _sftp_connect_kwargs(monkeypatch)["disabled_algorithms"]["ciphers"]
    effective = [c for c in offered if c not in disabled]

    # CONTROL 1: the fixture offers every name this test says is removed.
    withdrawn = ["aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com"]
    assert set(withdrawn) <= set(offered), "restore the real paramiko cipher list in the fake"
    # CONTROL 2: the connector still proposes something.
    assert effective, f"every cipher was disabled; negotiation would fail. disabled={disabled}"

    assert not [c for c in effective if c in withdrawn]
    assert effective == ["aes256-gcm@openssh.com"]
    # And the allow-list itself cannot take either back without this reddening.
    assert not [c for c in _APPROVED_SFTP_CIPHERS if c.endswith("-ctr") or c.startswith("aes128")]


# --- A real handshake, where the [sftp] extra is installed --------------------------------------
#
# The tests above prove the deny list the connector COMPUTES. These prove paramiko honours it on the
# wire: a loopback paramiko server offers a chosen cipher list, and `_SftpClient._connect` -- the
# production call, `disabled_algorithms` and all -- either negotiates or is refused. Each refusal has
# a CONTROL: a stock paramiko client, with no deny list, that DOES negotiate against the same server.
# Without that control a refusal could just as well be a broken test server.
#
# They SKIP where paramiko is absent (see tests/test_sftp_extra_on_ci_leg.py for where it is not), the same
# as `test_fake_paramiko_algorithm_lists_match_the_installed_library` above.


def _real_paramiko() -> Any:
    return pytest.importorskip(
        "paramiko",
        reason="the [sftp] extra is not installed, so no real SSH handshake can run here. "
        "Install 'messagefoundry[sftp]' to run it.",
    )


def _sftp_server_offering(
    paramiko: Any, ciphers: tuple[str, ...], tmp_path: Path, macs: tuple[str, ...] | None = None
) -> tuple[int, Path, Any]:
    """Start a one-connection loopback SSH server that offers only ``ciphers`` (and only ``macs``,
    when given; otherwise paramiko's default MAC list, which includes the ETM names).

    Returns its port, a ``known_hosts`` file naming its host key (so the client's ``RejectPolicy``
    stays on), and the thread, which the caller joins.
    """
    import socket
    import threading

    host_key = paramiko.ECDSAKey.generate()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    tmp_path.mkdir(parents=True, exist_ok=True)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        f"[127.0.0.1]:{port} {host_key.get_name()} {host_key.get_base64()}\n", encoding="ascii"
    )

    class _Server(paramiko.ServerInterface):  # type: ignore[misc]
        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_auth_password(self, username: str, password: str) -> int:
            return int(paramiko.AUTH_SUCCESSFUL)

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            listener.close()
            return
        transport = paramiko.Transport(conn)
        try:
            transport.add_server_key(host_key)
            transport.get_security_options().ciphers = ciphers
            if macs is not None:
                transport.get_security_options().digests = macs
            try:
                transport.start_server(server=_Server())
            except (paramiko.SSHException, EOFError, OSError):
                return  # the refusal cases end here, and the client side asserts them
            # Hold the session open until the client has read what it negotiated and hung up.
            while transport.is_active():
                transport.join(0.05)
        finally:
            transport.close()
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, known_hosts, thread


def _connector_handshake(
    paramiko: Any,
    ciphers: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    macs: tuple[str, ...] | None = None,
) -> str:
    """Run the production ``_SftpClient._connect`` against a server offering ``ciphers``.

    Returns the cipher it negotiated. A refused handshake raises the connector's ``_RemoteError``,
    with paramiko's exception as its ``__cause__``.
    """
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    monkeypatch.setattr(remotefile, "_import_paramiko", lambda: paramiko)
    port, known_hosts, thread = _sftp_server_offering(paramiko, ciphers, tmp_path, macs)
    try:
        client = _SftpClient(
            {
                "host": "127.0.0.1",
                "port": port,
                "username": "u",
                "password": "p",
                "known_hosts": str(known_hosts),
                "connect_timeout": 10,
            }
        )
        ssh = client._connect()
        try:
            negotiated = str(ssh.get_transport().remote_cipher)
        finally:
            ssh.close()
    finally:
        thread.join(10)
    # Checked only on the success path, so a failed handshake reports its own exception.
    assert not thread.is_alive(), "the loopback SSH server did not shut down"
    return negotiated


def _stock_handshake(
    paramiko: Any, ciphers: tuple[str, ...], tmp_path: Path, macs: tuple[str, ...] | None = None
) -> str:
    """The CONTROL: a stock paramiko ``Transport`` with no deny list, against the same server."""
    port, _known_hosts, thread = _sftp_server_offering(paramiko, ciphers, tmp_path, macs)
    try:
        transport = paramiko.Transport(("127.0.0.1", port))
        try:
            transport.start_client(timeout=10)
            negotiated = str(transport.remote_cipher)
        finally:
            transport.close()
    finally:
        thread.join(10)
    assert not thread.is_alive(), "the loopback SSH server did not shut down"
    return negotiated


def test_sftp_real_handshake_negotiates_aes256_gcm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Against a server that offers CTR, AES-128 and AES-256, the connector picks AES-256-GCM.

    The SSH client's order decides the pick, so the CONTROL is a stock paramiko client against the
    same offer: it picks ``aes128-ctr``, first in paramiko's own list. The connector's pick differs
    only because its deny list removed that name and the other two withdrawn ones.
    """
    paramiko = _real_paramiko()
    offered = ("aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com")
    assert _stock_handshake(paramiko, offered, tmp_path / "control") == "aes128-ctr"
    negotiated = _connector_handshake(paramiko, offered, tmp_path, monkeypatch)
    assert negotiated == "aes256-gcm@openssh.com"


@pytest.mark.parametrize(
    "offered",
    [
        pytest.param(("aes128-ctr", "aes192-ctr", "aes256-ctr"), id="ctr-only"),  # BACKLOG #2041
        pytest.param(("aes128-gcm@openssh.com",), id="aes128-gcm-only"),  # BACKLOG #2044
    ],
)
def test_sftp_real_handshake_refuses_ctr_only_and_aes128_only_servers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, offered: tuple[str, ...]
) -> None:
    paramiko = _real_paramiko()
    # CONTROL: a stock client negotiates with this very server, so the refusal below is the deny
    # list's doing and not a server that cannot handshake at all.
    assert _stock_handshake(paramiko, offered, tmp_path / "control") in offered
    # The connector wraps paramiko's refusal in a permanent _RemoteError; the cause is paramiko's.
    with pytest.raises(_RemoteError, match="(?i)cipher") as caught:
        _connector_handshake(paramiko, offered, tmp_path, monkeypatch)
    assert isinstance(caught.value.__cause__, paramiko.SSHException)
    assert caught.value.permanent and not caught.value.credential_fault


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
    check_egress_allowed(_remote_dest("anywhere.example"), EgressSettings(deny_by_default=False))


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
    check_source_allowed(
        _remote_src_cfg("anywhere.example"), "IB_REMOTE", EgressSettings(deny_by_default=False)
    )


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
            Destination(name="OB", type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings),
            egress=EgressSettings(deny_by_default=False),
        )


# === test_connection() reachability probe ====================================


async def test_dest_probe_ensures_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    dest = _dest(monkeypatch, client)
    await dest.test_connection()  # connect + ensure the upload dir; no file written
    assert "/in" in client.dirs
    assert not client.files


async def test_dest_probe_lists_when_overwrite_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # #1936: overwrite=false deliveries list the directory and fail closed if they cannot, so the
    # probe must list too, or it passes a write-only directory that no delivery can use.
    client = _FakeClient(list_exc=_RemoteError("550 permission denied", permanent=True))
    dest = _dest(monkeypatch, client, overwrite=False)
    with pytest.raises(NegativeAckError):
        await dest.test_connection()
    assert client.dirs == ["/in"]  # it still ensured first
    assert not client.files


async def test_dest_probe_skips_the_listing_when_overwrite_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Control: overwrite=true deliveries never list, so neither does the probe.
    client = _FakeClient(list_exc=_RemoteError("550 permission denied", permanent=True))
    dest = _dest(monkeypatch, client, overwrite=True)
    await dest.test_connection()
    assert client.list_calls == 0


async def test_dest_probe_permanent_error_is_negative_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()

    def _boom(remote_dir: str) -> bool:
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
    # The approved wrap: the loader refuses BestAvailableEncryption's 2048 iterations (#1352).
    kp.write_bytes(approved_pkcs8_pem(key, passphrase))
    return str(cp), str(kp)


def test_ftps_encrypted_client_key_missing_password_raises_not_prompts(tmp_path: Path) -> None:
    # LOAD-BEARING security assertion (FILE-19): an encrypted client key with NO tls_key_password must
    # fail deterministically, NOT fall back to OpenSSL's blocking TTY prompt (there is no TTY under a
    # service account). Since BACKLOG #1352 the key-wrap check refuses it before OpenSSL reads the
    # key; the empty-bytes callback in _ftps_ssl_context stays behind it as the backstop.
    cert, key = _encrypted_client_cert(tmp_path, "s3cr3t-pass")
    with pytest.raises(KeyWrapRefused, match="no passphrase is configured"):
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
    await _settle(src)
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

    Skips honestly where the ``[sftp]`` extra is absent rather
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


# --- BACKLOG #1748: the REMOTEFILE source never logs a partner-chosen name ----

_REMOTE_LOGGER = "messagefoundry.transports.remotefile"


@pytest.mark.parametrize("name", IDENTIFIER_SHAPED_NAMES)
async def test_remote_source_oversize_reject_never_logs_the_partner_chosen_name(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """The remote half of #1748, through the real ``_install_phi_filters`` sink rather than ``caplog``.

    ``caplog`` reads a record BEFORE any handler filter runs, so it cannot answer what would reach the
    NSSM-captured log. The share names the file, so this is the arm a partner's naming convention hits
    first."""
    client = _FakeClient(files={f"/in/{name}": b"M" * 100})
    src = _src(monkeypatch, client, max_file_bytes=10)
    src._handler = _RecordingHandler()
    await _settle(src)
    with filtered_sink(_REMOTE_LOGGER) as sink:
        await src._poll_once()
    assert f"/in/.error/{name}" in client.files  # the arm really ran (not a vacuous pass)
    assert "exceeds max_file_bytes" in sink.text
    assert name not in sink.text
    assert IDENTIFIER_SHAPE.search(strip_safe_labels(sink.text)) is None
    assert SAFE_NAME_LABEL.search(sink.text)


async def test_remote_source_control_the_shipped_filters_alone_would_not_have_caught_it() -> None:
    """The negative control. Without it every assertion above is equally consistent with "the filter
    chain was already scrubbing the name", and the call-site edits would have bought nothing."""
    with filtered_sink(_REMOTE_LOGGER) as sink:
        logging.getLogger(_REMOTE_LOGGER).warning(
            "REMOTEFILE file %s exceeds max_file_bytes (%s); routing to error dir",
            "MRN123456789_ADT.hl7",
            10,
        )
    assert "MRN123456789_ADT.hl7" in sink.text
    assert IDENTIFIER_SHAPE.search(sink.text)


async def test_remote_source_retrieve_failure_logs_neither_the_name_nor_a_raw_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The transient-retrieve arm carries both helpers. A remote client's error text routinely quotes
    the path it was asked for, which is why ``safe_exc`` is given the name to swap out."""
    name = "DOE_JANE_19800505_ADT.hl7"
    client = _FakeClient(
        files={f"/in/{name}": b"MSH|^~\\&|A"},
        retrieve_exc=_RemoteError(f"550 no such file: /in/{name}", permanent=False),
    )
    src = _src(monkeypatch, client)
    src._handler = _RecordingHandler()
    await _settle(src)
    with filtered_sink(_REMOTE_LOGGER) as sink:
        await src._poll_once()
    assert "could not retrieve" in sink.text  # the arm ran
    assert name not in sink.text
    assert "_RemoteError" in sink.text  # safe_exc keeps the type
    assert "550" in sink.text  # and the server's code, which is the diagnostic
    assert IDENTIFIER_SHAPE.search(strip_safe_labels(sink.text)) is None


async def test_remote_source_move_failure_logs_neither_the_name_nor_a_raw_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "PID-100001-DOE-JANE.hl7"
    client = _FakeClient(
        files={f"/in/{name}": b"MSH|^~\\&|A"},
        rename_exc=_RemoteError(f"permission denied: /in/.processed/{name}", permanent=True),
    )
    src = _src(monkeypatch, client)
    src._handler = _RecordingHandler()
    await _settle(src)
    with filtered_sink(_REMOTE_LOGGER) as sink:
        await src._poll_once()
    assert "could not move" in sink.text  # the arm ran
    assert name not in sink.text
    assert IDENTIFIER_SHAPE.search(strip_safe_labels(sink.text)) is None


async def test_remote_source_unsafe_name_refusal_still_logs_no_name_at_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one arm that deliberately logs NO label, not even a derived one: it has just refused the
    name as an unsafe path component, so it must not hand that name to any helper either.

    Its comment used to justify this by asserting that names are not logged elsewhere in the source.
    Nine WARNING sites falsified that (#1748); the justification is now the refusal itself."""
    client = _HostileListingClient(["../../drops/MRN123456789_ADT.hl7"])
    src = _src(monkeypatch, client)
    src._handler = _RecordingHandler()
    with filtered_sink(_REMOTE_LOGGER) as sink:
        await src._poll_once()
    assert "refused as an unsafe path component" in sink.text  # the arm ran
    assert "MRN123456789" not in sink.text
    assert SAFE_NAME_LABEL.search(sink.text) is None  # no label either — the name is not touched
    assert IDENTIFIER_SHAPE.search(sink.text) is None


def test_sftp_real_handshake_still_needs_an_etm_mac_beside_gcm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """paramiko agrees a MAC even beside an AEAD cipher, so the MAC allow-list still gates the
    handshake. ``docs/CONNECTIONS.md`` and the CHANGELOG tell server owners so; this pins it.

    CONTROL: a stock client negotiates with the same server, so the refusal is the MAC allow-list's.
    """
    paramiko = _real_paramiko()
    ciphers = ("aes256-gcm@openssh.com",)
    encrypt_and_mac = ("hmac-sha2-256", "hmac-sha2-512")
    assert _stock_handshake(paramiko, ciphers, tmp_path / "control", encrypt_and_mac) == ciphers[0]
    with pytest.raises(_RemoteError, match="(?i)macs") as caught:
        _connector_handshake(paramiko, ciphers, tmp_path, monkeypatch, encrypt_and_mac)
    assert isinstance(caught.value.__cause__, paramiko.SSHException)
    assert caught.value.permanent and not caught.value.credential_fault


# --- BACKLOG #2083: only a refused credential is a credential fault ---------------------------------
#
# A credential fault stops the lane (ADR 0095). Before #2083 every 5xx reply while opening an FTP
# session was one, so an FTP server at its connection limit, or one that refused TLS, stopped a lane
# that should have retried or dead-lettered. Why an ambiguous 530 still stops the lane is stated once,
# in ``remotefile._names_connection_limit``.


class _ScriptedFtp:
    """An ``ftplib.FTP_TLS`` stand-in that refuses one step of the session open with ``reply``."""

    instances: list[_ScriptedFtp] = []

    def __init__(self, *, refuse_at: str, reply: str) -> None:
        self._refuse_at = refuse_at
        self._reply = reply
        self.steps: list[str] = []
        self.closed = False
        _ScriptedFtp.instances.append(self)

    def _step(self, name: str) -> None:
        import ftplib as _ftplib

        self.steps.append(name)
        if name == self._refuse_at:
            if self._reply.startswith("4"):
                raise _ftplib.error_temp(self._reply)
            raise _ftplib.error_perm(self._reply)

    def connect(self, host: str, port: int) -> None:
        self._step("greeting")

    def auth(self) -> None:
        self._step("auth")

    def login(self, *, user: str, passwd: str) -> None:
        self._step("login")

    def prot_p(self) -> None:
        self._step("prot_p")

    def mlsd(self, path: str) -> list[tuple[str, dict[str, str]]]:
        return []

    def quit(self) -> None:
        self.closed = True

    def close(self) -> None:
        self.closed = True


def _scripted_ftps(monkeypatch: pytest.MonkeyPatch, *, refuse_at: str, reply: str) -> None:
    """Make ``ftplib.FTP_TLS`` a :class:`_ScriptedFtp` refusing ``refuse_at`` with ``reply``."""
    import ftplib as _ftplib

    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    _ScriptedFtp.instances = []

    class _Ftps(_ScriptedFtp):
        def __init__(self, *, context: Any = None, timeout: float | None = None) -> None:
            super().__init__(refuse_at=refuse_at, reply=reply)

    monkeypatch.setattr(_ftplib, "FTP_TLS", _Ftps)


def _ftps_client() -> _FtpClient:
    return _FtpClient(
        {"host": "ftp.example.com", "remote_dir": "/in", "username": "u", "password": "p"}, tls=True
    )


@pytest.mark.parametrize(
    ("refuse_at", "reply"),
    [
        # ProFTPD's MaxClientsPerUser wording, the case the row names.
        (
            "login",
            "530 Sorry, the maximum number of clients (5) for this user are already connected.",
        ),
        ("login", "530 Sorry, no more than 10 users allowed"),
        ("login", "530 Too many connections from your internet address"),
        ("login", "530 Too many connections, please retry later"),
        ("login", "530 No more than 10 users permitted"),
        # "entries" holds "tries"; a busy server's text must not read as a credential word.
        ("login", "530 Too many connections; see the FAQ entries on our site"),
        ("login", "530 Connection limit reached"),
        ("login", "530 Maximum number of users exceeded"),
        (
            "greeting",
            "530 Sorry, the maximum number of allowed clients (20) are already connected.",
        ),
        # Before the login no credential has been sent, so a credential word does not veto the limit
        # there. Review round 3: the widened word list had made these permanent dead-letters.
        ("greeting", "530 Too many connections from your IP; connections are blocked for 60 s"),
        ("greeting", "530-Unauthorized access is prohibited.\n530 Too many connections"),
        # Fix round 4 review: a full stop inside a token, or after "max", does not end the phrase.
        (
            "login",
            "530 Sorry, the maximum number of clients (5) from 192.0.2.10 are already connected.",
        ),
        ("login", "530 Maximum connections for host ftp.example.com reached"),
        ("login", "530 Sorry, max. number of clients reached"),
    ],
)
def test_a_connection_limit_reply_is_transient(
    monkeypatch: pytest.MonkeyPatch, refuse_at: str, reply: str
) -> None:
    _scripted_ftps(monkeypatch, refuse_at=refuse_at, reply=reply)
    with pytest.raises(_RemoteError) as caught:
        _ftps_client().list_dir("/in")
    assert caught.value.permanent is False, "a busy server clears on its own; retry it"
    assert caught.value.credential_fault is False
    assert "connection limit" in str(caught.value)
    (ftp,) = _ScriptedFtp.instances
    assert ftp.closed, "the refused connection must be closed, not leaked"


@pytest.mark.parametrize(
    ("refuse_at", "reply"),
    [
        ("auth", "500 AUTH not understood"),
        ("auth", "534 Request denied for policy reason."),
        ("prot_p", "536 Requested PROT level not supported by mechanism."),
        ("prot_p", "504 PBSZ not implemented"),
    ],
)
def test_a_tls_refusal_is_a_configuration_fault_not_a_credential_fault(
    monkeypatch: pytest.MonkeyPatch, refuse_at: str, reply: str
) -> None:
    _scripted_ftps(monkeypatch, refuse_at=refuse_at, reply=reply)
    with pytest.raises(_RemoteError) as caught:
        _ftps_client().list_dir("/in")
    assert caught.value.permanent is True, "no retry makes the server offer TLS"
    assert caught.value.credential_fault is False, "no credential was at fault"
    assert caught.value.config_fault is True, "every row meets it alike, so it stops the lane"
    assert "TLS configuration fault" in str(caught.value)


@pytest.mark.parametrize(
    "reply",
    [
        # THE CONTROL: a real credential refusal still stops the lane.
        "530 Login incorrect.",
        # A 530 whose text does not plainly name a connection limit falls to the credential fault.
        "530 Not logged in.",
        # Names a maximum, but of login ATTEMPTS: a lockout warning, never a busy server.
        "530 Maximum login attempts exceeded for this user",
        # Names a limit and the password: the credential words win.
        "530 Too many users failed the password check",
        # Read as busy servers by a first, looser pattern. Each is about the credential or the
        # account, so each must stop the lane rather than retry into a lockout.
        "530 Maximum retries exceeded for this user",
        "530 Max auth tries reached for user jdoe",
        "530-This server allows a maximum of 50 users.\n530 Authentication rejected.",
        "530 User account disabled: maximum sessions policy",
        "530 Access denied: user jmax, user not permitted",
        # Compound replies that name a limit AND the credential or the account.
        "530 Bad login: too many connections",
        "530 Too many connections or wrong credentials",
        "530 Unknown user; too many users",
        "530 User not found: too many users",
        "530 Account suspended: maximum sessions exceeded",
        # Fix round 3. Round 2 anchored "lock" and "auth" at a word boundary, so these four read as
        # busy servers and the login was retried into a lockout.
        "530 Too many connections, account temporarily blocked",
        "530 Unauthorized: too many sessions",
        "530 Too many connections from this user, try again after unlock",
        "530 Too many sessions: user unauthenticated",
        # Fix round 4 review: "authenticated" is TLS vocabulary only inside a TLS demand. Beside a
        # limit it names the credential, as "unauthenticated" above already did.
        "530 User not authenticated: too many connections",
        "530 Not authenticated; too many sessions",
        # Fix round 3. Round 2's list did not have these words at all.
        "530 Too many sessions: account deactivated",
        "530 Too many users; access revoked",
        "530 Forbidden: too many connections",
        "530 Too many users; server denies this account",
        "530 Too many sessions: account inactive",
        "530 Too many sessions; login prohibited",
        "530 Too many connections; access refused for this account",
        "530 Too many connections; user blacklisted",
        "530 Too many unsuccessful login sessions",
        # Review of fix round 3. A trailing word boundary on "denied", and machine-style tokens with
        # an underscore or run together, each let a lockout reply read as a busy server.
        "530 Too many users; DeniedAccess",
        "530 Too many users; denied_access",
        "530 Too many users; LOGIN_FAILED",
        "530 Too many users; loginfailed",
        "530 Too many users; E_BADPASS",
        "530 Too many users; ERR_WRONGPASS",
        "530 Too many users; wrongpassword",
        "530 Too many users; badpassword",
        "530 Too many users; user_unknown",
        "530 Too many users; USER_NOT_FOUND",
        # Review of fix round 3. Account-refusal phrases the list did not have.
        "530 Too many connections; login not permitted",
        "530 Too many users; no such user",
        "530 Too many connections; user does not exist",
        "530 Too many users. Login not accepted.",
        "530 Too many connections; account terminated",
        "530 Too many users; pwd mismatch",
        # On FTPS the control channel is already TLS, so a TLS hint is no TLS demand.
        "530 Not logged in; SSL/TLS required",
    ],
)
def test_a_refused_credential_is_still_a_credential_fault(
    monkeypatch: pytest.MonkeyPatch, reply: str
) -> None:
    _scripted_ftps(monkeypatch, refuse_at="login", reply=reply)
    with pytest.raises(_RemoteError) as caught:
        _ftps_client().list_dir("/in")
    assert caught.value.permanent is True
    assert caught.value.credential_fault is True, "a refused credential must stop the lane"
    assert "login refused" in str(caught.value)


def _scripted_plain_ftp(monkeypatch: pytest.MonkeyPatch, *, refuse_at: str, reply: str) -> None:
    """Make ``ftplib.FTP`` a :class:`_ScriptedFtp`, for plain FTP under the insecure escape."""
    import ftplib as _ftplib

    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    _ScriptedFtp.instances = []

    class _Plain(_ScriptedFtp):
        def __init__(self, *, timeout: float | None = None) -> None:
            super().__init__(refuse_at=refuse_at, reply=reply)

    monkeypatch.setattr(_ftplib, "FTP", _Plain)


_TLS_DEMANDS = [
    "530 Non-anonymous sessions must use encryption.",  # vsftpd, force_local_logins_ssl
    "550 SSL/TLS required on the control channel",  # ProFTPD, TLSRequired
    "530 This server does not allow plain FTP. You have to use FTP over TLS.",  # FileZilla
    "534 Policy requires SSL.",  # IIS
    "530 TLSv1.2 required",
    "530 Sessions must be encrypted using AUTH TLS first",  # "AUTH TLS" is no credential word
    "550 SSL/TLS required for authentication",  # "authentication" is TLS vocabulary here
    "530 You must authenticate over TLS",
]


def _plain_client() -> _FtpClient:
    return _FtpClient(
        {"host": "ftp.example.com", "remote_dir": "/in", "username": "u", "password": "p"},
        tls=False,
    )


@pytest.mark.parametrize("reply", _TLS_DEMANDS)
def test_a_tls_demand_at_the_login_is_a_configuration_fault(
    monkeypatch: pytest.MonkeyPatch, reply: str
) -> None:
    """Fix round 3: a server that demands TLS refuses a plain session's login, whatever the
    credential. The fault is the connection's TLS setting, so it is classed as a refused ``AUTH TLS``
    is: permanent, and not a credential fault."""
    _scripted_plain_ftp(monkeypatch, refuse_at="login", reply=reply)
    with pytest.raises(_RemoteError) as caught:
        _plain_client().list_dir("/in")
    assert caught.value.permanent is True, "no retry makes the connection use TLS"
    assert caught.value.credential_fault is False, "no credential was at fault"
    assert caught.value.config_fault is True, "every row meets it alike, so it stops the lane"
    assert "TLS configuration fault" in str(caught.value)
    (ftp,) = _ScriptedFtp.instances
    assert ftp.closed, "the refused connection must be closed"
    assert ftp.steps == ["greeting", "login"]


@pytest.mark.parametrize(
    "reply",
    [
        "530 Not logged in; SSL/TLS required",  # RFC 959's own refusal text, with a TLS hint
        # Names TLS and the credential: the credential words win over the TLS demand.
        "530 Login incorrect; SSL/TLS required",
        "530 Login for SSL-VPN users only",  # refuses an account; "only" is no TLS demand
        "530 Only anonymous logins over TLS accepted",
        # Review of fix round 3: a TLS demand beside an account refusal.
        "530 TLS required; no such user",
        "530 TLS required; user does not exist",
        "530 Encrypted login required: user not recognised",
        "530 TLS required for this login (PWD mismatch)",
        "530 Mandatory SSL: login not accepted",
        "530 User bob is not permitted; TLS mandatory",
        "530 TLS required; account closed",
        # Review of fix round 3: TLS names that are an account's group, path or VPN, not a demand.
        "530 SSL-VPN users must log in through the portal",
        "530 Access requires SSL-VPN membership",
        "530 This account must connect over the SSL VPN",
        "530 User must be a member of group ftps-users",
        "530 Home directory must exist (sslhome)",
        "530 Account must be reactivated at https://tlsportal.example",
        # Fix round 4 review: a TLS name joined to "/" or "_" is a path or a group, not a demand.
        "530 Home directory must be under /srv/tls",
        "530 Users must be in group encrypted_users",
    ],
)
def test_a_tls_hint_on_an_account_refusal_is_still_a_credential_fault(
    monkeypatch: pytest.MonkeyPatch, reply: str
) -> None:
    """CONTROL on a plain session: a reply that mentions TLS but refuses the login or the account
    stays a credential fault. Read as a TLS fault, each row would dead-letter after one more
    login, and a partner lockout counter would move."""
    _scripted_plain_ftp(monkeypatch, refuse_at="login", reply=reply)
    with pytest.raises(_RemoteError) as caught:
        _plain_client().list_dir("/in")
    assert caught.value.credential_fault is True, "a refused credential must stop the lane"


@pytest.mark.parametrize("reply", _TLS_DEMANDS[:2])
def test_a_tls_demand_on_ftps_is_a_credential_fault(
    monkeypatch: pytest.MonkeyPatch, reply: str
) -> None:
    """CONTROL: an FTPS control channel is already TLS, so the TLS-demand rule is not asked there,
    and the refusal falls to the credential fault like any other unclear login reply."""
    _scripted_ftps(monkeypatch, refuse_at="login", reply=reply)
    with pytest.raises(_RemoteError) as caught:
        _ftps_client().list_dir("/in")
    assert caught.value.credential_fault is True


# --- BACKLOG #2083 fix round 4: a configuration fault stops the lane and keeps the queue -----------

#: Each session-open refusal classed as a configuration fault, with the session kind that meets it.
_CONFIG_FAULTS = [
    pytest.param("ftps", "greeting", "550 Access denied for your address", id="greeting"),
    pytest.param("ftps", "auth", "534 Request denied for policy reason.", id="auth-tls"),
    pytest.param(
        "ftps", "prot_p", "536 Requested PROT level not supported by mechanism.", id="prot-p"
    ),
    pytest.param("plain", "login", _TLS_DEMANDS[0], id="tls-demand"),
]


def _config_fault_dest(
    monkeypatch: pytest.MonkeyPatch, kind: str, refuse_at: str, reply: str, **over: Any
) -> Any:
    """A real FTP destination whose session open is refused at ``refuse_at`` with ``reply``."""
    if kind == "ftps":
        _scripted_ftps(monkeypatch, refuse_at=refuse_at, reply=reply)
    else:
        _scripted_plain_ftp(monkeypatch, refuse_at=refuse_at, reply=reply)
    # A credentialed plain-ftp hop needs the escape on a warn posture (vault BACKLOG #2354). FTPS
    # needs no escape, so it keeps the default (unstamped) posture.
    posture = HopPosture(enforcing=False) if kind == "plain" else None
    with active_hop_posture(posture):
        return build_destination(
            _ftp_dest(tls=kind == "ftps", username="u", password="p", filename="m.hl7", **over),
            egress=EgressSettings(deny_by_default=False),
        )


@pytest.mark.parametrize(("kind", "refuse_at", "reply"), _CONFIG_FAULTS)
async def test_a_configuration_fault_reaches_the_runner_marked_as_one(
    monkeypatch: pytest.MonkeyPatch, kind: str, refuse_at: str, reply: str
) -> None:
    """Through ``send``: each refusal reaches the delivery worker as a permanent
    :class:`NegativeAckError` carrying ``config_fault`` and not ``credential_fault``. The marker is
    what makes the worker stop the lane rather than dead-letter every queued row (fix round 4)."""
    dest = _config_fault_dest(monkeypatch, kind, refuse_at, reply)
    with pytest.raises(NegativeAckError) as caught:
        await dest.send(_UPLOAD_BODY)
    assert caught.value.permanent is True
    assert caught.value.config_fault is True, "the lane must stop, not dead-letter each row"
    assert caught.value.credential_fault is False, "no credential was at fault"


_E2E_DEST = "OB"


async def _e2e_runner(
    tmp_path: Path, connector: Any, *, batch: bool = False
) -> tuple[Any, Any, list[str]]:
    """A store holding three rows queued to ``_E2E_DEST`` and a runner wired to ``connector``, with
    a recording alert sink. Returns the runner, the sink and the message ids."""
    from messagefoundry.config.models import BatchConfig, RetryPolicy
    from messagefoundry.config.wiring import Registry
    from messagefoundry.pipeline.alerts import LoggingAlertSink
    from messagefoundry.pipeline.wiring_runner import RegistryRunner
    from messagefoundry.store import MessageStore

    class _Sink(LoggingAlertSink):
        def __init__(self) -> None:
            super().__init__()
            self.stopped: list[tuple[str, str]] = []

        def connection_stopped(self, name: str, *, detail: str) -> None:
            self.stopped.append((name, detail))

    store = await MessageStore.open(tmp_path / "config_fault.db")
    try:
        mids = []
        for n in range(3):
            body = f"MSH|^~\\&|A|B|C|D|20260810||ADT^A01|MSG{n}|P|2.5\r"
            mids.append(
                await store.enqueue_message(
                    channel_id="IB", raw=body, deliveries=[(_E2E_DEST, body)], now=100.0 + n
                )
            )
        sink = _Sink()
        runner = RegistryRunner(
            Registry(),
            store,
            poll_interval=0.02,
            alert_sink=sink,
            egress=EgressSettings(deny_by_default=False),
        )
    except BaseException:
        await store.close()  # the callers' finally closes it only once this returns
        raise
    runner._destinations[_E2E_DEST] = connector
    runner._retry[_E2E_DEST] = RetryPolicy()
    runner._simulate[_E2E_DEST] = False
    if batch:
        runner._batch[_E2E_DEST] = BatchConfig(max_count=5, max_wait_ms=1)
    return runner, sink, mids


async def _queue_rows(runner: Any, mids: list[str]) -> list[tuple[str, int, Any]]:
    """Each message's outbound row as (status, attempts, last_error), in ``mids`` order."""
    rows = [r for mid in mids for r in await runner.store.outbox_for(mid)]
    return [(r["status"], r["attempts"], r["last_error"]) for r in rows]


async def test_a_refused_auth_tls_stops_the_lane_and_keeps_the_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A single-row outbound whose FTPS server refuses ``AUTH TLS``. Every queued row would meet the
    same refusal, so dead-lettering the head would dead-letter them all, one per attempt. Before
    #2083 the refusal was misread as a credential fault and so stopped the lane; #2083 made it a
    configuration fault and it dead-lettered. Fix round 4 stops the lane again and keeps the row."""
    from messagefoundry.pipeline.wiring_runner import _ItemOutcome
    from messagefoundry.store import OutboxStatus

    dest = _config_fault_dest(monkeypatch, "ftps", "auth", "534 Request denied for policy reason.")
    runner, sink, mids = await _e2e_runner(tmp_path, dest)
    try:
        item = await runner.store.claim_next_fifo(_E2E_DEST)
        assert item is not None
        outcome, retry_until = await runner._process_delivery_item(_E2E_DEST, item)

        assert outcome is _ItemOutcome.STOPPED
        assert retry_until is None
        pending = OutboxStatus.PENDING.value
        assert await _queue_rows(runner, mids) == [(pending, 0, None)] * 3, "every row kept"
        assert await runner.store.count_dead() == 0
        assert len(sink.stopped) == 1
        assert sink.stopped[0][0] == _E2E_DEST
        assert "configuration fault" in sink.stopped[0][1]
        assert "credential" not in sink.stopped[0][1]
        assert ("outbound", _E2E_DEST) in runner._stop_held, "the scheduler must not re-arm it"
        assert len(_ScriptedFtp.instances) == 1, "stopped after one attempt"
    finally:
        await runner.store.close()


async def test_a_refused_auth_tls_on_a_batch_stops_the_lane_and_keeps_every_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The batch twin: a batching outbound hands the whole envelope to one ``send``, so a
    dead-letter there would empty every member of the batch into the DLQ at once."""
    from messagefoundry.pipeline.wiring_runner import _ItemOutcome
    from messagefoundry.store import OutboxStatus

    dest = _config_fault_dest(monkeypatch, "ftps", "auth", "534 Request denied for policy reason.")
    runner, sink, mids = await _e2e_runner(tmp_path, dest, batch=True)
    try:
        head = await runner.store.claim_next_fifo(_E2E_DEST)
        assert head is not None
        outcome, retry_until = await runner._process_delivery_batch(
            _E2E_DEST, head, runner._batch[_E2E_DEST]
        )

        assert outcome is _ItemOutcome.STOPPED
        assert retry_until is None
        pending = OutboxStatus.PENDING.value
        assert await _queue_rows(runner, mids) == [(pending, 0, None)] * 3, "every member kept"
        assert await runner.store.count_dead() == 0
        assert [name for name, _ in sink.stopped] == [_E2E_DEST]
        assert "configuration fault" in sink.stopped[0][1]
        assert ("outbound", _E2E_DEST) in runner._stop_held
    finally:
        await runner.store.close()


@pytest.mark.parametrize(
    ("reply", "credential_fault"),
    [
        ("430 Invalid username or password", True),
        ("421 Too many connections (8) from this IP", False),  # CONTROL: a busy server
        # Fix round 4 review 2: a credential word wins over a limit phrase at a 4xx, as at a 5xx.
        # Retried, the first would log in again into a locked account. The second is a busy
        # server that stops the lane anyway, the cheaper error; the same word list decides both.
        ("421 Too many connections; account locked", True),
        ("421 Too many users - blocked for 60 s", True),
    ],
    ids=["430-credential", "421-busy-control", "421-limit-and-lock", "421-busy-blocked"],
)
def test_a_4xx_login_refusal_naming_the_credential_is_a_credential_fault(
    monkeypatch: pytest.MonkeyPatch, reply: str, credential_fault: bool
) -> None:
    """Review of fix round 3: ftplib raises ``error_temp`` for a 4xx, which was always transient.
    A 4xx at the login that names the credential is a refused login, and retried it would lock the
    partner account."""
    _scripted_ftps(monkeypatch, refuse_at="login", reply=reply)
    with pytest.raises(_RemoteError) as caught:
        _ftps_client().list_dir("/in")
    assert caught.value.credential_fault is credential_fault
    assert caught.value.permanent is credential_fault
    (ftp,) = _ScriptedFtp.instances
    assert ftp.closed


def test_a_refused_greeting_is_permanent_but_not_a_credential_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No credential has been sent when the greeting is refused, so it cannot be a credential fault.
    _scripted_ftps(monkeypatch, refuse_at="greeting", reply="550 Access denied for your address")
    with pytest.raises(_RemoteError) as caught:
        _ftps_client().list_dir("/in")
    assert caught.value.permanent is True
    assert caught.value.credential_fault is False
    assert caught.value.config_fault is True, "every row meets it alike, so it stops the lane"
    assert _ScriptedFtp.instances[0].steps == ["greeting"]


@pytest.mark.parametrize(
    ("reply", "stops_the_lane"),
    [
        (
            "530 Sorry, the maximum number of clients (5) for this user are already connected.",
            False,
        ),
        ("530 Login incorrect.", True),  # the control
    ],
    ids=["connection-limit", "credential-control"],
)
async def test_validate_directory_stops_the_lane_only_on_a_refused_credential(
    monkeypatch: pytest.MonkeyPatch, reply: str, stops_the_lane: bool
) -> None:
    """With ``validate_directory`` on, each send lists ``remote_dir`` first and passes a credential
    fault through unchanged, so a transient fault marked as one would stop the lane. Driven through
    the real ``_FtpClient`` so the classification under test is the shipped one."""
    _scripted_ftps(monkeypatch, refuse_at="login", reply=reply)
    dest = build_destination(
        _ftp_dest(tls=True, username="u", password="p", validate_directory=True, filename="m.hl7"),
        egress=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(DeliveryError) as caught:
        await dest.send(_UPLOAD_BODY)
    if stops_the_lane:
        assert isinstance(caught.value, NegativeAckError)
        assert caught.value.credential_fault is True
    else:
        assert not isinstance(caught.value, NegativeAckError), "a busy server is retried"


@pytest.mark.parametrize(("kind", "refuse_at", "reply"), _CONFIG_FAULTS)
async def test_validate_directory_passes_a_configuration_fault_through(
    monkeypatch: pytest.MonkeyPatch, kind: str, refuse_at: str, reply: str
) -> None:
    """With ``validate_directory`` on, ``_list_or_retry`` re-raises a directory fault as transient
    but passes a connection fault through unchanged. Fix round 4 makes a configuration fault a
    connection fault, so it stops the lane here too, as it does with the toggle off. Retried
    instead, every row would reconnect into the same refusal until its retry cap dead-lettered it."""
    dest = _config_fault_dest(monkeypatch, kind, refuse_at, reply, validate_directory=True)
    with pytest.raises(NegativeAckError) as caught:
        await dest.send(_UPLOAD_BODY)
    assert caught.value.config_fault is True
    assert caught.value.credential_fault is False


# --- BACKLOG #2071: the settle gate on the remote source -------------------------------------------

_SETTLE_HEAD = b"MSH|^~\\&|A|B|C|D|20260929||ADT^A01|SETTLE1|P|2.5\rPID|1||SYNTH"
_SETTLE_WHOLE = _SETTLE_HEAD + b"0001\r"


async def test_a_file_that_grows_between_polls_is_read_only_once_it_settles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partner that writes, pauses and writes again leaves a file that is still for the length of
    one retrieve, so #116's before-and-after check passes the head as a whole message. The gate
    compares the listed size across polls instead.

    Red mutation: make ``_settled`` return True. The first poll then emits the head, which is a
    truncated message that nothing downstream can tell from a whole one."""
    client = _FakeClient(files={"/in/a.hl7": _SETTLE_HEAD})
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h

    await src._poll_once()  # first sighting: recorded, nothing read
    assert h.bodies == []
    assert not any(op == "retrieve" for op, _ in client.ops)

    client.files["/in/a.hl7"] = _SETTLE_WHOLE  # the partner writes the rest between polls
    await src._poll_once()  # the listed size moved, so it waits again
    assert h.bodies == []
    assert "/in/a.hl7" in client.files

    await src._poll_once()  # unchanged since the last poll: read whole
    assert h.bodies == [_SETTLE_WHOLE]
    assert client.files["/in/.processed/a.hl7"] == _SETTLE_WHOLE
    assert src._settle_seen == {}  # an admitted file leaves the map


async def test_a_file_the_listing_drops_is_forgotten_after_the_miss_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The map is bounded by the poll directory, not by every name it ever held.

    Red mutation: delete the ``_prune_settle`` call. The removed file's entry is never forgotten."""
    from messagefoundry.transports.file import SETTLE_MISS_LIMIT

    client = _FakeClient(files={"/in/a.hl7": _SETTLE_HEAD, "/in/b.hl7": _SETTLE_HEAD})
    src = _src(monkeypatch, client)
    src._handler = _RecordingHandler()
    await src._poll_once()
    assert sorted(src._settle_seen) == ["a.hl7", "b.hl7"]

    del client.files["/in/b.hl7"]  # renamed away by the partner before it settled
    for _ in range(SETTLE_MISS_LIMIT - 1):
        await src._poll_once()
        assert "b.hl7" in src._settle_seen, "one missed listing must not restart the wait"
    await src._poll_once()
    assert "b.hl7" not in src._settle_seen


async def test_at_the_settle_cap_a_new_file_waits_and_every_file_still_settles(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """At the cap a new file is not recorded, and every file still settles in turn.

    Red mutation: evict the oldest entry to make room instead. With a cap of one and two files, each
    first sighting pushes the other out and nothing is ever emitted."""
    monkeypatch.setattr(remotefile, "SETTLE_SEEN_MAX", 1)
    client = _FakeClient(files={"/in/a.hl7": _SETTLE_WHOLE, "/in/b.hl7": _SETTLE_WHOLE})
    src = _src(monkeypatch, client)
    h = _RecordingHandler()
    src._handler = h
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.transports.remotefile"):
        await src._poll_once()
    assert list(src._settle_seen) == ["a.hl7"]  # b waits for room
    assert "settle memory is full" in caplog.text
    await src._poll_once()  # a is admitted, which makes room for b's first sighting
    assert h.bodies == [_SETTLE_WHOLE]
    await src._poll_once()
    assert h.bodies == [_SETTLE_WHOLE, _SETTLE_WHOLE]
    assert src._settle_seen == {}


async def test_an_unsettled_file_does_not_charge_the_poll_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file still being written stays in place, so it must not spend the per-tick budget.

    Red mutation: charge ``disposed`` on the not-yet-settled arm. The growing file, which sorts first,
    then eats a ceiling of one on every poll and the settled file behind it is never read."""
    client = _FakeClient(files={"/in/a.hl7": _SETTLE_HEAD, "/in/b.hl7": _SETTLE_WHOLE})
    src = _src(monkeypatch, client, poll_max_files=1)
    h = _RecordingHandler()
    src._handler = h
    await src._poll_once()
    client.files["/in/a.hl7"] += b"X"  # a keeps growing on every poll
    await src._poll_once()
    assert h.bodies == [_SETTLE_WHOLE]  # b was read although a sorts ahead of it
    assert "/in/a.hl7" in client.files


# --- BACKLOG #2082: every entry is a collision, and the probe uses one connection -------------------


class _DropBoxFtp:
    """An ``ftplib.FTP_TLS`` stand-in over an in-memory drop directory whose ``MLSD`` listing is
    ``entries``. Records every connection and every command that changes the directory."""

    connections: list[_DropBoxFtp] = []
    entries: list[tuple[str, dict[str, str]]] = []

    def __init__(self, *, context: Any = None, timeout: float | None = None) -> None:
        self.stored: list[str] = []
        self.renamed: list[tuple[str, str]] = []
        self.made: list[str] = []
        self.listed = 0
        self._rnfr = ""
        _DropBoxFtp.connections.append(self)

    def connect(self, host: str, port: int) -> None:
        pass

    def auth(self) -> None:
        pass

    def login(self, *, user: str, passwd: str) -> None:
        pass

    def prot_p(self) -> None:
        pass

    def mkd(self, path: str) -> str:
        self.made.append(path)
        return path

    def mlsd(self, path: str) -> list[tuple[str, dict[str, str]]]:
        self.listed += 1
        return list(_DropBoxFtp.entries)

    def storbinary(self, cmd: str, fp: Any) -> None:
        self.stored.append(cmd.removeprefix("STOR "))

    def sendcmd(self, cmd: str) -> str:
        # The publish sends RNFR and RNTO itself rather than through ftplib's rename (BACKLOG #2553).
        assert cmd.startswith("RNFR "), cmd
        self._rnfr = cmd.removeprefix("RNFR ")
        return "350 Ready for RNTO"

    def voidcmd(self, cmd: str) -> str:
        assert cmd.startswith("RNTO "), cmd
        self.renamed.append((self._rnfr, cmd.removeprefix("RNTO ")))
        return "250 Rename successful"

    def quit(self) -> None:
        pass

    def close(self) -> None:
        pass


def _drop_box(
    monkeypatch: pytest.MonkeyPatch, entries: list[tuple[str, dict[str, str]]]
) -> type[_DropBoxFtp]:
    import ftplib as _ftplib

    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    _DropBoxFtp.connections = []
    _DropBoxFtp.entries = entries
    monkeypatch.setattr(_ftplib, "FTP_TLS", _DropBoxFtp)
    return _DropBoxFtp


_MLSD_DOTS = [(".", {"type": "cdir"}), ("..", {"type": "pdir"})]


@pytest.mark.parametrize(
    "entry_type",
    ["OS.unix=symlink", "dir", "OS.unix=slink:/elsewhere/a.hl7"],
    ids=["symlink", "directory", "symlink-with-target"],
)
async def test_a_same_named_entry_that_is_not_a_file_is_a_collision(
    monkeypatch: pytest.MonkeyPatch, entry_type: str
) -> None:
    """The regular-file listing the source reads leaves these out, so before #2082 the collision
    check did not see them, and the rename would have replaced a partner's symlink.

    Driven through the shipped ``_FtpClient``, so the MLSD parsing under test is the real one."""
    box = _drop_box(monkeypatch, [*_MLSD_DOTS, ("msg.hl7", {"type": entry_type})])
    dest = build_destination(
        _ftp_dest(tls=True, username="u", password="p", filename="msg.hl7", overwrite=False),
        egress=EgressSettings(deny_by_default=False),
    )
    await dest.send(_UPLOAD_BODY)
    (rename,) = [r for c in box.connections for r in c.renamed]
    assert rename[1] == "/in/msg-1.hl7", f"the upload was published over the {entry_type} entry"


def test_the_source_listing_still_takes_regular_files_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """CONTROL: the widening is the collision check's alone. The source's ``list_dir`` must not
    start offering a symlink or directory for retrieval."""
    _drop_box(
        monkeypatch,
        [
            *_MLSD_DOTS,
            ("link.hl7", {"type": "OS.unix=symlink"}),
            ("sub", {"type": "dir"}),
            ("a.hl7", {"type": "file", "size": "5"}),
        ],
    )
    client = _ftps_client()
    assert client.list_dir("/in") == [("a.hl7", 5)]
    assert client.list_names("/in") == {"link.hl7", "sub", "a.hl7"}


def test_sftp_list_names_takes_every_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SFTPClient.listdir`` names every entry; ``listdir_attr`` with ``S_ISREG``, which the source
    reads, would drop a symlink (``listdir_attr`` reports the link itself, not its target)."""

    class _Listing:
        def listdir(self, path: str) -> list[str]:
            return ["link.hl7", "sub", "a.hl7"]

    monkeypatch.setattr(_SftpClient, "_op", lambda self, fn: fn(_Listing()))
    client = _SftpClient({"host": "sftp.example.com"})
    assert client.list_names("/in") == {"link.hl7", "sub", "a.hl7"}


async def test_the_overwrite_off_probe_uses_one_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """The probe ensures the directory and lists it. On two connections, two connect bounds in a
    row can outlast the API's cap on the probe; on one, they cannot."""
    box = _drop_box(monkeypatch, list(_MLSD_DOTS))
    dest = build_destination(
        _ftp_dest(tls=True, username="u", password="p", overwrite=False),
        egress=EgressSettings(deny_by_default=False),
    )
    await dest.test_connection()
    (conn,) = box.connections
    assert conn.made == ["/in"] and conn.listed == 1, "the probe must still ensure AND list"
