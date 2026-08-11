# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Transports: MLLP framing/decoding, ACK building, file + MLLP connectors.

The MLLP source/destination talk to each other over a real loopback TCP socket (port 0)
so the framing and ACK round-trip are exercised end-to-end, not mocked."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Destination, Source
from messagefoundry.config.wiring import MLLP, File
from messagefoundry.parsing import RawMessage
from messagefoundry.parsing.compression import gzip_compress, gzip_decompress
from messagefoundry.parsing.peek import Peek
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationStartupError,
    NegativeAckError,
    SourceStartupError,
)
from messagefoundry.transports.file import (
    DEFAULT_MAX_FILE_BYTES,
    FileDestination,
    FileSource,
    _claim_unique,
    render_filename,
)
from messagefoundry.transports.mllp import (
    CR,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES,
    DEFAULT_RECEIVE_TIMEOUT,
    EB,
    SB,
    MLLPDecoder,
    MLLPDestination,
    MLLPFrameError,
    MLLPSource,
    build_ack,
    frame,
)

ADT = (Path(__file__).resolve().parents[1] / "samples" / "messages" / "adt_a01.hl7").read_text(
    encoding="utf-8"
)


# --- framing -----------------------------------------------------------------


def test_frame_wraps_with_sb_eb_cr() -> None:
    framed = frame("HELLO")
    assert framed[0] == SB
    assert framed[-2:] == bytes([EB, CR])
    assert framed[1:-2] == b"HELLO"


def test_decoder_single_message() -> None:
    msgs = list(MLLPDecoder().feed(frame("MSH|one")))
    assert msgs == [b"MSH|one"]


def test_decoder_splits_multiple_messages_in_one_chunk() -> None:
    data = frame("AAA") + frame("BBB")
    assert list(MLLPDecoder().feed(data)) == [b"AAA", b"BBB"]


def test_decoder_reassembles_across_chunks() -> None:
    full = frame("MSH|split me up")
    dec = MLLPDecoder()
    out: list[bytes] = []
    # Feed one byte at a time — the worst-case fragmentation.
    for i in range(len(full)):
        out.extend(dec.feed(full[i : i + 1]))
    assert out == [b"MSH|split me up"]


def test_decoder_discards_inter_frame_noise() -> None:
    # Leading junk, and a stray CR/keepalive between frames, must be ignored.
    data = b"garbage" + frame("AAA") + b"\r\n" + frame("BBB")
    assert list(MLLPDecoder().feed(data)) == [b"AAA", b"BBB"]


# --- ACK building ------------------------------------------------------------


def test_build_ack_accept_swaps_sender_receiver_and_echoes_control() -> None:
    ack = build_ack(ADT, code="AA", timestamp="20260604120001")
    p = Peek.parse(ack)
    assert p.message_type == "ACK"
    assert p.field("MSA-1") == "AA"
    assert p.field("MSA-2") == "MSG00001"  # original control id
    # Inbound was SENDINGAPP->...->RECEIVINGFAC; the ACK reverses that.
    assert p.sending_app == "RECEIVINGAPP"
    assert p.receiving_facility == "SENDINGFAC"
    assert p.version == "2.5.1"


def test_build_ack_defaults_msh7_to_now() -> None:
    # An omitted timestamp must yield a populated MSH-7 (a 14-digit HL7 DTM), not an empty field a
    # strict sender would reject (low-6). An explicit timestamp is still honored (test above).
    ack = build_ack(ADT, code="AA")
    msh7 = Peek.parse(ack).field("MSH-7")
    assert msh7 is not None and len(msh7) == 14 and msh7.isdigit()


def test_build_ack_enhanced_mode_uses_commit_codes() -> None:
    ack = build_ack(ADT, code="AA", ack_mode=AckMode.ENHANCED)
    assert Peek.parse(ack).field("MSA-1") == "CA"


def test_build_ack_error_carries_reason_text() -> None:
    ack = build_ack(ADT, code="AE", text="PID missing")
    p = Peek.parse(ack)
    assert p.field("MSA-1") == "AE"
    assert p.field("MSA-3") == "PID missing"


def test_build_ack_for_unparseable_inbound_still_builds() -> None:
    # A garbage inbound must still yield a (negative) ACK, not crash the listener.
    ack = build_ack("not hl7 at all", code="AR", text="unparseable")
    p = Peek.parse(ack)
    assert p.message_type == "ACK"
    assert p.field("MSA-1") == "AR"


def test_build_ack_rejects_unknown_code() -> None:
    with pytest.raises(ValueError):
        build_ack(ADT, code="ZZ")


def test_build_ack_text_cannot_inject_extra_fields() -> None:
    # A NACK reason containing the field separator must not add MSA fields (HL7-3).
    ack = build_ack(ADT, code="AE", text="bad|field|MSA-99-injection")
    p = Peek.parse(ack)
    assert p.field("MSA-1") == "AE"
    assert p.field("MSA-4") is None  # the embedded '|' was escaped, not turned into new fields


def test_build_ack_text_cannot_inject_segments() -> None:
    # A CR in the reason text must not inject a new segment into the ACK (HL7-3).
    ack = build_ack(ADT, code="AR", text="line1\rZZZ|injected|segment")
    assert Peek.parse(ack).segments() == ["MSH", "MSA"]  # no stray ZZZ segment


# --- file destination --------------------------------------------------------


def test_render_filename_resolves_placeholders() -> None:
    assert render_filename("{MSH-10}.hl7", ADT, fallback="x") == "MSG00001.hl7"
    assert render_filename("{MSH-9.1}_{MSH-10}.hl7", ADT, fallback="x") == "ADT_MSG00001.hl7"


def test_render_filename_falls_back_when_unresolvable() -> None:
    assert render_filename("{PID-99}.hl7", ADT, fallback="fb") == "fb.hl7"
    assert render_filename("{MSH-10}.hl7", "garbage", fallback="fb") == "fb.hl7"


async def test_file_destination_writes_named_file(tmp_path: Path) -> None:
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "{MSH-10}.hl7"},
        )
    )
    await dest.send(ADT)
    out = tmp_path / "MSG00001.hl7"
    assert out.read_text(encoding="utf-8") == ADT
    assert not list(tmp_path.glob("*.part"))  # temp file cleaned up by atomic rename


async def test_file_destination_does_not_clobber(tmp_path: Path) -> None:
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "fixed.hl7"},
        )
    )
    await dest.send(ADT)
    await dest.send(ADT)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["fixed-1.hl7", "fixed.hl7"]


def test_claim_unique_falls_back_to_copy_when_link_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On FAT/exFAT/SMB os.link raises a non-FileExistsError OSError; delivery must still land via an
    # exclusive-create copy, still claiming a unique name when the target exists (low-5).
    def _no_link(src: str, dst: str) -> None:
        raise OSError("hard links not supported on this filesystem")

    monkeypatch.setattr(os, "link", _no_link)
    src = tmp_path / "src.part"
    src.write_bytes(b"PAYLOAD")
    target = tmp_path / "out.hl7"
    target.write_bytes(b"existing")  # name already taken -> fallback must pick out-1.hl7

    claimed = _claim_unique(src, target)
    assert claimed.name == "out-1.hl7"
    assert claimed.read_bytes() == b"PAYLOAD"
    assert target.read_bytes() == b"existing"  # the pre-existing file is never clobbered


@pytest.mark.skipif(
    os.name != "posix", reason="POSIX permission bits; Windows ignores os.open mode"
)
def test_claim_unique_copy_fallback_is_not_world_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The cross-filesystem copy fallback creates the delivered file with mode 0o600, matching the
    # mkstemp temp + the os.link/os.replace paths that inherit it. A delivered file can carry PHI, so
    # the fallback must not be the one path that leaves it group/world-readable (CodeQL
    # py/overly-permissive-file). Assert the group/other bits are clear (umask-independent).
    def _no_link(src: str, dst: str) -> None:
        raise OSError("hard links not supported on this filesystem")

    monkeypatch.setattr(os, "link", _no_link)
    src = tmp_path / "src.part"
    src.write_bytes(b"PAYLOAD")
    target = tmp_path / "out.hl7"

    claimed = _claim_unique(src, target)
    assert claimed.read_bytes() == b"PAYLOAD"
    assert claimed.stat().st_mode & 0o077 == 0  # no group/other access


# --- file source -------------------------------------------------------------


async def test_file_source_reads_and_archives(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    # write_bytes (not write_text) so on-disk content is byte-exact across platforms.
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]
    assert (inbox / ".processed" / "msg1.hl7").exists()
    assert not (inbox / "msg1.hl7").exists()


async def test_file_source_keeps_persistently_failing_file_for_retry(tmp_path: Path) -> None:
    # M-15: a handler that keeps failing (a persistent store/infra outage) must NOT quarantine the
    # file to .error — that would drop a received message unrecorded. It stays in the inbox as
    # back-pressure and is retried until the store recovers.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "bad.hl7").write_text("MSH|^~\\&|A", encoding="utf-8")
    attempts = {"n": 0}

    async def handler(raw: bytes) -> None:
        attempts["n"] += 1
        raise RuntimeError("store unavailable")  # never recovers

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: attempts["n"] >= 3)  # retried across multiple scans
    finally:
        await src.stop()
        await task
    assert (inbox / "bad.hl7").exists()  # still in the inbox (back-pressure, not lost)
    assert not (inbox / ".error" / "bad.hl7").exists()  # never quarantined as accept-and-drop
    assert not (inbox / ".processed" / "bad.hl7").exists()


async def test_file_source_quarantines_content_rejected_by_scan_hook(tmp_path: Path) -> None:
    # ASVS 5.4.3: a configured pre-ingest scan hook (AV/ICAP/plugin) runs over every inbound file; the
    # content it rejects is quarantined to .error and never handed to the handler.
    from messagefoundry.transports.file import ScanRejected, set_scan_hook

    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    def _reject_all(raw: bytes, source: str) -> None:
        raise ScanRejected("blocked by test scanner")

    set_scan_hook(_reject_all)
    try:
        src = build_source(
            Source(
                type=ConnectorType.FILE,
                settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
            )
        )
        task = asyncio.create_task(src.start(handler))
        try:
            await _until(lambda: (inbox / ".error" / "msg1.hl7").exists())
        finally:
            await src.stop()
            await task
    finally:
        set_scan_hook(None)  # restore the default no-op so the global doesn't leak between tests
    assert received == []  # the scanner blocked it before the handler
    assert (inbox / ".error" / "msg1.hl7").exists()  # quarantined
    assert not (inbox / ".processed" / "msg1.hl7").exists()


async def test_file_source_scan_hook_malfunction_fails_closed(tmp_path: Path) -> None:
    # ASVS 5.4.3, BACKLOG #204: a scan hook that MALFUNCTIONS (raises a non-ScanRejected exception — the
    # AV/ICAP service is unreachable, or a plugin bug) must fail CLOSED. The file is never emitted, and —
    # unlike a content rejection — it is NOT quarantined but left in place to be re-scanned once the
    # scanner recovers (at-least-once). It must never be passed through unscanned.
    from messagefoundry.transports.file import set_scan_hook

    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    def _scanner_down(raw: bytes, source: str) -> None:
        raise ConnectionError(
            "ICAP service unreachable"
        )  # a transient scanner outage, not a rejection

    set_scan_hook(_scanner_down)
    try:
        src = build_source(
            Source(
                type=ConnectorType.FILE,
                settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
            )
        )
        task = asyncio.create_task(src.start(handler))
        try:
            # Give the poller several ticks to (fail to) process the file.
            for _ in range(20):
                await asyncio.sleep(0.01)
                if received:
                    break
        finally:
            await src.stop()
            await task
    finally:
        set_scan_hook(None)  # restore the default no-op so the global doesn't leak between tests
    assert received == []  # fail-closed: never emitted while the scanner is down
    assert (inbox / "msg1.hl7").exists()  # left in place to retry (NOT quarantined, NOT processed)
    assert not (inbox / ".error" / "msg1.hl7").exists()
    assert not (inbox / ".processed" / "msg1.hl7").exists()


# --- MLLP source <-> destination round trip ----------------------------------


# Both connection modes (ADR 0067): the connect-per-send default and the persistent-reuse opt-in
# must be observably identical for a single round-trip (AC-2/AC-12).
@pytest.mark.parametrize("persistent", [True, False])
async def test_mllp_round_trip_positive_ack(tmp_path: Path, persistent: bool) -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": source.sockport,
                    "timeout_seconds": 5,
                    "persistent": persistent,
                },
            )
        )
        try:
            await dest.send(ADT)  # returns normally only on a positive ACK
        finally:
            await dest.aclose()
    finally:
        await source.stop()
    assert received == [ADT.encode("utf-8")]


@pytest.mark.parametrize("persistent", [True, False])
@pytest.mark.parametrize(
    ("ack_code", "expect_code", "expect_permanent"),
    [
        ("AR", "AR", True),  # application reject → permanent → fail-fast
        ("AE", "AE", False),  # application error → transient → retry
    ],
)
async def test_mllp_negative_ack_classifies_permanence(
    ack_code: str, expect_code: str, expect_permanent: bool, persistent: bool
) -> None:
    # A negative ACK surfaces as NegativeAckError (a DeliveryError subclass) carrying the failure
    # classification the delivery worker keys its policy on: AR rejects fail-fast, AE retries.
    # Identical in both connection modes (ADR 0067 AC-10/AC-12).
    async def handler(raw: bytes) -> str:
        return build_ack(raw, code=ack_code, text="rejected")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": source.sockport,
                    "timeout_seconds": 5,
                    "persistent": persistent,
                },
            )
        )
        try:
            with pytest.raises(NegativeAckError, match="negative ACK") as exc_info:
                await dest.send(ADT)
            assert exc_info.value.code == expect_code
            assert exc_info.value.permanent is expect_permanent
        finally:
            await dest.aclose()
    finally:
        await source.stop()


@pytest.mark.parametrize("persistent", [True, False])
async def test_mllp_connect_failure_raises_delivery_error(persistent: bool) -> None:
    # Nothing is listening on this port.
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={
                "host": "127.0.0.1",
                "port": 1,
                "timeout_seconds": 2,
                "persistent": persistent,
            },
        )
    )
    with pytest.raises(DeliveryError):
        await dest.send(ADT)


# --- connector settings (Mirth-parity expansion) -----------------------------


def test_frame_honors_encoding() -> None:
    framed = frame("café", "latin-1")
    assert framed[1:-2] == "café".encode("latin-1")


async def test_file_destination_honors_encoding(tmp_path: Path) -> None:
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "out.txt", "encoding": "latin-1"},
        )
    )
    payload = "PID|1||X||café\r"
    await dest.send(payload)
    assert (tmp_path / "out.txt").read_bytes() == payload.encode("latin-1")


async def test_file_source_min_age_skips_recent_files(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "new.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "min_age_seconds": 3600,  # far in the future → the fresh file is "too new"
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await asyncio.sleep(0.1)  # several poll cycles
        assert received == []  # skipped — still being "written"
        assert (inbox / "new.hl7").exists()  # left in place for a later poll
    finally:
        await src.stop()
        await task


async def test_file_source_after_read_delete(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "m.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "after_read": "delete",
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert not (inbox / "m.hl7").exists()
    assert not (inbox / ".processed" / "m.hl7").exists()  # deleted, not moved


def _raise_locked(*_a: object, **_k: object) -> None:
    raise OSError("locked")


async def test_file_source_move_failure_leaves_file_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # FILE-5: when archiving a processed file can't move it (dest unwritable / file locked), _move
    # catches OSError, logs it, and swallows — the file stays in place (re-read next scan, a bounded
    # duplicate) rather than crashing the poller or vanishing unrecorded. Monkeypatch (not POSIX chmod)
    # because this runs on Windows.
    from messagefoundry.transports import file as file_mod

    inbox = tmp_path / "in"
    inbox.mkdir()
    # The archive dir MUST exist, so the injected failure is the ONLY reason the move can fail. It
    # did not before, and a missing destination failed the move on its own — which meant this test
    # passed whether or not the injection was still on the code path. It stopped being on it the
    # moment _move left Path.replace behind (BACKLOG #1046), and nothing said so.
    (inbox / ".processed").mkdir()
    (inbox / "m.hl7").write_bytes(ADT.encode("utf-8"))
    src = FileSource(Source(type=ConnectorType.FILE, settings={"directory": str(inbox)}))
    # The atomic destination-name claim is the seam now (#1046): _move claims the name with
    # os.link/O_EXCL instead of exists()-then-replace, so a locked/unwritable destination surfaces
    # there rather than at Path.replace.
    monkeypatch.setattr(file_mod, "_claim_unique", _raise_locked)  # every move raises
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        src._after_processing(inbox / "m.hl7")  # default after_read="move"
    assert (inbox / "m.hl7").exists()  # left in place, not lost
    assert not (inbox / ".processed" / "m.hl7").exists()  # never archived
    assert "could not move" in caplog.text


async def test_file_source_delete_failure_leaves_file_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # FILE-5 (delete mode): after_read="delete" that can't unlink the processed file catches OSError,
    # logs it (the file will be re-read = a bounded duplicate), and swallows — never crashes the poller.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "m.hl7").write_bytes(ADT.encode("utf-8"))
    src = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "after_read": "delete"})
    )
    monkeypatch.setattr(Path, "unlink", _raise_locked)  # every delete raises
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        src._after_processing(inbox / "m.hl7")
    assert (inbox / "m.hl7").exists()  # still there, not silently dropped
    assert "could not delete" in caplog.text


# --- #114 opt-in startup directory validation -------------------------------


async def test_file_validate_directory_off_is_noop_on_missing_dir(tmp_path: Path) -> None:
    # Default (validate_directory unset): a missing directory does NOT fail validate_startup — the
    # historical run-time deferral (the source binds and logs-and-retries once started). #114.
    src = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(tmp_path / "nope")})
    )
    await src.validate_startup()  # no raise


async def test_file_validate_directory_fails_fast_on_missing_dir(tmp_path: Path) -> None:
    # validate_directory=true + a missing directory → SourceStartupError, and the probe NEVER creates
    # the directory (the #114 semantic-gap guard: reusing the mkdir'ing probe would fabricate+pass it).
    missing = tmp_path / "nope"
    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(missing), "validate_directory": True},
        )
    )
    with pytest.raises(SourceStartupError):
        await src.validate_startup()
    assert not missing.exists()  # never fabricated by the probe


async def test_file_validate_directory_passes_on_existing_writable_dir(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "validate_directory": True},
        )
    )
    await src.validate_startup()  # exists + writable → passes


async def test_file_validate_directory_leave_mode_requires_only_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A leave-in-place source (#142) never writes to the poll dir, so validate_directory checks READ
    # only — a read-only share passes. Force the write probe to fail: leave mode must NOT call it (so it
    # still passes), while a move-mode source on the same dir DOES fail (write required).
    import messagefoundry.transports.file as filemod

    inbox = tmp_path / "ro"
    inbox.mkdir()
    monkeypatch.setattr(filemod.tempfile, "mkstemp", _raise_locked)  # any write probe raises
    leave = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "validate_directory": True,
                "after_read": "leave",
            },
        )
    )
    await leave.validate_startup()  # read-only probe → no write attempt → passes
    move = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "validate_directory": True},
        )
    )
    with pytest.raises(SourceStartupError):
        await move.validate_startup()  # move mode needs write → the failing probe raises


# --- #114 opt-in startup directory validation: the OUTBOUND half -------------


def _file_dest(directory: Path, **over: object) -> FileDestination:
    settings: dict[str, object] = {"directory": str(directory), "filename": "msg.hl7"}
    settings.update(over)
    dest = build_destination(
        Destination(name="OB_FILE", type=ConnectorType.FILE, settings=settings)
    )
    assert isinstance(dest, FileDestination)
    return dest


async def test_file_destination_test_probe_creates_the_directory(tmp_path: Path) -> None:
    # Pins WHY the outbound needs a startup hook of its own: #114's score rested on "a clean workaround
    # via the on-demand test probe", and in this direction that premise is false. POST
    # /connections/{name}/test CREATES the target directory, so the act of asking "does this directory
    # exist?" makes the answer yes. Measured, not inferred — the rest of the design leans on it.
    missing = tmp_path / "typo"
    await _file_dest(missing).test_connection()
    assert missing.is_dir()  # the probe fabricated it


async def test_file_destination_validate_directory_off_is_noop(tmp_path: Path) -> None:
    # Default: validate_startup is a no-op even on a missing directory. That is the item's own trigger
    # (an intermittently-available target must NOT fail startup), so the toggle defaults to deferral.
    missing = tmp_path / "nope"
    await _file_dest(missing).validate_startup()  # no raise
    assert not missing.exists()  # and the hook itself creates nothing


async def test_file_destination_validate_directory_refuses_missing_dir(tmp_path: Path) -> None:
    # The opt-in arm: a typo'd target directory FAILS startup validation, and the no-mkdir probe never
    # fabricates it (the same semantic gap the source hook closes — _probe_dir_writable would pass).
    missing = tmp_path / "nope"
    dest = _file_dest(missing, validate_directory=True)
    with pytest.raises(DestinationStartupError):
        await dest.validate_startup()
    assert not missing.exists()


async def test_file_destination_validate_directory_passes_on_existing_writable_dir(
    tmp_path: Path,
) -> None:
    outdir = tmp_path / "out"
    outdir.mkdir()
    await _file_dest(outdir, validate_directory=True).validate_startup()  # exists + writable


async def test_file_destination_created_directory_is_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Default behaviour is unchanged — the directory is still created on write and the delivery still
    # succeeds — but the creation is no longer SILENT. Without this line a typo'd directory would be
    # created on first delivery and every message counted and logged as delivered (it was), into a path
    # nobody is watching, with nothing anywhere saying so.
    outdir = tmp_path / "made"
    dest = _file_dest(outdir)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        await dest.send(ADT)
    assert (outdir / "msg.hl7").exists()
    assert "CREATED missing directory" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        await dest.send(ADT)
    assert "CREATED missing directory" not in caplog.text  # only a real creation is loud


async def test_file_destination_non_directory_at_the_path_still_errors(tmp_path: Path) -> None:
    # A regular FILE sitting at the configured directory path is still a mapped DeliveryError (retried,
    # never a crash and never a silent success) after the create-detection rework swapped
    # mkdir(exist_ok=True) for mkdir()+FileExistsError.
    #
    # Deliberately NOT claimed as a pin on that swap: sabotaging the re-raise (swallowing the
    # FileExistsError) was measured and left this test GREEN, because the mkstemp two lines later fails
    # with NotADirectoryError — another OSError — and maps to the same DeliveryError. That is precisely
    # why the swap is safe, and why this asserts only the invariant that actually holds either way.
    clash = tmp_path / "not_a_dir"
    clash.write_text("i am a file", encoding="utf-8")
    with pytest.raises(DeliveryError):
        await _file_dest(clash).send(ADT)
    assert clash.is_file()  # untouched


async def test_file_destination_validate_directory_never_creates_on_write(tmp_path: Path) -> None:
    # Under the toggle the target is not fabricated at DELIVERY time either: "this directory must
    # exist" has to keep meaning that after start, or a share that vanished mid-run would be silently
    # re-created at the mount point. The send fails RETRYABLY (DeliveryError), so the lane backs off and
    # self-heals when the share returns — the row is never dropped.
    missing = tmp_path / "gone"
    dest = _file_dest(missing, validate_directory=True)
    with pytest.raises(DeliveryError):
        await dest.send(ADT)
    assert not missing.exists()


async def test_file_destination_validate_directory_test_probe_never_creates(tmp_path: Path) -> None:
    # ... and the on-demand probe honours the same rule under the toggle, so POST
    # /connections/{name}/test cannot silently repair the typo the toggle exists to catch (after which
    # the next restart would validate clean and the operator would never learn the path was wrong).
    missing = tmp_path / "typo"
    dest = _file_dest(missing, validate_directory=True)
    with pytest.raises(DeliveryError):
        await dest.test_connection()
    assert not missing.exists()


# --- #142 leave-in-place process-in-place disposition -----------------------


class _FakeLedger:
    """An in-memory ProcessedFileLedger stand-in — proves the connector calls the injected seam
    (records a HASHED key, skips a seen key, prunes) without a real store."""

    def __init__(self) -> None:
        self.keys: set[str] = set()
        self.pruned = 0

    async def is_processed(self, file_key: str) -> bool:
        return file_key in self.keys

    async def mark_processed(self, file_key: str) -> None:
        self.keys.add(file_key)

    async def prune(self) -> None:
        self.pruned += 1


def test_file_source_rejects_unknown_after_read(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        FileSource(
            Source(
                type=ConnectorType.FILE, settings={"directory": str(tmp_path), "after_read": "x"}
            )
        )


async def test_file_source_leave_in_place_keeps_file_and_dedups(tmp_path: Path) -> None:
    # after_read='leave' (#142): the source file is NEVER moved/deleted, and the durable ledger dedups
    # so it is ingested exactly ONCE despite many polls. The ledger holds a HASHED key (64 hex chars).
    inbox = tmp_path / "share"
    inbox.mkdir()
    (inbox / "m.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "after_read": "leave",
            },
        )
    )
    ledger = _FakeLedger()
    src.processed_ledger = ledger
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
        await asyncio.sleep(0.1)  # several more poll cycles — must NOT re-ingest
    finally:
        await src.stop()
        await task
    assert len(received) == 1  # ingested ONCE, not once-per-poll
    assert (inbox / "m.hl7").exists()  # left in place
    assert not (inbox / ".processed" / "m.hl7").exists()  # never moved
    assert len(ledger.keys) == 1
    (key,) = ledger.keys
    assert len(key) == 64 and all(c in "0123456789abcdef" for c in key)  # a sha256 hex digest
    assert "m.hl7" not in key  # the cleartext filename never appears in the key
    assert ledger.pruned >= 1  # pruned after recording a new file


async def test_file_source_leave_in_place_reingests_a_changed_file(tmp_path: Path) -> None:
    # An UPDATED file (new size → new hashed key) is re-ingested; an unchanged file is not.
    inbox = tmp_path / "share"
    inbox.mkdir()
    f = inbox / "m.hl7"
    f.write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "after_read": "leave",
            },
        )
    )
    src.processed_ledger = _FakeLedger()
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: len(received) >= 1)
        f.write_bytes(ADT.encode("utf-8") + b"PID|2||changed\r")  # different size → new key
        await _until(lambda: len(received) >= 2)
    finally:
        await src.stop()
        await task
    assert len(received) >= 2


async def test_file_source_leave_in_place_without_ledger_uses_memory(tmp_path: Path) -> None:
    # No durable ledger injected (a direct caller/test): the in-process set still dedups within the
    # process lifetime, and the file is left in place.
    inbox = tmp_path / "share"
    inbox.mkdir()
    (inbox / "m.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "after_read": "leave",
            },
        )
    )  # processed_ledger stays None
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
        await asyncio.sleep(0.1)
    finally:
        await src.stop()
        await task
    assert len(received) == 1
    assert (inbox / "m.hl7").exists()


async def test_file_source_leave_recursive_same_name_distinct_subdirs(tmp_path: Path) -> None:
    # #142 Finding-1 guard: under recursive=True, two DISTINCT same-basename files in different subdirs
    # that ALSO share size AND mtime (the coarse-share collision this feature targets) must BOTH be
    # ingested — the dedup key folds the RELATIVE PATH, so they get DISTINCT hashes. A basename-only key
    # would silently dedup the second away (an accept-and-drop of a received file).
    inbox = tmp_path / "share"
    (inbox / "a").mkdir(parents=True)
    (inbox / "b").mkdir(parents=True)
    body = ADT.encode("utf-8")
    fa, fb = inbox / "a" / "m.hl7", inbox / "b" / "m.hl7"
    fa.write_bytes(body)
    fb.write_bytes(body)  # identical content → identical size
    ts = 1_700_000_000  # force identical mtime on both (the collision the finding describes)
    os.utime(fa, (ts, ts))
    os.utime(fb, (ts, ts))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "recursive": True,
                "after_read": "leave",
            },
        )
    )
    ledger = _FakeLedger()
    src.processed_ledger = ledger
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: len(received) >= 2)
        await asyncio.sleep(0.1)  # no further re-ingest
    finally:
        await src.stop()
        await task
    assert len(received) == 2  # BOTH ingested — never one silently deduped
    assert len(ledger.keys) == 2  # two DISTINCT hashed keys (path folded in)
    assert fa.exists() and fb.exists()  # both left in place


async def test_file_source_leave_durable_ledger_read_is_the_dedup(tmp_path: Path) -> None:
    # #142 Finding-3: with an EMPTY in-memory cache, a file already recorded in the DURABLE ledger is
    # skipped with ZERO emits — exercising ledger.is_processed() in isolation (the cross-restart /
    # failover path the in-memory fast-path short-circuit otherwise hides).
    inbox = tmp_path / "share"
    inbox.mkdir()
    f = inbox / "m.hl7"
    f.write_bytes(ADT.encode("utf-8"))
    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "after_read": "leave",
            },
        )
    )
    ledger = _FakeLedger()
    ledger.keys.add(
        src._file_key(f)
    )  # pre-seed the DURABLE ledger; the in-memory cache stays EMPTY
    src.processed_ledger = ledger
    assert len(src._processed_seen) == 0
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    task = asyncio.create_task(src.start(handler))
    try:
        await asyncio.sleep(0.15)  # several polls — the durable read must dedup it every time
    finally:
        await src.stop()
        await task
    assert received == []  # ZERO emits — the durable is_processed() read is the deciding dedup
    assert f.exists()


async def test_file_source_run_loop_survives_a_scan_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # FILE-13: a scan that raises (mirrors test_remotefile_transport's poll-error test) must NOT kill
    # the poller — _run catches it, logs, and keeps looping; that a "running" connection silently stops
    # receiving (and re-raises inside stop()/reload) is exactly review H-4. We force _scan_once to raise
    # directly (the P2 table's "bad glob / vanished dir" triggers are swallowed one level down in
    # _candidates and never reach the outer guard) and set _stop inside it so _run exits after one tick.
    src = FileSource(Source(type=ConnectorType.FILE, settings={"directory": str(tmp_path)}))
    calls: list[int] = []

    async def boom() -> None:
        calls.append(1)
        src._stop.set()  # so _run exits after this single caught tick
        raise RuntimeError("scan blew up")

    src._scan_once = boom  # type: ignore[method-assign]
    src.poll_seconds = 0.0
    src._stop.clear()
    with caplog.at_level(logging.ERROR, logger="messagefoundry.transports.file"):
        await src._run()  # must NOT propagate — a bad scan never kills the poller
    assert calls == [1]
    assert "file source scan failed" in caplog.text


async def test_file_source_recursive_descends_subdirs(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    (inbox / "sub").mkdir(parents=True)
    (inbox / "sub" / "deep.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "recursive": True,
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]


def test_file_source_within_root_rejects_escaping_path(tmp_path: Path) -> None:
    # Path-confinement (3.2): a candidate that resolves outside the watch root is rejected, so a
    # recursive scan can't be walked out of its directory via a symlink.
    inbox = tmp_path / "in"
    inbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    inside = inbox / "ok.hl7"
    inside.write_bytes(b"MSH|x\r")
    secret = outside / "secret.hl7"
    secret.write_bytes(b"MSH|x\r")
    src = build_source(Source(type=ConnectorType.FILE, settings={"directory": str(inbox)}))
    assert isinstance(src, FileSource)
    assert src._within_root(inside) is True
    assert src._within_root(secret) is False


async def test_file_source_skips_symlink_escaping_watch_root(tmp_path: Path) -> None:
    # End-to-end: a symlinked subdir pointing outside the root must never let the poller deliver a
    # file from outside the configured directory (whether or not rglob follows the symlink).
    inbox = tmp_path / "in"
    inbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        (inbox / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported / not permitted on this platform")

    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "recursive": True,
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await asyncio.sleep(0.1)  # several poll intervals; the escaping file must never arrive
    finally:
        await src.stop()
        await task
    assert received == []


async def test_file_destination_refuses_path_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Defence in depth (3.2): even if a filename slipped past sanitization with a path component,
    # the destination refuses to write outside its configured directory.
    out = tmp_path / "out"
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.FILE, settings={"directory": str(out)})
    )
    monkeypatch.setattr(
        "messagefoundry.transports.file.render_filename", lambda *a, **k: "../escape.hl7"
    )
    with pytest.raises(DeliveryError, match="outside the destination directory"):
        await dest.send("MSH|x\r")
    assert not (tmp_path / "escape.hl7").exists()


async def test_file_source_sort_mtime_orders_by_time(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    # Name order is a,z; mtime order is z (older), a (newer) — so they disagree.
    (inbox / "z.hl7").write_bytes(b"MSH|z\r")
    (inbox / "a.hl7").write_bytes(b"MSH|a\r")
    now = time.time()
    os.utime(inbox / "z.hl7", (now - 100, now - 100))
    os.utime(inbox / "a.hl7", (now, now))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "sort": "mtime",
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: len(received) == 2)
    finally:
        await src.stop()
        await task
    assert received == [b"MSH|z\r", b"MSH|a\r"]  # mtime order, not name (a,z) order


async def test_mllp_max_connections_refuses_extra() -> None:
    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0, "max_connections": 1}
        )
    )
    await source.start(handler)
    try:
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        await asyncio.sleep(0.05)  # let the server register the first client
        r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        data = await asyncio.wait_for(r2.read(), 2.0)  # second is refused → EOF
        assert data == b""
        w1.close()
        w2.close()
    finally:
        await source.stop()


async def test_mllp_receive_timeout_closes_idle_client() -> None:
    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "receive_timeout": 0.1},
        )
    )
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        data = await asyncio.wait_for(reader.read(), 2.0)  # closed after ~0.1s idle → EOF
        assert data == b""
        writer.close()
    finally:
        await source.stop()


# --- resource caps (DoS guards: MLLP-1/2/3/4, FILE-2) ------------------------


def test_decoder_rejects_oversized_frame() -> None:
    # An open frame (SB, no EB) that grows past the cap must raise rather than buffer forever.
    dec = MLLPDecoder(max_frame_bytes=10)
    with pytest.raises(MLLPFrameError):
        list(dec.feed(bytes([SB]) + b"A" * 20))


def test_decoder_unbounded_by_default() -> None:
    # No cap configured → the decoder buffers whatever arrives (back-compat).
    dec = MLLPDecoder()
    assert list(dec.feed(frame("A" * 1000))) == [b"A" * 1000]


def test_mllp_source_defaults_are_secure() -> None:
    src = MLLPSource(Source(type=ConnectorType.MLLP, settings={"port": 0}))
    assert src.host == "127.0.0.1"  # loopback, not 0.0.0.0
    assert src.max_connections == DEFAULT_MAX_CONNECTIONS
    assert src.receive_timeout == DEFAULT_RECEIVE_TIMEOUT
    assert src.max_frame_bytes == DEFAULT_MAX_FRAME_BYTES


def test_mllp_source_caps_can_be_disabled_explicitly() -> None:
    src = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"port": 0, "max_connections": 0, "receive_timeout": 0, "max_frame_bytes": 0},
        )
    )
    assert src.max_connections is None
    assert src.receive_timeout is None
    assert src.max_frame_bytes is None


def test_dsl_defaults_match_connector_constants() -> None:
    # The MLLP()/File() DSL literals must stay in sync with the connector DEFAULT_* constants.
    s = MLLP(port=1).settings
    assert (
        s["host"] is None
    )  # no authored host: the bind interface is service-level ([inbound].bind_host)
    assert s["max_connections"] == DEFAULT_MAX_CONNECTIONS
    assert s["receive_timeout"] == DEFAULT_RECEIVE_TIMEOUT
    assert s["max_frame_bytes"] == DEFAULT_MAX_FRAME_BYTES
    assert File(directory="x").settings["max_file_bytes"] == DEFAULT_MAX_FILE_BYTES


async def test_mllp_source_drops_oversized_frame() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> str:
        handled.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "max_frame_bytes": 64},
        )
    )
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(bytes([SB]) + b"A" * 200)  # open frame past the cap, never closed
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 2.0)  # server drops the connection → EOF
        assert data == b""
        writer.close()
    finally:
        await source.stop()
    assert handled == []  # no complete frame was ever delivered to the handler


async def test_mllp_stop_closes_established_clients() -> None:
    """An idle-but-connected peer must not hang stop()/reload: stop closes the connection and
    returns promptly, and the client then sees EOF (review H-2)."""

    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
    try:
        await _until(lambda: source._active == 1)  # connection established + registered
        await asyncio.wait_for(source.stop(), timeout=3.0)  # must NOT hang on the open connection
        assert await asyncio.wait_for(reader.read(), timeout=2.0) == b""  # client sees EOF
    finally:
        writer.close()


async def test_mllp_stop_lets_inflight_handler_finish() -> None:
    """A message being handled when stop() runs still finishes its commit (the body is durably
    stored before any ACK; only a not-yet-sent ACK is lost, which the sender retries) — review H-2."""
    started = asyncio.Event()
    release = asyncio.Event()
    committed: list[bytes] = []

    async def slow_handler(raw: bytes) -> str:
        started.set()
        await release.wait()  # block mid-handler
        committed.append(raw)  # stands in for the durable store commit
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(slow_handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
    try:
        writer.write(frame("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1"))
        await writer.drain()
        await asyncio.wait_for(started.wait(), timeout=2.0)  # handler is mid-flight
        stop_task = asyncio.ensure_future(source.stop())
        release.set()  # let the in-flight handler complete its commit
        await asyncio.wait_for(stop_task, timeout=3.0)
        assert committed  # the in-flight message was fully handled, not dropped/cancelled
    finally:
        writer.close()


async def test_file_source_routes_oversized_to_error(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "big.hl7").write_bytes(b"X" * 5000)
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "max_file_bytes": 100,
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: (inbox / ".error" / "big.hl7").exists())
    finally:
        await src.stop()
        await task
    assert received == []  # never read into memory
    assert (inbox / ".error" / "big.hl7").exists()


async def test_file_source_leaves_file_in_place_on_handler_failure(tmp_path: Path) -> None:
    # M-15: an exception escaping the handler is an infrastructure (store-write) failure — the file
    # must stay in place to retry, not be quarantined to .error as an unrecorded accept-and-drop.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg.hl7").write_bytes(b"MSH|^~\\&|A\r")
    attempts = {"n": 0}

    async def handler(raw: bytes) -> None:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("store write failed")  # transient infra failure on the first scan

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        # The retry (store "recovered") eventually succeeds and the file moves to .processed.
        await _until(lambda: (inbox / ".processed" / "msg.hl7").exists())
    finally:
        await src.stop()
        await task
    assert attempts["n"] >= 2  # the first failure left it in place; a later scan retried it
    assert not (inbox / ".error" / "msg.hl7").exists()  # never quarantined


# --- file connector: gzip compress / decompress (ADR 0123) -------------------


async def test_file_destination_gzip_compress(tmp_path: Path) -> None:
    # compress="gzip" gzips the drop and appends `.gz`; the gunzip of the file is the original payload.
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "out.hl7", "compress": "gzip"},
        )
    )
    await dest.send(ADT)
    written = tmp_path / "out.hl7.gz"
    assert written.exists()  # `.gz` appended
    assert not (tmp_path / "out.hl7").exists()
    assert gzip_decompress(written.read_bytes()) == ADT.encode("utf-8")


async def test_file_source_gunzips_before_sniff(tmp_path: Path) -> None:
    # AC-5: a gzipped HL7 drop is gunzipped, sniffed on the DECOMPRESSED bytes (which do start with
    # MSH), and the HL7 is emitted. Without decompress=, the gzip container fails the MSH sniff.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg.hl7.gz").write_bytes(gzip_compress(ADT.encode("utf-8")))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.gz",
                "poll_seconds": 0.01,
                "decompress": "gzip",
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]  # decompressed HL7, not the gzip container
    assert (inbox / ".processed" / "msg.hl7.gz").exists()
    assert not (inbox / ".error" / "msg.hl7.gz").exists()


async def test_file_source_quarantines_decompression_bomb(tmp_path: Path) -> None:
    # AC-6: a gzip that expands past max_decompressed_bytes is a bomb — the ORIGINAL compressed file is
    # moved to .error and never emitted (never accept-and-dropped). The compressed st_size cap can't
    # catch this (the archive on disk is tiny).
    inbox = tmp_path / "in"
    inbox.mkdir()
    bomb = gzip_compress(b"\x00" * (4 * 1024 * 1024))
    assert len(bomb) < 50_000  # small on disk — passes the compressed max_file_bytes cap
    (inbox / "bomb.hl7.gz").write_bytes(bomb)
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.gz",
                "poll_seconds": 0.01,
                "decompress": "gzip",
                "max_decompressed_bytes": 1024,
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: (inbox / ".error" / "bomb.hl7.gz").exists())
    finally:
        await src.stop()
        await task
    assert received == []  # never emitted
    assert (inbox / ".error" / "bomb.hl7.gz").exists()


async def test_file_source_quarantines_corrupt_archive(tmp_path: Path) -> None:
    # A file that isn't a valid gzip stream is quarantined to .error, never crashes the poller.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "junk.hl7.gz").write_bytes(b"not a gzip stream at all")
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.gz",
                "poll_seconds": 0.01,
                "decompress": "gzip",
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: (inbox / ".error" / "junk.hl7.gz").exists())
    finally:
        await src.stop()
        await task
    assert received == []


async def test_file_source_gunzips_non_hl7_content_type(tmp_path: Path) -> None:
    # Decompression is orthogonal to content_type: a gzipped X12/binary drop gunzips too (before the
    # content_type-gated sniff, which is skipped for a non-hl7v2 inbound), emitting the raw payload.
    inbox = tmp_path / "in"
    inbox.mkdir()
    payload = b"ISA*00*...*~GS*...*~"  # non-HL7 (X12-ish); no MSH header
    (inbox / "edi.x12.gz").write_bytes(gzip_compress(payload))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.gz",
                "poll_seconds": 0.01,
                "decompress": "gzip",
            },
        )
    )
    src.content_type = ContentType.X12  # runner injects this; set it directly
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [payload]  # decompressed, emitted verbatim (no sniff, no split)


def test_file_connector_rejects_unsupported_compression() -> None:
    # Single-stream gzip only: a zip/deflate value is rejected at construction (config typo caught at
    # wiring / `messagefoundry check`), not silently ignored.
    with pytest.raises(ValueError, match="compress"):
        build_destination(
            Destination(
                name="ob",
                type=ConnectorType.FILE,
                settings={"directory": "x", "compress": "zip"},
            )
        )
    with pytest.raises(ValueError, match="decompress"):
        FileSource(
            Source(type=ConnectorType.FILE, settings={"directory": "x", "decompress": "bzip2"})
        )


def test_file_factory_carries_compression_knobs() -> None:
    spec = File(directory="/tmp/x", compress="gzip", decompress="gzip", max_decompressed_bytes=999)
    assert spec.settings["compress"] == "gzip"
    assert spec.settings["decompress"] == "gzip"
    assert spec.settings["max_decompressed_bytes"] == 999


# --- file source: content_type-gated ingress (ADR 0004 / 0028) ---------------


async def test_file_source_ingests_binary_file_when_content_type_binary(tmp_path: Path) -> None:
    # Parity with RemoteFileSource (ADR 0004/0028): a File inbound declared content_type=binary must
    # INGEST a raw binary drop (e.g. a PDF) verbatim, NOT quarantine it for lacking an MSH/FHS/BHS
    # header. The exact bytes — including a NUL and high bytes — must survive to the pipeline (read as
    # BYTES, never text-decoded), recoverable via RawMessage.from_bytes (mfb64 carriage).
    inbox = tmp_path / "in"
    inbox.mkdir()
    pdf = b"%PDF-1.7\r\n\x00\x01\x02binary body\xff\xfe\x00tail"  # non-HL7; NUL + high bytes
    (inbox / "doc.pdf").write_bytes(pdf)
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.pdf", "poll_seconds": 0.01},
        )
    )
    src.content_type = ContentType.BINARY  # runner injects this; set it directly here
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: len(received) == 1)
    finally:
        await src.stop()
        await task
    assert received == [
        pdf
    ]  # handed off verbatim — not text-decoded, not batch-split, not quarantined
    # The content_type-aware pipeline carries these bytes NUL-safely via mfb64 (ADR 0028); prove the
    # EXACT bytes round-trip back out of a RawMessage.
    assert RawMessage.from_bytes(received[0], "binary").raw_bytes == pdf
    assert not (inbox / ".error" / "doc.pdf").exists()  # NOT quarantined
    assert (inbox / ".processed" / "doc.pdf").exists()  # processed like any received message


async def test_file_source_sniffs_x12_and_quarantines_non_isa(tmp_path: Path) -> None:
    # The accept-time sniff is PER content_type, not hl7v2-only: an x12 inbound sniffs the ISA magic
    # (ASVS 5.2.2). A conformant ISA drop (no MSH header, by X12 design) flows to the pipeline verbatim;
    # a non-ISA body on the SAME x12 inbound is quarantined — proving the x12 sniff is genuinely ACTIVE.
    # (This replaces the stale "sniff disabled for non-hl7" test, whose ISA payload passed because it
    # MATCHED the x12 magic, not because the sniff was off.)
    inbox = tmp_path / "in"
    inbox.mkdir()
    x12 = b"ISA*00*          *00*          *ZZ*SENDER\r"
    (inbox / "claim.hl7").write_bytes(x12)
    (inbox / "bogus.hl7").write_bytes(b"%PDF-1.7 not an x12 interchange")
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    src.content_type = ContentType.X12  # x12 inbound → ISA sniff stays ON
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: received == [x12] and (inbox / ".error" / "bogus.hl7").exists())
    finally:
        await src.stop()
        await task
    assert received == [x12]  # conformant ISA delivered verbatim (magic matched)
    assert not (inbox / ".error" / "claim.hl7").exists()  # NOT quarantined
    assert (inbox / ".error" / "bogus.hl7").exists()  # non-ISA quarantined (sniff is active)


async def test_file_source_quarantines_non_fhir_when_content_type_fhir(tmp_path: Path) -> None:
    # ASVS 5.2.2 (WP245 follow-up): a File inbound declared content_type=fhir runs the JSON magic sniff
    # (FHIR is HL7 FHIR JSON) — a PDF that merely matches the glob is quarantined to .error before its
    # bytes reach the pipeline, while a JSON-shaped FHIR resource flows through.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "bad.fhir").write_bytes(b"%PDF-1.7\r\nnot a fhir resource")
    resource = b'{"resourceType":"Patient","id":"1"}'
    (inbox / "ok.fhir").write_bytes(resource)
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.fhir", "poll_seconds": 0.01},
        )
    )
    src.content_type = ContentType.FHIR  # fhir inbound → JSON {/[ sniff ON
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: received == [resource] and (inbox / ".error" / "bad.fhir").exists())
    finally:
        await src.stop()
        await task
    assert received == [resource]  # JSON-shaped FHIR delivered
    assert (inbox / ".error" / "bad.fhir").exists()  # the PDF quarantined before the pipeline
    assert not (inbox / ".error" / "ok.fhir").exists()


async def test_file_source_quarantines_non_hl7_when_content_type_hl7v2(tmp_path: Path) -> None:
    # The hl7v2 guard is INTACT: a File inbound declared content_type=hl7v2 still runs the MSH/FHS/BHS
    # header sniff and quarantines a binary/non-HL7 drop to .error before its bytes reach the pipeline
    # (ASVS 5.2.2) — exactly as before the content_type gate was added.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "bad.hl7").write_bytes(b"\x00\x01not an hl7 message")
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    src.content_type = ContentType.HL7V2  # hl7v2 inbound → sniff stays ON
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: (inbox / ".error" / "bad.hl7").exists())
    finally:
        await src.stop()
        await task
    assert received == []  # quarantined before reaching the pipeline
    assert (inbox / ".error" / "bad.hl7").exists()
    assert not (inbox / ".processed" / "bad.hl7").exists()


# --- file source: leader-gating (Track B Step 4b) ----------------------------


def test_file_source_declares_polls_shared_resource() -> None:
    # A directory is a shared external resource — the runner reads this flag to know the intake is
    # leader-gated (only the cluster leader polls it).
    assert FileSource.polls_shared_resource is True


async def test_file_source_skips_scan_when_gate_false(tmp_path: Path) -> None:
    # A follower (leader_gate() -> False) must NOT read or move a dropped file across a poll tick:
    # the directory is shared, so a non-leader ingesting it would duplicate intake.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler, leader_gate=lambda: False))
    try:
        # Give the loop several poll intervals; a follower must scan none of them.
        await asyncio.sleep(0.1)
    finally:
        await src.stop()
        await task
    assert received == []  # never delivered
    assert (inbox / "msg1.hl7").exists()  # file untouched (not read, not moved)
    assert not (inbox / ".processed" / "msg1.hl7").exists()


async def test_file_source_processes_when_gate_true(tmp_path: Path) -> None:
    # A leader (leader_gate() -> True) processes exactly as the un-gated default does.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler, leader_gate=lambda: True))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]
    assert (inbox / ".processed" / "msg1.hl7").exists()


async def test_file_source_resumes_when_gate_flips_to_true(tmp_path: Path) -> None:
    # Reactive-by-polling: with the gate initially False the file is left untouched; once the gate
    # flips True (this node became leader) the very next tick scans it — no restart needed.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []
    leader = {"on": False}

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler, leader_gate=lambda: leader["on"]))
    try:
        await asyncio.sleep(0.05)
        assert received == []  # still a follower — nothing ingested
        leader["on"] = True  # this node wins leadership
        await _until(lambda: bool(received))  # the next tick scans it
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]
    assert (inbox / ".processed" / "msg1.hl7").exists()


# --- listen sources accept (and ignore) the leader_gate ----------------------


async def test_mllp_source_accepts_and_ignores_leader_gate() -> None:
    # A listen source runs on every node; passing leader_gate must be accepted without error and have
    # no effect (it still binds + serves). Even a False gate does not stop it listening.
    src = MLLPSource(Source(type=ConnectorType.MLLP, settings={"port": 0}))
    await src.start(_noop_handler, leader_gate=lambda: False)
    try:
        assert src.sockport > 0  # bound + listening despite a False gate
        assert MLLPSource.polls_shared_resource is False  # a listen source is not a poll source
    finally:
        await src.stop()


async def test_tcp_source_accepts_and_ignores_leader_gate() -> None:
    from messagefoundry.transports.tcp import TcpSource

    src = TcpSource(Source(type=ConnectorType.TCP, settings={"port": 0, "framing": "stx_etx"}))
    await src.start(_noop_handler, leader_gate=lambda: False)
    try:
        assert src.sockport > 0  # bound + listening despite a False gate
        assert TcpSource.polls_shared_resource is False
    finally:
        await src.stop()


# --- helpers -----------------------------------------------------------------


async def _noop_handler(raw: bytes) -> str | None:
    return None


async def _until(cond, timeout: float = 2.0) -> None:
    """Poll ``cond`` until true or timeout (avoids fixed sleeps in async tests)."""
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")
