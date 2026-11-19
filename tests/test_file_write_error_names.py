# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2814: a FILE write failure never carries the name rendered from the message into the
error text. The REMOTEFILE half is in ``tests/test_remotefile_error_reply_text.py`` (BACKLOG #5026).

The template here names the file after PID-3.1 and PID-5.1, so the rendered name holds a synthetic
MRN. ``test_the_runner_stores_and_alerts_no_rendered_name`` checks that it reaches none of the
outbox row's ``last_error``, the stored ``connection_lost`` event, the ``connection_error`` alert
detail and the general log. The error text goes to at least one more place it does not read: the
message event row ``mark_failed`` writes. That test forces the failure with a ``PermissionError`` it
raises itself; ``test_a_real_os_error_leaves_no_rendered_name`` uses a real OS error instead: a
directory sits at the target name, so the publish's replace fails, and the OS quotes the path,
name included. Synthetic data only (CLAUDE.md section 9).
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import traceback
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.config.models import ConnectorType, Destination, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, Registry
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.redaction import safe_exc
from messagefoundry.store import MessageStore
from messagefoundry.transports import wincred
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    build_destination,
)
from messagefoundry.transports.file import FileDestination, _Replaced
from tests._log_absence import assert_capture_sees
from tests._refusal_log_capture import record_texts

MRN = "SYN900002"
OUT = "OB_FILE_ADT"
TEMPLATE = "{PID-3.1}_{PID-5.1}.hl7"
NAME = f"{MRN}_SYNTHETIC.hl7"
BODY = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    f"PID|1||{MRN}^^^H^MR||SYNTHETIC^PAT\r"
)


class _Sink(LoggingAlertSink):
    """The default sink, which also records the connection_error alert's detail."""

    def __init__(self) -> None:
        self.details: list[str | None] = []

    def connection_error(
        self, name: str, *, kind: str, detail: str | None = None, error_class: str | None = None
    ) -> None:
        self.details.append(detail)
        super().connection_error(name, kind=kind, detail=detail, error_class=error_class)


def _file_destination(directory: Path) -> FileDestination:
    spec = ConnectionSpec(
        ConnectorType.FILE, {"directory": str(directory), "filename": TEMPLATE, "overwrite": True}
    )
    d = build_destination(
        Destination(name=OUT, type=ConnectorType.FILE, settings=spec.settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, FileDestination)
    return d


def _blocked(tmp_path: Path) -> Path:
    """A destination directory where the rendered name is taken by a directory, so a replace onto
    it fails with a real OS error that quotes the target path."""
    out = tmp_path / "out"
    (out / NAME).mkdir(parents=True)
    return out


def _traceback(exc: BaseException) -> str:
    """Everything a log line with ``exc_info`` would print for ``exc``, its chain included."""
    return "".join(traceback.format_exception(exc))


async def test_a_real_os_error_leaves_no_rendered_name(tmp_path: Path) -> None:
    out = _blocked(tmp_path)
    dest = _file_destination(out)
    # Positive control: the OS error itself quotes the name, so this test can see a leak.
    with pytest.raises(OSError) as os_error:
        dest._write_as(NAME, out / NAME, BODY)
    assert MRN in str(os_error.value)
    with pytest.raises(DeliveryError) as raised:
        await dest.send(BODY)
    text = str(raised.value)
    assert text.startswith("file write failed: ") and type(os_error.value).__name__ in text
    assert MRN not in text and MRN not in safe_exc(raised.value)
    # The OS error is not chained, so a traceback of the delivery error cannot print it.
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    assert MRN not in _traceback(raised.value)


def _refuse_replace(monkeypatch: pytest.MonkeyPatch) -> list[OSError]:
    """Fail the publish step's replace with the error a share that refuses the write raises,
    quoting the target. The directory is relative, so the text stays short: with an absolute temp
    path the store's 200-character bound cut the name off on the unfixed code, which then passed.
    ``monkeypatch`` is a context the caller closes right after the delivery, so nothing else in the
    test meets the patched ``os.replace``."""
    raised: list[OSError] = []

    def refuse(src: object, dst: object) -> None:
        raised.append(PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(dst)))
        raise raised[-1]

    monkeypatch.setattr(os, "replace", refuse)  # the module file.py calls
    return raised


async def test_the_runner_stores_and_alerts_no_rendered_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    monkeypatch.chdir(tmp_path)
    out = Path("out")
    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        sink = _Sink()
        runner = RegistryRunner(
            Registry(), store, alert_sink=sink, egress=EgressSettings(deny_by_default=False)
        )
        runner._destinations[OUT] = cast(DestinationConnector, _file_destination(out))
        runner._retry[OUT] = RetryPolicy(max_attempts=5)
        runner._simulate[OUT] = False
        runner._conn_event_q = asyncio.Queue(maxsize=10)  # normally created in start()
        mid = await store.enqueue_message(
            channel_id="c1", raw=BODY, deliveries=[(OUT, BODY)], now=100.0
        )
        item = await store.claim_next_fifo(OUT, now=1e12)
        assert item is not None
        with monkeypatch.context() as patch:
            forced = _refuse_replace(patch)
            await runner._process_delivery_item(OUT, item)

        (row,) = await store.outbox_for(mid)
        events = []
        while not runner._conn_event_q.empty():
            events.append(runner._conn_event_q.get_nowait())
        await store.record_connection_events(events)
        (event,) = await store.list_connection_events(connection=OUT, allowed_channels=None)
    finally:
        await store.close()

    # Positive control: the forced error quoted the name, and the text the destination built from
    # it before this fix kept the name through the store's scrub and bound.
    (cause,) = forced
    assert MRN in safe_exc(DeliveryError(f"file write failed: {cause}"))
    # Each copy is present, so an absent identifier is a scrubbed text and not a missing one.
    assert row["last_error"] and "file write failed" in row["last_error"]
    assert event.kind == "connection_lost" and event.reason
    (detail,) = sink.details
    assert detail
    for text in (row["last_error"], event.reason, detail):
        assert MRN not in text
    assert_capture_sees(caplog, "messagefoundry")
    assert not [r for r in caplog.records if any(MRN in t for t in record_texts(r))]


@pytest.mark.parametrize(
    ("raised", "kept"),
    [
        (OSError(f"share refused out/{MRN}_SYNTHETIC-1.hl7"), "file write failed: OSError"),
        (_Replaced("not the file that was read"), "_Replaced: not the file that was read"),
    ],
    ids=["message-only", "own-fixed-message"],
)
async def test_an_error_with_no_errno_keeps_only_what_names_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raised: OSError, kept: str
) -> None:
    # A message-only OSError can quote a bumped name, so only its type is kept; this module's own
    # refusals carry fixed words, so their message is kept.
    def refuse(src: object, dst: object) -> None:
        raise raised

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(DeliveryError) as caught:
        await _file_destination(tmp_path / "out").send(BODY)
    assert kept in str(caught.value) and MRN not in _traceback(caught.value)


async def test_send_reports_an_error_before_the_name_by_errno_and_directory(tmp_path: Path) -> None:
    # BACKLOG #5302: a regular file sits at the configured directory, so making it fails before a
    # name is rendered. send's own arm reports it by type, errno and the configured directory.
    out = tmp_path / "out"
    out.write_text("not a directory", encoding="utf-8")
    with pytest.raises(DeliveryError) as raised:
        await _file_destination(out).send(BODY)
    text = str(raised.value)
    assert text.startswith(f"file write failed: FileExistsError: [Errno {errno.EEXIST}]")
    assert text.endswith(f"(directory {out})")
    # The raw OS error is not chained, so a traceback of the delivery error cannot print it.
    assert raised.value.__cause__ is None and raised.value.__context__ is None


async def test_send_reports_a_missing_validated_directory_in_words(tmp_path: Path) -> None:
    out = tmp_path / "out"
    dest = _file_destination(out)
    dest.validate_directory = True
    with pytest.raises(DeliveryError) as raised:
        await dest.send(BODY)
    assert str(raised.value) == (
        f"file write failed: FileNotFoundError: [Errno {errno.ENOENT}] not found, and "
        f"validate_directory never creates it (directory {out})"
    )
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    # The directory survives safe_exc's length bound for a share path of this length (63 characters).
    long_out = Path(r"\\hl7-share01.corp.example\interfaces\outbound\OB_ACME_ADT\drop")
    assert str(long_out) in safe_exc(
        DeliveryError(str(raised.value).replace(str(out), str(long_out)))
    )


async def test_a_validated_directory_that_is_a_file_is_not_called_missing(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.write_text("not a directory", encoding="utf-8")
    dest = _file_destination(out)
    dest.validate_directory = True
    with pytest.raises(DeliveryError) as raised:
        await dest.send(BODY)
    assert str(raised.value) == (
        f"file write failed: NotADirectoryError: [Errno {errno.ENOTDIR}] not a directory "
        f"(directory {out})"
    )


async def test_a_refused_validated_directory_is_reported_by_its_own_errno(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # is_dir() is False for a refused directory too; the text names the refusal, not "missing".
    out = tmp_path / "out"
    out.mkdir()
    dest = _file_destination(out)
    dest.validate_directory = True
    real_stat = Path.stat

    def refuse(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        if self == out:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(self))
        return real_stat(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "stat", refuse)
    with pytest.raises(DeliveryError) as raised:
        await dest.send(BODY)
    text = str(raised.value)
    assert text == (
        f"file write failed: PermissionError: [Errno {errno.EACCES}] "
        f"{os.strerror(errno.EACCES)} (directory {out})"
    )
    assert "not found" not in text


@pytest.mark.parametrize(
    ("raised", "kept"),
    [
        (
            PermissionError(errno.EACCES, os.strerror(errno.EACCES), f"out/{MRN}_SYNTHETIC.hl7"),
            f"PermissionError: [Errno {errno.EACCES}] {os.strerror(errno.EACCES)} (directory",
        ),
        (
            OSError(f"share refused out/{MRN}_SYNTHETIC-1.hl7"),
            "file write failed: OSError (directory",
        ),
        (
            wincred.CredentialLogonError(
                "alternate Windows credential logon failed (win32 error 5)"
            ),
            "CredentialLogonError: alternate Windows credential logon failed (win32 error 5)",
        ),
    ],
    ids=["errno", "message-only", "credential-logon"],
)
async def test_send_never_carries_a_raw_os_error_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raised: OSError, kept: str
) -> None:
    # BACKLOG #5302: whatever path an OS error reaching send's arm quotes, only its type, errno and
    # OS text reach the delivery error, its traceback and the stored text. A message-only error
    # keeps its type alone, except a credential logon error, whose words are fixed.
    dest = _file_destination(tmp_path / "out")

    def refuse(payload: str) -> None:
        raise raised

    monkeypatch.setattr(dest, "_write", refuse)
    with pytest.raises(DeliveryError) as caught:
        await dest.send(BODY)
    text = str(caught.value)
    assert kept in text and text.endswith(f"(directory {tmp_path / 'out'})")
    assert MRN not in text and MRN not in _traceback(caught.value)
    assert MRN not in safe_exc(caught.value)


def _share_not_found() -> FileNotFoundError:
    """What a stat of an unreachable UNC share raises on Windows (Win32 53), built on any platform."""
    exc = FileNotFoundError(errno.ENOENT, "The network path was not found", "out")
    exc.winerror = 53  # type: ignore[attr-defined,unused-ignore]
    return exc


@pytest.mark.parametrize(
    ("raised", "kept"),
    [
        (_share_not_found(), f"[Errno {errno.ENOENT}] The network path was not found"),
        (ValueError("embedded null character in path"), "[Errno {}] not a valid path"),
    ],
    ids=["share-not-found", "nul"],
)
async def test_a_validated_directory_stat_fault_is_not_called_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raised: Exception, kept: str
) -> None:
    # A Win32 share fault surfaces as a FileNotFoundError too, and keeps the OS's own words; a path
    # the OS cannot take is a ValueError, which still leaves send as a DeliveryError.
    out = tmp_path / "out"
    dest = _file_destination(out)
    dest.validate_directory = True
    real_stat = Path.stat

    def refuse(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        if self == out:
            raise raised
        return real_stat(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "stat", refuse)
    with pytest.raises(DeliveryError) as caught:
        await dest.send(BODY)
    text = str(caught.value)
    assert kept.format(errno.EINVAL) in text and "not found, and" not in text
