# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2814: a FILE or REMOTEFILE write failure never carries the name rendered from the
message into the error text.

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
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.config.models import ConnectorType, Destination, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, Registry
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.redaction import safe_exc, safe_name
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    NegativeAckError,
    build_destination,
)
from messagefoundry.transports.file import FileDestination, _Replaced
from messagefoundry.transports.remotefile import _RemoteError
from tests._refusal_log_capture import record_texts
from tests.test_remotefile_transport import _dest, _FakeClient

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
    assert not [r for r in caplog.records if any(MRN in t for t in record_texts(r))]


class _EchoingClient(_FakeClient):
    """A server whose refusal at ``step`` quotes the paths it names, as an FTP 550 reply can. The
    rename reply quotes the name lower-cased, as a case-insensitive server's stored case can."""

    def __init__(self, step: str, *, permanent: bool) -> None:
        super().__init__()
        self.step = step
        self.permanent = permanent

    def _refuse(self, quoted: str) -> _RemoteError:
        return _RemoteError(
            f"FTP rejected the operation: 550 {quoted}: Permission denied",
            permanent=self.permanent,
            credential_fault=self.permanent,
        )

    def store(self, path: str, data: bytes) -> None:
        self.ops.append(("store", path))
        if self.step == "store":
            raise self._refuse(path)
        self.files[path] = data

    def rename(self, src: str, dst: str) -> None:
        self.ops.append(("rename", dst))
        raise self._refuse(f"{src} -> {dst.lower()}")

    def publish(self, src: str, candidates: Sequence[str]) -> str | None:
        self.ops.append(("publish", candidates[1]))
        raise self._refuse(f"{src} -> {candidates[0]}, {candidates[1]}")


@pytest.mark.parametrize("permanent", [False, True], ids=["transient", "permanent"])
@pytest.mark.parametrize("step", ["store", "publish", "rename"])
async def test_the_remotefile_error_text_holds_no_rendered_name(
    monkeypatch: pytest.MonkeyPatch, step: str, permanent: bool
) -> None:
    client = _EchoingClient(step, permanent=permanent)
    dest = _dest(monkeypatch, client, filename=TEMPLATE, overwrite=step == "rename")
    with pytest.raises(DeliveryError) as raised:
        await dest.send(BODY)
    (quoted,) = [path for op, path in client.ops if op == step]
    assert MRN in quoted  # the reply quoted a path that held the name
    text = str(raised.value)
    assert text.startswith("FTP rejected the operation: 550 ") and "Permission denied" in text
    assert MRN not in text.upper() and MRN not in safe_exc(raised.value).upper()
    # The unscrubbed reply is not chained, so a traceback of the delivery error cannot print it.
    assert MRN not in _traceback(raised.value).upper()
    # The markers survive the scrub: a permanent credential refusal still stops the lane.
    assert isinstance(raised.value, NegativeAckError) is permanent
    if permanent:
        assert cast(NegativeAckError, raised.value).credential_fault


def test_without_names_keeps_text_that_names_no_file() -> None:
    exc = _RemoteError("FTP operation failed: timed out", permanent=False, config_fault=True)
    scrubbed = exc.without_names([f"/in/{NAME}"])
    assert str(scrubbed) == str(exc) and scrubbed.config_fault and not scrubbed.permanent


def test_without_names_swaps_each_name_once_in_one_pass() -> None:
    # A shorter name must not be matched again inside the label a longer one became, and an echo
    # in another case takes the label of the name as rendered.
    names = ["/in/1.hl7", "/in/1-1.hl7", "/in/11.hl7"]
    exc = _RemoteError("550 /in/1-1.hl7 and /in/1.HL7", permanent=True)
    assert str(exc.without_names(names)) == (
        f"550 /in/{safe_name('1-1.hl7')} and /in/{safe_name('1.hl7')}"
    )


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
