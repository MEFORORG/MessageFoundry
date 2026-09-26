# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1594: an empty segment line must not escape the pre-ACK peek.

A sender that ends segments with ``CRLF`` and adds a blank line produces ``\\r\\r`` once line endings
are normalised. Before the fix, ``Peek.parse`` accepted that, then ``peek.control_id``,
``summarize(peek)`` and ``build_ack`` each raised ``IndexError`` on both parser backends. The
listener caught only ``HL7PeekError``, so the message got no row, no ACK and no NAK, and the MLLP
server dropped the connection. That broke the count-and-log invariant (CLAUDE.md section 2).

**The fix is tolerant, as the ledger row asks.** The peek drops empty lines before either backend
parses, so the message is ACKed ``AA`` and committed ``RECEIVED`` with its routing fields. The stored
raw keeps the blank line: the engine records what the sender sent. A runner guard and a ``build_ack``
guard back that up, so a field read that faults for any other reason still records ``ERROR`` and
NAKs ``AR``. Those two are driven here by injecting the fault, because no wire input reaches them
once the parser is fixed.

Synthetic HL7 only (CLAUDE.md section 9).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import NoReturn

import hl7
import pytest

import messagefoundry.pipeline.wiring_runner as wiring_runner
from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing._backend import backend
from messagefoundry.parsing.peek import Peek, normalize
from messagefoundry.parsing.summary import summarize
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports.mllp import build_ack

_INBOUND = "IB_HL7"
_HEADER = "MSH|^~\\&|SEND|SFAC|RECV|RFAC|20260101||ADT^A01|CTRL1594|P|2.5.1"
_PID = "PID|1||100^^^H^MR||DOE^JANE"

#: The two measured shapes from the ledger row, plus a control with no blank line.
_SHAPES = {
    "cr-cr": f"{_HEADER}\r\r{_PID}\r",
    "crlf-crlf": f"{_HEADER}\r\n\r\n{_PID}\r\n",
    "control": f"{_HEADER}\r{_PID}\r",
}
_BACKENDS = pytest.mark.parametrize("builtin", [True, False], ids=["builtins", "python-hl7"])


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


@pytest.fixture
def runner(store: MessageStore) -> tuple[RegistryRunner, InboundConnection]:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name=_INBOUND,
            spec=ConnectionSpec(ConnectorType.MLLP, {}),
            router="r",
            content_type=ContentType.HL7V2,
        )
    )
    reg.add_router("r", lambda m: [])  # no worker runs; routing is never reached
    return RegistryRunner(reg, store), reg.inbound[_INBOUND]


async def _rows(store: MessageStore) -> list[dict[str, object]]:
    cur = await store._db.execute("SELECT status, raw, control_id, summary, error FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def _queue_depth(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM queue")
    row = await cur.fetchone()
    assert row is not None
    return int(row["n"])


# --- the peek itself ------------------------------------------------------------------------------


@_BACKENDS
@pytest.mark.parametrize("shape", list(_SHAPES), ids=list(_SHAPES))
def test_the_peek_reads_every_routing_field_across_a_blank_segment(
    builtin: bool, shape: str
) -> None:
    with backend(builtin=builtin):
        peek = Peek.parse(_SHAPES[shape])
        assert peek.control_id == "CTRL1594"
        assert peek.routing()["message_type"] == "ADT^A01"
        assert peek.field("PID-3.1") == "100"
        assert summarize(peek)  # the pre-ACK summary no longer raises
        assert peek.segments() == ["MSH", "PID"]
        # The peek drops the empty line for its own parse only; its raw is what was received.
        assert peek.raw == normalize(_SHAPES[shape])
        ack = build_ack(_SHAPES[shape])
        assert "MSA|AA|CTRL1594" in ack


@_BACKENDS
def test_a_field_that_only_starts_with_the_separator_is_not_a_blank_segment(builtin: bool) -> None:
    # ``|stray`` has an empty id on the built-ins but is not an empty line. python-hl7 reads past it,
    # and the built-ins used to raise on it anyway. Both must read it now.
    raw = f"{_HEADER}\r|stray\r{_PID}\r"
    with backend(builtin=builtin):
        assert Peek.parse(raw).control_id == "CTRL1594"


def test_the_python_hl7_backend_maps_a_malformed_rich_text_count_to_none() -> None:
    # DELTA-02's fallback half. The expansion budget refuses this body at Peek.parse, so the only way
    # to reach the fallback's extractor with it is to build the Peek directly, as a fallback after an
    # internal built-ins fault would.
    text = f"{_HEADER}\rPID|1||100^^^H^MR||A\\.inX\\B^JANE\r"
    with pytest.raises(ValueError):
        hl7.parse(text).extract_field("PID", 1, 5, 1, 1, 1)  # the raw library still raises
    peek = Peek(message=hl7.parse(text), raw=text)
    assert peek.field("PID-5.1") is None
    assert peek.field("PID-5.2") == "JANE"


# --- the listener, end to end ---------------------------------------------------------------------


@_BACKENDS
@pytest.mark.parametrize("shape", list(_SHAPES), ids=list(_SHAPES))
async def test_the_mllp_listener_acks_and_commits_a_message_with_a_blank_segment(
    builtin: bool,
    shape: str,
    runner: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
) -> None:
    rr, ic = runner
    with backend(builtin=builtin):
        ack = await rr._handle_inbound(ic, _SHAPES[shape].encode())

    assert ack is not None and "MSA|AA|CTRL1594" in ack
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.RECEIVED.value
    assert rows[0]["control_id"] == "CTRL1594"
    assert rows[0]["summary"]
    # The stored raw is the received text, blank line and all.
    assert rows[0]["raw"] == normalize(_SHAPES[shape])
    assert await _queue_depth(store) == 1


@_BACKENDS
@pytest.mark.parametrize("shape", ["cr-cr", "crlf-crlf"])
async def test_the_http_listener_commits_a_message_with_a_blank_segment(
    builtin: bool,
    shape: str,
    runner: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
) -> None:
    rr, ic = runner
    with backend(builtin=builtin):
        mid = await rr._handle_inbound_http(ic, _SHAPES[shape].encode())

    assert isinstance(mid, str) and mid
    rows = await _rows(store)
    assert len(rows) == 1 and rows[0]["status"] == MessageStatus.RECEIVED.value
    assert rows[0]["control_id"] == "CTRL1594"


# --- defence in depth: a faulting field read on an accepted peek ----------------------------------


def _faulting_control_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``Peek.control_id`` raise, standing in for any parser fault the fix did not foresee."""

    def _raise(_self: Peek) -> NoReturn:
        raise IndexError("injected peek fault")

    monkeypatch.setattr(Peek, "control_id", property(_raise))


async def test_a_faulting_peek_read_records_error_and_naks_ar_on_mllp(
    runner: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rr, ic = runner
    _faulting_control_id(monkeypatch)

    ack = await rr._handle_inbound(ic, _SHAPES["control"].encode())

    # build_ack reads control_id too, so this also proves it degrades instead of raising.
    assert ack is not None and "MSA|AR" in ack
    assert "peek read failed" in ack
    assert "injected" not in ack  # the fault's own text never reaches the sender
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert rows[0]["error"] == "parse error: peek read failed (IndexError)"
    assert await _queue_depth(store) == 0  # recorded before any ingress row


async def test_a_faulting_peek_read_records_error_on_http(
    runner: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rr, ic = runner
    _faulting_control_id(monkeypatch)

    mid = await rr._handle_inbound_http(ic, _SHAPES["control"].encode())

    assert mid is None
    rows = await _rows(store)
    assert len(rows) == 1 and rows[0]["status"] == MessageStatus.ERROR.value
    assert await _queue_depth(store) == 0


def test_a_faulting_peek_read_marks_a_loopback_peek_failed(
    runner: tuple[RegistryRunner, InboundConnection], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, ic = runner
    assert wiring_runner._peek_for_loopback(ic, _SHAPES["control"])[3] is False  # control
    _faulting_control_id(monkeypatch)
    assert wiring_runner._peek_for_loopback(ic, _SHAPES["control"]) == (None, None, None, True)


def test_build_ack_degrades_to_defaults_when_a_peek_read_faults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _faulting_control_id(monkeypatch)
    ack = build_ack(_SHAPES["control"], code="AR", text="x", timestamp="20260101")
    assert ack == "MSH|^~\\&|||||20260101||ACK||P|2.5.1\rMSA|AR||x\r"
