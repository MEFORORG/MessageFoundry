# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The streaming document detach and the egress re-attach keep their size-scaled work off the event
loop (vault BACKLOG #2757).

Both paths parse the whole body, scan or splice each document and re-encode, and the detach also
hashes and seals every chunk. On the loop that stalled every listener, worker and the API in
proportion to the document. These tests record which thread each of those steps ran on, which pins
the behaviour without a timing assertion; the stall itself was measured once and is recorded beside
the code. Synthetic HL7 only.
"""

from __future__ import annotations

import base64
import threading
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Validation
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.binary import is_doc_ref
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "offloop.db")
    yield s
    await s.close()


def _doc(fill: bytes, nbytes: int) -> str:
    return base64.b64encode(fill * nbytes).decode("ascii")


def _hl7(first: str, second: str) -> str:
    """An MDM^T02 carrying two OBX-5 ED Base64 documents, so the per-document loop runs twice."""
    return (
        "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|MSGID001|P|2.5\r"
        "PID|1||MRN123^^^FAC||DOE^JOHN\r"
        f"OBX|1|ED|PDF^Report||^Application^PDF^Base64^{first}||||||F\r"
        f"OBX|2|ED|PDF^Report||^Application^PDF^Base64^{second}||||||F\r"
    )


def _runner(store: MessageStore) -> tuple[RegistryRunner, InboundConnection]:
    ic = InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
        router="r",
        ack_mode=AckMode.ORIGINAL,
        content_type=ContentType.HL7V2,
        validation=Validation(strict=False),
        stream_threshold_bytes=500,
    )
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])
    return RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False)), ic


class _Threads:
    """Which threads each wrapped step ran on, by step name."""

    def __init__(self) -> None:
        self.seen: dict[str, set[int]] = defaultdict(set)

    def wrap(self, name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        def call(*args: Any, **kwargs: Any) -> Any:
            self.seen[name].add(threading.get_ident())
            return fn(*args, **kwargs)

        return call


def _watch(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> _Threads:
    threads = _Threads()
    parse = Message.parse
    monkeypatch.setattr(Message, "parse", threads.wrap("parse", parse))
    for name in ("field", "set", "encode"):
        monkeypatch.setattr(Message, name, threads.wrap(name, getattr(Message, name)))
    monkeypatch.setattr(store._cipher, "encrypt", threads.wrap("seal", store._cipher.encrypt))
    return threads


async def test_the_detach_parses_scans_seals_and_encodes_off_the_loop(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store)
    text = _hl7(_doc(b"A", 3000), _doc(b"B", 3000))
    threads = _watch(monkeypatch, store)
    loop_thread = threading.get_ident()

    skeleton, refs = await runner._detach_documents(ic, text)

    assert len(refs) == 2
    assert set(threads.seen) == {"parse", "field", "set", "encode", "seal"}
    for step, idents in threads.seen.items():
        assert loop_thread not in idents, f"{step} ran on the event loop"
    monkeypatch.undo()
    for occ in (1, 2):
        assert is_doc_ref(Message.parse(skeleton).field("OBX-5.5", occurrence=occ) or "")


async def test_the_reattach_parses_splices_and_encodes_off_the_loop(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store)
    text = _hl7(_doc(b"C", 3000), _doc(b"D", 3000))
    skeleton, _ = await runner._detach_documents(ic, text)
    threads = _watch(monkeypatch, store)
    loop_thread = threading.get_ident()

    hydrated = await runner._hydrate_payload(skeleton)

    assert hydrated == text  # byte-for-byte, as before
    assert {"parse", "field", "set", "encode"} <= set(threads.seen)
    for step, idents in threads.seen.items():
        assert loop_thread not in idents, f"{step} ran on the event loop"


async def test_a_body_with_no_document_is_still_returned_unchanged(store: MessageStore) -> None:
    """The no-document arms are unchanged: no attachment, and the body comes back byte-identical."""
    runner, ic = _runner(store)
    text = "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||ADT^A01|M2|P|2.5\rPID|1||" + "X" * 900 + "\r"
    assert await runner._detach_documents(ic, text) == (text, [])
    marker_outside_obx = text.replace("PID|1||", "PID|1||mfdoc:v1:ref:")
    assert await runner._hydrate_payload(marker_outside_obx) == marker_outside_obx
