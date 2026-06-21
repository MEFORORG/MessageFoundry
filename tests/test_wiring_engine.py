# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""End-to-end: RegistryRunner runs inbound → Router → Handler(s) → outbox → delivery.

Real file connectors over a temp dir + a real store; drives the runner and polls for the
observable outcome (file written, store dispositions)."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import (
    BuildupThreshold,
    ConnectorType,
    ContentType,
    Destination,
    InternalErrorPolicy,
    RetryPolicy,
    Validation,
)
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
)
from messagefoundry.logging_setup import ControlCharScrubFilter, RedactionFilter
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports import DeliveryError, NegativeAckError
from messagefoundry.transports.mllp import MLLPDestination

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(inbox: Path, outdir: Path, route, handlers: dict) -> Registry:  # type: ignore[no-untyped-def]
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", route)
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    return reg


def _inbound_registry(encoding: str) -> Registry:
    """Minimal registry: one MLLP inbound carrying ``encoding``, a router that routes nowhere."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "mllp_in",
            ConnectionSpec(
                ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0, "encoding": encoding}
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


async def test_inbound_decodes_with_connection_encoding(store: MessageStore) -> None:
    # A latin-1 feed ('ü' = 0xFC) on a connection declaring latin-1 must decode correctly at the
    # listener (before the ingress commit), not be corrupted to U+FFFD in the stored raw (review H-3).
    # Staged pipeline: the listener decodes + persists to the ingress stage (status RECEIVED) and
    # ACKs; routing happens later in the ingress worker (not started here).
    reg = _inbound_registry("latin-1")
    runner = RegistryRunner(reg, store)
    raw = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||100||Müller^X\r".encode("latin-1")
    await runner._handle_inbound(reg.inbound["mllp_in"], raw)
    cur = await store._db.execute("SELECT status, raw FROM messages")
    row = await cur.fetchone()
    assert row["status"] == MessageStatus.RECEIVED.value  # committed at ingress, awaiting routing
    assert "Müller" in row["raw"]  # decoded with the declared charset, not mangled


async def test_non_hl7_inbound_commits_raw_without_parsing(store: MessageStore) -> None:
    # ADR 0004: a non-HL7 (content_type=json) inbound SKIPS HL7 peek/validate/ACK — the body is
    # committed verbatim at ingress (RECEIVED) with message_type=content_type and control_id/summary
    # null, and no HL7 ACK is returned. A body that isn't valid HL7 must NOT be rejected.
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "json_in",
            ConnectionSpec(ConnectorType.FILE, {"directory": "x"}),
            router="r",
            content_type=ContentType.JSON,
        )
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store)
    body = b'{"mrn": "100", "note": "not HL7 at all"}'
    ack = await runner._handle_inbound(reg.inbound["json_in"], body)
    assert ack is None  # the non-HL7 source owns its own receive-time response; no HL7 ACK here
    cur = await store._db.execute(
        "SELECT status, raw, message_type, control_id, summary FROM messages"
    )
    row = await cur.fetchone()
    assert row["status"] == MessageStatus.RECEIVED.value  # accepted + committed at ingress
    assert row["raw"] == body.decode()  # verbatim — no \r-normalization or HL7 munging
    assert row["message_type"] == "json"
    assert row["control_id"] is None and row["summary"] is None


async def test_inbound_decode_error_records_error_and_naks(store: MessageStore) -> None:
    # Bytes invalid for the declared encoding → ERROR disposition (exact bytes preserved) + NAK,
    # never a silent U+FFFD substitution (review H-3). Decode failures still NAK SYNCHRONOUSLY at the
    # listener (before the ingress commit) — the partner contract for a malformed message is preserved.
    from messagefoundry.parsing.peek import Peek

    reg = _inbound_registry("utf-8")
    runner = RegistryRunner(reg, store)
    raw = b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||100||bad \xff\xfe utf8\r"
    ack = await runner._handle_inbound(reg.inbound["mllp_in"], raw)
    cur = await store._db.execute("SELECT status, raw, error FROM messages")
    row = await cur.fetchone()
    assert row["status"] == MessageStatus.ERROR.value
    assert "decode error" in (row["error"] or "")
    assert row["raw"].encode("latin-1") == raw  # exact original bytes recoverable
    assert ack is not None and Peek.parse(ack).field("MSA-1") == "AR"  # NAK


async def test_inbound_unknown_handler_dead_letters_at_ingress(
    store: MessageStore, tmp_path: Path
) -> None:
    # A router naming an unregistered handler fails CLOSED: under the staged pipeline the message is
    # ACKed at ingress, then the ingress worker hits the unknown-handler error and dead-letters it
    # (message ERROR), never a silent FILTERED accept-and-drop (review M-7). The failure is post-ACK,
    # so there is no NAK — the ERROR disposition is the operator's signal.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    reg = _registry(
        inbox, outdir, lambda m: ["ghost"], {}
    )  # router names a handler that isn't registered
    runner = await _run(reg, store)
    try:
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()
    assert not (
        outdir / "MSG1.hl7"
    ).exists()  # nothing delivered — failed closed, not accept-and-drop


class _BoomSource:
    """A source whose start() always fails (simulates a port-in-use bind error)."""

    polls_shared_resource = False

    async def start(self, handler: object, *, leader_gate: object = None) -> None:
        raise OSError("address already in use")

    async def stop(self) -> None:
        pass


async def test_start_inbound_does_not_register_on_bind_failure(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # M-9: a failed source.start() must NOT leave a dead source registered (which would make
    # inbound_running() report True and turn a retry into a no-op).
    from messagefoundry.pipeline import wiring_runner as wr

    reg = _inbound_registry("utf-8")
    runner = RegistryRunner(reg, store)
    monkeypatch.setattr(wr, "build_source", lambda cfg: _BoomSource())
    with pytest.raises(OSError):
        await runner.start_inbound("mllp_in")
    assert not runner.inbound_running("mllp_in")
    assert "mllp_in" not in runner._sources


async def test_start_isolates_inbound_bind_failure_and_recovers(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ADR 0031: an inbound bind failure mid-start() is ISOLATED — start() does NOT raise, the engine
    # comes up (degraded), the already-built outbound stays, the failed inbound is reported in
    # degraded_connections() + alerted, and a later restart (once the bind succeeds) clears + binds it.
    from messagefoundry.pipeline import wiring_runner as wr

    reg = _inbound_registry("utf-8")
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}))
    )
    sink = _RecordingAlertSink()
    runner = RegistryRunner(reg, store, alert_sink=sink)
    real_build_source = wr.build_source
    calls = {"n": 0}

    def flaky(cfg: object):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return _BoomSource() if calls["n"] == 1 else real_build_source(cfg)

    monkeypatch.setattr(wr, "build_source", flaky)
    try:
        await runner.start()  # does NOT raise — the bad inbound is isolated
        assert runner.running  # engine is up, just degraded
        assert not runner.inbound_running("mllp_in")  # the failed listener isn't bound
        assert "mllp_in" in runner.degraded_connections()
        reason = runner.connection_failed("mllp_in")
        assert reason and "address already in use" in reason
        assert "out" in runner._destinations  # the healthy outbound still came up
        assert sink.stopped and sink.stopped[0][0] == "mllp_in"  # alerted

        await runner.restart_inbound("mllp_in")  # bind now succeeds → recovers
        assert runner.inbound_running("mllp_in")
        assert runner.connection_failed("mllp_in") is None  # marker cleared
        assert runner.degraded_connections() == {}
    finally:
        await runner.stop()
    assert not runner.running  # stop() is idempotent and leaves a clean slate


async def test_fatal_startup_error_still_unwinds_and_raises(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ADR 0031 backstop: a graph-WIDE startup error (here the live-lookup executor build) is NOT a
    # single connection, so it still unwinds the partial start + re-raises and leaves _running False
    # (M-8) — only per-connection build/bind failures are isolated.
    reg = _inbound_registry("utf-8")
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}))
    )
    runner = RegistryRunner(reg, store)

    def boom():  # type: ignore[no-untyped-def]
        raise RuntimeError("lookup executor build failed")

    monkeypatch.setattr(runner, "_build_lookup_executor", boom)
    with pytest.raises(RuntimeError, match="lookup executor"):
        await runner.start()
    assert not runner.running  # truly fatal → unwound, not degraded
    assert runner._sources == {} and runner._workers == {} and runner._destinations == {}


async def test_per_connection_ops_take_reload_lock(store: MessageStore) -> None:
    # M-10: public per-connection ops serialize against reload()/stop() via _reload_lock.
    reg = _inbound_registry("utf-8")
    runner = RegistryRunner(reg, store)
    await runner._reload_lock.acquire()
    task = asyncio.ensure_future(runner.start_inbound("mllp_in"))
    await asyncio.sleep(0.05)
    assert not task.done()  # blocked on the lock held above
    runner._reload_lock.release()
    await asyncio.wait_for(task, timeout=2.0)
    try:
        assert runner.inbound_running("mllp_in")
    finally:
        await runner.stop()


async def _until_stat(
    store: MessageStore, status: str, expected: int, timeout: float = 3.0
) -> None:
    elapsed = 0.0
    while (await store.stats()).get(status, 0) != expected:
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"{status} != {expected} within timeout")


async def _until_message(
    store: MessageStore, status: str, *, channel_id: str = "file_in", timeout: float = 3.0
) -> None:
    elapsed = 0.0
    while not await store.list_messages(channel_id=channel_id, status=status):
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"no {status} message within timeout")


async def _run(reg: Registry, store: MessageStore) -> RegistryRunner:
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    return runner


async def test_handler_exception_redacts_phi_from_stored_error(
    store: MessageStore, tmp_path: Path
) -> None:
    # A Handler is user code; one that does `raise ValueError(f"...{m}")` would otherwise carry the
    # full HL7 body into the stored last_error + 'dead' event detail. safe_exc redacts it at the
    # wiring-runner chokepoint, keeping the exception type (WP-6c, ASVS 16.2.5 / PHI.md P1-3).
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))  # carries PID|...||DOE^JANE

    def boom(m):  # type: ignore[no-untyped-def]
        raise ValueError(f"cannot transform {m}")  # str(m) is the full HL7 body (PHI)

    reg = _registry(inbox, outdir, lambda m: ["boom"], {"boom": boom})
    runner = await _run(reg, store)
    try:
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()

    mid = (await store.list_messages(channel_id="file_in", status=MessageStatus.ERROR.value))[0][
        "id"
    ]
    cur = await store._db.execute("SELECT last_error FROM queue WHERE message_id=?", (mid,))
    errors = " ".join(store._cipher.decrypt(r["last_error"] or "") for r in await cur.fetchall())
    assert "ValueError" in errors and "handler error" in errors  # type + context kept
    assert "DOE" not in errors and "JANE" not in errors  # PHI redacted out of last_error
    # the 'dead' event detail (built from the same exception) is redacted too
    assert all("DOE" not in (e["detail"] or "") for e in await store.events_for(mid))


# --- Gate #1: PHI must not reach the general LOG (not just the stored error) --------------------

# Distinctive PHI so the absence assertions can't be fooled by timestamps / control-ids.
PHI_ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG9|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||Z9998887^^^H^MR||DOE^JANE\r"
)


def _phi_capture() -> tuple[logging.Handler, list[tuple[int, str]]]:
    """A capture handler wearing the PRODUCTION filter chain (RedactionFilter → ControlCharScrubFilter),
    collecting each record's final formatted line so a test can assert no PHI survives to the log."""
    lines: list[tuple[int, str]] = []

    class _Cap(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append((record.levelno, self.format(record)))

    handler = _Cap(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactionFilter())  # same order configure_logging installs them
    handler.addFilter(ControlCharScrubFilter())
    return handler, lines


def _phi_leaks(lines: list[tuple[int, str]]) -> list[str]:
    return [
        line
        for level, line in lines
        if level >= logging.WARNING and any(tok in line for tok in ("DOE", "JANE", "Z9998887"))
    ]


async def test_runner_refuses_non_loopback_plaintext_mllp(store: MessageStore) -> None:
    # §0 exposed-gate (ADR 0002): starting an MLLP listener bound off-loopback without TLS is refused
    # (the gate fires before the socket binds). TLS-on, loopback, or --allow-insecure-bind would pass.
    reg = Registry()
    reg.add_inbound(
        InboundConnection("mllp_in", ConnectionSpec(ConnectorType.MLLP, {"port": 0}), router="r")
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, inbound_bind_host="0.0.0.0", poll_interval=0.02)
    with pytest.raises(WiringError, match="without TLS"):
        await runner._start_inbound_unsafe("mllp_in")


async def test_pipeline_handler_exception_logs_no_phi(store: MessageStore, tmp_path: Path) -> None:
    # Gate #1 end-to-end: a Handler that raises carrying the full body must not leak the name/MRN into
    # the general log at WARNING+ under the production logging config (the global RedactionFilter).
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(PHI_ADT.encode("utf-8"))

    def boom(m):  # type: ignore[no-untyped-def]
        raise ValueError(f"cannot transform {m}")  # str(m) is the full HL7 body (PHI)

    reg = _registry(inbox, outdir, lambda m: ["boom"], {"boom": boom})
    handler, lines = _phi_capture()
    root = logging.getLogger()
    root.addHandler(handler)
    prior = root.level
    root.setLevel(logging.DEBUG)
    runner = await _run(reg, store)
    try:
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()
        root.removeHandler(handler)
        root.setLevel(prior)
    # Non-vacuous: the failure must actually surface at WARNING+ (else "no PHI" proves nothing).
    assert any(level >= logging.WARNING for level, _ in lines), "expected a WARNING+ log on failure"
    assert _phi_leaks(lines) == [], f"PHI leaked to logs: {_phi_leaks(lines)}"


async def test_pipeline_delivery_failure_logs_no_phi(store: MessageStore, tmp_path: Path) -> None:
    # Gate #1 end-to-end: a delivery failure whose exception carries the transformed body must not leak
    # the name/MRN into the general log at WARNING+ under the production logging config.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()

    class _RejectsWithPayload:
        async def send(self, payload: str) -> None:
            # A generic (non-DeliveryError) exception → the delivery worker's `except Exception` branch,
            # which logs a WARNING and dead-letters. The exc carries the transformed body (PHI); the
            # WARNING must still not surface it (the worker logs the type only; the filter is the backstop).
            raise RuntimeError(f"downstream blew up on {payload}")

        async def aclose(self) -> None:
            return None

    reg = _retry_registry(inbox, outdir, RetryPolicy(max_attempts=1, backoff_seconds=0.02))
    handler, lines = _phi_capture()
    root = logging.getLogger()
    root.addHandler(handler)
    prior = root.level
    root.setLevel(logging.DEBUG)
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    runner._destinations["file_out"] = _RejectsWithPayload()  # swap in before any traffic
    (inbox / "a.hl7").write_bytes(PHI_ADT.encode("utf-8"))
    try:
        await _until_stat(store, OutboxStatus.DEAD.value, 1)
    finally:
        await runner.stop()
        root.removeHandler(handler)
        root.setLevel(prior)
    # Non-vacuous: the failure must actually surface at WARNING+ (else "no PHI" proves nothing).
    assert any(level >= logging.WARNING for level, _ in lines), "expected a WARNING+ log on failure"
    assert _phi_leaks(lines) == [], f"PHI leaked to logs: {_phi_leaks(lines)}"


async def test_router_handler_transforms_and_delivers(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    def route(msg: Message) -> list[str]:
        return ["arch"] if msg["MSH-9.1"] == "ADT" else []

    def handle(msg: Message) -> Send:
        msg["MSH-3"] = "FOUNDRY"  # transform
        return Send("file_out", msg)

    runner = await _run(_registry(inbox, outdir, route, {"arch": handle}), store)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()

    written = (outdir / "MSG1.hl7").read_bytes().decode("utf-8")
    assert "FOUNDRY" in written  # the Handler's transform was applied before delivery
    assert len(await store.list_messages(channel_id="file_in")) == 1


async def test_router_routes_nowhere_is_unrouted(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    def route(msg: Message) -> list[str]:
        return []  # router forwards to nobody

    runner = await _run(_registry(inbox, outdir, route, {}), store)
    try:
        await _until_message(store, MessageStatus.UNROUTED.value)
    finally:
        await runner.stop()
    assert not (outdir / "MSG1.hl7").exists()


async def test_handler_filters_is_logged_filtered(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    def route(msg: Message) -> list[str]:
        return ["arch"]

    def handle(msg: Message) -> None:
        return None  # handler drops it

    runner = await _run(_registry(inbox, outdir, route, {"arch": handle}), store)
    try:
        await _until_message(store, MessageStatus.FILTERED.value)
    finally:
        await runner.stop()
    assert not (outdir / "MSG1.hl7").exists()


# --- MLLP inbound: ACK / strict NACK -----------------------------------------


def _mllp_registry(outdir: Path, *, strict: bool = False) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "mllp_in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
            validation=Validation(strict=strict, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "archive",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("archive", m))
    return reg


def _mllp_client(port: int) -> MLLPDestination:
    return MLLPDestination(
        Destination(
            name="c",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": port, "timeout_seconds": 5},
        )
    )


async def test_mllp_inbound_acks_and_delivers(store: MessageStore, tmp_path: Path) -> None:
    outdir = tmp_path / "out"
    runner = await _run(_mllp_registry(outdir), store)
    try:
        port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
        await _mllp_client(port).send(ADT)  # returns only on a positive ACK (asserts the AA)
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()
    assert (outdir / "MSG1.hl7").exists()


async def test_strict_validation_nacks(store: MessageStore, tmp_path: Path) -> None:
    runner = await _run(_mllp_registry(tmp_path / "out", strict=True), store)
    try:
        port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
        bad = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N1|P|2.5.1\rEVN|A01|20260101\r"  # no PID
        with pytest.raises(DeliveryError, match="negative ACK"):
            await _mllp_client(port).send(bad)
        await _until_message(store, MessageStatus.ERROR.value, channel_id="mllp_in")
    finally:
        await runner.stop()
    assert (await store.stats()) == {}  # logged ERROR, never enqueued for delivery
    # #120: the persisted strict-validation error is prefixed and run through the PHI scrub (safe_text),
    # so hl7apy error strings that quote an offending field VALUE can't land raw in messages.error.
    errored = (await store.list_messages(channel_id="mllp_in", status=MessageStatus.ERROR.value))[0]
    assert (errored["error"] or "").startswith("strict-validation failed:")


# --- delivery worker: retry / dead-letter ------------------------------------


class _FlakyDestination:
    """Test connector: fails the first ``fail_times`` sends, then succeeds."""

    def __init__(self, fail_times: int) -> None:
        self.remaining = fail_times
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        if self.remaining > 0:
            self.remaining -= 1
            raise DeliveryError("temporary")
        self.deliveries.append(payload)

    async def aclose(self) -> None:
        return None


def _retry_registry(inbox: Path, outdir: Path, retry: RetryPolicy) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            retry=retry,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    return reg


async def test_failed_delivery_retries_then_succeeds(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _retry_registry(inbox, outdir, RetryPolicy(max_attempts=3, backoff_seconds=0.03))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    flaky = _FlakyDestination(fail_times=2)
    runner._destinations["file_out"] = flaky  # swap in before any traffic
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()
    assert len(flaky.deliveries) == 1  # failed twice, third attempt delivered exactly once


async def test_exhausted_retries_dead_letter(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _retry_registry(inbox, outdir, RetryPolicy(max_attempts=2, backoff_seconds=0.02))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    runner._destinations["file_out"] = _FlakyDestination(fail_times=99)  # always fails
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until_stat(store, OutboxStatus.DEAD.value, 1)
    finally:
        await runner.stop()
    assert (await store.stats()).get(OutboxStatus.DEAD.value) == 1


class _AlwaysRaises:
    """Test connector that counts sends and always raises a fixed exception (no successes)."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls = 0

    async def send(self, payload: str) -> None:
        self.calls += 1
        raise self.exc

    async def aclose(self) -> None:
        return None


async def test_permanent_reject_fails_fast_without_retrying(
    store: MessageStore, tmp_path: Path
) -> None:
    # AR permanent reject dead-letters on the first attempt even under the retry-forever default —
    # it must not be retried (it can never succeed) and must not block the lane.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _retry_registry(inbox, outdir, RetryPolicy())  # default: retry forever
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    dest = _AlwaysRaises(NegativeAckError("negative ACK (MSA-1=AR)", code="AR", permanent=True))
    runner._destinations["file_out"] = dest
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until_stat(store, OutboxStatus.DEAD.value, 1)
    finally:
        await runner.stop()
    assert dest.calls == 1  # failed fast — no retry
    assert (await store.stats()).get(OutboxStatus.DEAD.value) == 1


async def test_internal_error_dead_letters_and_continues(
    store: MessageStore, tmp_path: Path
) -> None:
    # An internal/code error (a non-DeliveryError exception escaping send) is our bug, not the
    # partner's: error-and-continue → dead-letter immediately (no retry) so it can't wedge the lane.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _retry_registry(
        inbox, outdir, RetryPolicy()
    )  # default: retry forever (would loop if hit)
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    dest = _AlwaysRaises(ValueError("boom in connector"))
    runner._destinations["file_out"] = dest
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until_stat(store, OutboxStatus.DEAD.value, 1)
    finally:
        await runner.stop()
    assert dest.calls == 1  # internal errors are not retried under the default policy
    assert (await store.stats()).get(OutboxStatus.DEAD.value) == 1


class _RecordingAlertSink:
    """Test AlertSink that records emitted events instead of logging them."""

    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []
        self.buildups: list[tuple[str, int, float]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        self.buildups.append((name, depth, oldest_age_seconds))


def _stop_registry(inbox: Path, outdir: Path, internal_error) -> Registry:  # type: ignore[no-untyped-def]
    """Like _retry_registry but with an explicit per-connection internal_error policy and no retry
    override (so it inherits the retry-forever default)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            internal_error=internal_error,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    return reg


async def _until(predicate, timeout: float = 3.0) -> None:  # type: ignore[no-untyped-def]
    elapsed = 0.0
    while not predicate():
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


async def test_stop_policy_halts_connection_and_alerts(store: MessageStore, tmp_path: Path) -> None:
    # internal_error=STOP: an internal/code error halts the lane (worker stops), preserves the
    # message for replay (PENDING, not DEAD), and emits a connection_stopped alert.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _stop_registry(inbox, outdir, InternalErrorPolicy.STOP)
    sink = _RecordingAlertSink()
    runner = RegistryRunner(reg, store, poll_interval=0.02, alert_sink=sink)
    await runner.start()
    dest = _AlwaysRaises(ValueError("boom in connector"))
    runner._destinations["file_out"] = dest
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until(lambda: bool(sink.stopped))  # alert fired
        await _until(lambda: runner._workers["file_out"].done())  # worker halted
    finally:
        await runner.stop()
    assert dest.calls == 1  # halted on the first internal error, did not loop
    assert sink.stopped[0][0] == "file_out"
    # message preserved for replay, not dead-lettered
    assert (await store.stats()).get(OutboxStatus.DEAD.value, 0) == 0
    assert await store.list_messages(channel_id="file_in")  # still in the store, pending redelivery


async def test_queue_buildup_alert_on_blocked_lane(store: MessageStore, tmp_path: Path) -> None:
    # A retry-forever transport failure keeps the FIFO head blocked → the lane's pending depth crosses
    # the buildup threshold → a queue_buildup alert fires.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            buildup=BuildupThreshold(
                max_depth=1, max_oldest_seconds=None
            ),  # alert as soon as 1 waits
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    sink = _RecordingAlertSink()
    runner = RegistryRunner(reg, store, poll_interval=0.02, alert_sink=sink)
    await runner.start()
    runner._destinations["file_out"] = _AlwaysRaises(DeliveryError("downstream down"))
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until(lambda: bool(sink.buildups))
    finally:
        await runner.stop()
    name, depth, _age = sink.buildups[0]
    assert name == "file_out"
    assert depth >= 1
    assert not sink.stopped  # a transport failure is not an internal error → no connection_stopped


async def test_stop_policy_via_global_default(store: MessageStore, tmp_path: Path) -> None:
    # The global internal_error_default (no per-connection override) threads through and halts too.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _stop_registry(inbox, outdir, None)  # inherit the global default
    sink = _RecordingAlertSink()
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        internal_error_default=InternalErrorPolicy.STOP,
        alert_sink=sink,
    )
    await runner.start()
    runner._destinations["file_out"] = _AlwaysRaises(ValueError("boom"))
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until(lambda: bool(sink.stopped))
    finally:
        await runner.stop()
    assert sink.stopped[0][0] == "file_out"


# --- ingress-worker error / alert / lifecycle paths (staged pipeline, ADR 0001) ----------------


def _raising_router_registry(inbox: Path, outdir: Path, route):  # type: ignore[no-untyped-def]
    reg = _registry(inbox, outdir, route, {"h": lambda m: Send("file_out", m)})
    return reg


async def test_ingress_stop_policy_halts_and_alerts(store: MessageStore, tmp_path: Path) -> None:
    # internal_error=STOP at the INGRESS stage: a router code error halts the ingress worker
    # (it returns, not respawned), preserves the message (RECEIVED, not dead), and emits a
    # connection_stopped alert keyed by the INBOUND name.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()

    def route(msg: Message) -> list[str]:
        raise ValueError("boom in router")

    reg = _raising_router_registry(inbox, outdir, route)
    sink = _RecordingAlertSink()
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        internal_error_default=InternalErrorPolicy.STOP,
        alert_sink=sink,
    )
    await runner.start()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until(lambda: bool(sink.stopped))  # connection_stopped fired
        await _until(lambda: runner._router_workers["file_in"].done())  # router worker halted
    finally:
        await runner.stop()
    assert sink.stopped[0][0] == "file_in"  # keyed by the inbound, not an outbound
    # Message preserved for replay (RECEIVED at ingress), NOT dead-lettered.
    msgs = await store.list_messages(channel_id="file_in")
    assert msgs and msgs[0]["status"] == MessageStatus.RECEIVED.value


async def test_ingress_stop_then_restart_rearms_worker(store: MessageStore, tmp_path: Path) -> None:
    # Regression: a per-connection restart must re-arm a STOP-halted router worker, otherwise the
    # restarted source resumes ACK-on-receipt into an ingress backlog with nothing draining it.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    state = {"raise": True}

    def route(msg: Message) -> list[str]:
        if state["raise"]:
            raise ValueError("boom in router")
        return ["h"]

    reg = _raising_router_registry(inbox, outdir, route)
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        internal_error_default=InternalErrorPolicy.STOP,
        alert_sink=_RecordingAlertSink(),
        delivery_defaults=RetryPolicy(backoff_seconds=0.01, backoff_multiplier=1.0),
    )
    await runner.start()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until(lambda: runner._router_workers["file_in"].done())  # halted on the router error
        # Fix the router, then restart the connection — the halted ingress worker must come back.
        state["raise"] = False
        await runner.restart_inbound("file_in")
        assert not runner._router_workers["file_in"].done()  # re-armed
        # The preserved message (rescheduled, tiny backoff) now routes + delivers.
        await _until(lambda: (outdir / "MSG1.hl7").exists())
    finally:
        await runner.stop()


async def test_ingress_buildup_alert_is_stage_aware(store: MessageStore, tmp_path: Path) -> None:
    # The ingress lane raises queue_buildup keyed by the inbound's channel_id (the ingress lane key),
    # using the global buildup threshold.
    reg = Registry()
    sink = _RecordingAlertSink()
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        buildup_default=BuildupThreshold(max_depth=2),
        alert_sink=sink,
    )
    await store.enqueue_ingress(channel_id="IB", raw=ADT)
    await store.enqueue_ingress(channel_id="IB", raw=ADT)
    await runner._maybe_alert_buildup(
        "IB", stage=Stage.INGRESS.value, threshold=runner._buildup_default
    )
    assert sink.buildups and sink.buildups[0][0] == "IB" and sink.buildups[0][1] >= 2


async def test_ingress_inbound_not_in_registry_reschedules_not_dead_letters(
    store: MessageStore, tmp_path: Path
) -> None:
    # Residual ingress rows of a removed inbound must NEVER be dead-lettered by attempt exhaustion,
    # even under a finite [delivery] max_attempts — they reschedule (retry-forever) and wait for a
    # reload to restore the inbound. The worker then exits (returns) rather than spinning.
    reg = Registry()  # "GONE" is not in the registry
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, delivery_defaults=RetryPolicy(max_attempts=1)
    )
    mid = await store.enqueue_ingress(channel_id="GONE", raw=ADT)
    await runner._router_worker("GONE")  # returns after rescheduling the one residual row
    # Not dead-lettered (would be ERROR under the finite cap if it used the delivery policy); the
    # message is preserved and the row is pending again.
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value
    rows = [
        r
        for r in await (
            await store._db.execute("SELECT status FROM queue WHERE message_id=?", (mid,))
        ).fetchall()
    ]
    assert rows and rows[0]["status"] == OutboxStatus.PENDING.value


async def test_transient_nak_retries_under_finite_cap(store: MessageStore, tmp_path: Path) -> None:
    # A transient AE NAK goes through the retry path (not fail-fast): with a finite max_attempts it
    # dead-letters only after the cap is exhausted, proving AE != AR.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _retry_registry(inbox, outdir, RetryPolicy(max_attempts=3, backoff_seconds=0.02))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    dest = _AlwaysRaises(NegativeAckError("negative ACK (MSA-1=AE)", code="AE", permanent=False))
    runner._destinations["file_out"] = dest
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        await _until_stat(store, OutboxStatus.DEAD.value, 1)
    finally:
        await runner.stop()
    assert dest.calls == 3  # retried up to the finite cap before dead-lettering


# --- Step B: split router/transform across the routed stage -------------------


async def test_two_handlers_both_deliver_end_to_end(store: MessageStore, tmp_path: Path) -> None:
    # Router fans out to two handlers; each transforms + delivers independently through the routed
    # stage, and the message finalizes PROCESSED only after BOTH deliver. Exercises the full split
    # listener → router worker → transform worker → delivery worker path.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    def route(msg: Message) -> list[str]:
        return ["h1", "h2"]

    def h1(msg: Message) -> Send:
        msg["MSH-10"] = "OUT1"  # distinct filename per handler
        return Send("file_out", msg)

    def h2(msg: Message) -> Send:
        msg["MSH-10"] = "OUT2"
        return Send("file_out", msg)

    runner = await _run(_registry(inbox, outdir, route, {"h1": h1, "h2": h2}), store)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 2)  # both deliveries landed
        await _until_message(store, MessageStatus.PROCESSED.value)
    finally:
        await runner.stop()
    assert (outdir / "OUT1.hl7").exists() and (outdir / "OUT2.hl7").exists()
    msgs = await store.list_messages(channel_id="file_in")
    assert len(msgs) == 1 and msgs[0]["status"] == MessageStatus.PROCESSED.value
    # The transient stages left nothing behind: only the two outbound rows persist (no ingress/routed).
    by_stage = {
        r["stage"]: r["n"]
        for r in await (
            await store._db.execute(
                "SELECT stage, COUNT(*) AS n FROM queue WHERE message_id=? GROUP BY stage",
                (msgs[0]["id"],),
            )
        ).fetchall()
    }
    assert by_stage == {Stage.OUTBOUND.value: 2}


async def test_transform_buildup_alert_is_stage_aware(store: MessageStore, tmp_path: Path) -> None:
    # The routed (transform) lane raises queue_buildup keyed by the inbound's channel_id — reported
    # separately from the ingress lane, so a slow transform is distinguishable from a slow router.
    reg = Registry()
    sink = _RecordingAlertSink()
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        buildup_default=BuildupThreshold(max_depth=2),
        alert_sink=sink,
    )
    for _ in range(2):  # two routed rows for inbound "IB"
        mid = await store.enqueue_ingress(channel_id="IB", raw=ADT)
        item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
        assert item is not None
        await store.route_handoff(
            ingress_id=item.id,
            message_id=mid,
            channel_id="IB",
            handlers=[("h", ADT)],
            disposition=MessageStatus.ROUTED,
        )
    await runner._maybe_alert_buildup(
        "IB", stage=Stage.ROUTED.value, threshold=runner._buildup_default
    )
    assert sink.buildups and sink.buildups[0][0] == "IB" and sink.buildups[0][1] >= 2


async def test_transform_worker_dead_letters_missing_handler(
    store: MessageStore, tmp_path: Path
) -> None:
    # A routed row whose handler has left the registry since routing (a reload race) is dead-lettered
    # by the transform worker (message ERROR, replayable) rather than spinning forever on a head it
    # can never transform.
    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = _registry(inbox, tmp_path / "out", lambda m: [], {})  # inbound present; no handlers
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    # Pre-seed a routed row naming a handler that isn't registered (route_handoff bypasses route_only's
    # existence check, simulating a handler removed after the routed row was produced).
    mid = await store.enqueue_ingress(channel_id="file_in", raw=ADT)
    item = await store.claim_next_fifo("file_in", stage=Stage.INGRESS.value)
    assert item is not None
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="file_in",
        handlers=[("ghost", ADT)],
        disposition=MessageStatus.ROUTED,
    )
    await runner.start()
    try:
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value
