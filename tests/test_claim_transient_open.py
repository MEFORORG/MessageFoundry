# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A claim does not dead-letter a row it could not open for a reason that is not the row (BACKLOG
#5735).

A key service that gave no verdict (a Vault Transit outage) or a failed read of the store says
nothing about the claimed row. A per-lane claim puts the row back to ``pending`` with a durable
backoff, and in a FIFO claim every later row of its lane with it, so the lane never delivers past
it. The pooled FIFO claim, ``claim_fifo_heads``, neither re-pends nor dead-letters it: it returns
the row and its lane tail carrying the fault, and the dispatcher's ADR 0070 T17 path re-pends
them while holding the lane and bounds a lasting fault with ``infra_fault_policy`` and its alert. A dead-letter write that fails is
treated the same way, and a tag failure behind it is still audited and alerted. A real tag failure
is still dead-lettered and reported (the control). SQLite; the server backends make the same change.
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import sqlite3
import time
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.store import MessageStore, OutboxItem
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    CipherUnavailableError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import (
    QUEUE_TAG_FAILED_ACTION,
    QueueOpenFault,
    queue_open_fault,
)

_DEST = "OB_T"


class _OutageCipher:
    """An :class:`AesGcmCipher` whose decrypt raises a key-service outage once ``healthy_opens``
    decrypts have run (``None``: never)."""

    def __init__(self, inner: AesGcmCipher) -> None:
        self._inner = inner
        self.healthy_opens: int | None = None
        #: The error a failing decrypt raises; an outage unless a test sets another.
        self.fault: Callable[[], CipherError] = lambda: CipherUnavailableError(
            "Transit decrypt failed (key='k'): ConnectionError"
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        if self.healthy_opens is not None:
            if self.healthy_opens <= 0:
                raise self.fault()
            self.healthy_opens -= 1
        return self._inner.decrypt(stored, aad=aad)


Claim = Callable[[MessageStore], Awaitable[list[Any]]]


async def _claim_ready(store: MessageStore) -> list[Any]:
    return await store.claim_ready(10, destination_name=_DEST)


async def _claim_next_fifo(store: MessageStore) -> list[Any]:
    one = await store.claim_next_fifo(_DEST)
    return [] if one is None else [one]


async def _claim_next_fifo_batch(store: MessageStore) -> list[Any]:
    return await store.claim_next_fifo_batch(_DEST, stage="outbound", limit=10)


async def _claim_fifo_heads(store: MessageStore) -> list[Any]:
    heads = await store.claim_fifo_heads("outbound", [_DEST], per_lane_limit=10)
    return [item for items in heads.by_lane.values() for item in items]


_PER_LANE = [_claim_ready, _claim_next_fifo, _claim_next_fifo_batch]
_IDS = ["claim_ready", "claim_next_fifo", "claim_next_fifo_batch"]
_CLAIMS = pytest.mark.parametrize("claim", _PER_LANE, ids=_IDS)
_ALL_CLAIMS = pytest.mark.parametrize(
    "claim", [*_PER_LANE, _claim_fifo_heads], ids=[*_IDS, "claim_fifo_heads"]
)


async def _open(tmp_path: pathlib.Path) -> tuple[MessageStore, _OutageCipher, pathlib.Path]:
    inner = make_cipher(generate_key(), write_v2=True)
    assert isinstance(inner, AesGcmCipher)
    cipher = _OutageCipher(inner)
    db = tmp_path / "claim.db"
    store = await MessageStore.open(db, cipher=cipher)  # type: ignore[arg-type]
    await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B1")])
    await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B2")])
    return store, cipher, db


def _side(db: pathlib.Path, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(db, timeout=30)
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def _rows(db: pathlib.Path) -> list[tuple[str, int]]:
    return [
        (str(r[0]), int(r[1]))
        for r in _side(
            db,
            "SELECT status, attempts FROM queue WHERE destination_name=? ORDER BY rowid",
            (_DEST,),
        )
    ]


def _deferred(db: pathlib.Path) -> bool:
    """Whether the lane's head was set aside: its next attempt is in the future, not due now. (A
    claim that takes only the head leaves the row behind it as it was.)"""
    head = _side(
        db,
        "SELECT next_attempt_at FROM queue WHERE rowid=(SELECT MIN(rowid) FROM queue"
        " WHERE destination_name=?)",
        (_DEST,),
    )
    return float(head[0][0]) > time.time()


def _audited(db: pathlib.Path) -> int:
    rows = _side(db, "SELECT COUNT(*) FROM audit_log WHERE action=?", (QUEUE_TAG_FAILED_ACTION,))
    return int(rows[0][0])


def _tamper_head(db: pathlib.Path) -> None:
    _side(
        db,
        "UPDATE queue SET handler_name='MOVED' WHERE rowid=(SELECT MIN(rowid) FROM queue"
        " WHERE destination_name=?)",
        (_DEST,),
    )


@_CLAIMS
async def test_a_key_service_outage_sets_the_rows_aside(
    tmp_path: pathlib.Path, claim: Claim
) -> None:
    store, cipher, db = await _open(tmp_path)
    try:
        cipher.healthy_opens = 0
        assert await claim(store) == []
        assert _rows(db) == [("pending", 0), ("pending", 0)]  # nothing dead-lettered or stranded
        assert _deferred(db)  # a durable backoff, so a sweep does not re-claim at once
        assert _audited(db) == 0  # no false integrity report
        cipher.healthy_opens = None
        _side(db, "UPDATE queue SET next_attempt_at=0")  # the backoff has passed
        payloads = [i.payload for i in await claim(store)]  # control: they deliver once it is back
        if claim is _claim_ready:  # orders by next_attempt_at, which ties here
            assert sorted(payloads) == ["B1", "B2"]
        else:  # a FIFO claim still starts at the lane's head
            assert payloads[:1] == ["B1"]
    finally:
        await store.close()


@_CLAIMS
async def test_a_store_read_error_sets_the_rows_aside(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _cipher, db = await _open(tmp_path)
    try:

        async def failing(_row: Any) -> Any:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(store, "_outbox_item_from_row", failing)
        assert await claim(store) == []
        assert _rows(db) == [("pending", 0), ("pending", 0)]
        assert _deferred(db)
    finally:
        await store.close()


@_CLAIMS
async def test_a_failed_dead_letter_write_still_reports_the_tag_failure(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tag failure whose dead-letter write fails is audited and alerted all the same, and the row
    is set aside rather than left ``inflight``."""
    store, _cipher, db = await _open(tmp_path)
    try:
        _side(db, "UPDATE queue SET handler_name='MOVED' WHERE destination_name=?", (_DEST,))

        async def failing(*_a: Any, **_kw: Any) -> None:
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(store, "dead_letter_now", failing)
        assert await claim(store) == []
        assert _rows(db) == [("pending", 0), ("pending", 0)]  # set aside, not left inflight
        assert _audited(db) >= 1  # the integrity report did not wait on the dead-letter
    finally:
        await store.close()


@_ALL_CLAIMS
async def test_a_programming_error_in_the_dead_letter_write_stays_loud(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _cipher, db = await _open(tmp_path)
    try:
        _tamper_head(db)

        async def broken(*_a: Any, **_kw: Any) -> None:
            raise TypeError("dead_letter_now() got an unexpected keyword argument")

        monkeypatch.setattr(store, "dead_letter_now", broken)
        with pytest.raises(TypeError):
            await claim(store)
    finally:
        await store.close()


@pytest.mark.parametrize("claim", _PER_LANE[1:], ids=_IDS[1:])
async def test_a_fifo_claim_stops_at_the_row_it_sets_aside(
    tmp_path: pathlib.Path, claim: Claim
) -> None:
    """Row one fails its tag and is dead-lettered; the outage then hits row two, which is set
    aside. The dead-letter stands, and nothing past row two is delivered."""
    store, cipher, db = await _open(tmp_path)
    try:
        await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B3")])
        _tamper_head(db)
        cipher.healthy_opens = 1  # row one's open runs (and fails its tag), then the outage
        await claim(store)  # a single claim stops at the dead head; the batch claim goes on
        if claim is _claim_next_fifo:
            assert await claim(store) == []  # the next claim meets the outage on row two
        assert _rows(db) == [("dead", 1), ("pending", 0), ("pending", 0)]
        assert _audited(db) == 1
    finally:
        await store.close()


@_ALL_CLAIMS
async def test_a_real_tag_failure_is_still_dead_lettered_and_reported(
    tmp_path: pathlib.Path, claim: Claim
) -> None:
    """The control: a row whose routing field changed outside the store fails its tag, and the
    claim dead-letters and reports it exactly as before."""
    store, _cipher, db = await _open(tmp_path)
    try:
        _tamper_head(db)
        items = await claim(store)
        assert all(i.payload != "B1" for i in items)
        assert _rows(db)[0][0] == "dead"
        assert _audited(db) == 1
    finally:
        await store.close()


def _transit_error(kind: str) -> Callable[[], CipherError]:
    """The error the Transit cipher's decrypt raises for the reply or failure ``kind`` names, built
    by its own classifier from the error hvac or requests raises, with the reply status the store's
    client records (BACKLOG #8222)."""
    pytest.importorskip("hvac")
    import requests  # noqa: PLC0415
    from hvac import exceptions as hv  # type: ignore[import-untyped]  # noqa: PLC0415

    from messagefoundry.store.crypto_transit import _transit_failure  # noqa: PLC0415
    from messagefoundry.transports.bounded_read import EgressReplyError  # noqa: PLC0415
    from messagefoundry.transports.strict_requests import VaultHopRefused  # noqa: PLC0415
    from tests.test_queue_tag import with_reply_status as recorded  # noqa: PLC0415

    def unexpected(status: int) -> Exception:
        return recorded(hv.UnexpectedError(f"status {status}"), status)

    raw: dict[str, Callable[[], Exception]] = {
        "400": lambda: hv.InvalidRequest(errors=["invalid ciphertext"]),
        "401": lambda: hv.Unauthorized(errors=["missing client token"]),
        "403": lambda: hv.Forbidden(errors=["permission denied"]),
        "404": lambda: hv.InvalidPath(errors=["no handler for route"]),
        "408": lambda: unexpected(408),
        "413": lambda: unexpected(413),
        # hvac raises a TypeError where it cannot read a reply body's ``errors``; the store's client
        # records the status on it all the same (BACKLOG #8222).
        "503-typeerror": lambda: recorded(TypeError("string indices must be integers"), 503),
        "tls": lambda: requests.exceptions.SSLError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
        ),
        "429": lambda: hv.RateLimitExceeded(errors=["rate limited"]),
        "501": lambda: hv.VaultNotInitialized(errors=["not initialized"]),
        "503": lambda: hv.VaultDown(errors=["Vault is sealed"]),
        "504": lambda: unexpected(504),
        "timeout": lambda: requests.exceptions.ReadTimeout("read timed out"),
        "connection": lambda: requests.exceptions.ConnectionError("connection refused"),
        # The strict Vault adapter raises these unwrapped, through hvac.
        "hop-refused": lambda: VaultHopRefused("vault_transit: refused"),
        "reply-refused": lambda: EgressReplyError("a reply the engine cannot read strictly"),
    }

    def build() -> CipherError:
        cause = raw[kind]()
        error = _transit_failure("decrypt", "k", cause)
        error.__cause__ = cause  # as the cipher's ``raise ... from`` sets it
        return error

    return build


#: The replies that are Vault's verdict on the row (``queue_tag._key_service_gave_no_verdict``).
_VERDICTS = ["400", "404", "413"]
#: At least these give no verdict on the row. 401, 403, 408, the TLS refusal, the 503 recorded on
#: a TypeError and the two strict-adapter refusals were verdicts before the rule was revised.
_NO_VERDICTS = [
    "503",
    "429",
    "501",
    "504",
    "timeout",
    "connection",
    "401",
    "403",
    "408",
    "tls",
    "503-typeerror",
    "hop-refused",
    "reply-refused",
]


@_ALL_CLAIMS
@pytest.mark.parametrize("kind", _VERDICTS)
async def test_a_verdict_is_still_dead_lettered_and_reported(
    tmp_path: pathlib.Path, claim: Claim, kind: str
) -> None:
    """BACKLOG #5765: a 400, a 404 and a 413 are Vault's verdict on the row, so the claim
    dead-letters and reports it as before, never sets it aside to retry with no cap."""
    store, cipher, db = await _open(tmp_path)
    try:
        cipher.fault = _transit_error(kind)
        cipher.healthy_opens = 0
        assert all(i.payload != "B1" for i in await claim(store))
        assert _rows(db)[0][0] == "dead"
        assert _audited(db) >= 1
    finally:
        await store.close()


@_CLAIMS
@pytest.mark.parametrize("kind", _NO_VERDICTS)
async def test_a_key_service_with_no_verdict_sets_the_rows_aside(
    tmp_path: pathlib.Path, claim: Claim, kind: str
) -> None:
    """BACKLOG #5765: a failure reaching or authenticating to the key service gives no verdict on
    the row, so a per-lane claim sets it aside unaudited."""
    store, cipher, db = await _open(tmp_path)
    try:
        cipher.fault = _transit_error(kind)
        cipher.healthy_opens = 0
        assert await claim(store) == []
        assert _rows(db) == [("pending", 0), ("pending", 0)]
        assert _deferred(db)
        assert _audited(db) == 0
    finally:
        await store.close()


@pytest.mark.parametrize("kind", _NO_VERDICTS)
async def test_the_pooled_claim_hands_a_no_verdict_to_t17(
    tmp_path: pathlib.Path, kind: str
) -> None:
    """The same failures, on ``claim_fifo_heads``: the rows come back carrying the fault, with
    nothing dead-lettered or audited, for the dispatcher's T17 path."""
    store, cipher, db = await _open(tmp_path)
    try:
        cipher.fault = _transit_error(kind)
        cipher.healthy_opens = 0
        items = await _claim_fifo_heads(store)
        assert items and all(i.open_fault is not None for i in items)
        statuses = [s for s, _a in _rows(db)]
        assert statuses[0] == "inflight" and "dead" not in statuses
        assert _audited(db) == 0
    finally:
        await store.close()


@_CLAIMS
async def test_the_set_aside_deadline_runs_from_the_fault_not_the_claim(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decrypt that times out slowly must not leave a deadline already past: the backoff runs
    from the clock at the set-aside write. The clock is injected and moves 60 seconds while the
    decrypt runs."""
    store, cipher, db = await _open(tmp_path)
    try:
        start = time.time()
        clock = {"now": start}
        monkeypatch.setattr(time, "time", lambda: clock["now"])

        def slow_timeout() -> CipherError:
            clock["now"] = start + 60.0
            return CipherUnavailableError("Transit decrypt failed (key='k'): ReadTimeout")

        cipher.fault = slow_timeout
        cipher.healthy_opens = 0
        assert await claim(store) == []
        head = _side(
            db,
            "SELECT next_attempt_at FROM queue WHERE rowid=(SELECT MIN(rowid) FROM queue"
            " WHERE destination_name=?)",
            (_DEST,),
        )
        assert float(head[0][0]) == pytest.approx(start + 65.0, abs=0.5)
    finally:
        await store.close()


@pytest.mark.parametrize("backend", ["sqlserver", "postgres"])
async def test_the_server_set_aside_deadline_runs_from_the_fault(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server backends compute the deadline the same way, from the clock at the write."""
    store = _server_store(backend, _FakeServer(None))
    written: list[tuple[list[str], float]] = []

    async def reschedule(ids: Any, when: float) -> None:
        written.append((list(ids), when))

    store.reschedule_claimed = reschedule
    monkeypatch.setattr(time, "time", lambda: 1060.0)
    await store._set_aside_claimed([{"id": "row-1"}], 1000.0)  # the claim started at 1000
    assert written == [(["row-1"], 1065.0)]
    await store._set_aside_claimed([{"id": "row-2"}], 2000.0)  # an injected later claim time
    assert written[-1] == (["row-2"], 2005.0)


# --- the pooled claim hands the fault to the dispatcher's T17 path --------------------------------

_LANE = "IB_T17"


async def _open_ingress(
    tmp_path: pathlib.Path, n: int
) -> tuple[MessageStore, _OutageCipher, pathlib.Path]:
    inner = make_cipher(generate_key(), write_v2=True)
    assert isinstance(inner, AesGcmCipher)
    cipher = _OutageCipher(inner)
    db = tmp_path / "heads.db"
    store = await MessageStore.open(db, cipher=cipher)  # type: ignore[arg-type]
    for t in range(n):
        await store.enqueue_ingress(channel_id=_LANE, raw=f"MSH|{t}", now=100.0 + t)
    return store, cipher, db


def _ingress(db: pathlib.Path) -> list[tuple[str, int]]:
    return [
        (str(r[0]), int(r[1]))
        for r in _side(
            db,
            "SELECT status, attempts FROM queue WHERE stage='ingress' AND channel_id=?"
            " ORDER BY rowid",
            (_LANE,),
        )
    ]


async def test_the_pooled_claim_returns_the_fault_and_writes_nothing(
    tmp_path: pathlib.Path,
) -> None:
    """Row one opens; the outage hits row two. The claim returns row one's body, then row two and
    row three carrying the fault with no body, and leaves all three ``inflight`` for the
    dispatcher, which holds the lane until it has re-pended them."""
    store, cipher, db = await _open_ingress(tmp_path, 3)
    try:
        cipher.healthy_opens = 1
        heads = await store.claim_fifo_heads("ingress", [_LANE], per_lane_limit=10)
        items = heads.by_lane[_LANE]
        assert [i.payload for i in items] == ["MSH|0", "", ""]
        assert items[0].open_fault is None
        faults = [i.open_fault for i in items[1:]]
        assert all(isinstance(f, QueueOpenFault) for f in faults)
        # The fault names the outage but carries no chain or frames: a log of it with
        # exc_info must not print the raw key-service error or reach the claim's locals.
        assert all("CipherUnavailableError" in str(f) for f in faults)
        assert all(
            f is not None and (f.__cause__, f.__context__, f.__traceback__) == (None, None, None)
            for f in faults
        )
        assert _ingress(db) == [("inflight", 1)] * 3  # nothing set aside or dead-lettered here
        assert _audited(db) == 0
    finally:
        await store.close()


async def test_a_lasting_outage_stops_the_lane_through_t17(tmp_path: pathlib.Path) -> None:
    """ADR 0070 end to end: a lane whose head the key service never answers for reaches STOPPED
    after ``infra_fault_stop_after`` faults, with one ``connection_stopped`` alert. The body never
    runs on an unopened row, nothing is dead-lettered, and the rows end ``pending`` with their
    attempts intact."""
    from tests.test_stage_dispatcher import (  # noqa: PLC0415
        ManualClock,
        RecordingAlertSink,
        RecordingStub,
        _drive_infra_faults_until_stop,
        _make,
    )

    store, cipher, db = await _open_ingress(tmp_path, 2)
    store._test_backend = "sqlite"  # type: ignore[attr-defined]
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    alert = RecordingAlertSink()
    d = _make(store, stub, set(), clock=mc, alert_sink=alert, infra_fault_stop_after=3)
    cipher.healthy_opens = 0
    await d.start()
    try:
        d.mark_ready(_LANE)
        await _drive_infra_faults_until_stop(d, mc, _LANE, budget=8)
        assert d.infra_error_streak(_LANE) == 3
        assert len(alert.stopped) == 1 and alert.stopped[0][0] == _LANE
        assert stub.records == []  # the body never saw an unopened row
        assert _ingress(db) == [("pending", 0), ("pending", 0)]
        assert _audited(db) == 0
    finally:
        await d.stop()
        await store.close()


# --- the server backends' classifier, offline ------------------------------------------------------


class _FakeServer:
    """Stands in for the server store's dead-letter and audit writes on an instance built with no
    pool, so the shared classifier runs with no database."""

    def __init__(self, fail_with: BaseException | None) -> None:
        self.fail_with = fail_with
        self.dead_lettered: list[str] = []
        self.audited: list[str] = []

    async def dead_letter_now(self, outbox_id: str, error: str, now: float | None = None) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.dead_lettered.append(outbox_id)

    async def record_audit(self, action: str, **_kw: Any) -> None:
        self.audited.append(action)


def _server_store(backend: str, fake: _FakeServer) -> Any:
    if backend == "sqlserver":
        from messagefoundry.store.sqlserver import SqlServerStore  # noqa: PLC0415

        store: Any = SqlServerStore.__new__(SqlServerStore)
    else:
        from messagefoundry.store.postgres import PostgresStore  # noqa: PLC0415

        store = PostgresStore.__new__(PostgresStore)
    store._cipher = make_cipher(generate_key(), write_v2=True)
    store.dead_letter_now = fake.dead_letter_now
    store.record_audit = fake.record_audit
    return store


async def _classify(backend: str, store: Any, exc: Any) -> BaseException | None:
    row = {"id": "row-1", "message_id": "m", "stage": "outbound", "channel_id": "IB"}
    if backend == "sqlserver":
        result: BaseException | None = await store._dead_letter_unopenable(row, "outbound", exc)
        return result
    result = await store._dead_letter_unopenable(row, exc)
    return result


@pytest.mark.parametrize("backend", ["sqlserver", "postgres"])
async def test_the_server_classifier_matches_sqlite(backend: str) -> None:
    from messagefoundry.store.queue_tag import QueueTagError  # noqa: PLC0415

    outage = CipherUnavailableError("down")
    fake = _FakeServer(None)
    fault = await _classify(backend, _server_store(backend, fake), outage)
    assert isinstance(fault, QueueOpenFault) and str(fault) == "CipherUnavailableError: down"
    assert fake.dead_lettered == [] and fake.audited == []  # an outage writes nothing

    fake = _FakeServer(None)  # control: a tag failure is dead-lettered and reported
    assert await _classify(backend, _server_store(backend, fake), QueueTagError("t")) is None
    assert fake.dead_lettered == ["row-1"] and fake.audited == [QUEUE_TAG_FAILED_ACTION]

    store_fault = OSError("connection reset")
    fake = _FakeServer(store_fault)  # the dead-letter write fails: still reported, then returned
    fault = await _classify(backend, _server_store(backend, fake), QueueTagError("t"))
    # Named by its type alone: a driver's text can echo a value, and T17 logs the fault at ERROR.
    assert isinstance(fault, QueueOpenFault) and str(fault) == "OSError"
    assert fake.audited == [QUEUE_TAG_FAILED_ACTION]

    fake = _FakeServer(TypeError("bug"))  # an engine bug stays loud
    with pytest.raises(TypeError):
        await _classify(backend, _server_store(backend, fake), QueueTagError("t"))


def test_the_postgres_unopened_item_carries_the_fault() -> None:
    from messagefoundry.store.postgres import PostgresStore  # noqa: PLC0415

    fault = queue_open_fault(CipherUnavailableError("down"))
    row = {
        "id": "r",
        "message_id": "m",
        "channel_id": "IB",
        "destination_name": None,
        "attempts": 1,
        "stage": "ingress",
        "handler_name": None,
        "created_at": 1.0,
    }
    item = PostgresStore._unopened_item(row, fault)
    assert item.open_fault is fault and item.payload == "" and item.id == "r"


# --- the fault T17 logs holds no claimed row's plaintext (BACKLOG #6706) --------------------------


def _frames(exc: BaseException) -> list[Any]:
    """Every frame ``exc`` reaches: each traceback entry's frame and its ``f_back`` callers, for
    ``exc`` and for every exception on its ``__cause__``/``__context__`` chain."""
    frames: list[Any] = []
    seen_exc: set[int] = set()
    seen_frames: set[int] = set()
    pending: list[BaseException | None] = [exc]
    while pending:
        cur = pending.pop()
        if cur is None or id(cur) in seen_exc:
            continue
        seen_exc.add(id(cur))
        pending += [cur.__cause__, cur.__context__]
        tb = cur.__traceback__
        while tb is not None:
            frame: Any = tb.tb_frame
            while frame is not None and id(frame) not in seen_frames:
                seen_frames.add(id(frame))
                frames.append(frame)
                frame = frame.f_back
            tb = tb.tb_next
    return frames


def _payloads_in(value: Any) -> set[str]:
    values = value if isinstance(value, (list, tuple)) else [value]
    return {v.payload for v in values if isinstance(v, OutboxItem) and v.payload}


async def test_the_fault_t17_logs_holds_no_claimed_payload(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Row one opens and its body runs; the outage hits row two. The exception T17 logs is a fresh
    fault with no chain, and no frame it reaches, through its traceback, a caller's ``f_back`` or
    its cause and context, holds row one's plaintext."""
    from messagefoundry.pipeline.stage_dispatcher import _LanePhase  # noqa: PLC0415
    from tests.test_stage_dispatcher import (  # noqa: PLC0415
        ManualClock,
        RecordingAlertSink,
        RecordingStub,
        _make,
        _wait_lane,
    )

    store, cipher, _db = await _open_ingress(tmp_path, 2)
    store._test_backend = "sqlite"  # type: ignore[attr-defined]
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    d = _make(store, stub, set(), clock=mc, alert_sink=RecordingAlertSink())
    cipher.healthy_opens = 1
    caplog.set_level(logging.ERROR, logger="messagefoundry.pipeline.stage_dispatcher")
    await d.start()
    try:
        d.mark_ready(_LANE)
        await _wait_lane(d, _LANE, _LanePhase.PARKED, _LanePhase.STOPPED)
        assert len(stub.records) == 1  # row one's body ran on its plaintext
        seen = [
            r.exc_info[1]
            for r in caplog.records
            if "T17 infra fault" in r.getMessage() and r.exc_info is not None
        ]
        assert len(seen) == 1
        fault = seen[0]
        assert isinstance(fault, QueueOpenFault)
        assert (fault.__cause__, fault.__context__) == (None, None)
        leaked = {p for f in _frames(fault) for v in f.f_locals.values() for p in _payloads_in(v)}
        assert leaked == set(), "a frame the logged fault reaches holds claimed plaintext"
    finally:
        await d.stop()
        await store.close()


# --- an engine error in the pooled claim leaves no lane stranded (BACKLOG #5735) ------------------


class _RefusingCipher(_OutageCipher):
    """Refuses the row itself (a plain :class:`CipherError`) once ``healthy_opens`` opens ran."""

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        if self.healthy_opens is not None:
            if self.healthy_opens <= 0:
                raise CipherError("bad cell")
            self.healthy_opens -= 1
        return self._inner.decrypt(stored, aad=aad)


async def _broken_dead_letter(*_a: Any, **_kw: Any) -> None:
    raise TypeError("dead_letter_now() got an unexpected keyword argument")


async def test_an_engine_error_in_the_pooled_claim_releases_every_lane(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two lanes are claimed in one commit. Lane A's two rows open; lane B's head is refused and
    its dead-letter write hits an engine bug, which the claim re-raises. Every claimed row is back
    to ``pending`` with its attempts undone, and the next claim returns each lane's head first."""
    inner = make_cipher(generate_key(), write_v2=True)
    assert isinstance(inner, AesGcmCipher)
    cipher = _RefusingCipher(inner)
    db = tmp_path / "strand.db"
    store = await MessageStore.open(db, cipher=cipher)  # type: ignore[arg-type]
    lanes = ["IB_A", "IB_B"]
    try:
        for t, lane in enumerate(lanes):
            for k in range(2):
                await store.enqueue_ingress(channel_id=lane, raw=f"MSH|{lane}{k}", now=100.0 + t)
        cipher.healthy_opens = 2  # lane A's two rows open, then lane B's head is refused
        monkeypatch.setattr(store, "dead_letter_now", _broken_dead_letter)
        with pytest.raises(TypeError):
            await store.claim_fifo_heads("ingress", lanes, per_lane_limit=10)
        rows = _side(db, "SELECT status, attempts FROM queue WHERE stage='ingress' ORDER BY rowid")
        assert [(str(s), int(a)) for s, a in rows] == [("pending", 0)] * 4

        cipher.healthy_opens = None
        monkeypatch.undo()
        heads = await store.claim_fifo_heads("ingress", lanes, per_lane_limit=10)
        assert [i.payload for i in heads.by_lane["IB_A"]] == ["MSH|IB_A0", "MSH|IB_A1"]
        assert [i.payload for i in heads.by_lane["IB_B"]] == ["MSH|IB_B0", "MSH|IB_B1"]
    finally:
        await store.close()


def _server_row(lane: str, seq: int) -> dict[str, Any]:
    return {
        "id": f"{lane}-{seq}",
        "message_id": "m",
        "channel_id": lane,
        "destination_name": None,
        "handler_name": None,
        "attempts": 1,
        "stage": "ingress",
        "created_at": 1.0,
        "seq": seq,
    }


@pytest.mark.parametrize("backend", ["sqlserver", "postgres"])
async def test_the_server_pooled_claim_releases_every_lane_on_an_engine_error(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server twins of the test above, offline: the decode step that runs after the claim
    commits hands every claimed row of every lane, lane A's opened rows included, to the backend's
    own ``release_claimed`` before it re-raises an engine bug. That release's ``inflight`` guard is
    what puts them back to ``pending``; it is covered on each backend by test_claim_fifo_heads."""
    from messagefoundry.store.queue_tag import QueueTagError  # noqa: PLC0415

    store = _server_store(backend, _FakeServer(TypeError("bug")))
    released: list[str] = []

    async def release_claimed(ids: Any, now: float | None = None) -> None:
        released.extend(ids)

    store.release_claimed = release_claimed
    by_lane_rows = {
        "A": [_server_row("A", 1), _server_row("A", 2)],
        "B": [_server_row("B", 3), _server_row("B", 4)],
    }

    def opened(r: Any, *_a: Any) -> Any:
        if r["channel_id"] == "B":
            raise QueueTagError("t")
        return "body" if backend == "sqlserver" else OutboxItem.from_row(r, "body")

    if backend == "sqlserver":
        monkeypatch.setattr(store, "_open_claimed", opened)
        with pytest.raises(TypeError):
            await store._open_claimed_heads(by_lane_rows, "ingress", set())
    else:
        monkeypatch.setattr(store, "_outbox_item", opened)
        with pytest.raises(TypeError):
            await store._open_claimed_heads(by_lane_rows, set())
    assert sorted(released) == ["A-1", "A-2", "B-3", "B-4"]


#: Errors that are not an engine bug and still escape the pooled claim's decode (BACKLOG #5735).
_ESCAPING = pytest.mark.parametrize(
    "error", [ValueError("not a bug"), asyncio.CancelledError()], ids=["ValueError", "cancelled"]
)


@_ESCAPING
async def test_any_escaping_error_in_the_pooled_claim_releases_every_lane(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    """Lane A's two rows open; lane B's head is refused and handling it raises ``error``, which
    the claim re-raises unchanged. Every claimed row of both lanes is back to ``pending``."""
    inner = make_cipher(generate_key(), write_v2=True)
    assert isinstance(inner, AesGcmCipher)
    cipher = _RefusingCipher(inner)
    db = tmp_path / "escape.db"
    store = await MessageStore.open(db, cipher=cipher)  # type: ignore[arg-type]
    lanes = ["IB_A", "IB_B"]
    try:
        for t, lane in enumerate(lanes):
            for k in range(2):
                await store.enqueue_ingress(channel_id=lane, raw=f"MSH|{lane}{k}", now=100.0 + t)
        cipher.healthy_opens = 2

        async def escaping(*_a: Any, **_kw: Any) -> None:
            raise error

        monkeypatch.setattr(store, "_dead_letter_unopenable", escaping)
        with pytest.raises(type(error)) as raised:
            await store.claim_fifo_heads("ingress", lanes, per_lane_limit=10)
        assert raised.value is error
        rows = _side(db, "SELECT status, attempts FROM queue WHERE stage='ingress' ORDER BY rowid")
        assert [(str(s), int(a)) for s, a in rows] == [("pending", 0)] * 4
    finally:
        await store.close()


@_ESCAPING
@pytest.mark.parametrize("backend", ["sqlserver", "postgres"])
async def test_the_server_pooled_claim_releases_every_lane_on_any_escaping_error(
    backend: str, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    """The server twins of the test above, offline: lane B's open raises ``error``, which is not
    a :class:`CipherError`, so it escapes the decode, and every claimed row of every lane is handed
    to ``release_claimed`` before the claim re-raises it unchanged."""
    store = _server_store(backend, _FakeServer(None))
    released: list[str] = []

    async def release_claimed(ids: Any, now: float | None = None) -> None:
        released.extend(ids)

    store.release_claimed = release_claimed
    by_lane_rows = {
        "A": [_server_row("A", 1), _server_row("A", 2)],
        "B": [_server_row("B", 3), _server_row("B", 4)],
    }

    def opened(r: Any, *_a: Any) -> Any:
        if r["channel_id"] == "B":
            raise error
        return "body" if backend == "sqlserver" else OutboxItem.from_row(r, "body")

    if backend == "sqlserver":
        monkeypatch.setattr(store, "_open_claimed", opened)
        with pytest.raises(type(error)) as raised:
            await store._open_claimed_heads(by_lane_rows, "ingress", set())
    else:
        monkeypatch.setattr(store, "_outbox_item", opened)
        with pytest.raises(type(error)) as raised:
            await store._open_claimed_heads(by_lane_rows, set())
    assert raised.value is error
    assert sorted(released) == ["A-1", "A-2", "B-3", "B-4"]


async def test_a_failed_id_list_does_not_replace_the_claims_error() -> None:
    """``release_unreturned`` builds its id list inside its own guard, so a row it cannot read
    is logged and the caller still re-raises its own error."""
    from messagefoundry.store.queue_tag import release_unreturned  # noqa: PLC0415

    called: list[Any] = []

    async def release_claimed(ids: Any, now: float | None = None) -> None:
        called.append(ids)

    store = type("S", (), {"release_claimed": staticmethod(release_claimed)})()
    await release_unreturned(store, [[{"no_id": 1}]])  # must not raise
    assert called == []
