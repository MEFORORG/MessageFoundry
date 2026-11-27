# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5727: whatever escapes the re-ingress step leaves only as a QueueOpenFault or as a
type name (the Lander's hold on PR 3155, items 1 to 3).

The step's store writes seal their error text, and a raw cipher error can chain a key service's
URL or body, a driver error its statement, and a traceback the frames that hold the reply. The
fault arm logs what escapes with its traceback. SQLite only: the boundary is in the runner, and
the store contract runs on every backend from ``tests/_undecryptable_reply_contract.py``.
"""

from __future__ import annotations

import logging
import pathlib
import sqlite3
from typing import Any

import pytest

from messagefoundry.pipeline.wiring_runner import _ReplyStepFault
from messagefoundry.store import MessageStore, OutboxStatus, Stage
from messagefoundry.store.crypto import (
    CipherError,
    CipherUnavailableError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import QueueOpenFault
from tests import _undecryptable_reply_contract as contract
from tests._erased_reply_contract import LOOP, children

#: A marker the reply carries, to show no frame of the escaping fault holds it.
REPLY_MARK = "SYNTHETIC-REPLY-MARK"


@pytest.fixture
async def store(tmp_path: pathlib.Path) -> Any:
    s = await MessageStore.open(
        tmp_path / "step_boundary.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    yield s
    await s.close()


def _seal_error(outage: bool) -> CipherError:
    """A seal failure whose own cause carries the key service's text: no verdict with ``outage``,
    else the invocation ceiling, a verdict."""
    error: CipherError = (
        CipherUnavailableError("synthetic") if outage else CipherError("synthetic ceiling")
    )
    error.__cause__ = ValueError(contract.KEY_SERVICE_TEXT)
    return error


def _assert_clean(fault: BaseException, outage: bool) -> None:
    """``fault`` is the boundary's: the right class, no chain, no key-service text or reply in its
    rendering, and no frame that holds the reply."""
    assert isinstance(fault, QueueOpenFault if outage else _ReplyStepFault), type(fault)
    assert fault.__cause__ is None and fault.__context__ is None
    rendered = logging.Formatter().formatException((type(fault), fault, fault.__traceback__))
    assert contract.KEY_SERVICE_TEXT not in rendered and REPLY_MARK not in rendered
    walked, holding = contract._engine_frames_holding(fault, (REPLY_MARK,))
    assert walked and holding == [], (walked, holding)


async def _head(store: MessageStore) -> tuple[str, Any]:
    mid = await contract.captured(store, control="SB-HEAD", now=1.0, reply=REPLY_MARK)
    item = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
    assert item is not None and item.message_id == mid
    return mid, item


async def _status(store: MessageStore, row_id: str) -> str:
    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (row_id,))
    row = await cur.fetchone()
    assert row is not None
    return str(row["status"])


@pytest.mark.parametrize("outage", [True, False], ids=["outage", "verdict"])
async def test_a_failed_seal_in_the_missing_inbound_revert_leaves_clean(
    store: MessageStore, outage: bool
) -> None:
    """Item 1: a loopback a reload removed reverts its token with ``mark_failed``, whose seal can
    fail. Before the boundary the raw error, chain and all, reached the fault arm."""
    _, item = await _head(store)
    step = contract.runner(store)
    del step.registry.inbound[LOOP]
    with contract.faulting_cipher(store) as fault:
        fault.seal_error = _seal_error(outage)
        with pytest.raises(Exception) as caught:
            await step._process_response_item(LOOP, item)
    _assert_clean(caught.value, outage)
    # Nothing was written: the step's caller, the fault arm, re-pends it.
    assert await _status(store, item.id) == OutboxStatus.INFLIGHT.value


@pytest.mark.parametrize("outage", [True, False], ids=["outage", "verdict"])
async def test_a_failed_seal_in_the_unstorable_dead_letter_leaves_clean(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, outage: bool
) -> None:
    """Item 1: an unstorable reply (a lone surrogate, BACKLOG #5616) is dead-lettered, and that
    seal can fail with the reply in the step's frame. No frame of what escapes may hold it."""
    _, item = await _head(store)

    async def _read(row_id: str) -> str | None:
        return f'{{"a": "{REPLY_MARK}\udc80"}}'

    monkeypatch.setattr(store, "response_body_for_work_row", _read)
    step = contract.runner(store)
    with contract.faulting_cipher(store) as fault:
        fault.seal_error = _seal_error(outage)
        with pytest.raises(Exception) as caught:
            await step._process_response_item(LOOP, item)
    _assert_clean(caught.value, outage)
    assert await _status(store, item.id) == OutboxStatus.INFLIGHT.value


async def test_a_verdict_seal_in_the_handoff_leaves_clean(store: MessageStore) -> None:
    """Item 2: a seal in the handoff that counts as a verdict, a Vault 400 for example, is
    re-raised by the store as it is. The step boundary names it by type. Armed after the step's
    own read, so the handoff is what seals. CONTROL: the token hands off once the fault clears."""
    _, item = await _head(store)
    step = contract.runner(store)
    real_handoff = store.ingress_handoff
    with contract.faulting_cipher(store) as fault:

        async def armed_handoff(**kwargs: Any) -> bool:
            fault.seal_error = _seal_error(outage=False)
            produced: bool = await real_handoff(**kwargs)
            return produced

        store.ingress_handoff = armed_handoff  # type: ignore[method-assign]
        try:
            with pytest.raises(Exception) as caught:
                await step._process_response_item(LOOP, item)
        finally:
            del store.ingress_handoff
        _assert_clean(caught.value, outage=False)
        fault.heal()
        await step._process_response_item(LOOP, item)
    assert len(await children(_fetch(store))) == 1


def _fetch(store: MessageStore) -> contract.RawFetch:
    async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        cur = await store._db.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]

    return fetch


async def test_a_failed_pooled_reply_buildup_check_logs_no_driver_text(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Item 3: the pooled reply lane's build-up check, after a handed-off token, logs a failed
    store read as the per-lane check does, as a redacted stand-in. ``_pooled_maybe_buildup``'s
    ``log.exception`` wrote the driver's raw text."""
    _, item = await _head(store)
    step = contract.runner(store)

    async def _broken(name: str, *, stage: str = "") -> tuple[int, float | None]:
        raise sqlite3.OperationalError(f"driver text quoting {REPLY_MARK}")

    monkeypatch.setattr(store, "pending_depth", _broken)
    with caplog.at_level(logging.DEBUG):
        await step._dispatch_response(LOOP, item)
    failed = [r for r in caplog.records if "build-up check failed" in r.getMessage()]
    assert failed, [r.getMessage() for r in caplog.records]  # CONTROL: the check ran and failed
    assert REPLY_MARK not in caplog.text
