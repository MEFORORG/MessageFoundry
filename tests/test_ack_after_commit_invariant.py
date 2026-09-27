# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1608: failure-injection guards for the ACK-after-commit invariant.

CLAUDE.md section 2 states the promise these tests pin -- the inbound connection is ACKed only after
the raw message is durably committed to the ingress stage, and every received message is persisted
before that ACK. Read it there; this cites it rather than restating the reasoning.

The shipped runner honours both. Nothing exercised the FAILURE side, so a change that moved the ACK
ahead of the commit -- or that swallowed a commit failure and ACKed anyway -- would go green all the
way to a merge, and the first deployment would inherit an engine that can tell a sender "I have your
message" over a store that never took it.

Each test injects a store failure and asserts three things:

1. no AA ACK (or, on the HTTP path, no receipt id) goes back to the sender,
2. nothing durable lands, and
3. the failure propagates instead of being swallowed.

All three earn their place, measured against three deliberate breaks: moving the ACK ahead of the
commit trips (1); swallowing the commit failure and returning a receipt trips (1); swallowing an
ERROR-branch write failure and NAKing anyway trips only (3), because a swallow on a reject path
never produces an AA.

Two injection DEPTHS, because they prove different things and neither substitutes for the other:

* Replacing a whole store METHOD (the first three tests) runs no SQL at all. It proves ACK ordering
  and catches a fallback write, but it cannot prove the commit is atomic -- zero rows is partly a
  property of the stub. The docstrings below do not claim otherwise.
* Failing the underlying COMMIT (the fourth test) runs the store's real SQL and then denies it the
  commit, so the rollback is genuine and "nothing durable landed" is a real measurement. It is read
  back through a SECOND store handle on the same file, which is the only instrument that answers
  "durable" rather than "visible to the connection that wrote it".

Every injected arm is paired with an UNPATCHED control over the same body. An assertion that
something is ABSENT passes for free when the body was never going to produce it, so the control is
what makes the absence attributable to the injection rather than to a malformed message.
"""

from __future__ import annotations

from collections.abc import Awaitable
from pathlib import Path
from typing import Any, NoReturn

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore

_INBOUND = "IB_HL7"


class _InjectedStoreFailure(RuntimeError):
    """The injected fault. ``_outcome`` catches only this, so an unrelated error still surfaces."""


# Synthetic HL7 only (never real PHI). The good body parses and needs no strict validation, so the
# ONLY thing between it and an AA ACK is the ingress commit -- which is what gets injected.
_HL7_OK = b"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|MSG1|P|2.5\rPID|1||MRN1^^^H^MR||Doe^Jane\r"
# No MSH, so Peek.parse rejects it and the handler takes the parse-error branch -- the
# record_received site under test in the third pair.
_HL7_MALFORMED = b"NOTHL7|this body has no MSH header\r"

# Distinguishes "the handler raised" from "the handler returned None". Collapsing the two would hide
# the swallow-and-ACK defect, which is the subject here.
_RAISED = object()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """The store file. A FILE, not ``:memory:``, because the commit-failure test reads durability back
    through a second handle on this same path."""
    return tmp_path / "engine.db"


@pytest.fixture
async def store(db_path: Path):
    s = await MessageStore.open(db_path)
    yield s
    await s.close()


@pytest.fixture
def inbound(store: MessageStore) -> tuple[RegistryRunner, InboundConnection]:
    """The runner and the one inbound connection every test drives."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name=_INBOUND,
            spec=ConnectionSpec(ConnectorType.FILE, {}),
            router="r",
            content_type=ContentType.HL7V2,
        )
    )
    reg.add_router("r", lambda m: [])  # no worker runs, so routing is never reached
    return RegistryRunner(reg, store), reg.inbound[_INBOUND]


async def _raise_injected(*args: Any, **kwargs: Any) -> NoReturn:
    """Stand in for a store write that fails. Accepts any signature so a call-convention change in the
    runner cannot redden these tests for a reason unrelated to the invariant."""
    raise _InjectedStoreFailure("injected store failure at the ingress commit boundary")


async def _outcome(call: Awaitable[str | None]) -> object:
    """Await ``call`` and return what it produced, or ``_RAISED`` if the injected failure propagated."""
    try:
        return await call
    except _InjectedStoreFailure:
        return _RAISED


def _has_msa(value: object, code: str) -> bool:
    """Whether ``value`` is an ORIGINAL-mode ACK frame carrying ``MSA|<code>`` (transports/mllp)."""
    return isinstance(value, str) and f"MSA|{code}" in value


async def _counts(store: MessageStore) -> tuple[int, int]:
    """``(messages rows, in-pipeline queue rows)``.

    Public store counters, not raw SQL against ``store._db``: they read the same on every backend, so
    this file can move onto the backend-parametrized fixture later without a rewrite, and a schema
    rename reddens it with an assertion rather than an OperationalError. A freshly committed ingress
    row is ``pending``, so ``in_pipeline_depth`` sees it; no worker runs here to move it past that.
    """
    return await store.count_messages(), await store.in_pipeline_depth()


# --- 1. MLLP/HL7 path: enqueue_ingress fails ------------------------------------------------------


async def test_mllp_ingress_commit_failure_sends_no_aa_and_persists_nothing(
    inbound: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, ic = inbound
    monkeypatch.setattr(store, "enqueue_ingress", _raise_injected)

    outcome = await _outcome(runner._handle_inbound(ic, _HL7_OK))

    assert not _has_msa(outcome, "AA"), "an AA ACK went back to the sender though the commit failed"
    # No SQL ran, so this is not an atomicity proof (see the module docstring). It still catches a
    # handler that answered a failed commit with a consolation write of its own.
    assert await _counts(store) == (0, 0), "a row landed though the ingress commit failed"
    # Propagation is what lets the transport answer with a NAK (BACKLOG #1619) so the sender resends.
    assert outcome is _RAISED, "the commit failure was swallowed instead of propagating"


async def test_control_mllp_ingress_commit_succeeds_acks_aa_and_persists(
    inbound: tuple[RegistryRunner, InboundConnection], store: MessageStore
) -> None:
    runner, ic = inbound

    ack = await runner._handle_inbound(ic, _HL7_OK)

    assert _has_msa(ack, "AA")
    assert await _counts(store) == (1, 1)


# --- 2. HTTP path: enqueue_ingress fails ----------------------------------------------------------


async def test_http_ingress_commit_failure_returns_no_receipt_and_persists_nothing(
    inbound: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, ic = inbound
    monkeypatch.setattr(store, "enqueue_ingress", _raise_injected)

    outcome = await _outcome(runner._handle_inbound_http(ic, _HL7_OK))

    # HTTP's receipt is the engine message_id the source maps to a 202-with-id (ADR 0023 D3). An id
    # handed back over an empty store is the same defect as an AA over an empty store.
    assert not isinstance(outcome, str), "a receipt id came back though the commit failed"
    assert await _counts(store) == (0, 0), "a row landed though the ingress commit failed"
    assert outcome is _RAISED, "the commit failure was swallowed instead of propagating"


async def test_control_http_ingress_commit_succeeds_returns_receipt_and_persists(
    inbound: tuple[RegistryRunner, InboundConnection], store: MessageStore
) -> None:
    runner, ic = inbound

    mid = await runner._handle_inbound_http(ic, _HL7_OK)

    assert isinstance(mid, str) and mid
    assert await _counts(store) == (1, 1)


# --- 3. Error branch: record_received fails -------------------------------------------------------
#
# The count-and-log invariant covers the rejection path too: a message the engine refuses is still
# recorded with an ERROR disposition BEFORE the NAK. If that write fails, the sender must not be
# handed any frame at all -- least of all an AA, which would claim a receipt the store never took.


async def test_error_branch_record_failure_sends_no_ack_and_persists_nothing(
    inbound: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, ic = inbound
    monkeypatch.setattr(store, "record_received", _raise_injected)

    outcome = await _outcome(runner._handle_inbound(ic, _HL7_MALFORMED))

    assert not _has_msa(outcome, "AA"), "an AA ACK went back though the ERROR write failed"
    assert await _counts(store) == (0, 0), "a row landed though the ERROR write failed"
    # Stronger than "not AA": no frame at all. The control below shows this body earns an AR when the
    # write succeeds, so an AR here would mean the engine NAK'd a message it never recorded.
    assert outcome is _RAISED, "the ERROR write failure was swallowed instead of propagating"


async def test_control_error_branch_records_error_and_naks_ar(
    inbound: tuple[RegistryRunner, InboundConnection], store: MessageStore
) -> None:
    runner, ic = inbound

    ack = await runner._handle_inbound(ic, _HL7_MALFORMED)

    assert _has_msa(ack, "AR")
    # One ERROR row, no queue row: a rejected message is recorded, never handed to the ingress stage.
    assert await _counts(store) == (1, 0)
    assert await store.count_messages(status=MessageStatus.ERROR.value) == 1


# --- 4. The commit itself fails -------------------------------------------------------------------
#
# The deepest arm, and the only one whose "nothing durable landed" half is a real measurement. The
# store's own SQL runs and is then denied its commit (the shape tests/test_response_capture.py uses
# for the same class of crash window), so the rollback under test is the engine's, not a stub's.


async def test_ingress_rollback_on_commit_failure_sends_no_aa_and_nothing_is_durable(
    inbound: tuple[RegistryRunner, InboundConnection],
    store: MessageStore,
    db_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, ic = inbound
    real_commit = store._db.commit
    state = {"failed": False}

    async def flaky_commit() -> None:
        # Fail the FIRST commit only -- enqueue_ingress's. Later commits (the fixture's close, any
        # read bookkeeping) must work, so teardown cannot fail for a reason unrelated to this test.
        if not state["failed"]:
            state["failed"] = True
            raise _InjectedStoreFailure("simulated crash before the ingress commit")
        await real_commit()

    monkeypatch.setattr(store._db, "commit", flaky_commit)

    outcome = await _outcome(runner._handle_inbound(ic, _HL7_OK))

    assert state["failed"], "the injection never fired; enqueue_ingress issued no commit"
    assert not _has_msa(outcome, "AA"), "an AA ACK went back though the ingress commit failed"
    assert outcome is _RAISED, "the commit failure was swallowed instead of propagating"

    # Durability read through a SECOND handle on the same file. The writing connection can see its own
    # uncommitted rows, so reading back through `store` would answer a weaker question than "durable".
    other = await MessageStore.open(db_path)
    try:
        assert await _counts(other) == (0, 0), "a row survived the failed ingress commit"
    finally:
        await other.close()


async def test_control_ingress_commit_is_durable_to_a_second_handle(
    inbound: tuple[RegistryRunner, InboundConnection], db_path: Path
) -> None:
    # Anti-vacuity for the test above: without the injection the same body IS durable to a second
    # handle, so the zero there is the failed commit and not the instrument failing to see anything.
    runner, ic = inbound

    assert _has_msa(await runner._handle_inbound(ic, _HL7_OK), "AA")

    other = await MessageStore.open(db_path)
    try:
        assert await _counts(other) == (1, 1)
    finally:
        await other.close()
