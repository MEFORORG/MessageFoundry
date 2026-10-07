# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: an operator mutation and its audit row commit together (BACKLOG #2624).

Replay, dead-letter replay, purge (``cancel_queued``), resend, the edit-and-resubmit re-ingress and
the upload inject each take an :data:`~messagefoundry.store.store.OperatorAudit`. The store appends
the row it builds inside the mutation's own transaction. Before #2624 the API wrote the row in a
second transaction, so a crash between the two kept the change and lost who made it.

Each case runs twice. First the audit append is made to fail, and the case asserts the store change
rolled back with it: neither committed. Then it runs clean and asserts both committed, the row
carrying the actor, channel and client the caller gave. The failing leg alone would also pass a store
that never called the audit at all, so the clean leg is the control that makes it mean something.

The fault is injected at ``_append_audit_row``, the one append every backend's audited writes go
through. Its action argument is matched by value, so the same wrapper fits all three signatures.

Deliberately **extra-free**, like ``_pending_approval_store_contract``: the live server legs import it
inside a test function. Every name it writes is unique per run, so a shared server database is safe.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any
from uuid import uuid4

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store.store import AuditAppend

_RAW = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01|MSG0001|P|2.5\r"
    "PID|1||12345^^^HOSP^MR||DOE^JANE\r"
)
_CLIENT = "10.0.0.24"


class AppendFailed(RuntimeError):
    """The fault this contract injects into the audit append."""


@contextmanager
def failing_append(store: Any, action: str) -> Iterator[None]:
    """Make ``store``'s audit append raise for ``action``, and only for it."""
    real = store._append_audit_row

    async def _append(*args: Any, **kwargs: Any) -> Any:
        if action in args:
            raise AppendFailed(action)
        return await real(*args, **kwargs)

    store._append_audit_row = _append
    try:
        yield
    finally:
        del store._append_audit_row


def _builder(action: str, channel_id: str | None) -> Callable[[Any], AuditAppend | None]:
    """An audit that records every result it is handed, so a zero is visible too."""

    def _row(result: Any) -> AuditAppend:
        return AuditAppend(
            action,
            actor="contract-op",
            channel_id=channel_id,
            detail=json.dumps({"result": str(getattr(result, "status", result))}),
            client=_CLIENT,
        )

    return _row


async def _statuses(store: Any, message_id: str) -> dict[str, str]:
    return {
        str(r["destination_name"]): str(r["status"]) for r in await store.outbox_for(message_id)
    }


async def _seed(store: Any, channel: str, dest: str, *, settle: str | None) -> str:
    """One message with one outbound row to ``dest``, left pending, dead or done."""
    mid = str(await store.enqueue_message(channel_id=channel, raw=_RAW, deliveries=[(dest, _RAW)]))
    if settle is not None:
        items = await store.claim_ready(channel_id=channel, destination_name=dest)
        assert [i.message_id for i in items] == [mid]
        if settle == "dead":
            await store.mark_failed(items[0].id, "boom", RetryPolicy(max_attempts=1))
        else:
            await store.mark_done(items[0].id)
    assert (await _statuses(store, mid)) == {dest: settle or "pending"}
    return mid


async def _rows(store: Any, action: str) -> list[Any]:
    return list(await store.list_audit(action=action, limit=10))


async def _check(
    store: Any,
    *,
    label: str,
    channel: str | None,
    run: Callable[[Callable[[Any], AuditAppend | None]], Awaitable[Any]],
    unchanged: Callable[[], Awaitable[None]],
    changed: Callable[[Any], Awaitable[None]],
) -> None:
    action = f"contract.{label}.{uuid4().hex[:8]}"
    audit = _builder(action, channel)
    with failing_append(store, action), pytest.raises(AppendFailed):
        await run(audit)
    await unchanged()
    assert await _rows(store, action) == [], f"{label}: a failed append left its row"
    result = await run(audit)
    await changed(result)
    rows = await _rows(store, action)
    assert len(rows) == 1, f"{label}: the clean run committed {len(rows)} audit rows"
    row = rows[0]
    assert (row["actor"], row["channel_id"], row["client"]) == ("contract-op", channel, _CLIENT)


async def assert_operator_audit_atomic(store: Any) -> None:
    """Every operator mutation commits its audit row with its change, or neither."""
    tag = uuid4().hex[:8]
    ch, dest, alt = f"IB_C{tag}", f"OB_C{tag}", f"OB_ALT{tag}"

    # --- replay: a dead row is re-pended
    mid = await _seed(store, ch, dest, settle="dead")

    async def replay_unchanged() -> None:
        assert await _statuses(store, mid) == {dest: "dead"}

    async def replay_changed(n: Any) -> None:
        assert n == 1 and await _statuses(store, mid) == {dest: "pending"}

    await _check(
        store,
        label="replay",
        channel=ch,
        run=lambda audit: store.replay(mid, audit=audit),
        unchanged=replay_unchanged,
        changed=replay_changed,
    )

    # --- replay_dead: the bulk dead-letter replay. Each seed takes its own outbound, so a claim sees
    # only the row it seeded.
    dead_dest = f"OB_D{tag}"
    dead_mid = await _seed(store, ch, dead_dest, settle="dead")

    async def dead_unchanged() -> None:
        assert await _statuses(store, dead_mid) == {dead_dest: "dead"}

    async def dead_changed(n: Any) -> None:
        assert n == 1 and await _statuses(store, dead_mid) == {dead_dest: "pending"}

    await _check(
        store,
        label="replay_dead",
        channel=ch,
        run=lambda audit: store.replay_dead(channel_id=ch, destination_name=dead_dest, audit=audit),
        unchanged=dead_unchanged,
        changed=dead_changed,
    )

    # --- cancel_queued (purge): pending rows to an outbound are cancelled
    purge_dest = f"OB_P{tag}"
    purge_mid = await _seed(store, ch, purge_dest, settle=None)

    async def purge_unchanged() -> None:
        assert await _statuses(store, purge_mid) == {purge_dest: "pending"}

    async def purge_changed(n: Any) -> None:
        assert n == 1 and await _statuses(store, purge_mid) == {purge_dest: "cancelled"}

    await _check(
        store,
        label="cancel_queued",
        channel=None,
        run=lambda audit: store.cancel_queued(None, purge_dest, audit=audit),
        unchanged=purge_unchanged,
        changed=purge_changed,
    )
    # A purge that cancels nothing still records itself (BACKLOG #1641), and still in one commit.
    zero_action = f"contract.cancel_zero.{tag}"
    assert await store.cancel_queued(None, purge_dest, audit=_builder(zero_action, None)) == 0
    assert len(await _rows(store, zero_action)) == 1

    # --- resend_to: a delivered body goes to an alternate outbound
    done_dest = f"OB_S{tag}"
    done_mid = await _seed(store, ch, done_dest, settle="done")
    key = f"contract-resend-{tag}"

    async def resend_unchanged() -> None:
        assert await _statuses(store, done_mid) == {done_dest: "done"}

    async def resend_changed(outcome: Any) -> None:
        # "resent", not "duplicate": the failed run's idempotency claim rolled back with it.
        assert outcome.status == "resent"
        assert await _statuses(store, done_mid) == {done_dest: "done", alt: "pending"}

    await _check(
        store,
        label="resend_to",
        channel=ch,
        run=lambda audit: store.resend_to(
            message_id=done_mid, to=alt, idempotency_key=key, audit=audit
        ),
        unchanged=resend_unchanged,
        changed=resend_changed,
    )

    # --- reingress: an edited body re-enters the origin channel as a new message
    origin_ch = f"IB_R{tag}"
    origin = await _seed(store, origin_ch, dest, settle=None)
    edited = _RAW.replace("DOE^JANE", "DOE^JOAN")

    async def count(channel: str) -> int:
        return int(await store.count_messages(channel_id=channel, allowed_channels=None))

    async def reingress_unchanged() -> None:
        assert await count(origin_ch) == 1

    async def reingress_changed(outcome: Any) -> None:
        assert outcome.status == "resubmitted" and await count(origin_ch) == 2

    await _check(
        store,
        label="reingress",
        channel=origin_ch,
        run=lambda audit: store.reingress(
            origin_message_id=origin,
            raw=edited,
            idempotency_key=f"contract-reingress-{tag}",
            audit=audit,
        ),
        unchanged=reingress_unchanged,
        changed=reingress_changed,
    )

    # --- enqueue_ingress with an audit: the upload inject
    inject_ch = f"IB_I{tag}"

    async def inject_unchanged() -> None:
        assert await count(inject_ch) == 0

    async def inject_changed(new_mid: Any) -> None:
        assert await count(inject_ch) == 1
        assert (await store.get_message(new_mid)) is not None

    await _check(
        store,
        label="inject",
        channel=inject_ch,
        run=lambda audit: store.enqueue_ingress(
            channel_id=inject_ch, raw=_RAW, source_type="upload", audit=audit
        ),
        unchanged=inject_unchanged,
        changed=inject_changed,
    )

    # The rows joined the hash chain the way record_audit's do: the chain still verifies.
    ok, message = await store.verify_audit_chain()
    assert ok, message
