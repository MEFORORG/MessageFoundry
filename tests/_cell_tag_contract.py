# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for the message and preset cell tags (BACKLOG #2593).

Extra-free, on the ``_queue_tag_contract`` precedent: it imports nothing optional, so the live
Postgres and SQL Server suites import it inside their test functions and run the same assertions on
legs that install only their own driver extra.

The caller passes a store opened with a store key under the cell-bound writer (``write_v2=True``),
and two adapters for the same database that bypass the store: ``raw`` runs one statement and commits,
and ``fetch`` runs one query and returns its rows as dicts. Both take SQL written with ``?``
placeholders; each backend's adapter respells them for its driver.

Every refused read has a control beside it: the same kind of row, left alone, reads. A tag that
refused everything, or bound nothing, fails this contract.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

from messagefoundry.store.cell_tag import (
    MESSAGE_TAG_FAILED_ACTION,
    PRESET_TAG_FAILED_ACTION,
    CellTagError,
)
from messagefoundry.store.content_search import make_spec
from messagefoundry.store.crypto import CipherError, generate_key, make_cipher
from messagefoundry.store.store import MessageStatus, OutboxStatus, Stage
from tests._store_audit import no_operator_audit

#: Runs one statement with ``?`` placeholders against the store's database, outside the store.
RawSql = Callable[[str, tuple[Any, ...]], Awaitable[None]]
#: Runs one query with ``?`` placeholders outside the store and returns its rows as dicts.
RawFetch = Callable[[str, tuple[Any, ...]], Awaitable[list[dict[str, Any]]]]

_RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|CT1|P|2.5.1\rPID|1||SYNTH-200||DOE^JOHN\r"
#: Keys and owners the contract mints carry this, so a rerun on a database that kept the last
#: run's rows does not collide with them.
_RUN = uuid4().hex[:8]
_META = json.dumps({"user": {"k": "SYNTH-META"}})


class _Hook:
    """Records each tag-failure alert the store's cipher raises."""

    def __init__(self) -> None:
        self.alerts: list[tuple[str, str]] = []

    def __call__(self, table: str, reason: str) -> None:
        self.alerts.append((table, reason))

    def saw(self, table: str, row_id: str) -> bool:
        return any(t == table and row_id[:12] in r for t, r in self.alerts)


async def _message(store: Any, channel_id: str) -> str:
    return str(
        await store.record_received(
            channel_id=channel_id,
            raw=_RAW,
            status=MessageStatus.ERROR,
            error="SYNTH-ERROR",
            summary="SYNTH-SUMMARY",
            metadata=_META,
        )
    )


async def _audited(fetch: RawFetch, action: str, row_id: str) -> int:
    rows = await fetch(
        "SELECT detail FROM audit_log WHERE action=? AND detail LIKE ?",
        (action, f"%{row_id[:12]}%"),
    )
    return len(rows)


async def _refused(call: Callable[[], Awaitable[Any]], label: str) -> None:
    try:
        await call()
    except Exception as exc:  # noqa: BLE001 -- the refusal type is the cipher's, asserted below
        assert "integrity" in str(exc), (label, exc)
    else:
        raise AssertionError(f"{label}: a read of a cell that fails its tag was not refused")


def _assert_reads(message: dict[str, Any] | None) -> None:
    assert message is not None
    assert message["raw"] == _RAW
    assert message["error"] == "SYNTH-ERROR"
    assert message["summary"] == "SYNTH-SUMMARY"
    assert message["metadata"] == _META


async def assert_cell_tag_contract(store: Any, raw: RawSql, fetch: RawFetch) -> None:
    """Drive the message and preset tags through their whole contract on ``store``'s backend."""
    cipher = store.cipher()
    assert cipher.encrypts, "the contract needs a store opened with a store key"
    hook = _Hook()
    cipher.set_tag_failure_hook(hook)

    # --- control: an untouched message reads in full ------------------------------------------
    ctl = await _message(store, f"IB_CT_A_{_RUN}")
    _assert_reads(await store.get_message(ctl))
    assert await store.message_metadata_json(ctl) == _META

    # --- a message moved to another channel is refused, alerted and audited ---------------------
    moved = await _message(store, f"IB_CT_B_{_RUN}")
    await raw("UPDATE messages SET channel_id=? WHERE id=?", (f"IB_CT_A_{_RUN}", moved))
    await _refused(lambda: store.get_message(moved), "get_message")
    assert hook.saw("messages", moved)
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, moved) == 1
    await _refused(lambda: store.message_metadata_json(moved), "message_metadata_json")
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, moved) == 2

    # The list still shows the moved row by its plaintext columns, its cells withheld; the
    # untouched row beside it lists in full.
    listed = {
        r["id"]: r
        for r in await store.list_messages(channel_id=f"IB_CT_A_{_RUN}", allowed_channels=None)
    }
    assert listed[ctl]["summary"] == "SYNTH-SUMMARY" and listed[ctl]["metadata"] == _META
    assert listed[moved]["summary"] is None and listed[moved]["error"] is None
    assert listed[moved]["metadata"] is None and listed[moved]["channel_id"] == f"IB_CT_A_{_RUN}"

    # Content search cannot match a moved row; the untouched row still matches.
    found = await store.search_messages(
        make_spec(content="SYNTH-200", field_path=None, field_value=None),
        channel_id=f"IB_CT_A_{_RUN}",
        allowed_channels=None,
    )
    found_ids = {r["id"] for r in found.rows}
    assert ctl in found_ids and moved not in found_ids, found_ids

    # --- a cell copied onto another row of the same channel is refused --------------------------
    m1 = await _message(store, f"IB_CT_C_{_RUN}")
    m2 = await _message(store, f"IB_CT_C_{_RUN}")
    cells = {
        r["id"]: r for r in await fetch("SELECT id, raw FROM messages WHERE id IN (?, ?)", (m1, m2))
    }
    await raw("UPDATE messages SET raw=? WHERE id=?", (cells[m2]["raw"], m1))
    await _refused(lambda: store.get_message(m1), "swapped raw")
    _assert_reads(await store.get_message(m2))  # control: the source row still reads

    # --- a dead-letter list keeps a moved message's row and withholds its summary ---------------
    dmid = await store.enqueue_message(
        channel_id=f"IB_CT_D_{_RUN}",
        raw=_RAW,
        summary="SYNTH-SUMMARY",
        deliveries=[(f"OB_CT_D_{_RUN}", "B")],
    )
    item = await store.claim_next_fifo(f"OB_CT_D_{_RUN}")
    assert item is not None
    await store.dead_letter_now(item.id, "synthetic permanent reject")
    dctl = await store.enqueue_message(
        channel_id=f"IB_CT_D_{_RUN}",
        raw=_RAW,
        summary="SYNTH-SUMMARY",
        deliveries=[(f"OB_CT_D_{_RUN}", "B")],
    )
    item = await store.claim_next_fifo(f"OB_CT_D_{_RUN}")
    assert item is not None
    await store.dead_letter_now(item.id, "synthetic permanent reject")
    await raw("UPDATE messages SET channel_id=? WHERE id=?", (f"IB_CT_E_{_RUN}", dmid))
    dead = {
        r["message_id"]: r
        for r in await store.list_dead(destination_name=f"OB_CT_D_{_RUN}", allowed_channels=None)
    }
    assert dead[dctl]["summary"] == "SYNTH-SUMMARY"  # control
    assert dead[dmid]["summary"] is None
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, dmid) == 1

    # --- an edit-and-resubmit from a moved origin is refused -----------------------------------
    outcome = await store.reingress(
        origin_message_id=ctl,
        raw=_RAW,
        idempotency_key=f"ct-reingress-ctl-{_RUN}",
        audit=no_operator_audit,
    )
    assert outcome.status != "duplicate"  # control: an untouched origin resubmits
    await _refused(
        lambda: store.reingress(
            origin_message_id=moved,
            raw=_RAW,
            idempotency_key=f"ct-reingress-moved-{_RUN}",
            audit=no_operator_audit,
        ),
        "reingress",
    )

    # --- a transform handoff on a moved message dead-letters the routed row --------------------
    await _assert_transform_handoff(store, raw, fetch, hook)

    # --- presets: one moved to another owner is refused ----------------------------------------
    await _assert_presets(store, raw, fetch, hook)

    # --- a cell under a key the store does not hold is withheld from a list --------------------
    await _assert_foreign_key_cells(store, raw)
    # --- a substituted cell under a held key still fails a list read loudly --------------------
    await _assert_substituted_listed_cells(store, raw, fetch)
    # --- the per-message detail reads withhold under the same narrow rule ---------------------
    await _assert_detail_reads(store, raw, fetch)
    # --- under Transit, only a refusal naming a key version withholds a listed cell ----------
    await _assert_transit_listed_refusals(store, raw, fetch)


#: Vault's 400 texts for a Transit data-key decrypt, read 2026-11-19 from Vault ``main``
#: (``sdk/helper/keysutil/policy.go``, ``builtin/logical/transit/path_decrypt.go``). The first
#: two name a retired or unknown key version, so a list withholds the cell; the rest are a
#: missing configured key or a malformed, truncated or rewritten cell, which must fail the list
#: read (BACKLOG #5970, owner ruling 2026-11-19).
_TRANSIT_KEY_REFUSALS = (
    "ciphertext or signature version is disallowed by policy (too old)",
    "invalid ciphertext: version is too new",
)
_TRANSIT_LOUD_REFUSALS = (
    "encryption key not found",
    "invalid ciphertext: could not decode base64",
    "invalid ciphertext length",
    "invalid ciphertext: version number could not be decoded",
    "invalid ciphertext: wrong number of fields",
    "invalid ciphertext: no prefix",
)


class _TransitShaped:
    """The store's own cipher, shown to the store as the Vault Transit cipher is: it names no keys
    (no ``holds_key_for``, ``names_no_keys``), and each planted value is refused with the error
    :class:`~messagefoundry.store.crypto_transit.TransitCipher` raises for Vault's 400 with that
    text. Every other value goes to the real cipher, so the rest of the store still reads."""

    names_no_keys = True

    def __init__(self, real: Any, refusal: Callable[[str], CipherError]) -> None:
        self._real = real
        self._refusal = refusal
        self.planted: dict[str, str] = {}

    def __getattr__(self, name: str) -> Any:
        if name in ("holds_key_for", "named_key_id"):
            raise AttributeError(name)
        return getattr(self._real, name)

    def decrypt(self, stored: str, **kw: Any) -> str:
        if stored in self.planted:
            raise self._refusal(self.planted[stored])
        return self._real.decrypt(stored, **kw)


async def _assert_transit_listed_refusals(store: Any, raw: RawSql, fetch: RawFetch) -> None:
    """BACKLOG #5970, owner ruling 2026-11-19: under Transit a list read withholds a cell only
    where Vault's refusal names a retired or unknown key version. Any other refusal, such as the
    configured key not found, an invalid or truncated ciphertext or a ``vault:vN`` version that
    does not decode, fails the read on every list path: messages list, content search,
    ``queue.last_error``, ``connection_event.reason`` and ``alert_instance.reason``. Each planted
    cell is put back after, and each list has an untouched row beside it."""
    try:
        from hvac.exceptions import (  # type: ignore[import-untyped]  # noqa: PLC0415
            InvalidRequest,
        )
    except ImportError:
        return  # a leg without the [vault] extra cannot build Vault's 400
    from messagefoundry.store.crypto_transit import _transit_failure  # noqa: PLC0415

    def refusal(text: str) -> CipherError:
        try:
            raise InvalidRequest(errors=[text])
        except InvalidRequest as exc:
            error = _transit_failure("decrypt", "mefor-store", exc)
            error.__cause__ = exc
            return error

    real = store._cipher
    shaped = _TransitShaped(real, refusal)

    def plant(text: str) -> str:
        value = f"mfenc:v3:vault:v1:SYNTH-{uuid4().hex}"
        shaped.planted[value] = text
        return value

    ch, out = f"IB_CT_V_{_RUN}", f"OB_CT_V_{_RUN}"
    m, mctl = await _message(store, ch), await _message(store, ch)
    for _ in range(2):
        await store.enqueue_message(channel_id=f"IB_CT_Y_{_RUN}", raw=_RAW, deliveries=[(out, "B")])
        item = await store.claim_next_fifo(out)
        assert item is not None
        await store.dead_letter_now(item.id, "synthetic permanent reject")
    qa, qb = [
        r["outbox_id"] for r in await store.list_dead(destination_name=out, allowed_channels=None)
    ]
    planted, kept = f"IB_CT_W_{_RUN}", f"IB_CT_X_{_RUN}"
    for conn in (planted, kept):
        await store.record_connection_event(
            connection=conn, transport="mllp", direction="in", kind="closed", reason="SYNTH-REASON"
        )
        await store.upsert_alert_instance(
            event_type="connection_error", connection=conn, severity="warning", reason="SYNTH-ALERT"
        )
    [summary] = [r["summary"] for r in await fetch("SELECT summary FROM messages WHERE id=?", (m,))]
    [last_error] = [
        r["last_error"] for r in await fetch("SELECT last_error FROM queue WHERE id=?", (qa,))
    ]
    reasons = {
        table: next(
            r["reason"]
            for r in await fetch(
                f"SELECT reason FROM {table} WHERE connection=?",  # noqa: S608
                (planted,),
            )
        )
        for table in ("connection_event", "alert_instance")
    }

    async def messages_list() -> list[dict[str, Any]]:
        return list(await store.list_messages(channel_id=ch, allowed_channels=None))

    async def content_search() -> list[dict[str, Any]]:
        spec = make_spec(content="SYNTH-200", field_path=None, field_value=None)
        return list((await store.search_messages(spec, channel_id=ch, allowed_channels=None)).rows)

    async def dead_list() -> list[dict[str, Any]]:
        return list(await store.list_dead(destination_name=out, allowed_channels=None))

    async def events() -> list[Any]:
        return list(await store.list_connection_events(connection=planted, allowed_channels=None))

    async def alerts() -> list[Any]:
        found = await store.list_active_alert_instances(allowed_channels=[planted, kept])
        return [a for a in found if a.connection in (planted, kept)]

    # (the statement that plants and puts back, its row, the put-back parameters, the list read)
    cases: list[
        tuple[str, tuple[Any, ...], tuple[Any, ...], Callable[[], Awaitable[list[Any]]]]
    ] = [
        ("UPDATE messages SET summary=? WHERE id=?", (m,), (summary, m), messages_list),
        ("UPDATE messages SET summary=? WHERE id=?", (m,), (summary, m), content_search),
        ("UPDATE queue SET last_error=? WHERE id=?", (qa,), (last_error, qa), dead_list),
        (
            "UPDATE connection_event SET reason=? WHERE connection=?",
            (planted,),
            (reasons["connection_event"], planted),
            events,
        ),
        (
            "UPDATE alert_instance SET reason=? WHERE connection=?",
            (planted,),
            (reasons["alert_instance"], planted),
            alerts,
        ),
    ]
    store._cipher = shaped
    try:
        for sql, where, put_back, read in cases:
            for text in (*_TRANSIT_KEY_REFUSALS, *_TRANSIT_LOUD_REFUSALS):
                loud = text in _TRANSIT_LOUD_REFUSALS
                await raw(sql, (plant(text), *where))
                try:
                    rows = await read()
                except CellTagError as exc:
                    raise AssertionError(
                        f"{read.__name__}: {text!r} read as a tag failure"
                    ) from exc
                except CipherError:
                    assert loud, f"{read.__name__}: a key refusal failed the read: {text!r}"
                    continue
                finally:
                    await raw(sql, put_back)
                assert not loud, f"{read.__name__}: {text!r} was withheld, not refused"
                _assert_withheld(read.__name__, rows, m=m, mctl=mctl, qa=qa, qb=qb)
    finally:
        store._cipher = real
    # Control: with the cells put back every list reads in full again.
    assert {r["id"]: r for r in await messages_list()}[m]["summary"] == "SYNTH-SUMMARY"
    assert all(r["last_error"] is not None for r in await dead_list())
    assert [e.reason for e in await events()] == ["SYNTH-REASON"]
    assert {a.reason for a in await alerts()} == {"SYNTH-ALERT"}


def _assert_withheld(name: str, rows: list[Any], *, m: str, mctl: str, qa: str, qb: str) -> None:
    """The planted cell is withheld and its untouched sibling reads (the control)."""
    if name == "messages_list":
        listed = {r["id"]: r for r in rows}
        assert listed[m]["summary"] is None and listed[mctl]["summary"] == "SYNTH-SUMMARY"
    elif name == "content_search":
        assert {r["id"] for r in rows} == {mctl}
    elif name == "dead_list":
        listed = {r["outbox_id"]: r for r in rows}
        assert listed[qa]["last_error"] is None and listed[qb]["last_error"] is not None
    elif name == "events":
        assert [e.reason for e in rows] == [None]
    else:
        assert sorted((a.reason or "") for a in rows) == ["", "SYNTH-ALERT"]


async def _assert_foreign_key_cells(store: Any, raw: RawSql) -> None:
    """BACKLOG #5969, #5970: a cell sealed under a key the store does not hold raises a plain
    :class:`CipherError`, not a tag failure. A by-id read still raises it, for the API to answer;
    a list withholds that row's cell and lists the rest, where it used to fail the whole page.
    Each list has an untouched row beside the planted one as its control."""
    foreign = make_cipher(generate_key(), write_v2=True).encrypt("SYNTH-FOREIGN")
    ch = f"IB_CT_F_{_RUN}"

    # The scope read opens no cell, so it answers for a message whose cells cannot be opened.
    fm = await _message(store, ch)
    fctl = await _message(store, ch)
    assert await store.message_channel_id(fm) == ch
    assert await store.message_channel_id(f"no-such-{_RUN}") is None
    await raw("UPDATE messages SET summary=? WHERE id=?", (foreign, fm))
    try:
        await store.get_message(fm)
    except CellTagError as exc:
        raise AssertionError("a foreign-key cell read as a tag failure") from exc
    except CipherError:
        pass
    else:
        raise AssertionError("a foreign-key cell was opened")
    listed = {r["id"]: r for r in await store.list_messages(channel_id=ch, allowed_channels=None)}
    assert listed[fctl]["summary"] == "SYNTH-SUMMARY"  # control
    assert listed[fm]["summary"] is None and listed[fm]["error"] is None
    assert listed[fm]["metadata"] is None
    # Content search leaves the row out, as it does a failed tag, and still finds its sibling.
    found = await store.search_messages(
        make_spec(content="SYNTH-200", field_path=None, field_value=None),
        channel_id=ch,
        allowed_channels=None,
    )
    assert {r["id"] for r in found.rows} == {fctl}

    # Dead letters: a foreign last_error is withheld; the row and its sibling still list.
    out = f"OB_CT_F_{_RUN}"
    for _ in range(2):
        await store.enqueue_message(channel_id=ch, raw=_RAW, deliveries=[(out, "B")])
        item = await store.claim_next_fifo(out)
        assert item is not None
        await store.dead_letter_now(item.id, "synthetic permanent reject")
    dead = await store.list_dead(destination_name=out, allowed_channels=None)
    assert len(dead) == 2
    await raw("UPDATE queue SET last_error=? WHERE id=?", (foreign, dead[0]["outbox_id"]))
    reread = {
        r["outbox_id"]: r
        for r in await store.list_dead(destination_name=out, allowed_channels=None)
    }
    assert reread[dead[0]["outbox_id"]]["last_error"] is None
    assert reread[dead[1]["outbox_id"]]["last_error"] is not None  # control

    # Connection events and alert instances: a foreign reason is withheld, its sibling reads.
    planted, kept = f"IB_CT_G_{_RUN}", f"IB_CT_H_{_RUN}"
    for conn in (planted, kept):
        await store.record_connection_event(
            connection=conn, transport="mllp", direction="in", kind="closed", reason="SYNTH-REASON"
        )
        await store.upsert_alert_instance(
            event_type="connection_error", connection=conn, severity="warning", reason="SYNTH-ALERT"
        )
    await raw("UPDATE connection_event SET reason=? WHERE connection=?", (foreign, planted))
    await raw("UPDATE alert_instance SET reason=? WHERE connection=?", (foreign, planted))
    for conn, want in ((planted, None), (kept, "SYNTH-REASON")):
        [event] = await store.list_connection_events(connection=conn, allowed_channels=None)
        assert event.reason == want, conn
    alerts = {
        a.connection: a
        for a in await store.list_active_alert_instances(allowed_channels=None)
        if a.connection in (planted, kept)
    }
    assert alerts[planted].reason is None
    assert alerts[kept].reason == "SYNTH-ALERT"  # control
    # A by-id alert read (the ack, resolve, suspend and resume echoes) is not a list: the owner's
    # ruling covers list reads only, so it still raises on the cell, as before #5970.
    try:
        await store.get_alert_instance(alerts[planted].id, allowed_channels=None)
    except CellTagError as exc:
        raise AssertionError("a foreign-key alert reason read as a tag failure") from exc
    except CipherError:
        pass
    else:
        raise AssertionError("a by-id alert read withheld a reason the store's keys refused")
    echoed = await store.get_alert_instance(alerts[kept].id, allowed_channels=None)
    assert echoed is not None and echoed.reason == "SYNTH-ALERT"  # control


async def _assert_list_fails(read: Awaitable[object]) -> None:
    """The list read raises the cipher's own error, neither a tag error nor a withheld cell."""
    try:
        await read
    except CellTagError as exc:
        raise AssertionError(
            "a substituted cell on an untagged table read as a CellTagError"
        ) from exc
    except CipherError:
        return
    raise AssertionError("a substituted cell under a held key was withheld, not refused")


async def _assert_substituted_listed_cells(store: Any, raw: RawSql, fetch: RawFetch) -> None:
    """BACKLOG #5970 withholds only a key or format refusal. A cell copied from a sibling row,
    sealed under a key the store holds but for the sibling's cell, fails its tag: on the queue,
    connection_event and alert_instance tables, which have no tag-failed audit or alert, the list
    read still fails with the cipher's error, so the tamper is not hidden as a withheld cell. Each
    planted cell is put back after, so later lists on the same store still read."""
    ch, out = f"IB_CT_S_{_RUN}", f"OB_CT_S_{_RUN}"
    for _ in range(2):
        await store.enqueue_message(channel_id=ch, raw=_RAW, deliveries=[(out, "B")])
        item = await store.claim_next_fifo(out)
        assert item is not None
        await store.dead_letter_now(item.id, "synthetic permanent reject")
    a, b = [
        r["outbox_id"] for r in await store.list_dead(destination_name=out, allowed_channels=None)
    ]
    rows = {
        r["id"]: r["last_error"]
        for r in await fetch("SELECT id, last_error FROM queue WHERE id IN (?, ?)", (a, b))
    }
    await raw("UPDATE queue SET last_error=? WHERE id=?", (rows[b], a))
    await _assert_list_fails(store.list_dead(destination_name=out, allowed_channels=None))
    await raw("UPDATE queue SET last_error=? WHERE id=?", (rows[a], a))
    assert len(await store.list_dead(destination_name=out, allowed_channels=None)) == 2  # control

    planted, kept = f"IB_CT_T_{_RUN}", f"IB_CT_U_{_RUN}"
    for conn in (planted, kept):
        await store.record_connection_event(
            connection=conn, transport="mllp", direction="in", kind="closed", reason="SYNTH-REASON"
        )
        await store.upsert_alert_instance(
            event_type="connection_error", connection=conn, severity="warning", reason="SYNTH-ALERT"
        )
    for table in ("connection_event", "alert_instance"):
        sealed = {
            r["connection"]: r["reason"]
            for r in await fetch(
                f"SELECT connection, reason FROM {table} WHERE connection IN (?, ?)",  # noqa: S608
                (planted, kept),
            )
        }
        await raw(
            f"UPDATE {table} SET reason=? WHERE connection=?",  # noqa: S608
            (sealed[kept], planted),
        )
        await _assert_list_fails(
            store.list_connection_events(connection=planted, allowed_channels=None)
            if table == "connection_event"
            else store.list_active_alert_instances(allowed_channels=None)
        )
        await raw(
            f"UPDATE {table} SET reason=? WHERE connection=?",  # noqa: S608
            (sealed[planted], planted),
        )
    [event] = await store.list_connection_events(connection=planted, allowed_channels=None)
    assert event.reason == "SYNTH-REASON"  # control: the put-back cell opens
    assert any(
        a.connection == planted and a.reason == "SYNTH-ALERT"
        for a in await store.list_active_alert_instances(allowed_channels=None)
    )


async def _assert_detail_reads_fail(store: Any, mid: str, *reads: str) -> None:
    """Each named per-message read raises the cipher's own error, and withholds nothing."""
    for name in reads:
        await _assert_list_fails(getattr(store, name)(mid))


async def _assert_detail_reads(store: Any, raw: RawSql, fetch: RawFetch) -> None:
    """BACKLOG #5693, owner ruling 2026-11-22: ``outbox_for``, ``outbox_payloads_for`` and
    ``events_for`` withhold a ``last_error`` or event ``detail`` only for a key the store does not
    hold, and say so on the row. A substituted, malformed or unknown-format cell still raises, and
    a message body under a key the store does not hold still refuses. Each planted cell is put
    back, so the untouched read is the control."""
    foreign = make_cipher(generate_key(), write_v2=True).encrypt("SYNTH-FOREIGN")
    ch, a_out, b_out = f"IB_CT_D_{_RUN}", f"OB_CT_DA_{_RUN}", f"OB_CT_DB_{_RUN}"
    mid = await store.enqueue_message(
        channel_id=ch, raw=_RAW, deliveries=[(a_out, "BODY-A"), (b_out, "BODY-B")]
    )
    other = await store.enqueue_message(channel_id=ch, raw=_RAW, deliveries=[(a_out, "BODY-C")])
    for out in (a_out, b_out, a_out):
        item = await store.claim_next_fifo(out)
        assert item is not None
        await store.dead_letter_now(item.id, "synthetic permanent reject")
    rows = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    a, b = rows[a_out]["id"], rows[b_out]["id"]
    assert rows[a_out]["last_error"] and not rows[a_out]["last_error_withheld"]  # control
    [sibling] = await fetch("SELECT last_error FROM queue WHERE id=?", (b,))
    [sealed] = await fetch("SELECT last_error FROM queue WHERE id=?", (a,))
    good = sealed["last_error"]

    await raw("UPDATE queue SET last_error=? WHERE id=?", (foreign, a))
    for name in ("outbox_for", "outbox_payloads_for"):
        got = {r["destination_name"]: r for r in await getattr(store, name)(mid)}
        assert got[a_out]["last_error"] is None and got[a_out]["last_error_withheld"] is True, name
        assert got[b_out]["last_error"] and got[b_out]["last_error_withheld"] is False, name
        if name == "outbox_payloads_for":
            assert got[a_out]["payload"] == "BODY-A"  # only last_error was withheld

    # A cell that was never written is empty, not withheld.
    await raw("UPDATE queue SET last_error=NULL WHERE id=?", (a,))
    [blank] = [r for r in await store.outbox_for(mid) if r["id"] == a]
    assert blank["last_error"] is None and blank["last_error_withheld"] is False

    # Tampered under a held key, malformed, truncated, unknown format, unmarked: all still raise.
    for bad in (sibling["last_error"], good[:-8], "mfenc:v9:x", "SYNTH-UNMARKED"):
        await raw("UPDATE queue SET last_error=? WHERE id=?", (bad, a))
        await _assert_detail_reads_fail(store, mid, "outbox_for", "outbox_payloads_for")
    await raw("UPDATE queue SET last_error=? WHERE id=?", (good, a))

    # A body under a key the store does not hold still refuses, on a live row.
    live_out = f"OB_CT_DL_{_RUN}"
    live = await store.enqueue_message(channel_id=ch, raw=_RAW, deliveries=[(live_out, "BODY-L")])
    [live_row] = await store.outbox_for(live)
    [held] = await fetch("SELECT payload, body_ref FROM queue WHERE id=?", (live_row["id"],))
    await raw("UPDATE queue SET payload=?, body_ref=NULL WHERE id=?", (foreign, live_row["id"]))
    try:
        await store.outbox_payloads_for(live)
    except CipherError:
        pass
    else:
        raise AssertionError("a body under a key the store does not hold did not refuse")
    await raw(
        "UPDATE queue SET payload=?, body_ref=? WHERE id=?",
        (held["payload"], held["body_ref"], live_row["id"]),
    )

    # The event timeline: the same rule on message_events.detail.
    pick = "SELECT id, detail FROM message_events WHERE message_id=? AND event=?"
    event = next(
        e["event"] for e in await store.events_for(mid) if e["detail"] and e["destination"]
    )
    cell = (await fetch(pick, (mid, event)))[0]
    moved = (await fetch(pick, (other, event)))[0]["detail"]
    await raw("UPDATE message_events SET detail=? WHERE id=?", (foreign, cell["id"]))
    timeline = {e["id"]: e for e in await store.events_for(mid)}
    assert timeline[cell["id"]]["detail"] is None
    assert timeline[cell["id"]]["detail_withheld"] is True
    others = [e for i, e in timeline.items() if i != cell["id"]]
    assert others and not any(e["detail_withheld"] for e in others)  # control
    for bad in (moved, cell["detail"][:-8], "mfenc:v9:x", "SYNTH-UNMARKED"):
        await raw("UPDATE message_events SET detail=? WHERE id=?", (bad, cell["id"]))
        await _assert_detail_reads_fail(store, mid, "events_for")
    await raw("UPDATE message_events SET detail=? WHERE id=?", (cell["detail"], cell["id"]))
    assert all(not e["detail_withheld"] for e in await store.events_for(mid))  # control


async def _routed(store: Any, fetch: RawFetch, channel_id: str) -> tuple[str, str]:
    """A message with metadata, routed to one handler; returns its id and the routed row id."""
    mid = await store.enqueue_ingress(channel_id=channel_id, raw=_RAW, metadata=_META)
    ingress = await store.claim_next_fifo(channel_id, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=channel_id,
        handlers=[("H_CT", _RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo(channel_id, stage=Stage.ROUTED.value)
    assert routed is not None
    return mid, str(routed.id)


async def _assert_transform_handoff(store: Any, raw: RawSql, fetch: RawFetch, hook: _Hook) -> None:
    async def handoff(mid: str, routed_id: str, channel_id: str) -> bool:
        return bool(
            await store.transform_handoff(
                routed_id=routed_id,
                message_id=mid,
                channel_id=channel_id,
                deliveries=[(f"OB_CT_T_{_RUN}", "SYNTH-OUT")],
                meta_ops=[("added", "SYNTH-ADDED")],
            )
        )

    # Control: an untouched message hands off, and its merged metadata reads back.
    mid, rid = await _routed(store, fetch, f"IB_CT_T_{_RUN}")
    assert await handoff(mid, rid, f"IB_CT_T_{_RUN}") is True
    merged = json.loads(await store.message_metadata_json(mid) or "{}")
    assert merged["user"]["added"] == "SYNTH-ADDED"

    mid, rid = await _routed(store, fetch, f"IB_CT_U_{_RUN}")
    await raw("UPDATE messages SET channel_id=? WHERE id=?", (f"IB_CT_T_{_RUN}", mid))
    assert await handoff(mid, rid, f"IB_CT_U_{_RUN}") is False
    rows = await fetch("SELECT status, stage FROM queue WHERE message_id=?", (mid,))
    assert rows == [{"status": OutboxStatus.DEAD.value, "stage": Stage.ROUTED.value}], rows
    status = await fetch("SELECT status FROM messages WHERE id=?", (mid,))
    assert status[0]["status"] == MessageStatus.ERROR.value
    assert hook.saw("messages", mid)
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, mid) == 1


async def _assert_presets(store: Any, raw: RawSql, fetch: RawFetch, hook: _Hook) -> None:
    criteria = json.dumps({"content": "SYNTH-200"})
    owner1, owner2 = f"u-ct-1-{_RUN}", f"u-ct-2-{_RUN}"
    ctl, _ = await store.upsert_search_preset(
        preset_id=uuid4().hex, owner_user_id=owner2, name="ctl", criteria=criteria
    )
    pid, _ = await store.upsert_search_preset(
        preset_id=uuid4().hex, owner_user_id=owner1, name="moved", criteria=criteria
    )
    got = await store.get_search_preset(preset_id=pid, owner_user_id=owner1)
    assert got is not None and got["criteria"] == criteria  # control, before the move
    await raw("UPDATE search_presets SET owner_user_id=? WHERE id=?", (owner2, pid))
    await _refused(lambda: store.get_search_preset(preset_id=pid, owner_user_id=owner2), "preset")
    assert hook.saw("search_presets", pid)
    assert await _audited(fetch, PRESET_TAG_FAILED_ACTION, pid) == 1
    got = await store.get_search_preset(preset_id=ctl, owner_user_id=owner2)
    assert got is not None and got["criteria"] == criteria  # control: the owner's own preset
