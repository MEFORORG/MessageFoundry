# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The keyless-then-keyed on-open contract, one definition for all three backends (BACKLOG #1723).

A store written with no key holds plaintext, and the first keyed open must seal every one of those
values in place. ``tests/test_store_cipher_sweep_parity.py`` proves statically that each sweep NAMES
every written cell. This proves at runtime that each cell's pass WORKS: one plaintext value goes into
every written cell through that cell's real writer, a keyed handle re-opens the store, and each cell
must then be sealed at rest and read back through its real read path.

**The scope is the parity guard's own instrument, not a list here.** The cells come from
``_written_cells``, per backend, so this covers at least every cell that instrument can see: one
sealed through a tag builder it does not know is outside both. A new cell it does see stops the
keyless half on every leg until :func:`write_every_cell` writes it, and reds the plain leg with no
database until :data:`READERS` reads it. ``shared_body`` is in scope on SQLite alone for the same
reason it is there: only that backend writes a row into it.

**The cipher is the cell-bound writer, ``write_v2=True``, and that is what makes the read-back mean
anything.** ``make_cipher`` defaults to the v1 format, which binds no AAD, so a v1 read-back would
pass over a sweep that rebuilt a cell's AAD wrongly. Sealed cells are therefore held to the v4 prefix
rather than the bare marker.

**Once a keyed open completes, every failure is collected, not the first.** The report names every
unsealed and every unreadable cell in one run, so a server leg nobody can run locally says all of that
the first time. A keyed open that raises ends the run instead, as a failed writer does.

**A value reads back exactly or not at all.** Containment would pass a sweep that damaged a value
around the text being looked for, so each read is compared with :func:`value_of` by equality.

**A fresh store is a precondition.** A surface with a ``keyed_surface`` marker (BACKLOG #3383) has its
unmarked values refused rather than sealed, so a marker left behind would turn this contract into a
test of the refusal. It is asserted rather than assumed. Blank cells are not asserted either way:
NULL and ``''`` are never sealed, and whether a blank row is written at all is not this contract's
question. Every value is synthetic (CLAUDE.md section 9).
"""

from __future__ import annotations

import functools
import inspect
import json
import os
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import load_settings
from messagefoundry.store import MessageStatus
from messagefoundry.store.crypto import (
    _V4_PREFIX,
    MARKER_PREFIX,
    CipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.store import Stage
from tests.test_store_cipher_sweep_parity import _parsed, _written_cells

Cell = tuple[str, str]

#: Reads one statement's rows off a store handle, whichever backend it is.
Fetch = Callable[[Any, str], Awaitable[Sequence[Mapping[str, Any]]]]

_CHANNEL = "IB_SYNTH"
_STATE_NS, _STATE_KEY = "synth-ns", "synth-key"
_REFERENCE, _REFERENCE_KEY = "synth_ref", "SYNTH-CODE"
_PRESET, _PRESET_OWNER = "synth-preset", "synth-owner"
_USER = "synth-user"
#: Two destinations on one body put it in ``shared_body`` on SQLite and inline on the server backends.
_SHARED = ("OB_SHARED_A", "OB_SHARED_B")
_QUEUED, _DEAD, _REPLIED = "OB_QUEUED", "OB_DEAD", "OB_REPLIED"
#: A kind the store accepts: connection_event kinds are a closed vocabulary
#: (messagefoundry.connection_events.CONNECTION_EVENT_KIND_ORDER), refused outside it. An MLLP
#: listener records this one for a bad frame, so it carries a reason like the one written here.
_EVENT_KIND = "framing_error"

#: The cells every open decrypts to warm a cache, through the strict cipher. A plaintext value left in
#: one fails a keyed open itself, and a sealed one fails a keyless open.
WARMED_AT_OPEN: tuple[Cell, ...] = (("state", "value"), ("reference", "value"))

#: The cell a server leg's negative control removes. Its read opens no other cipher cell, so the report
#: names it alone. Not every cell's does: a response read opens all three of its columns.
CONTROL_CELL: Cell = ("connection_event", "reason")


def plain(cell: Cell) -> str:
    """The synthetic value written into ``cell``, unique per cell so a value cannot pass for another's."""
    return f"SYNTH-PLAIN-{cell[0]}-{cell[1]}"


#: The cells whose writer takes :func:`plain` in another shape.
_SHAPES: dict[Cell, Callable[[str], Any]] = {
    ("messages", "raw"): lambda text: f"MSH|^~\\&|{text}",
    ("messages", "metadata"): lambda text: json.dumps({"synth": text}),
    ("search_presets", "criteria"): lambda text: json.dumps({"synth": text}),
    ("state", "value"): lambda text: {"synth": text},
    ("response", "resp_headers"): lambda text: {"X-Synth": text},
}


def value_of(cell: Cell) -> Any:
    """What ``cell``'s writer is handed, and so exactly what its read path must return."""
    shape = _SHAPES.get(cell)
    return plain(cell) if shape is None else shape(plain(cell))


@dataclass(frozen=True)
class Written:
    """What :func:`write_every_cell` leaves behind for the readers to find."""

    errored: str
    dead: str
    replied: str
    attachment: str


@dataclass(frozen=True)
class KeyedReopenReport:
    """What a keyed open left wrong. Both empty is the contract holding."""

    unsealed: list[Cell] = field(default_factory=list)
    unreadable: dict[Cell, str] = field(default_factory=dict)


async def _one_claim(store: Any, destination: str) -> Any:
    claimed = await store.claim_ready(destination_name=destination)
    assert claimed, f"nothing to claim for {destination}"
    return claimed[0]


async def write_every_cell(store: Any) -> Written:
    """Put one plaintext value into every written cell, each through its real store writer.

    Every backend's public signatures for these are identical, so one body serves all three. ``state``
    goes through the transform handoff because that is its live writer: ``MERGE`` on SQL Server,
    ``INSERT OR REPLACE INTO`` on SQLite.
    """
    errored = await store.record_received(
        channel_id=_CHANNEL,
        raw="MSH|^~\\&|SYNTH-ERRORED",
        status=MessageStatus.ERROR,
        error=plain(("messages", "error")),
    )

    dead = await store.enqueue_message(
        channel_id=_CHANNEL,
        raw=value_of(("messages", "raw")),
        deliveries=[(_DEAD, "SYNTH-DEAD-PAYLOAD")],
        summary=plain(("messages", "summary")),
        metadata=value_of(("messages", "metadata")),
    )
    await store.record_message_event(dead, "failed", detail=plain(("message_events", "detail")))
    item = await _one_claim(store, _DEAD)
    await store.mark_failed(item.id, plain(("queue", "last_error")), RetryPolicy(max_attempts=1))

    await store.enqueue_message(
        channel_id=_CHANNEL,
        raw="MSH|^~\\&|SYNTH-QUEUED",
        deliveries=[(_QUEUED, plain(("queue", "payload")))],
    )
    await store.enqueue_message(
        channel_id=_CHANNEL,
        raw="MSH|^~\\&|SYNTH-SHARED",
        deliveries=[(name, plain(("shared_body", "body"))) for name in _SHARED],
    )

    replied = await store.enqueue_message(
        channel_id=_CHANNEL,
        raw="MSH|^~\\&|SYNTH-REPLIED",
        deliveries=[(_REPLIED, "SYNTH-REPLIED-PAYLOAD")],
    )
    item = await _one_claim(store, _REPLIED)
    await store.complete_with_response(
        item.id,
        body=plain(("response", "body")),
        outcome="accepted",
        detail=plain(("response", "detail")),
        response_headers=value_of(("response", "resp_headers")),
    )

    transformed = await store.enqueue_ingress(channel_id=_CHANNEL, raw="MSH|^~\\&|SYNTH-STATE")
    ingress = await store.claim_next_fifo(_CHANNEL, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=transformed,
        channel_id=_CHANNEL,
        handlers=[("H", "MSH|^~\\&|SYNTH-STATE")],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo(_CHANNEL, stage=Stage.ROUTED.value)
    assert routed is not None
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=transformed,
        channel_id=_CHANNEL,
        deliveries=[("OB_STATE", "SYNTH-STATE-PAYLOAD")],
        state_ops=[(_STATE_NS, _STATE_KEY, value_of(("state", "value")))],
    )

    await store.write_reference_snapshot(
        name=_REFERENCE, version="1", rows={_REFERENCE_KEY: plain(("reference", "value"))}
    )
    attachment = await store.put_attachment(
        [plain(("attachment_chunk", "ciphertext"))], "text/plain"
    )
    await store.record_connection_event(
        connection=_CHANNEL,
        transport="mllp",
        direction="inbound",
        kind=_EVENT_KIND,
        reason=plain(("connection_event", "reason")),
    )
    await store.upsert_alert_instance(
        event_type="synth_event",
        connection=_CHANNEL,
        severity="warning",
        reason=plain(("alert_instance", "reason")),
    )
    await store.upsert_search_preset(
        preset_id=_PRESET,
        owner_user_id=_PRESET_OWNER,
        name="synth",
        criteria=value_of(("search_presets", "criteria")),
    )
    await store.create_user(
        user_id=_USER,
        username="synth-user",
        auth_provider="local",
        password_hash="h",
        password_generated=False,
    )
    staged = await store.set_totp_secret(_USER, secret=plain(("users", "totp_secret")))
    assert staged is not None
    return Written(errored=errored, dead=dead, replied=replied, attachment=attachment)


async def _message_field(store: Any, message_id: str, name: str) -> Any:
    row = await store.get_message(message_id)
    if row is None:
        raise LookupError(f"no message {message_id}")
    return row[name]


async def _response_field(store: Any, message_id: str, name: str) -> Any:
    return getattr((await store.correlate_response(message_id))[0], name)


async def _claimed_payload(store: Any, destination: str) -> Any:
    # Indexed, not _one_claim: a claim dead-letters a row it cannot open and returns nothing, and that
    # is this cell reading back wrongly, for the report to name.
    return (await store.claim_ready(destination_name=destination))[0].payload


async def _attachment(store: Any, ref: str) -> str:
    return "".join([chunk async for chunk in store.read_attachment(ref)])


async def _state(store: Any) -> Any:
    return store.state_view()[(_STATE_NS, _STATE_KEY)]


async def _reference(store: Any) -> Any:
    return store.reference_view()[_REFERENCE][_REFERENCE_KEY]


async def _event_detail(store: Any, message_id: str) -> Any:
    """The written detail if an event holds it, else every detail, for the report to show. The
    message's routine events have details of their own."""
    details = [event["detail"] for event in await store.events_for(message_id)]
    return next((d for d in details if d == value_of(("message_events", "detail"))), details)


async def _last_error(store: Any, message_id: str) -> Any:
    """Through both of its read paths, which decrypt it separately: a delivery row, and the
    dead-letter list's join."""
    delivery = (await store.outbox_for(message_id))[0]["last_error"]
    # Filtered to the contract's own dead row: a reader that claims a row it cannot open
    # dead-letters it, so the whole-table listing's first row need not be this one.
    dead = (await store.list_dead(destination_name=_DEAD, allowed_channels=None))[0]["last_error"]
    return delivery if delivery == dead else (delivery, dead)


async def _connection_reason(store: Any) -> Any:
    events = await store.list_connection_events(connection=_CHANNEL, allowed_channels=None)
    # Selected by the written row's own identity rather than by list order, so a refusal some other
    # reader records cannot stand in for it.
    ours = [
        e for e in events if (e.transport, e.direction, e.kind) == ("mllp", "inbound", _EVENT_KIND)
    ]
    if not ours:
        raise LookupError(f"no connection event for {_CHANNEL}")
    return ours[0].reason


async def _alert_reason(store: Any) -> Any:
    alerts = await store.list_active_alert_instances(allowed_channels=None)
    # By event type, not list order: alerts list newest first, and a refusal can raise one.
    ours = [a for a in alerts if (a.event_type, a.connection) == ("synth_event", _CHANNEL)]
    if not ours:
        raise LookupError("no synth_event alert")
    return ours[0].reason


async def _preset_criteria(store: Any) -> Any:
    row = await store.get_search_preset(preset_id=_PRESET, owner_user_id=_PRESET_OWNER)
    if row is None:
        raise LookupError(f"no preset {_PRESET}")
    return row["criteria"]


#: One real read path per cell. Each must return exactly :func:`value_of` that cell.
READERS: dict[Cell, Callable[[Any, Written], Awaitable[Any]]] = {
    ("messages", "raw"): lambda s, w: _message_field(s, w.dead, "raw"),
    ("messages", "error"): lambda s, w: _message_field(s, w.errored, "error"),
    ("messages", "summary"): lambda s, w: _message_field(s, w.dead, "summary"),
    ("messages", "metadata"): lambda s, w: s.message_metadata_json(w.dead),
    ("queue", "payload"): lambda s, w: _claimed_payload(s, _QUEUED),
    ("queue", "last_error"): lambda s, w: _last_error(s, w.dead),
    ("shared_body", "body"): lambda s, w: _claimed_payload(s, _SHARED[0]),
    ("state", "value"): lambda s, w: _state(s),
    ("reference", "value"): lambda s, w: _reference(s),
    ("response", "body"): lambda s, w: _response_field(s, w.replied, "body"),
    ("response", "detail"): lambda s, w: _response_field(s, w.replied, "detail"),
    ("response", "resp_headers"): lambda s, w: _response_field(s, w.replied, "headers"),
    ("attachment_chunk", "ciphertext"): lambda s, w: _attachment(s, w.attachment),
    ("message_events", "detail"): lambda s, w: _event_detail(s, w.dead),
    ("connection_event", "reason"): lambda s, w: _connection_reason(s),
    ("alert_instance", "reason"): lambda s, w: _alert_reason(s),
    ("search_presets", "criteria"): lambda s, w: _preset_criteria(s),
    ("users", "totp_secret"): lambda s, w: s.get_totp_secret(_USER),
}


@functools.cache
def cells_in_scope(backend: str) -> tuple[Cell, ...]:
    """The written cells of ``backend`` (a module name under ``store/``), by the parity instrument.
    Cached because each call walks the whole module's AST."""
    return tuple(sorted(_written_cells(_parsed(backend))))


async def _at_rest(store: Any, fetch: Fetch, cell: Cell) -> list[str]:
    """The cell's non-blank values as stored. The table and column come from code, never from data."""
    rows = await fetch(store, f"SELECT {cell[1]} AS v FROM {cell[0]}")
    return [str(row["v"]) for row in rows if row["v"]]


async def _unsealed(store: Any, fetch: Fetch, cells: Sequence[Cell]) -> list[Cell]:
    """The cells holding no value, or any value not sealed under the cell-bound format."""
    unsealed = []
    for cell in cells:
        values = await _at_rest(store, fetch, cell)
        if not values or not all(value.startswith(_V4_PREFIX) for value in values):
            unsealed.append(cell)
    return unsealed


async def _unreadable(store: Any, written: Written, cells: Sequence[Cell]) -> dict[Cell, str]:
    """The cells whose read path refused, or returned something other than what was written."""
    unreadable: dict[Cell, str] = {}
    for cell in cells:
        try:
            value = await READERS[cell](store, written)
        except (CipherError, LookupError) as exc:
            unreadable[cell] = f"{type(exc).__name__}: {exc}"
            continue
        if value != value_of(cell):
            unreadable[cell] = f"read back {value!r}"
    return unreadable


async def keyed_reopen_report(
    store_cls: Any,
    *,
    open_keyless: Callable[[], Awaitable[Any]],
    open_keyed: Callable[[], Awaitable[Any]],
    fetch: Fetch,
) -> KeyedReopenReport:
    """Write every cell keyless, re-open keyed, and report each cell left unsealed or unreadable.

    A keyed open that hits a :data:`WARMED_AT_OPEN` cell left plaintext raises ``CipherError``, and
    that propagates: it is a failure the caller sees either way.
    """
    cells = cells_in_scope(Path(inspect.getfile(store_cls)).name)

    store = await open_keyless()
    try:
        marked = await fetch(store, "SELECT surface_table AS v FROM keyed_surface")
        assert not marked, f"not a fresh store: these surfaces would refuse, not seal: {marked}"
        written = await write_every_cell(store)
        for cell in cells:
            values = await _at_rest(store, fetch, cell)
            assert any(plain(cell) in value for value in values), (
                f"{cell}: the keyless writer left no plaintext here, so this proves nothing: {values}"
            )
            assert not any(value.startswith(MARKER_PREFIX) for value in values), (
                f"{cell}: a keyless write is already marked: {values}"
            )
    finally:
        await store.close()

    store = await open_keyed()
    try:
        # At rest first: a read can claim a row, or dead-letter one it cannot open.
        unsealed = await _unsealed(store, fetch, cells)
        return KeyedReopenReport(unsealed, await _unreadable(store, written, cells))
    finally:
        await store.close()


async def server_keyed_reopen_report(store: Any) -> KeyedReopenReport:
    """:func:`keyed_reopen_report` on a shared server database.

    ``store`` is the caller's fixture handle. It has already cleared the database, ``keyed_surface``
    included, and it clears what must not outlive this: state and reference rows sealed under this
    key would fail closed in the next keyless fixture's open, before that fixture could clear them.
    The handle is keyless and a DELETE needs no key, so this holds even when the keyed open failed.
    Those legs open keyless by default, so the keyed handles are this function's own.
    """
    store_cls = type(store)
    settings = load_settings(environ=os.environ).store
    key = generate_key()
    try:
        return await keyed_reopen_report(
            store_cls,
            open_keyless=lambda: store_cls.open(settings),
            open_keyed=lambda: store_cls.open(settings, cipher=make_cipher(key, write_v2=True)),
            fetch=lambda handle, sql: handle._fetchall(sql),
        )
    finally:
        for table, _column in WARMED_AT_OPEN:
            await store._execute(f"DELETE FROM {table}")
        await store._execute("DELETE FROM reference_version")


def remove_seal_passes(
    monkeypatch: pytest.MonkeyPatch, store_cls: Any, cells: Collection[Cell]
) -> None:
    """Drop ``cells`` from ``_seal_surface``, the runtime equal of deleting their on-open passes."""
    real = store_cls._seal_surface

    async def seal(self: Any, table: str, column: str, like: str, **kwargs: Any) -> int:
        if (table, column) in cells:
            return 0
        sealed: int = await real(self, table, column, like, **kwargs)
        return sealed

    monkeypatch.setattr(store_cls, "_seal_surface", seal)


def assert_names_the_control_cell_alone(report: KeyedReopenReport) -> None:
    """With :data:`CONTROL_CELL`'s pass removed, both halves name it and every sibling stays good."""
    assert report.unsealed == [CONTROL_CELL]
    assert list(report.unreadable) == [CONTROL_CELL]
