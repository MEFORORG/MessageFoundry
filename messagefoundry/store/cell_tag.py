# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The tags a message cell and a saved-search preset's criteria are sealed under (BACKLOG #2593).

A ``messages`` row's ``raw``, ``error``, ``summary`` and ``metadata`` are AEAD cells. Their associated
data, the **tag**, binds each cell to its row id AND to the row's ``channel_id``, the plaintext column
the per-channel access scope reads. A ``search_presets`` row's ``criteria`` cell binds its row id AND
its ``owner_user_id``, the plaintext column every preset read is scoped by. So a change to either
column made outside the store's writers stops the cells opening, and a moved message or preset reads
as a refusal rather than as another channel's or another user's data.

**One builder per table.** :func:`message_cell_aad` and :func:`preset_criteria_aad` are the only
builders, and :func:`row_tag_aad` reads their inputs off a fetched row for the store's whole-surface
passes (the on-open seal pass, rotation, the restore verify). ``tests/test_cell_tag.py`` asserts that no
store module builds a ``messages`` or ``search_presets`` cell's associated data any other way.

**One encoder.** The bound columns are encoded by :func:`~messagefoundry.store.row_seal.seal_bytes`, as
the queue payload's tag is (:mod:`messagefoundry.store.queue_tag`), and wrapped in the :func:`cell_aad`
frame for the cell, so :func:`~messagefoundry.store.crypto.aad_cell_name` still names it in a refusal.

**A read that fails its tag is refused, alerted and audited** (the database-integrity design, D13).
:func:`open_tagged_cell` raises :class:`CellTagError` and raises the ``integrity_drift`` alert through
the cipher's tag-failure hook. The store writes the audit row once the read has left any writer
transaction (:func:`audits_cell_tag`). A list-shaped read withholds the failed row's cells and keeps the
row, so its plaintext columns still list and nothing is silently dropped. A corrupt cell under a held
key raises :class:`CorruptCellError`: it is contained the same way, but only logged, since it is not
drift. An unmarked value the cipher refuses raises :class:`UnmarkedCellError`: drift, audited and
contained, with the cipher's own refusal as its alert (BACKLOG #5650).

**The store id.** No store id is minted yet, so every tag carries
:data:`~messagefoundry.store.crypto.NO_STORE_ID`, as the queue tag does.
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import threading
import time
from collections.abc import Callable, Coroutine, Mapping
from typing import TYPE_CHECKING, Any, ClassVar, Concatenate, Final, Protocol

import annotationlib

from messagefoundry.store.crypto import (
    NO_STORE_ID,
    CipherError,
    CipherUnavailableError,
    UnauthenticatedCipherError,
    UnmarkedCipherError,
    cell_aad,
)
from messagefoundry.store.queue_tag import is_tag_failure
from messagefoundry.store.row_seal import seal_bytes

if TYPE_CHECKING:
    from messagefoundry.store.crypto import Cipher

__all__ = [
    "MESSAGE_TAG_CELLS",
    "MESSAGE_TAG_COLUMNS",
    "MESSAGE_TAG_FAILED_ACTION",
    "PRESET_TAG_COLUMNS",
    "PRESET_TAG_FAILED_ACTION",
    "CellTagError",
    "CellTagSink",
    "CorruptCellError",
    "UnmarkedCellError",
    "audits_cell_tag",
    "dead_letter_on_cell_tag",
    "dead_letters_on_cell_tag",
    "is_row_tagged",
    "message_cell_aad",
    "open_message_cell",
    "open_preset_criteria",
    "open_tagged_cell",
    "preset_criteria_aad",
    "report_cell_tag_failure",
    "report_cell_tag_failures",
    "row_tag_aad",
    "row_tag_columns",
    "withhold_message_cells",
]

_log = logging.getLogger(__name__)

#: The ``messages`` cells bound to the row's channel.
MESSAGE_TAG_CELLS: Final = ("raw", "error", "summary", "metadata")
#: The ``messages`` columns a message cell's tag is built from. A reader must SELECT both.
MESSAGE_TAG_COLUMNS: Final = ("id", "channel_id")
#: The ``search_presets`` columns the ``criteria`` tag is built from. A reader must SELECT both.
PRESET_TAG_COLUMNS: Final = ("id", "owner_user_id")

#: The audit action written when a message cell does not open under its row's tag.
MESSAGE_TAG_FAILED_ACTION: Final = "integrity.message_tag_failed"
#: The audit action written when a preset's criteria do not open under its row's tag.
PRESET_TAG_FAILED_ACTION: Final = "integrity.preset_tag_failed"
#: Each tagged table's tag-failed audit action. A :class:`CellTagError` names one of these tables, so
#: no failure is audited under another table's action (BACKLOG #6697).
_TAG_FAILED_ACTION: Final[Mapping[str, str]] = {
    "messages": MESSAGE_TAG_FAILED_ACTION,
    "search_presets": PRESET_TAG_FAILED_ACTION,
}

# Each table's ``seal_bytes`` kind: its own, so no tag can equal another table's or a row seal's.
_MESSAGE_KIND: Final = "message-cell"
_PRESET_KIND: Final = "preset-criteria"

#: How much of a row id an audit row or alert names. Message and preset ids are random, never PHI.
_ROW_REF_LEN: Final = 12


def _framed(table: str, column: str, kind: str, fields: tuple[tuple[str, object], ...]) -> bytes:
    encoded = seal_bytes(kind, fields)
    # The cell_aad frame names the cell, and the bound encoding is its one trailing field.
    return cell_aad(table, column) + len(encoded).to_bytes(4, "big") + encoded


def message_cell_aad(
    column: str, *, message_id: str, channel_id: str, store_id: bytes = NO_STORE_ID
) -> bytes:
    """The associated data for one ``messages`` cell: ``column`` of the row ``message_id``, bound to
    the row's ``channel_id``."""
    if column not in MESSAGE_TAG_CELLS:
        raise ValueError(f"messages.{column} is not a tagged message cell")
    return _framed(
        "messages",
        column,
        _MESSAGE_KIND,
        (("store_id", bytes(store_id)), ("id", message_id), ("channel_id", channel_id)),
    )


def preset_criteria_aad(
    *, preset_id: str, owner_user_id: str, store_id: bytes = NO_STORE_ID
) -> bytes:
    """The associated data for a ``search_presets`` row's ``criteria``, bound to its owner."""
    return _framed(
        "search_presets",
        "criteria",
        _PRESET_KIND,
        (("store_id", bytes(store_id)), ("id", preset_id), ("owner_user_id", owner_user_id)),
    )


def _message_row_aad(column: str, row: Any) -> bytes:
    return message_cell_aad(column, message_id=row["id"], channel_id=row["channel_id"])


def _preset_row_aad(_column: str, row: Any) -> bytes:
    return preset_criteria_aad(preset_id=row["id"], owner_user_id=row["owner_user_id"])


#: The id-keyed cipher cells whose tag binds more than the row id: (table, column) to the columns the
#: tag reads and the builder that reads them off a row.
_ROW_TAGGED: Final[
    Mapping[tuple[str, str], tuple[tuple[str, ...], Callable[[str, Any], bytes]]]
] = {
    **{("messages", c): (MESSAGE_TAG_COLUMNS, _message_row_aad) for c in MESSAGE_TAG_CELLS},
    ("search_presets", "criteria"): (PRESET_TAG_COLUMNS, _preset_row_aad),
}


def is_row_tagged(table: str, column: str) -> bool:
    """Whether ``table.column`` is sealed under a row tag from this module."""
    return (table, column) in _ROW_TAGGED


def row_tag_columns(table: str, column: str) -> tuple[str, ...]:
    """The columns an id-keyed cell's associated data is built from: the tag's columns for a cell this
    module binds, otherwise just ``id``."""
    entry = _ROW_TAGGED.get((table, column))
    return entry[0] if entry is not None else ("id",)


def row_tag_aad(table: str, column: str, row: Any) -> bytes:
    """The associated data for an id-keyed cell, read off ``row``, which holds every column
    :func:`row_tag_columns` names. A missing column raises, so a pass that forgot to select one fails
    closed rather than building a different tag."""
    entry = _ROW_TAGGED.get((table, column))
    if entry is None:
        return cell_aad(table, column, row["id"])
    return entry[1](column, row)


class CellTagError(CipherError):
    """A message cell or a preset's criteria did not open under the tag its own row builds.

    A subclass of :class:`CipherError`, so every path that already refuses an undecryptable cell
    refuses this one the same way. Names the cell and a short row-id prefix, never a row value."""

    #: Whether this is tag drift: the cell was sealed for another row, or changed outside the
    #: store's writers. Only drift writes the tag-failed audit row and raises the
    #: ``integrity_drift`` alert.
    drift: ClassVar[bool] = True
    #: Whether the cipher already alerted and logged the refusal this error wraps, so
    #: :func:`open_tagged_cell` raises no second alert and logs no second WARNING.
    cipher_alerted: ClassVar[bool] = False

    def __init__(self, table: str, column: str, row_id: str, channel_id: str | None) -> None:
        if table not in _TAG_FAILED_ACTION:
            raise ValueError(f"{table} is not a table this module tags")
        self.table = table
        self.column = column
        self.row_ref = str(row_id)[:_ROW_REF_LEN]
        self.channel_id = channel_id
        #: Set once the audit row is written, so nested boundaries write it once.
        self.audited = False
        super().__init__(self._describe())

    def _describe(self) -> str:
        return (
            f"integrity: the {self.table}.{self.column} cell of row {self.row_ref} does not open"
            " under its own row's tag"
        )


class CorruptCellError(CellTagError):
    """A cell under a key this process holds that no tag check can judge, because the row is corrupt:
    bad base64, or a plaintext whose tag VERIFIED but is not UTF-8 (BACKLOG #2308).

    It is not drift, so it raises no ``integrity_drift`` alert and writes no tag-failed audit row. It
    is still a :class:`CellTagError`, so every read and handoff contains it the same way: a list
    withholds the row, a handoff dead-letters it rather than re-pending a row that fails forever."""

    drift = False

    def _describe(self) -> str:
        return (
            f"the {self.table}.{self.column} cell of row {self.row_ref} is corrupt and cannot be"
            " read under the key it names"
        )


class UnmarkedCellError(CellTagError):
    """A non-blank unmarked value in a tagged cell of a keyed store, which the cipher refused
    (:class:`~messagefoundry.store.crypto.UnmarkedCipherError`): a stripped marker or a planted row
    (BACKLOG #5650). The store's writers never write one, so, like a cell sealed for another row,
    it is a change made outside them.

    It counts as drift, so it writes the tag-failed audit row and is contained as drift is: a list
    withholds the row, a handoff dead-letters it. Its alert is the cipher's own unmarked-value
    refusal, already raised when the cipher refused it, so :func:`open_tagged_cell` raises no
    second, ``integrity_drift``, alert for it and logs no second WARNING."""

    cipher_alerted = True

    def _describe(self) -> str:
        return (
            f"integrity: the {self.table}.{self.column} cell of row {self.row_ref} holds an"
            " unmarked value, which the store's writers never write"
        )


def _tag_failure_kind(cipher: Cipher, stored: str, exc: CipherError) -> type[CellTagError] | None:
    """The :class:`CellTagError` class a failed open of ``stored`` raises, or ``None`` to keep the
    cipher's own error: an outage, a key or a format problem."""
    if isinstance(exc, CipherUnavailableError):
        return None  # the key service gave no verdict, so nothing is known about the cell
    if isinstance(exc, UnmarkedCipherError):
        return UnmarkedCellError
    if not is_tag_failure(cipher, stored):
        return None
    # Only a tag that failed under every held key can mean the cell was sealed elsewhere. A cipher
    # that cannot name its keys (Vault Transit) still says when the value's own tag failed: its
    # UnauthenticatedCipherError is Transit's AEAD refusal, and nothing else it raises is a corrupt
    # row it can vouch for, so it keeps its own error there.
    if isinstance(exc, UnauthenticatedCipherError):
        return CellTagError
    return CorruptCellError if callable(getattr(cipher, "holds_key_for", None)) else None


def open_tagged_cell(
    cipher: Cipher,
    stored: str | None,
    aad: bytes,
    *,
    table: str,
    column: str,
    row_id: str,
    channel_id: str | None = None,
) -> str | None:
    """Open ``stored`` under ``aad``. ``None`` reads as ``None``, and a blank or unmarked value goes to
    the cipher's own policy, as the store's ``_dec`` does.

    A marked value whose AEAD tag fails under a key this process holds (:func:`is_tag_failure`)
    raises :class:`CellTagError` and raises the ``integrity_drift`` alert. So does one the Vault
    Transit cipher, which cannot name its keys, refuses with
    :class:`~messagefoundry.store.crypto.UnauthenticatedCipherError` (BACKLOG #5650). Under a held
    key, a corrupt row (bad base64, or a verified plaintext that is not UTF-8) raises
    :class:`CorruptCellError`, which is contained the same way but is not drift. An unmarked value
    the cipher refuses raises :class:`UnmarkedCellError`, with the cipher's own alert only. An
    outage (:class:`~messagefoundry.store.crypto.CipherUnavailableError`), and a key or format
    problem, raise the cipher's own error."""
    # Checked on every open, not only on a failure: a CellTagError for an unknown table would raise
    # ValueError instead, losing the alert and escaping every containment.
    if table not in _TAG_FAILED_ACTION:
        raise ValueError(f"{table} is not a table this module tags")
    if stored is None:
        return None
    try:
        return cipher.decrypt(stored, aad=aad)
    except CipherError as exc:
        kind = _tag_failure_kind(cipher, stored, exc)
        if kind is None:
            raise
        err = kind(table, column, row_id, channel_id)
        if not err.cipher_alerted:
            _alert(cipher, err)
        raise err from exc


def open_message_cell(
    cipher: Cipher, column: str, stored: str | None, *, message_id: str, channel_id: str
) -> str | None:
    """Open one ``messages`` cell under the tag its row's id and channel build."""
    return open_tagged_cell(
        cipher,
        stored,
        message_cell_aad(column, message_id=message_id, channel_id=channel_id),
        table="messages",
        column=column,
        row_id=message_id,
        channel_id=channel_id,
    )


def open_preset_criteria(
    cipher: Cipher, stored: str | None, *, preset_id: str, owner_user_id: str
) -> str | None:
    """Open a preset's ``criteria`` under the tag its row's id and owner build."""
    return open_tagged_cell(
        cipher,
        stored,
        preset_criteria_aad(preset_id=preset_id, owner_user_id=owner_user_id),
        table="search_presets",
        column="criteria",
        row_id=preset_id,
    )


def withhold_message_cells(
    cipher: Cipher,
    record: dict[str, Any],
    columns: tuple[str, ...],
    *,
    message_id: str,
    channel_id: str,
    failures: list[CellTagError],
) -> None:
    """Open ``columns`` of one message in ``record`` in place, for a list-shaped read. A cell that
    fails its tag withholds every one of the row's cells (``None``) and appends the error to
    ``failures`` for the caller to audit, so the row still lists by its plaintext columns."""
    try:
        for col in columns:
            if col in record:
                record[col] = open_message_cell(
                    cipher, col, record[col], message_id=message_id, channel_id=channel_id
                )
    except CellTagError as err:
        for col in columns:
            if col in record:
                record[col] = None
        failures.append(err)


#: How long one cell's failure is reported once per process. A list view or a retention pass meets
#: the same failed row on every run; without this each run would write the WARNING, the alert and the
#: audit row again.
_REPORT_INTERVAL_S: Final = 3600.0
#: The most cells remembered; the oldest is forgotten first.
_REPORTED_MAX: Final = 4096
type _Key = tuple[str, str, str, bool]
type _Memo = dict[_Key, float]
_reported: _Memo = {}
_reported_audit: _Memo = {}
#: The memos are touched from the event loop and from worker threads (the content-search scan, the
#: SQL Server fused handoff), so every read-modify-write holds this lock.
_reported_lock = threading.Lock()


def _memo_key(err: CellTagError) -> _Key:
    return (err.table, err.column, err.row_ref, err.drift)  # a corrupt read never mutes drift


def _is_recent(memo: _Memo, key: _Key, now: float) -> bool:
    last = memo.get(key)
    return last is not None and now - last < _REPORT_INTERVAL_S


def _remember(memo: _Memo, key: _Key, now: float) -> None:
    memo.pop(key, None)
    memo[key] = now
    while len(memo) > _REPORTED_MAX:
        memo.pop(next(iter(memo)))


def _first_in_interval(memo: _Memo, err: CellTagError) -> bool:
    """Whether ``err``'s cell has not been reported in ``memo`` within the interval; records it."""
    key, now = _memo_key(err), time.monotonic()
    with _reported_lock:
        if _is_recent(memo, key, now):
            return False
        _remember(memo, key, now)
    return True


def _alert(cipher: object, err: CellTagError) -> None:
    """Log a WARNING and, for drift, raise ``integrity_drift`` through the cipher's tag-failure hook,
    once per cell per interval. Never raises."""
    if not _first_in_interval(_reported, err):
        return
    if not err.drift:
        _log.warning("%s; the read was refused", err)
        return
    reason = f"a {err.table}.{err.column} cell failed its integrity tag (row {err.row_ref})"
    _log.warning("%s; the read was refused", reason)
    report = getattr(cipher, "report_tag_failure", None)
    if callable(report):
        report(err.table, reason)


class _AuditSink(Protocol):
    async def record_audit(
        self,
        action: str,
        *,
        actor: str | None = None,
        channel_id: str | None = None,
        detail: str | None = None,
        client: str | None = None,
        now: float | None = None,
    ) -> None: ...


async def report_cell_tag_failure(store: _AuditSink, err: CellTagError) -> None:
    """Write the audit row for ``err``, once. The alert was raised when the read was refused. An
    audit failure is logged and swallowed: reporting must never change what the read did. A corrupt
    cell is not drift, so it writes no tag-failed row; its WARNING was logged at the read.

    The cell is muted for the interval only once its row is WRITTEN, so a write that fails or is
    cancelled leaves the cell's next refusal to write it (BACKLOG #6697). Nothing marks a write in
    flight: concurrent reports of one cell may each write a row, so a failed write never mutes
    another report. The row is written at most once per later refusal, not guaranteed: a failed
    write is retried only if the cell is refused again, and a row the pipeline dead-letters is not
    read again by the pipeline, so its audit row would be lost unless a later read refuses it."""
    if err.audited or not err.drift:
        return
    key = _memo_key(err)
    with _reported_lock:
        recent = _is_recent(_reported_audit, key, time.monotonic())
    if recent:
        err.audited = True
        return
    action = _TAG_FAILED_ACTION[err.table]
    try:
        await store.record_audit(
            action,
            actor="system",
            channel_id=err.channel_id,
            detail=json.dumps({"cell": err.column, "row": err.row_ref}, sort_keys=True),
        )
    except Exception as exc:  # noqa: BLE001 -- the refusal stands whatever the audit write does
        # Class and an error code only (SQLSTATE, or SQLite's error name), as the store's other
        # driver-failure lines: a driver's text and traceback are not this function's to vouch for.
        from messagefoundry.store.base import driver_sqlstate  # lazy: base imports this module

        _log.error(
            "the %s audit row could not be written (%s, code %s); it is written only if the cell"
            " is refused again",
            action,
            type(exc).__name__,
            driver_sqlstate(exc) or getattr(exc, "sqlite_errorname", None),
        )
        return
    err.audited = True
    with _reported_lock:
        _remember(_reported_audit, key, time.monotonic())


def audits_cell_tag[S: _AuditSink, **P, R](
    fn: Callable[Concatenate[S, P], Coroutine[Any, Any, R]],
) -> Callable[Concatenate[S, P], Coroutine[Any, Any, R]]:
    """Wrap a store read entry point so a :class:`CellTagError` it raises is audited before it
    propagates. Apply it only to a method no store method calls while holding the writer lock: the
    audit write takes that lock."""

    async def wrapper(self: S, /, *args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return await fn(self, *args, **kwargs)
        except CellTagError as err:
            await report_cell_tag_failure(self, err)
            raise

    functools.update_wrapper(wrapper, fn)
    return wrapper


class CellTagSink(_AuditSink, Protocol):
    async def dead_letter_now(
        self, outbox_id: str, error: str, now: float | None = None
    ) -> None: ...


def dead_letters_on_cell_tag[S: CellTagSink, **P](
    fn: Callable[Concatenate[S, P], Coroutine[Any, Any, bool]],
) -> Callable[Concatenate[S, P], Coroutine[Any, Any, bool]]:
    """Wrap a stage handoff whose keyword ``routed_id`` names the in-flight row it consumes. When the
    handoff raises :class:`CellTagError`, its transaction has rolled back: the row is dead-lettered so
    the lane moves on and the message is ``ERROR`` (count-and-log), the failure is audited (the alert
    was raised at the read), and the handoff reports ``False``. Without this the runner would read the
    raise as an infrastructure fault and re-pend the row until the inbound stopped.

    ``routed_id`` must be keyword-only with no default, so every call that reaches the handoff
    carries it in ``kwargs``; a handoff that takes it any other way is refused here, at decoration
    (BACKLOG #6698)."""
    # STRING: only the kind is read, so no annotation is evaluated (a TYPE_CHECKING-only one would
    # raise NameError at decoration).
    sig = inspect.signature(fn, annotation_format=annotationlib.Format.STRING)
    param = sig.parameters.get("routed_id")
    if (
        param is None
        or param.kind is not inspect.Parameter.KEYWORD_ONLY
        or param.default is not inspect.Parameter.empty
    ):
        raise TypeError(
            f"{fn.__qualname__} must take routed_id as a keyword-only parameter with no default"
        )

    async def wrapper(self: S, /, *args: P.args, **kwargs: P.kwargs) -> bool:
        try:
            return await fn(self, *args, **kwargs)
        except CellTagError as err:
            await dead_letter_on_cell_tag(self, str(kwargs["routed_id"]), err)
            return False

    functools.update_wrapper(wrapper, fn)
    return wrapper


async def dead_letter_on_cell_tag(store: CellTagSink, row_id: str, err: CellTagError) -> None:
    """Dead-letter the in-flight queue row ``row_id`` whose message failed its cell tag, so the lane
    moves on and the message is ``ERROR`` (count-and-log), then audit the failure. The one policy for
    a stage that met a tag failure, on the async handoffs and the runner's fused path alike.

    The audit is written even when the dead-letter fails, whose error then propagates: the row
    stays in flight, meets the tag failure again on its re-run and is dead-lettered then, and the
    audit row is not lost meanwhile (BACKLOG #6698). A cancellation is not held up by a write."""
    try:
        await store.dead_letter_now(row_id, str(err))
    except Exception:
        await report_cell_tag_failure(store, err)
        raise
    await report_cell_tag_failure(store, err)


async def report_cell_tag_failures(store: _AuditSink, failures: list[CellTagError]) -> None:
    """:func:`report_cell_tag_failure` for each failure a list-shaped read collected."""
    for err in failures:
        await report_cell_tag_failure(store, err)
