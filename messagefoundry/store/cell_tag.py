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

**A list-shaped read withholds a cell only for a key the store does not hold** (BACKLOG #5970,
owner ruling 2026-11-19): in-process, a key not supplied, a retired key version or an unknown
one; under Vault Transit, only a retired or unknown key VERSION, never a configured key Transit
does not find (:func:`refused_for_key`, which names the marker rewrites it cannot tell from
those). Every other cipher error fails the read, as it did before #5970.

**The store id.** No store id is minted yet, so every tag carries
:data:`~messagefoundry.store.crypto.NO_STORE_ID`, as the queue tag does.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import json
import logging
import re
import sys
import threading
import time
import traceback
from collections.abc import Callable, Coroutine, Mapping
from typing import TYPE_CHECKING, Any, ClassVar, Concatenate, Final, Protocol, cast

import annotationlib

from messagefoundry.store.crypto import (
    NO_STORE_ID,
    CipherError,
    UnauthenticatedCipherError,
    UnmarkedCipherError,
    cell_aad,
    gave_no_verdict,
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
    "BlankCellError",
    "CellTagError",
    "CellTagSink",
    "CorruptCellError",
    "NonTextCellError",
    "SealedBlankCellError",
    "UnmarkedCellError",
    "audits_cell_tag",
    "dead_letter_on_cell_tag",
    "dead_letters_on_cell_tag",
    "is_row_tagged",
    "message_cell_aad",
    "open_listed_cell",
    "open_message_cell",
    "open_message_record",
    "open_preset_criteria",
    "open_tagged_cell",
    "preset_criteria_aad",
    "refused_for_key",
    "report_cell_tag_failure",
    "report_cell_tag_failures",
    "require_preset_criteria",
    "row_tag_aad",
    "row_tag_columns",
    "withhold_message_cells",
    "withhold_refused_cell",
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


def _require_tagged_table(table: str) -> None:
    """Refuse a table this module does not tag, so no failure is reported under another table's
    audit action and no open meets a :class:`CellTagError` it cannot build."""
    if table not in _TAG_FAILED_ACTION:
        raise ValueError(f"{table} is not a table this module tags")


class CellTagError(CipherError):
    """A message cell or a preset's criteria did not open under the tag its own row builds.

    A subclass of :class:`CipherError`, so every path that already refuses an undecryptable cell
    refuses this one the same way. Names the cell and a short row-id prefix, never a row value."""

    #: Whether this is tag drift: the cell was sealed for another row, or changed outside the
    #: store's writers. Only drift writes the tag-failed audit row and raises the
    #: ``integrity_drift`` alert.
    drift: ClassVar[bool] = True
    #: Whether the cipher already alerted on the refusal this error wraps, so
    #: :func:`open_tagged_cell` raises no second alert; it still audits each row and logs a WARNING
    #: once per cell column per interval.
    cipher_alerted: ClassVar[bool] = False

    def __init__(self, table: str, column: str, row_id: str, channel_id: str | None) -> None:
        _require_tagged_table(table)
        self.table = table
        self.column = column
        self.row_ref = str(row_id)[:_ROW_REF_LEN]
        self.channel_id = channel_id
        #: Set once this error needs no further audit write: its row was written, or the cell's row
        #: was written within the interval. So nested boundaries report it once.
        self.audited = False
        super().__init__(self._describe())

    def _describe(self) -> str:
        return (
            f"integrity: the {self.table}.{self.column} cell of row {self.row_ref} does not open"
            " under its own row's tag"
        )

    def alert_reason(self) -> str:
        """The ``integrity_drift`` alert's reason: the cell and a row-id prefix, never a value."""
        return f"a {self.table}.{self.column} cell failed its integrity tag (row {self.row_ref})"


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
    (:class:`~messagefoundry.store.crypto.UnmarkedCipherError`), BACKLOG #5650. A keyed writer
    never writes one. It is at least a stripped marker, a planted row, or a value a keyless run of
    an already keyed store wrote; nothing here tells those apart.

    It counts as drift, so it writes the tag-failed audit row and is contained as drift is: a list
    withholds the row, a handoff dead-letters it. Its alert is the cipher's own unmarked-value
    refusal, already raised when the cipher refused it, so :func:`open_tagged_cell` raises no
    second, ``integrity_drift``, alert for it. Its audit row is written per row, once per interval,
    as a moved cell's is. Its WARNING is logged once per cell column per interval, naming the first
    row met: a keyless run can leave one in every row it wrote."""

    cipher_alerted = True

    def _describe(self) -> str:
        return (
            f"integrity: the {self.table}.{self.column} cell of row {self.row_ref} holds an"
            " unmarked value, which a keyed writer does not write"
        )


class BlankCellError(CellTagError):
    """A preset's ``criteria`` cell holds NULL or an empty string (BACKLOG #5523). The store never
    writes either, keyed or keyless, and a keyed cipher passes a blank value through unopened, so a
    blank cell was written outside the store. Read as an empty filter it would drop a narrowing
    preset out of a layered search and widen it, so it is refused.

    It counts as drift: it writes the tag-failed audit row and, on a keyed store, raises the
    ``integrity_drift`` alert, as a moved cell does. A keyless store's cipher has no alert hook."""

    def _describe(self) -> str:
        return (
            f"integrity: the {self.table}.{self.column} cell of row {self.row_ref} is blank, which"
            " the store never writes"
        )

    def alert_reason(self) -> str:
        return (
            f"a {self.table}.{self.column} cell is blank, which the store never writes"
            f" (row {self.row_ref})"
        )


class SealedBlankCellError(BlankCellError):
    """A preset's ``criteria`` cell is sealed and the cipher opens it, but to an empty string
    (BACKLOG #5523). The cell on disk is ciphertext, not blank, so the text says what opened. The
    store never seals blank criteria, so it is drift and refused as a blank cell is. Under a marker
    whose tag binds no row (v1), opening says nothing about which row it was sealed for."""

    def _describe(self) -> str:
        return (
            f"integrity: the {self.table}.{self.column} cell of row {self.row_ref} opens to an"
            " empty value, which the store never seals"
        )

    def alert_reason(self) -> str:
        return (
            f"a {self.table}.{self.column} cell opens to an empty value, which the store never"
            f" seals (row {self.row_ref})"
        )


class NonTextCellError(CellTagError):
    """A tagged cell holds a value that is not text, a planted BLOB say: a preset's ``criteria``
    (BACKLOG #5523) or a ``messages`` cell (BACKLOG #5650). The store writes these cells as text
    only, so this was written outside the store. A keyed cipher handed it would fail with a
    ``TypeError``, and a keyless one would return it unchanged. Drift, as :class:`BlankCellError`
    is."""

    def _describe(self) -> str:
        return (
            f"integrity: the {self.table}.{self.column} cell of row {self.row_ref} is not text,"
            " which the store never writes"
        )

    def alert_reason(self) -> str:
        return (
            f"a {self.table}.{self.column} cell is not text, which the store never writes"
            f" (row {self.row_ref})"
        )


def _tag_failure_kind(cipher: Cipher, stored: str, exc: CipherError) -> type[CellTagError] | None:
    """The :class:`CellTagError` class a failed open of ``stored`` raises, or ``None`` to keep the
    cipher's own error: an outage, a key or a format problem."""
    if gave_no_verdict(exc):
        return None  # the key service gave no verdict, so nothing is known about the cell
    if isinstance(exc, UnmarkedCipherError):
        return UnmarkedCellError
    if not is_tag_failure(cipher, stored):
        return None
    if callable(getattr(cipher, "holds_key_for", None)):
        # Only a tag that failed under every held key can mean the cell was sealed elsewhere.
        return CellTagError if isinstance(exc, UnauthenticatedCipherError) else CorruptCellError
    # A cipher that cannot name its keys says when the value's own tag failed only when it
    # declares that it does (Vault Transit, whose UnauthenticatedCipherError is Transit's AEAD
    # refusal). A wrapper that just forgot holds_key_for may raise it for a key that is not
    # supplied, so its error stays its own. Other errors are not told apart by class, a corrupt
    # row among them, so they keep their own error too.
    if isinstance(exc, UnauthenticatedCipherError) and _declares_tag_refusals(cipher):
        return CellTagError
    return None


def _declares_tag_refusals(cipher: object) -> bool:
    """Whether ``cipher``, which cannot name its keys, declares that its
    :class:`~messagefoundry.store.crypto.UnauthenticatedCipherError` is the value's own tag
    failing, never a key it does not hold (``names_no_keys``, set by the Vault Transit cipher)."""
    return getattr(cipher, "names_no_keys", False) is True


def open_tagged_cell(
    cipher: Cipher,
    stored: object,
    aad: bytes,
    *,
    table: str,
    column: str,
    row_id: str,
    channel_id: str | None = None,
) -> str | None:
    """Open ``stored`` under ``aad``. ``None`` reads as ``None``, and a blank or unmarked value goes to
    the cipher's own policy, as the store's ``_dec`` does. A value that is not text, a planted BLOB
    say, raises :class:`NonTextCellError` on a keyed and a keyless store alike, rather than a
    ``TypeError`` out of the cipher or a non-text value back to the caller (BACKLOG #5650).

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
    _require_tagged_table(table)
    if stored is None:
        return None
    if not isinstance(stored, str):
        refused = NonTextCellError(table, column, row_id, channel_id)
        _alert(cipher, refused)
        raise refused
    try:
        return cipher.decrypt(stored, aad=aad)
    except CipherError as exc:
        kind = _tag_failure_kind(cipher, stored, exc)
        if kind is None:
            raise
        err = kind(table, column, row_id, channel_id)
        _alert(cipher, err)
        raise err from exc


def open_message_cell(
    cipher: Cipher, column: str, stored: object, *, message_id: str, channel_id: str
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


def open_message_record(cipher: Cipher, record: dict[str, Any]) -> None:
    """Open a whole ``messages`` row's cells in place, each under the tag its row's id and channel
    build (ASVS 11.3.3, BACKLOG #2593), so a cell that fails that tag refuses the whole read. Every
    backend's ``get_message`` runs it through ``asyncio.to_thread`` (BACKLOG #5981)."""
    for column in MESSAGE_TAG_CELLS:
        record[column] = open_message_cell(
            cipher,
            column,
            record[column],
            message_id=record["id"],
            channel_id=record["channel_id"],
        )


def open_preset_criteria(
    cipher: Cipher, stored: object, *, preset_id: str, owner_user_id: str
) -> str:
    """Open a preset's ``criteria`` under the tag its row's id and owner build.

    The store writes every preset's criteria as non-blank text, so a NULL or empty cell raises
    :class:`BlankCellError` and a value that is not text, a planted BLOB say, raises
    :class:`NonTextCellError`, on a keyed and a keyless store alike, and a sealed cell that opens to
    an empty string raises :class:`SealedBlankCellError` (BACKLOG #5523). Each is drift:
    logged here, alerted here on a keyed store only, and audited by the store's read, before the
    caller reads the cell or stamps the preset as used. The store's whole-surface cell walks do not run this check."""
    if stored is None or stored == "":
        # Not opened: a keyed cipher passes a blank value through.
        refused: CellTagError = BlankCellError("search_presets", "criteria", preset_id, None)
        _alert(cipher, refused)
        raise refused
    # open_tagged_cell refuses a non-text cell, and returns None only for a None cell, refused above.
    opened = cast(
        str,
        open_tagged_cell(
            cipher,
            stored,
            preset_criteria_aad(preset_id=preset_id, owner_user_id=owner_user_id),
            table="search_presets",
            column="criteria",
            row_id=preset_id,
        ),
    )
    if opened == "":
        refused = SealedBlankCellError("search_presets", "criteria", preset_id, None)
        _alert(cipher, refused)
        raise refused
    return opened


def require_preset_criteria(criteria: object) -> None:
    """Refuse, with ``ValueError``, criteria that are not text or are the empty string, before a
    preset write seals them: :func:`open_preset_criteria` refuses either as drift, so no writer
    stores one (BACKLOG #5523). It does not check the text is a JSON object; the layered search
    refuses one that is not, as malformed."""
    if not isinstance(criteria, str) or criteria == "":
        raise ValueError("a search preset's criteria must be text and not empty")


def withhold_message_cells(
    cipher: Cipher,
    record: dict[str, Any],
    columns: tuple[str, ...],
    *,
    message_id: str,
    channel_id: str,
    failures: list[CellTagError],
) -> None:
    """Open ``columns`` of one message in ``record`` in place, for a list-shaped read. A
    :class:`CellTagError` from :func:`open_message_cell`, which is at least a failed tag, a
    corrupt cell under a held key and an unmarked value, withholds every one of the row's cells
    (``None``) and appends the error to ``failures`` for the caller to audit or log, so the row
    still lists by its plaintext columns. A cell the cipher refused only for a key the store does
    not hold, a retired key version or an unknown one (:func:`refused_for_key`), withholds them
    too, but is only logged, never appended (:func:`withhold_refused_cell`, BACKLOG #5970). Any
    other cipher error raises, failing the read as before #5970 (owner ruling 2026-11-19): at
    least an outage, a malformed or truncated cell under a key the store does not hold, and a
    Transit refusal other than its tag that names no key version."""
    stored: str | None = None
    try:
        for col in columns:
            if col in record:
                stored = record[col]
                record[col] = open_message_cell(
                    cipher, col, stored, message_id=message_id, channel_id=channel_id
                )
    except CipherError as exc:
        if isinstance(exc, CellTagError):
            failures.append(exc)
        else:
            withhold_refused_cell(cipher, "messages", exc, stored)
        for col in columns:
            if col in record:
                record[col] = None


#: How long one cell's failure is reported once per process. A list view or a retention pass meets
#: the same failed row on every run; without this each run would write the WARNING, the alert and the
#: audit row again.
_REPORT_INTERVAL_S: Final = 3600.0
#: The most cells remembered; the oldest is forgotten first.
_REPORTED_MAX: Final = 4096
type _Key = tuple[str, str, str, type[CipherError]]
type _Memo = dict[_Key, float]
_reported: _Memo = {}
_reported_audit: _Memo = {}
#: The memos are touched from the event loop and from worker threads (the content-search scan, the
#: SQL Server fused handoff), so every read-modify-write holds this lock.
_reported_lock = threading.Lock()


def _memo_key(err: CellTagError) -> _Key:
    # By class, not only by drift: a corrupt or unmarked read never mutes a moved cell (BACKLOG #5650).
    return (err.table, err.column, err.row_ref, type(err))


def _warning_key(err: CellTagError) -> _Key:
    # An unmarked value's WARNING is per cell column, not per row: a keyless run can leave one in
    # every row it wrote, and a list over them would otherwise log each. Its audit row stays per
    # row (_memo_key), so every row is still audited in its own scope (BACKLOG #5650).
    if isinstance(err, UnmarkedCellError):
        return (err.table, err.column, "", type(err))
    return _memo_key(err)


def _is_recent(memo: _Memo, key: _Key, now: float) -> bool:
    last = memo.get(key)
    return last is not None and now - last < _REPORT_INTERVAL_S


def _remember(memo: _Memo, key: _Key, now: float) -> None:
    memo.pop(key, None)
    memo[key] = now
    while len(memo) > _REPORTED_MAX:
        memo.pop(next(iter(memo)))


def _first_in_interval(memo: _Memo, err: CellTagError, key: _Key | None = None) -> bool:
    """Whether ``err``'s cell (or ``key``) has not been reported in ``memo`` within the interval;
    records it."""
    key, now = (key if key is not None else _memo_key(err)), time.monotonic()
    with _reported_lock:
        if _is_recent(memo, key, now):
            return False
        _remember(memo, key, now)
    return True


#: The texts, lower-cased and matched WHOLE, never as a substring, that a Transit data-key
#: ``decrypt`` 400 names a retired or unknown key version with (BACKLOG #5970). Read on 2026-11-19
#: from Vault ``main``'s ``sdk/helper/keysutil/policy.go`` (``ErrTooOld``, ``DecryptWithOptions``,
#: ``safeGetKeyEntry``); OpenBao was not read. Decrypt-only on purpose: the audit walk's
#: :data:`~messagefoundry.store.crypto_transit._VERSION_REFUSAL_TEXTS` holds HMAC wording and is
#: matched as a substring, so a missing-key or malformed-cell reason that merely mentions a
#: version would read as one. Wording a release changes stops matching, so that refusal fails the
#: read loudly, the side the owner's ruling keeps. ``encryption key not found`` is deliberately
#: absent: Transit answers it when the store's configured key is missing, a fault of the whole
#: store rather than of a cell's key version, so a list read raises on it (owner ruling
#: 2026-11-19).
_TRANSIT_KEY_REFUSAL_TEXTS: Final = frozenset(
    {
        "ciphertext or signature version is disallowed by policy (too old)",
        "invalid ciphertext: version is too new",
        "no such key version",
    }
)


def _transit_refused_for_key(cause: BaseException | None) -> bool:
    """Whether a Transit ``decrypt`` failure's ``cause`` is Vault's HTTP 400 whose every reason
    names the cell's key version: one below ``min_decryption_version``, one past the key's latest,
    or one it has no entry for. Every other 400 is ``False``, at least invalid or truncated
    ciphertext, bad base64, a version number that does not decode, a missing prefix, the
    configured key not found, and a body too long to read. The reply is read by the Transit
    cipher's own bounded reader. A memory or stack fault reading it reads as ``False``, and is
    logged by class where the warning can still be written; a second such fault while logging is
    suppressed, so the warning is lost but the read still fails. Anything else the reader raises
    propagates in place of the cipher's error, which fails the read too."""
    from messagefoundry.store.crypto_transit import (  # noqa: PLC0415 -- Transit only
        _READ_FAULTS,
        _reply_errors,
    )
    from messagefoundry.store.keyprovider_vault import is_vault_bad_request  # noqa: PLC0415

    if not isinstance(cause, Exception) or not is_vault_bad_request(cause):
        return False
    try:
        errors, oversize = _reply_errors(cause, bound_parsed=True)
    except _READ_FAULTS as fault:
        kind = type(fault).__name__
        # Short of memory or stack, logging can fault again; the read still fails either way.
        with contextlib.suppress(*_READ_FAULTS):
            _log.warning("reading a Transit decrypt 400 raised %s; not read as a key refusal", kind)
        return False
    if oversize is not None or not isinstance(errors, list) or not errors:
        return False
    return all(
        isinstance(entry, str) and entry.strip().lower() in _TRANSIT_KEY_REFUSAL_TEXTS
        for entry in errors
    )


def refused_for_key(cipher: Cipher, exc: CipherError, stored: str | None) -> bool:
    """Whether ``exc``, from opening ``stored``, is the cipher refusing that cell only because it
    does not hold the key the cell names (BACKLOG #5970): in-process, a key not supplied, a
    retired key version, or an unknown one; under Transit, a retired or unknown key version only.
    Only such a cell may a list-shaped read withhold (owner ruling 2026-11-19); every other
    refusal fails the read.

    Under Transit only a retired or unknown key VERSION counts; a configured key Transit does not
    find is a fault of the whole store, so it fails the read.

    The in-process cipher, which names its keys (``holds_key_for``), says so with
    :class:`~messagefoundry.store.crypto.UnauthenticatedCipherError` for a marked value whose
    marker names a key id of the shape it writes (``named_key_id``) that it does not hold. Its
    plain :class:`~messagefoundry.store.crypto.CipherError` is a malformed, truncated or
    unknown-format value, so it is not. The Vault Transit cipher, which names none
    (``names_no_keys``), says so only in Vault's own 400 text (:func:`_transit_refused_for_key`).
    A cipher that declares neither is never read as refusing for its key. A tag failure, an
    outage and an unmarked value are never this.

    It reads the marker, which a writer outside the store can rewrite, so a substituted cell whose
    marker was rewritten to name a key the store does not hold reads as this too: in-process, a
    well-shaped key id outside the keyring; under Transit, a ``vault:vN`` version past the key's
    latest or below its ``min_decryption_version``. Neither can be told from a key genuinely not
    held."""
    if isinstance(exc, (CellTagError, UnmarkedCipherError)) or gave_no_verdict(exc):
        return False
    holds = getattr(cipher, "holds_key_for", None)
    if callable(holds):
        if stored is None or not isinstance(exc, UnauthenticatedCipherError):
            return False
        named = getattr(cipher, "named_key_id", None)
        return not holds(stored) and (not callable(named) or named(stored) is not None)
    if _declares_tag_refusals(cipher):
        return not isinstance(exc, UnauthenticatedCipherError) and _transit_refused_for_key(
            exc.__cause__
        )
    return False


#: One WARNING per (table, error class) per interval for a cell a list-shaped read withheld for
#: a key it does not hold; a list view meets the same cells on every refresh.
_withheld: _Memo = {}


def withhold_refused_cell(cipher: Cipher, table: str, exc: CipherError, stored: str | None) -> None:
    """For a list-shaped read that met a plain cipher error opening the ``table`` cell ``stored``
    (BACKLOG #5970): when the cipher refused it only for a key it does not hold
    (:func:`refused_for_key`), log
    that the cell was withheld, once per table and error class per interval, and return; else
    re-raise ``exc``, failing the read as before #5970 (owner ruling 2026-11-19). That raises at
    least an outage, a malformed or truncated cell, and a Transit 400 that names no key version.
    The class name only: the cipher's text can echo fields cut from the stored value."""
    if not refused_for_key(cipher, exc, stored):
        raise exc
    key, now = (table, "", "", type(exc)), time.monotonic()
    with _reported_lock:
        if _is_recent(_withheld, key, now):
            return
        _remember(_withheld, key, now)
    _log.warning(
        "a %s cell is sealed under a key the store does not hold (%s), so a list read withheld it",
        table,
        type(exc).__name__,
    )


def open_listed_cell(cipher: Cipher, stored: str | None, aad: bytes, *, table: str) -> str | None:
    """Open one cell of a table this module does not tag, for a list-shaped read, or ``None`` when
    the cipher refuses it only because it does not hold the key the cell names: in-process, a key
    not supplied, a retired key version or an unknown one; under Transit, a retired or unknown key
    version only (:func:`refused_for_key`, BACKLOG #5970). So one such cell withholds that cell
    rather than failing the page.

    Every other refusal raises the cipher's own error, failing the read as it did before #5970
    (owner ruling 2026-11-19): at least an outage, a tag that failed under a key the store holds
    (a substituted or tampered cell), a corrupt, malformed or truncated cell, an unmarked value,
    and any Transit refusal whose text names no key version. These tables have no tag-failed
    audit row or ``integrity_drift`` alert, so the failed read is the only signal, and withholding
    it would hide the tamper. A substituted cell whose marker was also rewritten to name a key the
    store does not hold cannot be told from a key genuinely not held, so it is withheld
    (:func:`refused_for_key` names the cases)."""
    if stored is None:
        return None
    try:
        return cipher.decrypt(stored, aad=aad)
    except CipherError as exc:
        withhold_refused_cell(cipher, table, exc, stored)
        return None


def _alert(cipher: object, err: CellTagError) -> None:
    """Log a WARNING and, for drift the cipher did not already alert on, raise ``integrity_drift``
    through the cipher's tag-failure hook, once per cell per interval. Never raises."""
    if not _first_in_interval(_reported, err, _warning_key(err)):
        return
    if not err.drift or err.cipher_alerted:
        # The text, not the error: a record keeps its args, and the error's chain reaches PHI.
        _log.warning("%s; the read was refused", str(err))
        return
    reason = err.alert_reason()
    _log.warning("%s; the read was refused", reason)
    report = getattr(cipher, "report_tag_failure", None)
    if callable(report):
        report(err.table, reason)


#: Exception classes that usually mean a defect in this code rather than a failed write, so the
#: audit write's refusal logs where they were raised (BACKLOG #6697).
_OWN_BUGS: Final = (TypeError, AttributeError, NameError, KeyError, IndexError)


def _frames(exc: BaseException) -> str:
    """``exc``'s traceback frames as file, line and function, without its message or its chain,
    which may carry a driver's text. No source line is read, so no file is opened on the event
    loop."""
    return "\nTraceback (frames only):" + "".join(
        f"\n  {frame.f_code.co_filename}:{lineno} in {frame.f_code.co_name}"
        for frame, lineno in traceback.walk_tb(exc.__traceback__)
    )


#: The shape of SQLite's own error names (``SQLITE_BUSY``). Any other ``sqlite_errorname`` value is
#: not logged, as ``transports/database.py`` withholds one.
_SQLITE_ERRORNAME: Final = re.compile(r"SQLITE_[A-Z_]{1,40}")


def _error_code(exc: BaseException) -> str | None:
    """The driver's SQLSTATE or SQLite error name for ``exc``, or ``None``. Never raises: the audit
    write's refusal is logged and swallowed, and a lookup that failed would escape that."""
    try:
        from messagefoundry.store.base import driver_sqlstate  # lazy: base imports this module

        code = driver_sqlstate(exc)
        if code:
            return code
        name = getattr(exc, "sqlite_errorname", None)
    except Exception as lookup:  # noqa: BLE001 -- a code is a nicety; the refusal still logs
        _log.debug("could not read the error code (%s)", type(lookup).__name__)
        return None
    return name if isinstance(name, str) and _SQLITE_ERRORNAME.fullmatch(name) else None


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
    """Write the audit row for ``err``, unless the cell's row was already written within the interval
    (then nothing is written and ``err`` is marked reported). The alert was raised when the read was
    refused. An audit failure is logged and swallowed: reporting must never change what the read
    did. A corrupt cell is not drift, so it writes no tag-failed row; its WARNING was logged at the
    read.

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
        # A programming error gets its frames, so its site can be found, but still not its message
        # or its chain, either of which may hold a driver's text.
        _log.error(
            "the %s audit row for the %s.%s cell of row %s could not be written (%s, code %s); it"
            " is written only if the cell is refused again%s",
            action,
            err.table,
            err.column,
            err.row_ref,
            type(exc).__name__,
            _error_code(exc),
            _frames(exc) if isinstance(exc, _OWN_BUGS) else "",
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
    (BACKLOG #6698). Every layer of a ``functools.wraps`` chain that has a code object is read, the
    one this wrapper calls included, and none may take ``routed_id`` positionally or give it a
    default. A layer without a code object, such as an ``lru_cache`` wrapper or a callable object,
    is skipped by that read. Where the chain's innermost layer has a code object and no layer carries a
    ``__signature__``, that layer must take ``routed_id`` keyword-only. Otherwise
    ``inspect.signature`` decides it, as before this walk: ``routed_id`` must be keyword-only with
    no default in the signature it reports. What a layer does with ``*args`` or ``**kwargs`` is not
    read."""
    name = getattr(fn, "__qualname__", repr(fn))
    layers: list[object] = [fn]
    while hasattr(layers[-1], "__wrapped__"):
        if len(layers) >= sys.getrecursionlimit():  # the bound inspect.unwrap applies
            raise TypeError(f"{name} has a __wrapped__ chain too long to read")
        layer = layers[-1].__wrapped__
        if any(layer is seen for seen in layers):
            raise TypeError(f"{name} has a cycle in its __wrapped__ chain")
        layers.append(layer)
    # A layer with no code object (an lru_cache wrapper, a callable object) is skipped, and the
    # layers that have one are judged.
    coded = [(layer, code) for layer in layers if (code := getattr(layer, "__code__", None))]
    # The code objects give the signature the call reaches only when the chain's innermost layer has
    # one and no layer declares a __signature__ (mock.create_autospec does). Otherwise the signature
    # read below decides whether routed_id is keyword-only with no default.
    walk_decides = (
        bool(coded)
        and coded[-1][0] is layers[-1]
        and not any(hasattr(layer, "__signature__") for layer in layers)
    )
    for depth, (layer, code) in enumerate(coded):
        # Each refusal names the layer that failed: functools.wraps copies the innermost's
        # __qualname__ onto every layer, so the code object's own name is read.
        label = code.co_qualname
        if "routed_id" in code.co_varnames[: code.co_argcount]:
            raise TypeError(f"{label} must take routed_id as a keyword-only parameter")
        keyword_only = code.co_varnames[
            code.co_argcount : code.co_argcount + code.co_kwonlyargcount
        ]
        if walk_decides and depth == len(coded) - 1 and "routed_id" not in keyword_only:
            raise TypeError(f"{label} must take routed_id as a keyword-only parameter")
        if "routed_id" in (getattr(layer, "__kwdefaults__", None) or {}):
            raise TypeError(f"{label} must give its keyword-only routed_id no default")
    if not walk_decides:
        # STRING: only the kind is read, so no annotation is evaluated (a TYPE_CHECKING-only one
        # would raise NameError at decoration).
        sig = inspect.signature(fn, annotation_format=annotationlib.Format.STRING)
        param = sig.parameters.get("routed_id")
        if (
            param is None
            or param.kind is not inspect.Parameter.KEYWORD_ONLY
            or param.default is not inspect.Parameter.empty
        ):
            raise TypeError(
                f"{name} must take routed_id as a keyword-only parameter with no default"
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

    The audit is written even when the dead-letter fails with an ``Exception``, whose error then
    propagates: the row stays in flight, meets the tag failure again on its re-run and is
    dead-lettered then, and the audit row is not lost meanwhile (BACKLOG #6698). A
    ``BaseException`` that is not an ``Exception``, such as a cancellation, ``KeyboardInterrupt`` or
    ``SystemExit``, propagates with NO audit write, so a store write never holds up a shutdown;
    that audit row is written only if the cell is refused again."""
    try:
        await store.dead_letter_now(row_id, str(err))
    except Exception:
        # Exception, not BaseException: a cancellation, KeyboardInterrupt or SystemExit propagates
        # at once and skips the audit write, which is then made only if the cell is refused again.
        # An Exception is re-raised after the audit.
        await report_cell_tag_failure(store, err)
        raise
    await report_cell_tag_failure(store, err)


async def report_cell_tag_failures(store: _AuditSink, failures: list[CellTagError]) -> None:
    """:func:`report_cell_tag_failure` for each failure a list-shaped read collected."""
    for err in failures:
        await report_cell_tag_failure(store, err)
