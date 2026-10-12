# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The tag a staged-queue row's ``payload`` cell is sealed under (BACKLOG #2593).

A queue row's ``payload`` is an AEAD cell. Its associated data, the **tag**, binds the cell to the
row's identity AND to the fields the engine routes the row by: ``id``, ``message_id``, ``stage``,
``channel_id``, ``destination_name``, ``handler_name``, the body kind (``inline`` or ``ref``) and the
store id. A cell opens only on the row it was sealed for, so a change to any of those columns made
outside the store's writers stops the cell opening, and the claim dead-letters the row.

**One helper builds every tag.** :func:`queue_payload_aad` is the only builder, and
:func:`queue_row_aad` reads its inputs off a row. ``tests/test_queue_tag.py`` asserts that no store
module builds the queue payload's associated data any other way.

**One encoder.** The routing fields are encoded by :func:`~messagefoundry.store.row_seal.seal_bytes`,
the row-seal encoder (BACKLOG #2592), so a NULL ``destination_name``, the empty string and the text
``"None"`` give three different tags. The encoding is wrapped in the :func:`cell_aad` frame for
``queue.payload``, so :func:`~messagefoundry.store.crypto.aad_cell_name` still names the cell in a
refusal.

**A shared-body row seals its reference.** A store-once fan-out row (``body_ref`` set) keeps its body
once in ``shared_body``. Its own ``payload`` holds the ``shared_body`` key, sealed under the row's tag
with body kind ``ref``. :func:`open_queue_cell` opens it and refuses the row when the sealed key and
the ``body_ref`` column differ. So every deliverable row holds exactly one sealed cell, and a row whose
``payload`` is blank is never delivered on a keyed store.

**The store id.** The tag carries the store id the row was written under. No store id is minted yet
(BACKLOG #2592 uses the same placeholder), so every tag today carries
:data:`~messagefoundry.store.crypto.NO_STORE_ID`.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Final, Protocol

from messagefoundry.store.crypto import NO_STORE_ID, CipherError, cell_aad
from messagefoundry.store.row_seal import seal_bytes

if TYPE_CHECKING:
    from messagefoundry.store.crypto import Cipher

__all__ = [
    "BODY_INLINE",
    "BODY_REF",
    "QUEUE_TAG_COLUMNS",
    "QUEUE_TAG_SELECT",
    "QUEUE_TAG_FAILED_ACTION",
    "QueueTagError",
    "alert_queue_tag_failure",
    "is_tag_failure",
    "open_queue_cell",
    "queue_payload_aad",
    "queue_row_aad",
    "report_queue_tag_failure",
]

_log = logging.getLogger(__name__)

#: The body kind of a row whose body is its own ``payload``.
BODY_INLINE: Final = "inline"
#: The body kind of a store-once row: its ``payload`` holds the sealed ``shared_body`` key.
BODY_REF: Final = "ref"

#: The ``seal_bytes`` kind the routing fields are encoded under. Its own kind, so a queue tag can
#: never equal the encoding of an authority-row seal.
_QUEUE_TAG_KIND: Final = "queue-payload"

#: The queue columns a tag is built from, in the order :func:`queue_row_aad` reads them. A reader
#: that opens a payload must SELECT every one of them.
QUEUE_TAG_COLUMNS: Final = (
    "id",
    "message_id",
    "stage",
    "channel_id",
    "destination_name",
    "handler_name",
    "body_ref",
)
#: :data:`QUEUE_TAG_COLUMNS` as a SELECT list.
QUEUE_TAG_SELECT: Final = ", ".join(QUEUE_TAG_COLUMNS)

#: The audit action written when a queue row's payload does not open under its own tag.
QUEUE_TAG_FAILED_ACTION: Final = "integrity.queue_tag_failed"

#: How much of a queue row id an audit row or alert names. Row ids are random, never PHI.
_ROW_REF_LEN: Final = 12


class QueueTagError(CipherError):
    """A queue row's ``payload`` did not open under the tag its own routing fields build.

    Raised for a cell whose AEAD tag fails, a blank ``payload`` where a sealed cell must be, and a
    sealed ``shared_body`` key that differs from the row's ``body_ref``. A subclass of
    :class:`CipherError`, so every claim path that already dead-letters an undecryptable row
    dead-letters this one the same way. Carries no row value."""


def queue_payload_aad(
    *,
    row_id: str,
    message_id: str,
    stage: str,
    channel_id: str,
    destination_name: str | None,
    handler_name: str | None,
    body_ref: str | None,
    store_id: bytes = NO_STORE_ID,
) -> bytes:
    """The associated data for one queue row's ``payload`` cell.

    ``body_ref`` decides the body kind and is not itself in the tag: a ``ref`` row seals the
    reference inside the cell, where :func:`open_queue_cell` checks it against the column."""
    fields: tuple[tuple[str, object], ...] = (
        ("store_id", bytes(store_id)),
        ("id", row_id),
        ("message_id", message_id),
        # A str-valued Enum member is passed by some callers; its value is what the column holds.
        ("stage", str(getattr(stage, "value", stage))),
        ("channel_id", channel_id),
        ("destination_name", destination_name),
        ("handler_name", handler_name),
        ("body_kind", BODY_INLINE if body_ref is None else BODY_REF),
    )
    encoded = seal_bytes(_QUEUE_TAG_KIND, fields)
    # The cell_aad frame names the cell, and the routing encoding is its one trailing field.
    return cell_aad("queue", "payload") + len(encoded).to_bytes(4, "big") + encoded


def queue_row_aad(row: Any) -> bytes:
    """:func:`queue_payload_aad` for a fetched queue row: anything indexable by column name that
    holds every column in :data:`QUEUE_TAG_COLUMNS`. A missing column raises, so a reader that
    forgot to select one fails closed rather than building a different tag."""
    return queue_payload_aad(
        row_id=row["id"],
        message_id=row["message_id"],
        stage=row["stage"],
        channel_id=row["channel_id"],
        destination_name=row["destination_name"],
        handler_name=row["handler_name"],
        body_ref=row["body_ref"],
    )


def is_tag_failure(cipher: Cipher, stored: str) -> bool:
    """Whether a failed open of ``stored`` means the cell does not belong to its row, rather than a
    key or format problem: the value is marked and the cipher holds the key its marker names.

    An unmarked value is the cipher's own refusal, which raises its own alert, and a value under a
    key that is not configured is a key-configuration fault. Neither is a tag failure. A cipher that
    cannot say which keys it holds (Vault Transit) counts every marked value as held."""
    if not cipher.is_encrypted(stored):
        return False
    holds = getattr(cipher, "holds_key_for", None)
    return bool(holds(stored)) if callable(holds) else True


def open_queue_cell(cipher: Cipher, row: Any) -> str:
    """Open ``row``'s ``payload`` under its own tag: the body for an inline row, the sealed
    ``shared_body`` key for a ``ref`` row.

    Raises :class:`QueueTagError` when the cell does not open under the row's tag (see
    :func:`is_tag_failure`; a key or format problem raises the cipher's own error), when a keyed
    store's row (or any ``ref`` row) holds a blank ``payload``, or when a ``ref`` row's sealed key
    differs from its ``body_ref`` column. A keyless store writes plaintext and has no tag to check,
    so there only the reference comparison binds anything."""
    payload = row["payload"]
    body_ref = row["body_ref"]
    if payload == "" and (cipher.encrypts or body_ref is not None):
        # A keyed writer seals every body, an empty one included, and a ref row always holds its
        # reference. Blank is what retention leaves, so it is never a cell to deliver.
        raise QueueTagError("integrity: the queue row holds no sealed payload")
    try:
        opened = cipher.decrypt(payload, aad=queue_row_aad(row))
    except CipherError as exc:
        if not is_tag_failure(cipher, payload):
            raise  # a key or format problem, which the cipher's own error names
        raise QueueTagError(
            f"integrity: the queue row's payload does not open under its own tag ({exc})"
        ) from exc
    if body_ref is not None and opened != body_ref:
        raise QueueTagError("integrity: the queue row's sealed reference differs from its body_ref")
    return opened


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
        expect_prev: str | None = None,
    ) -> None: ...


async def report_queue_tag_failure(store: _AuditSink, cipher: object, row: Any) -> None:
    """Record that ``row`` failed its queue tag: a WARNING, a :data:`QUEUE_TAG_FAILED_ACTION` audit
    row and an ``integrity_drift`` alert through the cipher's tag-failure hook (BACKLOG #2593).

    The caller has already dead-lettered the row, so the lane has moved on and the message is
    ``ERROR``. Names the row by a short id prefix and its stage, never a row value. An audit or
    alert failure is logged and swallowed: reporting must never undo the dead-letter."""
    ref = str(row["id"])[:_ROW_REF_LEN]
    stage = row["stage"]
    try:
        await store.record_audit(
            QUEUE_TAG_FAILED_ACTION,
            actor="system",
            channel_id=row["channel_id"],
            detail=json.dumps({"queue_row": ref, "stage": stage}, sort_keys=True),
        )
    except Exception:  # noqa: BLE001 -- the dead-letter stands whatever the audit write does
        _log.exception("the %s audit row could not be written", QUEUE_TAG_FAILED_ACTION)
    alert_queue_tag_failure(cipher, row, outcome="was dead-lettered")


def alert_queue_tag_failure(cipher: object, row: Any, *, outcome: str) -> None:
    """Log a WARNING and raise the ``integrity_drift`` alert for ``row`` through the cipher's
    tag-failure hook, with no audit row (BACKLOG #2593).

    The audit-free form is for a read that runs inside a writer transaction (an operator resend's
    source), which cannot take the writer lock again; that read is refused, and ``outcome`` says
    so. Names the row by its stage and a short id prefix, never a row value. Never raises."""
    reason = (
        f"a {row['stage']} queue row failed its integrity tag and {outcome}"
        f" (row {str(row['id'])[:_ROW_REF_LEN]})"
    )
    _log.warning("%s", reason)
    report = getattr(cipher, "report_tag_failure", None)
    if callable(report):
        report("queue", reason)
