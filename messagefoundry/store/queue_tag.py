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
import time
from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar, Final, Literal, Protocol

from messagefoundry.store.crypto import (
    NO_STORE_ID,
    CipherError,
    CipherUnavailableError,
    UnauthenticatedCipherError,
    cell_aad,
)
from messagefoundry.store.row_seal import seal_bytes

if TYPE_CHECKING:
    from messagefoundry.store.crypto import Cipher

__all__ = [
    "BODY_INLINE",
    "BODY_REF",
    "LIVE_INLINE_ROW",
    "QUEUE_TAG_COLUMNS",
    "QUEUE_TAG_SELECT",
    "PROGRAMMING_ERRORS",
    "QUEUE_CORRUPT_ALERT_TABLE",
    "QUEUE_TAG_CAUSES",
    "QUEUE_TAG_FAILED_ACTION",
    "TRANSIENT_OPEN_BACKOFF_SECONDS",
    "QueueOpenFault",
    "queue_open_fault",
    "release_unreturned",
    "set_aside_deadline",
    "CorruptQueueCellError",
    "QueueTagCause",
    "QueueTagError",
    "alert_queue_tag_failure",
    "is_tag_failure",
    "is_transient_open_failure",
    "open_queue_cell",
    "queue_payload_aad",
    "queue_row_aad",
    "report_queue_tag_failure",
    "reseal_unless_tag_failure",
]

_log = logging.getLogger(__name__)

#: The body kind of a row whose body is its own ``payload``.
BODY_INLINE: Final = "inline"
#: The body kind of a store-once row: its ``payload`` holds the sealed ``shared_body`` key.
BODY_REF: Final = "ref"

#: A queue row a blank ``payload`` on a keyless store is taken as a real, empty body for (BACKLOG
#: #3495): an inline row that is still owed work. Retention blanks only ``done``, ``cancelled`` and
#: ``dead`` rows, so a blank ``pending`` or ``inflight`` row is a keyless writer's ``encrypt('')`` or a
#: plant. Nothing tells those apart on a surface with no ciphertext, where a planted plaintext value is
#: sealed too (docs/PHI.md names that limit). A blank terminal row may be an erasure and cannot be told
#: from an empty body. A ``ref`` row and a ``response`` re-ingress token are left out, because each
#: writer always stores a reference, so a blank there is damage and stays refused. Literal values, so
#: each backend can splice this beside its own spelling of "blank".
LIVE_INLINE_ROW: Final = (
    "body_ref IS NULL AND stage <> 'response' AND status IN ('pending', 'inflight')"
)

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

#: How long a per-lane claim sets a row aside when opening it failed for a reason that is not the
#: row (BACKLOG #5735): the row goes back to ``pending`` with ``next_attempt_at`` this far past the
#: fault (:func:`set_aside_deadline`), so a key service that gave no verdict is retried no sooner
#: than this rather than on every sweep, with no cap and no alert of its own. Only
#: ``claim_fifo_heads`` does not use it: it hands the fault to the pooled dispatcher's ADR 0070 T17
#: path, whose own backoff, ``infra_fault_policy`` and ``lane_stuck`` alert bound it. Pooled mode
#: still runs per-lane claims, at least an unordered lane's ``claim_ready`` and a batch window's
#: ``claim_next_fifo``, and those are not bounded.
TRANSIENT_OPEN_BACKOFF_SECONDS: Final = 5.0


def set_aside_deadline(claim_now: float | None) -> float:
    """The ``next_attempt_at`` a per-lane claim sets a row aside to (BACKLOG #5735):
    :data:`TRANSIENT_OPEN_BACKOFF_SECONDS` after the fault, read from the clock at the set-aside
    write, not from the claim's start. A decrypt that timed out slowly would otherwise leave a
    deadline already past, and the row would be re-claimed at once. Never earlier than the claim's
    own ``claim_now`` plus the backoff either, so a claim given an injected time later than the
    clock still finds the row not due."""
    fault_at = time.time()
    return max(fault_at, claim_now or fault_at) + TRANSIENT_OPEN_BACKOFF_SECONDS


#: The errors a claim never contains as a failed dead-letter write (BACKLOG #5735): each names a
#: fault in the engine's own code, which must stay loud, never one in the store or the key service.
PROGRAMMING_ERRORS: Final = (AssertionError, AttributeError, LookupError, NameError, TypeError)


class QueueOpenFault(Exception):
    """A claimed queue row that could not be opened for a reason that is not the row (BACKLOG
    #5735): a key service that gave no verdict, a failed store read, or a failed dead-letter write.
    Built by :func:`queue_open_fault` with no cause, context or traceback, so a handler that logs
    it with ``exc_info`` prints neither the raw key-service error, which can echo a URL or a
    request body (BACKLOG #2318), nor the claim's frames, which hold other rows' plaintext (BACKLOG
    #6706)."""


def queue_open_fault(exc: BaseException) -> QueueOpenFault:
    """:class:`QueueOpenFault` naming ``exc`` by its type, and by its own text only where ``exc``
    is a :class:`CipherError`, whose text never holds a value. Any other error, a failed store read
    or dead-letter write, is named by its type alone: a driver's text can echo a statement, a key
    or a truncated value, and the T17 path logs this fault at ERROR."""
    if isinstance(exc, CipherError):
        return QueueOpenFault(f"{type(exc).__name__}: {exc}")
    return QueueOpenFault(type(exc).__name__)


class _Releaser(Protocol):
    async def release_claimed(self, ids: Sequence[str], now: float | None = None) -> None: ...


async def release_unreturned(store: _Releaser, lanes: Iterable[Iterable[Any]]) -> None:
    """Return every row of ``lanes`` that ``claim_fifo_heads`` claimed but will not return to
    ``pending``, through ``store.release_claimed``, before the claim re-raises an ``Exception``
    that escaped its decode (BACKLOG #5735). The claim committed before it decoded, so without
    this every lane's rows stay ``inflight`` and the next claim delivers past them. A cancellation,
    or any other ``BaseException`` that is not an ``Exception``, that escapes the decode never
    reaches this: the claim leaves its rows ``inflight`` then, as the pooled dispatcher's teardown
    leaves a cancelled serializer's (ADR 0066), for lease expiry or ``reset_stale_inflight``, with
    the claim's ``attempts`` increment left in place. A release during a demotion's cancel is a
    return-to-``pending`` write ADR 0157 C1 leaves unfenced, so it could re-pend rows a successor
    already claimed. A row the claim already settled (dead-lettered) is
    not ``inflight``, and the release leaves it as it is. A release that fails with an
    ``Exception``, building the id list included, is logged and swallowed, so the caller re-raises
    the original error; the rows then stay ``inflight`` until ``reset_stale_inflight``. A
    cancellation delivered while the release awaits is not swallowed: it propagates in place of
    the original error, which survives only as its ``__context__``, and the release may not land,
    leaving the rows ``inflight`` as any other cancellation does."""
    ids: list[str] = []
    try:
        ids = [str(row["id"]) for rows in lanes for row in rows]
        await store.release_claimed(ids)
    except Exception as failed:  # noqa: BLE001 -- the error being re-raised must stay the caller's
        _log.error(
            "could not release %d claimed queue row(s) after an error in the claim (%s);"
            " they stay inflight until the next start",
            len(ids),
            type(failed).__name__,
        )


#: The audit action written when a claimed queue row is refused by :func:`open_queue_cell` or a
#: claim's own check, whatever the cause: its detail's ``cause`` (:data:`QUEUE_TAG_CAUSES`) says
#: which, and only ``tag`` means the row's tag failed.
QUEUE_TAG_FAILED_ACTION: Final = "integrity.queue_tag_failed"

#: How much of a queue row id an audit row or alert names. Row ids are random, never PHI.
_ROW_REF_LEN: Final = 12


type QueueTagCause = Literal[
    "tag",
    "unknown",
    "corrupt",
    "blank",
    "ref",
    "ref-unsealed",
    "ref-not-delivered",
]

#: Every ``cause`` a :class:`QueueTagError` carries, and the words its alert and WARNING use for it
#: (BACKLOG #5884). **The values are defined here once**; the ``cause`` field of an
#: ``integrity.queue_tag_failed`` audit row's detail is one of these keys. Each states only what the
#: code knows when it raises:
#:
#: - ``tag``: the cell's AEAD check failed under the row's own tag. The cell was sealed for another
#:   row, or its ciphertext was altered; an AEAD check cannot tell those apart.
#: - ``unknown``: the row was refused and its cause was not determined. Nothing more is claimed.
#:   A Vault Transit verdict that is not an AEAD failure reads this, as does a
#:   :class:`QueueTagError` raised with no cause.
#: - ``corrupt``: a cipher that names its keys refused a cell under a key it holds for a reason
#:   other than a failed AEAD check (:class:`CorruptQueueCellError`).
#: - ``blank``: the row holds a blank ``payload`` where a sealed cell must be.
#: - ``ref``: on a keyed store, a store-once row's cell opened and the ``shared_body`` key it holds
#:   differs from the row's ``body_ref`` column. Whether this one payload was sealed is not checked.
#: - ``ref-unsealed``: as ``ref``, on a keyless store, where nothing is sealed.
#: - ``ref-not-delivered``: a store-once row on a backend that does not deliver one; its cell opened
#:   and nothing says it was altered.
QUEUE_TAG_CAUSES: Final[Mapping[QueueTagCause, str]] = MappingProxyType(
    {
        "tag": "failed its integrity tag",
        "unknown": "was refused, and its cause was not determined,",
        "corrupt": "holds a payload that is corrupt",
        "blank": "holds no sealed payload",
        "ref": "holds a reference that differs from its body_ref (the store is keyed)",
        "ref-unsealed": "holds a reference that differs from its body_ref (the store is keyless)",
        "ref-not-delivered": "is a store-once row, which this backend does not deliver,",
    }
)

#: The table name :func:`alert_queue_tag_failure` hands the cipher's tag-failure hook for a corrupt
#: cell, so its alert takes its own ``integrity_drift`` subject and throttle key
#: (``pipeline.alerts.QUEUE_CORRUPT_SUBJECT``), never the drift subject's (BACKLOG #5884). A corrupt
#: cell inside the cooldown then cannot hold back a drift page, as ``cell_tag`` keys by class
#: (BACKLOG #5650). A test pins the two spellings together.
QUEUE_CORRUPT_ALERT_TABLE: Final = "queue-corrupt"


class QueueTagError(CipherError):
    """A queue row's ``payload`` was refused: it did not open under the tag its own routing fields
    build, or it opened and a check refused it.

    Raised for at least a cell whose AEAD tag fails, a cell a cipher refused for a cause it did not
    name, a corrupt cell (:class:`CorruptQueueCellError`), a blank ``payload`` where a sealed cell
    must be, a ``shared_body`` key that differs from the row's ``body_ref``, and a store-once row on
    a backend that does not deliver one. A subclass of
    :class:`CipherError`, so every claim path that already dead-letters an undecryptable row
    dead-letters this one the same way. Carries no row value. Its :attr:`cause` names which case it
    was, from :data:`QUEUE_TAG_CAUSES`."""

    #: Whether the refusal is drift rather than a corrupt cell, :class:`CorruptQueueCellError`. A
    #: claim audits and alerts both; a read alerts both and writes no audit row.
    drift: ClassVar[bool] = True
    #: What the code knows about this failure, a key of :data:`QUEUE_TAG_CAUSES`.
    cause: QueueTagCause = "unknown"

    def __init__(self, message: str, *, cause: QueueTagCause | None = None) -> None:
        super().__init__(message)
        if cause is not None:
            # ``corrupt`` and ``drift`` must agree, or the alert's subject and words disagree.
            if (cause == "corrupt") == self.drift:
                raise ValueError(f"cause {cause!r} contradicts {type(self).__name__}")
            self.cause = cause


class CorruptQueueCellError(QueueTagError):
    """A queue row's ``payload`` under a key this process holds that no tag check can judge,
    because the cell is corrupt (BACKLOG #5884). That covers at least bad base64, a ciphertext too
    short to hold a tag, and a plaintext whose tag VERIFIED but is not UTF-8. A cell whose marker
    the cipher cannot read is not this error, nor any :class:`QueueTagError`: docs/PHI.md section 1,
    *A database writer is refused only where a seal or a tag covers the row*, names that gap.

    It is not drift, so its alert says corrupt rather than a failed tag, under its own alert
    subject (:data:`QUEUE_CORRUPT_ALERT_TABLE`), and a claim's audit row names cause ``corrupt``.
    Unlike :class:`~messagefoundry.store.cell_tag.CorruptCellError`, which is logged only, it keeps
    the audit row and the alert: a queue row that cannot be read is a dead-lettered message an
    operator must see. It is a :class:`QueueTagError`, so every claim and read contains it the same
    way: a claim dead-letters the row, a read is refused."""

    drift = False
    cause = "corrupt"


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
    cannot say which keys it holds (Vault Transit) counts every marked value as held. This reads the
    VALUE only: whether a given failed open was the key service failing instead is the caller's
    question, :func:`is_transient_open_failure` (BACKLOG #5765). Nor does it tell a corrupt cell
    from one sealed for another row: :func:`open_queue_cell` makes that split after this check
    (BACKLOG #5884)."""
    if not cipher.is_encrypted(stored):
        return False
    holds = getattr(cipher, "holds_key_for", None)
    return bool(holds(stored)) if callable(holds) else True


def _names_its_keys(cipher: object) -> bool:
    """Whether ``cipher`` can say which keys it holds (Vault Transit cannot)."""
    return callable(getattr(cipher, "holds_key_for", None))


#: The only HTTP statuses that are the key service's verdict on the row (BACKLOG #5765): 400 and
#: 413. A 400 is at least invalid ciphertext or input, or a key version that is unknown or below
#: the key's ``min_decryption_version``, and Transit also answers it when the configured key itself
#: is missing ("encryption key not found"); this rule reads every 400 as a verdict all the same. A
#: 413 is a payload too large. A 404 is not a verdict: Vault answers it for a path it has no handler
#: for, such as a missing mount or a wrong namespace, and the path is built from engine config,
#: never from the row.
_VERDICT_STATUSES: Final = frozenset({400, 413})

#: The ``hvac`` error classes for a reply whose status is not a verdict, as hvac 2.4.0's
#: ``VaultError.from_status`` maps them: 401 ``Unauthorized``, 403 ``Forbidden``, 404
#: ``InvalidPath``, 429 ``RateLimitExceeded``, 500 ``InternalServerError``, 501
#: ``VaultNotInitialized``, 502 ``BadGateway``, 503 ``VaultDown`` (a sealed or standby node), and
#: ``UnexpectedError`` for every other status. hvac also defines ``UnsupportedOperation`` and
#: ``PreconditionFailed``, which that map does not raise; they are kept in case another hvac
#: release or caller raises them for a 405 or 412, neither of which is a verdict. Read only when no
#: status was recorded on the error. ``InvalidRequest`` (400) is a verdict, so it is not here. Named
#: rather than imported, so ``hvac`` stays imported in ``keyprovider_vault`` only (BACKLOG #2337).
_NO_VERDICT_HVAC_ERRORS: Final = frozenset(
    {
        "Unauthorized",
        "Forbidden",
        "UnsupportedOperation",
        "InvalidPath",
        "PreconditionFailed",
        "RateLimitExceeded",
        "InternalServerError",
        "VaultNotInitialized",
        "BadGateway",
        "VaultDown",
        "UnexpectedError",
    }
)

#: The attribute the store's Vault client sets on an error raised for a reply, to that reply's
#: HTTP status (``keyprovider_vault._REPLY_STATUS_ATTR``, BACKLOG #8222). It is set on whatever
#: class hvac raised, an ``UnexpectedError``, a ``TypeError`` or any other, so it is read on a
#: cause of any class, and before the cause's class.
_REPLY_STATUS_ATTR: Final = "mefor_reply_status"

#: The engine's own refusal of a hop's TLS settings, ``tls_policy.InsecureHopRefused``, which the
#: strict Vault adapter raises as its subclass ``VaultHopRefused``. Named rather than imported, so
#: this module adds no TLS-policy use to the crypto inventory.
_HOP_REFUSED: Final = ("messagefoundry.config.tls_policy", "InsecureHopRefused")


def _key_service_gave_no_verdict(exc: CipherError) -> bool:
    """Whether ``exc`` says nothing about the row, because the key service gave no verdict on it.

    **The rule, stated here once (BACKLOG #5765, #5735).** A failed open is the key service's
    verdict on the row only when the service answered HTTP 400 (invalid ciphertext or input) or 413
    (payload too large), or when a decrypt or tag check ran and failed
    (:class:`UnauthenticatedCipherError`). Everything else about reaching or authenticating to the
    key service gives no verdict, at least: a 401, 403 or 408; a 404, which names a path the
    engine's config built, such as a missing mount or a wrong namespace; a 429 or any
    5xx; a connection failure, timeout, dropped connection or cut-off reply (an ``OSError`` cause,
    which every ``requests`` error is); a TLS or certificate refusal, the engine's own hop refusal
    (``InsecureHopRefused``) among them; a reply the engine would not read (``EgressReplyError``,
    which the strict Vault adapter raises unwrapped); an ``UnexpectedError`` with
    no recorded status; and a :class:`CipherUnavailableError`. A reply status the store's client
    recorded (:data:`_REPLY_STATUS_ATTR`) decides first, on a cause of any class.

    Any other cipher error keeps the classification it had before this rule, a verdict: one with
    no cause, or whose cause none of the above names, such as a malformed reply's ``KeyError`` or
    hvac's client-side ``ParamValidationError``.

    Deliberately not :func:`~messagefoundry.store.crypto.gave_no_verdict` or
    :func:`~messagefoundry.store.keyprovider_vault.is_vault_timeout_reply`: other modules read
    those, and this rule does not change them. Nor does it rest on the Transit cipher's own split
    into :class:`CipherUnavailableError` (``keyprovider_vault.is_vault_unavailable``), which keeps
    a 403, a 504 and a certificate refusal as plain refusals for the upload routes' 423: this rule
    reads the cause itself, so for those three the two answers differ on purpose."""
    if isinstance(exc, UnauthenticatedCipherError):
        return False  # the decrypt ran and the tag check failed
    if isinstance(exc, CipherUnavailableError):
        return True
    cause = exc.__cause__
    if cause is None:
        return False  # nothing to read: a verdict, as before this rule
    status = getattr(cause, _REPLY_STATUS_ATTR, None)
    if type(status) is int:
        return status not in _VERDICT_STATUSES
    if type(cause).__module__.split(".")[0] == "hvac":
        return type(cause).__name__ in _NO_VERDICT_HVAC_ERRORS
    from messagefoundry.transports.bounded_read import EgressReplyError  # noqa: PLC0415

    # The strict Vault adapter raises these itself, unwrapped: a hop it refused, and a reply it
    # would not read. A cause none of the above names is unknown here: a verdict, as before.
    return isinstance(cause, (OSError, EgressReplyError)) or any(
        (kind.__module__, kind.__qualname__) == _HOP_REFUSED for kind in type(cause).__mro__
    )


def is_transient_open_failure(exc: BaseException) -> bool:
    """Whether a failed open said nothing about the cell (BACKLOG #5765, #5735), by the rule
    :func:`_key_service_gave_no_verdict` states. Such a failure is never a tag failure, and a claim
    sets the row aside with a backoff (:data:`TRANSIENT_OPEN_BACKOFF_SECONDS`) rather than
    dead-lettering it. A :class:`QueueTagError` is never transient: it is raised only after this
    check passed."""
    return (
        isinstance(exc, CipherError)
        and not isinstance(exc, QueueTagError)
        and _key_service_gave_no_verdict(exc)
    )


def reseal_unless_tag_failure(cipher: Cipher, stored: str, aad: bytes) -> str | None:
    """Re-seal ``stored`` under the active key with the same ``aad``, or ``None`` for a tag failure.

    The one seam the rotation's tagged-cell loops step over a cell with (BACKLOG #2593, #5610). Only
    the DECRYPT may be skipped, and only for :class:`UnauthenticatedCipherError` on a cell
    :func:`is_tag_failure` names: a marked value whose AEAD tag fails under a key this process holds.
    Every other failure raises and stops the rotation, at least: a malformed envelope (bad base64,
    too short), a verified plaintext that is not UTF-8, and anything the ENCRYPT raises, the active
    key's invocation ceiling above all. Counting those as tag failures would leave rows under a
    retired key while the rotation reports success."""
    try:
        plaintext = cipher.decrypt(stored, aad=aad)
    except UnauthenticatedCipherError:
        if not is_tag_failure(cipher, stored):
            raise
        return None
    return cipher.encrypt(plaintext, aad=aad)


def _names_tag_failure(cipher: Cipher, stored: str, exc: CipherError) -> bool:
    """Whether ``exc``, raised opening the marked value ``stored``, says the cell failed its tag.

    A key service that gave no verdict (:func:`is_transient_open_failure`, BACKLOG #5765) says
    nothing about the cell, so it is never a tag failure. Otherwise :func:`is_tag_failure` decides,
    so under Vault Transit, which cannot name its keys, every other refusal of a marked value is
    refused as a :class:`QueueTagError`. Its cause is ``tag`` only for an AEAD failure, and
    ``unknown`` for any other refusal (:data:`QUEUE_TAG_CAUSES`). That is deliberately louder than
    :func:`~messagefoundry.store.cell_tag.open_tagged_cell`, which keeps a non-AEAD Transit refusal
    as the cipher's own error: narrowing this control would rest on matching Vault's error text, and
    that change is not this fix's to make."""
    return not is_transient_open_failure(exc) and is_tag_failure(cipher, stored)


def open_queue_cell(cipher: Cipher, row: Any) -> str:
    """Open ``row``'s ``payload`` under its own tag: the body for an inline row, the sealed
    ``shared_body`` key for a ``ref`` row.

    Raises :class:`QueueTagError`, which is drift, when the cell does not open under the row's
    tag (see :func:`_names_tag_failure`), when a keyed store's row (or any ``ref`` row) holds a
    blank ``payload``, or when a ``ref`` row's opened key differs from its ``body_ref`` column. Any
    other key or format problem raises the cipher's own error, and so does a key service that gave
    no verdict (:func:`is_transient_open_failure`). That includes at least a cell whose marker the
    cipher cannot read, which then gets no queue-tag audit row and no alert: docs/PHI.md section 1,
    *A database writer is refused only where a seal or a tag covers the row*, states that gap.
    Raises its subclass
    :class:`CorruptQueueCellError`, which is not drift, only when a cipher that names its keys
    refuses a cell under a key it holds for a reason other than a failed AEAD check. A keyless
    store writes plaintext and has no tag to check, so there only the reference comparison binds
    anything. :data:`QUEUE_TAG_CAUSES` names each case's ``cause``."""
    payload = row["payload"]
    body_ref = row["body_ref"]
    if payload == "" and (cipher.encrypts or body_ref is not None):
        # A keyed writer seals every body, an empty one included, and a ref row always holds its
        # reference. Blank is what retention leaves, so it is never a cell to deliver. A keyless
        # writer's live empty body is sealed by the first keyed open (BACKLOG #3495), so a blank that
        # reaches this line on a keyed store is an erasure, a plant, or an empty body from a keyless
        # run of an already keyed store. Nothing tells those apart, so all three are refused.
        raise QueueTagError("integrity: the queue row holds no sealed payload", cause="blank")
    try:
        opened = cipher.decrypt(payload, aad=queue_row_aad(row))
    except CipherError as exc:
        if not _names_tag_failure(cipher, payload, exc):
            raise  # a key, format or key-service problem, which the cipher's own error names
        if not isinstance(exc, UnauthenticatedCipherError) and _names_its_keys(cipher):
            # Under a key this process holds, only a failed AEAD check means the cell was sealed
            # for another row. Any other refusal is the cell itself being unreadable. A cipher that
            # cannot name its keys has every refusal refused below, as cause tag or unknown.
            raise CorruptQueueCellError(
                f"the queue row's payload is corrupt and cannot be read under the key it names ({exc})"
            ) from exc
        # Only a failed AEAD check says the tag failed; any other refusal here is from a cipher that
        # cannot name its keys, which cannot say whether the cell is corrupt or sealed elsewhere.
        raise QueueTagError(
            f"integrity: the queue row's payload does not open under its own tag ({exc})",
            cause="tag" if isinstance(exc, UnauthenticatedCipherError) else "unknown",
        ) from exc
    if body_ref is not None and opened != body_ref:
        raise QueueTagError(
            "integrity: the queue row's sealed reference differs from its body_ref",
            cause="ref" if cipher.encrypts else "ref-unsealed",
        )
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


async def report_queue_tag_failure(
    store: _AuditSink,
    cipher: object,
    row: Any,
    *,
    error: QueueTagError,
    outcome: str = "was dead-lettered",
) -> None:
    """Record that ``row`` was refused with ``error``: a WARNING, a :data:`QUEUE_TAG_FAILED_ACTION`
    audit row and an ``integrity_drift`` alert through the cipher's tag-failure hook (BACKLOG #2593).

    The caller has usually dead-lettered the row, so the lane has moved on and the message is
    ``ERROR``. A caller whose dead-letter write failed reports the tag failure all the same, with
    ``outcome`` saying so (BACKLOG #5735). Names the row by a short id prefix and its stage, never
    a row value. An audit or alert failure is logged and swallowed: reporting must never undo the
    dead-letter. The audit detail's ``cause`` is ``error.cause``, whose values
    :data:`QUEUE_TAG_CAUSES` defines (BACKLOG #5884)."""
    ref = str(row["id"])[:_ROW_REF_LEN]
    stage = row["stage"]  # outside the try, so a missing column is not logged as the audit's
    try:
        await store.record_audit(
            QUEUE_TAG_FAILED_ACTION,
            actor="system",
            channel_id=row["channel_id"],
            detail=json.dumps(
                {"cause": error.cause, "queue_row": ref, "stage": stage}, sort_keys=True
            ),
        )
    except Exception as exc:  # noqa: BLE001 -- the dead-letter stands whatever the audit write does
        # Class and an error code only, as cell_tag's audit failure, and no exc_info: the error's
        # traceback and __context__ reach the claim frame, whose locals can hold other rows' opened
        # bodies, and a driver's text is not this function's to vouch for (BACKLOG #5884).
        from messagefoundry.store.cell_tag import _error_code  # noqa: PLC0415 -- it imports this

        _log.error(
            "the %s audit row for queue row %s could not be written (%s, code %s)",
            QUEUE_TAG_FAILED_ACTION,
            ref,
            type(exc).__name__,
            _error_code(exc),
        )
    alert_queue_tag_failure(cipher, row, error=error, outcome=outcome)


def alert_queue_tag_failure(
    cipher: object, row: Any, *, error: QueueTagError, outcome: str
) -> None:
    """Log a WARNING and raise the ``integrity_drift`` alert for ``row`` through the cipher's
    tag-failure hook, with no audit row (BACKLOG #2593).

    The audit-free form is for a read that runs inside a writer transaction (an operator resend's
    source), which cannot take the writer lock again; that read is refused, and ``outcome`` says
    so. Names the row by its stage and a short id prefix, never a row value. The reason says what
    ``error.cause`` says, in :data:`QUEUE_TAG_CAUSES`'s words (BACKLOG #5884). A corrupt cell
    (:class:`CorruptQueueCellError`) alerts under its own subject
    (:data:`QUEUE_CORRUPT_ALERT_TABLE`), and its WARNING also carries the cipher's reason. Unlike
    the tagged-cell path's WARNING, none of these is rate-limited. Never raises."""
    ref = str(row["id"])[:_ROW_REF_LEN]
    reason = f"a {row['stage']} queue row {QUEUE_TAG_CAUSES[error.cause]} and {outcome} (row {ref})"
    if error.drift:
        _log.warning("%s", reason)
    else:
        # The text, not the error: a record keeps its args, and the error's traceback holds the
        # claim frame's locals, which can include other rows' opened bodies.
        _log.warning("%s: %s", reason, str(error))
    report = getattr(cipher, "report_tag_failure", None)
    if callable(report):
        report("queue" if error.drift else QUEUE_CORRUPT_ALERT_TABLE, reason)
