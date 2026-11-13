# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Embedded-document strip result + per-connection cutoff resolution (#47, ADR 0042).

The in-place embedded-document strip (a sibling to ``purge_message_bodies``, ADR 0042 D2) is a
**select → codec-transform → write-back** path, not pure SQL: the bulky base64 in each stored ``raw``
is replaced by a small self-describing tombstone via the :mod:`messagefoundry.parsing.binary` codec
(the generic ``mfb64:v1:`` carriage marker AND HL7 OBX-5 ED embeds), while the surrounding message
stays byte-stable and parseable (CLAUDE.md §8 — never string-slice raw HL7). Each store backend
implements ``strip_embedded_documents`` (SQLite / Postgres / SQL Server) on this shared contract.

This module is intentionally dependency-light (no backend imports) so it can be shared by all three
store backends and the retention runner without a cycle.

The pass is shaped the same way on every backend, by :func:`run_strip_pass` (BACKLOG #5651). It
scans candidates in keyset batches of at most :data:`STRIP_BATCH_ROWS` rows, ordered by
``(received_at, id)`` so the scan stays on the ``(received_at, id)`` index. The read is bounded by
the loosest finite cutoff only: a row older than that but on a connection with a tighter or a
keep-forever window is still read, body included, and then skipped by :func:`cutoff_for`. It runs the
decrypt, strip and encrypt of a batch through :func:`transform_strip_batch` in a worker thread,
holding no pooled connection, so the crypto never runs on the event loop. A backend supplies only
the batch read and the guarded write.

It writes each row back only by ``id`` AND ``documents_pruned IS NULL`` AND ``raw`` equal, byte for
byte, to the stored cell the batch read, AND with no queue row ``pending``/``inflight``, the same
in-flight guard the read applied. A body purge that emptied ``raw``, a key rotation that re-sealed it,
or another strip that pruned it, committed between the read and the write, therefore fails the guard:
the row is left as the other writer left it, and the strip never writes old content back over it. It
counts a row only when its own guarded update changed it. This compare-and-swap is the strip's only
protection against a concurrent writer; it takes no row locks.

**Its limit.** The queue check is a ``NOT EXISTS`` inside each UPDATE statement, so it sees what was
committed when that statement ran. On PostgreSQL and SQL Server, a replay that re-pends one of the
message's queue rows after that statement and before the batch commits can still have the message
stripped, and the replay then re-processes the stripped body. SQLite's single writer cannot
interleave them.

A row that fails on its own, in its decrypt or its strip, is logged and skipped, and so is a row
whose encrypt the key service gives no verdict on. Any other :class:`CipherError` from ``encrypt`` is
store-wide, the AES-GCM invocation ceiling for one, and propagates out of the call as on origin/main,
so its instruction (rotate the store key) reaches the operator. A batch whose transform or write
raises anything else is rolled back whole, counts nothing, is logged (its type at WARNING, its
traceback at DEBUG), and the keyset moves past it; its rows are tried again on the next pass. A row
the key service gives no verdict on (a :class:`~messagefoundry.store.crypto.CipherError` that
:func:`~messagefoundry.store.crypto.gave_no_verdict` reads as the service failing) is skipped like
any unreadable row.

A strip call ends early, flagged ``ended_early`` with what its batches committed, in two cases: a
batch read fails (``read_failed`` is then set too), or at least :data:`OUTAGE_MIN_ROWS` rows of one
batch reached the key service and none got a verdict. The retention pass then skips the rest of its
strip phase, and logs the early end at WARNING. An outage alone is not counted as work for the pass's
audit row, so it does not also send that row through the failing key service; a failed read is a
database fault, not a key-service one, so it is counted, and the audit row records it.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from messagefoundry.parsing.binary import strip_documents
from messagefoundry.store.cell_tag import CellTagError, message_cell_aad, open_message_cell
from messagefoundry.store.crypto import CipherError, detached, gave_no_verdict

if TYPE_CHECKING:
    from messagefoundry.store.crypto import Cipher

__all__ = [
    "OUTAGE_MIN_ROWS",
    "STRIP_BATCH_ROWS",
    "StripBatch",
    "StripResult",
    "StripUpdate",
    "cutoff_for",
    "log_unreadable_skips",
    "run_strip_pass",
    "transform_strip_batch",
]

log = logging.getLogger(__name__)

#: How many candidate rows one keyset batch of the strip reads, transforms and writes. It bounds the
#: number of bodies a pass holds in memory at once, whatever the store's size; it is a row count, not
#: a byte budget. Not ``Final``: :func:`run_strip_pass` reads it per batch, so a test may shrink it.
STRIP_BATCH_ROWS = 200

#: The fewest rows of one batch that must reach the key service, every one without a verdict, before
#: the call reads it as an outage and ends early. Fewer such rows are skipped one by one, as on
#: origin/main, so one row the service always refuses cannot stop the strip (BACKLOG #5651).
OUTAGE_MIN_ROWS = 3


@dataclass(frozen=True)
class StripResult:
    """What one ``strip_embedded_documents`` pass did (ADR 0042 D3): how many messages had at least one
    embedded document stripped, the total documents stripped across them, and the on-disk base64 bytes
    reclaimed. Returned for the runner's single audit row + the tests — **metadata only**, never any
    message content (no PHI)."""

    messages_stripped: int = 0
    documents_stripped: int = 0
    bytes_reclaimed: int = 0
    #: The call ended before its last batch, on a failed batch read or a key-service outage
    #: (BACKLOG #5651); the counts are what its batches committed.
    ended_early: bool = False
    #: The early end was a failed batch read, a database fault (BACKLOG #5651).
    read_failed: bool = False


def cutoff_for(
    channel_id: str,
    global_cutoff: float,
    connection_cutoffs: Mapping[str, float] | None,
) -> float:
    """The strip cutoff for a message received by ``channel_id``: its per-connection override when the
    connection is in ``connection_cutoffs`` (``float('-inf')`` = keep forever → never stripped),
    otherwise the ``global_cutoff`` (the ELSE branch). The Python analog of the SQL ``CASE`` the purge
    path uses — applied here because the strip selects-then-transforms in Python, so the cutoff is
    re-checked on the materialized row rather than baked into a pure-SQL UPDATE. Empty/None ⇒ always the
    global cutoff (byte-identical to a single global window)."""
    if connection_cutoffs:
        override = connection_cutoffs.get(channel_id)
        if override is not None:
            return override
    return global_cutoff


def log_unreadable_skips(message_ids: Sequence[object]) -> None:
    """Log, once per ``strip_embedded_documents`` call and at WARNING, the rows it skipped because
    their HL7 delimiters could not be read (``strip_documents``' ``on_unreadable``, BACKLOG
    #5099): a document such a row holds stays past its strip window, so the skip must not be
    silent (CLAUDE.md section 6). One record per call rather than one per row, since the same rows
    are selected again on every pass until their bodies are purged; the retention runner makes one
    call per distinct ``min_bytes`` threshold, so a pass may log more than one. It names the count
    and the first message id, never a byte of a body. Nothing is logged when none was skipped."""
    if not message_ids:
        return
    log.warning(
        "document strip skipped %d stored HL7 bodies whose delimiters could not be read (first: "
        "message %s); any document they hold stays past the strip window",
        len(message_ids),
        message_ids[0],
    )


@dataclass(frozen=True)
class StripUpdate:
    """One row's guarded write-back, as :func:`transform_strip_batch` builds it: the message id, the
    ``raw`` cell exactly as the batch read it (the guard's comparand), the stripped body sealed under
    the row's tag, and what stripping it reclaimed. On a keyless store both cells are plaintext
    bodies, so neither is in its ``repr`` (PHI.md section 2)."""

    message_id: str
    stored: str = field(repr=False)
    new_cell: str = field(repr=False)
    documents: int
    reclaimed: int


#: Where the previous batch ended: the last row's ``(received_at, id)``, or ``None`` before the first.
type StripCursor = tuple[float, str] | None
#: Reads one keyset batch: ``(scan_cutoff, after, limit)`` to at most ``limit`` candidate rows with
#: ``received_at < scan_cutoff`` and ``(received_at, id)`` past ``after``, in ``(received_at, id)``
#: order, each with ``id``, ``channel_id``, ``raw`` and ``received_at``. It applies the in-flight
#: guard, and gives its connection back before it returns.
type FetchStripBatch = Callable[[float, StripCursor, int], Awaitable[Sequence[Any]]]
#: Writes one batch's guarded updates in one transaction, returning those whose own guarded update
#: changed their row.
type WriteStripBatch = Callable[[Sequence[StripUpdate]], Awaitable[Sequence[StripUpdate]]]


async def run_strip_pass(
    cipher: Cipher,
    *,
    fetch: FetchStripBatch,
    write: WriteStripBatch,
    report: Callable[[list[CellTagError]], Awaitable[None]],
    now: float,
    older_than: float,
    connection_cutoffs: Mapping[str, float] | None,
    min_bytes: int,
    content_types: Mapping[str, str],
) -> StripResult:
    """One ``strip_embedded_documents`` call, the same on every backend (BACKLOG #5651): keyset
    batches of :data:`STRIP_BATCH_ROWS` from ``fetch``, each transformed in a worker thread by
    :func:`transform_strip_batch` with no connection held, and written back by ``write`` in one
    transaction. Only the rows ``write`` reports changed are counted. The module docstring states
    how a failed row, a failed batch and an outage are handled.

    A store-wide :class:`CipherError` from a batch's transform, a cancellation, or a failure of
    ``report`` itself, is re-raised after a WARNING with the committed counts, which no audit row
    then records. The refused cells and unreadable rows every batch's transform found are collected
    as each transform returns, even when that batch's write then fails, and audited by one
    ``report`` call and logged by one :func:`log_unreadable_skips` call, after the loop (or, for the
    report, in the handler that re-raises).

    The scan is bounded by the loosest finite cutoff (the global one or the largest override; a
    keep-forever ``-inf`` never widens it), and the precise per-connection cutoff is re-checked per
    row by :func:`cutoff_for`. With no finite cutoff, nothing is scanned."""
    finite = [c for c in [older_than, *(connection_cutoffs or {}).values()] if c != float("-inf")]
    if not finite:
        return StripResult()
    scan_cutoff = max(finite)
    messages = documents = reclaimed = 0
    failures: list[CellTagError] = []
    unreadable: list[object] = []
    after: StripCursor = None
    reported = False
    ended_early = read_failed = False
    try:
        while True:
            limit = STRIP_BATCH_ROWS
            try:
                rows = await fetch(scan_cutoff, after, limit)
            except Exception as exc:
                # The cursor cannot move past a batch it could not read: end the call.
                ended_early = read_failed = True
                _log_early_end("a batch read failed", exc, documents, messages)
                break
            if not rows:
                break
            after = (rows[-1]["received_at"], rows[-1]["id"])
            try:
                batch = await asyncio.to_thread(
                    transform_strip_batch,
                    cipher,
                    rows,
                    now=now,
                    older_than=older_than,
                    connection_cutoffs=connection_cutoffs,
                    min_bytes=min_bytes,
                    content_types=content_types,
                )
                failures.extend(batch.refused)
                unreadable.extend(batch.unreadable)
                if batch.outage:
                    # Every row that reached the key service got no verdict: an outage, which
                    # every later batch would meet too. End the call.
                    ended_early = True
                    _log_early_end("the key service gave no verdict", None, documents, messages)
                    break
                for done in await write(batch.updates) if batch.updates else ():
                    messages += 1
                    documents += done.documents
                    reclaimed += done.reclaimed
            except CipherError:
                # Only a store-wide cipher error leaves the transform (it contains each row's own),
                # such as the AES-GCM invocation ceiling: raise it, as on origin/main.
                raise
            except Exception as exc:
                # The batch rolled back whole and counts nothing. The cursor has already moved past
                # it, so it cannot stall the strip; its rows are tried again on the next pass. The
                # type at WARNING (a server error's text can quote stored values), the traceback
                # at DEBUG, for diagnosis.
                log.warning(
                    "document strip passed over a batch that failed (%s); it goes on past it",
                    type(exc).__name__,
                )
                log.debug("document strip batch failure", exc_info=True)
            if len(rows) < limit:
                break
        reported = True
        await report(failures)  # inside the try, so its own failure still logs the WARNING
    except BaseException:
        # A cancellation (engine stop), or the report failing: the pass then raises, and no
        # retention audit row records what committed.
        log.warning(
            "document strip failed part way; it had already stripped and committed %d documents "
            "in %d messages, which no retention audit row records",
            documents,
            messages,
        )
        if not reported:
            try:
                await report(failures)
            except Exception as exc:  # the original error is the one to raise
                log.warning(
                    "document strip could not audit %d refused cells: %s",
                    len(failures),
                    type(exc).__name__,
                )
        raise
    finally:
        log_unreadable_skips(unreadable)
    return StripResult(
        messages_stripped=messages,
        documents_stripped=documents,
        bytes_reclaimed=reclaimed,
        ended_early=ended_early,
        read_failed=read_failed,
    )


def _log_early_end(why: str, exc: BaseException | None, documents: int, messages: int) -> None:
    log.warning(
        "document strip ended early: %s (%s); it had stripped and committed %d documents in %d "
        "messages before it",
        why,
        type(exc).__name__ if exc is not None else "no error raised",
        documents,
        messages,
    )


@dataclass(frozen=True)
class StripBatch:
    """What :func:`transform_strip_batch` made of one batch: the guarded write-backs it needs, the
    refused cells, the ids of rows whose HL7 delimiters could not be read, and whether at least
    :data:`OUTAGE_MIN_ROWS` rows reached the key service and none got a verdict (``outage``)."""

    updates: list[StripUpdate]
    refused: list[CellTagError]
    unreadable: list[object]
    outage: bool


def transform_strip_batch(
    cipher: Cipher,
    rows: Sequence[Any],
    *,
    now: float,
    older_than: float,
    connection_cutoffs: Mapping[str, float] | None,
    min_bytes: int,
    content_types: Mapping[str, str],
) -> StripBatch:
    """Decrypt, strip and re-seal one batch of candidate rows (each with ``id``, ``channel_id``,
    ``raw`` and ``received_at``). Synchronous and free of any store connection, so a backend runs it
    through ``asyncio.to_thread`` with no pooled connection held (BACKLOG #5651).

    The per-connection cutoff is re-checked here (:func:`cutoff_for`), so a row past the loose scan
    bound but not past its own tighter or keep-forever cutoff is left intact. A row whose body is
    refused or cannot be decrypted is contained, and left exactly as found (BACKLOG #1169, #2593):
    a :class:`CellTagError` is returned, detached, for the caller to audit on the loop; any other
    :class:`CipherError`, a no-verdict one included, is logged with the message id and the error's
    text. A row whose strip raises, or whose encrypt the key service gives no verdict on, is
    logged with the message id and the error's type only, and skipped. Any other
    :class:`CipherError` from ``encrypt`` is store-wide and is raised. A row whose HL7 delimiters cannot be read is returned for
    :func:`log_unreadable_skips`. A body holding no embedded document needs no write."""
    updates: list[StripUpdate] = []
    failures: list[CellTagError] = []
    unreadable: list[object] = []
    asked = no_verdict = 0  # rows that reached the key service, and those it gave no verdict on
    for row in rows:
        message_id = row["id"]
        channel_id = row["channel_id"]
        if row["received_at"] >= cutoff_for(channel_id, older_than, connection_cutoffs):
            continue  # not past its own (per-connection) window
        stored = row["raw"]
        asked += 1
        try:
            raw = open_message_cell(
                cipher, "raw", stored, message_id=message_id, channel_id=channel_id
            )
        except CellTagError as exc:
            # The read already logged and alerted it, once per hour; the caller audits it. It is
            # returned, not raised, so its traceback is cleared: its frames would keep this batch's
            # bodies alive until the end of the pass (BACKLOG #6706).
            detached(exc)
            failures.append(exc)
            continue
        except CipherError as exc:
            if gave_no_verdict(exc):
                no_verdict += 1
            log.warning(
                "document strip skipped message %s: its body could not be read: %s",
                message_id,
                exc,
            )
            continue
        assert raw is not None  # raw is NOT NULL
        try:
            new_raw, n_docs, n_bytes = strip_documents(
                raw,
                pruned_at=now,
                min_bytes=min_bytes,
                content_type=content_types.get(channel_id),
                on_unreadable=functools.partial(unreadable.append, message_id),
            )
        except Exception as exc:
            # One row's own failure skips that row. The type only: an error raised over a body
            # may quote it.
            log.warning(
                "document strip skipped message %s: it could not be stripped (%s)",
                message_id,
                type(exc).__name__,
            )
            continue
        if n_docs == 0:
            continue  # no embedded document in this body: leave it, and its NULL flag, untouched
        try:
            new_cell = cipher.encrypt(
                new_raw, aad=message_cell_aad("raw", message_id=message_id, channel_id=channel_id)
            )
        except CipherError as exc:
            if not gave_no_verdict(exc):
                raise  # store-wide, such as the AES-GCM invocation ceiling: as on origin/main
            no_verdict += 1
            log.warning(
                "document strip skipped message %s: the key service gave no verdict on its seal (%s)",
                message_id,
                type(exc).__name__,
            )
            continue
        updates.append(StripUpdate(message_id, stored, new_cell, n_docs, n_bytes))
    outage = asked >= OUTAGE_MIN_ROWS and no_verdict == asked
    return StripBatch(updates, failures, unreadable, outage=outage)
