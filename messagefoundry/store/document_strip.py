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
counts a row only when its own guarded update changed it.

The in-flight half needs locks to hold on the server backends, whose statements read committed data
or a row version only. Before its updates, in the same transaction, each server write locks the
batch's message rows and then their existing queue rows: PostgreSQL with ``FOR UPDATE`` then
``FOR SHARE``, SQL Server with ``UPDLOCK`` on the clustered rows of both tables, and its guard's
subquery reads under ``READCOMMITTEDLOCK``. A replay that re-pends one of those queue rows therefore
either committed first, and the guard sees it, or waits until the batch commits. A message re-pended
after the batch commits is replayed with its stripped body, as any later replay of a stripped message
is. SQLite's single writer serializes the two already. The server locks are not measured on a live
server, and the SQL Server lock depends on its plan reaching the clustered queue rows.

The locks cover queue rows that exist when the batch writes. They are taken in the order a body
purge takes the same rows, message row first, so the two do not deadlock. A replay takes them in the
other order, queue rows first, so a replay can deadlock with a batch, and the server then aborts one
of the two transactions; no single order avoids both. When the batch is the one aborted, the pass
fails, which the WARNING in :func:`run_strip_pass` records.

A key-service outage, a :class:`~messagefoundry.store.crypto.CipherError` that
:func:`~messagefoundry.store.crypto.gave_no_verdict` reads as the service failing, ends the strip
call early with what earlier batches committed, flagged ``ended_early``, so the retention pass skips
the rest of its strip phase and still writes its audit row.
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
    "STRIP_BATCH_ROWS",
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


@dataclass(frozen=True)
class StripResult:
    """What one ``strip_embedded_documents`` pass did (ADR 0042 D3): how many messages had at least one
    embedded document stripped, the total documents stripped across them, and the on-disk base64 bytes
    reclaimed. Returned for the runner's single audit row + the tests — **metadata only**, never any
    message content (no PHI)."""

    messages_stripped: int = 0
    documents_stripped: int = 0
    bytes_reclaimed: int = 0
    #: A key-service outage ended the call before its last batch (BACKLOG #5651); the counts are
    #: what earlier batches committed.
    ended_early: bool = False


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
    :func:`transform_strip_batch` with no connection held, and written back by ``write``. Only the
    rows ``write`` reports changed are counted.

    Each batch commits on its own. A key-service outage met in a batch's transform ends the call
    there: it logs a WARNING with what earlier batches committed and returns that, flagged
    ``ended_early``, so the runner can audit it. Any other error from a later batch leaves the
    earlier batches' strips committed too: the call then logs a WARNING with what it had already
    stripped, since the runner writes no audit row for a pass that raised, and re-raises. Either
    way it audits the refused cells, and logs the unreadable rows, of the batches before the one
    that failed; that batch's own are lost with its transform.

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
    ended_early = False
    try:
        while True:
            limit = STRIP_BATCH_ROWS
            rows = await fetch(scan_cutoff, after, limit)
            if not rows:
                break
            after = (rows[-1]["received_at"], rows[-1]["id"])
            try:
                updates, refused, skipped = await asyncio.to_thread(
                    transform_strip_batch,
                    cipher,
                    rows,
                    now=now,
                    older_than=older_than,
                    connection_cutoffs=connection_cutoffs,
                    min_bytes=min_bytes,
                    content_types=content_types,
                )
            except CipherError as exc:
                if not gave_no_verdict(exc):
                    raise
                # Every later row would fail the same way: end the call, keeping what committed.
                ended_early = True
                log.warning(
                    "document strip stopped early: the key service gave no verdict (%s); it had "
                    "stripped and committed %d documents in %d messages before it",
                    type(exc).__name__,
                    documents,
                    messages,
                )
                break
            failures.extend(refused)
            unreadable.extend(skipped)
            for done in await write(updates) if updates else ():
                messages += 1
                documents += done.documents
                reclaimed += done.reclaimed
            if len(rows) < limit:
                break
        reported = True
        await report(failures)  # inside the try, so its own failure still logs the WARNING
    except BaseException:
        # BaseException, so a cancelled pass (engine stop) is recorded too.
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
    )


def transform_strip_batch(
    cipher: Cipher,
    rows: Sequence[Any],
    *,
    now: float,
    older_than: float,
    connection_cutoffs: Mapping[str, float] | None,
    min_bytes: int,
    content_types: Mapping[str, str],
) -> tuple[list[StripUpdate], list[CellTagError], list[object]]:
    """Decrypt, strip and re-seal one batch of candidate rows (each with ``id``, ``channel_id``,
    ``raw`` and ``received_at``), returning the guarded write-backs it needs, the refused cells and
    the ids of the rows whose HL7 delimiters could not be read. Synchronous and free of
    any store connection, so a backend runs it through ``asyncio.to_thread`` with no pooled
    connection held (BACKLOG #5651).

    The per-connection cutoff is re-checked here (:func:`cutoff_for`), so a row past the loose scan
    bound but not past its own tighter or keep-forever cutoff is left intact. A row whose body is
    refused or cannot be decrypted is contained: a :class:`CellTagError` is returned, detached, for
    the caller to audit on the loop, any other :class:`CipherError` is logged naming only the
    message id, and the row is left exactly as found (BACKLOG #1169, #2593). A :class:`CipherError`
    that :func:`~messagefoundry.store.crypto.gave_no_verdict` reads as the key service failing is
    raised instead, and :func:`run_strip_pass` ends the call early. A row whose HL7 delimiters cannot be
    read is returned for :func:`log_unreadable_skips`. A body holding no embedded document needs no
    write."""
    updates: list[StripUpdate] = []
    failures: list[CellTagError] = []
    unreadable: list[object] = []
    for row in rows:
        message_id = row["id"]
        channel_id = row["channel_id"]
        if row["received_at"] >= cutoff_for(channel_id, older_than, connection_cutoffs):
            continue  # not past its own (per-connection) window
        stored = row["raw"]
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
                # The key service failed, not this value: every later row would fail the same
                # way, so the pass stops here rather than time out once per row.
                raise
            log.warning(
                "document strip skipped message %s: its body could not be read: %s",
                message_id,
                exc,
            )
            continue
        assert raw is not None  # raw is NOT NULL
        new_raw, n_docs, n_bytes = strip_documents(
            raw,
            pruned_at=now,
            min_bytes=min_bytes,
            content_type=content_types.get(channel_id),
            on_unreadable=functools.partial(unreadable.append, message_id),
        )
        if n_docs == 0:
            continue  # no embedded document in this body: leave it, and its NULL flag, untouched
        new_cell = cipher.encrypt(
            new_raw, aad=message_cell_aad("raw", message_id=message_id, channel_id=channel_id)
        )
        updates.append(StripUpdate(message_id, stored, new_cell, n_docs, n_bytes))
    return updates, failures, unreadable
