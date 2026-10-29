# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The per-inbound refused-body allowance (vault BACKLOG #2608).

A body the listener refuses before ingress -- at least a decode, NUL, size, declared-type, parse,
strict-validation or streaming-detach refusal -- is still recorded as an ``ERROR`` row, because
count-and-log forbids accepting and dropping anything (CLAUDE.md section 2). Before this module every
such row stored the WHOLE body, up to the 16 MiB frame limit, and no intake bound counted it: the
staged-depth pause counts not-done ingress and routed rows only, and a refused body never becomes
one. So a flood of refusals would have grown the store unmetered on a first deployment.

What this bounds is the BYTES each refusal stores, never the count of refusals:

* Every refused body's length is always recorded, in the message's engine-internal metadata under
  :data:`METADATA_KEY`, and so is a KEYED digest of it, ``body_hmac``
  (:func:`~messagefoundry.store.crypto.refused_body_digest`), whenever the store holds an in-heap
  key. A plain hash would let anyone who can read the row confirm a guessed body, or the guessed
  tail of a head, offline. The keyed digest lets a holder of the store key confirm whether a
  candidate copy, such as the sender's own, is the body the row refused, which a head alone cannot
  show (:func:`~messagefoundry.store.crypto.verify_refused_body_digest`). Nothing in the API or the
  console shows or checks it today. On a store with no in-heap key (keyless, or Vault Transit),
  ``body_hmac`` is recorded as ``null``: no digest, never a plain hash.
* The whole body is stored only while its inbound's rolling byte allowance covers it. Past that,
  the first ``head_bytes`` of it are stored, and the stored ``error`` says so. The API refuses to
  edit and resubmit a row stored that way (:func:`head_only_resubmit_refusal`), since its body is cut.
* A body whose head would be the whole of it is always stored whole and charges nothing: storing
  it costs no more than storing its head would.

The charge is the UTF-8 length of the form the store would write, so a body whose stored view takes
two or three bytes a character is charged for them.

The sender's ACK or NAK is untouched: this runs after the refusal is decided, on what is STORED. A
listener's peer sent the body over the wire and, for HL7 with an ACK mode, was answered AR or AE, so it
holds its own copy. A poll source is different: the engine consumes the only copy (a file it deletes,
a row it marks), so the runner keeps every refusal from one whole. Nothing here pauses intake, so it
is not the depth budget that owner rulings R1 and R2 keep off.

The allowance is a token bucket per inbound name, held by the engine process. An inbound lives on
exactly one engine shard, so a per-inbound count needs no cross-shard state. The Engine owns one
:class:`RefusedBodyAllowance` and hands it to every runner a reload builds, so a reload does not
refill a spent allowance.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass

from messagefoundry.config.settings import (
    REFUSED_BODY_ALLOWANCE_BYTES as DEFAULT_ALLOWANCE_BYTES,
)
from messagefoundry.config.settings import REFUSED_BODY_HEAD_BYTES as DEFAULT_HEAD_BYTES
from messagefoundry.config.settings import (
    REFUSED_BODY_WINDOW_SECONDS as DEFAULT_WINDOW_SECONDS,
)
from messagefoundry.parsing import RawMessage
from messagefoundry.parsing.binary import MARKER as CARRIAGE_MARKER
from messagefoundry.parsing.binary import is_marked
from messagefoundry.pipeline.ingress_guards import store_safe_raw
from messagefoundry.redaction import _DEFAULT_LIMIT as _ERROR_LIMIT
from messagefoundry.redaction import safe_text
from messagefoundry.store.crypto import Cipher, refused_body_digest

__all__ = [
    "DEFAULT_ALLOWANCE_BYTES",
    "DEFAULT_HEAD_BYTES",
    "DEFAULT_WINDOW_SECONDS",
    "METADATA_KEY",
    "BoundedRefusal",
    "RefusedBodyAllowance",
    "RefusedBodyPolicy",
    "head_only_resubmit_refusal",
]

#: The engine-internal metadata key. ``store.metadata.user_metadata`` exposes only the ``user`` bag,
#: so this never reaches the API's user-metadata field.
METADATA_KEY = "refused_body"

#: The bytes a latin-1 view writes as two UTF-8 bytes.
_HIGH_BYTES = bytes(range(0x80, 0x100))


@dataclass(frozen=True, slots=True)
class RefusedBodyPolicy:
    """The three ``[inbound]`` settings. ``allowance_bytes = 0`` stores only the head of every
    refused body larger than a head. The settings carry the operator's bounds; these checks only
    refuse values the arithmetic below cannot use."""

    allowance_bytes: int = DEFAULT_ALLOWANCE_BYTES
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    head_bytes: int = DEFAULT_HEAD_BYTES

    def __post_init__(self) -> None:
        if self.allowance_bytes < 0:
            raise ValueError("refused-body allowance_bytes must be >= 0")
        if not self.window_seconds > 0:
            raise ValueError("refused-body window_seconds must be > 0")
        if self.head_bytes < 1:
            raise ValueError("refused-body head_bytes must be >= 1")


@dataclass(frozen=True, slots=True)
class BoundedRefusal:
    """What to store for one refused body: the ``raw`` view, the ``error`` text, and the ``metadata``
    JSON carrying its length and its keyed digest."""

    raw: str
    error: str
    metadata: str


class RefusedBodyAllowance:
    """A rolling byte allowance per inbound name (a token bucket that refills evenly over the window).

    Mutated only on the event loop, and nothing here awaits, so it needs no lock."""

    def __init__(
        self,
        policy: RefusedBodyPolicy | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy or RefusedBodyPolicy()
        self._clock = clock
        # inbound name -> (bytes left, when last charged). Bounded by the number of inbounds.
        self._buckets: dict[str, tuple[float, float]] = {}

    def try_charge(self, inbound: str, size: int) -> bool:
        """Charge ``size`` bytes to ``inbound``'s allowance if it covers them, and say whether it
        did. It is a charge, not a question: a ``True`` spends the bytes."""
        policy = self.policy
        now = self._clock()
        capacity = float(policy.allowance_bytes)
        left, last = self._buckets.get(inbound, (capacity, now))
        left = min(capacity, left + (now - last) * capacity / policy.window_seconds)
        charged = size <= left
        if charged:
            left -= size
        self._buckets[inbound] = (left, now)
        return charged

    def bound(
        self,
        inbound: str,
        wire: bytes,
        text: str | None,
        content_type: str,
        error: str,
        *,
        cipher: Cipher,
        keep_whole: bool = False,
    ) -> BoundedRefusal:
        """Decide what to store for one refused body.

        ``wire`` is the body as received, which is what the length and the keyed digest describe,
        so they match the sender's copy. ``text`` is its decoded form when the refusal came after
        the decode, else ``None``. The whole stored form is :func:`store_safe_raw` of the two, as it
        was before this bound. It is built only when it will be stored, because under a flood the
        head is the common case and building a 16 MiB view to discard it is waste.

        ``cipher`` is the store's live cipher, whose audit key the digest is keyed from. With no
        in-heap key the record holds ``"body_hmac": null``. It is required, so a caller cannot leave
        the digest out by forgetting to pass it.

        ``keep_whole`` stores the body whole and charges nothing. The runner passes it for an
        inbound whose source consumes the only copy (a poll source), where a head would lose the
        rest for good.

        The HMAC runs on the event loop, as the decode before it does: about the same cost, and
        no thread or await between the refusal and its row, so a cancelled listener cannot leave a
        refusal unrecorded in that gap and a full thread pool cannot hold up its NAK."""
        digest = refused_body_digest(cipher, wire)
        head_bytes = self.policy.head_bytes
        carried, stored_bytes = _stored_form(wire, text)
        fits_in_head = (len(wire) if carried else stored_bytes) <= head_bytes
        whole = keep_whole or fits_in_head or self.try_charge(inbound, stored_bytes)
        if whole:
            stored = store_safe_raw(wire, content_type, text=text)
        else:
            stored = _head(wire, text, content_type, head_bytes)
            note = f"[refused-body allowance spent: stored only the head of a {len(wire):,}-byte body] "
            error = _with_note(note, error)
        record: dict[str, object] = {
            "bytes": len(wire),
            "body_hmac": digest,
            "stored": "whole" if whole else "head",
        }
        if not whole:
            # The bound this head was cut to, kept because the policy may change before anyone reads
            # it: the edit-and-resubmit refusal names it (:func:`head_only_resubmit_refusal`).
            record["head_bytes"] = head_bytes
        metadata = json.dumps({METADATA_KEY: record})
        return BoundedRefusal(raw=stored, error=error, metadata=metadata)


def head_only_resubmit_refusal(message_id: str, metadata: str | None) -> str | None:
    """Why an edit-and-resubmit of ``message_id`` must be refused, or ``None`` when it may proceed.

    ``metadata`` is the message's decrypted metadata JSON, as the store's own read returns it. The
    answer is a refusal only when that metadata records a refused body of which only the head was
    stored. Such a row's ``raw`` is cut at a byte or character offset, and a cut HL7 body can still
    parse, so resubmitting it could route a message with its tail missing as if it were whole.

    A whole-stored refusal, any other row, and metadata that is absent (a retention purge nulls it
    with the body) or unreadable all answer ``None``, as before this check existed. The text names
    lengths and ids only, never a byte of the body."""
    if not metadata:
        return None
    try:
        parsed = json.loads(metadata)
    except (TypeError, ValueError):
        return None
    record = parsed.get(METADATA_KEY) if isinstance(parsed, dict) else None
    if not isinstance(record, dict) or record.get("stored") != "head":
        return None
    total = _count(record.get("bytes"))
    head = _count(record.get("head_bytes"))
    body = f"this {total:,}-byte refused body" if total is not None else "this refused body"
    # The bound, not a count of the sender's bytes: a decoded head is cut to this much UTF-8.
    kept = f", cut to a {head:,}-byte head bound" if head is not None else ""
    return (
        f"message {message_id} stored only the head of {body}{kept}, so it cannot be edited and"
        " resubmitted from this copy; have the sender send its own copy again"
    )


def _count(value: object) -> int | None:
    """``value`` when it is a non-negative int (never a bool), else ``None``."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _stored_form(wire: bytes, text: str | None) -> tuple[bool, int]:
    """Whether :func:`store_safe_raw` would store the body as byte carriage, and the UTF-8 length of
    the form it would store, worked out without building that form. A test holds the two to the same
    answer, so a change to that function's rule turns it red."""
    if text is not None and "\x00" not in text:
        return False, len(text) if text.isascii() else len(text.encode("utf-8", "surrogatepass"))
    if text is None and b"\x00" not in wire:
        # The latin-1 view: one character per byte, two UTF-8 bytes for each byte from 0x80 up.
        return False, 2 * len(wire) - len(wire.translate(None, _HIGH_BYTES))
    return True, len(CARRIAGE_MARKER) + 4 * ((len(wire) + 2) // 3)  # mfb64:v1: byte carriage


def _with_note(note: str, error: str) -> str:
    """``note`` then ``error``, with ``error`` cut so the two fit the store's bound on the column.

    The note goes first because the store runs :func:`safe_text` again, and its HL7-segment rule
    redacts from a segment id such as ``MSH|`` to the end of the text. A reason quoting one would
    take a note after it with it. Inside the bound nothing is cut, so the note survives that pass."""
    budget = _ERROR_LIMIT - len(note)
    while True:
        reason = safe_text(error, limit=budget)
        over = len(note) + len(reason) - _ERROR_LIMIT
        if over <= 0 or budget <= over:
            return note + reason
        budget -= over


def _head(wire: bytes, text: str | None, content_type: str, head_bytes: int) -> str:
    """The first ``head_bytes`` of a refused body, in the form the store would have held.

    A NUL-free decoded text is cut at a character boundary, so its UTF-8 is at most ``head_bytes``.
    Otherwise the head of the received bytes goes through :func:`store_safe_raw` on its own, so a
    head with no NUL in it stays readable even when the whole body needed byte carriage. Anything
    that reads as byte carriage is re-made from the head bytes, never cut: a cut base64 string no
    longer decodes, and a sender may open a text body with the carriage marker itself."""
    if text is not None and "\x00" not in text and not is_marked(text):
        view = text[:head_bytes]
    else:
        view = store_safe_raw(wire[:head_bytes], content_type)
        if is_marked(view):
            return RawMessage.from_bytes(wire[:head_bytes], content_type).raw
    encoded = view.encode("utf-8", "surrogatepass")
    if len(encoded) <= head_bytes:
        return view
    return encoded[:head_bytes].decode("utf-8", "ignore")
