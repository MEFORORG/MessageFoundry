# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The per-inbound refused-body allowance (vault BACKLOG #2608).

A body the listener refuses before ingress -- a decode, NUL, size, declared-type, parse,
strict-validation or streaming-detach refusal -- is still recorded as an ``ERROR`` row, because
count-and-log forbids accepting and dropping anything (CLAUDE.md section 2). Before this module every
such row stored the WHOLE body, up to the 16 MiB frame limit, and no intake bound counted it: the
staged-depth pause counts not-done ingress and routed rows only, and a refused body never becomes
one. So a flood of refusals would have grown the store unmetered on a first deployment.

What this bounds is the BYTES each refusal stores, never the count of refusals:

* Every refused body's length and SHA-256 are always recorded, in the message's engine-internal
  metadata under :data:`METADATA_KEY`, so an operator can still match it against the sender's copy.
* The whole body is stored only while its inbound's rolling byte allowance covers it. Past that,
  the first ``head_bytes`` of it are stored, and the stored ``error`` says so.
* A body no larger than a head is always stored whole and charges nothing: storing it costs no more
  than storing its head would.

The sender's ACK or NAK is untouched: this runs after the refusal is decided, on what is STORED. The
sender was answered AR or AE, so it still holds its own copy. Nothing here pauses intake, so it is not
the depth budget that owner rulings R1 and R2 keep off.

The allowance is a token bucket per inbound name, held by the engine process. An inbound lives on
exactly one engine shard, so a per-inbound count needs no cross-shard state. The Engine owns one
:class:`RefusedBodyAllowance` and hands it to every runner a reload builds, so a reload does not
refill a spent allowance.
"""

from __future__ import annotations

import asyncio
import hashlib
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
from messagefoundry.parsing.binary import MARKER as CARRIAGE_MARKER
from messagefoundry.parsing.binary import is_marked
from messagefoundry.pipeline.ingress_guards import store_safe_raw
from messagefoundry.redaction import safe_text

__all__ = [
    "DEFAULT_ALLOWANCE_BYTES",
    "DEFAULT_HEAD_BYTES",
    "DEFAULT_WINDOW_SECONDS",
    "METADATA_KEY",
    "BoundedRefusal",
    "RefusedBodyAllowance",
    "RefusedBodyPolicy",
]

#: The engine-internal metadata key. ``store.metadata.user_metadata`` exposes only the ``user`` bag,
#: so this never reaches the API's user-metadata field.
METADATA_KEY = "refused_body"

#: Hash a body larger than this in a worker thread. ``hashlib`` releases the GIL on large inputs, so a
#: flood of 16 MiB refusals does not stall the event loop for the hash.
_THREAD_HASH_BYTES = 1024 * 1024

#: The store's own bound on the ``error`` column (``redaction.safe_text``'s default limit).
_ERROR_LIMIT = 200


@dataclass(frozen=True, slots=True)
class RefusedBodyPolicy:
    """The three ``[inbound]`` settings. ``allowance_bytes = 0`` stores only the head of every
    refused body larger than a head; there is no off value, by design. The settings carry the
    operator floors; these checks only refuse values the arithmetic below cannot use."""

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
    JSON carrying its length and SHA-256."""

    raw: str
    error: str
    metadata: str


class RefusedBodyAllowance:
    """A rolling byte allowance per inbound name (a token bucket that refills evenly over the window).

    Mutated only on the event loop, and :meth:`admit` never awaits, so it needs no lock."""

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

    def admit(self, inbound: str, size: int) -> bool:
        """Whether a refused body of ``size`` bytes on ``inbound`` may be stored whole, charging the
        allowance when it may. A body no larger than a head is free and always admitted."""
        policy = self.policy
        if size <= policy.head_bytes:
            return True
        now = self._clock()
        capacity = float(policy.allowance_bytes)
        left, last = self._buckets.get(inbound, (capacity, now))
        left = min(capacity, left + (now - last) * capacity / policy.window_seconds)
        admitted = size <= left
        if admitted:
            left -= size
        self._buckets[inbound] = (left, now)
        return admitted

    async def bound(
        self, inbound: str, wire: bytes, text: str | None, content_type: str, error: str
    ) -> BoundedRefusal:
        """Decide what to store for one refused body.

        ``wire`` is the body as received, which is what the length and SHA-256 describe, so they
        match the sender's copy. ``text`` is its decoded form when the refusal came after the
        decode, else ``None``. The whole stored form is :func:`store_safe_raw` of the two, as it was
        before this bound. It is built only when the allowance admits it, because under a flood the
        head is the common case and building a 16 MiB view to discard it is the waste this avoids."""
        if len(wire) > _THREAD_HASH_BYTES:
            digest = await asyncio.to_thread(_sha256, wire)
        else:
            digest = _sha256(wire)
        whole = self.admit(inbound, _stored_length(wire, text))
        if whole:
            stored = store_safe_raw(wire, content_type, text=text)
        else:
            stored = _head(wire, text, content_type, self.policy.head_bytes)
            note = (
                f" [refused-body allowance spent: stored the first {len(stored)} characters"
                f" of a {len(wire)}-byte body]"
            )
            error = safe_text(error, limit=_ERROR_LIMIT - len(note)) + note
        metadata = json.dumps(
            {
                METADATA_KEY: {
                    "bytes": len(wire),
                    "sha256": digest,
                    "stored": "whole" if whole else "head",
                }
            }
        )
        return BoundedRefusal(raw=stored, error=error, metadata=metadata)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stored_length(wire: bytes, text: str | None) -> int:
    """The charge for storing a body whole: the larger of its received length and the length of
    the form :func:`store_safe_raw` would give it, worked out without building that form."""
    if text is not None and "\x00" not in text:
        return max(len(wire), len(text))
    if text is None and b"\x00" not in wire:
        return len(wire)  # the latin-1 view, one character per byte
    return len(CARRIAGE_MARKER) + 4 * ((len(wire) + 2) // 3)  # mfb64:v1: byte carriage


def _head(wire: bytes, text: str | None, content_type: str, head_bytes: int) -> str:
    """The first ``head_bytes`` of a refused body, in the form the store would have held.

    A NUL-free decoded text is cut at a character boundary. Otherwise the head of the received bytes
    goes through :func:`store_safe_raw` on its own, so a head with no NUL in it stays readable even
    when the whole body needed byte carriage. A text form is cut so its UTF-8 is at most
    ``head_bytes``; byte carriage is never cut, because a cut base64 string no longer decodes."""
    if text is not None and "\x00" not in text:
        view = text[:head_bytes]
    else:
        view = store_safe_raw(wire[:head_bytes], content_type)
        if is_marked(view):
            return view
    encoded = view.encode("utf-8", "surrogatepass")
    if len(encoded) <= head_bytes:
        return view
    return encoded[:head_bytes].decode("utf-8", "ignore")
