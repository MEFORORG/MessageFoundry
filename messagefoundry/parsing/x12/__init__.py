# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure ASC X12 EDI codec (ADR 0012) — a tolerant routing peek, an interchange splitter/assembler, and
a mutable message model, mirroring the HL7 :mod:`messagefoundry.parsing` library.

It is **pure and side-effect-free** (no I/O, no engine state) and imports nothing from
``messagefoundry.config`` / ``pipeline`` / ``store`` / ``transports`` — so the console may import it,
and a code-first Router/Handler calls it **on demand** against a
:class:`~messagefoundry.parsing.message.RawMessage` (``content_type="x12"``, ADR 0004): X12 is **not**
pushed through the engine pipeline as a bespoke object. The X12 content type is referred to by the
literal string ``"x12"`` (never imported from ``config``) to keep this purity.

Two tiers, mirroring python-hl7 (tolerant) / hl7apy (strict):

* **Tolerant (built here):** :class:`X12Peek` (cheap ISA + GS/ST peek for routing), :func:`split` /
  :class:`X12FrameReader` (interchange framing), :class:`X12Message` (read/set/encode for transforms),
  :func:`check_integrity` (envelope tie-out).
* **Strict (deferred):** implementation-guide validation (e.g. 005010X222A1 for 837P) is future work.
"""

from __future__ import annotations

from messagefoundry.parsing.x12.delimiters import (
    Delimiters,
    discover_delimiters,
    find_isa_start,
)
from messagefoundry.parsing.x12.errors import X12Error, X12FrameError, X12PeekError
from messagefoundry.parsing.x12.interchange import X12FrameReader, check_integrity, split
from messagefoundry.parsing.x12.message import X12Message
from messagefoundry.parsing.x12.peek import X12Group, X12Peek

__all__ = [
    "X12Peek",
    "X12Group",
    "X12Message",
    "X12FrameReader",
    "split",
    "check_integrity",
    "discover_delimiters",
    "find_isa_start",
    "Delimiters",
    "X12Error",
    "X12PeekError",
    "X12FrameError",
]
