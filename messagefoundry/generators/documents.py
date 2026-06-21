# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synthetic **encapsulated-document** (ED) HL7 messages for round-trip / transport tests.

Real-world ORU lab/radiology results and MDM transcriptions carry a scanned PDF as a base64
``OBX-5`` ED field, e.g.::

    OBX|1|ED|DOC^Report^L||^application^pdf^Base64^JVBERi0xLjQK...||||||F

The reference-driven generators (:mod:`messagefoundry.generators._core`) only emit numeric/text OBX
values, so this module adds the document-carrying ORU/MDM variants plus a deterministic synthetic PDF
blob — the fixtures the base64 round-trip tests need (plan SYNTHETIC-TEST-PLAN §1.0.b).

Everything here is **synthetic and PHI-free**. :func:`synthetic_pdf` returns a *transport* fixture — a
blob with a valid ``%PDF`` header and ``%%EOF`` trailer for byte-exact round-trip assertions, **not** a
renderable clinical document. Output is deterministic given ``seed`` (and ``n_bytes``).
"""

from __future__ import annotations

import base64
import random

from messagefoundry.generators import all_types  # noqa: F401  (registers ORU/MDM/... specs on import)
from messagefoundry.generators._core import DEFAULT_SEED, generate_message
from messagefoundry.parsing.message import Message

__all__ = ["synthetic_pdf", "oru_with_pdf", "mdm_with_pdf"]

_PDF_HEADER = b"%PDF-1.4\n"
_PDF_TRAILER = b"\n%%EOF\n"
# A minimal catalog/pages/page object skeleton so even a small blob is shaped like a real PDF.
_PDF_SKELETON = (
    b"1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n"
    b"2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n"
    b"3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>> endobj\n"
)


def synthetic_pdf(*, n_bytes: int | None = None, seed: str = "mefor-pdf") -> bytes:
    """A deterministic synthetic PDF blob: ``%PDF-1.4`` header → object skeleton → optional filler →
    ``%%EOF`` trailer.

    Pass ``n_bytes`` to pad to exactly that size (when larger than the skeleton); the filler is
    deterministic opaque bytes (seeded), so the ED payload exercises arbitrary binary, not just text.
    It is a transport/round-trip fixture, not a renderable document.
    """
    parts = bytearray(_PDF_HEADER)
    parts += _PDF_SKELETON
    if n_bytes is not None:
        pad = n_bytes - len(parts) - len(_PDF_TRAILER)
        if pad > 0:
            parts += random.Random(seed).randbytes(pad)
    parts += _PDF_TRAILER
    return bytes(parts)


def _ed_obx(set_id: int, pdf: bytes) -> str:
    """An ``OBX`` segment line carrying ``pdf`` as a base64 ED field (the data in ``OBX-5.5``).

    Standard base64 is ``[A-Za-z0-9+/=]`` — none of those are HL7 delimiters, so the payload is a
    single component-structured ``OBX-5`` field that needs no escaping and round-trips verbatim (the
    property the tests assert)."""
    b64 = base64.b64encode(pdf).decode("ascii")
    return f"OBX|{set_id}|ED|DOC^Encapsulated Document^L||^application^pdf^Base64^{b64}||||||F"


def oru_with_pdf(pdf: bytes, *, index: int = 1, seed: str = DEFAULT_SEED) -> str:
    """A deterministic ``ORU^R01`` message carrying ``pdf`` as a trailing base64 ED ``OBX``."""
    msg = Message.parse(generate_message("ORU", "R01", index, seed=seed))
    msg.add_segment(_ed_obx(msg.count_segments("OBX") + 1, pdf))
    return msg.encode()


def mdm_with_pdf(pdf: bytes, *, index: int = 1, seed: str = DEFAULT_SEED) -> str:
    """A deterministic ``MDM^T02`` message carrying ``pdf`` as a trailing base64 ED ``OBX``."""
    msg = Message.parse(generate_message("MDM", "T02", index, seed=seed))
    msg.add_segment(_ed_obx(msg.count_segments("OBX") + 1, pdf))
    return msg.encode()
