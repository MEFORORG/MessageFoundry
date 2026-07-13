# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared transform helper for the PDF -> base64 -> MDM feed (Shape B, #149/ADR 0105).

Split out per CLAUDE.md §4 ("author config as modular Python … put shared helpers in ``_``-prefixed
files"; the loader skips ``_*``). Pure: bytes in -> an ``MDM^T02`` :class:`Message` out, deterministic
in its inputs (the control id is the content address of the PDF, the timestamp is the engine's re-run-
stable ingest time), so an at-least-once re-run re-derives an identical message (CLAUDE.md §2)."""

from __future__ import annotations

import hashlib
import time

from messagefoundry import Message
from messagefoundry.parsing.binary import embed_obx_document

# A minimal MDM^T02 skeleton with ONE empty OBX; embed_obx_document fills OBX-2/OBX-5 with the base64 ED
# document. All fields are synthetic — never real PHI (CLAUDE.md §9).
_MDM_TEMPLATE = (
    "MSH|^~\\&|MEFOR|FACILITY|EPIC|EPICFAC|{ts}||MDM^T02|{cid}|P|2.5.1\r"
    "EVN|T02|{ts}\r"
    "PID|1||SYNTH123^^^FACILITY||DOE^JANE\r"
    "TXA|1|CN|AP^application/pdf|{ts}\r"
    "OBX|1|ED|PDF^Scanned document||||||F\r"
)


def build_mdm_from_pdf(pdf: bytes, *, ingest_time: float | None = None) -> Message:
    """Base64-encode ``pdf`` and insert it into an ``MDM^T02`` as an ``OBX-5`` ED document (owner's
    words: "pick up a PDF … base64 encode it, then insert it into an MDM"). The control id (MSH-10) is
    the PDF's SHA-256 (content-addressed → stable + dedup-friendly); the timestamp is the engine ingest
    time when provided (re-run-stable, ADR 0009) else the wall clock. Pure and deterministic in its
    inputs. Recover the exact PDF bytes with ``extract_obx_document`` — the base64 round-trips verbatim."""
    ts = time.strftime(
        "%Y%m%d%H%M%S", time.gmtime(ingest_time if ingest_time is not None else time.time())
    )
    control_id = hashlib.sha256(pdf).hexdigest()[:16].upper()
    mdm = Message.parse(_MDM_TEMPLATE.format(ts=ts, cid=control_id))
    embed_obx_document(mdm, pdf, data_subtype="PDF")
    return mdm
