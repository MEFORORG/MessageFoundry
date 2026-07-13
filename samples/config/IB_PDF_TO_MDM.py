# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample feed (Shape B): pick up a PDF from a file drop, base64-encode it, wrap it in an MDM, send to Epic.

The owner's end-to-end scenario, build-the-document half (#149, ADR 0105): "pick up a PDF from a file
location, base64 encode it, then insert it into an MDM." A **File inbound** with ``content_type=BINARY``
polls a drop directory and delivers each file as raw bytes (ADR 0004 payload-agnostic ingress; ADR 0028
base64 carriage), so the Router/Handler receive a :class:`RawMessage` whose ``.raw_bytes`` is the exact
PDF. A code-first **Handler** base64-encodes those bytes and builds an ``MDM^T02`` with the document in
``OBX-5`` (see ``_pdf_mdm_transforms.build_mdm_from_pdf``), then Sends it to an **MLLP outbound** that
delivers it **inline** to Epic. A Handler-built large MDM rides the outbound row terminally — there is no
ingress detach here (nothing was over-threshold on the way in), and the outbound MLLP frame is uncapped,
so the whole document streams inline.

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db

Drop a synthetic (never real PHI) PDF into the DEV inbox to exercise it. Endpoints are loopback/synthetic.
"""

from messagefoundry import (
    MLLP,
    ContentType,
    File,
    Send,
    current_ingest_time,
    handler,
    inbound,
    outbound,
    router,
)

from _pdf_mdm_transforms import build_mdm_from_pdf

# File inbound: poll a DEV drop directory for *.pdf and deliver each as raw bytes (content_type=BINARY →
# base64-carried, routed as a RawMessage). The bind directory is a DEV path; a real deployment points it
# at the partner's landing zone.
inbound(
    "IB_PDF_TO_MDM",
    File(directory="./dev-inbox/pdf", pattern="*.pdf", after_read="move"),
    router="pdf_mdm_router",
    content_type=ContentType.BINARY,
)
# Epic's inbound MDM receiver over MLLP (loopback in DEV). The outgoing frame is uncapped, so the base64
# PDF streams inline; max_frame_bytes bounds only the ACK read (ADR 0105 Phase 1b).
outbound("OB_EPIC_PDF_MDM", MLLP(host="127.0.0.1", port=2778, max_frame_bytes=64 * 1024 * 1024))


@router("pdf_mdm_router")
def route(msg):
    # Only base64-carried binary bodies are PDFs to wrap; anything else (e.g. a mis-fed text body, or a
    # dry-run over an HL7 fixture) is UNROUTED — counted + logged, never an error (CLAUDE.md §2).
    if not msg.is_binary:
        return []
    return ["pdf_mdm_handler"]


@handler("pdf_mdm_handler")
def handle(msg):
    # RawMessage.raw_bytes recovers the exact PDF; build the MDM (base64 the bytes into OBX-5). Pure: same
    # PDF in -> same MDM out (control id = content hash; timestamp = the re-run-stable ingest time), so an
    # at-least-once re-run re-derives identical output. The MDM rides the outbound row terminally (no
    # detach needed — it was never over-threshold at ingress).
    mdm = build_mdm_from_pdf(msg.raw_bytes, ingest_time=current_ingest_time())
    return Send("OB_EPIC_PDF_MDM", mdm)
