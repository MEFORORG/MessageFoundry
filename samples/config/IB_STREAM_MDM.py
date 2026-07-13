# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample feed (Shape A): stream a very-large MDM (a base64 PDF in OBX-5.5) into Epic, inline over MLLP.

The owner's end-to-end scenario, document-present-at-ingress half (#149, ADR 0105). A partner sends a
single very-large ``MDM^T02`` whose ``OBX-5.5`` is a base64-encoded PDF that would push the MLLP frame
past the store's 16 MiB cap. ``stream_threshold_bytes`` arms the **ingress detach** (Phase 1a): a body
at/above the threshold has its oversized ``OBX-5`` ED document lifted **VERBATIM** into a
content-addressed, per-chunk-sealed attachment, leaving a small ``mfdoc:v1:ref:<sha256>:<type>`` handle
in a well-under-cap skeleton. Routing and this Handler are **pure pass-through** — the detached document
is opaque to them (owner ruling 2). At **delivery** (Phase 1b) the handle is re-attached VERBATIM (the
exact stored base64 spliced back into ``OBX-5.5`` — no decode/re-encode) and the full MDM streams
**inline** to Epic's MLLP receiver, which does not cap the frame (owner ruling 1).

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db

All endpoints are loopback/synthetic; send a synthetic large MDM with ``samples/send_mllp.py``.
"""

from messagefoundry import MLLP, Send, handler, inbound, outbound, router

# Streaming MLLP inbound. `stream_threshold_bytes` (Phase 1a opt-in; None = OFF, byte-identical to today)
# arms the detach for a received body at/above 256 KiB; `max_message_bytes` is the per-connection
# total-body OOM guard that replaces the frame-cap-as-only-guard, sized to admit multi-hundred-MB PDFs.
inbound(
    "IB_STREAM_MDM",
    MLLP(port=2775),
    router="stream_mdm_router",
    stream_threshold_bytes=256 * 1024,
    max_message_bytes=256 * 1024 * 1024,
)
# Epic's inbound MDM receiver over MLLP (loopback in DEV). Epic does NOT cap the frame, so the re-attached
# full document streams inline. `max_frame_bytes` bounds ONLY the ACK we read back — the OUTGOING frame is
# uncapped, so the large hydrated MDM always sends inline (ADR 0105 Phase 1b).
outbound("OB_EPIC_STREAM_MDM", MLLP(host="127.0.0.1", port=2776, max_frame_bytes=64 * 1024 * 1024))


@router("stream_mdm_router")
def route(msg):
    # Pure pass-through: every received MDM goes to the one Handler. By the time routing runs the document
    # is already a `mfdoc:v1:ref:` handle (detached at ingress) — routing never materializes the PDF.
    return ["stream_mdm_handler"]


@handler("stream_mdm_handler")
def handle(msg):
    # Pure pass-through (owner ruling 2: doc-mutating transforms are a non-goal on a streaming feed). The
    # skeleton's OBX-5.5 handle is an opaque leaf carried verbatim by Message.copy()/the Send snapshot
    # (ADR 0104); the terminal delivery re-attaches the verbatim document just before the wire.
    return Send("OB_EPIC_STREAM_MDM", msg)
