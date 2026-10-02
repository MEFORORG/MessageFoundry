# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DICOM DIMSE graph for the headless harness: a C-STORE SCP inbound forwarded, unchanged, to a
C-STORE SCU outbound whose peer is the harness DIMSE sink (ADR 0025).

    IB_Harness_DIMSE (SCP, AE MEFOR_HARNESS, port harness_dimse_in = 2650)
      -> dimse_router -> dimse_forward -> OB_Harness_DIMSE (SCU -> AE HARNESS_SINK on
         harness_dimse_out = 2651)

The inbound declares ``content_type="dicom"``, so each object is base64-carried (ADR 0028) and the
engine records it with NO control id: a DICOM object has no MSH-10, and the SCP does not lift the
SOPInstanceUID into one. The harness scenarios (``harness/scenarios/dimse.py``) correlate by reading
each new row's body back through the audited raw-body route and peeking its SOPInstanceUID.

The outbound retries on a fast policy so an Out of Resources answer (0xA700, transient) dead-letters
after three attempts within seconds, and a hard refusal (0xC000) dead-letters after one. The SCP
binds ``[inbound].bind_host`` (loopback unless an operator changes it; this cleartext SCP sets no
``source_ip_allowlist`` or TLS, so the engine refuses it on any other bind) and the SCU dials
``harness_host``. ``MEFOR_VALUE_HARNESS_DIMSE_IN`` / ``_DIMSE_OUT`` move the ports, and the AE titles
below must equal the ones ``harness/drivers/dimse.py`` and ``harness/sinks/dimse.py`` use (a test holds
them equal; this module imports nothing from ``harness``). Needs the ``[dicom]`` extra at run time.
All data is synthetic; never point a real PHI feed at a harness config.
"""

from messagefoundry import DICOM, ContentType, Send, env, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy

inbound(
    "IB_Harness_DIMSE",
    DICOM(
        ae_title="MEFOR_HARNESS",
        port=env("harness_dimse_in", default=2650, cast=int),
        timeout_seconds=10.0,
    ),
    router="dimse_router",
    content_type=ContentType.DICOM,
)

outbound(
    "OB_Harness_DIMSE",
    DICOM(
        ae_title="MEFOR_HARNESS",
        host=env("harness_host", default="127.0.0.1"),
        port=env("harness_dimse_out", default=2651, cast=int),
        called_ae_title="HARNESS_SINK",
        connect_timeout=3.0,
        timeout_seconds=5.0,
    ),
    retry=RetryPolicy(
        max_attempts=3, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=2.0
    ),
)


@router("dimse_router")
def route(msg):  # type: ignore[no-untyped-def]
    # A body that is not base64-carried cannot be a DICOM object: routed nowhere (UNROUTED), logged.
    if not msg.is_binary:
        return []
    return ["dimse_forward"]


@handler("dimse_forward")
def forward(msg):  # type: ignore[no-untyped-def]
    # Forward the carried object byte for byte; the SCU recovers the Part-10 bytes from the carriage.
    return Send("OB_Harness_DIMSE", msg)
