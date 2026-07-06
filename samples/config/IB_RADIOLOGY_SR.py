# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample route: receive radiology **DICOM Structured Reports** over C-STORE and map them to HL7 v2
**ORU** for a dictation/reporting system (the Corepoint "DICOM Gear" replacement, ADR 0025).

This is the standalone-value demo: a modality/PACS **C-STOREs** an SR object into MessageFoundry; a
Router peeks the SOP class with the pure ``messagefoundry.parsing.dicom`` codec and forwards SR objects
to the Handler; the Handler walks the SR ``ContentSequence`` for measurements and builds an **ORU^R01**
with one **OBX** per measurement, delivered to an outbound MLLP connection (the PowerScribe analog). The
mapping is **code-first pure Python** — diffable, unit-testable, no proprietary GUI mapper.

The inbound declares ``content_type="dicom"`` so each received object is base64-carried (ADR 0028) and
routed as a ``RawMessage`` (ADR 0004); the codec recovers the bytes via ``.raw_bytes`` on demand. The
SCP binds ``[inbound].bind_host`` (a non-loopback bind requires ``tls=true`` or
``serve --allow-insecure-bind``); ``ae_title``/``calling_ae_allowlist`` gate which peers may associate.

    pip install 'messagefoundry[dicom]'   # pydicom + pynetdicom (the codec + the SCP both need it)
    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db

Generate a synthetic, PHI-free SR to send with ``samples/dicom/generate_sr_sample.py``.
"""

from messagefoundry import (
    DICOM,
    MLLP,
    ContentType,
    Message,
    Send,
    env,
    handler,
    inbound,
    outbound,
    router,
)
from messagefoundry.parsing.dicom import DicomDataset, DicomPeek, hl7_map

# Inbound C-STORE SCP. No host (the bind interface is [inbound].bind_host); the SCP's AE Title is
# "MEFOR_SR_SCP" and only the listed modality AE may associate. Default port 104 (set port=11112 for a
# non-privileged dev bind).
inbound(
    "IB_RADIOLOGY_SR",
    DICOM(ae_title="MEFOR_SR_SCP", port=11112, calling_ae_allowlist=["RAD_MODALITY"]),
    router="sr_router",
    content_type=ContentType.DICOM,
)
# The downstream dictation system (PowerScribe analog) over MLLP. Host/port are environment-specific, so
# they are authored with env() (resolved from environments/<env>.toml).
outbound(
    "OB_POWERSCRIBE", MLLP(host=env("powerscribe_host"), port=env("powerscribe_port", cast=int))
)


@router("sr_router")
def route(msg):
    # content_type="dicom" → msg is a RawMessage carrying the object as base64 (.is_binary). A body that
    # isn't base64-carried (e.g. a mis-fed text message, as in a dryrun-over-all-routers pass) is
    # UNROUTED — counted + logged, never an error (the FHIR sample's "filter non-matching bodies"
    # pattern). DicomPeek then recovers the bytes (.raw_bytes) and does a cheap shallow tag read — no
    # full dataset walk on the hot path. A non-SR object (a plain image) is UNROUTED; a carried body
    # that won't parse as DICOM lets DicomPeek.parse raise → ERROR/dead-letter (count-and-log).
    if not msg.is_binary:
        return []
    peek = DicomPeek.parse(msg)
    if peek.is_structured_report():
        return ["sr_to_oru"]
    return []  # non-SR objects are not mapped here


@handler("sr_to_oru")
def handle(msg):
    # Parse the SR (headers + ContentSequence; no pixel data) and map it to an ORU. Pure: same object in
    # → same ORU out (MSH-10 is the deterministic SOP Instance UID, never a wall-clock id), so an
    # at-least-once re-run re-derives identical output (CLAUDE.md §2).
    ds = DicomDataset.parse(msg)
    measurements = ds.measurements()
    if not measurements:
        return None  # an SR with no numeric content delivers nothing → FILTERED (counted + logged)
    control_id = ds.sop_instance_uid or "UNKNOWN"
    oru = Message.parse(
        "MSH|^~\\&|MEFOR|RADIOLOGY|POWERSCRIBE|FACILITY|"
        f"{ds.study_date or ''}||ORU^R01|{control_id}|P|2.5.1"
    )
    oru.add_segment(hl7_map.pid_from_dataset(ds))
    oru.add_segment(hl7_map.obr_from_dataset(ds))
    for set_id, measurement in enumerate(measurements, start=1):
        oru.add_segment(hl7_map.obx_from_measurement(set_id, measurement))
    return Send("OB_POWERSCRIBE", oru.encode())
