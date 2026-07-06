# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure DICOM codec (ADR 0025) — a tolerant routing peek + a navigable dataset model + DICOM→HL7
mapping helpers, mirroring the HL7 :mod:`messagefoundry.parsing` library and the X12
(:mod:`messagefoundry.parsing.x12`) / FHIR (:mod:`messagefoundry.parsing.fhir`) codecs.

It is **pure and side-effect-free** (no I/O, no engine state) and imports nothing from
``messagefoundry.config`` / ``pipeline`` / ``store`` / ``transports`` — so the console may import it for
a client-side DICOM tag-tree viewer, and a code-first Router/Handler calls it **on demand** against a
:class:`~messagefoundry.parsing.message.RawMessage` (``content_type="dicom"``, ADR 0004): DICOM is
**not** pushed through the engine pipeline as a bespoke object. The DICOM content type is referred to by
the literal string ``"dicom"`` (never imported from ``config``) to keep this purity (enforced by the two
import-purity tests).

A DICOM object is **binary**; it rides the ``str``/TEXT ingress+store as base64 via the ADR 0028 §3
carriage (``RawMessage.from_bytes`` at the SCP, ``.raw_bytes`` here — the one decode), **never** the
lossy latin-1 round-trip.

Two tiers, mirroring python-hl7 (tolerant) / hl7apy (strict):

* **Tolerant (the hot path):** :class:`~messagefoundry.parsing.dicom.peek.DicomPeek` — a cheap shallow
  read of ``SOPClassUID``/``Modality``/study-series-instance UIDs for routing (``stop_before_pixels``,
  ``specific_tags``), no full dataset walk, no pixel data.
* **Strict (on demand in a Handler):** :class:`~messagefoundry.parsing.dicom.dataset.DicomDataset` — a
  full header + SR ``ContentSequence`` walk (headers/SR only — **no pixel data, no ``numpy``**), lazily
  pulling the optional ``messagefoundry[dicom]`` extra (``pydicom``).

DICOM ↔ HL7 v2 mapping stays in code-first Handlers (``DicomDataset`` in → python-hl7 ``Message`` out)
via the :mod:`~messagefoundry.parsing.dicom.hl7_map` helpers, never a declarative mapper.
"""

from __future__ import annotations

from messagefoundry.parsing.dicom.dataset import DicomDataset, SrMeasurement
from messagefoundry.parsing.dicom.errors import DicomError, DicomPeekError
from messagefoundry.parsing.dicom.peek import DicomPeek

__all__ = [
    "DicomPeek",
    "DicomDataset",
    "SrMeasurement",
    "DicomError",
    "DicomPeekError",
]
