# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Exceptions for the DICOM codec (ADR 0025).

Kept in their own module (mirroring :mod:`messagefoundry.parsing.fhir.errors` /
:mod:`messagefoundry.parsing.x12.errors`) so peek / dataset / hl7_map can raise them without importing
each other. Both derive from :class:`ValueError`, so a Router/Handler that already routes ``ValueError``
to the error/dead-letter path catches malformed / non-DICOM bodies without special-casing DICOM — the
count-and-log invariant holds for free.

The **missing ``[dicom]`` extra** failure is deliberately **not** one of these: it is a
:class:`RuntimeError` (see :mod:`messagefoundry.parsing.dicom._deps`), a deploy/config error that a
Handler's ``except ValueError`` must **not** swallow (identical to the FHIR / SQL-Server / Postgres
posture).

**PHI rule (do not break):** these messages — and *any* codec/transport log line — carry only
**routing-safe identifiers** (``SOPClassUID``, ``Modality``, a study/series/instance UID, an AE Title),
**never** the dataset, an element value, or pixel data. The full PHI-bearing object goes only to the
secured store (CLAUDE.md §9 / ADR 0025 §1).
"""

from __future__ import annotations

__all__ = ["DicomError", "DicomPeekError"]


class DicomError(ValueError):
    """Base class for every DICOM codec data error."""


class DicomPeekError(DicomError):
    """The body is not a parseable DICOM Part-10 object (no preamble/``DICM`` magic, truncated, or
    otherwise undecodable). The DICOM analog of
    :class:`~messagefoundry.parsing.fhir.errors.FhirPeekError` /
    :class:`~messagefoundry.parsing.x12.errors.X12PeekError` — a Router routes the message to the
    error/dead-letter path rather than guessing. **PHI-safe:** names the failure, never the bytes."""
