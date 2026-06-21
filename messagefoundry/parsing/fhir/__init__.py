# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure FHIR codec (ADR 0022) — a tolerant routing peek + a validated resource model, mirroring the
HL7 :mod:`messagefoundry.parsing` library and the X12 :mod:`messagefoundry.parsing.x12` codec.

It is **pure and side-effect-free** (no I/O, no engine state) and imports nothing from
``messagefoundry.config`` / ``pipeline`` / ``store`` / ``transports`` — so the console may import it,
and a code-first Router/Handler calls it **on demand** against a
:class:`~messagefoundry.parsing.message.RawMessage` (``content_type="fhir"``, ADR 0004): FHIR is
**not** pushed through the engine pipeline as a bespoke object. The FHIR content type is referred to by
the literal string ``"fhir"`` (never imported from ``config``) to keep this purity (enforced by the two
import-purity tests).

Two tiers, mirroring python-hl7 (tolerant) / hl7apy (strict):

* **Tolerant (the hot path):** :class:`~messagefoundry.parsing.fhir.peek.FhirPeek` — a cheap shallow
  read of ``resourceType``/``id``/``meta.profile``/``Bundle.type``/entry resource types for routing,
  with no typed model construction and no dependency on the optional extra.
* **Strict (on demand in a Handler):** :class:`~messagefoundry.parsing.fhir.resource.FhirResource` — a
  full, validated :mod:`fhir.resources` (pydantic-v2) model for transforms, lazily pulling the optional
  ``messagefoundry[fhir]`` extra. JSON is the MVP format; FHIR-XML is deferred (ADR 0022 Options #5).

HL7 v2 ↔ FHIR mapping stays in code-first Handlers (python-hl7 ``Message`` in → ``fhir.resources``
resource out), never here.
"""

from __future__ import annotations

from messagefoundry.parsing.fhir.errors import FhirError, FhirPeekError, FhirValidationError
from messagefoundry.parsing.fhir.peek import FhirPeek
from messagefoundry.parsing.fhir.resource import FhirResource

__all__ = [
    "FhirPeek",
    "FhirResource",
    "FhirError",
    "FhirPeekError",
    "FhirValidationError",
]
