# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Exceptions for the FHIR codec (ADR 0022).

Kept in their own module (mirroring :mod:`messagefoundry.parsing.x12.errors`) so the peek / resource
modules can raise them without importing each other. All derive from :class:`ValueError`, so a
Router/Handler that already routes ``ValueError`` to the error/dead-letter path catches malformed /
non-FHIR bodies without special-casing FHIR — the count-and-log invariant holds for free.

**PHI rule (do not break):** these messages — and *any* codec log line — carry only routing-safe
identifiers (``resourceType``, a resource ``id``, an ``OperationOutcome`` ``issue.code``/``severity``,
field *locations*/*types*), **never** the FHIR resource body. The full PHI-bearing body goes only to
the secured store (CLAUDE.md §9 / ADR 0022 §1).
"""

from __future__ import annotations

__all__ = ["FhirError", "FhirPeekError", "FhirValidationError"]


class FhirError(ValueError):
    """Base class for every FHIR codec error."""


class FhirPeekError(FhirError):
    """The body is not a parseable FHIR resource (not JSON, not a resource object, or an unsupported
    serialization). The FHIR analog of :class:`~messagefoundry.parsing.x12.errors.X12PeekError` — a
    Router routes the message to the error/dead-letter path rather than guessing."""


class FhirValidationError(FhirError):
    """A structurally-parseable body failed FHIR model validation (unknown/absent ``resourceType``, or a
    cardinality/type violation caught by :mod:`fhir.resources`). Its message is **PHI-safe**: it names
    the ``resourceType``, version, and the offending field *locations*/*types* only — never the input
    values."""
