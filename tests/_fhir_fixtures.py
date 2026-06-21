# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synthetic, PHI-free FHIR-JSON fixtures shared by the codec tests (and the FHIR transport tests).

NOT a test module (the leading underscore keeps pytest from collecting it). Every payload here is
**synthetic** — invented names/ids, no real patient data — so it is safe to commit and to surface in
assertions. Resources validate against FHIR R4B unless noted.
"""

from __future__ import annotations

import json
from typing import Any

# A valid R4B Patient with a conformance profile and a synthetic name.
PATIENT_R4B: dict[str, Any] = {
    "resourceType": "Patient",
    "id": "synthetic-001",
    "meta": {"profile": ["http://hl7.org/fhir/us/core/StructureDefinition/us-core-patient"]},
    "name": [{"family": "Synthetic", "given": ["Test", "Demo"]}],
    "gender": "unknown",
    "birthDate": "2000-01-01",
}

# A transaction Bundle that fans out to two inline resources plus one request-only (conditional
# DELETE) entry carrying no inline resource — exercises entry_resource_types()/entry_requests().
BUNDLE_TRANSACTION: dict[str, Any] = {
    "resourceType": "Bundle",
    "id": "synthetic-bundle-001",
    "type": "transaction",
    "entry": [
        {
            "resource": {"resourceType": "Patient", "id": "p1", "name": [{"family": "Synthetic"}]},
            "request": {"method": "POST", "url": "Patient"},
        },
        {
            "resource": {
                "resourceType": "Observation",
                "status": "final",
                "code": {"text": "synthetic vital"},
            },
            "request": {"method": "POST", "url": "Observation"},
        },
        {  # request-only entry (conditional delete): no inline resource — must be skipped, never error
            "request": {"method": "DELETE", "url": "Patient?identifier=synthetic|gone"},
        },
    ],
}

# OperationOutcome variants (FHIR's structured result) for the transport's classification (ADR 0022 §2.4).
OPERATION_OUTCOME_ERROR: dict[str, Any] = {
    "resourceType": "OperationOutcome",
    "issue": [
        {"severity": "error", "code": "invalid", "diagnostics": "synthetic validation problem"}
    ],
}
OPERATION_OUTCOME_TRANSIENT: dict[str, Any] = {
    "resourceType": "OperationOutcome",
    "issue": [{"severity": "error", "code": "throttled", "diagnostics": "synthetic backpressure"}],
}
OPERATION_OUTCOME_SUCCESS: dict[str, Any] = {
    "resourceType": "OperationOutcome",
    "issue": [{"severity": "information", "code": "informational", "diagnostics": "ok"}],
}

# A distinctive token standing in for PHI, placed in a *wrong-typed* field so model validation fails.
# Used to prove the codec never leaks the body into an error message / log line.
PHI_CANARY = "LEAKCANARY-SSN-000000000"
INVALID_PATIENT_WITH_CANARY: dict[str, Any] = {
    "resourceType": "Patient",
    "name": PHI_CANARY,  # name MUST be an array of HumanName → ValidationError; the canary is the input
}


def as_json(obj: dict[str, Any]) -> str:
    """Serialize a fixture dict to a FHIR-JSON string (what FhirPeek.parse / FhirResource.parse take)."""
    return json.dumps(obj)
