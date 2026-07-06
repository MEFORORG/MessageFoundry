# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the FHIR codec's **typed tier** (ADR 0022): FhirResource (validated model over
fhir.resources) + FhirPeek.evaluate (FHIRPath). These need the optional ``[fhir]`` extra, so the whole
module importorskips when it is absent (mirroring the repo's optional-driver test convention) — CI
installs ``.[dev,console,fhir]`` so they actually RUN their assertions there, incl. the headline
PHI-no-leak invariant."""

from __future__ import annotations

import pytest

pytest.importorskip("fhir.resources")
pytest.importorskip("fhirpathpy")

from messagefoundry.parsing import FhirPeek, FhirResource  # noqa: E402  (after importorskip, by design)
from messagefoundry.parsing.fhir import FhirError, FhirValidationError  # noqa: E402

from _fhir_fixtures import (  # noqa: E402
    INVALID_PATIENT_WITH_CANARY,
    PATIENT_R4B,
    PHI_CANARY,
    as_json,
)


def test_peek_evaluate_fhirpath() -> None:
    peek = FhirPeek.parse(as_json(PATIENT_R4B))
    assert peek.evaluate("Patient.name.family") == ["Synthetic"]


def test_resource_parse_validate_and_encode() -> None:
    res = FhirResource.parse(as_json(PATIENT_R4B), version="R4B")
    assert res.resource_type == "Patient"
    assert res.id == "synthetic-001"
    assert res.version == "R4B"
    assert res.model.name[0].family == "Synthetic"
    # re-serialize → valid JSON carrying the resourceType
    assert res.as_dict()["resourceType"] == "Patient"
    assert '"resourceType":"Patient"' in res.encode().replace(" ", "")


def test_resource_default_version_is_r4b() -> None:
    assert FhirResource.parse(as_json(PATIENT_R4B)).version == "R4B"


def test_resource_other_versions_parse() -> None:
    for version in ("R5", "STU3"):
        assert FhirResource.parse(as_json(PATIENT_R4B), version=version).version == version


def test_resource_tolerates_utf8_bom() -> None:
    # A UTF-8 BOM prefix must not dead-letter a valid resource (matches the FhirPeek BOM tolerance).
    assert FhirResource.parse("﻿" + as_json(PATIENT_R4B)).resource_type == "Patient"


def test_resource_evaluate_fhirpath() -> None:
    res = FhirResource.parse(as_json(PATIENT_R4B))
    assert "Test" in res.evaluate("Patient.name.given")


def test_resource_unknown_resource_type() -> None:
    with pytest.raises(FhirValidationError, match="NotAResource"):
        FhirResource.parse('{"resourceType": "NotAResource"}')


def test_resource_missing_resource_type() -> None:
    with pytest.raises(FhirValidationError, match="resourceType"):
        FhirResource.parse("{}")


def test_resource_unsupported_version() -> None:
    with pytest.raises(FhirError, match="fhir_version"):
        FhirResource.parse(as_json(PATIENT_R4B), version="R4")  # plain R4 not on pydantic-v2 wheels


def test_resource_xml_is_deferred() -> None:
    with pytest.raises(FhirError, match="JSON only"):
        FhirResource.parse(as_json(PATIENT_R4B), format="xml")


def test_resource_invalid_structure_raises_validation_error() -> None:
    with pytest.raises(FhirValidationError):
        FhirResource.parse(as_json(INVALID_PATIENT_WITH_CANARY))


def test_validation_error_never_leaks_the_body() -> None:
    """The ADR's headline PHI guarantee: a validation failure surfaces only routing-safe info
    (resourceType/version/field loc+type), never the offending input value (PHI) — and must NOT chain
    the pydantic error (which carries it). Runs in CI because the `test` leg installs `[fhir]`."""
    with pytest.raises(FhirValidationError) as excinfo:
        FhirResource.parse(as_json(INVALID_PATIENT_WITH_CANARY))
    exc = excinfo.value
    assert PHI_CANARY not in str(exc)
    assert PHI_CANARY not in repr(exc)
    assert exc.__cause__ is None  # `from None` severed the PHI-bearing pydantic ValidationError
