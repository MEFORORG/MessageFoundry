# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the FHIR codec's **extra-less surface** (ADR 0022): the tolerant FhirPeek routing tier,
the ValueError-rooted error hierarchy, the PHI-no-leak peek path, and the two console-carve-out
import-purity guards + the lazy-extra guard. These run WITHOUT the optional ``[fhir]`` extra (FhirPeek's
structural accessors and the codec's purity are dependency-free). The typed tier (FhirResource +
FhirPeek.evaluate, which need the extra) lives in tests/test_fhir_resource.py behind an importorskip."""

from __future__ import annotations

import subprocess
import sys

import pytest

from messagefoundry.parsing import FhirPeek, FhirPeekError
from messagefoundry.parsing.fhir import FhirError, FhirValidationError

from _fhir_fixtures import (
    BUNDLE_TRANSACTION,
    OPERATION_OUTCOME_ERROR,
    PATIENT_R4B,
    PHI_CANARY,
    as_json,
)

# --- FhirPeek: the tolerant routing tier (no [fhir] extra needed) ------------


def test_peek_patient_routing_fields() -> None:
    peek = FhirPeek.parse(as_json(PATIENT_R4B))
    assert peek.resource_type == "Patient"
    assert peek.id == "synthetic-001"
    assert peek.profiles == ("http://hl7.org/fhir/us/core/StructureDefinition/us-core-patient",)
    assert peek.bundle_type is None
    assert peek.entry_resource_types() == []  # not a Bundle


def test_peek_accepts_bytes() -> None:
    peek = FhirPeek.parse(as_json(PATIENT_R4B).encode("utf-8"))
    assert peek.resource_type == "Patient"


def test_peek_tolerates_utf8_bom() -> None:
    # A UTF-8 BOM (﻿) prefix — common from some EHR exporters — must not dead-letter the resource.
    assert FhirPeek.parse("﻿" + as_json(PATIENT_R4B)).resource_type == "Patient"
    assert FhirPeek.parse(("﻿" + as_json(PATIENT_R4B)).encode("utf-8")).resource_type == "Patient"


def test_peek_bundle_fans_out_full_list() -> None:
    peek = FhirPeek.parse(as_json(BUNDLE_TRANSACTION))
    assert peek.resource_type == "Bundle"
    assert peek.bundle_type == "transaction"
    # full list, in order; the request-only DELETE entry (no inline resource) is skipped
    assert peek.entry_resource_types() == ["Patient", "Observation"]
    assert ("DELETE", "Patient?identifier=synthetic|gone") in peek.entry_requests()
    assert ("POST", "Patient") in peek.entry_requests()


def test_peek_operation_outcome_resource_type() -> None:
    assert FhirPeek.parse(as_json(OPERATION_OUTCOME_ERROR)).resource_type == "OperationOutcome"


@pytest.mark.parametrize("body", ['{"resourceType": "Patient"', "not json at all", "", "[1, 2, 3]"])
def test_peek_rejects_unparseable_or_non_object(body: str) -> None:
    with pytest.raises(FhirPeekError):
        FhirPeek.parse(body)


def test_peek_xml_is_deferred() -> None:
    with pytest.raises(FhirPeekError, match="JSON only"):
        FhirPeek.parse('<Patient xmlns="http://hl7.org/fhir"/>')


# --- error hierarchy (ValueError-rooted → dead-letters without special-casing) ----


def test_errors_are_valueerror_rooted() -> None:
    assert issubclass(FhirError, ValueError)
    assert issubclass(FhirPeekError, FhirError)
    assert issubclass(FhirValidationError, FhirError)


# --- PHI-no-leak invariant on the peek path (ADR 0022 §1; CLAUDE.md §9) ------


def test_peek_error_never_leaks_the_body() -> None:
    malformed = '{"resourceType": "Patient", "name": ' + PHI_CANARY  # invalid JSON, canary unquoted
    with pytest.raises(FhirPeekError) as excinfo:
        FhirPeek.parse(malformed)
    exc = excinfo.value
    assert PHI_CANARY not in str(exc)
    assert PHI_CANARY not in str(
        exc.__cause__ or ""
    )  # the chained JSONDecodeError is position-only


# --- console carve-out: import purity (mirrors tests/test_x12_parsing.py) ----


def test_parsing_fhir_pulls_no_heavy_engine_or_gui_modules() -> None:
    """Importing parsing.fhir must NOT pull in the engine internals or the GUI (ADR 0022 §5 + CLAUDE.md
    §4 carve-out): no pipeline/store/transports/api/console. (``config`` is excluded here because the
    root ``messagefoundry/__init__`` imports config *models* unconditionally — a baseline shared by all
    of parsing/; that fhir's own sources don't import config is enforced by the static test below.)"""
    code = (
        "import sys, messagefoundry.parsing.fhir as _;"
        "heavy=('messagefoundry.pipeline','messagefoundry.store','messagefoundry.transports',"
        "'messagefoundry.api','messagefoundry.console');"
        "bad=sorted(m for m in sys.modules if m.startswith(heavy));"
        "print('\\n'.join(bad));"
        "sys.exit(1 if bad else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"parsing.fhir pulled heavy engine/GUI modules:\n{result.stdout}"


def test_parsing_fhir_does_not_eagerly_import_the_extra() -> None:
    """A bare ``import messagefoundry.parsing.fhir`` (and the peek-only structural accessors) must NOT
    pull the optional ``[fhir]`` extra (``fhir.resources``/``fhirpathpy``) — only FhirResource.parse and
    FhirPeek.evaluate may. This keeps a console/peek-only import working without the extra (ADR 0022 §1
    + Consequences). Asserted in a subprocess so it is independent of test-suite import order."""
    code = (
        "import sys, messagefoundry.parsing.fhir as fhir;"
        'fhir.FhirPeek.parse(\'{"resourceType": "Patient"}\').resource_type;'  # peek tier only
        "lazy=('fhir.resources','fhir_core','fhirpathpy');"
        "leaked=sorted(m for m in sys.modules if m.startswith(lazy));"
        "print('\\n'.join(leaked));"
        "sys.exit(1 if leaked else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"parsing.fhir eagerly imported the [fhir] extra:\n{result.stdout}"
    )


def test_parsing_fhir_sources_import_no_engine_packages() -> None:
    """Every parsing.fhir module must import zero engine packages — config included (the ADR's
    'refer to the content type by the literal "fhir"' rule) — so the codec stays pure."""
    import pathlib

    import messagefoundry.parsing.fhir as pkg

    forbidden = (
        "messagefoundry.config",
        "messagefoundry.transports",
        "messagefoundry.pipeline",
        "messagefoundry.store",
        "messagefoundry.api",
        "messagefoundry.console",
    )
    offenders: list[str] = []
    for module_file in sorted(pathlib.Path(pkg.__file__).parent.glob("*.py")):
        for line in module_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for pkg_name in forbidden:
                if stripped.startswith((f"import {pkg_name}", f"from {pkg_name}")):
                    offenders.append(f"{module_file.name}: {stripped}")
    assert not offenders, "parsing.fhir sources import engine packages:\n" + "\n".join(offenders)
