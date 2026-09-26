# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the FHIR codec's **extra-less surface** (ADR 0022): the tolerant FhirPeek routing tier,
the ValueError-rooted error hierarchy, the PHI-no-leak peek path, and the two console-carve-out
import-purity guards + the lazy-extra guard. These run WITHOUT the optional ``[fhir]`` extra (FhirPeek's
structural accessors and the codec's purity are dependency-free). The typed tier (FhirResource +
FhirPeek.evaluate, which need the extra) lives in tests/test_fhir_resource.py behind an importorskip."""

from __future__ import annotations

import json
import subprocess
import sys
import traceback
import uuid
from collections.abc import Callable
from types import SimpleNamespace

import pytest
from _fhir_fixtures import (
    BUNDLE_TRANSACTION,
    OPERATION_OUTCOME_ERROR,
    PATIENT_R4B,
    PHI_CANARY,
    as_json,
)

from messagefoundry import redaction
from messagefoundry.parsing import FhirPeek, FhirPeekError, FhirResource
from messagefoundry.parsing.fhir import FhirError, FhirValidationError

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


@pytest.mark.parametrize(
    ("parse", "wrapper"),
    [
        pytest.param(FhirPeek.parse, FhirPeekError, id="FhirPeek"),
        # The JSON decode runs before FhirResource loads the [fhir] extra, so this needs no extra.
        pytest.param(FhirResource.parse, FhirValidationError, id="FhirResource"),
    ],
)
def test_too_deep_json_is_the_typed_error(
    monkeypatch: pytest.MonkeyPatch,
    parse: Callable[[str], object],
    wrapper: type[FhirError],
) -> None:
    """json's depth limit is a ``RecursionError``, a ``RuntimeError`` the ``ValueError`` arm does not
    reach (BACKLOG #1600). The trigger is a raised ``RecursionError``, not a deep body, because the
    depth where json's C decoder gives out is a property of the runner (BACKLOG #1222). Both parsers
    decode through ``redaction.json_loads_or_refusal`` (BACKLOG #2048), so json is patched there."""

    def _recursing_loads(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("simulated deep nesting")

    stand_in = SimpleNamespace(loads=_recursing_loads, JSONDecodeError=json.JSONDecodeError)
    monkeypatch.setattr(redaction, "json", stand_in)
    with pytest.raises(wrapper, match=r"not parseable FHIR JSON \(RecursionError\)") as excinfo:
        parse(as_json(PATIENT_R4B))
    # The class name survives in the message; the chain does not (BACKLOG #2048).
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None


@pytest.mark.parametrize(
    ("parse", "wrapper"),
    [
        pytest.param(FhirPeek.parse, FhirPeekError, id="FhirPeek"),
        pytest.param(FhirResource.parse, FhirValidationError, id="FhirResource"),
    ],
)
def test_unparseable_json_leaves_the_body_off_the_exception_chain(
    parse: Callable[[str], object], wrapper: type[FhirError]
) -> None:
    """A JSON refusal must not carry the body on the raised error's chain (BACKLOG #2048).

    ``json.JSONDecodeError.doc`` is the WHOLE input. Chaining it with ``from exc`` put the FHIR body
    on ``__cause__``, and ``from None`` would still leave it on ``__context__``. The default
    traceback printer renders only the chained error's position-only ``str``, so it hid this; a
    chain walker that reads the attribute would have written the body to a log on first
    deployment. The marker is built at run time: a literal would sit in this file's source, and
    ``traceback`` echoes source lines, so the rendering check could not fail.

    The chain asserts are the ones that discriminate: the default printer renders a chained
    JSONDecodeError position-only, so the rendering check passes against ``from exc`` too. It stays
    as the guard against a message that interpolates the body. Frame locals are out of scope: the
    raised error's traceback still holds ``parse``'s frame and its ``raw``."""
    marker = "SYNTH" + uuid.uuid4().hex
    malformed = '{"resourceType": "Patient", "name": ' + marker  # unquoted token: invalid JSON
    with pytest.raises(wrapper, match="not parseable FHIR JSON") as excinfo:
        parse(malformed)
    err = excinfo.value
    assert err.__cause__ is None
    assert err.__context__ is None, "the JSONDecodeError (and its .doc) is still on __context__"
    assert "line 1, column" in str(err), "the content-free position hint should survive"
    assert marker not in "".join(traceback.format_exception(err))


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
    # No chain at all: a chained JSONDecodeError renders position-only, but its `.doc` is the body.
    assert exc.__cause__ is None and exc.__context__ is None


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
