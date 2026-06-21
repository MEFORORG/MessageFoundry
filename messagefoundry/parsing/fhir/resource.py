# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The full, validated FHIR resource model for transforms — the strict/slow path (the HL7
:class:`~messagefoundry.parsing.message.Message` / X12
:class:`~messagefoundry.parsing.x12.message.X12Message` analog).

:meth:`FhirResource.parse` constructs and **validates** a typed :mod:`fhir.resources` resource (raising
on non-conformant structure/cardinality — local pydantic-v2 schema work, **zero terminology-server
calls**, offline + PHI-safe). It is **not** the hot path — a Router routes on the cheap
:class:`~messagefoundry.parsing.fhir.peek.FhirPeek`; ``FhirResource`` is built on demand inside a
Handler. The typed model (:attr:`model`) is read/set by attribute, FHIRPath read via :meth:`evaluate`,
and re-serialized with :meth:`encode`.

The FHIR **version** is an explicit per-connection choice (default ``"R4B"`` — the pydantic-v2 wheels
ship R5/R4B/STU3, not plain R4; ``"R5"``/``"STU3"`` opt-in), mirroring CLAUDE.md §8's "be explicit about
the version" rule. **JSON is the MVP**; FHIR-XML is deferred (ADR 0022 Options #5).

Pure: no I/O, no engine imports, no network. The typed library (``fhir.resources``) is lazily loaded
from the optional ``[fhir]`` extra, so importing this module needs neither the extra nor the engine.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from messagefoundry.parsing.fhir._deps import _SUPPORTED_VERSIONS, load_get_fhir_model_class
from messagefoundry.parsing.fhir.errors import FhirError, FhirValidationError

__all__ = ["FhirResource"]


def _safe_validation_summary(resource_type: str, version: str, exc: ValidationError) -> str:
    """A **PHI-safe** one-line summary of a pydantic validation failure: the resourceType, version, and
    the offending field *locations* + error *types* only — never the input *values* (which are PHI)."""
    errors = exc.errors(include_url=False)
    shown = "; ".join(
        ".".join(str(part) for part in err.get("loc", ())) + f" ({err.get('type', '?')})"
        for err in errors[:5]
    )
    more = "" if len(errors) <= 5 else f" (+{len(errors) - 5} more)"
    return (
        f"FHIR {resource_type} ({version}) failed validation: {len(errors)} error(s): {shown}{more}"
    )


class FhirResource:
    """A parsed + validated FHIR resource. Read/mutate the typed :attr:`model`, then :meth:`encode`."""

    def __init__(self, model: Any, *, version: str, resource_type: str) -> None:
        self._model = model
        self._version = version
        self._resource_type = resource_type

    @classmethod
    def parse(cls, raw: str | bytes, *, version: str = "R4B", format: str = "json") -> FhirResource:
        """Parse + validate ``raw`` into a typed model for ``version`` (default ``"R4B"``).

        Raises :class:`FhirValidationError` if the body is not parseable FHIR JSON, lacks a
        ``resourceType``, names an unknown resource, or violates the model's structure/cardinality;
        :class:`FhirError` for an unsupported ``version``/``format``; :class:`RuntimeError` if the
        ``[fhir]`` extra is not installed."""
        if version not in _SUPPORTED_VERSIONS:
            raise FhirError(
                f"unsupported fhir_version {version!r}; expected one of {', '.join(_SUPPORTED_VERSIONS)}"
            )
        if format != "json":
            raise FhirError(
                f"FHIR {format!r} is not supported in the MVP (JSON only; ADR 0022 Options #5)"
            )
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw).decode("utf-8", "replace")
        raw = raw.lstrip("﻿")  # tolerate a leading UTF-8 BOM (json.loads would otherwise choke)
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise FhirValidationError("body is not parseable FHIR JSON") from exc
        if not isinstance(data, dict):
            raise FhirValidationError(
                "FHIR JSON body must be a resource object, not a scalar/array"
            )
        resource_type = data.get("resourceType")
        if not isinstance(resource_type, str) or not resource_type:
            raise FhirValidationError("FHIR resource is missing a string 'resourceType'")

        get_model_class = load_get_fhir_model_class(version)
        try:
            model_class = get_model_class(resource_type)
        except (ValueError, KeyError) as exc:
            # resourceType is a routing-safe token — never the body.
            raise FhirValidationError(
                f"unknown FHIR resourceType {resource_type!r} for version {version}"
            ) from exc
        try:
            model = model_class.model_validate(data)
        except ValidationError as exc:
            # `from None`: a pydantic ValidationError carries the offending input values (PHI) in its
            # message/__cause__ — sever the chain and surface only the PHI-safe summary.
            raise FhirValidationError(
                _safe_validation_summary(resource_type, version, exc)
            ) from None
        return cls(model=model, version=version, resource_type=resource_type)

    @property
    def model(self) -> Any:
        """The underlying typed :mod:`fhir.resources` (pydantic-v2) model — read/set FHIR elements by
        attribute (e.g. ``res.model.name[0].family``) inside a Handler."""
        return self._model

    @property
    def resource_type(self) -> str:
        """The resource type (e.g. ``"Patient"``, ``"Bundle"``)."""
        return self._resource_type

    @property
    def version(self) -> str:
        """The FHIR version this resource was validated against (``"R4B"``/``"R5"``/``"STU3"``)."""
        return self._version

    @property
    def id(self) -> str | None:
        """The resource ``id`` (logical id), or None."""
        value = getattr(self._model, "id", None)
        return value if isinstance(value, str) and value else None

    def evaluate(self, path: str) -> list[Any]:
        """Evaluate a FHIRPath expression against this resource. Requires the optional ``[fhir]`` extra
        (``fhirpathpy``)."""
        from messagefoundry.parsing.fhir._deps import load_fhirpathpy

        evaluator = load_fhirpathpy()
        return list(evaluator(self.as_dict(), path, {}))

    def as_dict(self) -> dict[str, Any]:
        """The validated resource as a plain JSON-compatible dict (drops absent/empty elements)."""
        obj = json.loads(self.encode())
        return obj if isinstance(obj, dict) else {}

    def encode(self, *, format: str = "json") -> str:
        """Re-serialize the validated resource. JSON only at MVP; ``format="xml"`` is deferred."""
        if format != "json":
            raise FhirError(
                f"FHIR {format!r} serialization is deferred (JSON only; ADR 0022 Options #5)"
            )
        return str(self._model.model_dump_json())

    def __str__(self) -> str:
        return self.encode()
