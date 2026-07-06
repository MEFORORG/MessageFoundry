# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tolerant FHIR *peek* — cheap routing-field extraction (the HL7
:class:`~messagefoundry.parsing.peek.Peek` / X12 :class:`~messagefoundry.parsing.x12.peek.X12Peek`
analog for FHIR).

Routing must never force a full validated parse, so :class:`FhirPeek` does a **shallow read of the
parsed JSON object** — ``resourceType`` (the FHIR analog of HL7 MSH-9), ``id``, ``meta.profile[]``
(the conformance profiles a Router most often branches on), and, for a ``Bundle``, ``Bundle.type`` and
the **list** of ``entry[].resource.resourceType`` — without constructing the typed
:mod:`fhir.resources` model. The peek is **version-agnostic**: those structural fields are stable across
R5/R4B/STU3, so routing needs no version selection (full model construction does — see
:class:`~messagefoundry.parsing.fhir.resource.FhirResource`).

A ``Bundle`` fans out: :meth:`entry_resource_types` returns the **full list** (returning only the first
would silently mis-route a multi-entry Bundle, the same trap :meth:`X12Peek.groups` warns about). It
tolerates request-only entries (a transaction/batch entry may carry only ``request.method``/``url`` —
e.g. a conditional ``DELETE`` — so a missing inline ``resource`` is skipped, never a ``KeyError``).

Pure: works on ``str`` (or ``bytes``, decoded UTF-8/replace), no I/O, no engine imports. The bare
structural accessors need **no** dependency; only :meth:`evaluate` (FHIRPath) pulls the optional
``[fhir]`` extra. The content type is referred to by the literal string ``"fhir"`` (never imported from
``config``) to keep this purity. **JSON-FHIR is the MVP**; FHIR-XML is deferred (ADR 0022 Options #5).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from messagefoundry.parsing.fhir._deps import load_fhirpathpy
from messagefoundry.parsing.fhir.errors import FhirPeekError

__all__ = ["FhirPeek"]


def _detect_format(raw: str) -> str:
    """Cheap serialization sniff: a body whose first non-whitespace char is ``<`` is XML, else JSON."""
    stripped = raw.lstrip("﻿ \t\r\n")
    return "xml" if stripped.startswith("<") else "json"


@dataclass(frozen=True)
class FhirPeek:
    """A tolerant view over one FHIR resource exposing routing fields. Construct via :meth:`parse`.

    ``obj`` is the parsed JSON object; ``format`` is the detected/declared serialization (``"json"``)."""

    obj: dict[str, Any]
    format: str = "json"

    @classmethod
    def parse(cls, raw: str | bytes, *, format: str | None = None) -> FhirPeek:
        """Peek the FHIR resource in ``raw``.

        Raises :class:`FhirPeekError` if the body is not parseable FHIR JSON (not JSON, or not a resource
        *object*), or if it is FHIR-XML (deferred to a hardened path; JSON-only MVP per ADR 0022)."""
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw).decode("utf-8", "replace")
        raw = raw.lstrip("﻿")  # tolerate a leading UTF-8 BOM (json.loads would otherwise choke)
        fmt = _detect_format(raw) if format is None else format
        if fmt != "json":
            raise FhirPeekError(
                f"FHIR {fmt!r} peek is not supported in the MVP (JSON only; ADR 0022 Options #5)"
            )
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            # PHI rule: name the failure, never echo the body.
            raise FhirPeekError("body is not parseable FHIR JSON") from exc
        if not isinstance(parsed, dict):
            raise FhirPeekError("FHIR JSON body must be a resource object, not a scalar/array")
        return cls(obj=parsed, format=fmt)

    @property
    def resource_type(self) -> str | None:
        """The top-level ``resourceType`` discriminator (the FHIR analog of MSH-9), or None."""
        value = self.obj.get("resourceType")
        return value if isinstance(value, str) and value else None

    @property
    def id(self) -> str | None:
        """The resource ``id`` (logical id), or None."""
        value = self.obj.get("id")
        return value if isinstance(value, str) and value else None

    @property
    def profiles(self) -> tuple[str, ...]:
        """``meta.profile[]`` — the conformance profile URLs (e.g. a US Core profile), possibly empty."""
        meta = self.obj.get("meta")
        if not isinstance(meta, dict):
            return ()
        profile = meta.get("profile")
        if not isinstance(profile, list):
            return ()
        return tuple(p for p in profile if isinstance(p, str) and p)

    @property
    def bundle_type(self) -> str | None:
        """``Bundle.type`` (``transaction``/``batch``/``message``/``searchset``/…) when this is a Bundle."""
        if self.resource_type != "Bundle":
            return None
        value = self.obj.get("type")
        return value if isinstance(value, str) and value else None

    def entry_resource_types(self) -> list[str]:
        """Every ``entry[].resource.resourceType`` in a Bundle, in order — the **full list** (a Bundle
        fans out). Entries with no inline ``resource`` (request-only, e.g. a conditional delete) are
        skipped. Empty for a non-Bundle or an empty Bundle."""
        entries = self.obj.get("entry")
        if not isinstance(entries, list):
            return []
        out: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            resource = entry.get("resource")
            if isinstance(resource, dict):
                rtype = resource.get("resourceType")
                if isinstance(rtype, str) and rtype:
                    out.append(rtype)
        return out

    def entry_requests(self) -> list[tuple[str, str]]:
        """Every ``entry[].request`` ``(method, url)`` pair in a Bundle (the request-only entries a
        transaction/batch carries — e.g. ``("DELETE", "Patient?identifier=…")``). Empty otherwise."""
        entries = self.obj.get("entry")
        if not isinstance(entries, list):
            return []
        out: list[tuple[str, str]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            request = entry.get("request")
            if isinstance(request, dict):
                method = request.get("method")
                url = request.get("url")
                if isinstance(method, str) and isinstance(url, str):
                    out.append((method, url))
        return out

    def evaluate(self, path: str) -> list[Any]:
        """Evaluate a FHIRPath expression against the raw object (e.g.
        ``Bundle.entry.resource.ofType(MessageHeader).event.code``) for richer routing without a typed
        parse. Requires the optional ``[fhir]`` extra (``fhirpathpy``); raises :class:`RuntimeError` if
        it is absent."""
        evaluator = load_fhirpathpy()
        return list(evaluator(self.obj, path, {}))
