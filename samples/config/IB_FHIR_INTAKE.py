# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample route: ingest FHIR resources (JSON) and deliver them to a FHIR server (ADR 0022).

The inbound declares ``content_type="fhir"`` so each body routes as a ``RawMessage`` (ADR 0004); the
Router peeks the ``resourceType`` with the pure ``messagefoundry.parsing.fhir`` codec — a cheap shallow
read, no typed parse, no ``[fhir]`` extra needed on the hot path. The Handler validates the resource
against FHIR R4B (a non-conformant resource raises → ERROR/dead-letter, the count-and-log invariant) and
delivers the canonical JSON to a FHIR server with the ``FHIR()`` destination. The server is
environment-specific, so it's authored with ``env()`` (resolved from ``environments/<env>.toml``).

A real HL7 v2 → FHIR route would do the same, with the Handler mapping a python-hl7 ``Message`` into a
``fhir.resources`` resource before ``Send`` — the mapping stays code-first here, never in the connector.

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db

The Handler's typed validation needs the optional extra: ``pip install 'messagefoundry[fhir]'`` (the
Router's peek does not). See ``samples/messages/`` for a synthetic FHIR Patient to drop in ``./in/fhir``.
"""

from messagefoundry import FHIR, ContentType, File, Send, env, handler, inbound, outbound, router
from messagefoundry.parsing.fhir import FhirPeek, FhirResource

inbound(
    "IB_FHIR_INTAKE",
    File(directory="./in/fhir", pattern="*.json"),
    router="fhir_router",
    content_type=ContentType.FHIR,
)
# A FHIR REST destination. ``url`` is the service BASE (e.g. https://host/fhir); ``interaction="create"``
# POSTs each resource to {base}/{ResourceType}. A SMART/OAuth deployment adds
# ``bearer_token=env("fhir_bearer_token")`` (a secret → MEFOR_VALUE_FHIR_BEARER_TOKEN). For idempotent
# re-sends, set interaction="update" (PUT by id) or a conditional knob (if-none-exist / conditional-update
# / if-match) — see docs/CONNECTIONS.md.
outbound("OB_FHIR_SERVER", FHIR(url=env("fhir_base_url"), interaction="create"))


@router("fhir_router")
def route(msg):
    # content_type="fhir" → msg is a RawMessage. A body that isn't a FHIR JSON object at all (e.g. a
    # mis-dropped file) is UNROUTED — still counted + logged, never an error. A body that looks like
    # JSON but is malformed lets FhirPeek.parse raise below → ERROR/dead-letter (count-and-log).
    if not msg.raw.lstrip().startswith("{"):
        return []
    peek = FhirPeek.parse(msg.raw)  # cheap shallow read, no [fhir] extra
    if peek.resource_type in ("Patient", "Observation"):
        return ["fhir_handler"]
    return []  # other resource types are UNROUTED here (still counted + logged)


@handler("fhir_handler")
def handle(msg):
    # Validate against R4B before delivery (a non-conformant resource raises → ERROR/dead-letter), then
    # forward the canonical JSON. An HL7 v2 → FHIR mapping would also live here, code-first.
    resource = FhirResource.parse(msg.raw, version="R4B")
    return Send("OB_FHIR_SERVER", resource.encode())
