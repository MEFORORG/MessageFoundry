# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/http.py``: the Http inbounds and the four HTTP-family outbounds.

The outbound ports are where a harness HTTP sink listens. The graph reads each one as
``env("harness_<key>")`` and turns it into ``http://127.0.0.1:<port><path>``: always loopback,
because a sink binds nothing else (``harness.sinks.LOOPBACK``), so the ``host`` endpoint, which is
what a DRIVER dials, plays no part in an outbound URL. A graph may not import this module, so it
repeats the defaults and paths below as literals; ``tests/test_harness_http.py`` holds the two
equal."""

from __future__ import annotations

from harness.endpoints import PORT, Endpoint

ENDPOINTS = (
    Endpoint("http_in", PORT, "2590", "IB_Http_HL7: the Http inbound taking HL7 v2 over POST"),
    Endpoint(
        "http_dicom_in", PORT, "2591", "IB_Http_DICOM: the Http inbound taking a DICOM Part-10 POST"
    ),
    Endpoint("http_rest", PORT, "2592", "OB_Http_Rest: the REST outbound's peer (a harness sink)"),
    Endpoint("http_soap", PORT, "2593", "OB_Http_Soap: the SOAP outbound's peer (a harness sink)"),
    Endpoint("http_fhir", PORT, "2594", "OB_Http_FHIR: the FHIR outbound's peer (a harness sink)"),
    Endpoint(
        "http_dicomweb",
        PORT,
        "2595",
        "OB_Http_DICOMweb: the DICOMweb STOW-RS outbound's peer (a harness sink)",
    ),
)

#: The URL paths the graph's destinations use, shared with the scenarios that assert them. The FHIR
#: and DICOMweb entries are the BASE paths: the engine appends ``/{resourceType}`` (a FHIR create)
#: and ``/studies`` (a STOW-RS store) to them.
REST_PATH = "/rest/adt"
SOAP_PATH = "/soap/HarnessService"
FHIR_BASE_PATH = "/fhir"
DICOMWEB_BASE_PATH = "/dicom-web"

#: The SOAPAction the SOAP outbound declares (SOAP 1.1 sends it quoted in a ``SOAPAction`` header).
SOAP_ACTION = "urn:messagefoundry:harness:Notify"
