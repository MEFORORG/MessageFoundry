# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""HTTP family graph: an ``Http`` inbound for HL7 v2 and one for DICOM, feeding the four HTTP-family
outbounds (REST, SOAP, FHIR, DICOMweb), each aimed at a harness HTTP sink on loopback.

Ports come from ``env("harness_<endpoint key>")``, so ``MEFOR_VALUE_HARNESS_<KEY>`` moves one; each
default is the one ``harness/endpoints/http.py`` declares, and the paths are the ones it exports
(``tests/test_harness_http.py`` holds the two files together, since a graph may not import the
harness). An outbound's env value is the sink's PORT; the graph turns it into the loopback URL. The
routing is by message type, on this family's own routers, so no other family's traffic reaches it:

| POST this to ``http_in``    | Delivered as                                    | Outbound      |
|-----------------------------|-------------------------------------------------|---------------|
| ADT (any trigger)           | JSON ``POST /rest/adt``                         | OB_Http_Rest  |
| ORM (any trigger)           | SOAP 1.1 envelope ``POST /soap/HarnessService`` | OB_Http_Soap  |
| ORU (any trigger)           | FHIR Patient create ``POST /fhir/Patient``      | OB_Http_FHIR  |
| any other type              | routed nowhere                                  | (UNROUTED)    |

A DICOM Part-10 object POSTed to ``http_dicom_in`` is stored, unchanged, by a STOW-RS
``POST /dicom-web/studies`` framed ``multipart/related; type="application/dicom"``.

Every body carries the message's control id (MSH-10) so a sink can match it to the run that sent it;
none carries patient fields. Each outbound retries a 5xx on a fast policy and then dead-letters,
which is what the dead-letter scenarios drive by having the sink answer 503.

**Egress.** These outbounds are gated by ``[egress].allowed_http``. ``serve`` turns
``[security].block_unlisted_outbound`` on when it is unset, and then an empty ``allowed_http``
refuses all four at start (each is isolated as ``failed``; the engine runs on). Allow the loopback
host the supported way: ``[egress] allowed_http = ["127.0.0.1"]`` in the settings file, or
``MEFOR_EGRESS_ALLOWED_HTTP=127.0.0.1``. The harness tests serve this graph with that list set.

All data is synthetic; never point a real PHI feed at a sample config.
"""

import json
from html import escape

from messagefoundry import (
    FHIR,
    DICOMweb,
    Http,
    Rest,
    RetryPolicy,
    Send,
    Soap,
    env,
    handler,
    inbound,
    outbound,
    router,
)
from messagefoundry.config.wiring import EnvRef


class _LoopbackUrl:
    """An ``env()`` cast: the sink's port, as the environment gives it, to the loopback URL.

    The default each ``env()`` below carries is this cast applied to the endpoint's default port,
    since the engine does not cast a default. Harness sinks always bind loopback, so the host is
    fixed."""

    __name__ = "port"  # what the engine names when a value fails this cast

    def __init__(self, path: str) -> None:
        self.path = path

    # Compared by value, and across two loads of this module (each load defines a new class), so a
    # no-op reload does not read the four outbounds as changed and rebuild them.
    def __eq__(self, other: object) -> bool:
        return type(other).__qualname__ == type(self).__qualname__ and (
            getattr(other, "path", None) == self.path
        )

    def __hash__(self) -> int:
        return hash((type(self).__qualname__, self.path))

    def __call__(self, raw: object) -> str:
        port = int(str(raw))
        if not 0 < port < 65536:
            raise ValueError("port out of range")
        return f"http://127.0.0.1:{port}{self.path}"


def _sink_url(key: str, default_port: int, path: str) -> EnvRef:
    to_url = _LoopbackUrl(path)
    return env(f"harness_{key}", default=to_url(default_port), cast=to_url)


#: Fast enough that a 5xx peer dead-letters inside a scenario's timeout, slow enough that the sink
#: sees each retry as its own request.
_FAST_RETRY = RetryPolicy(
    max_attempts=3, backoff_seconds=0.3, backoff_multiplier=1.0, max_backoff_seconds=0.5
)

inbound(
    "IB_Http_HL7", Http(port=env("harness_http_in", default=2590, cast=int)), router="http_router"
)
inbound(
    "IB_Http_DICOM",
    Http(port=env("harness_http_dicom_in", default=2591, cast=int)),
    router="http_dicom_router",
    content_type="dicom",
)

outbound(
    "OB_Http_Rest",
    Rest(url=_sink_url("http_rest", 2592, "/rest/adt"), timeout_seconds=5.0),
    retry=_FAST_RETRY,
)
outbound(
    "OB_Http_Soap",
    Soap(
        url=_sink_url("http_soap", 2593, "/soap/HarnessService"),
        soap_action="urn:messagefoundry:harness:Notify",
        timeout_seconds=5.0,
    ),
    retry=_FAST_RETRY,
)
outbound(
    "OB_Http_FHIR",
    FHIR(url=_sink_url("http_fhir", 2594, "/fhir"), timeout_seconds=5.0),
    retry=_FAST_RETRY,
)
outbound(
    "OB_Http_DICOMweb",
    DICOMweb(url=_sink_url("http_dicomweb", 2595, "/dicom-web"), timeout_seconds=5.0),
    retry=_FAST_RETRY,
)


@router("http_router")
def route(msg):  # type: ignore[no-untyped-def]
    # Literal handler names, not a lookup table, so `messagefoundry check` sees every reference.
    kind = msg["MSH-9.1"]
    if kind == "ADT":
        return ["http_rest"]
    if kind == "ORM":
        return ["http_soap"]
    if kind == "ORU":
        return ["http_fhir"]
    return []  # anything else is logged UNROUTED, never dropped


@router("http_dicom_router")
def route_dicom(msg):  # type: ignore[no-untyped-def]
    return ["http_dicomweb"]


@handler("http_rest")
def to_rest(msg):  # type: ignore[no-untyped-def]
    body = {"control_id": msg["MSH-10"], "message_type": f"{msg['MSH-9.1']}^{msg['MSH-9.2']}"}
    return Send("OB_Http_Rest", json.dumps(body, sort_keys=True))


def _xml_text(value: object) -> str:
    """``value`` as XML 1.0 character data: escaped, with the C0 controls XML forbids dropped."""
    text = "" if value is None else str(value)
    # html.escape with quote=False escapes exactly &, < and >, as xml.sax.saxutils.escape does, without
    # importing the xml package (tests/test_security_static.py confines XML parse surfaces).
    return escape("".join(c for c in text if c >= " " or c in "\t\n\r"), quote=False)


@handler("http_soap")
def to_soap(msg):  # type: ignore[no-untyped-def]
    # The values are untrusted message content: escaped, and stripped of the control characters XML
    # 1.0 forbids, so a field can neither reshape the envelope nor make it ill-formed.
    envelope = (
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soap:Body>"
        '<h:Notify xmlns:h="urn:messagefoundry:harness">'
        f"<h:ControlId>{_xml_text(msg['MSH-10'])}</h:ControlId>"
        f"<h:MessageType>{_xml_text(msg['MSH-9.1'])}^{_xml_text(msg['MSH-9.2'])}</h:MessageType>"
        "</h:Notify>"
        "</soap:Body>"
        "</soap:Envelope>"
    )
    return Send("OB_Http_Soap", envelope)


@handler("http_fhir")
def to_fhir(msg):  # type: ignore[no-untyped-def]
    patient = {
        "resourceType": "Patient",
        "identifier": [{"system": "urn:messagefoundry:harness:control-id", "value": msg["MSH-10"]}],
    }
    return Send("OB_Http_FHIR", json.dumps(patient, sort_keys=True))


@handler("http_dicomweb")
def to_dicomweb(msg):  # type: ignore[no-untyped-def]
    return Send("OB_Http_DICOMweb", msg)  # the Part-10 object, forwarded unchanged
