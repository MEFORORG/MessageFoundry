# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample feed: submit HL7 VXU to a certificate-authenticated WS-* SOAP web service (ADR 0015).

The shape of a state-immunization-registry submission (a `submit`-style SOAP operation wrapping an
HL7 v2 VXU, over **mutual TLS** with **WS-Security**/**WS-Addressing**). It is partner-agnostic — the
endpoint, client cert/key, and credentials are environment-specific, so they come from ``env()``
(non-secret values in ``environments/<env>.toml``; secrets via ``MEFOR_VALUE_<KEY>`` env vars).

Key WS-* contract (ADR 0015): the **Handler returns only the operation ``<Body>`` fragment**; the
transport builds the ``<soap:Envelope>`` and stamps the non-deterministic ``<wsa:MessageID>`` /
``<wsu:Timestamp>`` / ``<wsse:UsernameToken>`` headers in ``send()`` (so this pure transform never
mints them). ``capture_response=True`` records the submit confirmation/error into the immutable
``response`` artifact for reconciliation (view it via ``GET /messages/{id}/responses``).

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db
"""

from html import escape

from messagefoundry import MLLP, Send, Soap, env, handler, inbound, outbound, router

# The CDC IIS WSDL operation namespace (a public standard, not a partner secret).
_IIS_NS = "urn:cdc:iisb:2011"

inbound("IB_IMMUNIZATION_VXU", MLLP(port=2620), router="immunization_router")

# WS-* SOAP submit: mutual TLS + WS-Security/WS-Addressing. WS-* requires SOAP 1.2. Secrets (cert/key/
# password/credentials) resolve via env()/MEFOR_VALUE_* — never source. Populate [egress].allowed_http.
outbound(
    "OB_IMMUNIZATION_REGISTRY",
    Soap(
        url=env("registry_url"),
        soap_version="1.2",
        soap_action=f"{_IIS_NS}:submitSingleMessage",
        client_cert_file=env("registry_client_cert"),
        client_key_file=env("registry_client_key"),
        client_key_password=env("registry_key_password"),
        ws_addressing=True,
        ws_security=True,
        ws_username=env("registry_user"),
        ws_password=env("registry_password"),
        capture_response=True,  # record the submit confirmation/error for reconciliation (ADR 0013)
    ),
)


@router("immunization_router")
def route(msg):
    # Only VXU (vaccination update) goes to the registry; anything else is UNROUTED (counted + logged).
    return ["immunization_submit_handler"] if (msg["MSH-9.1"] or "") == "VXU" else []


@handler("immunization_submit_handler")
def submit(msg):
    # Build ONLY the operation <Body> fragment (XML-escaped HL7). The transport wraps it in the envelope
    # and stamps the WS-* headers in send() — keeping this transform pure (no per-call nonce/timestamp).
    body = (
        f'<sub:submitSingleMessage xmlns:sub="{_IIS_NS}">'
        f"<sub:hl7Message>{escape(msg.encode())}</sub:hl7Message>"
        f"</sub:submitSingleMessage>"
    )
    return Send("OB_IMMUNIZATION_REGISTRY", body)
