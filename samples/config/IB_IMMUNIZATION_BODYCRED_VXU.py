# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample feed: submit HL7 VXU to a registry that takes credentials in the operation **body**.

The sibling of ``IB_IMMUNIZATION_VXU.py``. That one authenticates with a WS-Security ``UsernameToken``
**header** (ADR 0015) — **prefer it** whenever the service accepts a header. This sample is for the
other case: a CDC-IIS-style ``submitSingleMessage`` whose WSDL takes username/password/facility as
**elements of the ``<Body>``**, where a header cannot carry them (ADR 0015 amendment, BACKLOG #236).

The point of ``body_secrets`` is that **the credential never enters the message**. The Handler emits
opaque high-entropy **placeholder tokens** where the credentials go — staying pure, never holding a
secret — and the transport substitutes the ``env()``-resolved values in ``send()``, after the payload
leaves the store and before it hits the wire. So the stored outbound/done/dead-letter rows, a replayed
body, and ``dryrun`` output all contain only the tokens.

Everything is environment-specific and comes from ``env()`` (non-secret values in
``environments/<env>.toml``; secrets via ``MEFOR_VALUE_<KEY>`` env vars). No PHI, no real endpoint.

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db
"""

from html import escape

from messagefoundry import MLLP, Send, Soap, env, handler, inbound, outbound, router

# The CDC IIS WSDL operation namespace (a public standard, not a partner secret).
_IIS_NS = "urn:cdc:iisb:2011"

# The placeholder tokens the Handler emits and the transport substitutes. They are NOT secret — a
# placeholder is public by nature (it lives here, in committed source). High-entropy + distinct so a
# real HL7 body can't collide with one; keep them >= 16 chars (the factory enforces the shape).
_TOK_USER = "MF_IIS_USER_9f2c41ab3d7e"
_TOK_PASSWORD = "MF_IIS_PW_5b1d90ee0a11f7"
_TOK_FACILITY = "MF_IIS_FAC_2c7e0143bd96"

inbound("IB_IMMUNIZATION_BODYCRED_VXU", MLLP(port=2621), router="bodycred_router")

# Body-credential submit. NOTE the WSDL check: if this service accepted a WS-Security UsernameToken
# header, IB_IMMUNIZATION_VXU.py (ws_security=True) would be the right sample and body_secrets would be
# unnecessary. Populate [egress].allowed_http for the host. Secrets resolve via env()/MEFOR_VALUE_* —
# never inline, and body_secrets is code-first only (no connections.toml form).
outbound(
    "OB_IMMUNIZATION_BODYCRED",
    Soap(
        url=env("registry_url"),
        soap_action=f"{_IIS_NS}:submitSingleMessage",
        capture_response=True,  # record the submit confirmation/error for reconciliation (ADR 0013)
        body_secrets={
            _TOK_USER: env("registry_user"),
            _TOK_PASSWORD: env("registry_password"),
            _TOK_FACILITY: env("registry_facility"),
        },
    ),
)


@router("bodycred_router")
def route(msg):
    # Only VXU (vaccination update) goes to the registry; anything else is UNROUTED (counted + logged).
    return ["bodycred_submit_handler"] if (msg["MSH-9.1"] or "") == "VXU" else []


@handler("bodycred_submit_handler")
def submit(msg):
    # Build the operation <Body> with the credential PLACEHOLDER TOKENS, never the real credentials — the
    # transport swaps each token for its env() secret in send(). This transform stays pure (no secret,
    # no per-call state). Each token must appear EXACTLY ONCE or the transport fails closed (nothing is
    # sent) — so emit them unconditionally, not inside a branch.
    body = (
        f'<sub:submitSingleMessage xmlns:sub="{_IIS_NS}">'
        f"<sub:username>{_TOK_USER}</sub:username>"
        f"<sub:password>{_TOK_PASSWORD}</sub:password>"
        f"<sub:facilityID>{_TOK_FACILITY}</sub:facilityID>"
        f"<sub:hl7Message>{escape(msg.encode())}</sub:hl7Message>"
        f"</sub:submitSingleMessage>"
    )
    return Send("OB_IMMUNIZATION_BODYCRED", body)
