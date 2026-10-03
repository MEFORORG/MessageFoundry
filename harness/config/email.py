# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Email (SMTP) outbound graph: an MLLP entry inbound whose handler mails each message to the
harness email sink. Served with the rest of ``harness/config``; ``harness/scenarios/email.py``
drives it.

| Send this to ``IB_Harness_Email`` (2660) | Handler decision                          | Outcome          |
|------------------------------------------|-------------------------------------------|------------------|
| ADT^A31                                  | mail to ``refused@harness.invalid``       | the sink answers |
|                                          | via ``OB_Harness_Email_Rejected``         | 550 at RCPT ->   |
|                                          |                                           | dead-lettered    |
| any other ADT trigger                    | mail to ``clinic@harness.invalid`` via    | PROCESSED, and   |
|                                          | ``OB_Harness_Email``                      | one message at   |
|                                          |                                           | the sink         |
| any non-ADT type                         | router returns []                         | UNROUTED         |

**The SMTP hop is cleartext, and says so.** The sink is a loopback listener with no certificate, so
both outbounds set ``use_tls=False`` with ``cleartext_accepted`` and a written reason (ADR 0153): the
engine's own declaration for "this hop is not encrypted and that is accepted". It is not
``tls_hop_attested``, which would claim the hop is secure by other means, and it is not the
process-wide ``MEFOR_ALLOW_INSECURE_TLS`` escape. The Email outbound refuses ``use_tls=False``
without one of those three, even to loopback, which is why this graph declares it where the coverage
graph's cleartext MLLP to the same host declares nothing.

What the declaration does NOT do is confine the hop to loopback: it applies to whatever
``harness_host`` resolves to. On the default ``127.0.0.1`` the engine's cleartext guard allows the
hop silently; pointed at another host, the declaration lets it cross with a warning, even on an
enforcing instance. So never move ``harness_host`` off this machine while this graph is served, and
never point it at a real mail server.

**Egress.** ``serve`` refuses unrestricted egress, and these outbounds dial SMTP, so an instance
serving ``harness/config`` behind an allowlist lists the sink too:
``[egress].allowed_smtp = ["127.0.0.1:2661"]`` (or the port ``email_smtp`` is moved to). The
recipient list is gated as well, and that gate is deny-by-default: any instance serving this graph
needs ``[egress].allowed_recipient_domains = ["harness.invalid"]``, or neither outbound loads.

``harness/config/direct/`` is the STARTTLS + S/MIME sibling. It needs certificates minted for the
run, so it is served on its own rather than with this directory.

All data is synthetic.
"""

from messagefoundry import MLLP, Email, Send, env, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy

# Each default equals its declared entry under harness/endpoints/ (email.py for the email_* keys,
# coverage.py for `host`); tests/test_harness_scenarios.py holds them equal. Like coverage.py, this
# module imports nothing from `harness`.

_SENDER = "engine@harness.invalid"
_CLEARTEXT_REASON = (
    "harness SMTP sink with no certificate, dialled on harness_host (127.0.0.1 unless moved); "
    "synthetic test data only, never a real relay"
)

inbound(
    "IB_Harness_Email",
    MLLP(port=env("harness_email_in", default=2660, cast=int)),
    router="email_router",
)

outbound(
    "OB_Harness_Email",
    Email(
        host=env("harness_host", default="127.0.0.1"),
        port=env("harness_email_smtp", default=2661, cast=int),
        sender=_SENDER,
        recipients=["clinic@harness.invalid"],
        subject="MessageFoundry harness delivery",
        use_tls=False,
        timeout_seconds=5.0,
    ),
    cleartext_accepted=True,
    cleartext_reason=_CLEARTEXT_REASON,
    retry=RetryPolicy(
        max_attempts=3, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=2.0
    ),
)

# Same sink, a recipient the rejected-recipient scenario tells the sink to refuse. A short retry
# ceiling, because a 550 does not get better on a retry and the scenario waits on the dead letter.
outbound(
    "OB_Harness_Email_Rejected",
    Email(
        host=env("harness_host", default="127.0.0.1"),
        port=env("harness_email_smtp", default=2661, cast=int),
        sender=_SENDER,
        recipients=["refused@harness.invalid"],
        subject="MessageFoundry harness delivery (refused recipient)",
        use_tls=False,
        timeout_seconds=5.0,
    ),
    cleartext_accepted=True,
    cleartext_reason=_CLEARTEXT_REASON,
    retry=RetryPolicy(
        max_attempts=2, backoff_seconds=0.5, backoff_multiplier=1.0, max_backoff_seconds=0.5
    ),
)


@router("email_router")
def route_email(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # logged UNROUTED, never dropped
    return ["email_handler"]


@handler("email_handler")
def mail(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.2"] == "A31":
        return Send("OB_Harness_Email_Rejected", msg)
    return Send("OB_Harness_Email", msg)
