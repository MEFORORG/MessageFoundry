# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Direct (S/MIME over SMTP) outbound graph: an MLLP entry inbound whose handler sends each message
as a Direct message to the harness email sink, over STARTTLS.

**Served on its own, never with ``harness/config``.** A ``Direct`` outbound loads and checks its
signing key, its partner's certificate and both trust anchors when it is BUILT, so this graph cannot
build until certificates exist for the run, and a top-level graph that could not build would break
``serve`` and ``check`` for every other family. The loader reads only top-level ``*.py``, so this
subdirectory stays out of ``serve --config harness/config``. ``tests/test_harness_email.py`` mints
synthetic trust material, serves this directory, and asserts what the sink received::

    python -m messagefoundry serve --config harness/config/direct --env dev --db ./direct.db

with these engine environment values set (``MEFOR_VALUE_<KEY>``): ``direct_signing_cert`` /
``direct_signing_key`` (the sender's S/MIME pair), ``direct_recipient_cert`` (the partner's RSA
encryption certificate), ``direct_trust_anchor`` (the CA that issued it), and ``direct_relay_ca``
(the CA the SMTP relay's TLS certificate chains to). None has a default, so a missing one refuses
the load rather than reading a blank. Never commit key material, and never point this graph at a
real HISP.

It reuses the email graph's two endpoint keys, ``email_in`` and ``email_smtp``, with the same
defaults, so it is not meant to run while ``harness/config`` is being served: two engines on the
defaults contend for 2660. Move ``MEFOR_VALUE_HARNESS_EMAIL_IN`` (and ``_EMAIL_SMTP``) to run both.

**Egress.** A Direct outbound is gated by ``[egress].allowed_direct``, not ``allowed_smtp``, so an
instance serving this graph behind an allowlist lists ``allowed_direct = ["127.0.0.1:2661"]``.

The hop is the engine's default posture, not a weakened one: STARTTLS with the relay certificate
verified against ``direct_relay_ca`` and checked against the host name. All data is synthetic.
"""

from messagefoundry import MLLP, Direct, Send, env, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy

inbound(
    "IB_Harness_Direct",
    MLLP(port=env("harness_email_in", default=2660, cast=int)),
    router="direct_router",
)

outbound(
    "OB_Harness_Direct",
    Direct(
        host=env("harness_host", default="127.0.0.1"),
        port=env("harness_email_smtp", default=2661, cast=int),
        sender="engine@direct.harness.invalid",
        recipients=["partner@direct.harness.invalid"],
        subject="MessageFoundry harness Direct delivery",
        signing_cert=env("direct_signing_cert"),
        signing_key=env("direct_signing_key"),
        recipient_cert=env("direct_recipient_cert"),
        trust_anchor=env("direct_trust_anchor"),
        tls_ca_file=env("direct_relay_ca"),
        timeout_seconds=5.0,
    ),
    retry=RetryPolicy(
        max_attempts=3, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=2.0
    ),
)


@router("direct_router")
def route_direct(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # logged UNROUTED, never dropped
    return ["direct_handler"]


@handler("direct_handler")
def send_direct(msg):  # type: ignore[no-untyped-def]
    return Send("OB_Harness_Direct", msg)
