# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1793: a password written into an HTTP-family endpoint URL must not reach a stored error.

THE DEFECT. An endpoint ``url`` carrying userinfo and no explicit port -- ``http://svc:PW@host/x``, the
ordinary shape -- never worked: urllib hands ``svc:PW@host`` to ``http.client`` as the host, which
reads ``PW@host`` as the port and raises ``InvalidURL("nonnumeric port: 'PW@host'")``. With an
explicit port the lookup fails on a host string that still holds the password. Either way urllib never
turns URL userinfo into an ``Authorization`` header. But the ``InvalidURL`` text kept the password, and
``safe_exc`` kept the text, so it reached ``queue.last_error``/``messages.error`` and the
test-connection reply (gated only by ``connections:test``).

THREE LAYERS, each tested here:

1. Construction refuses userinfo (and a port that is not a number, which is what a password holding
   an unencoded ``/`` looks like to ``urlsplit``) in every endpoint URL at least these sites read:
   REST/SOAP/FHIR/DICOMweb ``url``, the FhirLookup ``url``, ``oauth2_token_url``, ``smart_token_url``
   and ``[ai].endpoint``. The refusal names the setting and never echoes the secret.
2. ``redaction.redact`` drops the userinfo from the ``nonnumeric port`` shape, so ``safe_exc``,
   ``safe_text``, the installed log filter chain and the support-bundle redactor all lose it.
3. DICOMweb and SOAP classify an ``InvalidURL`` (send and probe) instead of letting it escape.

Synthetic values only. Nothing here opens a socket: ``http.client`` raises ``InvalidURL`` before it
connects.
"""

from __future__ import annotations

import http.client
import logging
import sys
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, OutboundConnection, Registry, WiringError
from messagefoundry.logging_setup import _install_phi_filters, _make_formatter
from messagefoundry.pipeline.wiring_runner import (
    _http_egress_allowed,
    build_check_registry,
    check_egress_allowed,
    check_fhir_lookup_allowed,
)
from messagefoundry.redaction import redact, safe_exc, safe_text
from messagefoundry.support.redact import redact_log_line
from messagefoundry.transports.ai_broker import AiBroker, AiBrokerError
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.dicomweb import DicomWebDestination
from messagefoundry.transports.fhir import FhirDestination, FhirLookupExecutor
from messagefoundry.transports.http_auth import HttpAuthError, OAuth2ClientCredentialsProvider
from messagefoundry.transports.rest import RestDestination, _redact_url
from messagefoundry.transports.smart import SmartAuthError, SmartBackendTokenProvider
from messagefoundry.transports.soap import SoapDestination
from tests.test_dicomweb import _FakeOpener

SECRET = "S3CRETPW"

#: The shapes a password takes inside an endpoint URL. Every one must be refused without echoing it.
#:
#: * ``plain`` -- the ordinary shape, and the one that raised ``nonnumeric port``.
#: * ``port`` -- an explicit port. urllib fails on DNS instead, but the password is still in the URL.
#: * ``user_only`` -- no password. Not secret, but it never works, so it is refused for the same reason.
#: * ``encoded_at`` -- ``%40`` in place of ``@``. urllib UNQUOTES the host, so it reaches
#:   ``http.client`` as ``svc:PW@host`` and leaks exactly like ``plain``.
#: * ``slash_in_pw`` -- an unencoded ``/`` in the password. ``urlsplit`` stops the authority there, so it
#:   sees no ``@`` at all and reads the password's HEAD as a port: ``nonnumeric port: 'S3CRETPW'``.
#: * ``colon_slash_in_pw`` -- the same, where the head ENDS in ``:``. ``urlsplit`` reads the port as
#:   ``S3CRETPW:``, which is not empty, so it must not pass as the empty-port form ``host:/``.
_USERINFO_SHAPES = {
    "plain": f"https://svc:{SECRET}@endpoint.example.invalid/x",
    "port": f"https://svc:{SECRET}@endpoint.example.invalid:8443/x",
    "user_only": f"https://{SECRET}@endpoint.example.invalid/x",
    "encoded_at": f"https://svc%3A{SECRET}%40endpoint.example.invalid/x",
    "slash_in_pw": f"https://svc:{SECRET}/tail@endpoint.example.invalid/x",
    "colon_slash_in_pw": f"https://svc:{SECRET}:/tail@endpoint.example.invalid/x",
}


def _dest(ctype: ConnectorType, url: str, **extra: Any) -> Destination:
    return Destination(name="OB_1793", type=ctype, settings={"url": url, **extra})


# --- 1. construction refuses a credential in an endpoint URL ----------------------------------------

_DESTINATIONS: list[tuple[str, Any]] = [
    ("REST", lambda url: RestDestination(_dest(ConnectorType.REST, url))),
    ("SOAP", lambda url: SoapDestination(_dest(ConnectorType.SOAP, url, soap_action="urn:x"))),
    ("FHIR", lambda url: FhirDestination(_dest(ConnectorType.FHIR, url))),
    ("DICOMweb", lambda url: DicomWebDestination(_dest(ConnectorType.DICOMWEB, url))),
    ("FhirLookup", lambda url: FhirLookupExecutor({"FL_1793": {"url": url}})),
]


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
@pytest.mark.parametrize(("label", "build"), _DESTINATIONS, ids=[d[0] for d in _DESTINATIONS])
def test_a_destination_refuses_a_credential_in_its_url(label: str, build: Any, shape: str) -> None:
    with pytest.raises(ValueError) as exc:
        build(_USERINFO_SHAPES[shape])
    message = str(exc.value)
    assert SECRET not in message, message
    assert "'url'" in message, message  # names the setting, so the operator knows what to fix


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_the_oauth2_token_url_refuses_a_credential(shape: str) -> None:
    with pytest.raises(HttpAuthError) as exc:
        OAuth2ClientCredentialsProvider(
            token_url=_USERINFO_SHAPES[shape], client_id="cid", client_secret="csecret"
        )
    assert SECRET not in str(exc.value)
    assert "oauth2_token_url" in str(exc.value)


def test_the_oauth2_token_url_is_refused_through_the_rest_settings_too() -> None:
    """The verifier's own shape: the token URL arrives as a REST setting, and the connector build is
    where ``check`` / dry-run / start see it."""
    with pytest.raises(ValueError) as exc:
        RestDestination(
            _dest(
                ConnectorType.REST,
                "https://api.example.invalid/x",
                oauth2_token_url=_USERINFO_SHAPES["plain"],
                oauth2_client_id="cid",
                oauth2_client_secret="csecret",
            )
        )
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_the_smart_token_url_refuses_a_credential(shape: str) -> None:
    with pytest.raises(SmartAuthError) as exc:
        SmartBackendTokenProvider(
            token_url=_USERINFO_SHAPES[shape], client_id="cid", private_key="unused-before-refusal"
        )
    assert SECRET not in str(exc.value)
    assert "smart_token_url" in str(exc.value)


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_the_ai_endpoint_refuses_a_credential(shape: str) -> None:
    with pytest.raises(AiBrokerError) as exc:
        AiBroker(
            endpoint=_USERINFO_SHAPES[shape],
            api_key="k",
            allowed_endpoints=["endpoint.example.invalid", "svc"],
        )
    assert SECRET not in str(exc.value)
    assert "[ai].endpoint" in str(exc.value)


def test_the_refusal_leaves_ordinary_urls_alone() -> None:
    """The control half. A screen that refuses every URL would pass everything above. An ``@`` in the
    PATH or QUERY is legitimate and must survive, and so must an explicit empty port, which
    ``http.client`` reads as the default port."""
    for url in (
        "https://api.example.invalid/x",
        "https://api.example.invalid:8443/x",
        "https://api.example.invalid/users/@me?who=a@b",
        "https://api.example.invalid:/x",
        "https://[::1]:8443/x",
    ):
        RestDestination(_dest(ConnectorType.REST, url))
        DicomWebDestination(_dest(ConnectorType.DICOMWEB, url))


# --- 2. the redaction layer drops the userinfo from the InvalidURL shape ------------------------------

#: The exact text ``http.client`` raises for ``http://svc:S3CRETPW@127.0.0.1/x``.
_LEAK = f"nonnumeric port: '{SECRET}@127.0.0.1'"


def test_safe_exc_drops_the_password_from_an_invalid_url() -> None:
    rendered = safe_exc(http.client.InvalidURL(_LEAK))
    assert SECRET not in rendered, rendered
    # The type and the host survive: the operator still sees what failed and where.
    assert rendered.startswith("InvalidURL: ")
    assert "@127.0.0.1" in rendered


def test_safe_text_drops_the_password() -> None:
    """The test-connection reply renders a ``DeliveryError`` through ``safe_text``, not ``safe_exc``."""
    assert SECRET not in safe_text(f"InvalidURL: {_LEAK}")


@pytest.mark.parametrize(
    "tail",
    [
        f"{SECRET}@127.0.0.1",
        f"p@{SECRET}@127.0.0.1",  # an '@' inside the password (a decoded %40): the LAST '@' ends it
        f"pa'{SECRET}@127.0.0.1",  # http.client quotes with '%s', not repr, so a quote is literal
        f"pa {SECRET}@127.0.0.1",  # a decoded %20
    ],
    ids=["plain", "at_in_pw", "quote_in_pw", "space_in_pw"],
)
def test_redact_drops_every_password_shape(tail: str) -> None:
    out = redact(f"nonnumeric port: '{tail}'")
    assert SECRET not in out, out
    assert out.endswith("@127.0.0.1'")


def test_redact_leaves_a_non_credential_invalid_url_alone() -> None:
    """The control: a bad port that carries no '@' has nothing to hide, and the diagnostic stays."""
    assert redact("nonnumeric port: 'abc'") == "nonnumeric port: 'abc'"


def test_the_redaction_is_idempotent() -> None:
    """``safe_text`` re-applies ``redact`` at the store-layer chokepoint, so it must be a fixed point."""
    once = redact(_LEAK)
    assert redact(once) == once


def test_the_support_bundle_redactor_drops_the_password() -> None:
    """``redact_log_line`` feeds the support archive and ``GET /logs/tail``. It delegates its PHI pass
    to ``redaction.redact``, which is what reaches this shape."""
    out = redact_log_line(f"2026-09-18T00:00:00Z WARNING x: internal error: InvalidURL: {_LEAK}")
    assert SECRET not in out, out


def test_the_installed_log_filter_chain_drops_the_password() -> None:
    """The write-time chain every handler carries, built by ``_install_phi_filters`` rather than listed
    here, over both the rendered message and a traceback. ``RedactionFilter`` runs first and calls
    ``redaction.redact``; the credential-label filters behind it do not know this shape."""
    try:
        raise http.client.InvalidURL(_LEAK)
    except http.client.InvalidURL:
        record = logging.LogRecord(
            "mefor.t", logging.ERROR, __file__, 1, "send failed: %s", (_LEAK,), sys.exc_info()
        )
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    for scrub in handler.filters:
        assert isinstance(scrub, logging.Filter)
        scrub.filter(record)
    rendered = _make_formatter("text").format(record)
    assert "InvalidURL" in rendered  # the traceback is really there, so the check can see it
    assert SECRET not in rendered, rendered


def test_redact_url_never_echoes_a_port_that_is_not_a_number() -> None:
    """``_redact_url`` is what every classified arm prints. A password head read as a port must not
    come back through it, and it must not RAISE there -- a raise inside an ``except`` arm escapes
    unclassified with ``urlsplit``'s own message, which quotes the port."""
    assert (
        _redact_url(f"https://svc:{SECRET}/tail@h.example.invalid/x")
        == "https://svc/tail@h.example.invalid/x"
    )
    assert _redact_url("http://127.0.0.1:abc/x") == "http://127.0.0.1/x"
    assert _redact_url("http://127.0.0.1:8080/x") == "http://127.0.0.1:8080/x"


# --- 3. DICOMweb and SOAP classify an InvalidURL instead of letting it escape --------------------------


#: A URL that constructs but that ``http.client`` refuses before connecting: a space in the path. The
#: ``InvalidURL`` it raises is REAL, not faked, and carries no credential.
_SPACE_URL = "http://127.0.0.1/dicom web"


def test_dicomweb_post_classifies_a_real_invalid_url() -> None:
    dest = DicomWebDestination(_dest(ConnectorType.DICOMWEB, _SPACE_URL))
    with pytest.raises(NegativeAckError) as exc:
        dest._post(b"\x00" * 16)
    assert exc.value.permanent is True
    assert exc.value.code == "bad-request-value"


def test_dicomweb_post_does_not_carry_an_invalid_url_message() -> None:
    dest = DicomWebDestination(_dest(ConnectorType.DICOMWEB, "http://127.0.0.1/dicomweb"))
    dest._opener = _FakeOpener(http.client.InvalidURL(_LEAK))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        dest._post(b"\x00" * 16)
    assert str(exc.value) == "DICOMweb http://127.0.0.1/dicomweb rejected an invalid request value"


async def test_dicomweb_probe_classifies_a_real_invalid_url() -> None:
    dest = DicomWebDestination(_dest(ConnectorType.DICOMWEB, _SPACE_URL))
    with pytest.raises(DeliveryError) as exc:
        await dest.test_connection()
    assert "rejected an invalid request value" in str(exc.value)


async def test_soap_send_classifies_a_real_invalid_url() -> None:
    dest = SoapDestination(_dest(ConnectorType.SOAP, "http://127.0.0.1/ws x", soap_action="urn:x"))
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("<a/>")
    assert exc.value.permanent is True
    assert exc.value.code == "bad-request-value"


async def test_soap_send_does_not_carry_an_invalid_url_message() -> None:
    dest = SoapDestination(_dest(ConnectorType.SOAP, "http://127.0.0.1/ws", soap_action="urn:x"))
    dest._opener = _FakeOpener(http.client.InvalidURL(_LEAK))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("<a/>")
    assert str(exc.value) == "SOAP http://127.0.0.1/ws rejected an invalid request value"


async def test_soap_send_classifies_a_value_error_too() -> None:
    """The arm's other limb. SOAP had neither, so a urllib ``ValueError`` escaped as well."""
    dest = SoapDestination(_dest(ConnectorType.SOAP, "http://127.0.0.1/ws", soap_action="urn:x"))
    dest._opener = _FakeOpener(ValueError("Invalid header value"))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("<a/>")
    assert exc.value.code == "bad-request-value"


async def test_soap_probe_classifies_a_real_invalid_url() -> None:
    dest = SoapDestination(_dest(ConnectorType.SOAP, "http://127.0.0.1/ws x", soap_action="urn:x"))
    with pytest.raises(DeliveryError) as exc:
        await dest.test_connection()
    assert "rejected an invalid request value" in str(exc.value)


# --- the same classification on the REST and FHIR probes and the FhirLookup read ----------------------
#
# After layer 1 no credential can reach these, so these arms classify rather than stop a leak: the
# reply names the redacted URL instead of carrying urllib's own text.


async def test_rest_probe_classifies_a_real_invalid_url() -> None:
    dest = RestDestination(_dest(ConnectorType.REST, "http://127.0.0.1/api x"))
    with pytest.raises(DeliveryError) as exc:
        await dest.test_connection()
    assert str(exc.value) == "REST http://127.0.0.1/api x rejected an invalid request value"


async def test_fhir_probe_classifies_a_real_invalid_url() -> None:
    dest = FhirDestination(_dest(ConnectorType.FHIR, "http://127.0.0.1/fhir x"))
    with pytest.raises(DeliveryError) as exc:
        await dest.test_connection()
    assert "rejected an invalid request value" in str(exc.value)


async def test_fhir_lookup_read_and_probe_classify_a_real_invalid_url() -> None:
    from messagefoundry.config.fhir_lookup import FhirLookupError

    executor = FhirLookupExecutor({"FL_1793": {"url": "http://127.0.0.1/fhir x"}})
    with pytest.raises(FhirLookupError) as exc:
        await executor.read("FL_1793", "Patient/1")
    assert "rejected an invalid request value" in str(exc.value)
    with pytest.raises(FhirLookupError) as exc:
        executor._probe("FL_1793")
    assert "rejected an invalid request value" in str(exc.value)


# --- 4. the alert webhook screens its URL and never echoes it -----------------------------------------
#
# ``[alerts].webhook_url`` is built in the app lifespan, outside the connector gate, so layer 1 never
# saw it. Its cleartext-http refusal also printed ``{url!r}``: the whole password for the userinfo
# shapes, and a Slack-style secret path token for an ordinary hook. ``redact()`` keeps both.


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_the_alert_webhook_refuses_a_credential_in_its_url(shape: str) -> None:
    from messagefoundry.pipeline.alert_sinks import WebhookTransport

    with pytest.raises(ValueError) as exc:
        WebhookTransport(_USERINFO_SHAPES[shape])
    assert SECRET not in str(exc.value), str(exc.value)
    assert "[alerts].webhook_url" in str(exc.value)


@pytest.mark.parametrize(
    "url",
    [
        f"http://svc:{SECRET}@hooks.example.invalid/x",  # the userinfo shape, over cleartext
        f"http://hooks.example.invalid/services/{SECRET}",  # a path token, which IS the credential
    ],
    ids=["userinfo", "path_token"],
)
def test_the_cleartext_webhook_refusal_never_echoes_the_url(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.pipeline.alert_sinks import WebhookTransport

    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError) as exc:
        WebhookTransport(url)
    assert SECRET not in str(exc.value), str(exc.value)
    assert "[alerts].webhook_url" in str(exc.value)


def test_the_webhook_scheme_and_allowlist_refusals_name_their_settings() -> None:
    """Neither of these echoed a credential before, since a scheme cannot hold one and the host is
    screened at construction. They name the setting so every refusal in the sink reads the same way."""
    from messagefoundry.pipeline.alert_sinks import WebhookTransport

    with pytest.raises(ValueError, match=r"\[alerts\]\.webhook_url must be http or https"):
        WebhookTransport(f"ftp://hooks.example.invalid/{SECRET}")
    sink = WebhookTransport(
        f"https://hooks.example.invalid/services/{SECRET}", allowed_hosts=("ok.example",)
    )
    with pytest.raises(ValueError) as exc:
        sink._post({"type": "t", "connection": "c"})
    assert SECRET not in str(exc.value)
    assert "[alerts].webhook_allowed_hosts" in str(exc.value)


def test_the_webhook_screen_leaves_an_ordinary_hook_alone() -> None:
    """The control half: a secret PATH token is how Slack and Teams hooks authenticate, so it must
    still construct. So must an ``@`` in the path or query."""
    from messagefoundry.pipeline.alert_sinks import WebhookTransport

    for url in (
        f"https://hooks.example.invalid/services/{SECRET}",
        "https://hooks.example.invalid:8443/x",
        "https://hooks.example.invalid/users/@me?who=a@b",
    ):
        assert WebhookTransport(url).url == url


# --- 5. the [egress] allowlist neither raises with nor echoes a credential ----------------------------
#
# ``check_egress_allowed`` runs BEFORE ``build_destination`` on every path that builds a connector:
# build-check (``check``, reload, connection upsert), test-connection, start and resume. So the
# construction refusal above never got the chance. Two leaks sat in front of it:
#
# * ``_http_egress_allowed`` read ``urlsplit(url).port``, which raises ``Port could not be cast to
#   integer value as '<head>'`` for the ``slash_in_pw`` shape once an allow entry pins a port and names
#   the parsed host. ``redact()`` does not match that text.
# * every arm echoed ``urlsplit(url).hostname`` in its refusal, and for ``encoded_at`` that hostname
#   holds the whole password.
#
# Every allowlist below lists the real host AND ``svc:443``. The pinned-port entry naming ``svc`` is
# what drove the ``slash_in_pw`` shape into the port read before the fix; it keeps these tests able to
# reproduce that leak if the screen in front of the match is ever removed.

_EGRESS_HOSTS = ["endpoint.example.invalid", "svc:443"]


def test_the_http_egress_match_never_raises_on_a_port_that_is_not_a_number() -> None:
    assert _http_egress_allowed(_USERINFO_SHAPES["slash_in_pw"], _EGRESS_HOSTS) is False
    # The control half: an ordinary URL still matches, with or without a pinned port.
    assert _http_egress_allowed("https://endpoint.example.invalid/x", _EGRESS_HOSTS) is True
    assert _http_egress_allowed("https://svc:443/x", _EGRESS_HOSTS) is True


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_the_egress_gate_refuses_a_credential_in_the_data_url(
    shape: str, caplog: pytest.LogCaptureFixture
) -> None:
    egress = EgressSettings(allowed_http=_EGRESS_HOSTS)
    with caplog.at_level(logging.DEBUG), pytest.raises(WiringError) as exc:
        check_egress_allowed(_dest(ConnectorType.REST, _USERINFO_SHAPES[shape]), egress)
    assert SECRET not in str(exc.value), str(exc.value)
    assert "'url'" in str(exc.value)
    assert SECRET not in caplog.text


@pytest.mark.parametrize("key", ["oauth2_token_url", "smart_token_url"])
@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_the_egress_gate_refuses_a_credential_in_a_token_url(
    shape: str, key: str, caplog: pytest.LogCaptureFixture
) -> None:
    egress = EgressSettings(allowed_http=_EGRESS_HOSTS)
    dest = _dest(
        ConnectorType.REST, "https://endpoint.example.invalid/v1", **{key: _USERINFO_SHAPES[shape]}
    )
    with caplog.at_level(logging.DEBUG), pytest.raises(WiringError) as exc:
        check_egress_allowed(dest, egress)
    assert SECRET not in str(exc.value), str(exc.value)
    assert key in str(exc.value)
    assert SECRET not in caplog.text


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_the_fhir_lookup_egress_gate_refuses_a_credential(
    shape: str, caplog: pytest.LogCaptureFixture
) -> None:
    egress = EgressSettings(allowed_http=_EGRESS_HOSTS)
    with caplog.at_level(logging.DEBUG), pytest.raises(WiringError) as exc:
        check_fhir_lookup_allowed("FL_1793", {"url": _USERINFO_SHAPES[shape]}, egress)
    assert SECRET not in str(exc.value), str(exc.value)
    assert "'url'" in str(exc.value)
    assert SECRET not in caplog.text


def test_the_proxy_egress_refusal_never_echoes_a_credential(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``proxy_url`` is deliberately NOT screened for userinfo: a forward proxy legitimately carries
    its own. So it gets only the two leak fixes: an unreadable port is not allowed, and a host holding
    an ``@`` once unquoted is withheld from the message instead of printed."""
    egress = EgressSettings(
        allowed_http=["endpoint.example.invalid"],
        allowed_proxy=["proxy.example.invalid:3128", "svc:3128"],
    )
    for proxy in (
        f"http://svc%3A{SECRET}%40proxy.example.invalid:3128",  # encoded_at: hostname holds it
        f"http://svc:{SECRET}/tail@proxy.example.invalid:3128",  # slash: head read as the port
    ):
        dest = _dest(ConnectorType.REST, "https://endpoint.example.invalid/x", proxy_url=proxy)
        with caplog.at_level(logging.DEBUG), pytest.raises(WiringError) as exc:
            check_egress_allowed(dest, egress)
        assert SECRET not in str(exc.value), str(exc.value)
        assert "allowed_proxy" in str(exc.value)
    assert SECRET not in caplog.text
    # The control half: the ordinary credentialed proxy shape is still accepted.
    check_egress_allowed(
        _dest(
            ConnectorType.REST,
            "https://endpoint.example.invalid/x",
            proxy_url=f"http://svc:{SECRET}@proxy.example.invalid:3128",
        ),
        egress,
    )


@pytest.mark.parametrize("shape", sorted(_USERINFO_SHAPES))
def test_build_check_never_carries_the_password(shape: str) -> None:
    """End to end on the ``messagefoundry check`` / reload path. Before the fix, ``slash_in_pw`` came
    back as ``connector build failed: Port could not be cast to integer value as 'S3CRETPW'``, and
    ``encoded_at`` as ``rest host 'svc%3AS3CRETPW%40endpoint.example.invalid' is not in ...``."""
    registry = Registry()
    registry.add_outbound(
        OutboundConnection(
            "OB_1793", ConnectionSpec(ConnectorType.REST, {"url": _USERINFO_SHAPES[shape]})
        )
    )
    with pytest.raises(WiringError) as exc:
        build_check_registry(
            registry,
            inbound_bind_host="127.0.0.1",
            env_values={},
            egress=EgressSettings(allowed_http=_EGRESS_HOSTS),
        )
    assert SECRET not in str(exc.value), str(exc.value)
