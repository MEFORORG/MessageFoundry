# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""What binds an outbound token-endpoint credential to its destination, and what does not.

BACKLOG #1158 records an asymmetry between the two outbound OAuth2 legs: the SMART provider signs a
``client_assertion`` whose ``aud`` is the pinned token endpoint, while its symmetric sibling sends a
reusable ``client_secret`` with nothing tying it to a destination. That is true at HEAD, and this
module is the instrument that says so, because the row's reading of it invites a fix that would not
close it.

**Every test here is a change detector with a stated reason.** A red is not automatically a defect --
it means one of the five facts below moved, and the ledger row rests on all five. Read the failing
test's own docstring, then amend the row.

1. The SMART assertion carries ``aud`` = the pinned token endpoint. The binding exists.
2. The OAuth2 client-credentials provider transmits the raw secret and carries no audience claim of
   any kind, under both ``basic`` and ``post``. The gap exists.
3. The asymmetric binding already composes onto a plain ``Rest()`` outbound, and what it puts on the
   wire is a generic RFC 7523 section 2.2 ``private_key_jwt`` exchange carrying no SMART-only field.
   The remedy the row asks for is shipped; it is only named ``smart_*``.
4. No per-connection auth mode reaches ``connections.toml`` -- SMART, OAuth2-CC and Digest are all
   refused there. "Reachable from both surfaces" is a property none of them has, so it is not a bar a
   new auth style would be the first to miss.

A **fifth fact carries the refusal and is deliberately NOT re-asserted here**:
:class:`~messagefoundry.config.models.SignatureAlgorithm` admits no HMAC member and no ``none``, which
``transports/signing.py`` names as what makes an RS256-to-HS256 confusion inexpressible on the
attacker-reachable ``verify_compact_jws`` path. So reaching ``client_secret_jwt`` means either widening
that enum or standing up a second JWT minter beside the audited one, and that is the cost this row's
destination-binding limb declined to pay. The invariant already has an owner --
``tests/test_compact_jws_verify.py::test_none_and_hs_are_absent_from_the_enum``, whose docstring calls
it "a property of config/models.py" for the same reason. A second copy here would be a silently
different definition of one rule, so this module points at it instead.

Nothing here hits the network: the provider's opener is replaced with a recorder, as
``test_http_auth.py`` and ``test_smart_backend.py`` already do. Each fake ``read`` takes an optional
``amt`` so it answers a bounded socket read and a bare one identically -- the providers' response read
is being narrowed on another branch, and a fake that only answers the older call shape would red on
the merge rather than on a real regression.
"""

from __future__ import annotations

import base64
import json
import textwrap
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Literal

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.config.models import ConnectorType, SignatureAlgorithm
from messagefoundry.config.wiring import ConnectionSpec, Rest, WiringError, load_config
from messagefoundry.transports.http_auth import (
    OAuth2ClientCredentialsProvider,
    with_oauth2_client_credentials,
)
from messagefoundry.transports.signing import b64u_decode
from messagefoundry.transports.smart import (
    _CLIENT_ASSERTION_TYPE,
    SmartBackendTokenProvider,
    token_provider_from_settings,
    with_smart_backend,
)

TOKEN_URL = "https://auth.partner.example/token"
REST_URL = "https://api.partner.example/v1"
CLIENT_ID = "cid"
CLIENT_SECRET = "s3cr3t"


# --- fakes -------------------------------------------------------------------


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else self._body[:amt]

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_exc: object) -> Literal[False]:
        return False


class _Recorder:
    """Captures each token-endpoint Request instead of sending it."""

    def __init__(self) -> None:
        self.requests: list[urllib.request.Request] = []

    # `timeout` is unused and must stay: both providers call `opener.open(req, timeout=...)`, so a
    # recorder without it raises TypeError and the test reds for the wrong reason.
    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _Resp:
        self.requests.append(req)
        return _Resp(b'{"access_token":"AT","expires_in":3600}')


def _posted_form(req: urllib.request.Request) -> dict[str, str]:
    """The token POST's form body as a flat mapping."""
    raw = req.data if isinstance(req.data, bytes) else b""
    return dict(urllib.parse.parse_qsl(raw.decode("ascii")))


def _jwt_claims(assertion: str) -> dict[str, Any]:
    """The claims of a compact JWT, WITHOUT verifying it -- this asks what was SENT, not whether it
    was well signed. ``test_smart_backend.py`` owns the signature half.

    Decodes through ``signing.b64u_decode`` rather than a local base64url helper: that alias exists
    precisely so a second implementation cannot disagree with the minter about padding.
    """
    decoded: dict[str, Any] = json.loads(b64u_decode(assertion.split(".")[1]))
    return decoded


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _drive(
    provider: SmartBackendTokenProvider | OAuth2ClientCredentialsProvider,
) -> urllib.request.Request:
    """Mint once against a recorder and hand back the single token POST that reached the wire."""
    rec = _Recorder()
    provider._opener = rec  # type: ignore[assignment]
    provider.access_token()
    assert len(rec.requests) == 1
    return rec.requests[0]


# --- fact 1: the SMART leg IS bound to its destination ------------------------


def test_the_smart_assertion_audience_is_the_pinned_token_endpoint(rsa_pem: str) -> None:
    """The signed assertion names the endpoint it is POSTed to, so a second authorization server
    that validates ``aud`` (RFC 7523 section 3) rejects a replayed one.

    A red means the SMART leg stopped binding, which is the stronger half of BACKLOG #1158's
    comparison disappearing.

    ``test_smart_backend.py``'s S12 audit anchors already assert the default ``aud`` off
    ``_assertion_claims()``; this reads the claim off the POSTed FORM instead, because the comparison
    below is about what each leg puts on the wire.
    """
    provider = SmartBackendTokenProvider(
        token_url=TOKEN_URL, client_id=CLIENT_ID, private_key=rsa_pem
    )
    form = _posted_form(_drive(provider))
    claims = _jwt_claims(form["client_assertion"])
    assert claims["aud"] == TOKEN_URL
    # iss and sub are the client id (RFC 7523 section 3), so the assertion also names WHO it is for.
    assert claims["iss"] == CLIENT_ID and claims["sub"] == CLIENT_ID
    assert isinstance(claims["exp"], int) and claims["jti"]


# --- fact 2: the symmetric leg is NOT ----------------------------------------


@pytest.mark.parametrize("auth_style", ["basic", "post"])
def test_the_symmetric_secret_reaches_the_wire_with_no_destination_claim(auth_style: str) -> None:
    """Both shipped styles transmit the reusable secret itself and assert no audience.

    ``basic`` puts it in an ``Authorization`` header, ``post`` in the form body; neither carries a
    ``client_assertion``, an ``aud`` or an expiry, so the credential a token endpoint receives is
    replayable at every other endpoint the same secret is registered with. This is the gap BACKLOG
    #1158 names, held here so the row cannot go stale silently.
    """
    provider = OAuth2ClientCredentialsProvider(
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        auth_style=auth_style,
    )
    req = _drive(provider)
    form = _posted_form(req)
    header = req.get_header("Authorization", "")
    if auth_style == "basic":
        assert base64.b64decode(header.removeprefix("Basic ")).decode() == (
            f"{CLIENT_ID}:{CLIENT_SECRET}"
        )
        assert "client_secret" not in form
    else:
        assert form["client_secret"] == CLIENT_SECRET
        assert header == ""
    # The discriminating half: nothing in EITHER style names the destination or bounds the lifetime.
    unbound = {"client_assertion", "client_assertion_type", "aud", "exp", "jti"}
    assert unbound.isdisjoint(form), sorted(unbound & set(form))


# The asymmetric-only SignatureAlgorithm enum is the fifth fact and has an owner elsewhere; see the
# module docstring for why it is not re-asserted here.
#
# --- fact 3: the asymmetric binding already reaches a generic OAuth2 partner ---


def test_the_asymmetric_binding_composes_onto_a_plain_rest_outbound(rsa_pem: str) -> None:
    """``with_smart_backend`` over a bare ``Rest()`` is a generic RFC 7523 private_key_jwt client.

    Nothing SMART-specific reaches the wire: the exchange is ``grant_type=client_credentials`` plus
    the RFC 7523 section 2.2 assertion pair, which is what any authorization server registering a
    public key expects. So an operator who wants BACKLOG #1158's missing binding on a non-FHIR
    partner has it today -- under settings named ``smart_*``, which is a discoverability problem and
    not an absent control.
    """
    spec = with_smart_backend(
        Rest(url=REST_URL),
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        private_key=rsa_pem,
        algorithm=SignatureAlgorithm.RS256,  # a generic AS, not SMART's RS384 SHALL
    )
    # The composer's return is a union (it also takes a FhirLookup read-side spec), and only the
    # ConnectionSpec arm carries `type`. Narrowing here is the assertion, not a cast for the checker:
    # the point of the test is that a REST outbound came back.
    assert isinstance(spec, ConnectionSpec)
    assert spec.type is ConnectorType.REST
    provider = token_provider_from_settings(spec.settings)
    assert provider is not None
    form = _posted_form(_drive(provider))
    assert set(form) == {"grant_type", "client_assertion_type", "client_assertion"}
    assert form["grant_type"] == "client_credentials"
    assert form["client_assertion_type"] == _CLIENT_ASSERTION_TYPE
    assert _jwt_claims(form["client_assertion"])["aud"] == TOKEN_URL


# --- fact 4: the both-surfaces floor -----------------------------------------


def _toml_config(tmp_path: Path, settings: str) -> Path:
    """A config dir whose ``connections.toml`` declares one REST outbound with ``settings``."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "logic.py").write_text("", encoding="utf-8")
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(f"""
            [[outbound]]
            name = "OB"
            transport = "rest"
              [outbound.settings]
              url = "{REST_URL}"
            {settings}
            """),
        encoding="utf-8",
    )
    return tmp_path


def test_no_per_connection_auth_mode_reaches_the_connections_toml_surface(tmp_path: Path) -> None:
    """``connections.toml`` refuses SMART, OAuth2-CC and Digest alike, and refuses them LOUDLY.

    The loader hands the ``[settings]`` table to the transport factory, and ``Rest`` is keyword-only
    with a closed parameter list, so an auth key is a ``TypeError`` reported as a ``WiringError``.
    That is the safe direction -- no key is silently swallowed -- but it means every one of the three
    auth modes is code-first only. Recorded here because "an operator must be able to reach it from
    both surfaces" is a bar the shipped modes do not clear either, so it cannot be what decides
    whether a fourth auth style is worth building.

    Driven through the public ``load_config`` rather than the loader's internals, so it answers the
    question an operator actually asks -- can I write this in the file -- and passes through the same
    TOML decode and unknown-key screen a real config dir does.
    """
    # Control: the same table without an auth key loads, so a refusal below is about the key.
    registry = load_config(_toml_config(tmp_path / "control", ""))
    assert registry.outbound["OB"].spec.type is ConnectorType.REST

    for i, key in enumerate(("oauth2_token_url", "smart_token_url", "http_auth")):
        with pytest.raises(WiringError) as ei:
            load_config(_toml_config(tmp_path / f"probe{i}", f'  {key} = "x"'))
        assert key in str(ei.value)


def test_the_code_first_composer_does_place_every_oauth2_setting() -> None:
    """The code-first surface, by contrast, lands each key -- the arm a kwargs swallow would break.

    Asserted by NAME on the spec the loader reads, not by calling the provider, so a composer that
    quietly dropped ``oauth2_auth_style`` into a catch-all would fail here rather than at first mint.
    """
    spec = with_oauth2_client_credentials(
        Rest(url=REST_URL),
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        auth_style="post",
        scope="claims.write",
    )
    assert spec.settings["oauth2_auth_style"] == "post"
    assert spec.settings["oauth2_token_url"] == TOKEN_URL
    assert spec.settings["oauth2_scope"] == "claims.write"
    # The provider built from those settings honours the style that travelled through them.
    provider = OAuth2ClientCredentialsProvider(
        token_url=str(spec.settings["oauth2_token_url"]),
        client_id=str(spec.settings["oauth2_client_id"]),
        client_secret=str(spec.settings["oauth2_client_secret"]),
        auth_style=str(spec.settings["oauth2_auth_style"]),
    )
    assert "client_secret" in _posted_form(_drive(provider))
