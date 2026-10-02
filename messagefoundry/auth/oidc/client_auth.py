# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``private_key_jwt`` client authentication at the OIDC token endpoint (BACKLOG #296).

The default client authentication is ``client_secret_post``: the engine sends its client secret in
the token request body. That secret is reusable. Nothing in it names the endpoint it was sent to or
bounds its lifetime. ``private_key_jwt`` (OIDC Core section 9, RFC 7523 section 2.2) sends a
short-lived JWT signed with a private key instead. The key never leaves this process, and the identity
provider holds only its public half.

**The assertion.** ``iss`` and ``sub`` are the client id. ``aud`` is the pinned token endpoint by
default, which OIDC Core section 9 says it SHOULD be and which Entra ID and Okta require. Where an IdP
wants its issuer identifier instead, ``[auth].oidc_client_assertion_audience = "issuer"`` sends the
pinned issuer. Both values are operator-pinned https URLs whose hosts are on the OIDC allow-list, so
the assertion is never addressed to a party the engine does not already trust. ``exp`` is
:data:`CLIENT_ASSERTION_TTL_SECONDS` after ``iat``, and ``jti`` is 256 random bits, so each token
request carries a fresh assertion.

**The signer is the engine's one compact-JWT signer**,
:class:`~messagefoundry.transports.signing.CompactJwtSigner`, the one the SMART Backend Services
client already uses. So the key load, the RSA-3072 floor, the per-algorithm curve check and the
refusal to echo key material are that class's, not a second copy. Its algorithms are the asymmetric
:class:`~messagefoundry.config.models.SignatureAlgorithm` set. ``none`` and every HMAC algorithm are
outside that set, so neither can be configured.

Like the rest of :mod:`messagefoundry.auth.oidc`, nothing here opens a socket or logs. The assertion
is a credential: it is built only inside :func:`~messagefoundry.auth.oidc.flow.exchange_code`, which
keeps every request value out of its exceptions.
"""

from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING

from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.transports.signing import CompactJwtSigner, _PublicKey

if TYPE_CHECKING:
    from messagefoundry.config.settings import AuthSettings

__all__ = [
    "CLIENT_ASSERTION_TTL_SECONDS",
    "CLIENT_ASSERTION_TYPE",
    "PrivateKeyJwtClientAuth",
    "client_auth_from_settings",
]

#: RFC 7523 section 2.2: the ``client_assertion_type`` value for a JWT client assertion.
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: How long an assertion is valid. It is minted immediately before the one POST that carries it, so
#: the window only has to cover the request and a modest clock difference with the IdP. The SMART
#: client uses 240 s because SMART caps it at 300; nothing on this hop asks for that much.
CLIENT_ASSERTION_TTL_SECONDS = 120


class PrivateKeyJwtClientAuth:
    """Mints a fresh ``private_key_jwt`` client assertion for each token request.

    Built once, at :class:`~messagefoundry.auth.service.AuthService` construction, so a missing,
    unreadable, weak or wrong-curve key refuses startup instead of failing the first federated
    sign-in. :meth:`form_fields` is then called once per token request.
    """

    def __init__(
        self,
        *,
        client_id: str,
        audience: str,
        private_key: str,
        algorithm: SignatureAlgorithm,
        setting: str,
        private_key_password: str | None = None,
        key_id: str | None = None,
    ) -> None:
        self.client_id = client_id
        self.audience = audience
        # `setting` names the operator-facing key in a key-read refusal, never the value.
        self._signer = CompactJwtSigner(
            private_key=private_key,
            algorithm=algorithm,
            setting=setting,
            private_key_password=private_key_password,
            key_id=key_id,
        )

    @property
    def public_key(self) -> _PublicKey:
        """The verifying key, for tests and for the operator registering the client at the IdP."""
        return self._signer.public_key

    def claims(self) -> dict[str, object]:
        """The assertion's claims: ``iss`` = ``sub`` = client id, ``aud``, ``iat``, ``exp``, ``jti``."""
        now = int(time.time())
        return {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.audience,
            "iat": now,
            "exp": now + CLIENT_ASSERTION_TTL_SECONDS,
            "jti": secrets.token_urlsafe(32),
        }

    def form_fields(self) -> dict[str, str]:
        """The two token-request form fields that authenticate the client in place of a secret."""
        return {
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._signer.sign(self.claims()),
        }


def client_auth_from_settings(
    settings: AuthSettings, secret_provider: SecretProvider | None
) -> PrivateKeyJwtClientAuth | None:
    """The ``private_key_jwt`` client for ``[auth]``, or ``None`` under ``client_secret_post``.

    The ONE construction, shared by :class:`~messagefoundry.auth.service.AuthService` and
    ``messagefoundry verify --section federation``, so the check resolves and loads the key exactly
    as the engine does. Raises the secret provider's error for a reference that does not resolve,
    and :class:`~messagefoundry.transports.signing.SigningError` for a key that cannot be read,
    parsed or used with the configured algorithm. Neither message carries key material.
    """
    if not settings.oidc_private_key_jwt:
        return None
    key = resolve_connector_secret(
        secret_provider,
        ref=settings.oidc_client_private_key_ref,
        literal=settings.oidc_client_private_key,
        label="[auth].oidc_client_private_key",
    )
    audience = (
        settings.oidc_issuer
        if settings.oidc_client_assertion_audience == "issuer"
        else settings.oidc_token_endpoint
    )
    return PrivateKeyJwtClientAuth(
        client_id=settings.oidc_client_id or "",
        audience=audience or "",
        private_key=key or "",
        algorithm=settings.oidc_client_assertion_algorithm,
        setting="oidc_client_private_key",
        private_key_password=settings.oidc_client_private_key_password,
        key_id=settings.oidc_client_assertion_key_id,
    )
