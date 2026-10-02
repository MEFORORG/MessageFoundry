# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How the OIDC relying party authenticates to the token endpoint (ADR 0142, BACKLOG #296).

Two methods, and the configured one is the only credential the engine resolves or sends:

* ``client_secret_post`` (:class:`ClientSecretPost`, the default): the client secret rides the token
  request body. That secret is reusable. Nothing in it names the endpoint it was sent to or bounds
  its lifetime.
* ``private_key_jwt`` (:class:`PrivateKeyJwtClientAuth`, OIDC Core section 9, RFC 7523 section 2.2):
  a short-lived JWT signed with a private key, and no secret. The key never leaves this process, and
  the identity provider holds only its public half.

**The assertion.** ``iss`` and ``sub`` are the client id. ``aud`` is the pinned token endpoint by
default, which OIDC Core section 9 says it SHOULD be and which Entra ID and Okta require. Where an IdP
wants its issuer identifier instead, ``[auth].oidc_client_assertion_audience = "issuer"`` sends the
pinned issuer. Both values are operator-pinned https URLs whose hosts are on the OIDC allow-list, so
the assertion is never addressed to a party the engine does not already trust. ``exp`` is
:data:`CLIENT_ASSERTION_TTL_SECONDS` after ``iat``, and ``jti`` is 256 random bits, so each token
request carries a fresh assertion.

**Nothing here is a second copy of the SMART client's assertion code.** The claim set and the
assertion type come from :mod:`messagefoundry.transports.signing`, and the signature is
:class:`~messagefoundry.transports.signing.CompactJwtSigner`'s. So the key load, the RSA-3072 floor,
the per-algorithm curve check and the refusal to echo key material are that module's. Its
algorithms are the asymmetric :class:`~messagefoundry.config.models.SignatureAlgorithm` set; ``none``
and every HMAC algorithm are outside it, so neither can be configured.

Like the rest of :mod:`messagefoundry.auth.oidc`, nothing here opens a socket or logs; building a
:class:`PrivateKeyJwtClientAuth` reads its key (and any certificate) from a file when given a path.
Resolving the configured credential from settings, which may call a ``[secrets]`` provider, is
``oidc_client_auth_from_settings`` in :mod:`messagefoundry.auth.service`. Both credentials are form
fields built only inside :func:`~messagefoundry.auth.oidc.flow.exchange_code`, which keeps every
request value out of its exceptions.
"""

from __future__ import annotations

from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.transports.signing import (
    CLIENT_ASSERTION_TYPE,
    CompactJwtSigner,
    _PublicKey,
    client_assertion_claims,
)

__all__ = [
    "CLIENT_ASSERTION_TTL_SECONDS",
    "ClientAuthentication",
    "ClientSecretPost",
    "PrivateKeyJwtClientAuth",
]

#: How long an assertion is valid. It is minted immediately before the one POST that carries it, so
#: the window only has to cover the request and a modest clock difference with the IdP. The SMART
#: client uses 240 s because SMART caps it at 300; nothing on this hop asks for that much.
CLIENT_ASSERTION_TTL_SECONDS = 120


class ClientSecretPost:
    """``client_secret_post``: the client secret in the token request body (the default)."""

    def __init__(self, secret: str) -> None:
        self._secret = secret

    def __repr__(self) -> str:  # the secret must never reach a repr, a log line or a traceback
        return "ClientSecretPost(<secret>)"

    def form_fields(self) -> dict[str, str]:
        return {"client_secret": self._secret}


class PrivateKeyJwtClientAuth:
    """``private_key_jwt``: a fresh signed client assertion for each token request.

    Built once, when the auth service is built, so a missing, unreadable, weak or wrong-curve key
    refuses startup instead of failing the first federated sign-in.
    """

    def __init__(
        self,
        *,
        client_id: str,
        audience: str,
        private_key: str,
        algorithm: SignatureAlgorithm,
        private_key_password: str | None = None,
        key_id: str | None = None,
        certificate: str | None = None,
    ) -> None:
        self.client_id = client_id
        self.audience = audience
        self._signer = CompactJwtSigner(
            private_key=private_key,
            algorithm=algorithm,
            # Named in a key-read refusal in place of the value, never the value itself.
            setting="oidc_client_private_key",
            private_key_password=private_key_password,
            key_id=key_id,
            certificate=certificate,
            certificate_setting="oidc_client_certificate",
        )

    @property
    def public_key(self) -> _PublicKey:
        """The verifying key, for tests and for the operator registering the client at the IdP."""
        return self._signer.public_key

    def form_fields(self) -> dict[str, str]:
        """The two token-request form fields that authenticate the client in place of a secret."""
        claims = client_assertion_claims(
            self.client_id,
            self.audience,
            ttl_seconds=CLIENT_ASSERTION_TTL_SECONDS,
            include_iat=True,
        )
        return {
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._signer.sign(claims),
        }


#: The credential the token request carries, whichever method is configured.
ClientAuthentication = ClientSecretPost | PrivateKeyJwtClientAuth
