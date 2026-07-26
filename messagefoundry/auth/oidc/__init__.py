# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""OIDC authorization-code + PKCE relying party for the web console (ADR 0142, BACKLOG #274).

A pure, side-effect-free federation layer: PKCE + flow-binding (:mod:`flow`), JWKS handling with a
key-material floor (:mod:`jwks`), and the ``id_token`` claim-validation ladder (:mod:`claims`). It
opens no socket except the injected token-endpoint opener, holds no session or cookie knowledge (that
lives in ``api``/the web console), and touches no store. ``auth/service.py`` drives it and maps a
verified :class:`~messagefoundry.auth.oidc.claims.FederatedPrincipal` onto an existing on-prem AD
identity via the same ``resolve_principal`` the Kerberos path uses — so roles come from LDAP, never
from a token claim.
"""

from __future__ import annotations

from messagefoundry.auth.oidc.claims import (
    REASONS,
    ClaimsError,
    FederatedPrincipal,
    OidcClaimPolicy,
    validate_id_token,
)
from messagefoundry.auth.oidc.flow import (
    DEFAULT_FLOW_CACHE_MAX,
    DEFAULT_FLOW_TTL_SECONDS,
    FlowCache,
    FlowCacheFullError,
    FlowError,
    PendingFlow,
    build_authorization_url,
    exchange_code,
    generate_pkce,
    new_flow_id,
    pkce_challenge,
    start_flow,
    state_matches,
)
from messagefoundry.auth.oidc.jwks import (
    DEFAULT_JWKS_MIN_REFETCH_SECONDS,
    DEFAULT_JWKS_TTL_SECONDS,
    JwksCache,
    JwksError,
    jwk_to_public_key,
    parse_jwks,
)

__all__ = [
    "DEFAULT_FLOW_CACHE_MAX",
    "DEFAULT_FLOW_TTL_SECONDS",
    "DEFAULT_JWKS_MIN_REFETCH_SECONDS",
    "DEFAULT_JWKS_TTL_SECONDS",
    "REASONS",
    "ClaimsError",
    "FederatedPrincipal",
    "FlowCache",
    "FlowCacheFullError",
    "FlowError",
    "JwksCache",
    "JwksError",
    "OidcClaimPolicy",
    "PendingFlow",
    "build_authorization_url",
    "exchange_code",
    "generate_pkce",
    "jwk_to_public_key",
    "new_flow_id",
    "parse_jwks",
    "pkce_challenge",
    "start_flow",
    "state_matches",
    "validate_id_token",
]
