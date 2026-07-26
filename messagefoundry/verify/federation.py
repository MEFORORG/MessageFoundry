# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Federated-SSO (OIDC) verify section — ADR 0142, BACKLOG #274.

Wheel-only and **offline by default**: nothing here opens a socket, so `verify` never makes a
reachable IdP a precondition for an acceptance run (the same constraint the engine itself honours).

The honesty contract from :mod:`messagefoundry.verify.checks` is the hard part of this section, and
the temptation it guards against is specific: almost everything about `[auth].oidc_*` is already
guaranteed by the settings validators, so a check that merely reads config back would emit a wall of
green PASS rows proving nothing. Those facts are reported **MANUAL** with the pinned values as
evidence. ``PASS`` is reserved for things that can actually fail here — resolving the client secret,
building the pinned TLS context, parsing a JWKS through the key-material floor, and the offline
``id_token`` replay.

The replay reports a **per-rung** verdict without decomposing the ladder or re-parsing the token.
``validate_id_token`` is an ordered ladder that raises on the FIRST failure with a closed-set reason,
so one call is enough: the reason names the rung that failed, every earlier rung necessarily passed,
and every later rung was never reached (reported SKIP, never PASS — an unreached check is not a
passing one).
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.settings import ServiceSettings
from messagefoundry.verify.model import CheckResult, Status

#: The ladder's rungs, in the order :func:`~messagefoundry.auth.oidc.claims.validate_id_token` walks
#: them, each with the closed-set reason slugs that indict it. Order is load-bearing: it is what lets
#: a single call yield a verdict per rung.
_RUNGS: tuple[tuple[str, str, frozenset[str]], ...] = (
    (
        "fed.replay.key",
        "id_token key selection (kid -> JWKS)",
        frozenset({"malformed_token", "unknown_kid", "ambiguous_kid", "key_rejected"}),
    ),
    (
        "fed.replay.signature",
        "id_token signature",
        frozenset({"bad_signature", "malformed_payload"}),
    ),
    (
        "fed.replay.claims",
        "iss / aud / azp / exp / iat / nbf",
        frozenset(
            {
                "claim_iss",
                "claim_aud",
                "claim_azp",
                "expired",
                "claim_not_numeric",
                "not_yet_valid",
                "issued_in_future",
            }
        ),
    ),
    ("fed.replay.nonce", "nonce (browser flow binding)", frozenset({"nonce_mismatch"})),
    ("fed.replay.mfa", "amr / acr MFA gate", frozenset({"mfa_claim_missing"})),
    (
        "fed.replay.username",
        "username claim + UPN suffix allow-list",
        frozenset({"username_claim_missing", "username_domain_not_allowed"}),
    ),
)

#: A nonce that cannot match anything the engine minted, used when the operator supplies no
#: ``--fed-nonce``. The ladder then stops at the nonce rung, which is reported SKIP (not FAIL): a
#: captured token's browser binding is genuinely untestable offline.
_SENTINEL_NONCE = "offline-replay-no-flow-nonce"


def _disabled_row() -> CheckResult:
    return CheckResult(
        "fed.enabled",
        "Federated SSO (OIDC)",
        Status.SKIP,
        "[auth].oidc_enabled is false — federation is off (the shipped default)",
    )


def _config_rows(settings: ServiceSettings) -> list[CheckResult]:
    """Report the pinned posture. MANUAL, not PASS: the settings validators already refuse an
    unusable combination at load, so a PASS here would be a check that cannot fail."""
    auth = settings.auth
    rows = [
        CheckResult(
            "fed.enabled",
            "Federated SSO (OIDC)",
            Status.MANUAL,
            "confirm these pinned endpoints are the intended identity provider",
            evidence=(
                f"issuer={auth.oidc_issuer}; client_id={auth.oidc_client_id}; "
                f"authorize={auth.oidc_authorization_endpoint}; token={auth.oidc_token_endpoint}; "
                f"jwks={auth.oidc_jwks_uri}; redirect={settings.api.public_origin or '<unset>'}"
                f"{auth.oidc_redirect_path}"
            ),
        ),
        CheckResult(
            "fed.algorithms",
            "Accepted id_token signature algorithms",
            Status.MANUAL,
            "confirm this matches what the identity provider signs with",
            evidence=", ".join(auth.oidc_signing_algorithms),
        ),
    ]

    # The #99(g) control. Reported MANUAL either way rather than FAIL: disabling it is config-legal,
    # and failing a legal configuration would be the verifier overriding an operator decision. The
    # detail states plainly what was given up, so a green run cannot be mistaken for MFA enforcement.
    if auth.oidc_require_mfa_claim:
        rows.append(
            CheckResult(
                "fed.mfa_gate",
                "IdP MFA claim gate",
                Status.MANUAL,
                "the engine refuses a login whose verified token carries none of these. It verifies "
                "what the IdP ASSERTS, cryptographically — it CANNOT prove the IdP enforced MFA",
                evidence=(
                    f"amr any-of {list(auth.oidc_mfa_amr_values)}; "
                    f"acr any-of {list(auth.oidc_required_acr_values)}"
                ),
            )
        )
    else:
        rows.append(
            CheckResult(
                "fed.mfa_gate",
                "IdP MFA claim gate",
                Status.MANUAL,
                "DISABLED — oidc_require_mfa_claim is false, so a federated login is accepted with "
                "no MFA assertion at all. This gives up the control BACKLOG #99(g) exists for",
            )
        )

    # AC-11. Also MANUAL (the validator refuses an empty source when stripping), but the effective
    # list is exactly what an operator needs to eyeball: it is what stops a federated principal
    # choosing which on-prem account its username resolves to.
    if auth.oidc_username_strip_domain:
        rows.append(
            CheckResult(
                "fed.username_binding",
                "Username UPN-suffix allow-list",
                Status.MANUAL,
                "confirm these are the ONLY UPN suffixes whose local part may name an on-prem account",
                evidence=(
                    f"claim={auth.oidc_username_claim}; "
                    f"allowed={list(auth.effective_oidc_username_domains)}"
                ),
            )
        )
    else:
        rows.append(
            CheckResult(
                "fed.username_binding",
                "Username UPN-suffix allow-list",
                Status.MANUAL,
                "oidc_username_strip_domain is false — the claim is used verbatim as the account name",
                evidence=f"claim={auth.oidc_username_claim}",
            )
        )
    return rows


def _secret_row(settings: ServiceSettings) -> CheckResult:
    """Resolve the client secret exactly as the engine does. This CAN fail (a Vault reference that
    does not resolve, a provider that is unset), so it earns a PASS."""
    from messagefoundry.config.secretprovider import (
        SecretProviderError,
        resolve_connector_secret,
        resolve_secret_provider,
    )

    rid, title = "fed.client_secret", "OIDC client secret resolves"
    auth = settings.auth
    try:
        provider = resolve_secret_provider(settings.secrets)
        value = resolve_connector_secret(
            provider,
            ref=auth.oidc_client_secret_ref,
            literal=auth.oidc_client_secret,
            label="[auth].oidc_client_secret",
        )
    except SecretProviderError as exc:
        return CheckResult(rid, title, Status.FAIL, str(exc))
    except Exception as exc:  # never raise out of a check
        return CheckResult(rid, title, Status.ERROR, f"{type(exc).__name__}: {exc}")
    if not value:
        return CheckResult(rid, title, Status.FAIL, "resolved to an empty value")
    source = "[secrets] provider reference" if auth.oidc_client_secret_ref else "environment"
    return CheckResult(rid, title, Status.PASS, f"resolved from the {source} (value not shown)")


def _tls_row(settings: ServiceSettings) -> CheckResult:
    """Build the real IdP TLS context. A bad/unreadable CA path fails here rather than at the last
    hop of a live login. No socket is opened."""
    from messagefoundry.auth.oidc_http import build_idp_opener

    rid, title = "fed.idp_tls", "IdP TLS trust"
    ca = settings.auth.oidc_tls_ca_cert_file
    try:
        build_idp_opener(ca)
    except OSError as exc:
        return CheckResult(
            rid, title, Status.FAIL, f"could not build the pinned TLS context: {exc}"
        )
    except Exception as exc:
        return CheckResult(rid, title, Status.ERROR, f"{type(exc).__name__}: {exc}")
    if ca:
        return CheckResult(
            rid, title, Status.PASS, f"pinned to {ca} (that PEM is the ENTIRE trust anchor set)"
        )
    return CheckResult(
        rid,
        title,
        Status.PASS,
        "using the OS trust store (a private/AD-CS IdP certificate must be installed there, or set "
        "[auth].oidc_tls_ca_cert_file)",
    )


def _read(path: str, rid: str, title: str) -> tuple[bytes | None, CheckResult | None]:
    try:
        return Path(path).read_bytes(), None
    except (OSError, ValueError) as exc:
        # ValueError too: a path carrying a NUL raises it from io.open, and this module
        # promises never to raise.
        return None, CheckResult(rid, title, Status.FAIL, f"could not read {path}: {exc}")


def _jwks_row(jwks_bytes: bytes) -> tuple[object | None, CheckResult]:
    """Parse a JWKS through the real key-material floor. Genuinely fallible, so it earns a PASS."""
    from messagefoundry.auth.oidc import JwksError, parse_jwks

    rid, title = "fed.jwks", "JWKS parses through the key-material floor"
    try:
        keys = parse_jwks(jwks_bytes)
    except JwksError as exc:
        return None, CheckResult(rid, title, Status.FAIL, str(exc))
    except Exception as exc:
        return None, CheckResult(rid, title, Status.ERROR, f"{type(exc).__name__}: {exc}")
    return keys, CheckResult(
        rid,
        title,
        Status.PASS,
        f"{len(keys)} key(s) survived the floor: {', '.join(sorted(keys))}",
    )


def _replay_rows(
    settings: ServiceSettings, id_token_file: str, jwks_file: str, nonce: str | None
) -> list[CheckResult]:
    """Drive a captured ``id_token`` through the real ladder and report a verdict per rung."""
    from messagefoundry.auth.oidc import ClaimsError, JwksCache, OidcClaimPolicy, validate_id_token
    from messagefoundry.config.models import SignatureAlgorithm

    rows: list[CheckResult] = []
    token_bytes, err = _read(id_token_file, "fed.replay", "Offline id_token replay")
    if err is not None:
        return [err]
    jwks_bytes, err = _read(jwks_file, "fed.replay", "Offline id_token replay")
    if err is not None:
        return [err]
    assert token_bytes is not None and jwks_bytes is not None

    keys, jwks_result = _jwks_row(jwks_bytes)
    rows.append(jwks_result)
    if keys is None:
        rows += [
            CheckResult(rid, title, Status.SKIP, "not reached — the JWKS did not parse")
            for rid, title, _ in _RUNGS
        ]
        return rows

    auth = settings.auth
    policy = OidcClaimPolicy(
        issuer=auth.oidc_issuer or "",
        client_id=auth.oidc_client_id or "",
        signing_algorithms=[SignatureAlgorithm(a) for a in auth.oidc_signing_algorithms],
        nonce=nonce or _SENTINEL_NONCE,
        username_claim=auth.oidc_username_claim,
        username_strip_domain=auth.oidc_username_strip_domain,
        allowed_username_domains=frozenset(auth.effective_oidc_username_domains),
        require_mfa_claim=auth.oidc_require_mfa_claim,
        mfa_amr_values=auth.oidc_mfa_amr_values,
        required_acr_values=auth.oidc_required_acr_values,
        clock_skew_seconds=auth.oidc_clock_skew_seconds,
    )
    # The cache's fetch is a closure over the supplied file — no socket, so this stays offline.
    cache = JwksCache(lambda: jwks_bytes)

    failed_reason: str | None = None
    try:
        principal = validate_id_token(token_bytes.decode("ascii", "replace").strip(), policy, cache)
    except ClaimsError as exc:
        failed_reason = exc.reason
        principal = None
    except Exception as exc:
        rows.append(
            CheckResult(
                "fed.replay",
                "Offline id_token replay",
                Status.ERROR,
                f"{type(exc).__name__}: {exc}",
            )
        )
        return rows

    # `stopped_because` carries WHY the walk stopped, so a downstream SKIP does not claim "an
    # earlier rung failed" when the nonce rung was merely un-testable offline.
    stopped_because: str | None = None
    for rid, title, reasons in _RUNGS:
        is_nonce_rung = rid == "fed.replay.nonce"
        is_mfa_rung = rid == "fed.replay.mfa"
        if stopped_because is not None:
            rows.append(CheckResult(rid, title, Status.SKIP, f"not reached — {stopped_because}"))
        elif failed_reason is not None and failed_reason in reasons:
            if is_nonce_rung and nonce is None:
                # Substituting the token's own nonce would make this rung a check that cannot fail.
                # A captured token's browser binding is genuinely untestable offline; say so.
                stopped_because = "the nonce rung could not be verified offline"
                rows.append(
                    CheckResult(
                        rid,
                        title,
                        Status.SKIP,
                        "no --fed-nonce supplied — the browser flow binding cannot be verified "
                        "offline (it is exercised by the live lab cells)",
                    )
                )
            elif failed_reason == "expired":
                # A stale capture is not a deployment defect. NOTE this is now reachable ONLY for a
                # genuinely past `exp` -- a missing or non-numeric one raises `claim_not_numeric`
                # and FAILs, because an IdP that mints no usable `exp` breaks the AC-6 session cap.
                stopped_because = "the captured token has expired"
                rows.append(
                    CheckResult(
                        rid,
                        title,
                        Status.SKIP,
                        "the captured id_token has expired — re-capture to exercise this rung",
                    )
                )
            else:
                stopped_because = "an earlier rung failed"
                rows.append(CheckResult(rid, title, Status.FAIL, f"reason={failed_reason}"))
        elif is_mfa_rung and not auth.oidc_require_mfa_claim:
            # _check_mfa_gate returns before reading a claim when the gate is off, so this rung
            # could only ever read PASS -- a check that cannot fail, which this section reserves
            # PASS against. It would also contradict the DISABLED row emitted above.
            rows.append(
                CheckResult(
                    rid,
                    title,
                    Status.SKIP,
                    "oidc_require_mfa_claim is false — the gate is disabled, so there is nothing "
                    "to verify here (see the fed.mfa_gate row)",
                )
            )
        else:
            rows.append(CheckResult(rid, title, Status.PASS, "verified"))

    if principal is not None:
        rows.append(
            CheckResult(
                "fed.replay.principal",
                "Resolved federated principal",
                Status.MANUAL,
                "confirm this is the on-prem account the token's holder should map to (roles come "
                "from AD, never from the token)",
                evidence=(
                    f"username={principal.username}; sub={principal.subject}; "
                    f"amr={list(principal.amr)}; acr={principal.acr}"
                ),
            )
        )
    return rows


def run_federation_checks(
    settings: ServiceSettings | None,
    *,
    id_token_file: str | None = None,
    jwks_file: str | None = None,
    nonce: str | None = None,
) -> list[CheckResult]:
    """Run the federation section. Never raises; returns one row per check.

    With federation off (the shipped default) this emits exactly ONE SKIP row, so a non-federated
    deployment's report is unchanged apart from that single line.
    """
    if settings is None:
        return [
            CheckResult(
                "fed.enabled",
                "Federated SSO (OIDC)",
                Status.SKIP,
                "service settings did not load — see the config.load row",
            )
        ]
    if not settings.auth.oidc_enabled:
        return [_disabled_row()]

    rows = _config_rows(settings)
    rows.append(_secret_row(settings))
    rows.append(_tls_row(settings))

    if id_token_file and jwks_file:
        rows += _replay_rows(settings, id_token_file, jwks_file, nonce)
    elif id_token_file or jwks_file:
        rows.append(
            CheckResult(
                "fed.replay",
                "Offline id_token replay",
                Status.SKIP,
                "--fed-id-token and --fed-jwks must BOTH be supplied: without a key source there is "
                "nothing to verify the signature against, and reporting claim rungs off an unverified "
                "payload would be dishonest",
            )
        )
    else:
        rows.append(
            CheckResult(
                "fed.replay",
                "Offline id_token replay",
                Status.SKIP,
                "not requested — pass --fed-id-token <file> --fed-jwks <file> to replay a captured "
                "token through the validation ladder",
            )
        )
    return rows
