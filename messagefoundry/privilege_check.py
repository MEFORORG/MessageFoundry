# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``messagefoundry check-privileges`` — what each backend hop's identity holds, and what it should
hold (BACKLOG #305 part E2, ASVS 13.2.2).

**It probes only where the engine already has a read-only probe, and says so everywhere else.** One
hop is a real probe today: the store principal, through the same
:mod:`~messagefoundry.store.privilege` probe the startup preflight runs. The other four hops the
backlog row names (Vault, LDAP, SMTP and the OIDC identity provider) have no read-only
self-inspection primitive in the engine: no Vault token self-lookup, no LDAP "who am I" extended
operation, and nothing an SMTP relay or an IdP will say about its own grants. For those this module
prints the identity the engine is configured to present and the minimal privilege it needs, and
reports ``not_probed`` with the reason. It never makes a network call that the engine does not
already make, and a hop it cannot probe never fails the run: an operator attests those by hand.

**The states are distinct on purpose.** ``unobservable`` (a probe that should have run and could not)
and ``not_probed`` (a hop with no probe at all) are different findings with different exit codes, the
same split the preflight draws between ``UNOBSERVABLE`` and ``NOT_APPLICABLE``.

**Nothing printed is a secret or PHI.** Identities are principal names, DNs, usernames, env-var
NAMES and client ids, never a password, token or key; the store detail has already been through the
preflight's redactor. Every function here is pure: it reads its arguments and nothing else.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from messagefoundry.config.settings import (
    SchemaManagement,
    ServiceSettings,
    SqlAuth,
    StoreBackend,
    StorePrivilegeStatus,
    StoreSettings,
)
from messagefoundry.store.privilege import (
    SQLSERVER_DOCUMENTED_DATABASE_ROLES,
    SQLSERVER_RUNTIME_DATABASE_ROLES,
    StorePrivilegeReport,
)

__all__ = [
    "EXIT_CLEAN",
    "EXIT_OVER_PRIVILEGED",
    "EXIT_SETTINGS",
    "EXIT_UNOBSERVABLE",
    "HopPrivilege",
    "HopState",
    "exit_code_for",
    "render_text",
    "settings_hops",
    "store_hop",
]

#: Every probe that ran found nothing beyond the documented grant. Hops with no probe do not count.
EXIT_CLEAN = 0
#: The service settings did not load, so nothing was probed.
EXIT_SETTINGS = 1
#: A probe OBSERVED a privilege beyond the documented grant. Wins over :data:`EXIT_UNOBSERVABLE`.
EXIT_OVER_PRIVILEGED = 3
#: A probe that should have run could not observe the principal (connect failure, NULL reads).
#: Not 2: argparse spends 2 on a usage error, and a job keying on the code must not read one as this.
EXIT_UNOBSERVABLE = 4


class HopState(str, Enum):  # noqa: UP042 - the repo's str-enum convention (see config.settings)
    """What the command could say about one hop."""

    CLEAN = "clean"
    OVER_GRANTED = "over_granted"
    UNOBSERVABLE = "unobservable"
    NOT_APPLICABLE = "not_applicable"
    NOT_PROBED = "not_probed"
    NOT_CONFIGURED = "not_configured"


#: The two states that fail the run read loud; every other state prints its value in words.
_LOUD_LABEL: dict[HopState, str] = {
    HopState.OVER_GRANTED: "OVER-GRANTED",
    HopState.UNOBSERVABLE: "could not observe",
}


@dataclass(frozen=True, slots=True)
class HopPrivilege:
    """One backend hop: who the engine presents, what that identity should hold, and what was seen."""

    hop: str
    state: HopState
    identity: str
    minimal: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "hop": self.hop,
            "state": self.state.value,
            "identity": self.identity,
            "minimal": self.minimal,
            "detail": self.detail,
        }


# --- the store: the one real probe ------------------------------------------------------------


def _store_minimal(store: StoreSettings) -> str:
    external = store.resolved_schema_management() is SchemaManagement.EXTERNAL
    if store.backend is StoreBackend.SQLSERVER:
        # Built from the sets the probe measures excess against, so the two lines cannot disagree.
        roles = (
            SQLSERVER_RUNTIME_DATABASE_ROLES if external else SQLSERVER_DOCUMENTED_DATABASE_ROLES
        )
        mode = "external" if external else "auto"
        return f"{' + '.join(sorted(roles))} (schema_management = {mode!r}), no server role"
    if store.backend is StoreBackend.POSTGRES:
        return (
            "a LOGIN role with no attributes: CONNECT, USAGE on the store schema and row grants; "
            "no CREATE on the schema and no owned objects"
            if external
            else "a LOGIN role with no attributes that owns its own schema "
            "(schema_management = 'auto')"
        )
    return "the service account alone may read and write the .db file and its -wal/-shm sidecars"


def _store_identity(store: StoreSettings, report: StorePrivilegeReport) -> str:
    if report.principal:
        return f"{store.backend.value} principal {report.principal!r} on {report.database!r}"
    if store.backend is StoreBackend.SQLITE:
        return f"sqlite file {store.path!r}"
    if store.backend is StoreBackend.SQLSERVER and store.auth is SqlAuth.INTEGRATED:
        who = "the Windows account running this command ([store].auth = 'integrated')"
    elif store.backend is StoreBackend.SQLSERVER and store.auth is SqlAuth.ENTRA:
        # ActiveDirectoryDefault walks a credential chain (environment, managed identity, CLI login),
        # so the identity is whatever that chain resolves in THIS process's environment.
        who = "the Entra identity this command's environment resolves ([store].auth = 'entra')"
    else:
        who = repr(store.username or "")
    return f"{store.backend.value} principal {who} on {store.database!r}"


def store_hop(report: StorePrivilegeReport, store: StoreSettings) -> HopPrivilege:
    """The store hop from a probe report. ``store`` supplies the minimal grant, and the identity
    when the report names no principal (a probe that could not connect names none)."""
    if report.finding is not None:
        state = HopState(report.finding)
    elif report.status is StorePrivilegeStatus.NOT_APPLICABLE:
        state = HopState.NOT_APPLICABLE
    else:
        state = HopState.CLEAN
    return HopPrivilege(
        hop="store",
        state=state,
        identity=_store_identity(store, report),
        minimal=_store_minimal(store),
        detail=report.summary(),
    )


# --- the hops the engine cannot probe ---------------------------------------------------------

_NO_VAULT_PROBE = (
    "not probed: the engine has no read-only Vault token self-lookup, so it cannot read the "
    "token's policies. Attest them by hand, as the service account, against the minimal set"
)
_NO_LDAP_PROBE = (
    "not probed: the engine has no LDAP 'who am I' or effective-rights read, so it cannot read "
    "what the bind account may change. Attest it by hand in the directory"
)
_NO_SMTP_PROBE = (
    "not probed: an SMTP relay reports nothing about an account's rights, so there is nothing to "
    "read. Attest the relay's send-as policy by hand"
)
_NO_IDP_PROBE = (
    "not probed: the engine has no read of the client registration at the identity provider. "
    "Attest the client's grants by hand in the IdP"
)


def _not_configured(hop: str, why: str) -> HopPrivilege:
    return HopPrivilege(hop, HopState.NOT_CONFIGURED, identity="", minimal="", detail=why)


def _vault_hop(settings: ServiceSettings) -> HopPrivilege:
    store, auth, alerts = settings.store, settings.auth, settings.alerts
    uses: list[str] = []
    minimal: list[str] = []
    # One consumer per branch, mirroring static_credentials._settings_hops: Transit replaces the key
    # provider rather than adding to it.
    if store.cipher_provider == "vault_transit":
        uses.append("store Transit cipher (token in MEFOR_STORE_VAULT_TOKEN)")
        minimal.append(
            "read on transit/keys/<data key> and transit/keys/<audit key>; update on "
            "transit/encrypt/<data key>, transit/decrypt/<data key> and transit/hmac/<audit key>"
        )
    elif store.key_provider == "vault":
        uses.append("store key provider (token in MEFOR_STORE_VAULT_TOKEN)")
        minimal.append("read on transit/keys/<KEK> and update on transit/decrypt/<KEK>")
    refs = [
        ref
        for ref in (
            auth.ad_bind_password_secret,
            auth.oidc_client_secret_ref,
            alerts.email_password_secret,
        )
        if ref
    ]
    if settings.secrets.provider == "vault" and refs:
        uses.append(
            f"connector secret provider for {len(refs)} reference(s) "
            "(token in MEFOR_SECRETS_VAULT_TOKEN)"
        )
        minimal.append("read on the KV v2 data path of each reference, and nothing else")
    if not uses:
        return _not_configured("vault", "no Vault consumer is configured")
    return HopPrivilege(
        "vault", HopState.NOT_PROBED, "; ".join(uses), "; ".join(minimal), _NO_VAULT_PROBE
    )


def _ldap_hop(settings: ServiceSettings) -> HopPrivilege:
    auth = settings.auth
    if not auth.ad_enabled:
        return _not_configured("ldap", "[auth].ad_enabled is off")
    return HopPrivilege(
        "ldap",
        HopState.NOT_PROBED,
        f"bind DN {auth.ad_bind_dn!r} on {auth.ad_server!r}",
        "read and search on the user and group search bases; no write, no administrative group",
        _NO_LDAP_PROBE,
    )


def _smtp_hop(settings: ServiceSettings) -> HopPrivilege:
    alerts = settings.alerts
    if not (alerts.email_smtp_host and alerts.email_from):
        return _not_configured("smtp", "no alert SMTP relay is set")
    account = repr(alerts.email_username) if alerts.email_username else "no AUTH account"
    return HopPrivilege(
        "smtp",
        HopState.NOT_PROBED,
        f"{account} on {alerts.email_smtp_host}:{alerts.email_smtp_port}",
        f"send as {alerts.email_from!r} only; no mailbox read, no send-as for any other sender",
        _NO_SMTP_PROBE,
    )


def _idp_hop(settings: ServiceSettings) -> HopPrivilege:
    auth = settings.auth
    if not auth.oidc_enabled:
        return _not_configured("idp", "[auth].oidc_enabled is off")
    return HopPrivilege(
        "idp",
        HopState.NOT_PROBED,
        f"OIDC client {auth.oidc_client_id!r} at {auth.oidc_issuer!r}",
        f"a confidential client allowed the scopes {' '.join(auth.oidc_scopes)!r} only; no "
        "directory or admin API permission",
        _NO_IDP_PROBE,
    )


def settings_hops(settings: ServiceSettings) -> list[HopPrivilege]:
    """The four hops the engine cannot probe, in a fixed order, read from the settings alone."""
    return [_vault_hop(settings), _ldap_hop(settings), _smtp_hop(settings), _idp_hop(settings)]


# --- the verdict ------------------------------------------------------------------------------


def exit_code_for(hops: Iterable[HopPrivilege]) -> int:
    """Over-privilege wins over could-not-observe; hops with no probe never fail the run."""
    states = {h.state for h in hops}
    if HopState.OVER_GRANTED in states:
        return EXIT_OVER_PRIVILEGED
    if HopState.UNOBSERVABLE in states:
        return EXIT_UNOBSERVABLE
    return EXIT_CLEAN


def render_text(hops: Iterable[HopPrivilege]) -> list[str]:
    """Operator-readable lines, one block per hop."""
    lines: list[str] = []
    for h in hops:
        lines.append(f"{h.hop}: {_LOUD_LABEL.get(h.state, h.state.value.replace('_', ' '))}")
        if h.identity:
            lines.append(f"  identity: {h.identity}")
        if h.minimal:
            lines.append(f"  minimal:  {h.minimal}")
        lines.append(f"  {h.detail}")
    return lines
