# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``messagefoundry check-privileges`` — what each backend hop's identity holds, and what it should
hold (BACKLOG #305 part E2 and its Vault and LDAP probes, ASVS 13.2.2).

**Three hops are probed; two are printed.** The store principal is probed through the same
:mod:`~messagefoundry.store.privilege` probe the startup preflight runs. Each Vault token the engine
is configured to use is probed with a token self-lookup and a capabilities read, and the AD bind
account with an LDAP "Who am I?" and a read of its own groups (:mod:`messagefoundry.privilege_probes`
does that I/O; this module judges what it returns). SMTP and the OIDC identity provider have no
read-only self-inspection: an SMTP relay reports nothing about an account's rights, and the engine
has no read of the client registration at the IdP. For those this module prints the identity the
engine presents and the minimal privilege it needs, and reports ``not_probed`` with the reason.

**The LDAP probe proves identity and administrative-group membership, not rights.** Delegated
directory ACLs are not read, and the hop's detail says so even when it reads clean.

**The states are distinct on purpose.** ``unobservable`` (a probe that should have run and could not)
and ``not_probed`` (a hop with no probe at all) are different findings with different exit codes, the
same split the preflight draws between ``UNOBSERVABLE`` and ``NOT_APPLICABLE``.

**Nothing printed is a secret or PHI.** Identities are principal names, DNs, usernames, env-var
NAMES, Vault policy names and client ids, never a password, token, accessor or key; the store detail
has already been through the preflight's redactor. Every function here is pure: it reads its
arguments and nothing else.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from messagefoundry.config.settings import (
    SchemaManagement,
    SecurityEnforcement,
    ServiceSettings,
    SqlAuth,
    StoreBackend,
    StorePrivilegeStatus,
    StoreSettings,
)
from messagefoundry.store.privilege import (
    OVER_GRANT_OPT_OUT,
    SQLSERVER_DOCUMENTED_DATABASE_ROLES,
    SQLSERVER_RUNTIME_DATABASE_ROLES,
    PreflightOutcome,
    StorePrivilegeReport,
    preflight_outcome,
    refusal_reason,
)

if TYPE_CHECKING:
    from messagefoundry.auth.ldap import BindAccountReading
    from messagefoundry.privilege_probes import VaultTokenReading

__all__ = [
    "EXIT_CLEAN",
    "EXIT_OVER_PRIVILEGED",
    "EXIT_SETTINGS",
    "EXIT_UNOBSERVABLE",
    "VAULT_ADMIN_PATHS",
    "HopPrivilege",
    "HopState",
    "VaultConsumer",
    "ad_bind_configured",
    "administrative_group",
    "exit_code_for",
    "ldap_hop",
    "render_text",
    "serve_verdict",
    "settings_hops",
    "store_hop",
    "vault_consumers",
    "vault_hop",
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
    HopState.UNOBSERVABLE: "COULD NOT OBSERVE",
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


# --- Vault: one hop per token ------------------------------------------------------------------

#: Paths the engine never calls, asked about in the same capabilities read as the paths it does.
#: Any capability but ``deny`` on one means the token can widen its own reach: write a policy, mount
#: a secrets or auth engine, or mint a token. The names after the last slash are placeholders no
#: deployment uses; Vault answers with the policy that would apply to them.
VAULT_ADMIN_PATHS: tuple[str, ...] = (
    "sys/policies/acl/messagefoundry-check-privileges",
    "sys/mounts/messagefoundry-check-privileges",
    "sys/auth/messagefoundry-check-privileges",
    "auth/token/create",
)


@dataclass(frozen=True, slots=True)
class VaultConsumer:
    """One Vault token the engine is configured to use, and which of the three providers uses it:
    ``"kek"`` (the store key provider), ``"transit"`` (the store Transit cipher) or ``"kv"`` (the
    connector-secret provider, reading ``refs``). The probe dispatches on ``kind`` alone."""

    hop: str
    kind: str
    identity: str
    minimal: str
    refs: tuple[str, ...] = ()


def vault_consumers(settings: ServiceSettings) -> list[VaultConsumer]:
    """Each Vault token the settings put to use, in a fixed order: the store token, then the
    connector-secret token. Empty when no Vault consumer is configured."""
    store = settings.store
    out: list[VaultConsumer] = []
    # One consumer per branch, mirroring static_credentials._settings_hops: Transit replaces the key
    # provider rather than adding to it.
    if store.cipher_provider == "vault_transit":
        out.append(
            VaultConsumer(
                "vault.store",
                "transit",
                "store Transit cipher (token in MEFOR_STORE_VAULT_TOKEN)",
                "read on transit/keys/<data key> and transit/keys/<audit key>; update on "
                "transit/encrypt/<data key>, transit/decrypt/<data key> and transit/hmac/<audit key>",
            )
        )
    elif store.key_provider == "vault":
        out.append(
            VaultConsumer(
                "vault.store",
                "kek",
                "store key provider (token in MEFOR_STORE_VAULT_TOKEN)",
                "read on transit/keys/<KEK> and update on transit/decrypt/<KEK>",
            )
        )
    # The same reader as the settings:vault.secrets hop, so the two cannot disagree about which
    # references are resolved (BACKLOG #1989). Lazy: static_credentials imports the wiring module.
    from messagefoundry.config.static_credentials import resolved_secret_refs

    refs = resolved_secret_refs(settings)
    if settings.secrets.provider == "vault" and refs:
        out.append(
            VaultConsumer(
                "vault.secrets",
                "kv",
                f"connector secret provider for {len(refs)} reference(s) "
                "(token in MEFOR_SECRETS_VAULT_TOKEN)",
                "read on the KV v2 data path of each reference, and nothing else",
                tuple(refs),
            )
        )
    return out


def _caps(caps: Iterable[str]) -> str:
    return ", ".join(sorted(caps)) or "none"


def vault_hop(consumer: VaultConsumer, reading: VaultTokenReading) -> HopPrivilege:
    """Judge one token's self-reading against what the engine calls with it.

    Over-granted: a ``root`` policy; any capability beyond the one a configured path needs; or any
    capability but ``deny`` on an administrative path the engine never calls. A capability the
    engine needs and the token lacks is reported but is not an over-grant: the engine's own call
    would fail. Unobservable: any part of the reading could not be made, and no over-grant was seen.
    Over-grant wins, as it does in the exit code."""
    over: list[str] = []
    notes: list[str] = []
    if "root" in reading.policies:
        over.append("the token carries the root policy")
    for path, needed in reading.required.items():
        if path not in reading.capabilities:
            continue  # the probe already reports it as a problem
        got = set(reading.capabilities[path])
        excess = got - needed - {"deny"}  # needed never holds root, so a root grant is excess
        missing = set() if "root" in got else needed - got
        if excess:
            over.append(f"{path} also grants {_caps(excess)} (needs {_caps(needed)})")
        if missing:
            notes.append(f"{path} lacks {_caps(missing)}, so the engine's own call would fail")
    for path in VAULT_ADMIN_PATHS:
        extra = set(reading.capabilities.get(path, ())) - {"deny"}
        if extra:
            over.append(f"{path} grants {_caps(extra)}; the engine never calls it")

    seen: list[str] = []
    if reading.looked_up:
        if reading.ttl == 0:
            ttl = "no expiry"
        elif reading.ttl is None:
            ttl = "ttl not reported"
        else:
            ttl = f"ttl {reading.ttl}s"
        renew = {True: "renewable", False: "not renewable", None: "renewability not reported"}
        seen.append(
            f"token policies [{', '.join(reading.policies)}], {ttl}, {renew[reading.renewable]}"
        )
    checked = [p for p in reading.required if p in reading.capabilities]
    if checked:
        seen.append("; ".join(f"{p}: {_caps(reading.capabilities[p])}" for p in checked))
    if over:
        state = HopState.OVER_GRANTED
    elif reading.problems:
        state = HopState.UNOBSERVABLE
    else:
        state = HopState.CLEAN
    parts = [*(f"over-granted: {o}" for o in over), *seen, *notes]
    parts += [f"could not observe: {p}" for p in reading.problems]
    if state is HopState.CLEAN:
        parts.append(
            "paths the engine does not call were read only for the administrative ones; "
            "attest the rest of the policy by hand"
        )
    return HopPrivilege(consumer.hop, state, consumer.identity, consumer.minimal, ". ".join(parts))


# --- LDAP: the AD bind account ------------------------------------------------------------------

#: Well-known BUILTIN groups whose members administer the domain or its controllers (the MS-DTYP
#: well-known SID list). A SID is language-neutral, so a localised group name cannot hide one.
_ADMIN_BUILTIN_SIDS: dict[str, str] = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
}
#: Relative ids of a domain's own administrative groups, read off ``S-1-5-21-a-b-c-<rid>``. The same
#: three the config-directory ACL check treats as administrators (config/wiring.py).
_ADMIN_DOMAIN_RIDS: dict[int, str] = {
    512: "Domain Admins",
    518: "Schema Admins",
    519: "Enterprise Admins",
}
#: The same groups by name, for the direct ``memberOf`` read. A localised directory names them
#: differently, which is why the SID read comes first.
_ADMIN_GROUP_NAMES: dict[str, str] = {
    name.lower(): name for name in (*_ADMIN_BUILTIN_SIDS.values(), *_ADMIN_DOMAIN_RIDS.values())
}

_LDAP_RIGHTS_NOT_READ = (
    "rights not read: Who am I proves identity, and the group read covers administrative groups "
    "only; delegated directory ACLs (what the account may change, and where) are not read. "
    "Attest them by hand in the directory"
)


def administrative_group(sid: str) -> str | None:
    """The administrative group ``sid`` names, or ``None``. A domain SID must have exactly the
    ``S-1-5-21-a-b-c-<rid>`` shape with an ASCII rid, as the config-directory check requires."""
    if sid in _ADMIN_BUILTIN_SIDS:
        return _ADMIN_BUILTIN_SIDS[sid]
    parts = sid.split("-")
    rid = parts[-1]
    if len(parts) == 8 and sid.startswith("S-1-5-21-") and rid.isascii() and rid.isdigit():
        return _ADMIN_DOMAIN_RIDS.get(int(rid))
    return None


def ad_bind_configured(settings: ServiceSettings) -> bool:
    """AuthService, which holds the AD bind, is built only with ``[auth]`` enabled (BACKLOG #1989)."""
    return settings.auth.enabled and settings.auth.ad_enabled


def ldap_hop(settings: ServiceSettings, probe: Callable[[], BindAccountReading]) -> HopPrivilege:
    """Probe and judge the bind account, when AD is configured.

    Over-granted: any administrative group, by SID from ``tokenGroups`` (every nested and primary
    group) or, when that was unreadable, by name from the direct ``memberOf`` and ``primaryGroupID``.
    Clean: the transitive read found none. Unobservable: the bind or the read failed, or only the
    direct read was possible and it found none."""
    if not ad_bind_configured(settings):
        return _not_configured("ldap", "[auth].enabled or [auth].ad_enabled is off")
    auth = settings.auth
    identity = f"bind DN {auth.ad_bind_dn!r} on {auth.ad_server!r}"
    minimal = (
        "read and search on the user and group search bases; no write, no administrative group"
    )
    reading = probe()
    transitive = bool(reading.group_sids)
    if transitive:
        found = {g for sid in reading.group_sids if (g := administrative_group(sid))}
    else:
        # The canonical spelling, never the directory's, so nothing remote reaches the output.
        found = {
            _ADMIN_GROUP_NAMES[c.lower()]
            for c in reading.member_of
            if c.lower() in _ADMIN_GROUP_NAMES
        }
        if reading.primary_group_rid in _ADMIN_DOMAIN_RIDS:
            found.add(_ADMIN_DOMAIN_RIDS[reading.primary_group_rid])
    problem = reading.problem
    if problem is None and not transitive:
        problem = (
            "nested group membership not read: tokenGroups came back empty, so only the direct "
            "memberOf and primaryGroupID were read"
        )
    parts: list[str] = []
    if reading.authzid is not None:
        parts.append(f"Who am I: bound as {reading.authzid!r}")
    scope = "transitive, from tokenGroups" if transitive else "direct memberOf only"
    if found:
        state = HopState.OVER_GRANTED
        parts.insert(0, f"over-granted: member of {', '.join(sorted(found))} ({scope})")
    elif problem is not None:
        state = HopState.UNOBSERVABLE
    else:
        state = HopState.CLEAN
        parts.append(f"no administrative group ({scope})")
    if problem is not None:
        parts.append(f"could not observe: {problem}")
    parts.append(_LDAP_RIGHTS_NOT_READ)
    return HopPrivilege("ldap", state, identity, minimal, ". ".join(parts))


# --- the hops the engine cannot probe ---------------------------------------------------------

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
    # AuthService, which holds the OIDC client, is built only with [auth] enabled (BACKLOG #1989).
    if not (auth.enabled and auth.oidc_enabled):
        return _not_configured("idp", "[auth].enabled or [auth].oidc_enabled is off")
    return HopPrivilege(
        "idp",
        HopState.NOT_PROBED,
        f"OIDC client {auth.oidc_client_id!r} at {auth.oidc_issuer!r}",
        f"a confidential client allowed the scopes {' '.join(auth.oidc_scopes)!r} only; no "
        "directory or admin API permission",
        _NO_IDP_PROBE,
    )


def settings_hops(
    settings: ServiceSettings,
    *,
    vault_probe: Callable[[VaultConsumer], VaultTokenReading],
    ldap_probe: Callable[[], BindAccountReading],
) -> list[HopPrivilege]:
    """Every hop after the store, in a fixed order: the Vault tokens, LDAP, SMTP and the IdP.

    The probes are injected so this module stays free of I/O: each runs only for a hop the settings
    configure (:mod:`messagefoundry.privilege_probes` supplies the real ones)."""
    consumers = vault_consumers(settings)
    vault = (
        [vault_hop(c, vault_probe(c)) for c in consumers]
        if consumers
        else [_not_configured("vault", "no Vault consumer is configured")]
    )
    return [*vault, ldap_hop(settings, ldap_probe), _smtp_hop(settings), _idp_hop(settings)]


# --- the verdict ------------------------------------------------------------------------------


def exit_code_for(hops: Iterable[HopPrivilege]) -> int:
    """Over-privilege wins over could-not-observe; hops with no probe never fail the run."""
    states = {h.state for h in hops}
    if HopState.OVER_GRANTED in states:
        return EXIT_OVER_PRIVILEGED
    if HopState.UNOBSERVABLE in states:
        return EXIT_UNOBSERVABLE
    return EXIT_CLEAN


def serve_verdict(
    report: StorePrivilegeReport,
    settings: ServiceSettings,
    hops: Iterable[HopPrivilege] = (),
) -> str:
    """What ``serve`` would do at startup with this store observation under these settings (ADR 0199).

    The decision is the preflight's own :func:`~messagefoundry.store.privilege.preflight_outcome`, so
    the read-out and the serve gate cannot disagree. The exit code does NOT follow it: an over-grant
    exits 3 whether or not serve would start, because the grant is still wider than the runbook's.

    Only the store finding gates a start. When another hop in ``hops`` is over-granted, the verdict
    says so, so nobody reads a Vault or LDAP over-grant as one ``serve`` would refuse. Whether an
    observed Vault over-grant should refuse start under ``enforce``, as the store's does under
    ADR 0199, is left to its own change."""
    ungated = [h.hop for h in hops if h.hop != "store" and h.state is HopState.OVER_GRANTED]
    note = (
        f" (the over-grant on {', '.join(ungated)} is reported only; it does not gate a start)"
        if ungated
        else ""
    )
    return _store_verdict(report, settings) + note


def _store_verdict(report: StorePrivilegeReport, settings: ServiceSettings) -> str:
    enforcing = settings.security.enforcement is SecurityEnforcement.ENFORCE
    rlp = settings.store.require_least_privilege
    outcome = preflight_outcome(
        report,
        require_least_privilege=rlp,
        enforcing=enforcing,
        over_grant_accepted=settings.security.allow_over_granted_store_principal,
    )
    if outcome is PreflightOutcome.REFUSE:
        return f"would REFUSE to start: {refusal_reason(require_least_privilege=rlp)}"
    if outcome is PreflightOutcome.ACCEPTED:
        return f"would start: the over-grant is accepted by {OVER_GRANT_OPT_OUT} (audited)"
    if outcome is PreflightOutcome.WARN:
        why = "the probe could not observe the principal" if enforcing else "enforcement is 'warn'"
        return f"would start with a warning ({why})"
    return "would start: the store probe found nothing to refuse"


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
