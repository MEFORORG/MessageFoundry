"""Active Directory authentication: LDAP simple-bind + nested-group resolution, and Kerberos SSO.

Pure (no FastAPI). ``ldap3`` does a service-account bind to locate the user, then a bind *as the
user* to verify the password, then resolves group membership (optionally nested via the AD matching
rule ``LDAP_MATCHING_RULE_IN_CHAIN``). Windows SSO is handled by a SPNEGO server step (``pyspnego``)
that yields the authenticated principal, whose groups are resolved the same way.

All calls here are **synchronous**; :class:`~messagefoundry.auth.service.AuthService` runs them via
``asyncio.to_thread`` so the event loop never blocks. ``ldap3``/``spnego`` are imported lazily so a
local-only deployment never touches them.
"""

from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass
from typing import Any

from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AuthSettings,
    insecure_tls_allowed,
)

logger = logging.getLogger(__name__)

_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"  # AD nested-group ("member in chain")


@dataclass(frozen=True)
class AdPrincipal:
    """An authenticated AD user: identity attributes + the set of groups governing role mapping.

    ``groups`` holds **lower-cased** identifiers — both each group's DN and its ``sAMAccountName`` —
    so the admin can map roles by whichever form they configured in ``ad_group_role_map``.
    """

    username: str
    display_name: str | None
    email: str | None
    dn: str
    groups: frozenset[str]


class LdapError(RuntimeError):
    """LDAP/Kerberos configuration or connectivity failure (distinct from rejected credentials)."""


def _escape_filter(value: str) -> str:
    """RFC 4515 escaping for values interpolated into an LDAP search filter."""
    out: list[str] = []
    for ch in value:
        if ch in "\\*()\x00":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _attr(entry: Any, name: str) -> str | None:
    if name not in entry:
        return None
    value = entry[name].value
    return str(value) if value else None


def _multi(entry: Any, name: str) -> list[str]:
    if name not in entry:
        return []
    return [str(v) for v in entry[name].values]


def _cn_of(dn: str) -> str | None:
    head = dn.split(",", 1)[0]
    return head[3:] if head[:3].upper() == "CN=" else None


class LdapAuthenticator:
    """Binds against Active Directory over LDAPS and resolves a user's (nested) group membership."""

    def __init__(self, settings: AuthSettings) -> None:
        if not settings.ad_server or not settings.ad_user_search_base:
            raise LdapError("AD is enabled but ad_server / ad_user_search_base are not configured")
        if not settings.ad_bind_dn or not settings.ad_bind_password:
            raise LdapError("AD is enabled but the service-account bind is not configured")
        self._s = settings
        # A disabled-cert-verification posture (ad_tls_verify=false over LDAPS) makes the service-
        # account and user binds MITM-able, so it now REFUSES at startup unless the operator sets the
        # explicit MEFOR_ALLOW_INSECURE_TLS dev escape — it can no longer be silently turned on in
        # production (ASVS 12.3.2). With the escape set, we still warn loudly once at startup.
        if str(settings.ad_server).lower().startswith("ldaps") and not settings.ad_tls_verify:
            if not insecure_tls_allowed():
                raise LdapError(
                    "ad_tls_verify=false disables LDAPS certificate verification (MITM risk). Use a "
                    f"trusted CA via ad_tls_ca_cert_file, or set {INSECURE_TLS_ESCAPE_ENV}=1 to "
                    "explicitly allow it for a trusted-network dev/test bind."
                )
            logger.warning(
                "AD LDAPS certificate verification is DISABLED (ad_tls_verify=false, permitted by "
                "%s) — the service-account and user binds are exposed to MITM; do not use in "
                "production.",
                INSECURE_TLS_ESCAPE_ENV,
            )

    def _server(self) -> Any:
        import ldap3

        tls = None
        if str(self._s.ad_server).lower().startswith("ldaps"):
            validate = ssl.CERT_REQUIRED if self._s.ad_tls_verify else ssl.CERT_NONE
            tls = ldap3.Tls(validate=validate, ca_certs_file=self._s.ad_tls_ca_cert_file)
        return ldap3.Server(self._s.ad_server, tls=tls, get_info=ldap3.NONE)

    def _service_conn(self) -> Any:
        import ldap3

        return ldap3.Connection(
            self._server(),
            user=self._s.ad_bind_dn,
            password=self._s.ad_bind_password,
            authentication=ldap3.SIMPLE,
            auto_bind=True,
        )

    def _find_user(self, conn: Any, username: str) -> dict[str, Any] | None:
        import ldap3

        upn = f"{username}@{self._s.ad_domain}" if self._s.ad_domain else username
        conn.search(
            search_base=self._s.ad_user_search_base,
            search_filter=(
                f"(|(sAMAccountName={_escape_filter(username)})"
                f"(userPrincipalName={_escape_filter(upn)}))"
            ),
            search_scope=ldap3.SUBTREE,
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "displayName",
                "mail",
                "memberOf",
                "userAccountControl",
            ],
        )
        if not conn.entries:
            return None
        e = conn.entries[0]
        # ACCOUNTDISABLE (0x2): a disabled AD account must not authenticate. The local-user path
        # checks `disabled` up front; the AD password + Kerberos paths both go through here, so
        # rejecting a disabled account at the lookup covers both (review M-18).
        uac = _attr(e, "userAccountControl")
        if uac and uac.isdigit() and (int(uac) & 0x2):
            return None
        return {
            "dn": str(e.entry_dn),
            "username": _attr(e, "sAMAccountName") or username,
            "display_name": _attr(e, "displayName"),
            "email": _attr(e, "mail"),
            "memberOf": _multi(e, "memberOf"),
        }

    def _resolve_groups(self, conn: Any, user_dn: str, member_of: list[str]) -> frozenset[str]:
        import ldap3

        groups: set[str] = set()
        for dn in member_of:  # direct membership from the user's memberOf attribute
            groups.add(dn.lower())
            cn = _cn_of(dn)
            if cn:
                groups.add(cn.lower())
        if self._s.ad_use_nested_groups and self._s.ad_group_search_base:
            conn.search(
                search_base=self._s.ad_group_search_base,
                search_filter=f"(member:{_MATCHING_RULE_IN_CHAIN}:={_escape_filter(user_dn)})",
                search_scope=ldap3.SUBTREE,
                attributes=["distinguishedName", "sAMAccountName"],
            )
            for e in conn.entries:
                groups.add(str(e.entry_dn).lower())
                sam = _attr(e, "sAMAccountName")
                if sam:
                    groups.add(sam.lower())
        return frozenset(groups)

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        """Verify ``username``/``password`` against AD and return the principal, or ``None`` if the
        credentials are rejected. Raises :class:`LdapError` on a connectivity/config failure."""
        import ldap3

        if not password:  # never allow an empty password (it triggers an anonymous bind)
            return None
        try:
            with self._service_conn() as svc:
                info = self._find_user(svc, username)
                if info is None:
                    return None
                user_dn = str(info["dn"])
                user_conn = ldap3.Connection(
                    self._server(), user=user_dn, password=password, authentication=ldap3.SIMPLE
                )
                if not user_conn.bind():
                    return None
                user_conn.unbind()
                groups = self._resolve_groups(svc, user_dn, info["memberOf"])
        except ldap3.core.exceptions.LDAPException as exc:  # pragma: no cover - needs real AD
            raise LdapError(str(exc)) from exc
        return AdPrincipal(
            username=str(info["username"]),
            display_name=info["display_name"],
            email=info["email"],
            dn=user_dn,
            groups=groups,
        )

    def resolve_principal(self, username: str) -> AdPrincipal | None:
        """Look a user up + resolve groups *without* a password — for Kerberos, where SSO already
        proved the identity. Uses the service-account bind only."""
        import ldap3

        try:
            with self._service_conn() as svc:
                info = self._find_user(svc, username)
                if info is None:
                    return None
                user_dn = str(info["dn"])
                groups = self._resolve_groups(svc, user_dn, info["memberOf"])
        except ldap3.core.exceptions.LDAPException as exc:  # pragma: no cover - needs real AD
            raise LdapError(str(exc)) from exc
        return AdPrincipal(
            username=str(info["username"]),
            display_name=info["display_name"],
            email=info["email"],
            dn=user_dn,
            groups=groups,
        )


def kerberos_principal(token: bytes, settings: AuthSettings) -> str | None:
    """Complete one SPNEGO server step and return the authenticated sAMAccountName, or ``None``.

    Experimental — **not a supported v0.1 feature**: off by default (``kerberos_enabled=False``),
    production hardening (CI coverage, keytab/SPN preflight) targeted for 0.2. Single-leg only: no
    NTLM fallback, no mutual-auth response token, no multi-leg challenge handshake. The server must
    have a usable keytab/credential for ``kerberos_spn`` in its environment; the realm suffix
    (``user@REALM``) is stripped to yield the account name.
    """
    import spnego

    try:  # pragma: no cover - requires a domain-joined server + keytab
        server = (
            spnego.server(service=settings.kerberos_spn)
            if settings.kerberos_spn
            else spnego.server()
        )
        server.step(token)
        principal = server.client_principal
    except spnego.exceptions.SpnegoError as exc:  # pragma: no cover
        raise LdapError(str(exc)) from exc
    if not principal:
        return None
    return str(principal).split("@", 1)[0]
