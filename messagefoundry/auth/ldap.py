# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Active Directory authentication: LDAP simple-bind + nested-group resolution, and Kerberos SSO.

Pure (no FastAPI). ``ldap3`` does a service-account bind to locate the user, then a bind *as the
user* to verify the password, then resolves group membership (optionally nested via the AD matching
rule ``LDAP_MATCHING_RULE_IN_CHAIN``). Windows SSO is handled by a SPNEGO server step (``pyspnego``)
that yields the authenticated principal, whose groups are resolved the same way.

All calls here are **synchronous**; :class:`~messagefoundry.auth.service.AuthService` runs them via
``asyncio.to_thread`` so the event loop never blocks. That dispatch carries **no** ``asyncio.wait_for``,
so the only bound on an unresponsive domain controller is the pair of finite ``ldap3`` timeouts every
``Server``/``Connection`` here is constructed with — ``[auth].ad_connect_timeout`` (the TCP connect) and
``[auth].ad_receive_timeout`` (each LDAP response read), both defaulting to 10 s (ASVS 13.1.3). ldap3's
own defaults are ``None`` on both, i.e. wait forever. ``ldap3``/``spnego`` are imported lazily so a
local-only deployment never touches them.
"""

from __future__ import annotations

import logging
import ssl
import uuid
from dataclasses import dataclass
from typing import Any

from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AuthSettings,
    weakened_tls_escape_permitted,
)
from messagefoundry.config.tls_policy import HopPosture, assert_ldap3_tls_suites

logger = logging.getLogger(__name__)

_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"  # AD nested-group ("member in chain")

#: Operator-recognisable label for this hop in a TLS suite-assertion error (BACKLOG #1317). Pinned to
#: this file by ``test_every_covered_file_still_names_its_connector_label``.
_LDAPS_CONNECTOR = "AD LDAPS bind"

#: The directory attribute carrying the account's immutable identity (BACKLOG #1471). ``objectGUID``
#: is minted once per account object and survives a rename, a move between organizational units and a
#: change of ``sAMAccountName``; it is NOT reissued when a name is recycled to a different person,
#: which is the whole reason the engine binds on it.
_OBJECT_GUID_ATTR = "objectGUID"


@dataclass(frozen=True)
class AdPrincipal:
    """An authenticated AD user: identity attributes + the set of groups governing role mapping.

    ``groups`` holds **lower-cased** identifiers — both each group's DN and its ``sAMAccountName`` —
    so the admin can map roles by whichever form they configured in ``ad_group_role_map``.

    ``directory_object_id`` is the account's **immutable** directory identity (BACKLOG #1471): the
    normalised ``objectGUID``, which is what the engine resolves a MessageFoundry user row by. It
    defaults to ``None`` for the directory that returns no such attribute — an unreadable or trimmed
    attribute is not an identity claim, and the caller falls back to the username on that path. ``dn``
    is deliberately NOT that key: a DN changes on a rename or an OU move.
    """

    username: str
    display_name: str | None
    email: str | None
    dn: str
    groups: frozenset[str]
    directory_object_id: str | None = None


class LdapError(RuntimeError):
    """LDAP/Kerberos configuration or connectivity failure (distinct from rejected credentials)."""


def _escape_filter(value: str) -> str:
    """RFC 4515 escaping for values interpolated into an LDAP search filter."""
    out: list[str] = []
    for ch in value:
        if ch in "\\*()\x00":
            out.append("\\%02x" % ord(ch))  # noqa: UP031
        else:
            out.append(ch)
    return "".join(out)


def _attr(entry: Any, name: str) -> str | None:
    if name not in entry:
        return None
    value = entry[name].value
    return str(value) if value else None


def normalise_object_guid(value: object) -> str | None:
    """Render a directory ``objectGUID`` in ONE canonical text form, or ``None`` if it cannot be.

    BACKLOG #1471. ``objectGUID`` arrives in at least two shapes and **an identifier that renders two
    ways is not an identifier**: the raw 16 bytes off the wire, and the braced upper-case string
    ``ldap3``'s own formatter produces. Both normalise here to the lower-case hyphenated form without
    braces — the spelling Windows tooling shows — so a row bound through one shape is still found
    through the other. Do the conversion at this boundary and nowhere else; a second spelling created
    downstream is the same defect in a new place.

    **The 16 bytes are read little-endian** (``UUID(bytes_le=...)``), which is the Microsoft GUID
    layout: the first three fields are byte-swapped relative to RFC 4122. Reading them big-endian
    produces a well-formed UUID that is a DIFFERENT identifier, and nothing downstream could tell.

    ``None`` for a value of any other shape or length, and the caller then falls back to the username.
    Refusing the login instead was considered and not taken: an unexpected attribute shape is a
    directory-side condition, not an attack, and the fallback is the behaviour that shipped before
    this column existed. The caller logs it.
    """
    try:
        if isinstance(value, bytes | bytearray | memoryview):
            return str(uuid.UUID(bytes_le=bytes(value)))
        if isinstance(value, str):
            return str(uuid.UUID(value.strip()))
    except ValueError:
        # One rule applied to both shapes: the constructor already refuses a wrong length as well as
        # a malformed string, so there is no separate length guard to drift out of step with it.
        return None
    return None


#: Shapes of ``objectGUID`` already reported by :func:`_object_guid`, so the warning below fires once
#: per distinct shape rather than once per read. ``_find_user`` is NOT login-only: the ADR 0079
#: session reconciler probes it once per user per pass (``ad_session_recheck_seconds``, 300 by
#: default), so an unreadable attribute would otherwise emit one identical line per user every five
#: minutes. ``_probe_principal`` logs its own failure at DEBUG for exactly that reason; this keeps the
#: louder level and pays for it by saying each thing once.
_object_guid_shapes_warned: set[str] = set()


def _warn_once_about_object_guid(shape: str) -> None:
    """Report an unusable ``objectGUID`` once per distinct ``shape`` (a type name, or ``absent``)."""
    if shape in _object_guid_shapes_warned:
        return
    _object_guid_shapes_warned.add(shape)
    logger.warning(
        "AD %s is unusable (%s); these logins resolve by sAMAccountName, which a directory-side "
        "name recycle can redirect (BACKLOG #1471). Reported once per shape.",
        _OBJECT_GUID_ATTR,
        shape,
    )


def _object_guid(entry: Any) -> str | None:
    """The entry's normalised ``objectGUID`` (BACKLOG #1471), or ``None`` when it cannot be read.

    ``raw_values`` is preferred over ``value`` because it is the bytes off the wire, before whichever
    formatter ``ldap3`` has registered for this attribute has had an opinion about them.
    """
    if _OBJECT_GUID_ATTR not in entry:
        # AN ATTRIBUTE THE DIRECTORY NEVER RETURNS IS THE QUIETEST WAY TO BE ON THE OLD PATH, so it
        # is reported too. Every account at such a site resolves by name, and an operator who is told
        # nothing has no way to learn that the control they read about is not running for them.
        _warn_once_about_object_guid("absent")
        return None
    attr = entry[_OBJECT_GUID_ATTR]
    raw = getattr(attr, "raw_values", None)
    value = raw[0] if raw else attr.value
    text = normalise_object_guid(value)
    if text is None:
        # The value itself is NOT logged: it identifies a directory account, and the SHAPE is what a
        # reader needs in order to fix the read.
        _warn_once_about_object_guid(f"unreadable {type(value).__name__}")
    return text


def _multi(entry: Any, name: str) -> list[str]:
    if name not in entry:
        return []
    return [str(v) for v in entry[name].values]


def _cn_of(dn: str) -> str | None:
    head = dn.split(",", 1)[0]
    return head[3:] if head[:3].upper() == "CN=" else None


class LdapAuthenticator:
    """Binds against Active Directory over LDAPS and resolves a user's (nested) group membership."""

    def __init__(
        self,
        settings: AuthSettings,
        *,
        secret_provider: SecretProvider | None = None,
        posture: HopPosture | None = None,
    ) -> None:
        if not settings.ad_server or not settings.ad_user_search_base:
            raise LdapError("AD is enabled but ad_server / ad_user_search_base are not configured")
        # Resolve the effective service-account bind password ONCE at construction (ADR 0019 §5): from a
        # [secrets].provider when ad_bind_password_secret is set, else the env-sourced ad_bind_password
        # (byte-identical when no reference/provider). A configured-but-unresolvable reference fails closed
        # here (SecretProviderError propagates) — a blank bind is never used. Held on the instance so a
        # Vault-backed secret is fetched once, not on every authenticate().
        self._bind_password = resolve_connector_secret(
            secret_provider,
            ref=settings.ad_bind_password_secret,
            literal=settings.ad_bind_password,
            label="[auth].ad_bind_password",
        )
        if not settings.ad_bind_dn or not self._bind_password:
            raise LdapError("AD is enabled but the service-account bind is not configured")
        self._s = settings
        # One definition of "is this bind LDAPS", read by the verify-off refusal below, the suite
        # assertion, and _server(). The assertion would have been its third open-coded spelling.
        self._ldaps = str(settings.ad_server).lower().startswith("ldaps")
        # #329: the instance hop posture (threaded by AuthService from create_app's derived posture).
        # LDAPS is built OUT of the connector-construction gate (AuthService, not build_check_registry),
        # so current_hop_posture() would be None here; the posture must be passed explicitly or the
        # clamp below would be inert. None (a direct/test/embedding construction) falls back to the
        # unclamped escape — byte-identical to the pre-#329 bare read.
        self._posture = posture
        # A disabled-cert-verification posture (ad_tls_verify=false over LDAPS) would make the service-
        # account and user binds MITM-able on first deployment, so it REFUSES at startup unless the
        # operator sets the explicit MEFOR_ALLOW_INSECURE_TLS dev escape (ASVS 12.3.2). #329 routes that
        # escape through the ADR-0092 clamp (weakened_tls_escape_permitted): under an enforcing-PHI
        # posture the escape is INERT, so it can never silence this refusal on such an instance — the
        # blunt env var no longer buys verify-off there. With the escape permitted (non-enforcing/non-PHI
        # or unstamped posture), we still warn loudly once at startup.
        if self._ldaps and not settings.ad_tls_verify:
            if not weakened_tls_escape_permitted(self._posture):
                raise LdapError(
                    "ad_tls_verify=false disables LDAPS certificate verification (MITM risk). Use a "
                    f"trusted CA via ad_tls_ca_cert_file, or set {INSECURE_TLS_ESCAPE_ENV}=1 to "
                    "explicitly allow it for a trusted-network dev/test bind (refused on an enforcing "
                    "PHI instance even with that override set, #329)."
                )
            logger.warning(
                "AD LDAPS certificate verification is DISABLED (ad_tls_verify=false, permitted by "
                "%s) — the service-account and user binds are exposed to MITM; do not use in "
                "production.",
                INSECURE_TLS_ESCAPE_ENV,
            )
        # BACKLOG #1317. Assert the suite list this hop will negotiate (ASVS 12.1.2). Verification-off
        # is refused/warned above; this is the separate question of whether the traffic is ENCRYPTED and
        # the peer AUTHENTICATED at all, which was inherited from the interpreter default and unchecked.
        # Measured: the inherited list is clean today, so this raises on no supported configuration --
        # it converts an inherited property into a checked one, the same move harden_cipher_suites
        # documents. Done ONCE here rather than in _server() because the answer is fixed by config and
        # _server() runs up to three times per login; AuthService builds this eagerly, so a bad suite
        # list fails app startup rather than the first bind.
        if self._ldaps:
            assert_ldap3_tls_suites(self._tls_kwargs(), connector=_LDAPS_CONNECTOR)

    def _tls_kwargs(self) -> dict[str, Any]:
        """The ``ldap3.Tls`` arguments for this bind — the SINGLE definition, read by both consumers.

        ``__init__`` asserts the suite list these resolve to and ``_server()`` builds the real ``Tls``
        from them, so the two cannot drift onto different shapes. Keep it that way: the assertion runs
        against a REBUILT context (``ldap3.Tls`` holds no ``SSLContext`` to check directly), and a
        rebuilt context is only evidence about this hop while it is built from the hop's own arguments.
        """
        return {
            "validate": ssl.CERT_REQUIRED if self._s.ad_tls_verify else ssl.CERT_NONE,
            "ca_certs_file": self._s.ad_tls_ca_cert_file,
        }

    def _server(self) -> Any:
        import ldap3

        tls = None
        if self._ldaps:
            tls = ldap3.Tls(**self._tls_kwargs())
        # ASVS 13.1.3: ldap3's Server.connect_timeout defaults to None (wait forever) and the engine
        # never sets a process-wide socket default, so this is the ONLY bound on the TCP connect to the
        # domain controller. Every Server in this module is built here, so threading it here covers the
        # service-account bind AND the user bind.
        return ldap3.Server(
            self._s.ad_server,
            tls=tls,
            get_info=ldap3.NONE,
            connect_timeout=self._s.ad_connect_timeout,
        )

    def _service_conn(self) -> Any:
        import ldap3

        # ASVS 13.1.3: receive_timeout bounds every LDAP RESPONSE read on this connection (the bind and
        # each search). ldap3's default is None — an unresponsive DC would otherwise pin the thread-pool
        # worker AuthService dispatches this call on, since that dispatch has no asyncio.wait_for.
        return ldap3.Connection(
            self._server(),
            user=self._s.ad_bind_dn,
            password=self._bind_password,  # resolved once in __init__ (env or [secrets].provider)
            authentication=ldap3.SIMPLE,
            auto_bind=True,
            receive_timeout=self._s.ad_receive_timeout,
        )

    def _equalizing_bind(self, password: str) -> None:
        """Do the password-verifying bind's work for a principal that does not exist, and discard it.

        ASVS 6.3.8 (BACKLOG #1140). Builds the same second ``Server`` and ``Connection`` with the
        same finite ``receive_timeout``, binds against a DN that cannot exist under the configured
        search base, and unbinds — so the absent/disabled branch costs the same Server build, TCP
        connect and bind round trip as the present-and-enabled one.

        **Swallows every LDAP error, and that is load-bearing rather than lazy.** The caller wraps
        this in a handler that turns ``LDAPException`` into :class:`LdapError`, so letting a bind
        against a deliberately-bogus DN raise would turn a plain failed login into a *connectivity
        error* — a louder oracle than the timing one this exists to close, and a behaviour change on
        the ordinary wrong-username path.

        **What this does NOT claim:** that wall-clock is now provably equal. It equalizes the code
        PATH, which is what the item measured; a directory may still answer ``invalidCredentials``
        and a no-such-object in different times, and the group-resolution search on the success path
        remains unmatched. No timing measurement has been run here either.
        """
        import ldap3

        try:
            conn = ldap3.Connection(
                self._server(),
                # Cannot collide with a real principal: `mf-` prefixed, and a CN this shape is not
                # issued by the account provisioning any deployment of this engine would use.
                user=f"CN=mf-nonexistent-timing-equalizer,{self._s.ad_user_search_base}",
                password=password,
                authentication=ldap3.SIMPLE,
                receive_timeout=self._s.ad_receive_timeout,
            )
            try:
                conn.bind()  # result deliberately ignored — this branch always fails the login
            finally:
                conn.unbind()
        except ldap3.core.exceptions.LDAPException:
            return

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
                _OBJECT_GUID_ATTR,
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
            # BACKLOG #1471. Read through _object_guid, never _attr: that helper str()s whatever it
            # is given, which would render the raw 16 bytes as a Python bytes repr and store a
            # second, non-canonical spelling of the same identity.
            "object_id": _object_guid(e),
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
                    # ASVS 6.3.8 (BACKLOG #1140): an absent or disabled principal used to return
                    # HERE, skipping the whole second Server build, TCP connect and bind round trip
                    # below — so a valid username was deducible from response TIME behind an
                    # identical response. Do that work anyway and discard it. This is the AD leg's
                    # analogue of _DUMMY_PASSWORD_HASH on the local leg (auth/service.py).
                    #
                    # DELIBERATELY NOT THE OBVIOUS FIX: the disabled-bit check stays inside
                    # _find_user. It has TWO callers — this one binds, the Kerberos/SSO one below
                    # does not — so relocating it into the bind path alone would let a DISABLED
                    # ACCOUNT AUTHENTICATE OVER SSO. Equalize the CALLER, never move the check.
                    self._equalizing_bind(password)
                    return None
                user_dn = str(info["dn"])
                # The password-verifying bind — a SECOND connection (and a second Server, built by
                # _server() with its own connect_timeout). It carries the same finite receive_timeout
                # so a DC that accepts the TCP connect but never answers the bind cannot hang the
                # login thread (ASVS 13.1.3).
                user_conn = ldap3.Connection(
                    self._server(),
                    user=user_dn,
                    password=password,
                    authentication=ldap3.SIMPLE,
                    receive_timeout=self._s.ad_receive_timeout,
                )
                # Released on BOTH paths. A rejected password is the common adversarial case, so
                # returning early without unbinding would leave the connection to GC under exactly
                # the load that matters (ASVS 13.1.3 — resource release).
                try:
                    if not user_conn.bind():
                        return None
                finally:
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
            directory_object_id=info["object_id"],
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
            directory_object_id=info["object_id"],
        )


def kerberos_principal(token: bytes, settings: AuthSettings) -> str | None:
    """Complete one SPNEGO server step and return the authenticated sAMAccountName, or ``None``.

    Experimental — **not a supported v0.1 feature**: off by default (``kerberos_enabled=False``),
    production hardening (CI coverage, keytab/SPN preflight) targeted for 0.2. Single-leg only: no
    NTLM fallback, no mutual-auth response token, no multi-leg challenge handshake. The server must
    have a usable keytab/credential for ``kerberos_spn`` in its environment; the realm suffix
    (``user@REALM``) is stripped to yield the account name.
    """
    import struct

    import spnego

    try:  # pragma: no cover - requires a domain-joined server + keytab
        server = (
            spnego.server(service=settings.kerberos_spn)
            if settings.kerberos_spn
            else spnego.server()
        )
        server.step(token)
        principal = server.client_principal
    except (spnego.exceptions.SpnegoError, ValueError, struct.error) as exc:  # pragma: no cover
        # SpnegoError is the SSPI/GSSAPI (Windows/Linux-krb5) rejection; the pure-Python provider
        # instead raises a bare ValueError/struct.error while parsing an untrusted token. Both are
        # a failed SSO attempt — map to LdapError so authenticate_kerberos audits an
        # `auth.login_error` reject (AUTH-K-AUDIT) rather than escaping to an unaudited 500.
        raise LdapError(str(exc)) from exc
    if not principal:
        return None
    return str(principal).split("@", 1)[0]


def _kerberos_capable() -> bool:
    """Whether a **Kerberos-capable** SPNEGO provider is present — SSPI (Windows) or GSSAPI (Linux
    with the krb5 libraries). The pure-Python NTLM-only fallback cannot validate a Kerberos ticket,
    so browser SSO on such a host must degrade rather than advertise a dead link (ADR 0068 §9).
    Fails **open** (returns ``True``) if the provider APIs can't be introspected — it never newly
    blocks a deployment that works today."""
    import importlib

    try:
        for mod, cls in (("spnego._sspi", "SSPIProxy"), ("spnego._gss", "GSSAPIProxy")):
            try:
                proxy = getattr(importlib.import_module(mod), cls)
                if "kerberos" in proxy.available_protocols():
                    return True
            except Exception as exc:
                # An absent provider module is expected (SSPI on Linux, GSSAPI without krb5) — not an
                # error; record at debug and probe the next rather than swallowing silently.
                logger.debug("kerberos-capability probe skipped for %s.%s: %s", mod, cls, exc)
                continue
        return False
    except Exception:  # pragma: no cover - defensive: unknown provider layout ⇒ don't block
        return True


def kerberos_acceptor_preflight(settings: AuthSettings) -> None:
    """Construct the SPNEGO server acceptor once (the app-lifespan boot preflight, ADR 0068 §9).

    Raises :class:`LdapError` when browser SSO cannot actually work on this host — either no
    Kerberos-capable provider exists (the pure-Python NTLM fallback, e.g. a Linux install without
    the gssapi/krb5 libraries) or the acceptor can't be built (missing keytab/SPN credential) — so
    browser SSO degrades legibly at startup (providers ``kerberos=false``, the login-page link
    hidden, ``GET /ui/sso`` → ``e=sso_unavailable``) instead of advertising a dead link or failing
    per-request. Boot-once by design — a transient failure sticks until restart (recorded ADR 0068
    open item)."""
    import spnego

    if not _kerberos_capable():
        raise LdapError(
            "no Kerberos-capable SPNEGO provider on this host — SSPI (Windows) or the GSSAPI/krb5 "
            "libraries (Linux) are required; the pure-Python NTLM fallback cannot validate a ticket"
        )
    try:  # pragma: no cover - requires a domain-joined server + keytab
        if settings.kerberos_spn:
            spnego.server(service=settings.kerberos_spn)
        else:
            spnego.server()
    except spnego.exceptions.SpnegoError as exc:  # pragma: no cover
        raise LdapError(str(exc)) from exc
