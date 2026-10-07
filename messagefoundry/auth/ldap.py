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

**No referral is followed, and one is refused** (BACKLOG #2530); :func:`_refuse_referral` says why.
"""

from __future__ import annotations

import contextlib
import logging
import math
import re
import ssl
import struct
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple
from urllib.parse import urlsplit

from messagefoundry.auth.trust_anchors import ad_anchor_spec, verified_anchor_cadata
from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AuthSettings,
    is_ldaps_address,
    split_kerberos_spn,
    weakened_tls_escape_permitted,
)
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.redaction import safe_name

if TYPE_CHECKING:
    from messagefoundry.auth.ldap_tls import NarrowedTls

logger = logging.getLogger(__name__)

_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"  # AD nested-group ("member in chain")

#: Operator-recognisable label for this hop in a TLS suite-assertion error (BACKLOG #1317). Pinned to
#: this file by ``test_every_covered_file_still_names_its_connector_label``.
_LDAPS_CONNECTOR = "LDAPS bind to AD"

#: The directory attribute carrying the account's immutable identity (BACKLOG #1471). ``objectGUID``
#: is minted once per account object and survives a rename, a move between organizational units and a
#: change of ``sAMAccountName``; it is NOT reissued when a name is recycled to a different person,
#: which is the whole reason the engine binds on it.
_OBJECT_GUID_ATTR = "objectGUID"

#: The directory attribute whose ACCOUNTDISABLE bit (0x2) marks a disabled account (review M-18).
_UAC_ATTR = "userAccountControl"
_ACCOUNTDISABLE = 0x2


@dataclass(frozen=True)
class AdPrincipal:
    """An authenticated AD user: identity attributes + the set of groups governing role mapping.

    ``groups`` holds **lower-cased** identifiers — both each group's DN and its ``sAMAccountName`` —
    so the admin can map roles by whichever form they configured in ``ad_group_role_map``.

    ``directory_object_id`` is the account's **immutable** directory identity (BACKLOG #1471): the
    normalised ``objectGUID``, which is what the engine resolves a MessageFoundry user row by. It
    defaults to ``None`` for the directory that returns no such attribute — an unreadable or trimmed
    attribute is not an identity claim, and a sign-in on that path is refused (BACKLOG #2027). ``dn``
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


class LdapReferralError(LdapError):
    """The directory answered with a referral, which the engine never follows (BACKLOG #2530).

    A subclass, so every ``except LdapError`` still refuses it as before. The session reconciler
    tells it apart (BACKLOG #2538): a referral is a configuration error that recurs on every pass,
    not an outage that passes, so it must page rather than read as unavailable forever.
    """


class DirectoryAnswer(Enum):
    """What one password-free lookup of one account established (ADR 0195 rule item 2).

    At least three callers read this: the session reconciler, ``verify_mfa``'s directory check
    (BACKLOG #2023), which fails closed on anything but :attr:`FOUND`, and the step-up re-bind
    through :class:`DirectoryBind` (BACKLOG #2434). Each writes the answer only to the audit row, and
    every sign-in caller keeps its plain ``None`` for anything but :attr:`FOUND`, so the reason an
    account was refused never reaches a client.
    """

    #: The entry was found and ``userAccountControl`` proved it enabled.
    FOUND = "found"
    #: The search matched nothing, or an id-keyed probe held an id the filter builder cannot parse,
    #: so no search ran, or an id-keyed search's entry did not read back that id (BACKLOG #2027).
    NOT_FOUND = "not_found"
    #: The entry was found and ``userAccountControl`` read, with ACCOUNTDISABLE (0x2) set.
    DISABLED = "disabled"
    #: The entry was found and ``userAccountControl`` was absent, empty or not an integer. Refused
    #: like a disabled account on every sign-in path (BACKLOG #1639); told apart here so the
    #: reconciler can hold a wave of them (ADR 0195) instead of revoking it.
    UNDETERMINED = "undetermined"
    #: The search matched more than one entry, so none is provably the account asked about (vault
    #: BACKLOG #2778). Refused on every sign-in path; the reconciler reads it as absent, and the
    #: step-up re-bind audits it as ``not_in_directory`` and does not count it.
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class DirectoryBind:
    """One password bind: what its lookup found, and the principal when the bind succeeded.

    :meth:`LdapAuthenticator.authenticate` returns this (BACKLOG #2434), so the step-up re-bind can
    tell a refused password from an absent or disabled account without a second directory read.
    ``answer`` is ``None`` when no lookup ran, which only an empty password causes. ``FOUND`` with
    no principal means the entry was found enabled and the directory refused the bind, so the
    password was judged against that account. Any other answer means no bind was judged. None of
    this may reach a client: a sign-in caller must refuse every answer alike.
    """

    answer: DirectoryAnswer | None
    principal: AdPrincipal | None = None

    def __post_init__(self) -> None:
        # A principal only for FOUND: a bind that succeeded found its entry first.
        if self.principal is not None and self.answer is not DirectoryAnswer.FOUND:
            raise ValueError(f"DirectoryBind({self.answer}) with principal={self.principal!r}")


@dataclass(frozen=True)
class DirectoryProbe:
    """One reconciler lookup: the answer, and the principal when the answer is :attr:`FOUND`."""

    answer: DirectoryAnswer
    principal: AdPrincipal | None = None

    def __post_init__(self) -> None:
        # A principal exactly when the answer is FOUND. The reconciler maps every other answer to a
        # probe outcome, so a FOUND with no principal would have no outcome to read as.
        if (self.principal is not None) is not (self.answer is DirectoryAnswer.FOUND):
            raise ValueError(
                f"DirectoryProbe({self.answer.name}) with principal={self.principal!r}"
            )


def sid_text(raw: bytes) -> str | None:
    """A binary Windows SID (the MS-DTYP SID structure) as ``S-1-...`` text, or ``None`` if it is malformed.

    Not ldap3's ``format_sid``: that hands a malformed value back unchanged, and a caller comparing
    the result against a SID would then compare against raw bytes."""
    if len(raw) < 8 or len(raw) != 8 + 4 * raw[1]:
        return None
    authority = int.from_bytes(raw[2:8], "big")
    subs = (int.from_bytes(raw[8 + 4 * i : 12 + 4 * i], "little") for i in range(raw[1]))
    return "S-" + "-".join(str(part) for part in (raw[0], authority, *subs))


@dataclass(frozen=True, slots=True)
class BindAccountReading:
    """What the service-account bind can read about itself (BACKLOG #305, ASVS 13.2.2). Facts
    only: ``privilege_check`` judges them.

    ``authzid`` is the RFC 4532 "Who am I?" answer: the identity the directory says the bind
    authenticated as. It proves identity, not rights. ``group_sids`` is the account's own
    ``tokenGroups``, which AD computes over every nested group and the primary group; empty when it
    could not be read. ``member_of`` (the CN of each direct ``memberOf``) is the direct read for when
    it could not. ``primary_group_rid`` is read either way: a RID cannot be faked by a group name. ``problem`` says what could not be read. Nothing
    here is a secret: no password is held."""

    authzid: str | None
    group_sids: tuple[str, ...] = ()
    member_of: tuple[str, ...] = ()
    primary_group_rid: int | None = None
    problem: str | None = None
    #: False when no bind was made at all, so nothing here was read from the directory.
    bound: bool = True
    #: Why Who am I failed after a good bind, when it raised rather than answering. ``None`` when
    #: it answered, even with no identity.
    whoami_error: str | None = None


class _Lookup(NamedTuple):
    """One user search: the answer, and the extracted entry when the answer is FOUND."""

    answer: DirectoryAnswer
    info: dict[str, Any] | None = None


def _ldap3_receive_timeout(seconds: float) -> int:
    """``[auth].ad_receive_timeout`` as the whole seconds ldap3 can actually apply on every OS.

    ldap3 sets ``SO_RCVTIMEO`` with ``struct.pack('LL', receive_timeout, 0)`` on every non-Windows
    host, and ``struct.pack`` refuses a float. The setting is a float (default ``10.0``), so passing
    it straight through made EVERY ldap3 socket open raise ``struct.error`` on Linux after the TCP
    connect and before the bind was sent: AD sign-in could not work there at all. Windows hides it,
    because ldap3 converts with ``int(1000 * t)`` on that branch.

    Rounds UP, never to nearest, so the result is never shorter than the operator configured. The
    cost is a timeout up to one second longer on every OS: ldap3 first calls
    ``socket.settimeout(receive_timeout)``, which would have kept sub-second precision. Rounding up
    also never yields 0. The settings validator already refuses values <= 0, and 0 would make
    ``settimeout`` turn the socket non-blocking, so every read would fail at once.
    """
    return math.ceil(seconds)


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

    ``None`` for a value of any other shape or length. The caller logs it, and since BACKLOG #2027 a
    Windows SSO sign-in or step-up re-bind with no id is refused. Falling back to the username was
    the earlier choice, and it left a directory-side name recycle able to redirect the account.
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


def object_guid_filter_value(object_id: str) -> str | None:
    r"""Render a canonical ``objectGUID`` text form as an LDAP filter value, or ``None`` if it cannot.

    A directory does not answer ``(objectGUID=b3e1...-...)``. The attribute's syntax is **octet
    string**, so the filter carries the 16 raw bytes, each escaped as ``\hh`` (RFC 4515 section 3) --
    the form Microsoft's own tooling emits. The bytes are ``bytes_le``, the same little-endian layout
    :func:`normalise_object_guid` reads them back with, so a value that round-trips through the store
    asks the directory about the account it came from.

    **The output contains no caller-supplied text**, which is why it needs no
    :func:`_escape_filter` pass: every character is one of ``\`` or a lower-case hex digit, produced
    here from 16 validated bytes. A malformed id yields ``None`` rather than a filter, so a value the
    parser cannot read can never reach a search string.
    """
    try:
        raw = uuid.UUID(object_id.strip()).bytes_le
    except (ValueError, AttributeError):
        return None
    return "".join(f"\\{b:02x}" for b in raw)


def _principal_from(info: dict[str, Any], user_dn: str, groups: frozenset[str]) -> AdPrincipal:
    """Build an :class:`AdPrincipal` from one ``_search_user`` mapping.

    One construction for all three lookups. A new field on ``AdPrincipal`` otherwise has to be added
    in three places, and the copy most likely to be missed is the reconciler's -- which carries
    ``# pragma: no cover`` on its error path and has no real-AD coverage at all.
    """
    return AdPrincipal(
        username=str(info["username"]),
        display_name=info["display_name"],
        email=info["email"],
        dn=user_dn,
        groups=groups,
        directory_object_id=info["object_id"],
    )


#: Shapes of ``objectGUID`` already reported by :func:`_object_guid`, so the warning below fires once
#: per distinct shape rather than once per read. ``_find_user`` is NOT login-only: the ADR 0079
#: session reconciler probes it once per user per pass (``ad_session_recheck_seconds``, 300 by
#: default), so an unreadable attribute would otherwise emit one identical line per user every five
#: minutes. ``_probe_principal`` logs its own failure at DEBUG for exactly that reason; this keeps the
#: louder level and pays for it by saying each thing once. Since vault BACKLOG #2778 it also holds
#: ``ambiguous:<label>`` keys, one per name that matched more than one entry.
_object_guid_shapes_warned: set[str] = set()


def _warn_once(cause: str, message: str, *args: object) -> None:
    """Log ``message`` at WARNING the first time ``cause`` is seen in this process, never again."""
    if cause in _object_guid_shapes_warned:
        return
    _object_guid_shapes_warned.add(cause)
    logger.warning(message, *args)


#: What an id-keyed lookup does with an account whose entry is refused, stated once for both
#: warnings below (BACKLOG #1471, #2027).
_REFUSAL_EFFECT = (
    "sign-ins and step-ups that need these accounts' ids are refused, and the directory recheck "
    "reads an account found by its id as absent, so it ends that account's sessions after "
    "[auth].ad_session_recheck_strikes passes"
)


def _warn_once_about_object_guid(shape: str) -> None:
    """Report an unusable ``objectGUID`` once per distinct ``shape`` (a type name, or ``absent``)."""
    _warn_once(
        shape,
        "AD %s is unusable (%s); %s. A directory can recycle a name, so the engine will not fall "
        "back to it (BACKLOG #1471, #2027). Reported once per shape.",
        _OBJECT_GUID_ATTR,
        shape,
        _REFUSAL_EFFECT,
    )


def _warn_once_about_foreign_object_guid() -> None:
    """Report, once, an id-keyed search whose entry reads back ANOTHER object's ``objectGUID``.

    Told apart from :func:`_warn_once_about_object_guid`: the attribute is readable here, so the
    cause is the directory answering the filter with the wrong entry, not the attribute's access or
    shape. Neither value is logged; each identifies a directory account. The cause key holds an
    apostrophe, which no shape key (``absent``, ``unreadable <type name>``) can.
    """
    _warn_once(
        "another object's id",
        "An AD search by %s returned an entry carrying a different %s; it is treated as no match. "
        "%s (BACKLOG #2027). Reported once.",
        _OBJECT_GUID_ATTR,
        _OBJECT_GUID_ATTR,
        _REFUSAL_EFFECT,
    )


def _object_guid(entry: Any) -> str | None:
    """The entry's normalised ``objectGUID`` (BACKLOG #1471), or ``None`` when it cannot be read.

    ``raw_values`` is preferred over ``value`` because it is the bytes off the wire, before whichever
    formatter ``ldap3`` has registered for this attribute has had an opinion about them.
    """
    if _OBJECT_GUID_ATTR not in entry:
        # AN ATTRIBUTE THE DIRECTORY NEVER RETURNS IS THE QUIETEST WAY TO FAIL, so it is reported
        # too. Every Windows SSO sign-in at such a site is refused (BACKLOG #2027), and an operator
        # who is told nothing sees only refusals, with no hint that the attribute is the cause.
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


#: Shapes of an unusable ``userAccountControl`` already reported by :func:`_account_state`. Same
#: reasoning as the ``objectGUID`` latch above: the reconciler reads every signed-in user every pass,
#: and a bind account that cannot read the attribute makes EVERY entry unusable at once.
_uac_shapes_warned: set[str] = set()


def _warn_once_about_user_account_control(shape: str) -> None:
    """Report an unusable ``userAccountControl`` once per distinct ``shape``."""
    if shape in _uac_shapes_warned:
        return
    _uac_shapes_warned.add(shape)
    logger.warning(
        "AD %s is unusable (%s), so the engine cannot tell whether these accounts are disabled; "
        "their AD logins are refused. The session reconciler may hold their sessions rather than "
        "revoke them, and raises the ad_reconcile_held alert while it does (ADR 0195 states the "
        "rule). Check that the [auth].ad_bind_dn service account can read this attribute and that "
        "it arrives as an integer (BACKLOG #1639). Reported once per shape.",
        _UAC_ATTR,
        shape,
    )


def _account_enabled(entry: Any) -> bool:
    """Whether the entry's ``userAccountControl`` proves the account ENABLED. Fails closed.

    BACKLOG #1639. ``True`` only for a readable integer with ACCOUNTDISABLE (0x2) clear. An absent,
    empty or non-integer attribute is ``False``, the same answer a disabled account gets: the check
    must not pass on a value it could not read. Before this, a bind account without read rights on
    the attribute saw every principal as enabled, so a directory-disabled account would still sign
    in and keep its sessions through the reconciler. :func:`_account_state` says which refusal it
    was; only the reconciler asks.
    """
    return _account_state(entry) is DirectoryAnswer.FOUND


def _account_state(entry: Any) -> DirectoryAnswer:
    """Read ``userAccountControl`` three ways: FOUND (enabled), DISABLED, or UNDETERMINED.

    ADR 0195 rule item 1. DISABLED is a readable flag word with ACCOUNTDISABLE (0x2) set.
    UNDETERMINED is an absent, empty or non-integer attribute, and warns once per shape.

    The parse is ``int()`` inside a ``ValueError`` handler, and it is lenient rather than strict:
    whatever ``int()`` reads as an integer is taken as the flag word. What it must never do is
    raise out of the lookup; the old ``str.isdigit()`` guard could, because ``isdigit`` accepts
    superscript digits that ``int`` rejects. The value itself is never logged; the shape is what a
    reader needs in order to fix the read.

    **The only property checked is ACCOUNTDISABLE**, as before this item. Expiry
    (``accountExpires``) and lockout are not read here.
    """
    if _UAC_ATTR not in entry:
        shape = "absent"
    else:
        value = entry[_UAC_ATTR].value
        # bool is an int subclass, and True is not a flag word. int() itself refuses an empty or
        # blank string, so that case needs no guard of its own.
        if isinstance(value, int | str | bytes) and not isinstance(value, bool):
            try:
                flags = int(value)
            except ValueError:
                pass
            else:
                return (
                    DirectoryAnswer.DISABLED if flags & _ACCOUNTDISABLE else DirectoryAnswer.FOUND
                )
        # ldap3 can return an attribute it asked for and did not receive as present with no value
        # (its return_empty_attributes option), so "empty" is usually the same fact as "absent".
        blank = isinstance(value, str | bytes) and not value.strip()
        shape = "empty" if blank or not value else f"non-numeric {type(value).__name__}"
    _warn_once_about_user_account_control(shape)
    return DirectoryAnswer.UNDETERMINED


def _multi(entry: Any, name: str) -> list[str]:
    if name not in entry:
        return []
    return [str(v) for v in entry[name].values]


def _cn_of(dn: str) -> str | None:
    head = dn.split(",", 1)[0]
    return head[3:] if head[:3].upper() == "CN=" else None


#: A referred host the refusal may name. Anything else is replaced, because the text comes from the
#: directory and is written to the log and the audit row.
_PRINTABLE_HOST = re.compile(r"[A-Za-z0-9._:\[\]-]{1,253}")

#: How many referred hosts the refusal names before it only counts the rest.
_HOSTS_NAMED = 3


def _referred_hosts(referrals: Iterable[object]) -> str:
    """The hosts ``referrals`` point at, for the refusal. Never the whole URL.

    An LDAP URL can carry a DN, a filter and extensions (RFC 4516), and a bindname extension would
    name an account. Only the host part says where the directory tried to send the engine.
    """
    hosts: set[str] = set()
    unreadable = False
    for uri in referrals:
        try:
            host = urlsplit(str(uri)).hostname
        except ValueError:
            host = None
        if host and _PRINTABLE_HOST.fullmatch(host):
            hosts.add(host)
        else:
            unreadable = True
    # Readable hosts take the named slots; an unreadable one is only ever listed last.
    shown = sorted(hosts) + (["<unreadable host>"] if unreadable else [])
    named = shown[:_HOSTS_NAMED]
    more = len(shown) - len(named)
    return ", ".join(named) + (f" and {more} more" if more else "") or "<no host given>"


def _refuse_referral(conn: Any, operation: str) -> None:
    """Raise :class:`LdapReferralError` when the directory answered ``conn``'s last operation with a
    referral.

    BACKLOG #2530. With ``auto_referrals`` on, which is ldap3's default, ldap3 2.9.1 opens a new
    connection to the referred host and, on a bound connection, binds there with this connection's
    user and password (``strategy/base.py``, ``create_referral_connection``). It builds a plain
    ``ldap3.Tls`` for that hop: no pinned CA bytes, no narrowed suites, and none at all for an
    ``ldap://`` referral. So one referral would carry the service-account password off the anchored
    hop. Every ``Connection`` here is built with ``auto_referrals=False``, so ldap3 hands the
    referral back instead, and this turns it into a refusal.

    **A refusal, not a "no match" or a wrong password.** Left alone, a referred search reads as no
    entries, which the session reconciler would count toward revoking the account. A referred bind
    reads as a rejected password, which the step-up re-bind would count toward the engine lockout.
    An :class:`LdapError` is audited as ``auth.login_error`` at sign-in. The reconciler reads this
    subclass as referred, which never revokes that account and alerts (BACKLOG #2538). A
    referral usually means a search base in another domain of the forest.

    **Only a referral RESULT (resultCode 10).** A search continuation reference (``searchResRef``)
    arrives with resultCode 0, beside the entries. ldap3 never follows one, with or without this
    item, so it leaks nothing, and it still reads as no entry from that subtree. AD adds such
    references to every search based at a domain root, so refusing them would refuse every search.
    """
    from ldap3.core.results import RESULT_REFERRAL  # lazy, like every ldap3 import here

    result = conn.result
    if not isinstance(result, dict) or result.get("result") != RESULT_REFERRAL:
        return
    hosts = _referred_hosts(result.get("referrals") or ())
    message = (
        f"AD answered the {operation} with a referral to {hosts}; the engine does not follow "
        "referrals, because ldap3 would re-send the bind credentials there without the pinned CA "
        "(BACKLOG #2530). This usually means a configured search base lies in another domain of "
        "the forest; use a base in this domain controller's own domain, or a global catalog, "
        "which carries universal-group membership only (ADR 0180 Amendment F)."
    )
    _warn_once(f"referral: {operation}", "%s Reported once per operation.", message)
    raise LdapReferralError(message)


def _search(conn: Any, operation: str, **kwargs: Any) -> None:
    """``conn.search(**kwargs)``, refusing a referral result. Every search in this module goes
    through here, so none can read one as "no entries"; a test pins that."""
    conn.search(**kwargs)
    _refuse_referral(conn, operation)


#: What opening an ldap3 socket can raise that is not an ldap3 error (BACKLOG #2566). ldap3's
#: ``_open_socket`` wraps a ``socket.error`` in its own ``LDAPSocketOpenError``, but not what
#: ``settimeout`` and ``setsockopt`` raise on a bad value: ``OverflowError``, ``TypeError``, or the
#: ``struct.error`` BACKLOG #2546 found. With one candidate address, ``open()`` re-raises that fault
#: bare. ``ValueError`` is a host name that fails IDNA encoding in ``getaddrinfo``, which runs outside
#: ldap3's per-address try. ``OSError`` covers what else escapes. At least these; others still escape.
_SOCKET_FAULTS: tuple[type[Exception], ...] = (
    OSError,
    OverflowError,
    TypeError,
    ValueError,
    struct.error,
)


@contextlib.contextmanager
def _socket_faults_as_ldap_error() -> Iterator[None]:
    """Turn a :data:`_SOCKET_FAULTS` error from the ldap3 call inside into :class:`LdapError`.

    Every caller maps ``LdapError`` to a directory failure, and the sign-in callers write
    ``auth.login_error``, so an unmapped fault would skip both and surface as an unhandled error.

    **It wraps only the ldap3 calls that OPEN a socket**: the service account's ``auto_bind``
    construction and the explicit binds. An operation on an open socket needs none, because ldap3
    already re-raises a ``socket.error`` there as its own ``LDAPSocket*Error``. A wider wrap would
    catch the engine's own defects, such as a ``TypeError`` from a bad keyword or from parsing an
    answer. Mapped, that reads as a directory outage, which the session reconciler holds on and logs
    at debug level, so the defect would hide.

    Two wraps are wider than the open, and each says why. The ``auto_bind`` construction checks its
    keywords and opens in one call, so a renamed ldap3 keyword there would map; the real-ldap3 arms
    of ``tests/test_ldap_referrals.py`` build that connection, so one would fail there first. And
    ``authenticate`` wraps the whole decoy bind, which must neither map nor swallow by itself.

    An ``LDAPException`` passes through untouched, even one that is also an ``OSError``,
    ``TypeError`` or ``ValueError``, so its own handler keeps its own text. The new text is fixed
    and names only the type: a fault's message is not the engine's to repeat. **That holds only for
    a fault that reaches this wrap bare.** With more than one candidate address, ldap3 bundles each
    address's fault into ``LDAPSocketOpenError``, whose text the ldap3 handler keeps.
    """
    import ldap3

    try:
        yield
    except ldap3.core.exceptions.LDAPException:
        raise
    except _SOCKET_FAULTS as exc:
        kind = type(exc)
        # The type alone, never str(exc). struct.error's own name is just "error", so a type from
        # outside builtins carries its module.
        name = (
            kind.__qualname__
            if kind.__module__ == "builtins"
            else f"{kind.__module__}.{kind.__qualname__}"
        )
        raise LdapError(f"AD directory call failed: {name}") from exc


class LdapAuthenticator:
    """Binds against Active Directory over LDAPS and resolves a user's (nested) group membership."""

    def __init__(
        self,
        settings: AuthSettings,
        *,
        secret_provider: SecretProvider | None = None,
        posture: HopPosture | None = None,
        enforcing: bool = True,
    ) -> None:
        if not settings.ad_server or not settings.ad_user_search_base:
            raise LdapError("AD is enabled but ad_server / ad_user_search_base are not configured")
        # One definition of "is this bind LDAPS", read by the plain-bind refusal and the verify-off
        # refusal below, the suite assertion, and _server(). It is the settings module's own test, so
        # this and AuthSettings agree: a bare host that merely starts with "ldaps" is plain (#2354).
        self._ldaps = is_ldaps_address(str(settings.ad_server))
        # Vault BACKLOG #2354: a plain bind sends both passwords in cleartext. ServiceSettings refuses
        # it at load under [security].enforcement = enforce; this repeats that refusal for a caller that
        # hands over an AuthSettings alone. It refuses if EITHER dial input says enforce: `enforcing`
        # (the [security].enforcement dial, defaulting to enforce) or a known enforcing `posture`. It
        # runs before the bind secret is resolved, so a refused build never fetches the password.
        if not self._ldaps:
            if not settings.ad_allow_insecure_ldap:
                # AuthSettings requires the opt-in only while ad_enabled; a direct construction can
                # carry ad_enabled = false, so check it here too rather than assume it.
                raise LdapError(
                    "ad_server is not an ldaps:// address; a plain bind needs "
                    "ad_allow_insecure_ldap = true under [security].enforcement = warn."
                )
            if enforcing or (posture is not None and posture.enforcing):
                raise LdapError(
                    "ad_server is not an ldaps:// address, and ad_allow_insecure_ldap is inert under "
                    "[security].enforcement = enforce (the binds would send passwords in cleartext). "
                    "Use an ldaps:// ad_server."
                )
            logger.warning(
                "AD binds over plain ldap:// (ad_allow_insecure_ldap=true, honoured because "
                "[security].enforcement = warn) -- the service-account and user passwords cross the "
                "network in cleartext; do not use in production."
            )
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
        # BACKLOG #2034 (ASVS 6.7.1): check [auth].ad_tls_ca_cert_file ONCE, here, and keep the bytes
        # the pin, ACL and path check read. Every bind hands ldap3 those bytes as ca_certs_data, so a
        # file swapped after this check is never trusted. ldap3 used to get the path, and read the
        # file again on every bind. `enforcing` is the [security].enforcement dial, as for the OIDC
        # anchor: a pin mismatch always refuses, and an anchor others can replace refuses at enforce.
        # Only an LDAPS bind loads a CA; a plain ldap:// bind builds no Tls at all. So rotating the AD
        # CA now takes a restart, as the OIDC anchor already did: a reload re-checks and audits the
        # file, but no reload rebuilds this authenticator.
        self._ca_certs_data: str | None = None
        spec = ad_anchor_spec(settings)
        if self._ldaps and spec is not None:
            self._ca_certs_data = verified_anchor_cadata(spec, enforcing=enforcing)
        # #329: the instance hop posture (threaded by AuthService from create_app's derived posture).
        # LDAPS is built OUT of the connector-construction gate (AuthService, not build_check_registry),
        # so current_hop_posture() would be None here; the posture must be passed explicitly or the
        # escape below is refused. None (a direct/test/embedding construction) FAILS CLOSED: the escape
        # is not permitted (vault BACKLOG #2354). CORRECTED: this read that None *"falls back to the
        # unclamped escape -- byte-identical to the pre-#329 bare read"*; weakened_tls_escape_permitted
        # stopped doing that in engine PR 1886.
        self._posture = posture
        # A disabled-cert-verification posture (ad_tls_verify=false over LDAPS) would make the service-
        # account and user binds MITM-able on first deployment, so it REFUSES at startup unless the
        # operator sets the explicit MEFOR_ALLOW_INSECURE_TLS dev escape (ASVS 12.3.2). #329 routes that
        # escape through the ADR-0092 clamp (weakened_tls_escape_permitted): under an enforcing-PHI
        # posture the escape is INERT, so it can never silence this refusal on such an instance — the
        # blunt env var no longer buys verify-off there. With the escape permitted (a known, non-enforcing
        # posture; an unstamped one now refuses), we still warn loudly once at startup.
        if self._ldaps and not settings.ad_tls_verify:
            if not weakened_tls_escape_permitted(self._posture):
                raise LdapError(
                    "ad_tls_verify=false disables LDAPS certificate verification (MITM risk). Use a "
                    f"trusted CA via ad_tls_ca_cert_file, or set {INSECURE_TLS_ESCAPE_ENV}=1 on an "
                    "instance at [security].enforcement = warn to explicitly allow it for a "
                    "trusted-network dev/test bind (the override has no effect while enforcing, the "
                    "default, or with no posture)."
                )
            logger.warning(
                "LDAPS certificate verification for AD is DISABLED (ad_tls_verify=false, permitted by "
                "%s at [security].enforcement = warn) — the service-account and user binds are "
                "exposed to MITM; do not use in production.",
                INSECURE_TLS_ESCAPE_ENV,
            )
        # BACKLOG #1317, #2494. The engine builds this hop's TLS context (ASVS 12.1.2): narrowed to the
        # approved suites at TLS 1.2 and, where the interpreter allows it, TLS 1.3, then asserted.
        # Verification-off is refused/warned above; this is the separate question of whether the
        # traffic is ENCRYPTED and the peer AUTHENTICATED at all. NarrowedTls builds and asserts that
        # context once here, so a bad one fails app startup (AuthService builds this eagerly), and
        # again for every connection. One Tls serves every Server: ldap3.Tls holds only settings.
        # The CA goes in as the bytes checked above, never a path (BACKLOG #2034); None loads the OS
        # trust store, as ldap3 did. The accepted risk of owner ruling 2026-09-27 stands: an older
        # domain controller that offers none of the approved suites fails to bind.
        self._tls: NarrowedTls | None = None
        if self._ldaps:
            from messagefoundry.auth.ldap_tls import NarrowedTls  # lazy: it imports ldap3

            self._tls = NarrowedTls(
                validate=ssl.CERT_REQUIRED if settings.ad_tls_verify else ssl.CERT_NONE,
                ca_certs_data=self._ca_certs_data,
                connector=_LDAPS_CONNECTOR,
            )

    def _server(self) -> Any:
        import ldap3

        # ASVS 13.1.3: ldap3's Server.connect_timeout defaults to None (wait forever) and the engine
        # never sets a process-wide socket default, so this is the ONLY bound on the TCP connect to the
        # domain controller. Every Server in this module is built here, so threading it here covers the
        # service-account bind AND the user bind.
        return ldap3.Server(
            self._s.ad_server,
            tls=self._tls,
            get_info=ldap3.NONE,
            connect_timeout=self._s.ad_connect_timeout,
            # BACKLOG #2530, see _refuse_referral. ldap3's default, None, admits every host; empty
            # admits none, so this holds even for a Connection that omits auto_referrals=False.
            allowed_referral_hosts=[],
        )

    def _service_conn(self) -> Any:
        import ldap3

        # ASVS 13.1.3: receive_timeout bounds every LDAP RESPONSE read on this connection (the bind and
        # each search). ldap3's default is None — an unresponsive DC would otherwise pin the thread-pool
        # worker AuthService dispatches this call on, since that dispatch has no asyncio.wait_for.
        # auto_bind opens the socket here, so a socket fault surfaces here (BACKLOG #2566). The
        # Server is built outside the wrap to keep engine code out of it. The timeout conversion
        # stays inline, because tests/test_ldap_timeouts.py checks for that call at this site.
        server = self._server()
        with _socket_faults_as_ldap_error():
            return ldap3.Connection(
                server,
                user=self._s.ad_bind_dn,
                password=self._bind_password,  # resolved once in __init__ (env or a provider)
                authentication=ldap3.SIMPLE,
                auto_bind=True,
                receive_timeout=_ldap3_receive_timeout(self._s.ad_receive_timeout),
                auto_referrals=False,  # BACKLOG #2530: see _refuse_referral
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

        **A socket fault that is not an ldap3 error is NOT swallowed (BACKLOG #2566).** It propagates,
        and ``authenticate`` maps it to :class:`LdapError` exactly as it maps the real bind's. Both
        branches open a socket to the same directory, so such a fault fails them alike; swallowing
        it here alone would answer "wrong password" for an absent account and "directory error" for
        a present one.

        **What #2566 does not settle:** ldap3's OWN socket errors still differ between the branches.
        This method swallows an ``LDAPSocketOpenError`` while the real bind's handler maps it, so a
        directory that fails only the second connect answers the two differently. That predates
        #2566 and is not changed here.

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
                receive_timeout=_ldap3_receive_timeout(self._s.ad_receive_timeout),
                auto_referrals=False,  # BACKLOG #2530: see _refuse_referral
            )
            try:
                conn.bind()  # result deliberately ignored — this branch always fails the login
            finally:
                conn.unbind()
        except ldap3.core.exceptions.LDAPException:
            return

    def _search_user(
        self,
        conn: Any,
        search_filter: str,
        *,
        fallback_username: str,
        expected_object_id: str | None = None,
    ) -> _Lookup:
        """Run one user search and extract the entry. ``info`` is ``None`` for no match, more than
        one match (``AMBIGUOUS``, vault BACKLOG #2778), a disabled account or an undetermined one,
        and ``answer`` says which (ADR 0195 rule item 2).

        ``expected_object_id``, the canonical id an id-keyed search asked for, makes an entry that
        does not read it back a no-match, before its account state is read (BACKLOG #2027). See
        :meth:`_lookup_by_object_id`.

        The filter is the caller's; everything after it -- the attribute list, the ACCOUNTDISABLE
        rejection and the extraction -- is shared by both lookups on purpose. **The two lookups differ
        only in which question they ask the directory**, and an attribute list that drifted between
        them would give the name-keyed and id-keyed paths different views of the same account.

        ``fallback_username`` is what to call the account when the entry carries no
        ``sAMAccountName``. For the name-keyed lookup that is the name searched for; for the id-keyed
        one it is the name already stored on the row, so a directory that answers with no name leaves
        the cached one alone rather than inventing a rename.
        """
        import ldap3

        _search(
            conn,
            "user search",
            search_base=self._s.ad_user_search_base,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                _OBJECT_GUID_ATTR,
                "displayName",
                "mail",
                "memberOf",
                _UAC_ATTR,
            ],
        )
        if not conn.entries:
            return _Lookup(DirectoryAnswer.NOT_FOUND)
        if len(conn.entries) > 1:
            # Vault BACKLOG #2778. The name filter matches sAMAccountName OR userPrincipalName, and
            # a directory may legally give one account a UPN prefix equal to another's
            # sAMAccountName. Taking entries[0] would let the server's result order pick which
            # account signs in. No entry is provably the one asked about, so none is. Logged with
            # a label for the name and the count only, once per name: the attempts repeat at
            # sign-in rate, and the set of names stays bounded by the collisions the directory holds.
            label = safe_name(fallback_username)
            _warn_once(
                f"ambiguous:{label}",
                "AD user search for %s matched %d directory entries; refusing it as ambiguous "
                "(logged once per name)",
                label,
                len(conn.entries),
            )
            return _Lookup(DirectoryAnswer.AMBIGUOUS)
        e = conn.entries[0]
        own: str | None = None
        if expected_object_id is not None:
            own = _object_guid(e)
            if own != expected_object_id:
                if own is not None:  # an absent or unreadable id already warned in _object_guid
                    _warn_once_about_foreign_object_guid()
                return _Lookup(DirectoryAnswer.NOT_FOUND)
        # ACCOUNTDISABLE (0x2): a disabled AD account must not authenticate. The local-user path
        # checks `disabled` up front; the AD password + Kerberos paths both go through here, so
        # rejecting a disabled account at the lookup covers both (review M-18). An UNREADABLE
        # attribute is refused the same way (BACKLOG #1639): every sign-in caller reads `info` alone
        # and sees `None` for both. The session reconciler also reads `answer`, which tells a set
        # bit from an unreadable one, so it can hold a wave of unreadable answers (ADR 0195).
        # Answering rather than raising is deliberate: the reconciler reads an `LdapError` as
        # UNAVAILABLE, which never revokes, and that would be the same fail-open in a new place.
        state = _account_state(e)
        if state is not DirectoryAnswer.FOUND:
            return _Lookup(state)
        return _Lookup(
            DirectoryAnswer.FOUND,
            {
                "dn": str(e.entry_dn),
                "username": _attr(e, "sAMAccountName") or fallback_username,
                # BACKLOG #1471. Read through _object_guid, never _attr: that helper str()s whatever it
                # is given, which would render the raw 16 bytes as a Python bytes repr and store a
                # second, non-canonical spelling of the same identity.
                # An id-keyed lookup has already read it, and proved it equal to the id asked for.
                "object_id": own if expected_object_id is not None else _object_guid(e),
                "display_name": _attr(e, "displayName"),
                "email": _attr(e, "mail"),
                "memberOf": _multi(e, "memberOf"),
            },
        )

    def _find_user(self, conn: Any, username: str) -> dict[str, Any] | None:
        return self._lookup_by_name(conn, username).info

    def _lookup_by_name(self, conn: Any, username: str) -> _Lookup:
        upn = f"{username}@{self._s.ad_domain}" if self._s.ad_domain else username
        return self._search_user(
            conn,
            (
                f"(|(sAMAccountName={_escape_filter(username)})"
                f"(userPrincipalName={_escape_filter(upn)}))"
            ),
            fallback_username=username,
        )

    def _lookup_by_object_id(self, conn: Any, object_id: str, *, fallback_username: str) -> _Lookup:
        """Find a user by the directory's immutable ``objectGUID`` rather than by a name.

        This is the lookup a **renamed** account needs. A name-keyed search asks a question the
        directory stopped answering the moment the name changed, and its "no match" is the same answer
        it gives for a deleted or disabled account -- so a rename read as an offboarding.

        **THE ENTRY MUST READ BACK THE ID IT WAS FOUND BY (BACKLOG #2027, ADR 0184 AC-5).** The entry's
        own ``objectGUID`` is read separately from the filter that found it. An entry whose id is
        absent, unreadable, or another object's is not provably the account asked about, so it is
        answered :attr:`DirectoryAnswer.NOT_FOUND`: no entry was found that is this account. That is
        decided before the entry's account state, so a disabled foreign entry is a no-match too.
        Checked on this one path because every id-keyed answer comes through it: ``authenticate``'s
        bind entry, and ``probe_principal`` and ``resolve_principal``, which serve the step-up legs,
        the federated re-resolve and the session reconciler. So ``authenticate`` never binds the
        typed password as such an entry, and the reconciler never reads another entry's name as a
        rename. **The cost:** a directory-wide change that hides ``objectGUID`` reads as a wave of
        absent accounts. The reconciler's mass-revocation abort stops a large wave, but not one at
        or below its absolute floor, so on a small estate those sessions end after the strike
        threshold. The warnings above say so.
        """
        value = object_guid_filter_value(object_id)
        expected = normalise_object_guid(object_id)
        if value is None or expected is None:
            # A stored id the filter builder cannot parse. Refusing to search is the honest answer:
            # a search with no filter, or one falling back to the name, would report on a different
            # question than the one asked. The reconciler reads it as ABSENT (ADR 0195 rule item 1).
            return _Lookup(DirectoryAnswer.NOT_FOUND)
        return self._search_user(
            conn,
            f"({_OBJECT_GUID_ATTR}={value})",
            fallback_username=fallback_username,
            # Never None here, so the read-back check cannot be skipped by the two parsers drifting.
            expected_object_id=expected,
        )

    def _resolve_groups(self, conn: Any, user_dn: str, member_of: list[str]) -> frozenset[str]:
        import ldap3

        groups: set[str] = set()
        for dn in member_of:  # direct membership from the user's memberOf attribute
            groups.add(dn.lower())
            cn = _cn_of(dn)
            if cn:
                groups.add(cn.lower())
        if self._s.ad_use_nested_groups and self._s.ad_group_search_base:
            _search(
                conn,
                "group search",
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

    def authenticate(
        self, username: str, password: str, *, object_id: str | None = None
    ) -> DirectoryBind:
        """Verify ``username``/``password`` against AD. Raises :class:`LdapError` on a
        connectivity/config failure.

        The answer carries the principal on success, and otherwise says what the lookup found
        (:class:`DirectoryBind`, BACKLOG #2434). Before that it returned ``None`` for a wrong
        password and for an absent or disabled account alike, so the step-up re-bind made a second
        lookup to tell them apart and still could not tell absent from disabled.

        ``object_id`` picks the entry to bind as by its ``objectGUID`` rather than by the name, the
        same key rule as :meth:`resolve_principal` (BACKLOG #2027). The step-up re-bind passes the
        row's id, so the typed password goes to that account's own entry and never to whoever a
        directory has since given the name to, and a renamed account still binds."""
        import ldap3

        if not password:  # never allow an empty password (it triggers an anonymous bind)
            return DirectoryBind(None)
        try:
            with self._service_conn() as svc:
                found = (
                    self._lookup_by_object_id(svc, object_id, fallback_username=username)
                    if object_id is not None
                    else self._lookup_by_name(svc, username)
                )
                info = found.info
                if info is None:
                    # ASVS 6.3.8 (BACKLOG #1140): an absent or disabled principal used to return
                    # HERE, skipping the whole second Server build, TCP connect and bind round trip
                    # below — so a valid username was deducible from response TIME behind an
                    # identical response. Do that work anyway and discard it. This is the AD leg's
                    # analogue of _DUMMY_PASSWORD_HASH on the local leg (auth/service.py).
                    #
                    # DELIBERATELY NOT THE OBVIOUS FIX: the disabled-bit check stays inside the
                    # shared lookup (_search_user). It has more than one caller -- this one binds,
                    # the Kerberos/SSO one below does not -- so relocating it into the bind path
                    # alone would let a DISABLED ACCOUNT AUTHENTICATE OVER SSO. Equalize the CALLER, never move the check.
                    #
                    # A _SOCKET_FAULTS error in the decoy is mapped HERE, the same way the real
                    # bind's is below, so for those types an absent and a present account fail
                    # alike (BACKLOG #2566). Swallowing it inside _equalizing_bind would tell the two
                    # apart. That method's docstring says what this does not settle.
                    with _socket_faults_as_ldap_error():
                        self._equalizing_bind(password)
                    return DirectoryBind(found.answer)
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
                    receive_timeout=_ldap3_receive_timeout(self._s.ad_receive_timeout),
                    auto_referrals=False,  # BACKLOG #2530: see _refuse_referral
                )
                # Released on BOTH paths. A rejected password is the common adversarial case, so
                # returning early without unbinding would leave the connection to GC under exactly
                # the load that matters (ASVS 13.1.3 — resource release).
                try:
                    # BACKLOG #2566: the bind opens the socket, so only the bind is wrapped. The
                    # build above does no I/O, and the release runs on an open socket.
                    with _socket_faults_as_ldap_error():
                        bound = user_conn.bind()
                    if not bound:
                        _refuse_referral(user_conn, "user bind")
                        # The entry was found enabled, so the refusal judged this account.
                        return DirectoryBind(DirectoryAnswer.FOUND)
                finally:
                    user_conn.unbind()
                groups = self._resolve_groups(svc, user_dn, info["memberOf"])
        except ldap3.core.exceptions.LDAPException as exc:
            raise LdapError(str(exc)) from exc
        return DirectoryBind(DirectoryAnswer.FOUND, _principal_from(info, user_dn, groups))

    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        """Look a user up + resolve groups *without* a password. Uses the service-account bind only.

        For Kerberos, where SSO already proved the identity, and for the ADR 0079 session reconciler.

        **``object_id`` WINS WHEN GIVEN, and choosing here rather than at the call site is the point
        (BACKLOG #1532).** ``username`` is a label a directory may reassign; ``objectGUID`` is not. A
        caller that holds the account's id passes it and gets an answer that survives a rename -- the
        returned principal carries the directory's **current** ``sAMAccountName``, so a caller holding
        a stale cached name learns the new one here. A caller that has only a name passes only a name
        and gets the old behaviour, which is all a directory returning no readable ``objectGUID`` can
        ever support.

        That matters because a name-keyed miss and a rename are the **same** answer: ``None``, which
        the reconciler reads as "the account is gone". Letting each caller assemble its own key
        preference is how that stayed wrong for a release; there is one rule and it lives here.

        ``username`` is still required, and is what the principal reports when the matched entry
        carries no ``sAMAccountName`` of its own -- an absent attribute is not the directory announcing
        a rename to nothing.
        """
        return self.probe_principal(username, object_id=object_id).principal

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        """:meth:`resolve_principal`, also saying WHY an account did not resolve (ADR 0195).

        The session reconciler's lookup, and ``verify_mfa``'s before it renews a directory
        account's step-up window (BACKLOG #2023). A change to its answers reaches both, and the
        second fails closed on anything but FOUND. Same key choice, same service-account bind,
        same refusals: :meth:`resolve_principal` is this method with the answer dropped, so the two
        cannot drift. The answer tells a search that matched nothing from a set disabled bit and from
        an unreadable ``userAccountControl``; the reconciler holds a wave of the last kind rather
        than revoking it. Raises :class:`LdapError` on a connectivity or configuration failure,
        exactly as :meth:`resolve_principal` does.
        """
        import ldap3

        try:
            with self._service_conn() as svc:
                found = (
                    self._lookup_by_object_id(svc, object_id, fallback_username=username)
                    if object_id is not None
                    else self._lookup_by_name(svc, username)
                )
                info = found.info
                if info is None:
                    return DirectoryProbe(found.answer)
                user_dn = str(info["dn"])
                groups = self._resolve_groups(svc, user_dn, info["memberOf"])
        except ldap3.core.exceptions.LDAPException as exc:
            raise LdapError(str(exc)) from exc
        return DirectoryProbe(DirectoryAnswer.FOUND, _principal_from(info, user_dn, groups))

    def read_bind_account(self) -> BindAccountReading:
        """Who the service-account bind is, and which groups it is in, read-only.

        For ``check-privileges`` (BACKLOG #305, ASVS 13.2.2). It opens the same connection every
        lookup here opens -- the LDAPS bind with the narrowed, anchored TLS context, finite timeouts
        and no referral following -- and only reads: the RFC 4532 "Who am I?" extended operation,
        then one BASE-scope read of ``[auth].ad_bind_dn``'s own entry. It never writes.

        Raises :class:`LdapError` when the bind itself fails. A failed group read is reported in
        :attr:`BindAccountReading.problem` instead, so the identity the bind proved is kept."""
        import ldap3

        try:
            svc = self._service_conn()
        except ldap3.core.exceptions.LDAPException as exc:
            raise LdapError(str(exc)) from exc
        # Unbound explicitly: ldap3's context manager does not unbind a connection that was already
        # bound when it entered, which auto_bind makes every one here, so the session would stay
        # open until the object is collected.
        try:
            # Its own try: the bind has already succeeded here, so a failed Who am I is not a bind
            # failure, and the group read still runs.
            whoami_error: str | None = None
            try:
                who = _authzid_text(svc.extend.standard.who_am_i())
            except ldap3.core.exceptions.LDAPException as exc:
                # The type name only, as the group read below does: ldap3's text for an
                # extended-operation error carries the directory's own diagnostic message.
                who, whoami_error = None, f"Who am I failed: {type(exc).__name__}"
            try:
                _search(
                    svc,
                    "bind-account group read",
                    search_base=self._s.ad_bind_dn,
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["tokenGroups", "memberOf", "primaryGroupID"],
                )
            except (ldap3.core.exceptions.LDAPException, LdapError) as exc:
                # An LdapError is a refused referral, whose text is the engine's own.
                why = str(exc) if isinstance(exc, LdapError) else type(exc).__name__
                return BindAccountReading(
                    who, problem=f"group membership not read: {why}", whoami_error=whoami_error
                )
            entry = svc.entries[0] if svc.entries else None
            result = svc.result if isinstance(svc.result, dict) else {}
        except ldap3.core.exceptions.LDAPException as exc:
            raise LdapError(str(exc)) from exc
        finally:
            with contextlib.suppress(ldap3.core.exceptions.LDAPException):
                svc.unbind()
        if entry is None:
            # ldap3 does not raise on a failed search here, so the result code is the only record of
            # why: invalidDNSyntax for a bind identity that is a UPN or DOMAIN\\user rather than a
            # DN, insufficientAccessRights for an entry the account may not read.
            why = result.get("description") or "no result code"
            return BindAccountReading(
                who,
                problem=f"group membership not read: the base read of [auth].ad_bind_dn returned "
                f"no entry ({why}); the read needs a distinguished name the account may read",
                whoami_error=whoami_error,
            )
        raw = entry["tokenGroups"].raw_values if "tokenGroups" in entry else ()
        sids = tuple(
            sid for v in raw if isinstance(v, (bytes, bytearray)) and (sid := sid_text(bytes(v)))
        )
        rid = _attr(entry, "primaryGroupID")
        return BindAccountReading(
            who,
            group_sids=sids,
            member_of=tuple(cn for dn in _multi(entry, "memberOf") if (cn := _cn_of(dn))),
            primary_group_rid=int(rid) if rid and rid.isascii() and rid.isdigit() else None,
            whoami_error=whoami_error,
        )


def _authzid_text(value: object) -> str | None:
    """The "Who am I?" answer as printable text, or ``None`` for an anonymous or absent one."""
    from messagefoundry.controlchars import strip_control_chars

    return strip_control_chars(str(value)) if value else None


def _kerberos_acceptor(settings: AuthSettings) -> Any:
    """Build the SPNEGO acceptor for ``kerberos_spn`` -- the one place both call sites share.

    pyspnego takes the SPN as two arguments, ``hostname`` and ``service``, and joins them itself.
    Passing the whole ``HTTP/host`` as ``service=`` built ``HTTP/host/unspecified`` (BACKLOG #275).
    A malformed value raises ``ValueError``; the settings validator refuses it at load first.
    """
    import spnego

    if not settings.kerberos_spn:
        return spnego.server()
    service, hostname = split_kerberos_spn(settings.kerberos_spn)
    return spnego.server(hostname=hostname, service=service)


def kerberos_principal(token: bytes, settings: AuthSettings) -> str | None:
    """Complete one SPNEGO server step and return the authenticated sAMAccountName, or ``None``.

    Experimental — **not a supported v0.1 feature**: off by default (``kerberos_enabled=False``),
    production hardening (CI coverage, keytab/SPN preflight) targeted for 0.2. Single-leg only: no
    NTLM fallback, no mutual-auth response token, no multi-leg challenge handshake. The server must
    have a usable keytab/credential for ``kerberos_spn`` in its environment; the realm suffix
    (``user@REALM``) is stripped to yield the account name.
    """
    import spnego

    try:
        server = _kerberos_acceptor(settings)
        server.step(token)
        principal = server.client_principal
    except (spnego.exceptions.SpnegoError, ValueError, struct.error) as exc:
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
    try:
        _kerberos_acceptor(settings)
    except (spnego.exceptions.SpnegoError, ValueError) as exc:
        raise LdapError(str(exc)) from exc
