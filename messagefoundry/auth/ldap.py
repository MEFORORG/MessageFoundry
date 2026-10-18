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
own defaults are ``None`` on both, i.e. wait forever. All the pages of the paged nested group search
also share one ``[auth].ad_group_search_deadline`` (:func:`_search_paged`, BACKLOG #3696).
``ldap3``/``spnego`` are imported lazily so a local-only deployment never touches them.

**No referral is followed, and one is refused** (BACKLOG #2530); :func:`_refuse_referral` says why.
**A search that ends with any result code but success is refused too** (BACKLOG #3010), never read
as no entries; :func:`_refuse_unanswered` says why.
"""

from __future__ import annotations

import contextlib
import logging
import math
import re
import ssl
import struct
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from types import FrameType
from typing import TYPE_CHECKING, Any, NamedTuple, NoReturn
from urllib.parse import urlsplit

from messagefoundry.auth.trust_anchors import ad_anchor_spec, verified_anchor_cadata
from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import (
    AuthSettings,
    is_ldaps_address,
    split_kerberos_spn,
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

    ``groups`` holds each group's **distinguished name in canonical form** (lower-cased, escaped
    one way: :func:`canonical_group_dn`), and nothing else. The group
    maps take a full DN only (BACKLOG #2610): a short name is unique in no sense the engine can
    check, so a same-named group in another unit would grant the mapped roles.

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


class KerberosTokenRefused(Exception):
    """The SPNEGO acceptor refused the client's token (BACKLOG #3186, #3196).

    Not an :class:`LdapError`: the directory was never asked, and the caller audits it as a refused
    sign-in, not an outage. ``error_type`` is the class name of whatever the acceptor's step raised.
    That set is open, since the step catches every exception, but the token never chooses a name.
    The message is dropped, because it can quote the token.
    """

    def __init__(self, error_type: str) -> None:
        super().__init__(f"SPNEGO token refused: {error_type}")
        self.error_type = error_type


class LdapReferralError(LdapError):
    """The directory answered with a referral, which the engine never follows (BACKLOG #2530).

    A subclass, so every ``except LdapError`` still refuses it as before. The session reconciler
    tells it apart (BACKLOG #2538): a referral is a configuration error that recurs on every pass,
    not an outage that passes, so it must page rather than read as unavailable forever. The step-up
    re-bind does not tell it apart (``AuthService._reauth_ad``): it refuses every ``LdapError`` as
    ``directory_unavailable`` and counts none, which is right for a referral, because the engine
    never follows one, so no bind judged the password (BACKLOG #3169).
    """


class LdapUnansweredError(LdapError):
    """The directory ended an operation with a result code that is not an answer (BACKLOG #3010).

    A subclass, so every ``except LdapError`` handles it as before; :func:`_refuse_unanswered` says
    what that means for each of its callers. A user bind raises it too, through
    :func:`_refuse_unjudged_bind` (BACKLOG #3169), and the step-up re-bind
    (``AuthService._reauth_ad``) reads it as ``directory_unavailable``, not counted. ``code`` is
    the result code, or ``None`` when the result held none that is an integer or a paged search was
    refused for its paging (:func:`_search_paged`); ``code_name`` is ldap3's name for the code, or
    the engine's for the case, never text the directory sent.
    Both default, so the exception survives a copy or a pickle, which rebuild it from its message
    and then restore both from its ``__dict__``.
    """

    def __init__(
        self, message: str, *, code: int | None = None, code_name: str = "no code"
    ) -> None:
        super().__init__(message)
        self.code = code
        self.code_name = code_name


class LdapUndecodableError(LdapError):
    """ldap3 could not decode the directory's response to an operation (BACKLOG #3010).

    :func:`_ldap3_call` raises it. A subclass, so every ``except LdapError`` catches it. A caller
    that must tell it from an outage catches it first, as the session reconciler's probe does
    (``AuthService._probe_principal``). Its own class keeps a paged search that met one from being
    abandoned (:func:`_search_paged`). No result code was read, so none is claimed: the text names
    the type of the exception ldap3 raised, never its text or a value the directory sent.
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
    #: The search ended with success and matched nothing, or an id-keyed probe held an id the
    #: filter builder cannot parse, so no search ran, or an id-keyed search's entry did not read
    #: back that id (BACKLOG #2027). A search that ended with any other result code raises
    #: :class:`LdapUnansweredError` instead (BACKLOG #3010).
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
    no principal means the entry was found enabled and the directory refused the bind with a code
    outside :data:`_UNJUDGED_BIND_CODES` that is not a referral (10), or with a result that holds no
    integer code at all, which the step-up re-bind counts too. A bind on a found entry that
    ends with a referral or a code inside that set returns no answer at all: ``authenticate``
    raises it instead (BACKLOG #2530, #3169). The engine reads every other refusal as the password
    judged against that account, though a code such as strongerAuthRequired (8) judges none. Any other answer means no bind was judged. None of
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
    in three places, and the copy most likely to be missed is the reconciler's, which has no
    real-AD coverage at all.
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


#: The fewest RDNs a group map key may hold (BACKLOG #2610). One RDN, such as ``CN=Admins``, names a
#: group in no particular unit, which is the short-name match this rule exists to remove.
_GROUP_DN_MIN_RDNS = 2


_ASCII_LETTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_ASCII_DIGITS = frozenset("0123456789")
_DESCR_REST = _ASCII_LETTERS | _ASCII_DIGITS | {"-"}
_HEX = frozenset("0123456789abcdefABCDEF")


def _is_dn_attr_type(name: str) -> bool:
    """Whether ``name`` is an attribute type: a name (RFC 4512 ``descr``) or a dotted OID.

    A character loop rather than a regex, so the parser holds no quantified group a static ReDoS
    scan must clear (BACKLOG #2610). ASCII only, as ``[0-9]`` was: ``str.isdigit`` would admit
    other scripts' digits."""
    if name[:1] in _ASCII_LETTERS:
        return all(ch in _DESCR_REST for ch in name[1:])
    return all(part and all(ch in _ASCII_DIGITS for ch in part) for part in name.split("."))


#: Characters a canonical value escapes with a backslash wherever they appear (RFC 4514 section 2.4).
_DN_ESCAPED = frozenset('\\"+,;<>')
#: The one padding token: an unescaped space at either end of a value (RFC 4514 section 3). Only a
#: space. A tab or line break is part of the value, so ``CN=Admins<TAB>`` names a different group.
_DN_PAD = (b" ", False)


def _hex_escaped(ch: str) -> str:
    """``ch`` as ``\\xx`` escapes of its UTF-8 bytes, lower-case hex so ``str.lower()`` keeps it."""
    return "".join(f"\\{b:02x}" for b in ch.encode("utf-8"))


def _canonical_value(tokens: list[tuple[bytes, bool]]) -> str | None:
    """One attribute value, case-folded and re-escaped, or ``None``.

    ``tokens`` holds each character or hex pair as ``(bytes, escaped)``. An unescaped space at
    either end is padding, so it is dropped. An unescaped ``#`` at the start would make the value a
    BER hex string, which no group map needs, so it is refused.

    **The output is printable ASCII, and only ASCII letters fold case.** Every other character is
    written as ``\\xx`` escapes of its UTF-8 bytes, in lower-case hex. Python's Unicode case tables
    fold some characters onto a different letter (the Kelvin sign onto ``k``) and pair scripts AD's
    own table may keep apart, and a SQL Server column under a case- and width-insensitive collation
    folds far more. An all-ASCII key with no upper-case letter means none of those can merge two
    groups, and the store's ``strip().lower()`` is a no-op on it. **The cost fails closed:** a
    non-ASCII letter matches only in the case it was written in, so ``CN=Ärzte`` and ``CN=ärzte``
    name different keys. Copy a key from the directory's own spelling.

    The plain space is the one exception to escaping, and only inside a value. At either end it is
    written ``\\20``, so a key never starts or ends with white space."""
    first, last = 0, len(tokens)
    while first < last and tokens[first] == _DN_PAD:
        first += 1
    while last > first and tokens[last - 1] == _DN_PAD:
        last -= 1
    tokens = tokens[first:last]
    if not tokens or tokens[0] == (b"#", False):
        return None
    try:
        raw = b"".join(part for part, _escaped in tokens).decode("utf-8")
    except UnicodeDecodeError:
        return None
    out = []
    for i, ch in enumerate(raw):
        if ch in _DN_ESCAPED or (ch == "#" and i == 0):
            out.append("\\" + ch)
        elif ch == " ":
            out.append("\\20" if i in (0, len(raw) - 1) else " ")
        elif "!" <= ch <= "~":  # printable ASCII other than the space
            out.append(ch.lower())
        else:
            out.append(_hex_escaped(ch))
    return "".join(out)


def canonical_group_dn(text: str) -> str | None:
    """The one form a group DN is compared in (BACKLOG #2610), or ``None`` if ``text`` is no DN.

    Each attribute becomes ``type=value``, ASCII letters lower-cased, with the value unescaped and
    then escaped again one way (:func:`_canonical_value`). The parts of a multi-valued RDN (``+``) are
    sorted, and RDNs are joined with ``,``. So however a value is escaped, one DN gives one
    string: ``CN=C# Developers``, ``cn=C\\# developers`` and ``CN=C\\23 Developers`` all become
    ``cn=c# developers``, and ``\\2C`` and ``\\,`` agree. It does not map an attribute's OID onto
    its name, a non-ASCII letter onto its other case, or one Unicode normal form onto another;
    those spellings stay apart and match nothing, which fails closed.

    The parser is tolerant where Active Directory is. A ``#`` after a value's first character is
    literal, which RFC 4514 allows and ldap3's ``parse_dn`` refuses, and AD writes it unescaped in
    ``memberOf``. Spaces around a separator are padding. It refuses an unescaped ``"`` or ``;``,
    an unescaped ``#`` that starts a value, an empty value, a value that is not UTF-8 once
    unescaped, text that cannot be encoded as UTF-8, and anything with fewer than
    :data:`_GROUP_DN_MIN_RDNS` RDNs.

    The output is printable ASCII and never changes under ``str.lower()`` or ``str.strip()``, so
    the store's own ``strip().lower()`` is a no-op on it. Linear apart from sorting a multi-valued RDN's parts, so
    operator text cannot make it backtrack.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return None  # a lone surrogate: no directory DN holds one
    rdns: list[list[str]] = []
    avas: list[str] = []
    attr: str | None = None  # None while reading a type, the type once its "=" is read
    start = 0  # where the current type began
    tokens: list[tuple[bytes, bool]] = []

    def close_ava() -> bool:
        if attr is None:
            return False
        value = _canonical_value(tokens)
        if value is None:
            return False
        avas.append(f"{attr}={value}")
        return True

    i = 0
    while i < len(text):
        ch = text[i]
        if attr is None:
            if ch in ",+":
                return None  # a separator before any "="
            if ch == "=":
                # Only a space, a tab or a line break pads a type, so a DN with a line break after
                # a comma still parses. A bare strip() also took Unicode white space, such as a
                # no-break space (BACKLOG #3222). A break before a comma is part of the value.
                name = text[start:i].strip(" \t\r\n")
                if not _is_dn_attr_type(name):
                    return None
                attr, tokens = name.lower(), []
            i += 1
            continue
        if ch == "\\":
            pair = text[i + 1 : i + 3]
            if len(pair) == 2 and pair[0] in _HEX and pair[1] in _HEX:
                tokens.append((bytes.fromhex(pair), True))
                i += 3
            elif i + 1 < len(text):
                tokens.append((text[i + 1].encode("utf-8"), True))
                i += 2
            else:
                return None  # a trailing lone backslash
            continue
        if ch in ",+":
            if not close_ava():
                return None
            if ch == ",":
                rdns.append(sorted(avas))
                avas = []
            attr, start = None, i + 1
        elif ch in '";':
            return None  # a quoted value, or the old ";" separator: not a form AD writes
        else:
            tokens.append((ch.encode("utf-8"), False))
        i += 1
    if not close_ava():
        return None
    rdns.append(sorted(avas))
    if len(rdns) < _GROUP_DN_MIN_RDNS:
        return None
    return ",".join("+".join(rdn) for rdn in rdns)


def is_group_dn(value: str) -> bool:
    """Whether ``value`` is a full distinguished name that a group map may key on (BACKLOG #2610).

    Both group maps match a principal's ``groups``, which hold canonical DNs only
    (:func:`canonical_group_dn`). A key in any other form would match nothing, or, as a short name
    did before this item, match a same-named group in any unit. The map routes call
    :func:`canonical_group_dn` themselves, because they store its result; this predicate is the
    same test for a caller that only needs the yes or no.
    """
    return canonical_group_dn(value) is not None


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
        "(BACKLOG #2530). This usually means a configured DN or search base lies in another "
        "domain of the forest; use one in this domain controller's own domain, or a global catalog, "
        "which carries universal-group membership only (ADR 0180 Amendment F)."
    )
    raise _referral_error(operation, message)


def _referral_error(operation: str, message: str) -> LdapReferralError:
    """The referral refusal for ``operation``, warned once per operation, whether ldap3 decoded the
    referral (:func:`_refuse_referral`) or could not (:func:`_referred_bind`)."""
    _warn_once(f"referral: {operation}", "%s Reported once per operation.", message)
    return LdapReferralError(message)


#: What a refused code most likely means, where the code points at the configuration rather than at
#: a passing load. Engine text only. Each names what the operation was aimed at, which for a search
#: is its configured base and for the bind-account read is ``[auth].ad_bind_dn``.
_UNANSWERED_HINTS: dict[int, str] = {
    32: " noSuchObject usually means the configured base or DN does not exist, or the service "
    "account cannot see it.",
    34: " invalidDNSyntax usually means a configured DN is not a distinguished name, such as a UPN "
    "or DOMAIN\\user.",
    49: " invalidCredentials on a bind usually means the DN or its password is wrong, or the "
    "account is locked or its password has expired; for the service-account bind, check "
    "[auth].ad_bind_dn and its password.",
    50: " insufficientAccessRights means the service account may not read it.",
}


def _refuse_unanswered(conn: Any, operation: str, *, answers: frozenset[int] | None = None) -> None:
    """Raise :class:`LdapReferralError` for a referral, and otherwise :class:`LdapUnansweredError`
    unless ``conn``'s last operation ended with a result code in ``answers``, which is success alone
    unless the caller names another set.

    BACKLOG #3010. ldap3 raises no ``LDAPException`` for any of these codes here. (ldap3's decoder
    raises ``KeyError`` on a code outside its own table, which :func:`_ldap3_call` refuses as a
    response it could not decode.) Every ``Connection`` in this module keeps ldap3's default
    ``raise_exceptions=False``, and even under ``True`` ldap3 2.9.1 passes
    sizeLimitExceeded (4) and timeLimitExceeded (3) through (``DO_NOT_RAISE_EXCEPTIONS``). So a
    search the directory did not finish -- busy (51), unavailable (52), unwillingToPerform (53),
    adminLimitExceeded (11), a time or size limit -- came back with no entries, or some. Read on, the
    user search answered ``NOT_FOUND``, which the session reconciler counts toward revoking the
    account, and the nested group search answered fewer groups, which narrows the account's roles.

    **Which code is an answer.** For a search, success alone. A search that ended with success and
    matched nothing is the one result that means "no such entry", so only it reads ``NOT_FOUND``,
    and offboarding still revokes. Every other code says the directory did not answer the question
    asked, so any entries that came with it are not the whole answer and none is used. That
    includes noSuchObject (32): on these searches it names the search BASE, not the account, so
    read as absence it would read every account absent at once, which the reconciler's mass-revoke
    breaker does not stop at or under its floor.

    **What each caller makes of it.** The session reconciler reads an :class:`LdapError` as
    unavailable, which never strikes; a sign-in writes ``auth.login_error``; the nested group search
    raising means no caller sees a shorter group list.

    **The cost, named.** Unavailable never revokes, so a code that recurs on every pass, such as a
    deleted search base, stops offboarding and the role re-diff for as long as it lasts, and nothing
    latches an alert for it. Making a standing one visible is #3010's item 4, which the batch
    deferred to vault BACKLOG #3100's item 3. As filed, that item names the reconciler's broad
    ``except Exception`` arm, which this error does not reach, so it must widen to cover the
    ``except LdapError`` arm before the deferral holds. This warns once per operation and code, and
    the text carries no directory text: the code, ldap3's name for it and the operation, never the
    diagnostic message the directory sent.

    **A result that is not a dict is let through.** ldap3's synchronous strategy, the only one built
    here, reads ``self.result['type']`` straight after every search, so a real search cannot return
    without one. Only a test double can.

    ``answers`` is a parameter so an operation whose answers differ, such as a bind, can reuse this
    with its own set. A referral is refused first, as a referral, whatever ``answers`` holds, so
    the reconciler still reads it as referred (BACKLOG #2538).
    """
    from ldap3.core.results import RESULT_SUCCESS  # lazy, like every ldap3 import here

    _refuse_referral(conn, operation)
    result = conn.result
    if not isinstance(result, dict):
        return
    code = result.get("result")
    if type(code) is not int:  # not isinstance: a bool is an int, and is no result code
        raise _unanswered(operation, None)
    if code not in (answers if answers is not None else (RESULT_SUCCESS,)):
        raise _unanswered(operation, code)


def _unanswered(operation: str, code: int | None) -> LdapUnansweredError:
    """The refusal for ``operation`` ending with ``code``, warned once per operation and code name.

    The text carries the code, ldap3's name for it and the operation, never directory text.
    """
    from ldap3.core.results import RESULT_CODES  # lazy, like every ldap3 import here

    if code is None:
        name, shown, hint = "no code", "no readable result code", ""
    else:
        name = RESULT_CODES.get(code, "an unknown result code")
        shown, hint = f"result code {code} ({name})", _UNANSWERED_HINTS.get(code, "")
    message = (
        f"AD ended the {operation} with {shown}, which is not an answer; the engine reads it as "
        f"the directory not answering (BACKLOG #3010).{hint}"
    )
    # Keyed on ldap3's name, not the raw code: a directory chooses the code, and ldap3's table is
    # finite, so the set of warnings stays bounded.
    _warn_once(f"unanswered: {operation}: {name}", "%s Reported once per code.", message)
    return LdapUnansweredError(message, code=code, code_name=name)


#: The result codes that end a user bind without judging its password (BACKLOG #3169): busy (51),
#: unavailable (52), unwillingToPerform (53) and adminLimitExceeded (11), the codes #3010 names
#: for a search the directory did not finish. Literals, because every ldap3 import here is lazy; a
#: test pins each against ldap3's constant.
_UNJUDGED_BIND_CODES = frozenset({11, 51, 52, 53})


def _refuse_unjudged_bind(conn: Any) -> None:
    """Raise :class:`LdapUnansweredError` when ``conn``'s bind ended with a code in
    :data:`_UNJUDGED_BIND_CODES`, and do nothing otherwise.

    BACKLOG #3169. ldap3's ``bind()`` returns ``False`` for each of these, as it does for
    invalidCredentials (49), so read on, a busy domain controller was a wrong password: the step-up
    re-bind counted it toward the engine lockout and could lock out a user who typed the right
    password. Raised, it is an :class:`LdapError`, which the re-bind reads as
    ``directory_unavailable`` and does not count.

    Not :func:`_refuse_unanswered`, which refuses every code outside a set of answers: every other
    refused bind, 49 included, still reads as a refused password, so the bind's answers are an open
    set. The one exception is a referral, which ``authenticate`` refuses first through
    :func:`_refuse_referral` and which is not counted either. The refusal is :func:`_unanswered`'s,
    so its text and warning match the searches'.
    """
    result = conn.result
    code = result.get("result") if isinstance(result, dict) else None
    # type(), not isinstance(): a bool is an int, and is no result code.
    if type(code) is int and code in _UNJUDGED_BIND_CODES:
        raise _unanswered("user bind", code)


def _search(conn: Any, operation: str, **kwargs: Any) -> None:
    """``conn.search(**kwargs)``, refusing a referral result and any other result but success
    (:func:`_refuse_unanswered`). Every search in this module goes through here, so none can read
    either as "no entries"; a test pins that. The search runs inside :func:`_ldap3_call`.
    """
    with _ldap3_call(operation):
        conn.search(**kwargs)
    _refuse_unanswered(conn, operation)


#: What ldap3 raises, other than its own ``LDAPException``, when a response it reads is malformed.
#: ldap3 2.9.1's default fast decoder indexes the BER it reads without checking it: a context tag a
#: response may not carry is ``KeyError(tag)`` (``utils/asn1.py``, ``decode_sequence``), so a bind
#: response carrying a referral raises ``KeyError(3)``, which :func:`_ldap3_call` refuses as a
#: referral (:func:`_is_bind_referral`); a result code outside its table is
#: ``KeyError(code)`` (``ldap_result_to_dict_fast``, ``operation/bind.py``,
#: ``operation/extended.py``); a paged results control with no value is ``TypeError`` and one with no
#: cookie is ``IndexError`` (``strategy/base.py``, ``decode_control_fast``); a bind response whose
#: matchedDN is not a string is ``AttributeError`` (``decode_response_fast``); a Who am I value that
#: is not UTF-8 is ``UnicodeError``, a ``ValueError`` (``extend/standard/whoAmI.py``,
#: ``populate_result``). At least these; the decoder trusts every length and tag it reads, so others
#: are reachable.
_DECODE_FAULTS: tuple[type[Exception], ...] = (LookupError, TypeError, ValueError, AttributeError)

#: Where ldap3 reads and decodes a response: a module prefix, and the methods under it that do. A
#: fault raised under one was raised reading what the directory sent, not building what the engine
#: asked for. The strategy reads the message; an extended operation such as Who am I decodes its
#: value after that read has returned. ``self`` in each holds the ``connection`` it read on.
_RESPONSE_READERS: tuple[tuple[str, frozenset[str]], ...] = (
    ("ldap3.strategy.", frozenset({"get_response", "_get_response"})),
    ("ldap3.extend.", frozenset({"decode_response", "populate_result", "set_response"})),
)


def _type_name(exc: BaseException) -> str:
    """An exception's type, never its text. ``struct.error``'s own name is just "error", so a type
    from outside builtins carries its module."""
    kind = type(exc)
    if kind.__module__ == "builtins":
        return kind.__qualname__
    return f"{kind.__module__}.{kind.__qualname__}"


def _reading_connection(exc: BaseException) -> Any:
    """The ldap3 connection whose response was being read when ``exc`` was raised, or ``None`` when
    ``exc`` was not raised by ldap3 while reading one.

    Decided by ORIGIN, never by the exception's value: the innermost frame belongs to the ldap3
    package, and an outer frame is one of :data:`_RESPONSE_READERS`. A ``KeyError(3)`` the decoder
    raises and a ``KeyError(3)`` engine code raises carry the same value, and only the first is the
    directory's. The second condition keeps out what ldap3 raises while building a request from the
    engine's own arguments, which is the engine's defect.
    """
    connection: Any = None
    module = ""
    tb = exc.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        module = str(frame.f_globals.get("__name__", ""))
        if connection is None and any(
            module.startswith(prefix) and frame.f_code.co_name in names
            for prefix, names in _RESPONSE_READERS
        ):
            connection = getattr(frame.f_locals.get("self"), "connection", None)
        tb = tb.tb_next
    in_ldap3 = module == "ldap3" or module.startswith("ldap3.")
    return connection if in_ldap3 else None


@contextlib.contextmanager
def _ldap3_call(operation: str, *, close: bool = False) -> Iterator[None]:
    """The boundary every ldap3 call that reads a response runs inside: each search and each page
    of one, every bind including the service account's ``auto_bind``, and the Who am I extended
    operation. A static test pins that. An unbind reads no response, so it runs outside.

    BACKLOG #3010. A :data:`_DECODE_FAULTS` exception that ldap3 raised while reading the
    directory's response becomes :class:`LdapUndecodableError` (its docstring says who reads it
    how). Unmapped, it would escape every ``except LdapError``, and a sign-in would fail as an
    unhandled error with no audit row. An exception from anywhere else propagates unchanged, since
    mapped it would report an engine defect as a fault in what the directory sent
    (:func:`_reading_connection` says how the two are told apart). An ``LDAPException`` passes
    through untouched, for its own handler.

    **One fault is a referral, not an undecodable response.** ldap3's decoder has no field for the
    referral a bind response may carry, so it raises ``KeyError(3)`` on one. That becomes
    :class:`LdapReferralError`, as a referral ldap3 could decode does (:func:`_refuse_referral`),
    so the session reconciler reads it as referred and alerts (BACKLOG #2538).
    :func:`_is_bind_referral` says how it is told apart, again by origin.

    ``close`` closes the socket the failed read was on, where nothing else will. Only the service
    account's bind passes it: its ``auto_bind`` runs inside ldap3's ``Connection`` constructor, so
    when it raises no caller holds the connection to unbind. A search does not need it (BACKLOG
    #3010): every caller holding a searched connection unbinds it when its block ends, through
    ``_service_session`` (BACKLOG #3017).
    """
    import ldap3

    try:
        yield
    except ldap3.core.exceptions.LDAPException:
        raise
    except _DECODE_FAULTS as exc:
        connection = _reading_connection(exc)
        if connection is None:
            raise
        if close:
            # BaseStrategy.close shuts the socket without sending anything on a stream that may
            # be out of step. Best effort: the refusal below is the answer either way.
            try:
                connection.strategy.close()
            except (ldap3.core.exceptions.LDAPException, OSError) as failed:
                logger.debug(
                    "AD socket close after an undecodable response: %s", _type_name(failed)
                )
        if _is_bind_referral(exc):
            raise _referred_bind(operation) from exc
        raise _undecodable(operation, exc) from exc


#: The context tag of the ``referral`` field of an LDAPResult (RFC 4511 section 4.1.9).
_REFERRAL_TAG = 3
#: ldap3's number for the context-specific tag class (``utils/asn1.py``, ``CLASSES``).
_CONTEXT_CLASS = 2


def _is_bind_referral(exc: BaseException) -> bool:
    """Whether ``exc`` is ldap3's decoder meeting the referral field of a bind response.

    Decided by ORIGIN and decoder state, never by the exception's value alone: the innermost frame is
    ldap3's ``decode_sequence`` reading a bind response's fields (its ``context_decoders`` is
    ``BIND_RESPONSE_CONTEXT``, which has no entry for the field) at the referral's tag. A
    ``KeyError(3)`` from anywhere else, such as a stray tag [3] in some other response or engine
    code, is not this. A test pins the ldap3 names this reads.
    """
    # The context-class tag alone: a universal, application or private tag 3 raises KeyError((class,
    # 3)) from the class table instead, and is a malformed response, not a referral.
    if not isinstance(exc, KeyError) or exc.args != (_REFERRAL_TAG,):
        return False
    from ldap3.utils import asn1  # lazy, like every ldap3 import here

    frame = _innermost_frame(exc)
    if frame is None:
        return False
    return (
        frame.f_globals.get("__name__") == asn1.__name__
        and frame.f_code.co_name == "decode_sequence"
        and frame.f_locals.get("context_decoders") is asn1.BIND_RESPONSE_CONTEXT
        and frame.f_locals.get("ber_class") == _CONTEXT_CLASS
        and frame.f_locals.get("ber_type") == _REFERRAL_TAG
    )


def _referred_bind(operation: str) -> LdapReferralError:
    """The refusal for a bind answered with a referral ldap3 could not decode, warned once per
    operation. The referred hosts were in the part that could not be read, so none is named."""
    message = (
        f"AD answered the {operation} with a referral, whose hosts ldap3 cannot decode in a bind "
        "response; the engine does not follow referrals (BACKLOG #2530, #3010). This usually "
        "means a configured DN or search base lies in another domain of the forest; use one in "
        "this domain controller's own domain, or a global catalog."
    )
    return _referral_error(operation, message)


def _undecodable(operation: str, exc: BaseException) -> LdapUndecodableError:
    """The refusal for ``operation`` whose response ldap3 could not decode, warned once per
    operation and fault type. The text names the type only: neither a value the directory sent
    nor ldap3's text, and no result code, since none was read."""
    fault = _type_name(exc)
    message = (
        f"AD answered the {operation} with a response ldap3 could not decode ({fault}); the "
        "engine does not read it as an answer (BACKLOG #3010)."
    )
    _warn_once(f"undecodable: {operation}: {fault}", "%s Reported once.", message)
    return LdapUndecodableError(message)


#: The simple paged results control (RFC 2696), which AD and ldap3 both name by this OID.
_PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"

#: Entries asked for per page of a search that can return many. Below AD's default MaxPageSize
#: (1000), the cap an unpaged search ends at with sizeLimitExceeded. A directory whose cap is lower
#: returns smaller pages, which is still the whole answer.
_PAGE_SIZE = 500

#: Entries a paged search may return before it is refused as unfinished (BACKLOG #3696 item 4).
#: A count of entries, not of pages, so the cap does not move with the page size a directory
#: returns: a directory capping a page at 100 (``MaxPageSize = 100``) gets the same 10,000 as one
#: returning :data:`_PAGE_SIZE`. It was 20 pages, which at 100 a page refused an account in more
#: than 2,000 groups.
_MAX_PAGED_ENTRIES = 10_000

#: Pages read before a paged search is refused, a backstop against a directory that keeps
#: returning a cookie with empty or tiny pages. The overall deadline already bounds the time
#: (:func:`_search_paged`); this bounds the round trips inside it. Set where it cannot bind before
#: :data:`_MAX_PAGED_ENTRIES` on any page of 10 entries or more.
_MAX_PAGES = _MAX_PAGED_ENTRIES // 10 + 1

#: The ``code_name`` of a paged search refused for its bounds rather than for its answer: past its
#: overall deadline, past :data:`_MAX_PAGED_ENTRIES`, or past the :data:`_MAX_PAGES` backstop
#: (BACKLOG #3696). Public, because the directory reconciler pages on them where it reads every
#: other unanswered search as an outage (``AuthService._probe_principal``).
PAGING_DEADLINE_SPENT = "deadline spent"
PAGING_TOO_MANY_ENTRIES = "too many entries"
PAGING_TOO_MANY_PAGES = "too many pages"

#: The clock a paged search's overall deadline reads. Monotonic, so a wall-clock step cannot
#: stretch or cut the budget; a module name so a test can drive it.
_monotonic = time.monotonic


def _paged_cookie(conn: Any) -> bytes | None:
    """The cookie ``conn``'s last search returned: empty at the last page (RFC 2696), and ``None``
    when the result carries no paged results control that can be read.

    ldap3 decodes the control into ``result['controls'][oid]['value']['cookie']``.
    """
    result = conn.result
    controls = result.get("controls") if isinstance(result, dict) else None
    control = controls.get(_PAGED_RESULTS_OID) if isinstance(controls, dict) else None
    value = control.get("value") if isinstance(control, dict) else None
    cookie = value.get("cookie") if isinstance(value, dict) else None
    return cookie if isinstance(cookie, bytes) else None


def _search_paged(conn: Any, operation: str, *, budget: float, **kwargs: Any) -> list[Any]:
    """Every entry of a search that can outrun a directory's unpaged cap, read page by page.

    BACKLOG #3010. Each page goes through :func:`_search`, so a page that does not end with success
    refuses the whole search, and the pages already read are dropped with it: a part of the answer
    is never used as the whole. Unpaged, an account in more groups than the cap would end the
    nested group search with sizeLimitExceeded, which that refusal turns into a failed sign-in.

    **A first page with no readable control is the whole answer**, under the entry cap below: the
    control is sent non-critical, so a directory may ignore it, and that answer either is complete
    or ends with a code :func:`_refuse_unanswered` refuses. **A later page with none is refused**:
    the directory was paging, and a page that does not say whether it is the last cannot be read
    as the last.

    **All the pages share one deadline, ``budget`` seconds** (BACKLOG #3696 item 3). Each socket
    read of a page waits at most what was left when the page was asked for
    (:class:`_SocketTimeoutCap`), and no page is asked for once it is spent. A deadline spent
    between pages, or a read or send of a later page that waits out what was left, is refused as
    ``deadline spent``; a first page that times out is one slow read, as any other search's. Without it, every page could take the whole
    ``[auth].ad_receive_timeout``, so the bound was that times the page count. What the bound
    does not cover is in ``docs/CONNECTIONS.md``, the Active Directory row of the timeout table.

    **More than :data:`_MAX_PAGED_ENTRIES` entries refuses the search** (BACKLOG #3696 item 4),
    whatever size the directory's pages are, one page included; :data:`_MAX_PAGES` is a backstop.

    **A refused search is abandoned** (:func:`_abandon_paging`) once the directory has sent a
    cookie, so it need not hold the paging state until its own timeout. Not after a response ldap3
    could not decode: the stream may be out of step after one, so no abandon is sent on it, and
    the directory holds the paging state until its own timeout or the connection ends. **Nor once
    the deadline is spent**: an abandon is one more round trip, so it gets only what is left. The
    caller unbinds the connection as its block ends (``_service_session``), and that drops the
    state too.
    """
    import ldap3

    entries: list[Any] = []
    cookie: bytes | None = None  # what the next page is asked with
    newest: bytes | None = None  # the newest non-empty cookie the directory sent
    deadline = _monotonic() + budget
    timeout = _SocketTimeoutCap(conn)
    out_of_time = False

    def spent() -> LdapUnansweredError:
        nonlocal out_of_time
        out_of_time = True
        return _paging_refused(
            operation,
            PAGING_DEADLINE_SPENT,
            f"did not finish paging within {budget:g} s",
            "BACKLOG #3696",
        )

    try:
        for page in range(_MAX_PAGES):
            remaining = deadline - _monotonic()
            if remaining <= 0:
                raise spent()
            shortened = timeout.cap(remaining)
            try:
                _search(conn, operation, paged_size=_PAGE_SIZE, paged_cookie=cookie, **kwargs)
            except (
                ldap3.core.exceptions.LDAPSocketReceiveError,
                ldap3.core.exceptions.LDAPSocketSendError,
            ) as exc:
                # ldap3 merges the socket's own exception into its class, so a read or send that
                # waited out the deadline rather than the socket's timeout is a TimeoutError here.
                if page and shortened and isinstance(exc, TimeoutError):
                    raise spent() from exc
                raise
            entries.extend(conn.entries)
            cookie = _paged_cookie(conn)
            if cookie is None and page:
                raise _paging_refused(
                    operation, "paging control lost", "dropped the paging control"
                )
            if len(entries) > _MAX_PAGED_ENTRIES:
                # Only this page's cookie is live: after a last page the directory holds no
                # state, and an older cookie would ask it to drop state it already dropped.
                newest = None
                raise _paging_refused(
                    operation,
                    PAGING_TOO_MANY_ENTRIES,
                    f"returned more than {_MAX_PAGED_ENTRIES:,} entries",
                    "BACKLOG #3696",
                )
            if not cookie:
                return entries
            newest = cookie
        raise _paging_refused(
            operation, PAGING_TOO_MANY_PAGES, f"was still paging after {_MAX_PAGES} pages"
        )
    except (LdapUnansweredError, LdapReferralError):
        remaining = deadline - _monotonic()
        if not out_of_time and remaining > 0:
            # The refusing page was read, so the stream is in step and a cookie in it is readable.
            timeout.cap(remaining)
            _abandon_paging(conn, operation, _paged_cookie(conn) or newest, kwargs)
        raise
    finally:
        timeout.restore()


class _SocketTimeoutCap:
    """Shortens ``conn``'s socket receive timeout for a paged search, and restores it after.

    BACKLOG #3696 item 3. ldap3 applies ``receive_timeout`` once, when it opens the socket, through
    ``socket.settimeout``, which leaves the socket non-blocking under Python's own poll, so a later
    ``settimeout`` governs every read that follows on every OS; the ``SO_RCVTIMEO`` ldap3 also sets
    applies only to a blocking socket. A connection with no socket, such as a test double, is left
    alone.
    """

    def __init__(self, conn: Any) -> None:
        self._sock: Any = getattr(conn, "socket", None)
        self._original: float | None = self._sock.gettimeout() if self._sock is not None else None

    def cap(self, seconds: float) -> bool:
        """Bound each read to at most ``seconds``, never longer than the socket's own timeout.
        Returns whether ``seconds`` is now the bound, rather than that timeout."""
        if self._sock is None:
            return False
        shortened = self._original is None or seconds < self._original
        try:
            self._sock.settimeout(seconds if shortened else self._original)
        except OSError as failed:
            # A socket ldap3 already closed: nothing reads it, and the refusal or the next
            # search's own error is the answer, so this must not replace either.
            logger.debug("AD socket timeout cap on a paged search: %s", _type_name(failed))
            return False
        return shortened

    def restore(self) -> None:
        """Put the socket's own timeout back. ldap3 closes the socket when a read fails, and
        ``settimeout`` on a closed one raises, which is logged and is no fault: nothing reads it."""
        if self._sock is None:
            return
        try:
            self._sock.settimeout(self._original)
        except OSError as failed:
            logger.debug("AD socket timeout restore after a paged search: %s", _type_name(failed))


def _abandon_paging(
    conn: Any, operation: str, cookie: bytes | None, kwargs: dict[str, Any]
) -> None:
    """Tell the directory to drop a refused paged search's state: the same search again with a page
    size of zero and ``cookie``, which RFC 2696 section 3 defines as abandoning it. ldap3 sends a
    zero size as given (``Connection.search`` adds the control for any integer ``paged_size``).

    A finding of BACKLOG #3010's review. ``cookie`` is the newest non-empty one the directory sent;
    with none, it never held state for this search and nothing is sent. Best effort: the search is
    refused whatever this answers, so a failed abandon is not raised: a refusal of it is warned once
    by :func:`_search`, and an ldap3 error from it is logged at debug level. It costs one more
    round trip, whose reads wait at most what is left of the paged search's deadline, and it is
    not sent once that is spent (BACKLOG #3696).
    """
    import ldap3

    if not cookie:
        return
    try:
        _search(conn, f"{operation} abandon", paged_size=0, paged_cookie=cookie, **kwargs)
    except (LdapError, ldap3.core.exceptions.LDAPException) as failed:
        # The type only: an ldap3 error's text can carry the directory's diagnostic message.
        logger.debug("AD abandon of a refused %s failed: %s", operation, _type_name(failed))


def _paging_refused(
    operation: str, case: str, what: str, item: str = "BACKLOG #3010"
) -> LdapUnansweredError:
    """The refusal for a paged search refused for its paging rather than for a result code: the
    paging did not end, or ran past its deadline or entry cap. Warned once per operation and case;
    ``item`` is the backlog item that added the case."""
    message = (
        f"AD {what} on the {operation}; the engine reads it as the directory not answering "
        f"({item})."
    )
    _warn_once(f"unanswered: {operation}: {case}", "%s Reported once.", message)
    return LdapUnansweredError(message, code_name=case)


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

    A response ldap3 could not decode is not a socket fault: each bind also runs inside
    :func:`_ldap3_call`, nested inside this wrap, which refuses it first.

    An ``LDAPException`` passes through untouched, even one that is also an ``OSError``,
    ``TypeError`` or ``ValueError``, for its own handler. The new text is fixed and names only the
    type: a fault's message is not the engine's to repeat. With more than one candidate address,
    ldap3 bundles each address's fault into ``LDAPSocketOpenError``, which reaches the ldap3 handler
    instead, and that handler names only the type too (:func:`_ldap3_failed`).
    """
    import ldap3

    try:
        yield
    except ldap3.core.exceptions.LDAPException:
        raise
    except _SOCKET_FAULTS as exc:
        # The type alone, never str(exc).
        raise LdapError(f"AD directory call failed: {_type_name(exc)}") from exc


def _ldap3_failed(exc: BaseException) -> LdapError:
    """The :class:`LdapError` an ldap3 error becomes in ``authenticate``, ``probe_principal`` and
    ``read_bind_account``.

    BACKLOG #3017. The text is fixed and names ldap3's error type, never its text. That text can
    carry each address the engine tried and the error at each (``LDAPSocketOpenError``), or the
    directory's diagnostic message, and the sign-in callers write this text into
    ``auth.login_error``. ``check-privileges`` prints the same text. It differs from
    :func:`_socket_faults_as_ldap_error`'s text, so a reader can tell an ldap3 error from a bare
    socket fault.

    **The cause's type is named too.** ldap3 builds a socket error as a class that also
    subclasses the error the interpreter raised (``communication_exception_factory``), such as
    ``SSLCertVerificationError`` or ``ConnectionRefusedError``. Its name tells a pinned-CA mismatch
    from a refused port without quoting anything. The full text goes to a DEBUG traceback only.
    """
    logger.debug("AD directory call failed", exc_info=exc)
    name = type(exc).__name__
    cause = next(
        (
            kind.__name__
            for kind in type(exc).__mro__
            if not kind.__module__.startswith("ldap3")
            and kind not in (Exception, BaseException, object)
        ),
        None,
    )
    return LdapError(
        f"AD directory call failed: ldap3 raised {name}" + (f" ({cause})" if cause else "")
    )


#: The ldap3 module and method whose frame raises ``LDAPBindError`` for a refused ``auto_bind``.
_AUTO_BIND_FRAME = ("ldap3.core.connection", "_do_auto_bind")


def _innermost_frame(exc: BaseException) -> FrameType | None:
    """The frame ``exc`` was raised in, or ``None`` when it carries no traceback."""
    tb = exc.__traceback__
    if tb is None:
        return None
    while tb.tb_next is not None:
        tb = tb.tb_next
    return tb.tb_frame


def _auto_binding_connection(exc: BaseException) -> Any:
    """The connection whose ``auto_bind`` raised ``exc``, or ``None``.

    ldap3 raises a refused ``auto_bind`` from inside the ``Connection`` constructor, so no caller
    holds the connection whose result says why. Decided by ORIGIN, as :func:`_reading_connection`
    is: the innermost frame is ldap3's ``_do_auto_bind``, whose ``self`` is that connection. A test
    pins the ldap3 names this reads.
    """
    frame = _innermost_frame(exc)
    if frame is None or (frame.f_globals.get("__name__"), frame.f_code.co_name) != _AUTO_BIND_FRAME:
        return None
    return frame.f_locals.get("self")


def _refuse_service_bind(exc: BaseException) -> NoReturn:
    """Raise the refusal of a service-account ``auto_bind`` that ldap3 raised ``exc`` for.

    BACKLOG #3017. ldap3 raises a plain ``LDAPBindError`` for every refused ``auto_bind``, so a
    referral read as a directory failure, which the session reconciler reads as an outage. The
    refused connection's result goes through :func:`_refuse_unanswered`, as a search's does: a
    referral is refused by name, so the reconciler reads it as referred and alerts (BACKLOG
    #2538), and any other code is named with ldap3's name for it and the hint for it, never the
    directory's diagnostic message, so an operator still sees ``invalidCredentials`` for a wrong
    service password. A bind response carrying the referral's hosts never reaches here: ldap3
    cannot decode one, and :func:`_ldap3_call` refuses it first.
    """
    conn = _auto_binding_connection(exc)
    if conn is not None:
        _refuse_unanswered(conn, "service-account bind")
    raise LdapError("AD refused the service-account bind; ldap3 raised LDAPBindError") from exc


@contextlib.contextmanager
def _released(conn: Any) -> Iterator[None]:
    """Unbind ``conn`` when the block ends, however it ends.

    An ldap3 error from the unbind never replaces an exception the block raised (BACKLOG #3010).
    The block's own exception is the answer both bind branches give, so an unbind failing after an
    undecodable bind must not replace it on one branch only, or an absent account and a present
    one would answer differently. After a block that raised nothing, the unbind's error propagates
    as before.
    """
    import ldap3

    try:
        yield
    except BaseException:
        with contextlib.suppress(ldap3.core.exceptions.LDAPException):
            conn.unbind()
        raise
    conn.unbind()


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
        # Every LDAPS bind carries a password: the service account's (required below) and then the
        # user's. With ad_tls_verify=false the engine would hand both to whichever peer answered, so it
        # is refused, with no escape and in every posture (vault BACKLOG #3230; the rule is stated in
        # docs/SECURITY-LOOSENING.md). Until then MEFOR_ALLOW_INSECURE_TLS released it at
        # [security].enforcement = warn (#329). Like the plain-bind refusal above, it runs before the
        # bind secret is resolved, so a refused build never fetches the password.
        if self._ldaps and not settings.ad_tls_verify:
            raise LdapError(
                "ad_tls_verify=false would send the AD service-account and user passwords to an "
                "LDAPS peer whose certificate is not verified; refused, with no escape. Leave "
                "ad_tls_verify on (the default). For a directory whose certificate comes from a "
                "private or self-signed CA, pin that CA with ad_tls_ca_cert_file."
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
        # BACKLOG #1317, #2494. The engine builds this hop's TLS context (ASVS 12.1.2): narrowed to the
        # approved suites at TLS 1.2 and, where the interpreter allows it, TLS 1.3, then asserted.
        # Verification-off is refused above; this is the separate question of whether the
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
                validate=ssl.CERT_REQUIRED,  # ad_tls_verify=false is refused above
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
        try:
            with (
                _socket_faults_as_ldap_error(),
                _ldap3_call("service-account bind", close=True),
            ):
                return ldap3.Connection(
                    server,
                    user=self._s.ad_bind_dn,
                    password=self._bind_password,  # resolved once in __init__ (env or a provider)
                    authentication=ldap3.SIMPLE,
                    auto_bind=True,
                    receive_timeout=_ldap3_receive_timeout(self._s.ad_receive_timeout),
                    auto_referrals=False,  # BACKLOG #2530: see _refuse_referral
                )
        except ldap3.core.exceptions.LDAPBindError as exc:
            # ldap3 unbound the refused connection before raising, so nothing is left open.
            _refuse_service_bind(exc)

    @contextlib.contextmanager
    def _service_session(self) -> Iterator[Any]:
        """The service-account connection, unbound when the block ends, however it ends.

        BACKLOG #3017. Not ldap3's own ``with``: its ``Connection.__exit__`` (ldap3 2.9.1) unbinds
        only a connection that was not bound on entry, and ``auto_bind`` binds every one here, so
        the session stayed open and bound until the object was collected, after an undecodable
        response on a stream that may be out of step too. It also reopens a connection that was
        open on entry and closed on exit, so an unbind inside it would cost one more connect.

        An ldap3 error from the unbind is suppressed: by then the block has answered or raised, and
        an unbind failure changes neither. ``_released`` lets one through after a block that raised
        nothing, which the user bind's connection keeps.
        """
        import ldap3

        svc = self._service_conn()
        try:
            yield svc
        finally:
            try:
                svc.unbind()
            except ldap3.core.exceptions.LDAPException as failed:
                logger.debug("AD service-account unbind failed: %s", _type_name(failed))

    def _equalizing_bind(self, password: str) -> None:
        """Do the password-verifying bind's work for a principal that does not exist, and discard it.

        ASVS 6.3.8 (BACKLOG #1140). Builds the same second ``Server`` and ``Connection`` with the
        same finite ``receive_timeout``, binds against a DN that cannot exist under the configured
        search base, and unbinds — so the absent/disabled branch costs the same Server build, TCP
        connect and bind round trip as the present-and-enabled one.

        **Swallows nothing (BACKLOG #3017).** Every error propagates, and ``authenticate`` maps it
        exactly as it maps the real bind's: an ``LDAPException`` to :class:`LdapError`, a socket
        fault that is not an ldap3 error the same way (BACKLOG #2566), and a bind response ldap3
        could not decode through :func:`_ldap3_call` as the "user bind" (BACKLOG #3010). Both
        branches open a socket to the same directory, so a directory that fails the second connect
        fails them alike, where a swallow here would tell them apart.

        **Why a plain wrong user name still reads as a failed sign-in.** The swallow was there so
        that a bind against a DN that does not exist would not read as a directory error. It never
        does: every ``Connection`` here keeps ldap3's default ``raise_exceptions=False``, so a bind
        the directory refuses, ``invalidCredentials`` included, returns ``False`` and raises
        nothing. ldap3 2.9.1's simple bind raises when the connection fails, and when it cannot
        ask: no user or no password, neither possible here, or a password SASLprep (RFC 4013)
        refuses, such as one holding a control character. That last raises after the socket opens
        and before the bind request is sent, on both branches alike, so such a password reads as a directory error for an absent
        account and a present one. A test pins the healthy-directory path.

        **The decoy reads no result code except a referral; it ignores an outage code (BACKLOG
        #3169).** The real bind refuses one in :data:`_UNJUDGED_BIND_CODES` as the directory not
        answering; here the lookup has already answered, and its answer (absent, disabled,
        undetermined) is what the caller audits. Refusing it would replace that answer with an
        outage. So a busy directory answers the two branches differently, a case #3017 does not make
        alike; the caller is a signed-in session re-proving its own account, so the difference
        names nothing it does not hold.

        **What this does NOT claim:** that wall-clock is now provably equal. It equalizes the code
        PATH, which is what the item measured; a directory may still answer ``invalidCredentials``
        and a no-such-object in different times, and the group-resolution search on the success path
        remains unmatched. No timing measurement has been run here either.
        """
        import ldap3

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
        # Labelled as the real bind is, and released the same way, so an undecodable answer
        # fails both branches with the same text (_ldap3_call, _released).
        with _released(conn):
            with _ldap3_call("user bind"):
                bound = conn.bind()
            if not bound:
                # As the real bind does, so a referral answers both branches alike (BACKLOG
                # #3017). Any other refusal is ignored, an outage code included (BACKLOG #3169):
                # this branch always fails the re-bind.
                _refuse_referral(conn, "user bind")

    def _search_user(
        self,
        conn: Any,
        search_filter: str,
        *,
        fallback_username: str,
        expected_object_id: str | None = None,
        tie_break_object_id: str | None = None,
    ) -> _Lookup:
        """Run one user search and extract the entry. ``info`` is ``None`` for no match, more than
        one match (``AMBIGUOUS``, vault BACKLOG #2778), a disabled account or an undetermined one,
        and ``answer`` says which (ADR 0195 rule item 2).

        ``tie_break_object_id``, a canonical id, picks among several matches of a name-keyed search
        (vault BACKLOG #3228). It is used only when exactly one match holds ``fallback_username`` as
        its own ``sAMAccountName`` and that entry is the only match reading the id back. Anything
        else is still ``AMBIGUOUS``. It never changes a search that matched one entry. See
        :meth:`_lookup_by_name`.

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
        e = conn.entries[0]
        own: str | None = None
        if len(conn.entries) > 1:
            # Vault BACKLOG #2778. The name filter matches sAMAccountName OR userPrincipalName, and
            # a directory may legally give one account a UPN prefix equal to another's
            # sAMAccountName. Taking entries[0] would let the server's result order pick which
            # account signs in. Logged with a label for the name and the count only, once per name:
            # the attempts repeat at sign-in rate, and the set of names stays bounded by the
            # collisions the directory holds.
            #
            # Vault BACKLOG #3228. When the caller holds the account's stored objectGUID, the one
            # entry that reads it back is the account the engine row is bound to, so it is used.
            # Refusing it too let anyone able to write a colliding entry lock the account out. No
            # match, or more than one, still proves nothing, so it is refused as before.
            #
            # THE CHOSEN ENTRY MUST BE THE ONLY MATCH HOLDING THE NAME AS ITS sAMAccountName. The
            # Kerberos caller passes the ticket's name with its realm already dropped, so the ticket
            # proves only that its holder has this sAMAccountName in SOME realm the acceptor trusts.
            # - An entry that matched only through its UPN is not that holder. Choosing it would let
            #   a renamed account that kept its old UPN be signed in by whoever was later given the
            #   old name.
            # - Two entries holding the name, as same-named accounts in two domains under one
            #   search base would, cannot be told apart by the ticket, so the id does not choose.
            # The id must also be on that entry alone: an id on two entries names neither.
            # Compared with lower(), not casefold(), so "straße" does not equal "strasse".
            # The `is not None` test is load-bearing: an entry with no readable id reads back
            # None, which must never match a caller that holds no id.
            label = safe_name(fallback_username)
            name = fallback_username.lower()
            holders = [
                x for x in conn.entries if (_attr(x, "sAMAccountName") or "").lower() == name
            ]
            chosen = (
                tie_break_object_id is not None
                and len(holders) == 1
                # Identity, not ==: the one entry carrying the id must be the holder itself.
                and [id(x) for x in conn.entries if _object_guid(x) == tie_break_object_id]
                == [id(holders[0])]
            )
            # Reported either way: the collision is in the directory, and an operator should clear it.
            _warn_once(
                f"ambiguous-chosen:{label}" if chosen else f"ambiguous:{label}",
                "AD user search for %s matched %d directory entries; %s (logged once per name)",
                label,
                len(conn.entries),
                f"using the one carrying the account's stored {_OBJECT_GUID_ATTR}"
                if chosen
                else "refusing it as ambiguous",
            )
            if not chosen:
                return _Lookup(DirectoryAnswer.AMBIGUOUS)
            e, own = holders[0], tie_break_object_id
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
                # An id-keyed lookup or a tie-break has already read it, and proved it equal to
                # the id the caller holds.
                "object_id": own if own is not None else _object_guid(e),
                "display_name": _attr(e, "displayName"),
                "email": _attr(e, "mail"),
                "memberOf": _multi(e, "memberOf"),
            },
        )

    def _find_user(self, conn: Any, username: str) -> dict[str, Any] | None:
        return self._lookup_by_name(conn, username).info

    def _lookup_by_name(
        self, conn: Any, username: str, *, tie_break_object_id: str | None = None
    ) -> _Lookup:
        """Find a user by name. ``tie_break_object_id`` only chooses among several matches.

        Vault BACKLOG #3228. The name stays the key: a Kerberos ticket proves a name, so searching
        by the stored id instead would sign the ticket holder in as whoever holds that id now, even
        after the name passed to someone else. For the same reason the tie-break only accepts the
        one entry whose own ``sAMAccountName`` is the name (:meth:`_search_user`). The id is
        normalised here, the one place it enters this lookup; one that cannot be read breaks no tie.
        """
        upn = f"{username}@{self._s.ad_domain}" if self._s.ad_domain else username
        return self._search_user(
            conn,
            (
                f"(|(sAMAccountName={_escape_filter(username)})"
                f"(userPrincipalName={_escape_filter(upn)}))"
            ),
            fallback_username=username,
            tie_break_object_id=normalise_object_guid(tie_break_object_id),
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
        """The user's groups as canonical DNs (:func:`canonical_group_dn`), the one form both group
        maps key on.

        BACKLOG #2610. This used to add each direct group's first CN and each nested group's
        ``sAMAccountName`` too, so a map key written as a short name matched a same-named group in
        any unit. Anyone able to create a group anywhere could then take the roles mapped to it.

        Canonical rather than merely lower-cased, so a key matches however either side escapes a
        value: AD writes ``CN=C# Developers`` in ``memberOf``, and an operator may write ``C\\#``. A
        DN that has no canonical form is dropped, and the drop is counted in the log. No map key can
        name it, since every key is stored canonical, so dropping it takes nothing a member could
        have been granted.
        """
        import ldap3

        # Direct membership from the user's memberOf attribute.
        found = list(member_of)
        if self._s.ad_use_nested_groups and self._s.ad_group_search_base:
            # A search the directory did not finish raises here (BACKLOG #3010), never a shorter
            # group list.
            # Paged, so an account in more groups than the directory's unpaged cap still resolves.
            # All the pages together get one [auth].ad_group_search_deadline, so paging no longer
            # multiplies the per-read ad_receive_timeout (BACKLOG #3696 item 3).
            groups = _search_paged(
                conn,
                "group search",
                budget=self._s.ad_group_search_deadline,
                search_base=self._s.ad_group_search_base,
                search_filter=f"(member:{_MATCHING_RULE_IN_CHAIN}:={_escape_filter(user_dn)})",
                search_scope=ldap3.SUBTREE,
                attributes=["distinguishedName"],
            )
            found.extend(str(e.entry_dn) for e in groups)
        canonical = [canonical_group_dn(dn) for dn in found]
        dropped = canonical.count(None)
        if dropped:
            # A count only, at DEBUG: a group DN is directory text, and this runs on every sign-in
            # and every reconcile probe.
            logger.debug(
                "AD group resolution dropped %d group DN(s) with no canonical form; no group map "
                "key can name such a group, so it grants nothing (BACKLOG #2610)",
                dropped,
            )
        return frozenset(c for c in canonical if c is not None)

    def authenticate(
        self, username: str, password: str, *, object_id: str | None = None
    ) -> DirectoryBind:
        """Verify ``username``/``password`` against AD. Raises :class:`LdapError` on a
        connectivity/config failure, and on a bind the directory ended without judging the
        password (:func:`_refuse_unjudged_bind`, BACKLOG #3169).

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
            with self._service_session() as svc:
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
                    # Every error in the decoy is mapped HERE, the same way the real bind's is
                    # below, so an absent and a present account fail alike (BACKLOG #2566, #3017).
                    # Swallowing it inside _equalizing_bind would tell the two apart. A bind result
                    # code is not such an error: a busy one answers the two apart, by design
                    # (_equalizing_bind, BACKLOG #3169).
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
                with _released(user_conn):
                    # BACKLOG #2566: the bind opens the socket, so only the bind is wrapped. The
                    # build above does no I/O, and the release runs on an open socket.
                    with _socket_faults_as_ldap_error(), _ldap3_call("user bind"):
                        bound = user_conn.bind()
                    if not bound:
                        _refuse_referral(user_conn, "user bind")
                        # A busy or unavailable directory judged no password (BACKLOG #3169).
                        _refuse_unjudged_bind(user_conn)
                        # The entry was found enabled, so the refusal judged this account.
                        return DirectoryBind(DirectoryAnswer.FOUND)
                groups = self._resolve_groups(svc, user_dn, info["memberOf"])
        except ldap3.core.exceptions.LDAPException as exc:
            raise _ldap3_failed(exc) from exc
        return DirectoryBind(DirectoryAnswer.FOUND, _principal_from(info, user_dn, groups))

    def resolve_principal(
        self,
        username: str,
        *,
        object_id: str | None = None,
        tie_break_object_id: str | None = None,
    ) -> AdPrincipal | None:
        """Look a user up + resolve groups *without* a password. Uses the service-account bind only.

        At least for Kerberos, where SSO already proved the identity, the federated legs and
        ``create_directory_account``. The ADR 0079 session reconciler calls
        :meth:`probe_principal`, which this is with the answer dropped.

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

        ``tie_break_object_id`` serves a name-keyed caller that already holds the account's stored
        ``objectGUID``: when the name matches several entries, the one carrying that id is used
        (vault BACKLOG #3228, :meth:`_lookup_by_name`). Passing it with ``object_id`` is a
        programming error and raises :class:`ValueError`: an id-keyed search has no tie to break.
        """
        return self.probe_principal(
            username, object_id=object_id, tie_break_object_id=tie_break_object_id
        ).principal

    def probe_principal(
        self,
        username: str,
        *,
        object_id: str | None = None,
        tie_break_object_id: str | None = None,
    ) -> DirectoryProbe:
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

        if object_id is not None and tie_break_object_id is not None:
            raise ValueError("pass object_id or tie_break_object_id, not both")
        try:
            with self._service_session() as svc:
                found = (
                    self._lookup_by_object_id(svc, object_id, fallback_username=username)
                    if object_id is not None
                    else self._lookup_by_name(
                        svc, username, tie_break_object_id=tie_break_object_id
                    )
                )
                info = found.info
                if info is None:
                    return DirectoryProbe(found.answer)
                user_dn = str(info["dn"])
                groups = self._resolve_groups(svc, user_dn, info["memberOf"])
        except ldap3.core.exceptions.LDAPException as exc:
            raise _ldap3_failed(exc) from exc
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

        # Unbound when the block ends, however it ends (_service_session).
        try:
            with self._service_session() as svc:
                # Its own try: the bind has already succeeded here, so a failed Who am I is not a
                # bind failure, and the group read still runs.
                whoami_error: str | None = None
                try:
                    with _ldap3_call("Who am I"):
                        answered = svc.extend.standard.who_am_i()
                    who = _authzid_text(answered)
                except (ldap3.core.exceptions.LDAPException, LdapError) as exc:
                    # The type name only, as the group read below does: ldap3's text for an
                    # extended-operation error carries the directory's own diagnostic message.
                    # An LdapError is a response ldap3 could not decode (BACKLOG #3010), in
                    # engine text.
                    why = str(exc) if isinstance(exc, LdapError) else type(exc).__name__
                    who, whoami_error = None, f"Who am I failed: {why}"
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
                    # An LdapError is a refused referral, or a read that ended with a result code
                    # that is not success (BACKLOG #3010): noSuchObject, invalidDNSyntax for a bind
                    # identity that is a UPN rather than a DN, insufficientAccessRights. Both texts
                    # are the engine's own, naming the code and never the directory's diagnostic
                    # message.
                    why = str(exc) if isinstance(exc, LdapError) else type(exc).__name__
                    return BindAccountReading(
                        who, problem=f"group membership not read: {why}", whoami_error=whoami_error
                    )
                entry = svc.entries[0] if svc.entries else None
        except ldap3.core.exceptions.LDAPException as exc:
            raise _ldap3_failed(exc) from exc
        if entry is None:
            # A base read that ended with success and no entry: no directory should answer so.
            return BindAccountReading(
                who,
                problem="group membership not read: the base read of [auth].ad_bind_dn returned "
                "no entry; the read needs a distinguished name the account may read",
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
    A malformed value raises :class:`LdapError`; the settings validator refuses it at load first.
    Building the acceptor reads settings only, never a token, so every failure here is configuration.
    """
    import spnego

    try:
        if not settings.kerberos_spn:
            return spnego.server()
        service, hostname = split_kerberos_spn(settings.kerberos_spn)
        return spnego.server(hostname=hostname, service=service)
    except (spnego.exceptions.SpnegoError, ValueError) as exc:
        raise LdapError(str(exc)) from exc


def _kerberos_context_complete(server: Any) -> bool:
    """Whether one acceptor step finished the Kerberos context that checked the client's ticket.

    ``server.complete`` answers this for the native SSPI acceptor, which is what Windows uses. On
    any host without SSPI, Linux and macOS included, every sign-in goes through pyspnego's own
    Negotiate wrapper instead: pyspnego 0.12's GSSAPI proxy offers ``kerberos`` only, never
    ``negotiate``, so the default ``negotiate`` acceptor :func:`_kerberos_acceptor` asks for is
    always the wrapper there. The wrapper can stay incomplete after a step whose inner Kerberos
    context did finish. It waits for a ``mechListMIC`` (RFC 4178 section 4.2.2) when the client's
    first mechanism differs from its own, as a Windows client's does, and this single-leg acceptor
    never takes a second leg. So for that wrapper the inner context is read, and only a finished
    KERBEROS context counts. It is a private attribute: if pyspnego moves it, this returns
    ``False`` and the sign-in is refused.
    """
    if server.complete:
        return True
    try:
        from spnego._negotiate import NegotiateProxy  # lazy, like every spnego import here

        if not isinstance(server, NegotiateProxy):
            return False
        inner = server._context
    except (ImportError, AttributeError, KeyError, StopIteration):
        # The wrapper moved, or it chose no mechanism: nothing finished that can be read.
        return False
    return (
        getattr(inner, "complete", False) is True
        and getattr(inner, "negotiated_protocol", None) == "kerberos"
    )


def _refusal_diagnostic(exc: BaseException) -> str:
    """The log form of a refused token: class names and numeric codes, never message text.

    A provider's message can quote the token too. GSSAPI's names the ticket's service principal,
    which travels in cleartext, so the caller chose it. That also means the codes do not prove a
    configuration fault: a caller can name a principal the keytab lacks. ``code`` is pyspnego's
    ``ErrorCode``. ``maj_code``, ``min_code`` and ``winerror`` are the GSSAPI or SSPI status, read
    from the error itself (a raw provider error) and from the one pyspnego wrapped.
    """
    parts = [type(exc).__name__]
    code = getattr(exc, "ERROR_CODE", None)
    if isinstance(code, int):
        parts.append(f"code={int(code)}")
    parts.extend(_status_codes(exc))
    base = getattr(exc, "base_error", None)
    if isinstance(base, BaseException):
        parts.append(f"base={type(base).__name__}")
        parts.extend(_status_codes(base))
    return " ".join(parts)


def _status_codes(exc: BaseException) -> list[str]:
    """The numeric GSSAPI or SSPI status ``exc`` carries, as ``name=value`` pairs."""
    codes = []
    for attr in ("maj_code", "min_code", "winerror"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            codes.append(f"{attr}={value}")
    return codes


def kerberos_principal(token: bytes, settings: AuthSettings) -> str | None:
    """Complete one SPNEGO server step and return the authenticated sAMAccountName, or ``None``.

    Experimental — **not a supported v0.1 feature**: off by default (``kerberos_enabled=False``),
    production hardening (CI coverage, keytab/SPN preflight) targeted for 0.2. Single-leg only: no
    NTLM fallback, no mutual-auth response token, no multi-leg challenge handshake. The server must
    have a usable keytab/credential for ``kerberos_spn`` in its environment; the realm suffix
    (``user@REALM``) is stripped to yield the account name.

    ``None`` unless :func:`_kerberos_context_complete` says the context finished (BACKLOG #2610
    review point c), so no provider can hand back a principal from a half-done exchange. That is
    defence in depth: no such provider is known.

    Raises :class:`KerberosTokenRefused` when the acceptor refuses the token, and
    :class:`LdapError` when the acceptor cannot be built from settings or cannot read the principal
    of a token its step accepted.
    """
    server = _kerberos_acceptor(settings)
    refused: str | None = None
    try:
        server.step(token)
    except Exception as exc:
        # Deliberately broad, because step() parses bytes the caller chose. A list of types failed
        # here before (BACKLOG #3186). pyspnego raised StopIteration and KeyError outside it, and a
        # mutation search later found IndexError. Each was an unaudited 500. A StopIteration must
        # not reach asyncio.to_thread at all, because a Future refuses it.
        refused = type(exc).__name__
        # No message text crosses, into the refusal or the log. It can quote the token, as a
        # ValueError quotes a mechanism OID the caller chose (BACKLOG #3196).
        logger.warning("Kerberos sign-in refused the SPNEGO token: %s", _refusal_diagnostic(exc))
        # The traceback, for a pyspnego defect that looks like a refusal. DEBUG, as it holds text.
        logger.debug("Kerberos acceptor step raised", exc_info=True)
    if refused is not None:
        # Raised outside the except block, so neither __cause__ nor __context__ keeps the original.
        raise KerberosTokenRefused(refused)
    unreadable: str | None = None
    try:
        principal = server.client_principal if _kerberos_context_complete(server) else None
    except Exception as exc:
        # The step took the token, so this is the provider failing, not the caller's token. Broad,
        # because pyspnego does not wrap this read: SSPI raises an OSError and GSSAPI a GSSError, and
        # either one outside this arm was an unaudited 500. Without gssapi installed,
        # spnego.exceptions.GSSError is Exception itself, so no narrower tuple is honest.
        unreadable = _refusal_diagnostic(exc)
        logger.warning("Kerberos sign-in could not read the accepted principal: %s", unreadable)
        logger.debug("Kerberos principal read raised", exc_info=True)
    if unreadable is not None:
        # Severed like the refusal above, so no chained provider text rides out on the outage.
        raise LdapError(f"Kerberos principal read failed: {unreadable}")
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
    if not _kerberos_capable():
        raise LdapError(
            "no Kerberos-capable SPNEGO provider on this host — SSPI (Windows) or the GSSAPI/krb5 "
            "libraries (Linux) are required; the pure-Python NTLM fallback cannot validate a ticket"
        )
    _kerberos_acceptor(settings)
