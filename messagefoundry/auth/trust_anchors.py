# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Operator-supplied trust-anchor integrity (ASVS 6.7.1, BACKLOG #285).

With OIDC and/or AD federation enabled the engine holds operator-supplied CA anchors on the LIVE
authentication path:

* ``[auth].oidc_tls_ca_cert_file`` — trusts the OIDC IdP legs (token endpoint + JWKS); loaded into the
  one opener both legs share (:func:`messagefoundry.auth.oidc_http.build_idp_opener`). Substituting this
  PEM permits JWKS substitution and forged id_tokens.
* ``[auth].ad_tls_ca_cert_file`` — trusts the AD LDAPS bind (:mod:`messagefoundry.auth.ldap`).
  Substituting this PEM permits an LDAPS MITM. It has **no** opener-construction seam, so its check
  lives in the central preflight below (per the #285 binding correction).
* ``[api].tls_client_ca_file`` — the in-process mTLS console client-CA (:mod:`messagefoundry.api.tls`),
  which maps a verified peer cert to a principal with no bearer token. Substituting it admits a forged
  client cert.

The engine previously applied **no** integrity control to any of these. This module adds three, and is
**dormant when no anchor is configured** — zero anchors set means byte-identical behaviour (no preflight
runs, no audit rows, no new settings effects):

1. A **read-only ACL preflight**: a group-/world-**writable** anchor (anyone who can write the file can
   substitute the CA and defeat authentication) is **refused** at ``[security].enforcement = enforce``
   and **warned + audited** at ``warn``. It reuses ``_secure_file``'s ``icacls`` DACL mechanism as a
   *verify-only* companion — it inspects the DACL and never changes it. Readability is deliberately not
   the threat (a CA certificate is public); tamperability is. The verdict is **tri-state**: a DACL the
   engine could not read is ``acl_indeterminate``, audited and warned but not refused, and never
   reported as owner-only (BACKLOG #1142).
2. An **optional SHA-256 fingerprint pin** per anchor. A configured pin that the PEM's SHA-256 does not
   match **refuses** — always, independent of the enforcement dial — at construction and at reload.
3. An **anchor-changed audit event**: when a configured anchor's SHA-256 differs from the previously
   observed load's, a first-class ``auth.trust_anchor`` audit row is written (reusing
   :meth:`~messagefoundry.store.base.Store.record_audit`, mirroring the ``config_reload`` fingerprint row).
4. A **path check** (BACKLOG #1142, the directory arm): every object from the volume root down to the
   anchor, links included, read in-process by SID on Windows and by ``lstat`` on POSIX
   (:mod:`messagefoundry.auth.anchor_path`). A directory that lets an untrusted principal delete or
   rename an entry lets it replace the anchor without any right on the file itself. ``path_ok`` is
   ``False`` then, and it refuses at ``enforce`` and warns at ``warn``, as ``acl_ok`` does. A chain
   that could not be read is ``path_indeterminate``: audited and warned, not refused. The file arm
   (1) still runs beside it, so the combined verdict is never weaker than the file arm alone.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess  # nosec B404 — used only to read a DACL via icacls (fixed tool, no shell)
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from messagefoundry.auth.anchor_path import (
    DIRECTORY,
    LINK,
    ChainFinding,
    PathVerdict,
    anchor_path_verdict,
)
from messagefoundry.service_status import _system_exe

if TYPE_CHECKING:
    from messagefoundry.config.settings import ApiSettings, AuthSettings
    from messagefoundry.store.base import Store

log = logging.getLogger(__name__)

#: The audit action for every trust-anchor observation. One action so an operator can filter the whole
#: family, and so :func:`_last_fingerprint` can find the prior load. The ``event`` field in the detail
#: carries which one: ``observed`` (baseline), ``changed``, ``pin_mismatch``, ``acl_insecure``,
#: ``acl_indeterminate`` (the ACL could not be determined, BACKLOG #1142), and ``path_insecure`` and
#: ``path_indeterminate`` (the path check, BACKLOG #1142 directory arm).
AUDIT_ACTION = "auth.trust_anchor"


class TrustAnchorError(Exception):
    """An operator-supplied auth-path trust anchor failed its integrity preflight — a configured
    SHA-256 pin mismatch, or a group-/world-writable DACL under ``[security].enforcement = enforce``.
    Raised at construction and at reload so the engine refuses a tampered/exposed anchor rather than
    silently trusting it."""


@dataclass(frozen=True)
class AnchorSpec:
    """One operator-supplied trust anchor to preflight.

    ``label`` is the stable, PHI-free audit key (``"oidc"`` / ``"ad"`` / ``"api_client"``); ``setting``
    is the human-facing config key for messages; ``path`` is the configured PEM; ``pin`` is the optional
    configured SHA-256 pin (any case, optional ``:`` separators)."""

    label: str
    setting: str
    path: str
    pin: str | None = None


@dataclass(frozen=True)
class AnchorVerdict:
    """The pure result of inspecting an anchor file (no enforcement, no I/O side effects)."""

    fingerprint: str
    acl_ok: bool | None  # None = the DACL could not be determined (degrade, don't refuse)
    pin_ok: bool | None  # None = no pin configured
    # False = another principal can replace the anchor through its path; None = could not tell.
    path_ok: bool | None = None
    path_check: PathVerdict | None = None  # the findings behind path_ok, for messages and audit


# --- fingerprint --------------------------------------------------------------------------------


def anchor_fingerprint(path: str | os.PathLike[str]) -> str:
    """Lowercase-hex SHA-256 of the anchor PEM's bytes.

    A missing/unreadable anchor raises the underlying :class:`OSError` — the engine already refuses to
    start on a missing/unreadable CA (``build_idp_opener`` / ``load_verify_locations`` do), and this
    preserves that fail-closed contract rather than masking it as a softer error."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _normalize_pin(pin: str) -> str:
    """A configured pin normalized to 64 lowercase hex chars. Accepts optional ``:`` separators and any
    case. Raises :class:`TrustAnchorError` on a malformed pin (fail loud, never silently never-match)."""
    cleaned = pin.strip().lower().replace(":", "")
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise TrustAnchorError(
            "a trust-anchor pin must be a SHA-256 hex digest (64 hex chars, optional ':'); "
            f"got {pin!r}"
        )
    return cleaned


# --- read-only DACL inspection (mirrors _secure_file's icacls mechanism, verify-only) -----------

#: Group/world principals whose members are not the file owner — a WRITE grant to any of them means a
#: non-owner can substitute the anchor. SYSTEM and Administrators are deliberately absent: they are
#: already trusted (they can rewrite any file regardless).
#:
#: The English display names, in two sets, both matched WHOLE rather than as substrings. A substring
#: match read an ordinary account such as ``DESKTOP-A\usersync`` as ``\Users``, and a false "broad"
#: refuses a secure anchor under enforce. This half is **at least** these and can never be complete:
#: ``icacls`` resolves a SID to its *localized* name by default, so a German ``Jeder`` or a Spanish
#: ``Todos`` is Everyone under a name this set does not carry. The SID half below is the
#: locale-invariant matcher; this one is a convenience for the host that speaks English.
#:
#: Whole principal tokens. ``NT AUTHORITY\`` stays on the pseudo-groups so an account named
#: ``DOMAIN\Service`` is not read as ``NT AUTHORITY\SERVICE``, and ``Local account`` is whole so
#: ``Local account and member of Administrators group`` (trusted, as Administrators) is not caught.
_BROAD_PRINCIPAL_NAMES: frozenset[str] = frozenset(
    {
        "everyone",
        "nt authority\\authenticated users",
        "nt authority\\interactive",
        "nt authority\\service",
        "nt authority\\batch",
        "nt authority\\network",
        "nt authority\\anonymous logon",
        "nt authority\\local account",
    }
)

#: Group names matched whole against the part after the LAST ``\`` of the token, under any qualifier:
#: ``BUILTIN\Users``, ``DOMAIN\Users`` and ``DOMAIN\Domain Users`` all match.
_BROAD_GROUP_LEAF_NAMES: frozenset[str] = frozenset(
    {"users", "domain users", "guests", "domain guests", "authenticated users"}
)

#: The locale-invariant half: well-known SIDs, matched **whole** against the principal token, with or
#: without a leading ``*`` (plain ``icacls`` printed an unresolvable SID with none, measured on
#: Windows 11). Whole-token matching is load-bearing rather than tidiness: as substrings,
#: ``S-1-5-3`` (BATCH) is a prefix of ``S-1-5-32-544`` (``BUILTIN\Administrators``, deliberately
#: trusted) and ``S-1-5-11`` (Authenticated Users) of ``S-1-5-114`` (local administrators), so a
#: substring set would report the administrators ACE that sits on every ordinary Windows file as a
#: broad-principal write.
_BROAD_PRINCIPAL_SIDS: frozenset[str] = frozenset(
    {
        "s-1-1-0",  # Everyone
        "s-1-5-11",  # Authenticated Users
        "s-1-5-32-545",  # BUILTIN\Users
        "s-1-5-32-546",  # BUILTIN\Guests
        "s-1-5-2",  # NT AUTHORITY\NETWORK
        "s-1-5-3",  # NT AUTHORITY\BATCH
        "s-1-5-4",  # NT AUTHORITY\INTERACTIVE
        "s-1-5-6",  # NT AUTHORITY\SERVICE
        "s-1-5-7",  # NT AUTHORITY\ANONYMOUS LOGON
        "s-1-5-113",  # NT AUTHORITY\Local account (every local user)
    }
)

#: Domain-relative RIDs that are broad in every domain: an unresolved ``S-1-5-21-<domain>-<rid>``.
_BROAD_DOMAIN_RIDS: frozenset[str] = frozenset({"513", "514"})  # Domain Users, Domain Guests

# INTERACTIVE, SERVICE and BATCH are broad here, as ``_evaluate_config_dacl``
# (``messagefoundry/config/wiring.py``) also refuses them. Commit 0adde6059 measured why on
# Windows 11: ``icacls C:\Users\Public`` lists ``NT AUTHORITY\INTERACTIVE:(OI)(CI)(IO)(M,DC)`` and
# the same for SERVICE and BATCH, which object-inherit propagates as ``(I)(M)`` onto every file
# created there. An anchor placed in that directory is modifiable by every interactive logon, and
# before BACKLOG #1142 it read as owner-only.
#
# CREATOR OWNER and OWNER RIGHTS are NOT broad, matching wiring.py's trusted set. OWNER RIGHTS
# (S-1-3-4) carries the current owner's rights. CREATOR OWNER (S-1-3-0) is a placeholder that no
# logon token ever carries, so an ACE for it on a file grants nobody anything.

#: icacls right tokens that permit modifying or replacing the file (simple + specific write masks).
#: DELETE (``D``/``DE``) is here because deleting an anchor and planting a new one replaces it, and
#: wiring.py's write mask counts DELETE too.
_WRITE_RIGHTS: frozenset[str] = frozenset(
    {"F", "M", "W", "D", "DE", "WD", "AD", "WEA", "WA", "WO", "WDAC", "GA", "GW"}
)


def _is_broad_sid(token: str) -> bool:
    """Whether a lowercased token is a broad SID, matched whole, with or without a leading ``*``."""
    sid = token.lstrip("*")
    if sid in _BROAD_PRINCIPAL_SIDS:
        return True
    return sid.startswith("s-1-5-21-") and sid.rsplit("-", 1)[-1] in _BROAD_DOMAIN_RIDS


def _is_broad_principal(principal: str) -> bool:
    """Whether an already-lowercased icacls principal token names an identity broader than the file's
    owner. Every match is whole: the SID after any leading ``*``, the display name as a whole token,
    or a group name as the part after the last ``\\``."""
    if _is_broad_sid(principal) or principal in _BROAD_PRINCIPAL_NAMES:
        return True
    return principal.rsplit("\\", 1)[-1] in _BROAD_GROUP_LEAF_NAMES


def _ends_in_broad_principal(text: str) -> bool:
    """Whether lowercased line-1 text, path echo and all, ENDS in a broad principal.

    The parser uses this on line 1 whenever the path echo was not verbatim, so it cannot be sure
    where the principal starts. The principal always comes last, after whitespace, so a broad one
    is a whole-word suffix: a SID as the last word, a display name after a space, or a group leaf
    after the last ``\\``. This keeps a line-1 broad grant visible whatever the echo looked like.

    It errs toward broad on purpose. It cannot tell ``<path> Everyone`` from ``<path> CORP\\Not
    Everyone``, and a missed broad grant is the failure to avoid. The leaf is taken after the last
    ``\\`` only, never after the last space, so ``CORP\\Power Users`` does not read as ``Users``."""
    flat = " ".join(text.split())
    if flat and _is_broad_sid(flat.rsplit(" ", 1)[-1]):
        return True
    if any(flat == name or flat.endswith(" " + name) for name in _BROAD_PRINCIPAL_NAMES):
        return True
    return flat.rsplit("\\", 1)[-1] in _BROAD_GROUP_LEAF_NAMES


def _echoed_path_pattern(anchor_path: str) -> re.Pattern[str]:
    """A fixed-width pattern for the path as ``icacls`` echoes it at the start of line 1.

    icacls writes the OEM code page, so a character outside it does not come back as itself.
    Measured on Windows 11 (OEM 437): two CJK characters echoed as ``??``, an emoji as ``??``, and
    ``l-stroke`` as a best-fit ``l``. So an ASCII character must match itself, ignoring case, and any
    other character matches one character of any kind: two outside the BMP, which icacls counts as
    two UTF-16 units. Every width in the path part is fixed. Whitespace or the end of the line must
    follow the path, and that trailing ``\\s+`` is the one repetition: nothing follows it, so a
    failed ``.match`` has nothing to backtrack into.

    The template is written inside the ``re.compile`` call on purpose: the ReDoS blind-spot pin in
    ``tests/test_security_static.py`` records the argument's source text, so an edit to how each
    character is rendered reds that pin rather than hiding behind a local name."""
    return re.compile(
        "".join(
            re.escape(ch) if ch.isascii() else (".." if ord(ch) > 0xFFFF else ".")
            for ch in anchor_path
        )
        + r"(?:\s+|$)",
        re.IGNORECASE,
    )


def _continuation_indent(lines: list[str]) -> int | None:
    """The indent of the first ACE line after line 1, or ``None`` if there is none.

    icacls pads each continuation line to the width of the path it ECHOED, plus one space. Measured
    on Windows 11: a CJK, an emoji and a best-fit path each padded to the echo, not to the path
    passed. So this column is where line 1's principal starts, whatever the echo looked like."""
    seen_first = False
    for raw in lines:
        if not raw.strip():
            continue
        if not seen_first:
            seen_first = True
            continue
        if ":(" in raw:
            return (len(raw) - len(raw.lstrip())) or None
    return None


def _path_echo_end(line: str, anchor_path: str, indent: int | None) -> tuple[int, bool] | None:
    """Where the echoed path ends on line 1, and whether the echo was verbatim.

    ``None`` when the end cannot be found reliably. A verbatim echo is trusted as it stands. A
    lenient match (:func:`_echoed_path_pattern`) must agree with the continuation indent when there
    is one, because an echo narrower than the path would let the pattern run into a principal that
    contains a space, such as ``NT AUTHORITY\\INTERACTIVE``."""
    n = len(anchor_path)
    if line[:n].lower() == anchor_path.lower() and (len(line) == n or line[n].isspace()):
        return n, True
    echo = _echoed_path_pattern(anchor_path).match(line)
    if echo is None or (indent is not None and echo.end() != indent):
        return None
    return echo.end(), False


#: Bare (unqualified) principal names that are the owner, or that grant nobody anything, so a write
#: grant to them is not a non-owner write. Matched whole against the lowercased principal token.
_OWNER_BARE_NAMES: frozenset[str] = frozenset({"owner rights", "creator owner"})


def _is_bare_name(principal: str) -> bool:
    """Whether an icacls principal token is a bare display name: no ``DOMAIN\\`` qualifier and no
    SID form. The file's owner is always an account, and icacls always prints an account
    qualified (``COMPUTER\\user``, ``DOMAIN\\user``, ``AzureAD\\user``). Bare names are the
    well-known groups icacls prints unqualified, such as ``Everyone`` -- and their localized forms,
    such as the German ``Jeder``, which no name set can list in full.

    A SID is excluded with or without the leading ``*``: measured on Windows 11, plain ``icacls``
    prints an unresolvable SID bare (``S-1-5-21-...:(I)(M)``), and the well-known broad SIDs are
    already matched whole by :data:`_BROAD_PRINCIPAL_SIDS`. The names in :data:`_OWNER_BARE_NAMES`
    are excluded too. ``OWNER RIGHTS`` is the owner: measured on Windows 11, a pytest temp file
    carries ``OWNER RIGHTS:(I)(F)`` beside SYSTEM and Administrators and nothing else. Only their
    English names are listed, so a host that localizes them reads such a file as ``None``."""
    if "\\" in principal or principal.lstrip("*").startswith("s-1-"):
        return False
    return principal not in _OWNER_BARE_NAMES


def owner_only_from_icacls(text: str, *, anchor_path: str) -> bool | None:
    """Parse ``icacls <path>`` output into a **tri-state** verdict. Pure — unit-tested with synthetic
    icacls output.

    * ``True`` — at least one ACE was read and no broad group/world principal holds a write-capable
      right (owner-only-writable).
    * ``False`` — such a principal does hold one.
    * ``None`` — the DACL could **not be determined**.

    **Determined means exactly this: at least one line parsed as an ACE, i.e. a non-empty principal
    token followed by a ``:(rights)`` blob.** Empty output, a read cut off before its first ACE, a
    banner or trailer with no ACE under it, and text that is not icacls output at all therefore all
    answer ``None``. A read cut off AFTER an ACE is not detected: the only end marker is the success
    trailer, which is localized, and :func:`dacl_is_owner_only` already answers ``None`` on the
    non-zero exit a killed ``icacls`` returns. Before
    BACKLOG #1142 this returned ``bool`` and fell through to ``True``, so "no broad principal has
    write" and "I parsed nothing" were the same answer — and the second is an affirmative assertion of
    owner-only storage the parser has no basis for. ``None`` is the caller's cue to degrade.

    Broad principals are matched by locale-invariant SID and by **at least** the English display names
    in :data:`_BROAD_PRINCIPAL_NAMES`. Because ``icacls`` resolves SIDs to localized names by default,
    that name set cannot be complete across locales. So a write-capable ACE held by a **bare** name
    the set does not recognise (no ``DOMAIN\\`` qualifier and not a SID, e.g. the German ``Jeder``
    for Everyone) answers ``None``, not ``True``: the owner never prints bare, so such a principal is
    an unrecognised group and the parser has no basis to call it harmless. A localized *qualified*
    group (e.g. ``VORDEFINIERT\\Benutzer`` for ``BUILTIN\\Users``) is still not caught by name, so a
    ``True`` from a non-English host remains weaker than one from an English host. Closing that needs
    a SID-form read (the in-process DACL walk ``config/wiring.py`` already ships) and is not done here.

    The known ``anchor_path`` is stripped from line 1, and from line 1 only, so a path that
    legitimately contains ``\\Users`` (e.g. ``C:\\Users\\svc\\anchor.pem``) is never mistaken for a
    ``BUILTIN\\Users`` ACE. icacls echoes that path in the OEM code page, so where the echo is not
    verbatim it is matched leniently and checked against the continuation indent
    (:func:`_path_echo_end`). On any line 1 that is not a verbatim echo, a broad principal at the
    end of the line answers ``False``. Where the end of the echo cannot be found at all, any other
    write grant on line 1 answers ``None``, so an unmatched echo never yields ``True`` for a write.

    Lines split on ``\\n`` only. ``str.splitlines`` also splits on U+2028 and its kin, which a path
    may contain, and that would move line 1's ACE onto a line with the path still on its front."""
    lines = text.split("\n")
    indent = _continuation_indent(lines)
    saw_ace = False
    unattributed_write = False
    first_line = True
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        is_first, first_line = first_line, False
        low = line.lower()
        if low.startswith("successfully processed") or low.startswith("failed processing"):
            continue
        # Line 1 carries the path prefix; skip it so its characters can't be read as a principal.
        # Only line 1: a short relative path such as "NT" would cut the front off "NT AUTHORITY\..."
        # on a later line.
        start = 0
        echo_verbatim = True
        path_left_on = False
        if is_first:
            found = _path_echo_end(line, anchor_path, indent)
            if found is None:
                path_left_on, echo_verbatim = True, False
            else:
                start, echo_verbatim = found
        idx = line.find(":(", start)
        if idx == -1:
            continue
        principal = line[start:idx].strip().lower()
        if not principal:
            continue  # a rights blob with nothing in front of it is attributable to nobody
        rights_blob = line[idx:]
        tokens = {t.strip().upper() for t in re.split(r"[(),]", rights_blob) if t.strip()}
        # A DENY reduces access; it never grants write.
        grants_write = "(deny)" not in rights_blob.lower() and bool(tokens & _WRITE_RIGHTS)
        if grants_write and not echo_verbatim and _ends_in_broad_principal(line[:idx].lower()):
            return False  # the echo was not verbatim, so check the line's end as well as the split
        if path_left_on:
            # Nobody knows where the echo ends. This ACE counts toward nothing determined, and a
            # write in it that is not visibly broad is unattributable.
            unattributed_write = unattributed_write or grants_write
            continue
        saw_ace = True
        if not grants_write:
            continue
        if _is_broad_principal(principal):
            return False  # a broad write settles it; the rest of the DACL cannot take it back
        if _is_bare_name(principal):
            unattributed_write = True
    if not saw_ace or unattributed_write:
        return None
    return True


def dacl_is_owner_only(path: str | os.PathLike[str]) -> bool | None:
    """Whether the anchor is writable only by its owner (+ the always-trusted SYSTEM/Administrators),
    i.e. no group/world principal can modify it. READ-ONLY: it never changes the file's ACL (unlike
    ``_secure_file``, whose ``icacls`` mechanism it mirrors). ``None`` when the DACL cannot be
    determined, so the caller degrades rather than refusing on an inconclusive read.

    These make it undeterminable on Windows, and all answer ``None``: ``icacls`` could not be run,
    it exited non-zero, it returned no output, or (BACKLOG #1142) the parser answered ``None``. That
    last covers three causes the warning names together: no ACE it could attribute to a principal,
    a write grant to a bare principal name it does not recognise, or a write grant on line 1 whose
    principal could not be split from the echoed path.

    * POSIX: no group- or other-WRITE bit (``mode & 0o022 == 0``).
    * Windows: read the DACL with ``icacls <path>`` (no modifying flags) and flag any broad-group ACE
      that grants a write-capable right."""
    if os.name == "nt":
        try:
            # icacls is pinned to its absolute System32 path and invoked without a shell; the path is
            # a single argv token, never a shell word (matches _secure_file's low-27/STORE-5 note).
            # No modifying flags. The pin is what makes "fixed system tool" true: CreateProcess
            # resolves an unqualified name through a search path that reaches the caller's working
            # directory, and this call's OUTPUT is what decides the verdict below, so a planted
            # icacls.exe printing a clean DACL would turn a group-writable anchor into an accepted
            # one (BACKLOG #1769).
            result = subprocess.run(  # nosec B603 B607
                [_system_exe("icacls.exe"), os.fspath(path)],
                check=False,
                capture_output=True,
                # icacls writes the OEM code page to a pipe. Decoding it with the default ANSI code
                # page failed on a non-ASCII path (measured: "Schluessel" with u-umlaut came back as
                # byte 0x81, stdout arrived as None, and the parse raised AttributeError, which no
                # caller catches). "oem" decodes it so the echoed path matches the one passed;
                # errors="replace" keeps a stray byte from ever making the read crash.
                encoding="oem",
                errors="replace",
            )
        except OSError as exc:
            log.warning("icacls could not read the DACL of %s: %s", path, exc)
            return None
        if result.stdout is None:
            log.warning("icacls returned no readable output for %s", path)
            return None
        if result.returncode != 0:
            log.warning(
                "icacls could not read the DACL of %s (exit %s): %s",
                path,
                result.returncode,
                (result.stderr or result.stdout or "").strip(),
            )
            return None
        parsed = owner_only_from_icacls(result.stdout, anchor_path=os.fspath(path))
        if parsed is None:
            log.warning(
                "icacls exited 0 for %s but its output carried no readable ACE, granted write to a "
                "bare principal name it does not recognise, or granted write on a first line whose "
                "path echo did not match; the DACL could not be determined",
                path,
            )
        return parsed
    try:
        mode = Path(path).stat().st_mode
    except OSError as exc:
        log.warning("could not stat %s to check its permissions: %s", path, exc)
        return None
    return (mode & 0o022) == 0


# --- evaluation + enforcement -------------------------------------------------------------------


def evaluate_anchor(spec: AnchorSpec) -> AnchorVerdict:
    """Inspect one anchor file: compute its fingerprint, its DACL verdict, and (if pinned) whether the
    fingerprint matches the pin. Pure inspection — no enforcement, no audit. Reads the file + the DACL,
    so callers on the event loop should dispatch it via :func:`asyncio.to_thread`."""
    fingerprint = anchor_fingerprint(spec.path)
    pin_ok: bool | None = None
    if spec.pin is not None:
        pin_ok = fingerprint == _normalize_pin(spec.pin)
    path_check = anchor_path_verdict(spec.path)
    return AnchorVerdict(
        fingerprint=fingerprint,
        acl_ok=dacl_is_owner_only(spec.path),
        pin_ok=pin_ok,
        path_ok=path_check.ok,
        path_check=path_check,
    )


def _pin_mismatch_message(spec: AnchorSpec, verdict: AnchorVerdict) -> str:
    return (
        f"{spec.setting}: the trust anchor {spec.path!r} does not match its configured SHA-256 pin "
        f"(loaded {verdict.fingerprint}); refusing to load a substituted anchor"
    )


def _acl_message(spec: AnchorSpec) -> str:
    return (
        f"{spec.setting}: the trust anchor {spec.path!r} is writable by a non-owner (group/world DACL) "
        "— anyone who can modify it can substitute the CA and defeat authentication; restrict it to "
        "owner-only (see docs/security/OFF-LOOPBACK-DEPLOYMENT.md)"
    )


def _findings(verdict: AnchorVerdict, *, insecure: bool) -> list[ChainFinding]:
    check = verdict.path_check
    return [f for f in (check.findings if check else ()) if f.insecure is insecure]


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _sh_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def _path_fix(verdict: AnchorVerdict) -> list[str]:
    """The fix, as commands, for every insecure object. The message must carry its own fix: the
    document the file arm's message cites ships in neither a checkout nor a wheel."""
    check = verdict.path_check
    bad = _findings(verdict, insecure=True)
    objects: dict[str, str] = {}
    for f in bad:
        objects.setdefault(f.path, f.kind)
    if check is not None and check.platform == "windows":
        account = f"*{check.engine_sid}" if check.engine_sid else "<the engine's account>"
        lines = [
            "Fix: move the anchor into a directory that only administrators and the engine's "
            "account can change, such as the engine's data directory under C:\\ProgramData. Or, "
            "from an elevated PowerShell, for each object named above:"
        ]
        for obj, kind in objects.items():
            q = _ps_quote(obj)
            inherit = "(OI)(CI)" if kind == DIRECTORY else ""
            link = " /L" if kind == LINK else ""
            grants = " ".join(
                _ps_quote(f"{sid}:{inherit}{right}")
                for sid, right in (("*S-1-5-18", "F"), ("*S-1-5-32-544", "F"), (account, "RX"))
            )
            lines.append(f"  icacls {q}{link} /inheritance:r /grant:r {grants}")
            sids = sorted({sid for f in bad if f.path == obj for sid in f.sids})
            if sids:
                removed = " ".join(_ps_quote("*" + sid) for sid in sids)
                lines.append(f"  icacls {q}{link} /remove:g {removed}")
            lines.append(f"  icacls {q}{link} /setowner '*S-1-5-32-544'")
        lines.append("Then read each one back with: icacls <path>")
        return lines
    lines = [
        "Fix: move the anchor under a root-owned 755 directory such as /etc/messagefoundry/. Or, "
        "for each object named above:"
    ]
    for obj in objects:
        lines.append(f"  chown root:root {_sh_quote(obj)} && chmod go-w {_sh_quote(obj)}")
    return lines


def _path_message(spec: AnchorSpec, verdict: AnchorVerdict) -> str:
    lines = [
        f"{spec.setting}: the trust anchor '{spec.path}' can be replaced through its path, and "
        "anyone who replaces it can substitute the CA and defeat authentication:"
    ]
    lines += [f"  {f.kind} '{f.path}': {f.reason}" for f in _findings(verdict, insecure=True)]
    return "\n".join(lines + _path_fix(verdict))


def _path_indeterminate_message(spec: AnchorSpec, verdict: AnchorVerdict) -> str:
    lines = [
        f"{spec.setting}: could not settle whether the trust anchor '{spec.path}' can be replaced "
        "through its path, so it is loaded without that check:"
    ]
    lines += [f"  {f.kind} '{f.path}': {f.reason}" for f in _findings(verdict, insecure=False)]
    return "\n".join(lines)


def _enforce_verdict(spec: AnchorSpec, verdict: AnchorVerdict, *, enforcing: bool) -> None:
    """Apply the owner fork to a verdict: a pin mismatch always refuses; a group/world-writable DACL,
    or a path another principal can replace the anchor through, refuses at ``enforce`` and warns at
    ``warn``. A path that could not be judged warns at both. Raises :class:`TrustAnchorError` on a
    fatal violation."""
    if verdict.pin_ok is False:
        raise TrustAnchorError(_pin_mismatch_message(spec, verdict))
    if verdict.acl_ok is False:
        if enforcing:
            raise TrustAnchorError(
                _acl_message(spec) + " — [security].enforcement=enforce refuses to start"
            )
        log.warning("%s — [security].enforcement=warn, starting anyway", _acl_message(spec))
    if verdict.path_ok is False:
        if enforcing:
            raise TrustAnchorError(
                _path_message(spec, verdict) + "\n[security].enforcement=enforce refuses to start"
            )
        log.warning(
            "%s\n[security].enforcement=warn, starting anyway", _path_message(spec, verdict)
        )
    elif verdict.path_ok is None:
        # Not fatal, as acl_ok None is not: a refusal here must wait until the verified bytes are the
        # bytes the consumer loads (BACKLOG #1142, slice 3).
        log.warning("%s", _path_indeterminate_message(spec, verdict))


def enforce_anchor(spec: AnchorSpec, *, enforcing: bool) -> str:
    """Construction-site preflight (no store/audit): evaluate + enforce one anchor, returning its
    fingerprint. Used by ``build_idp_opener`` / ``build_api_ssl_context`` so a pinned or exposed anchor
    fails fast at the point the CA is loaded into an opener/context."""
    verdict = evaluate_anchor(spec)
    _enforce_verdict(spec, verdict, enforcing=enforcing)
    return verdict.fingerprint


# --- spec collection ----------------------------------------------------------------------------


def api_client_anchor_spec(api: ApiSettings) -> AnchorSpec | None:
    """The ``[api].tls_client_ca_file`` anchor spec, or ``None`` when unset (dormant)."""
    if not api.tls_client_ca_file:
        return None
    return AnchorSpec(
        "api_client", "[api].tls_client_ca_file", api.tls_client_ca_file, api.tls_client_ca_pin
    )


def collect_anchor_specs(auth: AuthSettings, api: ApiSettings) -> list[AnchorSpec]:
    """Every configured operator-supplied auth-path trust anchor, in a stable order. An anchor with no
    path set is omitted, so an install with no OIDC/AD/mTLS anchor yields an empty list — the dormant,
    byte-identical path."""
    specs: list[AnchorSpec] = []
    if auth.oidc_tls_ca_cert_file:
        specs.append(
            AnchorSpec(
                "oidc",
                "[auth].oidc_tls_ca_cert_file",
                auth.oidc_tls_ca_cert_file,
                auth.oidc_tls_ca_cert_pin,
            )
        )
    if auth.ad_tls_ca_cert_file:
        specs.append(
            AnchorSpec(
                "ad",
                "[auth].ad_tls_ca_cert_file",
                auth.ad_tls_ca_cert_file,
                auth.ad_tls_ca_cert_pin,
            )
        )
    api_spec = api_client_anchor_spec(api)
    if api_spec is not None:
        specs.append(api_spec)
    return specs


# --- central preflight (store-backed: audit the load, detect changes, then enforce) -------------


async def _last_fingerprint(store: Store, label: str) -> str | None:
    """The most-recently audited fingerprint for ``label``, or ``None`` if this anchor has never been
    observed. Reads the ``auth.trust_anchor`` audit rows (most-recent-first) and returns the first
    matching label's fingerprint."""
    rows = await store.list_audit(action=AUDIT_ACTION, limit=200)
    for row in rows:
        detail_raw = row["detail"]
        if not detail_raw:
            continue
        try:
            detail = json.loads(detail_raw)
        except (ValueError, TypeError):
            continue
        if detail.get("label") == label:
            fp = detail.get("fingerprint")
            return fp if isinstance(fp, str) else None
    return None


async def _record(store: Store, spec: AnchorSpec, event: str, **extra: object) -> None:
    detail = {"label": spec.label, "setting": spec.setting, "event": event, **extra}
    await store.record_audit(AUDIT_ACTION, actor=None, detail=json.dumps(detail))


async def _preflight_one(store: Store, spec: AnchorSpec, *, enforcing: bool) -> None:
    """Preflight one anchor: audit the observation (baseline / changed) FIRST so a change is durably
    recorded even when the anchor then fails its pin/ACL, record any violation, then enforce (which may
    raise)."""
    verdict = await asyncio.to_thread(evaluate_anchor, spec)
    previous = await _last_fingerprint(store, spec.label)
    if previous is None:
        await _record(store, spec, "observed", fingerprint=verdict.fingerprint)
    elif previous != verdict.fingerprint:
        await _record(store, spec, "changed", fingerprint=verdict.fingerprint, previous=previous)
    if verdict.pin_ok is False:
        await _record(store, spec, "pin_mismatch", fingerprint=verdict.fingerprint)
    if verdict.acl_ok is False:
        await _record(
            store, spec, "acl_insecure", fingerprint=verdict.fingerprint, enforcing=enforcing
        )
    elif verdict.acl_ok is None:
        # BACKLOG #1142. This branch used to write no row at all, so an operator following the
        # runbook's "alert on auth.trust_anchor" instruction saw nothing on the one branch where the
        # engine cannot vouch for the anchor — a detective control blind on its own subject.
        #
        # It is deliberately VISIBLE and NOT FATAL. Refusing here would buy the verdict with
        # availability, and it must not ship before the verified bytes are bound to the bytes the
        # opener actually loads: until then a refusal would attest a file that is re-read afterwards.
        await _record(
            store, spec, "acl_indeterminate", fingerprint=verdict.fingerprint, enforcing=enforcing
        )
    if verdict.path_ok is not True:
        # Each row names every object that failed, with the principal and the right, or the cause.
        insecure = verdict.path_ok is False
        await _record(
            store,
            spec,
            "path_insecure" if insecure else "path_indeterminate",
            fingerprint=verdict.fingerprint,
            enforcing=enforcing,
            components=[
                {"path": f.path, "kind": f.kind, "reason": f.reason}
                for f in _findings(verdict, insecure=insecure)
            ],
        )
    _enforce_verdict(spec, verdict, enforcing=enforcing)


async def run_anchor_preflight(
    specs: Sequence[AnchorSpec], store: Store, *, enforcing: bool
) -> None:
    """The central load/reload preflight over every configured anchor. Called at serve startup (before
    any listener binds) and on a config reload (re-reading the on-disk PEMs, so a swapped anchor is
    caught). **Dormant when ``specs`` is empty** — it makes no store call and writes no audit row, so an
    install with no OIDC/AD/mTLS anchor is byte-identical.

    On a fatal violation (pin mismatch, or a group/world-writable DACL under ``enforce``) it raises
    :class:`TrustAnchorError` after auditing it, so the caller refuses to start / refuses the reload."""
    for spec in specs:
        await _preflight_one(store, spec, enforcing=enforcing)
