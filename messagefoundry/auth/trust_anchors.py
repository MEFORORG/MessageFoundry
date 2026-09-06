# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

if TYPE_CHECKING:
    from messagefoundry.config.settings import ApiSettings, AuthSettings
    from messagefoundry.store.base import Store

log = logging.getLogger(__name__)

#: The audit action for every trust-anchor observation. One action so an operator can filter the whole
#: family, and so :func:`_last_fingerprint` can find the prior load. The ``event`` field in the detail
#: carries which one: ``observed`` (baseline), ``changed``, ``pin_mismatch``, ``acl_insecure``, and
#: ``acl_indeterminate`` (the ACL could not be read at all — BACKLOG #1142).
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
#: The English display names, matched as a lowercase substring of the icacls principal token (so
#: ``BUILTIN\Users`` and ``DOMAIN\Domain Users`` both match). This half is **at least** these and can
#: never be complete: ``icacls`` resolves a SID to its *localized* name by default, so a German
#: ``Jeder`` or a Spanish ``Todos`` is Everyone under a name this set does not carry. The SID half
#: below is the locale-invariant matcher; this one is a convenience for the host that speaks English.
#: The ``NT AUTHORITY\`` prefix is kept on the three pseudo-groups so a real account named
#: ``DOMAIN\ServiceAccount`` is not mistaken for ``NT AUTHORITY\SERVICE``.
_BROAD_PRINCIPAL_NAMES: tuple[str, ...] = (
    "everyone",
    "authenticated users",
    "\\users",  # BUILTIN\Users or DOMAIN\Users
    "domain users",
    "nt authority\\interactive",
    "nt authority\\service",
    "nt authority\\batch",
    "creator owner",
)

#: The locale-invariant half: well-known SIDs, matched **whole** against the principal token (icacls
#: renders an unresolvable SID with a leading ``*``). Whole-token matching is load-bearing rather than
#: tidiness — as substrings, ``S-1-5-3`` (BATCH) is a prefix of ``S-1-5-32-544``
#: (``BUILTIN\Administrators``, deliberately trusted) and ``S-1-5-11`` (Authenticated Users) of
#: ``S-1-5-113`` (Local Account), so a substring set would report the administrators ACE that sits on
#: every ordinary Windows file as a broad-principal write.
_BROAD_PRINCIPAL_SIDS: frozenset[str] = frozenset(
    {
        "s-1-1-0",  # Everyone
        "s-1-5-11",  # Authenticated Users
        "s-1-5-32-545",  # BUILTIN\Users
        "s-1-5-4",  # NT AUTHORITY\INTERACTIVE
        "s-1-5-6",  # NT AUTHORITY\SERVICE
        "s-1-5-3",  # NT AUTHORITY\BATCH
        "s-1-3-0",  # CREATOR OWNER
    }
)

# INTERACTIVE / SERVICE / BATCH / CREATOR OWNER are broad here and are *trusted* by
# ``_evaluate_config_dacl`` (``messagefoundry/config/wiring.py``). That divergence is deliberate: the
# config guard is handed the object's owner SID and can therefore resolve the CREATOR OWNER
# placeholder to a principal it already trusts, while this parser is handed text and no owner, so it
# cannot tell the owner from any other creator. Measured on Windows 11: ``icacls`` on a file in a
# temp directory or a user profile lists only SYSTEM, Administrators and the owner, so none of the
# four fires on an ordinary anchor placement — whereas ``icacls C:\Users\Public`` lists
# ``NT AUTHORITY\INTERACTIVE:(OI)(CI)(IO)(M,DC)`` and the same for SERVICE and BATCH, which
# object-inherit propagates as ``(I)(M)`` onto every file created there. An anchor placed in that
# directory is modifiable by every interactive logon, and before BACKLOG #1142 it read as owner-only.

#: icacls right tokens that permit modifying the file's contents (simple + specific write masks).
_WRITE_RIGHTS: frozenset[str] = frozenset(
    {"F", "M", "W", "WD", "AD", "WEA", "WA", "WO", "WDAC", "GA", "GW"}
)


def _is_broad_principal(principal: str) -> bool:
    """Whether an already-lowercased icacls principal token names an identity broader than the file's
    owner. The SID is matched whole (after any leading ``*``); the display name as a substring."""
    if principal.lstrip("*") in _BROAD_PRINCIPAL_SIDS:
        return True
    return any(name in principal for name in _BROAD_PRINCIPAL_NAMES)


def owner_only_from_icacls(text: str, *, anchor_path: str) -> bool | None:
    """Parse ``icacls <path>`` output into a **tri-state** verdict. Pure — unit-tested with synthetic
    icacls output.

    * ``True`` — at least one ACE was read and no broad group/world principal holds a write-capable
      right (owner-only-writable).
    * ``False`` — such a principal does hold one.
    * ``None`` — the DACL could **not be determined**.

    **Determined means exactly this: at least one line parsed as an ACE, i.e. a non-empty principal
    token followed by a ``:(rights)`` blob.** Empty output, a truncated read, a banner or trailer with
    no ACE under it, and text that is not icacls output at all therefore all answer ``None``. Before
    BACKLOG #1142 this returned ``bool`` and fell through to ``True``, so "no broad principal has
    write" and "I parsed nothing" were the same answer — and the second is an affirmative assertion of
    owner-only storage the parser has no basis for. ``None`` is the caller's cue to degrade.

    Broad principals are matched by locale-invariant SID and by **at least** the English display names
    in :data:`_BROAD_PRINCIPAL_NAMES`. Because ``icacls`` resolves SIDs to localized names by default,
    that name set cannot be complete across locales, so a ``True`` from a non-English host is weaker
    than the same answer from an English one. Closing that gap needs a SID-form read (``icacls /sid``
    or the in-process DACL walk ``config/wiring.py`` already ships) and is not done here.

    The known ``anchor_path`` is stripped from the leading line so a path that legitimately contains
    ``\\Users`` (e.g. ``C:\\Users\\svc\\anchor.pem``) is never mistaken for a ``BUILTIN\\Users`` ACE."""
    saw_ace = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("successfully processed") or low.startswith("failed processing"):
            continue
        # Line 1 carries the path prefix; strip the exact path we passed so its characters can't be
        # read as a principal.
        if low.startswith(anchor_path.lower()):
            line = line[len(anchor_path) :].strip()
        idx = line.find(":(")
        if idx == -1:
            continue
        principal = line[:idx].strip().lower()
        if not principal:
            continue  # a rights blob with nothing in front of it is attributable to nobody
        saw_ace = True
        rights_blob = line[idx:]
        if not _is_broad_principal(principal):
            continue
        if "(deny)" in rights_blob.lower():
            continue  # a DENY reduces access; it never grants write
        tokens = {t.strip().upper() for t in re.split(r"[(),]", rights_blob) if t.strip()}
        if tokens & _WRITE_RIGHTS:
            return False  # a broad write settles it; the rest of the DACL cannot take it back
    return True if saw_ace else None


def dacl_is_owner_only(path: str | os.PathLike[str]) -> bool | None:
    """Whether the anchor is writable only by its owner (+ the always-trusted SYSTEM/Administrators),
    i.e. no group/world principal can modify it. READ-ONLY: it never changes the file's ACL (unlike
    ``_secure_file``, whose ``icacls`` mechanism it mirrors). ``None`` when the DACL cannot be
    determined, so the caller degrades rather than refusing on an inconclusive read.

    Three things make it undeterminable on Windows, and all three are ``None``: ``icacls`` could not
    be run, it exited non-zero, or (BACKLOG #1142) it exited zero with output carrying no ACE the
    parser could attribute to a principal. Each logs a warning naming which one happened.

    * POSIX: no group- or other-WRITE bit (``mode & 0o022 == 0``).
    * Windows: read the DACL with ``icacls <path>`` (no modifying flags) and flag any broad-group ACE
      that grants a write-capable right."""
    if os.name == "nt":
        try:
            # icacls is a fixed system tool, invoked without a shell; the path is a single argv token,
            # never a shell word (matches _secure_file's low-27/STORE-5 note). No modifying flags.
            result = subprocess.run(  # nosec B603 B607
                ["icacls", os.fspath(path)],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            log.warning("icacls could not read the DACL of %s: %s", path, exc)
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
                "icacls exited 0 for %s but its output carried no readable ACE; the DACL could "
                "not be determined",
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
    return AnchorVerdict(
        fingerprint=fingerprint, acl_ok=dacl_is_owner_only(spec.path), pin_ok=pin_ok
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


def _enforce_verdict(spec: AnchorSpec, verdict: AnchorVerdict, *, enforcing: bool) -> None:
    """Apply the owner fork to a verdict: a pin mismatch always refuses; a group/world-writable DACL
    refuses at ``enforce`` and warns at ``warn``. Raises :class:`TrustAnchorError` on a fatal violation."""
    if verdict.pin_ok is False:
        raise TrustAnchorError(_pin_mismatch_message(spec, verdict))
    if verdict.acl_ok is False:
        if enforcing:
            raise TrustAnchorError(
                _acl_message(spec) + " — [security].enforcement=enforce refuses to start"
            )
        log.warning("%s — [security].enforcement=warn, starting anyway", _acl_message(spec))


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
