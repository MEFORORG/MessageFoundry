# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 13.1.4 re-drift guard: the critical-secret enumeration + rotation schedule in
``docs/ASVS-L2-PHASE0-CHANGES.md`` must stay complete.

The 2026-07-16 / 07-20 failure mode was silent: a new secret-bearing ``MEFOR_*`` env var landed in the
engine (most recently the ADR 0138 ``vault_transit`` Transit keys) without a matching row in the
rotation schedule, so the "define critical secrets" control drifted back to incomplete with nothing to
catch it. This module makes that a build failure, modelled on
``scripts/security/crypto_inventory_check.py`` (WP-L3-02):

* **Discovery ⊆ registry.** Every secret-bearing ``MEFOR_*`` name that actually appears in
  ``messagefoundry/`` must be in the curated :data:`CRITICAL_SECRETS` registry — a new one trips the
  gate until it is registered *and* documented.
* **``_FILE_SECRET_KEYS`` ⊆ registry.** The engine's authoritative "env-only, never the config file"
  secret list must be fully registered, so a new file-forbidden secret can't be added there in isolation.
* **``_SECRET_SETTING_KEYS`` ⊆ registry.** Every rotatable connector-credential setting in
  ``config/wiring._SECRET_SETTING_KEYS`` (the single source of truth for ``/metadata`` redaction) —
  minus a curated set of non-secret *identifiers* (usernames) — must be a registered critical secret, so
  a new connector credential can't be added there without a rotation row here.
* **Registry ⊆ doc.** Every registered secret's token must appear in the doc's **Rotation schedule**
  section — so a registered secret with no rotation row also fails.

This guards the *definition/enumeration* only. It does **not** assert the engine force-rotates or hard-
expires anything — that stays operator- / secret-manager-driven by design (session tokens are the one
engine-expired credential). The *detect-and-remind* side of ASVS 13.3.4 is now **built** (BACKLOG #282):
`pipeline/secret_rotation.py` fingerprints each tracked secret with a DEK-derived **keyed MAC** in store
meta, tracks the DEK live-by-default off a tracked-since stamp, auto-detects a rotation (a changed
fingerprint resets the clock), alerts against the documented cadence, and escalates under
`[security].enforcement=ENFORCE` — behaviour covered by `tests/test_secret_rotation_watcher.py`. This
module stays scoped to the enumeration's completeness. PHI-free — it reads only env-var/setting *names*
and doc prose, never a secret value.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_PKG = _ROOT / "messagefoundry"
_DOC = _ROOT / "docs" / "ASVS-L2-PHASE0-CHANGES.md"

# The section the enumeration + schedule live in; sliced by these exact headings so the check is anchored
# to the schedule (and fails loudly if the section is ever restructured away).
_SECTION_START = "### Rotation schedule (ASVS 13.1.4 / 13.3.4)"
_SECTION_END = "### TLS key-exchange & cipher posture (ASVS 11.6.2)"

# A fully-qualified MEFOR_* token (\b-anchored so the `_MEFOR_SECRET` redaction identifier and `MEFOR_X_*`
# comment fragments do NOT match; a real "MEFOR_A_B" literal or comment mention does).
_ENV_TOKEN = re.compile(r"\bMEFOR_[A-Z0-9]+(?:_[A-Z0-9]+)*\b")

# The suffixes that mark a MEFOR_* name as carrying / naming secret material.
_SECRET_SUFFIXES = ("_TOKEN", "_SECRET", "_PASSWORD", "_KEY")

# MEFOR_* names that end in a secret suffix but are NOT a secret value to rotate. "MEFOR_SECRET" is the
# fragment a naïve (non-\b) grep pulls out of the `_MEFOR_SECRET` redaction identifier / `MEFOR_SECRETS_*`
# env prefix; the \b regex already excludes it — this is belt-and-suspenders + documentation of intent.
_NOT_A_SECRET: frozenset[str] = frozenset({"MEFOR_SECRET"})

# The curated critical-secret registry (ASVS 13.1.4). Key = the env var or connector setting the operator
# rotates; value = a human label. The MEFOR_* env vars are ALSO cross-checked against the code by the
# discovery + _FILE_SECRET_KEYS tests below; the connector env()-settings (arbitrary operator-chosen env
# names, referenced via `env()`) are stable, ADR-gated additions carried here and asserted present in the
# doc. Every key must appear verbatim in the doc's Rotation schedule section.
CRITICAL_SECRETS: dict[str, str] = {
    # --- fixed MEFOR_* env vars (also code-discovered) ------------------------
    "MEFOR_STORE_ENCRYPTION_KEY": "store at-rest data-encryption key",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED": "retired store DEKs (decrypt-only)",
    "MEFOR_STORE_PASSWORD": "SQL/Postgres store password",
    "MEFOR_AUTH_AD_BIND_PASSWORD": "Active Directory bind password",
    "MEFOR_AUTH_OIDC_CLIENT_SECRET": "Federated OIDC confidential-client secret (ADR 0142)",
    "MEFOR_ALERTS_EMAIL_PASSWORD": "SMTP alert password",
    "MEFOR_AI_API_KEY": "AI engine-broker LLM credential (ADR 0135)",
    "MEFOR_API_TLS_KEY_PASSWORD": "off-loopback TLS private-key passphrase",
    "MEFOR_STORE_VAULT_TOKEN": "Vault access token — store DEK provider (ADR 0019)",
    "MEFOR_SECRETS_VAULT_TOKEN": "Vault access token — connector KV provider (ADR 0019)",
    "MEFOR_STORE_VAULT_TRANSIT_KEY": "Vault Transit KEK name — DEK unwrap (ADR 0019)",
    "MEFOR_STORE_TRANSIT_KEY": "Vault Transit data-key name — vault_transit (ADR 0138)",
    "MEFOR_STORE_TRANSIT_AUDIT_KEY": "Vault Transit audit-HMAC key name (ADR 0138)",
    "MEFOR_PFX_PASSWORD": "PKCS#12 import passphrase — transient `cert import` CLI input (#71); never stored",
    # --- per-Connection connector credentials (env()-sourced settings) --------
    "password": "generic connector credential (DB ODBC / SMTP / relay / FTP-SFTP)",
    "basic_password": "HTTP Basic auth password (REST/FHIR/SOAP/DICOMweb)",
    "bearer_token": "static HTTP bearer token (REST/FHIR/SOAP/DICOMweb)",
    "api_key": "generic connector API-key credential (env()-sourced)",
    "token": "generic connector token credential (env()-sourced; distinct from bearer_token)",
    "proxy_password": "egress proxy password (REST)",
    "oauth2_client_secret": "OAuth2 client-credentials secret",
    "http_auth_password": "HTTP Digest password",
    "tls_key_password": "connector TLS key passphrase (MLLP/DICOM/FTPS)",
    "client_key_password": "SOAP mTLS client-key passphrase",
    "key_password": "SFTP SSH private-key passphrase (remote-file)",
    "signing_key_password": "DIRECT S/MIME signing-key passphrase (ADR 0085)",
    "private_key": "per-message JWS signing key — PEM material (ADR 0018)",
    "private_key_password": "per-message JWS signing-key passphrase (ADR 0018)",
    "smart_private_key": "SMART Backend Services signing key — PEM material (ADR 0024)",
    "smart_private_key_password": "SMART Backend Services JWT key passphrase (ADR 0024)",
    "ws_password": "SOAP WS-Security UsernameToken password",
    "credential_password": "File-endpoint UNC-share / Windows alternate credential password (ADR 0132)",
    "body_secret_value": "SOAP body_secret_value_<i> injected secrets (ADR 0015)",
    "intake_api_key": "inbound HTTP intake-auth peer credential (ADR 0154)",
    "intake_api_key_next": "inbound HTTP intake-auth rotation key, live alongside intake_api_key (ADR 0154)",
}


def _iter_py(package: Path) -> list[Path]:
    return [p for p in package.rglob("*.py") if "__pycache__" not in p.parts]


def discover_secret_env_vars(package: Path) -> set[str]:
    """Every secret-bearing ``MEFOR_*`` name that appears in ``package`` (string literals, comments, or
    docstrings — anything an operator could set), minus the :data:`_NOT_A_SECRET` allowlist."""
    found: set[str] = set()
    for path in _iter_py(package):
        for tok in _ENV_TOKEN.findall(path.read_text(encoding="utf-8")):
            if tok.endswith(_SECRET_SUFFIXES) and tok not in _NOT_A_SECRET:
                found.add(tok)
    return found


def _rotation_schedule_section() -> str:
    text = _DOC.read_text(encoding="utf-8")
    start = text.find(_SECTION_START)
    end = text.find(_SECTION_END)
    assert start != -1, f"rotation-schedule heading {_SECTION_START!r} missing from {_DOC.name}"
    assert end != -1 and end > start, (
        f"section-end heading {_SECTION_END!r} missing/misordered in {_DOC.name}"
    )
    return text[start:end]


def test_discovered_secret_env_vars_are_registered() -> None:
    # Every secret MEFOR_* the code actually uses is in the curated registry — a NEW one (the 07-16
    # failure mode) trips this until it is registered AND documented.
    discovered = discover_secret_env_vars(_PKG)
    registered = {k for k in CRITICAL_SECRETS if k.startswith("MEFOR_")}
    missing = sorted(discovered - registered)
    assert not missing, (
        "secret-bearing MEFOR_* env var(s) found in messagefoundry/ but not registered in "
        "CRITICAL_SECRETS (add each here AND a rotation row in "
        f"docs/ASVS-L2-PHASE0-CHANGES.md §4): {missing}"
    )


def _whole_token_present(token: str, section: str) -> bool:
    # Whole-token (identifier-boundary) match, NOT a bare substring: a token flanked by an
    # identifier character does not count. This catches deletion of a token that is a prefix of a
    # surviving one -- e.g. MEFOR_STORE_ENCRYPTION_KEY vs ..._KEYS_RETIRED, or key_password vs
    # tls_key_password -- which a plain substring check would silently pass.
    return (
        re.search(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])", section)
        is not None
    )


def test_registry_secrets_appear_in_rotation_schedule() -> None:
    # Every registered critical secret has a token in the Rotation schedule section — so a registered
    # secret with no rotation row also fails (doc completeness, ASVS 13.1.4).
    section = _rotation_schedule_section()
    undocumented = sorted(
        name for name in CRITICAL_SECRETS if not _whole_token_present(name, section)
    )
    assert not undocumented, (
        "critical secret(s) with no entry in the rotation-schedule section of "
        f"docs/ASVS-L2-PHASE0-CHANGES.md: {undocumented}"
    )


def test_every_file_secret_key_is_registered() -> None:
    # settings._FILE_SECRET_KEYS is the engine's authoritative "env-only, never the config file" secret
    # list; every derived MEFOR_* name must be a registered critical secret, so a new file-forbidden
    # secret can't be added there without landing in this inventory too. Imported locally so a
    # collection-time settings import error is contained to this one test.
    from messagefoundry.config.settings import _ENV_PREFIX, _FILE_SECRET_KEYS

    derived = {f"{_ENV_PREFIX}{section}_{field}".upper() for section, field in _FILE_SECRET_KEYS}
    missing = sorted(name for name in derived if name not in CRITICAL_SECRETS)
    assert not missing, f"_FILE_SECRET_KEYS secret(s) absent from CRITICAL_SECRETS: {missing}"


def test_secret_setting_keys_are_registered() -> None:
    # wiring._SECRET_SETTING_KEYS is the single source of truth for which connector settings carry a
    # credential (it drives BOTH /metadata redaction and graph --json). Every rotatable member — i.e.
    # every one that is not a bare identifier in _NON_ROTATABLE_SECRET_SETTING_KEYS — must be a registered
    # critical secret with a rotation row, so a FUTURE connector credential added there trips this gate
    # until it is inventoried + documented. Both are imported from wiring (the single source of truth,
    # ALSO read by the ASVS-13.3.4 runtime fingerprinter connector_secret_env_values). This gate proves
    # only the FORWARD direction (every _SECRET_SETTING_KEYS member is registered); that the registration
    # gate and the runtime rotation set agree is ENFORCED, not self-evident -- the reverse is checked by
    # test_registered_connector_secrets_are_reachable_by_the_fingerprinter (BACKLOG #1009), which is the
    # direction body_secret_value slipped through (it entered CRITICAL_SECRETS by hand, never through
    # _SECRET_SETTING_KEYS). Imported locally so a collection-time wiring import error is contained here.
    from messagefoundry.config.wiring import (
        _NON_ROTATABLE_SECRET_SETTING_KEYS,
        _SECRET_SETTING_KEYS,
    )

    # The exclusion set must stay a subset of the source of truth, so it can never silently mask a real
    # omission after a rename/removal in wiring.
    stale = sorted(_NON_ROTATABLE_SECRET_SETTING_KEYS - set(_SECRET_SETTING_KEYS))
    assert not stale, (
        "_NON_ROTATABLE_SECRET_SETTING_KEYS names key(s) no longer in wiring._SECRET_SETTING_KEYS: "
        f"{stale} — prune the exclusion so it cannot hide a real gap"
    )

    rotatable = set(_SECRET_SETTING_KEYS) - _NON_ROTATABLE_SECRET_SETTING_KEYS
    missing = sorted(name for name in rotatable if name not in CRITICAL_SECRETS)
    assert not missing, (
        "connector-credential setting(s) in wiring._SECRET_SETTING_KEYS absent from CRITICAL_SECRETS — "
        "register each here AND add a rotation row in docs/ASVS-L2-PHASE0-CHANGES.md §4 (or add "
        f"it to _NON_ROTATABLE_SETTING_KEYS if it is a non-secret identifier): {missing}"
    )


# --- ASVS 13.3.4: the REVERSE of test_secret_setting_keys_are_registered (BACKLOG #1009) ----------
#
# The forward gate proves _SECRET_SETTING_KEYS is registered. It is blind to the other direction: a
# registered CONNECTOR secret whose runtime setting never resolves through connector_secret_env_values
# (the ASVS-13.3.4 fingerprinter). The SOAP body_secret_value class entered CRITICAL_SECRETS by hand
# without passing through _SECRET_SETTING_KEYS, and the fingerprinter's bare-frozenset filter dropped it
# -- so a rotation of a SOAP injected body secret was not auto-detected, while the forward gate walked
# straight past (its comment even promised the two sets "can never disagree"). This gate closes that
# direction: every registered connector secret must be REACHABLE by the fingerprinter (ADR 0015).

#: Registered connector secrets that name NO reachable connector setting, each with the reason. Kept
#: here (not only in prose) so an exclusion is a reviewed decision with a hygiene test behind it, exactly
#: like _NOT_FINGERPRINTED: silently removing a real reachable secret must not pass unnoticed.
_NOT_A_CONNECTOR_SETTING: dict[str, str] = {
    "private_key_password": (
        "a per-message JWS SigningConfig passphrase (ADR 0018); the connector-level setting names are "
        "sign_private_key / sign_private_key_password (transports/signing.py), neither a "
        "_SECRET_SETTING_KEYS member, so connector_secret_env_values does not resolve it. Whether the "
        "JWS signing key is itself fingerprinted/redacted is a real but SEPARATE question, deliberately "
        "not folded into the one-predicate #1009 scope"
    ),
}

#: A registered connector secret whose runtime setting name is DYNAMIC -- the CRITICAL_SECRETS key is a
#: family label, not the literal setting the fingerprinter sees. Maps label -> a representative concrete
#: setting name in that family, so the reachability probe uses a name _is_secret_setting accepts.
_CONNECTOR_SETTING_REPRESENTATIVE: dict[str, str] = {
    "body_secret_value": "body_secret_value_0",  # Soap(body_secrets=...) -> body_secret_value_<i>
}


def test_registered_connector_secrets_are_reachable_by_the_fingerprinter() -> None:
    """The missing reverse of test_secret_setting_keys_are_registered (BACKLOG #1009, ADR 0015).

    For every registered CONNECTOR secret (a CRITICAL_SECRETS key that is not a fixed ``MEFOR_*`` env
    var), build a representative outbound whose settings name that secret and assert
    ``connector_secret_env_values`` returns its env key -- so a future registry entry added by hand
    cannot silently fall through the fingerprint filter the way ``body_secret_value`` did.

    Mutation (current bug): revert the ``config/wiring.py`` predicate to bare ``_SECRET_SETTING_KEYS``
    membership -> ``body_secret_value``'s probe key is absent from the result -> named in ``unreachable``.
    Mutation (future-proofing): add a fabricated unreachable entry to ``CRITICAL_SECRETS`` -> it is named
    in ``unreachable`` too. Both are genuine reds, not vacuous passes.
    """
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        EnvRef,
        OutboundConnection,
        Registry,
        connector_secret_env_values,
    )

    connector_secrets = [
        k
        for k in CRITICAL_SECRETS
        if not k.startswith("MEFOR_") and k not in _NOT_A_CONNECTOR_SETTING
    ]
    reg = Registry()
    env_values: dict[str, str] = {}
    probes: dict[str, str] = {}  # registered secret -> its unique probe env-value key
    for secret in connector_secrets:
        # The fingerprinter reads setting NAMES and ignores connector type, so a REST spec carrying an
        # arbitrary secret setting name is a valid probe of the filter (no connector-type validation runs).
        setting_name = _CONNECTOR_SETTING_REPRESENTATIVE.get(secret, secret)
        probe = f"probe_env_{secret}"
        settings: dict[str, Any] = {setting_name: EnvRef(key=probe)}
        reg.outbound[f"OB_{secret}"] = OutboundConnection(
            name=f"OB_{secret}",
            spec=ConnectionSpec(type=ConnectorType.REST, settings=settings),
        )
        env_values[probe] = f"SYNTH-{secret}"  # synthetic; env key names are not PHI
        probes[secret] = probe

    resolved = connector_secret_env_values(reg, env_values)
    unreachable = sorted(secret for secret, probe in probes.items() if probe not in resolved)
    assert not unreachable, (
        "registered connector secret(s) that connector_secret_env_values does not resolve -- a rotation "
        "of them would not be fingerprinted (ASVS 13.3.4). Fix the wiring._is_secret_setting / "
        "_SECRET_SETTING_KEYS coverage, or excuse each in _NOT_A_CONNECTOR_SETTING WITH the reason it "
        f"names no connector setting: {unreachable}"
    )

    # Hygiene: the two curated maps must be disjoint and may name only registered CONNECTOR secrets, so
    # neither can rot into a place to park an unreachable secret (mirrors the _NOT_FINGERPRINTED discipline).
    overlap = sorted(set(_NOT_A_CONNECTOR_SETTING) & set(_CONNECTOR_SETTING_REPRESENTATIVE))
    assert not overlap, f"secret(s) both excused AND represented -- pick one: {overlap}"
    for name in (*_NOT_A_CONNECTOR_SETTING, *_CONNECTOR_SETTING_REPRESENTATIVE):
        assert name in CRITICAL_SECRETS and not name.startswith("MEFOR_"), (
            f"{name!r} in a curated connector-secret map is not a registered connector secret"
        )


def test_scanner_flags_a_planted_secret(tmp_path: Path) -> None:
    # The guard must actually catch a new secret env var, so a real regression can't pass silently
    # (mirrors test_security_static.test_scanner_flags_a_planted_pattern).
    pkg = tmp_path / "plantpkg"
    pkg.mkdir()
    (pkg / "sneaky.py").write_text(
        'TOKEN_ENV = "MEFOR_NEW_PARTNER_TOKEN"  # a brand-new secret\n', encoding="utf-8"
    )
    assert discover_secret_env_vars(pkg) == {"MEFOR_NEW_PARTNER_TOKEN"}


def test_scanner_ignores_non_secret_and_identifier_forms(tmp_path: Path) -> None:
    # A non-secret MEFOR_* (wrong suffix), the `_MEFOR_SECRET` redaction identifier, and `MEFOR_X_*`
    # comment fragments must NOT be treated as secrets (no false positives).
    pkg = tmp_path / "mixedpkg"
    pkg.mkdir()
    (pkg / "m.py").write_text(
        "_MEFOR_SECRET = 1  # redaction identifier, not an env var\n"
        'ADDR = "MEFOR_STORE_VAULT_ADDR"  # non-secret suffix\n'
        "# prefix fragments MEFOR_SECRETS_* and MEFOR_STORE_VAULT_*\n"
        'REAL = "MEFOR_PARTNER_SECRET"\n',
        encoding="utf-8",
    )
    assert discover_secret_env_vars(pkg) == {"MEFOR_PARTNER_SECRET"}


# --- claim-truth: the SecretRotationSettings docstring is the 13.3.4 evidence string --------------
#
# The ASVS L3 13.3.4 residual cites this docstring verbatim. It went stale once #282 made the DEK
# live-by-default and added connector/AD/SMTP/Vault/OIDC fingerprint tracking: the docstring still
# said "deny-by-default" and the connector generalization was "intentionally NOT tracked here yet",
# contradicting its own inline comments 15 lines down and the shipped watcher. Neither presence guard
# reads settings.py prose, so nothing caught it. This pins the docstring to the shipped behaviour,
# gated on the watcher module actually existing so it degrades cleanly if #282 were ever reverted.


def _rotation_docstring_lie() -> str | None:
    """The offending phrase if SecretRotationSettings' docstring is stale, else None (self-testable)."""
    from messagefoundry.config.settings import SecretRotationSettings

    doc = SecretRotationSettings.__doc__ or ""
    # Only meaningful once the live-by-default watcher exists; otherwise the old wording was truthful.
    if not (_ROOT / "messagefoundry" / "pipeline" / "secret_rotation.py").exists():
        return None
    collapsed = " ".join(doc.split())
    return next(
        (lie for lie in ("deny-by-default", "NOT tracked here yet") if lie in collapsed),
        None,
    )


def test_secret_rotation_settings_docstring_matches_the_shipped_watcher() -> None:
    """ASVS 13.3.4 — the residual cites this docstring; it must state the live-by-default reality, not
    the retired deny-by-default / not-tracked-yet wording that pipeline/secret_rotation.py made false."""
    lie = _rotation_docstring_lie()
    assert lie is None, (
        "SecretRotationSettings.__doc__ still says "
        f"{lie!r}, but the DEK is tracked live-by-default and connector/AD/SMTP/Vault/OIDC secrets are "
        "fingerprint-tracked (pipeline/secret_rotation.py, #282). Correct the docstring — the ASVS L3 "
        "13.3.4 residual quotes it as evidence."
    )
    from messagefoundry.config.settings import SecretRotationSettings

    assert "live-by-default" in " ".join((SecretRotationSettings.__doc__ or "").split()), (
        "the docstring should positively state the live-by-default tracking it now performs"
    )


def test_rotation_docstring_guard_self_test() -> None:
    """Non-vacuity: the scan must catch the retired phrases and clear the corrected wording."""
    collapse = lambda s: " ".join(s.split())  # noqa: E731
    stale = collapse(
        "The store DEK is tracked deny-by-default: watched only once you set the date."
    )
    assert any(lie in stale for lie in ("deny-by-default", "NOT tracked here yet"))
    fixed = collapse(
        "The store DEK is tracked live-by-default off a persisted tracked-since stamp."
    )
    assert not any(lie in fixed for lie in ("deny-by-default", "NOT tracked here yet"))


# --- ASVS 13.3.4: the fingerprinting arm must cover the fixed env secrets -------------------------

#: Fixed ``MEFOR_*`` critical secrets deliberately NOT fingerprinted by the rotation watcher, each with
#: the reason. Kept HERE rather than only in the module so the exclusion is a reviewed decision with a
#: test behind it: dropping a name into ``_ENV_SECRET_CLASSES``'s exclusion comment alone changes
#: nothing, but silently *removing* a real secret from the tracked set would otherwise go unnoticed.
_NOT_FINGERPRINTED: dict[str, str] = {
    "MEFOR_STORE_ENCRYPTION_KEY": (
        "the DEK itself — tracked by its own arm (_maybe_escalate_dek), which reasons over the wrapped "
        "key's age rather than an env fingerprint; listing it here too would double-count it"
    ),
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED": (
        "a decrypt-only tail of superseded keys — rotating it is meaningless, and flagging it 'due' "
        "would tell an operator to destroy their own recovery path"
    ),
    "MEFOR_STORE_VAULT_TRANSIT_KEY": "a Vault Transit KEK NAME, not a secret value",
    "MEFOR_STORE_TRANSIT_KEY": "a Vault Transit data-key NAME, not a secret value",
    "MEFOR_STORE_TRANSIT_AUDIT_KEY": "a Vault Transit audit-key NAME, not a secret value",
    "MEFOR_PFX_PASSWORD": (
        "a one-shot passphrase for the `cert import` CLI — the running service never holds it, so "
        "there is nothing to fingerprint"
    ),
}


def test_every_fixed_env_secret_is_fingerprinted_or_explicitly_excused() -> None:
    """The gap this closes was live and silent.

    ``MEFOR_AI_API_KEY`` was a registered critical secret **with a documented rotation cadence** in the
    schedule above, and yet was absent from ``_ENV_SECRET_CLASSES`` — so the watcher never fingerprinted
    the one credential the documentation explicitly tells operators to rotate. Enumeration completeness
    (which this module already guarded) and *rotation* coverage are different properties, and nothing
    checked the second.

    Mutation: remove ``MEFOR_AI_API_KEY`` from ``_ENV_SECRET_CLASSES``. Red: it appears in the
    "registered ... but neither fingerprinted nor excused" list below.
    """
    from messagefoundry.pipeline.secret_rotation import _ENV_SECRET_CLASSES

    fingerprinted = {name for name, _label in _ENV_SECRET_CLASSES}
    fixed_env = {k for k in CRITICAL_SECRETS if k.startswith("MEFOR_")}

    unaccounted = sorted(fixed_env - fingerprinted - set(_NOT_FINGERPRINTED))
    assert not unaccounted, (
        f"registered critical secret(s) neither fingerprinted by the rotation watcher nor excused: "
        f"{unaccounted}. Add each to _ENV_SECRET_CLASSES in messagefoundry/pipeline/secret_rotation.py, "
        f"or to _NOT_FINGERPRINTED here WITH the reason it cannot be rotated. A documented rotation "
        f"cadence with no fingerprint is a reminder nothing can ever emit."
    )

    # The exclusion list must not rot into a place to park real secrets: every name in it has to still
    # be a registered critical secret, and must NOT also be fingerprinted (which would be contradictory).
    stale = sorted(set(_NOT_FINGERPRINTED) - fixed_env)
    assert not stale, f"_NOT_FINGERPRINTED names that are no longer registered secrets: {stale}"
    both = sorted(set(_NOT_FINGERPRINTED) & fingerprinted)
    assert not both, f"names both excused AND fingerprinted — the excuse is false: {both}"


def test_every_fingerprinted_env_secret_is_a_registered_critical_secret() -> None:
    """The other direction: the watcher must not fingerprint something the registry does not know
    about, or the rotation alert names a secret with no documented cadence to measure it against.

    Mutation: add a fabricated ``MEFOR_NOT_REAL`` to ``_ENV_SECRET_CLASSES``. Red: named below."""
    from messagefoundry.pipeline.secret_rotation import _ENV_SECRET_CLASSES

    unregistered = sorted({n for n, _ in _ENV_SECRET_CLASSES} - set(CRITICAL_SECRETS))
    assert not unregistered, (
        f"fingerprinted secret(s) missing from the CRITICAL_SECRETS registry: {unregistered}. "
        f"Register each (and give it a rotation-schedule row) so the alert has a cadence to cite."
    )
