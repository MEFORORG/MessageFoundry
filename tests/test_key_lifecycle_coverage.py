# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 11.1.1: every key-carrying module the crypto gate sees must have a key-lifecycle row.

``docs/ASVS-L2-PHASE0-CHANGES.md`` §4 writes a lifecycle policy for the store DEK and, in the
subsection after it, lifecycle tables for the other keys the engine loads or mints. On 2026-09-06 a
mutation showed nothing guarded those tables: deleting the SFTP client key row left every doc-guard
suite green (BACKLOG #1162). This module is that guard.

**It discovers from the crypto gate, not from a pattern set of its own.** The research that filed
#1162 found a key census built on ``load_cert_chain`` / ``load_pem_private_key`` patterns, and it
missed the anonymizer salt, because a keyed-hash key matches none of them. So this module reads
``INVENTORY`` from ``scripts/security/crypto_inventory_check.py`` and requires a decision for EVERY
module in it: either the module carries a key, and names the lifecycle row that governs that key, or
it does not, and says why. A module nobody has sorted fails, which is what stops the sorting falling
behind the gate.

**THIS IS A FLOOR, NOT A COMPLETENESS PROOF.** ``INVENTORY`` finds a module by what it IMPORTS
(BACKLOG #1163 and #1164 record why that granularity cannot prove "all"). A key loaded in a module
that imports no crypto-gate trigger is invisible to this guard exactly as it is to the gate. The SFTP
client key is the worked example: ``paramiko`` is not a trigger, and ``transports/remotefile.py`` is
guarded here only because it ALSO imports ``ssl`` and ``hashlib``. Widening discovery is #1164's
instrument work, not this module's; do not read a green here as "every key has a lifecycle".

The DEK has no table row: its lifecycle is the ``Store-key management policy`` bullet list, so the
label :data:`_DEK` counts as governed only while that heading AND each of its five lifecycle bullets
(:data:`_DEK_BULLETS`) are present with text after the bullet's lead.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "ASVS-L2-PHASE0-CHANGES.md"
_CRYPTO_GATE = _ROOT / "scripts" / "security" / "crypto_inventory_check.py"

_DEK_HEADING = "### Store-key management policy"
#: The bold leads of the DEK's lifecycle bullets. Every one must be present, with text after it.
_DEK_BULLETS = (
    "- **Generation**",
    "- **Storage / access**",
    "- **Distribution / holders**",
    "- **Rotation / retirement**",
    "- **Destruction**",
)
_LIFECYCLE_HEADING = "### Key management for the other keys the engine loads or mints"
_NEXT_HEADING = "### Rotation schedule"

#: A cell or bullet counts as written only if it holds a letter or digit, not just a dash.
_WORD = re.compile(r"\w")

#: The pseudo-label for the store DEK, whose lifecycle is a bullet list rather than a table row.
_DEK = "Store DEK"

# Lifecycle row labels, spelled exactly as the bold lead of each row in the doc.
_JWS = "Per-message JWS signing key"
_SMART = "SMART Backend Services client-assertion key"
_DIRECT = "DIRECT S/MIME sender signing key"
_SFTP = "SFTP client key"
_API_TLS = "API TLS server key"
_API_PLACEHOLDER = "API TLS placeholder key"
_CONN_SERVER = "Per-connection TLS server key"
_MTLS_CLIENT = "Outbound mTLS client key"
_LOG_FORWARD = "Off-box log-forward client key"
_API_CLIENT = "Native API client key"
_NONPROD = "Non-production self-signed key"
_TOTP = "TOTP shared secret"
_ANON_SALT = "Anonymizer re-identification salt"

#: Modules that load, mint, derive from, or feed a key, and the lifecycle row(s) governing it.
_CARRIES_KEY: dict[str, frozenset[str]] = {
    # The store DEK and everything keyed on it or derived from it (the audit-chain HMAC subkey, the
    # rotation-fingerprint MAC, the GCM invocation bound, the DR archive codec).
    "messagefoundry/store/crypto.py": frozenset({_DEK}),
    "messagefoundry/store/backup_codec.py": frozenset({_DEK}),
    "messagefoundry/store/keyprovider_vault.py": frozenset({_DEK}),
    "messagefoundry/store/crypto_transit.py": frozenset({_DEK}),
    "messagefoundry/store/base.py": frozenset({_DEK}),
    "messagefoundry/store/store.py": frozenset({_DEK}),
    "messagefoundry/store/postgres.py": frozenset({_DEK}),
    "messagefoundry/store/sqlserver.py": frozenset({_DEK}),
    "messagefoundry/store/gcm_bound.py": frozenset({_DEK}),
    "messagefoundry/pipeline/gcm_invocations.py": frozenset({_DEK}),
    "messagefoundry/pipeline/dr_backup.py": frozenset({_DEK}),
    "messagefoundry/pipeline/secret_rotation.py": frozenset({_DEK}),
    "messagefoundry/uploads.py": frozenset({_DEK}),
    "messagefoundry/__main__.py": frozenset({_DEK, _NONPROD}),
    # Private keys the engine loads or mints.
    "messagefoundry/transports/signing.py": frozenset({_JWS, _SMART}),
    "messagefoundry/transports/rest.py": frozenset({_JWS}),
    "messagefoundry/transports/fhir.py": frozenset({_JWS}),
    "messagefoundry/transports/soap.py": frozenset({_JWS, _MTLS_CLIENT}),
    "messagefoundry/transports/smart.py": frozenset({_SMART}),
    "messagefoundry/transports/direct.py": frozenset({_DIRECT}),
    "messagefoundry/transports/remotefile.py": frozenset({_SFTP, _MTLS_CLIENT}),
    "messagefoundry/api/tls.py": frozenset({_API_TLS, _API_PLACEHOLDER}),
    "messagefoundry/transports/mllp.py": frozenset({_CONN_SERVER, _MTLS_CLIENT}),
    "messagefoundry/transports/http_listener.py": frozenset({_CONN_SERVER}),
    "messagefoundry/transports/dicom.py": frozenset({_CONN_SERVER, _MTLS_CLIENT}),
    "messagefoundry/logging_setup.py": frozenset({_LOG_FORWARD}),
    "messagefoundry/apiclient/client.py": frozenset({_API_CLIENT}),
    "messagefoundry/pki.py": frozenset({_NONPROD}),
    "harness/load/tlsmat.py": frozenset({_NONPROD}),
    # Secret keys the engine holds or feeds.
    "messagefoundry/auth/totp.py": frozenset({_TOTP}),
    "messagefoundry/auth/service.py": frozenset({_TOTP}),
    "messagefoundry/anon/keying.py": frozenset({_ANON_SALT}),
    "tee/anon/keying.py": frozenset({_ANON_SALT}),
    "tee/__main__.py": frozenset({_ANON_SALT}),
}

_KEYLESS = (
    "keyless digests only: a content hash, fingerprint or placement hash with no key on either side"
)
_VERIFY_ONLY = (
    "verification only: it builds or consumes a trust anchor (a CA file, a pinned certificate or the "
    "OS trust store) or a PUBLIC key, and loads no private or secret key"
)
_POSTURE_ONLY = (
    "imports the tls_policy seam for posture checks, refusals or context factories whose callers "
    "load any key; the module itself loads, mints and holds none"
)
_EPHEMERAL = (
    "CSPRNG draws of values that live for one request, session or ceremony (tokens, nonces, "
    "challenges, ids); they have their own inventory rows and no key lifecycle to manage"
)

#: Modules in INVENTORY that carry no key, each with the reason. A reason is a judgment, so it is
#: written down per module rather than inferred from which trigger the module imports.
_NO_KEY: dict[str, str] = {
    "messagefoundry/auth/passwords.py": "argon2id password hashing: a salted one-way hash, no key",
    "messagefoundry/auth/policy.py": _KEYLESS,
    "messagefoundry/auth/tokens.py": _EPHEMERAL,
    "messagefoundry/auth/trust_anchors.py": _KEYLESS,
    "messagefoundry/auth/webauthn.py": _EPHEMERAL + "; the credentials it verifies are PUBLIC keys",
    "messagefoundry/auth/ldap.py": _VERIFY_ONLY,
    "messagefoundry/auth/oidc/claims.py": _VERIFY_ONLY,
    "messagefoundry/auth/oidc/jwks.py": _VERIFY_ONLY,
    "messagefoundry/auth/oidc/flow.py": _EPHEMERAL + " (PKCE verifier, state, nonce). The OIDC "
    "client secret it presents is a credential governed by the rotation schedule, not key material",
    "messagefoundry/auth/oidc_http.py": _VERIFY_ONLY,
    "messagefoundry/config/fingerprint.py": _KEYLESS,
    "messagefoundry/config/wiring.py": _KEYLESS,
    "messagefoundry/config/tls_policy.py": "the TLS policy seam itself: it builds verifying contexts, "
    "floors and suite lists for its callers, and never loads, mints or holds a private key; each "
    "caller that loads one is sorted under its own row",
    "messagefoundry/config/tls_probe.py": "an outbound protocol-version probe that builds contexts "
    "with certificate checks deliberately off; it measures which TLS versions a peer accepts and "
    "loads no key and no trust anchor",
    "messagefoundry/config/models.py": _POSTURE_ONLY,
    "messagefoundry/config/settings.py": _POSTURE_ONLY,
    "messagefoundry/config/secretprovider_vault.py": "reads connector credentials from Vault KV over "
    "a verifying hop; the Vault token is a credential in the rotation schedule, and a key it fetches "
    "is governed by the row for the setting it fills",
    "messagefoundry/credential.py": _KEYLESS + "; it compares a configured credential in constant "
    "time, and that credential is governed by the rotation schedule",
    "messagefoundry/integrity.py": _KEYLESS,
    "messagefoundry/redaction.py": _KEYLESS,
    "messagefoundry/parsing/xml/signature.py": _VERIFY_ONLY,
    "messagefoundry/parsing/xml/_deps.py": _VERIFY_ONLY,
    "messagefoundry/pipeline/cert_expiry.py": "reads PUBLIC certificate facts to alarm on expiry; "
    "it loads no key",
    "messagefoundry/pipeline/sharding.py": _KEYLESS,
    "messagefoundry/pipeline/sandbox.py": _EPHEMERAL,
    "messagefoundry/pipeline/alert_sinks.py": _POSTURE_ONLY,
    "messagefoundry/pipeline/engine.py": _POSTURE_ONLY,
    "messagefoundry/pipeline/security_notify.py": _POSTURE_ONLY,
    "messagefoundry/pipeline/wiring_runner.py": _POSTURE_ONLY,
    "messagefoundry/api/app.py": _POSTURE_ONLY,
    "messagefoundry/api/security.py": _POSTURE_ONLY,
    "messagefoundry/store/cipher_cells.py": "a read-only declaration of cipher-covered cells; it "
    "builds a cell's AAD, which is byte framing, and never loads or holds a key",
    "messagefoundry/transports/base.py": "names the ssl types for a connect helper that receives a "
    "context built elsewhere and reports handshake failures; it builds no context and loads no key",
    "messagefoundry/transports/ai_broker.py": _POSTURE_ONLY,
    "messagefoundry/transports/database.py": _POSTURE_ONLY,
    "messagefoundry/transports/http_auth.py": _POSTURE_ONLY,
    "messagefoundry/transports/email.py": _VERIFY_ONLY,
    "messagefoundry/transports/dicomweb.py": _EPHEMERAL + " (a multipart boundary)",
    "messagefoundry/transports/file.py": _KEYLESS,
    "messagefoundry/tray/probe.py": _VERIFY_ONLY,
    "messagefoundry/verify/smoke.py": _VERIFY_ONLY,
    "messagefoundry_webconsole/_security.py": _EPHEMERAL + " (the per-response CSP nonce)",
    "tee/mefor_api.py": _VERIFY_ONLY,
    "scripts/asvs/scorecard.py": _KEYLESS,
    "scripts/asvs/prove_report.py": _KEYLESS,
    "scripts/asvs/anchor_report.py": _KEYLESS,
    "scripts/security/dast_target.py": _EPHEMERAL + " (a throwaway scan password)",
    "scripts/webconsole_seam_snapshot.py": _KEYLESS,
    "scripts/security/build_password_corpus.py": _KEYLESS,
    "scripts/security/build_cla_action_provenance.py": _KEYLESS,
}


def _inventory() -> dict[str, frozenset[str]]:
    """``INVENTORY`` from the crypto gate, loaded by path (``scripts/`` is not a package)."""
    spec = importlib.util.spec_from_file_location("_crypto_inventory_lifecycle", _CRYPTO_GATE)
    assert spec is not None and spec.loader is not None, f"cannot load {_CRYPTO_GATE}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    inventory: dict[str, frozenset[str]] = module.INVENTORY
    return inventory


def lifecycle_labels(doc: str) -> set[str]:
    """The key labels the document gives a lifecycle to.

    Every table row in the lifecycle subsection whose first cell leads with a bold label, plus
    :data:`_DEK` when the store-key policy heading is present. A row counts only if every one of its
    cells has text, so a row emptied down to its label does not count as governed.
    """
    lines = doc.splitlines()
    labels: set[str] = set()
    dek = next((i for i, line in enumerate(lines) if line.startswith(_DEK_HEADING)), None)
    start = next((i for i, line in enumerate(lines) if line.startswith(_LIFECYCLE_HEADING)), None)
    if dek is not None:
        policy = lines[dek + 1 : start if start is not None and start > dek else len(lines)]
        if all(
            any(line.startswith(lead) and _WORD.search(line[len(lead) :]) for line in policy)
            for lead in _DEK_BULLETS
        ):
            labels.add(_DEK)
    if start is None:
        return labels
    end = next(
        (
            i
            for i, line in enumerate(lines[start + 1 :], start + 1)
            if line.startswith(_NEXT_HEADING)
        ),
        len(lines),
    )
    for line in lines[start:end]:
        match = re.match(r"^\| \*\*(.+?)\*\*", line)
        if not match:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and all(_WORD.search(cell) for cell in cells):
            labels.add(match.group(1))
    return labels


def uncovered(doc: str) -> list[str]:
    """``path -> label`` pairs whose label has no lifecycle in ``doc``."""
    have = lifecycle_labels(doc)
    return sorted(
        f"{path} -> {label}"
        for path, needed in _CARRIES_KEY.items()
        for label in needed
        if label not in have
    )


def test_the_inventory_and_the_doc_were_actually_read() -> None:
    """Liveness receipt: an empty INVENTORY or an unparsed doc would turn every check below green."""
    inventory = _inventory()
    assert len(inventory) >= 60, f"INVENTORY has only {len(inventory)} entries; the load broke"
    labels = lifecycle_labels(_DOC.read_text(encoding="utf-8"))
    assert {_DEK, _SFTP, _TOTP, _ANON_SALT} <= labels, (
        f"lifecycle parse found only {sorted(labels)}"
    )


def test_every_inventory_module_is_sorted() -> None:
    """Completeness against discovery: a module new to INVENTORY must be sorted here.

    Mutation: add a path to INVENTORY without touching this file. Red: that path is named.
    """
    inventory = set(_inventory())
    unsorted = sorted(inventory - set(_CARRIES_KEY) - set(_NO_KEY))
    assert not unsorted, (
        f"INVENTORY module(s) with no key decision: {unsorted}. Add each to _CARRIES_KEY with the "
        f"lifecycle row that governs its key, or to _NO_KEY with the reason it carries none."
    )


def test_the_sorting_does_not_rot() -> None:
    """Both maps must name modules still in INVENTORY, and must not overlap."""
    inventory = set(_inventory())
    stale = sorted((set(_CARRIES_KEY) | set(_NO_KEY)) - inventory)
    assert not stale, f"sorted module(s) no longer in INVENTORY: {stale}"
    both = sorted(set(_CARRIES_KEY) & set(_NO_KEY))
    assert not both, f"module(s) sorted as carrying a key AND not: {both}"


def test_every_key_carrying_module_has_a_lifecycle_row() -> None:
    """The property ASVS 11.1.1's scope half rests on, at the floor INVENTORY allows.

    Mutation: delete the SFTP client key row from the doc. Red: ``remotefile.py -> SFTP client key``.
    """
    missing = uncovered(_DOC.read_text(encoding="utf-8"))
    assert not missing, (
        f"key-carrying module(s) with no lifecycle row: {missing}. Add the row to "
        f"'{_LIFECYCLE_HEADING}' in docs/ASVS-L2-PHASE0-CHANGES.md."
    )


def test_every_lifecycle_row_is_claimed_by_a_discovered_module() -> None:
    """The reverse direction: a lifecycle row no INVENTORY module points at is a row about code the
    crypto gate cannot see, or a row for a key that is gone. Either way a reader should be told."""
    claimed = {label for labels in _CARRIES_KEY.values() for label in labels}
    orphans = sorted(lifecycle_labels(_DOC.read_text(encoding="utf-8")) - claimed)
    assert not orphans, f"lifecycle row(s) no key-carrying INVENTORY module claims: {orphans}"


def test_deleting_a_row_turns_the_guard_red() -> None:
    """The mutation, run in-process so it cannot be skipped: a guard proven only by passing on
    today's tree is the trap #1162 was filed about. Removing each known row must be reported."""
    doc = _DOC.read_text(encoding="utf-8")
    assert not uncovered(doc), "the unmutated doc must be clean for this mutation to mean anything"
    for label, culprit in (
        (_SFTP, "messagefoundry/transports/remotefile.py"),
        (_TOTP, "messagefoundry/auth/totp.py"),
        (_ANON_SALT, "tee/anon/keying.py"),
    ):
        mutated = "\n".join(
            line for line in doc.splitlines() if not line.startswith(f"| **{label}**")
        )
        assert mutated != doc, f"no row for {label!r} to delete; the row label moved"
        assert f"{culprit} -> {label}" in uncovered(mutated), f"deleting {label!r} stayed green"
    # The DEK has no row; its policy is a bullet list. Gutting one bullet must also turn it red.
    # Gutting a bullet down to its lead and dash must be red too, not just deleting it.
    emptied = "\n".join(
        "- **Destruction** \u2014" if line.startswith("- **Destruction**") else line
        for line in doc.splitlines()
    )
    assert f"messagefoundry/store/crypto.py -> {_DEK}" in uncovered(emptied), (
        "a DEK bullet emptied to its lead stayed green"
    )
    gutted = "\n".join(
        line for line in doc.splitlines() if not line.startswith("- **Destruction**")
    )
    assert gutted != doc, "no DEK Destruction bullet to delete; the bullet lead moved"
    assert f"messagefoundry/store/crypto.py -> {_DEK}" in uncovered(gutted), (
        "deleting the DEK Destruction bullet stayed green"
    )


def test_a_no_key_reason_is_a_sentence() -> None:
    """An exclusion whose reason is empty is where real key material gets parked."""
    thin = sorted(path for path, reason in _NO_KEY.items() if len(reason.split()) < 5)
    assert not thin, f"_NO_KEY entries with no real reason: {thin}"
