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

**The SP 800-57 mapping is held to the same floor.** Every lifecycle label except the DEK must also
have a row in the ``NIST SP 800-57 mapping for the other keys`` table, and every row there must name a
lifecycle label. Each table is read only up to the next ``### `` heading, so a mapping row can never
stand in for a deleted lifecycle row. This checks that each key HAS a mapping row, not that the row
maps it correctly, and not that the key's lifecycle follows the standard: the mapping itself records
where it departs. Judging the rows is the reviewer's job.

**The DEK has its own SP 800-57 mapping, keyed by clause (BACKLOG #1162).** It is one key, so its
table's rows are clauses, not keys. :data:`_DEK_CLAUSES` names every clause row, and the table must
hold exactly those rows, each written. The rows that name a departure must keep naming it, so a
departure cannot be edited out of the record while its row stays.
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
#: The NIST SP 800-57 mapping for the non-DEK keys. Its rows lead with a PLAIN label.
_MAPPING_HEADING = "### NIST SP 800-57 mapping for the other keys"

#: The clause-by-clause SP 800-57 mapping for the store DEK. Its rows lead with a clause, not a key.
_DEK_MAPPING_HEADING = "### NIST SP 800-57 mapping for the store DEK"
#: Every clause row that mapping must hold, spelled exactly as its first cell.
_DEK_CLAUSES = frozenset(
    {
        "5.1.1 key type",
        "5.2 one purpose",
        "8.1.5.2.1 generation",
        "8.1.5.2.2 distribution",
        "8.1.5.2.2.1 manual distribution",
        "8.2.4 key derivation",
        "5.3.6 cryptoperiod",
        "7.4 deactivated",
        "7.5 compromised",
        "Table 7 backup",
        "Table 9 archive",
        "B.3.4 data-encryption key backup",
        "8.3.4 destruction",
    }
)
#: The clause rows that record a departure from the standard. Each must keep saying so.
_DEK_DEPARTURES = frozenset(
    {
        "5.2 one purpose",
        "8.1.5.2.1 generation",
        "8.1.5.2.2.1 manual distribution",
        "8.2.4 key derivation",
        "5.3.6 cryptoperiod",
        "7.4 deactivated",
        "7.5 compromised",
        "8.3.4 destruction",
    }
)

#: A cell or bullet counts as written only if it holds a letter or digit, not just a dash.
_WORD = re.compile(r"\w")

#: The pseudo-label for the store DEK, whose lifecycle is a bullet list rather than a table row.
_DEK = "Store DEK"

# Lifecycle row labels, spelled exactly as the bold lead of each row in the doc.
_JWS = "Per-message JWS signing key"
_SMART = "SMART Backend Services client-assertion key"
_OIDC_ASSERTION = "OIDC client-assertion key"
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
_SEALED = "Sealed-cache key"

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
    "messagefoundry/transports/signing.py": frozenset({_JWS, _SMART, _OIDC_ASSERTION}),
    # BACKLOG #296: builds the private_key_jwt signer from the operator's key.
    "messagefoundry/auth/oidc/client_auth.py": frozenset({_OIDC_ASSERTION}),
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
    # BACKLOG #1352 / #1171: every TLS private-key load goes through keywrap.load_checked_cert_chain,
    # which checks the key's passphrase wrap and then calls load_cert_chain itself. So it LOADS the
    # keys of each site that calls it; the modules above still name their own rows. The engine-minted
    # placeholder is loaded directly in api/tls.py, not here.
    "messagefoundry/keywrap.py": frozenset(
        {_API_TLS, _CONN_SERVER, _MTLS_CLIENT, _LOG_FORWARD, _API_CLIENT}
    ),
    "messagefoundry/pki.py": frozenset({_NONPROD}),
    "harness/load/tlsmat.py": frozenset({_NONPROD}),
    # Secret keys the engine holds or feeds.
    "messagefoundry/auth/totp.py": frozenset({_TOTP}),
    "messagefoundry/auth/service.py": frozenset({_TOTP}),
    "messagefoundry/anon/keying.py": frozenset({_ANON_SALT}),
    "tee/anon/keying.py": frozenset({_ANON_SALT}),
    "tee/__main__.py": frozenset({_ANON_SALT}),
    # BACKLOG #1174: the per-process key that seals the state and reference caches.
    "messagefoundry/store/sealed_cache.py": frozenset({_SEALED}),
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
    "messagefoundry/auth/ldap_tls.py": _VERIFY_ONLY,
    "messagefoundry/auth/oidc/claims.py": _VERIFY_ONLY,
    "messagefoundry/auth/oidc/jwks.py": _VERIFY_ONLY,
    "messagefoundry/auth/oidc/flow.py": _EPHEMERAL + " (PKCE verifier, state, nonce). The OIDC "
    "client secret it presents is a credential governed by the rotation schedule, not key material",
    "messagefoundry/auth/oidc_http.py": _VERIFY_ONLY,
    "messagefoundry/config/fingerprint.py": _KEYLESS,
    "messagefoundry/config/loaded_crls.py": "a weak registry of the CRL copies live TLS contexts "
    "hold, for the expiry monitor (BACKLOG #299); it stores public CRL metadata and holds no key",
    "messagefoundry/config/wiring.py": _KEYLESS,
    "messagefoundry/config/tls_policy.py": "the TLS policy seam itself: it builds verifying contexts, "
    "floors and suite lists for its callers, and never loads, mints or holds a private key; each "
    "caller that loads one is sorted under its own row",
    "messagefoundry/config/tls_probe.py": "an outbound protocol-version probe that builds contexts "
    "with certificate checks deliberately off; it measures which TLS versions a peer accepts and "
    "loads no key and no trust anchor",
    "messagefoundry/config/models.py": _POSTURE_ONLY,
    "messagefoundry/config/settings.py": _POSTURE_ONLY,
    "messagefoundry/transports/strict_requests.py": _VERIFY_ONLY + "; the Vault clients' reply "
    "adapter loads requests' CA onto the https-proxy leg's TLS context, which another module "
    "builds and narrows (BACKLOG #300)",
    "messagefoundry/config/secretprovider_vault.py": "reads connector credentials from Vault KV over "
    "a verifying hop; the Vault token is a credential in the rotation schedule, and a key it fetches "
    "is governed by the row for the setting it fills",
    "messagefoundry/privilege_probes.py": _KEYLESS + "; check-privileges reads each Vault "
    "token's own policies through the providers' client builders, and the token is a credential "
    "in the rotation schedule (BACKLOG #305)",
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
    "messagefoundry/pipeline/reference_sync.py": _POSTURE_ONLY,
    "harness/load/connscale/runner.py": _POSTURE_ONLY,
    "harness/load/shardcert.py": _POSTURE_ONLY,
    # Vault BACKLOG #2719: the per-run rig password is a credential, hashed by argon2id like any
    # local account's. It is classified the same way in tests/test_key_usage_scope_inventory.py.
    "harness/load/rigadmin.py": "draws a per-run rig Administrator password (a credential, not a "
    "key) and signs in over a verifying TLS context; it loads, mints and holds no private or "
    "secret key",
    "messagefoundry/pipeline/security_notify.py": _POSTURE_ONLY,
    "messagefoundry/pipeline/wiring_runner.py": _POSTURE_ONLY,
    "messagefoundry/api/app.py": _POSTURE_ONLY,
    "messagefoundry/api/security.py": _POSTURE_ONLY,
    "messagefoundry/store/cipher_cells.py": "a read-only declaration of cipher-covered cells; it "
    "builds a cell's AAD, which is byte framing, and never loads or holds a key",
    "messagefoundry/transports/base.py": "names the ssl types for a connect helper that receives a "
    "context built elsewhere and reports handshake failures; it builds no context and loads no key",
    "messagefoundry/transports/ai_broker.py": _POSTURE_ONLY,
    "messagefoundry/transports/bounded_read.py": _POSTURE_ONLY,
    "messagefoundry/transports/database.py": _POSTURE_ONLY + ". It also READS the wrap of a "
    "driver client key (libpq sslkey) to refuse a weak one (BACKLOG #1352), but the ODBC driver "
    "loads that key, not the engine, and it has no lifecycle row of its own yet",
    "messagefoundry/transports/http_auth.py": _POSTURE_ONLY,
    "messagefoundry/transports/email.py": _VERIFY_ONLY,
    "messagefoundry/transports/dicomweb.py": _EPHEMERAL + " (a multipart boundary)",
    "messagefoundry/transports/file.py": _KEYLESS,
    "messagefoundry/tray/probe.py": _VERIFY_ONLY,
    "messagefoundry/verify/smoke.py": _VERIFY_ONLY,
    # BACKLOG #1923: reads the OIDC revocation guard's decision off the tls_policy seam. The IdP
    # context it inspects is built by auth/oidc_http.py from a CA anchor and a CRL, neither a key.
    "messagefoundry/verify/federation.py": _POSTURE_ONLY,
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


def _first_cells(lines: list[str], heading: str) -> list[str]:
    """The first cell of each WRITTEN table body row under ``heading``, up to the next ``### ``.

    A row counts as written only if it has at least four cells and every one holds text, so a row
    emptied down to its label does not count. Header rows (the ones a separator follows) and
    separators are skipped. An absent heading yields nothing.
    """
    start = next((i for i, line in enumerate(lines) if line.startswith(heading)), None)
    if start is None:
        return []
    end = next(
        (i for i, line in enumerate(lines[start + 1 :], start + 1) if line.startswith("### ")),
        len(lines),
    )
    separator = re.compile(r"^\|\s*-")
    firsts: list[str] = []
    for i in range(start + 1, end):
        line = lines[i]
        if not line.startswith("| ") or separator.match(line):
            continue
        if i + 1 < end and separator.match(lines[i + 1]):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and all(_WORD.search(cell) for cell in cells):
            firsts.append(cells[0])
    return firsts


def lifecycle_labels(doc: str) -> set[str]:
    """The key labels the document gives a lifecycle to.

    Every written table row in the lifecycle subsection whose first cell leads with a bold label,
    plus :data:`_DEK` when the store-key policy heading and all its bullets are present. The
    subsection ends at the next ``### `` heading, so a table in a later subsection (the SP 800-57
    mapping) can never stand in for a deleted lifecycle row.
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
    for first in _first_cells(lines, _LIFECYCLE_HEADING):
        match = re.match(r"\*\*(.+?)\*\*", first)
        if match:
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


def mapping_labels(doc: str) -> set[str]:
    """The key labels the SP 800-57 mapping table gives a written row to.

    The first cell of each written row under :data:`_MAPPING_HEADING` is the label, spelled exactly
    as the lifecycle label it maps. A bold first cell is not counted, because bold labels belong to
    the lifecycle tables, so a key whose mapping row is bold reads as unmapped.
    """
    return {
        first
        for first in _first_cells(doc.splitlines(), _MAPPING_HEADING)
        if not first.startswith("**")
    }


def unmapped(doc: str) -> list[str]:
    """Lifecycle labels other than the DEK with no row in the SP 800-57 mapping table."""
    return sorted(lifecycle_labels(doc) - {_DEK} - mapping_labels(doc))


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


def test_every_lifecycle_key_has_an_sp800_57_mapping_row() -> None:
    """Every key with a lifecycle row, except the store DEK, has a row in the SP 800-57 mapping.

    This is row PRESENCE only. It says nothing about whether a key's lifecycle follows the standard,
    and the mapping records several places where it does not; do not score ASVS 11.1.1 off a green
    here. Mutation: delete the SFTP client key's mapping row. Red: ``SFTP client key``.
    """
    doc = _DOC.read_text(encoding="utf-8")
    assert {_SFTP, _TOTP, _ANON_SALT} <= mapping_labels(doc), (
        f"mapping parse found only {sorted(mapping_labels(doc))}; the table or its heading moved"
    )
    missing = unmapped(doc)
    assert not missing, (
        f"lifecycle key(s) with no SP 800-57 mapping row: {missing}. Add a row under "
        f"'{_MAPPING_HEADING}' in docs/ASVS-L2-PHASE0-CHANGES.md."
    )


def test_every_mapping_row_names_a_lifecycle_key() -> None:
    """The reverse: a mapping row whose label matches no lifecycle row maps a key the policy does not
    govern, or carries a typo that would let the real key go unmapped unnoticed."""
    doc = _DOC.read_text(encoding="utf-8")
    strays = sorted(mapping_labels(doc) - lifecycle_labels(doc))
    assert not strays, f"SP 800-57 mapping row(s) naming no lifecycle key: {strays}"


def test_deleting_a_mapping_row_turns_the_guard_red() -> None:
    """The mutation, run in-process. Deleting a mapping row, or emptying one down to its label, must
    be reported; a bold-labelled row must not count as a mapping row."""
    lines = _DOC.read_text(encoding="utf-8").splitlines()
    assert not unmapped("\n".join(lines)), (
        "the unmutated doc must be clean for this to mean anything"
    )
    for label in (_SFTP, _TOTP, _ANON_SALT):
        kept = [line for line in lines if not line.startswith(f"| {label} |")]
        assert len(kept) == len(lines) - 1, (
            f"expected one mapping row for {label!r}; the label moved"
        )
        assert label in unmapped("\n".join(kept)), (
            f"deleting the {label!r} mapping row stayed green"
        )
    row = f"| {_SFTP} |"
    emptied = [f"{row} - | - | - |" if line.startswith(row) else line for line in lines]
    assert _SFTP in unmapped("\n".join(emptied)), "a mapping row emptied to its label stayed green"
    bolded = [
        line.replace(row, f"| **{_SFTP}** |", 1) if line.startswith(row) else line for line in lines
    ]
    assert _SFTP in unmapped("\n".join(bolded)), "a bold-labelled mapping row counted as mapped"
    # A bold mapping row must not stand in for the lifecycle row either: delete the lifecycle row.
    kept = [line for line in bolded if not line.startswith(f"| **{_SFTP}** —")]
    assert len(kept) == len(bolded) - 1, "expected one SFTP lifecycle row to delete; its lead moved"
    masked = "\n".join(kept)
    assert f"messagefoundry/transports/remotefile.py -> {_SFTP}" in uncovered(masked), (
        "a bold mapping row hid a deleted lifecycle row"
    )


def test_the_totp_mapping_row_takes_no_cryptoperiod() -> None:
    """BACKLOG #1931 (owner ruling 2026-09-27): the TOTP secret is exempt from a calendar lifetime.
    Its mapping row must say so and cite the ruling, rather than borrow a 5.3.6 cryptoperiod."""
    doc = _DOC.read_text(encoding="utf-8")
    row = next((line for line in doc.splitlines() if line.startswith(f"| {_TOTP} |")), "")
    assert "**Cryptoperiod: none.**" in row and "#1931" in row, (
        "the TOTP mapping row must state it has no cryptoperiod and cite BACKLOG #1931"
    )


def dek_section(doc: str) -> list[str]:
    """The lines of the DEK mapping subsection, from its heading to the next ``### ``."""
    lines = doc.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith(_DEK_MAPPING_HEADING)), None)
    if start is None:
        return []
    end = next(
        (i for i, ln in enumerate(lines[start + 1 :], start + 1) if ln.startswith("### ")),
        len(lines),
    )
    return lines[start:end]


def dek_clause_rows(doc: str) -> tuple[dict[str, str], list[str]]:
    """The DEK mapping's WRITTEN rows by clause -> whole row, and any clause written twice.

    Only lines inside the DEK mapping subsection are read, so a row elsewhere in the doc that
    happens to lead with the same clause can neither stand in for one nor mask an edit to one."""
    section = dek_section(doc)
    firsts = _first_cells(section, _DEK_MAPPING_HEADING)
    rows: dict[str, str] = {}
    for line in section:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if line.startswith("| ") and cells[0] in firsts:
            rows.setdefault(cells[0], line)
    twice = sorted({c for c in firsts if firsts.count(c) > 1})
    return rows, twice


def _claim_cell(row: str) -> str:
    """The third cell of a mapping row: the claim about the engine, where a departure belongs."""
    cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
    return cells[2] if len(cells) > 2 else ""


def dek_mapping_problems(doc: str) -> list[str]:
    """Where the DEK mapping departs from :data:`_DEK_CLAUSES` and :data:`_DEK_DEPARTURES`."""
    rows, twice = dek_clause_rows(doc)
    problems = [f"clause row written twice: {c}" for c in twice]
    problems += [f"missing clause row: {c}" for c in sorted(_DEK_CLAUSES - set(rows))]
    problems += [f"clause row not in _DEK_CLAUSES: {c}" for c in sorted(set(rows) - _DEK_CLAUSES)]
    problems += [
        f"departure no longer named: {c}"
        for c in sorted(_DEK_DEPARTURES & set(rows))
        if "**Departure" not in _claim_cell(rows[c])
    ]
    return problems


def test_the_dek_has_a_clause_by_clause_sp800_57_mapping() -> None:
    """BACKLOG #1162: the DEK's SP 800-57 alignment is mapped, not only claimed. Row PRESENCE and the
    departure flags only; whether each row reads the standard correctly is the reviewer's job."""
    doc = _DOC.read_text(encoding="utf-8")
    assert len(dek_clause_rows(doc)[0]) >= 10, "the DEK mapping table or its heading moved"
    problems = dek_mapping_problems(doc)
    assert not problems, f"DEK SP 800-57 mapping under '{_DEK_MAPPING_HEADING}': {problems}"


def test_the_dek_mapping_guard_turns_red() -> None:
    """The mutations, run in-process: delete a clause row, empty one to its clause, strip a
    departure, and put the DEK table under the other-keys heading. Each must be reported."""
    doc = _DOC.read_text(encoding="utf-8")
    assert not dek_mapping_problems(doc), (
        "the unmutated doc must be clean for this to mean anything"
    )
    lines = doc.splitlines()
    row = "| 5.2 one purpose |"
    kept = [line for line in lines if not line.startswith(row)]
    assert len(kept) == len(lines) - 1, "expected one 5.2 row to delete; its clause label moved"
    assert "missing clause row: 5.2 one purpose" in dek_mapping_problems("\n".join(kept))
    emptied = [f"{row} - | - | - |" if line.startswith(row) else line for line in lines]
    assert "missing clause row: 5.2 one purpose" in dek_mapping_problems("\n".join(emptied))
    stripped = [
        re.sub(r"\*\*Departure[^*]*\*\*", "", line) if line.startswith(row) else line
        for line in lines
    ]
    assert "departure no longer named: 5.2 one purpose" in dek_mapping_problems("\n".join(stripped))
    # A departure moved out of the engine-claim column into the site column no longer counts.
    moved = []
    for line in lines:
        if line.startswith(row):
            cells = line.strip().strip("|").split("|")
            cells[2] = re.sub(r"\*\*Departure[^*]*\*\*", "", cells[2])
            cells[3] = cells[3] + " **Departure** "
            line = "|" + "|".join(cells) + "|"
        moved.append(line)
    assert "departure no longer named: 5.2 one purpose" in dek_mapping_problems("\n".join(moved))
    doubled = [line for line in lines for _ in range(2 if line.startswith(row) else 1)]
    assert "clause row written twice: 5.2 one purpose" in dek_mapping_problems("\n".join(doubled))
    # Delete the DEK heading: its rows fall under the other-keys mapping. The DEK guard must report
    # every clause missing, and the other-keys guard must see the clause rows as strays.
    headless = "\n".join(line for line in lines if not line.startswith(_DEK_MAPPING_HEADING))
    assert "missing clause row: 8.3.4 destruction" in dek_mapping_problems(headless)
    assert "5.2 one purpose" in mapping_labels(headless) - lifecycle_labels(headless)
    assert "5.2 one purpose" not in mapping_labels(doc)


#: Code symbols the DEK mapping cites, by module. A rename leaves the prose pointing at nothing.
_DEK_CITED_SYMBOLS: dict[str, tuple[str, ...]] = {
    "messagefoundry/store/crypto.py": (
        "derive_store_data_key",
        "_SubkeyDeriver",
        "_derive_audit_mac_key",
        "rotation_fingerprint_key",
        "_WriteKey",
        "generate_key",
        "_secure_zero",
        "_lock_memory",
    ),
    "messagefoundry/store/backup_codec.py": ("ArchiveHeader", "frame_key"),
    "messagefoundry/pipeline/dr_backup.py": ("_resolve_key", "_store_salt"),
    "messagefoundry/store/store.py": ("settle_audit_ranges",),
}


def test_the_dek_mapping_cites_live_code() -> None:
    """The symbols and defaults the DEK mapping quotes must still exist and match, so a rename or a
    changed default turns this red instead of leaving the mapping quietly wrong."""
    from messagefoundry.config.settings import SecretRotationSettings
    from messagefoundry.store.crypto import CipherInfo  # noqa: F401 - cited as the fingerprint view
    from messagefoundry.store.store import AUDIT_KEY_EPOCH_ACTION

    doc = _DOC.read_text(encoding="utf-8")
    section = "\n".join(dek_section(doc))
    for rel, names in _DEK_CITED_SYMBOLS.items():
        source = (_ROOT / rel).read_text(encoding="utf-8")
        for name in names:
            # Inside the DEK subsection only, and inside one code span.
            assert re.search(rf"`[^`\n]*\b{name}\b[^`\n]*`", section), (
                f"{name} is listed here but the DEK mapping no longer cites it"
            )
            assert re.search(rf"^\s*(?:async\s+)?(?:def|class)\s+{name}\b", source, re.M), (
                f"{rel} no longer defines {name}, which the DEK mapping cites"
            )
    defaults = SecretRotationSettings()
    assert defaults.store_key_max_age_days == 365 and "`store_key_max_age_days` (365)" in section
    assert defaults.enforce_grace_days == 30 and "`enforce_grace_days` (30)" in section
    assert AUDIT_KEY_EPOCH_ACTION == "audit.key_epoch" and "`audit.key_epoch`" in doc
