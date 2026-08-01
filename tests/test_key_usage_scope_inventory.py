# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 11.1.2: every key-material row in the §4 inventory must document its **usage scope**.

11.1.2 asks that cryptographic keys be inventoried *with the scope of their use* — which key protects
which data, for what property. The 2026-07 assessment scored this cell **Pass** on the strength of the
``**Usage scope:**`` clauses in ``docs/ASVS-L2-PHASE0-CHANGES.md`` §4.

**Nothing pinned them.** ``grep -rn 'Usage scope' tests/`` returned nothing before this module: a new
key-material row could ship with no scope clause, or an existing clause could be deleted, and the cell
would silently regress from a Pass that had been claimed. That is the same defect class as the
threat-model absence claim (``test_threat_model_doc_drift``) and the un-fingerprinted rotation class
(``test_secret_rotation_inventory``) — a *documentation* control with no guard over the document.

Writing this guard found one live gap: the **Audit chain** row keys its HMAC on an HKDF-derived subkey
of the store DEK (and, under ``vault_transit``, a named Transit audit key) and carried no scope clause,
despite being exactly the case 11.1.2 is about — a key derived from a confidentiality key but used for
a different property, whose separation is the thing worth writing down.

**Why an explicit classification rather than a regex.** A "does this row look like key material"
heuristic mis-sorted two of twenty rows on first contact (it missed a plural, and it flagged the audit
chain — which turned out to be right, but for the wrong reason). A guard whose false-positive rate is
non-zero gets suppressed. So every row is classified here, and an UNCLASSIFIED row fails: a new row
cannot be added without someone deciding which side it is on. This is the ``CRITICAL_SECRETS`` pattern
from ``test_secret_rotation_inventory`` — a curated registry plus a completeness check against
discovery, so the curation cannot silently fall behind.

Unlike the threat-model guard, this document is **tracked**, so this module runs where CI runs.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "ASVS-L2-PHASE0-CHANGES.md"
_SECTION = "## 4. Key-management"

#: Rows that describe KEY MATERIAL — a key the engine holds, derives, or consumes to protect the
#: confidentiality or authenticity of something. Each MUST carry a ``**Usage scope:**`` clause naming
#: what it protects and, as importantly, what it does NOT.
_KEY_MATERIAL = frozenset(
    {
        "Store-at-rest cipher",  # both rows: in-process aesgcm and vault_transit
        "Vault Transit KeyProvider",
        "Audit chain",
        "Outbound message signing",
        "DIRECT S/MIME",
        "OIDC IdP JWKS verification keys",
        "OIDC IdP TLS trust anchor",
        "Cert tooling",
    }
)

#: Rows that are NOT key material, each with the reason. These are inventoried in §4 because the
#: section covers the whole cryptographic surface, but 11.1.2's usage-scope clause does not apply:
#: there is no key whose scope could be stated.
_NOT_KEY_MATERIAL: dict[str, str] = {
    "Local password hashes": "a one-way hash with no key — argon2id output, nothing to scope",
    "Session tokens": "CSPRNG bearer values stored as SHA-256; a token is not a key",
    "WebAuthn ceremony challenges": "single-use CSPRNG nonces — no key material",
    "WebAuthn credentials": "COSE PUBLIC keys supplied by the authenticator; the engine holds no "
    "private half and the row already says they are verification material, not a secret",
    "Config fingerprint": "a keyless content hash for change attribution",
    "ASVS corpus pin": "a keyless content hash over a build input (the OWASP ASVS corpus file), "
    "not a key, a secret, or a message authenticator",
    "Engine wheel attestation": "a keyless digest over the installed distribution, verified against "
    "a recorded value; no key is involved on either side",
    "AD transport": "a TLS hop whose key material is the OS/directory trust store, not engine-held",
    "SQL Server transport": "a TLS hop trusted via the OS certificate store and the ODBC driver; the "
    "engine holds no key for it",
    "Console → engine TLS": "a TLS hop configured from the engine's own listener cert (scoped in "
    "the Cert tooling row)",
    "Tray → engine TLS": "a tokenless local TLS probe; no engine-held key",
    "Engine-shard lane ownership": "a coordination record, not cryptographic material",
    "DAST scan-target credential": "a throwaway CSPRNG password for two ephemeral scan identities, "
    "stored only as an argon2id hash in a temp-directory store the scan destroys; a credential is "
    "not a key and it protects nothing",
    "Inbound HTTP intake credential comparison": "keyless — SHA-256 digests of both sides compared "
    "with hmac.compare_digest, which is a constant-time byte comparison and NOT a keyed MAC. The "
    "digesting exists to make the comparison length-blind, not to authenticate anything. The "
    "configured secret is an env()-sourced connector setting whose lifecycle is the rotation "
    "schedule, not engine-held key material",
}


def _rows() -> list[tuple[str, str]]:
    """``(label, full row text)`` for every body row of the §4 inventory table."""
    lines = _DOC.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(_SECTION))
    end = next(i for i, line in enumerate(lines[start + 1 :], start + 1) if line.startswith("### "))
    out: list[tuple[str, str]] = []
    for line in lines[start:end]:
        if not line.startswith("| ") or re.match(r"^\|\s*-+", line) or "| Asset " in line:
            continue
        asset = line.strip().strip("|").split("|")[0].strip()
        # The label is the asset name before its first qualifier — an ADR link, a parenthetical, an
        # em-dash variant, or a config token. Two rows share the "Store-at-rest cipher" label (the
        # aesgcm and vault_transit modes); both are key material, so collapsing them is correct.
        out.append((re.split(r"\s*\(|\s*\[|\s*—|\s*`", asset)[0].strip(), line))
    return out


def test_the_inventory_table_was_actually_parsed() -> None:
    """Liveness receipt. Every assertion below iterates the parsed rows, so a heading rename or a
    table restructure would turn this module into a wall of green over an empty list."""
    rows = _rows()
    assert len(rows) >= 18, f"parsed only {len(rows)} inventory rows — the §4 table shape moved"
    labels = {label for label, _ in rows}
    assert "Store-at-rest cipher" in labels and "Audit chain" in labels, (
        f"the anchor rows are missing from the parse; got {sorted(labels)}"
    )


def test_every_row_is_classified() -> None:
    """Completeness: a NEW inventory row must be classified as key material or not.

    This is what stops the curated set falling behind the document. Mutation: add a row to §4 without
    touching this file. Red: named below.
    """
    unclassified = sorted({label for label, _ in _rows()} - _KEY_MATERIAL - set(_NOT_KEY_MATERIAL))
    assert not unclassified, (
        f"unclassified §4 inventory row(s): {unclassified}. Add each to _KEY_MATERIAL (and give the "
        f"row a **Usage scope:** clause) or to _NOT_KEY_MATERIAL with the reason it holds no key."
    )


def test_every_key_material_row_documents_its_usage_scope() -> None:
    """The property ASVS 11.1.2 was scored Pass on.

    Mutation: delete the ``**Usage scope:**`` clause from any key-material row. Red: that row is named.
    """
    missing = sorted(
        label for label, row in _rows() if label in _KEY_MATERIAL and "**Usage scope:**" not in row
    )
    assert not missing, (
        f"key-material row(s) with no **Usage scope:** clause: {missing}. ASVS 11.1.2 requires the "
        f"inventory to record what each key protects — and what it does not. This cell is currently "
        f"scored Pass on exactly these clauses."
    )


def test_the_classification_does_not_rot() -> None:
    """Both sets must name rows that still exist, and must not overlap.

    A stale entry silently stops guarding (the row it names is gone); an overlapping one is
    self-contradictory. Mutation: rename a row in the doc without updating this file. Red below.
    """
    labels = {label for label, _ in _rows()}
    stale = sorted((_KEY_MATERIAL | set(_NOT_KEY_MATERIAL)) - labels)
    assert not stale, f"classification names §4 rows that no longer exist: {stale}"
    overlap = sorted(_KEY_MATERIAL & set(_NOT_KEY_MATERIAL))
    assert not overlap, f"rows classified as BOTH key material and not: {overlap}"


def test_a_non_key_row_carries_a_reason_not_an_empty_excuse() -> None:
    """An exclusion list whose entries carry no reason is where real key material gets parked. Every
    reason must be a sentence, not a placeholder."""
    thin = sorted(k for k, v in _NOT_KEY_MATERIAL.items() if len(v.split()) < 5)
    assert not thin, f"_NOT_KEY_MATERIAL entries with no real reason: {thin}"
