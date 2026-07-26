# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 11.1.2 / 11.1.4 §4 truth-guard: the key-management & cryptographic inventory in
``docs/ASVS-L2-PHASE0-CHANGES.md`` §4 must stay TRUE and complete.

Sibling of ``tests/test_secret_rotation_inventory.py`` (13.1.4) and
``scripts/security/crypto_inventory_check.py`` (11.1.3). Those two guard the *rotation schedule* and the
*crypto call-site inventory*; this one guards the **cipher/key-material inventory truth** the 11.1.2 /
11.1.4 remediation established, so it cannot silently rot back:

* **Every ``[store].cipher_provider`` value is documented.** The values ``build_store_cipher`` accepts
  (discovered from ``store/base.py``) must each have a §4 asset row — a new cipher provider trips the
  gate until it is documented. The store-cipher **seam module** for each provider (``store/crypto.py``
  for ``aesgcm``, ``store/crypto_transit.py`` for ``vault_transit``) must be cited too.
* **The INVENTORY store-cipher-seam group is documented.** Every ``store/crypto*`` module the ASVS
  11.1.3 scanner inventories must be cited by path in §4 (the crypto seam that performs at-rest crypto
  with zero stdlib-crypto imports is invisible to the un-widened scanner, so the doc is its backstop).
* **The OIDC verification/trust material is documented** (ADR 0142) — the JWKS verifying keys and the
  pinned TLS trust anchor.
* **The retired false claims cannot reappear** — the "keyless identity (plaintext) by default" cipher
  claim (false since ADR 0148) and the "no classical-public-key data at rest" PQC claim (false given
  the WebAuthn COSE + OIDC RP keys).
* **Every migration row keeps a dated milestone + a named owner** (11.1.4), and the section states a
  review cadence tied to this guard.

PHI-free: it reads only doc prose and code *names/paths*, never a secret value.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PKG = _ROOT / "messagefoundry"
_DOC = _ROOT / "docs" / "ASVS-L2-PHASE0-CHANGES.md"
_CRYPTO_GATE = _ROOT / "scripts" / "security" / "crypto_inventory_check.py"


def _load_crypto_gate_inventory() -> dict[str, frozenset[str]]:
    """Load ``INVENTORY`` from the ASVS 11.1.3 crypto-gate script by file path.

    ``scripts/`` is not an importable package (the gate is otherwise run as a subprocess — see
    ``test_security_static.py``), so load the module standalone. It imports only stdlib and its
    ``__main__`` guard keeps ``main()`` from running on import."""
    spec = importlib.util.spec_from_file_location("_crypto_inventory_check_doc", _CRYPTO_GATE)
    assert spec is not None and spec.loader is not None, f"cannot load {_CRYPTO_GATE}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    inventory: dict[str, frozenset[str]] = module.INVENTORY
    return inventory


# §4 is sliced by these exact headings; the check fails loudly if the section is restructured away.
_SECTION4_START = "## 4. Key-management & cryptographic inventory"
_SECTION4_END = "## 5. Communications inventory"

# The migration subsection (11.1.4) lives at the tail of §4.
_MIGRATION_START = "### Cryptographic migration & agility"

# The exact false claims 11.1.2 / 11.1.4 deleted. If either literal reappears anywhere in §4 the cell
# has regressed. (Both are substrings, not tokens — they are whole false sentences.)
_RETIRED_CLAIMS = (
    "keyless identity (plaintext) by default",  # the false at-rest cipher default (ADR 0148 refutes it)
    "no classical-public-key data at rest",  # the false PQC posture (WebAuthn COSE + OIDC RP refute it)
)


def _section4() -> str:
    text = _DOC.read_text(encoding="utf-8")
    start = text.find(_SECTION4_START)
    end = text.find(_SECTION4_END)
    assert start != -1, f"§4 heading {_SECTION4_START!r} missing from {_DOC.name}"
    assert end != -1 and end > start, (
        f"§5 heading {_SECTION4_END!r} missing/misordered in {_DOC.name}"
    )
    return text[start:end]


def _migration_subsection() -> str:
    section = _section4()
    start = section.find(_MIGRATION_START)
    assert start != -1, f"migration heading {_MIGRATION_START!r} missing from §4 of {_DOC.name}"
    return section[start:]


def _accepted_cipher_providers() -> set[str]:
    """The ``[store].cipher_provider`` values ``build_store_cipher`` accepts, discovered from source.

    Tied to the code (not a hand-list) so a NEW provider added to ``store/base.py`` without a §4 row
    fails this guard. ``build_store_cipher`` dispatches on string-literal comparisons
    (``settings.cipher_provider == "vault_transit"`` / ``!= "aesgcm"``); we harvest those literals."""
    src = (_PKG / "store" / "base.py").read_text(encoding="utf-8")
    providers = set(re.findall(r'cipher_provider\s*(?:==|!=)\s*"([a-z0-9_]+)"', src))
    assert providers, "no [store].cipher_provider literals found in store/base.py — parse drifted"
    return providers


def _missing_from_section(tokens: set[str], section: str) -> list[str]:
    """Tokens that do not appear (substring) in ``section`` — the reusable drift check."""
    return sorted(t for t in tokens if t not in section)


def test_every_cipher_provider_value_is_documented() -> None:
    section = _section4()
    providers = _accepted_cipher_providers()
    missing = _missing_from_section(providers, section)
    assert not missing, (
        "[store].cipher_provider value(s) accepted by store/base.py but not documented in "
        f"docs/ASVS-L2-PHASE0-CHANGES.md §4: {missing}"
    )


def test_cipher_provider_constant_matches_the_documented_value() -> None:
    # Rename guard: the vault_transit provider constant must stay the value the doc + base.py use, so a
    # rename of PROVIDER_NAME cannot silently orphan the §4 row. Imported locally so an import hiccup is
    # contained to this one test.
    from messagefoundry.store.crypto_transit import PROVIDER_NAME

    assert PROVIDER_NAME == "vault_transit"
    assert PROVIDER_NAME in _accepted_cipher_providers()


def test_cipher_provider_seam_modules_are_cited() -> None:
    # Each accepted cipher provider's implementing seam module must be cited by path in §4.
    section = _section4()
    seam_by_provider = {
        "aesgcm": "store/crypto.py",
        "vault_transit": "store/crypto_transit.py",
    }
    # Every accepted provider must have a known seam mapping (a new provider forces a mapping + a row).
    unmapped = sorted(_accepted_cipher_providers() - set(seam_by_provider))
    assert not unmapped, f"cipher provider(s) with no seam-module mapping in this test: {unmapped}"
    missing = sorted(p for p, mod in seam_by_provider.items() if mod not in section)
    assert not missing, f"cipher-provider seam module(s) not cited in §4: {missing}"


def test_inventory_store_cipher_seam_group_is_documented() -> None:
    # The "INVENTORY module group" tie: every store-cipher seam the ASVS 11.1.3 scanner inventories
    # (store/crypto*) must be cited by path in §4. store/crypto_transit.py imports none of the six stdlib
    # crypto modules, so the un-widened scanner cannot see it — the doc is its sole inventory anchor,
    # which is exactly why this guard exists. Green now (store/crypto.py) and after 11.1.3 widens the
    # scanner to add store/crypto_transit.py (already documented here).
    inventory = _load_crypto_gate_inventory()

    section = _section4()
    seam_group = {p for p in inventory if p.startswith("messagefoundry/store/crypto")}
    # store/crypto.py is always inventoried; be resilient if a refactor renames it away.
    seam_group.add("messagefoundry/store/crypto.py")
    missing = sorted(p for p in seam_group if p.removeprefix("messagefoundry/") not in section)
    assert not missing, (
        "store-cipher seam module(s) in crypto_inventory_check.INVENTORY not cited in §4 "
        f"(add a §4 row): {missing}"
    )


def test_oidc_verification_material_is_documented() -> None:
    section = _section4()
    required = {"auth/oidc/jwks.py", "oidc_tls_ca_cert_file"}
    missing = _missing_from_section(required, section)
    assert not missing, (
        f"OIDC (ADR 0142) verification/trust material not documented in §4: {missing}"
    )


def test_retired_false_claims_are_absent() -> None:
    section = _section4()
    present = [claim for claim in _RETIRED_CLAIMS if claim in section]
    assert not present, (
        "a retired FALSE cryptographic-inventory claim reappeared in §4 of "
        f"docs/ASVS-L2-PHASE0-CHANGES.md: {present}"
    )


def _migration_data_rows() -> list[list[str]]:
    """The migration table's data rows as cell lists (header + separator dropped)."""
    rows: list[list[str]] = []
    for line in _migration_subsection().splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) < 4:
            continue
        if cells[0] in {"Crypto surface", ""} or set(cells[0]) <= {"-", ":"}:
            continue  # header row / --- separator
        rows.append(cells)
    return rows


def test_every_migration_row_has_a_dated_milestone_and_owner() -> None:
    rows = _migration_data_rows()
    # The pre-existing four plus the five new (at-rest aesgcm, vault_transit, password, hashing/signing,
    # TLS, WebAuthn, OIDC, JWS, DIRECT) — a table that collapsed would fail this floor.
    assert len(rows) >= 9, f"expected >=9 migration rows, found {len(rows)}"
    ownerless: list[str] = []
    undated: list[str] = []
    for cells in rows:
        surface, _mechanism, milestone, owner = cells[0], cells[1], cells[2], cells[3]
        if not owner:
            ownerless.append(surface)
        if not re.search(r"20\d\d", milestone):  # a dated milestone (a year)
            undated.append(surface)
    assert not ownerless, f"migration row(s) with NO named owner (ASVS 11.1.4): {ownerless}"
    assert not undated, f"migration row(s) with NO dated milestone (ASVS 11.1.4): {undated}"


def test_review_cadence_ties_to_this_guard() -> None:
    section = _section4()
    assert "Review cadence" in section, "§4 migration section states no review cadence"
    assert "test_crypto_inventory_doc.py" in section, (
        "§4 review cadence must name this drift-guard (tests/test_crypto_inventory_doc.py) so the "
        "section cannot silently rot"
    )


def test_guard_detects_a_removed_provider_row() -> None:
    # The guard must actually catch a dropped provider row (mirrors
    # test_secret_rotation_inventory.test_scanner_flags_a_planted_secret) — a real regression can't pass
    # silently.
    providers = _accepted_cipher_providers()
    fake_section = "only aesgcm is mentioned here"
    missing = _missing_from_section(providers, fake_section)
    assert "vault_transit" in missing
