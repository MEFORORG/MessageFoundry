#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-L3-02 (ASVS 11.1.3): cryptographic-discovery gate.

Enumerate every cryptographic call site in ``messagefoundry/`` (imports of ``hashlib``, ``secrets``,
``hmac``, ``ssl``, ``argon2``, ``cryptography``) via the AST and diff them against the maintained
inventory below. The build **fails** when a module uses a crypto primitive it isn't documented to use
— so a new (or moved) crypto usage can't slip in unreviewed, and the inventory below stays an accurate
"where is crypto used" map (it is the machine-readable companion to the human-readable inventory in
``docs/security/ASVS-L2-PHASE0-CHANGES.md`` §4).

Stdlib only (no install), like ``scripts/publish/scan_forbidden.py`` — runnable as a CI step and a
pytest. Usage::

    python scripts/security/crypto_inventory_check.py            # scan the real package
    python scripts/security/crypto_inventory_check.py --package DIR   # scan an arbitrary package (tests)
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

# Top-level modules that mean "crypto happens here".
CRYPTO_MODULES = frozenset({"hashlib", "secrets", "hmac", "ssl", "argon2", "cryptography"})

# The maintained inventory: repo-relative module path -> the crypto modules it is documented to use.
# Keep this in sync with docs/security/ASVS-L2-PHASE0-CHANGES.md §4. To add an entry, document *why*
# the new crypto usage is needed there, then list it here.
INVENTORY: dict[str, frozenset[str]] = {
    "messagefoundry/api/tls.py": frozenset({"ssl"}),
    "messagefoundry/auth/ldap.py": frozenset({"ssl"}),
    "messagefoundry/auth/passwords.py": frozenset({"argon2"}),
    "messagefoundry/auth/policy.py": frozenset({"hashlib"}),
    "messagefoundry/auth/service.py": frozenset({"secrets"}),
    "messagefoundry/auth/tokens.py": frozenset({"hashlib", "secrets"}),
    "messagefoundry/auth/totp.py": frozenset({"hashlib", "hmac", "secrets"}),
    "messagefoundry/config/tls_policy.py": frozenset({"ssl"}),
    "messagefoundry/config/wiring.py": frozenset({"hashlib"}),
    "messagefoundry/pipeline/cert_expiry.py": frozenset({"cryptography"}),
    "messagefoundry/store/crypto.py": frozenset({"hashlib", "cryptography"}),
    "messagefoundry/store/postgres.py": frozenset({"ssl"}),
    "messagefoundry/store/store.py": frozenset({"hashlib"}),
    "messagefoundry/transports/mllp.py": frozenset({"ssl"}),
    "messagefoundry/transports/rest.py": frozenset({"ssl"}),
    "messagefoundry/transports/signing.py": frozenset({"cryptography"}),
    "messagefoundry/transports/soap.py": frozenset({"hashlib", "ssl"}),
}


def crypto_imports_in(source: str) -> set[str]:
    """The crypto top-level modules imported anywhere in a module (including function-local imports)."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                if top in CRYPTO_MODULES:
                    found.add(top)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            top = node.module.split(".", 1)[0]
            if top in CRYPTO_MODULES:
                found.add(top)
    return found


def discover(package: Path) -> dict[str, frozenset[str]]:
    """Map repo-relative module path -> crypto modules it actually imports (only files that use crypto)."""
    out: dict[str, frozenset[str]] = {}
    for path in sorted(package.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        mods = crypto_imports_in(path.read_text(encoding="utf-8"))
        if mods:
            out[path.relative_to(package.parent).as_posix()] = frozenset(mods)
    return out


def find_violations(
    actual: dict[str, frozenset[str]],
    inventory: dict[str, frozenset[str]],
    *,
    check_stale: bool,
) -> tuple[list[str], list[str]]:
    """Return ``(undocumented, stale)`` message lists. ``undocumented`` = a file uses a crypto module
    not recorded for it (the security-relevant direction). ``stale`` = an inventory entry the file no
    longer backs (kept honest only when scanning the real package)."""
    undocumented: list[str] = []
    for path, mods in sorted(actual.items()):
        extra = mods - inventory.get(path, frozenset())
        if extra:
            documented = sorted(inventory.get(path, frozenset())) or "(file not in inventory)"
            undocumented.append(
                f"{path}: undocumented crypto use {sorted(extra)} (documented: {documented})"
            )
    stale: list[str] = []
    if check_stale:
        for path, mods in sorted(inventory.items()):
            gone = mods - actual.get(path, frozenset())
            if gone:
                stale.append(
                    f"{path}: inventory lists {sorted(gone)} but the file no longer imports it"
                )
    return undocumented, stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cryptographic-discovery gate (ASVS 11.1.3).")
    parser.add_argument(
        "--package",
        type=Path,
        default=None,
        help="package directory to scan (default: the repo's messagefoundry/ with the built-in inventory)",
    )
    args = parser.parse_args(argv)

    scanning_default = args.package is None
    package = args.package or (Path(__file__).resolve().parents[2] / "messagefoundry")
    if not package.is_dir():
        print(f"crypto-inventory: package not found: {package}", file=sys.stderr)
        return 2

    actual = discover(package)
    undocumented, stale = find_violations(actual, INVENTORY, check_stale=scanning_default)

    if undocumented:
        print("crypto-inventory: UNDOCUMENTED crypto usage (add it to INVENTORY + ASVS §4):")
        for line in undocumented:
            print(f"  - {line}")
    if stale:
        print("crypto-inventory: STALE inventory entries (remove them from INVENTORY):")
        for line in stale:
            print(f"  - {line}")
    if undocumented or stale:
        return 1

    print(f"crypto-inventory: OK - {len(actual)} documented crypto call site(s), no drift.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
