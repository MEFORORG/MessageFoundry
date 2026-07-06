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
    # ADR 0030: keyed BLAKE2b derives the deterministic, salt-keyed seed that picks a surrogate, so
    # the anonymizer's pseudonymization is consistent-within-a-dataset yet one-way (re-id-resistant).
    "messagefoundry/anon/keying.py": frozenset({"hashlib"}),
    "messagefoundry/api/tls.py": frozenset({"ssl"}),
    "messagefoundry/auth/ldap.py": frozenset({"ssl"}),
    "messagefoundry/auth/passwords.py": frozenset({"argon2"}),
    "messagefoundry/auth/policy.py": frozenset({"hashlib"}),
    "messagefoundry/auth/service.py": frozenset({"secrets"}),
    "messagefoundry/auth/tokens.py": frozenset({"hashlib", "secrets"}),
    "messagefoundry/auth/totp.py": frozenset({"hashlib", "hmac", "secrets"}),
    # ADR 0068 (WP-14b): first-party 64-byte WebAuthn ceremony challenges (secrets.token_bytes) —
    # single-use, TTL'd, staged server-side (ASVS 6.7.2 evidence). The `webauthn` library's own
    # crypto (COSE signature verification via cryptography) is documented in the §4 rows; the
    # library is an optional [webauthn] extra, lazy-imported inside this module's functions.
    "messagefoundry/auth/webauthn.py": frozenset({"secrets"}),
    # ADR 0041 (D1): SHA-256 content fingerprint of a loaded config bundle, recorded in the
    # config_reload audit to bind reviewed-commit -> loaded-bytes (integrity/attribution, not a secret).
    "messagefoundry/config/fingerprint.py": frozenset({"hashlib"}),
    "messagefoundry/config/tls_policy.py": frozenset({"ssl"}),
    "messagefoundry/config/wiring.py": frozenset({"hashlib"}),
    # CONSOLE-3: the console verifies the engine API server cert — the OS trust store
    # (truststore.SSLContext) by default, or a pinned PEM via --cacert (ssl.create_default_context),
    # plus opt-in client-cert mTLS (load_cert_chain). Builds the client-side TLS verification context.
    "messagefoundry/console/client.py": frozenset({"ssl"}),
    # ADR 0041 (D3): SHA-256 hashes of the loaded first-party modules vs the wheel dist-info/RECORD at
    # startup self-attestation — drift detection (integrity/tamper-evidence, not a secret); the engine
    # alerts by default and (opt-in) fails closed on drift.
    "messagefoundry/integrity.py": frozenset({"hashlib"}),
    # BACKLOG #31: XML-DSig signature verification for the XML codec runs via signxml (which pulls in
    # cryptography + hashlib for the DSig digest/signature primitives). The hashlib import in
    # signature.py is the crypto-inventory anchor making that otherwise-transitive provenance visible.
    "messagefoundry/parsing/xml/signature.py": frozenset({"hashlib"}),
    "messagefoundry/pipeline/cert_expiry.py": frozenset({"cryptography"}),
    # ADR 0049 (#60): the DR BackupRunner SHA-256s the consistent store snapshot (recorded in the
    # manifest + the dr_backup audit row as a PHI-free integrity fingerprint) and re-derives the key_id
    # fingerprint via the backup codec; the AEAD itself lives in store/backup_codec.py.
    "messagefoundry/pipeline/dr_backup.py": frozenset({"hashlib"}),
    # ADR 0049 (#60): the .mfbak DR-backup archive codec — a chunked AES-256-GCM streaming framing
    # (cryptography AESGCM) keyed by the existing store DEK, with a SHA-256 (hashlib) header digest bound
    # as per-frame AAD + the one-way key_id fingerprint. Net-new crypto surface; the store DEK key source
    # is reused, the cipher mechanism is new.
    "messagefoundry/store/backup_codec.py": frozenset({"hashlib", "cryptography"}),
    "messagefoundry/store/crypto.py": frozenset({"hashlib", "cryptography"}),
    # ADR 0064: hashlib = the sha256 CONTENT hash of the shipped schema-DDL batch, stored in the
    # schema_meta marker so a current DB's open can skip the batch + the exclusive schema lock.
    # Content addressing / cache invalidation — not a security control, no secret material involved.
    "messagefoundry/store/postgres.py": frozenset({"hashlib", "ssl"}),
    "messagefoundry/store/sqlserver.py": frozenset({"hashlib"}),
    "messagefoundry/store/store.py": frozenset({"hashlib"}),
    # ADR 0025: the DICOM C-STORE SCP's server SSLContext (Phase 1) + the C-STORE SCU's client SSLContext
    # (Phase 2) for DICOM-over-TLS (the MLLP inbound/outbound posture).
    "messagefoundry/transports/dicom.py": frozenset({"ssl"}),
    # ADR 0025 Phase 2: a per-request random multipart boundary (secrets.token_hex) for the DICOMweb
    # STOW-RS body, generated absent from the object bytes (RFC 2046 §5.1.1) — framing, not a secret.
    "messagefoundry/transports/dicomweb.py": frozenset({"secrets"}),
    # ADR 0023: the inbound HTTP/1.1 listen source reuses MLLP's _mllp_ssl_context (server=True) to
    # build its per-connection HTTPS server identity (+ opt-in mTLS) — the same MLLP inbound-TLS posture.
    "messagefoundry/transports/http_listener.py": frozenset({"ssl"}),
    "messagefoundry/transports/mllp.py": frozenset({"ssl"}),
    # SEC-001 (CWE-295): FTPS (ftplib.FTP_TLS) builds a verifying ssl.create_default_context() for the
    # remote-file connector's TLS control/data channel; CERT_NONE only under the insecure_tls_allowed()
    # escape, mirroring mllp.py's outbound posture.
    "messagefoundry/transports/remotefile.py": frozenset({"ssl"}),
    "messagefoundry/transports/rest.py": frozenset({"ssl"}),
    "messagefoundry/transports/signing.py": frozenset({"cryptography"}),
    # ADR 0024: a random `jti` for the SMART Backend Services client_assertion JWT (the JWT signing
    # itself reuses signing.py's `cryptography`).
    "messagefoundry/transports/smart.py": frozenset({"secrets"}),
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
