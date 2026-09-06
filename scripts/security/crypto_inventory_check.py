#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-L3-02 (ASVS 11.1.3): cryptographic-discovery gate.

Enumerate every cryptographic call site across the five first-party roots (:data:`WALK_ROOTS`) via
the AST and diff them against the maintained inventory below. The build **fails** when a module uses a
crypto primitive it isn't documented to use — so a new (or moved) crypto usage can't slip in
unreviewed, and the inventory below stays an accurate "where is crypto used" map (it is the
machine-readable companion to the human-readable inventory in
``docs/ASVS-L2-PHASE0-CHANGES.md`` §4).

A module counts as a crypto call site when it imports any of three trigger classes (BACKLOG #282
widened the original six-stdlib-module list so *delegated* crypto stops being invisible):

* the six stdlib crypto modules (:data:`CRYPTO_MODULES`);
* a third-party crypto library (:data:`CRYPTO_LIBRARY_MODULES` — ``hvac`` / ``truststore`` /
  ``webauthn`` / ``signxml``), whose primitive lives in the library rather than this file; and
* a **first-party delegated-crypto seam** (:data:`CRYPTO_SEAM_MODULES`) — importing one means this
  file performs at-rest / key-management / audit-MAC crypto *through* the seam. This is what makes
  ``store/crypto_transit.py`` (all Vault-Transit AEAD + the audit MAC ride the HTTP seam; it imports
  **none** of the six) a documented, inventoried crypto site.

The walk-set (:data:`WALK_ROOTS`) is byte-identical to ``tests/test_security_static.py``'s
``_CRYPTO_ROOTS`` (BACKLOG #283 owns that pin; this gate consumes it).

**Adding a TLS/crypto call site? Read this first — it is cheaper than a red CI leg.** #323's opening
commit `e4728d7f` failed ``Tests (pytest)`` on all three OS legs by adding ``import ssl`` to
``transports/{email,direct}.py`` without an entry here; layer 3 then avoided the gate entirely rather
than feeding it. Four facts, each measured, that are not obvious from the code below:

* **The gate is BIDIRECTIONAL, so "just register the file" is not a free fix.** An unregistered file
  that imports a trigger fails one way (*undocumented crypto use*); a registered file that STOPS
  importing it fails the other (*inventory lists ['ssl'] but the file no longer imports it*). A
  registration is a standing commitment, not a one-time appeasement.
* **``if TYPE_CHECKING: import ssl`` does NOT hide the import.** Under ``from __future__ import
  annotations`` the annotation still trips the scanner. There is no cheap way to keep the name and
  dodge the gate — nor should there be.
* **The only real escape is not naming the type.** Hold the *inputs* (``tls_verify`` / ``tls_ca_file``
  / a ``TrustAnchorPolicy``) as plain data and let one inventoried builder produce the context into a
  **bare local** with no annotation. Then no ``ssl`` name exists in the calling module at all.
* **For SMTP that builder already exists:** :func:`~messagefoundry.config.tls_policy.build_smtp_tls_context`.
  All three SMTP cells (EMAIL, DIRECT, the ``[alerts]`` sink) route through it, so exactly one file is
  registered here and the ``pipeline/`` call sites stay ``ssl``-free. That is centralization, not
  evasion: one place decides the TLS policy for every SMTP hop in the product.

**A SECOND ARM COVERS THE NON-PYTHON TREE (BACKLOG #1172, ASVS 11.5.1).** Everything above is an
``import ast`` walk of ``*.py``, so it is Python-only *by construction* and cannot see a randomness
draw in another language however the walk-set is spelled. :func:`check_non_python_randomness` scans
:data:`NON_PYTHON_WALK_ROOTS` (``ide/``, the shipped TypeScript VS Code extension, and
``messagefoundry_webconsole/``, whose ``static/*.js`` is the operator console's own first-party
JavaScript) for randomness sources and diffs them against :data:`NON_PYTHON_INVENTORY` the same
bidirectional way. Note that the second root is ALSO a Python walk root: a first-party root may be
mixed-language, and requiring otherwise is what kept the console's JavaScript out of both arms until
the ASVS 11.5.1 scope pass (see :data:`NON_PYTHON_WALK_ROOTS`). Three
properties are the point of it, and each is pinned by a test in
``tests/test_crypto_inventory_scanner.py``:

* a **weak** source (:data:`WEAK_RANDOMNESS_PATTERNS`, i.e. ``Math.random()``) fails the gate and has
  **no inventory row to hide behind** - registering one is refused on purpose, because ASVS 11.5.1
  states an entropy floor on the VALUE and #1172 names "narrow the declared scope so the hit stops
  being visible" as a disqualified pass;
* a **strong** source is inventoried rather than merely tolerated, so a new CSPRNG site is reviewed;
* an **empty walk is a violation, not a clean result**. A scan that reaches no files, and an
  inventory anchor that has gone missing, both red. The anchor (``ide/src/cspNonce.ts`` ->
  ``randomBytes``) is what makes this instrument able to fail: break the walk and the stale direction
  names it.

This is a *randomness* inventory, and that is the whole claim it supports. The other first-party
crypto in ``ide/`` - the TLS floor ``ide/src/engineClient.ts`` applies to every https request - is
still not discoverable from here.

Stdlib only (no install), like ``scripts/security/scan_forbidden.py`` — runnable as a CI step and a
pytest. Usage::

    python scripts/security/crypto_inventory_check.py            # scan the five real roots
    python scripts/security/crypto_inventory_check.py --package DIR   # scan an arbitrary package (tests)
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

# The five first-party roots the gate walks — byte-identical (as basenames) to
# ``tests/test_security_static.py``'s ``_CRYPTO_ROOTS`` (#283 owns that pin; this gate consumes it).
# ``ide/`` is deliberately absent: it is the TypeScript VS Code extension and contains ZERO ``.py``
# files, so THIS scanner — which rglobs ``*.py`` and walks the Python AST — has nothing to read there.
# ``_assert_ide_is_typescript`` below turns that into an enforced invariant, so a future ``.py`` under
# ``ide/`` reds the gate instead of silently escaping the walk.
#
# WHAT THAT EXCLUSION DOES **NOT** MEAN, and this comment used to say otherwise (BACKLOG #1164): it is
# NOT a finding that ``ide/`` is crypto-free. Zero ``.py`` files is a fact about the LANGUAGE, and the
# question this gate exists to answer is whether a tree contains cryptography. ``ide/`` does:
# ``ide/src/cspNonce.ts`` imports ``randomBytes`` from ``node:crypto`` and draws CSPRNG bytes consumed
# across the extension, and ``ide/src/engineClient.ts`` pins a TLS floor it applies to every https
# request. Both are first-party crypto in a shipped artifact and NEITHER is discoverable from here.
#
# ADDING ``ide/`` TO WALK_ROOTS WOULD STILL BE A NO-OP THAT LOOKS LIKE A FIX, and that has not
# changed: the Python AST scanner would find zero ``.py`` there, report clean, and the TypeScript
# sites would stay invisible while the tree gained a green whose greenness is evidence of nothing.
# ``ide/`` is covered by a SEPARATE arm instead (:data:`NON_PYTHON_WALK_ROOTS` below, BACKLOG #1172),
# which reads ``.ts``/``.js`` by pattern rather than by AST and rides this same required context. So
# this gate's green now means "no undocumented crypto in the PYTHON of five roots, AND no
# undocumented or weak RANDOMNESS source in the non-Python roots". The randomness half is the only
# claim the second arm supports - the extension's TLS floor is still outside both.
# ``samples/`` is absent by design too, on the SAME rationale as the ``ide/`` exclusion (ASVS 11.1.3):
# it is author-space EXAMPLE config, not shipped engine code, so its crypto (e.g. a content-fingerprint
# ``hashlib.sha256`` in a sample Handler) is out of the deployed-system inventory scope — the gate
# enumerates the crypto an operator actually runs, not the crypto an author demonstrates. #283's
# ``_CRYPTO_ROOTS`` tuple likewise omits ``samples/`` and this walk-set is pinned byte-identical to it,
# so adding ``samples/`` here would break that pin AND drag author-space into the ReDoS/XML static
# guards that consume the same tuple.
WALK_ROOTS = ("messagefoundry", "messagefoundry_webconsole", "harness", "tee", "scripts")

# --------------------------------------------------------------------------------------------
# The NON-PYTHON randomness arm (BACKLOG #1172, ASVS 11.5.1).
# --------------------------------------------------------------------------------------------
#: First-party roots that hold shipped source in a language the AST walk above cannot read: ``ide/``
#: (the TypeScript VS Code extension) and ``messagefoundry_webconsole/`` (the operator console's
#: hand-written JavaScript under ``static/``).
#:
#: THIS SET DELIBERATELY OVERLAPS :data:`WALK_ROOTS`, and it used to be asserted disjoint from it.
#: That assertion cost real coverage (BACKLOG #1172, ASVS 11.5.1 scope pass). Its stated reason —
#: "the two arms read different file types with different instruments, and merging them would let
#: one arm's green stand in for the other's silence" — is sound, and it argues for keeping the two
#: ARMS separate, which they still are: different instruments, separately reported corpus sizes,
#: neither substituting for the other. It does NOT argue that a first-party ROOT must be
#: single-language, which is what disjointness actually asserted.
#:
#: ``messagefoundry_webconsole`` is the counter-example that was sitting in the tree the whole time.
#: Its Python is in :data:`WALK_ROOTS`, so the root reported green and READ as covered, while
#: ``static/app.js`` and ``static/csp-probe.js`` were read by neither arm — :func:`discover` rglobs
#: ``*.py``, and this walk stopped at ``ide/``. The green was a true statement about the root's
#: ``.py`` and an accidental one about everything else in it. Coverage was being reasoned about per
#: ROOT while the instruments split per LANGUAGE, and disjointness froze that mismatch as an
#: invariant with nothing checking whether it should hold.
#:
#: The console's JavaScript is not incidental to security: ``csp-probe.js`` is the ASVS 3.7.5
#: CSP-enforcement canary, and ``app.js`` registers the page's security controls ahead of its
#: cosmetic ones. Both are served to an authenticated operator's browser at ``/ui``.
NON_PYTHON_WALK_ROOTS = ("ide", "messagefoundry_webconsole")

#: Suffixes the non-Python arm reads. Source only.
NON_PYTHON_SUFFIXES = (".ts", ".js", ".mjs", ".cjs")

#: Never walked: dependency trees and bundler output. They are not first-party source, and a
#: node_modules walk would bury a real finding under thousands of vendor hits.
NON_PYTHON_SKIP_DIRS = frozenset({"node_modules", "out", "dist", ".vscode-test", "coverage"})

#: Randomness sources that are cryptographically sound. A file using one must carry a
#: :data:`NON_PYTHON_INVENTORY` row, so a new CSPRNG site is reviewed rather than merely allowed.
#: The lookbehind stops a longer identifier ending in the same word from matching.
STRONG_RANDOMNESS_PATTERNS: dict[str, re.Pattern[str]] = {
    "randomBytes": re.compile(r"(?<![A-Za-z0-9_$])randomBytes\s*\("),
    "randomFillSync": re.compile(r"(?<![A-Za-z0-9_$])randomFillSync\s*\("),
    "randomInt": re.compile(r"(?<![A-Za-z0-9_$])randomInt\s*\("),
    "randomUUID": re.compile(r"(?<![A-Za-z0-9_$])randomUUID\s*\("),
    "getRandomValues": re.compile(r"(?<![A-Za-z0-9_$])getRandomValues\s*\("),
}

#: Randomness sources that are NOT cryptographic. A hit here fails the gate outright and there is
#: deliberately no inventory row that can silence it: V8's ``Math.random`` is xorshift128+, whose
#: full internal state is recoverable from a short run of outputs, so no draw length rescues it.
#: ``ide/src/cspNonce.ts`` is the worked replacement (``randomBytes`` from ``node:crypto``).
#:
#: IF A GENUINELY NON-SECURITY USE EVER APPEARS (jitter, a sample colour), the fix is not a row
#: here. Either keep it out of the shipped extension, or make the non-security intent structural by
#: routing it through one named helper and widening this comment to say why that helper is sound.
#: An inventory row would record the same green whether the site was sound or not, which is the
#: exact move BACKLOG #1172 rules out as a dishonest pass for ASVS 11.5.1.
WEAK_RANDOMNESS_PATTERNS: dict[str, re.Pattern[str]] = {
    "Math.random": re.compile(r"(?<![A-Za-z0-9_$])Math\s*\.\s*random\s*\("),
    "pseudoRandomBytes": re.compile(r"(?<![A-Za-z0-9_$])pseudoRandomBytes\s*\("),
}

#: The maintained non-Python randomness inventory: repo-relative path -> the STRONG sources it is
#: documented to draw from. Bidirectional like :data:`INVENTORY`, and the stale direction is what
#: makes this arm able to fail: if the walk ever breaks or the file moves, this row is unbacked and
#: the gate reds instead of reporting a clean empty scan.
NON_PYTHON_INVENTORY: dict[str, frozenset[str]] = {
    # ADR 0065-adjacent, BACKLOG #1172. The single source of CSP nonces for every webview the
    # extension builds: 18 bytes (144 bits) of ``randomBytes`` in base64url. A CSP nonce is a
    # capability, so its entropy SOURCE is the security property; the file's own header explains why
    # ``node:crypto`` and not ``crypto.getRandomValues`` (extension-host code, not webview code).
    "ide/src/cspNonce.ts": frozenset({"randomBytes"}),
}

# Top-level stdlib modules that mean "crypto happens here".
CRYPTO_MODULES = frozenset({"hashlib", "secrets", "hmac", "ssl", "argon2", "cryptography"})

# Third-party crypto libraries whose import means "crypto happens here" even when none of the six
# stdlib modules appear — the delegated primitive lives in the library: hvac (Vault Transit / KV),
# truststore (OS trust-store TLS contexts), webauthn (COSE verification), signxml (XML-DSig).
CRYPTO_LIBRARY_MODULES = frozenset({"hvac", "truststore", "webauthn", "signxml"})

# First-party delegated-crypto SEAMS — importing one means this file performs at-rest / key /
# audit-MAC crypto THROUGH the seam, so a module can be a crypto site with zero of the six stdlib
# imports. Recorded as the fully-qualified seam path so each inventory token is self-documenting.
CRYPTO_SEAM_MODULES = frozenset(
    {
        "messagefoundry.store.crypto",
        "messagefoundry.store.keyprovider",
        "messagefoundry.store.keyprovider_vault",
        "messagefoundry.store.crypto_transit",
        "messagefoundry.store.backup_codec",
        # BACKLOG #1323. The TLS-policy seam: importing it means this file resolves a TLS posture
        # (minimum version, cipher/curve policy, verification mode, trust anchor) through the shared
        # helper rather than hand-rolling an SSLContext. Before this entry the seam set was
        # messagefoundry.store.* ONLY, so it was STORE-ONLY BY CONSTRUCTION -- a first-party TLS seam
        # in any other package could not be matched by any entry, and the gate reported the same green
        # whether that surface was sound or not. pipeline/alert_sinks.py was the worked example: it
        # imports smtplib and this module, and no entry could see it.
        "messagefoundry.config.tls_policy",
    }
)

# The union checked against an import's TOP-LEVEL name (seams are matched on their full dotted path).
_TOPLEVEL_TRIGGERS = CRYPTO_MODULES | CRYPTO_LIBRARY_MODULES

# The maintained inventory: repo-relative module path -> the crypto modules it is documented to use.
# Keep this in sync with docs/ASVS-L2-PHASE0-CHANGES.md §4. To add an entry, document *why*
# the new crypto usage is needed there, then list it here.
INVENTORY: dict[str, frozenset[str]] = {
    # ADR 0030: keyed BLAKE2b derives the deterministic, salt-keyed seed that picks a surrogate, so
    # the anonymizer's pseudonymization is consistent-within-a-dataset yet one-way (re-id-resistant).
    "messagefoundry/anon/keying.py": frozenset({"hashlib"}),
    "messagefoundry/api/tls.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    # ASVS 12.1.1: the startup TLS-floor probe. Client contexts ONLY, and deliberately weakened ones —
    # a withdrawn-version offer (minimum==maximum==TLSv1/1.1) at ALL:@SECLEVEL=0 with CERT_NONE, so the
    # ClientHello is actually sent and an untrusted internal CA cannot abort before the version is
    # settled. It measures the operator's proxy and carries NO application data; the contexts are built,
    # used for one handshake, and never returned. Not a data path — do not reuse these settings.
    "messagefoundry/config/tls_probe.py": frozenset({"ssl"}),
    "messagefoundry/auth/ldap.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    # ADR 0142 (OIDC relying party, BACKLOG #274): the federated-SSO layer.
    #   claims.py — hmac.compare_digest for the constant-time nonce comparison; cryptography only for
    #     catching InvalidSignature (the verification itself is transports/signing.py, inventoried).
    #   flow.py   — secrets for the PKCE verifier / state / nonce / flow-id, hashlib.sha256 for the
    #     PKCE S256 challenge and the sha256(flow_id) cache key, hmac.compare_digest for state match.
    #   jwks.py   — cryptography (RSAPublicNumbers/EllipticCurvePublicNumbers) rebuilds a verifying
    #     public key from a JWK; the TLS opener that fetches the JWKS is built in the wiring layer
    #     (auth/oidc_http.py), not here (fetch is injected), so this module imports no ssl.
    #   oidc_http.py — THE wiring layer: ssl builds the one verifying, no-redirect opener both IdP
    #     legs share. Pinned-only trust when [auth].oidc_tls_ca_cert_file is set (mirroring
    #     ad_tls_ca_cert_file); otherwise truststore reads the live OS store. No insecure escape
    #     exists here by design — the IdP hop carries an authentication assertion.
    "messagefoundry/auth/oidc/claims.py": frozenset({"cryptography", "hmac"}),
    "messagefoundry/auth/oidc/flow.py": frozenset({"hashlib", "hmac", "secrets"}),
    "messagefoundry/auth/oidc/jwks.py": frozenset({"cryptography"}),
    "messagefoundry/auth/oidc_http.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    "messagefoundry/auth/passwords.py": frozenset({"argon2"}),
    "messagefoundry/auth/policy.py": frozenset({"hashlib"}),
    "messagefoundry/auth/service.py": frozenset({"messagefoundry.config.tls_policy", "secrets"}),
    "messagefoundry/auth/tokens.py": frozenset({"hashlib", "secrets"}),
    "messagefoundry/auth/totp.py": frozenset({"hashlib", "hmac", "secrets"}),
    # WP #285 (ASVS 6.7.1): SHA-256 fingerprint of an operator-supplied auth-path trust anchor
    # (oidc/ad/api-client CA PEM) — the optional pin compared at construction + reload, and the
    # anchor-changed audit fingerprint. Integrity/tamper-evidence over a public CA cert, not a secret.
    "messagefoundry/auth/trust_anchors.py": frozenset({"hashlib"}),
    # ADR 0068 (WP-14b): first-party 64-byte WebAuthn ceremony challenges (secrets.token_bytes) —
    # single-use, TTL'd, staged server-side (ASVS 6.7.2 evidence). The `webauthn` library (an optional
    # [webauthn] extra, lazy-imported inside this module's functions) performs the COSE signature
    # verification via cryptography — a CRYPTO_LIBRARY_MODULES trigger, so the delegated verification
    # is a first-class inventory token here, not merely §4 prose.
    "messagefoundry/auth/webauthn.py": frozenset({"secrets", "webauthn"}),
    # ADR 0041 (D1): SHA-256 content fingerprint of a loaded config bundle, recorded in the
    # config_reload audit to bind reviewed-commit -> loaded-bytes (integrity/attribution, not a secret).
    "messagefoundry/config/fingerprint.py": frozenset({"hashlib"}),
    "messagefoundry/config/tls_policy.py": frozenset({"ssl"}),
    "messagefoundry/config/wiring.py": frozenset({"hashlib"}),
    # ADR 0154 (D6): the neutral credential leaf both the transports and the API depend on.
    # `hmac.compare_digest` over fixed-width SHA-256 digests of BOTH sides — the digesting is what
    # makes the comparison length-blind, so a credential's length cannot leak by timing. Not a
    # password hash (no KDF, no stored verifier): this compares a presented shared secret against a
    # configured one that is already in memory from env(). Password storage remains argon2 in
    # auth/passwords.py.
    "messagefoundry/credential.py": frozenset({"hashlib", "hmac"}),
    # CONSOLE-3 (ADR 0088: extracted from console/client.py to the Qt-free apiclient library): the
    # engine-client verifies the engine API server cert — the OS trust store (truststore.SSLContext,
    # a CRYPTO_LIBRARY_MODULES trigger) by default, or a pinned PEM via --cacert
    # (ssl.create_default_context), plus opt-in client-cert mTLS (load_cert_chain). Builds the
    # client-side TLS verification context.
    "messagefoundry/apiclient/client.py": frozenset({"ssl", "truststore"}),
    # BACKLOG #1276 part A: the engine always serves TLS now and mints a self-signed placeholder when
    # no operator cert is configured. This harness supplies its own certificate instead — one pair
    # minted per run (ssl.create_default_context(cafile=...) pins to it) rather than chasing the one
    # the engine mints, so no client ever races a file that doesn't exist until the engine writes it.
    # Non-prod only: the pair lives in a per-process temp dir and covers loopback names alone.
    "harness/load/tlsmat.py": frozenset({"ssl"}),
    # ADR 0041 (D3): SHA-256 hashes of the loaded first-party modules vs the wheel dist-info/RECORD at
    # startup self-attestation — drift detection (integrity/tamper-evidence, not a secret); the engine
    # alerts by default and (opt-in) fails closed on drift.
    "messagefoundry/integrity.py": frozenset({"hashlib"}),
    # BACKLOG #202 (ADR 0080): native TLS-syslog off-box forwarding wraps the syslog TCP socket in an
    # ssl.SSLContext (forward_protocol="tls") — verified against forward_tls_ca_file per forward_tls_verify,
    # with opt-in client-cert mTLS. Transport-layer confidentiality for the off-box audit/log stream; the
    # default udp/tcp forwarders and the no-collector path use no crypto.
    "messagefoundry/logging_setup.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    # BACKLOG #31: XML-DSig signature verification for the XML codec runs via signxml (which pulls in
    # cryptography + hashlib for the DSig digest/signature primitives). The hashlib import in
    # signature.py is the crypto-inventory anchor making that otherwise-transitive provenance visible.
    "messagefoundry/parsing/xml/signature.py": frozenset({"hashlib"}),
    # BACKLOG #71/#72: the `cert` CLI group's PKI primitives live in ONE module — PKCS#12/.pfx import
    # (pkcs12.load_key_and_certificates), the read-only cert inventory (x509 load + SAN/notAfter facts),
    # and self-signed dev-cert minting (EC P-256 CertificateBuilder + SHA-256). pipeline/cert_expiry.py's
    # `_inspect` delegates its load/notAfter/days path here too (read_cert_facts), so it no longer imports
    # `cryptography` directly — this is the single cert-tooling crypto call site.
    "messagefoundry/pki.py": frozenset({"cryptography"}),
    # ASVS 6.4.5: the expiry monitor's PEM path still delegates to pki.read_cert_facts above, but the
    # service-caller arm inspects a cert the engine only ever SEES at the mTLS handshake, which arrives
    # as an `ssl.getpeercert()` DICT rather than PEM bytes. `ssl.cert_time_to_seconds` parses that dict's
    # OpenSSL-textual `notAfter` — the stdlib parser rather than a hand-rolled one. Read-only date
    # arithmetic on an ALREADY-VERIFIED cert: it builds no SSLContext, reads no key material, and makes
    # no trust decision (the chain was verified by the listener long before this runs).
    "messagefoundry/pipeline/cert_expiry.py": frozenset({"ssl"}),
    # ASVS 11.3.4 (#301): the periodic AES-GCM invocation-reserve refill runner reads the live
    # cipher's key_id + per-key bound through the store.crypto seam — no direct stdlib crypto import.
    "messagefoundry/pipeline/gcm_invocations.py": frozenset({"messagefoundry.store.crypto"}),
    # ASVS 13.3.4 (BACKLOG #282): the secret-rotation watcher fingerprints each tracked secret with a
    # KEYED MAC — hmac.new(key, value, sha256), keyed by a DEK-derived subkey (rotation_fingerprint_key
    # in store/crypto.py, HKDF), never a salted hash — to auto-detect rotation without persisting or
    # logging any value. hashlib supplies the SHA-256 digestmod for that HMAC. The DEK-derived key is
    # obtained through the store cipher (store.crypto seam), delegated, so this module keeps only the
    # keyed-MAC primitive.
    "messagefoundry/pipeline/secret_rotation.py": frozenset({"hashlib", "hmac"}),
    # ADR 0049 (#60): the DR BackupRunner SHA-256s the consistent store snapshot (recorded in the
    # manifest + the dr_backup audit row as a PHI-free integrity fingerprint) and re-derives the key_id
    # fingerprint via the backup codec; the AEAD itself is delegated to store/backup_codec.py — a
    # CRYPTO_SEAM_MODULES import, so that delegation is now a first-class inventory token.
    "messagefoundry/pipeline/dr_backup.py": frozenset(
        {"hashlib", "messagefoundry.store.backup_codec"}
    ),
    # ADR 0073: rendezvous (HRW) outbound-lane ownership for engine shards — sha256 as a STABLE,
    # process-independent hash (the salted builtin hash() differs per process, which would let two
    # shards disagree on a lane's owner). Deterministic placement, not a security control, no secret
    # material involved.
    "messagefoundry/pipeline/sharding.py": frozenset({"hashlib"}),
    # ADR 0087 (#197) — secrets = a fresh 16-byte token_hex per DISPATCH, carried as that call's
    # request id and bound on the way back. This IS a security control: a grandchild the sandboxed
    # Handler spawns inherits fd 1 (the response pipe) and outlives the worker's kill, so a DERIVABLE
    # id (a per-spawn nonce plus a counter) would let the code running one call pre-stage the answer to
    # the next — for an `accepts=` predicate, a routing-verdict flip with no ERROR and no disposition
    # anomaly. Unpredictability is the whole property, hence secrets rather than random.
    "messagefoundry/pipeline/sandbox.py": frozenset({"secrets"}),
    # ADR 0049 (#60): the .mfbak DR-backup archive codec — a chunked AES-256-GCM streaming framing
    # (cryptography AESGCM) keyed by the existing store DEK, with a SHA-256 (hashlib) header digest bound
    # as per-frame AAD + the one-way key_id fingerprint. Net-new crypto surface; the store DEK key source
    # is reused, the cipher mechanism is new.
    "messagefoundry/store/backup_codec.py": frozenset({"hashlib", "cryptography"}),
    # crypto.py also derives the audit-chain HMAC key (#190) via HKDF-SHA256 (cryptography) from the
    # store DEK — no new import (still hashlib + cryptography), an additive key-derivation off the DEK.
    "messagefoundry/store/crypto.py": frozenset({"hashlib", "cryptography"}),
    # ASVS 11.3.4 (#301): the persisted per-key_id AES-GCM invocation bound (cipher_meta table) reads
    # the cipher reserve-block size + AesGcmCipher/Cipher types through the store.crypto seam.
    "messagefoundry/store/gcm_bound.py": frozenset({"messagefoundry.store.crypto"}),
    # ADR 0064: hashlib = the sha256 CONTENT hash of the shipped schema-DDL batch, stored in the
    # schema_meta marker so a current DB's open can skip the batch + the exclusive schema lock.
    # Content addressing / cache invalidation — not a security control, no secret material involved.
    # store.crypto seam (#282) + ASVS 11.2.4 (#301): each backend imports the cipher's
    # MARKER_PREFIX + cell_aad/CipherError to encrypt/decrypt PHI columns through the shared cipher
    # seam (delegated at-rest crypto); hmac = compare_digest ONLY (constant-time comparison of the
    # audit-chain row MAC + the external-anchor head in verify_audit_chain). No key is held/derived
    # here and no digest is COMPUTED here — the digest primitive stays the shared audit_row_hash in
    # store/store.py, so all three backends produce byte-identical chains.
    "messagefoundry/store/postgres.py": frozenset(
        {
            "messagefoundry.config.tls_policy",
            "hashlib",
            "hmac",
            "ssl",
            "messagefoundry.store.crypto",
        }
    ),
    "messagefoundry/store/sqlserver.py": frozenset(
        {"messagefoundry.config.tls_policy", "hashlib", "hmac", "messagefoundry.store.crypto"}
    ),
    # #190: hmac = the keyed HMAC-SHA256 audit-chain digest (audit_row_hash) — tamper-evidence that a
    # row-writer without the store DEK cannot forge; hashlib = the keyless SHA-256 chain + delivery/body
    # digests. The HMAC key is HKDF-derived (in crypto.py) from the DEK. store.crypto seam = the at-rest
    # cipher (MARKER_PREFIX/cell_aad/CipherError) it drives over the PHI columns.
    "messagefoundry/store/store.py": frozenset({"hashlib", "hmac", "messagefoundry.store.crypto"}),
    # ADR 0025: the DICOM C-STORE SCP's server SSLContext (Phase 1) + the C-STORE SCU's client SSLContext
    # (Phase 2) for DICOM-over-TLS (the MLLP inbound/outbound posture).
    "messagefoundry/transports/dicom.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    # ADR 0025 Phase 2: a per-request random multipart boundary (secrets.token_hex) for the DICOMweb
    # STOW-RS body, generated absent from the object bytes (RFC 2046 §5.1.1) — framing, not a secret.
    "messagefoundry/transports/dicomweb.py": frozenset({"secrets"}),
    # ADR 0085: DIRECT-HISP outbound S/MIME — cryptography.serialization.pkcs7 SIGN then ENCRYPT of the
    # Handler body + x509 recipient-cert / trust-anchor cross-validation at construction. No new dependency.
    # #323: ssl = the SMTP/HISP relay's TRANSPORT hop, a separate concern from the S/MIME message
    # layer above. The context is built by tls_policy.build_smtp_tls_context and handed to smtplib,
    # which otherwise defaults to ssl._create_stdlib_context -- which IS _create_unverified_context
    # (CERT_NONE / check_hostname=False). CERT_NONE only under the CLAMPED tls_verify=false escape.
    "messagefoundry/transports/direct.py": frozenset(
        {"messagefoundry.config.tls_policy", "cryptography", "ssl"}
    ),
    # #323: EMAIL outbound STARTTLS (587) / implicit TLS (465). Same factory, same reason as above --
    # an explicit verifying context anchored to the OS roots, a per-connection tls_ca_file, or
    # [tls].internal_ca_file (ADR 0093), because smtplib's own default verifies nothing.
    "messagefoundry/transports/email.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    # ADR 0129 (#142): hashlib = sha256 of a source file's identity (name+mtime+size) as a HASHED dedup
    # key for the leave-in-place processed_files ledger — a DERIVED id, never a cleartext filename (which
    # can embed an MRN), never logged. Not a secret/keyed primitive.
    "messagefoundry/transports/file.py": frozenset({"hashlib"}),
    # ADR 0023: the inbound HTTP/1.1 listen source reuses MLLP's _mllp_ssl_context (server=True) to
    # build its per-connection HTTPS server identity (+ opt-in mTLS) — the same MLLP inbound-TLS posture.
    "messagefoundry/transports/http_listener.py": frozenset({"ssl"}),
    "messagefoundry/transports/mllp.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    # SEC-001 (CWE-295): FTPS (ftplib.FTP_TLS) builds a verifying ssl.create_default_context() for the
    # remote-file connector's TLS control/data channel; CERT_NONE only under the insecure_tls_allowed()
    # escape, mirroring mllp.py's outbound posture. ADR 0129 (#142): hashlib = sha256 of a remote file's
    # name+size as a HASHED dedup key for the leave-in-place processed_files ledger (a derived id, never
    # a cleartext filename).
    "messagefoundry/transports/remotefile.py": frozenset(
        {"messagefoundry.config.tls_policy", "ssl", "hashlib"}
    ),
    "messagefoundry/transports/rest.py": frozenset({"messagefoundry.config.tls_policy", "ssl"}),
    "messagefoundry/transports/signing.py": frozenset({"cryptography"}),
    # ADR 0024: a random `jti` for the SMART Backend Services client_assertion JWT (the JWT signing
    # itself reuses signing.py's `cryptography`).
    "messagefoundry/transports/smart.py": frozenset(
        {"messagefoundry.config.tls_policy", "secrets"}
    ),
    "messagefoundry/transports/soap.py": frozenset(
        {"messagefoundry.config.tls_policy", "hashlib", "ssl"}
    ),
    # ADR 0113 (2026-07-22 amendment): the tray's TOKENLESS /health + /ui probes must verify the
    # engine's server cert when [api].tls_cert_file makes the loopback bind serve https. Builds the
    # same OS-trust-store context the engine client uses (truststore.SSLContext, lazily imported) —
    # https only, no pinned-PEM option, and no verify=False escape at all (the tray holds no
    # credential to protect, but an unverified probe could not tell the engine from an impostor).
    # truststore (a CRYPTO_LIBRARY_MODULES trigger) supplies that OS-trust-store context.
    "messagefoundry/tray/probe.py": frozenset({"ssl", "truststore"}),
    # ADR 0134 (#125/#126): secrets = the random 32-hex uploaded-file id (secrets.token_hex, the
    # path-traversal-safe on-disk identity + tmp-file suffix); hashlib = sha256 of an uploaded file's
    # bytes (integrity/dedup metadata). Body encryption at rest rides the store cipher — the
    # store.crypto seam (Cipher, cell_aad) it imports directly, now a first-class inventory token.
    "messagefoundry/uploads.py": frozenset({"hashlib", "secrets", "messagefoundry.store.crypto"}),
    # --- BACKLOG #282: modules the seam / library / non-messagefoundry-root widening newly surfaces ---
    # The CLI (gen-key / rotate-key / serve): mints the store DEK (store.crypto.generate_key),
    # gates a keyless PHI start, and surfaces KeyProviderError — all delegated through the store seams,
    # with zero direct stdlib-crypto import in the module.
    "messagefoundry/__main__.py": frozenset(
        {
            "messagefoundry.config.tls_policy",
            "messagefoundry.store.crypto",
            "messagefoundry.store.keyprovider",
        }
    ),
    # ADR 0019 §5: the `vault` connector-secret provider does a Vault KV v2 read of a connector
    # credential (AD bind / SMTP password) over hvac, fail-closed, value never logged — the delegated
    # transport/crypto is hvac's (behind the optional [vault] extra, lazy-imported).
    "messagefoundry/config/secretprovider_vault.py": frozenset({"hvac"}),
    # BACKLOG #31: the lazy [xml]-extra loader for signxml (which pulls cryptography for the XML-DSig
    # digest/signature primitives). The sibling parsing/xml/signature.py hashlib anchor already
    # documents the DSig primitives; this loader is where the signxml dependency actually enters.
    "messagefoundry/parsing/xml/_deps.py": frozenset({"signxml"}),
    # ADR 0019 / 0138: build_store_cipher — the cipher + key-provider FACTORY. Resolves the in-process
    # aesgcm cipher (store.crypto) or the Vault-Transit cipher (store.crypto_transit, function-local)
    # and the key provider (store.keyprovider); every primitive is delegated through the seams.
    "messagefoundry/store/base.py": frozenset(
        {
            "messagefoundry.config.tls_policy",
            "messagefoundry.store.crypto",
            "messagefoundry.store.crypto_transit",
            "messagefoundry.store.keyprovider",
        }
    ),
    # ADR 0138: TransitCipher — every at-rest AEAD op AND the audit-chain MAC run INSIDE Vault Transit
    # over the hvac seam (reached via keyprovider_vault._build_client), reusing store.crypto's markers /
    # AuditMacFn / CipherError and keyprovider's errors. It imports NONE of the six stdlib crypto
    # modules, so the seam trigger is what makes this all-delegated at-rest crypto site visible at all
    # (the plaintext DEK never enters engine heap — ASVS 13.3.3). This is #282's canonical target.
    "messagefoundry/store/crypto_transit.py": frozenset(
        {
            "messagefoundry.store.crypto",
            "messagefoundry.store.keyprovider",
            "messagefoundry.store.keyprovider_vault",
        }
    ),
    # ADR 0019: the Vault Transit KeyProvider envelope-unwraps the store DEK INSIDE Vault over hvac
    # (fail-closed; key material never logged), reusing store.keyprovider's errors + retired-key split.
    "messagefoundry/store/keyprovider_vault.py": frozenset(
        {"hvac", "messagefoundry.store.keyprovider"}
    ),
    # --- non-messagefoundry roots (#283's _CRYPTO_SITES_OUTSIDE_THE_PACKAGE, now walked by this gate) ---
    # ASVS 3.4.7/3.4.8: mints the per-response CSP script nonce (secrets) stamped into <script> for the
    # effective-https /ui nonce-CSP. A single-use per-response nonce, not a stored key.
    "messagefoundry_webconsole/_security.py": frozenset({"secrets"}),
    # The standalone tee CLI builds the ssl context (create_default_context, or a cafile via --cacert;
    # CERT_NONE only under the explicit --insecure escape) for the tee's https engine-API pulls.
    "tee/__main__.py": frozenset({"ssl"}),
    # ADR 0030: the byte-identical vendored twin of messagefoundry/anon/keying.py — keyed BLAKE2b
    # (hashlib) derives the deterministic, per-dataset, one-way pseudonymization seed. Kept in lockstep
    # with the engine copy by the parity test.
    "tee/anon/keying.py": frozenset({"hashlib"}),
    # #14: the tee's stdlib MEFOR engine-API client accepts an optional ssl.SSLContext for authenticated
    # GETs against an https engine (the tee stays stdlib-only; no mTLS / rich-retry client).
    "tee/mefor_api.py": frozenset({"ssl"}),
    # ADR 0155: the DAST scan target generates a THROWAWAY per-run password (secrets.token_urlsafe) for
    # the two ephemeral scan identities it provisions into a store it creates empty in a temp directory
    # and destroys with it. Not a key and never persisted: a checked-in constant would be strictly
    # weaker, and the alternative — an operator-supplied credential — is the optional escape hatch only.
    # ADR 0156: SHA-256 over the OWASP ASVS corpus FILE, to pin it to the tagged v5.0.0_release
    # asset. Integrity of a build input, not a security control: no secret, no key, no message
    # authentication, and nothing user- or PHI-derived is hashed. It exists because the corpus was
    # originally fetched from `master` (the bleeding-edge branch, where a rolling "latest" release
    # republishes identical filenames) and happened to match the release by luck — so the digest is
    # recorded and recomputed rather than assumed. Non-cryptographic alternatives were rejected only
    # because SHA-256 is already the tree's convention for file pinning.
    "scripts/asvs/scorecard.py": frozenset({"hashlib"}),
    # Same class as the line above, registered for the same reason: SHA-256 over the SCORECARD FILE,
    # printed truncated so a run states WHICH revision of the record it read. Two runs reporting
    # different counts are otherwise indistinguishable from one run whose input changed underneath
    # it. No secret, no key, no message authentication, nothing user- or PHI-derived — the digest is
    # an identifier in a log line. It covers the record itself rather than a build input, which is
    # the only way it differs from the entry above.
    "scripts/asvs/prove_report.py": frozenset({"hashlib"}),
    # BACKLOG #1405, the SAME class again: SHA-256 over the SCORECARD FILE, truncated into the anchor
    # report's header so a run states WHICH revision of the record it read. A digest rather than a
    # commit ref because the record lives in a DIFFERENT repository, so a ref printed here names a
    # commit the reader cannot resolve from this one. No secret, no key, no message authentication,
    # nothing user- or PHI-derived: it is an identifier in a log line.
    "scripts/asvs/anchor_report.py": frozenset({"hashlib"}),
    "scripts/security/dast_target.py": frozenset({"secrets"}),
    # BACKLOG #1220: SHA-256 over the DISCOVERED engine/console seam surface, truncated to 16 hex
    # characters, to give ENGINE_UI_SEAM an identity nobody chooses by hand. A CHANGE DETECTOR, not a
    # security control: no secret, no key, no message authentication, and nothing user- or PHI-derived
    # is hashed -- the input is a serialization of public type signatures and field names. What it
    # needs is accidental-collision avoidance across the distinct contract surfaces this project will
    # ever produce, and 64 bits gives 2.7e-12 at 10,000 surfaces (about 500x the ~20 seam moves to
    # date). Preimage resistance buys nothing here: anyone who could craft a colliding surface already
    # has commit access to _ui_seam.py, where writing the constant directly is strictly easier.
    # SHA-256 rather than BLAKE2 or a non-approved digest only because the engine renders a fips_mode
    # attestation, and a non-approved hash in the shipped surface invites a FIPS question for no gain.
    "scripts/webconsole_seam_snapshot.py": frozenset({"hashlib"}),
    # BACKLOG #1323 -- ELEVEN SITES THE GATE COULD NOT SEE AT ALL until the TLS-policy seam was
    # added above. Each imports messagefoundry.config.tls_policy and NONE of the six stdlib crypto
    # modules, so before the seam widened there was no token that could match them and no row was
    # owed. THE SHARED REASON, stated once because it IS shared: each resolves a TLS posture through
    # the common helper instead of building an SSLContext by hand -- which is the point of the seam,
    # and centralising it is why these files import no `ssl`. Where a file's usage is not merely that,
    # it carries its own line below.
    "messagefoundry/api/app.py": frozenset({"messagefoundry.config.tls_policy"}),
    "messagefoundry/api/security.py": frozenset({"messagefoundry.config.tls_policy"}),
    # reach the seam to parse and bound it rather than to open a connection.
    "messagefoundry/config/models.py": frozenset({"messagefoundry.config.tls_policy"}),
    # settings/models are where the operator's TLS posture is DECLARED and validated, so they
    "messagefoundry/config/settings.py": frozenset({"messagefoundry.config.tls_policy"}),
    # alert_sinks also imports smtplib: the alert SMTP hop's STARTTLS posture. This is the file
    # BACKLOG #1323 named as the worked example of a seam the store-only set could not match.
    "messagefoundry/pipeline/alert_sinks.py": frozenset({"messagefoundry.config.tls_policy"}),
    "messagefoundry/pipeline/engine.py": frozenset({"messagefoundry.config.tls_policy"}),
    "messagefoundry/pipeline/security_notify.py": frozenset({"messagefoundry.config.tls_policy"}),
    "messagefoundry/pipeline/wiring_runner.py": frozenset({"messagefoundry.config.tls_policy"}),
    "messagefoundry/transports/ai_broker.py": frozenset({"messagefoundry.config.tls_policy"}),
    "messagefoundry/transports/database.py": frozenset({"messagefoundry.config.tls_policy"}),
    "messagefoundry/transports/http_auth.py": frozenset({"messagefoundry.config.tls_policy"}),
}


def crypto_imports_in(source: str) -> set[str]:
    """The crypto trigger tokens imported anywhere in a module (including function-local imports).

    A token is a six-stdlib / third-party-library top-level name (:data:`_TOPLEVEL_TRIGGERS`) or a
    fully-qualified first-party seam path (:data:`CRYPTO_SEAM_MODULES`). Only top-level (``level ==
    0``) ``from`` imports are resolved — the seams have no in-package relative importers today, and
    the six-module scan has always been ``level``-0 only."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in _TOPLEVEL_TRIGGERS:
                    found.add(alias.name.split(".", 1)[0])
                if alias.name in CRYPTO_SEAM_MODULES:  # import messagefoundry.store.crypto[ as _]
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if node.module.split(".", 1)[0] in _TOPLEVEL_TRIGGERS:
                found.add(node.module.split(".", 1)[0])
            if node.module in CRYPTO_SEAM_MODULES:  # from messagefoundry.store.crypto import X
                found.add(node.module)
            else:  # from messagefoundry.store import crypto
                for alias in node.names:
                    if f"{node.module}.{alias.name}" in CRYPTO_SEAM_MODULES:
                        found.add(f"{node.module}.{alias.name}")
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
    noun: str = "crypto",
    stale_verb: str = "imports",
) -> tuple[list[str], list[str]]:
    """Return ``(undocumented, stale)`` message lists. ``undocumented`` = a file uses a crypto module
    not recorded for it (the security-relevant direction). ``stale`` = an inventory entry the file no
    longer backs (kept honest only when scanning the real package).

    ``noun``/``stale_verb`` only reword the messages so the non-Python randomness arm can reuse this
    diff verbatim rather than growing a second, silently different one. The defaults reproduce the
    Python arm's wording byte-for-byte."""
    undocumented: list[str] = []
    for path, mods in sorted(actual.items()):
        extra = mods - inventory.get(path, frozenset())
        if extra:
            documented = sorted(inventory.get(path, frozenset())) or "(file not in inventory)"
            undocumented.append(
                f"{path}: undocumented {noun} use {sorted(extra)} (documented: {documented})"
            )
    stale: list[str] = []
    if check_stale:
        for path, mods in sorted(inventory.items()):
            gone = mods - actual.get(path, frozenset())
            if gone:
                stale.append(
                    f"{path}: inventory lists {sorted(gone)} but the file no longer {stale_verb} it"
                )
    return undocumented, stale


def _is_comment_only(line: str) -> bool:
    """True for a line that is nothing but a ``//`` or block-comment line.

    DELIBERATELY CONSERVATIVE, and the direction matters. A code line carrying a TRAILING comment is
    still scanned in full, so a call cannot be hidden by putting a ``//`` earlier on the same line;
    the cost is that a line beginning with ``*`` for some non-comment reason is skipped. The error
    this can make is a false POSITIVE (flagging a call quoted inside a string), never a false
    negative, which is the only safe direction for a security gate. Stripping comments properly would
    need a JS lexer, and a naive strip would cut a line at the ``//`` of a URL and hide what follows.

    The shipped extension test ``ide/src/test/suite/extension-hardening.test.ts`` uses the same rule
    for the same reason: ``cspNonce.ts`` NAMES ``Math.random`` in prose to explain why it is unusable.
    """
    stripped = line.lstrip()
    return stripped.startswith(("//", "*", "/*"))


def randomness_tokens_in(text: str) -> set[str]:
    """The randomness-source tokens (strong and weak) a non-Python source draws from."""
    found: set[str] = set()
    patterns = {**STRONG_RANDOMNESS_PATTERNS, **WEAK_RANDOMNESS_PATTERNS}
    for line in text.splitlines():
        if _is_comment_only(line):
            continue
        for token, pattern in patterns.items():
            if token not in found and pattern.search(line):
                found.add(token)
    return found


def non_python_sources(root: Path) -> list[Path]:
    """Every first-party non-Python source under ``root``, dependency and build trees pruned."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in root.walk():
        dirnames[:] = [d for d in dirnames if d not in NON_PYTHON_SKIP_DIRS]
        out.extend(dirpath / name for name in filenames if name.endswith(NON_PYTHON_SUFFIXES))
    return sorted(out)


def discover_non_python(root: Path, *, repo: Path) -> dict[str, frozenset[str]]:
    """Map repo-relative path -> randomness tokens, for the files that draw randomness at all."""
    out: dict[str, frozenset[str]] = {}
    for path in non_python_sources(root):
        tokens = randomness_tokens_in(path.read_text(encoding="utf-8"))
        if tokens:
            out[path.relative_to(repo).as_posix()] = frozenset(tokens)
    return out


def check_non_python_randomness(repo: Path) -> tuple[list[str], int]:
    """Run the non-Python randomness arm. Returns ``(violation lines, files scanned)``.

    The file count is returned so the caller can PRINT what was scanned. An instrument that reports
    "clean" without saying what it read is indistinguishable from one that read nothing, which is the
    failure this arm exists to close for ASVS 11.5.1."""
    violations: list[str] = []
    actual: dict[str, frozenset[str]] = {}
    scanned = 0

    for name in NON_PYTHON_WALK_ROOTS:
        root = repo / name
        if not root.is_dir():
            violations.append(
                f"randomness arm: declared walk root {name}/ is not a directory under {repo} - the "
                "scan cannot report clean on a corpus it never reached"
            )
            continue
        files = non_python_sources(root)
        if not files:
            violations.append(
                f"randomness arm: the walk over {name}/ reached ZERO "
                f"{'/'.join(NON_PYTHON_SUFFIXES)} files, so a clean result would be VACUOUS. Either "
                "the sources moved, the suffix list is wrong, or the pruned-directory list now eats "
                "the corpus. Fix the walk; do not read this as a clean tree"
            )
            continue
        scanned += len(files)
        actual |= discover_non_python(root, repo=repo)

    weak_tokens = set(WEAK_RANDOMNESS_PATTERNS)
    for path, tokens in sorted(actual.items()):
        weak = sorted(tokens & weak_tokens)
        if weak:
            violations.append(
                f"{path}: WEAK randomness source {weak} in shipped non-Python source. There is no "
                "inventory row for this and adding one is refused: ASVS 11.5.1 states an entropy "
                "floor on the VALUE, and hiding the hit is the disqualified pass BACKLOG #1172 names."
                " Draw from node:crypto instead - ide/src/cspNonce.ts is the worked example"
            )

    strong_actual = {
        path: frozenset(tokens - weak_tokens)
        for path, tokens in actual.items()
        if tokens - weak_tokens
    }
    undocumented, stale = find_violations(
        strong_actual,
        NON_PYTHON_INVENTORY,
        check_stale=True,
        noun="randomness",
        stale_verb="draws from",
    )
    violations.extend(undocumented)
    violations.extend(stale)
    return violations, scanned


def _assert_ide_is_typescript(repo: Path) -> list[str]:
    """``ide/`` is outside the PYTHON walk because it is TypeScript with zero ``.py`` files. Enforce
    that fact so a future ``.py`` there reds the gate (and forces a WALK_ROOTS + inventory update)
    rather than silently escaping the crypto scan. Returns violation message lines (empty = OK).

    Still needed after the non-Python arm landed, and for a different reason than before: that arm
    reads ``.ts``/``.js``, so a ``.py`` under ``ide/`` would fall between the two walks rather than
    merely outside one. This is the guard that catches it."""
    ide = repo / "ide"
    if not ide.is_dir():
        return []
    stray = [
        p.relative_to(repo).as_posix()
        for p in sorted(ide.rglob("*.py"))
        if "__pycache__" not in p.parts
    ]
    if not stray:
        return []
    return [
        f"ide/ is documented as TypeScript-only (excluded from WALK_ROOTS) but now has {len(stray)} "
        f".py file(s): {stray} — add ide/ to WALK_ROOTS and inventory the crypto site(s), or move them"
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cryptographic-discovery gate (ASVS 11.1.3).")
    parser.add_argument(
        "--package",
        type=Path,
        default=None,
        help="single package directory to scan (default: the five real WALK_ROOTS + built-in inventory)",
    )
    args = parser.parse_args(argv)

    scanning_default = args.package is None
    actual: dict[str, frozenset[str]] = {}
    ide_violations: list[str] = []
    randomness_violations: list[str] = []
    randomness_scanned = 0
    if scanning_default:
        repo = Path(__file__).resolve().parents[2]
        roots = [repo / name for name in WALK_ROOTS]
        missing = [r for r in roots if not r.is_dir()]
        if missing:
            print(f"crypto-inventory: walk root(s) not found: {missing}", file=sys.stderr)
            return 2
        for root in roots:
            actual |= discover(root)
        ide_violations = _assert_ide_is_typescript(repo)
        randomness_violations, randomness_scanned = check_non_python_randomness(repo)
    else:
        package = args.package
        if not package.is_dir():
            print(f"crypto-inventory: package not found: {package}", file=sys.stderr)
            return 2
        actual = discover(package)

    undocumented, stale = find_violations(actual, INVENTORY, check_stale=scanning_default)

    if ide_violations:
        print("crypto-inventory: ide/ TypeScript-only invariant VIOLATED:")
        for line in ide_violations:
            print(f"  - {line}")
    if undocumented:
        print("crypto-inventory: UNDOCUMENTED crypto usage (add it to INVENTORY + ASVS §4):")
        for line in undocumented:
            print(f"  - {line}")
    if stale:
        print("crypto-inventory: STALE inventory entries (remove them from INVENTORY):")
        for line in stale:
            print(f"  - {line}")
    if randomness_violations:
        print("crypto-inventory: NON-PYTHON RANDOMNESS arm (ASVS 11.5.1, BACKLOG #1172) FAILED:")
        for line in randomness_violations:
            print(f"  - {line}")
    if undocumented or stale or ide_violations or randomness_violations:
        return 1

    # Print the corpus, not just the verdict: "clean" means nothing without what was read.
    print(
        f"crypto-inventory: OK - {len(actual)} documented crypto call site(s) across "
        f"{len(WALK_ROOTS)} Python root(s), no drift; "
        f"{randomness_scanned} non-Python source(s) scanned for randomness across "
        f"{len(NON_PYTHON_WALK_ROOTS)} root(s), no weak source and no inventory drift."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
