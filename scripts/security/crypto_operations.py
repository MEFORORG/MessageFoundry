# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1164 (ASVS 11.1.3): OPERATION-granular crypto discovery for the Python tree.

``crypto_inventory_check.py`` discovers crypto by IMPORT: a module is a crypto site when it imports a
trigger. That cannot see a new operation inside a module that is already registered, and it cannot
see a module that reaches crypto through a first-party helper it happens not to import from a
registered seam. This module is the finer instrument the gate now runs beside the import arm.

What it does, in order:

1. Parse every ``.py`` file under the walk roots and resolve each call's callee to a fully qualified
   name through that module's imports (absolute, relative, aliased and function-local).
2. Classify a call as a crypto OPERATION when its qualified callee, or for a method call its method
   name, is in the taxonomy below. The result is keyed ``path:line -> operation class``.
3. Follow first-party helpers. A module-level function that performs an operation, directly or
   through another such function, is a PROVIDER (the spread rule is stated where it is computed, in
   :func:`discover_operations_in`). A call to a provider from a DIFFERENT module is itself an
   operation site in the caller, of the provider's classes. That is what makes
   ``pipeline/alert_sinks.py`` visible through ``build_smtp_tls_context`` with no crypto import and
   no registered seam, and it needs no seam list: a NEW helper is followed the day it is written.

WHAT THIS DOES NOT SEE, so any clean result reads "at least", never "all":

* a method called on a first-party OBJECT (``self._cipher.encrypt_cell(...)``) unless its method name
  is in :data:`METHOD_RULES`. There is no type inference, so a first-party class is followed only
  through its module-level functions;
* a chain that leaves the crypto modules for more than one call. The spread rule stops there on
  purpose, to keep the noise down, and a crypto use at the far end of a longer chain is not reported
  at the caller;
* a call made through ``getattr``, ``importlib`` or any other dynamic dispatch, or in a subprocess;
* a crypto DECISION that is not a call or a TLS-attribute assignment. ``transports/database.py``
  appends ``Encrypt=`` and ``TrustServerCertificate=`` to a DSN string: a first-party TLS posture
  decision with no crypto-shaped expression for any pattern instrument to match;
* crypto inside a third-party library the engine calls. The call is seen; the library's own
  operations are not.

Stdlib only, like the gate that imports it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

#: The operation taxonomy, in the ASVS 11.1.3 verb's own vocabulary plus the two classes a real
#: inventory of this tree needs that the verb does not spell out (constant-time comparison, and
#: key or certificate handling). Every rule below maps to exactly one of these.
OPERATION_CLASSES: dict[str, str] = {
    "cipher": "encrypt or decrypt: AEAD, S/MIME envelope, Vault Transit",
    "hash": "a cryptographic hash computed over data",
    "mac": "a message authentication code computed over data",
    "compare": "a constant-time comparison of digests, MACs or secrets",
    "sign_verify": "a digital signature made or checked",
    "kdf": "key derivation or password hashing",
    "csprng": "a draw from a cryptographically secure random source",
    "tls_context": "a TLS context built, or a TLS posture set on one",
    "key_cert": "a key generated, or a key or certificate loaded or parsed",
}

#: Exact qualified callees. Checked before :data:`PREFIX_RULES`.
EXACT_RULES: dict[str, str] = {
    # hash
    "hashlib.new": "hash",
    "hashlib.file_digest": "hash",
    "cryptography.hazmat.primitives.hashes.Hash": "hash",
    # kdf (these two live in hashlib but derive keys)
    "hashlib.pbkdf2_hmac": "kdf",
    "hashlib.scrypt": "kdf",
    "argon2.PasswordHasher": "kdf",
    # mac
    "hmac.new": "mac",
    "hmac.digest": "mac",
    "hmac.HMAC": "mac",
    "cryptography.hazmat.primitives.hmac.HMAC": "mac",
    # compare
    "hmac.compare_digest": "compare",
    "secrets.compare_digest": "compare",
    # csprng
    "os.urandom": "csprng",
    "os.getrandom": "csprng",
    "random.SystemRandom": "csprng",
    # tls_context
    "ssl.create_default_context": "tls_context",
    "ssl.SSLContext": "tls_context",
    "ssl._create_unverified_context": "tls_context",
    "ssl._create_default_https_context": "tls_context",
    "truststore.SSLContext": "tls_context",
    "ssl.get_server_certificate": "tls_context",
    # key_cert
    "ssl.cert_time_to_seconds": "key_cert",
    "ssl.DER_cert_to_PEM_cert": "key_cert",
    "ssl.PEM_cert_to_DER_cert": "key_cert",
    # sign_verify: library ceremonies whose primitive lives in the library
    "webauthn.verify_registration_response": "sign_verify",
    "webauthn.verify_authentication_response": "sign_verify",
    "signxml.XMLSigner": "sign_verify",
    "signxml.XMLVerifier": "sign_verify",
    "cryptography.hazmat.primitives.serialization.pkcs7.PKCS7SignatureBuilder": "sign_verify",
    "cryptography.hazmat.primitives.serialization.pkcs7.load_pem_pkcs7_certificates": "key_cert",
    "cryptography.hazmat.primitives.serialization.pkcs7.load_der_pkcs7_certificates": "key_cert",
    "cryptography.hazmat.primitives.serialization.pkcs7.PKCS7EnvelopeBuilder": "cipher",
    "cryptography.hazmat.primitives.serialization.pkcs7.pkcs7_decrypt_der": "cipher",
    "cryptography.hazmat.primitives.serialization.pkcs7.pkcs7_decrypt_pem": "cipher",
    "cryptography.hazmat.primitives.serialization.pkcs7.pkcs7_decrypt_smime": "cipher",
    # cipher: the key-generation classmethods on AEAD classes are key generation, not encryption,
    # and must win over the aead prefix rule below.
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM.generate_key": "key_cert",
    "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.generate_key": "key_cert",
    "cryptography.fernet.Fernet.generate_key": "key_cert",
}

#: Qualified-name PREFIXES, longest match wins. A prefix ends in ``.`` so ``hashlib.`` cannot match
#: a module that merely starts with the same letters.
PREFIX_RULES: dict[str, str] = {
    "hashlib.": "hash",  # sha256, sha1, md5, blake2b, sha3_*, ...
    "secrets.": "csprng",  # token_bytes, token_hex, token_urlsafe, choice, randbelow, randbits
    "cryptography.hazmat.primitives.kdf.": "kdf",
    "argon2.low_level.": "kdf",  # hash_secret, hash_secret_raw, verify_secret
    "cryptography.hazmat.primitives.ciphers.": "cipher",
    "cryptography.fernet.": "cipher",
    "cryptography.x509.": "key_cert",
    "cryptography.hazmat.primitives.serialization.": "key_cert",
    "cryptography.hazmat.primitives.asymmetric.": "key_cert",
}

#: Qualified callees that match a rule above but are NOT operations. Each needs a reason. This is
#: the documented noise allow-list: an entry here is a claim a reviewer can check, not a silencer.
NOT_OPERATIONS: dict[str, str] = {
    "cryptography.x509.NameAttribute": "a name component for a certificate being built, no crypto",
    "cryptography.x509.Name": "a distinguished-name value object, no crypto",
    "cryptography.x509.DNSName": "a SAN value object, no crypto",
    "cryptography.x509.IPAddress": "a SAN value object, no crypto",
    "cryptography.x509.SubjectAlternativeName": "an extension value object, no crypto",
    "cryptography.x509.BasicConstraints": "an extension value object, no crypto",
    "cryptography.x509.KeyUsage": "an extension value object, no crypto",
    "cryptography.x509.ExtendedKeyUsage": "an extension value object, no crypto",
    "cryptography.hazmat.primitives.serialization.NoEncryption": (
        "an encoding option passed to a key serializer; the serializer call is the operation"
    ),
    "cryptography.hazmat.primitives.serialization.BestAvailableEncryption": (
        "an encoding option passed to a key serializer; the serializer call is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.padding.PSS": (
        "a padding PARAMETER object passed to sign or verify; that call is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15": (
        "a padding PARAMETER object passed to sign or verify; that call is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.padding.MGF1": (
        "a padding PARAMETER object passed to sign or verify; that call is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.ec.SECP256R1": (
        "a curve PARAMETER object; the key generation or load it is passed to is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.ec.SECP384R1": (
        "a curve PARAMETER object; the key generation or load it is passed to is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.ec.SECP521R1": (
        "a curve PARAMETER object; the key generation or load it is passed to is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.ec.ECDSA": (
        "an algorithm PARAMETER object passed to sign or verify; that call is the operation"
    ),
    "cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature": (
        "re-encodes an existing signature's DER into (r, s); no key, no verification"
    ),
    "cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature": (
        "re-encodes (r, s) into DER; no key, no signing"
    ),
    "cryptography.hazmat.primitives.ciphers.aead.InvalidTag": "an exception type, raised not run",
}

#: Method names that are crypto operations whatever the receiver. Kept to names that are specific
#: enough that a hit on a non-crypto object would itself be worth a look. ``update``, ``digest``
#: and ``hexdigest`` are deliberately absent: they follow a hash object the rules above already
#: counted where it was made, and ``update`` would match every ``dict.update`` in the tree.
METHOD_RULES: dict[str, str] = {
    "encrypt": "cipher",
    "decrypt": "cipher",
    "encrypt_data": "cipher",  # hvac Vault Transit
    "decrypt_data": "cipher",  # hvac Vault Transit
    "rewrap_data": "cipher",  # hvac Vault Transit
    "sign": "sign_verify",
    "verify": "sign_verify",
    "sign_data": "sign_verify",  # hvac Vault Transit
    "verify_signed_data": "sign_verify",  # hvac Vault Transit
    "generate_hmac": "mac",  # hvac Vault Transit
    "derive": "kdf",
    "load_cert_chain": "tls_context",
    "load_verify_locations": "tls_context",
    "load_default_certs": "tls_context",
    "set_default_verify_paths": "tls_context",
    "set_ciphers": "tls_context",
    "set_ecdh_curve": "tls_context",
    "wrap_socket": "tls_context",
    "wrap_bio": "tls_context",
    "private_bytes": "key_cert",
    "public_bytes": "key_cert",
    "public_key": "key_cert",
}

#: Method-rule hits that the receiver-blind rule gets WRONG, keyed ``(repo-relative path, method
#: name)``. The value is the corrected class, or ``None`` when the call is not an operation at all,
#: and then the reason. A method rule cannot see its receiver, so this is where a reviewer who can
#: records what the receiver is.
METHOD_OVERRIDES: dict[tuple[str, str], tuple[str | None, str]] = {
    ("messagefoundry/auth/passwords.py", "verify"): (
        "kdf",
        "argon2 PasswordHasher.verify: re-derives the password hash to compare, not a signature",
    ),
}

#: First-party providers whose CALLERS are not operation sites. The operation is still counted once,
#: where the provider performs it. An entry needs a reason, and the test it has to pass is the same
#: one the gate applies to a pass-through TLS context: does the CALLER decide anything about the
#: crypto? A caller that establishes a TLS hop, hashes a secret or checks a signature does, and is
#: never opaque. A caller that asks for a log-safe label and gets a digest back as an implementation
#: detail does not, and counting it would add one "hash" per log line to every module that logs.
OPAQUE_PROVIDERS: dict[str, str] = {
    "messagefoundry.redaction.safe_name": (
        "a log-safe label for a partner-chosen file name; the SHA-256 inside it is an identifier "
        "derivation counted once in redaction.py, and its callers (with safe_exc's, about 160) are "
        "logging and error reporting, not hashing"
    ),
    "messagefoundry.config.wiring._exec_module": (
        "names a loaded config module after a SHA-256 of its resolved path, so two same-stem files "
        "cannot collide in sys.modules; naming, and no caller of the loader decides anything by it"
    ),
    "messagefoundry.pipeline.sharding.owner_shard_of_destination": (
        "rendezvous placement uses SHA-256 as a restart-stable hash with no secret; a caller picks "
        "which engine shard owns a destination, not a crypto property"
    ),
}

#: Assigning one of these attributes on any object sets a TLS posture on a context. The object is
#: not type-checked, so the names are chosen to be specific to ``ssl.SSLContext``.
TLS_POSTURE_ATTRIBUTES = frozenset(
    {"minimum_version", "maximum_version", "verify_mode", "check_hostname", "verify_flags"}
)


#: Top-level package names whose calls are resolved as first-party (followed by provider
#: propagation rather than guessed at by a method-name rule).
_FIRST_PARTY = tuple(
    f"{root}."
    for root in ("messagefoundry", "messagefoundry_webconsole", "harness", "tee", "scripts")
)


@dataclass(frozen=True, order=True)
class Operation:
    """One crypto operation at one line. ``via`` names the first-party provider it crossed, if any."""

    path: str
    line: int
    op_class: str
    callee: str
    via: str | None = None

    def render(self) -> str:
        how = f" via {self.via}" if self.via else ""
        return f"{self.path}:{self.line} -> {self.op_class} ({self.callee}{how})"


def module_name(relpath: str) -> str:
    """Dotted module name for a repo-relative file: ``a/b/c.py`` -> ``a.b.c``."""
    parts = relpath.removesuffix(".py").split("/")
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _package_of(mod: str, is_init: bool) -> str:
    return mod if is_init else mod.rpartition(".")[0]


def _resolve_relative(mod: str, is_init: bool, level: int, target: str | None) -> str:
    base = _package_of(mod, is_init)
    for _ in range(level - 1):
        base = base.rpartition(".")[0]
    if target:
        return f"{base}.{target}" if base else target
    return base


def import_aliases(tree: ast.Module, mod: str, is_init: bool) -> dict[str, str]:
    """Local name -> fully qualified target, for every import anywhere in the module.

    Function-local imports are included and scoping is ignored: a name bound by an import anywhere
    in the file resolves the same way everywhere in it. That can over-resolve a shadowed name, which
    errs toward reporting an operation, never toward hiding one."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".", 1)[0]
                    aliases.setdefault(head, head)
        elif isinstance(node, ast.ImportFrom):
            source = (
                _resolve_relative(mod, is_init, node.level, node.module)
                if node.level
                else (node.module or "")
            )
            for alias in node.names:
                if alias.name == "*":
                    continue
                aliases[alias.asname or alias.name] = f"{source}.{alias.name}"
    return aliases


def dotted(expr: ast.expr, aliases: dict[str, str], mod: str, local_defs: set[str]) -> str | None:
    """The qualified name an expression refers to, or ``None`` when it cannot be resolved."""
    if isinstance(expr, ast.Name):
        if expr.id in aliases:
            return aliases[expr.id]
        if expr.id in local_defs:
            return f"{mod}.{expr.id}"
        return None
    if isinstance(expr, ast.Attribute):
        base = dotted(expr.value, aliases, mod, local_defs)
        return f"{base}.{expr.attr}" if base else None
    return None


def classify_qualified(name: str) -> str | None:
    """The operation class of a qualified callee, or ``None`` when it is not a crypto operation."""
    if name in NOT_OPERATIONS:
        return None
    if name in EXACT_RULES:
        return EXACT_RULES[name]
    best = ""
    for prefix in PREFIX_RULES:
        if name.startswith(prefix) and len(prefix) > len(best):
            best = prefix
    return PREFIX_RULES[best] if best else None


@dataclass
class _Module:
    path: str
    mod: str
    tree: ast.Module
    aliases: dict[str, str]
    local_defs: set[str]


def _parse(relpath: str, source: str) -> _Module:
    tree = ast.parse(source)
    mod = module_name(relpath)
    is_init = relpath.endswith("__init__.py")
    local_defs = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    return _Module(
        path=relpath,
        mod=mod,
        tree=tree,
        aliases=import_aliases(tree, mod, is_init),
        local_defs=local_defs,
    )


def _enclosing_functions(tree: ast.Module) -> dict[int, str]:
    """``id(node) -> top-level function name`` for every node inside a module-level function."""
    owner: dict[int, str] = {}
    for top in tree.body:
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(top):
                owner[id(node)] = top.name
    return owner


def _resolve_reexport(name: str, reexports: dict[str, str]) -> str:
    """Follow ``pkg.name -> real.target`` re-export links, so a call through a package ``__init__``
    lands on the function that is actually defined. Bounded, so a cycle cannot hang the gate."""
    for _ in range(8):
        target = reexports.get(name)
        if target is None or target == name:
            return name
        name = target
    return name


def _direct_operations(m: _Module) -> list[tuple[ast.AST, int, str, str]]:
    """``(node, line, class, callee)`` for every direct operation in one module."""
    found: list[tuple[ast.AST, int, str, str]] = []
    for node in ast.walk(m.tree):
        if isinstance(node, ast.Call):
            qualified = dotted(node.func, m.aliases, m.mod, m.local_defs)
            if qualified is not None:
                op = classify_qualified(qualified)
                if op is not None:
                    found.append((node, node.lineno, op, qualified))
                    continue
            if isinstance(node.func, ast.Attribute) and node.func.attr in METHOD_RULES:
                if qualified is not None and qualified.startswith(_FIRST_PARTY):
                    # A resolvable first-party call is handled by provider propagation, which knows
                    # whether the target really performs crypto; a method-name guess would not.
                    continue
                op_class: str | None = METHOD_RULES[node.func.attr]
                override = METHOD_OVERRIDES.get((m.path, node.func.attr))
                if override is not None:
                    op_class = override[0]
                if op_class is not None:
                    found.append((node, node.lineno, op_class, f".{node.func.attr}()"))
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr in TLS_POSTURE_ATTRIBUTES:
                    found.append((node, node.lineno, "tls_context", f".{target.attr} ="))
    return found


def discover_operations(files: list[Path], repo: Path) -> list[Operation]:
    """Every crypto operation site in ``files``, direct or through a first-party provider."""
    return discover_operations_in(
        {path.relative_to(repo).as_posix(): path.read_text(encoding="utf-8") for path in files}
    )


def discover_operations_in(sources: dict[str, str]) -> list[Operation]:
    """:func:`discover_operations` over ``repo-relative path -> source text``, so the gate's own
    positive control can run the SAME instrument over a fixture that never touches the disk."""
    modules = [_parse(relpath, source) for relpath, source in sorted(sources.items())]

    # Module-level re-exports: ``pkg.name -> target`` for every name a module binds by import.
    reexports: dict[str, str] = {}
    for m in modules:
        for local, target in m.aliases.items():
            reexports.setdefault(f"{m.mod}.{local}", target)

    direct: dict[str, list[tuple[ast.AST, int, str, str]]] = {}
    owners: dict[str, dict[int, str]] = {}
    # provider qualified name -> the operation classes it performs, directly or transitively.
    providers: dict[str, set[str]] = {}
    for m in modules:
        ops = _direct_operations(m)
        direct[m.path] = ops
        owner = _enclosing_functions(m.tree)
        owners[m.path] = owner
        for node, _line, op, _callee in ops:
            fn = owner.get(id(node))
            if fn is not None:
                providers.setdefault(f"{m.mod}.{fn}", set()).add(op)

    # Calls to first-party functions, resolved once: (module, node, line, enclosing fn, target).
    first_party_calls: list[tuple[_Module, ast.Call, str | None, str]] = []
    for m in modules:
        owner = owners[m.path]
        for node in ast.walk(m.tree):
            if not isinstance(node, ast.Call):
                continue
            qualified = dotted(node.func, m.aliases, m.mod, m.local_defs)
            if qualified is None:
                continue
            target = _resolve_reexport(qualified, reexports)
            first_party_calls.append((m, node, owner.get(id(node)), target))

    # Fixed point. Who BECOMES a provider is the noise budget, so it is rationed:
    #
    # * Within a module, always. A public entry point over a private helper is followed.
    # * Across modules, only into a CRYPTO MODULE, one that performs at least one direct operation of
    #   its own. ``transports/rest._no_redirect_opener`` builds its opener through ``tls_policy``, and
    #   ``rest.py`` is a crypto module, so the OAuth token hop in ``transports/http_auth.py`` that calls
    #   it is found two hops from the ``ssl`` call. Without the rule it was invisible.
    # * Never into a module with no direct operation of its own. Following every chain to its root
    #   marks the app factory, the verifier's entry point and every load-harness runner as crypto
    #   (measured on this tree, with the opaque providers below already applied: 301 seam sites with
    #   unrestricted spread, 221 with this rule), and a gate that noisy gets ignored. So a chain that
    #   leaves the crypto modules is followed one call further and then stops, which is a stated depth,
    #   not a silent one.
    #
    # Once a function IS a provider it takes every class it reaches, so a caller of
    # ``auth/oidc/claims.validate_id_token`` is told about the signature check it delegates to
    # ``transports/signing`` as well as its own constant-time compare. An opaque provider spreads
    # neither membership nor classes.
    crypto_modules = {m.mod for m in modules if direct[m.path]}
    changed = True
    while changed:
        changed = False
        for m, _node, fn, target in first_party_calls:
            if fn is None or target not in providers or target in OPAQUE_PROVIDERS:
                continue
            caller = f"{m.mod}.{fn}"
            if (
                caller not in providers
                and target.rpartition(".")[0] != m.mod
                and m.mod not in crypto_modules
            ):
                continue
            before = len(providers.get(caller, ()))
            providers.setdefault(caller, set()).update(providers[target])
            if len(providers[caller]) != before:
                changed = True

    out: list[Operation] = []
    for m in modules:
        for _site, line, op, callee in direct[m.path]:
            out.append(Operation(m.path, line, op, callee))
    for m, node, _fn, target in first_party_calls:
        if target not in providers or target in OPAQUE_PROVIDERS:
            continue
        if target.rpartition(".")[0] == m.mod:
            continue  # a call to this module's own helper; the helper's operation is already counted
        for op in sorted(providers[target]):
            out.append(Operation(m.path, node.lineno, op, target, via=target))
    return sorted(set(out))


def operation_token(op: Operation) -> str:
    """The inventory token for one operation: ``class:callee`` for a direct call, so the ALGORITHM is
    part of what is reviewed (``hash:hashlib.sha256`` and ``hash:hashlib.md5`` are different rows),
    and ``class:via <module>`` for a call through a first-party provider. The provider's MODULE, not
    its function, so renaming a helper inside a seam does not ripple through every caller's row."""
    if op.via is not None:
        return f"{op.op_class}:via {op.via.rpartition('.')[0]}"
    return f"{op.op_class}:{op.callee}"


def aggregate(operations: list[Operation]) -> dict[str, frozenset[str]]:
    """``path -> operation tokens`` - the granularity the human inventory is kept at."""
    grouped: dict[str, set[str]] = {}
    for op in operations:
        grouped.setdefault(op.path, set()).add(operation_token(op))
    return {path: frozenset(tokens) for path, tokens in grouped.items()}


def class_counts(operations: list[Operation]) -> dict[str, int]:
    """Operation count per class, every class present (a zero is printed, not omitted)."""
    counts = dict.fromkeys(OPERATION_CLASSES, 0)
    for op in operations:
        counts[op.op_class] += 1
    return counts
