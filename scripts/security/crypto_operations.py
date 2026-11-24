# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1164 (ASVS 11.1.3): OPERATION-granular crypto discovery for the Python tree.

``crypto_inventory_check.py`` discovers crypto by IMPORT: a module is a crypto site when it imports a
trigger. That cannot see a new operation inside a module that is already registered, and it cannot
see a module that reaches crypto through a first-party helper it happens not to import from a
registered seam. This module is the finer instrument the gate now runs beside the import arm.

What it does, in order:

1. Parse every ``.py`` file under the walk roots and resolve each call's callee to a fully qualified
   name through that module's imports (absolute, relative, aliased, function-local, re-exported
   through a package ``__init__``, and bare sibling imports under ``scripts/``).
2. Classify a call as a crypto OPERATION when its qualified callee, or for a method call its method
   name, is in the taxonomy below. A TLS posture attribute set on a context counts too. The result
   is keyed ``path:line -> operation class``.
3. Follow first-party helpers. A module-level function that performs an operation, directly or
   through another such function, is a PROVIDER (the spread rule is stated where it is computed, in
   :func:`discover_operations_in`). A call to a provider from a DIFFERENT module is itself an
   operation site in the caller, of the provider's classes. That is what makes
   ``pipeline/alert_sinks.py`` visible through ``build_smtp_tls_context`` with no crypto import and
   no registered seam, and it needs no seam list: a new module-level helper is followed the day it
   is written.

THE RESIDUAL. The gate's docstring and ``docs/ASVS-L2-PHASE0-CHANGES.md`` point here rather than
repeat it, so this is the one place to extend when a new limit is found. It is a list of AT LEAST
these, not a complete one. Any clean result reads "at least", never "all", because none of these is
seen:

* a SECOND call to a callee a file already lists. The inventory is kept per file and token, so a new
  ``hashlib.sha256`` call beside an existing one changes nothing;
* a call to ANOTHER provider in a module a file already reaches, for a class the file already lists
  through it. A ``via`` token names the module and the class, not the function, so a new call from
  ``pipeline/cert_expiry.py`` to ``pki.make_self_signed``, which signs, would add no token beside
  the ``sign_verify:via messagefoundry.pki`` its CRL signature check holds (vault BACKLOG #3512);
* an algorithm or TLS value held in a VARIABLE. A token carries the algorithm only when the call
  names it, in the callee or as a literal or named constant anywhere in its arguments;
* a plain ``ctx.options = ...`` or ``setattr(ctx, "options", ...)``. ``options`` is too common a
  name to match outside an augmented assignment;
* a method called on a first-party OBJECT (``self._cipher.encrypt_cell(...)``) unless its method name
  is in :data:`METHOD_RULES`. There is no type inference, so a first-party class is followed only
  through its module-level functions;
* a chain that leaves the crypto modules for more than one call. The spread rule stops there on
  purpose, to keep the noise down;
* a call made through ``getattr``, ``importlib`` or any other dynamic dispatch, or in a subprocess;
* a provider passed as a VALUE and called elsewhere, such as the function handed to
  ``asyncio.to_thread``. The reload preflight reaches ``anchor_cadata`` that way (BACKLOG #2025).
  ``Engine.fingerprint_bundle_blocking`` calls its fold directly instead, so that one is seen
  (vault BACKLOG #2839, #2782);
* a crypto DECISION that is not a call or a TLS-attribute assignment. ``odbc_dsn.py`` appends
  ``Encrypt=`` and ``TrustServerCertificate=`` to a DSN string for ``transports/database.py`` and
  ``store/sqlserver.py``: a first-party TLS posture decision with no crypto-shaped expression for
  any pattern instrument to match;
* crypto inside a third-party library the engine calls. The call is seen; the library's own
  operations are not;
* for the non-Python arms, which are PATTERN instruments: an alias that renames the API, an idiom
  no pattern names, a call split across lines (a PowerShell backtick continuation, a multi-line
  JavaScript options object whose key and value sit on different lines), and a file outside the
  walked roots and suffixes;
* for the PowerShell arm: a ``<#`` inside a string or here-string that opens a line with it. The
  comment stripper cannot tell it from a real block comment and hides the lines up to the next
  ``#>``;
* for the TypeScript/JavaScript arms: a line that STARTS with ``//``, ``*`` or ``/*`` and holds
  code, inside a region the comment lexer (``js_lexer.py``) misreads. The per-line view skips such
  a line, and a misread lexer blanks it. At least these misread a literal: regex-versus-division
  decided from the previous token only (a TypeScript ``x! / y``, a ``)`` before a regex), a quoted
  string ended at a newline, and a U+2028 or U+2029 inside a string, which is folded to a newline;
* for the TypeScript/JavaScript arms' per-token verdict (BACKLOG #5578): a lexer match is
  confirmed only where both scans behind ``js_lexer.strict_verdicts`` give it a verdict that
  confirms it, so a misread only one scan makes cannot confirm a mention. A misread both make, such as a quoted string
  misread from an apostrophe that swallows a template's backtick, still makes template text after
  it read as code, and a mention there is confirmed as if it were a call. The first scan reads
  code inside a ``${}`` hole as template text, so a real call in a hole that the per-line view does
  not also see is marked ``(not code)``, and so is a real call the per-line view skips inside any
  region either scan misreads as a literal (the misreads listed above). The per-line view's own false
  positives (at least a trailing comment or a mention inside a quoted string) are confirmed as
  before #5578.
  A cipher-string word's mark follows the file's admission rule, not the word's own position, so
  a real word is marked when the only suite that admits it is unconfirmed;
* for the scope-aware Python reading (BACKLOG #5578), at least: a PEP 695 type-parameter scope
  (names in it resolve to nothing), a walrus in a comprehension, and a ``match`` capture are not
  modelled as bindings. A call only the scope-aware reading gives is not reported, because the
  gate reports the union reading's tokens and only judges them. An import a PEP 562
  ``__getattr__`` serves is an export only in the shapes ``_hook_exports`` reads, so one served
  in any other shape is marked out of scope though PEP 562 may serve it. The other way, a name
  bound without a module-level statement (at least a submodule of the same name, or a
  ``globals()`` or ``sys.modules`` write) still reads as served, so a call the hook never
  answers can be confirmed;
* A union token is confirmed by its callee before ``[`` at one of its own sites, a file and a
  line, not by its label. So an out-of-scope label variant on a line that also holds an in-scope
  call of the same callee stays confirmed, and so does an in-scope call whose algorithm label
  only an out-of-scope binding gives (``hmac.new(k, m, hashlib.md5)`` in a function whose
  ``hashlib`` is a local first-party import, in a file that also imports the stdlib ``hashlib``
  in another scope).
* A provider ``via`` token is marked out of scope when the module's only direct operation is out
  of scope, though the call reaches crypto in scope.
* a parameter or local assignment that shadows an imported name. Only imports are bindings, so a
  ``def go(sig): sig.verify(d)`` in a module that imports a first-party ``sig`` reads as a call to
  that first-party function and skips the method rule.

Stdlib only, like the gate that imports it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
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
    # The COSE public-key parse at registration, which is where ES256 is bound to P-256 (#1166).
    "webauthn.helpers.decode_credential_public_key": "key_cert",
    "webauthn.helpers.decoded_public_key_to_cryptography": "key_cert",
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
    # BACKLOG #1352 / #1171: a first-party key parse. It reads a private key's passphrase wrap
    # before a loader decrypts it, and refuses a weak one. Classified here so every file that
    # reaches it carries the token. That makes the gate a tripwire for a file whose only route to
    # it is gone, not for each call site: a file with two routes keeps its token when one goes.
    "messagefoundry.keywrap.key_wrap_refusal": "key_cert",
    # The same parse for a PKCS#12 bundle's MAC and bags, and for an SSH key's encryption header.
    "messagefoundry.keywrap.pkcs12_wrap_refusal": "key_cert",
    "messagefoundry.keywrap.ssh_key_encrypted": "key_cert",
    # BACKLOG #1352: the second PKCS#12 step, for the key bags inside an encrypted part. pki hands
    # each part's decrypted contents back to be judged; a loader that drops the judging call loses
    # this token while keeping the cipher and kdf ones its decryption leaves.
    "messagefoundry.keywrap.pkcs12_encrypted_parts": "key_cert",
    "messagefoundry.keywrap.refuse_weak_pkcs12_contents": "key_cert",
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
    # Vault BACKLOG #6706: a BatchCipher opens or seals several values per call.
    "encrypt_many": "cipher",
    "decrypt_many": "cipher",
    "encrypt_data": "cipher",  # hvac Vault Transit
    "decrypt_data": "cipher",  # hvac Vault Transit
    "rewrap_data": "cipher",  # hvac Vault Transit
    "sign": "sign_verify",
    "verify": "sign_verify",
    # ADR 0217: the row sealers' awaitable verify, served by the local and Transit sealers.
    "verify_async": "sign_verify",
    "sign_data": "sign_verify",  # hvac Vault Transit
    "verify_signed_data": "sign_verify",  # hvac Vault Transit
    "generate_hmac": "mac",  # hvac Vault Transit
    "derive": "kdf",
    "load_cert_chain": "tls_context",
    "load_verify_locations": "tls_context",
    "load_default_certs": "tls_context",
    "set_default_verify_paths": "tls_context",
    "set_ciphers": "tls_context",
    "set_ciphersuites": "tls_context",
    "set_server_sigalgs": "tls_context",
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
    "messagefoundry.config.wiring._config_module_name": (
        "names a loaded config module or helper after a SHA-256 of its resolved path, so two "
        "same-stem files cannot collide in sys.modules; naming, and no caller of the loader decides "
        "anything by it"
    ),
    "messagefoundry.pipeline.sharding.owner_shard_of_destination": (
        "rendezvous placement uses SHA-256 as a restart-stable hash with no secret; a caller picks "
        "which engine shard owns a destination, not a crypto property"
    ),
}

#: Assigning one of these attributes on any object sets a TLS posture on a context. The object is
#: not type-checked, so the names are chosen to be specific to ``ssl.SSLContext``. Tuple targets
#: (``a.check_hostname, a.verify_mode = ...``) and ``setattr(ctx, "verify_mode", ...)`` count too.
TLS_POSTURE_ATTRIBUTES = frozenset(
    {
        "minimum_version",
        "maximum_version",
        "verify_mode",
        "check_hostname",
        "verify_flags",
        "keylog_filename",
        "post_handshake_auth",
        "hostname_checks_common_name",
    }
)

#: ``options`` is too common a name to match on plain assignment, so it counts only when it is
#: AUGMENTED (``ctx.options |= ssl.OP_NO_TLSv1``), which is how an SSLContext's option bits are set.
TLS_AUGMENTED_ATTRIBUTES = frozenset({"options"})

#: Hash algorithm names, for labelling a call whose algorithm is an ARGUMENT rather than part of the
#: callee (``hmac.new(k, m, hashlib.sha256)``, ``hashlib.new("md5")``, ``HKDF(hashes.SHA256())``).
HASH_ALGORITHMS = frozenset(
    {
        "md4",
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512_224",
        "sha512_256",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "shake_128",
        "shake_256",
        "blake2b",
        "blake2s",
        "sm3",
        "ripemd160",
    }
)

#: Roots whose files import their SIBLINGS by bare name through ``sys.path`` (``import scorecard``
#: from ``scripts/asvs/anchor_report.py``). For these, an import that names no known module is
#: retried against the importing file's own package. Not applied to the package roots, where a
#: bare name that happens to match a sibling file is a stdlib or third-party module instead.
SIBLING_IMPORT_ROOTS = ("scripts.",)


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


def _import_bindings(node: ast.AST, mod: str, is_init: bool) -> list[tuple[str, str]]:
    """``(local name, fully qualified target)`` for every name one import statement binds."""
    out: list[tuple[str, str]] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                out.append((alias.asname, alias.name))
            else:
                head = alias.name.split(".", 1)[0]
                out.append((head, head))
    elif isinstance(node, ast.ImportFrom):
        source = (
            _resolve_relative(mod, is_init, node.level, node.module)
            if node.level
            else (node.module or "")
        )
        for alias in node.names:
            if alias.name != "*":
                out.append((alias.asname or alias.name, f"{source}.{alias.name}"))
    return out


def _bind(table: dict[str, list[str]], local: str, target: str) -> None:
    targets = table.setdefault(local, [])
    if target not in targets:
        targets.append(target)


def import_aliases(nodes: list[ast.AST], mod: str, is_init: bool) -> dict[str, list[str]]:
    """Local name -> EVERY fully qualified target an import anywhere in the module binds it to.

    Function-local imports are included and scoping is ignored, so a name bound by an import
    anywhere in the file resolves the same way everywhere in it. A name bound more than once keeps
    ALL its targets (BACKLOG #5579). It was last-write-wins, so a function-local
    ``from x import y as hashlib`` replaced the module-level ``hashlib`` for the whole file and hid
    every real ``hashlib`` call in it. A call, a TLS value and a method-rule decision are now each
    taken under every IMPORT binding, so one import binding does not mask another's operation; a
    parameter or assignment is not a binding here (see THE RESIDUAL). That can over-resolve
    a shadowed name into a token for an API the call does not reach, which is the direction meant:
    a spurious row costs a review, a hidden call costs the inventory. The gate judges each token
    this reading gives by the scope-aware one, :func:`scoped_bindings` (BACKLOG #5578)."""
    aliases: dict[str, list[str]] = {}
    for node in nodes:
        for local, target in _import_bindings(node, mod, is_init):
            _bind(aliases, local, target)
    return aliases


class _Scope:
    """One Python name scope: the module, a function (a lambda or a comprehension counts as one),
    or a class body. Only its import bindings are recorded, as in :func:`import_aliases`."""

    def __init__(self, kind: str, parent: _Scope | None) -> None:
        self.kind = kind
        self.parent = parent
        self.imports: dict[str, list[str]] = {}
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        #: Every name the scope binds by any means, so a ``nonlocal`` can find the scope it names.
        self.binds: set[str] = set()


_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def scoped_bindings(
    tree: ast.Module, mod: str, is_init: bool
) -> tuple[dict[int, list[str]], set[int], dict[str, list[str]]]:
    """The scope-aware reading of every name in a module (BACKLOG #5578).

    Returns ``(names, module_reach, module_aliases)``: ``id(Name node) -> the import targets that
    reach it``; the ids of the names whose lookup reaches module scope, where a module-level ``def``
    can answer too; and the module-scope import bindings alone, which are what another module
    reaches through this one.

    Python's own rule, for imports: an import binds its name in the scope it runs in, so a
    function-local ``from x import y as hashlib`` makes ``hashlib`` local to that whole function.
    The module-level ``hashlib`` does not reach a call inside it, and the local one reaches no
    other function. A class body does not enclose the functions nested in it. ``global`` moves an
    import's binding to the module, and ``nonlocal`` to the nearest enclosing function that binds
    the name. Within one scope every binding is kept, because which one runs depends on control
    flow (a ``try`` import and its ``except ImportError`` fallback). A parameter or assignment is
    still not a binding for this reading, as in :func:`import_aliases`, so a name that only a
    parameter shadows reads as the enclosing import; it is tracked only to place a ``nonlocal``.

    The walk keeps its own stack rather than recursing, so a deeply nested expression (a long
    ``+`` chain) cannot exhaust the interpreter's recursion limit and crash the gate."""
    module = _Scope("module", None)
    pending: list[tuple[_Scope, str, str]] = []
    names: list[tuple[ast.Name, _Scope]] = []
    stack: list[tuple[ast.AST, _Scope]] = [(top, module) for top in reversed(tree.body)]

    def push(nodes: list[ast.AST], scope: _Scope) -> None:
        stack.extend((child, scope) for child in reversed(nodes))

    while stack:
        node, scope = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # Defaults, decorators and annotations run in the enclosing scope; the body in its own.
            args = node.args
            outer: list[ast.AST] = [*args.defaults, *(d for d in args.kw_defaults if d)]
            every = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            every += [a for a in (args.vararg, args.kwarg) if a]
            inner = _Scope("function", scope)
            inner.binds.update(a.arg for a in every)
            if isinstance(node, ast.Lambda):
                body: list[ast.AST] = [node.body]
            else:
                scope.binds.add(node.name)
                body = [*node.body]
                outer += [*node.decorator_list, *(a.annotation for a in every if a.annotation)]
                outer += [node.returns] if node.returns else []
            push(outer, scope)
            push(body, inner)
            continue
        if isinstance(node, ast.ClassDef):
            scope.binds.add(node.name)
            push([*node.decorator_list, *node.bases, *node.keywords], scope)
            push([*node.body], _Scope("class", scope))
            continue
        if isinstance(node, _COMPREHENSIONS):
            # The first iterable runs in the enclosing scope; everything else in the comprehension.
            first, *rest = node.generators
            inner = _Scope("function", scope)
            parts: list[ast.AST] = [first.target, *first.ifs]
            for gen in rest:
                parts += [gen.target, gen.iter, *gen.ifs]
            parts += [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            push([first.iter], scope)
            push(parts, inner)
            continue
        if isinstance(node, ast.Global):
            scope.globals.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
        elif isinstance(node, ast.Name):
            names.append((node, scope))
            if not isinstance(node.ctx, ast.Load):
                scope.binds.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope.binds.add(node.name)
        for local, target in _import_bindings(node, mod, is_init):
            scope.binds.add(local)
            pending.append((scope, local, target))
        push(list(ast.iter_child_nodes(node)), scope)

    def nonlocal_scope(scope: _Scope, name: str) -> _Scope:
        """The nearest enclosing function that binds ``name`` and does not pass it further up."""
        outer = scope.parent
        while outer is not None and outer is not module:
            if outer.kind == "function" and name in outer.binds and name not in outer.nonlocals:
                return outer
            outer = outer.parent
        # Python refuses such a ``nonlocal`` at compile time; keep the binding somewhere it is seen.
        return scope.parent or module

    # A declaration applies to its whole scope, so imports are placed once every one is read.
    for scope, local, target in pending:
        if scope.kind != "module" and local in scope.globals:
            scope = module
        elif scope.kind != "module" and local in scope.nonlocals:
            scope = nonlocal_scope(scope, local)
        _bind(scope.imports, local, target)

    resolved: dict[int, list[str]] = {}
    module_reach: set[int] = set()
    for node, start in names:
        at: _Scope | None = start
        while at is not None:
            if at is not start and at.kind == "class":
                at = at.parent  # a class body does not enclose what is nested in it
                continue
            if at.kind != "module" and node.id in at.globals:
                at = module
            elif at.kind != "module" and node.id in at.nonlocals:
                at = nonlocal_scope(at, node.id)
                continue
            hit = at.imports.get(node.id)
            if hit:
                resolved[id(node)] = list(hit)
            if at is module:
                module_reach.add(id(node))
            if hit or at is module:
                break
            at = at.parent
    return resolved, module_reach, {k: list(v) for k, v in module.imports.items()}


#: The attribute names a PEP 562 hook may still serve at one point of its body:
#: ``(True, excluded)`` is every name but ``excluded``, ``(False, names)`` is ``names`` alone.
_Admitted = tuple[bool, frozenset[str]]


def _bound_names(node: ast.AST) -> set[str]:
    """Every name ``node`` binds anywhere inside it, nested scopes included, so the reading that
    uses it errs toward forgetting an import rather than keeping one."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Load):
            out.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, ast.alias):
            out.add((n.asname or n.name).split(".", 1)[0])
        elif isinstance(n, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            out.add(n.rest)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            out.update(n.names)
        elif isinstance(n, ast.arg):
            out.add(n.arg)
    return out


def _literal_test(test: ast.expr, param: str) -> frozenset[str] | None:
    """The names ``param == "x"`` or ``param in ("x", "y")`` admits, or ``None`` for any other
    test."""
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.left, ast.Name)
        and test.left.id == param
    ):
        return None
    op, right = test.ops[0], test.comparators[0]
    if isinstance(op, ast.Eq) and isinstance(right, ast.Constant) and isinstance(right.value, str):
        return frozenset({right.value})
    if isinstance(op, ast.In) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
        values = [
            e.value for e in right.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
        if right.elts and len(values) == len(right.elts):
            return frozenset(values)
    return None


def _pep562_hook(tree: ast.Module) -> ast.FunctionDef | None:
    """The module's PEP 562 ``__getattr__`` when it has a shape :func:`_hook_exports` reads: the
    last module-level binding of the name, a plain undecorated ``def`` directly in the module body,
    with no later statement binding the name anywhere inside it (a nested scope included) and no
    ``global`` naming it, with exactly one positional parameter and no ``yield``, ``global`` or
    ``nonlocal`` in it. Any other shape gives ``None``."""
    defs = [
        i
        for i, stmt in enumerate(tree.body)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == "__getattr__"
    ]
    if not defs:
        return None
    hook = tree.body[defs[-1]]
    if not isinstance(hook, ast.FunctionDef) or hook.decorator_list:
        return None
    if any("__getattr__" in _bound_names(stmt) for stmt in tree.body[defs[-1] + 1 :]):
        return None
    if any(isinstance(n, ast.Global) and "__getattr__" in n.names for n in ast.walk(tree)):
        return None
    args = hook.args
    if len(args.posonlyargs + args.args) != 1 or args.vararg or args.kwarg or args.kwonlyargs:
        return None
    if any(
        isinstance(n, (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal)) for n in ast.walk(hook)
    ):
        return None
    return hook


def _hook_exports(tree: ast.Module, mod: str, is_init: bool) -> dict[str, list[str]]:
    """The imports a module's PEP 562 ``__getattr__`` (:func:`_pep562_hook`) serves as attributes
    of the module, for the scope-aware exports (BACKLOG #5578).

    The body is read in order, tracking which attribute names can still reach each point. An
    ``if`` testing the parameter as :func:`_literal_test` reads it narrows its body to those names,
    and when that body ends in a ``return`` or ``raise`` and has no ``else``, it narrows what
    follows to every other name. ``return X`` serves ``X`` only when ``X`` is a bare name bound by
    an import earlier on the same path and ``"X"`` can still reach it. Any other statement (an
    expression other than a constant, an assignment, a loop, a ``try``, a ``with``, a ``match``),
    any other ``if``, and an import that is a star import or binds the parameter ends the reading:
    nothing after it is served. A name any other module-level statement binds is never served,
    because Python calls the hook only for a name the module lacks, and a module-level star import
    turns the reading off.

    The body is walked with an explicit work list, so a long ``elif`` chain cannot exhaust the
    recursion limit and crash the gate."""
    hook = _pep562_hook(tree)
    if hook is None:
        return {}
    param = (hook.args.posonlyargs + hook.args.args)[0].arg
    elsewhere = {name for stmt in tree.body if stmt is not hook for name in _bound_names(stmt)}
    if "*" in elsewhere:  # ``_bound_names`` keeps a star import's alias as ``*``
        return {}
    out: dict[str, list[str]] = {}
    work: list[tuple[list[ast.stmt], _Admitted, dict[str, list[str]]]] = [
        (hook.body, (True, frozenset()), {})
    ]
    while work:
        stmts, admitted, imports = work.pop()  # each task owns its ``imports`` copy
        for stmt in stmts:
            if isinstance(stmt, ast.Return):
                value = stmt.value
                if isinstance(value, ast.Name) and value.id in imports:
                    every, names = admitted
                    served = (value.id not in names) if every else (value.id in names)
                    if served and value.id not in elsewhere:
                        for target in imports[value.id]:
                            _bind(out, value.id, target)
                break
            if isinstance(stmt, ast.Raise):
                break
            if isinstance(stmt, ast.If):
                lits = _literal_test(stmt.test, param)
                if lits is None:
                    break
                every, names = admitted
                narrowed: _Admitted = (False, lits - names if every else names & lits)
                work.append((stmt.body, narrowed, dict(imports)))
                rest: _Admitted = (True, names | lits) if every else (False, names - lits)
                if stmt.orelse:
                    work.append((stmt.orelse, rest, dict(imports)))
                    break
                if not isinstance(stmt.body[-1], (ast.Return, ast.Raise)):
                    break
                admitted = rest
                continue
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                pairs = _import_bindings(stmt, mod, is_init)
                if any(a.name == "*" for a in stmt.names) or any(p == param for p, _ in pairs):
                    break
                for local, target in pairs:
                    imports[local] = [target]
                continue
            docstring = isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            if not (docstring or isinstance(stmt, ast.Pass)):
                break
    return out


def dotted(
    expr: ast.expr, aliases: dict[str, list[str]], mod: str, local_defs: set[str]
) -> list[str]:
    """Every qualified name an expression can refer to; empty when it cannot be resolved. A name
    both imported and defined in the module keeps both readings, for the reason
    :func:`import_aliases` gives."""
    if isinstance(expr, ast.Name):
        out = list(aliases.get(expr.id, ()))
        if expr.id in local_defs and f"{mod}.{expr.id}" not in out:
            out.append(f"{mod}.{expr.id}")
        return out
    if isinstance(expr, ast.Attribute):
        return [f"{base}.{expr.attr}" for base in dotted(expr.value, aliases, mod, local_defs)]
    return []


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
class ParsedModule:
    path: str
    mod: str
    tree: ast.Module
    nodes: list[ast.AST]  # one walk, reused by every pass over the module
    aliases: dict[str, list[str]]
    local_defs: set[str]
    functions: set[str]
    #: The scope-aware reading (BACKLOG #5578); :func:`scoped_bindings` says what each holds, and
    #: ``module_aliases`` also holds :func:`_hook_exports`.
    scope_names: dict[int, list[str]] = field(default_factory=dict)
    module_reach: set[int] = field(default_factory=set)
    module_aliases: dict[str, list[str]] = field(default_factory=dict)
    #: When set, :meth:`resolve` reads a name through its scope, not through every import.
    scope_aware: bool = False

    def resolve(self, expr: ast.expr) -> list[str]:
        if not self.scope_aware:
            return dotted(expr, self.aliases, self.mod, self.local_defs)
        if isinstance(expr, ast.Name):
            out = list(self.scope_names.get(id(expr), ()))
            local = f"{self.mod}.{expr.id}"
            if id(expr) in self.module_reach and expr.id in self.local_defs and local not in out:
                out.append(local)
            return out
        if isinstance(expr, ast.Attribute):
            return [f"{base}.{expr.attr}" for base in self.resolve(expr.value)]
        return []

    @property
    def exports(self) -> dict[str, list[str]]:
        """The import bindings another module reaches through this one: every one for the union
        reading, and for the scope-aware reading the module-scope ones plus those
        :func:`_hook_exports` reads from a PEP 562 ``__getattr__``."""
        return self.module_aliases if self.scope_aware else self.aliases


def _parse(relpath: str, source: str) -> ParsedModule:
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    mod = module_name(relpath)
    is_init = relpath.endswith("__init__.py")
    functions = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    scope_names, module_reach, module_aliases = scoped_bindings(tree, mod, is_init)
    for local, targets in _hook_exports(tree, mod, is_init).items():
        for target in targets:
            _bind(module_aliases, local, target)
    return ParsedModule(
        path=relpath,
        mod=mod,
        tree=tree,
        nodes=nodes,
        aliases=import_aliases(nodes, mod, is_init),
        local_defs=functions | classes,
        functions=functions,
        scope_names=scope_names,
        module_reach=module_reach,
        module_aliases=module_aliases,
    )


def _resolve_siblings(modules: list[ParsedModule]) -> None:
    """Rewrite a bare sibling import under :data:`SIBLING_IMPORT_ROOTS` to its real module path, in
    the union reading and the scope-aware one alike."""
    known = {m.mod for m in modules}
    for m in modules:
        if not m.mod.startswith(SIBLING_IMPORT_ROOTS):
            continue
        package = m.mod.rpartition(".")[0]
        tables = (m.aliases, m.module_aliases, m.scope_names)
        for targets in (t for table in tables for t in table.values()):
            for i, target in enumerate(targets):
                head = target.split(".", 1)[0]
                # The SIBLING module must exist as a file. Accepting any known prefix instead would
                # let one ``__init__.py`` in the directory rewrite ``import hashlib`` into a
                # first-party name and silently drop every operation in the file.
                if head not in known and f"{package}.{head}" in known:
                    targets[i] = f"{package}.{target}"
            # Two imports can rewrite to one target; keep the list unique, as ``_bind`` does.
            targets[:] = dict.fromkeys(targets)


def _enclosing_functions(tree: ast.Module) -> dict[int, str]:
    """``id(node) -> top-level function name`` for every node inside a module-level function."""
    owner: dict[int, str] = {}
    for top in tree.body:
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(top):
                owner[id(node)] = top.name
    return owner


def _resolve_reexport(name: str, reexports: dict[str, list[str]]) -> set[str]:
    """Follow ``pkg.name -> real.target`` re-export links, so a call through a package ``__init__``
    lands on the function that is actually defined. A name re-exported more than once follows every
    link (BACKLOG #5579). Returns ``name`` and every name reached, so a caller looking for a
    first-party function to follow keeps any of them. Bounded, so a cycle cannot hang the gate."""
    reached = {name}
    frontier = {name}
    for _ in range(8):
        frontier = {t for n in frontier for t in reexports.get(n, ()) if t not in reached}
        if not frontier:
            break
        reached |= frontier
    return reached


def _lands_on(
    qualified: str, reexports: dict[str, list[str]], known_functions: set[str], depth: int = 0
) -> bool:
    """Whether EVERY branch of a qualified callee's re-export chain ends on a first-party
    module-level function. Used only to decide when the method rule may be skipped, so any doubt
    keeps the rule: a branch that loops (a cycle or a self-link) or passes the depth cap counts as
    NOT first-party, and so does a name with a link, such as a ``def verify`` its module also binds
    by an import, whose own def is not one of its branches."""
    return _all_branches_first_party(qualified, reexports, known_functions, (), depth)


def _all_branches_first_party(
    name: str,
    reexports: dict[str, list[str]],
    known_functions: set[str],
    path: tuple[str, ...],
    depth: int,
) -> bool:
    links = reexports.get(name)
    if not links:
        return name in known_functions
    if name in path or depth >= 8:
        return False
    return all(
        _all_branches_first_party(t, reexports, known_functions, (*path, name), depth + 1)
        for t in links
    )


def _canonical_algorithm(name: str) -> str | None:
    """``SHA-256``, ``sha_256``, ``SHA2-256`` and ``sha256`` are one algorithm; so are ``SHAKE128``
    and ``shake_128``. Returns the :data:`HASH_ALGORITHMS` spelling, or ``None``."""
    key = "".join(ch for ch in name.lower() if ch.isalnum())
    return _ALGORITHM_KEYS.get(key)


_ALGORITHM_KEYS: dict[str, str] = {
    **{"".join(ch for ch in algo if ch.isalnum()): algo for algo in HASH_ALGORITHMS},
    "sha2224": "sha224",
    "sha2256": "sha256",
    "sha2384": "sha384",
    "sha2512": "sha512",
}


def _algorithms_in(call: ast.Call, m: ParsedModule) -> list[str]:
    """Hash algorithms named anywhere in a call's ARGUMENTS, nested calls included
    (``key.sign(data, ec.ECDSA(hashes.SHA256()))``), so the token can carry them."""
    found: set[str] = set()
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        for node in ast.walk(arg):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                names = [node.value]
            elif isinstance(node, (ast.Name, ast.Attribute)):
                names = [
                    qualified.rpartition(".")[2]
                    for qualified in m.resolve(node)
                    if qualified.startswith(("hashlib.", "cryptography.hazmat.primitives.hashes."))
                ]
            else:
                continue
            found.update(algo for name in names if (algo := _canonical_algorithm(name)))
    return sorted(found)


def _value_labels(value: ast.expr | None, m: ParsedModule) -> list[str]:
    """Short labels for the value a TLS attribute is set to, when it is a literal or a named
    constant (``False``, ``CERT_NONE``, ``TLSv1_2``): one per binding a named value has (BACKLOG
    #5579), so a weakening value under any binding reaches a token. ``[""]`` for anything else."""
    if value is None:
        return [""]
    if isinstance(value, ast.Constant) and isinstance(value.value, (bool, int, str)):
        return [f" {value.value}"]
    if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Invert):
        return [f" ~{inner.strip()}" if inner else "" for inner in _value_labels(value.operand, m)]
    labels = [f" {q.rpartition('.')[2]}" for q in m.resolve(value)]
    return list(dict.fromkeys(labels)) or [""]


_AUG_OPERATORS: dict[type[ast.operator], str] = {
    ast.BitOr: "|=",
    ast.BitAnd: "&=",
    ast.BitXor: "^=",
    ast.Add: "+=",
    ast.Sub: "-=",
}


def _posture_targets(node: ast.AST) -> list[tuple[str, ast.expr | None]]:
    """``(attribute, assigned value)`` for every TLS posture attribute an assignment sets."""
    out: list[tuple[str, ast.expr | None]] = []

    def visit(target: ast.expr, value: ast.expr | None) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            values = (
                value.elts
                if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts)
                else [None] * len(target.elts)
            )
            for sub, sub_value in zip(target.elts, values, strict=True):
                visit(sub, sub_value)
        elif isinstance(target, ast.Attribute) and target.attr in TLS_POSTURE_ATTRIBUTES:
            out.append((target.attr, value))

    if isinstance(node, ast.Assign):
        for target in node.targets:
            visit(target, node.value)
    elif isinstance(node, ast.AnnAssign):
        visit(node.target, node.value)
    elif (
        isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Attribute)
        and node.target.attr in TLS_POSTURE_ATTRIBUTES | TLS_AUGMENTED_ATTRIBUTES
    ):
        out.append((node.target.attr, node.value))
    return out


def _direct_operations(
    m: ParsedModule, known_functions: set[str], reexports: dict[str, list[str]]
) -> list[tuple[ast.AST, int, str, str]]:
    """``(node, line, class, callee)`` for every direct operation in one module."""
    found: list[tuple[ast.AST, int, str, str]] = []
    for node in m.nodes:
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "setattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in TLS_POSTURE_ATTRIBUTES
            ):
                value = node.args[2] if len(node.args) >= 3 else None
                for label in _value_labels(value, m):
                    found.append(
                        (node, node.lineno, "tls_context", f".{node.args[1].value} ={label}")
                    )
                continue
            candidates = m.resolve(node.func)
            classified = [(q, classify_qualified(q)) for q in candidates]
            hits = [(q, op) for q, op in classified if op is not None]
            if hits:
                algorithms = _algorithms_in(node, m)
                for qualified, op in hits:
                    label = f"{qualified}[{','.join(algorithms)}]" if algorithms else qualified
                    found.append((node, node.lineno, op, label))
            # The bindings no rule above classified. A hit under one binding must not stop the
            # method rule for another, or a crypto-module binding masks a signer's ``.sign()``.
            rest = [q for q, op in classified if op is None]
            if hits and not rest:
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr in METHOD_RULES:
                if rest and all(_lands_on(q, reexports, known_functions) for q in rest):
                    # A call that lands on a first-party module-level FUNCTION is handled by provider
                    # propagation, which knows whether that function really performs crypto; a
                    # method-name guess would not. Anything else (a first-party class's method, a
                    # module-level instance, an unresolvable receiver, or a name that only SOME of
                    # its bindings resolve to a first-party function) keeps the method rule.
                    continue
                op_class: str | None = METHOD_RULES[node.func.attr]
                override = METHOD_OVERRIDES.get((m.path, node.func.attr))
                if override is not None:
                    op_class = override[0]
                if op_class is not None:
                    algorithms = _algorithms_in(node, m)
                    suffix = f"[{','.join(algorithms)}]" if algorithms else ""
                    found.append((node, node.lineno, op_class, f".{node.func.attr}(){suffix}"))
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for attr, value in _posture_targets(node):
                # The REAL operator: ``&= ~FLAG`` clears a bit that ``|= FLAG`` sets, and one of
                # them is often the weakening direction, so they must not share a token.
                sign = (
                    _AUG_OPERATORS.get(type(node.op), "?=")
                    if isinstance(node, ast.AugAssign)
                    else "="
                )
                for label in _value_labels(value, m):
                    found.append((node, node.lineno, "tls_context", f".{attr} {sign}{label}"))
    return found


def parse_files(files: list[Path], repo: Path) -> list[ParsedModule]:
    """Parse ``files`` once. The gate hands the result to BOTH Python arms, so neither re-parses."""
    return parse_sources(
        {path.relative_to(repo).as_posix(): path.read_text(encoding="utf-8") for path in files}
    )


def parse_sources(sources: dict[str, str]) -> list[ParsedModule]:
    """Parse ``repo-relative path -> source text`` into modules with their imports resolved."""
    modules = [_parse(relpath, source) for relpath, source in sorted(sources.items())]
    _resolve_siblings(modules)
    return modules


def discover_operations(files: list[Path], repo: Path) -> list[Operation]:
    """Every crypto operation site in ``files``, direct or through a first-party provider."""
    return discover_operations_in_modules(parse_files(files, repo))


def discover_operations_in(sources: dict[str, str]) -> list[Operation]:
    """:func:`discover_operations` over ``repo-relative path -> source text``, so the gate's own
    positive control can run the SAME instrument over a fixture that never touches the disk."""
    return discover_operations_in_modules(parse_sources(sources))


def discover_operations_in_modules(
    modules: list[ParsedModule], *, scope_aware: bool = False
) -> list[Operation]:
    """:func:`discover_operations` over modules already parsed by :func:`parse_sources`.

    ``scope_aware`` reads every name through its scope (:func:`scoped_bindings`) rather than
    through every import in its file. The gate runs both readings and judges each token of the
    union reading by the scope-aware one (BACKLOG #5578)."""
    if scope_aware:
        modules = [replace(m, scope_aware=True) for m in modules]
    # Module-level re-exports: ``pkg.name -> target`` for every name a module binds by import.
    reexports: dict[str, list[str]] = {}
    for m in modules:
        for local, targets in m.exports.items():
            reexports.setdefault(f"{m.mod}.{local}", []).extend(targets)
    # Every first-party module-level function: the only things that can become providers.
    known_functions = {f"{m.mod}.{name}" for m in modules for name in m.functions}

    direct: dict[str, list[tuple[ast.AST, int, str, str]]] = {}
    owners: dict[str, dict[int, str]] = {}
    # provider qualified name -> the operation classes it performs, directly or transitively.
    providers: dict[str, set[str]] = {}
    for m in modules:
        ops = _direct_operations(m, known_functions, reexports)
        direct[m.path] = ops
        owner = _enclosing_functions(m.tree)
        owners[m.path] = owner
        for node, _line, op, _callee in ops:
            fn = owner.get(id(node))
            if fn is not None:
                providers.setdefault(f"{m.mod}.{fn}", set()).add(op)

    # Calls that land on a first-party module-level function: (module, node, enclosing fn, target).
    first_party_calls: list[tuple[ParsedModule, ast.Call, str | None, str]] = []
    for m in modules:
        owner = owners[m.path]
        for node in m.nodes:
            if not isinstance(node, ast.Call):
                continue
            # Every name the chain REACHES, not only its ends: a def its module also binds by an
            # import (function-local, earlier, or the same name re-imported) may still be what the
            # call reaches at runtime, and binding order and scope are not modelled. Counting it
            # can over-report a provider; dropping it would hide the call.
            landed = {
                target
                for qualified in m.resolve(node.func)
                for target in _resolve_reexport(qualified, reexports)
                if target in known_functions
            }
            for target in sorted(landed):
                first_party_calls.append((m, node, owner.get(id(node)), target))

    # Fixed point. Who BECOMES a provider is the noise budget, so it is rationed:
    #
    # * Within a module, always. A public entry point over a private helper is followed.
    # * Across modules, only into a CRYPTO MODULE, one that performs at least one direct operation of
    #   its own. ``transports/rest._no_redirect_opener`` builds its opener through ``tls_policy``, and
    #   ``rest.py`` is a crypto module, so the token-hop base in ``transports/smart.py`` that calls it
    #   is found two hops from the ``ssl`` call. Without the rule it was invisible. (That call sat in
    #   ``transports/http_auth.py`` until BACKLOG #2115 moved both token hops onto the one base.)
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
    """The inventory token for one operation: ``class:callee`` for a direct call and ``class:via
    <module>`` for a call through a first-party provider.

    The callee carries the ALGORITHM wherever the call names one, in the callee itself
    (``hashlib.sha256`` against ``hashlib.md5``) or in an argument (``hmac.new[sha256]``,
    ``hashlib.new[md5]``), and a TLS posture assignment carries a literal or named-constant value
    (``.verify_mode = CERT_NONE``). So changing an algorithm, or switching verification off, changes
    a token. An algorithm held in a VARIABLE does not; see the residual in the module docstring. The
    provider half names the MODULE, not its function, so renaming a helper inside a seam does not
    ripple through every caller's row."""
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
