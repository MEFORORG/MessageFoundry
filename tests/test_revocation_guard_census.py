# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A census of verifying client TLS contexts: each is tied to a revocation guard or a named exemption
(vault BACKLOG #2987, ADR 0173).

Engine PR 2021 (vault BACKLOG #2193) found four outbound hops that verified a peer certificate and
ran no revocation guard: the FhirLookup read path, the DICOM SCU, the FTPS upload and a credentialed
DIRECT relay. Nothing reported them, because nothing listed the hops a guard had to cover. This file
is that list. A new site that obtains a verifying client context fails here until someone decides,
in review, whether it is guarded or exempt and why.

**What counts as a site.** A function in ``messagefoundry/`` that calls a name in :data:`_BUILDERS`,
passes one of the engine's own builders as a value (to ``run_in_executor``, say), or reads
``_NO_REDIRECT_OPENER``. Those names are at least the ways the engine hands out a verifying
client context today, not all of them (SDS-3.6): a context reached by another name is outside this
census, which is why :func:`test_every_builder_name_is_still_defined` keeps the list from rotting
under a rename. A function whose own name is in :data:`_BUILDERS` is not a site. It hands its context
to its callers, and they are the sites. A SERVER context (``PROTOCOL_TLS_SERVER``) is not counted;
the listener gates are a different control.

**What "guarded" proves.** The site's function, or the one its entry names, calls a name in
:data:`_GUARDS`, and every such name reaches ``RevocationHopGuard.capture``. That ties the site to a
guard call. It does not prove that every branch reaches the call, or that the call refuses: the
behaviour tests (at least ``tests/test_revocation_guard_remaining_hops.py`` and
``tests/test_hop_refusal_revocation.py``) prove that. A second hop added inside a function that is
already guarded passes here too, so read the function in review.

**It goes red.** Delete the guard call from one guarded site and
:func:`test_every_guarded_site_calls_a_guard` fails naming that site; measured when this file was
written, by deleting the ``RevocationHopGuard.capture`` call in ``DicomScuDestination.__init__``.
"""

from __future__ import annotations

import ast
import functools
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.config.tls_policy import RevocationHopGuard
from tests._ast_sites import callee_name

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "messagefoundry"

#: Names whose call hands the caller a verifying client context, directly or inside an opener.
#: ``SSLContext`` counts only with ``PROTOCOL_TLS_CLIENT`` in its arguments (see :func:`_is_builder`).
_BUILDERS = frozenset(
    {
        # stdlib and truststore
        "create_default_context",
        "SSLContext",
        # config/tls_policy.py
        "build_verifying_client_context",
        "build_anchored_https_handler",
        "build_asserted_https_handler",
        "build_smtp_tls_context",
        "assert_ldap3_tls_suites",
        "assert_hvac_tls_suites",
        # transports/
        "build_strict_opener",  # with no HTTPS handler, urllib supplies a verifying one
        "_no_redirect_opener",
        "_expiry_relaxed_opener",
        "_client_cert_opener",
        "_client_ssl_context",
        "_mllp_ssl_context",
        "_ftps_ssl_context",
        # the store, the syslog forwarder, the IdP, the LDAPS bind
        "_verifying_context",
        "_build_tls_context",
        "build_idp_opener",
        "NarrowedTls",
    }
)

#: The shared import-time opener, defined in each of :data:`_SHARED_OPENER_MODULES`. Reading it is
#: how a hop dials through a verifying context without calling a builder.
_SHARED_OPENER = "_NO_REDIRECT_OPENER"
_SHARED_OPENER_MODULES = ("transports/rest.py", "pipeline/alert_sinks.py")

#: The stdlib and truststore names. Matched only as a call: a bare ``SSLContext`` also names a type.
_STDLIB_BUILDERS = frozenset({"create_default_context", "SSLContext"})

#: Names whose call runs a revocation guard. Each one other than ``capture`` must reach ``capture``
#: through the others (:func:`test_every_guard_name_reaches_the_guard`).
_GUARDS = frozenset(
    {
        "capture",  # RevocationHopGuard.capture, matched only on that receiver
        "refuse_unrevoked_verified_hop",
        "_refuse_store_revocation",
        "_refuse_forward_revocation",
        "_refuse_idp_revocation",
        "idp_revocation_guards",
    }
)

#: Ungated verifying hops, with the reason recorded in docs/DEPLOYMENT.md.
_UNGATED = (
    "an ungated verifying hop, listed in docs/DEPLOYMENT.md under 'Ungated verifying TLS hop'"
)
_TRAY = "the Windows tray probing the engine's own API on this box"
_LISTENER = (
    "a SERVER context for an inbound listener. Its client-certificate revocation gate is "
    "check_inbound_revocation, not this guard"
)


@dataclass(frozen=True, slots=True)
class Guarded:
    """The site is tied to a guard call. ``by`` names the function that makes it, as
    ``module::qualname``; ``None`` means the site's own function. ``note`` is printed with a
    failure, so the reader sees what the guard covers."""

    by: str | None = None
    note: str = ""


@dataclass(frozen=True, slots=True)
class Exempt:
    """The site takes no revocation guard, for the reason given. A blank reason fails collection."""

    reason: str

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("a census exemption needs a reason")


_CENSUS: dict[str, Guarded | Exempt] = {
    # --- guarded ---------------------------------------------------------------------------------
    "messagefoundry/auth/service.py::AuthService.__init__": Guarded(
        note="the OIDC token and JWKS legs, through _refuse_idp_revocation"
    ),
    "messagefoundry/logging_setup.py::_build_syslog_handler": Guarded(
        by="messagefoundry/logging_setup.py::_build_tls_context",
        note="the builder runs _refuse_forward_revocation on the context it returns",
    ),
    "messagefoundry/store/postgres.py::_build_ssl": Guarded(note="the PostgreSQL store hop"),
    "messagefoundry/store/postgres.py::_per_connection_ssl_connect.connect": Guarded(
        by="messagefoundry/store/postgres.py::_build_ssl",
        note="each pool connection rebuilds, from the same settings, the context _build_ssl "
        "guarded at store open",
    ),
    "messagefoundry/transports/dicom.py::DicomScuDestination.__init__": Guarded(),
    "messagefoundry/transports/dicomweb.py::DicomWebDestination.__init__": Guarded(),
    "messagefoundry/transports/direct.py::DirectDestination.__init__": Guarded(
        note="a relay with no SMTP credential takes no guard by design: its body is S/MIME"
    ),
    "messagefoundry/transports/email.py::EmailDestination.__init__": Guarded(),
    "messagefoundry/transports/fhir.py::FhirDestination.__init__": Guarded(),
    "messagefoundry/transports/fhir.py::FhirLookupExecutor.__init__": Guarded(),
    "messagefoundry/transports/mllp.py::MLLPDestination.__init__": Guarded(),
    "messagefoundry/transports/remotefile.py::_FtpClient.__init__": Guarded(
        by="messagefoundry/transports/remotefile.py::RemoteFileDestination.__init__",
        note="the FTPS upload. The inbound FTPS poll builds the same client and is " + _UNGATED,
    ),
    "messagefoundry/transports/rest.py::RestDestination.__init__": Guarded(),
    "messagefoundry/transports/smart.py::_TokenEndpointProvider._open_token_hop": Guarded(
        note="the SMART and OAuth2 token hops"
    ),
    "messagefoundry/transports/soap.py::SoapDestination.__init__": Guarded(),
    # --- exempt: ungated verifying hops ------------------------------------------------------------
    "messagefoundry/auth/ldap.py::LdapAuthenticator.__init__": Exempt(f"LDAPS: {_UNGATED}"),
    "messagefoundry/pipeline/alert_sinks.py::_build_no_redirect_opener": Exempt(
        f"the webhook alert sink: {_UNGATED}"
    ),
    "messagefoundry/pipeline/alert_sinks.py::WebhookTransport._post": Exempt(
        f"the webhook alert sink: {_UNGATED}"
    ),
    "messagefoundry/pipeline/alert_sinks.py::send_plain_email": Exempt(
        f"the [alerts] SMTP sink and the security notifier, built outside every "
        f"active_hop_posture scope, so a guard here could not see the posture: {_UNGATED}"
    ),
    "messagefoundry/transports/ai_broker.py::AiBroker.__init__": Exempt(
        f"the AI-broker endpoint: {_UNGATED}"
    ),
    "messagefoundry/config/secretprovider_vault.py::_build_client": Exempt(
        "the Vault KV secret provider hop. Ungated, and NOT in docs/DEPLOYMENT.md's ungated table: "
        "its requests-based client takes one CA bundle and no revocation flag, so no CRL can reach "
        "it (tls_policy refuses [tls].crl_file there). Found by this census; unfiled"
    ),
    "messagefoundry/store/keyprovider_vault.py::_build_client": Exempt(
        "the Vault Transit key provider hop. Ungated, and NOT in docs/DEPLOYMENT.md's ungated "
        "table, for the same reason as the KV provider above. Found by this census; unfiled"
    ),
    # --- exempt: not a partner hop -----------------------------------------------------------------
    "messagefoundry/apiclient/client.py::_build_verify_context": Exempt(
        "the engine's own HTTP client library (ADR 0088), dialing the engine's API from a client "
        "process such as the harness or the CLI. No hop posture is stamped there"
    ),
    "messagefoundry/tray/probe.py::_pinned_context": Exempt(_TRAY),
    "messagefoundry/tray/probe.py::build_verify": Exempt(_TRAY),
    "messagefoundry/verify/smoke.py::live_smoke_ssl_context": Exempt(
        "`messagefoundry verify` smoke-testing the engine's own API"
    ),
    "messagefoundry/verify/federation.py::_idp_opener": Exempt(
        "`messagefoundry verify` builds the IdP opener to report on it, and reports the engine's "
        "own decision through idp_revocation_guards. The engine's hop is AuthService.__init__"
    ),
    "messagefoundry/config/tls_probe.py::_offer_context": Exempt(
        "the startup TLS-floor probe of the engine's own front door. It verifies nothing by design "
        "(see its module docstring), so no verified certificate exists whose revocation matters"
    ),
    "messagefoundry/transports/rest.py::_insecure_opener": Exempt(
        "a verify-OFF context, so no verified certificate exists whose revocation matters. The "
        "verify-off gate (#200, refuse_verify_off) owns that hop"
    ),
    "messagefoundry/transports/rest.py::<module>": Exempt(
        "builds the shared import-time _NO_REDIRECT_OPENER. Each function that dials through it "
        "reads that name and is its own entry here"
    ),
    "messagefoundry/transports/http_listener.py::HttpSource.__init__": Exempt(_LISTENER),
    "messagefoundry/transports/mllp.py::MLLPSource.__init__": Exempt(_LISTENER),
    # --- exempt: never handshakes ------------------------------------------------------------------
    "messagefoundry/auth/trust_anchors.py::anchor_cadata": Exempt(
        "loads a PEM into a scratch context to prove OpenSSL parses it; never handshakes"
    ),
    "messagefoundry/config/tls_policy.py::<module>": Exempt(
        "reads the stock client security level at import; never handshakes"
    ),
    "messagefoundry/config/tls_policy.py::crl_scratch_context": Exempt(
        "counts the CRLs OpenSSL loads from a file; never handshakes"
    ),
}


@dataclass(frozen=True, slots=True)
class _Scan:
    sites: frozenset[str]
    guard_calls: frozenset[str]
    #: modules that assign the shared opener at module level.
    opener_modules: frozenset[str]
    #: bare function or class name -> the guard names its body calls, for every def in the package.
    defs: dict[str, frozenset[str]]


def _is_builder(call: ast.Call) -> bool:
    name = callee_name(call)
    if name == "SSLContext":
        return "PROTOCOL_TLS_CLIENT" in ast.unparse(call)
    return name in _BUILDERS


def _is_guard(call: ast.Call) -> bool:
    name = callee_name(call)
    if name == "capture":
        func = call.func
        return isinstance(func, ast.Attribute) and ast.unparse(func.value) == "RevocationHopGuard"
    return name in _GUARDS


class _Visitor(ast.NodeVisitor):
    def __init__(
        self,
        rel: str,
        sites: set[str],
        guards: set[str],
        defs: dict[str, set[str]],
        opener_modules: set[str],
    ):
        self._rel = rel
        self._opener_modules = opener_modules
        self._scope: list[str] = []
        self._sites = sites
        self._guards = guards
        self._defs = defs

    def _key(self) -> str:
        return f"{self._rel}::{'.'.join(self._scope) or '<module>'}"

    def _in_builder(self) -> bool:
        return any(scope in _BUILDERS for scope in self._scope)

    def _enter(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self._scope.append(node.name)
        self._defs.setdefault(node.name, set())
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = _enter
    visit_AsyncFunctionDef = _enter
    visit_ClassDef = _enter

    def visit_Name(self, node: ast.Name) -> None:
        if not isinstance(node.ctx, ast.Load) or self._in_builder():
            return
        # A bare-name call to an engine builder lands here too, which is harmless: same site key.
        if node.id == _SHARED_OPENER or node.id in _BUILDERS - _STDLIB_BUILDERS:
            self._sites.add(self._key())

    def visit_Assign(self, node: ast.Assign) -> None:
        if not self._scope and any(
            isinstance(t, ast.Name) and t.id == _SHARED_OPENER for t in node.targets
        ):
            self._opener_modules.add(self._rel)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_builder(node) and not self._in_builder():
            self._sites.add(self._key())
        if _is_guard(node):
            self._guards.add(self._key())
            if self._scope:  # _enter made the entry
                self._defs[self._scope[-1]].add(str(callee_name(node)))
        self.generic_visit(node)


#: Every name the scan keys on. A file holding none of them can add nothing, so it is not parsed.
_ANY_NAME = (*_BUILDERS, *_GUARDS, _SHARED_OPENER)


@functools.cache
def _scan() -> _Scan:
    sites: set[str] = set()
    guards: set[str] = set()
    defs: dict[str, set[str]] = {}
    opener_modules: set[str] = set()
    for path in sorted(_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not any(name in source for name in _ANY_NAME):
            continue
        rel = path.relative_to(_ROOT).as_posix()
        _Visitor(rel, sites, guards, defs, opener_modules).visit(ast.parse(source))
    return _Scan(
        frozenset(sites),
        frozenset(guards),
        frozenset(opener_modules),
        {k: frozenset(v) for k, v in defs.items()},
    )


def test_every_site_is_in_the_census() -> None:
    """The check that stops the next unguarded hop: a new site fails here until it is classified."""
    unlisted = sorted(_scan().sites - _CENSUS.keys())
    assert not unlisted, (
        f"verifying client TLS context(s) with no census entry: {unlisted}. Add a guard "
        f"(RevocationHopGuard.capture, or refuse_unrevoked_verified_hop for an https hop) and list "
        f"the site as Guarded, or list it as Exempt with the reason. See ADR 0173 and "
        f"docs/DEPLOYMENT.md, 'Revocation-guard behavior'."
    )


def test_every_census_entry_is_still_a_site() -> None:
    """A stale entry would keep an exemption alive for code that no longer exists."""
    stale = sorted(_CENSUS.keys() - _scan().sites)
    assert not stale, f"census entries that are no longer a site: {stale}"


def test_every_guarded_site_calls_a_guard() -> None:
    scan = _scan()
    unguarded = [
        f"{site} (guard expected in {entry.by or 'the site itself'}; {entry.note or 'no note'})"
        for site, entry in sorted(_CENSUS.items())
        if isinstance(entry, Guarded) and (entry.by or site) not in scan.guard_calls
    ]
    assert not unguarded, f"census sites marked Guarded whose guard call is gone: {unguarded}"


def test_every_guard_name_reaches_the_guard() -> None:
    """A wrapper that stopped calling the guard would leave every site it covers green above.

    Followed through the wrappers to ``capture``, so two wrappers that only call each other are
    hollow too. Keyed by bare function name, so a same-named def elsewhere in the package could
    stand in for a wrapper; the guard names here are unique today."""
    defs = _scan().defs
    assert callable(getattr(RevocationHopGuard, "capture", None))
    reaches = {"capture"}
    grew = True
    while grew:
        grew = False
        for name in _GUARDS - reaches:
            if defs.get(name, frozenset()) & reaches:
                reaches.add(name)
                grew = True
    hollow = sorted(_GUARDS - reaches)
    assert not hollow, f"guard name(s) that never reach RevocationHopGuard.capture: {hollow}"


def test_every_builder_name_is_still_defined() -> None:
    """A renamed builder would drop all its callers from the census without a red."""
    scan = _scan()
    missing = sorted(name for name in _BUILDERS - _STDLIB_BUILDERS if name not in scan.defs)
    assert not missing, f"builder name(s) no longer defined in messagefoundry/: {missing}"
    # The shared opener is a module-level assignment, not a def.
    expected = {f"messagefoundry/{rel}" for rel in _SHARED_OPENER_MODULES}
    assert scan.opener_modules == expected, (
        f"{_SHARED_OPENER} is assigned at module level in {sorted(scan.opener_modules)}, "
        f"expected {sorted(expected)}"
    )
