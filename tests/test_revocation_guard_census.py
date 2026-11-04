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
``_NO_REDIRECT_OPENER``, by bare name or through a module. Those names are at least the ways the engine hands out a verifying
client context today, not all of them (SDS-3.6): a context reached by another name is outside this
census, which is why :func:`test_every_builder_name_is_still_defined` keeps the list from rotting
under a rename. A function whose own name is in :data:`_BUILDERS` is not a site. It hands its context
to its callers, and they are the sites. A SERVER context (``PROTOCOL_TLS_SERVER``) is not counted;
the listener gates are a different control.

**What "guarded" proves.** The site's function, or the one its entry names, calls a name in
:data:`_GUARDS`, and every such name reaches a guard in :data:`_GUARD_ROOTS`. That ties the site
to a guard call. It does not prove that every branch reaches the call, or that the call refuses,
or that a guard checks a CRL: the behaviour tests (at least
``tests/test_revocation_guard_remaining_hops.py``, ``tests/test_hop_refusal_revocation.py`` and
``tests/test_vault_revocation_hop_guard.py``) prove that. A second hop added inside a function that
is already guarded passes here too, so read the function in review.

**It goes red.** Delete the guard call from one guarded site and
:func:`test_every_guarded_site_calls_a_guard` fails naming that site; measured when this file was
written, by deleting the ``RevocationHopGuard.capture`` call in ``DicomScuDestination.__init__``.
Measured again when the two Vault ``_build_client`` sites became Guarded (vault BACKLOG #3587):
renaming the ``mount_strict_reply_adapter`` call in either one failed that test naming it, and
renaming either link of the chain from the mount to the Vault guard failed
:func:`test_every_guard_name_reaches_a_root`. So did a second def named ``refuse_an_unrevoked_hop``
in another module, and renaming the Vault guard's ``_crossed_unrevoked`` call failed
:func:`test_the_vault_root_decides_through_the_authority`.

**The relaxed-hop handoff census** at the end of this file is a second list, of the sites that
reach ``relax_verify_expiry`` (vault BACKLOG #5086). ``RevocationHopGuard.capture`` gives no CRL
credit to a context that skips time validity, with or without ``expiry_relaxed``, so a relaxed hop
can earn that credit only by handing the guard some other, unrelaxed context without the flag;
that is what :func:`test_every_relaxed_hop_is_a_connection_whose_guard_call_cannot_credit_a_crl`
fails on. Measured when it was rebuilt on main after vault BACKLOG #5089, against in-memory copies
of the package: MLLP handing a fresh context with no flag, the DICOM SCU doing so with the flag
negated, the FTPS guard wrapper dropping its flag, and FHIR handing its relaxed opener each failed
that test, naming the hops (the last two are false faults the census accepts: see
:func:`_from_relaxing_builder`), and ``remotefile.py``'s module code calling ``_FtpClient`` failed
its exemption. Those runs are a record, not a test; the synthetic controls at the end of this file
are what stays checked.
"""

from __future__ import annotations

import ast
import functools
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.config.tls_policy import RevocationHopGuard
from tests._ast_sites import (
    call_sites,
    callee_name,
    calls_to,
    find_funcs,
    named_func,
    parse_source,
)

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "messagefoundry"

#: Names whose call hands the caller a verifying client context, directly or inside an opener.
#: ``SSLContext`` counts unless its arguments name ``PROTOCOL_TLS_SERVER`` (see :func:`_is_builder`).
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
        # The settings-reading wrapper both IdP opener sites call (vault BACKLOG #3145), so those
        # two stay the sites and the wrapper hands its opener on, as build_idp_opener does.
        "build_idp_opener_from_settings",
        "NarrowedTls",
        # pipeline/alert_sinks.py: the [alerts] SMTP recipe the send and its guard share
        # (BACKLOG #2193), so both stay the sites, as for the IdP wrapper above.
        "_alerts_smtp_context",
    }
)

#: The shared import-time opener, defined in each of :data:`_SHARED_OPENER_MODULES`. Reading it is
#: how a hop dials through a verifying context without calling a builder.
_SHARED_OPENER = "_NO_REDIRECT_OPENER"
_SHARED_OPENER_MODULES = ("transports/rest.py", "pipeline/alert_sinks.py")

#: The stdlib and truststore names. Matched only as a call: a bare ``SSLContext`` also names a type.
_STDLIB_BUILDERS = frozenset({"create_default_context", "SSLContext"})

#: The guards every other name in :data:`_GUARDS` must reach. The Vault hop guard, in
#: ``transports/strict_requests.py`` (vault BACKLOG #2983), decides through
#: ``tls_policy.revocation_hop_disposition`` and never calls ``RevocationHopGuard``; its docstring
#: says why.
_GUARD_ROOTS = frozenset(
    {
        "capture",  # RevocationHopGuard.capture, matched only on that receiver
        "_refuse_an_unrevoked_vault_hop",
    }
)

#: Names whose call runs a revocation guard. Each one outside :data:`_GUARD_ROOTS` must reach a root
#: through the others (:func:`test_every_guard_name_reaches_a_root`).
_GUARDS = _GUARD_ROOTS | frozenset(
    {
        "refuse_unrevoked_verified_hop",
        "_guard_ftps_revocation",  # transports/remotefile.py, both FTPS directions (BACKLOG #2193)
        "_refuse_store_revocation",
        "_refuse_forward_revocation",
        "_refuse_idp_revocation",
        "idp_revocation_guards",
        "_refuse_ad_revocation",  # auth/ldap.py, the LDAPS AD bind (BACKLOG #2193)
        # pipeline/alert_sinks.py, the [alerts] SMTP login and the webhook (BACKLOG #2193)
        "_refuse_alert_smtp_revocation",
        "_refuse_webhook_revocation",
        "_refuse_an_unrevoked_ai_hop",  # transports/ai_broker.py, the AI endpoint (BACKLOG #2193)
        # transports/strict_requests.py, the Vault hops (vault BACKLOG #2983)
        "refuse_an_unrevoked_hop",  # StrictReplyAdapter's, at the mount and before each send
        "mount_strict_reply_adapter",
    }
)

#: What the two Vault entries' guard covers, and what this census does not follow there.
_VAULT_GUARD = (
    "through mount_strict_reply_adapter, which runs _refuse_an_unrevoked_vault_hop at "
    "construction (vault BACKLOG #2983). No CRL lever is built for these hops, so off the box "
    "the hop crosses an enforcing posture only on its vault_revocation_attested pair. This census "
    "follows the construction-time call only, not the adapter's check before each send, and not "
    "_refuse_an_unrevoked_proxy_leg (vault BACKLOG #3561), handed on as a value"
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
    "messagefoundry/auth/ldap.py::LdapAuthenticator.__init__": Guarded(
        note="the LDAPS AD bind, through _refuse_ad_revocation on the finished NarrowedTls "
        "(BACKLOG #2193). Every engine build passes it a posture: "
        "tests/test_ldaps_revocation_guard.py pins that"
    ),
    "messagefoundry/auth/ldap.py::_refuse_ad_revocation": Guarded(
        note="the LDAPS guard itself, which takes the finished NarrowedTls and reads a context "
        "its factory builds (BACKLOG #2193)"
    ),
    "messagefoundry/logging_setup.py::_build_syslog_handler": Guarded(
        by="messagefoundry/logging_setup.py::_build_tls_context",
        note="the builder runs _refuse_forward_revocation on the context it returns",
    ),
    "messagefoundry/store/postgres.py::_build_ssl": Guarded(note="the PostgreSQL store hop"),
    "messagefoundry/__main__.py::_warn_on_an_unrevoked_store_hop": Guarded(
        note="the store-opening CLI commands' warn-posture WARNING (BACKLOG #2532). It runs "
        "_refuse_store_revocation on the context it builds and never handshakes on it; the "
        "store's open builds and guards its own in _build_ssl"
    ),
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
        note="the FTPS upload. The inbound FTPS poll builds the same client, and "
        "RemoteFileSource.__init__ calls the same _guard_ftps_revocation (BACKLOG #2193); Guarded "
        "names one caller, so the poll's call is pinned by the behaviour tests",
    ),
    "messagefoundry/transports/rest.py::RestDestination.__init__": Guarded(),
    "messagefoundry/transports/smart.py::_TokenEndpointProvider._open_token_hop": Guarded(
        note="the SMART and OAuth2 token hops"
    ),
    "messagefoundry/transports/soap.py::SoapDestination.__init__": Guarded(),
    "messagefoundry/transports/ai_broker.py::AiBroker.__init__": Guarded(
        note="the AI endpoint, through _refuse_an_unrevoked_ai_hop (BACKLOG #2193 slice (e)). No "
        "CRL lever is built for this hop, so off the box it crosses an enforcing posture only on "
        "its [ai].endpoint_revocation_attested pair; an unknown posture counts as enforcing"
    ),
    "messagefoundry/config/secretprovider_vault.py::_build_client": Guarded(
        note=f"the Vault KV secret provider hop, {_VAULT_GUARD}"
    ),
    "messagefoundry/store/keyprovider_vault.py::_build_client": Guarded(
        note=f"the Vault Transit key provider hop, which the Transit cipher shares, {_VAULT_GUARD}"
    ),
    "messagefoundry/pipeline/alert_sinks.py::_build_no_redirect_opener": Guarded(
        by="messagefoundry/pipeline/alert_sinks.py::WebhookTransport.__init__",
        note="the webhook's shared opener, built at import. Each WebhookTransport runs "
        "_refuse_webhook_revocation for an https URL, with its [alerts] attestation pair as the "
        "only lever (BACKLOG #2193)",
    ),
    "messagefoundry/pipeline/alert_sinks.py::WebhookTransport._post": Guarded(
        by="messagefoundry/pipeline/alert_sinks.py::WebhookTransport.__init__",
        note="each POST dials the shared opener the constructor's guard judged (BACKLOG #2193)",
    ),
    "messagefoundry/pipeline/alert_sinks.py::send_plain_email": Guarded(
        by="messagefoundry/pipeline/alert_sinks.py::EmailTransport.__init__",
        note="the [alerts] SMTP hop when it carries a login. EmailTransport and "
        "SecurityEventNotifier each run _refuse_alert_smtp_revocation at construction; Guarded "
        "names one caller, so the notifier's call is pinned by tests/test_alert_revocation_guard.py. "
        "A hop with no login takes no guard by design (ADR 0173)",
    ),
    "messagefoundry/pipeline/alert_sinks.py::_refuse_alert_smtp_revocation": Guarded(
        note="the SMTP login guard itself, which builds the context each send builds (BACKLOG #2193)"
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
        return "PROTOCOL_TLS_SERVER" not in ast.unparse(call)
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

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # The same, read through a module: ``rest._NO_REDIRECT_OPENER`` or
        # ``tls_policy.build_verifying_client_context`` passed as a value.
        is_engine_name = node.attr == _SHARED_OPENER or node.attr in _BUILDERS - _STDLIB_BUILDERS
        if is_engine_name and isinstance(node.ctx, ast.Load) and not self._in_builder():
            self._sites.add(self._key())
        self.generic_visit(node)

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
        f"(RevocationHopGuard.capture, refuse_unrevoked_verified_hop for an https hop, or "
        f"mount_strict_reply_adapter for an hvac Vault client, which must not use "
        f"RevocationHopGuard) and list the site as Guarded, or list it as Exempt with the reason. "
        f"See ADR 0173 and docs/DEPLOYMENT.md, 'Revocation-guard behavior'."
    )


def test_every_census_entry_is_still_a_site() -> None:
    """A stale entry would keep an exemption alive for code that no longer exists."""
    stale = sorted(_CENSUS.keys() - _scan().sites)
    assert not stale, f"census entries that are no longer a site: {stale}"


def test_every_guarded_site_calls_a_guard() -> None:
    scan = _scan()
    guarded = {site: entry for site, entry in _CENSUS.items() if isinstance(entry, Guarded)}
    # 15 sites were Guarded when this floor was set, so 10 lets up to five retire with no edit here.
    # It is a floor against a census emptied or turned all Exempt, over which the check below would
    # pass on nothing. It does not catch a single hop moved from Guarded to Exempt; review does.
    assert len(guarded) >= 10, f"only {len(guarded)} Guarded census entries, floor 10"
    unguarded = [
        f"{site} (guard expected in {entry.by or 'the site itself'}; {entry.note or 'no note'})"
        for site, entry in sorted(guarded.items())
        if (entry.by or site) not in scan.guard_calls
    ]
    assert not unguarded, f"census sites marked Guarded whose guard call is gone: {unguarded}"


def _def_count(name: str) -> int:
    """How many ``def``s named ``name`` the package holds, nested ones and methods included."""
    return sum(
        len(find_funcs(parse_source(source), name))
        for path in sorted(_PACKAGE.rglob("*.py"))
        if name in (source := path.read_text(encoding="utf-8"))
    )


def test_every_guard_name_reaches_a_root() -> None:
    """A wrapper that stopped calling the guard would leave every site it covers green above.

    Followed through the wrappers to a root, so two wrappers that only call each other are hollow
    too. Keyed by bare function name, so each guard name but ``capture`` must have exactly one def
    in the package: a second same-named def could otherwise stand in for a wrapper. ``capture`` is
    matched only on ``RevocationHopGuard``, and ``transports/mllp.py`` defines another one."""
    defs = _scan().defs
    assert callable(getattr(RevocationHopGuard, "capture", None))
    # Pinned exactly, so a hollow wrapper moved into the roots needs an edit here that review sees.
    assert sorted(_GUARD_ROOTS) == ["_refuse_an_unrevoked_vault_hop", "capture"], _GUARD_ROOTS
    # Counted from the source, not imported: the Vault guard's module needs the [vault] extra.
    counts = {name: _def_count(name) for name in sorted(_GUARDS - {"capture"})}
    # 8 names when this floor was set; 4 is the Vault root plus the wrapper floor below. It fails a
    # walk over nothing, over which the one-def check would pass.
    assert len(counts) >= 4, f"only {len(counts)} guard names besides capture, floor 4"
    not_one = {name: n for name, n in counts.items() if n != 1}
    assert not not_one, f"guard name(s) without exactly one def in messagefoundry/: {not_one}"
    # 5 wrappers when this floor was set, so 3 lets two go with no edit here (BACKLOG #3512). It
    # fails a list cut to the roots alone, over which the check below passes on nothing.
    wrappers = _GUARDS - _GUARD_ROOTS
    assert len(wrappers) >= 3, f"only {len(wrappers)} guard names outside the roots, floor 3"
    reaches = set(_GUARD_ROOTS)
    grew = True
    while grew:
        grew = False
        for name in _GUARDS - reaches:
            if defs.get(name, frozenset()) & reaches:
                reaches.add(name)
                grew = True
    hollow = sorted(_GUARDS - reaches)
    assert not hollow, f"guard name(s) that never reach a root in {sorted(_GUARD_ROOTS)}: {hollow}"


def test_the_vault_root_decides_through_the_authority() -> None:
    """The Vault root is not ``RevocationHopGuard``, so its tie to the decision is checked here.

    It must call ``_crossed_unrevoked``, and that must call ``revocation_hop_disposition``, the
    authority every other revocation guard uses. This shows the calls exist, not that their answer
    is used: a root that returns first stays green here, and the behaviour tests in
    ``tests/test_vault_revocation_hop_guard.py`` catch that."""
    tree = parse_source(
        (_PACKAGE / "transports" / "strict_requests.py").read_text(encoding="utf-8")
    )
    root = named_func(tree, "_refuse_an_unrevoked_vault_hop")
    decider = named_func(tree, "_crossed_unrevoked")
    assert calls_to(root, {"_crossed_unrevoked"}, bare_only=True), (
        "the Vault root no longer decides"
    )
    assert calls_to(decider, {"revocation_hop_disposition"}, bare_only=True), (
        "_crossed_unrevoked no longer asks tls_policy.revocation_hop_disposition"
    )


def test_every_builder_name_is_still_defined() -> None:
    """A renamed builder would drop all its callers from the census without a red."""
    scan = _scan()
    engine_builders = _BUILDERS - _STDLIB_BUILDERS
    # 17 engine builder names when this floor was set, so 12 lets up to five go with no edit here.
    # It fails a list emptied or cut to a few names, over which the check below would pass on
    # nothing. Most such cuts also turn census entries stale in the test above; this floor makes
    # this test stand on its own.
    assert len(engine_builders) >= 12, f"only {len(engine_builders)} engine builder names, floor 12"
    missing = sorted(name for name in engine_builders if name not in scan.defs)
    assert not missing, f"builder name(s) no longer defined in messagefoundry/: {missing}"
    # The shared opener is a module-level assignment, not a def.
    expected = {f"messagefoundry/{rel}" for rel in _SHARED_OPENER_MODULES}
    assert scan.opener_modules == expected, (
        f"{_SHARED_OPENER} is assigned at module level in {sorted(scan.opener_modules)}, "
        f"expected {sorted(expected)}"
    )


# The relaxed-hop handoff census (vault BACKLOG #5086). ``relax_verify_expiry`` sets
# ``X509_V_FLAG_NO_CHECK_TIME``, which OpenSSL applies to a CRL's validity window too, so a CRL on a
# relaxed context is no revocation check. ``RevocationHopGuard.capture`` gives such a CRL no credit
# whether or not the caller passes ``expiry_relaxed``, since it reads the flag off the context it is
# handed. The tests below find every reach of the function, through any builder that hands the
# relaxed context or opener on, and read the guard call at each hop the reach ends in: it must hand
# the guard that relaxed context, pass the flag, or hand no context (ADR 0173 §4.3 and §13).

_RELAX = "relax_verify_expiry"

#: Sites that reach ``relax_verify_expiry``, directly or through another builder here, and hand the
#: relaxed context or opener to their caller. Each calls no guard: one that did would be a hop.
_RELAXING_BUILDERS = frozenset(
    {
        "messagefoundry/transports/dicom.py::_client_ssl_context",
        "messagefoundry/transports/mllp.py::_mllp_ssl_context",
        "messagefoundry/transports/remotefile.py::_FtpClient.__init__",
        "messagefoundry/transports/remotefile.py::_ftps_ssl_context",
        "messagefoundry/transports/remotefile.py::_make_client",
        "messagefoundry/transports/rest.py::_expiry_relaxed_opener",
        "messagefoundry/transports/soap.py::_client_cert_opener",
    }
)

#: The hops: sites that take a relaxed context or opener from a builder above and run a guard.
_RELAXED_HOPS = frozenset(
    {
        "messagefoundry/transports/dicom.py::DicomScuDestination.__init__",
        "messagefoundry/transports/fhir.py::FhirDestination.__init__",
        "messagefoundry/transports/mllp.py::MLLPDestination.__init__",
        "messagefoundry/transports/remotefile.py::RemoteFileDestination.__init__",
        "messagefoundry/transports/remotefile.py::RemoteFileSource.__init__",
        "messagefoundry/transports/rest.py::RestDestination.__init__",
        "messagefoundry/transports/soap.py::SoapDestination.__init__",
    }
)

#: Sites that reach a builder above and build no relaxed client context. Each names the builder and
#: the keyword that keeps it off its relaxing branch, checked as ``True`` at every call in the site,
#: or ``None`` for a site that only reads the builder's name and must never call it.
_NOT_RELAXED: dict[str, tuple[str, str | None]] = {
    # The server branch of _mllp_ssl_context returns before its relax_verify_expiry call.
    "messagefoundry/transports/mllp.py::MLLPSource.__init__": ("_mllp_ssl_context", "server"),
    "messagefoundry/transports/http_listener.py::HttpSource.__init__": (
        "_mllp_ssl_context",
        "server",
    ),
    # _REPLY_PARSERS reads _FtpClient._list.__code__ to match a reply parser's frame; it builds
    # no client.
    "messagefoundry/transports/remotefile.py::<module>": ("_FtpClient", None),
}

#: The bases a hop's class must name directly, so the hop is a connection.
_CONNECTION_BASES = frozenset({"DestinationConnector", "SourceConnector"})

_Def = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class _Unit:
    """The code a reach is charged to: a module-level function, a method (a nested def is charged
    to it), a class body outside its methods, or a module's top-level statements."""

    key: str
    #: The name a caller reaches it by: the class for a dunder method or a class body, else the def's.
    alias: str | None
    node: ast.AST
    #: The bases its class names, by bare name; empty outside a class.
    bases: frozenset[str]


def _units(rel: str, tree: ast.Module) -> list[_Unit]:
    units: list[_Unit] = []

    def walk(body: list[ast.stmt], prefix: str, cls: ast.ClassDef | None) -> None:
        bases = frozenset(
            name
            for base in (cls.bases if cls else [])
            if (name := base.id if isinstance(base, ast.Name) else getattr(base, "attr", None))
        )
        rest: list[ast.stmt] = []
        for stmt in body:
            if isinstance(stmt, ast.ClassDef):
                walk(stmt.body, f"{prefix}{stmt.name}.", stmt)
            elif isinstance(stmt, _Def):
                # A dunder method (__init__, __post_init__, __call__, __enter__) runs through its
                # class or an instance of it, never through its own name, so its class is the name
                # a caller reaches it by.
                dunder = stmt.name.startswith("__") and stmt.name.endswith("__")
                alias = cls.name if cls is not None and dunder else stmt.name
                units.append(_Unit(f"{rel}::{prefix}{stmt.name}", alias, stmt, bases))
            else:
                rest.append(stmt)
        if rest:
            key = f"{rel}::{prefix.rstrip('.') or '<module>'}"
            body_alias = cls.name if cls is not None else None
            units.append(_Unit(key, body_alias, ast.Module(body=rest, type_ignores=[]), bases))

    walk(tree.body, "", None)
    return units


def _loads(node: ast.AST) -> set[str]:
    """The names code under ``node`` reads, bare or as an attribute: a call and a value both count."""
    return {
        sub.id if isinstance(sub, ast.Name) else sub.attr
        for sub in ast.walk(node)
        if isinstance(sub, ast.Name | ast.Attribute) and isinstance(sub.ctx, ast.Load)
    }


def _guard_calls(node: ast.AST) -> list[ast.Call]:
    return [sub for sub in ast.walk(node) if isinstance(sub, ast.Call) and _is_guard(sub)]


@dataclass(frozen=True, slots=True)
class _Reach:
    units: dict[str, _Unit]
    #: Every name a reach was followed through: the function, the builders' aliases, import aliases.
    names: frozenset[str]


def _relaxed_reach(sources: dict[str, str], stop: frozenset[str]) -> _Reach:
    """Every unit in ``sources`` that reads ``relax_verify_expiry``, or reads the alias of a reached
    unit that calls no guard, to a fixed point. A unit that calls a guard is a hop, and a unit in
    ``stop`` is reviewed as building no relaxed context, so neither passes its alias on. A file is
    parsed only once its text names something reached, so most of the package is never parsed."""
    names = {_RELAX}
    units: dict[str, list[_Unit]] = {}
    #: Per parsed file, each ``from ... import name as other`` pair, re-read on every pass so an
    #: alias of a name that is reached only later, or in a file visited earlier, is still followed.
    imports: dict[str, list[tuple[str, str]]] = {}
    #: Each unit's loaded names, read once when its file is parsed. Keyed by the unit, not its key:
    #: a property's getter and setter, or a redefined def, share one key.
    loads: dict[int, set[str]] = {}
    reached: dict[str, _Unit] = {}
    grew = True
    while grew:
        grew = False
        for rel, source in sources.items():
            if rel not in units:
                if not any(name in source for name in names):
                    continue
                tree = parse_source(source)
                units[rel] = _units(rel, tree)
                loads.update((id(unit), _loads(unit.node)) for unit in units[rel])
                imports[rel] = [
                    (alias.name, alias.asname)
                    for imp in ast.walk(tree)
                    if isinstance(imp, ast.ImportFrom)
                    for alias in imp.names
                    if alias.asname
                ]
            for name, asname in imports[rel]:
                if name in names and asname not in names:
                    names.add(asname)
                    grew = True
            for unit in units[rel]:
                if unit.key in reached or not loads[id(unit)] & names:
                    continue
                reached[unit.key] = unit
                grew = True
                if unit.key not in stop and not _guard_calls(unit.node) and unit.alias:
                    names.add(unit.alias)
    return _Reach(reached, frozenset(names))


#: Stands for a binding the census does not read as a value: a ``for`` or ``with`` target, a walrus,
#: an augmented assignment, a deletion, or an unpacking target.
_UNREAD: ast.expr = ast.Constant(value=Ellipsis)


def _rebinds(node: ast.AST, target: str) -> bool:
    """Whether the binding target ``node`` rebinds ``target``: it is that spelling, or an unpacking
    that holds it. Setting an attribute or item of ``target`` does not rebind it."""
    if isinstance(node, ast.Tuple | ast.List):
        return any(_rebinds(elt, target) for elt in node.elts)
    if isinstance(node, ast.Starred):
        return _rebinds(node.value, target)
    return ast.unparse(node) == target


def _bindings(fn: ast.AST, target: str) -> list[ast.expr]:
    """Every value code under ``fn`` binds to ``target``, an ``ast.unparse`` spelling such as
    ``self._ssl``, in any order: a binding after the use counts as one before it. A binding it does
    not read as a value is :data:`_UNREAD`. At least these are not seen: a binding made in another
    function ``fn`` calls (a method that resets ``self._ssl``), and an ``except ... as``, ``import
    ... as`` or ``match`` capture."""
    values: list[ast.expr] = []
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Assign):
            for t in sub.targets:
                if ast.unparse(t) == target:
                    values.append(sub.value)
                elif _rebinds(t, target):
                    values.append(_UNREAD)
        elif isinstance(sub, ast.AnnAssign) and sub.value and ast.unparse(sub.target) == target:
            values.append(sub.value)
        elif isinstance(sub, ast.AugAssign | ast.For | ast.AsyncFor | ast.NamedExpr):
            if _rebinds(sub.target, target):
                values.append(_UNREAD)
        elif isinstance(sub, ast.withitem):
            if sub.optional_vars is not None and _rebinds(sub.optional_vars, target):
                values.append(_UNREAD)
        elif isinstance(sub, ast.comprehension):
            if _rebinds(sub.target, target):
                values.append(_UNREAD)
        elif isinstance(sub, ast.Delete) and any(_rebinds(t, target) for t in sub.targets):
            values.append(_UNREAD)
    return values


def _holds_when_relaxed(
    expr: ast.expr, fn: ast.AST, builders: frozenset[str], seen: frozenset[str] = frozenset()
) -> bool:
    """Whether ``expr``, read in ``fn``, is true on a relaxed hop, read off its shape. It is when it
    is ``True``; reads the setting as ``<x>.get("tls_allow_expired", ...)``; asks
    ``skips_validity_period`` of the context a relaxing builder returned
    (:func:`_from_relaxing_builder`), never of some other context; is ``bool(...)`` of one of
    those; is an ``or`` with one of them as a part, or an ``and`` of them; or is a local name every
    binding of which is one. Anything else does not hold, ``not`` and a comparison included. It
    reads shape, not value, so at least ``<x>.get("tls_allow_expired")`` holds whatever ``<x>`` is."""
    if isinstance(expr, ast.Constant):
        return expr.value is True
    if isinstance(expr, ast.BoolOp):
        parts = [_holds_when_relaxed(v, fn, builders, seen) for v in expr.values]
        return any(parts) if isinstance(expr.op, ast.Or) else all(parts)
    if isinstance(expr, ast.Name):
        if expr.id in seen:
            return False
        values = _bindings(fn, expr.id)
        return bool(values) and all(
            v is not _UNREAD and _holds_when_relaxed(v, fn, builders, seen | {expr.id})
            for v in values
        )
    if isinstance(expr, ast.Call) and not expr.keywords and expr.args:
        name, first = callee_name(expr), expr.args[0]
        if name == "bool" and len(expr.args) == 1:
            return _holds_when_relaxed(first, fn, builders, seen)
        if name == "skips_validity_period" and len(expr.args) == 1:
            return _from_relaxing_builder(first, fn, builders)
    if isinstance(expr, ast.Call) and callee_name(expr) == "get" and expr.args:
        first = expr.args[0]
        return isinstance(first, ast.Constant) and first.value == "tls_allow_expired"
    return False


def _is_none(value: ast.expr) -> bool:
    return isinstance(value, ast.Constant) and value.value is None


def _none_when_relaxed(value: ast.expr, fn: ast.AST, builders: frozenset[str]) -> bool:
    """``None``, or ``None if <relaxed> else ...``."""
    return _is_none(value) or (
        isinstance(value, ast.IfExp)
        and _is_none(value.body)
        and _holds_when_relaxed(value.test, fn, builders)
    )


def _none_param(value: ast.expr) -> str | None:
    """The parameter ``P`` when ``value`` is ``None if P is None else E``, where ``E`` is ``P`` or a
    call that takes ``P`` as an argument, else ``None``. What the call does with ``P`` is not read."""
    if not (isinstance(value, ast.IfExp) and _is_none(value.body)):
        return None
    test, orelse = value.test, value.orelse
    if not (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Is)
        and _is_none(test.comparators[0])
    ):
        return None
    param = test.left.id
    uses = isinstance(orelse, ast.Name) and orelse.id == param
    takes = isinstance(orelse, ast.Call) and any(
        isinstance(arg, ast.Name) and arg.id == param
        for arg in (*orelse.args, *(kw.value for kw in orelse.keywords))
    )
    return param if uses or takes else None


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _is_capture(call: ast.Call) -> bool:
    return callee_name(call) == "capture" and _is_guard(call)


def _from_relaxing_builder(value: ast.expr, fn: ast.AST, builders: frozenset[str]) -> bool:
    """Whether ``value`` is the context or opener a relaxing builder handed ``fn``: a name or
    attribute that ``fn`` binds, every time, to a call to one of ``builders``. Read as written,
    so at least a value reassigned through another name, read off such an object's attribute, or
    bound on another branch, or by a ``for``, ``with`` or walrus, to something else, does not
    count. Such a hop may be faulted although ``capture`` would read the relaxed context it hands
    over: a false fault, which fails closed."""
    values = _bindings(fn, ast.unparse(value))
    return bool(values) and all(
        isinstance(v, ast.Call) and callee_name(v) in builders - {_RELAX} for v in values
    )


def _capture_cannot_credit(
    capture: ast.Call,
    where: ast.AST,
    builders: frozenset[str],
    bound: dict[str, ast.expr] | None = None,
    fn: ast.AST | None = None,
) -> bool:
    """Whether ``capture``, a ``RevocationHopGuard.capture`` call made in ``where``, can give a CRL
    no credit on a relaxed hop. One of three holds (vault BACKLOG #5086): it hands ``capture`` no
    context there, it passes ``expiry_relaxed`` as true there, or the context it hands is the one
    a relaxing builder returned, whose own time-validity flag ``capture`` reads. In a wrapper,
    ``bound`` maps the parameters it never rebinds to the hop's arguments, read in ``fn``, the
    hop's code. A ``**`` argument is not read, so a call holding one is a fault."""
    if any(kw.arg is None for kw in capture.keywords):
        return False
    context = _keyword(capture, "context")
    flag = _keyword(capture, "expiry_relaxed")
    if context is None or _none_when_relaxed(context, where, builders):
        return True
    if flag is not None and _holds_when_relaxed(flag, where, builders):
        return True
    if bound is None or fn is None:
        return _from_relaxing_builder(context, where, builders)
    flag_arg = bound.get(flag.id) if isinstance(flag, ast.Name) else None
    if flag_arg is not None and _holds_when_relaxed(flag_arg, fn, builders):
        return True
    param = context.id if isinstance(context, ast.Name) else _none_param(context)
    arg = bound.get(param) if param is not None else None
    return arg is not None and (
        _none_when_relaxed(arg, fn, builders) or _from_relaxing_builder(arg, fn, builders)
    )


def _guard_call_cannot_credit(
    call: ast.Call, fn: ast.AST, defs: dict[str, list[_Def]], builders: frozenset[str]
) -> bool:
    """Whether the guard call ``call``, made in ``fn``, can give a CRL no credit on a relaxed hop.
    A ``capture`` call is read where it is (:func:`_capture_cannot_credit`). A wrapper is read one
    level down, in its one def, and each ``capture`` there must pass that read with the wrapper's
    parameters bound to ``call``'s arguments; a parameter the wrapper rebinds is left unbound. Any
    other shape is not read, so it counts as a fault: so does a wrapper that makes a guard call
    other than ``capture``, and a call to it that passes a ``**`` argument."""
    if _is_capture(call):
        return _capture_cannot_credit(call, fn, builders)
    found = defs.get(str(callee_name(call)), [])
    if len(found) != 1 or any(kw.arg is None for kw in call.keywords):
        return False
    wrapper = found[0]
    params = [arg.arg for arg in (*wrapper.args.posonlyargs, *wrapper.args.args)]
    if params and params[0] in {"self", "cls"} and isinstance(call.func, ast.Attribute):
        params = params[1:]  # a method called through its receiver: the receiver is not an argument
    bound: dict[str, ast.expr] = dict(zip(params, call.args, strict=False))
    bound.update({kw.arg: kw.value for kw in call.keywords if kw.arg})
    bound = {name: arg for name, arg in bound.items() if not _bindings(wrapper, name)}
    inner = _guard_calls(wrapper)
    captures = [sub for sub in inner if _is_capture(sub)]
    if not captures or len(captures) != len(inner):
        return False
    return all(_capture_cannot_credit(c, wrapper, builders, bound, fn) for c in captures)


def _defs_named(sources: dict[str, str], names: set[str]) -> dict[str, list[_Def]]:
    found: dict[str, list[_Def]] = {name: [] for name in names}
    for source in sources.values():
        for name in names:
            if f"def {name}(" in source:
                found[name].extend(find_funcs(parse_source(source), name))
    return found


def _handoff_faults(
    sources: dict[str, str], hops: list[_Unit], builders: frozenset[str]
) -> list[str]:
    """Every way a hop in ``hops`` fails: it runs no guard, it is not the ``__init__`` of a class
    naming a connection base, or a guard call passes no ``connection`` argument (or a literal
    ``None``) or could credit a CRL on a relaxed hop (:func:`_guard_call_cannot_credit`).
    ``builders`` are the names the reach followed. The ``connection`` argument is read as written,
    so one that is ``None`` only at run time passes."""
    wrappers = {
        str(callee_name(call))
        for hop in hops
        for call in _guard_calls(hop.node)
        if not _is_capture(call)
    }
    defs = _defs_named(sources, wrappers)
    faults: list[str] = []
    for hop in hops:
        calls = _guard_calls(hop.node)
        if not calls:
            faults.append(f"{hop.key}: runs no revocation guard")
        if not hop.key.endswith(".__init__"):
            faults.append(f"{hop.key}: is not a constructor")
        if not hop.bases & _CONNECTION_BASES:
            faults.append(f"{hop.key}: its class names neither of {sorted(_CONNECTION_BASES)}")
        for call in calls:
            where = f"{hop.key}: {ast.unparse(call.func)} at line {call.lineno}"
            if not _guard_call_cannot_credit(call, hop.node, defs, builders):
                faults.append(f"{where} may credit a CRL on the relaxed hop")
            connection = _keyword(call, "connection")
            if connection is None or _is_none(connection):
                faults.append(f"{where} names no connection")
    return faults


@functools.cache
def _package_sources() -> dict[str, str]:
    return {
        path.relative_to(_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(_PACKAGE.rglob("*.py"))
    }


@functools.cache
def _package_reach() -> _Reach:
    return _relaxed_reach(_package_sources(), frozenset(_NOT_RELAXED))


def _not_relaxed_faults(reach: _Reach, not_relaxed: dict[str, tuple[str, str | None]]) -> list[str]:
    """Every way a site in ``not_relaxed`` fails its exemption: the one reached name it reads is not
    its builder, a call to that builder does not pass its keyword as ``True``, or, for a site with
    no keyword, it calls the builder at all. A stop site passes no alias on, so this is the only
    read of it."""
    faults: list[str] = []
    for key, (builder, keyword) in not_relaxed.items():
        node = reach.units[key].node
        other = sorted(_loads(node) & reach.names - {builder})
        if other:
            faults.append(f"{key}: reads {other} beside {builder}")
        calls = call_sites(node, builder)
        if keyword is None:
            faults.extend(f"{key}: calls {builder} at line {call.lineno}" for call in calls)
            continue
        if not calls:
            faults.append(f"{key}: no longer calls {builder}")
        for call in calls:
            value = _keyword(call, keyword)
            if not (isinstance(value, ast.Constant) and value.value is True):
                faults.append(f"{key}: {builder} at line {call.lineno} lacks {keyword}=True")
    return faults


def test_every_reach_of_relax_verify_expiry_is_a_listed_builder_hop_or_exemption() -> None:
    """Every site in ``messagefoundry/`` that reaches ``relax_verify_expiry`` by name, directly or
    through a builder that hands the relaxed context or opener on, is listed above. An import alias
    of any such name is followed. A new site fails here until it is read and listed, and a listed
    one that no longer reaches it fails too. A context relaxed by another means is outside it, and
    so is a builder with no name to follow: a builder listed here must have one."""
    reach = _package_reach()
    expected = _RELAXING_BUILDERS | _RELAXED_HOPS | _NOT_RELAXED.keys()
    assert sorted(reach.units.keys() - expected) == [], "unlisted reach of relax_verify_expiry"
    assert sorted(expected - reach.units.keys()) == [], "listed sites that no longer reach it"
    hops = sorted(key for key, unit in reach.units.items() if _guard_calls(unit.node))
    assert hops == sorted(_RELAXED_HOPS), "a builder runs a guard, or a hop runs none"
    # 7 builders when this floor was set (vault BACKLOG #5086), so the walk below cannot pass on an
    # emptied list.
    assert len(_RELAXING_BUILDERS) >= 7, f"only {len(_RELAXING_BUILDERS)} relaxing builders"
    # A module's top-level code has no name a caller reads, so listing it would end the trace.
    nameless = sorted(key for key in _RELAXING_BUILDERS if not reach.units[key].alias)
    assert not nameless, f"builders with no name to follow: {nameless}"
    faults = _not_relaxed_faults(reach, _NOT_RELAXED)
    assert not faults, faults


def test_every_relaxed_hop_is_a_connection_whose_guard_call_cannot_credit_a_crl() -> None:
    """Each hop above is the ``__init__`` of a class naming a connection base, and each of its guard
    calls passes a ``connection`` argument and, read at the call or one wrapper down, either hands
    ``RevocationHopGuard.capture`` its relaxed context, passes ``expiry_relaxed`` as true on a
    relaxed hop, or hands no context there. ``capture`` gives no CRL credit in any of the three
    (vault BACKLOG #5086); what it cannot see is a different, unrelaxed context handed over without
    the flag, which is what this fails on. It reads shapes, as :func:`_holds_when_relaxed` and
    :func:`_from_relaxing_builder` say."""
    reach = _package_reach()
    hops = [reach.units[key] for key in sorted(_RELAXED_HOPS)]
    faults = _handoff_faults(_package_sources(), hops, reach.names)
    assert not faults, faults


_SYNTHETIC_HOP = """
class Dest(DestinationConnector):
    def __init__(self, config):
        self._ssl = _relaxed(config.settings)
        self._other = ssl.create_default_context()
        relaxed = skips_validity_period(self._ssl)
        PRE
        RevocationHopGuard.capture(
            host="h", cell="c", description="d", attested=False, connection=config.name,
            context=HANDOFF, expiry_relaxed=FLAG,
        ).enforce_construction()
        EXTRA


def _relaxed(s):
    ctx = ssl.create_default_context()
    if s.get("tls_allow_expired"):
        relax_verify_expiry(ctx, host="h")
    return ctx
"""


def test_a_relaxed_hop_whose_guard_call_could_credit_a_crl_is_flagged() -> None:
    """The positive controls for the three ways a direct ``capture`` call passes. A synthetic hop
    reaches ``relax_verify_expiry`` through a builder. Handing its guard some other context with no
    flag is faulted, and each pass is shown clean beside a fault that undoes it: the flag read off
    the relaxation (and negated), the relaxed context itself (and reassigned from elsewhere), and
    ``None if relaxed else ...`` (and negated)."""
    for handoff, flag, extra, faulted in (
        ("self._other", "False", "pass", True),
        # Bound before the call: the reader is order-blind, so after the call (below) is the same.
        ("self._ssl", "False", "PRE:self._ssl = ssl.create_default_context()", True),
        ("self._other", "relaxed", "pass", False),
        ("self._other", "not relaxed", "pass", True),
        # A flag asked of the context it hands over says nothing capture does not already read.
        ("self._other", "skips_validity_period(self._other)", "pass", True),
        ("self._other", "relaxed", "relaxed = False", True),
        ("self._ssl", "False", "pass", False),
        ("self._ssl", "False", "self._ssl = ssl.create_default_context()", True),
        ("self._ssl", "False", "for self._ssl in [ssl.create_default_context()]: pass", True),
        ("self._ssl", "False", "with open_ctx() as self._ssl: pass", True),
        ("None if relaxed else self._other", "False", "pass", False),
        ("None if not relaxed else self._other", "False", "pass", True),
        ("None if skips_validity_period(self._other) else self._other", "False", "pass", True),
    ):
        text = _SYNTHETIC_HOP.replace("HANDOFF", handoff).replace("FLAG", flag)
        pre, post = (extra[4:], "pass") if extra.startswith("PRE:") else ("pass", extra)
        sources = {"fake.py": text.replace("PRE", pre).replace("EXTRA", post)}
        reach = _relaxed_reach(sources, frozenset())
        assert sorted(reach.units) == ["fake.py::Dest.__init__", "fake.py::_relaxed"], reach
        faults = _handoff_faults(sources, [reach.units["fake.py::Dest.__init__"]], reach.names)
        assert bool(faults) is faulted, (handoff, flag, extra, faults)
        if faulted:
            assert faults == [
                "fake.py::Dest.__init__: RevocationHopGuard.capture at line 8 may credit a CRL on "
                "the relaxed hop"
            ], faults
    # A context passed through ** is not read, so it is a fault even beside the relaxed one.
    text = _SYNTHETIC_HOP.replace("HANDOFF", "self._ssl").replace("FLAG", "False")
    text = text.replace("expiry_relaxed=False,", '**{"context": self._other},')
    sources = {"fake.py": text.replace("PRE", "pass").replace("EXTRA", "pass")}
    reach = _relaxed_reach(sources, frozenset())
    faults = _handoff_faults(sources, [reach.units["fake.py::Dest.__init__"]], reach.names)
    assert faults == [
        "fake.py::Dest.__init__: RevocationHopGuard.capture at line 8 may credit a CRL on the "
        "relaxed hop"
    ], faults


_SYNTHETIC_WRAPPED = """
class Dest(DestinationConnector):
    def __init__(self, config):
        self._opener = _relaxed(config.settings)
        self._other = build_strict_opener()
        refuse_unrevoked_verified_hop(opener=OPENER, connection=config.name, expiry_relaxed=FLAG)

    def reconnect(self):
        RevocationHopGuard.capture(host="h", cell="c", description="d", attested=False,
                                   connection="n", context=self._ssl)


def refuse_unrevoked_verified_hop(*, opener, connection, expiry_relaxed=False):
    RevocationHopGuard.capture(host="h", cell="c", description="d", attested=False,
                               connection=connection, context=None if opener is None else opener,
                               expiry_relaxed=expiry_relaxed)
    EXTRA


class Src(SourceConnector):
    def __init__(self, config):
        self._ssl = _relaxed(config.settings, server=True)
        SECOND


def _relaxed(s, server=False):
    ctx = ssl.create_default_context()
    if s.get("tls_allow_expired"):
        relax_verify_expiry(ctx, host="h")
    return ctx
"""

#: Visited before ``fake.py`` and parsed on the first pass, as a comment names the function, so
#: the alias it imports is of a name that joins the reach only later.
_SYNTHETIC_ALIAS = """
# relax_verify_expiry
from fake import _relaxed as _r


def _aliased(s):
    return _r(s)
"""


def test_the_wrapper_alias_constructor_and_exemption_reads_each_fail_on_a_synthetic_fault() -> None:
    """The controls for the reads the first one does not reach. One wrapper down: some other opener
    forwarded with no flag is faulted, and each pass is clean (the flag bound off the relaxation,
    the relaxed opener itself, ``None if relaxed else ...``); a wrapper making a second guard call
    is faulted. A hop that is not a constructor is faulted. An import alias of a builder is followed
    whatever order the files are read in. An exemption that also reads ``relax_verify_expiry`` is
    faulted, and so is a read-only exemption that calls its builder."""
    hop = "fake.py::Dest.__init__"
    relaxed = 'config.settings.get("tls_allow_expired")'
    for opener, flag, extra, faulted in (
        ("self._other", "False", "pass", True),
        ("self._other", relaxed, "pass", False),
        ("self._opener", "False", "pass", False),
        (f"None if {relaxed} else self._other", "False", "pass", False),
        (f"None if {relaxed} else self._other", "False", "_guard_ftps_revocation(o)", True),
        # The wrapper rebinds the parameter, so the relaxed opener it was handed is not what it hands.
        ("self._opener", "False", "opener = build_strict_opener()", True),
    ):
        text = _SYNTHETIC_WRAPPED.replace("OPENER", opener).replace("FLAG", flag)
        sources = {"fake.py": text.replace("EXTRA", extra).replace("SECOND", "pass")}
        reach = _relaxed_reach(sources, frozenset({"fake.py::Src.__init__"}))
        faults = _handoff_faults(sources, [reach.units[hop]], reach.names)
        assert bool(faults) is faulted, (opener, flag, extra, faults)
        if faulted:
            assert faults == [
                f"{hop}: refuse_unrevoked_verified_hop at line 6 may credit a CRL on the relaxed hop"
            ], faults
    # The wrapper's else branch must be the parameter or take it: a fresh context there is faulted.
    fresh = _SYNTHETIC_WRAPPED.replace(
        "context=None if opener is None else opener", "context=None if opener is None else fresh()"
    )
    for wrapped, faulted in ((_SYNTHETIC_WRAPPED, False), (fresh, True)):
        text = wrapped.replace("OPENER", "self._opener").replace("FLAG", "False")
        sources = {"fake.py": text.replace("EXTRA", "pass").replace("SECOND", "pass")}
        reach = _relaxed_reach(sources, frozenset({"fake.py::Src.__init__"}))
        assert bool(_handoff_faults(sources, [reach.units[hop]], reach.names)) is faulted
    # A method wrapper binds its arguments after self: here the unrelaxed one reaches capture.
    method_hop = """
class Dest(DestinationConnector):
    def __init__(self, config):
        self._ssl = _relaxed(config.settings)
        self.refuse_unrevoked_verified_hop(FIRST, SECOND, connection=config.name)

    def refuse_unrevoked_verified_hop(self, context, spare, connection):
        RevocationHopGuard.capture(host="h", cell="c", description="d", attested=False,
                                   connection=connection, context=context)


def _relaxed(s):
    ctx = ssl.create_default_context()
    if s.get("tls_allow_expired"):
        relax_verify_expiry(ctx, host="h")
    return ctx
"""
    for first, second, faulted in (
        ("self._ssl", "self._other", False),
        ("self._other", "self._ssl", True),
    ):
        sources = {"fake.py": method_hop.replace("FIRST", first).replace("SECOND", second)}
        reach = _relaxed_reach(sources, frozenset())
        faults = _handoff_faults(sources, [reach.units[hop]], reach.names)
        assert bool(faults) is faulted, (first, second, faults)
    # A hop on a method other than __init__ is not a constructor, so it is faulted as one.
    method = ast.parse(_SYNTHETIC_WRAPPED).body[0]
    assert isinstance(method, ast.ClassDef)
    bases = frozenset({"DestinationConnector"})
    reconnect = _Unit("fake.py::Dest.reconnect", "reconnect", method.body[1], bases)
    faults = _handoff_faults({}, [reconnect], frozenset())
    assert "fake.py::Dest.reconnect: is not a constructor" in faults, faults
    # The alias file sorts first and is parsed on the first pass, before _relaxed is reached.
    clean = (
        _SYNTHETIC_WRAPPED.replace("OPENER", "None")
        .replace("FLAG", "False")
        .replace("EXTRA", "pass")
    )
    sources = {"a.py": _SYNTHETIC_ALIAS, "fake.py": clean.replace("SECOND", "pass")}
    stop: dict[str, tuple[str, str | None]] = {"fake.py::Src.__init__": ("_relaxed", "server")}
    reach = _relaxed_reach(sources, frozenset(stop))
    assert "a.py::_aliased" in reach.units, sorted(reach.units)
    assert _not_relaxed_faults(reach, stop) == []
    second = clean.replace("SECOND", 'relax_verify_expiry(self._ssl, host="h")')
    sources = {"fake.py": second}
    reach = _relaxed_reach(sources, frozenset(stop))
    assert _not_relaxed_faults(reach, stop) == [
        "fake.py::Src.__init__: reads ['relax_verify_expiry'] beside _relaxed"
    ]
    # Two units sharing a key (a property's getter and setter) are each read: the getter is reached.
    prop = """
class Box:
    @property
    def ctx(self):
        c = ssl.create_default_context()
        relax_verify_expiry(c, host="h")
        return c

    @ctx.setter
    def ctx(self, value):
        self._c = value
"""
    reach = _relaxed_reach({"p.py": prop}, frozenset())
    assert sorted(reach.units) == ["p.py::Box.ctx"], sorted(reach.units)
    # A dunder method is followed through its class, the name a caller loads.
    post = """
class Box:
    def __post_init__(self):
        relax_verify_expiry(self.c, host="h")


def build(s):
    return Box(s)
"""
    reach = _relaxed_reach({"p.py": post}, frozenset())
    assert reach.units["p.py::Box.__post_init__"].alias == "Box"
    assert "p.py::build" in reach.units, sorted(reach.units)
    # A read-only exemption: reading the builder's name is clean, calling it is faulted.
    read_only: dict[str, tuple[str, str | None]] = {"fake.py::Src.__init__": ("_relaxed", None)}
    call = "self._ssl = _relaxed(config.settings, server=True)"
    line = clean.splitlines().index(f"        {call}") + 1
    for text, expected in (
        (clean.replace(call, "self._code = _relaxed.__code__"), []),
        (clean, [f"fake.py::Src.__init__: calls _relaxed at line {line}"]),
    ):
        sources = {"fake.py": text.replace("SECOND", "pass")}
        reach = _relaxed_reach(sources, frozenset(read_only))
        assert _not_relaxed_faults(reach, read_only) == expected, text
