# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 3.7.5 — the CSP-ENFORCEMENT canary, its expected-violation filter, and the degrade contract.

The console relies on browser features that a non-conforming client can silently ignore. Before this,
exactly one of them was actively feature-detected (``window.isSecureContext``), and that one is
correctly INERT on the scored loopback posture because ``http://127.0.0.1`` is itself a secure
context — so nothing detectable ever fired on the default deployment.

The canary is an UN-NONCED external script the shell loads whenever a per-response nonce CSP is bound.
Under ``script-src 'nonce-…' 'strict-dynamic'`` an enforcing browser refuses it, so its global stays
undefined; a browser that does not enforce CSP runs it and the nonce'd detect raises a visible
``role="alert"`` banner. These tests pin the three properties that make that a real control:

* it is emitted ONLY when a nonce is bound (byte-identity everywhere else — the opt-out and the
  cleartext non-loopback legs must stay unchanged), and it must NOT itself be nonced or the enforcing
  browser would run it and the detect would never fire;
* the detect script and the canary execute in the right ORDER, and the detect reads the canary's flag;
* the report route recognises the canary's own violation by SAME-ORIGIN blocked URL — scheme AND
  authority — per report entry, so neither a foreign host's copy of that path, nor a scheme-downgraded
  load of our own, nor a real violation batched behind the canary in one Reporting-API POST is
  swallowed;
* the INVERSE detect ships: a browser that enforces CSP without understanding nonce sources (or one
  with JavaScript disabled) runs no script at all, so the warning for that case is server-rendered and
  removed from view by a nonce'd mark script — fail-visible rather than fail-silent, and without
  crying wolf on a healthy client whose cached stylesheet predates the hiding rule;
* the degrade contract enumerates all THREE sets it claims to — every browser-security header the
  console (and the engine, on /ui responses) emits, every client-side feature the console
  feature-detects, and the session cookie's security attributes — each derived from the CODE, not from
  a literal in this file. A header-only derivation cannot notice a missing WebAuthn bucket.
"""

from __future__ import annotations

import logging
import os
import re
import warnings
from pathlib import Path

import httpx
import pytest

import messagefoundry.api.app as engine_app
import messagefoundry.api.header_floor as engine_header_floor
import messagefoundry_webconsole
import messagefoundry_webconsole._auth as webconsole_auth
import messagefoundry_webconsole._security as security
from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._html import (
    _SCRIPTS_RUNNING_MARK_JS,
    CSP_PROBE_SRC,
    SCRIPTS_BLOCKED_BANNER_ID,
    SCRIPTS_OK_CLASS,
)
from messagefoundry_webconsole.routes.core import _is_expected_csp_probe_report

_NONCE_RE = re.compile(r"script-src 'nonce-([A-Za-z0-9_-]+)' 'strict-dynamic'")
PROBE_TAG = '<script src="/ui/static/csp-probe.js">'
PROBE_TAG_RE = re.compile(r"<script[^>]*csp-probe\.js[^>]*>")
PROBE_FLAG = "window.__mfCspProbe"
DEGRADED_BANNER_ID = "mf-csp-degraded-banner"
_STATIC = Path(messagefoundry_webconsole.__file__).parent / "static"


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, *, scheme: str, loopback: bool = False
) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=True, loopback=loopback)
    )
    return httpx.AsyncClient(transport=transport, base_url=f"{scheme}://t")


# --- emission is gated on a bound nonce -----------------------------------------------------------


async def test_canary_and_detect_ship_when_a_nonce_is_bound(engine: Engine) -> None:
    """Over effective-https the shell carries BOTH halves: the un-nonced probe tag and the nonce'd
    detect that reads its flag and can raise the degraded-hardening banner."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r = await c.get("/ui/login")
        nonce_match = _NONCE_RE.search(r.headers["content-security-policy"])
        assert nonce_match, r.headers["content-security-policy"]
        assert PROBE_TAG in r.text
        assert PROBE_FLAG in r.text
        assert DEGRADED_BANNER_ID in r.text
        assert "role" in r.text and "does not enforce Content-Security-Policy" in r.text


async def test_canary_is_emitted_on_the_default_loopback_posture(engine: Engine) -> None:
    """The scored posture: the loopback secure-context binds a nonce (ADR 0143), so the canary — the
    one detect that is NOT inert there — ships. This is the whole point of the cell."""
    service = await _service(engine)
    async with _client(engine, service, scheme="http", loopback=True) as c:
        r = await c.get("/ui/login")
        assert _NONCE_RE.search(r.headers["content-security-policy"])
        assert PROBE_TAG in r.text


async def test_canary_carries_no_nonce(engine: Engine) -> None:
    """Load-bearing: if the probe tag were nonced, an ENFORCING browser would execute it and the
    detect would fire on every conforming browser — inverting the signal."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r = await c.get("/ui/login")
        nonce_match = _NONCE_RE.search(r.headers["content-security-policy"])
        assert nonce_match
        nonce = nonce_match.group(1)
        assert PROBE_TAG in r.text
        # the ONLY script tags carrying the nonce are app.js and the inline detect
        assert f'<script src="/ui/static/csp-probe.js" nonce="{nonce}"' not in r.text
        assert f'<script src="/ui/static/app.js" defer nonce="{nonce}">' in r.text


async def test_canary_executes_before_the_detect_that_reads_it(engine: Engine) -> None:
    """Document order matters: the probe is parser-blocking (no defer/async) and precedes the inline
    detect, so the flag is settled before the detect runs. Located by REGEX over the emitted tag — so
    this fails if a future edit adds defer/async/a nonce to it, or reorders the two."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        body = (await c.get("/ui/login")).text
        match = PROBE_TAG_RE.search(body)
        assert match, body
        tag = match.group(0)
        for forbidden in ("defer", "async", "nonce="):
            assert forbidden not in tag, tag
        assert match.start() < body.index(DEGRADED_BANNER_ID)


async def test_no_nonce_shell_is_byte_identical(engine: Engine) -> None:
    """Cleartext, non-loopback: no nonce is bound, so NO detect ships. Emitting the canary here
    would be worse than useless — the static ``script-src 'self'`` CSP would ALLOW it, so the flag
    would be set on a perfectly conforming browser and the banner would be a lie."""
    service = await _service(engine)
    async with _client(engine, service, scheme="http") as c:
        r = await c.get("/ui/login")
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert PROBE_TAG not in r.text
        assert PROBE_FLAG not in r.text
        assert DEGRADED_BANNER_ID not in r.text
        assert SCRIPTS_BLOCKED_BANNER_ID not in r.text
        assert SCRIPTS_OK_CLASS not in r.text


# --- the INVERSE detect: CSP enforced, nonce sources unsupported (every script blocked) ------------


async def test_scripts_blocked_banner_is_server_rendered_and_script_hidden(engine: Engine) -> None:
    """A browser that ENFORCES CSP but does not understand ``'nonce-…'``/``'strict-dynamic'`` blocks
    every script — app.js, both detects, and the 14.3.1 session watchdog — so a script-RAISED banner
    could never render. The warning must therefore come from the SERVER and be removed by the script,
    not the other way round: fail-visible."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r = await c.get("/ui/login")
        body = r.text
        assert SCRIPTS_BLOCKED_BANNER_ID in body
        assert 'role="alert"' in body
        # the banner ELEMENT is plain server-rendered markup INSIDE <body> — no script needed to show
        # it. Matched on the id ATTRIBUTE, because the id also appears earlier, in the head mark
        # script that hides the node directly as a belt against a stale cached stylesheet.
        banner_at = body.index(f'id="{SCRIPTS_BLOCKED_BANNER_ID}"')
        assert body.index("<body>") < banner_at
        # the mark that hides it is a NONCE'D script in <head>, so a script-blocked client never sets it
        nonce_match = _NONCE_RE.search(r.headers["content-security-policy"])
        assert nonce_match
        mark = (
            f'<script nonce="{nonce_match.group(1)}">' + "(function(){try{document.documentElement"
        )
        assert mark in body, body
        assert body.index(mark) < body.index("</head>")


def test_the_scripts_blocked_banner_is_hidden_by_css_not_by_js() -> None:
    """Load-bearing: ``style-src 'self'`` keeps working on exactly the clients whose ``script-src``
    blocks everything, so the hiding rule must live in the stylesheet. If app.js removed the banner
    instead, the CSP-enforcing/nonce-blind client would keep... nothing: the banner would show, but a
    JS-only rule would also mean a broken app.js silently hides a real degradation."""
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    js = (_STATIC / "app.js").read_text(encoding="utf-8")
    rule = f".{SCRIPTS_OK_CLASS} #{SCRIPTS_BLOCKED_BANNER_ID}"
    assert rule in css, css[-800:]
    assert "display: none" in css.split(rule, 1)[1].split("}", 1)[0]
    assert SCRIPTS_BLOCKED_BANNER_ID not in js  # never removed/hidden from script


def test_the_mark_script_also_hides_the_banner_directly() -> None:
    """The BELT against a warn control that cries wolf on a HEALTHY client.

    The class stamp above is the load-bearing path — it is the only one that can work when no script
    runs — but it is only effective if the stylesheet the browser has actually carries the hiding
    rule. The link has no cache-buster (adding one would break the deliberate byte-identity of the
    no-nonce shell) and the static mount emits etag/last-modified but no ``Cache-Control``, so a
    browser applying heuristic freshness can pair post-upgrade HTML with a pre-upgrade ``app.css`` and
    render the red "not running the console's scripts" alert on a perfectly conforming browser. A warn
    control that fires on healthy clients trains operators to ignore it — the opposite of what 3.7.5
    asks for — so the mark script ALSO hides the node directly.
    """
    mark = str(_SCRIPTS_RUNNING_MARK_JS)
    assert SCRIPTS_OK_CLASS in mark
    assert f"getElementById('{SCRIPTS_BLOCKED_BANNER_ID}')" in mark
    assert "style.display='none'" in mark
    # the class stamp comes FIRST: it is the path that survives a stale stylesheet AND a slow parse
    assert mark.index(SCRIPTS_OK_CLASS) < mark.index("getElementById")
    # the banner lives in <body>; this script runs during HEAD parsing, so an undeferred
    # getElementById would find nothing and the belt would be purely decorative
    assert "DOMContentLoaded" in mark
    assert "readyState" in mark


async def test_the_rendered_shell_carries_the_belt(engine: Engine) -> None:
    """…and the belt reaches the wire, not just the constant."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        body = (await c.get("/ui/login")).text
        assert f"getElementById('{SCRIPTS_BLOCKED_BANNER_ID}')" in body
        assert body.index(f"getElementById('{SCRIPTS_BLOCKED_BANNER_ID}')") < body.index("</head>")


async def test_opt_out_suppresses_the_canary(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The org opt-out reverts to the pre-hardening shell over https too — canary included."""
    monkeypatch.setenv("MEFOR_WEBCONSOLE_DISABLE_BROWSER_HARDENING", "1")
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r = await c.get("/ui/login")
        assert PROBE_TAG not in r.text
        assert PROBE_FLAG not in r.text
        assert SCRIPTS_BLOCKED_BANNER_ID not in r.text


async def test_probe_asset_is_served_and_is_inert(engine: Engine) -> None:
    """The probe must actually load on a non-enforcing browser (a 404 would make the detect silently
    dead), and it must do nothing but set the flag."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        r = await c.get(CSP_PROBE_SRC)
        assert r.status_code == 200
        assert "window.__mfCspProbe = true;" in r.text
        for forbidden in ("fetch(", "XMLHttpRequest", "document.", "eval("):
            assert forbidden not in r.text


# --- the expected-violation filter ----------------------------------------------------------------


def test_probe_report_is_recognised_in_both_delivery_shapes() -> None:
    assert _is_expected_csp_probe_report(
        {"violated-directive": "script-src-elem", "blocked-uri": CSP_PROBE_SRC}, "https://t"
    )
    assert _is_expected_csp_probe_report(
        {"blocked-uri": f"https://console.example{CSP_PROBE_SRC}"}, "https://console.example"
    )
    # scheme + host comparison is case-insensitive on both sides (RFC 3986 §3.1/§3.2.2)
    assert _is_expected_csp_probe_report(
        {"blocked-uri": f"HTTPS://Console.Example{CSP_PROBE_SRC}"}, "https://console.example"
    )
    assert _is_expected_csp_probe_report(
        {"effectiveDirective": "script-src", "blockedURL": CSP_PROBE_SRC}, "https://t"
    )
    # a cache-buster query cannot smuggle a different URL past the path match, and does not defeat it
    assert _is_expected_csp_probe_report({"blocked-uri": CSP_PROBE_SRC + "?v=2"}, "https://t")


def test_the_filter_does_not_swallow_a_real_violation() -> None:
    """The security-critical half: an injected INLINE script's report — the shape a real XSS attempt
    produces — must NOT be classified as expected, nor must any other blocked URL, nor a FOREIGN
    host's copy of the probe path (which is attacker-selectable on an attacker-hosted payload)."""
    assert not _is_expected_csp_probe_report(
        {"violated-directive": "script-src-elem", "blocked-uri": "inline"}, "https://t"
    )
    assert not _is_expected_csp_probe_report({"blocked-uri": "eval"}, "https://t")
    assert not _is_expected_csp_probe_report(
        {"blocked-uri": "https://evil.example/ui/static/csp-probe.js.js"}, "https://t"
    )
    assert not _is_expected_csp_probe_report(
        {"blockedURL": "https://evil.example/payload.js"}, "https://t"
    )
    # SAME PATH, FOREIGN HOST — the case a path-only match would have swallowed
    assert not _is_expected_csp_probe_report(
        {"blocked-uri": f"https://evil.example{CSP_PROBE_SRC}"}, "https://t"
    )
    # a different PORT is a different origin too
    assert not _is_expected_csp_probe_report(
        {"blocked-uri": f"https://t:8443{CSP_PROBE_SRC}"}, "https://t"
    )
    # SAME AUTHORITY, DIFFERENT SCHEME. "Same-origin" includes the scheme (RFC 6454 §4), so an
    # http:// load of our own probe path on an https deployment is NOT our canary — it is a mixed
    # content / downgrade signal and must reach the operational log. An authority-only comparison
    # (the shape this filter had) silently dropped it to DEBUG.
    assert not _is_expected_csp_probe_report(
        {"blocked-uri": f"http://t{CSP_PROBE_SRC}"}, "https://t"
    )
    assert not _is_expected_csp_probe_report(
        {"blocked-uri": f"https://t{CSP_PROBE_SRC}"}, "http://t"
    )
    # a scheme-relative URL carries an authority but no scheme -> cannot be confirmed same-origin
    assert not _is_expected_csp_probe_report({"blocked-uri": f"//t{CSP_PROBE_SRC}"}, "https://t")
    # unknown origin fails CLOSED: an absolute URL cannot be confirmed same-origin, so it warns
    assert not _is_expected_csp_probe_report({"blocked-uri": f"https://t{CSP_PROBE_SRC}"}, None)
    # hostile / empty shapes never raise and are never "expected"
    assert not _is_expected_csp_probe_report({}, "https://t")
    assert not _is_expected_csp_probe_report({"blocked-uri": 1234}, "https://t")


async def test_a_scheme_downgraded_probe_url_still_warns_through_the_route(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """End-to-end companion to the unit case above: over https the SAME host and path on ``http://``
    must not be filtered. This is the route deriving its own origin from the request, so it fails if
    ``_request_origin`` reverts to an authority-only comparison."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        with caplog.at_level(logging.WARNING, logger="messagefoundry_webconsole.routes.core"):
            r = await c.post(
                "/ui/csp-report",
                json={"csp-report": {"blocked-uri": f"http://t{CSP_PROBE_SRC}"}},
            )
            assert r.status_code == 204
            warnings = [rec for rec in caplog.records if rec.levelno >= logging.WARNING]
            assert warnings and "http://t" in warnings[0].getMessage()


async def test_report_route_tags_the_canary_and_still_warns_on_a_real_violation(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """End-to-end through the route: the canary's own report does not reach WARNING (no per-page-load
    log flood on every conforming browser), while an inline-script violation still does."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        with caplog.at_level(logging.WARNING, logger="messagefoundry_webconsole.routes.core"):
            expected = await c.post(
                "/ui/csp-report",
                json={
                    "csp-report": {
                        "document-uri": "https://t/ui",
                        "violated-directive": "script-src-elem",
                        "blocked-uri": f"https://t{CSP_PROBE_SRC}",
                    }
                },
            )
            assert expected.status_code == 204
            assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="messagefoundry_webconsole.routes.core"):
            real = await c.post(
                "/ui/csp-report",
                json={
                    "csp-report": {
                        "document-uri": "https://t/ui",
                        "violated-directive": "script-src-elem",
                        "blocked-uri": "inline",
                    }
                },
            )
            assert real.status_code == 204
            warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
            assert warnings and "blocked-uri=inline" in warnings[0].getMessage()


async def test_a_real_violation_batched_behind_the_canary_still_warns(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The DEFAULT Reporting-API path, not an edge case: the canary fires once per page load on every
    conforming browser and the Reporting API batches per endpoint, so a genuine violation raised on
    the same page load is delivered in the SAME POST, behind the canary's report. Classifying the
    batch by its first entry would drop the real one to DEBUG — a detection hole introduced by a
    detection improvement. The warning must also NAME the real entry, not the canary."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        with caplog.at_level(logging.WARNING, logger="messagefoundry_webconsole.routes.core"):
            batched = await c.post(
                "/ui/csp-report",
                json=[
                    {"body": {"blockedURL": f"https://t{CSP_PROBE_SRC}"}},
                    {"body": {"blockedURL": "inline", "documentURL": "https://t/ui/messages"}},
                ],
            )
            assert batched.status_code == 204
            warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
            assert warnings, "a real violation batched behind the canary must still WARN"
            message = warnings[0].getMessage()
            assert "blocked-uri=inline" in message
            assert "csp-probe.js" not in message  # the summary names the REAL entry


async def test_a_foreign_hosts_probe_path_is_not_filtered(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The blocked path is attacker-selectable on an attacker-hosted payload, so an identical path on
    a foreign origin must reach WARNING like any other blocked script."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        with caplog.at_level(logging.WARNING, logger="messagefoundry_webconsole.routes.core"):
            r = await c.post(
                "/ui/csp-report",
                json={"csp-report": {"blocked-uri": f"https://evil.example{CSP_PROBE_SRC}"}},
            )
            assert r.status_code == 204
            warnings = [rec for rec in caplog.records if rec.levelno >= logging.WARNING]
            assert warnings and "evil.example" in warnings[0].getMessage()


async def test_only_all_canary_batches_are_silenced(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The inverse of the batch test, so the filter is a scalpel: a batch whose entries are ALL the
    canary's own report stays out of the operational log."""
    service = await _service(engine)
    async with _client(engine, service, scheme="https") as c:
        with caplog.at_level(logging.WARNING, logger="messagefoundry_webconsole.routes.core"):
            r = await c.post(
                "/ui/csp-report",
                json=[
                    {"body": {"blockedURL": f"https://t{CSP_PROBE_SRC}"}},
                    {"body": {"blockedURL": CSP_PROBE_SRC}},
                ],
            )
            assert r.status_code == 204
            assert not [rec for rec in caplog.records if rec.levelno >= logging.WARNING]


# --- the documented degrade contract --------------------------------------------------------------


#: The closed vocabulary of BROWSER-SECURITY response headers. A header name from this list that
#: appears anywhere in the code reaching a /ui response MUST be bucketed by the degrade contract
#: (detected-and-warned, or degrades-silently with a named compensating control) — that is the
#: invariant ASVS 3.7.5 rests on. The vocabulary is deliberately WIDER than what ships today: the
#: point is that the next one shipped (Permissions-Policy, COEP, Report-To…) reds CI until it is
#: bucketed, instead of quietly joining an already-stale enumeration.
BROWSER_SECURITY_HEADERS = (
    "Cache-Control",
    "Clear-Site-Data",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Origin-Agent-Cluster",
    "Permissions-Policy",
    "Referrer-Policy",
    "Report-To",
    "Reporting-Endpoints",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-Permitted-Cross-Domain-Policies",
    "X-XSS-Protection",
)

#: The closed vocabulary of CLIENT-SIDE browser security features a page script can feature-detect off
#: ``window``. Exactly the same design as :data:`BROWSER_SECURITY_HEADERS`, for the OTHER half of the
#: contract: a header vocabulary structurally cannot notice a missing ``window.PublicKeyCredential``
#: bucket, because WebAuthn is not a header — and that omission is precisely what 3.7.5 measures (the
#: console disables the passkey button and prints "This browser does not support passkeys." with no
#: documented contract entry). Deliberately WIDER than what is read today, so the NEXT detect added to
#: ``app.js`` or the page shell reds CI until the degrade contract buckets it.
BROWSER_SECURITY_JS_FEATURES = (
    "CookieStore",
    "CredentialsContainer",
    "PublicKeyCredential",
    "ReportingObserver",
    "Sanitizer",
    "SecurityPolicyViolationEvent",
    "SubtleCrypto",
    "crossOriginIsolated",
    "isSecureContext",
    "trustedTypes",
)

#: Session-cookie SECURITY attributes: ``(token in the code that writes the cookie, token the degrade
#: contract must name)``. A page script cannot observe any of them (``HttpOnly`` is what makes that
#: true), so they can only ever degrade silently — but "undetectable" is a reason to DOCUMENT the
#: compensating control, not a reason to leave the attribute out of the enumeration.
COOKIE_SECURITY_ATTRIBUTES = (
    ("httponly=True", "`HttpOnly`"),
    ('samesite="strict"', "`SameSite`"),
    ("secure=secure", "`Secure`"),
    ("__Host-", "`__Host-`"),
)

#: The first cell of the degrade-contract row that must carry the cookie attributes.
COOKIE_ATTRIBUTE_ROW_LABEL = "Session-cookie security attributes"

_HEADER_WRITE_RE = re.compile(r'headers\[\s*"([A-Za-z0-9-]+)"\s*\]\s*=')
_WINDOW_READ_RE = re.compile(r"window\.([A-Za-z_$][A-Za-z0-9_$]*)")
_PACKAGE_DIR = Path(messagefoundry_webconsole.__file__).parent


class RunbookContractUnenforced(UserWarning):
    """The runbook is absent from this checkout, so the code-vs-runbook comparisons are inert.

    A warning rather than only a skip reason because a skip is invisible: the CI step runs ``-q``
    with no ``-rs``, so three skips print as three ``s`` characters among hundreds and the run still
    reads as clean. This lands in pytest's warnings summary, which prints even under ``-q``.

    Adopted from ``tests/test_threat_model_doc_drift.py`` (BACKLOG #1043), which solved this exact
    problem for the same reason -- a control that cannot report its own inertness is ADR 0158's
    class 2.
    """


#: Announce once per session, not once per inert test.
_RUNBOOK_ABSENCE_ANNOUNCED = False

#: Point this at a copy of the runbook (e.g. the vault working tree) to enforce the comparison half
#: from a checkout that does not carry it.
_RUNBOOK_ENV = "MEFOR_WEBCONSOLE_RUNBOOK"
#: Set truthy where the runbook is EXPECTED to be present. Absence is then a failure, not a notice.
_REQUIRE_RUNBOOK_ENV = "MEFOR_REQUIRE_WEBCONSOLE_RUNBOOK"


def _runbook_path() -> Path:
    """Where the runbook is read from — the env override, else the in-tree (vault) location."""
    override = os.environ.get(_RUNBOOK_ENV, "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "docs/security/OFF-LOOPBACK-DEPLOYMENT.md"


def _announce_runbook_absence(path: Path) -> None:
    global _RUNBOOK_ABSENCE_ANNOUNCED
    if _RUNBOOK_ABSENCE_ANNOUNCED:
        return
    _RUNBOOK_ABSENCE_ANNOUNCED = True
    warnings.warn(
        RunbookContractUnenforced(
            f"{path} is absent from this checkout (docs/security/** is withheld from public "
            "checkouts — deny-listed and vaulted), so the code-vs-runbook comparisons in this "
            "module are INERT in this run: the runbook's header rows, its client-side detect rows "
            "and its session-cookie attribute row are compared against nothing, and the runbook "
            "can drift from the _security.py enumeration without anything going red. STILL "
            "ENFORCED here, and it is the half that guards the artifact shipping in the wheel: "
            "every emitted header, every client-side detect and every cookie attribute must be "
            "bucketed in the _security.py degrade contract. Set "
            f"{_RUNBOOK_ENV}=<path to OFF-LOOPBACK-DEPLOYMENT.md> to enforce the comparison half "
            f"from this checkout, or {_REQUIRE_RUNBOOK_ENV}=1 to make its absence a hard failure."
        ),
        stacklevel=3,
    )


def _runbook_contract() -> str:
    """The runbook's degrade-contract section (prose + table), or an ANNOUNCED per-test skip where it
    is absent.

    ``docs/security/**`` is deny-listed from the OSS mirror (and vaulted after the cutover), so this
    runbook is not there and an assertion about its CONTENT has nothing to say. The skip sits at this
    single accessor — ``_runbook_contract_table`` funnels through it too — so every test in this
    module that asserts about the console's own CODE keeps running publicly; only the three that
    compare code against the runbook table stand down (BACKLOG #1124 split those apart: they used to
    be the SAME three tests, with the code-side assertions downstream of this skip and therefore
    never executed anywhere).
    """
    doc = _runbook_path()
    if not doc.exists():
        if os.environ.get(_REQUIRE_RUNBOOK_ENV, "").strip():
            raise AssertionError(
                f"{_REQUIRE_RUNBOOK_ENV} is set but {doc} is absent — the runbook comparison was "
                "expected to be enforced on this leg and would have silently stood down."
            )
        _announce_runbook_absence(doc)
        pytest.skip("docs/security/OFF-LOOPBACK-DEPLOYMENT.md is private-only (deny-list / vault)")
    contract = doc.read_text(encoding="utf-8").split(
        "Browser security-feature support and degrade contract", 1
    )[1]
    return contract.split("## Per-message signing", 1)[0]


def _runbook_contract_table() -> str:
    """Just the TABLE — the per-feature bucket rows. Narrower than the section on purpose: a new
    feature must earn a ROW, not merely be mentioned somewhere in the surrounding prose."""
    table = _runbook_contract().split("| Relied-on browser feature |", 1)[1]
    return table.split("\n\n", 1)[0]


def _detected_browser_security_features() -> set[str]:
    """Every :data:`BROWSER_SECURITY_JS_FEATURES` name the console's OWN scripts read off ``window``:
    the served static JS plus the nonce'd shell scripts that live as string constants in ``_html.py``.
    Derived from the CODE, like the header set — a detect added without a bucket reds the guard."""
    sources = [p.read_text(encoding="utf-8") for p in sorted(_STATIC.glob("*.js"))]
    sources.append((_PACKAGE_DIR / "_html.py").read_text(encoding="utf-8"))
    names: set[str] = set()
    for source in sources:
        names.update(_WINDOW_READ_RE.findall(source))
    return names & set(BROWSER_SECURITY_JS_FEATURES)


def _emitted_browser_security_headers() -> set[str]:
    """Every :data:`BROWSER_SECURITY_HEADERS` name present in the code that reaches a /ui response:
    the whole console package, plus the ENGINE modules that stamp headers onto /ui responses.

    ``api/header_floor.py`` is named alongside ``api/app.py`` because the baseline header LITERALS
    live there now, and a derivation that misses the emitter goes circular rather than red: the only
    remaining occurrence of a name would be the ``_security.py`` degrade-contract docstring, which is
    the very text this guard then asserts the name appears in. Deleting a bucket row would drop the
    header from ``emitted`` too, and the loop below would simply stop checking it. Measured on this
    branch: with ``header_floor.py`` absent from this list, removing ``X-Frame-Options: DENY`` from
    the docstring left the module GREEN. **Any future module that writes one of these names has to be
    added here** — the contract this guard enforces is only as wide as the code it reads."""
    sources = [p.read_text(encoding="utf-8") for p in _PACKAGE_DIR.rglob("*.py")]
    sources.append(Path(engine_app.__file__).read_text(encoding="utf-8"))
    sources.append(Path(engine_header_floor.__file__).read_text(encoding="utf-8"))
    blob = "\n".join(sources)
    return {name for name in BROWSER_SECURITY_HEADERS if name in blob}


def test_the_middleware_header_constant_matches_what_it_actually_writes() -> None:
    """``SECURITY_HEADER_NAMES`` is what the contract guard below reads, so it must not be able to
    drift from the middleware's real ``send_wrapper``. Re-derive the written names from the SOURCE
    and require equality — adding a header write without declaring it reds here."""
    source = Path(security.__file__).read_text(encoding="utf-8")
    wrapper = source.split("async def send_wrapper", 1)[1].split("\n        token =", 1)[0]
    written = set(_HEADER_WRITE_RE.findall(wrapper))
    assert written, wrapper
    assert written == set(security.SECURITY_HEADER_NAMES), (
        written,
        security.SECURITY_HEADER_NAMES,
    )


def test_degrade_contract_enumerates_every_relied_on_feature() -> None:
    """ASVS 3.7.5's bar is "behaves as DOCUMENTED", so the contract must classify EVERY relied-on
    browser feature as detected-and-warned or degrade-silent-with-rationale.

    The header half of that set is DERIVED FROM THE CODE that emits it — the console package and the
    engine's /ui security-headers middleware — not from a literal in this file, so a header shipped
    without a bucket fails here. (The previous version hardcoded both sides and therefore could not
    fail for the property it is named after: it stayed green when ``Clear-Site-Data`` was added.)
    The in-code source of truth is the _security.py docstring; the runbook mirrors it."""
    docstring = security.__doc__ or ""
    assert "DETECTED and WARNED" in docstring
    assert "DEGRADES SILENTLY" in docstring

    emitted = _emitted_browser_security_headers()
    # sanity: the set is non-trivial and contains the ones this lane knows ship today
    assert {*security.SECURITY_HEADER_NAMES, "Clear-Site-Data"} <= emitted, emitted
    for header in sorted(emitted):
        assert header in docstring, (
            f"{header} reaches a /ui response but is not bucketed in the _security.py "
            f"degrade contract (detected-and-warned, or degrades-silently + compensating control)"
        )

    # the non-header features stay pinned by name too
    for feature in (
        "isSecureContext",
        "csp-probe.js",
        "SameSite",
        "PublicKeyCredential",
        "__Host-",
        SCRIPTS_BLOCKED_BANNER_ID,
    ):
        assert feature in docstring, feature
    # crossOriginIsolated is named as a NON-detect so nobody "fixes" COOP with a false banner
    assert "crossOriginIsolated" in docstring
    # no hardcoded feature COUNT may drift away from the list it introduces
    assert "Four features are relied on" not in docstring


def test_runbook_mirrors_the_degrade_contract_enumeration() -> None:
    """The RUNBOOK half of the enumeration guard, split out of the test above (BACKLOG #1124).

    ``docs/security/OFF-LOOPBACK-DEPLOYMENT.md`` is deny-listed from this repo by design, so this
    comparison legitimately stands down in every public checkout. It used to stand down carrying the
    CODE-side assertions with it: ``_runbook_contract()`` was called before the loop, so the whole
    test reported ``skipped`` and the ``header in docstring`` check -- which needs no runbook at all
    -- never ran and never showed a result. The contract shipping inside the wheel was unchecked
    while ``_security.py`` told every reader a CI guard enforced it.

    Splitting them means the code-side half now PASSES visibly and only this one skips.
    """
    contract = _runbook_contract()
    docstring = security.__doc__ or ""
    assert "Detected + warned" in contract and "Degrades **silently**" in contract
    assert "DETECTED and WARNED" in docstring and "DEGRADES SILENTLY" in docstring

    for header in sorted(_emitted_browser_security_headers()):
        assert header in contract, (
            f"{header} reaches a /ui response but has no row in the OFF-LOOPBACK-DEPLOYMENT.md "
            f"degrade-contract table"
        )
    for feature in (
        "window.isSecureContext",
        "/ui/static/csp-probe.js",
        "`SameSite=Strict` session cookie",
        "nonce-source support",
    ):
        assert feature in contract, feature
    # the 3.1.1 Pass artifact's named fallback baseline must survive the rewrite (line-wrap agnostic)
    flat = " ".join(contract.split())
    assert (
        "The security baseline that still holds on a non-supporting client is the "
        "`SameSite=Strict` session cookie, the `frame-ancestors 'none'` CSP directive, and the "
        "`Sec-Fetch` / `Origin` cross-origin checks" in flat
    )
    assert "No browser-feature support is a precondition for serving `/ui`" in flat
    # the superseded "JS cannot feature-detect CSP-nonce enforcement" concession is gone
    assert "cannot** feature-detect" not in flat


def test_degrade_contract_buckets_every_client_side_feature_detect() -> None:
    """The half a header-only guard structurally cannot see (ASVS 3.7.5).

    The cell's bar is "behaves as DOCUMENTED when an expected security feature is missing". A feature
    the console genuinely feature-detects and WARNS about in the UI, with no entry in the contract, is
    exactly the residual — and ``window.PublicKeyCredential`` was in that state: ``app.js`` disables
    the passkey buttons and prints "This browser does not support passkeys.", while neither the
    ``_security.py`` contract nor the runbook table mentioned WebAuthn at all, under a docstring that
    claimed to enumerate EVERY relied-on feature. The detect set is derived from the console's own
    scripts, so the next one added reds here until it is bucketed in BOTH places.
    """
    detected = _detected_browser_security_features()
    # sanity: the derivation actually finds the two detects that ship today (a guard that finds
    # nothing would pass vacuously forever)
    assert {"isSecureContext", "PublicKeyCredential"} <= detected, detected
    docstring = security.__doc__ or ""
    for feature in sorted(detected):
        assert feature in docstring, (
            f"window.{feature} is feature-detected by the console but is not bucketed in the "
            f"_security.py degrade contract (detected-and-warned, or degrades-silently + "
            f"compensating control)"
        )


def test_runbook_table_buckets_every_client_side_feature_detect() -> None:
    """The RUNBOOK half of the detect guard, split out of the test above (BACKLOG #1124). Skips in
    every public checkout because the runbook is deny-listed; the code-side half no longer skips
    with it."""
    detected = _detected_browser_security_features()
    assert {"isSecureContext", "PublicKeyCredential"} <= detected, detected
    table = _runbook_contract_table()
    for feature in sorted(detected):
        assert feature in table, (
            f"window.{feature} is feature-detected by the console but has no row in the "
            f"OFF-LOOPBACK-DEPLOYMENT.md degrade-contract table"
        )
    # the WebAuthn row must state the fallback, or "detected" is only half a contract
    assert "TOTP" in table


def test_degrade_contract_buckets_every_session_cookie_security_attribute() -> None:
    """The third set. A cookie attribute is undetectable by construction (``HttpOnly`` is what makes
    it so), which is a reason to name the compensating control, not to leave it out of an enumeration
    that claims to be exhaustive. Derived from the module that actually writes the cookie."""
    source = Path(webconsole_auth.__file__).read_text(encoding="utf-8")
    docstring = security.__doc__ or ""
    # The attribute must be NAMED by the bucket entry's own label — its "what compensates" prose
    # mentioning it in passing is not a bucket. Without this the guard stayed green when the label was
    # narrowed to a single attribute, because the rationale cell still happened to say the words.
    docstring_label = docstring.split(COOKIE_ATTRIBUTE_ROW_LABEL, 1)[1].split("**", 1)[0]
    matched = 0
    for code_token, doc_token in COOKIE_SECURITY_ATTRIBUTES:
        if code_token not in source:
            continue
        matched += 1
        bare = doc_token.strip("`")
        if bare == "SameSite":
            # SameSite is the one attribute with its own dedicated bucket entry (it predates this
            # row), pinned by name in the whole-contract test above.
            assert bare in docstring
            continue
        assert bare in docstring_label, (
            f"{bare} is set on the session cookie but the _security.py cookie-attributes bucket "
            f"does not name it"
        )
    assert matched == len(COOKIE_SECURITY_ATTRIBUTES), matched


def test_runbook_table_buckets_every_session_cookie_security_attribute() -> None:
    """The RUNBOOK half of the cookie-attribute guard, split out of the test above (BACKLOG #1124).

    This is the half that genuinely needs the deny-listed runbook, so it is the half that should
    skip. Before the split it took the ``_security.py`` side down with it -- and the cookie test was
    the worst of the three, because ``_runbook_contract_table()`` was its FIRST statement, so not one
    line of its body ever executed in a public checkout.
    """
    source = Path(webconsole_auth.__file__).read_text(encoding="utf-8")
    table = _runbook_contract_table()
    rows = [
        line
        for line in table.splitlines()
        if line.startswith("|") and COOKIE_ATTRIBUTE_ROW_LABEL in line
    ]
    assert len(rows) == 1, rows
    runbook_label = [c.strip() for c in rows[0].strip().strip("|").split("|")][0]
    matched = 0
    for code_token, doc_token in COOKIE_SECURITY_ATTRIBUTES:
        if code_token not in source:
            continue
        matched += 1
        bare = doc_token.strip("`")
        if bare == "SameSite":
            assert bare in table
            continue
        assert bare in runbook_label, (
            f"{bare} is set on the session cookie but the OFF-LOOPBACK-DEPLOYMENT.md "
            f"cookie-attributes row does not name it"
        )
    assert matched == len(COOKIE_SECURITY_ATTRIBUTES), matched
