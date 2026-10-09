# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 3.1.1 / 3.7.5 -- ``docs/BROWSER-SUPPORT.md`` pinned past the degrade tables (BACKLOG #1116, #1124).

``test_ui_csp_canary.py`` pins the page's degrade tables to the response headers, the
``window.<Feature>`` reads and the cookie attributes, and stops at ``## Two configurations turn the
warnings off``. Everything the page says after that point, and the request-header rows it gained
beside those tables, was pinned by nothing. Three sentences there had already gone false against the
code: the opt-out cookie name, the HSTS condition, and "the engine's HTTP API needs no browser".

Each pin here is DERIVED FROM THE CODE, by name or by running it, rather than compared against a
literal in this file:

* the request headers the server reads are found in the source, and each needs a row;
* each row's verdict on ABSENCE is found by running the code without that header;
* the opt-out cookie names come from the resolvers themselves;
* the HSTS conditions come from calling ``hsts_notable``;
* the IDE webview list comes from the files that set a webview's HTML;
* the two IDE banner quotes come from ``ide/src/webviewMessaging.ts``, and "every panel that runs a
  script" from which of those files embed the banners;
* the denial page's status, header, two shapes and policy come from running the middleware;
* which API page has a no-JavaScript message comes from FastAPI's own page builders.

Each carries a positive control, so a green run cannot be an extraction that found nothing.
"""

from __future__ import annotations

import inspect
import os
import re
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import HTTPException
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from starlette.datastructures import Headers
from starlette.types import Message, Receive, Scope, Send

import messagefoundry.api.client_networks as client_networks
import messagefoundry.api.header_floor as header_floor
import messagefoundry.api.security as engine_security
import messagefoundry_webconsole
import messagefoundry_webconsole._auth as webconsole_auth
import messagefoundry_webconsole._security as security

_REPO = Path(__file__).resolve().parents[3]
_PACKAGE_DIR = Path(messagefoundry_webconsole.__file__).parent

#: Same override the canary module reads, so one variable points both at a relocated copy.
_SUPPORT_DOC_ENV = "MEFOR_WEBCONSOLE_BROWSER_SUPPORT_DOC"

_REQUEST_HEADERS_HEADING = "### Request headers the browser sends"
_TWO_CONFIGURATIONS_HEADING = "## Two configurations turn the warnings off"
_DEGRADE_HEADING = "### Degrades silently, with a control that still holds"
_IDE_HEADING = "## The IDE extension's webviews"
#: Where the ``_security.py`` contract's request-header list starts.
_FOURTH_SET_HEADING = "**The fourth set: request headers the browser sends"
#: Point this at an ``ide/src`` tree from a checkout that does not carry one beside the docs.
_IDE_SRC_ENV = "MEFOR_IDE_SRC_DIR"

#: Where the absence verdict sits: the LAST cell of a request-header row opens with one of these.
_ALLOWED = "**Allowed"
_REFUSED = "**Refused"


def _doc() -> str:
    override = os.environ.get(_SUPPORT_DOC_ENV, "").strip()
    path = Path(override) if override else _REPO / "docs/BROWSER-SUPPORT.md"
    assert path.exists(), (
        f"{path} is absent. It is public and in-tree by design (BACKLOG #1116); set "
        f"{_SUPPORT_DOC_ENV} if this checkout carries it elsewhere."
    )
    return path.read_text(encoding="utf-8")


def _section(heading: str) -> str:
    """The text under ``heading`` up to the next heading of the same or a higher level."""
    text = _doc()
    assert heading in text, heading
    level = heading.split(" ", 1)[0]
    body = text.split(heading, 1)[1]
    stop = re.search(r"^#{1," + str(len(level)) + r"} ", body, re.MULTILINE)
    return body[: stop.start()] if stop else body


def _rows(section: str) -> list[list[str]]:
    """Table rows as cell lists. Every table's header row is dropped, not only the first table's: a
    Markdown header is the row directly above a ``|---|`` separator, so it is removed when the
    separator is seen."""
    rows: list[list[str]] = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        if set(line.strip()) <= set("|-: "):
            if rows:
                rows.pop()
            continue
        rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return rows


def _canonical(name: str) -> str:
    return "-".join(part.capitalize() for part in name.lower().split("-"))


# --- request headers: names derived from the code --------------------------------------------------

_FETCH_KEY_RE = re.compile(r'b"(sec-fetch-[a-z]+)"')
_HEADER_READ_RE = re.compile(r"""headers\.get\(\s*["']((?i:sec-fetch-[a-z]+|origin))["']""")


def _middleware_fetch_headers() -> set[str]:
    source = inspect.getsource(security.UiFetchMetadataMiddleware)
    return {_canonical(name) for name in _FETCH_KEY_RE.findall(source)}


def _request_headers_read() -> set[str]:
    """Every ``Sec-Fetch-*`` or ``Origin`` header the console package or the engine's WebSocket gate
    reads off a request. The middleware's raw-scope reads are the bytes spelling; everything else is
    a ``headers.get`` call."""
    names = _middleware_fetch_headers()
    sources = [p.read_text(encoding="utf-8") for p in sorted(_PACKAGE_DIR.rglob("*.py"))]
    sources.append(Path(engine_security.__file__ or "").read_text(encoding="utf-8"))
    for source in sources:
        names.update(_canonical(name) for name in _HEADER_READ_RE.findall(source))
    return names


def _request_header_rows() -> list[list[str]]:
    rows = _rows(_section(_REQUEST_HEADERS_HEADING))
    assert len(rows) >= 5, rows
    return rows


def _row_for(lead: str) -> list[str]:
    matches = [row for row in _request_header_rows() if lead in row[0]]
    assert len(matches) == 1, (lead, matches)
    return matches[0]


def test_every_request_header_the_server_reads_has_a_row() -> None:
    derived = _request_headers_read()
    # positive control: the derivation finds the headers that ship today, so an empty or partial
    # set is a broken extraction rather than a clean contract
    assert {
        "Sec-Fetch-Site",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Dest",
        "Sec-Fetch-User",
        "Origin",
    } <= derived, derived
    leads = [row[0] for row in _request_header_rows()]
    # Only the fourth-set list counts: the docstring names Sec-Fetch-Site and Origin earlier, in the
    # cookie and SameSite bullets, so a whole-docstring search could not fail for those two.
    docstring = (security.__doc__ or "").split(_FOURTH_SET_HEADING, 1)[-1]
    assert _FOURTH_SET_HEADING in (security.__doc__ or ""), _FOURTH_SET_HEADING
    for name in sorted(derived):
        assert any(f"`{name}`" in lead for lead in leads), (
            f"the server reads {name} off a request but docs/BROWSER-SUPPORT.md has no "
            f"request-header row for it, so what its absence does is not stated"
        )
        assert f"``{name}``" in docstring, (
            f"the server reads {name} off a request but the _security.py contract does not name it"
        )


# --- request headers: absence verdicts derived by running the code ---------------------------------

#: A same-site navigation that satisfies every middleware condition. Dropping one header at a time
#: from it measures what the middleware does when a browser omits that header.
_SAFE_SAME_SITE_NAVIGATION = {
    "sec-fetch-site": "same-site",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
    "sec-fetch-user": "?1",
}


async def _middleware_status(headers: dict[str, str]) -> int:
    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": "/ui",
        "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
    }
    await security.UiFetchMetadataMiddleware(inner)(scope, receive, send)
    return int(next(m["status"] for m in sent if m["type"] == "http.response.start"))


async def test_each_fetch_metadata_rows_absence_verdict_matches_the_middleware() -> None:
    # positive controls: the complete navigation passes and a cross-site fetch is refused, so the
    # harness can observe BOTH outcomes and a verdict below is a measurement, not a default
    assert await _middleware_status(dict(_SAFE_SAME_SITE_NAVIGATION)) == 200
    assert (
        await _middleware_status({"sec-fetch-site": "cross-site", "sec-fetch-mode": "cors"}) == 403
    )
    names = _middleware_fetch_headers()
    assert len(names) >= 4, names
    for name in sorted(names):
        headers = {k: v for k, v in _SAFE_SAME_SITE_NAVIGATION.items() if _canonical(k) != name}
        assert len(headers) == len(_SAFE_SAME_SITE_NAVIGATION) - 1, (name, headers)
        verdict = _ALLOWED if await _middleware_status(headers) == 200 else _REFUSED
        absence = _row_for(f"`{name}`")[-1]
        assert absence.startswith(verdict), (
            f"with {name} missing the middleware answers {verdict.strip('*')}, but the "
            f"docs/BROWSER-SUPPORT.md row says: {absence[:80]!r}"
        )


def _fake_request(headers: dict[str, str]) -> Any:
    state = SimpleNamespace(public_origin=None, loopback=False, webauthn_rp_from_request=True)
    # A POST: the row is the form-POST row, and the check keeps its earlier rule on a GET.
    return SimpleNamespace(method="POST", headers=headers, app=SimpleNamespace(state=state))


def test_the_form_post_origin_rows_absence_verdict_matches_assert_same_origin() -> None:
    # control: the check is live -- a foreign Origin with no Sec-Fetch-Site is refused
    with pytest.raises(HTTPException):
        webconsole_auth.assert_same_origin(
            _fake_request({"origin": "https://foreign.example", "host": "engine.example"})
        )
    try:
        webconsole_auth.assert_same_origin(_fake_request({"host": "engine.example"}))
        verdict = _ALLOWED
    except HTTPException:
        verdict = _REFUSED
    absence = _row_for("`Origin` on a form POST")[-1]
    assert absence.startswith(verdict), absence[:80]


class _RecordingCookies:
    """An empty cookie jar that records whether the session credential was ever looked up."""

    read = False

    def get(self, key: str, default: str | None = None) -> str | None:
        _RecordingCookies.read = True
        return default


def _fake_websocket(headers: dict[str, str]) -> Any:
    state = SimpleNamespace(
        public_origin=None,
        loopback=False,
        webauthn_rp_from_request=True,
        exposure_protected=False,
        auth=None,
    )
    return SimpleNamespace(
        headers=Headers(headers),  # has getlist (BACKLOG #2454)
        app=SimpleNamespace(state=state),
        url=SimpleNamespace(scheme="wss", path="/ws/stats"),
        cookies=_RecordingCookies(),
    )


async def test_the_websocket_origin_rows_absence_verdict_matches_both_origin_gates() -> None:
    """The handshake's ``Origin`` rule is two gates in sequence: the console's cookie hook
    (``authorize_ui_ws``), then, when that declines, the engine's ``_ws_origin_allowed``. With no
    ``Origin`` the hook DEFERS -- it returns before reading the cookie -- and the verdict is the
    engine gate's. A first version of this test read the hook's early return as a refusal; the
    engine gate then passes the handshake, so by the table's own definition absence is Allowed by the
    Origin rule and it is the later bearer-token check that stops a browser."""
    # controls: both gates are live, so the absence verdicts below are measurements
    _RecordingCookies.read = False
    matching = _fake_websocket({"origin": "https://engine.example", "host": "engine.example"})
    assert await webconsole_auth.authorize_ui_ws(matching) == (None, None)
    assert _RecordingCookies.read, "a matching Origin should have reached the cookie lookup"
    foreign = _fake_websocket({"origin": "https://foreign.example", "host": "engine.example"})
    foreign.app.state.ws_allowed_origins = ()
    assert engine_security._ws_origin_allowed(foreign) is False

    _RecordingCookies.read = False
    absent = _fake_websocket({"host": "engine.example"})
    absent.app.state.ws_allowed_origins = ()
    assert await webconsole_auth.authorize_ui_ws(absent) == (None, None)
    hook_deferred = not _RecordingCookies.read
    assert hook_deferred, "with no Origin the console hook read the cookie instead of deferring"
    verdict = _ALLOWED if engine_security._ws_origin_allowed(absent) else _REFUSED
    absence = _row_for("`Origin` on the `/ws/stats` WebSocket handshake")[-1]
    assert absence.startswith(verdict), absence[:80]


# --- the opt-out cookie names -----------------------------------------------------------------------


def _resolved_names(monkeypatch: pytest.MonkeyPatch, *, opt_out: bool, scheme: str) -> set[str]:
    if opt_out:
        monkeypatch.setenv(webconsole_auth.BROWSER_HARDENING_OPT_OUT_ENV, "1")
    else:
        monkeypatch.delenv(webconsole_auth.BROWSER_HARDENING_OPT_OUT_ENV, raising=False)
    conn = cast(
        Any,
        SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(exposure_protected=False)),
            url=SimpleNamespace(scheme=scheme),
        ),
    )
    return {
        webconsole_auth.session_cookie_name(conn),
        webconsole_auth.oidc_flow_cookie_name(conn),
    }


def test_the_opt_out_section_names_the_cookies_the_resolvers_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The page said the opt-out falls back to "the plain session cookie". Over HTTPS, which is
    every ``messagefoundry serve`` posture, both resolvers return a ``__Secure-`` name instead."""
    hardened = _resolved_names(monkeypatch, opt_out=False, scheme="https")
    opted_out = _resolved_names(monkeypatch, opt_out=True, scheme="https")
    cleartext = _resolved_names(monkeypatch, opt_out=True, scheme="http")
    # control: the opt-out really selects a different rung, so the names below are that rung's
    assert hardened.isdisjoint(opted_out), (hardened, opted_out)
    rows = _rows(_section(_TWO_CONFIGURATIONS_HEADING))
    https_rows = [row for row in rows if "HTTPS" in row[0]]
    clear_rows = [row for row in rows if "cleartext" in row[0]]
    assert len(https_rows) == 1 and len(clear_rows) == 1, rows
    for name in sorted(opted_out):
        assert f"`{name}`" in " ".join(https_rows[0][1:]), (name, https_rows[0])
    for name in sorted(cleartext):
        assert f"`{name}`" in " ".join(clear_rows[0][1:]), (name, clear_rows[0])
    if webconsole_auth.COOKIE_NAME not in opted_out:
        assert "plain session cookie" not in _section(_TWO_CONFIGURATIONS_HEADING)


# --- the HSTS condition -----------------------------------------------------------------------------


def _sentences_with(text: str, phrase: str) -> list[str]:
    return [s for s in re.split(r"(?<=\.)\s+", text) if phrase in s]


def test_the_hsts_row_states_the_conditions_hsts_notable_applies() -> None:
    """Each condition is tied to the row two ways: the phrase is present exactly when the code
    behaves that way, and the sentence carrying it says the right thing about it -- "absent" for a
    suppression, "sends it only when" for an emit condition. Phrase presence alone was satisfied by
    a row saying the opposite."""
    rows = [
        row for row in _rows(_section(_DEGRADE_HEADING)) if "Strict-Transport-Security" in row[0]
    ]
    assert len(rows) == 1, rows
    row = " ".join(rows[0])
    dns = "engine.example"
    # control: the gate can emit, so a False below is a suppression and not a dead predicate
    assert header_floor.hsts_notable("https", True, host=dns)
    suppressions = (
        (not header_floor.hsts_notable("https", False, host=dns), "minted self-signed certificate"),
        (not header_floor.hsts_notable("https", True, host="127.0.0.1"), "IP-literal host"),
    )
    for suppressed, phrase in suppressions:
        carriers = _sentences_with(row, phrase)
        assert bool(carriers) == suppressed, (
            f"hsts_notable {'suppresses' if suppressed else 'emits'} HSTS for the {phrase!r} "
            f"case, and the docs/BROWSER-SUPPORT.md row "
            f"{'does not say so' if suppressed else 'still says it is suppressed'}"
        )
        for sentence in carriers:
            assert "absent" in sentence, sentence
    # the emit conditions: an operator-supplied chain arrives as scheme https with
    # exposure_protected, and a declared terminator as exposure_protected over a cleartext hop
    emits = (
        (header_floor.hsts_notable("https", True, host=dns), "supplied a certificate chain"),
        (header_floor.hsts_notable("http", True, host=dns), "declared a TLS terminator"),
    )
    for emitted, phrase in emits:
        carriers = _sentences_with(row, phrase)
        assert bool(carriers) == emitted, (phrase, emitted, row[:200])
        for sentence in carriers:
            assert "sends it only when" in sentence, sentence


# --- the IDE webview list ---------------------------------------------------------------------------

#: Any assignment to a webview's HTML: ``panel.webview.html =``, ``view.webview.html =`` and a bare
#: ``webview.html =`` on a parameter all match. ``==`` does not.
_WEBVIEW_HTML_RE = re.compile(r"\bwebview\.html\s*=(?!=)")
_STARTUP_CHECK = "script did not initialize"
#: The handshake timer that closes the ``setTimeout`` carrying the startup-check message:
#: ``}, 3000);``. The window is bounded so a timer rewritten as a named constant is REPORTED as not
#: found, instead of the search running on to some later, unrelated ``}, 50);`` in the file.
_STARTUP_TIMER_RE = re.compile(r"script did not initialize.{0,400}?\},\s*(\d+)\s*\);", re.DOTALL)


def _ide_panel_sources() -> Iterator[Path]:
    """Every extension source file that sets a webview's HTML, at any depth under ``ide/src`` except
    the test tree."""
    override = os.environ.get(_IDE_SRC_ENV, "").strip()
    src = Path(override) if override else _REPO / "ide/src"
    assert src.is_dir(), (
        f"{src} is absent, so the IDE rows cannot be checked against their panels; set "
        f"{_IDE_SRC_ENV} if this checkout carries ide/src elsewhere"
    )
    for path in sorted(src.rglob("*.ts")):
        if "test" in path.relative_to(src).parts[:-1]:
            continue
        if _WEBVIEW_HTML_RE.search(path.read_text(encoding="utf-8")):
            yield path


def test_the_ide_section_names_every_webview_and_its_startup_check() -> None:
    panels = {path.name: path.read_text(encoding="utf-8") for path in _ide_panel_sources()}
    # positive control: the scan finds panels that ship today
    assert {"home.ts", "stepsView.ts", "configEditors.ts"} <= set(panels), sorted(panels)
    rows = _rows(_section(_IDE_HEADING))
    by_source: dict[str, list[str]] = {}
    for row in rows:
        for name in re.findall(r"`([A-Za-z]+\.ts)`", row[1]):
            by_source[name] = row
    missing = sorted(set(panels) - set(by_source))
    stale = sorted(set(by_source) - set(panels))
    assert not missing, f"these files set a webview's HTML and have no row: {missing}"
    assert not stale, f"these rows name files that no longer set a webview's HTML: {stale}"
    checked = {name for name, source in panels.items() if _STARTUP_CHECK in source}
    assert checked, "no panel carries a startup check; the page's Steps-view claim needs revisiting"
    for name in sorted(checked):
        timer = _STARTUP_TIMER_RE.search(panels[name])
        assert timer, f"{name} has the startup-check message but no timer after it"
        seconds = int(timer.group(1)) / 1000
        phrase = f"within {seconds:g} second" + ("" if seconds == 1 else "s")
        assert phrase in by_source[name][-1], (name, phrase, by_source[name][-1])
    claimed = {name for name, row in by_source.items() if re.search(r"within \d", row[-1])}
    assert claimed == checked, (claimed, checked)
    lead = " ".join(_section(_IDE_HEADING).split())
    assert ("Only one webview also has a host-side startup check" in lead) == (len(checked) == 1)


# --- the IDE startup banners (BACKLOG #1116, #1124) -------------------------------------------------

_IDE_BANNERS_SOURCE = "webviewMessaging.ts"
_BANNERS_EMBED = "${STARTUP_BANNERS}"
#: A banner as the helper writes it: ``<div id="${NAME}" role="alert" ...>text</div>``.
_BANNER_RE = re.compile(r'<div id="\$\{(\w+)\}" role="alert"[^>]*>([^<]+)</div>')
#: The one panel file whose script-running documents are all built by another file's builder.
_DELEGATING_PANELS = {"configEditors.ts": ("connectionFormHtml", "codeSetFormHtml")}


def _quoted_blocks(section: str) -> list[str]:
    """Each Markdown block quote in ``section``, joined to one line."""
    blocks: list[str] = []
    current: list[str] = []
    for line in [*section.splitlines(), ""]:
        if line.startswith(">"):
            current.append(line.lstrip("> ").strip())
        elif current:
            blocks.append(" ".join(current))
            current = []
    return blocks


def test_the_ide_section_quotes_both_banners_as_the_code_writes_them() -> None:
    """The page tells a reader what each warning SAYS. Both quotes are compared with the text in
    ``webviewMessaging.ts``, so a reworded banner cannot leave the page describing the old one."""
    panels = {path.name: path for path in _ide_panel_sources()}
    helper = next(iter(panels.values())).parent / _IDE_BANNERS_SOURCE
    banners = dict(_BANNER_RE.findall(helper.read_text(encoding="utf-8")))
    # positive control: the extraction finds the two banners that ship today
    assert set(banners) == {"SCRIPT_BANNER_ID", "CSP_BANNER_ID"}, banners
    quotes = _quoted_blocks(_section(_IDE_HEADING))
    for name, text in banners.items():
        assert text in quotes, (
            f"docs/BROWSER-SUPPORT.md does not quote the {name} banner as "
            f"{_IDE_BANNERS_SOURCE} writes it: {text!r}"
        )


def test_every_ide_panel_that_runs_a_script_carries_the_banners() -> None:
    """The section says EVERY panel that runs a script warns. Each file that sets a webview's HTML
    must embed the banners itself, or be a named delegator whose builders live in files that do.
    ``ide/src/test/suite/startup-banners.test.ts`` checks the same wiring one assignment at a time."""
    panels = {path.name: path.read_text(encoding="utf-8") for path in _ide_panel_sources()}
    carriers = {name for name, source in panels.items() if _BANNERS_EMBED in source}
    # positive control: the scan sees real carriers, so an empty set is a broken search
    assert {"home.ts", "stepsView.ts", "testBench.ts"} <= carriers, sorted(carriers)
    for name in sorted(set(panels) - carriers):
        builders = _DELEGATING_PANELS.get(name)
        assert builders, (
            f"{name} sets a webview's HTML and does not embed the startup banners, so the page's "
            f"claim that every panel with a script warns is no longer true"
        )
        for builder in builders:
            homes = [n for n in carriers if f"function {builder}(" in panels[n]]
            assert len(homes) == 1 and builder in panels[name], (name, builder, homes)
    lead = " ".join(_section(_IDE_HEADING).split())
    assert "Every panel that runs a script warns you when that script has not started" in lead


# --- the client-network denial page -----------------------------------------------------------------

_DENIAL_HEADING = "## The client-network denial page needs no browser feature"


async def _denial(path: str, accept: str | None) -> tuple[int, dict[str, str], str]:
    """What ``ClientNetworkMiddleware`` answers a refused address on ``path``."""

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        raise AssertionError("a refused address reached the app")

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    state = SimpleNamespace(client_networks=("192.0.2.0/24",))
    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [(b"accept", accept.encode("latin-1"))] if accept else [],
        "client": ("198.51.100.7", 4000),
        "app": SimpleNamespace(state=state),
    }
    await client_networks.ClientNetworkMiddleware(inner)(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in start["headers"]}
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return int(start["status"]), headers, body.decode("utf-8")


async def test_the_denial_page_section_states_what_the_middleware_answers() -> None:
    section = " ".join(_section(_DENIAL_HEADING).split())
    marker = f"`{client_networks.DENIAL_HEADER}: {client_networks.DENIAL_MARKER}`"
    assert marker in section, marker
    shapes = {
        "ui": await _denial("/ui/messages", None),
        "html": await _denial("/status", "text/html,application/xhtml+xml"),
        "json": await _denial("/status", "application/json"),
        "bare": await _denial("/status", None),
    }
    for name, (status_code, headers, _body) in shapes.items():
        assert status_code == 403, (name, status_code)
        assert headers[client_networks.DENIAL_HEADER.lower()] == client_networks.DENIAL_MARKER, name
    assert "`403`" in section
    # the two shapes, and which request gets which
    assert {n for n, s in shapes.items() if s[1]["content-type"].startswith("text/html")} == {
        "ui",
        "html",
    }
    assert {
        n for n, s in shapes.items() if s[1]["content-type"].startswith("application/json")
    } == {
        "json",
        "bare",
    }
    assert "`/ui`" in section and "`text/html`" in section and "JSON" in section
    page = shapes["ui"][2]
    heading = re.search(r"<h1>([^<]+)</h1>", page)
    assert heading and heading.group(1) in section, heading
    assert "198.51.100.7" in page and "198.51.100.7" in shapes["json"][2]
    # "runs no script": true of the page and of its policy, and the section says so only then
    policy = shapes["ui"][1]["content-security-policy"]
    scriptless = "<script" not in page.lower() and "script-src" not in policy
    assert ("It runs no script" in section) == scriptless
    for directive in ("default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"):
        assert directive in policy, (directive, policy)
        assert f"`{directive}`" in section, directive
    # control: an allowed address is not denied, so the 403s above are the rule and not a default
    assert client_networks.client_network_allowed("192.0.2.9", ("192.0.2.0/24",))
    for exempt in sorted(client_networks._EXEMPT_PATHS):
        assert f"`{exempt}`" in section, exempt


# --- the API pages' no-JavaScript message -----------------------------------------------------------

_API_PAGES_HEADING = "## The engine's API pages load third-party scripts"


def test_the_api_pages_section_states_which_page_has_a_no_javascript_message() -> None:
    """``/redoc`` carries FastAPI's ``<noscript>`` line and ``/docs`` carries none. The section says
    which page warns and which is blank, so a FastAPI upgrade that changes either moves this test."""
    redoc = bytes(get_redoc_html(openapi_url="/openapi.json", title="t").body).decode("utf-8")
    swagger = bytes(get_swagger_ui_html(openapi_url="/openapi.json", title="t").body).decode(
        "utf-8"
    )
    section = " ".join(_section(_API_PAGES_HEADING).split())
    warned = re.search(r"<noscript>\s*(.*?)\s*</noscript>", redoc, re.DOTALL)
    assert ("`/redoc` with JavaScript off shows FastAPI's own line" in section) == bool(warned)
    if warned:
        first_sentence = warned.group(1).split(". ")[0] + "."
        assert first_sentence in section, first_sentence
    assert ("`/docs` with JavaScript off is a blank page" in section) == (
        "<noscript" not in swagger
    )
