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
* the IDE webview list comes from the files that set a webview's HTML.

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
from starlette.types import Message, Receive, Scope, Send

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
    return SimpleNamespace(headers=headers, app=SimpleNamespace(state=state))


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
        headers=headers,
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
    assert ("Only one webview checks that its script started" in lead) == (len(checked) == 1)
