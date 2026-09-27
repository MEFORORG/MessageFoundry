# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The dashboard re-opens ``/ws/stats`` a BOUNDED number of times (ASVS 7.2.4, BACKLOG #1146).

Completing MFA or a step-up rotates the session token, and the server then closes the live socket,
because the token it captured at the handshake stops resolving. Before this change ``app.js`` only
fell back to the HTTP poll, so the live push was gone for the rest of that page's life. It now
re-opens the socket, and the new handshake carries the new cookie.

The budget is the security half. A session that really ended must not become a handshake loop, and
the console audits every refused MFA-pending handshake, so an unbounded reconnect would also be an
audit-write amplifier. These tests run the REAL ``static/app.js`` under Node with a fake DOM, fake
timers and a fake WebSocket, and count the sockets it opens. A text grep of the source could not
tell a working budget from one that never refills or never stops.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import messagefoundry_webconsole

_APP_JS = Path(messagefoundry_webconsole.__file__).parent / "static" / "app.js"
_NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(_NODE is None, reason="node is not installed")

#: Loads app.js against just enough of a browser for the [data-poll] feature, then runs a scenario:
#: a list of "open", "close", "flush" (fire every pending timer) and "advance:<ms>" steps. Prints the
#: number of WebSocket objects constructed after each step.
_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const [appPath, scenarioJson] = process.argv.slice(2);
const scenario = JSON.parse(scenarioJson);
let now = 1000000;
let timers = [];
const sockets = [];
class FakeWebSocket {
  constructor(url) { this.url = url; sockets.push(this); }
}
const container = {
  getAttribute(name) {
    return { "data-poll": "/ui/fragment", "data-poll-ms": "5000" }[name] ?? null;
  },
  set innerHTML(_v) {},
};
const document = {
  querySelector(sel) { return sel === "[data-poll]" ? container : null; },
  querySelectorAll() { return []; },
  getElementById() { return null; },
  addEventListener() {},
  body: { classList: { contains() { return false; } } },
};
const sandbox = {
  document,
  window: { addEventListener() {}, location: {} },
  location: { protocol: "https:", host: "ops.example" },
  WebSocket: FakeWebSocket,
  Date: { now: () => now },
  Math,
  JSON,
  Object,
  parseInt,
  setInterval() { return 1; },
  clearInterval() {},
  setTimeout(fn, ms) { timers.push({ fn, at: now + ms }); return timers.length; },
  clearTimeout() {},
  fetch() { return new Promise(() => {}); },
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(appPath, "utf8"), sandbox);
const out = [];
for (const step of scenario) {
  const ws = sockets[sockets.length - 1];
  if (step === "open") ws.onopen();
  else if (step === "close") { ws.onerror && ws.onerror(); ws.onclose(); }
  else if (step === "flush") {
    const due = timers; timers = [];
    for (const t of due) { now = Math.max(now, t.at); t.fn(); }
  } else if (step.startsWith("advance:")) now += Number(step.slice(8));
  out.push(sockets.length);
}
console.log(JSON.stringify(out));
"""


def _run(scenario: list[str], tmp_path: Path) -> list[int]:
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS, encoding="utf-8")
    assert _NODE is not None
    proc = subprocess.run(
        [_NODE, str(harness), str(_APP_JS), json.dumps(scenario)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    counts: list[int] = json.loads(proc.stdout.strip().splitlines()[-1])
    return counts


def test_a_dropped_socket_is_reopened(tmp_path: Path) -> None:
    # One socket at load; it opens, the server closes it (a rotation), and a new one follows.
    counts = _run(["open", "close", "flush"], tmp_path)
    assert counts == [1, 1, 2]


def test_a_session_that_really_ended_stops_after_the_budget(tmp_path: Path) -> None:
    # Handshakes that never open (a revoked session is refused at the handshake): 1 + 3 retries, then
    # nothing, however long the page stays up.
    steps = ["close", "flush"] * 6
    counts = _run(steps, tmp_path)
    assert counts[-1] == 4, counts


def test_the_budget_refills_only_after_a_socket_stayed_up(tmp_path: Path) -> None:
    # Two rotations far apart each get a reconnect, because the socket in between lived 60 s.
    stable = ["open", "advance:60000", "close", "flush"]
    counts = _run(stable * 5, tmp_path)
    assert counts[-1] == 6, counts


def test_a_socket_that_opens_and_drops_at_once_does_not_refill_the_budget(tmp_path: Path) -> None:
    # Accepted then closed within a second, over and over: the "opened" flag alone must not reset the
    # budget, or a server that accepts and immediately closes would be reconnected forever.
    flapping = ["open", "advance:500", "close", "flush"]
    counts = _run(flapping * 6, tmp_path)
    assert counts[-1] == 4, counts
