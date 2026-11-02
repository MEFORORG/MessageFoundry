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

#: The bound on ONE harness run, which is what catches a reconnect hang. The harness cannot loop on
#: its own: ``setTimeout`` only pushes onto ``timers``, ``setInterval`` is a no-op, ``fetch`` never
#: resolves, and "flush" swaps the due list out (``const due = timers; timers = [];``) before running
#: it, so a timer that re-arms lands in the NEXT flush. So once the cold start below is paid, a run
#: that outlives this bound is app.js spinning synchronously -- the hang this file must still fail
#: on -- or node itself stalling again, which this bound cannot tell apart. Locally a run takes about
#: 0.05 s.
_RUN_TIMEOUT_S = 60

#: The bound on the job's FIRST harness run, kept apart from the run bound above. On windows-2025
#: under xdist the first node launch of the web console job has stalled past 60 s twice (merge-queue
#: evictions, BACKLOG #4773): run 41141529043 lost the first of this file's four launches and run
#: 41490064678 the first two; every later launch in both jobs, the same harness over the same app.js,
#: passed. No other file in this suite starts node. So the cost is a first-launch one -- an
#: inference, since the logs carry no per-launch timing, and it may be node.exe or the first read of
#: the script files, so the warm-up runs the real harness over the real app.js. Unlike the
#: never-returning pwsh launch BACKLOG #1304 records, this stall ended, so a longer bound on the cold
#: start alone absorbs it. Run 41490064678 puts it over 120 s and under about 180 s.
_COLD_START_TIMEOUT_S = 240

pytestmark = [
    pytest.mark.skipif(_NODE is None, reason="node is not installed"),
    # The cold start is charged to the setup of the module's first test. Under the per-test
    # --timeout (120 on the Windows CI tiers, 60 on ubuntu and in pyproject), pytest-timeout's
    # thread method would kill the worker before the cold-start bound fires, losing the
    # TimeoutExpired that names the stalled command. One cold start plus one run, plus 60 s of slack,
    # lets each subprocess bound fire first. A cold start past the step's faulthandler_timeout (150 s
    # on Windows) writes a stack dump to the log that is not a failure: the dump does not end the run.
    pytest.mark.timeout(_COLD_START_TIMEOUT_S + _RUN_TIMEOUT_S + 60),
]


def _node(*args: str, timeout: int) -> str:
    """Run node with ``args`` under ``timeout`` s; return stdout, failing on a non-zero exit."""
    assert _NODE is not None
    proc = subprocess.run(
        [_NODE, *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


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


def _run(scenario: list[str], harness: Path, timeout: int = _RUN_TIMEOUT_S) -> list[int]:
    out = _node(str(harness), str(_APP_JS), json.dumps(scenario), timeout=timeout)
    counts: list[int] = json.loads(out.strip().splitlines()[-1])
    return counts


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Write the harness once and pay the first-launch cost on it, outside the run bound."""
    path = tmp_path_factory.mktemp("ws_reconnect") / "harness.js"
    path.write_text(_HARNESS, encoding="utf-8")
    # The same argv shape every test uses, so whatever the cold cost is, this run pays it. An empty
    # scenario still loads app.js, so a spin at load fails here, at the cold-start bound.
    assert _run([], path, timeout=_COLD_START_TIMEOUT_S) == []
    return path


def test_a_dropped_socket_is_reopened(harness: Path) -> None:
    # One socket at load; it opens, the server closes it (a rotation), and a new one follows.
    counts = _run(["open", "close", "flush"], harness)
    assert counts == [1, 1, 2]


def test_a_session_that_really_ended_stops_after_the_budget(harness: Path) -> None:
    # Handshakes that never open (a revoked session is refused at the handshake): 1 + 3 retries, then
    # nothing, however long the page stays up.
    steps = ["close", "flush"] * 6
    counts = _run(steps, harness)
    assert counts[-1] == 4, counts


def test_the_budget_refills_only_after_a_socket_stayed_up(harness: Path) -> None:
    # Two rotations far apart each get a reconnect, because the socket in between lived 60 s.
    stable = ["open", "advance:60000", "close", "flush"]
    counts = _run(stable * 5, harness)
    assert counts[-1] == 6, counts


def test_a_socket_that_opens_and_drops_at_once_does_not_refill_the_budget(harness: Path) -> None:
    # Accepted then closed within a second, over and over: the "opened" flag alone must not reset the
    # budget, or a server that accepts and immediately closes would be reconnected forever.
    flapping = ["open", "advance:500", "close", "flush"]
    counts = _run(flapping * 6, harness)
    assert counts[-1] == 4, counts
