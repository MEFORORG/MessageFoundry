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
import time
import warnings
from pathlib import Path

import pytest

import messagefoundry_webconsole

_APP_JS = Path(messagefoundry_webconsole.__file__).parent / "static" / "app.js"
_NODE = shutil.which("node")

#: The bound on ONE harness run, which is what catches a reconnect hang. The harness cannot loop on
#: its own: ``setTimeout`` only pushes onto ``timers``, ``setInterval`` is a no-op, ``fetch`` never
#: resolves, and "flush" swaps the due list out (``const due = timers; timers = [];``) before running
#: it, so a timer that re-arms lands in the NEXT flush. So once the cold start below is paid, a run
#: that outlives this bound is app.js looping -- synchronously or through a microtask chain, the hang
#: this file must still fail on -- or node itself stalling again, which this bound cannot tell
#: apart. Locally a run takes about 0.05 s.
_RUN_TIMEOUT_S = 60

#: The bound on the module's FIRST harness run, kept apart from the run bound above. On windows-2025
#: under xdist the first node launch of the web console job has stalled past 60 s twice: run
#: 41141529043 lost the first of this file's four launches and run 41490064678 the first two; every
#: later launch in both jobs, the same harness over the same app.js, passed. At this commit no other
#: file in this suite starts node. So the cost reads as a first-launch one -- an inference, since the
#: logs carry no per-launch timing, and it may be node.exe or the first read of the script files, so
#: the warm-up runs the real harness over the real app.js. Concurrent load, the cause BACKLOG #1304
#: measured for pwsh launches, is not ruled out; there the launch never returned, here the later
#: launches did. If one stall spanned both of run 41490064678's killed launches, it ran over 120 s
#: and under about 180 s; that is an inference too. The warm-up FAILS SOFT: a timeout or a non-zero
#: exit only warns, and each test then runs under its own 60 s bound, so the warm-up can never error
#: the tests by itself and a real app.js fault still fails them by name. It also warns with its time
#: when it runs past _COLD_START_WARN_S, so the next occurrence leaves a measurement.
_COLD_START_TIMEOUT_S = 180
_COLD_START_WARN_S = 10

pytestmark = [
    pytest.mark.skipif(_NODE is None, reason="node is not installed"),
    # The cold start is charged to the setup of whichever test first asks for the module fixture,
    # which -k or another --dist mode can change, so the marker covers the module. Under the CI
    # tiers' per-test --timeout, which today sits below this marker, pytest-timeout's thread method
    # would kill the worker before the cold-start bound fires. One cold start plus one run, plus
    # 60 s of slack, lets each subprocess bound fire first. (func_only=True would keep the call
    # bound tight but leave fixture setup with no watchdog at all.) A cold start past the step's
    # faulthandler_timeout writes a stack dump to the log; the dump does not end the run.
    pytest.mark.timeout(_COLD_START_TIMEOUT_S + _RUN_TIMEOUT_S + 60),
]


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


def _run(scenario: list[str], harness: Path) -> list[int]:
    assert _NODE is not None
    proc = subprocess.run(
        [_NODE, str(harness), str(_APP_JS), json.dumps(scenario)],
        capture_output=True,
        text=True,
        timeout=_RUN_TIMEOUT_S,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    counts: list[int] = json.loads(proc.stdout.strip().splitlines()[-1])
    return counts


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Write the harness once and pay the first-launch cost on it, outside the run bound."""
    path = tmp_path_factory.mktemp("ws_reconnect") / "harness.js"
    path.write_text(_HARNESS, encoding="utf-8")
    # The same argv shape every test uses, so whatever the cold cost is, this run pays it. It never
    # fails the fixture: an empty scenario still loads app.js, so a fault at load fails every test
    # under its own bound instead.
    assert _NODE is not None
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [_NODE, str(path), str(_APP_JS), "[]"],
            capture_output=True,
            text=True,
            timeout=_COLD_START_TIMEOUT_S,
            check=False,
        )
        outcome = "ok" if proc.returncode == 0 else f"exit {proc.returncode}"
    except subprocess.TimeoutExpired:
        outcome = f"timed out at {_COLD_START_TIMEOUT_S} s"
    elapsed = time.monotonic() - started
    if outcome != "ok" or elapsed > _COLD_START_WARN_S:
        warnings.warn(f"node cold start took {elapsed:.1f} s: {outcome}", stacklevel=1)
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
