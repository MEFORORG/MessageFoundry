// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import { hexdump } from "../../hexdump";
import { diffMessages } from "../../hl7diff";
import { testBenchScript } from "../../testBenchWebview";
import { heldAfterIncoming, judgeCollectionRun, pickCaseDetail, releaseRun } from "../../testCollections";
import { buildTraceDetail, type TraceEntry } from "../../traceView";
import { CHANNEL_FIELD } from "../../webviewMessaging";

// ASVS 3.5.5 (BACKLOG #1123), the syntax half at the Test Bench receiver.
//
// mfTrusted() decides who sent a message. This suite pins the next step: a correctly stamped message
// whose PAYLOAD is not the shape the panel renders is discarded, so `detail` is left exactly as it
// was. Escaping is not a discard, and a payload that only rendered escaped would fail these tests.
//
// Each well-formed fixture is built by the SAME pure host-side function testBench.ts posts from
// (hexdump, diffMessages, buildTraceDetail, judgeCollectionRun), and each one must render. That is the
// control: a receiver that discarded everything would pass every malformed case below and prove
// nothing. Every malformed case is that fixture with ONE field changed.
//
// Node-side only, like webview-guard.test.ts: no `vscode` import, so this runs on the unit leg too.

// jsdom through a narrow local shape, for the reason webview-guard.test.ts gives: the base tsconfig
// has no DOM lib, and @types/jsdom would pull it in.
interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib.
  [key: string]: any;
}
interface JsdomWindow {
  document: DomNode;
  origin: string;
  MessageEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  Event: new (type: string) => unknown;
  dispatchEvent(event: unknown): boolean;
  close(): void;
  [key: string]: unknown;
}
interface JsdomVirtualConsole {
  on(event: string, handler: (...args: unknown[]) => void): void;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => JsdomVirtualConsole;
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

const TOKEN = "BENCHtokenBENCHtokenBE00";
const SENTINEL = '<p id="sentinel">before</p>';

/** The Test Bench body markup the script looks up by id. A missing id throws at load, which fails. */
const BODY = `
  <div class="bar">
    <button id="load"></button><button id="savecoll"></button><button id="collections"></button>
    <button id="back" hidden></button><button id="layout" hidden></button>
    <button id="tracetoggle" hidden></button>
  </div>
  <div id="results"></div>
  <div id="detail"></div>`;

interface Bench {
  readonly window: JsdomWindow;
  readonly detail: DomNode;
  readonly results: DomNode;
  /** Every exception the page raised, loading or handling a message. */
  readonly errors: unknown[];
  /** Every message the page posted to the host, JSON-copied out of the page's realm. */
  readonly posted: Payload[];
  /** Every console.warn the page wrote. A shape discard names itself there. */
  readonly warnings: string[];
  /** Deliver a stamped, same-origin message exactly as the host path would. */
  deliver(data: Record<string, unknown>): void;
}

/** Every window bench() opened. Each suite closes them after each test, so ~70 realms do not pile up. */
const openWindows: JsdomWindow[] = [];
function closeWindows(): void {
  for (const w of openWindows.splice(0)) {
    w.close();
  }
}

function bench(state: Record<string, unknown> | null = null): Bench {
  const errors: unknown[] = [];
  const posted: Payload[] = [];
  const warnings: string[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => errors.push(e));
  virtualConsole.on("warn", (...args: unknown[]) => warnings.push(args.map(String).join(" ")));
  const dom = new JSDOM(`<!DOCTYPE html><body>${BODY}</body>`, {
    runScripts: "dangerously",
    virtualConsole,
    url: "https://localhost/",
  });
  const window = dom.window;
  openWindows.push(window);
  window.acquireVsCodeApi = () => ({
    getState: () => state,
    setState: () => undefined,
    postMessage: (m: unknown) => posted.push(JSON.parse(JSON.stringify(m)) as Payload),
  });
  const script = window.document.createElement("script");
  script.textContent = testBenchScript(TOKEN);
  window.document.body.appendChild(script);
  assert.deepStrictEqual(errors.map(String), [], "the Test Bench script threw while loading");
  // The page announces each load once (BACKLOG #2441). Taken off here, so each test sees only the
  // messages its own actions post.
  assert.deepStrictEqual(posted.splice(0), [{ command: "ready" }], "the page did not post ready once on load");
  const detail = window.document.getElementById("detail");
  const results = window.document.getElementById("results");
  return {
    window,
    detail,
    results,
    errors,
    posted,
    warnings,
    deliver(data): void {
      const ev = new window.MessageEvent("message", {
        origin: window.origin,
        source: null,
        data: { ...data, [CHANNEL_FIELD]: TOKEN },
      });
      window.dispatchEvent(ev);
    },
  };
}

type Payload = Record<string, any>;

function clone(p: Payload): Payload {
  return JSON.parse(JSON.stringify(p)) as Payload;
}

/**
 * Assert that `payload` is DISCARDED: detail's markup and both panes' visibility are unchanged, and
 * nothing threw. The no-throw half matters: a renderer that crashed partway would also leave
 * `detail` alone, and would read here as a discard it is not.
 */
function assertDiscarded(payload: Payload, why: string): void {
  const b = bench();
  b.detail.innerHTML = SENTINEL;
  const before = { html: b.detail.innerHTML, d: b.detail.style.display, r: b.results.style.display };
  b.deliver(payload);
  assert.deepStrictEqual(b.errors.map(String), [], `${why}: the page threw instead of discarding`);
  assert.strictEqual(b.detail.innerHTML, before.html, `${why}: detail was re-rendered`);
  assert.strictEqual(b.detail.style.display, before.d, `${why}: detail visibility changed`);
  assert.strictEqual(b.results.style.display, before.r, `${why}: results visibility changed`);
}

/** Assert that `payload` RENDERS, and return the bench so the caller can inspect what rendered. */
function assertRendered(payload: Payload, why: string, state: Record<string, unknown> | null = null): Bench {
  const b = bench(state);
  b.detail.innerHTML = SENTINEL;
  b.deliver(payload);
  assert.deepStrictEqual(b.errors.map(String), [], `${why}: the page threw`);
  assert.notStrictEqual(b.detail.innerHTML, SENTINEL, `${why}: a well-formed payload did not render`);
  assert.strictEqual(b.detail.style.display, "block", `${why}: detail was not shown`);
  return b;
}

/** Run each mutation on a fresh copy of `good` and assert every result is discarded. */
function assertEachDiscarded(good: Payload, cases: [string, (p: Payload) => void][]): void {
  assert.ok(cases.length > 0);
  // The mutations start from a JSON copy, so the copy itself must render. Otherwise a fixture value
  // JSON cannot carry (NaN, undefined) would make every case below a discard for the wrong reason.
  assertRendered(clone(good), "the unmutated JSON copy");
  for (const [why, mutate] of cases) {
    const p = clone(good);
    mutate(p);
    assert.notDeepStrictEqual(p, good, `${why}: the mutation changed nothing, so it tests nothing`);
    assertDiscarded(p, why);
  }
}

const XSS = '<img src=x onerror="window.__pwned=1">';

// ---- Fixtures, built by the host's own pure functions -------------------------------------------

const MSG_A = "MSH|^~\\&|APP|FAC|RCV|RF|20200101010101||ADT^A01|C1|P|2.5\rPID|1||A123";
const MSG_B = "MSH|^~\\&|APP|FAC|RCV|RF|20200101010101||ADT^A01|C1|P|2.5\rPID|1||B456";

const HEX: Payload = { type: "hex", source: "a.hl7", dump: hexdump(MSG_A) };

const DETAIL: Payload = { type: "detail", source: "a.hl7", to: "OB_X", diff: diffMessages(MSG_A, MSG_B) };

const TRACE_SOURCE = ['@handler("h")', "def handle(msg):", '    msg["MSH-3"] = "X"', '    return Send("out", msg)'].join("\n");
const TRACE_ENTRY = {
  source: "a.hl7",
  disposition: "received",
  invocations: [
    {
      kind: "handler",
      name: "h",
      module: "IB_X",
      file: "C:/cfg/IB_X.py",
      def_line: 1,
      events: [
        { line: 3, event: "line", assigned: {}, t: 1e-5 },
        { line: 4, event: "line", assigned: {}, t: 2e-6 },
      ],
      disposition: "received",
      sends: [{ outbound: "out" }],
      annotations: [],
    },
  ],
} as unknown as TraceEntry;
const TRACE: Payload = { type: "trace", detail: buildTraceDetail(TRACE_ENTRY, () => TRACE_SOURCE) };

// Two failing cases, each with its own distinctive values, so a test can tell whose values rendered.
// Case 0 differs in PID-3 (A123 expected, B456 actual). Case 1 differs in PID-3 (C789, D012) and
// carries an error text naming E555.
const MSG_C = "MSH|^~\\&|APP|FAC|RCV|RF|20200101010101||ADT^A01|C2|P|2.5\rPID|1||C789";
const MSG_D = "MSH|^~\\&|APP|FAC|RCV|RF|20200101010101||ADT^A01|C2|P|2.5\rPID|1||D012";
const JUDGED = judgeCollectionRun(
  [
    { name: "case_a", input: MSG_A, expected: [{ to: "OB_X", payload: MSG_A }] },
    { name: "case_c", input: MSG_C, expected: [{ to: "OB_X", payload: MSG_C }] },
  ],
  [
    { disposition: "received", error: null, deliveries: [{ to: "OB_X", payload: MSG_B }] },
    { disposition: "received", error: "handler failed near E555", deliveries: [{ to: "OB_X", payload: MSG_D }] },
  ],
);
const RUN_ID = 3;
const RUN: Payload = {
  type: "collectionRun",
  name: "regress",
  run: RUN_ID,
  passed: JUDGED.passed,
  total: JUDGED.summaries.length,
  results: JUDGED.summaries,
};
/** What the host posts when case `index` is clicked (testBench.ts showCaseDetail). */
function caseDetail(index: number, run = RUN_ID): Payload {
  return { type: "caseDetail", run, index, ...JUDGED.details[index] };
}
/** Every before/after value and error text of case `index`, which the run view must not show unasked. */
function valuesOf(index: number): string[] {
  const d = JUDGED.details[index];
  const vals = d.deliveries.flatMap((x) => x.differences.flatMap((f) => [f.before, f.after]));
  return d.error ? [...vals, d.error] : vals;
}

const COLLECTIONS: Payload = { type: "collections", items: [{ name: "regress", cases: 2 }] };

suite("Test Bench webview — the harness itself", () => {
  teardown(closeWindows);

  test("the fixtures are the non-trivial shapes the host posts", () => {
    // If a fixture were empty, "renders" would be satisfied by an empty-state message and the
    // malformed cases below would mutate fields no renderer ever reads.
    assert.ok((HEX.dump as Payload).lines.length > 0, "hex fixture has no rows");
    assert.ok(TRACE.detail.invocations[0].coverage.lines.length > 0, "trace fixture has no coverage lines");
    assert.ok(TRACE.detail.invocations[0].profile.lines.length > 0, "trace fixture has no profile lines");
    for (const i of [0, 1]) {
      assert.strictEqual(JUDGED.summaries[i].pass, false, `run case ${i} must fail`);
      assert.strictEqual(JUDGED.details[i].deliveries[0].status, "mismatch", `run case ${i} must carry a difference`);
    }
    assert.deepStrictEqual(valuesOf(0), ["A123", "B456"]);
    assert.deepStrictEqual(valuesOf(1), ["C789", "D012", "handler failed near E555"]);
  });

  test("the harness sees an exception thrown by a listener", () => {
    // NEGATIVE CONTROL for the no-throw half of assertDiscarded(). If jsdom swallowed listener
    // errors, a renderer that crashed would pass as a clean discard.
    const b = bench();
    const s = b.window.document.createElement("script");
    s.textContent = "window.addEventListener('mfboom', () => { throw new Error('boom'); });";
    b.window.document.body.appendChild(s);
    b.window.dispatchEvent(new b.window.Event("mfboom"));
    assert.strictEqual(b.errors.length, 1, "a thrown listener error was not reported");
  });

  test("a message without the channel token never reaches the renderer", () => {
    // The guard still runs first. Posting a well-formed body UNSTAMPED must not render.
    const b = bench();
    b.detail.innerHTML = SENTINEL;
    b.window.dispatchEvent(new b.window.MessageEvent("message", { origin: b.window.origin, source: null, data: clone(HEX) }));
    assert.strictEqual(b.detail.innerHTML, SENTINEL);
  });
});

suite("Test Bench webview — a malformed payload is discarded, a well-formed one renders", () => {
  teardown(closeWindows);

  test("hex: well-formed renders (control)", () => {
    const b = assertRendered(HEX, "hex");
    assert.ok(b.detail.querySelector("pre.hex"), "no hex rows rendered");
    assert.ok(b.detail.innerHTML.includes("4d 53 48"), "the MSH bytes are not in the render");
  });

  test("hex: malformed payloads are discarded", () => {
    assertEachDiscarded(HEX, [
      ["markup in a hex pair", (p) => (p.dump.lines[0].hex[0] = XSS)],
      ["a non-hex pair", (p) => (p.dump.lines[0].hex[0] = "zz")],
      ["an uppercase pair (the host emits lowercase)", (p) => (p.dump.lines[0].hex[0] = "4D")],
      ["a three-digit pair", (p) => (p.dump.lines[0].hex[0] = "4d0")],
      ["a numeric pair", (p) => (p.dump.lines[0].hex[0] = 77)],
      ["hex not an array", (p) => (p.dump.lines[0].hex = "4d 53")],
      ["more pairs than bytesPerRow", (p) => (p.dump.lines[0].hex = new Array(17).fill("00"))],
      ["a string offset", (p) => (p.dump.lines[0].offset = "0")],
      ["a negative offset", (p) => (p.dump.lines[0].offset = -16)],
      ["a fractional offset", (p) => (p.dump.lines[0].offset = 1.5)],
      ["markup in totalBytes", (p) => (p.dump.totalBytes = XSS)],
      ["a null renderedBytes (NaN over JSON)", (p) => (p.dump.renderedBytes = null)],
      ["a huge bytesPerRow", (p) => (p.dump.bytesPerRow = 1e9)],
      ["a zero bytesPerRow", (p) => (p.dump.bytesPerRow = 0)],
      ["a string truncated flag", (p) => (p.dump.truncated = "false")],
      ["a numeric ascii gutter", (p) => (p.dump.lines[0].ascii = 5)],
      ["lines not an array", (p) => (p.dump.lines = { 0: p.dump.lines[0] })],
      ["a numeric source", (p) => (p.source = 5)],
      ["no dump", (p) => delete p.dump],
    ]);
  });

  test("hex: non-finite numbers survive structured clone, so they are refused too", () => {
    // JSON cannot carry NaN or Infinity but postMessage can, so these are built without clone().
    for (const [field, value] of [
      ["totalBytes", Infinity],
      ["renderedBytes", NaN],
      ["bytesPerRow", Infinity],
    ] as const) {
      const p = clone(HEX);
      p.dump[field] = value;
      assertDiscarded(p, `${field} = ${String(value)}`);
    }
  });

  test("trace: well-formed renders (control)", () => {
    const b = assertRendered(TRACE, "trace");
    assert.ok(b.detail.querySelector("pre.cov"), "no coverage rendered");
  });

  test("trace: well-formed renders in profiling mode too (control)", () => {
    // The remembered view state picks the mode, so this is the profileInv() path, which the default
    // (coverage) render never reaches.
    const b = assertRendered(TRACE, "trace, profiling", { traceMode: "profile" });
    assert.ok(b.detail.querySelector("table.prof"), "no profiling table rendered");
  });

  test("trace: malformed profile payloads are discarded in profiling mode", () => {
    const cases: [string, (p: Payload) => void][] = [
      ["a string profile seconds", (p) => (p.detail.invocations[0].profile.lines[0].seconds = "0.1")],
      ["markup in a profile pct", (p) => (p.detail.invocations[0].profile.lines[0].pct = XSS)],
    ];
    for (const [why, mutate] of cases) {
      const p = clone(TRACE);
      mutate(p);
      const b = bench({ traceMode: "profile" });
      b.detail.innerHTML = SENTINEL;
      b.deliver(p);
      assert.deepStrictEqual(b.errors.map(String), [], `${why}: the page threw instead of discarding`);
      assert.strictEqual(b.detail.innerHTML, SENTINEL, `${why}: detail was re-rendered`);
    }
  });

  test("trace: malformed payloads are discarded", () => {
    assertEachDiscarded(TRACE, [
      ["markup in a coverage line number", (p) => (p.detail.invocations[0].coverage.lines[0].line = XSS)],
      ["a string hit count", (p) => (p.detail.invocations[0].coverage.lines[0].hits = "3")],
      ["a string executed count", (p) => (p.detail.invocations[0].coverage.executed = "1")],
      ["markup in executable", (p) => (p.detail.invocations[0].coverage.executable = XSS)],
      ["a string pct", (p) => (p.detail.invocations[0].coverage.pct = "50")],
      ["a numeric line text", (p) => (p.detail.invocations[0].coverage.lines[0].text = 1)],
      ["a string profile seconds", (p) => (p.detail.invocations[0].profile.lines[0].seconds = "0.1")],
      ["markup in a profile line", (p) => (p.detail.invocations[0].profile.lines[0].line = XSS)],
      ["a string totalSeconds", (p) => (p.detail.totalSeconds = "1")],
      ["a string hasTiming", (p) => (p.detail.hasTiming = "yes")],
      ["no profile", (p) => delete p.detail.invocations[0].profile],
      ["invocations not an array", (p) => (p.detail.invocations = {})],
      ["a numeric source", (p) => (p.detail.source = 1)],
      ["no detail", (p) => delete p.detail],
    ]);
  });

  test("collectionRun: well-formed renders (control)", () => {
    const b = assertRendered(RUN, "collectionRun");
    assert.ok(b.detail.innerHTML.includes("0 / 2 passed"), "the summary did not render");
    assert.strictEqual(b.detail.querySelectorAll("button[data-case-detail]").length, 2, "each case needs a Details button");
  });

  test("collectionRun: malformed payloads are discarded", () => {
    assertEachDiscarded(RUN, [
      ["markup in passed", (p) => (p.passed = XSS)],
      ["a string total", (p) => (p.total = "1")],
      ["no total", (p) => delete p.total],
      ["results not an array", (p) => (p.results = { 0: p.results[0] })],
      ["a string pass flag", (p) => (p.results[0].pass = "false")],
      ["a numeric case name", (p) => (p.results[0].name = 1)],
      ["a numeric disposition", (p) => (p.results[0].disposition = 1)],
      ["a null run name", (p) => (p.name = null)],
      ["no run id", (p) => delete p.run],
      ["markup as the run id", (p) => (p.run = XSS)],
      ["a negative run id", (p) => (p.run = -1)],
    ]);
  });

  test("collections: well-formed renders (control)", () => {
    const b = assertRendered(COLLECTIONS, "collections");
    assert.ok(b.detail.innerHTML.includes("2 cases"), "the case count did not render");
  });

  test("collections: malformed payloads are discarded", () => {
    assertEachDiscarded(COLLECTIONS, [
      ["markup as a case count", (p) => (p.items[0].cases = XSS)],
      ["a string case count", (p) => (p.items[0].cases = "2")],
      ["a negative case count", (p) => (p.items[0].cases = -1)],
      ["a numeric name", (p) => (p.items[0].name = 3)],
      ["items not an array", (p) => (p.items = "regress")],
    ]);
  });

  test("detail: well-formed renders (control)", () => {
    const b = assertRendered(DETAIL, "detail");
    assert.ok(b.detail.querySelector(".panes"), "the diff panes did not render");
  });

  test("detail: malformed payloads are discarded", () => {
    assertEachDiscarded(DETAIL, [
      ["a numeric field text", (p) => (p.diff.before[0].fields[0].t = 5)],
      ["a string changed flag", (p) => (p.diff.before[0].fields[0].c = "true")],
      ["a string seg flag", (p) => (p.diff.after[0].seg = "yes")],
      ["after not an array", (p) => (p.diff.after = {})],
      ["no diff", (p) => delete p.diff],
      ["a numeric destination", (p) => (p.to = 1)],
    ]);
  });

  test("an unknown type is discarded, as it was before the shape check", () => {
    assertDiscarded({ type: "nothingWeRender", source: "a.hl7" }, "unknown type");
    assertDiscarded({ type: 7 }, "numeric type");
    assertDiscarded({ type: "hasOwnProperty" }, "a type naming an Object.prototype member");
  });
});

suite("Test Bench webview — escaping still applies to a well-formed payload", () => {
  teardown(closeWindows);

  test("esc() encodes both quote characters", () => {
    // Pinned directly: a text-node render cannot show it, because innerHTML re-serialises a quote in
    // text as a bare quote. A top-level function in a classic script is a window global.
    const b = bench();
    const esc = b.window.esc as (s: unknown) => string;
    assert.strictEqual(esc(`<a href="x" title='y'>&`), "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;");
    assert.strictEqual(esc(7), "7", "a number is stringified, not dropped");
  });

  test("markup inside a well-formed string renders as text", () => {
    // The second layer. A string field is the right shape whatever it contains, so the shape check
    // passes it and esc() is what stops it becoming markup.
    const p = clone(HEX);
    p.source = XSS;
    const b = assertRendered(p, "hex with a markup source");
    assert.strictEqual(b.detail.querySelector("img"), null, "the source became an element");
    assert.ok(b.detail.textContent.includes("<img"), "the source text was dropped rather than escaped");
  });
});

// ASVS 14.2.6 (BACKLOG #2437, owner ruling R13; ADR 0121 "Reveal on click"). A collection run shows
// pass or fail per case, and a case's field values only after a click on that case, one at a time.
suite("Test Bench webview — a collection run reveals values one case at a time", () => {
  teardown(closeWindows);

  function runOnScreen(): Bench {
    return assertRendered(RUN, "collectionRun");
  }
  function button(b: Bench, index: number): DomNode {
    const btn = b.detail.querySelector(`button[data-case-detail="${index}"]`);
    assert.ok(btn, `no Details button for case ${index}`);
    return btn;
  }
  /** Click case `index`, then deliver the host's reply to that click. */
  function reveal(b: Bench, index: number): void {
    button(b, index).click();
    b.deliver(caseDetail(index));
  }
  /** Assert the view shows every value of case `index` and none of the other case's; null: none. */
  function assertShows(b: Bench, index: number | null, why: string): void {
    const html = b.detail.innerHTML as string;
    for (const i of [0, 1]) {
      for (const v of valuesOf(i)) {
        const want = i === index;
        assert.strictEqual(html.includes(v), want, `${why}: case ${i} value ${v} ${want ? "missing" : "shown"}`);
      }
      assert.strictEqual(button(b, i).getAttribute("aria-expanded"), String(i === index), `${why}: case ${i} aria-expanded`);
    }
    assert.deepStrictEqual(b.errors.map(String), [], `${why}: the page threw`);
  }

  test("the run renders names, PASS or FAIL and dispositions, and no value", () => {
    const b = runOnScreen();
    assertShows(b, null, "before any click");
    assert.strictEqual(b.detail.querySelector(".diffs"), null, "a difference rendered unasked");
    for (const c of JUDGED.summaries) {
      assert.ok(b.detail.textContent.includes(c.name), `case name ${c.name} missing`);
    }
    assert.strictEqual(b.detail.querySelectorAll(".case .badge.fail").length, 2, "one FAIL badge per case");
    assert.strictEqual(button(b, 1).getAttribute("aria-label"), "Details for case_c");
  });

  test("a click asks the host for that one case, and nothing renders until it answers", () => {
    const b = runOnScreen();
    button(b, 1).click();
    assert.deepStrictEqual(b.posted, [{ command: "caseDetail", run: RUN_ID, index: 1 }]);
    assertShows(b, null, "clicked, no reply yet");
  });

  test("one click shows one case, and a second case replaces the first", () => {
    const b = runOnScreen();
    reveal(b, 1);
    assertShows(b, 1, "case 1 revealed");
    reveal(b, 0);
    assertShows(b, 0, "case 0 revealed after case 1");
  });

  test("a second click on an open case closes it without asking the host", () => {
    const b = runOnScreen();
    reveal(b, 0);
    button(b, 0).click();
    assertShows(b, null, "closed again");
    assert.strictEqual(b.posted.length, 1, "closing posted a request");
  });

  test("a second click on a case still waiting asks again rather than doing nothing", () => {
    const b = runOnScreen();
    button(b, 0).click();
    button(b, 0).click();
    assert.strictEqual(b.posted.length, 2);
    b.deliver(caseDetail(0));
    assertShows(b, 0, "the reply to either request");
  });

  test("a reply that lands after Back does not reveal the case", () => {
    const b = runOnScreen();
    button(b, 0).click();
    b.window.document.getElementById("back").click();
    b.deliver(caseDetail(0));
    assertShows(b, null, "late reply after Back");
  });

  test("a reply that lands after another view replaced the run renders nothing", () => {
    const b = runOnScreen();
    button(b, 0).click();
    b.deliver(clone(COLLECTIONS));
    b.deliver(clone(RUN)); // the same run id back on screen, with no case asked for
    b.deliver(caseDetail(0));
    assertShows(b, null, "reply for a request made before the view changed");
  });

  test("a reply for a case other than the one last asked for renders nothing", () => {
    const b = runOnScreen();
    button(b, 0).click();
    button(b, 1).click();
    b.deliver(caseDetail(0));
    assertShows(b, null, "reply for the replaced request");
    b.deliver(caseDetail(1));
    assertShows(b, 1, "reply for the latest request");
  });

  test("Back clears a revealed case from the hidden view", () => {
    const b = runOnScreen();
    reveal(b, 1);
    b.window.document.getElementById("back").click();
    assertShows(b, null, "after Back");
  });

  test("a reply nobody asked for, or for another run, renders nothing", () => {
    const b = runOnScreen();
    const before = b.detail.innerHTML;
    b.deliver(caseDetail(0));
    button(b, 0).click();
    b.deliver(caseDetail(0, RUN_ID + 1));
    b.deliver({ ...caseDetail(0), index: 7 });
    assert.strictEqual(b.detail.innerHTML, before, "an unasked or stale reply rendered");
    assertShows(b, null, "unasked or stale replies");
    assertDiscarded(caseDetail(0), "no run on screen");
  });

  test("a case with no difference and no error says so rather than rendering blank", () => {
    const b = runOnScreen();
    button(b, 0).click();
    b.deliver({ type: "caseDetail", run: RUN_ID, index: 0, error: null, deliveries: [] });
    assert.ok(b.detail.textContent.includes("No differences."));
  });

  test("caseDetail: malformed payloads are discarded by the shape check", () => {
    // Control: the unmutated JSON copy renders, and warns nothing.
    const control = runOnScreen();
    button(control, 0).click();
    control.deliver(clone(caseDetail(0)));
    assertShows(control, 0, "control");
    assert.deepStrictEqual(control.warnings, []);
    const good = caseDetail(0);
    const cases: [string, (p: Payload) => void][] = [
      ["a string difference index", (p) => (p.deliveries[0].differences[0].index = "3")],
      ["markup as a difference index", (p) => (p.deliveries[0].differences[0].index = XSS)],
      ["a numeric before value", (p) => (p.deliveries[0].differences[0].before = 5)],
      ["a numeric error", (p) => (p.error = 5)],
      ["deliveries not an array", (p) => (p.deliveries = null)],
      ["a string case index", (p) => (p.index = "0")],
      ["a string run id", (p) => (p.run = String(RUN_ID))],
      ["no run id", (p) => delete p.run],
    ];
    for (const [why, mutate] of cases) {
      const b = runOnScreen();
      button(b, 0).click();
      const shown = b.detail.innerHTML;
      const p = clone(good);
      mutate(p);
      assert.notDeepStrictEqual(p, good, `${why}: the mutation changed nothing, so it tests nothing`);
      b.deliver(p);
      assert.deepStrictEqual(b.errors.map(String), [], `${why}: the page threw instead of discarding`);
      assert.strictEqual(b.detail.innerHTML, shown, `${why}: detail was re-rendered`);
      // The discard must come from the shape check, not from the stale-reply check behind it.
      assert.ok(b.warnings.some((w) => w.includes('discarded a malformed "caseDetail"')), `${why}: not a shape discard`);
    }
  });

  test("markup in a revealed value renders as text", () => {
    const b = runOnScreen();
    button(b, 0).click();
    const p = clone(caseDetail(0));
    p.deliveries[0].differences[0].after = XSS;
    b.deliver(p);
    assert.strictEqual(b.detail.querySelector("img"), null, "a difference value became an element");
    assert.ok(b.detail.textContent.includes("<img"), "the value was dropped rather than escaped");
  });
});

// BACKLOG #2441: leaving the run view tells the host, and the host then answers no caseDetail for it.
suite("Test Bench webview — leaving the run view releases the run the host holds", () => {
  teardown(closeWindows);

  type Held = { id: number; details: typeof JUDGED.details } | null;
  const leave = { command: "leaveRun", run: RUN_ID };
  function leaves(b: Bench): Payload[] {
    return b.posted.filter((m) => m.command === "leaveRun");
  }
  /** Play the host's half: apply each posted message to the held run, as testBench.ts onMessage does. */
  function hostAfter(b: Bench): Held {
    let held: Held = { id: RUN_ID, details: JUDGED.details };
    for (const m of b.posted) {
      held = heldAfterIncoming(held, m);
    }
    return held;
  }

  test("on the run view the host still answers a caseDetail (control)", () => {
    const b = assertRendered(RUN, "collectionRun");
    b.detail.querySelector('button[data-case-detail="0"]').click();
    assert.deepStrictEqual(leaves(b), [], "the run view posted leaveRun while still on screen");
    assert.strictEqual(pickCaseDetail(hostAfter(b), RUN_ID, 0), JUDGED.details[0]);
  });

  test("Back posts leaveRun once, and the host then answers no caseDetail for that run", () => {
    const b = assertRendered(RUN, "collectionRun");
    b.window.document.getElementById("back").click();
    assert.deepStrictEqual(leaves(b), [leave]);
    assert.strictEqual(pickCaseDetail(hostAfter(b), RUN_ID, 0), null, "a released run was answered");
    b.deliver(clone(COLLECTIONS)); // the run view is already gone, so nothing is left again
    assert.deepStrictEqual(leaves(b), [leave], "a second leave was posted");
  });

  test("another view replacing the run view posts leaveRun, and the host answers nothing after", () => {
    const b = assertRendered(RUN, "collectionRun");
    b.deliver(clone(COLLECTIONS));
    assert.deepStrictEqual(leaves(b), [leave]);
    assert.strictEqual(pickCaseDetail(hostAfter(b), RUN_ID, 1), null, "a released run was answered");
  });

  test("each other view type replacing the run view posts leaveRun", () => {
    for (const [why, payload] of [
      ["detail", DETAIL],
      ["trace", TRACE],
      ["hex", HEX],
    ] as [string, Payload][]) {
      const b = assertRendered(RUN, "collectionRun");
      b.deliver(clone(payload));
      assert.deepStrictEqual(b.errors.map(String), [], `${why}: the page threw`);
      assert.deepStrictEqual(leaves(b), [leave], why);
    }
  });

  test("a caseDetail reply does not count as leaving the run view", () => {
    const b = assertRendered(RUN, "collectionRun");
    b.detail.querySelector('button[data-case-detail="0"]').click();
    b.deliver(caseDetail(0));
    assert.deepStrictEqual(leaves(b), []);
  });

  test("a newer run replacing the view releases only the old run id", () => {
    const b = assertRendered(RUN, "collectionRun");
    b.deliver({ ...clone(RUN), run: RUN_ID + 1 });
    assert.deepStrictEqual(leaves(b), [leave]);
    const newer = { id: RUN_ID + 1, details: JUDGED.details };
    assert.strictEqual(releaseRun(newer, RUN_ID), newer, "the old run's leave dropped the newer run");
  });

  test("no run view on screen means nothing to leave", () => {
    const b = bench();
    b.deliver(clone(COLLECTIONS));
    b.window.document.getElementById("back").click();
    assert.deepStrictEqual(leaves(b), []);
  });
});
