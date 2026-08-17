// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  ADD_MENU_CATALOG,
  addMenuGroups,
  blockExtent,
  blockLabel,
  buildDropSlots,
  buildHandlerViewModels,
  canDropRow,
  captureBlock,
  contextMenuEnablement,
  insertionBarAnchor,
  isReturnRow,
  itemAllowedInRole,
  paletteFor,
  roleScopeAttr,
  renderHandlersHtml,
  renderStepsContextMenuHtml,
  resolveDrop,
  scopeLabel,
  walkMove,
  type BlockCaptureRow,
  type DropResolution,
  type LensHandler,
  type LensParseResult,
  type LensRow,
  type RowDropContext,
  type RowKind,
  type RowViewModel,
} from "../../stepsModel";

// ---------------------------------------------------------------------------------------------------
// BACKLOG #233 — the webview↔model MIRROR-PARITY differential suite (master test plan
// docs/testing/master-test-plan/13-steps-editor.md §S2, STEPS-06..12).
//
// `ide/media/stepsWebview.js` is loaded as a plain script into a `default-src 'none'` webview (the
// `<script nonce src>` tag `pageHtml` emits in `stepsView.ts`, from an `asWebviewUri` of `media/`), so
// it CANNOT import `ide/src/stepsModel.ts`. It therefore re-implements ten pure
// model functions by hand. The drag/drop PREVIEW the user sees comes from the webview copy while the
// COMMITTED splice coordinates come from the model copy — a divergence would land a statement somewhere
// other than where the indicator said, byte-stably, re-parsing clean, with every existing test green.
//
// This suite closes that hole WITHOUT de-duplicating the code (owner ruling: option (c)): it loads the
// real webview script under jsdom, reaches its mirrors through an opt-in test hook, and asserts they
// agree with `stepsModel`'s versions over TWO populations — four hand-authored adversarial cases that
// go through the real render → DOM → read-back boundary, and 2,000 seeded generated row sets for the
// mirrors that are pure array functions. See the note above `generateRowSet` for why the split exists.
//
// ADAPTER DISCIPLINE — the one thing that could make this suite vacuous is a generous adapter that
// reshapes one side until parity is trivially true. So:
//   * the WEBVIEW side is always sourced from the RENDERED DOM (renderRowHtml → dataset → stepsCtxRows),
//     never from the fixtures directly;
//   * the MODEL side is always sourced from the VIEW MODELS (buildHandlerViewModels), never from the DOM;
//   * every adapter below is a one-line field read and is commented as such.
// The comparison therefore spans the real serialization boundary, which is where `suite`,
// `isControlHeader`, `draggable` and `data-is-return` are actually decided. T1's falsification (deleting
// the `data-suite` emission from renderRowHtml) is the specific check that the adapter did not paper
// over that boundary.
//
// Node-side only: this file must NOT import `vscode`, so it runs on EVERY `ide` CI leg (the ubuntu one
// included), not only the Windows-only Extension Host leg.
// ---------------------------------------------------------------------------------------------------

// jsdom is loaded through a CommonJS `require` behind a narrow local shape ON PURPOSE: `ide/tsconfig.json`
// sets `lib: ["ES2022"]` with NO "DOM" (a deliberate guardrail for an extension that must not reach for
// browser globals), and `npm run typecheck` covers `src/test` too. Pulling in `@types/jsdom` — or typing
// any local as a DOM interface — would reference `lib.dom` and break the type-check for the whole
// extension. DOM values therefore stay loosely typed inside this file only.
interface JsdomWindow {
  document: DomNode;
  MouseEvent: new (type: string, init?: Record<string, unknown>) => unknown;
  Event: new (type: string, init?: Record<string, unknown>) => unknown;
  [key: string]: unknown;
}
interface DomNode {
  // Deliberately `any`: the base tsconfig has no DOM lib (see the note above), so DOM values are
  // untyped here rather than dragging lib.dom into the extension's own type-check.
  [key: string]: any;
}
interface JsdomVirtualConsole {
  on(event: string, handler: (err: unknown) => void): void;
}
interface JsdomModule {
  JSDOM: new (html: string, options?: Record<string, unknown>) => { window: JsdomWindow };
  VirtualConsole: new () => JsdomVirtualConsole;
}
const { JSDOM, VirtualConsole } = require("jsdom") as JsdomModule;

const IDE_ROOT = path.join(__dirname, "..", "..", "..");
const WEBVIEW_JS = path.join(IDE_ROOT, "media", "stepsWebview.js");
const STEPS_VIEW_TS = path.join(IDE_ROOT, "src", "stepsView.ts");

/** Row height (px) used by the per-row `getBoundingClientRect` stub — see {@link stubRowRects}. */
const ROW_H = 20;

// ---- the corpus ------------------------------------------------------------------------------------

/** One generated corpus case: a `lens parse` payload plus the module source its rows index into. */
interface CorpusCase {
  name: string;
  parse: LensParseResult;
  source: string;
}

/**
 * A module source of `lineCount` lines, each distinctive AND carrying `&`, `<`, `>`, `"` and `'` — so a
 * row's `expectSrc` round-trip through `escapeHtml` → `data-expect-src` → `dataset.expectSrc` is
 * exercised by every single row of every case rather than by one bespoke test.
 */
function sourceOf(lineCount: number): string {
  return Array.from(
    { length: lineCount },
    (_v, i) => `    stmt_${i + 1}(a & b, "<x>", '\\''); # line ${i + 1}`,
  ).join("\n");
}

function handlerOf(name: string, defLine: number, rows: LensRow[]): LensHandler {
  return { handler: name, module: "corpus", def_line: defLine, rows };
}

/** Nesting 0–4, an if/elif/else chain, nested `for` headers, an EMPTY-bodied `if`, a `raise`, code rows,
 * the accumulator scaffold pair and a mid-body append send. The structural workhorse of the suite. */
function caseDeepNesting(): CorpusCase {
  const rows: LensRow[] = [
    { kind: "code", line_start: 2, line_end: 2, nesting: 0, suite: "1", scaffold: "collector_init" },
    {
      kind: "action",
      action: "set_field",
      line_start: 3,
      line_end: 3,
      nesting: 0,
      suite: "1",
      params: { path: "PID-3", value: "X" },
      literal_params: ["path", "value"],
    },
    {
      kind: "control",
      control: "for",
      line_start: 4,
      line_end: 4,
      nesting: 0,
      suite: "1",
      label: 'For each & <OBX> "segment"',
      test_src: "seg in msg.groups()",
      recognized: true,
    },
    { kind: "action", action: "copy_field", line_start: 5, line_end: 5, nesting: 1, suite: "4", params: { src: "A", dst: "B" }, literal_params: ["src", "dst"] },
    { kind: "control", control: "if", line_start: 6, line_end: 6, nesting: 1, suite: "4", test_src: 'msg["PID-3"] == "X"', recognized: true },
    { kind: "lookup", call: "code_lookup", assign_to: "v", line_start: 7, line_end: 7, nesting: 2, suite: "6", params: { path: "PID-8" }, literal_params: ["path"] },
    { kind: "control", control: "for", line_start: 8, line_end: 8, nesting: 2, suite: "6", test_src: "obx in segs", recognized: false },
    { kind: "diagnostic", call: "log_note", line_start: 9, line_end: 9, nesting: 3, suite: "8", params: { template: "note" }, literal_params: ["template"] },
    { kind: "control", control: "if", line_start: 10, line_end: 10, nesting: 3, suite: "8", test_src: "v", recognized: true },
    { kind: "action", action: "append_to_field", line_start: 11, line_end: 11, nesting: 4, suite: "10", params: { path: "OBX-5", value: "!" }, literal_params: ["path", "value"] },
    { kind: "control", control: "elif", line_start: 12, line_end: 12, nesting: 1, suite: "4", test_src: "other", recognized: true },
    { kind: "code", line_start: 13, line_end: 13, nesting: 2, suite: "12" },
    { kind: "control", control: "else", line_start: 14, line_end: 14, nesting: 1, suite: "4", test_src: null, recognized: true },
    { kind: "action", action: "convert_case", line_start: 15, line_end: 15, nesting: 2, suite: "14", params: { path: "PID-5", mode: "upper" }, literal_params: ["path", "mode"] },
    { kind: "send", line_start: 16, line_end: 16, nesting: 1, suite: "4", appended: true, outbounds: ["OB_A"] },
    { kind: "code", line_start: 17, line_end: 17, nesting: 0, suite: "1" },
    // An `if` whose body has NO row in this list — the "into the body" gesture has nothing to anchor to.
    { kind: "control", control: "if", line_start: 18, line_end: 18, nesting: 0, suite: "1", test_src: "flag", recognized: true },
    { kind: "control", control: "raise", line_start: 19, line_end: 19, nesting: 0, suite: "1", test_src: null, recognized: true },
    { kind: "send", line_start: 20, line_end: 20, nesting: 0, suite: "1", appended: true, outbounds: ["OB_B"] },
    { kind: "code", line_start: 21, line_end: 21, nesting: 0, suite: "1", scaffold: "return_collector" },
  ];
  return {
    name: "deep-nesting",
    parse: { module: "corpus", handlers: [handlerOf("deep", 1, rows)] },
    source: sourceOf(21),
  };
}

/** The ADR 0104/0108 fan-out shapes: a `return []` FILTER inside a guard, the accumulator init, two
 * appended sends and the `return sends` footer. */
function caseFanout(): CorpusCase {
  const rows: LensRow[] = [
    { kind: "action", action: "set_field", line_start: 2, line_end: 2, nesting: 0, suite: "1", params: { path: "MSH-3", value: "MF" }, literal_params: ["path", "value"] },
    { kind: "control", control: "if", line_start: 3, line_end: 3, nesting: 0, suite: "1", test_src: 'msg["MSH-9.1"] != "ADT"', recognized: true },
    { kind: "send", line_start: 4, line_end: 4, nesting: 1, suite: "3", filtered: true, outbounds: [] },
    { kind: "code", line_start: 5, line_end: 5, nesting: 0, suite: "1", scaffold: "collector_init" },
    { kind: "send", line_start: 6, line_end: 6, nesting: 0, suite: "1", appended: true, outbounds: ["OB_X"] },
    { kind: "send", line_start: 7, line_end: 7, nesting: 0, suite: "1", appended: true, outbounds: ["OB_Y"] },
    { kind: "code", line_start: 8, line_end: 8, nesting: 0, suite: "1", scaffold: "return_collector" },
  ];
  return {
    name: "fanout-and-filter",
    parse: { module: "corpus", handlers: [handlerOf("fanout", 1, rows)] },
    source: sourceOf(8),
  };
}

/** A flat handler whose def is NOT on line 1, containing a MULTI-LINE row (a call split over two lines)
 * and a terminal returned send. */
function caseFlat(): CorpusCase {
  const rows: LensRow[] = [
    { kind: "action", action: "delete_segment", line_start: 3, line_end: 3, nesting: 0, suite: "2", params: { segment_id: "ZZZ" }, literal_params: ["segment_id"] },
    { kind: "lookup", call: "db_lookup", assign_to: "row", line_start: 4, line_end: 5, nesting: 0, suite: "2", params: { statement: "SELECT 1" }, literal_params: ["statement"] },
    { kind: "diagnostic", call: "checkpoint", line_start: 6, line_end: 6, nesting: 0, suite: "2", params: { label: "after-lookup" }, literal_params: ["label"] },
    { kind: "code", line_start: 7, line_end: 7, nesting: 0, suite: "2" },
    { kind: "send", line_start: 8, line_end: 8, nesting: 0, suite: "2", outbounds: ["OB_Z"] },
  ];
  return {
    name: "flat-multiline",
    parse: { module: "corpus", handlers: [handlerOf("flat", 2, rows)] },
    source: sourceOf(8),
  };
}

/** Control headers whose titles carry `&`, `<`, `>`, `"` and `'` — the HTML-escaping boundary the
 * webview's `scopeLabel` crosses (it reads `.textContent` off escaped markup; the model takes the raw
 * title). */
function caseEscaping(): CorpusCase {
  const rows: LensRow[] = [
    {
      kind: "control",
      control: "for",
      line_start: 2,
      line_end: 2,
      nesting: 0,
      suite: "1",
      label: `For each & <OBX>-5 "rep" 'x' > 1`,
      test_src: "obx in segs",
      recognized: true,
    },
    { kind: "action", action: "set_field", line_start: 3, line_end: 3, nesting: 1, suite: "2", params: { path: "OBX-5", value: "1" }, literal_params: ["path", "value"] },
    {
      kind: "control",
      control: "if",
      line_start: 4,
      line_end: 4,
      nesting: 1,
      suite: "2",
      label: `If <PID>-3 & "MRN" isn't blank`,
      test_src: 'msg["PID-3"]',
      recognized: true,
    },
    { kind: "action", action: "format_date", line_start: 5, line_end: 5, nesting: 2, suite: "4", params: { path: "PID-7", format: "%Y" }, literal_params: ["path", "format"] },
    { kind: "action", action: "split_field", line_start: 6, line_end: 6, nesting: 0, suite: "1", params: { path: "PID-5" }, literal_params: ["path"] },
  ];
  return {
    name: "escaping",
    parse: { module: "corpus", handlers: [handlerOf("escapes", 1, rows)] },
    source: sourceOf(6),
  };
}

/** TWO handlers in one document — the only shape that can exercise `canDrop`'s cross-handler refusal
 * (the DOM carries `data-handler`; a single-handler page can never disagree about it). */
function caseTwoHandlers(): CorpusCase {
  const a: LensRow[] = [
    { kind: "action", action: "set_field", line_start: 2, line_end: 2, nesting: 0, suite: "1", params: { path: "PID-3", value: "A" }, literal_params: ["path", "value"] },
    { kind: "action", action: "copy_field", line_start: 3, line_end: 3, nesting: 0, suite: "1", params: { src: "A", dst: "B" }, literal_params: ["src", "dst"] },
  ];
  const b: LensRow[] = [
    { kind: "action", action: "set_field", line_start: 6, line_end: 6, nesting: 0, suite: "5", params: { path: "PID-4", value: "B" }, literal_params: ["path", "value"] },
    { kind: "send", line_start: 7, line_end: 7, nesting: 0, suite: "5", outbounds: ["OB_Q"] },
  ];
  return {
    name: "two-handlers",
    parse: { module: "corpus", handlers: [handlerOf("first", 1, a), handlerOf("second", 5, b)] },
    source: sourceOf(7),
  };
}

const CORPUS: CorpusCase[] = [caseDeepNesting(), caseFanout(), caseFlat(), caseEscaping()];

// ---- the seeded ROW-SET GENERATOR (master test plan §S2 step 1, STEPS-07/08) -----------------------
//
// The four cases above are hand-authored and adversarial, but finite: they only cover shapes somebody
// thought of. The generator covers the ones nobody did. It drives ONLY those mirrors that take a plain
// ROW ARRAY (`blockExtent`, `captureBlock` + `clipLabel`, `buildDropSlots`, `walkMove`) — which is what
// makes ≥2,000 sets affordable: those five are pure array-in/value-out on both sides, so the whole
// sweep runs against ONE loaded page instead of one jsdom document per set.
//
// The DOM-bound four (`canDrop`, `resolveDrop`, `barAnchor`, and `scopeLabel`, which reads
// `.textContent` off the rendered header) take `<li>` ELEMENTS and a `getBoundingClientRect`, so they
// cannot be driven this way at all. They stay on the rendered corpus, where each case is a real
// render → DOM → read-back round trip (T1/T2/T5) — a smaller population, but the only one that can
// exercise them. Neither half subsumes the other, and §12.2 of the test plan says so.
//
// `raise` headers are deliberately NOT generated: `RowDropContext.control` omits `"raise"` because no
// drop helper tests for anything but `elif`/`else`, and the hand-authored corpus already carries one.

/** How many row sets the sweep generates (the test plan's ≥2,000). */
const GENERATED_SETS = 2000;
/** The reproduction handle. Set `i`'s seed is `GENERATOR_SEED + i`, printed on any failure. */
const GENERATOR_SEED = 0x5713_2026;
/** Row budget per generated set — enough for nesting 0–4 with continuations, small enough to stay fast. */
const MAX_GENERATED_ROWS = 16;

/** mulberry32 — a tiny, well-known deterministic PRNG. Same seed ⇒ byte-identical row set, on every
 * platform and every Node version, which is what makes a failure reproducible from the printed seed. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** One generated row set, in BOTH sides' shapes — built from the SAME draw, so any divergence the sweep
 * reports is the two IMPLEMENTATIONS disagreeing, never the two inputs differing. */
interface GeneratedRowSet {
  seed: number;
  web: CtxRow[];
  model: BlockCaptureRow[];
}

function generateRowSet(seed: number): GeneratedRowSet {
  const rnd = mulberry32(seed);
  const web: CtxRow[] = [];
  const model: BlockCaptureRow[] = [];
  let line = 2;

  interface Draw {
    kind: RowKind;
    nesting: number;
    suite: string;
    control?: RowDropContext["control"];
    appended?: boolean;
    scaffold?: string;
    draggable: boolean;
    isControlHeader: boolean;
    multiLine?: boolean;
  }

  /** Append one row to both sides. `isReturn` is derived with the SHIPPED {@link isReturnRow}, so the
   * DOM flag the webview reads and the `appended`/`scaffold` pair the model reads can never disagree
   * about it by construction — the same derivation `buildRowViewModel` performs. */
  const push = (d: Draw): number => {
    const lineStart = line;
    const lineEnd = line + (d.multiLine ? 1 : 0);
    line = lineEnd + 1;
    const expectSrc = `${"    ".repeat(d.nesting + 1)}stmt_${lineStart}(a & b, "<x>", 'y')`;
    const isReturn = isReturnRow({ kind: d.kind, appended: d.appended, scaffold: d.scaffold });
    web.push({
      lineStart,
      lineEnd,
      nesting: d.nesting,
      suite: d.suite,
      kind: d.kind,
      control: d.control,
      expectSrc,
      draggable: d.draggable,
      isControlHeader: d.isControlHeader,
      isReturn,
    });
    model.push({
      handler: "gen",
      lineStart,
      lineEnd,
      nesting: d.nesting,
      suite: d.suite,
      kind: d.kind,
      draggable: d.draggable,
      appended: d.appended,
      scaffold: d.scaffold,
      isControlHeader: d.isControlHeader,
      control: d.control,
      expectSrc,
    });
    return lineStart;
  };

  const leaf = (nesting: number, suite: string): void => {
    const roll = rnd();
    if (roll < 0.18) {
      // A `code` row: read-only, yet marked draggable so the webview can INTERCEPT the gesture — the
      // exact combination the one real divergence hid in. Sometimes a scaffold row.
      const s = rnd();
      push({
        kind: "code",
        nesting,
        suite,
        scaffold: s < 0.2 ? "collector_init" : s < 0.4 ? "return_collector" : undefined,
        draggable: true,
        isControlHeader: false,
      });
      return;
    }
    if (roll < 0.4) {
      // A send: `appended` (a mid-body step, a normal two-zone target) vs a terminal return.
      push({
        kind: "send",
        nesting,
        suite,
        appended: rnd() < 0.5 ? true : undefined,
        draggable: true,
        isControlHeader: false,
      });
      return;
    }
    push({
      kind: rnd() < 0.5 ? "action" : rnd() < 0.5 ? "lookup" : "diagnostic",
      nesting,
      suite,
      // Adversarial: a non-draggable editable leaf does not occur in today's projection, but both
      // mirrors must still agree about it, and pinning that keeps the gate honest if the rule moves.
      draggable: rnd() < 0.9,
      isControlHeader: false,
      multiLine: rnd() < 0.15,
    });
  };

  const emitSuite = (suite: string, nesting: number, count: number): void => {
    for (let i = 0; i < count && web.length < MAX_GENERATED_ROWS; i++) {
      if (nesting < 4 && rnd() < 0.4) {
        const kw = rnd() < 0.5 ? "if" : "for";
        const header = push({
          kind: "control",
          nesting,
          suite,
          control: kw,
          draggable: true,
          isControlHeader: true,
        });
        // 0 body rows is a real shape (an `if` whose only statement is unrecognized and filtered out of
        // this list) and is the one that has no "into the body" anchor.
        emitSuite(String(header), nesting + 1, Math.floor(rnd() * 3));
        if (kw === "if") {
          const conts = Math.floor(rnd() * 3);
          for (let k = 0; k < conts && web.length < MAX_GENERATED_ROWS; k++) {
            // A CONTINUATION sits at the header's nesting, in the header's OWN suite, and is neither
            // draggable nor a control header — it is consumed with its `if`.
            const cont = push({
              kind: "control",
              nesting,
              suite,
              control: k === conts - 1 && rnd() < 0.5 ? "else" : "elif",
              draggable: false,
              isControlHeader: false,
            });
            emitSuite(String(cont), nesting + 1, Math.floor(rnd() * 3));
          }
        }
      } else {
        leaf(nesting, suite);
      }
    }
  };

  // The root suite is the handler's `def` line, exactly as `lens parse` numbers it. At least one row.
  emitSuite("1", 0, 1 + Math.floor(rnd() * 5));
  if (web.length === 0) {
    leaf(0, "1");
  }
  return { seed, web, model };
}

// ---- the jsdom harness -----------------------------------------------------------------------------

/** What one loaded page gives the assertions. */
interface Harness {
  window: JsdomWindow;
  /** The webview's own mirrors, handed out by the opt-in `__mfStepsTestExports` hook. */
  hook: Record<string, (...args: any[]) => any>;
  /** Every `postMessage` the script made, in order (the recording `acquireVsCodeApi` double). */
  posted: Record<string, unknown>[];
  /** Uncaught script errors jsdom reported while the page ran (empty on a healthy load). */
  scriptErrors: unknown[];
  /** How many times the script called `acquireVsCodeApi()`. */
  acquireCount: number;
  /** The `<li class="row">` elements, in document order. */
  rowEls: DomNode[];
}

/** The CSP/nonce page shell reduced to exactly the elements `stepsWebview.js` reads. The five ids below
 * are read UNGUARDED (`document.getElementById('x').addEventListener(...)` at :151-153, and the
 * `addAction`/`insertAction` consts at :263-264 that `updateAddState` dereferences), so omitting any one
 * of them makes the script throw at load — which is exactly what T9's inventory guard pins. */
function pageShell(bodyHtml: string): string {
  const insertOptions = [`<option value="">[select item]</option>`]
    .concat(
      addMenuGroups().map(
        ({ group, items }) =>
          `<optgroup label="${group}">` +
          items
            .map(
              (item) =>
                `<option value="${item.id}"` +
                (item.anchorConstraint ? ` data-anchor="${item.anchorConstraint}"` : "") +
                `>${item.label}</option>`,
            )
            .join("") +
          `</optgroup>`,
      ),
    )
    .join("");
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>steps</title></head><body>` +
    `<div class="bar">` +
    `<input id="stepsFilter" type="search" />` +
    `<select id="insertAction">${insertOptions}</select>` +
    `<button id="addAction" disabled>Add</button>` +
    `<button id="pickSample">Pick Sample</button>` +
    `<button id="test">Test</button>` +
    `<button id="openText">View as Code</button>` +
    `</div>` +
    bodyHtml +
    renderStepsContextMenuHtml() +
    `</body></html>`
  );
}

/**
 * jsdom has no layout engine, so EVERY `getBoundingClientRect()` returns an all-zero rect. The webview's
 * `resolveDrop` computes `frac = (ev.clientY - box.top) / box.height` and falls back to a CONSTANT 0.5
 * when `box.height <= 0` — which would silently collapse every tri-zone assertion in this file into the
 * same middle-zone case and make them vacuous. Give each row a deterministic 20 px band so a pointer
 * fraction actually means something. (T5's second falsification removes this and proves the assertions
 * stop discriminating without it.)
 */
function stubRowRects(rowEls: DomNode[]): void {
  rowEls.forEach((el, i) => {
    const top = i * ROW_H;
    el.getBoundingClientRect = (): Record<string, number> => ({
      top,
      bottom: top + ROW_H,
      left: 0,
      right: 400,
      width: 400,
      height: ROW_H,
      x: 0,
      y: top,
    });
  });
}

/** The clientY that lands `fraction` of the way down row `index`, given {@link stubRowRects}. */
function clientYFor(index: number, fraction: number): number {
  return index * ROW_H + fraction * ROW_H;
}

interface LoadOptions {
  /** Set `window.__mfStepsTestExportsEnabled` before the script runs (default true). */
  exposeHook?: boolean;
  /** Skip the per-row rect stub (T5's harness falsification only). */
  skipRectStub?: boolean;
  /** Require the hook to be present afterwards (default: mirrors `exposeHook`). */
  requireHook?: boolean;
}

/** Load the REAL `media/stepsWebview.js` into a jsdom page built from `bodyHtml`. */
function loadWebview(bodyHtml: string, opts: LoadOptions = {}): Harness {
  const exposeHook = opts.exposeHook !== false;
  const scriptErrors: unknown[] = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e: unknown) => scriptErrors.push(e));

  const dom = new JSDOM(pageShell(bodyHtml), {
    runScripts: "dangerously",
    virtualConsole,
    url: "https://localhost/",
  });
  const window = dom.window;
  const posted: Record<string, unknown>[] = [];
  let acquireCount = 0;
  let webviewState: unknown = undefined;
  // The recording double: captures EVERY postMessage so a test can assert what the page told the
  // provider (the ping handshake, `codeLocked`, a moveTo, …). `getState`/`setState` are the webview's
  // own clipboard/selection store (stepsWebview.js:297-303) — an in-memory object is faithful enough.
  window.acquireVsCodeApi = (): Record<string, unknown> => {
    acquireCount += 1;
    return {
      postMessage: (m: Record<string, unknown>): void => {
        posted.push(m);
      },
      getState: (): unknown => webviewState,
      setState: (v: unknown): void => {
        webviewState = v;
      },
    };
  };
  if (exposeHook) {
    window.__mfStepsTestExportsEnabled = true;
  }

  const rowEls: DomNode[] = Array.from(
    window.document.querySelectorAll("li.row"),
  ) as DomNode[];
  if (!opts.skipRectStub) {
    stubRowRects(rowEls);
  }

  const script = window.document.createElement("script");
  script.textContent = fs.readFileSync(WEBVIEW_JS, "utf8");
  window.document.body.appendChild(script);

  const hook = window.__mfStepsTestExports as
    | Record<string, (...args: any[]) => any>
    | undefined;
  const requireHook = opts.requireHook ?? exposeHook;
  if (requireHook && !hook) {
    assert.fail(
      `stepsWebview.js did not publish __mfStepsTestExports — the script most likely threw at load. ` +
        `jsdom errors: ${scriptErrors.map((e) => String(e)).join(" | ") || "(none)"}; ` +
        `posted: ${JSON.stringify(posted)}`,
    );
  }
  return {
    window,
    hook: hook ?? {},
    posted,
    scriptErrors,
    acquireCount,
    rowEls,
  };
}

// ---- the two sides, and the one-line adapters between them -----------------------------------------

/**
 * Rebuild a plain value that came out of the jsdom realm using THIS realm's Object/Array prototypes.
 *
 * `assert.deepStrictEqual` compares prototypes, and every object the webview script creates is built
 * inside jsdom's realm — so a byte-for-byte identical row object fails with an EMPTY diff ("actual" and
 * "expected" print the same). This is a cross-realm artifact of loading the script under jsdom, NOT a
 * divergence, so it is normalised away here rather than by weakening the comparison to `deepEqual`.
 * `undefined`-valued keys are preserved (they are load-bearing: `deepStrictEqual` distinguishes
 * `{control: undefined}` from `{}`), which is why this is not `JSON.parse(JSON.stringify(...))`.
 * Only ever applied to PLAIN data — DOM elements are converted by the one-line adapters instead.
 */
function plain<T>(value: T): T {
  if (Array.isArray(value)) {
    // NOT `.map()`: Array.prototype.map builds its result through the SOURCE array's species
    // constructor, so mapping a jsdom array yields another jsdom array and the prototype mismatch
    // survives. Push into a literal array declared in this realm instead.
    const out: unknown[] = [];
    for (const item of value as unknown[]) {
      out.push(plain(item));
    }
    return out as unknown as T;
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>)) {
      out[key] = plain((value as Record<string, unknown>)[key]);
    }
    return out as unknown as T;
  }
  return value;
}

/** The row shape `stepsCtxRows()` yields — i.e. a row AFTER the renderRowHtml → dataset → read-back
 * round trip. The model side is built into the SAME shape from the view models, never from the DOM. */
interface CtxRow {
  lineStart: number;
  lineEnd: number;
  nesting: number;
  suite: string;
  kind: string;
  control: string | undefined;
  expectSrc: string;
  draggable: boolean;
  isControlHeader: boolean;
  isReturn: boolean;
}

/** The MODEL side of a row context, derived from the view model only. Every line is a direct field read:
 *  `draggable` is the model's own rule (`isRowMovable` → `RowViewModel.movable`, plus the `code`-row
 *  drag-interception marker documented in `renderRowHtml`); `isReturn` is recomputed with the
 *  exported {@link isReturnRow} rather than trusting the precomputed `RowViewModel.isReturn`, so the
 *  comparison also pins `buildRowViewModel`'s emission of it. */
function modelCtxRows(vms: RowViewModel[]): CtxRow[] {
  return vms.map((vm) => {
    const draggable = vm.movable === true || vm.kind === "code";
    return {
      lineStart: vm.lineStart,
      lineEnd: vm.lineEnd,
      nesting: vm.nesting,
      suite: vm.suite ?? "",
      kind: vm.kind,
      control: vm.control,
      expectSrc: vm.expectSrc ?? "",
      draggable,
      isControlHeader: vm.kind === "control" && draggable,
      isReturn: isReturnRow(vm),
    };
  });
}

/** The model functions' input type. `control` is narrowed because `RowDropContext.control` deliberately
 * omits `"raise"` (a `raise` header is neither an `elif` nor an `else`, the only two values any of the
 * drop helpers test for, so the narrowing is behaviour-preserving). */
function modelDropRows(vms: RowViewModel[], handler: string): BlockCaptureRow[] {
  const ctx = modelCtxRows(vms);
  return vms.map((vm, i) => ({
    handler,
    lineStart: ctx[i].lineStart,
    lineEnd: ctx[i].lineEnd,
    nesting: ctx[i].nesting,
    suite: ctx[i].suite,
    kind: ctx[i].kind as RowKind,
    draggable: ctx[i].draggable,
    isControlHeader: ctx[i].isControlHeader,
    control: vm.control as RowDropContext["control"],
    appended: vm.appended,
    scaffold: vm.scaffold,
    expectSrc: ctx[i].expectSrc,
  }));
}

/** The webview's `resolveDrop` returns a DOM ELEMENT as its anchor; the model returns line numbers. The
 * single adapter line is the `dataset` read below — nothing else is reshaped. */
function normalizeWebviewDrop(res: DomNode | null): DropResolution | null {
  if (!res) {
    return null;
  }
  return {
    anchorLineStart: Number(res.anchorEl.dataset.lineStart),
    anchorLineEnd: Number(res.anchorEl.dataset.lineEnd),
    toPosition: res.position,
    toSuite: res.toSuite,
    landingDepth: res.landingDepth,
  };
}

/** Same one-line-adapter rule for `barAnchor` (element → its line start). */
function normalizeWebviewBar(a: DomNode): { anchorLineStart: number; edge: string } {
  return { anchorLineStart: Number(a.el.dataset.lineStart), edge: a.edge };
}

/** One loaded corpus case: both sides, plus the view models the model side comes from. */
interface Loaded {
  name: string;
  harness: Harness;
  vms: RowViewModel[];
  handlerName: string;
  webviewRows: CtxRow[];
  modelRows: BlockCaptureRow[];
  /** `{lineStart, title}` for EVERY row — the webview's `scopeLabel` searches all rows, not just the
   * control headers, so the model side is given the same population. */
  titles: { lineStart: number; title: string }[];
}

function loadCase(c: CorpusCase, opts: LoadOptions = {}): Loaded {
  const handlers = buildHandlerViewModels(c.parse, c.source);
  const harness = loadWebview(renderHandlersHtml(handlers), opts);
  const vms = handlers.flatMap((h) => h.rows);
  return {
    name: c.name,
    harness,
    vms,
    handlerName: handlers[0].handler,
    webviewRows: plain(harness.hook.stepsCtxRows()) as CtxRow[],
    modelRows: modelDropRows(vms, handlers[0].handler),
    titles: vms.map((vm) => ({ lineStart: vm.lineStart, title: vm.title })),
  };
}

/** Rows the webview will actually START a drag from: `draggable`, and not a `code` row (a code row's
 * `dragstart` is INTERCEPTED at stepsWebview.js:469-473 and never sets `dragSrc`). The model's
 * `canDropRow` is a pure (drag, target) predicate with no notion of an event-layer source gate, so the
 * pair sweep is scoped to sources the webview can actually drag; the code-row SOURCE half of the
 * contract is asserted separately in T11. */
function dragStartableIndexes(rows: CtxRow[]): number[] {
  const out: number[] = [];
  rows.forEach((r, i) => {
    if (r.draggable && r.kind !== "code") {
      out.push(i);
    }
  });
  return out;
}

/** Set the webview's `dragSrc` by dispatching a REAL `dragstart` (no test-only mutator exists, on
 * purpose — this drives the same listener production uses). Returns the event so a caller can inspect
 * `defaultPrevented`. */
function beginDrag(h: Harness, el: DomNode): DomNode {
  const ev = new h.window.Event("dragstart", { bubbles: true, cancelable: true }) as DomNode;
  el.dispatchEvent(ev);
  return ev;
}

function endDrag(h: Harness, el: DomNode): void {
  el.dispatchEvent(new h.window.Event("dragend", { bubbles: true, cancelable: true }));
}

// ---- T1: row-context parity ------------------------------------------------------------------------

suite("Steps mirror — row context parity (stepsCtxRows vs the view models)", () => {
  for (const c of CORPUS) {
    test(`${c.name}: every row survives renderRowHtml → dataset → stepsCtxRows unchanged`, () => {
      const L = loadCase(c);
      assert.strictEqual(
        L.webviewRows.length,
        L.modelRows.length,
        `${c.name}: the DOM and the view models disagree on the ROW COUNT`,
      );
      const expected = modelCtxRows(L.vms);
      for (let i = 0; i < expected.length; i++) {
        assert.deepStrictEqual(
          L.webviewRows[i],
          expected[i],
          `${c.name}: row ${i} (line ${expected[i].lineStart}) diverges between the rendered DOM and the model`,
        );
      }
    });
  }
});

// ---- T2: canDrop / canDropRow parity, including the code-row target --------------------------------

suite("Steps mirror — canDrop parity (webview canDrop vs model canDropRow)", () => {
  for (const c of CORPUS) {
    test(`${c.name}: every ordered (drag, target) pair agrees`, () => {
      const L = loadCase(c);
      for (const di of dragStartableIndexes(L.webviewRows)) {
        beginDrag(L.harness, L.harness.rowEls[di]);
        for (let ti = 0; ti < L.webviewRows.length; ti++) {
          const web = L.harness.hook.canDrop(L.harness.rowEls[ti]) as boolean;
          const mdl = canDropRow(L.modelRows[di], L.modelRows[ti]);
          assert.strictEqual(
            web,
            mdl,
            `${c.name}: canDrop disagreed — drag line ${L.webviewRows[di].lineStart} ` +
              `(${L.webviewRows[di].kind}) onto line ${L.webviewRows[ti].lineStart} ` +
              `(${L.webviewRows[ti].kind}): webview=${web} model=${mdl}`,
          );
        }
        endDrag(L.harness, L.harness.rowEls[di]);
      }
    });

    test(`${c.name}: a CODE row is never a drop target on either side`, () => {
      const L = loadCase(c);
      const codeTargets = L.webviewRows
        .map((r, i) => (r.kind === "code" ? i : -1))
        .filter((i) => i >= 0);
      if (codeTargets.length === 0) {
        return; // this case carries no code rows
      }
      for (const di of dragStartableIndexes(L.webviewRows)) {
        beginDrag(L.harness, L.harness.rowEls[di]);
        for (const ti of codeTargets) {
          assert.strictEqual(
            L.harness.hook.canDrop(L.harness.rowEls[ti]),
            false,
            `${c.name}: the webview must refuse a code-row drop target (line ${L.webviewRows[ti].lineStart})`,
          );
          assert.strictEqual(
            canDropRow(L.modelRows[di], L.modelRows[ti]),
            false,
            `${c.name}: the MODEL must also refuse a code-row drop target (line ` +
              `${L.webviewRows[ti].lineStart}) — its own contract in renderRowHtml says it ` +
              `"never treats a code row as a drop target"`,
          );
        }
        endDrag(L.harness, L.harness.rowEls[di]);
      }
    });
  }

  test("two handlers: a cross-handler drop is refused on both sides", () => {
    const c = caseTwoHandlers();
    const handlers = buildHandlerViewModels(c.parse, c.source);
    const harness = loadWebview(renderHandlersHtml(handlers), {});
    const web = harness.hook.stepsCtxRows() as CtxRow[];
    // Model contexts carry the handler each row actually belongs to (the DOM carries it as data-handler).
    const model: BlockCaptureRow[] = handlers.flatMap((h) => modelDropRows(h.rows, h.handler));
    assert.strictEqual(web.length, model.length);
    const firstIdx = 0; // handler "first"
    const secondIdx = handlers[0].rows.length; // first row of handler "second"
    beginDrag(harness, harness.rowEls[firstIdx]);
    assert.strictEqual(
      harness.hook.canDrop(harness.rowEls[secondIdx]),
      false,
      "the webview refuses a drop into a DIFFERENT handler",
    );
    assert.strictEqual(
      canDropRow(model[firstIdx], model[secondIdx]),
      false,
      "the model refuses a drop into a DIFFERENT handler",
    );
    endDrag(harness, harness.rowEls[firstIdx]);
  });
});

// ---- T3: blockExtent / captureBlock / clipLabel-vs-blockLabel ---------------------------------------

suite("Steps mirror — blockExtent / captureBlock / clipLabel parity", () => {
  for (const c of CORPUS) {
    test(`${c.name}: blockExtent agrees for every row (and for an absent line)`, () => {
      const L = loadCase(c);
      for (const r of L.webviewRows) {
        assert.deepStrictEqual(
          plain(L.harness.hook.blockExtent(L.webviewRows, r.lineStart)),
          blockExtent(L.modelRows, r.lineStart),
          `${c.name}: blockExtent diverged at block-start line ${r.lineStart} (${r.kind})`,
        );
      }
      assert.deepStrictEqual(
        plain(L.harness.hook.blockExtent(L.webviewRows, 9999)),
        blockExtent(L.modelRows, 9999),
        `${c.name}: blockExtent diverged for a line that is not a row`,
      );
    });

    test(`${c.name}: captureBlock + clipLabel/blockLabel agree for every row`, () => {
      const L = loadCase(c);
      for (const r of L.webviewRows) {
        const web = L.harness.hook.captureBlock(L.webviewRows, r.lineStart) as DomNode | null;
        const mdl = captureBlock(L.modelRows, r.lineStart);
        // The webview's capture carries ONE extra key, `control`, because its `clipLabel` mirror takes
        // the whole capture object while the model's `blockLabel` takes the keyword as a separate
        // argument (a deliberate signature difference, not drift). Compare the six shared keys, then
        // assert the extra key separately rather than silently dropping it.
        const webShared =
          web === null
            ? null
            : {
                source: web.source,
                nesting: web.nesting,
                kind: web.kind,
                lineStart: web.lineStart,
                lineEnd: web.lineEnd,
                lineCount: web.lineCount,
              };
        assert.deepStrictEqual(
          webShared,
          mdl,
          `${c.name}: captureBlock diverged at line ${r.lineStart} (${r.kind})`,
        );
        if (mdl && web) {
          const control = L.modelRows.find((m) => m.lineStart === r.lineStart)?.control;
          assert.strictEqual(
            web.control,
            control,
            `${c.name}: the capture's control keyword diverged at line ${r.lineStart}`,
          );
          assert.strictEqual(
            L.harness.hook.clipLabel(web),
            blockLabel(mdl.kind, mdl.lineCount, control),
            `${c.name}: the clipboard label diverged at line ${r.lineStart}`,
          );
        }
      }
    });
  }
});

// ---- T4: buildDropSlots / walkMove ------------------------------------------------------------------

suite("Steps mirror — buildDropSlots / walkMove parity", () => {
  for (const c of CORPUS) {
    test(`${c.name}: buildDropSlots enumerates the same slots, in the same order`, () => {
      const L = loadCase(c);
      assert.deepStrictEqual(
        plain(L.harness.hook.buildDropSlots(L.webviewRows)),
        buildDropSlots(L.modelRows),
        `${c.name}: the insertion-slot enumeration diverged`,
      );
      // …and again with each block removed, which is the shape walkMove actually feeds it.
      for (const r of L.webviewRows) {
        const ext = blockExtent(L.modelRows, r.lineStart);
        if (!ext) {
          continue;
        }
        const keep = (_v: unknown, i: number): boolean => i < ext.startIndex || i > ext.endIndex;
        assert.deepStrictEqual(
          plain(L.harness.hook.buildDropSlots(L.webviewRows.filter(keep))),
          buildDropSlots(L.modelRows.filter(keep)),
          `${c.name}: the slot enumeration diverged with the block at line ${r.lineStart} removed`,
        );
      }
    });

    test(`${c.name}: walkMove agrees up AND down for every row`, () => {
      const L = loadCase(c);
      for (const r of L.webviewRows) {
        for (const dir of ["up", "down"] as const) {
          assert.deepStrictEqual(
            plain(L.harness.hook.walkMove(L.webviewRows, r.lineStart, dir)),
            walkMove(L.modelRows, r.lineStart, dir),
            `${c.name}: walkMove('${dir}') diverged at line ${r.lineStart} (${r.kind})`,
          );
        }
      }
    });
  }
});

// ---- T4b: the generated row-set sweep (STEPS-07/08, ≥2,000 sets) ------------------------------------

suite("Steps mirror — generated row sets (STEPS-07/08)", () => {
  test(`the row-array mirrors agree over ${GENERATED_SETS} generated row sets`, function (this: Mocha.Context) {
    this.timeout(120_000);
    // ONE page load for the whole sweep: these five mirrors never touch the DOM, so re-rendering a
    // document per set would buy nothing and cost ~30 ms each. The render → DOM → read-back boundary is
    // pinned separately, over the hand-authored corpus, by T1.
    const hook = loadCase(caseFlat()).harness.hook;
    let comparisons = 0;
    let nonNullExtents = 0;
    let nonNullWalks = 0;
    let slots = 0;

    for (let i = 0; i < GENERATED_SETS; i++) {
      const g = generateRowSet(GENERATOR_SEED + i);
      const where = (what: string, line: number): string =>
        `${what} diverged (generated set ${i}, line ${line}).\n` +
        `  reproduce: generateRowSet(${g.seed})\n` +
        `  row set: ${JSON.stringify(g.web)}`;

      const webSlots = plain(hook.buildDropSlots(g.web)) as DropResolution[];
      assert.deepStrictEqual(webSlots, buildDropSlots(g.model), where("buildDropSlots", 0));
      slots += webSlots.length;
      comparisons += 1;

      for (const r of g.web) {
        const ext = plain(hook.blockExtent(g.web, r.lineStart));
        assert.deepStrictEqual(ext, blockExtent(g.model, r.lineStart), where("blockExtent", r.lineStart));
        if (ext) {
          nonNullExtents += 1;
        }

        const webCap = hook.captureBlock(g.web, r.lineStart) as DomNode | null;
        const mdlCap = captureBlock(g.model, r.lineStart);
        // Same six-shared-keys comparison T3 makes: the webview's capture carries an extra `control`
        // because its `clipLabel` takes the whole capture while `blockLabel` takes the keyword apart.
        assert.deepStrictEqual(
          webCap === null
            ? null
            : {
                source: webCap.source,
                nesting: webCap.nesting,
                kind: webCap.kind,
                lineStart: webCap.lineStart,
                lineEnd: webCap.lineEnd,
                lineCount: webCap.lineCount,
              },
          mdlCap,
          where("captureBlock", r.lineStart),
        );
        if (mdlCap && webCap) {
          const control = g.model.find((m) => m.lineStart === r.lineStart)?.control;
          assert.strictEqual(webCap.control, control, where("captureBlock.control", r.lineStart));
          assert.strictEqual(
            hook.clipLabel(webCap),
            blockLabel(mdlCap.kind, mdlCap.lineCount, control),
            where("clipLabel/blockLabel", r.lineStart),
          );
        }

        for (const dir of ["up", "down"] as const) {
          const walk = plain(hook.walkMove(g.web, r.lineStart, dir));
          assert.deepStrictEqual(walk, walkMove(g.model, r.lineStart, dir), where(`walkMove('${dir}')`, r.lineStart));
          if (walk) {
            nonNullWalks += 1;
          }
        }
        comparisons += 4;
      }
    }

    // A sweep that compared only nulls would pass for the wrong reason. Report the volume AND prove the
    // interesting branches were actually reached, the way the plan's "print what you scanned" rule asks.
    assert.ok(comparisons > 10_000, `the generated sweep made only ${comparisons} comparisons`);
    assert.ok(nonNullExtents > 1_000, `only ${nonNullExtents} generated rows had a block extent at all`);
    assert.ok(nonNullWalks > 1_000, `only ${nonNullWalks} generated walks resolved to a move`);
    assert.ok(slots > 5_000, `the generated sets enumerated only ${slots} drop slots in total`);
  });
});

// ---- T5/T6/T7: resolveDrop tri-zone, barAnchor, scopeLabel ------------------------------------------

// Pointer fractions swept over every (drag, target) pair. 0.1 / 0.5 / 0.9 alone are NOT enough: they
// sit either side of BOTH tri-zone thresholds, so moving `frac < 1/3` to `frac < 1/2` changes no
// outcome among them (0.5 is not `< 0.5`) and a real threshold drift would slip through. 0.4 and 0.6
// straddle the 1/3 and 2/3 boundaries and are what actually pins them — verified by falsification.
// With ROW_H = 20 every one of these lands on an exact pixel, so the fraction arithmetic is exact.
const FRACTIONS = [0.1, 0.4, 0.5, 0.6, 0.9];

suite("Steps mirror — resolveDrop / barAnchor / scopeLabel parity", () => {
  for (const c of CORPUS) {
    test(`${c.name}: resolveDrop + barAnchor + scopeLabel agree over all ordered pairs × ${JSON.stringify(FRACTIONS)}`, () => {
      const L = loadCase(c);
      let compared = 0;
      let nonNull = 0;
      for (const di of dragStartableIndexes(L.webviewRows)) {
        beginDrag(L.harness, L.harness.rowEls[di]);
        for (let ti = 0; ti < L.webviewRows.length; ti++) {
          for (const f of FRACTIONS) {
            const ev = { clientY: clientYFor(ti, f), clientX: 0 };
            const web = normalizeWebviewDrop(
              L.harness.hook.resolveDrop(L.harness.rowEls[ti], ev) as DomNode | null,
            );
            const mdl = resolveDrop(L.modelRows[di], L.modelRows[ti], f, L.modelRows);
            compared += 1;
            const where =
              `${c.name}: drag line ${L.webviewRows[di].lineStart} onto line ` +
              `${L.webviewRows[ti].lineStart} (${L.webviewRows[ti].kind}) at fraction ${f}`;
            assert.deepStrictEqual(web, mdl, `${where}: resolveDrop diverged`);
            if (!mdl) {
              continue;
            }
            nonNull += 1;
            assert.deepStrictEqual(
              normalizeWebviewBar(
                L.harness.hook.barAnchor(L.harness.hook.resolveDrop(L.harness.rowEls[ti], ev)),
              ),
              insertionBarAnchor(mdl, L.modelRows),
              `${where}: barAnchor diverged`,
            );
            assert.strictEqual(
              L.harness.hook.scopeLabel(mdl.landingDepth, mdl.toSuite),
              scopeLabel(mdl.landingDepth, mdl.toSuite, L.titles),
              `${where}: scopeLabel diverged`,
            );
          }
        }
        endDrag(L.harness, L.harness.rowEls[di]);
      }
      assert.ok(compared > 0, `${c.name}: the pair sweep compared nothing`);
      assert.ok(nonNull > 0, `${c.name}: every resolveDrop was null — the sweep proved nothing`);
    });

    test(`${c.name}: the three ZONES are DISCRIMINATING (the tri-zone is not collapsed)`, () => {
      // Guards the harness itself: jsdom returns all-zero rects, and the webview's `resolveDrop` falls
      // back to a constant 0.5 when height <= 0. Without stubRowRects() every fraction would resolve
      // identically and every tri-zone assertion above would be vacuous. Assert that the five swept
      // fractions really do land in the control header's three DISTINCT zones (before / into / after).
      const L = loadCase(c);
      const headerIdx = L.webviewRows.findIndex((r) => r.isControlHeader);
      if (headerIdx < 0) {
        return; // this case has no control header
      }
      const di = dragStartableIndexes(L.webviewRows).find((i) => {
        const drag = L.modelRows[i];
        const tgt = L.modelRows[headerIdx];
        return resolveDrop(drag, tgt, 0.1, L.modelRows) !== null;
      });
      if (di === undefined) {
        throw new Error(`${c.name}: no legal drag onto the first control header`);
      }
      beginDrag(L.harness, L.harness.rowEls[di]);
      const seen = FRACTIONS.map((f) =>
        JSON.stringify(
          normalizeWebviewDrop(
            L.harness.hook.resolveDrop(L.harness.rowEls[headerIdx], {
              clientY: clientYFor(headerIdx, f),
              clientX: 0,
            }) as DomNode | null,
          ),
        ),
      );
      endDrag(L.harness, L.harness.rowEls[di]);
      // …and prove the STUB is what makes them discriminate: without it jsdom's all-zero rects send
      // the webview's `resolveDrop` down its `height <= 0` fallback and every fraction collapses to one
      // resolution. This is T5's harness falsification kept in the tree, so nobody can quietly delete
      // stubRowRects() and leave the tri-zone assertions passing vacuously.
      const bare = loadCase(c, { skipRectStub: true });
      const bareHeaderIdx = bare.webviewRows.findIndex((r) => r.isControlHeader);
      beginDrag(bare.harness, bare.harness.rowEls[di]);
      const bareSeen = FRACTIONS.map((f) =>
        JSON.stringify(
          normalizeWebviewDrop(
            bare.harness.hook.resolveDrop(bare.harness.rowEls[bareHeaderIdx], {
              clientY: clientYFor(bareHeaderIdx, f),
              clientX: 0,
            }) as DomNode | null,
          ),
        ),
      );
      endDrag(bare.harness, bare.harness.rowEls[di]);
      assert.strictEqual(
        new Set(bareSeen).size,
        1,
        `${c.name}: with no rect stub the fractions were expected to COLLAPSE to one resolution; they ` +
          `did not, so this test is no longer proving that the stub is what makes them discriminate`,
      );
      assert.strictEqual(
        new Set(seen).size,
        3,
        `${c.name}: the control-header tri-zone collapsed — every fraction resolved to ${seen[0]}. ` +
          `The per-row getBoundingClientRect stub is missing or wrong, so the fraction assertions are vacuous.`,
      );
    });
  }

  test("escaping: a title carrying & < > \" ' produces the SAME scope label on both sides", () => {
    const c = caseEscaping();
    const L = loadCase(c);
    const headers = L.vms.filter((vm) => vm.kind === "control");
    assert.ok(headers.length >= 2, "the escaping case must carry control headers");
    for (const h of headers) {
      assert.ok(
        /[&<>"']/.test(h.title),
        `the escaping corpus must actually carry markup characters (got ${JSON.stringify(h.title)})`,
      );
      const suiteId = String(h.lineStart);
      assert.strictEqual(
        L.harness.hook.scopeLabel(1, suiteId),
        scopeLabel(1, suiteId, L.titles),
        `scopeLabel diverged across the HTML-escaping boundary for title ${JSON.stringify(h.title)}`,
      );
      assert.strictEqual(
        L.harness.hook.scopeLabel(1, suiteId),
        `inside ${h.title}`,
        "the webview reads .textContent off escaped markup — it must recover the RAW title",
      );
    }
  });
});

// ---- T8/T9/T10/T11: the script itself ---------------------------------------------------------------

suite("Steps mirror — the webview script under jsdom (STEPS-06)", () => {
  test("loads to completion: one 'alive' ping, no error diagnostics, no uncaught throw", () => {
    const c = caseDeepNesting();
    const handlers = buildHandlerViewModels(c.parse, c.source);
    const h = loadWebview(renderHandlersHtml(handlers));
    assert.deepStrictEqual(
      h.scriptErrors.map((e) => String(e)),
      [],
      "the script threw while loading under jsdom",
    );
    const pings = plain(h.posted.filter((m) => m.command === "stepsDiag" && m.level === "ping"));
    assert.deepStrictEqual(
      pings,
      [{ command: "stepsDiag", level: "ping", text: "alive" }],
      "exactly one provider handshake ping",
    );
    assert.deepStrictEqual(
      plain(h.posted.filter((m) => m.command === "stepsDiag" && m.level === "error")),
      [],
      "no stepsDiag error — the arrow-greying and context-menu wiring both completed",
    );
    assert.strictEqual(h.acquireCount, 1, "acquireVsCodeApi is called exactly once per page");
    // NOTE: STEPS-06's second clause ("a second load against the RETAINED window does not re-acquire")
    // is deliberately NOT asserted here. VS Code's retain-context reload gives the script a fresh
    // realm-with-retained-window that a single jsdom document cannot reproduce — re-running a classic
    // script in the SAME global would fail on its own top-level `const`, which would test the harness,
    // not the product. That clause stays manual (STEPS-76).
  });

  test("element inventory: every id the script reads UNGUARDED exists in the page shell", () => {
    // Without this, the "loads to completion" test above only proves the shell matches TODAY's script.
    const src = fs.readFileSync(WEBVIEW_JS, "utf8");
    const ids = new Set<string>();
    const re = /document\.getElementById\(\s*(['"])([^'"]+)\1\s*\)/g;
    let m: RegExpExecArray | null = re.exec(src);
    while (m) {
      ids.add(m[2]);
      m = re.exec(src);
    }
    assert.ok(ids.size >= 5, `expected at least 5 getElementById ids, found ${ids.size}`);
    const c = caseFlat();
    const handlers = buildHandlerViewModels(c.parse, c.source);
    const h = loadWebview(renderHandlersHtml(handlers));
    for (const id of ids) {
      assert.ok(
        h.window.document.getElementById(id),
        `stepsWebview.js reads #${id}, but the jsdom page shell does not provide it — either add it to ` +
          `pageShell() or confirm stepsView.ts's real shell still renders it`,
      );
    }
  });

  test("the export hook is INERT unless the loader opts in", () => {
    // Honest scope: stepsWebview.js is a CLASSIC script, so its top-level `function` declarations are
    // ALREADY globals on the page — this gate does not newly hide behaviour that was previously
    // exposed. What it does is keep the shipped webview free of a NAMED, greppable test contract that a
    // future reader could mistake for a supported API, and make the test surface opt-in.
    const c = caseFlat();
    const handlers = buildHandlerViewModels(c.parse, c.source);
    const h = loadWebview(renderHandlersHtml(handlers), { exposeHook: false });
    assert.strictEqual(
      h.window.__mfStepsTestExports,
      undefined,
      "__mfStepsTestExports must be absent when __mfStepsTestExportsEnabled was never set",
    );
    assert.deepStrictEqual(h.scriptErrors.map((e) => String(e)), [], "the gate must not break the load");
  });

  test("a CODE row's dragstart is intercepted: codeLocked, preventDefault, and no drop target follows", () => {
    // The other half of the contract `renderRowHtml` declares: a code row is marked draggable
    // ONLY so the attempt can be answered with "edit it in the code editor".
    const c = caseDeepNesting();
    const L = loadCase(c);
    const codeIdx = L.webviewRows.findIndex((r) => r.kind === "code");
    assert.ok(codeIdx >= 0, "the corpus must carry a code row");
    assert.strictEqual(L.webviewRows[codeIdx].draggable, true, "a code row IS marked draggable");
    const before = L.harness.posted.length;
    const ev = beginDrag(L.harness, L.harness.rowEls[codeIdx]);
    assert.strictEqual(ev.defaultPrevented, true, "the code-row drag is cancelled");
    assert.deepStrictEqual(
      plain(L.harness.posted.slice(before)),
      [{ command: "codeLocked" }],
      "the interception tells the provider to point at the code editor",
    );
    for (let ti = 0; ti < L.webviewRows.length; ti++) {
      assert.strictEqual(
        L.harness.hook.canDrop(L.harness.rowEls[ti]),
        false,
        `no drop target may follow an intercepted code-row drag (line ${L.webviewRows[ti].lineStart})`,
      );
    }
  });
});

// ---- Amendment D: the Add-palette's role scope, mirrored -------------------------------------------

suite("Steps mirror — inRole parity (webview inRole vs model itemAllowedInRole)", () => {
  test("every catalog item agrees, in both roles, and an absent scope means handler-only", () => {
    const L = loadCase(CORPUS[0]);
    for (const item of ADD_MENU_CATALOG) {
      // The webview reads the attribute the server rendered; the model reads the catalog entry itself.
      const el = { dataset: { roleScope: roleScopeAttr(item) } };
      for (const role of ["handler", "router"] as const) {
        assert.strictEqual(
          L.harness.hook.inRole(el, role),
          itemAllowedInRole(item, role),
          `role scope diverged for "${item.id}" in a ${role}`,
        );
      }
    }
    // An item rendered by an OLDER provider carries no data-role-scope; both sides must read that as
    // handler-only, so a stale render can never smuggle a transform verb into a router.
    assert.strictEqual(L.harness.hook.inRole({ dataset: {} }, "handler"), true);
    assert.strictEqual(L.harness.hook.inRole({ dataset: {} }, "router"), false);
    // No selected option at all (the placeholder) is not a role problem — the Add button has its own gate.
    assert.strictEqual(L.harness.hook.inRole(null, "router"), true);
  });

  test("the router palette offers routing constructs ONLY (AC-R5)", () => {
    const router = paletteFor("router").map((i) => i.id);
    assert.deepStrictEqual(
      router.sort(),
      ["comment", "elif", "else", "for_each", "if", "raise", "route"].sort(),
      "a Router may author guards, loops, a raise, a comment and a routing return — nothing else",
    );
    // Not one transform verb, lookup, diagnostic or outbound send survives the filter.
    for (const id of ["set_field", "copy_field", "db_lookup", "code_lookup", "log_note", "send"]) {
      assert.ok(!router.includes(id), `"${id}" must not be offered inside a @router`);
    }
    // ...and the handler palette is unchanged apart from not offering the router's own item.
    const handler = paletteFor("handler").map((i) => i.id);
    assert.ok(!handler.includes("route"), "a Handler does not select handlers");
    assert.strictEqual(handler.length, ADD_MENU_CATALOG.length - 1);
  });
});

// ---- T12: mirror inventory guard --------------------------------------------------------------------

/** Every top-level `function <name>(` in stepsWebview.js that is a MIRROR of a stepsModel function and
 * therefore has a parity assertion above. */
const MIRRORED = new Set([
  "stepsCtxRows",
  "blockExtent",
  "captureBlock",
  "buildDropSlots",
  "walkMove",
  "clipLabel",
  "canDrop",
  "scopeLabel",
  "resolveDrop",
  "barAnchor",
  "inRole",
]);

/** Top-level functions that are NOT mirrors — DOM/wiring helpers with no pure model counterpart. Each
 * entry carries the reason it is exempt. Adding an 11th mirror without a parity test must fail. */
const NOT_A_MIRROR: Record<string, string> = {
  selectRow: "DOM: applies the .selected class and records the toolbar's insert anchor",
  updateAddState: "DOM: greys the toolbar Add button from the <select> + selection",
  getClipboard: "storage: reads the webview's vscode.getState() clipboard slot",
  setClipboard: "storage: writes the webview's vscode.setState() clipboard slot",
  selectedIsMovable: "DOM: reads draggable/kind off the currently selected <li>",
  copySelected: "wiring: captureBlock + setClipboard + a toast postMessage",
  cutSelected: "wiring: copySelected then a deleteRow postMessage",
  pasteSelected: "wiring: a paste postMessage from the clipboard slot",
  ensureIndicators: "DOM: creates the insertion bar + scope pill elements",
  clearIndicators: "DOM: removes the insertion bar + scope pill and the scope tint",
  rowByLineStart: "DOM: finds an <li> by data-line-start",
  showIndicators: "DOM: positions the bar/pill from getBoundingClientRect (layout, not logic)",
  menuInsert: "wiring: posts the same insertItem message the toolbar Add posts",
  menuDelete: "wiring: posts the same deleteRow message the row button posts",
  menuMove: "wiring: walkMove + the same moveTo message the row arrows post",
  menuAddDestination: "wiring: posts the same addDestination message the row button posts",
};

suite("Steps mirror — inventory guard (STEPS-12)", () => {
  test("every top-level webview function is either mirrored-and-tested or explicitly not a mirror", () => {
    const src = fs.readFileSync(WEBVIEW_JS, "utf8");
    // The file's body is indented four spaces; nested helpers (inside the two IIFEs) are indented more,
    // and the IIFEs themselves start with `(function`. So exactly-four-space `function` == top level.
    const re = /^ {4}function ([A-Za-z0-9_$]+)\s*\(/gm;
    const found: string[] = [];
    let m: RegExpExecArray | null = re.exec(src);
    while (m) {
      found.push(m[1]);
      m = re.exec(src);
    }
    assert.ok(found.length >= 20, `expected the full top-level function list, found ${found.length}`);
    const unaccounted = found.filter((n) => !MIRRORED.has(n) && NOT_A_MIRROR[n] === undefined);
    assert.deepStrictEqual(
      unaccounted,
      [],
      `new top-level function(s) in media/stepsWebview.js with no parity test and no "not a mirror" ` +
        `allowlist entry: ${unaccounted.join(", ")}. Add a parity assertion in this file, or an entry ` +
        `in NOT_A_MIRROR with a one-line reason.`,
    );
    for (const name of MIRRORED) {
      assert.ok(found.includes(name), `mirrored ${name}() vanished from media/stepsWebview.js`);
    }
    // Stale allowlist entries are a slower rot, but still rot.
    for (const name of Object.keys(NOT_A_MIRROR)) {
      assert.ok(found.includes(name), `NOT_A_MIRROR names ${name}(), which no longer exists`);
    }
  });
});

// ---- T13: context-menu enablement parity (STEPS-10) -------------------------------------------------

interface MenuState {
  insertBefore: boolean;
  insertAfter: boolean;
  deleteRow: boolean;
  moveUp: boolean;
  moveDown: boolean;
  addDestination: boolean;
}

/** Right-click a row and read the REAL server-rendered menu's enabled/disabled state back off the DOM. */
function openMenuFor(h: Harness, el: DomNode): MenuState {
  const ev = new h.window.MouseEvent("contextmenu", {
    bubbles: true,
    cancelable: true,
    clientX: 4,
    clientY: 4,
  });
  el.dispatchEvent(ev);
  const menu = h.window.document.getElementById("stepsCtxMenu");
  assert.ok(menu, "the server-rendered context menu template is in the page");
  const enabled = (sel: string): boolean => {
    const node = menu.querySelector(sel);
    assert.ok(node, `the context menu has no ${sel}`);
    return node.disabled !== true;
  };
  return {
    insertBefore: enabled('.ctx-parent[data-sub="before"]'),
    insertAfter: enabled('.ctx-parent[data-sub="after"]'),
    deleteRow: enabled('.ctx-item[data-cmd="deleteRow"]'),
    moveUp: enabled('.ctx-item[data-cmd="moveUp"]'),
    moveDown: enabled('.ctx-item[data-cmd="moveDown"]'),
    addDestination: enabled('.ctx-item[data-cmd="addDestination"]'),
  };
}

suite("Steps mirror — context-menu enablement parity (STEPS-10)", () => {
  for (const c of CORPUS) {
    test(`${c.name}: the webview's greying equals contextMenuEnablement for every row`, () => {
      const L = loadCase(c);
      for (let i = 0; i < L.vms.length; i++) {
        const vm = L.vms[i];
        // The webview gates ↑/↓ on isRowMovable AND the walk (stepsWebview.js:699-703); the model takes
        // the walk result as an INPUT, so the model side composes the same two facts from its own data.
        const movable = vm.movable === true;
        const expected = contextMenuEnablement(
          { kind: vm.kind, appended: vm.appended, scaffold: vm.scaffold, filtered: vm.filtered },
          {
            canMoveUp: movable && walkMove(L.modelRows, vm.lineStart, "up") !== null,
            canMoveDown: movable && walkMove(L.modelRows, vm.lineStart, "down") !== null,
          },
        );
        assert.deepStrictEqual(
          openMenuFor(L.harness, L.harness.rowEls[i]),
          expected,
          `${c.name}: context-menu enablement diverged on row ${i} (line ${vm.lineStart}, ${vm.kind})`,
        );
      }
    });
  }
});

// ---- #234: the provider never releases the edit slot outside releaseEdit ---------------------------

suite("Steps update-loop guard — every release site goes through releaseEdit (#234)", () => {
  test("ide/src/stepsView.ts contains no bare guard.endEdit() call", () => {
    // A FOURTH release site added later would silently reintroduce the dropped-save defect: endEdit()
    // frees the slot without draining the refresh a save owed while the slot was held. releaseEdit is
    // the only sanctioned release.
    const src = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    const offenders = src
      .split(/\r?\n/)
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => /\bguard\s*\.\s*endEdit\s*\(/.test(line));
    assert.deepStrictEqual(
      offenders.map(({ n, line }) => `${n}: ${line.trim()}`),
      [],
      "every edit-slot release in stepsView.ts must go through releaseEdit(guard, scheduleRerender) so " +
        "a save suppressed by the guard is DEFERRED, not dropped",
    );
    assert.ok(
      /releaseEdit\(/.test(src),
      "stepsView.ts must actually call releaseEdit — a file with neither call would pass vacuously",
    );
  });

  test("render() cancels the debounce on entry, so a forced re-projection is not doubled (AC-C2)", () => {
    // The composed behaviour is unit-tested in steps-edit.test.ts against RerenderDebouncer + a fake
    // clock; what no node-side test can reach is the PROVIDER's wiring, because stepsView.ts imports
    // vscode. This scan pins the one line that connects them: three release sites arm the debounce and
    // then force `await render()` a few lines later, so a render that does not cancel first replaces
    // the whole webview HTML a second time 250 ms afterwards.
    const src = fs.readFileSync(STEPS_VIEW_TS, "utf8");
    const start = src.indexOf("const render = async (): Promise<void> => {");
    assert.ok(start >= 0, "stepsView.ts no longer declares `const render = async (): Promise<void> =>`");
    const end = src.indexOf("\n    };", start);
    assert.ok(end > start, "could not find the end of the render() body (4-space `};`)");
    const body = src.slice(start, end);
    assert.ok(
      /rerender\.cancel\(\)/.test(body),
      "render() must cancel the armed re-projection debounce on entry (ADR 0076 Amendment C, AC-C2) — " +
        "otherwise a save suppressed while the edit slot was held is re-projected TWICE: once by the " +
        "forced render and again when the deferred timer fires",
    );
    assert.ok(
      /guard\.takeSuppressedChange\(\)/.test(body),
      "render() must also take the guard's owed-refresh debt (AC-C2) — that covers the one path where " +
        "the render happens BEFORE the release rather than after it (drainEdits' rejection handler), " +
        "which the debounce cancel alone cannot reach",
    );
    // …and it must be the FIRST statement, before the `lens parse` await — a cancel after the await
    // would swallow a save that legitimately arrived mid-render.
    const firstStatement = body
      .split(/\r?\n/)
      .slice(1) // [0] is the `const render = …` declaration line itself
      .find((l) => l.trim() !== "" && !l.trim().startsWith("//"));
    assert.ok(
      firstStatement !== undefined && /rerender\.cancel\(\);/.test(firstStatement),
      `render()'s first statement must be rerender.cancel(); got: ${JSON.stringify(firstStatement)}`,
    );
  });
});
