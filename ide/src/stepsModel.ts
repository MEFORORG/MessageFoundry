// Pure (vscode-free) view-model behind the read-only Steps view (ADR 0076 §2 phase 2b / #222).
//
// It consumes the `messagefoundry lens parse --json` contract (ADR 0076 §3) — the engine owns the
// grammar, this file NEVER parses Python — and folds it, together with the module source text, into an
// ordered, nested row view-model that the webview renders (a Corepoint-style typed Steps VIEW).
// Separated from stepsView.ts so the mapping is unit-testable node-side with the committed fixtures
// (no Extension Host): kind→row-type, params display, the in-place `code`-row passthrough (the §4
// degradation ladder — an unrecognized line is never hidden), the coverage/order invariant (every row
// rendered, in order), the parse-error→fallback decision, and the redacted-by-default live-value merge.
// No vscode, no I/O.
//
// Live-value acquisition (ADR 0076 addendum, 2026-07-10): the trace event/invocation shapes below are
// imported as TYPES ONLY from liveDebug (erased at compile time — no runtime dependency, so this module
// stays vscode-free and node-testable). The values come from a SECOND `dryrun --trace json` the provider
// shells (ADR 0072), never from reaching into LiveDebugController's private trace state.
import type { TraceInvocation, TraceValue } from "./liveDebug";

// ---- the `lens parse --json` contract (ADR 0076 §3; mirror of messagefoundry/lens.py output) --------

export type RowKind = "action" | "lookup" | "control" | "send" | "code" | "diagnostic";

/** One row of a handler's Steps, exactly as `lens parse` emits it (§3). Fields are per-kind. */
export interface LensRow {
  kind: RowKind;
  line_start: number; // 1-based, inclusive
  line_end: number; // 1-based, inclusive
  nesting: number; // 0 = top of the def body; +1 per control block
  // A stable id for the row's SUITE — the enclosing block's header line as a string (the def body uses the
  // def line). Rows that share it are true siblings; the webview offers a drag-reorder drop only among them
  // and greys an ↑/↓ at a suite edge (a reorder never crosses into/out of an if/for body — that would
  // change when the code runs). Absent on an older contract → the webview offers no cross-row drops (safe).
  suite?: string;
  // action rows
  action?: string;
  // lookup | diagnostic rows (diagnostic = log_note / checkpoint, ADR 0106 §5 K)
  call?: string;
  assign_to?: string;
  // action | lookup | diagnostic rows
  params?: Record<string, unknown>;
  // The subset of `params` whose argument is a Python literal (`ast.Constant`) — the only params the
  // lens can edit in place from a scalar (§5). Emitted by `lens parse` on action/lookup rows; the
  // webview offers ONLY these as editable inputs (an expression/list slot always refuses a scalar edit,
  // F6). Absent on an older contract / a hand-built test row → treated as "all params editable".
  literal_params?: string[];
  // control rows
  control?: "if" | "elif" | "else" | "for" | "raise";
  test_src?: string | null;
  recognized?: boolean;
  // A recognized native control idiom's descriptive header + captured display operand (ADR 0089 Phase C):
  // e.g. `label: "for each PID segment"`, `operand: "PID"`. Absent on a plain/unrecognized control (and on
  // an older contract) → the row falls back to its generic `CONTROL_LABELS` title. Read-only (recognition
  // + display only — Phase C never edits the if/for structure).
  label?: string | null;
  operand?: unknown;
  // send rows
  outbounds?: string[];
  // A `return []` explicit filter (the store maps it to FILTERED) — an additive flag on a send row so it
  // renders as "Filter" without overloading empty `outbounds` (a dynamic-destination Send also has none).
  filtered?: boolean;
}

/** One `@handler`'s contract: its registered name, def line, and ordered rows. */
export interface LensHandler {
  handler: string;
  module: string;
  def_line: number;
  rows: LensRow[];
  // ADR 0104 §2.3 P2: the handler's recognized message type, for the field-picker scope. Optional — a
  // typeless handler / older contract omits them (→ generic, unscoped picker).
  accepts_types?: string[];
  inferred_type?: { code?: string; trigger?: string };
}

/** The whole-file `lens parse --json` payload: `{ module, handlers }` (see __main__._lens). */
export interface LensParseResult {
  module: string;
  handlers: LensHandler[];
}

// ---- the row view-model the webview renders ---------------------------------------------------------

/** One read-only parameter of a row's form (label + display value). */
export interface ParamField {
  name: string;
  value: string;
}

/**
 * One rendered row. `index` is its 0-based position within the handler — the coverage invariant means
 * `index` also equals the row's position in `LensHandler.rows`, so a test can assert the view-model
 * partitions the def body in order. `liveValue` is attached (redacted by default) by {@link mergeLiveValues}.
 */
export interface RowViewModel {
  index: number;
  kind: RowKind;
  nesting: number;
  lineStart: number;
  lineEnd: number;
  // The control keyword for a `control` row (`if`/`elif`/`else`/`for`/`raise`), carried through so the DOM can
  // tell an `elif`/`else` CONTINUATION of a block apart from a genuine following sibling at the same nesting —
  // needed to find a dropped-after block's VISUAL bottom (the insertion-bar anchor, {@link insertionBarAnchor}).
  // Undefined for non-control rows.
  control?: "if" | "elif" | "else" | "for" | "raise";
  // The row's suite id (see {@link LensRow.suite}) + whether it can be REORDERED (drag/↑/↓). `movable` is
  // computed once at fold time (it needs the contract's `control` field, absent from this view-model) so
  // the webview stays a pure consumer. Optional only so a hand-built test row may omit it (→ not movable);
  // {@link buildRowViewModel} always populates it.
  suite?: string;
  movable?: boolean;
  title: string;
  subtitle?: string;
  badge?: string; // e.g. "unrecognized" for a control whose test is outside the bounded grammar (§4)
  params: ParamField[];
  // The recognized vocabulary name — an `action` row's action (e.g. "set_field") OR a `lookup` row's call
  // (e.g. "code_lookup") — enabling the HL7 field picker on a path slot (ADR 0104 §2.3). Undefined for
  // code/control rows / hand-built test rows.
  action?: string;
  /**
   * Names of the params that are editable in phase 3 (ADR 0076 §5) — a subset of `params[].name`.
   * Only recognized `action`/`lookup`/`send` rows have any; `code`/`control` rows are read-only, so this
   * is always empty for them (they are never regenerable from a template). A `send` row's synthetic `to`
   * field is editable only when it has exactly one static destination (a list-of-Sends / dynamic
   * destination is out of v1 edit scope — the engine refuses it). The webview renders a param whose name
   * is in this list as an enabled input; every other field stays disabled + read-only. Optional so a
   * hand-built RowViewModel (tests) may omit it — treated as "nothing editable".
   */
  editableParams?: string[];
  code?: string; // verbatim source slice — code rows only (the degradation-ladder passthrough)
  liveValue?: string; // redacted-by-default #92 annotation (see mergeLiveValues); undefined = none
  /**
   * The PROJECTION-TIME source text of this row's [lineStart, lineEnd] range — the row exactly as the user
   * saw it when the lens projected the inputs (engine newline model: split on `\r\n`|`\r`|`\n`, joined by
   * `\n`, no trailing EOL; mirrors `messagefoundry/lens._physical_lines`). Carried through an edit as the
   * engine's `expect_src` so `lens rewrite` refuses a stale coordinate before splicing the wrong same-shape
   * row (F7). It is NEVER re-derived from the live buffer at edit time — that is what made the guard
   * tautological (the engine would compare the buffer against itself). Optional so a hand-built
   * RowViewModel (tests) may omit it.
   */
  expectSrc?: string;
}

/** One handler's rendered Steps. */
export interface HandlerViewModel {
  handler: string;
  defLine: number;
  rows: RowViewModel[];
}

// ---- friendly labels (Corepoint action analogs, ADR 0076 §2 table) ---------------------------------

const ACTION_LABELS: Record<string, string> = {
  copy_field: "Copy Field",
  set_field: "Set Field",
  append_to_field: "Append to Field",
  format_date: "Format Date",
  convert_case: "Convert Case",
  split_field: "Split Field",
  copy_segment: "Copy Segment",
  delete_segment: "Delete Segment",
};

const LOOKUP_LABELS: Record<string, string> = {
  db_lookup: "DB Lookup",
  fhir_lookup: "FHIR Lookup",
  code_lookup: "Code Lookup",
};

// Diagnostics (ADR 0106 §5 K / Group 4) — the one output-independent side effect (DEBUG-only logging).
const DIAGNOSTIC_LABELS: Record<string, string> = {
  log_note: "Log Note",
  checkpoint: "Checkpoint",
};

const CONTROL_LABELS: Record<string, string> = {
  if: "If",
  elif: "Else If",
  else: "Else",
  for: "For each",
  raise: "Raise",
};

/** Title-case a snake_case identifier for a fallback label (e.g. `new_helper` → "New Helper"). */
export function humanizeIdentifier(name: string): string {
  return name
    .split("_")
    .filter((w) => w.length > 0)
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

// ---- param rendering ---------------------------------------------------------------------------------

/**
 * Render one contract param value for display. `lens parse` emits a literal arg as its JSON value
 * (string / number / bool / null, or a list of those) and anything else as verbatim source text (a
 * bounded `Message` read like `msg["PID-5.1"]`). Strings pass through verbatim (so a source snippet
 * reads naturally); scalars/arrays are stringified.
 */
export function renderParamValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => renderParamValue(v)).join(", ");
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  return String(value);
}

/** The ordered read-only form fields for a row's params (insertion order = call arg order). */
export function paramsToFields(params: Record<string, unknown> | undefined): ParamField[] {
  if (!params) {
    return [];
  }
  return Object.entries(params).map(([name, value]) => ({ name, value: renderParamValue(value) }));
}

// ---- row → view-model --------------------------------------------------------------------------------

/** Split module source into lines the way the parser did (`str.splitlines()` semantics for \n / \r\n). */
export function splitLines(source: string): string[] {
  return source.split(/\r?\n/);
}

/**
 * Split module source into physical lines on `\r\n` / `\r` / `\n` ONLY — the exact newline set the engine
 * uses (`messagefoundry/lens._physical_lines`, matching the CPython tokenizer / AST line numbers). Used for
 * every source→line-range slice in the build path so a projection-time `expectSrc` compares byte-for-byte
 * against what `lens rewrite` recomputes from the buffer (F7). NOT `str.splitlines()`'s wider Unicode set
 * (vertical tab, form feed, NEL, U+2028/9), which would insert phantom breaks and spuriously refuse.
 */
export function physicalLines(source: string): string[] {
  return source.split(/\r\n|\r|\n/);
}

/** The verbatim source of a row's inclusive 1-based [lineStart, lineEnd] range (for `code` rows). */
function sliceSource(lines: string[], lineStart: number, lineEnd: number): string {
  // Clamp defensively: a dirty buffer edited in a split view can be shorter than the parsed file.
  const from = Math.max(1, lineStart);
  const to = Math.min(lines.length, lineEnd);
  if (to < from) {
    return "";
  }
  return lines.slice(from - 1, to).join("\n");
}

/** The human title for a row (kind-specific). */
function rowTitle(row: LensRow): string {
  switch (row.kind) {
    case "action":
      return row.action ? (ACTION_LABELS[row.action] ?? humanizeIdentifier(row.action)) : "Action";
    case "lookup":
      return row.call ? (LOOKUP_LABELS[row.call] ?? humanizeIdentifier(row.call)) : "Lookup";
    case "control":
      // A recognized Phase-C idiom carries a descriptive label (ADR 0089); else the generic control label.
      if (row.label) {
        return row.label;
      }
      return row.control ? (CONTROL_LABELS[row.control] ?? humanizeIdentifier(row.control)) : "Control";
    case "send":
      // An explicit `return []` filter reads as "Filter"; a real Send stays "Send".
      return row.filtered ? "Filter" : "Send";
    case "diagnostic":
      return row.call ? (DIAGNOSTIC_LABELS[row.call] ?? humanizeIdentifier(row.call)) : "Diagnostic";
    case "code":
      return "Code";
  }
}

/** The secondary line for a row (the control test, the lookup assignment target, the send targets). */
function rowSubtitle(row: LensRow): string | undefined {
  if (row.kind === "control") {
    return row.test_src ?? undefined;
  }
  if (row.kind === "lookup" && row.assign_to) {
    return `→ ${row.assign_to}`;
  }
  if (row.kind === "send") {
    if (row.filtered) {
      return "(drop the message)";
    }
    const outs = row.outbounds ?? [];
    return outs.length > 0 ? outs.join(", ") : "(dynamic destination)";
  }
  if (row.kind === "diagnostic") {
    // The template (log_note) / label (checkpoint) literal — the one meaningful, editable field.
    const p = row.params ?? {};
    const text = p.template ?? p.label;
    return text !== undefined ? renderParamValue(text) : undefined;
  }
  return undefined;
}

/** The read-only param fields for a row (send rows surface their destinations as a `to` field). */
function rowParams(row: LensRow): ParamField[] {
  if (row.kind === "send") {
    const outs = row.outbounds ?? [];
    return [{ name: "to", value: outs.length > 0 ? outs.join(", ") : "(dynamic destination)" }];
  }
  return paramsToFields(row.params);
}

/**
 * Whether a row kind is a recognized, lens-editable row (ADR 0076 §5 + ADR 0106 §5 K). `diagnostic`
 * (log_note/checkpoint) is editable too — only its template/label LITERAL, enforced by the engine's
 * `_editable_slots` (operands render verbatim / read-only).
 */
export function isRowEditable(kind: RowKind): boolean {
  return kind === "action" || kind === "lookup" || kind === "send" || kind === "diagnostic";
}

/**
 * Whether a row can be REORDERED within its suite (drag-and-drop or ↑/↓): a recognized action/lookup/send
 * row, OR a whole `if`/`for` control BLOCK (its header row moves the block — header + body — as one unit,
 * ADR 0089). An `elif`/`else` header is part of its `if`, not independently movable; a `code` row is the
 * degradation catch-all (a comment / multi-statement group has no single statement to relocate). The engine
 * is authoritative (it locates the statement by header line, re-indents across nesting for a cross-suite
 * drop, and refuses an empty-source / into-self / stale drop); this gates which rows the webview makes
 * draggable + shows ↑/↓ on.
 */
export function isRowMovable(row: LensRow): boolean {
  return (
    isRowEditable(row.kind) ||
    (row.kind === "control" && (row.control === "if" || row.control === "for" || row.control === "raise"))
  );
}

/**
 * Whether a row can be DELETED. Mirrors the engine's delete gate (messagefoundry/lens rewrite_source):
 * any lens-editable leaf (action/lookup/send/diagnostic), plus a whole `if`/`for` control BLOCK (its
 * header removes the block). A `raise`/`elif`/`else`/`code` row is NOT deletable — the engine refuses it
 * (so the webview greys the trash to avoid an error toast, F6).
 */
export function isRowDeletable(row: LensRow): boolean {
  return isRowEditable(row.kind) || (row.kind === "control" && (row.control === "if" || row.control === "for"));
}

/**
 * The param names editable in phase 3 for a row (a subset of its rendered fields). `action`/`lookup`
 * rows expose only their **literal-valued** params (`literal_params` from the contract): an
 * expression/list-valued slot — `db_lookup(..., params={...})`, `split_field(..., dests=[...])` — always
 * refuses a scalar edit, so offering it as editable would guarantee an error toast (F6). A `send` row
 * exposes `to` only when it has exactly one static destination (list-of-Sends / dynamic destinations are
 * out of v1 edit scope). `code`/`control` rows expose none — they stay read-only (the §4 degradation
 * ladder). A contract that omits `literal_params` (older engine / hand-built row) degrades to the prior
 * "all params editable".
 */
export function editableParamNames(row: LensRow): string[] {
  // action / lookup / diagnostic expose only their literal-valued params (diagnostics: the template/label
  // literal — operands are excluded by the engine, so `literal_params` already omits them, ADR 0106 §5 K).
  if (row.kind === "action" || row.kind === "lookup" || row.kind === "diagnostic") {
    const names = Object.keys(row.params ?? {});
    if (row.literal_params === undefined) {
      return names;
    }
    const literal = new Set(row.literal_params);
    return names.filter((name) => literal.has(name));
  }
  if (row.kind === "send") {
    return (row.outbounds ?? []).length === 1 ? ["to"] : [];
  }
  return [];
}

/** Fold one contract row + the module lines into its view-model. */
export function buildRowViewModel(row: LensRow, index: number, lines: string[]): RowViewModel {
  const vm: RowViewModel = {
    index,
    kind: row.kind,
    nesting: row.nesting,
    lineStart: row.line_start,
    lineEnd: row.line_end,
    movable: isRowMovable(row),
    title: rowTitle(row),
    params: rowParams(row),
    editableParams: editableParamNames(row),
    action: row.action ?? row.call, // ADR 0104 §2.3: recognized name (action OR lookup call, e.g. code_lookup)

    // The row's projected source — sliced from the SAME (engine-newline) lines the projection parsed, so
    // it equals `"\n".join(_physical_lines(src)[start-1:end])` on the engine side (F7). `.slice` clamps an
    // over-range end exactly like Python's slice, so a shorter dirty buffer never throws here.
    expectSrc: lines.slice(row.line_start - 1, row.line_end).join("\n"),
  };
  const subtitle = rowSubtitle(row);
  if (subtitle !== undefined) {
    vm.subtitle = subtitle;
  }
  if (row.suite !== undefined) {
    vm.suite = row.suite;
  }
  if (row.kind === "control" && row.control !== undefined) {
    vm.control = row.control;
  }
  // A control row whose test falls outside the bounded grammar keeps its structure but is flagged — it
  // is still shown, never hidden (§4 degradation ladder). recognized is only meaningful for controls.
  if (row.kind === "control" && row.recognized === false) {
    vm.badge = "unrecognized";
  }
  if (row.kind === "code") {
    vm.code = sliceSource(lines, row.line_start, row.line_end);
  }
  return vm;
}

/** Fold one handler contract + module source into its rendered Steps (rows in contract order). */
export function buildHandlerViewModel(handler: LensHandler, lines: string[]): HandlerViewModel {
  return {
    handler: handler.handler,
    defLine: handler.def_line,
    rows: handler.rows.map((row, i) => buildRowViewModel(row, i, lines)),
  };
}

/** Fold the whole `lens parse` payload + module source into per-handler view-models. */
export function buildHandlerViewModels(
  parse: LensParseResult,
  source: string,
): HandlerViewModel[] {
  // Engine newline model so a row's projected `expectSrc` (and code-row slice) matches what `lens rewrite`
  // recomputes from the buffer (F7). `source` is the document text AT PROJECTION TIME — the snapshot the
  // user saw — so slicing it here is the row's projected source, never a live-buffer re-read.
  const lines = physicalLines(source);
  return parse.handlers.map((h) => buildHandlerViewModel(h, lines));
}

// ---- the parse-error → text-editor fallback decision (ADR 0076 §4 / §6 gate 6) ----------------------

/** Whether the lens should step aside to the plain text editor, and the notice to show if so. */
export interface FallbackDecision {
  fallback: boolean;
  reason?: string;
}

/**
 * Decide whether to fall back to the text editor. The lens is a projection of *parseable* code, so it
 * refuses in two cases (never a silent blank): the CLI could not parse the file (a whole-file refusal —
 * `error` is the CLI/exec message), or the file parsed but defines no `@handler` (routers are out of v1
 * scope, so there is nothing to project). A successful parse with ≥1 handler renders. Pure/testable.
 */
export function shouldFallBackToText(
  parse: LensParseResult | null,
  error: string | null,
): FallbackDecision {
  if (error) {
    return {
      fallback: true,
      reason: `MessageFoundry: cannot open the Steps view — ${error}. Opening as text.`,
    };
  }
  if (!parse || parse.handlers.length === 0) {
    return {
      fallback: true,
      reason:
        "MessageFoundry: no @handler found in this module — the Steps view shows Handlers only. Opening as text.",
    };
  }
  return { fallback: false };
}

// ---- live-value merge (#92 / ADR 0072) --------------------------------------------------------------

/**
 * A structural subset of liveDebug's `InlineValue` — deliberately re-declared here (not imported) so
 * this module stays vscode-free and node-side-testable. `line` is 0-based (VS Code coordinates, as
 * liveDebug emits); `after` is the rendered annotation, which is ALREADY redacted (the `▸ ⋯`
 * placeholder) whenever the caller obtained it with reveal off — this module never un-redacts anything.
 */
export interface LiveInlineValue {
  line: number; // 0-based
  after: string;
  kind: "value" | "warning";
}

/** The redacted annotation shown by default (matches liveDebug's VALUE_MARKER + REVEAL_PLACEHOLDER). */
export const REDACTED_LIVE_VALUE = "▸ ⋯";

/**
 * Attach live values to the rows they belong to, by line containment. An inline value on 0-based line
 * `iv.line` belongs to a row whose 1-based [lineStart, lineEnd] contains `iv.line + 1`. When several
 * fall in one row, their annotations are joined in line order. This is a THIN, pure read of whatever the
 * caller already computed — crucially it never reveals anything: with reveal off (the default) each
 * `after` is the redacted `▸ ⋯`, so the merged `liveValue` is redacted too. Mutates + returns `rows`.
 */
export function mergeLiveValues(rows: RowViewModel[], inline: LiveInlineValue[]): RowViewModel[] {
  const ordered = [...inline].sort((a, b) => a.line - b.line);
  for (const row of rows) {
    const hits = ordered.filter(
      (iv) => iv.line + 1 >= row.lineStart && iv.line + 1 <= row.lineEnd,
    );
    if (hits.length > 0) {
      row.liveValue = hits.map((h) => h.after).join("  ·  ");
    }
  }
  return rows;
}

/**
 * Whether the lens should attach live values on THIS projection, given the open document's dirty state.
 *
 * Live values come from a SECOND `dryrun --trace json` that reads the module **from disk** (the addendum
 * design: a self-contained trace, deliberately NOT the live buffer). The rows, in contrast, are projected
 * from the LIVE buffer (`lens parse -` over stdin) so their coordinates describe what the user sees. When
 * the document is **dirty** — an unsaved structural edit (insert/delete/move) shifted every following row,
 * or any unsaved change made buffer != disk — the disk trace's line numbers describe the PRE-edit file,
 * so mapping them onto the shifted buffer rows by line containment ({@link mergeLiveValues}) would land a
 * marker on the WRONG row (BACKLOG #225). A dry-run cannot reflect an unsaved buffer, so the lens SKIPS
 * live values while dirty (the toolbar's redacted placeholder stands) and re-attaches them on the next
 * SAVE, when disk == buffer realigns the coordinates. Pure — the provider passes `document.isDirty`.
 */
export function shouldAttachLiveValues(isDirty: boolean): boolean {
  return !isDirty;
}

// ---- live-value acquisition: the lens's second traced dry-run (ADR 0076 addendum / ADR 0072) --------
//
// The provider shells `dryrun --trace json` against a chosen SYNTHETIC sample, filters the result to the
// open module (liveDebug.invocationsForFile), then folds the invocations into the redacted-by-default
// inline values these two pure helpers produce; {@link mergeLiveValues} attaches them to rows by line
// containment. The redaction MIRRORS liveDebug's inline path EXACTLY (same `▸ ⋯` placeholder, same
// "REDACTED" CLI sentinel, same live-lookup warning) so PHI can never surface through the lens.

/** The exact sentinel the CLI substitutes for a captured value when `--show-phi` was NOT passed (ADR
 * 0072 §5); a value equal to it always renders as the placeholder, mirroring liveDebug's `TRACE_REDACTED`. */
const TRACE_REDACTED = "REDACTED";
/** liveDebug's VALUE_MARKER / REVEAL_PLACEHOLDER — kept in sync so both surfaces read identically. */
const VALUE_MARKER = "▸";
const REVEAL_PLACEHOLDER = "⋯";
/** liveDebug's WARNING_TEXT — a live db_lookup/fhir_lookup cannot be evaluated in an offline preview. */
const LIVE_LOOKUP_WARNING = "⚠ live lookup — not evaluated in preview";

/** One captured item on a line: a local assignment (`mrn`) or a `msg[...]` write. */
interface TraceLineItem {
  label: string;
  value: TraceValue;
}

/**
 * Render one captured value. Off-reveal it is ALWAYS the placeholder — a defense-in-depth belt beyond the
 * CLI's own redaction, so a real value can never leak through the lens even if a caller mis-wires the gate
 * — and a value the CLI already redacted stays a placeholder even under reveal. Mirrors liveDebug.renderValue.
 */
function renderTraceValue(value: TraceValue, reveal: boolean): string {
  if (!reveal || value === TRACE_REDACTED) {
    return REVEAL_PLACEHOLDER;
  }
  return JSON.stringify(value); // "SMITH" / 12345 / true / null
}

/** The row annotation text: a single `▸ ⋯` placeholder off-reveal; the value(s) on-reveal. */
function renderTraceAfter(items: TraceLineItem[], reveal: boolean): string {
  if (!reveal) {
    return `${VALUE_MARKER} ${REVEAL_PLACEHOLDER}`; // === REDACTED_LIVE_VALUE
  }
  if (items.length === 1) {
    return `${VALUE_MARKER} ${renderTraceValue(items[0].value, true)}`;
  }
  return `${VALUE_MARKER} ${items.map((it) => `${it.label} = ${renderTraceValue(it.value, true)}`).join(", ")}`;
}

/**
 * Fold the open module's Router/Handler invocations (from a second `dryrun --trace json`) into the
 * redacted-by-default {@link LiveInlineValue}s the lens attaches to rows. Locals assigned and `msg[...]`
 * writes are attributed to their producing line; across traced messages the newest invocation touching a
 * line wins. A `live_lookup_skipped` annotation renders a warning on its line and suppresses any value
 * there. `reveal` defaults OFF and the provider ALWAYS calls it off (the lens never un-redacts / never
 * passes `--show-phi`); the parameter exists only so the redaction is unit-testable against real values.
 * Pure — no vscode, no I/O.
 */
export function traceRowValues(invocations: TraceInvocation[], reveal = false): LiveInlineValue[] {
  const byLine = new Map<number, TraceLineItem[]>(); // 1-based line → items
  const warnings = new Map<number, string>(); // 1-based line → call name
  for (const inv of invocations) {
    const local = new Map<number, TraceLineItem[]>();
    for (const ev of inv.events) {
      const items = local.get(ev.line) ?? [];
      for (const [name, value] of Object.entries(ev.assigned ?? {})) {
        items.push({ label: name, value });
      }
      for (const w of ev.writes ?? []) {
        items.push({ label: `msg["${w.path}"]`, value: w.value });
      }
      if (items.length > 0) {
        local.set(ev.line, items);
      }
    }
    for (const [line, items] of local) {
      byLine.set(line, items); // newest invocation (latest message) wins for a shared line
    }
    for (const ann of inv.annotations) {
      if (ann.kind === "live_lookup_skipped") {
        warnings.set(ann.line ?? inv.def_line ?? 1, ann.call);
      }
    }
  }
  const out: LiveInlineValue[] = [];
  for (const [line, items] of byLine) {
    if (warnings.has(line)) {
      continue; // a live-lookup line raised before assigning — the warning speaks for it
    }
    out.push({ line: line - 1, after: renderTraceAfter(items, reveal), kind: "value" });
  }
  for (const line of warnings.keys()) {
    out.push({ line: line - 1, after: LIVE_LOOKUP_WARNING, kind: "warning" });
  }
  return out.sort((a, b) => a.line - b.line);
}

/**
 * Assemble the lens's `dryrun --trace json` argv (the caller adds `--json` via runJson). It NEVER contains
 * `--show-phi`: the lens is redacted-by-default and, unlike the Test Bench, must not request real values —
 * so the CLI redacts every captured value at the source (ADR 0072 §5) and no PHI leaves the Python process.
 * Pure (no vscode) so the "no `--show-phi` in the default argv" guarantee is directly unit-testable.
 */
export function buildLensTraceArgs(configDir: string, samplePath: string): string[] {
  return ["dryrun", "--config", configDir, "--messages", samplePath, "--trace", "json"];
}

// ---- phase 3 editing: edit request + rewrite result + loop guard (ADR 0076 §5) ----------------------

/** A webview → provider param-edit message (one field changed on a recognized row). */
export interface EditMessage {
  command: "edit";
  handler: string;
  lineStart: number;
  lineEnd: number;
  name: string; // the param name (e.g. "dst", "to")
  value: string; // the new value, as typed in the field
  // The row's PROJECTION-TIME source text (the row as the user saw it when the lens projected the inputs),
  // echoed back from the webview's `data-expect-src` and carried to `lens rewrite` as `expect_src` (F7).
  // Optional so a hand-built message (tests / an older payload) may omit it — then no stale check is sent.
  expectSrc?: string;
}

/** The `lens rewrite` edit spec (mirror of messagefoundry/lens.rewrite_source's contract). */
export interface EditRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "set_params";
  params: Record<string, string>;
  // The projected row's source text from the LIVE buffer (no EOL). `lens rewrite` verifies it still
  // matches the row before splicing, so a stale coordinate (a coincidental same-shape row) is refused
  // instead of edited in the wrong place (F7). Omitted → no stale check (older/no-buffer callers).
  expect_src?: string;
}

/**
 * Map a webview edit message to the engine's `lens rewrite` edit spec (ADR 0076 §5) — pure, so the
 * mapping is unit-testable without the Extension Host. The value is passed as a JSON string, which the
 * engine renders as a Python **string literal** when the current argument is a literal (the common
 * analyst edit: a field path, a code, a destination name); the engine refuses — and the provider
 * surfaces — an edit of an argument that is currently an expression, so the lens never guesses.
 *
 * `expectSrc` is the row's PROJECTION-TIME source text (the row as the user saw it when the lens
 * projected the inputs). It is taken from the explicit argument when given (older 2-arg callers) and
 * otherwise from `msg.expectSrc`; when present it is carried as `expect_src` so the engine can reject a
 * stale coordinate before splicing (F7). Crucially it is the PROJECTED source, never a live-buffer
 * recompute — recomputing it from the same buffer sent as stdin made the guard tautological.
 */
export function buildEditRequest(msg: EditMessage, expectSrc?: string): EditRequest {
  const req: EditRequest = {
    handler: msg.handler,
    line_start: msg.lineStart,
    line_end: msg.lineEnd,
    op: "set_params",
    params: { [msg.name]: msg.value },
  };
  const src = expectSrc ?? msg.expectSrc;
  if (src !== undefined) {
    req.expect_src = src;
  }
  return req;
}

/** The outcome of shelling `lens rewrite`: the rewritten source, or a refusal message. */
export interface RewriteOutcome {
  source?: string;
  error?: string;
}

/**
 * Interpret a `lens rewrite` CLI result (pure — testable with a canned CLI output). On exit 0 the
 * stdout is the rewritten module source (byte-identical outside the edited row). On a refusal the CLI
 * prints `{"error": …}` + exit 1; anything else falls back to stderr. Never throws.
 */
export function parseRewriteResult(result: { stdout: string; stderr: string; code: number }): RewriteOutcome {
  if (result.code === 0) {
    return { source: result.stdout };
  }
  const text = result.stdout.trim();
  if (text) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (
        parsed !== null &&
        typeof parsed === "object" &&
        typeof (parsed as { error?: unknown }).error === "string"
      ) {
        return { error: (parsed as { error: string }).error };
      }
    } catch {
      // stdout was not JSON — fall through to stderr.
    }
  }
  return { error: result.stderr.trim() || "lens rewrite failed" };
}

// ---- phase 3 v2 editing: STRUCTURAL ops (insert / delete / move rows) --------------------------------

/**
 * The vocabulary actions the "add step" affordance offers, mapped to their scalar parameter names in
 * signature order. Only scalar-param actions appear in the simple add form; lookups and list-valued
 * actions (`split_field`, `db_lookup`, …) need expression arguments and are added via text — out of the
 * quick form (the engine still inserts them if a caller supplies the right spec).
 */
export const INSERTABLE_ACTIONS: Record<string, string[]> = {
  copy_field: ["src", "dst"],
  set_field: ["path", "value"],
  append_to_field: ["path", "suffix"],
  convert_case: ["path", "mode"],
  format_date: ["path", "out_fmt"],
  copy_segment: ["segment_id"],
  delete_segment: ["segment_id"],
};

// ---- toolbar insert (Corepoint-style top-of-lens Add, ADR 0076 §5 / BACKLOG #222) -------------------
//
// The toolbar Add inserts a TEMPLATE with default params (NO prompts) at the currently selected row, then
// lets the user edit the fields inline. Its catalog is exactly the {@link INSERTABLE_ACTIONS} keys — the
// scalar-param vocabulary actions. `split_field` / `code_lookup` are deliberately EXCLUDED: their
// list/dict-valued params are not inline-editable, so they remain text-editor-only (add them via "Open as
// Text"), the same rule the per-row edit path enforces (F6).

/** The dropdown order + friendly labels (single source of truth for both the `<option>`s and the tests).
 * Order mirrors the ADR 0076 §2 action table; labels reuse the SAME friendly names the rows show. */
export const INSERT_ACTION_LABELS: ReadonlyArray<{ value: string; label: string }> = [
  // Only the actions the engine inserts in their NATIVE, import-free form (ADR 0089 Phase A) are offered,
  // so every dropdown entry works on a native-API Handler with no `from messagefoundry import …`. The
  // wrapper-only verbs (append_to_field / convert_case / format_date / copy_segment) return once Phase B
  // recognizes + natively inserts their forms.
  "set_field",
  "copy_field",
  "delete_segment",
].map((value) => ({ value, label: ACTION_LABELS[value] }));

/** The DEFAULT template params filled for a toolbar insert (no InputBox prompts) — keyed by action, then
 * by the action's scalar param names (in signature order, mirroring {@link INSERTABLE_ACTIONS}). Empty
 * strings render as empty inline inputs the user then fills; `convert_case` seeds a valid `mode`. */
export const TOOLBAR_INSERT_DEFAULTS: Record<string, Record<string, string>> = {
  set_field: { path: "", value: "" },
  copy_field: { src: "", dst: "" },
  append_to_field: { path: "", suffix: "" },
  convert_case: { path: "", mode: "upper" },
  format_date: { path: "", out_fmt: "" },
  copy_segment: { segment_id: "" },
  delete_segment: { segment_id: "" },
};

/**
 * Build an insert_row spec for the toolbar Add: a NEW vocabulary `action` (seeded with its default
 * template params) inserted relative to the SELECTED anchor row (pure; unit-testable). The POSITION is
 * derived from the anchor's kind — a `send` row is the handler's return, so a new action must precede it
 * (`before`); every other row inserts `after`. The anchor's projection-time source is carried as
 * `expect_src` so the insertion is refused on a stale coordinate (F7). Reuses {@link buildInsertRequest}.
 */
export function buildToolbarInsertRequest(
  anchor: { handler: string; lineStart: number; lineEnd: number; expectSrc?: string; kind: RowKind },
  action: string,
  position?: "before" | "after",
): InsertRequest {
  const params = { ...(TOOLBAR_INSERT_DEFAULTS[action] ?? {}) };
  // An EXPLICIT position (the row context menu's "Insert before"/"Insert after") wins; otherwise DERIVE it
  // from the anchor kind (the toolbar Add, which passes none) — a `send` row is the handler's return, so a
  // new action must precede it. Both callers ride the same `insert_row` engine path (no second surface).
  const pos: "before" | "after" = position ?? (anchor.kind === "send" ? "before" : "after");
  return buildInsertRequest(anchor, action, params, pos);
}

// ---- ADR 0106 grouped Add menu (the full palette) ----------------------------------------------------
//
// ADD_MENU_CATALOG is the SINGLE source of truth for the grouped <optgroup> select, the right-click
// submenu, and the tests. Each item names the lens op it requests and the inputs the provider gathers
// (a picker / input / fixed choice) before building the edit; a no-prompt item seeds default params and
// is filled inline. #26 holds: every item requests a NATIVE-code insert the lens recognizes — no
// declarative logic is executed.

export type AddMenuGroup = "Transform" | "Translate & lookup" | "Structure & flow" | "Diagnostics";

/** One input the Add flow gathers before building the edit. `field` is the edit-dict key it fills. */
export interface PromptSpec {
  field: string;
  label: string;
  kind: "text" | "codeset" | "destination" | "choice";
  choices?: readonly string[]; // kind === "choice"
  optional?: boolean;
  expr?: boolean; // wrap the gathered value as `{expr: <value>}` (a Name / numeric / expression arg)
  placeholder?: string;
}

/** One grouped Add-menu item. Exactly one op-discriminator field (`action`/`template`/`clause`) is set. */
export interface AddMenuItem {
  id: string;
  label: string;
  group: AddMenuGroup;
  op: "insert_row" | "template" | "insert_clause" | "insert_comment" | "insert_code_lookup";
  action?: string; // op === "insert_row"
  template?: string; // op === "template"
  clause?: "elif" | "else"; // op === "insert_clause"
  assignVar?: boolean; // op === "insert_row" lookups that bind a var (the "var" prompt → assign_to)
  seed?: Record<string, ParamValue>; // op === "insert_row": default params for a no-prompt inline-fill
  prompts: PromptSpec[];
  anchorConstraint?: "if_chain"; // Else / Else If: only valid on an if-chain anchor
}

const IF_OPERATORS = ["exists", "equals", "not_equals", "contains"] as const;

export const ADD_MENU_CATALOG: readonly AddMenuItem[] = [
  // --- Transform: scalar/string params filled inline (no prompt) ---
  { id: "set_field", label: "Set Field", group: "Transform", op: "insert_row", action: "set_field", seed: { path: "", value: "" }, prompts: [] },
  { id: "copy_field", label: "Copy Field", group: "Transform", op: "insert_row", action: "copy_field", seed: { src: "", dst: "" }, prompts: [] },
  { id: "trim_field", label: "Trim Field", group: "Transform", op: "insert_row", action: "trim_field", seed: { path: "" }, prompts: [] },
  { id: "replace_literal", label: "Replace", group: "Transform", op: "insert_row", action: "replace_literal", seed: { path: "", old: "", new: "" }, prompts: [] },
  { id: "date_diff_field", label: "Date Diff", group: "Transform", op: "insert_row", action: "date_diff_field", seed: { start_path: "", end_path: "", dst: "" }, prompts: [] },
  { id: "format_date", label: "Format Date", group: "Transform", op: "insert_row", action: "format_date", seed: { path: "", out_fmt: "" }, prompts: [] },
  { id: "copy_segment", label: "Copy Segment", group: "Transform", op: "insert_row", action: "copy_segment", seed: { segment_id: "" }, prompts: [] },
  { id: "delete_segment", label: "Delete Segment", group: "Transform", op: "insert_row", action: "delete_segment", seed: { segment_id: "" }, prompts: [] },
  { id: "add_segment", label: "Insert Segment", group: "Transform", op: "insert_row", action: "add_segment", seed: { line: "" }, prompts: [] },
  { id: "add_repetition", label: "Add Repetition", group: "Transform", op: "insert_row", action: "add_repetition", seed: { path: "", value: "" }, prompts: [] },
  // --- Transform: numeric / list params gathered at insert (rendered as raw exprs, not string literals) ---
  {
    id: "substring_field", label: "Substring Field", group: "Transform", op: "insert_row", action: "substring_field",
    prompts: [
      { field: "path", label: "Field path", kind: "text", placeholder: "PID-3.1" },
      { field: "start", label: "Start index", kind: "text", expr: true, placeholder: "0" },
      { field: "end", label: "End index", kind: "text", expr: true, placeholder: "6" },
    ],
  },
  {
    id: "pad_field", label: "Pad Field", group: "Transform", op: "insert_row", action: "pad_field",
    prompts: [
      { field: "path", label: "Field path", kind: "text", placeholder: "PID-3.1" },
      { field: "width", label: "Width", kind: "text", expr: true, placeholder: "10" },
    ],
  },
  {
    id: "arith_field", label: "Arith", group: "Transform", op: "insert_row", action: "arith_field",
    prompts: [
      { field: "path", label: "Field path", kind: "text", placeholder: "OBX-5" },
      { field: "op", label: "Operator", kind: "choice", choices: ["+", "-", "*", "/"] },
      { field: "operand", label: "Operand", kind: "text", expr: true, placeholder: "2.20462" },
    ],
  },
  {
    id: "split_field", label: "Split Field", group: "Transform", op: "insert_row", action: "split_field",
    prompts: [
      { field: "src", label: "Source field", kind: "text", placeholder: "PID-5" },
      { field: "sep", label: "Separator", kind: "text", placeholder: "^" },
      { field: "dests", label: "Destination fields (Python list)", kind: "text", expr: true, placeholder: '["PID-5.1", "PID-5.2"]' },
    ],
  },
  // --- Translate & lookup ---
  {
    id: "code_lookup", label: "Code Lookup", group: "Translate & lookup", op: "insert_code_lookup",
    prompts: [
      { field: "code_set", label: "Code set", kind: "codeset" },
      { field: "path", label: "Field path", kind: "text", placeholder: "PID-8" },
      { field: "default", label: "Default (on a miss, optional)", kind: "text", optional: true },
    ],
  },
  {
    id: "db_lookup", label: "DB Lookup", group: "Translate & lookup", op: "insert_row", action: "db_lookup",
    assignVar: true, seed: { params: { expr: "{}" } },
    prompts: [
      { field: "var", label: "Assign result to", kind: "text", placeholder: "row" },
      // db_lookup / fhir_lookup connections live in [egress].allowed_db / allowed_http, NOT the outbound
      // graph — so this is free text (an outbound picker would offer the wrong, message-sending set).
      { field: "connection", label: "DB connection ([egress].allowed_db)", kind: "text", placeholder: "MPI" },
      { field: "statement", label: "SQL statement", kind: "text", placeholder: "select 1" },
    ],
  },
  {
    id: "fhir_lookup", label: "FHIR Lookup", group: "Translate & lookup", op: "insert_row", action: "fhir_lookup",
    assignVar: true,
    prompts: [
      { field: "var", label: "Assign result to", kind: "text", placeholder: "pat" },
      { field: "connection", label: "FHIR connection ([egress].allowed_http)", kind: "text", placeholder: "epic" },
      { field: "query", label: "FHIR query", kind: "text", placeholder: "Patient?identifier=X" },
    ],
  },
  // --- Structure & flow ---
  {
    id: "if", label: "If", group: "Structure & flow", op: "template", template: "if",
    prompts: [
      { field: "field", label: "Field path", kind: "text", placeholder: "PID-3.1" },
      { field: "operator", label: "Condition", kind: "choice", choices: IF_OPERATORS },
      { field: "value", label: "Value", kind: "text", optional: true },
    ],
  },
  {
    id: "elif", label: "Else If", group: "Structure & flow", op: "insert_clause", clause: "elif", anchorConstraint: "if_chain",
    prompts: [
      { field: "field", label: "Field path", kind: "text", placeholder: "PID-3.1" },
      { field: "operator", label: "Condition", kind: "choice", choices: IF_OPERATORS },
      { field: "value", label: "Value", kind: "text", optional: true },
    ],
  },
  { id: "else", label: "Else", group: "Structure & flow", op: "insert_clause", clause: "else", anchorConstraint: "if_chain", prompts: [] },
  {
    id: "for_each", label: "For Each", group: "Structure & flow", op: "template", template: "for_each",
    prompts: [{ field: "segment_id", label: "Segment id", kind: "text", placeholder: "OBX" }],
  },
  { id: "filter", label: "Filter", group: "Structure & flow", op: "template", template: "filter", prompts: [] },
  {
    id: "raise", label: "Raise", group: "Structure & flow", op: "template", template: "raise",
    prompts: [
      { field: "exc_type", label: "Exception", kind: "choice", choices: ["ValueError", "RuntimeError"] },
      { field: "message", label: "Message", kind: "text", placeholder: "bad MRN" },
    ],
  },
  {
    id: "send", label: "Send", group: "Structure & flow", op: "template", template: "send",
    prompts: [{ field: "destination", label: "Destination", kind: "destination" }],
  },
  {
    id: "comment", label: "Comment", group: "Structure & flow", op: "insert_comment",
    prompts: [{ field: "text", label: "Comment", kind: "text" }],
  },
  // --- Diagnostics (editable after insert, ADR 0106 §5 K — filled inline) ---
  { id: "log_note", label: "Log Note", group: "Diagnostics", op: "insert_row", action: "log_note", seed: { template: "" }, prompts: [] },
  { id: "checkpoint", label: "Checkpoint", group: "Diagnostics", op: "insert_row", action: "checkpoint", seed: { label: "" }, prompts: [] },
];

/** The catalog keyed by id — the provider's untrusted-input allowlist (the `insertItem` message's itemId). */
export const ADD_MENU_BY_ID: Readonly<Record<string, AddMenuItem>> = Object.fromEntries(
  ADD_MENU_CATALOG.map((item) => [item.id, item]),
);

/** The catalog grouped in stable order — for the grouped <optgroup> select + the right-click submenu. */
export function addMenuGroups(): { group: AddMenuGroup; items: AddMenuItem[] }[] {
  const order: AddMenuGroup[] = ["Transform", "Translate & lookup", "Structure & flow", "Diagnostics"];
  return order.map((group) => ({ group, items: ADD_MENU_CATALOG.filter((i) => i.group === group) }));
}

/**
 * Build the `lens rewrite` edit for a chosen Add-menu item + the values the provider gathered (pure;
 * unit-testable). `values` maps each prompt's `field` to its gathered string; a no-prompt item leaves it
 * empty and uses `item.seed`. The POSITION follows the toolbar-Add rule (a `send` anchor → `before`).
 * The anchor's projection-time source rides as `expect_src` (F7). Never runs a picker — that is the
 * provider's job before it calls this.
 */
export function buildAddMenuRequest(
  item: AddMenuItem,
  anchor: { handler: string; lineStart: number; lineEnd: number; expectSrc?: string; kind: RowKind },
  values: Record<string, string>,
  position?: "before" | "after",
): StructuralRequest {
  const pos: "before" | "after" = position ?? (anchor.kind === "send" ? "before" : "after");
  const base = { handler: anchor.handler, line_start: anchor.lineStart, line_end: anchor.lineEnd };
  const withExpect = <T extends { expect_src?: string }>(req: T): T => {
    if (anchor.expectSrc !== undefined) {
      req.expect_src = anchor.expectSrc;
    }
    return req;
  };
  const promptByField = new Map(item.prompts.map((p) => [p.field, p]));
  const paramValue = (field: string): ParamValue => {
    const v = values[field] ?? "";
    return promptByField.get(field)?.expr ? { expr: v } : v;
  };

  switch (item.op) {
    case "insert_row": {
      const params: Record<string, ParamValue> = { ...(item.seed ?? {}) };
      let assignTo: string | undefined;
      for (const p of item.prompts) {
        if (item.assignVar && p.field === "var") {
          assignTo = values[p.field];
          continue;
        }
        if (!(p.optional && !values[p.field])) {
          params[p.field] = paramValue(p.field);
        }
      }
      const req: InsertRequest = { ...base, op: "insert_row", position: pos, action: item.action ?? "", params };
      if (assignTo) {
        req.assign_to = assignTo;
      }
      return withExpect(req);
    }
    case "template": {
      const req: TemplateRequest = { ...base, op: "template", position: pos, template: item.template ?? "" };
      if (values.field) req.field = values.field;
      if (values.operator) req.operator = values.operator;
      if (values.value !== undefined && values.value !== "") req.value = values.value;
      if (values.test) req.test = values.test;
      if (values.segment_id) req.segment_id = values.segment_id;
      if (values.exc_type) req.exc_type = values.exc_type;
      if (values.message !== undefined && values.message !== "") req.message = values.message;
      if (values.destination) req.destination = values.destination;
      return withExpect(req);
    }
    case "insert_clause": {
      const req: InsertClauseRequest = { ...base, op: "insert_clause", clause: item.clause ?? "else" };
      if (values.field) req.field = values.field;
      if (values.operator) req.operator = values.operator;
      if (values.value !== undefined && values.value !== "") req.value = values.value;
      if (values.test) req.test = values.test;
      return withExpect(req);
    }
    case "insert_comment": {
      const req: InsertCommentRequest = { ...base, op: "insert_comment", position: pos, text: values.text ?? "" };
      return withExpect(req);
    }
    case "insert_code_lookup": {
      const req: InsertCodeLookupRequest = {
        ...base,
        op: "insert_code_lookup",
        position: pos,
        code_set: values.code_set ?? "",
        path: values.path ?? "",
      };
      if (values.var) req.var = values.var;
      if (values.default) req.default = values.default;
      return withExpect(req);
    }
  }
}

// ---- row context menu (right-click, BACKLOG #222 follow-up to ADR 0100) ------------------------------
//
// The right-click menu is a NEW SURFACE onto the EXISTING row operations — it posts the same
// `insertToolbar` / `deleteRow` / `moveTo` (via walkMove) messages the toolbar Add and the per-row ↑/↓/🗑
// buttons already post (no second execution path). These two pure helpers are the source of truth (the
// enablement matrix + the server-rendered menu template); the webview mirrors the enablement and renders
// the template it positions on right-click. Copy/Cut/Paste stay keyboard-served (out of this menu).

/** Which context-menu items are enabled for a row (pure; the webview greys the rest). */
export interface ContextMenuEnablement {
  insertBefore: boolean;
  insertAfter: boolean;
  deleteRow: boolean;
  moveUp: boolean;
  moveDown: boolean;
}

/**
 * The enable/disable state of each row context-menu item for a given row (pure; unit-testable). Rules:
 * Insert BEFORE is always available; Insert AFTER is suppressed on a `send` row (a step after the return
 * would be dead code — the same reason {@link buildToolbarInsertRequest} derives `before` for a send);
 * Delete is offered only on an editable `action`/`lookup`/`send` row (a `code`/`control` row is read-only
 * — the §4 degradation ladder); Move up/down follow the ↑/↓ walk (`canMoveUp`/`canMoveDown` come from
 * {@link walkMove} returning a destination, so a suite edge / non-movable / sole-child row greys them).
 */
export function contextMenuEnablement(
  kind: RowKind,
  ctx: { canMoveUp: boolean; canMoveDown: boolean },
): ContextMenuEnablement {
  return {
    insertBefore: true,
    insertAfter: kind !== "send",
    deleteRow: isRowEditable(kind),
    moveUp: ctx.canMoveUp,
    moveDown: ctx.canMoveDown,
  };
}

/** A webview → provider structural-op message (delete/move a row, or begin the add-row flow). */
export interface StructuralMessage {
  command: "deleteRow" | "moveRow" | "insertRow" | "moveTo";
  handler: string;
  lineStart: number;
  lineEnd: number;
  direction?: "up" | "down"; // moveRow only
  // moveTo (drag-and-drop) only — the DESTINATION anchor row + which side of it the moved block lands. The
  // anchor is a direct member of the LANDING suite (for a header "into" drop it is the body's first row).
  toLineStart?: number;
  toLineEnd?: number;
  toPosition?: "before" | "after";
  // moveTo only — the landing suite id the client intended (a header line number as a string, or the def
  // line for top level). Carried to `lens rewrite` as `to_suite` so the engine refuses a stale/mis-targeted
  // cross-suite drop (the destination analog of `expect_src`). Optional — an older client omits it.
  toSuite?: string;
  // The target row's PROJECTION-TIME source, echoed from `data-expect-src` and carried to `lens rewrite`
  // as `expect_src` so a structural op on a stale coordinate is refused, not mis-applied (F7).
  expectSrc?: string;
}

/** The `lens rewrite` spec for a delete_row op. */
export interface DeleteRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "delete_row";
  expect_src?: string;
}

/**
 * The `lens rewrite` spec for a move_row op — one of two forms, exactly one populated:
 *  - adjacent swap: `direction` ("up"/"down"), the ↑/↓ buttons; or
 *  - drag-to-target: `to_line_start`/`to_line_end` (the destination sibling row) + `to_position`
 *    ("before"/"after"), the drag-and-drop reorder. The engine routes on `to_line_start` presence.
 */
export interface MoveRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "move_row";
  direction?: "up" | "down";
  to_line_start?: number;
  to_line_end?: number;
  to_position?: "before" | "after";
  // The landing suite id the drag intended — the engine refuses a stale/mis-targeted cross-suite drop
  // (the destination analog of `expect_src`). Present only on the drag-to-target form, and only when the
  // client supplied it (keeps the deepStrictEqual mapping test's no-toSuite payload byte-identical).
  to_suite?: string;
  expect_src?: string;
}

/** A value in an inserted call's params: a scalar literal, or a raw `{expr: <source>}` for a Name /
 * expression argument (a code-set table Name, a db params dict, a numeric literal, a split_field list). */
export type ParamValue = string | { expr: string };

/** The `lens rewrite` spec for an insert_row op. */
export interface InsertRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "insert_row";
  position: "before" | "after";
  action: string;
  params: Record<string, ParamValue>;
  // db_lookup / fhir_lookup bind their result: `<var> = <call>` (ADR 0106 §5 J). Absent for actions.
  assign_to?: string;
  expect_src?: string;
}

/** The `lens rewrite` spec for a `template` op (ADR 0106 §5 A — If / For Each / Filter / Raise / Send). */
export interface TemplateRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "template";
  position: "before" | "after";
  template: string;
  field?: string; // if / elif: structured test
  operator?: string;
  value?: string;
  test?: string; // if / elif: raw test escape
  segment_id?: string; // for_each
  exc_type?: string; // raise
  message?: string;
  destination?: string; // send
  expect_src?: string;
}

/** The `lens rewrite` spec for an `insert_clause` op (ADR 0106 §5 D — Else If / Else clause-append). */
export interface InsertClauseRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "insert_clause";
  clause: "elif" | "else";
  field?: string;
  operator?: string;
  value?: string;
  test?: string;
  expect_src?: string;
}

/** The `lens rewrite` spec for an `insert_comment` op (ADR 0106 §5 L). */
export interface InsertCommentRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "insert_comment";
  position: "before" | "after";
  text: string;
  expect_src?: string;
}

/** The `lens rewrite` spec for an `insert_code_lookup` op (ADR 0106 §5 I — Code Lookup + code-set binding). */
export interface InsertCodeLookupRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "insert_code_lookup";
  position: "before" | "after";
  code_set: string;
  path: string;
  var?: string;
  default?: string;
  expect_src?: string;
}

/** The `lens rewrite` spec for a paste_block op — insert the captured `block` at the anchor, re-indented
 * to the anchor's suite by the engine. `position` follows the toolbar-Add rule (send → before, else after). */
export interface PasteRequest {
  handler: string;
  line_start: number;
  line_end: number;
  op: "paste_block";
  position: "before" | "after";
  block: string;
  expect_src?: string;
}

export type StructuralRequest =
  | DeleteRequest
  | MoveRequest
  | InsertRequest
  | PasteRequest
  | TemplateRequest
  | InsertClauseRequest
  | InsertCommentRequest
  | InsertCodeLookupRequest;

/**
 * The lens ops that change LINE COUNTS — after any of them every row coordinate the webview held is
 * stale, so the provider MUST force a full re-projection (re-run `lens parse` on the NEW buffer and
 * rebuild the webview) rather than batch a queued param edit on stale coordinates (ADR 0076 §5 v2).
 */
export const STRUCTURAL_OPS: ReadonlySet<string> = new Set([
  "delete_row",
  "insert_row",
  "move_row",
  "paste_block",
  // ADR 0106 inserts — all change line counts, so each forces a full re-projection.
  "template",
  "insert_clause",
  "insert_comment",
  "insert_code_lookup",
]);

/** Whether an op invalidates every row coordinate (structural) and so forces a re-projection. */
export function opForcesReprojection(op: string): boolean {
  return STRUCTURAL_OPS.has(op);
}

/** Map a delete-row message to the engine's `lens rewrite` delete_row spec (pure; unit-testable). */
export function buildDeleteRequest(msg: StructuralMessage): DeleteRequest {
  const req: DeleteRequest = {
    handler: msg.handler,
    line_start: msg.lineStart,
    line_end: msg.lineEnd,
    op: "delete_row",
  };
  if (msg.expectSrc !== undefined) {
    req.expect_src = msg.expectSrc;
  }
  return req;
}

/** Map a move-row message to the engine's `lens rewrite` move_row spec (pure; unit-testable). */
export function buildMoveRequest(msg: StructuralMessage): MoveRequest {
  if (msg.direction !== "up" && msg.direction !== "down") {
    throw new Error("moveRow requires direction 'up' or 'down'");
  }
  const req: MoveRequest = {
    handler: msg.handler,
    line_start: msg.lineStart,
    line_end: msg.lineEnd,
    op: "move_row",
    direction: msg.direction,
  };
  if (msg.expectSrc !== undefined) {
    req.expect_src = msg.expectSrc;
  }
  return req;
}

/**
 * Map a drag-and-drop drop message to the engine's `lens rewrite` move_row spec (the drag-to-target form;
 * pure, unit-testable). `toLineStart`/`toLineEnd` name the destination anchor row; `toPosition` names the
 * side it lands. A CROSS-suite drop also carries `toSuite` (the landing suite id) as the engine's
 * destination stale-guard. The moved row's projection-time source rides as `expect_src` (F7 stale guard).
 */
export function buildMoveToRequest(msg: StructuralMessage): MoveRequest {
  if (
    typeof msg.toLineStart !== "number" ||
    (msg.toPosition !== "before" && msg.toPosition !== "after")
  ) {
    throw new Error("moveTo requires toLineStart and toPosition 'before' or 'after'");
  }
  const req: MoveRequest = {
    handler: msg.handler,
    line_start: msg.lineStart,
    line_end: msg.lineEnd,
    op: "move_row",
    to_line_start: msg.toLineStart,
    to_line_end: msg.toLineEnd ?? msg.toLineStart,
    to_position: msg.toPosition,
  };
  // Copied ONLY when defined so a caller that passes no toSuite (the existing mapping test) keeps a payload
  // with no to_suite key — backward-compatible with the engine's "absent → skip the destination guard".
  if (msg.toSuite !== undefined) {
    req.to_suite = msg.toSuite;
  }
  if (msg.expectSrc !== undefined) {
    req.expect_src = msg.expectSrc;
  }
  return req;
}

// ---- cross-suite drag-and-drop: the pure drop resolver (ADR 0076 §5 v2 / #222 cross-suite) ----------
//
// The DROP UX must let the user UNAMBIGUOUSLY choose the LANDING SUITE — especially the classic for-header
// ambiguity ("first statement INSIDE the loop" vs "after the whole loop at the outer level"). These pure
// helpers are the SOURCE OF TRUTH for that resolution; the inline stepsView.ts <script> mirrors them (it
// cannot import across the webview boundary, the same pattern canDrop/dropSide already follow). A drop
// JOINS the landing suite at the landing indent; the engine re-derives the real suite + re-indents, so a
// stale/malformed client coordinate is refused, never mis-applied.

/** A row as the drop resolver sees it — derived from the row view-model / the <li> dataset. */
export interface RowDropContext {
  handler: string;
  lineStart: number;
  lineEnd: number;
  nesting: number;
  suite: string;
  kind: RowKind;
  draggable: boolean;
  // A draggable if/for HEADER row (elif/else are neither draggable nor a target). It gets the tri-zone
  // hit-test (before-outer / into-body / after-outer); a leaf gets the two-zone before/after.
  isControlHeader: boolean;
  // The control keyword (control rows only) — lets {@link insertionBarAnchor} recognize an `elif`/`else`
  // CONTINUATION of an `if` when walking a dropped-after block to its visual bottom. Undefined on a leaf.
  control?: "if" | "elif" | "else" | "for";
}

/** Where a drop resolves to: the anchor row + side, plus the landing suite id and its indent depth. */
export interface DropResolution {
  anchorLineStart: number;
  anchorLineEnd: number;
  toPosition: "before" | "after";
  toSuite: string;
  landingDepth: number;
}

/**
 * Whether `target` can accept a drop of `drag` (pure). Widened from the same-suite rule to: same handler,
 * not itself, target draggable, and target is NOT inside the dragged block's own [start, end] span (so a
 * block can't be dropped into itself). NO same-suite requirement — the headline cross-suite move.
 */
export function canDropRow(drag: RowDropContext, target: RowDropContext): boolean {
  return (
    target !== drag &&
    target.draggable &&
    target.handler === drag.handler &&
    !(drag.lineStart <= target.lineStart && target.lineStart <= drag.lineEnd)
  );
}

/**
 * Resolve a drop over `target` at vertical `pointerFraction` (0 = top edge … 1 = bottom edge) to its
 * landing suite + anchor (pure; unit-tested). Returns null if the drop is illegal (see {@link canDropRow}).
 *
 * A control HEADER row uses a TRI-ZONE hit-test that resolves the for-header ambiguity EXPLICITLY:
 *  - top third    → BEFORE the whole block at the OUTER level (anchor = the header, before);
 *  - middle third → INTO the body as its FIRST statement (anchor = the body's first row, before; one level
 *    deeper) — the "first inside the loop" gesture, at the header itself;
 *  - bottom third → AFTER the whole block at the OUTER level (anchor = the header, after).
 * A leaf keeps the two-zone model (pointer half); a send/return clamps to `before` (a block never lands
 * after the return as dead code). `rows` is the flat handler row list — used to find a header's body's
 * first row (the row whose suite id equals the header's line number).
 */
export function resolveDrop(
  drag: RowDropContext,
  target: RowDropContext,
  pointerFraction: number,
  rows: readonly RowDropContext[],
): DropResolution | null {
  if (!canDropRow(drag, target)) {
    return null;
  }
  if (target.isControlHeader) {
    if (pointerFraction < 1 / 3) {
      return {
        anchorLineStart: target.lineStart,
        anchorLineEnd: target.lineEnd,
        toPosition: "before",
        toSuite: target.suite,
        landingDepth: target.nesting,
      };
    }
    if (pointerFraction > 2 / 3) {
      return {
        anchorLineStart: target.lineStart,
        anchorLineEnd: target.lineEnd,
        toPosition: "after",
        toSuite: target.suite,
        landingDepth: target.nesting,
      };
    }
    // Middle → into the body. The body's suite id IS this header's line number; its first row is the anchor.
    const bodySuiteId = String(target.lineStart);
    const first = rows.find((r) => r.suite === bodySuiteId);
    if (!first) {
      return null; // no body row to anchor against (an empty body is not a drop target)
    }
    return {
      anchorLineStart: first.lineStart,
      anchorLineEnd: first.lineEnd,
      toPosition: "before",
      toSuite: bodySuiteId,
      landingDepth: target.nesting + 1,
    };
  }
  const toPosition: "before" | "after" =
    target.kind === "send" ? "before" : pointerFraction > 0.5 ? "after" : "before";
  return {
    anchorLineStart: target.lineStart,
    anchorLineEnd: target.lineEnd,
    toPosition,
    toSuite: target.suite,
    landingDepth: target.nesting,
  };
}

/**
 * The scope-pill label for a landing suite (pure): `"top level"` at depth 0, else `"inside <title>"` where
 * `<title>` is the title of the enclosing header row (the row whose line start equals the suite id). A terse
 * fallback is used when that header is not in `headers` (defensive — the suite id always names a real row).
 */
export function scopeLabel(
  landingDepth: number,
  landingSuiteId: string,
  headers: readonly { lineStart: number; title: string }[],
): string {
  if (landingDepth === 0) {
    return "top level";
  }
  const id = Number(landingSuiteId);
  const header = headers.find((h) => h.lineStart === id);
  return header ? `inside ${header.title}` : "inside this block";
}

/** Which row the insertion bar aligns to, and which edge of its rect (the DOM layer reads the rect). */
export interface BarAnchor {
  /** The row (by its line start) whose rect edge the insertion bar sits on. */
  anchorLineStart: number;
  /** Which edge of that row's rect: the bar's `top` follows the row's `top` or `bottom`. */
  edge: "top" | "bottom";
}

/**
 * Resolve which row edge the insertion bar should sit on for a drop (pure; the DOM layer maps the returned
 * row → `getBoundingClientRect()` and uses `edge`). For a normal anchor the bar hugs the anchor row (its
 * BOTTOM for an `after`, its TOP for a `before`).
 *
 * The one case that needs correction is the control-HEADER "after the whole block" gesture (the bottom
 * third of a for/if header, {@link resolveDrop}): there the anchor is the HEADER with `after`, but the
 * engine lands the block AFTER the ENTIRE block (its `end_lineno`), which is visually BELOW every body row.
 * Anchoring the bar to the header's bottom would draw it directly above the body — indistinguishable from
 * the middle-third "into the body" bar — so it must sit at the block's VISUAL bottom instead. We find that
 * last body row by walking `rows` (document order) forward from the header while each row is either DEEPER
 * (a body row) or an `elif`/`else` CONTINUATION at the header's own nesting (whose own body then follows,
 * deeper) — matching the engine's block extent (`dest.end_lineno`). `rows` must be in document order.
 */
export function insertionBarAnchor(res: DropResolution, rows: readonly RowDropContext[]): BarAnchor {
  const anchor = rows.find((r) => r.lineStart === res.anchorLineStart);
  if (anchor && anchor.isControlHeader && res.toPosition === "after") {
    const start = rows.indexOf(anchor);
    let lastBody = anchor;
    for (let i = start + 1; i < rows.length; i++) {
      const r = rows[i];
      const deeper = r.nesting > anchor.nesting;
      const continuation =
        r.nesting === anchor.nesting && (r.control === "elif" || r.control === "else");
      if (deeper || continuation) {
        lastBody = r;
      } else {
        break; // a genuine following sibling at the header's nesting — the block ends above it
      }
    }
    return { anchorLineStart: lastBody.lineStart, edge: "bottom" };
  }
  return {
    anchorLineStart: res.anchorLineStart,
    edge: res.toPosition === "after" ? "bottom" : "top",
  };
}

// ---- keyboard walk: ↑/↓ as a stepwise cross-suite drag (#222 cross-suite / "walk into blocks") -------
//
// The ↑/↓ arrows are the KEYBOARD equivalent of the drag: a press moves the step one insertion slot in
// visible (DFS) order, ENTERING a following loop/if body when it reaches one and stepping out the far
// side — so repeated ↓ walks the step through every position top-to-bottom. It reuses the SAME slots
// drag-and-drop reaches ({@link resolveDrop}: a leaf's before/after, a control header's before-outer /
// into-body-first / after-whole-block), so an arrow move maps 1:1 to a drag-to-target `move_row`
// ({@link buildMoveToRequest}) and rides the verified cross-suite engine path — no new engine surface.

/**
 * Every insertion slot of a handler, in visible (DFS) order — the ordered targets the ↑/↓ walk steps
 * through (pure). Each slot is a {@link DropResolution} identical to what {@link resolveDrop} yields for
 * the equivalent drag. `rows` MUST be in document order and MUST already have the moving block removed
 * (so no slot lands inside it). A suite contributes one "before its first child" slot, then one slot
 * after each primary child; a control header recurses into its body (the "into body" slots) and, after
 * its elif/else continuation bodies, gets an "after the whole block" slot at the outer level; a
 * send/return contributes no "after" slot (a block never lands after the return). elif/else headers are
 * CONTINUATIONS (consumed with their `if`), never standalone slots.
 */
function buildDropSlots(rows: readonly RowDropContext[]): DropResolution[] {
  const childrenBySuite = new Map<string, RowDropContext[]>();
  for (const r of rows) {
    const list = childrenBySuite.get(r.suite);
    if (list) {
      list.push(r);
    } else {
      childrenBySuite.set(r.suite, [r]);
    }
  }
  const rootRow = rows.find((r) => r.nesting === 0);
  const slots: DropResolution[] = [];
  if (!rootRow) {
    return slots;
  }
  const isContinuation = (r: RowDropContext): boolean =>
    r.control === "elif" || r.control === "else";
  const emitSuite = (suiteId: string): void => {
    const children = childrenBySuite.get(suiteId) ?? [];
    let firstEmitted = false;
    for (let i = 0; i < children.length; i++) {
      const R = children[i];
      if (isContinuation(R)) {
        continue; // handled when we reach its `if`; never a standalone slot
      }
      if (!firstEmitted) {
        // The gap before the suite's first primary child (also the "into body, first statement" slot).
        slots.push({
          anchorLineStart: R.lineStart,
          anchorLineEnd: R.lineEnd,
          toPosition: "before",
          toSuite: suiteId,
          landingDepth: R.nesting,
        });
        firstEmitted = true;
      }
      if (R.isControlHeader) {
        emitSuite(String(R.lineStart)); // the block's own body — the "into body" slots
        for (let j = i + 1; j < children.length && isContinuation(children[j]); j++) {
          emitSuite(String(children[j].lineStart)); // each elif/else continuation body
        }
        // The gap AFTER the whole if/elif/else (or for) block, back at the outer level.
        slots.push({
          anchorLineStart: R.lineStart,
          anchorLineEnd: R.lineEnd,
          toPosition: "after",
          toSuite: suiteId,
          landingDepth: R.nesting,
        });
      } else if (R.kind !== "send") {
        slots.push({
          anchorLineStart: R.lineStart,
          anchorLineEnd: R.lineEnd,
          toPosition: "after",
          toSuite: suiteId,
          landingDepth: R.nesting,
        });
      }
    }
  };
  emitSuite(rootRow.suite);
  return slots;
}

// ---- Steps block copy / cut / paste: extent + capture + clipboard (ADR 0076 §5, block clipboard) ----
//
// COPY/CUT capture a movable block's SOURCE TEXT into a WEBVIEW-OWNED clipboard (`vscode.setState`, NOT the
// OS clipboard — it survives re-projection). PASTE re-inserts it at an anchor, re-indented to the anchor's
// suite by the ENGINE (`paste_block`, reusing the cross-suite move re-indent). These pure helpers are the
// source of truth the inline stepsView.ts <script> mirrors (it can't import across the webview boundary).

/** The captured Steps block on the webview clipboard (stored via `vscode.setState`, survives re-projection).
 * `source` is the block LF-joined (no trailing EOL); the engine derives the paste indent from it, never from
 * `nesting`. `nesting`/`kind`/`lineCount`/`label` are UX-only (the toolbar/toast). */
export interface ClipboardBlock {
  source: string;
  nesting: number;
  kind: RowKind;
  lineCount: number;
  label: string;
}

/** A row the capture sees — a {@link RowDropContext} plus its projection-time source (`expectSrc`), which
 * the capture joins into the clipboard block. (RowDropContext already carries the coords/suite/kind/control.) */
export type BlockCaptureRow = RowDropContext & { expectSrc: string };

/**
 * The [startIndex, endIndex] row span of the movable block whose header is at `blockStartLine`, in `rows`
 * (document order) — a LEAF is itself; an `if`/`for` control HEADER extends over its DEEPER body rows and
 * its `elif`/`else` CONTINUATIONS' bodies (the same extent {@link walkMove} moves and {@link captureBlock}
 * joins). Returns null when the start row is absent or not draggable, so a code/elif/else/missing start is a
 * non-extent. Pure — {@link walkMove} and {@link captureBlock} both route through it so they cannot diverge.
 */
export function blockExtent(
  rows: readonly RowDropContext[],
  blockStartLine: number,
): { startIndex: number; endIndex: number } | null {
  const mi = rows.findIndex((r) => r.lineStart === blockStartLine);
  if (mi < 0) {
    return null;
  }
  const moving = rows[mi];
  if (!moving.draggable) {
    return null;
  }
  let mj = mi;
  if (moving.isControlHeader) {
    for (let i = mi + 1; i < rows.length; i++) {
      const r = rows[i];
      const deeper = r.nesting > moving.nesting;
      const continuation =
        r.nesting === moving.nesting && (r.control === "elif" || r.control === "else");
      if (deeper || continuation) {
        mj = i;
      } else {
        break;
      }
    }
  }
  return { startIndex: mi, endIndex: mj };
}

/**
 * Capture the movable block whose header is at `blockStartLine` into its clipboard-ready shape (pure). The
 * block SOURCE is `rows[mi..mj].expectSrc` joined by "\n" — which equals the verbatim buffer slice in the
 * engine LF model (the coverage/contiguity invariant makes each row's projected source contiguous). Returns
 * null unless the start row is MOVABLE (draggable + not a `code` row) — the same scope reorder allows; a
 * `code`/`elif`/`else`/absent start yields null (a friendly no-op at the call site).
 */
export function captureBlock(
  rows: readonly BlockCaptureRow[],
  blockStartLine: number,
): {
  source: string;
  nesting: number;
  kind: RowKind;
  lineStart: number;
  lineEnd: number;
  lineCount: number;
} | null {
  const extent = blockExtent(rows, blockStartLine);
  if (!extent) {
    return null;
  }
  const start = rows[extent.startIndex];
  if (start.kind === "code") {
    return null; // a Code step is read-only — never copied (blockExtent marks it draggable to intercept)
  }
  const source = rows
    .slice(extent.startIndex, extent.endIndex + 1)
    .map((r) => r.expectSrc)
    .join("\n");
  return {
    source,
    nesting: start.nesting,
    kind: start.kind,
    lineStart: start.lineStart,
    lineEnd: rows[extent.endIndex].lineEnd,
    lineCount: extent.endIndex - extent.startIndex + 1,
  };
}

/** A short, human label for a captured block (UX-only — the toolbar tooltip + the copy/cut/paste toast).
 * `control` (the row's `if`/`for` keyword) distinguishes "the loop" from "the if block"; a leaf run uses its
 * step count. */
export function blockLabel(
  kind: RowKind,
  lineCount: number,
  control?: "if" | "elif" | "else" | "for",
): string {
  if (kind === "control") {
    return control === "for" ? "the loop" : `the ${control ?? "if"} block`;
  }
  return lineCount > 1 ? `${lineCount} steps` : "1 step";
}

/**
 * Resolve where a ↑/↓ arrow press on the block starting at `blockStartLine` should land (pure; the
 * source of truth the inline stepsView.ts <script> mirrors, like {@link resolveDrop}). The block's whole
 * span is removed, every insertion slot is enumerated in visible order ({@link buildDropSlots}), the
 * block's CURRENT gap is located, and the ADJACENT slot in `direction` is returned as a
 * {@link DropResolution} — which maps 1:1 to a drag-to-target `move_row` ({@link buildMoveToRequest}),
 * reusing the verified cross-suite engine path. Returns null when there is no next slot (the block is
 * already at the very top/bottom of the handler) or when it is the SOLE primary child of its suite
 * (moving it would empty the suite — the engine refuses that, so the arrow is a no-op). `rows` must be
 * the full handler row list in document order.
 */
export function walkMove(
  rows: readonly RowDropContext[],
  blockStartLine: number,
  direction: "up" | "down",
): DropResolution | null {
  // The block's row span [mi..mj] — the SAME extent {@link captureBlock} joins, so an arrow move and a
  // copy/cut can never disagree about what "the block" is (both go through {@link blockExtent}).
  const extent = blockExtent(rows, blockStartLine);
  if (!extent) {
    return null;
  }
  const { startIndex: mi, endIndex: mj } = extent;
  const moving = rows[mi];
  if (!moving.suite) {
    return null;
  }
  // The block's true siblings = the PRIMARY children of its suite (elif/else are continuations). Moving
  // the sole primary child would empty the suite — the engine refuses it (constraint 4), so grey it.
  const siblings = rows.filter(
    (r) => r.suite === moving.suite && !(r.control === "elif" || r.control === "else"),
  );
  if (siblings.length < 2) {
    return null;
  }
  const k = siblings.findIndex((r) => r.lineStart === moving.lineStart);
  const slots = buildDropSlots(rows.filter((_r, idx) => idx < mi || idx > mj));
  // The block's CURRENT gap: "after the previous sibling", or (it was first) "before the next sibling".
  const current =
    k > 0
      ? { toSuite: moving.suite, toPosition: "after" as const, anchorLineStart: siblings[k - 1].lineStart }
      : { toSuite: moving.suite, toPosition: "before" as const, anchorLineStart: siblings[1].lineStart };
  const ci = slots.findIndex(
    (s) =>
      s.toSuite === current.toSuite &&
      s.toPosition === current.toPosition &&
      s.anchorLineStart === current.anchorLineStart,
  );
  if (ci < 0) {
    return null; // defensive — the current gap is always one of the enumerated slots
  }
  return (direction === "down" ? slots[ci + 1] : slots[ci - 1]) ?? null;
}

/**
 * Build an insert_row spec: a NEW vocabulary `action` (+ its scalar `params`) inserted relative to an
 * anchor recognized row (pure; unit-testable). The anchor's projection-time source is carried as
 * `expect_src` so the insertion is refused on a stale coordinate (F7).
 */
export function buildInsertRequest(
  anchor: { handler: string; lineStart: number; lineEnd: number; expectSrc?: string },
  action: string,
  params: Record<string, string>,
  position: "before" | "after" = "after",
): InsertRequest {
  const req: InsertRequest = {
    handler: anchor.handler,
    line_start: anchor.lineStart,
    line_end: anchor.lineEnd,
    op: "insert_row",
    position,
    action,
    params,
  };
  if (anchor.expectSrc !== undefined) {
    req.expect_src = anchor.expectSrc;
  }
  return req;
}

/**
 * Build a paste_block spec: insert the clipboard `clip.source` at the SELECTED anchor, re-indented to the
 * anchor's suite by the engine (pure; unit-testable). The POSITION follows the toolbar-Add rule — a `send`
 * anchor is the handler's return, so a paste must PRECEDE it (`before`); every other anchor pastes `after`.
 * The anchor's projection-time source rides as `expect_src` (the F7 stale guard); only `clip.source` is
 * used from the clipboard (the engine derives the indent from the block text, never from `clip.nesting`).
 */
export function buildPasteRequest(
  anchor: { handler: string; lineStart: number; lineEnd: number; expectSrc?: string; kind: RowKind },
  clip: ClipboardBlock,
): PasteRequest {
  const position: "before" | "after" = anchor.kind === "send" ? "before" : "after";
  const req: PasteRequest = {
    handler: anchor.handler,
    line_start: anchor.lineStart,
    line_end: anchor.lineEnd,
    op: "paste_block",
    position,
    block: clip.source,
  };
  if (anchor.expectSrc !== undefined) {
    req.expect_src = anchor.expectSrc;
  }
  return req;
}

/**
 * One-editor-at-a-time + webview↔document update-loop guard (ADR 0076 §5, the InterSystems guardrail).
 *
 * `beginEdit()` claims the single in-flight slot (returns false if an edit is already applying, so a
 * second field change never races a half-applied rewrite). Instead of silently dropping that second
 * change, the caller `queue()`s it — coalesced by field — and drains it via `takePending()` once the
 * in-flight rewrite finishes, so the user's typed intent is never lost (F5). While an edit is applying,
 * `shouldReactToDocumentChange()` is false, so the `WorkspaceEdit` we apply does NOT feed back into a
 * re-render that would fight the webview (the loop). `endEdit()` releases the slot. Pure + synchronous,
 * so the provider's flow is unit-testable without the Extension Host.
 */
export class EditLoopGuard {
  private inFlight = false;
  private readonly pending = new Map<string, EditMessage>();

  beginEdit(): boolean {
    if (this.inFlight) {
      return false;
    }
    this.inFlight = true;
    return true;
  }

  /**
   * Remember an edit that arrived while one was applying, so it is applied after the in-flight rewrite
   * rather than silently dropped (F5). Coalesced by field (handler + line range + param name): re-typing
   * the SAME field keeps only the latest value; distinct fields each retain their own pending edit.
   */
  queue(msg: EditMessage): void {
    const key = `${msg.handler} ${msg.lineStart} ${msg.lineEnd} ${msg.name}`;
    this.pending.set(key, msg);
  }

  /** Take the next queued edit to apply (FIFO by first-seen field), or `undefined`. Keeps the slot claimed. */
  takePending(): EditMessage | undefined {
    const next = this.pending.entries().next();
    if (next.done) {
      return undefined;
    }
    const [key, msg] = next.value;
    this.pending.delete(key);
    return msg;
  }

  /**
   * Discard every queued param edit WITHOUT applying it (the orphaned-queue hazard, ADR 0076 §5 v2). A
   * STRUCTURAL op (insert/delete/move) shifts every row coordinate and forces a full re-projection, so a
   * param edit that was queued while the structural op held the slot references now-invalid PRE-op
   * coordinates. Draining it later would edit the wrong (shifted) row — or, if a textually-identical row
   * slid into the stale line range, silently pass the F7 guard and edit the wrong instance. The
   * structural path calls this before releasing the slot so those stale edits never survive re-projection.
   */
  clearPending(): void {
    this.pending.clear();
  }

  endEdit(): void {
    this.inFlight = false;
  }

  get isEditing(): boolean {
    return this.inFlight;
  }

  /** How many distinct-field edits are waiting to be applied after the in-flight one (F5). */
  get pendingCount(): number {
    return this.pending.size;
  }

  /** Whether a document-change event should trigger a re-render (false for our own in-flight edit). */
  shouldReactToDocumentChange(): boolean {
    return !this.inFlight;
  }
}

/**
 * Drain one edit + any queued follow-ups through `apply`, one at a time, under the loop guard (ADR 0076
 * §5). Extracted from the provider (which imports vscode) so the whole drain — including the guarantee
 * that an UNEXPECTED `apply` rejection never strands a queued edit — is unit-testable node-side.
 *
 * If an edit is already in flight, `first` is queued (coalesced by field) and this returns — the running
 * drain will pick it up. Otherwise it claims the slot and drains `first` then everything `takePending()`
 * yields. `apply` performs the actual `lens rewrite` + `WorkspaceEdit`; its OWN handled outcomes (a CLI
 * refusal) never throw, but an unexpected `WorkspaceEdit` rejection (or a spawn failure) would — that is
 * caught, routed to `onError`, and the loop KEEPS DRAINING so a pending second edit is not wedged until
 * the user types again. The slot is always released in `finally`. Never throws.
 */
export async function drainEdits(
  guard: EditLoopGuard,
  first: EditMessage,
  apply: (msg: EditMessage) => Promise<void>,
  onError?: (err: unknown, msg: EditMessage) => void,
): Promise<void> {
  if (!guard.beginEdit()) {
    guard.queue(first);
    return;
  }
  try {
    let current: EditMessage | undefined = first;
    while (current) {
      try {
        await apply(current);
      } catch (err) {
        onError?.(err, current);
      }
      current = guard.takePending();
    }
  } finally {
    guard.endEdit();
  }
}

// ---- HTML rendering (pure; the provider wraps this body in a CSP/nonce shell) -----------------------

/** Escape a string for safe interpolation into HTML text or a double-quoted attribute. */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const INDENT_PX = 20; // per nesting level

/**
 * Render the parameter form for a row. A param whose name is in `editable` renders as an ENABLED input
 * carrying the edit coordinates (handler + line range + param name) the webview posts on change; every
 * other param stays disabled + read-only. `code`/`control` rows pass an empty `editable` set, so they
 * remain entirely view-only (ADR 0076 §5). Pure — every dynamic value is HTML-escaped.
 */
// (action, param) pairs whose value is an HL7 path/segment the field picker (ADR 0104 §2.3) can drive.
// The pick writes the chosen literal through the SAME edit/lens-rewrite splice a typed edit uses, so it is
// only ever offered on an already-editable literal slot — never on `value`, `occurrence`, `repetition`, or
// a code/control row.
const HL7_PATH_PARAMS: Record<string, string[]> = {
  set_field: ["path"],
  copy_field: ["src", "dst"],
  append_to_field: ["path"],
  format_date: ["path"],
  convert_case: ["path"],
  code_lookup: ["path"],
};

/** Whether `param` of `action` is a pickable HL7 path (`"path"`) or a segment-only slot (`"segment"`). */
export function pickMode(action: string | undefined, param: string): "path" | "segment" | undefined {
  if (action === "delete_segment" && param === "segment_id") return "segment";
  return action && HL7_PATH_PARAMS[action]?.includes(param) ? "path" : undefined;
}

function renderParamsHtml(params: ParamField[], editable: Set<string>, handlerName: string, row: RowViewModel): string {
  if (params.length === 0) {
    return "";
  }
  const fields = params
    .map((p) => {
      const label = `<label>${escapeHtml(p.name)}</label>`;
      if (editable.has(p.name)) {
        // The row's PROJECTION-TIME source (`data-expect-src`) is echoed back on edit as `expect_src` so a
        // stale coordinate is refused, not mis-spliced (F7). An empty value shows a `[blank]` placeholder (a
        // hint, NOT a value) so a freshly-inserted template reads as "fill me in"; `placeholder` is inert on
        // submit, so the F7 round-trip is unaffected.
        const input =
          `<input type="text" class="edit" data-handler="${escapeHtml(handlerName)}" ` +
          `data-line-start="${row.lineStart}" data-line-end="${row.lineEnd}" ` +
          `data-expect-src="${escapeHtml(row.expectSrc ?? "")}" ` +
          `data-name="${escapeHtml(p.name)}" value="${escapeHtml(p.value)}" placeholder="[blank]" />`;
        // ADR 0104 §2.3: a pickable HL7 path/segment slot gets a picker button BESIDE its input. The input is
        // NEVER removed (free-text always available); the pick writes through the SAME edit splice. Only a
        // slot with a pick button gets the horizontal `.edit-row` wrapper — every other editable field's
        // markup is byte-identical to before.
        const pm = pickMode(row.action, p.name);
        const pickBtn = pm
          ? `<button class="pickpath" data-handler="${escapeHtml(handlerName)}" ` +
            `data-line-start="${row.lineStart}" data-line-end="${row.lineEnd}" ` +
            `data-expect-src="${escapeHtml(row.expectSrc ?? "")}" ` +
            `data-name="${escapeHtml(p.name)}" data-mode="${pm}" ` +
            `data-tip="Pick an HL7 field">&#8942;</button>`
          : "";
        return (
          `<div class="field">${label}` +
          (pickBtn ? `<div class="edit-row">${input}${pickBtn}</div>` : input) +
          `</div>`
        );
      }
      return (
        `<div class="field">${label}` +
        `<input type="text" readonly disabled value="${escapeHtml(p.value)}" /></div>`
      );
    })
    .join("");
  return `<div class="params">${fields}</div>`;
}

/**
 * Render the per-row STRUCTURAL affordances (move up/down, delete) — but ONLY on a recognized
 * (`action`/`lookup`/`send`) row of a writable projection (a known `handlerName`). `code` and `control`
 * rows are structurally read-only (they are not regenerable from a template), so they get NO structural
 * buttons — matching the param-edit read-only rule (ADR 0076 §5). Each button carries the row's edit
 * coordinates + its projection-time source (`data-expect-src`) for the F7 stale guard. Pure.
 *
 * NOTE: the per-row ＋ (add-step-after) button was REPLACED by the top-of-lens INSERT TOOLBAR (a native
 * <select> + green Add that inserts at the SELECTED row, ADR 0076 §5 / BACKLOG #222). Delete + move stay.
 */
function renderRowActionsHtml(row: RowViewModel, handlerName: string): string {
  // ↑/↓ appear on any MOVABLE row (an action/lookup/send row or a whole if/for block); the client greys
  // the ↑ on the first sibling and the ↓ on the last (a reorder never crosses a suite edge). 🗑 stays on
  // EDITABLE rows only — deleting mutates the row and is refused on a read-only control/code row.
  if (!handlerName || !row.movable) {
    return "";
  }
  const coords =
    `data-handler="${escapeHtml(handlerName)}" data-line-start="${row.lineStart}" ` +
    `data-line-end="${row.lineEnd}" data-expect-src="${escapeHtml(row.expectSrc ?? "")}"`;
  const btn = (op: string, glyph: string, title: string): string =>
    `<button class="rowop" data-op="${op}" ${coords} data-tip="${escapeHtml(title)}">${glyph}</button>`;
  const buttons = [
    btn("moveUp", "&#8593;", "Move up one step (walks into / out of blocks)"),
    btn("moveDown", "&#8595;", "Move down one step (walks into / out of blocks)"),
  ];
  if (isRowEditable(row.kind)) {
    buttons.push(btn("deleteRow", "&#128465;", "Delete this row"));
  }
  return `<span class="row-actions">${buttons.join("")}</span>`;
}

/** Render one row as a nested list item. Pure — every dynamic value is escaped. `handlerName` scopes an
 * editable field's edit coordinates + the structural affordances (phase 3); omit it (read-only callers)
 * to keep every field disabled and hide the structural buttons. */
export function renderRowHtml(row: RowViewModel, handlerName = ""): string {
  const indent = `style="margin-left:${row.nesting * INDENT_PX}px"`;
  const badge = row.badge ? `<span class="badge">${escapeHtml(row.badge)}</span>` : "";
  const subtitle = row.subtitle ? `<span class="subtitle">${escapeHtml(row.subtitle)}</span>` : "";
  const live = row.liveValue
    ? `<span class="live" data-tip="Live value (redacted by default — synthetic samples only)">${escapeHtml(row.liveValue)}</span>`
    : "";
  // A field is editable only when the handler name is known (the write path); read-only callers pass "".
  const editable = new Set(handlerName ? (row.editableParams ?? []) : []);
  const body =
    row.kind === "code"
      ? `<pre class="code">${escapeHtml(row.code ?? "")}</pre>`
      : renderParamsHtml(row.params, editable, handlerName, row);
  const lineLabel =
    row.lineStart === row.lineEnd ? `line ${row.lineStart}` : `lines ${row.lineStart}–${row.lineEnd}`;
  // A MOVABLE row (an action/lookup/send row, or a whole if/for block via its header row) is a drag SOURCE
  // and a drop TARGET for the reorder; a code / elif / else row is not. `data-suite` groups true siblings so
  // the ↑/↓ arrows stay suite-confined; the DRAG path may cross suites (the block re-indents to the landing
  // suite) — the engine stays authoritative on the re-indent + the empty-source/into-self/stale refusals.
  // Movable rows are real drag SOURCES. A `code` row is ALSO marked draggable, but ONLY so a drag ATTEMPT
  // can be intercepted and answered with "edit it in the code editor" — it stays read-only (the page script
  // cancels the drag on dragstart and never treats a code row as a drop target). See stepsView.ts.
  const draggable = handlerName && (row.movable || row.kind === "code") ? ` draggable="true"` : "";
  // Every row carries its anchor coordinates + projection-time source + kind on the <li> so the webview's
  // ROW-SELECTION model (the toolbar Add's insert location) can read them; `tabindex` makes a selected row
  // keyboard-focusable. `data-kind` lets the client derive the insert position (send → before, else after).
  return (
    `<li class="row row-${escapeHtml(row.kind)}"${draggable} ${indent} tabindex="0" ` +
    `data-handler="${escapeHtml(handlerName)}" data-line-start="${row.lineStart}" ` +
    `data-line-end="${row.lineEnd}" data-expect-src="${escapeHtml(row.expectSrc ?? "")}" ` +
    `data-kind="${escapeHtml(row.kind)}" data-nesting="${row.nesting}" data-suite="${escapeHtml(row.suite ?? "")}" ` +
    // data-control (control rows only) lets the DnD layer include an elif/else CONTINUATION when it walks a
    // dropped-after block's body to find its visual bottom (the insertion-bar anchor, insertionBarAnchor).
    `data-control="${escapeHtml(row.control ?? "")}">` +
    `<div class="row-head">` +
    `<span class="kind">${escapeHtml(row.kind)}</span>` +
    `<span class="title">${escapeHtml(row.title)}</span>` +
    subtitle +
    badge +
    live +
    `<button class="jump" data-line="${row.lineStart}" data-tip="Jump to the source line">${escapeHtml(lineLabel)}</button>` +
    renderRowActionsHtml(row, handlerName) +
    `</div>` +
    body +
    `</li>`
  );
}

/** Render one handler's Steps (header + ordered nested rows). Pure. */
export function renderHandlerHtml(handler: HandlerViewModel): string {
  const rows = handler.rows.map((r) => renderRowHtml(r, handler.handler)).join("");
  return (
    `<section class="handler">` +
    `<h2>${escapeHtml(handler.handler)}` +
    `<button class="jump" data-line="${handler.defLine}" data-tip="Jump to the handler definition">def line ${handler.defLine}</button>` +
    `</h2>` +
    `<ol class="rows">${rows}</ol>` +
    `</section>`
  );
}

/** Render every handler's Steps body (the provider wraps this in the CSP/nonce page shell). Pure. */
export function renderHandlersHtml(handlers: HandlerViewModel[]): string {
  if (handlers.length === 0) {
    return `<p class="empty">No handlers to show.</p>`;
  }
  return handlers.map(renderHandlerHtml).join("");
}

/**
 * Render the single, hidden row context-menu template the webview positions on right-click (BACKLOG #222
 * follow-up to ADR 0100 — its own note called a "right-click row menu … a follow-up"). Rendered
 * SERVER-SIDE so the insert catalog is the same {@link INSERT_ACTION_LABELS} single source of truth the
 * toolbar uses and NO markup is built by `innerHTML` in the strict-CSP webview — the script only
 * shows/positions/enables/dismisses this node and posts the SAME `insertToolbar`/`deleteRow`/`moveTo`
 * messages the toolbar Add + row ↑/↓/🗑 already post (no second execution path). Insert is a two-level
 * submenu (before / after → one item per insertable action); Delete / Move up / Move down are leaves. The
 * webview greys items per {@link contextMenuEnablement}. Pure — every label/value is HTML-escaped.
 */
export function renderStepsContextMenuHtml(): string {
  // The full ADR 0106 palette, grouped. Each item carries data-item-id (the ADD_MENU_BY_ID allowlist key
  // the provider validates) and, for a clause insert, data-anchor="if_chain" so the webview greys it off a
  // non-if row. Delete/Move enablement still comes from contextMenuEnablement.
  const actionItems = (position: "before" | "after"): string =>
    addMenuGroups()
      .map(
        ({ group, items }) =>
          `<div class="ctx-group-label" role="presentation">${escapeHtml(group)}</div>` +
          items
            .map(
              (item) =>
                `<button type="button" class="ctx-item" role="menuitem" ` +
                `data-cmd="insert" data-position="${position}" data-item-id="${escapeHtml(item.id)}"` +
                (item.anchorConstraint ? ` data-anchor="${escapeHtml(item.anchorConstraint)}"` : "") +
                `>${escapeHtml(item.label)}</button>`,
            )
            .join(""),
      )
      .join("");
  const insertParent = (position: "before" | "after", label: string): string =>
    `<div class="ctx-sub">` +
    `<button type="button" class="ctx-item ctx-parent" role="menuitem" aria-haspopup="true" ` +
    `data-sub="${position}">${escapeHtml(label)}<span class="ctx-arrow" aria-hidden="true">&#9656;</span></button>` +
    `<div class="ctx-menu ctx-submenu" role="menu" data-for="${position}">${actionItems(position)}</div>` +
    `</div>`;
  const leaf = (cmd: string, label: string): string =>
    `<button type="button" class="ctx-item" role="menuitem" data-cmd="${escapeHtml(cmd)}">${escapeHtml(label)}</button>`;
  return (
    `<div id="stepsCtxMenu" class="ctx-menu ctx-root" role="menu" hidden>` +
    insertParent("before", "Insert before") +
    insertParent("after", "Insert after") +
    `<div class="ctx-sep" role="separator"></div>` +
    leaf("deleteRow", "Delete") +
    leaf("moveUp", "Move up") +
    leaf("moveDown", "Move down") +
    `</div>`
  );
}
