// Pure, dependency-free mapping of a `messagefoundry dryrun --trace json` trace into the Test Bench's
// Coverage and Profiling panes. No `vscode` import, so it is unit-testable in isolation and never pulls
// the extension host into a test (mirrors hl7diff.ts). The engine's `parsing/` package is intentionally
// NOT imported (§4 keeps the IDE off the engine internals).
//
// Two derivations, both from ONE trace:
//   * COVERAGE — which lines of each @router/@handler actually ran. `events[].line` gives the executed
//     lines exactly; the enclosing function's line span (read from the config .py source) supplies the
//     lines that COULD run, so we can mark executed vs. not-executed. Executed marking is exact; the
//     "not-executed"/`%` denominator is a line-hit heuristic (blank/comment lines don't count; a
//     multi-physical-line statement reports only its first line — documented, best-effort).
//   * PROFILING — per-line and per-handler wall time. Each `events[].t` is the passive `perf_counter`
//     time attributed to that line (ADR 0072 / #84); we sum per line and per invocation and compute %.
//     Timings include the tracer's own overhead, so they rank hot lines/handlers rather than give an
//     absolute wall-clock — surfaced as a comparative view, never a benchmark.

// ---- Trace schema (subset mirror of messagefoundry/pipeline/dryrun_trace.py) -------------------

export interface TraceWrite {
  path: string;
  value: unknown;
}

export interface TraceEvent {
  line: number;
  event?: string;
  assigned?: Record<string, unknown>;
  writes?: TraceWrite[];
  t?: number; // seconds spent on this line (passive perf_counter timing); absent on a pre-#84 trace
}

export interface TraceAnnotation {
  line: number | null;
  kind: string;
  call?: string;
}

export interface TraceInvocation {
  kind: string; // "router" | "handler"
  name: string;
  module: string | null;
  file: string | null;
  def_line: number | null; // co_firstlineno — the FIRST DECORATOR line in Py3.14, not the `def`
  events: TraceEvent[];
  disposition: string;
  sends: { outbound: string }[];
  routed_to: string[];
  annotations: TraceAnnotation[];
  truncated?: boolean;
}

export interface TraceEntry {
  source: string;
  path?: string | null;
  inbound?: string | null;
  disposition: string;
  message_type?: string | null;
  control_id?: string | null;
  handlers?: string[];
  sends?: { outbound: string }[];
  error?: string | null;
  trace_ok?: boolean;
  invocations: TraceInvocation[];
}

// ---- Coverage model ----------------------------------------------------------------------------

export type LineRole = "def" | "code" | "comment" | "blank";

export interface CoverageLine {
  line: number; // 1-based source line number
  text: string; // source text ("" when the source file was unreadable)
  role: LineRole;
  executable: boolean; // counts toward the coverage denominator (role === "code")
  executed: boolean; // a line event fired on this line
  hits: number; // how many line events (loop iterations show > 1)
}

export interface InvocationCoverage {
  kind: string;
  name: string;
  module: string | null;
  file: string | null;
  defLine: number; // 1-based; where co_firstlineno points (decorator or def)
  startLine: number; // first rendered line (topmost decorator)
  endLine: number; // last rendered line (last body statement)
  sourceAvailable: boolean;
  lines: CoverageLine[];
  executable: number; // # of executable (code) lines
  executed: number; // # of executable lines that ran
  pct: number; // executed / executable * 100 (0 when executable === 0)
  truncated: boolean; // the trace hit its event cap — coverage may under-report
}

// ---- Profiling model ---------------------------------------------------------------------------

export interface LineProfile {
  line: number;
  text: string; // source text ("" when unavailable)
  hits: number;
  seconds: number; // total time attributed to this line across all hits
  pct: number; // seconds / invocation total * 100 (0 when total === 0)
}

export interface InvocationProfile {
  kind: string;
  name: string;
  hasTiming: boolean; // false on a pre-#84 trace with no `t` fields
  totalSeconds: number;
  lines: LineProfile[]; // hottest first (seconds desc, then line asc)
}

export interface InvocationView {
  kind: string;
  name: string;
  coverage: InvocationCoverage;
  profile: InvocationProfile;
}

export interface TraceDetail {
  source: string;
  disposition: string;
  traceOk: boolean;
  hasTiming: boolean; // any invocation carried timing
  totalSeconds: number; // summed across all invocations
  invocations: InvocationView[];
}

// ---- helpers -----------------------------------------------------------------------------------

const DEF_RE = /^\s*(async\s+)?def\b/;

/** Count leading whitespace (spaces/tabs) — a config .py file is internally consistent, so a raw char
 *  count orders indent levels correctly without needing to expand tabs. */
function leadingWidth(line: string): number {
  let n = 0;
  while (n < line.length && (line[n] === " " || line[n] === "\t")) {
    n++;
  }
  return n;
}

/** Line-event hit counts keyed by 1-based source line. */
function hitsByLine(inv: TraceInvocation): Map<number, number> {
  const hits = new Map<number, number>();
  for (const ev of inv.events) {
    if (typeof ev.line === "number") {
      hits.set(ev.line, (hits.get(ev.line) ?? 0) + 1);
    }
  }
  return hits;
}

interface Span {
  start: number; // 0-based, inclusive (topmost decorator)
  header: number; // 0-based index of the `def` line
  end: number; // 0-based, inclusive (last body statement)
}

/**
 * Line span of the function whose co_firstlineno is `defLine1` (1-based). In Python 3.14 that anchor is
 * the first DECORATOR line, so we scan DOWN to the real `def` header, take that header's indent, and walk
 * the body until it dedents back to the header level. Decorators above the header are kept as context.
 */
export function functionSpan(lines: string[], defLine1: number): Span {
  const anchor = Math.max(0, Math.min(defLine1 - 1, lines.length - 1));
  let header = anchor;
  while (header < lines.length && !DEF_RE.test(lines[header])) {
    header++;
  }
  if (header >= lines.length) {
    header = anchor; // no `def` found (malformed) — treat the anchor as the header
  }
  let start = Math.min(anchor, header);
  for (let i = start - 1; i >= 0; i--) {
    if (lines[i].trim().startsWith("@")) {
      start = i;
    } else {
      break;
    }
  }
  const headerIndent = leadingWidth(lines[header]);
  let end = header;
  for (let i = header + 1; i < lines.length; i++) {
    if (lines[i].trim() === "") {
      continue; // a blank line inside the body doesn't end it
    }
    if (leadingWidth(lines[i]) <= headerIndent) {
      break; // dedent back to (or past) the header → end of function
    }
    end = i;
  }
  return { start, header, end };
}

function classify(line: string, isHeaderOrDecorator: boolean): LineRole {
  if (isHeaderOrDecorator) {
    return "def";
  }
  const trimmed = line.trim();
  if (trimmed === "") {
    return "blank";
  }
  if (trimmed.startsWith("#")) {
    return "comment";
  }
  return "code";
}

/**
 * Build the coverage model for one invocation. `source` is the full text of the invocation's `file`
 * (the config .py), or `null` when it could not be read — in which case we fall back to the exact
 * executed-line list from the trace (no text, denominator = the executed lines themselves).
 */
export function buildCoverage(source: string | null, inv: TraceInvocation): InvocationCoverage {
  const hits = hitsByLine(inv);
  const defLine = inv.def_line ?? 0;
  const truncated = inv.truncated === true;

  if (source === null || inv.def_line === null) {
    // Source unavailable: we still know EXACTLY which lines ran (events[].line). List them.
    const executedLines = [...hits.keys()].sort((a, b) => a - b);
    const lines: CoverageLine[] = executedLines.map((line) => ({
      line,
      text: "",
      role: "code",
      executable: true,
      executed: true,
      hits: hits.get(line) ?? 0,
    }));
    return {
      kind: inv.kind,
      name: inv.name,
      module: inv.module,
      file: inv.file,
      defLine,
      startLine: executedLines[0] ?? defLine,
      endLine: executedLines[executedLines.length - 1] ?? defLine,
      sourceAvailable: false,
      lines,
      executable: lines.length,
      executed: lines.length,
      pct: 100,
      truncated,
    };
  }

  const srcLines = source.split(/\r\n|\r|\n/);
  const span = functionSpan(srcLines, inv.def_line);
  // A safety net: never hide an executed line the span heuristic missed.
  const maxHit = hits.size ? Math.max(...hits.keys()) - 1 : span.end; // -1 → 0-based
  const end = Math.max(span.end, Math.min(maxHit, srcLines.length - 1));

  const lines: CoverageLine[] = [];
  let executable = 0;
  let executed = 0;
  for (let i = span.start; i <= end; i++) {
    const text = srcLines[i] ?? "";
    const lineNo = i + 1;
    const isHeader = i <= span.header || text.trim().startsWith("@");
    const role = classify(text, isHeader);
    const hitCount = hits.get(lineNo) ?? 0;
    const isExecutable = role === "code";
    const didRun = hitCount > 0;
    if (isExecutable) {
      executable++;
      if (didRun) {
        executed++;
      }
    }
    lines.push({
      line: lineNo,
      text,
      role,
      executable: isExecutable,
      executed: didRun,
      hits: hitCount,
    });
  }

  return {
    kind: inv.kind,
    name: inv.name,
    module: inv.module,
    file: inv.file,
    defLine,
    startLine: span.start + 1,
    endLine: end + 1,
    sourceAvailable: true,
    lines,
    executable,
    executed,
    pct: executable === 0 ? 0 : (executed / executable) * 100,
    truncated,
  };
}

/** Build the profiling model for one invocation: per-line time (summed over hits) + %, hottest first. */
export function buildProfile(source: string | null, inv: TraceInvocation): InvocationProfile {
  const srcLines = source === null ? null : source.split(/\r\n|\r|\n/);
  const seconds = new Map<number, number>();
  const hits = new Map<number, number>();
  let hasTiming = false;
  for (const ev of inv.events) {
    const line = ev.line;
    if (typeof line !== "number") {
      continue;
    }
    hits.set(line, (hits.get(line) ?? 0) + 1);
    if (typeof ev.t === "number" && Number.isFinite(ev.t)) {
      hasTiming = true;
      seconds.set(line, (seconds.get(line) ?? 0) + ev.t);
    }
  }
  let totalSeconds = 0;
  for (const s of seconds.values()) {
    totalSeconds += s;
  }
  const lines: LineProfile[] = [...hits.keys()].map((line) => {
    const s = seconds.get(line) ?? 0;
    return {
      line,
      text: srcLines ? (srcLines[line - 1] ?? "") : "",
      hits: hits.get(line) ?? 0,
      seconds: s,
      pct: totalSeconds > 0 ? (s / totalSeconds) * 100 : 0,
    };
  });
  // Hottest first; ties broken by line number for a stable order.
  lines.sort((a, b) => b.seconds - a.seconds || a.line - b.line);
  return { kind: inv.kind, name: inv.name, hasTiming, totalSeconds, lines };
}

/**
 * Assemble the full Coverage + Profiling detail for one traced message. `readSource(file)` returns the
 * .py text for an invocation's `file` (or `null` when unreadable) — injected so the core stays pure and
 * testable; the Test Bench supplies an fs-backed, cached reader.
 */
export function buildTraceDetail(
  entry: TraceEntry,
  readSource: (file: string | null) => string | null,
): TraceDetail {
  const invocations: InvocationView[] = entry.invocations.map((inv) => {
    const src = readSource(inv.file);
    return {
      kind: inv.kind,
      name: inv.name,
      coverage: buildCoverage(src, inv),
      profile: buildProfile(src, inv),
    };
  });
  let totalSeconds = 0;
  let hasTiming = false;
  for (const v of invocations) {
    totalSeconds += v.profile.totalSeconds;
    hasTiming = hasTiming || v.profile.hasTiming;
  }
  return {
    source: entry.source,
    disposition: entry.disposition,
    traceOk: entry.trace_ok === true,
    hasTiming,
    totalSeconds,
    invocations,
  };
}
