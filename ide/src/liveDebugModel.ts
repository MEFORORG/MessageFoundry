// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The pure half of live-debug (#92): the traced dry-run's schema, and the folds that turn one run into
// CodeLens summaries. No `vscode` import, so the unit suite (mocha, no Extension Host) runs these
// directly; liveDebug.ts re-exports every name here, so its importers are unchanged.
import type { ElementKind } from "./editorToolbar";

/**
 * The subset of a traced `dryrun` entry this lane reads for the v1 CodeLens summary — deliberately
 * minimal: only routing/disposition fields, NOT any body. Derived from a {@link LiveTraceEntry} via
 * {@link rowsFromTrace}, so the same fold ({@link summarize}) drives the summaries as before.
 */
export interface LiveDryRunRow {
  inbound: string;
  disposition: string;
  handlers: string[];
  deliveries: { to: string }[];
  error: string | null;
}

// --- traced dry-run schema (messagefoundry/pipeline/dryrun_trace.py, ADR 0072) -------------------
// A JSON-safe captured value. Without --show-phi the CLI collapses every value to the string
// "REDACTED"; with it, scalars pass through (strings/numbers/bools/null, length-capped upstream).
export type TraceValue = string | number | boolean | null;

/** One executed source line: the locals it (re)bound and the `msg[...]`/`msg.set(...)` writes it made. */
export interface TraceEvent {
  line: number; // 1-based (Python line number)
  event: string; // always "line"
  assigned?: Record<string, TraceValue>;
  writes?: { path: string; value: TraceValue }[];
}

/** A live db_lookup/fhir_lookup that a pure preview cannot evaluate (raised + re-raised by the tracer). */
export interface TraceAnnotation {
  line: number | null; // 1-based Handler line the call was made on (or null → fall back to def_line)
  kind: string; // "live_lookup_skipped"
  call: string; // "db_lookup" | "fhir_lookup"
}

/** One Router/Handler invocation's execution trace. */
export interface TraceInvocation {
  kind: string; // "router" | "handler"
  name: string;
  module: string | null;
  file: string | null; // absolute path of the module that defines the fn
  def_line: number | null; // 1-based
  events: TraceEvent[];
  disposition: string;
  sends: { outbound: string }[];
  routed_to: string[];
  annotations: TraceAnnotation[];
  truncated?: boolean;
}

/** One traced message (one array element of `dryrun --trace json`). */
export interface LiveTraceEntry {
  source?: string;
  path?: string;
  inbound: string;
  disposition: string;
  handlers: string[];
  sends: { outbound: string }[];
  error: string | null;
  trace_ok?: boolean;
  invocations: TraceInvocation[];
}

/** Project the v1 CodeLens fields out of the richer trace entries (the summary path is unchanged). */
export function rowsFromTrace(entries: LiveTraceEntry[]): LiveDryRunRow[] {
  return entries.map((e) => ({
    inbound: e.inbound,
    disposition: e.disposition,
    handlers: e.handlers,
    deliveries: e.sends.map((s) => ({ to: s.outbound })),
    error: e.error,
  }));
}

/** A config element located by line, with the name from its `("...")` argument (router/handler/inbound). */
export interface NamedElement {
  line: number; // 0-based
  kind: ElementKind;
  name: string | null;
}

/** A rendered summary, as plain data (line + label). The provider maps these to `vscode.CodeLens`. */
export interface LiveLens {
  line: number; // 0-based
  title: string;
  tooltip?: string;
}

/** The aggregate of one dry-run over a (possibly multi-message) sample — everything the lenses need. */
export interface LiveSummary {
  messageCount: number;
  handlersUnion: string[]; // handler names selected across the run, first-seen order, de-duped
  dispositions: [string, number][]; // disposition → count, first-seen order
  totalSends: number; // total deliveries across every message
  soleHandler: string | null; // the one handler name IFF exactly one distinct handler ran (else null)
  errors: string[]; // distinct per-message error strings
  errorCount: number; // messages that carried an error (not de-duped), the only error fact a masked run shows
}

/**
 * Fold a run's rows into a {@link LiveSummary}. `soleHandler` is set only when the entire run selected
 * exactly one distinct handler — the sole case in which `totalSends` is unambiguously that handler's,
 * given the CLI flattens handler→delivery attribution. Pure; unit-testable.
 */
export function summarize(rows: LiveDryRunRow[]): LiveSummary {
  const handlersUnion: string[] = [];
  const seen = new Set<string>();
  const dispCounts = new Map<string, number>();
  let totalSends = 0;
  const errors: string[] = [];
  for (const r of rows) {
    for (const h of r.handlers) {
      if (!seen.has(h)) {
        seen.add(h);
        handlersUnion.push(h);
      }
    }
    dispCounts.set(r.disposition, (dispCounts.get(r.disposition) ?? 0) + 1);
    totalSends += r.deliveries.length;
    if (r.error) {
      errors.push(r.error);
    }
  }
  return {
    messageCount: rows.length,
    handlersUnion,
    dispositions: [...dispCounts.entries()],
    totalSends,
    soleHandler: seen.size === 1 ? handlersUnion[0] : null,
    errors: [...new Set(errors)],
    errorCount: errors.length,
  };
}

/**
 * The inbound lens's tooltip. On a masked run it states only how many messages failed, and that a
 * reveal is available: the CLI's masked error is scrubbed, not removed, so it can still carry a field
 * value, and hovering a lens is not an act aimed at reading one (ASVS 14.2.6, vault BACKLOG #1187,
 * ground d1). The text itself shows only on a run the user revealed.
 */
export function inboundTooltip(summary: LiveSummary, label: string, revealed: boolean): string {
  if (summary.errorCount === 0) {
    return `Live dry-run of ${label || "the selected sample"} (${summary.messageCount} message(s)).`;
  }
  if (revealed) {
    return `Errors: ${summary.errors.join("; ")}`;
  }
  const n = summary.errorCount;
  return (
    `${n} of ${summary.messageCount} message(s) failed. The error text is hidden because it can ` +
    "quote message data. Run *MessageFoundry: Reveal Values for One Run* to read one message's error."
  );
}

/**
 * Build the CodeLens summaries for one config document's elements against a run summary. Attaches the
 * disposition to inbound() lines, the routing decision to `@router` lines, and a Send count to a
 * `@handler` line ONLY when it is the run's sole handler (unambiguous). `revealed` says whether the run
 * was one the user asked to reveal; it decides whether the per-message error text may show. Pure.
 */
export function buildLiveLenses(
  elements: NamedElement[],
  summary: LiveSummary,
  label: string,
  revealed: boolean,
): LiveLens[] {
  const out: LiveLens[] = [];
  const dispText = summary.dispositions.length
    ? summary.dispositions
        .map(([d, n]) => (summary.messageCount === 1 ? d : `${n} ${d}`))
        .join(" · ")
    : "no messages";
  for (const el of elements) {
    if (el.kind === "inbound") {
      const prefix = label ? `${label}: ` : "";
      out.push({
        line: el.line,
        title: `$(pulse) ${prefix}${dispText}`,
        tooltip: inboundTooltip(summary, label, revealed),
      });
    } else if (el.kind === "router") {
      const routed = summary.handlersUnion.length
        ? `[${summary.handlersUnion.join(", ")}]`
        : "(nowhere)";
      out.push({
        line: el.line,
        title: `$(arrow-right) routed → ${routed}`,
        tooltip: "Handlers this router selected across the sample run (from dryrun `handlers`).",
      });
    } else if (el.kind === "handler" && summary.soleHandler !== null && el.name === summary.soleHandler) {
      const n = summary.totalSends;
      out.push({
        line: el.line,
        title: `$(arrow-small-right) ${n} Send${n === 1 ? "" : "s"}`,
        tooltip:
          "Send count is attributable here because exactly one handler ran this sample. v1 flattens " +
          "handler→delivery attribution, so per-handler counts for a multi-handler module are v2.",
      });
    }
  }
  return out;
}
