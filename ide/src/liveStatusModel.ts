// Pure (vscode-free) reduction of the engine's `GET /connections` payload into the RuntimeMap the
// CONNECTIONS tree renders (ADR 0091 "live decorations"). The endpoint emits one "source" row per
// inbound connection and one "destination" row per (inbound → outbound) EDGE that has carried
// traffic (api/models.py ConnectionRow) — so destination rows must be aggregated per outbound:
// counts sum across edges; the status collapses to the worst-severity one, so a failed lane is
// never hidden behind a healthy sibling. Node-side unit-tested (no Extension Host).

import { runtimeKey, type RuntimeInfo, type RuntimeMap } from "./graphModel";

/** The subset of the engine's ConnectionRow (api/models.py) the IDE consumes. Everything else in
 *  the payload (peers, ports, backlog, shard ownership …) is deliberately ignored — the tree shows
 *  status words + counts only, never message content (PHI rule). */
export interface ConnectionRowLite {
  role: string; // "source" | "destination"
  channel_id: string; // the inbound connection name (both roles)
  destination?: string | null; // the outbound connection name (destination rows only)
  status: string; // running | stopping | stopped | failed | filtered | draining
  read?: number | null; // source rows: inbound received
  written?: number | null; // destination rows: delivered
  errored?: number | null; // source: inbound errors; destination: dead-lettered
}

/** Engine status words, least → most severe. An unknown word (a future engine) ranks least severe
 *  so it can never mask a known-bad one; it still renders verbatim when it's all there is. */
const SEVERITY = ["running", "draining", "stopping", "stopped", "filtered", "failed"];

function worse(a: string, b: string): string {
  return SEVERITY.indexOf(b) > SEVERITY.indexOf(a) ? b : a;
}

function addCounts(a: number | undefined, b: number | null | undefined): number | undefined {
  if (typeof b !== "number") {
    return a;
  }
  return (a ?? 0) + b;
}

/**
 * Fold the `/connections` rows into connKey → {status, count, errored}. Source rows map 1:1 to
 * inbound elements; destination rows aggregate per outbound element (see the header). Rows with a
 * missing join key are skipped — a malformed payload degrades to fewer decorations, never a throw.
 */
export function buildRuntimeMap(rows: ConnectionRowLite[]): RuntimeMap {
  const map = new Map<string, RuntimeInfo>();
  for (const r of rows) {
    if (r.role === "source" && r.channel_id) {
      map.set(runtimeKey("inbound", r.channel_id), {
        status: r.status,
        count: typeof r.read === "number" ? r.read : undefined,
        errored: typeof r.errored === "number" ? r.errored : undefined,
      });
    } else if (r.role === "destination" && r.destination) {
      const key = runtimeKey("outbound", r.destination);
      const prev = map.get(key);
      map.set(key, {
        status: prev ? worse(prev.status, r.status) : r.status,
        count: addCounts(prev?.count, r.written),
        errored: addCounts(prev?.errored, r.errored),
      });
    }
  }
  return map;
}
