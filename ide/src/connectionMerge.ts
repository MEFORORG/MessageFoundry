// Pure (vscode-free) save-merge model behind BOTH connections.toml writers (#234 Phase 3). The
// webview form (connectionEditor.ts / configEditors.ts) posts ONLY the fields it renders, but the
// CLI's `connection upsert` is a FULL REPLACE of the named table (ADR 0007 — merge-on-absent was
// evaluated under #234 and rejected server-side), so upserting the bare post silently deleted every
// non-rendered key (schedule, shard, source_ip_allowlist, …). The fix: merge the posted form over
// the full object a save-time fresh `connection list` returns, HERE, where it can be unit-tested
// node-side (`npm run test:unit` is plain-node mocha — this module must never import vscode).

/** The connection object `connection upsert --data <json>` consumes and `connection list` returns
 *  (ADR 0007). Lives in this pure module (not connectionEditor.ts, which imports vscode) so the
 *  mocha-run tests can import it; connectionEditor.ts re-exports it for its existing consumers. */
export interface ConnObj {
  direction: "inbound" | "outbound";
  name: string;
  transport: string;
  router?: string;
  settings?: Record<string, unknown>;
  ack_mode?: string;
  strict?: boolean;
  ordering?: string;
  retry?: Record<string, unknown>;
  [k: string]: unknown;
}

export type Direction = ConnObj["direction"];

/**
 * The fields the form's `build()` (connectionEditor.ts) actually renders and posts, per direction —
 * the ONLY keys the posted object is authoritative for. Verified against `build()`:
 * both directions always post direction/name/transport (identity fields, so the posted value simply
 * overlays) plus `settings` (every row is rendered, so the posted table wins wholesale — no rows
 * posted = the key is deleted); inbound additionally posts `router` / `ack_mode` / `strict`;
 * outbound posts `ordering` and `retry` — but the form renders only `retry.max_attempts`, so
 * `retry` merges FIELD-WISE (see mergeFormIntoInitial), not strip-wholesale like the rest.
 * For every listed key, absence from the post means "the user cleared it" → the key is DELETED
 * from the merged object (absent = the read schema's default).
 */
export const RENDERED_FIELDS: Record<Direction, readonly string[]> = {
  inbound: ["settings", "router", "ack_mode", "strict"],
  outbound: ["settings", "ordering", "retry"],
};

/**
 * Mirror of the loader's per-direction read schema (`_INBOUND_KEYS` / `_OUTBOUND_KEYS` in
 * messagefoundry/config/connections_file.py) — consulted ONLY on the clone direction-flip path, to
 * decide which carried keys are legal in the posted direction's table. The same-direction merge
 * deliberately does NOT intersect against this mirror, so a key added to the read schema later can
 * never be silently dropped by an ordinary edit even if this copy drifts; a drifted flip-carry is
 * caught fail-loud by the CLI's `_validate_input` (the write never lands), not silently written.
 */
export const READ_SCHEMA_KEYS: Record<Direction, ReadonlySet<string>> = {
  inbound: new Set([
    "name",
    "transport",
    "settings",
    "router",
    "ack_mode",
    "ack_after",
    "strict",
    "hl7_version",
    "strict_timeout_s",
    "content_type",
    "metadata",
    "bind_address",
    "source_ip_allowlist",
    "capture_ack",
    "capture_connection_errors",
    "messages_days",
    "prune_documents_after",
    "prune_documents_min_bytes",
    "stream_threshold_bytes",
    "max_message_bytes",
    "priority",
    "shard",
    "schedule",
    "auto_start",
    "deployed",
  ]),
  outbound: new Set([
    "name",
    "transport",
    "settings",
    "retry",
    "ordering",
    "internal_error",
    "buildup",
    "stall",
    "batch",
    "simulate",
    "dead_letter_days",
    "priority",
    "metadata",
    "schedule",
    "auto_start",
    "deployed",
  ]),
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * Merge the posted form object over the full connection it was editing, producing the object to
 * upsert (a full replace server-side).
 *
 * - No `initial` (a brand-new connection, or the merge source vanished between open and save):
 *   the post IS the object.
 * - Same direction: result = `{initial minus RENDERED_FIELDS[direction]}` overlaid with the post —
 *   non-rendered keys (schedule, shard, allowlist, …) survive untouched; a rendered key absent from
 *   the post is deleted (cleared select / unchecked strict → the read-schema default). `retry`
 *   merges field-wise: the posted `max_attempts` sets-or-deletes over `initial.retry`'s other
 *   RetryPolicy fields (backoff_*), and an emptied retry table drops the key entirely.
 * - Direction flip (clone keeps direction editable): a naive overlay would carry
 *   direction-inapplicable keys (`router`/`ack_mode`/`shard`/…) into the other direction's table
 *   and the loader's `_reject_unknown` / the writer's `_validate_input` would fail EVERY
 *   clone-flip save. Instead, carried keys are intersected with the POSTED direction's read-schema
 *   set (direction-neutral keys — schedule/priority/metadata/auto_start/deployed — survive the
 *   flip; inapplicable ones are dropped), then the post overlays.
 */
export function mergeFormIntoInitial(initial: ConnObj | undefined, posted: ConnObj): ConnObj {
  if (!initial) {
    return { ...posted };
  }

  if (posted.direction !== initial.direction) {
    // Clone direction-flip: carry only direction-neutral, non-form-owned keys.
    const merged: ConnObj = { ...posted };
    const formOwned = new Set<string>([...RENDERED_FIELDS.inbound, ...RENDERED_FIELDS.outbound]);
    for (const [key, value] of Object.entries(initial)) {
      if (key === "direction" || key === "name" || formOwned.has(key)) {
        continue;
      }
      if (!READ_SCHEMA_KEYS[posted.direction].has(key)) {
        continue; // inapplicable in the posted direction's table — dropping it is the point
      }
      if (!(key in posted)) {
        merged[key] = value;
      }
    }
    return merged;
  }

  const direction = posted.direction;
  const merged: ConnObj = { ...initial };
  for (const key of RENDERED_FIELDS[direction]) {
    delete merged[key]; // absent-from-post = deleted; present-in-post re-set by the overlay below
  }
  for (const [key, value] of Object.entries(posted)) {
    if (key === "retry") {
      continue; // field-wise below — a raw overlay would clobber initial.retry's backoff fields
    }
    merged[key] = value;
  }
  if (direction === "outbound") {
    // The form renders exactly retry.max_attempts: posted max_attempts sets-or-deletes over the
    // initial retry table's OTHER RetryPolicy fields (backoff_seconds/…), which the form never shows
    // and must never destroy. An emptied table drops the key (absent = read-schema default).
    const carried = { ...(asRecord(initial.retry) ?? {}) };
    delete carried.max_attempts;
    const retry = { ...carried, ...(asRecord(posted.retry) ?? {}) };
    if (Object.keys(retry).length > 0) {
      merged.retry = retry;
    } else {
      delete merged.retry;
    }
  }
  return merged;
}

/**
 * The existing connection a save under `postedName` would silently destroy, or undefined when the
 * save is safe. `editingName` is the connection an in-place edit is allowed to replace (the form
 * locks the name input in edit mode); create and clone pass undefined — a clone is a brand-new
 * connection, so colliding with ANY existing name (including its own source) is refused.
 */
export function findNameCollision(
  existingNames: readonly string[],
  postedName: string,
  editingName?: string,
): string | undefined {
  if (postedName === editingName) {
    return undefined;
  }
  return existingNames.find((name) => name === postedName);
}

/** The one refusal message both writers surface for a name collision (#234 overwrite hole). */
export function nameCollisionError(name: string): string {
  return (
    `A connection named "${name}" already exists in connections.toml — saving would silently ` +
    `replace it. Choose a different name, or edit "${name}" itself.`
  );
}

export interface SavePlan {
  /** The object to `connection upsert` (the merged full object). */
  conn: ConnObj;
  /** Set → the save must be REFUSED: it would silently overwrite this existing connection. */
  collision?: string;
}

/**
 * The ONE save policy both writers (connectionEditor.ts save() and configEditors.ts's save handler)
 * apply over a save-time FRESH `connection list` (#234 merge-source policy — no cached copy, so an
 * external edit between open and save is never resurrected):
 *
 * 1. collision gate — a create/clone whose name matches an existing connection is refused;
 * 2. merge — the post is merged over the `mergeFrom` entry (the connection the form was opened
 *    from: the edited name, or the clone source), preserving every non-rendered key. No
 *    `mergeFrom`, or the entry vanished externally: the post stands alone (there is nothing left
 *    to preserve).
 */
export function planSave(
  entries: readonly ConnObj[],
  posted: ConnObj,
  opts: { mergeFrom?: string; editingName?: string },
): SavePlan {
  const collision = findNameCollision(
    entries.map((entry) => entry.name),
    posted.name,
    opts.editingName,
  );
  if (collision !== undefined) {
    return { conn: posted, collision };
  }
  const initial =
    opts.mergeFrom !== undefined
      ? entries.find((entry) => entry.name === opts.mergeFrom)
      : undefined;
  return { conn: mergeFormIntoInitial(initial, posted) };
}
