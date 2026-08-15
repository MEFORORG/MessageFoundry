// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// Pure (vscode-free) half of the engine-derived connection catalogue (ADR 0007). The engine now
// describes its own transports — `messagefoundry connection schema --json`
// (messagefoundry/config/connection_schema.py) — instead of the editor carrying a hand-written
// mirror that covered 9 of 11 transports and silently omitted every setting the engine grew.
//
// The typed CLI call lives in connectionSchema.ts, which imports cli.ts and therefore vscode.
// EVERYTHING that can be reasoned about without a subprocess lives HERE — the wire types, the
// version guard, the old-engine translation, the memo cache and the per-direction/per-param
// helpers — so `npm run test:unit` (plain-node mocha, no Extension Host, no Python) can exercise
// it. Same split, and the same reason, as connectionMerge.ts.

import type { Direction } from "./connectionMerge";

/** Re-exported so consumers of the catalogue need only one import for "inbound" | "outbound";
 *  it is deliberately the SAME type connections are written with (connectionMerge.ts). */
export type { Direction };

/** The schema shape this extension knows how to render. The engine bumps its `SCHEMA_VERSION`
 *  when the emitted shape changes in a way a consumer must notice, so a newer engine is refused
 *  loudly (see {@link parseConnectionSchema}) rather than rendering a form it cannot round-trip. */
export const SUPPORTED_SCHEMA_VERSION = 1;

/** Any value that survives the engine's `_jsonable_default` (an exotic default is reported null). */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/**
 * The coarse type tag the form picks a control from (bool → checkbox, int/float → number,
 * table → key/value grid). `"unknown"` is a real emitted value — an annotation the engine could not
 * classify — and must render as free text rather than being treated as a bug.
 */
export type ParamType = "str" | "int" | "float" | "bool" | "table" | "unknown";

/** One authorable setting of one transport, as the engine introspects it from the factory. */
export interface ParamSchema {
  type: ParamType;
  /** The allowed values of a `Literal[...]` annotation → a select; null → a free-text control. */
  choices: JsonValue[] | null;
  default: JsonValue;
  /** No default at all: the factory raises without this setting, in EITHER direction. */
  required: boolean;
  /** The prose says "required" — i.e. mandatory only in `direction` (MLLP outbound `host`). */
  requiredHint: boolean;
  /** May be written as `{env = "KEY"}`. */
  env: boolean;
  /** Credential-bearing: never echo it back into the form or a log. */
  secret: boolean;
  /** The direction this setting applies to; null = both. */
  direction: Direction | null;
  help: string;
  /** Group heading, emitted only on the FIRST param of a group (hence optional). */
  section?: string;
}

/** One transport: its one-line description plus every keyword-only setting its factory accepts. */
export interface TransportSchema {
  doc: string;
  params: Record<string, ParamSchema>;
}

/** The whole catalogue: `connection schema --json` verbatim. */
export interface ConnectionSchema {
  schemaVersion: number;
  transports: Record<string, TransportSchema>;
  /** The loader's per-direction read schema (the connection-level keys, not transport settings). */
  directionKeys: { inbound: string[]; outbound: string[] };
}

/** A param carrying the key it was filed under — what a form renders a row from. */
export interface NamedParam extends ParamSchema {
  name: string;
}

/** What the editor tells a user whose engine is too old to describe itself. */
export const ENGINE_PREDATES_SCHEMA =
  "This MessageFoundry engine predates `connection schema`, so it cannot describe its transports " +
  "and the rich connection editor is unavailable. Update the engine (e.g. " +
  "`pip install -U messagefoundry`) in the interpreter this workspace uses.";

/** What the editor tells a user whose ENGINE is ahead of the extension (the other direction). */
export const SCHEMA_TOO_NEW =
  "Update the MessageFoundry extension to edit connections with this engine.";

/** Argparse's rejection of a verb it does not have: an old engine lacks either the `connection`
 *  command or its `schema` action, and in both cases prints `invalid choice: ...` + a usage blob. */
const ARGPARSE_REJECTION = /invalid choice|unrecognized arguments/i;

/** A JSON.parse failure, as V8 words it. The quoted input fragment is TRUNCATED (`"usage: mes"…`),
 *  so an old engine is recognised by the fragment, not by the full `usage: messagefoundry` line. */
const NOT_JSON = /not valid JSON|JSON at position/i;

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * True when a failed schema fetch means "this engine has no such verb" rather than a real error.
 *
 * cli.ts's parseJsonResult reports the two old-engine shapes differently, so both are classified
 * here: argparse writes the usage blob to STDERR and exits 2 with empty stdout → parseJsonResult
 * throws the stderr text (`invalid choice: 'schema'`); if a build ever writes usage to stdout
 * instead, JSON.parse throws a SyntaxError quoting the start of that blob. Anything else (an
 * `{"error": ...}` body, the untrusted-workspace refusal, a crashed interpreter) is NOT this and
 * must keep its own message.
 */
export function isEnginePredatesSchema(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  if (ARGPARSE_REJECTION.test(message)) {
    return true;
  }
  return (err instanceof SyntaxError || NOT_JSON.test(message)) && /usage/i.test(message);
}

/**
 * The error a caller should see for a failed fetch: the actionable "your engine is too old"
 * sentence instead of a raw argparse usage blob, and every other failure untouched.
 */
export function translateSchemaFailure(err: unknown): Error {
  if (isEnginePredatesSchema(err)) {
    return new Error(ENGINE_PREDATES_SCHEMA);
  }
  return err instanceof Error ? err : new Error(String(err));
}

/**
 * Validate a raw `connection schema` body and type it.
 *
 * The version guard is the whole point: a schema whose version this extension does not understand
 * may have moved or re-meant a field, and a form built from it could not be round-tripped safely —
 * so an absent or newer `schemaVersion` is refused loudly, pointing at the fix (update the
 * extension). An OLDER version is accepted: this extension still reads every shape at or below the
 * one it was written for.
 *
 * Beyond the version, only the TOP-LEVEL shape is checked. Per-param validation is deliberately
 * omitted — the engine is the single source of truth for what a transport accepts (that is the
 * point of deriving the catalogue), so a setting or flag added later must flow through untouched
 * rather than being rejected by a stale mirror in the editor.
 */
export function parseConnectionSchema(raw: unknown): ConnectionSchema {
  const body = asRecord(raw);
  if (!body) {
    throw new Error(
      `The engine did not return a connection schema (got ${raw === null ? "null" : typeof raw}).`,
    );
  }
  const version = body.schemaVersion;
  if (typeof version !== "number" || !Number.isFinite(version)) {
    throw new Error(
      "This MessageFoundry engine returned a connection schema with no schemaVersion; this " +
        `extension understands version ${SUPPORTED_SCHEMA_VERSION}. ${SCHEMA_TOO_NEW}`,
    );
  }
  if (version > SUPPORTED_SCHEMA_VERSION) {
    throw new Error(
      `This MessageFoundry engine speaks connection-schema version ${version}; this extension ` +
        `understands version ${SUPPORTED_SCHEMA_VERSION}. ${SCHEMA_TOO_NEW}`,
    );
  }
  const transports = asRecord(body.transports);
  const directionKeys = asRecord(body.directionKeys);
  if (
    !transports ||
    !directionKeys ||
    !Array.isArray(directionKeys.inbound) ||
    !Array.isArray(directionKeys.outbound)
  ) {
    throw new Error(
      "The engine's connection schema is missing its transports/directionKeys tables — the " +
        "connection editor cannot render a catalogue it cannot read.",
    );
  }
  return body as unknown as ConnectionSchema;
}

/** How {@link loadConnectionSchema} obtains a raw body — the seam that keeps this module (and its
 *  tests) free of both vscode and Python. connectionSchema.ts passes the real CLI call. */
export type ConnectionSchemaFetcher = (cwd?: string) => Promise<unknown>;

/**
 * Module-level memo of the catalogue, keyed by the cwd the CLI ran in.
 *
 * The catalogue describes the ENGINE, not a workspace, and the engine binary cannot change while
 * the extension host lives — but WHICH engine answers does depend on cwd: `python -m messagefoundry`
 * puts the cwd first on sys.path, so a folder containing a `messagefoundry/` package shadows the
 * installed one. Keying by cwd keeps a source checkout and an installed engine from sharing an
 * answer. {@link resetConnectionSchemaCache} is the escape hatch for the cases that DO change the
 * engine under us: a changed interpreter setting, or an engine-changed event.
 */
const cache = new Map<string, Promise<ConnectionSchema>>();

/** Drop every memoised catalogue (tests; an engine/interpreter change). */
export function resetConnectionSchemaCache(): void {
  cache.clear();
}

/**
 * The memoised catalogue for `cwd`. Concurrent callers share ONE in-flight fetch (the promise is
 * cached, not its result), so the editor opening twice before the first answer lands still shells
 * out once.
 *
 * A FAILED fetch is not memoised: a transient failure (an engine mid-upgrade, a workspace not yet
 * trusted) must not poison the catalogue for the rest of the session, so the slot is dropped and
 * the next caller retries.
 */
export function loadConnectionSchema(
  fetch: ConnectionSchemaFetcher,
  cwd?: string,
): Promise<ConnectionSchema> {
  const key = cwd ?? "";
  const hit = cache.get(key);
  if (hit) {
    return hit;
  }
  const pending = fetchAndParse(fetch, cwd);
  cache.set(key, pending);
  pending.catch(() => {
    if (cache.get(key) === pending) {
      cache.delete(key);
    }
  });
  return pending;
}

async function fetchAndParse(
  fetch: ConnectionSchemaFetcher,
  cwd: string | undefined,
): Promise<ConnectionSchema> {
  let raw: unknown;
  try {
    raw = await fetch(cwd);
  } catch (err) {
    throw translateSchemaFailure(err);
  }
  return parseConnectionSchema(raw);
}

/**
 * The settings of one transport that apply in `direction`, each carrying its key.
 *
 * A param declares the direction it belongs to (`null` = both), and getting this wrong is
 * user-visible in both directions: MLLP `host` is outbound-only and the engine REJECTS it on an
 * inbound, while the inbound-only TLS server-cert fields are meaningless outbound.
 *
 * Order is the engine's emission order (the factory's declaration order), NOT alphabetical: the
 * optional `section` heading is emitted on the first param of a group and only groups the params
 * that FOLLOW it, so re-sorting would orphan every heading. Object key order is insertion order
 * here — every param name is a Python identifier, so none is integer-like.
 */
export function paramsForDirection(transport: TransportSchema, direction: Direction): NamedParam[] {
  return Object.entries(transport.params ?? {})
    .filter(([, param]) => param.direction === null || param.direction === direction)
    .map(([name, param]) => ({ ...param, name }));
}

/** Credential-bearing → render masked, never echo the current value back into the webview. A body
 *  that omits the flag reads false, matching a schema-less (pre-catalogue) field. */
export function isSecret(param: ParamSchema): boolean {
  return param.secret === true;
}

/** May be authored as `{env = "KEY"}` → offer the "from environment" affordance. */
export function acceptsEnv(param: ParamSchema): boolean {
  return param.env === true;
}
