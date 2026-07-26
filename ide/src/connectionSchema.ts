// Typed wrapper over `messagefoundry connection schema --json` — the transport catalogue the
// connection editor renders its form from (ADR 0007). The engine introspects its own factories
// (messagefoundry/config/connection_schema.py), so the editor shows whatever the INSTALLED engine
// supports instead of a hand-maintained TypeScript mirror that could only go stale.
//
// This module is the vscode-facing half (it imports cli.ts, which imports vscode); the types, the
// version guard, the old-engine translation, the memo cache and the pure helpers all live in
// connectionSchemaModel.ts so `npm run test:unit` can exercise them node-side. Consumers can import
// everything from here.

import { runJson } from "./cli";
import { type ConnectionSchema, loadConnectionSchema } from "./connectionSchemaModel";

export {
  ENGINE_PREDATES_SCHEMA,
  SUPPORTED_SCHEMA_VERSION,
  acceptsEnv,
  isSecret,
  paramsForDirection,
  resetConnectionSchemaCache,
} from "./connectionSchemaModel";
export type {
  ConnectionSchema,
  Direction,
  JsonValue,
  NamedParam,
  ParamSchema,
  ParamType,
  TransportSchema,
} from "./connectionSchemaModel";

/**
 * The engine's connection catalogue, memoised per cwd (see loadConnectionSchema) — the editor opens
 * often and the catalogue cannot change while the engine binary is fixed; call
 * `resetConnectionSchemaCache()` when it might have (a changed interpreter, an engine upgrade).
 *
 * Deliberately NO `--config`: the verb is introspection-only and takes no config directory (it
 * describes the ENGINE, not a workspace), so passing one would be wrong — it would also make a
 * schema fetch fail on an unrelated broken module in the user's config dir and trip the Windows
 * config-source trust check, on every editor open.
 *
 * Throws with an actionable message when the installed engine is too old to have the verb, or newer
 * than this extension understands.
 */
export async function connectionSchema(cwd?: string): Promise<ConnectionSchema> {
  const fetch = (dir?: string) => runJson<ConnectionSchema>(["connection", "schema"], dir);
  return loadConnectionSchema(fetch, cwd);
}
