// Pure (vscode-free) target resolution for Stage → Promote. Separated from promote.ts so the
// "which engine URL does (environment, shard-pick) resolve to?" decision is unit-testable without
// launching the Extension Host.
import { shardsOf, type EnvironmentTarget, type Shard } from "./cli";

/** The concrete engine instance a promote will deploy to: a display name + the URL to POST to. */
export interface ResolvedTarget {
  /** Display name, e.g. "PROD" or "PROD / shard-2" when a shard was chosen within an environment. */
  name: string;
  /** Engine API URL the dry-run + apply POST to. */
  url: string;
}

/**
 * Decide whether the user must be asked to choose a shard, and if not, what URL to use.
 *
 * Rules (additive, backward-compatible with shard-less environments):
 *  - 0 shards → use the environment's own `url` (today's behavior, no prompt).
 *  - 1 shard  → auto-select that single shard's url (no prompt; a lone shard isn't a choice).
 *  - ≥2 shards → the caller must prompt; this returns the shard list so it can.
 *
 * Pure: no vscode API, no side effects. The caller (promote.ts) runs the QuickPick when
 * `needsPick` is true and then calls {@link resolveTargetUrl} with the chosen shard.
 */
export function planTargetResolution(env: EnvironmentTarget): {
  /** True iff the caller must show a shard QuickPick (≥2 shards). */
  needsPick: boolean;
  /** Present iff !needsPick — the target to deploy to with no further prompt. */
  resolved?: ResolvedTarget;
  /** The shards to offer when needsPick is true (the ≥2-shard list). */
  shards: Shard[];
} {
  const shards = shardsOf(env);
  if (shards.length === 0) {
    return { needsPick: false, resolved: { name: env.name, url: env.url }, shards };
  }
  if (shards.length === 1) {
    return { needsPick: false, resolved: shardTarget(env, shards[0]), shards };
  }
  return { needsPick: true, shards };
}

/**
 * The final ResolvedTarget given an environment and an OPTIONAL chosen shard. A pure folding of
 * `planTargetResolution` + a pick: with no shard (or a shard-less environment) it is the environment
 * url; with a shard it is that shard's url and a "ENV / shard" label. Used both for the auto-selected
 * single-shard case and after the user picks from a multi-shard QuickPick.
 */
export function resolveTargetUrl(env: EnvironmentTarget, shard?: Shard): ResolvedTarget {
  return shard ? shardTarget(env, shard) : { name: env.name, url: env.url };
}

function shardTarget(env: EnvironmentTarget, shard: Shard): ResolvedTarget {
  return { name: `${env.name} / ${shard.name}`, url: shard.url };
}
