// Pure (vscode-free) logic for the engine status-bar item (#221c). Separated from statusBar.ts so the
// "which target does (engineUrl, environments) point at?", "is a probe outcome reachable?" and "what
// text/tooltip does the item show?" decisions are unit-testable without launching the Extension Host
// (mirrors promoteTarget.ts / engineTarget.ts). No vscode, no I/O — data in, data out.

/** A configured named environment (a subset of cli.ts's EnvironmentTarget — kept local so this module
 *  stays vscode-free and does not import cli.ts, which pulls in vscode). */
export interface StatusEnvironment {
  name: string;
  url: string;
}

/** The single engine instance the status bar reflects: a short display name + the URL it probes. */
export interface EngineStatusTarget {
  name: string; // e.g. "127.0.0.1:8765", "PROD", or "PROD (+2)"
  url: string; // the URL the reachability probe hits
  /** All configured targets (for the tooltip); one entry for the engineUrl fallback. */
  all: StatusEnvironment[];
}

/** Reachability of the probed target. `unknown` = not yet probed (or a probe is in flight). */
export type Reachability = "reachable" | "unreachable" | "unknown";

/** The outcome of one reachability probe, as a discriminated union the status bar maps HTTP results to.
 *  An HTTP response of ANY status (even 401/404) means the engine answered → reachable; only a
 *  transport failure (connection refused, DNS, reset, timeout) is unreachable. */
export type ProbeOutcome =
  | { kind: "ok" } // 2xx
  | { kind: "httpError"; status: number } // engine answered with a non-2xx (still up)
  | { kind: "networkError" }; // no HTTP response at all

/**
 * Short host:port label for a URL (the fallback target's display name). Falls back to the raw string
 * when it does not parse as a URL, so a mistyped setting still shows *something* rather than throwing.
 */
export function hostLabel(url: string): string {
  try {
    const u = new URL(url);
    return u.port ? `${u.hostname}:${u.port}` : u.hostname;
  } catch {
    return url;
  }
}

/**
 * Resolve the status-bar target from the promote settings (engineUrl + named environments), mirroring
 * how promote.ts picks a default:
 *  - no environments → the single `engineUrl` (labelled host:port);
 *  - exactly one environment → that environment;
 *  - several environments → the first is the primary probe target, labelled "<name> (+N)" so the item
 *    stays compact; the tooltip (via `all`) lists them all.
 */
export function resolveEngineStatusTarget(
  engineUrl: string,
  environments: StatusEnvironment[],
): EngineStatusTarget {
  const envs = environments.filter((e) => e && typeof e.name === "string" && typeof e.url === "string");
  if (envs.length === 0) {
    return { name: hostLabel(engineUrl), url: engineUrl, all: [{ name: "engine", url: engineUrl }] };
  }
  if (envs.length === 1) {
    return { name: envs[0].name, url: envs[0].url, all: envs };
  }
  const extra = envs.length - 1;
  return { name: `${envs[0].name} (+${extra})`, url: envs[0].url, all: envs };
}

/** Fold a probe outcome into a reachability verdict. An HTTP answer (any status) means the engine is up. */
export function classifyProbe(outcome: ProbeOutcome): Reachability {
  switch (outcome.kind) {
    case "ok":
    case "httpError":
      return "reachable";
    case "networkError":
      return "unreachable";
  }
}

/** The rendered status item: the codicon-prefixed text and the hover tooltip. Pure so it is testable. */
export interface EngineStatusText {
  text: string;
  tooltip: string;
}

/**
 * Render the status item text + tooltip for a target and its current reachability. The icon encodes
 * state at a glance: a filled dot when reachable, a disconnect glyph when not, a hollow dot while
 * unknown. The tooltip always names the probed URL and lists every configured target.
 */
export function formatEngineStatus(
  target: EngineStatusTarget,
  reachability: Reachability,
): EngineStatusText {
  const icon =
    reachability === "reachable"
      ? "$(pass-filled)"
      : reachability === "unreachable"
        ? "$(debug-disconnect)"
        : "$(circle-outline)";
  const text = `${icon} MEFOR: ${target.name}`;
  const state =
    reachability === "reachable"
      ? "reachable"
      : reachability === "unreachable"
        ? "not reachable — start it (Console or `messagefoundry serve`)"
        : "checking…";
  const lines = [
    `MessageFoundry engine — ${state}.`,
    `Target: ${target.url}`,
  ];
  if (target.all.length > 1) {
    lines.push("", "Configured environments:");
    for (const e of target.all) {
      lines.push(`  • ${e.name} — ${e.url}`);
    }
  }
  lines.push("", "Click for engine actions.");
  return { text, tooltip: lines.join("\n") };
}
