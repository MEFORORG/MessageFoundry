// Pure (vscode-free) logic for the engine status-bar item — the IDE's window onto the engine it
// promotes to. Separated from statusBar.ts so every decision here ("what does this probe outcome
// MEAN?", "what may the user do about it?", "what does the item say?") is unit-testable node-side
// without launching an Extension Host (mirrors promoteTarget.ts / engineTarget.ts). No vscode, no I/O.
//
// THE RULE THIS MODULE EXISTS TO ENFORCE (ADR — engine-link doctor):
//   Green means "the IDE can USE this engine", not "a socket answered".
// The previous model folded EVERY http answer — including a 401 — into "reachable" and painted it
// green, so an engine the IDE had no session with looked perfectly healthy. `GET /health` is tokenless
// but discloses `version` ONLY to an authenticated caller (api/app.py: WP-L3-07 / ASVS 13.4.6), so the
// body we were already fetching and throwing away is exactly the evidence we needed.
//
// Two engine facts constrain everything below; both are load-bearing, neither is obvious:
//   1. `optional_identity` applies NO RBAC and NO must-change gate. So a `version` in /health proves
//      only that *a* session exists — NOT that it can do anything. Hence `unverified`, never `ok`.
//      Only a non-exempt PROTECTED route can earn a green check (see DEEP_PROBE_ROUTE).
//   2. The periodic poll MUST stay tokenless: `identity_for_token(..., activity=True)` refreshes the
//      session's idle clock, so a bearer on a 15s timer from an open editor would make the engine's
//      30-minute idle timeout unreachable forever (CWE-613). The cheap poll may only ever prove the
//      NEGATIVE. "Usable" is earned by a user-initiated probe, and it decays.

/** A configured named environment (a subset of cli.ts's EnvironmentTarget — kept local so this module
 *  stays vscode-free and does not import cli.ts, which pulls in vscode). */
export interface StatusEnvironment {
  name: string;
  url: string;
}

/** The single engine instance the status bar reflects: a short display name + the URL it probes. */
export interface EngineStatusTarget {
  name: string; // e.g. "127.0.0.1:8765", "PROD", or "PROD (+2)"
  url: string; // the URL the probes hit
  /** All configured targets (for the tooltip); one entry for the engineUrl fallback. */
  all: StatusEnvironment[];
}

/**
 * The outcome of one probe, as a discriminated union the shell maps HTTP results to. Unlike the
 * previous version this CARRIES THE EVIDENCE: the parsed body of a 2xx, the `detail` string of a
 * non-2xx (FastAPI's, already extracted by engineClient), and the errno of a transport failure.
 * Discarding those three things is what left the old status bar unable to say anything true.
 */
export type ProbeOutcome =
  | { kind: "ok"; body: unknown }
  | { kind: "httpError"; status: number; detail: string }
  | { kind: "networkError"; code?: string };

/**
 * What the IDE knows about its link to the engine. A closed union — every state names a DIFFERENT
 * fault with a DIFFERENT remedy, which is the whole point (the old model had one bucket, "reachable",
 * covering four of these).
 *
 *  - `unknown`      — not probed yet / a probe is in flight
 *  - `unreachable`  — no HTTP answer at all (refused / DNS / hung / TLS); `code` says which
 *  - `foreign`      — something answered, but it is not a MessageFoundry engine (wrong port?)
 *  - `signedOut`    — the engine is up, auth is on, and the IDE has NO session with it  ← the default!
 *  - `unverified`   — a session exists, but it has not been proven able to do anything
 *  - `blocked`      — authenticated and REFUSED (must-change password / missing permission / MFA / step-up)
 *  - `drifted`      — usable, but the engine's loaded config differs from what is on disk
 *  - `ok`           — verified usable, within the freshness window
 */
export type LinkState =
  | "unknown"
  | "unreachable"
  | "foreign"
  | "signedOut"
  | "unverified"
  | "blocked"
  | "drifted"
  | "ok";

/** Why an authenticated caller was refused. Sub-classified from the engine's 403 `detail` string,
 *  which is stable and already extracted by engineClient's httpErrorMessage — so classification is
 *  free and needs no new response headers. */
export type BlockedReason = "mustChangePassword" | "permission" | "stepUp" | "mfa" | "forbidden";

/**
 * The complete state of the IDE↔engine LINK. **This type is the boundary** (ADR — engine-link doctor):
 * the IDE renders and repairs the LINK, it never renders the engine's WORKLOAD. There is deliberately
 * no field here for a connection, a message, a queue depth, a count or a rate — and
 * {@link ENGINE_LINK_FIELDS} is asserted frozen in CI, so adding one is a red test, not a quiet diff.
 * Anything operational deep-links to the web console at `<url>/ui`, which is the sole operator console.
 */
export interface EngineLink {
  state: LinkState;
  target: EngineStatusTarget;
  /** Transport errno for `unreachable` (ECONNREFUSED / ENOTFOUND / MF_TIMEOUT / …). */
  code?: string;
  /** Human-readable, already-classified explanation of a non-ok state. Shown verbatim. */
  reason?: string;
  /** Sub-classification of `blocked`, which decides WHICH remedy is offered. */
  blocked?: BlockedReason;
  /** The engine's build version — only ever known to an authenticated caller. */
  version?: string;
  /** The engine's active environment name (from the tokenless /ai/policy), when known. */
  environment?: string;
  /** ms epoch of the last completed probe of any depth. */
  checkedAt?: number;
  /** ms epoch of the last SUCCESSFUL deep probe — the only thing that can justify `ok`. */
  verifiedAt?: number;
}

/**
 * The frozen field allowlist for {@link EngineLink} — the boundary, as CI. A test asserts this list
 * exactly, and asserts that no entry names a connection / message / queue / count / rate. To add a
 * field you must change this line, which trips the test, which forces the ADR conversation. That is
 * the mechanism by which "don't grow a second operator console in the IDE" stops being a docstring.
 */
export const ENGINE_LINK_FIELDS = [
  "blocked",
  "checkedAt",
  "code",
  "environment",
  "reason",
  "state",
  "target",
  "verifiedAt",
  "version",
] as const;

/** The ONLY engine routes the status bar may probe — frozen and asserted in CI. `/messages`,
 *  `/connections`, `/stats`, `/dead-letters`, `/alerts` are absent by design: probing them is how an
 *  indicator turns into a monitor, and a monitor is the Console's job. */
export const PROBE_ENDPOINTS = ["/ai/policy", "/config/provenance", "/health"] as const;

/** The tokenless liveness probe. Cheap, and safe on a timer precisely BECAUSE it is tokenless. */
export const HEALTH_ROUTE = "/health";

/** One planned HTTP probe. `authenticated` decides whether a bearer is attached — and it is the whole
 *  ballgame, so it is DATA (asserted in CI) rather than a decision buried in the shell. */
export interface ProbePlanEntry {
  route: string;
  authenticated: boolean;
}

/**
 * What the PERIODIC (timer-driven) poll is allowed to do. Every entry is `authenticated: false`, and a
 * test asserts exactly that.
 *
 * This is the executable form of the hard rule in the file header. `identity_for_token(..., activity=True)`
 * refreshes a session's idle clock, so a bearer on a 15-second timer from an open editor window would keep
 * the session alive forever and make the engine's 30-minute idle timeout mathematically unreachable
 * (CWE-613) — on the exact client the automatic-logoff control exists for. A comment saying "don't add a
 * token here" is not a control; this list is.
 */
export const POLL_PLAN: readonly ProbePlanEntry[] = [
  { route: HEALTH_ROUTE, authenticated: false },
];

/** What a USER-INITIATED deep check may do. A bearer is permitted here: a click/activation/promote IS real
 *  user activity, so refreshing the idle clock is honest rather than a forgery. */
export const VERIFY_PLAN: readonly ProbePlanEntry[] = [
  { route: "/config/provenance", authenticated: true },
  { route: HEALTH_ROUTE, authenticated: true }, // learns the version, which a tokenless probe never sees
];

/** The tokenless policy read that names the engine's active environment (ADR 0017). Best-effort: any
 *  failure just means the hover omits the environment line. */
export const POLICY_ROUTE = "/ai/policy";

/**
 * The route that EARNS a green check. It must be (a) authenticated, (b) permission-gated, and (c) NOT
 * must-change-exempt — `/health` and `/auth/me` are both exempt and answer 200 for a user locked out of
 * everything, so neither can establish usability. `/config/provenance` is gated by `monitoring:read`
 * with no step-up, and returns `drift` for free — the highest-value signal the IDE can get about the
 * engine it is authoring for.
 */
export const DEEP_PROBE_ROUTE = "/config/provenance";

/** How long a verified-usable verdict stays green before decaying back to `unverified`. A status-bar
 *  tooltip is a VALUE, not a provider: it must never keep asserting a fact it has not re-checked. */
export const VERIFY_TTL_MS = 5 * 60_000;

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
  const envs = environments.filter(
    (e) => e && typeof e.name === "string" && typeof e.url === "string",
  );
  if (envs.length === 0) {
    return { name: hostLabel(engineUrl), url: engineUrl, all: [{ name: "engine", url: engineUrl }] };
  }
  if (envs.length === 1) {
    return { name: envs[0].name, url: envs[0].url, all: envs };
  }
  const extra = envs.length - 1;
  return { name: `${envs[0].name} (+${extra})`, url: envs[0].url, all: envs };
}

/** Name a transport errno in words the user can act on. "unreachable" alone is useless — "nothing is
 *  listening", "the engine is hung" and "you spoke http to an https port" have different fixes. */
export function describeNetworkCode(code: string | undefined, url: string): string {
  const where = hostLabel(url);
  switch (code) {
    case "ECONNREFUSED":
      return `nothing is listening on ${where} — the engine isn't running`;
    case "ENOTFOUND":
      return `the host name in ${where} does not resolve`;
    case "ETIMEDOUT":
      return `the connection to ${where} timed out — unreachable host, or a firewall is dropping it`;
    case "MF_TIMEOUT":
      return `${where} accepted the connection but never answered — the engine is hung`;
    case "ECONNRESET":
      return `${where} reset the connection`;
    case "EPROTO":
    case "ERR_SSL_WRONG_VERSION_NUMBER":
      return `TLS handshake failed against ${where} — is the engine http:// rather than https://?`;
    default:
      return code
        ? `the connection to ${where} failed (${code})`
        : `the connection to ${where} failed`;
  }
}

/** Sub-classify a 403 from the engine's `detail` string (stable; already extracted by engineClient). */
export function classifyForbidden(detail: string): BlockedReason {
  const d = detail.toLowerCase();
  if (d.includes("password change") || d.includes("change password") || d.includes("must change")) {
    return "mustChangePassword";
  }
  if (d.includes("step-up") || d.includes("step up") || d.includes("re-verification")) {
    return "stepUp";
  }
  if (d.includes("mfa") || d.includes("multi-factor") || d.includes("totp")) {
    return "mfa";
  }
  if (d.includes("permission")) {
    return "permission";
  }
  return "forbidden";
}

/** The `/health` body we care about. Deliberately loose — a FOREIGN server may return anything. */
interface HealthBody {
  status?: unknown;
  version?: unknown;
}

/**
 * The SHALLOW (tokenless, on-a-timer) classification. It can prove the negative and nothing more:
 *  - no answer                 → unreachable (named by errno)
 *  - an answer that isn't ours → foreign
 *  - `version: null`           → signedOut, but ONLY if we hold no session (see below)
 *  - `version` present         → unverified (NOT ok — see the header: /health applies no RBAC)
 *
 * It never returns `ok`. That is the entire correction: a green check must be earned, not assumed.
 *
 * `hasSession` — whether SecretStorage holds a token for this target — is LOAD-BEARING, and its absence
 * was a real bug. Because the poll is tokenless, `/health` returns `version: null` to it *always* on an
 * auth-enabled engine — even when the IDE holds a perfectly good session. Reading `version: null` as
 * "signed out" therefore told a signed-in user to sign in, and (worse) threw away the `ok` verdict the
 * deep probe had just earned, 15 seconds after every sign-in. A tokenless probe simply CANNOT observe our
 * session state; when we hold a token it must say `unverified` — "up, and I can't tell from here" — and
 * leave the earned verdict to be restored by the caller and expired by {@link withStaleness}.
 *
 * Note this reads SecretStorage, not the wire: it sends no bearer, so the engine's idle clock is untouched.
 */
export function classifyHealth(
  outcome: ProbeOutcome,
  target: EngineStatusTarget,
  now: number,
  hasSession: boolean,
): EngineLink {
  const base = { target, checkedAt: now };
  if (outcome.kind === "networkError") {
    return {
      ...base,
      state: "unreachable",
      code: outcome.code,
      reason: describeNetworkCode(outcome.code, target.url),
    };
  }
  if (outcome.kind === "httpError") {
    // /health is tokenless and always answers 200 on a real engine, so a non-2xx here means we are
    // NOT talking to a MessageFoundry engine (a proxy, another service, the wrong port).
    return {
      ...base,
      state: "foreign",
      reason: `${hostLabel(target.url)} answered HTTP ${outcome.status}, which a MessageFoundry engine would not — is this the right port?`,
    };
  }
  const body = (outcome.body ?? {}) as HealthBody;
  if (body.status !== "ok") {
    return {
      ...base,
      state: "foreign",
      reason: `something is listening on ${hostLabel(target.url)}, but it is not a MessageFoundry engine`,
    };
  }
  if (typeof body.version !== "string" || body.version === "") {
    // The engine withholds `version` from an unauthenticated caller — and this probe IS unauthenticated,
    // so a null version tells us nothing about our own session. It is decisive ONLY when we hold no token.
    if (!hasSession) {
      return {
        ...base,
        state: "signedOut",
        reason: "the engine is running, but the IDE is not signed in to it",
      };
    }
    return {
      ...base,
      state: "unverified",
      reason: "the engine is up; this tokenless check cannot confirm the session",
    };
  }
  // A version came back to a TOKENLESS caller ⇒ the engine is running with auth disabled
  // (`allow_no_auth` → optional_identity yields the system identity). Still not `ok`: earn it.
  return {
    ...base,
    state: "unverified",
    version: body.version,
    reason: "a session exists, but it has not been verified against a protected route",
  };
}

/** The engine's build version, if this body carries one. Only ever disclosed to an authenticated caller. */
export function readVersion(body: unknown): string | undefined {
  const v = (body as HealthBody | null)?.version;
  return typeof v === "string" && v !== "" ? v : undefined;
}

/**
 * The DEEP (authenticated, user-initiated ONLY) classification against {@link DEEP_PROBE_ROUTE}. This
 * is the only thing that may produce `ok`. It runs on click / activation / after a promote — all real
 * user activity — so sending the bearer here does NOT falsify the engine's idle clock the way a timer
 * would.
 *
 * `prior` carries what the shallow probe already learned (version, environment) so a deep verdict
 * never loses it.
 */
export function classifyDeep(outcome: ProbeOutcome, prior: EngineLink, now: number): EngineLink {
  const base: EngineLink = { ...prior, checkedAt: now, verifiedAt: undefined };
  if (outcome.kind === "networkError") {
    return {
      ...base,
      state: "unreachable",
      code: outcome.code,
      reason: describeNetworkCode(outcome.code, prior.target.url),
    };
  }
  if (outcome.kind === "httpError") {
    if (outcome.status === 401) {
      // The token we hold is expired/invalid — indistinguishable, to the user, from never having one.
      return {
        ...base,
        state: "signedOut",
        reason: "the IDE's session has expired — sign in again",
      };
    }
    const blocked =
      outcome.status === 403 ? classifyForbidden(outcome.detail) : ("forbidden" as const);
    return {
      ...base,
      state: "blocked",
      blocked,
      reason: outcome.detail || `the engine answered HTTP ${outcome.status}`,
    };
  }
  const body = (outcome.body ?? {}) as { drift?: unknown };
  if (body.drift === true) {
    return {
      ...base,
      state: "drifted",
      reason: "the engine's loaded config differs from what is on disk — promote to sync it",
      verifiedAt: now,
    };
  }
  return { ...base, state: "ok", reason: undefined, blocked: undefined, verifiedAt: now };
}

/**
 * Decay a verified verdict once it is older than {@link VERIFY_TTL_MS}. Applied at RENDER time, so the
 * item cannot sit on a stale "everything's fine" for hours after the session it verified has died.
 */
export function withStaleness(link: EngineLink, now: number): EngineLink {
  if (link.state !== "ok" && link.state !== "drifted") {
    return link;
  }
  if (link.verifiedAt !== undefined && now - link.verifiedAt <= VERIFY_TTL_MS) {
    return link;
  }
  return {
    ...link,
    state: "unverified",
    reason: "this session was verified a while ago — re-check it",
  };
}

/** "12s ago" / "4m ago" / "2h ago" — honest staleness, so the tooltip never implies it just looked. */
export function ago(then: number | undefined, now: number): string {
  if (then === undefined) {
    return "never";
  }
  const s = Math.max(0, Math.round((now - then) / 1000));
  if (s < 60) {
    return `${s}s ago`;
  }
  const m = Math.round(s / 60);
  if (m < 60) {
    return `${m}m ago`;
  }
  return `${Math.round(m / 60)}h ago`;
}

/** The status-bar background to use. `undefined` = the normal bar colour. */
export type StatusBackground = "error" | "warning" | undefined;

/** The rendered status item: item text, the hover MARKDOWN (a plain string — the vscode.MarkdownString
 *  is built by the shell, so this module stays vscode-free), and the background colour. */
export interface EngineStatusText {
  text: string;
  tooltipMarkdown: string;
  background: StatusBackground;
}

/**
 * Neutralise server-supplied text before it enters the hover.
 *
 * The hover is a TRUSTED MarkdownString (`isTrusted.enabledCommands` includes `messagefoundry.promote`),
 * and `reason` can carry the engine's own 403 `detail` string verbatim. Interpolating that raw would let
 * whatever is answering on that port inject `[Click me](command:messagefoundry.promote)` into a link the
 * user is invited to click — and "whatever is answering on that port" is not necessarily our engine (that
 * is what the `foreign` state is FOR). So: strip the markdown link/code metacharacters, flatten newlines,
 * and cap the length. Defence in depth behind the command allowlist, not instead of it.
 */
export function escapeMarkdown(text: string, max = 300): string {
  const flat = text.replace(/\s+/g, " ").trim().slice(0, max);
  return flat.replace(/[\\`*_[\]()<>#|]/g, (c) => `\\${c}`);
}

/** One-line headline per state — the first thing the hover says. */
function headline(state: LinkState): string {
  switch (state) {
    case "unknown":
      return "Checking the engine…";
    case "unreachable":
      return "Engine unreachable";
    case "foreign":
      return "Not a MessageFoundry engine";
    case "signedOut":
      return "Engine up — the IDE is signed out";
    case "unverified":
      return "Engine up — session not verified";
    case "blocked":
      return "Engine up — this account is blocked";
    case "drifted":
      return "Engine up — config has drifted";
    case "ok":
      return "Engine ready";
  }
}

function icon(state: LinkState): string {
  switch (state) {
    case "unknown":
      return "$(circle-outline)";
    case "unreachable":
      return "$(debug-disconnect)";
    case "foreign":
      return "$(question)";
    case "signedOut":
      return "$(lock)";
    case "unverified":
      return "$(circle-large-outline)";
    case "blocked":
      return "$(warning)";
    case "drifted":
      return "$(git-compare)";
    case "ok":
      return "$(pass-filled)";
  }
}

/**
 * Colour discipline — deliberately conservative.
 *
 * `signedOut` gets NO background. It is the author's harmless steady state: he is writing Python, live
 * status is off by default, and promote prompts for a sign-in anyway. Painting it amber would leave the
 * status bar permanently amber, which trains the eye to ignore it — and then it cannot warn about the
 * states that actually block something he is trying to do. An alarm that is always on is not an alarm.
 */
function background(state: LinkState): StatusBackground {
  switch (state) {
    case "unreachable":
    case "foreign":
      return "error";
    case "blocked":
    case "drifted":
      return "warning";
    default:
      return undefined;
  }
}

/**
 * Render the item text + the hover markdown for a link. The hover is the PRIMARY surface: it appears
 * at the item, under a cursor that is already there, and needs no command dispatch at all — which is
 * exactly why the diagnosis lives here and not only behind the click.
 */
export function formatEngineStatus(link: EngineLink, now: number): EngineStatusText {
  const l = withStaleness(link, now);
  const lines: string[] = [`**${headline(l.state)}**`];

  // Everything below that came from the network is escaped: `reason` can carry the engine's 403 `detail`
  // verbatim, and `version`/`environment` are server-supplied too. See escapeMarkdown.
  lines.push(`Target: \`${escapeMarkdown(l.target.url, 200)}\``);
  if (l.environment) {
    lines.push(`Environment: \`${escapeMarkdown(l.environment, 60)}\``);
  }
  if (l.version) {
    lines.push(`Engine version: \`${escapeMarkdown(l.version, 40)}\``);
  }
  if (l.reason) {
    lines.push(escapeMarkdown(l.reason));
  }
  if (l.state === "ok") {
    lines.push(`Session verified ${ago(l.verifiedAt, now)}.`);
  }
  if (l.target.all.length > 1) {
    lines.push(
      ["Configured environments:", ...l.target.all.map((e) => `- ${e.name} — \`${e.url}\``)].join(
        "\n",
      ),
    );
  }
  if (l.state !== "unknown") {
    lines.push(`_Checked ${ago(l.checkedAt, now)}._`);
  }
  lines.push("Click the item for engine actions.");

  return {
    text: `${icon(l.state)} MEFOR: ${l.target.name}`,
    tooltipMarkdown: lines.join("\n\n"),
    background: background(l.state),
  };
}

/**
 * An action offered in the click menu. It carries a COMMAND ID, never data — the QuickPick handler's
 * only permitted body is `executeCommand(action.command, ...action.args)`. That is structural: there is
 * no channel through which engine workload data could reach this surface even if someone fetched it,
 * which is the second of the three devices holding the operator-console boundary.
 */
export interface EngineAction {
  label: string;
  detail?: string;
  command: string;
  args?: unknown[];
}

/** Command ids this model may emit. Named here so the shell and the tests agree on one list. */
export const CMD = {
  signIn: "messagefoundry.engineSignIn",
  signOut: "messagefoundry.engineSignOut",
  recheck: "messagefoundry.engineRecheck",
  showLog: "messagefoundry.engineShowLog",
  openConsole: "messagefoundry.engineOpenConsole",
  copyStart: "messagefoundry.engineCopyStartCommand",
  startEngine: "messagefoundry.startEngine",
  stopEngine: "messagefoundry.stopEngine",
  restartEngine: "messagefoundry.restartEngine",
  setupEnvironment: "messagefoundry.setupEnvironment",
  openEngineSetup: "messagefoundry.openEngineSetup",
  settings: "messagefoundry.openEngineSettings",
  promote: "messagefoundry.promote",
  panel: "workbench.view.extension.messagefoundry",
} as const;

/**
 * What the SHELL can currently do to the LOCAL engine process — computed from `vscode` + the filesystem
 * by statusBar.ts and passed in so this module stays vscode-free and pure. The default ({@link NO_CONTROL})
 * is all-false: no lifecycle control offered, which is exactly the behaviour for a remote or untrusted
 * target, and keeps every `planActions(link, now)` (2-arg) caller — including the whole engine-doctor
 * test suite — on the pre-lifecycle menu.
 *
 * This is why start/stop can exist WITHOUT reintroducing the ADR 0110 §5 hazard (a `serve` that forks the
 * user's engine with a rogue empty DB): the two safety facts are decided by the shell and encoded here —
 *   - `canControl` — the target is loopback AND the workspace is trusted AND there is a workspace to run in
 *     (a remote engine reads its OWN filesystem; an untrusted workspace must not exec a repo-supplied venv).
 *   - `hasStore`   — a real engine store already lives where `serve` would run; when false, Start does not
 *     silently create one — the shell confirms it will make a NEW database + bootstrap admin first.
 *   - `weStartedIt`— the IDE owns a LIVE engine process it launched; only then may Stop/Restart act. We never
 *     kill an engine we did not start (with parallel worktrees a port-kill could down another session's).
 */
export interface EngineControlContext {
  canControl: boolean;
  hasStore: boolean;
  weStartedIt: boolean;
}

/** No lifecycle control — the default for `planActions`, so a 2-arg call is the pre-lifecycle menu. */
export const NO_CONTROL: EngineControlContext = {
  canControl: false,
  hasStore: false,
  weStartedIt: false,
};

/** True when the engine is answering as itself (not down, not a stranger, not still-unknown). */
function engineIsUp(state: LinkState): boolean {
  return state !== "unreachable" && state !== "foreign" && state !== "unknown";
}

/**
 * The engine LIFECYCLE actions, prepended to the menu. Command ids only (like every action here), so they
 * add no data channel and trip neither frozen allowlist. The gating is the whole safety story — see
 * {@link EngineControlContext}:
 *   - we own a live process → Stop + Restart (whatever the link currently reads);
 *   - else, the engine is down and we CAN run it here → Start when a store already lives here; with NO
 *     store, the lead is "Set up an engine…" — the guided setup page (ADR 0112 amendment, BACKLOG #238) —
 *     because a store-less workspace is an authoring checkout, where the right move is pointing at an
 *     engine, not forking a fresh DB. The create-DB start still exists behind the page's clearly-labelled
 *     dev-engine button (and the palette), where startEngine's modal confirm remains the fork guard.
 */
function lifecycleActions(l: EngineLink, ctx: EngineControlContext): EngineAction[] {
  if (ctx.weStartedIt) {
    return [
      {
        label: "$(debug-stop) Stop the engine",
        detail: "Stops the engine this IDE started",
        command: CMD.stopEngine,
      },
      {
        label: "$(debug-restart) Restart the engine",
        detail: "Stop it and start it again — reloads the config",
        command: CMD.restartEngine,
      },
    ];
  }
  if (!engineIsUp(l.state) && ctx.canControl) {
    return [
      ctx.hasStore
        ? {
            label: "$(run) Start the engine",
            detail: "Runs `serve` here with this project's Python",
            command: CMD.startEngine,
          }
        : {
            label: "$(tools) Set up an engine…",
            detail: "No store found here — point the IDE at an engine, or set one up",
            command: CMD.openEngineSetup,
          },
    ];
  }
  return [];
}

/**
 * The state-gated action menu. The point of gating: when the engine is DOWN, "open engine URL in a
 * browser" is worse than useless — it is what the old menu led with, and it opened the API root, which
 * has no route and answers a FastAPI 404. What you want when it is down is to start it or fix the URL.
 *
 * Everything operational (messages, connections, queues) is a deep-link to the Console — never rebuilt
 * here. Remedies the IDE cannot honestly perform are not offered as buttons; the reason line says so.
 */
export function planActions(
  link: EngineLink,
  now: number,
  ctx: EngineControlContext = NO_CONTROL,
): EngineAction[] {
  const l = withStaleness(link, now);
  // Lifecycle controls lead the menu (Stop/Restart when we own the process, Start when it is down and we
  // may run it) — the pre-lifecycle menu is exactly the `NO_CONTROL` default, so a 2-arg call is unchanged.
  const actions: EngineAction[] = [...lifecycleActions(l, ctx)];

  switch (l.state) {
    case "unreachable":
    case "foreign":
      actions.push({
        label: "$(terminal) Copy the engine start command",
        detail: "Paste it into a terminal — the IDE will not start the engine for you",
        command: CMD.copyStart,
      });
      actions.push({
        label: "$(gear) Configure engine target…",
        detail: l.target.url,
        command: CMD.settings,
      });
      break;

    case "signedOut":
      actions.push({
        label: "$(sign-in) Sign in to the engine",
        detail: "The engine is up; the IDE has no session with it",
        command: CMD.signIn,
      });
      actions.push({
        label: "$(link-external) Open the web console",
        detail: `${l.target.url}/ui`,
        command: CMD.openConsole,
      });
      break;

    case "unverified":
      actions.push({
        label: "$(shield) Verify this session",
        detail: "Check it against a protected route — /health cannot prove a session works",
        command: CMD.recheck,
      });
      actions.push({ label: "$(sign-out) Sign out", command: CMD.signOut });
      break;

    case "blocked":
      // Every one of these is fixed in the Console, not here: credential management is the operator
      // console's job (ADR 0065), and the IDE deep-links to it rather than growing a second one.
      if (l.blocked === "permission" || l.blocked === "forbidden") {
        actions.push({
          label: "$(account) This account lacks the permission",
          detail: "An administrator must grant it — the IDE cannot fix this",
          command: CMD.showLog,
        });
      } else {
        actions.push({
          label: "$(link-external) Fix this in the web console",
          detail: `${l.target.url}/ui/login`,
          command: CMD.openConsole,
          args: ["/ui/login"],
        });
      }
      actions.push({ label: "$(sign-out) Sign out", command: CMD.signOut });
      break;

    case "drifted":
      actions.push({
        label: "$(cloud-upload) Promote config to the engine",
        detail: "The engine's loaded config differs from what is on disk",
        command: CMD.promote,
      });
      actions.push({
        label: "$(link-external) Open the web console",
        detail: `${l.target.url}/ui`,
        command: CMD.openConsole,
      });
      break;

    case "ok":
      actions.push({
        label: "$(link-external) Open the web console",
        detail: `${l.target.url}/ui`,
        command: CMD.openConsole,
      });
      actions.push({ label: "$(sign-out) Sign out", command: CMD.signOut });
      break;

    case "unknown":
      break;
  }

  // Always available, in a stable order — the tail of the menu never moves under the user's muscle memory.
  actions.push({ label: "$(refresh) Re-check the engine now", command: CMD.recheck });
  actions.push({
    label: "$(output) Show the engine log",
    detail: "Every probe and action — URLs, status codes, timings",
    command: CMD.showLog,
  });
  if (l.state !== "unreachable" && l.state !== "foreign") {
    actions.push({
      label: "$(gear) Configure engine target…",
      detail: l.target.url,
      command: CMD.settings,
    });
  }
  actions.push({ label: "$(window) Open the MessageFoundry panel", command: CMD.panel });
  return actions;
}
