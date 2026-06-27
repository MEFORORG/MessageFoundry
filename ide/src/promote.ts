// "Stage → Promote": validate the local config, choose a target environment, pre-flight it against
// that environment (dry-run — resolves its env() values, so a missing value fails BEFORE going
// live), confirm, then apply. The engine/API do the hard part (atomic quiesce-and-swap reload); this
// is the IDE-side guided flow, authenticated to the (auth-required) engine.
import * as path from "node:path";
import * as vscode from "vscode";
import { withAuth } from "./auth";
import { configDir, engineUrl, environments, runJson, workspaceDir, type EnvironmentTarget } from "./cli";
import { HttpError, postJson } from "./engineClient";
import { assertTargetAllowed, isLocalEngine } from "./engineTarget";
import { planTargetResolution, resolveTargetUrl, type ResolvedTarget } from "./promoteTarget";

// Shape emitted by `messagefoundry validate --json` (see ide/src/validate.ts).
interface Diagnostic {
  message: string;
  file: string | null;
  severity: string;
}

// Mirrors messagefoundry/api/models.py:ReloadResult (the /config/reload response).
interface ReloadResult {
  inbound: number;
  outbound: number;
  routers: number;
  handlers: number;
  running: boolean;
  dry_run: boolean;
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** The environment to promote to: a configured one (picked if several), else the single engineUrl. */
async function pickTarget(): Promise<EnvironmentTarget | undefined> {
  const envs = environments();
  if (envs.length === 0) {
    return { name: "engine", url: engineUrl() };
  }
  if (envs.length === 1) {
    return envs[0];
  }
  const pick = await vscode.window.showQuickPick(
    envs.map((e) => ({ label: e.name, description: e.url, env: e })),
    { placeHolder: "Promote to which environment?" },
  );
  return pick?.env;
}

/**
 * Resolve the chosen environment to a concrete engine instance. With ≥2 shards this shows a SECOND
 * QuickPick to choose one and deploys to its url; with 0 or 1 shard it behaves exactly as before (no
 * extra prompt). Returns undefined if the user cancels the shard pick. The url decision itself lives
 * in the pure {@link resolveTargetUrl}/{@link planTargetResolution} (unit-tested without vscode).
 */
async function pickTargetUrl(env: EnvironmentTarget): Promise<ResolvedTarget | undefined> {
  const plan = planTargetResolution(env);
  if (!plan.needsPick) {
    return plan.resolved;
  }
  const pick = await vscode.window.showQuickPick(
    plan.shards.map((s) => ({ label: s.name, description: s.url, shard: s })),
    { placeHolder: `Promote to which engine instance in ${env.name}?` },
  );
  if (!pick) {
    return undefined; // shard selection cancelled
  }
  return resolveTargetUrl(env, pick.shard);
}

export async function promote(context: vscode.ExtensionContext): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
    return;
  }
  const cfg = configDir();

  // 1. Stage — validate the candidate config locally; block the promote on any error.
  let diags: Diagnostic[];
  try {
    diags = await runJson<Diagnostic[]>(["validate", "--config", cfg], ws);
  } catch (e) {
    void vscode.window.showErrorMessage(`MessageFoundry: validate failed — ${errText(e)}`);
    return;
  }
  const errors = diags.filter((d) => d.severity === "error");
  if (errors.length > 0) {
    void vscode.commands.executeCommand("messagefoundry.validate"); // populate Problems
    const choice = await vscode.window.showErrorMessage(
      `MessageFoundry: ${errors.length} config error(s) — fix them before promoting.`,
      "Show Problems",
    );
    if (choice === "Show Problems") {
      void vscode.commands.executeCommand("workbench.action.problems.focus");
    }
    return;
  }

  // 2. Choose the target environment (DEV/PROD/…), then — if it defines several engine instances
  //    (shards) — which instance within it. With 0 or 1 shard this is a single prompt as before.
  const env = await pickTarget();
  if (!env) {
    return;
  }
  const target = await pickTargetUrl(env);
  if (!target) {
    return; // shard selection cancelled
  }
  // Guard the target host BEFORE any credential prompt / token send (SEC-005): refuse plain http://
  // off-box, and for an https off-box target require an explicit, host-naming confirmation so a
  // (plausibly internal-looking) malicious URL can't silently collect a developer's account password
  // and bearer token. Loopback over http stays allowed (the default 127.0.0.1 dev flow).
  const gate = assertTargetAllowed(target.url);
  if (!gate.ok) {
    void vscode.window.showErrorMessage(`MessageFoundry: ${gate.reason}`);
    return;
  }
  if (!isLocalEngine(target.url)) {
    let host: string;
    try {
      host = new URL(target.url).hostname;
    } catch {
      host = target.url;
    }
    const confirm = await vscode.window.showWarningMessage(
      `You are about to sign in and send credentials to ${host} (${target.url}). Continue?`,
      { modal: true },
      "Continue",
    );
    if (confirm !== "Continue") {
      return;
    }
  }
  // The engine reads the config dir from ITS OWN filesystem. Only send our local absolute path to a
  // local engine; to a remote target that path is meaningless (it would 403/404, or worse resolve to
  // a different in-root dir and reload the wrong config), so send null → the engine reloads from its
  // own startup --config dir (the same code, promoted there out of band) (review M-29).
  const abs = path.isAbsolute(cfg) ? cfg : path.join(ws, cfg);
  const configDirForTarget = isLocalEngine(target.url) ? abs : null;
  const reload =
    (dryRun: boolean) =>
    (token: string): Promise<ReloadResult> =>
      postJson<ReloadResult>(
        target.url,
        "/config/reload",
        { config_dir: configDirForTarget, dry_run: dryRun },
        token,
      );

  // 3. Pre-flight — dry-run the graph against the TARGET environment. This resolves the graph's
  //    env() values there, so a value the target doesn't define (or a bad spec) fails NOW, not after
  //    the swap. Nothing on the running engine changes.
  let check: ReloadResult | undefined;
  try {
    check = await withAuth(context, target.url, reload(true));
  } catch (e) {
    const hint =
      e instanceof HttpError && e.status === 422
        ? " — a referenced environment value may be undefined for this environment"
        : "";
    void vscode.window.showErrorMessage(`MessageFoundry: pre-flight failed${hint}: ${errText(e)}`);
    return;
  }
  if (check === undefined) {
    return; // sign-in cancelled
  }

  // 4. Confirm — a live swap is production-affecting, so require an explicit OK.
  const ok = await vscode.window.showWarningMessage(
    `Promote "${cfg}" to ${target.name} (${target.url})?\n\nPre-flight passed: ` +
      `${check.inbound} inbound, ${check.outbound} outbound. This atomically swaps the live graph.`,
    { modal: true },
    "Promote",
  );
  if (ok !== "Promote") {
    return;
  }

  // 5. Promote — apply for real.
  let result: ReloadResult | undefined;
  try {
    result = await withAuth(context, target.url, reload(false));
  } catch (e) {
    void vscode.window.showErrorMessage(`MessageFoundry: promote failed — ${errText(e)}`);
    return;
  }
  if (result === undefined) {
    return; // sign-in cancelled
  }
  void vscode.window.showInformationMessage(
    `MessageFoundry: promoted to ${target.name} — live graph: ${result.inbound} inbound, ` +
      `${result.outbound} outbound, ${result.routers} routers, ${result.handlers} handlers` +
      `${result.running ? " • running" : ""}.`,
  );
}
