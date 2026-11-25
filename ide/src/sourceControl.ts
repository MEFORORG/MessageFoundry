// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// "Set Up Version Control & Checks" — a guided, offline, provider-agnostic flow that puts a
// code-first MessageFoundry project under git and wires a local pre-commit hook running
// `messagefoundry check`. Leans on the user's git (respecting an existing repo); never contacts a
// network. Scaffold templates are string consts in sourceControlTemplates.ts (esbuild bundles only
// TS, not loose assets).
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { logChecks, showChecks } from "./checksChannel";
import { baselineBypassRecord } from "./checksLog";
import { configDir, run, workspaceDir, writerPathSetting } from "./cli";
import { CASE_RULE, committedRelativePath } from "./workspaceContainment";
import { foldAsciiCase } from "./pathFold";
import { findGit, getHooksPath, getRemoteUrl, git, isRepo } from "./git";
import { STARTUP_BANNERS, openChannel, postToWebview } from "./webviewMessaging";
import { sourceControlScript } from "./sourceControlWebview";
import {
  GITATTRIBUTES_LINE,
  GITIGNORE_ENTRIES,
  GITIGNORE_MARKER,
  HOOK_REL,
  HOOKS_DIR,
  PRE_COMMIT_TEMPLATE,
  setupText,
  type HookState,
  type SetupText,
} from "./sourceControlTemplates";

const DISMISS_KEY = "messagefoundry.scPromptDismissed";

// Setup writes a commit hook that runs the folder's own `.venv` interpreter on every later commit,
// and runs git inside the folder. That is the workspace-supplied-interpreter hazard cli.ts refuses in
// an untrusted workspace (SEC-004, CWE-426), reached through `git()` and the file writes rather than
// `run()`, so `isExecGated` does not cover it. Every entry point in this file that runs git refuses
// until the folder is trusted; extension.ts re-offers the nudge when trust is granted.
const UNTRUSTED_SETUP_MESSAGE =
  "MessageFoundry: trust this workspace to set up version control and checks. The commit hook it " +
  "installs runs this folder's own Python environment.";

/** One-time, dismissible nudge: offer setup when there are config modules but no repo yet. */
export async function maybeSuggestSourceControl(context: vscode.ExtensionContext): Promise<void> {
  const ws = workspaceDir();
  if (!ws || !vscode.workspace.isTrusted) {
    return; // no nudge in an untrusted workspace: setup would refuse there anyway
  }
  if (!vscode.workspace.getConfiguration("messagefoundry").get<boolean>("sourceControl.autoPrompt", true)) {
    return;
  }
  if (
    context.globalState.get<boolean>(DISMISS_KEY) ||
    context.workspaceState.get<boolean>(DISMISS_KEY)
  ) {
    return;
  }
  if (await pathExists(path.join(ws, ".git"))) {
    return; // already under version control
  }
  const dir = configDir();
  if (!(await hasConfigModules(path.isAbsolute(dir) ? dir : path.join(ws, dir)))) {
    return; // not a MessageFoundry project (no config modules)
  }
  const pick = await vscode.window.showInformationMessage(
    "Put this MessageFoundry project under version control and run checks on every commit?",
    "Set it up",
    "Not now",
    "Don't ask again",
  );
  if (pick === "Set it up") {
    await setupSourceControl(context);
  } else if (pick === "Not now") {
    await context.workspaceState.update(DISMISS_KEY, true); // this project, this machine
  } else if (pick === "Don't ask again") {
    await context.globalState.update(DISMISS_KEY, true); // any project
  }
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await vscode.workspace.fs.stat(vscode.Uri.file(p));
    return true;
  } catch {
    return false;
  }
}

async function hasConfigModules(dir: string): Promise<boolean> {
  try {
    const entries = await vscode.workspace.fs.readDirectory(vscode.Uri.file(dir));
    return entries.some(
      ([name, type]) =>
        type === vscode.FileType.File && name.endsWith(".py") && !name.startsWith("_"),
    );
  } catch {
    return false;
  }
}

export async function setupSourceControl(_context: vscode.ExtensionContext): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showErrorMessage("MessageFoundry: open a workspace folder first.");
    return;
  }
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage(UNTRUSTED_SETUP_MESSAGE);
    return;
  }
  // Read before git init, so a refusal leaves nothing half set up.
  const hookPaths = hookPathValues(ws);
  if (hookPaths === undefined) {
    return;
  }

  const bin = await findGit();
  if (!bin) {
    await guideGitInstall();
    return;
  }

  // Respect an existing repo (don't re-init); otherwise offer to initialize locally.
  if (!(await isRepo(bin, ws))) {
    const pick = await vscode.window.showInformationMessage(
      "No git repository here yet. Initialize one? (Stays on this machine — no network.)",
      "Initialize",
      "Cancel",
    );
    if (pick !== "Initialize") {
      return;
    }
    let res = await git(bin, ["init", "-b", "main"], ws);
    if (res.code !== 0) {
      // Older git without `-b`: init, then best-effort rename the branch.
      res = await git(bin, ["init"], ws);
      if (res.code !== 0) {
        void vscode.window.showErrorMessage(`MessageFoundry: git init failed — ${res.stderr.trim()}`);
        return;
      }
      await git(bin, ["checkout", "-b", "main"], ws);
    }
  }

  const notes: string[] = [];
  notes.push(`.gitignore: ${await scaffoldGitignore(ws)}`);
  notes.push(`.gitattributes: ${await scaffoldGitattributes(ws)}`);
  // Checks run on commit only once the hook is both written AND wired: a hook git is not pointed at
  // never runs, so the text below claims checks only when both happened.
  let hookState: HookState = "none";
  if (hookPaths.hook === undefined) {
    notes.push("hook: not written (a path setting names a folder outside the workspace)");
  } else {
    notes.push(`hook: ${await scaffoldHook(bin, ws, hookPaths.hook)}`);
    const wiring = await wireHooksPath(bin, ws);
    notes.push(`core.hooksPath: ${wiring.note}`);
    hookState = wiring.wired ? "wired" : "written";
  }

  // Logged here, before the prompts below. Every line is time-stamped, so logging these after the
  // first commit would date the hook install later than the commit it came before.
  logChecks(["Set Up Version Control & Checks:", ...notes.map((n) => `  • ${n}`)].join("\n"));

  await maybeAddRemote(bin, ws);
  const text = setupText(hookState);
  await maybeFirstCommit(bin, ws, hookPaths.check, text);

  void vscode.window.showInformationMessage(text.done);
}

async function guideGitInstall(): Promise<void> {
  const choice = await vscode.window.showWarningMessage(
    "Git isn't installed (or wasn't found). Version control needs it — nothing leaves your machine.",
    "Install with winget",
    "Open git-scm.com",
    "Later",
  );
  if (choice === "Install with winget") {
    const term = vscode.window.createTerminal("Install Git");
    term.show();
    term.sendText("winget install --id Git.Git -e", false); // typed, not run — the user presses Enter
  } else if (choice === "Open git-scm.com") {
    await vscode.env.openExternal(vscode.Uri.parse("https://git-scm.com/downloads"));
  }
}

async function readFileOrEmpty(uri: vscode.Uri): Promise<string> {
  try {
    return Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf8");
  } catch {
    return "";
  }
}

/** Append only the missing entries under a delimited block; never rewrite the user's content. */
async function scaffoldGitignore(ws: string): Promise<string> {
  const uri = vscode.Uri.file(path.join(ws, ".gitignore"));
  const existing = await readFileOrEmpty(uri);
  const present = new Set(existing.split(/\r?\n/).map((l) => l.trim()));
  const missing = GITIGNORE_ENTRIES.filter((e) => !present.has(e));
  if (missing.length === 0) {
    return "already up to date";
  }
  const sep = existing.length && !existing.endsWith("\n") ? "\n" : "";
  const header = existing.includes(GITIGNORE_MARKER) ? "" : `${GITIGNORE_MARKER}\n`;
  await vscode.workspace.fs.writeFile(
    uri,
    Buffer.from(`${existing}${sep}${header}${missing.join("\n")}\n`, "utf8"),
  );
  return `added ${missing.length} entr${missing.length === 1 ? "y" : "ies"}`;
}

/** Ensure the LF-eol rule for the hook exists (CRLF would break the `#!/bin/sh` shebang on Windows). */
async function scaffoldGitattributes(ws: string): Promise<string> {
  const uri = vscode.Uri.file(path.join(ws, ".gitattributes"));
  const existing = await readFileOrEmpty(uri);
  const present = new Set(existing.split(/\r?\n/).map((l) => l.trim()));
  if (present.has(GITATTRIBUTES_LINE)) {
    return "already up to date";
  }
  const sep = existing.length && !existing.endsWith("\n") ? "\n" : "";
  await vscode.workspace.fs.writeFile(
    uri,
    Buffer.from(`${existing}${sep}${GITATTRIBUTES_LINE}\n`, "utf8"),
  );
  return "added LF rule";
}

// POSIX single-quote a value for safe embedding in the generated /bin/sh hook. `configDir`/
// `messageSetsDir` are window-scoped settings a checked-in `.vscode/settings.json` can supply, so a
// crafted value (e.g. `"; rm -rf ~ #`) must not break out of its argument and run arbitrary shell on
// the next `git commit`. Single quotes disable every sh metacharacter; an embedded `'` is closed,
// escaped as `\'`, and reopened.
function shSingleQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** The two folders setup's `check` runs on. */
interface CheckPaths {
  readonly configDir: string;
  readonly messagesDir: string;
}

/**
 * The `configDir` and `messageSetsDir` setup uses, or undefined after a refusal. Each is read as a
 * write (BACKLOG #5404): a dropped value refuses the whole setup rather than run on the substitute.
 * `check` is the pair as set, for the first commit's pre-flight on this machine. `hook` is the same
 * pair relative to the workspace for the committed hook, or undefined when either lies outside the
 * folder, which a user setting can name: the hook is committed, so every clone would run it against
 * this machine's layout (see committedRelativePath). Setup then writes no hook and says so.
 */
function hookPathValues(ws: string): { check: CheckPaths; hook: CheckPaths | undefined } | undefined {
  const cfg = writerPathSetting("configDir");
  if (cfg === undefined) {
    return undefined;
  }
  const msgs = writerPathSetting("messageSetsDir");
  if (msgs === undefined) {
    return undefined;
  }
  const check = { configDir: cfg, messagesDir: msgs };
  const configRel = committedRelativePath(ws, cfg);
  const messagesRel = committedRelativePath(ws, msgs);
  if (configRel === undefined || messagesRel === undefined) {
    const key = configRel === undefined ? "configDir" : "messageSetsDir";
    void vscode.window.showWarningMessage(
      `MessageFoundry: messagefoundry.${key} is not spelled as a path inside the workspace folder ${CASE_RULE}. ` +
        "The commit hook is " +
        "committed to the repository, so it names folders inside the workspace only; no commit hook was set up.",
    );
    return { check, hook: undefined };
  }
  return { check, hook: { configDir: configRel, messagesDir: messagesRel } };
}

async function scaffoldHook(bin: string, ws: string, paths: CheckPaths): Promise<string> {
  // Function replacements (not string ones) — a string replacement would interpret `$`-sequences
  // (e.g. `$'`) in the quoted value, re-injecting unescaped text.
  const hook = PRE_COMMIT_TEMPLATE.replace(
    /__CONFIG_DIR__/g,
    () => shSingleQuote(paths.configDir),
  ).replace(/__MESSAGES_DIR__/g, () => shSingleQuote(paths.messagesDir));
  const hookPath = path.join(ws, HOOKS_DIR, "pre-commit");
  await vscode.workspace.fs.createDirectory(vscode.Uri.file(path.join(ws, HOOKS_DIR)));
  await vscode.workspace.fs.writeFile(vscode.Uri.file(hookPath), Buffer.from(hook, "utf8"));
  fs.chmodSync(hookPath, 0o755);
  // Record the exec bit in git so it survives a clone on macOS/Linux (Windows FS has no x bit).
  // update-index --chmod needs the path in the index, so add it first.
  await git(bin, ["add", HOOK_REL, ".gitattributes"], ws);
  await git(bin, ["update-index", "--chmod=+x", HOOK_REL], ws);
  return "written (.mefor-hooks/pre-commit, +x)";
}

/** Whether `p` is spelled as a UNC path (`\\host\share`, or `//host/share`). */
function isUncSpelling(p: string): boolean {
  return /^[\\/]{2}/.test(p);
}

/**
 * Whether `ours` and `theirs` name one directory, compared by real path (ASCII case folded on Windows).
 *
 * Asynchronous, so a slow or unreachable share cannot block the extension host (BACKLOG #5404 item
 * 1); the synchronous realpath did. `ours` is a path the extension derives from the workspace
 * folder, and its real path is always read. `theirs` can come from the repository's own
 * `core.hooksPath` or from git's answer, so when it is SPELLED as a UNC share it is compared by
 * spelling alone, with no file-system call on it: a value written as a share is not opened. A
 * workspace on a mapped drive still matches its UNC spelling, through the real path of `ours`.
 * Open limits: a `theirs` spelled locally that reaches a share is still opened when its real path is
 * read, at least through a link or a mapped drive letter, though no longer on the extension host's
 * own thread. Setup runs only in a trusted window, where the repository's code runs. Exported, with
 * `win32` (by default, on Windows) choosing the fold, for the unit suite only.
 */
export async function sameDir(
  ours: string,
  theirs: string,
  win32: boolean = process.platform === "win32",
): Promise<boolean> {
  // ASCII A-Z only, not toLowerCase() (pathFold.ts, BACKLOG #5832).
  const fold = (p: string): string => (win32 ? foldAsciiCase(p) : p);
  const real = async (p: string): Promise<string> => {
    try {
      return fold(await fs.promises.realpath(p));
    } catch {
      return fold(p); // a folder that cannot be read: compare its spelling instead
    }
  };
  const spelledOurs = path.resolve(ours);
  const spelledTheirs = path.resolve(theirs);
  if (fold(spelledOurs) === fold(spelledTheirs)) {
    return true;
  }
  const [a, b] = await Promise.all([
    real(spelledOurs),
    isUncSpelling(spelledTheirs) ? Promise.resolve(fold(spelledTheirs)) : real(spelledTheirs),
  ]);
  return a === b;
}

/**
 * Point git at the hook only if safe: don't clobber a user's existing hooksPath or real hook.
 * `wired` is true only when core.hooksPath resolves to the hook's folder afterwards. Git resolves a
 * relative core.hooksPath from the repository's top level, so a workspace folder below that top
 * level is never wired: `.mefor-hooks` there would name a folder the hook was not written to.
 */
async function wireHooksPath(bin: string, ws: string): Promise<{ note: string; wired: boolean }> {
  const top = await git(bin, ["rev-parse", "--show-toplevel"], ws);
  const topDir = top.code === 0 ? top.stdout.trim() : "";
  if (!topDir || !(await sameDir(ws, topDir))) {
    return {
      note: "not set (git resolves core.hooksPath from the repository's top level, which is not this workspace folder)",
      wired: false,
    };
  }
  const current = await getHooksPath(bin, ws);
  if (current && (await sameDir(path.join(ws, HOOKS_DIR), path.resolve(topDir, current)))) {
    return { note: "already set", wired: true };
  }
  if (current) {
    void vscode.window.showWarningMessage(
      `MessageFoundry: core.hooksPath is already '${current}'. Left as-is — point it at '${HOOKS_DIR}' to enable checks.`,
    );
    return { note: `left as '${current}' (not clobbered)`, wired: false };
  }
  const realHook = vscode.Uri.file(path.join(ws, ".git", "hooks", "pre-commit"));
  try {
    await vscode.workspace.fs.stat(realHook);
    void vscode.window.showWarningMessage(
      "MessageFoundry: an existing .git/hooks/pre-commit was found. Left it alone — remove or merge it, then re-run setup.",
    );
    return { note: "not set (existing .git/hooks/pre-commit)", wired: false };
  } catch {
    // no existing real hook — safe to set
  }
  const res = await git(bin, ["config", "core.hooksPath", HOOKS_DIR], ws);
  return res.code === 0
    ? { note: `set to '${HOOKS_DIR}'`, wired: true }
    : { note: `failed: ${res.stderr.trim()}`, wired: false };
}

// "Where should this config repo be stored?" — the setup-time storage choice. Local-only suits a
// single-box (non-HA) engine, dev, or air-gapped work with no server; a shared remote is the durable,
// team- and HA-friendly home (see docs/VERSION-CONTROL.md). Offline-safe: we only *configure* the
// 'origin' remote — nothing is fetched or pushed here (the user pushes later from Source Control).
async function maybeAddRemote(bin: string, ws: string): Promise<void> {
  if (await getRemoteUrl(bin, ws)) {
    return; // respect an existing 'origin' — the storage location is already chosen
  }
  const pick = await vscode.window.showQuickPick(
    [
      {
        label: "On this machine only",
        detail:
          "Keep the repo local — fine for a single-box (non-HA) engine, dev, or air-gapped work with no server. You can add a remote later.",
        remote: false,
      },
      {
        label: "Store on a shared remote…",
        detail:
          "Recommended for high availability (multiple engine hosts), a team of developers, or off-machine backup. Any git host, or a bare repo on a network share.",
        remote: true,
      },
    ],
    {
      placeHolder: "Where should this config repo be stored? Nothing is contacted now — you push later.",
      ignoreFocusOut: true,
    },
  );
  if (!pick?.remote) {
    return; // local only (or cancelled)
  }
  await promptAndSetRemote(bin, ws);
}

// Prompt for a remote URL/path and point 'origin' at it (add if absent, update if present). Never
// fetches or pushes — provider-agnostic (any host, scp-style, or a local/UNC bare path). Returns
// whether a remote was set.
async function promptAndSetRemote(bin: string, ws: string, current?: string): Promise<boolean> {
  const url = await vscode.window.showInputBox({
    prompt: "Remote URL or path — any host, scp-style, or a local/UNC bare path (never GitHub-specific)",
    placeHolder: "https://forgejo.example/org/cfg.git · git@host:repo.git · \\\\server\\repos\\cfg.git",
    value: current ?? "",
    ignoreFocusOut: true,
  });
  if (!url?.trim()) {
    return false;
  }
  const exists = Boolean(await getRemoteUrl(bin, ws));
  const res = exists
    ? await git(bin, ["remote", "set-url", "origin", url.trim()], ws)
    : await git(bin, ["remote", "add", "origin", url.trim()], ws);
  if (res.code !== 0) {
    void vscode.window.showErrorMessage(`MessageFoundry: could not set remote — ${res.stderr.trim()}`);
    return false;
  }
  void vscode.window.showInformationMessage(
    "MessageFoundry: remote 'origin' set. Push later via the Source Control view (nothing was sent).",
  );
  return true;
}

// "MessageFoundry: Config Repo Storage Location" — view or change where the config repo is stored,
// after setup. The git 'origin' remote IS the storage location (single source of truth — no separate
// MEFOR setting to drift from it). This is a small, offline-safe FORM over it (a webview panel, not a
// modal QuickPick chain) so the current location and the local-vs-remote choice are visible at once.
export async function setRepoStorage(): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showErrorMessage("MessageFoundry: open a workspace folder first.");
    return;
  }
  if (!vscode.workspace.isTrusted) {
    // It runs git in the folder and rewrites its remote, and it hands off to setup.
    void vscode.window.showWarningMessage(UNTRUSTED_SETUP_MESSAGE);
    return;
  }
  const bin = await findGit();
  if (!bin) {
    await guideGitInstall();
    return;
  }
  if (!(await isRepo(bin, ws))) {
    const pick = await vscode.window.showInformationMessage(
      "This folder isn't under version control yet. Set it up first?",
      "Set Up Version Control & Checks",
      "Cancel",
    );
    if (pick === "Set Up Version Control & Checks") {
      await vscode.commands.executeCommand("messagefoundry.setupSourceControl");
    }
    return;
  }
  const current = (await getRemoteUrl(bin, ws)) ?? "";
  const panel = vscode.window.createWebviewPanel(
    "messagefoundry.repoStorage",
    "Config Repo Storage",
    vscode.ViewColumn.Active,
    { enableScripts: true },
  );
  panel.webview.html = renderRepoStorageHtml(panel.webview, current);
  panel.webview.onDidReceiveMessage(
    async (m: { command?: string; mode?: string; url?: string }) => {
      if (m.command === "cancel") {
        panel.dispose();
        return;
      }
      if (m.command !== "save") {
        return;
      }
      const hadRemote = Boolean(await getRemoteUrl(bin, ws));
      if (m.mode === "local") {
        if (hadRemote) {
          const res = await git(bin, ["remote", "remove", "origin"], ws);
          if (res.code !== 0) {
            postToWebview(panel.webview, { command: "error", text: `Could not remove remote — ${res.stderr.trim()}` });
            return;
          }
          void vscode.window.showInformationMessage(
            "MessageFoundry: now local-only. Your history stays on this machine; nothing was deleted on the remote.",
          );
        } else {
          void vscode.window.showInformationMessage("MessageFoundry: storage stays local-only.");
        }
        panel.dispose();
        return;
      }
      // Shared remote: set-url if one exists, else add. Never fetches/pushes — provider-agnostic.
      const url = (m.url ?? "").trim();
      if (!url) {
        postToWebview(panel.webview, { command: "error", text: "Enter a remote URL or path." });
        return;
      }
      const res = hadRemote
        ? await git(bin, ["remote", "set-url", "origin", url], ws)
        : await git(bin, ["remote", "add", "origin", url], ws);
      if (res.code !== 0) {
        postToWebview(panel.webview, { command: "error", text: `Could not set remote — ${res.stderr.trim()}` });
        return;
      }
      void vscode.window.showInformationMessage(
        "MessageFoundry: remote 'origin' set. Push later via the Source Control view (nothing was sent).",
      );
      panel.dispose();
    },
  );
}

function scEscape(v: string): string {
  return v
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderRepoStorageHtml(webview: vscode.Webview, current: string): string {
  const { nonce: n, token } = openChannel(webview);
  const isRemote = current.length > 0;
  const currentLabel = isRemote
    ? `Shared remote — <code>${scEscape(current)}</code>`
    : "On this machine only (local)";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px 20px; max-width: 640px; }
    h2 { margin: 0 0 4px; font-size: 16px; }
    .sub { color: var(--vscode-descriptionForeground); font-size: 13px; margin: 0 0 14px; }
    .current { margin: 0 0 16px; padding: 8px 10px; border: 1px solid var(--vscode-panel-border); border-radius: 4px;
               background: var(--vscode-editorWidget-background, rgba(127,127,127,0.06)); font-size: 13px; }
    .current code { font-family: var(--vscode-editor-font-family, monospace); }
    fieldset { border: none; padding: 0; margin: 0; }
    .opt { margin: 10px 0 2px; }
    .opt label { font-weight: 600; cursor: pointer; }
    .hint { color: var(--vscode-descriptionForeground); font-size: 12px; margin: 0 0 6px 22px; }
    #url { width: calc(100% - 22px); margin: 4px 0 0 22px; box-sizing: border-box;
           font-family: var(--vscode-editor-font-family, monospace); font-size: 12px;
           color: var(--vscode-input-foreground); background: var(--vscode-input-background);
           border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 2px; padding: 4px 6px; }
    #url:disabled { opacity: 0.5; }
    .err { color: var(--vscode-errorForeground); font-size: 12px; margin: 10px 0 0; min-height: 16px; }
    .actions { margin-top: 18px; display: flex; gap: 8px; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
             border: none; padding: 5px 14px; cursor: pointer; border-radius: 2px; font-size: 13px; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
  </style>
</head>
<body>
  ${STARTUP_BANNERS}
  <h2>Config Repo Storage</h2>
  <p class="sub">Where this MessageFoundry config repo lives. Nothing is contacted here — you push later from the Source Control view.</p>
  <div class="current">Current: ${currentLabel}</div>
  <fieldset>
    <div class="opt"><label><input type="radio" name="mode" value="local" ${isRemote ? "" : "checked"} /> On this machine only</label></div>
    <div class="hint">Fine for a single-box (non-HA) engine, dev, or air-gapped work with no server.</div>
    <div class="opt"><label><input type="radio" name="mode" value="remote" ${isRemote ? "checked" : ""} /> Shared remote</label></div>
    <div class="hint">Recommended for high availability (multiple engine hosts), a team, or off-machine backup. Any git host, scp-style, or a local/UNC bare path.</div>
    <input id="url" type="text" value="${scEscape(current)}" placeholder="https://forgejo.example/org/cfg.git &middot; git@host:repo.git &middot; \\\\server\\repos\\cfg.git" ${isRemote ? "" : "disabled"} />
  </fieldset>
  <div class="err" id="err"></div>
  <div class="actions">
    <button id="save">Save</button>
    <button id="cancel" class="secondary">Cancel</button>
  </div>
  <script nonce="${n}">${sourceControlScript(token)}
  </script>
</body>
</html>`;
}

function logResult(label: string, res: { stdout: string; stderr: string }): void {
  for (const part of [label, res.stdout.trim(), res.stderr.trim()]) {
    if (part) {
      logChecks(part);
    }
  }
}

// Every unignored file under the workspace folder is staged only once the user has chosen to commit,
// right before each baseline commit: staging before the prompts would leave the whole tree in the
// index after a Cancel, one stray `git commit` away from history (BACKLOG #5413). The pre-flight
// check reads the files on disk, not the index, so it needs nothing staged. The `.` pathspec keeps a
// workspace that is a subfolder of a larger repository from staging its parent's changes. Staged
// files setup's own gitignore entries match are then taken back out ({@link unstageIgnored}).
async function stageBaseline(bin: string, ws: string): Promise<boolean> {
  const res = await git(bin, ["add", "-A", "--", "."], ws);
  if (res.code !== 0) {
    logResult(`--- staging the baseline failed: git exit code ${res.code} ---`, res);
    void vscode.window.showErrorMessage(`MessageFoundry: could not stage the baseline — ${res.stderr.trim()}`);
    return false;
  }
  return unstageIgnored(bin, ws);
}

// The most paths, and the most characters of them, one `git rm --cached` call takes, so a long list
// stays well under the Windows command-line limit of 32,767 characters.
const UNSTAGE_BATCH_PATHS = 100;
const UNSTAGE_BATCH_CHARS = 8000;

/** `paths` in order, cut into batches of at most {@link UNSTAGE_BATCH_PATHS} paths and, where each
 *  path is shorter than it, {@link UNSTAGE_BATCH_CHARS} characters. */
function unstageBatches(paths: readonly string[]): string[][] {
  const batches: string[][] = [];
  let batch: string[] = [];
  let chars = 0;
  for (const p of paths) {
    if (batch.length > 0 && (batch.length >= UNSTAGE_BATCH_PATHS || chars + p.length > UNSTAGE_BATCH_CHARS)) {
      batches.push(batch);
      batch = [];
      chars = 0;
    }
    batch.push(p);
    chars += p.length + 1;
  }
  if (batch.length > 0) {
    batches.push(batch);
  }
  return batches;
}

/** The exact names among setup's gitignore entries, with no wildcard or folder slash. */
const LITERAL_ENTRIES = new Set(GITIGNORE_ENTRIES.filter((e) => !/[*?[\]/]/.test(e)));

/** The Checks-channel summary of the paths left out: a count per top-level folder, and a top-level
 *  file by name only when its name is one of setup's exact entries (such as the minted key), so no
 *  name that could hold message content is printed. */
function unstagedSummary(paths: readonly string[]): string[] {
  const counts = new Map<string, number>();
  let otherFiles = 0;
  for (const p of paths) {
    const slash = p.indexOf("/");
    if (slash >= 0) {
      const head = `${p.slice(0, slash)}/`;
      counts.set(head, (counts.get(head) ?? 0) + 1);
    } else if (LITERAL_ENTRIES.has(p)) {
      counts.set(p, 1);
    } else {
      otherFiles += 1;
    }
  }
  const lines = [...counts].map(([head, n]) => {
    // A folder name is shown only when it is printable ASCII, so it cannot forge or reorder a line.
    const shown = /^[\x20-\x7e]+$/.test(head) ? head : "(a folder with an unprintable name)";
    return head.endsWith("/") ? `  ${shown} (${n} file${n === 1 ? "" : "s"})` : `  ${shown}`;
  });
  if (otherFiles > 0) {
    lines.push(`  ${otherFiles} other file(s) at the top level`);
  }
  return lines;
}

/** The paths `ls-files` printed with `-z`, or undefined after its failure is shown. Only the exit
 *  code is logged: its output names paths, which can hold message content. */
async function lsFiles(bin: string, ws: string, args: readonly string[]): Promise<Set<string> | undefined> {
  const res = await git(bin, ["ls-files", "-z", "--cached", "--ignored", ...args, "--", "."], ws);
  if (res.code !== 0) {
    logChecks(`--- listing ignored staged files failed: git exit code ${res.code} ---`);
    void vscode.window.showErrorMessage(
      `MessageFoundry: could not check the baseline for ignored files (git exit code ${res.code}).`,
    );
    return undefined;
  }
  return new Set(res.stdout.split("\0").filter((p) => p !== ""));
}

// `git add -A` never removes a path that is already in the index, so a file the user staged before
// setup wrote the gitignore, such as the minted TLS key, would still go into the baseline (BACKLOG
// #5413, #8237 item 2). So a staged path is taken back out of the index when both hold: the
// repository's own ignore rules ignore it (`--exclude-standard`, so a `!` negation that re-includes
// it, and each .gitignore's own base folder, are honoured), and one of setup's entries
// (GITIGNORE_ENTRIES) matches it, so a file the user force-added under one of their own rules stays
// staged. The file on disk is kept. Since the path is ignored, a later `git add -A` does not add it
// back either: it stays out of every commit until someone runs `git add -f`. The Checks channel says
// how many left before any is unstaged. A failure refuses the commit; the tree then stays staged, as
// a failed commit already leaves it (#8237 item 4).
async function unstageIgnored(bin: string, ws: string): Promise<boolean> {
  const byRules = await lsFiles(bin, ws, ["--exclude-standard"]);
  if (byRules === undefined) {
    return false;
  }
  const bySetup = byRules.size === 0 ? new Set<string>() : await lsFiles(bin, ws, GITIGNORE_ENTRIES.flatMap((p) => ["-x", p]));
  if (bySetup === undefined) {
    return false;
  }
  const ignored = [...byRules].filter((p) => bySetup.has(p));
  if (ignored.length === 0) {
    return true;
  }
  logChecks(
    [
      `Leaving out of the baseline ${ignored.length} staged file(s) that setup's .gitignore entries match ` +
        "(kept on disk; `git add -f` adds one back):",
      ...unstagedSummary(ignored),
    ].join("\n"),
  );
  showChecks();
  for (const batch of unstageBatches(ignored)) {
    // --literal-pathspecs, so a file name holding `*` or `:(` names only itself. -f, because with no
    // HEAD git refuses an index entry whose file changed since `add -A`, such as a live engine's log
    // or store; --cached keeps the removal to the index, so the file itself is never touched.
    const rm = await git(bin, ["--literal-pathspecs", "rm", "--cached", "-f", "-q", "--", ...batch], ws);
    if (rm.code !== 0) {
      // Only the exit code: git's message names the path it refused.
      logChecks(`--- unstaging ignored files failed: git exit code ${rm.code} ---`);
      void vscode.window.showErrorMessage(
        `MessageFoundry: could not take ignored files out of the baseline (git exit code ${rm.code}).`,
      );
      return false;
    }
  }
  return true;
}

// The first commit is the project's BASELINE snapshot. Rather than run `git commit` blind and let the
// freshly-installed hook block it with a bare "bypass with --no-verify" (which reads as a dead-end and
// teaches bypass on day one), we PRE-FLIGHT the same gate and branch on the result. Exit 0 iff no
// REQUIRED check failed — advisories (e.g. dead-config) print but never block (checks.py / __main__).
// A required failure doesn't stop the baseline: the seed is conventionally exempt, so we offer to
// commit it and fix forward, with the details one click away — never leading with --no-verify.
async function maybeFirstCommit(bin: string, ws: string, paths: CheckPaths, text: SetupText): Promise<void> {
  // Only a repository with no commits yet gets a baseline. In one with history, staging the whole
  // tree would sweep the user's work in progress into a commit named "Initial commit".
  if ((await git(bin, ["rev-parse", "--verify", "-q", "HEAD"], ws)).code === 0) {
    void vscode.window.showInformationMessage(text.hasHistory);
    return;
  }
  const pick = await vscode.window.showInformationMessage(
    "Make the first commit now? MessageFoundry will run the checks first so you can see the results.",
    "Run checks & commit",
    "Skip",
  );
  if (pick !== "Run checks & commit") {
    return;
  }

  logChecks("--- pre-flight: messagefoundry check ---");
  // The folders setup read at its start, so the pre-flight judges the ones the hook names.
  const chk = await run(["check", "--config", paths.configDir, "--messages", paths.messagesDir], ws);
  logResult("", chk);

  if (chk.code === 0) {
    if (!(await stageBaseline(bin, ws))) {
      return;
    }
    const res = await git(bin, ["commit", "-m", text.commitMessage], ws);
    logResult("--- baseline commit ---", res);
    if (res.code === 0) {
      void vscode.window.showInformationMessage(
        "MessageFoundry: baseline committed — all required checks passed. ✓",
      );
    } else {
      showChecks();
      void vscode.window.showWarningMessage(text.commitFailed);
    }
    return;
  }

  // A required check failed. Offer the baseline anyway (fix-forward) — the seed commit is the only one
  // exempted; every commit after it runs the hook.
  showChecks();
  const choice = await vscode.window.showWarningMessage(
    text.offerBaseline,
    "Commit baseline anyway",
    "Show details",
    "Cancel",
  );
  if (choice === "Commit baseline anyway") {
    // Logged before git runs: the stamped line is the timed record of the bypass itself.
    logChecks(baselineBypassRecord(chk.code));
    if (!(await stageBaseline(bin, ws))) {
      return;
    }
    const res = await git(
      bin,
      ["commit", "-m", text.commitMessage, "--no-verify"],
      ws,
    );
    logResult(`--- baseline commit (hooks skipped): git exit code ${res.code} ---`, res);
    if (res.code === 0) {
      void vscode.window.showInformationMessage(text.committedAnyway);
    } else {
      void vscode.window.showErrorMessage(`MessageFoundry: commit failed — ${res.stderr.trim()}`);
    }
  } else if (choice === "Show details") {
    showChecks();
  }
}
