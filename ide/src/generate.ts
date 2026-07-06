// "Generate Samples" — a guided flow over the `messagefoundry generate` CLI: pick a message type
// (from `generate --list`), choose triggers + a per-trigger count, and write a synthetic-but-
// conformant corpus into the Test Bench's message-sets folder. All data is synthetic — no PHI.
import * as path from "node:path";
import * as vscode from "vscode";
import { messageSetsDir, run, runJson, workspaceDir } from "./cli";

function err(message: string): void {
  void vscode.window.showErrorMessage(`MessageFoundry: ${message}`);
}

export async function generateSamples(): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    err("open a workspace folder first.");
    return;
  }

  let listing: Record<string, string[]>;
  try {
    listing = await runJson<Record<string, string[]>>(["generate", "--list"], ws);
  } catch (e) {
    err(`could not list message types — ${String(e)}`);
    return;
  }
  const types = Object.keys(listing);
  if (types.length === 0) {
    err("no message types are registered.");
    return;
  }

  const type = await vscode.window.showQuickPick(types, {
    placeHolder: "Message type to generate (synthetic — no PHI)",
  });
  if (!type) {
    return;
  }

  const triggers = listing[type] ?? [];
  const scope = await vscode.window.showQuickPick(
    [
      { label: `$(check-all) All ${triggers.length} triggers`, all: true },
      { label: "$(list-selection) Choose triggers…", all: false },
    ],
    { placeHolder: `${type}: which triggers?` },
  );
  if (!scope) {
    return;
  }
  let chosen: string[] | undefined;
  if (!scope.all) {
    const picks = await vscode.window.showQuickPick(triggers, {
      canPickMany: true,
      placeHolder: `${type} triggers to generate`,
    });
    if (!picks || picks.length === 0) {
      return;
    }
    chosen = picks;
  }

  const countStr = await vscode.window.showInputBox({
    prompt: "Messages per trigger",
    value: "5",
    validateInput: (v) =>
      /^\d+$/.test(v.trim()) && Number(v) > 0 ? undefined : "enter a positive integer",
  });
  if (countStr === undefined) {
    return;
  }
  const count = parseInt(countStr.trim(), 10);

  const setsDir = messageSetsDir();
  const baseAbs = path.isAbsolute(setsDir) ? setsDir : path.join(ws, setsDir);
  const outAbs = path.join(baseAbs, type.toLowerCase());

  const args = ["generate", "--type", type, "--count", String(count), "--out", outAbs];
  if (chosen) {
    args.push("--triggers", chosen.join(","));
  }

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `Generating ${type} messages…` },
    async () => {
      const res = await run(args, ws);
      if (res.code !== 0) {
        err(`generate failed — ${(res.stderr || res.stdout).trim() || "unknown error"}`);
        return;
      }
      const choice = await vscode.window.showInformationMessage(
        `MessageFoundry: generated ${type} messages into ${path.relative(ws, outAbs)}.`,
        "Reveal in Explorer",
      );
      if (choice === "Reveal in Explorer") {
        await vscode.commands.executeCommand("revealInExplorer", vscode.Uri.file(outAbs));
      }
    },
  );
}
