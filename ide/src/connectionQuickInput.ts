// Keyboard-first new-connection wizard (#221e): a native multi-step QuickInput (the official
// multiStepInput pattern — chained QuickPick/InputBox with Back navigation) that is an alternative to
// the connectionEditor webview form. It collects the same fields and writes through the SAME
// `messagefoundry connection upsert` CLI, so the two entry points stay behaviourally identical. The
// answer→ConnObj mapping, argv, and validators live in the vscode-free connectionWizardModel (tested
// node-side); this file is just the Extension-Host plumbing.
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";
import {
  WIZARD_TRANSPORTS,
  buildConnObj,
  connectionUpsertArgs,
  settingKeysFor,
  shouldSaveConnection,
  validateName,
  validatePort,
  validateRequired,
  type WizardConnObj,
  type WizardState,
} from "./connectionWizardModel";
import { InputFlowAction, MultiStepInput, type InputStep } from "./multiStepInput";

export interface WizardOpts {
  routers: string[];
  onSaved?: () => void;
}

const TITLE = "New Connection";

/**
 * How many steps the wizard shows. Once direction+transport are both chosen the count is fully
 * determined, so it is LOCKED into `state.totalSteps` (by pickTransport) and returned verbatim
 * thereafter — the "Step X of N" header then stays stable for the tail steps instead of shrinking as
 * the optimistic (inbound/mllp) defaults resolve to the real choices.
 */
function totalStepsFor(state: WizardState): number {
  if (state.totalSteps !== undefined) {
    return state.totalSteps;
  }
  // direction + transport + name = 3, then per-transport settings, then (inbound) router.
  let n = 3;
  const dir = state.direction ?? "inbound";
  const transport = state.transport ?? "mllp";
  n += settingKeysFor(transport, dir).length;
  if (dir === "inbound") {
    n += 1; // router
  }
  return n;
}

/**
 * Run the wizard. Cancels silently (Esc/Back-off-the-front). On completion it shells `connection
 * upsert` (same CLI, same validation/comment-preserving write as the form), refreshes the graph via
 * `onSaved`, and offers a Promote — mirroring the webview form's post-save flow.
 */
export async function newConnectionWizard(opts: WizardOpts): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
    return;
  }

  const state: WizardState = {};

  const directionItems = [
    { label: "Inbound", description: "receives messages", detail: "MLLP/file listener → a Router" },
    { label: "Outbound", description: "sends messages", detail: "a Handler delivers to it" },
  ];

  const pickDirection: InputStep = async (input) => {
    const pick = await input.showQuickPick({
      title: TITLE,
      step: 1,
      totalSteps: totalStepsFor(state),
      placeholder: "Direction — does this connection receive or send?",
      items: directionItems,
      // On Back into this step, re-select whatever the user had chosen before (F8).
      activeItem: state.direction
        ? directionItems[state.direction === "outbound" ? 1 : 0]
        : undefined,
    });
    state.direction = pick.label === "Outbound" ? "outbound" : "inbound";
    return pickTransport;
  };

  const pickTransport: InputStep = async (input) => {
    const pick = await input.showQuickPick({
      title: TITLE,
      step: 2,
      totalSteps: totalStepsFor(state),
      placeholder: "Transport",
      items: WIZARD_TRANSPORTS.map((t) => ({ label: t })),
      activeItem: state.transport ? { label: state.transport } : undefined,
    });
    state.transport = pick.label;
    // Both determinants are now known → lock the total so the tail header stays stable (F8).
    state.totalSteps = totalStepsFor({ ...state, totalSteps: undefined });
    return enterName;
  };

  const enterName: InputStep = async (input) => {
    state.name = await input.showInputBox({
      title: TITLE,
      step: 3,
      totalSteps: totalStepsFor(state),
      value: state.name ?? "",
      prompt: "Connection name — convention [TYPE]_[PARTNER]_[MESSAGE], e.g. IB_ACME_ADT",
      validate: async (v) => validateName(v),
    });
    return firstSettingStep(state);
  };

  // ---- per-transport settings (host/port/directory), then the inbound router ----
  const enterHost: InputStep = async (input) => {
    state.host = await input.showInputBox({
      title: TITLE,
      step: 4,
      totalSteps: totalStepsFor(state),
      value: state.host ?? "",
      prompt: "Host / peer address",
      validate: async (v) => validateRequired(v, "Host"),
    });
    return enterPort;
  };

  const enterPort: InputStep = async (input) => {
    const dir = state.direction ?? "inbound";
    const step = dir === "outbound" && settingKeysFor(state.transport ?? "", dir).includes("host") ? 5 : 4;
    state.port = await input.showInputBox({
      title: TITLE,
      step,
      totalSteps: totalStepsFor(state),
      value: state.port ?? "",
      prompt: "Port (1–65535)",
      validate: async (v) => validatePort(v),
    });
    return state.direction === "inbound" ? pickRouter : undefined;
  };

  const enterDirectory: InputStep = async (input) => {
    state.directory = await input.showInputBox({
      title: TITLE,
      step: 4,
      totalSteps: totalStepsFor(state),
      value: state.directory ?? "",
      prompt: "Directory (watched for inbound, written for outbound)",
      validate: async (v) => validateRequired(v, "Directory"),
    });
    return state.direction === "inbound" ? pickRouter : undefined;
  };

  const pickRouter: InputStep = async (input) => {
    // Inbound feeds a Router (defined in a .py module). Offer the known router names; allow a free entry
    // when the graph has none yet (the analyst may be wiring the router next). An empty pick is allowed.
    if (opts.routers.length === 0) {
      state.router = await input.showInputBox({
        title: TITLE,
        step: totalStepsFor(state),
        totalSteps: totalStepsFor(state),
        value: state.router ?? "",
        prompt: "Router name this inbound feeds (define it in a .py module) — blank to wire later",
        validate: async () => undefined,
      });
      return undefined;
    }
    const pick = await input.showQuickPick({
      title: TITLE,
      step: totalStepsFor(state),
      totalSteps: totalStepsFor(state),
      placeholder: "Router this inbound feeds",
      items: opts.routers.map((r) => ({ label: r })),
      activeItem: state.router ? { label: state.router } : undefined,
    });
    state.router = pick.label;
    return undefined;
  };

  /** Which settings step to run first for the chosen transport (or straight to the router / finish). */
  function firstSettingStep(s: WizardState): InputStep | undefined {
    const dir = s.direction ?? "inbound";
    const keys = settingKeysFor(s.transport ?? "", dir);
    if (keys.includes("host")) {
      return enterHost;
    }
    if (keys.includes("port")) {
      return enterPort;
    }
    if (keys.includes("directory")) {
      return enterDirectory;
    }
    return dir === "inbound" ? pickRouter : undefined;
  }

  let completed = false;
  try {
    completed = await MultiStepInput.run(pickDirection);
  } catch (e) {
    if (e === InputFlowAction.cancel) {
      return; // user dismissed — nothing to save
    }
    throw e;
  }
  // Gate the write on EXPLICIT completion, NOT on required-field presence (F1): run() resolves
  // normally on a cancel too (the step chain is unwound internally), and by step 3 name/direction/
  // transport are all set — so a cancel on a later settings/router step would slip past a required-
  // field check and save a partial connection. `completed` is true only when the chain reached its
  // terminal step.
  state.completed = completed;
  if (!shouldSaveConnection(state)) {
    return; // cancelled / dismissed at some step — nothing to save
  }

  const conn = buildConnObj(state);
  await saveConnection(conn, ws, opts.onSaved);
}

/** Shell `connection upsert` with the assembled ConnObj; surface CLI/validation errors, else offer Promote. */
async function saveConnection(
  conn: WizardConnObj,
  ws: string,
  onSaved?: () => void,
): Promise<void> {
  try {
    await runJson(connectionUpsertArgs(configDir(), conn), ws);
  } catch (e) {
    void vscode.window.showErrorMessage(
      `MessageFoundry: could not save ${conn.name} — ${e instanceof Error ? e.message : String(e)}`,
    );
    return;
  }
  onSaved?.();
  const pick = await vscode.window.showInformationMessage(
    `MessageFoundry: saved ${conn.name} to connections.toml.`,
    "Promote…",
  );
  if (pick === "Promote…") {
    void vscode.commands.executeCommand("messagefoundry.promote");
  }
}
