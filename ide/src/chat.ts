// @messagefoundry chat participant. Provider-agnostic: it uses whichever model the user picked in
// VS Code's Chat view (Copilot/Enterprise under their BAA, Claude, etc.) — we never bundle a vendor
// or ship keys. PHI boundary: we only ever attach code + the config graph (names) — never message
// bodies / patient data — regardless of the chosen model.
import * as vscode from "vscode";
import { assistantState, resolveAiPolicy } from "./aiPolicy";
import { aiContextCharLimit } from "./cli";
import { GraphProvider } from "./graphTree";

const PRIMER = `You are an assistant embedded in the MessageFoundry VS Code extension. MessageFoundry is a
code-first Python HL7 v2 integration engine. Users author config modules that declare named
Connections and decorate Router/Handler functions:
- inbound(name, MLLP(host=..., port=...) | File(directory=...), router="..."); outbound(name, ...)
- @router(name): def route(msg) -> list[str]  (handler names to forward to; [] = routed nowhere = UNROUTED)
- @handler(name): def handle(msg) -> Send(to, msg) | None  (None = FILTERED). Read fields with
  msg["SEG-F.C"] / msg.field("..."); write with msg["SEG-F.C"] = "...". Return Send("outbound_name", msg).
Dispositions: RECEIVED (>=1 delivery), UNROUTED, FILTERED, ERROR (parse/validation/script failure).
Be concise and concrete; prefer runnable code using this exact API. There is no declarative
YAML/ChannelConfig (it was removed). PHI: never request or include real patient data — use synthetic
or de-identified examples only.`;

export const COMMAND_TASKS: Record<string, string> = {
  explain: "Explain what the user selected (an HL7 field path, a Router, or a Handler) clearly and briefly.",
  transform:
    "Draft a MessageFoundry @handler implementing the transform the user describes. Output runnable code using the msg[...] read/write API and Send(...).",
  router:
    'Draft a MessageFoundry @router implementing the routing policy the user describes: def route(msg) -> list[str] returning the handler name(s) to forward to ([] = routed nowhere = UNROUTED). Decide with fast field peeks (msg["MSH-9.1"] etc.); keep it pure (no side effects) and light — routing is the hot path.',
  review:
    "Review the user's active Router/Handler code for correctness, PHI-leak risks (e.g. logging full message bodies at INFO+), and missing/!wrong dispositions. List concrete, actionable issues.",
  migrate:
    "Translate the Mirth (Rhino JavaScript) transformer/filter — or the Corepoint mapping — the user pastes into an equivalent MessageFoundry Router and/or Handler. Map a Mirth filter to router filtering (or a @handler returning None = FILTERED) and a transformer to a @handler transform, using the msg[...] read/write API and Send(...). Call out source logic that does NOT translate — message-mutating globals, channel-scoped state, DB/network writes — since Routers/Handlers must be pure (only a read-only db_lookup is allowed). Use synthetic values in any example, never real PHI.",
  test:
    "Fabricate a synthetic, conformant HL7 v2 sample that exercises the field paths the active Router/Handler reads, ready to paste into the Test Bench. Cover the segments/fields the code touches, and state which disposition it should drive (PROCESSED / FILTERED / UNROUTED) and why. Use only fabricated synthetic data — invented names, MRNs, dates — never real PHI.",
};

function graphSummary(graph: GraphProvider): string {
  const g = graph.getGraph();
  if (!g) {
    return "";
  }
  const fmt = (xs: string[]) => (xs.length ? xs.join(", ") : "none");
  return [
    "Current config graph (names only — no message data):",
    `- inbound: ${fmt(g.inbound.map((c) => `${c.name} (${c.type} → ${c.router})`))}`,
    `- outbound: ${fmt(g.outbound.map((c) => c.name))}`,
    `- routers: ${fmt(g.routers.map((r) => r.name))}`,
    `- handlers: ${fmt(g.handlers.map((h) => h.name))}`,
  ].join("\n");
}

/** The active editor's Python code — the selection if there is one, else the whole document; "" if
 * the active editor isn't Python. Returned *uncapped*; the caller applies the configurable cap. */
function activeCode(): string {
  const ed = vscode.window.activeTextEditor;
  if (!ed || ed.document.languageId !== "python") {
    return "";
  }
  const sel = ed.selection;
  return sel.isEmpty ? ed.document.getText() : ed.document.getText(sel);
}

export interface CappedCode {
  text: string; // possibly-truncated code, ready to embed (carries a marker when truncated)
  truncated: boolean; // whether the cap actually cut anything
  shownChars: number; // characters of the original code retained
  totalChars: number; // original length
}

/**
 * Cap editor code to `limit` characters before it is attached to an AI request. Pure + testable.
 *
 * When the code fits, it passes through untouched. When it doesn't, we cut on the last line boundary
 * within the budget (never mid-line) and append a Python-comment marker, so both the model and the
 * user can see the tail was withheld — *silent* truncation would let the model confidently answer
 * about code it never saw. A single over-long line with no newline in the window falls back to a hard
 * cut rather than sending nothing. `limit <= 0` keeps no code (the marker is then unused by the
 * caller, which drops a zero-length block).
 */
export function capCode(code: string, limit: number): CappedCode {
  const totalChars = code.length;
  if (totalChars <= limit) {
    return { text: code, truncated: false, shownChars: totalChars, totalChars };
  }
  const hard = code.slice(0, limit);
  const lastNl = hard.lastIndexOf("\n");
  const kept = lastNl > 0 ? hard.slice(0, lastNl) : hard; // back off to a whole-line boundary
  const marker =
    `\n# … (truncated: ${kept.length} of ${totalChars} chars sent; ` +
    `raise messagefoundry.ai.contextCharLimit to include more)`;
  return { text: kept + marker, truncated: true, shownChars: kept.length, totalChars };
}

export function registerChat(context: vscode.ExtensionContext, graph: GraphProvider): void {
  if (!vscode.chat?.createChatParticipant) {
    return; // older host without the Chat API
  }

  const handler: vscode.ChatRequestHandler = async (request, _chatContext, stream, token) => {
    // Honor the centrally-governed AI policy before touching any model: a "off" / managed-provider /
    // unpermitted policy disables assistance entirely (see aiPolicy.assistantState).
    const state = assistantState(await resolveAiPolicy(context));
    if (!state.enabled) {
      stream.markdown(state.message ?? "AI assistance is unavailable under your MessageFoundry policy.");
      return;
    }

    const parts = [PRIMER];
    const summary = graphSummary(graph);
    if (summary) {
      parts.push(summary);
    }
    // DATA-SCOPE CAP: in MVP only code_only context is ever attached (the config graph *names* above
    // and the active editor *code* below). Nothing above code_only — message bodies / patient data —
    // may be attached here regardless of mode/provider until later phases build that path. The size
    // cap (messagefoundry.ai.contextCharLimit, default 8000) additionally bounds how much of the
    // user's own code egresses; oversized files are cut on a line boundary and marked.
    const limit = aiContextCharLimit();
    const capped = capCode(activeCode(), limit);
    if (capped.shownChars > 0) {
      parts.push("Active editor code:\n```python\n" + capped.text + "\n```");
    }
    // Tell the user when their file was cut to fit the budget — but stay silent when they've
    // intentionally set the limit to 0 (graph names only), which would otherwise nag every message.
    if (capped.truncated && limit > 0) {
      stream.markdown(
        `_Sent the first ${capped.shownChars.toLocaleString()} of ` +
          `${capped.totalChars.toLocaleString()} characters of the active file (limit ` +
          `${limit.toLocaleString()}). Select a region, or raise ` +
          "`messagefoundry.ai.contextCharLimit`, to include more._\n\n",
      );
    }
    const task = request.command ? COMMAND_TASKS[request.command] : undefined;
    if (task) {
      parts.push("Task: " + task);
    }
    parts.push("User request: " + request.prompt);

    let model = request.model;
    if (!model) {
      const models = await vscode.lm.selectChatModels();
      model = models[0];
    }
    if (!model) {
      stream.markdown(
        "No language model is available. Pick one in the Chat view (e.g. GitHub Copilot, which can run under your organization's BAA).",
      );
      return;
    }

    try {
      const response = await model.sendRequest(
        [vscode.LanguageModelChatMessage.User(parts.join("\n\n"))],
        {},
        token,
      );
      for await (const chunk of response.text) {
        stream.markdown(chunk);
      }
    } catch (e) {
      stream.markdown(`\n\n_Model request failed: ${String(e)}_`);
    }
  };

  const participant = vscode.chat.createChatParticipant("messagefoundry.chat", handler);
  participant.iconPath = vscode.Uri.joinPath(context.extensionUri, "media", "icon.png");
  context.subscriptions.push(participant);
}
