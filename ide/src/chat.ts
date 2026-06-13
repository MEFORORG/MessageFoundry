// @messagefoundry chat participant. Provider-agnostic: it uses whichever model the user picked in
// VS Code's Chat view (Copilot/Enterprise under their BAA, Claude, etc.) — we never bundle a vendor
// or ship keys. PHI boundary: we only ever attach code + the config graph (names) — never message
// bodies / patient data — regardless of the chosen model.
import * as vscode from "vscode";
import { assistantState, resolveAiPolicy } from "./aiPolicy";
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

const COMMAND_TASKS: Record<string, string> = {
  explain: "Explain what the user selected (an HL7 field path, a Router, or a Handler) clearly and briefly.",
  transform:
    "Draft a MessageFoundry @handler implementing the transform the user describes. Output runnable code using the msg[...] read/write API and Send(...).",
  review:
    "Review the user's active Router/Handler code for correctness, PHI-leak risks (e.g. logging full message bodies at INFO+), and missing/!wrong dispositions. List concrete, actionable issues.",
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

function activeCode(): string {
  const ed = vscode.window.activeTextEditor;
  if (!ed || ed.document.languageId !== "python") {
    return "";
  }
  const sel = ed.selection;
  const text = sel.isEmpty ? ed.document.getText() : ed.document.getText(sel);
  return text.slice(0, 8000); // cap; this is code, not PHI
}

export function registerChat(context: vscode.ExtensionContext, graph: GraphProvider): void {
  if (!vscode.chat?.createChatParticipant) {
    return; // older host without the Chat API
  }

  const handler: vscode.ChatRequestHandler = async (request, _chatContext, stream, token) => {
    // Honor the centrally-governed AI policy before touching any model: a "off" / managed-provider /
    // unpermitted policy disables assistance entirely (see aiPolicy.assistantState).
    const state = assistantState(await resolveAiPolicy());
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
    // may be attached here regardless of mode/provider until later phases build that path.
    const code = activeCode();
    if (code) {
      parts.push("Active editor code:\n```python\n" + code + "\n```");
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
