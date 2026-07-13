// Live, no-server completion: HL7 field paths inside msg["..."]/.field("...")/.set("...") from the
// bundled hl7schema.json, and connection/router names in Send("...")/router="..." from the cached
// graph. All answered from in-memory data — no per-keystroke Python.
import * as vscode from "vscode";
import { GraphProvider } from "./graphTree";
import { Hl7Schema, loadSchema, segmentSortText } from "./hl7schema";

function rangeFor(partial: string, pos: vscode.Position): vscode.Range {
  return new vscode.Range(pos.line, pos.character - partial.length, pos.line, pos.character);
}

function nameItems(names: string[], partial: string, pos: vscode.Position): vscode.CompletionItem[] {
  const range = rangeFor(partial, pos);
  return names.map((n) => {
    const item = new vscode.CompletionItem(n, vscode.CompletionItemKind.Value);
    item.range = range;
    item.preselect = true; // highlight the real connection name over Copilot's guessed ghost text
    item.detail = "MessageFoundry connection";
    return item;
  });
}

const RETRIGGER: vscode.Command = { command: "editor.action.triggerSuggest", title: "" };

function pathItems(
  schema: Hl7Schema,
  partial: string,
  pos: vscode.Position,
): vscode.CompletionItem[] {
  const range = rangeFor(partial, pos);
  const items: vscode.CompletionItem[] = [];
  const dash = partial.indexOf("-");

  if (dash < 0) {
    for (const seg of Object.keys(schema.segments)) {
      const item = new vscode.CompletionItem(seg, vscode.CompletionItemKind.Class);
      item.insertText = `${seg}-`;
      item.range = range;
      item.sortText = segmentSortText(seg); // common segments first, then alphabetical
      item.command = RETRIGGER; // chain into field suggestions
      items.push(item);
    }
    return items;
  }

  const seg = partial.slice(0, dash);
  const segDef = schema.segments[seg];
  if (!segDef) {
    return items;
  }
  const rest = partial.slice(dash + 1);
  const dot = rest.indexOf(".");

  if (dot < 0) {
    for (const f of segDef.fields) {
      const label = `${seg}-${f.index}`;
      const item = new vscode.CompletionItem(
        { label, description: f.name ?? f.datatype ?? "" },
        vscode.CompletionItemKind.Field,
      );
      item.insertText = label;
      item.range = range;
      if (f.components.length > 0) {
        item.command = RETRIGGER;
      }
      items.push(item);
    }
    return items;
  }

  const fieldIndex = Number.parseInt(rest.slice(0, dot), 10);
  const field = segDef.fields.find((f) => f.index === fieldIndex);
  if (!field) {
    return items;
  }
  for (const c of field.components) {
    const label = `${seg}-${fieldIndex}.${c.index}`;
    const item = new vscode.CompletionItem(
      { label, description: c.name ?? c.datatype ?? "" },
      vscode.CompletionItemKind.Field,
    );
    item.insertText = label;
    item.range = range;
    items.push(item);
  }
  return items;
}

const PATH_CTX = /(?:\[|\.field\(|\.set\()\s*"([^"]*)$/;
const SEND_CTX = /\bSend\(\s*"([^"]*)$/;
const ROUTER_CTX = /\brouter\s*=\s*"([^"]*)$/;

export function registerCompletion(context: vscode.ExtensionContext, graph: GraphProvider): void {
  const schema = loadSchema(context.extensionPath);

  const provider: vscode.CompletionItemProvider = {
    provideCompletionItems(document, position) {
      const prefix = document.lineAt(position.line).text.slice(0, position.character);

      const send = SEND_CTX.exec(prefix);
      if (send) {
        return nameItems(graph.getGraph()?.outbound.map((o) => o.name) ?? [], send[1], position);
      }
      const router = ROUTER_CTX.exec(prefix);
      if (router) {
        const routerNames = (graph.getGraph()?.routers ?? []).map((r) => r.name);
        return nameItems(routerNames, router[1], position);
      }
      const hl7 = PATH_CTX.exec(prefix);
      if (hl7 && schema) {
        return pathItems(schema, hl7[1], position);
      }
      return undefined;
    },
  };

  context.subscriptions.push(
    vscode.languages.registerCompletionItemProvider({ language: "python" }, provider, '"', "-", "."),
  );
}
