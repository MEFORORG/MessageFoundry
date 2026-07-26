// Live, no-server completion: HL7 field paths inside msg["..."]/.field("...")/.set("...") from the
// bundled hl7schema.json — segment suggestions ranked by the enclosing @handler's declared message
// type (accepts=message_type_of / the inert message_type= kwarg) via the bundled hl7structures.json
// (completionScope.ts; rank-never-remove — no artifact / no typed handler keeps today's order) —
// occurrence=/repetition= snippets after the path argument of .set()/.field(), and connection/router
// names in Send("...")/router="..." from the cached graph. All answered from in-memory data — no
// per-keystroke Python.
import * as vscode from "vscode";
import {
  KWARG_SNIPPETS,
  KwargContext,
  SegmentRank,
  enclosingHandlerTypes,
  kwargContext,
  scopedSegmentSortText,
} from "./completionScope";
import { GraphProvider } from "./graphTree";
import { Hl7Schema, loadSchema, loadStructures, segmentSortText } from "./hl7schema";

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
  rank: ReadonlyMap<string, SegmentRank> | undefined,
): vscode.CompletionItem[] {
  const range = rangeFor(partial, pos);
  const items: vscode.CompletionItem[] = [];
  const dash = partial.indexOf("-");

  if (dash < 0) {
    for (const seg of Object.keys(schema.segments)) {
      const r = rank?.get(seg);
      // An out-of-scope segment stays offered (rank, never remove) with the visible miss marker.
      const item = new vscode.CompletionItem(
        r?.description ? { label: seg, description: r.description } : seg,
        vscode.CompletionItemKind.Class,
      );
      item.insertText = `${seg}-`;
      item.range = range;
      // No rank (no structures artifact / no typed enclosing handler) → today's order, byte-identical.
      item.sortText = r ? r.sortText : segmentSortText(seg); // common segments first, then alphabetical
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

/** The occurrence=/repetition= snippet items for a KWARG_CTX hit (kwargs already written in the
 *  call are skipped — a duplicate keyword argument is a Python syntax error). */
function kwargItems(kw: KwargContext, pos: vscode.Position): vscode.CompletionItem[] {
  const range = rangeFor(kw.partial, pos);
  return KWARG_SNIPPETS.filter((s) => !kw.present.includes(s.name)).map((s) => {
    const item = new vscode.CompletionItem(s.label, vscode.CompletionItemKind.Snippet);
    item.insertText = new vscode.SnippetString(s.insert);
    item.range = range;
    item.detail = `MessageFoundry: ${s.detail}`;
    item.documentation = new vscode.MarkdownString(s.doc);
    return item;
  });
}

const PATH_CTX = /(?:\[|\.field\(|\.set\()\s*"([^"]*)$/;
const SEND_CTX = /\bSend\(\s*"([^"]*)$/;
const ROUTER_CTX = /\brouter\s*=\s*"([^"]*)$/;

export function registerCompletion(context: vscode.ExtensionContext, graph: GraphProvider): void {
  const schema = loadSchema(context.extensionPath);
  const structures = loadStructures(context.extensionPath); // once at registration, like loadSchema

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
        // Segment stage only: rank by the enclosing handler's declared message type — a pure
        // in-memory text pass + the bundled structures artifact, still no per-keystroke Python.
        // undefined (no artifact / no typed handler) keeps today's order byte-identically.
        const rank = hl7[1].includes("-")
          ? undefined
          : scopedSegmentSortText(
              Object.keys(schema.segments),
              structures,
              enclosingHandlerTypes(document.getText(), position.line),
            );
        return pathItems(schema, hl7[1], position, rank);
      }
      // KWARG_CTX is disjoint from the string contexts above (it never fires inside a literal);
      // it surfaces on word-character typing / Ctrl+Space — no new trigger characters needed.
      const kwarg = kwargContext(prefix);
      if (kwarg) {
        return kwargItems(kwarg, position);
      }
      return undefined;
    },
  };

  context.subscriptions.push(
    vscode.languages.registerCompletionItemProvider({ language: "python" }, provider, '"', "-", "."),
  );
}
