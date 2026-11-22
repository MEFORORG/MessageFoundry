// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Per-panel projection state for the Steps editor (stepsView.ts). One StepsEditorProvider serves every
// Steps panel, so anything a panel's render() derives from ITS parse must live with that panel, never on
// the provider: two open Steps editors would otherwise read each other's projection (BACKLOG #5843).
// Kept free of `vscode` so the unit suite can load it.
import type { HandlerViewModel, LensParseResult, RowKind, RowViewModel } from "./stepsModel";

/** A handler's recognized message type, for the HL7 field picker's scope (ADR 0104 section 2.3 P2). */
export interface HandlerType {
  acceptsTypes?: string[];
  inferredType?: { code?: string; trigger?: string };
}

/** The anchor a structural insert is built from: the row's coordinates plus its fan-out flags. */
export interface StructuralAnchor {
  handler: string;
  lineStart: number;
  lineEnd: number;
  expectSrc?: string;
  kind: RowKind;
  appended?: boolean;
  scaffold?: string;
}

/** The anchor fields a webview message may carry. Untrusted, so every field is read defensively. */
export interface AnchorMessage {
  handler: string;
  lineStart: number;
  lineEnd: number;
  expectSrc?: unknown;
  kind?: unknown;
  appended?: unknown;
  scaffold?: unknown;
}

type ProjectedRow = Pick<RowViewModel, "kind" | "expectSrc" | "appended" | "scaffold">;

const rowKey = (handler: string, lineStart: number, lineEnd: number): string =>
  `${handler}\u0000${lineStart}\u0000${lineEnd}`;

/**
 * What ONE panel's last render projected: each element's message type and role, and each row's kind and
 * fan-out flags. A projection of that panel's current parse, never persisted state; `update` replaces
 * all of it wholesale, as render() does.
 */
export class StepsPanelProjection {
  private types = new Map<string, HandlerType>();
  private roles = new Map<string, "handler" | "router">();
  private rows = new Map<string, ProjectedRow>();

  update(parse: LensParseResult, handlers: readonly HandlerViewModel[]): void {
    this.types = new Map(
      parse.handlers.map((h) => [
        h.handler,
        { acceptsTypes: h.accepts_types, inferredType: h.inferred_type },
      ]),
    );
    this.roles = new Map(parse.handlers.map((h) => [h.handler, h.role ?? "handler"]));
    this.rows = new Map();
    for (const h of handlers) {
      for (const r of h.rows) {
        const { kind, expectSrc, appended, scaffold } = r;
        this.rows.set(rowKey(h.handler, r.lineStart, r.lineEnd), { kind, expectSrc, appended, scaffold });
      }
    }
  }

  typeOf(handler: string): HandlerType | undefined {
    return this.types.get(handler);
  }

  /** The element's role; an element this projection does not know reads as a Handler, as before. */
  roleOf(handler: string): "handler" | "router" {
    return this.roles.get(handler) ?? "handler";
  }

  /**
   * The anchor for a structural insert at the row a message names (BACKLOG #5844). The insert position
   * depends on the row's fan-out flags (stepsModel.isReturnRow: a mid-body append send takes an insert
   * after it, a return-collector footer before it), and a message built from `kind` alone carries none.
   * So the row's kind and flags come from THIS panel's projection when it holds the row the message
   * names (same handler and line range, and the same source when the message carries one); otherwise
   * from the message's own fields, as addDestination always sent them. `fallbackKind` is used only when
   * neither names a kind. Returns undefined for a message whose expectSrc is present but not a string:
   * dropping it there would run the op with no stale check at all, so the caller drops the message.
   */
  anchorFor(m: AnchorMessage, fallbackKind: RowKind = "send"): StructuralAnchor | undefined {
    if (m.expectSrc !== undefined && typeof m.expectSrc !== "string") {
      return undefined;
    }
    const expectSrc = m.expectSrc;
    const row = this.rows.get(rowKey(m.handler, m.lineStart, m.lineEnd));
    const flags =
      row !== undefined && (expectSrc === undefined || row.expectSrc === expectSrc)
        ? row
        : {
            kind: typeof m.kind === "string" ? (m.kind as RowKind) : fallbackKind,
            appended: m.appended === true,
            scaffold: typeof m.scaffold === "string" ? m.scaffold : undefined,
          };
    return {
      handler: m.handler,
      lineStart: m.lineStart,
      lineEnd: m.lineEnd,
      expectSrc,
      kind: flags.kind,
      appended: flags.appended === true,
      scaffold: flags.scaffold,
    };
  }
}
