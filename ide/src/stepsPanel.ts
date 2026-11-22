// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Per-panel projection state for the Steps editor (stepsView.ts). One StepsEditorProvider serves every
// Steps panel, so anything a panel's render() derives from ITS parse must live with that panel, never on
// the provider: two open Steps editors would otherwise read each other's projection (BACKLOG #5843).
// Kept free of `vscode` so the unit suite can load it.
import type { LensParseResult } from "./stepsModel";

/** A handler's recognized message type, for the HL7 field picker's scope (ADR 0104 section 2.3 P2). */
export interface HandlerType {
  acceptsTypes?: string[];
  inferredType?: { code?: string; trigger?: string };
}

/**
 * What ONE panel's last render projected: each element's message type and role. A projection of that
 * panel's current parse, never persisted state; `update` replaces all of it wholesale, as render() does.
 */
export class StepsPanelProjection {
  private types = new Map<string, HandlerType>();
  private roles = new Map<string, "handler" | "router">();

  update(parse: LensParseResult): void {
    this.types = new Map(
      parse.handlers.map((h) => [
        h.handler,
        { acceptsTypes: h.accepts_types, inferredType: h.inferred_type },
      ]),
    );
    this.roles = new Map(parse.handlers.map((h) => [h.handler, h.role ?? "handler"]));
  }

  typeOf(handler: string): HandlerType | undefined {
    return this.types.get(handler);
  }

  /** The element's role; an element this projection does not know reads as a Handler, as before. */
  roleOf(handler: string): "handler" | "router" {
    return this.roles.get(handler) ?? "handler";
  }
}
