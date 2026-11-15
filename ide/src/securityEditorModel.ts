// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The host-side checks of the Security Settings editor (securityEditor.ts), kept free of `vscode` so
// the unit suite runs them (BACKLOG #5411). The editor writes the `[security]` posture, so each
// check fails closed: a refusal names what is wrong and nothing is run.
import * as path from "node:path";

import type { Field, FieldType } from "./securityEditorWebview";

/** The service-settings file the editor reads and writes, or why it may not. */
export type ConfigTarget = { readonly ok: true; readonly path: string } | { readonly ok: false; readonly problem: string };

/** Whether `target` lies strictly inside `root`. path.relative so a sibling sharing a name prefix
 *  does not match, and on Windows the comparison ignores case as the file system does. */
function inside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/** `target` with every symbolic link in the part of it that exists resolved. The rest, a file or
 *  folders not made yet, cannot be a link, so it is joined back as written. */
function resolveLinks(target: string, realpath: (p: string) => string): string {
  const tail: string[] = [];
  let at = target;
  for (;;) {
    try {
      return path.join(realpath(at), ...tail);
    } catch {
      const parent = path.dirname(at);
      if (parent === at) {
        // Not even the root resolves. Read as written, which the lexical check already passed.
        return path.join(at, ...tail);
      }
      tail.unshift(path.basename(at));
      at = parent;
    }
  }
}

/**
 * The absolute service-settings path for `setting` (`messagefoundry.serviceConfig`), which must name
 * a file inside the workspace folder `workspace` (BACKLOG #5411). The setting is workspace-scoped, so
 * a repository's own `.vscode/settings.json` can set it; this keeps such a setting from pointing the
 * security editor at a file elsewhere on the machine. A path that leaves the workspace, by `..`, by
 * being absolute elsewhere, or through a symbolic link, is refused, as is a blank or non-string
 * setting and one that names the workspace folder itself. `realpath` throws for a path that does not
 * exist, as fs.realpathSync does.
 */
export function securityConfigTarget(
  workspace: string,
  setting: unknown,
  realpath: (p: string) => string,
): ConfigTarget {
  if (typeof setting !== "string" || setting.trim() === "") {
    return { ok: false, problem: "messagefoundry.serviceConfig is blank or is not text" };
  }
  const root = path.resolve(workspace);
  const target = path.resolve(root, setting);
  const outside = {
    ok: false,
    problem: `messagefoundry.serviceConfig names ${JSON.stringify(setting)}, which is not a file inside the workspace folder`,
  } as const;
  if (!inside(root, target)) {
    return outside;
  }
  if (!inside(resolveLinks(root, realpath), resolveLinks(target, realpath))) {
    return outside;
  }
  return { ok: true, path: target };
}

/** The `security show` argv. Each value is bound to its flag with `=`, so a value that starts with
 *  `-` is read as that flag's value and never as another flag. */
export function securityShowArgs(configPath: string): string[] {
  return ["security", "show", `--service-config=${configPath}`];
}

/** The `security set` argv, bound with `=` as {@link securityShowArgs} is. */
export function securitySetArgs(configPath: string, updates: Record<string, unknown>): string[] {
  return ["security", "set", `--service-config=${configPath}`, `--data=${JSON.stringify(updates)}`];
}

// The non-null value each switch type saves. Keyed by every FieldType, so a new type is a compile error.
const VALUE_OK = {
  bool: (v: unknown) => typeof v === "boolean",
  tristate: (v: unknown) => typeof v === "boolean",
  string: (v: unknown) => typeof v === "string",
  int: (v: unknown, f: Field) => Number.isSafeInteger(v) && (v as number) >= (f.min ?? 0),
} satisfies Record<FieldType, (v: unknown, f: Field) => boolean>;

/**
 * What is wrong with the `updates` of a save message, or null. The webview builds it in
 * collectUpdates(), but anything that reaches the host is checked again before it is written. It
 * must be a plain object whose every key is a switch `fields` lists, each value null (reset to the
 * default) or of that switch's type: an int a whole number at or above the switch's minimum.
 */
export function saveUpdatesProblem(updates: unknown, fields: readonly Field[]): string | null {
  if (typeof updates !== "object" || updates === null || Array.isArray(updates)) {
    return "the updates are not an object";
  }
  const proto: unknown = Object.getPrototypeOf(updates);
  if (proto !== Object.prototype && proto !== null) {
    return "the updates are not a plain object";
  }
  const byKey = new Map(fields.map((f) => [f.key, f]));
  for (const [key, value] of Object.entries(updates as Record<string, unknown>)) {
    const f = byKey.get(key);
    if (f === undefined) {
      return `${JSON.stringify(key)} is not a switch this editor sets`;
    }
    if (value === null) {
      continue;
    }
    if (!Object.hasOwn(VALUE_OK, f.type) || !VALUE_OK[f.type](value, f)) {
      return `${f.label} has a value this editor does not save`;
    }
  }
  return null;
}
