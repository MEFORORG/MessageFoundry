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
 *  does not match, and on Windows the comparison ignores case as the file system does. A first
 *  component that only starts with two dots, such as `..conf`, is inside. */
function inside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel !== "" && rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel);
}

/** The file-system reads the containment check makes, as fs.realpathSync.native and fs.lstatSync
 *  make them: each throws an error carrying `code` for a path it cannot read. */
export interface LinkFs {
  realpath(p: string): string;
  lstat(p: string): unknown;
}

function errCode(e: unknown): unknown {
  return typeof e === "object" && e !== null ? (e as { code?: unknown }).code : undefined;
}

/** `target` with every symbolic link in it resolved, or undefined when that cannot be told. The part
 *  that does not exist yet is joined back as written, so each missing component is checked to be
 *  truly absent: a dangling link exists to lstat and is refused, since it could later lead anywhere.
 *  Any error but "does not exist" is refused too. */
function resolveLinks(target: string, fsx: LinkFs): string | undefined {
  const tail: string[] = [];
  let at = target;
  for (;;) {
    try {
      return path.join(fsx.realpath(at), ...tail);
    } catch (e) {
      const code = errCode(e);
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        return undefined;
      }
    }
    try {
      fsx.lstat(at);
      return undefined; // it exists, yet does not resolve: a dangling or looping link
    } catch (e) {
      const code = errCode(e);
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        return undefined;
      }
    }
    const parent = path.dirname(at);
    if (parent === at) {
      return undefined;
    }
    tail.unshift(path.basename(at));
    at = parent;
  }
}

/** Whether `target`, followed component by component, reaches the folder whose resolved path is
 *  `realRoot`: some existing prefix of it resolves to that folder or into it. That is how an alias
 *  outside the folder, such as a link, a mapped drive or an 8.3 short name, leads into it. Undefined
 *  when a prefix cannot be read, so the caller refuses. */
function reachesRoot(target: string, realRoot: string, fsx: LinkFs): boolean | undefined {
  let at = target;
  for (;;) {
    try {
      const real = fsx.realpath(at);
      if (path.relative(realRoot, real) === "" || inside(realRoot, real)) {
        return true;
      }
    } catch (e) {
      const code = errCode(e);
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        return undefined;
      }
    }
    const parent = path.dirname(at);
    if (parent === at) {
      return false;
    }
    at = parent;
  }
}

/**
 * The absolute service-settings path for `setting` (`messagefoundry.serviceConfig`), resolved against
 * the workspace folder `workspace` (BACKLOG #5411). A blank or non-string setting is refused.
 *
 * `fromWorkspace` says the value in force comes from the workspace's own settings, which a
 * repository's `.vscode/settings.json` can set. Such a value must name a file inside the workspace
 * folder: one that leaves it by `..` or by being absolute elsewhere is refused, as is the folder
 * itself. A value from user settings is the operator's own and may name a file anywhere, such as the
 * service's TOML in another folder.
 *
 * Whatever its scope, a path inside the workspace folder, the default `messagefoundry.toml`
 * included, must not leave it through a symbolic link the repository holds, a dangling one included.
 * Inside is decided on resolved paths as well as lexically: a user-set path that reaches the folder
 * by an alias, such as a link, a mapped drive or an 8.3 short name, gets the same link rules. The
 * path returned has its links resolved, so the CLI opens the folders that were checked.
 */
export function securityConfigTarget(
  workspace: string,
  setting: unknown,
  fromWorkspace: boolean,
  fsx: LinkFs,
): ConfigTarget {
  if (typeof setting !== "string" || setting.trim() === "") {
    return { ok: false, problem: "messagefoundry.serviceConfig is blank or is not text" };
  }
  const root = path.resolve(workspace);
  const target = path.resolve(root, setting);
  // The value is not quoted back (docs/REVIEW-STANDARDS.md R12); the operator can read the setting.
  const outside = {
    ok: false,
    problem:
      "messagefoundry.serviceConfig names a path that leaves the workspace folder, or whose links cannot be checked. " +
      "A value in workspace settings must name a file inside the workspace folder, and a path inside it must not leave " +
      "it through a link; to use a file elsewhere, set it in user settings",
  } as const;
  const lexicallyInside = inside(root, target);
  if (!lexicallyInside && fromWorkspace) {
    return outside;
  }
  const realRoot = resolveLinks(root, fsx);
  const realTarget = resolveLinks(target, fsx);
  if (realRoot === undefined || realTarget === undefined) {
    return outside;
  }
  const entersRoot = lexicallyInside || reachesRoot(target, realRoot, fsx);
  if (entersRoot === undefined || (entersRoot && !inside(realRoot, realTarget))) {
    return outside;
  }
  return { ok: true, path: realTarget };
}

/** The file one editor panel now shows (BACKLOG #5411). Save writes only to this file, so a setting
 *  that moved after the form rendered cannot send one file's values into another. Each panel holds
 *  its own, and once the panel is disposed a late refresh cannot set it and nothing saves through it. */
export class ShownFile {
  private file: string | undefined;
  private gone = false;

  /** Whether the panel has been disposed. */
  get disposed(): boolean {
    return this.gone;
  }

  /** The form shows no file, as while it reads one. */
  clear(): void {
    this.file = undefined;
  }

  /** The form now shows `file`, unless the panel is gone. */
  set(file: string): void {
    if (!this.gone) {
      this.file = file;
    }
  }

  /** The panel is gone: it shows no file again. */
  dispose(): void {
    this.gone = true;
    this.file = undefined;
  }

  /** Whether a save may write to `file`: the live panel shows exactly that file. */
  matches(file: string): boolean {
    return !this.gone && this.file !== undefined && this.file === file;
  }
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
  int: (v: unknown, f: Field) => Number.isSafeInteger(v) && (f.min === undefined || (v as number) >= f.min),
} satisfies Record<FieldType, (v: unknown, f: Field) => boolean>;

/**
 * What is wrong with the `updates` of a save message, or null. The webview builds it in
 * collectUpdates(), but anything that reaches the host is checked again before it is written. It
 * must be a plain object whose every key is a switch `fields` lists, each value null (reset to the
 * default) or of that switch's type: an int a whole number, at or above the switch's minimum if it has one.
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
    if (!VALUE_OK[f.type](value, f)) {
      return `${f.label} has a value this editor does not save`;
    }
  }
  return null;
}
