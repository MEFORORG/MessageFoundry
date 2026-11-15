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

/** The one file-system read the link check makes, as fs.lstatSync makes it: it throws an error
 *  carrying `code` for a path it cannot read. */
export interface LinkFs {
  lstat(p: string): { isSymbolicLink(): boolean };
}

/** Whether `e` says only that the path does not exist, the one read error the check passes over. */
function missing(e: unknown): boolean {
  const code = typeof e === "object" && e !== null ? (e as { code?: unknown }).code : undefined;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** Whether no existing path from `root` down to `target`, both ends included, is a link. `target`
 *  lies inside `root`. Each path is lstat'd, so a dangling link counts. The walk stops at the first
 *  path that does not exist, since nothing below it can. Any other read error answers false. */
function noLinkBelow(root: string, target: string, fsx: LinkFs): boolean {
  let at = root;
  for (const part of ["", ...path.relative(root, target).split(path.sep)]) {
    at = path.join(at, part);
    try {
      if (fsx.lstat(at).isSymbolicLink()) {
        return false;
      }
    } catch (e) {
      return missing(e);
    }
  }
  return true;
}

/**
 * The absolute service-settings path for `setting` (`messagefoundry.serviceConfig`), resolved against
 * the workspace folder `workspace` (BACKLOG #5411). A blank or non-string setting is refused. The
 * value is resolved as text, so a `..` is collapsed before any check, and the path returned is the
 * one the checks ran on: the CLI is handed exactly that path.
 *
 * 1. Untrusted workspace (`scope.trusted` false): refused before anything else, so this check makes
 *    no file-system call there. That bounds this check only; it says nothing of what VS Code itself
 *    reads in Restricted Mode.
 * 2. Workspace-set value (`scope.fromWorkspace` true: the workspace's own settings, which a
 *    repository's `.vscode/settings.json` can set): the path, as spelled, must lie inside the
 *    workspace folder. One that leaves it by `..`, is absolute elsewhere, or is the folder itself is
 *    refused. Then every existing path from the workspace folder down to the target, both included,
 *    must lstat as not a link (a symbolic link or a junction), a dangling one included. An lstat
 *    error other than ENOENT or ENOTDIR refuses.
 * 3. User-set value: the operator's own choice. If it lies inside the workspace folder as spelled,
 *    the default `messagefoundry.toml` included, it gets the link check of rule 2, and the folder
 *    itself is refused. Otherwise it is accepted as written, with no file-system call.
 *
 * Open limit: rule 3 compares spellings only. A user-set path that reaches the workspace folder by
 * an alias is accepted as written, and no link the repository holds is checked on it. That covers at
 * least a subst drive, an 8.3 short name, a UNC spelling of the folder, a junction or symbolic link
 * outside the folder that leads into it, and a mapped network drive.
 */
export function securityConfigTarget(
  workspace: string,
  setting: unknown,
  scope: { readonly fromWorkspace: boolean; readonly trusted: boolean },
  fsx: LinkFs,
): ConfigTarget {
  if (!scope.trusted) {
    return { ok: false, problem: "This workspace is not trusted. Trust it to read or write its security settings" };
  }
  if (typeof setting !== "string" || setting.trim() === "") {
    return { ok: false, problem: "messagefoundry.serviceConfig is blank or is not text" };
  }
  const root = path.resolve(workspace);
  const target = path.resolve(root, setting);
  // The value is not quoted back (docs/REVIEW-STANDARDS.md R12); the operator can read the setting.
  if (path.relative(root, target) === "") {
    return { ok: false, problem: "messagefoundry.serviceConfig names the workspace folder itself, not a file" };
  }
  if (!inside(root, target)) {
    if (scope.fromWorkspace) {
      return {
        ok: false,
        problem:
          "messagefoundry.serviceConfig, set in workspace settings, names a path outside the workspace folder. " +
          "To use a file elsewhere, set it in user settings",
      };
    }
    return { ok: true, path: target };
  }
  if (!noLinkBelow(root, target, fsx)) {
    return {
      ok: false,
      problem:
        "messagefoundry.serviceConfig names a path in the workspace folder that passes through a link, " +
        "or whose folders cannot be read. Name a path whose folders are all plain folders",
    };
  }
  return { ok: true, path: target };
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
