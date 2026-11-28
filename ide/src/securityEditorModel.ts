// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The host-side checks of the Security Settings editor (securityEditor.ts), kept free of `vscode` so
// the unit suite runs them (BACKLOG #5411). The editor writes the `[security]` posture, so each
// check fails closed: a refusal names what is wrong and nothing is run.
import * as fs from "node:fs";
import * as path from "node:path";

import { isFullyQualifiedPath } from "./engineTrustModel";
import { isPathWithin, isSamePath, nonAsciiCaseVariant, sameIgnoringAnyCase, segmentsBelow } from "./pathFold";
import type { Field, FieldType } from "./securityEditorWebview";
import {
  CASE_RULE,
  hasColonInName,
  hasReservedDeviceName,
  hasTrailingDotOrSpaceName,
  type ContainedPathSetting,
  type PathSettingScopes,
} from "./workspaceContainment";

/**
 * The value and scope {@link securityConfigTarget} judges for `messagefoundry.serviceConfig`, from
 * VS Code's `inspect()` answer and cli.ts's contained reading of it (BACKLOG #5404). A value the
 * containment dropped is judged as written, in the scope it was written in, so it is refused here as
 * the editor's own rules refuse it, rather than the editor reading and saving the file used in its
 * place. An unread scope (`seen` undefined) counts as the workspace's, so no check is skipped.
 */
export function securityConfigInput(
  seen: PathSettingScopes | undefined,
  setting: ContainedPathSetting,
): { readonly value: unknown; readonly fromWorkspace: boolean } {
  if (setting.dropped === "workspace") {
    return { value: seen?.workspaceValue, fromWorkspace: true };
  }
  if (setting.dropped === "user") {
    return { value: seen?.globalValue, fromWorkspace: false };
  }
  return { value: setting.value, fromWorkspace: seen === undefined || setting.source === "workspace" };
}

/** The service-settings file the editor reads and writes, or why it may not. */
export type ConfigTarget = { readonly ok: true; readonly path: string } | { readonly ok: false; readonly problem: string };

/** The file-system reads the link check makes, as fs.lstatSync and fs.realpathSync.native make
 *  them: each throws an error carrying `code` for a path it cannot read. `fileId`, a file's device
 *  and file id as text, as fs.statSync reads them, places a case-variant spelling of the workspace
 *  where its real path keeps the spelling's case, and a user-set path spelled outside the workspace
 *  that reaches it by another spelling; without it both are refused. It throws, as statSync does,
 *  for a path it cannot read, and with code {@link NO_FILE_ID} for an entry that has no file id. */
export interface LinkFs {
  lstat(p: string): { isSymbolicLink(): boolean };
  realpath(p: string): string;
  fileId?(p: string): string;
}

/** The error code {@link LinkFs.fileId} throws for an entry whose file system reports no file id. */
export const NO_FILE_ID = "ENOFILEID";

/** {@link LinkFs.fileId} as the editor reads it: `p`'s device and file id from fs.statSync, which
 *  follows links. A file id of 0, which a file system that keeps none can report for every entry,
 *  throws {@link NO_FILE_ID} rather than match another entry's. */
export function securityFileId(p: string): string {
  const st = fs.statSync(p, { bigint: true });
  if (st.ino === 0n) {
    throw Object.assign(new Error("no file id"), { code: NO_FILE_ID });
  }
  return `${st.dev}:${st.ino}`;
}

/** The `.code-workspace` file VS Code's `workspace.workspaceFile` names, as a path, or undefined for
 *  none and for an untitled workspace, whose folders and settings the operator chose. */
export function workspaceFilePath(file: { readonly scheme: string; readonly fsPath: string } | undefined): string | undefined {
  return file === undefined || file.scheme === "untitled" ? undefined : file.fsPath;
}

/** Whether `e` says only that the path does not exist, the one lstat error the check passes over. */
function missing(e: unknown): boolean {
  const code = typeof e === "object" && e !== null ? (e as { code?: unknown }).code : undefined;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** Whether `rel`, a relative path inside `root`, passes through no link. The rules are rule 2 of
 *  {@link securityConfigTarget}. */
function noLinkBelow(root: string, rel: string, fsx: LinkFs): boolean {
  let deepest = root;
  for (const part of rel.split(path.sep)) {
    const next = path.join(deepest, part);
    try {
      if (fsx.lstat(next).isSymbolicLink()) {
        return false;
      }
    } catch (e) {
      if (!missing(e)) {
        return false;
      }
      break; // nothing below a path that does not exist can exist
    }
    deepest = next;
  }
  try {
    // The folder's own real path must be the root of the deepest one's, ASCII case only on Windows
    // (pathFold.ts, BACKLOG #5832). Below it, the same names in any case: a real path names the
    // case on disk, which NTFS may have folded from the spelling, and stays inside the folder.
    const spelled = segmentsBelow(root, deepest) ?? [];
    const real = segmentsBelow(fsx.realpath(root), fsx.realpath(deepest));
    return (
      real !== undefined && real.length === spelled.length && real.every((seg, i) => sameIgnoringAnyCase(seg, spelled[i]))
    );
  } catch {
    return false; // any realpath error refuses
  }
}

/** Whether `head` is the folder `root`, by real path and then by {@link LinkFs.fileId}, as
 *  escapesByLink places it: true, false when `head` does not exist or its file id differs, or
 *  undefined when a read fails for any reason but absence, a dangling link at `head` included, or
 *  when the real paths differ and there is no `fileId` to settle it. */
function isWorkspaceFolder(root: string, head: string, fsx: LinkFs): boolean | undefined {
  let realRoot: string;
  try {
    realRoot = fsx.realpath(root);
  } catch {
    return undefined;
  }
  try {
    if (isSamePath(realRoot, fsx.realpath(head))) {
      return true;
    }
    return fsx.fileId === undefined ? undefined : fsx.fileId(root) === fsx.fileId(head);
  } catch (e) {
    if (!missing(e)) {
      return undefined;
    }
  }
  try {
    fsx.lstat(head);
    return undefined; // the entry exists but its target does not: a dangling link
  } catch (e) {
    return missing(e) ? false : undefined;
  }
}

/** `p`'s root (drive, UNC share or `/`) and the segments below it, as `p` spells them, or undefined
 *  for a spelling the root does not split, at least a `\\?\` or `\\.\` prefix. */
function rootAndSegments(p: string): { readonly head: string; readonly segments: readonly string[] } | undefined {
  const head = path.parse(p).root;
  const segments = segmentsBelow(head, p);
  return segments === undefined ? undefined : { head, segments };
}

/** The path `head` and the first `n` of `segments` spell. */
function prefixOf(head: string, segments: readonly string[], n: number): string {
  return path.join(head, ...segments.slice(0, n));
}

/**
 * Where `target`, spelled outside the workspace folder `root`, reaches that folder by another
 * spelling (BACKLOG #5411, #8237 item 16): the segments below the workspace folder of the first
 * folder on `target`, shallowest first and the drive or share root included, that is inside it,
 * followed by the segments of `target` below that folder; and whether it was placed by file id
 * (`byId`) rather than by real path. A folder is inside when its real path is inside the folder's,
 * which was measured to place a junction and a directory symbolic link onto the folder or one below
 * it (a subst drive is UNMEASURED), or when a folder on its real path has the workspace folder's
 * {@link LinkFs.fileId}, which was measured to place a UNC loopback admin share: Node keeps a UNC spelling's server and share, so the real path
 * of `\\localhost\C$\ws` is that spelling and not `C:\ws`, while the device and file id are the same
 * (measured 2026-11-27 on Windows 11 with standalone Node v24.20.0, not the editor's Electron
 * runtime, through `\\localhost\D$` and `\\127.0.0.1\D$`). An entry with no file id ({@link NO_FILE_ID}), the workspace folder's own
 * included, is placed by real path only, so where the workspace folder has none a UNC alias of it
 * is not placed (an open limit below). False when no folder on `target` is inside, the walk
 * stopping at the first that does not exist; undefined when the workspace folder cannot be read,
 * a folder on `target` is a dangling link, any other read fails, a spelling cannot be split into
 * its folders ({@link rootAndSegments}), or there is no `fileId`.
 *
 * Open limit: a real path follows every link at once, so an alias whose target passes through a
 * link the repository holds, at any depth, is placed where that link leads, not in the workspace
 * folder, and the repository's link is not checked: an alias onto `ws\linked` or onto
 * `ws\linked\deeper`, where `ws\linked` is the repository's link (measured). Only a walk that
 * follows each link one hop at a time would see it pass through the folder.
 */
function reachesWorkspace(
  root: string,
  target: string,
  fsx: LinkFs,
): { readonly rest: string[]; readonly byId: boolean } | false | undefined {
  if (fsx.fileId === undefined) {
    return undefined;
  }
  // Each id read once: consecutive folders on a path share their real path's ancestors.
  const ids = new Map<string, string | undefined>();
  const idOf = (p: string): string | undefined => {
    if (!ids.has(p)) {
      try {
        ids.set(p, fsx.fileId?.(p));
      } catch (e) {
        if (typeof e !== "object" || e === null || (e as { code?: unknown }).code !== NO_FILE_ID) {
          throw e;
        }
        ids.set(p, undefined);
      }
    }
    return ids.get(p);
  };
  let realRoot: string;
  let rootId: string | undefined;
  try {
    realRoot = fsx.realpath(root);
    rootId = idOf(root);
  } catch {
    return undefined;
  }
  const spelled = rootAndSegments(target);
  if (spelled === undefined) {
    return undefined;
  }
  for (let i = 0; i <= spelled.segments.length; i++) {
    const prefix = prefixOf(spelled.head, spelled.segments, i);
    const tail = spelled.segments.slice(i);
    let real: string;
    try {
      real = fsx.realpath(prefix);
    } catch (e) {
      if (!missing(e)) {
        return undefined;
      }
      try {
        fsx.lstat(prefix);
        return undefined; // the entry exists but its target does not: a dangling link
      } catch (e2) {
        return missing(e2) ? false : undefined;
      }
    }
    const below = segmentsBelow(realRoot, real);
    if (below !== undefined) {
      return { rest: [...below, ...tail], byId: false };
    }
    if (rootId === undefined) {
      continue;
    }
    const onReal = rootAndSegments(real);
    if (onReal === undefined) {
      return undefined;
    }
    for (let j = 0; j <= onReal.segments.length; j++) {
      try {
        if (idOf(prefixOf(onReal.head, onReal.segments, j)) === rootId) {
          return { rest: [...onReal.segments.slice(j), ...tail], byId: true };
        }
      } catch {
        return undefined; // the folders on an existing real path exist, so any error refuses
      }
    }
  }
  return false;
}

/** The refusal for a user-set path {@link reachesWorkspace} could not read. */
const UNREAD_PATH =
  "messagefoundry.serviceConfig, set in user settings, names a path this check could not read to tell " +
  "whether it reaches the workspace folder by another spelling: at least a folder on it that cannot be " +
  "read, a dangling link on it, or a long-path or device prefix. Name a path whose folders can be read, " +
  "spelled without such a prefix, or one inside the workspace folder";

/** The refusal for a folder or file name in `rel` that Windows can open as another entry or a
 *  device ({@link hasTrailingDotOrSpaceName}, {@link hasColonInName}, {@link hasReservedDeviceName}),
 *  or undefined. `inWhere` names where the path is, with a leading space, or is empty. */
function nameProblem(rel: string, inWhere: string): string | undefined {
  if (hasTrailingDotOrSpaceName(rel)) {
    return (
      `messagefoundry.serviceConfig names a path${inWhere} with a folder or file name that ends in ` +
      "a dot or a space, which Windows can open as a different name. Remove the trailing dot or space"
    );
  }
  if (hasColonInName(rel)) {
    return (
      `messagefoundry.serviceConfig names a path${inWhere} with a folder or file name that holds ` +
      "a colon, which Windows opens as a stream on another entry. Remove the colon"
    );
  }
  if (hasReservedDeviceName(rel)) {
    return (
      `messagefoundry.serviceConfig names a path${inWhere} with a folder or file name that is ` +
      "a Windows device name such as nul or com1, which Windows can open as the device. Rename the folder or file"
    );
  }
  return undefined;
}

/** Whether `setting` names its path by itself rather than one read against the workspace folder:
 *  {@link isFullyQualifiedPath}, and a UNC spelling must name a server and a share as well, since
 *  Node resolves `\\x.toml`, with no share, on the workspace folder's drive. */
function namesItsOwnPath(setting: string): boolean {
  if (!isFullyQualifiedPath(setting)) {
    return false;
  }
  return path.sep !== "\\" || !/^[\\/]{2}/.test(setting) || path.win32.parse(setting).root.length > 2;
}

/** Whether the workspace folder `root` lies inside the folder that holds the `.code-workspace` file
 *  `workspaceFile`, an absolute path, as spelled and by real path; any realpath error refuses. */
function insideWorkspaceFileFolder(root: string, workspaceFile: string, fsx: LinkFs): boolean {
  const home = path.dirname(workspaceFile);
  if (!isPathWithin(home, root)) {
    return false;
  }
  try {
    return isPathWithin(fsx.realpath(home), fsx.realpath(root));
  } catch {
    return false;
  }
}

/**
 * The absolute service-settings path for `setting` (`messagefoundry.serviceConfig`), resolved against
 * the workspace folder `workspace` (BACKLOG #5411). A blank or non-string setting is refused. The
 * value is resolved as text, so a `..` is collapsed before any check, and the path returned is the
 * one the checks ran on, but for an alias rule 3 places by file id alone: the CLI is handed exactly
 * that path.
 *
 * 1. Untrusted workspace (`scope.trusted` false): refused before anything else, so this check makes
 *    no file-system call there. That bounds this check only; it says nothing of what VS Code itself
 *    reads in Restricted Mode.
 * 2. Workspace-set value (`scope.fromWorkspace` true: the workspace's own settings, which a
 *    repository's `.vscode/settings.json` can set): the path, as spelled, must lie inside the
 *    workspace folder. One that leaves it by `..`, is absolute elsewhere, or is the folder itself is
 *    refused. On Windows, a path whose folder or file name below the workspace folder ends in a dot
 *    or a space is refused before any file-system call. Node reads such a name as written, while
 *    the CLI's open goes through Windows path normalization, which can drop the ending and open
 *    another entry. Measured through Python 3.14.7's open, it dropped at least every trailing dot
 *    and space from the file name and one trailing dot from a folder name, and kept a folder name's
 *    trailing space. The check refuses every such name, the ones kept as written included. A
 *    folder or file name below the workspace folder that holds a colon is refused there too, before
 *    any file-system call, since a Win32 open reads it as a stream on another entry, which may be a
 *    link out of the folder ({@link hasColonInName} says why the link walk cannot be relied on). So
 *    is a folder or file name that is a reserved device name, such as `nul` or `com1.toml`
 *    ({@link hasReservedDeviceName}), which a Win32 open can read as the device. Then
 *    every existing path below the workspace folder, down to the target, must lstat as not a link,
 *    a dangling one included; the walk stops at the first that does not exist. The deepest
 *    existing one must then realpath to the folder's own realpath, ASCII case only on Windows,
 *    joined with the same parts in any case (pathFold.sameIgnoringAnyCase), since NTFS may have
 *    folded the spelling's case onto the disk's and the result stays inside the folder,
 *    because lstat does not report every reparse point as a link, at least not a junction onto a
 *    volume GUID path. An lstat error other than ENOENT or ENOTDIR, or any realpath error, the
 *    folder's own included, refuses. An 8.3 short name below the folder is refused too, since
 *    realpath spells it in full. The workspace folder the operator opened is taken as given and is
 *    not checked for a link: it may be one. But in a window opened from a `.code-workspace` file
 *    (`scope.workspaceFile`, VS Code's `workspace.workspaceFile`), that file holds the workspace
 *    settings and chooses the folder, the first in its `folders`. So there, once the name checks
 *    above pass and before the link walk, a path these checks run on is refused, at either scope,
 *    unless the workspace folder lies inside the folder that holds the file, both as spelled and
 *    by real path; any realpath error refuses (BACKLOG #8237 item 57). And since the file may choose
 *    a folder below its own as the workspace folder, a user-set path spelled inside the file's
 *    folder but outside the workspace folder, that rule 3 places nowhere in the workspace folder,
 *    gets the name checks and the link walk above from the file's folder instead. A path spelled
 *    outside the file's folder is placed in it as rule 3 places one in the workspace folder, by
 *    real path and file id, with the same open limits.
 * 3. User-set value: the operator's own choice. If it lies inside the workspace folder as spelled,
 *    the default `messagefoundry.toml` and a relative value included, it gets the checks of rule 2,
 *    and the folder itself is refused. Otherwise every folder and file name on its whole path gets
 *    rule 2's name checks first, before any file-system call: a name ending in a dot or a space,
 *    holding a colon, or that is a device name is refused, not normalised, since Node reads `ws.`
 *    as written while the CLI's Win32 open drops the dot and may reach the workspace folder. Next,
 *    in a `.code-workspace` window whose file chose the workspace folder from outside its own
 *    folder, as rule 2 tests it, a value that is not a full path is refused, since it is read
 *    against the folder the file chose. A full path is {@link isFullyQualifiedPath}, and on
 *    Windows a UNC spelling must also name a server and a share; so at least `..\x`, `\x`, `C:x`,
 *    `\\x` and `\\\x` are refused there. Then,
 *    once the case variant below is settled, each folder on its path is read, shallowest first and the drive or share root included, down to
 *    the first that does not exist (BACKLOG #8237 item 16). The first that is inside the workspace
 *    folder by real path, or whose real path passes through a folder with the workspace folder's
 *    device and file id ({@link LinkFs.fileId}), means the path reaches the folder by another
 *    spelling. Measured: a junction or a directory symbolic link onto the folder or one below it,
 *    by real path, and a UNC loopback admin share (`\\localhost\C$\...`), by file id; other
 *    spellings, a subst drive among them, are UNMEASURED (Open limits). The part below the workspace folder
 *    then gets rule 2's checks, spelled from the workspace folder, after those reads. Placed by real path, the path
 *    returned is spelled from the workspace folder; placed by file id alone, it is returned as
 *    written, so two entries that report one id (file ids are not unique on every file system, at
 *    least not on ReFS) can cause a refusal but never send the CLI to a file the setting does not
 *    name. When no folder on it is inside, it is accepted as written, but for rule 2's
 *    `.code-workspace` case. A dangling link on it, any other read error, a long-path or device
 *    prefix (`\\?\`, `\\.\`), or a caller that passes no `fileId`, refuses; an entry with no file id
 *    is placed by real path only.
 *
 * On Windows a spelling is inside the folder when it matches with only ASCII case ignored, not
 * toLowerCase()'s fold (pathFold.ts, BACKLOG #5832). A path that
 * differs from the folder's spelling only by a case outside A-Z may still be the folder, since NTFS
 * folds at least e-acute against E-acute. Set in workspace settings, it is refused. Set in user
 * settings, the real path of the folder it names at the workspace's depth is read: when that is the
 * workspace folder, the path gets rule 2's checks, spelled from the workspace folder; when it does
 * not exist or is another folder, rule 3's id walk decides; any other error, a dangling link
 * included, refuses. Where the real paths differ, the file ids decide, as escapesByLink decides;
 * a caller that passes no `fileId` refuses then.
 *
 * Open limits, at least these. Rule 3's placement was measured on Windows 11 with standalone Node v24.20.0, not
 * the editor's Electron runtime, for a junction and a directory symbolic link (by real path) and a
 * UNC loopback admin share (by file id), and nothing else: at least a subst or mapped drive, an
 * 8.3 short name, a bind mount and a macOS firmlink are UNMEASURED, and may be accepted as written
 * with no link check. Where the
 * workspace folder reports no file id ({@link NO_FILE_ID}), a UNC alias of it is accepted as
 * written with no link check: a fail-open, though no looser than before #8237 item 16, when every
 * user-set path outside the folder was. A real path follows every link at once, so an alias whose
 * target passes through a link the repository holds, at any depth, is placed where that link
 * leads and the repository's link is not checked: measured for an alias onto `ws\linked\deeper`,
 * where `ws\linked` is the repository's junction. Following each link one hop at a time would be
 * needed to see it. Where the
 * native realpath fails, at least with EISDIR on some RAM disks and virtual drives, every user-set
 * path refuses, as every rule 2 path already did. Its reads are synchronous, so a user-set path on a slow share holds the extension host while they
 * run. Nor does this check cover the files the CLI creates beside the target, or a link made or a
 * folder renamed between this check and the CLI's write, since the CLI opens the path itself, later.
 */
export function securityConfigTarget(
  workspace: string,
  setting: unknown,
  scope: { readonly fromWorkspace: boolean; readonly trusted: boolean; readonly workspaceFile?: string },
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
  // Set when the path reaches the workspace folder by file id alone, so it is returned as written.
  let aliasById = false;
  // The folder the checks below run from: the workspace folder, or the one holding the window's
  // .code-workspace file for a user-set path inside that folder but outside the workspace folder.
  let base = root;
  let below = segmentsBelow(root, target);
  if (below === undefined) {
    const variant = nonAsciiCaseVariant(root, target);
    if (scope.fromWorkspace) {
      return {
        ok: false,
        problem:
          variant === undefined
            ? "messagefoundry.serviceConfig, set in workspace settings, names a path outside the workspace folder. " +
              "To use a file elsewhere, set it in user settings"
            : "messagefoundry.serviceConfig, set in workspace settings, is not a path inside the workspace folder " +
              `as spelled ${CASE_RULE}. Spell it with the folder's own case, or, to use a file elsewhere, set it ` +
              "in user settings",
      };
    }
    // Every folder and file name on a user-set path outside the folder, before any read: Node reads
    // `ws.` as written and finds nothing, while the CLI's Win32 open drops the dot, so an alias of
    // the folder spelled that way would pass the walk below and reach the folder's links (BACKLOG
    // #8237 item 16, review round-d1ff257d). Refused, never normalised and accepted.
    const spelled = rootAndSegments(target);
    const named = spelled === undefined ? undefined : nameProblem(spelled.segments.join(path.sep), "");
    if (named !== undefined) {
      return { ok: false, problem: named };
    }
    // A value that is not a full path is read against the workspace folder, so where a
    // .code-workspace file chose that folder from outside its own folder, one that leaves it lands
    // where the file chose (round-55360875 finding 2). Where the folder lies inside the file's own,
    // as rule 2 tests it, the operator's placement of the file decides, as on main.
    if (
      scope.workspaceFile !== undefined &&
      !namesItsOwnPath(setting) &&
      !insideWorkspaceFileFolder(root, scope.workspaceFile, fsx)
    ) {
      return {
        ok: false,
        problem:
          "messagefoundry.serviceConfig is not a full path and leaves the workspace folder, and this window's " +
          ".code-workspace file chose that folder from outside the folder that holds the file. Give the full path",
      };
    }
    if (variant !== undefined) {
      const same = isWorkspaceFolder(root, variant.head, fsx);
      if (same === undefined) {
        return {
          ok: false,
          problem:
            "messagefoundry.serviceConfig spells a folder on its path with a case outside A-Z that differs from the " +
            "workspace folder's, and whether it is the workspace folder could not be read. Spell it with the " +
            `folder's own case ${CASE_RULE}`,
        };
      }
      if (same) {
        below = [...variant.rest];
      }
    }
    if (below === undefined) {
      const reached = reachesWorkspace(root, target, fsx);
      if (reached === undefined) {
        return { ok: false, problem: UNREAD_PATH };
      }
      if (reached !== false) {
        below = reached.rest;
        aliasById = reached.byId;
      } else {
        // In a .code-workspace window the file's own folder is checked too, since the file may have
        // chosen a folder below it as the workspace folder (BACKLOG #8237 item 57), and is placed
        // the same way: by spelling, then by real path and file id.
        const home = scope.workspaceFile === undefined ? undefined : path.dirname(scope.workspaceFile);
        if (home === undefined) {
          return { ok: true, path: target };
        }
        below = segmentsBelow(home, target);
        if (below === undefined) {
          const viaHome = reachesWorkspace(home, target, fsx);
          if (viaHome === undefined) {
            return { ok: false, problem: UNREAD_PATH };
          }
          if (viaHome === false) {
            return { ok: true, path: target };
          }
          below = viaHome.rest;
          aliasById = viaHome.byId;
        }
        base = home;
      }
    }
  }
  const where = base === root ? "the workspace folder" : "the folder that holds this window's .code-workspace file";
  // The value is not quoted back (docs/REVIEW-STANDARDS.md R12); the operator can read the setting.
  if (below.length === 0) {
    return { ok: false, problem: `messagefoundry.serviceConfig names ${where} itself, not a file` };
  }
  const rel = below.join(path.sep);
  const named = nameProblem(rel, ` in ${where}`);
  if (named !== undefined) {
    return { ok: false, problem: named };
  }
  if (base === root && scope.workspaceFile !== undefined && !insideWorkspaceFileFolder(root, scope.workspaceFile, fsx)) {
    return {
      ok: false,
      problem:
        "messagefoundry.serviceConfig names a path in the workspace folder, and this window's .code-workspace " +
        "file chose that folder from outside the folder that holds the file, or its real path could not be read. " +
        "Open the workspace folder itself, or name a file outside it in user settings",
    };
  }
  if (!noLinkBelow(base, rel, fsx)) {
    return {
      ok: false,
      problem:
        `messagefoundry.serviceConfig names a path in ${where} that passes through a link, ` +
        "or whose folders cannot be read. Name a path whose folders are all plain folders",
    };
  }
  // Spelled from the workspace folder as the walk was, so the CLI opens the path that was checked;
  // an alias placed by file id alone keeps its own spelling, for the reason rule 3 gives.
  return { ok: true, path: aliasById ? target : path.join(base, rel) };
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
