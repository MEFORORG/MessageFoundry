// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as fs from "fs";
import * as path from "path";
import { isAt } from "../collectionCaseFiles";

/** Unlinks every link at or below `dir`, a junction included, without following any. The VS Code
 *  extension host's recursive rmSync follows a junction into its target, and fails with "The name of
 *  the file cannot be resolved by the system" on two junctions that lead into each other; measured
 *  on its Node v24.21.0, while plain Node v24.20.0 does neither. So a teardown that removes a tree
 *  holding links unlinks them first.
 *
 *  A junction to a `\\?\Volume{GUID}\` path lstats as a plain directory, not a link (measured on
 *  Node v24.20.0), and the extension host's recursive rmSync follows it into its target (measured
 *  on its Node v24.21.0). So a directory that the OS does not resolve to its own path (isAt) is
 *  treated as a link: it is removed with rmdir, which removes the junction and leaves its target,
 *  since unlink fails on it with EPERM. `real` is `dir`'s real path. Where the OS cannot resolve
 *  `dir`, at least where realpathSync.native fails with EISDIR on some RAM disks and virtual
 *  drives, the walk falls back to lstat alone, which a volume-GUID junction gets past. */
export function unlinkLinks(dir: string, real: string | undefined = realPath(dir)): void {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) {
      fs.unlinkSync(p);
    } else if (st.isDirectory()) {
      const expected = real === undefined ? undefined : path.join(real, name);
      if (expected === undefined || isAt(p, expected)) {
        unlinkLinks(p, expected);
      } else {
        fs.rmdirSync(p);
      }
    }
  }
}

function realPath(dir: string): string | undefined {
  try {
    return fs.realpathSync.native(dir);
  } catch {
    return undefined; // see the docblock: the walk falls back to lstat alone
  }
}
