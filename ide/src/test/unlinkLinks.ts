// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as fs from "fs";
import * as path from "path";

/** Unlinks every link at or below `dir`, a junction included, without following any. The VS Code
 *  extension host's recursive rmSync follows a junction into its target, and fails with "The name of
 *  the file cannot be resolved by the system" on two junctions that lead into each other; measured
 *  on its Node v24.21.0, while plain Node v24.20.0 does neither. So a teardown that removes a tree
 *  holding links unlinks them first. */
export function unlinkLinks(dir: string): void {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) {
      fs.unlinkSync(p);
    } else if (st.isDirectory()) {
      unlinkLinks(p);
    }
  }
}
