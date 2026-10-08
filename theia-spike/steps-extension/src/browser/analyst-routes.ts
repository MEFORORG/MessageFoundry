// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-2: which URIs the analyst build refuses to show in a text editor, and the commands it
// removes. Kept free of Theia service imports so the guard module and the widget can share it.

import { DiffUris } from '@theia/core/lib/browser/diff-uris';
import URI from '@theia/core/lib/common/uri';

/** A Router or Handler module. Case-insensitive, because a Windows file system is. */
export function isPythonUri(uri: URI): boolean {
    return uri.path.ext.toLowerCase() === '.py';
}

/** The Steps view opens only a `.py` on disk. An `untitled:` buffer named `x.py` is not a config file. */
export function isStepsUri(uri: URI): boolean {
    return uri.scheme === 'file' && isPythonUri(uri);
}

/**
 * Why the analyst build refuses to show `uri` in a text editor, or undefined when it may.
 *
 * - a `.py`, under any scheme;
 * - a diff whose either side is a `.py`, because a diff editor is a text editor on both sides;
 * - an `untitled:` buffer, because Save As turns one into a `.py` written as raw text.
 */
export function textEditorRefusal(uri: URI): string | undefined {
    if (DiffUris.isDiffUri(uri)) {
        return DiffUris.decode(uri).some(isPythonUri) ? 'diff-py' : undefined;
    }
    if (uri.scheme === 'untitled') {
        return 'untitled';
    }
    return isPythonUri(uri) ? 'py' : undefined;
}

/**
 * Commands the analyst build does not register, each a route to a `.py` as text. A command that
 * only reaches a `.py` through the opener service is NOT here: the opener sends it to the Steps view.
 */
export const BLOCKED_COMMANDS: ReadonlyMap<string, string> = new Map([
    ['navigator.openWith', 'Open With... offers the text editor for any file'],
    ['workbench.action.files.newUntitledFile', 'New Text File: an untitled text buffer that Save As writes to a .py'],
    ['workbench.action.files.pickNewFile', 'New File picker: its first entry is New Text File'],
    ['file.saveAs', 'Save As writes any open buffer, including a JSON editor\'s, to a chosen .py path'],
    ['file.compare', 'Compare with Each Other opens a text diff editor'],
    ['compare:first', 'Select for Compare is the first half of a text diff'],
    ['compare:second', 'Compare with Selected opens a text diff editor'],
]);
