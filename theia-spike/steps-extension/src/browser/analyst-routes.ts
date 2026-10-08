// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-2: which URIs the analyst build refuses to show in a text editor, and the commands it
// removes. Kept free of Theia service imports so the guard module and the widget can share it.

import { DiffUris } from '@theia/core/lib/browser/diff-uris';
import URI from '@theia/core/lib/common/uri';

/**
 * A Router or Handler module. Case-insensitive, because a Windows file system is. Windows also drops
 * trailing dots and spaces from a name (`x.py.` and `x.py ` both land as `x.py`) and reads `x.py:s` as
 * a stream of `x.py`, so those spellings count as a `.py` too (S-2b review).
 */
export function isPythonUri(uri: URI): boolean {
    const base = uri.path.base.replace(/:.*$/, '').replace(/[. ]+$/, '');
    return base.toLowerCase().endsWith('.py');
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
    // Spike S-2b: three commands only the Electron build registers. Each leaves the app for a route
    // the guard cannot see. Underneath, the main-process guard (electron-app/analyst-main-guard.js)
    // refuses the first two outright and closes Developer Tools as soon as a forged message opens it.
    ['openWithSystemApp', 'Open With System Editor hands the file to the operating system, which opens a .py in Notepad or an IDE'],
    ['revealFileInOS', 'Reveal in File Explorer opens Explorer on the file, whose own context menu offers Edit and Open with'],
    ['theia.toggleDevTools', 'Developer Tools is a console in the page, with every service the guard wraps one call away'],
]);

/**
 * Open With entries the analyst build drops for a guarded URI: Theia's text editor ('default', and
 * EditorWidgetFactory.ID, spelled out here to keep this file free of service imports), and the OS
 * editor (Electron). A Theia upgrade that renames either id must update this set.
 */
export const TEXT_OPEN_WITH_HANDLERS: ReadonlySet<string> = new Set(['default', 'code-editor-opener', 'system-editor']);
