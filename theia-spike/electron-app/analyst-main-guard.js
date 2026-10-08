// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// Spike S-2b (ADR 0208): the analyst build's guard in the Electron MAIN process. The frontend guard
// (steps-extension/src/browser/analyst-frontend-module.ts) closes every route it can see in the page.
// These routes leave the page, so the page cannot close them alone:
//
//   1. The operating system's editor. Open With System Editor, Reveal in File Explorer, a link opened
//      with window.open, and the external-app opener all end in electron.shell. Only http and https
//      may leave through it; a file path or file: URL is refused, so a .py never reaches Notepad.
//   2. Native elements. The Windows file dialog is a small Explorer with its own Edit and Open with
//      menu, and a native menu bar can be turned on by preference. Theia's in-app dialog, menus and
//      title bar replace both. Theia reads THEIA_ELECTRON_DISABLE_NATIVE_ELEMENTS in this process and,
//      through the inherited environment, in the preload script. The four dialog.show*Dialog functions
//      are refused as well, so a forged IPC message cannot open the native dialog either.
//   3. Electron's default application menu. With none set, Electron installs one whose View menu binds
//      Ctrl+Shift+I to Developer Tools and Ctrl+R to reload. Theia sets a window menu only in native
//      title-bar mode, so the default one would otherwise stay live, unseen, under the custom title bar.
//   4. Developer Tools, by any route: closed the moment it opens. This is a close, not a refusal: a
//      forged toggle message still opens it for an instant.
//
// It must be required before Theia's electron-main, so its environment and menu settings land first.
//
// LIMITS, stated so nobody reads more into this: a renderer flag (--remote-debugging-port) or a Node
// flag (--inspect, NODE_OPTIONS, ELECTRON_RUN_AS_NODE) reaches the page or this process without
// passing through anything here. Electron fuses close the Node ones; S-2b's report covers which.
// `devTools: false` in webPreferences would be stronger than closing it on open, and needs a rebind
// of Theia's ElectronMainApplication; the spike measures the close instead.

'use strict';

const { app, dialog, Menu, shell } = require('electron');

/** Every refused attempt, for the S-2b walk. Spike-only: a shipped build would not keep it on global. */
const refusals = [];

function refuse(route, target) {
    refusals.push({ at: Date.now(), route, target: String(target).slice(0, 300) });
}

/** http and https only. Everything else (a path, file:, a custom scheme) is a route out of the app. */
function isWebUrl(target) {
    try {
        const { protocol } = new URL(String(target));
        return protocol === 'http:' || protocol === 'https:';
    } catch {
        return false;
    }
}

function install() {
    process.env.THEIA_ELECTRON_DISABLE_NATIVE_ELEMENTS = '1';

    // Passing null before ready stops Electron from installing its default menu.
    Menu.setApplicationMenu(null);

    const openExternal = shell.openExternal.bind(shell);
    shell.openExternal = (url, options) => {
        if (!isWebUrl(url)) {
            refuse('shell.openExternal', url);
            // Resolve, not reject: Theia's callers do not await this, so a rejection would surface as an
            // unhandled rejection in the main process.
            return Promise.resolve();
        }
        return openExternal(url, options);
    };

    // The renderer no longer asks for native dialogs (route 2), but its preload can still send the
    // IPC message that makes Theia's main process open one. Refuse here too, answering "cancelled".
    dialog.showOpenDialog = async () => {
        refuse('dialog.showOpenDialog', '');
        return { canceled: true, filePaths: [] };
    };
    dialog.showSaveDialog = async () => {
        refuse('dialog.showSaveDialog', '');
        return { canceled: true, filePath: '' };
    };
    dialog.showOpenDialogSync = () => {
        refuse('dialog.showOpenDialogSync', '');
        return undefined;
    };
    dialog.showSaveDialogSync = () => {
        refuse('dialog.showSaveDialogSync', '');
        return '';
    };
    shell.openPath = path => {
        refuse('shell.openPath', path);
        return Promise.resolve('The analyst build does not hand files to the operating system.');
    };
    shell.showItemInFolder = path => {
        refuse('shell.showItemInFolder', path);
    };

    app.on('web-contents-created', (_event, contents) => {
        contents.on('devtools-opened', () => {
            refuse('devtools', contents.getURL());
            contents.closeDevTools();
        });
    });

    globalThis.__mfMainGuard = { refusals };
}

module.exports = { install, isWebUrl };
