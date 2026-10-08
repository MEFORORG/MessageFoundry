// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-2b (ADR 0208): S-2's no-text-route walk on the ELECTRON build, through Playwright's Electron
// launch. The first three tests are S-2's walk, shared with the browser spec (analyst-walk.ts). The
// fourth drives the routes only Electron has: the operating system's editor and Explorer, window.open,
// Developer Tools, Electron's default menu, and native dialogs and menus.
//
// Which app it drives:
//   - MF_S3_EXE set (scripts/smoke-installed.ps1 sets it): the INSTALLED, packaged app;
//   - otherwise the PACKAGED but not installed app in dist/win-unpacked, which
//     scripts/build-installer.ps1 leaves beside the installer. The unpackaged layout (electron.exe plus
//     this folder) is not used: Playwright puts --remote-debugging-port ahead of the app path, so
//     Theia's argv parser takes the app folder, not the workspace, as the folder to open.
//   - MF_S2B_CDP_EXE set (scripts/measure-fuses.ps1 sets it): a copy with the Node fuses OFF. Playwright's
//     Electron launch needs --inspect, which that fuse refuses, so this mode starts the app itself with
//     --remote-debugging-port and attaches over CDP. Only the page is reachable that way, so the
//     Electron-only test, which reads the main process, is skipped.
// Either way the workspace is a temporary copy of samples/config, and Electron's user-data folder and
// Theia's config folder are temporary too. Two things still use the user's profile: the launcher
// appends to launcher.log under %APPDATA%, and Electron takes its single-instance lock before
// --electronUserData applies, so an open copy of the spike app makes every test instance quit.
//
// The probes that reach the operating system use a path that does not exist, so a guard that failed
// would hand Windows a missing file rather than open a real one.

import { _electron as electron, Browser, chromium, ElectronApplication, expect, Page, test } from '@playwright/test';
import { TheiaApp, TheiaWorkspace } from '@theia/playwright';
import { execFileSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AnalystPage } from '../../browser-app/test/analyst-pages';
import { messageGate, namedRoutes, scriptedWalk } from '../../browser-app/test/analyst-walk';

const PROBE_PATH = 'C:\\mf-s2b-probe-does-not-exist\\probe.py';
const PROBE_URI = 'file:///C:/mf-s2b-probe-does-not-exist/probe.py';

interface Launched { electronApp?: ElectronApplication; cdp?: Browser; pid?: number; a: AnalystPage; scratch: string; workspace: string }

const CDP_PORT = 9339;

const launched: Launched[] = [];

function which(): string {
    if (process.env.MF_S2B_CDP_EXE) {
        return `fused copy over CDP (${process.env.MF_S2B_CDP_EXE})`;
    }
    return process.env.MF_S3_EXE ? `installed (${process.env.MF_S3_EXE})` : 'packaged, not installed (dist/win-unpacked)';
}

async function launch(): Promise<Launched> {
    const workspace = new TheiaWorkspace(['../../samples/config']);
    workspace.initialize();
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mf-s2b-'));
    const userData = path.join(scratch, 'user-data');
    const cdpExe = process.env.MF_S2B_CDP_EXE;
    const executablePath = cdpExe ?? process.env.MF_S3_EXE
        ?? path.resolve(__dirname, '..', 'dist', 'win-unpacked', 'MessageFoundry Steps Spike.exe');
    if (!fs.existsSync(executablePath)) {
        throw new Error(`No app at ${executablePath}; run scripts/build-installer.ps1 first`);
    }
    const args = [`--electronUserData=${userData}`, workspace.path];
    const env = {
        ...process.env,
        THEIA_CONFIG_DIR: path.join(scratch, 'theia-config'),
        // The splash and early window would be firstWindow(); the walk wants the shell.
        THEIA_NO_SPLASH: 'true',
        THEIA_ELECTRON_NO_EARLY_WINDOW: '1',
    };
    // Registered before anything can throw, so afterEach still kills the app and removes the folders.
    const entry: Launched = { a: undefined as unknown as AnalystPage, scratch, workspace: workspace.path };
    launched.push(entry);
    let page: Page;
    if (cdpExe) {
        // --no-cluster runs Theia's backend inside the main process. Without it Theia forks the backend
        // as `<exe>` with ELECTRON_RUN_AS_NODE=1, which the RunAsNode fuse refuses: the child starts as a
        // second app, prints its usage and exits, and no window ever loads (measured, S-2b).
        const child = spawn(executablePath, [`--remote-debugging-port=${CDP_PORT}`, '--no-cluster', ...args],
            { env, stdio: 'ignore', windowsHide: true });
        entry.pid = child.pid;
        entry.cdp = await connectWithRetry(`http://127.0.0.1:${CDP_PORT}`, 120_000);
        page = await shellPage(entry.cdp, 120_000);
    } else {
        entry.electronApp = await electron.launch({ executablePath, args, env, timeout: 120_000 });
        entry.pid = entry.electronApp.process().pid;
        page = await entry.electronApp.firstWindow({ timeout: 120_000 });
    }
    const app = new TheiaApp(page, workspace, true);
    await app.waitForShellAndInitialized();
    entry.a = new AnalystPage(app);
    await entry.a.showNavigator();
    console.log(`S2B-APP ${which()}`);
    return entry;
}

async function connectWithRetry(url: string, ms: number): Promise<Browser> {
    const deadline = Date.now() + ms;
    for (;;) {
        try {
            return await chromium.connectOverCDP(url, { timeout: 10_000 });
        } catch (err) {
            if (Date.now() > deadline) {
                throw err;
            }
            await new Promise(r => setTimeout(r, 1000));
        }
    }
}

/** The Theia window, once it has loaded: CDP also lists the splash and any secondary window. */
async function shellPage(cdp: Browser, ms: number): Promise<Page> {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
        for (const context of cdp.contexts()) {
            const found = context.pages().find(p => /\/lib\/frontend\/index\.html/.test(p.url()));
            if (found) {
                return found;
            }
        }
        await new Promise(r => setTimeout(r, 1000));
    }
    throw new Error('No Theia window appeared over CDP');
}

test.afterEach(async () => {
    for (const { electronApp, cdp, pid, scratch, workspace } of launched.splice(0)) {
        await cdp?.close().catch(() => undefined);
        if (electronApp) {
            await Promise.race([electronApp.close().catch(() => undefined), new Promise(r => setTimeout(r, 20_000))]);
        }
        // Theia's backend and the Python children can outlive a close; end the whole tree.
        if (pid) {
            const taskkill = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe');
            try {
                execFileSync(taskkill, ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
            } catch {
                // Already gone.
            }
        }
        // Chromium's cache can stay locked for a moment after the tree is killed.
        for (const dir of [scratch, workspace]) {
            try {
                fs.rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 500 });
            } catch (err) {
                console.log(`S2B-CLEANUP could not remove ${dir}: ${String(err)}`);
            }
        }
    }
});

/** The main-process guard's refusals (analyst-main-guard.js). */
async function mainRefusals(electronApp: ElectronApplication): Promise<{ route: string; target: string }[]> {
    return electronApp.evaluate(() => (globalThis as unknown as { __mfMainGuard?: { refusals: { route: string; target: string }[] } })
        .__mfMainGuard?.refusals.map(r => ({ route: r.route, target: r.target })) ?? []);
}

test('S-2b: every named route to a .py ends in the Steps view or a refusal (Electron)', async () => {
    test.setTimeout(300_000);
    const { a } = await launch();
    const results = await namedRoutes(a, { electron: true });
    expect(results.length).toBeGreaterThan(0);
});

test('S-2b: scripted walk over every command and context-menu item (Electron)', async () => {
    test.setTimeout(1_200_000);
    const { a } = await launch();
    await scriptedWalk(a);
});

test('S-2b: a message on the Steps path lands in the panel; the control raises a toast (Electron)', async () => {
    test.setTimeout(300_000);
    const { a } = await launch();
    await messageGate(a);
});

test('S-2b: the routes only Electron has are closed', async () => {
    test.setTimeout(300_000);
    test.skip(!!process.env.MF_S2B_CDP_EXE, 'reads the main process, which a CDP attach cannot reach');
    const { electronApp: maybeApp, a } = await launch();
    const electronApp = maybeApp!;
    const page = a.page;
    const results: { route: string; outcome: string }[] = [];
    const note = (route: string, outcome: string) => { results.push({ route, outcome }); };
    const pyUri = await a.fileUri('IB_ACME_ADT.py');

    // The guard is installed: the main process has its log, and the default menu is gone.
    expect(await electronApp.evaluate(() => !!(globalThis as unknown as { __mfMainGuard?: unknown }).__mfMainGuard)).toBe(true);

    // E1. The three Electron-only commands. The command-registry refusals are the control: they show the
    // Electron contributions really tried to register each one, so "no handler" is the guard's doing.
    const electronOnly = ['openWithSystemApp', 'revealFileInOS', 'theia.toggleDevTools'];
    const attempted = (await a.hook(h => h.refusals)).filter(r => r.layer === 'command-registry').map(r => r.target);
    for (const id of electronOnly) {
        expect(attempted, `the Electron build registers ${id}`).toContain(id);
        expect(await a.hook((h, c: string) => h.hasHandler(c), id)).toBe(false);
    }
    await a.navigatorNode('IB_ACME_ADT.py').click({ button: 'right' });
    const navMenu = await a.visibleMenuLabels();
    await a.dismissTransient();
    // An empty read would pass the check below for the wrong reason.
    expect(navMenu.length).toBeGreaterThan(3);
    expect(navMenu.filter(l => /system editor|reveal in|file explorer|open with/i.test(l))).toEqual([]);
    note('Open With System Editor / Reveal in File Explorer / Toggle Developer Tools commands',
        `not registered (each attempted and refused); navigator menu: ${navMenu.join(' | ')}`);

    // E2. Open With's "System Editor" handler: dropped for a .py, still offered for a non-.py (the control).
    expect(await a.hook((h, u: string) => h.openWithHandlers(u), pyUri)).not.toContain('system-editor');
    const toml = await a.fileUri('connections.toml');
    expect(await a.hook((h, u: string) => h.exists(u), toml)).toBe(true);
    expect(await a.hook((h, u: string) => h.openWithHandlers(u), toml)).toContain('system-editor');
    note('Open With > System Editor handler', 'dropped for a .py; offered for connections.toml (control)');

    // E3. The external-app opener (openExternalApp option) and the preload API, both into electron.shell.
    expect(await a.hook((h, u: string) => h.openViaOpenerWith(u, { openExternalApp: true }), PROBE_URI)).toBe('ok');
    await page.evaluate(([p]) => {
        const core = (window as unknown as { electronTheiaCore: { openWithSystemApp(p: string): void; showItemInFolder(p: string): void } }).electronTheiaCore;
        core.openWithSystemApp(p);
        core.showItemInFolder(p);
    }, [PROBE_PATH]);
    await expect.poll(async () => (await mainRefusals(electronApp)).map(r => r.route)).toEqual(
        expect.arrayContaining(['shell.openExternal', 'shell.showItemInFolder']));
    const shellRefusals = (await mainRefusals(electronApp)).filter(r => r.route.startsWith('shell.'));
    expect(shellRefusals.filter(r => r.route === 'shell.openExternal').length).toBeGreaterThanOrEqual(2);
    note('external-app opener and electronTheiaCore.openWithSystemApp / showItemInFolder (forged IPC)',
        `refused in the main process: ${JSON.stringify(shellRefusals.map(r => r.route))}`);

    // E4. window.open on a file: URL. Theia's window-open handler asks "Open link ... in the system
    // handler?" with a synchronous native box; the stub answers OK, as a user would, so the refusal
    // has to come from the guard underneath.
    await electronApp.evaluate(({ dialog }) => {
        const g = globalThis as unknown as { __mfS2bBoxes: string[] };
        g.__mfS2bBoxes = [];
        dialog.showMessageBoxSync = ((...args: unknown[]) => {
            const opts = args[args.length - 1] as { message?: string };
            g.__mfS2bBoxes.push(String(opts?.message ?? ''));
            return 0;
        }) as typeof dialog.showMessageBoxSync;
    });
    const before = (await mainRefusals(electronApp)).length;
    await page.evaluate(u => { window.open(u); }, PROBE_URI);
    await expect.poll(async () => (await mainRefusals(electronApp)).length).toBeGreaterThan(before);
    const boxes = await electronApp.evaluate(() => (globalThis as unknown as { __mfS2bBoxes: string[] }).__mfS2bBoxes);
    expect(boxes.length).toBe(1);
    expect((await mainRefusals(electronApp)).slice(before).map(r => r.route)).toEqual(['shell.openExternal']);
    note('window.open(file:...py), user answers OK', 'refused in the main process after the prompt');

    // E5. Developer Tools: the keybinding, and the preload call. The preload call is the control: it
    // does open Developer Tools, and the guard's close is what the refusal records.
    const devtoolsOpen = () => electronApp.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows().some(w => w.webContents.isDevToolsOpened()));
    const devRefusals = async () => (await mainRefusals(electronApp)).filter(r => r.route === 'devtools').length;
    await page.locator('.mf-steps-widget, #theia-main-content-panel').first().click({ position: { x: 5, y: 5 } }).catch(() => undefined);
    // Alt+F12 is Theia's own binding; Ctrl+Shift+I and F12 are Chromium's and Electron's default menu's.
    // The refusal count must not move: a move would mean the key opened it and the guard closed it.
    const keysBefore = await devRefusals();
    for (const key of ['Alt+F12', 'Control+Shift+I', 'F12']) {
        await page.keyboard.press(key);
        await page.waitForTimeout(1500);
        expect(await devtoolsOpen(), key).toBe(false);
    }
    expect(await devRefusals()).toBe(keysBefore);
    const devBefore = await devRefusals();
    await page.evaluate(() => (window as unknown as { electronTheiaCore: { toggleDevTools(): void } }).electronTheiaCore.toggleDevTools());
    await expect.poll(async () => (await mainRefusals(electronApp)).filter(r => r.route === 'devtools').length).toBeGreaterThan(devBefore);
    await page.waitForTimeout(500);
    expect(await devtoolsOpen()).toBe(false);
    note('Developer Tools (Alt+F12, Ctrl+Shift+I, F12, forged toggleDevTools IPC)', 'keys never open it; the forged call opens it and the main process closes it');

    // E6. Electron's default application menu (Ctrl+Shift+I, Ctrl+R) and the native menu bar.
    expect(await electronApp.evaluate(({ Menu }) => Menu.getApplicationMenu() === null)).toBe(true);
    expect(await page.evaluate(() => (window as unknown as { electronTheiaCore: { useNativeElements: boolean } }).electronTheiaCore.useNativeElements)).toBe(false);
    await expect(page.locator('#theia-top-panel .lm-MenuBar')).toBeVisible();
    note('Electron default menu / native menu bar', 'no application menu; native elements off; Theia\'s in-app menu bar only');

    // E7. Native file dialogs: File > Open File shows Theia's in-app dialog, and the main process's
    // dialog.showOpenDialog is never called. The spy counts calls without answering them.
    await electronApp.evaluate(({ dialog }) => {
        const g = globalThis as unknown as { __mfS2bDialogs: number };
        g.__mfS2bDialogs = 0;
        for (const name of ['showOpenDialog', 'showOpenDialogSync', 'showSaveDialog', 'showSaveDialogSync'] as const) {
            const original = dialog[name].bind(dialog) as (...args: unknown[]) => unknown;
            (dialog as unknown as Record<string, unknown>)[name] = (...args: unknown[]) => { g.__mfS2bDialogs++; return original(...args); };
        }
    });
    await a.hook(h => h.exec('workspace:openFile', 1000));
    await expect(page.locator('.dialogOverlay').filter({ visible: true })).toHaveCount(1);
    await a.dismissTransient();
    expect(await electronApp.evaluate(() => (globalThis as unknown as { __mfS2bDialogs: number }).__mfS2bDialogs)).toBe(0);
    note('File > Open File (native dialog)', 'Theia\'s in-app dialog; the native dialog is never called');

    // E7b. A forged request for the native dialog, through the preload API. The main guard answers
    // "cancelled" and records it; a native dialog here would block this test until it timed out.
    const forged = await page.evaluate(async () => {
        const fsApi = (window as unknown as { electronTheiaFilesystem: { showOpenDialog(o: object): Promise<unknown>; showSaveDialog(o: object): Promise<unknown> } }).electronTheiaFilesystem;
        return [await fsApi.showOpenDialog({ title: 'probe' }), await fsApi.showSaveDialog({ title: 'probe' })];
    });
    expect(forged).toEqual([[], '']);
    const dialogRefusals = (await mainRefusals(electronApp)).filter(r => r.route.startsWith('dialog.')).map(r => r.route);
    expect(dialogRefusals).toEqual(['dialog.showOpenDialog', 'dialog.showSaveDialog']);
    note('forged native-dialog IPC (electronTheiaFilesystem.showOpenDialog / showSaveDialog)', 'refused in the main process; answered "cancelled"');

    await a.expectNoPyTextEditor('the Electron-only routes');
    console.log(`S2B-ELECTRON-ROUTES ${JSON.stringify(results)}`);
    console.log(`S2B-MAIN-REFUSALS ${JSON.stringify(await mainRefusals(electronApp))}`);
});
