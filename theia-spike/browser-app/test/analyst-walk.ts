// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-2 and S-2b: the no-text-route walk, shared by the browser spec (analyst-routes.spec.ts) and
// the Electron spec (electron-app/test/analyst-routes-electron.spec.ts). The analyst build has no route
// that opens a `.py` in a text editor (FR-14, AC-G1), and a message on the Steps path lands in the
// Steps panel, not a pop-up (FR-17).
//
// Each function takes a loaded app; the spec that calls it decides how the app was launched. Both
// specs run against a temporary COPY of samples/config.

import { expect } from '@playwright/test';
import { TheiaQuickCommandPalette } from '@theia/playwright';
import { AnalystPage } from './analyst-pages';

export interface RouteResult { route: string; outcome: string }

/** What differs between the two builds the walk runs on. */
export interface WalkOptions {
    /** The Electron build: an operating-system drop carries a path instead of becoming an untitled buffer. */
    electron: boolean;
}

export interface WalkCounts {
    commands: { enumerated: number; executed: number; skipped: number; ok: number; threw: number; timeout: number };
    menus: { navigator: number; tab: number; clicked: number; skipped: number };
    toastAfter: string[];
    pyEditorAfter: string[];
}

/** Every named route to a `.py` ends in the Steps view or a refusal, never a text editor. */
export async function namedRoutes(a: AnalystPage, opts: WalkOptions): Promise<RouteResult[]> {
    const page = a.page;
    const results: RouteResult[] = [];
    const note = (route: string, outcome: string) => { results.push({ route, outcome }); };

    // Double-clicking the empty editor area runs New Text File in stock Theia. Not registered here.
    const main = page.locator('#theia-main-content-panel');
    // The double-click must land on the dock panel itself, or Theia's handler never runs.
    expect(await main.evaluate(el => {
        const r = el.getBoundingClientRect();
        return document.elementFromPoint(r.left + 300, r.top + 300) === el;
    })).toBe(true);
    await main.dblclick({ position: { x: 300, y: 300 } });
    await page.waitForTimeout(500);
    expect(await a.hook(h => h.textEditors())).toEqual([]);
    note('double-click empty editor area (New Text File)', 'nothing opens; command not registered');

    // 1. Navigator double-click (the S-1 route).
    await a.navigatorNode('IB_ACME_ADT.py').dblclick();
    await a.expectSteps('IB_ACME_ADT.py');
    note('navigator double-click', 'Steps view');

    // 2. Navigator: select and press Enter.
    await a.navigatorNode('IB_FHIR_INTAKE.py').click();
    await page.keyboard.press('Enter');
    await a.expectSteps('IB_FHIR_INTAKE.py');
    note('navigator Enter', 'Steps view');

    // 3. Open With: the command is gone, and the service lists no text editor and refuses.
    const pyUri = await a.fileUri('IB_PARTNER_X12.py');
    expect(await a.hook(h => h.hasHandler('navigator.openWith'))).toBe(false);
    expect(await a.hook((h, u: string) => h.openWithHandlers(u), pyUri)).not.toContain('default');
    expect(await a.hook((h, u: string) => h.openWith(u), pyUri)).toBe('ok');
    await a.navigatorNode('IB_PARTNER_X12.py').click({ button: 'right' });
    const navMenu = await a.visibleMenuLabels();
    // An empty read would pass the check below for the wrong reason.
    expect(navMenu.length).toBeGreaterThan(3);
    expect(navMenu.filter(l => /open with/i.test(l))).toEqual([]);
    await a.dismissTransient();
    note('navigator context menu "Open With..."', `absent (menu: ${navMenu.join(' | ')})`);

    // 4. Every registered opener for a .py: Steps is the only one with a positive priority.
    const openers = await a.hook((h, u: string) => h.openers(u), pyUri);
    expect(openers.map(o => o.id)).toEqual(['mf-steps-spike']);
    note('opener service priorities for a .py', JSON.stringify(openers));

    // 5. workbench.editorAssociations set to the text editor ("default") for *.py.
    expect(await a.hook(h => h.setWorkspacePreference('workbench.editorAssociations', { '*.py': 'default' }))).toBe('ok');
    // The setting must be live, or the check below passes for the wrong reason.
    await expect.poll(() => a.hook(h => h.getPreference('workbench.editorAssociations'))).toEqual({ '*.py': 'default' });
    expect((await a.hook((h, u: string) => h.openers(u), pyUri)).map(o => o.id)).toEqual(['mf-steps-spike']);
    await a.hook((h, u: string) => h.openViaOpener(u), pyUri);
    await a.expectSteps('IB_PARTNER_X12.py');
    await a.hook(h => h.setWorkspacePreference('workbench.editorAssociations', undefined));
    note('workbench.editorAssociations {"*.py": "default"}', 'ignored; Steps view');

    // 6. Quick Open (Ctrl+P). Its file picker comes from @theia/file-search, which this build does not
    // include; if a later build adds it, the picker opens through the opener service (route 4).
    await a.navigatorNode('IB_ACME_ADT.py').click();
    await page.keyboard.press('Control+p');
    await page.waitForTimeout(1000);
    const quick = page.locator('.quick-input-widget');
    if (await quick.isVisible()) {
        await page.keyboard.type('IB_RADIOLOGY_SR.py');
        const row = page.locator('.quick-input-list .monaco-list-row', { hasText: 'IB_RADIOLOGY_SR.py' }).first();
        if (await row.isVisible({ timeout: 3000 }).catch(() => false)) {
            await page.keyboard.press('Enter');
            await a.expectSteps('IB_RADIOLOGY_SR.py');
            note('Quick Open (Ctrl+P)', 'Steps view');
        } else {
            await a.dismissTransient();
            note('Quick Open (Ctrl+P)', 'a picker opened but lists no files (no @theia/file-search)');
        }
    } else {
        note('Quick Open (Ctrl+P)', 'not bound in this build (no @theia/file-search)');
    }
    await a.expectNoPyTextEditor('Ctrl+P');

    // 7. Command palette: the blocked commands are not offered.
    const palette = new TheiaQuickCommandPalette(a.app);
    const offered: string[] = [];
    for (const label of ['Open With', 'New Text File', 'Save As', 'Compare with Each Other', 'Select for Compare', 'Compare with Selected']) {
        await palette.open();
        await palette.type(label, false);
        await page.waitForTimeout(300);
        const rows = await page.locator('.quick-input-list .monaco-list-row .label-name').allInnerTexts();
        offered.push(...rows.filter(r => r.toLowerCase().includes(label.toLowerCase())));
        await palette.hide();
    }
    expect(offered).toEqual([]);
    note('command palette (Open With, New Text File, Save As, Compare...)', 'no entry offered');

    // 8. Problems view: MarkerTreeModel opens a marker with open(openerService, uri, {selection}).
    const pdf = await a.fileUri('IB_PDF_TO_MDM.py');
    expect(await a.hook((h, u: string) => h.openViaOpener(u, 3), pdf)).toBe('ok');
    await a.expectSteps('IB_PDF_TO_MDM.py');
    note('Problems entry (opener with a selection)', 'Steps view');

    // 9. Outline / reopen-closed-editor / workspace edits call EditorManager.open directly.
    const stream = await a.fileUri('IB_STREAM_MDM.py');
    expect(await a.hook((h, u: string) => h.openViaEditorManager(u, 3), stream)).toMatch(/^threw: The analyst build does not open/);
    await a.expectSteps('IB_STREAM_MDM.py');
    note('Outline entry / EditorManager.open direct', 'refused; Steps view opened instead; panel message');

    // 10. The editor widget factory and TextEditorProvider (layout restore, reopen closed editor, split).
    expect(await a.hook((h, u: string) => h.editorFactory(u), stream)).toMatch(/^threw: The analyst build does not create a text editor/);
    expect(await a.hook((h, u: string) => h.textEditorProvider(u), stream)).toMatch(/^threw:/);
    note('editor widget factory / TextEditorProvider (layout restore)', 'refused');

    // 11. A diff editor with a .py on either side.
    const left = await a.fileUri('IB_IMMUNIZATION_VXU.py');
    const diff = await a.hook((h, lr: string[]) => h.diffUri(lr[0], lr[1]), [left, stream]);
    expect(await a.hook((h, u: string) => h.openViaEditorManager(u), diff)).toMatch(/^threw:/);
    expect(await a.hook((h, u: string) => h.openViaOpener(u), diff)).toMatch(/^threw:/);
    note('diff editor on two .py files', 'refused (no opener; EditorManager refuses)');

    // 12. An untitled buffer named x.py.
    expect(await a.hook(h => h.openViaOpener('untitled:/scratch.py'))).toMatch(/^threw:/);
    note('untitled:/scratch.py', 'refused (no opener)');

    // 13. Drag a workspace .py onto the editor area (the navigator's drag payload).
    const rte = await a.fileUri('IB_RTE_ELIGIBILITY.py');
    await page.evaluate((u: string) => {
        const dt = new DataTransfer();
        dt.setData('theia-editor-dnd', u);
        document.getElementById('theia-main-content-panel')!.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true }));
    }, rte);
    await a.expectSteps('IB_RTE_ELIGIBILITY.py');
    note('drag a workspace .py onto the editor area', 'Steps view');

    // 14. Drop a .py from the operating system onto the editor area. The browser build makes it
    // untitled:/dropped.py; the Electron build asks webUtils.getPathForFile for the file's path and
    // opens that through the opener service (application-shell.js), which route 4 covers. A synthetic
    // File has no path, so on Electron this measures only that nothing else opens.
    await page.evaluate(() => {
        const dt = new DataTransfer();
        dt.items.add(new File(['x = 1\n'], 'dropped.py', { type: 'text/x-python' }));
        document.getElementById('theia-main-content-panel')!.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true }));
    });
    await page.waitForTimeout(1000);
    expect((await a.hook(h => h.stepsWidgets())).filter(u => u.includes('dropped'))).toEqual([]);
    await a.expectNoPyTextEditor('an operating-system drop');
    note('drop a .py from the operating system onto the editor area', opts.electron
        ? 'nothing opens (a synthetic File has no path; a real one goes through the opener, route 4)'
        : 'refused (untitled:/dropped.py has no opener)');

    // 15. File > Open File...: Theia's own file dialog, then the opener.
    await a.hook(h => h.exec('workspace:openFile', 1000));
    const dialog = page.locator('.dialogOverlay').filter({ visible: true });
    await dialog.waitFor();
    await dialog.locator('.theia-TreeNode', { hasText: 'IB_IMMUNIZATION_VXU.py' }).first().click();
    await dialog.locator('.dialogControl button.main').click();
    await a.expectSteps('IB_IMMUNIZATION_VXU.py');
    note('File > Open File...', 'Steps view');

    // 16. Open Preferences (JSON) opens settings.json as text (allowed: not a .py), and Save As, the one
    // way to write that buffer to a .py, is not registered.
    await a.hook(h => h.exec('workbench.action.openSettingsJson', 5000));
    await expect.poll(async () => (await a.hook(h => h.textEditors())).some(u => u.endsWith('settings.json'))).toBe(true);
    expect(await a.hook(h => h.hasHandler('file.saveAs'))).toBe(false);
    note('Open Preferences (JSON)', 'settings.json opens as text (not a .py); Save As not registered');

    // 17. A forged openText / openSource message from the Steps webview (its controls are hidden).
    await a.hook((h, u: string) => h.activateSteps(u), await a.fileUri('IB_ACME_ADT.py'));
    const frame = page.frameLocator('.mf-steps-widget:visible iframe');
    await expect(frame.locator('#openText')).toBeHidden();
    await expect(frame.locator('button.jump').first()).toBeHidden();
    const panelMessages = page.locator('.mf-steps-widget:visible .mf-steps-message');
    // The panel keeps five; clear it so two new ones are countable.
    while (await panelMessages.count()) {
        await panelMessages.first().locator('button').click();
    }
    await frame.locator('body').evaluate(() => {
        parent.postMessage({ mfSteps: { command: 'openText' } }, '*');
        parent.postMessage({ mfSteps: { command: 'openSource', line: 3 } }, '*');
    });
    await expect(panelMessages).toHaveCount(2);
    note('Steps webview "View as Code" / jump-to-line (forged message)', 'controls hidden; message refused in the panel');

    // 18. Rename a text file to .py: New File x.txt, typed in the text editor, then renamed.
    const txt = await a.fileUri('notes.txt');
    expect(await a.hook((h, u: string) => h.createFile(u, 'x = 1\n'), txt)).toBe('ok');
    const renamed = await a.fileUri('notes.py');
    expect(await a.hook((h, ft: string[]) => h.move(ft[0], ft[1]), [txt, renamed])).toMatch(/^threw:/);
    expect(await a.hook((h, u: string) => h.exists(u), renamed)).toBe(false);
    note('rename a .txt to .py', 'refused by the FileService rebind');
    // Windows drops a trailing dot, so `notes.py.` lands as `notes.py` (S-2b review).
    expect(await a.hook((h, ft: string[]) => h.move(ft[0], ft[1]), [txt, `${renamed}.`])).toMatch(/^threw:/);
    expect(await a.hook((h, u: string) => h.exists(u), renamed)).toBe(false);
    note('rename a .txt to "notes.py." (Windows drops the dot)', 'refused by the FileService rebind');

    // 18c. Upload a .py (File > Upload Files, or a drop from the operating system onto the navigator).
    // Upload writes through the backend's HTTP endpoint, not the FileService, so route 18 does not
    // cover it. The control upload, a .txt, must land, or a refusal here proves nothing.
    const root = (await a.fileUri('x')).replace(/\/x$/, '');
    expect(await a.hook((h, r: string) => h.upload(r, 'uploaded-control.txt', 'x = 1\n'), root)).toBe('ok');
    await expect.poll(async () => a.hook((h, u: string) => h.exists(u), await a.fileUri('uploaded-control.txt'))).toBe(true);
    // With a Steps view showing, the refusal goes to its panel; with none, it is a toast, which the
    // final no-toast check would count. The walk is about the Steps path, so show one first.
    await a.hook((h, u: string) => h.activateSteps(u), await a.fileUri('IB_ACME_ADT.py'));
    expect(await a.hook((h, r: string) => h.upload(r, 'uploaded.py', 'x = 1\n'), root)).toBe('ok');
    await page.waitForTimeout(1000);
    expect(await a.hook(async (h, u: string) => h.exists(u), await a.fileUri('uploaded.py'))).toBe(false);
    expect((await a.hook(h => h.refusals)).some(r => r.layer === 'upload' && r.target === 'uploaded.py')).toBe(true);
    note('upload a .py (File > Upload Files)', 'refused by the FileUploadService rebind; a .txt control uploads');

    // 18d. The same upload as a drop onto a navigator node, the shape an operating-system drag takes.
    // A synthetic DataTransfer item may carry no file-system entry, so the .txt control says whether
    // this drop reached the upload service at all.
    const dropOnNavigator = async (name: string) => {
        await a.showNavigator();
        await a.navigatorNode('IB_ACME_ADT.py').evaluate((el, n: string) => {
            const dt = new DataTransfer();
            dt.items.add(new File(['x = 1\n'], n, { type: 'text/plain' }));
            el.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
        }, name);
        await page.waitForTimeout(1500);
        return a.hook(async (h, u: string) => h.exists(u), await a.fileUri(name));
    };
    const droppedControl = await dropOnNavigator('dropped-control.txt');
    expect(await dropOnNavigator('dropped-on-navigator.py')).toBe(false);
    note('drop a .py onto the navigator (operating-system drag shape)', droppedControl
        ? 'refused by the FileUploadService rebind; a .txt control lands'
        : 'nothing lands; the synthetic drop does not reach upload (control did not land), so 18c is the evidence');

    // 18b. Keybindings: none is bound to a blocked command.
    const blocked = await a.hook(h => h.blocked);
    const bound = (await a.hook(h => h.keybindings())).filter(k => blocked.includes(k.command));
    expect(bound).toEqual([]);
    note('keybindings to blocked commands', 'none');

    // 19. Main and context menus: no item names a blocked command.
    const menuHits = (await a.hook(h => h.menuItems())).filter(m => blocked.includes(m.commandId));
    expect(menuHits).toEqual([]);
    note('menu items for blocked commands', 'none');

    await a.expectNoPyTextEditor('the named routes');
    expect(await a.toastCount()).toBe(0);
    const refusals = await a.hook(h => h.refusals);
    console.log(`S2-ROUTES ${JSON.stringify(results)}`);
    console.log(`S2-REFUSALS ${JSON.stringify(refusals.map(r => `${r.layer}:${r.reason}:${r.target.slice(-60)}`))}`);
    return results;
}

/** Commands the walk does not run, and why. Matched against the command id. */
export const SKIP: { re: RegExp; why: string }[] = [
    { re: /reload|newWindow|window\.new|closeWindow|close\.window|quit|exit\b/i, why: 'reloads, closes or opens a window' },
    { re: /^workspace:(open|openFolder|openWorkspace|openRecent|close|saveAs)$|openFolder|openWorkspace/i, why: 'changes the workspace and reloads the page' },
    { re: /reset.*layout|layout.*reset/i, why: 'reloads the page' },
    { re: /delete|remove(?!.*Editor)/i, why: 'deletes from the workspace the walk runs in' },
    { re: /download|upload/i, why: 'downloads or uploads a file' },
    { re: /toggleDevTools|devtools/i, why: 'opens developer tools' },
    { re: /^workbench\.action\.(openDocumentationUrl|openIssueReporter|openWebsite)|\.url$/i, why: 'opens an external URL' },
];

/** The scripted walk: every command and context-menu item, no .py text editor, no toast on the Steps path. */
export async function scriptedWalk(a: AnalystPage): Promise<WalkCounts> {
    const page = a.page;
    const file = 'IB_ACME_ADT.py';
    const fileUri = await a.fileUri(file);
    await a.navigatorNode(file).dblclick();
    await a.expectSteps(file);
    // Leave the .py selected in the navigator, so a command that acts on the selection acts on it.
    await a.navigatorNode(file).click();

    const commands = await a.hook(h => h.commands());
    const counts = { enumerated: commands.length, executed: 0, skipped: 0, ok: 0, threw: 0, timeout: 0 };
    const skippedBy: Record<string, number> = {};
    const toastAfter: string[] = [];
    const dialogAfter: string[] = [];
    const pyEditorAfter: string[] = [];

    const ensureSteps = async () => {
        if (!(await a.hook((h, u: string) => h.activateSteps(u), fileUri))) {
            await a.hook((h, u: string) => h.openViaOpener(u), fileUri);
            await a.expectSteps(file);
        }
    };

    for (const cmd of commands) {
        const skip = SKIP.find(s => s.re.test(cmd.id));
        let reason = skip?.why;
        if (!reason && !(await a.hook((h, id: string) => h.hasHandler(id), cmd.id))) {
            reason = 'no handler registered';
        }
        if (!reason) {
            await ensureSteps();
            if (!(await a.hook((h, id: string) => h.isEnabled(id), cmd.id))) {
                reason = 'disabled in this context (needs arguments or a different focus)';
            }
        }
        if (reason) {
            counts.skipped++;
            skippedBy[reason] = (skippedBy[reason] ?? 0) + 1;
            continue;
        }
        const toastsBefore = (await a.hook(h => h.toastPath)).length;
        const outcome = await a.hook((h, id: string) => h.exec(id, 2500), cmd.id);
        counts.executed++;
        if (outcome === 'ok') {
            counts.ok++;
        } else if (outcome === 'timeout') {
            counts.timeout++;
        } else {
            counts.threw++;
        }
        await page.waitForTimeout(150);
        if ((await a.toastCount()) > 0 || (await a.hook(h => h.toastPath)).length > toastsBefore) {
            toastAfter.push(cmd.id);
        }
        if ((await a.dialogCount()) > 0) {
            dialogAfter.push(cmd.id);
        }
        await a.dismissTransient();
        const py = await a.pyTextEditors();
        if (py.manager.length || py.created.length || py.dom) {
            pyEditorAfter.push(`${cmd.id}: ${JSON.stringify(py)}`);
        }
    }

    // Context menus, clicked through the UI: the navigator's on the .py, then the Steps tab's.
    const menuCounts = { navigator: 0, tab: 0, clicked: 0, skipped: 0 };
    const MENU_SKIP = /delete|download|upload|close all|close others|close to the/i;
    const clickEach = async (open: () => Promise<void>, which: 'navigator' | 'tab') => {
        await open();
        const labels = (await a.visibleMenuLabels()).filter(l => l.trim());
        await a.dismissTransient();
        menuCounts[which] = labels.length;
        // An empty read would make this whole loop pass for the wrong reason.
        expect(labels.length, `${which} context menu labels`).toBeGreaterThan(3);
        for (const label of labels) {
            if (MENU_SKIP.test(label)) {
                menuCounts.skipped++;
                continue;
            }
            await ensureSteps();
            await open();
            const item = page.locator('.lm-Menu .lm-Menu-item:not(.lm-mod-hidden)', { hasText: label }).first();
            if (!(await item.isVisible().catch(() => false)) || (await item.getAttribute('class'))?.includes('lm-mod-disabled')) {
                menuCounts.skipped++;
                await a.dismissTransient();
                continue;
            }
            const toastsBefore = (await a.hook(h => h.toastPath)).length;
            await item.click();
            menuCounts.clicked++;
            await page.waitForTimeout(300);
            if ((await a.toastCount()) > 0 || (await a.hook(h => h.toastPath)).length > toastsBefore) {
                toastAfter.push(`${which} menu: ${label}`);
            }
            if ((await a.dialogCount()) > 0) {
                dialogAfter.push(`${which} menu: ${label}`);
            }
            await a.dismissTransient();
            const py = await a.pyTextEditors();
            if (py.manager.length || py.created.length || py.dom) {
                pyEditorAfter.push(`${which} menu ${label}: ${JSON.stringify(py)}`);
            }
        }
    };
    await clickEach(async () => {
        await a.showNavigator();
        await a.navigatorNode(file).click({ button: 'right' });
        await page.locator('.lm-Menu').first().waitFor();
    }, 'navigator');
    await clickEach(async () => {
        await ensureSteps();
        await page.locator('.lm-TabBar-tab', { hasText: `${file} (Steps)` }).first().click({ button: 'right' });
        await page.locator('.lm-Menu').first().waitFor();
    }, 'tab');

    const menus = await a.hook(h => h.menuItems());
    const keybindings = await a.hook(h => h.keybindings());
    console.log(`S2-WALK commands ${JSON.stringify(counts)}`);
    console.log(`S2-WALK skipped ${JSON.stringify(skippedBy)}`);
    console.log(`S2-WALK menus registered=${menus.length} distinct-commands=${new Set(menus.map(m => m.commandId)).size} keybindings=${keybindings.length}`);
    console.log(`S2-WALK context-menus ${JSON.stringify(menuCounts)}`);
    console.log(`S2-WALK dialogs-after ${JSON.stringify(dialogAfter)}`);
    console.log(`S2-WALK toasts-after ${JSON.stringify(toastAfter)}`);
    console.log(`S2-WALK py-text-editors ${JSON.stringify(pyEditorAfter)}`);
    const panel = await page.evaluate(() => ((window as unknown as { __mfStepsSpike?: { kind: string; detail?: string }[] })
        .__mfStepsSpike ?? []).filter(e => e.kind === 'panel-message').map(e => e.detail ?? ''));
    console.log(`S2-WALK panel-messages count=${panel.length} distinct=${JSON.stringify([...new Set(panel)])}`);

    expect(pyEditorAfter).toEqual([]);
    expect(toastAfter).toEqual([]);
    return { commands: counts, menus: menuCounts, toastAfter, pyEditorAfter };
}

/**
 * A message raised while the Steps view is up lands in the panel, not a toast; and the control: with
 * no Steps view, the same call raises a toast, so the counter is live.
 */
export async function messageGate(a: AnalystPage): Promise<void> {
    await a.navigatorNode('IB_ACME_ADT.py').dblclick();
    await a.expectSteps('IB_ACME_ADT.py');
    for (const type of ['info', 'warn', 'error'] as const) {
        await a.hook((h, t: string) => h.message(t as 'info', `S-2 probe ${t}`), type);
    }
    await a.hook(h => h.progress('S-2 probe progress'));
    await expect(a.page.locator('.mf-steps-widget:visible .mf-steps-message')).toHaveCount(4);
    expect(await a.toastCount()).toBe(0);
    expect(await a.hook(h => h.toastPath)).toEqual([]);
    // The panel's own Dismiss removes a message: no pop-up is needed to clear one.
    await a.page.locator('.mf-steps-widget:visible .mf-steps-message button').first().click();
    await expect(a.page.locator('.mf-steps-widget:visible .mf-steps-message')).toHaveCount(3);

    // Control: with no Steps view showing, the same call raises a toast. Without this, a toast counter
    // that can never fire would pass the walk's "no toast" check too.
    await a.page.locator('.lm-TabBar-tab', { hasText: 'IB_ACME_ADT.py (Steps)' }).first().locator('.lm-TabBar-tabCloseIcon').click();
    await expect.poll(() => a.hook(h => h.stepsWidgets())).toEqual([]);
    await a.hook(h => h.message('info', 'S-2 control toast'));
    await expect.poll(() => a.toastCount()).toBeGreaterThan(0);
    expect((await a.hook(h => h.toastPath)).map(t => t.text)).toEqual(['S-2 control toast']);
}
