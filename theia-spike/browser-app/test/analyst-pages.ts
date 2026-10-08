// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-2 page objects. They extend what the S-1 smoke test does by hand (open a file from the
// navigator, read the Steps widget) with the instruments the no-text-route walk needs. Most reads go
// through `window.__mfAnalyst`, the hook analyst-frontend-module.ts installs; the DOM checks are the
// independent second instrument for the two claims that matter (no text editor, no toast).

import { expect, Locator, Page } from '@playwright/test';
import { TheiaApp } from '@theia/playwright';

export interface Refusal { at: number; layer: string; reason: string; target: string }
export interface MenuItemRecord { path: string[]; commandId: string; label: string }

/** The hook's shape, as the test uses it. Every function runs in the page. */
export interface AnalystHook {
    refusals: Refusal[];
    toastPath: { at: number; type: string; text: string }[];
    createdEditors: string[];
    blocked: string[];
    fileUri(rel: string): Promise<string>;
    commands(): { id: string; label: string; category: string }[];
    isEnabled(id: string): boolean;
    hasHandler(id: string): boolean;
    exec(id: string, ms?: number): Promise<string>;
    menuItems(): MenuItemRecord[];
    keybindings(): { keybinding: string; command: string }[];
    textEditors(): string[];
    stepsWidgets(): string[];
    currentWidget(): string;
    openers(u: string): Promise<{ id: string; priority: number }[]>;
    openViaOpener(u: string, line?: number): Promise<string>;
    openViaEditorManager(u: string, line?: number): Promise<string>;
    openWithHandlers(u: string): string[];
    openWith(u: string): Promise<string>;
    editorFactory(u: string): Promise<string>;
    textEditorProvider(u: string): Promise<string>;
    diffUri(l: string, r: string): string;
    message(type: 'info' | 'warn' | 'error', text: string): Promise<string>;
    setWorkspacePreference(key: string, value: unknown): Promise<string>;
    getPreference(key: string): unknown;
    createFile(u: string, text: string): Promise<string>;
    move(from: string, to: string): Promise<string>;
    exists(u: string): Promise<boolean>;
    progress(text: string): Promise<string>;
    activateSteps(u?: string): Promise<string>;
}

type HookFn<A, R> = (hook: AnalystHook, arg: A) => R | Promise<R>;

export class AnalystPage {
    readonly page: Page;

    constructor(readonly app: TheiaApp) {
        this.page = app.page;
    }

    /** Run `fn` against the hook in the page. `fn` must be self-contained: it is serialized. */
    async hook<R, A = undefined>(fn: HookFn<A, R>, arg?: A): Promise<R> {
        await this.page.waitForFunction(() => !!(window as unknown as { __mfAnalyst?: unknown }).__mfAnalyst);
        return this.page.evaluate(
            ([src, a]) => {
                // eslint-disable-next-line no-new-func
                const f = new Function(`return (${src as string})`)() as HookFn<unknown, unknown>;
                return f((window as unknown as { __mfAnalyst: AnalystHook }).__mfAnalyst, a);
            },
            [fn.toString(), arg] as const,
        ) as Promise<R>;
    }

    fileUri(name: string): Promise<string> {
        return this.hook((h, n: string) => h.fileUri(n), name);
    }

    navigatorNode(name: string): Locator {
        return this.page.locator('#files .theia-TreeNode', { hasText: name }).first();
    }

    async showNavigator(): Promise<void> {
        if (!(await this.page.locator('#files').isVisible().catch(() => false))) {
            await this.page.keyboard.press('Control+Shift+E');
        }
        await this.page.locator('#files .theia-TreeNode').first().waitFor();
    }

    /** Waits until a Steps widget for `name` has rendered. */
    async expectSteps(name: string): Promise<void> {
        await expect.poll(async () => (await this.hook(h => h.stepsWidgets())).some(u => u.endsWith(`/${name}`)),
            { timeout: 30_000 }).toBe(true);
    }

    /** Text editors open on a `.py`, counted two ways: the editor manager, and Monaco DOM in a `.py` tab. */
    async pyTextEditors(): Promise<{ manager: string[]; created: string[]; dom: number }> {
        // A `.py` at the end of the path, or before a query, fragment or encoded delimiter (a diff URI).
        const isPy = (u: string) => /\.py(?=$|[?#%&])/i.test(u);
        const manager = (await this.hook(h => h.textEditors())).filter(isPy);
        const created = (await this.hook(h => h.createdEditors)).filter(isPy);
        const dom = await this.page.evaluate(() => Array.from(document.querySelectorAll('.theia-editor .monaco-editor'))
            .filter(el => {
                const owner = el.closest('[id^="code-editor-opener:"]');
                return owner !== null && /\.py/i.test(owner.id);
            }).length);
        return { manager, created, dom };
    }

    async expectNoPyTextEditor(context: string): Promise<void> {
        const found = await this.pyTextEditors();
        expect(found, `a .py text editor after: ${context}`).toEqual({ manager: [], created: [], dom: 0 });
    }

    /**
     * Notifications on screen: a toast, or an entry in an open notification center. Counting only the
     * toast container would read 0 for the rest of a walk once some command opened the center.
     */
    toastCount(): Promise<number> {
        return this.page.locator('.theia-notification-list-item').filter({ visible: true }).count();
    }

    dialogCount(): Promise<number> {
        return this.page.locator('.dialogOverlay').filter({ visible: true }).count();
    }

    /** Close whatever a command left open: a quick pick, a menu, a dialog. */
    async dismissTransient(): Promise<void> {
        for (let i = 0; i < 3; i++) {
            if ((await this.dialogCount()) === 0 && !(await this.page.locator('.quick-input-widget').isVisible().catch(() => false))
                && (await this.page.locator('.lm-Menu').count()) === 0) {
                return;
            }
            await this.page.keyboard.press('Escape');
            await this.page.waitForTimeout(100);
        }
        // A dialog that ignores Escape: press its secondary (Cancel/Close) button.
        const cancel = this.page.locator('.dialogOverlay .dialogControl button.secondary').first();
        if (await cancel.isVisible().catch(() => false)) {
            await cancel.click();
        }
    }

    /** The visible labels of an open Lumino menu. */
    async visibleMenuLabels(): Promise<string[]> {
        return this.page.locator('.lm-Menu .lm-Menu-item:not(.lm-mod-hidden) .lm-Menu-itemLabel').allInnerTexts();
    }
}
