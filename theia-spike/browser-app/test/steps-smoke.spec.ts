// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-1 smoke test: open a sample handler in the Steps widget, edit a typed row through
// `lens rewrite`, undo it, and check whether a dirty buffer survives a reload (hot-exit).
// The workspace is a temporary COPY of samples/config made by @theia/playwright, so the
// edit never touches the checked-in samples.

import { expect, Page, test } from '@playwright/test';
import { TheiaAppLoader, TheiaWorkspace } from '@theia/playwright';

interface SpikeEvent { kind: string; detail?: string }

/** The events the Steps widget records on `window.__mfStepsSpike` (see steps-widget.ts). */
function events(page: Page): Promise<SpikeEvent[]> {
    return page.evaluate(() => (window as unknown as { __mfStepsSpike?: SpikeEvent[] }).__mfStepsSpike ?? []);
}

const FILE = 'IB_ACME_ADT.py';

test('Steps widget renders, edits, undoes', async ({ playwright, browser }) => {
    const workspace = new TheiaWorkspace(['../../samples/config']);
    const app = await TheiaAppLoader.load({ playwright, browser }, workspace);
    const page = app.page;

    // Open the file the way an analyst would: double-click it in the navigator.
    await page.locator('#files').waitFor({ state: 'attached' }).catch(() => undefined);
    const node = page.locator('.theia-TreeNode', { hasText: FILE }).first();
    if (!(await node.isVisible())) {
        await page.keyboard.press('Control+Shift+E');
    }
    await node.dblclick();

    const widget = page.locator('.mf-steps-widget');
    await expect(widget).toHaveAttribute('data-mf-last', /render|webview/, { timeout: 30_000 });
    await expect(widget).toHaveAttribute('data-mf-rows', '2');
    const frame = page.frameLocator('.mf-steps-widget iframe');
    await expect(frame.locator('li.row')).toHaveCount(2);
    await page.screenshot({ path: 'test-results/steps-rendered.png' });

    // The webview script loaded and pinged the host through the acquireVsCodeApi shim.
    await expect.poll(async () => (await events(page))
        .some(e => e.kind === 'webview' && (e.detail ?? '').includes('alive'))).toBe(true);

    // One set_params edit on the send row's `to`.
    const to = frame.locator('input.edit[data-name="to"]');
    await expect(to).toHaveValue('OB_ACME_ADT');
    await to.fill('OB_ACME_ADT_TEST');
    await to.press('Enter');
    await to.evaluate(el => (el as HTMLInputElement).blur());
    await expect.poll(async () => (await events(page)).filter(e => e.kind === 'edit').length).toBe(1);
    await expect(frame.locator('input.edit[data-name="to"]')).toHaveValue('OB_ACME_ADT_TEST', { timeout: 15_000 });
    // The tab carries Theia's dirty marker once the document model is dirty.
    await expect(page.locator('.lm-TabBar-tab.theia-mod-dirty', { hasText: FILE })).toHaveCount(1);

    // Undo from inside the webview (Ctrl+Z posts `undo`; the host calls the model's undo).
    await frame.locator('li.row').first().click();
    await page.keyboard.press('Control+z');
    await expect.poll(async () => (await events(page)).filter(e => e.kind === 'undo').length).toBeGreaterThan(0);
    await expect(frame.locator('input.edit[data-name="to"]')).toHaveValue('OB_ACME_ADT', { timeout: 15_000 });
    await expect(page.locator('.lm-TabBar-tab.theia-mod-dirty', { hasText: FILE })).toHaveCount(0);

    // Hot-exit probe: make the buffer dirty again, reload the page, and see what survives.
    const to2 = frame.locator('input.edit[data-name="to"]');
    await to2.fill('OB_HOT_EXIT_PROBE');
    await to2.press('Enter');
    await to2.evaluate(el => (el as HTMLInputElement).blur());
    await expect(frame.locator('input.edit[data-name="to"]')).toHaveValue('OB_HOT_EXIT_PROBE', { timeout: 15_000 });
    page.on('dialog', d => d.accept());
    await page.reload();
    await app.waitForShellAndInitialized();
    const reopened = page.locator('.mf-steps-widget');
    const restored = await reopened.isVisible({ timeout: 20_000 }).catch(() => false);
    let value: string | null = null;
    if (restored) {
        await expect(reopened).toHaveAttribute('data-mf-last', /render|webview/, { timeout: 30_000 });
        value = await page.frameLocator('.mf-steps-widget iframe').locator('input.edit[data-name="to"]').inputValue();
    }
    console.log(`HOT-EXIT widget restored=${restored} to=${value}`);
});
