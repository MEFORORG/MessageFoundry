// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-3 smoke test: drive the INSTALLED app through Playwright's Electron launch. It opens a
// sample handler in Steps, makes one typed edit, saves, and checks the file on disk changed.
//
// Run it through scripts/smoke-installed.ps1, which installs the app per-user to a temp folder,
// sets MF_S3_EXE and MF_S3_WORKSPACE, and uninstalls afterwards. The workspace is a temp COPY of
// samples/config, so the edit never touches the checked-in samples or the user's Documents folder.

import { _electron as electron, expect, test } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const FILE = 'IB_ACME_ADT.py';

/** Working set of every process whose image lives under the install folder, in MiB. */
function memoryMiB(installDir: string): { processes: number; mib: number } {
    const ps = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const script = '$d = $env:MF_S3_DIR; $p = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and '
        + '$_.ExecutablePath.StartsWith($d, [StringComparison]::OrdinalIgnoreCase) }; '
        + '"{0} {1}" -f @($p).Count, (($p | Measure-Object WorkingSetSize -Sum).Sum)';
    const out = execFileSync(ps, ['-NoProfile', '-NonInteractive', '-Command', script], {
        // stdin ignored: Windows PowerShell waits on a piped stdin that never closes.
        encoding: 'utf8', env: { ...process.env, MF_S3_DIR: installDir }, timeout: 60_000,
        stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    }).trim();
    const [count, bytes] = out.split(/\s+/).map(Number);
    return { processes: count, mib: Math.round(bytes / 1024 / 1024) };
}

test('installed app opens a handler in Steps, edits and saves', async () => {
    const exe = process.env.MF_S3_EXE;
    const workspace = process.env.MF_S3_WORKSPACE;
    if (!exe || !workspace) {
        throw new Error('MF_S3_EXE and MF_S3_WORKSPACE must be set; run scripts/smoke-installed.ps1');
    }
    const target = path.join(workspace, FILE);
    const before = fs.readFileSync(target, 'utf8');

    const started = Date.now();
    const app = await electron.launch({
        executablePath: exe,
        args: [workspace],
        env: { ...process.env, THEIA_CONFIG_DIR: path.join(path.dirname(workspace), 'theia-config') },
        timeout: 120_000,
    });
    const pid = app.process().pid;
    try {
        const page = await app.firstWindow({ timeout: 120_000 });
        await page.locator('.theia-ApplicationShell').waitFor({ state: 'attached', timeout: 120_000 });
        await page.locator('.theia-preload').waitFor({ state: 'detached', timeout: 120_000 }).catch(() => undefined);
        console.log(`S3 shell ready after ${Date.now() - started} ms`);

        const node = page.locator('.theia-TreeNode', { hasText: FILE }).first();
        if (!(await node.isVisible().catch(() => false))) {
            await page.keyboard.press('Control+Shift+E');
        }
        await node.waitFor({ state: 'visible', timeout: 60_000 });
        await node.dblclick();

        const widget = page.locator('.mf-steps-widget');
        await expect(widget).toHaveAttribute('data-mf-last', /render|webview/, { timeout: 60_000 });
        const frame = page.frameLocator('.mf-steps-widget iframe');
        await expect(frame.locator('li.row').first()).toBeVisible({ timeout: 30_000 });
        await page.screenshot({ path: 'test-results/s3-steps-rendered.png' });
        console.log('S3 step: Steps rendered');

        const to = frame.locator('input.edit[data-name="to"]');
        await expect(to).toHaveValue('OB_ACME_ADT');
        await to.fill('OB_ACME_ADT_S3');
        await to.press('Enter');
        await to.evaluate(el => (el as HTMLInputElement).blur());
        await expect(frame.locator('input.edit[data-name="to"]')).toHaveValue('OB_ACME_ADT_S3', { timeout: 30_000 });
        // The editor tab and its Open Editors entry both carry the dirty marker, so count at least one.
        await expect.poll(() => page.locator('.lm-TabBar-tab.theia-mod-dirty', { hasText: FILE }).count()).toBeGreaterThan(0);
        console.log('S3 step: edit applied, tab dirty');

        const memory = memoryMiB(path.dirname(exe));
        console.log(`S3 memory after edit: ${memory.processes} processes, ${memory.mib} MiB working set`);

        await page.locator('.mf-steps-widget').click({ position: { x: 5, y: 5 } }).catch(() => undefined);
        console.log('S3 step: saving');
        await page.keyboard.press('Control+s');
        await expect(page.locator('.lm-TabBar-tab.theia-mod-dirty', { hasText: FILE })).toHaveCount(0, { timeout: 30_000 });
        await expect.poll(() => fs.readFileSync(target, 'utf8'), { timeout: 15_000 }).toContain('OB_ACME_ADT_S3');
        await page.screenshot({ path: 'test-results/s3-saved.png' });
        const after = fs.readFileSync(target, 'utf8');
        console.log(`S3 saved: ${before.length} -> ${after.length} characters; contains OB_ACME_ADT_S3`);
    } finally {
        // Bounded: a close that hangs must not eat the whole test budget.
        await Promise.race([app.close(), new Promise(r => setTimeout(r, 20_000))]);
        // Theia's backend and the Python children can outlive a close; end the whole tree.
        if (pid) {
            const taskkill = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe');
            try {
                execFileSync(taskkill, ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
            } catch {
                // Already gone.
            }
        }
    }
});
