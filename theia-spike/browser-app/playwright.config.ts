// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import { defineConfig } from '@playwright/test';

// Spike S-1 smoke test. It drives the installed Microsoft Edge (channel 'msedge') so no Playwright
// browser download is needed. The app must already be running: theia-spike/scripts/start.ps1.
export default defineConfig({
    testDir: './test',
    timeout: 120_000,
    workers: 1,
    reporter: 'list',
    use: {
        baseURL: 'http://127.0.0.1:3030',
        channel: 'msedge',
        headless: true,
        viewport: { width: 1400, height: 900 },
    },
});
