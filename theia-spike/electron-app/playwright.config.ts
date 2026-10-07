// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import { defineConfig } from '@playwright/test';

// Spike S-3 smoke test of the installed Electron app. Playwright drives Electron itself, so no
// browser download is needed. Run it through theia-spike/scripts/smoke-installed.ps1.
export default defineConfig({
    testDir: './test',
    timeout: 300_000,
    workers: 1,
    reporter: 'list',
});
