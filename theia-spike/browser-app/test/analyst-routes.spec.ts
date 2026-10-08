// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-2: the analyst build has no route that opens a `.py` in a text editor (FR-14, AC-G1), and a
// message on the Steps path lands in the Steps panel, not a pop-up (FR-17). This is the browser build;
// the walk itself is in analyst-walk.ts, which the Electron spec (S-2b) runs too.
//
// Three tests: the named routes, the scripted walk over every command and context-menu item, and the
// message gate with its toast control. Each runs against a temporary COPY of samples/config made by
// @theia/playwright.

import { expect, test } from '@playwright/test';
import { TheiaAppLoader, TheiaWorkspace } from '@theia/playwright';
import { AnalystPage } from './analyst-pages';
import { messageGate, namedRoutes, scriptedWalk } from './analyst-walk';

async function load(playwright: Parameters<typeof TheiaAppLoader.load>[0]['playwright'],
    browser: Parameters<typeof TheiaAppLoader.load>[0]['browser']): Promise<AnalystPage> {
    const workspace = new TheiaWorkspace(['../../samples/config']);
    const app = await TheiaAppLoader.load({ playwright, browser }, workspace);
    const a = new AnalystPage(app);
    await a.showNavigator();
    return a;
}

test('every named route to a .py ends in the Steps view or a refusal, never a text editor', async ({ playwright, browser }) => {
    test.setTimeout(300_000);
    const a = await load(playwright, browser);
    const results = await namedRoutes(a, { electron: false });
    expect(results.length).toBeGreaterThan(0);
});

test('scripted walk: every command and context-menu item, no .py text editor, no toast on the Steps path', async ({ playwright, browser }) => {
    test.setTimeout(1_200_000);
    await scriptedWalk(await load(playwright, browser));
});

test('a message raised while the Steps view is up lands in the panel, not a toast', async ({ playwright, browser }) => {
    await messageGate(await load(playwright, browser));
});
