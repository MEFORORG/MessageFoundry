// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-1: how much of ide/src/stepsModel.ts the Theia Steps widget actually links.
//
// Method: bundle ide/src/stepsModel.ts with esbuild three ways, tree-shaken and unminified, and
// compare the bytes that survive.
//   all     - every export (the whole file as code)
//   spike   - only the names steps-widget.ts imports
//   vscode  - only the names ide/src/stepsView.ts (the VS Code provider) imports
// The spike/all ratio is the share this spike reuses; vscode/all is the share a full port would need.
// Run from the repository root: node theia-spike/scripts/measure-reuse.mjs

import { build } from '../node_modules/esbuild/lib/main.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const model = resolve('ide/src/stepsModel.ts').replace(/\\/g, '/');

function importedNames(file, fromModule) {
    const text = readFileSync(file, 'utf8');
    const re = new RegExp(`import\\s*\\{([^}]*)\\}\\s*from\\s*["'][^"']*${fromModule}["']`, 'g');
    const names = new Set();
    for (const m of text.matchAll(re)) {
        for (const raw of m[1].split(',')) {
            const name = raw.replace(/\btype\b/g, '').trim();
            if (name) { names.add(name); }
        }
    }
    return [...names];
}

async function bytes(entrySource) {
    const out = await build({
        stdin: { contents: entrySource, resolveDir: process.cwd(), loader: 'ts' },
        bundle: true, write: false, format: 'esm', treeShaking: true, minify: false,
        platform: 'neutral', logLevel: 'silent',
    });
    return out.outputFiles[0].contents.length;
}

const spikeNames = importedNames('theia-spike/steps-extension/src/browser/steps-widget.ts', 'stepsModel');
const vscodeNames = importedNames('ide/src/stepsView.ts', 'stepsModel');
// Type-only names have no runtime code; esbuild drops them, so passing them is harmless.
const entry = names => names.map(n => `export { ${n} } from '${model}';`).join('\n');

const all = await bytes(`export * from '${model}';`);
const spike = await bytes(entry(spikeNames));
const vscode = await bytes(entry(vscodeNames));
const lines = readFileSync('ide/src/stepsModel.ts', 'utf8').split('\n').length;

console.log(`stepsModel.ts lines: ${lines}`);
console.log(`names imported: spike ${spikeNames.length}, VS Code provider ${vscodeNames.length}`);
console.log(`bundled bytes: all ${all}, spike ${spike} (${(100 * spike / all).toFixed(1)}%), VS Code provider ${vscode} (${(100 * vscode / all).toFixed(1)}%)`);
