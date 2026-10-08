// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// Spike S-2b: read or flip the Electron fuses on a built app's executable. @theia/electron 1.76 has no
// fuse setting of its own; the fuses live in the Electron binary, and @electron/fuses (a dependency of
// electron-builder 26, which also exposes it as the `electronFuses` build option) flips them.
//
//   node scripts/fuses.mjs read <exe>
//   node scripts/fuses.mjs flip <exe>     # the three that stop a Node redirect; COPY the app first
//
// `flip` writes the executable in place. scripts/measure-fuses.ps1 runs it on a temp copy only.

import fuses from '@electron/fuses';

const { FuseV1Options, FuseVersion, flipFuses, getCurrentFuseWire } = fuses;

/** The fuses S-3 named: ELECTRON_RUN_AS_NODE, NODE_OPTIONS, and --inspect. */
export const NODE_REDIRECT_FUSES = {
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
};

async function read(exe) {
    const wire = await getCurrentFuseWire(exe);
    const out = {};
    for (const [name, index] of Object.entries(FuseV1Options)) {
        if (typeof index === 'number' && wire[index] !== undefined) {
            // FuseState: 0x30 '0' disabled, 0x31 '1' enabled, 0x72 'r' removed, 0x90 inherit.
            out[name] = { 48: 'disabled', 49: 'enabled', 114: 'removed', 144: 'inherit' }[wire[index]] ?? String(wire[index]);
        }
    }
    return out;
}

const [command, exe] = process.argv.slice(2);
if (!exe || !['read', 'flip'].includes(command)) {
    console.error('usage: node scripts/fuses.mjs read|flip <exe>');
    process.exit(2);
}
if (command === 'flip') {
    await flipFuses(exe, { version: FuseVersion.V1, ...NODE_REDIRECT_FUSES });
}
console.log(JSON.stringify(await read(exe)));
