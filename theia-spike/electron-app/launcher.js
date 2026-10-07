// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// Spike S-3 (ADR 0208): the Electron entry point. It resolves the Python interpreter, checks the
// engine version, picks the workspace, then hands over to Theia's generated electron main.
//
// Interpreter resolution follows spec section 9, in this order and nothing else:
//   1. The administrator setting: HKLM\SOFTWARE\Policies\MessageFoundry\StepsSpike, value PythonPath.
//      HKLM is used because a standard user cannot write it. A per-user key would let the analyst
//      point the app at any interpreter, which is what the setting exists to prevent.
//      If the value is present but unusable, the app refuses. It does not fall through to the
//      bundled runtime, because an administrator who set it meant that interpreter.
//   2. The bundled runtime under the app's resources folder.
// There is no PATH lookup and no interpreter from the workspace (the rule ide/src/cli.ts calls
// SEC-004). Inherited MF_SPIKE_PYTHON and MF_SPIKE_REPO values are discarded first, so a user
// environment variable cannot skip the order above. The Steps backend reads only these two values.
//
// LIMIT OF THIS SPIKE, stated so nobody reads more into it: the install is per-user, so every file
// under it (this launcher, runtime-pin.json, resources\python, resources\mfassets) is writable by
// the analyst, and no Electron fuses are set (Playwright's smoke test needs --inspect and -r). So
// with no HKLM setting, a user who edits those files or sets ELECTRON_RUN_AS_NODE or NODE_OPTIONS can
// run another interpreter. The order below stops a careless or accidental redirect; on a managed
// desktop the real control is App Control. A shipped build needs fuses and a signed, asar-only app.
//
// The engine version check is FR-28 in miniature: the interpreter must import a messagefoundry at or
// above the minimum recorded in runtime-pin.json, which the build script writes. A missing pin
// refuses, so a build that skipped the script cannot run an unchecked engine.

'use strict';

const { app, dialog } = require('electron');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const POLICY_KEY = 'HKLM\\SOFTWARE\\Policies\\MessageFoundry\\StepsSpike';
const POLICY_VALUE = 'PythonPath';
const CHILD_TIMEOUT_MS = 60_000;

delete process.env.MF_SPIKE_PYTHON;
delete process.env.MF_SPIKE_REPO;

const log = [];
function note(line) {
    log.push(`${new Date().toISOString()} ${line}`);
}

/** The folder that holds python/, mfassets/ and samples/: resources when packaged, build/ in a checkout. */
function payloadRoot() {
    return app.isPackaged ? process.resourcesPath : path.join(__dirname, 'build', 'payload');
}

/** Only what Windows needs to start Python, the same set the Steps backend passes. */
function minimalEnv() {
    const env = {};
    for (const key of ['SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'PATHEXT', 'COMSPEC']) {
        if (process.env[key] !== undefined) {
            env[key] = process.env[key];
        }
    }
    return env;
}

function regQuery(args) {
    const reg = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe');
    return execFileSync(reg, ['query', ...args], {
        encoding: 'utf8', windowsHide: true, timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'],
    });
}

/**
 * Read the policy value with reg.exe by absolute path. Returns undefined only when the value is
 * provably absent. reg.exe exits 1 for EVERY failure, access denied and a "prevent access to
 * registry editing tools" policy included, so exit 1 alone does not mean absent. HKLM\SOFTWARE\Policies
 * always exists, so the launcher first proves it can read the registry; only then does exit 1 on the
 * value mean absent. Any other failure throws, and the caller refuses rather than falling through.
 */
function readPolicy() {
    try {
        regQuery(['HKLM\\SOFTWARE\\Policies']);
    } catch (err) {
        throw new Error(`cannot read the registry to check the administrator setting: ${err.message}`);
    }
    let out;
    try {
        out = regQuery([POLICY_KEY, '/v', POLICY_VALUE]);
    } catch (err) {
        if (typeof err.status === 'number' && err.status === 1) {
            return undefined;
        }
        throw new Error(`could not read ${POLICY_KEY}: ${err.message}`);
    }
    // A line looks like:    PythonPath    REG_SZ    C:\Program Files\Python314\python.exe
    // REG_SZ only: nothing here expands %VARIABLES%, so REG_EXPAND_SZ is refused rather than misread.
    const match = /^\s*PythonPath\s+REG_SZ\s+(.+?)\s*$/im.exec(out);
    if (!match) {
        throw new Error(`${POLICY_KEY}\\${POLICY_VALUE} is not a REG_SZ value`);
    }
    return match[1];
}

function checkInterpreterFile(candidate, source) {
    if (!path.isAbsolute(candidate)) {
        throw new Error(`${source} is not an absolute path: ${candidate}`);
    }
    let stat;
    try {
        stat = fs.statSync(candidate);
    } catch {
        throw new Error(`${source} does not exist: ${candidate}`);
    }
    if (!stat.isFile()) {
        throw new Error(`${source} does not name a file: ${candidate}`);
    }
    return candidate;
}

function resolvePython() {
    const policy = readPolicy();
    if (policy !== undefined) {
        note(`python: administrator setting ${POLICY_KEY}\\${POLICY_VALUE}`);
        return checkInterpreterFile(policy, 'the administrator setting');
    }
    note('python: no administrator setting, using the bundled runtime');
    return checkInterpreterFile(path.join(payloadRoot(), 'python', 'python.exe'), 'the bundled runtime');
}

/**
 * "0.5.1" -> [0, 5, 1]. Only a plain release is accepted. A pre-release or dev build such as
 * 0.5.1rc1 sorts BELOW 0.5.1, so reading only its leading digits would wave it through.
 */
function parseVersion(text, what) {
    const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(text.trim());
    if (!match) {
        throw new Error(`${what} is not a version: ${JSON.stringify(text)}`);
    }
    return match.slice(1, 4).map(Number);
}

function compareVersions(a, b) {
    for (let i = 0; i < 3; i++) {
        if (a[i] !== b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

function checkEngine(python) {
    const pinFile = path.join(__dirname, 'runtime-pin.json');
    let pin;
    try {
        pin = JSON.parse(fs.readFileSync(pinFile, 'utf8'));
    } catch (err) {
        throw new Error(`runtime-pin.json is missing or unreadable (${err.message}); run scripts/build-installer.ps1`);
    }
    const minimum = parseVersion(String(pin.minimumEngineVersion), 'minimumEngineVersion');
    const out = execFileSync(python, ['-I', '-c', 'import messagefoundry,sys; sys.stdout.write(messagefoundry.__version__)'], {
        encoding: 'utf8', windowsHide: true, timeout: CHILD_TIMEOUT_MS, env: minimalEnv(),
        stdio: ['ignore', 'pipe', 'pipe'], cwd: app.getPath('temp'),
    });
    const found = parseVersion(out, 'the engine version');
    note(`engine: messagefoundry ${found.join('.')}, minimum ${minimum.join('.')}`);
    if (compareVersions(found, minimum) < 0) {
        throw new Error(`messagefoundry ${found.join('.')} is below the minimum ${minimum.join('.')}`);
    }
}

/**
 * The workspace. The real analyst build clones the site's config repository; the spike copies the
 * bundled samples/config once into a per-user folder and opens that copy, so an edit never touches
 * the install folder. An explicit folder on the command line wins.
 */
function workspaceFolder() {
    const target = path.join(app.getPath('documents'), 'MessageFoundry Steps Spike', 'config');
    if (!fs.existsSync(target)) {
        // Copy beside the target, then rename, so an interrupted copy is never reused as the workspace.
        const staging = `${target}.partial-${process.pid}`;
        fs.rmSync(staging, { recursive: true, force: true });
        fs.cpSync(path.join(payloadRoot(), 'samples', 'config'), staging, { recursive: true });
        fs.renameSync(staging, target);
        note(`workspace: copied the bundled samples to ${target}`);
    }
    return target;
}

function writeLog() {
    try {
        const dir = app.getPath('logs');
        fs.mkdirSync(dir, { recursive: true });
        fs.appendFileSync(path.join(dir, 'launcher.log'), log.join('\n') + '\n', 'utf8');
    } catch {
        // The log is evidence for the spike, not a precondition for running.
    }
}

let refusal;
try {
    const python = resolvePython();
    checkEngine(python);
    process.env.MF_SPIKE_PYTHON = python;
    process.env.MF_SPIKE_REPO = path.join(payloadRoot(), 'mfassets');
    note(`python: ${python}`);
} catch (err) {
    refusal = err instanceof Error ? err.message : String(err);
    note(`REFUSED: ${refusal}`);
}

// Theia reads a folder argument after the executable (and after the app path when unpackaged).
const userArgs = process.argv.slice(app.isPackaged ? 1 : 2).filter(a => !a.startsWith('-'));
if (userArgs.length === 0) {
    try {
        process.argv.push(workspaceFolder());
    } catch (err) {
        note(`workspace: could not prepare the samples copy: ${err.message}`);
    }
}
writeLog();

if (refusal) {
    // The Steps view also reports the missing interpreter; this says why, once, at start.
    app.whenReady().then(() => dialog.showErrorBox('MessageFoundry Steps',
        `The Steps view cannot run the engine.\n\n${refusal}\n\nDetails: ${path.join(app.getPath('logs'), 'launcher.log')}`));
}

require('./lib/backend/electron-main.js');
