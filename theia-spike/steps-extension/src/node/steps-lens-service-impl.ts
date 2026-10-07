// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Spike S-1: the backend half of the Steps view. It is the only code that starts a process.
//
// Interpreter resolution follows spec section 9 in miniature: one administrator setting
// (MF_SPIKE_PYTHON, an absolute path to an existing file) and nothing else. There is no PATH
// fallback and no interpreter taken from the opened workspace (the rule `ide/src/cli.ts` calls
// SEC-004). The child runs with `-I` (isolated mode), so neither the working directory nor any
// PYTHON* variable can put a workspace-supplied `messagefoundry` package ahead of the installed one.
// The frontend sends module source, never a path, and the edit spec travels as one argv element
// through execFile with no shell, so nothing the frontend sends is parsed by a shell.

import { injectable } from '@theia/core/shared/inversify';
import { execFile } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LensCallResult, LensServiceInfo, StepsLensService } from '../common/steps-protocol';

const LENS_CONTRACT = '2';
const MAX_SOURCE_BYTES = 4 * 1024 * 1024;
// Windows caps a whole command line at 32,767 characters, and the spec is one argv element.
const MAX_SPEC_CHARS = 30_000;
const CHILD_TIMEOUT_MS = 30_000;

/** Only what Windows needs to start Python; nothing else from the backend's environment reaches the child. */
function minimalEnv(): NodeJS.ProcessEnv {
    const keep = ['SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'PATHEXT', 'COMSPEC'];
    const env: NodeJS.ProcessEnv = {};
    for (const key of keep) {
        const value = process.env[key];
        if (value !== undefined) {
            env[key] = value;
        }
    }
    return env;
}

function refuse(stderr: string): LensCallResult {
    return { stdout: '', stderr, code: 1 };
}

@injectable()
export class StepsLensServiceImpl implements StepsLensService {

    protected resolvePython(): { python?: string; problem?: string } {
        const configured = process.env.MF_SPIKE_PYTHON;
        if (!configured) {
            return { problem: 'MF_SPIKE_PYTHON is not set. The spike runs no interpreter it was not given.' };
        }
        if (!path.isAbsolute(configured)) {
            return { problem: 'MF_SPIKE_PYTHON must be an absolute path.' };
        }
        try {
            if (!fs.statSync(configured).isFile()) {
                return { problem: 'MF_SPIKE_PYTHON does not name a file.' };
            }
        } catch {
            return { problem: 'MF_SPIKE_PYTHON does not exist.' };
        }
        return { python: configured };
    }

    async info(): Promise<LensServiceInfo> {
        return this.resolvePython();
    }

    protected run(args: string[], stdin: string): Promise<LensCallResult> {
        const { python, problem } = this.resolvePython();
        if (!python) {
            return Promise.resolve(refuse(problem ?? 'no interpreter'));
        }
        if (typeof stdin !== 'string' || Buffer.byteLength(stdin, 'utf8') > MAX_SOURCE_BYTES) {
            return Promise.resolve(refuse('module source is missing or larger than the spike accepts'));
        }
        return new Promise(resolve => {
            const child = execFile(
                python,
                // -I implies -E, so PYTHON* variables are ignored; -X utf8 sets UTF-8 mode directly.
                ['-I', '-X', 'utf8', '-m', 'messagefoundry', ...args],
                {
                    cwd: os.tmpdir(),
                    encoding: 'utf8',
                    maxBuffer: 16 * 1024 * 1024,
                    timeout: CHILD_TIMEOUT_MS,
                    windowsHide: true,
                    env: minimalEnv(),
                },
                (err, stdout, stderr) => {
                    const code = err && typeof (err as { code?: unknown }).code === 'number'
                        ? (err as { code: number }).code
                        : err ? 1 : 0;
                    // A spawn failure or a timeout leaves stderr empty; carry the reason instead.
                    const why = err && !stderr ? `${err.message}` : '';
                    resolve({ stdout: stdout ?? '', stderr: (stderr ?? '') + why, code });
                },
            );
            // EPIPE when the child exits before reading stdin: the exit code is the real signal.
            child.stdin?.on('error', () => undefined);
            child.stdin?.end(stdin, 'utf8');
        });
    }

    parse(source: string): Promise<LensCallResult> {
        return this.run(['lens', 'parse', '-', '--json', '--contract', LENS_CONTRACT], source);
    }

    rewrite(source: string, spec: object): Promise<LensCallResult> {
        if (spec === null || typeof spec !== 'object' || Array.isArray(spec)) {
            return Promise.resolve(refuse('the edit spec must be a JSON object'));
        }
        const json = JSON.stringify(spec);
        if (json.length > MAX_SPEC_CHARS) {
            return Promise.resolve(refuse('the edit spec is larger than the spike accepts'));
        }
        return this.run(['lens', 'rewrite', '-', '--contract', LENS_CONTRACT, '--edit', json], source);
    }

    schema(): Promise<LensCallResult> {
        return this.run(['lens', 'schema', '--json'], '');
    }

    async webviewAssets(): Promise<{ script: string; style: string }> {
        const repo = process.env.MF_SPIKE_REPO;
        if (!repo || !path.isAbsolute(repo)) {
            throw new Error('MF_SPIKE_REPO must be the absolute path of the MessageFoundry checkout.');
        }
        const script = await fs.promises.readFile(path.join(repo, 'ide', 'media', 'stepsWebview.js'), 'utf8');
        const view = await fs.promises.readFile(path.join(repo, 'ide', 'src', 'stepsView.ts'), 'utf8');
        const match = /<style>([\s\S]*?)<\/style>/.exec(view);
        if (!match) {
            throw new Error('could not find the pageHtml <style> block in ide/src/stepsView.ts');
        }
        return { script, style: match[1] };
    }
}
