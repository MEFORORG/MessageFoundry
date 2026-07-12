// Pure (vscode-free) helpers for the config-dir refresh lane (ADR 0091 follow-through): the
// trailing-edge debounce that coalesces a burst of file events (a git pull touching 40 files, or a
// save that fires BOTH onDidSaveTextDocument and the FileSystemWatcher) into ONE validate+refresh
// pass, and the config-dir containment check that decides whether a watcher can be created at all.
// Node-side unit-tested (no Extension Host) like graphModel/engineStatusModel.

import * as path from "node:path";

/** Quiet period before a coalesced refresh fires. Long enough to absorb a save's watcher echo and a
 *  multi-file checkout; short enough that the tree still feels live after an external edit. */
export const REFRESH_DEBOUNCE_MS = 750;

/** Injectable timer seam so tests drive the debounce deterministically (no real sleeps). */
export interface TimerHost {
  set(fn: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

const REAL_TIMERS: TimerHost = {
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/**
 * Trailing-edge debounce: every {@link trigger} (re)arms one timer; the action fires once, after
 * `delayMs` of quiet. A burst of N triggers — watcher create/change/delete storms plus the save
 * handler for the same write — therefore costs exactly one refresh pass. Disposal cancels any
 * pending fire (the Extension Host is shutting down; a late CLI run would be wasted or crash).
 */
export class RefreshCoalescer {
  private handle: unknown;
  private disposed = false;

  constructor(
    private readonly action: () => void,
    private readonly delayMs: number = REFRESH_DEBOUNCE_MS,
    private readonly timers: TimerHost = REAL_TIMERS,
  ) {}

  trigger(): void {
    if (this.disposed) {
      return;
    }
    if (this.handle !== undefined) {
      this.timers.clear(this.handle);
    }
    this.handle = this.timers.set(() => {
      this.handle = undefined;
      this.action();
    }, this.delayMs);
  }

  /** True while a refresh is armed but not yet fired (test observability). */
  pending(): boolean {
    return this.handle !== undefined;
  }

  dispose(): void {
    if (this.handle !== undefined) {
      this.timers.clear(this.handle);
      this.handle = undefined;
    }
    this.disposed = true;
  }
}

/**
 * The absolute directory a config-dir FileSystemWatcher should watch, or undefined when no watcher
 * can be created: no workspace folder, or a configDir that resolves OUTSIDE the workspace folder
 * (an absolute path elsewhere, or a relative one that escapes via `..`). Outside-the-workspace
 * stays unwatched by design — the graceful degradation is "manual refresh still works", never a
 * crash or a watcher over an unrelated part of the filesystem.
 */
export function watchableConfigDir(
  workspace: string | undefined,
  configDir: string,
): string | undefined {
  if (!workspace) {
    return undefined;
  }
  const abs = path.isAbsolute(configDir) ? configDir : path.join(workspace, configDir);
  const rel = path.relative(workspace, abs);
  if (rel === "") {
    return workspace; // the config dir IS the workspace root
  }
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return undefined; // outside the workspace — no watcher, no crash
  }
  return abs;
}
