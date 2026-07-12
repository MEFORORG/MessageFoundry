import * as assert from "assert";
import * as path from "path";

import {
  REFRESH_DEBOUNCE_MS,
  RefreshCoalescer,
  watchableConfigDir,
  type TimerHost,
} from "../../configRefresh";

// Pure config-refresh helpers (ADR 0091 follow-through), exercised vscode-free: the trailing-edge
// debounce that folds a save + its watcher echo (or a git-pull file storm) into ONE refresh pass,
// and the containment check deciding whether the config dir is watchable at all.

/** Deterministic timer host: records scheduled callbacks; the test fires them explicitly. */
class FakeTimers implements TimerHost {
  private nextId = 1;
  readonly scheduled = new Map<number, { fn: () => void; ms: number }>();

  set(fn: () => void, ms: number): unknown {
    const id = this.nextId++;
    this.scheduled.set(id, { fn, ms });
    return id;
  }

  clear(handle: unknown): void {
    this.scheduled.delete(handle as number);
  }

  /** Fire every armed timer (in order), as if the quiet period elapsed. */
  runAll(): void {
    for (const [id, t] of [...this.scheduled]) {
      this.scheduled.delete(id);
      t.fn();
    }
  }
}

suite("configRefresh — RefreshCoalescer", () => {
  test("a burst of triggers coalesces to exactly one action after the quiet period", () => {
    const timers = new FakeTimers();
    let fired = 0;
    const c = new RefreshCoalescer(() => fired++, 750, timers);
    c.trigger(); // the save handler
    c.trigger(); // the watcher echo of the same save
    c.trigger(); // two more files from the same git pull
    c.trigger();
    assert.strictEqual(fired, 0, "nothing fires before the quiet period");
    assert.strictEqual(timers.scheduled.size, 1, "re-arming replaces the timer, never stacks");
    timers.runAll();
    assert.strictEqual(fired, 1, "the burst costs exactly one refresh pass");
    assert.strictEqual(c.pending(), false);
  });

  test("a trigger AFTER a fire arms a fresh pass (the coalescer is reusable)", () => {
    const timers = new FakeTimers();
    let fired = 0;
    const c = new RefreshCoalescer(() => fired++, 750, timers);
    c.trigger();
    timers.runAll();
    c.trigger();
    assert.strictEqual(c.pending(), true);
    timers.runAll();
    assert.strictEqual(fired, 2);
  });

  test("the timer is armed with the configured delay", () => {
    const timers = new FakeTimers();
    const c = new RefreshCoalescer(() => {}, 123, timers);
    c.trigger();
    assert.deepStrictEqual([...timers.scheduled.values()].map((t) => t.ms), [123]);
  });

  test("dispose cancels a pending fire and disarms future triggers", () => {
    const timers = new FakeTimers();
    let fired = 0;
    const c = new RefreshCoalescer(() => fired++, 750, timers);
    c.trigger();
    c.dispose();
    assert.strictEqual(timers.scheduled.size, 0, "the pending timer was cleared");
    c.trigger(); // post-dispose trigger is a no-op (Extension Host shutting down)
    timers.runAll();
    assert.strictEqual(fired, 0);
    assert.strictEqual(c.pending(), false);
  });

  test("the default delay is the shared REFRESH_DEBOUNCE_MS", () => {
    assert.strictEqual(REFRESH_DEBOUNCE_MS, 750);
  });
});

suite("configRefresh — watchableConfigDir", () => {
  const ws = path.join(path.sep, "work", "proj");

  test("a relative configDir inside the workspace resolves to its absolute path", () => {
    assert.strictEqual(
      watchableConfigDir(ws, path.join("samples", "config")),
      path.join(ws, "samples", "config"),
    );
  });

  test("the workspace root itself is watchable (configDir = '.')", () => {
    assert.strictEqual(watchableConfigDir(ws, "."), ws);
  });

  test("an absolute configDir inside the workspace is watchable", () => {
    const inside = path.join(ws, "cfg");
    assert.strictEqual(watchableConfigDir(ws, inside), inside);
  });

  test("a configDir OUTSIDE the workspace yields no watcher (graceful, not a crash)", () => {
    assert.strictEqual(watchableConfigDir(ws, path.join(path.sep, "elsewhere", "cfg")), undefined);
    assert.strictEqual(watchableConfigDir(ws, path.join("..", "sibling")), undefined);
  });

  test("no workspace folder yields no watcher", () => {
    assert.strictEqual(watchableConfigDir(undefined, "samples/config"), undefined);
  });
});
