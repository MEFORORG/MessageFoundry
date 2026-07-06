import * as assert from "assert";

import type { EnvironmentTarget } from "../../cli";
import { planTargetResolution, resolveTargetUrl } from "../../promoteTarget";

// Pure shard/target resolution for Stage → Promote. These exercise the vscode-free resolver directly
// (no Extension Host needed): an environment with no shards resolves to its own url; a single shard is
// auto-selected; ≥2 shards require a pick and resolveTargetUrl folds the chosen shard's url in.
suite("planTargetResolution / resolveTargetUrl (shard selection)", () => {
  const PROD: EnvironmentTarget = { name: "PROD", url: "https://prod:8765" };

  test("no shards → environment url, no pick needed", () => {
    const plan = planTargetResolution(PROD);
    assert.strictEqual(plan.needsPick, false);
    assert.deepStrictEqual(plan.resolved, { name: "PROD", url: "https://prod:8765" });
    assert.deepStrictEqual(plan.shards, []);
  });

  test("empty shards array is treated as no shards", () => {
    const plan = planTargetResolution({ ...PROD, shards: [] });
    assert.strictEqual(plan.needsPick, false);
    assert.deepStrictEqual(plan.resolved, { name: "PROD", url: "https://prod:8765" });
  });

  test("single shard → auto-selected, no pick needed, uses the shard url", () => {
    const env: EnvironmentTarget = {
      ...PROD,
      shards: [{ name: "shard-1", url: "https://prod-shard-1:8765" }],
    };
    const plan = planTargetResolution(env);
    assert.strictEqual(plan.needsPick, false);
    assert.deepStrictEqual(plan.resolved, {
      name: "PROD / shard-1",
      url: "https://prod-shard-1:8765",
    });
  });

  test("two or more shards → a pick is required and the shard list is returned", () => {
    const env: EnvironmentTarget = {
      ...PROD,
      shards: [
        { name: "shard-1", url: "https://prod-shard-1:8765" },
        { name: "shard-2", url: "https://prod-shard-2:8765" },
      ],
    };
    const plan = planTargetResolution(env);
    assert.strictEqual(plan.needsPick, true);
    assert.strictEqual(plan.resolved, undefined);
    assert.strictEqual(plan.shards.length, 2);
  });

  test("resolveTargetUrl with a picked shard uses the shard url and a composite name", () => {
    const env: EnvironmentTarget = {
      ...PROD,
      shards: [
        { name: "shard-1", url: "https://prod-shard-1:8765" },
        { name: "shard-2", url: "https://prod-shard-2:8765" },
      ],
    };
    const chosen = env.shards![1];
    assert.deepStrictEqual(resolveTargetUrl(env, chosen), {
      name: "PROD / shard-2",
      url: "https://prod-shard-2:8765",
    });
  });

  test("resolveTargetUrl with no shard falls back to the environment url", () => {
    assert.deepStrictEqual(resolveTargetUrl(PROD), { name: "PROD", url: "https://prod:8765" });
  });

  test("malformed shard entries are dropped (a lone valid shard auto-selects)", () => {
    // shardsOf filters non-{name,url} entries; one valid shard survives → single-shard path.
    const env = {
      ...PROD,
      shards: [
        { name: "good", url: "https://good:8765" },
        { name: 123 } as unknown,
        null as unknown,
      ],
    } as EnvironmentTarget;
    const plan = planTargetResolution(env);
    assert.strictEqual(plan.needsPick, false);
    assert.deepStrictEqual(plan.resolved, { name: "PROD / good", url: "https://good:8765" });
  });
});
