// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// assistantState enables assistance only for the modes it names, and a retained ai:assist deny holds
// under managed_endpoint too (BACKLOG #5882; the allow-list is BACKLOG #5406).
//
// The sibling ai-policy-model.test.ts built nearly every policy as mode `byo`, so a gate that
// enabled a missing or unrecognized mode, or managed_endpoint with a retained deny, could pass. These
// cases build each of those shapes. They name only what aiPolicyModel.ts exported before the
// allow-list (`assistantState`, `mergeAuthoritativePolicy`, `cachedPolicyOffline`), so they run
// against that earlier source too, where they fail on the behaviour rather than on a missing symbol.
// Zero-import model, so this runs node-side on every ide leg.
import * as assert from "assert";

import { assistantState, cachedPolicyOffline, mergeAuthoritativePolicy, type AiPolicy } from "../../aiPolicyModel";

function policy(p: Partial<AiPolicy>): AiPolicy {
  return { mode: "byo", dataScope: "code_only", environment: null, assistPermitted: null, reason: null, ...p };
}

/** A policy whose `mode` is whatever a wire answer could carry, which `JSON.parse` does not check. */
function withMode(mode: unknown, assistPermitted: boolean | null): AiPolicy {
  return { ...policy({ assistPermitted }), mode: mode as string };
}

/** The permissions under which a mode the gate names WOULD enable, so only the mode can disable. */
const PERMITTING: (boolean | null)[] = [true, null];

suite("assistantState: a mode outside the allow-list disables assistance (BACKLOG #5882)", () => {
  const missing: [string, AiPolicy][] = PERMITTING.flatMap((ap): [string, AiPolicy][] => {
    const absent = policy({ assistPermitted: ap }) as Partial<AiPolicy>;
    delete absent.mode;
    return [
      [`absent mode, permitted=${ap}`, absent as AiPolicy],
      [`undefined mode, permitted=${ap}`, withMode(undefined, ap)],
    ];
  });
  for (const [name, p] of missing) {
    test(`M-missing: ${name}`, () => {
      const s = assistantState(p);
      assert.strictEqual(s.enabled, false, `a policy with no mode enabled assistance: ${name}`);
      assert.ok((s.message ?? "").length > 0, "the gate says why");
    });
  }

  for (const mode of ["managed_future", "BYO", "Managed_Endpoint", "byo ", "", "managed-endpoint"]) {
    for (const ap of PERMITTING) {
      test(`M-unknown: ${JSON.stringify(mode)}, permitted=${ap}`, () => {
        const s = assistantState(withMode(mode, ap));
        assert.strictEqual(s.enabled, false, `an unrecognized mode ${JSON.stringify(mode)} enabled assistance`);
        assert.ok((s.message ?? "").length > 0, "the gate says why");
      });
    }
  }

  for (const mode of [null, 0, 7, true, false, {}, ["byo"], { mode: "byo" }]) {
    for (const ap of PERMITTING) {
      test(`M-non-string: ${JSON.stringify(mode)}, permitted=${ap}`, () => {
        const s = assistantState(withMode(mode, ap));
        assert.strictEqual(s.enabled, false, `a non-string mode ${JSON.stringify(mode)} enabled assistance`);
        assert.ok((s.message ?? "").length > 0, "the gate says why");
      });
    }
  }

  test("M-unknown via the merge: a fresh answer in an unknown mode disables, whatever was cached", () => {
    const cachedChoices = [null, policy({ assistPermitted: true }), policy({ mode: "managed_endpoint", assistPermitted: true })];
    for (const cached of cachedChoices) {
      for (const ap of PERMITTING) {
        const merged = mergeAuthoritativePolicy(cached, withMode("managed_future", ap));
        assert.strictEqual(assistantState(merged).enabled, false, `cached=${JSON.stringify(cached)} permitted=${ap}`);
      }
    }
  });

  test("M-unknown offline: a cached answer in an unknown mode disables, fresh or old", () => {
    for (const cachedAt of [1_000, 0]) {
      const cached = { ...withMode("managed_future", true), cachedAt };
      assert.strictEqual(assistantState(cachedPolicyOffline(cached, 1_000)).enabled, false, `cachedAt=${cachedAt}`);
    }
  });

  test("M-control: the two allow-listed modes still enable when permitted or unknown", () => {
    // Without this, a gate that disabled everything would pass every case above.
    for (const mode of ["byo", "managed_endpoint"]) {
      for (const ap of PERMITTING) {
        assert.strictEqual(assistantState(policy({ mode, assistPermitted: ap })).enabled, true, `${mode} permitted=${ap}`);
      }
    }
  });
});

suite("assistantState: managed_endpoint with a retained ai:assist deny stays disabled (BACKLOG #5882)", () => {
  /** A fresh answer the engine could not attribute, so the merge retains any cached deny. */
  const unattributed = (mode: string): AiPolicy => policy({ mode, assistPermitted: null });

  const endpointDeny = policy({ mode: "managed_endpoint", assistPermitted: false });
  const retained: [string, AiPolicy, AiPolicy][] = [
    ["managed_endpoint deny, then managed_endpoint unattributed", endpointDeny, unattributed("managed_endpoint")],
    [
      "byo deny, then a switch to managed_endpoint, unattributed",
      policy({ mode: "byo", assistPermitted: false }),
      unattributed("managed_endpoint"),
    ],
    [
      "managed_endpoint deny, then a fresh answer that omits the permission",
      endpointDeny,
      { ...unattributed("managed_endpoint"), assistPermitted: undefined as unknown as null },
    ],
  ];
  for (const [name, cached, fresh] of retained) {
    test(`R-deny: ${name}`, () => {
      const merged = mergeAuthoritativePolicy(cached, fresh);
      assert.strictEqual(merged.mode, "managed_endpoint", "the fresh mode is taken");
      assert.strictEqual(merged.assistPermitted, false, "the merge must retain the cached deny");
      const s = assistantState(merged);
      assert.strictEqual(s.enabled, false, `managed_endpoint with a retained deny enabled assistance: ${name}`);
      assert.ok(/ai:assist/i.test(s.message ?? ""), "the gate names the missing permission");
    });
  }

  test("R-deny offline: a cached managed_endpoint deny disables however old it is", () => {
    for (const [cachedAt, now] of [
      [0, 0],
      [0, 10 * 24 * 60 * 60 * 1000],
      [undefined, 0],
    ] as [number | undefined, number][]) {
      const cached = { ...endpointDeny, cachedAt };
      const offline = cachedPolicyOffline(cached, now);
      assert.strictEqual(assistantState(offline).enabled, false, `cachedAt=${cachedAt} now=${now}`);
    }
  });

  test("R-control: an evaluated grant under managed_endpoint clears the retained deny", () => {
    // Without this, a gate that disabled managed_endpoint outright would pass the cases above.
    const merged = mergeAuthoritativePolicy(endpointDeny, policy({ mode: "managed_endpoint", assistPermitted: true }));
    assert.strictEqual(assistantState(merged).enabled, true);
  });
});
