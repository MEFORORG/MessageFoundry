// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

// SEC-005 / SEC-004 regression. These read package.json off disk (like chat.test.ts) and assert the
// declared settings *scope* and the untrusted-workspace *capability* — VS Code enforces both at the
// settings/trust layer, so the security property lives in the manifest, not in code.
//
// WHY THIS IS NOW AN INVARIANT AND NOT THREE ASSERTIONS: it used to check exactly three hard-coded keys,
// which meant a NEW setting that feeds a URL or an interpreter path could be added un-scoped and sail
// straight through — silently reverting ADR 0035's SEC-005/CWE-918 fix (a checked-in .vscode/settings.json
// retargeting promote at an attacker's host, or pointing the CLI at a repo-supplied interpreter). Below,
// every declared key must be *classified*, and anything that smells like a target must be machine-scoped.
function pkg(): {
  capabilities?: { untrustedWorkspaces?: { supported?: unknown; restrictedConfigurations?: unknown[] } };
  contributes: { configuration: { properties: Record<string, { scope?: string }> } };
} {
  const pkgPath = path.join(__dirname, "..", "..", "..", "package.json");
  return JSON.parse(fs.readFileSync(pkgPath, "utf8"));
}

/** Settings that steer WHERE the extension connects or WHAT it executes. These MUST be machine-scoped:
 *  a workspace settings file must never be able to retarget promote or the interpreter. */
const TARGET_AFFECTING = [
  "messagefoundry.engineUrl",
  "messagefoundry.environments",
  "messagefoundry.pythonPath",
];

/** Settings reviewed and found NOT to steer a target: they name paths *within* the workspace (which the
 *  user already controls by opening it) or tune local UI behaviour. Adding a key here is the moment to
 *  ask "could a hostile workspace use this to send my credentials somewhere?" */
const REVIEWED_NON_TARGET = [
  "messagefoundry.configDir",
  "messagefoundry.serviceConfig",
  "messagefoundry.messageSetsDir",
  "messagefoundry.sourceControl.autoPrompt",
  "messagefoundry.ai.contextCharLimit",
  "messagefoundry.liveDebug.debounceMs",
  "messagefoundry.liveStatus.enabled",
  "messagefoundry.liveStatus.intervalSeconds",
  "messagefoundry.revealViewOnStartup",
];

/** Window-scoped settings whose WORKSPACE value an untrusted workspace must not supply (BACKLOG
 *  #5404): the paths the extension reads and writes, the switch and rate of the live-status poll, and
 *  the bound on how much code leaves for the model provider. */
const WORKSPACE_RESTRICTED = [
  "messagefoundry.configDir",
  "messagefoundry.serviceConfig",
  "messagefoundry.messageSetsDir",
  "messagefoundry.liveStatus.enabled",
  "messagefoundry.liveStatus.intervalSeconds",
  "messagefoundry.ai.contextCharLimit",
];

suite("settings scope (SEC-005)", () => {
  test("every target-affecting setting is machine-scoped", () => {
    const props = pkg().contributes.configuration.properties;
    for (const key of TARGET_AFFECTING) {
      assert.ok(props[key], `${key} is missing from the manifest`);
      assert.strictEqual(
        props[key].scope,
        "machine",
        `${key} steers where we connect or what we execute — it must be machine-scoped`,
      );
    }
  });

  test("every declared setting is classified — a new key cannot slip in unreviewed", () => {
    // The family invariant. A new setting fails this test until someone decides which list it belongs
    // in, which is exactly the moment to notice it carries a URL.
    const declared = Object.keys(pkg().contributes.configuration.properties).sort();
    const classified = [...TARGET_AFFECTING, ...REVIEWED_NON_TARGET].sort();
    assert.deepStrictEqual(
      declared,
      classified,
      "a setting was added or removed without classifying it as target-affecting (machine-scoped) or not",
    );
  });

  test("anything that NAMES a target must be machine-scoped", () => {
    // Belt-and-braces over the classification above: even if a future key were mis-filed as
    // non-target-affecting, a name like `engineUrlFallback` / `pythonExec` / `apiEndpoint` still trips.
    const smellsLikeATarget = /url|endpoint|host|python|exec|command|token|credential/i;
    for (const [key, prop] of Object.entries(pkg().contributes.configuration.properties)) {
      if (smellsLikeATarget.test(key)) {
        assert.strictEqual(
          prop.scope,
          "machine",
          `${key} looks like it names a connection target or an executable — machine-scope it (SEC-005)`,
        );
      }
    }
  });
});

suite("caFile is reachable only through a machine-scoped setting (SEC-005, BACKLOG #1695)", () => {
  // A caFile becomes the request's `ca`, which decides whom the extension sends credentials to. It
  // lives INSIDE messagefoundry.environments so it inherits that setting's machine scope; a top-level
  // key would be classified separately and could be mis-scoped. Read the manifest to pin both.
  test("caFile is declared on environment entries and engine shards, and nowhere at the top level", () => {
    const props = pkg().contributes.configuration.properties as Record<
      string,
      { scope?: string; items?: { properties?: Record<string, { items?: unknown }> } }
    >;
    const env = props["messagefoundry.environments"];
    assert.ok(env, "package.json no longer contributes messagefoundry.environments");
    assert.strictEqual(env.scope, "machine");
    const entry = env.items?.properties ?? {};
    assert.ok(entry.caFile, "environment entries declare no caFile");
    const shard = (entry.shards?.items as { properties?: Record<string, unknown> } | undefined)
      ?.properties;
    assert.ok(shard?.caFile, "engine shard entries declare no caFile");
    assert.ok(
      !Object.keys(props).some((key) => /cafile|trust|cert/i.test(key)),
      "a top-level trust setting appeared; it needs its own SEC-005 review",
    );
  });
});

suite("untrusted-workspace capability (SEC-004)", () => {
  test("the extension declares untrustedWorkspaces.supported === 'limited'", () => {
    assert.strictEqual(pkg().capabilities?.untrustedWorkspaces?.supported, "limited");
  });

  // BACKLOG #5404. "limited" alone leaves every window-scoped setting overridable by an untrusted
  // workspace's own settings file. VS Code ignores the workspace value of a key named in
  // restrictedConfigurations until the workspace is trusted, so the keys that name a path the
  // extension reads or writes, or that switch on network activity, must be listed there.
  test("an untrusted workspace cannot set a path setting or switch on live status", () => {
    const manifest = pkg();
    const restricted = manifest.capabilities?.untrustedWorkspaces?.restrictedConfigurations;
    assert.ok(Array.isArray(restricted), "untrustedWorkspaces declares no restrictedConfigurations");
    for (const key of WORKSPACE_RESTRICTED) {
      assert.ok(restricted.includes(key), `${key} is not in restrictedConfigurations`);
    }
    const declared = Object.keys(manifest.contributes.configuration.properties);
    for (const key of restricted) {
      assert.ok(declared.includes(String(key)), `restrictedConfigurations names an undeclared key: ${key}`);
    }
  });

  test("every window-scoped setting that names a path or turns on polling is restricted", () => {
    // A family check over the hand list above, as the scope suite does for targets: a new path or
    // polling setting trips it until someone files it.
    const smells = (key: string): boolean =>
      /dir|path|config|file|liveStatus|poll|interval|limit/i.test(key.replace(/^messagefoundry\./, ""));
    // Positive control: the pattern must at least catch the hand list, or the loop below proves nothing.
    for (const key of WORKSPACE_RESTRICTED) {
      assert.ok(smells(key), `the family pattern does not match ${key}`);
    }
    const manifest = pkg();
    const props = manifest.contributes.configuration.properties;
    const restricted = manifest.capabilities?.untrustedWorkspaces?.restrictedConfigurations ?? [];
    // machine and application scope are not settable from a workspace at all, so need no restriction.
    const workspaceSettable = (scope: string | undefined): boolean => scope !== "machine" && scope !== "application";
    for (const [key, prop] of Object.entries(props)) {
      if (workspaceSettable(prop.scope) && smells(key)) {
        assert.ok(restricted.includes(key), `${key} names a path, polling or an egress bound; restrict it (BACKLOG #5404)`);
      }
    }
  });
});
