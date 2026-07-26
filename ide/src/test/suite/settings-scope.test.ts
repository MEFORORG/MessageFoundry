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
  capabilities?: { untrustedWorkspaces?: { supported?: unknown } };
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

suite("untrusted-workspace capability (SEC-004)", () => {
  test("the extension declares untrustedWorkspaces.supported === 'limited'", () => {
    assert.strictEqual(pkg().capabilities?.untrustedWorkspaces?.supported, "limited");
  });
});
