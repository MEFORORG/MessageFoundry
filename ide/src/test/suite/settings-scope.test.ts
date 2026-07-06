import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

// SEC-005 / SEC-004 regression. These read package.json off disk (like chat.test.ts) and assert the
// declared settings *scope* and the untrusted-workspace *capability* — VS Code enforces both at the
// settings/trust layer, so the security property lives in the manifest, not in code.
function pkg(): {
  capabilities?: { untrustedWorkspaces?: { supported?: unknown } };
  contributes: { configuration: { properties: Record<string, { scope?: string }> } };
} {
  const pkgPath = path.join(__dirname, "..", "..", "..", "package.json");
  return JSON.parse(fs.readFileSync(pkgPath, "utf8"));
}

suite("settings scope (SEC-005)", () => {
  test("engineUrl is machine-scoped — a workspace settings file cannot retarget promote", () => {
    const props = pkg().contributes.configuration.properties;
    assert.strictEqual(props["messagefoundry.engineUrl"].scope, "machine");
  });

  test("environments is machine-scoped", () => {
    const props = pkg().contributes.configuration.properties;
    assert.strictEqual(props["messagefoundry.environments"].scope, "machine");
  });

  test("pythonPath stays machine-scoped (regression guard)", () => {
    const props = pkg().contributes.configuration.properties;
    assert.strictEqual(props["messagefoundry.pythonPath"].scope, "machine");
  });
});

suite("untrusted-workspace capability (SEC-004)", () => {
  test("the extension declares untrustedWorkspaces.supported === 'limited'", () => {
    assert.strictEqual(pkg().capabilities?.untrustedWorkspaces?.supported, "limited");
  });
});
