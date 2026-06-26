import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import * as vscode from "vscode";

// publisher.name from package.json ("messagefoundry"."messagefoundry").
const EXT_ID = "messagefoundry.messagefoundry";

interface PackageJson {
  contributes: { commands: { command: string }[] };
}

function extension(): vscode.Extension<unknown> {
  const ext = vscode.extensions.getExtension(EXT_ID);
  assert.ok(ext, `extension ${EXT_ID} not found in the test host`);
  return ext;
}

suite("MessageFoundry extension", () => {
  test("activates without a workspace open", async () => {
    const ext = extension();
    await ext.activate();
    assert.strictEqual(ext.isActive, true);
  });

  test("registers every command it contributes", async () => {
    const ext = extension();
    await ext.activate();

    const pkg: PackageJson = JSON.parse(
      fs.readFileSync(path.join(ext.extensionPath, "package.json"), "utf8"),
    );
    const contributed = pkg.contributes.commands.map((c) => c.command);
    assert.ok(contributed.length > 0, "package.json contributes no commands");

    // The Translation Tables (code set) commands must be contributed AND registered — assert their
    // presence explicitly so dropping one is caught here, not only at runtime.
    const codeSetCommands = [
      "messagefoundry.newCodeSet",
      "messagefoundry.editCodeSet",
      "messagefoundry.renameCodeSet",
      "messagefoundry.deleteCodeSet",
      "messagefoundry.refreshCodeSets",
    ];
    const notContributed = codeSetCommands.filter((id) => !contributed.includes(id));
    assert.deepStrictEqual(
      notContributed,
      [],
      `code-set commands missing from package.json: ${notContributed.join(", ")}`,
    );

    const registered = await vscode.commands.getCommands(true);
    const missing = contributed.filter((id) => !registered.includes(id));
    assert.deepStrictEqual(
      missing,
      [],
      `commands contributed but not registered: ${missing.join(", ")}`,
    );
  });

  test("a non-interactive command runs end to end", async () => {
    const ext = extension();
    await ext.activate();
    // showAiPolicy resolves the AI policy (engine unreachable -> CLI absent -> safe built-in default)
    // and shows a non-blocking info message. No prompt, no editor, no external process to wait on —
    // so it completes headlessly and proves a registered command actually executes.
    await vscode.commands.executeCommand("messagefoundry.showAiPolicy");
  });
});
