// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

// Deliberately imports the pure content model, NOT ../../engineSetup (which pulls in `vscode` for the
// webview panel) — this suite runs unchanged under plain Node/Mocha, no Extension Host required.
import { SETUP_SECTIONS, buttonById } from "../../engineSetupContent";
import { CMD } from "../../engineStatusModel";

// The guided engine-setup page (BACKLOG #238, ADR 0112 amendment 2026-07-16). Two properties carry
// the safety story and are pinned here: every page button resolves to a KNOWN CMD id (the webview
// shell dispatches only what buttonById returns — never a command string from the webview message),
// and the test-only dev-engine section states the create-DB consequence honestly for BOTH the
// store-less and the has-store launch (the command is palette-visible; the page is context-blind).

interface Pkg {
  contributes: {
    commands: Array<{ command: string }>;
  };
}

function pkg(): Pkg {
  const p = path.join(__dirname, "..", "..", "..", "package.json");
  return JSON.parse(fs.readFileSync(p, "utf8")) as Pkg;
}

suite("engine setup page — the content model dispatches only known CMD ids", () => {
  test("every button's command is a known CMD id (the webview can never name an arbitrary command)", () => {
    const known = Object.values(CMD) as string[];
    for (const s of SETUP_SECTIONS) {
      if (s.button) {
        assert.ok(
          known.includes(s.button.command),
          `section ${s.id}: ${s.button.command} is not a known engine command`,
        );
      }
    }
  });

  test("section and button ids are unique, and buttonById resolves exactly the declared buttons", () => {
    const sectionIds = new Set<string>();
    const buttonIds = new Set<string>();
    for (const s of SETUP_SECTIONS) {
      assert.ok(!sectionIds.has(s.id), `duplicate section id ${s.id}`);
      sectionIds.add(s.id);
      if (s.button) {
        assert.ok(!buttonIds.has(s.button.id), `duplicate button id ${s.button.id}`);
        buttonIds.add(s.button.id);
        assert.strictEqual(buttonById(s.button.id), s.button, `buttonById(${s.button.id}) must resolve`);
      }
    }
    assert.strictEqual(buttonById("no-such-button"), undefined, "an unknown id must dispatch nothing");
  });

  test("the page covers the amendment's guidance paths: posture, point-at-engine, copy-start, environment", () => {
    const commands = SETUP_SECTIONS.flatMap((s) => (s.button ? [s.button.command] : []));
    assert.ok(commands.includes(CMD.settings), "point-at-an-engine must offer Configure engine target");
    assert.ok(commands.includes(CMD.copyStart), "the copy-start fallback must be on the page");
    assert.ok(commands.includes(CMD.setupEnvironment), "Set up environment must be on the page");
    // The production-as-a-service posture section is text-only guidance — it cites docs/SERVICE.md.
    const posture = SETUP_SECTIONS.find((s) => /service/i.test(s.title));
    assert.ok(posture, "the production-as-a-service posture section is missing");
    assert.ok(
      posture.body.some((p) => p.includes("SERVICE.md")),
      "the posture section should cite docs/SERVICE.md",
    );
  });
});

suite("engine setup page — the test-only dev engine is separated and context-honest", () => {
  test("exactly one dev-tone section, and its button dispatches the guarded CMD.startEngine", () => {
    const dev = SETUP_SECTIONS.filter((s) => s.tone === "dev");
    assert.strictEqual(dev.length, 1, "exactly one visually separated test-only section");
    const section = dev[0];
    assert.ok(section.button, "the dev-engine section needs its action button");
    assert.strictEqual(section.button.command, CMD.startEngine);
  });

  test("the dev-engine copy states the conditional truth for BOTH the no-store and has-store launch", () => {
    const dev = SETUP_SECTIONS.find((s) => s.tone === "dev");
    assert.ok(dev, "the dev-engine section is missing");
    const body = dev.body.join(" ");
    // No-store half: the modal create-DB confirm (runDirHasEngine guards only this case).
    assert.ok(
      /NEW database and a bootstrap admin/i.test(body),
      "must state that a store-less launch confirms creating a NEW database and a bootstrap admin",
    );
    // Has-store half: a launch where a store exists shows no modal — it just starts that engine.
    assert.ok(
      /if one exists.*starts that engine/i.test(body),
      "must state that with an existing store the command starts that engine (no modal)",
    );
  });

  test("CMD.startEngine appears on the page ONLY inside the dev-tone section", () => {
    for (const s of SETUP_SECTIONS) {
      if (s.button && s.button.command === CMD.startEngine) {
        assert.strictEqual(s.tone, "dev", `${s.id} offers the dev engine outside the test-only block`);
      }
    }
  });
});

suite("engine setup page — contribution", () => {
  test("the messagefoundry.openEngineSetup command is contributed (palette-visible — deliberate, per the ADR 0112 amendment)", () => {
    assert.ok(
      pkg().contributes.commands.find((c) => c.command === CMD.openEngineSetup),
      "package.json must contribute messagefoundry.openEngineSetup",
    );
  });
});
