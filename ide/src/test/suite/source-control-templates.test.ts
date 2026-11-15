// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// What "Set Up Version Control & Checks" scaffolds: the .gitignore keeps the engine's minted secrets
// out of the first commit (BACKLOG #5413), and the generated pre-commit hook runs the check with the
// project's own .venv interpreter when no python is on PATH (BACKLOG #5414).
import * as assert from "assert";
import * as childProcess from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { GITIGNORE_ENTRIES, PRE_COMMIT_TEMPLATE } from "../../sourceControlTemplates";

suite("Source-control setup ignores the engine's minted secrets (BACKLOG #5413)", () => {
  test("the TLS pair, its renewal and lock files, the bootstrap credential and .env are ignored", () => {
    for (const entry of [
      "api-generated-key.pem",
      "api-generated-cert.pem",
      "api-generated.lock",
      "api-generated-key.pem.renewing",
      "api-generated-cert.pem.renewing",
      "bootstrap-admin.txt",
      "master.key",
      "handoff.key",
      ".env",
      ".env.*",
    ]) {
      assert.ok(GITIGNORE_ENTRIES.includes(entry), `${entry} is not in the scaffolded .gitignore`);
    }
  });

  test("every entry the toolkit's config-repo scaffold ignores is ignored here too", function () {
    // The two scaffolds keep separate lists; this catches the next file the engine mints landing in
    // only one of them. Skipped where the repository is not beside the compiled suite.
    const scaffold = path.join(__dirname, "..", "..", "..", "..", "messagefoundry_toolkit", "scaffold.py");
    if (!fs.existsSync(scaffold)) {
      this.skip();
    }
    const text = fs.readFileSync(scaffold, "utf8");
    const block = /_GITIGNORE = """\\\r?\n([\s\S]*?)"""/.exec(text);
    assert.ok(block, "_GITIGNORE not found in scaffold.py; update this test");
    // The scaffold's spellings that this list covers with a wider pattern.
    const coveredOtherwise = new Set(["*.db", "*.db-shm", "*.db-wal", "/out/"]);
    const lines = block[1]
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#") && !coveredOtherwise.has(l));
    assert.ok(lines.includes("api-generated-key.pem"), "the parse found no entries; update this test");
    const missing = lines.filter((l) => !GITIGNORE_ENTRIES.includes(l));
    assert.deepStrictEqual(missing, [], "entries the toolkit scaffold ignores but setup does not");
  });

  test("git itself ignores the minted private key beside a workspace-root store", function () {
    this.timeout(30000); // a child git on a contended Windows runner can take seconds
    const probe = childProcess.spawnSync("git", ["--version"], { encoding: "utf8" });
    if (probe.status !== 0) {
      this.skip();
    }
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-gitignore-"));
    // No global or system config, so a user-level excludes file ignoring `*.pem` cannot pass this.
    const emptyConfig = path.join(ws, "..", `${path.basename(ws)}.gitconfig`);
    fs.writeFileSync(emptyConfig, "");
    const env = {
      ...process.env,
      GIT_CONFIG_GLOBAL: emptyConfig,
      GIT_CONFIG_NOSYSTEM: "1",
      // core.excludesFile defaults to $XDG_CONFIG_HOME/git/ignore; point it at nothing.
      XDG_CONFIG_HOME: path.join(ws, ".no-xdg"),
    };
    try {
      assert.strictEqual(childProcess.spawnSync("git", ["init", "-q"], { cwd: ws, env }).status, 0);
      fs.writeFileSync(path.join(ws, ".gitignore"), `${GITIGNORE_ENTRIES.join("\n")}\n`);
      fs.writeFileSync(path.join(ws, "api-generated-key.pem"), "not a real key\n");
      fs.writeFileSync(path.join(ws, "feed.py"), "# a config module\n");
      const res = childProcess.spawnSync(
        "git",
        ["ls-files", "--others", "--exclude-standard"],
        { cwd: ws, env, encoding: "utf8" },
      );
      const untracked = res.stdout.split(/\r?\n/).filter(Boolean);
      // The control: the config module IS stageable, so an empty list cannot pass this test.
      assert.ok(untracked.includes("feed.py"), `control file not listed: ${JSON.stringify(untracked)}`);
      assert.ok(!untracked.includes("api-generated-key.pem"), "the minted private key would be staged");
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
      fs.rmSync(emptyConfig, { force: true });
    }
  });
});

/** An absolute `sh`, found on the test process's PATH before the hook runs with an empty one. */
function findSh(): string | undefined {
  const name = process.platform === "win32" ? "sh.exe" : "sh";
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    const candidate = path.join(dir, name);
    if (dir && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  if (process.platform === "win32") {
    // Git for Windows runs hooks with its bundled sh, which is rarely on PATH outside Git Bash.
    const exec = childProcess.spawnSync("git", ["--exec-path"], { encoding: "utf8" });
    if (exec.status === 0) {
      const gitRoot = path.resolve(exec.stdout.trim(), "..", "..", "..");
      for (const rel of [["usr", "bin", "sh.exe"], ["bin", "sh.exe"]]) {
        const candidate = path.join(gitRoot, ...rel);
        if (fs.existsSync(candidate)) {
          return candidate;
        }
      }
    }
  }
  return undefined;
}

suite("The generated pre-commit hook prefers the project .venv (BACKLOG #5414)", () => {
  test("the .venv interpreter is probed before the PATH lookup can skip the check", () => {
    const venv = PRE_COMMIT_TEMPLATE.indexOf('[ -x ".venv/bin/python" ]');
    const skip = PRE_COMMIT_TEMPLATE.indexOf("python not found; skipping checks.");
    assert.ok(venv >= 0 && skip >= 0, "template markers moved; update this test");
    assert.ok(venv < skip, "the PATH lookup exits before the .venv interpreter is considered");
    assert.match(PRE_COMMIT_TEMPLATE, /exec "\$PY" -P -m messagefoundry check /);
  });

  test("the repository's own checked-in hook is the current template", function () {
    const checkedIn = path.join(__dirname, "..", "..", "..", "..", ".mefor-hooks", "pre-commit");
    if (!fs.existsSync(checkedIn)) {
      this.skip();
    }
    const rendered = PRE_COMMIT_TEMPLATE.replace(/__CONFIG_DIR__/g, "'samples/config'").replace(
      /__MESSAGES_DIR__/g,
      "'samples/messages'",
    );
    assert.strictEqual(fs.readFileSync(checkedIn, "utf8").replace(/\r\n/g, "\n"), rendered);
  });

  test("with no python on PATH the hook runs the check through .venv and propagates its exit code", function () {
    this.timeout(30000); // Git for Windows' sh is slow to start
    const sh = findSh();
    if (!sh) {
      this.skip();
    }
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), "mf-hook-"));
    const emptyPath = fs.mkdtempSync(path.join(os.tmpdir(), "mf-hook-path-"));
    try {
      fs.mkdirSync(path.join(ws, ".venv", "bin"), { recursive: true });
      const fakePython = path.join(ws, ".venv", "bin", "python");
      // The import probe succeeds; the check itself records its arguments and fails, as a broken
      // config would.
      fs.writeFileSync(
        fakePython,
        '#!/bin/sh\nfor a in "$@"; do [ "$a" = "-c" ] && exit 0; done\necho "$@" > ran.txt\nexit 7\n',
      );
      fs.chmodSync(fakePython, 0o755);
      const hook = PRE_COMMIT_TEMPLATE.replace(/__CONFIG_DIR__/g, "'config'").replace(
        /__MESSAGES_DIR__/g,
        "'messages'",
      );
      fs.writeFileSync(path.join(ws, "pre-commit"), hook);
      const res = childProcess.spawnSync(sh, ["pre-commit"], {
        cwd: ws,
        env: { PATH: emptyPath },
        encoding: "utf8",
      });
      assert.strictEqual(res.status, 7, `hook exited ${res.status}: ${res.stderr}`);
      assert.strictEqual(
        fs.readFileSync(path.join(ws, "ran.txt"), "utf8").trim(),
        "-P -m messagefoundry check --config config --messages messages",
      );
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
      fs.rmSync(emptyPath, { recursive: true, force: true });
    }
  });
});
