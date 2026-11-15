// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// BACKLOG #5415: the files a collection run writes for `dryrun`. Every body here is synthetic.

import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  CASE_DIR_PREFIX,
  STALE_CASE_DIR_MS,
  caseDryRunArgs,
  caseFileName,
  materializeCases,
  removeCaseDir,
  sweepStaleCaseDirs,
} from "../../collectionCaseFiles";
import { unlinkLinks } from "../unlinkLinks";

const BODY = "MSH|^~\\&|APP|FAC|RCV|RFAC|20200101010101||ADT^A01|C1|P|2.5\rPID|1||SYNTH^TEST";
const POSIX = process.platform !== "win32";

suite("collectionCaseFiles — a run's case files (BACKLOG #5415)", () => {
  let base: string;
  setup(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "mefor-casefiles-test-"));
  });
  teardown(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  test("writes one file per case, named so a dry-run row maps back to its case", () => {
    const dir = materializeCases([BODY, BODY + "2"], base);
    assert.ok(path.basename(dir).startsWith(CASE_DIR_PREFIX));
    assert.deepStrictEqual(fs.readdirSync(dir).sort(), [caseFileName(0), caseFileName(1)]);
    assert.strictEqual(fs.readFileSync(path.join(dir, caseFileName(1)), "utf8"), BODY + "2");
  });

  test("the directory and every file are owner-only", function () {
    if (!POSIX) {
      this.skip(); // Windows ignores POSIX mode bits; the per-user TEMP ACL governs there
    }
    const dir = materializeCases([BODY], base);
    assert.strictEqual(fs.statSync(dir).mode & 0o777, 0o700);
    assert.strictEqual(fs.statSync(path.join(dir, caseFileName(0))).mode & 0o777, 0o600);
  });

  test("a failed write leaves no directory and no body behind", () => {
    // A non-string input makes writeFileSync throw after the first case file is on disk.
    const bad = [BODY, 42 as unknown as string];
    assert.throws(() => materializeCases(bad, base));
    assert.deepStrictEqual(fs.readdirSync(base), []);
  });

  test("removeCaseDir removes the run's directory and tolerates one already gone", () => {
    const dir = materializeCases([BODY], base);
    removeCaseDir(dir);
    assert.ok(!fs.existsSync(dir));
    removeCaseDir(dir);
  });

  test("the dry-run gets the directory, never one path per case", () => {
    const dir = materializeCases([BODY, BODY, BODY], base);
    assert.deepStrictEqual(caseDryRunArgs("cfg", dir), ["dryrun", "--config", "cfg", "--show-phi", "--messages", dir]);
  });
});

suite("collectionCaseFiles.sweepStaleCaseDirs — what a crashed run left (BACKLOG #5415)", () => {
  let base: string;
  setup(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "mefor-casefiles-test-"));
  });
  teardown(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  test("removes a stale run directory and keeps a fresh one and anything not ours", () => {
    const stale = materializeCases([BODY], base);
    const fresh = materializeCases([BODY], base);
    const other = path.join(base, "someone-else");
    fs.mkdirSync(other);
    const old = (Date.now() - STALE_CASE_DIR_MS - 60_000) / 1000;
    fs.utimesSync(stale, old, old);
    fs.utimesSync(other, old, old);
    assert.strictEqual(sweepStaleCaseDirs(base), 1);
    assert.ok(!fs.existsSync(stale));
    assert.ok(fs.existsSync(fresh));
    assert.ok(fs.existsSync(other));
  });

  test("a prefixed file that is not a directory is left alone", () => {
    const f = path.join(base, CASE_DIR_PREFIX + "file");
    fs.writeFileSync(f, "x");
    assert.strictEqual(sweepStaleCaseDirs(base, Date.now() + 10 * STALE_CASE_DIR_MS), 0);
    assert.ok(fs.existsSync(f));
  });

  test("a symlink named like a run directory is never followed or removed", function () {
    if (!POSIX) {
      this.skip(); // a Windows symlink needs a privilege a test runner may not hold
    }
    const target = fs.mkdtempSync(path.join(base, "target-"));
    fs.writeFileSync(path.join(target, "keep.hl7"), BODY);
    const link = path.join(base, CASE_DIR_PREFIX + "link");
    fs.symlinkSync(target, link);
    assert.strictEqual(sweepStaleCaseDirs(base, Date.now() + 10 * STALE_CASE_DIR_MS), 0);
    assert.ok(fs.existsSync(path.join(target, "keep.hl7")));
  });

  test("on POSIX a run directory another user owns is left alone", function () {
    if (!POSIX) {
      this.skip();
    }
    const dir = materializeCases([BODY], base);
    const geteuid = process.geteuid;
    const later = Date.now() + 10 * STALE_CASE_DIR_MS;
    try {
      // Pretend to be a different user: the directory's owner then no longer matches.
      (process as { geteuid?: () => number }).geteuid = () => (geteuid ? geteuid() : 0) + 1;
      assert.strictEqual(sweepStaleCaseDirs(base, later), 0);
      assert.ok(fs.existsSync(dir));
    } finally {
      (process as { geteuid?: () => number }).geteuid = geteuid;
    }
    assert.strictEqual(sweepStaleCaseDirs(base, later), 1); // control: as its owner, it goes
  });

  test("an unreadable base removes nothing and does not throw", () => {
    assert.strictEqual(sweepStaleCaseDirs(path.join(base, "missing")), 0);
  });
});

suite("collectionCaseFiles: a run directory is deleted without recursing (BACKLOG #5415)", () => {
  let base: string;
  setup(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "mefor-casefiles-test-"));
  });
  teardown(() => {
    try {
      unlinkLinks(base);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  // Each way a run directory is deleted: at the end of its run, and by a later run's sweep.
  const deleters: [string, (dir: string) => void][] = [
    ["removeCaseDir", removeCaseDir],
    ["sweepStaleCaseDirs", (dir) => void sweepStaleCaseDirs(path.dirname(dir), Date.now() + 10 * STALE_CASE_DIR_MS)],
  ];

  for (const [how, remove] of deleters) {
    test(`${how}: a junction inside a run directory leaves its target's files intact`, function () {
      const dir = materializeCases([BODY], base);
      const target = fs.mkdtempSync(path.join(base, "target-"));
      // A case-named file in the target too: it must survive as much as any other.
      for (const name of ["keep.txt", caseFileName(0)]) {
        fs.writeFileSync(path.join(target, name), BODY);
      }
      try {
        fs.symlinkSync(target, path.join(dir, "linked"), "junction");
      } catch {
        this.skip(); // creating a link can need a privilege the runner lacks
      }
      remove(dir);
      assert.deepStrictEqual(fs.readdirSync(target).sort(), [caseFileName(0), "keep.txt"].sort(), "a file in the junction's target was deleted");
      // The run's own case file goes; the directory stays, since the link is still in it.
      assert.deepStrictEqual(fs.readdirSync(dir), ["linked"]);
    });

    test(`${how}: a run directory holding a file that is not a case file is left in place`, () => {
      const dir = materializeCases([BODY, BODY], base);
      fs.writeFileSync(path.join(dir, "notes.txt"), "x");
      remove(dir);
      assert.deepStrictEqual(fs.readdirSync(dir), ["notes.txt"]);
      // THE CONTROL: a directory of case files only goes.
      const plain = materializeCases([BODY, BODY], base);
      remove(plain);
      assert.ok(!fs.existsSync(plain), "a directory of case files only was not removed");
    });

    test(`${how}: an entry named like a case file that is not a regular file is left, and the case files around it go`, () => {
      const dir = materializeCases([BODY, BODY], base);
      fs.mkdirSync(path.join(dir, caseFileName(9999)));
      remove(dir);
      assert.deepStrictEqual(fs.readdirSync(dir), [caseFileName(9999)]);
    });
  }
});
