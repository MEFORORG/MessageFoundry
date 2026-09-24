// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  MAX_SAMPLE_FILE_BYTES,
  SampleTooLargeError,
  checkSampleSize,
  readSampleCapped,
} from "../../sampleFile";

// Synthetic only: every sample here is a made-up header, never real PHI.
const MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X1|P|2.5.1\r";

function sample(size: number): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mefor-sample-"));
  const file = path.join(dir, "s.hl7");
  fs.writeFileSync(file, (MSG + "X".repeat(size)).slice(0, size), "utf8");
  return file;
}

suite("sampleFile: the Steps view's picked-sample read is capped (ASVS 5.1.1, BACKLOG #1127)", () => {
  test("the default cap is dryrun's MAX_FIXTURE_FILE_BYTES, 16 MiB", () => {
    assert.strictEqual(MAX_SAMPLE_FILE_BYTES, 16 * 1024 * 1024);
  });

  test("a sample under or at the cap is read whole", () => {
    const small = sample(20);
    assert.strictEqual(readSampleCapped(small, 64), MSG.slice(0, 20));
    const exact = sample(64);
    assert.strictEqual(readSampleCapped(exact, 64).length, 64);
    checkSampleSize(exact, 64); // does not throw
  });

  test("a sample one byte over the cap is refused, naming the file", () => {
    const big = sample(65);
    assert.throws(() => readSampleCapped(big, 64), (e: unknown) => {
      assert.ok(e instanceof SampleTooLargeError);
      assert.match((e as Error).message, /s\.hl7 is over the 64-byte sample file cap/);
      return true;
    });
    assert.throws(() => checkSampleSize(big, 64), SampleTooLargeError);
  });

  test("a missing sample is the fs error, not a size refusal", () => {
    const missing = path.join(os.tmpdir(), "mefor-no-such-sample.hl7");
    assert.throws(
      () => readSampleCapped(missing, 64),
      (e: unknown) => !(e instanceof SampleTooLargeError),
    );
  });
});
