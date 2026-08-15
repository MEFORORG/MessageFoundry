// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";

import { formatOffset, hexdump } from "../../hexdump";

// Flatten every rendered byte back to one hex-pair string, in order — handy for asserting content
// independent of row wrapping.
function allHex(text: string, maxBytes?: number): string[] {
  return hexdump(text, maxBytes === undefined ? {} : { maxBytes }).lines.flatMap((l) => l.hex);
}

suite("hexdump.formatOffset", () => {
  test("8-digit lowercase hex", () => {
    assert.strictEqual(formatOffset(0), "00000000");
    assert.strictEqual(formatOffset(16), "00000010");
    assert.strictEqual(formatOffset(255), "000000ff");
  });
});

suite("hexdump — offsets, hex pairs, ASCII gutter", () => {
  test("ASCII text maps byte-for-byte with a monotonic offset (AC-1)", () => {
    const dump = hexdump("ABC");
    assert.strictEqual(dump.totalBytes, 3);
    assert.strictEqual(dump.truncated, false);
    assert.strictEqual(dump.lines.length, 1);
    const row = dump.lines[0];
    assert.strictEqual(row.offset, 0);
    assert.deepStrictEqual(row.hex, ["41", "42", "43"]); // A, B, C
    assert.strictEqual(row.ascii, "ABC");
  });

  test("rows advance by bytesPerRow and offsets are monotonic", () => {
    const dump = hexdump("0123456789abcdefX", { bytesPerRow: 16 });
    assert.strictEqual(dump.lines.length, 2);
    assert.strictEqual(dump.lines[0].offset, 0);
    assert.strictEqual(dump.lines[1].offset, 16);
    assert.deepStrictEqual(dump.lines[1].hex, ["58"]); // trailing 'X'
    assert.strictEqual(dump.lines[1].ascii, "X");
  });

  test("non-printable bytes render as '.' in the ASCII gutter but keep their hex", () => {
    // \r (0x0d), \n (0x0a), NUL (0x00) — all non-printable → '.'; 'M','S','H' printable.
    const dump = hexdump("MSH\r\n\x00");
    const row = dump.lines[0];
    assert.deepStrictEqual(row.hex, ["4d", "53", "48", "0d", "0a", "00"]);
    assert.strictEqual(row.ascii, "MSH...");
  });
});

suite("hexdump — multi-byte / non-ASCII (AC-3)", () => {
  test("é dumps its 2-byte UTF-8 sequence, not the code unit", () => {
    // 'é' U+00E9 → 0xC3 0xA9 in UTF-8.
    const dump = hexdump("é");
    assert.strictEqual(dump.totalBytes, 2);
    assert.deepStrictEqual(dump.lines[0].hex, ["c3", "a9"]);
    assert.strictEqual(dump.lines[0].ascii, ".."); // both bytes > 0x7e
  });

  test("U+FFFD replacement char (what a corrupted binary body decodes to) dumps its 3 bytes and never throws", () => {
    // The dry-run decodes invalid bytes to U+FFFD; hexdump must handle the string form.
    const dump = hexdump("�");
    assert.deepStrictEqual(dump.lines[0].hex, ["ef", "bf", "bd"]);
  });

  test("an emoji (surrogate pair) encodes to its 4 UTF-8 bytes", () => {
    // '😀' U+1F600 → F0 9F 98 80.
    assert.deepStrictEqual(allHex("😀"), ["f0", "9f", "98", "80"]);
  });
});

suite("hexdump — render cap (AC-2)", () => {
  test("caps at maxBytes, sets truncated, and reports the true totalBytes", () => {
    const text = "a".repeat(100);
    const dump = hexdump(text, { maxBytes: 10 });
    assert.strictEqual(dump.totalBytes, 100);
    assert.strictEqual(dump.renderedBytes, 10);
    assert.strictEqual(dump.truncated, true);
    assert.strictEqual(dump.lines.flatMap((l) => l.hex).length, 10);
  });

  test("no truncation when the body fits", () => {
    const dump = hexdump("short", { maxBytes: 1024 });
    assert.strictEqual(dump.truncated, false);
    assert.strictEqual(dump.renderedBytes, dump.totalBytes);
  });

  test("empty input yields no rows and no truncation", () => {
    const dump = hexdump("");
    assert.strictEqual(dump.totalBytes, 0);
    assert.strictEqual(dump.lines.length, 0);
    assert.strictEqual(dump.truncated, false);
  });
});
