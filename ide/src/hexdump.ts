// Pure, dependency-free UTF-8 byte hex dump for the Test Bench (BACKLOG #84, ADR 0119). No `vscode`
// import, so it is unit-testable in isolation and cannot pull the extension host into a test — the
// same discipline as hl7diff.ts.
//
// SCOPE (ADR 0119, verifier-narrowed): the input is `DryRunRow.raw`, a JSON *string* the
// `dryrun --show-phi --json` CLI produced by UTF-8/`errors="replace"`-decoding the file bytes
// (parsing/peek.py). So this dumps the UTF-8 bytes of THAT string — the message as the dry-run
// decoded it — NOT the original wire bytes (genuinely-binary content is already lossily U+FFFD'd
// upstream and cannot be recovered here) and NOT an `mfb64:`/base64 whole-body decode (`raw` never
// carries the marker). A true binary hex view would need an engine/CLI read-path change.

/** One rendered row of the dump: a byte offset, its bytes as two-hex-digit pairs, and the ASCII gutter. */
export interface HexLine {
  offset: number; // byte offset of this row's first byte
  hex: string[]; // per-byte lowercase two-hex-digit strings (length ≤ bytesPerRow)
  ascii: string; // printable ASCII (0x20–0x7E) per byte, "." otherwise; length === hex.length
}

export interface HexDump {
  lines: HexLine[];
  totalBytes: number; // full UTF-8 byte length of the input (before any cap)
  renderedBytes: number; // bytes actually rendered (≤ maxBytes)
  truncated: boolean; // true when totalBytes > renderedBytes (render was capped)
  bytesPerRow: number;
}

export interface HexOptions {
  /** Max bytes to render; the rest is elided with `truncated=true`. Default 16 KiB (1024 rows @ 16). */
  maxBytes?: number;
  /** Bytes per rendered row. Default 16. */
  bytesPerRow?: number;
}

const DEFAULT_MAX_BYTES = 16 * 1024;
const DEFAULT_BYTES_PER_ROW = 16;

/** Format an 8-digit lowercase hex offset for the row gutter (matches a classic `hexdump -C`). */
export function formatOffset(n: number): string {
  return n.toString(16).padStart(8, "0");
}

/** UTF-8-encode a string to bytes. TextEncoder is a Node/Extension-Host global (no import needed). */
function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * Build a capped `offset · hex · ASCII` dump of the UTF-8 bytes of `text`. Pure: no I/O, never throws
 * on any string (control chars, multi-byte runes, U+FFFD replacement chars all encode to real bytes).
 */
export function hexdump(text: string, opts: HexOptions = {}): HexDump {
  const bytesPerRow = Math.max(1, Math.floor(opts.bytesPerRow ?? DEFAULT_BYTES_PER_ROW));
  const maxBytes = Math.max(0, Math.floor(opts.maxBytes ?? DEFAULT_MAX_BYTES));
  const all = utf8Bytes(text);
  const totalBytes = all.length;
  const renderedBytes = Math.min(totalBytes, maxBytes);

  const lines: HexLine[] = [];
  for (let off = 0; off < renderedBytes; off += bytesPerRow) {
    const end = Math.min(off + bytesPerRow, renderedBytes);
    const hex: string[] = [];
    let ascii = "";
    for (let i = off; i < end; i++) {
      const b = all[i];
      hex.push(b.toString(16).padStart(2, "0"));
      ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
    }
    lines.push({ offset: off, hex, ascii });
  }

  return {
    lines,
    totalBytes,
    renderedBytes,
    truncated: totalBytes > renderedBytes,
    bytesPerRow,
  };
}
