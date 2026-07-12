import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { buildSymbolIndex, matchSymbols, scanModuleSymbols, type SymbolDef } from "../../symbolIndex";

// Pure (vscode-free) symbol scan for the sidebar name search (BACKLOG #228): find top-level
// handler/router/transform `def`s so a search reveals a transform / differently-named handler that is
// a Python symbol inside a role-combined feed module — not a connection filename or a graph element.

const SRC = [
  "import messagefoundry as mf",
  "",
  "@router",
  "def route_acme(msg):",
  '    return ["xform_acme_to_premier"]',
  "",
  "@functools.cache",
  "@mf.handler",
  "def handle_acme_mfn(msg):",
  "    return xform_acme_to_premier(msg)",
  "",
  "async def xform_acme_to_premier(msg):",
  "    def _local_helper(x):  # nested — must NOT be indexed",
  "        return x",
  "    return _local_helper(msg)",
  "",
  "def _shared_util(v):",
  "    return v",
].join("\n");

suite("symbolIndex — scanModuleSymbols (top-level defs + classification)", () => {
  const defs = scanModuleSymbols("/c/feed.py", SRC);
  const by = (n: string): SymbolDef | undefined => defs.find((d) => d.name === n);

  test("finds every top-level def, skips the indented nested def", () => {
    const names = defs.map((d) => d.name).sort();
    assert.deepStrictEqual(names, [
      "_shared_util",
      "handle_acme_mfn",
      "route_acme",
      "xform_acme_to_premier",
    ]);
    assert.strictEqual(
      by("_local_helper"),
      undefined,
      "an indented (nested) def is not a module-level symbol",
    );
  });

  test("classifies by the decorator run: @router / @handler / plain transform", () => {
    assert.strictEqual(by("route_acme")?.kind, "router");
    // @handler survives even under a preceding, unrelated decorator (@functools.cache) and a dotted name.
    assert.strictEqual(by("handle_acme_mfn")?.kind, "handler");
    assert.strictEqual(by("xform_acme_to_premier")?.kind, "transform");
    assert.strictEqual(by("_shared_util")?.kind, "transform");
  });

  test("line numbers are 1-based and the file is echoed through", () => {
    assert.strictEqual(by("route_acme")?.line, 4);
    assert.strictEqual(by("handle_acme_mfn")?.line, 9);
    assert.strictEqual(by("xform_acme_to_premier")?.line, 12);
    assert.ok(defs.every((d) => d.file === "/c/feed.py"));
  });

  test("CRLF source scans identically to LF", () => {
    const crlf = scanModuleSymbols("/c/feed.py", SRC.replace(/\n/g, "\r\n"));
    assert.deepStrictEqual(crlf, defs);
  });

  test("no false positive on a string/comment that mentions 'def'", () => {
    const s = ['x = "def not_a_def(): pass"', "# def also_not(): ...", "    def indented(): pass"].join("\n");
    assert.deepStrictEqual(scanModuleSymbols("/c/x.py", s), []);
  });
});

suite("symbolIndex — matchSymbols (filter, exclude, dedup, order)", () => {
  const index: SymbolDef[] = [
    { name: "xform_acme_to_premier", kind: "transform", file: "/c/feed.py", line: 12 },
    { name: "handle_acme_mfn", kind: "handler", file: "/c/feed.py", line: 9 },
    { name: "route_acme", kind: "router", file: "/c/feed.py", line: 4 },
    { name: "xform_acme_to_premier", kind: "transform", file: "/c/feed.py", line: 12 }, // dup
  ];

  test("case-insensitive substring match", () => {
    assert.deepStrictEqual(
      matchSymbols(index, "PREMIER").map((d) => d.name),
      ["xform_acme_to_premier"],
    );
  });

  test("a blank filter matches nothing (the section only exists while searching)", () => {
    assert.deepStrictEqual(matchSymbols(index, "   "), []);
  });

  test("excludeNames drops symbols already shown as graph elements", () => {
    const got = matchSymbols(index, "acme", new Set(["handle_acme_mfn", "route_acme"]));
    assert.deepStrictEqual(
      got.map((d) => d.name),
      ["xform_acme_to_premier"],
      "the handler+router are element rows already; only the transform remains",
    );
  });

  test("deduped by (name,file,line) and sorted by name", () => {
    const got = matchSymbols(index, "acme");
    assert.deepStrictEqual(
      got.map((d) => d.name),
      ["handle_acme_mfn", "route_acme", "xform_acme_to_premier"],
    );
  });
});

suite("symbolIndex — buildSymbolIndex (recurse, include _-prefixed, skip vendor dirs)", () => {
  let root: string;

  suiteSetup(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "mfsym-"));
    fs.writeFileSync(path.join(root, "IB_FILE_ACME_MFN.py"), "@mf.handler\ndef handle_mfn(m):\n    return m\n");
    fs.mkdirSync(path.join(root, "sub"));
    // A decomposed feed keeps transforms in a `_<feed>_transforms.py` — the loader skips `_*` for
    // WIRING, but #228 must still index it, so buildSymbolIndex includes it.
    fs.writeFileSync(path.join(root, "sub", "_acme_transforms.py"), "def xform_a(m):\n    return m\n");
    // Vendor/cache dirs and non-.py files must be ignored.
    fs.mkdirSync(path.join(root, "__pycache__"));
    fs.writeFileSync(path.join(root, "__pycache__", "ghost.py"), "def should_not_appear(m):\n    return m\n");
    fs.writeFileSync(path.join(root, "notes.txt"), "def also_ignored(): pass\n");
  });

  suiteTeardown(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  test("indexes .py under the tree incl. a `_`-prefixed transforms module, absolute paths, skips vendor + non-.py", () => {
    const names = buildSymbolIndex(root).map((d) => d.name).sort();
    assert.deepStrictEqual(names, ["handle_mfn", "xform_a"]);
    assert.ok(buildSymbolIndex(root).every((d) => path.isAbsolute(d.file)), "paths must be Uri.file-ready");
  });

  test("a missing config dir yields an empty index, never throws", () => {
    assert.deepStrictEqual(buildSymbolIndex(path.join(root, "does-not-exist")), []);
  });
});
