// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
import * as assert from "assert";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { buildSymbolIndex, matchSymbols, scanModuleSymbols, type SymbolDef } from "../../symbolIndex";

// The REAL node:fs module object, for the descriptor test's spies. `import * as fs` compiles
// (esModuleInterop, module=commonjs) to a namespace COPY whose members are forwarding getters onto this
// object — so the copy cannot be assigned to, while a spy installed HERE is what symbolIndex.ts calls.
const FS_MODULE: Record<string, unknown> = require("node:fs");

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

// #228 remainder (b): the outbound connections a handler Sends to. A `Send(…)` sits INSIDE a def body,
// so the column-0 def regex can never reach one — this is a separate extraction pass, and these tests
// pin its BOUND as hard as its reach. The scan is line-scoped and text-only, so what it DROPS (a
// computed target, a ruff-wrapped call, a commented one) is asserted alongside what it finds — a bound
// that is only asserted in a docstring is a claim, not a control.
suite("symbolIndex — scanModuleSymbols (Send targets)", () => {
  test("a literal Send target indexes as kind 'send' at the CALL-SITE line", () => {
    const src = ["@mf.handler", "def handle(msg):", '    return Send("OB_ACME_ADT", msg)'].join("\n");
    const sends = scanModuleSymbols("/c/feed.py", src).filter((d) => d.kind === "send");
    assert.deepStrictEqual(sends, [{ name: "OB_ACME_ADT", kind: "send", file: "/c/feed.py", line: 3 }]);
  });

  test("two Send calls on ONE line each yield a row", () => {
    const src = ["def handle(msg):", '    return [Send("OB_A", msg), Send("OB_B", msg)]'].join("\n");
    assert.deepStrictEqual(
      scanModuleSymbols("/c/feed.py", src)
        .filter((d) => d.kind === "send")
        .map((d) => d.name),
      ["OB_A", "OB_B"],
    );
  });

  test("a commented-out Send is not a call site — whole-line OR trailing", () => {
    // The trailing form is the one a whole-line `#` guard misses, and it is the likelier one in real
    // source: a call site edited in place leaves the old target in a comment on the SAME line.
    const src = [
      "def handle(msg):",
      '    # return Send("OB_GHOST_LEADING", msg)',
      '    return Send("OB_REAL", msg)  # was Send("OB_GHOST_TRAILING", msg)',
    ].join("\n");
    assert.deepStrictEqual(
      scanModuleSymbols("/c/feed.py", src)
        .filter((d) => d.kind === "send")
        .map((d) => d.name),
      ["OB_REAL"],
      "neither commented target may contribute a row",
    );
  });

  test("a `#` INSIDE a string literal does not truncate the line", () => {
    // The failure mode a naive split-at-first-`#` would introduce: it would silently drop OB_B, i.e.
    // fix the comment bug by creating a worse one — a real call site missing from the index.
    const src = ["def handle(msg):", '    return Send("OB_A", msg) if "#" in msg.text else Send("OB_B", msg)'].join(
      "\n",
    );
    assert.deepStrictEqual(
      scanModuleSymbols("/c/feed.py", src)
        .filter((d) => d.kind === "send")
        .map((d) => d.name),
      ["OB_A", "OB_B"],
    );
  });

  test("a module constant with a trailing comment still resolves", () => {
    const src = [
      'OB_DEMO = "OB_DEMO_ORU"  # the relay outbound',
      "",
      "def handle(msg):",
      "    return Send(OB_DEMO, msg)",
    ].join("\n");
    assert.deepStrictEqual(
      scanModuleSymbols("/c/feed.py", src)
        .filter((d) => d.kind === "send")
        .map((d) => d.name),
      ["OB_DEMO_ORU"],
    );
  });

  // Pins the BOUND rather than the reach: the scan is line-scoped, so a target ruff wrapped onto its own
  // line is invisible to it. Asserting this keeps the documented bound honest — "a quoted literal target
  // is indexed" is false for the wrapped form, and a silent [] is what actually happens.
  test("a line-wrapped Send is DROPPED, not half-indexed — the scan is line-scoped", () => {
    const src = ["def handle(msg):", "    return Send(", '        "OB_WRAPPED",', "        msg,", "    )"].join("\n");
    assert.deepStrictEqual(
      scanModuleSymbols("/c/feed.py", src).filter((d) => d.kind === "send"),
      [],
      "the bound must be a drop, never a phantom row",
    );
  });

  test("an unresolvable Send target is dropped, never indexed as a phantom name", () => {
    const src = ["def handle(msg, some_var):", "    return Send(some_var, msg)"].join("\n");
    assert.deepStrictEqual(
      scanModuleSymbols("/c/feed.py", src).filter((d) => d.kind === "send"),
      [],
      "a computed/unknown target is invisible to a text scan — dropping it is the honest answer",
    );
  });

  // The repo's own flagship decomposition sample (samples/config/IB_DEMO_ORU_handler.py) sends through a
  // module constant, so without this the feature would miss the file docs/CONNECTIONS.md holds up as THE
  // "decomposing by role" example.
  test("a module-level constant target indexes its RESOLVED literal, not the constant's name", () => {
    const src = ['OB_DEMO = "OB_DEMO_ORU"', "", "def handle(msg):", "    return Send(OB_DEMO, msg)"].join("\n");
    const sends = scanModuleSymbols("/c/feed.py", src).filter((d) => d.kind === "send");
    assert.deepStrictEqual(sends, [{ name: "OB_DEMO_ORU", kind: "send", file: "/c/feed.py", line: 4 }]);
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

  // The one defect in remainder (b) that the compiler is blind to. A send row's name IS an outbound
  // connection name, so it is in excludeNames whenever the graph loaded (graphTree passes
  // collectElementNames(vms)). Without the carve-out every send row is filtered out and the feature
  // ships DEAD — built, compiling, and rendering nothing.
  test("a send row survives excludeNames — a call site is not the element", () => {
    const withSend: SymbolDef[] = [...index, { name: "OB_ACME_ADT", kind: "send", file: "/c/feed.py", line: 29 }];
    assert.deepStrictEqual(
      matchSymbols(withSend, "OB_ACME", new Set(["OB_ACME_ADT"])).map((d) => `${d.kind}:${d.name}`),
      ["send:OB_ACME_ADT"],
    );
  });

  test("...and the carve-out is not too wide: an excluded HANDLER row is still dropped", () => {
    const withSend: SymbolDef[] = [...index, { name: "OB_ACME_ADT", kind: "send", file: "/c/feed.py", line: 29 }];
    assert.deepStrictEqual(
      matchSymbols(withSend, "acme", new Set(["handle_acme_mfn", "route_acme", "OB_ACME_ADT"])).map((d) => d.name),
      ["OB_ACME_ADT", "xform_acme_to_premier"],
      "only the send row is exempt; the handler/router still must not double-list",
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

// CodeQL js/file-system-race: the scan used to size-check with `statSync(path)` and then read with
// `readFileSync(path)` — two independent path resolutions, so the file that was READ need not be the
// file that was CHECKED. That voids the maxBytes guard with no attacker involved (a save, a formatter
// or a codegen step rewriting a module between the two calls is routine in a live workspace).
suite("symbolIndex — buildSymbolIndex resolves each file once (js/file-system-race)", () => {
  let root: string;

  suiteSetup(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "mfsym-race-"));
    fs.writeFileSync(path.join(root, "small.py"), "def xform_small(m):\n    return m\n");
    // Comfortably over the 64-byte cap the tests below pass, so it takes the oversize path.
    fs.writeFileSync(path.join(root, "big.py"), `def xform_big(m):\n    return m\n# ${"p".repeat(4096)}\n`);
  });

  suiteTeardown(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  test("a file over maxBytes is skipped; smaller siblings still index", () => {
    assert.deepStrictEqual(
      buildSymbolIndex(root, { maxBytes: 64 }).map((d) => d.name),
      ["xform_small"],
    );
  });

  test("size-checks and reads the SAME descriptor, and closes every one it opens", () => {
    const readArgs: fs.PathOrFileDescriptor[] = [];
    const statPaths: string[] = [];
    const opened: number[] = [];
    const closed: number[] = [];

    // Captured through the namespace import BEFORE patching, so they are the real, fully-typed
    // functions; the spies delegate to these rather than to the (now patched) module members.
    const origRead = fs.readFileSync;
    const origStat = fs.statSync;
    const origOpen = fs.openSync;
    const origClose = fs.closeSync;

    try {
      FS_MODULE.readFileSync = (p: fs.PathOrFileDescriptor, o: BufferEncoding): string => {
        readArgs.push(p);
        return origRead(p, o);
      };
      FS_MODULE.statSync = (p: fs.PathLike): fs.Stats => {
        statPaths.push(String(p));
        return origStat(p);
      };
      FS_MODULE.openSync = (p: fs.PathLike, flags: fs.OpenMode): number => {
        const fd = origOpen(p, flags);
        opened.push(fd);
        return fd;
      };
      FS_MODULE.closeSync = (fd: number): void => {
        closed.push(fd);
        origClose(fd);
      };

      assert.deepStrictEqual(
        buildSymbolIndex(root, { maxBytes: 64 }).map((d) => d.name),
        ["xform_small"],
      );
    } finally {
      FS_MODULE.readFileSync = origRead;
      FS_MODULE.statSync = origStat;
      FS_MODULE.openSync = origOpen;
      FS_MODULE.closeSync = origClose;
    }

    // Fail loudly rather than pass vacuously: if the scan read nothing, every check below is empty.
    assert.ok(readArgs.length > 0, "the index build read no file — the checks below would be vacuous");
    for (const a of readArgs) {
      assert.strictEqual(
        typeof a,
        "number",
        `readFileSync was handed a PATH (${String(a)}); the size check and the read must share one fd`,
      );
    }
    assert.deepStrictEqual(statPaths, [], "a path-based statSync re-opens the TOCTOU window");
    // Both files are opened (the oversize one too, to fstat it), so this also proves the `finally` in
    // readCapped releases the descriptor on the skip path — the leak the fd rewrite could have added.
    assert.strictEqual(opened.length, 2, "expected one open per .py file in the fixture tree");
    assert.deepStrictEqual(closed, opened, "every opened descriptor must be closed, oversize path included");
  });
});
