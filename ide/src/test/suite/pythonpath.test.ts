import * as assert from "assert";
import * as path from "path";

import { resolvePythonPath } from "../../cli";

// SEC-004 regression. resolvePythonPath is the pure interpreter-selection helper; these assert that a
// trojaned workspace .venv is NOT preferred in an untrusted workspace, while the existing trusted
// auto-detect and explicit-config behaviors are preserved.
const WS = "/work/ws"; // a posix-style workspace root used for both platform branches

suite("resolvePythonPath (SEC-004)", () => {
  test("an explicitly-configured interpreter is returned verbatim regardless of trust", () => {
    for (const isTrusted of [true, false]) {
      const r = resolvePythonPath({
        configured: "/opt/py/bin/python",
        workspace: WS,
        isTrusted,
        venvExists: () => true,
        platform: "linux",
      });
      assert.strictEqual(r, "/opt/py/bin/python");
    }
  });

  test("untrusted workspace does NOT prefer a present .venv — falls through to PATH 'python'", () => {
    const r = resolvePythonPath({
      configured: "python",
      workspace: WS,
      isTrusted: false,
      venvExists: () => true, // a trojaned .venv exists on disk…
      platform: "win32",
    });
    assert.strictEqual(r, "python"); // …and is ignored because the workspace is untrusted
  });

  test("trusted workspace prefers the .venv — win32 path", () => {
    const r = resolvePythonPath({
      configured: "python",
      workspace: WS,
      isTrusted: true,
      venvExists: () => true,
      platform: "win32",
    });
    assert.strictEqual(r, path.join(WS, ".venv", "Scripts", "python.exe"));
  });

  test("trusted workspace prefers the .venv — posix path", () => {
    const r = resolvePythonPath({
      configured: "python",
      workspace: WS,
      isTrusted: true,
      venvExists: () => true,
      platform: "linux",
    });
    assert.strictEqual(r, path.join(WS, ".venv", "bin", "python"));
  });

  test("no workspace → 'python'", () => {
    const r = resolvePythonPath({
      configured: "python",
      workspace: undefined,
      isTrusted: true,
      venvExists: () => true,
      platform: "linux",
    });
    assert.strictEqual(r, "python");
  });

  test("trusted but no .venv on disk → 'python'", () => {
    const r = resolvePythonPath({
      configured: "python",
      workspace: WS,
      isTrusted: true,
      venvExists: () => false,
      platform: "linux",
    });
    assert.strictEqual(r, "python");
  });
});
