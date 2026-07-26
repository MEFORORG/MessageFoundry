import * as assert from "assert";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import type { Socket } from "node:net";

import { GET_TIMEOUT_MS, HttpError, NetworkError, TIMEOUT_CODE, getJson } from "../../engineClient";
import { classifyHealth, resolveEngineStatusTarget } from "../../engineStatusModel";

// F2: a hung engine (accepts the socket but never answers) must not leave the status probe pending
// forever — it would stick on "checking…" and leak the socket. getJson now caps the request; the status
// bar then folds the resulting transport failure into "unreachable". Exercised node-side against a
// loopback server that never responds — no vscode, no Python CLI.
suite("engineClient — getJson timeout (F2)", () => {
  let server: http.Server;
  let url: string;
  const sockets = new Set<Socket>();

  setup(async () => {
    server = http.createServer(() => {
      /* accept the request but never send a response — model a hung engine */
    });
    server.on("connection", (s) => {
      sockets.add(s);
      s.on("close", () => sockets.delete(s));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    url = `http://127.0.0.1:${addr.port}`;
  });

  teardown(() => {
    for (const s of sockets) {
      s.destroy();
    }
    sockets.clear();
    server.close();
  });

  test("an unanswered request rejects (does not hang) and is TAGGED as a timeout", async () => {
    const started = Date.now();
    await assert.rejects(
      () => getJson(url, "/health", undefined, 80),
      (e: unknown) => {
        assert.ok(e instanceof NetworkError, "a timeout is a transport failure, not an HttpError");
        assert.ok(!(e instanceof HttpError));
        // The errno is the whole point: "the engine accepted my connection and then went silent" is a
        // DIFFERENT fault from "nothing is listening", and the status bar must be able to say which.
        assert.strictEqual((e as NetworkError).code, TIMEOUT_CODE);
        return true;
      },
    );
    // Bounded by the injected cap — proves we rejected at the timeout, not after some OS socket wait.
    assert.ok(Date.now() - started < 4000, "rejects promptly at the injected timeout");
  });

  test("a refused connection carries ECONNREFUSED, distinctly from a timeout", async () => {
    // Close the server first so the port is dead — the OS refuses immediately.
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await assert.rejects(
      () => getJson(url, "/health", undefined, 500),
      (e: unknown) => {
        assert.ok(e instanceof NetworkError);
        assert.strictEqual((e as NetworkError).code, "ECONNREFUSED");
        return true;
      },
    );
  });

  test("the production default cap is a positive, bounded value", () => {
    assert.ok(GET_TIMEOUT_MS > 0 && GET_TIMEOUT_MS <= 30_000);
  });

  test("the status bar renders a hung engine and a dead one DIFFERENTLY", () => {
    // Before NetworkError.code existed, both of these arrived as the same bare Error and rendered as one
    // undifferentiated "not reachable" — so a hung engine and a stopped one were indistinguishable.
    const target = resolveEngineStatusTarget(url, []);
    const hung = classifyHealth({ kind: "networkError", code: TIMEOUT_CODE }, target, Date.now(), false);
    const dead = classifyHealth({ kind: "networkError", code: "ECONNREFUSED" }, target, Date.now(), false);
    assert.strictEqual(hung.state, "unreachable");
    assert.strictEqual(dead.state, "unreachable");
    assert.notStrictEqual(hung.reason, dead.reason);
    assert.ok(/hung/i.test(hung.reason ?? ""));
    assert.ok(/nothing is listening/i.test(dead.reason ?? ""));
  });
});
