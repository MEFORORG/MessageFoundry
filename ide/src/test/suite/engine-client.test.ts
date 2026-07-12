import * as assert from "assert";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import type { Socket } from "node:net";

import { GET_TIMEOUT_MS, HttpError, getJson } from "../../engineClient";
import { classifyProbe } from "../../engineStatusModel";

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

  test("an unanswered request rejects (does not hang) with a transport-failure Error", async () => {
    const started = Date.now();
    await assert.rejects(
      () => getJson(url, "/health", undefined, 80),
      (e: unknown) => {
        assert.ok(e instanceof Error, "rejects with an Error");
        assert.ok(!(e instanceof HttpError), "a timeout is a transport failure, not an HttpError");
        return true;
      },
    );
    // Bounded by the injected cap — proves we rejected at the timeout, not after some OS socket wait.
    assert.ok(Date.now() - started < 4000, "rejects promptly at the injected timeout");
  });

  test("the production default cap is a positive, bounded value", () => {
    assert.ok(GET_TIMEOUT_MS > 0 && GET_TIMEOUT_MS <= 30_000);
  });

  test("classifyProbe folds that transport failure (as httpProbe would) into unreachable", () => {
    // httpProbe maps any non-HttpError — including the timeout above — to { kind: "networkError" }.
    assert.strictEqual(classifyProbe({ kind: "networkError" }), "unreachable");
  });
});
