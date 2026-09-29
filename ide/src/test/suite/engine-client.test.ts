// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import type { Socket } from "node:net";

import {
  GET_TIMEOUT_MS,
  HTTP_PENDING_APPROVAL,
  HttpError,
  NetworkError,
  TIMEOUT_CODE,
  classifyApprovable,
  getJson,
  postApprovable,
  postJson,
} from "../../engineClient";
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

// BACKLOG #330 — the LAST HOP of the chain. Every other test in this change stops at a call boundary
// (a recorded argument, a plan constant); this one puts a real request on a real socket and reads the
// header the engine would see. Without it the item's headline claim — "the read is authenticated" —
// rests on a header nobody has observed. Both polarities are asserted: that a token becomes a Bearer
// header, AND that a tokenless call really sends nothing (the status bar's read depends on the latter).
suite("engineClient — getJson sends the bearer only when given one (BACKLOG #330)", () => {
  let server: http.Server;
  let url: string;
  let seen: string | undefined;
  let sawHeader = false;

  setup(async () => {
    seen = undefined;
    sawHeader = false;
    server = http.createServer((req, res) => {
      seen = req.headers.authorization;
      sawHeader = "authorization" in req.headers;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    url = `http://127.0.0.1:${addr.port}`;
  });

  teardown(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("T15a: a token is sent as `Authorization: Bearer <token>`", async () => {
    await getJson(url, "/ai/policy", "tok-abc");
    assert.strictEqual(seen, "Bearer tok-abc");
  });

  test("T15b: a tokenless call sends NO Authorization header at all", async () => {
    // Not merely "not a valid token" — the header must be absent. `Bearer undefined` would be a string
    // the engine tries to resolve, and on the status bar's 15s path any bearer at all is the CWE-613 bug.
    await getJson(url, "/ai/policy");
    assert.strictEqual(seen, undefined);
    assert.strictEqual(sawHeader, false, "the header key must not be present");
  });
});

// BACKLOG #1981 — a route dual control may hold answers 202 with a PendingApprovalResponse body
// (messagefoundry/api/models.py). postJson reads every 2xx as the expected type, so a held action came
// back as a "result" with undefined fields. postApprovable keeps the status and tags the outcome.
suite("engineClient — postApprovable tells a hold from a result (BACKLOG #1981)", () => {
  let server: http.Server;
  let url: string;
  let replyStatus = 200;
  let replyBody: unknown = {};

  const pendingBody = {
    approval_id: "0f3c9a4e5b6d47e8a1b2c3d4e5f60718",
    operation: "config_reload",
    status: "pending_approval",
    detail: "held for a second approver (dual-control)",
  };

  setup(async () => {
    replyStatus = 200;
    replyBody = {};
    server = http.createServer((_req, res) => {
      res.writeHead(replyStatus, { "Content-Type": "application/json" });
      res.end(JSON.stringify(replyBody));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    url = `http://127.0.0.1:${addr.port}`;
  });

  teardown(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("the hold status is the engine's 202", () => {
    assert.strictEqual(HTTP_PENDING_APPROVAL, 202);
  });

  test("a 202 with a pending-approval body is HELD, carrying the approval id", async () => {
    replyStatus = 202;
    replyBody = pendingBody;
    const out = await postApprovable<{ inbound: number }>(url, "/config/reload", {}, "tok");
    assert.ok(out.kind === "held", `expected held, got ${out.kind}`);
    assert.strictEqual(out.pending.approval_id, pendingBody.approval_id);
    assert.strictEqual(out.pending.operation, "config_reload");
    assert.strictEqual(out.pending.status, "pending_approval");
  });

  test("control: a 200 with a result body is DONE, with the body as sent", async () => {
    replyStatus = 200;
    replyBody = { inbound: 3 };
    const out = await postApprovable<{ inbound: number }>(url, "/config/reload", {}, "tok");
    assert.deepStrictEqual(out, { kind: "done", body: { inbound: 3 } });
  });

  test("a 202 WITHOUT a pending-approval body rejects rather than reading as success", async () => {
    replyStatus = 202;
    replyBody = { inbound: 3 };
    await assert.rejects(
      () => postApprovable(url, "/config/reload", {}, "tok"),
      /HTTP 202 without a pending-approval body/,
    );
  });

  test("a non-2xx still rejects with HttpError, exactly as postJson does", async () => {
    replyStatus = 403;
    replyBody = { detail: "forbidden" };
    await assert.rejects(
      () => postApprovable(url, "/config/reload", {}, "tok"),
      (e: unknown) => e instanceof HttpError && e.status === 403 && e.message === "forbidden",
    );
  });

  test("postJson's contract is unchanged: every 2xx still decodes as the body", async () => {
    replyStatus = 202;
    replyBody = pendingBody;
    assert.deepStrictEqual(await postJson(url, "/auth/logout", {}, "tok"), pendingBody);
  });

  test("classifyApprovable refuses a 202 body with the wrong status or a missing field", () => {
    for (const body of [
      { ...pendingBody, status: "approved" },
      { ...pendingBody, approval_id: "" },
      { ...pendingBody, detail: undefined },
      null,
      "pending_approval",
    ]) {
      assert.throws(() => classifyApprovable(202, body), /pending-approval body/);
    }
  });

  test("the status decides, not the body: a 200 carrying a pending shape is DONE", () => {
    // The Python client (`_decode_approvable`) keys on the status the same way.
    assert.strictEqual(classifyApprovable(200, pendingBody).kind, "done");
  });

  test("a held body's server text is bounded before it reaches a notification", () => {
    const out = classifyApprovable(202, { ...pendingBody, detail: "x".repeat(5000) });
    assert.ok(out.kind === "held");
    assert.ok(out.pending.detail.length <= 201, "clamped to the error-detail bound");
  });
});
