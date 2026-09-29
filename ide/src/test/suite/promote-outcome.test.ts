// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import {
  preflightOutcome,
  promoteOutcomeMessage,
  reloadConfig,
  type ReloadResult,
} from "../../promoteOutcome";

// BACKLOG #1981 — the promote apply step against a real socket. Where dual control holds
// config_reload, the engine answers 202 with a PendingApprovalResponse, and the promote used to
// announce "promoted ... live graph: undefined inbound". This drives both replies through the same
// request and message code promote.ts calls, with no vscode, so it runs on every test:unit leg.
suite("promote outcome — a held reload is reported as held (BACKLOG #1981)", () => {
  let server: http.Server;
  let url: string;
  let replyStatus = 200;
  let replyBody: unknown = {};
  let sent: unknown;
  let route: string | undefined;

  const pendingBody = {
    approval_id: "7c1e2d3f4a5b46c7980a1b2c3d4e5f60",
    operation: "config_reload",
    status: "pending_approval",
    detail: "held for a second approver (dual-control)",
  };
  const live: ReloadResult = {
    inbound: 2,
    outbound: 3,
    routers: 1,
    handlers: 4,
    running: true,
    dry_run: false,
  };

  setup(async () => {
    replyStatus = 200;
    replyBody = {};
    sent = undefined;
    route = undefined;
    server = http.createServer((req, res) => {
      route = req.url;
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        sent = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        res.writeHead(replyStatus, { "Content-Type": "application/json" });
        res.end(JSON.stringify(replyBody));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    url = `http://127.0.0.1:${addr.port}`;
  });

  teardown(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("a 202 hold yields a WARNING naming the approval id and saying the config is not live", async () => {
    replyStatus = 202;
    replyBody = pendingBody;
    const outcome = await reloadConfig(url, "/cfg", false, "tok");
    assert.strictEqual(route, "/config/reload");
    assert.deepStrictEqual(sent, { config_dir: "/cfg", dry_run: false });

    const msg = promoteOutcomeMessage("PROD", outcome);
    assert.strictEqual(msg.level, "warning");
    assert.ok(msg.text.includes("held for a second approver"), msg.text);
    assert.ok(msg.text.includes(pendingBody.approval_id), msg.text);
    assert.ok(msg.text.includes("NOT live"), msg.text);
    // The defect's own symptoms: the success wording and the graph counts must not appear.
    assert.ok(!msg.text.includes("promoted to"), msg.text);
    assert.ok(!msg.text.includes("undefined"), msg.text);
    assert.ok(!/live graph/.test(msg.text), msg.text);
  });

  test("control: a 200 result still reports success with the live graph counts", async () => {
    replyStatus = 200;
    replyBody = live;
    const msg = promoteOutcomeMessage("PROD", await reloadConfig(url, null, false, "tok"));
    assert.deepStrictEqual(sent, { config_dir: null, dry_run: false });
    assert.strictEqual(msg.level, "info");
    assert.strictEqual(
      msg.text,
      "MessageFoundry: promoted to PROD — live graph: 2 inbound, 3 outbound, 1 routers, " +
        "4 handlers, running.",
    );
  });

  test("the dry-run pre-flight still decodes as a normal result the promote confirms", async () => {
    replyStatus = 200;
    replyBody = { ...live, dry_run: true };
    const outcome = await reloadConfig(url, "/cfg", true, "tok");
    assert.deepStrictEqual(sent, { config_dir: "/cfg", dry_run: true });
    assert.deepStrictEqual(outcome, { kind: "done", body: { ...live, dry_run: true } });
    assert.deepStrictEqual(preflightOutcome(outcome), {
      ok: true,
      result: { ...live, dry_run: true },
    });
  });

  test("a held pre-flight stops the promote with an ERROR naming the approval to reject", async () => {
    replyStatus = 202;
    replyBody = pendingBody;
    const pre = preflightOutcome(await reloadConfig(url, "/cfg", true, "tok"));
    assert.ok(!pre.ok, "a held dry run must not reach the confirm step");
    assert.strictEqual(pre.message.level, "error");
    assert.ok(pre.message.text.includes("pre-flight failed"), pre.message.text);
    assert.ok(pre.message.text.includes(pendingBody.approval_id), pre.message.text);
    assert.ok(pre.message.text.includes("reject"), pre.message.text);
  });

  test("a 2xx that is not a reload result is an ERROR, never 'promoted' with undefined counts", async () => {
    replyStatus = 200;
    replyBody = {};
    const outcome = await reloadConfig(url, null, false, "tok");
    const msg = promoteOutcomeMessage("PROD", outcome);
    assert.strictEqual(msg.level, "error");
    assert.ok(msg.text.includes("unknown whether the new config is live"), msg.text);
    assert.ok(!msg.text.includes("undefined"), msg.text);
    const pre = preflightOutcome(outcome);
    assert.ok(!pre.ok, "the pre-flight must not confirm a graph it never saw");
    assert.strictEqual(pre.message.level, "error");
  });

  test("a hold whose body carries no usable id still says HELD, and says the id is missing", async () => {
    replyStatus = 202;
    replyBody = {};
    const msg = promoteOutcomeMessage("PROD", await reloadConfig(url, null, false, "tok"));
    assert.strictEqual(msg.level, "warning");
    assert.ok(msg.text.includes("held for a second approver"), msg.text);
    assert.ok(msg.text.includes("did not report an approval id"), msg.text);
    assert.ok(!msg.text.includes("undefined"), msg.text);
  });
});
