// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Vault BACKLOG #2625: the engine binds config reload (and five other routes) to a step-up proof
// minted for that action, so a fresh sign-in no longer opens it. These pin the IDE's answer: read
// the signal off the 403, prompt, POST /me/reauth with the named purpose, adopt the re-keyed token,
// retry once. Node-only (no vscode), so the `test:unit` leg runs them.
import * as assert from "assert";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import { HttpError, postApprovable, stepUpSignalOf } from "../../engineClient";
import {
  IdpStepUpRequiredError,
  STEP_UP_ATTEMPTS,
  type StepUpHost,
  withStepUp,
} from "../../stepUp";

const PASSWORD = "a-typed-password-never-echoed";

function refusal(action?: string, viaIdp = false): HttpError {
  return new HttpError(403, "step-up re-verification required", { action, viaIdp });
}

/** A host that records what it was asked, with a scripted prompt answer and rotated token. */
function fakeHost(answer: string | undefined, rotated: string | undefined) {
  const seen = {
    prompts: 0,
    reauths: [] as { token: string; password: string; purpose: string | undefined }[],
    stored: [] as string[],
  };
  const host: StepUpHost = {
    promptPassword: () => {
      seen.prompts += 1;
      return Promise.resolve(answer);
    },
    reauth: (token, password, purpose) => {
      seen.reauths.push({ token, password, purpose });
      return Promise.resolve(rotated);
    },
    storeToken: (token) => {
      seen.stored.push(token);
      return Promise.resolve();
    },
  };
  return { host, seen };
}

suite("stepUp — the signal on a 403 (vault BACKLOG #2625)", () => {
  test("an action-bound refusal carries its action", () => {
    const s = stepUpSignalOf(403, {
      "x-step-up-required": "1",
      "x-step-up-action": "config_reload",
    });
    assert.deepStrictEqual(s, { action: "config_reload", viaIdp: false });
  });

  test("a window refusal carries no action", () => {
    assert.deepStrictEqual(stepUpSignalOf(403, { "x-step-up-required": "1" }), {
      action: undefined,
      viaIdp: false,
    });
  });

  test("an IdP session is flagged", () => {
    const s = stepUpSignalOf(403, { "x-step-up-required": "1", "x-step-up-via": "idp" });
    assert.strictEqual(s?.viaIdp, true);
  });

  test("an action that is not an engine action id is dropped, never sent back", () => {
    const s = stepUpSignalOf(403, {
      "x-step-up-required": "1",
      "x-step-up-action": "config_reload\r\nX-Evil: 1",
    });
    assert.deepStrictEqual(s, { action: undefined, viaIdp: false });
  });

  test("control: a plain 403 and a non-403 carry no signal", () => {
    assert.strictEqual(stepUpSignalOf(403, {}), undefined);
    assert.strictEqual(stepUpSignalOf(401, { "x-step-up-required": "1" }), undefined);
  });

  test("a real POST refused with the headers rejects with the signal attached", async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(403, {
        "Content-Type": "application/json",
        "X-Step-Up-Required": "1",
        "X-Step-Up-Action": "config_reload",
      });
      res.end(JSON.stringify({ detail: "step-up re-verification required" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      await assert.rejects(
        () => postApprovable(url, "/config/reload", {}, "tok"),
        (e: unknown) =>
          e instanceof HttpError &&
          e.status === 403 &&
          e.stepUp?.action === "config_reload" &&
          !e.stepUp.viaIdp,
      );
    } finally {
      server.close();
    }
  });
});

suite("stepUp — withStepUp re-proves once and retries once (vault BACKLOG #2625)", () => {
  test("re-proves for the named action, adopts the re-keyed token, and retries with it", async () => {
    const { host, seen } = fakeHost(PASSWORD, "rotated");
    const used: string[] = [];
    const out = await withStepUp(
      "old",
      (token) => {
        used.push(token);
        return used.length === 1 ? Promise.reject(refusal("config_reload")) : Promise.resolve(42);
      },
      host,
    );
    assert.strictEqual(out, 42);
    assert.deepStrictEqual(used, ["old", "rotated"]);
    assert.deepStrictEqual(seen.reauths, [
      { token: "old", password: PASSWORD, purpose: "config_reload" },
    ]);
    assert.deepStrictEqual(seen.stored, ["rotated"]);
  });

  test("a window step-up re-proves with no purpose", async () => {
    const { host, seen } = fakeHost(PASSWORD, "rotated");
    let calls = 0;
    await withStepUp(
      "old",
      () => (++calls === 1 ? Promise.reject(refusal()) : Promise.resolve("ok")),
      host,
    );
    assert.strictEqual(seen.reauths[0].purpose, undefined);
  });

  test("a reply with no token keeps the current one and stores nothing", async () => {
    const { host, seen } = fakeHost(PASSWORD, undefined);
    const used: string[] = [];
    await withStepUp(
      "old",
      (token) => {
        used.push(token);
        return used.length === 1 ? Promise.reject(refusal("config_reload")) : Promise.resolve(1);
      },
      host,
    );
    assert.deepStrictEqual(used, ["old", "old"]);
    assert.deepStrictEqual(seen.stored, []);
  });

  test("a cancelled prompt sends nothing and resolves undefined", async () => {
    const { host, seen } = fakeHost(undefined, "rotated");
    const out = await withStepUp("old", () => Promise.reject(refusal("config_reload")), host);
    assert.strictEqual(out, undefined);
    assert.strictEqual(seen.reauths.length, 0);
  });

  test("a second refusal rejects instead of prompting again", async () => {
    const { host, seen } = fakeHost(PASSWORD, "rotated");
    await assert.rejects(
      () => withStepUp("old", () => Promise.reject(refusal("config_reload")), host),
      (e: unknown) => e instanceof HttpError && e.status === 403,
    );
    assert.strictEqual(seen.prompts, 1);
  });

  test("an IdP session is told where to step up, and no password is asked for", async () => {
    const { host, seen } = fakeHost(PASSWORD, "rotated");
    await assert.rejects(
      () => withStepUp("old", () => Promise.reject(refusal("config_reload", true)), host),
      (e: unknown) => e instanceof IdpStepUpRequiredError && /\/ui\/reauth/.test(e.message),
    );
    assert.strictEqual(seen.prompts, 0);
  });

  test("a wrong password re-asks, saying so, and the right one then goes through", async () => {
    const retries: boolean[] = [];
    let reauths = 0;
    const host: StepUpHost = {
      promptPassword: (_s, retry) => {
        retries.push(retry);
        return Promise.resolve(PASSWORD);
      },
      reauth: () =>
        ++reauths === 1
          ? Promise.reject(new HttpError(403, "re-verification failed"))
          : Promise.resolve("rotated"),
      storeToken: () => Promise.resolve(),
    };
    let calls = 0;
    const out = await withStepUp(
      "old",
      () => (++calls === 1 ? Promise.reject(refusal("config_reload")) : Promise.resolve("swapped")),
      host,
    );
    assert.strictEqual(out, "swapped");
    assert.deepStrictEqual(retries, [false, true]);
  });

  test("wrong passwords stop at the attempt cap, without the password in the error", async () => {
    let prompts = 0;
    const host: StepUpHost = {
      promptPassword: () => {
        prompts += 1;
        return Promise.resolve(PASSWORD);
      },
      reauth: () => Promise.reject(new HttpError(403, "re-verification failed")),
      storeToken: () => Promise.resolve(),
    };
    await assert.rejects(
      () => withStepUp("old", () => Promise.reject(refusal("config_reload")), host),
      (e: unknown) => e instanceof HttpError && e.status === 403 && !e.message.includes(PASSWORD),
    );
    assert.strictEqual(prompts, STEP_UP_ATTEMPTS);
  });

  test("a directory that could not judge the password is not reported as a wrong password", async () => {
    let prompts = 0;
    const host: StepUpHost = {
      promptPassword: () => {
        prompts += 1;
        return Promise.resolve(PASSWORD);
      },
      reauth: () =>
        Promise.reject(
          new HttpError(
            403,
            "the directory could not confirm this account; try again later, or ask an administrator",
          ),
        ),
      storeToken: () => Promise.resolve(),
    };
    await assert.rejects(
      () => withStepUp("old", () => Promise.reject(refusal("config_reload")), host),
      (e: unknown) => e instanceof HttpError && /directory/.test(e.message),
    );
    assert.strictEqual(prompts, 1);
  });

  test("a re-proof refused for a reason a password cannot fix is not re-asked", async () => {
    let prompts = 0;
    const host: StepUpHost = {
      promptPassword: () => {
        prompts += 1;
        return Promise.resolve(PASSWORD);
      },
      reauth: () => Promise.reject(new HttpError(401, "session ended; sign in again")),
      storeToken: () => Promise.resolve(),
    };
    await assert.rejects(
      () => withStepUp("old", () => Promise.reject(refusal("config_reload")), host),
      (e: unknown) => e instanceof HttpError && e.status === 401,
    );
    assert.strictEqual(prompts, 1);
  });

  test("control: any other error passes through untouched, with no prompt", async () => {
    const { host, seen } = fakeHost(PASSWORD, "rotated");
    const other = new HttpError(422, "bad config");
    await assert.rejects(
      () => withStepUp("old", () => Promise.reject(other), host),
      (e: unknown) => e === other,
    );
    assert.strictEqual(seen.prompts, 0);
  });
});
