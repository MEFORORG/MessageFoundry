// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Minimal HTTP client for the local MessageFoundry engine API. The IDE otherwise only shells out to
// the Python CLI; Stage → Promote is the one action that drives the *running* engine over HTTP. Uses
// the Node built-ins (no global `fetch` dependency, no npm deps) — same zero-dep style as cli.ts.
import * as http from "node:http";
import * as https from "node:https";

import { engineHostKey, trustRemedy } from "./engineTrustModel";

/** A non-2xx engine response. `status` lets callers branch (e.g. 401 → (re)authenticate). */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

/** Our own code for a request the engine accepted but never answered (see {@link GET_TIMEOUT_MS}).
 *  Distinct from Node's `ETIMEDOUT` (the TCP connect itself timing out) — "hung" and "unroutable" are
 *  different faults with different fixes, and the status bar names them differently. */
export const TIMEOUT_CODE = "MF_TIMEOUT";

/**
 * A transport-layer failure: no HTTP response at all. `code` carries Node's `ErrnoException.code`
 * (`ECONNREFUSED` / `ENOTFOUND` / `ECONNRESET` / `EPROTO` / `ETIMEDOUT` / a TLS `ERR_TLS_*`), or
 * {@link TIMEOUT_CODE} when our own read timeout fired.
 *
 * It exists so a caller can tell "nothing is listening" from "the name doesn't resolve" from "the
 * engine is hung" from "you spoke http to an https port" — every one of which used to arrive as the
 * same bare Error and rendered as one undifferentiated "unreachable". The message text is unchanged
 * from what the plain Error carried, so existing callers that only show `e.message` are unaffected.
 */
export class NetworkError extends Error {
  constructor(
    message: string,
    readonly code?: string,
  ) {
    super(message);
    this.name = "NetworkError";
  }
}

/**
 * The negotiated TLS floor for every https request this client makes.
 *
 * State the defect precisely, because the overstated version is wrong: Node has defaulted
 * `tls.DEFAULT_MIN_VERSION` to TLSv1.2 since Node 12, so this client was NOT negotiating TLS 1.0. What
 * it was doing is INHERITING a process-wide mutable default. `NODE_OPTIONS=--tls-min-v1.0` in the
 * environment VS Code is launched from lowers that default for the whole process, and every request
 * here silently followed it down — a security property of a credential-bearing client should not be
 * settable by an environment variable it never reads. Pinning it per-request costs nothing (it names
 * the value that was already in force) and removes the override.
 */
export const TLS_MIN_VERSION = "TLSv1.2";

/**
 * The TLS 1.2 suites every https request here offers, in preference order (BACKLOG #300).
 *
 * A COPY of `APPROVED_TLS12_SUITES` in the engine's `messagefoundry/config/tls_policy.py`, which is
 * the source of record. The engine's API listener offers exactly these by default, so this client
 * and the engine it talks to agree by construction. `tests/test_tls_default_suites.py` in the Python
 * suite reads this array and pins it to the engine's tuple, order included, so the two cannot drift.
 *
 * Owner ruling R4 of 2026-09-26 (BACKLOG #2042) took the three AES-128-GCM suites out, here and in
 * the engine. Measured with this list: a TLS 1.2 server offering only
 * `ECDHE-ECDSA-AES128-GCM-SHA256` is refused, and the unpinned control completed against it. That
 * held on Node 22.17.1 / OpenSSL 3.0.16 and on VS Code's own runtime, Electron 42.10.0.
 *
 * Whether the runtime offers all five is its own property: this pins names, and a TLS library that
 * lacks a suite drops it. None of the five is AES-128.
 */
export const TLS_12_SUITES: readonly string[] = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "DHE-RSA-AES256-GCM-SHA384",
];

/**
 * The TLS 1.3 suites named in the same `ciphers` string (ruling R4). A COPY of `APPROVED_TLS13_SUITES`
 * in `messagefoundry/config/tls_policy.py`, pinned to it by the same Python test.
 *
 * **Whether they take effect depends on where the extension host runs.** Measured with this list
 * against a TLS 1.3 server offering only `TLS_AES_128_GCM_SHA256`:
 *
 * - plain Node 22.17.1 / OpenSSL 3.0.16 REFUSES it, where the TLS 1.2 names alone completed. A
 *   remote extension host (Remote-SSH, WSL, dev containers) runs on plain Node.
 * - VS Code's desktop runtime, Electron 42.10.0 (BoringSSL), still COMPLETES on it. BoringSSL ignores
 *   TLS 1.3 names in `ciphers`, so on the desktop the IDE keeps offering that suite. It is a gap of
 *   the same kind as the engine's on CPython 3.14 (`narrow_tls13_suites` in `tls_policy.py`), but R4
 *   names only that one, so this one is recorded here rather than ruled on.
 *
 * Against a stock TLS 1.3 server, which is what a 3.14 engine is, the handshake completes with
 * these names present on both runtimes, so naming them refuses nothing a stock engine speaks.
 */
export const TLS_13_SUITES: readonly string[] = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
];

/** Both suite lists as the one OpenSSL cipher string Node's `ciphers` option takes. */
export const TLS_CIPHERS = TLS_12_SUITES.concat(TLS_13_SUITES).join(":");

/**
 * Extra trust anchors, keyed by `host:port` (see {@link engineHostKey}) — BACKLOG #1695.
 *
 * Module-level because a trust anchor is a property of a SERVER, not of one request: every caller
 * in this extension reaching a given engine needs the same one, and threading a `ca` argument
 * through `postJson`/`getJson` and their eight call sites would let one of them be forgotten.
 * Populated by `engineTrust.ts` from what the engine itself reports; empty until then, which is
 * exactly the previous behaviour (Node's default CA set alone).
 */
const trustAnchors = new Map<string, string>();

/** Register (or, with `undefined`, drop) the PEM to verify `url`'s engine with. */
export function setEngineTrustAnchor(url: string, pem: string | undefined): void {
  const key = engineHostKey(url);
  if (key === undefined) {
    return;
  }
  if (pem === undefined) {
    trustAnchors.delete(key);
  } else {
    trustAnchors.set(key, pem);
  }
}

/** Drop every registered anchor, and report whether there WAS one. `engineTrust.ts` calls this before
 *  each refresh, so a target the user edits away from does not leave its certificate registered for
 *  the life of the window. The return value is what tells that caller the trust state changed even
 *  when the refresh ends up registering nothing — dropping an anchor is a change worth re-probing. */
export function clearEngineTrustAnchors(): boolean {
  const had = trustAnchors.size > 0;
  trustAnchors.clear();
  return had;
}

/**
 * TLS options for `url`, empty for plain http (the loopback cleartext flow, where there is no
 * handshake to constrain and `assertTargetAllowed` separately refuses cleartext off-box).
 *
 * `ca`, when this engine has a registered anchor, is what lets the client verify the self-signed
 * certificate the engine mints on first run. It REPLACES Node's default bundle for that request,
 * which is safe here precisely because the anchor is the certificate that engine presents — and it
 * is why `rejectUnauthorized` is never touched. Verification stays on in every posture; the only
 * thing that changes is which anchors it may succeed against.
 *
 * The TLS 1.2 suites are pinned to {@link TLS_CIPHERS} (BACKLOG #300). This comment used to record
 * the opposite decision: no cipher list, so the client could track Node's upstream default and never
 * refuse a handshake a correctly configured proxy would complete. Two things changed. The engine now
 * serves exactly these suites by default, so pinning them refuses nothing a stock engine speaks. And
 * Node's default still offers the CBC-SHA2 suites the engine's allow-list excludes, so an unpinned
 * client kept offering them to the engine. The cost that argument named is real
 * and now paid on purpose: a TLS terminator in front of the engine that speaks only CBC suites will
 * fail the handshake, and the fix is on that terminator. The list names TLS 1.3 suites too, which
 * take effect on plain Node and not under the desktop's Electron; {@link TLS_13_SUITES} says more.
 */
export function tlsOptions(url: URL): https.RequestOptions {
  if (url.protocol !== "https:") {
    return {};
  }
  // engineHostKey on BOTH sides of the Map. Spelling the normalization inline here and calling the
  // helper in setEngineTrustAnchor would let a later change to one make every lookup silently miss.
  const key = engineHostKey(url.href);
  const ca = key === undefined ? undefined : trustAnchors.get(key);
  const base: https.RequestOptions = { minVersion: TLS_MIN_VERSION, ciphers: TLS_CIPHERS };
  return ca === undefined ? base : { ...base, ca };
}

/** Fold a Node request error into a {@link NetworkError}, preserving its errno. Shared by GET/POST so
 *  the two paths cannot drift (they had duplicate, subtly different branches before). */
function networkError(err: NodeJS.ErrnoException, baseUrl: string): NetworkError {
  // A certificate we cannot verify is NOT "not reachable": something answered, and telling the user
  // to start an engine that is already running is the failure BACKLOG #1695 records. Tested first
  // because it must never fall into the bucket below.
  const remedy = trustRemedy(err.code, baseUrl);
  if (remedy !== undefined) {
    return new NetworkError(remedy, err.code);
  }
  if (err.code === "ECONNREFUSED" || err.code === "ECONNRESET" || err.code === "ENOTFOUND") {
    return new NetworkError(
      `engine not reachable at ${baseUrl} — start it (Console or \`messagefoundry serve\`).`,
      err.code,
    );
  }
  return new NetworkError(`engine request failed: ${err.message}`, err.code);
}

/**
 * POST `body` as JSON to `<baseUrl><path>` and parse the JSON response.
 *
 * Pass `token` to send `Authorization: Bearer <token>` (the engine requires authentication). Throws
 * an {@link HttpError} (carrying the status) on any non-2xx response — surfacing FastAPI's
 * `{"detail": ...}` when present — and a plain Error when the engine is unreachable, so a caller's
 * try/catch shows a useful message and can special-case 401/403.
 *
 * Every 2xx decodes as `T`. A route dual control can hold answers 202 with a different body, so
 * call such a route through {@link postApprovable} instead.
 */
export function postJson<T>(
  baseUrl: string,
  route: string,
  body: unknown,
  token?: string,
): Promise<T> {
  return postReply(baseUrl, route, body, token).then((reply) => reply.body as T);
}

/**
 * The status the engine answers when dual control holds an action instead of running it (ADR 0041
 * D2, ASVS 2.3.5). The Python client keys on the same number (`_HTTP_PENDING_APPROVAL` in
 * `messagefoundry/apiclient/client.py`).
 */
export const HTTP_PENDING_APPROVAL = 202;

/** Mirrors `messagefoundry/api/models.py:PendingApprovalResponse`, the body of that 202. */
export interface PendingApproval {
  approval_id: string;
  operation: string;
  status: "pending_approval";
  detail: string;
}

/**
 * The outcome of a route dual control may hold: the finished result, or the hold. A tagged union,
 * so a caller has to check `kind` before it can read a result, and a hold can never be read as one.
 */
export type Approvable<T> = { kind: "done"; body: T } | { kind: "held"; pending: PendingApproval };

/**
 * Sort a decoded 2xx reply into done or held (BACKLOG #1981).
 *
 * The status is the discriminator, as it is in the Python client, because it is what the engine
 * varies. A 202 must also carry the pending-approval body: a 202 without one is neither a result nor
 * a hold the user can act on, so it throws rather than being read as success. The body's strings
 * are server text headed for a notification, so they are bounded like an error detail.
 */
export function classifyApprovable<T>(status: number, body: unknown): Approvable<T> {
  if (status !== HTTP_PENDING_APPROVAL) {
    return { kind: "done", body: body as T };
  }
  if (!isPendingApproval(body)) {
    throw new Error(
      `engine answered HTTP ${status} without a pending-approval body, so the outcome is unknown`,
    );
  }
  return {
    kind: "held",
    pending: {
      approval_id: clamp(body.approval_id),
      operation: clamp(body.operation),
      status: body.status,
      detail: clamp(body.detail),
    },
  };
}

function isPendingApproval(body: unknown): body is PendingApproval {
  if (body === null || typeof body !== "object") {
    return false;
  }
  const b = body as Record<string, unknown>;
  return (
    b.status === "pending_approval" &&
    typeof b.approval_id === "string" &&
    b.approval_id.length > 0 &&
    typeof b.operation === "string" &&
    typeof b.detail === "string"
  );
}

/**
 * POST to a route dual control may hold, and report whether it ran or was held.
 *
 * Same transport, errors and auth as {@link postJson}; only the 2xx handling differs. The engine's
 * holdable routes are `/config/reload`, `/dead-letters/replay` and `/connections/{name}/purge`.
 */
export function postApprovable<T>(
  baseUrl: string,
  route: string,
  body: unknown,
  token?: string,
): Promise<Approvable<T>> {
  return postReply(baseUrl, route, body, token).then((reply) =>
    classifyApprovable<T>(reply.status, reply.body),
  );
}

/** A decoded 2xx POST reply. The status is kept so {@link postApprovable} can tell a hold apart. */
interface PostReply {
  status: number;
  body: unknown;
}

function postReply(
  baseUrl: string,
  route: string,
  body: unknown,
  token?: string,
): Promise<PostReply> {
  return new Promise<PostReply>((resolve, reject) => {
    let url: URL;
    try {
      // Concatenate (not URL-resolve) so a base URL with a path prefix (e.g. a reverse-proxy
      // mount like https://gw/mf) is preserved — a leading-slash route would otherwise replace it.
      url = new URL(baseUrl.replace(/\/+$/, "") + route);
    } catch {
      reject(new Error(`invalid engine URL: ${baseUrl}`));
      return;
    }
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const headers: Record<string, string | number> = {
      "Content-Type": "application/json",
      "Content-Length": payload.byteLength,
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const transport = url.protocol === "https:" ? https : http;
    const options: https.RequestOptions = { method: "POST", headers, ...tlsOptions(url) };
    const req = transport.request(url, options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8").trim();
        const status = res.statusCode ?? 0;
        if (status >= 200 && status < 300) {
          try {
            resolve({ status, body: text ? (JSON.parse(text) as unknown) : {} });
          } catch {
            reject(new Error(`engine returned a non-JSON response (HTTP ${status})`));
          }
          return;
        }
        reject(new HttpError(status, httpErrorMessage(status, text)));
      });
    });
    req.on("error", (err: NodeJS.ErrnoException) => reject(networkError(err, baseUrl)));
    req.write(payload);
    req.end();
  });
}

/** Default GET timeout (ms). A hung engine (accepts the socket but never answers) must not leave the
 *  caller pending forever — the status-bar probe would then stick on "checking…" and leak the socket. */
export const GET_TIMEOUT_MS = 5000;

/**
 * GET `<baseUrl><route>` and parse the JSON response. Mirrors {@link postJson} (same unreachable /
 * non-2xx handling and FastAPI `{"detail": ...}` extraction) but sends no body — used for read-only
 * engine endpoints such as `/ai/policy` and the status-bar `/health` probe.
 *
 * A `timeoutMs` cap (default {@link GET_TIMEOUT_MS}) destroys a request that produces no response in
 * time, rejecting with a plain (non-{@link HttpError}) Error — so a hung engine classifies as a
 * transport failure (→ unreachable), exactly like a refused connection. `timeoutMs` is injectable so a
 * test can force the path fast; production callers omit it.
 */
export function getJson<T>(
  baseUrl: string,
  route: string,
  token?: string,
  timeoutMs: number = GET_TIMEOUT_MS,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let url: URL;
    try {
      // Concatenate (not URL-resolve) so a base URL with a path prefix (e.g. a reverse-proxy
      // mount like https://gw/mf) is preserved — a leading-slash route would otherwise replace it.
      url = new URL(baseUrl.replace(/\/+$/, "") + route);
    } catch {
      reject(new Error(`invalid engine URL: ${baseUrl}`));
      return;
    }
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
    const transport = url.protocol === "https:" ? https : http;
    const options: https.RequestOptions = { method: "GET", headers, ...tlsOptions(url) };
    const req = transport.request(url, options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8").trim();
        const status = res.statusCode ?? 0;
        if (status >= 200 && status < 300) {
          try {
            resolve((text ? JSON.parse(text) : {}) as T);
          } catch {
            reject(new Error(`engine returned a non-JSON response (HTTP ${status})`));
          }
          return;
        }
        reject(new HttpError(status, httpErrorMessage(status, text)));
      });
    });
    // Fail an unanswered request (hung engine) after the cap: destroy it with a NetworkError carrying
    // TIMEOUT_CODE → the 'error' handler below passes it straight through, so "hung" stays
    // distinguishable from "refused" instead of collapsing into the same unreachable bucket.
    req.setTimeout(timeoutMs, () =>
      req.destroy(new NetworkError(`engine request timed out after ${timeoutMs}ms`, TIMEOUT_CODE)),
    );
    req.on("error", (err: NodeJS.ErrnoException) =>
      reject(err instanceof NetworkError ? err : networkError(err, baseUrl)),
    );
    req.end();
  });
}

/** How much server-supplied error text may ride along in an Error message. Whatever is listening on that
 *  port is not necessarily our engine, and this text reaches a status-bar hover and a menu — so it is
 *  bounded here rather than trusted to be short. (It is never logged; see engineLog.) */
const MAX_DETAIL_CHARS = 200;

/** Pull FastAPI's `{"detail": "..."}` out of an error body, else fall back to status + raw text. */
function httpErrorMessage(status: number, text: string): string {
  if (text) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (
        parsed !== null &&
        typeof parsed === "object" &&
        typeof (parsed as { detail?: unknown }).detail === "string"
      ) {
        return clamp((parsed as { detail: string }).detail);
      }
    } catch {
      // not JSON — fall through to the raw text
    }
  }
  return `engine returned HTTP ${status}${text ? `: ${clamp(text)}` : ""}`;
}

function clamp(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > MAX_DETAIL_CHARS ? `${flat.slice(0, MAX_DETAIL_CHARS)}…` : flat;
}
