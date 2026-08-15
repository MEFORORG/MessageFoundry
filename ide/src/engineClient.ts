// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// Minimal HTTP client for the local MessageFoundry engine API. The IDE otherwise only shells out to
// the Python CLI; Stage → Promote is the one action that drives the *running* engine over HTTP. Uses
// the Node built-ins (no global `fetch` dependency, no npm deps) — same zero-dep style as cli.ts.
import * as http from "node:http";
import * as https from "node:https";

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

/** Fold a Node request error into a {@link NetworkError}, preserving its errno. Shared by GET/POST so
 *  the two paths cannot drift (they had duplicate, subtly different branches before). */
function networkError(err: NodeJS.ErrnoException, baseUrl: string): NetworkError {
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
 */
export function postJson<T>(
  baseUrl: string,
  route: string,
  body: unknown,
  token?: string,
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
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const headers: Record<string, string | number> = {
      "Content-Type": "application/json",
      "Content-Length": payload.byteLength,
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(url, { method: "POST", headers }, (res) => {
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
    const req = transport.request(url, { method: "GET", headers }, (res) => {
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
