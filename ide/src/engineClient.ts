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
    req.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED" || err.code === "ECONNRESET" || err.code === "ENOTFOUND") {
        reject(new Error(`engine not reachable at ${baseUrl} — start it (Console or \`messagefoundry serve\`).`));
      } else {
        reject(new Error(`engine request failed: ${err.message}`));
      }
    });
    req.write(payload);
    req.end();
  });
}

/**
 * GET `<baseUrl><route>` and parse the JSON response. Mirrors {@link postJson} (same unreachable /
 * non-2xx handling and FastAPI `{"detail": ...}` extraction) but sends no body — used for read-only
 * engine endpoints such as `/ai/policy`.
 */
export function getJson<T>(baseUrl: string, route: string, token?: string): Promise<T> {
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
    req.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED" || err.code === "ECONNRESET" || err.code === "ENOTFOUND") {
        reject(new Error(`engine not reachable at ${baseUrl} — start it (Console or \`messagefoundry serve\`).`));
      } else {
        reject(new Error(`engine request failed: ${err.message}`));
      }
    });
    req.end();
  });
}

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
        return (parsed as { detail: string }).detail;
      }
    } catch {
      // not JSON — fall through to the raw text
    }
  }
  return `engine returned HTTP ${status}${text ? `: ${text}` : ""}`;
}
