// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// Engine-target host policy, shared by promote.ts and auth.ts so the loopback host list and the
// non-TLS refusal live in ONE place (a divergent list would be a SSRF/credential-exfil gap).
// Complements the machine-scoping of messagefoundry.engineUrl/environments (SEC-005, CWE-918): scope
// stops a checked-in workspace settings file from silently retargeting promote, and these guards stop
// an explicitly-set/typed malicious target from receiving credentials and a bearer token in clear.

/** True if `url`'s host is loopback — only then does the IDE's local config path mean anything to the
 *  engine (a remote engine reads its own filesystem — review M-29), and only loopback is allowed to
 *  receive credentials over plain http://. */
export function isLocalEngine(url: string): boolean {
  try {
    // URL.hostname keeps IPv6 literals bracketed ("[::1]"), so strip the brackets before comparing.
    const host = new URL(url).hostname.replace(/^\[|\]$/g, "");
    return host === "127.0.0.1" || host === "localhost" || host === "::1";
  } catch {
    return false; // unparseable → treat as remote (the safe choice)
  }
}

export type TargetCheck = { ok: true } | { ok: false; reason: string };

/**
 * The ONLY schemes an engine URL may carry. A positive allow-list, deliberately: every check in this
 * file used to be a deny-list, and a deny-list of URL schemes cannot be written — the OS handler
 * registry is open-ended, so the set to refuse is unbounded and unknowable. `javascript:`, `file:`,
 * `data:` and every registered application handler (`ms-msdt:` being the well-known example) all
 * passed the host rules below unchallenged, because those rules only ever asked about `http:`.
 */
const ALLOWED_URL_SCHEMES: readonly string[] = ["http:", "https:"];

/** Parse `url` and refuse any scheme outside {@link ALLOWED_URL_SCHEMES}. Shared by both gates below
 *  so the allow-list has exactly one definition. */
function parseAllowedScheme(url: string): { parsed: URL } | { reason: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { reason: `not a valid engine URL: ${url}` };
  }
  if (!ALLOWED_URL_SCHEMES.includes(parsed.protocol)) {
    return {
      reason: `refusing a ${parsed.protocol} URL — only http:// and https:// are accepted: ${url}`,
    };
  }
  return { parsed };
}

/**
 * Gate a promote/login target before any credential prompt or token send. Refuses:
 *   - an unparseable URL (fail-safe),
 *   - any scheme outside the allow-list above, and
 *   - plain `http://` to a NON-loopback host (credentials/token would go in clear off-box).
 * Loopback over http stays allowed (the default 127.0.0.1 dev flow). A non-loopback https target is
 * allowed here; the caller additionally surfaces an explicit confirmation naming the host.
 */
export function assertTargetAllowed(url: string): TargetCheck {
  const screened = parseAllowedScheme(url);
  if ("reason" in screened) {
    return { ok: false, reason: screened.reason };
  }
  if (screened.parsed.protocol === "http:" && !isLocalEngine(url)) {
    return {
      ok: false,
      reason:
        `refusing to send credentials over plain http:// to non-loopback host ${screened.parsed.hostname} — use https://`,
    };
  }
  return { ok: true };
}

/**
 * Gate a URL before it is handed to `vscode.env.openExternal`, which routes to the OS handler and so
 * can launch an application, not just a browser.
 *
 * Separate from {@link assertTargetAllowed} because the two answer different questions. That gate
 * refuses cleartext off-box because CREDENTIALS would cross the wire; merely opening a console page
 * sends none, so applying it here would refuse a legitimate off-box http console for a reason that
 * does not hold. What both must refuse is the scheme, which is why that half is shared.
 */
export function assertBrowsableUrl(url: string): TargetCheck {
  const screened = parseAllowedScheme(url);
  return "reason" in screened ? { ok: false, reason: screened.reason } : { ok: true };
}
