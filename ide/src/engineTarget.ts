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
 * Gate a promote/login target before any credential prompt or token send. Refuses:
 *   - an unparseable URL (fail-safe), and
 *   - plain `http://` to a NON-loopback host (credentials/token would go in clear off-box).
 * Loopback over http stays allowed (the default 127.0.0.1 dev flow). A non-loopback https target is
 * allowed here; the caller additionally surfaces an explicit confirmation naming the host.
 */
export function assertTargetAllowed(url: string): TargetCheck {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: `not a valid engine URL: ${url}` };
  }
  if (parsed.protocol === "http:" && !isLocalEngine(url)) {
    return {
      ok: false,
      reason:
        `refusing to send credentials over plain http:// to non-loopback host ${parsed.hostname} — use https://`,
    };
  }
  return { ok: true };
}
