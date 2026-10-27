// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure (vscode-free, I/O-free) logic for trusting the engine's TLS certificate — BACKLOG #1695.
//
// WHY THIS EXISTS. Since ADR 0172 the engine ALWAYS serves TLS, minting a self-signed certificate
// beside its store when no operator chain is configured. That certificate is in nobody's trust
// store, so the extension's https request failed with DEPTH_ZERO_SELF_SIGNED_CERT and its http
// default failed with ECONNRESET — reported as "engine not reachable … start it" while the engine
// was running. The fix is to read the certificate the engine says it presents and hand it to Node
// as the request's `ca`.
//
// TWO THINGS THIS MODULE DELIBERATELY DOES NOT DO, because each was a way of getting it wrong:
//   * it does not parse the service TOML, and it does not know the generated file's name or that it
//     lands beside `[store].path`. Those are ENGINE facts; `messagefoundry cert inventory --json`
//     reports them, and a copy here is a copy that drifts (the engine's own tray predicate had to be
//     repaired once for exactly that, BACKLOG #1126).
//   * it never decides that the engine speaks https. It reads the scheme the engine reports. A
//     client that hardcodes https breaks the one topology where the engine deliberately mints
//     nothing: `[api].tls_terminated_upstream`, a reverse proxy holding the protected hop and
//     speaking plaintext behind it.

// `node:path` only — pure string algebra over separators, so this module stays I/O-free. It is
// platform-aware, which is exactly right here: the only anchor it will resolve belongs to an engine
// on THIS machine (see `trustAnchorForTarget`). `join`/`normalize` and NOT `resolve`, deliberately —
// `path.resolve` reads `process.cwd()` (and, on win32, the per-drive cwd in `process.env['=D:']`)
// whenever its arguments do not settle the root between them, which is the very read this module
// must not make.
import * as path from "node:path";

import { isLocalEngine } from "./engineTarget";

/** The `api_tls` object of `messagefoundry cert inventory --service-config … --json`. */
export interface ApiTlsFacts {
  /** The scheme the engine's own bind serves. `http` ONLY for a declared upstream terminator. */
  scheme: "http" | "https";
  /** Where the certificate comes from — the engine's own three-way answer. */
  source: "operator" | "generated" | "upstream";
  /** Path to the certificate the bind will present. Absent for `upstream`, and present-but-not-yet-
   *  on-disk for a `generated` pair the engine has not minted (it mints on its first run). */
  cert?: string;
  certPresent: boolean;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Read the `api_tls` object out of a `cert inventory --json` payload, or `undefined`.
 *
 * Validating rather than casting, for two reasons that both bite in practice: the extension shells
 * whatever `messagefoundry` is on PATH, so an OLDER engine answers with no `api_tls` key at all and
 * must degrade silently; and the value steers a TLS decision, so a malformed one must fall back to
 * "we learned nothing" instead of half-configuring the client.
 */
export function parseApiTls(raw: unknown): ApiTlsFacts | undefined {
  if (!isRecord(raw) || !isRecord(raw.api_tls)) {
    return undefined;
  }
  const api = raw.api_tls;
  const scheme = api.scheme;
  const source = api.source;
  if (scheme !== "http" && scheme !== "https") {
    return undefined;
  }
  if (source !== "operator" && source !== "generated" && source !== "upstream") {
    return undefined;
  }
  const cert = typeof api.cert === "string" && api.cert ? api.cert : undefined;
  return { scheme, source, cert, certPresent: cert !== undefined && api.cert_present === true };
}

/**
 * The certificate file to hand Node as `ca`, or `undefined` for "trust nothing extra".
 *
 * **Both TLS sources are anchored, not just the minted one.** Node's `ca` REPLACES its default
 * bundle for that request, and the file named here is the very certificate the server presents — so
 * verification succeeds whether it is a self-signed leaf or a full operator chain, and in neither
 * case does the extension become more trusting of anything else. Anchoring only the generated pair
 * would leave an internal-CA deployment failing for a reason the extension could have fixed.
 *
 * `upstream` yields nothing because there is no engine-terminated handshake to verify.
 */
export function trustAnchorFor(facts: ApiTlsFacts | undefined): string | undefined {
  if (facts === undefined || facts.scheme !== "https" || !facts.certPresent) {
    return undefined;
  }
  return facts.cert;
}

/**
 * What to anchor for a target, and — when the answer is "nothing" — which of the two reasons it was.
 *
 * Three cases rather than an optional path, because the caller has to tell them apart to say anything
 * useful: `nothing` is the ordinary quiet outcome (no engine, not minted yet, an upstream
 * terminator), while `notLocal` means the engine DID name a usable certificate and we declined it.
 * Returning `undefined` for both forced the shell to re-derive the reason, and it derived it wrong.
 */
export type TrustAnchorDecision =
  | { readonly kind: "anchor"; readonly file: string }
  | { readonly kind: "notLocal" }
  | { readonly kind: "nothing" };

/**
 * Whether the certificate this engine reports may be anchored for `url`, and where that file is.
 *
 * {@link trustAnchorFor} answers only *does this engine present an anchorable certificate*. This
 * function answers the question the caller actually has — *may we anchor it for THIS target, and
 * where is the file* — and it exists because a shell that computed the two halves separately was free
 * to pair the wrong ones, which is what it did.
 *
 * **IT REFUSES A NON-LOOPBACK TARGET.** The facts come from `messagefoundry.serviceConfig`, a
 * workspace-relative path to the LOCAL engine's settings; a remote engine reads its own filesystem,
 * so that file describes a DIFFERENT server. Handing its certificate to a remote target is not a
 * harmless extra anchor: `tlsOptions` passes it as `ca`, which REPLACES Node's default root store for
 * that request, so a remote engine on a perfectly valid public chain stops verifying. This is the
 * same boundary {@link trustRemedy} branches on and the same one `engineTarget.ts` states.
 *
 * **WHAT THAT COSTS, because it is a real narrowing and not a free win.** `isLocalEngine` is three
 * host spellings, so an engine running on THIS machine but dialled by its hostname or its LAN address
 * — legitimate, and its minted SAN is `[api].host`, so the certificate would have verified — now gets
 * no anchor and fails with `DEPTH_ZERO_SELF_SIGNED_CERT`. That is the deliberate trade: the extension
 * cannot tell a local engine addressed by hostname from a remote one, `messagefoundry.serviceConfig`
 * describes only the former, and guessing wrong in the permissive direction is what broke remote
 * engines. The shell says so in the log rather than failing silently.
 *
 * **IT IS PORT-BLIND, and that residue is NOT closed here.** `isLocalEngine` asks only about the
 * host, so an anchor read for the engine on `127.0.0.1:8765` is still installed for a DIFFERENT local
 * engine on `127.0.0.1:9999`. Closing it needs the engine to report which bind the facts describe;
 * `cert inventory --json` emits only scheme/source/cert/cert_present, so there is nothing here to
 * compare against. Strictly smaller than the defect above — both engines are on this machine and the
 * user configured both — but it is a residue, not an absence.
 *
 * **IT RESOLVES A RELATIVE PATH AGAINST `workspaceDir`.** The engine passes an operator's
 * `[api].tls_cert_file` through unchanged (`plan_api_tls_material`), so `certs/server.pem` arrives
 * verbatim. `workspaceDir` is not a guess about what it means: `cert inventory` was run with that
 * directory as its cwd and stat-ed `cert_present` against it, so resolving there reads exactly the
 * file the engine reported. Leaving it relative hands it to `fs.openSync`, which resolves against the
 * EXTENSION HOST's cwd instead — a different directory, where the read fails and the anchor is
 * silently never installed even though inventory said the certificate was there.
 *
 * `workspaceDir` must be absolute (it comes from `Uri.fsPath`). An already-absolute anchor is
 * normalized and otherwise untouched, which is what the generated pair beside `[store].path` needs.
 */
export function trustAnchorForTarget(
  facts: ApiTlsFacts | undefined,
  url: string,
  workspaceDir: string,
): TrustAnchorDecision {
  const anchor = trustAnchorFor(facts);
  if (anchor === undefined) {
    return { kind: "nothing" };
  }
  if (!isLocalEngine(url)) {
    return { kind: "notLocal" };
  }
  // join/normalize, never `path.resolve` — see the import note. A win32 drive-relative anchor
  // (`D:certs\server.pem`) is the case that separates them: `resolve` would drop `workspaceDir` and
  // fall back to that drive's cwd, re-creating the very read this function exists to remove. Joined,
  // it yields a path under the workspace that simply does not exist, so the read fails and the shell
  // names the file it could not open.
  return {
    kind: "anchor",
    file: path.isAbsolute(anchor) ? path.normalize(anchor) : path.join(workspaceDir, anchor),
  };
}

/**
 * The map key an anchor is filed under: `host:port`, lower-cased, scheme-free.
 *
 * Scheme-free on purpose. The key answers "which server is this?", and a target does not become a
 * different server because one caller spelled it `http://`. Keying by full origin would file the
 * anchor under the scheme that cannot use it and silently never apply it.
 */
export function engineHostKey(url: string): string | undefined {
  try {
    return new URL(url).host.toLowerCase() || undefined;
  } catch {
    return undefined;
  }
}

/** True when `url` parses and its scheme is `https:`. The one definition the pin pass and the
 *  unanchored-target warning share, so they cannot disagree about a URL. */
export function isHttpsUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Node error codes meaning "the handshake completed but I do not trust who signed this".
 *
 * A closed list of the OpenSSL verify failures the engine's own postures can produce. Kept apart
 * from CERT_HAS_EXPIRED and ERR_TLS_CERT_ALTNAME_INVALID, which are also verification failures but
 * have DIFFERENT remedies — an expired certificate is re-minted, a name mismatch is a wrong host in
 * the URL, and neither is fixed by pointing the extension at a trust anchor.
 */
export const TLS_TRUST_CODES: readonly string[] = [
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_UNTRUSTED",
];

/** True when `code` is one of {@link TLS_TRUST_CODES}. */
export function isTlsTrustError(code: string | undefined): boolean {
  return code !== undefined && TLS_TRUST_CODES.includes(code);
}

/**
 * The one sentence a user can act on after a trust failure, or `undefined` when the code is not one.
 *
 * The remote remedy names `caFile` first because it is the one fix that needs no administrator: it is
 * a machine-scoped user setting (see {@link trustPinsFor}). Whether a CA imported into the OS store
 * reaches this client is READ, not measured (BACKLOG #1695, closing step 4). The `@vscode/proxy-agent`
 * 0.45.0 that VS Code 1.142.0 bundles adds the OS store under `http.systemCertificates` only when
 * the request carries NO `ca` of its own (both its `addCertificatesV1` request patch and its V2
 * `tls.connect` patch return early on a caller's `ca`). So an unpinned target should verify against
 * an OS-store CA, and a pinned or locally anchored one never does — its `ca` is the whole trust set.
 *
 * **It branches on locality, and that is not a nicety.** The anchor comes from
 * `messagefoundry.serviceConfig`, a workspace-relative path to the LOCAL engine's settings — a
 * remote engine reads its own filesystem, so that file says nothing about the certificate a remote
 * host just presented. Naming it there would send the user to fix a file with no bearing on the
 * engine they dialled. See `engineTarget.ts` for the same boundary on the credential side.
 */
export function trustRemedy(code: string | undefined, url: string): string | undefined {
  if (!isTlsTrustError(code)) {
    return undefined;
  }
  const head = `cannot verify the TLS certificate ${url} presented (${code}).`;
  return isLocalEngine(url)
    ? `${head} The engine mints a self-signed certificate when no chain is configured, and the ` +
        `extension trusts it by reading the engine's own service TOML — check that ` +
        `\`messagefoundry.serviceConfig\` names it, and that the engine has started at least once ` +
        `so the certificate exists.`
    : `${head} The extension can only learn a LOCAL engine's certificate (from ` +
        `\`messagefoundry.serviceConfig\`), so a remote engine's must be trusted by this machine — ` +
        `set \`caFile\` on its \`messagefoundry.environments\` entry to its issuing CA, install that ` +
        `CA in the system trust store, or front it with a publicly-trusted chain.`;
}

/**
 * A sentence naming a scheme disagreement between the configured URL and the engine, else `undefined`.
 *
 * The extension does NOT rewrite `messagefoundry.engineUrl` to resolve it. That setting is
 * machine-scoped for an SSRF reason (SEC-005, CWE-918), and a client that edits its own target on
 * evidence read from a subprocess is the same class of move the scoping exists to prevent. Say what
 * disagrees; the user changes it.
 */
export function schemeMismatch(facts: ApiTlsFacts | undefined, url: string): string | undefined {
  if (facts === undefined) {
    return undefined;
  }
  let configured: string;
  try {
    configured = new URL(url).protocol === "https:" ? "https" : "http";
  } catch {
    return undefined;
  }
  if (configured === facts.scheme) {
    return undefined;
  }
  return facts.scheme === "https"
    ? `messagefoundry.engineUrl is http:// but this engine serves https:// — change the setting to https://`
    : `messagefoundry.engineUrl is https:// but this engine declares tls_terminated_upstream and serves plaintext behind its proxy — change the setting to http://, or point it at the proxy`;
}

/**
 * One engine a `messagefoundry.environments` entry names, as the pin pass reads it: the entry's own
 * `url`, or one of its engine shards' (BACKLOG #1695, residual a).
 *
 * `caFile` is `unknown` because it arrives from a settings file nothing has type-checked.
 */
export interface PinTarget {
  readonly url: string;
  readonly caFile?: unknown;
}

/** An environment entry as `cli.ts` returns it, reduced to what the pin pass needs. */
export interface PinnableEnvironment extends PinTarget {
  readonly shards?: readonly PinTarget[];
}

/**
 * Every engine the configured environments name, each with the `caFile` that applies to it.
 *
 * An engine shard takes its own `caFile` when it sets one and its environment's otherwise: the
 * engine shards of one environment are instances of one deployment, which normally share an issuing
 * CA. When they do not
 * (each serving its own self-signed leaf), the inherited file fails verification and the request
 * says so; it never widens what is trusted.
 */
export function pinTargetsOf(envs: readonly PinnableEnvironment[]): PinTarget[] {
  const out: PinTarget[] = [];
  for (const env of envs) {
    out.push({ url: env.url, caFile: env.caFile });
    for (const shard of env.shards ?? []) {
      // "" inherits like an absent key, as trustPinsFor reads "" as "no caFile"; it is not an opt-out.
      const own = shard.caFile === "" ? undefined : shard.caFile;
      out.push({ url: shard.url, caFile: own ?? env.caFile });
    }
  }
  return out;
}

/**
 * What the pin pass decided for one target that named a `caFile`.
 *
 * A refusal still CLAIMS its host (`claims`, the host key) when the target is https: the user meant
 * to pin that host, so a broken pin must leave it unanchored rather than hand it to the certificate a
 * workspace setting names. An `http://` target claims nothing. Host keys carry no scheme, so a claim
 * there would take the anchor from an https engine on the same `host:port`, and plain http has no
 * handshake to pin anyway.
 */
export type TrustPin =
  | { readonly kind: "pin"; readonly url: string; readonly key: string; readonly file: string }
  | {
      readonly kind: "refused";
      readonly url: string;
      readonly reason: string;
      readonly claims: string | undefined;
    };

/** The two path flavours {@link isFullyQualifiedPath} distinguishes; `node:path` itself is one. */
type PathFlavour = Pick<typeof path, "sep" | "isAbsolute" | "normalize">;

/**
 * True when `file` names one file whatever the process cwd is.
 *
 * Stricter than `path.isAbsolute` on Windows, on purpose. `path.win32.isAbsolute` accepts
 * `\certs\ca.pem`, which is ROOT-relative: Windows reads it on the drive of the current directory,
 * so the same setting could name a different file in a different process. Only a drive-letter path
 * (`C:\…`) or a UNC path (`\\server\share\…`) is accepted there.
 */
export function isFullyQualifiedPath(file: string, flavour: PathFlavour = path): boolean {
  if (flavour.sep === "\\") {
    // `[^\\/.?]` after the two separators refuses the device namespaces `\\.\` and `\\?\`. A device
    // such as `\\.\pipe\x` is not a file. This is a first screen only: a named pipe reached by a UNC
    // host name (`\\localhost\pipe\x`) passes it, and the shell's reader refuses any descriptor that
    // is not a regular file, though on Windows the open itself may already have blocked.
    return /^[A-Za-z]:[\\/]/.test(file) || /^[\\/]{2}[^\\/.?]/.test(file);
  }
  return flavour.isAbsolute(file);
}

/**
 * Which configured targets get an explicit trust anchor, and which `caFile` values are refused.
 *
 * A target with no `caFile` yields NOTHING, not a refusal: that is the ordinary case, a target on a
 * publicly trusted chain or one whose CA is in the machine's trust store.
 *
 * **Why a pin is an explicit per-target file and not trust-on-first-use.** The setting holding it,
 * `messagefoundry.environments`, is machine-scoped (SEC-005), so a checked-in workspace settings file
 * cannot add a pin, and nothing here asks the user to accept a certificate by clicking. A pin can
 * only make verification succeed against the file the user named. It never turns verification off,
 * and Node's `ca` REPLACES the default roots for that request, so the pinned target stops trusting
 * the public roots too. That is the point of a pin.
 *
 * Each refusal is a value the shell logs, because a pin that silently does nothing fails later with
 * an unexplained trust error:
 *   * a `caFile` that is not a non-empty string;
 *   * a path that is not fully qualified (see {@link isFullyQualifiedPath}). A relative path would be
 *     read against the workspace or the extension host's cwd, and a workspace is exactly what the
 *     machine scope keeps out of this decision;
 *   * a URL that does not parse, or is not `https:` — plain http has no handshake to anchor;
 *   * a second, DIFFERENT file for a `host:port` an earlier entry already pinned. Anchors are filed by
 *     `host:port` ({@link engineHostKey}), so two files cannot both apply; the first one stays, and
 *     the same file named twice (an engine shard repeating its environment's URL) is not a conflict.
 */
export function trustPinsFor(
  targets: readonly PinTarget[],
  flavour: PathFlavour = path,
): TrustPin[] {
  const out: TrustPin[] = [];
  const byKey = new Map<string, string>();
  for (const { url, caFile } of targets) {
    if (caFile === undefined || caFile === null || caFile === "") {
      continue;
    }
    const parsed = engineHostKey(url);
    const key = parsed !== undefined && isHttpsUrl(url) ? parsed : undefined;
    if (typeof caFile !== "string") {
      out.push({ kind: "refused", url, reason: "caFile is not a string", claims: key });
      continue;
    }
    if (!isFullyQualifiedPath(caFile, flavour)) {
      out.push({
        kind: "refused",
        url,
        claims: key,
        reason:
          flavour.sep === "\\"
            ? `caFile ${caFile} is not a full path (on Windows: a drive-letter or UNC path)`
            : `caFile ${caFile} is not an absolute path`,
      });
      continue;
    }
    if (key === undefined) {
      out.push({
        kind: "refused",
        url,
        reason: "caFile applies only to an https:// url",
        claims: undefined,
      });
      continue;
    }
    const file = flavour.normalize(caFile);
    const earlier = byKey.get(key);
    if (earlier !== undefined) {
      // Windows paths are case-insensitive, so C:\PKI\ca.pem and c:\pki\ca.pem are one file.
      const same =
        flavour.sep === "\\" ? earlier.toLowerCase() === file.toLowerCase() : earlier === file;
      if (!same) {
        out.push({
          kind: "refused",
          url,
          reason: `${key} is already pinned to ${earlier} by an earlier entry`,
          claims: key,
        });
      }
      continue;
    }
    byKey.set(key, file);
    out.push({ kind: "pin", url, key, file });
  }
  return out;
}
