// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The shell around engineTrustModel: ask the ENGINE where its certificate is, read it, read any
// per-target `caFile` pins, and register them with engineClient (BACKLOG #1695). Every decision worth
// testing lives in the model; this file is the vscode + filesystem + subprocess half.
import * as vscode from "vscode";

import { engineUrl, environments, isExecGated, runJson, serviceConfig, workspaceDir } from "./cli";
import {
  clearEngineTrustAnchors,
  setEngineTrustAnchor,
  setTrustFailureHandler,
} from "./engineClient";
import { engineLog } from "./engineLog";
import { isLocalEngine } from "./engineTarget";
import {
  engineHostKey,
  isHttpsUrl,
  parseApiTls,
  pinTargetsOf,
  schemeMismatch,
  trustAnchorForTarget,
  trustPinsFor,
} from "./engineTrustModel";
import type { PinTarget } from "./engineTrustModel";
import { readCapped } from "./symbolIndex";

/**
 * How much of a certificate file we are willing to read. A PEM chain is kilobytes; this only bounds
 * the damage if `messagefoundry.serviceConfig` names a TOML whose `[api].tls_cert_file` points at
 * something enormous, or a `caFile` names one, which would otherwise be read whole into the
 * extension host.
 */
const MAX_PEM_BYTES = 512 * 1024;

/**
 * The shortest gap between two full refreshes started by a verification failure rather than by
 * activation or a settings change. Each one spawns the engine's CLI, and the status bar probes every
 * 15 seconds, so an engine that keeps failing verification would otherwise spawn one per probe.
 */
const FAILURE_REFRESH_MIN_MS = 60_000;

/** An anchor this file registered: the file it came from, so a renewal can be re-read, the PEM, and
 *  whether it is a `caFile` pin (which the engine's CLI can never replace, so it is never asked). */
interface Registered {
  readonly file: string;
  readonly pem: string;
  readonly pinned: boolean;
}

/**
 * What this file has registered with engineClient, keyed like engineClient's own map
 * ({@link engineHostKey}). Kept here, not read back from the client, because following a renewal
 * needs the FILE an anchor came from and the client holds only its contents.
 */
const registered = new Map<string, Registered>();

/** When the last failure-started full refresh began, for {@link FAILURE_REFRESH_MIN_MS}. */
let lastFailureRefresh = Number.NEGATIVE_INFINITY;

/** The tail of the refresh chain. Refreshes run one at a time; see {@link refreshEngineTrust}. */
let refreshTail: Promise<unknown> = Promise.resolve();

function register(url: string, anchor: Registered): void {
  const key = engineHostKey(url);
  if (key === undefined) {
    return;
  }
  registered.set(key, anchor);
  setEngineTrustAnchor(url, anchor.pem);
}

/** What the client trusts, as one comparable string: host keys and PEMs, never the file paths. */
function trustState(): string {
  return JSON.stringify([...registered].map(([key, r]) => [key, r.pem]).sort());
}

/**
 * Re-learn every trust anchor: the per-target `caFile` pins from `messagefoundry.environments`, then
 * the local engine's certificate as its CLI reports it.
 *
 * **Fail-soft throughout.** Every failure here leaves the affected target on Node's default CA set
 * with verification on. The request then fails with a trust error carrying the remedy
 * (`trustRemedy`), which is a better outcome than a half-configured client and is why nothing here
 * throws.
 *
 * Resolves to true when what the client TRUSTS changed, compared as host keys and PEM contents, so
 * the caller can re-probe rather than leave a stale verdict on screen. Dropping an anchor counts,
 * because a retarget to a remote engine registers nothing and still invalidates the verdict on
 * screen. Re-reading the same certificate does not count, so a refresh started by a verification
 * failure cannot re-probe itself into a loop.
 *
 * Refreshes run ONE AT A TIME. Each clears the anchors and then awaits a subprocess, so two
 * interleaved runs could each clear what the other had just registered.
 */
export function refreshEngineTrust(): Promise<boolean> {
  const run = refreshTail.then(refreshOnce, refreshOnce);
  refreshTail = run.catch(() => undefined);
  return run;
}

/** Anchors one refresh has gathered, keyed by host key, committed together at its end. */
type Staged = Map<string, { readonly url: string; readonly anchor: Registered }>;

function stage(next: Staged, url: string, anchor: Registered): void {
  const key = engineHostKey(url);
  if (key !== undefined) {
    next.set(key, { url, anchor });
  }
}

async function refreshOnce(): Promise<boolean> {
  const before = trustState();
  const next: Staged = new Map();
  const targets = pinTargetsOf(environments());
  const claimed = stagePins(targets, next);
  await anchorLocalEngine(claimed, next);
  // Swap only now, after the subprocess has answered. Clearing first and then awaiting left EVERY
  // engine unanchored for as long as `cert inventory` ran, so a request in that window failed against
  // an engine trusted a moment earlier. Replacing the whole set still drops a host the user edited
  // away from, so it is not trusted later from a cached read.
  clearEngineTrustAnchors();
  registered.clear();
  for (const { url, anchor } of next.values()) {
    register(url, anchor);
  }
  warnAboutUnanchoredTargets(targets);
  return trustState() !== before;
}

/**
 * Stage every `caFile` pin `messagefoundry.environments` names, and return every host key a `caFile`
 * CLAIMS, whether or not it could be used.
 *
 * A claimed key whose pin is refused or unreadable gets NO anchor, not the certificate
 * `messagefoundry.serviceConfig` names. The user pinned that host so that a workspace-chosen file
 * would not decide it; falling back to one when the pin breaks would undo that.
 *
 * No workspace and no CLI are involved, and that is why this runs BEFORE the workspace guard in
 * {@link anchorLocalEngine}: the setting is machine-scoped, so the file it names was chosen by the
 * user of this machine, and a pin is just as valid with no folder open or in an untrusted workspace.
 */
function stagePins(targets: readonly PinTarget[], next: Staged): Set<string> {
  const claimed = new Set<string>();
  for (const pin of trustPinsFor(targets)) {
    const key = engineHostKey(pin.url);
    if (key !== undefined) {
      claimed.add(key);
    }
    if (pin.kind === "refused") {
      engineLog().warn(`messagefoundry.environments: not pinning ${pin.url}: ${pin.reason}`);
      continue;
    }
    const read = readAnchorPem(pin.file);
    if (read.pem === undefined) {
      engineLog().warn(`${read.problem} — not pinning ${pin.url}`);
      continue;
    }
    stage(next, pin.url, { file: pin.file, pem: read.pem, pinned: true });
    engineLog().info(`trusting ${pin.file} for ${pin.url} (its caFile in messagefoundry.environments)`);
  }
  return claimed;
}

/** The usable `caFile` configured for `key`, if any: the file a pin read at refresh time could not
 *  register still deserves a re-read when a request to that engine fails. */
function configuredPinFile(key: string): string | undefined {
  for (const pin of trustPinsFor(pinTargetsOf(environments()))) {
    if (pin.kind === "pin" && pin.key === key) {
      return pin.file;
    }
  }
  return undefined;
}

/**
 * Ask the engine's CLI which certificate its API bind presents, and register it as the trust anchor
 * for the configured `messagefoundry.engineUrl` — unless an explicit `caFile` pin already covers that
 * `host:port`. The user named the pin; the CLI's answer is inferred from a workspace setting.
 */
async function anchorLocalEngine(claimed: ReadonlySet<string>, next: Staged): Promise<void> {
  // The same guard the three sibling CLI calls in extension.ts use. Without it, opening a loose .py
  // file with no folder spawns a Python interpreter for a command that can only fail: isExecGated()
  // is false when there is no workspace, so it does not cover this on its own.
  //
  // Captured ONCE, and every use below is this constant. The workspace is both the cwd the reading is
  // taken in and the base a relative certificate path is resolved against, so two calls that could
  // disagree would silently resolve the path against a directory the command never ran in.
  //
  // `!workspace`, not `workspace === undefined`: an empty string must fail the guard too. It would
  // otherwise reach `path.join("", …)`, whose result is relative, and a relative path is read against
  // the extension host's own cwd — the defect the resolution below exists to remove.
  const workspace = workspaceDir();
  if (!workspace || isExecGated()) {
    return;
  }

  let payload: unknown;
  try {
    // `cert inventory` is read-only and starts no server; --service-config alone is a valid source.
    // The path is workspace-relative (like every other messagefoundry.* path setting), so it runs
    // from the workspace the same way alertEditor.ts runs `alert list`.
    payload = await runJson<unknown>(
      ["cert", "inventory", "--service-config", serviceConfig()],
      workspace,
    );
  } catch {
    // No engine, no TOML, an older CLI — all "we learned nothing".
    return;
  }

  const facts = parseApiTls(payload);
  const url = engineUrl();
  // The TARGET and the workspace go into the decision, not just the facts. Computing the file here
  // and choosing whom to register it for separately is what let a local certificate become a remote
  // engine's trust anchor, so the two arrive together or not at all. The decision also carries WHY it
  // declined, because re-deriving that here is the same split the bug came from.
  const decision = trustAnchorForTarget(facts, url, workspace);
  const key = engineHostKey(url);
  if (decision.kind === "anchor" && key !== undefined && claimed.has(key)) {
    engineLog().info(
      `${url} has a caFile in messagefoundry.environments, so the certificate ` +
        `messagefoundry.serviceConfig names (${decision.file}) is not used for it.`,
    );
  } else if (decision.kind === "anchor") {
    const read = readAnchorPem(decision.file);
    if (read.pem === undefined) {
      engineLog().warn(`${read.problem} — not trusting it`);
    } else {
      stage(next, url, { file: decision.file, pem: read.pem, pinned: false });
      engineLog().info(`trusting the engine certificate at ${decision.file} for ${url}`);
    }
  } else if (decision.kind === "notLocal") {
    // The engine named a usable certificate and the model declined it because the target is not
    // loopback. Say so: a silently unanchored target fails later with no explanation the user can
    // act on. The REMEDY is not repeated here — `trustRemedy` owns that wording and delivers it when
    // the request itself fails.
    engineLog().info(
      `${url} is not a loopback address, so messagefoundry.serviceConfig — which describes the ` +
        `LOCAL engine — is not used to trust it.`,
    );
  }

  const mismatch = schemeMismatch(facts, url);
  if (mismatch !== undefined) {
    engineLog().warn(mismatch);
  }
}

/** A certificate read: the PEM, or why there is none, worded for the log. */
type PemRead = { pem: string; problem?: undefined } | { pem?: undefined; problem: string };

/**
 * Read a certificate PEM, or say why it cannot be used.
 *
 * `file` arrives ABSOLUTE, from {@link trustAnchorForTarget} or {@link trustPinsFor}. It has to:
 * `readCapped` ends in a bare `fs.openSync`, which resolves a relative path against the extension
 * host's own cwd — a directory that has nothing to do with the workspace or the setting.
 *
 * `readCapped` rather than a statSync/readFileSync pair: it resolves the path ONCE and checks the
 * size against that descriptor, which is the CodeQL `js/file-system-race` fix `symbolIndex.ts`
 * already carries and pins.
 *
 * The caller logs the problem, not this function: a re-read after a verification failure runs on
 * every failing probe, and logging there each time would bury the log in one repeated line.
 */
function readAnchorPem(file: string): PemRead {
  const pem = readCapped(file, MAX_PEM_BYTES);
  if (pem === undefined) {
    return { problem: `could not read the engine certificate at ${file}` };
  }
  // A readable file is not yet a certificate, and the difference is invisible downstream: Node's
  // `tls.createSecureContext` treats a FALSY `ca` as "use the default roots", so an empty or
  // truncated file would register an anchor that silently does nothing while the caller logs
  // "trusting the engine certificate" and reports success. Check the one marker every PEM chain
  // carries. A DER file fails it, correctly — `readCapped` decodes utf8, so DER never worked here.
  if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
    return {
      problem: `the engine certificate at ${file} is not PEM (no BEGIN CERTIFICATE block)`,
    };
  }
  return { pem };
}

/**
 * Follow a certificate that changed under a registered anchor — BACKLOG #1695, residual c.
 *
 * engineClient calls this when a request to `url` failed verification while it carried `usedCa`. It
 * resolves true only when an anchor DIFFERENT from `usedCa` is now registered for that engine, which
 * is engineClient's cue to retry the request once.
 *
 * Two cases:
 *   * a file describes that `host:port` — the registered anchor's, or a configured `caFile` that
 *     could not be read at refresh time (a share not yet mounted): re-read it, synchronously and
 *     capped. The engine renews its generated pair at startup into the same file (ADR 0172,
 *     2026-09-26 amendment), and a `caFile` rotated in place behaves the same way. Nothing is
 *     spawned, so the request's own timeout still bounds the wait.
 *   * otherwise (no file, or its certificate is the one that just failed), for the engine
 *     `messagefoundry.engineUrl` names when it is loopback and has no `caFile`: start the full refresh in the BACKGROUND, at most once per
 *     {@link FAILURE_REFRESH_MIN_MS}, and answer false. That covers the first-run gap (an engine
 *     started after the window opened mints its certificate only then). It is not awaited because
 *     it spawns the engine's CLI, which has no timeout; a request waiting on it would no longer
 *     honour its own. The refresh re-probes the status bar when it registers something.
 *
 * Every other target gets nothing: the CLI anchors only `engineUrl`'s host, and no file of this
 * machine describes the rest.
 *
 * Exported for the shell test; production reaches it through {@link registerEngineTrust}.
 */
export function followCertificateChange(url: string, usedCa: string | undefined): Promise<boolean> {
  const key = engineHostKey(url);
  if (key === undefined) {
    return Promise.resolve(false);
  }
  const held = registered.get(key);
  const file = held?.file ?? configuredPinFile(key);
  const read = file === undefined ? undefined : readAnchorPem(file).pem;
  if (file !== undefined && read !== undefined && read !== usedCa) {
    if (read !== held?.pem) {
      register(url, { file, pem: read, pinned: held?.pinned ?? true });
      engineLog().info(`the certificate at ${file} changed; trusting it for ${url}`);
    }
    // Equal to `held.pem` means another request already followed it; this one retries all the same.
    return Promise.resolve(true);
  }
  const now = Date.now();
  // A caFile, registered or only configured, wins over the CLI's answer, so asking would change nothing.
  const pinnedHere = held?.pinned === true || (held === undefined && file !== undefined);
  const cliCanAnchor = !pinnedHere && key === engineHostKey(engineUrl()) && isLocalEngine(url);
  if (cliCanAnchor && now - lastFailureRefresh >= FAILURE_REFRESH_MIN_MS) {
    lastFailureRefresh = now;
    void refreshEngineTrustThenRecheck();
  }
  return Promise.resolve(false);
}

/** Drop every anchor and reset the failure-refresh rate limit. For the shell test only. */
export function forgetEngineTrust(): void {
  clearEngineTrustAnchors();
  registered.clear();
  lastFailureRefresh = Number.NEGATIVE_INFINITY;
}

/**
 * Say so when configured targets have NO anchor, rather than letting them fail unexplained.
 *
 * `messagefoundry.environments` can name several engines, and the status bar probes the FIRST of
 * them rather than `engineUrl`. A target with no `caFile` and no loopback certificate from
 * `messagefoundry.serviceConfig` is verified against the default roots only, which is right for a
 * publicly trusted chain and fails for anything else.
 */
function warnAboutUnanchoredTargets(targets: readonly PinTarget[]): void {
  const unanchored = targets.filter((t) => {
    const key = engineHostKey(t.url);
    return key !== undefined && isHttpsUrl(t.url) && !registered.has(key);
  });
  if (unanchored.length === 0) {
    return;
  }
  engineLog().info(
    `messagefoundry.environments names ${unanchored.length} https target(s) with no trust anchor ` +
      `(${unanchored.map((t) => t.url).join(", ")}); they verify against the default roots only. ` +
      `Set caFile on the entry to trust a private CA or a self-signed engine certificate.`,
  );
}

/**
 * Refresh at activation, and again whenever a target or the service TOML setting moves; follow a
 * changed certificate when a request fails verification.
 *
 * The re-check afterwards matters because the status bar starts probing on the same tick and its
 * first probe necessarily runs before the subprocess answers. Without it, a healthy engine renders
 * as "cannot verify" until the next 15-second poll, on every window open.
 */
export function registerEngineTrust(context: vscode.ExtensionContext): void {
  setTrustFailureHandler(followCertificateChange);
  context.subscriptions.push({ dispose: () => setTrustFailureHandler(undefined) });
  void refreshEngineTrustThenRecheck();
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        e.affectsConfiguration("messagefoundry.engineUrl") ||
        e.affectsConfiguration("messagefoundry.environments") ||
        e.affectsConfiguration("messagefoundry.serviceConfig")
      ) {
        void refreshEngineTrustThenRecheck();
      }
    }),
  );
}

/** Re-learn the engine certificate, and re-probe if what the client trusts changed. Exported for the
 *  workspace-trust grant, which activation cannot re-run (vault BACKLOG #3166). */
export async function refreshEngineTrustThenRecheck(): Promise<void> {
  if (!(await refreshEngineTrust())) {
    return; // nothing changed about what we trust, so nothing to re-probe
  }
  try {
    await vscode.commands.executeCommand("messagefoundry.engineRecheck");
  } catch {
    // The status bar registers that command on the same activation tick; if it is not there, there
    // is nothing to refresh and this is not a failure worth surfacing.
  }
}
