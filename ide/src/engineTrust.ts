// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The shell around engineTrustModel: ask the ENGINE where its certificate is, read it, read any
// per-target `caFile` pins, and register them with engineClient (BACKLOG #1695). Every decision worth
// testing lives in the model; this file is the vscode + filesystem + subprocess half.
import * as fs from "node:fs";

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
import type { PinTarget, TrustPin } from "./engineTrustModel";

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

/**
 * How long `cert inventory` may run before it is killed. Refreshes run one at a time, so a CLI that
 * never answers (an interpreter waiting on a hung share, a debugger-attached Python) would otherwise
 * hold every later refresh behind it for the life of the window: added pins would never register and
 * removed ones would keep their anchor. The command reads a TOML and stats a few files; a cold Python
 * start on Windows takes seconds, so this leaves an order of magnitude of headroom. A killed run is
 * "we learned nothing", like any other CLI failure here.
 */
const CERT_INVENTORY_TIMEOUT_MS = 30_000;

/**
 * The most one refresh may take, CLI and file reads together. The CLI's own timeout does not bound a
 * refresh on its own: Node kills the child and then waits for it to close, which a process stuck in
 * an uninterruptible read never does, and the pin reads after it have no timeout at all. Past this
 * the refresh is ABANDONED: it commits nothing when it does finish, and the next one runs.
 */
const REFRESH_MAX_MS = CERT_INVENTORY_TIMEOUT_MS + 30_000;

/**
 * The most a failing request waits for the follow path's re-read before it gives up on following. A
 * request has its own timeout (five seconds for a GET), and a file on an unreachable share would
 * otherwise hold it for the share's timeout instead. A read cut short is not followed this time.
 */
const FOLLOW_READ_MAX_MS = 2_000;

/** An anchor this file registered: the file it came from, so a renewal can be re-read, the PEM,
 *  whether it is a `caFile` pin (which the engine's CLI can never replace, so it is never asked), and
 *  when its read STARTED ({@link readSeq}), so an older read never replaces a newer one. */
interface Registered {
  readonly file: string;
  readonly pem: string;
  readonly pinned: boolean;
  readonly readAt: number;
}

/**
 * Counts certificate reads in the order they start. Refresh and follow reads now overlap (both are
 * asynchronous), so "which read is newer" is decided by this, not by which one finished last.
 */
let readSeq = 0;

/**
 * What this file has registered with engineClient, keyed like engineClient's own map
 * ({@link engineHostKey}). Kept here, not read back from the client, because following a renewal
 * needs the FILE an anchor came from and the client holds only its contents.
 */
const registered = new Map<string, Registered>();

/**
 * Every host key a `caFile` claimed at the last refresh, usable or not. Such a host never takes the
 * CLI's certificate (see {@link claimedBy}), so a failure there must not spawn the CLI either.
 */
let claimedKeys: ReadonlySet<string> = new Set();

/**
 * The usable `caFile` for each host key at the last refresh, read or not. Taken from the SAME pass as
 * {@link claimedKeys}, so the follow path never pairs a claim from one configuration with a file from
 * another; a settings change starts a refresh that replaces both together.
 */
let pinFiles: ReadonlyMap<string, string> = new Map();

/** When the last failure-started full refresh began, on the MONOTONIC clock (`performance.now`), so
 *  a wall clock stepped backward cannot hold the limit shut. For {@link FAILURE_REFRESH_MIN_MS}. */
let lastFailureRefresh = Number.NEGATIVE_INFINITY;

/** How many refreshes are queued or running. A failure while one is pending starts no other at once:
 *  see {@link lateFailureKey} for the one case the pending refresh cannot cover. */
let refreshesPending = 0;

/**
 * The running refresh has begun asking the CLI, so a certificate minted from now on may be invisible
 * to it (the CLI reads the engine's state at some point during its run, not at its answer), AND that
 * refresh is not itself a follow-up: a failure now may ask for one more refresh ({@link lateFailure}).
 */
let acceptsLateFailure = false;

/**
 * A CLI-anchorable failure that arrived while the last pending refresh was asking the CLI or after,
 * with the anchor that request carried. When the refresh finishes, one more runs if that anchor is
 * still what is registered: the refresh did not fix it. Only one follow-up per refresh, and never one
 * from a follow-up, so failures cannot chain CLI spawns faster than the rate limit allows.
 */
let lateFailure: { readonly key: string; readonly usedCa: string | undefined } | undefined;

/** A read and when it started ({@link readSeq}). */
interface StampedRead {
  readonly readAt: number;
  readonly read: PemRead;
}

/** Re-reads the follow path has in flight, by file, so a burst of failing requests against one file
 *  on an unreachable share queues one read rather than one per request. */
const followReads = new Map<string, Promise<StampedRead>>();

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
 * Refreshes run ONE AT A TIME. Each awaits a subprocess and then replaces the whole set, so two
 * interleaved runs could each replace what the other had just registered with an older reading.
 */
export function refreshEngineTrust(): Promise<boolean> {
  return queueRefresh(false);
}

function queueRefresh(followUp: boolean): Promise<boolean> {
  refreshesPending++;
  const once = (): Promise<boolean> => {
    const token = { abandoned: false };
    return withDeadline(refreshOnce(followUp, token), REFRESH_MAX_MS, () => {
      token.abandoned = true;
      engineLog().warn(
        `refreshing the engine trust anchors took over ${REFRESH_MAX_MS / 1000} s; abandoned it`,
      );
      return false;
    });
  };
  // `finally`, so the count returns to 0 however the refresh ended, and REFRESH_MAX_MS makes sure it
  // does end.
  const run = refreshTail.then(once, once).finally(() => {
    refreshesPending--;
    acceptsLateFailure = false;
    if (refreshesPending === 0) {
      startLateFollowUp();
    }
  });
  refreshTail = run.catch(() => undefined);
  return run;
}

/** Run the follow-up {@link lateFailure} asked for, if the refresh left the failing anchor in place
 *  and the CLI could still anchor that host. Past the rate limit on purpose: it is bounded to one per
 *  refresh instead. */
function startLateFollowUp(): void {
  const late = lateFailure;
  lateFailure = undefined;
  if (
    late === undefined ||
    registered.get(late.key)?.pem !== late.usedCa ||
    !cliCouldAnchor(late.key)
  ) {
    return;
  }
  void refreshThenRecheck(true);
}

/** `promise`, or `onTimeout()` if it has not settled within `ms`. The promise keeps running. */
function withDeadline<T>(promise: Promise<T>, ms: number, onTimeout: () => T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), ms);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

/** Anchors one refresh has gathered, keyed by host key, committed together at its end. */
type Staged = Map<string, { readonly url: string; readonly anchor: Registered }>;

function stage(next: Staged, url: string, anchor: Registered): void {
  const key = engineHostKey(url);
  if (key !== undefined) {
    next.set(key, { url, anchor });
  }
}

async function refreshOnce(
  followUp: boolean,
  token: { readonly abandoned: boolean },
): Promise<boolean> {
  const before = trustState();
  const next: Staged = new Map();
  const targets = pinTargetsOf(environments());
  const pins = trustPinsFor(targets);
  const claimed = claimedBy(pins);
  acceptsLateFailure = !followUp;
  await anchorLocalEngine(claimed, next);
  // The pin FILES are read only now, after the CLI has answered, so a caFile rotated in place while
  // the CLI runs is read as rotated.
  await stagePins(pins, next);
  if (token.abandoned) {
    return false; // past REFRESH_MAX_MS: a later refresh has the newer answer
  }
  // Swap only now, after the subprocess has answered. Clearing first and then awaiting left EVERY
  // engine unanchored for as long as `cert inventory` ran, so a request in that window failed against
  // an engine trusted a moment earlier. Replacing the whole set still drops a host the user edited
  // away from, so it is not trusted later from a cached read.
  claimedKeys = claimed;
  pinFiles = new Map(pins.flatMap((pin) => (pin.kind === "pin" ? [[pin.key, pin.file] as const] : [])));
  const previous = new Map(registered);
  clearEngineTrustAnchors();
  registered.clear();
  for (const [key, { url, anchor }] of next) {
    // A request may have followed the same file while this refresh read it. Keep whichever read
    // STARTED later, so a rotation the follow path saw is not undone by this older read.
    const live = previous.get(key);
    register(url, live?.file === anchor.file && live.readAt > anchor.readAt ? live : anchor);
  }
  warnAboutUnanchoredTargets(targets);
  return trustState() !== before;
}

/**
 * Every host key a `caFile` CLAIMS, whether or not its pin can be used ({@link TrustPin} says which
 * refusals claim). A claimed key whose pin is refused or unreadable gets NO anchor, not the
 * certificate `messagefoundry.serviceConfig` names.
 */
function claimedBy(pins: readonly TrustPin[]): Set<string> {
  const claimed = new Set<string>();
  for (const pin of pins) {
    const key = pin.kind === "pin" ? pin.key : pin.claims;
    if (key !== undefined) {
      claimed.add(key);
    }
  }
  return claimed;
}

/**
 * Read and stage every usable `caFile` pin, logging each refusal.
 *
 * No workspace and no CLI are involved, so a pin applies with no folder open or in an untrusted
 * workspace: the setting is machine-scoped, so the file it names was chosen by the user of this
 * machine.
 */
async function stagePins(pins: readonly TrustPin[], next: Staged): Promise<void> {
  // One read per distinct file (an engine shard inherits its environment's), one at a time: parallel
  // opens on an unreachable share would each hold a thread of the pool every extension shares.
  const reads = new Map<string, StampedRead>();
  for (const pin of pins) {
    if (pin.kind === "refused") {
      engineLog().warn(`messagefoundry.environments: not pinning ${pin.url}: ${pin.reason}`);
      continue;
    }
    let stamped = reads.get(pin.file);
    if (stamped === undefined) {
      stamped = await stampedRead(pin.file);
      reads.set(pin.file, stamped);
    }
    const { read, readAt } = stamped;
    if (read.pem === undefined) {
      engineLog().warn(`${read.problem} — not pinning ${pin.url}`);
      continue;
    }
    stage(next, pin.url, { file: pin.file, pem: read.pem, pinned: true, readAt });
    engineLog().info(`trusting ${pin.file} for ${pin.url} (its caFile in messagefoundry.environments)`);
  }
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
      { timeoutMs: CERT_INVENTORY_TIMEOUT_MS },
    );
  } catch {
    // A run killed at the timeout, no engine, no TOML, an older CLI — all "we learned nothing".
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
    const { read, readAt } = await stampedRead(decision.file);
    if (read.pem === undefined) {
      engineLog().warn(`${read.problem} — not trusting it`);
    } else {
      stage(next, url, { file: decision.file, pem: read.pem, pinned: false, readAt });
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

/**
 * Read at most `maxBytes` of `file` as utf8, or `undefined` when it is not a regular file, is over
 * the cap, or cannot be read.
 *
 * Not `readCapped` from symbolIndex.ts, whose cap is a best-effort guard: it trusts `fstat`'s size,
 * which is 0 for `/dev/zero` or a FIFO, and then reads to an EOF that never comes. Not
 * `readSampleCapped` from sampleFile.ts either, which is hard-bounded but accepts any file type,
 * blocks opening a FIFO, and is synchronous. A `caFile` is a free-form path, so here the descriptor
 * must be a REGULAR file and the read is bounded by the buffer. `O_NONBLOCK` makes opening a FIFO
 * return at once (POSIX) instead of waiting for a writer; it is ignored on Windows, where a named pipe
 * reached by a UNC host name can still block the open.
 *
 * ASYNCHRONOUS, because the follow path runs on every failing request and a file on an unreachable
 * share takes the share's own timeout to fail. Synchronous, that wait blocked the extension host; here
 * it holds one libuv pool thread. The buffer is sized like `readSampleCapped`'s: what `fstat` reports
 * plus one byte to notice growth, so only a file that grew mid-read gets the full cap.
 * The path is resolved once, into the descriptor every check reads (CodeQL `js/file-system-race`).
 */
async function readRegularFileCapped(file: string, maxBytes: number): Promise<string | undefined> {
  let handle: fs.promises.FileHandle | undefined;
  try {
    handle = await fs.promises.open(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > maxBytes) {
      return undefined;
    }
    // allocUnsafe: only the bytes the reads filled are ever decoded.
    let buffer = Buffer.allocUnsafe(stat.size + 1);
    let length = await fillFrom(handle, buffer, 0);
    if (length > stat.size) {
      const bigger = Buffer.allocUnsafe(maxBytes + 1);
      buffer.copy(bigger, 0, 0, length);
      buffer = bigger;
      length = await fillFrom(handle, buffer, length);
    }
    return length > maxBytes ? undefined : buffer.toString("utf8", 0, length); // over: grew past the cap
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Read from `handle` into `buffer` from offset `length` until end of file or a full buffer; the new
 *  fill level. The asynchronous twin of `fillFrom` in sampleFile.ts. */
async function fillFrom(
  handle: fs.promises.FileHandle,
  buffer: Buffer,
  length: number,
): Promise<number> {
  while (length < buffer.length) {
    const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
    if (bytesRead === 0) {
      break;
    }
    length += bytesRead;
  }
  return length;
}

/** A certificate read: the PEM, or why there is none, worded for the log. */
type PemRead = { pem: string; problem?: undefined } | { pem?: undefined; problem: string };

/**
 * Read a certificate PEM, or say why it cannot be used.
 *
 * `file` arrives ABSOLUTE, from {@link trustAnchorForTarget} or {@link trustPinsFor}. It has to:
 * the read ends in a bare `fs.promises.open`, which resolves a relative path against the extension
 * host's own cwd — a directory that has nothing to do with the workspace or the setting.
 *
 * The caller logs the problem, not this function: a re-read after a verification failure runs on
 * every failing probe, and logging there each time would bury the log in one repeated line.
 */
async function readAnchorPem(file: string): Promise<PemRead> {
  const pem = await readRegularFileCapped(file, MAX_PEM_BYTES);
  if (pem === undefined) {
    return { problem: `could not read the engine certificate at ${file}` };
  }
  // A readable file is not yet a certificate, and the difference is invisible downstream: Node's
  // `tls.createSecureContext` treats a FALSY `ca` as "use the default roots", so an empty or
  // truncated file would register an anchor that silently does nothing while the caller logs
  // "trusting the engine certificate" and reports success. Check the one marker every PEM chain
  // carries. A DER file fails it, correctly — the read decodes utf8, so DER never worked here.
  if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
    return {
      problem: `the engine certificate at ${file} is not PEM (no BEGIN CERTIFICATE block)`,
    };
  }
  return { pem };
}

/** {@link readAnchorPem}, stamped with when it started. */
async function stampedRead(file: string): Promise<StampedRead> {
  const readAt = ++readSeq;
  return { readAt, read: await readAnchorPem(file) };
}

/**
 * {@link stampedRead} for the follow path, bounded by {@link FOLLOW_READ_MAX_MS} and sharing one read
 * per file while it is in flight. `joined` says the read began before this call, so it may predate
 * the rotation that made the request fail.
 */
async function rereadForFollow(file: string): Promise<StampedRead & { readonly joined: boolean }> {
  let pending = followReads.get(file);
  const joined = pending !== undefined;
  if (pending === undefined) {
    pending = stampedRead(file).finally(() => followReads.delete(file));
    followReads.set(file, pending);
  }
  const stamped = await withDeadline(pending, FOLLOW_READ_MAX_MS, () => ({
    readAt: 0,
    read: { problem: `reading ${file} took over ${FOLLOW_READ_MAX_MS} ms` },
  }));
  return { ...stamped, joined };
}

/**
 * True when a refresh could anchor `key` from the engine's CLI: it is `messagefoundry.engineUrl`'s
 * host, that host is loopback, and no `caFile` claims it (a pin, usable or not, wins over the CLI's
 * answer, so asking would change nothing). The CLI anchors no other host.
 */
function cliCouldAnchor(key: string): boolean {
  const url = engineUrl();
  return (
    // anchorLocalEngine's own guard: with no workspace, or an untrusted one, the CLI is never asked.
    !!workspaceDir() &&
    !isExecGated() &&
    !claimedKeys.has(key) &&
    registered.get(key)?.pinned !== true &&
    key === engineHostKey(url) &&
    isLocalEngine(url)
  );
}

/**
 * Start a full refresh for a failure the CLI could answer, without spawning one per failing probe.
 *
 * With no refresh pending, at most one per {@link FAILURE_REFRESH_MIN_MS}. With one pending, none at
 * once: a refresh that has not yet asked the CLI will see whatever caused this failure. One already
 * asking may not, since the CLI reads the engine's state partway through its run, so the failure is
 * noted and {@link startLateFollowUp} runs one more refresh when it finishes, unless that refresh
 * replaced the anchor the request failed with.
 */
function noteCliAnchorableFailure(key: string, usedCa: string | undefined): void {
  if (refreshesPending > 0) {
    if (refreshesPending === 1 && acceptsLateFailure) {
      lateFailure = { key, usedCa };
    }
    return;
  }
  const now = performance.now();
  if (now - lastFailureRefresh >= FAILURE_REFRESH_MIN_MS) {
    lastFailureRefresh = now;
    void refreshThenRecheck(false);
  }
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
 *     could not be read at refresh time (a share not yet mounted): re-read it, asynchronously and
 *     capped, one read per file at a time, waiting at most {@link FOLLOW_READ_MAX_MS}. The engine renews its generated pair at startup into the
 *     same file (ADR 0172, 2026-09-26 amendment), and a `caFile` rotated in place behaves the same
 *     way. Nothing is spawned.
 *   * otherwise (no file, or its certificate is the one that just failed), for the engine
 *     `messagefoundry.engineUrl` names when it is loopback and no `caFile` claims it: start the full
 *     refresh in the BACKGROUND (see {@link noteCliAnchorableFailure} for when), and answer false.
 *     That covers the first-run gap (an engine started after the window opened mints its certificate
 *     only then). It is not awaited because it spawns the engine's CLI, which may take up to
 *     {@link REFRESH_MAX_MS}; a request waiting on it would no longer honour its own timeout. The refresh re-probes the status bar when it registers something.
 *
 * Every other target gets nothing: the CLI anchors only `engineUrl`'s host, and no file of this
 * machine describes the rest.
 *
 * Exported for the shell test; production reaches it through {@link registerEngineTrust}.
 */
export async function followCertificateChange(
  url: string,
  usedCa: string | undefined,
): Promise<boolean> {
  const key = engineHostKey(url);
  if (key === undefined) {
    return false;
  }
  const fileFor = (): string | undefined => registered.get(key)?.file ?? pinFiles.get(key);
  const file = fileFor();
  let stamped = file === undefined ? undefined : await rereadForFollow(file);
  if (file !== undefined && stamped?.joined === true && stamped.read.pem === usedCa) {
    // A shared read that began before this request failed may predate the rotation; read again.
    stamped = await rereadForFollow(file);
  }
  const read = stamped?.read.pem;
  // Read the registration again: a refresh may have committed while the file was being read.
  const held = registered.get(key);
  // The file must still be the one that describes this host, and no newer read of it registered: a
  // refresh that read it later, or moved the host to another file, has the newer answer, and the
  // branch below retries against that.
  const newer = held !== undefined && held.file === file && held.readAt > (stamped?.readAt ?? 0);
  if (file !== undefined && stamped !== undefined && read !== undefined && read !== usedCa && file === fileFor() && !newer) {
    if (read !== held?.pem) {
      register(url, { file, pem: read, pinned: held?.pinned ?? true, readAt: stamped.readAt });
      engineLog().info(`the certificate at ${file} changed; trusting it for ${url}`);
    }
    // Equal to `held.pem` means another request already followed it; this one retries all the same.
    return true;
  }
  if (held !== undefined && held.pem !== usedCa) {
    // A refresh registered a different anchor while this request was in flight. The re-read above
    // may have failed (a file mid-rewrite), but what is registered now is still worth one retry.
    return true;
  }
  if (cliCouldAnchor(key)) {
    noteCliAnchorableFailure(key, usedCa);
  }
  return false;
}

/** Resolves once no refresh is queued or running, a follow-up included. For the shell test only. */
export async function engineTrustSettled(): Promise<void> {
  while (refreshesPending > 0) {
    await refreshTail;
  }
}

/** Drop every anchor and reset the failure-refresh state. For the shell test only. */
export function forgetEngineTrust(): void {
  clearEngineTrustAnchors();
  registered.clear();
  claimedKeys = new Set();
  pinFiles = new Map();
  lastFailureRefresh = Number.NEGATIVE_INFINITY;
  lateFailure = undefined;
  followReads.clear();
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
export function refreshEngineTrustThenRecheck(): Promise<void> {
  return refreshThenRecheck(false);
}

async function refreshThenRecheck(followUp: boolean): Promise<void> {
  if (!(await queueRefresh(followUp))) {
    return; // nothing changed about what we trust, so nothing to re-probe
  }
  try {
    await vscode.commands.executeCommand("messagefoundry.engineRecheck");
  } catch {
    // The status bar registers that command on the same activation tick; if it is not there, there
    // is nothing to refresh and this is not a failure worth surfacing.
  }
}
