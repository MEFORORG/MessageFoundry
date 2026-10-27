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
  setPinnedEngineHosts,
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
 * start on Windows takes seconds, so this leaves an order of magnitude of headroom.
 */
const CERT_INVENTORY_TIMEOUT_MS = 30_000;

/**
 * How many certificate reads may be running at once, across refreshes and the follow path. A read of
 * a file on an unreachable share holds one thread of the libuv pool every extension shares (four by
 * default) until the share's own timeout, and a caller that stops waiting does not stop the read. So
 * a new read waits for one of these to finish, within its caller's own deadline, rather than taking
 * another thread.
 */
const MAX_RUNNING_READS = 2;

/** The waits this file bounds. Constant in production; {@link setEngineTrustLimitsForTest} shortens
 *  them so the shell test can reach the timeout paths. */
interface Limits {
  /**
   * The most a refresh waits for the CLI to report. The kill at {@link CERT_INVENTORY_TIMEOUT_MS}
   * does not bound that on its own: Node kills the child and then waits for it to close, which a
   * process stuck in an uninterruptible read never does. Past this the refresh learns nothing from
   * the CLI; no other run starts until that child has exited ({@link cliRun}).
   */
  readonly cliAnswerMs: number;
  /**
   * The most a refresh spends reading certificates, all of them together, after the CLI answered. A
   * file not read by then counts as inconclusive, so with the CLI's own bound a refresh ends within
   * `cliAnswerMs + refreshReadMs` however many files sit on an unreachable share.
   */
  readonly refreshReadMs: number;
  /**
   * The most a failing request waits for the follow path's re-read. A request has its own timeout
   * (five seconds for a GET), and a file on an unreachable share would otherwise hold it for the
   * share's timeout instead. A read cut short is not followed this time.
   */
  readonly followReadMs: number;
}

const LIMITS: Limits = {
  cliAnswerMs: CERT_INVENTORY_TIMEOUT_MS + 5_000,
  refreshReadMs: 10_000,
  followReadMs: 2_000,
};

let limits: Limits = LIMITS;

/** An anchor this file registered: the file it came from, so a renewal can be re-read, the PEM,
 *  whether it is a `caFile` pin (which the engine's CLI can never replace, so it is never asked), and
 *  when its read STARTED ({@link readSeq}), so an older read never replaces a newer one. */
interface Registered {
  readonly url: string;
  readonly file: string;
  readonly pem: string;
  readonly pinned: boolean;
  readonly readAt: number;
}

/**
 * Counts certificate reads in the order they start. Refresh and follow reads overlap (both are
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
 * The usable `caFile` for each host key at the last refresh, read or not; `undefined` until a refresh
 * has committed, when the follow path reads the configuration itself. Taken from the SAME pass as
 * {@link claimedKeys}, so the follow path never pairs a claim from one configuration with a file from
 * another; a settings change starts a refresh that replaces both together.
 */
let pinFiles: ReadonlyMap<string, string> | undefined;

/** When the last failure-started full refresh began, on the MONOTONIC clock (`performance.now`), so
 *  a wall clock stepped backward cannot hold the limit shut. For {@link FAILURE_REFRESH_MIN_MS}. */
let lastFailureRefresh = Number.NEGATIVE_INFINITY;

/** How many refreshes are queued or running. A failure while one is pending starts no other at once:
 *  see {@link lateFailure} for the one case the pending refresh cannot cover. */
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

/** A read and when it started ({@link readSeq}); `readAt` 0 is a read this caller stopped waiting on. */
interface StampedRead {
  readonly readAt: number;
  readonly read: PemRead;
}

/**
 * Certificate reads still running, by file, shared by refreshes and the follow path. One file is
 * never read twice at once, and an entry leaves only when its read ends, so this map's size is the
 * number of pool threads these reads hold, abandoned ones included ({@link MAX_RUNNING_READS}).
 */
const inflightReads = new Map<string, Promise<StampedRead>>();

/** Wakers for reads waiting on {@link MAX_RUNNING_READS}; every one is called when any read ends. */
const readSlotWaiters = new Set<() => void>();

/** The `cert inventory` run whose child has not yet exited, if any. A refresh does not start another
 *  while one is alive, so a child that cannot be killed is never joined by a second. */
let cliRun: Promise<unknown> | undefined;

/** The refresh that started {@link cliRun} stopped waiting for it, and it has not exited. */
let cliAbandoned = false;

/**
 * Something needed the CLI while an abandoned child was alive: a refresh skipped it, or a failure
 * the CLI could answer arrived. When that child exits, one more refresh runs, so a setting changed
 * or a certificate minted in the meantime is picked up.
 */
let cliWanted = false;

/** The extension was deactivated, so an abandoned child's exit starts nothing. */
let deactivated = false;

/** The tail of the refresh chain. Refreshes run one at a time; see {@link refreshEngineTrust}. */
let refreshTail: Promise<unknown> = Promise.resolve();

function register(anchor: Registered): void {
  const key = engineHostKey(anchor.url);
  if (key === undefined) {
    return;
  }
  registered.set(key, anchor);
  setEngineTrustAnchor(anchor.url, anchor.pem);
}

/** What the client trusts, as one comparable string: host keys and PEMs, never the file paths. */
function trustState(): string {
  return JSON.stringify([...registered].map(([key, r]) => [key, r.pem]).sort());
}

/**
 * Re-learn every trust anchor: the per-target `caFile` pins from `messagefoundry.environments`, then
 * the local engine's certificate as its CLI reports it.
 *
 * **Fail-soft throughout, and never looser for it.** Nothing here throws. A target this refresh
 * cannot anchor and never anchored is verified against Node's default roots with verification on,
 * unless a usable `caFile` pins it: then engineClient refuses its requests until the file is read
 * ({@link publishPinnedHosts}). Either way a failing request carries the remedy (`trustRemedy`). A
 * target that WAS anchored keeps its anchor through any failure that proves nothing (see
 * {@link Outcome}), because dropping it would put an unpinned target back on the default roots, which
 * trusts more than the anchor did, and refuse every request to a pinned one.
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
  const once = (): Promise<boolean> => refreshOnce(followUp);
  // `finally`, so the count returns to 0 however the refresh ended. Every wait inside one is bounded
  // ({@link Limits}), so it does end.
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
  if (cliAbandoned) {
    cliWanted = true; // a refresh now would only skip the CLI; that child's exit asks instead
    return;
  }
  void refreshThenRecheck(true);
}

/** `promise`, or `onTimeout()` if it has not settled within `ms`. The promise keeps running. */
function withDeadline<T>(promise: Promise<T>, ms: number, onTimeout: () => T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), Math.max(0, ms));
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

/**
 * How one refresh ends for one host key. The whole rule a commit applies, so that no failure can
 * drop an anchor by accident:
 *
 *   * `fresh` — a certificate was read for it: register that.
 *   * `keep` — this refresh's answer for the key is inconclusive (a read failed or timed out, the CLI
 *     failed, did not answer in time, or was not started because an earlier run is still alive):
 *     keep what is registered NOW, but only an anchor from the same source (a pin, or the CLI) and,
 *     where the source named one, the same file. "Now" includes a renewal a request followed while
 *     this refresh ran.
 *   * no outcome — the key is authoritatively unanchored: no usable pin and no CLI answer names it
 *     (the pin was removed or refused, its file was read whole and holds something other than a
 *     certificate, `engineUrl`
 *     moved, the CLI answered with no certificate, or no trusted workspace remains to ask). Drop it.
 */
type Outcome =
  | Registered
  | { readonly keep: true; readonly pinned: boolean; readonly file?: string };

/** A certificate file a refresh reads, and the host key it would anchor. */
interface ToRead {
  readonly key: string;
  readonly url: string;
  readonly file: string;
  readonly pinned: boolean;
}

async function refreshOnce(followUp: boolean): Promise<boolean> {
  const before = trustState();
  const outcomes = new Map<string, Outcome>();
  const targets = pinTargetsOf(environments());
  const pins = trustPinsFor(targets);
  publishPinnedHosts(pins);
  const claimed = claimedBy(pins);
  // This refresh asks the CLI after any failure noted so far, so it covers that failure.
  lateFailure = undefined;
  acceptsLateFailure = !followUp;
  const reads: ToRead[] = [];
  await askCli(claimed, reads, outcomes);
  // After the CLI's file, so two pins on an unreachable share cannot take both read slots first.
  reads.push(...pinsToRead(pins));
  // Every file is read only now, after the CLI has answered, so a file rotated in place while the CLI
  // ran is read as rotated: a read already running from before (`since`) is read again.
  const since = readSeq;
  const deadline = performance.now() + limits.refreshReadMs;
  const results = await Promise.all(
    reads.map(async (r) => [r, await readSince(r.file, deadline, since)] as const),
  );
  for (const [{ key, url, file, pinned }, { read, readAt }] of results) {
    if (read.pem === undefined) {
      engineLog().warn(`${read.problem} — not ${pinned ? "pinning" : "trusting"} ${url}`);
      // A caFile that was read whole and holds no certificate is an answer: the user replaced it.
      // The engine's own file is not, since the engine renews into it in place.
      if (!(pinned && read.notACertificate)) {
        outcomes.set(key, { keep: true, pinned, file });
      }
      continue;
    }
    outcomes.set(key, { url, file, pem: read.pem, pinned, readAt });
    engineLog().info(
      pinned
        ? `trusting ${file} for ${url} (its caFile in messagefoundry.environments)`
        : `trusting the engine certificate at ${file} for ${url}`,
    );
  }
  // Swap only now, after the subprocess has answered. Clearing first and then awaiting left EVERY
  // engine unanchored for as long as `cert inventory` ran.
  const files = pinFilesOf(pins);
  claimedKeys = claimed;
  pinFiles = files;
  commit(outcomes);
  warnAboutUnanchoredTargets(targets, files);
  return trustState() !== before;
}

/** Replace the registered set by applying each key's {@link Outcome} to what is registered now. */
function commit(outcomes: ReadonlyMap<string, Outcome>): void {
  const previous = new Map(registered);
  clearEngineTrustAnchors();
  registered.clear();
  for (const [key, outcome] of outcomes) {
    const live = previous.get(key);
    const sameSource =
      live !== undefined &&
      live.pinned === outcome.pinned &&
      (outcome.file === undefined || sameFile(live.file, outcome.file));
    if (!("keep" in outcome)) {
      // A request may have followed the same file while this refresh read it. Keep whichever read
      // STARTED later, so a rotation the follow path saw is not undone by this older read.
      register(sameSource && live.readAt > outcome.readAt ? live : outcome);
    } else if (sameSource) {
      register(live);
      engineLog().info(`keeping the certificate read earlier from ${live.file} for ${live.url}`);
    }
  }
}

/**
 * Every host key a `caFile` CLAIMS, whether or not its pin can be used ({@link TrustPin} says which
 * refusals claim). A claimed key whose pin is refused or unreadable gets NO anchor from the
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

/** The usable `caFile` for each host key. */
function pinFilesOf(pins: readonly TrustPin[]): Map<string, string> {
  return new Map(pins.flatMap((pin) => (pin.kind === "pin" ? [[pin.key, pin.file] as const] : [])));
}

/** The pins `messagefoundry.environments` names now. */
function configuredPins(): TrustPin[] {
  return trustPinsFor(pinTargetsOf(environments()));
}

/**
 * Tell engineClient which hosts a usable `caFile` pins, so a request to one with no anchor yet is
 * refused rather than verified against the default roots (`pinRefusal` there).
 *
 * The keys are those of {@link pinFilesOf}, so a refused pin (an http:// url, a relative path) marks
 * nothing: it has no file that could ever anchor the host. Called SYNCHRONOUSLY from the settings, at
 * activation, on every settings change and at the start of every refresh, never after a file read,
 * so no read on a slow share can leave a pinned host on the default roots meanwhile.
 */
function publishPinnedHosts(pins: readonly TrustPin[]): void {
  setPinnedEngineHosts(pinFilesOf(pins).keys());
}

/**
 * Every usable `caFile` pin as a file to read, logging each refusal.
 *
 * No workspace and no CLI are involved, so a pin applies with no folder open or in an untrusted
 * workspace: the setting is machine-scoped, so the file it names was chosen by the user of this
 * machine.
 */
function pinsToRead(pins: readonly TrustPin[]): ToRead[] {
  const out: ToRead[] = [];
  for (const pin of pins) {
    if (pin.kind === "refused") {
      engineLog().warn(`messagefoundry.environments: not pinning ${pin.url}: ${pin.reason}`);
    } else {
      out.push({ key: pin.key, url: pin.url, file: pin.file, pinned: true });
    }
  }
  return out;
}

/**
 * Ask the engine's CLI which certificate its API bind presents, for the configured
 * `messagefoundry.engineUrl` — unless an explicit `caFile` pin already covers that `host:port`. The
 * user named the pin; the CLI's answer is inferred from a workspace setting.
 *
 * Adds the file to read to `reads`, or a `keep` {@link Outcome} for that key when the CLI's answer is
 * inconclusive (it failed, did not answer in time, or was not started); adds nothing when it decides
 * there is nothing to anchor.
 */
async function askCli(
  claimed: ReadonlySet<string>,
  reads: ToRead[],
  outcomes: Map<string, Outcome>,
): Promise<void> {
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
  const url = engineUrl();
  const key = engineHostKey(url);
  const inconclusive = (): void => {
    if (key !== undefined && !claimed.has(key)) {
      outcomes.set(key, { keep: true, pinned: false });
    }
  };

  if (cliRun !== undefined) {
    cliWanted = true;
    engineLog().warn("an earlier `cert inventory` run has not exited; not starting another");
    inconclusive();
    return;
  }
  let payload: unknown;
  try {
    // `cert inventory` is read-only and starts no server; --service-config alone is a valid source.
    // The path is workspace-relative (like every other messagefoundry.* path setting), so it runs
    // from the workspace the same way alertEditor.ts runs `alert list`.
    const call = runJson<unknown>(
      ["cert", "inventory", "--service-config", serviceConfig()],
      workspace,
      { timeoutMs: CERT_INVENTORY_TIMEOUT_MS },
    );
    const exited = (): void => {
      if (cliRun !== call) {
        return;
      }
      cliRun = undefined;
      cliAbandoned = false;
      if (cliWanted && !deactivated) {
        cliWanted = false;
        void refreshEngineTrustThenRecheck();
      }
    };
    cliRun = call;
    call.then(exited, exited);
    payload = await withDeadline(call, limits.cliAnswerMs, () => CLI_SILENT);
  } catch {
    // A run killed at the timeout, no engine, no TOML: we learned nothing.
    inconclusive();
    return;
  }
  if (payload === CLI_SILENT) {
    cliAbandoned = true;
    engineLog().warn(`\`cert inventory\` did not report within ${limits.cliAnswerMs / 1000} s`);
    inconclusive();
    return;
  }

  const facts = parseApiTls(payload);
  if (facts === undefined) {
    // An older engine (no `api_tls`) or a malformed answer says nothing about the certificate.
    inconclusive();
    return;
  }
  // The TARGET and the workspace go into the decision, not just the facts. Computing the file here
  // and choosing whom to register it for separately is what let a local certificate become a remote
  // engine's trust anchor, so the two arrive together or not at all. The decision also carries WHY it
  // declined, because re-deriving that here is the same split the bug came from.
  const decision = trustAnchorForTarget(facts, url, workspace);
  if (decision.kind === "anchor" && key !== undefined && claimed.has(key)) {
    engineLog().info(
      `${url} has a caFile in messagefoundry.environments, so the certificate ` +
        `messagefoundry.serviceConfig names (${decision.file}) is not used for it.`,
    );
  } else if (decision.kind === "anchor" && key !== undefined) {
    reads.push({ key, url, file: decision.file, pinned: false });
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

/** A certificate read: the PEM, or why there is none, worded for the log. `notACertificate` says the
 *  file was read whole, is not empty, and holds no PEM certificate, which is an answer rather than a
 *  failure. */
type PemRead =
  | { pem: string; problem?: undefined; notACertificate?: undefined }
  | { pem?: undefined; problem: string; notACertificate?: boolean };

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
  // An EMPTY file is not `notACertificate`: a file rewritten in place is empty between the truncate
  // and the write, so an empty read says nothing about what the file now holds.
  if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
    return {
      problem: `the engine certificate at ${file} is not PEM (no BEGIN CERTIFICATE block)`,
      notACertificate: pem.length > 0,
    };
  }
  return { pem };
}

/** How a file is identified: Windows paths are case-insensitive, as `trustPinsFor` treats them. */
function fileId(file: string): string {
  return process.platform === "win32" ? file.toLowerCase() : file;
}

function sameFile(a: string, b: string): boolean {
  return fileId(a) === fileId(b);
}

/** {@link askCli}'s marker for a CLI that did not report in time. */
const CLI_SILENT = Symbol("cli-silent");

/** The read a caller stopped waiting on: inconclusive, and newer than nothing (`readAt` 0). */
function cutShort(file: string): StampedRead {
  const problem = `reading the engine certificate at ${file} did not finish in time`;
  return { readAt: 0, read: { problem } };
}

/** Resolves true when a running read ends, or false at `deadline` (a `performance.now` time). */
function readSlotFreed(deadline: number): Promise<boolean> {
  let wake = (): void => {};
  const freed = new Promise<boolean>((resolve) => {
    wake = () => resolve(true);
    readSlotWaiters.add(wake);
  });
  return withDeadline(freed, deadline - performance.now(), () => false).finally(() =>
    readSlotWaiters.delete(wake),
  );
}

/**
 * {@link readAnchorPem}, stamped with when it started, waiting no later than `deadline` (a
 * `performance.now` time); a read cut short counts as inconclusive ({@link cutShort}).
 *
 * A file whose read is still running is never read again alongside it: the caller joins that read,
 * even one every earlier caller stopped waiting on. A new read starts only while fewer than
 * {@link MAX_RUNNING_READS} are running, and otherwise waits for one to end.
 */
async function sharedRead(file: string, deadline: number): Promise<StampedRead> {
  for (;;) {
    const running = inflightReads.get(fileId(file));
    if (running !== undefined) {
      return withDeadline(running, deadline - performance.now(), () => cutShort(file));
    }
    if (performance.now() >= deadline) {
      return cutShort(file); // a read nobody will wait for would only hold a slot
    }
    if (inflightReads.size < MAX_RUNNING_READS) {
      break;
    }
    if (!(await readSlotFreed(deadline))) {
      return cutShort(file);
    }
  }
  const readAt = ++readSeq;
  const pending: Promise<StampedRead> = readAnchorPem(file)
    .then((read) => ({ readAt, read }))
    .finally(() => {
      if (inflightReads.get(fileId(file)) === pending) {
        inflightReads.delete(fileId(file));
      }
      for (const wake of [...readSlotWaiters]) {
        wake();
      }
    });
  inflightReads.set(fileId(file), pending);
  return withDeadline(pending, deadline - performance.now(), () => cutShort(file));
}

/**
 * {@link sharedRead}, but never a read that started at or before `since` (a {@link readSeq} value):
 * a joined read that began before the caller's reason to read may predate the rotation it is looking
 * for, so once it ends the file is read again, within the same deadline. `worthAgain` lets a caller
 * skip that second read when the first already answers it.
 */
async function readSince(
  file: string,
  deadline: number,
  since: number,
  worthAgain: (read: PemRead) => boolean = () => true,
): Promise<StampedRead> {
  const first = await sharedRead(file, deadline);
  if (first.readAt === 0 || first.readAt > since || !worthAgain(first.read)) {
    return first;
  }
  const again = await sharedRead(file, deadline);
  // Cut short, the older read is still better than none.
  return again.readAt === 0 ? first : again;
}

/**
 * True when a refresh could anchor `key` from the engine's CLI: it is `messagefoundry.engineUrl`'s
 * host, that host is loopback, and no `caFile` claims it (a pin, usable or not, wins over the CLI's
 * answer, so asking would change nothing).
 */
function cliCouldAnchor(key: string): boolean {
  const url = engineUrl();
  return (
    // askCli's own guard: with no workspace, or an untrusted one, the CLI is never asked.
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
 * While an abandoned `cert inventory` child is alive, none: its exit runs one ({@link cliWanted}).
 * With no refresh pending, at most one per {@link FAILURE_REFRESH_MIN_MS}. With one pending, none at
 * once: a refresh that has not yet asked the CLI will see whatever caused this failure. One already
 * asking may not, since the CLI reads the engine's state partway through its run, so the failure is
 * noted and {@link startLateFollowUp} runs one more refresh when it finishes, unless that refresh
 * replaced the anchor the request failed with.
 */
function noteCliAnchorableFailure(key: string, usedCa: string | undefined): void {
  if (cliAbandoned) {
    // A refresh now would not start a second CLI beside it; that child's exit asks instead.
    cliWanted = true;
    return;
  }
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
 *     capped ({@link sharedRead}), waiting at most `followReadMs` ({@link Limits}). The engine renews
 *     its generated pair at startup into the same file (ADR 0172, 2026-09-26 amendment), and a
 *     `caFile` rotated in place behaves the same way. Nothing is spawned.
 *   * otherwise (no file, or its certificate is the one that just failed), for the engine
 *     `messagefoundry.engineUrl` names when it is loopback and no `caFile` claims it: start the full
 *     refresh in the BACKGROUND (see {@link noteCliAnchorableFailure} for when), and answer false.
 *     That covers the first-run gap (an engine started after the window opened mints its certificate
 *     only then). It is not awaited because it spawns the engine's CLI, which may take up to
 *     `cliAnswerMs`; a request waiting on it would no longer honour its own timeout. The refresh
 *     re-probes the status bar when it registers something.
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
  // Before the first refresh commits there is no snapshot, so this reads the configuration; again
  // after the read, so a setting changed meanwhile is seen.
  const fileFor = (): string | undefined =>
    registered.get(key)?.file ??
    (pinFiles ?? pinFilesOf(configuredPins())).get(key);
  const file = fileFor();
  // A read already running when this request failed may predate the rotation. Only when it returns
  // the certificate that just failed is the file read again; anything else answers this request.
  const deadline = performance.now() + limits.followReadMs;
  const stamped =
    file === undefined
      ? undefined
      : await readSince(file, deadline, readSeq, (r) => r.pem === usedCa);
  const read = stamped?.read.pem;
  // Read the registration again: a refresh may have committed while the file was being read.
  const held = registered.get(key);
  // The file must still be the one that describes this host, and no newer read of it registered: a
  // refresh that read it later, or moved the host to another file, has the newer answer, and the
  // branch below retries against that.
  const newer =
    held !== undefined &&
    file !== undefined &&
    sameFile(held.file, file) &&
    held.readAt > (stamped?.readAt ?? 0);
  const changed = read !== undefined && read !== usedCa;
  if (file !== undefined && stamped !== undefined && changed && sameFile(file, fileFor() ?? "") && !newer) {
    if (read !== held?.pem) {
      register({ url, file, pem: read, pinned: held?.pinned ?? true, readAt: stamped.readAt });
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

/** Shorten the waits in {@link Limits}; `forgetEngineTrust` restores them. For the shell test only. */
export function setEngineTrustLimitsForTest(next: Partial<Limits>): void {
  limits = { ...LIMITS, ...next };
}

/** Drop every anchor and reset the failure-refresh state. For the shell test only. */
export function forgetEngineTrust(): void {
  clearEngineTrustAnchors();
  setPinnedEngineHosts([]);
  registered.clear();
  claimedKeys = new Set();
  pinFiles = undefined;
  lastFailureRefresh = Number.NEGATIVE_INFINITY;
  lateFailure = undefined;
  inflightReads.clear();
  readSlotWaiters.clear();
  cliRun = undefined;
  cliAbandoned = false;
  cliWanted = false;
  deactivated = false;
  limits = LIMITS;
}

/**
 * Say so when configured targets have NO anchor, rather than letting them fail unexplained.
 *
 * `messagefoundry.environments` can name several engines, and the status bar probes the FIRST of
 * them rather than `engineUrl`. A target with no `caFile` and no loopback certificate from
 * `messagefoundry.serviceConfig` is verified against the default roots only, which is right for a
 * publicly trusted chain and fails for anything else.
 */
function warnAboutUnanchoredTargets(
  targets: readonly PinTarget[],
  pinned: ReadonlyMap<string, string>,
): void {
  const missing = targets.filter((t) => {
    const key = engineHostKey(t.url);
    return key !== undefined && isHttpsUrl(t.url) && !registered.has(key);
  });
  const unread = missing.filter((t) => pinned.has(engineHostKey(t.url) ?? ""));
  const unanchored = missing.filter((t) => !unread.includes(t));
  if (unread.length > 0) {
    engineLog().warn(
      `messagefoundry.environments pins ${unread.length} https target(s) whose caFile has not been ` +
        `read (${unread.map((t) => t.url).join(", ")}); requests to them are refused until it is, ` +
        `and never verified against the default roots.`,
    );
  }
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
  deactivated = false;
  setTrustFailureHandler(followCertificateChange);
  // Before the first refresh is queued: its file reads may take seconds, and a pinned host must not
  // be reachable on the default roots meanwhile.
  publishPinnedHosts(configuredPins());
  context.subscriptions.push({
    dispose: () => {
      setTrustFailureHandler(undefined);
      deactivated = true;
    },
  });
  void refreshEngineTrustThenRecheck();
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        e.affectsConfiguration("messagefoundry.engineUrl") ||
        e.affectsConfiguration("messagefoundry.environments") ||
        e.affectsConfiguration("messagefoundry.serviceConfig")
      ) {
        publishPinnedHosts(configuredPins()); // now, not when the queued refresh starts
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
