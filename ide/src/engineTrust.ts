// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// The shell around engineTrustModel: ask the ENGINE where its certificate is, read it, and register
// it with engineClient (BACKLOG #1695). Every decision worth testing lives in the model; this file
// is the vscode + filesystem + subprocess half.
import * as vscode from "vscode";

import { engineUrl, environments, isExecGated, runJson, serviceConfig, workspaceDir } from "./cli";
import { clearEngineTrustAnchors, setEngineTrustAnchor } from "./engineClient";
import { engineLog } from "./engineLog";
import { parseApiTls, schemeMismatch, trustAnchorFor } from "./engineTrustModel";
import type { ApiTlsFacts } from "./engineTrustModel";
import { readCapped } from "./symbolIndex";

/**
 * How much of a certificate file we are willing to read. A PEM chain is kilobytes; this only bounds
 * the damage if `messagefoundry.serviceConfig` names a TOML whose `[api].tls_cert_file` points at
 * something enormous, which would otherwise be read whole into the extension host.
 */
const MAX_PEM_BYTES = 512 * 1024;

/**
 * Ask the engine's CLI which certificate its API bind presents, and register it as the trust anchor
 * for the configured `messagefoundry.engineUrl`.
 *
 * **Fail-soft throughout.** Every failure here — no engine on PATH, no workspace, an untrusted
 * workspace, a `serviceConfig` that names nothing, an older CLI with no `api_tls` key, a certificate
 * not minted yet — leaves the client on Node's default CA set with verification on. The request then
 * fails with a trust error carrying the remedy (`trustRemedy`), which is a better outcome than a
 * half-configured client and is why nothing here throws.
 *
 * Resolves to true when an anchor was registered, so the caller can re-probe rather than leave a
 * stale verdict on screen.
 */
export async function refreshEngineTrust(): Promise<boolean> {
  // The same guard the three sibling CLI calls in extension.ts use. Without it, opening a loose .py
  // file with no folder spawns a Python interpreter for a command that can only fail: isExecGated()
  // is false when there is no workspace, so it does not cover this on its own.
  if (!workspaceDir() || isExecGated()) {
    return false;
  }

  // Drop every anchor first. Editing `messagefoundry.engineUrl` across hosts would otherwise leave
  // the previous host's certificate registered for the life of the extension host, so a target the
  // user moves away from and back to would be trusted from a cached read rather than a fresh one.
  clearEngineTrustAnchors();

  let payload: unknown;
  try {
    // `cert inventory` is read-only and starts no server; --service-config alone is a valid source.
    // The path is workspace-relative (like every other messagefoundry.* path setting), so it runs
    // from the workspace the same way alertEditor.ts runs `alert list`.
    payload = await runJson<unknown>(
      ["cert", "inventory", "--service-config", serviceConfig()],
      workspaceDir(),
    );
  } catch {
    return false; // no engine, no TOML, an older CLI — all "we learned nothing"
  }

  const facts = parseApiTls(payload);
  const url = engineUrl();
  const pem = readAnchorPem(trustAnchorFor(facts));
  setEngineTrustAnchor(url, pem);
  if (pem !== undefined) {
    engineLog().info(`trusting the engine certificate at ${trustAnchorFor(facts)} for ${url}`);
  }

  const mismatch = schemeMismatch(facts, url);
  if (mismatch !== undefined) {
    engineLog().warn(mismatch);
  }
  warnAboutUnanchoredTargets(facts);
  return pem !== undefined;
}

/**
 * Read a certificate PEM, or `undefined` if it is unreadable or over {@link MAX_PEM_BYTES}.
 *
 * `readCapped` rather than a statSync/readFileSync pair: it resolves the path ONCE and checks the
 * size against that descriptor, which is the CodeQL `js/file-system-race` fix `symbolIndex.ts`
 * already carries and pins. It also returns `undefined` on both failure modes, so "register
 * whatever we got, even nothing" stays one unconditional call at the site above.
 */
function readAnchorPem(anchor: string | undefined): string | undefined {
  if (anchor === undefined) {
    return undefined;
  }
  const pem = readCapped(anchor, MAX_PEM_BYTES);
  if (pem === undefined) {
    engineLog().warn(`could not read the engine certificate at ${anchor} — not trusting it`);
  }
  return pem;
}

/**
 * Say so when configured targets are NOT anchored, rather than letting them fail unexplained.
 *
 * `messagefoundry.environments` can name several engines, and the status bar probes the FIRST of
 * them rather than `engineUrl`. The anchor here comes from `messagefoundry.serviceConfig`, which
 * describes the local engine only — a remote engine reads its own filesystem — so those targets get
 * nothing from this path. Anchoring them needs a per-target trust source, which is unfiled work;
 * until then the honest thing is to name the gap in the log the user is told to read.
 */
function warnAboutUnanchoredTargets(facts: ApiTlsFacts | undefined): void {
  const named = environments();
  if (named.length === 0 || facts === undefined) {
    return;
  }
  engineLog().info(
    `messagefoundry.environments names ${named.length} target(s); their certificates are not ` +
      `trusted from messagefoundry.serviceConfig, which describes the local engine only. A remote ` +
      `engine's issuing CA has to be in this machine's trust store.`,
  );
}

/**
 * Refresh at activation, and again whenever a target or the service TOML setting moves.
 *
 * Activation-time is enough for the ordinary case because the engine mints its pair on its FIRST
 * run and reuses it forever after (`ensure_api_tls_material` refuses to overwrite a key). The one
 * gap is an engine that has never run when the window opens; that request fails with the trust
 * error and its remedy, and the next window — or a settings change — picks the certificate up.
 *
 * The re-check afterwards matters because the status bar starts probing on the same tick and its
 * first probe necessarily runs before the subprocess answers. Without it, a healthy engine renders
 * as "cannot verify" until the next 15-second poll, on every window open.
 */
export function registerEngineTrust(context: vscode.ExtensionContext): void {
  void refreshThenRecheck();
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        e.affectsConfiguration("messagefoundry.engineUrl") ||
        e.affectsConfiguration("messagefoundry.environments") ||
        e.affectsConfiguration("messagefoundry.serviceConfig")
      ) {
        void refreshThenRecheck();
      }
    }),
  );
}

async function refreshThenRecheck(): Promise<void> {
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
