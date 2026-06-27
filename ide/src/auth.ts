// Authentication to the MessageFoundry engine API. The engine requires auth (opaque bearer
// sessions), and promote drives the *running* engine, so it must sign in. Tokens are cached in
// VS Code SecretStorage (never written to disk by us), keyed by engine URL, and re-acquired on
// demand or after a 401.
import * as vscode from "vscode";
import { getJson, HttpError, postJson } from "./engineClient";
import { assertTargetAllowed } from "./engineTarget";

const SECRET_PREFIX = "messagefoundry.token:";

interface ProvidersInfo {
  local: boolean;
  ad: boolean;
  kerberos: boolean;
}
interface LoginResponse {
  token: string;
  must_change_password: boolean;
}

/** SecretStorage key for an engine URL (trailing slashes normalized so they don't fork the cache). */
function secretKey(url: string): string {
  return SECRET_PREFIX + url.replace(/\/+$/, "");
}

export async function clearToken(ctx: vscode.ExtensionContext, url: string): Promise<void> {
  await ctx.secrets.delete(secretKey(url));
}

/** Prompt for credentials and sign in to `url`; stores + returns the token, or undefined if cancelled. */
async function login(ctx: vscode.ExtensionContext, url: string): Promise<string | undefined> {
  // Belt-and-suspenders: any caller of login()/withAuth() (not just promote) inherits the non-TLS
  // refusal — never prompt for or send credentials in clear to a non-loopback host (SEC-005).
  const gate = assertTargetAllowed(url);
  if (!gate.ok) {
    void vscode.window.showErrorMessage(`MessageFoundry: ${gate.reason}`);
    return undefined;
  }
  let provider = "local";
  try {
    const providers = await getJson<ProvidersInfo>(url, "/auth/providers");
    if (providers.ad) {
      const pick = await vscode.window.showQuickPick(
        [
          { label: "Local account", value: "local" },
          { label: "Active Directory", value: "ad" },
        ],
        { placeHolder: `Sign in to ${url}`, ignoreFocusOut: true },
      );
      if (!pick) {
        return undefined;
      }
      provider = pick.value;
    }
  } catch {
    // /auth/providers unreachable or auth disabled — fall through to a plain local sign-in attempt.
  }
  // Re-prompt on a bad password (the common mistake) instead of tearing down the whole promote;
  // a non-auth failure (network/429/503) still propagates, and a cancelled prompt returns undefined.
  for (let attempt = 0; attempt < 3; attempt++) {
    const username = await vscode.window.showInputBox({
      prompt: `MessageFoundry username for ${url}`,
      ignoreFocusOut: true,
    });
    if (!username) {
      return undefined; // cancelled
    }
    const password = await vscode.window.showInputBox({
      prompt: "Password",
      password: true,
      ignoreFocusOut: true,
    });
    if (password === undefined) {
      return undefined; // cancelled
    }
    let res: LoginResponse;
    try {
      res = await postJson<LoginResponse>(url, "/auth/login", { username, password, provider });
    } catch (e) {
      if (e instanceof HttpError && e.status === 401) {
        void vscode.window.showWarningMessage("MessageFoundry: invalid credentials — try again.");
        continue;
      }
      throw e;
    }
    await ctx.secrets.store(secretKey(url), res.token);
    if (res.must_change_password) {
      void vscode.window.showWarningMessage(
        "MessageFoundry: this account must change its password — set a new one in the Console.",
      );
    }
    return res.token;
  }
  void vscode.window.showErrorMessage("MessageFoundry: sign-in failed after several attempts.");
  return undefined;
}

/** A cached token for `url`, prompting an interactive sign-in if there isn't one. */
export async function ensureToken(
  ctx: vscode.ExtensionContext,
  url: string,
): Promise<string | undefined> {
  return (await ctx.secrets.get(secretKey(url))) ?? (await login(ctx, url));
}

/**
 * Run `call(token)` against `url`, transparently authenticating: a cached token is used first; a
 * **401** (expired/invalid) clears it and retries once with a fresh sign-in. A 403 (authenticated
 * but lacking the permission) is NOT retried — re-login as the same user wouldn't help — and
 * propagates so the caller can surface it. Returns undefined if the user cancels a sign-in.
 */
export async function withAuth<T>(
  ctx: vscode.ExtensionContext,
  url: string,
  call: (token: string) => Promise<T>,
): Promise<T | undefined> {
  const token = await ensureToken(ctx, url);
  if (token === undefined) {
    return undefined; // sign-in cancelled
  }
  try {
    return await call(token);
  } catch (e) {
    if (e instanceof HttpError && e.status === 401) {
      await clearToken(ctx, url);
      const fresh = await login(ctx, url);
      if (fresh === undefined) {
        return undefined;
      }
      return await call(fresh);
    }
    throw e;
  }
}
