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
  // Deliberately NOT mirroring the engine's `oidc` field (ADR 0142). Federated sign-in is
  // browser-only by design — it needs a redirect, a flow cookie, and a same-site landing hop, none
  // of which exist here — so surfacing it would offer the user a provider this client cannot drive.
  // The extra JSON field is simply ignored (structural typing), so nothing breaks by omitting it.
}
/** The engine's own `CurrentUser` (api/auth_models.py). We keep `roles`/`permissions` so a caller can
 *  tell the user WHAT their account can do, instead of discovering it as an opaque 403 later. */
interface CurrentUser {
  username: string;
  roles: string[];
  permissions: string[];
}

/** The engine's full LoginResponse. The client used to declare only `{token, must_change_password}` and
 *  silently drop the rest — including `mfa_required`, which is exactly the field that explains why an
 *  otherwise-valid token 403s on every step-up route (promote / config reload) until TOTP is enrolled. */
interface LoginResponse {
  token: string;
  token_type?: string;
  must_change_password: boolean;
  mfa_required?: boolean;
  user?: CurrentUser;
}

/** SecretStorage key for an engine URL (trailing slashes normalized so they don't fork the cache). */
function secretKey(url: string): string {
  return SECRET_PREFIX + url.replace(/\/+$/, "");
}

export async function clearToken(ctx: vscode.ExtensionContext, url: string): Promise<void> {
  await ctx.secrets.delete(secretKey(url));
}

/**
 * Warn about an account state the IDE cannot fix, and offer the one place that can. Credential
 * management (password rotation, MFA enrolment) belongs to the web console (ADR 0065) — the IDE names
 * the problem precisely and deep-links, rather than growing a second credential UI.
 */
async function showConsoleFix(url: string, problem: string, path: string): Promise<void> {
  const open = "Open the web console";
  const pick = await vscode.window.showWarningMessage(`MessageFoundry: ${problem}`, open);
  if (pick === open) {
    await vscode.env.openExternal(vscode.Uri.parse(url.replace(/\/+$/, "") + path));
  }
}

/**
 * Sign out for real: REVOKE the session on the engine, then forget the token locally.
 *
 * Dropping only the local copy is not signing out — it leaves the session alive on the engine until it
 * idles out (30 min) or hits its absolute cap, so "signed out" would be a lie told to a user who may have
 * just walked away from a shared machine. `POST /auth/logout` is must-change-exempt, so it works even for
 * an account that is 403'd on everything else.
 *
 * The local token is cleared in a `finally`: if the engine is unreachable we cannot revoke, but we must
 * still forget it here — refusing to sign out because the engine is down would be worse. The caller is told
 * which of the two happened rather than being given a blanket "signed out".
 */
export async function signOut(ctx: vscode.ExtensionContext, url: string): Promise<boolean> {
  const token = await peekToken(ctx, url);
  if (!token) {
    return true; // nothing to revoke
  }
  try {
    await postJson<unknown>(url, "/auth/logout", {}, token);
    return true;
  } catch {
    return false; // could not reach the engine to revoke — the session lives until it times out
  } finally {
    await clearToken(ctx, url);
  }
}

/**
 * The cached token for `url`, or undefined — NEVER prompts. For background callers (the live-status
 * poll): a poll must not pop a sign-in from a timer, so it reads passively and degrades to "no live
 * data" when there is no session. Interactive flows keep using {@link ensureToken}/{@link withAuth}.
 */
export async function peekToken(
  ctx: vscode.ExtensionContext,
  url: string,
): Promise<string | undefined> {
  return await ctx.secrets.get(secretKey(url));
}

/**
 * Prompt for credentials and sign in to `url`; stores + returns the token, or undefined if cancelled.
 *
 * EXPORTED (it used to be private, reachable only as a side-effect of promote) so the engine status bar
 * can offer "Sign in" directly — being signed out is the IDE's DEFAULT state against an auth-enabled
 * engine, and there was no way to act on it. The non-loopback/plain-http refusal below runs BEFORE any
 * credential prompt, so every new caller inherits ADR 0035's SEC-005 guard rather than re-implementing it.
 */
export async function signIn(ctx: vscode.ExtensionContext, url: string): Promise<string | undefined> {
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
    // Both of these produce a token that LOOKS fine and then 403s later, so say so now, at the moment
    // the user can act on it, rather than letting them discover it as an opaque failure mid-promote.
    if (res.must_change_password) {
      // The engine 403s this token on every route except /auth/logout, /auth/me and /me/password.
      void showConsoleFix(
        url,
        "this account must change its password before it can do anything.",
        "/ui/account/password",
      );
    } else if (res.mfa_required) {
      // Login succeeded and reads will work, but every STEP-UP route (promote → POST /config/reload)
      // stays 403 until TOTP is enrolled. The old client dropped this field entirely.
      void showConsoleFix(
        url,
        "this account needs MFA before it can deploy config (reads will work).",
        "/ui/account",
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
  return (await ctx.secrets.get(secretKey(url))) ?? (await signIn(ctx, url));
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
      const fresh = await signIn(ctx, url);
      if (fresh === undefined) {
        return undefined;
      }
      return await call(fresh);
    }
    throw e;
  }
}
