// Pure (vscode-free) model behind the multi-step QuickInput new-connection wizard (#221e). The
// wizard (connectionQuickInput.ts) is a keyboard-first alternative to the connectionEditor webview
// form; both write via the SAME `messagefoundry connection upsert` CLI. Keeping the answer→ConnObj
// mapping, the upsert argv, the per-step validators, and the step plan here (no vscode) lets the whole
// state machine be unit-tested node-side (the CI ide job has no Python / Extension Host).

/** The connection object the `connection upsert --data <json>` CLI consumes (ADR 0007). Mirrors the
 *  shape connectionEditor.ts builds; kept local so this module imports nothing from vscode/cli. */
export interface WizardConnObj {
  direction: "inbound" | "outbound";
  name: string;
  transport: string;
  router?: string;
  settings?: Record<string, unknown>;
  ack_mode?: string;
  strict?: boolean;
  ordering?: string;
  retry?: Record<string, unknown>;
}

/** Transports the keyboard-first wizard offers. Deliberately only the ones it can fully configure via
 *  QuickInput steps — the ones `settingKeysFor` has hints for (host/port/directory). The webview form
 *  (connectionEditor.ts) still offers the full transport list and arbitrary settings; the wizard is the
 *  keyboard-first fallback, so it MUST NOT list a transport it would then leave unconfigured (a wizard
 *  that offers `rest`/`soap`/`database`/… but collects none of their settings writes a broken stub). */
export const WIZARD_TRANSPORTS = ["mllp", "tcp", "file"];

/** The answers collected across the wizard steps. Optional fields stay unset until their step runs. */
export interface WizardState {
  direction?: "inbound" | "outbound";
  name?: string;
  transport?: string;
  router?: string; // inbound only
  host?: string; // outbound MLLP/TCP
  port?: string; // MLLP/TCP (as typed; coerced on build)
  directory?: string; // file transport
  /** Set true ONLY when the step chain ran to its terminal step (see shouldSaveConnection). A cancel /
   *  dismiss at any step leaves this unset even though the earlier required fields are populated. */
  completed?: boolean;
  /** The wizard's total step count, locked once direction+transport are chosen so the "Step X of N"
   *  header stays stable for the tail steps instead of shrinking as optimistic defaults resolve. */
  totalSteps?: number;
}

/**
 * Whether the collected answers should be written as a connection. The gate is the EXPLICIT
 * {@link WizardState.completed} flag — set only when the step chain reaches its terminal step — NOT the
 * mere presence of the required fields. That distinction is the whole point: direction/transport/name
 * are all set by step 3, so a cancel (Esc) on a later settings/router step leaves them populated; a
 * required-field check would then mistake that cancel for a finished wizard and save a partial
 * connection. Only an explicit completion signal is trustworthy here.
 */
export function shouldSaveConnection(state: WizardState): boolean {
  return state.completed === true;
}

/** The suggested per-transport setting keys the wizard prompts for (matches the webview form's HINTS). */
export function settingKeysFor(transport: string, direction: "inbound" | "outbound"): string[] {
  const key = `${transport}:${direction}`;
  const hints: Record<string, string[]> = {
    "mllp:inbound": ["port"],
    "mllp:outbound": ["host", "port"],
    "tcp:inbound": ["port"],
    "tcp:outbound": ["host", "port"],
    "file:inbound": ["directory"],
    "file:outbound": ["directory"],
  };
  return hints[key] ?? [];
}

/** Coerce a typed setting value the way the webview form does: booleans, ints, floats, else the string. */
export function coerceSetting(text: string): unknown {
  if (text === "true") {
    return true;
  }
  if (text === "false") {
    return false;
  }
  if (/^-?\d+$/.test(text)) {
    return parseInt(text, 10);
  }
  if (/^-?\d*\.\d+$/.test(text)) {
    return parseFloat(text);
  }
  return text;
}

/** A connection name must be non-empty and use the connection-name alphabet (letters/digits/_). Returns
 *  an error string (for InputBox validation) or undefined when valid. */
export function validateName(value: string): string | undefined {
  const v = value.trim();
  if (!v) {
    return "A connection name is required (convention: [TYPE]_[PARTNER]_[MESSAGE], e.g. IB_ACME_ADT).";
  }
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(v)) {
    return "Use letters, digits, and underscores only, starting with a letter.";
  }
  return undefined;
}

/** A port (when required) must be an integer in 1–65535. Returns an error string or undefined. */
export function validatePort(value: string): string | undefined {
  const v = value.trim();
  if (!/^\d+$/.test(v)) {
    return "Enter a port number (1–65535).";
  }
  const n = parseInt(v, 10);
  if (n < 1 || n > 65535) {
    return "Port must be between 1 and 65535.";
  }
  return undefined;
}

/** A required free-text answer (host/directory) must be non-empty. Returns an error string or undefined. */
export function validateRequired(value: string, label: string): string | undefined {
  return value.trim() ? undefined : `${label} is required.`;
}

/**
 * Assemble the ConnObj from collected answers, applying the same rules the webview form does: only the
 * transport-relevant settings are included; inbound carries its router; blank optionals are dropped.
 * Pure and total — the caller has already validated each field.
 */
export function buildConnObj(state: WizardState): WizardConnObj {
  const direction = state.direction ?? "inbound";
  const transport = state.transport ?? "mllp";
  const conn: WizardConnObj = { direction, name: (state.name ?? "").trim(), transport };

  const settings: Record<string, unknown> = {};
  const keys = settingKeysFor(transport, direction);
  if (keys.includes("host") && state.host && state.host.trim()) {
    settings.host = state.host.trim();
  }
  if (keys.includes("port") && state.port && state.port.trim()) {
    settings.port = coerceSetting(state.port.trim());
  }
  if (keys.includes("directory") && state.directory && state.directory.trim()) {
    settings.directory = state.directory.trim();
  }
  if (Object.keys(settings).length > 0) {
    conn.settings = settings;
  }
  if (direction === "inbound" && state.router && state.router.trim()) {
    conn.router = state.router.trim();
  }
  return conn;
}

/** The `messagefoundry connection upsert` argv (sans the `--json` the runJson helper appends). */
export function connectionUpsertArgs(configDir: string, conn: WizardConnObj): string[] {
  return ["connection", "upsert", "--config", configDir, "--data", JSON.stringify(conn)];
}
