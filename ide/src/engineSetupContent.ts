// The guided engine-setup page's CONTENT MODEL (BACKLOG #238, ADR 0112 amendment 2026-07-16) — the
// copy and action buttons behind the pill's store-less "Set up an engine…" lead. Deliberately
// `vscode`-free (like cookbookRecipes.ts) so the plain-node unit suite can pin the two properties
// that carry the safety story:
//   1. every button dispatches a KNOWN CMD id — the webview shell (engineSetup.ts) executes only a
//      command it looked up HERE by button id, mirroring statusBar.ts's dispatch discipline, so the
//      webview message can never smuggle in an arbitrary command string;
//   2. the dev-engine section's copy is CONTEXT-HONEST — `messagefoundry.startEngine` is
//      palette-visible and this page is static/context-blind, so the copy must state the conditional
//      truth for both the store-less and the has-store launch (only the former shows the modal).
import { CMD } from "./engineStatusModel";

export interface SetupButton {
  /** Stable id the webview posts back; the shell resolves it HERE, never trusting the message's text. */
  readonly id: string;
  readonly label: string;
  /** A known CMD id — engine-setup.test.ts pins every command ⊆ Object.values(CMD). */
  readonly command: string;
}

export interface SetupSection {
  readonly id: string;
  readonly title: string;
  /** Paragraphs of plain text — the shell HTML-escapes them; nothing here is markup. */
  readonly body: readonly string[];
  readonly button?: SetupButton;
  /** "dev" renders the visually separated test-only block (the amendment's clearly-labelled dev engine). */
  readonly tone?: "dev";
}

export const SETUP_TITLE = "Set up an engine";

export const SETUP_LEDE =
  "This workspace has no engine store — no service TOML and no *.db. For a config-only / authoring " +
  "checkout that is the normal state, not a fault: the messages flow through an engine that runs " +
  "somewhere else. Pick the path that matches what you're doing.";

export const SETUP_SECTIONS: readonly SetupSection[] = [
  {
    id: "posture",
    title: "In production, the engine runs as a service",
    body: [
      "A production engine is installed as a Windows service (docs/SERVICE.md in the MessageFoundry " +
        "repository): it starts on boot, restarts on crash, and owns its store and logs where it is " +
        "installed. An authoring workspace like this one points at that engine — it doesn't host one, " +
        "so “nothing is running here” is exactly what you'd expect.",
    ],
  },
  {
    id: "point-at-engine",
    title: "Point the IDE at a running engine",
    body: [
      "If an engine is already running — a service on this machine, or another host — set the engine " +
        "target: messagefoundry.engineUrl, or messagefoundry.environments for named DEV/PROD targets. " +
        "The status pill, sign-in, and Stage → Promote all follow that target.",
    ],
    button: {
      id: "configure-target",
      label: "Configure engine target…",
      command: CMD.settings,
    },
  },
  {
    id: "copy-start",
    title: "Run the start command yourself",
    body: [
      "To launch an engine by hand — in the folder that actually holds its service TOML and store, on " +
        "this machine or another — copy the start command and paste it into a terminal there. The IDE " +
        "won't run it for you from this workspace.",
    ],
    button: {
      id: "copy-start-command",
      label: "Copy the engine start command",
      command: CMD.copyStart,
    },
  },
  {
    id: "python-environment",
    title: "Set up this workspace's Python environment",
    body: [
      "Fresh clone? If this workspace's Python can't import MessageFoundry yet, this creates a .venv " +
        "and installs the package. You confirm the exact steps first; they are then typed into a " +
        "visible terminal, so nothing runs out of sight.",
    ],
    button: {
      id: "setup-environment",
      label: "Set up environment",
      command: CMD.setupEnvironment,
    },
  },
  {
    id: "dev-engine",
    tone: "dev",
    title: "Testing only: start a developer engine here",
    body: [
      "This runs serve in this workspace with the project's Python — a local test engine, not a " +
        "production setup.",
      // The amendment's conditional truth, near-verbatim: the command is palette-visible and this page
      // is context-blind, so the copy states BOTH outcomes (runDirHasEngine guards only the store-less
      // launch — a has-store launch shows no modal).
      "If no engine store exists here, you'll be asked to confirm creating a NEW empty database " +
        "with no accounts; if one exists, this starts that engine.",
    ],
    button: {
      id: "start-dev-engine",
      label: "Start a developer engine…",
      command: CMD.startEngine,
    },
  },
];

/** The shell's ONLY lookup: webview button id → the declared button (and its known CMD), or nothing. */
export function buttonById(id: string): SetupButton | undefined {
  for (const s of SETUP_SECTIONS) {
    if (s.button !== undefined && s.button.id === id) {
      return s.button;
    }
  }
  return undefined;
}
