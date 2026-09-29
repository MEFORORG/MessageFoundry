// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Where the Test Bench keeps saved regression collections (BACKLOG #168, ADR 0121; moved by BACKLOG
// #1174). Case bodies are PHI, so they live in VS Code SecretStorage -- the OS-keychain-backed store
// auth.ts already uses for the engine bearer token -- and not in plain workspaceState, which VS Code
// writes to disk unencrypted. No `vscode` import: the two stores are passed in, so this is unit-testable
// in isolation like testCollections.ts.

import { createHash } from "node:crypto";

import type { TestCollection } from "./testCollections";

/** The subset of `vscode.SecretStorage` this module uses. */
export interface SecretStore {
  get(key: string): PromiseLike<string | undefined>;
  store(key: string, value: string): PromiseLike<void>;
  delete(key: string): PromiseLike<void>;
}

/** The subset of `vscode.Memento` (workspaceState) this module uses, for the one-time migration. */
export interface LegacyStore {
  get<T>(key: string): T | undefined;
  update(key: string, value: unknown): PromiseLike<void>;
}

/** The workspaceState key collections lived under before BACKLOG #1174. Read only to migrate. */
export const LEGACY_COLLECTIONS_KEY = "messagefoundry.testBench.collections";

/**
 * The SecretStorage key for one workspace's collections. SecretStorage is shared by every workspace
 * that runs the extension, while workspaceState was per-workspace, so the key carries a workspace
 * scope. The scope is hashed so the key names no local path.
 */
export function collectionsSecretKey(workspaceScope: string): string {
  const digest = createHash("sha256").update(workspaceScope, "utf8").digest("hex").slice(0, 32);
  return `${LEGACY_COLLECTIONS_KEY}.${digest}`;
}

/** Raised when the stored value cannot be read back. Its message never carries the stored text. */
export class CollectionStoreError extends Error {
  override name = "CollectionStoreError";
}

function parseCollections(raw: string): Record<string, TestCollection> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Never echo `raw` or the parser's message: either can quote a case body.
    throw new CollectionStoreError("saved Test Bench collections are unreadable");
  }
  return validCollections(parsed);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isCollection(v: unknown): v is TestCollection {
  return (
    isRecord(v) &&
    typeof v.name === "string" &&
    Array.isArray(v.cases) &&
    v.cases.every(
      (c: unknown) =>
        isRecord(c) &&
        typeof c.name === "string" &&
        typeof c.input === "string" &&
        Array.isArray(c.expected) &&
        c.expected.every(
          (d: unknown) => isRecord(d) && typeof d.to === "string" && typeof d.payload === "string",
        ),
    )
  );
}

/**
 * Keep only well-formed collections. One malformed entry must not block the list, or the user could
 * never reach Delete. A value that is not a map at all is unreadable as a whole.
 */
function validCollections(v: unknown): Record<string, TestCollection> {
  if (!isRecord(v)) {
    throw new CollectionStoreError("saved Test Bench collections are unreadable");
  }
  const out: Record<string, TestCollection> = {};
  for (const [name, coll] of Object.entries(v)) {
    if (isCollection(coll)) {
      out[name] = coll;
    }
  }
  return out;
}

/**
 * Load, save and migrate one workspace's collections.
 *
 * Migration runs on the first load: any map still in workspaceState is merged into SecretStorage and
 * then deleted from workspaceState. It writes the secret BEFORE it deletes the legacy copy, so a crash
 * between the two leaves both, and the next load finishes the job. On a name held in both places the
 * SecretStorage copy wins, because it can only have been written after the migration started.
 */
export class CollectionStore {
  private readonly key: string;
  private migration: Promise<void> | undefined;

  constructor(
    private readonly secrets: SecretStore,
    private readonly legacy: LegacyStore,
    workspaceScope: string,
  ) {
    this.key = collectionsSecretKey(workspaceScope);
  }

  async load(): Promise<Record<string, TestCollection>> {
    await this.migrate();
    return this.readSecret();
  }

  async save(map: Record<string, TestCollection>): Promise<void> {
    await this.migrate();
    await this.secrets.store(this.key, JSON.stringify(map));
  }

  private async readSecret(): Promise<Record<string, TestCollection>> {
    const raw = await this.secrets.get(this.key);
    return raw === undefined ? {} : parseCollections(raw);
  }

  /**
   * One migration per store, shared by every caller that arrives while it runs. Without the shared
   * promise, a save racing a first load could land and then be overwritten by the load's merge.
   */
  private migrate(): Promise<void> {
    this.migration ??= this.moveLegacy().catch((e: unknown) => {
      this.migration = undefined; // let the next call retry
      throw e;
    });
    return this.migration;
  }

  /** Delete this workspace's saved collections: the way out of a stored value that cannot be read. */
  async reset(): Promise<void> {
    await this.secrets.delete(this.key);
  }

  private async moveLegacy(): Promise<void> {
    const old = this.legacy.get<unknown>(LEGACY_COLLECTIONS_KEY);
    if (old !== undefined) {
      // Only this extension wrote the legacy key, but it is still checked the same way.
      const moved = isRecord(old) ? validCollections(old) : {};
      if (Object.keys(moved).length > 0) {
        const current = await this.readSecret();
        await this.secrets.store(this.key, JSON.stringify({ ...moved, ...current }));
      }
      // update(key, undefined) removes the key from workspaceState.
      await this.legacy.update(LEGACY_COLLECTIONS_KEY, undefined);
    }
  }
}
