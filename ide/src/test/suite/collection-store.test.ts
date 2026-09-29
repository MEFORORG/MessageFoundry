// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";

import {
  CollectionStore,
  CollectionStoreError,
  collectionsSecretKey,
  LEGACY_COLLECTIONS_KEY,
  type LegacyStore,
  type SecretStore,
} from "../../collectionStore";
import type { TestCollection } from "../../testCollections";

/** An in-memory SecretStorage stand-in that records every call. */
class FakeSecrets implements SecretStore {
  readonly data = new Map<string, string>();
  readonly calls: string[] = [];
  async get(key: string): Promise<string | undefined> {
    this.calls.push(`get ${key}`);
    return this.data.get(key);
  }
  async store(key: string, value: string): Promise<void> {
    this.calls.push(`store ${key}`);
    this.data.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.calls.push(`delete ${key}`);
    this.data.delete(key);
  }
}

/** An in-memory workspaceState stand-in. `update(key, undefined)` removes the key, as VS Code's does. */
class FakeMemento implements LegacyStore {
  readonly data = new Map<string, unknown>();
  get<T>(key: string): T | undefined {
    return this.data.get(key) as T | undefined;
  }
  async update(key: string, value: unknown): Promise<void> {
    if (value === undefined) {
      this.data.delete(key);
    } else {
      this.data.set(key, value);
    }
  }
}

const BODY = "MSH|^~\\&|APP|FAC|RCV|RFAC|20260101||ADT^A01|C1|P|2.5\rPID|1||MRN-123||DOE^JANE";

function coll(name: string, input = BODY): TestCollection {
  return { name, cases: [{ name: "case.hl7", input, expected: [{ to: "OB", payload: input }] }] };
}

suite("collectionStore -- Test Bench case bodies live in SecretStorage (BACKLOG #1174)", () => {
  test("save then load round-trips, and the body is never written to workspaceState", async () => {
    const secrets = new FakeSecrets();
    const memento = new FakeMemento();
    const store = new CollectionStore(secrets, memento, "file:///ws/a");
    await store.save({ smoke: coll("smoke") });
    assert.deepStrictEqual(await store.load(), { smoke: coll("smoke") });
    assert.strictEqual(memento.data.size, 0);
    const stored = secrets.data.get(collectionsSecretKey("file:///ws/a"));
    assert.ok(stored?.includes("MRN-123"), "the body is in SecretStorage");
  });

  test("an empty store loads as an empty map", async () => {
    const store = new CollectionStore(new FakeSecrets(), new FakeMemento(), "file:///ws/a");
    assert.deepStrictEqual(await store.load(), {});
  });

  test("each workspace has its own key, as workspaceState was per-workspace", async () => {
    const secrets = new FakeSecrets();
    const a = new CollectionStore(secrets, new FakeMemento(), "file:///ws/a");
    const b = new CollectionStore(secrets, new FakeMemento(), "file:///ws/b");
    await a.save({ onlyA: coll("onlyA") });
    assert.deepStrictEqual(await b.load(), {});
    assert.notStrictEqual(collectionsSecretKey("file:///ws/a"), collectionsSecretKey("file:///ws/b"));
  });

  test("the secret key names no local path", () => {
    const key = collectionsSecretKey("file:///srv/feeds/demo-project");
    assert.ok(!key.includes("feeds") && !key.includes("demo-project"), key);
    assert.ok(key.startsWith(`${LEGACY_COLLECTIONS_KEY}.`), key);
  });

  test("migration moves workspaceState collections into SecretStorage and deletes the old copy", async () => {
    const secrets = new FakeSecrets();
    const memento = new FakeMemento();
    memento.data.set(LEGACY_COLLECTIONS_KEY, { old: coll("old") });
    const store = new CollectionStore(secrets, memento, "file:///ws/a");
    assert.deepStrictEqual(await store.load(), { old: coll("old") });
    assert.strictEqual(memento.get(LEGACY_COLLECTIONS_KEY), undefined, "legacy copy removed");
    assert.ok(secrets.data.get(collectionsSecretKey("file:///ws/a"))?.includes("MRN-123"));
  });

  test("migration writes the secret BEFORE it deletes the legacy copy", async () => {
    const secrets = new FakeSecrets();
    const order: string[] = [];
    const memento: LegacyStore = {
      get: <T>(key: string) =>
        (key === LEGACY_COLLECTIONS_KEY ? { old: coll("old") } : undefined) as T | undefined,
      update: async () => {
        order.push(`legacy-delete after ${secrets.data.size} secret(s)`);
      },
    };
    await new CollectionStore(secrets, memento, "file:///ws/a").load();
    assert.deepStrictEqual(order, ["legacy-delete after 1 secret(s)"]);
  });

  test("a crash between the two migration steps is finished by the next load, secret copy winning", async () => {
    const secrets = new FakeSecrets();
    const memento = new FakeMemento();
    // State after a crash: the secret already holds a newer "shared", the legacy copy survived.
    await secrets.store(
      collectionsSecretKey("file:///ws/a"),
      JSON.stringify({ shared: coll("shared", "NEWER") }),
    );
    memento.data.set(LEGACY_COLLECTIONS_KEY, { shared: coll("shared", "OLDER"), old: coll("old") });
    const loaded = await new CollectionStore(secrets, memento, "file:///ws/a").load();
    assert.strictEqual(loaded.shared.cases[0].input, "NEWER");
    assert.deepStrictEqual(Object.keys(loaded).sort(), ["old", "shared"]);
    assert.strictEqual(memento.data.size, 0);
  });

  test("an empty legacy map is just removed", async () => {
    const secrets = new FakeSecrets();
    const memento = new FakeMemento();
    memento.data.set(LEGACY_COLLECTIONS_KEY, {});
    assert.deepStrictEqual(await new CollectionStore(secrets, memento, "file:///ws/a").load(), {});
    assert.strictEqual(memento.data.size, 0);
    assert.strictEqual(secrets.data.size, 0);
  });

  test("migration runs once per store, not on every call", async () => {
    const secrets = new FakeSecrets();
    const memento = new FakeMemento();
    const store = new CollectionStore(secrets, memento, "file:///ws/a");
    await store.load();
    // A value appearing in workspaceState later is not this build's to write; it is not re-read.
    memento.data.set(LEGACY_COLLECTIONS_KEY, { late: coll("late") });
    assert.deepStrictEqual(await store.load(), {});
  });

  test("a save racing the first load is not overwritten by the migration", async () => {
    const secrets = new FakeSecrets();
    const memento = new FakeMemento();
    memento.data.set(LEGACY_COLLECTIONS_KEY, { old: coll("old") });
    const store = new CollectionStore(secrets, memento, "file:///ws/a");
    const loading = store.load();
    const saving = store.save({ old: coll("old"), added: coll("added") });
    await Promise.all([loading, saving]);
    assert.deepStrictEqual(Object.keys(await store.load()).sort(), ["added", "old"]);
  });

  test("a failed migration is retried on the next call", async () => {
    const secrets = new FakeSecrets();
    const memento = new FakeMemento();
    memento.data.set(LEGACY_COLLECTIONS_KEY, { old: coll("old") });
    let fail = true;
    const flaky: SecretStore = {
      get: (key) => secrets.get(key),
      store: async (key, value) => {
        if (fail) {
          throw new Error("keychain unavailable");
        }
        await secrets.store(key, value);
      },
      delete: (key) => secrets.delete(key),
    };
    const store = new CollectionStore(flaky, memento, "file:///ws/a");
    await assert.rejects(store.load());
    assert.ok(memento.data.has(LEGACY_COLLECTIONS_KEY), "legacy copy kept when the secret write failed");
    fail = false;
    assert.deepStrictEqual(await store.load(), { old: coll("old") });
    assert.strictEqual(memento.data.size, 0);
  });

  test("an unreadable stored value raises without echoing any of it", async () => {
    const secrets = new FakeSecrets();
    await secrets.store(collectionsSecretKey("file:///ws/a"), "{not json MRN-123");
    const store = new CollectionStore(secrets, new FakeMemento(), "file:///ws/a");
    await assert.rejects(store.load(), (e: unknown) => {
      assert.ok(e instanceof CollectionStoreError);
      assert.ok(!String(e).includes("MRN-123"), String(e));
      return true;
    });
  });
});
