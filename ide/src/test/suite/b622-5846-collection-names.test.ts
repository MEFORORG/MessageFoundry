// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Batch 622 (BACKLOG #5846): the Test Bench indexes its collection map by the name the user typed or
// the webview sent. On a plain object, `__proto__` set the prototype instead of a key, so that
// collection was lost on load and on save, and `toString` read Object.prototype.toString as a saved
// collection. The store now hands back a null-prototype map; the on-disk JSON is unchanged.
import * as assert from "assert";

import {
  CollectionStore,
  type LegacyStore,
  type SecretStore,
  collectionsSecretKey,
} from "../../collectionStore";
import type { TestCollection } from "../../testCollections";

class FakeSecrets implements SecretStore {
  readonly data = new Map<string, string>();
  async get(key: string): Promise<string | undefined> {
    return this.data.get(key);
  }
  async store(key: string, value: string): Promise<void> {
    this.data.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }
}

class EmptyMemento implements LegacyStore {
  get<T>(): T | undefined {
    return undefined;
  }
  async update(): Promise<void> {
    return undefined;
  }
}

const SCOPE = "file:///ws/b622";

function coll(name: string): TestCollection {
  return { name, cases: [{ name: "c1.hl7", input: "MSH|^~\\&|A", expected: [], disposition: "PROCESSED" }] };
}

suite("b622 #5846 collection names that are Object.prototype keys", () => {
  test("a stored collection named __proto__ survives a load as an own key", async () => {
    const secrets = new FakeSecrets();
    // Written by hand: JSON.stringify of a plain object cannot produce this key, the old bug's other half.
    secrets.data.set(collectionsSecretKey(SCOPE), `{"__proto__":${JSON.stringify(coll("__proto__"))}}`);
    const map = await new CollectionStore(secrets, new EmptyMemento(), SCOPE).load();
    assert.ok(Object.hasOwn(map, "__proto__"));
    assert.strictEqual(map["__proto__"].name, "__proto__");
    assert.deepStrictEqual(Object.keys(map), ["__proto__"]);
  });

  test("a collection saved as __proto__ round-trips through save and load", async () => {
    const secrets = new FakeSecrets();
    const store = new CollectionStore(secrets, new EmptyMemento(), SCOPE);
    const map = await store.load();
    map["__proto__"] = coll("__proto__");
    await store.save(map);
    const raw = secrets.data.get(collectionsSecretKey(SCOPE)) ?? "";
    assert.ok(raw.includes('"__proto__"'), "the on-disk JSON should hold the key");
    const again = await store.load();
    assert.ok(Object.hasOwn(again, "__proto__"));
    assert.strictEqual(again["__proto__"].cases.length, 1);
  });

  test("a name such as toString or constructor is not a saved collection until one is saved", async () => {
    const secrets = new FakeSecrets();
    secrets.data.set(collectionsSecretKey(SCOPE), JSON.stringify({ A: coll("A") }));
    const store = new CollectionStore(secrets, new EmptyMemento(), SCOPE);
    const map = await store.load();
    assert.strictEqual(map["toString"], undefined);
    assert.strictEqual(map["constructor"], undefined);
    const empty = await new CollectionStore(new FakeSecrets(), new EmptyMemento(), SCOPE).load();
    assert.strictEqual(empty["toString"], undefined);
    map["toString"] = coll("toString");
    await store.save(map);
    const again = await store.load();
    assert.deepStrictEqual(Object.keys(again).sort(), ["A", "toString"]);
    assert.strictEqual(again["toString"].name, "toString");
  });
});
