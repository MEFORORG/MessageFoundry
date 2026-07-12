import * as assert from "assert";

import {
  codeSetNameFromPath,
  isReadOnlyCodeSet,
  isUnderConfigDir,
  pickCurrentConnection,
  shouldPushDocumentChange,
  type ConnectionListItem,
} from "../../configEditorModel";

// Pure customEditor document↔form mapping (#221b) — exercised vscode-free: the code-set name/path
// mapping, the read-only decision, the webview↔document loop guard, and the connections picker default.
suite("configEditorModel — code-set path mapping", () => {
  test("name is the basename without the .csv/.toml extension (both separators)", () => {
    assert.strictEqual(codeSetNameFromPath("/ws/samples/config/codesets/epic_diets.csv"), "epic_diets");
    assert.strictEqual(codeSetNameFromPath("C:\\ws\\config\\codesets\\epic_diets.csv"), "epic_diets");
    assert.strictEqual(codeSetNameFromPath("codesets/legacy.toml"), "legacy");
    assert.strictEqual(codeSetNameFromPath("plain"), "plain");
  });

  test("a .toml code set opens read-only; a .csv does not", () => {
    assert.strictEqual(isReadOnlyCodeSet("codesets/legacy.toml"), true);
    assert.strictEqual(isReadOnlyCodeSet("codesets/epic_diets.csv"), false);
  });
});

suite("configEditorModel — webview↔document loop guard", () => {
  test("our own CLI write (savingFromWebview) is swallowed — no re-render echo", () => {
    assert.strictEqual(
      shouldPushDocumentChange({ savingFromWebview: true, changedText: "new", lastRenderedText: "old" }),
      false,
    );
  });

  test("an external edit that changes content re-renders", () => {
    assert.strictEqual(
      shouldPushDocumentChange({ savingFromWebview: false, changedText: "new", lastRenderedText: "old" }),
      true,
    );
  });

  test("a no-op change (same content) does not re-render", () => {
    assert.strictEqual(
      shouldPushDocumentChange({ savingFromWebview: false, changedText: "same", lastRenderedText: "same" }),
      false,
    );
  });
});

suite("configEditorModel — config-dir scope guard (F3)", () => {
  test("the config-dir's own connections.toml is under the (relative) config dir", () => {
    assert.strictEqual(
      isUnderConfigDir("/ws/samples/config/connections.toml", "/ws", "samples/config"),
      true,
    );
  });

  test("a codesets/*.csv nested under the config dir is under it", () => {
    assert.strictEqual(
      isUnderConfigDir("/ws/samples/config/codesets/diets.csv", "/ws", "samples/config"),
      true,
    );
  });

  test("a same-named file elsewhere in the workspace is NOT under the config dir", () => {
    assert.strictEqual(
      isUnderConfigDir("/ws/other/connections.toml", "/ws", "samples/config"),
      false,
    );
  });

  test("a sibling dir that merely shares a name prefix is not a match (boundary check)", () => {
    // "samples/config-backup" must not count as under "samples/config".
    assert.strictEqual(
      isUnderConfigDir("/ws/samples/config-backup/connections.toml", "/ws", "samples/config"),
      false,
    );
  });

  test("Windows paths + an absolute config dir, case-insensitively", () => {
    assert.strictEqual(
      isUnderConfigDir("C:\\WS\\Config\\connections.toml", "C:\\ws", "C:\\ws\\config"),
      true,
    );
    assert.strictEqual(
      isUnderConfigDir("C:\\ws\\elsewhere\\connections.toml", "C:\\ws", "C:\\ws\\config"),
      false,
    );
  });
});

suite("configEditorModel — connections picker default", () => {
  const entries: ConnectionListItem[] = [
    { name: "IB_ACME_ADT", direction: "inbound", transport: "mllp" },
    { name: "OB_ACME_ADT", direction: "outbound", transport: "mllp" },
  ];

  test("requested connection wins when it still exists", () => {
    assert.strictEqual(pickCurrentConnection(entries, "OB_ACME_ADT"), "OB_ACME_ADT");
  });

  test("falls back to the first connection when the request is gone", () => {
    assert.strictEqual(pickCurrentConnection(entries, "DELETED"), "IB_ACME_ADT");
  });

  test("no request → first connection", () => {
    assert.strictEqual(pickCurrentConnection(entries, undefined), "IB_ACME_ADT");
  });

  test("empty file → undefined (the blank 'new' form)", () => {
    assert.strictEqual(pickCurrentConnection([], undefined), undefined);
  });
});
