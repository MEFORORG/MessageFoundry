// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import { assertTrustworthy, measureDelivery } from "../deliveryProbe";

// ASVS 3.5.5 (BACKLOG #1123). The probe and what it asserts live in ../deliveryProbe.ts; this is its
// mocha entry for the full suite. The floor build runs the same probe through ../probeHost.ts.
// Needs the Extension Host, so package.json's test:unit leg ignores this file.
suite("webview delivery probe (ASVS 3.5.5 origin arm)", () => {
  test("a host message arrives same-origin, with a tuple origin, from a source that is not the page", async function () {
    this.timeout(60_000);
    assertTrustworthy(await measureDelivery());
  });
});
