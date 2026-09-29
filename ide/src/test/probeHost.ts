// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import { assertTrustworthy, measureDelivery } from "./deliveryProbe";

// The extensionTestsPath runTest.ts uses at the floor VS Code build: the delivery probe alone, with
// no mocha. mocha 12 needs a Node that can require() an ES module (its engines field says
// ^20.19.0 || >=22.12.0), and the floor build's Extension Host carries an older Node, so the full
// suite cannot load there. Measured 2026-09-28 at 1.95.0: ERR_REQUIRE_ESM from mocha's own
// lib/mocha.cjs. The probe needs nothing mocha provides, so it runs here directly.
export async function run(): Promise<void> {
  assertTrustworthy(await measureDelivery());
}
