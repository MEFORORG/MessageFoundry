// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The one plain GET the OS trust store probe's controls make (BACKLOG #4576), shared by the launcher,
// in plain Node, and by osTrustProbeHost.ts, inside VS Code. Which `https` module's `get` it goes
// through is the caller's choice, because that choice is what a control measures.
import type * as https from "node:https";

import { outcomeOf, TRUSTED } from "./osTrustProbeModel";
import type { Outcome } from "./osTrustProbeModel";

/** Long enough for a cold runner, short enough that a hung server cannot eat the job's budget. */
export const PROBE_TIMEOUT_MS = 10_000;

/**
 * GET `url` through `get` and settle as an {@link Outcome}; never rejects. Any 2xx is trusted:
 * verification finished before a byte of the response could arrive.
 */
export function getOutcome(
  get: typeof https.get,
  url: string,
  options: https.RequestOptions,
): Promise<Outcome> {
  return new Promise((resolve) => {
    const req = get(url, options, (res) => {
      res.resume();
      const status = res.statusCode ?? 0;
      const ok = status >= 200 && status < 300;
      resolve(ok ? TRUSTED : { result: "error", code: `HTTP_${status}` });
    });
    req.setTimeout(PROBE_TIMEOUT_MS, () =>
      req.destroy(Object.assign(new Error("timed out"), { code: "MF_TIMEOUT" })),
    );
    req.on("error", (err) => resolve(outcomeOf(err)));
  });
}
