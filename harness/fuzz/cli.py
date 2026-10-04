# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``python -m harness --fuzz``: exit 0 when every invariant held, 1 when one broke, 2 on setup."""

from __future__ import annotations

import math
import sys
from collections.abc import Sequence
from pathlib import Path

from harness.endpoints import Endpoints
from harness.fuzz.campaign import FuzzConfig, SetupError, replay, run
from harness.fuzz.transport import build_transport
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.terminal_text import escape_for_terminal

EXIT_PASS = 0
EXIT_INVARIANT = 1
EXIT_SETUP = 2


def main(
    *,
    engine_url: str,
    token: str | None,
    cacert: str | None,
    endpoint_overrides: dict[str, str],
    driver: str,
    endpoint: str | None,
    seed: int,
    iterations: int,
    seconds: float | None,
    batch: int,
    out_dir: str | None,
    reply_timeout: float,
    replay_files: Sequence[str] = (),
) -> int:
    def fail_setup(message: str) -> int:
        # A SetupError can carry the engine API's own reply (an ApiFault's 4xx body), so the line
        # is escaped, newline included, before the operator's terminal sees it (ASVS 1.1.2).
        print(f"fuzz setup: {escape_for_terminal(message, single_line=True)}", file=sys.stderr)
        return EXIT_SETUP

    if not math.isfinite(reply_timeout) or reply_timeout <= 0:
        return fail_setup(f"--timeout must be a positive number of seconds, got {reply_timeout}")
    try:
        config = FuzzConfig(
            seed=seed,
            iterations=iterations,
            seconds=seconds,
            batch=batch,
            out_dir=None if out_dir is None else Path(out_dir),
        )
        endpoints = Endpoints(endpoint_overrides)
        # Every endpoint, as --scenario does: a malformed MEFOR_VALUE_HARNESS_* value is a setup
        # error now, not a traceback halfway through a campaign.
        endpoints.validate()
        transport = build_transport(driver, endpoints, endpoint, timeout=reply_timeout)
    except (KeyError, ValueError) as exc:
        return fail_setup(f"bad endpoint or option: {exc}")
    target = f"{driver} endpoint {endpoint or 'default'!r}"
    try:
        with EngineClient(engine_url, cacert=cacert) as client:
            if token:
                client.set_token(token)
            if replay_files:
                print(f"fuzz replay: {len(replay_files)} file(s) -> {target}")
                result = replay(client, transport, [Path(p) for p in replay_files], config)
            else:
                budget = "none" if seconds is None else f"{seconds:g}s"
                print(
                    f"fuzz: seed={seed} iterations={iterations} batch={batch} budget={budget} "
                    f"-> {target}; failing cases go to "
                    f"{config.out_dir or 'a fresh private temp directory'}"
                )
                result = run(client, transport, config)
    except (SetupError, ApiError, OSError, ValueError) as exc:
        # ApiError here is the client's own construction (bad TLS material, for one); a failure
        # once the campaign runs is recorded in the result, never raised, so it still exits 1.
        return fail_setup(str(exc))
    if not result.ok:
        if not replay_files:
            where = f"--fuzz-driver {driver}" + (f" --fuzz-endpoint {endpoint}" if endpoint else "")
            print(f"replay with: python -m harness --fuzz-replay FILE {where} (seed {seed})")
        return EXIT_INVARIANT
    return EXIT_PASS
