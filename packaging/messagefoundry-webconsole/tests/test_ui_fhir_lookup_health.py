# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The nav heart warns on a FhirLookup isolated at start (vault BACKLOG #3008)."""

from __future__ import annotations

from messagefoundry.api.models import DbInfo, EngineInfo, SystemStatus
from messagefoundry_webconsole.pages._common import _MAX_NAMED_FAILURES, _failed_lookup_reason
from messagefoundry_webconsole.routes.status import _derive_health


def _sys(lookups: list[str]) -> SystemStatus:
    return SystemStatus(
        engine=EngineInfo(
            version="0",
            uptime_seconds=10.0,
            pid=1,
            channels_total=1,
            channels_running=1,
            channels_stopped=0,
            outbox_by_status={},
            fhir_lookups_failed=lookups,
        ),
        db=DbInfo(
            path="db",
            size_bytes=1,
            disk_free_bytes=100 * 1024**3,
            disk_free_status="observed",
            journal_mode="wal",
            messages=0,
            events=0,
            audit=0,
        ),
    )


def test_an_isolated_lookup_turns_the_heart_to_warn_and_names_it() -> None:
    assert _derive_health(_sys(["FHIR_EMPI"]), None, None, None) == (
        "warn",
        "FHIR lookup FHIR_EMPI failed to start",
    )


def test_no_isolated_lookup_leaves_the_heart_ok() -> None:
    # The control: the same status with an empty list reads ok, so the warn above is this field's.
    assert _derive_health(_sys([]), None, None, None) == ("ok", None)


def test_the_sentence_names_at_most_the_cap() -> None:
    names = [f"L{i}" for i in range(_MAX_NAMED_FAILURES + 2)]
    listed = ", ".join(names[:_MAX_NAMED_FAILURES])
    assert _failed_lookup_reason(names) == (
        f"{len(names)} FHIR lookups failed to start: {listed}, and 2 more"
    )
    assert _failed_lookup_reason(["A", "B"]) == "2 FHIR lookups failed to start: A, B"
