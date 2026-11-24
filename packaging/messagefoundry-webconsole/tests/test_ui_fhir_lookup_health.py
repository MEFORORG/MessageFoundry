# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The nav heart warns on a FhirLookup isolated at start (vault BACKLOG #3008)."""

from __future__ import annotations

from _webui_support import _GIB, _sysinfo

from messagefoundry_webconsole.pages._common import _MAX_NAMED_FAILURES, _failed_lookup_reason
from messagefoundry_webconsole.routes.status import _derive_health


def test_an_isolated_lookup_turns_the_heart_to_warn_and_names_it() -> None:
    status = _sysinfo(50 * _GIB, fhir_lookups_failed=["FHIR_EMPI"])
    assert _derive_health(status, None, None, None) == (
        "warn",
        "FHIR lookup FHIR_EMPI failed to start",
    )


def test_no_isolated_lookup_leaves_the_heart_ok() -> None:
    # The control: the same status with an empty list reads ok, so the warn above is this field's.
    assert _derive_health(_sysinfo(50 * _GIB), None, None, None) == ("ok", None)


def test_a_failed_inbound_wins_the_tooltip_and_the_lookup_wins_over_low_disk() -> None:
    # The warn-level tie-break is insertion order: the inbound rules first, then the lookup, then
    # the disk, pool, forwarder and DR rules.
    both = _sysinfo(50 * _GIB, channels=3, failed_names=["IB_ACME_ADT"], fhir_lookups_failed=["L"])
    assert _derive_health(both, None, None, None) == ("warn", "inbound IB_ACME_ADT failed to start")
    low_disk = _sysinfo(2 * _GIB, fhir_lookups_failed=["L"])
    assert _derive_health(low_disk, None, None, None) == ("warn", "FHIR lookup L failed to start")
    saturated = _sysinfo(50 * _GIB, pool_idle=0, fhir_lookups_failed=["L"])
    assert _derive_health(saturated, None, None, None) == ("warn", "FHIR lookup L failed to start")
    # A down-level issue still takes the tooltip.
    full_disk = _sysinfo(0, fhir_lookups_failed=["L"])
    assert _derive_health(full_disk, None, None, None) == ("down", "low disk (db): 0.0 GiB free")


def test_the_sentence_names_at_most_the_cap() -> None:
    names = [f"L{i}" for i in range(_MAX_NAMED_FAILURES + 2)]
    listed = ", ".join(names[:_MAX_NAMED_FAILURES])
    assert _failed_lookup_reason(names) == (
        f"{len(names)} FHIR lookups failed to start: {listed}, and 2 more"
    )
    if _MAX_NAMED_FAILURES >= 2:  # one name takes the singular sentence instead
        at_cap = names[:_MAX_NAMED_FAILURES]
        assert _failed_lookup_reason(at_cap) == (
            f"{_MAX_NAMED_FAILURES} FHIR lookups failed to start: {listed}"
        )
