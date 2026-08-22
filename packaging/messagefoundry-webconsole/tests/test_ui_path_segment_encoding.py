# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection names cannot escape a /ui path segment (ASVS 1.2.2, BACKLOG #1107 clause 2).

The apiclient half of this item shipped with `_seg` and is pinned by `tests/test_apiclient.py`. The
console half was left: `safe=""` appeared ZERO times in `messagefoundry_webconsole/`, the two sites
that encoded a path segment used `quote`'s DEFAULT `safe="/"`, and the dead-letter replay forms
interpolated a channel id and a destination name with no encoding at all.

`quote`'s default is the whole defect: measured, `quote("IB/ACME")` returns it UNCHANGED, because the
one character it leaves alone is the one a path segment turns on.

**Scoped to CONNECTION NAMES on purpose.** The other /ui interpolations carry ids, where the
"every interpolated id is a `uuid4().hex`" argument is probably true. It is NOT true of connection
names: `Registry._add` checks only for a duplicate, so a name is unconstrained free text. Widening
this to all 54 sites needs each read first -- `_auth`'s reauth `next` is CORRECTLY `safe="/"`, and the
last test here fails if a blanket sweep breaks it.
"""

from __future__ import annotations

import pathlib
import re

from messagefoundry.api.models import DeadLetterList, DeadLetterRow
from messagefoundry_webconsole.pages._common import _seg


def test_seg_encodes_the_separator_that_the_default_leaves_alone() -> None:
    """The unit fact the rest rests on, with a benign name as the negative control."""
    from urllib.parse import quote

    assert quote("IB/ACME") == "IB/ACME", (
        "the premise of this whole file just changed: quote's default no longer leaves '/' alone"
    )
    assert _seg("IB/ACME") == "IB%2FACME"
    assert _seg("a?b") == "a%3Fb"
    assert _seg("a#b") == "a%23b"
    # NEGATIVE CONTROL: a guard that mangled everything would satisfy the assertions above.
    assert _seg("IB_ACME_ADT") == "IB_ACME_ADT"


def _dead_letters(channel: str, destination: str) -> DeadLetterList:
    row = DeadLetterRow(
        outbox_id="o1",
        message_id="m1",
        channel_id=channel,
        destination_name=destination,
        attempts=1,
        last_error=None,
        failed_at=0.0,
        control_id=None,
        message_type=None,
        received_at=0.0,
    )
    return DeadLetterList(total=1, limit=50, offset=0, dead_letters=[row])


def test_the_dead_letter_replay_forms_encode_a_name_carrying_a_slash() -> None:
    """RENDERS the real page rather than reading the f-string, so the assertion is about output.

    These two forms were the unencoded pair: before this fix a connection named ``IB/ACME`` produced
    ``/ui/dead-letters/IB/ACME/replay``, which is a different route with an extra segment.
    """
    from messagefoundry_webconsole.pages.messages import dead_letters

    html = str(dead_letters(_dead_letters("IB/ACME", "OB/PARTNER")))

    assert "/ui/dead-letters/IB%2FACME/replay" in html
    assert "/ui/dead-letters/IB%2FACME/OB%2FPARTNER/replay" in html
    assert "/ui/dead-letters/IB/ACME/" not in html, (
        "the name escaped its path segment; the action addresses a different route"
    )


def test_a_benign_connection_name_still_renders_readably() -> None:
    """NEGATIVE CONTROL for the render path: encoding must not disfigure ordinary names."""
    from messagefoundry_webconsole.pages.messages import dead_letters

    html = str(dead_letters(_dead_letters("IB_ACME_ADT", "OB_PARTNER_ADT")))
    assert "/ui/dead-letters/IB_ACME_ADT/replay" in html
    assert "%5F" not in html, "an unreserved character was percent-encoded"


def test_every_connection_name_route_interpolates_through_seg() -> None:
    """GUARD THE GUARD: a new site on these routes reds this rather than slipping in unencoded.

    Scans the page builders for f-string path literals on the three routes that carry a connection
    name, and requires each interpolation to go through ``_seg``. Mutation: revert any one site to a
    bare ``quote(...)`` or a raw ``{name}``. Red: that literal is listed in the failure.
    """
    pages = pathlib.Path(__file__).resolve().parents[3] / "messagefoundry_webconsole" / "pages"
    literals: list[str] = []
    for path in sorted(pages.glob("*.py")):
        for lit in re.findall(
            r'f"(/ui/(?:connection|connections|dead-letters)/[^"]*)"',
            path.read_text(encoding="utf-8"),
        ):
            if "{" in lit:
                literals.append(f"{path.name}: {lit}")
    assert literals, "found NO connection-name path literals -- the scan is broken, not the code"
    unencoded = [lit for lit in literals if "_seg(" not in lit]
    assert not unencoded, f"connection-name path segments not routed through _seg: {unencoded}"


def test_the_reauth_next_parameter_is_left_alone() -> None:
    """The site a blanket path-segment sweep would BREAK, pinned so the sweep cannot happen quietly.

    ``_auth``'s reauth ``next`` carries a whole PATH inside a query parameter, so ``safe="/"`` is
    correct there. Encoding it as one segment would turn every re-auth redirect into a broken link.
    """
    auth = pathlib.Path(__file__).resolve().parents[3] / "messagefoundry_webconsole" / "_auth.py"
    source = auth.read_text(encoding="utf-8")
    assert 'quote(next_path if next_path is not None else request.url.path, safe="/")' in source, (
        "the reauth 'next' encoding changed; if a path-segment builder was applied here it is wrong "
        "-- that value is a path carried in a query parameter"
    )
