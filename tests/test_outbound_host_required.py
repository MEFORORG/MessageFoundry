# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""One pre-defined rule, applied the same way by every outbound network connector: a destination that
dials a peer requires a ``host``, and refuses to invent one.

The MLLP/TCP/X12 destinations used to default a missing ``host`` to ``127.0.0.1`` while their
EMAIL/DIRECT/DIMSE siblings raised, so the same rule had two answers depending on the connector. The
defaulted address is the part that would bite on a first deployment: a delivery would dial the engine's
own machine, and where that engine also runs a listener on the port it would SUCCEED into its own
intake rather than failing, so the fault would present as a misrouted feed instead of a connection
error. ``build_outbound_connection`` refuses an ABSENT host at both authoring surfaces already, but it
tests ``is None``, so a blank host reached the connector untested by either layer.

Everything is built through :func:`build_destination` / :func:`build_source`, the seam the loader and
``build_check_registry`` use, so the tests exercise the real construction path rather than the classes.

Two halves of the suite are load-bearing and must not be trimmed:

  * the **positive controls** (each destination builds with a host; each sibling still raises without
    one) -- without them a registry that simply failed to build anything would pass every refusal
    assertion here;
  * the **source guard** -- MLLP/TCP/X12 *listeners* legitimately default a missing host to loopback,
    because their bind interface comes from the service's ``[inbound].bind_host`` and binding all
    interfaces must stay an admin decision. The destination fix must not touch that, and this is the
    test that tells the two apart.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.transports import build_destination, build_source

#: The outbound network connectors under test, with the minimum settings each needs *besides* a host.
_DIALING_DESTINATIONS: list[tuple[ConnectorType, dict[str, Any]]] = [
    (ConnectorType.MLLP, {"port": 2575}),
    (ConnectorType.TCP, {"port": 2575, "framing": "mllp"}),
    (ConnectorType.X12, {"port": 2575}),
]

#: The connectors that already refused a missing host, kept here as the control that the refusal being
#: asserted is this rule and not a broken registry. Each names settings that are otherwise valid, so a
#: raise can only come from the host check.
_SIBLING_DESTINATIONS: list[tuple[ConnectorType, dict[str, Any]]] = [
    (
        ConnectorType.EMAIL,
        {"port": 587, "sender": "feed@example.org", "recipients": ["a@b.example"]},
    ),
    (
        ConnectorType.DIRECT,
        {"port": 587, "sender": "feed@example.org", "recipients": ["a@b.example"]},
    ),
    (ConnectorType.DIMSE, {"port": 104, "ae_title": "MEFOR_SCU", "called_ae_title": "PACS"}),
]

_LISTENING_SOURCES: list[tuple[ConnectorType, dict[str, Any]]] = [
    (ConnectorType.MLLP, {"port": 2575}),
    (ConnectorType.TCP, {"port": 2575, "framing": "mllp"}),
    (ConnectorType.X12, {"port": 2575}),
]


def _ids(rows: list[tuple[ConnectorType, dict[str, Any]]]) -> list[str]:
    return [kind.value for kind, _ in rows]


@pytest.mark.parametrize(
    ("kind", "settings"), _DIALING_DESTINATIONS, ids=_ids(_DIALING_DESTINATIONS)
)
def test_dialing_destination_refuses_absent_host(
    kind: ConnectorType, settings: dict[str, Any]
) -> None:
    """No ``host`` key at all: refuse, rather than substitute a loopback peer nobody configured."""
    config = Destination(name=f"OB_{kind.value.upper()}", type=kind, settings=dict(settings))
    with pytest.raises(ValueError, match="requires a 'host' setting"):
        build_destination(config)


@pytest.mark.parametrize(
    ("kind", "settings"), _DIALING_DESTINATIONS, ids=_ids(_DIALING_DESTINATIONS)
)
@pytest.mark.parametrize("blank", ["", None], ids=["empty-string", "explicit-none"])
def test_dialing_destination_refuses_blank_host(
    kind: ConnectorType, settings: dict[str, Any], blank: str | None
) -> None:
    """A present-but-empty host is the case neither layer caught: ``build_outbound_connection`` tests
    ``is None`` so ``host=""`` passes wiring, and the connector then kept the blank string. An empty
    host is not loopback -- ``getaddrinfo("")`` resolves to this machine's own interfaces -- so it is
    the same misdelivery hazard wearing a different value."""
    config = Destination(
        name=f"OB_{kind.value.upper()}", type=kind, settings={**settings, "host": blank}
    )
    with pytest.raises(ValueError, match="requires a 'host' setting"):
        build_destination(config)


@pytest.mark.parametrize(
    ("kind", "settings"), _DIALING_DESTINATIONS, ids=_ids(_DIALING_DESTINATIONS)
)
def test_dialing_destination_builds_with_a_host(
    kind: ConnectorType, settings: dict[str, Any]
) -> None:
    """Positive control: the refusal is the missing host and nothing else. Without this row a
    connector (or a registry) that raised unconditionally would satisfy every test above."""
    config = Destination(
        name=f"OB_{kind.value.upper()}",
        type=kind,
        settings={**settings, "host": "downstream.example.org"},
    )
    connector = build_destination(config)
    assert connector.host == "downstream.example.org"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("kind", "settings"), _SIBLING_DESTINATIONS, ids=_ids(_SIBLING_DESTINATIONS)
)
def test_sibling_destinations_still_refuse_absent_host(
    kind: ConnectorType, settings: dict[str, Any]
) -> None:
    """Control on the other side: the three connectors that already enforced the rule still do, so a
    green suite means MLLP/TCP/X12 joined them rather than everyone quietly stopping."""
    config = Destination(name=f"OB_{kind.value.upper()}", type=kind, settings=dict(settings))
    with pytest.raises(ValueError, match="(?i)requires a 'host' setting"):
        build_destination(config)


@pytest.mark.parametrize(("kind", "settings"), _LISTENING_SOURCES, ids=_ids(_LISTENING_SOURCES))
def test_listening_source_still_defaults_to_loopback(
    kind: ConnectorType, settings: dict[str, Any]
) -> None:
    """The regression guard. An inbound MLLP/TCP/X12 connection takes no author-supplied host: the bind
    interface is injected from the service's ``[inbound].bind_host``, and a missing/None value must fall
    back to loopback so an unauthenticated raw listener is never bound to every interface by accident.
    Requiring a host here instead of on the destination would be a security regression, so the rule
    being tightened above is asserted NOT to have reached this side."""
    connector = build_source(Source(type=kind, settings=dict(settings)))
    assert connector.host == "127.0.0.1"  # type: ignore[attr-defined]


@pytest.mark.parametrize(("kind", "settings"), _LISTENING_SOURCES, ids=_ids(_LISTENING_SOURCES))
def test_listening_source_keeps_an_injected_bind_host(
    kind: ConnectorType, settings: dict[str, Any]
) -> None:
    """The other half of the guard: the loopback fallback is a *fallback*, so a bind host the service
    injected still reaches the listener. A change that hard-coded loopback would pass the test above."""
    connector = build_source(Source(type=kind, settings={**settings, "host": "10.0.0.5"}))
    assert connector.host == "10.0.0.5"  # type: ignore[attr-defined]
