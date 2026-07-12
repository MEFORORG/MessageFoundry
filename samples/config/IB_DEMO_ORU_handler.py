# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""IB_DEMO_ORU — Handler (the *handler* file of the per-feed **Hybrid** config layout).

The Handler stays **thin** on purpose: it filters, delegates the field-level work to the
``_demo_oru_transforms`` helper (a ``_``-prefixed sibling the loader resolves — see that module and
docs/CONNECTIONS.md §"Decomposing by role"), then hands the message to the ``OB_DEMO_ORU`` outbound
declared as data in ``connections.toml``. All the manipulation detail lives in the helper, where it is
small, reviewable, and unit-testable — not inlined here.
"""

from messagefoundry import Send, handler

from _demo_oru_transforms import apply_demo_oru_transforms

# The outbound is declared as data in connections.toml; the Handler references it by name.
OB_DEMO_ORU = "OB_DEMO_ORU"


@handler("demo_oru_relay")
def demo_oru_relay(msg):
    # filter → transform → Send. (A real feed may drop here by returning None — logged FILTERED.)
    apply_demo_oru_transforms(msg)
    return Send(OB_DEMO_ORU, msg)
