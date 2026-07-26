# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Estate-shape system-under-test config (#216) — a HETEROGENEOUS N-inbound code-first graph: a
majority of simple 1-in-1-out pass-through feeds + a minority of fan-out hubs. It desugars through the
same ``inbound()``/``outbound()`` factories into a flat endpoint list (no "channel" element). Where
:mod:`harness.config.connscale` models a UNIFORM high-connection-count estate (every feed identical,
fan-out 1), this models the real demo shape whose per-connection event rate the ``--estate`` driver
calibrates to a target total. See :mod:`harness.load.estate`."""
