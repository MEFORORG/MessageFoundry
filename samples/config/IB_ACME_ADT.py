# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample route: receive ACME ADT over MLLP, forward to a per-environment downstream.

The inbound takes only a port — it listens on the service's ``[inbound].bind_host`` (loopback in
DEV, a specific NIC in PROD), set by the operator, not here. The outbound peer differs by
environment, so it's authored with ``env()`` and resolved from ``environments/<env>.toml`` (DEV vs
PROD). Run it against the dev values with::

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db
"""

from messagefoundry import MLLP, Send, env, handler, inbound, outbound, router

inbound("IB_ACME_ADT", MLLP(port=2600), router="acme_adt_router")
# Downstream peer is environment-specific (DEV → loopback, PROD → the real receiver host): resolved
# per instance from environments/<env>.toml, so this one module runs unchanged in every environment.
outbound("OB_ACME_ADT", MLLP(host=env("acme_adt_host"), port=env("acme_adt_port", cast=int)))


@router("acme_adt_router")
def route(msg):
    return ["acme_adt_handler"]  # TODO: routing logic


@handler("acme_adt_handler")
def handle(msg):
    # TODO: filter / transform
    return Send("OB_ACME_ADT", msg)
