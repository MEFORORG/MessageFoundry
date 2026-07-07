# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The /ui route modules (moved from ``api.app``'s ``_register_*`` blocks + ``api.auth_routes``'s
admin/account/audit /ui routes). Each exposes ``register(app, deps)``; :func:`..mount.mount_ui`
imports them all eagerly (firing every module-level ``register_ui_action``) and calls each in a fixed,
test-pinned order (search before core so a literal path never loses to a path-param route)."""
