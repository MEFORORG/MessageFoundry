# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Thin re-export shim: Windows service control now lives in :mod:`messagefoundry.service` (ADR 0088).

The service-control body moved to :mod:`messagefoundry.service` and is exposed as the
``messagefoundry service {install,start,stop,status}`` CLI. This module re-exports the same public
API (and the module-private helpers the console widgets/tests reference by name) so the console's
Engine-Status page keeps driving it via ``from messagefoundry.console import service_control`` with no
behaviour change.
"""

from __future__ import annotations

from messagefoundry.service import (
    _NO_WINDOW,
    _install_params,
    _is_safe_service_name,
    control_service,
    install_script_path,
    install_service,
    is_safe_environment,
    parse_service_state,
    service_state,
)

__all__ = [
    "service_state",
    "control_service",
    "parse_service_state",
    "install_script_path",
    "install_service",
    "is_safe_environment",
]

# Re-exported (outside ``__all__``) because the console widgets and existing tests reference these
# module-private helpers by name from this shim's historical path.
_ = (_NO_WINDOW, _install_params, _is_safe_service_name)
