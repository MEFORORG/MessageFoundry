# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1497: ``serve`` logs the SQL Server renew-bound warning once logging is configured.

This seam test lives apart from ``tests/test_adr0157_b1497_sqlserver_renew_clamp.py``, which runs
in the SQL Server catch-all step of ``.github/workflows/ci.yml``. It was split out while the
``serverdb`` path-gate scan (``tests/test_serverdb_ci_coverage.py``) read
``from messagefoundry import __main__`` as an import of ``messagefoundry/__init__.py``, which that
regex does not admit. The scan now records ``messagefoundry/__main__.py``, which it does admit. The
split stays: nothing here needs a database.
"""

from __future__ import annotations

import inspect

from messagefoundry import __main__ as cli
from messagefoundry.config.settings import load_settings


def test_serve_logs_the_renew_bound_warning_once_logging_is_configured() -> None:
    """``serve`` loads its settings before ``configure_logging``, so the warning is logged after it,
    or it would reach the filtered lastResort only. Read from the source, as the breaker-budget seam
    test in tests/test_ad_user_account_control.py does, because running ``serve`` that far starts an
    engine."""
    source = inspect.getsource(cli._serve)
    checked = source.index("if _logging_refused is not None:")
    warned = source.index("settings.sqlserver_renew_bound_warning()")
    assert source.index("_load_service_settings(") < checked < warned
    assert source.count("sqlserver_renew_bound_warning") == 1
    assert "sqlserver_renew_bound_warning" not in inspect.getsource(load_settings)
