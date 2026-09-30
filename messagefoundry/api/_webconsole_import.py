# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Name a web console that is installed but will not import (BACKLOG #1907).

The console is a separately versioned wheel. An old one, or one whose own import chain fails
against this engine, raises ``ImportError`` at the engine's import of it. That import runs before
``assert_engine_seam`` can raise the clear ``UiSeamMismatch``. Without this module, ``serve`` would
exit 1 through the CLI's last-resort catch with one generic log line, and ``create_app`` would call
the broken install "not installed".

This is a **leaf** module. It never imports the console, because a console that fails to import is
exactly the case it describes, and importing a wheel runs its code (see the provenance gate in
``messagefoundry.__main__``). It reads only the exception and the installed distribution's
metadata.

It names no "required console version", because the engine holds none. What it can name is the
seam this engine speaks and the version the installed distribution's metadata reports.
"""

from __future__ import annotations

import importlib.metadata

from messagefoundry.api._ui_seam import ENGINE_UI_SEAM
from messagefoundry.redaction import safe_exc

#: The import name and the distribution name of the optional console wheel. ``__main__`` keeps its
#: own copy so the CLI does not import ``messagefoundry.api`` at module scope.
WEBCONSOLE_IMPORT_NAME = "messagefoundry_webconsole"
WEBCONSOLE_DISTRIBUTION = "messagefoundry-webconsole"


def console_is_absent(exc: ImportError) -> bool:
    """True when ``exc`` says the console package itself is missing, not that it failed to load.

    Python raises ``ModuleNotFoundError`` with ``name`` set to the missing module. Only that name
    being the console's own top-level package means "not installed". A missing submodule or a
    missing dependency of the console means it IS installed and broke on the way in."""
    return isinstance(exc, ModuleNotFoundError) and exc.name == WEBCONSOLE_IMPORT_NAME


def installed_console_version() -> str | None:
    """The version the console distribution's metadata reports, or ``None`` if there is none.

    This is the metadata's answer, not proof that the failing module came from that distribution:
    a shadowing copy earlier on ``sys.path`` would fail under the same reported version."""
    try:
        return importlib.metadata.version(WEBCONSOLE_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        return None


def _missing_dependency(exc: ImportError) -> str | None:
    """The name of a missing module outside this project, or ``None``.

    A console that cannot find a third-party package needs that package installed, not a
    different console release, so the advice differs."""
    if not isinstance(exc, ModuleNotFoundError) or not exc.name:
        return None
    top = exc.name.partition(".")[0]
    return None if top.startswith("messagefoundry") else exc.name


def console_import_failure(exc: ImportError) -> str:
    """The operator message for a console that is installed but failed to import.

    The exception goes through :func:`~messagefoundry.redaction.safe_exc`, the same rendering the
    CLI's last-resort catch uses, so this message prints nothing that catch would not."""
    version = installed_console_version()
    installed = (
        f"its distribution metadata reports version {version}"
        if version is not None
        else "no distribution metadata names its version"
    )
    head = (
        f"the web console package {WEBCONSOLE_DISTRIBUTION!r} is installed ({installed}) but failed "
        f"to import against this engine: {safe_exc(exc)}. "
    )
    missing = _missing_dependency(exc)
    if missing is not None:
        return head + (
            f"The console needs the module {missing!r}, which is not installed; install it, or set "
            "[security].serve_web_console=false to run JSON-only."
        )
    return head + (
        "This usually means the console is older or newer than this engine. This engine provides "
        f"web console seam {ENGINE_UI_SEAM}; install a {WEBCONSOLE_DISTRIBUTION} release whose "
        "SUPPORTED_ENGINE_SEAMS includes it, or set [security].serve_web_console=false to run "
        "JSON-only."
    )
