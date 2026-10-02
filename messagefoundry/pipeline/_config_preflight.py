# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Load one config directory in a child process, the way an engine shard will (vault BACKLOG #2587).

Run by :func:`messagefoundry.pipeline.supervisor.preflight_shard_config` through
:func:`messagefoundry.childenv.python_child_argv`, so this process has an engine shard's import
path: the working directory is not on it. A config that loads in the supervisor only because of
the working directory fails here, once, before any engine shard is started.

Exit 0 means the config loaded. :data:`EXIT_IMPORT` means an import failed; :data:`EXIT_OTHER`
means the load failed some other way. Either way one line on stderr says what failed. It names the
exception and its message and nothing else: no traceback, and no config source.
"""

from __future__ import annotations

import sys

#: The config imported something this process cannot find.
EXIT_IMPORT = 3
#: The config did not load, for any other reason.
EXIT_OTHER = 4


def main(argv: list[str]) -> int:
    from messagefoundry.config.wiring import load_config

    try:
        load_config(argv[1])
    except Exception as exc:  # noqa: BLE001 - every failure is reported to the parent, none is raised
        # ONE line, whatever the message holds: the parent reads the last line of this stream.
        print(f"{type(exc).__name__}: {' '.join(str(exc).split())}", file=sys.stderr)
        # The loader wraps a config module's failure, so the import error is the cause.
        failed_import = isinstance(exc, ImportError) or isinstance(exc.__cause__, ImportError)
        return EXIT_IMPORT if failed_import else EXIT_OTHER
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
