# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Extension-allowlisting static file serving for ``/ui/static`` (ASVS 13.4.7).

Starlette's :class:`~starlette.staticfiles.StaticFiles` serves **any regular file** under its
directory. Its only containment is path-traversal defence (a ``commonpath`` check plus symlink
refusal) — there is no extension policy, no dotfile rule and no backup-suffix rule anywhere in it.
Verified empirically against the shipped Starlette: a bare mount happily serves ``.env``,
``app.js.bak``, ``secrets.map``, ``x.py``, extension-less files and files in subdirectories.

That matters here because the console's asset directory IS the served surface: the wheel
force-includes the whole package tree with no exclude list, and dev/CI install it editable, so
``STATIC_DIR`` resolves to the live working tree with no build step standing between a stray file and
an UNAUTHENTICATED 200 (the ``/ui/static`` prefix is excluded from the /ui auth and no-store paths).
The worst instance is invisible to review: a ``.env`` dropped in there is matched by the repo
``.gitignore``, so ``git status``, diffs and PR review all skip it while it is served.

:class:`AllowlistedStaticFiles` closes that by construction rather than by curation: a request is
resolved only when its path's final component has exactly ONE suffix and that suffix is in
:data:`ALLOWED_STATIC_EXTENSIONS`. Everything else 404s *before* the filesystem is touched. It is the
second of three layers — the packaging manifest test (asset directory contents) and the planted-file
runtime test are the others; the runtime allowlist alone would still serve an ALLOWED-extension
accident such as a stray second ``.js``.

**Any future static mount must reuse this class**, not ``StaticFiles``: the allowlist governs the
mount it is installed on, not the process.
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath

from starlette.staticfiles import StaticFiles

__all__ = ["ALLOWED_STATIC_EXTENSIONS", "AllowlistedStaticFiles", "static_path_allowed"]

#: The ONLY file extensions ``/ui/static`` will serve — exactly the kinds of asset the console ships
#: (stylesheet, script). Lowercase, leading dot. Adding one is a reviewed security decision: it widens
#: an unauthenticated, uncached, same-origin file-serving surface.
ALLOWED_STATIC_EXTENSIONS = frozenset({".css", ".js"})


def static_path_allowed(path: str) -> bool:
    """Whether ``path`` (relative, as Starlette hands it to ``lookup_path``) may be served.

    Allowed only when the final component has exactly one suffix and that suffix is allow-listed.
    That single rule rejects each named class at once:

    * **dotfiles** — ``.env`` / ``.htpasswd``: no stem, so ``PurePosixPath.suffixes`` is empty;
    * **multi-suffix backup/derived forms** — ``app.js.bak``, ``app.css.map``: two suffixes, refused
      even when the LAST one is allow-listed (``notes.bak.js`` too), because a backup of a served
      asset is a different artifact from the asset;
    * **extension-less files** — ``notes``, ``Dockerfile``: no suffix;
    * **anything else** — ``x.py``, ``connections.toml``, ``deep.key``, in this directory or any
      subdirectory of it, since the rule is applied to the final component of the WHOLE relative path.
    """
    normalized = PurePosixPath(path.replace(os.sep, "/"))
    name = normalized.name
    if not name or name in (".", ".."):
        return False
    suffixes = PurePosixPath(name).suffixes
    return len(suffixes) == 1 and suffixes[0].lower() in ALLOWED_STATIC_EXTENSIONS


class AllowlistedStaticFiles(StaticFiles):
    """:class:`StaticFiles` restricted to :data:`ALLOWED_STATIC_EXTENSIONS`.

    The filter lands in ``lookup_path`` — the one funnel every resolution goes through — so a
    disallowed name is refused BEFORE any ``os.stat``, and returning the miss sentinel makes the base
    class raise its own ``404`` (``html=False``, so there is no index/404 fallback that could resolve
    a second path behind our back).
    """

    def lookup_path(self, path: str) -> tuple[str, os.stat_result | None]:
        if not static_path_allowed(path):
            return "", None
        return super().lookup_path(path)
