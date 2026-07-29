<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# messagefoundry-webconsole

The **web ops console** for [MessageFoundry](https://messagefoundry.org/) — the same-origin browser
dashboard served under `/ui` (ADR 0065). A separately-versioned second distribution that the engine
**mounts in-process, same-origin**, via one `mount_ui(app, deps)` call from `create_app`'s `serve_ui`
tail (Option B).

It owns the entire `/ui` surface — page rendering, the confined `mf_session` cookie auth, the
write-action registry, and every `/ui` route — and reaches the reused JSON handlers through the typed
`UiDeps` bundle the engine injects. It imports only `fastapi`, the leaf-safe `messagefoundry.api`
surface (`security`/`models`/`auth_models`/`_ui_seam`), `messagefoundry.auth`, and the pure
`messagefoundry.parsing` lib — never `pipeline`/`store`/`transports`/`config`.

## Install

```
pip install -e packaging/messagefoundry-webconsole    # from the source tree, alongside the engine
```

> **Not on PyPI yet.** This distribution has never been published, so its name is **unclaimed**.
> Installing it by bare name from an index would resolve whatever a third party has uploaded under
> that name — and an sdist executes its build backend during `pip install`, before any engine process
> exists. Install from the source tree until the name is registered (ASVS 15.2.4).

A plain `pip install messagefoundry` stays byte-identical: with the console absent and `serve_ui`
default-off, the JSON API is unchanged; `serve_ui=true` without the console fails LOUD at startup.

## Compatibility

The console pins itself against the engine's `ENGINE_UI_SEAM` (`SUPPORTED_ENGINE_SEAMS` +
`assert_engine_seam`) and supports **exactly one** seam — the engine build it was released against
(BACKLOG #279). Any other engine/console pair is refused at startup with a clear `UiSeamMismatch`
rather than failing later inside a page render.
