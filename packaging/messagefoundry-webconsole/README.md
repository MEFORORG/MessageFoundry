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
pip install messagefoundry[webconsole]        # engine + console
# or, explicitly:
pip install messagefoundry messagefoundry-webconsole
```

A plain `pip install messagefoundry` stays byte-identical: with the console absent and `serve_ui`
default-off, the JSON API is unchanged; `serve_ui=true` without the console fails LOUD at startup.

## Compatibility

The console pins itself against the engine's `ENGINE_UI_SEAM` (`SUPPORTED_ENGINE_SEAMS` +
`assert_engine_seam`). An out-of-range engine/console pair is refused at startup with a clear
`UiSeamMismatch` — the runtime backstop behind the version range.
