<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# messagefoundry-webconsole

The **web ops console** for [MessageFoundry](https://messagefoundry.org/) — the same-origin browser
dashboard served under `/ui` (ADR 0065). A separately-versioned second distribution that the engine
**mounts in-process, same-origin**, via one `mount_ui(app, deps)` call from `create_app`'s `serve_ui`
tail (Option B).

It owns the entire `/ui` surface — page rendering, the `mf_session` cookie auth, the write-action
registry, and every `/ui` route — and reaches the reused JSON handlers through the typed
`UiDeps` bundle the engine injects. It imports only `fastapi`, the leaf-safe `messagefoundry.api`
surface (`security`/`models`/`auth_models`/`validation`/`_ui_seam`), `messagefoundry.auth`, and the
pure `messagefoundry.parsing` lib — never `pipeline`/`store`/`transports`/`config`.

## Install

The published console 0.5.0 wheel pairs with engine 0.5.2. Install the engine and the console into
one environment.

> **Caution: the published console 0.5.0 wheel refuses engine 0.5.3.** Engine 0.5.3 moved the UI
> seam (see *Compatibility*), so the line below installs a pair that refuses to start with the
> console on, until a console release that supports engine 0.5.3 ships and its version replaces
> `0.5.0` here. The caution in
> [INSTALL-GUIDE.md, *Launching the admin console*](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/INSTALL-GUIDE.md#launching-the-admin-console-in-a-browser)
> says what works until then.

```
# refuses to start with the console on until a published console for engine 0.5.3 ships (caution above)
pip install "messagefoundry==0.5.3" "messagefoundry-webconsole==0.5.0"
# or, for development, beside an engine installed from the same checkout:
pip install -e packaging/messagefoundry-webconsole
```

> The distribution name is **registered on PyPI** and published only by this repository's
> `release.yml` over PyPI Trusted Publishing (OIDC, no API token), on its own `webconsole-v*` tag.
> Claiming the name is what forecloses the dependency-confusion substitution an unclaimed name invites
> (ASVS 15.2.4).

A plain `pip install messagefoundry` stays byte-identical, because the engine wheel does not contain
the console. The engine turns the console on by default for a loopback bind. With the console
absent, it serves the JSON API only and prints a warning at startup. Setting
`[security].serve_web_console = true` explicitly without the console makes it refuse to start.

## Compatibility

The console pins itself against the engine's `ENGINE_UI_SEAM` (`SUPPORTED_ENGINE_SEAMS` +
`assert_engine_seam`) and supports **exactly one** seam — the engine build it was released against
(BACKLOG #279). The published console 0.5.0 wheel supports seam `6d8b36eb7bb94bf0`, which engine
0.5.2 provides; the in-tree console, which also reports 0.5.0, tracks the engine's seam. Engine
0.5.3 provides `2fdef0ec34ace13d`, so the published console 0.5.0 wheel refuses it. With
the console on, the engine refuses to start beside any other console. The refusal is
`UiSeamMismatch` when startup reaches the seam check, and an import error when a mismatched pair
fails before it.

Console 0.5.0 declares `messagefoundry>=0.5.2`, a floor with no ceiling. So pip will not leave it
beside an engine older than 0.5.2. It upgrades the engine instead, and an unpinned upgrade takes
the newest release, whose seam may differ. The engine refuses that pair at startup. Pin both
versions, as a pair whose seams match.
