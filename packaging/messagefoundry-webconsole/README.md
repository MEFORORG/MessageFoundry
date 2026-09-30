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

Console 0.4.0 pairs with engine 0.5.0. Install the pair into one environment:

```
pip install "messagefoundry==0.5.0" "messagefoundry-webconsole==0.4.0"
# or from a checkout, for development:
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
(BACKLOG #279). Console 0.4.0 supports seam `10a6cc7c95459dcc`, which is engine 0.5.0. With the
console on, the engine refuses to start beside any other console. The refusal is `UiSeamMismatch`
when startup reaches the seam check, and an import error when a mismatched pair fails before it.

Console 0.4.0 declares `messagefoundry>=0.5.0`, a floor with no ceiling. So pip refuses an older
engine, but not a newer one; a newer engine with a different seam is refused at startup instead.
Pin both versions, as above.
