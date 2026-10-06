Point the extension at the **engine** you will promote to. The engine is a headless service (run it
with `messagefoundry serve`) — the IDE talks to it over a localhost HTTPS API.

- `messagefoundry.engineUrl` — the engine API URL (default `https://127.0.0.1:8765`).
- `messagefoundry.environments` — named targets (DEV/PROD/…) when you promote to more than one engine.

The **engine status item** in the status bar shows the current target and whether it is reachable —
click it to open the panel, the URL, or these settings. Nothing here sends messages; it only tells
the IDE where to stage a promote.
