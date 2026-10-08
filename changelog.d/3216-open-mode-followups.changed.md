- **Open-mode follow-ups: one check, one 503 text, and removed-key refusals that name the right fix.**
  The four places that ask whether an app runs with no sign-in now call one helper, and what the
  open mode permits is unchanged. With no auth service attached and no opt-in, the sign-in routes
  and the web console's account pages now answer 503 `authentication is not configured`, the text
  the permission gate already gave; they used to say `authentication is not enabled`, which named
  a switch that no longer exists. The refusal for a removed settings key now fits where the key
  came from. The loader names the config file and the `MEFOR_` variable, for all six removed keys.
  A section built in code, or `[security]` read by `messagefoundry security show`, no longer tells
  you to unset an environment variable it never read. `AuthSettings` built in code with `enabled`
  now gives that same refusal as every other removed key, and still points at `allow_no_auth=True`.
  (`vault BACKLOG #3216`)
