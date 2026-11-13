- **An API app built without `serve` or `supervise` now refuses on the same Windows service
  environment finding they refuse on.** `create_app` and `create_managed_app` raise
  `ServiceEnvironmentRefused` (`messagefoundry.serviceenv`), not a `RuntimeError`, as they are
  built, with the `serve` refusal's own text, where the engine finds its
  NSSM service and an engine secret is in that service's environment lists, or where it knows the
  service, cannot read the lists and has a store key in its own environment. Where neither holds,
  for example under a console-script launcher the engine cannot see past, an app builds as before.
  The factories refuse the app, not an engine the caller built and started before calling
  `create_app(engine)`, and an engine embedded with no API is not refused.
  See [SERVICE.md](../docs/SERVICE.md). (`BACKLOG #8212`)
