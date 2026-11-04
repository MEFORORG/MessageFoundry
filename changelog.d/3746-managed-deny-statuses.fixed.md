- **Corrected: the 0.5.2 note on `create_managed_app` denying by default named one status for every
  protected route.** That note said an app built with no `auth_settings` and no `allow_no_auth`
  refuses every protected route with `503`. It does not answer them all alike. At least the JSON
  routes, such as `/stats`, answer `503`. With `serve_ui=True`, at least the web console's pages,
  such as `/ui` and `/ui/connections`, redirect to sign-in with `303`, though `/ui/account` answers
  `503`. `GET /service/identity`, which takes only a client certificate, answers `401`. The code did
  not change; only the record did. (`BACKLOG #3746`)
