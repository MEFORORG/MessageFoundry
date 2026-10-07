- **`POST /me/reauth`'s own refusal of an `oidc` session now carries `X-Step-Up-Via: idp`**, the
  header the step-up gates send such a session. So `EngineClient.reauth()` raises
  `IdpStepUpRequired` there too, rather than a plain `ApiError` a caller had to tell apart by its
  text. The status and detail are unchanged. See [SECURITY.md](../docs/SECURITY.md).
  (`BACKLOG #2158`)
