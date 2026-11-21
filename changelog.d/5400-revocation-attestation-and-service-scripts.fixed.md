- **A revocation attestation that does not read as true now stops a `docker compose up` run
  without `--no-deps` before any engine starts.** The compose file required `MEFOR_TLS_REVOCATION_ATTESTED` but
  refused only an unset or empty value, so a value such as `0` would have started engines that
  exit 2 at the API revocation gate and restart forever. A one-shot `revocation-attestation-check`
  service now reads the value with the engine's own parser, from the same image, and every serving
  engine waits on it.
  At least `docker compose up --no-deps <engine>` and `docker compose run --no-deps` skip that
  check, so an engine started with `up --no-deps` and a false value would still restart forever.
  The Postgres password's missing-value message now says that `--env-file` reads its file instead of
  the `.env` beside `compose.yaml`. Both Kubernetes manifests,
  `docker/k8s/statefulset.yaml` and `docker/k8s/ha-postgres.yaml`, now run the same check as a
  first `revocation-attestation-check` initContainer on the value they read from the Secret's
  `tls-revocation-attested` key, so a value such as `0` there passes the kubelet and then holds
  the pod in Init instead of crash-looping the engine; their deploy docs say so. Every value in
  `docker/k8s/secret.example.yaml` now ships commented out, so applying it unedited creates a
  Secret the kubelet refuses the pod over rather than one holding placeholders. The compose
  `engine` and `ha` engines now carry the k8s manifests' block of commented inputs an enforcing
  `serve --env prod` start needs, and each `ha` engine gets its own named volume for the log
  spool. See docs/CLOUD-DEPLOYMENT.md, section 7. (BACKLOG #5400)
- **`install-service.ps1` now counts a "Log on as a service" holder written as an account name.**
  It compared the exported `SeServiceLogonRight` holders with the account's SID only, so a row that
  named the account would have read as missing and the policy would have been re-imported with the
  account added again. A name is now matched as given, then resolved and its SID compared.
  `uninstall-service.ps1` removes such a holder the same way. It also removes the account's own
  name when that no longer resolves, as after the service is deleted; any other name that does not
  resolve is kept. Of the lookups that fail, only one that finds no account now counts as another
  account. A lookup that fails any other way, a trust failure for example, is named in a warning: the installer adds the
  SID anyway, so the row may then name the account twice, and the uninstaller keeps the name and
  reports the right as unproven rather than as removed or not held. (BACKLOG #5401)
- **The service scripts read `-DataDir` literally and validate one more service name.**
  `uninstall-service.ps1` tests the data directory and reads the config directory's ACL with
  `-LiteralPath`, so a `[` in the path would no longer read an existing directory as gone and leave
  its ACE. `measure-store-access.ps1 -ServiceName` now takes the same name pattern as
  `uninstall-service.ps1`. (BACKLOG #5402)
