- **The compose `ha` profile's Postgres now serves TLS, and no compose service sets
  `MEFOR_ALLOW_INSECURE_TLS`.** The `ha` engines set that escape against a Postgres with no TLS, but
  the engine refuses a weakened store login at every posture, so the shipped HA template could not
  open its store. Postgres now serves your certificate and unencrypted key from `docker/pg-tls/`,
  and the engines pin its CA at `/config/pki/store-ca.pem`; `docker/compose.yaml` says what each
  file must hold. (`BACKLOG #5827`)
