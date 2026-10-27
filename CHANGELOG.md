# Changelog

All notable changes to MessageFoundry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **A row stranded in flight is recovered without a restart, and nothing overtakes it.** A store
  fault between a committed claim and its handoff leaves the row `inflight`, and the worker's
  re-pend of it can fail too. A worker, or a pooled lane serializer, whose re-pend fails now
  retries it on a capped backoff while it holds the lane, claiming nothing newer until the row is
  pending again, so per-lane order holds. A per-lane worker that dies holding a row has the rows on
  its own lane re-pended before its replacement claims anything, and a replacement for a worker
  that keeps dying waits a doubling backoff, up to 30 s; clustered, that step stands down, as the
  unconditional startup reset does. A stop during the retry leaves the row in flight for the
  next start, as before. While the store stays down the row stays in flight, and the in-flight
  watch added in 0.5.0 still pages it. (`BACKLOG #1611`)

## [0.5.2] — 2026-10-20 — Early Access

This engine pairs with web console 0.5.0, which is published after it under its own
`webconsole-v0.5.0` tag. Its UI seam is `6d8b36eb7bb94bf0`, so with the console on it refuses to
start beside console 0.4.0. Upgrade the two together, or set
`[security].serve_web_console = false`. A `BACKLOG #N` number cites the project's private planning
ledger, so it has no public page.

### Added
- **Federated sign-in can authenticate to the token endpoint with `private_key_jwt`.** Set
  `[auth].oidc_token_endpoint_auth_method = "private_key_jwt"` and supply
  `[auth].oidc_client_private_key` (inline PEM via `MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY`, a PEM
  file path, or `oidc_client_private_key_ref`). The token request then carries a short-lived
  signed assertion (RFC 7523) and no client secret. The default stays `client_secret_post`, and
  the request is unchanged unless you opt in. A missing or unusable key refuses startup, and
  `messagefoundry verify --section federation` loads it the same way. For an IdP that registers a
  certificate (Entra ID), `oidc_client_certificate` adds its `x5t#S256` thumbprint to each assertion. See
  [CONFIGURATION.md](docs/CONFIGURATION.md) and ADR 0142 Amendment D. (`BACKLOG #296`)
- **`messagefoundry admin-reset-totp` replaces a sole Administrator's authenticator seed from the
  host.** A sole Administrator whose only factor is TOTP had no way to replace a suspect seed: the
  administrator reset refuses a self-target, and self-service removal refuses the last factor. The
  command runs on the same host gate as `admin-unlock`, with the engine stopped. It shows a new key
  on the console only, under a name the app lists apart from the old entry, and writes nothing until
  a code from it is typed. One transaction then swaps the seed and the recovery codes with TOTP left
  on, ends the account's sessions and appends the `auth.admin_totp_reset` audit row, with the OS
  user as actor. So the account never has no factor, and the swap is never live unrecorded. The
  write also checks the enrolment it read before the prompt, so it never overwrites one made in
  the meantime. It shows the new recovery codes once and warns when passkeys were kept. An error
  from the swap is read back, and a seed replaced before a later failure exits 3, never 1. It refuses
  at least a non-Administrator, an Administrator who is not the only enabled one, a disabled
  account, an account with no TOTP, and an account with TOTP on but no seed stored. See
  [ADR 0171](docs/adr/0171-offline-administrator-unlock-a-host-gated-cli-recovery-path-for-a-sole-administrator-lockout.md)
  Amendment B. (`BACKLOG #2226`)
- **The VS Code security editor can set the four per-tier retention acknowledgements.** It offered
  `allow_keeping_phi_indefinitely` only. It now also offers the transform-state, search-preset,
  app-log and backup-archive switches, and marks each as a loosening when set. See the tier table
  in [CONFIGURATION.md](docs/CONFIGURATION.md). (`BACKLOG #2280`)
- **`messagefoundry check` prints an advisory `oauth-request` line.** It names an `oauth2_scope`
  token that contains a `*`, a `smart_audience` that is not exactly the token URL, and an
  `oauth2_audience` URL on a different scheme, host or port from the connection's `url`. It never
  blocks. It compares literal values only, so it also names every setting it could not compare,
  most often because a value is an `env()` reference. See
  [CONNECTIONS.md](docs/CONNECTIONS.md). (`BACKLOG #2334`)
- **An interop lab proxy checks what the engine signs with verifiers it did not write.** The
  `openssl` command-line tool decrypts the DIRECT connector's S/MIME message, then
  `openssl cms -verify` verifies its SignedData for the PKCS#1 v1.5, PSS and ECDSA signers. PyJWT
  verifies the PS256 and RS256 JWS that `transports/signing.py` mints. These are lab results on
  synthetic keys and messages, not partner data. PyJWT joins the `[dev]` extra for the tests only;
  the engine still signs with no JWT library. The DIRECT half skips where no OpenSSL 3.0 or later
  with a `cms` command is on PATH. (`BACKLOG #2377`)
- **The audit trail, a user's security events and the connection event log page past their
  first window.** `GET /audit`, `GET /me/security-events` and `GET /events` take `offset` and
  return `total`, `limit` and `offset` beside their rows, plus the snapshot the page was read
  under: `as_of` on the first two and `before_id` on `GET /events`. `GET /events` now returns a
  `ConnectionEventList` object rather than a bare list. Pass the first page's snapshot back with
  each later offset, and rows written in between neither repeat across pages nor move the total.
  Without it, the grant row every `GET /audit` writes before it reads would repeat one row on each
  page. The audit snapshots are timestamps, never row ids: an audit id is global, so the gap
  between two ids would count the lock rows a reader without `users:manage` may not see. Each
  total is counted under the same filters as its page: those lock rows are left out of the total
  too, and a channel-scoped caller's event total counts only its own events. An `offset` or
  `before_id` above 2**62 is refused with 422 rather than overflowing the database bind. The
  store's `list_audit`, `list_connection_events` and `security_events_for_user` take `offset` on
  all three backends, `count_audit` takes `limit=None` for an uncapped count, and
  `connection_event_extent` and `count_security_events_for_user` are new. No schema change.
  (`BACKLOG #2438`)
- **The approver queue says what a release would run and whether it can.** Each row of
  `GET /approvals` now carries `params`, the parameters the hold captured, which a release
  re-runs (vault `BACKLOG #2458`). It also carries `caller_is_requester`, compared on the user id
  as the self-approval refusal is, and `gated`, which is false once dual control no longer gates
  the operation (vault `BACKLOG #2460`). A pending row whose stored params cannot be read as a
  JSON object lists `params` as null, and approving it answers 409 rather than 500. The engine
  still makes every refusal itself; the fields only let a page stop offering a release it would
  refuse. See [SECURITY.md](docs/SECURITY.md).
- **`messagefoundry check` prints an advisory `fhir-update-if-match` line.** It names each
  path-form FHIR update with no `conditional="if-match"` and no static `If-Match` in `headers`. A
  plain `interaction="update"` sends no `If-Match` header, so a server that requires one on update
  would refuse it. The line never blocks: it cannot tell which server a connection points at, or see
  a header a Handler stamps. See [CONNECTIONS.md](docs/CONNECTIONS.md). (`BACKLOG #2570`)
- **A start now writes a `config_loaded` audit row, and `GET /config/provenance` has a baseline
  from the start on.** ADR 0041 D1 named a startup row beside the reload row, and none was written,
  so a restart left no record of which config or which security posture the engine started with.
  The row goes through the same writer as `config_reload`. It carries the config fingerprint, the
  active `security_loosenings()` switches, and the engine shard and cluster node. Every
  `config_reload` row now also names its shard and node, and both rows carry the digest the engine
  took of the bytes it loaded, so the row and the provenance route name one digest. The start, a dry
  run and an applied reload now share one best-effort fingerprint rule. A failed row is logged at
  ERROR and never stops the start. Comparing a start with the previous one and alerting on a change
  is not built yet. (`vault BACKLOG #2597`)
- **A log forwarder that is absent or losing records now raises an alert and shows on `GET /status`.**
  A collector whose certificate failed at start was one ERROR line, and the engine then ran without
  the forwarder with nothing else to say so. A full hand-off queue dropped records behind one
  rate-limited warning that nothing read. On a first deployment, an engine would have run with no
  off-host copy of its log and no page. The new `log_forward_failed` alert fires when a configured
  forwarder is not attached, when records are lost, when the on-disk spool cannot be read, and when
  sends have kept failing for five minutes. Every engine process watches its own forwarder, a
  cluster standby included. Where several processes share a store the alert key names the process,
  as `forwarder:<kind>@node:<node_id>` or `forwarder:<kind>@shard:<id>`, so each has its own alert
  row; a lone engine keeps `forwarder:<kind>`. The new `log_forwarder` field on `GET /status` gives the state and the
  counts. A forwarder that fails
  at start still does not stop the engine. With no spool, a record lost to a TCP or TLS collector that
  is down is now counted; it used to be lost with no count. Over UDP a failed send is still not
  detected, so a UDP forwarder with no fault seen reads `unconfirmed` and never `healthy`, and
  `delivery_confirmed` is `false`. A forwarder that stays absent raises the alert again every five
  minutes. The alert and the field are described in
  [CONFIGURATION.md](docs/CONFIGURATION.md). (`BACKLOG #2612`)
- **The test harness covers transports through pluggable drivers and sinks.** A headless scenario
  now injects through a driver and can assert, byte for byte, what an outbound delivered to a
  loopback sink. Drivers, sinks, endpoints and scenarios are discovered one module per transport
  family. `python -m harness --coverage` prints every connector kind the engine registers, by
  direction, against the scenarios that cover it, read from the live registries. The harness
  config graph reads its ports through `env()`, so `MEFOR_VALUE_HARNESS_<KEY>` moves an endpoint
  under `serve --env`. See [harness/README.md](harness/README.md). (`BACKLOG #2672`)
- **Hostile-content scenarios for the test harness.** `python -m harness --scenario hostile_<class>`
  sends a well-formed HL7 message carrying one hostile value class (path traversal, SQL
  metacharacters, HL7 escapes, redefined delimiters, line breaks, an oversize field, non-ASCII text,
  spreadsheet formulas, markup) over MLLP and File, and checks the disposition, the delivered bytes,
  file confinement and engine health. See [harness/README.md](harness/README.md). (`BACKLOG #2673`)
- **The test harness covers raw TCP and X12** in both directions, with drivers, byte-for-byte sinks
  and scenarios for the delivered, rejected and dead-letter paths. (`BACKLOG #2674`)
- **The test harness covers the Http inbound and the REST, SOAP, FHIR and DICOMweb outbounds**, with a
  loopback HTTP sink that records method, path, headers and body, and retry and dead-letter
  scenarios. The harness graph serves under `[egress] allowed_http` naming loopback. (`BACKLOG #2675`)
- **The test harness has a DATABASE family: a DatabasePoll inbound and a Database outbound.**
  `harness/config/database/` polls a harness-owned SQL Server table and writes another; the
  `database_roundtrip` and `database_unrouted` scenarios drive it through a database driver and
  sink. The family needs a SQL Server, the `[sqlserver]` extra and the ODBC Driver 18, and is
  unverified without them: where any is missing a scenario reports SKIPPED, and
  `python -m harness --scenario` prints `SKIP` and exits 2, which before meant setup only. See
  [harness/README.md](harness/README.md). (`BACKLOG #2676`)
- **The test harness drives DICOM DIMSE end to end.** A driver C-STOREs synthetic, PHI-free objects
  into the engine's C-STORE SCP inbound, and a loopback DIMSE sink records what the C-STORE SCU
  outbound forwards, answering Success or a configured failure status. Three scenarios cover
  delivery, retry then dead-letter, and refusal then dead-letter, matching rows by SOPInstanceUID
  through the audited raw-body route because the engine records a DICOM object with no control id.
  Serving `harness/config` now also binds that SCP, which needs the `[dicom]` extra. See
  [harness/README.md](harness/README.md). (`BACKLOG #2677`)
- **The test harness covers the Email outbound, and proves a Direct round trip.** A loopback SMTP
  sink records what an `Email` outbound submits and can refuse a recipient with 550. Two
  scenarios, `email_delivered` and `email_rejected_recipient`, run against a new graph that
  `serve --config harness/config` now loads: MLLP in on 2660, SMTP out to 2661. A separate
  `harness/config/direct/` graph sends S/MIME over STARTTLS, and the harness tests serve it with
  synthetic certificates minted per run. See [harness/README.md](harness/README.md).
  (`BACKLOG #2678`)
- **The test harness covers REMOTEFILE over SFTP** in both directions, against an in-process SFTP
  server with a pinned, freshly generated host key. FTP and FTPS are not exercised. (`BACKLOG #2679`)
- **The test harness covers the TIMER, LOOPBACK and PassThrough inbounds** with headless scenarios
  against the served harness graph. (`BACKLOG #2680`)
- **`python -m harness --coverage` is a gate.** Every connector kind and direction the engine
  registers needs a harness scenario or a reasoned exemption; a gap prints `GAP:` and exits 1, and
  the same check runs in the test suite. (`BACKLOG #2681`)
- **`python -m harness --fuzz` fuzzes a running engine.** Seeded byte, field and frame mutations go
  to an inbound, and after each batch the harness checks health, that every ACKed message is
  stored, that every reply is a well-formed ACK or NAK, and that no API call fails with a 5xx. A
  failing case prints its seed and writes its bytes for `--fuzz-replay`. Pure Python, so it runs on
  Windows. (`BACKLOG #2682`)
- **Five more Atheris fuzz targets** cover the decoders in front of the parsers: MLLP and TCP
  stream framing, the X12 frame reader, the HTTP listener's request reader, the decompressors and
  the binary-carriage helpers. [fuzz/README.md](fuzz/README.md) gains a recipe for running the
  fuzzers from Windows through WSL2 or a container. (`BACKLOG #2683`)
- **A script the remote-debugging guard refuses is now audited, and it raises an alert.** Until
  now a refusal left one WARNING line in the log and nothing else. Under `serve`, the engine now
  reads the guard's count as it starts, every 30 seconds after that, and as it stops. When
  scripts were refused since the last read, it raises one `remote_debug_refused` alert and
  writes one `remote_debug_refused` audit row. Each carries `count`, the number refused since
  the last one, and `total`, the number since the process started. The process that injects the
  scripts chooses how often it tries, so it gets at most one row and one alert for each read.
  Neither carries the script's file name, which that process also chooses. The name stays in
  the WARNING line. The alert's `connection` is `remote_debug:refused`, with the engine
  process's label appended where several share a store. A rule can match
  `event_type = "remote_debug_refused"`. Nothing resolves the alert, so an operator does. Other
  commands, such as `supervise`, `rotate-key` and `backup`, build no engine and still log the
  WARNING only. [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md) has the detail, under
  `remote_debug_enabled`. (`vault BACKLOG #2742`)
- **A refused CRL reload now raises its own alert, `crl_reload_refused`.** When the engine refuses
  a replaced CRL file, running TLS hops keep the copy they hold, and a revocation added to the new
  file is not enforced on them. Before, the only signals were an ERROR line in the log and, once
  the held copy neared its `nextUpdate`, the CRL expiry alert. The new alert carries the file, a
  short `remedy_class` token, the count of TLS contexts still on the old copy, the engine's own
  remedy sentence and, when a start would refuse the file too, a `start_refuses` flag. It carries
  no CRL contents: the reason is left out of it, and is in the log.
  The engine raises it
  once per version of the file, and resolves it with the inverse `crl_reload_applied` once the
  file is applied or the refusal is cleared, and when the engine stops. A rule can match
  `event_type = "crl_reload_refused"`. The fields, the class tokens and when the alert resolves
  are in [CONFIGURATION.md](docs/CONFIGURATION.md), under "CRL files". (`BACKLOG #2904`)
- The `/config/reload` response carries `restart_required`, the settings trust anchors a
  restart must apply. `null` means the check did not run (a dry run skips it); an empty list
  means it ran and nothing needs a restart. A released dual-control reload reports the same
  field. (`BACKLOG #3015`)

### Changed
- **The engine no longer says nobody can sign in when no Administrator exists.** A Windows sign-in
  (Kerberos), where configured, is not refused for want of an Administrator: on a new store it
  creates a directory account with no role. The start-up WARNING for a store with no enabled Administrator, logged when
  the security-notice gate is skipped, now begins `the engine is starting with the notice gate
  skipped:` instead of `the engine is starting with no way to sign in:`. Its detail, also used by
  the refusal at the shipped posture, now says no enabled account holds the role that manages users
  and roles. The `provision-admin --help` text
  now says nobody can manage a new install until it runs, not that an install has no way to sign
  in. This corrects an earlier release's start-without-an-Administrator note, which said nobody
  can sign in until `provision-admin` runs. (`vault BACKLOG #1133`)
- **The MFA posture texts say which sign-ins the second-factor switches free, and no longer say
  "admin".** With `[security].require_mfa` off, `security show` and `GET /security/posture` now
  say a checked OIDC amr/acr claim counts as the second factor, whether or not one is enrolled.
  The exposed-without-MFA refusal no longer names the OIDC exception twice. Its directory clause
  points back at the sentence that names it. In VS Code, the Security Settings label for
  `allow_single_factor_admin_when_exposed` now reads "Allow single-factor sign-in when exposed".
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md) and
  [CONFIGURATION.md](docs/CONFIGURATION.md) say that switch covers every account with no second
  factor enrolled, OIDC exception aside. The setting's name is unchanged. (`vault BACKLOG #1133`)
- **`messagefoundry cert self-signed` now calls its pair a placeholder, not a dev-only
  certificate.** The engine serves the same kind of self-signed certificate on first run when no
  `[api].tls_cert_file` is set and no upstream TLS terminator is declared (ADR 0172), so "never
  front production PHI" no longer matched what the engine does. The command's console note and
  the `note` field of its `--json` output now share one text, and its help says the same thing:
  the pair has no chain of trust, so it is better than cleartext and worse than an
  operator-supplied chain, and it is a placeholder to replace. The VS Code walkthrough now gives
  the `messagefoundry.engineUrl` default as `https://127.0.0.1:8765`, matching the setting itself.
  (`vault BACKLOG #1276`)
- **`admin-set-notify-email` and `provision-admin` exit 2, could not start, when the store cannot be opened or the audit chain's key check refuses the command's audit row.** That covers a keyed store opened from a shell without its key (`StoreKeylessError`), a row the open cannot read (`CipherError`: a row the key in this shell cannot decrypt, or a corrupt row), and, for `admin-set-notify-email`, a keyed audit chain with no key in this shell. Each exited 1; `admin-unlock` already exits 2 on that key check. A busy store that refuses `admin-set-notify-email`'s audit row, such as a running engine holding the write lock, still exits 1. This is a seat decision under owner delegation 2026-10-08, not an owner ruling. (`BACKLOG #2124`)
- **The keyless-backup refusal no longer calls `[backup].allow_unencrypted` a setting for a
  synthetic or no-PHI box.** No such box exists since every instance carries patient data
  (ADR 0186). The message now names the key first and says a cleartext archive can hold PHI.
  The setting and the refusal are unchanged. (`vault BACKLOG #2250`)
- **A trust-anchor path that is set is checked even when nothing loads it, and the docs now say
  so.** `[auth].ad_tls_ca_cert_file` with AD off or on plain `ldap://`, or
  `[auth].oidc_tls_ca_cert_file` with OIDC off, refuses the start, and every reload that is not a
  dry run, when the file cannot load. Unset a path nothing uses. The behaviour is unchanged since
  BACKLOG #2025; this records it in [CONFIGURATION.md](docs/CONFIGURATION.md) and pins it with
  a test. (`BACKLOG #2269`)
- **A client sign-in now ends the session it replaces inside the sign-in request.**
  `EngineClient.login` and the VS Code extension send the token they are replacing in the
  `supersedes` field of `POST /auth/login`, and no longer post `/auth/logout` after it. The engine
  ends that session before its per-user session cap counts, so a user at the cap keeps their other
  sessions. `EngineClient.login` names only a token the engine issued to it, never one adopted with
  `set_token`, which still ends a replaced token with its own `/auth/logout`. The cost: if the
  sign-in reply is lost or times out after the engine accepted it, the client holds a token that has
  already ended and must sign in again. An engine older than 0.5.0 refuses the new field.
  (`BACKLOG #2281`)
- **`[backup].allow_unencrypted = true` is now a reported loosening, with a guide entry.** With no
  store key, that flag lets the backup runner write a cleartext archive, which can hold PHI. With a
  key, it lets the restore-verify accept a plaintext archive. `security_loosenings()` names it as
  `backup.allow_unencrypted` whenever it is set, so the serve-time warning,
  `messagefoundry security show` and `GET /security/posture` list it. Nothing refuses the flag, and
  the setting itself is unchanged. See [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md).
  (`vault BACKLOG #2302`)
- **`tray.log` and the IDE's "MessageFoundry Checks" output now carry UTC time stamps.** A
  `tray.log` line starts with the engine log's form, `2026-01-02T03:04:05Z`. Before, it was local
  time with no offset, with milliseconds; the new form is whole seconds, as the engine's is. Every
  line of the Checks output starts with an ISO 8601 UTC instant, with milliseconds; before, it
  carried no time. "Commit baseline anyway" now writes a line there, before it commits, saying the
  commit hooks were skipped by the user's choice (`git commit --no-verify`). The commit itself is
  unchanged. The IDE's "MessageFoundry Engine" output is stamped by the editor, in the editor's own
  format, which the extension does not set. (vault `BACKLOG #2349`, `BACKLOG #2353`)
- **ADR 0200 Amendment A is accepted.** The forwarding start gate's own-host check was built
  ahead of a ruling. The owner accepted it as built on 2026-10-08: the gate refuses this host's
  own OS name and addresses, reads local host state to do so, and fails open with a logged
  WARNING. The ADR and its index row say so, and the `forward_spool_max_bytes` row of
  [CONFIGURATION.md](docs/CONFIGURATION.md) no longer says the gate reads configuration only.
  No behaviour changes. (`vault BACKLOG #2375`)
- **The shipped Kubernetes manifests set `enableServiceLinks: false`.** The engine reads no
  service-link variable, and a Service named `mefor` or `mefor-<section>` would otherwise inject
  names the settings loader refuses at start. Cluster DNS is unaffected. See
  [CONFIGURATION.md](docs/CONFIGURATION.md). (`vault BACKLOG #2600`)
- **`messagefoundry security show` says why a report is partial.** The new
  `loosenings_partial_reason` field carries the settings-load failure as every other command
  renders it: the refused input is hidden, and each validator's message is shown as written. It
  is `null` when the report is complete. A mistyped `MEFOR_<SECTION>_<KEY>` variable in the
  shell is one cause, and the reason names it and not its value. (`vault BACKLOG #2600`)
- **`[backup].destination`, `[dr].seed_archive`, `[dr].seed_dir` and `[dr].restore_token` refuse
  a `<scheme>://` URL whose scheme has two or more characters, and the refusal quotes the scheme and no longer
  the URL.** A fixed list of
  seven cloud schemes let `sftp://` or `s3a://` load as a local path. A URL can carry a
  credential, and a load failure is printed to stderr, to a service log and now to
  `security show`'s JSON. The `[dr].seed_dir` absolute-path refusal no longer quotes the value
  either. A drive letter (`C://`) and a UNC path are still paths. (`vault BACKLOG #2600`)
- **`serve` logs the unread-`MEFOR_*`-variable warnings again once logging is configured,** so
  they reach the log file and the off-box forwarder, not only stderr. Every command now logs them
  before the key and value refusals, so one refused key does not hide a mistyped variable. A
  missing, unreadable or malformed settings file still stops the load before they are logged.
  (`vault BACKLOG #2600`)
- **On Windows, a secret reference written in another letter case still spares its variable.**
  Under `[secrets].provider = "env"` the unknown-variable refusal compares the two names as the
  platform does: ignoring case on Windows, exactly elsewhere. (`vault BACKLOG #2600`)
- **The development standards now describe review and planning as the process runs them.**
  [Secure_AI_Development_Standards.md](docs/Secure_AI_Development_Standards.md) said the
  maintainer reviews every diff and approves a plan before every edit. No human reads every
  diff. Review before merge is an AI code-review pass, a proof check, the deterministic gates
  and the owner's rulings, and it is not an independent review. Appendix A.6 records the
  controls the process does not have.
  [Code_Quality_Standards.md](docs/Code_Quality_Standards.md),
  [Secure_Build_Standards.md](docs/Secure_Build_Standards.md) and
  [Secure_Development_Standards.md](docs/Secure_Development_Standards.md) no longer say a
  human reviews or arbitrates. The process itself is stated in `CLAUDE.md` section 5.
  (`vault BACKLOG #2631`)
- **The `[dicom]` extra now requires `pynetdicom>=3.0.4,<3.1`, where 0.5.1 allowed `<4`.** The
  DICOM listener runs its own association server, a subclass of pynetdicom's. It checks the peer
  address and bounds the TLS handshake in `socketserver` hooks that pynetdicom 3.0.4's server
  runs through. The listener already refuses to start on a pynetdicom that left those hooks, but
  a site would only learn that at startup. The cap keeps 3.1 and later out at install time,
  until that server is re-read against the new release. A 3.0.x patch is still allowed. No final
  pynetdicom 3.1 has been published, so the cap rules out no stable release. It does rule out
  the `3.1.0.dev0` development release on PyPI, which an install that opts into pre-releases
  could pick under the old cap. The lock already pinned 3.0.4, so no pinned version moves.
  (`vault BACKLOG #2713`)
- **CI and load rigs sign in.** Every test-harness runner that starts `messagefoundry serve`
  (`--failover`, `--connscale`, `--estate`, `multishard`, `shardcert`) now provisions one
  Administrator in that engine's store and reads the API with that account's session. The CI
  legs that serve an engine do the same. A run against a store you keep needs
  `MEFOR_RIG_ADMIN_USERNAME` and `MEFOR_RIG_ADMIN_PASSWORD` set, because a store that already has
  an Administrator cannot be provisioned again. The helper is test tooling and adds no password
  input to any shipped command. No engine behaviour changes. A signed-in poller is not free: the
  engine does six store commits for each poller sample, so `txn/msg` and DB growth figures taken
  after this change are not comparable with earlier ones until that is taken off. See
  [LOAD-TESTING.md](docs/LOAD-TESTING.md). (`vault BACKLOG #2719`)
- `create_managed_app` built with no `auth_settings` and without `allow_no_auth` now logs one
  WARNING at build, naming `authentication is not configured`. The app still builds and still
  refuses the permission-gated routes; the line says so instead of leaving it silent. `serve` always
  passes `auth_settings`, so it never logs it. (`vault BACKLOG #2731`)
- **A TCP connection refuses `0x20` (a space) as its `start` or `end` frame byte.** A reply's frame
  bytes are replaced by a space, so a space frame byte could not be kept out of a reply. A `0x20`
  `trailer` is still allowed. The refusal fires when the connection is built. (`BACKLOG #2900`)
- **A cluster node refuses the connection flag toggle.** `POST /connections/{name}/flag` answers
  409 on a cluster node and writes nothing. Each node loads its own config directory, so the
  toggle would have changed that node's `connections.toml` only. To flag a connection in a
  cluster, set `flagged` on its entry in the `connections.toml` you deploy to every node, and
  apply it with a coordinated restart. See [CLUSTERING.md](docs/CLUSTERING.md). (`BACKLOG #2933`)
- **Engine config writes record their own baseline through one helper.** An engine write of a
  file the config digest covers, today the connection flag toggle, now writes the file, takes
  the digest and records the `connection_flag_set` audit row in one step. The start's
  config-change check reads its action names from that helper, so it has no second list to
  keep in step. A test fails when engine code writes a config file any other way. A change made
  by a CLI subcommand still raises `config_changed` at the next start, unless a reload loads it
  first. (`BACKLOG #2945`)
- **A config write whose audit row does not land is undone and refused.** When the engine writes a
  file the config digest covers, today only through the connection flag toggle, its audit row is
  now bounded at 10 seconds. A row that fails or runs past that bound first restores the bytes of
  the files the write declares it touches, and the toggle then answers 503, since the audit log and
  not the request is at fault. A row or write that is cancelled is undone the same way, and the
  cancellation is passed on. At least these still leave a write on disk with no row: a file another
  edit changed in the meantime, which is left as that edit wrote it; a file the undo could not
  read, write or lock; a file the write changed but did not declare; and a crash before the row.
  The 503's detail says when the write could not be fully undone, and the next start reports each
  of these as a config change. (`BACKLOG #2945`)
- **The API client waits longer for a sign-in's reply.** `EngineClient.login`, `reauth`,
  `verify_mfa` and `confirm_mfa` now wait up to 30 seconds for the engine's reply, matching the
  IDE's sign-in timeout, instead of the client's 5 second default. Each can wait in the engine's
  per-account queue, and a request the client gave up on could still end or rotate the session it
  held, leaving the client signed out (and, for `confirm_mfa`, without its recovery codes). Only the
  read phase is raised: an unreachable engine is still reported within the client's own timeout.
  The longer wait makes a lost reply rarer, not impossible, because the queue has no bound. Every
  other request keeps the client's timeout. (`vault BACKLOG #2950`)
- **A directory refusal at the second factor, an enrolment or a step-up names the fix for its
  cause.** When a directory refuses an account at `/auth/mfa-verify`, `/me/mfa/confirm` or
  `/me/reauth`, the proof is not checked, except on at least the password re-bind refusals that
  come after the bind accepted the password, which the `vault BACKLOG #3081` entry lists. The 403
  now has one text per fix. A
  role the account lost in the directory since it signed in is told to sign out and sign in again,
  which takes the roles its groups grant now. Every other cause, an outage included, is told to try
  again later and, if it is still refused, to ask an administrator, never to sign out, since a new
  sign-in would fail the same way. A group-to-role map that fails its seal is in that second group,
  audited as `directory_role_map_unsealed`: a new sign-in reads the same map, and an administrator
  re-saving it is the fix. The identity provider step-up leg has its own texts for a demotion and an
  unsealed map. No text names a group or a role. Breaking for an embedder:
  `Elevation.directory_unconfirmed` is replaced by `directory_refusal`, a `DirectoryRefusal`, which
  is `None` when no directory refused. (`BACKLOG #3082`)
- **A File inbound refuses a negative `min_age_seconds` at build.** A negative value used to build
  and act as zero. It is now a build error naming the setting, with the value withheld. Zero, the
  default, and any positive value build as before. (`BACKLOG #3151`)
- **An upload no longer runs the uploaded-logs retention sweep on its own request.** Under `serve`,
  the upload route wakes the retention runner, which sweeps in the background and audits each
  pruned file as before. An app built without the runner still sweeps at save time. The sweep now
  writes each `upload.prune` row as soon as it removes that file, so a shutdown that cuts a sweep
  short loses at most the row of the file in progress. Each quota check now walks the uploads
  directory once rather than twice. (`BACKLOG #3184`)
- **Open-mode follow-ups: one check, one 503 text, and removed-key refusals that name the right fix.**
  The four places that ask whether an app runs with no sign-in now call one helper, and what the
  open mode permits is unchanged. With no auth service attached, the sign-in routes and the web
  console's account pages now answer 503 `authentication is not configured`, whether or not the
  app opted in to the open mode. That is the text the permission gate already gave when it
  refused; they used to say `authentication is not enabled`, which named
  a switch that no longer exists. The refusal for a removed settings key now fits where the key
  came from. The loader names the config file and the `MEFOR_` variable, for all six removed keys.
  A section built in code, or `[security]` read by `messagefoundry security show`, no longer tells
  you to unset an environment variable it never read. `AuthSettings` built in code with `enabled`
  now gives that same refusal as every other removed key, and still points at `allow_no_auth=True`.
  (`vault BACKLOG #3216`)
- **Breaking: `[dr].enabled` with `[cluster].enabled` is refused at config load**, as
  `[dr].activate` with it already was. A DR box that is not activated is passive, so as a
  cluster leader it would serve nothing. Run a warm DR-site engine as a non-promotable cluster
  member (`[cluster].promotable = false`), not as a `[dr]` box. (`vault BACKLOG #3263`)
- **A released replay or purge whose COMMIT reply was lost is now documented as recorded
  `failed`.** The effect and its audit row are committed, the request still moves to `failed`, and
  that row is not forwarded off-box. [SECURITY.md](docs/SECURITY.md) and the `Executor` and
  `approve()` docstrings now say so, and a test pins it. Tests now also refuse the COMMIT of a
  dual-control request, a dual-control transition and an administrator's TOTP replacement after
  the audit row was appended, on SQLite and SQL Server, and show that nothing is kept or forwarded
  off-box. The TOTP replacement gains a refused-append test on all three backends, and the INFO
  lines of a repeat approval request are tested to escape a CR or LF in the requester's name. No
  behaviour changed. (`BACKLOG #3324`)
- **A refused CRL reload is reminded about while the refusal stands.** The `crl_reload_refused`
  alert was raised once per version of the file, so a page that was throttled, muted or resolved
  by hand was never sent again. The engine now raises it again every five to six minutes while
  the refusal stands, as `intake_paused` reminds, with the same fields. It stops once the engine
  resolves the alert; a resolve by hand does not stop it. Each reminder counts as an occurrence, so count-based `escalate` tiers climb while the
  refusal stands. The notifier's cooldown still spaces the pages. See [CONFIGURATION.md](docs/CONFIGURATION.md), under "CRL
  files". (`vault BACKLOG #3543`)
- **A paged LDAP group search has one overall deadline, and its cap counts groups, not pages.**
  All the pages of the nested group search now share one deadline, the new
  `[auth].ad_group_search_deadline`, 120 s by default. Each page's reads stay bounded by
  `[auth].ad_receive_timeout`. Before, each page could take the whole receive timeout. It is not
  a hard wall-clock bound. A search still paging at the deadline is refused as the directory not
  answering. The search is now refused past 10,000 groups at any page size. Before, it was
  refused past 20 pages, which is 2,000 groups at 100 a page. Both refusals warn. **The session
  reconciler pages, and audits `auth.ad_reconcile_paging_refused`, for an account either refusal
  leaves unjudged**, once as the account enters that state rather than on every pass. A disable or
  deletion still revokes such an account; its role and scope re-diff does not run. A plain
  directory outage still pages nobody. A deadline above its default is a named loosening. The
  limits are in [CONNECTIONS.md](docs/CONNECTIONS.md), the Active Directory rows of Table B.
  (vault `BACKLOG #3696` items 3 and 4)
- **`audit-verify` prints a `FAIL` line and exits 1 when a key, key-provider or database error
  stops the check while it reads the chain's rows**, such as a Transit outage or a row that is
  not UTF-8, including the rows the store open reads. These reached the last-resort handler
  (exit 1) or the store-open refusal (exit 2) with no `FAIL` line, so a job on a first deployment
  would have had nothing to read, or a code a planted row could pick. The line names the error's
  class and its cause's class, never its text. A store that cannot be reached at the open now
  exits 2 on every backend. That covers at least a refused connection and a failed login, which
  on a server backend exited 1 at the last-resort handler. A server driver's error with a SQLSTATE is shown
  as its class, SQLSTATE and native error number, not its text, and a failed close never changes the exit code. `audit-anchor`
  also exits 2 when its store cannot be reached. A store cipher the settings
  cannot build, a key that is not base64 of 32 bytes among them, now exits 2, could not start,
  from at least `audit-verify`, `audit-anchor`, `admin-unlock`, `admin-set-notify-email`,
  `admin-reset-totp`, `provision-admin` and `rotate-key`; it exited 1 at the last-resort handler.
  `admin-unlock` and `admin-set-notify-email` also exit 2 on a key that does not resolve. The
  admin commands' shared host gate exits 2, not 1, for settings it cannot load and for an absent
  store. A store-open error no longer prints the text of a row SQLite could not decode. With a
  matched `--expected-anchor`, the exit-5 warning scopes a rewrite as keyless to before the anchor
  was taken. The exit table is in the *Tamper-evidence* paragraph of
  [SECURITY.md](docs/SECURITY.md).
- **The repository's locks, and so the container image, move FastAPI from 0.143.0 to 0.143.1, and
  `pyproject.toml` now requires `fastapi>=0.143.1`.** 0.143.1 is the first release whose
  `RouteContext` answers from the rebuilt route, the shape the route-gate walk and the refusal count
  now read. The required CI legs install through `constraints.lock`, so the lock decides which
  shape they exercise; before this, they ran the walk against only a simulated read of the new
  shape. 0.143.1 was published on 2026-10-14, past the five-day release cooldown
  `.github/dependabot.yml` sets for this ecosystem. When this lock moved, newer releases, such as
  0.153.0 (published 2026-10-20), were still inside it. The floor moves with the lock, because no
  required leg runs the older shape, so `pyproject.toml` no longer allows a release that has it.
  This supersedes the 0.140.0 and 0.142.0 floors other entries state. The advisory
  `dependency floors` workflow therefore installs 0.143.1 as the floor. No advisory prompted this.
  0.143.1 needs no newer Starlette, and the lock keeps 1.8.0. Not refreshed here:
  `security/bundled-code-survey.json` and `security/risky-component-readings.json` still describe
  FastAPI 0.142.2. They are dated snapshots made by hand. (`vault BACKLOG #3916`)
- **The `[harness]` extra now requires `PySide6>=6.6,<6.12`, where 0.5.1 allowed any later
  release.** PySide6 6.12 moves the Qt web engine and PDF modules out of `pyside6-addons` into two
  new distributions, `pyside6-pdf` and `pyside6-webengine`, that
  [RISKY-COMPONENTS.md](docs/RISKY-COMPONENTS.md) does not yet assess. The cap holds until it
  does. It also withholds any Qt fix shipped only in 6.12 or later. An install that already has
  PySide6 6.12 moves back to 6.11. The lock already pinned 6.11.2, so no pinned version moves.
  (Dependabot PR 2416)
- **Linux is not a supported v1 deployment target.** Windows is the only supported v1 deployment
  platform. Linux is not, on a host or in the container image. The engine drops the
  `Operating System :: POSIX :: Linux` classifier. The ruling is in
  [SYSTEM-REQUIREMENTS.md](docs/SYSTEM-REQUIREMENTS.md#linux-is-not-a-supported-v1-deployment-target),
  and at least the deployment, install, container and early-adopter docs link to it. ADRs 0017, 0047
  and 0149 gain dated amendments. `docker/compose.yaml` and the two Kubernetes reference manifests
  gain a header line saying they are not a supported v1 deployment. The code, the image, what the
  manifests deploy, and CI are unchanged.
- **BREAKING -- an unknown top-level section in `messagefoundry.toml`, or a key written above the
  first `[section]` header, now fails the start instead of loading silently.** This extends the
  0.4.0 refusal of an unrecognized key one level up. A misspelt section dropped every key under it
  at once: `[integrty]` with `fail_closed_on_drift = true` loaded clean and left the opt-in
  integrity tripwire alert-only while the operator believed it failed closed. The error names the
  section and the nearest real section name, and never the value. The scope is the config FILE
  only, as for keys: a `MEFOR_*` variable naming no section is still dropped by the env layer.
  `[engine]`, which [CONFIGURATION.md](docs/CONFIGURATION.md) used to describe as a tolerated
  section with no model, is refused like any other.
  **Who this would bite on first deployment:** a config file carrying a section the engine does
  not model, such as a typo or a section copied from newer documentation. **Remedy:** correct the
  spelling, or remove the section; it was doing nothing before. (2026-10-02 full review,
  decision 10)

### Fixed
- **An engine that restarts settles the dual-control releases it left `executing`.** The claim now
  records which engine process owns the release, in a new `pending_approvals.claim_owner` column on
  all three store backends. At its next start, before the API serves an approval, that process moves
  each `executing` row it owns to `interrupted` with an `approval.interrupted` audit row, `reason`
  `engine_restart`, in the same write. Nothing re-runs; resolve the row as for any interrupted
  release. A row another engine shard or cluster node owns is left alone and logged at WARNING. A
  cluster node keeps its owner across a restart only when `[cluster].node_id` is pinned. This also
  gives a row left `executing` by a twice-failed outcome write a way out. (vault `BACKLOG #1562`,
  `BACKLOG #2087`)
- **A shutdown cancelled partway through still stops the engine.** A cancel delivered while the
  managed lifespan drained approval writes, or flushed the summary-access audit, used to skip
  `engine.stop()`, so the store's worker could keep the process alive. An app built with
  `create_app(engine=...)` now drains approval outcome writes at its own shutdown too, instead of
  relying on the caller to. (vault `BACKLOG #2087`)
- **A held config reload whose directory vanished, or that named a directory outside the reload
  roots, is refused on release instead of answering 500.** The approve route answers 422 with the
  inline route's detail, and writes the `config_reload_failed` or `config_reload_denied` row the
  inline route writes. A refused reload's own audit row no longer raises during an audit outage.
  (vault `BACKLOG #2459`)
- **The approval gate answers a mapped status during an audit or store outage, and pages.** A
  too-early, stale-requester or no-longer-gated refusal whose audit row fails still answers 409. A
  claim, rejection or resolution that cannot be written with its audit row answers 503. A new
  `audit_write_failed` alert, keyed `approval:<id>`, pages on many failed audit writes. Some
  failures page nothing, and a cancel mid-write gets no ERROR line or alert from the gate on some
  writes. docs/SECURITY.md names at least the cases each way. Store reads on these routes are not
  mapped. Nor is a failed request write: it answers 500, or 503 if the request timeout cancels it.
  (vault `BACKLOG #2255`)
- **Each approval state change and its audit row are now one write.** The request and
  `approval.requested`, the claim and `approval.release_attempted`, a rejection, each release
  outcome and a resolve each commit or roll back together, on all three store backends. A request
  whose audit row fails is no longer written and then withdrawn; it rolls back with the row. Some
  failures can still hold the request while the call fails, such as a lost COMMIT reply or a
  cancel during the COMMIT. docs/SECURITY.md names at least these cases. It also says when a retry
  then files a second request. A rejection whose `approval.rejected` row fails now answers 503 and
  stays pending. A claim that loses a race writes
  no release row. The resolve no longer writes `approval.resolve_attempted`; its `approval.resolved`
  row goes with the move. After an operation has run, an outcome that cannot be written with its row
  is written alone, so the request never stays `executing` for that reason. (vault `BACKLOG #2255`)
- **A repeat of an open dual-control request no longer files a second one.** When the same
  requester asks again for the same operation with the same parameters while the first request is
  pending, the route answers the same 202 with the first request's id and writes an
  `approval.request_repeated` audit row. Concurrent repeats file one request between them, on all
  three store backends. A different requester still gets a request of their own. (vault
  `BACKLOG #2445`)
- **A held request is no longer released after dual control stops applying to it.** Before, a
  request held while `[approvals]` gated its operation could still be approved, and run, after
  `[approvals].enabled` was turned off or the operation left `[approvals].operations`. The approve
  now answers 409 with an `approval.no_longer_gated` audit row, runs nothing, and leaves the
  request pending for an approver to reject.
- **An MLLP, HTTP or DICOM listener's CRL refusal now names the connection and its
  `tls_crl_file`.** A missing or bad per-connection CRL used to be reported only as
  `CRL file '<path>'`, so the operator had to work out which connection it belonged to. It now
  reads `inbound connection '<name>' tls_crl_file ('<path>')`, the shape the inbound CA's refusals
  already use. A CRL reload refusal for a file that hops with different settings share names the
  file by its path, instead of whichever setting the reload pass met first.
  (`vault BACKLOG #1997`)
- **The admin-write `429` now says how long to wait.** Its `Retry-After` was a literal `1` on the
  JSON API and `10` on the `/ui` console, whatever the window was. A client that honoured either
  could have retried inside the default 15 s window and been refused again. Both surfaces now send
  the time until that account's next write would be admitted, in whole seconds, rounded up and
  never below 1. A client that reads the header as a number needs no change. (vault
  `BACKLOG #2144`)
- **The JSON step-up refusal tells an `oidc` session to step up at the IdP.** Every JSON step-up
  gate used to answer "POST /me/reauth then retry", and `POST /me/reauth` refuses a session the
  federated sign-in minted. So a bearer client holding such a session would have met a second 403.
  For an `oidc` session the refusal now names the web console's `/ui/reauth` and adds the header
  `X-Step-Up-Via: idp`. Every other session's refusal is unchanged. The engine client raises
  `IdpStepUpRequired` on that header rather than prompting for a password. The hint is a pointer:
  the IdP step-up still runs in a browser, so a bearer client cannot finish it. See
  [SECURITY.md](docs/SECURITY.md). (`BACKLOG #2158`)
- **`POST /me/reauth`'s own refusal of an `oidc` session now carries `X-Step-Up-Via: idp`**, the
  header the step-up gates send such a session. So `EngineClient.reauth()` raises
  `IdpStepUpRequired` there too, rather than a plain `ApiError` a caller had to tell apart by its
  text. The status and detail are unchanged. See [SECURITY.md](docs/SECURITY.md).
  (`BACKLOG #2158`)
- **A 2xx reply with a body over the byte bound is no longer sent again.** On the REST, SOAP, FHIR
  and DICOMweb destinations an over-size reply body raised a retryable error even after a 2xx, so
  on first deployment each retry would have re-sent a request the partner had already answered
  with a 2xx, and the message would then have dead-lettered after the retries ran out. The
  request is now sent once. Where nothing looks inside the body, the message is recorded
  delivered, the body is dropped, and a WARNING names the connection: REST with
  `capture_response` off, and FHIR with it off unless the write is an update the engine sends
  as a transaction. Everywhere else the engine needs the body or passes it on, so the delivery
  is a permanent refusal with the new code `reply-too-large` and the message dead-letters once:
  SOAP, DICOMweb, REST or FHIR with `capture_response` on, and a FHIR update sent as a
  transaction. The table is in the REST section of [CONNECTIONS.md](docs/CONNECTIONS.md).
  (`BACKLOG #2180`, owner ruling 2026-10-05) The ruling names the principle, which is to judge
  the body by who reads it. It does not name the FHIR cases that refuse: every FHIR write with
  `capture_response` on, and an update sent as a transaction with it off. Refusing those is a
  reading of the ruling made when this was built, and the owner may reverse that reading.
- **A reload refused over an unreadable inbound CA now audits `reason: "trust_anchor"`.** It used
  to audit `invalid_config`, while an unreadable settings anchor audited `trust_anchor`, so one
  audit filter for refused anchors missed the inbound case. On an inbound with both `tls` and
  `tls_ca_file` set, a `tls_ca_pin` that is blank or not text now audits `trust_anchor` too, and so
  does a `tls_ca_file` path holding a NUL. The direct `/config/reload` route and a released held
  reload both changed.
  (`BACKLOG #2183`)
- **The feature map and the ADR index no longer call the anonymizer's output PHI-free.** Both now
  say "de-identified", and both link to [PHI.md](docs/PHI.md) §9 for what the leak-check
  refuses and what it lets through. The feature map no longer says `tee/anon/` is a byte-identical
  copy of `messagefoundry/anon/`. Only some files are, and `tests/test_anon_parity.py` is the
  record of which. The harness `CaptureSink` docstring now shows `anonymize_checked` wired with
  `on_report`, which is how a caller gets the coverage report. It also says what else to check
  before sharing a capture. (vault `BACKLOG #2245`)
- **The anonymizer no longer refuses a legal empty segment, and its coverage line is harder to
  misread.** Five defects from the 0.5.0 leak-check work are fixed. (`BACKLOG #2247`)
  - A segment with no fields and no field separator, such as a bare `PV2`, is legal HL7. The
    anonymizer refused it as a malformed line, which failed a whole `python -m tee
    anonymize-captures` dataset. It now passes when the message's HL7 version defines the id,
    or when a rule that rewrites a field names the segment. A bare `LEE` or `ZOE` is still
    refused. So is a bare Z-segment id such as `ZPD` that no such rule names.
    A bare id from a later HL7 version than MSH-12 names, such as `SFT` in a 2.3 message, is
    refused as well.
    This supersedes the sentence in the 0.5.0 entry for `BACKLOG #1710` that lists a line "with
    no field separator (a legal empty segment such as `PV2` included)" among the refused ones.
  - The coverage line and the `LeakError` text said `denylist tables live: yes` whenever the tables
    loaded, even when the floor check had failed because a section was missing. They now say `yes`
    only when the tables loaded and passed the floor check.
  - `--log-level WARNING` hid the coverage line, the only record of what passed. The line is now
    printed plain to stderr at a level quieter than INFO.
  - Every `LeakError` suggested repairing a malformed line, even when a token was the cause. The
    advice now has one sentence for each kind of cause that fired.
  - The engine and the tee disagreed on a whitespace-only line at the start or end of a message.
    The tee kept it and the engine dropped it. Both now drop a line holding only whitespace or
    control characters. They still differ on whitespace after the last field of the last line.
- **The save-time upload prune now writes an `upload.prune` row for every file it removed, even
  when the request is cancelled.** The prune that runs after an upload had no way to stop. When the
  request deadline cancelled the upload mid-sweep, the sweep kept deleting aged files and no audit
  row was written for any of them. A cancel now tells the sweep to stop at its next file, and the
  upload waits up to 5 seconds for the rows of what it removed. A sweep still running at that bound
  is logged, and so is a later failure. The upload now also survives any prune error, not only a
  filesystem one, and a failed orphan sweep no longer drops the rows for files already pruned.
  (`BACKLOG #2261`)
- **A cancelled upload save now removes a file that already landed.** A cancellation that reached
  `save` after the body and its metadata sidecar were on disk used to keep both. The file was
  stored with no `upload.create` audit row, while the client was told the upload failed. The save
  now removes the pair, and logs at ERROR if the filesystem refuses. A caller cancelled in its own
  audit write, after `save` returned, still keeps the file. (`BACKLOG #2262`)
- **A cancelled upload save now pays its cross-engine-shard quota slot back.** A save cancelled while its
  quota reserve or release was running could leave the slot held. That narrowed the uploader's
  budget until the reservation went stale. The save now waits a bounded time for both calls to
  finish before the cancellation goes on. At least a few cancelled cases still leak a slot, such as
  a release that fails. The `UploadQuotaError` docstring in `messagefoundry/uploads.py` lists them.
  (`BACKLOG #2263`)
- **The upload retention stop logs an audit gap only when one exists, and names the files.** At
  shutdown the retention runner gives a sweep in flight a bounded wait, then cancels it. It used to
  log an ERROR saying files may have lost their `upload.prune` row, even when the sweep had removed
  nothing. It now tracks each file the sweep removed and each row written. The ERROR names every
  removed file with no row yet, and a sweep that lost no row logs a WARNING instead. A runner with
  no audit callback says it owed no rows. (`BACKLOG #2264`)
- **`python -m tee anonymize-captures` reads `anon.toml` once, before the first message.** It
  used to re-read the overlay for every captured row, inside the handler that counts any error as
  one failed message. So a malformed overlay would have been reported as "N message(s) failed
  anonymization", with advice to extend the rule map. A bad overlay now refuses the run with one
  `error:` line naming the problem, and no dataset is written. The same load prints one
  `warning:` line when the overlay keeps a field the default rules scrub; `--log-level` does not
  hide it. (vault BACKLOG #2267, #2268)
- **The `intake_paused` alert keeps reminding while its probe fails, and its reminder no longer
  slips an interval.** While a pause held and the depth read or disk probe kept failing, intake
  stayed paused but the reminder stopped, which would read as a pause that had ended. The reminder
  now fires on its usual cadence and carries the last reading, so the disk alert's text says
  "MiB free at the last reading" rather than "now". The reminder window is measured from after the
  sink returns, so it can no longer land just inside the notifier's own cooldown and be throttled
  for a whole interval. The emitters of `intake_paused` and `queue_buildup` now read their
  300-second reminder spacing from one constant. The notifier's own cooldown,
  `[alerts].realert_seconds`, is still a separate setting. (BACKLOG #2272)
- **Alert state writes for one condition now reach the store in the order they were raised.** The
  alert sink ran each open and each auto-resolve as its own background task. A slow open could
  then land after the clear raised behind it, so a recovered connection kept showing an open
  alert. The reverse could happen too. Writes for the same alert type and connection now queue in
  emit order, while writes for different conditions still run side by side. Each write records
  the time the sink raised or cleared the condition. Before, the store stamped the time the write
  reached it. (`vault BACKLOG #2272`)
- **Each engine process now raises and clears its own `intake_paused` alert.** Every node and engine
  shard on one store raised the pause under one shared subject, `intake:<reason>`. So one node's
  clear could resolve a pause another node still held, and a node that started inside the no-flap
  band kept a stale alert open. The subject now names the process, as
  `intake:<reason>@node:<node_id>` or `intake:<reason>@shard:<id>`; a lone engine keeps
  `intake:<reason>`. A process reports its own pause state at its first measurement, even inside
  the band. A cluster node without a pinned `[cluster].node_id` gets a new id on every start, so it
  clears its own pause alerts when it stops. (`vault BACKLOG #2272`)
- **A log spool that cannot be read now says so.** When a read of the on-disk forwarding spool
  fails for a reason other than a missing file, the engine logs a WARNING naming the spool
  directory and the count, at most once a minute. Before, the only sign was the later "spool is
  full" warning, which named the wrong cause; that warning now also says when read faults may be
  what filled the spool. The unreadable segments are still kept. (`BACKLOG #2278`)
- **On-disk log spool follow-ups.** Spooled text is written as UTF-8, so a non-ASCII character
  costs its own bytes against `[logging].forward_spool_max_bytes` and not six bytes each. A sent
  segment whose delete failed stays counted against the cap until a later delete succeeds. A full
  disk no longer leaves one empty segment file per record. A start whose forwarder cannot be built
  no longer leaves an empty spool directory and `spool.lock` behind. With the spool turned off,
  the engine logs one WARNING at start if the directory still holds segments from an earlier run;
  it never deletes them. Records moved to the spool at shutdown are reported once, at INFO, with
  their count. (`BACKLOG #2279`, ADR 0200)
- **Session follow-ups from the session-cap work.** A forward clock step no longer makes the session
  reaper purge sessions the validator still accepts. The reaper reads both clocks at start and runs
  its first pass five minutes later, then hourly. It skips a pass when the wall clock ran more than
  ten minutes ahead of the monotonic clock since the last reading. A pass that runs purges as of ten
  minutes before its reading, so one smaller step deletes nothing early, whatever the idle timeout. A
  session presented during a step is still refused and revoked. The session inventory now lists a
  session at the instant it expires, as the validator does. An AD group-map edit now revokes every
  unrevoked session of each enabled directory account. That includes rows the clock calls expired,
  which could otherwise come back on the old mapping. On SQL Server, revoking a user's sessions,
  rotating a session and the session cap now count what they changed from an `OUTPUT` rowset. A
  session-wide `SET NOCOUNT ON` cannot hide that count. Each run of the session cap that revokes
  anything now writes an `auth.session_revoked` audit row with scope `cap`, under the user's name.
  The row counts every session the run ended, lapsed ones included. Before, the cap wrote no audit
  row. (`BACKLOG #2283`)
- **A restart inside the temporary-password warn window no longer sends the expiry reminders
  again.** The once-only mark for the operator's `initial_credential_expiring` alert and the
  holder and issuer notices lived in process memory, so a restart or a crash loop would have sent
  all three again on a first deployment. The mark is now the holder's
  `auth.temporary_credential_expiring` audit row, which the store keeps. A new credential on the
  same account still gets its own reminders. (BACKLOG #2303)
- **A CRL expiry alert now says when its date belongs to a running hop's older copy.** The
  notifier's `cert_expiry` event for a CRL gains `held_copy`, a `detail` naming the setting that
  holds the copy and what to do, and `shared_with`, listing the other settings or connections
  whose rows name the same file. An event with nothing to add keeps its old fields. A CRL block
  inside an outbound hop's CA file, such as `[tls].internal_ca_file`, is now watched once
  revocation checking is on for that hop, in a `held-crl:` row. A changed CA file still needs a
  restart, and the alert says so. (`vault BACKLOG #2319`)
- **The secret-expiry warning no longer says a class "only alerts" where nothing alerts.** With
  `[secret_rotation].enforce_secret_expiry_classes` set, a keyless or `vault_transit` store logged
  that those classes only alert. Neither store fingerprints secrets, so the engine tracks no non-DEK
  class there, and no rotation alert fires for one. The warning now says so. The matching warning
  under `[security].enforcement = warn` now names when a class can alert at all: on a store that
  fingerprints secrets, with `[secret_rotation].warn_days` above 0. (`BACKLOG #2320`)
- **`rotate-key` no longer seals a lone plaintext upload sidecar over a missing or non-text body.**
  Sealing it would list an upload with no usable body, and would seal a planted sidecar too.
  `rotate-key` now counts such an upload as unsealable rather than skipped. The upload stays inside
  retention: the prune removes it at expiry, timed from the sidecar's mtime, and the quota bills
  it. A holder of both `files:access_any` and `files:delete` can delete it with
  `DELETE /uploads/{file_id}`, after step-up, and still gets 423 on browse and resend. Everyone else, its owner included, still gets 404. The startup
  warning no longer tells the operator to run `rotate-key` for it, and the 423 text no longer
  promises that `rotate-key` will seal it. It stays out of the listing. At least an oversized
  non-text body, and one that is not a regular file, are not covered; `docs/PHI.md` section 3
  names them. This narrows the 0.5.0 note on plaintext uploads, which said `rotate-key` seals
  every one. (`BACKLOG #2322`)
- **An HTTP Digest challenge the engine will not answer now stops the outbound lane and keeps its
  queue.** The engine answers a Digest challenge only with SHA-256. When an endpoint or a web
  proxy sent one it would not answer, a REST, SOAP, FHIR or DICOMweb send reported "rejected an
  invalid request value", code `bad-request-value`. On a first deployment each queued message
  would have dead-lettered in turn, and the code would have sent an operator looking for a bad
  header and not for an authentication mismatch. The send now raises its own code,
  `auth-challenge-refused`. Under the default `credential_fault_policy = "stop"` the lane stops
  and every queued message stays pending, as it does for a refused FTP security mode. The log
  line and the `connection_stopped` alert name the code. Under `"dead_letter"` the one message
  dead-letters, or every member of a batch sent together. Its stored error carries a fixed text
  and not the code. A test connection and a `fhir_lookup` read report that same text. The refusal
  needs Digest set up on the connection, for the endpoint or for the web proxy. The refused
  challenges are at least these: a Digest challenge that names no hash, or a hash other than
  SHA-256; a malformed challenge; and a challenge that leads with a scheme other than Digest or
  Basic, such as NTLM. Some other unanswered challenges do not raise it. At least one of them, a
  Digest challenge with an unsupported `qop`, still reads as unreachable and retries. A stopped
  lane stays stopped until a reload or a restart. See `credential_fault_policy` in
  [CONFIGURATION.md](docs/CONFIGURATION.md). Amendment B of
  [ADR 0095](docs/adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md) names
  at least one other thing that re-arms a stopped lane, and lists where the stop is weaker than
  it is for FTP. (vault BACKLOG #2323)
- **The intake pause WARNINGs now say what a DICOM inbound does.** Both the depth and the disk
  WARNING said the dimse inbounds "stop reading". A dimse inbound refuses only a new association
  while intake is paused; an association already open keeps running until it ends, and each
  C-STORE on it is still committed. The WARNINGs now say so, and say that the timer inbounds skip
  their tick, as `docs/CONFIGURATION.md` already did. (BACKLOG #2324)
- **The keyless `serve` messages name the opt-out you set.** The strict refusal, the `AUDIT:`
  line and the warning named `[security].allow_unencrypted_phi=true` even when only
  `[security].encrypt_stored_data = false` was set. Each now names the switch in your settings,
  and both when both are set. (`BACKLOG #2340`)
- **A sign-in or PHI-read rate-limit window that is not a finite number no longer loads.**
  `[auth].login_rate_limit_window_seconds` and `phi_read_rate_limit_window_seconds` accepted `NaN`
  and infinity. A `NaN` or `+inf` window never ages an attempt out, so once the count filled the
  limiter would refuse every sign-in, or every PHI read, until a restart. All three `[auth]`
  rate-limit windows now also refuse a value above `86400` s (one day), which does the same in
  practice. **A config that set one of these loads no more.** A window of `0` or less still loads,
  and is still reported as the limiter being off. (`vault BACKLOG #2466`)
- **A TLS list the linked OpenSSL refuses is now a named configuration refusal.** The engine sets
  its own TLS 1.2 suite list on every context it builds. Where the interpreter allows it, as on
  Python 3.15, it also sets a TLS 1.3 suite list and a signature scheme list. An OpenSSL build
  could refuse any of the three. That raised `ssl.SSLError` or `RuntimeError`, and only the LDAPS
  and Vault seam caught it. `narrow_to_approved_suites` and `apply_operator_tls_ciphers` now raise `EngineTlsListRefused`.
  It is a `ValueError` naming the list and `ssl.OPENSSL_VERSION`. On an MLLP or DICOM hop it names
  the connector, never "tls_ciphers rejected". It does not reach a context built at import. At
  least two shared openers are, in the REST and alert sink modules, so on such a build the import
  fails first. OpenSSL 3.5.7 accepts all three lists. (`BACKLOG #2484`)
- **A dry run or a failed config reload no longer moves the engine's record of where its running
  config came from.** `Engine.last_reload_dir` now changes only when a reload applies a new graph.
  Both the drift check behind `GET /config/provenance` and the connection-flag write read that
  field, so before this fix one dry run could leave either of them pointed at a directory the
  engine was not running. The `config_reload_check` audit row takes the checked directory from the
  reload's result instead. (`vault BACKLOG #2598`)
- **Three statements in the operator documents now match the code.**
  [SERVICE.md](docs/SERVICE.md) said a secret in the service's NSSM environment was readable
  by any local administrator. Treat it as readable by any local user.
  [SECURITY.md](docs/SECURITY.md) described the audit chain as SHA-256. A keyed chain uses a
  keyed MAC, and a keyless chain shows less. The same document said the engine never sees a role
  granted in the directory. The engine records that change at the account's next sign-in, or in
  a directory reconciler pass before it. Each passage states its own conditions.
  (`vault BACKLOG #2621`)
- **More security documents now match the code.** `SECURITY.md` says the DICOM server checks its
  peer address list when a connection is accepted, says what `audit-verify` needs under the
  Transit cipher, says what its exit 1 covers, and says when the directory reconciler is off or
  capped. `PHI.md` says the inbound web-service listener is built. `CONNECTIONS.md` says a
  connection whose every target is loopback lists no proxy credential. Two standards documents no
  longer call the audit chain plain SHA-256. (vault `BACKLOG #2621`)
- **The Corepoint importer no longer treats a statement written off a `<Line>` as run.** A
  `<Block>`, a `<Call>`, a construct, an unmodelled element or a list wrapper can carry a statement
  in `@Data`, such as `<Block Data="MsgTreeCopy %ADT/ to %OUT/">`. The importer kept it only as a
  label, or dropped it, while reading its copy as made, so a later send of that copy rendered as a
  send of `msg`. Such a statement is now a counted `# TODO` naming it, and it is never emitted as
  a write or a delivery. A `MsgSend` in a Block's or a Call's `@Data` is refused wherever the
  importer renders it: the handler raises at that send.
  Every role-marked send the importer renders in that action-list raises until someone finishes
  it by hand.
  A prose label renders as before. See
  [ADR 0086](docs/adr/0086-deterministic-corepoint-import.md), amendment (b.4).
  (`vault BACKLOG #2632`)
- **A slow upload no longer loses its cross-shard quota slot to a sibling engine shard.** The
  store reclaims an uploader's reservation row once it has gone 300 seconds with no activity, so a
  save slower than that had its live slot reclaimed. A short save joining an old row was reclaimed
  along with that row's leaked slot as well. Every applied reserve now moves the row's clock, and a
  live save touches the row every 100 seconds, for up to an hour. The clock never moves backwards,
  so a host whose clock lags cannot age a row a sibling keeps fresh. This applies to SQLite, SQL
  Server and PostgreSQL. A live slot can still be reclaimed in a few cases, such as a suspended
  process. The `UploadQuotaError` docstring in `messagefoundry/uploads.py` lists them.
  (`BACKLOG #2648`)
- **The auth rate limiter drops a key's aged bucket even when that key never returns.** Before this
  fix, `SlidingWindowRateLimiter` removed a key's bucket only inside a later call for that key. A
  limiter keyed on a client or peer address would have kept a bucket for every address it admitted.
  It would have held them for the life of the process. Now the limiter orders its table by each
  key's newest hit. Each call, for any key, drops up to two buckets from the front whose newest hit
  has left the window. The table never grows past the most keys live at one time, and no call walks
  it. Eviction is lazy, so after a burst the aged buckets go two per later call. A key that is still
  being refused keeps its bucket, so `Retry-After` is unchanged. A limiter with no per-key gate
  keeps no buckets at all, and one with no global gate keeps no global window. (`BACKLOG #2714`)
- **A replayed routed row whose Handler then sends nothing now settles.** A message replay that puts
  a dead routed row back in the queue now sets the message to `routed`, not `received`, on all three
  stores, so a Handler that now filters the message or declines every Send lets it finish as
  `filtered` or `not_deployed`. Before, the message stayed `received` with no queue rows, and a
  second replay had nothing to re-queue. Only a replayed ingress row still shows `received`. SQL
  Server's test-only `enqueue_message` now writes `routed` like the other two stores.
  (vault `BACKLOG #2723`)
- **`messagefoundry validate` and `messagefoundry graph` send a `print()` in a config module to
  stderr.** Stdout now carries only the command's result, so a debugging print no longer breaks
  the JSON, as `dryrun` already did for its own load. The load that `validate`, `graph`, `dryrun`
  and `check` share under `--project-root` with `--env` is redirected too; it ran before `dryrun`
  redirected anything. Other config loads are not redirected, at least those `check` makes
  afterwards and those of `connection`, `impact` and `cert inventory`. Nothing redacts what an
  author's own print writes, so stderr is no safer than stdout. (vault `BACKLOG #2727`)
- **DR release, DR activation and a config reload now finish when the request deadline cuts the
  caller off.** The API answers `503` to a request still building its response after 120 seconds,
  and it did that by cancelling the handler, which left these three operations half done. A DR
  release with any row that would not drain always hit the deadline first, and on a first
  deployment it would have left intake unbound while `GET /dr/status` still said active, with no
  `dr.release` row. An activation cut off at or after its last step left the box reporting active,
  and a retry answered success with no `dr.activate` row. A reload cut off partway left the
  listeners it had stopped down, with no rollback and no reload row. Each now runs on after its
  caller is gone and writes its own outcome row. A DR retry waits for it and then reads that
  outcome; a reload retry is a second reload, which waits for the first and then runs again.
  The `/ui` routes call the same handlers and get the same behaviour. A shutdown that stops one
  partway rolls it back and records it: a `dr_activation_aborted` row of kind
  `interrupted`, a new `dr_release_failed` row (also written when a release drain fails), or a
  new `config_reload_interrupted` row. (`BACKLOG #2751`, `#2752`, `#2753`)
- **The `dr.release` audit row records whether the queue drained.** It always said
  `"drained": true`, including when the drain gave up with rows still queued. It now records
  `drained` and `depth_left`, the number of rows left, and `POST /dr/release` returns
  `depth_left` too. The drain now waits up to 60 seconds of wall-clock time rather than 120
  seconds of sleep ticks, so with the default hook timeout the caller gets the answer inside the
  request deadline. Rows left behind stay queued and keep delivering. (`BACKLOG #2752`)
- **The config loader's `_`-helper imports no longer reach the rest of the process, and work inside
  a Router or Handler body.** Helpers used to be served by a finder at the front of
  `sys.meta_path` for the whole load, on the false premise that no real top-level module starts
  with `_`. So a `_csv.py` in the config directory would have broken a first `import csv` anywhere
  in the process during a reload. Helpers are now served only to config modules, through each
  module's own `import` statement, and a helper named after a standard library, installed or
  already-imported module (`_csv.py`, `_json.py`) is refused with an error naming the file. A
  helper imported only inside a Router or Handler body used to fail with `ModuleNotFoundError` on
  every message while load and `check` passed; it is now loaded with the config, once the module
  that imports it has run, and resolves at run time. A helper whose own import fails under an
  `except ImportError` in the body is left to that guard, with a WARNING; any other failure fails the
  load. A reload whose modules fail while they run no longer takes the live graph's modules out
  of `sys.modules`. A config file whose name starts with `.` (an editor backup such as
  `.IB_OLD.py`, a macOS `._` file) is no longer run, vetted by the config-source trust check, hashed
  into the config fingerprint (whose scheme is now `mefor-cfg-fp:v2`), linted by `check`, or edited
  by a rename. (vault BACKLOG #2780, #2781, #2783)
- **Four more files no longer call the anonymizer's output PHI-free.** `docs/AI.md` (twice), the
  `ai_policy` module docstring and the load-harness corpus docstring now say "de-identified".
  `docs/USER-GUIDE.md` no longer says you can build test data from real traffic "without ever
  handling PHI": the command reads real captures, and its output is not guaranteed free of PHI.
  Each one points to [PHI.md](docs/PHI.md) §9 for what the leak-check refuses and what it lets
  through. ADR 0201 carries a dated correction: the anonymizer's loaders build one fixed path to
  `scripts/security/` and no longer walk up the tree. The `messagefoundry.anon` package docstring
  no longer calls `tee/anon/` one byte-identical copy: only some of its files are, and
  `tests/test_anon_parity.py` names them. (vault `BACKLOG #2996`)
- **Anonymizer follow-ups: a false refusal, a raw error, a missing count, and refusal texts
  that changed.** The last bullet is breaking for a caller that matches the old text.
  (`vault BACKLOG #3004`)
  - A rule that rewrites `MSH-12` could make `anonymize_checked` refuse a message that plain
    `anonymize` passed. The leak-check read the HL7 version from its own output, where the rule
    had written a surrogate, and a surrogate version can leave out a bare segment id the real
    version defines. With an `id` rule on `MSH-12`, a 2.7 message and a bare `PRT` line, 13 of
    200 salts were refused on each anonymizer. The leak-check now judges a bare line by the
    version the message came with. `leak_report`, `leak_check`, `structural_phi_hits` and
    `unmapped_field_values` take it as an optional `version` argument, and the new
    `message_version` reads it. A caller that runs `anonymize` and then one of those checks
    itself must pass `version=message_version(raw)` to get the fix. A bare id the message's own version does not define is still
    refused.
  - A run of more than 32 digits in the `MSH-12` version is now refused with a body-free
    `AnonError`. A run past the interpreter's digit limit used to raise a plain `ValueError`
    from plain `anonymize`, `anonymize_checked` and a direct `leak_report` call, and only while
    that limit was on.
  - `python -m tee anonymize-captures` now says how many messages were refused before the
    leak-check built a report. Those messages are not in the coverage count, and since plain
    `anonymize` took over that refusal (`BACKLOG #2246`) only the failed count showed them. The
    summary names the fixed causes and never a value.
  - The same summary now says what an entry such as `PV2 (line with no fields)` is: a line
    holding only that segment id, not an overlay key, decided by a rule or a `keep` on any
    field of that segment.
  - The refusal texts that said only "malformed segment id" now also name a header line with no
    separator after its encoding characters. **A caller that matches the old text must change:**
    the leak-check hit reads `line no rule can reach (a malformed segment id, or a header line
    with no separator after its encoding characters)`.
- **An alert webhook that answers 2xx with an over-size body no longer counts as a failed send.**
  The alert was taken, so the engine now counts it as delivered and logs a WARNING that carries
  the status and the bound, and no byte of the reply (owner ruling 2026-10-12). The
  `reply-too-large` error a REST, SOAP, FHIR or DICOMweb delivery stores now puts the connection
  name last, so a long name no longer cuts off the advice to check the partner before a replay.
  The WARNING on the delivered arm no longer says the message "is recorded as delivered", because
  it is logged before the store write. (`BACKLOG #3040`)
- **A delivery whose 2xx reply body was dropped over the size bound now says so on the message.**
  REST with capture off, and a plain FHIR write with capture off, record a `reply_dropped` event
  on the message in the same write that marks it delivered, with the status and the bound and no
  byte of the reply. The WARNING now names the message, comes after that write, and says whether
  the write recorded anything. (vault `BACKLOG #3040`)
- **A permanent refusal that dead-letters now writes a WARNING.** The delivery worker used to
  dead-letter a permanently refused message with no log line at all. That held on the single-row
  path and the batch path. It now writes one WARNING after the dead-letter. The line names the
  connection, the outbox row, the exception class and the refusal code. The single-row line also
  names the message id, and the batch line names the batch size and its head row. No line carries
  any character of the message or the refusal's text, which stays in the secured store. The lines
  are throttled per connection and refusal code. The first refusal always logs and says that more
  are counted for 60 seconds. The next line reports how many rows went unlogged. All pairs
  together write at most 100 lines a minute, so a peer that varies its code is held too. A batch member
  the frame refuses joins the same throttle, so a burst of them now logs one line, not one per
  member. The dead-letter itself, its event and its counts are unchanged. (`BACKLOG #3043`)
- **A RemoteFile destination with `encoding = None` now uploads as UTF-8.** It passed `None` to the
  encoder, which raised a `TypeError`. The delivery worker treated that as an internal error, so
  under `internal_error = stop` the first send stopped the lane. (vault `BACKLOG #3044`)
- **`messagefoundry check` names the settings file it graded when `serve` may read another.**
  Under `--project-root` with no `--service-config`, `check` reads the project root's
  `messagefoundry.toml` (or the config dir's), while `serve` with the same flags reads
  `./messagefoundry.toml` in its own working directory. Run from anywhere but that file's folder,
  each settings line now names the file it read and the difference; the verdict is unchanged.
  Without `--project-root`, a directory named `messagefoundry.toml` in the working directory,
  which stops `serve`, now fails the settings legs when the upward search reaches it, where it got
  an environment-only OK. When `[security].require_encryption_for_remote = false` admits a
  cleartext listener, the `build-check` OK line now says so and names the first one. The `check`
  help now says an explicit `--service-config` is read wherever it points. (`BACKLOG #3063`)
- **An operator start or restart that a listener's start gate refuses with a configuration error
  now answers 409 and is audited.** It answered 500 and wrote no `connection_control` row. The
  answer names only the listener; the refusal text goes to the server log. (`BACKLOG #3063`)
- **`messagefoundry connection upsert` and `remove` name `--service-config` in a cleartext-listener
  refusal**, and say the command reads `[security].require_encryption_for_remote = false` in place
  of `serve --allow-insecure-bind`, besides the per-connection attestation. `check` says the same.
  (`BACKLOG #3063`)
- **A directory reconcile pass no longer files a false rename conflict from a stale holder read.**
  In the shipped code the reconciler read which account held an AD account's new name, then read
  the account itself, and refused the rename on the first read. A holder that let the name go in
  between still produced an `auth.ad_username_refresh_conflict` audit row and a lockout warning
  that nobody faced, and the rename waited for a later pass. Now the holder is read again after the
  account, and that check refuses the rename only when another account holds the name at the
  second read. The conflict row's `held_by_user_id` then names that account, not the one the first
  read saw. A holder whose record fails its integrity check at the second read is still refused
  with the lockout warning, naming the holder the first read verified. A store error on the second
  read skips that one rename for the pass instead of ending the pass; a store error on the
  pass's other rename reads still ends it. A holder that already fails its integrity check at the
  first read still reads as no holder there, so the write's guard stops the rename and the
  conflict row names no holder, with a warning that a later pass retries it. Vault BACKLOG #3070.
- **`cert self-signed` refuses an existing `cert.pem` and cleans up its key on failure.** It
  replaced a `cert.pem` with no `key.pem` beside it without a word, and a failed certificate write
  left the new key behind, so every later run refused. It now refuses an existing `cert.pem` as it
  does an existing `key.pem`. When the certificate write fails, it removes the key it wrote and
  names any file it could not remove. A common name over 64 characters or not in ASCII, or a
  `--days` past the year 9999, is now the command's own failure (exit 2, and `{"error": ...}`
  under `--json`) rather than an uncaught exception. The console output labels an IP address SAN
  as `IP:` rather than `SAN(DNS)`, and `cert self-signed` and `cert import` state the key's
  protection as this platform applies it. (`BACKLOG #3073`)
- **The directory reconciler says which reconcile alerts it will not resolve.** At its first read of
  alert state that succeeds, a process that finds reconcile alerts open or acknowledged logs one
  warning naming each one. It drops every clear of those instances for its life, so an operator
  resolves them. If earlier reads failed, that set can hold an alert this process opened itself.
  Each read of reconcile alert state is now bounded at 10 seconds; a read that runs past it drops
  that pass's clears, as a failed read does. A reconciler that may share its store reads no alert
  state, since it raises no clear. The warning for an account that left with an undetermined
  `userAccountControl` read no longer says this process held when it had not. (`BACKLOG #3084`)
- **The DR backup and the subprocess sandbox follow the running config dir.** After an operator
  reload from another allowed root, the engine's backup archived and fingerprinted the startup
  `--config` dir, and a `[sandbox].mode=subprocess` worker loaded the startup graph, so every
  sandboxed dispatch would have been refused for a graph mismatch. The backup now reads the
  directory the running graph came from once per pass and takes its fingerprint off the event
  loop. The archive's manifest and the `dr_backup` audit row record `config_bundled`, the
  `config_dir` the pass read, and `config_bundle_error`. When that dir is gone or cannot be
  listed, a full backup still succeeds with the store snapshot, logs one WARNING naming the
  directory and the error class, and records `config_bundled: false` with that class; no alert is
  raised for it. A config-only backup fails instead, as a `snapshot` failure. A file name that is
  not UTF-8 costs only the fingerprint, with a warning; the config is still bundled. A sandbox
  worker now loads the directory the served graph was loaded from. (`vault BACKLOG #3094`)
- **A DR activation's trust-anchor preflights are now bounded, and its abort rows say more.** The
  settings and registry preflights a `POST /dr/activate` runs before it re-applies the graph now
  share one bound, `[dr].takeover_timeout_seconds`. They run under the coordinator's lock, so an
  anchor on a share that stopped answering used to hold every later activate and release too. A
  timeout cancels the preflight, but a read blocked on the share may leave its thread stuck, and
  retries against a dead share can strand more of them. The re-apply itself is still not bounded, so
  at least the outbound and FTPS poller CA reads it makes can still hold an activation. Every
  `dr_activation_aborted` row of an activation now records the `seed_segment` of the marker that
  attempt wrote, and `vip_hook_ran`. The `[dr].takeover_hook` row of `docs/CONFIGURATION.md` says
  what each hook outcome records. An error no abort path caught is now an audited abort of kind
  `error` that answers `503`. One example is an error from the seed marker's digest provider. It
  used to escape as a bare `500`. (`vault BACKLOG #3094`)
- **A CA file that is not PEM is now a named refusal, and a DICOM suite refusal names its
  connection.** On at least the verifying paths the runner builds, a `tls_ca_file` or
  `[tls].internal_ca_file` that reads but that OpenSSL cannot load as PEM now raises
  `CaFileUnreadable`, as a missing file already did. It names the setting and the connection where
  the build knows it, and carries no path. Before, it escaped as a raw `ssl.SSLError` that named
  neither. Paths that load the CA without a `[tls]` policy, or with verification off, still raise
  the raw error. A refused `tls_ciphers` on a DICOM destination now names the
  connection, such as `DICOM destination 'OB_PACS'`. With `tls_ciphers` unset, nothing the
  engine's own narrowing raises can read as "tls_ciphers rejected". (`BACKLOG #3096`,
  `BACKLOG #2977`)
- **Listeners that share one CRL file no longer each log the scan's held-copy warning.** When
  running hops still hold an older copy of a replaced CRL file, the certificate monitor logs
  `a running TLS hop still holds a copy of ...` and names every setting that holds one. It logged
  that line once for each row naming the file, so N listeners sharing a file gave N lines a pass,
  each listing the same N holders. A pass now logs the same line once, under the first row that
  names the file, and the line ends by naming the other rows: `The same file also serves ...`. A
  file one row names logs the line it always did. At least two cases still log more than one such
  line for a file in a pass: a file replaced part way through the pass, and a pass whose row
  grouping failed. The `crl_expiry` alerts did not change. Each row still raises its own, with its
  own `detail` and `shared_with`, so with no `[alerts]` transport the logged alert lines are still
  one set for each row. (`vault BACKLOG #3099`)
- **The undeclared-proxy warning names both ways to declare a proxy.** `serve` prints it on a
  loopback bind when `[security].web_console_public_address` is set, no proxy is named and
  `[security].require_mfa` is off. It told the operator to declare the proxy with
  `[api].tls_terminated_upstream` and `trusted_proxies`. It now says to set `require_mfa`, and to
  name the proxy in `[api].trusted_proxies`, with a declared terminator if the proxy terminates TLS
  or an operator `[api].tls_cert_file` if it re-encrypts to the engine. It also says that a declared
  proxy counts as exposed, so the MFA-at-exposure gate then applies. The message that refuses
  `[api].trusted_proxies` without one of those two now says that either one counts as exposed.
  (vault `BACKLOG #3102`)
- **A cluster convergence reload's audit rows name that reload.** Its `config_reload` row is built
  from the reload's own result. A flag toggle or operator reload that lands before the write is no
  longer recorded under the convergence actor. The row is marked `superseded` instead. On a
  cluster, a reload row carries `config_version`, the shared version it applied. So a follower's
  row names the operator reload it followed. A convergence reload that fails writes
  `config_reload_failed`, where it wrote none. Each engine process writes each distinct row once
  per version, however often the loop retries. (`vault BACKLOG #3109`)
- **A start's `config_loaded` row holds up when a reload or a snapshot fault interrupts it.** It
  keeps its `loosenings` when a reload supersedes it. A start that could not take its config snapshot still compares the digest
  its load took, so a changed config still raises `config_changed`. That row writes no `shard` key
  rather than a `null` one. The `ClusterCoordinator` protocol now states that `config_version()`
  must answer before `start()`. (`vault BACKLOG #3076`)
- **The delta CRL refusal now gives both OpenSSL rules, and corrects the 0.5.0 entry's reason.**
  The 0.5.0 entry for `BACKLOG #299` says OpenSSL reads a delta CRL as complete. That holds only
  for a delta newer than its base, and only before openssl/openssl PR 31044. From that fix on,
  OpenSSL rejects a delta as a complete CRL, so the delta's revocations are lost. The engine turns
  on no delta CRL support, so revocations are lost under either rule, and the engine still refuses
  a delta CRL. The refusal text now states both rules. Give base CRLs only. (`BACKLOG #3112`)
- **A refused or malformed hop attestation is now reported plainly.** These are follow-ups to the
  strict hop-policy reader (vault BACKLOG #2232). The build check already refused each config here.
  (`vault BACKLOG #3139`)
  - The `tls-hop-attested`, `cleartext-accepted` and `tls-revocation-attested` lines of
    `messagefoundry check` show each entry as `name ("reason")`. A name outside letters, digits and
    `_.:-` is quoted too. Quotes, controls and non-ASCII characters are escaped, so a newline cannot
    split the line, and a lookalike quote cannot fake the end of a reason.
  - The `tls-hop-attested` line marks an entry the build check refuses as `REFUSED`, at the end of
    the entry. The mark comes from a field the engine sets, not from the reason text. The line no
    longer says every listed hop is allowed.
  - `serve` now refuses a reference set at start, before any sync, when its source carries a hop
    flag or attestation pair the build check refuses. That covers at least a raw `env()` or other
    non-boolean flag, and a missing, blank, non-string or control-character reason. It used to fail
    only at the set's first sync, which logged just `WiringError`. The sync now also logs the
    refusal text, which names the set and the flag but no value.
  - The `db_lookup` and `DatabaseRef` reader of `tls_hop_attested_reason` refuses a non-string or a
    control character, as the factories and the FHIR lookup already did.
  - A hop-policy flag refusal mentions `env()` only when the value is an `env()` reference.
  - The FHIR lookup executor and the anonymous FTP guard name the connection when they refuse a flag.
- **A passive DR box binds no inbound listener.** With `[dr].enabled = true` and the box not
  activated, at start or after `POST /dr/release`, no inbound listener binds, of any tier, and each
  reads `status: "filtered"`. It used to bind its whole graph. The load balancer that ADR 0048
  relies on to move the VIP to the live node would then have sent it traffic. `POST /dr/activate`
  binds the feeds at or above `[dr].priority_threshold`, as before. Outbounds are unchanged. A
  release parks intake before its drain. A reload or dry run on a passive box checks the listeners
  an activation would bind. An operator start of an inbound still binds it, until the next reload or its
  schedule window closes.
  An alert rule's restart and the scheduler bind nothing. (`vault BACKLOG #3140`)
- **The approval routes answer a failed store read with 503, not a raw 500.** At least the queue, the
  request row and, on a release, the requester's account row are covered; the queue's own read
  of that account leaves the request with no predicted refusal instead. The requester's roles,
  read through the auth service, are not covered. The read is logged at ERROR and pages nothing,
  because no audit row was lost. Before this, `GET /approvals` caught nothing. (`BACKLOG #3157`)
- **Only a missing config directory is answered as `not_found`.** The engine now raises
  `ConfigDirMissing` for it. **An operator reload's faults are now audited too.** On the reload
  routes, an error no refusal names, at least a `FileNotFoundError` or a `PermissionError` while the
  runner starts or swaps the graph, writes `config_reload_failed` with reason `reload_fault` and the
  error's type, and answers with a generic detail, 500 inline (a dry run included) and 422 on a
  released reload, rather than escaping as a raw 500 with no outcome row. A cancellation still
  propagates and is not audited as a fault. (`BACKLOG #3157`)
- **A shutdown drain no longer cuts a reload's own audit row short.** A cancel that lands while
  the `config_reload` row, or a refused reload's row, is being written now waits for the write.
  Under the shutdown drain it waits a little less than the drain's share of the stop budget has
  left (`BACKLOG #3191`); any other cancel, at least the convergence reload the engine's stop
  cancels, waits up to 1 second. Nothing waits past that: a write still running is left to
  finish, and one that fails after the cancel, as on the store the stop closes, is logged at ERROR
  with the row. (`BACKLOG #3157`)
- **A cancelled resolve whose write fails logs one ERROR, not two.** (`BACKLOG #3157`)
- **A CRL expiry alert no longer advises a restart into a CA-file CRL that would refuse peers.**
  When a hop's CA file now holds a CRL that is not yet in effect, badly signed, a delta CRL, or one
  the engine cannot read, the alert's `detail` says to fix it in the CA file before restarting.
  Before, those cases read "Restart the engine", and a restart would load the CRL unjudged. For a
  file one hop loads as its CRL setting and another as its CA file, the alert no longer says a
  reload is pending and then that a restart is needed either way. It names the steps in order: the
  reload, or a refused reload's own remedy, then the restart. (`BACKLOG #3176`)
- **`rotate-key` fails, and writes no key-rotation stamp, when it skips an uploaded file.** It used
  to print `OK`, exit 0 and write the ASVS 13.3.4 rotation stamp even when an uploaded file was left
  partly under the prior key, so an operator or a wrapper could retire a key that was still needed.
  It now prints `PARTIAL` and exits 1, and this run writes no stamp. The stamp is now written after
  the audit-chain step too, so a failed audit step writes none either. `serve` still stamps a
  changed key on its own when it next starts, so the stamp alone does not show that a rotation
  finished. One upload that no configured key opens, or that cannot be written, no longer aborts
  the whole pass: it is left as it was and counted as a skip, and every other upload is re-sealed.
  An upload whose body is missing or is not text, under a sealed sidecar, is no longer counted as a
  skip, since no re-run can change it; `rotate-key` re-seals its sidecar and prints a note instead.
  At least a body too large for an upload, one that is not a regular file, and a sidecar that is not
  text are still skips. (`BACKLOG #3181`)
- **The `upload-cipher` alert and the store cipher's refusal of a plaintext upload no longer
  promise that `rotate-key` will seal it.** Both, and the listing scan's log line that carries the
  cipher's text, now offer `rotate-key` with the engine stopped. For an upload it leaves unsealed
  for good, they say an operator may delete it, or the retention prune may remove it at expiry,
  where either can, and point to `docs/PHI.md` section 3, which names at least some kinds neither
  can remove. A per-uploader quota refusal (HTTP 409, and its `upload.reject_quota` audit
  reason) now says how many of the files it counts cannot be read and are not listed, and how
  many bytes they hold, whenever those files count toward the cap that refused it. It names no
  file. (`BACKLOG #3183`)
- **`GET /approvals` names a release the gate always refuses.** Each pending request carries
  `release_blocked`, a reason read from the same tests the release refuses on, or `null`. Its
  values include at least `no_requester_id`, `operation_unavailable`, `not_gated`,
  `params_unreadable` and `params_no_requester`; `PendingApprovalInfo` lists them all. The web
  console uses it to stop offering Approve on such a row. A release refused because its stored
  parameters are unreadable now writes an `approval.params_unreadable` audit row against the
  approver, like the gate's other refusals. A held purge or reload whose parameters name no
  requester is refused before the claim, as `params_no_requester`, with an
  `approval.params_no_requester` row, so it stays pending for a reject. (vault `BACKLOG #3192`)
- **A failed approval request write is read back, and the write outlives its caller.** When the
  write that files a held request reports an error, the gate reads the request back by its id. If
  the COMMIT landed and only its reply was lost, the caller gets the same 202 and id, so a retry no
  longer files a second releasable copy. It still pages `audit_write_failed`, because the row's
  off-box copy was not written, and so does an outcome write whose COMMIT reply was lost. A cancel,
  such as the request timeout, no longer cancels the write itself. On SQL Server a release's status
  write now reads its outcome from `OUTPUT` rather than the row count. A released operation whose
  result has a key json cannot encode, or a circular reference, still settles and answers, with
  those fields as text. [SECURITY.md](docs/SECURITY.md) no longer lists the SQL Server command
  timeout as a lost-COMMIT case: by a reading of pyodbc, the timeout does not bound a COMMIT.
  (vault `BACKLOG #3193`)
- **The retry-cap dead-letter WARNING now follows what the store wrote.** `mark_failed` and
  `mark_batch_failed` return what they did, on SQLite, Postgres and SQL Server: the retry time,
  the rows written DEAD, and the row the decision came from with the attempts read there. The
  delivery worker logs from that, with no read-back of the row. Three dead-letters that wrote no
  line now write one: a batch whose first member was gone, a row whose attempts a lease reclaim
  moved, and a row an operator replayed right after the write. A row dead-lettered at the cap with
  no running connector, or after a store read fault before sending, writes the line too. A pre-send
  store read fault no longer reports a vanished row as dead-lettered. When an internal-error STOP
  dead-letters a row because its attempts, counting the one that just failed, reached the retry
  cap, a WARNING now says so and names at most 10 of the affected messages. On a batched outbound
  the stop decides from the batch's first row still present, so when that row has reached the cap
  the dead-letter takes every row of the batch still present, even rows below the cap. A batch holds outbound rows only,
  and the dead-letter queue lists dead outbound rows. A router or transform row is not in the
  dead-letter queue, which lists outbound rows only, so the line says to replay the message
  instead. The recovery steps are in the user guide, under *A lane stopped processing*.
  (`vault BACKLOG #3211`)
- **Engine shard names are no longer scrubbed out of two log lines and two refusals.** The log's
  PHI pass reads two capitalized words around a comma as a possible patient name. The engine
  joined engine shard names with a comma. Names in capitals or in Title case, such as `EAST` and
  `WEST`, then showed as `[redacted]` in the log. The two log lines close a crash loop, so an
  operator would not have seen which engine shards were down. The two refusals would have lost
  the names too: a config with more than one engine shard on a single-file store, and a reload
  that changes the engine shard set. All four now join the names with ` / `, as in
  `EAST / WEST`. Lower-case names were never affected. A name the pass
  scrubs by itself, such as `East Wing`, is still scrubbed. The Windows fix text for a writable
  trust anchor also lost the words `Authenticated Users`. It now says `Authenticated users`,
  which Windows accepts. The redaction itself is unchanged. (`BACKLOG #3227`)
- **`rotate-key` counts a plaintext upload body it sealed even when that upload's sidecar could
  not be read.** Such an upload is now in the sealed-plaintext count as well as in `skipped`, so a
  planted body is not sealed uncounted. An upload whose two plaintext halves are sealed in two runs
  counts in both. `DELETE /uploads/{file_id}` now answers 404, not 423, for an upload whose sidecar
  is removed while the request runs. (`BACKLOG #3240`)
- **`rotate-key` exits 2 when the Vault client for the store key cannot be built.** Under
  `[store].key_provider = "vault"`, a check in the client build that refuses with a `ValueError`
  passed the command's first key check and exited 1 through the last-resort hook. At least the
  outbound length bound, the TLS suite assertion and the strict-reader mount refuse that way. The
  command now prints the refusal whole and exits 2, as it already did when the store open met the
  same refusal: it could not start, and nothing was changed. (vault BACKLOG #3247)
- **An embedded approval gate no longer fixes the default claim owner before its engine holds
  its graph.** `create_app(engine=...)` reconciles in its own lifespan, which can run before the
  engine knows its engine shard. The gate read `"engine"` there and kept it for life, so embedded
  engine shards would have shared one claim owner on a first deployment. The owner is now fixed
  only once the engine can name it, or once a claim is written under it. The restart reconcile
  waits until then too, and covers only rows claimed before the app started. (`BACKLOG #3252`)
- **The approval queue warns about a request with unreadable params at most once per five
  minutes per request**, rather than on every list. A refused release still warns each time.
  (`BACKLOG #3252`)
- **On Postgres and SQL Server, the engine-shard upload reservation now reads the database server's
  clock.** The row's activity stamp and its staleness test used each engine host's own clock, so a
  host whose clock ran ahead could hold a leaked slot for as long as the skew. Each heartbeat touch
  of a live upload's reservation is now bounded, so a stalled store cannot hold the heartbeat
  indefinitely. `serve` now bounds uvicorn's connection drain at a stop to 3 seconds, so an open
  request can no longer use up the service's stop window before the engine shuts down.
  (`BACKLOG #3256`)
- **A passive DR box delivers nothing.** With `[dr].enabled = true` and the box not activated, at
  start or after `POST /dr/release`, every outbound is parked: it reads `status: "filtered"` and
  holds its rows. It used to build every outbound. A box started over a store restored from a
  backup then delivered the rows that backup held undelivered, possibly while the primary was
  alive and delivering the same rows. `POST /dr/activate` delivers on the outbounds at or above
  `[dr].priority_threshold`, the held rows in the order they were queued. A release now parks
  every outbound when its drain ends and closes their connectors, so rows left on the released
  box stay queued there. The reload after a release no longer starts a parked outbound. An
  operator start, stop or restart of an outbound on a passive box answers `409`. The router and
  transform stages still run on a passive box. (`vault BACKLOG #3262`)
- **A passive DR box shows a broken critical feed at start, and an activation can fail one
  outbound without refusing the takeover.** At start a box with `[dr].enabled = true` that is
  not activated reads the `tls_ca_file` of each outbound and each FTPS poller an activation would start, and skips at least an outbound another engine shard owns and a listener's client-verification CA. A refused one
  reads `status: "failed"` and alerts. It builds, binds and dials nothing to do so. At
  `POST /dr/activate`, an outbound whose CA pin, ACL or path check or `validate_directory`
  check fails is failed on its own and keeps its rows queued, and the rest start. It stays
  parked, and still pages its buildup and stall checks, until a reload or an operator start
  builds it; neither the scheduler nor an alert rule's restart resumes it. Such a CA
  used to refuse the whole activation, and the `validate_directory` check never ran. At least a
  CA file that is missing or does not parse, a connector that does not build, and an unresolved `env()` value, still refuse the
  activation. A failed or cancelled activation now unbinds the listeners the attempt bound. A
  release cut short while it closed outbound sessions is still recorded as a release, and a release whose `dr.release` row the audit store refuses still closes them; the
  engine and the DR coordinator used to disagree about it. An activation while the application
  log is unwritable no longer leaves outbounds answering `409` "activate DR first" once the log
  is repaired. (`vault BACKLOG #3263`)
- **The start WARNING about no usable local Administrator no longer loses its first name to the
  credential scrub.** It listed the accounts right after "no usable password:". The log's credential
  scrub read that as a password and masked the first name, from the day the WARNING was added. The
  list now follows "Accounts that need one:", ahead of the word "password". A name that itself looks
  like a credential label or a date can still be rewritten by the log filters. The
  `auth.no_local_administrator` audit row holds the complete list. (`BACKLOG #3282`)
- **The PHI-read and sign-in `429`s no longer send a literal `Retry-After`.** The PHI-read `429`
  carried `10`, and the console's `POST /ui/login` carried `30`, against a default 60 s window. A
  client that honoured either could have retried inside the window and been refused again. The
  PHI-read `429` now sends the account's own wait from the limiter that refused, in whole seconds,
  rounded up and never below 1, as the admin-write `429` already did; while the all-accounts budget
  is spent it sends the whole window. The value is a reading, not a reservation. `POST /ui/login`
  sends the whole sign-in window, so the unauthenticated surface discloses no per-bucket timing.
  `POST /ui/mfa`, `/ui/reauth` and `/ui/reauth/webauthn` keep the constant `Retry-After: 30`, so a
  caller holding only the password gets no exact pacing for second-factor guesses.
  (vault `BACKLOG #3293`)
- **A negative `[auth].admin_write_rate_limit_per_actor` is refused at load.** It used to load,
  and the limiter then admitted one write per window. `0` still turns the count off.
  (vault `BACKLOG #3293`)
- **A protocol header floor self-test that fails with an exception now says where.** When a drive
  raised, the refusal named the exception's type and only the file and line where it was raised. It
  now names the Python and the module and line of each frame the exception passed through,
  outermost first, and still never the exception's message. A recursion's repeated frame is listed
  once with its count. So a fault in uvicorn, in asyncio or in the self-test itself reads apart.
  That matters for one case in particular: the self-test runs on a private event loop built on
  CPython internals. A later Python that moves `_selector` or `_process_events` still stops the
  start with exit code 2, and the refusal now names that Python, the `asyncio` frame that raised,
  and the Python as a possible cause. A Python that moved only `_write_to_self`, which no drive
  reaches today, would not show here. (`BACKLOG #3308`)
- **A removed key's refusal no longer says that no environment variable set it.** The refusal a
  section built directly gives for a removed key said the key was passed straight to the section,
  so no environment variable set it. That section is built in code, and also from the file's
  `[security]` table by at least `security show` and `security set`, so an operator whose file
  still held `require_sign_in` or `handles_real_patient_data` would read that claim. It held for
  the file the command read, not for the service, whose environment may set the same key and
  would still refuse at start. The refusal now says only to remove the key from the arguments or
  the file table, and no longer claims that no environment variable set it. The loader's refusal
  still names the `MEFOR_` variable to unset. (vault BACKLOG #3350)
- **A refused anonymizer salt now says that a random salt can be refused, and what to use
  instead.** The keyer's entropy screen refuses a small share of genuinely random salts drawn from
  a narrow alphabet, such as decimal digits, and that cost is accepted rather than the floor
  lowered. Both entropy refusals, in the engine's anonymizer and in `python -m tee
  anonymize-captures`, now carry the same advice: replace the salt with one from
  `secrets.token_urlsafe(24)`, not another draw from the same alphabet. The rates are stated in
  the docstring of `_estimated_entropy_bits`. The test that drew fresh random salts on every run,
  and so failed a required CI leg now and then, now uses fixed salts, an exact enumeration of the
  refusal rates and seeded sweeps. (`BACKLOG #3359`)
- **The `trusted_proxies` loosening names each range once, in list order within each wording, with
  its other spellings, and an IPv4 entry's mapped twin can now make IPv6 ranges read as trusting every peer.**
  The warning listed every IPv4 range before every IPv6 one, whatever the input order, and removed a
  repeat only when it was spelled the same way. So `10.0.0.0/08` beside `10.0.0.0/8`, or
  `::ffff:10.0.0.0/104` beside it, was named twice. Each network is now named once, under the first
  spelling given for it, with any other spelling in parentheses, as in
  `10.0.0.0/8 (also written as ::ffff:10.0.0.0/104)`; to clear it, remove every spelling. An IPv4
  entry now also counts toward the IPv6 family as its mapped twin, which uvicorn is handed too, so
  `0.0.0.0/0` beside IPv6 ranges covering the rest of `::/0` names those ranges with the
  every-address wording rather than the narrower range wording. (`BACKLOG #3393`)
- **An integer setting refuses a bool or a fraction instead of truncating it.** Before this fix,
  `int()` turned `True` into 1 and `1.9` into 1. A code-first call such as
  `MLLP(max_frame_bytes=1.9)`, or an `env()` reference cast to `float` or `bool`, would have built a
  listener with a one-byte cap. A `connections.toml` literal was already refused at load. Now one
  converter, `count_setting` in `transports/base.py`, reads every integer cap that `cap_setting` or
  `positive_cap` reads. It also reads at least these former bare `int()` reads: DICOM
  `max_associations` and `max_pdu_size`, DATABASE `pool_max`, `capture_max_rows` and
  `capture_max_bytes`, and SOAP `ws_timestamp_ttl_seconds`. Each is refused at build, naming the
  key, when it is a bool, an infinity, a NaN, or a number of any type that is not whole. A DATABASE
  reference source's `pool_max` gets the same refusal at each sync. **`False` is refused too.** It
  used to read as 0, which turns most caps off, so write `0` or `None` for that. A float cap read
  through `cap_setting`, such as the MLLP `receive_timeout` or a `max_messages_per_second` rate, now
  refuses a bool as well. Only those float caps change: at least the `timeout_seconds` and
  `connect_timeout` reads on outbound connections still read `True` as 1.0. A whole number such as
  `2048.0` still reads as 2048. Text in exponent form, such as `"1e-400"` or even `"0e0"`, no longer
  turns an integer cap off; it is refused. A refusal for a value that is not a valid number names the
  key and withholds the value. The converter's docstring holds the full rule. (`BACKLOG #3431`)
- **A float cap or timeout refuses a bool, a NaN, an infinity, or text that only rounds to zero.**
  Before this fix, a bare `float()` read `True` as one second and took `nan` and `inf`. A float cap
  such as `receive_timeout`, `idle_timeout_seconds`, `max_frame_seconds` or a
  `max_messages_per_second` rate read text such as `"1e-400"` as off, because `float()` rounds it to
  `0.0`, so the guard it sets would not have run. Now one reader, `float_setting` in
  `transports/base.py`, reads every float cap that `cap_setting` or `positive_cap` reads, and
  `poll_seconds`. Each refusal names the key and withholds the value. The reader's docstring holds
  the full rule. (`BACKLOG #3432`)
  - A float cap is off only for an exact zero, such as `0`, `"0"`, `"0.0"` or `"0_0"`. `"0e0"` is
    refused, as it already was on an integer cap.
  - A `connections.toml` literal `1e-400` still reads as zero. The TOML parser turns it into `0.0`
    before any reader sees it.
  - The reader also replaces bare `float()` reads of `timeout_seconds` and `connect_timeout` on the
    MLLP, TCP, X12 and DICOM connections.
  - It reads `timeout_seconds` on the FHIR, FHIR lookup, REST, SOAP, DICOMweb, Email and Direct
    connections.
  - On those timeouts, `false` used to read as a zero-second timeout and `true` as one second.
    Both now fail at build. A float cap read through `cap_setting`, such as `receive_timeout`,
    already refused a bool (`BACKLOG #3431`).
  - It reads `acquire_timeout` on the DATABASE connections, the DATABASE lookup and a DATABASE
    reference source. `messagefoundry check` now refuses at least a bool, a NaN or `"1e-400"` as
    a reference source's `acquire_timeout`. That covers a literal, and an `env()` value when it
    resolves at check time. A zero or negative one still passes.
  - It reads the REMOTEFILE `connect_timeout`, the File source's `min_age_seconds` and the Timer
    source's `interval_seconds`.
  - It reads the OAuth2 and SMART token timeouts and expiry skews.
  - It reads the HTTP source's `reply_timeout` and `reply_write_timeout`. An `HttpSource` built
    directly now refuses a zero there, where a numeric `0` took the 30-second default. `Http()` and
    `connections.toml` already refused it.
  - The `Http` factory's own check of those two keys now refuses a bool, a NaN, an infinity and an
    integer too large for a float.
  - The other timeouts above are checked for type only. A zero or negative `timeout_seconds`,
    `connect_timeout` or `acquire_timeout` is still not refused at build.
  - Range refusals withhold the value too. At least `positive_cap`, `resolve_poll_ceiling` and
    `poll_interval` do, and so do the HTTP `max_header_bytes` and File `max_decompressed_members`
    checks. So do the MLLP `max_connections_per_host` and `max_frame_seconds` checks.
- **A connection whose target urllib's bypass list names goes direct cleanly.** A connection with
  `proxy_user` sending to a host on `NO_PROXY`, or on the Windows proxy override list, attached its
  `Proxy-Authorization` header although urllib sends that request direct. The `BACKLOG #3417` rule
  would refuse each such send, and the message would retry until it dead-lettered. The connection
  now attaches no proxy credential for that host, so the send goes direct, and it logs a WARNING
  that the environment overrides its proxy. (`BACKLOG #3442`)
- **An `anon.toml` rule on `MSH-1` or `MSH-2` is now refused when the overlay loads.** No rule can
  rewrite those two fields, because they hold the message's delimiters. The refusal used to run
  only for each message. So such an overlay loaded, every message then failed, and
  `python -m tee anonymize-captures` printed a count of failed messages with advice to extend the
  rule map. `load_rules` now raises one `RuleError` that names the overlay file and the field, and
  the tee prints that one line and writes no dataset. A `keep` on either field still loads. The
  check for each message stays, so a rule set built in code still meets the refusal there. A rule
  on field 0 was already refused at load. (`BACKLOG #2997`)
- **A bad `anon.toml` overlay is reported more accurately, and earlier.** Four small changes, none
  of which changes what the anonymizer scrubs. A path the system refuses to open, such as one with
  an embedded NUL, is now reported as `the path is not one the system can open`; it used to be
  reported as a value the TOML parser refused. TOML that runs out in a file ending in a newline now reads
  `invalid TOML at the end of the file, line N`, where N is the last line; the old text named the
  line after the last one. `python -m tee anonymize-captures` now checks the salt
  and loads the overlay before it reads the store, so a bad overlay or a weak salt refuses the run
  even when the store holds no captured bodies. `kept_defaults` is now exported from
  `messagefoundry.anon` and `tee.anon`. (`BACKLOG #3003`)
- **An `anon.toml` overlay that points a default field at a different surrogate kind now warns.**
  The kinds do not rewrite the same parts of a field. `id`, `mrn` and `ssn` rewrite the first
  component only, so `"PID-5" = "id"` left the given name in the dataset, and `"PID-7" = "date"`
  left the birth year. Nothing said so. The leak check counts such a field as scrubbed and does
  not scan what is left; that is unchanged, so a clean `anonymize_checked` return does not clear
  a retargeted field. `load_rules` now logs each such retarget at WARNING, naming the field, the default kind and the
  new kind, and never a value. A retarget to the same kind and a `drop` do not warn. The new
  `retargeted_defaults`, exported from `messagefoundry.anon` and `tee.anon`, lists them, and
  `python -m tee anonymize-captures` prints them on stderr at every `--log-level`. The retarget
  still loads: refusing one is not built. Two smaller changes ride along. The overlay warnings are
  logged once per process for one set of lines; a caller that passed `overlay=` for every message
  used to get them once per message. And a schema refusal now quotes at most 80 characters of any
  overlay key or value, and of the whole list of unknown keys, with a count of what was left out.
  (`BACKLOG #3000`)
- **`provision-admin` tells the earlier holder before it writes the new `--email` address.** On a
  repair, the takeover notice now goes out before the address write. A run that stopped between
  that write and the role used to leave the operator's address on the row, so the re-run told the
  operator instead of the earlier holder. A run that stops just after the notice sends it again
  on the re-run. (vault BACKLOG #2915)
- **A row that runs out its retries now writes a WARNING when it dead-letters.** A transient
  refusal or a transport failure that reached a finite `max_attempts` was dead-lettered inside the
  store with no log line. That held on the single-row path and the batch path. The delivery worker
  now writes one WARNING after that dead-letter, the same content-free line a permanent refusal
  writes. It names the connection, the outbox row, the exception class and its code, and the
  attempt count. The single-row line also names the message id. The batch line names how many
  rows were dead-lettered and the first member still present, which the decision came from. No
  line carries the message or the error's text. The store reports
  the dead-letter itself, so a final write the HA epoch fence re-pended is not reported as one. The
  line has its own throttle key per connection and code, so it never merges with a permanent
  refusal's count; both share the cap of 100 lines a minute. `max_attempts = None` still retries
  forever and never writes it. The dead-letter itself, its event and its counts are unchanged.
  (`BACKLOG #3108`)
- **`python -m harness.load.rigadmin run` passes the session as one `--token=VALUE` argument.** A
  session is drawn from `secrets.token_urlsafe`, whose alphabet holds `-`, so about one in 64
  starts with it, and the child's argparse read `--token` followed by such a value as a missing
  value and exited 2 (`expected one argument`). The CI load-test legs failed intermittently on
  that; the benchmark legs, whose gate fails only on `run`'s own exit 4, went green on such a run
  with no report.
- **`rotate-key` refuses a Vault Transit key of an unsupported type with a clean exit 2.** In
  `vault_transit` mode with a local key set, the Transit key-type check runs while the store opens.
  Its refusal escaped the command's handlers, so the command exited 1 through the last-resort hook.
  It now prints the refusal and exits 2, as the other key-resolution failures do. No command moves
  Transit ciphertext between keys yet; the refusal still says so.
- **Harness engine nodes and the durability-hook tests no longer leave processes behind.** An
  engine a load-harness node starts (`harness.load.failover.EngineNode`, which the connection-scale,
  shard and failover runners use) now sits in a kill-on-close job on Windows, so it and every
  process it starts end with the harness process however that ends, and `stop()`/`kill()` take
  the whole tree. POSIX is unchanged: there they still end only the engine's own process.
  `tests/test_durability_hook_push_bound.py` runs each hook-firing commit in such a job and fails a
  test that leaves a process running. Measured on a developer box before the fix: 54 connscale
  engines up to 16.5 hours old, and suspended `git` processes from the durability tests.
- **An X12 outbound acts on a TA1 only when its TA1-01 names the interchange it just sent.** The
  TA1 classifier read TA1-04 without checking TA1-01 against the sent ISA13, so a stale,
  misdirected or wrongly-echoed TA1\*R would have dead-lettered a delivered interchange on first
  deployment, and a stale TA1\*A would have confirmed one the partner never acknowledged. A TA1
  naming another interchange is now logged at WARNING with the two control numbers only and the
  delivery is retried; a persistent connection is discarded instead of reused. The TA1\*R reject
  message and the TA1\*E warning now name `TA1-01` (the acknowledged interchange) where they
  named the reply's own `ISA-13`. The matching rule is in the X12 section of
  [CONNECTIONS.md](docs/CONNECTIONS.md).

### Security
- **A settings error no longer shows the mapping it refused.** Every service-settings section, and
  the settings as a whole, now replaces the refused input with `[not shown]` in the error text, in
  `errors()` and in the JSON form. Before, a refusal such as an `http://` OIDC token endpoint could
  print the whole `[auth]` section, the signing key and its passphrase included, from any command
  that printed the error. A validator's own message is not hidden, so the OIDC URL refusals no
  longer quote the URL, and a user name or password in a pinned OIDC URL is now refused at load.
  `[auth].oidc_client_secret_ref` set to whitespace, or set beside `oidc_client_secret`, is now
  refused too. (`BACKLOG #296`)
- **`messagefoundry check-privileges` now probes the Vault tokens and the AD bind account.** It
  used to print those hops as not probed.
  - For each Vault token the engine uses, it reads the token's policies, TTL and renewability. It
    then reads the token's capabilities on each path the engine calls, and on paths it never needs.
  - A token is over-granted when it carries the `root` policy or holds more than the engine's calls
    need. So is a token that can write a policy, mint a token, or export a store key.
  - One token serving both the store and the connector secrets is judged on both grants together.
  - The check reads only the token in `MEFOR_STORE_VAULT_TOKEN` or `MEFOR_SECRETS_VAULT_TOKEN`. It
    sends it only to the address in `MEFOR_STORE_VAULT_ADDR` or `MEFOR_SECRETS_VAULT_ADDR`. It never
    uses `VAULT_TOKEN`, `~/.vault-token` or `VAULT_ADDR`, which the engine itself still falls back
    to. It never prints the token, its id or its accessor.
  - For the AD bind account, it runs the LDAP "Who am I?" operation and reads the account's own
    groups. Membership of an administrative group it knows is an over-grant.
  - That proves identity and group membership, not rights. Delegated directory ACLs are not read,
    and the output says so.
  - Each run binds to AD as the service account. A wrong bind password counts toward the AD lockout
    threshold every time.
  - Each probe goes through the client the engine already builds for that hop. A probe that cannot
    run is reported as not observed.
  - **The command now exits 4 where it used to exit 0:** when a Vault or AD probe cannot read its
    principal, for example when run without the service's environment. Before, those hops were
    printed as not probed and never changed the exit code. The store hop already worked this way.
  - These findings are reported only. Unlike the store's, they never stop `serve` from starting.
  - SMTP and the identity provider are still printed, not probed. See
    [SECURITY.md](docs/SECURITY.md). (`BACKLOG #305`)
- **[SECURITY.md](docs/SECURITY.md) records one more limit of the sign-in time floors.** A
  federated sign-in that rides a live single sign-on session at the identity provider would get no
  time floor, so a client could avoid the floor by authenticating there first. The sign-in rate
  limit still applies while it is in force. It is recorded as a decided limitation, and it
  still counts as a gap. No behaviour changed.
  (`BACKLOG #1115`)
- **`serve` and `supervise` now test the protocol header floor at every start, and refuse on a
  failure.** The floor adds `nosniff` and the framing policy to the responses uvicorn writes
  itself. Until now the start-up check read only the shape of the uvicorn and websockets hooks the
  floor overrides. A new self-test, `messagefoundry/api/protocol_floor_selftest.py`, drives the
  built classes in memory: a malformed request, an app error, a WebSocket handshake with no key,
  and a WebSocket app error. It reads the headers off each answer. If one is missing, the engine
  names the response and the header and exits with code 2, before it mints a certificate or opens
  the store. It opens no socket and added about 7 ms to a start when measured. It covers those
  four response families only. With a client CA and a certificate identity map both set, it runs
  a second time, on the client-certificate class the engine then serves. There is no opt-out.
  (`BACKLOG #1120`)
- **The harness HTTP sinks answer Python's own error pages in plain text, not HTML.** Python's
  HTTP server writes some answers before the sink's code runs. At least these: a `400` for a
  malformed request line, `414`, `431`, `501` and `505`. It writes them through `send_error`,
  which defaults to an HTML page. The sink now sends them as `text/plain; charset=utf-8`. The
  body is the status and Python's explanation. It leaves out the reason phrase, which can echo
  the request line. The status line still carries that phrase, as Python writes it. Those
  answers also carry the baseline security headers, as every sink answer now does. (`BACKLOG #1120`)
- **Every answer the harness HTTP sinks write now carries the baseline security headers (ASVS
  3.4.4 and 3.4.6, and the `base-uri` part of 3.4.3).** `harness/sinks/_http.py` is the loopback
  server behind the REST, SOAP, FHIR and DICOMweb sinks. Its answers carried no `X-Content-Type-Options` and no
  `Content-Security-Policy`. They now carry the same four headers the engine's HTTP listener sends:
  `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and
  `frame-ancestors 'none'; base-uri 'none'`. That covers the answers Python's own HTTP server
  writes before the sink's code runs, such as its `400` for a malformed request and its `501` for
  an unknown method. Python's server would write some answers with no status line and no headers
  at all, in HTTP/0.9 form: at least an HTTP/0.9 request, its own `400` for a request line it
  cannot parse, and its `505` for a version it refuses. The sink now answers those with a status line and headers.
  The interim `100 Continue` carries the four headers too. No answer carries HSTS. The status, the sink's own
  bodies and what the sink records are unchanged. (`BACKLOG #1120`)
- **The protocol header floor now covers uvicorn's sans-I/O WebSocket protocol, and uvicorn moves
  past its `<0.50` cap.** From uvicorn 0.50, `ws="auto"` resolves to that protocol. The
  floor refused it, so `serve` exited with code 2 on any newer uvicorn, and the cap held uvicorn at
  0.49. The floor now adds `nosniff` and the framing policy to the handshake answers that protocol
  writes. At uvicorn 0.54.0 those are at least: the websockets library's own rejection of a bad
  handshake, uvicorn's `500`, its `403` for an app that closes before accepting, an app's own
  denial, and the `101`. It does so in one place,
  the `send_response` of the connection object the protocol hands each answer to. The legacy
  websockets server stays covered as before. wsproto is still refused. The lock moves
  uvicorn to 0.54.0. The entry on the uvicorn and `websockets` pins says how both are now held.
  The startup self-test drives whichever WebSocket class is served, and
  gains two drives: an app that closes before accepting, and an upgrade the websockets parser
  rejects. On this protocol the floor also does two things beyond adding headers, each a
  workaround for uvicorn 0.54.0 behaviour its legacy server did not have. It writes what the
  websockets parser queued for a request it rejected, a `414` or `431` or nothing at all, and
  closes; uvicorn leaves that unwritten and the connection open. And it drops a second handshake
  answer on a connection that has already ended its stream; uvicorn sends one at server stop,
  websockets asserts on it, and the stop would raise before the engine's own shutdown ran.
  (`BACKLOG #1120`)
- **uvicorn and websockets are pinned exactly, to `uvicorn==0.54.0` and `websockets==17.2`.**
  Release 0.5.1 declared `uvicorn>=0.29,<0.50` and `websockets>=16.0`, and locked uvicorn 0.49.0
  and websockets 17.1. The protocol header floor overrides internals of both. Its wire suite
  drives only the pinned versions, and a range let an install take a release nobody had read. A
  new test holds the pins equal to the versions the wire suite measured. The startup self-test
  still runs on whatever is installed.

  The pins have a cost. A site cannot take a newer uvicorn or websockets, a security fix
  included, without a new MessageFoundry release. When a uvicorn or websockets advisory lands,
  the fix reaches a site in a MessageFoundry release that moves the pin. Upgrade to that release.
  A site that runs `pip-audit` sees the advisory until then. (`BACKLOG #1120`)
- **websockets moves to 17.2 under the protocol header floor, and the floor refuses at start when
  an attribute its two uvicorn workarounds use is gone.** The floor wraps websockets internals, so
  its wire suite names the exact version it measured and fails on any other. The installed 17.1
  and 17.2 packages were compared file by file. At least these are byte-identical: `server.py`,
  `protocol.py`, `http11.py`, `datastructures.py`, and the legacy `server.py`, `protocol.py` and
  `handshake.py`. These changed and were read: `legacy/http.py`, which the legacy handshake uses
  to read a request, now stores a header it has just validated without validating it again;
  `extensions/permessage_deflate.py` no longer supports a compression window of 8 bits, which
  can change whether an accepted handshake's `101` carries `Sec-WebSocket-Extensions`;
  `frames.py` changes how a frame is rendered for a log line. None of them changes how a
  rejection is written or how any handshake answer gets the floor's headers. The compiled
  `speedups` module was not compared. The wire suite and the startup self-test pass on 17.2.
  Separately, the class build now requires at least these to be assigned upstream: `eof_sent`
  and `handshake_exc` on the websockets connection, and `handshake_initiated`,
  `handshake_complete`, `close_sent` and `transport` on uvicorn's protocol. A rename would
  otherwise have switched a workaround off, or left it setting a dead name, with no error.
  `serve` now names the missing one and exits with code 2. The check sees a name that is no
  longer assigned. It does not see one uvicorn still assigns and has stopped reading, and no test
  covers that case. Not refreshed here: `security/risky-component-readings.json` and
  `security/bundled-code-survey.json` still describe websockets 17.1. They are dated snapshots
  made by hand with network access. (`BACKLOG #1120`)
- **`serve` names a web proxy it may pick up from the environment.** With an environment or
  system proxy set, `serve` and `supervise` each log one WARNING at start. It names each proxy
  that is set, never a user or password from its URL, and the hops that may read one. If either
  cannot build that WARNING, it logs a value-free one saying a proxy may be set. What each says, and what
  reaches the proxy, is in
  [CONFIGURATION.md](docs/CONFIGURATION.md#serve-names-an-environment-proxy-at-start).
  ([BACKLOG #1125](docs/BACKLOG.md))
- **The deployment documents now state what a proxy in front of the engine must do about request
  framing.** A reverse proxy or load balancer must refuse the ambiguous request shapes the engine's
  own parser refuses, send each body with one `Content-Length`, and drop a connection after an
  error. A forward proxy named by `proxy_url` must not re-frame what it carries. See
  [DEPLOYMENT.md](docs/DEPLOYMENT.md#a-proxy-in-front-of-the-api-must-refuse-the-request-shapes-the-engine-refuses).
  ([BACKLOG #1125](docs/BACKLOG.md))
- **The ECH egress sidecar contract states a framing rule.** A conforming sidecar reads and re-sends
  every request and reply, so it must not re-frame them. It keeps each request's `Content-Length`,
  refuses ambiguous framing rather than cleaning it up, and drops its connection to the partner after
  a misframed reply. [samples/ech-sidecar/README.md](samples/ech-sidecar/README.md) links to the
  front-proxy rules rather than restating them. (`BACKLOG #1125`)
- **`serve` pins the API's HTTP parser to httptools (llhttp), and pyproject pins it exactly, to
  `httptools==0.8.0`.** uvicorn's `http="auto"` picks httptools when it imports and falls back to
  h11 when it does not, with no log line. The two parsers frame some ambiguous requests
  differently, and h11 answers shapes llhttp refuses. `serve` now names the httptools protocol
  itself, refuses to start when httptools does not import, and logs which parser it serves at
  startup. A new suite sends those shapes over a real socket and checks each gets one `400`. It
  drives only the pinned version, so the declared range `httptools>=0.8.0` became an exact pin.
  A test holds the pin equal to the version the suite measured.

  The pin has the same cost as the uvicorn and websockets pins. A site cannot take a newer
  httptools, a security fix included, without a new MessageFoundry release. Dependabot gained an
  ignore range for httptools at `>=0.9.0`, the next minor after the pin, and opens no security PR
  in it. `pip-audit` over the lock still reports an advisory. (`BACKLOG #1125`)
- **`gzip_decompress` caps the number of gzip members at `max_members`, default 1024.** A gzip
  stream may be many members back to back, and a member can inflate to nothing, so a stream of
  empty members passed any byte ceiling while each member still cost work. A 16 MiB drop on a
  File inbound with `decompress="gzip"` holds about 800,000 of them. The codec now counts each
  member as it starts and refuses the one past the cap before it inflates. The File connector
  quarantines an over-cap drop to `.error`. The gzip path now walks members through the shared
  bounded inflate loop rather than `gzip.GzipFile`, so it also refuses a header with a reserved
  flag bit set or a wrong header CRC, as RFC 1952 requires. Stdlib `gzip` ignores both.
  (`BACKLOG #1129`)
- **Every decompressor checks its caps in a trial pass before the real decompression.**
  `gzip_decompress`, `deflate_decompress`, `deflate_decompress_with_tail` and `zip_decompress`
  first inflate the whole input in bounded chunks and keep none of the output. A stream over the
  byte ceiling or the gzip member cap is refused there, with the same `CompressionError` as
  before, and the real decompression never starts. The zip entry cap is still read from the
  central directory before either pass. Before, a bomb was
  refused only after the real pass had kept up to the ceiling in memory. An admitted stream is
  now inflated twice, which costs less than double the time; ADR 0123 records a measurement. The
  trial pass is skipped where it has nothing to refuse, a zlib or zip call with
  `max_output_bytes=None`. (`BACKLOG #1129`)
- **The File connector has a `max_decompressed_members` setting, default 1024.** It sets the gzip
  member cap for one connection. A BGZF feed holds one member per 64 KiB block, so it trips the
  default cap near the 64 MiB byte ceiling, and a site can raise the cap for it. The cap cannot be
  turned off: unset or `None` takes the default, and `0` in any spelling is refused when an
  inbound File connection is built. (`BACKLOG #1129`)
- **An SVGZ attachment is checked by trial passes before the pass that keeps it.** The download
  route inflates a gzip attachment to vet any SVG inside. That inflate used to bound its output
  only as it kept it, so markup over the 32 MiB bound was refused after up to 32 MiB was held. Now
  the head sniff and the size check keep no output, through the shared bounded inflate loop the
  compression codec uses. Markup over the bound is refused before any of it is held, and only an
  admitted body is inflated again to be sanitized. The member cap and the size bound are
  unchanged. (`BACKLOG #1129`)
- **A File inbound with `decompress=` set warns when `max_decompressed_bytes` is off.** Turning the
  decompressed-byte ceiling off with `0` or `None` is still allowed, but the connection now logs one
  warning when it is built, naming the connection and the setting. Off without `decompress=` changes
  nothing and logs nothing. (`BACKLOG #1129`)
- **An `[api].trusted_proxies` entry that covers more than one address is now named as a security
  loosening.** Every host inside a trusted range may set `X-Forwarded-For`, so each one can declare
  its own source address. That poisons the audit trail, the per-address sign-in limit and the
  new-client-IP step-up signal. Before this, only entries covering a whole address family were
  named, and a `/8` or a `/31` was silent. Any entry wider than one host is named now, IPv4 or IPv6,
  a `/31` or `/127` included. Entries that cover a whole family keep their own wording. The check is
  advisory, so the load still accepts a range. The serve-time warning, `messagefoundry security show`
  and `GET /security/posture` all list it.
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md) says what it gives up. (`BACKLOG #1131`)
- **`provision-admin` now requires `--email`.** No Administrator it creates starts without the
  address its security notices go to. A missing `--email` is refused by the parser, and a blank or
  malformed one by the same one-mailbox check `POST /users` applies. Both refusals come before the
  password prompt and leave no store behind. The service method behind the command now refuses a
  blank or malformed address too, where it used to read a blank one as none. The missing-address
  warning is gone, and the `--json`
  body no longer carries `notify_email_set`, which could only read true. The IDE's Start flow now
  asks for the address and will not accept a blank one. `admin-set-notify-email` stays, for an
  Administrator that has no address some other way, such as a directory account granted the role.
  Email over SMTP stays the only push channel for security notices. (BACKLOG #1138, owner ruling
  2026-10-10)
- **Three more admin routes refuse your own account: the admin session revoke, the role write and
  the channel-scope write.** Each one revokes the target's sessions on the login window. Aimed at
  yourself, it would have ended every session you hold with no fresh proof (ASVS 7.5.2). Each now
  answers 400 for the caller's own account, on the JSON API and the console, and writes an
  `auth.self_target_refused` audit row with `op` `revoke_sessions`, `set_roles` or
  `channel_scope`. The guard compares the stored id too, as the other six do. End your own other
  sessions from `DELETE /me/sessions` or the console's **Active sessions…** view, and the current
  one with *Sign out*. A write that ends a whole group's sessions, such as an AD group-map save,
  is not refused. See [SECURITY.md](docs/SECURITY.md). (`BACKLOG #1149`)
- **The live monitor socket and the bulk export check the caller again while they run.** The
  `/ws/stats` feed resolves the session before every frame instead of every 3 s, and now also
  checks the second factor and the notification address there, not only at the handshake. A
  refusal closes the socket before the next frame. `GET` and `POST /messages/export` resolve the
  caller before every row. A revoked session, a withdrawn permission or a narrowed channel scope
  records `messages_export.stopped` and ends the download. (Corrected under `BACKLOG #3381`: this
  read "aborts the download"; the client receives a cleanly ended short file, not a failed one.) An administrator's scope change of
  either direction revokes the session, so it closes the socket and stops the download too. While
  rows flow, the export keeps its session's idle clock moving; a download stalled for about three
  quarters of the idle window can end the session, as any idle session ends. On a first
  deployment, a revoked or narrowed grant would otherwise have kept receiving up to three more
  frames, or the rest of an export of up to 100,000 bodies.
  (`BACKLOG #1154`)
- **The VS Code extension's cached AI policy expires when it enables assistance.** When the engine
  is unreachable, a cached answer that enables assistance now stands for 12 hours from the
  engine's answer, then assistance turns off until the engine can confirm it. A cached answer that
  disables assistance still stands at any age. A cache from an earlier version counts as expired.
  (`BACKLOG #1154`)
- **The audit export checks the caller again before each page.** `GET /audit/export` and the
  console's `/ui/audit/export` resolve the session before every page of up to 1,000 rows. A
  revoked session, a withdrawn `audit:export`, a pending password change or an unmet second factor
  records `audit.export.stopped` with counts only and ends the download. (Corrected under `BACKLOG #3381`: this read "aborts the
  download"; the client receives a cleanly ended short file, not a failed one.) So does a caller that
  has lost `users:manage` since the export started, because the pages would still carry the lock
  rows. On a first deployment, a revoked grant would otherwise have kept receiving the rest of an
  export of up to 1,000,000 rows. (`BACKLOG #1154`)
- **BREAKING: XML signature checks now refuse weak EC keys and every DSA key.** The XML-DSig
  `verify()` used to floor only RSA keys. It accepted a P-192 key and a 1024-bit DSA key on both
  the `x509_cert` and the `ca_pem_file` paths. Now an EC key must be on P-256, P-384 or P-521, the
  same curves the Direct transport allows. A DSA key is refused at any size, and so is any key type
  other than RSA, EC, Ed25519 or Ed448. A refused key returns
  `verified=False` with the reason `WeakSigningKey`, even when the signature itself is valid. A
  partner that signs XML with one of these keys must move to an approved EC curve or to RSA of at
  least 2048 bits. (`BACKLOG #1166`, ASVS 11.2.3)
- **Five more compares run in constant time.** The session-list routes in the API and the web
  console, the session-rotation grant walk, the trust-anchor pin check, and the DR backup's key-id
  match each used `==` or `!=`, which stops at the first differing character. Each now calls
  `messagefoundry.credential.constant_time_equal`. Only the grant walk compares a value the caller
  is not already shown: the session lists return each hash, a CA fingerprint is public, and an
  archive's key id sits in its header. The outcome of each compare is unchanged.
  The store cipher's keyring fallback no longer stops at the first key that opens a value. A row
  whose marker names no configured key, or whose named key fails, is now tried against every
  keyring key, so the read time no longer shows which fallback key sealed it. A row whose named
  key opens it still stops at that key. Fallback reads cost one tag check per keyring key, plus
  one sub-key derivation per key for a v4 row. The decrypted value and the error texts are
  unchanged. (`BACKLOG #1167`, ASVS 11.2.4)
- **An IDE error from a `--json` CLI call no longer quotes the CLI's output.** When the command's
  stdout is not JSON, or is empty, the message now names the subcommand, its exit code and a byte
  count, and says to run the command in a terminal to read the output. Before, the message quoted
  the start of stdout (through Node's JSON parse error) or the whole stderr. That text could carry
  message data, and it showed in the Live Debug lens title, the status-bar tooltip and the Test
  Bench failure toasts. The CLI's own `{"error": ...}` body still shows as before. The paths traced
  in `dryrun`, `validate` and `graph` build it from configuration and path facts, class-only text
  or `safe_exc`-scrubbed text; `ide/src/cliJson.ts` lists them. (ASVS 14.2.6, vault
  `BACKLOG #1187`)
- **`messagefoundry dryrun` reports an unexpected error that stops its per-message loop by class
  only.** Before, its `{"error"}` body was the exception's text, which can quote message data. The
  inbound-selection refusals keep their text, since they name connections. (vault `BACKLOG #1187`)
- **`messagefoundry dryrun` sends a `print()` in a config module, Router or Handler to stderr.**
  Stdout now carries only the JSON result, so a debugging print no longer breaks the IDE's parse.
  Nothing redacts what an author's own print writes, so stderr is no safer than stdout; see
  [PHI.md](docs/PHI.md). (vault `BACKLOG #1187`)
- **A custom role can no longer hold `messages:view_raw` without `messages:view_summary`.** Creating or
  editing one is refused with a `CustomRoleError` that names the pair. A stored role of that shape
  (hand-edited, or written before the rule) now grants everything but `view_raw`. A role that may
  read whole message bodies but not the patient summary is not a coherent role, and owner ruling
  R18 makes a one-message read the reveal act only for a `view_summary` holder. This closes every
  body route at once, `/raw`, attachments, the console body page and a one-id export among them. No
  built-in role has that shape. See [SECURITY.md](docs/SECURITY.md). (ASVS 14.2.6, vault
  `BACKLOG #1187`)
- **The IDE's Live Debug reveal now shows one message.** *Reveal Values for One Run* used to show
  values from every message in a multi-message sample. It now asks which message first, listing them
  by file name and disposition, and the revealed run keeps only that one. A one-message sample needs
  no choice. The pick is by position: if the sample's message count changed since it was listed,
  nothing is revealed, and the next reveal lists the messages again. Hide, or turning Live Debug
  off, while the choice is open starts no reveal. The `--show-phi` run still covers the whole
  sample, and the extension drops every other message before anything renders, as the Test
  Bench's per-case reveal does. Owner ruling R15 reads a reveal
  as per message. (ASVS 14.2.6, vault `BACKLOG #1187`)
- **The IDE's Live Debug no longer shows error text on a masked run.** The `inbound()` summary's
  tooltip now says only how many messages failed, and that a reveal is available. The CLI's masked
  error is scrubbed rather than removed, so it can still quote a field value, and a hover is not an
  act aimed at reading one. The text shows on a run the user revealed. (ASVS 14.2.6, vault
  `BACKLOG #1187`)
- **The captured-reply and outbound-payload bodies now need `messages:view_summary` as well as
  `messages:view_raw`.** `GET /messages/{id}/outbound` answers 403 and writes an
  `auth.permission_denied` row for a caller missing either. `GET /messages/{id}/responses` returns a
  null `body` to one. Owner ruling R18 makes these one-message requests the reveal act only for a
  `view_summary` holder, and an ADR 0045 custom role could hold `view_raw` alone. No built-in role
  changes: Administrator and Operator hold both. See
  [SECURITY.md](docs/SECURITY.md). (ASVS 14.2.6, vault `BACKLOG #1187`)
- **`cert import` now checks a private key inside an encrypted part of a PKCS#12 bundle.** Before,
  the wrap check read only the outside of a bundle. A key bag inside an encrypted part (an
  EncryptedData SafeContents) needed the passphrase to reach, so it went unchecked: a key wrapped
  with PBKDF2 at 2048 iterations, or with a PKCS#12 PBE scheme, loaded from inside an AES-256-CBC
  part at the floor. Now `pki.load_pkcs12` opens each encrypted part with the passphrase once the
  outside passes, and holds its key bags to the same floor before `cryptography` decrypts any key.
  This is design A, a Manager decision (M4, 2026-10-10), not an owner ruling. A bundle with the
  certificate in an AES-256-CBC part, the shape OpenSSL 3's export writes, still loads when its
  parameters meet the floor, as the re-export command's output does. **BREAKING** for at least
  these bundle shapes: a weak key bag inside an encrypted part, and an encrypted part the engine
  does not open to check, such as one under scrypt or a cipher other than AES-CBC. Each is refused
  with the reason. See
  [CONNECTIONS.md](docs/CONNECTIONS.md#encrypted-private-keys-must-meet-the-wrap-floor).
  (`BACKLOG #1352`)
- **`fhir_lookup` refuses a resource id that is only dots.** A read-by-id such as
  `fhir_lookup("epic", "Patient/..")` built `{base}/Patient/..` and sent it as written. The id
  rule admitted `.`, `..` and `...`, and percent-encoding leaves a dot as it is. A FHIR update
  already refused these ids; the read did not. `.` and `..` are dot segments under RFC 3986. On a
  first deployment behind a proxy or server that removes dot segments, a message-derived id of
  `..` would have turned a read of one resource into a request to the base URL, on the same
  allow-listed host. What a given proxy or server does was not measured. The read now raises
  `FhirLookupError` for all three ids, and nothing is sent. (vault BACKLOG #1589)
- **A bad OIDC authorization code can no longer hide the federated sign-in link, even when the
  identity provider answers it with a 5xx.** PR 1643 stopped a 4xx from the token endpoint marking
  the provider unavailable. A faulty provider that answered a caller's bad code with a 5xx still
  hid the link on `/ui/login` and in `/auth/providers` from every visitor. On a first deployment
  with OIDC on, a signed-out caller could have done that again and again. Now only a transport
  failure marks the provider unavailable: connection refused or reset, DNS, a timeout, a TLS
  handshake, or a reply cut short. Any status the token endpoint answers with, and a 2xx with no
  usable token, fails the sign-in and is audited `auth.login_failed` with `reason=token_refused`
  and the status. An outage where no answer arrives still hides the link, and the next success
  still restores it. The cost: a provider that answers every request with a 5xx keeps the link
  showing. That includes a provider behind a proxy whose outage arrives as a 502, 503 or 504. See
  [ADR 0142](docs/adr/0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md)
  Amendment E. (BACKLOG #1948)
- **An alert rule that can silence a credential reminder is now named as a security loosening.**
  A `[[alerts.rules]]` entry matching `any`, `initial_credential_expiring`, `cert_expiry` or
  `secret_rotation` that sets `mute = true` or `transports = []`, or has an `escalate` tier with
  `transports = []`, sends that reminder to no transport after the recipient gate has passed. Each
  such rule is now listed as `alerts.rules`, by position and `id`, in the serve-time warning,
  `messagefoundry security show` and `GET /security/posture`. The check reads each rule alone, so it
  can name a rule whose connection glob never matches a reminder. (`BACKLOG #2008`)
- **Resolving an interrupted approval now flags a resolver whose account changed after the
  request.** `POST /approvals/{id}/resolve` runs the approver-provenance check on the resolver, as
  a release runs it on the approver. A flagged resolution still goes ahead. It writes
  `approval.approver_provenance` with `act` set to `resolve`, and raises
  `approval_approver_provenance` keyed `approval:<id>:resolve`. A release's row now carries
  `act` set to `release`. See the dual-control section of
  [SECURITY.md](docs/SECURITY.md). Seat decision under owner delegation 2026-10-08, not an
  owner ruling. (`BACKLOG #2125`)
- **`messagefoundry check` has a new required leg, `oidc-revocation`.** With federated sign-in
  on, it fails where `serve` would refuse to start: an OIDC token or JWKS leg off this host that
  checks no certificate revocation, under an enforcing posture. It reads the same decision as
  `verify`'s `fed.idp_revocation` row. It reads no IdP anchor file, so an anchor that is missing
  or unreadable on the machine running `check` does not fail it; `verify` checks the anchor on
  the host. The lifespan now also seeds the built-in roles and runs the security-notice gate
  before `engine.start()`, so a first-run refusal stops startup before any connection starts.
  (`BACKLOG #2131`)
- **More directory sign-in refusal rows record the client address.** The OIDC `state_unknown`,
  `state_mismatch` and claims-check refusals wrote `auth.login_failed` with no `client`. So did at
  least the other OIDC, Windows SSO and retired simple-bind refusals that share their audit path.
  A spray of forged callbacks or junk tokens would have shown no source. Each of these rows now
  records the caller's address, as the `token_refused` row already did. A refusal that writes no
  row, such as rate-limit exhaustion, is unchanged. (vault BACKLOG #2132)
- **A directory revocation that never read the disabled bit no longer tells the holder an
  administrator disabled the account.** The directory session reconciler sent the
  `account_disabled` notice for every whole-account revocation. Only `directory_disabled` reads the
  disabled bit. Every other whole-account reason now sends a new `directory_sessions_ended`
  notice. At least `directory_absent`, `directory_undetermined` and `directory_object_id_missing`
  do. The notice says the engine ended the account's sessions. It says the engine could not
  confirm from the directory that the account may still sign in. It names no directory check,
  because for `directory_object_id_missing` the engine never asks the directory (vault BACKLOG
  #3171). `directory_disabled` still sends `account_disabled`, and a role change still sends
  `roles_changed`. (`vault BACKLOG #2140`)
- **The IdP step-up compares the IdP's clock with the IdP's clock.** An `oidc` session now stores
  its sign-in's verified `auth_time` as the IdP stated it, in a new `sessions.idp_auth_time` column
  on SQLite, Postgres and SQL Server. A step-up must now bring a later `auth_time`, with no skew
  allowance, as well as passing the existing check against the engine's clock. Each step-up that
  passes writes its own `auth_time` back in the statement that stamps `reauth_at`, and the value
  only moves forward. So an IdP that replays its last answer is refused too. That refusal is
  audited as `step_up_idp_auth_time_not_later`, and a session holding no value as
  `step_up_idp_auth_time_missing`, apart from the engine-clock `step_up_not_fresh`. A retry
  cannot clear a missing value, so that refusal tells the operator to sign in again. A later IdP
  answer can clear the not-later refusal, so its text offers a retry first. The step-up now checks
  the verified `(iss, sub)` before both freshness tests, so another person's IdP answer that passes
  the earlier checks is audited as `step_up_subject_mismatch` rather than a freshness reason.
  Before,
  an IdP that ignored `max_age=0` would pass when its last sign-in for the user was within
  `oidc_clock_skew_seconds` of the request. Now it would pass only when the user signed in at the
  IdP again after the stored value. An IdP clock that steps back would refuse a real step-up until
  it passes that value. (vault BACKLOG #2143, ADR 0142 AC-15)
- **The first-seen sign-in address signal reads a per-account record, not the audit log.** A new
  `known_login_addresses` table on SQLite, PostgreSQL and SQL Server holds one row per host an
  account finished a sign-in or passed a step-up from, keyed on the account id and deleted with the account. The signal
  reads it through the table's primary key, so a sign-in no longer scans `audit_log`, which has no
  actor index. A sign-in writes a row only once it owes nothing more, which closes four gaps in the old
  baseline: a directory sign-in that still owed a factor counted as seen; a challenged sign-in from
  a new address made the next one from that address unchallenged; a first sign-in finished through
  factor enrolment left no baseline; and history was keyed on the username. A first-seen address on
  a local sign-in that owes no factor now becomes known through a step-up from it, not by signing
  in again. The `login_new_ip` notice now says the address has not recently finished a sign-in. See [SECURITY.md](docs/SECURITY.md) and the PHI inventory in
  [PHI.md](docs/PHI.md). (vault `BACKLOG #2145`)
- **Signing in again ends the replaced session even when an elevation races it (ASVS 7.2.4).** The
  login supersession used to read the presented session, then revoke it by token hash. On a first
  deployment, an elevation (MFA, a step-up, a passkey ceremony) that gave the same session a new
  token between those two calls would have left it live. The two are now one atomic store
  operation, `supersede_session`, on SQLite, Postgres and SQL Server. An elevation after it now
  fails closed. One case stays open, and [SECURITY.md](docs/SECURITY.md) states it: an elevation
  that finishes before the supersession runs still leaves the session live under its new token.
  (`BACKLOG #2146`)
- **A federated step-up refuses an account demoted in the directory since sign-in.**
  `complete_oidc_step_up` already asked the directory whether the account is still there. It now
  also maps the account's current groups to roles, and refuses when a stored role is not among
  them, as the TOTP and passkey legs do (BACKLOG #2240). Before, such an operator could finish a
  step-up at the IdP with the old roles. That held until the reconciliation pass revoked the
  session. Only a lost role refuses, and channel scope is not compared. The refusal writes no
  roles, leaves the session as it was, and is audited on `auth.reauth` with
  `reason=directory_roles_demoted`. (vault BACKLOG #2154)
- **The first-seen sign-in address rows now say which directory leg signed in.**
  `auth.login_new_ip` and `auth.login_address_unevaluated` carried `provider: ad` for Kerberos and
  OIDC alike. A directory sign-in now adds `mech`, `kerberos` or `oidc`. The `login_new_ip`
  notice's event detail carries it too; the email text is unchanged. (`vault BACKLOG #2156`)
- **The mid-session new-address signal now reports each new address once per session, until the
  session re-verifies.** It used to remember only the last address, so a token alternating between
  two new addresses wrote an `auth.new_address_reverify_required` row and a notice on every switch. A
  re-verification now starts the count over, so an address flagged before it is reported again
  rather than step-up-forced with no row. One session reports at most eight addresses between
  re-verifications, plus one row carrying `cap_reached` for the first address past that, whose
  notice tells the holder that further new addresses go unreported until it re-verifies. An
  IPv4-mapped address such as `::ffff:10.0.0.5` now compares as its IPv4 form, as the sign-in
  signal already did, and that signal's notice debounce now folds it too. (`vault BACKLOG #2159`)
- **A federated step-up now records whether the browser's address moved mid-ceremony.** The
  `auth.reauth` row a completed step-up writes carries `start_client`, the address the step-up
  started from, and `client_moved`, whether the callback came from a different host. A move is
  recorded, never refused, and the session still anchors to the callback's address.
  (`BACKLOG #2160`)
- **Behind an ECH sidecar, a CRL no longer lifts the revocation refusal on a SMART or OAuth2 token
  endpoint.** Under an enforcing posture, a verifying `https` token endpoint on an off-loopback
  host is refused unless the hop checks revocation or the connection attests it. With
  `ech_egress` set, the engine sends the token request to the loopback sidecar, and the sidecar
  makes the TLS connection to the token host. The engine's own TLS context never meets that host.
  A `[tls].crl_file` that covered the token host still landed on that context, and the revocation
  check read it as proof. On a first deployment such a token endpoint would have crossed with no
  revocation check behind it. The check now ignores that context when `ech_egress` is set. That
  token endpoint is then refused unless the connection sets `tls_revocation_attested = true` with
  a `tls_revocation_attested_reason`, and the refusal names that attestation alone. A token
  endpoint with no sidecar is unchanged: a CRL that reaches it still lifts the refusal. The
  decision is the note dated 2026-10-04 in section 4.3 of
  [ADR 0173](docs/adr/0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md).
  (vault BACKLOG #2169)
- **A bare CR in a web proxy's own reply to `CONNECT` is now refused.** For an `https` target
  behind an HTTP proxy, that reply head was the one the bare-CR check did not reach. It is now
  refused before anything enters the tunnel, on the urllib egress hops and on the Vault hop (ASVS
  4.2.1). The header checks made on a partner's reply head still do not run on this one.
  (`BACKLOG #2170`)
- **A CRL that reaches a REST, SOAP, FHIR or DICOMweb destination now lifts its revocation
  refusal.** Under an enforcing posture, a verifying `https` destination to an off-loopback host
  is refused unless the hop checks revocation or the connection attests it. The four HTTP
  destinations ran that check without the opener the hop dials, so a CRL loaded on it never
  counted. On a first deployment the hop would have been refused even with `[tls].crl_file`
  reaching it, and the refusal would have told the operator to set the setting already set. Each
  destination now runs the check after its opener is built, and reads that opener. Two shapes
  stay refused unless the connection sets `tls_revocation_attested = true` with a
  `tls_revocation_attested_reason`:
  - A REST destination behind an ECH sidecar (`ech_egress`). The sidecar makes the TLS connection
    to the peer, so no CRL on the engine checks that peer. The refusal there names the
    attestation alone.
  - A REST, SOAP or FHIR destination with `tls_allow_expired = true`. That setting also lets a
    CRL past its `nextUpdate` date pass the handshake, so a CRL on that hop does not count. Its
    refusal text still offers `[tls].crl_file`, which cannot cross it.

  The revocation refusal now comes later at build, and on REST and FHIR it is the last check. A
  config with two faults reports at least these before it: a `tls_ca_file` that will not load, a
  bad `[tls].crl_file`, and on REST, SOAP and FHIR a Digest setup error. See
  [DEPLOYMENT.md](docs/DEPLOYMENT.md), *Revocation-guard behavior*. (vault BACKLOG #2188)
- **Four more verifying outbound hops are refused when they check no certificate revocation.** The
  four are an https `FhirLookup` read, a `DICOM()` outbound with `tls = true`, an FTPS upload, and
  a `Direct()` outbound that sets a `username`. Each verified the peer certificate and ran no
  revocation guard. On a first deployment under the default `enforcement = enforce`, each would
  have accepted a revoked certificate with no refusal, warning or audit record. Each now takes the
  refusal MLLP, REST and EMAIL take, when the peer is off-loopback.
  **A config with one of these hops to an off-box host now fails `messagefoundry check`, dry-run
  and reload.** A `serve` start runs no such check. There a refused `DICOM()`, FTPS or `Direct()`
  outbound costs that one lane: the engine records the lane as failed and starts the rest of the
  graph. A refused `FhirLookup` is isolated the same way (BACKLOG #3008). No refused hop is
  dialled in either case.
  **There are two ways across.** Load a CRL with `[tls].crl_file` where it reaches the hop. Or
  declare `tls_revocation_attested = true` with a `tls_revocation_attested_reason` on the
  connection. On a `FhirLookup`, one declaration covers both the read and its SMART token
  endpoint. A `Direct()` outbound with no SMTP credential is unchanged: its body is
  S/MIME-protected and it sends no login.
  **At least these still run no revocation guard:** the inbound FTPS poll, the alert SMTP and
  webhook sinks, the AI broker and the LDAPS bind. That list is not the whole set. See
  [DEPLOYMENT.md](docs/DEPLOYMENT.md), *Revocation-guard behavior*.
  ([BACKLOG #2193](docs/BACKLOG.md))
- **A test connection on a REST, SOAP, FHIR or DICOMweb destination now re-checks the hop as a
  send does.** A send re-checks an insecure hop against the instance posture before any byte
  crosses. The test-connection probe did not. Each probe now runs that same check first, before
  any bearer token is minted and before the request is built. A refused probe fails the test
  connection with a `probe refused` error. This is defence in depth. No reachable state was
  found where the probe's check and the build-time check give different answers, because the
  test-connection route builds a fresh connector and probes it at once. (vault BACKLOG #2196)
- **A hop URL that names no host is now refused, in any posture.** Two examples are
  `https:///path` and `https://:443/path`. The loopback rule reads an empty host as on-box, and
  some sites read a missing host as an empty one. On a first deployment such a URL would have
  passed those sites as an on-box hop, though nobody can say what it dials. One shared check now
  reads the host for at least these: the REST, SOAP, FHIR and DICOMweb build-time hop guards,
  their send-time re-checks, the `FhirLookup` read, the HTTP-family trust-anchor lookup and the
  OIDC revocation guards. Each refuses the URL with fixed text that quotes no part of it. No
  attestation or acceptance crosses this refusal: the remedy is to give the URL a host. A Vault
  address with no host is still refused when the Vault client is built, as before.
  **One refusal reads differently.** An `oauth2_token_url` or `smart_token_url` written with no
  scheme, such as `idp.example/token`, was refused with "must be http or https". It is now
  refused with "the URL names no host", because the host is read first. (vault BACKLOG #2207)
- **Two directory audit rows now commit in the same transaction as the change they record.** A
  directory sign-in that changes an account's address writes `auth.ad_profile_email_changed`
  with the address update. An administrator's directory account create writes `user.created`
  with the account insert. Before, each row was a second write after the commit. A crash between
  the two would have kept the change on a first deployment and lost its record. A failed audit
  append now also rolls the change back. The store methods `create_user` and
  `update_user_profile` take `audits=`, a sequence of rows, on all three backends.
  `create_user`'s single `audit=` keyword is gone. (vault `BACKLOG #2221`)
- **The SQL Server store's `[store].ssl_root_cert` pin now takes effect.** The store sent the
  pin as the ODBC `ServerCertificate` keyword beside `Encrypt=yes`. On the ODBC Driver 18.7
  build tested, the pin was enforced with `Encrypt=strict` and was not enforced with
  `Encrypt=yes`, where a pin naming the wrong certificate still connected. So the pin would not
  have pinned anything on a first deployment. With `ssl_root_cert` set, the store now sends
  `Encrypt=strict` with the pin. Strict encryption is TDS 8.0, so the pin needs SQL Server 2022
  or later, the supported floor; an older server refuses the connection rather than taking an
  unenforced pin. Point the setting at the server's own certificate, PEM or DER: the match is
  exact, so a file holding several certificates, or a CA certificate that signs others, is now
  refused at load. Under strict the driver's own expiry check does not apply to a pin match, so
  the store refuses, at each open, a pinned certificate that is expired or not yet valid, and
  `[cert_monitor]` warns ahead of its expiry as `store.ssl_root_cert`. A store opened before the
  pin expires keeps connecting until restart. The pin also takes the trust-anchor ACL and path
  checks: a pin file or folder a broad principal can write refuses under `enforce`. Do not count
  the pin as a revocation control. Unset, the store still sends `Encrypt=yes`, and the escaped
  dev posture is unchanged. The live Linux test of the pin,
  `test_server_certificate_pin_is_enforced_under_strict_encryption`, runs only with
  `MEFOR_TEST_SQLSERVER_STRICT=1` on a strict-configured server. No CI job sets it, so it is
  skipped in CI and the Linux reading is not yet taken. (vault `BACKLOG #2223`; measured under `#3009`)
- **Turning a credential reminder off, or shortening its lead, is now named as a security loosening.**
  `[cert_monitor].warn_days = 0` and `[secret_rotation].warn_days = 0` each turned a reminder off
  with only a debug line. Each is now listed, as `cert_monitor.warn_days` and
  `secret_rotation.warn_days`, in the serve-time warning, `messagefoundry security show` and
  `GET /security/posture`. A lead shorter than the default (`30` and `14` days) is listed too. The
  `[alerts]` recipient gate also counts the secret-rotation reminder now. Before, a config with the
  other two reminders off passed the gate with no recipient while that reminder still ran.
  `security_loosenings()` takes a new required `cert_monitor` argument. (`BACKLOG #2227`)
- **Two hop-policy flags must now be real booleans on a code-first declaration.** They are
  `cleartext_accepted` and `tls_revocation_attested`. The engine read them with a plain truth
  test, and the string `"false"` is truthy. A code-first
  `FhirLookup(cleartext_accepted="false", cleartext_reason=...)` loaded, and the lookup's read hop
  would have crossed as an accepted cleartext hop. `tls_revocation_attested="false"` would have
  counted as attested the same way. On an `inbound()` or `outbound()` the same string loaded and
  was refused only later, at `check` or start, with a message about the reason. Now
  `messagefoundry check`, dry-run and reload refuse a non-boolean value for either flag at load,
  and the error names the key. The third flag, `tls_hop_attested`, was already refused there.
  The settings-driven seams that gate a hop now read all three flags through one strict reader.
  A `FhirLookup`, `DatabaseLookup` or `DatabaseRef` keeps its settings in a mutable dict, and
  `env(..., cast=bool)` written there after the factory would have resolved `"false"` to true. Check,
  start, reload and every reference sync now refuse any of the three flags there that is not a real
  boolean, an `env()` reference included, before the value resolves. The loosening report lists any
  such flag that is not `false`, rather than missing it.
  `connections.toml` already refused a non-boolean, so it is unchanged. (`vault BACKLOG #2232`)
- **Verifying a directory account's passkey now needs the directory to confirm the account.**
  `finish_webauthn_assertion` asks the directory first, with the same lookup `verify_mfa` uses
  (BACKLOG #2023). Before, a passkey marked the factor met with no lookup, so an account disabled
  in the directory would clear the MFA gate with its passkey until the reconciliation pass revoked
  it. A refusal checks no assertion, keeps the challenge, moves no sign count, charges nothing to
  the lockout, and is audited as `auth.webauthn_failed` with `reason=directory_unconfirmed`. It
  fails closed: during a directory outage, or for a row with no directory object id, a directory
  account cannot clear the MFA gate by verifying a passkey either. Registering a passkey also
  marks the factor, and this change does not cover it. See [SECURITY.md](docs/SECURITY.md).
  (`vault BACKLOG #2239`)
- **A directory account demoted in the directory since sign-in can no longer step up with its old
  roles.** `verify_mfa` and `finish_webauthn_assertion` already asked the directory whether the
  account is present and enabled (BACKLOG #2023, #2239). They now also map the account's current
  groups to roles, as the reconciliation pass does, and refuse when a stored role is not among
  them. Before, such an account would renew its step-up window or clear the MFA gate with the old
  roles until the reconciliation pass revoked it. Only a demotion refuses; a promotion does not. A
  role map that fails its seal refuses too, as the `BACKLOG #3082` entry says.
  The refusal writes no roles, checks no code or assertion, charges nothing to the lockout, and is
  audited with `reason=directory_unconfirmed` and the outcome `directory_roles_demoted`. Channel
  scope is not compared. The password re-bind and the enrolment legs make the same role test in
  this release; their own entries say how (`vault BACKLOG #3081`, `#3061`). (`vault BACKLOG #2240`;
  corrected under `vault BACKLOG #3822`, as this entry said those legs did not compare roles.)
- **The password re-bind step-up refuses a directory account demoted in the directory since
  sign-in.** A good re-bind (`POST /me/reauth` and the `/ui/reauth` password leg) returns the
  account's current groups, and the engine judges them with the role test the TOTP, passkey and
  IdP step-up legs use, on the stored roles it reads after the bind returns. Before, such an
  account would renew its step-up window with the old roles until the reconciliation pass revoked
  it. The refusals are audited on the `auth.reauth` row, at least these:
  `reason=directory_roles_demoted` for a lost role; `reason=directory_identity_conflict` when the
  row's directory object id or provider moved during the bind, because the groups vouch only for
  the object the bind was keyed on; and `reason=directory_role_map_unsealed` when the AD
  group-to-role map fails its seal, for an account that holds a role. The password was right in
  each of these cases, so none of them is charged to the lockout or to the session's re-proof
  budget, and none clears either. `directory_identity_conflict` also marks an older, uncharged
  refusal, where the directory answered about another object than the row's, so the bind cannot
  vouch for this account whether or not it accepted the password (`vault BACKLOG #2027`).
  The per-actor step-up attempt budget is still drawn. None renews the window, mints an
  action-bound grant or writes roles. Each is a **403** on `POST /me/reauth`, with the per-fix text
  the `BACKLOG #3082` entry describes: a demotion is told to sign out and sign in again. Channel
  scope is not compared. See [SECURITY.md](docs/SECURITY.md).
  (`vault BACKLOG #3081`; added under `vault BACKLOG #3822`, after the 0.5.2 release notes were
  published without it.)
- **One account whose directory probe raises no longer ends the reconcile pass.** In v0.5.1 a
  probe that raised something other than an LDAP error ended the whole pass, so it stopped
  revocation for every account. Step-up also returned an error, not an audited refusal. The rest
  of the pass now runs, and step-up refuses that account. The `BACKLOG #3100` entry says how such
  a probe is read and paged. (`BACKLOG #2241`)
- **Plain `anonymize()` now refuses a line no rule can reach.** A line whose first field is not a
  segment id, such as a wrapped name or note, used to pass through plain `anonymize()` untouched.
  Only `anonymize_checked` refused it. The refusal now sits in the shared `normalized_message`,
  so both entry points raise the same body-free `AnonError`, on the engine and on the tee.
  `anonymize_checked` therefore raises `AnonError` for such a line, where it raised `LeakError`,
  and builds no coverage report for that message. At least these inputs that plain `anonymize()`
  used to emit are now refused: a bare three-character line that is not a segment id of the
  message's HL7 version, including an id from a later version than MSH-12 names (a bare `SFT` in
  a 2.3 message); a bare Z-segment id that no rewriting rule names; and a bare `BHS` or `FHS`
  line. Add the trailing field separator to a bare line that is not a header to get it through.
  (`BACKLOG #2246`)
- **A loopback bind that trusts a proxy now counts as exposed.** `serve` read an instance as exposed
  only for an off-loopback bind or a declared `[api].tls_terminated_upstream`. A loopback bind with
  `[api].trusted_proxies` set and an operator `[api].tls_cert_file`, which is a proxy re-encrypting to
  the engine, counted as unexposed to the arms named below. Its admin API would have reached the network
  on first deployment with no MFA-at-exposure refusal looking. The console degrade and advisories
  already counted it (vault `BACKLOG #2218`). Now at least these arms use that rule too, and on that shape:
  the MFA-at-exposure arm refuses under `enforcement = "enforce"` with `[security].require_mfa = false`
  unless `[security].allow_single_factor_admin_when_exposed` is set, and its message names
  `[api].trusted_proxies`; the dual-control advisory warns when `[approvals].enabled` is off; the
  in-use data protection arm (ADR 0152) warns when nothing is declared, and refuses when
  `[security].require_memory_encryption_declaration` is set; and the undeclared-proxy warning no
  longer prints, because the MFA arm covers the case. Not every arm reads that rule: at least the
  ASVS 12.1.1 TLS-floor probe still runs only behind a declared terminator, as
  [CONFIGURATION.md](docs/CONFIGURATION.md) says where it describes that probe. A config of that
  shape that starts today is
  refused under `enforce` when it also sets `require_mfa = false`, or sets that memory opt-in with no
  declaration. See [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). (vault `BACKLOG #2251`)
- **Saving a legacy directory scope over the JSON API now needs `expected_source: "ad"`.** An AD
  account's channel scope stored before the source column (#1927) has a null source, and the login
  sync withdraws it like a directory scope. `PUT /users/{id}/channel-scope` used to save it with no
  `expected_source` and mark it manual, which pinned a scope the sync would otherwise withdraw; it
  now answers **409** there, and accepts `"ad"`, which it used to refuse. A local account, an
  account with no stored scope, and a scope with a recorded writer behave as before. The GET still
  reports the null source. The web console already asked for the tick in this case and now sends
  `"ad"` with it. See [SECURITY.md](docs/SECURITY.md). (`vault BACKLOG #2252`)
- **An ungated config reload proves the audit log works before it swaps the graph.** When dual
  control did not hold a reload, nothing was written before the swap, and the `config_reload` row
  came after it. An audit log that refused writes would have let the new config go live with no
  record of it, only a degraded `audit` step on the answer. `POST /config/reload` now writes a
  `config_reload_attempted` row first, naming the requester and the requested directory. If the
  audit log refuses it, the route answers `503`, loads and swaps nothing, and raises an
  `audit_write_failed` alert keyed `config_reload:inline`. A dry run and a released reload write
  no such row: a dry run swaps nothing, and the gate's `approval.release_attempted` row already
  comes before a release. (`vault BACKLOG #2254`)
- **A config reload's audit row names the config that reload loaded, even when a second reload
  overlaps it.** The `config_reload` row is written after the swap, and the row read the engine's
  live state then. A second reload could swap the graph again in between, so the first reload's
  row named the second one's directory, connection counts and digest. The row from
  `POST /config/reload` and from a released reload is now built from that reload's own result,
  including the digest it took before its swap. When a later reload or a connection flag toggle
  has moved the engine on by the time the row is written, the row is marked `superseded` and
  `baseline_unchecked`, so the next start does not compare its config against it. A cluster
  convergence reload's row still reads live state. (`vault BACKLOG #2257`)
- **The tee anonymizer now applies a rule that names an MSH field.** It used to skip every MSH
  rule. Its leak-check still counted the field of such a rule on a later MSH line as scrubbed. So
  a dashed SSN in a second MSH line's field, named by a `drop` in `anon.toml`, would have stayed in
  the output of `python -m tee anonymize-captures`. The check would have passed it. The engine
  anonymizer already applied the rule. The tee now rewrites the field on each MSH line, the header
  included, as the engine does. No default rule names an MSH field, so output changes only for an
  overlay that maps one.
  **Breaking for such an overlay:** both anonymizers now refuse a rule that would rewrite `MSH-1`
  or `MSH-2`, which hold the message's delimiters. They also refuse a rule for field 0 of any
  segment, which is the segment id. Before, the tee ignored an MSH rule and blanked a segment id
  for a field 0 rule, and the engine could emit a header with no readable delimiters. A `keep` on
  `MSH-1` or `MSH-2` is still allowed.
  **This does not make the two anonymizers agree on every input.** [PHI.md](docs/PHI.md)
  section 9 names at least three cases that still differ: a `BHS` or `FHS` line, a short later
  header line, and a header not in capitals. (`vault BACKLOG #2265`)
- **An `anon.toml` keep that turns off a default scrub now says so.** A keep records a field as
  reviewed, and it also cancels any default scrub on that field. So a keep on `PID-5` would have
  left the patient name in the dataset on a first use, with no notice. `load_rules` now logs one WARNING line for each such field,
  but not on every load in the same process. The line names the field and the kind of scrub it
  lost, never a value. A keep on a field with no default rule logs nothing.
  `kept_defaults` in `anon/rules.py` returns the same list for a caller that wants to show it.
  (vault BACKLOG #2268)
- **A trust anchor that names an encryption header now refuses.** A `Proc-Type:` or `DEK-Info:`
  header name, in any case, anywhere after the first `-----BEGIN ` of the text the engine would
  load, refuses before the TLS library sees that text, whether or not it sits inside a block. A
  comment line that is not ASCII is dropped before the check. This holds at least for the `[api]`
  and `[auth]` anchor files and an inbound listener's `tls_ca_file`, at start and at every reload
  that is not a dry run. A CA the engine hands to its hop by path, such as an outbound
  connection's or an `Ftp` poller's `tls_ca_file`, does not get this check. A private key encrypted
  in the legacy header format refuses with it. A PKCS#8 `ENCRYPTED PRIVATE KEY` block has no such
  header and still loads. On an encrypted certificate block the library could otherwise wait for a
  password, so a start or reload could hang. (`BACKLOG #2270`)
- **A refused channel-scope save now leaves an audit row.** `PUT /users/{id}/channel-scope`
  answers 409 when a save would take over a directory scope without `expected_source: "ad"`, when
  `expected_source` does not match the owner, or when the owner changed mid-write, at least through
  a directory sign-in or another administrator's save. Only a
  successful save was audited, so a refused takeover left no trace. Each 409 now writes one
  `user.channel_scope_change_refused` row naming the administrator, the account and the conflict,
  never the scope. A store that refuses that row logs an ERROR instead, and the 409 stands (vault
  BACKLOG #2271).
- **`provision-admin` refuses to complete an existing roleless account that already holds a
  notification address unless `--email` is given.** Before, the repair kept that address and
  warned, so on a first deployment the new sole Administrator's security notices would have
  gone to an address nobody chose, possibly the earlier holder's. The refusal comes before the
  password prompt and writes nothing. Giving the address the account already holds is
  allowed. (vault BACKLOG #2288)
- **A session whose temporary password has lapsed is ended, and can no longer finish the second
  factor.** An administrator-issued password stops signing in at its deadline
  (`[auth].initial_password_expiry_hours`). A session opened a second before that deadline used to
  outlive it, and could still complete `POST /auth/mfa-verify` or the console's `/ui/mfa` page,
  which re-keyed the session and cleared the account's failed-code count. Now the engine ends that
  session the first time it is presented after the deadline, under every route, and audits
  `auth.temp_password_expired` with `"at": "session"`. A code check that waits past the deadline
  in the account's queue is refused too, with `"at": "mfa_verify"`, and no sign-in ceremony
  re-keys a session once its temporary password has lapsed. Such a session now gets 401 from
  `POST /me/password` as well, where it used to get that route's 403. (`BACKLOG #2298`)
- **`POST /me/password` ends the session when it refuses a lapsed temporary password.** The route
  still answers 403 "your temporary password has expired" when the deadline passes during the
  request, and now ends the session too, so a retry gets 401 and writes no second
  `auth.temp_password_expired` row. (`BACKLOG #2298`)
- **docs/SECURITY.md now describes the session-level refusal of a lapsed temporary password**
  that vault BACKLOG #2298 built: the session is ended with a generic 401, audited
  `auth.temp_password_expired` with `"at": "session"`. (vault BACKLOG #2298)
- **An unreadable `anon.toml` is refused without carrying the file.** `load_rules` raised its
  `RuleError` from inside the handler, so on Python 3.14 the whole overlay rode the chained
  `TOMLDecodeError`. An overlay that was not UTF-8 raised a bare `UnicodeDecodeError` holding the
  file's bytes, and one nested past the parser raised a bare `RecursionError`. Those, and a
  bare `ValueError` for a number past the digit limit, are now a
  `RuleError` with no chained exception. It names the file and, for bad TOML, the line and column.
  The reason no longer repeats the parser's own text. Both copies of the loader changed, the
  engine's and the tee's. (vault BACKLOG #2310)
- **An mTLS certificate identity for a directory account now asks the directory on every request.**
  `identity_for_cert_user_id` used to read only the engine row. The reconciliation pass probes only
  accounts that hold a live session, and a certificate caller holds none, so a directory-side
  disable or group removal would never have reached a certificate mapped to a directory account.
  The path now uses the same probe and refusals as directory step-up and fails closed: absent,
  disabled, undetermined, unavailable, referred, no directory wired, and a row with no
  `directory_object_id` all grant no identity. Roles and channel scope narrow to what the
  account's current groups still map to, within what the row holds, so an account removed from one
  of two mapped groups keeps the other role. One exception: when none of the account's groups is
  in the scope map, a channel scope an administrator set stays as stored. Nothing is written. At
  most 8 such probes run at once, and a request that gets no slot within 2 seconds is refused. A
  directory outage logs one WARNING and its end one INFO, not a line per request. An outage that
  starts within a minute of the last WARNING logs its own on its first refusal after that minute,
  and a change of reason during a logged outage logs one INFO. An engine fault raised past the
  directory layer's own catch is refused as `probe_fault`, not `unavailable`. When an account's
  probe starts to fault, it logs one WARNING that names the exception type. One account's
  WARNINGs are at least a minute apart, and other faults log at DEBUG. A fault a minute or more
  after the last WARNING warns again, a repeat included. When this engine process sees an account
  disabled, deleted, re-enabled or moved off the directory, the account starts afresh, and its
  next fault warns at once, even inside the minute. A fault the directory layer raises still
  reads as `unavailable` (`vault BACKLOG #3115`). ADR 0083 Amendment 3 records the change.
  (`vault BACKLOG #2316`)
- **A Vault hop refusal now reaches the operator in its own words, and it is one type at both
  phases.** The Vault KV secret provider, the store key provider and the Transit cipher used to
  shrink a refusal raised while sending, such as an `http://` Vault behind an `https://` proxy or a
  misframed reply, to a bare type name like `EgressReplyError`. They now keep the refusal's fixed
  text, which names no address, proxy URL, token or reply byte. Every other failure still gives
  its type name only. A refusal of the hop itself is now `InsecureHopRefused` whether it fires
  when the client is built or before a send; a refusal of the reply stays an `EgressReplyError`.
  The shared engine client (`messagefoundry.apiclient`) no longer sends through a proxy named by
  `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` or the system proxy settings. The configuration guide now
  says why the TLS leg to an `https://` proxy shares the Vault CA file, and why the proxy's CA must
  not be added to it. (`vault BACKLOG #2318`)
- **A blank `acr` or `amr` setting no longer counts as MFA.** `[auth].oidc_mfa_amr_values` and
  `oidc_required_acr_values` lost blank entries only when set as an env string. A TOML list such as
  `[""]` passed the load guard. The claim gate then accepted a token with an empty `acr`, or an
  empty `amr` value, as MFA. On a first deployment with OIDC on, a site that wrote a blank entry
  would have signed such a token in as MFA-verified. Both lists now lose blank entries in every
  form, and a list left empty with the gate on is refused at load. The gate also ignores a blank
  configured value. A whitespace-only `oidc_acr_values` now loads as no request and is not sent.
  Load also refuses an `oidc_acr_values` request while `oidc_require_mfa_claim` is off, since the
  gate reads no `acr` then. The `messagefoundry check` note on an unrequested required `acr` no
  longer says it refuses a login while a matching `amr` still admits one. (BACKLOG #2325)
- **The anonymizer's default rules now map eight more date fields.** `AIS-4`, `RXA-3`, `RXA-4`,
  `PR1-5` and `FT1-4` take the `date` kind, which keeps the year only. `GT1-8`, `IN1-18` and
  `NK1-16` are dates of birth and take the `dob` kind, like `PID-7`. Before, each of them left the
  anonymizer unchanged. A date field outside the list in
  [PHI.md](docs/PHI.md) section 9 still has no rule. (`BACKLOG #2330`)
- **A `FieldRule` built in code now has its path checked.** A path that is not a whole-field
  address, such as `pid-29` or `PID-29.1`, raises `RuleError` when the rule is built. Before,
  `pid-29` scrubbed nothing and said nothing, and `PID-29.1` raised a raw `ValueError` inside the
  tee on the first message. The check also refuses `PID-0`, a leading zero and a non-ASCII digit,
  for an `anon.toml` key as well. (`BACKLOG #2330`)
- **A date-typed `OBX-5` is now treated as a date.** A result whose `OBX-2` type is `DT` or `TS`
  keeps its year only, and a value under that label that is not a valid timestamp is scrubbed to
  empty. Before, the `OBX-5` allowlist kept the whole value. `NM`, `SN` and `TM` values are
  kept as before. (`BACKLOG #2330`)
- **The site-code pass no longer rewrites a filled date.** With a site-code prefix of `19` or `20`
  configured, a `YYYYMM` date has the shape of a site code. The pass replaced it with a salted
  number, which was not a date and did not match across datasets. The pass and the leak-check's
  site-code test now skip a field the `date` kind filled, and only while its value is what that
  kind writes. (`BACKLOG #2330`)
- **A date scrubbed to empty now leaves a record.** The `date` kind empties a value that is not a
  valid HL7 timestamp, and nothing said so. `anonymize_checked` now lists each such field, by
  address and never by value, in `LeakReport.blanked_fields`, and the
  `python -m tee anonymize-captures` run summary counts them. `anonymize` takes an optional
  `blanked` list for the same record. (`BACKLOG #2330`)
- **A six-digit date that reads two ways is now scrubbed to empty.** `201107` is July 2011 as
  `YYYYMM` and 7 November 2020 as `YYMMDD`. The `date` kind read it the first way and kept
  `2011`, which is the real year and month of the second reading. A true `YYYYMM` whose year ends
  in `01` to `12` is emptied too, and each emptied field is recorded. (`BACKLOG #2330`)
- **The `dob` kind keeps only a time after the date.** It used to keep everything after the eighth
  character, so a name or a second identifier that followed a date of birth left unchanged. It
  now keeps hours, minutes, seconds, a fraction and an offset, and drops anything else. This
  applies to `PID-7` as well as to the three dates of birth mapped above. (`BACKLOG #2330`)
- **A JSON caller can read an account's federated binding before it changes it.** The new
  `GET /users/{id}/federated-identity` returns the stored issuer and subject, the pair a bind or
  unbind must send back as `expected_issuer`/`expected_subject`. It needs `users:manage` and no
  step-up, like the channel-scope read, so reading spends no grant. Before it, a JSON caller
  guessed and spent a grant on each wrong guess. A bind or unbind refused because the pair changed
  now writes an audit row, `auth.federated_bind_refused` or the new
  `auth.federated_unbind_refused`, with reason `federated_binding_changed`. A bind on an account
  deleted while it ran now answers 404, not 409. `[auth].oidc_issuer` is refused at load beyond
  256 UTF-16 units, the narrowest issuer column, and `expected_issuer` is capped at 256 characters
  to match. See [SECURITY.md](docs/SECURITY.md). (`BACKLOG #2331`)
- **A vault_transit store now needs a recorded attestation of its AES-GCM bound to start under
  enforce.** The engine counts no encryptions on that cipher, so `messagefoundry store
  attest-transit-bound --reason` records who vouched for the Transit data key's rotation, and
  when, in a store row with its audit row in the same transaction. The row names that audit row,
  and a row the audit chain does not back counts as none, so DML on the table alone forges
  nothing. `serve` refuses to start under `[security].enforcement = enforce` when no row names the
  configured key, and warns under `warn`. `messagefoundry store withdraw-transit-bound` removes
  it, audited. `GET /security/posture` reports it. See [SECURITY.md](docs/SECURITY.md).
  (`BACKLOG #2337`)
- **On vault_transit, rotating the Transit audit key no longer reads as audit-chain tampering.**
  The chain walk and the attestation check recompute each row's MAC under the Transit key version
  that row's stored hash names, rather than the key's latest version. A row can name a version
  Transit refuses while it still answers under the latest. That row is now a chain break, and the
  walk goes on. `audit-verify` names the row. With `[integrity].audit_verify_on_start` on, the
  startup check raises its `audit-chain` alert. Other Transit failures, an outage among them, still
  read as a check that could not run. (`BACKLOG #2337`)
- **The anonymizer's leak check now loads the publish guard from one fixed path.** Both
  `leak.py` copies load `scripts/security/scan_forbidden.py` by path and run it. Each used to try
  every folder above its own file and run the first match. From an installed wheel that search
  would have gone past the install folder. On a first deployment, a file planted at that path in
  a folder above would have run inside the process calling the leak check. Each loader now builds
  a single path, under the folder that holds its package, and searches no other folder. In a
  source checkout that folder is the repository root, as before. With no scanner there, the
  engine's leak check still refuses to run, and the standalone tee's token tables still load
  empty. (vault BACKLOG #2344)
- **`messagefoundry check` reads an instance declared in the environment alone.** With no
  `messagefoundry.toml`, six of the seven legs that read service settings skipped before reading a
  single `MEFOR_*` variable, and `static-credentials` reported the graph only. So a site configured
  by environment alone would have passed a gate that read nothing. When `MEFOR_AI_ENVIRONMENT` names
  the instance, the `posture`, `build-check`, `reference-backend` and `upstream-hop-ack` legs and the
  `oidc-auth-params`, `static-credentials` and `alert-smtp-tls` advisories now read the settings
  from the environment, and say "settings from environment only" on their line. The dry-run preview
  reads `snapshot_on_send` the same way. At least these cases keep the skip. One is a
  `--service-config` that names a missing file, where `serve` would refuse to start. Another is
  `--project-root` with no `--service-config`, no file under the root or the config directory,
  and a `messagefoundry.toml` in a working directory that is not the root. `serve --project-root`
  started there reads that file, and `check` cannot tell where `serve` starts. So the line now
  names the file instead. A third is no file and no `MEFOR_AI_ENVIRONMENT`. Other `MEFOR_*`
  variables alone, such as a store key in a dev shell, keep the bare-directory skip. `serve`
  refuses to start without an active environment. A site that names its environment only with
  `serve --env` also keeps the skip, because `check --env` does not reach the settings legs.
  (vault `BACKLOG #2355`)
- **The off-box log collector is now an `[egress]` destination.** `[logging].forward_host` named an
  outbound destination that no `[egress]` list governed. The new `[egress].allowed_syslog` list
  takes `host` or `host:port` entries, like `allowed_tcp`, and follows the same empty-list rule:
  under the deny default a configured collector that is not listed is refused, and under
  `[security].block_unlisted_outbound = false` an empty list is unrestricted. `serve` and
  `supervise` check it at start, before the forwarder opens a socket, and exit 2 on a refusal.
  **Breaking:** an instance that forwards its logs must now list its collector, for example
  `allowed_syslog = ["siem.hospital.local:6514"]` or `MEFOR_EGRESS_ALLOWED_SYSLOG`. See
  [CONFIGURATION.md](docs/CONFIGURATION.md#egress). (`BACKLOG #2356`)
- **The engine-shard supervisor now forwards its own log records off-box.** `supervise` used to
  log to stdout only, so an engine shard crash loop left no copy off the host. With
  `[logging].forward_host` set, the supervisor process now installs the same syslog forwarder each
  engine shard does. It passes the same forwarding start gates as `serve` and refuses to start
  the fleet on those refusals, with the same messages. It does not run every `serve` gate, and a
  refusal it prints to stderr is still not forwarded. Its spool is a `supervisor` directory
  beside its engine shards' spool directories. With no collector configured it installs no
  forwarder. Under the default `enforce` it then refuses the fleet at once, where each engine
  shard used to refuse on its own; under `warn` it prints the warning and starts.
  `supervise` now also runs, in `serve`'s words, settings checks each engine shard makes.
  At least these refuse the fleet: no environment named, an `--env` name the settings
  refuse, a custom environment with no production tier, the SQL Server backend without its
  driver, and `[logging].level = "DEBUG"` on a production instance. At least these refuse
  under `enforce` and warn under `warn`: `[store].require_managed_identity`, the
  service-settings half of `[security].require_nonstatic_credentials`, and the open-egress
  gate.
  (`BACKLOG #2356`)
- **A trust-anchor refusal and its log lines now quote the anchor path with `repr`.** A newline or
  an escape byte in a configured anchor path, or in a folder on its way, used to reach the refusal
  text and the log raw, so one refusal could print as two lines. The suggested fix commands keep
  their own shell quoting, which does not escape such a byte. A Windows path now prints with
  doubled backslashes, as the pin-mismatch refusal already did. (`BACKLOG #2358`)
- **A connection's own keep-forever retention override now needs the audited acknowledgement.**
  An inbound `messages_days = 0` or an outbound `dead_letter_days = 0` keeps that connection's
  PHI bodies forever, and no gate read it. `serve` now checks it at least at startup and on every config reload. Without
  `[security].allow_keeping_phi_indefinitely = true`, an enforcing engine refuses the graph at
  startup and on reload, and `messagefoundry connection upsert` and `remove` refuse the edit.
  Under `enforcement = warn` it warns. With the acknowledgement it writes a WARNING-level
  `AUDIT:` line naming each connection. That switch covers the whole instance, so read
  *Per-connection overrides* in [CONFIGURATION.md](docs/CONFIGURATION.md#retention) before
  setting it. (`BACKLOG #2368`)
- **Per-connection `tls_ca_file` follow-ups.** A blank `env()` value for `tls_ca_file` is now
  refused when it resolves. The error names the setting, the connection and the environment key.
  Before, a blank value read as unset, so the hop would have run with no pin. A CA file that
  cannot be read now raises `CaFileUnreadable` on the verifying paths the runner builds. It names
  the setting, and the connection where the build knows it. It is both a `ValueError` and an
  `OSError`, and its text carries no path. Before, it was a bare `FileNotFoundError`. The inbound
  FTPS poller now reads the instance `[tls]` block, as the FTPS upload does. So
  `internal_ca_file`, `trust_anchor_mode` and `crl_file` reach it, and a pinned mode or a CRL must
  suit its partner. Its warnings now name it `inbound:<name>`. The token hop still shares the data
  hop's `tls_ca_file`, as
  [CONNECTIONS.md](docs/CONNECTIONS.md#pinning-a-private-ca-per-connection-tls_ca_file) says.
  (`BACKLOG #2370`)
- **The `tls_ca_file` of each connection that dials out is now checked.** It gets the checks an
  inbound listener's CA already had: every outbound that takes the key, an inbound `Ftp()` poller
  and a `FhirLookup()`. Every factory that takes `tls_ca_file` for an outbound hop now also takes an
  optional `tls_ca_pin`, the file's SHA-256. A pin that does not match is refused, naming the
  setting: `outbound connection '<name>' tls_ca_file`, `inbound connection '<name>'` for an
  `Ftp()` poller, or `fhir lookup '<name>'`. Under `[security].enforcement = enforce`, a file
  another account could replace, or one whose permissions the engine cannot read, is refused too. A
  changed file writes an `auth.trust_anchor` audit row under `outbound:<name>`,
  `fhir_lookup:<name>` for a `FhirLookup()`, or `inbound:<name>` for an `Ftp()` poller. Before
  this, whoever could replace the file would have chosen which CA the hop trusts, with no record
  of it.
- **Where a refusal lands follows ADR 0031.** At start, a refused outbound or `Ftp()` poller CA
  fails that connection only, and the rest of the graph comes up. An operator start of a lane, such
  as one with `auto_start = false`, checks it too. A `FhirLookup()` CA still refuses the start, and
  a reload is refused by a CA on a lane it builds or keeps running. An idle lane's CA, such as
  one DR-parked or not started, gets no pin, permission or path check at a reload. A file
  an `MLLP()`, `Ftp()`, `Email()` or `Direct()` build cannot load still refuses the reload. A lane its CA failed stays failed
  across a reload until its config changes, an operator starts it or the engine restarts. The ADR now also records that an inbound listener's refused CA
  refuses the start, as it has since BACKLOG #1142 slice 3.
- **A pin nothing would check is refused at load.** That includes a pin that is not 64 hex
  characters, and one beside a CA the hop never reads: `use_tls` or `tls_verify` off, or on the HTTP
  family `verify_tls` off or an `http://` url with no token hop, or `ech_egress` through an
  `http://` sidecar. Such a CA is not checked. A connection test checks the CA before it dials.
  `Email()` and `Direct()` now refuse a blank `tls_ca_file`.
- One gap remains: the hop still reads the file again by path when it is built, after the check.
  So a matching pin is no escape for a file whose permissions cannot be read, and a file swapped
  after a build stays trusted until that connection is built again. An outbound `MLLP()` or
  `DICOM()` with `tls = true` and a `tls_ca_file` now accepts `tls_ca_pin` instead of refusing it.
  [CONNECTIONS.md](docs/CONNECTIONS.md#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin)
  has the details. (`BACKLOG #2371`)
- **A credential reply is served `Cache-Control: no-store` by its response model, not by a step
  each route had to declare.** A session token, a TOTP seed, recovery codes and a temporary
  password are returned in models that subclass `CredentialReply`, and the engine adds the
  no-store step to every route that returns one. A test fails when a model with a credential field
  name is not marked. `docs/PHI.md` now rates the connection test's `detail` text PL-4, operational
  metadata. (BACKLOG #2372)
- **The log-forwarding start gate now refuses a collector that is this host.** The ASVS 16.4.3 gate
  refused a loopback `[logging].forward_host` only, so the engine's own LAN address passed. It now
  also refuses the host's own OS name and an IP literal that is one of its own addresses. The check
  sends no packet and resolves no name. When the local read fails it logs a WARNING and passes. An
  alias that resolves to this host still passes. A virtual address that the routing table treats
  as local is refused even when another system answers on it. `serve` writes the WARNING to stderr
  and again, as an ordinary WARNING that `[logging].level` applies to, through the configured
  log handlers. The gate compares the host in the form the
  network layer will dial, so loopback typed in full-width digits no longer passes it.
  `[logging].forward_host` now also refuses, at load, a control character, an undecodable byte,
  and a host name the network layer cannot encode (at least an empty label or an over-long one);
  such a name used to stop the start with a traceback. `[logging].ntp_peer` refuses a control
  character, an undecodable byte and non-ASCII text that cannot be encoded, for the same reason.
  See
  [ADR 0200](docs/adr/0200-on-disk-log-spool-behind-the-off-box-forwarder-and-a-config-keyed-forwarding-start-gate.md),
  Amendment A. (`vault BACKLOG #2375`)
- **A security notice the relay loses now leaves an audit row.** Before, a full notifier queue
  or a failed SMTP send left only a WARNING line. A lost lock notice left nothing at all. On a
  first deployment, the audit trail could not have said which account was never told. Now each
  such notice writes `auth.security_notice_undelivered`, with the recipient as the actor. Its
  detail names the notice kind and the `reason`, `queue_full` or `send_failed`. A lock notice
  writes `auth.lock_notice_undelivered` instead. A reader without `users:manage` does not see that
  row, as with the other lock rows. No row carries the address, the notice's own detail, or the
  error. (BACKLOG #2383)
- **`[api].expose_docs = true` is now a named loosening.** It serves at least `/docs`, `/redoc`
  and `/openapi.json` with no sign-in, and nothing reported it. `messagefoundry security show`,
  `GET /security/posture` and the serve-time warning now name it. The posture route reads it from
  the running app, so an embedder that passes `expose_docs=True` to `create_app` is reported too.
  A test floor now holds every `[api]` boolean to being named or exempt with a reason. See
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). (`vault BACKLOG #2385`)
- **The attachment download's two 422 refusals are now audited.** `GET /messages/{id}/attachments/{id}` refuses
  with HTTP 422 an SVG it cannot sanitize, or a stored value that will not decode, and serves
  nothing. The SVG refusal wrote only a log line and the undecodable one wrote nothing, so on a
  first deployment a refused attempt to fetch a crafted SVG would have left nothing in the
  tamper-evident audit chain. Both now log a content-free WARNING and write one
  `attachment_download_refused` row with the acting user, the channel, the message and attachment
  ids, and a `reason` of `svg_unsanitizable` or `undecodable`. The row never carries a byte of the
  document. A successful download is audited as before. The row is written after the refusal's
  error handling ends, and the SVG refusal no longer keeps the parser's error, which can quote an
  entity name, a system id or an encoding label from the file. So a store fault on the row is a
  500 whose traceback carries none of that text. (vault BACKLOG #2387)
- **An identity provider that signs people in with no prompt can be exempted from the OIDC callback
  floor by `amr`.** Such a provider, using integrated Windows sign-in or a client certificate,
  answers a step-up faster than `[auth].oidc_callback_min_elapsed_seconds` on every try. A site using
  one would have had to turn the floor off for everyone. The new
  `[auth].oidc_callback_floor_exempt_amr` lists the `amr` values that mark such a sign-in. A sign-in
  or step-up callback whose signature-verified `amr` names one skips the floor, and every other
  callback keeps it. The list is empty by default, and the step-up floor then refuses before the
  code exchange, as before. While OIDC and the floor are on, any value listed is named by
  `messagefoundry security show` as a loosening, since it proves a device answered, not that a
  person acted. While the claim gate is on, a value `oidc_mfa_amr_values` also accepts is refused
  at load. Each exempted pass records the matched values as `callback_floor_exempt_amr` on its
  success audit row. While the MFA claim gate is on, the token must still pass it by another `amr`
  or an `acr`.
  (BACKLOG #2388)
- **The docs now say which database driver key the engine checks.** On a generic `Database(...)`,
  the engine checks the wrap of the key `odbc_params` names with `sslkey`, and only for a driver
  that reads that keyword. psqlODBC takes a client key only through `pqopt`, which was already
  refused; a test now pins that. So on psqlODBC, libpq finds the key on its own, through at least
  `PGSSLKEY`, a service file or its default file, and no key is checked.
  [CONNECTIONS.md](docs/CONNECTIONS.md#encrypted-private-keys-must-meet-the-wrap-floor) now says
  so. The SFTP client no longer keeps the `key_password` it refuses, and the rotation inventory
  marks that setting as refused. (vault `BACKLOG #2423`)
- **The session reconciler no longer asks the directory about an id-less row by its name.** A
  name probe could read another account's entry and write that account's roles onto the row. A
  directory row with no `objectGUID` and no federated binding is now judged without a lookup: it
  gets no roles written, and its sessions end at the strike threshold with the reason
  `directory_object_id_missing`, as an absent account's do. It never moves the ADR 0195 hold. No
  sign-in or step-up admits such a row, so a session it holds is anomalous. The count on the
  outage's `auth.ad_reconcile_skipped` audit row is now the `asked` field, the lookups the pass
  sent, and it leaves such a row out. It was the `probed` field.
- **An empty password on the AD step-up re-bind is no longer counted as a wrong guess.** It is
  refused before the directory is asked, charged to neither the account lockout nor the session's
  re-proof budget, and audited on `auth.reauth` as `empty_password`. The caller sees a refused
  password. A local account's empty re-auth password is still checked and counted as before.
- **The step-up re-bind tells a disabled directory account from an absent one.**
  `LdapAuthenticator.authenticate` now returns what its lookup found, so the re-bind makes no
  second directory read and audits `directory_disabled` or `directory_undetermined` apart from
  `not_in_directory`. None of them is counted, and no client sees the difference. (`vault BACKLOG
  #2434`)
- **A reader whose permissions withhold audit rows is told so, and an OIDC-only auditor can
  export.** A reader without `users:manage`, such as the built-in Auditor, does not see the
  account-lock rows (BACKLOG #1131), and nothing said so. `GET /audit` now returns
  `withheld: true` for such a reader, and `GET /audit/export` sends `X-Audit-Withheld: true` and
  records `withheld` in its `audit.export` row. Each is decided by the permission alone, never by
  whether a hidden row is in range, so it cannot say a lock happened. `GET /audit/export` reads
  only a bearer token, which an account signing in only through OIDC never holds, so such an
  auditor had no export at all. The web console's new `GET /ui/audit/export` streams the same
  export from the console session under `audit:export`. See
  [SECURITY.md](docs/SECURITY.md). (`BACKLOG #2446`)
- **The engine API refuses a request that carries more than one `Authorization` header.** Starlette
  reads the first of two such headers, while a proxy in front may read the last, so the two would
  have judged different credentials. On a first deployment behind such a proxy, that gap would have
  been open. Every read of the header now goes through one check: a gated route, `POST
  /auth/negotiate` and `GET /ui/sso` answer `400`, and the `/ws/stats` handshake is refused. The
  rule matches the one the `Http()` intake listener already applies (BACKLOG #2051). The web
  console treats its session cookie the same way: two or more copies, identical or not, get `400`.
  Each refusal writes a WARNING log line and, within a rate budget of its own, an
  `auth.repeated_credential` audit row. Neither records the header or cookie value. (BACKLOG #2454)
- **`cert import` takes an empty PKCS#12 passphrase when `MEFOR_PFX_PASSWORD` is set to the empty
  string.** Before, empty read as unset, so a bundle whose PBMAC1 MAC used an empty passphrase could
  not be imported. The bundle must still meet every floor; unset still means no passphrase. A
  refused bundle with clear bags now says the problem, then that it is refused, then the routes,
  and the no-MAC route now says such a file has no integrity check. A MAC this engine cannot read
  is named as the MAC, not as the whole bundle. See
  [CONNECTIONS.md](docs/CONNECTIONS.md#encrypted-private-keys-must-meet-the-wrap-floor).
  (vault `BACKLOG #2456`)
- **BREAKING: `[api].trusted_proxies` refuses a CIDR with host bits set, such as `10.0.0.1/24`.**
  The load used to accept one. uvicorn parses each CIDR strictly, so it would have matched no
  peer. Every client behind that proxy would then have shown as the proxy's own address. The error
  names the single address, then the network the entry spans. The env form
  `MEFOR_API_TRUSTED_PROXIES` meets the same check. (`BACKLOG #2488`)
- **A shortened dual-control dwell is now named as a security loosening.** This applies while
  `[approvals].enabled` is on and holds at least one operation. A `min_dwell_seconds` below its
  default of `2.0` s, or `0`, is named. So is an `expiry_hours` above its default of `72`, or `0`.
  The serve-time warning, `messagefoundry security show` and `GET /security/posture` all list them.
  Before this, an operator could cut the floor to nothing and nothing said so. Dual control ships
  off, so a default instance names nothing new. [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md)
  says what each value gives up. `security_loosenings()` takes a new required `approvals` argument.
  (`BACKLOG #2489`)
- **An alert rule's `control_action` no longer restarts a connection on an event that is not about
  one.** Two emitters raise `connection_stopped` for something that is not a connection: a
  reference set that fails to sync (`reference:<name>`) and a cluster node whose transform-state
  cache fails to converge. The second used the key `transform-state`, which fits the
  connection-name rule. On a first deployment, a valid rule on `connection_stopped` would have run
  `restart_inbound("transform-state")`, and a rule with `control_target` set would have restarted
  that connection whenever a reference set failed to sync. The notifier now skips the action,
  logged, for any event whose `connection` key is not a connection name, even when the rule sets
  `control_target`. The convergence alert now carries `cluster:transform-state`. The notification
  itself still fires. (vault BACKLOG #2527)
- **An alert rule with no `control_target` no longer restarts a connection on the other side.**
  Inbound and outbound names are separate namespaces, so one bare name can be both an inbound and
  an outbound. With no `control_target`, a rule's `control_action` aimed at the event's own name,
  and the event does not say which side that name came from. On a first deployment, a
  `restart_inbound` rule on an outbound's `connection_stopped` would have restarted any inbound
  with the same name, and the reverse. Now the restart runs only when the running graph declares
  the name on the action's side and not on the other. Otherwise the engine logs a WARNING that
  says to set `control_target`, and restarts nothing. A rule with `control_target` set is
  unchanged. (vault BACKLOG #2528)
- **An LDAP referral now pages the directory reconciler instead of reading as an outage.** In
  v0.5.1 a referral read as a directory outage, which pages nobody. A referred account is now left
  unjudged, and every other account in the pass is still judged. Every pass with a referral audits
  `auth.ad_reconcile_referred`. It also raises `ad_reconcile_aborted` with reason
  `directory_referral` under its own source, `directory-reconciler-referral`. A user search base in
  another domain refers every probe, so that pass still revokes nothing, but now it pages. A
  referring group search base refers only enabled accounts, so disables still revoke. A directory
  role or channel-scope change does not reach those sessions while it lasts.
  (`BACKLOG #2538`)
- **An AD connect or receive timeout above its default is now a named loosening.** With
  `[auth].ad_enabled`, an `ad_connect_timeout` or `ad_receive_timeout` above `10` s is reported by
  `messagefoundry security show`, `GET /security/posture` and the serve-time warning. A longer
  timeout lets a domain controller that has stopped answering hold a worker thread longer. See
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). (`vault BACKLOG #2567`)
- **A FHIR connection set to `update_url_form = "path"` is now on the posture read-out.**
  `security_loosenings()` has an `update_url_form` entry naming each such connection, and
  `GET /security/posture` shows it. It reads the same list as the `fhir-update-path-form` line of
  `messagefoundry check`. The serve-time warning and `messagefoundry security show` have no
  connection graph, so they do not name it, and their scope notes say so. Nothing new is refused.
  See [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). (`vault BACKLOG #2571`)
- **A proxy URL that carries credentials is refused when they would reach the proxy in
  cleartext.** `urllib` sends a `user:password@` from a proxy URL to the proxy as a
  `Proxy-Authorization: Basic` header. A credentialed proxy not written `https://` is now refused
  for each request sent through it. The proxy may come from `proxy_url`, from `HTTP_PROXY` or
  `HTTPS_PROXY`, or from the system proxy settings. The Vault hop already refused this. For a proxy
  written `https://`, see the `BACKLOG #3410` entry. What the check does not cover is listed in
  [CONNECTIONS.md](docs/CONNECTIONS.md). (`BACKLOG #2572`)
- **On the generic ODBC dialect, no `odbc_params` keyword can give the driver another host.**
  `[egress].allowed_db` is checked against the `DATABASE` connector's `server` setting. On
  `dialect="generic"`, `odbc_params` took any driver keyword except `DRIVER`, `SERVER` and
  `DATABASE`, so a keyword could have told the driver to connect to a host the allowlist never
  checked. `odbc_params` now takes a fixed list of keywords: a port, TLS modes and files, and
  session options. Any other keyword is refused when the connection is built, and the error
  names the keyword and the connection. A keyword given twice, or spelled with a trailing or
  doubled blank, is refused. `odbc_user_key` and `odbc_password_key` take a credential keyword
  only. A file keyword must be a plain local path; a path that starts with two separators or a
  device prefix is refused. Every value must be printable ASCII, and `server`, `odbc_driver`,
  `database`, `username` and each `odbc_params` value may not hold `;`, `{` or `}`. This covers
  the `Database(...)` destination and the `DatabasePoll(...)` source. The SQL Server preset
  never read `odbc_params` and is unchanged. **Breaking for a generic connection** that set
  another keyword, at least a driver's own target keyword such as Oracle's `DBQ`, psqlODBC's
  `pqopt`, and `TrustServerCertificate`; or that holds a non-ASCII character in a value,
  its password included. See *Accepted `odbc_params` keywords* in
  [CONNECTIONS.md](docs/CONNECTIONS.md). (vault `BACKLOG #2577`)
- **A loopback hop is never sent through a web proxy.** The engine allows a cleartext `http://`
  hop to a loopback host because that hop stays on the box. `urllib`'s proxy handler did not know
  that rule. With a proxy in the environment and no `NO_PROXY` entry, a request to `127.0.0.1`
  would have gone to the proxy. Every engine `urllib` opener now dials a loopback host direct,
  reading the host by the same rule the cleartext check uses. That holds for a proxy from the
  environment, the operating system's own proxy settings and a configured `proxy_url` alike. An
  off-box hop still uses the proxy as before.
  - A per-connection proxy resolved for a loopback destination attaches no proxy handler and no
    `Proxy-Authorization` header, and says so in the log at INFO. The static-credential report
    lists no proxy credential for a connection whose every target is loopback.
  - The ECH sidecar hop uses no proxy at all. `ech_sidecar` is read by the same loopback rule, so
    a name that only starts with `127.`, and the short form `127.1`, are now refused at build.
    Write the full address, such as `127.0.0.1`.

  Which hops the rule covers, and which clients are outside it, is under `[egress]` in
  [CONFIGURATION.md](docs/CONFIGURATION.md). The decision is Amendment B of
  [ADR 0126](docs/adr/0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md).
  (vault BACKLOG #2579)
- **`POST /dr/activate` and `POST /dr/release` ask for step-up.** Both sat behind `require_paced`,
  while the planned failover on `POST /cluster/stepdown` asked for a fresh credential proof. They now
  use `require_step_up`, so a session outside its step-up window, or one calling from a new client
  address, is refused with `403` and `X-Step-Up-Required: 1`. A client that scripts a DR promotion
  calls `POST /me/reauth` first. A directory or federated session re-proves at its directory or
  identity provider, so keep a local administrator account for the DR box. The web console carries
  the matching gate on its own two routes in the same change, so update the console with the
  engine. See the route map in [SECURITY.md](docs/SECURITY.md) and the
  amendment in [ADR 0048](docs/adr/0048-third-tier-disaster-recovery-standby.md).
  ([BACKLOG #2581](docs/BACKLOG.md))
- **`POST /config/reload` reads the path as text before it touches it.** The engine resolved
  `config_dir` first and compared second, and resolving a path opens it and each parent. A path
  that is outside the allowed roots as written is now refused with no filesystem call on it. One
  that passes is then resolved and compared again. A network share or a device-namespace path is refused unless it lies
  under a root that is itself spelled that way. A subdirectory of a root still reloads. The resolve
  also moved off the event loop. Name the path the way the root is configured: another
  spelling of the same directory is refused. See `[api].config_reload_roots` in
  [CONFIGURATION.md](docs/CONFIGURATION.md). ([BACKLOG #2581](docs/BACKLOG.md))
- **An archive named in a `POST /dr/activate` request is confined to the new `[dr].seed_dir`.** The
  path was unconfined. A request may now name only an archive under `seed_dir`, and none while that
  key is empty, which is the default. The same text-first check applies, and activation verifies the
  resolved path. A refusal answers `422` with one generic message that names no part of the path,
  and the `dr_activation_aborted` audit row records the path that was asked for. `seed_dir` must be
  absolute. `[dr].seed_archive` is unchanged. A runbook that passes the archive in the request body
  must set `[dr].seed_dir`. See `[dr]` in
  [CONFIGURATION.md](docs/CONFIGURATION.md). ([BACKLOG #2581](docs/BACKLOG.md))
- **The DICOM C-STORE server (SCP) applies `source_ip_allowlist` when it accepts a connection, and
  bounds its inbound TLS handshake.** The SCP used to check the peer address for each C-STORE, after
  it had received the object, so a peer outside the allowlist could still open an association and
  send one. It now closes such a connection as soon as it is accepted, before the TLS handshake and
  before anything is read. The inbound TLS handshake also moved off the accept loop and has a 10
  second deadline, so a peer that connects and never completes its handshake would no longer delay
  other senders. One SCP runs at most 256 handshakes at once, and at most 32 from one address. A
  refused address is logged once per 60 seconds instead of once per connection.
  **A sender outside the allowlist now sees a closed connection, not status `0x0124`.** It cannot
  tell that from an SCP it cannot reach, so a sender that retries will retry.
  `calling_ae_allowlist` is unchanged: it is applied when the association request is read. See
  [DICOM.md](docs/DICOM.md) section 3. ([BACKLOG #2583](docs/BACKLOG.md))
- **A child process of the engine no longer inherits the engine's whole environment.** The engine's
  environment holds its secrets: the store key when it is supplied that way, the store password and
  every `MEFOR_VALUE_*` connection secret. The sandbox worker under `[sandbox].mode = "subprocess"`
  was started with a copy of all of it, so a Router or Handler there would have read them from its
  own environment. The worker now starts with a short allowlist, and the `[dr]` takeover and
  release hooks start without the engine's `MEFOR_*` variables. An engine shard under `supervise`
  is a whole engine and still gets everything. The worker and the engine shards also start with `-P`,
  which keeps the engine's working directory off their import path, and with the interpreter's
  remote debugging disabled. **This is not an isolation
  boundary by itself:** a child still runs as the engine's account and can read what that account
  can read. At least these things change for a config author, and the `[sandbox]` and `[dr]`
  sections of [CONFIGURATION.md](docs/CONFIGURATION.md) give the detail:
  - Config code that reads a variable from `os.environ` finds it unset in the sandbox worker unless
    it is on the allowlist. Name each variable a config reads in the new
    `[sandbox].pass_environment`. The engine now compares the graph a worker loaded with its own,
    by name, and refuses a worker whose graph differs. A config file changed on disk and not yet
    reloaded is refused the same way. The setting refuses every `MEFOR_*` name.
  - A helper module that a config imports from the working directory is no longer found by the
    worker or by an engine shard, and neither is one on a relative `PYTHONPATH` entry. Make it a
    `_`-prefixed file in the config directory, or install it. `supervise` now loads the config
    once under an engine shard's import path before it starts one, and refuses to start the fleet
    if that fails.
  - A hook that read a `MEFOR_*` variable must be given the value another way.

  See also the 2026-10-01 correction in
  [ADR 0087](docs/adr/0087-sandbox-subprocess-isolation.md). (`BACKLOG #2587`)
- **Dual-control approval requests carry an integrity seal on a store that holds a key.** Each
  `pending_approvals` row has its own HMAC-SHA256 seal (`pending_approvals.seal`) over every other
  column, under the same purpose-derived key the user, session and role seals use. That binds what a
  release acts on: the captured params, a held config reload's digest among them, and the requester
  id the self-approval refusal compares. Every INSERT and UPDATE of the table goes through one helper
  per backend. A new request is sealed as it is inserted; a status change reads the row, checks its
  seal, and writes the moved row and a new seal only while the row still carries the seal it read,
  so a row changed outside the store is never re-sealed. The approval gate reads requests only
  through its own seal check. A request that fails is left out of the pending and interrupted
  lists, and approving, rejecting or resolving it answers 409, so it runs nothing and expires where
  it stands. A repeat request never joins an open one that fails; it is filed on its own, and the store logs
  the skipped row at WARNING, with the audit row and alert following when the gate next reads it. A row
  changed while its operation runs is left `executing`, and the restart reconcile leaves it so. Each
  failure writes an `integrity.authority_seal_failed` audit row and raises `integrity_drift`, once
  per request per five minutes, and the engine keeps running. A keyed open names how many open
  requests carry no seal; nothing seals one automatically, so a request filed before this change
  can no longer be released and is requested again. `rotate-key` re-seals each request under the
  active key after checking it, and leaves one that fails as it is. A seal stops a request forged or
  edited outside the store, not an older sealed copy put back: a writer who kept a `pending` row
  with its seal can restore it after the request was decided. New column `pending_approvals.seal` on
  SQLite, Postgres and SQL Server. A keyless store, and the `vault_transit` provider, write and check
  no seal yet. (vault BACKLOG #2592)
- **Custom role definitions and both directory maps carry an integrity seal on a store that holds
  a key.** Each `roles` row has its own HMAC-SHA256 seal (`roles.seal`) over every other column.
  The AD group-to-role map and the AD group-to-channel map each have one seal over their sorted
  pairs and their name, kept in a new `authority_set_seal` table, under the same purpose-derived
  key the user and session seals use. Every INSERT, UPDATE or MERGE of those tables goes through one
  helper per backend; deletes need no key and stay plain. `AuthService` checks a custom role's seal
  before it grants anything from it, and checks a map's seal before any directory sign-in,
  step-up, session recheck, certificate-identity check or reconcile pass reads a role or a channel
  from it. A custom role that fails grants nothing, while its holders keep their other roles; a map
  that fails grants nothing from any of its pairs, so a failing channel map withdraws a
  directory-set channel scope rather than widening one. Either failure writes an
  `integrity.authority_seal_failed` audit row and raises `integrity_drift`, and the engine keeps
  running. The role list shows a failing role with no permissions and each map read shows a
  failing map as empty, so an administrator's re-save cannot carry a value written outside the
  store into a sealed row. Saving a role or a map again through the console or the API writes it
  whole and seals it, which is how one that fails, or one written before this change, is repaired;
  a keyed open names how many custom roles and maps carry no seal. Removing a deleted role's pairs
  from the role map re-seals that map only when it verifies. Built-in roles still resolve from code;
  their rows are sealed by the role seed at each start and grant nothing either way. `rotate-key`
  re-seals each role and both maps under the active key after checking them, and leaves one that
  fails as it is. A reconcile pass reads each map once. Because a failing role map grants
  nothing, a directory sign-in or reconcile pass that reads it writes the account's directory
  roles as none, and the roles come back only at the account's next sign-in or pass after the map
  is repaired. A seal stops a role or map forged outside the store, not an older sealed copy put
  back: a writer who kept a role row or a whole map with its seal can restore it. New column `roles.seal` and table
  `authority_set_seal` on SQLite, Postgres and SQL Server. A keyless store, and the `vault_transit`
  provider, write and check no seal yet. (vault BACKLOG #2592)
- **Session rows carry an integrity seal on a store that holds a key.** Each `sessions` row now
  stores an HMAC-SHA256 seal (`mfseal:v1:<key id>:<mac>`) over every column except `last_used_at`,
  under a key derived from the store key for this purpose alone. The engine writes the seal in one
  helper per backend and checks it in one place, `AuthService._load_session`. A row whose seal does
  not verify resolves to no session and is revoked. The refusal writes an
  `integrity.authority_seal_failed` audit row and raises an `integrity_drift` alert under the
  subject `authority-seal`, and the engine keeps running. A row sealed under a retired store key is
  ended with an INFO line instead, since that is a key change and not an integrity failure.
  Revoking a session blanks its seal. Ending every session of an account also raises that
  account's session epoch, and a session minted under an older epoch resolves to nothing.
  `rotate-key` now ends every session, so every operator signs in again after a rotation. New
  columns `sessions.user_epoch`, `sessions.seal` and `users.session_epoch` on SQLite, Postgres and
  SQL Server. A session row written before this change, or before the store had a local key, has
  no seal, so a keyed store refuses, reports and ends it once. A session that carries an older
  epoch than its account is ended and reported the same way. A keyless store, and the `vault_transit` provider, write and check no
  seal yet. (vault BACKLOG #2592)
- **Each account's authorization record carries an integrity seal on a store that holds a key.**
  One HMAC-SHA256 seal (`users.authz_seal`, `mfseal:v1:<key id>:<mac>`) covers every other column
  of the account's `users` row, the TOTP secret's stored bytes included, its `user_roles` rows and
  a digest of its passkeys (`users.cred_digest`), under the same purpose-derived key the session
  seal uses. Every INSERT or UPDATE of those tables goes through one helper per backend, with at
  least two named exceptions: the passkey sign-count update, which the digest leaves out, and the
  one-time column backfills of the schema migration. Deletes need no key and stay plain. The
  helper checks the seal it read before it writes, refuses the write and re-seals nothing when the
  check fails, and writes the whole record back with a compare on the old seal. `AuthService`
  checks the seal in one loader before it acts on an account, and the identity build, the
  password, TOTP and recovery-code checks take the checked type. An account whose record fails is
  refused, writes an `integrity.authority_seal_failed` audit row and raises `integrity_drift` under
  the `authority-seal` subject, and the engine keeps running; an API write the store refuses for
  that reason answers 409. A passkey set that no longer matches its digest refuses every passkey
  ceremony for that account the same way. The account's session epoch is now inside the seal, and
  the last-administrator guard counts only administrators whose record passes. A record sealed
  under a retired store key still verifies, and `rotate-key` re-encrypts each account's TOTP secret
  and re-seals the account under the active key in one write, so removing the retired key
  afterwards signs nobody out. New columns `users.cred_digest` and `users.authz_seal` on SQLite,
  Postgres and SQL Server. An account written before this change, or before the store had a local
  key, has no seal, so a keyed store refuses it: nothing seals a blank record automatically. A
  keyed open names how many such accounts there are, and `provision-admin` under a new username is
  the way back in. A keyless store, and the `vault_transit` provider, write and check no seal yet.
  (vault BACKLOG #2592)
- **A message's cells are sealed under a tag that binds the message's channel, and a saved search's
  criteria under one that binds its owner.** The associated data of `messages.raw`, `error`,
  `summary` and `metadata` now covers the row's `id` and `channel_id`, built by one helper,
  `message_cell_aad`; `search_presets.criteria` covers its `id` and `owner_user_id`, built by
  `preset_criteria_aad`. Both hold on SQLite, Postgres and SQL Server. A message moved to another
  channel, or a preset moved to another owner, outside the store no longer opens. Opening one of
  them raises an `integrity_drift` alert, under the subject `messages-tag` or `search_presets-tag`,
  and writes an `integrity.message_tag_failed` or `integrity.preset_tag_failed` audit row, once per
  cell per hour in each process. A message read or a preset recall refuses; the by-id message
  routes answer 423 inside the caller's channel scope and the usual 404 outside it, and an export
  skips the row; the layered-search preset recall answers 423. A delivery whose `dynamic_headers`
  metadata read fails its tag is dead-lettered without sending, whatever the internal-error policy.
  Under `vault_transit` a failed open keeps the cipher's own error and raises no
  integrity alert, because that cipher cannot tell a moved cell from an unreachable Vault. The message list and the dead-letter list keep the row,
  by its plaintext columns, with its sealed cells withheld. Content search leaves it out, and the
  document strip skips it. A transform handoff that reads such a message's metadata dead-letters the
  routed row, so the message records `ERROR` and the lane moves on; on the SQL Server fused path the
  runner does the same. A captured-response re-ingress whose origin fails its tag is consumed and
  dead-lettered like a corrupt reference. The on-open seal pass, `rotate-key` and the restore-verify
  cell list rebuild the same tags; `rotate-key` steps over a cell that fails its tag under a key it
  holds and names the count in a WARNING. Cells written before this change carry the old tag and
  are refused on read, and so is the criteria of a saved search moved from a 0.3.2 table, whose
  owner the open rewrites. A keyless store, and a store with `[store].aad_bind` off, bind no tag.
  (vault BACKLOG #2593)
- **A queue row's payload is sealed under a tag that binds the row's routing fields.** The
  associated data of every `queue.payload` cell now covers the row's `id`, `message_id`, `stage`,
  `channel_id`, `destination_name`, `handler_name` and body kind, built by one helper,
  `queue_payload_aad`, on SQLite, Postgres and SQL Server. A NULL field and the text `None` give
  different tags. A store-once fan-out row now seals its `shared_body` key in its own `payload`
  instead of leaving it blank, and a claim opens that cell and refuses the row when the sealed key
  and `body_ref` differ. A row with a blank payload is never delivered on a keyed store. A row whose
  payload does not open under its own tag is dead-lettered, its message records `ERROR`, the lane
  moves on, and the engine writes an `integrity.queue_tag_failed` audit row and raises an
  `integrity_drift` alert under the subject `queue-tag`. A resend from such a row is refused and
  alerted the same way. The outbound body view refuses a live row whose tag fails, and leaves out a
  dead one the claim already reported. A cell under a key that is not configured, or an unmarked
  one, is not a tag failure and keeps the cipher's own error. The on-open seal pass and
  `rotate-key` rebuild the same tag. `rotate-key` steps over a cell that fails its tag under a key
  it holds and names the count in a WARNING; a key it does not hold still stops it. On SQL Server
  a claim does not read `body_ref`, so a `body_ref` set outside the store delivers only that row's
  own body there. Queue cells written before this change carry the old tag and are dead-lettered
  when claimed, and so is a pending empty body written before the store had a key. A keyless
  store, and a store with `[store].aad_bind` off, bind no tag; on a keyless store only the
  shared-body reference check applies, and it is audited but not alerted. (vault BACKLOG #2593)
- **A store that holds a key now requires every audit row keyed, and the audit chain numbers its
  rows.** Row 1 of a keyed chain is a genesis row, written at the store's first start, that names
  the key the chain begins under. Every row carries its position, `seq`, inside its MAC: `seq`
  starts at 1 and rises by one, so a missing, repeated or renumbered row is a reported break. The
  `audit_chain_meta` table is removed on all three store backends: nothing in the database says
  where keying starts. A handle opened with no key reads from the genesis row that the chain is
  keyed, and refuses to append to it.
  **Breaking, and there is no migration.** `audit_log` gains a `seq` column, the row digest covers a
  new field list, and `messagefoundry rekey-audit` is deleted. A SQLite store created by an earlier
  build is refused at open, by name. A server database created by an earlier build fails at open
  with the driver's missing-column error, and running `provision-schema` again does not fix it:
  drop the database and provision a new one. The server-database runbook
  now makes one table append-only, `audit_log`. A store that has a key and opens onto rows written
  without one logs an ERROR, fails `audit-verify`, and is listed as `audit_chain_unkeyed`; no
  command converts those rows.
  The audit anchor's `COUNT` is the newest row's sequence number, and the off-box audit record
  carries it as `seq`, so a collector's record can be passed to `audit-verify --expected-anchor`.
  **What this does not show:** rows cut off the end of the chain, or a log emptied altogether. Only
  an anchor held outside the database shows either. See
  [SECURITY.md](docs/SECURITY.md), "Audit", and
  [ADR 0193](docs/adr/0193-audit-chain-key-ranges-survive-a-store-key-rotation.md) and
  [ADR 0194](docs/adr/0194-refuse-to-start-a-keyless-audit-chain-at-the-store-open-seam.md),
  both amended 2026-10-01. ([BACKLOG #2594](docs/BACKLOG.md))
- **A store key in the Windows service's NSSM environment now refuses the start.** NSSM keeps the
  service's `AppEnvironmentExtra` and `AppEnvironment` lists in the service's registry key, which
  any local user can read on a default Windows install. `serve` and `supervise` now read their own
  service's list at start and refuse when `MEFOR_STORE_ENCRYPTION_KEY` or
  `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` is in it, under every `[security].enforcement` setting. Keep
  the key in a DPAPI key file, which [SERVICE.md](docs/SERVICE.md) now lists first. Another
  engine secret in that list is named as the loosening `service_environment_secret`, a store key
  that reaches the service through its environment as `store_key_in_service_environment`, and a
  list the engine could not read as `service_environment_unobservable`. The Windows service smoke
  and the store-access measurement now pass the key through a DPAPI key file. (`BACKLOG #2595`,
  `#2601`)
- **A released config reload loads only the config its approval named.** When dual control holds
  `POST /config/reload`, the hold's params carry `fingerprint`. That is the content digest of the
  target directory, taken at request time. The release checks the directory against it before and
  after the load. A release whose config changed answers **422** and audits
  `config_reload_failed` with reason `digest_mismatch`. A hold that carries no digest gives reason
  `no_approved_digest`. A digest the engine cannot take gives reason `digest_unavailable`. A
  request whose digest cannot be taken files no hold and is refused the same way. A reload target
  the engine cannot resolve or list now answers **422** with reason `unreadable`, inline or held.
  It used to answer 404 `not_found`, or 422 `invalid_config` when the listing read as empty, or a
  500 with no audit row. A missing directory still answers 404 `not_found`. So does a name or path
  too long for the filesystem, or a name Windows refuses. See [SECURITY.md](docs/SECURITY.md).
  (`BACKLOG #2596`)
- **A start now alerts when its config differs from the one the store last recorded.** Each start
  compares its config fingerprint (ADR 0041 D1) with the newest `config_loaded`, `config_reload` or
  `connection_flag_set` audit row, from any node or engine shard, and raises the new
  `config_changed` alert on a change. A change applied with `POST /config/reload` before the
  restart does not alert. The start's `config_loaded` row records `previous_fingerprint` and
  `changed`, the fingerprint detail gains a `scheme` tag, and a flag toggle's row carries a
  digest, which vouches for the written directory only when the toggle was the one change since
  the load. On a first deployment, an edit that only a restart picked up would have left no
  signal. The check is alert-only: a failed or slow baseline read never blocks the start. See
  [CONFIGURATION.md](docs/CONFIGURATION.md). (vault BACKLOG #2597)
- **`MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` is refused under `[security].enforcement = enforce`.** The
  variable used to downgrade the config-source check to a warning at any posture. It is now
  honoured only when `MEFOR_SECURITY_ENFORCEMENT=warn` is set in the same environment. Under
  `enforce`, the default, it does nothing: a safe config directory loads as before, and one that a
  broad or low-privilege principal can write is refused with an error that names the variable.
  **`warn` set only in the settings file does not unlock it**, because the check also runs in
  processes that read no settings file. A dev or CI checkout that relied on the variable alone must
  now set both. While it is honoured, the `serve` start-up warning and `GET /security/posture` name
  it. The dial is read from the environment, so a program that embeds the engine with settings it
  built itself is outside the clamp. See its entry in
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md) for the limits, and Amendment C in
  [ADR 0036](docs/adr/0036-windows-config-source-trust.md).
  ([BACKLOG #2599](docs/BACKLOG.md))
- **A mistyped `MEFOR_<SECTION>_<KEY>` variable now refuses the load.** When the name points at
  a real section and no setting in it, `load_settings` raises, naming the variable and, when one
  fits, the nearest real one, or the file setting when one string cannot fill it. It never
  repeats the value. It used to be dropped, so
  `MEFOR_STORE_REQUIRE_ENCRYPTON=true` started an instance without the hardening it asked for. A
  variable aimed at a section with no env layer (`[service]`, `[cert_monitor]`,
  `[secret_rotation]`, `[update_check]`) is refused as well, real key or not. Variables that are
  not settings and are read straight from the environment (the Vault, Transit,
  revocation-attestation and phase-timing names) are spared by an explicit list. Under
  `[secrets].provider = "env"`, so is the variable a secret-reference setting names. **Not
  refused:** a variable that names no section. Some of those are warned about (see the entry
  on that warning), and the rest are dropped with no message. **The check reads the whole process
  environment**, so a Kubernetes Service named `mefor` or `mefor-<section>` in the engine's
  namespace would stop the start through its service-link variables. The shipped manifests now
  set `enableServiceLinks: false`. See
  [CONFIGURATION.md](docs/CONFIGURATION.md). (`vault BACKLOG #2600`)
- **Four `[auth]` switches are now reported loosenings when `false`:** `require_action_step_up`,
  `password_check_breached`, `password_check_context` and `password_check_username`. Each ships
  `true`, and nothing refuses one. The serve-time warning, `messagefoundry security show` and
  `GET /security/posture` name them. See
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). (`vault BACKLOG #2600`)
- **Three numeric `[auth]` settings are now reported loosenings when set looser than they ship:**
  `step_up_max_age_seconds` above `300`, `totp_skew_steps` of `1` or `2`, and
  `initial_password_expiry_hours` above `72` or at `0` or less (no expiry). The serve-time warning,
  `messagefoundry security show` and `GET /security/posture` name them. Nothing refuses one. The
  last two entries do not repeat the configured value. See
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). (`vault BACKLOG #2600`)
- **A `MEFOR_*` variable that names no section and looks like a setting now logs a WARNING.**
  It is still not refused, because the engine cannot know every `MEFOR_*` name another tool owns.
  At least two shapes are warned about: a name that is a section and nothing else
  (`MEFOR_UPDATE_CHECK=false`), and a name whose first part is close to a section and whose
  remainder is a real setting of it (`MEFOR_STOER_PATH`, with the name you probably meant, or the file setting when one
  string cannot fill it). The
  warning names the variable and never its value. Other names that match no section are still
  dropped with no message. See [CONFIGURATION.md](docs/CONFIGURATION.md).
  (`vault BACKLOG #2600`)
- **A file that holds a key is created restricted, and `protect-key` fails closed.** The DPAPI
  store key file and every TLS private key the engine writes are now restricted in the call that
  creates them, so the file never carries the directory's inherited access. `protect-key` and the
  `cert` commands refuse to replace an existing file or link, and `protect-key --grant-account`
  refuses a broad group, another group or a domain. If the file cannot be created restricted, the
  command exits non-zero, writes no file and prints no success line. `serve` and `supervise` now
  check the store key file and the TLS key the engine minted before using them, and refuse to
  start under `[security].enforcement = "enforce"` when a known broad group can read or change
  one. **This can stop a start that worked before:** a store on a filesystem that cannot hold
  permissions can no longer mint its TLS key. [PHI.md](docs/PHI.md), "Key files", lists what
  the check does not cover. (`vault BACKLOG #2601`)
- **The engine refuses a route that declares no authorization.** `create_app` adds one app-level
  dependency, `refuse_undeclared_route`. A route passes it only with a gate built by a `require*()`
  factory, or with an endpoint marked `public_route` and a reason. A WebSocket that authorizes in
  its own body is marked `authorizes_in_body`. Any other route answers 403, and a WebSocket is
  refused before it is accepted. Every route the engine ships answers as it did before. The check
  does not reach a mounted application or a plain Starlette route, so `/ui/static` stays the only
  mount and a test pins that. (`vault BACKLOG #2604`)
- **The route walk in `scripts/security/route_gates.py` sees more.** It knows a gate by a mark its
  factory sets, not by its name, so a dependency only named `require_*` reads as no gate. It
  descends into an included router and into a mounted application with routes.
  `full_surface_app()` builds the app with every route-registering flag on, and a test fails when
  a new flag registers a route that app lacks. (`vault BACKLOG #2604`)
- **The egress allowlist now denies by default everywhere, not only under `serve`.** The
  `[egress]` settings model refuses a destination whose transport has no allowlist unless
  `[security].block_unlisted_outbound = false` is written. Every connector build seam
  (`build_destination`, `build_source`, both live-lookup executors) and every embedding entry
  point (`RegistryRunner`, `ReferenceSyncRunner`, `Engine`, `create_managed_app`) now requires an
  explicit egress policy, and the build seams run the check themselves. The matcher moved to
  `messagefoundry/transports/egress.py`. `serve` still refuses to start when no destination list
  is set. (`vault BACKLOG #2605`)
- **The raw-TCP and X12 listeners gain MLLP's per-host connection cap and frame deadline, and every
  socket listener throttles its allowlist refusal log.** The MLLP, raw-TCP, X12 and HTTP listeners
  now decide admission in one shared place: refuse while stopping, the source allowlist, the global
  connection cap and the per-host cap. `Tcp()` and `X12()` take `max_connections_per_host` (default
  32) and `max_frame_seconds` (default 60), with the same meaning as on `MLLP()`. On X12 the frame
  is the interchange, from its `ISA` to its `IEA`. `Http()` takes `max_connections_per_host` too,
  but it ships off: that listener answers one request per connection, so behind a reverse proxy a
  cap would be its whole capacity. A peer outside `source_ip_allowlist` is now logged at most once
  per address per 60 seconds, and at most 20 lines per 60 seconds per listener, instead of once per
  connection; the `peer_not_allowlisted` event still records each one. The raw-TCP, X12 and HTTP
  listeners also refuse a connection that arrives while they stop, as MLLP already did.
  **Behind a source-NAT proxy, set `max_connections_per_host=None` on a raw-TCP or X12 inbound**,
  and raise `max_frame_seconds` with `max_frame_bytes` or `max_interchange_bytes` for large frames
  over slow links. See [CONNECTIONS.md](docs/CONNECTIONS.md).
  ([BACKLOG #2606](docs/BACKLOG.md))
- **Windows SSO refuses an account that holds a federated binding, and every bind ends the
  account's sessions.** An account an administrator has bound to a federated identity now signs
  in through its identity provider only. `POST /auth/negotiate` and `GET /ui/sso` answer a bound
  account as they answer any failed sign-in, and the `auth.login_failed` audit row carries
  `reason=federated_sign_in_required`. `PUT /users/{user_id}/federated-identity` now revokes every
  live session of the account on a first bind as well as on a rebind, in the same transaction as
  the write. It reports the count in its answer (`federated identity bound; revoked N session(s)`),
  in the `auth.federated_subject_bound` audit row as `sessions_revoked`, and in the notice to the
  account holder. A Windows SSO sign-in already in flight when a bind lands is refused at its
  session insert. An account with no binding is unchanged. Keep one local, unbound Administrator:
  a bound account has no Windows SSO fallback. (`provision-admin` is no longer blocked by a bound
  Administrator; see the BACKLOG #2711 entry.) The limits are in
  [Federated sign-in](docs/SECURITY.md#federated-sign-in-oidc-browser-only--adr-0142).
  ([BACKLOG #2609](docs/BACKLOG.md))
- **A directory sign-in that newly grants Administrator now raises the `administrator_granted`
  operator alert.** The directory can make an account an Administrator by adding it to a group
  already mapped to that role. The sign-in's role sync audited the change and notified the holder,
  but raised no alert, so the page every other Administrator grant raises was missing. `POST
  /auth/negotiate` and the web console's `GET /ui/sso` and `/ui/oidc` callback now raise it, keyed
  `user:<username>`, with `via` naming the route and `granted_by` the fixed marker `<directory>`.
  A sign-in refused after the role was written still raises it, since a later sign-in gains nothing
  to page on. A sign-in that gains only other roles, or by an account that already held
  Administrator, raises nothing. At least two cases still raise no alert. A sign-in that fails with
  a server error after the role write loses the page, because the retry gains nothing. And an
  account that never signs in again and holds no live session raises nothing, because the engine
  never sees the grant. A directory reconcile pass that applies the grant first raises the alert
  itself (vault BACKLOG #3141). See docs/SECURITY.md, *A directory grant*. (`vault BACKLOG #2610`)
- **The AD group maps take a full distinguished name only; a short name is no longer accepted.**
  `PUT /ad-group-map` and `PUT /ad-group-scope-map`, and the web console's AD group page, refuse a
  key that is not a full DN, such as `CN=MF-Admins,OU=Groups,DC=example,DC=com`, with a 400. A
  user's groups are now read as DNs only. Before, the engine also matched each direct group's first
  CN and each nested group's `sAMAccountName`, so a map key written as a short name matched a
  same-named group in any unit. On a first deployment
  that mapped a short name, anyone able to create such a group and add an account to it would have
  given that account the mapped roles, Administrator included. A short-name key already stored
  matches nothing, and there is no compatibility path; re-enter it as a DN. `SECURITY.md` said the
  short form was the group's `sAMAccountName`; it now states the DN-only rule. (vault
  `BACKLOG #2610`)
- **Group map keys and a user's groups are compared in one canonical DN form.** Each side is
  parsed, unescaped and escaped again one way, with the parts of a multi-valued RDN sorted. The
  result is printable ASCII: ASCII letters are lower-cased, and each non-ASCII or control
  character is written as hex escapes. So however a value is escaped, one DN gives one key:
  `CN=C# Developers,...`, which Active Directory writes with the `#` unescaped,
  `CN=C\# Developers,...` and `CN=C\23 Developers,...` all name the same group, and a space after
  a comma is ignored. Groups that differ stay apart: a tab or line break in a value is part of it,
  and a non-ASCII letter matches only in the case it was written in. A key whose canonical form
  passes 256 characters is refused with a 400. The maps store the canonical form, which is what
  `GET` now returns. (vault `BACKLOG #2610`)
- **A Windows SSO step names a client only when the Kerberos context that checked the ticket
  finished.** On Windows that is the SSPI context's own `complete` flag. On any host without SSPI,
  Linux and macOS included, every sign-in goes through pyspnego's own Negotiate wrapper, because
  pyspnego 0.12's GSSAPI proxy offers Kerberos only and never Negotiate. That wrapper can stay
  incomplete after one step while the Kerberos context inside it finished, so there the inner
  context is read, and only a Kerberos one counts. This is defence in depth; no provider is known to name a client on an unfinished context.
  Kerberos realm handling is unchanged. (vault `BACKLOG #2610`)
- **BREAKING (embedders only): `create_managed_app` denies by default.** The managed app factory treated a missing
  `auth_settings` as a request for the open mode, so an embedder that passed nothing would build an
  API whose protected routes answer as the built-in system identity. It now refuses every protected
  route with `503` unless the caller passes `allow_no_auth=True`, the same opt-in `create_app`
  takes. Settings never select the open mode, and the opt-in beside any `auth_settings` raises
  `ValueError`. `serve` never passes the opt-in: it always
  requires sign-in (`vault BACKLOG #2719`). An embedder or a test that relied on the old default adds
  `allow_no_auth=True`. See the enforcement model in [SECURITY.md](docs/SECURITY.md).
  (`vault BACKLOG #2611`)
- **Six security signals now raise an operator alert, not only an audit row.** A rule layer over
  the audit stream raises `signin_failure_burst` (refused sign-ins from one address),
  `access_denied_burst` (refused requests by one account), `body_view_burst` (stored-body reads by
  one account), `bulk_export` (many messages exported by one account), `log_level_debug` (a DEBUG
  log level set, or refused on a production instance) and `posture_loosened` (a start with
  security loosenings). It is on by default. The thresholds are `[alerts]` settings:
  `security_signals`, `security_window_seconds`, `security_signin_failures`, `security_denials`,
  `security_body_views` and `security_export_messages`. An alert carries a count and a fixed
  sentence, never a message body or a typed username. Where the MLLP listener runs its own TLS
  handshakes, which is the standard asyncio event loop and not uvloop, it also records a failed
  handshake as a `tls_handshake_failed` connection event: the first at once, then one per listener
  per minute carrying the count since the last one. See
  [CONFIGURATION.md](docs/CONFIGURATION.md) and [SECURITY.md](docs/SECURITY.md).
  ([BACKLOG #2613](docs/BACKLOG.md))
- **An edit-resend can be proved after retention blanks its bodies.** The `message_edit_resend`
  audit row now holds keyed HMAC-SHA256 digests of the original and the edited body, under a key
  derived from the audit key (`mefor/audit-body-digest/v1`), with the `key_id` it came from. With
  the store key and a candidate body, `verify_audit_body_digest` confirms it; without the key the
  digest reveals nothing. In re-route mode the edited digest covers the body the operator submitted,
  not the handler's transformed output. A store with no in-heap audit key (keyless, or
  `vault_transit`) records no digest rather than a plain hash. A direct edit-resend's row now names
  the new message too, and an upload inject's `upload.resend` row carries a digest of the injected
  body. Every message also records a plain `messages.origin` (`partner`, `operator_edit`,
  `operator_upload` or `reingress`) and, for an operator origin, `messages.origin_actor`. Retention
  leaves both when it blanks the body. This is a schema change on all three stores: two nullable
  columns, added on open. On a first deployment, a fabricated order or result sent by edit-resend
  could otherwise not have been reconstructed once the retention window passed. (vault
  `BACKLOG #2615`)
- **`[egress].allowed_recipient_domains` bounds where an `Email()` destination may send.**
  `[egress].allowed_smtp` gates only the relay host, and a listed relay forwards to any address. Now
  every address in an Email destination's `recipients` must sit in a listed domain, or the
  destination is refused at config load and reload. The list is **deny-by-default**: an empty list
  refuses every Email destination, whatever `[security].block_unlisted_outbound` says, so any
  configuration with an `Email()` outbound must add it. Matching is exact and ignores case; a
  subdomain needs its own entry. `Direct()` is not gated by it. Env:
  `MEFOR_EGRESS_ALLOWED_RECIPIENT_DOMAINS`. See [CONFIGURATION.md](docs/CONFIGURATION.md#egress)
  and the 2026-10-02 amendment to
  [ADR 0029](docs/adr/0029-email-smtp-destination.md). (vault BACKLOG #2616)
- **A session token replayed from a second address no longer reads message bodies or calls paced
  writes.** The new-address check (`[auth].admin_new_ip_step_up`, on by default) used to run only in
  the step-up gates. A bearer token signed in at one address could list messages, read a raw body
  and start or stop connections from another, with no signal. Now `require_phi_read`, the
  `reveal` reads on the monitoring lists and `require_paced` refuse such a request with the step-up answer, 403 + `X-Step-Up-Required: 1`,
  and write `auth.new_address_reverify_required` on a first sighting. A re-verification that re-anchors the
  session at the new address clears it: at least a `POST /me/reauth` or a code at
  `POST /auth/mfa-verify`. An `oidc` session re-anchors through the identity provider's step-up
  instead, since neither of those moves its anchor. A passkey proof moves no anchor. The base gate still never asks, so monitoring
  polls from a changed address keep working. The refusal runs before the PHI-read and admin-write budgets are charged, and
  costs one session read per request. See [SECURITY.md](docs/SECURITY.md). (vault BACKLOG #2620)
- **`messagefoundry check` now runs the four inbound TLS exposure gates.** The MLLP, DICOM, raw TCP
  and HTTP listener gates ran only when the engine started a listener. So the commit/CI gate passed
  a cleartext off-loopback listener that `serve` would then refuse to bind, starting the rest of the
  graph without it. The `build-check` leg now runs them with the instance's derived posture and the
  `[security].require_encryption_for_remote` escape. `check` has no `--allow-insecure-bind`, so a
  site that relies on that flag under `enforcement = "warn"` would see `check` refuse what `serve`
  admits. The gates run only on a listener the engine would bind: deployed and `auto_start`. On a
  running engine, a reload and a flag toggle also skip one the DR run-profile parks, and gate one an
  operator started. An `auto_start` listener outside its schedule window is gated, because the
  scheduler binds it when the window opens. An operator start of an `auto_start = false` listener
  meets the same gates. A `deployed = false` listener cannot be started (the start raises
  `NotDeployedError`); the reload that deploys it meets the gates if the engine would then bind
  it, and otherwise its first start does. **One
  exposed listener the engine would bind refuses the whole config at build check**, where engine
  start isolates only that listener. While it stands, a reload, dry-run reload, promote, connection
  edit, connection-flag toggle, DR activation and a cluster follower's convergence reload are all
  refused. The refusal names the listener.
  It says that `deployed = false`, or `auto_start = false` with the listener stopped, leaves it
  unbound. The HTTP intake-authentication start gate (ADR 0154 D7) is not filtered this way. It
  still runs on every deployed HTTP listener. A reload, a dry-run reload and a flag toggle pass the
  running engine's own escape. So they do not refuse a listener the engine bound under it. (vault
  `BACKLOG #2622` item 1)
- **BREAKING: an off-loopback DICOM server (SCP) no longer counts a too-wide `source_ip_allowlist`
  as a peer control.** Every entry must now be a /8 or narrower for IPv4, or a /32 or narrower for
  IPv6, the same floors the HTTP intake gate applies. `["0.0.0.0/0"]` used to satisfy the gate while
  admitting everyone; now the SCP is refused at construction unless mTLS is set, and the error says
  the list is too wide. The floor rule moved into `messagefoundry/netaddr.py`, so the two gates share
  one function. mTLS still counts by presence, with no client-subject binding; that half is not
  built. (`BACKLOG #2622`)
- **A DR takeover hook that runs past `[dr].takeover_timeout_seconds` is now killed, with the
  processes it started.** The timeout used to stop only the engine's wait. The
  shell and its children ran on, so a takeover hook could still take the address after the
  activation was recorded as aborted. The hook now starts as the root of a tree the engine can kill:
  a kill-on-close job object on Windows, which the hook joins before it runs, and its own process
  group elsewhere. The sandbox worker's tree kill moved into the same shared module. Some processes
  still escape; `[dr].takeover_timeout_seconds` in [CONFIGURATION.md](docs/CONFIGURATION.md)
  names them. A release hook that overruns, and a hook that finishes on its own, are left
  alone, as before. (`BACKLOG #2622`)
- **Operator actions now commit their audit row in the same transaction as the change.** At least
  message replay, dead-letter replay (inline and released), an inline purge, resend, edit-and-resubmit (direct
  and re-route) and the uploaded-log inject do so, on all three store backends. Before, each row was
  a second write after the commit. The web console writes no permission-grant row first, so a crash
  between the two would have kept a console action with no record of who made it, on a first
  deployment. A failed audit append now also rolls the change back. A released dead-letter replay
  whose row fails re-queues nothing and is recorded as `failed`. The store methods `replay`,
  `replay_dead`, `cancel_queued`, `resend_to`, `reingress` and `enqueue_ingress` take `audit=`, a
  function from the result to the row; the matching `Engine` methods require it. `AuditAppend`
  gains `channel_id`. (vault `BACKLOG #2624`)
- **Injection and bulk export take a step-up proof bound to the action.** A fresh session window
  no longer opens `POST /messages/{id}/resend`, `POST /messages/{id}/edit-resend`,
  `POST /uploads/{id}/resend`, `GET` and `POST /messages/export`, `POST /connections/{name}/purge`
  or `POST /config/reload` (a `dry_run` included). Each takes a single-use grant minted for its own
  action, which the 403 names in `X-Step-Up-Action` and `POST /me/reauth` mints when sent as
  `purpose`. The console's resend, edit-resend, upload resend, purge and reload lanes take the same
  proof, minted by its re-auth page. The rest of the step-up surface keeps the shared window, so
  replaying dead letters does not cost a typed password per message.
  `[auth].require_action_step_up = false` puts these routes back on the window. On a first
  deployment, one live session inside the window would otherwise have been enough to deliver a
  fabricated message to a partner or export bodies in bulk. (vault `BACKLOG #2625`)
- **A repeated purge or reload still rejoins its open dual-control hold.** Under dual control, a
  `POST /connections/{name}/purge` or `POST /config/reload` that repeats the caller's own open
  request answers the same 202 and hold id with no new proof, while the session window is live. A
  first or different request still needs the proof. The console's purge and reload still ask for a
  proof on every submit. (vault `BACKLOG #2625`)
- **Upload resend needs `messages:edit` beside `files:browse`.** It injects a message, and
  `files:browse` is a read. `edit-resend` with a reroute was already the same power under
  `messages:edit`, so no permission or role is new; the built-in Operator holds both. (vault
  `BACKLOG #2625`)
- **The VS Code extension's promote re-proves when the engine asks.** The reload behind promote now
  takes a bound proof. A promote answered with 403 and `X-Step-Up-Action` prompts for the password
  in a masked box, sends `POST /me/reauth` with that action as `purpose`, keeps the re-keyed token
  and retries once. The pre-flight and the swap each ask, since each spends its own proof. A session
  that signed in through the identity provider is told to step up in the web console instead. The
  password is never stored or logged. (vault `BACKLOG #2625`)
- **The Windows service installer no longer defaults to the checkout.** `install-service.ps1` used
  to run the engine from `<repo>\.venv`, load `<repo>\samples\config` and work in the repository.
  Its engine now defaults to `C:\Program Files\MessageFoundry\engine`, which it refuses unless
  only administrators can write it. `-Config` is required. The settings file and project root are
  registered by absolute path (`-ServiceConfig`, `-ProjectRoot`), quoted so that Windows
  PowerShell 5.1 keeps a path with a space whole. `-LockConfigDir` also locks the value file's
  folder, and the settings file's folder when that holds no other folder; it refuses to lock a
  volume root.
  [SERVICE.md](docs/SERVICE.md#install-the-engine-where-only-administrators-can-write) builds
  the install. (`BACKLOG #2626`)
- **The config trust check reads the cache folder, `connections.toml` and the code-set tables**,
  as well as the directory and its `*.py`. A cache file under `__pycache__` runs in place of the
  source beside it, so a writer there changed what ran while the check passed. (`BACKLOG #2626`,
  `#2596`)
- **`serve` refuses to start when another account can write its settings file or value file**, or
  the folder either sits in, with the same dev/test escape as a config refusal. `supervise` refuses
  the fleet on the same check, and each reload checks the value file again before it reads it.
  `serve` reports an interpreter or engine package another account can write at WARNING, and
  starts. (`BACKLOG #2626`)
- **`messagefoundry service install` requires `--config`**, and passes it and `--service-config`
  to the installer as absolute paths. (`BACKLOG #2626`)
- **`install-service.ps1` refuses an engine install that anyone but administrators can write.** It
  checks the default root and a passed `-AppExe` or `-PythonExe` alike: the interpreter, the
  launcher, the package's `__init__.py` and a venv's `pyvenv.cfg`, each file and every folder above
  it. It also refuses an editable install. So a service can no longer run from a checkout. The
  service's working directory is now always the install root, and its project root is the folder
  above `-Config`. [SERVICE.md](docs/SERVICE.md#install-the-engine-where-only-administrators-can-write)
  says how to build the install from the engine wheel. (`BACKLOG #2626`)
- **`serve` and `supervise` refuse to start as a Windows service without an absolute
  `--service-config`.** With no flag, or a relative one and no `--project-root`, a service would
  read a `messagefoundry.toml` from its working directory. The engine knows it is the service when
  `nssm.exe` is the first process above it other than Python and the `messagefoundry` launcher. A
  start from a shell, the developer loop, needs no flag. `install-service.ps1` refuses when it has
  no settings file to register. [SERVICE.md](docs/SERVICE.md#install) says how to register one.
  (`BACKLOG #2626`)
- **Channel scope on the management API is now checked by type and by a route table, though list
  routes still apply it by hand.** The store reads that take `allowed_channels` now require it. A
  caller that leaves it out fails type-checking instead of reading every channel. Engine-internal
  callers pass `None` by name, and a test refuses a literal `None` on those reads under
  `messagefoundry/api/`. Every by-id message route now opens the message through one helper. It
  checks the caller's channel, audits a refusal and answers the same 404 as before. A test fails if
  any other API module touches the store's `get_message`. Another test classifies every route of the
  default JSON API for channel scope, so an unclassified route fails the run. It runs the scoped GETs
  that take no path parameter as a scoped caller and as an all-channels caller. Each list route still
  passes the caller's scope to its store read itself, so a new list route can still forget it until
  that test classifies it. Responses, status codes and audit rows are unchanged.
- **Every PyPI publish now runs in a job that only publishes, and names the `pypi`
  environment.** The build jobs gate the files, record their SHA-256 digests and hand them over;
  each publish job checks every byte against those digests before it publishes. No publish job
  checks out the repository or builds anything, and none runs on a manual dry-run. This lets the
  owner bind each PyPI publisher to the environment and require an approval, without that approval
  gating the build. The build jobs that only published no longer hold the OIDC identity.
  (`vault BACKLOG #2631`)
- **A release now refuses a tag whose commit is not on `main`, or whose required checks did not
  pass.** A new `tag-provenance` job in `release.yml` runs before any job that builds a release
  artifact. It asks the server whether the tagged commit is on `main`, and whether every required
  check passed on it, reading the required set from branch protection, any ruleset and
  `.github/required-contexts.txt`. Each check is judged on its latest run, so a red run after the
  merge blocks the tag until it is re-run; a check still running is waited for. A check the
  server requires that never ran on the commit refuses it too. The rule is in
  `scripts/release/tag_provenance.py`.
  (`vault BACKLOG #2631`)
- **No asset is added to a GitHub release after it is published.** The engine release is created
  as a draft, the harness wheel is attached to the draft, and a new `publish-github-release` job
  publishes it last. A re-run never uploads to a published release. This lets immutable releases
  be turned on without breaking the release workflow. (`vault BACKLOG #2631`)
- **Every remote pre-commit hook repository is pinned by commit, not by tag.** Each `rev:` in
  `.pre-commit-config.yaml` is the commit its tag named, with the tag beside it as
  `# frozen: <tag>`. A test fails on a hook repository pinned any other way. (`vault BACKLOG #2631`)
- **A credentialed FTPS hop with either certificate check off is refused at construction, as SMTP
  refuses it (vault BACKLOG #2636).** With `tls_check_hostname = false`, any certificate that chains
  to the trust anchor is accepted whatever host it names. With `tls_verify = false`, any certificate
  at all is accepted. Either way the FTP login would go to a peer whose identity was never
  established. A `username` or `password` on such a hop now raises at build, in both directions,
  with no escape variable or posture to unlock it. Before this, the hostname case was only warned
  and the verify-off case was permitted under the clamped `MEFOR_ALLOW_INSECURE_TLS` escape. Both
  keys are reachable only from a hand-built `ConnectionSpec`; `Ftp()` and `connections.toml` do not
  expose them. A hop with no credential is unchanged: the hostname case keeps its WARNING and the
  verify-off case stays behind the clamped escape. A credential over plain `ftp` (`tls=False`) is
  refused outright too: it was released by the clamped escape on a non-enforcing instance, which left
  the cleartext rung weaker than the FTPS rungs above it. An anonymous plain-ftp hop is unchanged. See
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md).
- **Refusals and warnings that name `MEFOR_ALLOW_INSECURE_TLS` now say it works only on an
  instance at `[security].enforcement = warn`.** The escape has no effect while enforcing, the
  default, or with no posture. At least nine refusals across LDAPS, Direct, email, MLLP,
  remote-file, the alert webhook and the AI broker told an operator to set it without saying so.
  Several also said it was refused only on a "production-PHI" instance, a rule that no longer
  exists. Five warnings logged when the escape was honoured, and the security posture's
  enforcement line, now name the posture too. A new test checks the texts it can find that name
  the escape, and its docstring says which shapes it cannot see. (`vault BACKLOG #2637`)
- **A scoped caller now gets 403 for every connection name it cannot reach.** The per-name
  connection routes (`/metadata`, `/test`, `/test-credential`, `/start`, `/stop`, `/restart`)
  used to answer 404 for a name the caller's scope listed but no connection used. A listed
  outbound got an audited 403, so the two answers told such a caller which listed names exist.
  Both now get the same audited 403. With the engine started, only a caller with no channel scope
  still gets 404 for an unknown name. With the engine not started there is no name to find:
  `/metadata`, `/test` and `/test-credential` now check the scope before they answer 503, and
  `/start`, `/stop` and `/restart` answer a scoped caller 404 for a name in its scope. **This
  changes a status code:** a script that read a 404 from these routes as "connection removed" sees
  403 from a scoped account. (`vault BACKLOG #2640`)
- **The anonymizer's default rules now map nine more guarantor, insurance and order fields.**
  `GT1-16`, `GT1-17` and `GT1-18` are the guarantor's employer name, address and phone. `IN1-5`,
  `IN1-6` and `IN1-7` are the insurance company's address, contact person and phone. `IN1-11` and
  `IN1-44` are the insured's employer name and address. `OBR-35` is the transcriptionist. Before,
  each of them left the anonymizer unchanged. `IN1-4` is still kept by default; a committed
  overlay, `tests/fixtures/anon/batch_18.anon.toml`, scrubs it and a non-standard `DST` segment
  for the one sample corpus that needs it. (`BACKLOG #2645`)
- **The support bundle and `GET /logs/tail` now also run the write-time credential scrub.** After
  its own credential patterns and the PHI pass, `support/redact.py` calls
  `secretscrub.scrub_credentials`, the same pass the log handler filters run. So a credential word
  added to that vocabulary reaches the bundle with no second edit. So does the store error text the
  PostgreSQL, SQL Server and privilege checks build with this redactor. Measured over 822,616
  synthetic lines, one pass of the redactor hides more than before and prints nothing it used to
  hide. Over that corpus, text redacted twice, as store error text is, printed a value the old pair
  hid on 1 line, and hid one the old pair printed on 6,107. It now
  also hides the value of a label whose name starts with a character such as U+212A, which
  case-insensitive matching reads as an ASCII letter. The redactor's own copy of the patterns
  stays, because the shared pass alone printed values that copy hid. (vault `BACKLOG #2694`)
- **The engine process refuses a script injected through Python's remote debugging, and reports
  the setting.** Python 3.14 lets another process run a script inside a running interpreter
  (PEP 768, `sys.remote_exec`). The engine's children already start with that interface off. The
  engine itself starts through a console-script launcher, which cannot pass the option. So on a
  first deployment, code running as the service account could have run Python inside `serve` or
  `supervise`. The command line now installs an audit hook as it starts. The interpreter drops an
  injected script when the hook raises, and the hook logs a WARNING with the script's file name.
  `security_loosenings()` gains two entries, which the serve-time warning and
  `GET /security/posture` show: `remote_debug_enabled` with the hook in place, and
  `remote_debug_unguarded` without it. **A default start now reports `remote_debug_enabled`.**
  The hook is a residual control, and the engine does not refuse to start with the interface on.
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md) says what stays open and how to clear the
  entry. `security_loosenings()` takes a new required `remote_debug` argument.
  (`BACKLOG #2700`)
- **`serve` and `supervise` refuse to start under `enforcement = enforce` when Python remote
  debugging is enabled in their process** (vault BACKLOG #2700, owner ruling 2026-10-16). The
  shipped service launches already pass `-X disable-remote-debug` and are unaffected. A
  console-script start such as `messagefoundry serve` would now refuse; the refusal names the fix,
  `python -P -X disable-remote-debug -m messagefoundry serve ...`, and the named acceptance for the
  developer loop, `[security].allow_remote_debugging = true`, which is reported as a loosening.
- **The engine service starts in isolated mode, with remote debugging off.** Both shipped service
  launches ran the `messagefoundry` console script, which cannot pass an option to the
  interpreter. So the engine would have honoured a `PYTHONPATH` or `PYTHONHOME` left in the
  service's environment, and its remote-debugging interface was on. `install-service.ps1` now
  registers the install's `python.exe` with `-I -X disable-remote-debug -m messagefoundry serve ...`,
  and the container image's entry point is the same command with `-u -B`. The working directory
  is no longer on the import path of either launch. **A `PYTHON*` variable in the service's
  environment no longer reaches the engine itself**; its `MEFOR_*` variables work as before. The
  installer takes the `python.exe` beside `-AppExe`, or one folder up, and refuses when it finds
  neither; the new `-PythonExe` names one. A service launch no longer reports
  `remote_debug_enabled`; a start through the console script still does. See
  [SERVICE.md](docs/SERVICE.md#the-service-launch). (vault `BACKLOG #2701`, `#2700`)
- **`serve` and `supervise` list the start-up code in their interpreter, and refuse what no
  package records.** Isolated mode does not stop a `.pth` file's `import` lines or a
  `sitecustomize` module: the interpreter runs them at every start, before any engine code. The
  engine now reads each one on its own import path, which its Python children share. A file is expected when an installed package lists it in its `RECORD` with a
  matching hash, when it is in the base interpreter's own standard library, or when it is
  `virtualenv`'s own `.pth` in an environment that tool made. **Under
  `[security].enforcement = "enforce"`, the shipped default, a start refuses on any other**, and
  names it. Under `warn` it starts and reports `startup_code_unexpected`. **A start under a tool
  that injects an unrecorded `sitecustomize` through `PYTHONPATH`, as some debuggers do, would be
  refused under `enforce`.** This is detection: start-up code runs before the check and could
  defeat it. The engine also reports `interpreter_not_isolated` and, when its own account can add a file
  to a directory
  start-up code is read from, `startup_directory_writable`. A developer's own start reports the
  first and the last and is not refused. `GET /security/posture` gains an `interpreter` block
  with the whole reading, and the web console's status page shows it. `security_loosenings()` takes a new required `startup`
  argument. See
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md#interpreter_not_isolated-startup_code_unexpected-and-startup_directory_writable-what-runs-in-the-interpreter-before-the-engine-does).
  (vault `BACKLOG #2701`)
- **The container image's virtual environment is owned by root.** It was owned by uid 10001, the
  account the engine runs as, so that account could have written `site-packages`, and a plain
  `docker run` has no read-only root file system to stop it. Uid 10001 now owns only
  `/var/lib/mefor`; `/config` is root-owned (vault `BACKLOG #2759`). **A derived image that installs more packages must do so as
  root.** [`docker/README.md`](docker/README.md) now shows `--read-only` on its `docker run`
  example. (vault `BACKLOG #2701`)
- **The engine's Python children repeat its isolation.** The sandbox worker, each engine shard
  under `supervise`, the config check `supervise` runs first and the tray's branded relaunch now
  start with their parent's own `-I`, or its `-E` and `-s`, ahead of `-P -X disable-remote-debug`.
  Under the shipped service launch they are isolated, so a `PYTHONPATH` or `PYTHONHOME` in the
  service's environment reaches no engine process. A `serve` from a prompt is not isolated, and
  its children read the same variables it does. The `python_variables_reach_children` loosening
  is gone, because no child can honour a variable its engine ignores, and the start-up code
  inventory searches the engine's own import path only. It now logs a site directory it cannot
  list and a `.pth` file it cannot read. See
  [SERVICE.md](docs/SERVICE.md#the-service-launch). (vault `BACKLOG #2701`, `#2724`)
- **The Windows service installer limits the engine's token.** `install-service.ps1` set neither a
  service SID type nor a privilege list, so the service would have kept every privilege of its
  account and could have written wherever that account, or any group it belongs to, can. It now
  sets a one-entry `RequiredPrivileges` list, `SeChangeNotifyPrivilege`, for every run-as account,
  so Windows removes the rest when the service starts. When the service runs as its own virtual
  account, which is the default, it also sets the service SID type to `restricted`. A grant to
  `Users` or `Authenticated Users` then no longer lets the service write.
  **A deploying site would need to grant `NT SERVICE\<ServiceName>` by name on every directory the
  engine writes outside its data directory**, such as a File connection's, or a store placed
  elsewhere with `-DbPath`. The installer still grants the data directory and the logs itself.
  `-SkipRestrictedServiceSid` opts out of the restricted SID. `-AllowLocalSystem`, and a
  `-ServiceAccount` naming any other account, such as a gMSA, get the privilege list and not the
  restricted SID, and the installer says so. **This does not contain code that runs inside the
  engine**, which can ask Windows for a token that is not write-restricted.
  `uninstall-service.ps1` now reports a service that Windows has only marked for deletion, the one
  case where both settings outlive the uninstall. See
  [SERVICE.md](docs/SERVICE.md#restrict-the-service-token). (vault `BACKLOG #2702`)
- **The web console seam digest covers each console route's gate.** A console route calls the
  engine's handler in process, which skips the handler's own gate, so the console route's gate is
  the only one on that path. A change to that gate moved neither the console version nor the seam
  digest, so a console build that kept an older gate passed the start-up handshake. Engine PR 1910
  put a step-up on `/ui/dr/activate` and `/ui/dr/release` that way. The seam snapshot now records
  what the console installs: each route's top-level dependencies, gates included, with their own
  source and captured settings, and its mounts, middleware and WebSocket authorizer. A console
  built from a tree whose route gates differ in what the snapshot records pins a different digest,
  and the engine refuses it at mount with `UiSeamMismatch`. The snapshot does not cover everything
  a gate depends on, such as module-level data it reads. A console change that adds a route,
  changes a gate, or edits a console helper a gate calls by plain name now needs an engine that
  ships the new seam. A helper reached another way, such as through a module attribute, does not
  move the seam. The released console 0.4.0 passed the handshake of engines from
  PR 1910 up to PR 1940, whose unrelated seam move refuses it. See [WEBCONSOLE-PACKAGE.md](docs/WEBCONSOLE-PACKAGE.md).
  ([BACKLOG #2709](docs/BACKLOG.md))
- **A start warning when no Administrator can sign in without an outside service.** When every
  enabled Administrator needs Active Directory or a federated identity provider to sign in (a local
  one with an expired temporary password or none at all does not count), the
  engine logs a WARNING naming them and writes one `auth.no_local_administrator` audit row. It never
  refuses the start. Keep a local Administrator, made before you need it; see
  [SECURITY.md](docs/SECURITY.md). ([BACKLOG #2711](docs/BACKLOG.md))
- **`provision-admin` runs whenever no enabled local Administrator has a usable password.** It used
  to refuse while any enabled Administrator existed, and a directory or federated one counted. A
  site whose Administrators all sign in through Active Directory or an identity provider then had
  no host command to get back in during an outage. The refusal now reads the same check as the
  start warning. Whenever the warning names accounts, those accounts do not block the command. It
  can still refuse for other reasons, such as the password policy. It may now add an Administrator
  beside directory ones, and its audit row lists them in `administrators_at_check`. It still
  never promotes a directory account. A local Administrator with no usable password is refused by
  name, so make the new one under another name. The load-test rig keeps the old rule: it
  provisions its account, with or without an authenticator key, only into a store with no enabled
  Administrator at all. See
  [ADR 0183](docs/adr/0183-provision-the-first-administrator-offline-no-default-account-at-first-run.md)
  Amendment E and [SECURITY.md](docs/SECURITY.md). ([BACKLOG #2711](docs/BACKLOG.md))
- **`icacls` and `sc` no longer get the engine's whole environment.** The store's file-permission
  calls, the trust-anchor permission check and both service-state reads now start their tool
  with the platform's start-up names and nothing else, from the new
  `childenv.system_tool_environment()`. The engine's secrets, its `MEFOR_*` variables and the
  interpreter variables no longer reach those tools. The developer's `messagefoundry check`
  still runs `ruff` and `mypy` with the developer's whole environment, as an accepted
  exemption. (vault `BACKLOG #2716`)
- **BREAKING: `serve` always requires sign-in, on every bind.** It used to let a loopback bind with
  no declared TLS terminator run with `[security].require_sign_in = false`. Every request then ran
  as one shared system identity, so the audit trail named no person, and the mode could not repair
  an account: creating an account, unbinding one and reading the audit log all answered `503`.
  `serve` now refuses to start with sign-in off, and `[security].require_sign_in` and
  `[auth].enabled` are refused at load as removed keys, from the file or the environment, whatever
  their value. Delete the line. Embedders and tests keep `allow_no_auth=True` on the app factories;
  `serve` never passes it. The VS Code security editor and the web console's posture table no longer
  show the switch, and the container and Kubernetes examples no longer set it.
  See [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). ([BACKLOG #2719](docs/BACKLOG.md))
- **A sandbox worker that loaded edited config code is refused.** The engine already refused a
  `[sandbox].mode = "subprocess"` worker whose graph had different names. It now also compares a
  digest of the bytes of every `*.py` in the config directory, as each side loaded it. So after a
  config file is edited on disk with no reload, the next worker that starts is refused, instead
  of running a Router or Handler body nobody reloaded. Under the default
  `internal_error = "continue"` each message on that inbound dead-letters with an error naming
  `config module content`; under `"stop"` the inbound stops. A load whose config modules change
  while it runs is refused too. Reload the config. A worker refused because its graph differs
  from the engine's also raises a new `sandbox_worker_refused` alert, keyed by the inbound's
  name, once per refusal and not once per message, under either `internal_error` setting. A
  worker whose load fails, such as an edit that no longer imports or a load the change refused
  mid-run, raises no such alert. Its text names the cause and the remedy and
  carries no message content (owner ruling 2026-10-16: alert, keep dead-letter). Alert rules can
  route it by `event_type`. [CONFIGURATION.md](docs/CONFIGURATION.md) says, under `[sandbox]`,
  what an operator sees meanwhile. The spawn guard in
  `tests/test_child_process_environment.py` now also refuses an environment dict that is changed
  after a builder made it, and `worker_environment()` takes `defaults=` for the one value the
  sandbox used to set afterwards. (vault `BACKLOG #2724`)
- **`audit-verify` no longer reports a chain it could not check as a broken one.** Run from a shell
  that holds no store key, on a chain whose first row names a key, it exited 1, the code
  `docs/SECURITY.md` reserves for a broken chain. A scheduled job that reads only the exit code
  would have reported tampering on an intact log. It now exits 4 and prints a `NOT CHECKED` line
  saying no key is available and that the first row may have been changed. The store's verify sets
  this with a flag, never by matching text, and only in a process that holds no key, so a verify
  run with the key still exits 1 on the tampering it can see. Where the settings allow the store to
  run keyless (the audited opt-out), a chain that names a key still exits 1. Without a key the walk
  still checks at least the sequence numbers, the key-range digests and any expected anchor, and a
  break there exits 1.
- **One setup is weaker than before.** Take a keyless store verified from a shell whose settings
  require a key. A writer who rewrites the first row to name a key turns later edits into exit 4
  rather than 1. The vault BACKLOG #3054 entry says how that setup now reports.
- A store key the settings name that cannot be resolved while the store opens, such as
  `vault_transit` with no Transit key named or an unreadable key file, now exits 2 (could not
  start) from `audit-verify` and `audit-anchor`. It used to reach the dispatch floor and exit 1. A
  malformed key still exits 1. A `--service-config` path that is a directory or unreadable now
  makes `audit-verify` exit 2 rather than 1. Vault BACKLOG #2725.
- **A gated JSON route refuses a caller with no session before it reads the request body.**
  FastAPI decodes a declared body before it runs a route's dependencies, and the sign-in check
  is a dependency. So 34 gated routes answered a malformed body from the parser, with a 422 or
  a 400, where every other unauthenticated request gets the gate's 401. One route class now
  runs the gate's authentication step first on each gated route that declares a body. The
  answer no longer says whether the body parsed or whether the route takes one. A signed-in
  caller gets what it got before. The gate still runs in full after the body, so a signed-in
  request to such a route resolves its caller twice. [SECURITY.md](docs/SECURITY.md) has
  the detail and the limits under *Enforcement model*. (`vault BACKLOG #2739`)
- **Every `messagefoundry` command installs the remote-debugging guard, before it parses its
  arguments.** `rotate-key`, `backup`, `restore` and the rest have it, not only `serve` and
  `supervise`. The start-up window in which an injected script still runs is shorter.
  **`python -m pdb -p <pid>` cannot attach to any `messagefoundry` command.** Start the command
  under the debugger instead, as `python -m pdb -m messagefoundry <command>`. The refusal's log
  line writes the script's file name in printable ASCII, with a backslash escape for every other
  character and for the backslash itself. So a lone surrogate in the name does not keep the line
  out of the `[logging].file` sink or the syslog forwarder.
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md) says what stays open.
  (`vault BACKLOG #2742`)
- **Turning off a size cap on an HTTP, File or SFTP/FTP inbound now logs a warning.** Setting
  `max_body_bytes` on an HTTP inbound, or `max_file_bytes` on a File or SFTP/FTP inbound, to `0` or
  `None` is still allowed and still removes the cap. The connection now logs a warning each time it
  is built, naming the connection and the setting, never the value. (`BACKLOG #2749`)
- **The POSIX config-source check trusts an owner that is root or the engine's own user, and
  only root when the engine runs as root.** The check exempted a root ENGINE instead of a root
  OWNER. So an engine running as root would have executed config modules owned by any user, and
  an engine running as a service account refused a root-owned, read-only config, which is the
  safest layout. It now compares the owner against the engine's effective uid (`os.geteuid`), the
  rule the trust-anchor path check already used. **An engine run as root now refuses a config
  directory or module owned by an ordinary user**, such as a developer's own checkout. The
  container image leaves `/config` root-owned, and
  [`docker/README.md`](docker/README.md) now recommends root-owned config files rather than
  `chown` to uid 10001. See [SERVICE.md](docs/SERVICE.md). (vault `BACKLOG #2759`)
- **A production instance refuses `DEBUG` logging at run time, as it does at start-up.**
  `serve` refused to start at `DEBUG` on a production instance, but `PATCH /logging/level`, held by
  the `monitoring:diagnose` permission an Operator has, could switch the live level to `DEBUG` with
  no posture check, and the change survived `/config/reload`. On a first deployment that would let
  PHI reach the general log and any off-box forwarder. Both paths now use one predicate,
  `logging_setup.level_refused_on_production`. The route answers a refused level with a 403 that
  names the posture, leaves the level unchanged, and audits the attempt as
  `logging_level_change_denied`, and `GET /logging/level` no longer offers `DEBUG` there. A
  non-production instance can still switch to `DEBUG`. ADR 0130's
  "the level knob is not PHI" and the [PHI.md](docs/PHI.md) text that described the run-time
  switch as a qualification are corrected. (vault `BACKLOG #2777`)
- **BREAKING: an attachment the sender labelled `text/csv` now downloads as `text/plain` with a
  `.txt` name.** It was served as `text/csv` with a `.csv` name. A sender can start a cell with
  `=`, and a spreadsheet evaluates that cell when it opens the file. The bytes and the stored
  label are unchanged, and the message page still shows `text/csv`. This narrows the double-click
  only: renaming the file to `.csv`, or importing it into a spreadsheet, still evaluates its
  cells. **Migration:** a client that files downloads by `Content-Type` or file name now sees
  `text/plain` and `.txt` for these documents. Do not map the stored label back to a `.csv` name,
  because that restores the risk. The limits are listed in
  [CONNECTIONS.md](docs/CONNECTIONS.md). Seat decision, not an owner ruling.
  (`BACKLOG #2802`)
- **A FHIR `transaction` or `batch` connection now screens every Bundle entry before it posts.**
  It must declare `allowed_entry_methods`, which has no default, and may declare
  `allowed_entry_types`. An entry whose method, URL form or type the lists do not cover is refused,
  and so is a Bundle that is malformed, repeats a JSON key or names another `Bundle.type`. The
  message is dead-lettered and nothing is sent. A connection without the method list no longer
  loads. See [CONNECTIONS.md](docs/CONNECTIONS.md), "A Bundle connection screens every entry".
  (`vault BACKLOG #2804`)
- **`FhirPeek.parse` now refuses a FHIR body in which a JSON object repeats a key.** A body for a
  single-resource interaction, such as create, update or a conditional one, that repeats a key is
  dead-lettered with code `bad-body`, and nothing is sent. A Router that peeks such a body takes the
  error path, and a `fhir_lookup` whose reply repeats a key fails. A wrapped update's 2xx reply that
  repeats a key is read keeping the first and keeping the last value of each key. When the two
  readings would be judged differently, the update is a permanent refusal, code
  `reply-repeats-a-key`, and is not recorded as delivered; ADR 0095 Amendment B.1 states the rule.
  The text of the `bad-body` refusal now names which check fired. A `transaction` or `batch` Bundle
  was already refused for a repeated key (vault BACKLOG #2804). Other reads still keep the last of
  two equal keys, at least `FhirResource.parse`, `RawMessage.json()` and the classification of
  other FHIR replies. See [CONNECTIONS.md](docs/CONNECTIONS.md), "Interactions".
  (`vault BACKLOG #2812`)
- **Every log sink now escapes the C1 controls, the bidirectional controls and the Unicode line
  and paragraph separators, not only C0 and DEL.** Before, a logged value holding U+0085, U+2028,
  U+2029, an 8-bit CSI (U+009B) or a right-to-left override reached stdout, the `[logging].file`
  log and the syslog forwarder raw, in both the text and JSON formats. A reader that splits lines
  with `str.splitlines`, a log shipper or the tray's View Log would have split one record into
  several, and a terminal tailing `serve` would have acted on them. Each one is now written as its
  Python backslash escape, so U+2028 appears as a backslash followed by `u2028`. So are the other
  invisible format characters, at least the soft hyphen, the zero-width joiners and the byte-order
  mark, and a lone surrogate, which used to make the file and forwarder sinks fail the write.
  Accented letters, CJK and other printable text are unchanged. What a request path, header or
  file name refuses is unchanged too. The alphabet is `_escapes_in_a_log_line` in
  [controlchars.py](messagefoundry/controlchars.py). (`vault BACKLOG #2815`)
- **No setting can turn sign-in off, in a config file or in code (vault BACKLOG #2825).**
  `AuthSettings.enabled` is gone. Since vault BACKLOG #2719 no file or environment variable could
  set it, but an embedder building settings in code still could. Settings built in code through
  validated construction now refuse the key; `model_construct` and `model_copy(update=...)` skip
  validation, and nothing reads the key, so sign-in stays on. A built `AuthService` always requires
  a session, and has no `enabled` switch. **CORRECTED for vault BACKLOG #3062:** this said its
  `enabled` was a read-only `True`; #3062 removed the property. The only way an app runs without
  sign-in is the app factories' `allow_no_auth=True` with no auth settings and no service.
  Before this, an embedder could attach a disabled service beside that opt-in. Both `create_app`
  and `create_managed_app` now refuse `allow_no_auth=True` beside an
  auth service or auth settings. The security loosening report names the plain-LDAP, new-address
  step-up and sign-in limit entries without a sign-in gate, since there is no longer a sign-in-off
  state to hide them. `serve` was already always signed in, so a deploying site would see no
  change. The web console's supported engine seam moves.
- **A start's `config_loaded` audit row names the graph that start loaded.** The row read its
  fingerprint and its inbound and outbound counts from the engine when it was written, after
  `engine.start()`. On a clustered node a convergence reload could land in that gap, so the row
  would have named the reloaded graph, and the digest the start really loaded would appear in no
  row. The start now takes one snapshot of its fingerprint, directory, shard and counts right after
  its first load. Its config change comparison and its row both use that snapshot. When a reload
  swapped the graph before the row was written, the row is marked `superseded` and
  `baseline_unchecked`, and records `loosenings` as `null`. A later start passes over it, so it
  would not raise a false `config_changed` on the reloaded bytes. If the start cannot take its
  snapshot, it still starts, but it skips the config change comparison. Its row is degraded with
  the `start_snapshot` step and names no graph. A later start passes over that row.
  A reload's `config_reload` row is unchanged: it still names what the reload put live.
  (vault BACKLOG #2838)
- **A DR activation keeps the graph the running engine serves.** `POST /dr/activate` used to
  reload the startup `--config` dir. On a first DR deployment, an activation after an operator
  reload from another allowed root would have put the older graph back, and nothing would have
  said so. It now re-applies the graph already running; see the vault BACKLOG #3067 entry. The
  cluster convergence reload still reads each node's own startup dir. (vault BACKLOG #2840)
- **The DR seed marker's config digest no longer fails an activate or a release.** The
  coordinator behind `POST /dr/activate` and `/dr/release` used to take that digest when it was
  first built, on the event loop, and it caught only `OSError`. A config file name that cannot be
  encoded as UTF-8 would have made every activate or release fail, for as long as that file stayed
  in the config dir. The marker now records the provenance digest of the running graph, which the
  engine took off the event loop when it loaded that graph. Where that load took no digest, the
  marker records none and the activation goes on. (vault BACKLOG #2839)
- **An `Email()` destination's `sender` is now held to the recipients' address rule.** It must be
  one plain `local@domain` that reads back unchanged, so a display name, a group or an encoded word
  is refused at config load. `From:` is built from the checked text, and the same text is passed to
  the SMTP client as the envelope sender, rather than being derived from a parse of the header.
  (vault BACKLOG #2841)
- **A mail subject or alert template holding a lone surrogate is refused at load (vault BACKLOG
  #2842).** In the Email destination's `subject`, most surrogates made the message build raise
  `UnicodeEncodeError` at every send. Those in U+DC80 to U+DCFF went out as a garbled subject
  instead. The Direct destination already refused the first kind at load, through its construction
  probe, and now refuses the second kind too. `[alerts]` refuses one in `email_subject_template`,
  `email_body_template` and `email_html_template`. The refusal names the setting and never quotes
  its value. TOML cannot hold a surrogate, but at least Python config and environment values can.
  On a first deployment, such an Email subject would have dead-lettered every message on its lane
  as an internal error. Such an alert template would have failed or garbled every alert email. A
  non-ASCII sender address was already refused at load on every mail path, by the address rule.
- **Three domain lists and the mail address check now share one host-name rule.**
  `[security].organization_domains`, `[security].external_link_allowlist` and
  `[egress].allowed_recipient_domains` each checked an entry's shape their own way. The two
  `[security]` lists refused only `/`, `:` and `*`. They accepted a mail address and a non-ASCII
  domain, and neither ever matches a console host. They also accepted a partial IP address such as
  `0.1`, which would have matched every host ending in it. The egress list accepted hexadecimal
  IPv4 forms such as `10.0.0.0x1`, which the send rule refuses. All three now refuse at load what
  the address rule's domain check refuses, as listed under `allowed_recipient_domains` in
  [CONFIGURATION.md](docs/CONFIGURATION.md#egress). An underscore is refused too. The
  `[security]` lists used to drop a leading dot, and the egress list a trailing one. Both dots are
  now refused. The `[security]` lists still accept a dotted-quad IPv4 address such as
  `10.20.30.40`. An identity provider can be reached by address. The console now matches such an
  entry exactly. Domain matching is unchanged. (`vault BACKLOG #2843`)
- **The FastAPI floor is now 0.140.0, superseded in this release by `fastapi>=0.143.1`.** On 0.137.0 and 0.137.1 the route-gate walk in
  `scripts/security/route_gates.py` left every route added through `include_router` out of its
  gated view. It showed each include as one bare `MOUNT` row instead. Those releases hide included
  routes and lack `iter_route_contexts`. The walk now imports that call directly, so a FastAPI
  without it fails at import. On 0.137.2 to 0.139.x the walk is complete, but the guard against
  sync route dependencies cannot run. The engine still refused an undeclared route at request time
  on 0.137.0 and 0.137.1. The lock already pins 0.141.1. (`vault BACKLOG #2845`) In this
  release the lock pins 0.143.1.
- **The engine now counts every refusal of a route that declares no authorization.** It used to
  log only the first refusal of such a route, so a later burst wrote nothing. The ERROR line now
  repeats at most once a minute for each route. Each line says how many refusals came since the
  previous one. Refusals after a burst's last line reach the log only with a later refusal of that
  route, a minute or more on. The line names the route's path template and never the request.
  (`vault BACKLOG #2846`)
- **The route walk in `scripts/security/route_gates.py` says what the refusal makes of each row.**
  A row's `kind` is `gated`, `public`, `in-body`, `refused` or `outside`. Its `declaration` carries
  the reason a `public_route` or `authorizes_in_body` mark gives. The DAST sweep fails a run when
  an ungated HTTP route is not declared public with a reason. The walk reads a mounted
  application's WebSocket hooks from that application. A test now tries every non-boolean
  `create_app` parameter for routes the full-surface app lacks. (`vault BACKLOG #2846`)
- **The MLLP frame deadline now starts on the first byte of any kind, and `stop()` clears the
  per-host counts in a `finally`.** `max_frame_seconds` on an `MLLP()` inbound used to start only on
  a frame's start byte. Bytes outside a frame reset the idle bound but never started the deadline,
  so on a first deployment a peer trickling them would have held a slot with no frame deadline. The
  clock now starts on the first byte after the last completed frame, as on raw TCP and X12, and runs
  on the same shared clock. A completed frame stops it, and up to two CR or LF bytes directly after a
  frame's end byte, such as MLLP's CR trailer, count as part of that frame even in a read of their
  own, on MLLP and raw-TCP inbounds alike. **Keep-alive bytes between frames do start it**: a sender that keeps a quiet socket
  open with them is closed at `max_frame_seconds` with a `frame_deadline` reason, even where
  `receive_timeout` is longer or off. The MLLP `stop()` now clears the per-host table even when it is
  cancelled or fails part way, as the raw-TCP, X12 and HTTP listeners already did. See
  [CONNECTIONS.md](docs/CONNECTIONS.md).
  ([BACKLOG #2847](docs/BACKLOG.md))
- **An MLLP or TCP delivery refuses a payload holding more than one message.** In the shipped code
  a Handler that returned two HL7 messages in one `Send` had them framed and sent as one frame, so
  a receiver splitting on `MSH` would read two messages under one acknowledgement and the engine
  would count one. Now a payload that opens with `MSH` and holds a second `MSH` line, CR or LF line
  ends alike, is a permanent failure with code `multiple-messages`, dead-lettered at once with text
  that carries no message content. A live send, each batch member and a shadow outbound give the
  same answer. The `BHS` envelope of outbound batch aggregation, an X12 relay over TCP and any
  other payload not led by `MSH` are never refused by this rule. HTTP and File outbounds are
  unchanged. See
  [ADR 0209](docs/adr/0209-mllp-and-tcp-deliveries-refuse-a-payload-holding-more-than-one-msh.md).
  Vault BACKLOG #2858.
- **A `Direct()` destination and the `[alerts]` email sender now hold their addresses to the
  `Email()` destination's rule and pass the SMTP envelope explicitly.** The sender must be one plain
  `local@domain`, and each recipient must read as one once a display name or group is dropped. `From:`
  and `To:` are built from the checked text. The same text goes to the SMTP client as `MAIL FROM` and
  `RCPT TO`, instead of coming from a parse of the headers that decodes encoded words. Before this, an
  encoded-word or group address in the config would have moved the envelope on a first deployment.
  Direct checks at config load. On the alert side, `email_from`, `email_to` and any rule
  `recipients` override that can reach email are checked at startup. Every send checks again,
  per-user security notices included. `alert add` checks a new rule's override when its settings
  file configures email. A notification address must now pass the same rule when it is set. That
  holds for the user, for an administrator through the API, and for the `admin-set-notify-email`
  and `provision-admin --email` host commands. `admin-set-notify-email` used to accept a host-only
  address such as one at `localhost`. `provision-admin --email` used to check only the length, so it
  took any text, a two-address list included. Both refuse those now. A recipient entry holding a
  line break is now refused, by `Email()` and its `[egress]` check too, rather than sent with the
  break dropped. (vault BACKLOG #2870)
- **BREAKING: a start now refuses a CRL file that holds a CRL proven badly signed.** When a hop
  builds its TLS context, the engine checks each CRL's signature against the CA certificates that
  hop lists. It refuses one case only: the CRL names a listed CA's key by key identifier, and that
  key did not sign it. Before, such a file started clean and then failed the handshakes it judged
  with `CRL signature failure`, an error that does not name the file. Anything short of that proof
  still loads with a WARNING. At least these do: an issuer the hop does not list, a CRL that
  names no key, and a key the engine cannot check with. No setting turns the check off. The refusal has the reach of the
  expired-CRL refusal. **Migration:** give the setting the CRL its CA signed. A badly signed copy
  also refuses the file beside a newer good CRL from the same issuer, a file whose handshakes
  passed before; remove the bad copy. The cases, how often the WARNING is logged and the reach
  are in [CONFIGURATION.md](docs/CONFIGURATION.md), under "CRL files".
  Owner ruling 2026-10-05. (`BACKLOG #2905`)
- **The email address rule now checks the shape of the domain, not just its characters.** It
  refuses an empty label, a dot at either end of the domain, a label that starts or ends with a
  hyphen, and a label longer than 63 characters. It also refuses a domain whose last label does
  not start with a letter, such as a bare IP address: SMTP writes an IP address only in brackets,
  and the bracketed form was already refused. The letter test also catches hex forms such as
  `a@10.0.0.0x1`, which an IPv4 parser reads as an address. The rule covers at least the `Email()`
  and `Direct()` sender and recipients, the `[alerts]` email sender, recipients and rule
  overrides, and per-user notification addresses. Before this, `a@example.org.`, `a@example..org`
  and `a@10.0.0.1` would have passed every cell but one on a first deployment. That one is an
  `Email()` recipient: `[egress].allowed_recipient_domains` could list none of these domains, so
  it already refused them, under a less useful reason. A hex form could be listed there, so it was
  open on that cell too. (vault BACKLOG #2911)
- **An `Email()` destination's `sender` domain must now be in `[egress].allowed_recipient_domains`.**
  The sender is the envelope sender, so bounces and replies go to it, and they can carry the
  message body. An unlisted sender domain is refused at config load and reload, with the same exact,
  case-insensitive match as a recipient; a subdomain needs its own entry. There is no new setting.
  At least the `[alerts]` sender, the per-user security notifier's sender and `Direct()` are not
  gated by it. See the 2026-10-10 amendment to
  [ADR 0029](docs/adr/0029-email-smtp-destination.md). (vault BACKLOG #2912)
- **An administrator's password reset or MFA reset clears the account's known sign-in addresses.**
  An address learned before the reset no longer reads as known, so the next sign-in from it is
  judged first-seen, with what that verdict does on its leg. The reset leaves one marker row, so
  an account that never stamped a last sign-in is still judged rather than failed open. Revoking
  every session clears nothing. A failed clear is logged at ERROR and does not refuse the reset.
  See [SECURITY.md](docs/SECURITY.md). (vault `BACKLOG #2946`)
- **`GET /security/posture` now reports how often the deny-by-default refusal fired.** The new
  `undeclared_route_refusals` field counts the requests refused on a route that declares no
  authorization, keyed by the route's path template and never the request path. The count was
  kept on the route object, where nothing read it. An operator on a first deployment would have
  read it only from the throttled ERROR line, which reports refusals after a burst's last line
  only with a later refusal of the same route. It is read under the existing `monitoring:read`
  permission, and it is the count of the process that answered. The count is not persisted, and a
  restart starts it again at zero. The web console seam digest moved, because `SecurityPosture`
  grew. (`vault BACKLOG #2954`)
- **Four older edges of the route-gate walk and the deny-by-default refusal are closed.** The
  refusal's ERROR line names a route by the key `GET /security/posture` reports it under, so an
  included route is logged with its include prefix rather than under a path the app does not
  serve. The route walk refuses a marked gate that is not a closure, which it read as gated with
  no gate name and counted among the ungated routes at once. A plain Starlette `WebSocketRoute`
  is labelled `PLAIN-WS` rather than `MOUNT`, and stays in the ungated set a reviewer reads. A
  test now fails when an included route that takes a body is gated or undeclared and would have
  that body parsed before its refusal. An included router built with the engine's route class
  refuses a gated route early, but not an undeclared one, which can answer first with the body
  parser's 422 or 400. The operator doc no longer says such a route is refused before its body.
  (`vault BACKLOG #2956`)
- **The anonymizer keeps a numeric `OBX-5` only when it fits the grammar of its own type.** One
  character class used to serve `NM`, `SN` and `TM`, and any run of digits and marks fitted it. So
  a value of SSN shape or phone shape under a numeric `OBX-2`, such as `123-45-6789`, would have
  left whole, in a field the leak-check's shape detectors do not scan. Each type now has its own
  grammar: a number for `NM`, with an optional leading comparator; a comparator, a number, a
  separator and a number for `SN`; a range-checked time of day for `TM`. A value that does not fit
  becomes `[REDACTED]`. **This changes output for some non-conformant values, at least these:** a
  ratio or a clock time under `NM`; a bare number or an unsplit `<5` in the first component of an
  `SN`; and a time written with colons under `TM`. A message that declares a digit or one of
  `+ - . : / < > =` as its component, repetition or subcomponent separator keeps no numeric
  `OBX-5` value. The guard does not read the field separator. The vendored
  `tee/anon/surrogates.py` copy changes the same way. An undashed nine or ten digit number is a
  valid `NM` and is still kept, and the coded types `ID`, `IS`, `CE` and `CWE` are not changed.
  [PHI.md](docs/PHI.md) section 9 names these gaps and the field-separator one.
  (`BACKLOG #2961`)
- **A release goes public only after every PyPI upload its run makes.** The harness upload is now a step
  of the engine's `publish-pypi` job, after the engine, so one approval of the `pypi` environment
  covers the toolkit, engine and harness uploads, and that job waits on the harness build. The
  engine's GitHub release is published only after all of them; with `PUBLISH_HARNESS` unset, the
  harness is not uploaded and the release still goes public. The console's GitHub release is now
  created as a draft too, and a new job publishes it once its PyPI upload job has succeeded; with
  `PUBLISH_WEBCONSOLE` unset that job uploads nothing, but still asks for the `pypi` approval, and
  the release still goes public. Each release publisher re-reads its variable when it runs and fails
  the run, leaving the draft, while the variable is set and that run skipped the upload. The release job
  takes its PyPI digests right after the last step that writes the published files.
  (`vault BACKLOG #2975`)
- **Each Vault hop now refuses an off-box Vault whose certificate revocation nothing checks,
  unless that hop is attested.** The store key provider, the Transit cipher and the connector
  secret provider each verify the Vault server's certificate and check no CRL and no OCSP. The
  client build now refuses an `https://` Vault that is not a loopback host reached with no proxy.
  The way across is a new settings pair, one per Vault: `[store].vault_revocation_attested` or
  `[secrets].vault_revocation_attested`, each with a mandatory `vault_revocation_attested_reason`.
  The attestation adds no check on the wire, and no CRL lever is built for these hops. The
  process-wide `MEFOR_TLS_REVOCATION_ATTESTED` does not cross an enforcing hop.
  `security_loosenings()` names each attestation with its reason, `messagefoundry check` lists
  it, and an attested crossing logs a WARNING once per process for each hop.
  On an instance at `[security].enforcement = warn`, a caller that hands its posture to the hop
  crosses with a WARNING. A command that holds no posture is judged as enforcing, so it still
  refuses. `check-privileges` probes each Vault under that hop's own attestation.
  One gap is named and not closed: through an `https://` proxy, nothing checks revocation of
  the proxy's own certificate. See [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md).
  (`vault BACKLOG #2983`)
- **Follow-ups to the refused HTTP Digest challenge, and a 2xx reply that cannot be read is no
  longer sent again.** (`BACKLOG #2989`) On the REST, SOAP, FHIR and DICOMweb destinations:
  - A Digest challenge with no realm or nonce, or whose `qop` does not offer `auth`, is now refused
    as `auth-challenge-refused`, a configuration fault that stops the lane and keeps the queue under
    the default `credential_fault_policy`. Before, it read as a plain 401 or 407, or as an
    unreachable host that was retried. A `qop` list such as `"auth-int, auth"` is now answered with
    `qop=auth`.
  - The OAuth2 and SMART token hop raises the same fault for a web proxy's refused challenge on an
    `http://` token endpoint, instead of a retryable error. An `https://` token endpoint meets the
    proxy inside a tunnel, where its challenge is still read as unreachable and retried.
  - A 407 on a request that went direct, not through the configured web proxy, surfaces as the 407
    it is, instead of as the proxy's refused challenge.
  - A send-time hop refusal is now a configuration fault with the code `insecure-hop-refused`.
    Before, the raw refusal left the send unclassified and was filed as an internal error.
  - A 2xx reply body cut short of its declared length, or misframed, follows the rule the owner set
    for an over-size one on 2026-10-05: the request is sent once. Where nothing reads the body the
    message is delivered, gets a `reply_dropped` event that says what was wrong, and a WARNING is
    logged. Where the engine needs the body it is a permanent
    refusal with the code `reply-truncated` or `reply-misframed`. ADR 0095 Amendment B.1 records
    who decided this. The table is under REST in [CONNECTIONS.md](docs/CONNECTIONS.md).
- **The de-identification site-code loader reads one fixed token path and no longer searches
  parent folders.** With `MEFOR_FORBIDDEN_TOKENS` unset, `anon/surrogates.py` used to try
  `scripts/security/scan-tokens.local.txt` in every folder above its own file and read the first
  match. A file at that path above an installed copy would have set the site-code prefixes. It now
  builds one path, under the folder that holds the package, the same folder `anon/leak.py` uses for
  the publish guard. The vendored `tee/anon/surrogates.py` copy changes the same way. A git
  worktree nested under another checkout no longer picks up the outer checkout's token file: give
  the worktree its own copy, or set `MEFOR_FORBIDDEN_TOKENS`.
  [DANGEROUS-FUNCTIONALITY.md](docs/DANGEROUS-FUNCTIONALITY.md) now says the leak check needs a
  source checkout or an editable install. (`BACKLOG #2995`)
- **A de-identification rule on a `BHS` or `FHS` field now reaches the field the leak-check
  counts.** Field 1 of a batch or file header is the field separator, as `MSH-1` is. The engine
  anonymizer numbered those fields that way. Its leak-check and the tee anonymizer did not, so
  they counted one field to the right. With a rule on `BHS-5`, a dashed SSN in `BHS-6` would have
  passed `anonymize_checked` on the engine, and the tee would have rewritten a different field
  from the engine. Both anonymizers and both leak-checks now use the header numbering for `MSH`,
  `BHS` and `FHS`. No default rule names a `BHS` or `FHS` field, so which field gets rewritten
  changes only for an overlay that maps one. The other changes below reach every caller: the
  addresses in a coverage report, the refusal of a short header line, and the site-code pass.
  **Breaking for such an overlay:** on the tee, a `BHS-N` or `FHS-N` rule now rewrites the field
  one to the left of the field it rewrote before. On both sides the leak-check and its coverage
  report now name each `BHS` or `FHS` field one number higher: the encoding characters are
  `BHS-2`, where they were `BHS-1`. A `keep` or a rule written against the old address now
  decides the field one to the left, so `require_full_coverage` can refuse a message it passed
  before. Both anonymizers now refuse a rule that would
  rewrite `BHS-1`, `BHS-2`, `FHS-1` or `FHS-2`, per message and when `anon.toml` loads. Before, a
  `drop` on `BHS-1` loaded, and the output line lost its delimiters. A `keep` on any of the four
  still loads.
  **Both anonymizers now refuse a message with a short `MSH`, `BHS` or `FHS` line after the
  header**, one with no separator after its encoding characters. The engine anonymizer would have
  written `BHS|TEXT` back as `BHS|TEX|BHS|TEXT`, and its check would have passed a dashed SSN on
  that line. A leading `BHS` or `FHS` line that short is refused too.
  The site-code pass no longer exempts a field on a `BHS` or `FHS` line as date output. A `DATE`
  rule there used to exempt the field one to the right of the one it wrote.
  The engine's HL7 parser is unchanged: it still re-encodes such a short line out of shape for
  any other caller. (`vault BACKLOG #2998`)
- **A line that is a bare segment id now leaves a coverage record, and the anonymizer's
  leak-check reads one header line.** A line with no field separator passes the checked
  anonymizer when its whole text is a segment id the message's HL7 version defines, or a rule
  names. That is a legal empty segment, and it still passes. But a wrapped line of free text that
  is exactly such an id looks the same, and the coverage report held nothing for it. The report
  now names each such line by its segment id, as in `PV2 (line with no fields)`, with no line
  position. `require_full_coverage` refuses the line unless a rule or a `keep` names any field of
  that segment, so a dataset with an empty `PV2` that it passed before can now be refused; add a
  `keep` on any `PV2` field to decide it.
  The leak-check also took the first line that started `MSH` as the header, even a bare `MSH` or
  `msh`, and judged every line ahead of the header against the segment ids of every HL7 version.
  The standalone tee would have emitted a leading bare `MSH` line whole, and a bare id that only
  a later version defines. The header is now the one line the separators are read from, and
  every line is judged against that header's own version. The engine anonymizer already refused
  these messages in its parser. (`vault BACKLOG #3001`)
- **A refused `FhirLookup` no longer stops the engine from starting.** Before this, one lookup
  whose hop was refused at start, such as an off-box https read with no CRL and no revocation
  attestation under `enforcement = enforce`, unwound the whole start. On a clustered node the
  graph never started, and the supervisor logged "will retry" on every pass. A refused lookup is
  now isolated like a lane, on every start. It is recorded failed, logged at ERROR, alerted as
  `connection_stopped` under `fhir_lookup:<name>`, and named in `/status` as
  `fhir_lookups_failed` to a caller with no channel scope. Every Handler call to it raises `FhirLookupError` before anything is
  sent. A message whose Handler lets that error through takes the error path. A Handler that
  catches `FhirLookupError` decides for itself, as it does for any failed read. The other feeds
  start. `messagefoundry check`, dry-run, reload and a DR activation still refuse the whole config
  while the lookup is refused, as they do for a refused lane. A reload or a restart with the cause
  fixed brings it back. A refused `tls_ca_file` on a lookup is a separate check and still refuses
  the start.
  (`BACKLOG #3008`)
- **An LDAP search that does not end with success is never "no such account".** Each search the
  engine sends refuses any result code but success, with or without entries. That includes busy,
  unavailable, unwillingToPerform and adminLimitExceeded. It includes a time or size limit, and
  noSuchObject on a missing search base. Before, such a search read as no entries. The session
  reconciler would then have struck a present account toward revocation. A busy nested group
  search read as fewer groups. A sign-in now writes `auth.login_error` naming the code, and
  `check-privileges` names the code for the bind-account read. These refusals name the operation
  and the code, never the directory's diagnostic message. Other directory errors keep the text
  they had.
  **The session reconciler tells a configuration refusal from an outage.** noSuchObject,
  invalidDNSyntax and insufficientAccessRights point at the configuration: a search base that was
  deleted or moved, or that the service account may not read. Such a refusal leaves that account
  unjudged and never revokes it. Every pass with one logs an ERROR naming the code, audits
  `auth.ad_reconcile_misconfigured`, and raises `ad_reconcile_aborted` with reason
  `directory_misconfigured` under the source `directory-reconciler-misconfigured`. A pass where
  every lookup is refused, faulted or fails, at least one refused and none referred, aborts as
  `directory_misconfigured`. Before, a deleted search base read as "not found" for every account,
  which tripped the mass-revoke breaker on a large enough estate. Nothing resolves the new alert
  automatically; an operator does. Any other code is an outage, which never revokes and pages
  nobody. A second-factor step-up or a passkey assertion, which probes the directory before it
  grants, refuses a refused account with outcome `misconfigured`. The password step-up and the
  federated step-up refuse it as `directory_unavailable`, as they do any directory error.
  **Not covered:** ldap3 fetches a ranged `memberOf` with follow-up searches of its own, and those
  are not refused.
  **The cost:** a code that recurs on every pass, such as a deleted search base, stops revocation
  and the role re-diff for as long as it lasts. A configuration code alerts; any other code warns
  once per process for each operation and code, and latches no alert.
  **The nested group search is paged**, at 500 entries per page. So an account in more groups than
  a directory's unpaged cap no longer fails sign-in with sizeLimitExceeded. AD's cap, MaxPageSize,
  is 1000 by default. A page that does not end with success refuses the whole search. So does a
  later page that drops the paging control, and a search past its paging bounds
  (`BACKLOG #3696`). The pages already read are never used as the whole answer. A refused paged
  search is abandoned (RFC 2696) once the directory has sent a cookie, at the cost of one more
  round trip. Paging was measured against a loopback server through ldap3, not against a domain
  controller.
  **A response ldap3 cannot decode is a directory error, not an unhandled error.** ldap3's default
  decoder raises `KeyError`, `TypeError`, `IndexError`, `AttributeError` or `UnicodeError` on a
  malformed response. Cases include at least a result code outside its table, a malformed paged
  results control, and a Who am I value that is not text. A sign-in that met one would have failed
  with an unhandled error and no audit row; it now writes `auth.login_error`. The searches, binds
  and Who am I read the engine sends now run inside one boundary. It maps such a fault to a
  directory error when ldap3 raised it reading the response, and lets any other exception
  propagate. The session reconciler still reads such a fault as a probe fault, as before: a WARNING
  for each account, and the `ad_reconcile_aborted` alert with reason `probe_fault` under the source
  `directory-reconciler-probe-fault`. It never revokes. After one, the engine closes the socket of a
  service-account bind that met it.
  **A bind response carrying a referral is a referral.** ldap3 cannot decode one. The boundary
  refuses it as a referral, naming no host. A sign-in writes `auth.login_error`, and the session
  reconciler reads it as referred and raises the `ad_reconcile_aborted` alert with reason
  `directory_referral`, as on any referral. That alert's text names the two search bases and
  `[auth].ad_bind_dn`, any of which may name another domain of the forest.
  Before, a sign-in that met one failed with an unhandled error, and the reconciler read it as a
  probe fault. (vault `BACKLOG #3010`)
- **A passkey registration staged before the account gained a factor can no longer finish.**
  `finish_webauthn_registration` now asks the factor-binding rule again at finish. A session that
  has not proven its second factor, on an account that holds one, is refused with a 400 and its
  ceremony is ended; the refusal is audited `auth.mfa_denied`. Before, a ceremony staged while the
  account had no factor would still finish after a TOTP was enrolled on another session, binding a
  passkey and promoting a session that never proved the TOTP.
  (`BACKLOG #3014`)
- **A refused audit write in one account's directory reconcile no longer ends the pass.** In the
  shipped code, three audit writes in the reconciler raised on any store refusal:
  `auth.ad_session_revoked`, and a rename's `auth.ad_username_refreshed` and
  `auth.ad_username_refresh_conflict`. The raise came after the revocation or rename had committed,
  or after a rename was refused. It cost the user's notice, every later account in the pass, and
  the pass's alerts. Now the reconciler logs such a refusal at ERROR, naming the action and the
  account, and the pass goes on. This covers the store errors the reconciler already treats as a
  refusal; any other error, or a defect, still raises. A revocation's notice still goes, and so
  does its alert, unless something later in the same pass raises and ends it. The login path is
  unchanged: there a refused write still fails the sign-in. Vault BACKLOG #3018, steps 1-6.
- **On SQL Server, the session writes that follow a committed auth change now wait longer for a
  busy pool, and the wait is still bounded.** Rotating a session and revoking a user's sessions
  borrow a store connection with 2 times the `[store].acquire_timeout` limit, 60 s at the default,
  then raise `StoreAcquireTimeout` as any borrow does. A `[store].command_timeout` of 0 does not
  lift that limit. Before, a pool shortage at the ordinary limit could fail them after a password
  reset, a disable, a role change or a completed second factor had committed, which left the
  account's other sessions live or the old token unrotated. A shortage that outlasts the longer
  limit still fails them that way. The statement timeout still applies. **A rotation the store refuses now fails closed on every
  backend.** The session is revoked, best effort, under its old and new hash, an
  `auth.session_rotation_failed` audit row with reason `store_error` records in `revokes_landed`
  whether every revoke landed, and the caller is told to sign in again. A cancellation, such as an
  HTTP request's deadline, is not covered. Before, the error escaped the ceremony and the old token
  kept working with the factor it had just proved. (`BACKLOG #3023`)
- **A sign-in now ends the session its presented token became, when an elevation finished first.**
  A console sign-in ends the session its browser presented. An elevation in another tab that
  finished during the sign-in used to leave that token naming no session, so the session lived on
  under its new token. Each rotation now records which token hash replaced the old one, in its own
  store transaction, in a new `session_lineage` table on SQLite, Postgres and SQL Server. The
  supersession follows those links to the live session and ends it, in the same transaction as the
  revoke, for `[auth].oidc_flow_ttl_seconds` plus 120 seconds after each rotation; the session reaper
  deletes older links. A retired token still authenticates nothing: no session read consults the
  links. `docs/SECURITY.md` states the bound that remains, and ADR 0210 records the design.
  On the server backends the schema change moves the ADR 0064 schema hash: under their default
  `[store].schema_management`, `external`, the engine refuses to open until `provision-schema` has
  run; under `auto` the next open runs the DDL.
- **Sign-out and revoking one of your own sessions no longer report a revoke that missed (ASVS
  7.4.1).** Both used to revoke by token hash with an update that could not tell whether it matched
  a row. On a first deployment, an elevation that gave the session a new token between the
  caller's read and the revoke would have left the revoke ending nothing, while
  `DELETE /me/sessions/{id}` answered 200 and wrote an `auth.session_revoked` row, and sign-out
  wrote the same `auth.logout` row either way. Both now revoke through `supersede_session`.
  `auth.logout` rows carry `detail.outcome`, `revoked` or `nothing_to_revoke`, and a console
  sign-out's row names the owner of the session it ended instead of a NULL actor. Both sign-out
  routes still answer the same either way. A self-revoke that
  ends nothing answers 404 and writes no `auth.session_revoked` row, only the
  `auth.session_revoke_missed` row an unknown id writes (vault BACKLOG #3260). A sign-out or self-revoke that loses that race still
  leaves the session live under its new token; ending it there is not attempted. (`BACKLOG #3029`)
- **`safe_exc` no longer quotes the character or byte an encode or decode error failed on.** It
  rendered a `UnicodeEncodeError`, `UnicodeDecodeError` or
  `UnicodeTranslateError` through its `str()`, which names the offending character or byte: a
  character of the message. Any connector that skipped the shared encode guard would have put it
  into `queue.last_error`, a dead-letter event or a `safe_exc` log line on first deployment. It now
  builds the text from the error's codec, position and reason only. A reason is kept only from a
  fixed list, since the stdlib idna codec quotes the input in it, and the class name stands alone
  when the attributes are missing. At least three paths render one elsewhere and are not covered:
  a traceback logged with `exc_info`, an exception passed as a `%s` log argument, and a Unicode
  error quoted inside another exception's message. The Email
  outbound's body backstop now wraps only the body encode. A header that cannot be encoded is
  reported as a configuration fault, handled under `credential_fault_policy`, rather than as a
  bad body. (vault `BACKLOG #3033`)
- **BREAKING: `[api].trusted_proxies` refuses a zoned entry, matches an IPv4 entry in both
  spellings, and two `[api]` lists split their env form on commas.** An IPv6 entry with a zone
  such as `fe80::1%eth0` is refused, because a peer is reported without its zone; list `fe80::1`.
  uvicorn ignores a network's zone, so a zoned network is refused too. uvicorn compares a mapped
  `X-Forwarded-For` hop such as `::ffff:10.0.0.1` only with a mapped entry, so behind a dual-stack
  proxy that writes mapped hops the entry `10.0.0.1` would have resolved the client to that hop
  rather than to the real client. The engine now hands uvicorn each IPv4 entry, and each mapped
  entry, in both its plain and IPv4-mapped spellings, so `::ffff:0:0/96` also trusts every plain
  IPv4 peer; the `trusted_proxies` row of `docs/CONFIGURATION.md` says how.
  `MEFOR_API_TRUSTED_PROXIES`
  and `MEFOR_API_WS_ALLOWED_ORIGINS` now split on `,` on every platform, as
  `MEFOR_SECURITY_ALLOWED_CLIENT_NETWORKS` does. They split on the path separator before, `:` on
  Linux and macOS, which broke an IPv6 entry or an origin's port apart; on Windows, a `;` list
  must be rewritten with `,`. (`BACKLOG #3042`)
- **The new-address audit action is renamed `auth.new_address_reverify_required`.** It was named
  for an admin action, but since vault BACKLOG #2620 it also fires on PHI reads and paced writes.
  The notice kind is renamed to `new_address_reverify_required` with it, and its WARNING lines now
  read "a request from a new client address must re-verify". There is no alias: a search or alert
  keyed on the old name must use the new one. (vault BACKLOG #3052)
- **`POST /me/notify-email` now asks the new-address question, as its console twin does.** It rode
  the base gate, so a token replayed from a host the session had not verified from could choose
  where the holder's security notices go, while `POST /ui/account/notify-address` refused the same
  request. It is now `require_paced`: refused with the step-up answer from a new address, and
  paced. (vault BACKLOG #3052)
- **A console page refused for a new address comes back with its path still encoded.** The
  continuation was built from the decoded path, so an encoded `?` inside an id became a query after
  the re-auth. A path the browser would rewrite before following the redirect (an encoded `/`,
  `.` or `\`, or a `.` or `..` segment) now falls back to the landing. (vault BACKLOG #3052)
- **`audit-verify` exits 5, not 0, when a keyless chain walks clean in a shell whose settings
  require a store key.** The settings say the check is keyed, and a plain SHA-256 walk is not that.
  It prints a `NOT CHECKED` line and a `WARNING` on stderr naming the mismatch. In that shell 5 is
  a keyless store's steady state, and a matching `--expected-anchor` does not change it. Exit 4
  keeps its meaning: the same shell, on a chain whose first row names a key. So a move between 4
  and 5 is a sign of tampering: a forged first row moves 5 to 4, and a keyed chain rewritten as
  keyless moves 4 to 5. To get a pass, give the job the engine's key, or the keyless opt-out the
  engine runs under. See [SECURITY.md](docs/SECURITY.md) "Tamper-evidence".
- `audit-verify` loads its settings as `audit-anchor` does, so a settings error is rendered by
  field and message and never stringified with the value it refused. Vault BACKLOG #3054.
- **Enrolling a factor on a directory account now needs the directory to confirm the account.**
  `confirm_mfa_enrollment` and `finish_webauthn_registration` ask the directory first, through the
  same check `verify_mfa` and `finish_webauthn_assertion` use, which also refuses an account that
  lost a role in the directory. Before, a first enrolment marked the factor met with no lookup, so
  on a first deployment an account disabled or demoted in the directory could clear the MFA gate
  by enrolling until the reconciliation pass revoked it. A refusal spends no TOTP step, mints no
  recovery codes, stores no passkey and keeps the passkey challenge, and is audited with
  `reason=directory_unconfirmed` and `phase=enroll`. The route's own step-up grant and attempt
  budget are still spent. `POST /me/mfa/confirm` answers it with a **403**. Both enrolment legs
  also ask the factor-binding rule again after the lookup, so a pending session on an account that
  gained a factor during it is refused with a **400** `this account already has a second factor`,
  audited `auth.mfa_denied`; on the TOTP confirm that refusal is for a passkey, before any step is
  spent. A directory account under a second-step lock is refused at enrolment as a lock, not as a
  wrong code: `POST /me/mfa/confirm` answers **403** `account locked; try again later`. A session
  found gone at an enrolment leg's factor-binding ask is audited with `reason=session_lost` and
  `phase=enroll`. The passkey page now covers a passkey left on the authenticator by a failed
  registration: a failed finish does not prove it was not stored, so the page sends the user to
  the account's Passkeys list first, and only a passkey missing from that list may be deleted from
  the authenticator, and a user who cannot tell which is which keeps it (vault BACKLOG #3807, #3810). See
  [SECURITY.md](docs/SECURITY.md). (`vault BACKLOG #3061`)
- **The open mode is an app with no auth service, and the code now says so.** `AuthService.enabled`
  is removed. It always returned true, and the API and web console guards that read it now ask only
  whether a service is attached. A removed settings key built in code, such as
  `SecuritySettings(require_sign_in=False)`, is now refused with a message naming the key, rather
  than dropped. `messagefoundry security show` on a file that still holds one now refuses the same
  way. `GET /security/posture` names the `allow_no_auth` open mode as a loosening when an app
  runs in it: no service attached, and the opt-in passed. The web console seam digest moves.
  (`vault BACKLOG #3062`)
- **`[inbound].ack_after = "delivered"` is refused when the settings load.** That ACK timing is
  planned, not built. A connection's own `ack_after = "delivered"` was already refused at wiring,
  but the service-wide default was refused only as each listener started. So
  `messagefoundry check` said OK, and `serve` came up with every listener that inherited it
  isolated. Now `serve` will not start on it, and the `check` settings legs fail. (`BACKLOG #3063`)
- **The build check gates the same listeners a reload binds, from one copy of the skips.** Start,
  reload, the reload's CA check and the predicate the build check runs the inbound exposure gates
  under now read one helper. An operator-started `auto_start = false` listener with a schedule,
  reloaded after its window closes, is no longer gated: the reload leaves it unbound, and the
  scheduler never starts it. An `auto_start` listener outside its window is still gated, because
  the scheduler binds it when the window opens. The build-check refusal no longer says a later
  start meets the same refusal. It says what each setting does: an operator start of an
  `auto_start = false` listener meets the refusal, and a `deployed = false` listener cannot be
  started, so the reload that deploys it, or its first start, does. A dry run and a flag toggle
  read the listening set outside the reload lock; the code says why that window is accepted.
  (`BACKLOG #3063`)
- **A DR activation on a running box now parks the feeds below the threshold.** The runner took
  its DR threshold only when it was built, and `POST /dr/activate` reloaded through that same
  runner. On a box that came up passive, an activation would have parked nothing and kept every
  feed bound. A runner built under the profile also kept parking feeds after `POST /dr/release`.
  The engine now sets the threshold on the running runner before the activation reload, puts it
  back if the activation is refused, and clears it on release, so a later reload binds every
  feed again. (vault BACKLOG #3067)
- **A DR activation applies the running graph, not the config dir on disk.** The activation used
  to reload the config dir, so bytes edited there after an approved reload would have gone live
  with no second person. It now re-applies the graph in memory, after the settings and registry
  preflights, and the build check still runs. If the dir on disk differs, the `dr.activate` audit
  row records both digests and the engine logs one WARNING. Only `POST /config/reload`, under its
  own approval gate, applies those bytes. The activation no longer needs the dir, so the refusal
  added for a dir that could not be listed is removed: a dir on a share at the failed site no
  longer aborts the activation. Such a dir is recorded as `unreadable`. (vault BACKLOG #3067)
- **Rows queued to a parked outbound are held, not dead-lettered.** A parked outbound's worker
  used to claim each row, find no connector and charge it a failed attempt, so a finite
  `max_attempts` would have dead-lettered rows only for being parked. The lane is now parked the
  way a start-disabled one is, and its rows stay PENDING with no attempt charged. The release
  drain leaves them out of its wait, and `dr.release` records `held_on_parked_outbounds` beside
  `depth_left`, with `drained` true once every other row has drained. (vault BACKLOG #3067)
- **Start, stop and restart of a DR-parked outbound are refused with `409`.** An alert rule's
  restart and the scheduler's resume log the refusal at INFO and do nothing, and so does an alert
  rule's restart of a parked inbound. The first reload or start after `POST /dr/release` brings
  the lane back. A lane an operator or its schedule paused before DR stays paused, and an
  `auto_start = false` lane follows its gate. A below-threshold `auto_start = false` outbound is
  now recorded as parked by the profile too, so an operator start under DR can no longer bring
  up a feed the profile parks. Purging a parked lane works. (vault BACKLOG #3067)
- **A second stop of a paused outbound no longer leaves it `stopping`.** The pause of an
  already-paused lane never signalled quiescence again, so the lane read `stopping` for good and
  purge was refused. (vault BACKLOG #3067)
- **Two more domain checks at load.** `[egress].allowed_recipient_domains` refuses a domain
  longer than 252 characters, which no 254-character address could carry. The two `[security]`
  navigation lists refuse an IPv4 address that is not one host's: at least `0.0.0.0`, which some
  browsers route to the local machine, a multicast address, and the reserved class E range
  with the limited broadcast address. The web console no longer strips a leading dot from a domain entry, so a
  dot-led entry from outside settings matches nothing. (`BACKLOG #3075`)
- **A cluster convergence reload now writes its own `config_reload` audit row.** It is the row an
  operator reload writes, with actor `system:cluster-convergence` and `initiator`
  `cluster_convergence`. Before, a node that converged on a sibling's reload wrote no row. The
  store's newest config baseline could then name the graph that node ran before. A restart on the
  converged bytes raised a false `config_changed`, and a restart that reverted them raised
  nothing. A convergence row with no fingerprint is marked `baseline_unchecked`, so it never blinds
  the next start's check. (vault BACKLOG #3076)
- **A clustered node converges on a sibling's reload that lands during its own start.** The node
  read the shared config version only after its first load. A sibling's bump in between then read
  as applied, and the node kept the bytes it had loaded. It now reads the version before the first
  load. If that read fails, the start goes on and reads it later, as before. (vault BACKLOG #3076)
- **A repeat reconciler revocation of one account is audited but not alerted, and only a verified
  repeat stays quiet.** In the shipped code, two reconcilers on one store could both revoke one
  account. Each wrote a row and raised an `ad_session_revoked` alert. For any reason but a scope
  change, each also sent the user a notice. The second ended nothing. Now a revocation that ended no
  session and changed no role still writes its `auth.ad_session_revoked` row, with `sessions: 0`
  (owner ruling 2026-10-16, "audit always"). When the directory says the account is disabled or
  absent, it still alerts and sends its notice, as when the user signed out mid-pass (owner ruling
  2026-10-17). It is quiet only when another pass's row for the same username and reason, numbered
  after this pass began to list the account's sessions, verifies under the active audit key (owner
  ruling B258-R7; the MAC check is vault BACKLOG #3750 item 33). A keyless audit chain, a row that
  fails its MAC or sits under a retired key, or a failed read makes it alert, so a database writer
  without the audit key cannot forge a row to silence it; `AuthService._already_revoked_elsewhere`
  names the residuals.
  Any other revocation that ends nothing and changes no role is quiet; if its own row is refused, it
  alerts, with no notice. If both reconcilers read the old roles, or both read before either writes
  its row, both still report. If the first reconciler's pass ended before it alerted, a quiet repeat
  revocation leaves the account paging nobody. Vault BACKLOG #3085, item 2.
- **The engine names directory reconciler settings that leave the mass-revoke breaker unable to
  trip.** The breaker trips only when a pass exceeds both thresholds. With AD on and a non-zero
  `[auth].ad_session_recheck_seconds`, the load now refuses an `ad_session_revoke_max_fraction`
  of `1.0`. An `ad_session_recheck_max_users` at or below `ad_session_revoke_max` still loads,
  and revocation still works, but the engine logs a WARNING at start that names both settings.
  Before, neither setting was refused or warned of. The validator message and
  [CONFIGURATION.md](docs/CONFIGURATION.md) used to say `1.0` disabled only the proportional
  half. (`BACKLOG #3085`)
- **Authoring docstrings and connection-editor help that name `MEFOR_ALLOW_INSECURE_TLS` now say it
  works only on an instance at `[security].enforcement = warn`.** Six factory docstrings in
  `config/wiring.py` and twelve parameter comments, which the connection editor shows as help,
  said the escape alone was enough. So did docstrings in the Email, Direct, remote-file and
  DATABASE transports and the Postgres store. Where a connection can instead declare
  `tls_hop_attested` or `cleartext_accepted`, the text now says so. No gate changed. The test
  that checks these texts now reads docstrings in six pinned files and comments in
  `config/wiring.py`, and it closes three gaps in how it read calls. Its docstring says which
  shapes and files it still cannot see. (`vault BACKLOG #3099`)
- **A directory probe that raises is now a probe fault, not a directory outage, and it pages.**
  After `BACKLOG #2241`, and never in a release, `_probe_principal` read any non-LDAP error as `unavailable`, so a pass whose
  probes all raised would be audited as a skipped outage and page nobody, while those accounts kept
  their sessions to the absolute cap. A connection, timeout or name-lookup error is still read
  as `unavailable`. So is at least a plain `OSError` saying the network or host is unreachable,
  down or reset. The new `ProbeOutcome.FAULT` (`probe_fault`) leaves the account unjudged as before.
  Every pass with a fault now logs one ERROR naming no account, audits `auth.ad_reconcile_faulted`,
  and raises `ad_reconcile_aborted` with reason `probe_fault` under its own source,
  `directory-reconciler-probe-fault`. A pass of faults only aborts as `probe_fault`. Step-up audits
  the outcome `probe_fault`, and the certificate path logs it per account as a fault rather than as
  an outage. The referral pass's ERROR line, new in this release, names no username. Vault BACKLOG #3100.
- **The MFA requirement's enrol-first gates now cover an account with an unrecognised provider.**
  `_requirement_covers` allow-listed `local`, so a row whose provider was neither `local` nor `ad`
  skipped the gates, although the engine builds its identity as a local account. Only a directory
  account is now left out. The lockable-account census still names only local rows, because
  password sign-in refuses every other provider before it counts a failure. Vault BACKLOG #3117.
- **A lock notice the relay's full queue drops no longer holds the next one back.** The security
  notifier now says whether it queued a notice, and the `auth.lock_notice` row records
  `mailed: false` for one it dropped, so the next lock of the kind mails again rather than staying
  quiet for 24 hours. The same holds at shutdown: a lock notice that reaches the notifier once it
  has begun to close, which a cut shutdown drain allows, is refused and recorded `mailed: false`
  rather than reported queued for a mail that is never sent. The relay also records such a drop,
  with the new undelivered-notice reason `closing`. A send that fails later, on the
  relay's own task, still leaves `mailed: true`; `docs/SECURITY.md` states that residual.
  **The lock notice's throttle read has an index.** A new `ix_audit_actor` index on
  `audit_log(actor, action, id)`, on SQLite, Postgres and SQL Server, lets the read find one
  account's rows instead of walking every recent notice row of every account. On Postgres it keys
  the first 200 characters of the actor, since a whole overlong value would fail the audit write.
  A companion `ix_audit_actor_id` index on `audit_log(actor, id)`, keyed the same way, keeps the
  reads filtered by actor without an action equality (`GET /audit?actor=`, its export pages,
  `/me/security-events`)
  from sorting all of an actor's rows to return the newest few.
  On the server backends the schema change moves the ADR 0064 schema hash: under their default
  `[store].schema_management`, `external`, the engine refuses to open until `provision-schema` has
  run; under `auto` the next open runs the DDL.
  **Declined, with residuals in `docs/SECURITY.md`:** two mails across engine shards serving their
  own API ports, the timing of the content-free failure lines, and a cap on pending notice tasks.
- **A narrowed dual-control list is now named as a security loosening.** While
  `[approvals].enabled` is on, an `[approvals].operations` list that leaves out a default
  operation (`connection_purge` or `dead_letter_replay`) is named as `approvals.operations`, and
  the entry names each operation left out. An empty list, which loads and holds nothing, is named
  too. At least the serve-time warning, `messagefoundry security show` and `GET /security/posture`
  list it. Before this, an operator could take an operation out of dual control and nothing said so.
  Dual control ships off, so a default instance names nothing new, and adding `config_reload` to
  the list is not named. [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md) says what the
  narrowed list gives up. (`vault BACKLOG #3123`)
- **The sandbox worker's memory cap no longer fails innocent messages on Linux.** At
  `[sandbox].mode = "subprocess"`, `[sandbox].mem_mb` was an `RLIMIT_AS` cap set once after the
  worker loaded its graph. It counted the graph itself, and every thread's malloc arena reserved
  about 64 MiB of address space that stayed counted after the thread exited. A long-lived worker
  would have run out of room on a message that did nothing wrong. On Linux, `mem_mb` is now
  headroom above the loaded graph, enforced with `RLIMIT_DATA`, which does not count reserved
  address space, and the worker starts with `MALLOC_ARENA_MAX=2`. Other POSIX systems keep the
  absolute `RLIMIT_AS` cap and log a line saying so; Windows still has no memory cap. A call that
  runs out of memory now dead-letters with an error naming the memory cap, and its worker exits so
  the next message gets a fresh one. Owner ruling 2026-10-11; see
  [ADR 0087](docs/adr/0087-sandbox-subprocess-isolation.md) and
  [CONFIGURATION.md](docs/CONFIGURATION.md). (`BACKLOG #3133`)
- **`env(key, cast=bool)` now reads a boolean strictly.** It used Python's own `bool`, which reads
  any non-empty text as true. Every `MEFOR_VALUE_*` variable is text, so `false`, `0`, `no` and
  `off` all read as true. On a first deployment, an operator who wrote `false` would have turned on
  a loosening such as `tls_allow_expired` or `trust_server_certificate`. At least the `MLLP`,
  `Rest`, `FHIR`, `DICOM`, `Soap` and `Ftp` factories take the first. The Database family takes
  the second. `messagefoundry check` lists every `env()` `tls_allow_expired` as a loosening
  anyway. The SQL Server preset refuses a `trust_server_certificate` loosening when it builds the
  connector. It lets one pass on an attested hop, or with the insecure-TLS escape on an instance
  that only warns. `cast=bool` now uses
  the same cast as `connections.toml`'s `cast = "bool"`. `true`, `1`, `yes` and `on` read true, and `false`, `0`, `no` and `off` read
  false, in any case. A TOML `true` or `false` from `environments/<env>.toml` works as before.
  - Any other value now stops the load. An empty value, `y` or `enabled` used to load. The error
    names the setting and the key, never the value.
  - A `default=` with a bool cast is now read the same way, in code and in `connections.toml`. In
    code, a default of `"false"` used to reach the connector as text and read true.
    `connections.toml` refused that default on a boolean setting, and now reads it. An unreadable
    default is refused, naming the key, and in `connections.toml` the connection and setting too.
  - A DICOMweb `verify_tls` that resolves to a false, empty or unset value is now refused with a
    `tls_ca_file`, as the literal `False` already was. Nothing would read the CA. A Soap client
    certificate with verification off was already refused when the connector is built.
  - Not every route is strict yet. An `env()` with no cast, or with a `str` cast, hands a boolean
    setting text. A connector reads any non-empty text as true. A cast you write yourself, such
    as `cast=lambda s: bool(s)`, runs as written. Give a boolean setting `cast=bool`.
  - The `int` and `float` casts refuse text they cannot read. `int` does turn a TOML `1.9` into
    `1` and a TOML `true` into `1`. `float` accepts `nan` and `inf`. See
    [CONFIGURATION.md](docs/CONFIGURATION.md). (`vault BACKLOG #3138`)
- **A directory reconcile pass that newly grants Administrator now raises the
  `administrator_granted` operator alert.** The session reconciler re-diffs a signed-in directory
  account's roles and writes them. When that write gave the account Administrator, it raised only
  `ad_session_revoked`, which does not name the role, and the account's next sign-in then gained
  nothing, so no `administrator_granted` alert ever fired. The pass now raises it right after the
  role write, keyed `user:<username>`, with `via` set to `directory_reconcile` and `granted_by` the
  fixed marker `<directory>`. An account that already held Administrator raises nothing. A pass the
  mass-revoke breaker aborts writes no roles, so it raises nothing either. Like every
  `administrator_granted` alert, it clears the account's `no_enabled_administrator` cooldown in the
  engine process that raises it. (`vault BACKLOG #3141`)
- **A refused federated step-up records where it started.** An `auth.reauth` row for a step-up
  refused after its flow was redeemed now carries `start_client` and `client_moved`, as the row of
  a completed step-up does. Both come from the flow the start leg staged, never from the token. A
  refusal before the `state` check carries neither. The refusal a step-up gate sends an `oidc`
  session now says to repeat the action in the web console, because a bare `/ui/reauth` names no
  action and returns to `/ui`. A store fault while that refusal reads the session's sign-in
  mechanism now keeps the `403`, with the password wording, rather than answering `500`. See
  [SECURITY.md](docs/SECURITY.md). (`vault BACKLOG #3145`)
- **The administrator who resets an account's factors is now sent the expiry reminder for the
  temporary password that reset issues.** The issuer lookup read the account-creation and
  password-reset audit rows only, so a factor reset's issuer was never found and never told.
  Vault BACKLOG #3160.
- **An AD re-bind the domain controller ends busy is an outage, not a wrong password.** A user bind
  that ends with busy (51), unavailable (52), unwillingToPerform (53) or adminLimitExceeded (11)
  judged no password. Before, the step-up re-bind read it as a refused password and counted it
  toward the engine lockout and the per-session re-proof cap. On a first deployment a busy domain
  controller could then have locked out a user who typed the right password. The re-bind now
  refuses it as `directory_unavailable` and counts nothing. A Notice of Disconnection at the bind
  reads the same way. invalidCredentials (49) still counts, and so does every other code ldap3
  decodes but a referral. The engine never follows a referral, so no bind judged the password: the
  re-bind refuses it as `directory_unavailable` like any other directory error and does not count
  it. A referral on this bind raises no alert: the session reconciler, which alerts on a referral,
  never makes a user bind.
  **The cost:** such a re-bind is charged to neither the account nor the session, so only the
  per-actor step-up budget bounds it. A setting that turns that budget off, such as
  `[auth].login_rate_limit_enabled = false`, leaves nothing in the engine bounding it.
- **The session reconciler counts a referral or a probe fault over the lookups it sent, and strikes
  an id-less row on every pass.** A directory row with no `objectGUID` is judged without a lookup,
  so no referral or fault can answer it. The `auth.ad_reconcile_referred` and
  `auth.ad_reconcile_faulted` audit rows now carry the `asked` field in place of `probed`. Each
  row, its latched message and its `ad_reconcile_aborted` alert count only the lookups the pass
  sent. The breaker's alert still counts every account the pass judged, its denominator.
  An id-less row is now struck on every pass, as on a pass that judged the directory's answers.
  That includes a directory outage, and a pass aborted because every lookup was referred, faulted
  or failed. No aborted pass revokes the row. Only a pass that is not aborted can, once the row's
  strikes reach the threshold and the row is in that pass's probe budget. So while every pass
  aborts, its sessions last to their own expiry. Its revocation still counts toward the
  mass-revoke breaker, as before. (`vault BACKLOG #3170`)
- **Federated step-up and binding follow-ups.** These gaps from the IdP step-up work are
  closed. (vault BACKLOG #3174)
  - The engine refuses to mint an `oidc` session with no IdP `auth_time` at the one place a
    sign-in mints a session, not only in the directory sign-in path. Such a session could never
    step up.
  - Both the federated sign-in and the IdP step-up refuse a directory answer whose object id is
    not the account's own, as `directory_identity_conflict` or `directory_object_id_missing`,
    before they use the answer's groups.
  - A federated bind refused because another account holds the identity, because another bind of
    the same account landed first, or because the account is local, now writes an
    `auth.federated_bind_refused` row, with reason `federated_subject_held`,
    `account_bound_concurrently` or `not_a_directory_account`. The first two carry
    `previous_binding_removed`. A changed-pair refusal row now records the pair the account held,
    wherever the refusal read it.
  - The order of the IdP-clock test and the directory lookup is pinned by a test, and the
    `sessions.idp_auth_time` migration is tested on Postgres and SQL Server.
  - Not changed, by decision: the step-up replay mark stays per session, not per account. The
    engine-clock freshness test already limits the gap to an IdP sign-in within
    `oidc_clock_skew_seconds` of the request, and a per-account mark would need a new column on
    the users table.
- **A request deadline can no longer leave an uploaded file without its `upload.create` row, or a
  deleted one without its `upload.delete` row.** The creation row and the delete with its row now
  run as operations the request deadline does not cancel, so the caller gets its 503 and the row
  still lands. A creation row that fails outright removes the stored file rather than leaving it
  unattributed; a removal the filesystem refuses is logged at ERROR and keeps the file. The
  shutdown drain can still cancel a delete between its unlink and its row. (vault `BACKLOG #3178`)
- **Each upload-quota reservation now has its own identity.** The engine-shard ledger holds one row
  per upload in flight, named by the upload's `file_id`, in a new `upload_reservation` table that
  replaces `upload_quota` on all three store backends, and the old table is dropped at open. A
  leaked slot is reclaimed once its own window passes, however active the uploader stays; a
  release pays back only its own slot; and a reserve whose outcome is unknown is released by its
  id before the upload fails, so a retry in the same process is not refused for its own orphan
  slot. On SQL Server the release takes the uploader's lock first, as the reserve does, so the two
  cannot deadlock over a stale row. A ledger call a cancelled upload left running is cancelled
  after `_LEDGER_STRAGGLER_MAX_SECONDS`, the engine drains what is left before it closes the
  store, as one step of the API teardown under its one shutdown budget (`BACKLOG #3191`), and
  a cancelled upload's file is removed before the next upload in the same process scans the disk,
  so that upload is no longer refused at the quota edge. `Store.reserve_upload_quota` takes a
  `reservation_id` and no longer releases; `release_upload_quota` and `touch_upload_quota` are
  new. (vault `BACKLOG #3180`)
- **A codec error no longer puts the input it failed on into a log line or a refusal, on at
  least the paths below.** `str(UnicodeEncodeError)` names the character a codec could not encode,
  `str(UnicodeDecodeError)` the byte it could not decode, and `repr()` of either prints `.object`,
  the whole input. At least three paths still rendered that text after `safe_exc` stopped doing so:
  the traceback of any `exc_info` log call, a log argument holding the error (one character or byte
  through `%s`, the whole input through `%r` or inside a list or dict), and a refusal built as
  `f"...{exc}"`. On a first deployment each would have written message content to the general log.
  The log filter chain, the tray's included, now prints a Unicode error from its class, codec and
  position in a traceback (chained causes and exception groups included), as a log message, and as
  a log argument. In an argument it looks inside lists, tuples, sets, dicts, deques, their
  subclasses, dict views, a `UserDict` and an exception's arguments, at any depth. It does not look
  inside at least a `MappingProxyType` or a `slice`, so an error held there still prints raw; the
  `BACKLOG #3295` entry names the four kinds of object it now reads by attribute. A container on the path to an error prints its
  other elements as its own `repr` would, up to five levels deep. A fixed note stands in at least
  past that depth, at a cycle back through a container whose `repr` is its own, and where such a
  `repr` cannot run on a copy. An exception holding one prints its class and a fixed note, never
  its other arguments. An argument holding
  none reaches the formatter as the same object it was given. Twelve refusals across the file
  readers, the sandbox codec, the ingress charset guard and the CLI render it the same way, and so
  does a sandboxed Handler's error under `[sandbox].mode = "subprocess"`. Their text changes from
  `'utf-8' codec can't decode byte 0xfe in position 2` to `UnicodeDecodeError: 'utf-8' codec cannot
  decode at position 2: invalid start byte`. Where the same arm also catches an `OSError` or a TOML
  error, that error's text and path stay as they were. A source scan in
  `tests/test_unicode_error_log_paths.py` catches the common raw shapes in an `except` arm that
  names a Unicode error. It does not see most arms that catch one only as `ValueError` or
  `Exception`; the `BACKLOG #3295` entry says which of those it reads.
  (vault `BACKLOG #3185`)
- **A crafted SPNEGO token is now an audited Kerberos refusal, not a 500.** On a host without SSPI,
  pyspnego's Negotiate wrapper raises `StopIteration` or `KeyError` when the first token is a
  `NegTokenResp`, and `IndexError` on some truncated tokens. `kerberos_principal` caught none of
  them, so `POST /auth/negotiate` and `GET /ui/sso` would have answered with a 500 and written no
  audit row. Any exception from the acceptor's step is now a refused token. (`BACKLOG #3186`)
- **Three more routes now answer by channel scope.** `GET /security/posture` shows a channel-scoped
  reader a per-connection entry only for an inbound in its own scope, and says in
  `loosenings_scope` and `static_credential_hops_scope` that the reading is narrowed. The
  `security.posture_view` audit row now records `loosenings_scope` too.
  `GET /users` now sends each account's `channel_scope` and `channel_scope_source` only to a
  `users:manage` holder; any other caller gets null for both and the new required
  `channel_scope_withheld: true`, which says the nulls mean "not shown".
  `POST /config/reload` now refuses a channel-scoped caller 403, a dry run included, and the
  approval gate refuses to release a held reload whose requester has been scoped since. **This
  changes behaviour:** a deployer without the all-channels grant can no longer reload. That
  includes a deployer whose scope nobody has set, which is the default and reaches no channel
  (BACKLOG #1152). `GET /config/provenance` gains the required `reload_refused`, the refusal the
  reload gives this caller, or null. `GET /approvals` gains the `release_blocked` value
  `requester_not_authorized` for a held request whose requester no longer holds the authority it
  needs, such as a held reload or purge whose requester has since been channel-scoped, so it is no
  longer offered for approval and then refused. Every `auth.channel_denied` row now records a
  channel that fails the connection-name rule as no channel, with `"malformed_name": true` in its
  detail, whichever route or console seam call wrote it.
  (`vault BACKLOG #3189`, `vault BACKLOG #3031`, `vault BACKLOG #3192`)
- **A refused Kerberos token is audited as a refused sign-in, and the row no longer quotes the
  token.** A token the SPNEGO acceptor refused became a directory error that stored the
  exception's message as `auth.login_error`. That message can carry text parsed from the caller's
  token, such as an unknown mechanism OID. It is now an `auth.login_failed` row with the reason
  `token_refused` and only the error's type. The engine log names the error's class and its
  numeric GSSAPI or SSPI status, never its text. A fault in the acceptor's own key, such as a
  missing keytab entry, fails the same way on any host. The status helps tell the two apart, but
  the caller names the ticket's principal, so it does not prove either. Each such row counts toward
  the per-address `signin_failure_burst` alert, so a key fault can raise it. A principal that cannot be
  read after an accepted step is an audited `auth.login_error`, not an unaudited 500. While
  browser SSO is available, `POST /auth/negotiate` also audits a token that is not base64 as
  `malformed_token`, the row `GET /ui/sso` already wrote. (`BACKLOG #3196`)
- **The new-address step-up row records the address in its client column.** An
  `auth.new_address_reverify_required` row held the new address only in its detail, as `seen_ip`, and left
  the `client` column empty. So a search or an export by address missed it. The row now fills the
  column too. Not changed here: the sign-in entry points (`login`, `authenticate_kerberos`,
  `authenticate_oidc`) still default `client` to none. Making it required is left to its own
  backlog item. (vault BACKLOG #3197)
- **A forged federated sign-in callback no longer uses up the real one.** The engine compared the
  callback's `state` only after it had consumed the staged flow. So a page that sent the browser to
  the callback with a wrong `state` would end a sign-in in flight. An `error=` or malformed callback
  ended it with no `state` check at all. The engine now compares `state` first on every callback,
  through one `FlowCache.pop_if_state_matches`, and consumes the flow only on a match. A matching
  callback still spends it once, so a replay is refused. (vault BACKLOG #3198)
- **`GET /security/posture` reads the `[auth]` limits off the attached auth service.** An app built
  with `create_app(engine, auth=service)` stashes no `[auth]` settings, so the route read the
  shipped defaults and named none of the limits the embedder had loosened. It now reads them off
  the service that enforces them, and falls back to the stashed settings, then the defaults, only
  when no service is attached. (`vault BACKLOG #3215`)
- **A released dual-control purge now writes its `connection_purge` row, and alert acknowledge,
  resolve, suspend and resume commit their audit row with the change.** The released purge's row
  names the outbound, the scope and the count, is attributed to the requester, and commits in the
  cancel's own transaction, so a failed append cancels nothing and the release is recorded as
  `failed`. Before, a released purge left only the approval rows, and each alert action wrote its
  row in a second transaction after the change committed. `cancel_queued` now requires `audit=`,
  and the four store alert mutations require an `audit` row, which they append only when the change
  applied. (vault `BACKLOG #3217`)
- **A refused OIDC callback that the floor exemption let through now carries the
  `callback_floor_exempt_amr` marker.** Only the success row carried it before, so the review
  `docs/SECURITY-LOOSENING.md` asks for under `[auth].oidc_callback_floor_exempt_amr` would have
  missed an exempted sign-in or step-up that was refused afterwards, for example by the directory
  check or a subject mismatch. Every refusal row such an attempt writes after the exemption applied
  now holds the matched configured values at the top of its detail, except a lock refusal,
  whose row keeps the exact text that hides it from readers without `users:manage`. A Windows
  sign-in row is unchanged. (BACKLOG #3220)
- **A misframed JWKS reply no longer hides the federated sign-in link, and a verified token
  shows it again.** The JWKS fetch now says whether a reply arrived. A reply refused for its
  framing, or an `http.client` fault other than `BadStatusLine` or `IncompleteRead`, no longer
  counts as an outage: the sign-in fails as `idp_answer_unusable` and the link stays. A reply cut
  short is still an outage. Either leg now clears the outage flag once the code exchange
  yields a verified token, even when a later check, such as the callback floor, refuses the
  attempt. A whitespace-only `[auth].oidc_prompt` loads as no prompt and is not sent. Two
  step-up texts are reworded. [ADR 0142](docs/adr/0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md)
  Amendment G. (BACKLOG #3221)
- **An AD group map key that starts or ends with a non-printing character is refused.**
  `PUT /ad-group-map`, `PUT /ad-group-scope-map` and the web console's AD group page now trim
  only a space, a tab and a line break from a key. A key whose first or last character still
  fails Python's `str.isprintable()` gets a 400 with its own reason. That covers at least a
  no-break space, an em space, a zero-width space and a byte-order mark. Before, the white-space
  ones were trimmed as if they were plain spaces, and a trailing zero-width space was kept and
  stored a key that matched no group. Some invisible characters still count as printable to that
  test, such as the Hangul filler, and a key ending in one is still stored and matches nothing.
  Each refused key that holds a non-printing character is named in its `ascii()` form, so the
  character shows in the message. The DN parser likewise takes only a space, a tab and a line
  break as padding around an attribute type, so a DN with a line break after a comma still maps.
  A character before a comma, or anywhere inside a value, is still part of that value.
  (vault `BACKLOG #3222`)
- **A Windows sign-in whose name matches several directory entries can now succeed.** The
  engine used to refuse such a sign-in as ambiguous. So anyone able to write a colliding entry
  could lock the account out. Now the engine reads the account's stored `objectGUID` from its
  directory row. It picks the one entry that holds the name as its `sAMAccountName` and carries
  that id. It logs the choice at WARNING, once per name per process. The engine still refuses
  the sign-in in at least these cases: no stored id, two such holders, or the id on two entries.
  The engine reads the row through its integrity seal, so on a keyed store an edited row picks
  nothing. A keyless store checks no seal, so there a row written straight into the table still
  picks the entry. (`vault BACKLOG #3228`)
- **A directory role change that takes Administrator from its last enabled holder now raises an
  alert.** A directory sign-in's role sync and the session reconciler can take Administrator from
  an account, and neither goes through the console's last-administrator guard. By owner ruling 2026-10-13 the
  directory stays authoritative, so the change still applies. When it leaves no enabled
  Administrator, the engine now raises the `no_enabled_administrator` alert, keyed
  `user:<username>` with `via` set to `ad-sync` or `ad-reconcile`, and writes an
  `auth.no_enabled_administrator` audit row. With no enabled local Administrator holding a usable
  password, `provision-admin` runs again at the host (BACKLOG #2711). An `administrator_granted` alert for an account clears that account's
  `no_enabled_administrator` cooldown. It clears it only in the engine process that raises the
  `administrator_granted` alert. A reconciler re-grant raises `administrator_granted` too (vault
  BACKLOG #3141), so it clears the cooldown the same way. A directory disable or deletion of the
  last Administrator raises no `no_enabled_administrator` alert. For at least these cases
  and others that raise no `no_enabled_administrator` alert, see docs/SECURITY.md, *A directory role
  change can remove the last Administrator, and it alerts*. (`vault BACKLOG #3229`)
- **No escape sends a credential to a peer the engine has not verified (vault BACKLOG #3230).** A
  REST, SOAP, FHIR, DICOMweb or `FhirLookup` connection with `verify_tls = false` on an `https`
  URL is now refused at build when it carries a credential: a bearer token (static or minted by
  SMART or OAuth2), HTTP Basic or Digest, a SOAP UsernameToken or body secret, a credential-looking
  `url` query parameter, or a static header that settings views would mask (`Authorization`, an API
  key). Neither `MEFOR_ALLOW_INSECURE_TLS`, `tls_hop_attested` nor a loopback host lifts
  it. An SFTP login with a `password` no longer takes the escape's auto-accept of an unknown host
  key; it is refused before it authenticates. `[auth].ad_tls_verify = false` is refused in every
  posture, because every AD bind carries a password; pin a private CA with `ad_tls_ca_cert_file`
  instead. An `Email` or `Direct` connection with an SMTP login on a cleartext or unverified hop
  is refused as before, but that refusal now runs before the cleartext and verify-off checks,
  names the connection, and no longer
  points at `MEFOR_ALLOW_INSECURE_TLS`, `tls_hop_attested` or `cleartext_accepted`, none of which
  lifts it. A hop with no credential keeps its old behaviour. Separately, an explicit `None` for a
  default-on TLS setting (`tls_verify`, `tls_check_hostname`, `verify_tls`, `use_tls`, `encrypt`)
  now takes the default instead of reading as off. The rule is stated once, in
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md#no-escape-sends-a-credential-to-an-unverified-peer).
- **Approving a held action needs a fresh step-up.** `POST /approvals/{id}/approve` now asks for a
  fresh step-up window, as the resolve already did, because the release runs the held operation.
  A JSON client that approved under a paced session gets **403** with `X-Step-Up-Required` until
  it re-authenticates. Reject still runs nothing and stays paced. For a held config reload, the
  release is still bound to the digest its approval named. The web console's changes are in its
  own changelog. (vault `BACKLOG #3241`)
- **Edit-resend gives back its proof when the engine refuses before it writes.** A refusal raised
  before the message-store write, such as a bad target or a guard rejection, returns the action
  proof, so the operator can submit again with no new password. A refusal at or after the store
  call keeps the spend. Export and edit-resend now check their own input before they spend the
  proof, so a malformed request costs no proof. (vault `BACKLOG #3241`)
- **A Vault provider's error keeps the text of the Vault hop's own refusal only.** The three Vault
  clients put a hop refusal into their error in its own fixed words, which name no address, proxy
  URL or token. That rule accepted every `InsecureHopRefused`, a type other parts of the engine
  raise with a host in the text, so a provider that met one of those would have put the host in
  its error. The Vault hop's refusals are now a marked subclass, `VaultHopRefused`, and only that
  subclass keeps its text there. The provider's error names any other hop refusal by type, as it
  names every other failure. No refusal the Vault hop raises today changes its wording.
  (vault BACKLOG #3247)
- **The Vault client build no longer raises a parser error that quotes a proxy URL.** For an
  `http://` Vault address it read the proxy's scheme with a parser that rejects some URLs the
  HTTP library accepts. That parser's error quotes the proxy's user and password, and a command
  would have printed it. The scheme is now read the way the credential check reads it, and such a
  hop is refused with fixed text. (vault BACKLOG #3247)
- **An SVG or HTML attachment download refuses an `svg` start tag after leading text.** A body whose
  first byte past leading whitespace was not `<` was served as stored, even under an SVG or HTML
  label and even when it carried `<svg onload=...>` further on. Now, when the stored label is one a
  browser renders as SVG or HTML (a media type naming svg, or an HTML type such as `text/html`),
  the first 64 KiB past that leading noise is scanned for an `svg` start tag, plain or inflated
  from gzip, and the body is refused with a 422 when one is found. Under any other label, such as
  `text/plain`, `application/json`, HL7, PDF or DICOM, a quoted `<svg>` is data and is served as
  before. Detach already stores a `+xml`-labelled body that does not start with `<` as
  `application/octet-stream`, so under those labels the check never fires for a stored body.
  Every such body was already served as an inert type with `nosniff`, so this is defence in depth,
  and what the check does not reach rests on that inert-type allow-list, as
  [ADR 0105](docs/adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md)
  records. The 422 now says the attachment carries SVG rather than that it is one.
  (`BACKLOG #3257`)
- **The admin routes that refuse your own account now also check the stored id, and each refusal
  is audited.** Reset-password, reset-mfa and both federated-identity actions compared only the
  id in the path. The console's `/ui/users/{id}/` routes take that id as plain text. On a store
  that compares ids case-insensitively (SQL Server), an administrator could have reached their own
  account by changing the id's letter case. They could then have reset their own second factors.
  Every self-target guard, disable and delete included, now compares the stored id too. Each
  refusal also writes an `auth.self_target_refused` audit row on both planes. It names the actor,
  the route (`op`), the caller's id and the caller's address. Before, the JSON plane kept only the
  step-up grant row, and the console kept nothing. See [SECURITY.md](docs/SECURITY.md).
  (`vault BACKLOG #3259`, `vault BACKLOG #3260`)
- **A self-service revoke of one session that ends nothing is now audited.** `DELETE
  /me/sessions/{session_id}` and the console's revoke button answer as before when the id names no
  session or another account's. Each such miss now writes one `auth.session_revoke_missed` row. It
  names the actor, the caller's address and the first 12 characters of the id, and nothing else, so
  the row does not tell an unknown id from another account's any more than the answer does. Before,
  the miss left no row of its own on either plane. The `auth.session_revoked` row now carries the
  caller's address too. See [SECURITY.md](docs/SECURITY.md). (`vault BACKLOG #3260`)
- **`PATCH /users/{user_id}` now checks a changed `email` the way `POST /users` does.** The profile
  address must be one plain mailbox, and a blank one is refused; it used to be stored as sent,
  limited only by length. The refusal is a 400, comes before anything is written, and never quotes
  the value. Omitting `email` still keeps it, an explicit `null` still clears it, and the stored
  address posted back unchanged is not re-checked, so a directory-supplied address does not refuse
  a save that posts it back as stored. The console's account form goes through the same check. The
  `messagefoundry/api/validation.py` module docstring no longer claims that every bound
  [API-INPUT-VALIDATION.md](docs/API-INPUT-VALIDATION.md) quotes is pinned by a test.
  (BACKLOG #3278, owner ruling 2026-10-08)
- **More of the routes by which a codec error could put the input it failed on into a log line or
  a refusal are closed.** These were left open when the first three were fixed. On a first
  deployment each would have written a character, a byte or a whole input to the general log.
  - An exception that holds a `UnicodeError` now prints as its class and
    `[holding a codec error, not rendered]`. That covers at least `RuntimeError(exc)`,
    `ValueError("bad", exc)`, an `OSError` whose `strerror` or `filename` is the error, and one
    that keeps the error on an attribute when its class defines `__str__` or `__repr__`. It
    applies in a traceback, in `safe_exc()`, and in the error a sandboxed Handler reports under
    `[sandbox].mode = "subprocess"`; `codec_safe_str()` returns the note alone. Its other
    arguments are not printed either, so such an exception loses its own message in the log.
  - A log argument that is a dataclass, a `SimpleNamespace`, a `ChainMap` or a `UserDict`'s view
    is read from its own attributes. One that holds a `UnicodeError` prints as its class and a
    fixed note. One that holds none reaches the formatter as the same object. This walk has a
    work limit per argument, and an error past it still prints raw.
  - A code set CSV that is not UTF-8, that the `csv` module refuses, or that cannot be opened,
    is refused as `code set 'name.csv': invalid CSV`, without the byte. Each used to escape as a
    raw error.
  - Four refusals that catch a `ValueError` or an `Exception` render a Unicode error from its
    attributes: the trust-anchor reload preflight, the SQL Server claim-procedure startup gate,
    and two `messagefoundry verify` checks.
  - The source scan in `tests/test_unicode_error_log_paths.py` now also reads a `ValueError`,
    `Exception` or bare arm whose own `try` body calls `.decode()`, `.encode()`, `.read_text()`
    or `.write_text()`. It refuses at least a caught error handed to a call it does not know,
    returned, or appended to a list, alone or inside a tuple, list, set or dict literal.
  At least these stay open, and `docs/PHI.md` section 7 says what a caller does about each: text
  built from the error before a log record exists, a mapping whose own lookup returns such text,
  an error held in a `MappingProxyType` or in an object of a class that is neither a dataclass
  nor an exception, a broad `except` arm whose codec call is inside a callee, and a file path in
  an `OSError`.
  (vault `BACKLOG #3295`)
- **A failed inbound TLS handshake now leaves a record on the HTTP intake listener, the API and
  the MLLP listener, on any event loop.** The DICOM C-STORE SCP still logs one at DEBUG only.
  The HTTP intake listener records one as a `tls_handshake_failed` connection event, as the MLLP
  listener already did on the standard asyncio loop, and the MLLP listener now does so on uvloop
  too, which the engine uses outside Windows. The API logs a WARNING line. Each record is the first
  failure at once, then one per listener per minute carrying the count since the last, and names a
  count, an exception class and OpenSSL's reason, never the peer's bytes or certificate. Where the
  event loop runs the handshake the peer's address is not known, so those records name no peer,
  and a handshake that only runs past its time bound is not counted there.
  ([BACKLOG #3302](docs/BACKLOG.md))
- **A sign-out's `auth.logout` audit row records the client address it came from (ASVS 16.2.1).**
  Neither sign-out route passed an address. On a first deployment, an investigator could not have
  told from the audit log where a sign-out came from. `POST /auth/logout` and the console's
  `/ui/logout` now pass the `client_ip` address, the extractor other audited auth routes use.
  `AuthService.logout` takes it as a required `client` keyword, so a new caller cannot omit it.
  The row's actor is unchanged. A console sign-out that ends nothing, including one that loses a
  rotation race, still records no actor. A sign-out that revokes nothing keeps its own recorded
  `detail.outcome`, `nothing_to_revoke`. The web console seam digest moved, so a console and an
  engine built on either side of this change refuse each other at mount. (`BACKLOG #3339`)
- **The test harness's HTTP sinks no longer send a `Server` line.** Python's HTTP server named
  itself and the Python patch level on every answer, and the engine HTTP listener sends no such
  line. The sinks' package, `harness.sinks`, is now type-checked under the strict profile in CI.
  The protocol header floor also logs, at DEBUG, each handshake answer it drops on a WebSocket
  connection that has already ended its stream. (`BACKLOG #3358`)
- **The bulk export stops when the caller's channel scope widens mid-stream, not only when it
  narrows.** `GET` and `POST /messages/export` used to keep streaming after a grant that reached a
  live session without a revoke, as a direct store write does, or a row checked after an engine
  path wrote a scope or role set but before its revoke landed. An export by `ids` then streamed
  the newly granted channel's rows under the original step-up, and nothing recorded the widening.
  A grant followed by a withdrawal skipped and audited later rows one by one rather than stopping.
  Any change to the scope, wider or narrower, now records `messages_export.stopped` with the
  reason `scope_changed` and ends the stream, so no row streams on a scope the export's step-up
  and audit row did not cover. (`BACKLOG #3381`)
- **A deliberate export stop no longer reads as a crash in the server log.** A stopped bulk or
  audit export used to log an ERROR line naming `ExportStopped` and a uvicorn traceback beside the
  stop's own WARNING. It now logs that WARNING with the counts, beside the stop's audit row. A
  real crash still logs both. (`BACKLOG #3381`)
- **Known gap, not fixed: a stopped export reaches the client as a complete-looking short
  file.** The `BACKLOG #1154` entries said a stop aborts the download, and are corrected. It does not: the engine's
  `@app.middleware("http")` layers end the response cleanly before the stop's raise leaves them,
  so the client receives a normally ended 200 holding the rows streamed before the stop. The
  `messages_export.stopped` or `audit.export.stopped` audit row and the server's WARNING record
  that the file is short; the file does not. See [SECURITY.md](docs/SECURITY.md).
  (`BACKLOG #3381`)
- **BREAKING: a keyed store now remembers which encrypted columns it has keyed.** It refuses a
  plaintext value planted into one, even when the column holds no ciphertext. This follows an owner
  ruling of 2026-10-10. Before, the keyed open decided whether a `(table, column)` was sealed only
  from its own rows. A column with no ciphertext at that moment counted as unsealed. That covers a
  table that had emptied out, a column every purge had blanked, and one never written yet. So a row
  planted there was sealed as legacy data and then read back as genuine content. Now a writable
  keyed open records each column in a new `keyed_surface` table, on SQLite, SQL Server and
  PostgreSQL. A recorded column stays sealed whatever its rows hold. A plaintext value in it is
  refused and alerted under `store-cipher`. Legacy plaintext is still sealed once, by the open that
  first records its column. That open writes the record in the same transaction as the seal, so a
  crash leaves both undone. A row planted before that open, in a column with no ciphertext, still
  looks like legacy data and is sealed. [PHI.md](docs/PHI.md) section 3 states the rule and its limits.
  (`BACKLOG #3383`, ASVS 11.3.3)
  - **Migration:** values a keyless run writes into a store that was keyed before are now refused,
    even in a table that had emptied out. If you know they are legitimate, start the engine once
    with `[store].allow_unmarked_ciphertext = true`. That open seals them. Then set it back to
    `false`. The setting's meaning is unchanged: while it is on, the open seals every unmarked
    value, recorded column or not.
  - The server backends' schema batch changes, so the next open re-runs it. Under
    `[store].schema_management = external`, run `provision-schema` before starting the engine. Grant
    the runtime role row access to `keyed_surface`, as for every other table.
- **BREAKING: the Direct transport now refuses DSA keys and every unlisted key type.** Its key
  floor used to check only RSA size and EC curve, and passed any other type. An RSA recipient
  certificate issued by a 2048-bit DSA trust anchor was accepted. Now every `trust_anchor` must
  hold RSA of at least 2048 bits, EC on P-256, P-384 or P-521, Ed25519 or Ed448, the same key types
  the XML signature check allows. `signing_key` must be RSA or EC, and `recipient_cert` must be
  RSA, because the S/MIME library supports nothing else there. DSA is refused at any size on all
  three, and so is any other type. The error names the setting and the key type. A Direct partner
  whose issuing CA uses DSA would need an RSA or EC issuing CA instead. (`BACKLOG #3384`, ASVS
  11.2.3)
- **The first-Administrator service now requires the notification address, as `provision-admin`
  does.** `AuthService.provision_first_administrator` and its pre-check `provision_refusal` refuse
  a call with no address, where they used to accept one, so no caller of this service can create
  an Administrator with no notification address. An Administrator can still lack one by another
  route, such as a directory account granted the role; `admin-set-notify-email` and the start gate
  still cover that. The check is of form only: it does not prove mail reaches the address. The command, the pre-check and the write share one check, so
  they word a refusal the same way. The narrower BACKLOG #2288 refusal, which declined only a repair
  of an account already holding an address, could no longer fire and is removed. (BACKLOG #3391)
- **A credential in a proxy URL no longer reaches a second proxy in cleartext.** With `http` and
  `https` mapped to different web proxies, the urllib egress would have sent the first proxy's
  credential to the second one in a cleartext `CONNECT`. urllib keeps the header when it hands a
  request on, and the check read only the current proxy's URL. It now reads the header too, at
  every proxy. The check refuses a proxy URL credential on any leg where it would reach a proxy in
  cleartext. Writing the proxy `https://` does not by itself exempt the credential. Move the
  credential out of the URL. The Vault hop picks one proxy per request and did not leak. The rule,
  an example of a leg it lets through, and what it does not check are stated on
  [`ProxyCredentialsRefusedError`](messagefoundry/transports/bounded_read.py). (`BACKLOG #3410`)
- **On Python 3.15 with OpenSSL 3.4 or later, the apiclient and the tray probe stop offering
  SHA-224 TLS signature schemes too.** Their verifying contexts, on both trust branches, now drop
  `rsa_pkcs1_sha224`, `ecdsa_sha224` and `dsa_sha224` as the engine's own narrowed contexts do.
  The narrowing moved into the stdlib-only `messagefoundry.tls_sigalgs`, which `tls_policy`, the
  apiclient and the tray all call, so there is one copy and none to drift. ADR 0113 adds that
  module to the tray-importable list. The startup TLS-floor probe is left as it is, on purpose: it
  verifies no certificate, and its legacy offers carry no signature-scheme list. Python 3.14 is
  unchanged, and so is a 3.15 linked to an older OpenSSL, which logs a warning once. A build that
  refuses the list fails closed: the tray then reads UNKNOWN rather than failing to start.
  (`BACKLOG #3414`, ASVS 11.4.1)
- **A `proxy_user` credential bound for a proxy written `https://` is judged as cleartext.**
  urllib sends the `Proxy-Authorization` header to a proxy before any TLS, in the `CONNECT` that
  opens the tunnel, whatever the proxy's scheme. The connection-build check judged only a proxy
  written `http://`. It now judges both, so a `proxy_user` and `proxy_password` pair with an
  off-box proxy is refused under `[security].enforcement = enforce` unless the connection declares
  `cleartext_accepted` or `tls_hop_attested`. The opener also refuses any caller-set proxy header
  that check did not admit. A Handler can no longer set `Proxy-Authorization` through
  `http.header.*` metadata: the header is dropped, as `Authorization` already was. The rule, and
  its one exception for a credential that check admitted, are stated on
  [`ProxyCredentialsRefusedError`](messagefoundry/transports/bounded_read.py). (`BACKLOG #3416`)
- **A proxy credential on a request that goes direct is refused.** A request urllib sends past
  every proxy, to a loopback host, a host on the `NO_PROXY` list or a scheme with no proxy, would
  have carried its `Proxy-Authorization` header to the destination itself. Every engine opener now
  refuses that send, and `build_strict_opener` refuses redirects itself, since urllib copies the
  header onto a redirected request. The rule is stated on
  [`ProxyCredentialsRefusedError`](messagefoundry/transports/bounded_read.py). (`BACKLOG #3417`)
- **A proxy credential sent over TLS that does not verify the proxy is refused, admitted or
  not.** An `http` target sent to a credentialed `https://` proxy, with no proxy for `https`,
  reaches it over TLS with the opener's own context. On an `http://` destination with
  `verify_tls = false` or `tls_allow_expired = true`, that context does not fully verify, so the
  credential would have gone to an unauthenticated proxy. That send is now refused, and so is one
  on a context with no host name check. A `proxy_user` credential its connection admitted gets no
  pass on that leg; its one exception covers cleartext legs only. An explicit `proxy_url` address
  serves both schemes, so its credential rides a `CONNECT` before any TLS instead, and the
  cleartext rule governs it. The rule and its exception are stated on
  [`ProxyCredentialsRefusedError`](messagefoundry/transports/bounded_read.py). (`BACKLOG #3418`)
- **A trust-anchor pin may name its digest, and each `auth.trust_anchor` audit row names the digest
  of its fingerprint.** A pin such as `[api].tls_client_ca_pin` or a connection's `tls_ca_pin` may
  now be written `sha256:<hex>`. A pin with no prefix still reads as SHA-256, so every pin written
  before keeps working. A prefix the release does not support, such as `md5:`, is refused. Each
  audit row carries an `algorithm` field, and a row without one reads as `sha256`. The change check
  compares an anchor in the digest of its newest earlier row, and skips a row in a digest the
  release does not support, with a WARNING. A later release that changed the digest would then
  neither refuse every pinned anchor nor record a false `changed` row for each one (BACKLOG
  #3425). See *Trust-anchor pin syntax* in [CONFIGURATION.md](docs/CONFIGURATION.md#api).
- **A static `Proxy-Authorization` beside `proxy_user` is refused at build.** A connection's proxy
  handler admits a caller-set proxy header on a cleartext proxy leg once its `proxy_user`
  credential passes the posture-keyed guard. With `proxy_auth_type = "digest"` the connection sets
  no header of its own, so a `Proxy-Authorization` written into `headers` would have crossed that
  leg on the admission. Under Basic it would have been silently replaced. A connection that sets
  both now fails to build, and the error names the header key but not its value.
  (`BACKLOG #3443`)
- **The CRL signature texts now say only what the engine does.** On a CRL's signature, a start
  refuses the file only where the engine proves that signature bad. Its other CRL refusals are
  unchanged. The configuration guide now says what counts as proof,
  and names cases that load with a WARNING although the CRL names a CA's key: at least a
  signature the engine cannot check with that key, and an issuer name that differs from the CA's
  only in letter case. The reload's `bad_signature` remedy sentence and the start WARNING are
  reworded to match. The reload's two signature reasons are reworded too: one uses the WARNING's
  words, and the other no longer says a handshake fails where the engine only could not confirm
  the signature. The guide also says when the WARNING is logged again for an earlier version of
  the file, that the engine does not check the signature of a CRL that reaches a hop through its
  CA file alone, and which alert the held-copy paragraphs describe. No check changed. See
  [CONFIGURATION.md](docs/CONFIGURATION.md), under "CRL files". (`vault BACKLOG #3506`)
- **The account seal checks the TOTP code against the secret it checked, and names its rollback
  limit.** The two-step sign-in, the combined sign-in and the enrolment confirm now take the TOTP
  secret from the account record whose seal the loader checked. They no longer read the cell a
  second time, so a secret swapped into the store after that load is never the one a code is
  checked against. On the password sign-in, a store write can refuse the account's record because
  it stopped passing its seal after the load. That sign-in now gets the usual refusal, padded like a
  wrong password, with the same failed-sign-in audit row. A warning is logged, and the checked
  loader reports the record if it still fails when read again. The second-step, passkey and
  re-proof legs do not handle that case yet. `admin-unlock`, `admin-reset-totp` and
  `admin-set-notify-email` now refuse such a record with a fixed message. It names both causes: a
  store key this shell lacks, or a change made outside the engine. Before, each fell through to
  the command dispatcher's generic error. **The seal has a limit: it does not catch a rollback.**
  A writer who kept an earlier copy of an account's `users` row, with its seal and its role rows,
  can put it back, and it verifies. That can restore a removed role, a disabled account's access,
  an old password, a cleared lockout or an ended session. (vault BACKLOG #3510)
- **A CRL's issuer name is matched to the hop's CA as OpenSSL matches it, for ASCII letter case.**
  The CRL signature check, at a start and at a reload, compared a CRL's issuer name with each
  listed CA's subject exactly. OpenSSL folds the case of ASCII letters, so it judged peers by a CRL
  the engine had matched to no listed CA. A badly signed CRL that named that CA's key, under a name
  that differed only in ASCII case, started with a WARNING and then failed every handshake it
  judged. A start now refuses it, as it refuses the same CRL under the exact name. The issuer name
  a CRL's authority key identifier may carry is folded the same way. A letter outside ASCII is
  still compared exactly, as OpenSSL compares it. A name that differs only in white space still
  reads as unlisted and loads with the WARNING, although OpenSSL treats the two names as one. See [CONFIGURATION.md](docs/CONFIGURATION.md),
  under "CRL files". (`vault BACKLOG #3543`, `vault BACKLOG #2905`)
- **`pyproject.toml` now requires `certifi>=2026.10.19`, past
  [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2).** certifi is
  transitive: httpx and httpcore pull it in on a base install, requests through extras, and none
  of them sets a floor that excludes the affected releases. Before this, upgrading into an
  environment that already held an affected certifi could keep it, because the repository's locks
  bind only installs made from them. The floor binds an install that resolves the dependencies of
  a release built from this change onward. It does not bind an install with `--no-deps`, or any
  release already published. Not covered, at least: the copy pip vendors, the container image's
  own trust store, and hops that verify against the operating system's trust store, which never
  read certifi. Not refreshed here: `security/risky-component-readings.json`,
  `security/bundled-code-survey.json` and `docs/RISKY-COMPONENTS.md` still describe certifi
  2026.7.22 and do not record this advisory. They are dated snapshots made by hand.
  (`BACKLOG #3905`)
- **The `audit-pin` job `messagefoundry init` generates now audits the Windows-only dependencies.**
  `pip-audit` skips a dependency whose environment marker does not match the runner, so on
  `ubuntu-latest` the job never audited the engine's Windows-only dependencies (at least `colorama`
  and `sspilib`) on the only supported deployment platform. The job now runs on `windows-latest`, one
  step per command. With a hashed `requirements.lock` it installs the lock under `--require-hashes`
  and runs the engine's own auditor, `python -P -m messagefoundry.security.audit_all_platforms`,
  which audits every pin whatever its marker. That module first ships in the release after 0.5.1,
  and it refuses a lock with pip option lines. See [ADOPTER-CI.md](docs/ADOPTER-CI.md), Job 3.
- **The harness X12 sink never echoes an ISA13 that is not nine digits into its TA1 (ASVS 1.1.2).**
  The sink wrote the received ISA13 into TA101 with fixed separators, and ISA13 is read by fixed
  offset, so one holding `*` and `~` could turn a TA1 the sink sent as accepted into one the
  engine's codec reads as TA1-04 `R`, which the engine's X12 destination dead-letters. The sink now
  answers such an interchange with nothing, as it already did for one with no readable ISA13, and
  the TA1 builder refuses the value.
- **The harness Compose tab frames through `frame_checked` by default.** A message holding an MLLP
  frame byte is refused before any connection and shows `not sent:` with the byte and its position,
  as the Send tab does. Sending such bytes on purpose, to test the engine's ingress refusal
  ([ADR 0205](docs/adr/0205-an-outbound-frame-holds-exactly-one-message.md) rule 4), is a
  labelled opt-in checkbox that covers one send.
- **`samples/send_mllp.py` prints the peer's ACK as printable ASCII.** CR becomes a newline. A C0
  control (ESC among them) or DEL prints as `\xNN`, and every non-ASCII code point (a C1 control, a
  bidirectional override, an accented letter) as `\uNNNN` or `\UNNNNNNNN`, so an ACK cannot act on
  the operator's terminal or reorder what it shows. A backslash is doubled only where it would read
  as the start of an escape, so an ordinary ACK prints unchanged. The ACK is also read under the
  engine's frame cap, refused with exit 1 past it, and under one deadline for the whole reply.
- **`messagefoundry verify`'s live smoke frames through `frame_checked`**, as the harness and
  `send_mllp` do, and refuses before dialling. Its message is synthetic, so this is consistency.
- **More console lines, and the Markdown verify report, now escape a peer's text (ASVS 1.1.2).**
  The `messagefoundry verify` console summary printed each check's detail raw, a JWKS key id
  included, so on first deployment a crafted `kid` could have driven the operator's terminal or
  started a line reading as a check that passed. The summary now escapes control, bidirectional and
  other format characters and the newline, and keeps printable Unicode, so the engine's own em
  dashes still print as themselves; the `--report-json` file keeps the value as it was. At least
  the harness `shardcert-driver`, `shardcert-drive` and `shardcert-drive-ladder` engine-error
  lines, the `--fuzz` setup and failure lines, and the scenario and load verdict lines now escape
  the newline as well, so engine text cannot start a line of its own there, and the `connscale`,
  `connscale-remote`, `estate`, `multishard` and `failover` setup errors escape the engine log tail
  they quote. `scripts/service/import-db-ca.ps1` shows a certificate's Subject and Issuer with
  control and format characters as `\uXXXX`. `messagefoundry/terminal_text.py` gains the
  `single_line` and `keep_printable_unicode` options these use, and now doubles a run of
  backslashes only before text that reads as an escape, so most Windows and UNC paths print as
  typed. The `--report-md` table now applies the same escape to every cell and writes at least `&`,
  `<`, `>`, `|`, a backtick, `$` and the `(` after a link's `]` as character references, so a
  peer's text cannot start a forged row or render as raw HTML, a remote image or a link whose text
  hides its target; what it still leaves, at least a bare URL's autolink, is listed in
  `messagefoundry/verify/report.py`. At least the load report's engine `/status` strings and `tee
  naks` still carry a peer's text as it came.
  The `shardcert` shard-start errors now escape the engine log tail they quote, the
  `ingress_probe` setup-failure line escapes it to one line (it is printed beside the `RESULT`
  line its workflow reads), and the `connscale` reload probe's warning escapes the engine reply to
  one line. A `--fuzz` failure line escapes a quoted identifier once rather than twice, so a real
  ESC prints as `\x1b` and text spelling it prints doubled. With `keep_printable_unicode`, a
  backslash is now also doubled before any non-ASCII character and before `x`, `u` or `U` followed
  by non-ASCII look-alike hex digits, and a kept character standing directly before such an escape
  body is escaped, so at least fullwidth, Cyrillic, combining-mark and look-alike-backslash
  spellings of an escape no longer pass for an escaped bidirectional override. An ASCII letter
  that resembles a hex digit, such as `l` for `1`, is still not treated as one, in either mode.
  At least the `connscale` pooled-arm miss notes and the batch-box cell notes, and a `shardcert`
  provisioning failure's traceback, still print engine output as it came.
- **`samples/send_mllp.py` refuses a file holding an MLLP frame byte (ASVS 1.1.2).** The sender the
  operator docs tell a deployer to run framed a named file with the unchecked framer, so a file
  holding `0x1C`, CR, `0x0B` and a second MSH segment would have gone out as two frames. It now
  frames with `frame_checked`, the rule the engine's own MLLP delivery refuses by
  ([ADR 0205](docs/adr/0205-an-outbound-frame-holds-exactly-one-message.md) rule 1), before it
  connects. A refused file prints the reason to stderr, and the helper exits 3 without opening a
  connection. A file saved with its own MLLP framing around it is refused too; strip that first.
- **More of the tools that print a peer's text now escape it first, and harness labels fed by the
  engine show it as plain text (ASVS 1.1.2).** `rigadmin get` printed any 200 body raw, the
  attachment route included, so on first deployment a sender's ESC or OSC sequence would have
  reached the terminal of whoever ran it. It now prints a non-JSON body by the rule
  `samples/send_mllp.py` already printed an ACK by, which now lives once in
  `messagefoundry/terminal_text.py`: printable ASCII, newline and tab as themselves, every other
  character as a visible `\xNN`, `\uNNNN` or `\UNNNNNNNN` escape. A JSON body keeps its value:
  plain JSON prints byte for byte, and any other character prints as JSON's own `\uNNNN` escape.
  The harness scenario and load command lines escape the engine's error text and a scenario's
  detail the same way, so an em dash in that text now shows as `—`, and the harness reconcile
  text report escapes the message keys and difference lines it lists. The harness monitor status
  and stats labels, the receive status label and the sign-in error label are now plain text, so
  engine or peer text that looks like HTML is shown as written. At least `tee naks` and the JWKS
  key ids in `messagefoundry verify` still print a peer's text as it came.
- **`tls_check_hostname = false` is a recorded loosening now, never a silent one (ASVS 12.3.2).**
  The MLLP, FTPS, Email and Direct hops log a WARNING at each construction that names the connection
  and the host. `messagefoundry check` gains an advisory `tls-check-hostname` line, and
  `security_loosenings()`, and so `GET /security/posture`, gains a `tls_check_hostname` entry. On a
  first deployment the flag would have been accepted with no line anywhere on MLLP, on Email and
  Direct without credentials, and on a hand-built FTPS spec. It is not refused under
  `enforcement = enforce`, on the `tls_allow_expired` precedent. The `tls_allow_expired` WARNING,
  `check` line and registry entry no longer claim the hostname is verified on a hop that turns that
  check off. See [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md).
- **A credential in a connection `url`'s query string is a recorded loosening now (ASVS 14.2.1).**
  A WARNING names the connection and the parameter names, never a value, when the resolved `url`
  of an outbound or a `FhirLookup` carries a parameter named like a credential (`key`, `sig`,
  `signature`, or a name ending in `token`, `secret`, `password` and the rest of the engine's
  credential vocabulary, in snake_case or camelCase). It fires at least on a build check and on a
  start; a reload that replaces a running graph skips it on its rebuilds.
  docs/SECURITY-LOOSENING.md says where it fires. `messagefoundry check` gains an advisory
  `url-query-credential` line, and `security_loosenings()`, and so `GET /security/posture`, gains a
  `url_query_credential` entry. `GET /metadata` and `graph --json` now withhold such a URL whole,
  and any other URL setting that may carry a credential; they used to mask only a userinfo password
  and keep the user, host and path. The rule is in `config/wiring.py`
  (`_url_may_carry_a_credential`). On a first
  deployment such a URL would have been accepted with no line anywhere and served verbatim by those
  views. It is warned rather than refused, unlike a credential in the URL's user part: a query
  credential does authenticate, and some partner APIs take it nowhere else. See
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md).
- **The Vault TLS context now pins the approved key-exchange groups, as every other engine-built
  context does (ASVS 11.6.2).** `assert_hvac_tls_suites` calls `harden_kex_groups` on each context
  it builds. It pins nothing until Python 3.15 adds `SSLContext.set_groups`, the same as every other
  site. The data-layer census in [SECURITY.md](docs/SECURITY.md) no longer says the Vault hops
  have no scheme gate; engine PR 1880 added one, and those rows are corrected in place.
- **The off-box audit record stays valid JSON after the log scrub in more cases, and the tee adds
  no escaping before redaction.** The scrub spelled some characters as `\x7f` or `\U000e0001`,
  which JSON does not allow. At least a DEL, a C1 control, a soft hyphen or an escaped astral
  code point then left the collector unable to parse the record. The astral ones include at
  least format, unassigned and private-use code points. The field could be at least `action`,
  `actor`, `channel_id`, `client` or `detail`. A failed sign-in sets `actor` to the typed name,
  so a client could have caused this on a first deployment. The scrub now writes every escape
  in a form JSON accepts inside a string. So the audit tee keeps plain `json.dumps` and adds no
  escaping of its own. The first handler's redaction and credential filters see each character
  unescaped, except the quote, the backslash and the 32 C0 controls. `json.dumps` escapes those
  itself. Escaping more characters before the filters would hide a name or a `password=` value
  from them. At least three residuals remain, and the `emit_audit_tee` docstring names them. A
  filter can still take a closing quote, so the record fails to parse. With two
  attacker-influenced fields, the record can instead parse with fields missing, or with one
  field's text under another key. A later handler, the forwarder included, re-runs the filters
  over the first handler's escaped text. So a record that parses on stdout can fail there. And
  the filters can still miss text beside a C0 control, on either side. Measured cases include a
  name, a date, a bearer token and a `password=` value, which then reach the tee line
  unredacted. That third residual is not new: the code before this fix did the same. (vault
  `BACKLOG #3012`)
- **Many escaped characters in engine log lines are spelled differently.** An escaped code
  point up to U+00FF now takes JSON's form: DEL is `\u007f` where it was `\x7f`. This covers
  the C0 and C1 controls and the soft hyphen too. An escaped code point past U+FFFF is a
  surrogate pair: `\udb40\udc01` where it was `\U000e0001`. Printable characters such as emoji
  stay raw, as before. A lone surrogate is `\\udcff`, with the backslash doubled. A strict JSON
  decoder refuses an unpaired `\udcff`. Tab, CR, LF, and every escaped character from U+0100
  to U+FFFF that is not a surrogate, keep their spelling. A log reader or alert rule that
  matched a changed spelling would need the new one.
- **The repository's locks pin certifi 2026.10.19, past
  [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2).** The version locked
  before, 2026.7.22, trusted a root whose intermediates have compromised keys, and certifi
  2026.10.19 drops that root. A hop that trusts the certifi bundle, such as a Vault hop with no CA
  file set, would otherwise accept a forged certificate from an on-path attacker. Not covered by
  this change: the copy pip vendors, and the container image's own trust store.
- **BREAKING -- `messagefoundry check` now fails settings the retention start gate refuses.**
  `serve` refuses to start under `enforce` on an explicit `0` for an auto-bounded PHI retention
  window, and on a warn-only tier with neither a window nor its own acknowledgement. `check`
  passed the same settings. A new required check, `retention`, calls the function `serve` calls,
  so the refusal reads the same in both. Under `enforcement = warn` the gate warns instead, so
  the check passes and carries the warnings `serve` would write. A pass is about this gate
  alone; `serve` has other start gates. The check is skipped at least with no settings file, and
  for an environment name whose production tier is unresolved. Settings that name no
  environment are still judged, because a site may name it only on `serve --env`; the line
  then prints a placeholder for the name and says so.
  `serve`'s own text, exit code and defaulting are unchanged, with one exception: the notice for
  a defaulted window now reads the bound from each window instead of a fixed `(30 days)`, which
  prints the same text while every bound is 30.
  `messagefoundry init` now writes the two settings a new repository needs to pass this check:
  `[security].allow_keeping_transform_state_indefinitely = true`, an audited loosening, and
  `[retention].search_preset_days = 30`.
  `supervise` does not pre-check this settings gate. On settings the gate refuses, each engine
  shard would refuse to start and the supervisor would restart it until its crash-loop breaker
  trips. Run `check` first.
  **Who this would bite on first deployment:** a config repository whose CI runs `check` against
  settings that leave transform state or saved searches with no window and no acknowledgement.
  **Remedy:** the failure names each tier and its switch.
  [CONFIGURATION.md](docs/CONFIGURATION.md#retention) has the table.
  (`BACKLOG #2280`, `BACKLOG #2369`)
- **The Email destination refuses a body it cannot encode without naming any of it.** Such a body
  raised a bare `UnicodeEncodeError`. Its text named a character of the message, and its `.object`
  held the whole payload. The delivery worker would have stored that text as an internal error, or
  stopped the lane under the STOP policy. The body now goes through the shared `encode_wire_body`,
  as on Direct. The refusal is permanent, names the charset and a position, and carries no
  exception chain. A second check covers the encode inside the email package, which Python 3.15
  does in a different charset for `euc-jp` and `shift_jis`.
- **The route-gate walk and the refusal count read the `RouteContext` shape of FastAPI 0.143.1.**
  From 0.143.1, a FastAPI `RouteContext` for an included non-API route answers its properties and
  its attribute fallback from the rebuilt route it serves, not from its own record, so reading
  `starlette_route` through that fallback found nothing. On an app with such an include, the walk
  in `scripts/security/route_gates.py` raised `MissingFastAPISymbol` for at least every included
  plain route, WebSocket and mount, and `GET /security/posture` would have dropped an included
  WebSocket's refusal count. The app `create_app` builds registers no included route, so its own
  walk rows were unchanged; the failures were in the walk's tests, which build such apps. Both now
  read the rebuilt route from the context's own record. The route tests pass on at least FastAPI
  0.142.0, 0.143.0, 0.143.1, 0.151.0 and 0.153.0. Request-time refusal of an undeclared route was
  not affected.
- **The engine API turns fastapi's built-in OpenTelemetry telemetry off.** fastapi 0.142 turns it
  on by default. An `OTEL_EXPORTER_OTLP_*` endpoint in the service environment, with the OpenTelemetry
  SDK installed, would have made fastapi install its own OTLP exporters before startup. Its logs
  carry unhandled-exception messages and stack traces, either of which can hold PHI. `create_app` now passes a
  telemetry config with every switch off, so no environment variable can start that export. The
  engine's own optional OTLP metrics export is separate and unchanged. The FastAPI floor is now
  0.142.0, the first release with the `telemetry` argument. Superseded in this release: the floor
  is `fastapi>=0.143.1`.
- **The federated bind, rebind and unbind audit rows say whether the account holds engine
  factors.** `auth.federated_subject_bound`, `auth.federated_subject_rebound` and
  `auth.federated_subject_unbound` now carry `totp_enrolled` and `webauthn_enrolled`. A bind or
  rebind row reads them when the old binding is removed, so it can miss a factor change made just
  before the new binding is written.
  ([Keep a local Administrator](docs/SECURITY.md#keep-a-local-administrator), vault BACKLOG #2711)
- **The send-time proxy credential rule reads a header name however it is spelled.** The opener
  matched a caller-set header's name against `Proxy-Authorization` in any letter case, but did
  not trim it. `http.client` sends at least a name that ends in a space, a tab, a NUL, a
  backspace or a DEL as written. So on a connection with no
  `proxy_user`, a static header keyed `Proxy-Authorization` plus trailing whitespace would have
  reached a cleartext proxy, or the destination on a direct send, without a refusal. One function
  now reads the name: it ignores the letter case and every character at either end that a header
  name cannot hold, and it reads a `bytes` name as the wire would carry it. The message-metadata
  rule calls it too, and so does the build-time refusal of a static `Proxy-Authorization` beside
  `proxy_user`. A connection's admission of its own `proxy_user` header covers the plain
  spelling only, and the opener reads every matching header on a request, so one cannot hide
  another. A spelling `http.client` can never send still fails with a `ValueError`, after every
  credential refusal has run, so at least the REST send still maps it to a permanent refusal.
  The rule is stated on
  [`ProxyCredentialsRefusedError`](messagefoundry/transports/bounded_read.py).
- **A purge on SQLite now overwrites the old bytes, and the WAL is truncated hourly, by default.**
  A purge blanked a body but left its bytes in the file's free space and in stale `-wal` frames.
  The new `[store].secure_delete` (default `true`) sets `PRAGMA secure_delete` on the writer
  connection, so SQLite zeroes what a delete or a purge frees. `[retention].wal_checkpoint_seconds`
  now defaults to `3600`, so the retention pass truncates the `-wal` file after its purges. Both
  cost some extra write I/O; set them off for throughput only if leaving purged bytes in the file is
  acceptable. SQLite only. Turning `secure_delete` off on a file-backed store is a loosening that
  `security_loosenings()` names. When a reader or a DR snapshot copy stops the retention pass's
  truncate, the pass now logs a WARNING instead of passing in silence. (`vault BACKLOG #2619`)
- **No upload audit row carries the file name.** `upload.create`, `upload.delete`, `upload.reject`
  and `upload.reject_quota` wrote the operator-chosen file name into `audit_log.detail`, which is
  plaintext and kept. A stored file is now named by its `file_id`, and a refused one by its reason.
  The uploader's own error response still names the file. (`vault BACKLOG #2619`)
- **`docs/PHI.md` now says what a second length cut does to an earlier truncation note, and states
  the custom-delimiter residual an operator could not read before.** No redaction output changes.
  The store cuts a diagnostic again after an emit site already bounded it. The doc said a stored
  value then ends in one count. That was wrong: an earlier note that ends before the new cut is
  most often kept, so a value can hold two counts. The doc also now says the count is per call,
  with earlier notes counted as plain characters. So it is not how much of the original text the
  value lacks, and a dropped `[redaction bound: ...]` marker takes its unscanned figure with it.
  Text a peer writes can end a stored value early, at least by quoting the opening of such a
  note. Section 7 said a feed declaring its own HL7 separators "is covered". It now names the
  accepted gap from `BACKLOG #1848`: when the 64 KiB scan bound drops the MSH that declares the
  delimiters, a custom-delimiter run in the kept text is not scrubbed. On a first deployment such
  a diagnostic would keep those field values in the log or the store. The details are in
  `docs/PHI.md`, under *The store's 200-character bound* and *A third residual*. New tests pin the
  note behaviour, and one pins that a token ending exactly on the limit is kept. (vault
  `BACKLOG #3034`, items 2 to 6)
- **The RemoteFile destination refuses a payload it cannot encode without naming any of it.** Such a
  payload raised a bare `UnicodeEncodeError` on SFTP, FTP and FTPS uploads. Its text named a
  character of the message, and its `.object` held the whole payload. The delivery worker stored
  that text as an internal error, and `internal_error` decided the rest. The payload now goes
  through the shared `encode_wire_body`, as on Direct. The refusal is permanent, names the charset
  and a position, carries no exception chain, and comes before anything is sent.
- **Under `internal_error = stop`, an unencodable RemoteFile payload no longer stops the lane.**
  Before, `stop` kept the row queued, stopped the lane, and raised a `connection_stopped` alert.
  The engine now treats the refusal as a bad message. The row dead-letters on the first attempt
  under either policy, and no alert fires. One bad message no longer holds every message behind it,
  and the row stays replayable from the dead-letter queue. (vault `BACKLOG #3044`)
- **BREAKING -- `messagefoundry check` and `supervise` now refuse a connection's own keep-forever
  retention override that `serve` refuses.** An inbound `messages_days = 0` or an outbound
  `dead_letter_days = 0` with no `[security].allow_keeping_phi_indefinitely = true` is refused by
  an enforcing engine when it loads the graph. `check` passed that graph. A new required check,
  `retention-overrides`, now fails it in the engine's words. `supervise` did not look either, so
  on a first deployment each engine shard would have refused the graph and been restarted. It now
  refuses once, before it starts an engine shard, with exit code 2. Under `enforcement = warn`,
  or with the acknowledgement, both pass the graph; `check` shows the line the engine would
  write, and neither writes the warning or the `AUDIT:` line itself. `connection upsert` and
  `remove` now read the same decision instead of their own copy of it; what they refuse is
  unchanged.
  **Who this would bite on first deployment:** a config repository whose CI runs `check` on a
  graph with such an override and no acknowledgement. **Remedy:** the failure names each
  connection and the switch. Read *Per-connection overrides* in
  [CONFIGURATION.md](docs/CONFIGURATION.md#retention) before setting it. (`BACKLOG #2368`)
- **A redacted `UnicodeError` no longer prints a false position, and names a codec by a tighter
  rule.** Windows `mbcs` and `oem` errors raise with an empty span at index 0, wherever the
  character sat. `safe_exc` printed that as `position 0`. It now prints no position for an empty
  span, as in `'mbcs' codec cannot encode: invalid character`. A span of one or more characters
  reads as before. `safe_exc` prints a codec name only when it is exactly one of a fixed set of
  strings. The set holds each stdlib text codec name and non-numeric alias, in the spellings the
  codecs report, plus `cp1`. A real `oem` error reports `cp1`. Another spelling of a known name,
  such as `UTF-8` or `u-t-f-8`, no longer prints. A Windows code page with no stdlib module, such
  as `cp20127`, prints no name, as before. A digit-only alias such as `1252`, the `aliases` helper
  module and the bytes-to-bytes transforms such as `base64` are no longer printed. (vault
  `BACKLOG #3206`, items 1, 2 and 4)
- **The Email destination refuses, at load, a subject whose encoded word decodes to a control
  character.** The header parser decodes RFC 2047 encoded words in the configured subject. So
  `=?utf-8?b?AA==?=` held no control character as text, and the message would have gone out with
  a raw NUL in its `Subject:` line. The destination now sets the subject on a scratch message at
  load and refuses a read-back that holds a control character. A site deploying such a subject
  would get a load refusal naming the setting, and never its value. An encoded word that decodes
  to plain text still loads. (vault `BACKLOG #3206`, item 6)
- **A store-key rotation no longer resets the age of every other tracked secret.** The secret-rotation
  watcher fingerprints each secret under a key derived from the store key. Rotating the store key
  changed every fingerprint. On first deployment, every other secret would have read as rotated that
  day. That would have lifted each overdue refusal under `[secret_rotation].enforce_secret_expiry_classes`.
  Each fingerprint now names the key that made it. A changed key alone is a re-key: the engine
  re-fingerprints the secret and keeps its last-rotated date. Keep the prior store key in
  `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` through the engine's first start after `rotate-key`. Then a
  secret changed at the same time still reads as rotated. Without that key the engine cannot tell.
  It keeps the older date and logs a warning.

## [0.5.1] — 2026-10-01 — Early Access

### Changed
- **The service installer's NSSM download falls back to a mirror when `nssm.cc` fails.**
  `install-service.ps1` tries `nssm.cc` first, then the Internet Archive's copy of the same
  `nssm-2.24.zip`. Every download is still checked against the pinned archive SHA-256 before it is
  opened, and the extracted `nssm.exe` against the binary pin, so a mirror serving other bytes is
  skipped. With no source matching, the install stops and installs nothing. Allow
  `web.archive.org` on 443 at install time if `nssm.cc` may be unreachable; see
  [ANTIVIRUS-FIREWALL.md](docs/ANTIVIRUS-FIREWALL.md). (`BACKLOG #2504`)
- **The `[vault]` extra now declares `requests>=2.32.2`.** Most of the Vault clients' send-time hop
  checks run in a requests hook that requests first calls in 2.32.2. The extra used to leave
  requests to hvac, which does not require that version. So an install resolved without the lock
  could get an older requests, on which those checks would not run. The lock already pinned a newer
  requests, so no pinned version moves. ([BACKLOG #2548](docs/BACKLOG.md))

### Fixed
- **Correction to the 0.4.0 note on the load reconcile: the stranding budget caused the connscale
  red it names.** That note said the
  `tests/test_connscale_smoke.py::test_no_loss_reconciles_at_every_step` failure
  (`engine_read 15 < confirmed sent 18`) was the exact-shortfall arm, with a different cause such as
  absent rows. Both arms failed, and the budget is why the shortfall arm did. 15 unconfirmed sends
  of 18 were over the budget of 13, so the connscale reconcile excused none of them and judged all
  18 as confirmed. The per-message intake audit on that run found no accept-ACKed send without a
  row. A new test in `tests/test_harness_reconcile.py` pins the arithmetic. Test and comment changes
  only; no engine behaviour changes. (`BACKLOG #1866`)
- **The `messagefoundry-harness` wheel now ships `LICENSE` and `NOTICE`, and the web console's
  copies are pinned to LF.** A web console wheel built from a fresh or renormalized Windows
  checkout no longer carries CRLF license bytes that differ from the released Linux wheel. A
  checkout made before the pin keeps CRLF in those two files until they are deleted and checked
  out again. CI and each release job check that every separate wheel carries both files.
  (`BACKLOG #2513`)
- **The `messagefoundry-harness` wheel passes its release smoke again.** The release job installs
  the harness wheel without its dependencies and imports `harness.__main__` to prove the wheel
  carries its code. Two engine imports at the top of that module made the import fail, so the
  v0.5.0 release published the engine and toolkit but not the harness. The imports now run inside
  `main()`, and `tests/test_harness_entry_imports_no_engine.py` imports the entry module with only
  the standard library available, so the next one fails in CI instead of at tag time.

### Security
- **BREAKING: `MEFOR_ALLOW_INSECURE_TLS` is honoured only where an instance posture is known.** A
  weakened-TLS check that reads no posture used to fall back to the unclamped escape. On a first
  deployment at the shipped `[security].enforcement = enforce`, that would have let a CLI command
  that opens the store, or a reference sync, cross a weakened or cleartext hop. With no posture the
  escape is now refused, whatever the dial says. `serve` always passes its posture, so a `warn`
  instance keeps the escape there, and so do at least `provision-admin`, `store provision-schema` and
  `check-privileges`. At least `admin-unlock`, `admin-set-notify-email`, `audit-verify`,
  `audit-anchor`, `rekey-audit`, `rotate-key`, `backup`, `support-bundle` and `verify` pass none, so they refuse a weakened store even at `warn`. Give a dev store a verifying certificate.
  ([SECURITY.md](docs/SECURITY.md), vault `BACKLOG #2354`)
- **A `DatabaseRef` reference source with weakened TLS is refused at `messagefoundry check`, dry-run
  and reload**, as well as at every sync. A sync now carries the engine's posture, so the escape is
  clamped there as it is for `db_lookup`. A source whose `env()` values do not resolve at check time
  is left to its sync, as before. (vault `BACKLOG #2354`)
- **The documented `gh attestation verify` commands now name the release workflow and the tag.**
  At least the install guides, the README and the CI gate `messagefoundry init` writes passed
  `--repo` alone, which accepts an attestation from any workflow or ref in the repository. They
  now add `--signer-workflow` and `--source-ref`. How tightly those flags pin depends on `gh`:
  `--source-ref` needs `gh` 2.68.0 or later, and before 2.102.0 `gh` matches `--signer-workflow`
  against only the start of the signing identity and compares `--source-ref` ignoring case. The
  scaffolded gate refuses `gh` older than 2.68.0 and warns below 2.102.0. It rebuilds the tag from
  the pinned wheel, so a pre-release wheel `0.5.0rc1` checks against tag `v0.5.0-rc1`. A config
  repo scaffolded before this change keeps the old gate until its `check.yml` is updated by hand.
  (`BACKLOG #2534`)
- **An engine release tag must be spelled `vX.Y.Z` or `vX.Y.Z-aN`, `-bN` or `-rcN`.** The release
  job refuses any other spelling before it builds anything, because a verifier rebuilds the tag
  from the wheel's version and could not rebuild `v0.5.0-rc.1` or `v0.5.0-post1`. Every engine
  tag to date is a plain `vX.Y.Z`. (`BACKLOG #2534`)
- **The FILE source now archives or deletes only the file it read, and only into the archive
  directory it opened.** The check before a move or delete compares the file's identity with the
  handle that was read, so a file renamed over the name after the read is left for the next scan
  rather than archived or deleted unread. `.processed` and `.error` are opened through no link for
  every move, so one replaced by a link after start is refused and nothing is written through it.
  On Windows the listing and the read no longer open a link at a drop's name, so a link to a UNC
  path or a named pipe does not reach that server through them, and the move and delete act on the checked handle
  rather than the name. On POSIX the copy the archive falls back to (the usual path where
  `fs.protected_hardlinks` refuses a link) opens the name `O_NONBLOCK`, so a FIFO swapped in no
  longer holds a worker thread. Hard links are still not refused; see the FILE section of
  `docs/CONNECTIONS.md` for that and the other limits. ([BACKLOG #2535](docs/BACKLOG.md))
- **The IDE's Live Debug now reveals real values one run at a time.** The old *Reveal Values*
  toggle stayed on once clicked. Every later run then passed `--show-phi` and showed real values in
  every module until the user turned it off. On a first deployment that toggle would have shown
  message values from runs nobody asked to reveal. Now *Reveal Values for One Run* re-runs once with
  real values shown, and turns Live Debug on first if it is off. While Live Debug is on, a click on
  the **Values: Hidden** status-bar item does the same. The values go as soon as the next run, such
  as the next save, starts. *Hide Revealed Values* hides them sooner, or cancels a reveal still
  running. The command `messagefoundry.toggleRevealValues` is gone. (ASVS 14.2.6, vault
  `BACKLOG #1187`)
- **BREAKING: `[auth].ad_allow_insecure_ldap` is inert under `[security].enforcement = enforce`.**
  It used to be honoured at any dial, so on a first deployment at the shipped `enforce` a plain
  `ldap://` `ad_server` would have sent the service-account and user passwords in cleartext. That
  config is now refused at load, and again when the authenticator is built. This matches the
  `MEFOR_ALLOW_INSECURE_TLS` escape, which is already inert under `enforce`. A loopback `ldap://`
  address is refused too, and so is a bare host name with no `ldaps://` scheme. Under `warn` the
  opt-in still works: it logs a WARNING at startup, and `security_loosenings()`, the `serve` warning
  and `GET /security/posture` name it. Use an `ldaps://` server.
  ([SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md), vault `BACKLOG #2354`)
- **The Vault clients refuse a proxy URL that carries credentials and is not `https://`.** An
  `https://` Vault behind an `http://` proxy keeps its token inside the TLS tunnel. But requests
  sends a `user:password@` from the proxy URL to the proxy itself, in cleartext. At least the KV
  secret provider, the store key provider and the Transit cipher now refuse that proxy. The refusal
  comes when the client is built, as the provider's own fail-closed error, and again before each
  send. It covers the proxy variables in either case, `ALL_PROXY` and the Windows system proxy. The
  text names no part of the proxy URL, and `[security].enforcement` does not relax it. An `https://`
  proxy with credentials, and an `http://` proxy without them, are unchanged. See `[secrets]` in
  [CONFIGURATION.md](docs/CONFIGURATION.md). ([BACKLOG #2547](docs/BACKLOG.md))
- **A FHIR connection can opt back into the plain `PUT {base}/{ResourceType}/{id}` for `update` and
  `if-match`, as a listed loosening.** The shipped transaction form keeps the resource id out of the
  URL, but at least Epic and Oracle Health (Millennium) document no `transaction` interaction, so it
  would fail against them. `FHIR(..., update_url_form="path")` sends the plain `PUT`, with an
  `if-match` ETag in the `If-Match` header and the reply captured as the plain resource. The id must
  match the FHIR id grammar and must not be only dots, or the message is dead-lettered unsent. The
  default stays `"transaction"`. Setting `"path"` on a connection that is not an update is refused at
  load. Each construction logs a WARNING naming the connection, and `messagefoundry check` adds a
  `fhir-update-path-form` line naming every connection that sets it. See
  [CONNECTIONS.md](docs/CONNECTIONS.md), "Vendor compatibility and the path-form opt-in", and
  [SECURITY-LOOSENING.md](docs/SECURITY-LOOSENING.md). (vault `BACKLOG #2550`, ASVS 14.2.1)
- **The per-name connection routes no longer tell a channel-scoped caller which names exist.**
  This covers at least `GET /connections/{name}/metadata` and `POST /connections/{name}/test`,
  `/test-credential`, `/start`, `/stop` and `/restart`. Such a caller now gets the same 403, body
  and `auth.channel_denied` audit row in three cases. These are an inbound outside its scope, a
  shared outbound, and a name that exists nowhere. Before, the first three routes answered 404 for
  a name that exists nowhere. The control routes refused an outbound with a body of their own. So
  on a first deployment a scoped user could have listed connection names by probing. A name in the
  caller's own scope that exists nowhere still answers 404, as any unknown name does for an
  unscoped caller. Names still show elsewhere, at least in `GET /metrics` and `GET /alerts/rules`,
  and `POST /connections/{name}/flag` has no per-channel check (see `docs/SECURITY.md`).
  ([BACKLOG #2551](docs/BACKLOG.md))
- **A remote file upload no longer replaces a partner file written at its chosen name after the
  listing.** With `overwrite` off, the default, the upload picks a free name from a listing, stores
  a temp, then renames it. The rename now refuses a name taken since, and the upload moves on to
  the next free name, a bounded number of times, then retries. SFTP publishes with the plain
  `RENAME` instead of `posix-rename`. FTP is not atomic on a server whose `RNTO` replaces; the
  remote file section of `docs/CONNECTIONS.md` says what holds where. `overwrite = true` still
  replaces. ([BACKLOG #2553](docs/BACKLOG.md))

## [0.5.0] — 2026-10-01 — Early Access

### Added
- **The `messagefoundry-toolkit` wheel is now signed, attested and licensed like the engine wheel.**
  The release job signs it with Sigstore, attaches its `.sigstore.json` bundle to the GitHub
  release, and adds it to the SLSA build-provenance subjects, so `gh attestation verify` works on
  it. The wheel now ships `LICENSE` and `NOTICE`. See
  [SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md). (`BACKLOG #1192`)
- **Both engine SBOMs now list the vendored defusedxml.** The engine carries defusedxml 0.7.1 in
  `messagefoundry/_vendor/`, so no installer pulls it, and the SBOM generator lists only installed
  packages. `scripts/security/sbom_finalize.py` now adds a component for each vendored package, with
  its version, `PSF-2.0` licence and purl `pkg:pypi/defusedxml@0.7.1`. Its `pedigree` records the
  upstream sdist hash and each upstream file's SHA-256. A scanner reading either SBOM can now match
  an advisory against the copy the engine runs. (`BACKLOG #2498`)
- **A Windows-resolved engine SBOM ships with each release.** The new signed release asset
  `messagefoundry-sbom-windows.cdx.json` lists the packages the engine installs on Windows, beside
  `messagefoundry-sbom.cdx.json` for Linux. The two differ because the core lock picks some packages
  by platform. It carries its own Sigstore bundle and SLSA provenance, so the checks in
  [SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) work on it too. A release now scores both engine SBOMs
  with sbomqs even when one score fails. The nightly and manual `security.yml` runs now score the
  Windows SBOM too, so a fault in it can show before a tag reaches it. (`BACKLOG #2521`)

### Changed
- **A new default limit on the MLLP listener: `max_inflight_frames` (32).** At most this many
  complete frames of one listener are in the inbound handler (decode, parse, validate, ingress
  commit) at once. The row measured about 64 MiB of handling cost per 16 MiB message, so the peak
  was `max_connections` times that, 10 to 16 GiB across 256 frames; it is now a setting of its own.
  A frame over the limit waits for a slot, first come first served, and is never refused, dropped
  or NAK'd; once decoded it is always handled, as with the limit off, and a waiter still queued at
  stop is cancelled past the shutdown grace like a slow handler. It still holds the bytes it arrived
  in, so the raw buffer bound is unchanged. `None`/`0` turns it off. It is an inbound-only parameter of `MLLP()` and of a `connections.toml` MLLP inbound.
  ([BACKLOG #1725](docs/BACKLOG.md), act 3)
- **`messagefoundry generate` now gives every ORM^O01 an order detail.** The generator used to
  leave ORDER_DETAIL out, because it emitted every required child of a group, and the order
  detail's OBR/RQD/RQ1/RXO/ODS/ODT group is a choice. It now emits one alternative of a choice
  group, OBR by default. Each generated ORM^O01 now ends ORC then OBR and passes strict
  validation, so a corpus generated before this change differs in its ORM files.
  (`BACKLOG #2497`)

### Removed
- **python-hl7 is no longer a dependency.** The engine's own tolerant parser (ADR 0054) has been the
  default since it merged, and python-hl7 was only its fallback. The fallback is gone, and so are
  the `parsing/_backend.py` switch and the logger silencer that existed for python-hl7. A fault
  inside the parser is now refused as `HL7PeekError`, which the listener NAKs `AR` and records as
  `ERROR`; before, it fell back to python-hl7. **BREAKING:** `Message.parse` on a body with no
  leading `MSH`, `FHS` or `BHS`, or with a header too short to read, now raises `HL7PeekError`, a
  `ValueError`, where it raised `hl7.ParseException` or an `IndexError`. A Handler that catches
  `ValueError` around it now catches that refusal too.
  The outbound MSH encoding-character override now re-encodes through the engine's parser too. A
  field whose escape character is never closed now reads with that text kept: `SMITH\` reads as
  `SMITH\`, where python-hl7 dropped it and read `SMITH` (upstream python-hl7 issue 84). The
  parity suite holds the parser to python-hl7 0.4.5's answers, recorded once before it left. (ADR
  0054 amendment)

### Fixed
- **A DATABASE connection's `connect_timeout` now bounds the SQL Server login.** The SQL Server
  preset used to write it into the connection string as `Connection Timeout`, which ODBC Driver 18
  ignores, so the setting did nothing. It now reaches the driver as its login timeout, at least on
  `Database(...)`, `DatabasePoll(...)`, `DatabaseLookup(...)` and `DatabaseRef(...)`. The `generic`
  dialect is unchanged and still gets no login timeout from the engine. The value must be a whole
  number of seconds, at least 1. The first three refuse any other value when the connection is
  built. `DatabaseRef` refuses a literal value when declared, but an `env()` value only at each sync,
  so `messagefoundry check` does not catch that case. (`BACKLOG #2089`)
- **The DICOM server (SCP) now answers a status that tells the sender whether to re-send.** An object
  over the object or inflate cap was answered Out of Resources (`0xA700`), which senders retry, though
  a re-send is refused again. It is now Cannot Understand `0xC010`, a final refusal. A commit that
  raised was answered Cannot Understand (`0xC000`), though a store that is down may recover. It is now
  Out of Resources (`0xA700`), as is a C-STORE that arrives after the engine's loop has stopped. A
  negative `max_object_bytes` is still refused at build, but the message
  no longer says `0` or `None` disables the cap; on the SCP both resolve to 16 MiB. See
  `docs/DICOM.md` section 3 for the statuses. (`BACKLOG #2103`)
- **The DICOM server (SCP) now refuses a small deflated object that inflates past 16 MiB.** It bounded
  the inflate by `max_object_bytes`, 128 MiB at the shipped default, while the codec that parses the
  object after commit refuses anything past a fixed 16 MiB. So such an object was answered Success
  and could then only be recorded `ERROR`. The SCP's inflate bound is now the lesser of
  `max_object_bytes` and 16 MiB, and the object is refused before commit. (`BACKLOG #2104`)
- **A generated OBR now repeats its order's placer and filler numbers.** OBR-2 and OBR-3 drew
  fresh numbers instead of copying ORC-2 and ORC-3, as HL7 requires. In generated OML, MDM and
  ORU messages that carry an ORC then an OBR, only those two fields change, so a corpus
  generated before this change differs there. (`BACKLOG #2497`)
- **AD sign-in no longer fails on Linux over the receive timeout.** The engine passed
  `[auth].ad_receive_timeout`, a float, straight to ldap3. On every non-Windows host ldap3 packs
  that value as an integer. So each AD socket open would have raised `struct.error` after the TCP
  connect and before the bind was sent. On a first Linux deployment, AD sign-in would have failed
  for every user. Windows was not affected. The engine now passes ldap3 the timeout rounded up to
  whole seconds, so it is never shorter than configured. Both AD timeouts are also refused at
  config load above 3600 seconds. That cap keeps them far below the point where a socket timeout
  overflows, which would fail sign-in outside the audited error path. (`BACKLOG #2546`)

### Security
- **On the stdlib event loop, an MLLP TLS listener now applies `source_ip_allowlist`,
  `max_connections` and `max_connections_per_host` before the TLS handshake, not after it.** The
  listener accepts plain TCP, runs those checks exactly as a plaintext listener does, and only then
  starts TLS on the admitted socket. Before, a socket that never sent a ClientHello sat outside all
  three for up to the 10 s handshake bound, so a peer could hold as many as its connect rate
  allowed. Now each one holds a real slot, is refused with the same `at_capacity` or
  `peer_not_allowlisted` event as a plaintext connection, and is closed by stop(). A socket refused
  this way never starts a handshake. A handshake that fails or times out gives its slot back and,
  as before, emits no connection event and logs at DEBUG only. `established` is emitted once the
  handshake completes. **Under uvloop, which the engine's own `uvloop` dependency installs outside
  Windows, nothing changes**: the loop still runs the handshake and the three checks apply after it,
  because the listener's own upgrade could not be verified safe on uvloop. ([BACKLOG #1606](docs/BACKLOG.md))
- **BREAKING: an alert rule's `control_action` now needs a connection-scoped `event_type`.** Config
  load refuses a rule that sets `control_action` with `event_type = "any"` or with any type outside
  `connection_stopped`, `connection_error`, `queue_buildup`, `message_stall`, `saturation` and
  `lane_stuck`. Most other types put a stand-in in `connection`, and some stand-ins fit the
  connection-name grammar, such as a bare username, `store` or a cert label. A catch-all rule could
  therefore aim a restart at an unrelated connection with that name. Load also refuses a
  `control_target` that is not a connection name, or one on a rule with no `control_action`. This
  replaces the advice in the `approval_too_early` and `initial_credential_expiring` entries of this
  release to scope such rules: those rules are now refused.
  ([ADR 0128](docs/adr/0128-alert-rule-connection-control-action-auto-stop-restart-on-fire.md),
  `BACKLOG #1898`)
- **BREAKING: a FHIR `update` or `if-match` no longer puts the resource id in the request URL.**
  A RESTful update is `PUT {base}/{ResourceType}/{id}`, so on a first deployment a message-derived
  id would have reached the receiving server's access logs. The `FHIR()` destination now sends both
  as the one entry of a `transaction` Bundle, POSTed to `{base}`. The entry's `request` carries
  `PUT {ResourceType}/{id}`, and the `If-Match` ETag moves into `request.ifMatch`. The resource is
  spliced in byte for byte. The receiving server must support the `transaction` interaction, and for
  `if-match` it must honor the entry's `ifMatch`. A 2xx reply whose entry status failed is
  classified on that status, and `capture_response_headers` reads `ETag`, `Location` and
  `Last-Modified` from the entry. A resource id made only of dots is now refused. A `fhir_lookup`
  read-by-id still carries the id in its path, which is what a RESTful read is; owner ruling R3
  names the two writes only. See [CONNECTIONS.md](docs/CONNECTIONS.md), "An update keeps the
  resource id out of the URL". (vault `BACKLOG #1965`, ASVS 14.2.1)
- **A connection event's or an alert's reason is masked until a per-item reveal** (ASVS 14.2.6,
  owner ruling R12). `ConnectionEventInfo.reason` and `AlertInstanceInfo.reason` join the
  per-property map on the `messages:view_summary` tier. `GET /events`,
  `GET /connections/{name}/events` and `GET /alerts/active` return each reason as `****` to a
  holder, and `null` to a caller without that permission, until a `reveal=<id>` query parameter
  asks for one. That reveal charges the PHI-read budget and writes a `connection_event_reveal` or
  `alert_reveal` audit row. The alert ack, resolve, suspend and resume replies mask the reason the
  same way. Every other field stays readable under the route's monitoring permission. The web
  console adds three reveal routes; its changelog has the console half. See
  [SECURITY.md](docs/SECURITY.md) and [PHI.md](docs/PHI.md) section 3. (`BACKLOG #2443`)
- **A connection's start-failure reason is masked until the operator reveals it** (ASVS 14.2.6,
  owner ruling R12). `ConnectionRow.error` and `ConnectionMetadata.error` join the per-property
  map on the `messages:view_summary` tier. `GET /connections` and
  `GET /connections/{name}/metadata` return the error as `****` to a holder, and `null` to a caller
  without that permission. `reveal=<connection name>` on the dashboard, or `reveal=true` on the
  metadata route, returns it whole. That reveal needs `messages:view_summary`, is refused for a
  connection outside a scoped caller's channels, charges the PHI-read budget, and writes a
  `connection_error_reveal` audit row. The `status` word, the `errored` count and every other field
  stay readable under `monitoring:read`. The metadata route gains an ungated `fault` field
  (`failed` or `filtered`), so a role that sees `error` as `null` can still tell that the connection
  is down. `EngineClient.connections()` takes the same `reveal`.
- **Each gated response model now gets a serializer over its own gated properties only.** The
  shared one covered every field with a gateable name, gated or not, so a model whose `metadata`
  is a dict could not be gated. The published schema of every other model is unchanged. See
  [SECURITY.md](docs/SECURITY.md) and [PHI.md](docs/PHI.md) section 2. (`BACKLOG #2443`)
- **The AD hop follows no LDAP referral.** ldap3 follows one by default, and on a bound connection
  it binds to the referred host with the same service-account password, over a TLS setup without the
  pinned CA or the narrowed suites, or over plain `ldap://`. A first deployment would have sent that
  password to whatever host one referral named. Every `ldap3.Connection` the engine builds now sets
  `auto_referrals=False`, and its `ldap3.Server` sets `allowed_referral_hosts=[]`. A referral result
  to a search or to the user bind is refused as a directory error naming only the referred hosts,
  and one to the service-account bind fails that bind as before. Sign-in audits it as
  `auth.login_error`, and the session reconciler never revokes on it. A site whose users or groups
  span several domains of a forest would need a global catalog, or a search base in the bound
  controller's own domain. The `BACKLOG #2494` TLS-context entry says a followed referral still gets
  a plain ldap3 context. This supersedes that note: no referral is followed, so no referred hop is
  opened. See [ADR 0180](docs/adr/0180-asserting-tls-suites-on-a-library-that-exposes-no-sslcontext.md)
  Amendment F. (`BACKLOG #2530`)

### Changed
- **The `[fhir]` extra now needs `fhir-core>=1.1.11`, and annotated-types is no longer capped.**
  `pyproject.toml` capped annotated-types below 0.8 because fhir-core 1.1.9 imported the `SLOTS`
  constant that 0.8.0 removed. fhir-core 1.1.10 defines it itself, so the cap is gone from the core
  dependencies and from `[fhir]`, and the lock moves to annotated-types 0.8.0. fhir-core 1.1.11 also
  refuses negative `positiveInt` and `unsignedInt` values, which its own changelog says earlier releases let through.

### Fixed
- **Strict validation no longer rejects an order message for carrying one order detail.**
  hl7apy 1.3.5 checks a `choice` group as if every alternative were required (upstream
  crs4/hl7apy issue 151). A strict inbound would have NAKed every `ORM^O01` and `ORR^O02` with
  an OBR or RXO order detail, with `Missing required child ORM_O01_CHOICE.RQD` or its per-version
  name, and the same for any other structure with a choice group. The engine now carries the
  upstream fix (PR 152, unmerged) at its own validation boundary: a choice group needs exactly
  one alternative, and two in one group are still rejected. Sixteen groups that hl7apy's
  v2.6+ tables label as choices are really sequences (RSP_E22_QUERY_ACK is QAK then QPD, for
  one); the engine keeps validating them as sequences, where PR 152 as written would reject
  every valid message of those structures. The shim stays on while
  hl7apy itself gets any of three synthetic probe messages wrong, and a test goes red on the first hl7apy release
  that fixes the bug, so the shim is removed with it.

### Removed
- **BREAKING: the `content_match` alert event type and the `content_label` rule filter are gone.**
  Nothing outside the tests could ever fire them. An `[[alerts.rules]]` entry naming `event_type =
  "content_match"` or setting `content_label` is now refused at load, like any unknown event type
  or key. `GET /alerts/rules` no longer reports `content_label` on a rule, and an alert instance's
  `reason` no longer falls back to an event `label`. ADR 0133 D3 is retracted and not planned, by
  owner ruling 2026-09-30; the ADR's "Retraction of D3" bullet says why
  ([ADR 0133](docs/adr/0133-alert-escalation-tiers-schedule-aware-thresholds-and-content-triggered-alerts-the-56-remainder.md)).
  D1 escalation tiers, D2 schedule-aware rules and the D4 `escalation_tier` column are unchanged.
  The engine UI seam digest moved with the `AlertRuleInfo` field set, so the web console's
  `SUPPORTED_ENGINE_SEAMS` moved with it. (`BACKLOG #1504`)

### Added
- **BREAKING: `adr-analyze` moved to a separate `messagefoundry-toolkit` command, and out of the
  engine wheel.** ADR 0201 slice 2 adds a third sibling distribution, `messagefoundry-toolkit`,
  released in lockstep with the engine and pinned to the engine's own version. It carries the
  authoring and development commands, and `adr-analyze` is the first to move: its module is
  `messagefoundry_toolkit/adr_analyze.py`, and the engine wheel no longer ships
  `messagefoundry/adr_analyze.py`. `messagefoundry adr-analyze` now exits 2 with one line naming
  `messagefoundry-toolkit adr-analyze`, as `{"error": ...}` on stdout under `--json`, and the engine's
  `--help` names the moved commands in its epilog. In a checkout, run `python -m
  messagefoundry_toolkit adr-analyze`. An installed toolkit refuses to run beside an engine of another
  version. The other toolkit rows of `CLI_TIERS` move in later slices. (`BACKLOG #1192`, ASVS 15.2.3)
- **Turning the sign-in limiter or the account lockout off is now warned, not silent.** While
  sign-in is on, `security_loosenings()` names `[auth].login_rate_limit_enabled = false`, a
  `login_rate_limit_per_ip` or `login_rate_limit_global` of `0`, a `login_rate_limit_window_seconds`
  of `0` or less, a `lockout_minutes` of `0` or less, and a `lockout_threshold` above the 100 that
  NIST SP 800-63B allows, so each reaches the `serve` loosening warning, `messagefoundry security
  show` and `GET /security/posture`. The shipped defaults report nothing new. (`BACKLOG #1131`,
  ASVS 6.1.1)
- **A sign-in rate limit, lockout setting, PHI-read or admin-write limit, sign-in or admin-write
  time floor, session cap or OIDC flow-cache cap looser than its shipped default is now a named
  security loosening, not only an off value.** A `1e-6` s window or a count of `1e9` used to pass
  silently while the control was off in effect. `[api].trusted_proxies` ranges that cover every peer, such as `0.0.0.0/0` or `::/0`, are
  named too, since they trust every peer as the refused `*` would. Stricter values and the defaults
  report nothing. (`BACKLOG #1131`; ASVS 6.1.1, 6.3.1, 2.3.2, 2.4.1, 2.4.2, 7.1.2)
- **Under the shipped `[security].require_mfa`, no local account can be locked by a stranger
  before its holder has a way past the lock.** ADR 0197 Amendment A, wave 1. With the requirement
  off or narrowed to administrators, an account with no TOTP keeps the fixed lock (residual 1), and
  an account from before this change keeps it until it enrols. The engine now generates the credential of every account an
  administrator creates, and the one an administrator's factor reset issues; `POST /users` takes no
  password and returns the credential once as `temp_password`, and `POST /users/{id}/reset-mfa`
  returns one for a local account. While a generated credential stands, wrong passwords are counted
  and audited but arm no sign-in lock. Under the shipped `[security].require_mfa`, the holder must
  enrol an authenticator app before choosing a password: `POST /me/password` and the console's
  password form refuse with `enrol an authenticator app first` until TOTP is on, and a passkey
  cannot be the first factor or replace TOTP yet. `provision-admin` now enrols TOTP at the terminal
  and prints recovery codes once; `--no-totp` is refused while MFA is required. Its repair of a
  roleless account now clears that account's factors and ends its sessions first. At startup the
  engine warns about, and audits, every covered account that still has a chosen password and no
  TOTP, and every TOTP key it cannot decrypt; `messagefoundry verify` reports the same as
  `auth.lockable_accounts`. The `users.password_generated` column is added on all three backends.
  If `[auth].password_extra_context_words` is so broad that no generated credential clears the
  policy, creating an account and both resets answer 503 and change nothing, and a spent step-up
  grant is given back; the engine logs an ERROR at start and `verify` fails
  `auth.credential_generation`. `provision-admin` shows the TOTP key and recovery codes on the
  controlling terminal only, never on stdout or stderr. (`BACKLOG #1131`, ASVS 6.1.1)
- **A site can add its own context words to the password screen.** `[auth].password_extra_context_words`
  lists terms such as an organization, product, project or department name. They join the shipped
  `CONTEXT_WORDS` in the same case-insensitive substring screen, which `password_check_context`
  switches as a whole. They are screened at least on user create, password change,
  first-administrator provisioning and an administrator's password reset, which the tests cover.
  The reset screens each generated password, the own-username clause included. If none clears the
  policy, it answers 503 with a detail naming the setting, and the account keeps its password. The
  setting can only add; no setting removes a shipped term. Each term is trimmed and lower-cased at
  load. It must be one word, no shorter than the floor `docs/CONFIGURATION.md` states. The load refuses a blank entry, a trailing
  comma in the environment form, a term with a space inside, and terms set while
  `password_check_context` is off. A site term's refusal says it is one of the site's additions, since
  the published list cannot hold it. A password holding a shipped term and a site term gets both
  refusals. Env: comma-separated or a JSON array, in `MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS`.
  (`BACKLOG #1132`)
- **Six connection factories take a per-connection `tls_ca_file`.** `Rest()`, `FHIR()`, `Soap()`,
  `DICOMweb()`, `FhirLookup()` and `Ftp()` (FTPS only) now accept a PEM path or an `env()`
  reference. When it is set, that hop trusts only the CAs in that file, never the OS store. The
  connectors already read the key; before this, no factory could write it. Unset, every hop is
  built exactly as before, so defaults are unchanged. `docs/CONNECTIONS.md`, "Pinning a private CA
  per connection", covers what is refused at load, the token hop, CRLs and failures.
  (`BACKLOG #1180`, ASVS 12.3.4)
- **The anonymizer now scrubs eight event, visit, order and observation date fields, the county
  and the patient location.** A new `date` rule kind keeps the year and fills the rest of a DTM/TS
  at the same width, with no salt, so two captured sides still match. The default rules apply it
  to `EVN-2`, `EVN-6`, `PID-29`, `PV1-44`, `PV1-45`, `ORC-9`, `OBR-7` and `OBX-14`, and redact
  `PID-12` and `PV1-3` whole. A date value that is not a valid, in-range timestamp is scrubbed to
  empty. Other date fields, such as `AIS-4` and `RXA-3`, are still unmapped, and `MSH-7` is still
  kept, so the output is not Safe Harbor de-identified; `docs/PHI.md` §9 lists the gaps. A
  `FieldRule` with an unknown kind is now refused when it is built. (`BACKLOG #2248`)
- **The anonymizer can refuse any field nobody decided.** `anonymize_checked` takes
  `require_full_coverage=True`, and `python -m tee anonymize-captures` takes
  `--require-full-coverage`. Both are off by default. When on, the leak-check refuses a present
  field that no rule scrubs and no `anon.toml` `keep` names, apart from short set ids, `PID-8` and
  `PV1-2`. A `keep` now counts as a decision: `load_rules` returns it as a `keep` rule instead of
  dropping it. A kept field is still scanned for PHI shapes. Expect it to refuse conformant traffic
  for now. It refused all 186 messages in a generated corpus. Coded fields such as `EVN-1` and
  `PV1-10` have no rule yet; the dates and locations it first named now do (`BACKLOG #2248`).
  `docs/PHI.md` §9 lists what the switch does not cover. (`BACKLOG #1710`)
- **Secret classes other than the store DEK can now refuse to start on calendar expiry, if you opt
  them in.** `[secret_rotation].enforce_secret_expiry_classes` lists the classes that refuse. Under
  `[security].enforcement = enforce`, a listed class the engine holds that is past
  `secret_max_age_days + enforce_grace_days`, or that has no recorded age on a keyed store, stops
  engine start with `SecretRotationOverdueError` and an enforced `secret_rotation` alert. Entries
  are the fixed `MEFOR_*` class names, or `connector` for every per-Connection `env()` credential. An
  unknown name, or the DEK's own name, is refused at config load. The list ships empty, so a
  configuration that does not set it behaves exactly as before: those classes only alert.
  (`BACKLOG #1932`, ASVS 13.3.4)
- **`POST /auth/login` can end the token it replaces.** A new optional `supersedes` body field
  names the session token the client is replacing. On a successful sign-in the engine ends it before
  the per-user cap counts, as the console sign-in legs do, so the cap does not sign out another
  device to make room. Without the field nothing changes. (`BACKLOG #2096`, ASVS 7.2.4)
- **The off-box log forwarder keeps what the collector does not take in a bounded on-disk spool.**
  A record the collector refuses, or that is still queued past the shutdown drain, is written to
  `[logging].forward_spool_dir` and sent in order when the collector answers, across
  restarts. It is best effort, not at least once: after a collector reset the first send on the dead
  connection can be lost, a restart can resend up to one segment (12.5 MB at the default cap), and
  over UDP no failed send is detected. A failed send backs off from 1 to 60 seconds. A TCP or TLS collector that is down
  at start is retried instead of dropped for the life of the process. The spool holds only text the
  PHI, credential and control-character filters already processed, and is capped by
  `[logging].forward_spool_max_bytes` (default 100 MB; `0` turns it off). A certificate that fails
  verification or a host name that does not resolve is reported at ERROR as permanent, never
  deferred. (`BACKLOG #1966`, ADR 0200)
- **A PHI instance under `enforce` refuses to start without verified-TLS log forwarding.** `serve`
  exits 2 unless `[logging]` forwards over TLS with verification on to a `forward_host` that is not
  loopback; under `enforcement = "warn"` it warns. The check reads configuration only, so a collector
  that is down does not block a start. A local agent on 127.0.0.1 and `forward_hop_attested` do not
  satisfy it. Owner ruling R4 (a). (`BACKLOG #1966`, ADR 0200, ASVS 16.4.3)
- **Administrators can now see which accounts are locked.** `GET /users` carries a `lock_state`
  object per account with both ADR 0197 locks: whether the sign-in lock and the second-step lock
  are live now, when each ends, and each one's failed-attempt and lock-cycle counts. The engine
  decides "live" on its own clock. The console's users list shows a "Locked until" badge on a locked
  account, and the user page shows both locks and the ways to end one early: an administrator
  password reset on a local account, or `messagefoundry admin-unlock` on the host. Only a
  `users:manage` holder gets the object; a `users:read`-only caller gets `lock_state: null`, and
  `/auth/me` carries none of it.
  Read-only: there is no new unlock route. (`BACKLOG #1131`, ASVS 6.1.1)
- **`messagefoundry check-privileges` reads the store principal's privileges and changes
  nothing.** It runs the startup store probe once, over one connection, as the configured login: no
  schema batch, no migration and no audit row, and a SQLite path is never created. It prints the
  store principal's roles against the grant `[store].schema_management` selects. It also prints the
  identity and least grant of the Vault, LDAP, SMTP and OIDC hops, marked not probed, because the
  engine has no read-only way to inspect those. It exits 0 when every probe that ran was clean, 3 on
  an over-grant, 4 when the store probe could not read the principal, and 1 when the settings do not
  load. It checks for grants beyond the documented set, not that the documented grants are present.
  `--db` overrides `[store].path`. `docs/SECURITY.md` gains the per-hop least-privilege table, and
  `docs/DEPLOY-SERVER-DB.md` §1.1 gains step 6, which runs the command as the gMSA. (`BACKLOG #305` part E2, ASVS 13.2.2)
- **An over-granted or unreadable store principal now raises a `store_privilege_warning` alert at
  start.** The privilege preflight's WARN arm already logged, audited and listed the finding in
  `security_loosenings()`. It now also fires the alert through the configured notifier, before any
  refusal, so a refused start still pages. An alert rule can match
  the new event type. A later start that reads a clean principal resolves the open alert. SQLite
  raises nothing, and a failing sink never hides the finding. (`BACKLOG #305` part E2, ASVS 13.2.2)
- **A sign-in from an address the account has not used recently is now challenged and reported.**
  At every session mint, on the local, Kerberos and OIDC legs, the engine compares the sign-in's
  client address with the addresses the account finished authenticating from: its own
  `auth.login_success` rows that owed no second factor, plus its `auth.mfa_verified` and
  `auth.webauthn_verified` rows, the newest 200 of each from the last 90 days. There is no schema
  change. A first-seen address writes `auth.login_new_ip` and sends the holder a `login_new_ip`
  notice (at most one per account and address per 15 minutes). On a sign-in that owes no second
  factor it also mints the session without step-up freshness. A sign-in that owes a factor, which
  is every local sign-in under the shipped `require_mfa` scope, and every directory sign-in, is born
  unseeded anyway, so there the signal only audits and notifies. The login itself is never refused. An account's
  first sign-in ever, a sign-in with no client address, and a failed history read fail open and
  write `auth.login_address_unevaluated` with the reason. There is no setting. A typical-hours signal was
  ruled out, because it would challenge night staff on a 24-hour clinical service.
  (`BACKLOG #288`, owner ruling 2026-09-26, ASVS 8.2.4)
- **A session signed in through the identity provider now steps up there, not with a password.**
  Each session records how it was minted, in a new `sessions.auth_mechanism` column on all three
  store backends: `password`, `kerberos` or `oidc`. Rotation keeps it. For an `oidc` session the
  web console's `/ui/reauth` page shows no password field. Its Continue button posts to the new
  `POST /ui/reauth/oidc`, which sends the browser to the IdP with `max_age=0` and `prompt=login`.
  On the way back, the engine checks five things. The IdP signed the user in after the request.
  The whole claims check passes. The session is still live. The directory still has the account.
  The token's `(iss, sub)` is the pair bound to the account. Only then does it stamp the step-up
  window, rotate the session and mint any action grant, as the password leg does. Every outcome writes an `auth.reauth` row with `mech=oidc`, and a
  refusal names its reason. `POST /me/reauth` now refuses an `oidc` session before any password
  check, audited with `reason=idp_step_up_required`, charges nothing to the lockout, and answers 403
  naming `/ui/reauth`. `POST /ui/reauth` sends such a session to the IdP page unread. A Kerberos session on the same account keeps
  the password re-bind. Federated sign-in ships off (`[auth].oidc_enabled = false`), so this changes
  nothing until a site turns it on. Back-channel logout stays out of scope. (`BACKLOG #296`,
  `BACKLOG #295`, ADR 0142 Amendment B, ADR 0184 item (iv))
- **`deflate_decompress_with_tail` inflates a zlib stream that has other data after it.** It
  returns `(body, tail)`: the inflated stream, and every byte after the end of the stream, unread.
  `deflate_decompress` refuses such bytes, and the advice was to strip them first. That is not safe
  for a PDF stream's end-of-line: a stream's last byte is a checksum byte that can itself be a CR or
  LF, so stripping truncates it. Only the inflater knows where the stream ends. The new function runs
  the same bounded loop under the same required `max_output_bytes` ceiling, which bounds the one
  stream. A corrupt, truncated or over-ceiling stream still raises `CompressionError`.
  `deflate_decompress` is unchanged and stays strict. ([BACKLOG #1978](docs/BACKLOG.md))
- **The admin API and the web console now show who last wrote each channel scope.** `UserSummary`
  (from `GET /users`) carries `channel_scope_source`: `"ad"` for the AD login sync, `"manual"` for an
  administrator, `null` when no scope writer has run. The console's user list has a Scope source
  column, and the user page states the source beside the scope. Saving a directory scope, even
  unchanged, marks it manual. Since BACKLOG #1927 a sign-in that matches no mapped AD group leaves a
  manual scope in place, so that save quietly kept a grant the directory would have withdrawn. The
  console now warns on such a scope and refuses the save until the administrator ticks "Make this
  scope manual". The sync rule and the JSON `PUT /users/{id}/channel-scope` are unchanged. The web
  console seam moves to `48ba7fb78ed04d7a`. (`BACKLOG #1958`)
- **An operator can now record what an interrupted dual-control release did.** A release cut off
  mid-run is marked `interrupted`, and until now nothing could move it on. `GET /approvals` now lists
  `interrupted` rows after the pending ones, each with a `status`, the approver who released it and
  when it stopped. `POST /approvals/{approval_id}/resolve` takes `{"outcome": "effects_applied"}` or
  `{"outcome": "effects_not_applied"}` and moves the row to `resolved_applied` or
  `resolved_not_applied`. It needs `approvals:approve` and a fresh step-up, refuses the original
  requester, and answers `409` for a row that is not `interrupted`. It never runs the operation
  again. Each resolve writes an `approval.resolve_attempted` audit row naming the resolver and the
  outcome before the row moves, and `approval.resolved` after; if the audit log refuses the first,
  the row stays `interrupted` and the call answers `503`. The engine
  client gains `list_approvals()` and `resolve_interrupted_approval()`. Not built yet: a web console
  page for it, a startup pass over rows left `executing`, and a way out for a row left `executing`
  by a failed status write. (`BACKLOG #1562`)
- **A dual-control approve refused as too early now raises an alert and says when to retry.** When
  `POST /approvals/{id}/approve` arrives before `[approvals].min_dwell_seconds`, the 409 now carries
  a `Retry-After` header with the remaining wait in whole seconds. The engine also raises a new
  `approval_too_early` alert, beside the existing `approval.too_early` audit row. A request that
  reads as younger than zero is a clock behind, not a fast approver, and raises no alert. The alert
  is keyed `approval:<id>`, which can never name a connection. A catch-all rule still matches it, and
  one that sets `control_target` restarts that connection, so scope such rules. The alert carries the
  operation key and a fixed reason, with no names and no PHI. Nothing resolves it when the request is
  later decided. (`BACKLOG #287`, ASVS 2.4.2)
- **An administrator can create a directory (AD) account without a Windows SSO sign-in.**
  `POST /users/directory` takes a body of `{"username": "<name>"}` and creates the account's mirror
  row. Before, only a Kerberos sign-in created one, so a site with no Windows SSO had no account to
  link a federated (OIDC) identity to, and nobody could sign in through its identity provider. The
  engine looks the name up with the directory service account, as a Kerberos sign-in does. The
  account's `objectGUID`, display name and `mail` come from that answer, never from the request, so
  an administrator cannot choose which directory identity an account claims. The route refuses a
  name the directory does not return or returns disabled (404), an entry with no readable
  `objectGUID` (400, since that account could never be linked), a name or `objectGUID` an account
  already holds (409), and an unreachable directory (503). It needs `users:manage` and the same
  step-up as `POST /users`. The account is never created without a notification address. When the
  directory's `mail` passes the rule a sign-in applies to it, that is the address, and a
  `notify_email` in the body is refused, so an administrator cannot send the holder's notices
  elsewhere. Otherwise the body must carry `notify_email`, checked as `POST /users` checks `email`.
  The address gets the `account_created` notice. The account starts with no roles; they come from
  the AD-group map at sign-in. It writes a `user.created` audit row with `"provider": "ad"` and
  where the address came from.
  The account can then take `PUT /users/{user_id}/federated-identity`. There is no console screen
  for it yet. (`BACKLOG #2021`, ADR 0184)
- **A DAST pass now sends hostile bytes to live MLLP, raw-TCP and X12 listeners and checks the
  engine's ingress rules.** `scripts/security/dast_ingress_sweep.py` runs a real engine on loopback.
  It sends broken framing, hostile HL7 and seeded mutations. Six detectors check each case: one reply
  per decoded MLLP frame, one row per decoded frame, a listener that stays up, bounded time, bounded
  heap, handle and task growth, and no message content logged at INFO or above. Each detector has a
  canary that must trip it. The seeded run and the canaries run in the existing required test legs.
  A new advisory `dast-ingress` job in `dast.yml` adds a nightly randomized budget. The first run
  found three engine defects, each pinned by a strict xfail. A blank segment faulted the inbound
  handler; `BACKLOG #1594` has since fixed that, and its tests now assert the fix (see Fixed).
  An alphanumeric MSH-1 gets an ACK whose MSA-1 cannot be read.
  The raw-TCP and X12 listeners have no frame deadline. See ADR 0155's 2026-09-26 amendment.
  (`BACKLOG #318`)
- **Dual control now flags a release whose approver account is new or was just taken over, and an
  Administrator grant pages.** One Administrator can create or take over a second approver account,
  so dual control cannot prove two people agreed; `docs/SECURITY.md` now says so, and ADR 0041's
  "two colluding insiders" residual is corrected to one. A release whose approver account was
  created, had its password changed, or enrolled TOTP after the request writes an
  `approval.approver_provenance` audit row and raises the `approval_approver_provenance` alert. The
  release still goes ahead. Creating an Administrator, promoting to it, or newly mapping a directory
  group to it raises the `administrator_granted` alert. The `user.created` audit row now records the
  creating administrator's address, and an account created with a notification address gets an
  `account_created` notice. Both alert types can be targeted by `[[alerts.rules]]`.
  (`BACKLOG #315`)
- **`credential_expires_at` tells a client when an admin-issued temporary password stops working.**
  `POST /auth/login` returns it in `LoginResponse` when `must_change_password` is set. `POST /users`
  returns it in `UserSummary` for the account it creates. It is a Unix timestamp, read from the same
  stored stamp the login gate checks. It is `null` in at least these cases: no change is owed, or
  `[auth].initial_password_expiry_hours` is `0` or less. `GET /users` always returns `null` here.
  That route needs only `users:read`, and a list of live temporary passwords is a target list. The
  web console's create-user form now states how many hours the password
  lasts. Its user page and forced change-password page state the time, and so does the IDE's
  must-change warning. (`BACKLOG #1141`)
- **`messagefoundry admin-set-notify-email` sets a missing notification address on an enabled
  Administrator, from the host.** Under `enforce`, with `[auth].notify_security_events` and
  `[alerts].security_notifications_required` on (both defaults), the engine refuses to start unless
  an enabled Administrator has a notification address. `provision-admin` run without `--email`
  left exactly that state. It then refused to run again, because an enabled Administrator existed.
  The web console cannot be reached while the engine refuses to start. The new command takes
  `--username` and `--email`, plus `--service-config`, `--db` and `--json`. It works on the store
  directly, behind the same host gate as `admin-unlock`. Run it with the engine stopped. A running
  engine could change the address between the command's check and its write, or hold the lock its
  audit row needs. It only fills an absent address. It refuses at least a blank address, a
  non-Administrator, a disabled account, and an account that already has an address. Change an
  existing address from the web console, which notifies the old address. A second run with the same
  address reports success and writes nothing. The command appends an `auth.admin_notify_email_set`
  audit row before it writes the address, so the address never lands unaudited. If that write then
  fails, it does not report success. The warning `provision-admin` prints for a missing `--email`
  now names this command. (`BACKLOG #1136`)
- **On SQL Server and PostgreSQL the engine's runtime login no longer runs schema DDL, and
  `messagefoundry store provision-schema` does it instead.** New `[store].schema_management`
  takes `auto` or `external`; **`external` is the server-DB default**, and SQLite is always
  `auto`. Under `external`, `serve` reads the `schema_meta` marker and **refuses to start** when it
  does not match this build, naming the database, the login's default schema, and the command. It runs
  no schema DDL and, on SQL Server, no `ALTER DATABASE`, so a refused start leaves the database as it
  found it. It still refuses while `READ_COMMITTED_SNAPSHOT` is off, as `auto` does (BACKLOG #1628).
  A clustered node's coordinator tables now ride the same batch. A DBA runs
  `provision-schema` as a DDL-capable principal, with the engines stopped, before the first start and
  before the first start of any upgrade whose schema moved. It needs no store key, a re-run on a
  current schema is a no-op, and it exits 3 when `READ_COMMITTED_SNAPSHOT` is still off. On
  PostgreSQL an external-mode start also refuses when the runtime role lacks row access to a store
  object, instead of failing mid-pipeline. The runtime login then
  needs row access only: `db_datareader` + `db_datawriter` on SQL Server, `USAGE` plus row grants on
  PostgreSQL ([`DEPLOY-SERVER-DB.md`](docs/DEPLOY-SERVER-DB.md) §1.1, §1.2, §2). The startup
  privilege probe follows the mode: under `external` it names `db_ddladmin`, or `CREATE` on the store
  schema, as excess. Set `schema_management = "auto"` to keep the engine building its own schema;
  on a server DB that is reported by `security_loosenings()` as `schema_management`.
  ([BACKLOG #305](docs/BACKLOG.md), [ADR 0192](docs/adr/0192-server-db-schema-is-provisioned-externally-by-default-the-runtime-login-runs-no-ddl.md))
- **A row stranded in flight now pages.** A store fault between a committed claim and its handoff
  can leave a row `inflight` when the re-pend that follows fails too. A restart recovers it, and
  until now nothing saw it: the buildup and stall checks counted pending rows only, and ran only
  when the lane processed something. The engine now reads each stage's in-flight rows every 30 s,
  on every store backend. It fires `queue_buildup` when a row has been held longer than the lane's
  buildup `max_oldest_seconds`, which is on by default at 300 s. An outbound lane also fires
  `message_stall` on its stall threshold, when one is set. The age runs from the claim, so a row
  being worked right now does not page. The log line names the stage. This change re-pends
  nothing; the store's existing recovery paths, at least a restart, still do. (`BACKLOG #1611`)

### Changed
- **BREAKING: on SQL Server and PostgreSQL, the runtime login may only insert and read audit rows.**
  Under the `external` schema default, the startup privilege probe now names `UPDATE` or `DELETE`
  on `audit_log` or `audit_chain_meta` as an over-grant, a column `UPDATE` grant included. It also
  names `ALTER`, `CONTROL` and `TAKE OWNERSHIP` on SQL Server, and `TRUNCATE` and `TRIGGER` on PostgreSQL, so the
  start refuses under the shipped `enforce` dial. Without it, on a first
  deployment the engine's own login could rewrite audit rows. `docs/DEPLOY-SERVER-DB.md` adds the
  `DENY` (SQL Server) or `REVOKE` (PostgreSQL) to run once after the first `provision-schema`. The
  engine's own writes no longer need those rights: opening a fresh keyed store and `rekey-audit`
  insert the keying row and never replace one. The PostgreSQL grants check no longer asks for
  `UPDATE` or `DELETE` on the two tables. A keying row that records no watermark is no longer
  overwritten: `rekey-audit` and the open refuse it on both backends, and name the
  statement that removes it. Two engines keying one fresh store at once now agree on the first
  one's row on both backends, where the SQL Server loser used to fail its open on the primary key.
  (owner ruling R16, ASVS 16.4.2)
- **BREAKING: `cert import` now judges a PKCS#12 MAC even when the bundle's bags are not
  encrypted.** Before, the MAC was checked only when something in the bundle was encrypted. So an
  `openssl pkcs12 -export -keypbe NONE -certpbe NONE` bundle loaded with an MD5, SHA-1 or SHA-256
  MAC. That MAC still derives its key from the passphrase through the PKCS#12 KDF. It is now
  refused like any MAC that is not PBMAC1 at the PBKDF2 floor. **This includes OpenSSL's default
  MAC and `cryptography`'s `NoEncryption` output**, which carries a SHA-256 MAC under an empty
  passphrase. An unencrypted bundle with no MAC (`-nomac`) still loads with no passphrase, since
  nothing in it comes from a password. A bundle with an approved MAC now needs `MEFOR_PFX_PASSWORD`
  even when its bags are clear. The refusal gives the `openssl` re-export commands. (`BACKLOG #1352`)
- **BREAKING: the `Http()` listener answers 400 to a request that repeats its credential header.**
  That header is `intake_api_key_header` under `intake_auth="api_key"` and `Authorization` under
  `"bearer"`. In the shipped code the listener kept the last copy. So `x-api-key: wrong` then
  `x-api-key: <key>` was accepted, while a front end reading the first copy saw a wrong key. The
  listener now refuses the request before it compares any credential. Identical copies are refused
  too, and `x_api_key` counts as a copy of `x-api-key`. The refusal is charged and audited like a
  wrong key, and it never names the header or its value. `docs/SECURITY.md` Table B, intake
  authentication row, states the rule. (`BACKLOG #2051`)
- **`GET /cluster/status` says whether a stepdown on this node would send its lease release.** The
  new `owns_lease_row` field is the coordinator's own drain test, now the public
  `ClusterCoordinator.may_own_lease_row()` on the Postgres, SQL Server and single-node coordinators.
  It is true at least while the node leads and on a self-fenced node. It is also true while an
  earlier release write is owed. It means "may own": if another node has taken the lease, the
  stepdown releases nothing and answers `409`. The web console reads it to offer the stepdown
  control. It is false on a single node. See `docs/CLUSTERING.md`. (`BACKLOG #1988`)
- **The DR backup no longer stages plaintext in the OS temp dir.** On a SQLite store the snapshot,
  its tar and the backup's own verify copy now stage in the store's own data directory.
  Each staged tar and extracted store gets the store's best-effort `_secure_file` restriction before
  its first byte, and the snapshot gets it once its copy completes. A server-DB store stages in
  `.mefor-staging` under `[backup].destination`, secured the same way (see Fixed). Staging is
  removed on success, on an exception and on cancellation. A directory left by a crash or `SIGKILL`
  is removed by the next backup, which goes by each directory's lock and never by its age, so a
  sibling engine shard's live run survives it; nothing is swept at `serve` start. When a good
  backup's staging cannot be cleared, the run still succeeds, raises a `backup_failed` alert of kind
  `cleanup`, and names the directory in its audit row and in the `backup` command's output. Staging now needs free space on the data
  volume (about twice the store while it runs). A standalone `restore-verify` and the DR cold-seed
  activation stage in a private directory under the OS temp dir instead, so a read-only DR share
  verifies. The next standalone verify or backup on the same account sweeps what a killed one
  leaves there. It takes only directories with its own owner. They need about twice the store free
  on the temp volume, as before. `docs/PHI.md` §2 states what "private" means on each platform. The archive key is
  now picked by comparing every key in the keyring with `hmac.compare_digest`. `docs/PHI.md` §2 and
  §8 state what is still unbounded. (`BACKLOG #1174`, `BACKLOG #1721`, `BACKLOG #1167`)
- **BREAKING: every private-key loader now refuses a weak passphrase wrap.** Decrypting an
  encrypted key file derives a key from its passphrase, and the engine now holds that derivation to
  ASVS 11.4.4. It reads the wrap before anything decrypts it: at the TLS listeners and client hops,
  outbound signing and the SMART assertion, the DIRECT signing key, `cert import`, the SFTP key, and
  a database driver's `sslkey`. Refused, with no setting to allow them: legacy `Proc-Type` PEM,
  SHA-1-based derivations, PBKDF2 under 600,000 iterations over HMAC-SHA-256 (or 210,000 over
  HMAC-SHA-512), and a PKCS#12 MAC keyed by the PKCS#12 KDF rather than PBMAC1. **Keys written by
  `openssl req`, `openssl genpkey -aes256` or `cryptography`'s `BestAvailableEncryption` use 2048
  iterations and are refused until re-wrapped.** An encrypted key with no passphrase is refused
  before any library can prompt at a terminal. The SFTP connector no longer takes `key_password`
  or an encrypted key, and refuses an RSA key under 2048 bits. The refusal gives the `openssl`
  command to re-wrap; docs/CONNECTIONS.md, *Encrypted private keys must meet the wrap floor*, has
  both commands. (`BACKLOG #1352`, `#1171`)
- **The username-in-password screen no longer carries the ASVS 6.2.11 label.** That requirement
  grades the documented context-word list, and no ASVS 5.0 requirement names the username screen.
  (`BACKLOG #1135`)
- **BREAKING: with `[auth].oidc_enabled` on, a config that sets `oidc_acr_values` while
  `oidc_required_acr_values` names no non-blank value now refuses to load.** `oidc_acr_values` only
  asks the identity provider for an assurance class. The sign-in gate checks the returned `acr`
  against `oidc_required_acr_values` alone, which ships empty, so a site that set only the request
  would ask for a class and never check what came back. The gate reads that list only while
  `oidc_require_mfa_claim` is on; with it off, no `amr` or `acr` is checked at all, as before. The
  refusal names both keys. Set
  `oidc_required_acr_values` to the `acr` values you accept, or remove `oidc_acr_values`. The engine
  does not copy the request into the requirement, because `acr` values are not ordered. A blank
  `oidc_acr_values` still loads. With both keys set, a token whose `amr` matches
  `oidc_mfa_amr_values` still passes the gate whatever its `acr`. The `oidc-auth-params` advisory in
  `messagefoundry check` now reports this case as a settings load failure. (`BACKLOG #2032`)
- **The Vault clients now narrow and verify the TLS leg to an `https://` proxy, and refuse an
  `http://` Vault behind one.** Both Vault clients (the `vault` secret provider and the store's
  Vault key provider and Transit cipher) honour `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and, on
  Windows, the system proxy. Through an `https://` proxy, the leg to the proxy used urllib3's own
  context, which offered CBC suites off the approved list. It now gets a fresh engine context per
  connection, narrowed to the approved suites. The engine checks that the leg ran on that context
  before it sends `CONNECT`, and refuses otherwise. So a proxy that offers only a non-approved suite
  would now refuse. Verification of that leg is unchanged: it was, and is, checked against the
  Vault hop's anchor and the proxy's host name. **BREAKING:** an `http://` Vault address that requests would send through an `https://`
  proxy is refused when the client is built, and again before each send. requests does not verify
  that proxy for an `http://` address, so its TLS leg, which carries the Vault token, verified
  nobody. Use an `https://` Vault address. A direct `http://` Vault address was not refused by
  this change; the next entry refuses it.
  (`BACKLOG #300`, ASVS 12.1.2, 11.6.2)
- **BREAKING: the Vault clients refuse a Vault address that is not `https://`.** At least the KV
  secret provider, the store key provider and the Transit cipher took an `http://` address with no
  scheme check, so on a first deployment with one the `X-Vault-Token` would have crossed the
  network in cleartext, directly or through an `http://` proxy. Each now refuses such an address
  when its client is built, and again before each send in case a proxy appeared since. That
  includes an address from hvac's own `VAULT_ADDR` fallback, and an address that does not read as
  one well-formed URL. The one `http://` address allowed is a loopback Vault reached with no
  proxy, the shared cleartext-hop rule's on-box case, as `docs/CONFIGURATION.md` section
  `[secrets]` states it; hvac's built-in default, `http://localhost:8200`, is one. At build, each client raises its provider's own fail-closed error (`SecretProviderError` or
  `KeyProviderError`), caused by an `InsecureHopRefused` whose fixed text names no part of the
  address. The `https://`-proxy refusal above now reaches callers the same way at build; it was a
  bare `ValueError`. Before a send, the refusal is the `InsecureHopRefused` itself.
  `provision-admin` prints the refusal's own text, not its canned line about the secret reference.
  `[security].enforcement` does not relax it, since this hop has no posture in scope and no way to
  declare an accepted risk. An `https://` Vault behind an `http://` proxy is unchanged: the token
  rides inside the TLS tunnel. (`BACKLOG #2317`, ASVS 12.3.1)
- **The tray's engine probe no longer goes through a web proxy.** It read `HTTPS_PROXY`,
  `ALL_PROXY` and, on Windows, the system proxy, without that proxy's local-address bypass, so a
  site proxy would have taken the loopback probe off the host and read a running engine as down.
  The leg to an `https://` proxy also ran on httpcore's own context, not the narrowed one. The probe
  now ignores proxy settings. (`BACKLOG #300`, ASVS 12.1.2)
- **BREAKING -- `PUT` and `DELETE /users/{user_id}/federated-identity` now require the pair the
  caller saw.** Both bodies carry `expected_issuer` and `expected_subject`, and both fields are
  required. Send `null` for a half you saw unset, so `null` and `null` for an unbound account.
  `DELETE` now takes a JSON body. The engine removes or replaces a binding only if the account still
  holds exactly that pair. It compares under the clear's own row lock, on every store backend. If the
  pair has changed it writes nothing, revokes no session, and answers 409 with a detail starting
  `federated_binding_changed:`. Without this, an administrator acting on a stale read would remove
  a binding another administrator had written since, and sign its holder out. A retried bind of the
  pair the account already holds is still the harmless 400. A body without the
  two fields is a 422. The JSON API still has no read of the stored pair; the console's
  federated-identity screen shows it. (`BACKLOG #2026`)
- **BREAKING: `[api].tls_client_cert_identities` is now keyed by the issuing CA.** Each entry sits
  under the RFC 4514 DN of the CA that signs the client certificate, as
  `[api.tls_client_cert_identities.'CN=Acme Service CA,O=Acme,C=US']` then
  `"CN:svc.internal" = "<account id>"`. A subject maps only under the CA named for it. Before this, any CA in
  `[api].tls_client_ca_file` could issue a listed subject and reach the mapped account. The issuer
  is the CA loaded in `tls_client_ca_file` whose key signed the client certificate, not whatever the
  certificate's issuer field says, and a client-sent intermediate never counts. The flat,
  issuer-less form is refused at load, as are a non-canonical issuer DN and a name no certificate can
  carry, and `serve` warns about an issuer key that names no loaded CA or two of them.
  `docs/CONFIGURATION.md` `[api]` says how to print the DN to write.
  (`BACKLOG #2237`, ASVS 6.8.1)
- **BREAKING: each `[api].tls_client_cert_identities` value is now the account's id, not its
  username.** Use the `id` field of `GET /users`, 32 lowercase hex characters. A rename can hand a
  username to another account, and the certificate used to follow the name; the id never moves. A
  username, or anything else that is not an id, is refused at load. An unknown or disabled account
  still grants nothing. (`BACKLOG #2238`, ASVS 6.8.1)
- **BREAKING: the PostgreSQL store now builds its own TLS context on the default path, so it narrows
  the suites and can load a CRL there.** Without `[store].ssl_root_cert`, the engine used to hand
  asyncpg `ssl=True` and let asyncpg build the context. It now makes the same
  `ssl.create_default_context()` call asyncpg made. So the certificate, hostname, protocol-floor and
  system-trust checks are the same. It then narrows the context to the approved AEAD suite list and
  asserts it. A PostgreSQL server that offers only CBC or AES-128-GCM TLS 1.2 suites would no longer
  connect on that path. The engine builds a fresh context for **every new pool connection**, on both
  verifying branches, through asyncpg's pool `connect=` hook. So each connection still reads the OS
  trust store as it is then, as `ssl=True` did. It now also re-reads `ssl_root_cert` and
  `ssl_crl_file`, so a refreshed CRL or CA applies to each new connection. Connections already open
  keep the context they were made with, until the pool replaces them. So restart the engine to apply
  a revocation at once. If either file has gone missing, or the CRL has passed its `nextUpdate`, the
  next new connection fails with an error that names the setting. `[store].ssl_crl_file` no longer requires `ssl_root_cert` and loads on the
  system-trust path too. That gives a remote store on an enforcing posture a way across the
  revocation refusal besides loopback. It is now refused at load on a store hop that verifies
  nothing (`encrypt = false` or `trust_server_certificate = true`), so a config that set it there
  would no longer load. The `postgres` extra now requires `asyncpg>=0.30`, the release that added
  the `connect=` hook, and `messagefoundry verify` fails an older one.
  (`BACKLOG #300`, ASVS 12.1.2, 11.6.2)
- **`AlertSink.secret_rotation_due` takes `class_id=` where it took `secret=`.** The value is the
  same: the secret class's config or env-var name, never the secret itself. The rotation dataclasses
  (`MonitoredSecret`, `SecretCheck`, `SecretStamp`, `RefusedSecret`) rename their `secret` field to
  `class_id` to match. A custom alert sink must rename the keyword. The alert text and the notifier
  payload's `"secret"` key do not change. (`BACKLOG #1932`, CodeQL alert 204)
- **BREAKING: an over-granted store login now refuses to start under `enforce`.** The startup
  privilege preflight reads the SQL Server or Postgres login's effective privileges. When it holds
  more than the grant `docs/DEPLOY-SERVER-DB.md` §1.1/§1.2 prescribes, `serve` now refuses to start
  under the shipped `[security].enforcement = enforce`, with no setting needed. Before, it refused
  only when `[store].require_least_privilege` was set. To accept the grant, set
  `[security].allow_over_granted_store_principal = true`: the start goes ahead, a WARNING line
  starting `AUDIT:` names the switch, the `store_privilege_preflight` audit row carries
  `over_grant_accepted: true`, and `security_loosenings()` names it. A probe that cannot read the
  login still only warns; `require_least_privilege = true` still refuses on that too, and outranks
  the opt-out. `enforcement = warn` and SQLite are unchanged. `messagefoundry check-privileges`
  gains a last `serve:` line (a `serve` key under `--json`) saying what `serve` would do; its exit
  codes are unchanged. The local `ha` profile in `docker/compose.yaml` logs in as a Postgres
  superuser, so it now sets the opt-out. (`BACKLOG #305` Gate, ADR 0199, owner ruling 2026-09-27,
  ASVS 13.2.2)
- **Saving over a directory channel scope through the JSON API now needs explicit intent.**
  `PUT /users/{id}/channel-scope` takes an optional `expected_source` (`"ad"` or `"manual"`). A
  save marks the scope manual, and the AD login sync never withdraws a manual scope. So when the
  stored source is `"ad"`, a body without `"expected_source": "ad"` now answers **409** and changes
  nothing. A sent `expected_source` that does not match the stored source answers 409 too. The
  write is a compare-and-set on the source it read, on SQLite, SQL Server and Postgres, so an AD
  sign-in that changes the source mid-write gets a 409 instead of being overwritten. **Not breaking
  for a client that does not touch directory scopes**: a body without the field saves as before on
  any scope the directory does not own, and `GET` still returns only `channels`. `EngineClient.set_channel_scope`
  gains a keyword `expected_source`. The web console sends it when the administrator ticks "Make
  this scope manual", and shows a race as a refused save with the edits kept. The web console seam
  moves to `f695216425a5f7e7`. (`BACKLOG #2098`, owner ruling 2026-09-27)
- **The IDE's Start now provisions an administrator before it starts the engine.** The engine
  creates no account on its own, so a Start that only ran `serve` came up with nobody able to sign
  in. Start now asks `provision-admin`, with no terminal attached, whether the store already has an
  enabled Administrator. If it does, the engine starts as before. If not, the IDE offers to
  provision one. It asks a username and an optional notification address, runs `provision-admin`
  in its own terminal, where you type the password, and keeps that terminal open until you have
  read it. Then it checks again, and the engine starts only once an Administrator is in place.
  You can also start without one, for an engine with sign-in off. If the check itself is
  refused, the IDE shows the reason and offers to provision or to start anyway, since `serve`
  applies its own gates. The IDE passes no password on
  any command line. The store-less confirm and the setup page no longer promise a bootstrap admin.
  (`BACKLOG #1136`, ADR 0183 Amendment A, Wave 5)
- **The SMART and OAuth2 client-credentials token providers now share one token hop and one
  token cache.** Each once carried its own copy, and fixes reached one and missed the other. A
  private base in `transports/smart.py` now owns the URL checks, the cleartext and revocation
  refusals, the proxy, ECH and trust-anchor routing, `access_token` and `invalidate`. Each
  provider keeps its own grant. Both public classes, their error types and every message are
  unchanged. (`BACKLOG #2115`)
- **`[auth].admin_new_ip_step_up` now defaults to `true`.** A sensitive admin action from a client
  address the session has not verified from now forces a fresh step-up, writes
  `auth.admin_action_new_ip` and notifies the account holder, with no setting needed. It never
  denies a request, and it cannot fire on a single-host loopback bind. Setting it `false` is a named
  loosening: `security_loosenings()`, the `serve` warning and `GET /security/posture` report it while
  auth is on. The exposed-console advisory now fires only on that opt-out. ADR 0068 carries a dated
  amendment. (`BACKLOG #288`, owner ruling 2026-09-26, ASVS 8.2.4)
- **BREAKING: `[api].trusted_proxies` now needs `[api].tls_terminated_upstream` or an operator
  `[api].tls_cert_file`, and is refused at load without one.** uvicorn takes the request scheme from
  a trusted proxy's `X-Forwarded-Proto`. With neither key, a proxy that forwarded `http` made the
  web console issue its session cookie without `Secure`, even though the engine served TLS on its
  generated certificate (ASVS 3.3.1 and 3.3.3). Either key forces `Secure`. Declare the terminating
  proxy with `tls_terminated_upstream = true`, or set `tls_cert_file` if the proxy re-encrypts to
  the engine. A declared terminator brings its existing requirements with it: with no
  `tls_cert_file`, `serve` needs `plaintext_upstream_hop_acknowledged = true`, and under `enforce`
  it needs `[security].web_console_public_address`, whose TLS floor it probes at startup. The same-pod sidecar example in `docs/CONTAINER-EXPOSURE-EVALUATION.md` now declares
  the terminator, so that sidecar speaks http to the engine unless the engine has your own
  certificate. (`BACKLOG #2055`)
- **BREAKING: scripted bulk admin writes now get `429`.** The per-actor admin-write floor
  (`[auth].admin_write_rate_limit_window_seconds`) now defaults to **15 s** instead of 1.0 s, so the
  budget is 12 writes per 15 s rather than 12 per second. An `apiclient` script or IDE loop that
  makes more than twelve admin writes in 15 s is refused with `429`, on the JSON API and on `/ui`.
  The budget counts every non-GET request, so a POST that only reads, such as `POST /messages/search`,
  spends it too. Such a loop has to pace itself. Otherwise the site raises
  `admin_write_rate_limit_per_actor`, shortens the window, or sets
  `admin_write_rate_limit_enabled = false`. Each of those is a loosening. The new default is
  **provisional**: it comes from the keystroke-level model, not from timing a person on this console.
  The window now also refuses a zero, negative or non-finite value at load. The derivation is the
  comment on the setting in `config/settings.py`. (`BACKLOG #287`, ASVS 2.4.2)
- **BREAKING: the Windows config-source guard now refuses to load when it cannot finish reading an
  ACL.** It used to log a WARNING and load the config Python unchecked. At least these now refuse the
  load: a `GetNamedSecurityInfoW` error, an owner SID it cannot resolve, a DACL it cannot enumerate,
  and an unreadable process token. `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` downgrades the refusal to a
  WARNING for a dev/CI checkout, as it does every refusal from this guard. A `*.py` deleted between
  the listing and the read is still skipped. The refusal now names the Windows error text. The
  guard's decisions now run in tests on every platform; the ctypes reader itself still does not.
  See ADR 0036 Amendment B. (`BACKLOG #1654`)
- **BREAKING: `[api].serve_ui_explicit` is removed and refused at load, in the file and as
  `MEFOR_API_SERVE_UI_EXPLICIT`.** The loader set it when `[security].serve_web_console` was
  provided, so `serve` could tell an explicit console request from the default. It was an ordinary
  field, so an operator could set it too, with `[security]` reporting no choice. Doing so turned the
  console-absent warning into a hard refusal naming a switch nobody had set. On an exposed bind it
  kept a default-on console on the `/ui` exposure checks, which can refuse start, instead of dropping
  it. `serve` now reads whether `[security].serve_web_console` was provided directly, so that switch
  behaves as before. (`BACKLOG #2000`)
- **BREAKING: `[pipeline].require_rcsi_for_pooled` is removed and refused at load, in the file and
  as `MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED`, at either value.** A SQL Server store already
  refuses to open with `READ_COMMITTED_SNAPSHOT` off (`BACKLOG #1628`). So `false` could only start
  a pooled runner in the mode that deadlocks. The pooled start gate now always fails closed. The
  `rcsi_off_degraded` alert event type is removed too, because nothing can raise it. An
  `[[alerts.rules]]` entry naming it is now refused like any unknown event. Embedders lose the
  `require_rcsi_for_pooled` parameter of `RegistryRunner`, `Engine` and `create_managed_app`. The
  `AlertSink` protocol and both shipped sinks lose the `rcsi_off_degraded` method. See ADR 0066 §12.
  (`BACKLOG #2090`)
- **BREAKING: an administrator must give a notification address to create an account.**
  `POST /users` now requires `email`, and the web console's create-user form requires it too. The
  address becomes the account's notification address, so its holder is told about changes made
  before their first sign-in, an administrator's password reset included. A blank value, or anything
  but one plain mailbox, is refused with 400, the same check `PATCH /users/{id}` applies to
  `notify_email`. A body with no `email` is refused with 422. `EngineClient.create_user` takes `email`
  as a required keyword. An existing account with no address can be given one through
  `PATCH /users/{id}` with `notify_email`, which notifies the new address. (`BACKLOG #2018`)
- **BREAKING — the `Http()` inbound listener answers 400 to a request with no `Host` or with two.**
  RFC 9112 section 3.2 requires a server to refuse both shapes. In the shipped code an HTTP/1.1
  request with no `Host` was accepted, and a second `Host` silently replaced the first. The listener
  routes on no `Host` value, but a fronting proxy that honoured the first `Host` would have disagreed
  with it about the second. Both shapes are now refused while the request head is read, before any
  body byte is read or anything is dispatched. Each is a `framing_error` event with no ingress row,
  and the refusal never echoes the header's value. An HTTP/1.0 request with no `Host` is still
  accepted, because that version predates the field, and so is an empty `Host:` value. A `Host`
  value's syntax is not checked. **A deploying sender or health probe that sends HTTP/1.1 with no
  `Host` would be refused**, and must send one. (`BACKLOG #1972`)
- **BREAKING: `serve` now refuses to start when the credential reminders have no `[alerts]`
  recipient.** The unclaimed-temporary-password and cert-expiry reminders go to the `[alerts]`
  notifier. That notifier needs `webhook_url`, or `email_to` beside `email_smtp_host` and
  `email_from`. The start gate checked only host and sender, so the smallest admitted configuration
  sent every reminder to the log alone. With sign-in on, it now refuses under `enforce` and warns
  under `warn`. The existing `[alerts].security_notifications_required = false` waiver covers it
  and is audited. (`BACKLOG #2008`)
- **BREAKING — `length_of_stay` needs a zone for admit and discharge times that carry no offset.**
  It used to subtract the two wall clocks. A stay spanning a daylight-saving change came back an hour
  wrong, with no error: 48 hours for a 47-hour stay across the March change, 48 for a 49-hour stay
  across the November one. `length_of_stay` and `Message.length_of_stay` now take an optional
  `zone`, an IANA name such as `America/Chicago`. They read each offset-free stamp in that zone and
  subtract in UTC. With no `zone`, they refuse with `ValueError` a pair where only one stamp has an
  offset, and a pair with no offsets where either stamp has a time of day. A pair of date-only stamps
  with no offsets still needs no zone and stays a whole number of days. A stamp on a daylight-saving
  edge of the zone is refused as `convert_hl7_timestamp` refuses it, unless `on_dst_edge` names a
  resolution. (`BACKLOG #1770`)
- **BREAKING — the engine no longer creates an account on its own.** A `serve` on a store with no
  users used to create an enabled Administrator named `admin` and write its one-time password to
  `bootstrap-admin.txt` beside the store. It now creates no account and writes no file. Create the
  first Administrator at the host with `messagefoundry provision-admin --username <name> --email
  <address>`, before the first start or after one that was refused. At the shipped posture a start
  with no enabled Administrator is refused, and the refusal names that command. A start refused
  because no Administrator has an address now names `admin-set-notify-email` instead. Under
  `[security].enforcement = "warn"`, or with security notices off or waived in writing, the engine
  starts and routes HL7, logs one warning naming `provision-admin`, and nobody can sign in until it
  runs. The WP-3 lifecycle that disabled the first-run account went with it, and so did its expiry
  reminder. An account an operator names `admin` is now an ordinary account, so it gets a
  `credential_expires_at` like any other. `provision-admin` now refuses before it asks for a password
  when an enabled Administrator already exists or an argument is out of range. It opens the store
  only after the password passes the policy, so a refusal leaves no new SQLite store file behind.
  Its `--username`, `--email` and `--display-name` are limited to 256 characters, as in the web
  console.
  The two settings that timed the first-run account are removed as well; see the next entry.
  **Migration:** run `provision-admin` once at the host, as the account that installs the service,
  against the store and service config the service uses. ADR 0183 Amendment A, Wave 2. (`BACKLOG #1136`)
- **BREAKING — `[auth].bootstrap_expiry_hours`, `[auth].bootstrap_warn_hours` and the
  `bootstrap_admin_expiring` alert event are gone.** They timed and announced the first-run account,
  which the engine no longer creates. A service config file that sets either key now fails to load,
  with the same "unrecognized config key" error as a typo. An `[[alerts.rules]]` rule whose `event_type`
  is `bootstrap_admin_expiring` also fails to load. Nothing emitted that event after the account was
  retired, so such a rule could never match. The environment variables
  `MEFOR_AUTH_BOOTSTRAP_EXPIRY_HOURS` and `MEFOR_AUTH_BOOTSTRAP_WARN_HOURS` are now ignored without
  an error, as the environment layer ignores any variable that names no setting. **Migration:**
  delete both keys from `[auth]`, unset the two variables, and delete or retarget any rule that
  names the event. ADR 0183 Amendment A, Wave 3. (`BACKLOG #1136`)
- **BREAKING — the config loader refuses a connection name that does not match
  `^[A-Za-z][A-Za-z0-9_-]{0,255}$`.** In 0.4.0 such a name still loaded and ran, and only the API
  refused it. Now a code-first `inbound()` or `outbound()` call, or a `connections.toml` entry,
  carrying one fails the whole load with a `WiringError` that names it. The `connections.toml`
  editor and the rename planner refuse it before writing, and the Corepoint importer folds a
  generated connection name that would fail it. **Migration:** rename such connections to fit the pattern;
  stored history stays under the old name. ([BACKLOG #1107](docs/BACKLOG.md))
- **`POST /cluster/stepdown` now drains a node that has already self-fenced.** Such a node has
  cleared its leader flag, but its lease row stays live until `leader_lease_ttl_seconds` runs out.
  In 0.4.0 the stepdown sent no write there and answered `409` "not the current leader", while
  `GET /cluster/nodes` still named the node as `lease_owner`. Now the stepdown expires that row and
  answers `200`, so a standby can take the lease at once. `ClusterStepdownResult` and the
  `cluster_stepdown` audit row gain a `lease_released` field, which says whether the call expired a
  lease row naming this node. A self-fenced drain reads `was_leader: false, lease_released: true`.
  The endpoint answers `409` only when both are false. A retry after a `release-unconfirmed` `503`
  now answers `200` while the row still names this node, and `409` once a standby has taken it.
  The new field changes the web console engine UI seam, so install the engine and the console
  together. ([BACKLOG #1508](docs/BACKLOG.md))
- **Documented: leader preference does not steer a planned failover.** A stepdown writes the lease
  expiry as zero, so every promotable sibling can take a released lease on its next heartbeat,
  whatever its `acquire_delay_seconds`. The delay still applies to a lease that expired on its own.
  No code changed; the earlier docs said a handicapped sibling could be locked out by the stepdown
  pause, which was never true. ([BACKLOG #1507](docs/BACKLOG.md))
- **BREAKING — the `Http()` inbound listener answers 422 to a body it refuses at ingress.** The
  engine refuses some bodies after reading them, for example one it cannot decode or one over the
  ingress ceiling; `docs/CONNECTIONS.md` lists more. The receipt
  path answered that `202` with no `message_id`, which told the caller its body was accepted. It now
  answers `422` with `{"error":"message was not accepted"}`, the answer a `reply_from` inbound already
  gave. The message is still recorded with status `ERROR`. A committed body still gets `202` with its
  `message_id`. On a `reply_from` inbound, that `422` now logs a `closed` connection event, which it
  used to skip. Owner ruling 2026-09-26: "Answer 422, amend 0154 (Recommended)"; ADR 0154 is amended
  to match. ([BACKLOG #1960](docs/BACKLOG.md))
- **The install instructions now create the first Administrator with `provision-admin` before the
  first start.** The README, `docs/INSTALL-GUIDE.md`, `docs/SERVICE.md` and
  `docs/EARLY-ADOPTER-GUIDE.md` used to end at `serve`, and the early-adopter guide told you to sign
  in as `admin` with the password from `bootstrap-admin.txt`. Each now runs `messagefoundry
  provision-admin --username <name> --email <address>` against the service's store, with the store
  key set in that shell, and then starts the engine. `docs/SERVICE.md` and the early-adopter
  guide give the `--db` the installed service uses. `docs/SECURITY.md` replaces its first-run account sections with one
  section on provisioning, and the other operator documents drop the account, its timer, its alert
  and its password file. No code changed. ADR 0183 Amendment A, Wave 4. (`BACKLOG #1136`)
- **Changelog entries are now fragment files, assembled at release.** A pull request adds one
  file, `changelog.d/<item>.<category>.md`, instead of editing the `[Unreleased]` section of
  `CHANGELOG.md`, so two open pull requests no longer conflict there. The release pull request runs
  `python scripts/release/changelog_fragments.py assemble`, which appends every fragment under
  `[Unreleased]` and deletes it. CI refuses a malformed fragment, and refuses a release pull
  request that still has fragments. A pull request that still edits `CHANGELOG.md`
  gets a warning, not a failure. The release workflow refuses to publish a tag while a fragment is
  left unassembled. `changelog.d/README.md` has the naming rules. (`BACKLOG #2080`)
### Fixed
- **`provision-admin` now refuses before it prompts on a fresh install, and resolves directory
  secrets the way `serve` does.** It builds its auth service once, before the password prompt and
  before any store is created, with the `[secrets]` provider and hop posture `serve` passes, and
  opens the store with that posture too. A trust-anchor refusal at `enforce` on a fresh install no
  longer comes after the prompt and leaves an empty store. A store key that cannot be resolved,
  such as `vault` with no Vault environment in the shell or a DPAPI key the shell cannot read, is
  refused before the prompt with exit 2. An AD bind password or OIDC client secret held by a
  `[secrets]` provider now resolves here. A secret provider, directory or missing-file failure is
  refused in fixed words, with no text from the failure, instead of reaching the generic error
  report. An unusable bundled breach corpus is refused before the prompt. At `warn` an anchor
  warning now prints once, not twice. Two refusals `serve` already gives now apply here too, at
  `enforce`: an off-box OIDC identity provider with no `[auth].oidc_tls_crl_file` (exit 1), and a
  server store hop that `serve` would refuse, such as one with no revocation check (exit 2). The
  first applies here even with `[auth].enabled = false`, where `serve` builds no auth service.
  (`BACKLOG #2081`)
- **`audit-anchor --json` now reports a bad service settings file as JSON on stdout.** A missing,
  unparseable or invalid `--service-config` printed plain text to stderr whatever `--json` said, so
  a caller piping to `jq` got an empty stdout. It now prints `{"error": ...}` on stdout, as the
  command's other refusals do, and exits 2. A settings section that fails validation is now
  reported without echoing the section's values, and a directory named as the settings file now
  exits 2 rather than 1, which this command spends on a broken chain. (`BACKLOG #2094`)
- **`GET /dead-letters` now says which channels a replay would act on, not only which rows fit on
  the page.** The response gains `replay_targets` and `replayable_in_scope`; the `DeadLetterList`
  model defines both. The web console builds its bulk-replay buttons from them, so a channel whose
  dead deliveries are all past the first page still gets one. The store contract gains
  `list_replay_targets` on all three backends. (`BACKLOG #1743`, step 2)
- **A scheduled connection stopped by a pooled infra fault now stays stopped across its window.**
  The ADR 0070 T17 bound and the claimer-death bound stop a pooled lane inside the stage
  dispatcher, so the scheduler never saw a hold for them. A site would have seen the window close
  pause the stopped lane and the next open resume it, retrying the fault every window. The
  dispatcher now reports the STOPs it decides itself to the runner, which holds the lane until a
  real re-arm. A loopback's re-ingress lane is held too, as its inbound: after a log-write halt, a
  window open would have resumed that stopped lane.
  (`BACKLOG #2072`)
- **The scheduler no longer starts a connection the DR run-profile parked.** A window open called
  the same start an operator uses, which reads as overriding the profile. On a DR box it would have
  bound a below-threshold listener and cleared its `filtered` status. The scheduler now leaves a
  filtered connection alone in both directions. An operator start still overrides the profile, and
  the calendar owns the connection from then on. (`BACKLOG #2067`)
- **A log-write halt no longer makes the scheduler restart and re-page every tick.** A halted
  scheduled connection reads as not running, so each in-window tick called start. On a first
  deployment an inbound would have bound its partner port, probed the dead log sinks, paged and
  unbound, every tick; an outbound would have probed and paged. The scheduler now treats the halt
  as a held stop while the halt is latched, so the halt's own page is the only one. Once a restart
  proves the log writable, the calendar may bring the other halted connections back.
  The probe stays on the event loop; moving it to a thread opened a window at two recovery doors.
  (`BACKLOG #2066`)
- **A credential fault on a batching outbound now stops the lane and keeps the batch.** The
  single-message path already stopped on a permanent credential fault (#109). The HL7 batch path
  had no such branch, so a bad password would have dead-lettered every message in the batch. Under
  the default `credential_fault_policy = "stop"` the batch path now stops the lane, pages, and
  returns every member to pending with its attempt given back. `"dead_letter"` still dead-letters
  the batch. (`BACKLOG #2073`)
- **A reload now keeps each connection's schedule in step with the new config.** A scheduler task
  kept the calendar it started with, and only engine start created one. A reload that added a
  schedule never ran it, an edited schedule kept its old hours, and a removed connection logged a
  traceback every tick. The reload also opened a schedule-parked listener's port until the next
  tick closed it. A committed reload now replaces every scheduler task from the new config, and
  leaves a scheduled inbound unbound outside its window. An outbound whose schedule is removed is
  resumed if the calendar had parked it, since nothing else would. Because the reload no longer
  binds that inbound, a port another process holds is first found at the window open. The window
  open now records that inbound as failed and alerts once, as an engine start does, then retries
  quietly each tick. (`BACKLOG #2069`)
- **An FTP server that plainly says it is busy no longer stops an outbound lane.** Every 5xx reply
  while an FTP or FTPS session opened was treated as a refused credential, which stops the lane
  (ADR 0095). A reply that names a connection limit, such as ProFTPD's "maximum number of
  clients", is now retried. A refused `AUTH TLS`, `PBSZ` or `PROT P` is now a permanent
  configuration fault, not a credential fault. So is a plain session's login refusal that plainly
  demands TLS, and a refused greeting. A configuration fault still stops the lane and keeps the
  queue, because every queued message would meet the same refusal; its alert names the
  configuration, not a credential. A login reply that names the credential or the account stays a
  credential fault, even beside a limit or a TLS demand. So does any other 5xx at the login, and
  now a 4xx that names the credential, such as `430 Invalid username or password`. The credential
  words are broad on purpose, so a busy reply that also carries one, such as "blocked", still stops
  the lane. Both faults follow `credential_fault_policy`: the default `stop` stops the lane, on the
  single-message and the batch path, and `dead_letter` dead-letters the message. With
  `validate_directory` on, the per-send listing passes both through and retries every other fault.
  (`BACKLOG #2083`)
- **The SFTP and FTP source now waits for a file to stop growing before it reads it.** A file is
  read only once it lists at the same size on two polls in a row, as the local File source has done
  since `BACKLOG #1811`, so a partner that pauses between writes for less than `poll_seconds` is
  waited out. Every file now waits at least one poll. The gate is always on and reads the listed
  size alone, since a remote listing has no reliable modification time; it cannot see a same-size
  rewrite, nor anything on a server that lists every file at size 0. (`BACKLOG #2071`)
- **An SFTP upload to a server that stops reading is now cut off, and a few SFTP errors that escaped
  raw are now classified.** paramiko retries a stalled socket write without limit, so such an upload
  would have held its worker thread for good. The connector now closes the connection once an upload
  makes no progress for 120 s (`SFTP_WRITE_STALL_SECONDS`, per 32 KiB step), and the delivery is
  retried, after the partial temp file is removed where it can be; a failed store now removes its temp, except
  after a refused credential. An `EOFError` and a helper thread that cannot start are now transient, and a
  `paramiko.SFTPError` is permanent. With `overwrite = false`, a same-named symlink, directory or
  other non-file entry now counts as a collision, and `POST /connections/{name}/test` ensures and
  lists the upload directory on one connection. (`BACKLOG #2082`)
- **A DR backup or standalone `restore-verify` that will not fit now fails before it writes.** A
  backup checks the free space on its staging and destination volumes after its sweep and before
  anything is written. It counts the store file twice on the staging volume, the archive once on
  the destination, and all three when the two share a volume. It checks again with the snapshot's
  real size once the snapshot is taken, so a large idle WAL file does not refuse a run that fits.
  A short run fails
  with a `backup_failed` alert of the new kind `space` that names the volume and both sizes. A
  standalone verify needs about twice the archive free under the OS temp dir. Short, it returns
  `FAIL` with a reason that says the volume, not the archive, is at fault. A volume whose free
  space cannot be read is not checked. The `cleanup` alert, raised when a good backup's staging
  cannot be cleared, now uses its own subject, `dr_backup:staging`. It shared `dr_backup` with a
  failed backup, and so shared its realert throttle: one could silence the other. An alert rule
  that matches the subject `dr_backup` exactly no longer catches cleanup alerts; match
  `dr_backup:staging` too. A server-DB store's backup staging under `.mefor-staging` is now
  secured like a SQLite store's: each staged file gets the store's `_secure_file`. Every staging
  directory, in a SQLite data directory, in `.mefor-staging` and a standalone verify's under the
  OS temp dir alike, must now come out owner-only. On a volume that will not keep a directory
  owner-only, a backup fails with a reason naming the directory, and a
  standalone `restore-verify` returns `FAIL` saying the volume is at fault. Volumes that can
  refuse include, for example, a CIFS or Samba share without POSIX extensions, WSL `/mnt/c`
  without `metadata`, a Docker Desktop bind mount of a Windows path, and FAT or exFAT. Setups on
  such a volume that backed up before may now refuse. (`BACKLOG #1174`)
- **A trailing-slash path is now a 404, never a redirect to an `http://` URL.** The engine used to
  answer `GET /health/` or `GET /ui/` with a 307 before authentication, and its absolute `Location`
  kept the request's scheme. Behind a TLS-terminating proxy whose `X-Forwarded-Proto` is not
  trusted or not sent, that scheme is `http`, so the redirect would point a client at plaintext.
  `create_app` now sets `redirect_slashes=False`. Use `/ui`, not `/ui/`, in a bookmark or a proxy
  rule. (`BACKLOG #1968`)
- **A store created by 0.3.2 now keeps its saved searches on upgrade, and user deletion works on it.**
  The upgrade renames `search_presets.owner` to `owner_user_id` on SQLite, PostgreSQL and SQL Server.
  It maps each 0.3.2 username to that account's user id first. A preset is mapped only when its
  account existed at the preset's last save, so a new account that reused a deleted user's name does
  not inherit that user's presets. Every other preset is dropped, because no account could reach it.
  That includes presets saved under the no-auth `system` identity. On PostgreSQL and SQL Server the
  step runs in the schema batch, under `provision-schema` and `auto` alike. The 0.4.0 entry's advice
  to drop the table first no longer applies from this release on. (`BACKLOG #1909`)
- **A pooled stage no longer gains a processing slot when a claimer dies mid-bookkeeping.** When a
  claim ended with no serializer, the dispatcher returned the lane's slot and then booked the episode
  and moved the lane on. If either step raised, the claimer died with the lane still marked as
  claiming, and its replacement returned the same slot again. The stage could then run more lanes at
  once than `pooled_max_processing_lanes` allows. Each lane now records whether it holds a slot, and
  one helper returns it at most once per reservation, on every path that ends a claim.
  (`BACKLOG #2075`)
- **A lane that keeps killing its pooled claimer is now stopped, so the rest of the stage drains.**
  Before, the respawned claimer released the lane's row and re-readied the lane, and its next
  dispatch killed the claimer again. The release restores the row's attempts, so `max_attempts`
  never dead-lettered it, and every other lane on that claimer waited through the respawn backoff,
  up to 30 seconds, each time. The dispatcher now counts deaths per lane. After
  `infra_fault_stop_after` in a row it releases the lane's rows, STOPs the lane and raises
  `connection_stopped`. A reload, a recovery broadcast, or an operator stop and start re-arms it
  with a fresh count. Only a dispatch that hands rows to a worker clears the count, so an empty
  claim between deaths does not. This applies under both `infra_fault_policy` values.
  (`BACKLOG #2074`)
- **HTTP and web proxy Digest auth now answer only SHA-256, and proxy Digest works.** A web proxy
  whose `407` Digest challenge names MD5 is now refused. So is one naming `SHA` (SHA-1), or naming no
  algorithm, which means MD5. urllib reads only the first challenge, so that one decides. The refusal
  is an `HttpAuthError` naming the algorithm, raised before any hash uses the password. It is the
  `__cause__` of the error a send, probe or token request reports. Before this, the proxy path used
  urllib's own handler with no check. Endpoint Digest already refused MD5, and both paths now share
  one check. `SHA-512-256` and every `-sess` form are refused too. urllib cannot compute them, so a
  challenge naming one crashed with a bare `ValueError`. A challenge that is malformed, or leads with
  another scheme such as NTLM, is refused the same way. A lowercase `sha-256` is answered as SHA-256.
  Repeated refusals no longer leave the connection failing every later send as a `401`. A rejected
  credential is answered once per request, not six times, so the peer's own status surfaces.
  Separately, `proxy_auth_type = "digest"` never authenticated at all. urllib looked the proxy
  credential up by the destination URL and found nothing, so every send failed as a bare `407`. For
  an http destination it now finds the credential. It answers only a request that went through the
  proxy, never one sent direct under a `no_proxy` match. (`BACKLOG #1171`, ASVS 11.4.1)
- **The message for a group- or world-writable trust anchor now names its own fix.** It used to
  point at `docs/security/OFF-LOOPBACK-DEPLOYMENT.md`, which ships in neither a checkout nor a
  wheel. The same text is the refusal under `[security].enforcement = enforce` and the warning under
  `warn`. On Windows it now lists the `icacls` commands that replace each write grant with read
  (`R`), and names the rights the check counts as write. On POSIX it gives `chmod go-w`. Neither
  fix takes read away. The message now spans several lines. When the engine refuses or warns is
  unchanged. (`BACKLOG #2035`)
- **The web console explains an uploaded-file action the engine refused, throttled or could not
  serve.** The browse, resend and delete routes under `/ui/uploaded-logs` showed the engine's raw
  JSON for any status they did not map. A browse the PHI-read hop guard refused (`403`), a browse
  over the PHI-read rate limit (`429`), and a browse, resend or delete with no uploads directory
  configured (`503`) now return to the uploaded-files list with a fixed notice. The `503` also
  reaches both confirm pages, which now return to the list the same way. The `429` notice says to
  wait and try again. The bad-criteria retry on browse is covered too. The list page answers `503`
  as HTML with its own notice. No notice repeats the engine's own text, and the `404` answers are
  unchanged, so a refused owner check still reads as a missing file. The console's own pacing and
  permission refusals are not covered.
  (`BACKLOG #1169`, PR 1506 follow-up A)
- **Replacing a CRL file no longer clears its expiry alert while a running hop holds the old copy.**
  A hop reads its CRL once, when it builds its TLS context, and keeps that copy until a restart. The
  `[cert_monitor]` scan read only the file. So a replaced CRL looked fresh while the hop still held
  one that would lapse and then refuse every peer. The engine now records each CRL load against the
  context that holds it, and the scan judges those held copies as well as the file. The alert stays
  up until the hop is rebuilt, which a restart does. A replaced file that is not near expiry logs a
  warning on each scan, since the hop does not yet see the new revocations. A missing or unreadable
  file no longer silences the scan while a hop holds a copy. A CRL a hop loaded from a path no setting
  names gets its own `held-crl:` row. A CRL file that changes while it is being loaded now refuses,
  so the copy checked is the copy loaded. `[store].ssl_crl_file` records no copy, because that hop
  already re-reads the file for each new connection. (`BACKLOG #299`, ASVS 12.1.4)
- **A temporary password can no longer be rotated after its deadline.** Sign-in already refused an
  admin-issued temporary password past `[auth].initial_password_expiry_hours`. A session opened a
  moment before that instant could still use the lapsed password to set a new one. Now
  `POST /me/password` refuses it with a `403`, "your temporary password has expired; ask an
  administrator to reset it", before checking the password. It writes the sign-in gate's
  `auth.temp_password_expired` audit row, with `"at": "password_change"` and `password_checked` in
  its detail. It checks again after a correct password, in case the deadline passed while the
  request waited. Before the deadline nothing changes. (`BACKLOG #2009`, ASVS 6.4.1)
- **The test harness Monitor states when a temporary password stops working.** When it refuses to
  connect an account that must change its password, its status line now gives the deadline the
  engine's login response carries, in the web console's UTC stamp. (`BACKLOG #2009`, ASVS 6.4.5)
- **The tray's View Log now opens only a `.log` or `.txt` file on a local drive, and `tray.log` is
  scrubbed.** Before this, a `log_path` naming a `.bat`, `.lnk`, `.hta` or `.url` file, or a remote
  share, could have run a program or sent NTLM credentials as the tray user on a first deployment.
  The rule is checked on the configured name before any probe, and again on the resolved target. It
  refuses UNC, WebDAV, device and extended paths, mapped network drives, `.lnk`, alternate data
  streams, and a trailing dot or space. The refusal is a fixed message that echoes nothing from the
  path. `tray.log` now gets the PHI, credential and control-character scrub (new
  `tray/logscrub.py`, ADR 0113 amendment), and `httpx` and `httpcore` are held at WARNING.
  (`BACKLOG #2086`, `BACKLOG #2092`)
- **`python -m tee anonymize-captures` now logs what the leak-check did not look at.** One INFO
  line per run lists every field address no rule mapped, with a count, and says that a name, an
  undashed number or a date in those fields passes. `--log-level WARNING` hides it. The
  anonymizer's leak-check now also refuses a line no rule can reach: one whose first field is not
  a segment id, one with no field separator (a legal empty segment such as `PV2` included), or a
  lowercase second `msh` line. Such a line was passed through untouched, and its text could appear
  in the coverage report. A segment id that the message's HL7 version does not define, and that is
  not a Z-segment, is now shown as `(unknown segment)` rather than printed, so a wrapped `KIM|F`
  cannot put a name fragment in the log. A second `MSH` line is numbered as MSH fields.
  `docs/PHI.md` §9 now lists exactly what the leak-check refuses. (`BACKLOG #1710`)
- **A sign-in that still owes its second factor can no longer evict a fully signed-in session.**
  The per-user session cap counted every live session in one group. So a caller holding only the
  password could sign in `max_sessions_per_user` times and sign out every device that had finished
  MFA. Now the cap ranks sign-ins that still owe a factor apart from the full sessions. Each group
  keeps the cap, so a user holds at most twice the cap. A session ranks from its latest second
  factor, and the cap runs again when a factor is completed. Completing MFA therefore evicts the
  oldest full sibling, not the session that just finished. The cap asks the same rule as the MFA
  access gate, so the two agree on which sessions are pending. (`BACKLOG #2076`, ASVS 7.1.2)
- **The session list hides, and the hourly reaper deletes, sessions past the idle timeout.** Both
  used to act on the absolute expiry alone, so a session the engine already refused still showed on
  the user's own session list. A session stamped ahead of the clock stays on the list, because it
  can be accepted again once the clock catches up, and the user must be able to end it. Ending a
  prior session at sign-in now counts as ending a live one
  only when the engine would still accept it, clock-step checks included. The engine checks
  liveness with one rule in Python and one shared SQL clause, and a test holds those two equal
  on SQLite; the Postgres spelling is covered by the cross-backend contract cases.
  (`BACKLOG #2096`, ASVS 7.3.1)
- **The AD session reconciler now ends a session whose directory scope was withdrawn or narrowed.**
  It re-diffed roles on each pass but not channel scope. So on a first deployment, a user dropped
  from their last scope-mapped group in the directory would have kept the old channels in every
  live session until the next login, up to the absolute cap. A pass now revokes with reason
  `scope_changed` when the directory would withdraw the scope or drop a channel from it. It never
  writes the scope; the next login does, through the same decision function the pass plans with.
  A principal whose roles changed too is revoked once and counts once against the mass-revoke
  breaker, and a breaker abort drops these revocations with the rest. A widened scope still waits
  for the next login. (`BACKLOG #1957`, ADR 0198)
- **A config reload whose audit row fails now reports the swap it made, instead of a 500.** The
  inline `POST /config/reload` swapped the graph and then wrote its `config_reload` audit row. If
  that write failed, the operator got a 500 for a reload that had run, and a retry would run it
  again. The route now logs the lost row at ERROR and answers 200 with `degraded: true` and `audit`
  in `failures`. A released dual-control reload reports the same, so its `approval.approved` row
  records that the `config_reload` row is missing. On SQL Server, an audit COMMIT can fail and its
  rollback fail too. The connection is then discarded, so the next borrower cannot commit a release
  row the gate refused with 503. (`BACKLOG #1940`)
- **Stopping upload retention waits for its audit rows, and engine shards share the upload quota.**
  Stopping the upload retention runner mid-sweep cancelled the sweep. On a first deployment, that
  would have deleted files with no `upload.prune` row. The runner now asks the sweep to stop and
  waits up to 5 s for its audit rows. A pair is reported pruned only when its body was removed.
  Each upload now reserves, reads the ledger's in-flight total back, and then scans the disk. Before
  this, two engine shards could both have passed the per-uploader quota on a stale scan. The
  docstrings no longer claim the reservation alone made that decision exclusive. (`BACKLOG #2065`,
  `BACKLOG #1941`, `BACKLOG #1942`)
- **A store key that the pinned `[store].key_provider` does not read no longer counts as a key.**
  `key_provider = "dpapi"` reads only `[store].encryption_key_file`, and `"env"` reads only
  `MEFOR_STORE_ENCRYPTION_KEY`. With the other source set alone, the at-rest gate read the store as
  keyed, the provider returned no key, and the store would open under the plaintext cipher: under
  the audited opt-out, or on an existing store. Now `serve`, `supervise` and `provision-admin`
  refuse that pairing before they open anything, whatever the opt-out says, and name the source the
  provider reads. `open_store` refuses it for every other command. The keyless refusal texts now
  also name an external `[store].key_provider` such as `vault` as a remedy. (`BACKLOG #2077`)
- **Confirming TOTP enrolment no longer turns MFA on when its recovery codes are lost.** The
  confirm enabled MFA, then rotated the session, and only the rotation handed the one-time
  recovery codes back. A session revoked between the two steps left MFA on with codes nobody
  saw. The confirm now rotates first and enables MFA only once the rotation succeeds. On a lost
  session MFA stays off, and the user signs in again and enrols again. Over the API, the staged
  secret survives and a fresh code confirms it. (`BACKLOG #1902`)
- **A passkey sign-in refused for its stored key is now audited with its reason.** Since
  BACKLOG #1166 sign-in refuses a stored key that the registration rule refuses. That refusal was
  audited as `auth.webauthn_failed` with no detail, the same as a bad signature, so an admin
  could not see why a passkey-only user was stuck. The row now carries
  `reason=stored_key_refused` and the credential label, and the engine logs a WARNING naming the
  label. The fix is to register that passkey again. The sign-in response does not change.
  (`BACKLOG #1963`)
- **The `serve` warning for a public web console address with no declared proxy posture no longer
  says the session cookie ships without Secure.** Since BACKLOG #2055 that posture cannot trust a
  forwarded scheme, and the engine serves https on its self-signed placeholder, so the cookie
  carries Secure. The warning now says so. Its HSTS clause stands: HSTS stays off the placeholder
  until an operator certificate or a declared proxy posture is set. (`BACKLOG #2163`)
- **Operator text no longer says the OIDC username claim picks the on-prem account.** Since ADR
  0184 the bound (issuer, sub) pair selects it. The load-time refusal for
  `oidc_username_strip_domain` without a suffix list, the `verify` `fed.username_binding` rows, and
  the CONFIGURATION, SECURITY and FEATURE-MAP docs now say so, and call the suffix check defence
  in depth.
  ARCHITECTURE.md now lists `httpx` and `truststore` as base dependencies. (`BACKLOG #2155`)
- **`fhir_lookup` now reports a refused hop as a lookup error, re-checks the hop on its probe, and
  refuses to pile up reads behind one that timed out.** The send-time hop re-check raised a raw
  `InsecureHopRefused`. That is a `ValueError`, which the sandbox worker does not catch, so a Handler
  saw a crash rather than a `FhirLookupError`. It is now a `FhirLookupError` naming the connection.
  The "test connection" probe sends the same credential over the same hop, and it skipped that
  re-check; it now runs it before the SMART mint. When the Handler bridge gives up waiting, the read's
  thread keeps running, because a thread cannot be cancelled. A Handler that retried at once started a
  second live read beside it. Now a new read on that connection is refused with a `FhirLookupError`
  until the abandoned one ends. This bounds how many reads a retry adds, not how long an abandoned read
  runs. (`BACKLOG #2059`)
- **A refused egress reply now names the connection, not its URL.** When the engine refuses a reply
  body as too large, truncated or misframed, the error named the hop by its redacted URL, which still
  carries the host and path. It now names the connector kind and the connection, as
  `FHIR connection 'OB_FHIR'`, from a new `hop_identity` helper in `transports/bounded_read.py`. That
  covers the REST, SOAP, FHIR and DICOMweb destinations and their probes. The `fhir_lookup` read and
  probe say `FHIR lookup`, after the connection their `FhirLookupError` already names. The SMART and
  OAuth2 token reads say `SMART token endpoint` or `OAuth2 token endpoint`, and the AI broker says
  `AI endpoint`. The WARNING for an unreadable SOAP fault body or FHIR error body names
  the connection too. Other error text on those hops, such as an HTTP status or an unreachable host,
  is unchanged. A test now refuses any bounded-read call site whose label mentions a URL.
  (`BACKLOG #2060`)
- **A `db_lookup` that cannot reach its database now raises `DbLookupError`, not a raw driver
  error.** Opening the lookup pool, or borrowing a connection from it, dials the database, and a
  failure there escaped as the driver's own exception. So did the Handler bridge's 30-second wait,
  as a builtin `TimeoutError`, and a query the engine cancelled as a raw `CancelledError`. All now
  raise `DbLookupError`. The message names the connection and the error type, with the SQLSTATE and
  native error number for a driver error, or says the `sqlserver` extra is missing. It never quotes
  the driver text, the statement or its parameters. A Handler that catches `DbLookupError` now sees
  these failures too. (`BACKLOG #2062`)
- **A refused channel-scope save in the web console now keeps the administrator's edits.** Every
  refusal used to re-render the stored scope, so the edits were lost and had to be typed again. That
  included a save refused for a missing "Make this scope manual" tick, and a ticked resubmit refused
  for a bad connection name. The form now shows the scope the save would have stored, with names
  escaped and the box unticked. A list holding `*` keeps its other names and drops the token; a list of
  nothing but `*` shows the stored scope. Names
  typed while "All channels" or "No channels" was chosen are not kept, because that save would not
  store them either. An empty list and an unknown mode still show the stored scope, since the form
  cannot show them as chosen. Nothing is saved until a resubmit passes every check again. Each
  refusal and its `400` are unchanged. (`BACKLOG #2099`)
- **A message with a blank line between segments is now accepted and recorded, not dropped.** A
  sender that ends segments with CRLF and adds an empty line produced an empty segment. Every field
  read on it raised, so the MLLP listener wrote no row and sent no ACK or NAK. The parser now drops
  empty segment lines before it reads, so the message is ACKed `AA` and recorded `RECEIVED`. The
  stored raw keeps the blank line. A parsed `Message` does not, so a Handler's re-encoded output has
  no blank line. A field read that still faults for another reason records `ERROR` and NAKs `AR`.
  (`BACKLOG #1594`)
- **The AD session reconciler no longer signs out a small estate when its bind account loses read
  on `userAccountControl`.** Since BACKLOG #1639 an unreadable attribute refuses sign-in, and the
  reconciler read it as "not found". So a lost read right would have made every signed-in account
  look gone at once on a first deployment. With five or fewer signed in, the mass-revoke breaker
  would have let that through and revoked every session. On a larger site it would only have
  delayed it. The reconciler now tells an unreadable
  attribute apart from a disabled account and from a search that matched nothing. It holds the
  unreadable accounts without revoking them when more than one is known, or when nothing readable
  sits beside the one. It reconciles the rest of the estate as before. A held pass writes an
  `auth.ad_reconcile_held` audit row and raises the new `ad_reconcile_held` alert. A single
  unreadable account among readable ones is still revoked, except while an earlier wave's hold
  still stands; ADR 0195 states the rule. Sign-in still refuses every unreadable
  attribute. Revocations now carry the reason `directory_disabled` for a set disabled bit and
  `directory_undetermined` for a single unreadable attribute; `directory_absent` now means only a
  search that matched nothing. (`BACKLOG #2039`, ADR 0195)
- **The Vault and OpenBao clients now read every reply through the strict, bounded reader.** The
  KV secret provider, the Transit key provider and the `vault_transit` cipher read replies through
  `hvac`, `requests` and `urllib3`, which applied no byte bound and parsed framing leniently. On
  first deployment a misframed reply would have been read as an answer: a `Content-Length` beside
  a `Transfer-Encoding` with a space before its colon, a header line with no colon, or a chunk size
  such as `-5` or `0x5`. A new `requests` adapter, mounted on the session `hvac` builds, reads each
  body through `bounded_read`. It refuses those shapes, a KV reply past the 16 MiB egress bound, and
  a Transit reply past 64 MiB. The Transit bound is larger because a Transit reply carries a whole
  stored cell as base64. Each
  request now asks for `Accept-Encoding: identity`, and a reply with another content coding is
  refused. Connection reuse stays, because the Transit cipher makes one call per cell. A connection
  goes back to the pool only after a strictly complete read, and is closed after any refusal.
  (`BACKLOG #2053`)
- **The OAuth2 client-credentials token provider now keeps its `DeliveryError` contract, and caches
  a token for at most one hour.** BACKLOG #1980 fixed these defects in the SMART provider, and the
  OAuth2 provider had its own copy of the same code. Three token replies escaped it as raw errors: a
  malformed status line, a deeply nested body, and an `expires_in` too large for a float. A REST,
  SOAP or FHIR destination would have treated each as an internal error rather than a transient
  delivery failure to retry. Each now raises `DeliveryError`, and a malformed status line is named
  by class only. An `expires_in` of `1e999` parses as infinity, so the provider would have cached
  that token forever. It now caches a token for at most one hour after the expiry skew, as the SMART
  provider does. A `NaN` lifetime is treated as a missing one, and a negative lifetime still caches
  nothing. A JSON `true` or `false` lifetime is treated as a missing one too. Both providers now
  share one token-reply reader, parser and cache rule. For both, a bad token reply no longer carries
  the peer's bytes on the `DeliveryError`'s exception chain. The JSON decode error held the whole
  reply, bearer included. (`BACKLOG #2054`)
- **A FHIR or REST destination now retries a malformed reply from its partner instead of treating
  it as an internal error.** A partner that sent a broken status or header line made `http.client`
  raise `BadStatusLine` or `LineTooLong`. Neither is an `OSError` or a `URLError`, so it escaped the
  delivery and "test connection" paths unclassified. By default the row would have dead-lettered
  as an internal error at once. It is now a `DeliveryError` that retries like a dropped connection.
  The message names the error class only, never the reply bytes. This covers the partner's own
  endpoint; an OAuth2 token endpoint's malformed reply is not changed here. (`BACKLOG #2058`)
- **A Loopback re-ingress now holds a non-HL7 reply to the 16 MiB engine ingress ceiling.** The
  re-ingress step checked size only through the HL7 peek. So it routed a JSON, XML, text, X12, FHIR,
  binary or DICOM reply of any size. That would let an internal hop bypass the listeners' ceiling on
  first deployment. The step now runs the listeners' size check. It counts the bytes that binary
  carriage holds and the characters of any other reply. The engine records an oversize reply as one
  `ERROR` message with the listeners' wording and does not route it. The step gains the size check
  only; the listeners' NUL and declared-type checks still do not run there. An HL7 loopback keeps
  its peek check and its wording. SQL Server now also encrypts the error text of a re-ingress
  `ERROR` message, as it does every other message error. (`BACKLOG #1914`)
- **The OIDC revocation refusal now stops startup before any connection starts, and `verify`
  reports it.** On an enforcing instance, an off-box OIDC token or JWKS leg with no
  `[auth].oidc_tls_crl_file` refuses to start. That refusal fired when the API lifespan built the
  auth service, which was after the engine had started its connections. The lifespan now builds the
  service before `engine.start()`, so the engine starts nothing. Any other refusal the service's
  constructor raises moved with it. `verify --section federation` has a new `fed.idp_revocation`
  row. It runs the engine's own guard and FAILs where the engine would refuse. `messagefoundry
  check` still does not report it. (`BACKLOG #1923`)
- **A DR backup no longer holds the store write lock while it copies the store.** Both
  `[backup].snapshot_method` values ran the copy on the writer connection inside the store lock. On a
  deploying site every store write, logins included, would have waited for the whole copy. On a
  synthetic 201 MB store, one write issued during a snapshot waited 0.72 to 2.68 s under either
  method. Only the WAL checkpoint now holds the lock. The copy runs on its own read-only connection
  in one read transaction, so it is still point-in-time, and the same write took 3 to 7 ms. A
  retention WAL checkpoint that lands during a copy runs PASSIVE, since the copy keeps a TRUNCATE from
  finishing. `online_backup` was also documented as copying in yielding batches; it copied in one step under the
  lock. The default stays `vacuum_into`, which writes a defragmented copy. ADR 0049 carries the
  correction. (`BACKLOG #1937`)
- **A restore-verify no longer leaves the decrypted store in the OS temp directory when its cleanup
  is refused.** The verify decrypts the archive into a `mefor-verify-*` directory. On Windows, a
  handle still open on the extracted store, such as a scanner's, made the removal fail. The
  directory then stayed for good with the decrypted store in it. The failure also replaced the
  verdict with a `PermissionError`, or replaced the error the verify was raising. The verify now
  truncates every file to zero bytes and retries the removal for about two seconds. Truncation
  usually works while another process holds the file open, but not when the holder denies write
  sharing or has the file mapped. The verdict or error is the verify's own. If a file can be neither
  removed nor emptied, the verify names the directory to delete: a `PASS` becomes `FAIL`, another
  verdict keeps its status, and an exception carries it as a note.
  `docs/PHI.md` says the same. (`BACKLOG #1721`)
- **A failed federated sign-in now answers at the same fixed deadline as the other sign-in
  paths.** `complete_oidc_login` and `authenticate_oidc` returned their refusals as soon as they
  were decided. A refusal after the token exchange, such as an unlinked identity, a disabled or
  locked account, or an account the directory no longer holds, costs more store and directory work
  than one before it, so its timing could tell them apart. Both now hold every failed outcome to a
  fixed deadline, as the password and Windows SSO paths already do (ASVS 6.3.8). A refusal after
  the identity provider round trip counts that deadline from the end of the round trip, so the
  provider's latency cannot split refusals across it. A success is not delayed.
  (`BACKLOG #1947`)
- **A bad authorization code no longer hides the federated sign-in link.** A token endpoint that
  refuses the code a caller presents answers with an HTTP 4xx, and the engine used to read that as
  an identity provider outage. That set `oidc_available` to false, which hides the link on
  `/ui/login` and reports `oidc: false` from `/auth/providers`. So any signed-out visitor who
  started a flow could turn federated sign-in off for everyone by calling back with a junk code.
  The token exchange now raises `TokenRefusedError` for any 4xx, since the endpoint answered. The
  engine audits it as a failed sign-in with reason `token_refused`, the HTTP status and the client
  address, and leaves the flag alone. The engine's own faults, such as a wrong client secret, are
  4xx too: they are told apart by the status on the audit row, not by the flag, so no error body is
  read. A transport failure, 3xx or 5xx is still an outage.
  (`BACKLOG #1948`)
- **The Python engine client now ends the session a new sign-in replaces.** `EngineClient.login`
  used to overwrite the bearer token it held and never revoke it, so the old session would have
  stayed valid on first deployment until it idled out. It now calls `POST /auth/logout` with the
  old token after the engine accepts the new sign-in, as the IDE does. Unlike the IDE, it ends only
  a token the engine issued to that client. A token adopted with `set_token`, such as one from a
  keyring or `--token`, may be shared with another process, so the client drops it and leaves it
  live. A refused sign-in ends nothing, and a revoke that fails is logged without the token and
  never fails the sign-in.
  (`BACKLOG #1901`)
- **`audit-anchor --json` now reports a missing audit database, or one with no `audit_log` table,
  as JSON on stdout.** Both refusals printed plain text to stderr whatever `--json` said, so a
  caller piping to `jq` got an empty stdout. They now print `{"error": ...}` on stdout, as the
  unreadable-file refusal already did. The message and exit code 2 are unchanged, and text mode is
  byte-identical. (`BACKLOG #1922`)
- **`Direct(...)` now fails at construction on faults that used to fail every send.** A
  `recipient_cert` whose key is not RSA is refused, because the S/MIME envelope supports RSA key
  transport only. This reverses the EC recipient allowance. An EC `signing_key` or `trust_anchor` is
  still accepted. Construction also signs and encrypts one synthetic body. So a crypto library that
  refuses the algorithms, or a line break inside `subject`, now fails `check`.
- **A `Direct(...)` message that cannot be built now dead-letters at once, with no body on the
  error.** That is a body the `encoding` cannot represent, or a build failure that began after
  construction. It used to be a retried transport error. The error now keeps only the failure class,
  or the codec and position. The old one chained the encode error, whose `.object` is the whole body.
  `UnsupportedAlgorithm` and `InternalError` are now mapped too. The first was reported under a
  FIPS-enabled OpenSSL. Neither case was reproduced. (`BACKLOG #1918`, `#1919`, `#1920`, `#1921`)
- **The shared redactor now scrubs FHIR JSON, DICOM tag dumps and XML, not only HL7.** Its passes
  were HL7-shaped, so a structured payload handed them single tokens and a family name, an MRN or a
  DICOM patient id went through a stored error, a log line, the support bundle and `GET /logs/tail`
  unredacted. Three label-anchored passes now run after the HL7 ones, so they only add redaction.
  JSON (and Python dict repr) values under `family`, `given`, `name`, `birthDate` and `address` are
  scrubbed, and so is the `value` of an `identifier` or `telecom`, keeping `system` and `use`. DICOM
  `(0010,00xx)` tag values and `PatientName=`/`PatientID=` labels are scrubbed, and so are XML
  elements with the same vocabulary. Keys, tags and element names stay, so a reader sees which field
  was withheld. A `<name>` placeholder in a usage hint is left alone. JSON escaped inside a JSON
  string is not covered. DICOM identifiers outside `(0010,00xx)` were not covered either, until the
  entry below. ([BACKLOG #1711](docs/BACKLOG.md))
- **The shared redactor closes three more leaks.** A number after an `MRN` label in prose (`MRN 12345678`, `mrn: A1234`, `"mrn": "12345"`) is scrubbed,
  keeping the label; an ordinary number with no label is untouched. The DICOM pass covers all of
  group 0010, so Other Patient IDs, Patient's Address, Telephone Numbers and the Other, Birth and
  Mother's Birth names are scrubbed. A plain string under a JSON `name` or `address` is now judged by
  its shape: one token with a digit or one of `_ . :` (`IB_ACME_ADT`, `10.1.2.3`) is kept, and a
  one-word patient name, an email address or a `LAST/FIRST` name is scrubbed. That over-redacts a
  preset name a user types in the off-box audit copy, a connection named in plain letters, a path
  and a single-label host; the stored audit row is untouched. The redactor runs the passes as they
  were before this change first, and the widened ones over that result only when the text holds one
  of their triggers, so nothing it scrubbed before can now survive. The one token the name rule now
  keeps is an `MRN` label ending a run, so `INVALID MRN 12345678` loses its number; an ALL-CAPS word
  after the label (`MRN AB-12345`) still takes the label, as before. The name rule keeps no list of
  engine phrases: engine text it would eat is reworded where it is written (the tray's old `Open
  Console` refusal was), and until the rest are reworded they are scrubbed from engine messages.
  ([BACKLOG #2079](docs/BACKLOG.md))
- **A dual-control release can no longer run without an audit row, or be recorded as failed after
  it ran.** The approval gate wrote `approval.approved` only after the operation ran. An audit log
  that refused writes would have let a replay or a reload complete with no record of the release,
  and handed the approver a 500. The gate now writes a new `approval.release_attempted` row, naming
  both identities, before it moves the request. If that write fails, the approve returns 503, the
  operation does not run, and the request stays pending. After the operation has run, a failed
  `approval.approved` write is logged at ERROR and the release still succeeds. The replay and
  reload executors had the mirror defect: their own audit row failing after the action ran made
  the gate mark the request `failed`. They now log that failure at ERROR instead. (`BACKLOG #1940`)
- **A dual-control release now records whether its operation finished, failed or was cut off.**
  The gate used to mark a request `approved` before the operation ran, so a crash or a request
  timeout mid-run left a row claiming an outcome nobody saw. The gate now claims the request as
  `executing`, then settles it once the operation stops. `approved` means it ran and returned.
  `failed` means it raised, or the release was cancelled before it started. `interrupted` means it
  was cancelled while running, so it may have done none, some or all of its work; that writes a new
  `approval.interrupted` audit row, and nothing retries it. Every outcome write is shielded, so a
  second cancel cannot stop it. If the move to `approved` fails after the operation ran, the error
  is logged and the release still succeeds, and the row may stay `executing`. A process that dies
  mid-run also leaves its row at `executing`; nothing reconciles those rows yet.
  (`BACKLOG #1562`)
- **In the default pooled claim mode, a stage whose claimer task dies now recovers instead of
  stopping.** One claimer serves a whole stage by default. When it died, nothing restarted it: the
  stage stopped draining while intake kept acknowledging, and the engine still read healthy. The
  dispatcher now restarts a dead claimer or sweep task on the same lanes. The new claimer first
  returns any rows the dead one had claimed but not dispatched, so a lane's next message cannot
  overtake them. A task that keeps dying backs off instead of spinning, up to 30 seconds. While a
  dead claimer has not recovered, `GET /status` names its stage in `engine.stages_degraded` and the
  web console's health heart reads down. After one death that lasts until the new claimer runs.
  After repeated deaths it lasts until the claimer has run cleanly for 30 seconds. A dead sweep
  task is restarted and logged the same way, but is not reported there, because the claimers keep
  draining without it. (`BACKLOG #1609`)
- **Replay no longer re-queues a pass-through completion marker, so a replayed message that
  delivered ends `PROCESSED`, not `ERROR`.** A handler `Send` into a pass-through inbound leaves an
  already-finished marker row on the parent. Its lane is an inbound name, so no delivery worker
  drains it. On a store with an encryption key, message replay put a delivered marker back to
  pending. The parent then stayed `ROUTED`, even when its real delivery had gone out again. The next
  start's sweep dead-lettered the marker and recorded the delivered message as `ERROR`. Bulk
  dead-letter replay did the same to a marker that the depth cap had left dead: its parent went back
  to `ROUTED`, and nothing could finish it before the next start. Markers now carry the stamp `@passthrough-marker` in
  `handler_name`. Replay, bulk dead-letter replay and resend skip a row with that stamp, on SQLite,
  PostgreSQL and SQL Server. The attachment clean-up no longer keeps an attachment alive for a dead
  marker. Replay does not retransmit into a pass-through inbound, because the marker has no body. A
  depth-capped marker stays dead, so its parent keeps `ERROR`. A resend with no source named no
  longer calls a parent with one real delivery ambiguous. A pass-through-only parent now reports no
  delivered body, not a purged one, and its replay refusal names the pass-through case.
  ([BACKLOG #1580](docs/BACKLOG.md))
- **A failed SMART token mint in `fhir_lookup` now raises `FhirLookupError`, not a raw
  `DeliveryError`.** A lookup mints its bearer before the GET, outside the handling that maps
  every other lookup failure. So a token endpoint that was down, refused the client, or sent a bad
  reply let the provider's own error escape. A Handler that catches `FhirLookupError`, as the lookup
  contract says to, would have missed it. The mint now maps to `FhirLookupError`, with the cause
  chained. The message names the redacted token URL and a status or reason. It never carries the
  client assertion or the reply body. An over-length configured token URL maps the same way, with
  a fixed message. Three more raw errors reached a Handler from `fhir_lookup` and now map the same
  way:
  - A read that gets no result within the Handler's 30-second wait. That wait covers the token mint
    and the GET together, and each has its own 30-second default. So a token endpoint that never
    answers used to surface as a bare `TimeoutError`.
  - A malformed status or header line from the FHIR server itself. The message names the error
    class only.
  - The same malformed reply from the token endpoint.

  The SMART provider also raised errors outside its own `DeliveryError` contract: for a malformed
  status line, a deeply nested reply, and an `expires_in` too large for a float. It now raises
  `DeliveryError` for each. So a FHIR or REST destination using SMART would retry them as transient
  failures rather than treat them as internal errors. An `expires_in` of `1e999` parses as infinity,
  and the provider would have cached that token forever. It now caches a token for at most one hour
  after the expiry skew, and treats a `NaN` lifetime as a missing one. A deeply nested FHIR reply to
  a lookup now maps to `FhirLookupError` too. The lookup executor's probe method has no caller yet and
  gets the same mappings.
  (`BACKLOG #1980`)
- **A malformed reply to a SOAP or DICOMweb destination, or to the AI broker, is now a classified
  failure.** A bad status or header line from the partner, such as `BadStatusLine` or `LineTooLong`,
  escaped each of them as an internal error. A delivery now fails with a retryable `DeliveryError`,
  and a connection test fails with a plain one. Each names only the exception class, never the
  partner's bytes. The AI broker
  raises `AiBrokerError`, so the assist route answers `502` rather than `500`. It also maps an
  invalid request value the way the other HTTP callers do, without echoing it.
  (`BACKLOG #2113`)
- **A `GET /connections` row for an outbound with no traffic edge now reports `0`, not `null`, when
  it measures zero.** That standalone row gave `queue_depth`, `written` and `errored` as `null`.
  `null` means "not measured" and cannot be told apart from a real zero. The store's outbound totals
  group every queue row an outbound has. So when none of this outbound's rows is queued, or written
  or dead-lettered since the engine started, the row now says `0`, and `backlog_seconds` says `0`.
  The row keeps `null` in at least one case: its outbound has live traffic from an inbound this node
  does not run. That inbound may belong to another engine shard, or have left the config. Folding
  that traffic in would count it once per shard. The row still does not report `idle_seconds` or
  `delivered_age_seconds`. ([BACKLOG #1817](docs/BACKLOG.md))
- **A file destination now logs a WARNING when it cannot remove its `.part` temp file.** Each
  delivery writes a temp file inside the destination directory, then hard-links or copies it to the
  target name. The temp removal after that ignored every error. A failed removal left a full copy
  of the message in a `.part` file there permanently, with nothing in the log. The delivery still
  succeeds. The warning names the temp path and the OS error. The `overwrite` mode renames the temp
  into place, so it has no temp left to remove and logs nothing. (`BACKLOG #1862`)
- **An MLLP listener now answers a store outage at intake with a NAK before it closes the
  connection.** When the inbound handler faulted, for example because the store could not commit
  the message, the listener closed the socket with no reply and logged the event as
  `framing_error`. It now sends an `AE` (a `CE` in enhanced mode) with fixed text, then closes,
  and records a new `handler_error` connection event. An inbound that sends no replies keeps its
  socket, so frames already sent behind the failed one are still handled. The message is still
  not accepted, and the sender resends it. The NAK has no message row, so it is not in the ACK
  capture stream. ([BACKLOG #1619](docs/BACKLOG.md))
- **`db_lookup` now refuses a result larger than the lookup's `max_rows`, and stops reading at the
  ceiling.** It used to call `fetchall`, so a Handler's statement with a broad predicate held its whole
  result set in the transform worker. `DatabaseLookup(...)` takes `max_rows`, default `500`. The
  executor asks the driver for at most `max_rows + 1` rows. A larger result raises `DbLookupError`, and
  the message goes to `ERROR`; the Handler never sees a truncated result. `max_rows=0` removes the
  ceiling. ([BACKLOG #1730](docs/BACKLOG.md))
- **On Windows, the service account and the operator who runs `provision-admin` can now each open
  the SQLite store, in either order.** In 0.4.0 every open rewrote the store's `.db`, `-wal` and
  `-shm` files to grant the opener alone, so whichever opened a fresh store first locked the other
  out. A provisioned store stopped the service starting, and a store the service created refused
  `provision-admin`. In a data directory hardened the way `install-service.ps1` leaves it, each open
  now writes one protected ACL on those files naming SYSTEM, Administrators and the one service
  account. It is the same whoever opens, and it reaches every member of Administrators whose token
  carries the group enabled, not only the operator who provisioned. `install-service.ps1` now also
  makes Administrators the owner of the data directory, because the engine requires that. Outside a
  hardened directory, the old owner-only behaviour is unchanged. What this widens and narrows is
  stated in the ADR 0163 note of 2026-09-24; the measurement is ADR 0183 Wave 0 and 0b.
  (`BACKLOG #1136`)
- **The DICOM C-STORE SCP no longer answers Success for an object the engine does not accept.**
  The SCP's `max_object_bytes` defaults to 128 MiB, but the engine's binary ingress records any
  object over 16 MiB as `ERROR` and never processes it. So an object between 16 and 128 MiB was
  answered Success and dropped: the modality believed it delivered and would not re-send it. Two
  changes close this. The SCP now caps objects at the smaller of `max_object_bytes` and the 16 MiB
  ingress ceiling, including when `max_object_bytes` is `0`/`None`, and refuses a larger one with
  Out of Resources (`0xA700`) before any commit. Like the SCP's other pre-commit refusals, that
  object is logged and not recorded as a message; it used to leave an `ERROR` row. And whenever the engine's ingress refuses an object
  the SCP passed, the SCP now answers Cannot Understand (`0xC000`) instead of Success; the `ERROR`
  record is kept. **Behaviour change for a sending modality:** an object over 16 MiB now gets a
  failure status where it used to get Success. A `max_object_bytes` above 16 MiB no longer raises
  the SCP's limit; the outbound SCU's use of the key, and the SCP's pre-decode inflate bound for a
  deflated object, are unchanged. (`BACKLOG #1910`)
- **`POST /users` answers `409 username already exists` when two creates race for one name.** The
  route checks the name before it creates the account, but two requests can both pass that check.
  The second insert then met the store's UNIQUE index, and that error reached the API's catch-all
  handler as a `500`. The engine now catches it and answers `409` with the same text the check
  gives. The web console's create-user form shows that text too. (`BACKLOG #1808`)
- **On SQLite and PostgreSQL, adding a passkey to an account deleted mid-enrolment now says `no
  such user`.** It used to say `label already in use`, because every store refusal of the insert
  got that answer. On those two backends the insert is refused by the foreign key to the account.
  The engine now re-reads the account to tell the two refusals apart. SQL Server has no such foreign
  key, so there the insert is not refused and this change does not apply. (`BACKLOG #1807`)
- **A missing or blank CRL path is now refused at load, naming the setting the operator wrote.**
  Before, `[api].tls_client_crl_file`, `[logging].forward_tls_crl_file`, `[auth].oidc_tls_crl_file`
  and `[tls].crl_file` had no load-time check. A missing path failed closed only if a hop's TLS
  context was built, and that refusal began `[tls] crl file` for every one of them. Each now has its
  own validator, the shape `[store].ssl_crl_file` already had, and all five refuse a blank value.
  The refusal names the setting and the path, and nothing else. It applies even where the setting
  has no effect, such as `[auth].oidc_tls_crl_file` with OIDC off. A CRL that exists but is expired
  or unloadable is still refused when the context is built. That refusal used the old
  `[tls] crl file` prefix until `BACKLOG #299`, below. (`BACKLOG #1997`)
- **A CRL file is now judged on every CRL it holds when a TLS context is built.** Before, only the
  first CRL in the file was checked for freshness, so a file whose later CRL had expired was
  accepted, and every handshake under that CRL's issuer would then fail. The soonest `nextUpdate`
  in the file now decides, the rule the certificate expiry monitor already used, so an expired
  superseded copy left beside its replacement is refused too: remove it. A CRL block with no
  `nextUpdate`, one that does not parse, or a delta CRL is now refused rather than loaded. OpenSSL
  reads a delta CRL as complete, which was measured to drop the base CRL's revocations. The refusal
  names the setting, such as `[api].tls_client_crl_file`, and no longer says "listener" on an
  outbound hop. An inbound connection's `tls_crl_file` refusal names the path only.
  (`BACKLOG #299`)
- **An SFTP server that is slow to connect is now retried, not dead-lettered or treated as a bad
  credential.** A server that did not finish the SSH banner or key exchange within the connect
  timeout was classed as a permanent error, so the delivery would dead-letter on first deployment.
  One that did not answer authentication in time was classed as a credential fault, so the lane
  would stop (ADR 0095) though no credential was wrong. Both are now transient, and so is a server
  that drops the connection before the key exchange completes. A host-key rejection stays
  permanent, and an authentication refusal stays a credential fault. The connector now also closes
  the half-open client whenever the connect fails. (`BACKLOG #1999`)
- **The FHIR parsers and the OIDC token exchange no longer put their input on the exception
  chain.** `FhirPeek.parse`, `FhirResource.parse` and `exchange_code` each raised a content-free
  error `from exc`. The chained decode error holds the whole input: the FHIR body, or the token
  endpoint's reply. The default traceback printer does not show it. Anything that reads the chain
  by attribute would have written it to a log on first deployment. All three now decode
  through `redaction.json_loads_or_refusal` and raise outside any handler, so `__cause__` and
  `__context__` are both empty. The message keeps a content-free hint: the line and column, or the
  error's class name. A token reply nested past json's depth limit now also fails as a login
  error; it used to escape `exchange_code` as a `RecursionError`. At least four other JSON parse
  sites still chain the decode error and are not covered here. (`BACKLOG #2048`)
- **At least 29 more refusals no longer chain the input they withhold, and the HL7 parse refusal
  names no parser text.** Each raise sat inside a handler that had caught an error holding the input:
  a Unicode, JSON or TOML decode error, a truncated stream read, or a pydantic validation error. The
  input rode on the new error's chain. On first deployment that would have handed a Transit-decrypted
  plaintext, an `id_token`'s claims, request headers, a `connections.toml` or a message body to
  anything that walks the chain. Each now raises after its handler, or decodes through
  `redaction.json_loads_or_refusal`. Among the text and behaviour changes, at least:
  - more decodes (JWKS, database payload, backup header and manifest, preset criteria, WebAuthn,
    the AI broker, JWS and X12 reports) turn json's `RecursionError` into their normal refusal
    rather than an escape, and a TOML or engine-reply decode refuses a non-UTF-8 file or body;
  - the backup manifest refusal and the harness client's reply refusal name a line and column, not
    json's reason;
  - `RawMessage.json()` raises a copy of json's error with the same text and position and an empty
    `doc`;
  - the harness client's `ApiError` for a reply that fails its model names field locations, never
    the values pydantic would quote;
  - `Peek.parse` names only python-hl7's error class, since that text is not vetted;
  - MLLP `AR` text (MSA-3) now goes through the same redaction as the stored reason, without the
    Python class name, and the MLLP destination's `unparseable ACK` error is redacted the same way;
  - a non-ASCII compact JWS is a signing refusal, not an encode error, and a malformed preset or a
    non-UTF-8 module for the Steps-view rewrite is a 400 or a lens refusal, not a 500.

  A new source gate flags a raise inside a handler for a body-holding error type. It cannot see a
  raise moved into a helper or a decode behind one, and at least the environment values file and
  `anon` rules loaders still chain their input. (`BACKLOG #2085`)
### Added
- **The reset notice now states when a temporary password stops working, and the operator gets a
  reminder before it lapses.** The deadline itself is not new: `[auth].initial_password_expiry_hours`
  already enforced it. The `PASSWORD_RESET` security notice to the holder now states that instant,
  and asks them to choose a new password before then. A disabled account's notice carries no
  deadline line. A new `[alerts]` event, `initial_credential_expiring`, reminds the operator while
  an admin-issued temporary password is still unclaimed. It fires at most once per credential per
  engine process, in the last third of the window, capped at 24 hours (24 hours at the default 72).
  It names the holder as `user:<username>` and carries the deadline and whole hours left, never the
  password. With no `[alerts]` transport it goes to the log (`LoggingAlertSink`), where no rule
  applies. At `initial_password_expiry_hours = 0` no reminder runs. **Catch-all alert rules match
  this event**, because a rule's `connection` defaults to `*`. When such a rule is the first match,
  its `mute` or `transports = []` silences the reminder. Its `control_action` is dispatched at
  `user:<username>`, or, with `control_target` set, at that real connection, which it restarts.
  Scope such rules to real connection names or to one `event_type`.
  ([BACKLOG #1141](docs/BACKLOG.md))

### Security
- **LDAPS to Active Directory would no longer fail closed on Python 3.15, and it narrows TLS 1.3.**
  On an interpreter with `SSLContext.set_ciphersuites`, the approved list drops
  `TLS_AES_128_GCM_SHA256`. ldap3 builds its own TLS context and could not narrow TLS 1.3, so the
  engine refused to build the AD authenticator there. The engine now builds the LDAPS context
  itself: a new `ldap3.Tls` subclass, `messagefoundry.auth.ldap_tls.NarrowedTls`, wraps each
  connection with a context from `tls_policy.assert_ldap3_tls_suites`, which now returns a factory.
  That context loads the CA as ldap3 did and carries the posture every engine-built client hop
  has: the approved TLS 1.2 suites, the approved TLS 1.3 suites and the SHA-224-free signature
  schemes where the interpreter allows them, the key-exchange pin and a TLS 1.2 floor. ldap3's own
  host name check still runs after the handshake. `ciphers=` is no longer passed to ldap3.
  Python 3.14 is unchanged on the wire: its TLS 1.3 gap is recorded, not closed. A followed
  referral still gets a plain ldap3 context. (`BACKLOG #2494`, owner ruling R3 of
  2026-09-27, ADR 0188 amendment of 2026-09-30)
- **On Python 3.15 the engine stops offering SHA-224 TLS signature schemes.** Every context the
  engine narrows drops `rsa_pkcs1_sha224`, `ecdsa_sha224` and `dsa_sha224` through
  `SSLContext.set_server_sigalgs`. Read from the OpenSSL source, not yet measured on 3.15, that one
  list covers client offers, server signatures and client certificate requests. The list is
  OpenSSL's own catalogue minus SHA-224, with the three ML-DSA schemes that catalogue omits put
  back at the front. Measured with the OpenSSL 3.5.7 command line (`-sigalgs`, not a CPython 3.15
  run), the offer loses exactly the
  three SHA-224 schemes; `rsa_pss_rsae_*` now comes before `rsa_pss_pss_*`. A build that refuses
  the ML-DSA names still drops SHA-224, without ML-DSA, and logs a warning once. Python 3.14 is
  unchanged. A 3.15
  on an OpenSSL older than 3.4 pins nothing and logs a warning once. The LDAPS hop was not
  reached; since BACKLOG #2494, above, it is. (`BACKLOG #1171`, ASVS 11.4.1, owner ruling 2026-09-29)
- **A refused combined sign-in no longer names which factor was wrong in its `auth.login_failed`
  reason.** Every refused combined sign-in (password and TOTP code in one request) on a local
  account with TOTP enrolled now writes the same reason, `bad_credentials`, whether the password was
  wrong, the code was wrong, or both. Before, the reason named the failing factor
  (`bad_code`/`bad_password`/`bad_password_and_code`). Because the sign-in lock does not refuse a
  combined sign-in, an `audit:read` holder who is not an administrator (the built-in `AUDITOR` role)
  could arm a target's sign-in lock, send candidate passwords with any six digits, and read the
  reason to learn which candidate was right — one request per candidate, up to the global sign-in
  ceiling of about 86,400 a day, against ADR 0197's design bound of 35. ADR 0197's counting is
  unchanged: a right password with a wrong code still charges the second-step counter, both wrong
  still charges the sign-in counter, and which factor verified still reaches the account holder's
  own lock notice and the `users:manage` lock-state surface. The coarser residual, the lock rows a
  locked second-step counter emits, is closed by the next entry. (`BACKLOG #1131`, ASVS 6.1.1)
- **The Auditor no longer sees lockout events.** An audit reader without `users:manage`, the
  built-in `AUDITOR` role included, no longer sees `auth.account_locked`, `auth.lock_notice`,
  `auth.login_locked` or `auth.admin_unlocked`, nor the `reason: locked` refusals of the TOTP,
  passkey and directory sign-ins, in `GET /audit`, `GET /audit/export` or the console's
  `/ui/audit`. Administrators still see every row, and the engine still writes them all (ADR 0197
  AC-10). In their place every refused sign-in on an existing, enabled local account writes one
  `auth.login_failed` row with reason `bad_credentials`, whether a wrong credential or a live lock
  refused it. A password-only
  wrong password used to write `bad_password` and now writes `bad_credentials` too. Before, the
  lock rows told an Auditor which candidate password was right: sending one candidate
  `lockout_threshold` times in a combined sign-in locks the second-step counter only when the
  password is right. The cost, accepted by owner ruling 2026-09-28: the Auditor can no longer
  review lockouts. An account holder's own `/me/security-events` feed still shows their own lock.
  The general log no longer names lock events either: an undeliverable lock notice writes no
  per-event log line. With no relay or no address it is recorded instead as `mailed: false` on the
  administrator-only `auth.lock_notice` row; a full queue or a failed send of a lock notice is now
  recorded nowhere. `GET /logs/tail` no longer shows the audit-row copies the off-box tee
  writes into the log to a reader without `users:manage`, the built-in Operator included; that
  reader loses those lines from the log viewer. `GET /status` returns the log directory's
  `size_bytes` and the database's `audit` row count as null to the same readers. A failed
  lock-notice throttle read, a broken audit tee sink, and SMTP with `tls_verify = false` each log
  without naming a lock: the last two once per process. A refused local sign-in's audit rows are now
  written at a fixed point inside the failure pad, so their timestamp no longer shows whether a lock
  or a checked credential refused it. The channels still open are listed in `docs/SECURITY.md` under
  Audit.
  (`BACKLOG #1131`, ASVS 6.1.1)
- **BREAKING: XML signature checks now refuse an RSA signing key under 2048 bits.** Before, the
  XML-DSig `verify()` accepted a signature made with an RSA-1024 key, on both the `x509_cert` and
  the `ca_pem_file` paths. Now it returns `verified=False` with the reason `WeakSigningKey`, even
  when the signature itself is valid. A partner that signs XML with an RSA key under 2048 bits
  will now be refused and must move to a key of at least 2048 bits. A key the check cannot read
  is refused too, with the reason `UnreadableSigningKey`. The floor is 2048, not 3072, by owner
  ruling: partner keys keep the 2048-bit floor. EC and DSA keys are not changed by this.
  (`BACKLOG #1166`, ASVS 11.2.3)
- **The Python security scan now flags new calls into the `random` module.** Bandit check B311 was
  skipped in both the CI scan and the pre-commit hook, so nothing would have caught a weak generator
  returning to shipped code. Both now run it. B311 matches a fixed list of calls, such as
  `random.random()` and `random.choice()`, and misses a few, such as `random.shuffle()`. The five
  existing uses are seeded on purpose, for pseudonym picking, synthetic HL7 and PDF fixtures, and one
  fuzz script. Each carries a per-line `# nosec B311` with its reason. Security values still come from
  `secrets` and `os.urandom`.
  ([BACKLOG #1173](docs/BACKLOG.md))
- **`serve` now refuses to start when uvicorn lacks a hook the protocol header floor needs.**
  `messagefoundry/api/protocol_headers.py` checks each uvicorn and websockets internal it overrides
  when it builds its protocol classes. A missing one used to fall back to uvicorn's own protocol,
  whose `400` and `500` carry no `nosniff`. Now `serve` prints the missing hook and the installed
  versions, and exits with code 2, before it mints a certificate or opens the store. `supervise`
  refuses the whole fleet the same way before it spawns a shard. There is no opt-out. A hook the
  floor calls synchronously that became a coroutine is refused too. A WebSocket protocol without
  the legacy server's `write_http_response`, such as the sans-I/O one or wsproto, is refused the
  same way. `pyproject.toml` now bounds uvicorn below 0.50, and the DAST target serves the same
  floored protocols and the same bannerless `Server` setting `serve` does. Steps on a single
  response still degrade to uvicorn's own response and log a WARNING, and uvicorn's
  `100 Continue` still carries no header. (`BACKLOG #1120`)
- **BREAKING: a directory account with no directory id no longer signs in or steps up by its
  username.** The engine now refuses a Windows SSO sign-in whose directory entry has no readable
  `objectGUID`. It refuses whether or not an account already exists for that name, and it creates
  no account. The web console shows the generic SSO failure, and the `auth.login_failed` audit row
  carries `directory_object_id_missing`. The AD step-up re-bind (`POST /me/reauth`,
  `POST /ui/reauth`) refuses an account with no directory id for the same reason. It refuses before
  it sends the password anywhere. It also refuses an answer about a different directory object
  (`directory_identity_conflict`) or one with no readable id. None of these refusals counts toward
  the account lockout. The web console showed these step-up refusals as a wrong password until
  the step-up entry just below.
  - **Why.** A username is the only key such an account has, and a directory can give a freed
    username to a new person. That person's sign-in would then reach the old account and give it
    their groups, and their password would step up the old account's session (ADR 0184 AC-5).
  - **The cost.** A directory that does not return `objectGUID` to the service account signs nobody
    in through Windows SSO. The engine logs a warning naming the cause once. The fix is to make the
    attribute readable to the service account. For an account left with no directory id, an
    administrator deletes it, and the person signs in again to create it with one.
  - **The step-up re-bind now finds the account by its `objectGUID`, not its username.** The typed
    password goes only to the account's own directory entry, and a renamed account can still step
    up. This adds no directory read: each lookup is keyed on the id instead of the name.

  (`BACKLOG #2027`, ADR 0184)
- **BREAKING: a TOTP or recovery code no longer renews the step-up window of a directory account
  with no directory id.** Before the code is checked, the engine asks the directory to confirm a
  directory account. For an account with no `directory_object_id` and no federated link, it used
  to ask by the account's username. It now refuses such an account without asking, as it already
  did for a linked one. The code is not checked or spent, and nothing counts toward the lockout.
  `POST /auth/mfa-verify` answers `403`, and `/ui/mfa` and `/ui/reauth` say the directory could not
  confirm the account. The `auth.mfa_failed` row carries `directory_unconfirmed` and the outcome
  `directory_object_id_missing`. The same refusal means an MFA-pending session on such an account
  can never satisfy its second factor, so it reaches no MFA-gated route before it expires. The
  remedy is the one in the entry above: delete the account and have it created again with an id.
  - **A step-up the directory could not judge now says so.** That covers at least an account with
    no directory id, no enabled entry for its id, an unreachable directory, and no directory
    configured. `POST /me/reauth` answers `403` saying the directory could not confirm the account,
    instead of `re-verification failed`. The web console's re-auth form says the same instead of
    "Incorrect password." A password the directory refused still reads as wrong. The words name no
    directory detail. The `auth.reauth` audit row now carries the cause as `reason` in every such
    case: `directory_object_id_missing`, `not_in_directory`, `directory_unavailable` or
    `not_configured`. Before, only the first carried one, so an outage's row looked like a wrong
    password's. `Elevation.directory_unconfirmed` now carries this for `reauth` too.
  - **BREAKING: a lookup by `objectGUID` treats an entry that does not read back that id as no
    match.** Where the entry the directory finds by an account's `objectGUID` carries no readable
    `objectGUID`, or another one, the engine now reads it as absent, before its account state. The
    step-up re-bind never binds the typed password as it. The IdP step-up, a federated sign-in, the
    TOTP check and the directory recheck all refuse it, and the recheck no longer takes that entry's
    name as a rename. A federated sign-in or IdP step-up refused this way is audited
    `not_in_directory`, and so is the re-bind, where it was `directory_object_id_missing` or
    `directory_identity_conflict`. The engine logs a warning once when the id differs. **The
    cost:** a directory-wide change that hides `objectGUID` reads as absent accounts. The recheck's
    mass-revocation abort stops a large wave, but at or below its floor the affected sessions end
    after `[auth].ad_session_recheck_strikes` passes.
  - **What still asks by name:** at least the directory recheck, for an account with no directory
    id and no federated link.

  Federation still ships off. (`BACKLOG #2027`, ADR 0184)
- **An expiring temporary password now reminds its holder and the administrator who issued it.**
  Before, only the operator heard, through the `initial_credential_expiring` `[alerts]` event. That
  event is unchanged. With it, the holder gets a `temporary_credential_expiring` security notice that
  states the deadline, and the issuing administrator gets `temporary_credential_expiring_issuer`,
  which names the account and the deadline. Each goes to that person's own notification address,
  once per credential per engine process, and each is audited with its recipient as the actor. The
  engine finds the issuer from the audit row the create or reset wrote. When those rows do not name
  exactly one administrator who is still enabled and still holds `users:manage`, the issuer is
  skipped and an INFO line says why. Neither notice carries the password. (`BACKLOG #2007`, ASVS
  6.4.5)
- **A directory account is now told when the directory renames it.** When a directory sign-in or
  the directory session reconciler copies a new name onto the account, the engine sends a new
  `username_changed` security notice to the account's notification address. It names the old and
  the new username and says the change came from the directory. It is sent only when the new name
  was written: a rename refused because another account holds the name sends none. The
  `auth.ad_username_refreshed` audit row is unchanged. (`BACKLOG #2017`, ASVS 6.3.7)
- **`provision-admin` now tells the holder of an account it takes over.** With no enabled
  Administrator, the command can take over an enabled local account that holds no roles. It sets a
  new password, grants Administrator, and moves the notification address when `--email` is given.
  It used to tell nobody. It now sends a `first_administrator_takeover` notice to the address the
  account held before. It uses the notifier `serve` wires, from the same settings. It sends nothing
  when the account had no address or no channel can be built. It also sends nothing over an SMTP hop
  that does not authenticate the relay, unless that hop is acknowledged. The
  `auth.first_administrator_provisioned` audit row gains `holder_notice`, and `--json` output
  carries it too. The values are `dispatched`, `no_prior_address`, `no_channel`, or null on a fresh
  create. The command now warns when a taken-over account keeps its earlier holder's address.
  (`BACKLOG #2019`, ASVS 6.3.7)
- **A caller who knows only a username can no longer keep a TOTP-enrolled local owner out through the
  account lock.** The per-account lockout now keeps **two counters** on all three store backends: a
  sign-in counter for wrong passwords, and a second-step counter for attempts that got exactly one
  factor right. `POST /auth/login` takes an optional `totp_code`, and the console's sign-in form has
  an **Authenticator code** field on every sign-in. A sign-in that carries the password and a TOTP
  code passes the sign-in lock on a local account with TOTP enrolled; on any other account a code
  changes nothing. The engine always checks both factors and answers every refusal the same way, in
  the same padded time. The second-step lock on a local account, and the sign-in lock on a local
  account with TOTP enrolled, now **double per cycle** up to the new `[auth].lockout_max_minutes`
  (default 1440, 24 hours); every other lock keeps `lockout_minutes`. A live lock is never extended.
  A full sign-in resets both counters and both cycle counts. The `ACCOUNT_LOCKED` mail now names the
  lock and its cycle count and is sent at most once per lock kind per account per 24 hours; each
  mail writes an `auth.lock_notice` audit row. `messagefoundry admin-unlock` clears both locks,
  reports both, and keeps the cycle counts unless you pass `--reset-cycles`. The login-time password
  rehash no longer clears any lockout state. The API client's `login` and the harness sign-in take
  the code too. Control 2's global sign-in ceiling can still deny every sign-in, the owner's
  included; see `docs/SECURITY.md`, control 1.
  ([BACKLOG #1131](docs/BACKLOG.md), [ADR 0197](docs/adr/0197-cap-repeated-lock-cycles-on-one-account-without-making-malicious-lockout-cheaper.md), ASVS 6.1.1)
- **A passkey ceremony behind a trusted proxy no longer takes its rp_id from the forwarded Host.**
  A loopback bind with an operator `[api].tls_cert_file` and a set `[api].trusted_proxies` declares
  no TLS terminator, so the engine still let WebAuthn derive the rp_id from the request URL. That
  Host comes through the proxy and a client can set it. Ceremonies in that posture now fail closed
  with the existing notice until `[security].web_console_public_address` is set. With the console
  served, `serve` also warns about that posture, because the `/ui` origin checks still compare
  against the forwarded Host there. A proxy named in neither `trusted_proxies` nor
  `tls_terminated_upstream` is still undetectable in-engine. No config is newly refused at load or
  at start. (`BACKLOG #2116`, ADR 0068 section 7)
- **BREAKING (embedders only): `create_app` and `create_managed_app` no longer trust the request Host
  unless told the bind is loopback.** Both defaulted `webauthn_rp_from_request` to `True`, so code that built the app with
  `trusted_proxies` set and left the flag out took the passkey rp_id from the Host a proxy forwards.
  Left out, the flag now follows the rule `ApiSettings.webauthn_rp_from_request` uses: `True` only
  with `loopback=True` and no `trusted_proxies` or `tls_terminated_upstream`. `serve` is unchanged.
  An embedder that relied on the old default gets passkeys refused. It passes the flag itself, or
  `loopback=True`, which also turns on the console's loopback browser hardening (ADR 0143). The flag
  also drives the console's loopback origin checks (`BACKLOG #2217`), so passing `False` on a direct
  loopback bind refuses `Origin`-only POSTs and the WebSocket cookie path too. (`BACKLOG #2219`)
- **Behind a trusted proxy on a loopback bind, the `/ui` origin checks no longer trust the forwarded
  Host.** In the #2116 posture (a loopback bind, an operator `[api].tls_cert_file`, a set
  `[api].trusted_proxies`, no `[security].web_console_public_address`), the same-origin CSRF check,
  the WebSocket CSWSH check and the CSP-report filter compared a browser `Origin` against the Host
  the proxy forwards, which a client can set. They now match nothing there: an `Origin`-only POST is
  refused, the WebSocket cookie path is refused so pages fall back to polling, and CSP reports warn,
  including the console's own canary. A modern browser's POST still passes on `Sec-Fetch-Site`.
  Setting `web_console_public_address` restores all three. A direct loopback bind keeps the Host
  comparison. So does an off-loopback bind, including one with `trusted_proxies` set: through the
  engine-console seam the console cannot tell that bind from a direct one. No config is newly
  refused at load or at start. (`BACKLOG #2217`, ADR 0068 section 7)
- **A set `[api].trusted_proxies` on a loopback bind now counts as an exposed console.** It declares
  a proxy in front, so the console is off-box, but `serve`'s two console exposure checks read only
  the bind, a declared terminator and the external origin. Now a console left at its default in
  that posture auto-degrades to JSON-only with the ADR 0143 warning, which names `trusted_proxies`.
  An explicit `[security].serve_web_console = true` stays on and now gets the ASVS 8.4.2 pointer,
  and the warning when `[auth].admin_new_ip_step_up` is off. No config is newly refused. The
  refusing arms still key on the narrower `instance_exposed` (BACKLOG #326). (`BACKLOG #2218`,
  ADR 0143)
- **BREAKING: a `tls_ciphers` string that carries an OpenSSL `@` directive is now refused.** This
  covers `[api].tls_ciphers`, `[api].proxy_tls_ciphers`, and the per-connection `tls_ciphers` on the
  MLLP and DICOM listeners and destinations. `@SECLEVEL`, `@STRENGTH` and any other `@` token are
  refused at config load, or when the connection's TLS context is built. Before, a string such as
  `@SECLEVEL=0:ECDHE-ECDSA-AES256-GCM-SHA384` passed every suite check, because a directive names
  no suite. Applied, it dropped the security level from 2 to 0. An MLLP or DICOM destination then
  accepted a server certificate with an RSA-1024 key, and a listener with mTLS accepted a client
  certificate with one. `proxy_tls_ciphers` builds no context; it is refused so a declared proxy
  floor cannot claim level 0. To fix a refused config, remove each directive and list the suite
  names only. Every context that `harden_cipher_suites` checks is now also refused if it runs below
  the build's default security level. That is at least the API listener and the four MLLP and DICOM
  seams. The startup TLS floor probe is not among them; it sets level 0 on purpose and carries no
  data. ([BACKLOG #2106](docs/BACKLOG.md))
- **BREAKING: the OAuth2 client-credentials token endpoint now takes the revocation guard the SMART
  token endpoint has had since `BACKLOG #1498`.** It is the hop that carries the `client_secret`.
  On an enforcing PHI instance, an `https` token endpoint off loopback is refused at construction
  unless a CRL reaches that hop, or the connection sets `tls_revocation_attested` with a reason.
  `MEFOR_TLS_REVOCATION_ATTESTED` does not clear it there. A non-enforcing instance warns. The
  token host is often not the data host, so the destination's own guard never covered it.
  **Migration:** load a `[tls].crl_file` that covers the token host, or declare
  `tls_revocation_attested` on the connection. (ADR 0173 section 4.3, ASVS 12.1.4,
  `BACKLOG #2112`)
- **BREAKING: a federated link on an account with no directory id no longer signs anyone in.** The
  link-time refusal further down this section (`BACKLOG #1143` slice C) stops new links on such an
  account. This closes the ones made before it.
  A federated sign-in whose `(issuer, sub)` selects an account with no `directory_object_id` is now
  refused before the directory is asked. The login page shows the generic failure, and the
  `auth.login_failed` audit row carries `directory_object_id_missing`. The directory recheck no
  longer asks about such an account by its username either. It skips it and writes one
  `auth.ad_reconcile_binding_unkeyed` row with the same reason, once per account per process. That
  is a new audit action, separate from the outage's `auth.ad_reconcile_skipped`, because it is not
  benign. A Windows SSO sign-in to such an account is refused as well, by the directory-id
  entry at the top of this section; before it, that sign-in found the account by its username.
  - **Why.** The username is the only key such an account has. A directory can give a freed
    username to a new person, and the linked account would then take that person's groups (ADR
    0184 AC-5).
  - **The cost.** The recheck no longer ends that account's sessions when the directory disables
    or demotes it; they end at their own expiry. The fix is to remove the link with
    `DELETE /users/{user_id}/federated-identity`. The account is then an ordinary directory
    account and the recheck covers it again. The link is never removed automatically.

  Federation still ships off. (`BACKLOG #2027`, ADR 0184)
- **A connection can now attest its hop secure, and the attestation is reported.** `inbound()`,
  `outbound()`, `FhirLookup()`, `DatabaseLookup()` and `DatabaseRef()` take `tls_hop_attested` with a
  mandatory `tls_hop_attested_reason`. So do `connections.toml` inbound and outbound tables, as
  top-level keys. `messagefoundry check` lists every attested hop on a `tls-hop-attested` line, and
  `GET /security/posture` names them in a `tls_hop_attested` loosening. Before this, no factory took
  the flag, but the engine read it straight out of a connection's transport settings. A config module
  could write it there and pass the enforcing cleartext-bind refusal unreported. Those settings keys
  are now refused at load, naming the supported surface. Owner ruling 2026-09-24; registry entry in
  `docs/SECURITY-LOOSENING.md`.
- **BREAKING: `zip_decompress` now refuses any bytes before or after the archive.** Stdlib
  `zipfile` finds the archive's end record by scanning back from the end of the input, and skips
  anything in front of the archive as prepended data. So an archive with up to about 64 KiB of extra
  bytes after it, or with any bytes before it, opened and read normally, and those bytes were dropped
  without a word. Two archives joined end to end returned only the second one's members. On first
  deployment, a Handler unpacking an untrusted archive would have taken those members and never
  learned that anything else was there. Now bytes outside the archive raise `CompressionError`, the
  same rule `deflate_decompress` follows. That includes a self-extracting archive's stub, so a
  Handler must strip the stub first. An archive comment is part of the archive and is still
  accepted. A comment shorter than its end record declares is refused as truncated. Bytes hidden
  between two members are still not checked. ([BACKLOG #1976](docs/BACKLOG.md))
- **Startup attestation now checks the web console, not just the engine.** The console ships as its
  own wheel, `messagefoundry-webconsole`, and runs inside the engine process. Attestation compared
  only the engine wheel's files, so a console file edited, added or deleted in place went unseen.
  When the engine has loaded the console, it now checks every console file against the console
  wheel's own `RECORD`, under the same `[integrity]` rules. A console the engine has not loaded is
  skipped. The engine's own operator-facing messages are unchanged. Subjects and details are in
  [CONFIGURATION.md](docs/CONFIGURATION.md) under `[integrity]`. (`BACKLOG #1802`)
- **BREAKING: a CRL file can no longer add trust anchors.** Each CRL setting loaded its file as
  a CA file, so any certificate in it became a trusted CA for the hop. That CA skipped the hop's
  pin and permission checks. It covers at least `[api].tls_client_crl_file`, an inbound
  connection's `tls_crl_file`, `[tls].crl_file`, `[logging].forward_tls_crl_file`,
  `[auth].oidc_tls_crl_file` and `[store].ssl_crl_file`. The engine now refuses to build the hop
  when its CRL file carries a certificate not already in the hop's trust store. A file holding a
  CA already loaded for that hop, plus that CA's CRL, still loads. A bare CRL always does, so
  give each CRL setting a bare CRL. The inbound revocation refusal no longer tells an operator to
  put the CA in the CRL file. ([BACKLOG #1890](docs/BACKLOG.md))
- **BREAKING: under `enforce`, a trust anchor whose permissions or path the engine cannot read now
  refuses to start, unless its SHA-256 pin matches.** This covers `[auth].oidc_tls_ca_cert_file`,
  `[auth].ad_tls_ca_cert_file`, `[api].tls_client_ca_file` and, new in this release, the mTLS CA
  of every inbound connection. Before, an unreadable ACL or path only wrote an
  `acl_indeterminate` or `path_indeterminate` row and a warning. Now, under the default
  `[security].enforcement = enforce`, the engine refuses. The message names what it could not
  read, the anchor's SHA-256, and both fixes. **The escape is the pin:** set the anchor's pin to
  its SHA-256, after checking it is the CA you mean to trust. The engine loads the exact bytes it
  hashed, so a matching pin rules out a swapped file. It then starts with a warning, and the audit
  row carries `"pinned": true`. At `warn`, the engine starts with a warning, as before. A pin does
  not excuse an anchor that another account CAN replace; that still refuses. **The AD anchor has
  no pin escape:** `ldap3` reads `[auth].ad_tls_ca_cert_file` by path on every bind, so its pin
  cannot vouch for the bytes loaded. An AD anchor the engine cannot judge must move. **At least these
  placements started under 0.4.0 and now refuse under `enforce` with no pin:**
  - on Windows, an anchor under `C:\Windows\Temp` when the engine's account cannot read that
    folder's permissions. Measured on one Windows 11 host, as a non-elevated user;
  - an anchor on a network share, a mapped drive, or a FAT or exFAT volume;
  - on Linux, an anchor on a mount other than ext2/3/4, xfs, btrfs, tmpfs or overlay, such as NFS,
    a FUSE mount, or a Docker Desktop bind mount;
  - a path the check cannot finish: a link loop, an alternate data stream, or a folder it cannot
    read;
  - on Windows, an anchor whose `icacls` output is empty, cannot be run, or grants write to a group
    name the engine does not know, such as a localized `Everyone`.

  **Migration:** move the anchor into a folder the engine can read and only administrators and the
  engine's account can change. On Windows that is the engine's data folder under `C:\ProgramData`.
  On POSIX it is a root-owned `755` folder such as `/etc/messagefoundry/`. Both pass with no pin.
  Or set the pin: `[auth].oidc_tls_ca_cert_pin`, `[api].tls_client_ca_pin`, or the new
  `tls_ca_pin` on the connection. For the AD anchor, only the move works.
  ([BACKLOG #1142](docs/BACKLOG.md))
- **BREAKING: the mTLS CA of every inbound MLLP, HTTP and DICOM connection now gets the same
  checks as the auth anchors.** This is any inbound connection with `tls=True` and a
  `tls_ca_file`, which makes it require a client certificate. For the DICOM listener that CA is
  the whole peer authentication decision. Before, the engine read the file by path and checked
  nothing. Now each gets the SHA-256 pin, the ACL check and the path check, when the connection is
  built and at every config reload. The listener then loads the bytes the check read, never a
  second read of the file. The new optional `tls_ca_pin` on `MLLP(...)`, `Http(...)` and
  `DICOM(...)` is that CA's SHA-256; a pin that does not match always refuses. Each check writes
  its `auth.trust_anchor` rows under the label `inbound:<connection name>`. **These started under
  0.4.0 and now refuse under `enforce`:** an inbound CA another account can replace, as the
  directory-arm entry below lists, and an inbound CA the engine cannot judge, as the entry above
  lists. An inbound CA with no PEM block, or with a `TRUSTED CERTIFICATE` block, refuses at both
  dials. `tls_ca_pin` set on an outbound connection, or on one without `tls` and `tls_ca_file`,
  refuses, because nothing would check it. A pin that is set but empty or whitespace also
  refuses, and the message names the setting. That covers `tls_ca_pin`,
  `[api].tls_client_ca_pin`, `[auth].oidc_tls_ca_cert_pin` and `[auth].ad_tls_ca_cert_pin`, for
  example when an `env()` value or an environment variable is set to nothing. Leave the pin out
  for no pin. The connection test (`POST /connections/{name}/test`) now builds a connector under
  the same enforcement dial as the live build. So under `warn` it no longer fails a CA the
  listener loads. For an outbound connection, the test now applies the same `enforce` clamp and
  cleartext guards as the live build, so a hop the live build refuses now fails the test too. A
  refused CA answers the test with `trust anchor refused; see the server log`. The path and
  SHA-256 go to the log, not to the caller or the audit row. Not covered: the CAs of outbound connections, and an inbound `tls_crl_file`, which is still
  read by path. A certificate inside it was trusted unchecked until BACKLOG #1890, later in this release.
  ([BACKLOG #1142](docs/BACKLOG.md))
- **A config reload now refuses a trust anchor that the next start would refuse.** The reload
  check ran the pin, ACL and path checks, but not the check that the file holds a loadable PEM
  block. So a reload accepted an anchor with no PEM block, or a `TRUSTED CERTIFICATE` block, and
  the next start refused it. The reload now applies every check and writes a `pem_refused` row.
  The AD anchor is the exception: `ldap3` loads a `TRUSTED CERTIFICATE` block, so the reload does
  not refuse one there either.
  ([BACKLOG #1142](docs/BACKLOG.md))
- **BREAKING: a Windows SSO (Kerberos) sign-in through `POST /auth/negotiate` no longer opens a
  step-up window.** Now no directory sign-in opens it: Kerberos by either route, and the federated
  (OIDC) callback, which already did not. Local password sign-in is unchanged.
  (`BACKLOG #1144`, step 5)
  - **What it was.** The engine stamped the new session as freshly re-verified, so its own sign-in
    stamp passed the step-up check for `[auth].step_up_max_age_seconds` (300 seconds by default).
    Nothing checked with the directory again. The console's `GET /ui/sso` never opened the window,
    so one sign-in method had two postures.
  - **Who it reached.** An account with no engine second factor. With `[security].require_mfa`
    off, it owed no factor. A bearer client could then run the step-up-gated actions that use the
    session window on the ticket alone, such as purge, export, replay, config deploy and user admin.
  - **With `require_mfa` on, it reached further than it looked.** The session owed a factor first,
    so the window reached only the routes that skip that gate, and only with
    `[auth].require_action_step_up` off: at least factor enrollment and session termination. But
    enrollment let the session bind its own TOTP and clear the MFA gate with it. The seeded window
    then covered every window-gated action until it closed.
  - **Accounts that hold an engine factor see no change.** The session meets `403` with
    `X-MFA-Required: 1` first, as before. A TOTP or recovery code sent to `POST /auth/mfa-verify`
    opens the window. That route takes no passkey.
  - **Accounts with no engine factor now step up.** On the paths above, the first step-up-gated
    action returns `403` with `X-Step-Up-Required: 1`. The client answers with `POST /me/reauth` and
    the account's directory password, which the engine checks by a live bind.
  - **A session from `POST /auth/negotiate` on an account with no engine factor and no password the
    engine can bind with cannot step up.** A smart-card-only or passwordless AD account is one. ADR
    0068 accepted the same limit for `GET /ui/sso`. An engine TOTP opens the session window at the
    MFA gate, but a route that needs an action-bound proof still needs a bindable password. No
    shipped client calls `POST /auth/negotiate`.
  - `AuthService.authenticate_kerberos` and `AuthService.authenticate_oidc` no longer take a
    `seed_reauth` argument, so no caller can open the window at sign-in. The web console seam moved
    with it.
- **BREAKING: the OIDC and API client-CA trust anchors now load the bytes their check read, not a
  second read of the file.** `[auth].oidc_tls_ca_cert_file` and `[api].tls_client_ca_file` were
  checked once, for the SHA-256 pin, the ACL and the path, and then opened again by path. A file
  swapped between the two reads was trusted unchecked, under a pin that had matched. Both now load
  the checked bytes as `cadata=`. Measured on Windows, CPython 3.14.6 with OpenSSL 3.5.7, over a
  localhost socket: for a valid PEM, `cadata=` and `cafile=` verify the same CA, refuse the same
  wrong one, and each load exactly one anchor, on the client side and the server side. Non-ASCII
  text outside the PEM blocks still loads, and a UTF-8 byte-order mark still loads where OpenSSL
  reads one: at the start of the file, and straight after a block. **At least these anchors loaded under 0.4.0 and now refuse or change:**
  - an anchor holding a `TRUSTED CERTIFICATE` block, as `openssl x509 -trustout` writes, refuses at
    startup. Re-export each certificate in it as a plain `CERTIFICATE` block. `openssl x509 -in
    <one cert> -out <plain.pem>` converts one certificate per run;
  - a CRL inside the anchor file is no longer loaded. A CRL reaches these contexts only through
    `[auth].oidc_tls_crl_file` or `[api].tls_client_crl_file`. With revocation checking on, an
    issuer whose CRL sat only in the anchor file now fails every handshake with `unable to get
    certificate CRL`. Put that CRL, and no certificate, in the CRL file. The CRL file is still read
    by path, and a certificate in it is trusted with no pin, ACL or path check;
  - an anchor file that holds a CRL and no certificate refuses at startup. It never verified a
    handshake.

  `verify --section federation` no longer reports the `fed.idp_tls` row as PASS with no anchor set.
  The IdP hop then trusts every root in the OS trust store, so the row is MANUAL. With an anchor
  set, the row passes the pin, the CRL file and the `[security].enforcement` dial the engine uses,
  and it prints the ACL and path verdict. It names the account that ran the check, because that is
  not the service account. The AD anchor, `[auth].ad_tls_ca_cert_file`, still loads by path.
  ([BACKLOG #1142](docs/BACKLOG.md))
- **BREAKING: a federated (OIDC) sign-in no longer links itself to an account. An administrator
  links it first, through the API.** The engine now picks the account by the identity provider's
  verified issuer and `sub`, before it reads any username. Before, it picked the account by the
  username the token claimed. On that account's first federated sign-in it then linked whatever
  `sub` arrived. So a token that claimed the name of a directory account that had never signed in
  this way could take over that account and its roles. Now a sign-in whose `sub` is linked to no
  account is refused and links nothing. Its audit row names the issuer and `sub` that arrived, so
  an administrator can link it, and is filed under `<oidc>` rather than the name the token claimed.
  The refusal reason is `federated_subject_not_bound`. The web
  console's login page tells the person to ask an administrator. Roles come from the directory
  entry of the linked account, never from the name in the token. A link on a local (non-directory)
  account is refused as `local_account_conflict`. The refusal `federated_subject_conflict` is no
  longer emitted. **What an operator must do before turning on `[auth].oidc_enabled`:** link each
  account with `PUT /users/{user_id}/federated-identity` and a body of `{"subject": "<the IdP
  sub>"}`. The issuer is always `[auth].oidc_issuer`, which must be set. The account must already
  exist as a directory account. A Windows SSO (Kerberos) sign-in creates one, and so does an
  administrator's `POST /users/directory`, which needs no sign-in (`BACKLOG #2021`, its own entry).
  The same route with a new `sub` moves the link and signs the account out. `DELETE` on the same
  path removes the link and signs the account out. Both routes need `users:manage` and a fresh
  re-authentication for the action `admin_federated_identity`. Each write leaves an audit row
  (`auth.federated_subject_bound`, `auth.federated_subject_rebound` or
  `auth.federated_subject_unbound`) naming the administrator. Linking and unlinking each notify
  the account holder; unlinking sends the new notice `federated_identity_unbound`. An
  administrator cannot change their own link. The web console has a screen for this too; see the
  next entry. Federation still ships off. (`BACKLOG #1143`, `BACKLOG #295`, ADR 0184)
- **The web console can now link, relink and unlink a federated (OIDC) identity.** A user's page
  shows the account's link, its issuer and `sub`, or says it has none. The new screen
  `/ui/users/{user_id}/federated-identity` links the account to a `sub`, or moves the link to a
  new one. Unlinking goes through a confirm page that states the consequence first. Each change
  calls the same code as `PUT` and `DELETE /users/{user_id}/federated-identity`, so the checks,
  the audit rows and the notices to the holder are the same. Each needs `users:manage` and a fresh
  re-authentication for the action `admin_federated_identity`, as the API does. A recent sign-in
  is not enough, unless the site set `[auth].require_action_step_up = false`, which the API honours
  the same way. An administrator cannot change their own link here either. Each form posts back
  the link its page showed, and the console refuses the submit when the stored link has changed
  since. That check runs before the engine's handler and does not serialise against a concurrent
  write. So a stale page can still replace or remove a link another administrator set at the same
  moment. A later slice would move the check into the service's bind and unbind. The screen
  offers no Link form on a local account or when `[auth].oidc_issuer` is unset, and shows the engine's refusals in words. The engine gains the `AuthService.oidc_issuer`
  property and a `FederatedIdentityView` model the console renders; no JSON route returns it, and
  `GET /users` is unchanged. (`BACKLOG #1143`, `BACKLOG #295`, ADR 0184 slice B)
- **BREAKING: a federated (OIDC) identity now links only to a directory account that carries its
  immutable directory id.** `PUT /users/{user_id}/federated-identity` and the console's Link refuse
  an account with no `directory_object_id`, the normalised `objectGUID` a Windows SSO sign-in
  writes when it creates the account. The API answers `400` with a detail that starts
  `directory_object_id_missing:`. The console's federated-identity screen offers no Link form on
  such an account and says why, and a hand-made POST gets the same words. The refusal writes an
  `auth.federated_bind_refused` audit row naming the administrator. It links nothing, signs nobody
  out and sends no notice. `FederatedIdentityView` gains `has_directory_object_id`, so the web
  console seam moved.
  - **Why.** The engine finds an account with no id by its username, at sign-in and on each
    directory recheck. A directory can give a freed username to a new person, and a linked
    account would then take that person's groups. Now every new link sits on an account the engine
    finds by its `objectGUID` (ADR 0184 AC-5).
  - **Which accounts now refuse.** A directory account created by a Windows SSO sign-in through a
    directory that returned no readable `objectGUID`. Before this change it could be linked.
  - **The cost.** A site whose directory returns no readable `objectGUID` can link nobody, so
    nobody there can sign in through the identity provider. Windows SSO signs nobody in there
    either, since the `BACKLOG #2027` directory-id entry in this section. (This line said
    directory sign-in still works there, which stopped being true when that entry landed.)
  - **An account never gains an id after it is created.** To link one, make the directory return
    `objectGUID`, turn Windows SSO on if it is off, delete the account, and have the person sign in
    once with Windows SSO. Nothing else creates a directory account. The new account has a new
    `user_id`, so the old one's uploads, upload quota and saved searches do not follow.
  - **A link made before this change on such an account is left in place.** It can still be
    removed, and it cannot be moved to another `sub`. This change added no sign-in refusal for it;
    the `BACKLOG #2027` federated-link entry in this section does. On a directory that now
    returns `objectGUID`, its Windows SSO sign-in is refused as `directory_identity_conflict`, as
    it was before this change. Its federated sign-in is now refused as
    `directory_object_id_missing`, which that entry checks first.

  Federation still ships off. (`BACKLOG #1143`, slice C, ADR 0184)
- **BREAKING: an administrator's save no longer moves the notification address as a side effect.**
  `PATCH /users/{id}` copied any non-blank `email` into `users.notify_email`, and sent no notice
  unless the profile email changed. The route fills an omitted `email` from the stored profile, and
  the web console's user form posts it back on every save. So a display-name edit or a disable
  copied the profile address into the notification address. On a directory account that address is
  the directory's `mail`, so the save did the directory repoint ADR 0182 blocks. On an account with
  no notification address it filled one from the directory. Now `email` sets the profile address
  only. A new `notify_email` field on `PATCH /users/{id}` is the one way an administrator moves
  the notification address. Omitted, it leaves the address as it is. Sending the stored address
  back changes nothing. A new value must be one plain mailbox, and `null` or a blank value is
  refused with `400`, because the address can be changed but not cleared. A move writes a
  `user.notify_email_changed` audit row that holds no address. It sends an `email_changed` notice
  to the old address, which names the new one, or a `notify_email_set` notice to the new address
  when there was none. Both say an administrator made the change. The console's user page has a
  Notification address field for it. **What changes for a client:** a `PATCH` that sets `email` to
  repoint notices now moves only the profile address. Send `notify_email` too. (`BACKLOG #1139`,
  ADR 0182 Amendment A)
- **BREAKING: an account with no notification address must set one at sign-in, whenever this
  instance sends security notices.** A security notice goes to the account's engine-owned address,
  `users.notify_email`. An account without one was told nothing about a password reset or any other
  change to how it signs in. At least three paths create such an account: a user created with no
  email, `provision-admin` without `--email`, and a directory sign-in where the directory returns no
  `mail`. Now, while `[auth].notify_security_events` is on and an `[alerts]` SMTP
  relay is configured, that account is confined at sign-in. The JSON API answers other routes with
  `403` `notification address required` and `X-Notify-Email-Required: 1`. The web console sends other
  pages to `/ui/account/notify-address`. `POST /me/notify-email` sets the address, which must read as one
  plain mailbox. It only fills a missing one and answers `409` when one is set, so an administrator still changes an existing
  address. It stays behind the second-factor gate, so a session that has proven only the password
  cannot choose the address. Setting it writes `auth.notify_email_set` and sends a `notify_email_set`
  notice to the new address. A site with no mail relay is not confined. **Who is confined:** every
  existing account with no `notify_email`, at its next sign-in on an instance that sends notices. That
  includes API clients and scripts that sign in with a password. Each one gets the `403` until the
  address is set. (`BACKLOG #1139`)
- **Removing a passkey now always sends a notice.** Removing one passkey while another factor remained
  wrote an audit row and sent nothing. It now sends `mfa_credential_removed`. Removing the last factor
  still sends `mfa_disabled`. (`BACKLOG #1139`)
- **A dropped security notice is now logged.** With notices on and no SMTP relay configured, the engine
  dropped every notice without a word. Each drop now logs a warning naming the event type and the
  username, never the event detail. (`BACKLOG #1139`)
- **The web console's notification-address page now suggests the address already on the account.**
  At `/ui/account/notify-address`, the input starts with the account's profile address,
  `users.email`, when it passes the same checks as a submitted address. On a directory account that
  is the last `mail` the directory supplied. A line under the input says where it came from and
  asks the holder to change it if it is not theirs. A pre-filled input is not focused on load, so a
  stray Enter does not accept it. Opening the page writes nothing. The address becomes `notify_email` only when the holder submits
  the form, through the same check, audit row and notice as before. The directory still never sets
  `notify_email` itself. The API is unchanged and suggests nothing. A client with no browser still
  sets its address with `POST /me/notify-email`, or an administrator sets it. (`BACKLOG #1139`)
- **An approval can no longer be granted faster than a person could read it.** A new setting,
  `[approvals].min_dwell_seconds`, sets the youngest age at which a pending request may be
  approved. It defaults to 2.0 seconds, which is provisional and derived from the keystroke-level
  model; `docs/SECURITY.md` states the derivation. `ApprovalGate.approve()` refuses a younger
  request with `409`, stating the remaining wait, and writes an `approval.too_early` audit row. The
  request stays pending, and nothing retries it. The check sits inside `approve()`, so every release
  path meets it. `0` means no floor. `[approvals].expiry_hours` now also refuses NaN, infinity and
  overflow, and with dual control on, startup refuses a floor at or past the expiry. Dual control
  (`[approvals].enabled`) still ships off. ([BACKLOG #287](docs/BACKLOG.md))
- **A failed step-up re-auth or password change now counts toward the account lockout, and each
  session gets at most `lockout_threshold` of them.** In 0.4.0, `POST /me/reauth`, the web console's
  `POST /ui/reauth` and `POST /me/password` checked a password but counted no failure. So someone
  holding a stolen session could keep guessing, bounded only by the per-actor ceremony budget. A
  failure now counts on the account's sign-in counter, so it can lock sign-in and raise the lockout
  notice. It is also charged to the session, and the failure that reaches `lockout_threshold` (5 by
  default) revokes that session, so a stolen session gets 5 password guesses in total. The account
  lock does not refuse a live session's password re-proofs, so an attacker who locks the account from
  the sign-in page cannot take step-up or the password change away from the owner's live sessions,
  once those sessions have met their second factor. Wrong TOTP or recovery codes still count on the
  account alone. A rejected
  directory (AD) re-bind counts too. The engine never writes a lock to the directory, but each
  rejected re-bind still reaches the domain controller, so the domain's own lockout policy can still
  lock the domain account. A directory the engine cannot reach, or one with no such account, is not
  counted. The per-session count lives in each engine process: a restart resets it, and each engine
  shard serving its own API port keeps its own, so there the cap is per process rather than in
  total. The crossing attempt writes `auth.account_locked`. A
  re-auth that clears a run of three or more failures writes `auth.login_after_failures`. A failed
  current-password check at `POST /me/password` is now audited as `auth.password_change_failed`.
  (`BACKLOG #1138`)
- **BREAKING: the `Http()` inbound listener now refuses any `Transfer-Encoding`, not only
  `chunked`.** The listener decodes no transfer coding. In 0.4.0 it refused the header only when its
  whole value was `chunked`. A coding list such as `gzip, chunked` got through, and so did `chunked,`
  and `identity`. The listener then read the body raw. If the sender closed its side, that body was
  stored as the message. A `GET` or `HEAD` carrying `Transfer-Encoding` was also accepted. Now the
  listener refuses any `Transfer-Encoding` with `400`, on every method. It refuses before it reads a
  body byte. It also refuses a header named `Transfer_Encoding` or `Content_Length`. A front end that
  swaps `_` for `-` would read either one as real framing. A request with both `Transfer-Encoding`
  and `Content-Length` was already refused and still is. Each refusal is logged as a `framing_error`
  connection event and writes no ingress row. **A deploying sender that sets `Transfer-Encoding`
  would be refused**, and must send a `Content-Length` instead.
  ([BACKLOG #1125](docs/BACKLOG.md), [BACKLOG #1913](docs/BACKLOG.md))
- **BREAKING: the `Http()` inbound listener reads request framing more strictly.** A `POST`, `PUT`
  or `PATCH` with no `Content-Length` is now refused with `411`. In 0.4.0 the listener read such a
  request to the end of the connection and stored what it got. A non-zero `Content-Length` is now
  refused with `400` on every method other than `POST`, `PUT` and `PATCH`. A lowercase method such
  as `post` is no longer treated as `POST`. The header grammar is stricter too. It refuses with `400`
  at least these shapes:
  - a bare LF or CR;
  - a folded header line;
  - space before the colon;
  - a `Content-Length` such as `+3` or `1_0`;
  - any HTTP version other than 1.x.

  **A deploying sender relying on any of these would be refused.** ([BACKLOG #1125](docs/BACKLOG.md))
- **BREAKING — every TLS context the engine builds now defaults to the approved AEAD TLS 1.2
  suites, MLLP and DICOM included, and the engine's own signing key must be RSA-3072 or larger.**
  A CBC-only TLS 1.2 peer that connected on 0.4.0 would now fail the handshake. For MLLP and DICOM
  the owner ruled on 2026-09-23 to drop the six CBC-SHA2 suites with no peer census. There is no
  override setting: a legacy CBC-only peer is served only by a reviewed code change to
  `_APPROVED_TLS_SUITES`. TLS 1.3 is unaffected, and the IDE client pins the same suite list.
  [ADR 0188](docs/adr/0188-per-connection-tls-ciphers-on-the-mllp-and-dicom-connectors.md) is
  amended with a per-hop table. Separately, `transports/signing.py` now refuses an RSA signing key
  below 3072 bits, for outbound detached-JWS signing and the SMART `client_assertion`; 0.4.0
  accepted 2048. Counterparty keys, such as an IdP's JWKS key and the `Direct()` signer, keep the
  2048-bit floor. **Migration:** generate an RSA key of at least 3072 bits, or an EC key for
  ES256 / ES384, and register its public half with the counterparty.
  ([BACKLOG #300](docs/BACKLOG.md))
- **BREAKING: the AD LDAPS bind and the three Vault clients now offer only the approved AEAD TLS
  1.2 suites too.** Until now the library building each context chose its list, CBC-SHA2 included.
  The owner ruled on 2026-09-27 to narrow them like every engine-built context. An older AD domain
  controller that offers none of the approved suites would fail to bind, and a Vault server the same
  way. `assert_ldap3_tls_suites` and `assert_hvac_tls_suites` now hold each context to the approved
  list, and each TLS handshake with Vault runs on a context the assertion checked. Peer
  verification is unchanged. Still not narrowed, at least: the ODBC drivers and the TLS hop to an
  https proxy. The tray's health probe was on this list until the entry below. So was asyncpg on the
  default Postgres store path, until the store entry under Changed. ([BACKLOG #300](docs/BACKLOG.md))
- **The Windows tray's health probe now offers only the approved AEAD TLS 1.2 suites.** Both of
  its verifying contexts, the pinned engine certificate and the OS trust store, carry a copy of the
  engine's list, which a test holds equal to it. The engine's API listener offers exactly these by
  default, so a tray probing a stock engine is unaffected. The TLS 1.3 list is narrowed only where
  the interpreter allows it, as for the engine; CPython 3.14 does not, so there the probe still
  offers AES-128 at TLS 1.3. ([BACKLOG #300](docs/BACKLOG.md))
- **BREAKING: the default TLS suites no longer include AES-128.** The engine, the apiclient and
  the IDE client drop `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES128-GCM-SHA256` and
  `DHE-RSA-AES128-GCM-SHA256`. Five TLS 1.2 suites remain: AES-256-GCM and ChaCha20. A TLS 1.2 peer
  that offers only AES-128-GCM now fails the handshake. At TLS 1.3, `TLS_AES_128_GCM_SHA256` stays
  on Python 3.14, a gap the owner's 2026-09-26 ruling records rather than overrides; the engine
  drops it where Python can. The IDE client drops it on a remote extension host, and keeps it in
  the desktop app, whose runtime ignores TLS 1.3 suite names. A `tls_ciphers` or `[api].tls_ciphers` string
  that reaches an AES-128 suite now refuses at load. That includes `ECDHE+AESGCM:ECDHE+CHACHA20`,
  the string the 0.4.0 migration note below recommends. **Migration:** use
  `ECDHE+AESGCM+AES256:ECDHE+CHACHA20`, or leave `tls_ciphers` unset. There is no setting that
  re-admits AES-128; a legacy peer that needs it is served by a reviewed code change that widens
  the allow-list. The ADR 0188 amendment of 2026-09-26 records the ruling.
  ([BACKLOG #2042](docs/BACKLOG.md))
- **BREAKING: a trust anchor that another account can replace through its folder now refuses to
  start.** This covers `[auth].oidc_tls_ca_cert_file`, `[auth].ad_tls_ca_cert_file` and
  `[api].tls_client_ca_file`. 0.4.0 checked only the anchor file's own permissions. An account with
  delete-child on the anchor's folder could delete it and plant its own CA, and the engine trusted
  the copy. The engine now also checks the path. It reads every folder from the drive root or `/`
  down to the anchor, each link on the way, and the file itself. On Windows it reads each owner and
  DACL by SID, in process. On POSIX it reads each owner and mode. Under the default
  `[security].enforcement = enforce`, an object an untrusted account can delete, rename,
  re-permission or own refuses. At `warn` the engine starts and writes a `path_insecure` row under
  `auth.trust_anchor`. The message names each object, the account and the right, and gives the
  `icacls` or `chown` and `chmod` commands that fix it. On a folder, only removing or renaming an
  entry counts. Adding files does not, so `C:\`, `C:\ProgramData` and a new folder under it pass as
  Windows ships them. The trusted accounts include at least SYSTEM, Administrators,
  TrustedInstaller, direct members of local Administrators, and the account the check runs as.
  LocalService and NetworkService are not trusted as the engine's own. An owner is also trusted
  when its SID ends in a well-known admin RID (500, 512, 518 or 519) in any domain, as the config
  guard trusts it. On POSIX, root and the engine's uid are trusted, and only root when the engine
  runs as root. The verdict depends on the account the check runs as, so run
  `mefor verify federation` as the service account. Some paths the engine cannot judge: an unreadable folder, a network
  share or mapped drive, a FAT volume, or a Linux mount other than ext2/3/4, xfs, btrfs, tmpfs or
  overlay. They write a `path_indeterminate` row. Under `enforce` they refuse unless the pin
  matches, as the first Security entry above says; at `warn` the engine starts with a warning. The
  file check still runs beside the path check. **These placements, at least, started under 0.4.0
  and now refuse:**
  - a Windows anchor whose own permissions are locked, in a new folder under `C:\Users\Public`;
  - an anchor under a folder where a named account or local group can delete or rename entries.
    0.4.0 caught only broad groups. One Windows 11 host's `%TEMP%` refuses this way;
  - an anchor whose file or any folder above it is owned by an account that is neither an
    administrator nor the engine's own, such as a folder a standard user made under
    `C:\ProgramData`;
  - on POSIX, an anchor or any folder above it owned by a uid other than root or the engine's;
  - on POSIX, a group- or world-writable folder in the path, unless it is sticky and the entry
    below it belongs to root or the engine. A link to a good bundle, kept in such a folder, refuses
    too.

  **Migration:** keep each anchor in a folder that only administrators and the engine's account can
  change. On Windows that is the engine's data folder under `C:\ProgramData`. On POSIX it is a
  root-owned `755` folder such as `/etc/messagefoundry/`. The container's `/config`, owned by uid
  10001 as `docker/README.md` requires, passes when it sits on one of the mount types above. A
  Docker Desktop bind mount does not, so there it answers indeterminate, and under `enforce` it
  refuses unless the pin matches.
  ([BACKLOG #1142](docs/BACKLOG.md))
- **BREAKING: an HTTP-family reply is now refused when its header block or its chunked body breaks
  the HTTP/1.1 grammar.** 0.4.0 read most of these as the partner's answer. A REST, SOAP, FHIR or DICOMweb delivery,
  and an OAuth2 or SMART token request, now raises `AmbiguousFramingError`, a transient delivery
  error that is retried and then dead-lettered. A `fhir_lookup` reply raises inside the Handler. The
  OIDC token and JWKS reads refuse the same replies, and that sign-in fails as an unavailable IdP.
  The OIDC token read now also refuses a body shorter than its `Content-Length`, as the connectors
  already did. Newly refused, at least:
  - a header line that is not a field line, such as a line with no colon or a space before the
    colon. 0.4.0 dropped every header after that line. It then framed the body without them. So it
    could return three bytes of raw chunk framing as the answer. Or it could read to close and take
    in a second response as part of the body. This holds under any `Content-Type`. Under
    `multipart/*` or `message/*`, 0.4.0 built the lost lines into MIME parts and read the body
    without them all the same;
  - a header line with no name, a first line that is a continuation, a `From ` line, a field
    name that is not an RFC 9110 token, or a field value holding a control character such as NUL;
  - a chunk-size line that is not plain hex digits, such as `-5`, `1_0`, `+5`, `0x5` or ` 5`
    (whitespace before the size). Whitespace after the size, as in `5 `, is refused too, unless a
    chunk extension follows it. `5 ;ext` still reads, because RFC 9112 allows whitespace before the
    `;`. 0.4.0 parsed these with `int()`. On a negative size it read to the end of the stream, past
    the reply's byte bound, and only then failed;
  - a chunk line ended by a bare LF, or holding a bare CR, and chunk data not followed by CRLF;
  - a trailer line that is not a field line, or more than 100 trailer lines, counting folded
    continuations.

  Chunk extensions, trailer fields (folded or not), upper-case hex and leading zeros still read.
  So does a `multipart/*` reply, such as SOAP with MTOM. A chunked body still reads when its stream
  ends cleanly after the last chunk, or between trailer lines, with no final CRLF. 0.4.0 read that
  too. This check misses a bare CR followed by text that reads as a field line; the next entry
  refuses that shape earlier. The check sees only the header block the HTTP reader parsed, so any
  other lost line that leaves no trace there is missed, at least. Connection probes and the alert webhook discard the body and are not refused. They stop reading at the first bad
  chunk line and log a WARNING. **Migration:** none in configuration. The partner or its proxy must
  send well-formed HTTP/1.1. (ASVS 4.2.1, ASVS 15.2.2, [BACKLOG #1125](docs/BACKLOG.md),
  [BACKLOG #1979](docs/BACKLOG.md))
- **BREAKING: SFTP now offers one cipher, `aes256-gcm@openssh.com`.** 0.4.0 also offered
  `aes128-ctr`, `aes192-ctr`, `aes256-ctr` and `aes128-gcm@openssh.com`. ASVS Appendix C marks
  CTR as disallowed, and AES-128 is withdrawn. The server must also offer an ETM SHA-2 MAC, as in
  0.4.0; `_APPROVED_SFTP_CIPHERS` in `transports/remotefile.py` says why. A server that lacks
  either now fails the handshake with `Incompatible ssh server (no acceptable ciphers)` or `(no
  acceptable macs)`.
  **Migration:** the server owner enables `aes256-gcm@openssh.com` and
  `hmac-sha2-256-etm@openssh.com` or `hmac-sha2-512-etm@openssh.com`. No setting re-admits the
  others. This narrows the 0.4.0 note that SFTP offers "AES-CTR or AES-GCM".
  (`BACKLOG #2041`, `#2044`)
- **BREAKING: the Vault key provider and the `vault_transit` cipher refuse an `aes128-gcm96`
  Transit key.** 0.4.0 accepted it for the KEK, the data key and the audit key. `serve` now
  refuses to start, and the error names the key, its type, the setting that chose it and the
  type to create. Vault cannot change a key's type, and rotating a key keeps its type.
  **Migration:** create an `aes256-gcm96` key and point the setting at it. For the KEK, also
  re-wrap `MEFOR_STORE_VAULT_WRAPPED_DEK` under the new key, or the next start fails on the
  unwrap. A store already encrypted under the old data or audit key would not read under the new
  one, and no command moves Transit ciphertext between keys. This narrows the 0.4.0 advice "an AES or RSA-3072
  Transit key": AES now means `aes256-gcm96`. (`BACKLOG #2043`)
- **BREAKING: an HTTP-family reply whose status line or header block holds a bare CR is now refused
  as its head is read.** A CR not followed by LF split a header line in two. So
  `X-A: a<CR>Content-Length: 5` read as two fields, while a proxy that treats that CR as invalid or
  as a space sees one field and no length. 0.4.0 read the body by the hidden length. The check
  runs on every urllib opener the engine reads a partner reply through: REST, SOAP, FHIR, DICOMweb,
  `fhir_lookup`, the AI endpoint, the OAuth2 and SMART token requests, the OIDC token and JWKS
  reads, and the alert webhook. It raises `MalformedReplyHeadError`, an `AmbiguousFramingError`
  that is also an `http.client.HTTPException`. The OAuth2 and SMART token requests raise it too:
  their shared reader's `HTTPException` arm passes it through rather than retyping it as a plain
  `DeliveryError` (`BACKLOG #2114`). A delivery retries it and then dead-letters it, a
  non-2xx reply included, and an OIDC sign-in fails as an unavailable IdP. Unlike the body checks
  above, this one also fails a connection test (`POST /connections/{name}/test`) and an alert
  webhook send, because the head is refused before any body is read or discarded. A bare CR in the body, and a bare LF line end in
  the head, still read. The Vault and OpenBao clients use `requests` rather than urllib, and run
  the same check on the Vault reply, direct or through an HTTP proxy: the strict `requests` adapter
  of #2053 opens every connection with the same strict response class. Their KV and Transit errors
  name `MalformedReplyHeadError`, and the refused connection is closed rather than pooled
  (`BACKLOG #2123`). On every hop, an HTTP proxy's own reply to `CONNECT` is still read leniently. **Migration:** none in configuration. The partner
  or its proxy must end each head line with CRLF. (ASVS 4.2.1, `BACKLOG #2052`)
- **A reply body with no length, or a length the peer never sends, no longer costs the whole byte
  bound in memory.** The bounded read asked the socket for the bound plus one byte in one call, and
  Python's buffered reader sets aside that much before it learns how much arrives: 16 MiB per reply
  at the default. The engine now reads such a body 1 MiB at a time, so what it holds tracks what the
  peer sent. The bound, the truncation check and the body are unchanged. (ASVS 15.2.2,
  `BACKLOG #2052`)
### Fixed
- **A token endpoint that returns an `access_token` an HTTP header cannot carry now fails that
  mint, instead of dead-lettering every message for up to an hour.** The SMART and OAuth2
  client-credentials providers cached any non-empty string. A token holding a CR, an LF or a
  character outside latin-1 then failed in `http.client` at send time, and at least the REST, SOAP
  and FHIR destinations read that as a permanent `bad-request-value`. The shared token reader now
  refuses any token that is not visible ASCII, as a retryable `DeliveryError` that does not name the
  token. Nothing is cached, so the next attempt mints again. **BREAKING, by design:** a token with a
  space, a tab, another control character or a latin-1 letter used to reach the wire and is now
  refused too, because no RFC 6750 bearer holds one. (`BACKLOG #2114`)
- **The startup ERROR for an unusable bundled breach corpus now says what that corpus refuses.** An
  account that must change its password cannot finish the change, an administrator's reset leaves
  its user stuck the same way, and `provision-admin` cannot create the first administrator. It
  also says how to repair the file, and that turning `password_check_breached` off needs a restart
  (BACKLOG #1886).
- **BREAKING — an HTTP-family reply with ambiguous length framing now fails before its body is
  read.** 0.4.0 let `http.client` pick one reading, which could hand back raw chunk framing or the
  shorter of two lengths as the partner's answer. Refused now, under RFC 9112 section 6, at least:
  `Transfer-Encoding` beside `Content-Length`; a `Content-Length` that is not plain digits, such as
  `+5` or `5, 5`, or two that differ; `Transfer-Encoding` on an HTTP/1.0 reply; a codings list whose
  final coding is not a single `chunked`, including `gzip, chunked`; and `Transfer-Encoding` on a
  204, 304 or 1xx reply. A REST, SOAP, FHIR or DICOMweb delivery, and an OAuth2 or SMART token
  request, raises `AmbiguousFramingError`, a transient delivery error that is retried and then
  dead-lettered. A `fhir_lookup` reply raises inside the Handler. The OIDC token and JWKS reads
  refuse the same replies, and the sign-in that made the read fails as an unavailable IdP.
  Connection probes and the alert webhook discard the body and are not checked. **Migration:** none
  in configuration; the partner or its proxy must frame the reply by one rule. (ASVS 4.2.1,
  [BACKLOG #1125](docs/BACKLOG.md))
- **BREAKING — an AD or OIDC sign-in that matches no scope-mapped group now withdraws the user's
  channel scope, unless an administrator set it.** In 0.4.0 such a sign-in left the stored scope as
  it was. So a user removed from their last scope-mapped group would have kept those channels
  indefinitely. The engine now withdraws that scope to NULL, which denies. It also revokes the
  user's other sessions and writes an `auth.ad_scope_resynced` audit row. That row's `channels` is
  now null on a withdrawal, and a new `withdrawn` key holds the removed scope. The withdrawal is a
  compare-and-set, so a scope written during the sign-in survives. A matching group still
  overwrites any scope, an administrator's included. The scope it writes counts as the directory's
  from then on, even when the value did not change.
  **How the engine tells the two apart:** every scope write records its writer in a new column,
  `users.channel_scope_source` (`'ad'` or `'manual'`), on all three store backends. The column is
  added with no backfill. A scope with no recorded writer counts as the directory's, so it is
  withdrawn too, which fails closed.
  **Who this bites:** every AD account whose scope was set before the upgrade has a NULL source.
  So an administrator's scope on such an account would be withdrawn at the user's next unmatched
  sign-in. A site with no `/ad-group-scope-map` rows is hit hardest: no sign-in ever matches. So
  every `["*"]` or hand-set grant on an AD account would drop to deny at that user's next sign-in.
  **Migration:**
  - Stop every node, upgrade them all, then start. A 0.4.0 node writes a scope without its source,
    so on a shared store it would leave the source stale.
  - The first start on PostgreSQL or SQL Server needs DDL rights, as it did for 0.4.0. The
    PostgreSQL migration revision moves from 3 to 4, and the schema hash moves on both.
  - Before AD users sign in, set again each scope an administrator chose, with
    `PUT /users/{id}/channel-scope`. That records it as `'manual'`, and it revokes that user's
    sessions. Do not re-set a scope the directory granted. It would then survive the user leaving
    the group. If a sign-in withdraws a scope first, the audit row's `withdrawn` key holds it.
  ([BACKLOG #1927](docs/BACKLOG.md))
- **BREAKING: `deflate_decompress` now refuses any bytes after the end of the stream, and no longer
  hangs on them.** Its bounded loop never checked for the end of the stream. Take a stream whose
  output needs more than one 64 KiB round, and add one byte after it. The loop spun forever and the
  ceiling never fired. On first deployment, a Handler inflating an untrusted body would hang its
  transform worker. A shorter stream returned its output and dropped the extra bytes without a
  word. Both now raise `CompressionError`. Stdlib `zlib.decompress` ignores such bytes, so a Handler
  that expects a trailer should strip it first. The loop now feeds its input one 64 KiB window at a
  time, so it runs in linear time, not quadratic. A bomb now stops at the ceiling, not up to one
  window past it. `gzip_decompress` and `zip_decompress` do not use this loop and are unchanged.
  ([BACKLOG #1964](docs/BACKLOG.md))
- **The per-connection revocation attestation can now be set, in both directions (ADR 0173).**
  `tls_revocation_attested` and a mandatory `tls_revocation_attested_reason` are new `inbound()` and
  `outbound()` keywords and top-level `connections.toml` keys. The field sat on the connection models
  with nothing that could set it, and on the inbound side the runner never filled it, so the attested
  branch of the mTLS listener's revocation check could not fire. A flag without a reason fails at load.
  Each time the attestation lets a hop through that an enforcing instance would refuse, the engine logs
  a WARNING naming the hop and the reason. The revocation refusals name this lever again.
- **The per-connection revocation attestation is now reported, like `cleartext_accepted` (ADR 0173).**
  `messagefoundry check` has a `tls-revocation-attested` line naming every attesting connection and
  its reason. `security_loosenings()`, and so `GET /security/posture`, has a `tls_revocation_attested`
  entry. Both walk inbound, outbound and `FhirLookup` connections. Before this, the only record was the
  WARNING logged at construction.
- **BREAKING — sign-in now checks a stored passkey with the same rule as registration.** This
  reverses two promises in the 0.4.0 notes: "Passkeys registered on 0.3.2 still work" and "A
  passkey already registered on another curve still signs in". Neither holds any more. A stored
  RS256 key, a stored ES256 key on P-384 or P-521, or a stored curve encoded as `true` or `1.0`
  is now refused at sign-in. 0.3.2 registered all three, and 0.4.0 still registered the third. The
  refusal is audited as `auth.webauthn_failed`. **A deploying site with such a key would see its
  owner refused at every passkey sign-in; a passkey-only user would stay refused until an admin
  runs `admin_reset_mfa`.** **Migration:** register an ES256 passkey on P-256 or an EdDSA
  passkey, or use TOTP. ([BACKLOG #1166](docs/BACKLOG.md))
- **BREAKING: the Windows trust-anchor ACL check no longer reads what it cannot parse as
  owner-only, and it knows more broad principals.** This is the ACL check on
  `[auth].oidc_tls_ca_cert_file`, `[auth].ad_tls_ca_cert_file` and `[api].tls_client_ca_file`, run
  at startup and on a config deploy that re-checks the anchors. 0.4.0 passed an anchor whose
  `icacls` output was empty or was not `icacls` output. It also passed a write grant to a bare
  name it did not know, such as the German `Jeder` for Everyone, and a line-1 write grant it could
  not split from the echoed path. Those now read as indeterminate. The engine logs a warning,
  writes a new `acl_indeterminate` row under the `auth.trust_anchor` audit action. Under
  `enforce` it then refuses unless the pin matches, as the first Security entry above says; at
  `warn` it starts. 0.4.0 wrote no row for an ACL it could not read.
  Under the default `[security].enforcement = enforce`, the check now refuses a write or DELETE
  grant to broad principals 0.4.0 missed. They include at least `NT AUTHORITY\INTERACTIVE`,
  `SERVICE`, `BATCH`, `NETWORK`, `ANONYMOUS LOGON` and `Local account`, `Guests`, `Domain
  Guests`, a bare `Users`, and an unresolved Domain Users or Domain Guests SID
  (`S-1-5-21-...-513` or `-514`). A DELETE-only grant to any broad principal now refuses too. A
  file created under `C:\Users\Public` inherits modify rights for `INTERACTIVE`, `SERVICE` and
  `BATCH`, so such an anchor started under 0.4.0 and now refuses. At `warn` it starts with an
  `acl_insecure` row. Two cases 0.4.0 refused now pass. Names match whole, so an account such as
  `DESKTOP-A\usersync` no longer reads as `BUILTIN\Users`. A non-ASCII anchor path is now decoded
  in the OEM code page and matched to its echo, so its own characters no longer read as a
  principal. **Migration:** before you upgrade, run `icacls <anchor>` and look for write grants
  to those principals. Copy an anchor out of `C:\Users\Public` into a folder that grants them no
  write, rather than moving it: a move keeps the inherited grants. Or run `icacls <anchor> /reset`
  after the move.
  ([BACKLOG #1142](docs/BACKLOG.md))
### Changed
- **BREAKING — the web console engine UI seam moved, so this engine no longer pairs with web
  console 0.3.0.** Engine 0.4.0 shipped `75c4117d21fd0b98`. The seam moved because the console now
  imports three deadline helpers from `messagefoundry.api.security`, and `UserSummary` gained
  `credential_expires_at` (under Added). A console accepts exactly one seam. The web console 0.3.0
  release, tagged `webconsole-v0.3.0` beside engine 0.4.0, accepts only `75c4117d21fd0b98`. So
  with the console on, this engine refuses to start with that release installed
  (`UiSeamMismatch`). The version number alone does not tell a matching console apart, so check
  the constant. Engine 0.5.0 ships `32ad621e6081555e`, which web console 0.4.0 accepts.
  **Migration:** upgrade the web console to 0.4.0 together with the engine. Or set
  `[security].serve_web_console = false` to run the JSON API alone. (`BACKLOG #1141`)
- **BREAKING — the `403` for a session that must change its password is no longer always the exact
  string `password change required`.** When the engine can state the temporary password's
  deadline, the detail now reads `password change required; the temporary password stops working at
  <time>`. The time is UTC ISO 8601, for example `2026-09-27T14:00:00Z`. A must-change credential
  with no deadline still gets the bare string. The old text stays as the prefix, so a client that
  matches it as a substring still works. **Migration:** a client that compares the whole `detail`
  string must match on the prefix `password change required` instead. (`BACKLOG #1141`)
- **BREAKING — `/ws/stats` refusals now carry an HTTP status that says why.** Engine 0.4.0 answered
  every refused handshake with an empty `403`. On a server that offers the ASGI
  `websocket.http.response` extension, as uvicorn does, the answers now differ. An unauthenticated
  or forbidden handshake gets `403` with a JSON `detail`. An unavailable engine, or too many open
  monitor sockets, gets `503`. Without the extension the route still sends the bare close it sent
  before. **Migration:** a client that reads the handshake status should treat `503` as "try again
  later", not as a sign-in failure. (`BACKLOG #1120`)
- **BREAKING — `EngineClient()` and the Windows tray now default to `https://127.0.0.1:8765`, and
  the tray pins the certificate a stock engine mints.** Engine 0.4.0 serves https by default. Yet
  `EngineClient()` still aimed at `http://127.0.0.1:8765`, which a stock engine does not answer.
  So did the tray, unless its service entry named both `--host` and `--port`. A tray that took its
  address from the service entry already chose https. It then reported the engine down, because
  no trust store holds the minted certificate. (`BACKLOG #1276`)
  - `messagefoundry.apiclient.EngineClient` now defaults `base_url` to https. Its trust is
    unchanged. Without `cacert=`, it verifies against the OS trust store, so a stock engine's
    certificate fails verification. The client never turns verification off.
  - The tray's `DEFAULT_ENGINE_URL` is now https. `messagefoundry.tray.config.compose_config()` now
    defaults `engine_tls` to `True`, because an engine on its own defaults mints a pair.
  - When the engine mints its own pair, the tray now finds `api-generated-cert.pem` through the
    service entry and pins it as its only trust anchor. It looks beside `--db`, else
    `[store].path`, else `messagefoundry.db` under the service's `AppDirectory`. It finds nothing
    in at least these cases: a relative store path with no `AppDirectory` to sit under, or one
    under `--project-root` or `[environments].base_dir`. It can also name the wrong file, for
    example when `MEFOR_STORE_PATH` in the service's environment moves the store.
    `messagefoundry.tray.poller.StatusPoller` applies the pin unless the caller passes its own
    `client_factory`. A tray started before the engine's first run picks the file up once it
    loads, with no restart.
  - A new `tray.toml` key, `engine_cacert`, names the file to pin. It must be an absolute path; a
    relative one is ignored. An explicit `engine_url` drops the file the tray found. A pin that
    will not load falls back to the OS trust store, never to no verification.
  - **Migration:** to reach a stock engine, give `EngineClient` a `cacert=` that names
    `api-generated-cert.pem`. For an engine behind `[api].tls_terminated_upstream`, which speaks
    plain http, pass `base_url="http://127.0.0.1:8765"`. A tray that does not take its address
    from the service entry now tries https. Set `engine_url` in `tray.toml` to reach a plain-http
    engine. Set `engine_cacert` wherever the tray cannot find a stock engine's certificate on its
    own, as with no service entry or in the cases above. The tray must also be able to read that
    file; the entry under Security covers that. The standalone test harness is not part of this
    change, and its default engine URL is still `http://127.0.0.1:8765`.
- **BREAKING — `messagefoundry dryrun` and `messagefoundry check` now refuse an oversized fixture
  file.** The cap is 16 MiB (`MAX_FIXTURE_FILE_BYTES`, the engine's default per-message ceiling). It
  rises to the largest `max_message_bytes` that any inbound in the graph sets, and no other setting
  moves it. The cap applies to the whole file, not to each message in it. The file's size is
  checked before it is read, so an oversized fixture is never read whole. A fixture over the cap
  that 0.4.0 read would now fail the run. `dryrun` exits with an error naming the file, and `check`
  fails its `dryrun` gate. `docs/CONNECTIONS.md` also carries an ASVS 5.1.1 file-surface inventory,
  with upload and download tables and stated exclusions. A test fails when a row that follows the
  code drifts from it. The doc names the parts kept by hand, and the test does not check those for
  gaps. **Migration:** split a fixture file over the cap into smaller files.
  (`BACKLOG #1127`)
- **The test harness's MLLP receivers, the IDE's Steps view sample, and `check`'s `.expect`
  sidecars are now capped (ASVS 5.1.1).** The harness Receive tab, load sink and reconcile capture sink
  each bound a frame at `DEFAULT_MAX_FRAME_BYTES` (16 MiB) and drop an over-cap frame's connection with
  no ACK. The VS Code extension refuses a Steps view sample over 16 MiB when it is picked, and its own
  read of that sample is capped. `messagefoundry check` reads each `.expect` sidecar under its
  fixture's cap. A frame the harness accepts before a refusal in the same read still gets its ACK
  before the connection drops, a delayed Receive-tab ACK included. `max_frame_bytes` and
  `harness.reconcile capture --max-frame-bytes` read `0` as no cap, as the engine does, and refuse a
  negative value. The File tab's watch pane caps each file at `DEFAULT_MAX_MESSAGE_BYTES` (16 MiB),
  checks the size before it reads, and skips an over-cap file with a logged, counted reason. The
  inventory in [`docs/CONNECTIONS.md`](docs/CONNECTIONS.md) now lists the harness receivers and watch
  pane as one upload row. It lists the live-debug sample choice as an IDE picker, and its test
  checks both rows. ([BACKLOG #1127](docs/BACKLOG.md))
- **BREAKING — `[api].tls_terminated_upstream` without `[api].tls_cert_file` now requires
  `[api].plaintext_upstream_hop_acknowledged = true`.** 0.4.0 asked for no such acknowledgement. In
  that topology the engine mints no certificate (ADR 0172 decision 3). So the
  proxy-to-engine hop is plaintext by design, and securing it is the deploying site's job. `serve`
  refuses that topology (exit 2) until the operator sets the acknowledgement. It refuses in every
  mode: `enforce` or `warn`, loopback bind or not. With an operator `tls_cert_file` the engine serves
  that hop over TLS, so nothing needs acknowledging. The existing proxy attestations keep their own
  behaviour. Setting the acknowledgement without `tls_terminated_upstream` is refused at load.
  `messagefoundry check` fails the same config through a new required check, `upstream-hop-ack`, so
  a commit or CI gate that passed on 0.4.0 can now fail. See
  `docs/CONFIGURATION.md` and `docs/SECURITY.md`. **Migration:** after you upgrade, set
  `[api].plaintext_upstream_hop_acknowledged = true`. 0.4.0 refuses the key as unrecognized, so do
  not add it first. Or set `[api].tls_cert_file` and `[api].tls_key_file` so the engine serves that
  hop over TLS. The proxy must then speak https to the engine and trust that certificate, or every
  request through it fails. (`BACKLOG #1179`)
- **BREAKING — the password-policy refusal for a context word now names the list it checks.**
  Engine 0.4.0 said `not contain application or vendor terms`. The clause now reads `not contain a
  word from the context-word deny-list`. It appears in at least the `400` detail from `POST /users`
  and `POST /me/password`, after `password must`, and in the refusal from
  `messagefoundry provision-admin`. The status code is unchanged. The list is unchanged too, so the
  same passwords are refused. The old wording mis-described it, since the list also holds generic
  default-credential words such as `admin` and `password`. `docs/SECURITY.md` already published the
  list in full, and a new test holds it equal to `CONTEXT_WORDS`. **Migration:** a client that
  matches the old clause in the `detail` must match the new one. (`BACKLOG #1135`, `#1132`)
- **An opt-in refusal of backend hops on an unchanging credential, and an inventory of every such
  hop.** `[security].require_nonstatic_credentials` ships off. When on, `serve` refuses every backend
  hop that presents a password, API key, static token or no credential at all, unless
  `[security].static_credential_accepted` names it with a reason. The inventory covers the connection
  graph and six service-settings sections. It appears in `GET /security/posture` as
  `static_credential_hops`, served `Cache-Control: no-store`, and in `messagefoundry check`. Each
  hop's detail names its peer as scheme, host and port only. **BREAKING for anything that parses
  `check` output:** the `static-db-credentials` check line is renamed `static-credentials`, because it
  now covers every backend hop and not only database hops. (`BACKLOG #1182`)
- **BREAKING — an operator resend now meets the target inbound's ingress guards.** `POST
  /uploads/{file_id}/resend` and `POST /messages/{message_id}/edit-resend` wrote the stage row
  directly, so the inbound's size ceiling and declared-type checks never ran on them. An uploaded file
  may be 25 MiB by default, so a single message larger than the 16 MiB ingress ceiling could be
  injected into any inbound, and an HL7 message could be injected into a JSON one. Both routes now
  run the listener's checks first, at least: the size ceiling (an HL7 inbound's own lower
  `max_message_bytes`, never above 16 MiB), `Peek.parse` for HL7 or the declared-type sniff for
  another type, the NUL rule, and a check that the inbound's charset can hold the text. A refusal
  answers 413, 415 or 422, writes an `upload.resend_reject` or `message_edit_resend_reject` audit
  row, and writes no message. **A resend that 0.4.0 accepted can now be refused**: an oversize body,
  a body that does not match the inbound's declared type, or an HL7 body `Peek.parse` rejects.
  An admitted body is committed in the listener's form: HL7 with `\r` line endings, and a binary
  inbound's body as `mfb64:v1:` carriage. Strict `hl7apy` validation is covered by the next
  entry. A re-route whose origin inbound this engine does not hold (removed, or owned by
  another engine shard) is now refused with 409 rather than written unchecked. The edit-resend
  direct path (`to` set) writes an outbound row, so only the NUL rule applies there in practice; its
  body is already held below 16 MiB by the 1 MiB request cap. The web console shows an uploaded-log
  resend refused this way as its own notice. ([BACKLOG #1911](docs/BACKLOG.md))
- **BREAKING — a resend into a strictly validated inbound now meets its strict validation.** Where
  the target inbound sets `validation.strict`, `POST /uploads/{file_id}/resend` and an edit-resend
  re-route now run the listener's strict `hl7apy` validation before anything is written. It runs
  under the same `validation.strict_timeout_s` backstop, and a failure or a timeout is refused with
  422. The refusal writes the same `upload.resend_reject` or `message_edit_resend_reject` audit row
  as the other guards, with phase `strict`, and writes no message. Its reason counts the
  validation errors and quotes none, because `hl7apy` can echo a field value; a dry run against
  the inbound lists them. **A resend that 0.4.0 accepted can now be refused**: an HL7 body that passes `Peek.parse`
  but not the inbound's strict validation. As on the listener, a streaming inbound's body at or over
  `stream_threshold_bytes` gets header-only checking. The edit-resend direct path meets no inbound,
  so strict validation does not apply to it. ([BACKLOG #1911](docs/BACKLOG.md))
- **BREAKING — a session that has not proved its second factor can no longer change the password of
  an account that has one.** In 0.4.0 `POST /me/password` accepted an MFA-pending session on the
  password alone, and a change ends every session, so a caller holding only the password could lock
  the real user out. It now answers `403` with an `X-MFA-Required` header, and audits
  `auth.mfa_denied`, when the account has confirmed TOTP or a registered passkey. That covers every
  provider except a directory account, which still gets its `400`. The web console's password page
  sends the same session to `/ui/mfa` instead. `POST /auth/mfa-verify` is now reachable while a
  password change is required, so a must-change account with a factor, such as one an administrator
  reset, proves the factor first and then rotates. An account with no factor rotates as before.
  **Migration:** on that `403`, send `POST /auth/mfa-verify` with a TOTP code, adopt the token it
  returns, and retry. The JSON API has no passkey leg, so a passkey-only account proves its factor on
  the web console.
  ([BACKLOG #1954](docs/BACKLOG.md))
- **A new sign-in now ends the session it replaces.** A console sign-in by password,
  Windows SSO or OIDC ends the session the browser already held, and the IDE revokes
  the token a new sign-in replaces. The bearer `POST /auth/login` and
  `/auth/negotiate` legs revoke nothing, because they return a token without
  replacing one; ending the old token is the client's job there.
  ([BACKLOG #1146](docs/BACKLOG.md))
- **A console release now refuses a wheel whose engine requirement has no floor.** The
  `release-webconsole` job reads the built wheel's `Requires-Dist` and fails unless its
  `messagefoundry` requirement has a lower bound and no environment marker. An upper bound is
  allowed. The console's engine requirement is a floor with no ceiling, set at each console release;
  `docs/WEBCONSOLE-PACKAGE.md` says why. A bare dependency let `pip` keep an older engine that
  lacks the functions the console calls. ([BACKLOG #1585](docs/BACKLOG.md))

### Security
- **BREAKING — OIDC sign-in now bounds how old the IdP's authentication may be.** A new setting,
  `[auth].oidc_max_age_seconds`, is sent as `max_age` on every authorization request. It defaults
  to 43200 seconds (12 hours), accepts 300 to 86400, and has no off switch. The engine now requires
  the `auth_time` claim and refuses a sign-in whose `auth_time` is missing (`auth_time_missing`) or
  older than `max_age` (`auth_time_stale`). The session ends at the earliest of `auth_time + max_age`,
  the `id_token` `exp`, and the configured session caps. **A deploying site whose IdP does not return
  `auth_time` would have every federated sign-in refused**; that is spec-correct and deliberate.
  Federation still ships off (`oidc_enabled = false`). `exp`, `iat`, `nbf` and `auth_time` must now
  be finite numbers (`claim_not_numeric`). An `auth_time` further ahead than the clock skew is
  refused (`issued_in_future`). With `[auth].oidc_prompt = "none"`, the IdP may answer
  `login_required` once its own sign-in is older than `max_age`. The user then signs in at the IdP
  directly. `messagefoundry verify --section federation` gains a MANUAL `fed.max_age` row. Its token
  replay now fails an unexpired `id_token` with no `auth_time`. It skips one whose `auth_time` has
  aged past `max_age`. **Migration:** with OIDC on, confirm that the IdP returns `auth_time` when
  the request carries `max_age`, as OpenID Connect Core requires. No setting turns the check off.
  (`BACKLOG #296`)
- **BREAKING — the OIDC token endpoint and JWKS legs now carry the posture-keyed revocation
  guard.** Engine 0.4.0 checked revocation on these legs only when `[auth].oidc_tls_crl_file` was
  set, and started without it. Each leg is guarded on its own host, so an off-box JWKS host is
  guarded even when the token endpoint is on loopback. With OIDC on and
  `[security].enforcement = "enforce"`, the default, an off-box identity provider with no
  `[auth].oidc_tls_crl_file` now stops `serve`. The refusal comes when the API is built, after the
  engine has started its listeners and workers. Neither `messagefoundry check` nor
  `messagefoundry verify` reports it ahead of time. ADR 0173 section 4.3 called for this guard,
  and ADR 0173 AC-4 records these limits. **Migration:** with OIDC on, set
  `[auth].oidc_tls_crl_file` to a PEM file holding a CRL from each CA that issues the token and
  JWKS endpoint certificates. Put only CRLs in it. A certificate in that file became a trusted
  root for this hop until BACKLOG #1890, later in this release, made it refuse instead. `[security].enforcement = "warn"` also lets `serve` start, but it
  turns every enforce-only refusal in the instance into a warning, not this one alone.
  (`BACKLOG #1887`)
- **BREAKING — the `Direct()` S/MIME envelope now encrypts its content with AES-256-CBC.** Engine
  0.4.0 set no content cipher, so the `cryptography` library chose its default, AES-128-CBC. The
  mode is still CBC, and the content key is still wrapped with RSAES-PKCS1-v1_5. Signing is
  unchanged. With a 2048-bit RSA recipient key, the message as a whole stays near 112 bits of
  strength. A partner whose S/MIME stack cannot decrypt AES-256-CBC cannot read these messages.
  The engine cannot see that failure. The SMTP relay accepts each message before the partner tries
  to decrypt it, so the engine records a successful delivery. **Migration:** before upgrading,
  confirm that each Direct partner's health information service provider decrypts AES-256-CBC. RFC 5751 requires S/MIME agents to
  support AES-128-CBC (MUST) and only recommends AES-256-CBC (SHOULD+). No setting restores
  AES-128-CBC. (`BACKLOG #1168`)
- **BREAKING — the inbound `Http()` listener now settles a request's framing before it reads the
  body, and refuses framing it would have to guess at.** When a front proxy and the engine disagree
  about where a request ends, a request can be smuggled past the proxy (ASVS 4.2.1). Each refusal
  writes a `framing_error` connection event and no ingress row. No setting re-admits the old
  shapes. (`BACKLOG #1125`)
  - A `POST`, `PUT` or `PATCH` with no `Content-Length` now gets `411`. Engine 0.4.0 read it to the
    end of the connection and ingested it.
  - Any `Transfer-Encoding` now gets `400`, on every method. Engine 0.4.0 already refused one sent
    beside a `Content-Length`, or sent twice. Otherwise it refused only `chunked`, in any letter
    case, and never on `GET` or `HEAD`. So a lone `gzip, chunked` on a `POST` got through.
  - A `GET` or `HEAD` that declares a non-zero body now gets `400`, where engine 0.4.0 answered
    `200`. Any other method outside `POST`, `PUT` and `PATCH` that declares a body gets `400` too.
    `Content-Length: 0` is still accepted.
  - Methods are now case-sensitive. A lowercase `post` is no longer ingested, and a lowercase `get`
    or `head` is no longer answered as a health probe.
  - At least these also get `400`:
    - a `Content-Length` with a leading `+`, an underscore or more than 18 significant digits;
    - whitespace before a header colon, or a folded header line;
    - a bare CR or LF in the head, or a control character in a header value;
    - a method or header name that is not a token;
    - an HTTP version other than 1.x.
  - **Migration:** a sending partner puts a `Content-Length` on every `POST`, `PUT` or `PATCH`,
    sends no `Transfer-Encoding`, and writes the method in capitals. A health checker sends `GET`
    or `HEAD` in capitals, with no body.
- **BREAKING — an MFA-pending session on an account that has a second factor can no longer end
  sessions through the `/me/sessions` routes.** `DELETE /me/sessions` and
  `DELETE /me/sessions/{session_id}` skip the MFA gate, so an account with no factor can still end
  its own sessions. In 0.4.0 that also let a caller holding
  only the password sign out a user who has a factor. Now, for an account with a TOTP factor or a
  passkey, a pending session gets `403` with `X-MFA-Required: 1` from both routes. `POST /me/reauth`
  with `purpose` `session_terminate` still answers `200` and returns a new token, but it mints no
  grant. `POST /me/mfa/enroll` and `POST /me/mfa/confirm` already refused this case in 0.4.0. They
  now answer with `X-MFA-Required` instead of `X-Step-Up-Required` and `X-Step-Up-Action`. Each
  refusal on those four routes writes an `auth.mfa_denied` audit row. Every `auth.reauth` audit row
  now carries a `grant_refused` field. An account with no factor is unaffected. The web console
  applies the same rule and sends the browser to `/ui/reauth`, which asks for the second factor
  as well as the password. `POST /me/password` still revokes every session from a pending session;
  this change does not cover it. **Migration:** on a `403` with `X-MFA-Required` from those four routes, prove the
  existing factor on that same session first. A JSON client sends a TOTP or recovery code to
  `POST /auth/mfa-verify` and adopts the `token` it returns. Then it sends `POST /me/reauth` with
  the route's `purpose` (`session_terminate`, `mfa_enroll` or `mfa_confirm`), adopts that `token`,
  and retries. The JSON API has no passkey step, so a passkey-only account ends its sessions from the
  web console, where `/ui/reauth` asks for the passkey. (`BACKLOG #1951`)
- **BREAKING — a keyed store now refuses an unmarked value in an encrypted column, where 0.4.0
  read it back as plaintext.** Once a store key is set, only the keyed writer writes a covered
  column. So a non-blank value there without the `mfenc:` marker is a stripped marker or a planted
  row. The cipher raises `CipherError` on it. A purged `''` is never refused. The sweep at each
  keyed open still seals legacy plaintext, but only on a surface that holds no sealed value yet. On
  a surface that already holds one, it leaves the unmarked value in place and reports it. Under
  `serve`, each refusal raises an `integrity_drift` alert under the subject `store-cipher`. The
  alert names the table and column, never the row or the value. A CLI command that opens the store
  only logs the refusal. **An unmarked `state` or `reference` value on a sealed surface would stop
  the engine from starting**, because both caches load at open. The opt-out,
  `[store].allow_unmarked_ciphertext`, ships off and is reported as a loosening when on.
  (`BACKLOG #1169`)
  - At least these gaps remain. The Direct S/MIME enveloped body is not covered. A surface with
    no ciphertext yet at a keyed open counts as unsealed, so a row planted there is sealed as if it
    were real.
  - Uploaded files follow their own rule, in the separate BREAKING entry on plaintext uploaded
    files. `docs/PHI.md` section 3 lists that rule's limits.
  - A store keyed under 0.4.0 can hold legitimate unmarked values in at least two cases. One is a
    first keyed open that stopped part-way through its sweep, which 0.4.0 committed in batches.
    The other is a value made only of spaces on SQL Server, which 0.4.0's sweep skipped. The new
    code refuses both.
  - **Migration:** the engine names each column where it finds unmarked values beside sealed ones.
    If you know those values are legitimate, start it once with
    `[store].allow_unmarked_ciphertext = true`. That open seals them. Then set the setting back
    to `false`.
- **BREAKING: a keyed store now refuses a plaintext uploaded file on read until an operator runs
  `rotate-key`, which seals it.** This follows an owner ruling of 2026-09-23. An upload stored
  before the key was enabled has no `mfenc:` marker, and neither does a file planted in
  `[store].uploads_dir`. The AES-GCM store cipher now refuses both, and each refusal raises an
  `integrity_drift` alert under its own subject, `upload-cipher`, naming the surface but never the
  file. `serve` logs a WARNING at startup with the count of such uploads, never a filename, and
  `rotate-key` prints how many it sealed. The API answers 423 for a refused file, where an
  unhandled `CipherError` answered 500. When the refused part is the record that names the file's
  owner, only a holder of `files:access_any` sees 423; everyone else keeps the 404. A refused
  file drops out of the listing. **A deploying site that enabled its key after files were
  uploaded would find those files missing from the listing, and answering 423, until it ran
  `rotate-key` with the engine stopped.** Under `cipher_provider = "vault_transit"`, uploads keep
  the plaintext passthrough; that is a stated residual, and `docs/PHI.md` section 3 says why. The
  existing `[store].allow_unmarked_ciphertext` opt-out also restores the passthrough for uploads.
  **Migration:** 0.4.0 read a plaintext upload on a keyed store with no operator step. After you
  upgrade, stop the engine and run `messagefoundry rotate-key` once. The current key is enough; it
  does not need a new one. The command seals every plaintext upload, and until it runs they stay
  refused, as above. The startup WARNING says how many are waiting. Uploads written while the key was
  already set are sealed at write and need no step. ([BACKLOG #1169](docs/BACKLOG.md))
- **A lockout, and a sign-in that succeeds after failures, now write their own audit rows, so they
  reach the user's security-events feed.** Engine 0.4.0 wrote no row of its own for either event.
  Each lived only in the out-of-band notice, so no account saw either event in
  `GET /me/security-events`. An account with no notification address, or on an engine with no
  mail relay, got no notice of it at all. Two new audit actions carry them. `auth.account_locked` is written when a wrong password, or a
  wrong TOTP or recovery code, crosses the lockout threshold. `auth.login_after_failures` is written
  when a local password sign-in succeeds after three or more failures. Each row names the account
  as its actor and carries no more detail than the attempt's own row. The failure count stays in
  the notice. (`BACKLOG #1138`)
- **Refused WebSocket handshakes now carry the baseline security headers, and some responses
  uvicorn writes on its own gain two of them.** A WebSocket handshake gets an HTTP answer, but the
  header floor used to pass every WebSocket through untouched. It now adds to the `101` on accept
  the same baseline every HTTP response gets. That includes at least
  `X-Content-Type-Options: nosniff` and `frame-ancestors 'none'`, plus HSTS where HSTS applies. On
  a server that offers the ASGI `websocket.http.response` extension, as uvicorn does, it adds them
  to every refusal before accept as well. There, a WebSocket refused by
  `[security].allowed_client_networks` gets the same `403` body an HTTP request gets. Under
  `messagefoundry serve`, a new module, `messagefoundry/api/protocol_headers.py`, adds only
  `nosniff` and `frame-ancestors 'none'` to responses uvicorn writes below the app. It never adds
  HSTS. It covers at least uvicorn's `400` for a request it cannot parse, and its `500` when the
  app fails without starting a response. It also covers uvicorn's WebSocket `500` and the legacy
  websockets server's own handshake answers. A step on a single response that errors logs a
  WARNING, once per response family and step, and leaves uvicorn's own response as it was. Those
  steps rely on uvicorn and websockets internals, measured at uvicorn 0.49.0 and websockets 17.1,
  the versions `requirements.lock` pins. When one of those internals is missing, `serve` refuses
  to start; see the Security entry on the protocol header floor. (`BACKLOG #1120`)
- **Passkey registration now requires real CBOR integers where the COSE key needs them.** Engine
  0.4.0's P-256 pin for ES256 let `true`, `1.0` and some other non-integer CBOR values stand in for
  an integer. So an ES256 key whose curve read `true` or `1.0` could enrol past the pin.
  Registration now refuses a key whose `kty` or `alg` is not an integer, or, for an OKP or EC2 key,
  whose `crv` is not one. It also refuses a label that is neither an integer nor a text string (RFC
  9052 section 7), and a key sent as a CBOR array. Each refusal is audited as
  `auth.webauthn_failed`. Passkeys already registered are not re-checked. (`BACKLOG #1953`)
- **On Windows, the engine now lets local users read the API certificate it mints, and never the
  key.** When it mints its self-signed pair, it grants `BUILTIN\Users` read on
  `api-generated-cert.pem` alone. `scripts\service\install-service.ps1` locks the data directory
  to SYSTEM, Administrators and the service account. The tray runs as the signed-in user, so on
  such a host it may not be able to read the file it pins (under Changed). The certificate is
  public, since every TLS client receives it in the handshake. The key stays readable only by its
  owner. The grant adds one entry for this one file and leaves the directory as it was. It is
  best-effort: a failure is logged, and the engine still starts. **Migration:** the engine reuses
  a pair it already has, and engine 0.4.0 minted its pairs without the grant. On such a host,
  grant local users read on `api-generated-cert.pem` alone, never the key. Or delete both
  generated files so the engine mints a new pair. Then restart the tray, which does not reload a
  pin that already loaded, and re-pin every other client that pinned the old certificate.
  (`BACKLOG #1276`)
- **The DICOM deflate guard now bounds exactly the bytes `dcmread` inflates, and fails closed.**
  Engine 0.4.0's guard found the deflated Data Set with its own walk of the file meta. It let
  through any header it could not follow, and pydicom reads headers more leniently. So a crafted
  Deflated Explicit VR Little Endian object could pass the guard and then inflate without bound in
  `dcmread`. That path runs through `DicomPeek.parse`, `DicomDataset.parse` and the outbound
  C-STORE SCU. (`BACKLOG #1926`)
  - The guard now replays pydicom's own header readers, the ones `dcmread` runs just before it
    inflates, and bounds that stream. That covers at least a missing or wrong group length, a
    second transfer-syntax element, a forced read with no preamble, and a command set before the
    Data Set.
  - A header pydicom cannot read is refused the way `dcmread`'s own failure would be. A pydicom
    that lacks one of the replayed readers makes DICOM parsing fail with an error naming it, rather
    than parse unguarded.
  - The bounded inflate now stops at the end of the deflate stream. In 0.4.0 it looped without end
    on some Data Sets. Such a Data Set inflated past 64 KiB but not past the cap, and had any byte
    after the stream's end. pydicom and pynetdicom pad an odd-length deflated Data Set with one NUL
    byte, so an ordinary object could hit it. The inbound C-STORE SCP ran the same loop.
  - The `[dicom]` extra now requires `pydicom>=3.0.2,<3.1`, where 0.4.0 allowed `<4`. The guard
    replays private pydicom readers, and its agreement test covers only the locked release, 3.0.2.
    No pydicom 3.1 or later had been published when this changed, so the cap rules out no release
    a 0.4.0 `[dicom]` install could have picked.
- **BREAKING — every command now refuses to start a keyless audit chain, not only `serve` and
  `provision-admin`.** 0.4.0 gave those two commands a refusal to open a store with no key. Any other
  command that opens the store could still write the first audit row of a fresh store keyless, and a
  chain that starts keyless stays keyless. At least `backup` did (its `dr_backup` row, written even
  when the backup fails) and `admin-unlock` did. The decision now sits in the store-open path every
  command shares. **A command that opens a store with no key and an empty audit log now exits 2**
  unless the audited opt-out applies (`[security].allow_unencrypted_phi`, plus
  `allow_unencrypted_phi_under_strict_enforcement` under `enforcement = enforce`). That covers
  `backup`, `admin-unlock`, `admin-set-notify-email`, `audit-anchor`, `audit-verify` and
  `rekey-audit`. `supervise` now applies `serve`'s at-rest gate before it renews the API certificate
  or starts any shard, and exits 2 where each shard would have refused. `serve` now also refuses to
  start when a key is named that `[store].key_provider` did not resolve; before, it started keyless.
  A store whose chain already has rows opens as before. Three smaller fixes ride along.
  `provision-admin`, `admin-unlock` and `backup` now refuse before their first write when the store
  would refuse their audit row, and exit 2. Before, a keyed store opened from a shell with no key
  and a leftover opt-out got the account written and then a traceback, with no audit row.
  `provision-admin` now exits 2 on every refusal to start a keyless chain, including the no-key
  refusal 0.4.0 added, which exited 1. And `rekey-audit` no longer prints the keyless-chain warning
  that names `rekey-audit` as its fix.
  ([BACKLOG #1916](docs/BACKLOG.md))

## [0.4.0] — 2026-09-23 — Early Access

This section lists every breaking change since 0.3.2, each marked BREAKING, and summarizes the
non-breaking fixes rather than listing them all; the git history is the full record. A `BACKLOG #N`
or bare `#N` number cites the project's private planning ledger, so it has no public page.

### Added
- **`messagefoundry audit-anchor`, and `audit-verify --expected-anchor` / `--expected-anchor-file` to
  check one back.** The audit hash chain links each row to its predecessor, so deleting the *newest*
  rows leaves a shorter chain that still walks cleanly — `audit-verify` on its own reports OK after a
  tail-truncation, which is the shape an attacker hiding what they just did leaves behind. The store
  could always compare against an external anchor; nothing exposed it, so the capability was
  unreachable. `audit-anchor` prints `COUNT:HEAD` (a row count plus a digest — no PHI, no secret, safe
  to hold in a ticket or an object store); passing it back reports `truncated or rewritten` when the
  live chain differs. An anchor file must be UTF-8. PowerShell 5.1's `>` writes UTF-16, which the
  engine cannot read, so pipe the line to `Set-Content -Encoding utf8` instead.
  **Know what it is before you build a job on it: an EXACT point-in-time seal**, comparing the count
  *and* the head hash. The head half is not redundant — an attacker who cuts the newest rows and forges
  the same number of replacements restores the count and leaves a chain that walks cleanly, so the head
  is the only thing that differs. The cost of that detection is that a chain which merely **grew** also
  reports `truncated or rewritten`. So it seals a chain **at rest across a gap in custody**: quiesce the
  engine, anchor, hold the value off-box, re-verify while the chain is still quiesced — around a
  maintenance window, a database move, a backup/restore, a hand-off. Anchoring and immediately
  re-verifying compares a value to itself; re-checking a held anchor against a **running** engine alarms
  on every ordinary boot. For a running engine the off-box log forward / tee remains the continuous
  control, and the next entry adds a check at each startup. (`BACKLOG #328`)
- **`[integrity].audit_anchor_file` — the startup audit check can now hold an anchor, so it can see a
  truncated tail.** On its own, `[integrity].audit_verify_on_start` is a bare walk, blind to a
  truncated tail. **With this key and `audit_verify_on_start = true` both set, the startup check can
  see one.** Save the `COUNT:HEAD` line `messagefoundry audit-anchor` prints to a UTF-8 file, as the
  entry above describes, and point the new key at it; every startup that runs the check compares
  against it. The key alone arms nothing: with
  `audit_verify_on_start` left at its default of `false`, startup logs a WARNING that the anchor is
  never read. Leave the key empty (the default) and the walk is byte-identical to before.
  **It consumes the anchor as a PREFIX, not as the CLI's exact seal, and that is the whole reason a
  startup setting can hold one.** The exact seal compares the *current* head, so it diverges on the
  next appended row — and a running engine writes audit rows, so a startup check built on it would
  alarm on essentially every restart. The prefix comparison asks instead whether the recorded state was
  ever true and the chain has only **grown** since, which survives restarts while still catching a
  truncated tail and a mid-chain rewrite. A stale anchor therefore stays valid; it just witnesses less.
  **Alert-only in both directions.** A missing, unreadable or malformed anchor logs a WARNING naming
  the file, the reason and the coverage lost, then lets the bare walk run — it never blocks startup,
  and it never fires the tamper alert, because a config fault that raised a tamper alarm would train
  operators to ignore the real one. `0:`, the anchor of an empty log, is reported rather than compared:
  it can witness nothing, and passing it on would have alarmed on every start of an intact chain.
  A truncated tail and a broken chain fire **different** alert subjects (`audit-chain-truncated` /
  `audit-chain`) so they route and throttle separately — but they are not independent: a chain break is
  reported *before* the anchor comparison runs, so a break should be read as *at least* a break.
  **Scope.** It fires at startup and only at startup, so it detects a cut made since the last boot and
  says nothing about the window between two boots. (`BACKLOG #328`)
- **A startup preflight that reads the store principal's *effective* privileges, so the least-privilege
  grant the runbooks prescribe stops being a claim the engine cannot check.**
  `docs/DEPLOY-SERVER-DB.md` told operators exactly which grant the engine's
  database login needs, and the engine had no way to see what it had actually been given: no
  fixed-server-role probe and no database-role probe existed anywhere, and
  `[store].require_managed_identity` constrains the credential's *kind* rather than its privilege — a
  `sysadmin` gMSA satisfies it clean. On a first deployment an over-granted store principal would
  therefore have gone unobserved. `serve` now reads fixed **server**-role and **database**-role
  membership plus `CONTROL SERVER` / database `CONTROL` on SQL Server, and role attributes
  (`SUPERUSER`, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`), assumable predefined roles and
  database ownership on PostgreSQL — before any listener binds. The PostgreSQL attributes are read
  across **every role the principal may assume**, not only its own row: attributes are never
  inherited, but a member may `SET ROLE` to the holder and exercise them, so a wrapper role carrying
  `CREATEROLE` is named (`CREATEROLE via role site_ops`) instead of reading clean.
  **It observes and warns; it does not refuse by default** — refusing on an over-grant could block a
  legitimate deployment mid-setup, and the engine does not own the grant. Every start logs what it saw,
  writes a `store_privilege_preflight` audit row, and names each excess grant in
  `security_loosenings()` and `GET /security/posture`. Set `[store].require_least_privilege = true` to
  turn the warning into a refusal (refuse/warn splits on `[security].enforcement`, exactly like
  `require_managed_identity`).
  **It does not fail open, and that is the part to know before reading its output.** A probe that
  cannot run — permission denied, a driver error, a store handle with no probe — reports
  `unobservable`, which is a *different* result from "observed, and it is fine" in the log line, in the
  audit row and in the posture response, and which a declared `require_least_privilege` also refuses.
  SQLite reports `not_applicable` and says why: a local file has no server principal, and the control
  there is the filesystem ACL. The PostgreSQL least-privilege grant is now documented
  (`docs/DEPLOY-SERVER-DB.md` §1.2), which it previously was not.
  (`BACKLOG #1008`)
- **Three new alert events: `approval_stale_requester`, `ad_session_revoked` and
  `ad_reconcile_aborted`.** The first fires when a dual-control release is refused because the
  requester no longer holds the authority it needs (under Security below). The other two come from
  the directory session reconciler. It raises one `ad_session_revoked` per account whose sessions it
  revoked, and one `ad_reconcile_aborted` when its mass-revoke breaker stops a pass. Each has a
  matching audit row: `approval.stale_requester`, `auth.ad_session_revoked` and
  `auth.ad_reconcile_aborted`. A pass that stops because the whole directory is unreachable raises
  no alert, and neither does a pass that fails part-way. An `[[alerts.rules]]` `event_type` can now
  name all three, and `any` matches them too. (`BACKLOG #289`)

### Removed
- **BREAKING: `[security].handles_real_patient_data` is gone, and with it the whole data-class axis.**
  Every instance carries patient data; the PHI gates apply unconditionally. Setting the key — or its
  pre-ADR-0118 spelling `[ai].data_class` — now **refuses at load** with a message naming the switch to
  reach for instead. Removed with it: the `DataClass` enum, `HopPosture.is_phi`, the `data_class` and
  `synthetic_relaxation` fields on `SecurityPosture`, and `data_class` on `AiPolicy`.
  `derived_posture()` / `require_posture()` return the production tier alone.
  **Why, in one line: it turned off nineteen start-up gates on one line, and it was not the audited
  opt-out the documentation claimed.** `security_loosenings()` never named it, so the serve-time
  loosening warning — the thing that fires for every other deviation — did not fire for the widest
  relaxation the product shipped. The completeness test that should have caught that exempted the field
  with a reason that was false, in an exemption branch that could never execute.
  **What to use instead:** the gate you actually mean. Each is separately named, separately audited and
  separately reported — `allow_unencrypted_phi` (plus `allow_unencrypted_phi_under_strict_enforcement`
  under the shipped `enforcement = enforce`), `block_unlisted_outbound`,
  `allow_keeping_phi_indefinitely`, `allow_single_factor_admin_when_exposed`,
  `allow_unverified_alert_smtp_tls`, `[alerts].security_notifications_required`, a per-connection
  `cleartext_accepted`, a CRL for a revocation-checked hop, or the `[security].enforcement` dial.
  (A per-connection `tls_revocation_attested` exists in the engine but no factory parameter or
  `connections.toml` key can set it.)
  **What this costs:** a box that ran key-free on the declaration now needs a key or the audited
  per-gate ack. Nothing is deployed (there is no migration), and both in-repo users of the declaration —
  CI's SQL Server load leg and the failover load harness — moved to per-gate relaxations that are
  *narrower* than what they replace. See
  `docs/adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md`
  and `BACKLOG #1279`.
- **BREAKING — `[egress].fhir_require_structured_params` is gone, and with it the flat `?`-query form of
  `fhir_lookup`.** In 0.3.2 the setting defaulted to `false`, so a read query such as
  `"Patient?identifier=..."` was sent as written unless a site opted out. The flat form appended the
  author's string unencoded, so it was removed rather than left behind a setting. A query carrying `?`
  now raises `FhirLookupError` whatever the config says. With nothing left to switch, setting the key
  now **refuses at load**, under the unknown-key refusal in Changed below.
  **Migration:** delete the key from `messagefoundry.toml`. Move each flat query to `params=`, so
  `fhir_lookup("epic", "Patient?identifier=MRN|" + mrn)` becomes
  `fhir_lookup("epic", "Patient", params={"identifier": FhirToken("MRN", mrn)})`.
  (`BACKLOG #1243`, `docs/adr/0043-fhir-read-lookup.md`)
- **BREAKING — the Active Directory password sign-in (LDAP simple bind) is gone.** `POST
  /auth/login` with the `ad` provider now answers `401` and writes an audit row with the reason
  `pathway_retired`. `GET /auth/providers` reports `ad: false`, and the web console no longer offers
  the form. AD users sign in through Windows SSO (Kerberos, `POST /auth/negotiate`) or OIDC. The
  directory bind itself stays, because group mapping, the session reconciler and an AD account's
  step-up re-authentication still use it. **Migration:** turn on `[auth].kerberos_enabled` or OIDC
  for AD users, and change any client that posted an AD username and password to `/auth/login`.
  (`BACKLOG #1137`)
- **BREAKING — `Soap(ws_password_type="digest")` is gone.** The WS-Security PasswordDigest form
  hashes the password with SHA-1, so it was retired with the other weak algorithms. A SOAP outbound
  that sets it now fails at load and at `messagefoundry check`. **Migration:** set
  `ws_password_type="text"` over TLS; the partner must accept PasswordText. (`BACKLOG #1171`)
- **BREAKING — `messagefoundry.apiclient` drops the `audit_summary` keyword from `list_messages` and
  `list_dead_letters`.** No route ever read it. A call that passes it raises `TypeError`.
  **Migration:** drop the keyword. (`BACKLOG #1645`)

### Changed
- **Setting `[integrity].fail_closed_on_drift` on an editable install now says so at startup, and two
  claims about startup attestation are corrected.** An install that declares itself editable is exempt
  from attestation by design, so a dev checkout is never bricked. That exemption silently cancels the
  fail-closed opt-in, and the code path returned with no log, no audit row and no alert -- so a first
  deployment that opted into hard enforcement on an editable install would have started with its
  tripwire disarmed and nothing in the boot log to read. It now logs a WARNING naming the reason. **This
  reports a misconfiguration; it closes no hole** -- an actor who can write the virtual environment can
  plant the editable marker or rewrite the check in the same single write. AC-12's exemption is
  unchanged: still no refusal, no audit row, no alert, and silence under the default alert-only posture.
  Two ADR 0041 D3 claims were false in the shipped code and are narrowed rather than left standing: the
  non-editable hash-locked wheel is a **recommended** production default, not an enforced one (nothing
  in the engine refuses an editable install), and attestation runs **at startup only** -- there is no
  on-demand surface, no `attest` CLI subcommand and no API route. ADR 0041 D3 also now records the
  resolution of the baseline's trust domain: the wheel's own `RECORD` stays the baseline, no runtime
  out-of-domain anchor is adopted, and the control detects an *inconsistent* in-place edit and not a
  *consistent* one. (`BACKLOG #1679`)
- **BREAKING — an Active Directory login is now identified by the directory's immutable id, not by
  `sAMAccountName`.** A directory frees a deleted account's name and may reissue it to a different
  person. The engine resolved an AD principal by that name, so a recycle without a matching
  MessageFoundry `delete_user` adopted the departed operator's row and re-bound its `user_id` -- the
  value uploaded-file ownership, the per-uploader quota and saved search presets all key on. Nothing
  reported it. `AdPrincipal` now carries the normalised `objectGUID`, `users.directory_object_id`
  stores it on all three store backends (nullable, in-place upgraded, no index), and `_upsert_ad_user`
  resolves by that id. **A login whose id disagrees with the row holding its username is refused and
  audited (`directory_identity_conflict`), never adopted or backfilled** -- backfilling on first sight
  would leave the recycle window open for every account that had not signed in yet. A directory that
  returns no immutable identifier still resolves by username, and the engine warns once per distinct
  cause -- the attribute absent, or present in a shape it cannot read -- so a site on that path is
  told rather than left to assume the control is running. **A directory-side rename now keeps the
  account instead of minting a second one**, which is the other half of the same defect: before this,
  a rename resolved to nothing and silently orphaned the uploads and presets keyed to the first row.
  **Who this bites:** every AD account row that 0.3.2 created has no stored id. Its first 0.4.0
  sign-in through a directory that returns `objectGUID` is therefore refused as
  `directory_identity_conflict`. **Migration:** an administrator deletes each such MessageFoundry
  user row (`DELETE /users/{user_id}`; on a store created by 0.3.2, that call fails until the
  migration in the BREAKING saved-search entry below is applied, including its recovery step on
  PostgreSQL and SQL Server), and the person's
  next directory sign-in creates a new row bound to the id. Uploaded files, saved search presets and a
  per-user channel scope keyed to the old row do not carry over. (`BACKLOG #1471`)
- **The directory session reconciler is keyed on that same immutable id, and the stored username is
  now a cache the directory refreshes.** Identifying a login by `objectGUID` while
  `reconcile_directory_sessions` went on probing `resolve_principal(<the stored name>)` left a renamed
  account reading as absent on every pass -- the same answer a deleted or disabled account gives -- so
  at the shipped `ad_session_recheck_seconds = 300` and `ad_session_recheck_strikes = 2` a deploying
  site would have seen a renamed person's sessions revoked, a security notice emailed, and the cycle
  restart at the next sign-in, roughly every ten minutes and with no administrative escape, because
  nothing in the engine could write `users.username`. `_probe_principal` now asks the directory by
  `directory_object_id` where the row carries one, and the directory's current `sAMAccountName` is
  copied down onto the row -- from the login path and from the reconciler pass alike -- so the
  `user_id` that uploaded-file ownership, the per-uploader quota and saved search presets key on never
  moves. **A rename onto a name another row already holds is refused, not forced** (`username` is
  `NOT NULL UNIQUE`): the login path refuses at the `directory_identity_conflict` guard, and the
  reconciler leaves both rows alone and audits `auth.ad_username_refresh_conflict`, costing the renamed
  person neither their session nor their roles. A directory returning no readable `objectGUID` still
  probes by name, unchanged. **`set_user_username` is engine-internal and reachable from no API route,
  deliberately** -- an operator able to set it could point a row at a directory account it is not bound
  to, which is the privilege transfer `#1471` closes; there is still no setter for
  `directory_object_id`. (`BACKLOG #1532`)
- **BREAKING — web console engine UI seam: this release ships `75c4117d21fd0b98`.** 0.3.2 shipped the integer seam
  `14`. The seam is now a digest of the surface the console uses (`BACKLOG #1220`), and it moved several
  times in this release. One move, `93ba1f10b9dccfc8` -> `b93f38d097f97a45`, came when `SecurityPosture`
  gained the additive `store_privilege` object above and `StorePrivilegeView` joined the discovered
  surface. That field is additive with a default, but the seam still moves, because the golden seam
  contract introspects that model's field set. A console accepts exactly one seam, so with the console
  on, the engine refuses to start against a console built for any other seam. **Migration:** upgrade
  the web console wheel together with the engine, to the release built for this seam.
- **`DEPLOY-SERVER-DB.md` §1.2 posture B now states its prerequisite.** "A DBA pre-creates the objects"
  is not sufficient on its own: the engine skips its DDL batch only when the `schema_meta` marker
  records the current batch, and on PostgreSQL `CREATE TABLE IF NOT EXISTS` against an existing table
  is still refused for a role holding only `USAGE` (the schema ACL is checked before the existence
  skip, measured on 16.14). Bootstrap once with a DDL-capable principal, then hand over.
- **The advisory `raise-fstring` lint in `messagefoundry check` now reads three more spellings of the
  same risk.** It matched only an f-string, so `raise ValueError("bad " + x)`, the `%` form and
  `.format(...)` carried an interpolated message past it — the identical free-text PHI payload, in the
  spellings an author is most likely to reach for after an f-string. It now shares the predicate the
  ADR 0144 lookup lint already used, so the two cannot drift on what counts as interpolation. A
  deploying site's existing config dir may therefore report hits it did not report before: the check
  is advisory and still only ever prints, so it cannot block the gate, and its detail names a file and
  line, never the message text. The check keeps the name `raise-fstring`. It stays a nudge rather
  than a boundary: it reads only the first positional argument of the `raise`, so a message assigned
  to a local first, passed as a keyword or a later positional, or wrapped in a call is still
  unflagged. (`BACKLOG #1676`)
- **BREAKING — an API request body with an unknown or misspelled key is now refused with HTTP 422
  instead of being accepted and silently dropped.** Pydantic's default is `extra="ignore"`, and in
  0.3.2 no model in `messagefoundry/api/models.py` or `messagefoundry/api/auth_models.py`
  overrode it — so a
  key the engine did not recognise vanished and the route answered success. The sharpest case was
  `PUT /users/{id}/channel-scope`: in 0.3.2 `channels` was optional and `None` meant *all channels*,
  so `{"chanels": ["IB_ACME_ADT"]}` asked for one connection and granted every one of them. (`None`
  now means *no* channels; see the BREAKING channel-scope entry under Security.)
  **The posture is request-scoped, and that is the whole design.** Those two files now hold 130
  models. The 33 that FastAPI parses out of a request body subclass
  `messagefoundry.api.request_model.RequestModel`, which forbids unknown keys; the 97 response-only
  models stay tolerant, because `messagefoundry.apiclient` reads
  engine responses into those same classes and the web console ships as a separately-versioned wheel
  — a strict response model would make an older client raise on a newer engine that merely grew a
  field. Five shapes (`AdGroupMap`, `AdGroupMapEntry`, `AdGroupScopeEntry`, `AdGroupScopeMap`,
  `ChannelScope`) travel in both directions; they carry the request rule because a dropped key on the
  RBAC writes is a mis-grant, so adding a field to one of them needs the client bump in the same
  release. **Migration:** send only the keys each route defines. The `422` lists every refused key
  as its own `detail` entry, of type `extra_forbidden`. The key is the last element of `loc`, as in
  `["body", "limt"]`. Fix its spelling or drop it. (`BACKLOG #1109`)
- **BREAKING — a `fhir_lookup` search value now states its KIND, and a plain string carrying one of
  FHIR's value-layer separators is refused rather than sent.** Percent-encoding is a URL-layer
  control: it stops one value becoming two search parameters, and it cannot help at the FHIR value
  layer, where
  `,` `|` and `$` are FHIR's own separators. The FHIR specification is explicit that a server
  percent-decodes a parameter value first and reads FHIR's syntax second (R4 section 3.1.1.4.19, R5
  section 3.2.1.5.7), so `%7C` arrives as a live token separator. A message-derived value carrying one
  could therefore change what the search *means*.
  **Three kinds, because one string cannot carry two provenances.** A plain `str` is data and raises a
  PHI-safe error if it carries `,` `|` or `$` — the error names the parameter key and the character,
  never the value. `FhirToken(system, code)` splits `"MRN|" + mrn` into its two halves: the system is
  your literal and passes through, the code is data and screens. `FhirRaw("...")` is FHIR search syntax
  **you** wrote — a composite, a quantity, a comma-separated OR or `_sort` list — percent-encoded only.
  **Refusal rather than FHIR's backslash escape, deliberately:** the escape is correct only if the far
  end implements the unescape, and server behaviour there varies, whereas a value that never leaves the
  process cannot be misread by any server. Escaping is not built; it is left as a possible additive
  fourth kind for a site that has a real FHIR server and can verify it.
  **Migration:** `{"identifier": "MRN|" + mrn}` becomes `{"identifier": FhirToken("MRN", mrn)}`, which
  puts identical bytes on the wire. Import `FhirToken` / `FhirRaw` from `messagefoundry`. A non-string
  scalar also raises now — it was never in the declared type, but `urlencode` used to coerce it, so
  `{"_count": 50}` has to become `{"_count": "50"}`.
  **What is NOT screened:** the backslash. FHIR names it alongside these three because it introduces
  the escape, so a server that implements the unescape reads a bare `\` as an introducer. Widening a
  refusal is a behaviour change that should be ruled, so it is recorded on
  `messagefoundry/fhirsearch.py` rather than folded in here.
  (`BACKLOG #1243`, `docs/adr/0043-fhir-read-lookup.md`)
- **The authorization-grant audit trail now defaults ON, so a deployment records every authorization
  grant rather than only the state-changing ones.** `[security].audit_all_authorization_decisions` and
  the internal `[diagnostics].audit_all_authz` it desugars to both default `true`. Until now only a
  fixed set of state-change / configuration / user-management permissions wrote an
  `auth.permission_granted` row, so every authenticated **read** was authorized and never recorded — and
  a site could not reconstruct a read history afterwards, because the rows did not exist.
  **What the old default guarded against was measured, and it named the wrong surface.** The reason on
  record was that full tracing would flood the hash-chained audit log through console polling and the
  `/ws/stats` feed. The web console never traverses `require()` — it is server-rendered in-process and
  gates on its own cookie-world check, which records denials only — and WebSocket authorization fires
  once per *connection*, not per message.
  **The volume moves rather than vanishing, so size it.** The JSON API is the surface that changes: 33
  `require()`-gated GET routes in `api/app.py` and 9 more in `api/auth_routes.py` go from no grant row
  to **one row per authenticated request** (a per-request ceiling of one, whatever a route's permission
  count), bounded by your API clients' polling cadence. **Nothing prunes `audit_log`** —
  `[retention].audit_days` is reserved and unenforced by design — so `[retention].max_db_mb` is the
  signal to watch. **The per-request cost is a commit, not just a row:** the grant write is awaited
  before the route body runs, takes the store write lock, and commits standalone (audit is excluded
  from the group committer), so a busy JSON-API deployment pays one extra commit per authenticated
  request on the same lock the pipeline handoffs use.
  Set `[security].audit_all_authorization_decisions = false` to restore the previous
  narrow trail; that is now reported as a loosening at `serve` and on `GET /security/posture`. PHI-view
  grants stay excluded at either value, because the PHI-access audit path already records them.
  (`BACKLOG #1277`, `docs/adr/0118-secure-by-default-security-configuration-section.md` §5 amended)
- **BREAKING — a PHI instance reached through a declared reverse proxy with `[security].require_mfa`
  explicitly off would refuse to start on first deployment, where it previously would not have.** The
  MFA-at-exposure gate derived "is this instance exposed?" from `[api].serve_ui`, a field the ADR 0143
  console degrade arms rewrite **in place** earlier in the same startup. On the topology the runbooks
  recommend — a loopback bind behind a declared TLS terminator, with the web console left at its
  default — the auto-degrade cleared that flag first, so the gate evaluated "not exposed" and the
  refusal was unreachable, while the ASVS 11.7.1 arm in the same startup classified the identical boot
  as exposed. The gate now reads a single console-independent predicate (an off-loopback bind **or**
  `[api].tls_terminated_upstream`), so it also fires when the console is auto-degraded, when
  `serve_web_console = false` disables it outright, and when the console package is simply not
  installed: the surface authenticating with one factor is the JSON operator API, which the proxy
  serves either way. The `#189` dual-control advisory reads the same predicate and gains the same reach
  (still warn-only).
  **Who this would bite:** a deploying site that has explicitly set `require_mfa = false` on a
  PHI-carrying environment behind a declared TLS terminator, under `enforcement = enforce`. A plain
  loopback bind with nothing declared is **not** exposed and is byte-identical. An **undeclared** proxy
  (`web_console_public_address` set, no `tls_terminated_upstream`) deliberately still does not refuse —
  exposure there would be an inference — but it no longer passes in silence: a new warning names
  single-factor admin directly on a PHI instance with `require_mfa` off.
  **Migration:** set `[security].require_mfa = true`, or set the existing acknowledgment
  `[security].allow_single_factor_admin_when_exposed = true`, which turns the refusal into a loud
  audited warning. (`BACKLOG #326`, `docs/adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md` amendment)
- **BREAKING — an `[[alerts.rules]]` block that routes to an unconfigured transport now refuses at
  startup instead of being silently ignored.** `notifier_from_settings` returned early when **no**
  transport was configured, *before* the loop that cross-checks each rule's `transports` against the
  ones that exist. So the fail-loud guarantee held everywhere except the state an operator is most
  likely to be in while first setting alerts up: with one transport configured, a rule naming a
  different one was a hard `ValueError` at startup; with **zero** configured, the identical rule was
  accepted and then **never applied**, and nothing said so. Validation now runs first.
  **Who this bites:** an instance where `[[alerts.rules]]` exist AND at least one rule or escalation
  tier sets a non-empty `transports` AND no transport is actually configured (`webhook_url` unset, and
  **not all three** of `email_smtp_host` + `email_from` + `email_to` set — the email transport needs
  all three, which is what makes a half-filled `[alerts]` block look configured). Such an instance
  starts today and will refuse after upgrading.
  **Why this is safe to take:** in that state the rule has **never routed a single alert**. The
  refusal removes no working behaviour — it converts a permanent silent no-op into a startup error
  that names the exact keys to add. A rule that names **no** transport is unaffected and still starts
  (now with a warning when rules exist that cannot notify anyone), so the ordinary "write the rules
  first, wire the transport later" flow keeps working.
  The same cross-check now runs at **authoring** time: `messagefoundry alert add` (which the VS Code
  "New Alert" command shells) refuses a rule routing to an unconfigured transport rather than
  persisting a file that only fails at the next boot. It is scoped to the rule being added, so a file
  that already contains a bad rule can still be repaired with `alert remove`.
  **Migration:** configure each transport a rule or escalation tier names (`webhook_url`, or all
  three of `email_smtp_host`, `email_from` and `email_to`), or remove it from that `transports` list.
- **A mail-only or Direct-only PHI instance can now satisfy the open-egress startup gate by declaring
  its destinations.** `[egress]` has eight `allowed_*` lists and all eight are enforced downstream,
  but the startup gate hand-enumerated six: `allowed_smtp` and `allowed_direct` were absent, so an
  instance whose only egress is `Email()` or `Direct()` exited 2 with *"outbound egress is
  UNRESTRICTED"* while holding a fully-enumerated allow-list, and nothing in the message named the two
  lists that did not count. The two are now counted — deliberately **only** when
  `[security].block_unlisted_outbound` is left unset, which is exactly the state the deny-by-default
  flip turns ON, so such an instance starts **fail-closed**. An instance that explicitly set
  `block_unlisted_outbound = false` is unchanged and still refused, because there the other six
  transports stay allow-any; the refusal now names that override as the reason. **No shipped refusal
  stops firing.**
- **BREAKING — a non-loopback DICOM C-STORE SCP now requires a *verifiable* peer control;
  `calling_ae_allowlist` no longer satisfies the gate on its own.** The fail-closed peer-control check
  refuses a remotely-reachable SCP that has no peer control, and it accepted any one of three:
  `calling_ae_allowlist`, `source_ip_allowlist`, or mTLS. It **counted** them rather than weighing
  them. But a Calling AE Title is a string the caller asserts about **itself** in the association
  request — no key, no signature, nothing to verify — and AE Titles are published in conformance
  statements and visible in any capture. An SCP whose only control was an AE-title list was therefore
  reachable by anyone who could route to it and knew one string, while passing a check named
  "fail-closed peer controls". Server TLS does not close this: without `tls_ca_file` there is no client
  certificate, so the cleartext bind guard (confidentiality) and this gate (authentication) are
  orthogonal.
  **What changed:** off-loopback, the gate now requires `source_ip_allowlist` **or** mTLS
  (`tls` + `tls_ca_file`). `calling_ae_allowlist` is **kept and still enforced** at association time —
  it is a genuinely useful filter that catches a misrouted sender and pins intent — it simply has to be
  **paired** with one of the two. Measured: AE-title-only off-loopback goes from starting to refused;
  AE-title **paired** with an IP allowlist starts; IP-only and mTLS-only are unchanged; and every
  loopback bind (the common dev/single-box case) is unchanged.
  **Who this bites:** a site running a non-loopback SCP whose only peer control is
  `calling_ae_allowlist`. It starts today and will refuse after upgrading. The fix is one line — add
  `source_ip_allowlist=[...]` to the `inbound(...)` call, which for a DICOM SCP is the only authoring
  surface — and the refusal names it. Keep the AE list; it is still doing work.
  Tracked as **`BACKLOG #316`**. Options considered and declined: an audited opt-out switch, and
  documenting the weakness without changing the gate.
- **BREAKING — an unrecognized key in a known config section now fails the start instead of loading
  silently.** Every section model inherits `extra="ignore"`, so a mistyped or stale key in
  `messagefoundry.toml` loaded clean, did nothing, and said nothing: an operator could misspell
  `block_unlisted_outbound` and believe a posture control was on while the engine applied its
  permissive default. Exactly one section, `[security]`, warned about it; the other 27 were silent.
  The loader now refuses, naming the section and the offending key and suggesting the closest valid
  field name.
  **Scope, and it is deliberate — the refusal covers the config FILE only.** `MEFOR_*` environment
  variables and CLI flags are still accepted silently, because about a dozen documented `MEFOR_*`
  variables (the Vault store and secrets providers, the TLS revocation attestation, the lane timing
  probes) are read straight from `os.environ` by consumers that are not settings fields — so refusing
  an unrecognized environment key would refuse a deployment configured exactly as the shipped
  documentation instructs. `[security]` is the exception and is refused from the environment too.
  The check lives in the loader rather than a pydantic `extra="forbid"` for a second reason: pydantic
  echoes the offending **value** in its error, and the CLI prints validation errors verbatim to
  stderr, which the Windows service captures to a log file — so a mistyped secret key would have
  written the secret to disk. Both existing config refusals name keys only, never values.
  **Who this would bite on first deployment:** a config file carrying a key that is not a field of
  its section — a typo, a key copied from newer documentation, or a setting since removed from the
  engine. **Remedy:** correct the spelling; the error names the section and the key. Nothing needs
  migrating, because a key that is refused now was doing nothing before.
- **BREAKING — `convert_hl7_timestamp(..., from_tz=...)` now raises at the daylight-saving edges
  instead of guessing.** Twice a year a local wall-clock time happens twice (the fall-back overlap) or
  never (the spring-forward gap), and a timestamp with no offset cannot say which instant it means.
  0.3.2 silently picked one, which could be an hour wrong. The function now raises
  `AmbiguousLocalTimeError` or `NonExistentLocalTimeError`, so a Handler that calls it at those times
  fails the message instead of sending a shifted time. Both subclass `DstTransitionError`, a
  `ValueError`, and they are exported from `messagefoundry` with the `DstEdgePolicy` type. Only a time
  the sender wrote is refused: a value with no time field keeps its 0.3.2 result, and a timestamp that
  carries its own offset is unaffected.
  **Migration:** pass `on_dst_edge="earlier"` to keep the 0.3.2 result exactly, or `"later"` for the
  other offset. Better, have the sender include its offset. (`BACKLOG #1686`)
- **BREAKING — `gzip_decompress`, `deflate_decompress` and `zip_decompress` now require
  `max_output_bytes`.** In 0.3.2 it defaulted to `None`, which meant no ceiling, so a Handler that
  forgot it could be handed a decompression bomb. It is now keyword-only with no default, so a 0.3.2
  call such as `gzip_decompress(data)` raises `TypeError` and the message fails. **Migration:** pass
  a byte ceiling, for example `gzip_decompress(data, max_output_bytes=64 * 1024 * 1024)`, or pass
  `max_output_bytes=None` to keep the 0.3.2 behaviour on input you have already bounded.
  (`BACKLOG #1237`)
- **BREAKING — three smaller changes to the helpers a Router or Handler calls.** Each one makes a
  0.3.2 call raise, so the message goes to `ERROR` instead of being processed.
  - An HL7 field path with an index below 1, such as `PID-5.0` or `PID-0`, now raises
    `HL7PeekError`. In 0.3.2 index 0 wrapped to the *last* item, so a read returned a value nobody
    asked for and a write overwrote the last component or the segment id. **Migration:** use
    1-based indexes. (`BACKLOG #1089`)
  - `XmlMessage.find`, `get`, `get_all`, `exists`, `set` and `set_attribute` now take their
    expression, value and attribute name positionally only, because the keyword slots now carry
    `$variable` bindings for safe XPath. A 0.3.2 call such as `msg.get(expression="//x")` raises
    `TypeError`. **Migration:** pass those arguments by position, and bind message data as a
    `$variable` rather than formatting it into the expression. (`BACKLOG #1049`)
  - `messagefoundry.parsing.validate()` no longer takes `profile=`. It was accepted and never read.
    **Migration:** drop the argument.
- **BREAKING — a Handler that returns anything but `Send`, `SetState`, `SetMeta`, an iterable of
  those, or `None` now fails the message.** In 0.3.2 an unrecognised item fell silently out of the
  result: returning the `Message` itself, a `str`, `bytes`, a `dict` or a `(name, msg)` tuple
  finalized the message `FILTERED`, and a stray item in a list was dropped while the `Send`s beside it
  were delivered. Each of those is now an `ERROR` (dead-lettered and replayable), and a list holding
  one bad item delivers nothing. A `None` *inside* a list counts as a bad item. The reverse also
  changed: a tuple or generator of `Send`s used to deliver nothing and now delivers. **Migration:**
  return only those types, and filter `None` out of a list you build conditionally (for example
  `[s for s in (a, b) if s is not None]`). (`BACKLOG #1687`)
- **BREAKING — a network intake now checks a non-HL7 body against the connection's declared content
  type.** In 0.3.2 only the File and remote-file sources checked it. Now a body on any listener or
  poller that contradicts its declared type is stored as `ERROR` and never routed: `json` or `fhir`
  must start with `{` or `[`, `xml` with `<`, `x12` with `ISA`, and `dicom` needs `DICM` at byte
  128. `text`, `binary` and `hl7v2` are not checked. An HTTP sender still gets `202`, but with no
  `message_id`. **Migration:** declare the content type the feed really sends, or `text` / `binary`.
  (`BACKLOG #1109`)
- **BREAKING — an `Http()` inbound bound off loopback now needs a peer control, or it refuses to
  start.** 0.3.2 checked only that an exposed HTTP listener used TLS, so an off-loopback intake with
  TLS and no caller identity passed. Under `[security].enforcement = enforce`, the default, the
  connection now starts only with one of: `intake_auth` (`api_key`, `bearer` or `mtls_subject` with
  subjects), or a `source_ip_allowlist` whose entries are no wider than /8 (IPv4) or /32 (IPv6).
  `tls` with `tls_ca_file` alone does not count, and `--allow-insecure-bind` does not waive it. Only
  that connection fails. **Migration:** add `source_ip_allowlist=[...]` to the `inbound(...)` call,
  or set `intake_auth="api_key"` with `intake_api_key=env(...)`. (ADR 0154)
- **BREAKING — two new default limits on the MLLP listener.** `max_connections_per_host` (32)
  refuses the 33rd concurrent connection from one source address, and `max_frame_seconds` (60)
  closes a connection whose frame has not finished 60 seconds after its start byte, with no ACK and
  no NAK. 0.3.2 had neither. Behind a source-NAT proxy or load balancer every partner arrives as one
  address, so 32 becomes the whole listener's capacity. A large frame on a slow link (below about
  2.2 Mbit/s for the 16 MiB frame cap) never completes, and the sender resends it. **Migration:**
  set `MLLP(max_connections_per_host=None)` behind NAT, and raise `max_frame_seconds` whenever you
  raise `max_frame_bytes` or serve a slow link. (`BACKLOG #1725`)
- **BREAKING — `DatabasePoll` now reads at most 500 rows per poll (`poll_max_rows`).** In 0.3.2 a poll
  fetched every row. Rows past the 500th wait for the next poll, which picks them up only if
  `mark_statement` takes each handled row out of `poll_statement`'s result. With no
  `mark_statement`, or one that does not remove rows, the same 500 rows come back every poll and the
  rest are never read. A mark keyed on a column that is not unique to one row can mark unread rows
  as done. The File, FTP and SFTP pollers' new `poll_max_files` (500) only delays unread files.
  **Migration:** key the mark on one row, or set `poll_max_rows=None` to fetch every row as before.
  (`BACKLOG #1114`)
- **BREAKING — at startup, the backlog of an inbound connection that is no longer configured is
  dead-lettered.** In 0.3.2 its ingress, routed and response rows stayed pending, and resumed if the
  connection came back. Now each is marked dead ("inbound removed from registry"), the message
  becomes `ERROR`, and dead-letter retention applies. **Migration:** before removing or renaming a
  busy inbound, let it drain. After a restart, replay the dead-lettered messages once the inbound is
  back. (`BACKLOG #1612`)
- **BREAKING — `zip_decompress` refuses more archives.** An archive with two members of the same
  name, an unsafe member name, or a member whose content contradicts its file extension (`.hl7`,
  `.json`, `.xml`, `.pdf` and others) now raises `CompressionError`. In 0.3.2 the last duplicate
  won and any member was accepted. **Migration:** fix the archive at its source.
  (`BACKLOG #1128`, `#1581`)
- **BREAKING — an HTTP-family reply over 16 MiB now fails.** 0.3.2 read a partner's response with no
  size limit. A REST, SOAP, FHIR or DICOMweb delivery whose reply is larger than 16 MiB now raises
  `ResponseTooLargeError`, which is retried and then dead-lettered. A `fhir_lookup` reply over the cap
  raises inside the Handler, so under the default `internal_error = "continue"` that message goes
  to `ERROR` with no retry. An OAuth2 or SMART token
  response is capped at 256 KiB. There is no setting to raise either ceiling. **Migration:** none in
  configuration; the partner must send a smaller reply. (ASVS 15.2.2)
- **BREAKING — `File(sort=)` accepts only `"name"` or `"mtime"`.** In 0.3.2 any other string, such as
  `"Name"` or `"size"`, silently gave name order. It now fails the connection at build.
  **Migration:** `sort="name"`. (`BACKLOG #1655`)
- **BREAKING — an `env()` value that `connections.toml` reads with `cast = "bool"` now honours its
  spelling.** When the value arrives as text (a `MEFOR_VALUE_*` variable, or a quoted value in
  `environments/<env>.toml`), 0.3.2 cast it with Python's `bool()`, so `"false"`, `"0"`, `"no"` and
  `"off"` all became `true`, and only an empty string became `false`. Those four spellings now give
  `false`, and an empty or unrecognised value refuses at load. **Migration:** use one of `true`,
  `1`, `yes`, `on`, `false`, `0`, `no` or `off`, and check each such value still means what you
  intended. (`BACKLOG #1651`)
- **BREAKING — `serve` refuses a config directory that declares no connections.** In 0.3.2 a
  directory with no inbound and no outbound loaded, served an idle engine, and passed
  `messagefoundry check`. `serve` now refuses it, with no opt-out, and `check` fails on it unless
  given the new `--allow-empty-config`. **Migration:** declare at least one connection before
  `serve`; pass `--allow-empty-config` to a `check` run over an intentionally empty directory.
  (`BACKLOG #1648`)
- **BREAKING — the engine API always serves HTTPS, and mints a self-signed certificate on first run
  when none is configured.** 0.3.2 served plain `http://127.0.0.1:8765` unless `[api].tls_cert_file`
  was set. 0.4.0 serves `https://` on the same address. With no certificate configured, it writes
  `api-generated-cert.pem` and `api-generated-key.pem` beside the store database on first start and
  reuses them. That certificate names only `[api].host`, so `https://localhost` fails the host-name
  check. The only plaintext topology left is a declared reverse proxy terminating TLS in front
  (`[api].tls_terminated_upstream`). `messagefoundry.apiclient` still defaults to
  `http://127.0.0.1:8765`, which a default 0.4.0 engine no longer answers. Off loopback, the client
  now refuses to send a password or token over plain `http` even with `allow_insecure=True`, where
  0.3.2 sent it with a warning.
  **Who this bites:** every script, `curl` call, monitoring probe, `ws://` stats client and
  `EngineClient()` built with default arguments. **Migration:** use `https://127.0.0.1:8765` and
  trust `api-generated-cert.pem` (for example `curl --cacert`, or `EngineClient(url, cacert=...)`),
  or set `[api].tls_cert_file` and `[api].tls_key_file` to a certificate your clients already trust.
  (`docs/adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md`,
  `BACKLOG #1276`, `#1179`)
- **BREAKING — search criteria that can carry patient data left the query string, and the old form
  now returns more, not less.** `GET /messages/search`, `GET /messages/export` and
  `GET /uploads/{file_id}/messages` no longer declare `content` or `field_value`, and an undeclared
  query parameter is dropped silently. So a 0.3.2 call with `content` alone answers `400`, a call
  with `field_path` and `field_value` matches every message that merely has that field (and export
  streams them), and the uploads browse lists the whole file unfiltered. **Migration:** send the
  criteria in the JSON body of `POST /messages/search`, `POST /messages/export` or
  `POST /uploads/{file_id}/messages/search`. (`BACKLOG #1184`)
- **BREAKING — list and search responses mask the message summary and metadata.** `GET /messages`,
  both message searches, `GET /dead-letters` and the layered search now return `summary` and
  `metadata` masked for display (for example `MRN ****0001`). Only `GET /messages/{id}` reveals them,
  which needs `messages:view_raw` and spends the PHI-read budget. No setting turns the mask off.
  **Migration:** fetch each message you need in full with `GET /messages/{id}`.
  (`BACKLOG #1187`)
- **BREAKING — `GET /uploads` is paged and owner-scoped, and files uploaded under 0.3.2 are visible
  only to administrators.** It now returns at most `limit` files (default 50, up to 500) from
  `offset`, with `total` counting the whole visible set. A caller sees only its own uploads unless it
  holds `files:access_any` (Administrator). A 0.3.2 upload's metadata has no owner id, so it matches
  no ordinary user, and browsing, resending or deleting it answers `404` for them. **Migration:** page
  with `offset` until you reach `total`, and have an administrator handle files uploaded before the
  upgrade. (`BACKLOG #1152`)
- **BREAKING — a connection name that does not match `^[A-Za-z][A-Za-z0-9_-]{0,255}$` can no longer
  be named through the API.** Such a name still loads and runs, but every `/connections/{name}/...`
  route, the connection filters on message, dead-letter and event queries, resend targets and
  channel-scope grants now answer `422` for it. So `ADT.In`, `Lab Results` or `2ndLab` cannot be
  started, stopped, tested, purged or filtered on. **Migration:** rename such connections to fit the
  pattern; stored history stays under the old name. (`BACKLOG #1108`)
- **BREAKING — three storage fields in the status response can now be `null`.**
  `DbInfo.disk_free_bytes`, `LogInfo.disk_free_bytes` and `LogInfo.size_bytes` were `int`. They are
  now `null` when the engine cannot measure them, which is always the case for `disk_free_bytes` on
  PostgreSQL and SQL Server, where 0.3.2 reported `0`. A 0.3.2 `messagefoundry.apiclient` fails to
  parse that response. **Migration:** treat the fields as optional, and upgrade API clients with the
  engine. (`BACKLOG #1563`)
- **BREAKING — a request that has not started its response after 120 seconds now answers `503`.**
  0.3.2 had no request deadline. A long integrity check, deep search or export on a large store can
  now hit it, and no setting raises it. **Migration:** narrow the request, for example with a smaller
  `limit` or `scan_limit`. (`BACKLOG #1044`)
- **BREAKING — in `messagefoundry.apiclient`, a JSON dump of a result withholds its patient-data
  fields.** Message, dead-letter, event and response models the client parses now emit `null` for
  `summary`, `error` and `metadata` under `model_dump_json()` or `model_dump(mode="json")`. Reading
  the attributes still works. **Migration:** read the attributes, or use a Python-mode
  `model_dump()`. (`BACKLOG #1045`)
- **BREAKING — a dual-control approval still pending from 0.3.2 cannot be approved.** Its row has no
  requester id, so approving it answers `409`. **Migration:** settle pending approvals before the
  upgrade, or reject and request them again after. (`BACKLOG #1540`)
- **BREAKING — on a store created by 0.3.2, saved searches and user deletion fail.** The
  `search_presets.owner` column was renamed `owner_user_id`, and the store upgrade does not rename it,
  so every preset call and `DELETE /users/{user_id}` fails with `no such column: owner_user_id`.
  Measured on SQLite: a store created by 0.3.2 fails both calls under 0.4.0, and a store 0.4.0
  created passes both. 0.3.2 also keyed presets on the username, where 0.4.0 keys them on the user id.
  **Migration:** until the upgrade handles it, drop the `search_presets` table before the first 0.4.0
  start; 0.4.0 creates it again, empty. Saved presets are lost. **On PostgreSQL and SQL Server, drop
  it before that start, never after.** Once a start has applied the 0.4.0 schema, those backends skip
  their table DDL. A table dropped later is not created again. If that happens, run
  `DELETE FROM schema_meta` and start once with DDL rights. SQLite creates it again at every start.
  (`BACKLOG #1232`)
- **BREAKING — on a store created by 0.3.2 with a keyed audit chain, the chain now reads as broken.**
  `audit_chain_meta` gains a `key_id` column that names the key of the chain's first keyed range. The
  upgrade adds the column empty and never fills it: ADR 0193 decision 2 built no path to fill it,
  because no store was deployed. A 0.3.2 chain is keyed once `rekey-audit` ran. It is also keyed if a
  store key or the Vault Transit MAC was present at an open while its audit log was empty. On such a
  store, `audit-verify` prints `FAIL:` and exits 1. It names the first keyed row, with the reason
  `the audit chain does not record which key its keyed range is under`. A broken keyless row below
  that one is reported first. `rekey-audit` prints `FAIL:` and exits 1 too. The startup check under
  `[integrity].audit_verify_on_start` reports the same break, and every open logs an ERROR. From the
  first keyed row on, the walk checks no MAC. Nor does it reach an `--expected-anchor` or
  `[integrity].audit_anchor_file` comparison, because the chain already reads as broken. With a local
  store key, the audit step of `rotate-key` refuses every time, as the BREAKING `rotate-key` entry
  under Fixed describes. Measured on SQLite with synthetic data: a store 0.3.2 created fails the
  verify under this release, and a store this release created verifies and rolls. PostgreSQL and SQL
  Server add the column the same way; that was read in the code, not run. A store with no key is not
  affected.
  **Migration:** none is built. Before the upgrade, run `messagefoundry audit-verify` under 0.3.2 and
  keep its output. It records that the chain verified up to that point, but it holds no head hash to
  check against later.
  (`BACKLOG #1904`, `docs/adr/0193-audit-chain-key-ranges-survive-a-store-key-rotation.md`)
- **BREAKING — the default retry limit is now 100 attempts, not unlimited.**
  `[delivery].retry_max_attempts` and `RetryPolicy.max_attempts` defaulted to `None` (retry forever)
  in 0.3.2. At 100, with the default backoff, a destination that stays down for about 7 hours 50 minutes
  dead-letters the message at the head of its lane, and the lane moves on. The dead-letter queue is
  replayable. A global or environment value of `0` now refuses at load. **Migration:** set
  `retry_max_attempts = "forever"` (or `MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS=forever`,
  `max_attempts = "forever"` in `[outbound.retry]`, or `RetryPolicy(max_attempts=None)` in code) to
  keep 0.3.2's behaviour, and replace `0` with `1`. (`BACKLOG #1051`)
- **BREAKING — if the application log cannot be written, the engine now stops its connections.** In
  0.3.2 a failed log write was reported to stderr and processing went on. Under the new default,
  `[logging].on_write_failure = "stop"`, the engine first rolls the log aside; if the replacement is
  unwritable too, it stops every connection the process owns, and delivery stays halted until the log
  is writable and the lanes are restarted. **Migration:** set `[logging].on_write_failure =
  "continue"` to keep running without a log record, which is reported as a loosening.
  (`BACKLOG #122`)
- **BREAKING — an expired store encryption key now stops the engine from starting.** In 0.3.2 an
  overdue store key only raised an alert. Under `enforce`, an encrypted store whose key is older than
  `store_key_max_age_days` plus `enforce_grace_days` (365 + 30 by default), or whose age cannot be
  determined, now refuses to start. Age runs from `[secret_rotation].store_key_last_rotated` if set,
  otherwise from the date the engine first saw that key. **Migration:** run `messagefoundry
  rotate-key`, correct `store_key_last_rotated`, or set `[secret_rotation].enforce_store_key_expiry =
  false`, which is reported as a loosening. (`BACKLOG #1004`)
- **BREAKING — message bodies are purged after 30 days on every instance that sets no retention
  window.** 0.3.2 kept bodies forever on an instance it did not treat as carrying patient data.
  Every instance does now, so each unset window among `[security].delete_message_bodies_after_days`,
  `[retention].dead_letter_days` and `[retention].reference_snapshot_days` defaults to 30 days, and
  the purge runs. `dead_letter_days` now also purges a dead row at the ingress and routed stages. An
  explicit `0` refuses to start under `enforce`. **Migration:** set each window explicitly, or set
  `[security].allow_keeping_phi_indefinitely = true` to keep bodies. (`BACKLOG #1279`, `#1188`)
- **BREAKING — behind a declared TLS-terminating proxy under `enforce`, startup now measures the
  proxy.** With `[api].tls_terminated_upstream` on, `serve` refuses to start without
  `[security].web_console_public_address`. It then connects to that address at startup and refuses
  unless the proxy is reachable, refuses TLS 1.0 and 1.1, and negotiates TLS 1.3. An IP-literal
  address is refused. **Migration:** set the address to the DNS origin browsers use, enable TLS 1.3 on
  the proxy, and start the proxy before the engine. (`BACKLOG #1026`)
- **BREAKING — on Windows, the config directory's owner is now checked.** 0.3.2 trusted the owner
  unconditionally. The owner must now be the service's run-as account, a well-known administrator
  identity, or a direct member of the local Administrators group, and an owner whose membership
  cannot be resolved is refused. A directory owned by an operator who is an administrator only
  through a domain group no longer loads. **Migration:** `icacls <config dir> /setowner
  "*S-1-5-32-544" /T /C`, or re-run the service installer with `-LockConfigDir`.
  (`BACKLOG #1647`)
- **BREAKING — `connections.toml` `[settings]` values must match their parameter's type.** A quoted
  number or boolean such as `port = "2575"` or `persistent = "yes"` loaded in 0.3.2 and is now
  refused, naming the connection and setting. So is an `env()` default of the wrong type, such as
  `{ env = "port", cast = "int", default = "16" }`. **Migration:** write numbers and booleans
  unquoted. (`BACKLOG #1650`)
- **BREAKING — two settings that 0.3.2 silently ignored now take effect.** `validate_directory =
  true` on a File or remote-file *outbound* now refuses to start the lane when the directory is
  missing, and nothing creates it; 0.3.2 created it on first write. `MEFOR_SANDBOX_MODE` is now read,
  so `subprocess` there runs Routers and Handlers in the sandbox, with its time and memory caps.
  **Migration:** create the directory first, or drop the setting; unset the variable if you did not
  mean it. (`BACKLOG #114`, `#1365`)
- **BREAKING — more settings are range-checked at load.** `[ai].provider` must be `"claude"`, the only
  provider the engine can serve. `[cluster]` timings now refuse a leader fence and lease TTL pair that
  leaves no detection margin (roughly, keep the TTL more than 2 seconds above the fence), whether or
  not clustering is on. `[store].db_schema` is refused on a backend other than PostgreSQL.
  **Migration:** correct each value the error names. (`BACKLOG #95`, `#1497`)
- **BREAKING — a rolling upgrade of a SQL Server cluster can elect two leaders, and a 0.3.2 node
  cannot verify a 0.4.0 backup.** The SQL Server lease key changed from
  `<db_schema, or dbo>:mefor_cluster_leader` to `mefor_cluster_leader`, so a 0.3.2 node and a
  0.4.0 node contend for different lease rows. A 0.4.0 backup manifest counts every table, and
  0.3.2's verifier compares it against its own four and fails. 0.4.0 still reads and restores a
  0.3.2 backup. **Migration:** stop every node, upgrade them all, then start; upgrade a DR standby
  before it seeds from a 0.4.0 primary.
- **BREAKING — the first 0.4.0 start on PostgreSQL or SQL Server runs the schema upgrade and needs
  DDL rights.** The PostgreSQL migration revision and the schema hash both moved, so the first open
  runs the whole DDL batch. The 0.3.2 runbook allowed revoking `db_ddladmin` after the first start;
  such a principal now fails to open the store, and `serve` refuses. **Migration:** grant DDL rights
  for the first 0.4.0 start, then revoke them again.
- **BREAKING — several CLI commands now fail where 0.3.2 reported success, or print differently.**
  - `messagefoundry check` exits 1 when fixtures exist but no dry-run ran, when a pinned `.expect`
    now reads `NOT_DEPLOYED`, and when a `messagefoundry.toml` is found but fails to load (0.3.2
    skipped that leg). (`BACKLOG #1671`, `#1318`)
  - `messagefoundry verify` fails, not skips, an unknown `--inbound` or a config with no inbound. It
    fails a missing SQLite store and a missing writable directory, which 0.3.2 created and then
    passed. The `host.console` check is gone. (`BACKLOG #1708`, `#1713`)
  - `messagefoundry backup`, and any caller of `open_store()`, no longer creates a missing SQLite
    store; `backup` exits 2 and `open_store` raises `StoreNotFoundError`. `serve` still creates it,
    and code that provisions a store passes `create=True`. (`BACKLOG #1780`)
  - `messagefoundry rotate-key` on a `vault_transit` store exits 2 instead of printing "re-encrypted
    0 value(s)" and exiting 0. (`BACKLOG #1165`)
  - Text-mode error lines now go to stderr, not stdout, for `alert`, `backup`, `codeset`,
    `connection`, `dryrun`, `graph`, `impact`, `import`, `init`, `lens`, `restore-verify` and
    `security`. (`BACKLOG #1673`)
  - `messagefoundry dryrun` prints the disposition `not_deployed` where 0.3.2 printed `filtered` for
    a message whose only destinations are not deployed. (`BACKLOG #1690`)
  - `messagefoundry --version` prints a second line, `package: <path>`.
    (`BACKLOG #1677`)
  - **Migration:** for all of the above, read each new failure as the real result it is; capture
    stderr (`2>&1`) or use `--json`; run `serve` once before `backup` or `verify` on a new install.
- **BREAKING — with `[integrity].fail_closed_on_drift = true`, an install the engine cannot attest
  now refuses to start.** In 0.3.2 an install with no `RECORD`, a stripped one, or code loaded from
  outside the install root was silently skipped even under fail-closed. It now raises
  `IntegrityError`. The default (`false`) is unchanged. **Migration:** install the non-editable wheel,
  or leave `fail_closed_on_drift` off. (`BACKLOG #1679`)
- **BREAKING — the forward proxy and the OAuth2 token host must now be on an egress allow-list.**
  A `proxy_url` other than `"default"` now needs its host in the new `[egress].allowed_proxy`, and an
  `oauth2_token_url` host must be in `[egress].allowed_http`; otherwise the graph refuses to load.
  **Migration:** add `[egress] allowed_proxy = ["proxy.example.org:3128"]` and the token host to
  `allowed_http`. (`BACKLOG #1659`)
- **BREAKING — the MLLP listener's automatic ACK now stamps MSH-7 with a UTC offset.** 0.3.2 wrote
  local time as 14 digits (`YYYYMMDDHHMMSS`). The ACK now writes `YYYYMMDDHHMMSS±ZZZZ`, which HL7
  allows and which pins the instant across a daylight-saving change. **Migration:** none in
  configuration; a partner or test that parses a fixed 14-digit MSH-7 must accept the offset.
- **BREAKING — an attachment download is served as `application/octet-stream` with a `.bin` name
  unless its type is on a short allow-list.** 0.3.2 passed through any type a browser would not run
  and took the extension from the host's type table. Now only `application/dicom`,
  `application/json`, `application/pdf`, `image/bmp`, `image/gif`, `image/jpeg`, `image/png`,
  `image/tiff`, `text/csv` and `text/plain` keep their type and extension; the bytes are unchanged.
  **Migration:** a client that files downloads by `Content-Type` or file name identifies other types
  from the bytes.
- **BREAKING — a few narrower refusals.** Each worked in 0.3.2:
  - `db_lookup` refuses a statement carrying a write keyword anywhere outside a literal, so a read
    with a `MERGE JOIN` hint, or an unquoted column named `merge`, is now refused. **Migration:**
    drop the hint or quote the name. (`BACKLOG #1574`)
  - `anonymize_checked()` and the anonymizer tooling refuse a salt with too little entropy, not just
    a short one. **Migration:** use a random salt; a new salt changes every pseudonym.
  - Under a pinned `[tls]` trust anchor, every off-loopback HTTP-family hop now uses it: REST,
    SOAP, FHIR and DICOMweb deliveries, `fhir_lookup`, and the SMART and OAuth2 token requests. In
    0.3.2 none of them read the anchor, so a partner or token endpoint on a public CA outside it now
    fails. **Migration:** add that CA to the anchor, or leave `[tls].trust_anchor_mode` at `system`.
    (`BACKLOG #1180`, `#1660`, `#1794`)
  - The 8 KiB limits on an outbound URL and header value are now checked at send time as well as at
    build, and a header name over 256 characters is refused. A per-message header or token that
    grows past them now fails the delivery; a `fhir_lookup` URL that does fails the Handler's
    message.
  - `messagefoundry codeset rename` validates the old name, so a code set whose file stem carries a
    dot, such as `lab.results`, can no longer be renamed with it. **Migration:** rename the file by
    hand.
  - DR activation on SQLite refuses a seed that restored nothing: a config-only seed, which 0.3.2
    activated, and a drill seeded from an empty primary. **Migration:** seed from a full backup of
    a primary that holds data. (`BACKLOG #1717`)
- **BREAKING — the `[vault]` clients no longer follow HTTP redirects.** 0.3.2 let the Vault client
  follow a redirect, carrying its token to the new location. A Vault address that answers with a
  redirect, such as a standby node pointing at the active one, now fails. **Migration:** point the
  `[vault]` address at the active node or at a load balancer that forwards rather than redirects.
  (`BACKLOG #1042`)

### Security
- **BREAKING — raising a session's authority now re-keys it: each of the five elevation steps
  issues a fresh session token and retires the old one.** Re-authentication (`POST /me/reauth`),
  MFA verification (`POST /auth/mfa-verify`), MFA enrolment (`POST /me/mfa/confirm`), and the web
  console's passkey registration and passkey second-factor step each rotate the session (ASVS
  7.2.4). So a token captured before the second factor is never elevated in place. The rotation keeps
  the session's MFA state, and the old token stops resolving at once, with no grace window.
  `/me/reauth` and `/auth/mfa-verify` now return `{"detail": ..., "token": ...}` where 0.3.2
  returned `{"detail": ...}`. `/me/mfa/confirm` returns `token` beside `recovery_codes`. All three
  responses are sent `Cache-Control: no-store`. The web console re-issues its own cookie. A rotation
  also closes an open `/ws/stats` socket at its next check, and the console falls back to polling.
  **Migration:** after any of those three calls succeeds, replace the stored bearer token with the
  response's `token`. A client that keeps the old one gets `401` on its next call and must sign in
  again. (`BACKLOG #1146`)
- **BREAKING — the per-channel scope is deny-by-default: an account with no channel scope now
  reaches no channel.** In 0.3.2 an empty (`NULL`) scope meant *all channels*, and every account was
  created with one, so the per-channel checks narrowed nobody. An empty scope now denies. *All
  channels* is a grant somebody types: the token `*`, stored as `["*"]`. Administrators still reach
  every channel through their role. `PUT /users/{user_id}/channel-scope` still accepts
  `{"channels": null}`, and it now means *no* channels, so a 0.3.2 client that sent `null` to grant
  everything now revokes everything. **Who this bites:** every non-administrator account carried over
  from 0.3.2. Its channel-scoped lists come back empty and its per-connection actions are refused.
  **Migration:** grant each such account its connections, or `{"channels": ["*"]}` for all of them,
  and change any client that sends `null` to send `["*"]`. (`BACKLOG #1152`)
- **BREAKING — TOTP codes are now computed with HMAC-SHA-256 instead of SHA-1, so every
  authenticator enrolled on 0.3.2 stops producing codes the engine accepts.** The engine stores no
  per-user algorithm, so this is a cutover, not a migration. An enrolled user just sees
  `invalid code`, with nothing else to say why. New enrolments advertise `algorithm=SHA256` in the
  `otpauth://` URI. Some authenticator apps ignore that parameter and compute SHA-1 anyway, and
  their codes never match. Recovery codes and passkeys from 0.3.2 still work. **Migration:** each
  TOTP user enrols again, in an app that honours the `algorithm` parameter. The simplest route is
  an administrator clearing the factor with `POST /users/{user_id}/reset-mfa`; an administrator
  cannot reset their own. Otherwise the user signs in with a 0.3.2 recovery code, registers a
  passkey, removes the TOTP factor (`DELETE /me/mfa` refuses to remove the last factor while MFA is
  required) and enrols again. A sole administrator whose only factor is TOTP must take that route.
- **BREAKING — a Windows (Kerberos) sign-in now starts MFA-pending, and a directory account may enrol
  an engine second factor.** In 0.3.2 the Kerberos leg marked the session MFA-satisfied on the
  directory's behalf, so an AD user never met the engine's MFA gate. The engine never receives that
  assertion, so it no longer grants it. With `[security].require_mfa` on, which is the default, a
  Kerberos session is held to the MFA-exempt routes until the user completes an engine factor, and
  `POST /auth/negotiate` now reports `mfa_required: true` for it. **Migration:** each AD user enrols
  TOTP or a passkey at their first 0.4.0 sign-in (enrolment is now open to directory accounts) and
  completes it at each sign-in after that. (`BACKLOG #1144`)
- **BREAKING — security notices now go to an engine-owned address that a directory sign-in does not
  change.** In 0.3.2 one column was both the profile email and the address every out-of-band
  security notice went to, and each AD or OIDC sign-in overwrote it with the directory's value. The
  new `users.notify_email` column is seeded once from the account's email, at upgrade and at account
  creation. After that, only an administrator's `PATCH /users/{user_id}` with a non-blank `email`
  moves it. So after the upgrade a directory repoint no longer redirects notices, and clearing an
  account's email no longer stops them. `UserSummary` gains a read-only `notify_email`.
  **Migration:** when a directory account's address changes, also set it with `PATCH
  /users/{user_id}`, and read `notify_email`, not `email`, to see where notices go.
  (`BACKLOG #1139`, `docs/adr/0182-split-the-account-mirror-address-from-the-engine-owned-notification-address.md`)
- **BREAKING — under `enforce`, the engine refuses to start unless an enabled Administrator has a
  notification address.** 0.3.2 checked only that an SMTP transport was configured, so notices about
  the most privileged accounts could go nowhere. With `[auth].notify_security_events` and
  `[alerts].security_notifications_required` on, both defaults, startup now fails if no enabled
  Administrator has a `notify_email`. **Migration:** before upgrading, give at least one enabled
  Administrator an email address (0.4.0 copies it into `notify_email` at upgrade), or set
  `[alerts].security_notifications_required = false`. (`BACKLOG #1020`)
- **BREAKING — three sensitive actions now need a re-authentication bound to that one action.**
  `DELETE /me/sessions` and `DELETE /me/sessions/{id}`, `POST /users/{user_id}/reset-password` and
  `POST /users/{user_id}/reset-mfa` were satisfied in 0.3.2 by any recent step-up. Each now needs a
  single-use grant. Without one the call answers `403` with an `X-Step-Up-Action` header naming the
  action. `reset-mfa` on the caller's own account now answers `400`. **Migration:** before each call,
  send `POST /me/reauth` with `purpose` set to that header's value (`session_terminate`,
  `admin_reset_password` or `admin_reset_mfa`), and adopt the new token it returns. Another
  Administrator resets your own MFA. (`BACKLOG #1148`, `#1149`)
- **BREAKING — revocation checking reaches more hops, and the blanket attestation no longer waives
  it under `enforce`.** In 0.3.2 the process-wide `MEFOR_TLS_REVOCATION_ATTESTED=1` let every verified
  outbound TLS hop through the revocation refusal. Under `enforce` it now does not, and no
  per-connection attestation can be written in config. So an off-loopback verified outbound hop
  needs an in-engine CRL check. The syslog TLS forwarder, the SMART token hop and the remote
  PostgreSQL store hop are now guarded too. An inbound MLLP, HTTP or DICOM listener that requires
  client certificates (`tls` with `tls_ca_file`) and loads no CRL now refuses to start, on loopback
  as well. **Migration:** set `[tls].crl_file` (a PEM with the CA and its CRL) for outbound hops,
  `[logging].forward_tls_crl_file` for the syslog forwarder, `[store].ssl_crl_file` for PostgreSQL,
  and `tls_crl_file=` on each mTLS listener; or run with `[security].enforcement = "warn"`.
  (`BACKLOG #299`, `#1005`)
- **BREAKING — SMTP connections now verify the server certificate.** 0.3.2 called `starttls()` with
  no TLS context, which checks neither the certificate nor the host name. `Email()`, `SMTP()`,
  `Direct()` and the alert and security-notice mailer now verify both by default (`tls_verify`,
  `tls_check_hostname`, `[alerts].email_tls_verify`). A relay with a self-signed or private-CA
  certificate, or one reached by an address its certificate does not name, now fails: deliveries
  retry and dead-letter, and alert mail stops. Under `enforce`, `[alerts].email_use_tls = false` or
  `email_tls_verify = false` now refuses to start. On any posture, alert and security-notice mail
  with `email_use_tls = false` and an `email_username` now fails at send rather than sending the
  password in cleartext.
  SMTP login now offers only `PLAIN` and `LOGIN`, so a relay that accepts only `CRAM-MD5` refuses
  it. **Migration:** point `tls_ca_file` (per connection), `[alerts].email_tls_ca_file` or
  `[tls].internal_ca_file` at the relay's CA, and reach it by the name on its certificate. For alert
  mail only, `[security].allow_unverified_alert_smtp_tls = true` is the audited opt-out.
  (`BACKLOG #323`)
- **BREAKING — `MEFOR_ALLOW_INSECURE_TLS` no longer lets a cleartext hop cross, and three more
  cleartext or unverified hops are refused.** In 0.3.2 that variable let an off-box `http://` REST,
  SOAP, FHIR, DICOMweb or `FhirLookup` hop, or a credential sent over one, cross with a warning when
  enforcement was off. Only a per-connection `cleartext_accepted` with `cleartext_reason` does that
  now (`docs/adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md`).
  A plain-`http` SMART token endpoint is refused even under `enforce`. An off-loopback
  generic-dialect `DatabasePoll` or database hop with no TLS refuses under `enforce`; an outbound
  can declare `cleartext_accepted`, a `DatabasePoll` cannot. An LDAPS directory with
  `ad_tls_verify = false`, which `MEFOR_ALLOW_INSECURE_TLS` let start in 0.3.2, no longer starts
  under `enforce`. `[logging].forward_hop_attested = true` now needs `forward_hop_attested_reason`.
  **Migration:** use TLS, or declare `cleartext_accepted = true` with a reason on each hop you accept;
  give the directory a CA with `ad_tls_ca_cert_file`; add the reason.
- **BREAKING — weaker algorithms and short keys are refused.** Each of these worked in 0.3.2:
  - HTTP Digest now accepts only `SHA-256` and `SHA-512-256`. A challenge naming `MD5`, or naming
    no algorithm (which means MD5), fails every send. (`BACKLOG #1171`)
  - An RSA key under 2048 bits is refused for JWS and SMART signing, and for a `Direct()` S/MIME
    key, the partner's `recipient_cert` and the `trust_anchor`. A `Direct()` EC key must be on
    P-256, P-384 or P-521. (`BACKLOG #1166`)
  - XML signature verification refuses SHA-224 and SHA3-224 digests. (`BACKLOG #1171`)
  - A new passkey whose authenticator offers only RS256 cannot be registered; TPM-backed Windows
    Hello is that group. Passkeys registered on 0.3.2 still work. (`BACKLOG #1166`)
  - `[api].tls_ciphers` must now resolve only to suites on the approved list, so a string that
    reaches a CBC suite, or `DHE-RSA-CHACHA20-POLY1305`, refuses at load. (`BACKLOG #1317`)
  - The Vault key provider refuses a Transit key whose type is weaker than the floor, such as
    `rsa-2048`. (`BACKLOG #1166`)
  - SFTP now offers only SHA-2 ETM MACs with AES-CTR or AES-GCM; 0.3.2 passed no restriction, so
    a server offering only older MACs or CBC ciphers now fails the handshake. (`BACKLOG #1170`)
  - **Migration:** for all of the above, the partner or key owner must offer the stronger option:
    SHA-256 Digest, a key of 2048 bits or more, an ES256 passkey on P-256 or an EdDSA passkey (or
    TOTP), `tls_ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20"`, an AES or RSA-3072 Transit key. There is
    no setting that re-admits them.
- **BREAKING — a new ES256 passkey must use the P-256 curve.** 0.3.2 also registered an ES256
  passkey on P-384 or P-521. Registration now refuses one. This is not a strength rule: those keys
  verify and are strong enough. It follows the pairing RFC 9053 recommends, SHA-256 with P-256
  only, which is also how the WebAuthn specification describes ES256. A passkey already registered
  on another curve still signs in. **Migration:** register an ES256 passkey on P-256 or an EdDSA
  passkey, or use TOTP. (`BACKLOG #1166`)
- **BREAKING — directory sessions are now rechecked every 5 minutes by default.** In 0.3.2
  `[auth].ad_session_recheck_seconds` defaulted to `0`, so a signed-in AD user's session was never
  checked against the directory again. The default is now `300`: each pass looks the signed-in AD
  users up in the directory (up to 200 per pass), and after two consecutive passes in which the
  directory no longer returns an account, its sessions are revoked. **Migration:** set
  `[auth].ad_session_recheck_seconds = 0` to turn it off, which is reported as a loosening.
- **BREAKING — editing an AD group map signs out every AD session, the caller's included.** In 0.3.2 a
  change to `PUT /ad-group-map` or `PUT /ad-group-scope-map` took effect at each AD user's next
  sign-in. Both now revoke every live directory session at once, as the other authorization setters
  already did. **Migration:** a script that edits a map as an AD user signs in again before its next
  call. (`BACKLOG #1154`)
- **BREAKING — `DELETE /me/mfa` refuses to remove the last second factor while MFA is required.**
  0.3.2 allowed it. It now answers `400`. **Migration:** enrol another factor first, or have another
  administrator reset it. (`BACKLOG #1022`)
- **BREAKING — an unclaimed bootstrap administrator now expires under
  `[auth].initial_password_expiry_hours` too.** 0.3.2 exempted it from that clock and left it to
  `bootstrap_expiry_hours`, so `bootstrap_expiry_hours = 0` kept it alive indefinitely. It now also
  dies 72 hours after it was issued, by default. **Migration:** claim the bootstrap account before
  the upgrade, or set `[auth].initial_password_expiry_hours = 0`. (`messagefoundry provision-admin`
  helps only on a fresh store: it refuses once an enabled Administrator exists.)
  (`BACKLOG #1245`)
- **BREAKING — the OIDC id_token is checked more strictly.** A token whose `typ` header is present
  and is not `JWT`, a token without `iat` or `sub`, and a token carrying an `events` claim are now
  refused. `[auth].oidc_flow_ttl_seconds` must be between 30 and 1800. **Migration:** correct the
  identity provider's token profile, and set the flow TTL inside that range.
- **The web console's step-up actions would have refused an MFA-pending session without the audit
  row the console's other MFA refusals write.** `require_ui_step_up` and `require_ui_step_up_action` switched off
  `require_ui`'s second-factor gate to keep their `/ui/reauth?next=` continuation, then refused a
  pending session with a bare redirect of their own. On a first deployment with
  `[security].require_mfa` on, which is the default, a stolen password-only session cookie would have
  probed all 42 step-up route gates and left no `auth.mfa_denied` row. The same switch put the
  permission check first, so the refusal would also have shown which of those permissions the account
  holds, and it spent the account's admin-write budget before refusing. The gate now refuses, audits
  and orders its checks as it does on every other `/ui` route. Only where it sends the browser
  differs. The JSON API was never affected. (`BACKLOG #1542`)
- **The web console's message editor would have opened the raw body to a custom role holding
  `messages:edit` without `messages:view_raw`.** `GET /ui/messages/{id}/edit` and
  `POST /ui/messages/{id}/edit-resend` gated on `messages:edit` alone, while the JSON handler they
  call in-process (`GET /messages/{id}`, `require_phi_read(messages:view_raw)`) has its own gate
  skipped by that direct call — so the console re-asserted a *different* permission than the one it
  stood in for. Both verbs now require **both** permissions and fail closed on either, and both charge
  the per-actor PHI-read budget (`require_ui_step_up` gained `phi=`). Custom-role minting is
  deliberately unchanged: `messages:edit` is still not in `CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`, so a
  role meaning "may resubmit, must not read" remains mintable — it simply cannot open an editor that
  displays the body it edits. **Who this would bite:** a deploying org whose admin had minted such a
  custom role; that role would have exceeded its stated scope (HIPAA minimum-necessary) on first
  deployment. No built-in role reaches it — `ADMINISTRATOR` and `OPERATOR` grant both permissions —
  and every such read was already audited. (`BACKLOG #324`)
- **A dual-control release now re-checks the person who asked for it (ASVS 8.3.2).** A held
  request can wait hours for its second approver, and the requester's authority can be withdrawn in
  that time. `POST /approvals/{approval_id}/approve` now answers `409` when the requester's account
  is gone or disabled, no longer holds the operation's permission (`messages:replay`,
  `messages:purge` or `config:deploy`), or has left the channel scope the operation needs. The
  refusal writes an `approval.stale_requester` audit row and raises the `approval_stale_requester`
  alert. The request stays pending, so an approver can reject it. The check reads the engine's own
  copy of the account, so a change made only in Active Directory counts once it reaches that copy.
  (`BACKLOG #289`)
- **Three more admin writes now count against the per-account write limit (ASVS 2.4.2).**
  `PATCH /logging/level`, `DELETE /search/presets/{preset_id}` and `POST /alerts/test-email` were
  not rate-limited. They now share the budget the other paced admin writes draw on: past 12
  writes a second from one account, each answers `429` with `Retry-After: 1`. A client that stays
  under the limit sees no change. `[auth].admin_write_rate_limit_per_actor` and
  `admin_write_rate_limit_window_seconds` set the limit, and `admin_write_rate_limit_enabled =
  false` turns it off for every paced write. (`BACKLOG #287`)
- **A keyed store whose audit chain is keyless is now reported, and `provision-admin` refuses to
  start a chain without the store key.** A store that had audit rows before it had a key keeps a
  keyless chain: a keyed open keys only an empty audit log. Anyone able to write `audit_log` could
  then forge a row that verifies clean, and 0.3.2 said nothing. A 0.3.2 store created without a key
  and given one later is in that state. Such a store now logs a WARNING at each open naming
  `messagefoundry rekey-audit`, and `GET /security/posture` lists the loosening
  `audit_chain_unkeyed`. To clear it, stop the engine and run `messagefoundry rekey-audit` with the
  key set. `provision-admin`, new in this release, writes a store's first audit row, so it applies
  the at-rest check `serve` applies. Before it asks for the password, it refuses unless it can see the
  store key: `MEFOR_STORE_ENCRYPTION_KEY` in its own shell, or `[store].encryption_key_file`. Under an
  audited keyless opt-out it goes ahead, with a warning on stderr. It also refuses when a key is
  configured but `[store].key_provider` resolved none. That check runs after the password prompt,
  once the store is open (on SQLite, once it is created). (`BACKLOG #1905`)

### Fixed
- **The load harness's no-loss reconcile failed a run for being SLOW, and ejected pull requests from
  the merge queue.** Three of its detectors were fractions of the volume the phase OFFERED —
  `read >= sent // 2` (the intake floor), `timeouts <= max(connections, 3 * sent // 4)` (the
  stranding budget) and `acked >= sent // 4` in `tests/test_load_runner.py`. An open-loop phase paces
  sends by the wall clock, so `sent` reaches its nominal count whatever the host serviced, and all
  three reduce to "this runner confirmed at least X percent of the offered rate": a throughput
  reading wearing a loss label. Two unrelated pull requests were ejected inside twenty minutes on
  windows-2025 `merge_group` runs (`engine_read 36 < intake floor 45` with every delivery arriving;
  and 90 sent / 11 acked / 79 timeouts) while the same heads were green on the same leg as
  `pull_request` — a filed split of 2 reds in the last 40 `merge_group` runs against 0 in the last
  40 `pull_request` runs. **Why the trigger matters is not established**: hosted runners are one VM
  per job, so pull requests do not share one, and all that is known of the difference is that the
  queue launches entries in batches. The fix deliberately does not rest on a mechanism. Earlier work
  on this test swept offered rate across three runner SKUs and measured stranding at 0 percent at
  60/s, 150/s and 300/s alike — it never varied the trigger, which is the discriminator.
  **The replacements are engine invariants rather than tuned numbers.** `sent == acked + nak +
  timeouts`, so the existing shortfall check with the excusal made unconditional is exactly
  `read >= acked + nak`: every message the engine replied to must have an ingress row. Both reply
  paths commit before they reply (an accept-ACK follows `enqueue_ingress`, a NAK follows
  `record_received`), so a reply with no row is a real defect, and this fails it at magnitude **one**
  under any stranding width and at any host speed. A systemic dead ACK path is caught on its
  signature instead of on a volume fraction: a run that offered messages and got back not one reply,
  neither accept-ACK nor NAK. **That closes a gap the retired floor recorded as open** — a dead ACK
  path's signature is a high read with no ACKs, which clears a floor on `read` by construction.
  **This is a NET RELAXATION, not a tightening, and the ledger of it is exact.** The shortfall check
  itself is unchanged while the run is inside the stranding budget and *looser* outside it, because
  cancelling the excusal used to demand `read >= sent` there; what is stricter is only the comparison
  against the retired floor, which is a different detector. Three things are no longer failed at any
  magnitude: an unconfirmed send that never reached the engine, a partial reply-path regression, and
  a partial timeout flood. Nothing in the harness can tell the first from a frame that never left the
  socket, since `sent` is counted at write-buffer time, and the second is the same shape. They stay
  visible as a heavily-stranded note on the report; the drain and rate SLOs are where a throughput
  verdict belongs.
  **Scope, stated so this is not read as closing the class.** Only the load runner's copy changes —
  the copy `tests/test_load_runner.py` exercises. The connscale and estate copies keep the
  offered-volume detectors, and a test now pins that divergence as deliberate rather than as drift.
  `tests/test_connscale_smoke.py::test_no_loss_reconciles_at_every_step` also reds on the same
  windows-2025 leg, and **this change does not fix it**: its failure (`engine_read 15 < confirmed
  sent 18`) is the exact-shortfall arm, which is untouched here, so its cause is a different one —
  either genuinely absent rows or a short `engine_read` sample, which is the question
  `harness/load/connscale/intake_audit.py` exists to settle per message.
  (`BACKLOG #1866`)
- **BREAKING — `audit-verify` accepted a zero-byte database, wrote a schema into it, and reported a
  clean chain of nothing.** The existing guard on `audit-verify` and `rekey-audit`, which the new
  `audit-anchor` shared, only asked whether the `--db` path *existed*. A zero-byte file exists and is a valid, empty SQLite
  database —
  what a `touch` in an install script, a failed copy or a log-rotation mistake leaves behind — so it
  walked past the guard, `open_store` migrated 372,736 bytes of schema **into the file that was
  meant to be the evidence**, and the command printed `OK: verified 0 audit row(s)` and exited 0. A
  scheduled compliance job reads the exit code, so a first deployment with one would have reported
  OK forever while the real audit log went unchecked. All three subcommands now probe the path over
  a **read-only** SQLite handle before the store opens — it can neither create the file nor migrate
  it — and exit **2** when there is no `audit_log` table. The message tells the cases apart: no file,
  a database with no `audit_log` table, or a file that is not a database.
  **`audit-verify` also splits "verified nothing" out of its success code:** a clean walk over an
  empty log is now exit **3**, and `--allow-empty` (new) turns that back into 0, as does an expected
  anchor of `0:`, which asserts emptiness and is checked. Exit 1 stays a BROKEN CHAIN, so a job can
  no longer read an empty log as detected tamper. `audit-anchor`, new in this release, exits 0 on a
  real store whose log is legitimately empty — sealing a fresh instance as `0:` is a supported workflow — and refuses
  only the non-audit-database paths.
  **Migration:** on an empty log, a scheduled `audit-verify` job now gets exit 3 where 0.3.2 gave
  it 0. If an empty log is expected, as on a new instance, pass `--allow-empty`. Not
  `--expected-anchor 0:`, which is an exact seal and fails once the log gains a row. Anywhere else,
  treat 3 as a finding. `audit-verify` and `rekey-audit` now
  exit 2 on a SQLite `--db` with no `audit_log` table, a zero-byte file included. A file that is not
  a database also gets exit 2. Check that each job names the live store. (`BACKLOG #1669`)
- **BREAKING — a store key rotation broke the audit chain; `rotate-key` now carries the chain to the
  new key, and it and `rekey-audit` print and exit differently.** In 0.3.2 the audit chain's MAC key
  came from the active store key alone, and `rotate-key` never touched the chain. Take the rotation
  `docs/PHI.md` describes: new key active, old key retired, `rotate-key`, drop the old key. After it,
  `audit-verify` reported the chain broken at its first keyed row, for good once the old key was
  gone. `rekey-audit` still printed `OK`. The keyed chain is now a series of ranges, one per key.
  `rotate-key` verifies the whole chain, then appends one `audit.key_epoch` row under the new key.
  That row records a digest of the range it closes, the link to the row before that range, and a tag
  made with the outgoing key. So the old range stays provable after its key is dropped. No existing
  row is rewritten, so the off-box tee stays consistent and an `[integrity].audit_anchor_file` prefix
  stays valid. Until `rotate-key` runs, new audit rows stay under the retired key, and each open
  warns not to drop it.
  **Output and exit codes.** `rotate-key` now prints a second stdout line: `OK:` and the audit step's
  result. When the audit step refuses, the first line starts `PARTIAL:` instead and stderr names the
  reason. No range row is written, and the exit code is 1, although the data re-encryption before it
  has completed. The audit step refuses, at least, on a chain that does not verify and on key ranges
  that do not authenticate. It also refuses to rotate back to a key that keyed an earlier range. It
  refuses, too, when an audit row lands during the roll because the engine was left running.
  `rekey-audit` on an already-keyed chain now verifies it. It prints `OK:` with the result, or `FAIL:`
  and exits 1 when the chain does not verify; 0.3.2 printed `OK` without checking.
  **Migration:** stop the engine before `rotate-key`, and rotate to a new key, never back to an
  earlier one. Read the exit code, and keep the retired key configured until `rotate-key` exits 0. A
  keyed store created by 0.3.2 never reaches exit 0; see the BREAKING keyed-audit-chain entry under
  Changed. (`BACKLOG #1904`, `docs/adr/0193-audit-chain-key-ranges-survive-a-store-key-rotation.md`)
- **BREAKING — `verify --smoke self` reported PASS on a synthetic message the config would have
  dropped.**
  `smoke_self` failed only on `DryRunResult.error`, which `dry_run` sets for a parse failure, a
  strict-validation failure or a Router/Handler raise. `UNROUTED` (the Router selected no handler) and
  `FILTERED` (Handlers ran and sent nothing, including a sole destination that is
  present-but-not-deployed) carry `error=None`, so the disposition was written into the row's summary
  and never gated on. A deploying site whose Router matched nothing, or whose only outbound was not
  yet deployed, would read a green acceptance report off a message the engine would have dropped. The
  row now PASSES only on a delivering outcome and otherwise FAILs, naming the disposition and the
  handler/delivery counts. That is the verdict `_classify_disposition` already reaches for the **live**
  smoke on the **same** synthetic message, so the two halves of `verify` no longer answer one question
  two ways; an unrecognised disposition fails closed instead of falling through to PASS. **Visible
  change:** a config whose Router declines the fixed synthetic `ADT^A01` from `MAINHOSP` now reds this
  row, and the failure text says to point `--inbound` at a connection that takes one. The happy-path
  test asserted `"deliveries=" in detail`, which `deliveries=0` also satisfies, so neither the defect
  nor the `FAIL` branch had a covering test; both do now.
  **Migration:** read a FAIL on this row as a real result. If the Router declines the synthetic
  message, pass `--inbound` naming a connection whose Router takes an `ADT^A01` from `MAINHOSP`, or
  fix the Router or Handler. If every destination the Handler sends to is not deployed, deploy one.
  (`BACKLOG #1707`)
- **The shipped VS Code snippet generated a FHIR lookup the engine now refuses.** The
  `meforfhirlookup` snippet built its search by concatenating a message field into a flat `?`-query —
  the form removed along with `[egress].fhir_require_structured_params` — so the snippet emitted a
  Handler that raises on first use. The `FhirLookup` docstring, the `fhir_lookup` docstring and the
  Steps palette taught the same removed form. All now use the per-value-encoded `params=` form; the
  read-by-id form is unchanged. **Why it shipped broken:** nothing read that file. A new test parses
  every shipped snippet body and asserts none teaches the removed form — a test that merely checked
  the JSON parses would not have caught it.
  (`docs/adr/0043-fhir-read-lookup.md`)
- **BREAKING — a CR/LF inside an exception message could forge a whole log line on the text sink.**
  `ControlCharScrubFilter` escaped only the rendered message, and `logging.Formatter` appends a record's
  traceback (`exc_text`) and stack dump (`stack_info`) **verbatim** — so a newline-bearing exception
  string landed at column 0 on its own physical line, where a payload padded to the record layout was
  byte-indistinguishable from a real entry to an operator or a line-oriented SIEM parser. Both fields
  are now scrubbed too (ASVS 16.4.1; the residual ADR 0034 §1 disclosed, `BACKLOG #335`). **Visible
  change:** a traceback is *not* collapsed onto one line — its line breaks are kept and every line is
  indented with `    | `, so it stays readable while no line of it can start at column 0. A log parser
  keyed on `Traceback (most recent call last):` at the start of a line needs that prefix added. The
  JSON sink is unchanged in substance (`json.dumps` already escaped these fields); its `exception`
  and `stack` values now carry the same indent.
  **Migration:** a log parser or SIEM rule that reads a traceback or stack line from column 0 must
  first strip the `    | ` prefix, on the text sink and in the JSON `exception` and `stack` values.
- **The DICOM C-STORE SCP's fail-closed refusal named a settings key that does not exist.** It told
  the operator to set `[inbound].source_ip_allowlist`; `InboundSettings` has no such field and, in
  0.3.2, section models ignored unknown keys (they now refuse one, under the BREAKING unknown-key
  entry in Changed), so an operator following the engine's **own error message** wrote a key
  into `messagefoundry.toml` that was accepted and silently discarded — leaving a non-loopback SCP
  with no peer-IP gate while believing it had one. Aggravated by the construction gate *counting*
  controls: a `calling_ae_allowlist` (a caller-asserted AE Title with no cryptographic binding) plus
  the discarded key passed the check. The message now names the working surface — the `inbound(...)`
  keyword, which for a DICOM SCP is the **only** one, since `DICOM()` is not authorable in
  `connections.toml` — and distinguishes it from the `connections.toml` `[[inbound]]` key that *is*
  real, so a site running MLLP alongside DICOM cannot read it as licence to delete a working
  allowlist. The same wrong spelling is corrected in the module docstring, the gate comment,
  `config/wiring.py`, `config/settings.py`, `docs/SECURITY.md` and `docs/ASVS-L2-PHASE0-CHANGES.md`.
  Whether an AE-title list alone should keep satisfying that gate was tracked as **`BACKLOG #252`** — it
  is an ADR 0025 §9 contract change and was deliberately **not** decided in this fix. It has since been
  decided: see the BREAKING DICOM C-STORE SCP entry under Changed (`BACKLOG #316`).
- **Two startup gates described themselves against the deployment tier rather than the enforcement
  dial.** Comments on the managed-identity and security-notification gates read "refuse (production) /
  warn (non-production)" over branches that read `enforcing` — and `enforce` is the shipped default on
  `dev` and `staging` as much as on `prod`, so all three refuse. Comment-only, no behaviour change,
  but these are the comments two published documentation defects were copied from.
- **The load harness's no-loss reconcile did not enforce the `read >= sent // 2` intake guarantee
  0.3.2 documented.** The unconfirmed-send excusal was capped at `max(connections, half the run)`, but
  that `max()` takes the connection count as a *floor*, and every call site passes a connection count
  — so on a short, low-rate step (connscale-smoke's N=100 cell: ~105 sends, 100 connections) the count
  won the max() and the intake bound degraded to `read >= 5`, the very vacuity the cap exists to
  prevent. Nothing clamped the excusal to `sent` either, so `timeouts > sent` degraded it to
  `read >= 0`. In the connscale and estate copies the run-fraction cap still decides the systemic
  no-ACK verdict (it has since widened from half to three quarters of the run), and an
  **unconditional intake floor** the excusal cannot lower enforces `read >= sent // 2` at every call
  site. The load runner's copy had both as well, until the `#1866` entry above retired them there. The
  estate copy also gained the honest-reporting branch its two siblings had: it previously printed
  `read>=sent, …` on a bounded-excused run whose read was demonstrably below `sent`, and its
  over-budget detail string now matches connscale's — a test pins those two in step, since nothing
  enforced the claim that they were.
  *Known gap, unfixed in the connscale and estate copies:* their systemic no-ACK verdict is still gated
  on the same capped budget, so a dead ACK path that nonetheless delivered everything still passes
  when `connections >= sent`; an intake floor cannot catch a fault whose signature is a high read with
  no ACKs. The load runner's copy now catches it on that signature, under the `#1866` entry above.
- **BREAKING — `messagefoundry adr-analyze` exited 0 over an ADR directory that does not exist.**
  `Path.glob` yields nothing and raises nothing for a missing directory, so a missing, non-directory, or
  ADR-less `--adr-dir` produced zero reports and `AnalysisResult.ok = True` — the exact shape of a
  clean run. Withdrawing the ADRs would have silently turned a failing advisory check into a
  passing one. `AnalysisResult` now carries an `error` field, set to a line naming the directory
  when it is missing, is not a directory, or holds no file matching the ADR glob; discovery also
  drops a directory that happens to be named like an ADR, which the glob alone would have matched.
  **Visible change:** `adr-analyze` now exits **2**, with or without `--strict`, when there is no
  corpus to analyze — the same "could not start" code the CLI's other subcommands already spend on
  a store that fails to open, and distinct from `--strict`'s own coverage-gap exit of 1. `--json`
  output gains a permanent `error` key (`null` on a normal run), and `ok` is now
  `error is None and not coverage_gaps`. The error line says what was looked for, not why nothing
  matched: both `Path.exists` and `Path.glob` swallow `OSError`, so a directory the process cannot
  read is indistinguishable here from one that is absent, and a message guessing between them would
  send an operator after the wrong cause.
  **Migration:** `--adr-dir` defaults to `docs/adr` under the current directory. The installed
  package carries no ADRs, so run the command from the root of a source checkout, or pass
  `--adr-dir`. Exit 2 is also argparse's usage-error code. To tell them apart, run with `--json`: a
  missing corpus prints JSON with `error` set, and a usage error prints no JSON.
- **A passkey that could never sign in is now refused when it is registered.** A credential whose
  curve was unknown, whose point was not on its curve, or whose key type did not match its algorithm
  used to enrol and then fail at every sign-in. Registration now builds the key the way sign-in
  does, and refuses it there. A malformed key at either step used to answer `500`; it now lands on
  the audited invalid-input path. A passkey that can sign in is not affected.
  (`BACKLOG #1166`)

## [0.3.2] — 2026-07-28 — Early Access

A patch release for one adopter-facing defect shipped in 0.3.1, plus two gates that were passing
without being able to fail.

### Fixed
- **The scaffolded supply-chain gate named a repository adopters cannot read.** `messagefoundry init`
  writes a fail-closed CI gate that runs `gh attestation verify --repo …` on the pinned engine wheel
  before installing it. It named the retired private development vault rather than the public
  repository that actually mints the attestations, so **every project scaffolded by 0.3.1 shipped a
  provenance gate that fails on its owner's first CI run.** If you scaffolded against 0.3.1, either
  re-run `messagefoundry init`, or edit that one `--repo` argument in
  `.github/workflows/check.yml` to `MEFORORG/MessageFoundry`; setting the repository variable
  `MEFOR_VERIFY_ENGINE=off` skips the job entirely as a stopgap. The scaffold test had pinned the
  wrong value, so the defect was being actively enforced; it now also pins the negative.
- **The weekly vulnerability-metrics job measured an empty window instead of failing.**
  `vuln-metrics.yml` invokes `scripts/security/vuln_metrics.py` with no `--repo`, so the argparse
  default silently decided what was measured — and it named the same retired vault, whose Dependabot
  PRs a public token cannot read. All seven KPIs were computed over zero pull requests rather than
  erroring. The default is now `$GITHUB_REPOSITORY`, so the job measures the repository it runs in.
- **A partially-failed release could not be retried.** The GitHub release step failed when the tag or
  release already existed, so a publish that died midway (as 0.3.0's did) left no clean path forward.
  It is now idempotent.
- **The load harness's no-loss reconcile false-failed a demonstrably zero-loss run.** It excuses a
  send left unconfirmed at connection teardown, capped so a dead ACK path cannot pass as zero-loss —
  but the cap modelled legitimate stranding as "~one in-flight frame per connection". The sender
  keeps an unbounded in-flight window and paces open-loop sends by offered rate, so real stranding
  scales with rate × ACK-latency instead. A run that stranded 14 of 90 sends while the engine read
  and delivered every one of the rest was reported as message loss. The cap is now
  `max(connections, half the run)`, which keeps `read >= sent // 2` always required.

## [0.3.1] — 2026-07-27 — Early Access

### Security
- **BREAKING — multi-factor authentication is now an ACCESS gate, not only a step-up gate**
  (ASVS 6.3.3). An MFA-pending session is refused on **every** authorized route with `403` +
  `X-MFA-Required: 1`; a browser session is confined to the new `/ui/mfa` page until it verifies.
  Previously the second factor was demanded only at the step-up (sensitive-action) boundary, so a
  password-only session could read the whole estate.
  **`[security].require_mfa_scope`** (new, default **`every_local_account`**) widens who must enrol
  from the Administrator role to every local account; set it to `administrators` to keep the previous
  posture. It is reported as a loosening on `GET /security/posture` but never refuses to boot.
  **Who is affected on upgrade:**
  - **Existing sessions are unaffected until they expire** — they were minted MFA-satisfied and the
    stamp is honoured. The change bites at the next sign-in.
  - **Every un-enrolled local account must now enrol a factor before it can do anything else.** The
    escape path is reachable from the pending session itself (`/me/reauth` → `/me/mfa/enroll` →
    `/me/mfa/confirm`, or `/ui/account` in the browser), and confirming satisfies that same session.
    Note the consequence: for an un-enrolled account, whoever holds the password can self-enrol the
    second factor. The out-of-band `MFA_ENABLED` notification is the compensating control.
  - **Non-interactive local service accounts using bearer tokens will start failing** with
    `X-MFA-Required` and cannot enrol unattended. Move them to mTLS (`require_service_cert` is exempt
    by design) or to AD, or set `require_mfa_scope = "administrators"`.
  - **The PySide6 test harness** needs an enrolled account or `require_mfa_scope = "administrators"`:
    its API client only retries an `X-MFA-Required` refusal when an MFA handler is registered, and
    none is wired today.
  - **Caveat on factor strength:** a WebAuthn passkey is asserted at `user_verification=preferred`,
    so for a passkey-only account the second factor may be **device possession alone**. This is the
    owner-signed L3 relaxation, recorded in `docs/SECURITY.md`, not an oversight.
- **BREAKING (federated deployments only) — a directory session is no longer minted MFA-satisfied
  unconditionally** (ASVS 6.3.4). `_complete_ad_login` now takes the grant per mechanism: AD
  simple-bind and Kerberos still pass it under the owner-signed **delegated-directory-MFA
  relaxation** (the engine learns nothing about directory-side strength from a bind or a ticket),
  while the **federated (OIDC) leg passes `[auth].oidc_require_mfa_claim`** — the one directory
  signal the engine actually verifies. With the claim gate on (the default) nothing changes: a token
  carrying no configured `amr`/`acr` was already refused at claims validation. **With
  `oidc_require_mfa_claim = false`, federated sessions are now minted un-verified and refused** —
  turn the claim gate on, move those users to AD, or set `[security].require_mfa = false`, which
  remains the global off-switch.
  Also fail-closed: the directory exemption is now an **allow-list** (`provider == "ad"`) rather than
  a denylist (`!= "local"`), so an unrecognized provider value requires a second factor instead of
  silently skipping one.
- **New `auth.mfa_denied` audit event.** The MFA gate sits above the permission loop, so
  `auth.permission_denied` never fires for a pending session; without its own row a stolen
  password-only token could enumerate the entire authenticated surface leaving no trace.
- `ENGINE_UI_SEAM` 13 → 14 — `api.security.require()` gained an `mfa_gate` keyword, and the console
  imports it directly. A console wheel older than this engine refuses to mount, as designed.
- **In-use data protection for PHI is now declared and reported** ([ADR 0152](docs/adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-asvs-11-7-1.md),
  ASVS 11.7.1). An **exposed** PHI instance (a non-loopback bind **or** a declared
  `[api].tls_terminated_upstream`, which includes the recommended loopback-behind-proxy topology) that has
  not set **`[security].memory_encryption_operator_declared = true`** — the operator's declaration that the
  host provides hardware memory encryption (AMD SEV-SNP / Intel TDX) — now **warns at every start**.
  **Not a breaking change: nothing that boots today stops booting.** The refusal is opt-in via the new
  `[security].require_memory_encryption_declaration` (default `false`), because this is a **host**
  property that no operator can satisfy on Windows (where the platform read-out is always `null`) — the
  same scoping rule as `[security].allowed_client_networks`' companion refusal (ADR 0151). Loopback and
  synthetic instances are byte-identical. See
  OFF-LOOPBACK-DEPLOYMENT.md ladder row 12 and
  [SYSTEM-REQUIREMENTS.md](docs/SYSTEM-REQUIREMENTS.md).
- **Report-only platform memory-encryption read-out on `GET /security/posture`** (ADR 0152 rung 1;
  `ENGINE_UI_SEAM` 12 → 13) — `memory_encryption_self_reported_capability` / `..._self_reported_active` /
  `..._self_reported_mechanism` / `memory_encryption_readout_source`, plus
  `memory_encryption_operator_declared`, the tri-state
  `memory_encryption_readout_contradicts_declaration` (`null` = nothing was measured that could
  contradict anything) and `memory_encryption_note`, the disclaimer carried **in the response body** so it
  travels with any copy of the artifact. Linux reads `/proc/cpuinfo` flags (capability) and
  `/dev/sev-guest` / `/dev/tdx_guest` **character devices** (activation) as **separate** facts; everywhere
  else every field is `null`. **No value of any of these satisfies ASVS 11.7.1** — they are what the host
  says about itself, and cryptographic attestation (rung 3) is **not built**. The read-out is never
  accepted as a substitute for the declaration, in either direction.
- **Windows crash dumps of the engine process are suppressed** — a WER dump is a full PHI disclosure
  written to disk. `serve` applies the process-local half itself (`SetErrorMode` OR-ed into the inherited
  mode, `WerSetFlags(NOHEAP | NO_UI | DISABLE_SNAPSHOT_*)`); the machine-policy half no process can reach
  is opt-in via `install-service.ps1 -SuppressCrashDumps` (WER `ExcludedApplications`, registered for both
  `messagefoundry.exe` and the venv `python.exe`, plus a **narrowing-only** `LocalDumps` override that is
  written only where LocalDumps is already configured — creating that key would switch dump collection
  ON). Residuals in [SERVICE.md](docs/SERVICE.md).

### Fixed
- **The harness message list could livelock and stop updating entirely.** `MessagesPanel._apply` cleared
  its in-flight guard, re-fired any refresh latched during the read, then returned *before* rendering —
  discarding the snapshot as superseded. Whenever refreshes arrive faster than a read completes there is
  always a latch waiting when the read lands, so every snapshot was discarded and the table never
  updated: permanently stuck, not merely slow (measured: 391 reads served, 0 rendered). It now renders
  first and drains afterwards, costing at most one read of staleness while still converging on the
  latest filter. This surfaced as an intermittent CI failure that no timeout or retry could fix, because
  neither addresses a livelock.
- **Two config blocks in the off-loopback runbook aborted at load** — `[diagnostics].audit_all_authz` and
  `[ai].data_class` had been relocated by ADR 0118, so an operator copy-pasting either block got an
  immediate start failure. Corrected to `[security].audit_all_authorization_decisions` and
  `[security].handles_real_patient_data`, and every fenced `toml` block in that runbook is now pinned by a
  test that loads it and fails on a silently-ignored key.

## [0.3.0] — 2026-07-13 — Early Access

Highlights since 0.2.15 — streaming attachments end-to-end, a copy-on-Send message model, richer
connectivity, and a run of security hardening. (Concise highlights; the git history is the full change set.)

### Added
- **Streaming large attachments end-to-end** (#149, ADR 0105) — very-large OBX-5 documents are detached from
  the message skeleton at ingress and streamed through routing → transform → delivery on all three stores
  (SQLite / SQL Server / Postgres), with an operator read/download surface.
- **Copy-on-Send message model** (ADR 0104) — `Send` snapshots the message at construction (opt-in
  `[pipeline].snapshot_on_send`), plus `Message.copy()` and a recognition-first `message_type_of(accepts=)`
  predicate; and in the IDE, a point-and-click HL7 field picker and the Steps-view authoring palette
  (ADR 0103 / 0106).
- **Connectivity** — generic HTTP auth (OAuth 2.0 client-credentials + Digest) and HTTP response-header
  capture (#154, #65); a connector `SecretProvider` seam with a HashiCorp Vault backend (#196).
- **Monitoring** — an engine-wide KPI roll-up with a saturation-derivative alert and DB-pool metrics (#93).

### Changed
- **pipeline: `batch_handoff_statements` now defaults ON on SQL Server** ([ADR 0075](docs/adr/0075-per-hop-sql-statement-batching.md))
  — per-hop SQL statement batching (a **distance-insurance** lever: folds each message's per-hop store round-trips
  into the fewest `pyodbc.execute()` T-SQL batches, cutting **network round-trips, NOT transactions** — the
  single per-hop `COMMIT` is untouched, `commits/msg` stays 2.000) now activates **by default** on the SQL Server
  store. Promoted 2026-07-08 after Bench B showed **harmless-near** (batch ON vs OFF within ±0.4% at ~0.28 ms RTT,
  zero-loss) and **helps-far** (constant ~−18% ACK-p99, absolute saving widening with RTT: −84 ms @ +20 ms,
  −212 ms @ +50 ms) over a green SS correctness precondition (`tests/test_adr0075_batch_sqlserver.py`, 9 passed).
  **Fail-closed + SQL-Server-only** — Postgres (asyncpg) and SQLite are byte-identical no-ops; the flag is retained
  **only as an emergency off-switch**: set `[pipeline].batch_handoff_statements = false` to disable.

### Security
- **The published PyPI source distribution no longer ships the whole repo** (#1020) — the sdist is pinned to
  the `messagefoundry` package + its metadata, with a fail-closed "sdist is package-only" gate in the release
  workflow. No release ever exposed PHI or customer data.
- **Transport hardening** — certificate-revocation refusal extended to outbound-connector TLS (#201); in-use
  memory protection for the store (#198); the publish deny-list is read from the ref being published (#983).

### Fixed
- **CI reliability** — bound PHI-retention on the Windows service smoke (#1011); wrap pyodbc-heavy SQL Server
  steps with a native-crash retry (#1010); multi-message finalizers take their per-message locks in canonical
  order (#980).

## [0.2.15] — 2026-07-06 — Early Access

**Thread-hop fusion (ADR 0071 B5, flagged default-OFF) + the browser ops dashboard, pooled-claimer
primitives, and opt-in persistent outbound MLLP.** The headline engine change is **B5 thread-hop fusion** —
a SQL-Server-only path that fuses each off-loop CPU stage with its store handoff onto one synchronous-pyodbc
worker hop to cut the per-completion executor→loop marshaling wall; it ships **behind
`[pipeline].fuse_thread_hops` (default off)** pending the SQL-Server throughput bench. Everything else below
is additive / opt-in.

### Added
- **pipeline: thread-hop fusion — B5, opt-in** ([ADR 0071](docs/adr/0071-cut-executor-round-trips-b5.md);
  `[pipeline].fuse_thread_hops` default **off**, SQL Server + `pooled` claim mode only) — fuses each off-loop
  CPU stage (`route_only` / `transform_one`) with its adjacent store handoff onto **one** synchronous-pyodbc
  worker hop, so a multi-statement aioodbc handoff marshals back to the loop **once** instead of per
  statement (attacks the per-completion marshaling ceiling the 2026-07-04 profile named). Fuses **thread
  hops, not transactions** — commits/msg are identical (the poison-guard is intact); Postgres (asyncpg
  loop-native) and SQLite (loop-affine handoff lock) keep the async path by construction. Activation is
  fail-closed: fusion only turns on when the dedicated sync pyodbc pool + per-stage fusing executors open
  cleanly, otherwise the async path runs unchanged. Ships with the self-contained SQLite/Proactor
  crossing-count micro-bench + a Windows CI mechanism gate, and a connscale B0/B1 fusion A/B harness axis
  (`fuse_ab` profile, `trials`-banked); the throughput GO/NO-GO (ship-by-default vs escalate to
  free-threading, ADR 0053) is a separate SQL-Server bench, not a merge gate.
  - **Promote-gate resolved 2026-07-06 — NO-GO** ([ADR 0071](docs/adr/0071-cut-executor-round-trips-b5.md)
    §8/§10, #787): the SQL-Server `fuse_ab` bench measured a real but sub-threshold **+6.5 / +9.3 / +10.0 %**
    lift (below the ≥10% bar; zero-loss held), so `fuse_thread_hops` **stays default-OFF** and the lever
    escalates to free-threading (ADR 0053). Bench-SHA provenance: the run was at commit `8bab40e2`, which is
    **not** an ancestor of `main` (PR5 was squash-merged as `90f80a3`, #780) — but `git diff 8bab40e2 90f80a3`
    is **empty**, so the NO-GO bench ran a code tree byte-identical to merged PR5.
- **store: pooled-claimer primitives** `claim_fifo_heads` / `list_fifo_lanes` / `release_claimed` on all
  three backends ([ADR 0066](docs/adr/0066-pooled-stage-claimers.md) PR 2 — **now wired by the
  `StageDispatcher` and the default claim path since #755/#744, see _Changed_ below**): a FIFO-safe
  multi-lane head-claim (probe-then-claim, EMPTY-on-locked-head — never a #285 skip
  to seq N+1), a read-only head-due-aware lane discovery for the pooled sweep, and an attempts-neutral
  claim release. `claim_next_fifo` / `claim_next_fifo_batch` / `claim_ready` are untouched.
- **pipeline: bounded pooled-mode infra-fault handling (T17)** (ADR 0070; #766) — in `pooled` mode a lane
  whose head keeps failing on an infrastructure fault now **re-pends its head at an exponential-capped
  backoff** (cap `[pipeline].infra_fault_backoff_cap`, default **60 s**) instead of spinning the ~4×/s
  discovery sweep, and after `[pipeline].infra_fault_stop_after` (default **10**) consecutive zero-progress
  faults (~4 min of wall clock) applies `[pipeline].infra_fault_policy` (default **`stop`**): STOP-the-lane
  with a throttled `lane_stuck` alert — **never** auto-dead-letter. `retry_forever` instead keeps re-pending
  at the cap and alerts once the horizon is crossed. `per_lane` mode is unaffected.
- **Browser ops dashboard (read-only, M1)** (#75, [ADR 0065](docs/adr/0065-web-ops-dashboard.md)) — an
  **opt-in** (`[api].serve_ui`, default **off**), same-origin, zero-install browser ops view served under
  `/ui` by the engine's FastAPI app. Read-only: a live-polling connections dashboard (In/Out/Queued/
  Errors/Last-Activity), a message log with filters, the **audited** raw-message view (reuses the exact
  `GET /messages/{id}` PHI path — RBAC + per-access audit + redaction), and a dead-letter list. Auth is a
  new **HttpOnly + SameSite=Strict** session cookie **confined to `/ui`** — the JSON API stays
  Authorization-header-only, so a request bearing only the cookie is still rejected. Ships a strict CSP
  (`script-src 'self'`, no `unsafe-*`), `Cache-Control: no-store` on `/ui` + PHI reads, and autoescape-by-
  default rendering (a stdlib HTML builder — **no new runtime dependency, no npm**). A JSON-only
  deployment is byte-identical (`serve_ui` off); off-loopback requires TLS (refused even under
  `--allow-insecure-bind`).
- **Browser ops dashboard — connection controls (M2a)** (#75, ADR 0065) — the dashboard adds **safe
  operator actions**: inbound connection **start / stop / restart**, reusing the JSON control handlers
  (`connections:control` + per-channel guard). CSRF is defended in depth by an **Origin / Sec-Fetch-Site**
  same-origin check on top of the SameSite=Strict session cookie — **token-free (no crypto import)**.
- **Browser ops dashboard — message replay + step-up re-auth (M2b)** (#75, ADR 0065) — single-message
  **replay** from the browser (a Replay button on the message detail). Replay is `require_step_up` in the
  JSON API, so the /ui route uses a cookie-world step-up gate (`require_ui_step_up`): if the session hasn't
  recently stepped up it **redirects to a /ui re-auth page** (password, + TOTP when MFA is required)
  instead of a 403 header a browser can't act on; after re-auth the browser **auto-retries** the pending
  replay. The re-auth `next` target is validated to be a /ui replay action only (anti open-redirect).
- **Browser ops dashboard — dead-letter bulk replay (M3)** (#75, ADR 0065) — a per-channel **Replay all
  dead** action on the dead-letters page, re-queuing every dead delivery for a channel via the JSON
  `replay_dead_letters` handler. Same step-up gate as message replay (`require_ui_step_up` → /ui re-auth +
  auto-retry; the channel is in the action **path** so the body-less re-POST carries it), and it honors the
  **dual-control approval gate** — when a replay is held for a second approver it surfaces a "held for
  approval" page instead of redirecting.
- **Browser ops dashboard — live `/ws/stats` channel (M-ws)** (#75, ADR 0065) — the dashboard now shows a
  live queue-status strip pushed over the engine's `/ws/stats` WebSocket (previously only the desktop
  path existed and it was unused). A browser can't set the WS `Authorization` header, so a **same-origin
  browser handshake authenticates via the `mf_session` cookie** it carries; **CSWSH is defended** by a
  same-origin `Origin`-vs-`Host` check plus the `SameSite=Strict` cookie (a cross-site handshake carries no
  cookie). The native (header) path is unchanged — a client without an `Origin` falls through to it. The
  the WS strip degrades to empty if the socket can't connect. The **connections table itself now updates
  live over the socket** too: the server pushes the rendered (already-escaped) connections fragment, the
  client swaps it in and stops polling, and polling resumes as a fallback if the socket drops.
- **Browser ops dashboard — HL7 parse-tree view** (#75, ADR 0065) — the message-detail page links to a
  `GET /ui/messages/{id}/parse-tree` view that renders the HL7 segment/field tree server-side via the pure
  `parsing` lib. It reuses the **single audited** `GET /messages/{id}` PHI path (no new PHI egress), every
  field value is escaped (attacker-influenced HL7 can't inject markup), and a non-HL7 body (X12/DICOM/
  binary) surfaces a "no parse tree" notice rather than an error.
- **Browser ops dashboard — per-destination dead-letter replay** (#75, ADR 0065) — the dead-letters page
  now offers **Replay per (channel, destination)** buttons alongside the per-channel "Replay all dead"
  (`POST /ui/dead-letters/{channel_id}/{destination_name}/replay`), same step-up + approval-gate + path-
  based auto-retry as the channel-wide action. `is_safe_ui_action` was widened to the two-segment path and
  hardened to reject any `..` traversal marker.
- **Browser ops dashboard — off-loopback exposure via `[api].public_origin`** (#75, ADR 0065) — a new
  opt-in `[api].public_origin` (e.g. `https://ops.example.com`) makes the dashboard's same-origin **CSRF**
  and **CSWSH** checks work when `/ui` is reached off-loopback through a reverse proxy that doesn't preserve
  the `Host` header: the browser `Origin` is matched against the configured public origin instead of the
  request `Host`. Default (unset) is unchanged — loopback / Host-preserving-proxy behavior. The safe
  defaults stand: `[api].host` is `127.0.0.1`, and `serve_ui` off-loopback still requires TLS
  (`exposure_protected`), refused even under `--allow-insecure-bind`. (Phishing-resistant MFA / managed-
  admin-host controls for off-loopback admin remain a separate posture decision — WebAuthn #11 + the ASVS
  8.4.2 residual.)
- **mllp: persistent outbound connections — OPT-IN** ([ADR 0067](docs/adr/0067-persistent-outbound-mllp.md);
  `persistent=false` default **this release**, per-outbound opt-in via `persistent=true`) — the MLLP
  destination can reuse **one** lazily-established connection across deliveries (with
  `idle_timeout_seconds` / `max_connection_age_seconds` freshness knobs and reconnect-before-first-byte),
  eliminating the per-message TCP/TLS handshake and the `TIME_WAIT` ephemeral-port exhaustion measured on
  the 2026-07-02 load campaign. It ships **opt-in**: the default stays connect-per-message (today's proven
  posture — no behavior change for existing deployments), and `persistent=true` is a documented opt-in for
  sustained high-rate lanes.
  - **Shipped default: `persistent=false` (connect-per-message).** Existing outbounds are byte-for-byte
    unchanged. Set `persistent = true` on an `MLLP()` destination to opt into connection reuse (recommended
    on sustained high-rate lanes; see [docs/SERVICE.md](docs/SERVICE.md) "High-delivery-rate TCP tuning").
    The default flips to `persistent=true` in a subsequent release once the ADR 0067 §8 trigger is met:
    a real deployment runs `persistent=true` clean on a live feed **and** the mid-transaction stray-frame
    correctness edge is closed (a test / the MSA-2↔MSH-10 correlation, BACKLOG #82) or field-confirmed benign.

### Removed
- **Frozen zero-Python Windows console installer retired** (#39, [ADR 0032 Phase B](docs/adr/0032-console-desktop-launch.md)
  *Amendment (2026-07-01)*). The PyInstaller `--onedir` + Inno Setup channel added in 0.2.11 is removed:
  `packaging/console-installer/`, the `release-console-installer` job in the release workflow, and its
  AC-linked tests are deleted, along with the Qt-LGPL frozen-binary written-offer/bundled-license apparatus
  and the pending Authenticode signing-cert requirement. **Rationale:** zero uptake (the CI leg failed on
  every tag release since it merged; one out-of-band `.exe` with no downloads), the no-Python/no-IT demand
  gate never fired (adopters are pip + IT-covered), and it only ever shipped unsigned. **The desktop console
  is unaffected** — it stays installable via `pip install messagefoundry[console]` + the ADR 0032 Phase A
  `gui-script` and shortcut scripts; only the *frozen, zero-Python* conveyance is gone. The zero-install
  audience is now served by the browser ops dashboard ([BACKLOG #75](docs/BACKLOG.md)).

### Changed
- **Server-DB store opens now skip the schema DDL batch when it already ran** ([ADR 0064](docs/adr/0064-schema-init-fastpath.md)).
  A single-row `schema_meta` marker records the content hash of the shipped DDL batch; a re-open of a
  current database skips the whole guarded batch **and** the exclusive schema lock (previously every
  open re-ran dozens of check-then-create statements under `sp_getapplock`/the schema advisory lock —
  the measured N≥4 co-start convoy of the WS-B bench, and wasted round-trips on every single-engine
  restart). Any edit to the DDL batch changes the hash and forces exactly one full idempotent run, so
  upgraded databases still adopt on-open migrations (ADR 0060) unchanged. **Operational note:**
  out-of-band schema surgery is no longer self-healed at the next restart — run
  `DELETE FROM schema_meta` afterward to force one full run. SQLite is unaffected.
- **Startup crash recovery (`reset_stale_inflight`) is now index-seekable** ([ADR 0064](docs/adr/0064-schema-init-fastpath.md)):
  the all-stages pass runs one UPDATE per pipeline stage against the existing
  `ix_queue_ready(stage, status, …)` index instead of one unindexed status-only full scan of the
  queue (Postgres additionally drops an unsargable `OR $n IS NULL` form). Same rows recovered, same
  single transaction — all three backends.
- **Default staged-pipeline claim path flipped to pooled per-stage claimers**
  ([ADR 0066](docs/adr/0066-pooled-stage-claimers.md); `[pipeline].claim_mode` default `per_lane` →
  **`pooled`** — issue #744, shipped via PR #765). The `StageDispatcher` was first wired in behind
  `[pipeline].claim_mode` **default-OFF** (#755, ADR 0066 PR4) and is now the **default** claim topology:
  one dispatcher per stage running a handful of pooled claimer tasks over the `claim_fifo_heads` /
  `list_fifo_lanes` / `release_claimed` primitives (batch-claiming head-prefixes across lanes), collapsing
  the ~4,500 per-(lane×stage) claim loops that saturated a shared server DB at high fan-out and holding
  zero-loss where `per_lane` dropped messages. **`per_lane` stays fully selectable as the byte-identical
  opt-out** (`[pipeline].claim_mode = "per_lane"`), enforced by the zero-pooled-construction test sentinel.
  Reliability-core — read once at engine start (a `/config/reload` does not toggle it; restart to change).
  Single-node scope; the at-least-once / per-lane-FIFO / poison-guard invariants are unchanged in both modes.

## [0.2.14] — 2026-07-01 — Early Access

**Delta security-audit remediation.** A focused security audit of the surface added since the
2026-06-10 full review (v0.2.0 → v0.2.13) surfaced seven verified findings; this release fixes all of
them. No new critical, no SQL injection, no auth bypass, no RCE — the most serious was an
unauthenticated memory-exhaustion DoS in the new default HL7 parser. Each fix ships with a regression
test. See `docs/reviews/DELTA-REVIEW-2026-07-01.md`, a maintainer-internal document —
[`docs/SECURITY-DOCS-POLICY.md`](docs/SECURITY-DOCS-POLICY.md) states what is withheld and what you
can request.

### Security
- **Bounded the built-in HL7 rich-text repetition escape** (DELTA-01/02;
  [`_builtin_hl7.py`](messagefoundry/parsing/_builtin_hl7.py)). The tolerant built-in parser (now the
  default hot-path backend, ADR 0054) expanded `\.inN\`-style repetition escapes with no cap, so a
  ~15-byte inbound field (`\.in2000000000\`) allocated gigabytes synchronously on the event loop
  **before the ACK** — an unauthenticated OOM/denial-of-service. The count is now clamped
  (`MAX_ESCAPE_REPEAT = 512`), and a malformed count no longer raises out of a field read — that had
  severed the connection and dropped a parseable message with **no disposition**, breaking the
  count-and-log invariant.
- **XML-DSig `verify()` now requires an explicit trust anchor** (DELTA-03;
  [`parsing/xml/signature.py`](messagefoundry/parsing/xml/signature.py)). Called with neither `x509_cert`
  nor `ca_pem_file`, it previously fell back to signxml's default of trusting **any** certificate that
  chains to the host's system CA store (origin-blind verification); it now raises `ValueError`.
  **Behavior change** for the opt-in `[xml]` codec — a caller must pin the expected signer or a partner
  CA. No in-repo caller relied on the old default.
- **FhirLookup SMART token endpoint is now egress-gated** (DELTA-04;
  [`[egress].allowed_http`](docs/CONFIGURATION.md)). A `fhir_lookup` connection composed with
  `with_smart_backend()` POSTs a signed `client_assertion` to its `smart_token_url`; that host was not
  checked against the egress allowlist (only the FHIR base host was), so a crafted `smart_token_url`
  could exfiltrate the assertion to an un-allowlisted host. The lookup and outbound arms now share one
  gate ([ADR 0043](docs/adr/0043-fhir-read-lookup.md) §D3).
- **Support bundle no longer discloses the store host/database; its log redaction was widened**
  (DELTA-05/07; [`support/`](messagefoundry/support/)). The offline support bundle's `status.json`
  carried the SQL Server `host/database` verbatim — it is now reduced to the backend kind (file basename
  only for SQLite). The bundled-log redactor previously used a fixed HL7-segment allowlist with no
  free-text name/DOB heuristics; it now delegates to the engine redactor
  ([`messagefoundry.redaction`](messagefoundry/redaction.py)) for parity with stored-error redaction.
- **Inbound HTTP listener rejects ambiguous framing** (DELTA-06;
  [`transports/http_listener.py`](messagefoundry/transports/http_listener.py)). A duplicate
  `Content-Length`, a duplicate `Transfer-Encoding`, or the two present together are now refused with
  `400` per RFC 7230 §3.3.3 — closing an HTTP request-smuggling / desync surface behind a fronting proxy.

## [0.2.13] — 2026-07-01 — Early Access

The **store connection-scale sizing** wave — right-size the server-DB connection pool to the measured
inverted-U optimum, guard against over-provisioning, and guarantee the message store stays unified. All
changes are **server-DB-only**; the single-node SQLite default is unaffected.

### Added
- **Soft store-pool over-provisioning warning** ([ADR 0062](docs/adr/0062-default-store-pool-size.md)) — a
  server-DB engine now logs an advisory `WARNING` at graph start if `[store].pool_size` is sized past the
  connection-pool inverted-U optimum: at/beyond the ~80 catastrophic cliff, or oversized for the engine's
  inbound-interface count (`~2.5 ×` interfaces). Advisory only — it never blocks startup; SQLite has no pool
  so it is skipped, and the default (40) never trips it. Guards the "set a huge pool for 1500 connections"
  footgun (which is a *sharding* problem, not a pool one).

### Changed
- **Default server-DB store connection pool size raised 5 → 40** ([`[store].pool_size`](docs/CONFIGURATION.md),
  env `MEFOR_STORE_POOL_SIZE`; [ADR 0062](docs/adr/0062-default-store-pool-size.md)). A three-sweep
  connection-scale study found the pool is an **inverted-U**: it helps up to ~40 per engine, and
  **over-provisioning is catastrophic** — past ~40 the extra connections thrash one shared SQL instance
  (WRITELOG serialization + per-message finalizer applocks), and ACK latency explodes 30–90×. 40 is the
  measured optimum — **do not set it higher to chase connection count.** **Server-DB backends only** (Postgres
  / SQL Server) — the default **single-node SQLite** backend is unaffected (fixed read pool + single writer;
  never reads `pool_size`). **Existing explicit `[store].pool_size` / `MEFOR_STORE_POOL_SIZE` values are
  unchanged** — only the unset default moves. Behavioral deltas on server-DB engines: ~**8×** the steady-state
  DB sessions per engine, and the startup pool pre-warm rises from ~2 to **~20 connections per engine**
  (bounded by `warm_pool_timeout`, off the intake path, self-releasing, never raises). **Connection-budget
  caution:** `pool_size` is **per engine**, so on a shared server DB `engines × pool_size` all count against
  one `max_connections` (Postgres default ~100 → ~2 engines at 40) — raise `max_connections`, front the DB
  with a pooler (PgBouncer), or use SQL Server; or size `pool_size` down. **Never split the store** to fit the
  budget ([ADR 0063](docs/adr/0063-no-split-store-unified-store-for-sharding.md)). See
  [`docs/DEPLOY-SERVER-DB.md`](docs/DEPLOY-SERVER-DB.md) §3.
- **No split data store: multi-shard engine sharding now requires a server DB** ([ADR 0063](docs/adr/0063-no-split-store-unified-store-for-sharding.md),
  amends [ADR 0037](docs/adr/0037-multi-process-sharding-l3.md)). `messagefoundry supervise` with **more than
  one shard** on a **SQLite** store is now **refused at startup** — the old SQLite-file-per-shard behavior
  split the message store into one database per shard, fragmenting search/reporting/audit/replay. A sharded
  deployment must share **one unified store**, so `>1` shard requires `[store].backend = 'postgres'` or
  `'sqlserver'` (every shard connects to the same database). **A single un-sharded engine on SQLite is
  unaffected** (byte-identical to `serve`). Migrating an existing SQLite-sharded deployment: drain each shard
  store to empty, then re-point `supervise` at one server DB (not an offline store merge).

## [0.2.12] — 2026-07-01 — Early Access

The **throughput & connection-scale wave.** The staged-queue per-message commit chain is shortened
(opt-in inline fast-path + batch-claim, plus a result-preserving seq-only FIFO ordering that drops a
per-handoff round-trip); a connection-scale measurement harness + read-only engine instrumentation lands;
**per-lane wake events** (opt-in) eliminate the thundering-herd empty-claim storm that dominates at high
connection counts; and ADR 0059's seq-only FIFO index re-key now reaches **upgraded** databases via a
one-time on-open migration. All new *runtime* behavior is opt-in / off-by-default unless noted — the
seq-only ordering (B3) and the index migration (B10) are result-preserving.

### Added
- **Inline Step-A fast-path** ([ADR 0057](docs/adr/0057-inline-step-a-fast-path.md)) — **opt-in per
  inbound via `inline`**: for the pure all-deliver message (no filter/state/pass-through), fuse
  route+transform+handoff into **one committed transaction**, cutting the per-message commit depth from 7
  to 5 durable round-trips. Off by default → byte-identical to the split path; ineligible messages fall
  back automatically.
- **Batch-claim** (#671, [ADR 0058](docs/adr/0058-batch-claim-fifo-prefix.md)) — **opt-in via
  `[store].fifo_claim_batch`** (>1): the INGRESS/ROUTED FIFO claim takes the contiguous due head-prefix in
  one commit instead of one row per commit, processed in strict FIFO order. Default `1` = off
  (byte-identical); preserves per-lane FIFO (#285) and at-least-once.
- **Per-lane wake events** (#678, [ADR 0061](docs/adr/0061-per-lane-wake-events.md)) — **opt-in via
  `[pipeline].per_lane_wake`**: a committed message wakes **only its own `(stage, lane)` worker** instead
  of every worker of that stage, eliminating the thundering-herd empty-claim storm at high **connection**
  counts (~1,500 inbounds). Default off + byte-identical; the FIFO claim and the lost-wakeup poll backstop
  are unchanged (a missed wake self-heals). Env override `MEFOR_PIPELINE_PER_LANE_WAKE` for the harness A/B.
- **Connection-scale measurement harness + read-only engine instrumentation** (#675) — a headless harness
  that spins N inbound connections at a low per-connection rate and reads the connection-scale walls
  (executor saturation, server-store pool wait, idle-poll storm, FD/socket count, config-reload + ACK
  latency) vs connection count. The supporting engine instrumentation is **additive + read-only**, surfaced
  via `/stats` + `/status`: empty-claim counters split into idle-poll vs per-commit wake-fanout, and (on a
  server store) connection-pool acquire-wait percentiles + size/idle occupancy. Counters default to 0 /
  `None` — byte-identical when unused.

### Changed
- **Seq-only per-lane FIFO ordering** (#673, [ADR 0059](docs/adr/0059-seq-only-fifo-ordering.md)) — the
  per-lane FIFO claim now orders by the DB-assigned `seq` (rowid on SQLite) **alone** instead of
  `(created_at, seq)`, and the per-insert `SELECT MAX(created_at)` clamp is removed from **every stage
  handoff** (one fewer round-trip per produced row). **Result-preserving** (proven order-isomorphic to the
  prior clamped ordering) and strictly more robust under clock skew / failover (`seq` has no wall-clock
  dependence). `created_at` stays a real ingest-time/metrics timestamp — it is simply no longer an ordering
  key. The FIFO covering indexes re-key to trail in `seq` (see the migration below).
- **Rename-based FIFO covering-index migration** (#676, [ADR 0060](docs/adr/0060-rename-based-fifo-index-migration.md)) —
  ADR 0059 re-keyed the per-lane FIFO indexes to trail in `seq` for the seq-only claim, but kept their names
  under `IF NOT EXISTS` guards, so **only fresh databases** adopted the new index — an upgraded DB silently
  kept its old `created_at`-trailing index and never got ADR 0059's throughput win. The seq-trailing indexes
  are now named `ix_queue_fifo_in_seq` / `ix_queue_fifo_out_seq`, and a one-time, idempotent **on-open
  migration drops the old-named index and builds the new one** on all three backends, so upgraded databases
  adopt it. Correctness is unchanged (the claim orders by `seq`/`rowid` and names no index, so the migration
  only restores speed). Operational notes: the first open after upgrade pays a **one-time index rebuild** on
  the `queue` table (SQLite/Postgres blocking, SQL Server offline — bounded by live queue depth, at cold start
  before serving); on a very large SQLite queue a *concurrent* second opener may hit a transient, non-corrupting
  open failure during the rebuild; the shared-DB backends (SQL Server / Postgres) should upgrade **stop-the-world
  / under a drain window** (a mixed-version fleet or a live rejoin can re-create or contend on the index); a
  downgrade re-creates the old-named index (drop `ix_queue_fifo_in/out` manually if downgrading permanently).
- **`/status` DB observability** — the SQLite journal mode and `synchronous` durability setting are now
  surfaced in the DB status (`synchronous=NORMAL` remains the crash-safe-under-WAL default).

## [0.2.11] — 2026-06-29 — Early Access

The **Plan-6 disaster-recovery + cloud/HA wave** — turnkey DR backup/restore-verify and a third-tier DR
standby, Kubernetes/cloud HA deployment packaging, and a frozen zero-Python Windows console installer —
alongside the free-threading-keystone built-ins HL7 parser and the first SQLite durable-write group-commit
lever. All on-prem and code-first; new behavior is opt-in / off-by-default unless noted.

### Added
- **Turnkey DR backup + restore-verify** (#60, [ADR 0049](docs/adr/0049-turnkey-dr-backup-restore-verify.md)) —
  an engine-managed scheduled/on-demand backup that bundles the loaded `--config` dir + a consistent SQLite store
  snapshot into one AES-256-GCM-encrypted `.mfbak` archive (chunked-AEAD, fail-closed on tamper/truncate/reorder,
  keyed by the existing store DEK — no new key), to an operator-set **local/UNC path (no cloud target)** under
  keep-N retention. The snapshot runs read-only off the event loop and never touches a staged-queue row; each run
  restore-verifies the archive (decrypt → `integrity_check` → row-count) and audits a PHI-free `dr_backup` row.
  New `messagefoundry backup` / `restore-verify` CLI. **Off by default** (`[backup].enabled = false`); SQLite-only
  (server-DB stores are DBA-delegated, backed up config-only); leader-gated under HA; a keyless PHI instance
  refuses to write a cleartext archive unless the audited `[backup].allow_unencrypted` escape is set.
- **Third-tier DR standby** (#61, [ADR 0048](docs/adr/0048-third-tier-disaster-recovery-standby.md)) —
  a right-sized disaster-recovery box that activates **only** when the whole active-passive HA pair/site (or its
  shared store) is gone, running a reduced high-priority feed set in an accepted degraded mode. Adds: a
  per-connection **`priority` tier** (`critical`/`normal`/`low`, `[delivery].priority` default `normal` +
  per-connection override); a startup **DR run-profile** (`[dr]`) that starts only connections at/above
  `priority_threshold` (default `critical`), the rest reporting `status:"filtered"`, behind an acquire-VIP-or-abort
  takeover; and a **cold seed** from #60's encrypted `.mfbak` (restore-verify, local/UNC only). Activation is
  **manual only** — audited `POST /dr/activate` / `/dr/release` gated by a new `dr:operate` permission;
  `activation_mode='auto'` is rejected at config load. No `[dr]` section = a no-op, unaffected.
- **Cloud / Kubernetes HA deployment packaging** (#41, [ADR 0047](docs/adr/0047-cloud-kubernetes-ha-deployment-packaging.md)) —
  packages the already-shipped active-passive HA into a copyable cloud target. **Packaging + docs only — no engine
  code changed.** Adds a Postgres-backed multi-replica k8s reference manifest (`docker/k8s/ha-postgres.yaml`:
  `replicas: 3`, `[cluster].enabled`, a PodDisruptionBudget, `terminationGracePeriodSeconds` > `leader_lease_ttl_seconds`
  so a drained leader releases its lease before SIGKILL, hardened `securityContext`, secrets via `secretKeyRef`) — no
  PVC, since durability lives in external Postgres. The default `compose.yaml` stays single-node SQLite; a new `ha`
  profile runs Postgres + warm standby locally. New `docs/CLOUD-DEPLOYMENT.md` (primary-only L4 NLB MLLP recipe; no
  L7/HPA for MLLP; SQL Server AG variant) and `docs/CLOUD-PHI-HIPAA.md` (BAA, KMS CMEK layered with the engine's own
  AES-256-GCM, PrivateLink). Active-passive only; demand-gated.
- **Frozen zero-Python Windows console installer** (#39, [ADR 0032 Phase B](docs/adr/0032-console-desktop-launch.md)) —
  the PySide6 admin **console** now ships as a self-contained Windows installer (a PyInstaller `--onedir` freeze
  wrapped in an Inno Setup `.exe`) with Desktop/Start-Menu shortcuts and an Add/Remove-Programs uninstall entry —
  **no Python, venv, or `pip install` on the box**. **Per-user / no-elevation by default** (opt-in all-users via
  `/ALLUSERS`); this packages the **console client only** — the engine NSSM service and the `127.0.0.1:8765` API
  boundary are unchanged. Frozen from the same wheel the release publishes, by an isolated job that never reds an
  engine release. **Authenticode signing is gated on an owner-provisioned cert** — until that secret lands the
  installer ships **unsigned** (SmartScreen "Unknown publisher"). Windows-only; no MSIX/Store, no auto-update.
- **SQLite app-side group-commit committer** (#64, [ADR 0055](docs/adr/0055-group-commit-durable-write.md)) —
  an opt-in durable-write lever for the single-writer SQLite backend: a committer coroutine coalesces the grouped
  staged-queue handoffs into one commit under the writer lock, amortizing fsyncs/msg, while the claim /
  reference-snapshot / audit writes stay standalone and every staged-queue invariant (count-and-log, at-least-once,
  FIFO) is preserved. **Off by default** — `[store].group_commit_window_ms = 0.0` builds no committer and is
  byte-identical to today; set it (with `group_commit_max_batch`, default 64) to enable. The win is largest under
  `synchronous=FULL` and muted under the default NORMAL. **SQLite only** — the server-DB backends ignore these knobs
  (native concurrent-pool group-commit is a later increment); the absolute enterprise throughput figure stays
  pending hardware-matched measurement.
- **Background store connection-pool pre-warm** (#661) — on graph start/promotion the engine fires a best-effort
  background task that pre-opens pooled connections on the **server-DB backends** (Postgres / SQL Server), so a
  connection burst — the post-promotion delivery workers in active-passive HA, or a cold start — finds them warm
  instead of paying cold connects (TCP+TLS+login). **On by default** via `[store].warm_pool` (+ `warm_pool_timeout`
  / `warm_pool_target`), capped to ≤ half the pool; a **no-op on SQLite**. Cancellation- and shutdown-safe — it
  never strands or hangs the engine on a failover to a dead node.
- **Single project-root config anchoring** (#33-A, [ADR 0050](docs/adr/0050-single-project-root-config-anchoring.md)) —
  one opt-in `--project-root` (= `[environments].base_dir`) anchors the whole config bundle (the `--config`
  graph, `environments/<env>.toml`, `messagefoundry.toml`, and `[store].path`) under one root with a single
  precedence (explicit-absolute > project-root > CWD), so a `serve` launched from a non-repo CWD (the NSSM
  case) no longer silently reads empty `env()` values or creates the DB in the wrong place. Three PHI-safe
  startup diagnostics: a hard-fail when an explicit root + an `env()`-referencing graph is missing its
  `<env>.toml`, a WARNING when CWD differs from the root, and a WARNING for the NSSM silent-miss. The
  `--project-root` / `--env` / `--service-config` flags are extended to the offline `validate` / `graph` /
  `dryrun` / `check` subcommands (value resolution only — not `serve`'s required-env / posture refusal), and
  `check` suppresses its `messagefoundry.toml` upward-walk when those flags are passed.

### Changed
- **Tolerant HL7 parser re-backed by a low-allocation built-ins model** (#88, [ADR 0054](docs/adr/0054-low-allocation-builtins-hl7-parser.md)) —
  the hot-path `Peek`/`Message` tolerant tier now parses over native `dict`/`list`/`str` instead of python-hl7, a
  **behaviour-identical drop-in** (public API, field-path semantics, escape rules, MSH-1/2 raw handling, and
  `encode()` round-trips all byte-parity-verified against python-hl7 over the golden corpus). MSH parses eagerly,
  other segments lazily on first field-path touch. **On by default**, with a per-parse python-hl7 fallback kept for
  this release — a contract `HL7PeekError` still raises and dead-letters, while an unexpected internal error falls
  back to python-hl7 and is logged, never crashing a connection. The free-threading keystone for
  [ADR 0053](docs/adr/0053-free-threaded-multicore-engine.md) and a large single-thread parse win; the strict hl7apy
  `validate()` tier and `parse_tree` / `RawMessage` are untouched. python-hl7 stays a dependency for the fallback
  window (removal is a follow-up release).
- **A set project root (`--project-root` or `[environments].base_dir`) now anchors the store DB too, not
  just `environments/`.** A deployment that runs `serve`/`supervise` with a project root **and** a relative
  `--db` / `[store].path` (or relies on the default relative `messagefoundry.db`) will now find/create the DB
  under the root instead of the process CWD — including each shard's `<stem>_<shard>.db`. `--project-root`
  additionally anchors a relative `--config` / `--service-config` (a file-only `[environments].base_dir`
  anchors the DB + env values but not those two, since they are resolved before the settings load). This is
  the intended fix for the split-store footgun, but it **relocates an existing relative DB**: pass an
  **absolute** `[store].path` / `--db` to keep the DB where it is (absolute paths bypass the root), or accept
  the new location. Deployments with no project root, or with an absolute DB path, are unaffected. The new
  CWD-mismatch WARNING surfaces any move at startup.

## [0.2.10] — 2026-06-27 — Early Access

The **Plan-5 "v0.3 candidate" wave** — completing the deferred connector/codec set and the Corepoint
parity gaps, built across two multisession waves (L1–L9) and adversarially reviewed. All on-prem,
code-first, no behavior change to existing graphs.

### Added
- **Inbound HTTP / REST listener** (#7, [ADR 0023](docs/adr/0023-inbound-http-listener.md)) — a
  connector-owned bound `asyncio` HTTP/1.1 socket **source** in `transports/` (not `api/`), feeding the
  payload-agnostic ingress (ADR 0004) as a `RawMessage`. ACK-on-receipt (respond-with-receipt **after** the
  raw is durably committed), with oversize/malformed/slow-loris hardening surfaced as `connection_event`s;
  new `ConnectorType.HTTP`. The substrate for the future inbound FHIR facade (#20) / DICOMweb receiver (#24).
  *(SOAP-envelope sync-reply, intake-socket auth, and method/path routing metadata are deferred follow-ons.)*
- **`fhir_lookup(connection, query)`** (#58, [ADR 0043](docs/adr/0043-fhir-read-lookup.md)) — a Handler-callable,
  **read-only** FHIR read/search that extends the ADR 0010 `db_lookup` carve-out to FHIR: off the event loop,
  raises on a Router / in dry-run, reuses the SMART Backend bearer (ADR 0024) + `[egress].allowed_http`, GET-only.
- **Email / SMTP outbound destination** (#23, [ADR 0029](docs/adr/0029-email-smtp-destination.md)) — a stdlib
  `Email()`/`SMTP()` connector; STARTTLS-by-default, AUTH-over-TLS-only, a new deny-by-default
  `[egress].allowed_smtp` arm. (IMAP/POP read + XOAUTH2 is a deferred Phase 2.)
- **X12 strict implementation-guide validation** via `pyx12` (#32) behind the tolerant `X12Peek`/`X12Message`
  hot path (`messagefoundry[x12]`; yields 997/999 acks), and a **structured `[xml]` codec layer** (#31) —
  `XmlMessage` (XPath read/set + ns-aware re-encode) over **hardened lxml** + optional `xmlschema`/`signxml`
  (`messagefoundry[xml]`; XXE / entity-expansion / external-DTD refused).
- **Operator alert-state** (#56, [ADR 0044](docs/adr/0044-operator-alert-state.md)) — a new `alert_instance`
  store table (open / acknowledged / resolved + first/last-seen + count) across all three backends, de-duped on
  the ADR-0014 throttle key; `GET /alerts/active` + ack/resolve (RBAC `MONITORING_DIAGNOSE`); the per-connection
  `alerts_active` count is now real; a console Alerts tab. Metadata-only.
- **User-definable custom RBAC roles** (#57, [ADR 0045](docs/adr/0045-custom-rbac-roles.md)) — an admin-defined
  named role = a chosen **subset** of the existing Permission catalog (no new permission kinds), persisted via an
  additive `roles` migration (3 backends), gated by `USERS_MANAGE`; the six built-ins stay; narrowing revokes on
  live sessions.
- **Message-content search** (#51, [ADR 0046](docs/adr/0046-message-content-search.md)) — HL7 field-path /
  raw-content matching by **scan-and-decrypt-per-row** (the store is AES-GCM-encrypted at rest, so a plain `LIKE`
  is impossible): metadata-pre-filtered, hard row/result caps (truncate-and-tell), decrypt off the event loop,
  behind `messages:view_*` + **step-up** + a `message_search` audit row that never logs the search needle.
- **HL7 timestamp helpers on `Message`** (#59) — `age`-from-DOB, length-of-stay, and the tolerant HL7-TS parse
  surfaced on the `Message` API (reusing `timezone.py`; no duplicate parser).
- **`messagefoundry support-bundle`** CLI (#49) — a PHI-safe diagnostic zip (no message bodies, no secrets;
  redacted log tail) — and a **zero-egress version update-check** (#30,
  [ADR 0026](docs/adr/0026-off-box-egress-update-check.md)): a no-network pinned-vs-current diff surfaced as a
  `/status` field + an `update_available` alert + a console banner (on by default; `mode=live` rejected at load).

### Changed
- `[egress]` gains `allowed_smtp` (email); the read-only-lookup carve-out (CLAUDE.md §2/§8) now names
  `fhir_lookup` alongside `db_lookup`.
- New connectors/codecs are documented in [`docs/CONNECTIONS.md`](docs/CONNECTIONS.md) and the update-check in
  [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) (`[update_check]`).

### Security
- All new live-lookup / search paths stay on-prem and gated: `fhir_lookup` and the update-check are zero-/
  allow-listed-egress; content search is step-up-gated + audited and never weakens at-rest encryption (the
  cleartext key-field index was **declined**; a keyed-token index is a deferred 2nd slice). New crypto sites
  (`transports/http_listener.py` TLS) are registered in the ASVS-11.1.3 crypto inventory.

### Dependencies
- New optional extras only: `messagefoundry[x12]` (`pyx12`) and `messagefoundry[xml]`
  (`lxml`/`xmlschema`/`signxml`); the base install is unchanged. Lockfile re-exported.

## [0.2.9] — 2026-06-27 — Early Access

A retention + security-hardening + observability release: per-connection retention and
embedded-document pruning windows, dual-control config reloads with startup code-attestation,
operational-health metrics, and a fix for the intermittent Windows listener-teardown / CI hang.

### Added
- **Per-connection retention windows (ADR 0027).** Optional `messages_days` (inbound) and
  `dead_letter_days` (outbound) on a connection, layered over the global `[retention]` window and
  authored on the connection spec or `connections.toml` (the same override idiom as the delivery
  knobs): `None` inherits the global window, `0` keeps forever. The `RetentionRunner` threads a
  per-connection cutoff through the body and dead-letter purge on **all three** store backends; the
  never-purge-an-in-flight-body guard and the single per-pass audit row (now recording the overrides)
  are unchanged. (#34)
- **Embedded-document pruning (ADR 0042).** Optional `prune_documents_after` (+ a size threshold)
  per inbound connection: after the window, bulky **base64 embedded documents** — HL7 **OBX-5 ED**
  and the generic `mfb64:v1:` carriage — are stripped **in place** to a small size/content-type
  tombstone (via the parsed model / codec, **never** string-slicing HL7), keeping the rest of the
  message parseable; the row is never deleted and a `documents_pruned` flag is set. All three
  backends. (The ingest-time offload variant remains deferred.) (#47)
- **Dual-control `config:reload` (ADR 0041 D2).** `config_reload` is now a gateable
  `[approvals].operations` op — a **distinct** second approver must release a live config reload
  (the requester can never self-approve; both identities land in the hash-chained audit). Opt-in /
  deny-by-default, so single-operator deployments are unchanged. (#53)
- **Startup code self-attestation (ADR 0041 D3).** At startup the engine hashes its loaded modules
  against the wheel's `dist-info/RECORD`; on drift it records a hash-chained, off-box-teed
  `startup_integrity` audit row and raises an alert (**alert-only by default**; opt-in
  `[integrity].fail_closed_on_drift` refuses to start). A no-op on an editable (`pip install -e .`)
  install, so development is never bricked. (#54)
- **Operational-health metrics.** `GET /status` now meters the app-log directory's disk usage
  alongside the database, and a per-connection **message-stall** alert rule fires when a connection's
  oldest-undelivered age crosses a configurable threshold. (#50)

### Changed
- **Non-editable, hash-locked wheel is the enforced production default (ADR 0017 amendment).** The
  prior recommendation is now the default for production deployments; editable installs remain a
  no-op for development. (#54)

### Fixed
- **Intermittent Windows listener-teardown hang.** `MLLPSource` / `TcpSource` / `X12Source` no longer
  `await server.wait_closed()` / `writer.wait_closed()` **unbounded** on the Windows Proactor loop
  during teardown — a wait that never completes can no longer stall a shared event loop (the same
  class as the resolved py3.11 hang). Added CI guards (a per-test `faulthandler` stack dump and a
  step-level watchdog) so a future hang fails fast and names itself instead of silently timing out. (#55)

### Docs
- Refreshed `benchmarks/TUNING-BASELINE.md` with measured multi-process sharding throughput from the
  Windows Server 2025 box (η ≈ 0.85 speedup shape; per-shard E_core ≈ 42 msg/s — a test-box SQLite
  floor), plus the still-unmeasured hardware-gated follow-ups (enterprise E_core, the shared-DB
  commit-wall sweep). (#28, #29)
- Authored **ADR 0027** (per-connection retention) and **ADR 0042** (embedded-document pruning); added
  EARS acceptance criteria to **ADR 0041** D2/D3; amended **ADR 0017** for the enforced wheel.

### CI
- Locked the smoke job's config directory (#603) and skipped a mirror-only Dependabot guardrail test
  on the OSS mirror (#606), greening `main` CI post-0.2.8.

## [0.2.8] — 2026-06-27 — Early Access

A tooling/ops release: the load harness gains a **multi-shard driver** so one harness can drive a
`supervise` cluster (unblocking the multi-core throughput measurement), `supervise` resolves
`--env` files for its shards, and a prominent upgrade note for the config-directory permission
guard introduced in 0.2.6.

> ### ⚠ Upgrading from ≤ 0.2.5 — tighten config-dir ACLs first
> The config-directory permission guard (SEC-003 / ADR 0036), added in **0.2.6**, refuses to load a
> `--config` directory that is **writable by a broad principal** (e.g. `Authenticated Users` /
> `S-1-5-11`). A deployment whose config dir inherits that write — common under `C:\srv\…` — will
> **fail to start on first upgrade to ≥ 0.2.6** with *"refusing to load config from writable-by-others
> path …"*. **Before upgrading**, tighten the directory (elevated):
> ```powershell
> icacls "<config-dir>" /inheritance:d /T
> icacls "<config-dir>" /remove:g *S-1-5-11 /T          # drop Authenticated Users
> icacls "<config-dir>" /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-544:(OI)(CI)F /T  # SYSTEM + Admins
> ```
> See [`docs/SERVICE.md`](docs/SERVICE.md) → *Update to a new build* and *Lock down the config
> directory (CONFIG-2)*.

### Added
- **Multi-shard load driving (`messagefoundry-harness`).** `python -m harness` gains
  **`--skip-preflight`** (drive shard MLLP ports that no single `--engine` owns) and a repeatable
  **`--shard-engine <url>`**: the engine poller now takes a list of shard APIs and **sums** each
  shard's `/stats` (read/written/backlog/in_pipeline/queue_depth/dead) into one cluster sample, so
  the no-loss reconcile and drain are **cluster-aggregate** — a healthy K-shard run reports pass,
  not a false "lost on intake". With no `--shard-engine` the behavior is byte-identical to before.
  Two sample graphs ship for the throughput suite: `harness/config/store_once` (the
  dedup-triggering one-handler-`list[Send]`-of-identical-body shape for store-once) and
  `harness/config/passthrough` (an internal `PassThrough()` re-ingress hop); the load graph
  (`harness/config/load`) is now shard-taggable via `MEFOR_LOAD_SHARD_ADT`/`_RESULTS`/`_OTHER`. (#604)

### Fixed
- **`supervise --project-root`.** `supervise` now accepts `--project-root` and forwards it to each
  spawned `serve --shard`, so `supervise --config <dir> --env <env>` resolves each shard's
  `environments/<env>.toml` (previously the shards resolved nothing from their spawned cwd and
  required an explicit `--service-config` posture). Backward compatible — no `--project-root` is
  unchanged. (#602)

## [0.2.7] — 2026-06-27 — Early Access

A docs/packaging release that fixes the broken badge images on the PyPI project page
and adds a config-check pre-commit hook.

### Fixed
- **Broken badge images in the PyPI project description.** The CI and Security status
  badges in the README pointed at the **private** source repo, so they rendered as
  broken images on the public PyPI page — an anonymous viewer can't fetch a private
  repo's GitHub Actions badge SVG (it 404s). The README now points at the public
  mirror (`MEFORORG/MessageFoundry`), and the release build additionally rewrites any
  remaining `wshallwshall`→`MEFORORG` repo slug in the README before it is embedded as
  the PyPI `long_description`, so the rendered badges resolve anonymously. (#568)

### Added
- **`messagefoundry check` pre-commit hook.** A VS Code-extension-generated
  `.mefor-hooks/pre-commit` runs `messagefoundry check` so a commit can't introduce a
  broken config (skips cleanly if python or the package isn't importable; bypass with
  `--no-verify`). (#568)

### Docs
- Backlog **#47** — base64 embedded-document (attachment) pruning (Mirth
  attachment-handler / data-pruner parity); and a Changelog link in the README. (#568)

## [0.2.6] — 2026-06-27 — Early Access

A large release: the **throughput-maximization build** (high-fan-out store-once, multi-process
sharding, and internal pass-through connectors with full Postgres/SQL Server parity), a console +
IDE **"fleet" tier** for managing multiple engine shards, and a broad **security-hardening wave**
from the 2026-06 audit.

### Added
- **Multi-process sharding (L3).** An inbound connection can carry an optional `shard` tag;
  `serve --shard <id>` runs an engine process that owns only that shard's inbound connections
  (outbound + routing/handlers are shared), and a new `supervise` command spawns, monitors, and
  restarts one `serve` subprocess per shard (each with its own SQLite db file and API port).
  Per-connection sharding parallelizes intake across CPU cores; per-channel FIFO is preserved
  within a shard. (#584)
- **Internal pass-through (PT) connectors (L4).** A Handler may `Send` into an internal
  `PassThrough()` inbound that carries its own router; the message re-ingresses as a new
  content-addressed child message inside the same transaction (at-least-once, count-and-log, and
  single-finalizer authority all preserved), bounded by a correlation-depth loop guard. This
  generalizes the ADR 0013 re-ingress primitive. Implemented on **all three store backends** —
  SQLite, plus full **Postgres and SQL Server parity** for the atomic re-ingress. (#585, #590)
- **Store-once-deliver-many (L2b).** A high-fan-out outbound now stores the message body **once**
  (content-addressed, reference-counted `shared_body`) instead of once per destination;
  single-destination delivery is unchanged (inline, byte-identical). (#580)
- **Fleet tier — manage multiple engine shards.** The console can register and switch between
  multiple engine endpoints (#582); the IDE promote flow can target a specific engine
  instance/shard (#583).
- **IDE editor productivity.** A MessageFoundry build toolbar + CodeLens on config files (#593),
  an "Insert Element" quick-pick with expanded transform-idiom snippets (#595), a Wizards group
  with collapsible Home groups (#578), and a `vsce` VSIX packaging script (#577).
- **Config-fingerprint attestation.** Config reloads record a config fingerprint in the reload
  audit (ADR 0041 load-path attestation). (#597)

### Changed
- **Faster fan-out.** On a fan-out the engine parses the per-message payload once where it is
  value-identical, avoiding redundant re-parsing. (#581)

### Fixed
- **Fail-fast pass-through guard.** A graph with a PT inbound on a store backend that does not
  implement PT re-ingress is now rejected at startup *and* on reload/dry-run (a clear configuration
  error, HTTP 422) — before any listener binds — instead of failing at the first `Send`. (#587)
- **Auth hardening.** Tighter field-level authorization, a last-admin guard, a corrected TOTP
  window, and rate-limit documentation fixes. (#563)
- **API / store.** Channel-scoped event and topology reads, faster WebSocket session revocation,
  and atomic bootstrap-secret creation. (#565)
- **IDE.** Workspace-trust gating, machine-scoped promote targets, and a fail-closed AI-assist
  policy (SEC-004/005/022). (#561)

### Security
The 2026-06 security-audit remediation wave (in-repo remediation ledger, #566):
- **Transport TLS / SSRF / injection:** FTPS TLS verification, an FHIR-path SSRF guard, and
  read-only enforcement on `db_lookup` (SEC-001/010/009). (#560)
- **Listener hardening:** a cleartext-bind guard plus source-IP allowlist for the raw-TCP/X12
  listeners. (#558)
- **DICOM:** fail-closed C-STORE SCP peer controls (calling-AE + peer-IP) and a passphrase-key
  callback (SEC-012/016). (#559)
- **Pipeline:** off-event-loop router/transform execution and a non-HL7 ingress size cap
  (SEC-013/017). (#562)
- **Config trust:** enforce Windows config-source trust and scope the sibling-helper finder
  (SEC-003/019). (#564)
- **PHI redaction:** narrowed a free-text PHI residual and added an advisory raise-fstring lint
  (SEC-023). (#557)
- **Supply chain:** Dependabot security-track guardrails and adopter-scaffold hash-pinning. (#556)
- **Static analysis:** resolved two real CodeQL findings (webview HTML attribute escaping;
  owner-only file-delivery fallback) (#554) and adopted a CodeQL triage policy + accepted-risk
  register (ADR 0034). (#567)

### Docs
- ADRs 0037–0040 record the throughput-build decisions (multi-process sharding, pass-through
  connectors, the shelved L5 DB-sharding design, and the not-adopted free-threading assessment)
  (#591); design notes for L5 DB-sharding (#588) and cp314t readiness (#589); and the Secure
  AI-Assisted Development Standards updated with the audit lessons (#576).

## [0.2.5] — 2026-06-26 — Early Access

A bug-fix release hardening SQL Server cluster cold-start.

### Fixed
- **SQL Server: concurrent schema-init race on a virgin DB (HA cold start).** Two cluster nodes starting
  simultaneously against an empty database both ran the `IF OBJECT_ID(...) IS NULL CREATE TABLE` guards
  with no cross-node lock, so both issued `CREATE` and the loser died at startup on a `2714` ("There is
  already an object named ..."). `_ensure_schema` now takes an exclusive `sp_getapplock`
  (`mefor:schema_init`) around the DDL — the T-SQL analog of the PostgreSQL store's existing schema
  advisory lock — so the second node serializes and runs the now-no-op guarded CREATEs cleanly. Single-node
  and pre-created schema are unaffected; SQLite and PostgreSQL were already race-safe. (#553)

### Changed
- Docs: the `[cluster]` settings docstring and the pool-size validation error now name both `postgres` and
  `sqlserver` (the cross-section validator already admitted both). (#553)

## [0.2.4] — 2026-06-26 — Early Access

A bug-fix release that completes the EF-6 SQL Server fix shipped in 0.2.3.

### Fixed
- **SQL Server: EF-6 "Connection is busy with results for another command" fully resolved (0.2.3's fix
  was incomplete).** v0.2.3 (#543) switched the FIFO claim read to `fetchall`, but draining the
  `UPDATE...OUTPUT` *rows* does not free the *statement handle* — without MARS the pooled connection was
  still returned to the aioodbc pool busy, so the error reproduced at every cold start. All pooled cursor
  sites now close the cursor (`SQLFreeStmt`/`SQLCloseCursor`) via a new `_cursor` context manager before
  the connection is released, on both the success and exception paths; `claim_ready` (another
  `UPDATE...OUTPUT`) and the `DELETE...OUTPUT` handoffs had the same latent gap and are covered too. A
  driver-free unit test now asserts the close-before-release invariant so the regression can't recur.
  SQLite and PostgreSQL were unaffected. (#550)

## [0.2.3] — 2026-06-26 — Early Access

A bug-fix + feature release: the SQL Server store no longer raises "connection busy" errors under
concurrent load, plus connection/transport event logging, GUI-managed translation tables, and inbound
listener port-conflict detection.

### Fixed
- **SQL Server: "Connection is busy with results for another command" under concurrent load (EF-6).**
  `claim_next_fifo` — and three sibling sites (`_maybe_finalize`, `consume_recovery_code_hash`,
  `consume_totp_step`) — read a result-set-returning statement with a lone `fetchone()` and could return
  the pooled connection to the pool with the result set still pending, so the next borrower's first
  command raced an `HY000` busy error (ODBC Driver 18, no MARS). All affected sites now fully drain the
  result set (`fetchall`) before commit/release. SQLite and PostgreSQL were unaffected (asyncpg
  materializes rows; SQLite has no shared pooled-connection single-result-set constraint). (#543)

### Added
- **Connection/transport event log + "Response Sent" ACK capture** (ADR 0020 / ADR 0021). A new id-keyed,
  metadata-only `connection_event` table records inbound connection lifecycle, pre-ingress failures, and
  outbound lane transitions, with a `[diagnostics]` config block (per-connection overrides + retention),
  a `GET /events` read API, and a console **Event Log** page. Event reasons are scrubbed and encrypted at
  rest. (#541)
- **GUI-managed translation tables (code sets)** (ADR 0033). A code-set CLI + writer and a VS Code
  extension grid editor / **Translation Tables** view for maintaining code-set mappings. (#540)
- **Inbound listener port-conflict detection** — static + runtime checks that flag two inbound
  connections bound to the same host:port before they collide at startup. (#538)

### Changed
- Docs: README install instructions are now version-agnostic and link the website docs; the roadmap
  section is replaced with a features summary. (#542, #544)

## [0.2.2] — 2026-06-24 — Early Access

A security-hardening release: PHI-at-rest encryption is closed across every backend, the active-passive
cluster gains a store-checked split-brain fence, outbound delivery is effectively-once, and the at-rest
cipher becomes crypto-agile — all additive, with the on-disk `mfenc:v1` format byte-identical.

### Changed
- **BREAKING — Python 3.14 is now the only supported runtime.** `requires-python` is raised to `>=3.14`
  (was `>=3.11`), and the ruff/mypy targets, CI matrix (Linux + Windows Server 2022/2025, all on 3.14),
  Docker base image, lockfiles, and adopter scaffold move with it. **Adopters and engine hosts must be on
  Python 3.14** — a 3.11/3.12/3.13 host will refuse to install the wheel. The 3.11/3.12/3.13-specific test
  apparatus is retired with this change (the `MEFOR_PY311_QUARANTINE` conftest lever, the `py3.11 store
  soak` CI job, and `scripts/soak/store_soak.py`; the underlying BACKLOG #17 asyncio↔aiosqlite concern is
  still mitigated by the shared session loop in `pyproject.toml`).

### Security
- **PHI-at-rest encryption closed across all three backends.** The patient `summary` (MRN + name) and
  `metadata` columns are now encrypted at rest (previously cleartext even with encryption enabled), and the
  SQL Server `error` / `last_error` / `message_events.detail` columns are brought to parity with SQLite and
  Postgres — every cipher column is now AES-256-GCM at rest. Coverage is surfaced by a new authenticated,
  audited `GET /security/posture` route (reports the active-key fingerprint + per-backend column coverage;
  never key bytes).
- **Fail-closed for PHI without a key.** An instance declared `data_class = phi` now **refuses to start**
  without an encryption key (previously it started in cleartext with a warning), unless explicitly overridden
  by the new, audited `[store].allow_unencrypted_phi`.
- **Crypto-agility marker (additive).** The at-rest cipher marker is now version/algorithm-aware
  (`mfenc:v2:<alg>:…`) so a future algorithm can be introduced without a data migration. The `mfenc:v1`
  format is byte-identical and AES-256-GCM remains the only algorithm; decryption fails closed on an unknown
  marker version or algorithm.
- **Database-TLS hardening.** A new `[store].ssl_root_cert` pins a private database CA (Postgres), with
  machine-store CA-import and certificate-rotation operator runbooks. The DPAPI key file's ACL now grants the
  service account read access without broadening exposure.

### Added
- **Active-passive split-brain fence.** A monotonic leader-epoch fencing token on the leadership lease,
  validated inside the FIFO claim transaction, so a superseded or paused ex-leader that resumes is fenced out
  (it claims nothing) — backed by continuous "at most one leader" SLO checks and a real-handover failover
  test. SQLite (single-node) behavior is unchanged.
- **Effectively-once outbound delivery.** A same-transaction idempotency ledger skips re-delivery of an
  already-delivered message after a failover or crash-recovery re-claim, without re-ordering a lane; an
  operator-initiated replay still re-sends.
- **Pre-side-effect leadership re-checks** so a node that loses leadership between claiming and sending
  re-queues the work rather than emitting it as a stale leader.
- `messagefoundry verify --check-disposition` for post-deploy disposition validation.

### Fixed
- CycloneDX SBOM generation on Python 3.14.
- PyPI long-description rendering (version pins, links).
- De-flaked several intermittent CI tests (failover-load timeouts, a harness server port-bind race, the
  startup fault-isolation recovery assertion, and the docker-smoke shutdown-marker check).

## [0.2.1] — 2026-06-23 — Early Access

### Fixed
- **Windows: `messagefoundry --help` crashed on a legacy codepage** — the top-level help rendered a
  non-cp1252 character (a `->` arrow in the `adr-analyze` subcommand help, new in 0.2.0), so `--help`
  aborted with `UnicodeEncodeError` on a cp1252/charmap console (cmd, PowerShell, or any redirected
  stdout). `main()` now reconfigures stdout/stderr with `errors="replace"` and the help text is ASCII;
  the machine-read JSON introspection subcommands are unaffected (`json.dumps(ensure_ascii=True)`).
- **`verify --section host` crashed without the `[console]` extra** — `check_console_no_window()`
  resolved a console submodule via `find_spec`, which imported the console package and its eager `httpx`
  dependency, so a `[sqlserver]`-only install aborted with `ModuleNotFoundError: No module named 'httpx'`
  instead of skipping the console check. The console package now imports its API client lazily (PEP 562
  `__getattr__`), so resolving a submodule no longer requires `httpx`, and the check degrades to SKIP if a
  console dependency is absent.

## [0.2.0] — 2026-06-23 — Early Access

### Added
- **One-click console launch** — a windowed `messagefoundry-console` launcher (`[project.gui-scripts]`, no
  flashing console window) carrying the MessageFoundry badge as the window/taskbar icon, plus
  `scripts/console/install-console-shortcut.ps1` to drop Desktop / Start-Menu shortcuts (per-user, or
  `-AllUsers` for machine-wide). Operators open the admin console by double-clicking an icon instead of
  running a Python command. See [ADR 0032](docs/adr/0032-console-desktop-launch.md).
- **SQL Server 2025 support** — the SQL Server store + Database connector are now validated against SQL
  Server 2025 (17.x) in addition to 2022 (16.x): both majors are exercised by the gated CI legs (store,
  coordinator, failover, and load smoke). No schema or T-SQL change was needed — ODBC Driver 18 (18.5+)
  covers both. The supported-version matrix moves from 2019/2022 to **2022/2025**. Note: SQL Server 2025
  requires an AVX-capable CPU.

### Security
- **Dependency fast-response program** — a KEV→EPSS→CVSS triage policy with a **≤72h fast lane** for
  actively-exploited dependency CVEs ([`.github/SECURITY.md`](.github/SECURITY.md),
  `docs/security/DEP-CVE-RUNBOOK.md`); a **daily** SCA cron;
  Dependabot moved to the native `uv` ecosystem with **automatic hashed-lock re-export**; **scoped
  auto-merge** of safe patches with a **supply-chain cooldown**; weekly **RV.2 metrics**
  (`docs/security/DEPENDENCY-METRICS.md`); and an adopter
  remediation SLA + advisory process ([`docs/SUPPORT-POLICY.md`](docs/SUPPORT-POLICY.md),
  `docs/security/ADVISORY-PROCESS.md`).
- **Adopter "vulnerable pin" tripwire** — `messagefoundry init`'s scaffolded CI gains an `audit-pin` job
  that reds an adopter's build when their pinned engine or its dependencies have a known published
  advisory ([`docs/ADOPTER-CI.md`](docs/ADOPTER-CI.md)).
- **Release-sync drift guard** — a tag/PyPI/public-mirror version-consistency tripwire + a publish-time
  version guard, so the git tag, the PyPI wheel, and the OSS mirror can't silently diverge.

## [0.1.0] — 2026-06-18 — Early Access

First public **Early Access** release: the feature set is complete and validated by the project's own
tests, but the external code review + penetration test (the bar for a security-certified **v1.0**) happen
*after* launch — so this is not yet "GA / independently security-reviewed". See
[`docs/EARLY-ADOPTER-GUIDE.md`](docs/EARLY-ADOPTER-GUIDE.md).

### Added
- **Engine + staged pipeline** — code-first Connection / Router / Handler model on a durable staged queue
  (ingress → routed → outbound) with at-least-once handoff, retry/backoff, dead-letter, and replay.
  Count-and-log: every received message is persisted with its disposition before the ACK.
- **Transports** — MLLP and File (source & destination); REST, SOAP, and Database destinations; a Database
  poll source. Payload-agnostic ingress (HL7 v2.x by default; JSON / XML-SOAP / X12 / DB records).
- **Server-DB store backends (production)** — PostgreSQL and Microsoft SQL Server, alongside the
  zero-config single-node SQLite (WAL) default. Byte-identical single-node behaviour on every backend.
- **Active-passive high availability** — self-fencing leadership lease, leader-gated message graph,
  claim-time per-lane FIFO across nodes, cross-node convergence, and read-only `/cluster/*` observability
  (surfaced as a leader/role/lease + node-roster view on the console's Engine Status page), on **both**
  PostgreSQL and SQL Server. A two-node failover-load test harness (SIGKILL-the-primary under load) proves
  recovery + no acknowledged loss + preserved per-lane ordering.
- **Security** — authentication + RBAC (local and AD: LDAP/Kerberos), deny-by-default per-route
  permissions, opaque sessions, a user-attributed tamper-evident (hash-chained) audit log, AES-256-GCM
  body encryption at rest with key rotation, native transport TLS (API HTTPS/WSS + MLLP-over-TLS) with an
  off-loopback bind guard and a certificate-expiry monitor, deny-by-default egress controls, PHI log
  redaction, and a centrally-governed, PHI-safe AI-assist policy.
- **Operability & tooling** — a localhost HTTP/WebSocket API; a PySide6 admin console; the `messagefoundry`
  CLI (`serve` / `validate` / `graph` / `dryrun` / `check` / `connection` / `generate` / …); a VS Code
  extension (setup, promote, test bench); a headless load + failover test harness; and a published
  throughput + active-passive failover **baseline** ([`docs/benchmarks/TUNING-BASELINE.md`](docs/benchmarks/TUNING-BASELINE.md)).
- **Alerting** — a logging sink plus a webhook/email notifier; queue-buildup and certificate-expiry alerts.
- **Deployment** — runs as a Windows service via NSSM; a channel × TLS-posture deployment matrix
  ([`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)); a staged Lab → Shadow → Limited → Full early-adopter guide.

### Notes
- Throughput is **hardware-dependent** (a durable-write-bound path); the published numbers are "as measured
  on a reference config", not a guarantee — re-run the method on your hardware. See
  [`docs/benchmarks/TUNING-BASELINE.md`](docs/benchmarks/TUNING-BASELINE.md).
- Releases are built, SBOM'd (CycloneDX), and signed with [Sigstore](https://www.sigstore.dev/) — see the
  `release` workflow.

[Unreleased]: https://github.com/MEFORORG/MessageFoundry/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/MEFORORG/MessageFoundry/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/MEFORORG/MessageFoundry/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/MEFORORG/MessageFoundry/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/MEFORORG/MessageFoundry/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/MEFORORG/MessageFoundry/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/MEFORORG/MessageFoundry/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.15...v0.3.0
[0.2.15]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.14...v0.2.15
[0.2.14]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.13...v0.2.14
[0.2.13]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.12...v0.2.13
[0.2.12]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/MEFORORG/MessageFoundry/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MEFORORG/MessageFoundry/releases/tag/v0.1.0
