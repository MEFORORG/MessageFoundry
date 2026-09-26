# Changelog

All notable changes to MessageFoundry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **A DAST pass now sends hostile bytes to live MLLP, raw-TCP and X12 listeners and checks the
  engine's ingress rules.** `scripts/security/dast_ingress_sweep.py` runs a real engine on loopback.
  It sends broken framing, hostile HL7 and seeded mutations. Six detectors check each case: one reply
  per decoded MLLP frame, one row per decoded frame, a listener that stays up, bounded time, bounded
  heap, handle and task growth, and no message content logged at INFO or above. Each detector has a
  canary that must trip it. The seeded run and the canaries run in the existing required test legs.
  A new advisory `dast-ingress` job in `dast.yml` adds a nightly randomized budget. The first run
  found three engine defects, each pinned by a strict xfail and not fixed here. A blank segment faults
  the inbound handler. An alphanumeric MSH-1 gets an ACK whose MSA-1 cannot be read.
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

### Changed
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
### Fixed
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
- **A dual-control release can no longer run without an audit row, or be recorded as failed after
  it ran.** The approval gate wrote `approval.approved` only after the operation ran. An audit log
  that refused writes would have let a replay or a reload complete with no record of the release,
  and handed the approver a 500. The gate now writes a new `approval.release_attempted` row, naming
  both identities, before it moves the request. If that write fails, the approve returns 503, the
  operation does not run, and the request stays pending. After the operation has run, a failed
  `approval.approved` write is logged at ERROR and the release still succeeds. The replay and
  reload executors had the mirror defect: their own audit row failing after the action ran made
  the gate mark the request `failed`. They now log that failure at ERROR instead. (`BACKLOG #1940`)
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
- **BREAKING: a federated link on an account with no directory id no longer signs anyone in.** The
  link-time refusal further down this section (`BACKLOG #1143` slice C) stops new links on such an
  account. This closes the ones made before it.
  A federated sign-in whose `(issuer, sub)` selects an account with no `directory_object_id` is now
  refused before the directory is asked. The login page shows the generic failure, and the
  `auth.login_failed` audit row carries `directory_object_id_missing`. The directory recheck no
  longer asks about such an account by its username either. It skips it and writes one
  `auth.ad_reconcile_binding_unkeyed` row with the same reason, once per account per process. That
  is a new audit action, separate from the outage's `auth.ad_reconcile_skipped`, because it is not
  benign. On a directory that returns no readable `objectGUID`, a Windows SSO sign-in still finds
  such an account by its username, as it finds any account with no directory id there.
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
  exist as a directory account; a Windows SSO (Kerberos) sign-in creates one. Nothing else creates
  one yet, so a site with no Kerberos sign-in cannot link anyone until a later change adds that.
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
    nobody there can sign in through the identity provider. Directory sign-in still works there.
  - **An account never gains an id after it is created.** To link one, make the directory return
    `objectGUID`, turn Windows SSO on if it is off, delete the account, and have the person sign in
    once with Windows SSO. Nothing else creates a directory account. The new account has a new
    `user_id`, so the old one's uploads, upload quota and saved searches do not follow.
  - **A link made before this change on such an account is left in place.** It can still be
    removed, and it cannot be moved to another `sub`. This change added no sign-in refusal for it;
    the `BACKLOG #2027` entry at the top of this section does. On a directory that now
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
  too. Still missed, at least: a bare CR followed by text that reads as a field line. The engine
  sees only the header block the HTTP reader parsed, so any lost line that leaves no trace there
  is missed the same way. Connection probes and the alert webhook discard the body and are not refused. They stop reading at the first bad
  chunk line and log a WARNING. **Migration:** none in configuration. The partner or its proxy must
  send well-formed HTTP/1.1. (ASVS 4.2.1, ASVS 15.2.2, [BACKLOG #1125](docs/BACKLOG.md),
  [BACKLOG #1979](docs/BACKLOG.md))
### Fixed
- **The startup ERROR for an unusable bundled breach corpus now says a first `serve` still creates
  the bootstrap admin, whose forced password change that corpus would refuse.** It also says
  `provision-admin` fails for the same reason, where the deadline is, and that changing
  `password_check_breached` needs a restart (BACKLOG #1886).
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
  the constant. This entry does not quote the new value, because it can move again before the
  release. **Migration:** upgrade the web console together with the engine, to a release whose
  `messagefoundry_webconsole.SUPPORTED_ENGINE_SEAMS` holds this engine's
  `messagefoundry.api._ui_seam.ENGINE_UI_SEAM`. Or set `[security].serve_web_console = false` to
  run the JSON API alone. (`BACKLOG #1141`)
- **BREAKING — the `403` for a session that must change its password is no longer always the exact
  string `password change required`.** When the engine can state the temporary password's
  deadline, the detail now reads `password change required; the temporary password stops working at
  <time>`. The time is UTC ISO 8601, for example `2026-09-27T14:00:00Z`. The never-claimed
  bootstrap account still gets the bare string. The old text stays as the prefix, so a client that
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
  websockets server's own handshake answers. Each step it adds fails open. On an error it logs a
  WARNING, once per response family and step, and leaves uvicorn's own response as it was. Those
  steps rely on uvicorn and websockets internals, measured at uvicorn 0.49.0 and websockets 16.0,
  the versions `requirements.lock` pins. `pyproject.toml` admits other versions, and on one of
  them a step may fail open and leave its headers off. (`BACKLOG #1120`)
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

[Unreleased]: https://github.com/MEFORORG/MessageFoundry/compare/v0.4.0...HEAD
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
