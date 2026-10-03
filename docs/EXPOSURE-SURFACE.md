# What MessageFoundry exposes: a scoping map

**This page lists what the engine exposes and points to the document that holds each fact.** It is
for a site security team that runs an exposure-management program. Gartner calls that Continuous
Threat Exposure Management. Its first stages are scoping and discovery: deciding what is in view,
then finding what is exposed. This page feeds both for MessageFoundry.

It is a map, so it restates as little as it can. If this page and a linked document disagree, the
code decides.

These limits apply to the whole page:

- It describes the engine as shipped. What a deployment would expose depends on its configuration.
  [Read your own instance's lists](#read-your-own-instances-lists) says how to get that.
- Its lists say "at least". A longer inventory of interfaces is
  [section 5 of ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md#5-communications-inventory-asvs-1311).
  A test guards that inventory against drift, and the section says what the test can see.
- Configuration is Python that runs inside the engine. No allow-list on this page bounds what a
  Router or Handler module does. [DEPLOYMENT.md](DEPLOYMENT.md#egress-allow-lists) names the controls
  that do apply to that code.

---

## The engine listens on the operator socket and on one socket per listening Connection

At least these open a listening socket. Each one binds loopback (`127.0.0.1`) by default.

| What listens | Bind address | Port | Read more |
|---|---|---|---|
| The operator API, the web console at `/ui` and the stats WebSocket, all on one socket | `127.0.0.1` while `[security].local_access_only` is true, the default. Otherwise `[security].listen_address` | `[api].port`, default `8765` | [Control-plane listeners](ASVS-L2-PHASE0-CHANGES.md#52-control-plane-listeners) |
| Each inbound Connection of type MLLP, raw TCP, X12, HTTP or DICOM C-STORE SCP | `[inbound].bind_host`, default `127.0.0.1`. A Connection can override it with `bind_address` | Set on the Connection | [Message-plane connectors](ASVS-L2-PHASE0-CHANGES.md#51-message-plane-connectors) |

`serve --host` and `serve --port` override the settings file, and so do `MEFOR_*` environment
variables. Read the service's command line and environment too.

At least these inbound types open no listening socket. A File Connection reads a directory. On a UNC
path that directory is on another host, reached over SMB. A database-poll or remote-file (SFTP,
FTP, FTPS) Connection dials out. Timer, loopback and pass-through Connections reach no outside
system.

At least these settings change the size of the operator surface:

- `[api].expose_docs` is false by default. Set to true, the engine also serves `/docs`, `/redoc` and
  `/openapi.json`.
- `[security].serve_web_console = false` stops the engine from mounting `/ui`. Left unset, `/ui`
  also stays unmounted on at least a non-loopback bind.
- Under `supervise`, each engine shard gets its own API port, counted up from `--base-port`. Count
  one operator socket per engine shard.

[ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md#windows-firewall) has a port table for at least the
MLLP, DICOM and X12 listeners and the operator API. It has no row for some listeners on this page.
For the TLS and peer controls on each listener, see the
[channel matrix](DEPLOYMENT.md#channel--tls-posture-matrix).

## Each outbound hop has its own setting for the target

At least these hops dial out. The table names the setting that sets or limits each target. The
engine's own update check makes no network call: `[update_check].mode` accepts only `local`.

| Outbound hop | Setting that names or limits the target | Read more |
|---|---|---|
| Outbound Connections, the `db_lookup` and `fhir_lookup` reads, and database-poll and remote-file inbound Connections | The `[egress].allowed_*` destination lists | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |
| SMART and OAuth2 token endpoints | `[egress].allowed_http` | `_check_credential_token_url_egress` in `messagefoundry/pipeline/wiring_runner.py` |
| A forward web proxy that the config names by address | `[egress].allowed_proxy` | `_check_forward_proxy_egress` in `messagefoundry/pipeline/wiring_runner.py` |
| AI assistance broker | `[ai].allowed_endpoints` | [CONFIGURATION.md](CONFIGURATION.md#ai--ai-coding-assistance-policy) |
| OpenID Connect identity provider | `[auth].oidc_allowed_endpoints` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Alert webhook and alert email | `[alerts].webhook_allowed_hosts` and `[alerts].smtp_allowed_hosts` | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |
| Active Directory over LDAP | One target, `[auth].ad_server` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Store database on SQL Server or PostgreSQL | One target, `[store].server`. The default SQLite store is a local file | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| HashiCorp Vault, for the store key or for Connection secrets | One target each: `MEFOR_STORE_VAULT_ADDR` and `MEFOR_SECRETS_VAULT_ADDR`. With one unset, the Vault client falls back to its own `VAULT_ADDR` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Syslog forwarding and the startup clock check | `[logging].forward_host` and `[logging].ntp_peer` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Startup TLS-floor probe, behind a declared TLS terminator under `enforce` | One target, `[security].web_console_public_address` | `probe_tls_floor` in `messagefoundry/config/tls_probe.py` |
| Backup to a network share | `[backup].destination` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |

What an empty or unset list permits differs by setting and by `[security].block_unlisted_outbound`.
This page does not restate it. Read each setting's entry in [CONFIGURATION.md](CONFIGURATION.md)
before you rely on it.

A host firewall is the layer under all of this.
[ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md#windows-firewall) lists ports for some of these hops.
It says to mirror each outbound firewall rule with its allow-list entry.

## At startup, `serve` guards stop the engine and a listener guard fails one Connection

[DEPLOYMENT.md](DEPLOYMENT.md#bind-guard-behavior-summary) describes the bind guards and their
overrides, and [Before you expose off-loopback](DEPLOYMENT.md#before-you-expose-off-loopback) is the
checklist. `serve` would exit with code 2, before it starts the web server, on at least these.
Each one is in `_serve` in `messagefoundry/__main__.py`.

| Guard | What it refuses |
|---|---|
| Sign-in off | Authentication disabled, on any bind, loopback included (vault BACKLOG #2719). No setting turns it off; a config that sets the removed `[security].require_sign_in` key is refused at load, before this guard |
| Operator bind | A non-loopback operator bind that has neither an operator certificate (`[api].tls_cert_file`) nor a declared TLS terminator |
| Certificate revocation | A non-loopback operator bind that serves TLS on an operator certificate with no declared terminator in front, unless `MEFOR_TLS_REVOCATION_ATTESTED=1` is set |
| Plaintext proxy hop | A declared TLS terminator with no operator certificate, unless `[api].plaintext_upstream_hop_acknowledged` is true |
| Proxy attestations | Under the default `[security].enforcement = enforce`, a non-loopback bind behind a declared TLS terminator that lacks `[api].proxy_intra_service_auth` or `[api].proxy_tls_min_version` |
| Open egress | Under `enforce`, outbound egress that is fully open: `[security].block_unlisted_outbound` is not set to true, and no destination list that the guard counts is populated. The `egress_open` expression in `_serve` holds the rule |

Under `enforcement = warn`, the proxy-attestation and open-egress guards only warn, and the
operator-bind guard accepts the override that DEPLOYMENT.md describes. The sign-in, revocation and
plaintext-hop guards refuse under `warn` too.

`serve` refuses on more than this table, so clearing one guard does not mean `serve` starts. The
checklist names more of these refusals, and `_serve` holds at least some of the rest. Others come
later in startup.

A listener guard is different. At startup it fails one Connection, and `serve` keeps going. By
default, a non-loopback MLLP, HTTP, DICOM, raw TCP or X12 listener that has no TLS does not bind,
and its Connection shows as failed. Raw TCP and X12 have no TLS to turn on. A Connection that sets
`tls_hop_attested` with a reason crosses this guard, and the engine reports it as a loosening.
`_inbound_insecure_bind_permitted` in `messagefoundry/pipeline/wiring_runner.py` holds the rule.

At least two more listener checks fail a Connection under `enforce`, and `tls_hop_attested` clears
neither. `check_inbound_revocation` covers a mutual-TLS listener, and `tls_crl_file` or
`tls_revocation_attested` clears it. `check_http_intake_auth` covers a non-loopback HTTP listener,
which [CONNECTIONS.md](CONNECTIONS.md#http-web-service-listener--http-inbound-only-adr-0023)
describes. Both checks are in `messagefoundry/pipeline/wiring_runner.py`. They run when each inbound
Connection starts. So a running engine does not prove that every listener passed. On a config reload
the same refusal fails the whole reload.

**The operator socket serves TLS in every topology but one.** With no operator certificate, the
engine mints a self-signed pair on first run and serves TLS with it. The exception is
`[api].tls_terminated_upstream = true` with no `[api].tls_cert_file`. There the engine mints nothing
and speaks plaintext to the declared proxy, so that hop is the site's to protect.
[ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md)
has the detail.

`[security].allowed_client_networks` is a second layer. It does not limit who can reach the socket.
It filters requests by client address, with exemptions. It is empty by default, which means no
restriction. The check has limits, so keep a host firewall as the first layer.
[ADR 0151](adr/0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md)
has the detail. [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md) says what turning a protective
switch off costs.

## What sits on disk is listed in PHI.md

- [PHI.md, section 2](PHI.md#2-where-phi-lives--data-at-rest-inventory) is the inventory of where
  patient data rests.
- [ASVS-L2-PHASE0-CHANGES.md, section 4](ASVS-L2-PHASE0-CHANGES.md#4-key-management--cryptographic-inventory-asvs-1111--1112)
  is the inventory of keys.
- [ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md#path-exclusions) lists the Windows paths: the store
  file and its sidecars, the logs and the key files.

## Read your own instance's lists

No single source gives the whole answer. Each one below has gaps that this page does not list. The
operating system's socket list is the direct answer for what is listening.

| Question | Where to read it |
|---|---|
| What is listening on the host? | The operating system's socket list, such as `Get-NetTCPConnection -State Listen` on Windows |
| Which Connections exist, and of what type? | `messagefoundry graph --config <config dir> --json` |
| What is a running engine serving? | `GET /connections` |
| Which protective switches are off on a running engine? | `GET /security/posture` |
| Which switches does the settings file turn off? | `messagefoundry security show --service-config <file>` |
| Which Connections carry a loosening, across all engine shards? | `messagefoundry check --config <config dir>` |

## `messagefoundry verify` does not measure exposure

`verify` is an on-box acceptance check. Its sections are at least host, store, smoke, manual and
federation. [testing/VERIFY.md](testing/VERIFY.md) is its reference. It checks that the host can run
the engine and that the configured store opens. It checks that one synthetic message routes. It
checks that the federated sign-in settings hold together.

It does not check at least these, read from `messagefoundry/verify/`:

- Firewall rules, or reach from another host. The `host.ports` row is always MANUAL. It only tests
  whether a few ports are free on `127.0.0.1`.
- The ports your Connections bind. The `host.ports` row does not read your config directory.
- The operator bind and its TLS. The `manual.tls` row is MANUAL. A person confirms it.
- Egress. No row reads an `[egress]` list.
- Loosenings. No row reads the loosening list. Use the posture read-out above.
- Known vulnerabilities. `verify` reads no advisory feed and no software bill of materials.

So a green run says nothing about exposure.
[What a green run proves](testing/VERIFY.md#what-a-green-run-proves--and-what-it-doesnt) states the
rest of its limits.

## These documents feed a vulnerability program

| Input | Document | What to take from it |
|---|---|---|
| Component inventory | [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) | Each release carries a software bill of materials (SBOM) for Linux and one for Windows, a Vulnerability Exploitability eXchange (VEX) file, and signatures. Scan the SBOM for the platform you run. The document says what each SBOM covers |
| How the project ranks a dependency vulnerability | [.github/SECURITY.md](../.github/SECURITY.md#dependency-third-party-vulnerabilities) | Known exploited first (the CISA Known Exploited Vulnerabilities list), then the Exploit Prediction Scoring System (EPSS) score. The Common Vulnerability Scoring System (CVSS) score only breaks ties |
| How long an old version stays covered | [SUPPORT-POLICY.md](SUPPORT-POLICY.md) | Only the latest release is supported, with no back-port. A clock runs on adopting each security release, and the page gives the days |

Some security documents are not published.
[SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) says what is withheld and how to ask for it.
