# What MessageFoundry exposes: a scoping map

**This page lists what the engine exposes and points to the document that holds each fact.** It is
for a site security team that runs an exposure-management program. Gartner calls that Continuous
Threat Exposure Management. Its first stage is scoping, which asks what each product exposes. This
page is the input to that stage for MessageFoundry.

It is a map, so it restates as little as it can. If this page and a linked document disagree, the
code decides.

Three limits apply to the whole page:

- **It describes the engine as shipped.** What a deployment would expose depends on its
  configuration. [Read your own instance's lists](#read-your-own-instances-lists) says how to get
  that.
- **Its lists say "at least".** The full inventory of every interface is
  [section 5 of ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md#5-communications-inventory-asvs-1311).
  A test guards that inventory against drift, and the section says what the test can see.
- **Configuration is Python that runs inside the engine.** No allow-list on this page bounds what a
  Router or Handler module does. [DEPLOYMENT.md](DEPLOYMENT.md#egress-allow-lists) names the controls
  that do apply to that code.

---

## The engine listens on the operator socket and on one socket per listening Connection

At least these open a listening socket. Each one binds loopback (`127.0.0.1`) by default.

| What listens | Bind address | Port | Read more |
|---|---|---|---|
| The operator API, the web console at `/ui` and the stats WebSocket, all on one socket | `127.0.0.1` while `[security].local_access_only` is true, the default. Otherwise `[security].listen_address` | `[api].port`, default `8765` | [Control-plane listeners](ASVS-L2-PHASE0-CHANGES.md#52-control-plane-listeners) |
| Each inbound Connection of type MLLP, raw TCP, X12, HTTP or DICOM C-STORE SCP | `[inbound].bind_host`, default `127.0.0.1`. A Connection can override it with `bind_address` | Set on the Connection. Only `DICOM()` has a default, `104` | [Message-plane connectors](ASVS-L2-PHASE0-CHANGES.md#51-message-plane-connectors) |

**The settings file is not the last word on a bind.** `serve --host` and `serve --port` override it,
and so do `MEFOR_*` environment variables. Read the service's command line and environment too.

The other inbound types open no listening socket. A File Connection reads a directory. On a UNC
path that directory is on another host, reached over SMB. A database-poll or remote-file (SFTP,
FTP, FTPS) Connection dials out. Timer, loopback and pass-through Connections reach no outside
system.

These settings change the size of the operator surface:

- `[api].expose_docs` is false by default. Set to true, the engine also serves `/docs`, `/redoc` and
  `/openapi.json`.
- `[security].serve_web_console = false` stops the engine from mounting `/ui`.
- Under `supervise`, each engine shard gets its own API port, counted up from `--base-port`. Count
  one operator socket per engine shard.

[ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md#windows-firewall) has sample Windows Firewall rules
for at least the MLLP, DICOM and X12 listeners and the operator API. It has no row for some
listeners and hops on this page. For the TLS and peer controls on each listener, see the
[channel matrix](DEPLOYMENT.md#channel--tls-posture-matrix).

## Each outbound hop has its own limit on the target, and some have none

At least these hops dial out. The table says which setting limits each target, and what an empty
list means. The engine's own update check makes no network call: `[update_check].mode` accepts only
`local`.

| Outbound hop | Setting that limits the target | An empty list means | Read more |
|---|---|---|---|
| Outbound Connections, the `db_lookup` and `fhir_lookup` reads, and database-poll and remote-file inbound Connections | The eight `[egress].allowed_*` lists | Refuse every destination of that type, once `[security].block_unlisted_outbound` is on | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |
| SMART and OAuth2 token endpoints | `[egress].allowed_http` | The same | `_check_credential_token_url_egress` in `messagefoundry/pipeline/wiring_runner.py` |
| Forward web proxy | `[egress].allowed_proxy` | Refuse a proxy address. The `default` proxy, which the operating system names, is exempt | [CONFIGURATION.md](CONFIGURATION.md#egress) |
| AI assistance broker | `[ai].allowed_endpoints` | Refuse the endpoint | [AI.md](AI.md) |
| OpenID Connect identity provider | `[auth].oidc_allowed_endpoints` | Refused at load while OpenID Connect is on | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Alert webhook and alert email | `[alerts].webhook_allowed_hosts` and `[alerts].smtp_allowed_hosts` | Any host | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |
| Active Directory over LDAP | One target, `[auth].ad_server` | No list | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Store database on SQL Server or PostgreSQL | One target, `[store].server`. The default SQLite store is a local file | No list | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| HashiCorp Vault, for the store key or for Connection secrets | One target each: `MEFOR_STORE_VAULT_ADDR` and `MEFOR_SECRETS_VAULT_ADDR` | No list | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Syslog forwarding and the startup clock check | `[logging].forward_host` and `[logging].ntp_peer` | No list | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Backup to a network share | `[backup].destination` | No list | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |

Three things this table does not show:

- **An inbound File Connection is outside the `[egress]` lists.** `[egress].allowed_file_dirs` bounds
  File destinations only.
- **With `auth = entra`, a database hop adds a second target.** The ODBC driver gets its own token,
  and no MessageFoundry setting names where from.
- **Kerberos sign-in and the browser leg of OpenID Connect** are in the infrastructure-hops table.

Once `serve` is past the open-egress guard below, it turns `[security].block_unlisted_outbound` on
if the operator left it unset.

## Startup guards refuse an unsafe bind

`serve` checks the exposure before it opens a socket.
[DEPLOYMENT.md](DEPLOYMENT.md#bind-guard-behavior-summary) is the source of record for each guard,
its override and its exit code. A deploying site would meet at least these:

| Guard | What it does | Read more |
|---|---|---|
| Operator bind | Refuses a non-loopback operator bind that has neither an operator certificate (`[api].tls_cert_file`) nor a declared TLS terminator | [Before you expose off-loopback](DEPLOYMENT.md#before-you-expose-off-loopback) |
| Listener bind | Refuses a non-loopback MLLP, HTTP, DICOM, raw TCP or X12 listener that has no TLS. Raw TCP and X12 have no TLS to turn on. A Connection that sets `tls_hop_attested` with a reason crosses this guard, and the engine reports it as a loosening | [Bind-guard behavior](DEPLOYMENT.md#bind-guard-behavior-summary) |
| Open egress | Under the default `[security].enforcement = enforce`, refuses to start while outbound egress is fully open: no destination list is populated and `[security].block_unlisted_outbound` is not set to true | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |

**The operator socket serves TLS in every topology but one.** With no operator certificate, the
engine mints a self-signed pair on first run and serves TLS with it. The exception is
`[api].tls_terminated_upstream = true` with no `[api].tls_cert_file`. There the engine mints nothing
and speaks plaintext to the declared proxy, so that hop is the site's to protect.
[ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md)
has the detail.

**`[security].allowed_client_networks` is a second layer, and it does not limit who can reach the
socket.** It answers a request with a 403 when the client address is outside the listed networks.
It is empty by default, which means no restriction. Four limits apply:

- The check runs after the engine accepts the connection.
- `/health` is exempt, and loopback is always allowed.
- Behind a proxy the engine was not told about, or behind address translation, it does nothing.
- It does not cover the inbound Connection listeners. Each of those takes its own
  `source_ip_allowlist`.

So keep a host firewall as the first layer.
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

No one command gives the whole answer. Each row below has a stated gap.

| Question | Where to read it | What it leaves out |
|---|---|---|
| What is listening on the host? | The operating system's socket list, such as `Get-NetTCPConnection -State Listen` on Windows | This is the direct answer. It does not say which Connection owns a socket |
| Which Connections exist, and of what type? | `messagefoundry graph --config <config dir> --json` | It imports the config modules, so it runs their code. It prints each Connection's type and authored settings. It does not print the bind address, and an `env()` value shows as a placeholder |
| What is a running engine serving? | `GET /connections` | Needs the `monitoring:read` permission. One row per endpoint, with its method. It fills the peer and port for MLLP and File rows only. It shows only what the caller's scope and the answering engine shard cover |
| Which protective switches are off on a running engine? | `GET /security/posture` | It reports the engine shard that answers |
| Which switches does the settings file turn off? | `messagefoundry security show --service-config <file>` | It reads the authored file only. It leaves out a `serve --host` override and every per-Connection loosening. Its `loosenings_scope` field says so |
| Which Connections carry a loosening, across all engine shards? | `messagefoundry check --config <config dir>` | It also runs the config modules. It opens no store |

## `messagefoundry verify` does not measure exposure

`verify` is an on-box acceptance check with five sections: host, store, smoke, manual and
federation. [testing/VERIFY.md](testing/VERIFY.md) is its reference. It checks that the host can run
the engine and that the configured store opens. It checks that one synthetic message routes. It
checks that the federated sign-in settings hold together.

It does not check at least these, read from `messagefoundry/verify/`:

- **Firewall rules, or reach from another host.** The `host.ports` row is always MANUAL. It only
  tests whether three ports are free on `127.0.0.1`.
- **The ports your Connections bind.** Those three ports are the `--mllp-port` value (default
  `2575`), a fixed `11112`, and `[api].port`. The row does not read your config directory.
- **The operator bind and its TLS.** The `manual.tls` row is MANUAL. A person confirms it.
- **Egress.** No row reads an `[egress]` list, and `verify` dials no partner. The self smoke is a dry
  run with no network. The live smoke sends one message to the engine's own listener.
- **Loosenings.** No row reads the loosening list. Use the posture read-out above.
- **Known vulnerabilities.** `verify` reads no advisory feed and no software bill of materials.

So a green run says nothing about exposure.
[What a green run proves](testing/VERIFY.md#what-a-green-run-proves--and-what-it-doesnt) states the
rest of its limits.

## These documents feed a vulnerability program

| Input | Document | What to take from it |
|---|---|---|
| Component inventory | [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) | Each release carries a software bill of materials (SBOM) for Linux and one for Windows, a Vulnerability Exploitability eXchange (VEX) file, and signatures. Scan the SBOM for the platform you run. It covers the engine's core install only. It leaves out the optional extras, the web console wheel and the toolkit wheel |
| How the project ranks a dependency vulnerability | [.github/SECURITY.md](../.github/SECURITY.md#dependency-third-party-vulnerabilities) | Known exploited first (the CISA Known Exploited Vulnerabilities list), then the Exploit Prediction Scoring System (EPSS) score. The Common Vulnerability Scoring System (CVSS) score only breaks ties |
| How long an old version stays covered | [SUPPORT-POLICY.md](SUPPORT-POLICY.md) | Only the latest release is supported, with no back-port. A clock runs on adopting each security release, and the page gives the days |

The threat model and the security assessments are not published.
[SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) says what is withheld and how to ask for it.
