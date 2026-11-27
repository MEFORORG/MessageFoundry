# Running the engine as a Windows service

MessageFoundry runs as a long-lived background service via
[NSSM](https://nssm.cc) (the "Non-Sucking Service Manager"). NSSM wraps the engine's
`serve` command, run as `python -I -X disable-remote-debug -m messagefoundry serve`: it starts
the engine on boot, restarts it on crash,
and captures its output to rotating log files. Stopping the service sends Ctrl+C so the
engine drains its connections cleanly (the ASGI lifespan calls `engine.stop()`).

This is the localhost, single-machine setup: the service binds `127.0.0.1` and authentication is
already required (it is on by default). Networked deployment is **built but deliberate** — bind
off-loopback with `[security].local_access_only = false` + `[security].listen_address`, and an
off-loopback API bind is *refused at startup* without an operator certificate (`[api].tls_cert_file`);
[SECURITY.md, Enforcement model](SECURITY.md#enforcement-model) states the rule. See [DEPLOYMENT.md](DEPLOYMENT.md) for the exposure checklist and
[REMOTE-CONSOLE.md](REMOTE-CONSOLE.md) for operating this service from another PC.

Before going live, hand your endpoint-security and firewall admins the
[Antivirus Exclusions & Firewall Permissions guide](ANTIVIRUS-FIREWALL.md): it spells out the
narrow set of AV exclusions (the SQLite store + `-wal`/`-shm` sidecars, logs, key/cert files, the
venv interpreter) and the per-connection firewall openings the service needs.

## Prerequisites

1. **The engine, installed where only administrators can write.** The installer's default is
   `C:\Program Files\MessageFoundry\engine`, built from the engine wheel and never editable.
   The installer builds it when you pass the wheel, as
   [Install the engine where only administrators can write](#install-the-engine-where-only-administrators-can-write)
   shows, and refuses any install, such as a checkout's venv, that anyone but administrators can
   write.
2. **NSSM** — provisioned automatically. `install-service.ps1` keeps the `nssm.exe` the service
   runs in `-NssmDir`, `C:\Program Files\MessageFoundry\nssm` by default. It refuses a folder that
   anyone but administrators can write to or owns, because it runs that file as administrator. It
   fills the folder from `-NssmPath`, from an `nssm` on `PATH`, or by downloading the pinned,
   SHA‑256‑verified release. It downloads from `nssm.cc`, and falls back to the Internet Archive's
   copy of the same file when `nssm.cc` fails; either one must match the pin. No manual install
   needed.
   A copy you already have is used only if its SHA-256 matches the pinned win64 `nssm.exe` from
   NSSM 2.24. The installer refuses a `-NssmPath` copy that does not match, and names both hashes.
   A copy on `PATH` that does not match is skipped with a warning, and the installer downloads the
   pinned release instead. A package manager's `nssm` may be a different build, so it may be
   skipped this way. On a host with no internet access, pass `-NssmPath` with the win64 `nssm.exe`
   from `nssm-2.24.zip`. The uninstaller runs no `nssm.exe` at all.
3. **An elevated PowerShell** (Run as Administrator) — required to register a service.
   `messagefoundry service install --env <name> --config <dir>` elevates for you (a UAC prompt)
   and runs the install script below in a visible window so you can read its output. It passes
   `--config` as `-Config` and, when you give it, `--service-config` as `-ServiceConfig`, each made
   absolute first. Run the script yourself for any other option.
4. **A synchronized host clock.** The engine trusts the host's wall clock and does not set it.
   [SYSTEM-REQUIREMENTS.md, *Host clock*](SYSTEM-REQUIREMENTS.md#host-clock) states the
   requirement and how to check it with `w32tm`.

## Install the engine where only administrators can write

The service runs as its own account, and a PHI engine should run code only administrators can
change. So the installer's default engine is a virtual environment under Program Files, built from
the engine wheel (vault BACKLOG #2626). An editable install in a checkout is code its developers can
change, and the service would run their next edit.

1. Get the engine wheel and the `requirements.lock` of the same release into one folder. Take a
   release wheel and verify it as [INSTALL-GUIDE.md](INSTALL-GUIDE.md) shows, with the lock from
   that release's tag, or build a wheel from a checkout as yourself, not elevated:
   `python -m pip wheel --no-deps -w dist .`
2. Take the SHA-256 of each: `(Get-FileHash -Algorithm SHA256 <file>).Hash`. The lock pins every
   dependency by hash, but not the engine wheel. No signature covers the lock, so compare it with
   the release tag's copy (`git show v<version>:requirements.lock`) before you hash it: its pin
   shows only that pip reads the file you hashed.
3. Pass them to the installer, elevated, with the options [Install](#install) names:
   ```powershell
   .\scripts\service\install-service.ps1 -EngineWheel D:\release\messagefoundry-0.5.2-py3-none-any.whl `
       -EngineWheelSha256 <wheel hash> -RequirementsLockSha256 <lock hash> `
       -Environment prod -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml
   ```

**With `-EngineWheel`, the installer builds the root before it checks it** (vault BACKLOG #2626).
Without it, the installer builds nothing and checks the root that is there; it never falls back to
an editable install. It makes the root administrator-only before pip runs, and refuses, installing
nothing, when the copy of the wheel or the lock pip would read misses its pin. It installs the lock
with `--require-hashes` and binary wheels only, and the engine wheel with `--no-deps`, with pip
reading no configuration file or `PIP_` variable. So pip needs `pypi.org` for the dependencies:
it reads no mirror or proxy a `pip.ini` names. `Build-EngineInstall` in the script is the source
of record for the steps and their order.

It refuses to build into a root that already exists, so it never upgrades in place; see
[Update to a new build](#update-to-a-new-build-restart-vs-reinstall). An unfinished build deletes
the root. NSSM is fetched and checked before the build, so a refused `-NssmPath` or `-NssmDir`, or
a failed download, leaves no root. When a step after the build fails, such as the service
registration, re-run with `-EngineWheel` left out to use the root it built.
`-RequirementsLock` defaults to `requirements.lock` beside the wheel. `-BasePython` defaults to the first `python` on `PATH`; `Get-EngineBuildProblem` in the script lists what it
refuses there, at least a launcher, a shim, a venv's interpreter, a Python older than 3.14 and
one anyone but administrators can write. The installer installs the engine wheel only. Install
the web console wheel by hand if the service serves `/ui`, then reset the owner as below.

**To reset an existing root's access list and owner**, such as after an update by hand:

```powershell
$Root = "$env:ProgramFiles\MessageFoundry\engine"
$Parent = Split-Path -Parent $Root
foreach ($Folder in $Parent, $Root) {
    icacls $Folder /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" `
        "*S-1-5-32-545:(OI)(CI)RX" "*S-1-5-11:(OI)(CI)RX"
}
icacls $Parent /setowner "*S-1-5-32-544"
icacls $Root /setowner "*S-1-5-32-544" /T /C
```

A file an administrator creates there can be owned by that administrator's own account, under the
"Object creator" default-owner policy. That account then counts as another account that can write
it, and the installer refuses the install.

**The installer refuses an engine install anyone but administrators can write** (vault BACKLOG
#2626). That holds for the default root and for one you pass with `-AppExe` or `-PythonExe`. It
reads the interpreter, the launcher, the package's `__init__.py` and a venv's `pyvenv.cfg`, each
file and every folder above it. Only administrator principals, such as SYSTEM, Administrators
and TrustedInstaller, may write them. So at least `Everyone`, `Authenticated Users`,
`BUILTIN\Users` and the user who owns a checkout are refused. It also refuses an install with no `messagefoundry` folder in
its `Lib\site-packages`, or with an `__editable__` file for it. That is an editable install, which
imports the engine from a checkout. **A service can no longer run from a checkout.** To try the
engine from one, run `python -P -X disable-remote-debug -m messagefoundry serve` from a prompt.

## Install

```powershell
# from repo root, elevated PowerShell
.\scripts\service\install-service.ps1 -Environment prod -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml
```

`-Config` is required: the config directory the service loads. It used to default to the checkout's
`samples\config`, a demo graph.

**The service needs a settings file, registered by absolute path** (vault BACKLOG #2626). When the
engine finds it runs as an NSSM service, `serve` and `supervise` refuse to start with no
`--service-config`, or with a relative one and no `--project-root`. Either way they would read a
`messagefoundry.toml` from the working directory. Pass `-ServiceConfig <path>`, or put
`messagefoundry.toml` where the installer looks for it, which the Defaults table below names. With
neither, the installer refuses. A service that sets everything through its environment still needs
the file; an empty one will do. A start from a prompt needs no `--service-config`. The engine knows it is
the service when `nssm.exe` is the first process above it other than Python and the
`messagefoundry` launcher. A start it cannot place, such as one under a wrapper between NSSM and the
interpreter, is not refused. `messagefoundry/serviceenv.py` says what the reading covers.

`-Environment` is **required** (ADR 0017): it selects which `environments/<name>.toml` value file the
engine resolves and the instance's production tier. `serve` refuses to start without it (no silent
default), so the install script refuses too — pass `dev`, `staging`, `prod`, or a custom name.
**A custom name must also declare its production tier** — `[security].production_instance` in the
service config (`messagefoundry.toml`) — because a free-form environment name carries no tier to
derive one from (only `dev`/`staging`/`prod` do). There is no second declaration to make: every
instance carries patient data ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)). Without it, `serve` exits 2 with *"environment '\<name\>' has no built-in security posture"*, so the service
registers fine and then dies on every start. (Both `[ai]` spellings are **rejected at config load**,
and they are rejected differently — the difference is the remedy. `[ai].production` was **relocated**
by [ADR 0118](adr/0118-secure-by-default-security-configuration-section.md), so its refusal carries a
forwarding address: set `[security].production_instance` instead. `[ai].data_class` was **removed** by
[ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)
together with `[security].handles_real_patient_data`, so there is nowhere to forward it and the
refusal names the per-gate switches instead. Delete that line.)
`messagefoundry service install` requires the same name via `--env` and passes it straight through.

Defaults:

| Setting | Default |
|---|---|
| Service name | `MessageFoundry` |
| Engine launcher (`-AppExe`) | `C:\Program Files\MessageFoundry\engine\Scripts\messagefoundry.exe`. It names the install; the service does not run it. The installer refuses any install, the default or a passed one, when another account can write the launcher, the `python.exe` the service runs, the package's `__init__.py` or a venv's `pyvenv.cfg`, or a folder above them. It reads no other file, such as the base interpreter a venv's `python.exe` starts; `serve` reports the interpreter and package at start |
| Interpreter the service runs (`-PythonExe`) | the `python.exe` beside the launcher, or one folder up |
| Config dir (`-Config`) | *(required)* |
| Working directory | the install root: the folder above `Scripts` for a venv, else the folder of the `python.exe`. Never the checkout |
| Project root (`-ProjectRoot`, registered as `--project-root`) | the folder above `-Config` |
| Service settings (`-ServiceConfig`, registered as an absolute `--service-config`) | `messagefoundry.toml` under the project root, or else the working directory, when it exists. When it does not, the installer refuses |
| Active environment | *(required — `-Environment`)* |
| Data dir | `C:\ProgramData\MessageFoundry` |
| Message store | `<DataDir>\messagefoundry.db` |
| Logs | `<DataDir>\logs\service.out.log`, `service.err.log` |
| Secrets directory (`-SecretsDir`) | the one the service already names, else `<DataDir>-secrets`; named to the service as `MEFOR_SECRETS_DIRECTORY` |
| Custody directory (`-CustodyDir`), under `[store].key_provider = 'host'` only | the one the service already names, else `<DataDir>-custody`; named to the service as `MEFOR_CUSTODY_DIRECTORY` ([The custody directory](#the-custody-directory-under-the-host-key-provider)) |
| Bind | `127.0.0.1:8765` |
| Log level | `INFO` |

**A registered `--project-root` wins over `[environments].base_dir` in the settings file.** The
default install registers the folder above `-Config`, which is a drive root when `-Config` is a
top-level folder such as `D:\config`. It registers none only when `-Config` is itself a drive root.
The installer does not read the settings. So if your settings file sets `base_dir`, pass the same
folder as `-ProjectRoot`, or the service reads its value file from the folder above `-Config`.

**`-ListenHost` must be an IP address or a host name**, and no path may contain a double quote.
Each goes on the service's command line, so the installer refuses anything else before it acts.
No path the service is registered with may contain `%`, including `-NssmDir`, and `-ListenHost`
takes it only before a numeric IPv6 zone, such as `fe80::1%12`. nssm and the service manager
expand `%NAME%` when the service starts, so the service would read something other than what the
installer checked.

Override any of them, e.g.:

```powershell
.\scripts\service\install-service.ps1 -Environment prod -Port 9000 -LogLevel WARNING `
    -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml -DataDir D:\MessageFoundry
```

The install script is idempotent — re-running it reconfigures the existing service.

### Configure off-box log forwarding before the first start

**At the shipped `[security].enforcement = "enforce"`, `serve` refuses to start unless it forwards its
logs over verified TLS to a syslog collector on another host** (BACKLOG #1966, ASVS 16.4.3). Every
instance carries patient data, so this applies to every install. Set these under `[logging]` in the
service config (`messagefoundry.toml`) before you start the service:

| Setting | Value |
|---|---|
| `forward_host` | the collector's host name or address. Not `127.0.0.1`, `localhost` or any other address of this host |
| `forward_port` | the collector's TLS syslog port, usually `6514`. The default `514` is the plaintext port |
| `forward_protocol` | `"tls"` |
| `forward_tls_ca_file` | a PEM file holding the CA that signed the collector's certificate |
| `forward_tls_crl_file` | a PEM CRL from that CA. Under `enforce` the engine also refuses verified TLS with no revocation check |

Leave `forward_tls_verify` at its default, `true`. A local forwarding agent on 127.0.0.1 does **not**
satisfy the gate, and neither does `forward_hop_attested`.

Without these, the service exits 2 on every start, and NSSM pauses it after repeated failures. The
service's stderr log (`service.err.log`) carries the reason, starting *"error: a PHI instance ('prod')
must forward its logs off-box over verified TLS to a collector that is not on this host"*, then what is
missing and the settings above. The check reads the settings only and opens no connection, so a
collector that is down does not stop the start; the engine logs that at ERROR or WARNING and carries on.
Under `[security].enforcement = "warn"` the same condition only prints a warning, and the service starts.

### Provision the first administrator before you start the service

The engine creates no account on its own, so on a new store nobody can manage the engine. If a start
goes ahead without an Administrator, a Windows sign-in (Kerberos) can still create a directory
account, but that account holds no role. The install script registers the service but does not start
it. Before the first start, create the first
Administrator from an elevated shell on the host:

1. Set `MEFOR_STORE_ENCRYPTION_KEY` in that shell to the key the service runs with, unless the key
   comes from `[store].encryption_key_file` in `messagefoundry.toml`, which the command reads too. The
   key in the service's NSSM environment is not visible to your shell. Do not generate a new one. If
   the service has no key yet, set one up first; see
   [Protect the store encryption key at rest](#protect-the-store-encryption-key-at-rest-wp-11d).
2. From the repo root, run `provision-admin` against the service's store. The service runs
   `serve --db <DataDir>\messagefoundry.db` from the repo root (or the `-DbPath` you passed the
   install script), so pass that same `--db`. It asks for the password at the terminal.
   Under `[security].require_mfa`, the shipped default, it also enrols an authenticator app at that
   interactive console. With `require_mfa` off, `--no-totp` skips the enrolment; the password is
   still read at the terminal (ADR 0197 Amendment A).
3. Start the service.

```powershell
messagefoundry provision-admin --username <name> --email <address> --db C:\ProgramData\MessageFoundry\messagefoundry.db
```

If the service started first, at the shipped posture it refuses to start. Once the earlier start
checks pass (the store key and `[alerts]` among them), that refusal names `provision-admin` in the
log; run the command, then restart the service. In the data directory the install script hardens,
the service account and the operator can both open the store, in either order. The rules are in
[SECURITY.md](SECURITY.md#provisioning-the-first-administrator-asvs-632).

> **Migration note (ADR 0050, `--project-root`).** `serve`/`supervise --project-root R` now anchors the
> **whole** config bundle under `R` — the `--config` graph, `environments/<env>.toml`, `messagefoundry.toml`,
> **and** a relative `[store].path` / `--db` (and each shard's `<stem>_<shard>.db`). Previously only
> `environments/` was anchored; a relative DB resolved against the process CWD. If you already run with
> `--project-root` **and** a relative DB path, the DB will now be found/created under `R` — pass an
> **absolute** `[store].path` / `--db` to keep it in place (absolute paths bypass the root), or accept the
> new location. The startup CWD-mismatch WARNING names the resolved paths so any move is visible. Deployments
> without `--project-root`, or with an absolute DB path, are unchanged.

Under `[store].key_provider = 'host'` (vault BACKLOG #3411) the service cannot run as SYSTEM,
LOCAL SERVICE or NETWORK SERVICE: that provider refuses them as the engine account. When the
install script reads that setting, from the settings file as its `Get-SettingsKeyProvider`
describes, or from `MEFOR_STORE_KEY_PROVIDER` in the service's own
environment, it refuses such an account before it changes anything: `-AllowLocalSystem` with no
`-ServiceAccount`, and at least the usual spellings of those accounts as `-ServiceAccount`. Under
`[security].enforcement = 'enforce'` the provider also refuses an account that is not local to
this host, such as a domain user or a gMSA, and the script does not check for that.

The steps above do not yet cover that provider. It refuses a store key set beside it, so step 1's
key makes `provision-admin` refuse; and it mints the store key, which `--service-account` mints for
the service's account rather than yours (vault BACKLOG #3411).

#### The custody directory under the host key provider

The host key provider keeps two files, `handoff.key`, which `provision-admin --service-account`
writes, and `master.key`, which the service's first start writes from it and then reads at every
start. The service must be able to add a file where they live, and a service that may add a file
to the secrets directory may supply a secret-class setting (ADR 0214's 2026-11-22 amendment). The
install script's own grant to the service there is read, and the engine refuses no grant to one
account, so nothing guarantees the service read only there: a rerun keeps an explicit grant to
the service account itself, such as the write the Vault Agent sink route
([CONFIGURATION.md](CONFIGURATION.md#the-secrets-directory-mefor_secrets_directory)) gives it.
Of the entries the script does not set itself, at least an explicit grant to the service
account, an explicit Deny entry, and an explicit SYSTEM or Administrators entry with other
inheritance flags survive: the script turns inheritance off (`/inheritance:r`), which
drops every inherited entry, and tries to remove every other account's Allow entry that Get-Acl
lists, a group's included; the read-back, which reads the same list, refuses the install when a
listed one survives. At least a conditional (callback) Allow entry, and a plain one for an
APPLICATION PACKAGE AUTHORITY principal (the script passes its name, which icacls refuses),
survive that removal and are refused. An object Allow entry is not in that list, so it is neither
removed nor refused. The read-back does not check a surviving Deny entry, so one that names
the service account, or a group it belongs to, can leave the service unable to read its secrets.
So when the install script reads
`[store].key_provider = 'host'` it also makes a **custody directory** of its own for those two
files, `-CustodyDir`, else the one the service already names, else `<DataDir>-custody`, and names
it to the service as `MEFOR_CUSTODY_DIRECTORY`. It is judged before anything acts by the secrets
directory's rules, made restricted in one step, and then given this list:

- owner: Administrators, with inheritance off;
- SYSTEM and Administrators: full control, inherited by the files in it;
- the service account: read and add-file on the directory itself, inherited by nothing.

The script tries to replace any other plain grant the service account holds there, and to remove
every other account's allow entry and every deny entry that Get-Acl lists, whoever it names. At
least a conditional entry, the service account's own included, and an entry for an APPLICATION
PACKAGE AUTHORITY principal survive that removal, and an object entry is not listed at all. It
then reads the list back, and refuses, disabling the service, at least when its owner is neither
Administrators nor SYSTEM, still inherits, still has a listed allow entry for another account or a
listed deny entry that applies to the directory itself, or gives the service account more or less
than that grant. At least a surviving inherit-only deny entry, and every object entry, are not
refused. When the script does not read that provider, it refuses
`-CustodyDir`.

**The engine.** When `MEFOR_CUSTODY_DIRECTORY` is set, the host provider reads and writes the two
files there, in place of the directory `MEFOR_SECRETS_DIRECTORY` names or the store's own data
directory. Before it reads or mints, it checks that directory as it checks a secrets directory, at
any enforcement setting: a known broad group's right to read it, add a file to it or delete one in
it is refused, and so is a link. That check reads known broad groups only, so it refuses no entry
for one account, the service's or any other; the list the script sets is what leaves other
accounts no entry. While the variable is set and neither file is there, a key file in the secrets
directory or beside a SQLite store refuses a read and a mint, rather than being taken for no key at
all, so a mint run without the variable does not lead to a second key.

**Reinstalling over a kept custody directory.** The install script refuses an existing custody
directory the service does not name, as after an uninstall, and it never removes one that holds
anything. [When a refusal names master.key or handoff.key](#when-a-refusal-names-masterkey-or-handoffkey)
says how to go on.

**Minting.** Set the variable in the elevated shell that runs `provision-admin --service-account`,
to the same path, so the handoff lands where the service looks:

```powershell
$env:MEFOR_CUSTODY_DIRECTORY = 'C:\ProgramData\MessageFoundry-custody'
```

#### When a refusal names master.key or handoff.key

This is the one procedure for going on past a refusal that names `master.key` or `handoff.key`, the
host key provider's files ([The custody directory](#the-custody-directory-under-the-host-key-provider)).
The engine and the install and uninstall scripts point here when they find one where they cannot
tie it to this service's store, at least: a key file beside a store that another key provider
opens, a key file outside the custody directory the service names, and an existing custody
directory the service does not name, as after an uninstall. Neither the engine nor the scripts can
tell whose key a file holds, and either file may be the only copy of a store's key on this host.

1. **Delete nothing, and leave every key file where it is**, in every directory the refusal names,
   except as step 5 says once a copy has replaced an original, and unless step 3 sends you to move
   one; then move it only as step 5 says, which also says what to
   do with an original that a copy replaced.
2. **Stop the service** (`Stop-Service <ServiceName>`) if it is installed, and work from an
   elevated shell.
3. **If the file holds this store's key**, as when this store was set up under
   `[store].key_provider = 'host'`:
   - When the refusal says `[store].key_provider` is another provider, make the settings change
     the refusal names. That provider reads the file only from the custody directory
     `MEFOR_CUSTODY_DIRECTORY` names, else the one `MEFOR_SECRETS_DIRECTORY` names, else beside a
     SQLite store, and needs to add a file there. So, under the install script, re-run it once the
     settings name that provider, which makes the custody directory and names it to the service
     ([The custody directory](#the-custody-directory-under-the-host-key-provider)), and move the
     file into it as step 5 says.
   - When the file sits outside the custody directory the service names, move it into that
     directory as step 5 says.
   - When the install script refuses a kept custody directory, re-run it with `-CustodyDir` naming
     a new folder that does not exist yet, which it creates restricted
     ([The custody directory](#the-custody-directory-under-the-host-key-provider)). Then move each
     key file from the kept directory into the new one as step 5 says.
4. **If the file is another store's, or you cannot tell**, this store needs places that hold
   neither file. Let the install script make each one new and restricted, rather than making or
   filling a folder by hand. Re-run it with the option for where the file is:
   - beside the store's database: `-DataDir` naming a new folder that does not exist yet, so the
     store is `<DataDir>\messagefoundry.db` in a directory the script creates and restricts. Pass
     no `-DbPath`, or a `-DbPath` naming that same path, as the engine's refusal asks; keep both on
     every later reinstall. A `-DbPath` outside `-DataDir` names a folder the script grants nothing
     on.
   - in the directory `MEFOR_SECRETS_DIRECTORY` names: `-SecretsDir` naming a new folder that does
     not exist yet. Then add this service's secret files to it as
     [the secrets directory](#protect-the-store-encryption-key-at-rest-wp-11d) says.
   - in the directory `MEFOR_CUSTODY_DIRECTORY` names: under the host provider, `-CustodyDir`
     naming a new folder that does not exist yet. Under another provider the service reads no
     custody directory of its own, so take the `MEFOR_CUSTODY_DIRECTORY` entry out of its NSSM
     `AppEnvironmentExtra` list, keeping the other entries.

   A new data directory starts a new, empty store. Never copy another store's database, or any
   key file, into it. To keep this store's own data, move into the new one, as step 5 says, only
   files you know are this store's or this service's, and leave everything else where it is, at
   least any other database with its `-wal` and `-shm` files, since an old data directory may be
   shared. Those files are at least this store's database, the file the service's `--db` names,
   with that file's own `-wal` and `-shm` files; and, only where no other store's database sits
   in the same directory, the `log-spool` folder and the generated API certificate pair,
   `api-generated-cert.pem` with `api-generated-key.pem`. Move the pair together: where the new
   directory lacks either file, the engine mints a new pair there, and a client that pins the old
   certificate then refuses the new one. Leave `master.key` and `handoff.key` where they are: in
   this step they may be another store's.

   Under the host provider, leave this store's database, with its `-wal` and `-shm` files, out of
   that move, whichever route above you take. The new store needs a key that
   `messagefoundry provision-admin --service-account` mints for it, and `provision-admin` refuses
   to mint for a SQLite store that exists or a server database that holds data, because a new key
   cannot open it. So under that provider every route above needs a new store too: a new data
   directory for a SQLite store, a new database for a server store. Then run `provision-admin`
   again for the new store before step 6, with the arguments the engine's refusal names, at least
   `--db` naming the new SQLite path by its absolute path, and `MEFOR_CUSTODY_DIRECTORY` set in
   that shell to the custody directory the service names.
5. **Moving a file.** Within one volume, move it as an administrator
   (`Move-Item -LiteralPath <file> -Destination <directory>`): the file keeps its own owner and
   access list, which the engine checks exactly on a key file. Across volumes a move is a copy,
   and a plain copy takes the new directory's list in place of the file's own, so the engine
   refuses a key file copied that way. Copy a key file with its owner and list instead
   (`robocopy <from directory> <to directory> <file name> /COPY:DATSO /B`). Check that
   `icacls <file>` prints the same entries for the copy as for the original, and that
   `(Get-Acl -LiteralPath <file>).Owner` prints the same owner, and keep the original where it is
   until the service has started and opened its store from the copy. Copy the database files
   across volumes the same way, and keep their originals until then too. Copy the generated API
   certificate pair the same way, both files. Once the service has opened its store from the
   copies:
   - **A `master.key` original:** keep it as a second copy of the store's key, but take the
     service's access to it away first. Record its owner and list before you change them
     (`(Get-Acl -LiteralPath <file>).Sddl`), and keep that record with it: the engine reads it as
     a key file again only once that owner and list are back, and only as the account it was
     written for. Moving a file into another folder does not do that: the
     file keeps its own owner and access list, and an account that list names can still open it
     by its path. Set the original's owner and list, then check both
     (`icacls <file> /setowner *S-1-5-32-544`, then
     `icacls <file> /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F /remove:g "<service account>"`,
     then `icacls <file>`, which must print entries for Administrators and SYSTEM only, removing
     any other with `/remove:g`). Then move it, within its volume, into a folder only
     administrators can read, and keep it there. It is still read by at least SYSTEM,
     Administrators, and any account holding a privilege that reads past an access list, such as
     SeBackupPrivilege, which the `robocopy /B` above uses.
   - **A `handoff.key` original:** delete it once the service has started from the copy. A
     handoff is meant to last only from install to the service's first start, which converts it
     into `master.key` and deletes the copy it read. It is machine-scope DPAPI: on this host, any
     process that can read the file can unwrap the store key from it, though it does not unwrap
     on another host without this host's machine DPAPI keys, which at least a disk image or a
     cloned virtual machine of this host carries.
   - **The `api-generated-cert.pem` and `api-generated-key.pem` originals:** delete both once the
     service presents the copied pair. The key original is a second copy of the private key the
     service presents, readable by at least the accounts its own access list grants read and any
     account holding a privilege that reads past an access list, such as SeBackupPrivilege.
   - **The database originals** may hold PHI; dispose of them as [PHI.md](PHI.md) describes.
6. **Start the service**, and read its log for a refusal ([Verify it's running](#verify-its-running)).

**Without the install scripts**, as on Linux or in a container, the same steps hold with the
engine stopped in place of the service: leave every key file, and delete none except as the end
of this paragraph says; for a file that
is this store's, make the settings change and put the file where the host provider reads it; for
one that is not, run the store from a new, empty data directory for a file beside it, or set the
variable that names the file's directory, `MEFOR_SECRETS_DIRECTORY` or `MEFOR_CUSTODY_DIRECTORY`,
to a new directory owned by the account the engine runs as, mode 0700, in a folder only that
account or root may write, and add the engine's other secret files to a new secrets directory. A move
within one file system keeps the file's owner and mode; across file systems, copy it keeping them
(`cp -p`, as root). Once the engine has opened its store from the copy, take the engine account's
access to a `master.key` original away, since the file stays owned by that account with mode 0600
wherever it moves. Record its owner and mode first (`stat -c '%u:%g %a' <file>`, numeric ids, since
the engine's account may have no passwd entry) and keep that record with it, so they can be
restored if the engine ever has to read it again. Then make root its owner (`chown root:root
<file>`, keeping mode 0600), and move it, within its file system, into a directory root owns with
mode 0700, so the engine account can neither read it nor rename or delete it; keep it there. On
Windows, set a kept `master.key` original's owner and list as step 5 says rather than only moving
it, and delete a `handoff.key` original once the service has started from the copy, as step 5 says.
Delete the `api-generated-cert.pem` and `api-generated-key.pem` originals once the engine presents
the copied pair, as step 5 says.

## Update to a new build (restart vs reinstall)

The service runs `<install>\Scripts\python.exe -I -X disable-remote-debug -m messagefoundry
serve ...`. The default install is a **non-editable** wheel, as
[INSTALL-GUIDE.md](INSTALL-GUIDE.md) says, so a restart runs the same build. To update, install the
new wheel into the install root, then **restart** (elevated):

```powershell
& "$env:ProgramFiles\MessageFoundry\engine\Scripts\python.exe" -m pip install --no-deps `
    (Get-Item .\messagefoundry-*.whl).FullName
Restart-Service MessageFoundry
curl.exe --cacert C:\ProgramData\MessageFoundry\api-generated-cert.pem https://127.0.0.1:8765/health
```

Install the release's `requirements.lock` first when its dependencies changed, then reset the
owner as
[Install the engine where only administrators can write](#install-the-engine-where-only-administrators-can-write)
shows. The installer refuses an editable install, so a restart never runs whatever branch a
checkout has.

**Reinstall** instead when paths or flags change (port, config dir, data dir) or the service
definition drifted — the install script is idempotent (it stops and reconfigures in place):

```powershell
.\scripts\service\install-service.ps1 -Environment prod -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml   # elevated; re-points the exe + AppParameters
Start-Service MessageFoundry
```

> **WARNING: Upgrading from ≤ 0.2.5 → ≥ 0.2.6: tighten the config-dir ACLs first.** The config-directory
> permission guard (SEC-003 / ADR 0036) did **not** exist in 0.2.5. From 0.2.6 on, `serve` refuses to
> start against a `--config` directory **writable by a broad principal** (e.g. `Authenticated Users` /
> `S-1-5-11`) — *"refusing to load config from writable-by-others path …"*. A config dir that inherits
> that write (common under `C:\srv\…`) therefore **fails its first start after the upgrade**. Lock it
> down **before** restarting onto the new build — use the surgical recipe under
> [Lock down the config directory (CONFIG-2)](#lock-down-the-config-directory-config-2)
> (`icacls /inheritance:d /T` + `/remove:g *S-1-5-11 /T` + grant SYSTEM/Admins), the lighter-touch
> alternative to a full `/inheritance:r` reset for a shared tree.

## Start / stop / status

```powershell
Start-Service   MessageFoundry
Get-Service     MessageFoundry
Stop-Service    MessageFoundry   # NSSM answers with Ctrl+C -> graceful connection shutdown (up to 15s)
Restart-Service MessageFoundry
```

Run them from an elevated prompt. Services.msc and `sc.exe` work too. NSSM's own start, stop and
restart commands send the same request, so there is no reason to use them.

**A stop holds some of its waits to a budget, to keep inside NSSM's stop window, and that can cut
them short** (BACKLOG #3191; the owner ruled on 2026-11-22 that the budget wins over the work it
cuts). The service's shutdown hands `engine.stop()` what is left of its budget after the floors of
the steps after it, never less than 3 s. The budget covers at least these waits: the retention
runner's stop, a CRL reload pass in flight, the remote-debug refusal watch's two waits, for its
last audit pass and then for that pass's cancel, and the drain of alert-instance writes. A
budgeted wait is shortened only when what is left of the budget, less the time kept for the stop
steps after it, is under that wait's fixed bound, and it still gets at least 0.1 s. The graph supervisor's exit is not budgeted: it waits up
to its fixed 10 s, and then, once cancelled, for that cancel to land with no bound. It and the
other stop steps are not held to the budget, so a slow one can still carry the stop past NSSM's
window, and it spends budget the waits after it would have had. On a tight stop, at least these
can be lost:

- **The remote-debug watch's last pass** can be cut to about 0.1 s and cancelled. Every stop step
  before it, the graph supervisor's wait and the stopping of the message graph included, shortens
  its waits by what it took, so a slow graph stop alone can leave the pass only that floor. When
  the budget cuts the pass, a WARNING says so, and a refusal seen since the pass before it may then
  have no audit row and no alert. A cancel of the stop itself, in either wait, logs no WARNING.
  A pass whose cancel has not landed when the second wait ends is left running and can outlive the
  store's close, so its row may not be written; the WARNING then says it may still be running.
- **The alert-instance drain** can be cut to about 0.1 s. A raise or clear write still running
  then is not retried, and may fail when the store closes and go unrecorded. A clear still waiting
  to retry is cancelled, and an ERROR counts it. An alert whose clear is lost can still read open
  in the alert list. This drain covers alert records in the store, not the
  sending of alert notifications, which a later shutdown step closes.
- **The retention runner's stop** waits for its loop to end and then for `retention_purge` audit
  rows still being written, at most 5 s for both together. Under the budget it gets at most about
  1.5 s at the 3 s minimum, or about 0.5 s while a config write is still running, and less when an
  earlier stop step was slow, down to 0.1 s. A row still unwritten then is logged at ERROR and may
  land later or not at all, so a purge that finished can be left with no audit row
  ([PHI.md](PHI.md)). When the budget runs out before the loop has ended, the stop returns anyway:
  the retention pass may still be running when the store closes, and the interrupted audit row it
  would write for the phases it finished can be lost. The stop that ran out logs an ERROR saying
  so; a second stop call that joined it and ran out of its own time, cancelled or not, logs a
  WARNING. A cancel of the engine's stop during this wait is held and raised once the store has
  closed, except at least when a stop step that runs before the store's guarded teardown fails
  first: the stop then ends on that failure without closing the store, as it does when no cancel
  came.
- **A CRL reload pass in flight** gets at most about 1.8 s at the 3 s minimum, or about 0.8 s
  while a config write is still running, and less when an earlier stop step was slow, down to the
  same 0.1 s. When the budget cuts the pass, it is abandoned with a WARNING; a cancel of the stop
  itself cancels it and logs none. Abandoning it does not end its read: the worker
  thread running the pass cannot be cancelled and runs on, and it can hold the process's exit past
  NSSM's window. The next start loads every CRL from the file again.

The service's own `nssm.exe` is in `C:\Program Files\MessageFoundry\nssm` (the installer's
`-NssmDir`). The installer checked that copy's hash, and keeps it where only administrators can
write ([DANGEROUS-FUNCTIONALITY.md](DANGEROUS-FUNCTIONALITY.md) section 8). It never puts that
folder on `PATH`. So any other `nssm` is not the copy the service runs, and nothing checks it when
you run it. For a command only NSSM has, such as its `set`, run the service's copy by its full path:

```powershell
& "$env:ProgramFiles\MessageFoundry\nssm\nssm.exe" set MessageFoundry <setting> <value>
Restart-Service MessageFoundry   # the running engine keeps its old settings until it restarts
```

**`set AppEnvironmentExtra` replaces the service's whole list of extra variables.** Pass every
variable the service needs in one call, or the ones you leave out are gone at the next start.
That includes the `MEFOR_SECRETS_DIRECTORY` entry the installer wrote: without it the engine reads
no file in the secrets directory, and every secret moved there is missing, with no error naming
the directory. Read the list first with `nssm get MessageFoundry AppEnvironmentExtra`, unless it
may hold a value `serve` or `supervise` refused, as the next paragraph says.
**No secret goes in that list:** any local user can read it. Where the engine could read the
service's lists, `serve` and `supervise` refuse to start with one of the engine's own secret
settings there, or with any `MEFOR_VALUE_*` variable, secret or not. Where it knows the service but could not read them, they refuse a store key,
a retired store key or another engine secret setting found in their own environment, under every
enforcement setting. Where the engine could read the lists, and only under
`[security].enforcement = "enforce"`, they also refuse an engine secret setting other than a store
key or a retired store key that is in their own environment, is not in those lists, and is set
in the machine-wide environment's registry key, where the engine could read that key (vault BACKLOG #2595). Use the DPAPI
key file for
the store key, and the secrets directory for the rest (see
[Protect the store encryption key at rest](#protect-the-store-encryption-key-at-rest-wp-11d)).

**While a list holds a value `serve` or `supervise` refused, edit it in the registry, never with
`nssm get` or `nssm set`.** `nssm get` prints every value in the list, and `nssm set` takes the
values on its command line, where they reach at least the shell's history, a transcript and
process-creation audit events. Read `AppEnvironment` and `AppEnvironmentExtra`, under `Parameters`
in the service's registry key, and the service's own `Environment` value, on that key itself, into
a variable with `Get-ItemProperty`, printing nothing. Edit the strings in that same session, and
write each value back with `Set-ItemProperty -Type MultiString`:

```powershell
$service = 'MessageFoundry'   # the service the refusal names
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\$service\Parameters"
$extra = (Get-ItemProperty -LiteralPath $key -Name AppEnvironmentExtra).AppEnvironmentExtra
# edit $extra here, printing nothing
Set-ItemProperty -LiteralPath $key -Name AppEnvironmentExtra -Value $extra -Type MultiString
```

install-service.ps1's `Set-ServiceEnvironmentValue` writes `AppEnvironmentExtra` back the same
way, with `Set-ItemProperty -Type MultiString`.

**A `PYTHON*` variable in that list does nothing for the engine.** The service starts the
interpreter in isolated mode, which ignores every one of them
([The service launch](#the-service-launch)). The engine's own `MEFOR_*` variables work as before.

For a one-click desktop alternative to these commands — engine status at a glance plus
start/stop/restart, the console, and the log from the notification area — run the
**[Windows tray service-manager](TRAY.md)** (`messagefoundry-tray` — shipped in the wheel, on every install).

## Security hardening (recommended)

### Run as a least-privilege account (DEPLOY-1)

By default the service now installs under a **least-privilege per-service virtual account** —
`NT SERVICE\<ServiceName>` (e.g. `NT SERVICE\MessageFoundry`), which needs **no password** (#224). A
bare install therefore lands on the least-privilege posture with nothing extra to configure:

```powershell
.\scripts\service\install-service.ps1 -Environment prod -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml   # runs as NT SERVICE\MessageFoundry
```

The engine needs only **read** on the config directory and **read/write** on the data directory, so
the virtual account grants exactly what is required. The installer **auto-grants the account what it
needs**: read+execute on the config directory and read/write on the data directory — and, because a
per-service virtual-account SID does not resolve until the service exists, those ACLs are applied
**after** the service is registered and its run-as account is set (the manual `icacls` lines below are
only needed if you point the engine at directories outside those). Running as **LocalSystem** — the
most privileged local account — widens the blast radius of any compromise (a config module is executed
in-process — see *Lock down the config directory* below), so it is now an explicit opt-out:

```powershell
.\scripts\service\install-service.ps1 -Environment prod -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml -AllowLocalSystem   # opt out to LocalSystem
```

To run under a **different** account (a domain gMSA, a dedicated local user, or another virtual
account), pass `-ServiceAccount` — it always wins over the default:

```powershell
.\scripts\service\install-service.ps1 -Environment prod -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml -ServiceAccount "NT SERVICE\MessageFoundry"
```

```powershell
# only if config/data live outside the script-managed paths:
icacls "D:\hl7\config"                 /grant "NT SERVICE\MessageFoundry:(OI)(CI)RX"
icacls "C:\ProgramData\MessageFoundry" /grant "NT SERVICE\MessageFoundry:(OI)(CI)M"
```

A domain **gMSA** or a dedicated local user works the same way (pass `-ServiceAccountPassword`
for a password-based account — it's taken as a `SecureString`). The fallback when the store
refuses the data directory is in ADR 0163, *Note (2026-11-05)*.

**gMSA preflight + "Log on as a service" (#99).** When `-ServiceAccount` names a **gMSA** (a name ending
in `$`, e.g. `CORP\mefor-svc$`), the installer runs `Test-ADServiceAccount` first (verifying the account
is installed + usable on this host — run `Install-ADServiceAccount <name>` if not) and then grants the
account **`SeServiceLogonRight`** ("Log on as a service") via `secedit` before registering — without that
right the service fails to start with **error 1069**. Both steps are **best-effort and degrade
gracefully**: on a non-domain / RSAT-less dev box the preflight skips with a message and the install
proceeds; neither ever aborts. Pass `-SkipGmsaPreflight` when the account is provisioned by a separate
runbook. The end-to-end SQL-Server-integrated-auth gMSA walkthrough (grant the gMSA a SQL login,
`[store].auth = "integrated"`) is in [DEPLOY-SERVER-DB.md §1.1](DEPLOY-SERVER-DB.md).

**Default flipped to least-privilege; `-AllowLocalSystem` is the LocalSystem opt-out (#224, built on #99).**
Omitting both `-ServiceAccount` and `-AllowLocalSystem` now installs under the virtual account
`NT SERVICE\<ServiceName>` — **not** LocalSystem. To run as LocalSystem you must pass `-AllowLocalSystem`
explicitly (it prints a warning that LocalSystem is the acknowledged, non-default choice). An existing
unattended install that already passed `-ServiceAccount` is unaffected; one that relied on the old
LocalSystem default now needs `-AllowLocalSystem` to keep running as LocalSystem — the recommended
migration is to accept the new virtual-account default instead. This flip is exercised end-to-end by the
`windows-service-smoke` CI leg (a bare `-LockConfigDir` install, which now runs under the virtual account,
must start and serve `/health` + MLLP on both Windows Server SKUs).

### Restrict the service token

The installer sets two things on the service's registration. Both make Windows start the engine
with less than its account holds.

**A short privilege list, for every account.** A Windows service keeps every privilege of its
account unless its registration lists the ones it needs. The installer lists one,
`SeChangeNotifyPrivilege`, and Windows removes the rest when the service starts. By default Windows
gives every service account `SeImpersonatePrivilege`, which the engine does not use. This list is
set for the default account, for `-ServiceAccount` and for `-AllowLocalSystem` alike.

**A restricted service SID, for the default account.** When the service runs as its own virtual
account, `NT SERVICE\<ServiceName>`, the installer sets its SID type to `restricted`. Windows then
gives it a write-restricted token. It reads what it could read before. A permission for `Users`,
`Authenticated Users` or any other group the account belongs to no longer lets it write. It still
writes where a permission names at least one of these:

- the service itself, `NT SERVICE\<ServiceName>`;
- its logon session, `Everyone`, or the special `WRITE RESTRICTED` group;
- `OWNER RIGHTS`, on a file or folder the service owns. Measured 2026-10-01 with a stand-in token:
  it wrote inside a folder it had created whose only entries were SYSTEM, Administrators and
  `OWNER RIGHTS`.

So when you check whether the engine can write a directory, look for those entries and for who
owns it, and not only for the service's name.

What that changes for you:

- **The data directory and the logs work as before.** The installer grants them to the service by
  name, and reads that grant back.
- **Grant every other directory the engine writes to the service by name.** That covers at least
  the directory of each File connection, a DR backup directory, and the store's own directory when
  `-DbPath` puts it outside the data directory. The installer reads that last one and warns when
  the grant is missing. An inbound File directory counts
  too unless it uses `after_read="leave"`, because the engine moves each processed file into a
  subfolder. A directory that only `Users` can write would be refused, and the connection reports
  it the way it reports any directory it cannot write.

  ```powershell
  icacls "D:\hl7\out" /grant "NT SERVICE\MessageFoundry:(OI)(CI)M"
  ```

- **A network share is not affected.** The file server checks the account there. The restriction
  is part of the local token and does not travel.

Read both settings back with `sc.exe qsidtype MessageFoundry` and `sc.exe qprivs MessageFoundry`.

**Other accounts get the privilege list and not the restricted SID.** With `-AllowLocalSystem`, or
with `-ServiceAccount` naming anything but the service's own virtual account, the service runs as
an account that is not the service itself. Under a restricted SID that account's own profile and
the grants written for it would stop counting. No run has shown what such a service then fails to
write, so the installer sets the SID type to `none` for a gMSA, a named user, another virtual
account and LocalSystem, and prints a warning that says so. It writes `none` on every run. So a
re-install that changes the account never keeps a restricted SID from the account before, and a
SID type you set by hand with `sc.exe sidtype` is replaced.

The `windows-service-smoke` CI leg has an account leg for `-AllowLocalSystem`, on Windows Server
2025. It reads SID type `none` and the one-entry privilege list on the registration. It checks that
the engine starts and takes a message over MLLP. And it checks that the token of the service's root
process and of the engine's processes runs as SYSTEM, carries no restricting SID, and holds only
`SeChangeNotifyPrivilege`. Its first run is in the merge queue.

**No leg runs a named account yet, a local user or a gMSA.** A local-user leg is wired in `ci.yml`
and left out of the matrix. Listing it now would still fail: the installer's read-back of the
account it registered would refuse the `HOST\user` spelling the leg passes (BACKLOG #3938). A
gMSA leg would also need an Active Directory domain that the runner has joined, and no hosted
runner has one.

**A SQLite store in the data directory admits one named account.** The store shares its files
between the service and the operator only when the data directory grants SYSTEM, Administrators
and at most one run-as account, in the shape the installer writes. A `-AllowLocalSystem` install
grants none. The run-as account is either a per-service virtual account, `NT SERVICE\<name>`, or
one account whose SID is machine- or domain-relative (`S-1-5-21-` plus three sub-authorities and
the RID) and that Windows resolves to a user account with a RID of 1000 or more. A local user you
create for the service and name with `-ServiceAccount` is such an account; a built-in one, such as
Administrator (RID 500), is not. A gMSA is admitted only if `LookupAccountSid` resolves
it to a user account, which is unmeasured here. Who may own the directory is stated in ADR 0163,
*Note (2026-11-05)*. The engine does not check that this account is the one
the service runs as. It admits whichever user the directory grants, so grant the data
directory to the service account only, as the installer does.

The engine resolves the account with `LookupAccountSid` each time it opens the store. It refuses
the directory at least when the lookup fails, when the account resolves to anything but a user, such as a
group, or when the directory names a second account, and logs a WARNING naming the reason. In a
refused directory the engine tries to remove each store file's inherited entries and grant the
account that opened the store full control of it, and any other entry set on the file itself
stays (see ADR 0163, *Note (2026-11-05)*). Where that fails, the file keeps the entries it
inherited, and the engine logs a WARNING. With that fallback, the service and the operator who
provisions the first Administrator can lock each other out of the store.

At least these are unmeasured:

- **A named account end to end.** No run has installed and started the service as a local user or
  a gMSA.
- **What a gMSA resolves to.** A gMSA is a kind of computer account in Active Directory, so it is
  expected to resolve as a user. If it resolves as anything else, the WARNING names that type.
- **A start with no domain controller.** A gMSA resolves through a domain controller, or through
  the local lookup cache when no controller answers, and a slow or absent controller can delay
  the open or fail the lookup. A later start does not always repair what a failed lookup leaves.
  Why a time-out can read as an account that does not exist, and what that restriction leaves on
  each file, are in ADR 0163, *Note (2026-11-05)*, *Left open*.

The rule and its reasons are in ADR 0163, *Note (2026-11-05)*.

**`-SkipRestrictedServiceSid` opts out** for the default account. Use it only when the engine must
write somewhere you cannot grant to `NT SERVICE\<ServiceName>`. The engine can then write wherever
its account, or any group the account is in, can. The privilege list is still set.

**This is not a wall around code that runs inside the engine.** The restriction limits where the
engine's own token writes, which is what matters when a flaw lets a sender steer a file path. A
config module runs inside the engine's process, and code there can ask Windows for a second token
for the same account. Measured 2026-10-01 on Windows 11 with a stand-in token: the logon the File
connection's alternate credential uses (`LogonUserW` with `LOGON32_LOGON_NEW_CREDENTIALS`) returned
a token that kept the short privilege list and was no longer write-restricted. So the config
directory is still code that runs with the service account's access. Lock it down as
[Lock down the config directory](#lock-down-the-config-directory-config-2) says.

**When it takes effect.** A service gets both settings when Windows starts it. Microsoft documents
a SID type change as needing a system start. The `windows-service-smoke` CI leg installs a new
service, starts it and reads the token the running engine holds.

Measured 2026-10-02 on Windows Server 2022 and 2025, in CI run 36981542600: a new service held both
settings at its first start. The host was not restarted. All three service processes had a
write-restricted token whose only privilege was `SeChangeNotifyPrivilege`.

Nobody has measured a change on a service that was already installed. If you re-run the installer
over an existing service and need the new SID type in force, restart the host. The installer prints
that reminder on every re-install.

### The service launch

The service runs the Python interpreter of the engine's install, not the `messagefoundry.exe`
launcher:

```
<venv>\Scripts\python.exe -I -X disable-remote-debug -m messagefoundry serve --config ... --env ...
```

A launcher cannot pass an option to the interpreter it starts, and both options matter.

- **`-I` is isolated mode.** The interpreter ignores every `PYTHON*` environment variable, so a
  `PYTHONPATH` or `PYTHONHOME` in the service's environment cannot decide what the engine imports.
  Another product's installer can leave one behind, machine-wide. It also keeps the working
  directory and the user's own site directory off the import path. The service's working
  directory is the install root, and `python -m` would otherwise search it first.
- **`-X disable-remote-debug` turns off the interpreter's remote debugging** (PEP 768), which
  would let another process running as the service account run Python inside the engine. The
  environment variable for it is one of those `-I` ignores, so the option is the only form that
  works here. It is spelled with hyphens; the interpreter accepts the underscore spelling and
  ignores it.

What that changes for you:

- **`-AppExe` still names the launcher.** The installer takes the `python.exe` beside it, which
  is where a virtual environment keeps it, or one folder up, which is where a system-wide
  install keeps it. It refuses to install when it finds neither. Pass `-PythonExe` then.
- **A `pip install --user` copy of the engine will not start as the service.** Isolated mode
  leaves the user's site directory out. Install into a virtual environment.
- **`messagefoundry serve` from a prompt has remote debugging on** unless something turns it
  off, such as its environment setting `PYTHON_DISABLE_REMOTE_DEBUG`; give it a non-empty value, such as 1, since some shells delete a
  variable set to an empty value. With remote debugging on, under `enforce` the start refusal for it stops the engine
  unless `[security].allow_remote_debugging` accepts it (vault BACKLOG #2700). The variable works
  there only because the console script passes neither `-I` nor `-E`: a start by hand that keeps
  `-I` and drops `-X disable-remote-debug` has the interface on whatever the variable says, as
  the `-X disable-remote-debug` point above says. Run by hand what the service runs, the
  command above. When the refusal fires, and how a developer loop that needs the console script
  gets past it, are stated in full in
  [`SECURITY-LOOSENING.md`](SECURITY-LOOSENING.md#remote_debug_enabled-and-remote_debug_unguarded-the-interpreter-accepts-a-script-from-another-process).
  A console-script start is not isolated either, and the engine says so (`interpreter_not_isolated`, and
  `remote_debug_enabled` or `remote_debug_unguarded` where the start goes on with the interface on).
- **The engine's Python children are isolated when the engine is.** The sandbox worker and each
  engine shard repeat the engine's `-I`, so a `PYTHON*` variable in the service's environment
  reaches none of them. A `serve` from a prompt is not isolated, and neither are its children.

**Read it back.** `GET /security/posture` carries an `interpreter` block: `isolated` should be
`true` and `remote_debug_enabled` `false`. The status page of the web console shows the same two
readings. The `windows-service-smoke` CI leg reads the registration, the running engine's command
line and that block. Nobody has read a result from it yet: it runs on a schedule, on dispatch and
in the merge queue, not on a pull request.

**Keep the service account out of the directories the interpreter reads start-up code from.**
Isolated mode does not stop start-up code. The interpreter runs every line of a `.pth` file that
begins with `import`, and a module named `sitecustomize`, before any engine code. So whoever can
write one of those directories runs code inside the engine at its next start.

- The engine lists that start-up code at every start. Under `[security].enforcement = "enforce"`
  it refuses to start on a file no installed package records, and names it. That check is
  detection: code that already ran can defeat it.
- The engine also reads whether its own account can add a file to each of those directories,
  and reports `startup_directory_writable`, naming them, when it can. On Windows they are the
  virtual environment's own folder, its `Lib\site-packages`, the base interpreter's folders, and
  with an editable install the repository itself.
- **The installer does not change the permissions of any of them.** Check them yourself with
  `icacls`. Under the default account,
  [Restrict the service token](#restrict-the-service-token) lists the entries that would let the
  engine write. Under `-AllowLocalSystem` the engine runs as SYSTEM, which a directory's
  permissions usually grant full control.

What counts as expected start-up code, and what each entry leaves open, is in
[SECURITY-LOOSENING.md](SECURITY-LOOSENING.md#interpreter_not_isolated-startup_code_unexpected-and-startup_directory_writable-what-runs-in-the-interpreter-before-the-engine-does).

### Protect the store encryption key at rest (WP-11d)

PHI columns are AES-256-GCM-encrypted at rest when a key is configured (see [PHI.md](PHI.md) §3).
The key is a base64 32-byte secret. Two ways to supply it. **Under the Windows service, use the
DPAPI key file.** `serve` and `supervise` refuse to start when the store key is in the service's
NSSM environment.

- **DPAPI-protected key file (Windows).** Keep the key in a file that Windows DPAPI binds to *this
  machine*, so a copied file is useless elsewhere and no plaintext key is in the environment:

  ```powershell
  # mint + protect a fresh key (machine scope, so the service account can read it at startup).
  # SYSTEM can always read the file (covers a LocalSystem service); for a virtual / gMSA service
  # account add --grant-account '<that account>' so the service — not just you — can read the key.
  # --out must be a NEW path: protect-key never replaces a file.
  messagefoundry protect-key --generate --out "C:\ProgramData\MessageFoundry\store.key.dpapi"
  #   (virtual account example: ... --grant-account "NT SERVICE\MessageFoundry")
  #   -> prints the base64 key ONCE to stderr; back it up offline (the file is machine-bound and
  #      unrecoverable if the host is lost), then point the engine at it:
  ```
  ```toml
  [store]
  encryption_key_file = "C:/ProgramData/MessageFoundry/store.key.dpapi"
  ```
  Then **unset** `MEFOR_STORE_ENCRYPTION_KEY` (the env key takes precedence when both are set). The
  service account `CryptUnprotectData`s the file at startup; a missing/foreign/unreadable file makes
  `serve` fail closed rather than store PHI unencrypted. `protect-key` creates the file
  already restricted, with read for the one account `--grant-account` names (a virtual / gMSA
  account). The file does **not** inherit the data-dir ACL, so grant the right service account at
  mint time (above) rather than relying on the directory. If the file cannot be created restricted,
  or `--out` already exists, the command exits non-zero and writes nothing. `serve` checks the file
  before it uses it. Who the file is restricted to, what that check covers and what it does not are
  stated once, in [PHI.md](PHI.md), "Key files". To rotate, `protect-key` the new key to a **new** path, point
  `encryption_key_file` at it, and run `messagefoundry rotate-key` with the prior key in
  `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` (see [PHI.md](PHI.md) §3). Delete the old file only after
  the rotation, once nothing still needs its key. Set that retired key in the shell that runs
  `rotate-key`, never in the service's NSSM list: `serve` and `supervise` refuse to start with it
  there. The service's first start after a rotation needs no retired key ([PHI.md](PHI.md) §3,
  BACKLOG #3472).
  **CORRECTED 2026-10-01:** this said `protect-key` locks the file to the minting admin plus SYSTEM
  after writing it, and that a rotation writes the new key "to the file" (vault BACKLOG #2601).

- **Environment (off Windows, or a `serve` you start from a shell).** Set
  `MEFOR_STORE_ENCRYPTION_KEY` in the environment of the process that runs `serve`. **Not in the
  Windows service's NSSM settings.** NSSM keeps the service's environment list
  (`AppEnvironmentExtra` and `AppEnvironment`) in the service's registry key. Treat any secret
  placed there as readable by **any local user** of the host, not only by an administrator. On a
  default Windows install that key grants local users read by inheritance, and the installer does
  not change it. That was measured on one Windows 11 machine, so check who can read that key on
  your own host.
  **CORRECTED 2026-10-01:** this read "readable by any local administrator".

  **`serve` and `supervise` refuse to start when the store key, or a retired one, is in that
  list**, or in the service's own `Environment` registry value, whatever `[security].enforcement`
  says (vault BACKLOG #2595). An application that builds the API itself, with `create_app` or
  `create_managed_app`, raises on the same finding as it is built. Move the key to the DPAPI key
  file above. A retired key belongs in the shell that runs `messagefoundry rotate-key`, not in the
  service. What the engine reads, what it refuses and what it does not cover are in
  [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md#store_key_in_service_environment-service_environment_unobservable-and-secret_in_service_environment-secrets-in-the-windows-services-environment).

- **The other secrets: a secrets directory (any platform).** At least the engine's own secret
  settings other than the store key and its retired keys, among them the database password, and
  every `MEFOR_VALUE_*` value can each come from a file instead of the service's NSSM list. A variable an operator names
  as a `[secrets].provider = "env"` reference, and one a library reads for itself, are not read
  from it. **The installer creates it**, restricted, and adds `MEFOR_SECRETS_DIRECTORY=<its path>`
  to the service's NSSM list, keeping the entries already there; a path in the NSSM list is not a
  secret. The path is `-SecretsDir`, else the one the service already names, else
  `<DataDir>-secrets`, beside the data directory and not in it, so a backup of the data directory
  does not copy the plain files. The installer refuses a path that is a volume root, a junction, a
  file or a folder holding a folder, that sits below a junction, or that is, holds or sits inside
  at least the data, log, store, config, value-file and settings-file folders, NSSM's folder, the
  engine install, the checkout, the Windows folder and Program Files. It refuses a path another
  service already names as its `MEFOR_SECRETS_DIRECTORY` or `MEFOR_CUSTODY_DIRECTORY`, or a folder inside or around one, so a second service on the same
  `-DataDir` needs its own `-SecretsDir`. The installer makes the directory with its owner and
  access list in one step. The directory starts empty: as an administrator, create or copy in one
  file per setting, named as its variable, and restart the service. Do not move a file in: a
  moved file keeps its old access list. Each run makes Administrators the
  owner and removes every grant there but SYSTEM's, Administrators' and the service account's,
  whose own grant it keeps, and refuses when any is left or the account holds no read. It refuses
  an existing directory the service does not already name, since restricting a folder someone else
  made does not shut them out, and one the service names whose owner is no longer Administrators
  or SYSTEM. A refusal
  after the service is registered sets the service to Disabled. A folder above the directory that the installer
  creates is administrator-only; one that already existed is yours to restrict, since the engine
  does not read it. `uninstall-service.ps1` leaves the directory and its files, names them, and
  with `-RemoveAccountAces` removes the account's entry there too. Which settings it supplies, the
  access list it needs, and the rest of the rules are stated once, in
  [CONFIGURATION.md](CONFIGURATION.md#the-secrets-directory-mefor_secrets_directory). Move each
  of the engine's own secret settings other than the store key and its retired keys here from the
  service's NSSM list, where `serve` and `supervise` refuse it once the engine finds its
  service, whether or not it could read that list (the previous bullet links where that is
  stated).
  A `MEFOR_VALUE_*` value there is refused too, secret or not, but only where the engine could
  read that list: where it could not, a `MEFOR_VALUE_*` value is not refused. Move it here, or to
  the active environment's value file if it is not a secret and is the same for every instance
  (the previous bullet's link says when and why).
  **Off Windows, no installer creates the directory.** In `docker/compose.yaml` the `engine`
  service's bind mount and its `MEFOR_SECRETS_DIRECTORY` line are both commented out, so uncomment
  both. The `ha` profile's `engine-ha` and `engine-standby` services carry neither line. Add them
  to the `x-ha-engine` anchor's `volumes:` list and the `x-ha-engine-env` anchor, which both
  services merge (so does `schema-provision`), not to a service: a service-level `volumes:`
  replaces the anchor's list rather than adding to it.
  Where each platform's directory goes, a systemd unit's included, and what the engine refuses
  there are in [CONFIGURATION.md](CONFIGURATION.md#the-secrets-directory-mefor_secrets_directory).
  Linux, on a host or in a container, is not a supported v1 deployment target
  ([SYSTEM-REQUIREMENTS.md](SYSTEM-REQUIREMENTS.md#linux-is-not-a-supported-v1-deployment-target)).

> **External vault / managed identity.** DPAPI is the built-in on-box option. The engine can also call
> HashiCorp Vault itself. These surfaces are separate, and each needs the optional `[vault]` extra:
>
> - `[store].key_provider = "vault"` unwraps the store key through Vault Transit.
> - `[store].cipher_provider = "vault_transit"` does the at-rest encryption inside Transit instead.
> - `[secrets].provider = "vault"` reads a credential from Vault KV, for a credential whose reference
>   field is set.
>
> Each one's settings and preconditions are in [CONFIGURATION.md](CONFIGURATION.md), under
> [`[store]`](CONFIGURATION.md#store--message-store--db) and
> [`[secrets]`](CONFIGURATION.md#secrets--connector-secretprovider-selection). For any other source, fetch the secret in your
> service-start wrapper and export it as the corresponding `MEFOR_*` variable, or place the DPAPI key
> file via your provisioning tool. That covers Windows Credential Manager, Azure Key Vault via a
> **managed identity**, and any credential with no reference field. An AD **gMSA** has no
> secret to export: for the SQL Server store, run the service as the gMSA with
> `[store].auth = "integrated"`, as the walkthrough linked above describes.

### Lock down the config directory (CONFIG-2)

`messagefoundry serve --config <dir>` and `POST /config/reload` **execute the Python** in the
config directory in-process, with the service account's privileges. The directory is therefore a
trust boundary: anyone who can write a `.py` file there can run code as the service.

- Restrict the config directory's ACL so only administrators / the service account can write it, and
  set its **owner** — the guard checks both, and the ACL alone is not enough (see the owner bullet
  below):
  ```powershell
  icacls "D:\hl7\config" /inheritance:r /grant "Administrators:(OI)(CI)F" "NT SERVICE\MessageFoundry:(OI)(CI)R"
  icacls "D:\hl7\config" /setowner "*S-1-5-32-544" /T /C
  ```
  `/T` walks the tree, and the walk goes through a junction (measured with `/reset /T`), so remove
  any junction or link inside the dir first, or the command changes what it points at. That holds
  for every `/T` recipe in this section. `/inheritance:r` and `/grant` also leave an explicit entry
  for any other account in place; read the result with `icacls`.
  The supported one-step way to do this at install time is `install-service.ps1 -LockConfigDir`:
  it strips inherited ACEs and locks the dir to SYSTEM + Administrators (full) and the run-as
  account (read+execute) — no companion flag needed, since the run-as account defaults to the
  virtual account. It also removes at least the well-known broad entries (Everyone, Users,
  Authenticated Users and others) from the dir, makes Administrators the owner of each file and
  folder below it that it does not skip (see below), resets each one's DACL to inherit only those
  grants, discarding its own
  entries, and reads each owner and DACL back. What the read-back finds is named in a warning
  instead of the "locked" line: at least an entry for another account, an owner it could not set,
  a missing read for the run-as account, and a deny entry on the dir. The lockdown skips, and names
  in a warning, at least a junction, any other folder reparse point, a file link, a file reparse
  point whose link type it cannot read, and a file it reads as hard-linked, each as its checks of
  the item read it. It changes each other
  item with icacls /L. A hard-linked file it does not detect is changed under every name it has.
  A write grant the run-as account held below the dir becomes read, and
  is named in a warning too. It is **opt-in** because the config dir often lives inside a developer's repo
  where stripping inheritance is surprising — for production, point `-Config` at a dedicated
  admin-owned directory and pass `-LockConfigDir`.
- **Fix an existing tree that inherits a broad write grant** without a full ACL reset. A config dir
  placed under a shared root (e.g. `C:\srv\…`) often inherits `Authenticated Users` (`S-1-5-11`)
  write, which trips the guard below. The lighter-touch alternative to `/inheritance:r` is to break
  inheritance, surgically drop just the broad principal, and grant the run-as user read+execute:
  ```powershell
  icacls "C:\srv\mefor\config" /inheritance:d /T
  icacls "C:\srv\mefor\config" /remove:g *S-1-5-11 /T
  icacls "C:\srv\mefor\config" /grant "<run-as-user>:(OI)(CI)RX" /T
  ```
- The loader **actively enforces** this at load time (and on `/config/reload`), not just as a
  documented recommendation (ADR 0036, SEC-003):
  - On **Windows** the loader now parses the NTFS owner + DACL of the directory, each `*.py`, the
    `__pycache__` folder and each file in it, `connections.toml`, and `codesets\` with each table
    the loader reads, and
    **refuses** to load when a broad/low-privilege principal (Everyone, Authenticated Users,
    `BUILTIN\Users`, INTERACTIVE, …) or any non-owner/non-admin principal holds a write-class right
    (write/append/delete/`WRITE_DAC`/`WRITE_OWNER`/generic-write/delete-child). The principals that may hold one
    are SYSTEM, `BUILTIN\Administrators`, TrustedInstaller, the owner, the run-as account (never
    LocalService or NetworkService, which other services share) and a Domain, Schema or Enterprise
    Admins group the local Administrators lookup resolves. A grant to any other account is refused,
    an administrator's own account included, because it works without elevation. A conditional,
    object or compound allow entry with a write-class right is refused too, since the guard cannot
    tell whom it applies to (ADR 0036, amended for BACKLOG #5622). A `NULL` DACL (everyone allowed)
    is likewise refused. If the guard **cannot finish its read**, it **refuses** to load: a check
    that could not finish has not shown the code safe to run. That covers at least a Win32 API
    error, an owner SID it cannot resolve, a DACL it cannot enumerate, and this process's own token
    it cannot read. The refusal names the path and the Win32 error where there is one. The cure is
    to fix what made the read fail. Where it is honoured (see *Dev/test escape* below),
    `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` downgrades the refusal to a
    WARNING for a dev/CI checkout only, as it does every refusal of this owner and access-list
    read. It does not downgrade the refusal of a trust-list link that cannot be resolved or leads
    to nothing at check time, on either platform. A `*.py` deleted while the
    load runs is skipped, as on POSIX (ADR 0036 Amendment B).
  - **The OWNER is checked too, and this arm REFUSES rather than warning.** An owner holds
    `WRITE_DAC` implicitly, so it can rewrite the DACL and the executed `.py` whatever the ACEs
    currently say — a clean DACL owned by a low-privilege account is not evidence of anything. The
    owner passes when it is **the account the engine runs as** (never LocalService or
    NetworkService, which other services share), a **well-known administrator SID**
    (SYSTEM, `BUILTIN\Administrators`, TrustedInstaller, or a domain SID ending in RID
    500/512/518/519), or a
    **resolved direct member of the local Administrators group**. Anything else is refused, **and so
    is a membership lookup that cannot be completed**, the same as a DACL read that cannot finish
    (ADR 0036 Decision 3 as amended).
    - **The membership lookup is local-only and sees DIRECT members**, deliberately: it must not be
      able to block on an unreachable domain controller. So an account whose administrator rights
      come **through a nested domain group** (the common `Domain Admins` case) does **not** resolve
      and is refused, even though it really is an administrator on the box.
    - **The cure is to own the config dir as an administrator**, which `icacls` does in one line.
      `-LockConfigDir` now does this for you at install time; run it by hand on a directory you
      locked down before this behaviour shipped, or one created by an operator whose rights are
      nested:
      ```powershell
      icacls "D:\hl7\config" /setowner "*S-1-5-32-544" /T /C
      ```
      `*S-1-5-32-544` is `BUILTIN\Administrators` by SID, so the command is correct on a non-English
      Windows. `/T` covers the `*.py` files, which the guard vets individually; `/C` keeps the walk
      going past a file it cannot set (an open editor, an antivirus scan) instead of stopping at the
      first one and leaving the rest on the old owner — check its summary line for skipped files.
      Remove any junction or link inside the dir first, for the reason given above.
      Setting the owner does **not** grant anyone access — pair it with the DACL recipes above.
  - **An engine run as LocalService or NetworkService earns no self-trust**
    ([ADR 0036](adr/0036-windows-config-source-trust.md) Amendment E). Other services share
    LocalService (`S-1-5-19`) and NetworkService (`S-1-5-20`), which is why the grantee and owner
    rules above never count either as the account the engine runs as. On a site that ran the
    engine as one of them, the guard would refuse, at load or at `serve` start, a path it checks
    that the shared account owns, or on which an entry grants the shared account write. The one
    exception is the owner check's: a shared-account owner that is a direct member of the local
    Administrators group passes, and so do its own grants. That covers a config editor run as that
    account: the folder it writes into, the file it leaves, and its own validation load where it
    runs one. A load stops at the first path it refuses. The refusal is the guard's own message.
    Under this rule it names the shared account as a write grantee or as the owner, though another
    entry the guard refuses on the same path can be reported first. A `/config/reload` caller gets
    only a 422, and the reason is in the engine log. The refusal is deliberate and stays: the owner
    ruled on 2026-11-15 to keep it fail-closed. The remedy takes all three of these:
    - **Run the engine under an account that is its own:** the installer's default per-service
      virtual account, or a dedicated local account or gMSA passed with `-ServiceAccount`, with the
      caveat [Restrict the service token](#restrict-the-service-token) records for a named account.
    - **Do not run the config editors as LocalService or NetworkService,** whether from the CLI or
      through the VS Code extension: at least `connection`, `codeset`, `alert` and `security`.
    - **Leave every path the guard checks owned by the `BUILTIN\Administrators` group, readable by
      the engine account, writable only by SYSTEM and `BUILTIN\Administrators`, and with no entry
      for LocalService or NetworkService.** `-LockConfigDir` sets the folders it locks read-only to
      the engine account, but it replaces only the entries for SYSTEM, Administrators and the
      run-as account and leaves any other explicit entry. A file a config editor wrote carries its
      own protected access list and does not take its folder's grants, so the lockdown does not
      change that list, and the engine account needs a grant on that file itself.

    An editor run elevated has an open problem of its own: its rewrite can replace a config file
    with a new one, discarding the file's existing access list, owner and mode
    (vault BACKLOG #5619).
  - On **POSIX** hosts the loader **refuses** to load from a group/world-writable directory or module
    file, or from one owned by any uid other than root or the engine's effective uid. When the engine
    runs as root, only a root owner is trusted. A root-owned config that is not group/world-writable
    is the safest layout, because the engine's own account cannot rewrite it, provided the engine
    can still read every file. The loader checks the same paths as on Windows, following links.
    For each of them that is a symbolic link or a junction, the
    config directory included, it also checks what Python's path resolution says the link leads
    to and, for a file, the folder holding that file, on both platforms, and it refuses the load
    where a link it lists, a module, `__pycache__` entry, `connections.toml`, `codesets` or
    code-set table link among them, leads to nothing it can read at check time or cannot be
    resolved (vault BACKLOG #2596), and the dev/test escape does not downgrade that refusal. For
    a linked folder the folder holding its target is not
    checked. It then walks each such link as the `serve` start check walks its own files
    (`_link_chain`), so it also checks the real folder holding each link the walk follows, the
    links in between for a link to a link, and on Windows each link itself, and it refuses the
    load where that walk cannot run, reaches nothing, or reaches another object than an open of
    the link does, a Windows reparse point other than a symbolic link or a junction among them
    (vault BACKLOG #2596 step 4). So the layout also depends on at least these, which it
    does not check: every directory above the config directory, and above each folder a link
    leads to, is writable only by root; no link leads through a folder another account can write;
    and the file system reports real owners and modes (a network mount may synthesize them).
    - **Why the loader does not walk the directories above it (vault BACKLOG #3106).** The trust
      anchor check, `anchor_path.posix_path_verdict`, does walk them: it reads every directory from
      `/` down to the file, follows each link and reads its target's directories too, and reads the
      file system type of each. Here that walk would refuse a config directory whose parent another
      account can write, or a module that is a link into such a directory. It is not taken here, at
      least for these reasons. It answers *indeterminate* for any file system outside its short
      allowlist (`POSIX_TRUSTED_FS` in `messagefoundry/auth/anchor_path.py`), such as a CIFS, NFS,
      FUSE or 9p mount, and for one whose type it cannot read. The loader then has to choose
      between refusing every start from such a file system and passing what the walk could not
      vouch for, and that choice has not been made. A Kubernetes ConfigMap or projected volume
      reaches each file through two links (`<file>` to `..data/<file>`, and `..data` to a dated
      folder the kubelet swaps on update), and that layout has not been measured against the walk.
      It has not been measured against the current check either (see `docker/README.md`). And the
      POSIX policy is shared: the `serve` start check of the settings and value files
      (`assert_trusted_start_paths`) judges each path by the same code. That start check does not
      take this walk either, but it does walk the links an open of each file passes through, as
      it models the open, and vets the folders holding them, as the value-file paragraph in
      [SECURITY.md](SECURITY.md#dual-control-approval-for-high-value-actions-wp-l3-04-asvs-235)
      states. The config load's trust list takes that link walk too, for each member that is a
      link, as the bullet above says.
    - **The exposure that leaves is a known limit, not a safe layout.** An account that can write
      any directory above the config directory can rename that directory and put a link or another
      directory in its place. A substitute put there after the check runs unchecked, and one put
      there before it passes when it is a link to any directory owned by root or by the engine's
      own account that is not group- or world-writable, such as the engine's data directory.
      Nothing here detects either. An account that can write the directory a link points into
      can replace the file the check passed, after the check, and an account that can write a
      directory above that one, or a folder holding a link in between, can put another in its
      place, after the check or, with the same limit as above, before it. Before you deploy, run `namei -l <config dir>` to list
      every directory on the path. It does not look inside the directory, so also run `ls -lR` on
      the config directory, which lists at least its `codesets` and `environments` folders, and
      run `namei -l` on every file there that is a link. Each directory those commands list must be owned by root, or by the engine's own
      account for the config directory itself, with no group or other write bit. The shipped
      image's `/config` sits directly under `/`, which is root-owned.
  - **The cache folder is checked because a cache file there can still run.** The loader compiles
    each config module, and each `_` helper imported with an `import` statement, from the bytes it
    read, so neither runs from `__pycache__`. A module reached through the ordinary import system
    still can, at least through `importlib.import_module` or a sibling import while the config
    directory is on `sys.path`, and so can tools such as `python -m` (vault BACKLOG #2596).
  - **At start, `serve` checks two more files the same way, each with the folder it sits in**: the
    service settings file it read (`--service-config`, else `.\messagefoundry.toml`) and the value
    file `environments\<env>.toml`. It refuses to start when another account can write either one
    (*"refusing to start from writable-by-others path ..."*), because each one steers the service.
    `supervise` makes the same check before it starts any engine shard. Every reload reads the
    value file again, so it checks it again first and refuses the reload the same way. The dev/test
    escape below downgrades these refusals too. `install-service.ps1 -LockConfigDir` locks the
    value file's folder with the config directory. Locking reaches every folder below, so it locks
    the settings file's folder only when that folder holds no folder but `-Config` and the value
    folder, and passes at least the checks below for `-Config`; it must also not be this checkout
    or a folder in it. A config repo with drop folders or a `.git` folder beside `-Config` is left
    alone. Any folder it leaves is named in a warning, and you restrict that folder yourself. It
    refuses outright a `-Config` that is, at least, a volume root, a junction, a folder under the
    Windows folder, or one holding the data directory, the checkout, the install, Program Files,
    ProgramData or the user profiles. These checks compare paths as written, so an 8.3 short name
    or a `subst` drive gets past them.
  - **It also reads the interpreter and the engine package, and only reports them.** A start whose
    interpreter or `messagefoundry` package folder another account can write logs a WARNING,
    *"the engine runs code from writable-by-others path ..."*, and goes on. The installer refuses
    such an install before it registers the service (vault BACKLOG #2626), so the warning is for
    a start the installer did not set up, such as `serve` from a prompt.
  - **Dev/test escape (never set in production).** Because a default Windows checkout grants
    `BUILTIN\Users` write, set `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE=1` **and**
    `MEFOR_SECURITY_ENFORCEMENT=warn` in the same environment to downgrade the refusal to a
    loud WARNING when running from an intentionally user-writable dev/CI tree. The escape alone does
    nothing: under `[security].enforcement = enforce`, the default, it is refused, and the refusal
    names it. A production service leaves it unset and locks the config dir (above), so the guard
    stays fail-closed. While it is honoured, the `serve` start-up warning and `GET /security/posture`
    name it. Honouring it writes no audit row of its own. Its limits are stated once, in its entry in
    [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md): among them, the dial is read from the
    environment, so a program that embeds the engine with its own settings is outside the clamp.
- `/config/reload` only loads from the startup `--config` directory and any directories listed in
  `[api].config_reload_roots` (see [CONFIGURATION.md](CONFIGURATION.md)); an arbitrary path is
  rejected. Keep those roots admin-owned too.

### Suppress Windows crash dumps of the engine (ADR 0152 Phase 0)

A Windows Error Reporting crash dump of the engine is a **full PHI disclosure written to disk**:
in-flight HL7 bodies, the plaintext the store cipher just produced, and the unwrapped DEK all live in
process memory, and a dump copies that memory into a file that is **not** the store — not encrypted,
not covered by the store's ACLs, and never touched by the retention sweep.

The engine applies the **process-local** half of the fix on every `serve`, unconditionally and with no
configuration: `SetErrorMode` (ORed into the inherited mode, so it can never clear a protection you set
upstream) plus `WerSetFlags(NOHEAP | NO_UI | DISABLE_SNAPSHOT_CRASH | DISABLE_SNAPSHOT_HANG)`. It
persists nothing and needs no privilege — a `serve` invocation never silently rewrites machine state.

The other half is **machine policy and no process can reach it**: `HKLM\…\Windows Error
Reporting\LocalDumps` is evaluated independently of the WER exclusion list and of every flag a process
can set, so a LocalDumps-configured host still dumps a process that suppressed everything available to
it. Close it at install time:

```powershell
.\install-service.ps1 -Environment prod -Config D:\hl7\config -ServiceConfig D:\hl7\messagefoundry.toml -SuppressCrashDumps
```

It is **opt-in** because it writes `HKLM` keys **by image name**, which affects every process of that
name on the host — an explicit operator decision, not a side effect of installing. It registers
`python.exe`, the interpreter the service runs: that is the process holding the PHI heap, and so the
one WER would dump. A virtual environment's `python.exe` starts the base interpreter as a **child
process**, and both carry that one name. The `messagefoundry.exe` launcher is no longer registered,
because the service does not run it ([The service launch](#the-service-launch)).

**`LocalDumps` is only ever narrowed, never switched on.** WER local dump collection is **opt-in**: if
the `LocalDumps` key does not exist, no local dumps are collected for anything on the host. Creating
`LocalDumps\<image>` where the parent key was absent would therefore *configure* per-image dump
collection where there was none — a `-SuppressCrashDumps` switch that plausibly **enables** PHI dumps is
worse than no switch at all. So the installer writes the per-image override **only when a `LocalDumps`
configuration already exists**, and reports which of the two it did. Where it does write it, the override
is `DumpType=0` + `CustomDumpFlags=0` (`MiniDumpNormal` — **no heap**, which is the PHI-relevant part) so
a host configured for full dumps stops writing the engine's heap. Note that Microsoft documents
`DumpCount` as *the maximum number of dump files in the folder*, **not** as a disable switch, so treat
the override as a **reduction, not an elimination**: a `MiniDumpNormal` still carries thread stacks. To
eliminate local dumps entirely, remove the host's `LocalDumps` configuration.

**Residuals, stated plainly.** A postmortem debugger registered under `AeDebug` attaches ahead of WER
entirely and is outside both halves. The keys **persist after `uninstall-service.ps1`** (deliberately —
silently re-enabling PHI dumps on uninstall would be the more surprising default); remove them by hand
under that registry path to restore the host's original behaviour. Neither half has been verified by
forcing an actual crash with PHI resident and inspecting the dump directory — the Win32 calls were
confirmed to succeed, the registry writes were not executed. And none of this bears on ASVS 11.7.1:
memory **hygiene** is not memory **encryption**.

## Verify it's running

```powershell
curl.exe --cacert <DataDir>\api-generated-cert.pem https://127.0.0.1:8765/health   # -> {"status":"ok", ...}
```

`--cacert` names the certificate the engine minted on first start. If you set `[api].tls_cert_file`, pass your own certificate or CA bundle instead.

Send a test message and confirm it flows through:

```powershell
.venv\Scripts\python.exe samples\send_mllp.py samples\messages\adt_a01.hl7
```

Then check the log:

```powershell
Get-Content C:\ProgramData\MessageFoundry\logs\service.out.log -Tail 20 -Wait
```

You should see uvicorn's startup banner and `wiring started: N inbound, N outbound
connection(s)`. On stop you should see `wiring stopped` and `engine stopping` —
confirmation of a clean shutdown. (A live config swap logs `wiring reloaded: ...`.)

## Logs

The engine logs to stdout/stderr with a stdlib `logging` setup (one timestamped UTC
stream — see [`messagefoundry/logging_setup.py`](../messagefoundry/logging_setup.py)),
with a CR/LF log-injection filter and a `safe_exc()` PHI-redaction chokepoint on the
exception path (WP-6c — see [PHI.md §7](PHI.md#7-logging--phi-redaction)). NSSM captures
those streams to the files above and rotates them at ~10 MB.

**Structured (JSON) logging and off-box (syslog/SIEM) forwarding are built**, and both
are configured under `[logging]`. Set `format = "json"` to render stdout as one JSON
object per line. Point `forward_host` at a syslog/SIEM collector to ship a copy of every
record off-box: naming a host turns forwarding on by default, `forward_format` is
already `json`, and `forward_protocol` is `udp` (default), `tcp`, or `tls` (native RFC
5425 — no local agent). **Forwarding is required on an enforcing instance**: `serve` refuses to
start without verified TLS to a collector on another host (see [Configure off-box log forwarding
before the first start](#configure-off-box-log-forwarding-before-the-first-start)). The PHI-redaction and
CR/LF-scrub filters above apply to **every** sink, the forwarder included. Settings of
record, with the full `[logging]` table: [`CONFIGURATION.md`](CONFIGURATION.md).

Whatever the format or destination, **avoid raising the level to `DEBUG` in
production** — verbose output may include message content.

**Restrict the log directory's ACL** so the captured stdout/stderr (operational data,
not message bodies) is readable only by administrators and the service account — NSSM's
files would otherwise inherit a broadly-readable `ProgramData` ACL (ASVS 16.4.2):

```powershell
icacls "C:\ProgramData\MessageFoundry\logs" /inheritance:r `
  /grant "Administrators:(OI)(CI)F" "NT SERVICE\MessageFoundry:(OI)(CI)M"
```

### Who owns which log file, and what happens when one cannot be written

Two things can write log files here, and **each file has exactly one owner** — two rotators renaming
one file is how a log gets shredded, and the loser of that race is the log you read after an incident.

| File | Owner | Rotation | Configured by |
|---|---|---|---|
| The captured stdout/stderr (`logs\service-*.log` above) | **NSSM** | NSSM, at ~10 MB | the install script; `[logging].log_dir` only *tells the engine where they are*, for `GET /status` metering (#50), log retention (#120) and the console's log viewer |
| `[logging].file` (optional, off by default) | **the engine** | the engine, at `[logging].file_max_bytes`, keeping `file_backup_count` backups | `[logging]` in your settings TOML |

`[logging].file` is **opt-in and unset by default**; leave it unset and the engine is stdout-only
exactly as before. If you do set it, **put it outside `[logging].log_dir`** and do not point NSSM at
it — the engine refuses to start otherwise, naming the collision.

**The engine stops processing when it cannot log** (BACKLOG #122, ADR 0162), in two stages:

1. **Roll.** A write failure renames the broken file aside as `<name>.broken-<UTC>-<n>`, opens a fresh
   file at the live path, records the rollover event in it and re-writes the record that failed. A
   momentary lock or an antivirus scan heals here and **stops nothing**.
2. **Stop.** If the **replacement** cannot be written either, every connection this engine process
   owns is stopped, in **all three tiers**: inbounds stop accepting, messages already accepted stop
   being routed and transformed, and outbounds pause with their queued messages **retained** (not
   dead-lettered). All three, because processing a message you cannot log is the thing being
   prevented — not just accepting or sending one. You are told three ways — a `log_write_failed`
   alert through the notifier (email/webhook, which does not go through the log that broke), a
   `connection_stopped` alert per halted connection naming the log as the cause, and `GET /status`'s
   `log_sinks` block, which is read from memory and still answers when the disk does not.

A record the sink cannot format is not by itself a write failure. What happens to it, including
the case where the formatter cannot format even the guard's own notice and the sink counts as
unwritable, is stated in [ADR 0162](adr/0162-fail-closed-application-log-write-guard-detect-roll-and-stop.md)
amendment C, *A record that cannot be formatted is not a sink failure*.

**Every outbound reads `log_halted` on `/connections` while this is in force** (ADR 0189), not
`stopped`. The difference is the one that decides what you do next: `stopped` means the lane is
waiting for you to press start, and `log_halted` means it is waiting for a writable disk — pressing
start is refused until the disk is fixed. The state is process-wide because the broken thing is, so
every lane this engine owns shows it at once, and `outbound_running` reports false for all of them
(so `/stats`' running/stopped split counts them as not running). A lane that failed to build, was
parked by the DR run-profile, or is `deployed = false` keeps showing `failed` / `filtered` /
`not_deployed` instead: those are facts about that one connection, and the halt already has its own
alert.

Recover by fixing the disk or permissions and then **restarting the affected connections** — inbounds
*and* outbounds — from the web console, or by restarting the service. Restarting an inbound the halt
stopped also re-arms a router, transform or response lane of it that is STOPPED, for example one the
infra-fault bound stopped while the log was down, except a pooled lane kept STOPPED because it
holds claimed rows whose return to the queue never landed. Under the pooled claim mode only, a connection
restart leaves STOPPED a lane that still holds claimed rows whose return to the queue never landed;
under per_lane the restart respawns such a worker, and it can claim past rows left in flight.
Any later notify_work broadcast re-arms such a lane, at least a reload, a replay, a resend, an
inject or a dead-letter replay, and it can then claim past the unlanded rows; until one arrives it
stays STOPPED. At least a service restart returns them to the queue first, because the engine does that as it starts, so restart the service
to recover it.
**Fix the disk first — the restart is refused while the log is still unwritable.** The engine
re-checks by writing a real record to each dead sink at the moment you ask, so a restart issued
against a still-broken disk leaves the connection halted (and its listener down) and raises another
`log_write_failed` naming the refusal, rather than quietly resuming with no log. That is deliberate:
otherwise "restart it again" would be a way around the control.
`GET /status` may report a flapping sink `unwritable` even when nothing was halted: from the roll
that trips the flap bound until a roll more than 60 s after its last roll or failure, or until a
re-validation of the log releases it (ADR 0162 amendments B and C say when one does). The engine
re-validates at least when it starts and when a recovery action tries to lift a log-write halt; a
recovery action with no halt in force does not re-validate.
A `/config/reload` on its own is **not enough**: it re-arms the inbounds it re-binds, so messages
start being routed again, but it deliberately never resumes a paused **outbound** (that is an
operator decision), so the backlog moves one stage and stops. Restarting the service does both.
Set `[logging].on_write_failure = "continue"` if you would rather the engine keep
running with no log — it still rolls and still alerts, it just does not stop. The `*.broken-*` files
are incident evidence and are deliberately left for you to review and remove; nothing rotates them
away.

**The message store is unaffected by any of this.** It is a separate durable record: a message already
accepted and committed was ACKed, and a log-write failure neither loses it nor re-delivers it.

## Admin console (in a browser)

This service is **headless**. Operators watch and run it from the **browser web console** served
same-origin at `/ui` (not part of the service runtime — a separate wheel the engine mounts
in-process). It publishes as its **own** distribution on its own version line. With the console on,
the engine refuses to start beside a console built for a different UI seam, so match the pair:
console 0.5.0 for engine 0.5.2. Install it into the engine venv:

```powershell
pip install "messagefoundry-webconsole==0.5.0"       # into the engine venv (pairs with engine 0.5.2)
pip install -e packaging/messagefoundry-webconsole   # or, from a source checkout
```

No switch is needed: the console is **on by default** for a loopback bind
([ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md)),
and `[security].serve_web_console = false` turns it off. (`[api].serve_ui` was the old spelling and
is now **refused at config load** — [ADR 0118](adr/0118-secure-by-default-security-configuration-section.md)
moved the console/bind/origin switches into `[security]`.)

Browse to this service's `/ui` (`https://127.0.0.1:8765/ui`) and sign in as the administrator you
provisioned (see *Provision the first administrator* above). The engine always serves
HTTPS: with no `[api].tls_cert_file` it mints a self-signed certificate on first run, beside the
store database as `api-generated-cert.pem`, so the browser warns until you import that file into the
trust store or configure your own certificate.

**The engine renews that certificate early, and you must re-import it.** At startup, once less than
a third of its lifetime is left (about 122 of its 365 days) or it has expired, the engine replaces
it with a new key and certificate under the same file names. It never touches a certificate you
configured in `[api].tls_cert_file`, and it never renews while running: the expiry monitor warns
for an engine that is never restarted. Each renewal is logged at WARNING and written to the audit
log as `api.tls_generated_pair_replaced`, with the old and new SHA-256 fingerprints. **After a
renewal, import the new `api-generated-cert.pem` into the browser trust store again, and replace
any copy of it you pass to `--cacert`.** A sharded service (`supervise`) renews once, before it
starts its shards, and a shard it restarts never renews, so every shard serves the same certificate.
The same replacement runs at startup, whatever the expiry, when the certificate does not name the
address a client on this box dials for the current bind: the family's loopback for a wildcard
`--host` (`127.0.0.1` for `0.0.0.0`, `::1` for `::`), else the host without IPv6 brackets (`[::1]`
is the address `::1`), matched without regard to case or an IPv6 zone. For a bind the engine treats
as loopback (`127.0.0.1`, `::1`, `localhost`), whose certificate names all three, it also runs when
the certificate lacks any of them (BACKLOG #5790). A move from `0.0.0.0` to `::` replaces a pair a
first run minted for `0.0.0.0`; a move from `127.0.0.1` to `0.0.0.0` or `::` does not, and nor does
the move back. The new certificate names what a first-run mint for the current bind would. When a
client on this box dials that bind through `localhost`, `127.0.0.1` or `::1`, a replacement, a
renewal included, also keeps each of those three the old certificate named, and always `127.0.0.1`,
which the CLI, the IDE and the harness dial by default. A replacement for a missing name is audited
with reason `bind_changed`, unless the pair is also due for renewal, which is audited with reason
`renewal`. An engine shard makes neither. The audit row may be missing, at least if its write fails,
which logs an ERROR, or if the start fails after the replacement and before the row is written,
which leaves the WARNING line as the only record (ADR 0172 decision 6). Import the certificate from
either replacement as after a renewal (BACKLOG #5973). At least an engine shard, a bind the
certificate builder refuses (a WARNING names it), and a file or lock failure (a WARNING, and the
next start tries again) keep serving the old certificate, which lacks a name the current bind needs.
See
[INSTALL-GUIDE.md](INSTALL-GUIDE.md) → "Launching the admin console". (The former PySide6 desktop
console was retired — BACKLOG #103.)

## High-delivery-rate TCP tuning (engine host)

Outbound MLLP ships **connect-per-message as the default this release** (`persistent=false` —
today's proven posture; [ADR 0067](adr/0067-persistent-outbound-mllp.md) §8), so on the default
posture the engine opens **one TCP connection per delivered message**. At sustained delivery
rates in the hundreds of messages per second the engine host is the active closer of every one
of those connections, so closed sockets accumulate in `TIME_WAIT` and can exhaust the **default
Windows ephemeral port range (16,384 ports)** — deliveries then dead-letter with
`MLLP connect ... failed` even though the partner is healthy. This was measured on the
2026-07-02 load campaign: `TIME_WAIT` peaked above the default range and ~50% of deliveries
dead-lettered; with the tuning below the same load ran without exhaustion. This applies to the
Pilot/Standard tiers only at high per-lane rates — most on-prem feeds never approach it.

**The durable fix is `persistent=true`** (ADR 0067), a documented **opt-in** this release: it
reuses one connection per destination, removing the per-message handshake and the `TIME_WAIT`
accumulation entirely. Operators running sustained high-rate delivery can opt in per outbound
today (`persistent = true` on the `MLLP()` destination); the default flips to `persistent=true`
in a subsequent release once the ADR 0067 §8 trigger is met. Until you opt in — or the default
flips — apply the host tuning below on high-rate lanes.

If you run sustained delivery in the hundreds of msg/s on the default (`persistent=false`)
posture (or see connect-failure dead-letters while partners are reachable), either opt into
`persistent=true` on that outbound, or widen the range and shorten the wait (administrator
PowerShell, engine host only):

```powershell
# Widen the ephemeral range (here: 22000-65535 ~= 43,500 ports)
netsh int ipv4 set dynamicport tcp start=22000 num=43535
# Halve how long a closed socket lingers (default 120s on older builds, 60s on newer)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
  -Name TcpTimedWaitDelay -Value 30 -Type DWord   # reboot to apply
```

Check current state: `netsh int ipv4 show dynamicport tcp` and
`(Get-NetTCPConnection -State TimeWait).Count`. Revert by restoring the defaults
(`start=49152 num=16384`, delete the `TcpTimedWaitDelay` value). Both changes are
host-wide — coordinate with whatever else the box runs.

## Uninstall

```powershell
.\scripts\service\uninstall-service.ps1
```

This stops the service through Windows and removes its registration with `sc.exe`. It runs no
`nssm.exe`, so there is no copy for it to trust. **It does not return the host to its
pre-install state.** The script reads the host before it removes the registration, then prints an
inventory of what is still there and the command that clears each one. Read that inventory; the
list below says what it covers.

| Left behind | Why | Clear it with |
|---|---|---|
| The `DataDir` tree — logs and message store | Your data | Delete it yourself once you are sure you are not reinstalling. `DataDir` is a PHI sink — dispose of it the way [PHI.md](PHI.md) describes |
| The service's `nssm.exe`, in the installer's `-NssmDir` (`C:\Program Files\MessageFoundry\nssm` by default) | The copy the service ran; the inventory names the one it was registered with | Delete it yourself only when no other service installed with the same `-NssmDir` remains and you are not reinstalling |
| An access-control entry for the run-as account on `DataDir` **and** on the config directory | The installer grants both so the service can read config and write logs | `-RemoveAccountAces`, or `icacls "<dir>" /remove:g "*<SID>"` |
| Under `[store].key_provider = 'host'`, the custody directory `MEFOR_CUSTODY_DIRECTORY` names, with `master.key` (and `handoff.key` before the first start), and the run-as account's read and add-file entry on it | The files hold the store's key, maybe its only copy on this host. Each file carries its own access-control entry for the account, and `-RemoveAccountAces` takes the account's entry off the directory only, not off the files. A reinstall refuses the kept directory while the new service does not name it | Keep the directory and its files while the store is kept; never delete them. `-RemoveAccountAces` removes the directory's entry. To reinstall, see [When a refusal names master.key or handoff.key](#when-a-refusal-names-masterkey-or-handoffkey) |
| The `SeServiceLogonRight` ("Log on as a service") grant | Setting the service's run-as account does not grant it, so the installer does | `-RemoveLogonRight`, or secpol.msc under Local Policies, User Rights Assignment |
| Inheritance turned off on `DataDir`, and (with `-LockConfigDir`) on the config directory plus its owner moved to Administrators | See below | `icacls "<dir>" /inheritance:e`, by hand |
| Windows Error Reporting keys, when you installed with `-SuppressCrashDumps` — **two** surfaces, `ExcludedApplications` and `LocalDumps`, reported separately because Windows evaluates them independently | [Stated above](#suppress-windows-crash-dumps-of-the-engine-adr-0152-phase-0) — removing them switches PHI-carrying dumps back on | By hand, under that registry path |

**The service SID type and the privilege list are not in that table, because they go with the
registration.** The installer sets both on the registration and nowhere else. The uninstaller looks
for the service's registry key after it removes the service. If Windows has only marked the service
for deletion, the key and both settings are still there, and the inventory says so.

**Why the uninstaller does not put the permissions back.** Turning inheritance on again would hand
the parent directory's principals read access to logs and a message store that can carry PHI — on
the way out, when nobody is watching. And nothing recorded what the permissions and the owner were
before the installer changed them, so a "restore" would be inventing a state rather than returning
to one. The two switches exist for the residues that **are** reversible, and both are opt-in.

```powershell
.\scripts\service\uninstall-service.ps1 -RemoveLogonRight -RemoveAccountAces
```

**Pass them on the uninstall run itself.** Both act on facts that only exist while the service is
registered — the run-as account, its SID, the config directory. Once the service is gone the script
exits at its "not installed" guard, so a second run with the switches does nothing. The inventory
says so, and names the manual command for each.

`-RemoveLogonRight` is safe for the installer's default per-service virtual account, whose SID
belongs to this service alone. It warns first for any other account: a gMSA or a dedicated user may
log other services on, and they fail to start with error 1069 once the right is gone. The script
also refuses to remove the right when the account is the only holder on the host, which would take
it from every service at once.

A read that fails leaves its residue out of the inventory, so the script names what it could not
read rather than printing a shorter list. Check those by hand before you call the host clean.

## Troubleshooting

- **Service won't start / exits immediately.** Read `service.err.log`. The most common
  cause is a bad path baked into the service: a service resolves a relative path against
  its own working directory, not against yours. Read what is actually registered —
  `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\MessageFoundry\Parameters | Select-Object AppParameters, AppDirectory`,
  which needs no `nssm.exe` — and
  compare it against where the files really are. The installer makes `-Config`, `-DbPath`,
  `-DataDir` and `-AppExe` absolute, anchored to the directory you ran it from, so
  re-running it from a *different* directory changes what a relative argument meant. Pass
  absolute paths if you want to be certain.
- **Port already in use (e.g. 2575).** The sample config's inbound connection binds MLLP
  port `2575`. If a stray `messagefoundry serve` (or a second copy of the service) is already
  running, the listener fails to bind. Make sure only one instance runs:
  `Get-Process messagefoundry,python | Format-Table Id,ProcessName,Path`.
- **`/health` doesn't respond.** Confirm the service is running
  (`Get-Service MessageFoundry`) and that nothing else owns port `8765`.
- **Permissions on the data dir.** The service runs by default as the least-privilege virtual
  account `NT SERVICE\<ServiceName>`, to which the installer grants read/write on
  `C:\ProgramData\MessageFoundry` (after registration, once the per-service SID resolves). If
  you point `-DataDir` somewhere outside the script-managed path, grant that account read/write
  there too (the installer only ACLs the default data dir), or startup fails — pick a writable
  location and grant it, or opt out to LocalSystem with `-AllowLocalSystem` (see *Security
  hardening* above).
- **A File connection cannot write a directory that used to work.** The service's token is
  write-restricted, so a permission for `Users` or `Authenticated Users` no longer lets it write.
  Grant the directory to `NT SERVICE\<ServiceName>` by name. See
  [Restrict the service token](#restrict-the-service-token).
