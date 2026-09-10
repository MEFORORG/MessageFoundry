<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# mefor-net-helper

`mefor-net-helper.exe` binds and releases one floating IPv4 address (a VIP) for a MessageFoundry cluster
node. It is the privileged helper that [ADR 0056](../docs/adr/0056-engine-managed-vip-failover.md)
specifies. The engine runs as a least-privileged account, and moving an address needs administrator
rights. This small program holds those rights so the engine does not have to.

Nothing in the engine calls the helper yet; the engine-side controller is a later slice.

## It does four things, for one caller, for one address

The helper listens on the named pipe `\\.\pipe\mefor-net-helper`. Each connection carries one request: a
single line of UTF-8 JSON with no byte order mark, ending in a newline. The helper answers with one line.

| Request | What the helper does |
|---|---|
| `{"op":"ping"}` | Answers `{"ok":true,"version":"0.1.0"}`. |
| `{"op":"bind","address":"<ipv4>","interface":"<name>","mask":"<mask>"}` | Adds the address to the adapter. If the address is already there, it succeeds and changes nothing. |
| `{"op":"release","address":"<ipv4>","interface":"<name>"}` | Removes the address. If the address is already gone, it succeeds and changes nothing. |
| `{"op":"arp","address":"<ipv4>","interface":"<name>"}` | Announces the address to the adapter's gateway. Read [Known limits](#known-limits) first. |

Every other answer is `{"ok":true}` or `{"ok":false,"error":"<message>"}`. The message is a short fixed
phrase and never a stack trace. Addresses and masks are dotted decimal, such as `192.0.2.50` and
`255.255.255.0`. Only IPv4 is supported.

The pipe serves one caller at a time. A caller that tries to connect while another is being served is
refused; it should wait with `WaitNamedPipe` and try again. Each caller has 5 seconds to send its request,
and 5 seconds to close its end after reading the answer.

A caller connects with the identification impersonation level. The helper needs to know who the caller
is, but it never acts as the caller.

## Two properties are the reason this binary exists

**It is scoped to one address.** At start, the helper reads the address, interface, mask and client
account from `mefor-net-helper.conf`. It refuses any request that names a different address, interface or
mask, and never attempts it. The values the helper hands to Windows come from that file, not from the
request. A helper that bound whatever it was asked to would lend administrator rights to its caller.

**It checks who is calling.** Anything the pipe accepts runs as administrator, so the helper checks each
caller twice:

1. The pipe's access list denies network logons. It lets the configured client account and
   Administrators read and write, and gives the helper's own account full control.
2. After reading the request, the helper reads the caller's own token. It accepts the configured client
   account or an administrator running elevated. It refuses anonymous callers, network logons and
   everyone else.

The helper creates one pipe instance and reuses it for every caller. If another process already created a
pipe with this name, the helper refuses to start instead of joining it.

The helper never sees patient data. A request holds an operation, an address, an interface name and a
mask. The log records those fields, the caller's account and the outcome, and nothing else.

## Build it

You need Windows, the .NET 10 SDK, and the Visual Studio C++ build tools, which NativeAOT uses to link.

```powershell
dotnet publish net-helper/MeforNetHelper.csproj --configuration Release --output net-helper/out
```

`dotnet publish` compiles the helper with NativeAOT into one native executable, so the server needs no .NET
runtime installed. ADR 0056, "The helper as built", records why. Install only `dotnet publish` output:
`dotnet build` output needs the .NET 10 runtime.

The output folder holds `mefor-net-helper.exe`, its debug symbols in `mefor-net-helper.pdb`, and
`mefor-net-helper.conf.example`. The project references no NuGet packages. Publishing downloads only the
NativeAOT compiler and runtime pack that the SDK itself names. The `net-helper` workflow runs the same
command, then checks that the binary requires administrator and loads no DLL from its own folder.

## Install it

These steps are what a Windows administrator would do once the engine calls the helper.

### `pip install messagefoundry` does not install the helper

The helper would ship as its own release artifact, beside the engine's wheel. An administrator would
install it by hand.
[ADR 0056](../docs/adr/0056-engine-managed-vip-failover.md#the-helper-ships-beside-the-engine-wheel-never-inside-it-2026-09-10)
records why it never ships inside the wheel. No release publishes the helper yet, so for now
[build it](#build-it) and install that output.

### Only Windows nodes can use it

Engine-managed VIP is Windows-only, and so is the helper. A Linux or containerized deployment keeps an
external floating VIP or load balancer in front of the cluster instead. That path stays fully supported,
and [CLUSTERING.md](../docs/CLUSTERING.md#client-reconnect--a-floating-vip--lb-health-check-is-required)
describes it.

### Keep the helper's files where only administrators can write

The steps below run the helper as LocalSystem. Anyone who can replace its binary, its configuration or
the `nssm.exe` that starts it would gain those rights. That is also why the helper never goes into a
Python `site-packages` folder, as
[ADR 0056](../docs/adr/0056-engine-managed-vip-failover.md#the-helper-ships-beside-the-engine-wheel-never-inside-it-2026-09-10)
explains.

So put the binary, its configuration, `nssm.exe` and the log in
`C:\Program Files\MessageFoundry\net-helper\`. By default an unprivileged account cannot write under
Program Files, and a new folder inherits that. The per-node steps check it.

Keep them out of `C:\ProgramData\MessageFoundry`. The engine's installer gives the engine's account
modify rights on that folder and everything in it, including `bin` and `logs`. `Set-SecureDataDirAcl` in
[install-service.ps1](../scripts/service/install-service.ps1) grants them. So the engine's account could
rewrite a log or replace an `nssm.exe` kept there.

### Prepare the files once, on any machine

1. [Build the helper](#build-it).
2. Download the NSSM archive that `$NssmUrl` names in
   [install-service.ps1](../scripts/service/install-service.ps1). That script's `Resolve-Nssm` uses the
   same archive.
3. Check it: `(Get-FileHash <archive>).Hash -eq '<the $NssmSha256 value>'` must print `True`.
4. Extract the `nssm.exe` under `win64` from the archive into the build output folder.
5. In the build output folder, copy `mefor-net-helper.conf.example` to `mefor-net-helper.conf`.
6. Set `address` and `mask` in it, as
   [the configuration section](#the-configuration-file-fixes-the-address-interface-and-mask) describes.
   Both are the same on every node.

### Then run these steps in an elevated PowerShell on each cluster node

1. Install the engine's service first, so its account exists. By default that account is
   `NT SERVICE\MessageFoundry` ([SERVICE.md](../docs/SERVICE.md#run-as-a-least-privilege-account-deploy-1)).
2. Create the helper's folder, and keep its path in `$dir`:

   ```powershell
   $dir = "C:\Program Files\MessageFoundry\net-helper"
   New-Item -ItemType Directory $dir
   ```

3. Copy `mefor-net-helper.exe`, `mefor-net-helper.conf` and `nssm.exe` from the prepared build output into
   `$dir`.
4. Check the access list: `icacls $dir /T`. Only administrators, `SYSTEM`, `TrustedInstaller` and
   `CREATOR OWNER` may hold write rights: `(F)`, `(M)` or `(W)`. `BUILTIN\Users` should show `(RX)`.
5. In `$dir\mefor-net-helper.conf`, set `interface` and `client_account` for this node.
6. Register the helper as a service with that `nssm.exe`, logging beside the binary:

   ```powershell
   & "$dir\nssm.exe" install MessageFoundryNetHelper "$dir\mefor-net-helper.exe"
   & "$dir\nssm.exe" set MessageFoundryNetHelper AppStdout "$dir\net-helper.log"
   & "$dir\nssm.exe" set MessageFoundryNetHelper AppStderr "$dir\net-helper.log"
   & "$dir\nssm.exe" set MessageFoundryNetHelper Start SERVICE_AUTO_START
   ```

7. Confirm the service would start that copy of NSSM.
   `(Get-CimInstance Win32_Service -Filter "Name='MessageFoundryNetHelper'").PathName` must name
   `$dir\nssm.exe`.
8. Start it: `& "$dir\nssm.exe" start MessageFoundryNetHelper`.
9. Run [the ping check](#a-ping-proves-the-helper-is-up-but-not-that-a-bind-would-work).
10. Read `$dir\net-helper.log`. A good start shows `listening on \\.\pipe\mefor-net-helper`, followed by
    the ping check's line. A line with `startup refused` names what to fix. The helper then exits 2 if it
    refused its configuration, or 3 if another process holds the pipe name.

Do not add the VIP to the adapter yourself, and never as a persistent address. The helper adds it to the
active store only, so a node that reboots would not hold the VIP until it wins leadership again.

The helper's manifest requires administrator rights. Started by an account without them, it fails at once
with `ERROR_ELEVATION_REQUIRED` (740).

### The configuration file fixes the address, interface and mask

At start, the helper reads `mefor-net-helper.conf` from the folder that holds `mefor-net-helper.exe`. It
reads the file once, so restart the helper after every edit. No request can change these values.
[Two properties are the reason this binary exists](#two-properties-are-the-reason-this-binary-exists)
explains why.

| Key | Set it to | The helper refuses to start when it is |
|---|---|---|
| `address` | The engine's `[cluster.vip].address`, such as `192.0.2.50`. | Not plain dotted decimal, or an address that can never be a VIP, such as loopback. |
| `interface` | The engine's `[cluster.vip].interface`. It must match the `Name` column of `Get-NetAdapter` exactly, including case. | Empty, over 256 characters, or holding a double quote, a backslash or a control character. |
| `mask` | The engine's `[cluster.vip].netmask`, or its `prefix` written as a netmask: `prefix = 24` is `255.255.255.0`. | Not a contiguous dotted-decimal netmask, or `0.0.0.0`. |
| `client_account` | The account the engine service runs as, by name or SID. The next section says how to find it. | A name no account has, a malformed SID, or a broad group such as Everyone or Users. |

The format is plain:

- Each line holds one `key = value`. Spaces around the key and the value do not matter.
- A line that starts with `#` is a comment, and blank lines are skipped.
- A comment cannot follow a value on the same line, because everything after `=` is the value.
- Each key appears exactly once. A missing, unknown or repeated key stops the helper from starting.

### `client_account` must name the engine service's own account

A group that account belongs to does not count.

1. Find that account. For the default service name, run
   `(Get-CimInstance Win32_Service -Filter "Name='MessageFoundry'").StartName`.
2. Put it in `client_account`. A virtual account looks like `NT SERVICE\MessageFoundry`, and a gMSA looks
   like `CORP\mefor-svc$`.
3. If the helper is already running, restart it.

If this is wrong, the engine cannot use the helper at all. What the engine would see depends on what the
key names:

| `client_account` names | What happens to a call from the engine's account |
|---|---|
| Some other account | Windows refuses the connection at the pipe's access list, before the helper sees it. The helper logs nothing. |
| A group the engine's account belongs to | The access list lets it in, and the helper refuses it. It answers `{"ok":false,"error":"caller is not authorized"}`, and logs the caller by SID with `outcome=refused`. |

To turn a logged SID into a name, run
`([System.Security.Principal.SecurityIdentifier]'<SID>').Translate([System.Security.Principal.NTAccount])`.

The pipe refuses network logons, so the engine must run on the same machine as its helper.

### A ping proves the helper is up, but not that a bind would work

Run this on the node, in an elevated PowerShell:

```powershell
$pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'mefor-net-helper', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Identification)
$pipe.Connect(5000)
$request = [System.Text.Encoding]::UTF8.GetBytes("{`"op`":`"ping`"}`n")
$pipe.Write($request, 0, $request.Length)
[System.IO.StreamReader]::new($pipe).ReadLine()
$pipe.Dispose()
```

A healthy helper prints one line: the `ping` answer from
[the request table](#it-does-four-things-for-one-caller-for-one-address), with its own version. Its log
gains a line with `op=ping`, your account's SID and `outcome=ok`. From a PowerShell that is not elevated,
`Connect` fails with access denied.

A good answer proves the helper started, accepted its configuration and serves the pipe. It does not prove
two things:

- That the engine's account can connect. An elevated administrator passes both caller checks, whatever
  `client_account` names.
- That `interface` is right. The helper looks for the adapter only when asked to act, and a wrong name
  then fails with `interface not found`.

### Every build is unsigned until the project has a certificate

[Signing](#signing) says when the workflow would sign a build. Until then:

- `(Get-AuthenticodeSignature "C:\Program Files\MessageFoundry\net-helper\mefor-net-helper.exe").Status`
  reads `NotSigned`.
- A service start needs no approval. If an administrator starts the helper by hand and Windows asks to
  approve it, the prompt names an unknown publisher.

## Signing

The `net-helper` workflow signs the binary on `main` when these repository secrets are set. Without them
the build still passes, and the job summary marks the artifact as an unsigned development build. The
workflow's header records the full signing policy, including what to change if the certificate's private
key cannot be exported.

| Repository secret | Holds |
|---|---|
| `NET_HELPER_SIGNING_PFX_BASE64` | The code-signing certificate and its private key, as a base64-encoded PFX. |
| `NET_HELPER_SIGNING_PFX_PASSWORD` | The PFX password. |

## Known limits

- **The `arp` announcement is not verified on the wire.** Windows does not transmit when asked to resolve
  one of its own addresses, so the helper sends an ARP request to the adapter's IPv4 gateway, with the VIP
  as the source. ADR 0056, "The helper as built", records the measurement. Nobody has confirmed that the
  request's sender address is the VIP, and the engine must not rely on `arp` until someone does.
  BACKLOG #1522 has the capture steps.
- **`arp` needs an IPv4 gateway on the adapter.** Without one, it returns an error.
- **`bind` and `release` have not yet run against a real adapter.** The netsh commands they run are in
  `NetOps.cs`.
- **The licence-header gate does not read these files.** `scripts/quality/licence_header_check.py` covers
  `.py`, `.ps1`, `.sh`, `.ts`, `.js` and `.go`, so the headers here are kept by hand.
