<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# mefor-net-helper

`mefor-net-helper.exe` binds and releases one floating IPv4 address (a VIP) for a MessageFoundry cluster
node. It is the privileged helper that [ADR 0056](../../docs/adr/0056-engine-managed-vip-failover.md)
specifies. The engine runs as a least-privileged account, and moving an address needs administrator
rights. This small program holds those rights so the engine does not have to.

Nothing in the engine calls the helper yet; the engine-side controller is a later slice. Engine-managed
VIP is Windows-only.

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
dotnet publish packaging/net-helper/MeforNetHelper.csproj --configuration Release --output packaging/net-helper/out
```

`dotnet publish` compiles the helper with NativeAOT into one native executable, so the server needs no .NET
runtime installed. ADR 0056, "The helper as built", records why. Install only `dotnet publish` output:
`dotnet build` output needs the .NET 10 runtime.

The output folder holds `mefor-net-helper.exe`, its debug symbols in `mefor-net-helper.pdb`, and
`mefor-net-helper.conf.example`. The project references no NuGet packages. Publishing downloads only the
NativeAOT compiler and runtime pack that the SDK itself names. The `net-helper` workflow runs the same
command, then checks that the binary requires administrator and loads no DLL from its own folder.

## Install it

Run these steps in an elevated PowerShell on each cluster node.

1. Install the engine's service first, so its account exists. By default that account is
   `NT SERVICE\MessageFoundry` ([SERVICE.md](../../docs/SERVICE.md), DEPLOY-1).
2. Copy `mefor-net-helper.exe` and `mefor-net-helper.conf.example` from the build output to
   `C:\Program Files\MessageFoundry\net-helper\`. Only
   administrators can write there, and it must stay that way: anyone who can write that folder can replace
   the binary or its configuration.
3. In that folder, rename `mefor-net-helper.conf.example` to `mefor-net-helper.conf`.
4. Set `address` and `mask` to the same values as the engine's `[cluster.vip]` settings.
5. Set `interface` to the adapter name exactly as the `Name` column of `Get-NetAdapter` shows it. The
   match is case-sensitive.
6. Set `client_account` as described in the next section.
7. Do not add the VIP to the adapter yourself, and never as a persistent address. The helper adds it to the
   active store only, so a node that reboots does not hold the VIP until it wins leadership again.
8. Install the helper as a service that runs as LocalSystem. With NSSM:

   ```powershell
   nssm install MessageFoundryNetHelper "C:\Program Files\MessageFoundry\net-helper\mefor-net-helper.exe"
   nssm set MessageFoundryNetHelper AppStdout "C:\ProgramData\MessageFoundry\logs\net-helper.log"
   nssm set MessageFoundryNetHelper AppStderr "C:\ProgramData\MessageFoundry\logs\net-helper.log"
   nssm set MessageFoundryNetHelper Start SERVICE_AUTO_START
   nssm start MessageFoundryNetHelper
   ```

9. Read the log. A good start ends with `listening on \\.\pipe\mefor-net-helper`. A line starting
   `startup refused` names what to fix.
10. Check that the pipe answers:

    ```powershell
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'mefor-net-helper', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Identification)
    $pipe.Connect(5000)
    $request = [System.Text.Encoding]::UTF8.GetBytes("{`"op`":`"ping`"}`n")
    $pipe.Write($request, 0, $request.Length)
    [System.IO.StreamReader]::new($pipe).ReadLine()
    $pipe.Dispose()
    ```

    It prints `{"ok":true,"version":"0.1.0"}`.

The helper's manifest requires administrator rights. Started by an account without them, it fails at once
with `ERROR_ELEVATION_REQUIRED` (740).

## Make the pipe reachable by the engine's service account

The engine can reach the helper only when `client_account` names the account the engine service runs as.

1. Find that account: `(Get-CimInstance Win32_Service -Filter "Name='MessageFoundry'").StartName`.
2. Put it in `client_account`. A virtual account looks like `NT SERVICE\MessageFoundry`, and a gMSA looks
   like `CORP\mefor-svc$`. A SID string also works.
3. Restart the helper. It looks the account up at start and refuses to start if the account does not
   exist.
4. Have the engine connect with the identification impersonation level. The helper needs to know who the
   caller is, but it never acts as the caller.

`client_account` cannot be a broad group such as Everyone, Authenticated Users or Users. The helper refuses
to start with one, because every member of that group could then move the VIP.

The pipe refuses network logons, so the engine must run on the same machine as its helper.

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
  as the source. ADR 0056, "The helper as built", records the measurement. Before the engine relies on
  `arp`, capture ARP on a Windows Server node (for example with `pktmon` or Wireshark, run elevated) and
  confirm that the request's sender address is the VIP.
- **`arp` needs an IPv4 gateway on the adapter.** Without one, it returns an error.
- **`bind` and `release` have not yet run against a real adapter.** The netsh commands they run are in
  `NetOps.cs`.
- **The licence-header gate does not read these files.** `scripts/quality/licence_header_check.py` covers
  `.py`, `.ps1`, `.sh`, `.ts`, `.js` and `.go`, so the headers here are kept by hand.
