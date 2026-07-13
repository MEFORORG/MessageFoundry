# Self-hosted CI runner — GMKtec Nucbox M5 Ultra (Windows Server 2025)

> ## ⚠️ RETIRED — historical reference only
>
> **The self-hosted runners described here have been de-registered and their services removed.** The repo
> has **zero** self-hosted runners, and no workflow targets a self-hosted label for the `test` legs.
>
> **Why:** the OSS mirror is a **public** repo, where GitHub-hosted minutes are **free** — so the Windows
> test matrix now runs on **hosted** runners there at no cost, and self-hosting bought nothing. It also
> removed three liabilities: (1) a **SPOF** — self-hosted *required* checks had no hosted fallback, so an
> offline box left PRs queued ~24h and then failing, freezing auto-merge repo-wide; (2) a **security**
> concern — a self-hosted runner must never be reachable from a public repo (a fork PR would mean code
> execution on the maintainer's LAN); (3) ongoing **maintenance** (tool caches, PATH, service accounts).
>
> The Windows `test` legs are now selected by a **per-repo matrix** in `ci.yml`: ubuntu-only on the private
> source repo, full ubuntu + Windows on the public mirror.
>
> Follow this guide **only** if you are deliberately re-introducing a self-hosted runner. Note
> `selfhosted-win2025-sql.yml` remains dispatch-only and is currently **runner-less**.

How to register the **GMKtec Nucbox M5 Ultra** (AMD Ryzen 7 7730U, 8C/16T) as the CI
runner for the required `test (windows-2025, py3.14)` leg, with **two runner services**
on the one box so concurrent PRs don't serialize.

This box is a **physical Server 2025 machine**, NOT the `mefor-win2025-sql-01` VM — that
VM keeps its separate, dispatch-only role for the real-hardware SQL Server suite
(`selfhosted-win2025-sql.yml`) and its own label. Do not cross the two.

## Why

GitHub-hosted Windows minutes bill **2×** and were ~$165 of the June Actions bill; the
`test (windows-2025)` leg runs on every PR update and every push to main. A self-hosted
runner bills **$0** for those minutes. The M5 Ultra is 8C/16T — more cores than the
4-vCPU hosted runner it replaces — so per-run wall-clock is comparable (a shade slower
only if the 15–28 W chassis throttles under a sustained multi-minute load). Coverage is
unchanged: it's still a real Windows Server 2025 SKU.

## Two runners, always on

- The box **stays powered on 24/7**, runners installed as auto-start Windows services, so
  a required `test (windows-2025)` check is never waiting on a cold box.
- **Two runner services** share ONE label (`mefor-ci-win2025`). GitHub dispatches up to
  two `test (windows-2025)` jobs to the box at once, so when several PRs land together the
  Windows leg doesn't serialize behind itself. 8C/16T easily covers two single-threaded
  pytest runs (~2 cores each) with headroom.
- If the box is ever off, the required check just **queues** (up to ~24 h) and auto-merge
  fires when it comes back — jobs queue, they don't fail.

## Security posture (why this is safe here)

- The repo is **private with no fork PRs** — the classic self-hosted danger (untrusted
  fork code executing on your hardware) does not apply. Only code you or Dependabot (from
  allowlisted manifests) pushed ever runs here.
- Own label `mefor-ci-win2025`; never reuse `mefor-win2025-sql`. The SQL VM's contract
  (dispatch-only, DB secrets in machine env, one shared local DB) must not leak onto the
  CI runner and vice-versa.
- Run the runner services as a **dedicated non-admin local user**. The `test` leg is pytest
  only — no admin rights. Do NOT point `windows-service-smoke` at this box: it installs a
  real NSSM service and needs admin; it stays GitHub-hosted (nightly).
- Keep `migration-local/` and any customer data OFF this box. CI checks out the repo
  only.

## Prerequisites on the box

1. Windows Server 2025, updated, outbound 443 to github.com (no inbound holes — the runner
   long-polls out).
2. **Git for Windows, with its `bash` on the *machine* PATH.** `winget install --id Git.Git -s winget`,
   then confirm `C:\Program Files\Git\bin` is on the **system** PATH and restart the runner services.
   ci.yml's steps run under `shell: bash`; GitHub-hosted Windows images ship Git-Bash on PATH, but a
   self-hosted box does **not** by default — without it the `uv pip install` step dies with
   `bash: command not found`. See **Provisioning gotchas** below.
3. **Python 3.14 x64, pre-seeded into each runner's tool cache** — a non-admin runner **cannot**
   self-install it (see **Provisioning gotchas**). Install a standalone 3.14 and place it at
   `<runner-dir>\_work\_tool\Python\3.14.x\x64\`, drop an **empty** `...\3.14.x\x64.complete` marker
   file beside it, then `icacls <runner-dir>\_work\_tool /grant <service-user>:(OI)(CI)M`.
   `actions/setup-python` then cache-hits and skips the (admin-only) installer. uv is installed
   per-run by `astral-sh/setup-uv`; nothing to preinstall for it.
4. ~30 GB free (two work dirs + tool cache + uv cache).
5. Power: never sleep (Server default). Optional: BIOS "restore on AC power" so a power blip
   self-recovers.

## Register both runners

Repo → Settings → Actions → Runners → "New self-hosted runner" (Windows x64) gives the
download URL + a registration token (expires ~1 h; regenerate as needed). Install TWO,
in separate directories, SAME label:

```powershell
# Runner 1
mkdir C:\actions-runner-1; cd C:\actions-runner-1
# (download/extract the actions-runner package per the Settings page)
.\config.cmd --url https://github.com/MEFORORG/MessageFoundry `
  --name mefor-ci-win2025-01 --labels mefor-ci-win2025 --work _work `
  --runasservice --windowslogonaccount ".\<dedicated-user>" --windowslogonpassword "<password>"

# Runner 2 (fresh token from the Settings page; different dir + name, same label)
mkdir C:\actions-runner-2; cd C:\actions-runner-2
.\config.cmd --url https://github.com/MEFORORG/MessageFoundry `
  --name mefor-ci-win2025-02 --labels mefor-ci-win2025 --work _work `
  --runasservice --windowslogonaccount ".\<dedicated-user>" --windowslogonpassword "<password>"
```

- `--labels mefor-ci-win2025` is what ci.yml's windows-2025 leg targets; the default
  `self-hosted` / `Windows` / `X64` labels are added automatically.
- `--runasservice` installs + auto-starts the service — **`config.cmd` does this itself** on the
  current runner (v2.3xx); there is **no separate `svc.cmd install` step**. A named service account
  needs both `--windowslogonaccount ".\<user>"` (the `.\` = local account) and
  `--windowslogonpassword`.

## Verify BEFORE merging the pilot PR

- Settings → Actions → Runners shows **both** `mefor-ci-win2025-01` and `-02` as **Idle**.
- The pilot PR (routes `test (windows-2025)` to `runs-on: [self-hosted, windows,
  mefor-ci-win2025]`) is a **draft**. `test (windows-2025, py3.14)` is a REQUIRED check —
  if it merges while the label has no online runner, EVERY PR queues on it (up to 24 h) and
  auto-merge stalls repo-wide. Only mark it ready / merge once both runners are Idle.

## Provisioning gotchas (learned on the first box — a fresh box WILL hit these)

The first two windows-2025 runs failed at *setup*, not in tests. Both are the runner-account/
self-hosted differences from GitHub-hosted images. Fix them up front on any new box:

1. **A non-admin runner cannot self-install Python via `actions/setup-python`.** Its Windows
   package runs the official installer and writes **HKLM** registry keys — that needs admin, so on a
   non-admin service account it fails with *"Error happened during Python installation."* (The
   "let setup-python fetch it on first run" convenience is **false for a non-admin service account.**)
   **Fix:** pre-seed the tool cache as in Prerequisites §3 — a standalone Python 3.14 under
   `<runner-dir>\_work\_tool\Python\3.14.x\x64\` + an empty `x64.complete` marker + an `icacls … /grant
   <service-user>:(OI)(CI)M`. setup-python then cache-hits and never runs the installer. Keep the cache
   **per-runner** (not a shared `AGENT_TOOLSDIRECTORY`) so the two runners' concurrent jobs don't
   collide on site-packages.
2. **`shell: bash` steps need Git-Bash on the machine PATH.** ci.yml's `run:` steps use bash; hosted
   Windows images have it, a self-hosted box does not, so the `uv pip install` step fails with
   *"bash: command not found."* **Fix:** add `C:\Program Files\Git\bin` to the **machine** PATH and
   restart the runner services (Prerequisites §2).

Both are one-time per box. Fold them into the setup before the first PR routes work here.

## Operating notes

- **Flake watch (slow-hardware tail):** timing-sensitive async tests can surface flakes the
  hosted runners don't (project history: the SQL failover suite already hangs on the slower
  VM). The pilot PR gives the self-hosted leg a longer job cap (15 → 30 min) and per-test
  timeout (60 → 120 s) via matrix keys, without touching the hosted legs. If a test flakes
  here, fix it the house way — poll the actual asserted condition, don't just widen sleeps.
- **Rollback:** revert the pilot PR — `test (windows-2025)` goes straight back to the hosted
  `windows-2025` image; nothing else changes. Then remove the runners from Settings.
- **Second box:** the other M5 Ultra can register two more runners with the SAME label for
  more parallelism, or host a Server 2022 VM later to take `test (windows-2022)` off hosted
  runners too (its own label + a second pilot). Apply the **Provisioning gotchas** above on any
  new box before routing work to it.
