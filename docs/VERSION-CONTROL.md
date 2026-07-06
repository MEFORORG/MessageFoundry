# Version control for your config repository — where it lives, and how to change it

Your MessageFoundry **configuration repository** (the "config repo") holds *your* integration
code — Connection/Router/Handler `.py` modules, `connections.toml`, code sets, per-environment value
files, and synthetic test fixtures. It is a normal **git repository your organization owns**, separate
from the engine (the engine is a read-only, version-pinned dependency — see
[INSTALL-GUIDE.md](INSTALL-GUIDE.md) and [ADR 0017](adr/0017-consumer-deployment-model.md)).

Because the whole configuration is code-first, it is naturally **diffable, reviewable, and
revertable**. This document explains **where the repo should be stored** — on a single machine or on a
shared remote — how to choose, and how to set or change that later.

> **The basics** are also summarized in [USER-GUIDE.md](USER-GUIDE.md) and
> [INSTALL-GUIDE.md](INSTALL-GUIDE.md); this is the complete reference they link to.

---

## 1. Two places a repo lives: local vs. remote

A git repo always exists **locally** (a working copy plus its `.git` history on the machine where you
author it). It *optionally* also has a **remote** (`origin`) — a shared copy on a git server or a bare
repository — that acts as the durable, canonical home and the exchange point between people and hosts.

Choosing "where the repo is stored" is really choosing **whether it has a remote, and which one**:

| Choice | Good for | Trade-off |
|---|---|---|
| **On this machine only** (local, no remote) | A single-box (non-HA) engine, local development, or an air-gapped site with no git server | No off-machine backup; no easy way for a second developer or a second engine host to share it. You can add a remote later. |
| **Stored on a shared remote** | **High availability** (more than one engine host), a **team** of developers, and **off-machine backup / disaster recovery** | You stand up (or already have) a git host or a shared bare repo. |

**Rules of thumb**

- **Single box, one author, non-HA →** local only is fine. Add a remote whenever you outgrow it.
- **HA, a team, or you care about backup →** use a shared remote. This is the recommended default for
  any production or multi-host deployment.

Either way, **nothing about MessageFoundry requires a public repo or a specific vendor** — your config
repo is yours, and every option below works fully **on-premises**.

---

## 2. What a shared remote gives you (and what it does not)

A shared remote adds the things a git *server* provides on top of local history:

- **Off-machine backup / DR** — the repo no longer lives on one disk.
- **Team sync + review** — clone, branch, open a pull/merge request, review, merge, pull. See
  [§6](#6-working-as-a-team).
- **Server-side CI** — run `messagefoundry check` authoritatively on every change (the local
  pre-commit hook is bypassable with `git commit --no-verify`; server CI is not).
- **A single source of truth for HA** — every engine host deploys from the same reviewed commit.

**What it does *not* do:** a remote is not an auto-deploy mechanism. The running engine does **not**
pull from the remote and reload itself. Each engine instance still receives its configuration through
your normal **deploy / promote** process — a CI/CD checkout, or **Stage → Promote** from the IDE —
exactly as described in [ADR 0017](adr/0017-consumer-deployment-model.md). So "store it remotely" means
*shared authoring, review, backup, and the HA source of truth* — not GitOps auto-pull.

---

## 3. Choosing a remote (all on-premises, provider-agnostic)

MessageFoundry never assumes GitHub. Any of these work as the `origin` remote:

- **A self-hosted git server** — [**Forgejo**](https://forgejo.org/) (recommended: fully open-source,
  lightweight, on-prem), Gitea, GitLab CE, or Azure DevOps Server / Bitbucket Data Center. Gives you
  pull requests, protected branches, and CI in one place.
- **A private repo** on a hosted service (GitHub/GitLab/Azure DevOps/Bitbucket) if your organization
  already standardizes on one. Create it **private**.
- **A bare repository on a network share or SSH host** — no server software required. Ideal for
  **air-gapped** sites:

  ```bash
  # one-time, on the share (or any host you can reach):
  git init --bare \\server\repos\mefor-config.git      # UNC path on Windows
  # or:  git init --bare /srv/git/mefor-config.git      # then reach it over SSH
  ```

  Then point the config repo at it (see [§5](#5-set-or-change-the-storage-location)).

For a completely disconnected network, you can also move commits with `git bundle` (pack history into
one file, carry it across, `git pull` from the bundle).

---

## 4. Set the storage location during setup

Run **MessageFoundry: Set Up Version Control & Checks** (IDE Home → **Operate**, or the Command
Palette). It initializes the repo, installs a `messagefoundry check` pre-commit hook, and then asks:

> **Where should this config repo be stored?**
> • **On this machine only** • **Store on a shared remote…**

If you pick a shared remote, you are prompted for its URL or path (any git URL, an scp-style
`git@host:repo.git`, or a local/UNC bare path). Setup is **offline-safe**: it only *configures* the
`origin` remote — **nothing is fetched or pushed**. You push when you are ready (see [§7](#7-first-push-and-everyday-use)).

---

## 5. Set or change the storage location later

Run **MessageFoundry: Config Repo Storage Location** (IDE Home → **Operate**, or the Command Palette).
It shows the current location and lets you:

- **Add / change** the shared remote (URL or path), or
- **Switch to local only** (removes the `origin` remote — your local history is untouched; nothing is
  deleted on the server).

The git `origin` remote **is** the storage location — there is no separate MessageFoundry setting to
keep in sync. The equivalent git commands, if you prefer the terminal:

```bash
git remote -v                                  # show the current remote (blank = local only)
git remote add origin <url-or-path>            # add a remote (first time)
git remote set-url origin <url-or-path>        # change it
git remote remove origin                       # go back to local-only
```

---

## 6. Working as a team

Git is distributed — every developer has a full clone. A shared remote is the exchange point:

1. Each developer **clones** the remote and works on a **feature branch**.
2. They open a **pull/merge request**; server CI runs `messagefoundry check`; a reviewer approves.
3. Merge to `main`; everyone else **pulls**.

Merge conflicts are rare in practice because the config graph is **file-per-thing** — separate
Connection/Router/Handler modules and `_`-prefixed shared helpers — so developers who own different
interfaces seldom touch the same lines.

---

## 7. First push and everyday use

Setup and the storage command never contact the network. To publish the first time:

```bash
git push -u origin main
```

…or use the IDE's built-in **Source Control** view (VS Code drives git for commit, history, diff, and
push — MessageFoundry does not reimplement it). Day to day: commit as you author, push to share,
`git pull` to catch up, and deploy a reviewed commit with **Stage → Promote**.

---

## 8. Guardrails — never commit secrets or PHI

The scaffolded `.gitignore` and `.gitattributes` already exclude local stores, captures, and
credentials, and the design keeps secrets out of the repo entirely:

- **No secrets in the repo.** Passwords, keys, and connection credentials come from **environment
  variables** (`MEFOR_VALUE_*` for graph values, `MEFOR_*` for service settings) — never committed. The
  versioned `environments/<env>.toml` files hold only **non-secret** per-environment values.
- **No real PHI in the repo.** Test fixtures are **synthetic only**. Real message bodies live in the
  engine's message store, never in git. See [PHI.md](PHI.md).
- **`*.db`, `.env`, captures, and `bootstrap-admin.txt`** are git-ignored by the scaffold.

This holds regardless of where the repo is stored — a private on-prem remote does not change what may
be committed. When in doubt, review the diff before you commit.

---

## See also

- [INSTALL-GUIDE.md](INSTALL-GUIDE.md) — the full engine + config-repo + private-git deployment model.
- [USER-GUIDE.md](USER-GUIDE.md) — authoring interfaces and running the engine.
- [ADR 0017](adr/0017-consumer-deployment-model.md) — why the config repo is separate and how it is
  deployed to each engine instance.
