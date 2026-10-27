# 0214 — A secrets directory and one accessor for the engine's secret-class settings

- **Status:** Proposed
- **Date:** 2026-10-27
- **Related:** vault BACKLOG #2595 (step 3, slice A of four); [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) section 5;
  [`messagefoundry/restricted_file.py`](../../messagefoundry/restricted_file.py) (the file helper and its
  check); [`messagefoundry/serviceenv.py`](../../messagefoundry/serviceenv.py) (the NSSM reading);
  [CLAUDE.md](../../CLAUDE.md) section 9

---

## Context

A Windows service run under NSSM keeps its environment list in the service's registry key, and
docs/SERVICE.md records that a default Windows install lets local users read that key. The engine
takes every secret-class setting from the environment: the store password, the AD bind password,
the OIDC client secret and signing key, the SMTP password, the API TLS key password, both Vault
tokens, the AI key, and every `MEFOR_VALUE_*` value that an `env()` reference reads. On a first
deployment as a service, each would sit in that registry key.

The store key already has a protected alternative, the DPAPI key file, so the NSSM reading refuses
a store key in the service's list. The other secrets have none, so the reading names them as a
loosening and does not refuse them: a refusal would leave a service no way to start. Vault BACKLOG
#2595 step 3 is the channel that would let them be refused: one protected, access-controlled
source of secrets for a Windows service.

The maintainer-internal design drafts (process split, decision 2; key custody, slice S2b) settle
its shape: a secrets directory, one file per setting, the readers behind one accessor, each file
restricted, and the store key left in its key file. One owner ruling binds the result: a secret in
the environment follows one rule, under which the store key and anything in a Windows service's
NSSM list are refused always, and other secrets are refused under `enforce` (owner ruling
2026-10-01). Building that refusal is not this ADR's slice.

The CLAUDE.md section 9 rule in play: *"On-premises by default: no PHI leaves the local environment
without explicit, reviewed configuration."* A secret that unlocks PHI is held to the same bar.

## Decision

**A secret-class setting may come from a file in a secrets directory, and every reader of one goes
through one accessor.** This is slice A of four. It adds a source and moves the readers; it refuses
nothing that starts today.

1. **One list.** `messagefoundry/engine_secrets.py` holds `SECRET_SETTING_NAMES`, every
   secret-class setting by its environment name. `serviceenv` takes its two lists from it, so the
   NSSM reading and the accessor cannot disagree about what a secret is.
2. **One accessor.** `secret_settings(names)` (and `secret_setting(name)`) returns, for each name,
   the file's value when the directory has one, else the environment's value exactly as
   `os.environ.get` gave it. The directory wins, so a site moves one setting at a time.
3. **The directory.** `MEFOR_SECRETS_DIRECTORY` names it by absolute path. Unset, nothing is read.
   Each file is named exactly as its variable. The reader refuses, at every enforcement setting:
   a relative path; a directory, or a file, that a known broad group can read or change, judged by
   `restricted_file.broad_access_problem`, the check the store key file gets; a link on Windows; a
   file named for no setting, so a typo does not fall back to the environment unseen; an empty
   file, one that is not UTF-8, or one over 64 KiB. A refusal names the file and never the value.
4. **The directory's own access list is read.** A group that can add a file to the directory could
   supply a setting whatever the access list of the file it adds, so the directory is checked when
   it is opened, before any file in it.
5. **The store key is not read from the directory.** Its protected channel is the DPAPI key file,
   and the key-custody design keeps it there. A file named for the store key or its retired keys
   is refused, and the accessor reads those two names from the environment alone.
6. **Plain files, protected by their access list.** Whether a Windows file is also DPAPI-wrapped,
   and at which scope, waits on a spike: user-scope DPAPI under the service account. The access
   list is the control either way.
7. **The readers moved.** The store Vault token (the key provider and the Transit cipher read it
   through one helper), the connector Vault token, the `env()` values, the settings layer that
   carries the database password and the other settings-borne secrets, and the rotation
   watcher's fingerprint read.

## Acceptance Criteria

- **AC-1** — WHEN a secrets directory holds a file for a setting, THE SYSTEM SHALL return that
  file's value in preference to the environment variable of the same name.
  → `tests/test_engine_secrets.py::test_the_accessor_reads_a_file_in_the_directory`
- **AC-2** — WHEN the directory has no file for a setting, or none is named, THE SYSTEM SHALL
  return the environment's value unchanged, blank included.
  → `tests/test_engine_secrets.py::test_without_a_file_the_environment_is_read_as_it_is`
- **AC-3** — IF a file in the directory is readable or changeable by a known broad group, THEN THE
  SYSTEM SHALL refuse it, naming the file and not the value; a restricted file beside it is read.
  → `tests/test_engine_secrets.py::test_a_broadly_readable_file_is_refused_and_a_restricted_one_is_read`
- **AC-4** — IF the directory itself is readable or changeable by a known broad group, THEN THE
  SYSTEM SHALL refuse it before reading any file.
  → `tests/test_engine_secrets.py::test_a_broadly_readable_directory_is_refused`
- **AC-5** — IF the directory holds a file named for the store key, THEN THE SYSTEM SHALL refuse
  the directory.
  → `tests/test_engine_secrets.py::test_the_store_key_is_never_read_from_the_directory`
- **AC-6** — THE SYSTEM SHALL read each moved setting through the accessor: the two Vault tokens,
  the `env()` values, the settings-borne secrets and the rotation fingerprint.
  → `tests/test_engine_secrets.py::test_the_settings_secrets_read_the_environment_then_prefer_the_file`
- **AC-7** — THE SYSTEM SHALL NOT read a secret-class setting straight from `os.environ` in a moved
  module.
  → `tests/test_engine_secrets.py::test_a_moved_module_reads_no_secret_straight_from_the_environment`

## Options considered

1. **A directory of files, one per setting, behind one accessor.** Works on Windows, Linux and in
   a container, which mounts secret files. Its check is the one key files already get. **CHOSEN.**
2. **One DPAPI-wrapped file holding every secret.** Windows only, and an administrator who must
   change one password has to rewrite all of them. Rejected.
3. **Purge the secrets from the process environment after the settings load.** It leaves them in
   the service's registry key, which is the exposure, and later readers of the environment break.
   Rejected.
4. **A `[secrets].directory` setting in `messagefoundry.toml`.** The Vault modules read their tokens
   outside the settings load, so they would need the setting threaded to them. Rejected for this
   slice; a variable every reader can see is simpler, and it names a path, not a secret.

## Consequences

**Positive** — a site can move a service's secrets out of the registry key now, one at a time, and
each moved secret has an access check it did not have. The refusal in slice B has a channel to
point operators to.

**Negative / risks** — the access check is a list of known broad groups, so a file that passes has
not been shown reachable by the intended accounts alone. A file changed between its check and its
read is read as changed; the directory check limits who can make that change. A plain file is in
any backup that copies it, so the directory belongs outside what a data-directory backup takes,
until the wrapping spike decides otherwise. The right to delete a file inside the directory is not
part of the check; deleting one only sends the setting back to the environment.

**Out of scope** — slice B: refusing a secret found in the environment, and turning the NSSM
reading's named-not-refused into a refusal. Slice C: the installer creating the directory, and the
Linux and container locations (systemd credentials, a mounted secrets path). Slice D: the provider
names ADR 0019 declared and nobody built. Also not moved: the store key's own readers, the `env`
`SecretProvider`'s operator-named references, a command's one-off password such as
`MEFOR_PFX_PASSWORD`, and variables a library reads for itself (`VAULT_TOKEN`, `PGPASSWORD`).
**Step 3 of #2595 is not closed by this ADR.**

## To resolve on acceptance

- [ ] Whether the directory's location becomes a fixed path under the data directory once the
      installer creates it (slice C), or stays operator-named.
- [ ] Whether a Windows file is also DPAPI-wrapped, after the user-scope DPAPI spike.
