- **Custom role definitions and the directory group-to-role map carry an integrity seal on a store
  that holds a key.** Each `roles` row has its own HMAC-SHA256 seal (`roles.seal`) over every other
  column, and the whole AD group-to-role map has one seal over its sorted pairs, kept in a new
  `authority_set_seal` table, under the same purpose-derived key the user and session seals use.
  Every INSERT, UPDATE or MERGE of those tables goes through one helper per backend; deletes need
  no key and stay plain. `AuthService` checks a custom role's seal before it grants anything from
  it, and checks the map's seal before any directory sign-in, step-up, session recheck or
  reconcile reads a role from it. A custom role that fails grants nothing, while its holders keep
  their other roles; a map that fails grants nothing from any of its pairs. Either failure writes
  an `integrity.authority_seal_failed` audit row and raises `integrity_drift`, and the engine keeps
  running. The role list shows a failing role with no permissions and the map read shows a failing
  map as empty, so an administrator's re-save cannot carry a value written outside the store into
  a sealed row. Saving a role or the map again through the console or the API writes it whole and
  seals it, which is how one that fails, or one written before this change, is repaired; a keyed
  open names how many custom roles and maps carry no seal. Removing a deleted role's pairs from the
  map re-seals the map only when it verifies. Built-in roles still resolve from code; their rows are
  sealed by the role seed at each start and grant nothing either way. `rotate-key` re-seals each
  role and the map under the active key after checking it, and leaves one that fails as it is. New
  column `roles.seal` and table `authority_set_seal` on SQLite, Postgres and SQL Server. The AD
  group-to-channel map is not sealed by this change. A keyless store, and the `vault_transit`
  provider, write and check no seal yet. (vault BACKLOG #2592)
