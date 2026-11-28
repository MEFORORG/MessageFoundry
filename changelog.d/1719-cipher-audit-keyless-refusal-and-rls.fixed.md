- **`cipher-audit` names a missing key behind the keyless-chain refusal, and reads
  PostgreSQL row-level security as NOT_COVERED.** A keyless run over a PostgreSQL or SQL Server
  store whose audit log is empty is still refused as one that would start a keyless audit chain
  (BACKLOG #1916), and the refusal is unchanged. Before, that refusal was exit 2, could not
  start, for a keyed store and a fresh keyless store alike, where SQLite reports the keyed case
  as exit 4, KEY_MISMATCH. Now a read-only probe after the refusal, which writes nothing, tells
  them apart: a store holding keyed cells (a `keyed_surface` row or a sealed value) is exit 4,
  KEY_MISMATCH, and a store holding none, or one the probe cannot read, stays exit 2. A keyless
  run whose audit log is not empty is not refused, and is unchanged. Before, a PostgreSQL table
  with row-level security on could hide rows from the audit login, and the walk could PASS over
  the rows it was shown. Now a run over such a table is never a PASS: it is NOT_COVERED, exit 3,
  where no FAIL or KEY_MISMATCH leads, and at least every verdict whose run read the catalog
  names the table in its reason. The `--json` output gains a `row_filtered` list of those tables
  and a `hidden` list of the cells the catalog did not show. The exceptions are a login that is
  a superuser, has BYPASSRLS, or is itself the table's owner while the table does not force
  row-level security; a member of the owning role is read as not the owner. A row-security
  catalog read that fails, refused or not, names every table and is logged, so a run that can
  still finish is NOT_COVERED, never a PASS. SQL Server security policies are not
  read yet, so a SQL Server store's verdict is unchanged. (`BACKLOG #1719`)
