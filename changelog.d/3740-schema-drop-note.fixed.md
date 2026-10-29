- **Correction to the 0.5.2 notes on the upload reservation table.** They said the old
  `upload_quota` table is dropped at open. The schema DDL drops it, so that happens at open on
  SQLite and under `[store].schema_management = "auto"`, and only when a DBA runs
  `messagefoundry store provision-schema` under the `external` default on SQL Server and
  PostgreSQL. (vault `BACKLOG #3740`)
