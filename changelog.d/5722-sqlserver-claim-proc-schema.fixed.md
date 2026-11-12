- **The SQL Server claim procedures are deployed, gated and called in the store's schema, not in
  `dbo`.** A store provisioned under a login whose default schema is not `dbo` keeps its tables in
  that schema, but with `[store].fifo_claim_proc = true` the procedures were created as `dbo.`,
  guarded on `ALTER` over `dbo`, and called as `dbo.`, apart from the `queue` table they claim from.
  The procedures are now created unqualified, which puts them in the provisioning login's default
  schema with the tables, and the guard probes `ALTER` on that schema. The startup gate looks for
  them in the schema of the `queue` table the engine resolves and the claim calls them there; when
  that table does not resolve, the gate degrades to the ad-hoc batch and says why. A procedure
  stored under a schema-qualified head now reads to the gate as a hand deploy. The retained `_v1`
  procedures keep their `dbo` head. (`BACKLOG #5722`)
