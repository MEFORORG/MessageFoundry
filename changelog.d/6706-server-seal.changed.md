- **The PostgreSQL and SQL Server at-open seal of legacy plaintext sends its cells to the cipher in
  batches of up to 128, as the SQLite seal already does.** Under `vault_transit`, a surface of 200
  short legacy values was 200 Transit encrypt requests on these backends and is now 2, counted
  against a fake Transit in `tests/test_server_seal_transit_batch.py`. Larger values split into
  more requests. A batch Transit answers with HTTP 400 is resent value by value, and once Transit
  has refused a batch any other way, or answered one without its `reference` echo, the cipher
  sends every value alone for the life of the process. The seal's transaction, marker and
  rollback are unchanged. (vault `BACKLOG #6706`)
