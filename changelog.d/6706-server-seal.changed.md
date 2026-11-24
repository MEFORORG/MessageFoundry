- **The PostgreSQL and SQL Server at-open seal of legacy plaintext sends each page of cells to the
  cipher as one batch, as the SQLite seal already does.** Under `vault_transit` a surface of 200
  legacy values was 200 Transit encrypt requests on these backends; it is now 2 (batches of up to
  128 items), counted against a fake Transit in `tests/test_server_seal_transit_batch.py`. The
  seal's transaction, marker and rollback are unchanged. (vault `BACKLOG #6706`)
