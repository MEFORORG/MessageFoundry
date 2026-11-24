- **The PostgreSQL and SQL Server at-open seal of legacy plaintext sends its cells to the cipher in
  batches, as the SQLite seal already does.** Under `vault_transit`, a surface of 200 short legacy
  values was 200 Transit encrypt requests on these backends and is now 2, counted against a fake
  Transit in `tests/test_server_seal_transit_batch.py`. A batch holds at most 128 values and
  512 KiB of base64, so larger values take more requests. The cipher can still seal values one at a
  time, at least for a batch Transit answers with HTTP 400 and, for the rest of that cipher's life,
  after Transit refuses a batch in some other ways; `TransitCipher.encrypt_many` states when. All
  three stores now write each batch's rows before sealing the next. The seal's transaction, marker
  and rollback are unchanged. (vault `BACKLOG #6706`)
