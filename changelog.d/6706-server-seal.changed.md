- **The PostgreSQL and SQL Server at-open seal of legacy plaintext sends its cells to a batching
  cipher in batches, as the SQLite seal already does.** Under `vault_transit`, a surface of 200
  short legacy values was 200 Transit encrypt requests on these backends and is now 2, counted
  against a fake Transit in `tests/test_server_seal_transit_batch.py`. A batch of more than one
  value holds at most 128 values and 512 KiB of base64. A larger value is sent alone. The Transit
  cipher can still send values one at a time in some cases; `TransitCipher.encrypt_many` states
  when. A cipher with no batch path, such as AES-GCM, still encrypts one value per call. All three
  stores now write each batch's rows before encrypting the next. Under such a cipher the SQLite
  seal now writes one row per UPDATE call where it wrote a page per call, so its first keyed open
  is slower. The seal's transaction, marker
  and rollback are unchanged. (vault `BACKLOG #6706`)
