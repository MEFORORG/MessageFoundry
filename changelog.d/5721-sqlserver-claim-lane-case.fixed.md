- **The SQL Server pooled claim compares lane names exactly, on the batch, the stored procedure and
  the prepared text alike.** A connection name is case-sensitive everywhere else in the engine, but
  the claim compared lane names in the database collation. On a case-insensitive database two
  connections whose names differ only in case would have failed the ad-hoc batch on a primary-key
  violation, while the claim procedure merged the two names into one lane. Every lane comparison in
  the claim now pins a binary collation, and the lane-column index seek is kept. The pooled sweep's
  lane discovery tells the two names apart the same way, so neither lane is left without its
  backstop. Other queries that filter the queue by lane, the per-lane claim among them, still
  compare in the database collation. (`BACKLOG #5721`)
