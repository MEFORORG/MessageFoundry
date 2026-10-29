- **`Store.release_upload_quota` takes the uploader, and the upload-quota reserve reads its
  budget in one aggregate.** The release is now `release_upload_quota(*, uploader_id,
  reservation_id)`, keyword-only so the two ids cannot be swapped, and on every backend it deletes
  the reservation only when it belongs to that uploader. On SQL Server the release used to read
  the row's uploader under `READCOMMITTEDLOCK` only to name the applock it takes; it now takes the
  named uploader's applock with no such read, opening its transaction with the same statement the
  reserve does. A release whose row exists makes as many round trips as before. One with no row
  now makes four rather than two, and can wait for a sibling's reserve of the same uploader; in
  exchange it waits out a reserve that holds the lock but has not yet inserted. The PostgreSQL and
  SQLite releases take no such lock. The reserve's
  in-flight file count and byte total, two subqueries over the same rows, are one aggregate on
  SQLite, PostgreSQL and SQL Server, with the same budget decision. (vault `BACKLOG #3740` items
  10 and 12)
