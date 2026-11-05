- **The ODBC call gate now covers the cancel exits it missed.** A driver call whose task was
  cancelled before the call reached the gate no longer runs later, so it can no longer run after a
  cleanup closed its handle, or on a connection already lent to its next borrower. A cursor made by
  a cancelled `cursor()` call is now closed as that call returns, before its connection closes,
  instead of being left for the garbage collector. A DATABASE borrow cancelled while its cursor was
  being made now goes back to its pool only once that call has returned. A cancelled DATABASE
  borrow on a connection the gate could not wrap no longer closes its cursor beside the running
  statement: the connection is discarded unclosed, and the driver frees it once the statement
  returns. The SQL Server store's dedicated claim connections now leave as the open-time
  connections do: a cancelled open or a cancelled claim hands the connection and its cursor to the
  gate without waiting for the running driver call, and a second cancellation during an ordinary
  discard no longer waits for the close. (`BACKLOG #2394`, `BACKLOG #2395`)
