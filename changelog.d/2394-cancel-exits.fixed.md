- **The ODBC call gate now covers more of the cancel exits it missed.** A driver call whose task was
  cancelled before the call reached the gate no longer runs later, so it can no longer run after a
  cleanup closed its handle, or on a connection already lent to its next borrower; a cancelled close
  still runs, inside the gate. A cursor made by a cancelled `cursor()` call is now closed as that
  call returns, before its connection closes, instead of being left for the garbage collector. A
  DATABASE borrow cancelled while its cursor was being made now goes back to its pool only once that
  call has returned. A cancelled DATABASE borrow on a connection the gate could not wrap no longer
  closes its cursor beside the running statement: the connection is discarded unclosed, and the
  driver frees it once the statement returns and nothing else holds it, which can be on the event
  loop. The SQL Server store's dedicated
  claim connections now leave as the open-time connections do: a cancelled open hands the
  connection to the gate without waiting for the running driver call, the discard after a cancelled
  claim no longer waits for the claim statement itself, and a second cancellation during an
  ordinary discard no longer waits for the close. A cancelled claim still waits for its statement
  in the claim's own shielded lock-timeout reset, which runs before the discard. At least these are
  not covered: a cancellation that lands after a `cursor()` call returned but before its result was
  delivered, which leaves that cursor for the collector; and the store's pooled connections, its
  open-time connections and its claim connections, which on a connection the gate could not wrap
  still close beside a running driver call. (`BACKLOG #2394`, `BACKLOG #2395`)
