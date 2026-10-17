- **An administrator's password reset or MFA reset clears the account's known sign-in addresses.**
  An address learned before the reset no longer reads as known, so the next sign-in from it is
  challenged as first-seen and sends the `login_new_ip` notice. The reset leaves one marker row, so
  an account that never stamped a last sign-in is still judged rather than failed open. Revoking
  every session clears nothing. A failed clear is logged at ERROR and does not refuse the reset.
  See [SECURITY.md](../docs/SECURITY.md). (vault `BACKLOG #2946`)
