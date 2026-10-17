- **`provision-admin` runs whenever no enabled local Administrator has a usable password.** It used
  to refuse while any enabled Administrator existed, and a directory or federated one counted. A
  site whose Administrators all sign in through Active Directory or an identity provider then had
  no host command to get back in during an outage. The refusal now reads the same check as the
  start warning. Whenever the warning names accounts, those accounts do not block the command. It
  can still refuse for other reasons, such as the password policy. It may now add an Administrator
  beside directory ones, and its audit row lists them in `administrators_at_check`. It still
  never promotes a directory account. A local Administrator with no usable password is refused by
  name, so make the new one under another name. See
  [ADR 0183](../docs/adr/0183-provision-the-first-administrator-offline-no-default-account-at-first-run.md)
  Amendment E and [SECURITY.md](../docs/SECURITY.md). ([BACKLOG #2711](../docs/BACKLOG.md))
