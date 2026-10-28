- **The VS Code extension refuses a DHE key exchange over a group under 2048 bits.** Its https
  client to the engine sets `minDHSize` to 2048, where Node's default is 1024. The one DHE suite it
  offers, `DHE-RSA-AES256-GCM-SHA384`, stays in its list. OpenSSL 3.2 and later already refuse such
  a group at their default security level; the option holds the floor where that level is lower,
  as it is by default on OpenSSL before 3.2. (`BACKLOG #300`)
