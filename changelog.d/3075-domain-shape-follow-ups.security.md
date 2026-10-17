- **Two more domain checks at load.** `[egress].allowed_recipient_domains` refuses a domain
  longer than 252 characters, which no 254-character address could carry. The two `[security]`
  navigation lists refuse an IPv4 address that is not one host's: at least `0.0.0.0`, which some
  browsers route to the local machine, a multicast address, and the reserved class E range
  with the limited broadcast address. The web console no longer strips a leading dot from a domain entry, so a
  dot-led entry from outside settings matches nothing. (`BACKLOG #3075`)
