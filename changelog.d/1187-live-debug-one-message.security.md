- **The IDE's Live Debug reveal now shows one message.** *Reveal Values for One Run* used to show
  values from every message in a multi-message sample. It now asks which message first, listing them
  by file name and disposition, and the revealed run keeps only that one. A one-message sample needs
  no choice. If the sample changed since its messages were listed, nothing is revealed. Hide, or
  turning Live Debug off, while the choice is open starts no reveal. Owner ruling R15 reads a reveal
  as per message. (ASVS 14.2.6, vault `BACKLOG #1187`)
