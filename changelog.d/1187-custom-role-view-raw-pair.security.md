- **A custom role can no longer hold `messages:view_raw` without `messages:view_summary`.** Creating or
  editing one is refused with a `CustomRoleError` that names the pair. A stored role of that shape
  (hand-edited, or written before the rule) now grants everything but `view_raw`. A role that may
  read whole message bodies but not the patient summary is not a coherent role, and owner ruling
  R18 makes a one-message read the reveal act only for a `view_summary` holder. This closes every
  body route at once, `/raw`, attachments, the console body page and a one-id export among them. No
  built-in role has that shape. See [SECURITY.md](../docs/SECURITY.md). (ASVS 14.2.6, vault
  `BACKLOG #1187`)
