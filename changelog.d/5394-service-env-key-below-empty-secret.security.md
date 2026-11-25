- **The Windows service start now refuses a store key written below an empty secret under a name
  Windows sets, where the key is the next item, the empty secret is on a later line of its
  string, or the secret's name stands alone.** In the service's registry environment, below an
  empty secret such as `MEFOR_STORE_ENCRYPTION_KEY=`, a line or item under a name Windows itself
  sets, spelled as Windows spells it, or under `MEFOR_SECRETS_DIRECTORY`, whose whole value is
  one key or a comma list of keys, such as `Path=<key>`, a blank entry from a trailing or doubled
  comma skipped as the engine's own retired-keys reading skips it, now reads as that secret's
  value, and the
  start is refused. That is new at least in the next item of a multi-string value, below the
  secret's name written alone with no equals sign, as `nssm set ... NAME =value` writes it, and
  below an empty secret on a later line of its registry string. In those three forms, under such
  a name, at least a value holding key text beside other text, such as `Path=C:\x;<key>`, still
  ends the empty value. An empty secret set with
  its equals sign on a string's first line still refuses when such a line follows it, as it
  already did.
  (`BACKLOG #5394`)
