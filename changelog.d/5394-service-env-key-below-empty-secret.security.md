- **The Windows service start now refuses a store key written below an empty secret under a name
  Windows sets, in the next item or below a later line.** In the service's registry environment,
  below an empty secret such as `MEFOR_STORE_ENCRYPTION_KEY=`, a line or item under a name Windows
  itself sets, spelled as Windows spells it, or under `MEFOR_SECRETS_DIRECTORY`, whose whole value
  is one key or a comma list of keys, such as `Path=<key>`, now reads as that secret's value, and
  the start is refused. That is new where the key is the next item of a multi-string value, or
  where the empty secret is on a later line of its registry string, not the first, and the key on
  the line below it. An empty secret on a string's first line with the key on its next line was
  already refused. Under such a name, at least, these still end the empty value: a value holding
  key text beside other text, such as `Path=C:\x;<key>`, and a key list with an empty entry, such
  as one with a trailing or doubled comma, which the engine's own retired-keys reading accepts.
  (`BACKLOG #5394`)
