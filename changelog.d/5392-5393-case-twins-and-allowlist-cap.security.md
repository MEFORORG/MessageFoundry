- **Names that differ only in case are refused, and a source allow-list is judged as a whole.**
  Within each registry table `CASE_TWIN_TABLES` in
  [config/wiring.py](../messagefoundry/config/wiring.py) lists, a config with two names that differ
  only in case now refuses to load, and a rename onto such a name is refused, because a SQL Server
  store column that compares without case would read the two as one. A `DatabaseLookup` or
  reference-set name is also refused beside one that differs from it only in width or trailing
  spaces. Router and handler names are not checked. Separately, the HTTP intake gate and the DICOM
  SCP gate now cap the IPv4 addresses a `source_ip_allowlist`'s entries count together, so entries
  that each meet the prefix floors no longer pass as narrow when together they exceed the cap.
  Both gates quote one rule, `ALLOWLIST_RULE_TEXT` in [netaddr.py](../messagefoundry/netaddr.py),
  which defines the count, and the refusal names the rule the list failed.
  (`BACKLOG #5392`, vault `BACKLOG #5393`)
