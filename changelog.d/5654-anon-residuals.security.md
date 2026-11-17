- **The anonymizer's leak-check finds more shapes in fields no rule rewrites, and its denylist
  reads live only when the site-code table is the guard's.** An `MR` or `MRN` subcomponent past
  the first in components 7 and 13 is now an MRN-typed hit, as one in component 5 was. A dashed
  SSN or phone hidden by an invisible character or a `\H\` or `\N\` escape is found. A
  default-ignorable character outside Unicode Cc and Cf no longer hides an `MR` or a site code,
  and the MRN-typed and site-code checks read a fullwidth digit or letter folded. An IPv6 address with several dotted groups
  after its last colon, or joined by a dot to an allowed one, is judged. A report no longer
  calls the denylist live when the site-code check's prefixes differ from the publish guard's
  `[site_prefix]` table. (`BACKLOG #5654`, `#5541`)
- **The anonymizer's surrogates no longer write a separator digit or invent an id.** The
  site-code pass writes no digit the message declares as a separator. An identifier surrogate
  leaves an empty id empty and turns an escape sequence in an id into one letter. The tee's
  `anonymize-captures` names a field-separator refusal and its fix instead of advising a keep.
  (`BACKLOG #5534`, `#5540`)
