- **The anonymizer's leak-check finds more shapes in fields no rule rewrites, and its denylist
  reads live only when the site-code table is the guard's.** An `MR` or `MRN` subcomponent past
  the first in components 7 and 13 is now an MRN-typed hit, as one in component 5 was. A dashed
  SSN or phone hidden by an invisible character or a `\H\` or `\N\` escape is found, inside one
  field or cut across fields, and so is a denylisted token hidden that way. A
  default-ignorable character outside Unicode Cc and Cf no longer hides an `MR` or a site code,
  and the MRN-typed and site-code checks read a fullwidth digit or letter folded. The IPv6 check
  finds more addresses followed by dotted groups, or joined by a dot to an allowed one;
  docs/PHI.md section 9 names forms it still misses. A report no longer calls the denylist live
  when the site-code check's prefixes differ from the publish guard's `[site_prefix]` table.
  (`BACKLOG #5654`, `#5541`)
- **The anonymizer's site-code pass writes no separator digit, and an identifier surrogate
  invents no id.** The site-code pass writes no digit the message declares as a separator. An
  identifier or SSN surrogate fabricates every digit of an id and writes no digit the message
  declares as a separator or escape character. An
  identifier surrogate leaves an empty id empty and turns an escape sequence in an id into
  letters of the same width. The
  tee's `anonymize-captures` names a field-separator refusal and its fix instead of advising a
  keep. (`BACKLOG #5534`, `#5540`)
