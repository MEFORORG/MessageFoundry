- **The anonymizer's leak-check finds more shapes in fields no rule rewrites, and its denylist
  reads live only when the site-code table holds the guard's two-digit prefixes.** An `MR` or `MRN` subcomponent past
  the first in components 7 and 13 is now an MRN-typed hit, as one in component 5 was. The
  leak-check reads more values with their invisible characters and their `\H\` and `\N\` escapes
  removed, so it finds more dashed SSNs, phone numbers and denylisted tokens hidden that way. It
  counts a default-ignorable character outside Unicode Cc and Cf as invisible, and the
  MRN-typed and site-code checks read a fullwidth digit or letter folded. docs/PHI.md section 9
  names hidden forms these checks still miss. The IPv6 check
  finds more addresses followed by dotted groups; docs/PHI.md section 9 names forms it still
  misses. A report no longer calls the denylist live when the site-code check's prefixes differ
  from the two-digit entries of the publish guard's `[site_prefix]` table.
  (`BACKLOG #5654`, `#5541`)
- **The anonymizer's site-code pass writes no separator digit, and an identifier surrogate
  invents no id.** The site-code pass writes no digit the message declares as a separator or
  escape character. An identifier or SSN surrogate fabricates every digit of its first component, and an
  identifier surrogate every letter, non-ASCII character and escape character too, a declared
  separator that is a letter or not ASCII among them; neither writes a letter or digit the
  message declares as a separator or escape character. An
  identifier surrogate leaves an empty id empty and turns an escape sequence in an id into
  letters of the same width. The tee's `anonymize-captures` names a field-separator or site-code
  refusal and its fix instead of advising a keep. (`BACKLOG #5534`, `#5540`)
