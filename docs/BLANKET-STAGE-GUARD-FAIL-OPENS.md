# What the blanket-stage guard still lets through

`scripts/hooks/block-blanket-git-stage.ps1` refuses a git command that stages or commits a whole
tree. **It is a best-effort check of the common blanket-stage spellings.** Every blanket form it
does not match is a stated residual. This page lists the known residuals, each measured against
real git. Every list here is "at least": each measuring pass has found new shapes.

That framing comes from the owner's fourth answer, "Accept by mechanism (Recommended)"; see *The
owner answers*. The rest of this paragraph is the page's wording. The guard narrows how often a
session sweeps another session's files into its commit. It does not make that impossible, and no
reader should rely on it as if it did.

This page measures the engine copy only. The vault's rulings file of 2026-10-08 says the vault
runs an older copy, which it measured to behave differently. Whether a settings file here runs the
guard is asserted in `tests/test_claude_settings_contract.py`, so read it there.

## The owner answers

The owner answered at least four times on these forms. Each answer was a choice in a dialog in
the Special seat's session. **These four are reported by that seat. No other seat saw the
dialogs.** The vault's rulings file of 2026-10-08
(`docs/security/OWNER-RULINGS-2026-10-08-RUNBOOK.md`, entry #1339) records answer 1. The seat's
comments on engine PR 2209 record answers 2 and 3, and its comment on engine PR 2217 records
answer 4. The vault file also records an earlier answer that day, "Retire it, unwired
(Recommended)". It says that answer is withdrawn, because its question rested on a false premise.

| Answer | Date | The option the owner chose | What it covers | Section |
|---|---|---|---|---|
| 1 | 2026-10-08 | "Accept, wire it (Recommended)" | six fail-opens | 1 |
| 2 | 2026-10-08 | "Accept all five, wire it (Recommended)" | five groups, (a) to (e) | 2 |
| 3 | 2026-10-09 | "Accept the four, wire it (Recommended)" | four forms the Lander's review found | 3 |
| 4 | 2026-10-09 | "Accept by mechanism (Recommended)" | every form the guard does not match | every allowed form |

The owner's act is the choice of an option, and the quoted label is the option the owner chose.
The questions, the option labels and the option text are the Special seat's wording. The item
lines quoted in sections 1 to 3 are the seat's too. For answer 1, the vault file says so: the seat
worded the six items. For answers 2 and 3, the lines are the question text as the seat's PR 2209
comments give it.

**Answer 4 governs this page.** Its question, as the seat's PR 2217 comment gives it, asked: "Will
you accept by mechanism instead? That is: the guard is a best-effort check against the common
blanket-stage spellings; anything it does not match is a stated residual; the document lists the
known ones as at least." So every form on this page that the guard allows is a stated residual.
That includes section 5, which no per-form answer names.

**Answers 1 to 3 are per form, and this page still sorts by them.** The sort says which per-form
answer, if any, names a form. It does not decide whether a form is accepted; answer 4 does that.
The dialogs for answers 1 to 3 showed one line per item, not the tables on this page. So this page
puts a form under a per-form answer only when the line's own words describe it. A form the words
do not describe is in section 5. That holds even where it sat in an accepted group on this page
before. Where a line says "a stage", this page reads it as `git add` or `git stage` only. A commit
form under such a line is in section 5 too.

The PR 2209 record of answer 2 also says what that answer leaves out: "forms in
docs/BLANKET-STAGE-GUARD-FAIL-OPENS.md that fall in none of the five groups, and the three
unrepaired critic notes in the PR body." Three of the critic notes in the PR 2209 body name a
form, and those forms are in section 5.2.

Sorting a form under a line is the reading of the Builders who wrote this page. The owner may
draw a line elsewhere.

## What wiring waited on, and where each stands

At least these are on record. Items 1 and 3 come from the owner, as relayed or reported. Item 2
is a Lander's condition. **Where each stands is this page's reading, not an owner ruling.**

1. **Owner ruling 2026-08-25, relayed by the Liaison and not read first-hand here:** *"The
   blanket-git-stage guard is a CONTROL. Strike the claim now, wire it after the splitter
   repair."* The commit message of `786ac8b49b` (PR 579) quotes the relay. It reads that repair
   as the quote-state repair, BACKLOG #1341. PR 579 landed the over-deny half of it. The rest
   needs a quote-state parser, and nobody built one. Ledger row #1341 records that the owner
   declined that parser family on 2026-08-25, for the sibling hooks. A Manager ruling of
   2026-09-21 extended the decline to this script, as ledger row #1339 records.
   *Where it stands:* the splitter repair is still not built. No record read for this page shows
   that the owner was asked whether this condition still stands. The vault file's #1339 entry
   says the 2026-10-08 dialog did not put it. The wiring rests on answer 4 and on item 3. This
   page does not say that either one discharges this condition. That is the owner's to say.
2. **A Lander amendment of 2026-09-22 on ledger row #1339, under that Manager ruling:** the
   guard's known fail-opens "must be accepted IN WRITING by the owner before anything wires
   it". The wording is the Lander's, not the owner's.
   *Where it stands:* answer 4 accepts every form the guard does not match, and it is a reported
   dialog choice. The vault file's #1339 entry leaves it to the Lander to ask the owner whether
   such a choice meets this condition. No record read for this page shows that question
   answered.
3. **A hold, as the Special seat reports it on PR 2217.** It says the owner told it to "start no
   new work", and that wiring waits until the owner lifts that. The option the owner chose in
   answer 4 carries this text, which the seat wrote: "Recorded as your ruling. When you lift the
   hold, one Builder wires the guard. The three plain reading mistakes it found (a bare carriage
   return, a heredoc tag with - or ., $((1<<n))) are fixed first if they need no parser."
   *Where it stands:* the Special seat reports that the owner then chose "Lift for #1339 only
   (Recommended)", at 00:24:30Z on 2026-10-10 (UTC). No engine record holds that choice: the
   seat reported it in its brief for the wiring change, and a maintainer-internal vault record
   holds it too. The brief's account of that lift, in the seat's words, is that one wiring
   Builder is dispatched once engine PR 2217 merges. PR 2217 merged at 02:27:30Z on 2026-10-10
   (UTC), as `9afa08f5cf`. None of the three mistakes needed a parser, and section 4a records
   their fix.

**Why the guard is wired while items 1 and 2 stay open.** The owner made two choices that the
wiring rests on. In answer 4 the owner chose an option whose text, written by the seat, says
"When you lift the hold, one Builder wires the guard." The owner then chose the lift in item 3.
Those two choices are the authority this page cites for wiring. Whether they also discharge the
relayed 2026-08-25 condition in item 1, and the Lander's condition in item 2, is not settled by
any record read here. That is for the owner, and for the Lander to put to the owner.


## How this was measured

Three passes, with the same tools and the same method.

- **First pass:** engine commit `773e43c3fadb51222ead5f69520c222ffab25e9c` (2026-10-08), for
  engine PR 2209. At least 430 payloads. The "allowed before" readings in section 4 are of the
  guard at that commit.
- **Second pass:** engine commit `61361fff906067c9da0c0fa7d3457b7f229447b7` (2026-10-09), which
  holds PR 2209. At least 190 commands, each run in a repository. Also 18 payloads sent straight
  to the hook, 14 of which it cannot read. Section 3 and every row marked "second pass" come from
  this pass. So do the rows added to sections 1 and 2, and the rows section 4a moved from 5.1.
- **Third pass:** engine commit `9afa08f5cffefce5eb523dc8a4dac55878e00f9c` (2026-10-10), for the
  wiring change. Each row in section 4a, its
  scoped control and its neighbour were run again, before and after the fix. Section 4a marks
  the rows this pass found.
- **Tools:** git 2.55.0.windows.5, PowerShell 7.6.6, and GNU bash 5.3.15 from Git for Windows.
- **Guard verdict:** each command went to the guard as a real `PreToolUse` payload on stdin, as a
  `Bash` tool call or a `PowerShell` tool call.
- **What git did:** each command ran in its own throwaway repository under the temp directory,
  outside any tracked tree, under the shell its tool names. The repository held three modified
  tracked files at three depths (`a.txt`, `sub/b.txt`, `sub/deep/c.txt`) and two untracked files
  (`new.txt`, `sub/new2.txt`). The command ran from the repository root.
- **Controls:** every run carried `git add -A`, which the guard denied and git staged in full,
  and `git status --short`, which the guard allowed and which staged nothing.

The search stopped there. The surface is not exhausted, so every list below is "at least".

In the tables, **all five** means git staged the three tracked files and the two untracked ones.
**All tracked** means the three tracked files and no untracked one. A commit never picks up an
untracked file by pathspec, so the commit forms read "all tracked".

## 1. Accepted by answer 1: six fail-opens

The vault file says the dialog named exactly these six. Each heading quotes that file's wording
of one item. All of them are still allowed.

**1. "a stage after an unbalanced apostrophe or escaped quote is allowed".** At least:

| Command | Shell | What git did |
|---|---|---|
| `# it's fine`, newline, `git add -A` | bash, PowerShell | staged all five |
| `# don't forget`, newline, `git add .` | bash, PowerShell | staged all five |
| `# can't skip`, newline, `git stage -A` | bash | staged all five |
| `echo "a \" b" ; git add .` | bash | staged all five |
| `echo "a \" b"`, newline, `git add -A` | bash | staged all five |
| `echo it\'s fine && git add -A` | bash | staged all five |
| ``echo "a `" b" && git add -A`` | PowerShell | staged all five |

The control `# plain`, newline, `git add -A` is denied, so the apostrophe is the cause. The
commit of the same shape, `# that's it`, newline, `git commit -am wip`, is in section 5.2,
because the line says "a stage".

**2. "git run through a wrapper or a full path is allowed (cmd /c, env, a path to git.exe)".** At least:

| Command | Shell | What git did |
|---|---|---|
| `env git add -A` | bash | staged all five |
| `/usr/bin/env git add -A` | bash | staged all five |
| `command git add -A` | bash | staged all five |
| `exec git add -A` | bash | staged all five |
| `eval git add -A` | bash | staged all five |
| `bash -c "git add -A"` | bash | staged all five |
| `sh -c 'git add -A'` | bash | staged all five |
| `git ls-files -m \| xargs git add` | bash | staged all tracked |
| `/mingw64/bin/git add -A` | bash | staged all five |
| `"C:/Program Files/Git/cmd/git.exe" add -A` | bash | staged all five |
| `& "C:/Program Files/Git/cmd/git.exe" add -A` | PowerShell | staged all five |
| `cmd /c "git add -A"` | PowerShell | staged all five |
| `cmd /c git add -A` | PowerShell | staged all five |
| `iex 'git add -A'` | PowerShell | staged all five |
| `Start-Process git -ArgumentList 'add','-A' -Wait -NoNewWindow` | PowerShell | staged all five |

The vault file's wording names three examples: `cmd /c`, `env`, and a path to `git.exe`. The
option the owner chose in answer 2 carries this text, which the Special seat wrote: "I also read
eval, xargs, bash -c and similar as git through a wrapper, which you already accepted." The rows
that neither text names (`command`, `exec`, `sh -c`, `iex`,
`Start-Process`) are sorted here under "and similar". `cmd /c "git add -A"` under bash staged
nothing.

**3. "a shell glob or a magic pathspec beyond the common ones is allowed (git add \*, :^x)".** At least:

| Command | Shell | What git did |
|---|---|---|
| `git add *` | bash, PowerShell | staged all five |
| `git add ?*` | bash, PowerShell | staged all five |
| `git add .[!.]* *` | bash | staged all five |
| `git add */ *.txt` | bash | staged all five |
| `git add '*'` | bash | staged all five |
| `git add ':^nothing'` | bash | staged all five |
| `git add ':!nothing'` | bash | staged all five |
| `git add ':(exclude)nothing'` | bash | staged all five |
| `git add ':(glob)**'` | bash | staged all five |
| `git add ':(top,glob)**'` | bash | staged all five |
| `git add :` | bash, PowerShell | staged all five |
| `git add :/:` | bash, PowerShell | staged all five |
| `git commit -m wip *` | PowerShell | committed all tracked |

`git commit -m wip *` under bash committed nothing: bash expanded `*` to include an untracked
file, and git refused the pathspec.

**4. "--pathspec-from-file is allowed".** At least:

| Command | Shell | What git did |
|---|---|---|
| `git ls-files -mo \| git add --pathspec-from-file=-` | bash | staged all five |
| `printf '.' \| git add --pathspec-from-file=-` | bash | staged all five |
| `printf '.' \| git commit -m wip --pathspec-from-file=-` | bash | committed all tracked |

**5. "any script error or unreadable payload allows".** The hook fails open on input it cannot
read. It exits 0 with no output, which the session reads as "allow". A blanket stage sent in such
a payload would run. Measured in the second pass, each payload sent to the hook as its own
process. At least:

| Payload on stdin | Guard verdict |
|---|---|
| Empty stdin | allowed |
| White space only | allowed |
| Text that is not JSON | allowed |
| JSON cut short, holding `git add -A` | allowed |
| A valid `git add -A` payload with text after it | allowed |
| `{}`, or `[]` | allowed |
| No `tool_input` key, or no `command` key | allowed |
| `command` is `null`, or empty | allowed |
| The command under another key (`script`) | allowed |
| A UTF-8 byte order mark, then a valid `git add -A` payload | allowed |
| A valid `git add -A` payload encoded as UTF-16 | allowed |
| Control: a valid `git add -A` payload | denied |
| Control: a valid `git add -A` payload with no `tool_name` | denied |
| Control: `command` is the list `["git", "add", "-A"]` | denied |

`tests/test_blanket_stage_guard.py` drives these rows, apart from the byte order mark row and the
UTF-16 row. Those two depend on how the runtime decodes stdin. They were measured on Windows
only, so no test pins them.

Two more cases were not measured, because the script cannot show them by itself. One is a hook
that does not start: `tests/test_claude_settings_contract.py` records that the tool call then
proceeds. The other is a hook that runs past its timeout.

**6. "it sees only Bash and PowerShell tool calls".** This is a property of the wiring, not of
the script. The script itself judges any payload that carries a command. Which tools reach it
would be set by the matcher in the settings file. A command typed in a terminal outside the
session would never reach it.

## 2. Accepted by answer 2: five groups

The dialog listed five groups. Each heading below quotes the group's line as the Special seat's
PR 2209 comment gives the question. All of
these forms are still allowed. `tests/test_blanket_stage_guard.py` pins a sample of them as strict
expected failures, so a later repair shows up as a test change.

**(a) "a word before git: if/for/while, '!', 'time', 'FOO=1 git add -A'".** Closing these needs
the guard to know where a program name starts. That is the program-position test that was built
and reverted under BACKLOG #1229. At least:

| Command | Shell | What git did |
|---|---|---|
| `if true; then git add -A; fi` | bash | staged all five |
| `for i in 1; do git add -A; done` | bash | staged all five |
| `while true; do git add -A; break; done` | bash | staged all five |
| `true && ! git add -A` | bash | staged all five |
| `time git add -A` | bash | staged all five |
| `FOO=1 git add -A` | bash | staged all five |
| `GIT_TRACE=0 git add .` | bash | staged all five |

**(b) "the parent directory from a subfolder: 'cd sub && git add ..'".** The guard cannot see the
working directory. `..` is the whole tree from one level down and a scoped directory from two.
At least:

| Command | Shell | What git did |
|---|---|---|
| `cd sub && git add ..` | bash, PowerShell | staged all five |
| `cd sub && git add ../` | bash, PowerShell | staged all five |
| `cd sub && git add ../.` | bash, PowerShell | staged all five |
| `cd sub/deep && git add ../..` | bash, PowerShell | staged all five |
| `git -C sub add ..` | bash, PowerShell | staged all five |
| `cd sub && git commit -m wip ..` | bash, PowerShell | committed all tracked |

Denying `..` would also deny `cd sub/deep && git add ..`, which was measured to stage only the
three files under `sub/`. That is a scoped stage, so the deny would be a false one. From the
repository root, `git add ..` stages nothing: git answers `'..' is outside repository`. The
`../..` row is the same form one level deeper.

**(c) "quoting forms such as git commit -m wip '.' or "git" add -A".** The guard blanks quoted
text before it reads a commit, so a quoted pathspec looks the same as a quoted message. A quoted
or escaped command word hides the word. Closing these needs quote state, which nobody built.
*What wiring waited on, and where each stands*, item 1, gives the record of its decline. At least:

| Command | Shell | What git did |
|---|---|---|
| `git commit -m wip '.'` | bash, PowerShell | committed all tracked |
| `git commit -m wip "."` | bash, PowerShell | committed all tracked |
| `git commit -m wip ':/'` | PowerShell | committed all tracked |
| `git commit -m wip -- ':/'` | bash | committed all tracked |
| `git commit -m wip ':(top)'` | bash | committed all tracked |
| `git commit '-a' -m wip` | bash, PowerShell | committed all tracked |
| `git "add" -A` | bash, PowerShell | staged all five |
| `"git" add -A` | bash | staged all five |
| `& "git" add -A` | PowerShell | staged all five |
| `g\it add -A` | bash | staged all five |
| `git a''dd -A` | bash | staged all five |
| `git add -''A` | bash | staged all five |
| `git add $'-A'` | bash | staged all five |
| `git add $'.'` | bash | staged all five |

The first six rows are commit forms. A quoted whole-tree pathspec under `git add` is denied, and
so is a quoted `-A`, because `add` has no message and the guard reads its arguments unblanked.
`$'-A'` and `$'.'` are bash's dollar-quote. The guard accepts a plain quote around an `add`
argument and not this one.

**(d) "a path the shell supplies, such as git add "$PWD"".** The shell builds the path before
git runs. In the first nine rows the whole-tree path never appears in the command text. In the
last four the text holds a dot, inside a brace list or a substitution. At least:

| Command | Shell | What git did |
|---|---|---|
| `git add "$PWD"` | bash | staged all five |
| `git add "$(pwd)"` | bash | staged all five |
| `git add $(git rev-parse --show-toplevel)` | bash | staged all five |
| `git add "$(git rev-parse --show-toplevel)"` | bash | staged all five |
| `git add $(git ls-files -mo)` | bash | staged all five |
| `git add ~+` | bash | staged all five |
| `git add $PWD` | PowerShell | staged all five |
| `git add (Get-Location)` | PowerShell | staged all five |
| `git add (Get-Location).Path` | PowerShell | staged all five |
| `git add {.,}` | bash | staged all five |
| `git add {a.txt,.}` | bash | staged all five |
| `git commit -m wip $(echo .)` | bash | committed all tracked |
| `git commit -m wip -- $(echo .)` | bash | committed all tracked |

`~+` is bash's tilde form of the working directory. Each brace row expands to a dot.

**(e) "a stage inside a subshell, brace group or $(...)".** The stage runs, and the guard does
not see `git` at the front of a command with its flag. At least:

| Command | Shell | What git did |
|---|---|---|
| `(git add -A)`, `( git add -A )`, `{ git add -A; }`, `f() { git add -A; }; f` | bash | staged all five |
| `(cd sub && git add -A)` | bash | staged all five |
| `echo $(git add -A)`, ``echo `git add -A` ``, `x=$(git add .)` | bash | staged all five |
| `echo "$(git add -A)"` | bash | staged all five |
| `cat <<EOF`, newline, `$(git add -A)`, newline, `EOF` | bash | staged all five |
| `$(git add -A)`, `& { git add -A }`, `if ($true) { git add -A }`, `1..1 \| ForEach-Object { git add -A }`, `foreach ($i in 1) { git add . }`, `function f { git add -A }; f` | PowerShell | staged all five |

Notes on these rows:

- **Row 2** is allowed for a narrow reason: the closing bracket is glued to `-A`, and the guard
  does not take a bracket as the end of a flag. `(cd sub && git add -A )`, with a space, is
  denied. So is `{ cd sub; git add -A; }`. Both staged all five.
- **The backtick form in row 3** is the older spelling of `$(...)`. Bash runs it in a subshell,
  so the line's words describe it.
- **Rows 4 and 5** sat under the quoting group on this page before. Each runs a stage inside
  `$(...)`. In row 5 the guard blanks a heredoc body that bash still expands.
- **The PowerShell row** holds `$(...)` and script blocks in braces. PowerShell's plain round
  brackets are in section 5.

A reading that started a command after an opening bracket would have closed most of this group.
It was built for PR 2209 and withdrawn; see the end of section 4.

## 3. Accepted by answer 3: four forms the Lander's review found

The Lander's review of PR 2209 named four forms. Each heading below quotes the form's line as
the Special seat's PR 2209 comment gives the question.
All were measured in the second pass, and all are still allowed. Form 4 was already on this
page after PR 2209, in group E, with one row.

Forms 1 and 2 come from the commit rule. That rule reads the arguments after the word `commit`.
Before it reads them it drops a trailing comment, drops text inside round brackets, and drops
everything after a bracket that does not close. Forms 1 and 2 each make it drop the dot. Form 3
comes from the way the guard splits a command. Form 4 comes from the way it reads a heredoc.

**1. "an escaped quote that hides a bracket or '#' before the dot".** At least:

| Command | Shell | What git did |
|---|---|---|
| `git commit -m "a \" (b \" c" .` | bash | committed all tracked |
| `git commit -m "a \" #b \" c" .` | bash | committed all tracked |
| ``git commit -m "a `" (b `" c" .`` | PowerShell | committed all tracked |
| ``git commit -m "a `" #b `" c" .`` | PowerShell | committed all tracked |

The guard does not read an escape character. It takes each escaped quote as the end of a quoted
span, so the bracket or the hash looks unquoted. Three controls are denied: `git commit -m "a (b
c" .`, `git commit -m "a #b c" .`, and PowerShell's doubled quote, `git commit -m 'a '' (b '' c'
.`. Each committed all tracked files.

**2. "a PowerShell block comment before the dot".** At least:

| Command | Shell | What git did |
|---|---|---|
| `git commit -m wip <# note #> .` | PowerShell | committed all tracked |
| `git commit <# note #> -m wip .` | PowerShell | committed all tracked |
| `git commit -m wip <# ( #> .` | PowerShell | committed all tracked |

The guard reads the closing `#>` as the start of a trailing comment. These are denied:
`git commit -m wip <#note#> .`, which has no space before `#>`; `git add <# note #> .`; and
`git commit -m wip <# note #> -a`. The scoped `git commit -m wip <# note #> a.txt` is allowed and
committed `a.txt` only.

**3. "a piped $(...) substitution followed by a dot".** At least:

| Command | Shell | What git did |
|---|---|---|
| `git commit -m $(echo wip \| cat) .` | bash | committed all tracked |
| `git add $(echo a.txt \| cat) .` | bash | staged all five |
| `git commit -m $('wip' \| ForEach-Object { $_ }) .` | PowerShell | committed all tracked |

The guard splits a command at a pipe, and it does not know the pipe is inside a bracket. The dot
lands in a piece that does not start with `git`. The control with no pipe,
`git commit -m $(echo wip) .`, is denied. The scoped `git commit -m $(echo wip | cat) a.txt` is
allowed and committed `a.txt` only. Section 5 holds the forms next to this one that the line's
words do not describe.

**4. "a here-string line followed by a stage".** A bash here-string is `<<<word`. The guard reads
it as the start of a heredoc and blanks every later line. At least:

| Command | Shell | What git did |
|---|---|---|
| `cat <<<x`, newline, `git add -A` | bash | staged all five |
| `cat <<<x`, newline, `git add .` | bash | staged all five |
| `cat <<< x`, newline, `git add -A` | bash | staged all five |
| `cat <<<'x y'`, newline, `git add -A` | bash | staged all five |
| `cat <<<"$HOME"`, newline, `git add -A` | bash | staged all five |
| `git commit -m wip <<<x`, newline, `git add -A` | bash | staged all five |
| `read -r a b <<< "$line"`, newline, `git add -A` | bash | staged all five |

The last row is ordinary bash: a here-string feeds `read`, and a stage follows on a later line.
Three commits of the same shape are in section 5.2, because the line says "a stage".

Two controls are denied: `cat <<<x; git add -A`, where the stage is on the same line, and
`cat <<<$HOME`, newline, `git add -A`, where no plain word follows the `<<<`. A PowerShell
here-string that closes, then `git add -A` on the next line, is denied too.

A reading that stopped taking `<<<x` for a heredoc was built for PR 2209 and withdrawn; see the
end of section 4.

## 4. Closed by engine PR 2209

Each of these was allowed at the first measured commit and staged or committed a whole tree. Each
is now denied. `tests/test_blanket_stage_guard.py` drives every family beside a scoped control
that must stay allowed. At least:

| Family | Commands | Shell | What git did before |
|---|---|---|---|
| Commit with a whole-tree pathspec | `git commit -m wip .`, `git commit -m wip -- .`, `git commit . -m wip`, `git commit -m wip ./`, `git commit -m wip ./.`, `git commit -m wip :/`, `git commit -m wip -- :/`, `git commit -qm wip .`, `git commit --amend --no-edit .`, `git -c user.name=x commit -m wip .` | bash, PowerShell | committed all tracked |
| Commit with `--only` or `--include` | `git commit -o . -m wip`, `git commit --only . -m wip`, `git commit -i -m wip .`, `git commit --include -m wip .` | bash, PowerShell | committed all tracked |
| The dot family in `add` and `stage` | `git add ./.`, `git add ././`, `git add .//`, `git add .\`, `git add -- ./.`, `git stage ./.` | bash, PowerShell | staged all five |
| The dot family, PowerShell spelling | `git add .\.` | PowerShell | staged all five |
| A quoted flag | `git add "-A"`, `git add '-A'`, `git add '--all'` | bash, PowerShell | staged all five |
| A redirect glued to the last argument | `git add .>/dev/null`, `git add -A>/dev/null` | bash | staged all five |
| A redirect glued to a commit flag | `git commit -m wip -a>/dev/null` | bash | committed all tracked |
| A bash line continuation | `git add \`, newline, `-A`; `git \`, newline, `add -A`; `git add \`, newline, `.` | bash | staged all five |
| A bash line continuation inside a word | `git add -\`, newline, `A`; `git ad\`, newline, `d -A`; `gi\`, newline, `t add -A` | bash | staged all five |
| A bash line continuation, commit | `git commit \`, newline, `-am wip`; `git commit -m wip \`, newline, `.` | bash | committed all tracked |
| A PowerShell line continuation | ``git add ` ``, newline, `-A`; ``git ` ``, newline, `add -A` | PowerShell | staged all five |
| A PowerShell line continuation, commit | ``git commit ` ``, newline, `-am wip` | PowerShell | committed all tracked |

How each was closed:

- **Commit pathspec.** A new rule reads the arguments after the word `commit`, with quoted text
  blanked. A dot inside a quoted message is not a pathspec. Neither is a dot in a trailing
  comment or inside round brackets. Those two exceptions let whole-tree commits through.
  They are in sections 2(d), 3 and 5.2. No per-form answer covers the ones in 5.2.
- **Dot family.** The whole-tree pathspec now matches any path built only from single dots and
  separators.
- **Quoted flag and glued redirect.** The `add` rules accept a quote around a flag. All the
  rules treat `<` and `>` as the end of an argument.
- **Line continuation.** The guard also reads the command with each continuation joined the
  way the shell joins it. The tool name picks the character: a backslash for `Bash`, a
  backtick for `PowerShell`. This reading is added beside the old one and never replaces it,
  so it can only add a deny.

None of this is a quote-state parser or a program-position test. Across the first-pass corpus, no
command that was denied at the first measured commit is allowed now.

**Three wider readings were built for PR 2209 and withdrawn.** None is in the guard. At least:

- **Start a command after an opening bracket.** It would have closed most of group (e). It was
  withdrawn on a false deny. It refused prose in a message once an apostrophe or an escaped quote
  had put the quote tracking out of step, such as a PowerShell here-string body holding
  `doesn't` and then `(git add -A)`. It also refused `cmd=(git add -A)` and a script block that
  is defined and never run. A review measured it as quadratic on long commands: 57 seconds on a
  24 KB payload.
- **Join the lines of a quoted span.** It would have closed the messages that span lines, in
  section 5. It was withdrawn on a false deny. One stray apostrophe glued later lines onto git's
  arguments. It refused a here-string commit message reading
  `seat.ps1 doesn't accept -Declare without -Seat`, and `git add a.py  # don't forget b.py`
  followed by two ordinary commands.
- **Stop reading `<<<x` as a heredoc.** It would have closed form 4 of section 3. It was withdrawn
  because one command changed from denied to allowed: `cat <<<x`, then `# it's`, then `x`, then
  `git add -A`. That deny is an accident of the misreading. Without the first line, the same
  command is allowed today, as fail-open 1 of section 1 (measured in the second pass). The
  sibling guard, `scripts/hooks/block-unbounded-fs-scan.ps1`, does not take `<<<` for a heredoc.

## 4a. Closed by the wiring change: three reading mistakes

Each of these staged the whole tree, and each is now denied. The rows not marked as first measured
for this change were in section 5.1.
`tests/test_blanket_stage_guard.py` runs each in a throwaway repository under its shell, beside a
`git add -A` control that the guard denies and that stages all five, and drives a scoped form of
the same shape that must stay allowed. Measured with git 2.55.0.windows.5, PowerShell 7 and the
bash from Git for Windows.

| Command | Shell | What git did | The mistake |
|---|---|---|---|
| `Write-Host hi`, bare carriage return, `git add -A` | PowerShell | staged all five | PowerShell ends a line at a bare carriage return. The guard split lines at a line feed only. |
| `cat <<EOF-1`, newline, `x`, newline, `EOF-1`, newline, `git add -A` | bash | staged all five | The guard read a heredoc word as letters, digits and underscores, so it waited for a line `EOF` that never comes. |
| `cat <<E.O`, newline, `x`, newline, `E.O`, newline, `git add -A` | bash | staged all five | The same, with a dot in the word. |
| `cat <<EOF+1`, newline, `x`, newline, `EOF+1`, newline, `git add -A` | bash | staged all five | The same, with a plus sign. First measured for this change. |
| `cat <<'EOF'-1`, newline, `x`, newline, `EOF-1`, newline, `git add -A` | bash | staged all five | The guard took the quoted part alone as the word. bash removes the quotes and keeps the rest. First measured for this change. |
| `cat <<"EOF"x`, newline, `x`, newline, `EOFx`, newline, `git add -A` | bash | staged all five | The same, with double quotes. First measured for this change. |
| `cat <<E\OF`, newline, `x`, newline, `EOF`, newline, `git add -A` | bash | staged all five | The guard stopped the word at the backslash. bash removes it. First measured for this change. |
| `echo $((1<<n))`, newline, `git add -A` | bash | staged all five | The guard read the shift `<<n` as the start of a heredoc. |
| `(( x = 1<<n ))`, newline, `git add -A` | bash | staged all five | The same, in an arithmetic command. First measured for this change. |
| `echo $(( (1+(2)) << n ))`, newline, `git add -A` | bash | staged all five | The same, with brackets nested inside. First measured for this change. |
| `echo $[1<<n]`, newline, `git add -A` | bash | staged all five | The same, in bash's older spelling of arithmetic. First measured for this change. |

How each was closed. Neither is a quote-state parser or a program-position test:

- **Carriage return.** The guard also reads the command split at each bare carriage return. The
  tool name picks it: `PowerShell` and an unknown tool get it, and `Bash` does not, because bash
  does not end a line there. `Write-Host hi`, bare carriage return, `git add -A` under bash is
  still allowed, and it staged nothing.
- **Heredoc word and arithmetic.** The guard also reads heredocs a second way. It reads the
  word the way bash does, up to the first blank or one of `;`, `&`, `|`, `<`, `>`, `(` and `)`,
  and then removes its quotes and backslashes. It skips a `<<` inside `((` and `))` on the same
  line, or inside `$[` and `]`.

Both readings are added beside the old ones and never replace them. The guard judges the old
readings first and builds the new ones only when the old ones allow. So a slow new reading cannot
push the hook past its timeout before the old verdict is reached, and neither can turn a deny into
an allow. Before that order was set, a payload of 30,000 brackets holding a real `git add -A` took
19.7 seconds, past the 15-second timeout, and would have run.

## 5. Known residuals that no per-form answer names

Each form below is still allowed, and git stages or commits a whole tree with it. No line in
answers 1 to 3 describes it. Under answer 4 each is a stated residual, like every other allowed
form on this page, and none of them blocks wiring. This list is how the owner sees them. At least:

**5.1 Forms next to no per-form answer.** The four rows that stood here are closed; see section
4a. At least this one is still open, first measured for the wiring change:

| Command | Shell | What git did | Why the guard allows it |
|---|---|---|---|
| `echo $((1<<n)) # <<EOF-2`, newline, `git add -A` | bash | staged all five | Both heredoc readings take the `<<EOF-2` inside a trailing comment as an opener, and blank every later line. |

**5.2 Forms next to an accepted one, where the answer's words do not fit.** Each has a nearest
accepted line. This page does not sort them under it, because the words differ.

| Command | Shell | What git did | Nearest accepted line | On this page since |
|---|---|---|---|---|
| `>/dev/null git add -A`, `2>&1 git add -A`, `<<<x git add -A` | bash | staged all five | 2(a). The line says "a word" and names keywords and an assignment; these are redirects. | PR 2209, in group A |
| `<# note #> git add -A` | PowerShell | staged all five | 2(a). The line says "a word"; this is a comment. | second pass |
| `# that's it`, newline, `git commit -am wip` | bash, PowerShell | committed all tracked | 1, item 1. The line says "a stage"; this is a commit. | PR 2209, under item 1 |
| `cat <<<x`, newline, `git commit -m wip .`; `cat <<<x`, newline, `git commit -am wip`; `read -r a b <<< "$line"`, newline, `git commit -am wip` | bash | committed all tracked | 3, form 4. The line says "a stage"; these are commits. | second pass |
| `git add sub/..`, `git add sub/../.`, `git add ./sub/..` | bash, PowerShell | staged all five | 2(b). The line says "from a subfolder"; these run from the root. | PR 2209, in group B |
| `(git add -A)` | PowerShell | staged all five | 2(e). The line names a subshell, a brace group and `$(...)`; PowerShell's round brackets are none of these. | PR 2209, in group E |
| `git add "-\`, newline, `A"` | bash | staged all five | 2(c). A critic note from PR 2209, which the record of answer 2 leaves out. | second pass |
| `echo "see <<EOF"`, newline, `git add -A` | bash, PowerShell | staged all five | 2(c). Named in a critic note from PR 2209, which the record of answer 2 leaves out. | PR 2209, in group C |
| `$m = @'`, newline, `see <<EOF`, newline, `'@`, newline, `git add -A` | PowerShell | staged all five | The same, in a here-string. | second pass |
| `git commit -m fix\(x .` | bash | committed all tracked | 3, form 1. The line says "an escaped quote"; this is an escaped bracket. | second pass |
| ``git commit -m fix`(x .`` | PowerShell | committed all tracked | The same. | second pass |
| `git commit -m "a \" (b \" c" -- :/` | bash | committed all tracked | 3, form 1. The line says "before the dot"; this is `:/`. | second pass |
| `git commit -m $(echo wip \| cat) :/` | bash | committed all tracked | 3, form 3. The line says "followed by a dot"; this is `:/`. | second pass |
| `git commit -m $(echo wip \| cat) -a` | bash | committed all tracked | 3, form 3. The line says "followed by a dot"; this is a flag. | second pass |
| `git commit -m ('wip' \| ForEach-Object { $_ }) -a` | PowerShell | committed all tracked | The same. | second pass |
| ``git commit -m `echo wip \| cat` .`` | bash | committed all tracked | 3, form 3. The line says "$(...)"; this is a backtick form. | second pass |
| `git commit -m ('wip' \| ForEach-Object { $_ }) .` | PowerShell | committed all tracked | 3, form 3. The line says "$(...)"; this is a plain round bracket. | second pass |
| `git add ('a.txt' \| ForEach-Object { $_ }) .` | PowerShell | staged all five | The same. | second pass |
| `git commit -m $(true && echo wip) .` | bash | committed all tracked | 3, form 3. The line says "piped"; this is `&&`. | second pass |
| `git commit -m $(true; echo wip) .` | bash | committed all tracked | 3, form 3. The line says "piped"; this is `;`. | second pass |
| `git commit -m $(cat <<'EOF'`, newline, `subject`, newline, `EOF`, newline, `) .` | bash | committed all tracked | 3, form 3. The line says "piped"; this is a newline. A critic note from PR 2209. | second pass |
| `git commit -m "subject`, newline, `body" .` | bash, PowerShell | committed all tracked | 2(c). The quoted message spans lines; the pathspec is not quoted. | PR 2209, in group E |
| `git commit -m "subject`, newline, `body" -a` | bash, PowerShell | committed all tracked | The same. | PR 2209, in group E |
| `git commit -m "$(cat <<'EOF'`, newline, `subject`, newline, `EOF`, newline, `)" .` | bash | committed all tracked | The same. | PR 2209, in group E |
| `git commit -m @'`, newline, `x`, newline, `'@ .` | PowerShell | committed all tracked | The same, with a here-string message. | second pass |
| `git commit -m @'`, newline, `x`, newline, `'@ -a` | PowerShell | committed all tracked | The same. | second pass |
| `git -c alias.aa='add -A' aa` | bash, PowerShell | staged all five | 2(d). Git supplies the command, not the shell. | PR 2209, in group D |
| `git -c alias.aa=add aa .` | bash, PowerShell | staged all five | The same. | PR 2209, in group D |
| `git ls-files -m \| git update-index --stdin` | bash | staged all tracked | 2(d). The line says the shell supplies a path; here `git update-index` stages a list it reads on stdin. | PR 2209, in group D |
| `git diff \| git apply --cached` | bash, PowerShell | staged all tracked | 2(d). No path is supplied at all; `git apply --cached` stages a patch. The guard has rules for `add`, `stage` and `commit` only. | second pass |
| `git add <the repository root as an absolute path>` | bash, PowerShell | staged all five | 2(d). The line says the shell supplies the path; here it is typed. Git gets the same argument as from `"$PWD"`. | second pass |
| `git commit -m wip <the repository root as an absolute path>` | bash | committed all tracked | The same. | second pass |

Notes on these rows:

- **The rows marked "PR 2209"** sat under an accepted line on this page before. The line's
  words do not describe them. Whether that answer covers them is the owner's to say.
- **A message that spans lines** is the most ordinary form on this page. The guard splits a
  command at every newline, also inside a quoted message. The pathspec or flag after the message
  then lands in a piece that does not start with `git`.
- **The `sub/..` rows** name the current directory. Run from the root, that is the whole tree.
  A rule that read `x/..` as a dot would also refuse `cd sub && git add deep/..`, which was
  measured to stage only the three files under `sub/`. That is the same false deny the dot
  itself has from a subfolder; see the last table on this page. `git add <root>/a.txt`, the
  control for the absolute path rows, staged `a.txt` only.
- **The two `<<EOF` rows** hold `<<EOF` inside quoted text. The guard reads it as the start of a
  heredoc and blanks the lines after it. The critic note reports that the sibling guard,
  `scripts/hooks/block-unbounded-fs-scan.ps1`, finds a heredoc opener on text with quoted spans
  already blanked, so the two readers disagree. That was not built or measured here.
- **`git add "-\`, newline, `A"`**: bash joins the two lines inside the quote and git gets `-A`.
  The guard joins a continued line only outside a quote. The unquoted form, `git add -\`,
  newline, `A`, is denied.
- **The two `fix` rows** escape a bracket with no quote. The commit rule drops everything after
  a bracket it reads as open, so it never reaches the dot.
- **An alias already set in a git config file** would behave like the two alias rows. That was
  not measured, because the throwaway repository ran with the user and system config switched
  off.

## Forms that look blanket and were measured to do nothing

The guard allows these, and that costs nothing. At least:

| Command | What git did |
|---|---|
| `git add --renormalize` | staged nothing; git printed its empty-pathspec hint |
| `git add ..` from the repository root | staged nothing; `'..' is outside repository` |
| `git add :/.`, `git add :/./`, `git add ':(top).'` | staged nothing, exit 0 |
| `git commit --al -m wip`, `git commit --a -m wip` | committed nothing; `ambiguous option` |
| `git commit --interactive -m wip` with no terminal | committed nothing |
| `git update-index --again` | staged nothing |
| `git add -A#x` | staged nothing; git refused the arguments |
| `git add "-`, backtick, newline, `A"` in PowerShell | staged nothing |
| `git add $(echo a.txt \| cat) -A` | staged `a.txt` only; `-A` with a pathspec is scoped |

The guard's own comment used to list `--renormalize` as not reached, with `git add --renormalize .`
as the example. That example was already denied, by the pathspec rule. `git add --renormalize a.txt`
stages only `a.txt`. The comment now points here.

## Harmless commands the guard would refuse

A false deny is a defect of its own, because it is what gets a guard switched off. The first-pass
corpus held at least 100 harmless commands. The guard refuses at least these. "Since PR 2209"
means the guard at the first measured commit allowed the command.

| Command | What git did | Since |
|---|---|---|
| `git commit -m . a.txt` | committed `a.txt` only | PR 2209 |
| `git commit --dry-run .`, `git commit -m wip --dry-run .` | committed nothing | PR 2209 |
| `git stash push -m commit -- .` | committed nothing | PR 2209 |
| `git reset -q commit -- .`, with a branch named `commit` | staged nothing | PR 2209 |
| `cd sub && git commit -m wip .`, `git -C sub commit -m wip .` | committed only the two tracked files under `sub/` | PR 2209 |
| `git commit -m wip . ':!sub'` | committed `a.txt` only | PR 2209 |
| `git add .>$null` in PowerShell | staged nothing; git got the pathspec `.>` | PR 2209 |
| `git -C sub add .`, `cd sub && git add .` | staged only the files under `sub/` | before |
| `git add -A sub`, `git add -u sub` | staged only the files under `sub/` | before |
| `git add . ':!sub'` | staged only the files outside `sub/` | before |
| `git add -n .`, `git add --dry-run -A` | staged nothing | before |
| `git commit --dry-run -a` | committed nothing | before |
| `git commit -uall -m wip a.txt` | committed `a.txt` only | before |
| `git commit -ma a.txt` | committed `a.txt` only, with the message `a` | before |
| `git add a.txt # not .`, `git add a.txt # not -A` | staged `a.txt` only | before |
| `git commit -m wip a.txt # not -a` | committed `a.txt` only | before |

Notes on these rows:

- **Row 1** is the price of the commit rule: an unquoted one-character message reads as a
  pathspec. Quoting the message avoids it.
- **Rows 3 and 4** follow from matching the word `commit` wherever the subcommand is not `add`
  or `stage`. The guard's staging rule falls back to the bare word the same way, so that an
  option it does not know cannot hide the subcommand.
- **Rows 5 and 8** are a stage or a commit scoped to one directory. The guard cannot see the
  working directory, so it reads the dot as the whole tree.
- **The last two rows** hold the blanket spelling in a trailing comment. The `add` rules and the
  `commit -a` rule read the comment as arguments. Only the commit pathspec rule drops it, so
  `git commit -m wip a.txt # not .` is allowed.
- **The dry-run rows** change nothing in the repository.

`tests/test_blanket_stage_guard.py` pins a sample of these rows as strict expected failures.
