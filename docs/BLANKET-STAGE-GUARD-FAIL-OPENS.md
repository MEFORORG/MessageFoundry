# What the blanket-stage guard still lets through

`scripts/hooks/block-blanket-git-stage.ps1` refuses a git command that stages or commits a whole
tree. This page lists the blanket forms it still allows, each measured against real git. It is
the list put to the owner under BACKLOG #1339.

At the measured commit no settings file ran the guard. Whether one does now is asserted in
`tests/test_claude_settings_contract.py`, so read it there. Every "would" below describes what a
session would meet once the guard runs. Wiring waits on the owner's answer to the third list.

## How this was measured

- **Engine commit:** `773e43c3fadb51222ead5f69520c222ffab25e9c` (`origin/main`, 2026-10-08). The
  "allowed before" readings are of the guard at that commit.
- **Tools:** git 2.55.0.windows.5, PowerShell 7.6.6, and GNU bash 5.3.15 from Git for Windows.
- **Guard verdict:** each command went to the guard as a real `PreToolUse` payload on stdin, as a
  `Bash` tool call or a `PowerShell` tool call.
- **What git did:** each command ran in its own throwaway repository under the temp directory,
  under the shell its tool names. The repository held three modified tracked files at three
  depths (`a.txt`, `sub/b.txt`, `sub/deep/c.txt`) and two untracked files (`new.txt`,
  `sub/new2.txt`). The command ran from the repository root.
- **Controls:** every run carried `git add -A`, which the guard denied and git staged in full,
  and `git status --short`, which the guard allowed and which staged nothing.
- **Size:** at least 430 payloads. The search stopped there; the surface is not exhausted, so
  every list below is "at least".

In the tables, **all five** means git staged the three tracked files and the two untracked ones.
**All tracked** means the three tracked files and no untracked one. A commit never picks up an
untracked file by pathspec, so the commit forms read "all tracked".

## 1. The six fail-opens the owner accepted

The owner accepted exactly these six on 2026-10-08. Each is mapped to the forms measured under
it. All of them are still allowed.

**1. A stage after an unbalanced apostrophe or an escaped quote.** At least:

| Command | Shell | What git did |
|---|---|---|
| `# it's fine`, newline, `git add -A` | bash, PowerShell | staged all five |
| `# don't forget`, newline, `git add .` | bash, PowerShell | staged all five |
| `# that's it`, newline, `git commit -am wip` | bash, PowerShell | committed all tracked |
| `# can't skip`, newline, `git stage -A` | bash | staged all five |
| `echo "a \" b" ; git add .` | bash | staged all five |
| `echo "a \" b"`, newline, `git add -A` | bash | staged all five |
| `echo it\'s fine && git add -A` | bash | staged all five |
| ``echo "a `" b" && git add -A`` | PowerShell | staged all five |

The control `# plain`, newline, `git add -A` is denied, so the apostrophe is the cause.

**2. Git run through a wrapper or a full path.** At least:

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

The owner's wording names three examples: `cmd /c`, `env`, and a path to `git.exe`. The other
rows are mapped here by kind. That mapping is this page's reading, and the owner may draw the
line elsewhere. `cmd /c "git add -A"` under bash staged nothing.

**3. A shell glob, or a magic pathspec beyond the common ones.** At least:

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

**4. `--pathspec-from-file`.** At least:

| Command | Shell | What git did |
|---|---|---|
| `git ls-files -mo \| git add --pathspec-from-file=-` | bash | staged all five |
| `printf '.' \| git add --pathspec-from-file=-` | bash | staged all five |
| `printf '.' \| git commit -m wip --pathspec-from-file=-` | bash | committed all tracked |

**5. Any script error or unreadable payload allows.** This is not a command form. The guard
exits 0 with no output on an empty payload, a payload that is not JSON, and a payload with no
command. `tests/test_blanket_stage_guard.py` drives at least six such payloads.

**6. It sees only Bash and PowerShell tool calls.** This is a property of the wiring, not of
the script. The script itself judges any payload that carries a command. Which tools reach it
would be set by the matcher in the settings file. A command typed in a terminal outside the
session would never reach it.

## 2. The forms this change closed

Each of these was allowed at the measured commit and staged or committed a whole tree. Each
would now be denied. `tests/test_blanket_stage_guard.py` drives every family beside a scoped
control that must stay allowed. At least:

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
  comment or inside round brackets.
- **Dot family.** The whole-tree pathspec now matches any path built only from single dots and
  separators.
- **Quoted flag and glued redirect.** The `add` rules accept a quote around a flag. All the
  rules treat `<` and `>` as the end of an argument.
- **Line continuation.** The guard also reads the command with each continuation joined the
  way the shell joins it. The tool name picks the character: a backslash for `Bash`, a
  backtick for `PowerShell`. This reading is added beside the old one and never replaces it,
  so it can only add a deny.

None of this is a quote-state parser or a program-position test. Across the corpus, no command
that was denied at the measured commit is allowed now.

## 3. The measured remainder: neither accepted nor closed

Each form below is still allowed, and git stages or commits a whole tree with it. None is on the
accepted list. `tests/test_blanket_stage_guard.py` pins a sample of them as strict expected
failures, so a later repair shows up as a test change. At least:

**E. Built in this change, then withdrawn.** Three wider readings would have closed the rows
below. Each was built and measured, and each refused harmless commands, so each was taken out
again. The brief's test for closing a form was that no harmless command becomes denied.

| Command | Shell | What git did |
|---|---|---|
| `(git add -A)`, `( git add -A )`, `{ git add -A; }`, `f() { git add -A; }; f` | bash | staged all five |
| `echo $(git add -A)`, ``echo `git add -A` ``, `x=$(git add .)` | bash | staged all five |
| `(git add -A)`, `$(git add -A)`, `& { git add -A }`, `if ($true) { git add -A }`, `1..1 \| ForEach-Object { git add -A }`, `foreach ($i in 1) { git add . }`, `function f { git add -A }; f` | PowerShell | staged all five |
| `git commit -m "subject`, newline, `body" .` | bash, PowerShell | committed all tracked |
| `git commit -m "subject`, newline, `body" -a` | bash, PowerShell | committed all tracked |
| `git commit -m "$(cat <<'EOF'`, newline, `subject`, newline, `EOF`, newline, `)" .` | bash | committed all tracked |
| `cat <<<x`, newline, `git add -A` | bash | staged all five |

What each withdrawn reading cost, at least:

- **Start a command after an opening bracket** (rows 1 to 3). It refused prose in a message
  once an apostrophe or an escaped quote had put the quote tracking out of step, such as a
  PowerShell here-string body holding `doesn't` and then `(git add -A)`. It also refused
  `cmd=(git add -A)` and a script block that is defined and never run. A review measured it as
  quadratic on long commands: 57 seconds on a 24 KB payload.
- **Join the lines of a quoted span** (rows 4 to 6). One stray apostrophe glued later lines
  onto git's arguments. It refused a here-string commit message reading
  `seat.ps1 doesn't accept -Declare without -Seat`, and `git add a.py  # don't forget b.py`
  followed by two ordinary commands.
- **Stop reading `<<<x` as a heredoc** (row 7). This one bought a fail-open: `cat <<<x`, then
  `# it's`, then `x`, then `git add -A` is denied at the measured commit and was allowed with
  the change.

The record of the ruling also says the subshell forms are "not the Builder's to close". They
are not closed.

**A. A word before `git`.** Closing these needs the guard to know where a program name starts.
That is the program-position test that was built and reverted under BACKLOG #1229.

| Command | Shell | What git did |
|---|---|---|
| `if true; then git add -A; fi` | bash | staged all five |
| `for i in 1; do git add -A; done` | bash | staged all five |
| `while true; do git add -A; break; done` | bash | staged all five |
| `true && ! git add -A` | bash | staged all five |
| `time git add -A` | bash | staged all five |
| `FOO=1 git add -A` | bash | staged all five |
| `GIT_TRACE=0 git add .` | bash | staged all five |
| `>/dev/null git add -A` | bash | staged all five |
| `2>&1 git add -A` | bash | staged all five |
| `<<<x git add -A` | bash | staged all five |

`time` and `!` sit close to accepted item 2. They are listed here because they are shell
keywords, not wrapper programs. The owner may read them as wrappers.

**B. A parent-directory pathspec.** The guard cannot see the working directory. `..` is the whole
tree from one level down and a scoped directory from two.

| Command | Shell | What git did |
|---|---|---|
| `cd sub && git add ..` | bash, PowerShell | staged all five |
| `cd sub && git add ../` | bash, PowerShell | staged all five |
| `cd sub && git add ../.` | bash, PowerShell | staged all five |
| `cd sub/deep && git add ../..` | bash, PowerShell | staged all five |
| `git -C sub add ..` | bash, PowerShell | staged all five |
| `cd sub && git commit -m wip ..` | bash, PowerShell | committed all tracked |
| `git add sub/..` | bash, PowerShell | staged all five |
| `git add sub/../.` | bash, PowerShell | staged all five |
| `git add ./sub/..` | bash, PowerShell | staged all five |

Not closed, for two different reasons:

- **The bare `..` rows.** Denying `..` would also deny `cd sub/deep && git add ..`, which was
  measured to stage only the three files under `sub/`. That is a scoped stage, so the deny would
  be a false one. From the repository root, `git add ..` stages nothing: git answers
  `'..' is outside repository`. This is a one-line change if the owner accepts that false deny.
- **The `sub/..` rows.** These always name the current directory. Closing them needs the guard to
  normalise a path, which would cost no false deny. It was left out to keep this change small.

**C. Quoting the guard cannot read.** The guard blanks quoted text before it reads a commit, so
a quoted pathspec looks the same as a quoted message. A quoted or escaped command word hides the
word. Closing these needs quote state, which the owner declined under BACKLOG #1341.

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
| `echo "$(git add -A)"` | bash | staged all five |
| `cat <<EOF`, newline, `$(git add -A)`, newline, `EOF` | bash | staged all five |
| `echo "see <<EOF"`, newline, `git add -A` | bash, PowerShell | staged all five |

The first six rows are commit forms. A quoted whole-tree pathspec under `git add` is denied, and
so is a quoted `-A`, because `add` has no message and the guard reads its arguments unblanked.
The other rows are allowed under `add` as shown. In the last two, the guard blanks a heredoc
body: the first body holds a substitution that bash runs, and the second is not a heredoc at
all, because the `<<EOF` sits inside a quoted string.

The last row may not need quote state. A review reported that the sibling guard,
`scripts/hooks/block-unbounded-fs-scan.ps1`, finds the heredoc opener on text with quoted spans
already blanked. That was not built or measured here.

**D. The shell or git supplies the pathspec.** The whole-tree path never appears in the command
text, so no rule on the text can see it.

| Command | Shell | What git did |
|---|---|---|
| `git add "$PWD"` | bash | staged all five |
| `git add "$(pwd)"` | bash | staged all five |
| `git add $(git rev-parse --show-toplevel)` | bash | staged all five |
| `git add $PWD` | PowerShell | staged all five |
| `git add (Get-Location)` | PowerShell | staged all five |
| `git add $(git ls-files -mo)` | bash | staged all five |
| `git -c alias.aa='add -A' aa` | bash, PowerShell | staged all five |
| `git -c alias.aa=add aa .` | bash, PowerShell | staged all five |
| `git ls-files -m \| git update-index --stdin` | bash | staged all tracked |

An alias already set in a git config file would behave like the two alias rows. That was not
measured, because the throwaway repository ran with the user and system config switched off.

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

The guard's own comment used to list `--renormalize` as not reached, with `git add --renormalize .`
as the example. That example was already denied, by the pathspec rule. `git add --renormalize a.txt`
stages only `a.txt`. The comment now points here.

## Harmless commands the guard would refuse

A false deny is a defect of its own, because it is what gets a guard switched off. The corpus
held at least 100 harmless commands. The guard refuses at least these:

| Command | What git did | Since |
|---|---|---|
| `git commit -m . a.txt` | committed `a.txt` only | this change |
| `git commit --dry-run .` | committed nothing | this change |
| `git stash push -m commit -- .` | committed nothing | this change |
| `git add .>$null` in PowerShell | staged nothing; git got the pathspec `.>` | this change |
| `git -C sub add .` | staged only the files under `sub/` | before |
| `git add -A sub`, `git add -u sub` | staged only the files under `sub/` | before |
| `git add . ':!sub'` | staged only the files outside `sub/` | before |

Two notes on the rows this change added:

- **Row 1** is the price of the commit rule: an unquoted one-character message reads as a
  pathspec. Quoting the message avoids it.
- **Row 3** follows from matching the word `commit` wherever the subcommand is not `add` or
  `stage`. The guard's staging rule falls back to the bare word the same way, so that an option
  it does not know cannot hide the subcommand.

`tests/test_blanket_stage_guard.py` pins rows 1 and 3 as strict expected failures.
