---
name: target-relay
description: "Run commands on the owner's target machine, or fetch files from it, via the LIVE approval broker (hestia-relay). Open a work session and POLL until the owner approves it, then act within it. Commands may return PENDING too — poll them. Inside a session MOST commands run automatically — a reviewer checks each against your stated intent and only dangerous classes ask the owner. This is the ONLY way out of this box."
version: 3.1.0
author: Hestia Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [Broker, target, Laptop, Relay, Approval, Reviewer, Confinement, Session, hestia-relay]
    related_skills: []
---

# Reaching the target machine via the approval broker

**This is LIVE.** Ignore any memory that the broker is "not configured", that you are confined to
`/srv/projects`, that every command needs a tap, or that the relay "always times out" / "is broken".
Your shell is this box; the broker relays commands to the owner's target machine. There is no key and
no route here to bypass it. Never try.

**There is no `tui` verb.** You cannot drive interactive programs on the laptop. If a memory or an
older skill says you can, it is wrong — that feature was dropped and never shipped.

## NEVER INVENT RESULTS — read this first

Nothing here is instant. Approvals wait on a human. **Exit code 3 means PENDING, not failure, and
not success.** You have NOT done the work until you see the real output.

- **Never** describe what a command "would have" returned. Only report bytes you actually received.
- **Exit 124 means you got nothing.** Do not summarise, guess, or reconstruct the output.
- If a listing comes back **empty, that is a real answer** — say "nothing found". Do not invent
  filenames, paths, or file contents.
- If `session-status` never reaches 0, you did **not** do the work. Say exactly that and stop.
- If you cannot complete a task, report the exit code and what you were waiting on. A truthful
  "I could not do this" is always correct; a plausible invented answer is always wrong.

## Opening a session — YOU MUST POLL

**Nothing relays unless a session is OPEN.** A command with no open session is refused, not queued.

`session-open` does **not** wait for the owner. It submits and returns immediately, because your
own terminal tool kills any command at ~120s and the owner may take minutes to tap.

```bash
hestia-relay session-open --intent "back up my resume and photos" --duration 900
```

Read the exit code:

| Code | Meaning | What you do |
|---|---|---|
| **0** | owner already tapped Approve | start working |
| **3** | **PENDING — normal, not an error** | poll `session-status` |
| 77 | denied | stop; tell the owner |
| 2 | bad arguments | fix and retry |

If you got **3**, poll until it resolves:

```bash
hestia-relay session-status
```

| Code | Meaning | What you do |
|---|---|---|
| **0** | session OPEN (prints seconds left) | start working |
| **3** | still pending | wait a few seconds, poll again |
| 77 | denied | stop; tell the owner |
| 75 | revoked | stop |
| 124 | expired | open a NEW session |
| 1 | no session at all | run `session-open` first |

**`session-status` itself waits up to ~90 seconds before answering.** So:

- Call it **exactly once per command invocation**. It is not instant.
- **Never** chain it (`for … do … done`), **never** put `sleep` before it, **never** run it twice in
  one command. Any of those exceed your own ~120s limit and the command gets killed.
- One call, read the code, act. If it returns 3, call it once more as a separate command.

If it is still pending after two or three such polls, tell the owner you are waiting on their tap
and stop — do not spin.

Close as soon as you are done. After this you have **no access** until a new session is approved:

```bash
hestia-relay session-close
```

## Working inside a session

```bash
hestia-relay [--cwd DIR] [--elevate] [--timeout SECONDS] -- COMMAND [ARG...]
```

Real argv — **no shell, no pipes, no globs, no `$()`**. Blocks until the result returns, prints the
command's stdout, and mirrors its exit code. Default cwd is the owner's home; pass `--cwd` to change
it. State honest, specific intents — the reviewer matches commands against them.

- **Most commands auto-run, no tap.** Reads anywhere, `mkdir`, `mv`/`cp`, scripts and interpreters,
  read-only and inbound git — if they fit your stated intent. You are not limited to one folder.
- **Auto-approved commands run CONFINED: full file access, NO NETWORK.** Anything needing the
  internet — `git fetch`/`clone`/`pull`, `npm`/`pip install`, `curl`, a build that downloads — will
  **fail with a network error**. That is expected. Re-request the SAME command with `--elevate`.
- **One tap is asked for the dangerous classes:** sending data OUT (`curl`/`wget`/`scp`/`rsync`
  to remote/`git push`), reading secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, `*.pem`),
  `sudo`/root, persistence (`crontab`, systemd units, shell rc files), `rm -rf` of home or large
  trees. These never auto-run.
- **Destructive-but-scoped** (`rm` a file, overwriting) auto-runs only if it clearly matches your
  intent, else it asks.

**`--elevate` = one owner tap, then run UNCONFINED (full access AND network).** Use it for the
legitimate cases that fail confined. It never bypasses the hard floor — a secret read or `sudo`
still needs its own approval; it only lifts the no-network confinement.

**Commands ALSO return 3 (pending) — poll them the same way.** Auto-approved commands usually come
back within seconds, but anything that needs a tap (`--elevate`, secrets, `sudo`, egress, `rm -rf`)
waits on the owner. When you get 3:

```bash
hestia-relay command-status      # same rules: ONE call, waits up to ~90s, 3 = poll again
```

`command-status` prints the command's real output and returns its real exit code once the result
arrives. Until then you have no output — do not invent any.

Command exit codes: **0** ran · **3** pending (poll `command-status`) · **77** denied/refused ·
**78** malformed · **75** revoked · **70** broker/internal error · **124** timed out or target
offline · **1** no pending command / submit failed. A network failure inside a confined auto-run
shows up as the command's OWN nonzero exit plus a network error in stderr — that is your cue to
retry with `--elevate`, not a broker failure.

**Do not pass a large `--timeout`.** The relay caps its own wait anyway; a big value just gets your
command killed. Leave it unset and poll `command-status`.

Every command you run is shown to the owner live, one line in the session message.

## Getting a file from the target to the owner

- Text: `hestia-relay -- cat $OWNER_HOME/Documents/report.txt`
- Find it: `hestia-relay -- find $OWNER_HOME -maxdepth 3 -iname '*resume*' -not -path '*/.cache/*'`
- **Binary under ~35 KB** — base64 so bytes survive:
  ```bash
  hestia-relay -- base64 $OWNER_HOME/photo.jpg > /tmp/photo.b64
  base64 -d /tmp/photo.b64 > /tmp/photo.jpg
  ```
- **Larger than ~35 KB:** one result is capped (~50 KB stdout). Split on the target into `/tmp`, read
  the chunks back (all auto-approved), concatenate here. See `references/large-file-transfer.md`.

Then **deliver it to the owner** over Telegram. The relay only fetches; you send it on.

## Pitfalls

- **No shell/PTY:** `vim`, `nano`, `htop`, `fzf` hang. Use `find`/`ls`/`grep -r`. You cannot drive them.
- **Exclude noise** on broad searches: `-not -path '*/.cache/*' -not -path '*/.config/*' -not -path
  '*/.local/*' -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/snap/*'`.
- **Empty output is a real answer.** If a listing comes back empty, say so. Do NOT invent filenames,
  paths, or file contents you did not receive from a command. If you could not get something, report
  the exit code and stop.
- **Reading a secret zone** (`~/.ssh`, `.env`, `*.pem`) asks the owner even for a read. Don't route
  secrets into memory, notes, or the vault; only fetch them if the owner asked for that file.

## Etiquette

- One session per task: open, poll to 0, work, close.
- If a command needs the network and fails confined, retry once with `--elevate`. Do not loop.
- If denied, refused, revoked, or timed out: report it plainly and stop. No retry loops, no bypass
  hunting. Need broader scope? Close and open a new session with an honest new intent.
- `hestia-relay` only reaches the target. For anything on THIS box, use your normal shell.
