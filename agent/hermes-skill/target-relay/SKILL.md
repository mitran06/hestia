---
name: target-relay
description: "Use when acting on the owner's target machine from inside this box — running a command there, reading or fetching a file. Also use when a relay call returns an exit code you did not expect, or appears stuck."
version: 4.0.0
author: Hestia Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [Broker, target, Laptop, Relay, Approval, Session, hestia-relay]
    related_skills: []
---

# Reaching the target machine

`hestia-relay` is your one route to the owner's laptop. It is live and working. Your shell stays in
this box; the relay carries argv to the target and brings the result back.

Two things override anything you remember to the contrary: **the broker is configured and running**,
and **you act as the owner across their whole filesystem** — the old `/srv/projects` fence is gone.
Interactive programs stay out of reach: drive the laptop with commands that run and exit.

## Receipts

Every claim you make about the laptop traces to bytes a command returned **this session**. That is
your receipt. Say what your receipts support, and name the gap where you have none.

| What you have | What you say |
|---|---|
| output from a command | the output |
| an empty listing | "nothing found there" |
| exit 3 | "waiting on your approval" — then poll |
| exit 124 | "I got nothing back" — plus what you were waiting on |
| exit 77 | "that was denied" — and stop |
| a plan you never ran | what you intend to run, marked as intended |

When you cannot finish, report the exit code and what stopped you. A plain "I could not do this" is
a complete, correct answer.

## Open a session

Nothing relays until a session is open.

```bash
hestia-relay session-open --intent "<one honest line>" --duration 900
```

Your intent is what the reviewer matches commands against, so make it describe the work you are
about to do. Read the exit code:

| Code | Meaning | Next |
|---|---|---|
| **0** | open | start working |
| **3** | PENDING — the owner has not tapped yet | poll `session-status` |
| 77 | denied | stop; tell the owner |
| 2 | bad arguments | fix and retry |

```bash
hestia-relay session-status
```

| Code | Meaning | Next |
|---|---|---|
| **0** | open, prints seconds left | start working |
| **3** | still PENDING | poll again next turn |
| 77 / 75 | denied / revoked | stop |
| 124 | expired | open a new session |
| 1 | no session yet | run `session-open` |

**`session-status` takes up to ~90 seconds to answer.** Give it a whole command to itself and read
the code it returns. If it is still PENDING after two or three polls, tell the owner you are waiting
on their tap and stop there.

Close when the work is done. Access ends immediately:

```bash
hestia-relay session-close
```

## Run commands

```bash
hestia-relay [--cwd DIR] [--elevate] -- COMMAND [ARG...]
```

Real argv — the command runs directly, so pipes, globs and `$()` arrive as literal text. Default cwd
is the owner's home. Leave `--timeout` alone; the relay caps its own wait.

Most commands run automatically, with no tap: reads anywhere, `mkdir`, `mv`/`cp`, scripts and
interpreters, read-only and inbound git — when they fit your stated intent.

**Auto-approved commands run with the filesystem but without the network.** Anything that reaches
the internet — `git fetch`/`clone`/`pull`, `npm`/`pip install`, `curl`, a build that downloads —
comes back with a network error. That is the expected result, and the fix is to re-request the same
command with `--elevate`.

**`--elevate` buys one owner tap and full network access.** The owner sees the exact command. Use it
for the network cases above, and expect a tap for: sending data out (`curl`/`scp`/`rsync`/`git push`),
reading secrets (`~/.ssh`, `~/.aws`, `.env`, `*.pem`), `sudo`, persistence (`crontab`, systemd, shell
rc files), and `rm -rf` of home or a large tree. Fetch a secret only when the owner asked for that
file, and keep it out of memory, notes and the vault.

Commands return the same codes as sessions, plus **0** for a clean run and the command's own exit on
failure. Exit **3** means the same thing here: poll for it.

```bash
hestia-relay command-status
```

One call per turn, same as `session-status`. It prints the real output and the real exit code once
the result lands.

## Searching the laptop

Widen a search, then narrow it from what comes back.

- Prune noise on broad searches: `-not -path '*/.cache/*' -not -path '*/.config/*' -not -path
  '*/.local/*' -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/snap/*'`
- Found one document? `ls -lhS` its parent — related papers usually sit together.

## Fetching a file to the owner

Small text comes straight back: `hestia-relay -- cat $OWNER_HOME/Documents/report.txt`.

Binaries and anything past ~35 KB need staging and chunking — the recipe, the size maths and a
ready-made script live in `references/large-file-transfer.md`. Read it when you are moving a file.

Once you hold the bytes, deliver them to the owner over Telegram. The relay fetches; you send.

## Etiquette

One session per task: open, poll to 0, work, close. Most commands are tap-free, so the owner only
hears from you for `--elevate` and the classes above — spend those sparingly. A denial, a revoke or
a timeout is a final answer: report it and stop. Need wider scope than your intent covers? Close,
and open a new session with an honest new one.
