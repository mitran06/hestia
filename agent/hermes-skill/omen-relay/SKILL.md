---
name: omen-relay
description: >-
  Run commands on the owner's TARGET machine (their laptop/host) from inside the
  confined box, through the Hestia capability broker. Use this whenever the owner
  asks you to do something on their computer — read/inspect a file or repo on the
  target, or (with the owner's approval) act on their private files. You CANNOT
  reach the target directly; this is the only path, and every crossing is gated by
  a Telegram button the owner taps. Invoke via the `hestia-relay` client.
---

# Relaying commands to the owner's target machine

You run inside `hestia-box`, a network-isolated container. You can reach the
public internet but you have **no key and no route** to the owner's target
machine. The only way to run anything there is to REQUEST it through the
`hestia-relay` client. The request goes to a host-side **broker** that shows the
owner a **Telegram button**; nothing runs on the target until the owner taps
approve. You can only ask — you cannot approve on the owner's behalf, and you
cannot bypass this. Do not try to.

## The client

```
hestia-relay [--cwd DIR] [--elevate] [--timeout SECONDS] -- CMD [ARG...]
```

- `-- CMD [ARG...]` — everything after `--` is the exact command and its
  arguments, run WITHOUT a shell on the target (no pipes, globs, `&&`, `$()` or
  redirection — those are shell features and will NOT work; pass a real argv).
  The `--` is important: it separates relay flags from the command.
- `--cwd DIR` — the working directory ON THE TARGET (default: `/srv/projects`).
- `--elevate` — HINT that you expect this needs the owner's private files. It is
  only a hint: the broker decides independently, and the owner sees an ELEVATED
  (red) button. Use it when you already know you're touching owner files.
- `--timeout SECONDS` — how long to wait for the owner's approval + result
  before giving up (default 900). Raise it if you expect the owner to be slow to
  tap, or the command to run long.

The relay blocks until the broker returns a result (or the timeout hits). The
command's stdout/stderr come back on the relay's stdout/stderr.

## Two zones — free vs. elevated

**Free zone (NO button).** Read-only inspection of the target's shared
workspace at `/srv/projects`. If, and only if, the command is a bare read-only
inspector (e.g. `ls cat head tail grep find wc stat file diff tree du` and
similar), with no elevation, and its cwd and every path argument stay inside
`/srv/projects`, the broker runs it automatically — no button, instant result.
This is for quick look-ups the owner has pre-blessed by design.

- Do NOT expect shells/interpreters (`bash sh python node`), `git`, or writers
  to run free-zone — those always need a button.
- Value-bearing flags must be SEPARATE tokens: use `-n 5`, not `-n5`; do not
  glue a path onto a flag (`--foo=/path`). Glued paths force a button or a
  reject.

```
# Free-zone examples (auto-run, no owner tap):
hestia-relay -- ls -la
hestia-relay --cwd /srv/projects/myrepo -- grep -rn "TODO" .
hestia-relay -- find . -name '*.md'
```

**Elevated (RED button).** Anything else — writing files, running a build or a
script, `git`, working outside `/srv/projects`, or touching the OWNER'S OWN
private files (e.g. their home directory). The owner sees a button showing the
exact argv and a hash; on approve, the command runs as the owner's own user on
the target (reaching their private files). Always pass `--elevate` when you know
you're in this zone, and tell the owner in chat what you're about to request and
why, so the button isn't a surprise.

```
# Elevated examples (owner must tap approve):
hestia-relay --elevate --cwd /home/<owner> -- ls -la Documents
hestia-relay --elevate --cwd /srv/projects/myrepo -- git status
hestia-relay --elevate --cwd /srv/projects/myrepo --timeout 1200 -- make build
```

## The approval flow (what to expect)

1. You run `hestia-relay -- ...`. It prints `submitted <id> … awaiting owner
   approval + result` to stderr and blocks.
2. Free-zone commands come back immediately. Otherwise the owner gets a Telegram
   button (first a SESSION button to open a time-boxed window, then per-command
   buttons). The owner taps approve or deny.
3. On approve, the target runs the command and the result (stdout/stderr/exit)
   comes back through the relay. On deny/timeout you get a non-zero exit and a
   short reason on stderr.

If the owner has not opened a session yet, the first request may prompt them to
approve opening the window before the command itself runs — that is normal.

## Exit codes (check these)

The relay's exit code tells you what happened. On success it mirrors the
command's own exit code; special codes signal broker outcomes:

| Exit | Meaning |
|------|---------|
| `0`  | command ran and exited 0 (success) |
| non-zero < 70 | command ran but exited non-zero (that's the command's own exit) |
| `77` | REFUSED — the owner tapped **Deny**, or the broker refused it (policy, caps, or auto-deny on timeout) |
| `78` | REJECTED — the request was malformed/invalid and rejected before any button |
| `75` | REVOKED — the session/approval was pulled mid-flight (owner hit 🛑) |
| `70` | broker/target ERROR while running |
| `124`| TIMEOUT — no result in time (owner never tapped, target offline, or still pending) |

Do not retry a `77` (denied/refused) by hammering the same command — the owner
said no or the policy blocked it. Surface it and ask the owner what they'd prefer
instead. A `78` means you sent a malformed request — fix the argv, don't resend
as-is. A `124` may just mean the owner was away; you can re-try once with a longer
`--timeout` after checking with them.

## Moving files / binary data

The relay carries a command and its text output — it is not a file-copy tool,
and the broker caps result size. For BINARY files or anything the owner needs
back verbatim, base64-encode on the target and decode in the box:

```
# Pull a file FROM the target back into the box (elevated if it's an owner file):
hestia-relay --elevate --cwd /home/<owner> -- base64 report.pdf > /tmp/report.b64
base64 -d /tmp/report.b64 > /home/hestia/report.pdf   # decode locally in the box
```

Keep it small — the broker truncates large output (you'll see a "(output
truncated by broker)" note on stderr). For big transfers, break the file into
chunks, or prefer the shared vault sync if one is configured.

## Delivering results back to the owner

The owner talks to you over your OWN Telegram bot (separate from the broker's
approvals bot). After a relayed command:

- Report plainly what you ran, what came back, and the exit status — including
  failures. Don't overstate success.
- If you fetched a file, hand it to the owner over your chat gateway (attach it,
  or paste the relevant text). Don't dump huge raw output; summarize and offer
  the full result.
- If a request was denied or timed out, say so and ask how they'd like to
  proceed — don't silently swallow it or loop on retries.
