# The capability broker (Phase 2, in depth)

This is the reference for the protocol and the policy. The runtime code is `broker/broker.py` (pure policy engine), `broker/brokerd.py` (daemon: Telegram + sessions + relay + elevation), `broker/mover.sh` (the dumb pipe), and on the target `target/exec-argv` + `target/exec-argv-elevated`.

## Request schema

The agent (via `hestia-relay`) writes a JSON object named `<request_id>` (a UUID) to its outbox:

```json
{ "v": 1,
  "session_id": "<uuid>",
  "request_id": "<uuid>",     // MUST equal the filename
  "cwd": "/srv/projects/...",  // absolute
  "elevate": false,            // a HINT only; the broker decides independently
  "argv": ["ls", "-la"] }      // list of strings, non-empty, no NUL
```

The broker **validates** strictly (exact key set, `v==1`, `request_id`==filename, `cwd` absolute, `argv` non-empty list of NUL-free strings, total size ≤ 64 KiB). Anything else is **REJECT** (dropped + audited). `elevate` from the box is only a hint — the broker classifies on its own.

## Canonicalization and binding (anti-swap / TOCTOU)

The broker turns the request into a canonical byte string using **length-prefixed** fields (`session_id`, `request_id`, `cwd`, `elevate`, each `argv[i]`), then `cmd_hash = sha256(canon)`. Length-prefixing means delimiters and NULs can't be injected to make two different commands collide:

- `["ls","-la"]` and `["ls -la"]` hash **differently**.
- `["ab",""]` and `["a","b"]` hash **differently**.

The broker reads the box file **once**, unlinks the box-side copy, keeps the validated request in memory, and **never re-reads it**. At approval/dispatch it re-computes `cmd_hash` and re-derives the decision; any drift → refuse. So *what executes equals what was hashed and shown on the button.* Mutating the box file after you approve has no effect.

## Classification: free-zone vs button

The classifier is **default-DENY-to-button**. A command auto-runs (IN_SCOPE / free-zone) **only** if all hold:

1. **not** `elevate`;
2. `argv[0]` is a bare name (no `/`) on the read-only inspector allowlist — e.g. `ls cat head tail wc stat file find grep tree pwd du diff uniq cut basename dirname realpath echo date uname sha256sum md5sum cksum nl column`;
3. every flag passes the **strict per-binary flag policy** (below);
4. `cwd` and every path operand resolve inside `/srv/projects` (the authoritative, symlink-resolving check runs on the target).

Everything else is **NEEDS_BUTTON**: interpreters/shells (`bash -c`, `python`, `node`…), writers (`cp mv ln tee dd`…), `git`, `rg`, `sort`, `env`, `sudo/ssh/docker/systemctl`, any out-of-workspace path, or `elevate`.

### The flag policy (why an allowlisted binary still isn't a blank cheque)

Allowlisting a binary as "read-only" is unsafe without auditing its flags — several read tools can be turned into arbitrary exec or write via a flag. So:

- an **unlisted** binary allows **no** flags;
- short clusters (`-la`) must be all safe letters for that binary;
- long flags (`--color`) must be explicitly listed;
- **any** `=`, `@`, a glued path (`-f/etc/passwd`), or an unlisted flag → button;
- value-flags must be separate tokens (`-n 5`, never `-n5` — the glued form buttons, conservatively);
- `find` additionally buttons on `-exec/-execdir/-delete/-fprintf/-fls/-ok…`.

This is why `rg --pre=…` (arbitrary exec) and `sort -o FILE` (arbitrary write) are **not** in the free-zone at all, and `grep --file=/etc/passwd` / `-f /etc/passwd` button.

## Sessions and the human gate

State machine: `IDLE → (you approve a session) OPEN[t0, t0+dur] → EXPIRED / REVOKED / CLOSED`.

- Free-zone commands auto-run **only while a session is open**. While idle, even a free-zone command triggers a **session** button first.
- The window duration is **frozen server-side** at approval; no message can extend it. Expiry is checked on **both** a monotonic and a wall-clock deadline (closes at the earlier — safe against NTP steps).
- A per-window **command budget** and a **pending-button cap** bound approval-fatigue and flooding.
- **Restart = fail-closed:** state is purely in-memory, so a crashed/restarted broker resumes nothing; all nonces die with their session.

Telegram specifics: long-poll `getUpdates` (no inbound port); only updates from your `OWNER_ID` are honored; each button carries a **single-use nonce** consumed by compare-and-set on the first tap (replays → "already handled", no second run); unanswered buttons **auto-deny** at timeout. Buttons show the exact `cwd`, `argv` (as one JSON line), and `hash` prefix, with a header:

- 🟡 **session** — opens a work window; sensitive commands still ask separately;
- 🔵 **needs approval** — runs as `hestia-agent` (cannot read your files), outside the sandbox;
- 🔴 **elevated** — runs as **you**, full owner-file access, outside the sandbox.

A persistent **🛑 Revoke** button (and `/panic` / `/revoke`) closes the session, kills every in-flight command (locally and on the target), and denies all pending.

## The target executor

`exec-argv` (invoked by the broker over Tailscale SSH, as `hestia-agent`) decodes a base64 JSON payload `{cwd, argv, workspace_only, exec_token?}` and:

- **free-zone** (`workspace_only=true`): independently re-checks `argv[0]` is bare + allowlisted, `cwd` + operands realpath inside `/srv/projects`, then runs the command inside a **bubblewrap jail** where only `/srv/projects` is visible — so a recursive tool that follows an in-workspace symlink pointing out finds nothing. If bubblewrap is unavailable it **refuses** (fail-closed) rather than run unjailed.
- **approved** (`workspace_only=false`): the owner approved this exact command, so no workspace restriction — but it still runs as `hestia-agent`, DAC-fenced from your private files.

Execution is always `os.execvpe` (no shell) with a scrubbed, minimal environment (drops `LD_PRELOAD`, `BASH_ENV`, `IFS`, …). Each command runs in its own process group with a pidfile so `exec-argv --kill <uuid>` can terminate the whole tree (revoke).

## Elevation (reaching your own files)

Some tasks need to touch files only *you* can read (e.g. building a document in your home). That is a separate, HMAC-gated path.

`target/exec-argv-elevated` is a root wrapper (one narrow NOPASSWD sudoers line, no argument wildcard). It runs an approved command **as your own unix user** only when presented a **broker-signed ticket**:

```
ticket   = base64(json({v, action, session_id, request_id, cwd, run_as, argv, exec_token, issued, sig}))
sig      = HMAC-SHA256(key, json.dumps(ticket_without_sig, sort_keys=True, separators=(',',':')))
```

The shared `key` lives only on the broker host and the target (root `0400`). Defences, all fail-closed:

- **HMAC** — unforgeable without the key (a host-local process reaching the target's SSH still can't mint one);
- **TTL** — a ticket older than 300 s is rejected;
- **single-use marker** on a non-tmpfs path — no cross-reboot replay;
- **caller check** — only `hestia-agent` may invoke it;
- **run-as allowlist** — only your configured owner user (never root);
- **permanent `setresuid/setresgid` drop** before `execvpe` — no path back to root;
- **signed kill-ticket** for revoke (the unprivileged agent can't signal a process running as you).

The broker only ever sends an elevated ticket for a command **you approved on a 🔴 button**, and it will never elevate a free-zone command (binding refuses `elevated + IN_SCOPE`).

## Results

The broker returns `{request_id, status, exit, stdout, stderr, truncated?}` to the agent's inbox, budgeted to fit under the mailbox cap on **encoded** length (non-ASCII/binary can't silently blow the limit and drop the reply). `status` is one of:

| `status` | meaning | `hestia-relay` exit |
|---|---|---|
| `executed` | ran; `exit` is the command's own code | the command's exit code |
| `refused` | owner denied, or policy/binding/cap refusal (incl. auto-deny on timeout) | 77 |
| `rejected` | malformed/invalid request, rejected before any button | 78 |
| `revoked` | session/approval pulled mid-flight (🛑) | 75 |
| `timeout` | no result in time (relay-side) | 124 |
| `error` | broker/target error while running | 70 |
