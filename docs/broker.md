# The capability broker (Phase 2, in depth)

This is the reference for the protocol and the policy. The runtime code is `broker/broker.py` (the pure policy-tier engine), `broker/reviewer.py` (the fail-closed LLM reviewer), `broker/brokerd.py` (daemon: Telegram + sessions + reviewer + preflight + confined relay), `broker/mover.sh` (the dumb pipe), and on the target the HMAC-ticketed `target/exec-argv-elevated` (which runs commands confined or unconfined per the ticket).

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

The broker **validates** strictly (exact key set, `v==1`, `request_id`==filename, `cwd` absolute, `argv` non-empty list of NUL-free strings, total size ≤ 64 KiB). Anything else is **REJECT** (dropped + audited). `elevate` from the box is only a hint — the deterministic floor never depends on it (see below), and it can only route a *middle* command to a human tap; it can never lower the floor.

## Canonicalization and binding (anti-swap / TOCTOU)

The broker turns the request into a canonical byte string using **length-prefixed** fields (`session_id`, `request_id`, `cwd`, `elevate`, each `argv[i]`), then `cmd_hash = sha256(canon)`. Length-prefixing means delimiters and NULs can't be injected to make two different commands collide:

- `["ls","-la"]` and `["ls -la"]` hash **differently**.
- `["ab",""]` and `["a","b"]` hash **differently**.

The broker reads the box file **once**, unlinks the box-side copy, keeps the validated request in memory, and **never re-reads it**. At approval/dispatch it re-computes `cmd_hash` and re-derives the decision; any drift → refuse. So *what executes equals what was hashed and shown on the button.* Mutating the box file after you approve has no effect.

## The policy-tier floor (Layer 1)

Every request is scored by `policy_tier()` — a deterministic, pure function of `{argv, cwd}` that returns one tier, evaluated in **strict priority** order (the first that matches wins):

**`REFUSE > HARD_DENY > FREE_ZONE > SOFT_DENY > ALLOW`**

| Tier | What it is | Disposition |
|---|---|---|
| **REFUSE** | catastrophic hardline — `rm -rf ~`/`/`, `poweroff`/`reboot`, and similar | never runs; **no button** exists to approve it |
| **HARD_DENY** | intent-proof danger — outbound egress, a secret/credential zone, the broker's own files, sudo/root, persistence (units/cron/shell-rc), or `rm -rf` of a tree under `$HOME` | always a **human tap** (🔴); the reviewer never sees it; unconfined on approve |
| **FREE_ZONE** | a read-only inspector (`ls cat head tail wc stat file find grep tree pwd du diff …`) with safe flags, on a **non-secret** path | **auto-runs** (no LLM), confined, while a session is open |
| **SOFT_DENY** | destructive-but-recoverable — delete / overwrite / reset | the **reviewer** may unlock it only for the *same operation on the same target* the intent names; else a tap (🔵) |
| **ALLOW** | the default middle — writers, `git`, inline interpreters (`python -c`, `sed -i`…), path-invoked binaries | the **reviewer** may auto-run it if in-intent; else a tap (🔵) |

The floor is the **sole floor authority** and runs *first*. `REFUSE`/`HARD_DENY` are absolute — neither the reviewer nor the box's `elevate` lever can lower them. Note the tier is a pure function of `{argv, cwd}` only: it deliberately does **not** depend on `elevate`, so an escalation-lever command and its ordinary twin (same argv/cwd) share a tier; the lever only changes *where the middle goes* (see Sessions, below). The `/srv/projects` workspace containment that once gated the free-zone is retired — FREE_ZONE now means "a read-only inspector on a non-secret path anywhere", because the runtime confinement (below) is what stops out-of-workspace reads, not a lexical path gate.

## The reviewer (Layer 2)

`FREE_ZONE`, `SOFT_DENY`, and `ALLOW` are the only tiers that can auto-run. A `FREE_ZONE` inspector auto-runs with no LLM; the `SOFT_DENY` / `ALLOW` **middle** is judged by a **second, independent LLM reviewer** (`broker/reviewer.py`) against the operator-stamped **session intent**:

- It is **fail-closed** and can only ever *tighten*: a sole clean `<decision>ALLOW</decision>` removes the tap (auto-run, confined); **everything else** — a `BLOCK`, prose, an empty answer, a timeout, an HTTP error, the reviewer disabled or unconfigured — falls the command to your tap. It can never lower the floor.
- It sees only `{intent, argv, cwd}` as escaped, fenced **DATA** — never as instructions. `SOFT_DENY` gets a stricter *same-operation-same-target* prompt variant; the other middle tiers get the default-allow variant.
- **Transport resilience:** a transient blip is retried a bounded number of times before failing closed; a **circuit breaker** opens after N consecutive reviewer failures (then every middle command goes straight to a tap) and half-opens after a cooldown to probe recovery; a **concurrency cap** (`HESTIA_MAX_REVIEWS`) sends excess in-flight reviews to a tap rather than queueing. Base reasoning effort is `"none"`; the `SOFT_DENY` tier may opt into a bigger thinking budget (tier-adaptive thinking).
- The reviewer's key is a **secret** — it lives only in the broker's `0600` EnvironmentFile, never in `config/hestia.env`.

If the reviewer is disabled, or the auto-run preconditions are otherwise unmet (see the target executor, below), **every** middle command fails closed to your tap. The reviewer is off by default (`HESTIA_REVIEWER_ENABLED=0`).

### The flag policy (how a FREE_ZONE inspector is recognized)

Allowlisting a binary as "read-only" is unsafe without auditing its flags — several read tools can be turned into arbitrary exec or write via a flag. So:

- an **unlisted** binary allows **no** flags;
- short clusters (`-la`) must be all safe letters for that binary;
- long flags (`--color`) must be explicitly listed;
- **any** `=`, `@`, a glued path (`-f/etc/passwd`), or an unlisted flag → button;
- value-flags must be separate tokens (`-n 5`, never `-n5` — the glued form buttons, conservatively);
- `find` additionally buttons on `-exec/-execdir/-delete/-fprintf/-fls/-ok…`.

This is why `rg --pre=…` (arbitrary exec) and `sort -o FILE` (arbitrary write) do **not** qualify as a FREE_ZONE inspector (they fall to the middle → the reviewer), and `grep --file=/etc/passwd` / `-f /etc/passwd` likewise drop out of FREE_ZONE.

## Sessions and the human gate

State machine: `IDLE → (you approve a session) OPEN[t0, t0+dur] → EXPIRED / REVOKED / CLOSED`.

- Commands run **only while a session is open** — the auto tiers auto-run, the rest button. While idle, the broker asks you to open a **session** first; opening one stamps the operator's **session intent** (the trusted anchor the reviewer judges against).
- The window duration is **frozen server-side** at approval; no message can extend it. Expiry is checked on **both** a monotonic and a wall-clock deadline (closes at the earlier — safe against NTP steps).
- A per-window **command budget**, a **pending-button cap**, and an **exfil cap** (`HESTIA_EXFIL_CAP_N` — the N+1th *distinct* auto-approved command per window falls to a tap) bound approval-fatigue, flooding, and runaway auto operations.
- **The `elevate` lever.** The box may set `elevate` on a *middle* (`ALLOW`/`SOFT_DENY`) request to ask for it to run **unconfined** as you (e.g. it needs network or your private files). This is re-admitted as a non-security request: it only re-routes the command to a **human tap** — it never lowers the floor and never touches a HARD_DENY/REFUSE command.
- **Restart = fail-closed:** state is purely in-memory, so a crashed/restarted broker resumes nothing; all nonces die with their session.

Telegram specifics: long-poll `getUpdates` (no inbound port); only updates from your `OWNER_ID` are honored; each button carries a **single-use nonce** consumed by compare-and-set on the first tap (replays → "already handled", no second run); unanswered buttons **auto-deny** at timeout. Buttons show the exact `cwd`, `argv` (shell-rendered for legibility; the hash binds the true bytes), and `hash` prefix. Every executing outcome runs as **you** (the owner unix user); the header conveys the **risk class**, not an identity choice:

- 🟡 **session** — opens a work window; each sensitive command still asks separately;
- 🔴 **deterministic floor** — a HARD_DENY rule fired (the button names *which*: egress, secrets, sudo, persistence, …); unconfined on approve;
- 🔵 **reviewer escalation** — a middle command the reviewer flagged off-intent (or the `elevate` lever); it carries the reviewer's one-line reason; unconfined on approve.

A persistent **🛑 Revoke** button (and `/panic` / `/revoke`) closes the session, kills every in-flight command (locally and on the target), and denies all pending.

## The target executor

Every relayed command runs on the target through **one** HMAC-ticketed wrapper, `target/exec-argv-elevated`, as **your own unix user**. (The legacy `hestia-agent` run identity is retired.) The ticket carries a strict-bool **`confined`** flag that decides the runtime jail:

- **`confined=true`** (every auto-run: a FREE_ZONE inspector or a reviewer-approved middle command): the command runs inside a **bubblewrap jail** — full filesystem (`--bind / /`), but with the **network unshared** (`--unshare-net`) and PID/IPC/UTS isolated (`--unshare-pid` …), and the persistence dotfiles (shell/login rc-files) **read-only-bound** so a confined run cannot plant a payload that later executes unconfined-with-network (a delayed-exfil bypass). The network isolation — not a filesystem path gate — is the load-bearing anti-exfil boundary. If bubblewrap or unprivileged user namespaces are unavailable, the broker fails **closed** (auto-run is disabled; every command asks) rather than run unjailed.
- **`confined=false`** (an owner-tapped command — you explicitly approved it on a 🔴 or 🔵 button, or via the `elevate` lever): it runs unconfined, with your full network and file access.

The wrapper validates the ticket fail-closed before running: **HMAC** signature (unforgeable without the broker's key), a **TTL** (a ticket older than 300 s is rejected), a **single-use marker** on a non-tmpfs path (no cross-reboot replay), a **caller check** (only the SSH-reaching user may invoke it), a **run-as allowlist** (only your configured owner user, never root), and a strictly-bool **`confined`** field. It then does a **permanent `setresuid/setresgid` drop** to you before `os.execvpe` (no shell, scrubbed minimal env — drops `LD_PRELOAD`, `BASH_ENV`, `IFS`, …; `bwrap` runs *after* the uid-drop as an unprivileged user namespace). Each command runs in its own process group with a pidfile so a broker-minted, HMAC-signed **kill ticket** can tear down the whole tree on revoke.

## The elevation ticket (the HMAC capability)

Because every command runs as your own unix user, the wrapper is only invocable with a **broker-signed ticket** — the unforgeable capability the box cannot mint. `target/exec-argv-elevated` is a root wrapper (one narrow NOPASSWD sudoers line, no argument wildcard) whose payload is:

```
ticket   = base64(json({v, action, session_id, request_id, cwd, run_as, argv, exec_token, confined, issued, sig}))
sig      = HMAC-SHA256(key, json.dumps(ticket_without_sig, sort_keys=True, separators=(',',':')))
```

The shared `key` lives only on the broker host and the target (root `0400`). Defences, all fail-closed (see also the target-executor section above):

- **HMAC** — unforgeable without the key (a host-local process reaching the target's SSH still can't mint one);
- **TTL** — a ticket older than 300 s is rejected;
- **single-use marker** on a non-tmpfs path — no cross-reboot replay;
- **caller check** — only the broker's SSH-reaching user may invoke it;
- **run-as allowlist** — only your configured owner user (never root);
- **strict-bool `confined`** — decides the runtime jail (see above); a signed-but-malformed value is refused, so a run can never silently drop confinement;
- **permanent `setresuid/setresgid` drop** before `execvpe` — no path back to root;
- **signed kill-ticket** for revoke (an unprivileged caller can't signal a process running as you).

The `confined` flag is decided by the approval **path** in the broker — `true` for every auto-run, `false` for an owner tap — and is bound into the ticket; the target never recomputes it, and the broker re-derives the tier at dispatch and refuses on any drift.

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
