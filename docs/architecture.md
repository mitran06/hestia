# Architecture

Hestia has two layers:

1. **Confinement (Phase 1)** — the agent runs inside an unprivileged LXD container that can reach the public internet and nothing else. See [confinement.md](confinement.md).
2. **The capability broker (Phase 2)** — the single, gated path from that confined agent to your laptop/host. Every crossing requires a **Telegram button pressed by you**, enforced *outside* the language model. This document describes Phase 2.

The design principle: **the component that can be prompt-injected holds no key and no route.** A hijacked agent can *ask* to do something; it cannot make it happen. Only a physical tap on your phone can.

---

## The five trust domains

Each box below is a separate unix user (or machine) with a strict privilege fence. No single one holds both the secrets and the ability to reach your machines.

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  UNTRUSTED (assumed prompt-injectable)                                   │
  │                                                                         │
  │   [ Agent ]  user `hestia`, inside the LXD box                          │
  │      │  writes an opaque request file to  ~/broker/outbox/<uuid>        │
  │      │  (holds NO key, NO route — firewalled to internet-only)          │
  └──────┼──────────────────────────────────────────────────────────────────┘
         │  LXD mailbox (lxc file) — NOT a network socket, no firewall hole
         ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  [ Mover ]  user `hestia-mover`  (group: lxd only)                      │
  │     a DUMB PIPE: shuttles opaque, UUID-named, ≤64 KiB blobs between the │
  │     box mailbox and the host spool. Parses NO content, makes NO policy. │
  └──────┼──────────────────────────────────────────────────────────────────┘
         │  files on the host spool  /var/lib/hestia-spool/{incoming,outgoing}
         ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  [ Broker ]  user `hestia-broker`  (NO lxd, NO docker, NO sudo)         │
  │     THE BRAIN. Validates schema → canonicalizes → sha256 cmd_hash →     │
  │     classifies (free-zone / needs-button / reject) → append-only audit. │
  │     Holds the approvals-bot token + the elevation HMAC key.             │
  └───┬───────────────────────────────────────────────┬─────────────────────┘
      │  Telegram Bot API (long-poll; owner-id filter) │  Tailscale SSH
      ▼                                                ▼
  ┌───────────────────────┐              ┌──────────────────────────────────┐
  │  [ Owner ] YOU, on    │              │  [ Target ] user `hestia-agent`  │
  │  Telegram.            │              │  on your laptop/host. No sudo of  │
  │  The ONLY approver.   │              │  its own; DAC-fenced from your    │
  │  [Approve] [Deny]     │              │  files. `/srv/projects` free-zone.│
  │  [🛑 Revoke]          │              │  exec-argv (+ bubblewrap jail);   │
  └───────────────────────┘              │  exec-argv-elevated (HMAC-gated). │
                                         └──────────────────────────────────┘
```

| Domain | Runs as | Holds | Can it be injected? | Fence |
|---|---|---|---|---|
| **Agent** | `hestia` (in the box) | nothing | **Yes** (assumed) | firewalled to internet-only; can only write its outbox |
| **Mover** | `hestia-mover` (host) | no secrets, no policy | no (parses nothing) | group `lxd` only; moves opaque bounded blobs |
| **Broker** | `hestia-broker` (host) | bot token, HMAC key | no (never runs box data as code) | **no** lxd/docker/sudo |
| **Owner** | you, on Telegram | the trust anchor | no | you read the argv + hash before tapping |
| **Target** | `hestia-agent` (laptop) | nothing | no | no sudo; DAC-fenced; free-zone jailed |

---

## Invariants

These are the load-bearing properties. If any is violated, the model is broken.

- **INV-1 — separation of route and secret.** The process with `lxd` (the mover) holds no secrets and makes no decisions. The process with the secrets and the policy (the broker) has no `lxd`/`docker`/`sudo`. Neither runs as you.
- **INV-2 — the box has no path out except the mailbox.** The container is firewalled to the public internet only (v4 + v6). It cannot reach the host, the LAN, or the tailnet — so it cannot invoke the broker, reach the target directly, or exfiltrate over the tailnet. The only crossing is opaque files the mover shuttles.
- **INV-3 — approval is enforced outside the LLM.** The Telegram button lives on a *second* bot whose token is on the host only. The agent cannot press it, cannot see it, and cannot forge it. Auto-run is confined to a narrow, read-only "free-zone" (see below); everything else waits for your tap.
- **INV-4 — what executes equals what you approved.** The broker canonicalizes each command with length-prefixed fields, hashes it (`cmd_hash`), and runs its **own stored copy** — it never re-reads the box file after deciding. The button shows the argv and hash prefix; the hash is re-checked at dispatch. Mutating the request after approval does nothing (TOCTOU-proof).
- **INV-5 — elevation is an unforgeable, broker-held capability.** Running a command *as you* (reaching your private files) requires a broker-signed HMAC ticket that is single-use and TTL-bound. A host-local process that reaches the target's SSH still cannot elevate without the key.

---

## Request lifecycle

1. **Agent** builds a request `{v, session_id, request_id, cwd, elevate, argv[]}` and writes it to its outbox as `<request_id>.tmp`, then atomically renames to `<request_id>` (a UUID). It has no other capability.
2. **Mover** pulls the blob to the host spool (validates only: filename is a UUID, size ≤ 64 KiB; bounded batch per tick). It parses nothing else.
3. **Broker** reads it once, unlinks the box-side copy, validates the schema (or **REJECT**), canonicalizes + hashes, and **classifies**:
   - **IN_SCOPE (free-zone)** — a read-only inspector (`ls`, `cat`, `grep`, `find`, …) with safe flags, `cwd` and every path inside `/srv/projects`, not elevated. Auto-runs **only while a session is open**, inside a bubblewrap jail on the target.
   - **NEEDS_BUTTON** — anything else: interpreters/shells, writers, `git`, out-of-workspace paths, or `elevate`. The broker sends you a button.
   - **REJECT** — malformed/oversize/non-UUID. Dropped and audited.
4. **Owner** sees the exact argv, cwd, and hash prefix, and a color-coded header (🟡 session / 🔵 needs-approval / 🔴 elevated). You **Approve** or **Deny**. Unanswered → auto-deny.
5. On approve, the **broker** re-checks the hash + re-derives the decision (binding), then relays over **Tailscale SSH** to the target's `exec-argv` (normal) or `exec-argv-elevated` (HMAC-ticketed). Execution is always `shell=False`.
6. The **result** (bounded, ≤ mailbox cap) goes back to the spool → mover → the agent's inbox. The agent reads it and can deliver it to you (e.g. on its own Telegram bot).

Every step is written to an **append-only audit log** (`chattr +a`) the agent cannot reach or rewrite.

See [broker.md](broker.md) for the protocol details, the free-zone policy, and the elevation ticket format; [security-model.md](security-model.md) for the threat model and residual risks.
