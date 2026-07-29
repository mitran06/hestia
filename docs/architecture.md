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
  │     policy_tier() deterministic FLOOR → fail-closed LLM reviewer for    │
  │     the middle → append-only audit. Holds the approvals-bot token, the  │
  │     elevation HMAC key, and the reviewer API key.                       │
  └───┬────────────────────┬──────────────────────────┬─────────────────────┘
      │  Telegram Bot API   │  reviewer HTTPS          │  Tailscale SSH
      │  (long-poll;        │  (2nd LLM; can only      │
      │   owner-id filter)  │   TIGHTEN — remove a tap)│
      ▼                     ▼                          ▼
  ┌───────────────────────┐   ┌──────────┐  ┌──────────────────────────────────┐
  │  [ Owner ] YOU, on    │   │[Reviewer]│  │  [ Target ] runs as the OWNER    │
  │  Telegram.            │   │ 2nd LLM, │  │  unix user via the HMAC ticket.  │
  │  The ONLY approver.   │   │ fail-    │  │  exec-argv-elevated: auto-run    │
  │  [Approve] [Deny]     │   │ closed   │  │  confined (bubblewrap jail,      │
  │  [🛑 Revoke]          │   └──────────┘  │  network-isolated); owner-tapped │
  └───────────────────────┘                │  commands unconfined.            │
                                           └──────────────────────────────────┘
```

| Domain | Runs as | Holds | Can it be injected? | Fence |
|---|---|---|---|---|
| **Agent** | `hestia` (in the box) | nothing | **Yes** (assumed) | firewalled to internet-only; can only write its outbox |
| **Mover** | `hestia-mover` (host) | no secrets, no policy | no (parses nothing) | group `lxd` only; moves opaque bounded blobs |
| **Broker** | `hestia-broker` (host) | bot token, HMAC key, reviewer API key | no (never runs box data as code) | **no** lxd/docker/sudo |
| **Reviewer** | a second LLM (HTTPS) | nothing (stateless; sees only intent + argv + cwd as data) | **Yes** (assumed) | can only *tighten* — it removes a tap or does nothing; it can never lower the floor |
| **Owner** | you, on Telegram | the trust anchor | no | you read the argv + hash before tapping |
| **Target** | commands run as the **owner** unix user, gated by the HMAC ticket | nothing (the wrapper is a fixed root shim) | no | one narrow NOPASSWD sudoers line; auto-run is confined (bubblewrap, network-isolated); owner-tapped commands run unconfined |

---

## Invariants

These are the load-bearing properties. If any is violated, the model is broken.

- **INV-1 — separation of route and secret.** The process with `lxd` (the mover) holds no secrets and makes no decisions. The process with the secrets and the policy (the broker) has no `lxd`/`docker`/`sudo`. Neither runs as you.
- **INV-2 — the box has no path out except the mailbox.** The container is firewalled to the public internet only (v4 + v6). It cannot reach the host, the LAN, or the tailnet — so it cannot invoke the broker, reach the target directly, or exfiltrate over the tailnet. The only crossing is opaque files the mover shuttles.
- **INV-3 — approval is enforced outside the LLM.** The Telegram button lives on a *second* bot whose token is on the host only. The agent cannot press it, cannot see it, and cannot forge it. A **deterministic policy-tier floor** decides what can *never* auto-run: the dangerous tiers (egress, secret zones, sudo/root, persistence, `rm -rf` under home) are always a human tap. The reviewer (INV-6) may only *remove* a tap on the safer middle tiers — it can never lower the floor.
- **INV-4 — what executes equals what you approved.** The broker canonicalizes each command with length-prefixed fields, hashes it (`cmd_hash`), and runs its **own stored copy** — it never re-reads the box file after deciding. The button shows the argv and hash prefix; the hash is re-checked at dispatch. Mutating the request after approval does nothing (TOCTOU-proof).
- **INV-5 — execution is an unforgeable, broker-held capability.** *Every* command runs on the target as your own unix user, and only on a broker-signed HMAC ticket that is single-use and TTL-bound. A host-local process that reaches the target's SSH still cannot mint one without the key.
- **INV-6 — the reviewer can only tighten.** The Layer-2 LLM reviewer judges the middle tiers (FREE_ZONE / SOFT_DENY / ALLOW) against the operator-stamped session intent, and its *only* power is to remove a tap on an in-intent command. It is **fail-closed**: if it is disabled, unconfigured, unreachable, or its circuit breaker is open, every middle command falls back to your tap. It never sees the HARD_DENY/REFUSE tiers and can never lower the floor.
- **INV-7 — auto-run is confined.** Any command that auto-runs (a FREE_ZONE inspector, or a reviewer-approved middle command) executes inside a bubblewrap jail with the **network unshared** — so a hijacked-but-in-intent command still cannot exfiltrate. If the kernel cannot provide the user-namespace confinement, the broker fails **closed**: auto-run is disabled and every command asks. A startup preflight probes this and DMs you once if auto-mode is degraded.

---

## Request lifecycle

1. **Agent** builds a request `{v, session_id, request_id, cwd, elevate, argv[]}` and writes it to its outbox as `<request_id>.tmp`, then atomically renames to `<request_id>` (a UUID). It has no other capability.
2. **Mover** pulls the blob to the host spool (validates only: filename is a UUID, size ≤ 64 KiB; bounded batch per tick). It parses nothing else.
3. **Broker** reads it once, unlinks the box-side copy, validates the schema (or **REJECT**), canonicalizes + hashes, and evaluates the deterministic `policy_tier()` **floor** — the sole floor authority, in strict priority `REFUSE > HARD_DENY > FREE_ZONE > SOFT_DENY > ALLOW`:
   - **REFUSE** — a catastrophic hardline (e.g. `rm -rf ~`, `poweroff`). No button; can never run.
   - **HARD_DENY** — intent-proof danger: outbound egress, a secret zone, sudo/root, persistence, or `rm -rf` under home. Always a human tap (🔴), and unconfined on approve.
   - **FREE_ZONE** — a read-only inspector (`ls`, `cat`, `grep`, `find`, …) with safe flags on a non-secret path. Auto-runs **only while a session is open**, confined (bubblewrap, network-isolated).
   - **SOFT_DENY / ALLOW** — the middle: destructive-but-recoverable (`SOFT_DENY`) or the default (`ALLOW`, e.g. writers, `git`, inline interpreters). These go to the **fail-closed LLM reviewer**, which may auto-run an in-intent command confined, or fall it to your tap (🔵) otherwise. **REJECT** — malformed/oversize/non-UUID — is dropped and audited.
4. **Owner** sees the exact argv, cwd, and hash prefix, and a risk-typed header: 🟡 **session** (opens a work window), 🔴 **deterministic floor** (a HARD_DENY rule fired), or 🔵 **reviewer escalation** (the middle command is off-intent, with the reviewer's one-line reason). You **Approve** or **Deny**. Unanswered → auto-deny.
5. On auto-run or approve, the **broker** re-checks the hash + re-derives the tier (binding), then relays over **Tailscale SSH** to the target's `exec-argv-elevated` — a single HMAC-ticketed executor that runs the command as the **owner** unix user, **confined** (bubblewrap) when the ticket's `confined` flag is set (auto-run) and unconfined when it is not (owner-tapped). Execution is always `shell=False`.
6. The **result** (bounded, ≤ mailbox cap) goes back to the spool → mover → the agent's inbox. The agent reads it and can deliver it to you (e.g. on its own Telegram bot).

Every step is written to an **append-only audit log** (`chattr +a`) the agent cannot reach or rewrite.

See [broker.md](broker.md) for the protocol details, the policy tiers, the reviewer, and the elevation ticket format; [confinement.md](confinement.md) for the Phase-1 wall; [security-model.md](security-model.md) for the threat model and residual risks.
