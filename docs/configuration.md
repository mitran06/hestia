# Configuration

All site-specific values live in one file: `config/hestia.env` (copied from `config/hestia.env.example`). The install scripts and the runtime shell scripts source it. **The secrets — the approvals bot token and (if you enable it) the reviewer API key — are *not* in this file**; they go into the broker's `0600` EnvironmentFile (below) and are never committed.

```bash
cp config/hestia.env.example config/hestia.env
$EDITOR config/hestia.env
```

## Values you must set

### `HESTIA_OWNER_ID` — your Telegram user id  *(required)*
The numeric id (not a `@username`) of the account allowed to approve. Get it by messaging **@userinfobot** on Telegram. The broker ignores every update from any other id. `0` (the default) matches nobody, so nothing can be approved until you set this.

### `HESTIA_TARGET_HOST` — the machine the agent acts on  *(required)*
`hestia-agent@<target>`, where `<target>` is your laptop/host's Tailscale MagicDNS name (e.g. `laptop.tailnet-name.ts.net`) or its `100.x` tailnet IP. `hestia-agent` is the restricted user created by `install/target/1-users.sh`. The broker reaches it via **Tailscale SSH** — the target needs Tailscale with SSH enabled; no OpenSSH server is required.

### `OWNER_UNIX_USER` — your own account on the target  *(required)*
The unix user that owns your private files on the target machine (e.g. `alice`). **Every** command Hestia runs on the target runs as this user, via the HMAC-ticketed executor — auto-run commands confined (bubblewrap, network-isolated), owner-tapped commands unconfined. At install it is rendered into the executor's run-as allowlist (`ALLOWED_RUNAS`) and set as the broker's `HESTIA_ELEV_RUNAS`. The HMAC ticket is a hard dependency for execution now: with no elevation key configured, nothing can run at all (the broker fails closed to a refusal).

### The two Telegram bots
Hestia uses **two** bots, created with **@BotFather** (`/newbot` twice):

1. **Your agent's chat bot** — the one you already talk to (or a new one). This is the agent's own interface; its token lives in the agent's config inside the box. Not a Hestia secret per se.
2. **The approvals bot** — *new*, dedicated to Hestia. Its token is the security-critical secret. It goes **only** into the broker's EnvironmentFile — the same `0600` file that holds the reviewer API key (if you enable the reviewer):

   ```
   # /etc/hestia-broker/broker.env      (root:hestia-broker, chmod 0600)
   TELEGRAM_BROKER_BOT_TOKEN=123456:AA...your-approvals-bot-token...
   HESTIA_REVIEWER_KEY=sk-...your-reviewer-api-key...     # only if HESTIA_REVIEWER_ENABLED=1
   ```

   `install/host/5-broker-service.sh` creates this file (it will prompt you for the token, or you can place the file first). **Message the approvals bot once** from your account after creating it, so Telegram will deliver its updates to the broker.

### The LLM reviewer (optional — off by default)
Hestia's Layer-2 reviewer is a *second* LLM that judges middle-tier commands against your session intent, so in-intent commands auto-run and off-intent ones ask. It is **off by default** and **fail-closed** — leaving it off simply means every middle command asks for a tap. To enable it, set in `config/hestia.env`:

- `HESTIA_REVIEWER_ENABLED=1`;
- `HESTIA_REVIEWER_BASE_URL` / `HESTIA_REVIEWER_MODEL` — any OpenAI-compatible chat/completions endpoint and model (**not** a secret);
- `HESTIA_REVIEWER_KEY` — the API key, a **secret**: put it *only* in the broker's `0600` EnvironmentFile above, exactly like the bot token.

The reviewer needs the same auto-run preconditions as the free-zone: elevation configured and unprivileged user namespaces available. A startup preflight probes all three and DMs you once if auto-mode is degraded.

## Values with sensible defaults (usually leave alone)

| Var | Default | Meaning |
|---|---|---|
| `CONTAINER_NAME` | `hestia-box` | the LXD container running your agent |
| `AGENT_BOX_USER` | `hestia` | the agent's unix user inside the container |
| `HESTIA_BRIDGE` | `lxdbr0` | the LXD bridge the container is on |
| `WORKSPACE` | `/srv/projects` | the FREE_ZONE-tier workspace on the target (must match broker + target) |
| `LLM_BASE_URL` / `MODEL_NAME` / `LLM_API_KEY_ENV` | placeholders | your agent's OpenAI-compatible endpoint, model, and the *name* of the env var holding the API key (Phase 1 only) |

Optional broker tuning (`HESTIA_SESSION_SECS`, `HESTIA_CMD_SECS`, `HESTIA_MAX_INFLIGHT`, `HESTIA_SESSION_CMD_BUDGET`, …) is documented inline in `hestia.env.example`; the defaults are conservative.

The **reviewer** and **runtime confinement** have their own keys (`hestia.env.example` sections 6–7), all with safe defaults:

| Var | Default | Meaning |
|---|---|---|
| `HESTIA_REVIEWER_ENABLED` | `0` | turn the Layer-2 LLM reviewer on (`1`) or off; off = every middle command asks |
| `HESTIA_REVIEWER_TIMEOUT` / `HESTIA_REVIEWER_MAXTOK` / `HESTIA_REVIEWER_RETRIES` | `8` / `64` / `1` | per-call HTTP timeout, verdict token cap, transport-blip retries before failing closed |
| `HESTIA_MAX_REVIEWS` | `4` | concurrent in-flight reviews; excess → a tap |
| `HESTIA_REVIEWER_BREAKER_N` / `HESTIA_REVIEWER_BREAKER_COOLDOWN` | `4` / `30` | consecutive reviewer failures before the circuit breaker opens; seconds before a half-open recovery trial |
| `HESTIA_CONFINE_USERNS` | live-probe | pin the userns confinement probe (`1`/`0`); unset live-probes at startup |
| `HESTIA_BWRAP` | `bwrap` | the bubblewrap binary used for the auto-run jail |
| `HESTIA_EXFIL_CAP_N` | `= HESTIA_SESSION_CMD_BUDGET` | max *distinct* auto-approved commands per window before the next falls to a tap (`≤0` disables) |

The **startup preflight is always on** (there is no toggle): the broker probes confinement, reviewer auth, and elevation at start and DMs you once if any is degraded.

The egress firewall auto-detects the bridge subnets from the live bridge, so you normally don't set `CONTAINER_SUBNET_V4` / `LXDBR_GW4` / etc. Set them only if detection fails.

## What is a secret and what isn't

- **Secret (never commit, `0600`, host-only):** the approvals bot token; the reviewer API key (`HESTIA_REVIEWER_KEY`, if the reviewer is enabled) — both in the broker's `0600` EnvironmentFile; the elevation HMAC key (`/etc/hestia/elevation.key` on the target, `/etc/hestia-broker/elevation.key` on the host).
- **Not secret (but still per-user, `.gitignore`d):** `config/hestia.env` — it holds ids, hostnames, and usernames, not credentials. It is git-ignored anyway so you never accidentally publish your setup.

`config/hestia.env`, `*.env`, and `*.key` are all in `.gitignore`. Double-check with `git status` before your first push.
