# Configuration

All site-specific values live in one file: `config/hestia.env` (copied from `config/hestia.env.example`). The install scripts and the runtime shell scripts source it. **The one true secret — the approvals bot token — is *not* in this file**; it goes into the broker's `0600` EnvironmentFile (below) and is never committed.

```bash
cp config/hestia.env.example config/hestia.env
$EDITOR config/hestia.env
```

## Values you must set

### `HESTIA_OWNER_ID` — your Telegram user id  *(required)*
The numeric id (not a `@username`) of the account allowed to approve. Get it by messaging **@userinfobot** on Telegram. The broker ignores every update from any other id. `0` (the default) matches nobody, so nothing can be approved until you set this.

### `HESTIA_TARGET_HOST` — the machine the agent acts on  *(required)*
`hestia-agent@<target>`, where `<target>` is your laptop/host's Tailscale MagicDNS name (e.g. `laptop.tailnet-name.ts.net`) or its `100.x` tailnet IP. `hestia-agent` is the restricted user created by `install/target/1-users.sh`. The broker reaches it via **Tailscale SSH** — the target needs Tailscale with SSH enabled; no OpenSSH server is required.

### `OWNER_UNIX_USER` — your own account on the target  *(required for elevation)*
The unix user that owns your private files on the target machine (e.g. `alice`). 🔴 **Elevated** commands run as this user. At install it is rendered into the elevated wrapper's allowlist (`ALLOWED_RUNAS`) and set as the broker's `HESTIA_ELEV_RUNAS`. Leave blank to disable elevation entirely (the broker then only ever runs commands as `hestia-agent`).

### The two Telegram bots
Hestia uses **two** bots, created with **@BotFather** (`/newbot` twice):

1. **Your agent's chat bot** — the one you already talk to (or a new one). This is the agent's own interface; its token lives in the agent's config inside the box. Not a Hestia secret per se.
2. **The approvals bot** — *new*, dedicated to Hestia. Its token is the security-critical secret. It goes **only** into the broker's EnvironmentFile:

   ```
   # /etc/hestia-broker/broker.env      (root:hestia-broker, chmod 0600)
   TELEGRAM_BROKER_BOT_TOKEN=123456:AA...your-approvals-bot-token...
   ```

   `install/host/5-broker-service.sh` creates this file (it will prompt you for the token, or you can place the file first). **Message the approvals bot once** from your account after creating it, so Telegram will deliver its updates to the broker.

## Values with sensible defaults (usually leave alone)

| Var | Default | Meaning |
|---|---|---|
| `CONTAINER_NAME` | `hestia-box` | the LXD container running your agent |
| `AGENT_BOX_USER` | `hestia` | the agent's unix user inside the container |
| `HESTIA_BRIDGE` | `lxdbr0` | the LXD bridge the container is on |
| `WORKSPACE` | `/srv/projects` | the free-zone directory (must match broker + target) |
| `LLM_BASE_URL` / `MODEL_NAME` / `LLM_API_KEY_ENV` | placeholders | your agent's OpenAI-compatible endpoint, model, and the *name* of the env var holding the API key (Phase 1 only) |

Optional broker tuning (`HESTIA_SESSION_SECS`, `HESTIA_CMD_SECS`, `HESTIA_MAX_INFLIGHT`, `HESTIA_SESSION_CMD_BUDGET`, …) is documented inline in `hestia.env.example`; the defaults are conservative.

The egress firewall auto-detects the bridge subnets from the live bridge, so you normally don't set `CONTAINER_SUBNET_V4` / `LXDBR_GW4` / etc. Set them only if detection fails.

## What is a secret and what isn't

- **Secret (never commit, `0600`, host-only):** the approvals bot token; the elevation HMAC key (`/etc/hestia/elevation.key` on the target, `/etc/hestia-broker/elevation.key` on the host).
- **Not secret (but still per-user, `.gitignore`d):** `config/hestia.env` — it holds ids, hostnames, and usernames, not credentials. It is git-ignored anyway so you never accidentally publish your setup.

`config/hestia.env`, `*.env`, and `*.key` are all in `.gitignore`. Double-check with `git status` before your first push.
