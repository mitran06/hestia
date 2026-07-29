#!/usr/bin/env python3
"""brokerd.py — Hestia capability broker DAEMON (Part 5: Telegram approval + session lifecycle).

Runs as hestia-broker. Imports the Part-3 policy engine (broker.py) + the Layer-2 reviewer (reviewer.py)
and adds the human-approval boundary enforced OUTSIDE the LLM: a Telegram inline button, owner-id
filtered, single-use nonce.

Flow per request (delivered by the mover into incoming/):
  validate -> policy_tier() (the deterministic FLOOR, sole authority, runs FIRST):
    REJECT        -> audit + refusal result (malformed input).
    (need a session) commands only run inside an OPEN window (opened via an approved session_open).
    REFUSE        -> refused, NO button (unapprovable hardline).
    HARD_DENY     -> human button; on approve runs UNCONFINED on the ticketed executor.
    FREE_ZONE     -> auto (no LLM), CONFINED (exfil-capped), no button.
    SOFT_DENY/ALLOW -> the reviewer middle: an LLM reviewer (fail-CLOSED) may auto-run it CONFINED, else
                     it falls to the owner button. The box `elevate` lever re-routes it to a human tap to
                     run UNCONFINED (it can NEVER lower the floor).
Security: only callback_query from OWNER_ID is honored; each button carries a single-use nonce
(compare-and-set: consumed on first tap; replays -> "already handled"); unanswered -> auto-deny;
broker restart => in-memory state lost => all sessions CLOSED (fail-closed). Commands execute via
`tailscale ssh <target-host> -- exec-argv <BASE64>` (single opaque token; shell=False on the target)."""
import os, sys, json, time, base64, secrets, urllib.request, subprocess, importlib.util, threading, uuid, hmac, hashlib, unicodedata

# --- load the Part-3 policy engine + the Layer-2 reviewer (same dir) ---
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("broker", os.path.join(_here, "broker.py"))
broker = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(broker)
_rspec = importlib.util.spec_from_file_location("reviewer", os.path.join(_here, "reviewer.py"))
reviewer = importlib.util.module_from_spec(_rspec); _rspec.loader.exec_module(reviewer)

TOKEN     = os.environ.get("TELEGRAM_BROKER_BOT_TOKEN", "")
OWNER_ID  = int(os.environ.get("HESTIA_OWNER_ID", "0"))          # REQUIRED: your Telegram user id (0 = fail-closed, matches nobody)
TARGET    = os.environ.get("HESTIA_TARGET_HOST", "hestia-agent@127.0.0.1")  # REQUIRED: user@<target-tailscale-host>
EXECARGV  = os.environ.get("HESTIA_EXECARGV", "/usr/local/lib/hestia/exec-argv")
TAILSCALE = os.environ.get("HESTIA_TAILSCALE", "/usr/bin/tailscale")
SPOOL     = os.environ.get("HESTIA_SPOOL", "/var/lib/hestia-spool")
INCOMING  = os.path.join(SPOOL, "incoming")
OUTGOING  = os.path.join(SPOOL, "outgoing")
API       = f"https://api.telegram.org/bot{TOKEN}"
SESSION_SECS   = int(os.environ.get("HESTIA_SESSION_SECS", "600"))   # open-window duration
CMD_SECS       = int(os.environ.get("HESTIA_CMD_SECS", "180"))       # per-command approval timeout
SESSION_ASK_SECS = int(os.environ.get("HESTIA_SESSION_ASK_SECS", "300"))
EXEC_TIMEOUT   = int(os.environ.get("HESTIA_EXEC_TIMEOUT", "120"))
ELEV_KEY_FILE  = os.environ.get("HESTIA_ELEVATION_KEY_FILE", "/etc/hestia-broker/elevation.key")  # == target key
ELEV_WRAPPER   = os.environ.get("HESTIA_ELEV_WRAPPER", "/usr/local/lib/hestia/exec-argv-elevated")
ELEV_RUNAS     = os.environ.get("HESTIA_ELEV_RUNAS", "")         # REQUIRED for elevation: the owner unix user (must match the target wrapper's ALLOWED_RUNAS)
MAXOUT         = 50000                                                # pre-cap RAW stdout bytes (avoid decoding huge output)
RESULT_CAP     = 60000                                                # HARD cap on the ENCODED result JSON, safely < mover's 65536

# --- Layer-2 reviewer config (broker-held key, host-only 0600). Disabled by default: with the reviewer
#     off, every SOFT_DENY/ALLOW middle command fails CLOSED to the owner button (never a silent auto-run). ---
REVIEWER_ENABLED  = os.environ.get("HESTIA_REVIEWER_ENABLED", "0") == "1"
REVIEWER_BASE_URL = os.environ.get("HESTIA_REVIEWER_BASE_URL", "")
REVIEWER_KEY      = os.environ.get("HESTIA_REVIEWER_KEY", "")
REVIEWER_MODEL    = os.environ.get("HESTIA_REVIEWER_MODEL", "")   # owner must set; fail-closed if enabled w/o model
REVIEWER_TIMEOUT  = int(os.environ.get("HESTIA_REVIEWER_TIMEOUT", "8"))
REVIEWER_MAXTOK   = int(os.environ.get("HESTIA_REVIEWER_MAXTOK", "64"))
# Retry a TRANSPORT blip (not a clean verdict) before failing CLOSED to a tap, so one dropped HTTP call no
# longer needlessly escalates an in-intent command (reviewer.review_outcome retries INSIDE, so the breaker
# still counts one failure per command). Defaults: 1 retry, 0.3s linear backoff — cheap, self-heals a blip.
REVIEWER_RETRIES  = int(os.environ.get("HESTIA_REVIEWER_RETRIES", "1"))
REVIEWER_RETRY_BACKOFF = float(os.environ.get("HESTIA_REVIEWER_RETRY_BACKOFF", "0.3"))
# Tier-adaptive thinking (#3): base reasoning effort for the fast default-allow path, and an OPTIONAL bigger
# budget for the destructive SOFT_DENY tier. Defaults make soft_* == base -> a NO-OP until deliberately set
# (a reasoning model with thinking on but a small budget can spend it all on reasoning_content and return
# empty content, fail-CLOSED to a tap — enable soft only with evidence + a fitting timeout).
REVIEWER_EFFORT       = os.environ.get("HESTIA_REVIEWER_EFFORT", "none")
REVIEWER_SOFT_EFFORT  = os.environ.get("HESTIA_REVIEWER_SOFT_EFFORT", REVIEWER_EFFORT)
REVIEWER_SOFT_MAXTOK  = int(os.environ.get("HESTIA_REVIEWER_SOFT_MAXTOK", str(REVIEWER_MAXTOK)))
REVIEWER_SOFT_TIMEOUT = int(os.environ.get("HESTIA_REVIEWER_SOFT_TIMEOUT", str(REVIEWER_TIMEOUT)))

# --- Reviewer concurrency cap + circuit breaker (2nd-gate BLOCKER). The Breaker lives in reviewer.py;
#     brokerd is the SOLE caller that consults it. MAX_REVIEWS bounds concurrent in-flight reviews
#     (excess -> HUMAN button, no worker); after BREAKER_N consecutive reviewer timeouts/HTTP-errors the
#     breaker OPENS and every middle command goes STRAIGHT to HUMAN; after BREAKER_COOLDOWN seconds one
#     half-open trial is allowed through, a clean verdict CLOSES it (self-heals), a failure re-opens it. ---
HESTIA_MAX_REVIEWS              = int(os.environ.get("HESTIA_MAX_REVIEWS", "4"))          # concurrent reviews cap
HESTIA_REVIEWER_BREAKER_N       = int(os.environ.get("HESTIA_REVIEWER_BREAKER_N", "4"))  # consecutive fails -> OPEN
HESTIA_REVIEWER_BREAKER_COOLDOWN = float(os.environ.get("HESTIA_REVIEWER_BREAKER_COOLDOWN", "30"))  # half-open cooldown (s)
_breaker = reviewer.Breaker(HESTIA_REVIEWER_BREAKER_N, HESTIA_REVIEWER_BREAKER_COOLDOWN)  # consulted/recorded UNDER _lock


def _reviewer_cfg():
    """The reviewer's runtime config, read live so tests/deploy can flip it. review() checks
    enabled/key/base_url and fails CLOSED to HUMAN when any is missing (never a silent auto-run)."""
    return {"enabled": REVIEWER_ENABLED, "base_url": REVIEWER_BASE_URL, "key": REVIEWER_KEY,
            "model": REVIEWER_MODEL, "timeout": REVIEWER_TIMEOUT, "max_tokens": REVIEWER_MAXTOK,
            "retries": REVIEWER_RETRIES, "retry_backoff": REVIEWER_RETRY_BACKOFF,
            "reasoning_effort": REVIEWER_EFFORT, "soft_effort": REVIEWER_SOFT_EFFORT,
            "soft_max_tokens": REVIEWER_SOFT_MAXTOK, "soft_timeout": REVIEWER_SOFT_TIMEOUT}


# --- Runtime-confinement userns precondition. `confined=true` needs unprivileged user namespaces; on a
#     hardened kernel they die E_EXEC and the auto path is silently bricked. So the AUTO path may auto-run
#     ONLY if the startup/enable-time probe `bwrap --unshare-net --bind / / -- true` succeeds.
#     HESTIA_CONFINE_USERNS overrides the live probe: "1"/"0" force the answer (a rollout that ran the probe
#     as the target user pins it); unset -> run the live probe. Safe default: if the probe can't be established
#     the gate reads False, so the middle falls to the human button (never an unconfined/unconfinable auto-run). ---
CONFINE_USERNS_OVERRIDE = os.environ.get("HESTIA_CONFINE_USERNS", "")   # "1"/"0" pin; "" -> live probe
BWRAP              = os.environ.get("HESTIA_BWRAP", "bwrap")
_userns_probe_cache = None                                             # memoized _userns_ok() result


MAX_INFLIGHT   = int(os.environ.get("HESTIA_MAX_INFLIGHT", "6"))     # concurrent relayed execs cap
MAX_PENDING    = int(os.environ.get("HESTIA_MAX_PENDING", "20"))     # outstanding approval buttons cap
SESSION_CMD_BUDGET = int(os.environ.get("HESTIA_SESSION_CMD_BUDGET", "40"))  # commands per open window
EXFIL_CAP_N        = int(os.environ.get("HESTIA_EXFIL_CAP_N", str(SESSION_CMD_BUDGET)))  # exfil-cap:
#   max DISTINCT auto-approved commands (by cmd_hash) per open window before falling to the human button.
#   Independent of + in addition to SESSION_CMD_BUDGET (both enforced; cap <= budget). N<=0 disables it.
#   Belt-and-suspenders vs runaway repeated auto operations; the load-bearing egress block is confinement.
#   The DEFAULT is SESSION_CMD_BUDGET so the arithmetic backstop is ARMED out of the box; still operator-
#   tunable via HESTIA_EXFIL_CAP_N, and N<=0 is an explicit opt-out.
SESSION_LOG_WINDOW  = int(os.environ.get("HESTIA_SESSION_LOG_WINDOW", "20"))   # last-N log lines shown; older rolled up
SESSION_FLUSH_MIN_S = float(os.environ.get("HESTIA_SESSION_FLUSH_MIN_S", "1")) # min seconds between non-forced edits (coalesce)

# --- shared state (guarded by _lock; workers touch _inflight + write results) ---
_lock = threading.Lock()
_session_until      = 0.0     # monotonic deadline; 0 = CLOSED
_session_until_wall = 0.0     # wall-clock deadline (dual-clock: session closes at the EARLIER of the two)
_session_cmd_count  = 0       # commands consumed in the current window (budget-limited)
_exfil_hashes       = set()    # DISTINCT cmd_hashes auto-approved this window (exfil-cap; window-scoped)
_pending  = {}                # nonce -> dict(kind, req, chash, chat_id, msg_id, deadline)
_inflight = {}                # exec_token -> dict(req, chash, tier, confined, elevated, proc, revoked, started)
_reviews  = {}                # review_id -> dict(req, chash, tier, revoked, intent_hash)  [guarded by _lock]
_tg_offset = None

# --- session-render state (Phase A: in-memory; guarded by _lock; lost on restart => fail-closed) ---
_session_intent   = ""        # trusted anchor of the OPEN window; "" when closed. CANONICAL (sanitized once at
                              #   intake) so displayed == stored == anchor. Renderer displays it verbatim.
_session_secs     = 0         # approved duration of the open window (for display)
_session_msg_id   = None      # the ONE live session message id (reused button msg -> edited in place)
_session_log      = {}        # request_id -> {"icon":str,"argv":str,"status":str,"kind":str} (insertion-ordered)
_session_counts   = {"auto": 0, "approved": 0, "elevated": 0, "blocked": 0, "failed": 0}
_session_phase    = "idle"    # "idle" | "open" | "ended"
_session_end_reason = ""      # "agent" | "expired" | "revoked"
_session_killed   = 0         # in-flight execs killed by the terminating revoke (for the ⚪ header)
_render_dirty     = False     # set by session_log/state changes; consumed by _flush_session_msg
_session_last_flush = 0.0     # monotonic time of the last edit; enforces the <=1/sec coalescing on non-forced flushes


def now(): return time.monotonic()


def tg(method, **params):
    data = json.dumps(params).encode()
    req = urllib.request.Request(f"{API}/{method}", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)


def send_button(text, nonce):
    kb = {"inline_keyboard": [[{"text": "✅ Approve", "callback_data": nonce + ":A"},
                               {"text": "⛔ Deny",    "callback_data": nonce + ":D"}]]}
    r = tg("sendMessage", chat_id=OWNER_ID, text=text, reply_markup=kb)
    return r["result"]["message_id"] if r.get("ok") else None


def resolve_msg(chat_id, msg_id, text):
    try: tg("editMessageText", chat_id=chat_id, message_id=msg_id, text=text)
    except Exception: pass


def _reset_counts():
    global _session_counts
    _session_counts = {"auto": 0, "approved": 0, "elevated": 0, "blocked": 0, "failed": 0}


def _end_session(reason, killed=0):
    """Terminal transition for the open window (agent-close / expiry / revoke). Render the ⚪ summary
    ONTO the live session message WHILE the log + counts are still populated, invalidate any session-
    scoped pending approvals, then wipe the window state. _session_msg_id is intentionally KEPT so the
    already-edited message stays put; a fresh session_open mints a new message. `killed` feeds the
    ⚪ 'revoked — N killed' header (0 for agent/expired). Main-thread."""
    global _session_until, _session_until_wall, _session_intent, _session_secs
    global _session_phase, _session_end_reason, _session_killed
    if _session_phase == "ended":                  # idempotent: a double-call (expiry then revoke, or a
        return                                     #   repeated tick) must NOT overwrite the good ⚪ summary
    # review teardown FIRST, while phase is still 'open': mark every in-flight review revoked + route it to
    # a refused reply, so the worker's re-check sees the review gone and never dispatches into the closing
    # window (closes the _end_session flush-window fail-open). No-op if revoke_all pre-tore them.
    _teardown_reviews("session ended")
    _session_phase = "ended"
    _session_end_reason = reason
    _session_killed = killed
    _flush_session_msg(force=True)                 # renders ⚪ from the still-populated log/counts
    # T10 FULL pending-invalidation: the window just closed, so EVERY outstanding pending is a stale
    # button that must NEVER dispatch into the closed window. Invalidate ALL of them — commands via
    # refuse() (with their chash), control ops (session_open re-anchor / session_close) via
    # _control_refuse(). A pending whose msg_id IS the live session message (a re-anchor sharing it) is
    # still refused + dropped, but its button is NOT re-edited (that would clobber the ⚪ summary just
    # rendered). Note revoke_all() pre-clears _pending, so this loop is a no-op there (no double-refuse).
    stale = list(_pending.items())
    _pending.clear()
    for nonce, p in stale:
        if p.get("msg_id") != _session_msg_id:                 # own button -> mark it dead; keep the ⚪ summary intact
            resolve_msg(p["chat_id"], p["msg_id"], "⌛ session ended")
        if p["kind"] in ("session_open", "session_close"):
            _control_refuse(p["req"], "session ended")
        else:
            refuse(p["req"], p["chash"], "session ended")
    broker.audit({"decision": "SESSION_PENDING_INVALIDATED", "count": len(stale), "reason": reason})
    _session_until = 0.0
    _session_until_wall = 0.0
    _session_intent = ""
    _session_secs = 0
    _session_log.clear()
    _exfil_hashes.clear()                          # window closed -> reset the exfil-cap distinct-hash set
    _reset_counts()
    # NOTE: _session_msg_id is deliberately NOT reset — the edited message must remain.


def _hhmm(wall):
    """HH:MM (local) of a wall-clock deadline, for the 'expires HH:MM' header. 0/None -> '--:--'."""
    if not wall:
        return "--:--"
    return time.strftime("%H:%M", time.localtime(wall))


def _render_session():
    """Pure render of the session message from state (no I/O). Two shapes:
      open  -> 🟢 header + enforcing-intent + divider + (windowed) log lines.
      ended -> ⚪ summary header (reason + total cmds + counts) + the (windowed) log below.
    The intent is rendered VERBATIM from the (already-canonical) _session_intent — no re-sanitize,
    no re-truncate — so displayed == stored == anchor. Guaranteed < 4000 chars (Telegram hard-caps
    message text at 4096).
    Thread safety: SNAPSHOTS all shared state under _lock at the top, then renders from locals only,
    so a concurrent session_log() insert (up to MAX_INFLIGHT worker threads, also under _lock) can
    never mutate what we iterate — no `dictionary changed size during iteration`. VERIFIED: no caller
    (_flush_session_msg, on_deny) holds _lock, so this acquisition cannot deadlock (_lock is non-
    reentrant); revoke_all releases _lock before reaching _end_session -> _flush -> here."""
    with _lock:
        entries = list(_session_log.values())    # insertion-ordered snapshot (iteration is off the live dict)
        counts  = dict(_session_counts)
        phase   = _session_phase
        intent  = _session_intent
        end_reason  = _session_end_reason
        killed  = _session_killed
        until_wall  = _session_until_wall
        running = len(_inflight)                  # live in-flight execs -> the Revoke blast-radius counter
    total = len(entries)
    shown = entries[-SESSION_LOG_WINDOW:] if total > SESSION_LOG_WINDOW else entries
    hidden = total - len(shown)
    body = []
    if hidden > 0:
        c = counts
        body.append("…%d earlier · %d auto · %d approved · %d elevated · %d blocked · %d failed"
                    % (hidden, c["auto"], c["approved"], c["elevated"], c["blocked"], c["failed"]))
    for e in shown:
        body.append(e["icon"] + "  " + e["argv"] + "   " + e["status"])

    if phase == "open":
        rn = (" · %d running" % running) if running else ""
        head = ["🟢 Session open · expires " + _hhmm(until_wall) + rn,
                'enforcing: "' + intent + '"',     # verbatim canonical anchor
                "────────"]
    else:   # "ended" (or defensive fallback)
        c = counts
        reason = {"agent": "ended by agent",
                  "expired": "expired",
                  "revoked": "revoked — %d killed" % killed}.get(end_reason, "ended")
        summary = "%d auto · %d approved · %d elevated · %d blocked · %d failed" % (
            c["auto"], c["approved"], c["elevated"], c["blocked"], c["failed"])
        head = ["⚪ Session " + reason + " · " + str(total) + " cmds · " + summary,
                "────────"]

    text = "\n".join(head + body)
    while len(text) > 3900 and body:             # hard guard: drop oldest shown lines until it fits < 4000
        body.pop(0)
        text = "\n".join(head + body)
    return text[:3999]


def _flush_session_msg(force=False):
    """Edit the ONE live session message to the current render. No-op unless dirty (or forced).
    Non-forced edits are coalesced to at most ~1/sec (SESSION_FLUSH_MIN_S) via a min-interval guard;
    force=True is exempt so terminal/open/close edits always land. When the session is open, re-attaches
    the 🛑 Revoke inline keyboard after the text edit."""
    global _render_dirty, _session_last_flush
    if not force and not _render_dirty:
        return
    if not force and (now() - _session_last_flush) < SESSION_FLUSH_MIN_S:
        return                                              # coalesce: at most ~1 edit/sec on non-forced flushes
    if _session_msg_id is not None:
        resolve_msg(OWNER_ID, _session_msg_id, _render_session())
        if _session_phase == "open":                        # ride the Revoke button on the live session message
            try:
                tg("editMessageReplyMarkup", chat_id=OWNER_ID, message_id=_session_msg_id,
                   reply_markup={"inline_keyboard": [[{"text": "🛑 Revoke session", "callback_data": "REVOKE"}]]})
            except Exception:
                pass
        _session_last_flush = now()                         # monotonic stamp: NTP-step-safe throttle
    _render_dirty = False


def session_open(): return now() < _session_until and time.time() < _session_until_wall


def _fit_result(obj):
    """Return a valid JSON body <= RESULT_CAP bytes. ensure_ascii can inflate non-ASCII/binary output up
    to ~12x (surrogate pairs), so we budget on the ENCODED length and truncate stdout/stderr as needed —
    the box ALWAYS gets a valid reply, never a silent mover-drop of an oversized result."""
    obj = dict(obj)
    body = json.dumps(obj, ensure_ascii=True).encode("utf-8")
    if len(body) <= RESULT_CAP:
        return body
    obj["truncated"] = True
    for field in ("stdout", "stderr"):
        if not isinstance(obj.get(field), str):
            continue
        probe = dict(obj); probe[field] = ""
        overhead = len(json.dumps(probe, ensure_ascii=True).encode("utf-8"))
        obj[field] = obj[field][:max(0, (RESULT_CAP - overhead) // 12)]   # 12 = worst-case bytes/char
        body = json.dumps(obj, ensure_ascii=True).encode("utf-8")
        if len(body) <= RESULT_CAP:
            return body
    while len(body) > RESULT_CAP and obj.get("stdout"):                   # safety clamp -> guaranteed fit
        obj["stdout"] = obj["stdout"][:len(obj["stdout"]) // 2]
        body = json.dumps(obj, ensure_ascii=True).encode("utf-8")
    if len(body) > RESULT_CAP:                                           # last resort: drop text entirely
        obj["stdout"] = obj["stderr"] = ""
        body = json.dumps(obj, ensure_ascii=True).encode("utf-8")
    return body


def write_result(req_id, obj):
    if not broker.UUID_RE.match(req_id):                     # defense-in-depth: never a traversal filename
        broker.audit({"decision": "RESULT_DROP", "reason": "non-uuid request_id", "request_id": req_id}); return
    part = os.path.join(OUTGOING, req_id + ".part")
    with open(part, "wb") as f: f.write(_fit_result(obj))
    os.chmod(part, 0o660)                                    # group-readable (mover reads) regardless of umask
    os.replace(part, os.path.join(OUTGOING, req_id))


def _build_payload(req, workspace_only, token=None):
    # WIRE CONTRACT: the emitted confinement key MUST be `workspace_only` (target/exec-argv reads
    # `workspace_only`; a leaked `confined` key -> target E_SCHEMA at runtime). The daemon's internal
    # confined var is TRANSLATED to this wire key here.
    d = {"cwd": req["cwd"], "argv": req["argv"], "workspace_only": workspace_only}
    if token: d["exec_token"] = token
    return base64.b64encode(json.dumps(d).encode()).decode()


def relay_exec(req, workspace_only, token=None):
    """BLOCKING relay (used only by selftest). The daemon uses non-blocking dispatch()/_run_exec()."""
    try:
        p = subprocess.run([TAILSCALE, "ssh", TARGET, "--", EXECARGV, _build_payload(req, workspace_only, token)],
                           capture_output=True, timeout=EXEC_TIMEOUT)
        return p.returncode, p.stdout[:MAXOUT].decode("utf-8", "replace"), p.stderr[:4096].decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "", "exec timeout"


def _remote_kill(token, attempts=8):
    """Kill the in-flight command's process group on the target. Retries over ~5s cover the window between
    spawn and exec-argv writing its pidfile on a cold/loaded box (a LOCAL client kill does NOT terminate
    the remote command — proven). Runs off the main loop (thread) or inside the worker; never holds _lock."""
    for _ in range(attempts):
        try:
            subprocess.run([TAILSCALE, "ssh", TARGET, "--", EXECARGV, "--kill", token], timeout=15)
        except Exception:
            pass
        time.sleep(0.6)


# ---- ELEVATION: broker-held HMAC capability. The target wrapper runs an approved command as the owner ONLY
#      on a broker-signed ticket, so a host-local caller who can reach hestia-agent's SSH cannot forge it. ----
def _elev_key():
    try:
        with open(ELEV_KEY_FILE, "rb") as f:
            k = f.read().strip()
        return k if len(k) >= 32 else None
    except OSError:
        return None


def elevation_enabled():
    return _elev_key() is not None


def _userns_probe():
    """Raw (uncached) userns availability probe: run `bwrap --unshare-net --bind / / -- true` and return
    True ONLY on a clean zero exit. FAIL CLOSED — a non-zero exit (unprivileged userns disabled) OR any
    exception (bwrap absent, transport error) -> False, so confinement is never assumed available when it
    cannot be proven. `--unshare-net --bind / /` mirrors the exact confined exec's namespace request."""
    try:
        r = subprocess.run([BWRAP, "--unshare-net", "--bind", "/", "/", "--", "true"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _userns_ok():
    """The gate's view of userns availability, resolved ONCE at startup/enable time and cached (the probe
    spawns a process; the answer is a stable kernel/deploy property). HESTIA_CONFINE_USERNS pins it ("1"->
    True, "0"->False) so a rollout that ran the probe as the target user can record the result; otherwise
    the live _userns_probe() decides. Fail-closed: an unpinned probe that cannot succeed reads False."""
    global _userns_probe_cache
    if _userns_probe_cache is None:
        if CONFINE_USERNS_OVERRIDE == "1":
            _userns_probe_cache = True
        elif CONFINE_USERNS_OVERRIDE == "0":
            _userns_probe_cache = False
        else:
            _userns_probe_cache = _userns_probe()
    return _userns_probe_cache


def _auto_preconditions_ok():
    """The AUTO path (FREE_ZONE + reviewer-ALLOW + soft_deny-unlock) may auto-execute ONLY when ALL hold.
    If ANY is false, process() diverts every auto-tier command to the HUMAN button instead — fail CLOSED,
    never a silent refuse and never an unconfined/unconfinable auto-run:
      1. the reviewer is ENABLED and KEYED (a keyless/disabled reviewer can never remove a middle tap, and
         the FREE_ZONE auto-run relies on the same reviewed-auto posture);
      2. elevation_enabled() — everything executes as the owner unix user via the ticketed executor, so no
         key == no run;
      3. the userns/bwrap probe SUCCEEDS — else confinement (the load-bearing egress block) cannot be
         enforced, so an auto command would run UNCONFINED; refuse to auto-approve and fall to the human."""
    return bool(REVIEWER_ENABLED and REVIEWER_KEY) and elevation_enabled() and _userns_ok()


def _alert_owner(text):
    """Best-effort Telegram DM to the owner (a preflight/degradation warning). NEVER raises — a Telegram
    hiccup at startup must not crash the only approval path; a send failure is audited instead. Returns the
    send success bool so callers/tests can assert it."""
    try:
        tg("sendMessage", chat_id=OWNER_ID, text=text)
        return True
    except Exception as e:
        # Log the exception TYPE only, never repr(e): a urllib error's repr embeds the request URL, and the
        # Telegram API URL carries the bot TOKEN — which must never land in the audit log. Audit is itself
        # wrapped so a log failure can't defeat the "never raises" contract.
        try:
            broker.audit({"decision": "ALERT_FAILED", "err": type(e).__name__, "text": text[:200]})
        except Exception:
            pass
        return False


def _reviewer_preflight():
    """Probe the reviewer for a REAL auth/URL success — the check `_auto_preconditions_ok()`'s key-presence
    test can't do (a valid key with a wrong base_url still 403s). Returns one of:
      "disabled"      — REVIEWER_ENABLED is off (intentional; NOT a degradation);
      "misconfigured" — enabled but base_url/key missing;
      "auth_failed"   — enabled + configured but the live call FAILED (transport / HTTP / 403);
      "ok"            — a real call COMPLETED (a clean verdict came back).
    Warms the TLS session first, then spends ONE probe token; review_outcome's own retry (cfg default
    retries=1 -> 2 attempts) self-heals a lone startup blip so a transient hiccup never false-alarms."""
    if not REVIEWER_ENABLED:
        return "disabled"
    cfg = _reviewer_cfg()
    if not cfg.get("base_url") or not cfg.get("key"):
        return "misconfigured"
    reviewer.warm_up(cfg)                                   # token-free DNS/TLS prime before the real probe
    # A real single review (cfg's own retries=1 default -> 2 attempts): robust against a lone startup blip
    # without a long stall if the endpoint is truly down. We check only `ok` (the call COMPLETED) — a clean
    # BLOCK of this probe still means auth/URL are healthy, so ALLOW-vs-BLOCK of "true" is irrelevant.
    _, ok, _ = reviewer.review_outcome("broker startup preflight reachability probe",
                                       ["true"], "/", broker.ALLOW, cfg)
    return "ok" if ok else "auth_failed"


def _preflight():
    """BROKER_START self-check. Probe the three preconditions whose SILENT failure degrades the broker to
    'every command asks' — confinement (userns), the reviewer (a REAL auth probe, not just key presence),
    and elevation — AUDIT them in one BROKER_PREFLIGHT record, and DM the owner ONE warning if any ACTIONABLE
    one is down. All-green is silent (no Telegram noise on a healthy restart). Never raises; a probe/alert
    failure is contained so it can't stop the daemon from starting."""
    try:
        userns = _userns_ok()
        elevation = elevation_enabled()
        reviewer_state = _reviewer_preflight()
        broker.audit({"decision": "BROKER_PREFLIGHT", "userns": userns,
                      "elevation": elevation, "reviewer": reviewer_state})
        down = []
        if not userns:
            down.append("confinement (userns) is DOWN — auto-run can't be confined")
        if not elevation:
            down.append("elevation is DOWN — no ticket key, nothing can execute")
        if reviewer_state in ("misconfigured", "auth_failed"):
            down.append(f"reviewer is DOWN ({reviewer_state}) — middle commands can't auto-approve")
        if down:
            _alert_owner("⚠️ Hestia broker preflight — AUTO-MODE DEGRADED "
                         "(commands will fall back to manual approval):\n• " + "\n• ".join(down))
        return {"userns": userns, "elevation": elevation, "reviewer": reviewer_state, "down": down}
    except Exception as e:                                  # a preflight bug must NEVER block startup
        try:
            broker.audit({"decision": "PREFLIGHT_ERROR", "err": type(e).__name__})
        except Exception:
            pass
        return {"userns": None, "elevation": None, "reviewer": "error", "down": ["preflight probe errored"]}


def _mint(action, fields):
    """Return a base64 HMAC-signed ticket, or None if no key. Canon MUST match exec-argv-elevated._canon:
    json.dumps(ticket-without-sig, sort_keys=True, separators=(',',':'))."""
    key = _elev_key()
    if not key:
        return None
    t = {"v": 1, "action": action, **fields, "issued": int(time.time())}
    canon = json.dumps(t, sort_keys=True, separators=(",", ":")).encode("utf-8")
    t["sig"] = hmac.new(key, canon, hashlib.sha256).hexdigest()
    return base64.b64encode(json.dumps(t).encode("utf-8")).decode("ascii")


def _remote_kill_elevated(token, attempts=8):
    """Kill an ELEVATED (owner/root-owned) process group: hestia-agent cannot signal it, so the kill must
    itself be elevated via a broker-signed kill-ticket over the same sudoers path."""
    for _ in range(attempts):
        kt = _mint("kill", {"exec_token": token})
        if kt:
            try:
                subprocess.run([TAILSCALE, "ssh", TARGET, "--", "sudo", "-n", ELEV_WRAPPER, "kill", kt], timeout=15)
            except Exception:
                pass
        time.sleep(0.6)


def _do_remote_kill(token, elevated):
    (_remote_kill_elevated if elevated else _remote_kill)(token)


# Visual-spoofing unicode to NEUTRALIZE (strip) from every box-authored string we render to the owner or
# promote to the reviewer anchor. Bidirectional controls can REORDER displayed text (RLO/LRO make "read
# logs" render as "sgol daer"); zero-width chars can HIDE/splice text invisibly. We STRIP the whole Cf
# (format) category — which already covers all of these plus WORD JOINER / SOFT HYPHEN / etc. — so a future
# loosening of the printable-escape below can't silently reopen the hole. Homoglyph folding is intentionally
# OUT of scope (an accepted display residual): we kill reordering/invisibility, not lookalikes.
def _neutralize_spoof(s):
    """Remove visual-spoofing format chars (Unicode Cf category: bidi controls U+202A–U+202E / U+2066–U+2069,
    marks U+200E/U+200F, zero-width U+200B–U+200D, BOM U+FEFF, and every other Cf) BEFORE display/escape."""
    return "".join(c for c in s if unicodedata.category(c) != "Cf")


def _san(s):
    """Escape control chars/newlines so attacker-controlled argv/cwd CANNOT forge extra lines in the
    Telegram button (the owner must see the true command, not a spoofed one). First STRIPS Cf-category
    format chars (bidi-reorder + zero-width invisibility neutralization) so they can never survive as
    reordering controls NOR as visible '\\xNN' litter in the owner-facing text."""
    s = _neutralize_spoof(str(s))
    return "".join(c if (c.isprintable() and c not in "\r\n\t") else "\\x%02x" % ord(c) for c in s)


# Tokens carrying any of these need single-quoting when shell-rendered (kept ASCII; no `re` import here).
_SHELL_UNSAFE = set(" \t\r\n`\"'$&|;<>(){}*?![]#~\\")


def _shell(argv):
    """Render argv as a shell-like line for DISPLAY ONLY (owner button + session row). It is NEVER
    re-parsed or executed — execution runs the exact argv with shell=False on the ticketed exec-argv path,
    so a pretty line cannot change what runs, and the `hash:` line binds the true bytes. A token that could
    carry a shell metachar is single-quoted (embedded ' -> '\\''), so an attacker token like `; rm -rf ~`
    renders as the visibly-quoted `'; rm -rf ~'` — one argument, never a second command. _san() runs LAST
    (strips bidi/zero-width, escapes control chars). Falls back to the unambiguous JSON argv form if the
    shell line is longer (pathological token soup) or picks up any control-char escape."""
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
        return _san(json.dumps(argv, default=str))
    parts = []
    for a in argv:
        if a and not any(c in _SHELL_UNSAFE for c in a):
            parts.append(a)
        else:
            parts.append("'" + a.replace("'", "'\\''") + "'")
    out = _san(" ".join(parts))
    raw = _san(json.dumps(list(argv), default=str))
    return raw if ("\\x" in out or len(out) > len(raw)) else out


def _fmt(req, chash, kind, reason=""):
    """Render the human-approval button. Identity is uniformly the owner unix user ({ELEV_RUNAS}); the
    button conveys the RISK CLASS by policy tier. 🔴 HARD_DENY names the deterministic FLOOR rule; 🔵
    (reviewer-BLOCK / escalation lever) shows the reviewer's reason. The command is shell-rendered for
    legibility (display-only; the hash binds the true argv). `reason` is UNTRUSTED text about attacker-
    influenced argv (from the LLM reviewer or the deterministic floor) -> _san()'d + clamped. Every
    executing outcome runs as {ELEV_RUNAS}, UNCONFINED."""
    cmd = _shell(req["argv"])
    if len(cmd) > 400: cmd = cmd[:400] + "…(truncated; hash binds full cmd)"
    cwd = _san(req["cwd"])[:200]
    badge = f"runs as {ELEV_RUNAS} (you) · UNCONFINED · hash {chash[:16]}…"
    if kind == "session":
        return ("🟡 Start a work session?\n\n  " + cmd + "\n  in: " + cwd +
                "\n\n  note: this opens a work session; each sensitive command still asks separately"
                "\n\nApprove?")
    if kind == broker.HARD_DENY:
        head = "🔴 Approve high-risk command?"
        why = "Floor: " + (_san(reason)[:200] if reason else "crosses a hard security boundary")
    else:                                                      # SOFT_DENY / ALLOW via reviewer-BLOCK / lever
        head = "🔵 Approve? Reviewer flagged this"
        why = "Reason: " + (_san(reason)[:200] if reason else "off-intent for this session (reviewer escalated)")
    return f"{head}\n{why}\n\n  {cmd}\n  in: {cwd}\n\n{badge}\n\nApprove?"


def _canon_intent(intent):
    """Canonicalize the agent-proposed intent ONCE, at intake: sanitize control chars and cap length.
    The RESULT is the single canonical string used everywhere — shown on the 🟡 button, promoted to
    the trusted anchor _session_intent on approval, and rendered verbatim in the 🟢/⚪ header. This is
    what makes displayed == stored == anchor hold."""
    return _san(str(intent))[:broker.MAX_INTENT]        # == 500; single source of truth (no silent divergence)


def _fmt_session_open(intent, secs):
    # yellow session-request text. `intent` is ALREADY canonical (_canon_intent ran at intake) -> render as-is.
    return ("🟡 The agent requests a work session\n"
            "what: " + intent + "\n"
            "for:  " + str(secs // 60) + " min\n\n"
            "Approve?")


def session_log(request_id, icon, argv, status, kind="command"):
    """Record/UPDATE one command's outcome in the live session log, keyed by request_id so concurrent
    workers (MAX_INFLIGHT) update THEIR row in place — never duplicate, never reorder. Drops appends
    outside an open window (pre/post-session noise). Bumps the right _session_counts on a terminal
    status exactly once. Marks the render dirty for the next _flush_session_msg."""
    global _render_dirty
    with _lock:
        if _session_phase != "open":
            return
        prev = _session_log.get(request_id)
        kept_kind = prev["kind"] if prev else kind            # keep the ORIGINAL scope kind across updates
        _session_log[request_id] = {"icon": icon, "argv": _shell(argv)[:80],
                                    "status": status, "kind": kept_kind}
        # terminality/bucketing keys on the ICON (the canonical per-site signal) so free-form refuse/
        # rejected statuses ("refused: …" / "rejected") still count correctly; 'revoked' is terminal-
        # for-dedup but intentionally UNCOUNTED regardless of its (rc-derived) icon.
        revoked = status == "revoked"
        terminal = revoked or icon in ("✓", "✗", "⛔", "🚫", "⏱", "⌛")
        already = bool(prev) and prev.get("_counted")
        _session_log[request_id]["_counted"] = already or terminal
        if terminal and not already and not revoked:
            if icon in ("✗", "⏱"):                            # ran-and-failed OR exec-timeout
                _session_counts["failed"] += 1
            elif icon in ("⛔", "🚫", "⌛"):                   # denied / refused / approval-timed-out (never ran)
                _session_counts["blocked"] += 1
            elif icon == "✓" and kept_kind in ("auto", "approved", "elevated"):
                _session_counts[kept_kind] += 1
        _render_dirty = True


def _exfil_would_exceed_locked(chash):
    """Would auto-approving THIS command exceed the distinct-cmd_hash exfil-cap? CALLER MUST HOLD _lock.
    N<=0 disables (never exceeds). A REPEAT of an already-counted hash never exceeds (the cap is over
    DISTINCT hashes). A NEW distinct hash exceeds only once the window already holds N distinct auto
    hashes. Pure predicate — does NOT record; _exfil_add_locked() commits after the auto path is chosen."""
    if EXFIL_CAP_N <= 0:
        return False
    if chash in _exfil_hashes:
        return False
    return len(_exfil_hashes) >= EXFIL_CAP_N


def _exfil_add_locked(chash):
    """Record a DISTINCT auto-approved cmd_hash against the window's exfil-cap. CALLER MUST HOLD _lock.
    No-op when the cap is disabled (keeps the set empty so a later enable starts clean)."""
    if EXFIL_CAP_N > 0:
        _exfil_hashes.add(chash)


def dispatch(req, chash, tier, confined, elevated=True):
    """NON-BLOCKING. Binding-check in the caller thread, then run the relay in a WORKER thread so the
    control plane keeps polling Telegram + honoring revoke/expiry (a slow exec cannot stall approvals).
    Everything runs as the owner unix user on the HMAC-ticketed exec-argv-elevated path (elevated is always
    True now — hestia-agent is retired as a run identity). `confined` is decided by the approval PATH in
    process() and CARRIED here; dispatch()/_run_exec READ it and NEVER recompute it from the re-derived tier
    (recomputing would flip a human-approved escalation-lever command back to confined and silently defeat
    the lever). BINDING (anti-swap/TOCTOU): the stored req (box file already unlink'd, never re-read) is
    re-hashed and policy_tier() re-derived; refuse on hash OR tier drift, or when the concurrent-exec cap is
    hit."""
    if broker.cmd_hash(req) != chash:
        broker.audit({"decision": "BINDING_MISMATCH", "approved_hash": chash, "request_id": req.get("request_id"), "argv": req.get("argv")})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "binding mismatch (approved-hash != dispatch-hash)"}); return
    re_tier = broker.policy_tier(req)
    if re_tier != tier:
        broker.audit({"decision": "BINDING_MISMATCH", "reason": "tier drift", "approved": tier,
                      "redecided": re_tier, "request_id": req["request_id"]})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "binding mismatch (tier drift)"}); return
    token = str(uuid.uuid4())
    with _lock:
        capped = len(_inflight) >= MAX_INFLIGHT
        if not capped:
            _inflight[token] = {"req": req, "chash": chash, "tier": tier, "confined": confined,
                                "elevated": elevated, "proc": None, "revoked": False, "started": now()}
    if capped:
        broker.audit({"decision": "REFUSED", "reason": "inflight cap", "request_id": req["request_id"]})
        session_log(req["request_id"], "🚫", req["argv"], "refused: too many concurrent commands")
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": "too many concurrent commands"}); return
    _k = "auto" if confined else "approved"                  # confined auto vs human-approved (both run as the owner)
    session_log(req["request_id"], "⏳", req["argv"], "running", kind=_k)
    threading.Thread(target=_run_exec, args=(token,), daemon=True).start()


def _run_exec(token):
    """Worker thread: relay the command, honor revoke, ALWAYS free the _inflight slot + write exactly one
    result (even on crash) so the box is never stranded and the concurrency slot never leaks. Touches
    shared state (_inflight) only under _lock; never holds the lock across a blocking call."""
    with _lock:
        info = _inflight.get(token)
        if not info: return
        req, chash = info["req"], info["chash"]
        tier = info.get("tier", info.get("decision"))      # tier drives the audit; legacy dicts carry 'decision'
        elevated = info.get("elevated", False)
        wo = info.get("wo", False)                         # legacy _build_payload scope (revoke/kill test dicts only)
        confined = info.get("confined", True)              # READ from _inflight (set by process()); never recompute.
        #   Fail-CLOSED default: an _inflight dict that somehow lacks the key confines rather than runs open.
        pre_ticket = info.get("ticket")                    # auto path pre-mints the ticket UNDER _lock
    status, reason, rc, out_b, err_b = "error", "worker error", None, b"", b""
    try:
        if elevated:
            # Auto (reviewed/free-zone) tickets are minted inside _finalize_review's _lock hold and carried
            # here; the human-approved dispatch() path mints inline. Either way NEVER recompute confined.
            ticket = pre_ticket or _mint("run", {"session_id": req["session_id"], "request_id": req["request_id"],
                                                 "cwd": req["cwd"], "run_as": ELEV_RUNAS, "argv": req["argv"],
                                                 "exec_token": token, "confined": confined})
            if not ticket:
                with _lock: _inflight.pop(token, None)
                session_log(req["request_id"], "🚫", req["argv"], "refused: elevation not configured")
                write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                                 "reason": "elevation not configured (no key)"}); return
            cmd = [TAILSCALE, "ssh", TARGET, "--", "sudo", "-n", ELEV_WRAPPER, "run", ticket]
        else:
            cmd = [TAILSCALE, "ssh", TARGET, "--", EXECARGV, _build_payload(req, wo, token)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with _lock:
            info = _inflight.get(token)
            revoked_early = info is None or info.get("revoked")
            if info is not None: info["proc"] = proc
        if revoked_early:                                    # revoke fired before/just as we spawned
            try: proc.kill()
            except Exception: pass
            _do_remote_kill(token, elevated)
        try:
            out_b, err_b = proc.communicate(timeout=EXEC_TIMEOUT); rc = proc.returncode
        except subprocess.TimeoutExpired:
            try: proc.kill()
            except Exception: pass
            _do_remote_kill(token, elevated)
            try: out_b, err_b = proc.communicate(timeout=10)
            except Exception: pass
            rc = 124
        with _lock:
            info = _inflight.get(token)
            revoked = revoked_early or bool(info and info.get("revoked"))
        status, reason = ("revoked" if revoked else ("timeout" if rc == 124 else "executed")), None
        if status == "revoked":      _log_status = "revoked"
        elif status == "timeout":    _log_status = "⏱ timeout"
        elif rc == 0:                _log_status = "✓ exit0"
        else:                        _log_status = "✗ exit%d" % rc
        session_log(req["request_id"], ("⏱" if rc == 124 else ("✓" if rc == 0 else "✗")),
                    req["argv"], _log_status)
    except Exception as e:
        broker.audit({"decision": "WORKER_ERROR", "err": repr(e), "request_id": req["request_id"]})
        status, reason = "error", "worker error (spawn/exec failed)"
        session_log(req["request_id"], "✗", req["argv"], "✗ error")     # terminal: crashed worker counts as failed
    finally:
        with _lock: _inflight.pop(token, None)               # ALWAYS free the slot (no leak -> no wedge)
    out = out_b[:MAXOUT].decode("utf-8", "replace"); err = err_b[:4096].decode("utf-8", "replace")
    res = {"request_id": req["request_id"], "status": status, "stdout": out, "stderr": err,
           "cmd_hash": chash, "elevated": elevated, "confined": confined}
    if not elevated: res["workspace_only"] = wo
    if elevated: res["run_as"] = ELEV_RUNAS
    if rc is not None: res["exit"] = rc
    if reason: res["reason"] = reason
    try:
        broker.audit({"decision": tier, "phase": status, "exit": rc, "cmd_hash": chash, "elevated": elevated,
                      "confined": confined, "request_id": req["request_id"], "argv": req["argv"],
                      "run_as": ELEV_RUNAS if elevated else None})
    except Exception: pass
    write_result(req["request_id"], res)                     # exactly one result, always


def _teardown_reviews(reason):
    """Tear down every in-flight review. ATOMICALLY (under _lock) mark each review revoked=True AND remove
    it from _reviews, capturing its (req, chash) so we can route it to a refused reply after releasing the
    lock. Popping the review makes the still-running _review_worker see `info is None` in _finalize_review
    and return WITHOUT a second reply (teardown owns the reply — no double-write, no dangling request).
    Callers (revoke_all/_end_session) must hold NO lock when they call this."""
    with _lock:
        dead = list(_reviews.items())
        for _rid, rv in dead: rv["revoked"] = True
        _reviews.clear()
    for _rid, rv in dead:
        session_log(rv["req"]["request_id"], "🚫", rv["req"].get("argv"), "refused: " + _san(str(reason))[:60])
        write_result(rv["req"]["request_id"], {"request_id": rv["req"]["request_id"],
                                               "status": "refused", "reason": reason})
    if dead:
        broker.audit({"decision": "REVIEWS_TORN_DOWN", "count": len(dead), "reason": reason})


def revoke_all(reason="revoked by owner"):
    """Owner /panic or Revoke button: close the session, KILL every in-flight exec (local + target process-
    group kill), tear down every in-flight review, and deny all pending approvals. Main-thread only."""
    global _session_until, _session_until_wall
    _teardown_reviews(reason)                                 # in-flight reviews are revoked + refused
    with _lock:
        tokens = list(_inflight.keys())
        for t in tokens: _inflight[t]["revoked"] = True
        procs = [(t, _inflight[t].get("proc"), _inflight[t].get("elevated", False)) for t in tokens]
    killed = len(procs)                                        # captured BEFORE _end_session clears; feeds the ⚪ header
    pend = list(_pending.items()); _pending.clear()
    broker.audit({"decision": "REVOKE", "reason": reason, "inflight": killed, "pending": len(pend)})
    for t, proc, elev in procs:
        if proc:
            try: proc.kill()
            except Exception: pass
        threading.Thread(target=_do_remote_kill, args=(t, elev), daemon=True).start()   # elevated-aware, off the main loop
    for nonce, p in pend:
        resolve_msg(p["chat_id"], p["msg_id"], "🛑 Revoked.")
        if p["kind"] in ("session_open", "session_close"):
            _control_refuse(p["req"], reason)
        else:
            refuse(p["req"], p["chash"], reason)
    if _session_phase == "open":                              # only render/close a window that was actually open
        _end_session("revoked", killed=killed)                # renders ⚪ 'revoked — N killed' from live counts/log, then clears
    else:
        _session_until = _session_until_wall = 0.0            # defensive: ensure closed even with no open window


def refuse(req, chash, reason):
    broker.audit({"decision": "REFUSED", "reason": reason, "cmd_hash": chash,
                  "request_id": req["request_id"], "argv": req.get("argv")})
    session_log(req["request_id"], "🚫", req.get("argv"), "refused: " + _san(str(reason))[:60])
    write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": reason})


def _ask(kind, req, tier, chash, secs, reason=""):
    """Send an approval button + register a pending nonce. Everything runs as the owner unix user now, so
    the human-fallback button is a single uniform "command" kind that conveys the RISK class, not an
    identity choice; on approve it dispatches UNCONFINED (the human explicitly authorized it). The approved
    `tier` is stored for the dispatch-time re-derivation binding. Send failure -> refuse."""
    if len(_pending) >= MAX_PENDING:                        # bound outstanding buttons (anti-flood/fatigue)
        broker.audit({"decision": "REFUSED", "reason": "pending approvals cap", "request_id": req["request_id"]})
        refuse(req, chash, "too many pending approvals")
        return
    nonce = secrets.token_urlsafe(18)
    try:
        mid = send_button(_fmt(req, chash, tier, reason), nonce)
    except Exception as e:
        mid = None; broker.audit({"decision": "SEND_FAIL", "err": str(e), "request_id": req["request_id"]})
    if not mid:
        refuse(req, chash, "could not deliver approval button")
        return
    _pending[nonce] = {"kind": kind, "req": req, "chash": chash, "tier": tier, "reason": reason,
                       "chat_id": OWNER_ID, "msg_id": mid, "deadline": now() + secs}
    if kind == "command":                                      # awaiting row for a human-tapped command
        g = "🔴" if tier == broker.HARD_DENY else "🔵"          # row glyph matches the button (🔴 floor / 🔵 reviewer)
        session_log(req["request_id"], g, req.get("argv"), g + " awaiting your tap", kind="approved")


def _control_refuse(req, reason):
    """Refuse a CONTROL op (session_open/close) — like refuse() but writes NO cmd_hash (control ops
    are never classified/hashed). Always leaves the box a valid result."""
    broker.audit({"decision": "REFUSED", "reason": reason, "request_id": req["request_id"],
                  "kind": req.get("kind")})
    write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": reason})


def _ask_session(req, intent, secs, msg_id=None):
    """Send/EDIT the 🟡 session-open button + register a session_open pending nonce. `intent` MUST already
    be canonical (_canon_intent applied by the caller at intake). msg_id=None -> fresh send_button; msg_id
    set (T10 re-anchor) -> edit the live session message in place. On any send failure or pending-cap hit,
    control-refuse (never a dangling request)."""
    nonce = secrets.token_urlsafe(18)
    if msg_id is None:
        try:
            mid = send_button(_fmt_session_open(intent, secs), nonce)
        except Exception as e:
            mid = None; broker.audit({"decision": "SEND_FAIL", "err": str(e), "request_id": req["request_id"]})
    else:
        mid = msg_id                                   # T10 re-anchor edits the live message IN PLACE; keep its id
        kb = {"inline_keyboard": [[{"text": "✅ Approve", "callback_data": nonce + ":A"},
                                   {"text": "⛔ Deny",    "callback_data": nonce + ":D"}]]}
        try: tg("editMessageText", chat_id=OWNER_ID, message_id=mid,
                text=_fmt_session_open(intent, secs), reply_markup=kb)   # repaint 🟢 -> 🟡 re-anchor prompt, fresh nonce
        except Exception: pass
    if len(_pending) >= MAX_PENDING or mid is None:
        broker.audit({"decision": "REFUSED", "reason": "pending cap or send fail",
                      "request_id": req["request_id"], "kind": "session_open"})
        _control_refuse(req, "could not deliver session button")
        return
    _pending[nonce] = {"kind": "session_open", "req": req, "intent": intent, "secs": secs,
                       "chat_id": OWNER_ID, "msg_id": mid, "deadline": now() + SESSION_ASK_SECS}


def _handle_session_open(req):
    """Route a validated session_open control op. Canonicalize the agent-proposed intent ONCE here, then:
    if a window is already open, re-anchor; else ask the owner to approve the canonical intent/duration."""
    intent = _canon_intent(req["intent"])              # THE one sanitize+cap; anchor==display from here on
    if session_open():
        # re-anchor: re-prompt over the live session message; the OLD window keeps enforcing the OLD
        # intent until the owner re-approves. The anchor is NOT mutated here (only on_approve swaps it).
        broker.audit({"decision": "SESSION_REANCHOR", "old_intent": _session_intent,
                      "new_intent": intent, "request_id": req["request_id"]})
        _ask_session(req, intent, int(req["duration_secs"]), msg_id=_session_msg_id)
        return
    _ask_session(req, intent, int(req["duration_secs"]))


def _handle_session_close(req):
    """Agent asks to close the current window. If open -> end it (⚪ ended-by-agent) and ack; if there is
    no open session, still ack idempotently so the box never blocks (with a reason for observability)."""
    if session_open():
        _end_session("agent")
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "session_closed"})
    else:
        write_result(req["request_id"], {"request_id": req["request_id"],
                                         "status": "session_closed", "reason": "no open session"})


def _intent_hash(intent):
    """Hash of the trusted session-intent anchor. A review is registered with the hash of the intent it
    was ISSUED under; the worker's pre-dispatch re-check requires this hash to still match the LIVE
    _session_intent, so a mid-session re-anchor (_handle_session_open while open) invalidates every
    in-flight review. Any intent string maps to a stable hex digest."""
    return hashlib.sha256(str(intent).encode("utf-8")).hexdigest()


def _review(req, tier):
    """Layer-2 seam. Ask the LLM reviewer whether a SOFT_DENY/ALLOW command may auto-run. Returns
    (verdict, ok, reason): verdict is "ALLOW" (auto, confined) or "HUMAN" (fall to the owner button); reason
    is the BLOCK reason for the 🔵 button ('' on ALLOW/transport-fail) — fail CLOSED; `ok` is True for a
    CLEAN reviewer answer (ALLOW or BLOCK/HUMAN, incl. the deterministic disabled/keyless fail-closed) and
    False only for a transport FAILURE (timeout/HTTP/malformed) — the signal the circuit breaker records.
    Called by _review_worker with _lock RELEASED (the HTTPS call must never stall the main poll loop).
    Stubbed in tests (may return a bare verdict string, which the worker normalizes to a clean success)."""
    try:
        cfg = _reviewer_cfg()
        return reviewer.review_outcome(_session_intent, req["argv"], req.get("cwd", ""), tier, cfg)
    except Exception as e:                                  # any reviewer wiring error -> fail CLOSED to human;
        broker.audit({"decision": "REVIEWER_ERROR", "err": repr(e), "request_id": req["request_id"]})
        return reviewer.HUMAN, False, ""                   #   count it as a breaker FAILURE (reviewer unusable)


def _spawn_review(req, tier, chash):
    """Register an in-flight review in _reviews and launch the worker thread — UNLESS the concurrency cap
    or the circuit breaker says no. UNDER _lock, gate on BOTH:
      len(_reviews) < HESTIA_MAX_REVIEWS   (bounded in-flight reviews; excess = backpressure)
      _breaker.allow()                     (open breaker after N reviewer outages -> skip the reviewer)
    If EITHER fails, do NOT register a review and do NOT spawn a worker — fall CLOSED to the owner button
    (_ask_human), same as every other over-cap path. On the happy path, register with a per-review `revoked`
    flag + the _intent_hash it is ISSUED under, then run the HTTPS review + fail-closed finalize OFF the main
    loop in _review_worker (the poll loop keeps honoring revoke/expiry meanwhile). _ask_human/_lock
    re-entrancy: the gate decision is made UNDER _lock, but _ask_human is called AFTER releasing it."""
    review_id = str(uuid.uuid4())
    with _lock:
        inflight   = len(_reviews)
        over_cap   = inflight >= HESTIA_MAX_REVIEWS
        # call allow() ONCE, under the lock (it can transition OPEN->HALF-OPEN and must not be re-called).
        allowed    = _breaker.allow()
        gated      = over_cap or not allowed
        if not gated:
            _reviews[review_id] = {"req": req, "chash": chash, "tier": tier,
                                   "revoked": False, "intent_hash": _intent_hash(_session_intent)}
    if gated:                                              # backpressure/breaker-open -> owner button (no worker)
        broker.audit({"decision": "REVIEW_BACKPRESSURE", "inflight": inflight,
                      "max_reviews": HESTIA_MAX_REVIEWS, "over_cap": over_cap, "breaker_open": not allowed,
                      "request_id": req["request_id"], "argv": req["argv"]})
        _ask_human(req, tier, chash)
        return
    threading.Thread(target=_review_worker, args=(review_id,), daemon=True).start()


def _review_worker(review_id):
    """WORKER THREAD (off the main poll loop): run the LLM review with _lock RELEASED, record the outcome
    into the circuit breaker (a clean verdict — ALLOW or BLOCK/HUMAN — is a breaker SUCCESS; a transport
    failure is a breaker FAILURE), then finalize fail-CLOSED. Immediately before dispatching an ALLOW, re-
    acquire _lock and ATOMICALLY re-check _session_phase=='open' AND this review's `revoked` flag is false
    AND _session_intent's hash is unchanged; the ticket is minted INSIDE the same _lock hold (via
    _finalize_review). Any failure -> HUMAN, or a terminal "session closed" reply if the window closed
    (never a dangling request). Gates on _session_phase, NOT _session_until (because _end_session sets
    phase='ended' before it clears the clocks). The review is removed from _reviews on completion. A stubbed
    _review may return a bare verdict string -> normalized to a clean success (ok=True)."""
    with _lock:
        info = _reviews.get(review_id)
        if info is None:                                   # already torn down (revoke_all/_end_session)
            return
        req, tier = info["req"], info["tier"]
    outcome = _review(req, tier)                            # HTTPS call — _lock RELEASED (never stall the loop)
    reason = ""
    if isinstance(outcome, tuple):                         # (verdict, ok[, reason]) — breaker-aware contract
        verdict, ok = outcome[0], outcome[1]
        if len(outcome) > 2:
            reason = outcome[2]                            # BLOCK reason for the 🔵 owner button (untrusted)
    else:                                                  # legacy bare-string verdict -> clean success
        verdict, ok = outcome, True
    with _lock:
        _breaker.record(ok)                                # feed the breaker under _lock (record is not thread-safe)
    _finalize_review(review_id, verdict, reason)


def _finalize_review(review_id, verdict, reason=""):
    """Under a SINGLE _lock hold: pop the review, re-check phase/revoked/intent, and (on a passing clean
    ALLOW) mint the ticket + reserve the _inflight slot — all atomically, so a concurrent
    revoke/close/re-anchor cannot slip a ticket into a closing window (mint-under-lock). Decides the outcome
    under the lock, then acts (dispatch/HUMAN/terminal reply) AFTER releasing it, because
    session_log()/_ask_human() re-acquire _lock and must never be called while it is held."""
    outcome, token = "human", None
    with _lock:
        info = _reviews.pop(review_id, None)
        if info is None:                                   # torn down mid-review -> revoke_all/_end_session owns the reply
            return
        req, chash, tier = info["req"], info["chash"], info["tier"]
        phase_open   = _session_phase == "open"
        not_revoked  = not info["revoked"]
        intent_same  = _intent_hash(_session_intent) == info["intent_hash"]
        if verdict == reviewer.ALLOW and phase_open and not_revoked and intent_same:
            # BINDING (anti-swap/TOCTOU): re-hash + re-derive tier on the STORED req before minting.
            if broker.cmd_hash(req) == chash and broker.policy_tier(req) == tier:
                # Exfil-cap: reviewer-ALLOW auto commands count too — the (N+1)th DISTINCT auto cmd_hash
                # this window falls to the HUMAN button (checked+recorded under THIS lock hold, atomically
                # with the mint, so a concurrent finalize can't race past N).
                if _exfil_would_exceed_locked(chash):
                    outcome = "exfil_human"
                else:
                    capped = len(_inflight) >= MAX_INFLIGHT
                    if not capped:
                        token  = str(uuid.uuid4())
                        ticket = _mint("run", {"session_id": req["session_id"], "request_id": req["request_id"],
                                               "cwd": req["cwd"], "run_as": ELEV_RUNAS, "argv": req["argv"],
                                               "exec_token": token, "confined": True})
                        if ticket:
                            _exfil_add_locked(chash)       # commit the distinct auto hash against the cap
                            _inflight[token] = {"req": req, "chash": chash, "tier": tier, "confined": True,
                                                "elevated": True, "ticket": ticket, "proc": None,
                                                "revoked": False, "started": now()}
                            outcome = "dispatch"
                        else:                              # elevation not configured -> refuse (never auto without a key)
                            outcome = "no_key"
                    else:
                        outcome = "capped"
            else:
                outcome = "drift"
        elif not phase_open:
            outcome = "closed"                             # window closed mid-review -> terminal reply
        else:
            outcome = "human"                              # BLOCK / revoked / intent-drift while open -> owner button
    # --- act OUTSIDE the lock ---
    if outcome == "dispatch":
        session_log(req["request_id"], "🟢", req["argv"], "🟢 auto·reviewed", kind="auto")
        session_log(req["request_id"], "⏳", req["argv"], "running", kind="auto")
        threading.Thread(target=_run_exec, args=(token,), daemon=True).start()
    elif outcome == "closed":
        broker.audit({"decision": "REVIEW_WINDOW_CLOSED", "request_id": req["request_id"], "argv": req["argv"]})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "session closed — not executed"})
    elif outcome == "capped":
        session_log(req["request_id"], "🚫", req["argv"], "refused: too many concurrent commands")
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "too many concurrent commands"})
    elif outcome == "no_key":
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "elevation not configured"})
    elif outcome == "drift":
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "binding mismatch (tier/hash drift)"})
    elif outcome == "exfil_human":                        # exfil-cap hit -> owner button, UNCONFINED
        broker.audit({"decision": "EXFIL_CAP", "cap": EXFIL_CAP_N, "cmd_hash": chash,
                      "request_id": req["request_id"], "argv": req["argv"]})
        _ask_human(req, tier, chash)
    else:                                                  # "human": fail-closed -> owner button, UNCONFINED
        _ask_human(req, tier, chash, reason)               # reviewer BLOCK reason surfaced on the 🔵 button


def process(req, tier, chash):
    """Route a validated request by the deterministic policy_tier() (the sole floor authority).
    `confined` is decided HERE by the approval PATH — auto (FREE_ZONE / reviewer-ALLOW) -> True; ANY
    human-tap path (HARD_DENY tap, reviewer-BLOCK tap, escalation lever) -> False — and carried on
    _inflight; dispatch()/_run_exec READ it, never recompute it from the re-derived tier. policy_tier()
    runs FIRST: REFUSE/HARD_DENY are absolute (the reviewer + the box `elevate` lever can never lower them).
    (main thread)"""
    global _session_cmd_count
    if not session_open():
        broker.audit({"decision": "REFUSED", "reason": "no open session", "request_id": req["request_id"]})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "no open session — run session-open first"})
        return
    _session_cmd_count += 1
    if _session_cmd_count > SESSION_CMD_BUDGET:             # bound total activity per open window
        broker.audit({"decision": "REFUSED", "reason": "session command budget exceeded",
                      "count": _session_cmd_count, "request_id": req["request_id"]})
        session_log(req["request_id"], "🚫", req["argv"], "refused: budget exceeded")
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "session command budget exceeded (open a new session)"})
        return

    # 1) REFUSE — HARDLINE, unapprovable by ANY button (no approve path at all).
    if tier == broker.REFUSE:
        broker.audit({"decision": "REFUSED", "reason": "policy REFUSE (unapprovable)", "tier": tier,
                      "request_id": req["request_id"], "argv": req["argv"]})
        session_log(req["request_id"], "🚫", req["argv"], "refused (unapprovable)")
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "refused (unapprovable — hardline)"})
        return

    # 2) HARD_DENY — intent-proof; the reviewer NEVER sees it. Human button, UNCONFINED on approve.
    #    The box `elevate` lever cannot touch this path (it only re-routes ALLOW/SOFT_DENY).
    if tier == broker.HARD_DENY:
        _ask_human(req, tier, chash, broker.hard_deny_reason(req))
        return

    # AUTO-path preconditions (userns). Runs AFTER the absolute REFUSE/HARD_DENY floor (which never auto-run)
    # and BEFORE any auto tier. If the reviewer is disabled/keyless, elevation is absent, or the userns probe
    # fails, the AUTO path is unavailable: divert EVERY remaining (auto-tier) command — FREE_ZONE and the
    # SOFT_DENY/ALLOW middle alike — to the HUMAN button via _ask_human. This fails CLOSED to the owner's tap
    # (never a silent exec-time refuse, never an unconfined/unconfinable auto-run). The escalation lever below
    # is already a human-tap path, so this gate never blocks it wrongly.
    if not _auto_preconditions_ok():
        broker.audit({"decision": "AUTO_PRECONDITION_FALLBACK", "tier": tier,
                      "reviewer": bool(REVIEWER_ENABLED and REVIEWER_KEY), "elevation": elevation_enabled(),
                      "userns": _userns_ok(), "request_id": req["request_id"], "argv": req["argv"]})
        _ask_human(req, tier, chash)
        return

    # 3) FREE_ZONE — read-only inspector, non-secret operand. Auto, no LLM, CONFINED.
    #    Exfil-cap: the (N+1)th DISTINCT auto command per window falls to the HUMAN button (UNCONFINED on
    #    approve). Checked BEFORE dispatch, atomically recorded under _lock so concurrent auto commits can't
    #    race past N. FREE_ZONE reads count too.
    if tier == broker.FREE_ZONE:
        with _lock:
            capped = _exfil_would_exceed_locked(chash)
            if not capped:
                _exfil_add_locked(chash)
        if capped:
            broker.audit({"decision": "EXFIL_CAP", "cap": EXFIL_CAP_N, "cmd_hash": chash,
                          "request_id": req["request_id"], "argv": req["argv"]})
            _ask_human(req, tier, chash)
            return
        dispatch(req, chash, tier, confined=True)
        return

    # 4) SOFT_DENY | ALLOW — the reviewer middle.
    #    Escalation lever: the box `elevate` flag re-admitted as a NON-security request — it routes an
    #    ALLOW/SOFT_DENY command to the HUMAN button to run UNCONFINED (network/personal access). It CANNOT
    #    lower security (destination is a human tap) and never bypasses the floor.
    if req.get("elevate"):
        _ask_human(req, tier, chash)
        return
    # Layer 2 — the reviewer runs in a WORKER thread off the main poll loop. The review is registered in
    # _reviews; the worker re-checks phase/revoked/intent + mints under _lock before an ALLOW dispatch,
    # falls to HUMAN otherwise (fail-closed), and replies terminally if the window closed.
    _spawn_review(req, tier, chash)


def _ask_human(req, tier, chash, reason=""):
    """Send the owner approval button for a command that must run UNCONFINED on approve (HARD_DENY,
    reviewer-BLOCK, or the escalation lever). Uniform run-as is the owner unix user; the button conveys the
    RISK class, not an identity choice. Elevation (the HMAC ticket) is a hard dependency for EVERY executing
    outcome now, so a missing key -> refuse (never a silent unconfined exec)."""
    if not elevation_enabled():
        broker.audit({"decision": "REFUSED", "reason": "elevation not configured", "request_id": req["request_id"]})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": "elevation not configured"})
        return
    _ask("command", req, tier, chash, CMD_SECS, reason)


def on_approve(p):
    global _session_until, _session_until_wall, _session_cmd_count
    global _session_intent, _session_secs, _session_phase, _session_msg_id
    if p["kind"] == "session_open":
        _session_until      = now() + p["secs"]                 # BOTH clocks to the APPROVED duration
        _session_until_wall = time.time() + p["secs"]
        _session_cmd_count  = 0
        _exfil_hashes.clear()                                   # exfil-cap distinct-hash set is per-window
        _session_intent     = p["intent"]                       # trusted anchor == canonical == button text
        _session_secs       = p["secs"]
        _session_log.clear(); _reset_counts()
        _session_phase      = "open"
        _session_msg_id     = p["msg_id"]                       # REUSE the button msg -> edit in place
        broker.audit({"decision": "SESSION_OPENED", "secs": p["secs"], "intent": p["intent"], "by": OWNER_ID})
        _flush_session_msg(force=True)                          # synchronous edit: 🟡 button -> 🟢 session
        write_result(p["req"]["request_id"],
                     {"request_id": p["req"]["request_id"], "status": "session_opened", "secs": p["secs"]})
        return
    # Any human-tapped command (HARD_DENY / reviewer-BLOCK / escalation lever) approved by the owner:
    # dispatch UNCONFINED (confined=False) on the ticket path — the owner explicitly authorized it.
    resolve_msg(p["chat_id"], p["msg_id"], "✅ " + _shell(p["req"]["argv"]) + " — approved, running (see session)")
    dispatch(p["req"], p["chash"], p["tier"], confined=False)


def on_deny(p):
    if p["kind"] == "session_open":
        # denied session_open. If a window is still open, this was a RE-ANCHOR — the OLD window survives
        # unchanged, so revert the live message to the 🟢 open render (intent anchor untouched). If no
        # window is open, it was a first-open denial -> a plain refusal edit. Either way: refused result.
        if session_open():
            resolve_msg(p["chat_id"], p["msg_id"], _render_session())
            _flush_session_msg(force=True)                     # re-attach the 🛑 Revoke keyboard (T9)
        else:
            resolve_msg(p["chat_id"], p["msg_id"], "⛔ Session denied.")
        broker.audit({"decision": "SESSION_DENIED", "request_id": p["req"]["request_id"]})
        write_result(p["req"]["request_id"], {"request_id": p["req"]["request_id"],
                                              "status": "refused", "reason": "owner denied session"})
        return
    _dargv = p.get("req", {}).get("argv")
    resolve_msg(p["chat_id"], p["msg_id"], ("⛔ " + _shell(_dargv) + " — denied") if _dargv else "⛔ Denied.")
    if p["kind"] == "session_close":                            # control op, no chash
        _control_refuse(p["req"], "owner denied")
        return
    refuse(p["req"], p["chash"], "owner denied")
    session_log(p["req"]["request_id"], "⛔", p["req"].get("argv"), "⛔ denied")


def poll_telegram():
    global _tg_offset
    try:
        params = {"timeout": 2, "allowed_updates": ["callback_query", "message"]}
        if _tg_offset is not None: params["offset"] = _tg_offset
        r = tg("getUpdates", **params)
    except Exception:
        return
    for u in r.get("result", []):
        _tg_offset = u["update_id"] + 1
        # owner text commands: /panic, /revoke  (kill switch, independent of any button)
        msg = u.get("message")
        if msg:
            if msg.get("from", {}).get("id") == OWNER_ID and isinstance(msg.get("text"), str) \
               and msg["text"].strip().split()[0:1] in (["/panic"], ["/revoke"]):
                revoke_all("owner /panic")
                try: tg("sendMessage", chat_id=OWNER_ID, text="🛑 Revoked: session closed, in-flight killed, pending denied.")
                except Exception: pass
            continue
        cq = u.get("callback_query")
        if not cq: continue
        if cq.get("from", {}).get("id") != OWNER_ID:           # OWNER-ONLY: checked before any state change
            try: tg("answerCallbackQuery", callback_query_id=cq["id"], text="")
            except Exception: pass
            broker.audit({"decision": "CALLBACK_DROPPED", "reason": "non-owner", "from": cq.get("from", {}).get("id")})
            continue
        data = cq.get("data", "")
        if data == "REVOKE":                                   # persistent revoke button
            try: tg("answerCallbackQuery", callback_query_id=cq["id"], text="")
            except Exception: pass
            revoke_all("owner revoke button"); continue
        nonce, _, act = data.rpartition(":")
        p = _pending.pop(nonce, None)                          # compare-and-set: single use (main-thread only)
        try: tg("answerCallbackQuery", callback_query_id=cq["id"], text="")
        except Exception: pass
        if not p: continue
        (on_approve if act == "A" else on_deny)(p)


def check_expiries():
    global _session_until, _session_until_wall
    t = now()
    for nonce in [k for k, p in _pending.items() if t > p["deadline"]]:
        p = _pending.pop(nonce)
        resolve_msg(p["chat_id"], p["msg_id"], "⌛ Timed out — auto-denied.")
        if p["kind"] in ("session_open", "session_close"):
            _control_refuse(p["req"], "approval timeout (auto-deny)")
        else:
            refuse(p["req"], p["chash"], "approval timeout (auto-deny)")
            session_log(p["req"]["request_id"], "⌛", p["req"].get("argv"), "⌛ approval timeout")
    # close the session at the EARLIER of the monotonic or wall-clock deadline (NTP step-forward safe)
    if (_session_until and t > _session_until) or (_session_until_wall and time.time() > _session_until_wall):
        broker.audit({"decision": "SESSION_CLOSED", "reason": "expired"})
        _end_session("expired")                                # renders ⚪ summary, then clears clocks/intent/log/counts


def scan_incoming():
    try: names = sorted(os.listdir(INCOMING))
    except FileNotFoundError: return
    for name in names[:25]:
        if name.endswith(".part") or not broker.UUID_RE.match(name):
            continue
        path = os.path.join(INCOMING, name)
        try:
            with open(path, "rb") as f: raw = f.read(broker.MAXSIZE + 1)
        except OSError:
            continue
        os.unlink(path)                                        # take ownership (at-most-once)
        try:
            req = broker.validate_request(raw, name)
        except broker.Reject as e:
            broker.audit({"decision": "REJECT", "reason": str(e), "request_id": name})
            session_log(name, "🚫", "(malformed)", "rejected")
            write_result(name, {"request_id": name, "status": "rejected", "reason": str(e)})
            continue
        kind = req.get("kind", "command")
        if kind == "session_open":
            _handle_session_open(req)                           # never classified/hashed
            continue
        if kind == "session_close":
            _handle_session_close(req)
            continue
        chash = broker.cmd_hash(req)
        tier = broker.policy_tier(req)                           # policy_tier() is the sole floor, runs FIRST
        broker.audit({"decision": tier, "cmd_hash": chash,
                      "request_id": req["request_id"], "cwd": req["cwd"], "argv": req["argv"],
                      "elevate": req["elevate"], "session_open": session_open()})
        process(req, tier, chash)


def run_daemon():
    if not TOKEN: sys.exit("FATAL: TELEGRAM_BROKER_BOT_TOKEN not set")
    broker.audit({"decision": "BROKER_START", "owner": OWNER_ID, "target": TARGET})
    # Startup preflight: probe userns / reviewer-auth / elevation, audit them, and DM the owner ONE warning
    # if auto-mode is degraded — so a silent misconfig can never quietly turn into 'every command asks'. Also
    # warms the reviewer TLS session as a side effect. Runs OFF the main loop (its HTTPS probe must never
    # stall the start of polling — same rule as _review_worker); never raises.
    _userns_ok()   # populate the userns-probe cache on THIS thread first, so the preflight thread and the
                   # poll loop never race the (unlocked) cache write — both then read the settled value.
    threading.Thread(target=_preflight, daemon=True).start()
    while True:
        try:
            poll_telegram(); scan_incoming(); check_expiries(); _flush_session_msg()
        except Exception as e:                               # a transient error must NOT kill the only approval path
            broker.audit({"decision": "LOOP_ERROR", "err": repr(e)})
        time.sleep(0.5)                                       # floor: avoid busy-loop on persistent fast-return


# ---- selftest: exercise the FULL approval->relay->result loop without the box/mover ----
def selftest(argv_cmd, workspace_only_hint):
    if not TOKEN: sys.exit("FATAL: token not set")
    global _session_until, _session_until_wall, OUTGOING
    import tempfile
    OUTGOING = tempfile.mkdtemp(prefix="hestia-selftest-")      # writable by whoever runs the test
    os.environ.setdefault("HESTIA_AUDIT", os.path.join(OUTGOING, "audit.log"))
    broker.AUDIT_LOG = os.environ["HESTIA_AUDIT"]
    _session_until = now() + SESSION_SECS                      # force a session open (both clocks)
    _session_until_wall = time.time() + SESSION_SECS
    rid = "00000000-0000-4000-8000-000000000001"
    req = {"v": 1, "session_id": rid, "request_id": rid, "cwd": "/srv/projects",
           "elevate": False, "argv": argv_cmd}
    tier = broker.policy_tier(req)
    chash = broker.cmd_hash(req)
    print(f"[selftest] argv={argv_cmd} tier={tier}")
    if tier == broker.FREE_ZONE:
        print("[selftest] free-zone — executing directly (no button):")
        rc, out, err = relay_exec(req, True); print(f"  exit={rc}\n  stdout={out!r}\n  stderr={err!r}"); return
    nonce = secrets.token_urlsafe(18)
    mid = send_button(_fmt(req, chash, tier), nonce)
    _pending[nonce] = {"kind": "command", "req": req, "chash": chash, "tier": tier,
                       "chat_id": OWNER_ID, "msg_id": mid, "deadline": now() + CMD_SECS}
    print(f"[selftest] sent Telegram button to owner {OWNER_ID}; tap Approve or Deny (≤{CMD_SECS}s)…")
    while _pending:
        poll_telegram(); check_expiries(); time.sleep(1)
    rp = os.path.join(OUTGOING, rid)                            # dispatch is async; wait for the worker result
    for _ in range(EXEC_TIMEOUT + 5):
        if os.path.exists(rp) or not _inflight:
            if os.path.exists(rp): break
        time.sleep(1)
    print("[selftest] resolved. Check your Telegram message + the result below (if approved):")
    if os.path.exists(rp):
        print("  result:", open(rp).read()); os.unlink(rp)
    else:
        print("  (no result file — denied/timed out)")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "selftest":
        cmd = sys.argv[2:] or ["cat", "/etc/hostname"]
        selftest(cmd, False)
    elif len(sys.argv) >= 2 and sys.argv[1] == "run":
        run_daemon()
    else:
        sys.stderr.write("usage: brokerd.py {run | selftest [argv...]}\n"); sys.exit(2)
