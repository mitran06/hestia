#!/usr/bin/env python3
"""brokerd.py — Hestia capability broker DAEMON (Part 5: Telegram approval + session lifecycle).

Runs as hestia-broker. Imports the Part-3 policy engine (broker.py) and adds the human-approval
boundary enforced OUTSIDE the LLM: a Telegram inline button, owner-id filtered, single-use nonce.

Flow per request (delivered by the mover into incoming/):
  validate -> classify:
    REJECT        -> audit + refusal result.
    (need a session) if no OPEN session: send a SESSION button (Approve Nm / Deny); on approve the
                     window opens and the triggering command is re-processed.
    IN_SCOPE      -> (session open) execute on the target with workspace_only=true, no button.
    NEEDS_BUTTON  -> (session open) send a per-COMMAND button showing argv + cmd_hash; on approve
                     execute with workspace_only=false; on deny/timeout -> refusal.
Security: only callback_query from OWNER_ID is honored; each button carries a single-use nonce
(compare-and-set: consumed on first tap; replays -> "already handled"); unanswered -> auto-deny;
broker restart => in-memory state lost => all sessions CLOSED (fail-closed). Commands execute via
`tailscale ssh <target-host> -- exec-argv <BASE64>` (single opaque token; shell=False on the target)."""
import os, sys, json, time, base64, secrets, urllib.request, subprocess, importlib.util, threading, uuid, hmac, hashlib

# --- load the Part-3 policy engine (same dir) ---
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("broker", os.path.join(_here, "broker.py"))
broker = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(broker)

TOKEN     = os.environ.get("TELEGRAM_BROKER_BOT_TOKEN", "")
OWNER_ID  = int(os.environ.get("HESTIA_OWNER_ID", "0"))          # REQUIRED: your Telegram user id (0 = fail-closed, matches nobody)
TARGET      = os.environ.get("HESTIA_TARGET_HOST", "hestia-agent@127.0.0.1")  # REQUIRED: user@<target-tailscale-host>
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

MAX_INFLIGHT   = int(os.environ.get("HESTIA_MAX_INFLIGHT", "6"))     # concurrent relayed execs cap
MAX_PENDING    = int(os.environ.get("HESTIA_MAX_PENDING", "20"))     # outstanding approval buttons cap
SESSION_CMD_BUDGET = int(os.environ.get("HESTIA_SESSION_CMD_BUDGET", "40"))  # commands per open window
SESSION_LOG_WINDOW  = int(os.environ.get("HESTIA_SESSION_LOG_WINDOW", "20"))   # last-N log lines shown; older rolled up
SESSION_FLUSH_MIN_S = float(os.environ.get("HESTIA_SESSION_FLUSH_MIN_S", "1")) # min seconds between non-forced edits (coalesce)

# --- shared state (guarded by _lock; workers touch _inflight + write results) ---
_lock = threading.Lock()
_session_until      = 0.0     # monotonic deadline; 0 = CLOSED
_session_until_wall = 0.0     # wall-clock deadline (dual-clock: session closes at the EARLIER of the two)
_session_cmd_count  = 0       # commands consumed in the current window (budget-limited)
_pending  = {}                # nonce -> dict(kind, req, chash, chat_id, msg_id, deadline)
_inflight = {}                # exec_token -> dict(req, chash, decision, wo, proc, revoked, started)
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
    _session_phase = "ended"
    _session_end_reason = reason
    _session_killed = killed
    _flush_session_msg(force=True)                 # renders ⚪ from the still-populated log/counts
    # T10 FULL pending-invalidation: the window just closed, so EVERY outstanding pending is a stale
    # button that must NEVER dispatch into the closed window. Invalidate ALL of them — commands/elevated
    # via refuse() (with their chash), control ops (session_open re-anchor / session_close) via
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
        head = ["🟢 Session open · expires " + _hhmm(until_wall),
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


def _san(s):
    """Escape control chars/newlines so attacker-controlled argv/cwd CANNOT forge extra lines in the
    Telegram button (the owner must see the true command, not a spoofed one)."""
    return "".join(c if (c.isprintable() and c not in "\r\n\t") else "\\x%02x" % ord(c) for c in str(s))


def _fmt(req, chash, kind):
    # argv rendered as a JSON array (unambiguous quoting/splitting) then control-char-escaped; capped.
    cmd = _san(json.dumps(req["argv"]))
    if len(cmd) > 400: cmd = cmd[:400] + "…(truncated; hash binds full cmd)"
    cwd = _san(req["cwd"])[:200]
    if kind == "session":
        head = "🟡 The agent wants to START A SESSION and run:"
        note = "  note: opens a ~10-min work session; each sensitive command still asks separately"
    elif kind == "elevated":
        head = "🔴 The agent requests an ELEVATED command:"
        note = f"  runs as: {ELEV_RUNAS} — FULL owner-file access, OUTSIDE the /srv/projects sandbox"
    else:
        head = "🔵 The agent requests (needs approval):"
        note = "  runs as: hestia-agent (limited — cannot read your files), OUTSIDE the sandbox"
    return f"{head}\n\n  cwd: {cwd}\n  cmd: {cmd}\n  hash: {chash[:16]}…\n{note}\n\nApprove?"


def _canon_intent(intent):
    """Canonicalize the agent-proposed intent ONCE, at intake: sanitize control chars and cap length.
    The RESULT is the single canonical string used everywhere — shown on the 🟡 button, promoted to
    the trusted anchor _session_intent on approval, and rendered verbatim in the 🟢/⚪ header. This is
    what makes displayed == stored == anchor hold (decision ④)."""
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
        _session_log[request_id] = {"icon": icon, "argv": _san(str(argv))[:80],
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


def dispatch(req, chash, decision, elevated=False):
    """NON-BLOCKING. Binding-check in the caller thread, then run the relay in a WORKER thread so the
    control plane keeps polling Telegram + honoring revoke/expiry (a slow exec cannot stall approvals).
    BINDING (anti-swap/TOCTOU): the stored req (box file already unlink'd, never re-read) is re-hashed
    and the decision re-derived; scope mode (workspace_only) is PINNED to the pure classifier. `elevated`
    is set by the broker (never box data) and routes to the HMAC-ticketed exec-argv-elevated path. Refuse
    on any drift, or when the concurrent-exec cap is hit."""
    if broker.cmd_hash(req) != chash:
        broker.audit({"decision": "BINDING_MISMATCH", "approved_hash": chash, "request_id": req.get("request_id"), "argv": req.get("argv")})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "binding mismatch (approved-hash != dispatch-hash)"}); return
    re_decision, _ = broker.classify(req)
    if re_decision != decision:
        broker.audit({"decision": "BINDING_MISMATCH", "reason": "decision drift", "approved": decision,
                      "redecided": re_decision, "request_id": req["request_id"]})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused",
                                         "reason": "binding mismatch (decision drift)"}); return
    if elevated and re_decision == broker.IN_SCOPE:          # never elevate an auto-run/free-zone command
        broker.audit({"decision": "BINDING_MISMATCH", "reason": "elevated+IN_SCOPE", "request_id": req["request_id"]})
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": "elevation binding error"}); return
    wo = (re_decision == broker.IN_SCOPE)
    token = str(uuid.uuid4())
    with _lock:
        capped = len(_inflight) >= MAX_INFLIGHT
        if not capped:
            _inflight[token] = {"req": req, "chash": chash, "decision": decision, "wo": wo,
                                "elevated": elevated, "proc": None, "revoked": False, "started": now()}
    if capped:
        broker.audit({"decision": "REFUSED", "reason": "inflight cap", "request_id": req["request_id"]})
        session_log(req["request_id"], "🚫", req["argv"], "refused: too many concurrent commands")
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": "too many concurrent commands"}); return
    _k = "elevated" if elevated else ("auto" if wo else "approved")
    session_log(req["request_id"], "🔴" if elevated else "⏳", req["argv"], "running", kind=_k)
    threading.Thread(target=_run_exec, args=(token,), daemon=True).start()


def _run_exec(token):
    """Worker thread: relay the command, honor revoke, ALWAYS free the _inflight slot + write exactly one
    result (even on crash) so the box is never stranded and the concurrency slot never leaks. Touches
    shared state (_inflight) only under _lock; never holds the lock across a blocking call."""
    with _lock:
        info = _inflight.get(token)
        if not info: return
        req, wo, chash, decision, elevated = info["req"], info["wo"], info["chash"], info["decision"], info.get("elevated", False)
    status, reason, rc, out_b, err_b = "error", "worker error", None, b"", b""
    try:
        if elevated:
            ticket = _mint("run", {"session_id": req["session_id"], "request_id": req["request_id"],
                                   "cwd": req["cwd"], "run_as": ELEV_RUNAS, "argv": req["argv"], "exec_token": token})
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
           "cmd_hash": chash, "elevated": elevated}
    if not elevated: res["workspace_only"] = wo
    if elevated: res["run_as"] = ELEV_RUNAS
    if rc is not None: res["exit"] = rc
    if reason: res["reason"] = reason
    try:
        broker.audit({"decision": decision, "phase": status, "exit": rc, "cmd_hash": chash, "elevated": elevated,
                      "request_id": req["request_id"], "argv": req["argv"], "run_as": ELEV_RUNAS if elevated else None})
    except Exception: pass
    write_result(req["request_id"], res)                     # exactly one result, always


def revoke_all(reason="revoked by owner"):
    """Owner /panic or Revoke button: close the session, KILL every in-flight exec (local + target process-
    group kill), and deny all pending approvals. Main-thread only."""
    global _session_until, _session_until_wall
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


def _ask(kind, req, decision, chash, secs):
    """Send an approval button + register a pending nonce. If the send fails, refuse (no dangling)."""
    if len(_pending) >= MAX_PENDING:                        # bound outstanding buttons (anti-flood/fatigue)
        broker.audit({"decision": "REFUSED", "reason": "pending approvals cap", "request_id": req["request_id"]})
        refuse(req, chash, "too many pending approvals")
        return
    nonce = secrets.token_urlsafe(18)
    try:
        mid = send_button(_fmt(req, chash, kind), nonce)
    except Exception as e:
        mid = None; broker.audit({"decision": "SEND_FAIL", "err": str(e), "request_id": req["request_id"]})
    if not mid:
        refuse(req, chash, "could not deliver approval button")
        return
    _pending[nonce] = {"kind": kind, "req": req, "chash": chash, "decision": decision,
                       "chat_id": OWNER_ID, "msg_id": mid, "deadline": now() + secs}
    if kind in ("command", "elevated"):                        # scope kind for the 🔵 awaiting row
        session_log(req["request_id"], "🔵", req.get("argv"), "🔵 awaiting your tap",
                    kind=("elevated" if kind == "elevated" else "approved"))


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
    if a window is already open, re-anchor (T10 rewrites this branch); else ask the owner to approve the
    canonical intent/duration."""
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


def process(req, decision, chash):
    """Route a validated request. Sends buttons / executes / refuses. (main thread)"""
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
    if decision == broker.IN_SCOPE:
        dispatch(req, chash, decision)
    elif req.get("elevate"):                                # broker DECIDES elevation; box 'elevate' is a hint
        if not elevation_enabled():
            broker.audit({"decision": "REFUSED", "reason": "elevation not configured", "request_id": req["request_id"]})
            write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": "elevation not configured"})
            return
        _ask("elevated", req, decision, chash, CMD_SECS)
    else:  # NEEDS_BUTTON within an open session (hestia-agent, non-elevated)
        _ask("command", req, decision, chash, CMD_SECS)


def on_approve(p):
    global _session_until, _session_until_wall, _session_cmd_count
    global _session_intent, _session_secs, _session_phase, _session_msg_id
    if p["kind"] == "session_open":
        _session_until      = now() + p["secs"]                 # BOTH clocks to the APPROVED duration
        _session_until_wall = time.time() + p["secs"]
        _session_cmd_count  = 0
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
    if p["kind"] == "elevated":
        resolve_msg(p["chat_id"], p["msg_id"], f"✅ ELEVATED approved — running as {ELEV_RUNAS}…")
        dispatch(p["req"], p["chash"], p["decision"], elevated=True)
    else:
        resolve_msg(p["chat_id"], p["msg_id"], "✅ Approved — running…")
        dispatch(p["req"], p["chash"], p["decision"])


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
    resolve_msg(p["chat_id"], p["msg_id"], "⛔ Denied.")
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
            _handle_session_close(req)                          # T6 completes this handler
            continue
        chash = broker.cmd_hash(req)
        decision, reason = broker.classify(req)
        broker.audit({"decision": decision, "reason": reason, "cmd_hash": chash,
                      "request_id": req["request_id"], "cwd": req["cwd"], "argv": req["argv"],
                      "elevate": req["elevate"], "session_open": session_open()})
        process(req, decision, chash)


def run_daemon():
    if not TOKEN: sys.exit("FATAL: TELEGRAM_BROKER_BOT_TOKEN not set")
    broker.audit({"decision": "BROKER_START", "owner": OWNER_ID, "target": TARGET})
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
    decision, reason = broker.classify(req)
    chash = broker.cmd_hash(req)
    print(f"[selftest] argv={argv_cmd} decision={decision} ({reason})")
    if decision == broker.IN_SCOPE:
        print("[selftest] free-zone — executing directly (no button):")
        rc, out, err = relay_exec(req, True); print(f"  exit={rc}\n  stdout={out!r}\n  stderr={err!r}"); return
    nonce = secrets.token_urlsafe(18)
    mid = send_button(_fmt(req, chash, "command"), nonce)
    _pending[nonce] = {"kind": "command", "req": req, "chash": chash, "decision": decision,
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
