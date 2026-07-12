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

# --- shared state (guarded by _lock; workers touch _inflight + write results) ---
_lock = threading.Lock()
_session_until      = 0.0     # monotonic deadline; 0 = CLOSED
_session_until_wall = 0.0     # wall-clock deadline (dual-clock: session closes at the EARLIER of the two)
_session_cmd_count  = 0       # commands consumed in the current window (budget-limited)
_pending  = {}                # nonce -> dict(kind, req, chash, chat_id, msg_id, deadline)
_inflight = {}                # exec_token -> dict(req, chash, decision, wo, proc, revoked, started)
_tg_offset = None


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
        write_result(req["request_id"], {"request_id": req["request_id"], "status": "refused", "reason": "too many concurrent commands"}); return
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
    except Exception as e:
        broker.audit({"decision": "WORKER_ERROR", "err": repr(e), "request_id": req["request_id"]})
        status, reason = "error", "worker error (spawn/exec failed)"
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
    _session_until = 0.0; _session_until_wall = 0.0
    with _lock:
        tokens = list(_inflight.keys())
        for t in tokens: _inflight[t]["revoked"] = True
        procs = [(t, _inflight[t].get("proc"), _inflight[t].get("elevated", False)) for t in tokens]
    pend = list(_pending.items()); _pending.clear()
    broker.audit({"decision": "REVOKE", "reason": reason, "inflight": len(procs), "pending": len(pend)})
    for t, proc, elev in procs:
        if proc:
            try: proc.kill()
            except Exception: pass
        threading.Thread(target=_do_remote_kill, args=(t, elev), daemon=True).start()   # elevated-aware, off the main loop
    for nonce, p in pend:
        resolve_msg(p["chat_id"], p["msg_id"], "🛑 Revoked.")
        refuse(p["req"], p["chash"], reason)


def _send_revoke_control():
    try:
        tg("sendMessage", chat_id=OWNER_ID, text="Session is OPEN. Tap to STOP everything (or send /panic):",
           reply_markup={"inline_keyboard": [[{"text": "🛑 Revoke session", "callback_data": "REVOKE"}]]})
    except Exception:
        pass


def refuse(req, chash, reason):
    broker.audit({"decision": "REFUSED", "reason": reason, "cmd_hash": chash,
                  "request_id": req["request_id"], "argv": req.get("argv")})
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


def process(req, decision, chash):
    """Route a validated request. Sends buttons / executes / refuses. (main thread)"""
    global _session_cmd_count
    if not session_open():
        _ask("session", req, decision, chash, SESSION_ASK_SECS)
        return
    _session_cmd_count += 1
    if _session_cmd_count > SESSION_CMD_BUDGET:             # bound total activity per open window
        broker.audit({"decision": "REFUSED", "reason": "session command budget exceeded",
                      "count": _session_cmd_count, "request_id": req["request_id"]})
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
    if p["kind"] == "session":
        _session_until = now() + SESSION_SECS                  # monotonic AND wall-clock deadlines
        _session_until_wall = time.time() + SESSION_SECS
        _session_cmd_count = 0                                  # fresh command budget for the new window
        broker.audit({"decision": "SESSION_OPENED", "secs": SESSION_SECS, "by": OWNER_ID})
        resolve_msg(p["chat_id"], p["msg_id"], f"✅ Session opened ({SESSION_SECS//60} min). Processing…")
        _send_revoke_control()
        process(p["req"], p["decision"], p["chash"])           # re-route the triggering command
    elif p["kind"] == "elevated":
        resolve_msg(p["chat_id"], p["msg_id"], f"✅ ELEVATED approved — running as {ELEV_RUNAS}…")
        dispatch(p["req"], p["chash"], p["decision"], elevated=True)
    else:
        resolve_msg(p["chat_id"], p["msg_id"], "✅ Approved — running…")
        dispatch(p["req"], p["chash"], p["decision"])


def on_deny(p):
    resolve_msg(p["chat_id"], p["msg_id"], "⛔ Denied.")
    refuse(p["req"], p["chash"], "owner denied")


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
            try: tg("answerCallbackQuery", callback_query_id=cq["id"], text="not authorized")
            except Exception: pass
            broker.audit({"decision": "CALLBACK_DROPPED", "reason": "non-owner", "from": cq.get("from", {}).get("id")})
            continue
        data = cq.get("data", "")
        if data == "REVOKE":                                   # persistent revoke button
            try: tg("answerCallbackQuery", callback_query_id=cq["id"], text="revoked")
            except Exception: pass
            revoke_all("owner revoke button"); continue
        nonce, _, act = data.rpartition(":")
        p = _pending.pop(nonce, None)                          # compare-and-set: single use (main-thread only)
        try: tg("answerCallbackQuery", callback_query_id=cq["id"], text="ok" if p else "already handled")
        except Exception: pass
        if not p: continue
        (on_approve if act == "A" else on_deny)(p)


def check_expiries():
    global _session_until, _session_until_wall
    t = now()
    for nonce in [k for k, p in _pending.items() if t > p["deadline"]]:
        p = _pending.pop(nonce)
        resolve_msg(p["chat_id"], p["msg_id"], "⌛ Timed out — auto-denied.")
        refuse(p["req"], p["chash"], "approval timeout (auto-deny)")
    # close the session at the EARLIER of the monotonic or wall-clock deadline (NTP step-forward safe)
    if (_session_until and t > _session_until) or (_session_until_wall and time.time() > _session_until_wall):
        _session_until = 0.0; _session_until_wall = 0.0
        broker.audit({"decision": "SESSION_CLOSED", "reason": "expired"})


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
            write_result(name, {"request_id": name, "status": "rejected", "reason": str(e)})
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
            poll_telegram(); scan_incoming(); check_expiries()
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
