#!/usr/bin/env python3
"""hestia-relay — box-side client for the Hestia capability broker. Runs INSIDE the box as the agent user.
This is the confined agent's ONLY interface to the target / host: it drops a request in the outbox (which the
mover shuttles to the broker) and waits for the result the broker returns via the inbox. The agent has no
key and no route — it can only REQUEST; the owner's Telegram button decides whether anything runs.

  hestia-relay session-open --intent STR --duration SECS   # submit; 0=open 3=pending 77=denied
  hestia-relay session-status                              # poll;   0=open 3=pending 77/75/124
  hestia-relay session-close
  hestia-relay [--cwd DIR] [--elevate] [--timeout S] -- CMD [ARG...]

session-open does NOT block until the owner taps. The calling agent's terminal tool kills any command after a fixed deadline, so a blocking wait could never succeed — it just orphaned the owner's
tap in the inbox. Instead session-open polls for OPEN_WAIT seconds and returns 3 (PENDING); the
agent then polls session-status in fresh short calls until it returns 0.

--elevate is a HINT only (the broker decides independently and the owner sees an ELEVATED button).
Exit code mirrors the command's exit on success; special codes for refused/denied/revoked/timeout."""
import os, sys, json, time, uuid, tempfile


def _num(v):
    """Coerce a persisted field to a number; a corrupt/str value must not raise mid-arithmetic."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0

OUTBOX  = os.environ.get("HESTIA_OUTBOX", "/home/hestia/broker/outbox")
INBOX   = os.environ.get("HESTIA_INBOX",  "/home/hestia/broker/inbox")
SESSFILE = os.environ.get("HESTIA_SESSION_FILE", os.path.expanduser("~/.hestia-relay-session"))
STATEFILE = os.environ.get("HESTIA_RELAY_STATE", os.path.expanduser("~/.hestia-relay-state"))
DEFAULT_TIMEOUT = int(os.environ.get("HESTIA_RELAY_TIMEOUT", "900"))
# The caller (the agent's terminal tool) KILLS any command after a fixed deadline (120s in the
# reference agent). A session-open that blocks awaiting a human Telegram tap can
# never outlive that, so we poll for a short window and hand back a "pending" code instead.
OPEN_WAIT = min(int(os.environ.get("HESTIA_OPEN_WAIT", "90")), 100)   # clamp: must stay < the 120s kill
# Set HESTIA_DEFAULT_CWD to the OWNER's home on the target (see OWNER_UNIX_USER in hestia.env).
# Must NOT point at a retired/empty staging dir — a bare `ls`/`find` would then succeed with no
# output, which invites the agent to confabulate instead of reporting "nothing found".
DEFAULT_CWD = os.environ.get("HESTIA_DEFAULT_CWD", "/home/owner")
MAXREQ = 65536
PENDING = 3          # "no owner decision yet — poll session-status"
_CODES = {"refused": 77, "rejected": 78, "revoked": 75, "timeout": 124, "error": 70}


def session_id():
    """Stable per-box session id (correlation only; the security window is broker-side)."""
    try:
        s = open(SESSFILE).read().strip()
        if s:
            return s
    except OSError:
        pass
    s = str(uuid.uuid4())
    try:
        open(SESSFILE, "w").write(s)
    except OSError:
        pass
    return s


def build_request(cwd, argv, elevate):
    rid = str(uuid.uuid4())
    return rid, {"v": 1, "session_id": session_id(), "request_id": rid,
                 "cwd": cwd, "elevate": bool(elevate), "argv": list(argv)}


def build_control(kind, extra):
    """Build a non-command control op (session_open / session_close). No cwd/argv/elevate."""
    rid = str(uuid.uuid4())
    return rid, {"v": 1, "session_id": session_id(), "request_id": rid, "kind": kind, **extra}


def submit(req_id, req):
    """Atomic: write <uuid>.tmp then rename to <uuid> so the mover never sees a partial file."""
    body = json.dumps(req).encode("utf-8")
    if len(body) > MAXREQ:
        raise ValueError(f"request too large ({len(body)} > {MAXREQ})")
    tmp = os.path.join(OUTBOX, req_id + ".tmp")
    with open(tmp, "wb") as f:
        f.write(body)
    os.replace(tmp, os.path.join(OUTBOX, req_id))


def wait_result(req_id, timeout):
    """Poll the inbox for this request's result. timeout=0 = a single non-blocking check."""
    path = os.path.join(INBOX, req_id)
    deadline = time.monotonic() + timeout
    bad = 0
    while True:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    res = json.load(f)
            except (OSError, ValueError):        # ValueError = malformed JSON *or* partial UTF-8
                bad += 1
                if bad >= 10:                    # permanently unparseable: give up TERMINALLY rather
                    try: os.unlink(path)         # than re-reading it forever and reporting "pending"
                    except OSError: pass
                    return {"status": "error", "reason": "unparseable broker result"}
                time.sleep(0.3)
                if time.monotonic() >= deadline:
                    return None
                continue
            try:
                os.unlink(path)
            except OSError:
                pass
            return res if isinstance(res, dict) else {"status": "error", "reason": "malformed result"}
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.5)


def read_state():
    # ValueError covers BOTH JSONDecodeError and UnicodeDecodeError (a partially-written file).
    try:
        with open(STATEFILE) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return None
    return st if isinstance(st, dict) else None


def write_state(st):
    """Returns True only if the state actually hit disk. Callers MUST check: a silently-dropped
    write is how the owner's decision gets consumed from the inbox and then lost forever."""
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(STATEFILE) or ".", prefix=".relaystate-")
        with os.fdopen(fd, "w") as f:
            json.dump(st, f)
        os.replace(tmp, STATEFILE)      # unique tmp per process — a shared name lets two writers
        return True                     # truncate the same inode and render unparseable JSON
    except OSError:
        return False


def clear_state():
    try:
        os.unlink(STATEFILE)
    except OSError:
        pass


def _settle(st, res):
    """Fold a broker result into the persisted session state and return the exit code.

    The result file is consumed exactly once, so the outcome MUST be cached here — otherwise a
    second `session-status` would see an empty inbox and wrongly report "pending" forever."""
    status = res.get("status")
    if not isinstance(status, str) or not status:
        status = "error"                      # schema drift must be TERMINAL, never "pending forever"
        st["reason"] = "broker result carried no usable status"
    else:
        st["reason"] = str(res.get("reason", ""))
    st["status"] = status
    st["decided"] = True                      # explicit flag — do NOT rely on truthiness of `status`
    if status == "session_opened":
        # Prefer the broker's GRANTED duration over the box's REQUESTED one, and start the clock at
        # submit time, not observation time — the result may have sat unread in the inbox for a while,
        # so counting from now would over-report the remaining window.
        try:
            st["duration_secs"] = int(res.get("secs") or st.get("duration_secs") or 0)
        except (TypeError, ValueError):
            pass
        st["opened_at"] = _num(st.get("submitted_at")) or time.time()
    if not write_state(st):
        # The decision is already consumed from the inbox; if we cannot persist it, say so LOUDLY
        # rather than returning success and stranding the agent on "pending" forever.
        sys.stderr.write(f"[hestia-relay] FATAL: could not persist session state; "
                         f"the broker decision '{status}' is lost. Re-run session-open.\n")
        return 70
    if status == "session_opened":
        return 0
    sys.stderr.write(f"[hestia-relay] {status}: {st['reason']}\n")
    return _CODES.get(status, 1)


def session_status():
    """Report the pending/decided session WITHOUT blocking past the caller's kill deadline."""
    st = read_state()
    if not st or not st.get("request_id"):
        sys.stderr.write("[hestia-relay] no session — run session-open first\n")
        return 1
    status = st.get("status")
    if st.get("decided") and status == "session_opened":
        # A revoke/expiry can land AFTER the open settled; check once (non-blocking) so we do not
        # keep reporting OPEN for a session the owner already killed.
        late = wait_result(st["request_id"], 0)
        if late is not None:
            return _settle(st, late)
        left = _num(st.get("opened_at")) + _num(st.get("duration_secs")) - time.time()
        if left <= 0:
            sys.stderr.write("[hestia-relay] session expired — open a new one\n")
            return 124
        sys.stderr.write(f"[hestia-relay] session OPEN, ~{int(left)}s left\n")
        return 0
    if st.get("decided"):                        # already decided (refused/revoked/…) — replay it
        sys.stderr.write(f"[hestia-relay] {status}: {st.get('reason', '')}\n")
        return _CODES.get(status, 1)
    res = wait_result(st["request_id"], OPEN_WAIT)
    if res is None:
        sys.stderr.write("[hestia-relay] pending — owner has not decided yet; poll session-status again\n")
        return PENDING
    return _settle(st, res)


def main(av):
    if len(av) > 1 and av[1] == "session-status":
        return session_status()
    if len(av) > 1 and av[1] == "command-status":
        return command_status()
    if len(av) > 1 and av[1] in ("session-open", "session-close"):
        args = av[2:]
        if av[1] == "session-open":
            intent = None; secs = None; i = 0
            while i < len(args):
                a = args[i]
                if a == "--intent" and i + 1 < len(args): intent = args[i + 1]; i += 2
                elif a == "--duration" and i + 1 < len(args):
                    try: secs = int(args[i + 1])
                    except ValueError: sys.stderr.write("[hestia-relay] --duration must be an integer\n"); return 2
                    i += 2
                else: i += 1
            if intent is None or secs is None:
                sys.stderr.write("usage: hestia-relay session-open --intent STR --duration SECS\n"); return 2
            rid, req = build_control("session_open", {"intent": intent, "duration_secs": secs})
            ok_status = "session_opened"
        else:
            rid, req = build_control("session_close", {})
            ok_status = "session_closed"
        try:
            submit(rid, req)
        except (OSError, ValueError) as e:
            sys.stderr.write(f"[hestia-relay] submit failed: {e}\n"); return 1
        sys.stderr.write(f"[hestia-relay] submitted {av[1]} {rid}; awaiting owner…\n")
        if av[1] == "session-close":
            res = wait_result(rid, OPEN_WAIT)
            if res is None:
                # Do NOT clear state here: the broker window may well still be open, and wiping the
                # local record makes session-status say "no session", which invites the agent to open
                # a SECOND session (another owner tap) for a session it already has.
                sys.stderr.write("[hestia-relay] no close confirmation; the session may still be open "
                                 "(it expires on its own). Check session-status.\n")
                return 124
            status = res.get("status")
            if status == ok_status:
                clear_state()
                return 0
            sys.stderr.write(f"[hestia-relay] {status}: {res.get('reason', '')}\n")
            return _CODES.get(status, 1)
        # session-open: record the pending request FIRST so the owner's tap is never orphaned, then
        # poll only briefly. Returning PENDING is normal, not an error — the agent polls
        # session-status in fresh short calls instead of holding one long-lived blocked command.
        st = {"request_id": rid, "intent": intent, "duration_secs": secs,
              "submitted_at": time.time(), "status": None, "decided": False, "reason": ""}
        if not write_state(st):
            sys.stderr.write("[hestia-relay] FATAL: cannot write session state; a tap would be lost. "
                             "Fix the state file path before retrying.\n")
            return 70
        res = wait_result(rid, OPEN_WAIT)
        if res is None:
            sys.stderr.write("[hestia-relay] pending — owner has not tapped yet. "
                             "Poll `hestia-relay session-status` (exit 3 = still pending, 0 = open).\n")
            return PENDING
        return _settle(st, res)
    cwd, elevate, timeout, out_argv = DEFAULT_CWD, False, DEFAULT_TIMEOUT, None
    args = av[1:]; i = 0
    while i < len(args):
        a = args[i]
        if a == "--cwd" and i + 1 < len(args): cwd = args[i + 1]; i += 2
        elif a == "--elevate": elevate = True; i += 1
        elif a == "--timeout" and i + 1 < len(args): timeout = int(args[i + 1]); i += 2
        elif a == "--": out_argv = args[i + 1:]; break
        else: out_argv = args[i:]; break
    if not out_argv:
        sys.stderr.write("usage: hestia-relay [--cwd DIR] [--elevate] [--timeout S] -- CMD [ARG...]\n"); return 2
    rid, req = build_request(cwd, out_argv, elevate)
    try:
        submit(rid, req)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"[hestia-relay] submit failed: {e}\n"); return 1
    wait = min(timeout, OPEN_WAIT)
    sys.stderr.write(f"[hestia-relay] submitted {rid} ({'ELEVATED ' if elevate else ''}{' '.join(out_argv)}); "
                     f"awaiting owner approval + result (≤{wait}s, then PENDING)…\n")
    # A command that needs an owner tap (--elevate, secrets, sudo, egress, or a reviewer fail-closed)
    # has the SAME 120s-kill problem session-open had: waiting the full DEFAULT_TIMEOUT here would be
    # killed and orphan the result. Cap the in-process wait and hand back PENDING to be polled.
    write_cmd_state(rid, out_argv, elevate)
    res = wait_result(rid, wait)
    if res is None:
        sys.stderr.write("[hestia-relay] pending — no result yet (owner has not tapped, or it is still "
                         "running). Poll `hestia-relay command-status` (exit 3 = still pending).\n")
        return PENDING
    return _finish_cmd(res)


def write_cmd_state(rid, argv, elevate):
    st = read_state() or {}
    st["cmd"] = {"request_id": rid, "argv": list(argv), "elevate": bool(elevate),
                 "submitted_at": time.time()}
    write_state(st)


def _finish_cmd(res):
    if res.get("stdout"): sys.stdout.write(res["stdout"])
    if res.get("stderr"): sys.stderr.write(res["stderr"])
    status = res.get("status")
    if res.get("truncated"): sys.stderr.write("[hestia-relay] (output truncated by broker)\n")
    st = read_state()
    if st and st.pop("cmd", None) is not None:
        write_state(st)
    if status == "executed":
        try:
            return int(res.get("exit", 0))
        except (TypeError, ValueError):
            return 0
    sys.stderr.write(f"[hestia-relay] {status}: {res.get('reason', '')}\n")
    return _CODES.get(status, 1)


def command_status():
    """Poll the last relayed COMMAND without blocking past the caller's kill deadline."""
    st = read_state() or {}
    cmd = st.get("cmd")
    if not cmd or not cmd.get("request_id"):
        sys.stderr.write("[hestia-relay] no command pending\n")
        return 1
    res = wait_result(cmd["request_id"], OPEN_WAIT)
    if res is None:
        sys.stderr.write("[hestia-relay] pending — still no result; poll command-status again\n")
        return PENDING
    return _finish_cmd(res)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
