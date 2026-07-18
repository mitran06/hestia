#!/usr/bin/env python3
"""hestia-relay — box-side client for the Hestia capability broker. Runs INSIDE the box as the agent user.
This is the confined agent's ONLY interface to the target / host: it drops a request in the outbox (which the
mover shuttles to the broker) and waits for the result the broker returns via the inbox. The agent has no
key and no route — it can only REQUEST; the owner's Telegram button decides whether anything runs.

  hestia-relay [--cwd DIR] [--elevate] [--timeout S] -- CMD [ARG...]

--elevate is a HINT only (the broker decides independently and the owner sees an ELEVATED button).
Exit code mirrors the command's exit on success; special codes for refused/denied/revoked/timeout."""
import os, sys, json, time, uuid

OUTBOX  = os.environ.get("HESTIA_OUTBOX", "/home/hestia/broker/outbox")
INBOX   = os.environ.get("HESTIA_INBOX",  "/home/hestia/broker/inbox")
SESSFILE = os.environ.get("HESTIA_SESSION_FILE", os.path.expanduser("~/.hestia-relay-session"))
DEFAULT_TIMEOUT = int(os.environ.get("HESTIA_RELAY_TIMEOUT", "900"))
DEFAULT_CWD = os.environ.get("HESTIA_DEFAULT_CWD", "/srv/projects")
MAXREQ = 65536


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
    path = os.path.join(INBOX, req_id)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    res = json.load(f)
            except (OSError, json.JSONDecodeError):
                time.sleep(0.3); continue
            try:
                os.unlink(path)
            except OSError:
                pass
            return res
        time.sleep(0.5)
    return None


def main(av):
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
        res = wait_result(rid, DEFAULT_TIMEOUT)
        if res is None:
            sys.stderr.write("[hestia-relay] TIMEOUT: no result\n"); return 124
        status = res.get("status")
        if status == ok_status:
            return 0
        sys.stderr.write(f"[hestia-relay] {status}: {res.get('reason', '')}\n")
        return {"refused": 77, "rejected": 78, "revoked": 75, "timeout": 124, "error": 70}.get(status, 1)
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
    sys.stderr.write(f"[hestia-relay] submitted {rid} ({'ELEVATED ' if elevate else ''}{' '.join(out_argv)}); "
                     f"awaiting owner approval + result (≤{timeout}s)…\n")
    res = wait_result(rid, timeout)
    if res is None:
        sys.stderr.write("[hestia-relay] TIMEOUT: no result (target offline? denied? still pending?)\n"); return 124
    if res.get("stdout"): sys.stdout.write(res["stdout"])
    if res.get("stderr"): sys.stderr.write(res["stderr"])
    status = res.get("status")
    if res.get("truncated"): sys.stderr.write("[hestia-relay] (output truncated by broker)\n")
    if status == "executed": return int(res.get("exit", 0))
    sys.stderr.write(f"[hestia-relay] {status}: {res.get('reason', '')}\n")
    return {"refused": 77, "rejected": 78, "revoked": 75, "timeout": 124, "error": 70}.get(status, 1)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
