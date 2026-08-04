#!/usr/bin/env python3
"""test_relay.py — box-side client (hestia-relay) round-trip against temp outbox/inbox (no broker needed)."""
import os, sys, json, tempfile, threading, time, importlib.util

TD = tempfile.mkdtemp(prefix="test-relay-")
OUT = os.path.join(TD, "outbox"); IN = os.path.join(TD, "inbox"); os.makedirs(OUT); os.makedirs(IN)
os.environ.update({"HESTIA_OUTBOX": OUT, "HESTIA_INBOX": IN,
                   "HESTIA_SESSION_FILE": os.path.join(TD, "sess"), "HESTIA_RELAY_TIMEOUT": "6",
                   "HESTIA_RELAY_STATE": os.path.join(TD, "relaystate"), "HESTIA_OPEN_WAIT": "1"})
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("relay", os.path.join(HERE, "..", "agent", "hestia-relay.py"))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)

npass = nfail = 0
def ck(name, cond):
    global npass, nfail
    if cond: npass += 1; print(f"  PASS: {name}")
    else: nfail += 1; print(f"  FAIL: {name}")

print("== request construction ==")
rid, req = R.build_request("/srv/projects", ["ls", "-la"], False)
ck("request_id is a uuid", R.uuid.UUID(rid) and req["request_id"] == rid)
ck("schema fields present", set(req) == {"v", "session_id", "request_id", "cwd", "elevate", "argv"})
ck("elevate flag carried", R.build_request("/srv/projects", ["cat"], True)[1]["elevate"] is True)
ck("stable session_id across calls", R.build_request("/x", ["a"], False)[1]["session_id"] == req["session_id"])

print("== submit is atomic (only final uuid name appears; no .tmp left) ==")
R.submit(rid, req)
names = os.listdir(OUT)
ck("outbox has exactly the uuid file", names == [rid])
ck("submitted file parses back to the request", json.load(open(os.path.join(OUT, rid))) == req)

print("== wait_result round-trip (simulate broker delivering a result to inbox) ==")
rid2, req2 = R.build_request("/srv/projects", ["cat", "x"], False)
def deliver():
    time.sleep(1.0)
    with open(os.path.join(IN, rid2), "w") as f:
        json.dump({"request_id": rid2, "status": "executed", "exit": 0, "stdout": "hello\n", "stderr": ""}, f)
threading.Thread(target=deliver, daemon=True).start()
res = R.wait_result(rid2, 6)
ck("result received", res is not None and res["status"] == "executed" and res["stdout"] == "hello\n")
ck("inbox file consumed after read", not os.path.exists(os.path.join(IN, rid2)))

print("== wait_result times out cleanly when no result appears ==")
t0 = time.monotonic(); res = R.wait_result("99999999-9999-4999-8999-999999999999", 1)
ck("timeout returns None within budget", res is None and time.monotonic() - t0 < 3)

print("== oversize request refused ==")
try:
    R.submit("r", {"argv": ["x" * 70000]}); ck("oversize rejected", False)
except ValueError:
    ck("oversize rejected", True)

print("== build_control: session_open shape ==")
oid, oreq = R.build_control("session_open", {"intent": "deploy the site", "duration_secs": 1800})
ck("session_open kind set", oreq.get("kind") == "session_open")
ck("session_open carries intent", oreq.get("intent") == "deploy the site")
ck("session_open carries duration_secs (int)", oreq.get("duration_secs") == 1800 and isinstance(oreq["duration_secs"], int))
ck("session_open request_id is a uuid matching rid", R.uuid.UUID(oid) and oreq["request_id"] == oid)
ck("session_open exact schema", set(oreq) == {"v", "session_id", "request_id", "kind", "intent", "duration_secs"})
ck("session_open v==1", oreq["v"] == 1)
ck("session_open reuses stable session_id", oreq["session_id"] == req["session_id"])

print("== build_control: session_close shape ==")
cid, creq = R.build_control("session_close", {})
ck("session_close kind set", creq.get("kind") == "session_close")
ck("session_close exact schema (no extra)", set(creq) == {"v", "session_id", "request_id", "kind"})
ck("session_close request_id matches", creq["request_id"] == cid)

print("== main() session-open / session-close exit-code mapping ==")
_orig_build_control = R.build_control
def _spy_build_control(kind, extra):
    rid, req = _orig_build_control(kind, extra)
    _spy_build_control.last_rid = rid
    _spy_build_control.last_req = req
    return rid, req

def run_control(av, broker_result):
    """Run R.main(av) while a thread delivers broker_result (keyed to the generated rid) to the inbox."""
    R.build_control = _spy_build_control
    _spy_build_control.last_rid = None
    ready = threading.Event()
    def deliver():
        for _ in range(200):
            if _spy_build_control.last_rid is not None:
                break
            time.sleep(0.02)
        rid = _spy_build_control.last_rid
        if broker_result is not None and rid is not None:
            res = dict(broker_result); res["request_id"] = rid
            with open(os.path.join(IN, rid), "w") as f:
                json.dump(res, f)
        ready.set()
    th = threading.Thread(target=deliver, daemon=True); th.start()
    try:
        rc = R.main(av)
    finally:
        ready.wait(3); th.join(3); R.build_control = _orig_build_control
    return rc

rc = run_control(["hestia-relay", "session-open", "--intent", "deploy", "--duration", "1800"],
                 {"status": "session_opened", "secs": 1800})
ck("session-open approved -> 0", rc == 0)
ck("session-open sent kind session_open", _spy_build_control.last_req["kind"] == "session_open")
ck("session-open sent intent/duration", _spy_build_control.last_req["intent"] == "deploy" and _spy_build_control.last_req["duration_secs"] == 1800)

rc = run_control(["hestia-relay", "session-open", "--intent", "deploy", "--duration", "1800"],
                 {"status": "refused", "reason": "denied by owner"})
ck("session-open refused -> 77", rc == 77)

rc = run_control(["hestia-relay", "session-open", "--intent", "deploy", "--duration", "1800"], None)
# CONTRACT CHANGE 2026-08-03: no owner decision within the poll window is PENDING (3), not a
# timeout (124). Blocking to 900s here is what got the command killed at 120s by the agent.
ck("session-open no decision yet -> 3 (pending, was 124)", rc == 3)

rc = R.main(["hestia-relay", "session-open", "--duration", "1800"])
ck("session-open missing --intent -> 2", rc == 2)
rc = R.main(["hestia-relay", "session-open", "--intent", "deploy"])
ck("session-open missing --duration -> 2", rc == 2)
rc = R.main(["hestia-relay", "session-open", "--intent", "deploy", "--duration", "notanint"])
ck("session-open non-int --duration -> 2", rc == 2)

rc = run_control(["hestia-relay", "session-close"], {"status": "session_closed"})
ck("session-close closed -> 0", rc == 0)
ck("session-close sent kind session_close", _spy_build_control.last_req["kind"] == "session_close")

rc = run_control(["hestia-relay", "session-close"], None)
ck("session-close no-result (timeout) -> 124", rc == 124)

print("== non-blocking session (2026-08-03 close-out: agent terminal tool kills at 120s) ==")
# Root cause being fixed: hestia-relay blocked up to 900s awaiting a human Telegram tap, but the
# agent's terminal tool kills any command at 120s. Every agent session-open died at exit 124 and
# the owner's later tap landed in an inbox nobody was reading. session-open must now RETURN FAST.

STATE = os.path.join(TD, "relaystate")
os.environ["HESTIA_RELAY_STATE"] = STATE
os.environ["HESTIA_OPEN_WAIT"] = "1"          # poll window, must stay well under the 120s floor
R.STATEFILE = STATE
R.OPEN_WAIT = 1


def _reset_state():
    for p in (STATE,):
        try: os.unlink(p)
        except OSError: pass
    for f in os.listdir(IN):
        os.unlink(os.path.join(IN, f))
    for f in os.listdir(OUT):
        os.unlink(os.path.join(OUT, f))


def _pending_rid():
    """The request_id session-open recorded for later polling."""
    return json.load(open(STATE))["request_id"]


def _drop_result(rid, payload):
    payload = {"request_id": rid, **payload}
    open(os.path.join(IN, rid), "w").write(json.dumps(payload))


# --- session-open must not block ---
_reset_state()
t0 = time.monotonic()
rc = R.main(["hestia-relay", "session-open", "--intent", "back up resume", "--duration", "900"])
el = time.monotonic() - t0
ck("session-open with no tap yet -> 3 (pending), not 124", rc == 3)
ck("session-open returns fast (< 5s, was 900s)", el < 5)
ck("session-open recorded pending request_id in state", os.path.exists(STATE) and _pending_rid())
ck("session-open still wrote a request to the outbox", len(os.listdir(OUT)) == 1)

# --- session-status polls the pending request ---
ck("session-status while pending -> 3", R.main(["hestia-relay", "session-status"]) == 3)

_drop_result(_pending_rid(), {"status": "session_opened", "secs": 900})
ck("session-status after approval -> 0", R.main(["hestia-relay", "session-status"]) == 0)
ck("session-status is idempotent once opened -> 0",
   R.main(["hestia-relay", "session-status"]) == 0)

# --- denial / revoke / rejection map to the documented codes ---
_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "60"])
_drop_result(_pending_rid(), {"status": "refused", "reason": "owner denied"})
ck("session-status after denial -> 77", R.main(["hestia-relay", "session-status"]) == 77)

_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "60"])
_drop_result(_pending_rid(), {"status": "revoked", "reason": "owner revoke button"})
ck("session-status after revoke -> 75", R.main(["hestia-relay", "session-status"]) == 75)

# --- fast tap: result already there when session-open polls ---
_reset_state()


def _fast_tap():
    time.sleep(0.15)
    try: _drop_result(_pending_rid(), {"status": "session_opened", "secs": 60})
    except (OSError, ValueError, KeyError): pass


th = threading.Thread(target=_fast_tap, daemon=True); th.start()
rc = R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "60"])
th.join(timeout=3)
ck("session-open with a fast tap -> 0 (opened within the poll window)", rc == 0)

# --- session-status with no session at all ---
_reset_state()
ck("session-status with no prior session-open -> nonzero",
   R.main(["hestia-relay", "session-status"]) != 0)

# --- expiry is reported, not silently treated as open ---
_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "1"])
_drop_result(_pending_rid(), {"status": "session_opened", "secs": 1})
R.main(["hestia-relay", "session-status"])
time.sleep(1.2)
ck("session-status after the window elapsed -> 124 (expired)",
   R.main(["hestia-relay", "session-status"]) == 124)

# --- the empty-/srv/projects confabulation source ---
ck("DEFAULT_CWD is no longer the retired, EMPTY /srv/projects",
   R.DEFAULT_CWD != "/srv/projects")

print("== fresh-eyes findings (2026-08-03): the decision must never be consumed-then-lost ==")

# The command path had the IDENTICAL 120s-kill bug: any tap-requiring command (--elevate, secrets,
# sudo, egress, reviewer fail-closed) blocked DEFAULT_TIMEOUT=900s.
_reset_state()
t0 = time.monotonic()
rc = R.main(["hestia-relay", "--", "ls", "-la"])
el = time.monotonic() - t0
ck("tap-requiring command -> 3 (pending), not a 900s block", rc == 3)
ck("command returns fast (< 5s)", el < 5)
ck("command recorded pending rid for polling", (read_state_raw := json.load(open(STATE)))["cmd"]["request_id"])
ck("command-status while pending -> 3", R.main(["hestia-relay", "command-status"]) == 3)
_drop_result(read_state_raw["cmd"]["request_id"], {"status": "executed", "exit": 7, "stdout": ""})
ck("command-status after the result lands -> mirrors the command exit", R.main(["hestia-relay", "command-status"]) == 7)
ck("command-status with nothing pending -> 1", R.main(["hestia-relay", "command-status"]) == 1)

# H1: a swallowed state write consumed the decision and stranded the agent on "pending" forever.
_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "60"])
rid = _pending_rid()
_drop_result(rid, {"status": "session_opened", "secs": 60})
_real_write = R.write_state
R.write_state = lambda st: False
rc = R.main(["hestia-relay", "session-status"])
R.write_state = _real_write
ck("un-persistable decision -> loud failure (70), never a false 0", rc == 70)

# H3: a result with no usable status must be TERMINAL, not "pending" forever.
_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "60"])
_drop_result(_pending_rid(), {"reason": "schema drift"})
first = R.main(["hestia-relay", "session-status"])
ck("status-less result is terminal, not pending", first != 3)
ck("status-less result stays terminal on re-poll", R.main(["hestia-relay", "session-status"]) != 3)

# H4: session-close must NOT wipe local state when the close was refused/never confirmed.
_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "600"])
_drop_result(_pending_rid(), {"status": "session_opened", "secs": 600})
R.main(["hestia-relay", "session-status"])
ck("unconfirmed close -> 124", R.main(["hestia-relay", "session-close"]) == 124)
ck("unconfirmed close keeps the session record (no phantom second session)",
   os.path.exists(STATE) and R.main(["hestia-relay", "session-status"]) == 0)

# M1: corrupt state must not raise; wrong-typed fields must not crash the expiry arithmetic.
open(STATE, "w").write("just a string")
ck("scalar-JSON state -> handled, no traceback", R.main(["hestia-relay", "session-status"]) == 1)
open(STATE, "wb").write(b"\xff\xfe not utf8")
ck("non-UTF8 state -> handled, no traceback", R.main(["hestia-relay", "session-status"]) == 1)
json.dump({"request_id": "r", "status": "session_opened", "decided": True,
           "opened_at": "nope", "duration_secs": "60"}, open(STATE, "w"))
ck("string-typed timing fields -> no TypeError", R.main(["hestia-relay", "session-status"]) in (0, 124))

# M3: a revoke landing AFTER the session opened must be observed, not masked by the cache.
_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "600"])
rid = _pending_rid()
_drop_result(rid, {"status": "session_opened", "secs": 600})
R.main(["hestia-relay", "session-status"])
_drop_result(rid, {"status": "revoked", "reason": "owner revoke button"})
ck("revoke after open is seen -> 75, not a stale 0", R.main(["hestia-relay", "session-status"]) == 75)

# M4: the BROKER's granted duration wins over the box's requested one.
_reset_state()
R.main(["hestia-relay", "session-open", "--intent", "x", "--duration", "99999"])
_drop_result(_pending_rid(), {"status": "session_opened", "secs": 1})
R.main(["hestia-relay", "session-status"])
ck("broker-granted secs overrides the box-requested duration",
   json.load(open(STATE))["duration_secs"] == 1)

# M7: OPEN_WAIT must stay under the caller's kill deadline even if misconfigured.
ck("OPEN_WAIT is clamped below the 120s kill", R.OPEN_WAIT <= 100)

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
