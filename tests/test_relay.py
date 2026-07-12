#!/usr/bin/env python3
"""test_relay.py — box-side client (hestia-relay) round-trip against temp outbox/inbox (no broker needed)."""
import os, sys, json, tempfile, threading, time, importlib.util

TD = tempfile.mkdtemp(prefix="test-relay-")
OUT = os.path.join(TD, "outbox"); IN = os.path.join(TD, "inbox"); os.makedirs(OUT); os.makedirs(IN)
os.environ.update({"HESTIA_OUTBOX": OUT, "HESTIA_INBOX": IN,
                   "HESTIA_SESSION_FILE": os.path.join(TD, "sess"), "HESTIA_RELAY_TIMEOUT": "6"})
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

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
