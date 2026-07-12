#!/usr/bin/env python3
"""test_brokerd.py — Part 5 state-machine proof with a MOCKED Telegram + relay (no network, no taps).
Verifies: owner-filter drop, nonce single-use / no-double-exec on replay, auto-deny timeout, deny path,
full session lifecycle (idle->session button->open->free-zone auto-run; free-zone while idle does NOT run),
and scan_incoming REJECT vs valid free-zone."""
import os, sys, json, tempfile, importlib.util, base64, time
os.environ["TELEGRAM_BROKER_BOT_TOKEN"] = "dummy"
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("brokerd", os.path.join(HERE, "..", "broker", "brokerd.py"))
bd = importlib.util.module_from_spec(spec); spec.loader.exec_module(bd)
B = bd.broker

TD = tempfile.mkdtemp(prefix="test-brokerd-")
bd.OUTGOING = os.path.join(TD, "outgoing"); os.makedirs(bd.OUTGOING)
bd.INCOMING = os.path.join(TD, "incoming"); os.makedirs(bd.INCOMING)
B.AUDIT_LOG = os.path.join(TD, "audit.log")

# ---- mocks ----
sent, updates, relay_calls, remote_kills, cmds, remote_kills_elev = [], [], [], [], [], []
# provision an elevation key so elevation_enabled() is True in wiring tests
_KF = os.path.join(TD, "elev.key"); open(_KF, "wb").write(os.urandom(48)); bd.ELEV_KEY_FILE = _KF
bd.ELEV_RUNAS = "owner"                    # elevated commands run as the (test) owner user
_mid = [1000]; _uid = [1]; _rid = [0]
def fake_tg(method, **p):
    if method == "sendMessage": _mid[0] += 1; sent.append(p); return {"ok": True, "result": {"message_id": _mid[0]}}
    if method == "getUpdates":  r = updates[:]; updates.clear(); return {"ok": True, "result": r}
    return {"ok": True, "result": {}}
bd.tg = fake_tg

RealThread = bd.threading.Thread          # capture the REAL Thread BEFORE overriding it (used by test M)
class InlineThread:                       # run worker/remote-kill inline -> deterministic tests
    def __init__(self, target=None, args=(), daemon=None): self.t, self.a = target, args
    def start(self):
        if self.t: self.t(*self.a)
bd.threading.Thread = InlineThread

import threading as _threading             # for the blocking-proc Event (Thread itself is overridden above)
class FakePopen:                           # stands in for `tailscale ssh ... exec-argv <payload>`
    block_mode = False                     # True -> communicate() blocks until kill() (a "running" proc)
    raise_mode = False                     # True -> communicate() raises (simulate an exec/pipe failure)
    def __init__(self, cmd, stdout=None, stderr=None):
        self.killed = False; self.returncode = 0; self.ev = _threading.Event()
        if not FakePopen.block_mode: self.ev.set()
        cmds.append(list(cmd))
        try:
            payload = json.loads(base64.b64decode(cmd[-1]).decode())
            relay_calls.append((payload.get("argv"), payload.get("workspace_only"), payload.get("exec_token")))
        except Exception:
            pass
    def communicate(self, timeout=None):
        if FakePopen.raise_mode: raise RuntimeError("simulated communicate failure")
        self.ev.wait(timeout)
        return (b"MOCK\n", b"")
    def kill(self): self.killed = True; self.ev.set()
RealPopen = bd.subprocess.Popen            # capture before overriding (Test N needs a real subprocess)
bd.subprocess.Popen = FakePopen
bd._remote_kill = lambda token, attempts=4: remote_kills.append(token)
bd._remote_kill_elevated = lambda token, attempts=8: remote_kills_elev.append(token)

def cb(nonce, act, uid=None):
    _uid[0] += 1
    updates.append({"update_id": _uid[0], "callback_query":
                    {"id": f"c{_uid[0]}", "from": {"id": uid if uid is not None else bd.OWNER_ID}, "data": f"{nonce}:{act}"}})
def msg(text, uid=None):
    _uid[0] += 1
    updates.append({"update_id": _uid[0], "message": {"from": {"id": uid if uid is not None else bd.OWNER_ID}, "text": text}})
def req(argv, cwd="/srv/projects", elevate=False):
    _rid[0] += 1; rid = "00000000-0000-4000-8000-%012d" % _rid[0]
    return {"v": 1, "session_id": rid, "request_id": rid, "cwd": cwd, "elevate": elevate, "argv": argv}
def submit(r):
    d, why = B.classify(r); bd.process(r, d, B.cmd_hash(r)); return d
def only_nonce():
    assert len(bd._pending) == 1, f"expected 1 pending, got {len(bd._pending)}"; return list(bd._pending)[0]
def result_of(rid):
    p = os.path.join(bd.OUTGOING, rid); return json.load(open(p)) if os.path.exists(p) else None

npass = nfail = 0
def ck(name, cond):
    global npass, nfail
    if cond: npass += 1; print(f"  PASS: {name}")
    else: nfail += 1; print(f"  FAIL: {name}")
def reset():
    bd._pending.clear(); bd._inflight.clear(); relay_calls.clear(); sent.clear(); updates.clear()
    remote_kills.clear(); remote_kills_elev.clear(); cmds.clear()
    bd._session_until, bd._session_until_wall = 0.0, 0.0
    bd._session_cmd_count = 0
def opensess():
    bd._session_until, bd._session_until_wall = bd.now() + 600, time.time() + 600

print("== A: owner-filter + nonce single-use + no-double-exec (session forced open) ==")
reset(); opensess()
r = req(["cat", "/etc/hostname"]); ck("NEEDS_BUTTON classified", submit(r) == B.NEEDS_BUTTON)
n = only_nonce()
cb(n, "A", uid=999999); bd.poll_telegram()
ck("non-owner callback dropped (nonce NOT consumed)", len(bd._pending) == 1 and len(relay_calls) == 0)
cb(n, "A"); bd.poll_telegram()
ck("owner approve executes exactly once", len(relay_calls) == 1 and len(bd._pending) == 0)
ck("approved command ran workspace_only=False", relay_calls[0][1] is False)
cb(n, "A"); bd.poll_telegram()
ck("replay of consumed nonce does NOT re-execute", len(relay_calls) == 1)
ck("result status=executed", (result_of(r["request_id"]) or {}).get("status") == "executed")

print("== B: auto-deny on timeout (unanswered) ==")
reset(); opensess()
r = req(["cat", "/etc/hostname"]); submit(r); n = only_nonce()
bd._pending[n]["deadline"] = bd.now() - 1; bd.check_expiries()
ck("expired pending removed, NOT executed", len(bd._pending) == 0 and len(relay_calls) == 0)
ck("result status=refused (auto-deny)", (result_of(r["request_id"]) or {}).get("status") == "refused")

print("== C: explicit deny ==")
reset(); opensess()
r = req(["cat", "/etc/hostname"]); submit(r); n = only_nonce()
cb(n, "D"); bd.poll_telegram()
ck("deny -> not executed, refused result", len(relay_calls) == 0 and (result_of(r["request_id"]) or {}).get("status") == "refused")

print("== D: session lifecycle (free-zone must NOT auto-run while IDLE) ==")
reset()  # session CLOSED
r = req(["ls", "-la"]); ck("ls is IN_SCOPE", submit(r) == B.IN_SCOPE)
ck("IDLE: free-zone did NOT run; a SESSION button was sent", len(relay_calls) == 0 and bd._pending[only_nonce()]["kind"] == "session")
n = only_nonce(); cb(n, "A"); bd.poll_telegram()
ck("session opened by owner tap", bd.session_open())
ck("triggering free-zone cmd then auto-ran workspace_only=True", len(relay_calls) == 1 and relay_calls[0][1] is True)
r2 = req(["cat", "readme.md"]); submit(r2)
ck("OPEN: another free-zone auto-runs, no button", len(relay_calls) == 2 and len(bd._pending) == 0)
r3 = req(["cat", "/etc/hostname"]); submit(r3)
ck("OPEN: NEEDS_BUTTON still buttons (command)", len(bd._pending) == 1 and list(bd._pending.values())[0]["kind"] == "command")

print("== E: scan_incoming REJECT vs valid free-zone ==")
reset(); opensess()
bad = "11111111-1111-4111-8111-111111111111"
open(os.path.join(bd.INCOMING, bad), "wb").write(b"{ not json")
good = "22222222-2222-4222-8222-222222222222"
open(os.path.join(bd.INCOMING, good), "wb").write(json.dumps(
    {"v": 1, "session_id": good, "request_id": good, "cwd": "/srv/projects", "elevate": False, "argv": ["ls"]}).encode())
bd.scan_incoming()
ck("malformed -> consumed + rejected result", not os.path.exists(os.path.join(bd.INCOMING, bad)) and (result_of(bad) or {}).get("status") == "rejected")
ck("valid free-zone -> auto-ran under open session", any(e[0] == ["ls"] for e in relay_calls))

print("== F: oversized result is truncated to a VALID <= mover-cap JSON (ensure_ascii inflation fix) ==")
MOVER_CAP = 65536
for label, blob in [("2-byte é x50000", "é" * 50000), ("astral 😀 x30000 (surrogate pairs)", "😀" * 30000),
                    ("control \\x01 x40000", "\x01" * 40000)]:
    body = bd._fit_result({"request_id": "r", "status": "executed", "exit": 0, "stdout": blob, "stderr": blob})
    ok_size = len(body) <= bd.RESULT_CAP <= MOVER_CAP
    try: parsed = json.loads(body.decode("utf-8")); valid = True
    except Exception: parsed, valid = None, False
    ck(f"{label}: encoded <= RESULT_CAP({bd.RESULT_CAP}) and < mover cap", ok_size)
    ck(f"{label}: still valid JSON with truncated=True", valid and parsed.get("truncated") is True)
small = bd._fit_result({"request_id": "r", "status": "executed", "exit": 0, "stdout": "hi\n", "stderr": ""})
ps = json.loads(small.decode()); ck("small result passes through untouched (no truncated flag)", "truncated" not in ps and ps["stdout"] == "hi\n")

print("== G: binding/TOCTOU — dispatch runs the STORED approved command; a same-id swap has NO effect ==")
reset(); opensess()
RID = "00000000-0000-4000-8000-000000000099"
rA = {"v":1,"session_id":RID,"request_id":RID,"cwd":"/srv/projects","elevate":False,"argv":["cat","/etc/hostname"]}
hA = B.cmd_hash(rA); bd.process(rA, B.NEEDS_BUTTON, hA)
nA = only_nonce()
# box "swaps": a SECOND request reusing the SAME request_id but a different (worse) argv
rB = {"v":1,"session_id":RID,"request_id":RID,"cwd":"/srv/projects","elevate":False,"argv":["cat","/etc/shadow"]}
bd.process(rB, B.NEEDS_BUTTON, B.cmd_hash(rB))
ck("swap created a SEPARATE pending (didn't overwrite the first)", len(bd._pending) == 2)
cb(nA, "A"); bd.poll_telegram()
ck("approving nonce_A runs the STORED original argv, not the swap", relay_calls and relay_calls[-1][0] == ["cat","/etc/hostname"])
ck("dispatched hash == button hash (stored req still hashes to hA)", B.cmd_hash(rA) == hA)

print("== G2: dispatch-time binding assertion refuses an in-memory-mutated stored request ==")
reset(); opensess()
r = req(["cat","/etc/hostname"]); h = B.cmd_hash(r); bd.process(r, B.NEEDS_BUTTON, h); n = only_nonce()
bd._pending[n]["req"]["argv"] = ["cat","/etc/shadow"]        # simulate a bug/tamper mutating the stored req
cb(n, "A"); bd.poll_telegram()
ck("mutated stored req -> NOT executed (binding mismatch)", len(relay_calls) == 0)
ck("result = refused binding mismatch", (result_of(r["request_id"]) or {}).get("reason","").startswith("binding mismatch"))

print("== H: incoming file is consumed (unlinked) at scan, BEFORE any approval/exec (no re-read window) ==")
reset(); opensess()
rid = "44444444-4444-4444-8444-444444444444"
p = os.path.join(bd.INCOMING, rid)
open(p, "wb").write(json.dumps({"v":1,"session_id":rid,"request_id":rid,"cwd":"/srv/projects","elevate":False,"argv":["cat","/etc/hostname"]}).encode())
bd.scan_incoming()
ck("incoming file unlinked at scan (nothing left to mutate)", not os.path.exists(p))
ck("command held in memory awaiting approval (no exec yet)", len(bd._pending) == 1 and len(relay_calls) == 0)

print("== G3: workspace_only pinned to classifier — decision-drift is refused; scope disclosed on button ==")
reset(); opensess()
r = req(["cat","/etc/hostname"]); h = B.cmd_hash(r); bd.process(r, B.NEEDS_BUTTON, h); n = only_nonce()
bd._pending[n]["decision"] = B.IN_SCOPE                      # tamper the stored decision
cb(n, "A"); bd.poll_telegram()
ck("decision-drift -> refused, not executed", len(relay_calls) == 0 and (result_of(r["request_id"]) or {}).get("reason","").startswith("binding mismatch"))
mc = bd._fmt({"cwd":"/srv/projects","argv":["cat","/etc/hostname"],"request_id":"x"}, "a"*64, "command")
ck("command button discloses FULL scope (outside sandbox)", "OUTSIDE" in mc)
ck("session button discloses it opens a work session", "session" in bd._fmt({"cwd":"/srv/projects","argv":["ls"],"request_id":"x"}, "a"*64, "session").lower())
# and confirm the normal derived scope is still correct end-to-end
reset(); opensess()
r = req(["cat","/etc/hostname"]); bd.process(r, B.NEEDS_BUTTON, B.cmd_hash(r)); cb(only_nonce(), "A"); bd.poll_telegram()
ck("approved NEEDS_BUTTON derives workspace_only=False", relay_calls and relay_calls[-1][1] is False)

print("== I: dual-clock window expiry (monotonic OR wall-clock, whichever is earlier) ==")
reset(); bd._session_until, bd._session_until_wall = bd.now() + 600, time.time() + 600
bd._session_until_wall = time.time() - 1                     # wall deadline passed (e.g. NTP step-forward)
ck("session_open() False when WALL deadline passed (mono still future)", not bd.session_open())
bd.check_expiries(); ck("check_expiries closes it", bd._session_until == 0.0)
reset(); bd._session_until, bd._session_until_wall = bd.now() - 1, time.time() + 600
ck("session_open() False when MONO deadline passed", not bd.session_open())

print("== J: revoke_all — closes session, KILLS in-flight (local + target), denies pending ==")
reset(); opensess()
tok = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
fp = FakePopen(["x", "ssh", "o", "--", "e", base64.b64encode(b'{}').decode()])   # a fake in-flight proc
bd._inflight[tok] = {"req": {"request_id": "55555555-5555-4555-8555-555555555555", "argv": ["sleep"], "cwd": "/srv/projects"},
                     "chash": "x", "decision": B.NEEDS_BUTTON, "wo": False, "proc": fp, "revoked": False, "started": bd.now()}
rp = req(["cat", "/etc/hostname"]); submit(rp); npend = only_nonce()   # one pending too
bd.revoke_all("test")
ck("session closed by revoke", not bd.session_open())
ck("in-flight local proc killed", fp.killed is True)
ck("in-flight target process-group kill invoked", tok in remote_kills)
ck("in-flight marked revoked", bd._inflight.get(tok, {}).get("revoked") is True)
ck("pending denied + cleared", len(bd._pending) == 0 and (result_of(rp["request_id"]) or {}).get("status") == "refused")

print("== J2: a worker whose exec was revoked writes status=revoked ==")
reset()
tok2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"; rid2 = "66666666-6666-4666-8666-666666666666"
bd._inflight[tok2] = {"req": {"request_id": rid2, "argv": ["sleep"], "cwd": "/srv/projects"},
                      "chash": "x", "decision": B.NEEDS_BUTTON, "wo": False, "proc": None, "revoked": True, "started": bd.now()}
bd._run_exec(tok2)                                           # inline; sees revoked -> kills, writes revoked result
ck("revoked in-flight -> result status=revoked", (result_of(rid2) or {}).get("status") == "revoked")
ck("remote kill invoked for revoked worker", tok2 in remote_kills)

print("== K: concurrent-exec cap (dispatch refuses beyond MAX_INFLIGHT) ==")
reset(); opensess()
for i in range(bd.MAX_INFLIGHT):                            # fill the table with stuck fakes (proc set, not reaped)
    bd._inflight["cccccccc-cccc-4ccc-8ccc-%012d" % i] = {"req": {}, "proc": FakePopen(["x"]*6), "revoked": False}
rc = req(["cat", "/etc/hostname"]); bd.dispatch(rc, B.cmd_hash(rc), B.NEEDS_BUTTON)
ck("over-cap dispatch refused", (result_of(rc["request_id"]) or {}).get("reason") == "too many concurrent commands")

print("== L: /panic and REVOKE button trigger revoke; non-owner cannot ==")
reset(); opensess()
r = req(["cat", "/etc/hostname"]); submit(r); only_nonce()
msg("/panic something", uid=999999); bd.poll_telegram()     # non-owner
ck("non-owner /panic ignored (session still open, pending intact)", bd.session_open() and len(bd._pending) == 1)
msg("/panic"); bd.poll_telegram()                            # owner
ck("owner /panic closes session + clears pending", not bd.session_open() and len(bd._pending) == 0)
reset(); opensess()
updates.append({"update_id": 7000, "callback_query": {"id": "z", "from": {"id": bd.OWNER_ID}, "data": "REVOKE"}})
bd.poll_telegram()
ck("REVOKE button closes session", not bd.session_open())

print("== M: REAL-THREAD revoke of a LIVE in-flight worker (actual thread + lock + kill race) ==")
reset(); opensess()
bd.threading.Thread = RealThread; FakePopen.block_mode = True   # worker runs for real + blocks in communicate
try:
    rM = req(["cat", "/etc/hostname"])
    bd.dispatch(rM, B.cmd_hash(rM), B.NEEDS_BUTTON)             # NEEDS_BUTTON -> real worker thread, blocks
    tok = None
    for _ in range(50):                                        # wait until the worker registered its proc
        with bd._lock:
            live = [(k, v) for k, v in bd._inflight.items() if v.get("proc")]
        if live: tok = live[0][0]; break
        time.sleep(0.05)
    ck("worker is live in-flight (proc registered)", tok is not None)
    bd.revoke_all("test-m")                                    # kill it mid-flight
    rp = os.path.join(bd.OUTGOING, rM["request_id"])
    for _ in range(60):
        if os.path.exists(rp): break
        time.sleep(0.05)
    res = result_of(rM["request_id"])
    ck("live worker got killed + wrote status=revoked", (res or {}).get("status") == "revoked")
    ck("target process-group kill was invoked for it", tok in remote_kills)
    ck("in-flight table drained after revoke", len(bd._inflight) == 0)
finally:
    FakePopen.block_mode = False; bd.threading.Thread = InlineThread

print("== O: worker crash (communicate raises) -> ALWAYS frees the slot + writes an error result (B1 fix) ==")
reset(); opensess()
FakePopen.raise_mode = True
try:
    r = req(["cat", "/etc/hostname"]); bd.process(r, B.NEEDS_BUTTON, B.cmd_hash(r)); n = only_nonce()
    cb(n, "A"); bd.poll_telegram()                            # approve -> dispatch -> worker; communicate raises
    ck("crashed worker still wrote an error result (box not stranded)", (result_of(r["request_id"]) or {}).get("status") == "error")
    ck("crashed worker freed its _inflight slot (no leak/wedge)", len(bd._inflight) == 0)
finally:
    FakePopen.raise_mode = False

print("== P: per-session command budget (bounds total activity per open window) ==")
reset(); opensess()
_ob = bd.SESSION_CMD_BUDGET; bd.SESSION_CMD_BUDGET = 3
try:
    rs = [req(["ls"]) for _ in range(4)]
    for r in rs: bd.process(r, B.IN_SCOPE, B.cmd_hash(r))
    ck("first 3 within budget ran", len(relay_calls) == 3)
    ck("4th over budget refused", (result_of(rs[3]["request_id"]) or {}).get("reason", "").startswith("session command budget"))
finally:
    bd.SESSION_CMD_BUDGET = _ob

print("== Q: pending-approvals cap (bounds outstanding buttons; anti-flood/fatigue) ==")
reset(); opensess()
_op = bd.MAX_PENDING; bd.MAX_PENDING = 2
try:
    rs = [req(["cat", "/etc/hostname"]) for _ in range(3)]
    for r in rs: bd.process(r, B.NEEDS_BUTTON, B.cmd_hash(r))
    ck("pending capped at MAX_PENDING", len(bd._pending) == 2)
    ck("over-cap command refused (pending cap)", (result_of(rs[2]["request_id"]) or {}).get("reason", "").startswith("too many pending"))
finally:
    bd.MAX_PENDING = _op

print("== R: ELEVATED request -> elevated button (disclosed) -> HMAC-ticketed wrapper path ==")
reset(); opensess()
r = req(["cat", "resume.tex"], cwd="/home/owner", elevate=True)
d, _ = B.classify(r)
ck("elevate=true classifies NEEDS_BUTTON", d == B.NEEDS_BUTTON)
bd.process(r, d, B.cmd_hash(r))
n = only_nonce()
ck("routed to an ELEVATED pending", bd._pending[n]["kind"] == "elevated")
disc = bd._fmt(r, "a" * 64, "elevated")
ck("button discloses ELEVATED + run_as", "ELEVATED" in disc and bd.ELEV_RUNAS in disc)
cb(n, "A"); bd.poll_telegram()
last = cmds[-1] if cmds else []
ck("dispatch used sudo exec-argv-elevated run <ticket>", "sudo" in last and any("exec-argv-elevated" in x for x in last) and "run" in last)
res = result_of(r["request_id"])
ck("elevated result carries elevated=True + run_as", res and res.get("elevated") is True and res.get("run_as") == bd.ELEV_RUNAS)
# never elevate a free-zone command (belt-and-suspenders binding)
reset(); opensess()
r2 = req(["ls"], elevate=False)
bd.dispatch(r2, B.cmd_hash(r2), B.IN_SCOPE, elevated=True)
ck("elevated+IN_SCOPE dispatch refused (binding)", (result_of(r2["request_id"]) or {}).get("reason", "").startswith("elevation binding"))

print("== R2: ELEVATED in-flight revoke uses the elevated (signed kill-ticket) kill path ==")
reset(); opensess()
tok = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
bd._inflight[tok] = {"req": {"request_id": "77777777-7777-4777-8777-777777777777", "argv": ["x"], "cwd": "/home/owner"},
                     "chash": "x", "decision": B.NEEDS_BUTTON, "wo": False, "elevated": True,
                     "proc": FakePopen(["x"] * 6), "revoked": False, "started": bd.now()}
bd.revoke_all("test-elev")
ck("elevated token routed to ELEVATED kill (not plain kill)", tok in remote_kills_elev and tok not in remote_kills)

print("== S: elevation disabled (no key) -> elevated request refused, not run ==")
reset(); opensess()
_savedkf = bd.ELEV_KEY_FILE; bd.ELEV_KEY_FILE = os.path.join(TD, "nope")
try:
    r = req(["cat", "resume.tex"], cwd="/home/owner", elevate=True)
    bd.process(r, B.NEEDS_BUTTON, B.cmd_hash(r))
    ck("no key -> refused, no button, not run", len(bd._pending) == 0 and (result_of(r["request_id"]) or {}).get("reason", "") == "elevation not configured")
finally:
    bd.ELEV_KEY_FILE = _savedkf

print("== N: fail-closed restart — a fresh broker process has NO open session / pending / inflight ==")
import subprocess as _sp
_probe = ("import importlib.util,os;"
          "os.environ['TELEGRAM_BROKER_BOT_TOKEN']='x';"
          "s=importlib.util.spec_from_file_location('b',os.path.join(os.getcwd(),'brokerd.py'));"
          "b=importlib.util.module_from_spec(s); s.loader.exec_module(b);"
          "print('OK' if (not b.session_open() and not b._pending and not b._inflight) else 'BAD')")
bd.subprocess.Popen = RealPopen           # restore real Popen so subprocess.run works for this probe
_r = _sp.run([sys.executable, "-c", _probe], cwd=os.path.join(HERE, "..", "broker"), capture_output=True, text=True)
ck("fresh process = fail-closed (in-memory only; nothing persisted survives a kill -9)", "OK" in _r.stdout)

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
