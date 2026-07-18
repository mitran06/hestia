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
sent, updates, relay_calls, remote_kills, cmds, remote_kills_elev, acq = [], [], [], [], [], [], []
# provision an elevation key so elevation_enabled() is True in wiring tests
_KF = os.path.join(TD, "elev.key"); open(_KF, "wb").write(os.urandom(48)); bd.ELEV_KEY_FILE = _KF
bd.ELEV_RUNAS = "owner"                    # elevated commands run as the (test) owner user
_mid = [1000]; _uid = [1]; _rid = [0]
def fake_tg(method, **p):
    if method == "sendMessage": _mid[0] += 1; sent.append(p); return {"ok": True, "result": {"message_id": _mid[0]}}
    if method == "getUpdates":  r = updates[:]; updates.clear(); return {"ok": True, "result": r}
    if method == "editMessageText": sent.append(p); return {"ok": True, "result": {}}
    if method == "editMessageReplyMarkup": sent.append(p); return {"ok": True, "result": {}}
    if method == "answerCallbackQuery": acq.append(p)
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
def req_open(intent="edit resume", secs=600):
    _rid[0] += 1; rid = "00000000-0000-4000-8000-%012d" % _rid[0]
    return {"v": 1, "session_id": rid, "request_id": rid,
            "kind": "session_open", "intent": intent, "duration_secs": secs}
def req_close():
    _rid[0] += 1; rid = "00000000-0000-4000-8000-%012d" % _rid[0]
    return {"v": 1, "session_id": rid, "request_id": rid, "kind": "session_close"}
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
    remote_kills.clear(); remote_kills_elev.clear(); cmds.clear(); acq.clear()
    bd._session_until, bd._session_until_wall = 0.0, 0.0
    bd._session_cmd_count = 0
    bd._session_intent = ""; bd._session_secs = 0; bd._session_msg_id = None
    bd._session_log = {}; bd._reset_counts()
    bd._session_phase = "idle"; bd._session_end_reason = ""; bd._session_killed = 0; bd._render_dirty = False
    bd._session_last_flush = 0.0
def opensess():
    bd._session_until, bd._session_until_wall = bd.now() + 600, time.time() + 600
    bd._session_phase = "open"                   # a forced-open session is a real, logging-enabled window
    bd._session_intent = bd._session_intent or "forced-open (test)"
    bd._session_msg_id = bd._session_msg_id or 4242
def open_via_approve(intent="work", secs=600):
    # drive the REAL session_open approval so _session_phase becomes "open"
    reset()
    p = {"kind": "session_open", "req": req_open(intent, secs), "intent": intent, "secs": secs,
         "chat_id": bd.OWNER_ID, "msg_id": 5001, "deadline": bd.now() + bd.SESSION_ASK_SECS}
    bd.on_approve(p)                       # sets clocks + _session_phase="open"

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

print("== D: session lifecycle (T4a: no command opens a session; open window auto-runs free-zone) ==")
reset()  # session CLOSED
r = req(["ls", "-la"]); ck("ls is IN_SCOPE", submit(r) == B.IN_SCOPE)
# T4a: a command while IDLE no longer opens a session — the legacy auto-session is RETIRED.
ck("IDLE: free-zone did NOT run and NO session button was sent (legacy path retired)",
   len(relay_calls) == 0 and len(bd._pending) == 0)
ck("IDLE: no-session command is refused (must session-open first)",
   (result_of(r["request_id"]) or {}).get("status") == "refused")
# a window opens only via an approved agent session_open; force one open, then the OPEN-phase behaviour holds.
opensess()
r1 = req(["ls", "-la"]); submit(r1)
ck("OPEN: free-zone auto-runs workspace_only=True (no button)", len(relay_calls) == 1 and relay_calls[0][1] is True)
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

print("== T3a: _render_session open shape (header, intent, divider, log lines) ==")
reset()
bd._session_phase = "open"
bd._session_intent = "refactor the mover"                  # canonical (already-sanitized) stored value
bd._session_secs = 600
bd._session_until_wall = time.time() + 600
bd._session_log["00000000-0000-4000-8000-000000000a01"] = {"icon": "⏳", "argv": "git status", "status": "running", "kind": "command"}
bd._session_log["00000000-0000-4000-8000-000000000a02"] = {"icon": "✓", "argv": "ls -la", "status": "✓ exit0", "kind": "command"}
_txt = bd._render_session()
ck("open render has 🟢 Session open header", "🟢 Session open" in _txt)
ck("open render shows enforcing intent verbatim", 'enforcing: "refactor the mover"' in _txt)
ck("open render has the divider", "────────" in _txt)
ck("open render shows both argv log lines", "git status" in _txt and "ls -la" in _txt)
ck("open render under 4000 chars", len(_txt) < 4000)

print("== T3b: _render_session ended shape (⚪ summary + counts) ==")
reset()
bd._session_phase = "ended"
bd._session_end_reason = "agent"
bd._session_counts = {"auto": 2, "approved": 1, "elevated": 0, "blocked": 1, "failed": 0}
bd._session_log["00000000-0000-4000-8000-000000000b01"] = {"icon": "✓", "argv": "ls", "status": "✓ exit0", "kind": "command"}
_e = bd._render_session()
ck("ended render has ⚪ Session ended by agent", "⚪ Session ended by agent" in _e)
ck("ended render shows total cmd count", "1 cmds" in _e)
ck("ended render shows the counts summary", "2 auto" in _e and "1 approved" in _e and "1 blocked" in _e)
ck("ended render keeps the log below", "ls" in _e)

print("== T3c: _flush_session_msg honors _render_dirty + force ==")
reset()
bd._session_phase = "open"
bd._session_intent = "x"
bd._session_until_wall = time.time() + 600
bd._session_msg_id = 4242
sent.clear()
bd._render_dirty = False
bd._flush_session_msg(force=False)
ck("flush no-op when not dirty and not forced (no tg edit)", len(sent) == 0)
bd._flush_session_msg(force=True)
ck("flush edits the session message when forced", any(s.get("message_id") == 4242 for s in sent))
bd._render_dirty = True
bd._session_last_flush = 0.0        # reset coalescing guard so the next non-forced dirty flush is not throttled
bd._flush_session_msg()
ck("flush edits when dirty (and clears the flag)", any(s.get("message_id") == 4242 for s in sent) and bd._render_dirty is False)

print("== T4: session_open handler + button + approved-duration open ==")
reset()  # session CLOSED (idle)
ro = req_open(intent="edit my resume & push", secs=1200)
bd._handle_session_open(ro)
ck("idle session_open sends exactly ONE button", len(sent) == 1 and len(bd._pending) == 1)
ck("button is a session_open pending", list(bd._pending.values())[0]["kind"] == "session_open")
bt = sent[0]["text"]
ck("button text carries the intent", "edit my resume & push" in bt)
ck("button text shows duration in minutes", "20 min" in bt)          # 1200 // 60
ck("button text is the yellow session request", bt.startswith("🟡 The agent requests a work session"))
n = only_nonce()
_t0 = bd.now()
cb(n, "A"); bd.poll_telegram()
ck("approve opens the window for the APPROVED secs", abs(bd._session_until - (_t0 + 1200)) < 5)
ck("wall clock set to approved secs and session is open",
   abs(bd._session_until_wall - (time.time() + 1200)) < 5 and bd.session_open())
# displayed == stored == anchor: the pending intent, the button text, and the stored anchor are byte-identical
_pend_intent = "edit my resume & push"
ck("intent anchored to the approved (canonical) intent", bd._session_intent == _pend_intent)
ck("stored anchor == the exact string shown on the button", bd._session_intent in bt)
ck("phase is open", bd._session_phase == "open")
ck("session_secs recorded for display", bd._session_secs == 1200)
ck("command budget reset on open", bd._session_cmd_count == 0)
ck("result status=session_opened with secs", (result_of(ro["request_id"]) or {}).get("status") == "session_opened"
   and (result_of(ro["request_id"]) or {}).get("secs") == 1200)
ck("button message REUSED as the live session msg (edited in place)", bd._session_msg_id is not None)

print("== T4b: Deny a session_open -> refused, window stays CLOSED ==")
reset()
ro2 = req_open(intent="rm things", secs=600)
bd._handle_session_open(ro2)
n2 = only_nonce()
cb(n2, "D"); bd.poll_telegram()
ck("deny -> refused result", (result_of(ro2["request_id"]) or {}).get("status") == "refused")
ck("deny -> session stays CLOSED", not bd.session_open() and bd._session_phase != "open")

print("== T4c: session_open routed through scan_incoming ==")
reset()
ro3 = req_open(intent="scan-routed intent", secs=300)
rid3 = ro3["request_id"]
open(os.path.join(bd.INCOMING, rid3), "wb").write(json.dumps(ro3).encode())
bd.scan_incoming()
ck("scan_incoming routed session_open to a button (no classify/exec)",
   len(bd._pending) == 1 and list(bd._pending.values())[0]["kind"] == "session_open" and len(relay_calls) == 0)
ck("scan-routed button carries its intent", "scan-routed intent" in sent[-1]["text"])

print("== T4d: canonical intent — displayed == stored == anchor (sanitize+cap once) ==")
reset()
_ctrl = "bad\nintent\twith ctl"                              # control chars an attacker/agent might send
ro4 = req_open(intent=_ctrl, secs=600)
bd._handle_session_open(ro4)
_canon = bd._canon_intent(_ctrl)
_pend = list(bd._pending.values())[0]
ck("pending stores the CANONICAL intent (sanitized once)", _pend["intent"] == _canon)
ck("button shows the canonical intent verbatim", _canon in sent[-1]["text"])
n4 = only_nonce(); cb(n4, "A"); bd.poll_telegram()
ck("anchor == canonical == button text (byte-identical)", bd._session_intent == _canon)
ck("render shows the same canonical anchor verbatim", _canon in bd._render_session())

print("== T4a: legacy command-triggered auto-session is RETIRED — no session => command REFUSED ==")
reset()  # NO session open
rc = req(["ls", "-la"]); submit(rc)
ck("no-session command does NOT create a session_open/session pending",
   all(p.get("kind") not in ("session", "session_open") for p in bd._pending.values()))
ck("no-session command did NOT execute", len(relay_calls) == 0)
_r = result_of(rc["request_id"]) or {}
ck("no-session command is refused", _r.get("status") == "refused")
ck("refusal tells the agent to open a session first", "session" in (_r.get("reason") or "").lower())

print("== T5: no-toast callback contract ==")
bd.subprocess.Popen = FakePopen  # test N restored RealPopen; re-arm the fake for callback tests
# --- a NEEDS_BUTTON command approval: answerCallbackQuery must carry text="" (no toast) ---
reset(); opensess()
r = req(["cat", "/etc/hostname"]); submit(r); n = only_nonce()
cb(n, "A"); bd.poll_telegram()
ck("command approve executed", len(relay_calls) == 1)
ck("answerCallbackQuery invoked exactly once", len(acq) == 1)
ck("answerCallbackQuery text is empty (no 'ok' toast)", acq and acq[0].get("text") == "")

# --- non-owner drop: answerCallbackQuery still empty text (no 'not authorized' toast) ---
reset(); opensess()
r = req(["cat", "/etc/hostname"]); submit(r); n = only_nonce()
cb(n, "A", uid=999999); bd.poll_telegram()
ck("non-owner drop answered with text=''", len(acq) == 1 and acq[0].get("text") == "")
ck("non-owner drop did NOT consume nonce/execute", len(bd._pending) == 1 and len(relay_calls) == 0)

# --- REVOKE button: answerCallbackQuery empty text (no 'revoked' toast) ---
reset(); opensess()
updates.append({"update_id": 500001, "callback_query":
                {"id": "crev", "from": {"id": bd.OWNER_ID}, "data": "REVOKE"}})
bd.poll_telegram()
ck("REVOKE answered with text=''", len(acq) == 1 and acq[0].get("text") == "")

# --- already-handled (stale nonce): still text="" (no 'already handled' toast) ---
reset(); opensess()
updates.append({"update_id": 500002, "callback_query":
                {"id": "cstale", "from": {"id": bd.OWNER_ID}, "data": "deadnonce:A"}})
bd.poll_telegram()
ck("stale-nonce answered with text=''", len(acq) == 1 and acq[0].get("text") == "")

# --- session_open approval: NO "Processing" message; the 🟢 state is one edit via _flush ---
reset()
ro = req_open("touch cache", 600)                 # control session_open dict (T4 helper)
bd._handle_session_open(ro)                        # sends the 🟡 button (no window open yet)
n = only_nonce(); sent.clear(); acq.clear()        # isolate the APPROVAL side-effects
cb(n, "A"); bd.poll_telegram()
txts = [s.get("text", "") for s in sent]
ck("session_open: no 'Processing' message sent", all("Processing" not in t for t in txts))
ck("session_open: answerCallbackQuery text=''", len(acq) == 1 and acq[0].get("text") == "")
ck("session_open: window is open", bd.session_open() and bd._session_phase == "open")
ck("session_open: exactly one edit rendered the 🟢 state",
   sum(1 for s in sent if "🟢" in s.get("text", "")) == 1)
ck("session_open: result status=session_opened", (result_of(ro["request_id"]) or {}).get("status") == "session_opened")

print("== T6: session_close ends-by-agent (renders ⚪, then clears) + no-op when idle ==")
reset()
# open a real window via the T4 on_approve(session_open) path
_p_open = {"kind": "session_open", "req": req_open("ship the relay patch", 600),
           "intent": "ship the relay patch", "secs": 600,
           "chat_id": bd.OWNER_ID, "msg_id": 4242, "deadline": bd.now() + bd.SESSION_ASK_SECS}
bd.on_approve(_p_open)
ck("precondition: session is OPEN after on_approve", bd.session_open() and bd._session_phase == "open")
_sess_mid = bd._session_msg_id
# route a session_close request
rc6 = req_close()
bd._handle_session_close(rc6)
# the ⚪ ended-by-agent summary must have been rendered onto the SAME message before clearing
_edits = [p for p in sent if "⚪ Session ended by agent" in (p.get("text") or "")]
ck("session_close rendered '⚪ Session ended by agent' on the live message", len(_edits) == 1)
ck("edit targeted the live session message id", _edits and _edits[0].get("message_id") == _sess_mid)
ck("after close: session_open() False", not bd.session_open())
ck("after close: phase reset to 'ended'", bd._session_phase == "ended")
ck("after close: intent cleared", bd._session_intent == "")
ck("after close: end reason recorded 'agent'", bd._session_end_reason == "agent")
ck("after close: msg_id kept (message stays edited)", bd._session_msg_id == _sess_mid)
ck("close writes status=session_closed (no reason)", (result_of(rc6["request_id"]) or {}).get("status") == "session_closed" and "reason" not in (result_of(rc6["request_id"]) or {}))

# idle close: no open session -> still session_closed + reason, no error
reset()
rc6b = req_close()
_erred = False
try:
    bd._handle_session_close(rc6b)
except Exception:
    _erred = True
ck("idle session_close does not raise", not _erred)
_r = result_of(rc6b["request_id"]) or {}
ck("idle close -> status=session_closed + reason 'no open session'",
   _r.get("status") == "session_closed" and _r.get("reason") == "no open session")

print("== T7a: expiry -> ⚪ 'Session expired' summary, log/counts preserved into render, intent cleared ==")
reset(); opensess()                                            # opensess sets _session_phase='open' (T3)
bd._session_intent = "run the test suite"; bd._session_secs = 600
bd._session_msg_id = 4242                                       # a live session message to edit in place
bd._session_log["00000000-0000-4000-8000-0000000000a1"] = {"icon": "✓", "argv": "ls", "status": "✓ exit0", "kind": "command"}
bd._session_counts["auto"] += 1
bd._session_log["00000000-0000-4000-8000-0000000000a2"] = {"icon": "✓", "argv": "cat readme.md", "status": "✓ exit0", "kind": "command"}
bd._session_counts["approved"] += 1
_rendered = {}
_real_flush = bd._flush_session_msg
def _capture_flush(force=False):                               # capture what ⚪ actually renders at end-of-life
    _rendered["text"] = bd._render_session(); _real_flush(force=force)
bd._flush_session_msg = _capture_flush
try:
    bd._session_until = bd.now() - 1; bd._session_until_wall = time.time() - 1   # force BOTH deadlines past
    bd.check_expiries()
finally:
    bd._flush_session_msg = _real_flush
ck("expiry closed the window (session_open() False)", not bd.session_open())
ck("expiry set phase to 'ended' then cleared state", bd._session_phase == "ended")
ck("expiry cleared the trusted intent anchor", bd._session_intent == "")
ck("⚪ 'Session expired' header rendered at end-of-life", "⚪ Session expired" in _rendered.get("text", ""))
ck("expired render preserved the 2-cmd count summary", "2 cmds" in _rendered.get("text", ""))
ck("expired render still showed a log line (counts/log preserved before clear)", "readme.md" in _rendered.get("text", ""))
ck("expired render carried the auto/approved counts", "auto" in _rendered.get("text", "") and "approved" in _rendered.get("text", ""))
ck("post-clear log is empty", len(bd._session_log) == 0)

print("== T7b: expiry with NO open session does NOT call _end_session (no spurious ⚪) ==")
reset()                                                        # session CLOSED, phase idle
_ended = {"n": 0}
_real_end = bd._end_session
def _count_end(reason, killed=0): _ended["n"] += 1; _real_end(reason, killed=killed)
bd._end_session = _count_end
try:
    bd.check_expiries()                                        # nothing open -> must not end a session
finally:
    bd._end_session = _real_end
ck("no open session -> _end_session NOT called on expiry", _ended["n"] == 0)
ck("phase stays idle", bd._session_phase == "idle")

print("== T7c: revoke_all -> ⚪ 'Session revoked' with killed count, intent cleared ==")
reset(); opensess()                                            # real open window (phase='open' via T3 opensess)
bd._session_intent = "deploy the broker"; bd._session_secs = 600
bd._session_msg_id = 4343
bd._session_log["00000000-0000-4000-8000-0000000000b1"] = {"icon": "🔴", "argv": "systemctl restart", "status": "running", "kind": "elevated"}
bd._session_counts["elevated"] += 1
tokR = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"                  # one in-flight to be killed
fpR = FakePopen(["x", "ssh", "o", "--", "e", base64.b64encode(b'{}').decode()])
bd._inflight[tokR] = {"req": {"request_id": "00000000-0000-4000-8000-0000000000b1", "argv": ["systemctl"], "cwd": "/srv/projects"},
                      "chash": "x", "decision": B.NEEDS_BUTTON, "wo": False, "proc": fpR, "revoked": False, "started": bd.now()}
_rendered = {}
_real_flush = bd._flush_session_msg
def _capture_flush(force=False):
    _rendered["text"] = bd._render_session(); _real_flush(force=force)
bd._flush_session_msg = _capture_flush
try:
    bd.revoke_all("test-revoke")
finally:
    bd._flush_session_msg = _real_flush
ck("revoke closed the window", not bd.session_open())
ck("revoke killed the in-flight local proc", fpR.killed is True)
ck("revoke set phase to 'ended' after cleanup", bd._session_phase == "ended")
ck("revoke cleared the trusted intent anchor", bd._session_intent == "")
ck("⚪ 'Session revoked' header rendered", "⚪ Session revoked" in _rendered.get("text", ""))
ck("revoked render shows the killed count (1 killed)", "1 killed" in _rendered.get("text", ""))
ck("revoked render preserved the log line before clear", "systemctl" in _rendered.get("text", ""))

print("== T8: session_log — every outcome keyed by request_id, counts bump ==")
open_via_approve()
ck("session opened -> phase open, empty log", bd._session_phase == "open" and len(bd._session_log) == 0)

# (a) IN_SCOPE auto command -> ✓ exit0, auto++
rA = req(["ls", "-la"]); submit(rA)
ck("auto command logged ✓ exit0", (bd._session_log.get(rA["request_id"]) or {}).get("status") == "✓ exit0")
ck("auto command icon is the exit icon", (bd._session_log.get(rA["request_id"]) or {}).get("icon") == "✓")
ck("auto count == 1", bd._session_counts["auto"] == 1)

# (b) NEEDS_BUTTON approved -> 🔵 awaiting BEFORE tap, then ⏳ running, then ✓ exit0, approved++
rB = req(["cat", "/etc/hostname"]); submit(rB)
ck("approved command shows 🔵 awaiting BEFORE approval", (bd._session_log.get(rB["request_id"]) or {}).get("icon") == "🔵")
ck("🔵 awaiting does NOT bump any count yet", bd._session_counts["approved"] == 0)
nB = only_nonce()
cb(nB, "A"); bd.poll_telegram()
ck("approved command logged ✓ exit0 after run", (bd._session_log.get(rB["request_id"]) or {}).get("status") == "✓ exit0")
ck("approved count == 1", bd._session_counts["approved"] == 1)

# (c) denied command -> ⛔ denied + blocked++
open_via_approve()
rC = req(["cat", "/etc/hostname"]); submit(rC); nC = only_nonce()
cb(nC, "D"); bd.poll_telegram()
ck("denied command logged ⛔ denied", (bd._session_log.get(rC["request_id"]) or {}).get("status") == "⛔ denied")
ck("blocked count == 1 after deny", bd._session_counts["blocked"] == 1)

# (c2) approval TIMEOUT -> ⌛ + blocked++
open_via_approve()
rC2 = req(["cat", "/etc/hostname"]); submit(rC2)
for _n, _p in list(bd._pending.items()):
    if _p["kind"] == "command": _p["deadline"] = bd.now() - 1        # force this pending past its deadline
bd.check_expiries()
ck("approval-timeout logged ⌛", (bd._session_log.get(rC2["request_id"]) or {}).get("icon") == "⌛")
ck("approval-timeout counts as blocked", bd._session_counts["blocked"] == 1)

# (d) refused (pending cap) -> 🚫 refused: ...
open_via_approve()
_op = bd.MAX_PENDING; bd.MAX_PENDING = 1
try:
    rD1 = req(["cat", "/etc/hostname"]); submit(rD1)          # takes the one pending slot
    rD2 = req(["cat", "/etc/passwd"]);  submit(rD2)           # over cap -> refuse()
    ck("refused command logged 🚫", (bd._session_log.get(rD2["request_id"]) or {}).get("icon") == "🚫")
    ck("refused status carries reason", (bd._session_log.get(rD2["request_id"]) or {}).get("status", "").startswith("refused:"))
    ck("blocked bumped by refuse", bd._session_counts["blocked"] == 1)
finally:
    bd.MAX_PENDING = _op

# (e) rejected (malformed via scan_incoming) -> 🚫 rejected
open_via_approve()
badid = "33333333-3333-4333-8333-333333333333"
open(os.path.join(bd.INCOMING, badid), "wb").write(b"{ not json")
bd.scan_incoming()
ck("rejected malformed logged 🚫 rejected", (bd._session_log.get(badid) or {}).get("status") == "rejected"
   and (bd._session_log.get(badid) or {}).get("icon") == "🚫")

# (f) two distinct request_ids -> two distinct keyed entries (no overwrite/reorder)
open_via_approve()
r1 = req(["ls"]); r2 = req(["cat", "readme.md"]); submit(r1); submit(r2)
ck("two distinct request_ids -> two log entries", len(bd._session_log) == 2)
ck("entries keyed by request_id (both present, no overwrite)",
   r1["request_id"] in bd._session_log and r2["request_id"] in bd._session_log)
ck("insertion order preserved (r1 before r2)", list(bd._session_log)[0] == r1["request_id"])

# (f2) same request_id updated in place (⏳ -> ✓) yields ONE entry, counted once
open_via_approve()
_rid_same = "00000000-0000-4000-8000-0000000000f2"
bd.session_log(_rid_same, "⏳", ["ls"], "running", kind="auto")   # non-terminal
bd.session_log(_rid_same, "✓", ["ls"], "✓ exit0", kind="auto")   # terminal update, SAME key
ck("in-place update keeps a single entry", len([k for k in bd._session_log if k == _rid_same]) == 1)
ck("in-place terminal update sets final status", bd._session_log[_rid_same]["status"] == "✓ exit0")
ck("in-place update counted exactly once", bd._session_counts["auto"] == 1)

# (g) non-zero exit -> ✗ + failed++
open_via_approve()
FakePopen_rc = bd.subprocess.Popen
class RcPopen(FakePopen):                                     # a proc that exits non-zero
    def communicate(self, timeout=None): self.returncode = 2; return (b"", b"boom")
bd.subprocess.Popen = RcPopen
try:
    rG = req(["ls"]); submit(rG)
    ck("non-zero exit logged ✗ exit2", (bd._session_log.get(rG["request_id"]) or {}).get("status") == "✗ exit2")
    ck("failed count == 1", bd._session_counts["failed"] == 1)
finally:
    bd.subprocess.Popen = FakePopen_rc

# (h) appends OUTSIDE an open session are DROPPED (phase != open)
reset()                                                       # phase back to idle
bd.session_log("99999999-9999-4999-8999-999999999999", "✓", ["ls"], "✓ exit0")
ck("append while idle is dropped", len(bd._session_log) == 0)

# (i) lazy render when _session_msg_id is None: log buffers, no crash, renders on flush
open_via_approve()
bd._session_msg_id = None                                     # no live message yet
bd.session_log("00000000-0000-4000-8000-0000000000i1", "✓", ["uniq-buffered-cmd"], "✓ exit0", kind="auto")
ck("log buffers with no msg_id (no crash)", "00000000-0000-4000-8000-0000000000i1" in bd._session_log)
bd._flush_session_msg(force=True)                            # msg_id None -> no-op, must not raise
ck("flush with msg_id None is a safe no-op", True)
# (i2) subsequent-render contract (T11): once a live msg_id exists, the buffered entry RENDERS on the
# next forced flush. Locks the lazy-render guarantee — buffering while msg_id was None must NOT lose data.
sent.clear()
bd._session_msg_id = 7777                                     # a live message now exists
bd._flush_session_msg(force=True)
_i2 = [s for s in sent if s.get("message_id") == 7777 and "uniq-buffered-cmd" in (s.get("text") or "")]
ck("T11: buffered-while-None entry renders on the next forced flush", len(_i2) >= 1)

print("== T11: _render_session snapshots shared state under _lock (thread-safe) ==")
# (a) SNAPSHOT SAFETY (deterministic): _render_session copies _session_log under _lock, so mutating the
# live dict AFTER render started does not corrupt the returned text. We can't interleave mid-iteration
# deterministically with the harness, but we CAN prove the render reads a snapshot: render, then mutate,
# and confirm the earlier render text is unaffected by the later mutation (it captured its own copy).
open_via_approve()
bd.session_log("00000000-0000-4000-8000-00000000ma01", "✓", ["render-snap-a"], "✓ exit0", kind="auto")
_snap_txt = bd._render_session()                             # renders from a private copy under _lock
bd.session_log("00000000-0000-4000-8000-00000000ma02", "✓", ["render-snap-b-added-after"], "✓ exit0", kind="auto")
ck("T11: render captured a snapshot (later insert not in the earlier text)",
   "render-snap-a" in _snap_txt and "render-snap-b-added-after" not in _snap_txt)
# a fresh render DOES see the new entry (snapshot is per-call, not stale)
ck("T11: a fresh render sees the newly-inserted entry",
   "render-snap-b-added-after" in bd._render_session())

# (c) SNAPSHOT CONSISTENCY (deterministic): the header counts and the log body must come from the SAME
# atomic snapshot. FIX1 reads _session_log AND _session_counts together under _lock, so the total-cmds
# figure in the ⚪ header always equals the number of distinct logged request_ids at snapshot time —
# never a torn read where counts and log disagree. Log N>WINDOW terminal entries, end the session, and
# check the ⚪ header's 'N cmds' matches the live log size exactly.
open_via_approve()
_n = bd.SESSION_LOG_WINDOW + 5
for i in range(_n):
    bd.session_log("00000000-0000-4000-8000-%012d" % (800000 + i), "✓", ["c%02d" % i], "✓ exit0", kind="auto")
bd._session_phase = "ended"; bd._session_end_reason = "agent"
_end_txt = bd._render_session()
ck("T11: ⚪ header 'N cmds' equals the snapshotted log size (log+counts read together)",
   ("· %d cmds ·" % len(bd._session_log)) in _end_txt and ("· %d cmds ·" % _n) in _end_txt)
reset()

# (b) BEST-EFFORT CONCURRENCY (real threads): a background thread inserts into _session_log via
# session_log(phase=open) in a tight loop while the main thread calls _render_session() repeatedly.
# The under-_lock snapshot makes `RuntimeError: dictionary changed size during iteration` impossible.
# NOTE: on CPython the pre-fix `list(_session_log.values())` was already effectively atomic (the GIL is
# not released mid C-level snapshot), so this loop does NOT deterministically reproduce the race on a
# GIL build — it is a smoke test, not the primary FIX1 guard. The primary guard is the DETERMINISTIC
# snapshot-safety (a) and snapshot-consistency (c) assertions above, which prove render reads a private,
# internally-consistent copy — the property that also holds under a free-threaded / no-GIL build where
# the raw race WOULD be reachable. Uses the REAL Thread (captured before the InlineThread override).
# Non-flaky: asserts only "no RuntimeError / no exception" — never a timing-dependent value.
open_via_approve()
_race_err = []
_race_stop = _threading.Event()
def _race_writer():
    i = 0
    while not _race_stop.is_set():
        i += 1
        try:
            bd.session_log("00000000-0000-4000-8000-%012d" % (700000 + (i % 400)),
                           "✓", ["race-cmd-%d" % i], "running", kind="auto")
        except Exception as e:
            _race_err.append(("writer", repr(e)))
_wt = RealThread(target=_race_writer, daemon=True); _wt.start()
try:
    for _ in range(4000):                                    # hammer the reader against live inserts
        try:
            bd._render_session()
        except Exception as e:
            _race_err.append(("render", repr(e)))
finally:
    _race_stop.set(); _wt.join(timeout=2)
ck("T11: concurrent inserts during _render_session raise NO RuntimeError (snapshot under _lock)",
   not any("RuntimeError" in e[1] for e in _race_err))
ck("T11: concurrent race loop raised no exception at all", len(_race_err) == 0)
reset()                                                       # restore Thread-free state for later tests

print("== T9: render coalescing + length guard + Revoke-on-message ==")
# (a) 40-entry log renders under the 4000-char hard cap and shows a rollup marker
open_via_approve()
for i in range(40):
    rid = "00000000-0000-4000-8000-%012d" % (900000 + i)
    bd.session_log(rid, "✓", ["some-fairly-long-command", "--flag", "value%02d" % i], "✓ exit0")
rs = bd._render_session()
ck("T9: 40-entry render is under the 4000-char hard cap", len(rs) < 4000)
ck("T9: long log shows a rollup 'earlier' marker", "earlier" in rs and "…" in rs)
ck("T9: rollup did NOT drop the newest entry", "value39" in rs)

# (b) opening a session flushes an edit that (re)attaches the REVOKE inline keyboard
open_via_approve()
bd._flush_session_msg(force=True)
revoke_markup_calls = [
    s for s in sent
    if s.get("reply_markup", {}).get("inline_keyboard", [[{}]])[0][0].get("callback_data") == "REVOKE"
]
ck("T9: open-phase flush (re)attaches a REVOKE inline button", len(revoke_markup_calls) >= 1)

# (b2) non-forced flushes coalesce to <=1/sec; force is exempt
open_via_approve()
bd._session_last_flush = bd.now()                            # pretend we just flushed (monotonic stamp — T11 FIX3)
sent.clear()
bd._render_dirty = True
bd._flush_session_msg()                                       # non-forced, within the min interval -> skipped
ck("T9: non-forced flush within 1s is coalesced (skipped)", len(sent) == 0 and bd._render_dirty is True)
bd._flush_session_msg(force=True)                             # forced -> always edits
ck("T9: forced flush is exempt from coalescing", len(sent) >= 1 and bd._render_dirty is False)

# (c) the standalone 'Session is OPEN. Tap to STOP' control message is no longer sent on open
open_via_approve()
ck("T9: standalone Revoke-control message is NOT sent on open",
   not any("Tap to STOP" in (s.get("text") or "") for s in sent))
ck("T9: _send_revoke_control has been retired", not hasattr(bd, "_send_revoke_control"))

print("== T10a: re-anchor re-prompts (edits live msg) and does NOT change intent until approved ==")
reset()
ro = req_open("intent A", 600)
bd._handle_session_open(ro)
nA = only_nonce()
cb(nA, "A"); bd.poll_telegram()
ck("session open under intent A", bd.session_open() and bd._session_intent == "intent A")
ck("open render reuses one live session msg", bd._session_msg_id is not None)
mid_before = bd._session_msg_id
sent.clear()
rB = req_open("intent B", 1200)
bd._handle_session_open(rB)
ck("re-anchor created exactly one pending session_open", len(bd._pending) == 1
   and list(bd._pending.values())[0]["kind"] == "session_open")
ck("re-anchor did NOT send a NEW button (only edited the live msg in place)",
   not any(s.get("chat_id") == bd.OWNER_ID and "reply_markup" in s
           and s.get("text","").startswith("🟡") and "message_id" not in s for s in sent))
ck("re-anchor pending targets the live session msg id",
   list(bd._pending.values())[0]["msg_id"] == mid_before)
ck("re-anchor prompt carries the NEW intent B", list(bd._pending.values())[0]["intent"] == "intent B")
ck("OLD intent A still enforced until re-approval",
   bd._session_intent == "intent A" and bd.session_open())

print("== T10b: approving a re-anchor swaps intent -> B and resets the clock ==")
nB = only_nonce()
old_until = bd._session_until
cb(nB, "A"); bd.poll_telegram()
ck("approved re-anchor: intent is now B", bd._session_intent == "intent B")
ck("approved re-anchor: duration reset to B's secs", bd._session_secs == 1200)
ck("approved re-anchor: clock pushed forward", bd._session_until >= old_until)
ck("approved re-anchor: session still open, one msg id kept",
   bd.session_open() and bd._session_msg_id == mid_before)

print("== T10c: denying a re-anchor reverts to the 🟢 open render, intent A untouched ==")
reset()
ro = req_open("intent A", 600); bd._handle_session_open(ro); cb(only_nonce(), "A"); bd.poll_telegram()
rB = req_open("intent B", 1200); bd._handle_session_open(rB)
sent.clear()
cb(only_nonce(), "D"); bd.poll_telegram()
ck("denied re-anchor: intent stays A", bd._session_intent == "intent A")
ck("denied re-anchor: session still open", bd.session_open() and bd._session_phase == "open")
ck("denied re-anchor: pending cleared", len(bd._pending) == 0)
ck("denied re-anchor: message reverted to 🟢 open render",
   any(s.get("message_id") == bd._session_msg_id and s.get("text", "").startswith("🟢") for s in sent))
ck("denied re-anchor: box got a refused result",
   (result_of(rB["request_id"]) or {}).get("status") == "refused")

print("== T10d: a command pending at _end_session is refused+cleared; a later cb cannot dispatch ==")
reset()
ro = req_open("intent A", 600); bd._handle_session_open(ro); cb(only_nonce(), "A"); bd.poll_telegram()
rc = req(["cat", "/etc/hostname"]); submit(rc)               # NEEDS_BUTTON -> one command pending
ncmd = None
for k, v in bd._pending.items():
    if v["kind"] == "command": ncmd = k
ck("a command button is pending in the open window", ncmd is not None)
sent.clear()
bd._end_session("agent")                                     # agent closes the window
ck("session ended", bd._session_phase == "ended" and not bd.session_open())
ck("stale command pending was invalidated (cleared)", ncmd not in bd._pending)
ck("stale command's button edited to 'session ended'",
   any("session ended" in (s.get("text") or "") for s in sent))
ck("stale command got a refused result", (result_of(rc["request_id"]) or {}).get("status") == "refused")
relay_before = len(relay_calls)
cb(ncmd, "A"); bd.poll_telegram()                            # a late tap on the dead button
ck("late tap on invalidated pending does NOT dispatch", len(relay_calls) == relay_before)

print("== T10e: MIXED-pending carry-forward — REVOKE with BOTH a session_open (re-anchor) AND a command pending -> both refused ==")
reset()
ro = req_open("intent A", 600); bd._handle_session_open(ro); cb(only_nonce(), "A"); bd.poll_telegram()
rc = req(["cat", "/etc/hostname"]); submit(rc)               # a command pending in the open window
ncmd = None
for k, v in bd._pending.items():
    if v["kind"] == "command": ncmd = k
rB = req_open("intent B", 1200); bd._handle_session_open(rB)  # a re-anchor -> a session_open pending too
nreanchor = None
for k, v in bd._pending.items():
    if v["kind"] == "session_open": nreanchor = k
ck("both a command AND a session_open (re-anchor) pending outstanding",
   ncmd is not None and nreanchor is not None and len(bd._pending) == 2)
sent.clear()
bd.revoke_all("test-mixed")                                  # end the session (revoke path)
ck("mixed: session ended by revoke", bd._session_phase == "ended" and not bd.session_open())
ck("mixed: ALL pending cleared (none survive)", len(bd._pending) == 0)
ck("mixed: the COMMAND pending got status=refused",
   (result_of(rc["request_id"]) or {}).get("status") == "refused")
ck("mixed: the SESSION_OPEN (re-anchor) pending got status=refused",
   (result_of(rB["request_id"]) or {}).get("status") == "refused")
relay_before = len(relay_calls)
cb(ncmd, "A"); bd.poll_telegram()                            # late tap on the dead command button
ck("mixed: late tap on the invalidated command does NOT dispatch", len(relay_calls) == relay_before)
cb(nreanchor, "A"); bd.poll_telegram()                       # late tap on the dead re-anchor button
ck("mixed: late tap on the invalidated re-anchor does NOT re-open a session",
   not bd.session_open() and bd._session_phase == "ended")

print("== T10f: CLOSE (agent) with BOTH a re-anchor session_open AND a command pending -> both refused, no survivor ==")
reset()
ro = req_open("intent A", 600); bd._handle_session_open(ro); cb(only_nonce(), "A"); bd.poll_telegram()
rc = req(["cat", "/etc/hostname"]); submit(rc)               # command pending
ncmd = None
for k, v in bd._pending.items():
    if v["kind"] == "command": ncmd = k
rB = req_open("intent B", 1200); bd._handle_session_open(rB)  # re-anchor pending (shares the live session msg id)
nreanchor = None
for k, v in bd._pending.items():
    if v["kind"] == "session_open": nreanchor = k
ck("close-path: two pending outstanding (command + re-anchor)", len(bd._pending) == 2)
bd._handle_session_close(req_close())                        # agent closes the window -> _end_session directly
ck("close-path: session ended", bd._session_phase == "ended" and not bd.session_open())
ck("close-path: NO pending survives the close (re-anchor cannot re-open)", len(bd._pending) == 0)
ck("close-path: command pending refused", (result_of(rc["request_id"]) or {}).get("status") == "refused")
ck("close-path: re-anchor session_open pending refused", (result_of(rB["request_id"]) or {}).get("status") == "refused")
relay_before = len(relay_calls)
cb(nreanchor, "A"); bd.poll_telegram()                       # late tap on the dead re-anchor button
ck("close-path: late tap on re-anchor does NOT re-open a session",
   not bd.session_open() and bd._session_phase == "ended")

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
