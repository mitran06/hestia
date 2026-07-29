#!/usr/bin/env python3
"""test_brokerd.py — Part 5 state-machine proof with a MOCKED Telegram + relay (no network, no taps).
Verifies: owner-filter drop, nonce single-use / no-double-exec on replay, auto-deny timeout, deny path,
the deterministic tier router (REFUSE/HARD_DENY/FREE_ZONE/SOFT_DENY/ALLOW) + the fail-CLOSED LLM reviewer
middle, confined-by-path, the escalation lever, the in-flight review registry + teardown, the exfil-cap,
the AUTO-path preconditions, the userns probe, the circuit breaker + concurrency cap, startup preflight,
full session lifecycle, and scan_incoming REJECT vs valid free-zone. The EMITTED wire confinement key is
asserted to be `workspace_only` (never a leaked `confined`)."""
import os, sys, json, tempfile, importlib.util, base64, time
os.environ["TELEGRAM_BROKER_BOT_TOKEN"] = "dummy"
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("brokerd", os.path.join(HERE, "..", "broker", "brokerd.py"))
bd = importlib.util.module_from_spec(spec); spec.loader.exec_module(bd)
B = bd.broker
R = bd.reviewer

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
class FakePopen:                           # stands in for `tailscale ssh ... {exec-argv <payload> | sudo -n exec-argv-elevated run <ticket>}`
    block_mode = False                     # True -> communicate() blocks until kill() (a "running" proc)
    raise_mode = False                     # True -> communicate() raises (simulate an exec/pipe failure)
    def __init__(self, cmd, stdout=None, stderr=None):
        self.killed = False; self.returncode = 0; self.ev = _threading.Event()
        if not FakePopen.block_mode: self.ev.set()
        cmds.append(list(cmd))
        # everything now dispatches on the exec-argv-elevated TICKET path (`sudo -n exec-argv-elevated run
        # <ticket>`), NOT the retired `_build_payload` relay path. The last arg is the base64 HMAC ticket;
        # decode it and capture (argv, CONFINED, exec_token) into relay_calls so the tests observe the
        # ticket/`cmds` path + the signed `confined` flag. Legacy `_build_payload` payloads (still built by
        # relay_exec/selftest + a few manual test dicts) carry `workspace_only` instead of `action:'run'` —
        # capture those with confined=None so the legacy revoke/kill tests that hand-build _inflight work.
        try:
            payload = json.loads(base64.b64decode(cmd[-1]).decode())
            if payload.get("action") == "run":                 # signed elevated ticket (the live path)
                relay_calls.append((payload.get("argv"), payload.get("confined"), payload.get("exec_token")))
            else:                                              # legacy _build_payload (selftest/relay_exec)
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

# ---- Layer-2 reviewer STUB -----------------------------------------------------------------------
# process() calls bd._review(req, tier) for SOFT_DENY/ALLOW. Tests drive the verdict via review_verdict:
# default "HUMAN" (fail-closed) so a middle command falls to the owner button unless a test opts into
# ALLOW. review_calls records every (argv, tier) the reviewer was asked about (so tests can prove the
# reviewer was/was-not consulted — e.g. HARD_DENY/REFUSE must NEVER reach it).
review_verdict = ["HUMAN"]
review_calls = []
def _stub_review(req, tier):
    review_calls.append((req.get("argv"), tier))
    return review_verdict[0]
bd._review = _stub_review

# ---- AUTO-path preconditions ---------------------------------------------------------------------
# The AUTO path (FREE_ZONE + reviewer-ALLOW) may auto-execute ONLY when ALL hold: reviewer enabled+keyed,
# elevation_enabled(), and the userns/bwrap probe succeeds. The harness satisfies all three by default so
# every auto test keeps exercising the auto path; the BB block below flips each one off.
bd.REVIEWER_ENABLED  = True                      # reviewer enabled + keyed (precondition 1)
bd.REVIEWER_KEY      = "test-reviewer-key"
bd.REVIEWER_BASE_URL = "https://reviewer.invalid/v1/chat/completions"
# elevation_enabled() is already True (elev.key provisioned above) -> precondition 2.
bd._userns_ok = lambda: True                     # stub the bwrap userns probe TRUE by default (precondition 3)

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
    # process() routes on the deterministic policy_tier(), not classify(). submit() computes the tier (as
    # scan_incoming does) and returns it so callers can assert the tier.
    t = B.policy_tier(r); bd.process(r, t, B.cmd_hash(r)); return t
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
    bd._reviews.clear()                                       # in-flight review registry
    # fresh CLOSED breaker + default MAX_REVIEWS each test so breaker/concurrency state never leaks between
    # tests (a tripped breaker from one test would spuriously route later ones).
    bd._breaker = bd.reviewer.Breaker(bd.HESTIA_REVIEWER_BREAKER_N, bd.HESTIA_REVIEWER_BREAKER_COOLDOWN)
    review_calls.clear(); review_verdict[0] = "HUMAN"        # default fail-closed each test
    bd.REVIEWER_ENABLED = True; bd.REVIEWER_KEY = "test-reviewer-key"   # restore AUTO preconditions
    bd.REVIEWER_BASE_URL = "https://reviewer.invalid/v1/chat/completions"
    bd.ELEV_KEY_FILE = _KF; bd._userns_ok = lambda: True               #   (elevation key + userns probe TRUE)
    bd._session_until, bd._session_until_wall = 0.0, 0.0
    bd._session_cmd_count = 0
    bd._exfil_hashes.clear()                                  # exfil-cap distinct-hash set (per-window)
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

print("== WIRE: emitted confinement key MUST be `workspace_only` (never a leaked `confined`) ==")
# The broker's internal confined var must be TRANSLATED to the wire key `workspace_only` in _build_payload
# (target/exec-argv reads `workspace_only`; a leaked `confined` key -> target E_SCHEMA). Assert the emitted
# JSON payload key literally.
_wire = json.loads(base64.b64decode(bd._build_payload(
    {"cwd": "/srv/projects", "argv": ["ls"]}, True, "00000000-0000-4000-8000-000000000abc")).decode())
ck("emitted payload carries `workspace_only` (the wire confinement key)", "workspace_only" in _wire and _wire["workspace_only"] is True)
ck("emitted payload does NOT leak the internal `confined` key", "confined" not in _wire)

print("== A: owner-filter + nonce single-use + no-double-exec (session forced open) ==")
# A HARD_DENY command (git push, OUTBOUND egress) is the deterministic human-button case: reviewer never
# sees it, on approve it runs UNCONFINED on the owner ticket path.
reset(); opensess()
r = req(["git", "push"]); ck("HARD_DENY -> human button", submit(r) == B.HARD_DENY)
n = only_nonce()
cb(n, "A", uid=999999); bd.poll_telegram()
ck("non-owner callback dropped (nonce NOT consumed)", len(bd._pending) == 1 and len(relay_calls) == 0)
cb(n, "A"); bd.poll_telegram()
ck("owner approve executes exactly once", len(relay_calls) == 1 and len(bd._pending) == 0)
ck("approved command ran UNCONFINED (confined=False)", relay_calls[0][1] is False)
cb(n, "A"); bd.poll_telegram()
ck("replay of consumed nonce does NOT re-execute", len(relay_calls) == 1)
ck("result status=executed", (result_of(r["request_id"]) or {}).get("status") == "executed")

print("== B: auto-deny on timeout (unanswered) ==")
reset(); opensess()
r = req(["git", "push"]); submit(r); n = only_nonce()
bd._pending[n]["deadline"] = bd.now() - 1; bd.check_expiries()
ck("expired pending removed, NOT executed", len(bd._pending) == 0 and len(relay_calls) == 0)
ck("result status=refused (auto-deny)", (result_of(r["request_id"]) or {}).get("status") == "refused")

print("== C: explicit deny ==")
reset(); opensess()
r = req(["git", "push"]); submit(r); n = only_nonce()
cb(n, "D"); bd.poll_telegram()
ck("deny -> not executed, refused result", len(relay_calls) == 0 and (result_of(r["request_id"]) or {}).get("status") == "refused")

print("== D: session lifecycle (no command opens a session; open window auto-runs free-zone) ==")
reset()  # session CLOSED
r = req(["ls", "-la"]); ck("ls is FREE_ZONE", submit(r) == B.FREE_ZONE)
# a command while IDLE no longer opens a session — the legacy auto-session is RETIRED.
ck("IDLE: free-zone did NOT run and NO session button was sent (legacy path retired)",
   len(relay_calls) == 0 and len(bd._pending) == 0)
ck("IDLE: no-session command is refused (must session-open first)",
   (result_of(r["request_id"]) or {}).get("status") == "refused")
# a window opens only via an approved agent session_open; force one open, then the OPEN-phase behaviour holds.
opensess()
r1 = req(["ls", "-la"]); submit(r1)
ck("OPEN: free-zone auto-runs CONFINED (confined=True, no button)", len(relay_calls) == 1 and relay_calls[0][1] is True)
r2 = req(["cat", "readme.md"]); submit(r2)
ck("OPEN: another free-zone auto-runs, no button", len(relay_calls) == 2 and len(bd._pending) == 0)
r3 = req(["git", "push"]); submit(r3)
ck("OPEN: HARD_DENY still buttons (command)", len(bd._pending) == 1 and list(bd._pending.values())[0]["kind"] == "command")

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
rA = {"v":1,"session_id":RID,"request_id":RID,"cwd":"/srv/projects","elevate":False,"argv":["git","push"]}
hA = B.cmd_hash(rA); bd.process(rA, B.HARD_DENY, hA)
nA = only_nonce()
# box "swaps": a SECOND request reusing the SAME request_id but a different (worse) argv
rB = {"v":1,"session_id":RID,"request_id":RID,"cwd":"/srv/projects","elevate":False,"argv":["scp","f","host:"]}
bd.process(rB, B.HARD_DENY, B.cmd_hash(rB))
ck("swap created a SEPARATE pending (didn't overwrite the first)", len(bd._pending) == 2)
cb(nA, "A"); bd.poll_telegram()
ck("approving nonce_A runs the STORED original argv, not the swap", relay_calls and relay_calls[-1][0] == ["git","push"])
ck("dispatched hash == button hash (stored req still hashes to hA)", B.cmd_hash(rA) == hA)

print("== G2: dispatch-time binding assertion refuses an in-memory-mutated stored request ==")
reset(); opensess()
r = req(["git","push"]); h = B.cmd_hash(r); bd.process(r, B.HARD_DENY, h); n = only_nonce()
bd._pending[n]["req"]["argv"] = ["scp","f","host:"]         # simulate a bug/tamper mutating the stored req
cb(n, "A"); bd.poll_telegram()
ck("mutated stored req -> NOT executed (binding mismatch)", len(relay_calls) == 0)
ck("result = refused binding mismatch", (result_of(r["request_id"]) or {}).get("reason","").startswith("binding mismatch"))

print("== H: incoming file is consumed (unlinked) at scan, BEFORE any approval/exec (no re-read window) ==")
reset(); opensess()
rid = "44444444-4444-4444-8444-444444444444"
p = os.path.join(bd.INCOMING, rid)
open(p, "wb").write(json.dumps({"v":1,"session_id":rid,"request_id":rid,"cwd":"/srv/projects","elevate":False,"argv":["git","push"]}).encode())
bd.scan_incoming()
ck("incoming file unlinked at scan (nothing left to mutate)", not os.path.exists(p))
ck("command held in memory awaiting approval (no exec yet)", len(bd._pending) == 1 and len(relay_calls) == 0)

print("== G3: tier pinned by policy_tier() — tier-drift is refused; risk-class disclosed on button ==")
reset(); opensess()
r = req(["git","push"]); h = B.cmd_hash(r); bd.process(r, B.HARD_DENY, h); n = only_nonce()
bd._pending[n]["tier"] = B.FREE_ZONE                         # tamper the stored (approved) tier
cb(n, "A"); bd.poll_telegram()
ck("tier-drift -> refused, not executed", len(relay_calls) == 0 and (result_of(r["request_id"]) or {}).get("reason","").startswith("binding mismatch"))
mc = bd._fmt({"cwd":"/srv/projects","argv":["git","push"],"request_id":"x"}, "a"*64, B.HARD_DENY)
ck("command button discloses it runs UNCONFINED as the owner", "UNCONFINED" in mc and bd.ELEV_RUNAS in mc)
ck("session button discloses it opens a work session", "session" in bd._fmt({"cwd":"/srv/projects","argv":["ls"],"request_id":"x"}, "a"*64, "session").lower())
# and confirm the normal confined flag is still correct end-to-end (human tap -> unconfined)
reset(); opensess()
r = req(["git","push"]); bd.process(r, B.HARD_DENY, B.cmd_hash(r)); cb(only_nonce(), "A"); bd.poll_telegram()
ck("approved HARD_DENY runs UNCONFINED (confined=False)", relay_calls and relay_calls[-1][1] is False)

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
                     "chash": "x", "decision": B.HARD_DENY, "wo": False, "proc": fp, "revoked": False, "started": bd.now()}
rp = req(["git", "push"]); submit(rp); npend = only_nonce()   # one pending too
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
                      "chash": "x", "decision": B.HARD_DENY, "wo": False, "proc": None, "revoked": True, "started": bd.now()}
bd._run_exec(tok2)                                           # inline; sees revoked -> kills, writes revoked result
ck("revoked in-flight -> result status=revoked", (result_of(rid2) or {}).get("status") == "revoked")
ck("remote kill invoked for revoked worker", tok2 in remote_kills)

print("== K: concurrent-exec cap (dispatch refuses beyond MAX_INFLIGHT) ==")
reset(); opensess()
for i in range(bd.MAX_INFLIGHT):                            # fill the table with stuck fakes (proc set, not reaped)
    bd._inflight["cccccccc-cccc-4ccc-8ccc-%012d" % i] = {"req": {}, "proc": FakePopen(["x"]*6), "revoked": False}
rc = req(["git", "push"]); bd.dispatch(rc, B.cmd_hash(rc), B.HARD_DENY, confined=False)
ck("over-cap dispatch refused", (result_of(rc["request_id"]) or {}).get("reason") == "too many concurrent commands")

print("== L: /panic and REVOKE button trigger revoke; non-owner cannot ==")
reset(); opensess()
r = req(["git", "push"]); submit(r); only_nonce()
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
    rM = req(["git", "push"])
    bd.dispatch(rM, B.cmd_hash(rM), B.HARD_DENY, confined=False)  # -> real worker thread on the owner ticket path, blocks
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
    # everything now dispatches ELEVATED (owner ticket path), so revoke uses the elevated kill-ticket path
    ck("target process-group kill was invoked for it (elevated kill path)", tok in remote_kills_elev)
    ck("in-flight table drained after revoke", len(bd._inflight) == 0)
finally:
    FakePopen.block_mode = False; bd.threading.Thread = InlineThread

print("== O: worker crash (communicate raises) -> ALWAYS frees the slot + writes an error result (B1 fix) ==")
reset(); opensess()
FakePopen.raise_mode = True
try:
    r = req(["git", "push"]); bd.process(r, B.HARD_DENY, B.cmd_hash(r)); n = only_nonce()
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
    for r in rs: bd.process(r, B.FREE_ZONE, B.cmd_hash(r))
    ck("first 3 within budget ran", len(relay_calls) == 3)
    ck("4th over budget refused", (result_of(rs[3]["request_id"]) or {}).get("reason", "").startswith("session command budget"))
finally:
    bd.SESSION_CMD_BUDGET = _ob

print("== Q: pending-approvals cap (bounds outstanding buttons; anti-flood/fatigue) ==")
reset(); opensess()
_op = bd.MAX_PENDING; bd.MAX_PENDING = 2
try:
    rs = [req(["git", "push"]) for _ in range(3)]
    for r in rs: bd.process(r, B.HARD_DENY, B.cmd_hash(r))
    ck("pending capped at MAX_PENDING", len(bd._pending) == 2)
    ck("over-cap command refused (pending cap)", (result_of(rs[2]["request_id"]) or {}).get("reason", "").startswith("too many pending"))
finally:
    bd.MAX_PENDING = _op

print("== R: human-approved command -> HMAC-ticketed exec-argv-elevated path, unconfined, run_as owner ==")
# Uniform-owner: EVERY executing outcome runs as the owner unix user on the signed ticket path. A human-
# approved HARD_DENY command dispatches UNCONFINED (confined=False) via `sudo -n exec-argv-elevated run
# <ticket>` and the result carries elevated=True + run_as + confined=False.
reset(); opensess()
r = req(["git", "push"])
ck("HARD_DENY -> human button", submit(r) == B.HARD_DENY)
n = only_nonce()
ck("routed to a uniform 'command' button (no separate elevated kind)", bd._pending[n]["kind"] == "command")
disc = bd._fmt(r, "a" * 64, B.HARD_DENY)
ck("button discloses run_as + UNCONFINED risk", bd.ELEV_RUNAS in disc and "UNCONFINED" in disc)
cb(n, "A"); bd.poll_telegram()
last = cmds[-1] if cmds else []
ck("dispatch used sudo exec-argv-elevated run <ticket>", "sudo" in last and any("exec-argv-elevated" in x for x in last) and "run" in last)
res = result_of(r["request_id"])
ck("result carries elevated=True + run_as + confined=False", res and res.get("elevated") is True
   and res.get("run_as") == bd.ELEV_RUNAS and res.get("confined") is False)

print("== R2: in-flight revoke uses the elevated (signed kill-ticket) kill path (uniform owner) ==")
reset(); opensess()
tok = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
bd._inflight[tok] = {"req": {"request_id": "77777777-7777-4777-8777-777777777777", "argv": ["x"], "cwd": "/home/owner"},
                     "chash": "x", "decision": B.HARD_DENY, "wo": False, "elevated": True,
                     "proc": FakePopen(["x"] * 6), "revoked": False, "started": bd.now()}
bd.revoke_all("test-elev")
ck("elevated token routed to ELEVATED kill (not plain kill)", tok in remote_kills_elev and tok not in remote_kills)

print("== S: elevation disabled (no key) -> human-tap command refused, no button, not run ==")
# Uniform-owner: the HMAC ticket is a hard dependency for EVERY executing outcome. With no key, a command
# that would need a human tap (HARD_DENY) is refused BEFORE any button (never a silent unconfined exec).
reset(); opensess()
_savedkf = bd.ELEV_KEY_FILE; bd.ELEV_KEY_FILE = os.path.join(TD, "nope")
try:
    r = req(["git", "push"])
    bd.process(r, B.HARD_DENY, B.cmd_hash(r))
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
ck("open render has 🟢 Session header (open · expires)", "🟢 Session open · expires" in _txt)
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

print("== T4e: intent unicode-neutralization — no bidi/zero-width in the canonical anchor ==")
# The box-authored intent is shown VERBATIM on the owner's 🟡 approval button AND promoted to the reviewer
# anchor _session_intent. A malicious box could hide/reorder the displayed intent with bidirectional control
# chars (RLO/LRO/PDF/isolates) or make text vanish with zero-width chars. _canon_intent must NEUTRALIZE these
# so the owner sees the TRUE intent (homoglyph folding is intentionally out of scope — an accepted residual).
_BIDI = ["‪", "‫", "‬", "‭", "‮",   # LRE RLE PDF LRO RLO
         "⁦", "⁧", "⁨", "⁩",             # LRI RLI FSI PDI
         "‎", "‏"]                                 # LRM RLM
_ZW   = ["​", "‌", "‍", "﻿"]             # ZWSP ZWNJ ZWJ BOM/ZWNBSP
# a nasty intent: RLO reorder + zero-width joiner + BOM woven through readable text
_evil = "read " + "‮" + "elif/ " + "​" + "logs" + "﻿" + "⁦" + "now"
_out  = bd._canon_intent(_evil)
for _c in _BIDI + _ZW:
    ck("T4e: canonical intent contains NO U+%04X after neutralization" % ord(_c), _c not in _out)
    # STRIPPED, not merely escaped to visible '\x202e' litter (the owner must read a CLEAN intent, and a
    # future loosening of _san's printable check must not silently reopen the reorder/hide hole).
    ck("T4e: U+%04X is STRIPPED, not left as a '\\xNN' escape in the owner-facing intent" % ord(_c),
       ("\\x%02x" % ord(_c)) not in _out and ("\\x%04x" % ord(_c)) not in _out)
# the visible letters survive (we strip controls, not content) — spoofing controls gone, meaning intact,
# and the readable words are now CONTIGUOUS (the woven-in controls no longer split them).
ck("T4e: readable content of the intent survives neutralization",
   all(w in _out for w in ("read", "elif/", "logs", "now")))
ck("T4e: neutralized intent is clean readable text (no control/escape residue)",
   _out == "read elif/ logsnow")
# end-to-end: the neutralized string is what reaches BOTH the button text AND the promoted anchor.
reset()
ro4e = req_open(intent=_evil, secs=600)
bd._handle_session_open(ro4e)
for _c in _BIDI + _ZW:
    ck("T4e: 🟡 button text is free of U+%04X" % ord(_c), _c not in sent[-1]["text"])
ne = only_nonce(); cb(ne, "A"); bd.poll_telegram()
ck("T4e: promoted anchor _session_intent == canonical (neutralized) intent", bd._session_intent == _out)
for _c in _BIDI + _ZW:
    ck("T4e: reviewer anchor is free of U+%04X" % ord(_c), _c not in bd._session_intent)
# generic Cf-category format chars (beyond the named list) are also neutralized (e.g. U+2060 WORD JOINER,
# U+00AD SOFT HYPHEN) — the sanitizer kills the whole Cf class, not just an enumerated denylist.
_cf = bd._canon_intent("a⁠b­c")
import unicodedata as _ud
ck("T4e: other Cf-category format chars neutralized too (no residual Cf)",
   not any(_ud.category(ch) == "Cf" for ch in _cf))

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
# --- a HARD_DENY command approval: answerCallbackQuery must carry text="" (no toast) ---
reset(); opensess()
r = req(["git", "push"]); submit(r); n = only_nonce()
cb(n, "A"); bd.poll_telegram()
ck("command approve executed", len(relay_calls) == 1)
ck("answerCallbackQuery invoked exactly once", len(acq) == 1)
ck("answerCallbackQuery text is empty (no 'ok' toast)", acq and acq[0].get("text") == "")

# --- non-owner drop: answerCallbackQuery still empty text (no 'not authorized' toast) ---
reset(); opensess()
r = req(["git", "push"]); submit(r); n = only_nonce()
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
                      "chash": "x", "decision": B.HARD_DENY, "wo": False, "proc": fpR, "revoked": False, "started": bd.now()}
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

# (a) FREE_ZONE auto command -> ✓ exit0, auto++
rA = req(["ls", "-la"]); submit(rA)
ck("auto command logged ✓ exit0", (bd._session_log.get(rA["request_id"]) or {}).get("status") == "✓ exit0")
ck("auto command icon is the exit icon", (bd._session_log.get(rA["request_id"]) or {}).get("icon") == "✓")
ck("auto count == 1", bd._session_counts["auto"] == 1)

# (b) HARD_DENY approved -> 🔴 awaiting BEFORE tap, then ⏳ running, then ✓ exit0, approved++
rB = req(["git", "push"]); submit(rB)
ck("HARD_DENY command shows 🔴 awaiting BEFORE approval (row matches the 🔴 button)", (bd._session_log.get(rB["request_id"]) or {}).get("icon") == "🔴")
ck("🔴 awaiting does NOT bump any count yet", bd._session_counts["approved"] == 0)
nB = only_nonce()
cb(nB, "A"); bd.poll_telegram()
ck("approved command logged ✓ exit0 after run", (bd._session_log.get(rB["request_id"]) or {}).get("status") == "✓ exit0")
ck("approved count == 1", bd._session_counts["approved"] == 1)

# (c) denied command -> ⛔ denied + blocked++
open_via_approve()
rC = req(["git", "push"]); submit(rC); nC = only_nonce()
cb(nC, "D"); bd.poll_telegram()
ck("denied command logged ⛔ denied", (bd._session_log.get(rC["request_id"]) or {}).get("status") == "⛔ denied")
ck("blocked count == 1 after deny", bd._session_counts["blocked"] == 1)

# (c2) approval TIMEOUT -> ⌛ + blocked++
open_via_approve()
rC2 = req(["git", "push"]); submit(rC2)
for _n, _p in list(bd._pending.items()):
    if _p["kind"] == "command": _p["deadline"] = bd.now() - 1        # force this pending past its deadline
bd.check_expiries()
ck("approval-timeout logged ⌛", (bd._session_log.get(rC2["request_id"]) or {}).get("icon") == "⌛")
ck("approval-timeout counts as blocked", bd._session_counts["blocked"] == 1)

# (d) refused (pending cap) -> 🚫 refused: ...
open_via_approve()
_op = bd.MAX_PENDING; bd.MAX_PENDING = 1
try:
    rD1 = req(["git", "push"]); submit(rD1)          # takes the one pending slot
    rD2 = req(["scp", "f", "host:"]);  submit(rD2)           # over cap -> refuse()
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
# (i2) subsequent-render contract: once a live msg_id exists, the buffered entry RENDERS on the next forced
# flush. Locks the lazy-render guarantee — buffering while msg_id was None must NOT lose data.
sent.clear()
bd._session_msg_id = 7777                                     # a live message now exists
bd._flush_session_msg(force=True)
_i2 = [s for s in sent if s.get("message_id") == 7777 and "uniq-buffered-cmd" in (s.get("text") or "")]
ck("T11: buffered-while-None entry renders on the next forced flush", len(_i2) >= 1)

print("== T11: _render_session snapshots shared state under _lock (thread-safe) ==")
# (a) SNAPSHOT SAFETY (deterministic): _render_session copies _session_log under _lock, so mutating the
# live dict AFTER render started does not corrupt the returned text.
open_via_approve()
bd.session_log("00000000-0000-4000-8000-00000000ma01", "✓", ["render-snap-a"], "✓ exit0", kind="auto")
_snap_txt = bd._render_session()                             # renders from a private copy under _lock
bd.session_log("00000000-0000-4000-8000-00000000ma02", "✓", ["render-snap-b-added-after"], "✓ exit0", kind="auto")
ck("T11: render captured a snapshot (later insert not in the earlier text)",
   "render-snap-a" in _snap_txt and "render-snap-b-added-after" not in _snap_txt)
ck("T11: a fresh render sees the newly-inserted entry",
   "render-snap-b-added-after" in bd._render_session())

# (c) SNAPSHOT CONSISTENCY (deterministic): the header counts and the log body must come from the SAME
# atomic snapshot. The ⚪ header's 'N cmds' always equals the number of distinct logged request_ids at
# snapshot time — never a torn read where counts and log disagree.
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
bd._session_last_flush = bd.now()                            # pretend we just flushed (monotonic stamp)
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
rc = req(["git", "push"]); submit(rc)               # HARD_DENY -> one command pending
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
rc = req(["git", "push"]); submit(rc)               # a command pending in the open window
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
rc = req(["git", "push"]); submit(rc)               # command pending
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

print("== U: ROUTING — process() routes on policy_tier() (reviewer stubbed) ==")
# U1: FREE_ZONE -> auto, NO button, dispatched (on the owner ticket path).
reset(); opensess()
rfz = req(["ls", "-la"])
ck("FREE_ZONE tier", submit(rfz) == B.FREE_ZONE)
ck("FREE_ZONE auto-ran (dispatched) with NO button", len(relay_calls) == 1 and len(bd._pending) == 0)
ck("FREE_ZONE never consulted the reviewer (deterministic fast-path)", len(review_calls) == 0)

# U2: HARD_DENY -> human button, reviewer NOT consulted.
reset(); opensess()
rhd = req(["git", "push"])
ck("HARD_DENY tier", submit(rhd) == B.HARD_DENY)
ck("HARD_DENY -> exactly one human button, nothing ran", len(bd._pending) == 1 and len(relay_calls) == 0)
ck("HARD_DENY pending is a 'command' button", list(bd._pending.values())[0]["kind"] == "command")
ck("HARD_DENY never reaches the reviewer (intent-proof floor)", len(review_calls) == 0)

# U3: REFUSE -> refused, NO approve button at all (unapprovable).
reset(); opensess()
rref = req(["rm", "-rf", "/"])
ck("REFUSE tier", submit(rref) == B.REFUSE)
ck("REFUSE -> refused, NO button, nothing ran",
   len(bd._pending) == 0 and len(relay_calls) == 0
   and (result_of(rref["request_id"]) or {}).get("status") == "refused")
ck("REFUSE reason marks it unapprovable", "unapprovable" in (result_of(rref["request_id"]) or {}).get("reason", ""))
ck("REFUSE never reaches the reviewer", len(review_calls) == 0)

# U4: SOFT_DENY / ALLOW -> reviewer consulted.
reset(); opensess()
rsd = req(["rm", "foo"]); ck("SOFT_DENY tier", submit(rsd) == B.SOFT_DENY)
ck("SOFT_DENY consulted the reviewer", any(c[1] == B.SOFT_DENY for c in review_calls))
reset(); opensess()
ral = req(["mkdir", "newdir"]); ck("ALLOW tier", submit(ral) == B.ALLOW)
ck("ALLOW consulted the reviewer", any(c[1] == B.ALLOW for c in review_calls))

# U5: reviewer-ALLOW -> dispatch, NO pending button.
reset(); opensess(); review_verdict[0] = "ALLOW"
ra = req(["mkdir", "newdir"]); submit(ra)
ck("reviewer-ALLOW dispatched (ran)", len(relay_calls) == 1)
ck("reviewer-ALLOW left NO pending button", len(bd._pending) == 0)
ck("reviewer-ALLOW counted in the auto bucket (confined auto-run)", bd._session_counts["auto"] == 1)

# U6: reviewer-BLOCK (HUMAN) -> button, not run.
reset(); opensess(); review_verdict[0] = "HUMAN"
rb = req(["mkdir", "newdir"]); submit(rb)
ck("reviewer-BLOCK -> one human button, nothing ran", len(bd._pending) == 1 and len(relay_calls) == 0)
ck("reviewer-BLOCK pending is a 'command' button", list(bd._pending.values())[0]["kind"] == "command")

print("== V: CONFINED-BY-PATH — confined decided by the approval PATH in process(), carried on _inflight ==")
# V1: reviewer-ALLOW auto -> confined=True (on _inflight AND on the minted ticket).
reset(); opensess(); review_verdict[0] = "ALLOW"
rv = req(["mkdir", "newdir"]); submit(rv)
ck("reviewer-ALLOW: relay ticket carries confined=True", relay_calls and relay_calls[-1][1] is True)
ck("reviewer-ALLOW: result carries confined=True", (result_of(rv["request_id"]) or {}).get("confined") is True)

# V2: FREE_ZONE auto -> confined=True.
reset(); opensess()
rv2 = req(["ls", "-la"]); submit(rv2)
ck("FREE_ZONE: relay ticket carries confined=True", relay_calls and relay_calls[-1][1] is True)

# V3: SOFT_DENY-unlock (reviewer-ALLOW on a SOFT_DENY) -> confined=True.
reset(); opensess(); review_verdict[0] = "ALLOW"
rv3 = req(["rm", "foo"]); ck("SOFT_DENY tier", submit(rv3) == B.SOFT_DENY)
ck("SOFT_DENY unlock: relay ticket carries confined=True", relay_calls and relay_calls[-1][1] is True)

# V4: HARD_DENY human tap -> confined=False on approve.
reset(); opensess()
rv4 = req(["git", "push"]); submit(rv4); n = only_nonce()
cb(n, "A"); bd.poll_telegram()
ck("HARD_DENY approved: relay ticket carries confined=False", relay_calls and relay_calls[-1][1] is False)
ck("HARD_DENY approved: result carries confined=False", (result_of(rv4["request_id"]) or {}).get("confined") is False)

# V5: reviewer-BLOCK human tap -> confined=False on approve.
reset(); opensess(); review_verdict[0] = "HUMAN"
rv5 = req(["mkdir", "newdir"]); submit(rv5); n = only_nonce()
cb(n, "A"); bd.poll_telegram()
ck("reviewer-BLOCK approved: relay ticket carries confined=False", relay_calls and relay_calls[-1][1] is False)

# V6: confined is SET IN process() from the PATH — the stored _inflight.confined matches the path, and
#     _run_exec READS it (does not recompute from the re-derived tier). Prove: an auto command's
#     _inflight slot carries confined=True while it is in flight (block the worker to inspect).
reset(); opensess(); review_verdict[0] = "ALLOW"
bd.threading.Thread = RealThread; FakePopen.block_mode = True
try:
    rv6 = req(["mkdir", "newdir"]); submit(rv6)
    seen = None
    for _ in range(50):
        with bd._lock:
            live = [v for v in bd._inflight.values() if v.get("proc")]
        if live: seen = live[0]; break
        time.sleep(0.05)
    ck("auto command stored confined=True on _inflight (set in process, carried)", seen is not None and seen.get("confined") is True)
    bd.revoke_all("cleanup-v6")
finally:
    FakePopen.block_mode = False; bd.threading.Thread = InlineThread

print("== W: ESCALATION LEVER — elevate on ALLOW/SOFT_DENY -> HUMAN button UNCONFINED; no effect on floor ==")
# W1: elevate on an ALLOW command -> human button (reviewer NOT consulted), confined=False on approve.
reset(); opensess(); review_verdict[0] = "ALLOW"        # even with a would-be ALLOW verdict, elevate forces a tap
rw = req(["mkdir", "newdir"], elevate=True)
ck("elevate ALLOW tier is still ALLOW (tier is elevate-independent)", submit(rw) == B.ALLOW)
ck("elevate ALLOW -> one human button, nothing auto-ran", len(bd._pending) == 1 and len(relay_calls) == 0)
ck("elevate ALLOW bypassed the reviewer (goes straight to a tap)", len(review_calls) == 0)
n = only_nonce(); cb(n, "A"); bd.poll_telegram()
ck("elevate ALLOW approved -> ran UNCONFINED (confined=False)", relay_calls and relay_calls[-1][1] is False)

# W2: elevate on a SOFT_DENY command -> human button, confined=False on approve.
reset(); opensess()
rw2 = req(["rm", "foo"], elevate=True)
ck("elevate SOFT_DENY tier still SOFT_DENY", submit(rw2) == B.SOFT_DENY)
ck("elevate SOFT_DENY -> human button", len(bd._pending) == 1 and len(review_calls) == 0)
n = only_nonce(); cb(n, "A"); bd.poll_telegram()
ck("elevate SOFT_DENY approved -> UNCONFINED", relay_calls and relay_calls[-1][1] is False)

# W3: elevate on a HARD_DENY has NO effect — floor is unaffected (still HARD_DENY human tap, unconfined).
reset(); opensess()
rw3 = req(["git", "push"], elevate=True)
ck("elevate HARD_DENY tier UNCHANGED (still HARD_DENY)", submit(rw3) == B.HARD_DENY)
ck("elevate HARD_DENY -> still a human button, reviewer untouched", len(bd._pending) == 1 and len(review_calls) == 0)

# W4: elevate on a REFUSE has NO effect — still unapprovable, no button (cannot lower security).
reset(); opensess()
rw4 = req(["rm", "-rf", "/"], elevate=True)
ck("elevate REFUSE tier UNCHANGED (still REFUSE)", submit(rw4) == B.REFUSE)
ck("elevate REFUSE -> still refused, NO button (elevate cannot unlock the hardline)",
   len(bd._pending) == 0 and (result_of(rw4["request_id"]) or {}).get("status") == "refused")

# W5: elevate on a FREE_ZONE command still auto-runs confined (lever only fires on ALLOW/SOFT_DENY).
reset(); opensess()
rw5 = req(["ls", "-la"], elevate=True)
ck("elevate FREE_ZONE tier still FREE_ZONE", submit(rw5) == B.FREE_ZONE)
ck("elevate FREE_ZONE still auto-ran confined (no tap)", len(relay_calls) == 1 and relay_calls[-1][1] is True and len(bd._pending) == 0)

print("== X: _reviews registry + worker thread + teardown ==")
# The reviewer now runs in a WORKER thread off the main poll loop. Each in-flight review is registered
# in bd._reviews (guarded by _lock) with a per-review `revoked` flag + the `intent_hash` it was issued
# under; the HTTPS call is made with _lock RELEASED; immediately before dispatching ALLOW the worker
# re-acquires _lock and atomically re-checks phase=='open' AND not revoked AND intent_hash unchanged,
# minting the ticket inside the SAME lock hold. revoke_all() AND _end_session() tear down _reviews.

_review_gate = _threading.Event()
_review_entered = _threading.Event()
_blocking_verdict = ["ALLOW"]
def _blocking_review(req, tier):
    review_calls.append((req.get("argv"), tier))
    _review_entered.set()
    _review_gate.wait(5)
    return _blocking_verdict[0]

# X1: the review runs OFF the main loop — while a review blocks in-flight, submit() has returned and the
#     main thread stays responsive (can revoke). Registered in _reviews with a revoked flag + intent_hash.
print("-- X1: reviewer runs off the main loop (worker thread; main loop not stalled) --")
reset(); open_via_approve("intent-x1")
bd.threading.Thread = RealThread
_review_gate.clear(); _review_entered.clear(); _blocking_verdict[0] = "ALLOW"
_saved_review = bd._review; bd._review = _blocking_review
try:
    rx1 = req(["mkdir", "newdir"])
    t0 = time.time(); submit(rx1); submit_dt = time.time() - t0
    ck("submit() returns promptly (review is off the main loop)", submit_dt < 1.0)
    ck("review is registered in _reviews while in-flight", _review_entered.wait(2) and len(bd._reviews) == 1)
    _rinfo = list(bd._reviews.values())[0]
    ck("registered review carries a revoked flag (False) + an intent_hash",
       _rinfo.get("revoked") is False and isinstance(_rinfo.get("intent_hash"), str) and _rinfo["intent_hash"])
    ck("nothing dispatched yet (review still in-flight, no auto-run)", len(relay_calls) == 0)
    bd.revoke_all("x1-revoke")
    ck("main loop revoked the session while review in-flight (not stalled)", not bd.session_open())
    _review_gate.set()
    for _ in range(60):
        if len(bd._reviews) == 0: break
        time.sleep(0.02)
    ck("torn-down review does NOT dispatch after it unblocks", len(relay_calls) == 0)
    ck("review registry drained after teardown+unblock", len(bd._reviews) == 0)
finally:
    bd._review = _saved_review; bd.threading.Thread = InlineThread; _review_gate.set()

# X2: window-closed-mid-review -> the WORKER's pre-dispatch re-check (phase != 'open') blocks dispatch AND
#     the box gets a terminal "session closed" reply.
print("-- X2: window closed mid-review -> WORKER re-check terminal 'session closed' reply, no dispatch --")
reset(); open_via_approve("intent-x2")
rx2 = req(["mkdir", "newdir"])
_revid_x2 = "rev-x2"
with bd._lock:
    bd._reviews[_revid_x2] = {"req": rx2, "chash": B.cmd_hash(rx2), "tier": B.ALLOW,
                              "revoked": False, "intent_hash": bd._intent_hash(bd._session_intent)}
bd._session_phase = "ended"                                 # window closed while the review was OUT (no teardown)
bd._finalize_review(_revid_x2, "ALLOW")
ck("ALLOW verdict but window closed -> NOT dispatched", len(relay_calls) == 0)
_r = result_of(rx2["request_id"]) or {}
ck("window-closed-mid-review -> terminal refused result", _r.get("status") == "refused")
ck("terminal reply names the closed session", "session closed" in (_r.get("reason") or "").lower())
ck("review registry drained (no dangling review)", len(bd._reviews) == 0)
# and via the real _end_session teardown path (the common case): window closes mid-review -> refused reply
reset(); open_via_approve("intent-x2b")
def _close_then_allow(req, tier):                           # simulate the window closing DURING the call
    review_calls.append((req.get("argv"), tier))
    bd._end_session("agent")                                # phase -> 'ended' (teardown pops+refuses the review)
    return "ALLOW"
_saved_review = bd._review; bd._review = _close_then_allow
try:
    rx2b = req(["mkdir", "newdir"]); submit(rx2b)
    ck("close-during-review (teardown path) -> NOT dispatched", len(relay_calls) == 0)
    ck("close-during-review (teardown path) -> refused result",
       (result_of(rx2b["request_id"]) or {}).get("status") == "refused")
    ck("no dangling review after close", len(bd._reviews) == 0)
finally:
    bd._review = _saved_review

# X3: the re-check gates on the per-review `revoked` flag, NOT on _session_until.
print("-- X3: re-check gates on the per-review revoked flag (independent of _session_until) --")
reset(); open_via_approve("intent-x3")
def _revoke_then_allow(req, tier):
    review_calls.append((req.get("argv"), tier))
    with bd._lock:                                          # window stays OPEN; only THIS review is revoked
        for rv in bd._reviews.values(): rv["revoked"] = True
    return "ALLOW"
_saved_review = bd._review; bd._review = _revoke_then_allow
try:
    rx3 = req(["mkdir", "newdir"]); submit(rx3)
    ck("session still OPEN (revoked flag is per-review, not the window)", bd.session_open())
    ck("revoked review -> NOT auto-dispatched even though window is open", len(relay_calls) == 0)
    ck("revoked review (open window) -> falls to a HUMAN button", len(bd._pending) == 1
       and list(bd._pending.values())[0]["kind"] == "command")
    ck("review registry drained", len(bd._reviews) == 0)
finally:
    bd._review = _saved_review

# X4: the ticket is minted INSIDE the same _lock hold as the re-check.
print("-- X4: ticket minted under the same _lock hold as the re-check (pre-minted on _inflight) --")
reset(); open_via_approve("intent-x4")
bd.threading.Thread = RealThread
_review_gate.clear(); _review_entered.clear(); _blocking_verdict[0] = "ALLOW"
_saved_review = bd._review; bd._review = _blocking_review
try:
    rx4 = req(["mkdir", "newdir"]); submit(rx4)
    ck("review in-flight", _review_entered.wait(2))
    _review_gate.set()                                     # let it finalize -> mint under lock -> dispatch
    for _ in range(60):
        if relay_calls: break
        time.sleep(0.02)
    ck("passing ALLOW review dispatched confined=True", relay_calls and relay_calls[-1][1] is True)
    ck("dispatched ticket was minted by the broker (elevated ticket path)", cmds
       and "run" in cmds[-1] and any("exec-argv-elevated" in x for x in cmds[-1]))
finally:
    bd._review = _saved_review; bd.threading.Thread = InlineThread; _review_gate.set()
# negative: a re-check that fails (intent drift) mints nothing at all (no _inflight slot leaks)
reset(); open_via_approve("intent-x4b")
def _drift_then_allow(req, tier):
    review_calls.append((req.get("argv"), tier))
    bd._session_intent = "a totally different intent"       # re-anchor -> intent_hash drift
    return "ALLOW"
_saved_review = bd._review; bd._review = _drift_then_allow
try:
    rx4b = req(["mkdir", "newdir"]); submit(rx4b)
    ck("failed re-check minted nothing (no _inflight slot)", len(bd._inflight) == 0)
    ck("failed re-check did NOT dispatch", len(relay_calls) == 0)
finally:
    bd._review = _saved_review

# X5: revoke_all() tears down _reviews.
print("-- X5: revoke_all() tears down in-flight reviews (revoked=True + refused) --")
reset(); open_via_approve("intent-x5")
bd.threading.Thread = RealThread
_review_gate.clear(); _review_entered.clear(); _blocking_verdict[0] = "ALLOW"
_saved_review = bd._review; bd._review = _blocking_review
try:
    rx5 = req(["mkdir", "newdir"]); submit(rx5)
    ck("review registered before revoke", _review_entered.wait(2) and len(bd._reviews) == 1)
    _rid5 = rx5["request_id"]
    bd.revoke_all("x5")
    ck("revoke_all set the in-flight review's revoked flag (or drained it)",
       all(rv.get("revoked") for rv in bd._reviews.values()) or len(bd._reviews) == 0)
    _r = result_of(_rid5) or {}
    ck("revoke_all routed the in-flight review to a refused result", _r.get("status") == "refused")
    _review_gate.set()
    for _ in range(60):
        if len(bd._reviews) == 0: break
        time.sleep(0.02)
    ck("revoked-during-review command did NOT dispatch after unblock", len(relay_calls) == 0)
finally:
    bd._review = _saved_review; bd.threading.Thread = InlineThread; _review_gate.set()

# X6: _end_session() tears down _reviews the same way (agent close / expiry path).
print("-- X6: _end_session() tears down in-flight reviews (revoked + refused) --")
reset(); open_via_approve("intent-x6")
bd.threading.Thread = RealThread
_review_gate.clear(); _review_entered.clear(); _blocking_verdict[0] = "ALLOW"
_saved_review = bd._review; bd._review = _blocking_review
try:
    rx6 = req(["mkdir", "newdir"]); submit(rx6)
    ck("review registered before end_session", _review_entered.wait(2) and len(bd._reviews) == 1)
    _rid6 = rx6["request_id"]
    bd._end_session("agent")
    ck("_end_session set the in-flight review revoked (or drained it)",
       all(rv.get("revoked") for rv in bd._reviews.values()) or len(bd._reviews) == 0)
    _r = result_of(_rid6) or {}
    ck("_end_session routed the in-flight review to a refused result", _r.get("status") == "refused")
    _review_gate.set()
    for _ in range(60):
        if len(bd._reviews) == 0: break
        time.sleep(0.02)
    ck("ended-during-review command did NOT dispatch after unblock", len(relay_calls) == 0)
finally:
    bd._review = _saved_review; bd.threading.Thread = InlineThread; _review_gate.set()

# X7: a mid-session intent RE-ANCHOR bumps intent_hash, invalidating every in-flight review (-> HUMAN).
print("-- X7: intent re-anchor bumps intent_hash -> in-flight reviews -> HUMAN --")
reset(); open_via_approve("original intent")
def _reanchor_then_allow(req, tier):
    review_calls.append((req.get("argv"), tier))
    bd._session_intent = "re-anchored to a NEW intent"       # window still open, only the anchor changed
    return "ALLOW"
_saved_review = bd._review; bd._review = _reanchor_then_allow
try:
    rx7 = req(["mkdir", "newdir"]); submit(rx7)
    ck("re-anchored review NOT auto-dispatched (intent_hash drift)", len(relay_calls) == 0)
    ck("re-anchored review (window still open) -> HUMAN button", len(bd._pending) == 1
       and list(bd._pending.values())[0]["kind"] == "command")
    ck("review registry drained", len(bd._reviews) == 0)
finally:
    bd._review = _saved_review

print("== Y: dispatch confined-CARRY + tier-drift binding (replaces classify-equality; removes elevated+IN_SCOPE) ==")
# dispatch()/_run_exec: (1) they READ _inflight.confined and NEVER recompute it from the re-derived tier;
# (2) dispatch() re-derives policy_tier() and refuses on TIER drift; (3) a reviewer-ALLOW command (formerly
# a NEEDS_BUTTON per-command button) dispatches on the owner ticket path with NO pending button.

# Y1: _run_exec READS _inflight.confined — it does NOT recompute confined from the (re-derived) tier.
print("-- Y1: _run_exec reads _inflight.confined (never recomputed from tier) --")
reset(); opensess()
_toky1 = "10000000-0000-4000-8000-00000000ea01"
_ridy1 = "00000000-0000-4000-8000-00000000ea01"
bd._inflight[_toky1] = {"req": {"session_id": _ridy1, "request_id": _ridy1, "cwd": "/home/owner",
                                "argv": ["git", "push"]},
                        "chash": "x", "tier": B.HARD_DENY, "confined": True, "elevated": True,
                        "proc": None, "revoked": False, "started": bd.now()}
bd._run_exec(_toky1)
ck("Y1a: stored confined=True on a HARD_DENY slot -> minted ticket confined=True (read, not derived)",
   relay_calls and relay_calls[-1][1] is True)
ck("Y1a: result echoes the STORED confined=True (not tier-derived)",
   (result_of(_ridy1) or {}).get("confined") is True)
reset(); opensess()
_toky1b = "10000000-0000-4000-8000-00000000ea02"
_ridy1b = "00000000-0000-4000-8000-00000000ea02"
bd._inflight[_toky1b] = {"req": {"session_id": _ridy1b, "request_id": _ridy1b, "cwd": "/srv/projects",
                                 "argv": ["ls", "-la"]},
                         "chash": "x", "tier": B.FREE_ZONE, "confined": False, "elevated": True,
                         "proc": None, "revoked": False, "started": bd.now()}
bd._run_exec(_toky1b)
ck("Y1b: stored confined=False on a FREE_ZONE slot -> minted ticket confined=False (read, not derived)",
   relay_calls and relay_calls[-1][1] is False)
ck("Y1b: result echoes the STORED confined=False (not tier-derived)",
   (result_of(_ridy1b) or {}).get("confined") is False)

# Y2: dispatch() carries `confined` through to _run_exec unchanged for BOTH values, on the SAME argv/tier.
print("-- Y2: dispatch() carries the confined arg verbatim (same tier, both values) --")
reset(); opensess()
ry2t = req(["git", "push"], cwd="/home/owner")                 # HARD_DENY tier
bd.dispatch(ry2t, B.cmd_hash(ry2t), B.HARD_DENY, confined=True)   # unusual pairing, but the arg must win
ck("Y2: dispatch(confined=True) on HARD_DENY -> ticket confined=True (carried, not recomputed)",
   relay_calls and relay_calls[-1][1] is True)
reset(); opensess()
ry2f = req(["git", "push"], cwd="/home/owner")
bd.dispatch(ry2f, B.cmd_hash(ry2f), B.HARD_DENY, confined=False)
ck("Y2: dispatch(confined=False) on the SAME tier -> ticket confined=False (arg is authoritative)",
   relay_calls and relay_calls[-1][1] is False)

# Y3: dispatch() re-derives policy_tier() and refuses on TIER drift.
print("-- Y3: dispatch refuses on TIER drift (replaces the classify()-equality check) --")
reset(); opensess()
ry3 = req(["git", "push"], cwd="/home/owner")                  # actual tier = HARD_DENY
bd.dispatch(ry3, B.cmd_hash(ry3), B.FREE_ZONE, confined=True)    # approved tier lies (FREE_ZONE)
_ry3 = result_of(ry3["request_id"]) or {}
ck("Y3: tier drift -> refused, NOT executed", len(relay_calls) == 0 and _ry3.get("status") == "refused")
ck("Y3: refusal reason names TIER drift (not the retired 'decision drift')",
   "tier drift" in _ry3.get("reason", "") and "decision drift" not in _ry3.get("reason", ""))
_alog = open(B.AUDIT_LOG).read().splitlines()
_drift = [json.loads(l) for l in _alog if '"reason": "tier drift"' in l or '"reason":"tier drift"' in l]
ck("Y3: audit logged a 'tier drift' BINDING_MISMATCH naming the re-derived tier",
   any(d.get("redecided") == B.HARD_DENY and d.get("approved") == B.FREE_ZONE for d in _drift))

# Y4: the classify()-equality check is GONE.
print("-- Y4: no classify()-equality gate — dispatch keys on policy_tier() alone --")
reset(); opensess()
ry4a = req(["ls", "-la"])                                       # /srv/projects: classify IN_SCOPE, tier FREE_ZONE
ck("Y4a precondition: classify != tier for this argv",
   B.classify(ry4a)[0] == B.IN_SCOPE and B.policy_tier(ry4a) == B.FREE_ZONE)
bd.dispatch(ry4a, B.cmd_hash(ry4a), B.FREE_ZONE, confined=True)
ck("Y4a: FREE_ZONE (classify==IN_SCOPE) dispatched — no classify-equality refusal",
   len(relay_calls) == 1 and (result_of(ry4a["request_id"]) or {}).get("status") == "executed")
reset(); opensess()
ry4b = req(["mkdir", "newdir"])                                 # classify NEEDS_BUTTON, tier ALLOW
ck("Y4b precondition: classify != tier for this argv",
   B.classify(ry4b)[0] == B.NEEDS_BUTTON and B.policy_tier(ry4b) == B.ALLOW)
bd.dispatch(ry4b, B.cmd_hash(ry4b), B.ALLOW, confined=True)
ck("Y4b: ALLOW (classify==NEEDS_BUTTON) dispatched — no classify-equality refusal",
   len(relay_calls) == 1 and (result_of(ry4b["request_id"]) or {}).get("status") == "executed")

# Y5: the old `elevated+IN_SCOPE` guard is REMOVED.
print("-- Y5: elevated+IN_SCOPE guard removed (FREE_ZONE runs elevated on the ticket path) --")
reset(); opensess()
ry5 = req(["ls", "-la"])                                        # classify IN_SCOPE, tier FREE_ZONE
bd.dispatch(ry5, B.cmd_hash(ry5), B.FREE_ZONE, confined=True, elevated=True)
_ry5 = result_of(ry5["request_id"]) or {}
ck("Y5: FREE_ZONE + elevated dispatched (guard gone) — executed on the owner ticket path",
   len(relay_calls) == 1 and _ry5.get("status") == "executed" and _ry5.get("elevated") is True)
ck("Y5: never emits the retired 'elevation binding error' / 'elevated+IN_SCOPE' refusal",
   "elevation binding error" not in _ry5.get("reason", "") and "IN_SCOPE" not in _ry5.get("reason", ""))
last5 = cmds[-1] if cmds else []
ck("Y5: dispatched via sudo -n exec-argv-elevated run <ticket> (uniform owner)",
   "sudo" in last5 and any("exec-argv-elevated" in x for x in last5) and "run" in last5)

# Y6: a reviewer-ALLOW command dispatches on the owner ticket path with NO pending button, confined=True.
print("-- Y6: reviewer-ALLOW NEEDS_BUTTON-class command -> owner ticket path, no pending button --")
reset(); opensess(); review_verdict[0] = "ALLOW"
ry6 = req(["mkdir", "newdir"])                                  # classify NEEDS_BUTTON (formerly buttoned)
ck("Y6 precondition: this argv's classify() is NEEDS_BUTTON (the retired per-command button class)",
   B.classify(ry6)[0] == B.NEEDS_BUTTON)
submit(ry6)
ck("Y6: reviewer-ALLOW dispatched (ran), NO pending button", len(relay_calls) == 1 and len(bd._pending) == 0)
ck("Y6: dispatched confined=True (auto path)", relay_calls[-1][1] is True)
last6 = cmds[-1] if cmds else []
ck("Y6: ran on the sudo -n exec-argv-elevated run <ticket> path (uniform owner)",
   "sudo" in last6 and any("exec-argv-elevated" in x for x in last6) and "run" in last6)
ck("Y6: result carries elevated=True + confined=True + run_as owner",
   (result_of(ry6["request_id"]) or {}).get("elevated") is True
   and (result_of(ry6["request_id"]) or {}).get("confined") is True
   and (result_of(ry6["request_id"]) or {}).get("run_as") == bd.ELEV_RUNAS)

print("== Z: arithmetic exfil-cap (distinct auto cmd_hash / window) ==")
# A deterministic counter of DISTINCT auto-approved commands (by cmd_hash) per open window, checked in
# process() BEFORE dispatch, independent of and in addition to SESSION_CMD_BUDGET (both enforced). FREE_ZONE
# reads count too. Past HESTIA_EXFIL_CAP_N -> fall to HUMAN; N<=0 disables.

# Z1: the (N+1)th DISTINCT auto command in a window falls to the HUMAN button (not auto-run).
print("-- Z1: (N+1)th distinct auto cmd_hash -> HUMAN button --")
reset(); opensess()
_oc = bd.EXFIL_CAP_N; bd.EXFIL_CAP_N = 2
try:
    z1 = [req(["ls", "-la", "d%d" % i]) for i in range(3)]     # 3 DISTINCT free-zone reads (distinct cmd_hash)
    for r in z1[:2]: submit(r)
    ck("Z1: first N=2 distinct auto FREE_ZONE reads auto-ran", len(relay_calls) == 2 and len(bd._pending) == 0)
    submit(z1[2])                                              # the (N+1)th distinct auto command
    ck("Z1: (N+1)th distinct auto command did NOT auto-run", len(relay_calls) == 2)
    ck("Z1: (N+1)th distinct auto command fell to a HUMAN button", len(bd._pending) == 1
       and list(bd._pending.values())[0]["kind"] == "command")
    ck("Z1: capped command was NOT confined-dispatched (routed to unconfined human tap)",
       relay_calls[-1][1] is True)                             # last relay is still one of the first 2 (confined)
finally:
    bd.EXFIL_CAP_N = _oc

# Z2: a REPEAT of the SAME cmd_hash does NOT consume an extra cap slot (the cap is over DISTINCT hashes).
print("-- Z2: cap counts DISTINCT cmd_hash (a repeat of the same hash does not add) --")
reset(); opensess()
_oc = bd.EXFIL_CAP_N; bd.EXFIL_CAP_N = 2
try:
    zr = req(["ls", "-la", "same"])
    submit(zr); submit(zr); submit(zr)                        # SAME cmd_hash three times
    zd = req(["ls", "-la", "other"])                          # a 2nd DISTINCT hash
    submit(zd)
    ck("Z2: a 2nd distinct auto command still fits under N=2 despite 3 repeats of the 1st",
       len(bd._pending) == 0 and any(c[0] == ["ls", "-la", "other"] for c in relay_calls))
    ck("Z2: only 2 DISTINCT hashes recorded against the cap (a 3rd distinct would cap)",
       len(bd._exfil_hashes) == 2)
finally:
    bd.EXFIL_CAP_N = _oc

# Z3: N<=0 DISABLES the cap entirely (unbounded distinct auto commands).
print("-- Z3: HESTIA_EXFIL_CAP_N <= 0 disables the cap --")
reset(); opensess()
_oc = bd.EXFIL_CAP_N; bd.EXFIL_CAP_N = 0
try:
    z3 = [req(["ls", "-la", "z%d" % i]) for i in range(5)]     # well past any small cap
    for r in z3: submit(r)
    ck("Z3: N<=0 -> all distinct auto commands auto-ran (cap disabled)",
       len(relay_calls) == 5 and len(bd._pending) == 0)
finally:
    bd.EXFIL_CAP_N = _oc

# Z4: the exfil-cap is INDEPENDENT of SESSION_CMD_BUDGET — BOTH are enforced.
print("-- Z4: exfil-cap independent of SESSION_CMD_BUDGET (both enforced) --")
reset(); opensess()
_oc = bd.EXFIL_CAP_N; _ob = bd.SESSION_CMD_BUDGET
bd.EXFIL_CAP_N = 2; bd.SESSION_CMD_BUDGET = 40                 # budget >> cap: the CAP bites first
try:
    z4 = [req(["ls", "-la", "b%d" % i]) for i in range(3)]
    for r in z4: submit(r)
    _z4res = result_of(z4[2]["request_id"]) or {}
    ck("Z4a: budget>>cap -> the CAP bites (3rd -> HUMAN button, NOT a budget refuse)",
       len(bd._pending) == 1 and _z4res.get("status") != "refused")
finally:
    bd.EXFIL_CAP_N = _oc; bd.SESSION_CMD_BUDGET = _ob
reset(); opensess()
_oc = bd.EXFIL_CAP_N; _ob = bd.SESSION_CMD_BUDGET
bd.EXFIL_CAP_N = 40; bd.SESSION_CMD_BUDGET = 2                 # cap >> budget: the BUDGET bites first
try:
    z4b = [req(["ls", "-la", "c%d" % i]) for i in range(3)]
    for r in z4b: submit(r)
    ck("Z4b: cap>>budget -> the BUDGET bites (3rd -> refused, over budget)",
       (result_of(z4b[2]["request_id"]) or {}).get("reason", "").startswith("session command budget"))
finally:
    bd.EXFIL_CAP_N = _oc; bd.SESSION_CMD_BUDGET = _ob

# Z5: the cap resets on a fresh open window (the distinct-hash set is window-scoped).
print("-- Z5: exfil-cap distinct-hash set is per-window (resets on session open) --")
reset()
_oc = bd.EXFIL_CAP_N; bd.EXFIL_CAP_N = 2
try:
    open_via_approve("window one"); bd.EXFIL_CAP_N = 2
    for r in [req(["ls", "-la", "w1_%d" % i]) for i in range(2)]: submit(r)
    ck("Z5: window one filled the cap (2 distinct auto)", len(relay_calls) == 2)
    open_via_approve("window two"); bd.EXFIL_CAP_N = 2         # a NEW window (on_approve resets)
    ck("Z5: fresh window cleared the distinct-hash set", len(bd._exfil_hashes) == 0)
    for r in [req(["ls", "-la", "w2_%d" % i]) for i in range(2)]: submit(r)
    ck("Z5: window two runs 2 more distinct auto commands (cap reset)",
       len(relay_calls) == 2 and len(bd._pending) == 0)
finally:
    bd.EXFIL_CAP_N = _oc

# Z6: reviewer-ALLOW auto commands ALSO count against the cap (not just FREE_ZONE).
print("-- Z6: reviewer-ALLOW auto commands count against the cap too --")
reset(); opensess(); review_verdict[0] = "ALLOW"
_oc = bd.EXFIL_CAP_N; bd.EXFIL_CAP_N = 2
try:
    z6 = [req(["mkdir", "nd%d" % i]) for i in range(3)]        # 3 distinct reviewer-middle ALLOW commands
    for r in z6[:2]: submit(r)
    ck("Z6: first 2 reviewer-ALLOW auto commands ran", len(relay_calls) == 2)
    submit(z6[2])
    ck("Z6: (N+1)th reviewer-ALLOW distinct auto command did NOT auto-run", len(relay_calls) == 2)
    ck("Z6: (N+1)th reviewer-ALLOW distinct auto command fell to a HUMAN button", len(bd._pending) == 1)
finally:
    bd.EXFIL_CAP_N = _oc; review_verdict[0] = "HUMAN"

# Z7: the exfil-cap is ON BY DEFAULT. The DEFAULT EXFIL_CAP_N (no env set) must be a safe NON-ZERO value
#     <= SESSION_CMD_BUDGET, so the arithmetic backstop is armed out of the box.
print("-- Z7: EXFIL_CAP_N default is non-zero, <= SESSION_CMD_BUDGET, and enforces with no env set --")
assert not any(k.startswith("HESTIA_EXFIL_CAP_N") or k == "HESTIA_SESSION_CMD_BUDGET" for k in os.environ)
_z7cap, _z7budget = bd.EXFIL_CAP_N, bd.SESSION_CMD_BUDGET
ck("Z7: default EXFIL_CAP_N is NON-ZERO (backstop ON by default, no env)", _z7cap > 0)
ck("Z7: default EXFIL_CAP_N <= SESSION_CMD_BUDGET (cap never looser than the budget)", _z7cap <= _z7budget)
reset()
_z7_ob = bd.SESSION_CMD_BUDGET
bd.SESSION_CMD_BUDGET = bd.EXFIL_CAP_N + 5                     # budget > default cap -> the cap bites first
opensess()                                                    # live module still runs at the DEFAULT exfil cap
try:
    _dflt = bd.EXFIL_CAP_N                                     # NOT overridden — the compiled default
    ck("Z7: live module runs at the non-zero default cap", isinstance(_dflt, int) and _dflt > 0)
    z7 = [req(["ls", "-la", "z7_%d" % i]) for i in range(_dflt + 1)]  # default+1 DISTINCT free-zone reads
    for r in z7[:_dflt]: submit(r)
    ck("Z7: first `default` distinct auto reads auto-ran (cap not yet hit)",
       len(relay_calls) == _dflt and len(bd._pending) == 0)
    submit(z7[_dflt])                                         # the (default+1)th distinct auto command
    ck("Z7: (default+1)th distinct auto command did NOT auto-run (default cap enforces)",
       len(relay_calls) == _dflt)
    ck("Z7: (default+1)th distinct auto command fell to a HUMAN button (backstop armed by default)",
       len(bd._pending) == 1 and list(bd._pending.values())[0]["kind"] == "command")
finally:
    bd.SESSION_CMD_BUDGET = _z7_ob

print("== AA: transparency surfacing in session_log ==")
# reviewer ALLOW -> 🟢 auto·reviewed (auto bucket); reviewer BLOCK / HARD_DENY -> 🔵/🔴 awaiting your tap;
# REFUSE -> 🚫 refused (unapprovable) with NO approve button.

# AA1: reviewer-ALLOW surfaces 🟢 auto·reviewed in the session log (auto bucket).
print("-- AA1: reviewer-ALLOW -> 🟢 auto·reviewed --")
reset(); open_via_approve("aa1"); review_verdict[0] = "ALLOW"
_aa1_seen = []
_saved_slog = bd.session_log
def _cap_slog(request_id, icon, argv, status, kind="command"):
    _aa1_seen.append((icon, status)); return _saved_slog(request_id, icon, argv, status, kind=kind)
bd.session_log = _cap_slog
try:
    raa1 = req(["mkdir", "newdir"]); submit(raa1)
finally:
    bd.session_log = _saved_slog
ck("AA1: reviewer-ALLOW surfaced the exact '🟢 auto·reviewed' marker (auto·reviewed bucket)",
   any(ic == "🟢" and "auto·reviewed" in st for ic, st in _aa1_seen))
_aa1 = bd._session_log.get(raa1["request_id"]) or {}
ck("AA1: final row kind is the single canonical 'auto' bucket", _aa1.get("kind") == "auto")
ck("AA1: reviewer-ALLOW counted in the single canonical auto bucket", bd._session_counts["auto"] == 1)

# AA2: a human-tapped command (HARD_DENY OR reviewer-BLOCK) surfaces awaiting-your-tap BEFORE the tap.
print("-- AA2: HARD_DENY / reviewer-BLOCK -> awaiting your tap --")
reset(); open_via_approve("aa2")
raa2 = req(["git", "push"]); submit(raa2)                     # HARD_DENY -> human button
_aa2 = bd._session_log.get(raa2["request_id"]) or {}
ck("AA2: HARD_DENY surfaced 🔴 awaiting your tap (row glyph matches the 🔴 button)", _aa2.get("icon") == "🔴"
   and "awaiting" in _aa2.get("status", ""))
ck("AA2: 🔴 awaiting bumps NO count yet (has not run)", bd._session_counts["approved"] == 0)
reset(); open_via_approve("aa2b"); review_verdict[0] = "HUMAN"
raa2b = req(["mkdir", "newdir"]); submit(raa2b)              # reviewer-BLOCK -> human button
_aa2b = bd._session_log.get(raa2b["request_id"]) or {}
ck("AA2: reviewer-BLOCK surfaced 🔵 awaiting your tap", _aa2b.get("icon") == "🔵"
   and "awaiting" in _aa2b.get("status", ""))

# AA3: REFUSE surfaces 🚫 refused (unapprovable) with NO approve button (unapprovable by ANY tap).
print("-- AA3: REFUSE -> 🚫 refused (unapprovable), NO approve button --")
reset(); open_via_approve("aa3")
raa3 = req(["rm", "-rf", "/"]); submit(raa3)                  # REFUSE tier (hardline)
_aa3 = bd._session_log.get(raa3["request_id"]) or {}
ck("AA3: REFUSE surfaced the 🚫 icon", _aa3.get("icon") == "🚫")
ck("AA3: REFUSE status marks it unapprovable", "unapprovable" in _aa3.get("status", ""))
ck("AA3: REFUSE produced NO approve button (nothing to tap)", len(bd._pending) == 0)
ck("AA3: REFUSE nothing ran", len(relay_calls) == 0)

print("== BB: AUTO-path preconditions (reviewer enabled+keyed, elevation, userns probe) ==")
# FAIL-CLOSED TO THE HUMAN BUTTON (never a silent refuse, never an unconfined/unconfinable auto-run):
# the AUTO path may auto-execute ONLY when ALL preconditions hold — (1) reviewer ENABLED and KEYED,
# (2) elevation_enabled() true, (3) the bwrap userns probe SUCCEEDS.
_KF_BAD = os.path.join(TD, "does-not-exist.key")             # missing elevation key -> elevation_enabled() False

def _assert_falls_to_human(label, mkreq, elev_present=True):
    """A FREE_ZONE and a reviewer-ALLOW command each leave the AUTO path via the human-fallback gate:
    nothing is auto-dispatched (relay_calls empty), and it is NEVER a silent exec-time refuse. When
    elevation is present, the fallback creates exactly one pending 'command' approval. When elevation is
    ABSENT, no ticket path can execute even a human-approved command, so the _ask_human elevation guard
    turns it into an EXPLICIT gate-level refuse."""
    def _check(tier_label, mkr, is_free_zone):
        reset(); opensess()
        if not is_free_zone: review_verdict[0] = "ALLOW"
        mkreq()                                              # (re-)apply the precondition-off state after reset()
        r0 = mkr()
        submit(r0)
        ck(f"BB[{label}]: {tier_label} did NOT auto-dispatch", len(relay_calls) == 0)
        res = (result_of(r0["request_id"]) or {})
        if elev_present:
            ck(f"BB[{label}]: {tier_label} fell to a HUMAN button (pending command)",
               len(bd._pending) == 1 and list(bd._pending.values())[0]["kind"] == "command")
            ck(f"BB[{label}]: {tier_label} was NOT silently refused", res.get("status") != "refused")
        else:
            ck(f"BB[{label}]: {tier_label} produced the GATE-level 'elevation not configured' refuse (not the worker 'no key' path)",
               res.get("status") == "refused" and res.get("reason") == "elevation not configured")
    _check("FREE_ZONE",      lambda: req(["ls", "-la"]),   True)
    _check("reviewer-ALLOW", lambda: req(["mkdir", "newdir"]), False)

# BB0: SANITY — with ALL preconditions met, the auto path auto-DISPATCHES.
reset(); opensess()
rfz0 = req(["ls", "-la"]); submit(rfz0)
ck("BB0: all preconditions met -> FREE_ZONE auto-dispatches CONFINED",
   len(relay_calls) == 1 and relay_calls[0][1] is True and len(bd._pending) == 0)
reset(); opensess(); review_verdict[0] = "ALLOW"
ra0 = req(["mkdir", "newdir"]); submit(ra0)
ck("BB0: all preconditions met -> reviewer-ALLOW auto-dispatches CONFINED",
   len(relay_calls) == 1 and relay_calls[0][1] is True and len(bd._pending) == 0)

# BB1: reviewer DISABLED -> auto path falls to human.
_assert_falls_to_human("reviewer-disabled", lambda: setattr(bd, "REVIEWER_ENABLED", False))
# BB2: reviewer enabled but KEYLESS -> auto path falls to human.
_assert_falls_to_human("reviewer-keyless", lambda: setattr(bd, "REVIEWER_KEY", ""))
# BB3: elevation.key ABSENT (elevation_enabled() False) -> explicit gate-level refuse.
_assert_falls_to_human("elevation-absent", lambda: setattr(bd, "ELEV_KEY_FILE", _KF_BAD), elev_present=False)
# BB4: userns/bwrap probe FAILS -> confinement cannot be enforced -> auto path falls to human.
_assert_falls_to_human("userns-probe-fail", lambda: setattr(bd, "_userns_ok", lambda: False))

# BB5: the userns probe itself runs `bwrap --unshare-net --bind / / -- true` and is fail-closed.
reset()
_saved_run = bd.subprocess.run
try:
    _probe_seen = []
    def _fake_run(cmd, *a, **k):
        _probe_seen.append(list(cmd))
        class _R:  returncode = 0
        return _R()
    bd.subprocess.run = _fake_run
    ok_probe = bd._userns_probe()
    ck("BB5: real _userns_probe() returns True on a zero-exit probe", ok_probe is True)
    ck("BB5: probe invoked `bwrap --unshare-net --bind / / -- true`",
       any(c[:6] == ["bwrap", "--unshare-net", "--bind", "/", "/", "--"] and c[-1] == "true" for c in _probe_seen))
    class _RNZ:  returncode = 1
    bd.subprocess.run = lambda cmd, *a, **k: _RNZ()
    ck("BB5: probe fails CLOSED on a NON-zero exit (-> False)", bd._userns_probe() is False)
    def _raise_run(cmd, *a, **k): raise FileNotFoundError("bwrap")
    bd.subprocess.run = _raise_run
    ck("BB5: probe fails CLOSED when bwrap is absent/raises (-> False)", bd._userns_probe() is False)
    bd._userns_probe_cache = None                            # bust the cache
    bd.subprocess.run = _fake_run
    ck("BB5: _userns_ok() caches the probe result (True)", bd._userns_ok() is True)
finally:
    bd.subprocess.run = _saved_run
    bd._userns_ok = lambda: True; bd._userns_probe_cache = True

print("== CC: circuit-breaker WIRED + concurrency cap on _reviews ==")
# reviewer.py defines a complete Breaker (OPEN/HALF_OPEN/recovery) tested in isolation, but brokerd MUST
# actually consult it: in _spawn_review, UNDER _lock, before spawning a worker check
#   len(_reviews) < HESTIA_MAX_REVIEWS  AND  _breaker.allow()
# — if EITHER fails, route to the HUMAN button (_ask_human), do NOT spawn a worker. In the worker,
# _breaker.record(ok) distinctly: a clean HTTP verdict (incl BLOCK/HUMAN) = success; a timeout/HTTP-error
# = failure. After N consecutive failures the breaker OPENS; after cooldown+success it RECOVERS.

# CC0: the module wires a real reviewer.Breaker + the three env-configurable constants exist.
print("-- CC0: module wires a reviewer.Breaker + config constants --")
ck("CC0: bd._breaker is a reviewer.Breaker", isinstance(bd._breaker, bd.reviewer.Breaker))
ck("CC0: HESTIA_MAX_REVIEWS is a positive int", isinstance(bd.HESTIA_MAX_REVIEWS, int) and bd.HESTIA_MAX_REVIEWS >= 1)
ck("CC0: HESTIA_REVIEWER_BREAKER_N is a positive int", isinstance(bd.HESTIA_REVIEWER_BREAKER_N, int) and bd.HESTIA_REVIEWER_BREAKER_N >= 1)
ck("CC0: HESTIA_REVIEWER_BREAKER_COOLDOWN is a number", isinstance(bd.HESTIA_REVIEWER_BREAKER_COOLDOWN, (int, float)))

_fail_review = lambda req, tier: (review_calls.append((req.get("argv"), tier)) or ("HUMAN", False))
_clean_human = lambda req, tier: (review_calls.append((req.get("argv"), tier)) or ("HUMAN", True))
_clean_allow = lambda req, tier: (review_calls.append((req.get("argv"), tier)) or ("ALLOW", True))

# CC1: a clean HTTP verdict (BLOCK/HUMAN) records a breaker SUCCESS — the breaker never trips on clean
#      BLOCK verdicts, only on transport failures.
print("-- CC1: clean verdict (incl BLOCK/HUMAN) = breaker success (does NOT trip) --")
reset()
_saved_review = bd._review; bd._review = _clean_human
try:
    for i in range(bd.HESTIA_REVIEWER_BREAKER_N + 2):
        opensess()
        submit(req(["rm", "cleanfoo%d" % i]))                  # SOFT_DENY -> reviewer middle -> clean HUMAN verdict
    ck("CC1: breaker still CLOSED after many CLEAN BLOCK/HUMAN verdicts (allow())", bd._breaker.allow() is True)
finally:
    bd._review = _saved_review

# CC2: the breaker TRIPS after N CONSECUTIVE reviewer FAILURES (timeout/HTTP-error).
print("-- CC2: breaker TRIPS after N consecutive failures -> middle commands go straight to HUMAN, no worker --")
reset()
N = bd.HESTIA_REVIEWER_BREAKER_N
_saved_review = bd._review; bd._review = _fail_review
try:
    for i in range(N):
        opensess()
        rF = req(["rm", "failfoo%d" % i]); submit(rF)
        ck("CC2: failing review #%d spawned a worker + fell to HUMAN" % i,
           any(c[0] == ["rm", "failfoo%d" % i] for c in review_calls) and len(bd._pending) == 1)
        bd._pending.clear()
    ck("CC2: after N consecutive failures the breaker is OPEN (allow() False)", bd._breaker.allow() is False)
    review_calls.clear(); bd._reviews.clear()
    opensess()
    rOpen = req(["rm", "afteropen"]); submit(rOpen)
    ck("CC2: breaker OPEN -> middle command did NOT consult the reviewer (no worker spawned)",
       len(review_calls) == 0)
    ck("CC2: breaker OPEN -> middle command went straight to a HUMAN button", len(bd._pending) == 1
       and list(bd._pending.values())[0]["kind"] == "command")
    ck("CC2: breaker OPEN -> nothing auto-ran", len(relay_calls) == 0)
    ck("CC2: breaker OPEN -> no review left registered (never spawned)", len(bd._reviews) == 0)
finally:
    bd._review = _saved_review

# CC3: the breaker RECOVERS after cooldown + a trial SUCCESS.
print("-- CC3: breaker RECOVERS after cooldown + trial success (self-heals) --")
reset()
_clk = {"t": 1000.0}
bd._breaker = bd.reviewer.Breaker(n=bd.HESTIA_REVIEWER_BREAKER_N, cooldown=30.0, clock=lambda: _clk["t"])
N = bd.HESTIA_REVIEWER_BREAKER_N
_saved_review = bd._review; bd._review = _fail_review
try:
    for i in range(N):
        opensess()
        submit(req(["rm", "rfoo%d" % i])); bd._pending.clear()
    ck("CC3: breaker OPEN after N failures", bd._breaker.allow() is False)
    review_calls.clear(); bd._reviews.clear(); bd._pending.clear()
    opensess(); submit(req(["rm", "beforecooldown"]))
    ck("CC3: before cooldown the breaker is still OPEN (no worker, HUMAN button)",
       len(review_calls) == 0 and len(bd._pending) == 1)
    _clk["t"] = 1000.0 + 31.0
    bd._review = _clean_human                                  # the trial gets a CLEAN verdict -> success -> CLOSE
    review_calls.clear(); bd._reviews.clear(); bd._pending.clear()
    opensess(); submit(req(["rm", "trialcmd"]))
    ck("CC3: after cooldown a trial review WAS allowed through (worker consulted the reviewer)",
       len(review_calls) == 1)
    ck("CC3: trial success CLOSED the breaker (recovered)", bd._breaker.allow() is True)
    review_calls.clear(); bd._reviews.clear(); bd._pending.clear()
    opensess(); submit(req(["rm", "aftercooldown"]))
    ck("CC3: post-recovery middle command is reviewed again (worker spawned)", len(review_calls) == 1)
finally:
    bd._review = _saved_review
    bd._breaker = bd.reviewer.Breaker(bd.HESTIA_REVIEWER_BREAKER_N, bd.HESTIA_REVIEWER_BREAKER_COOLDOWN)

# CC4: CONCURRENCY CAP — at most HESTIA_MAX_REVIEWS concurrent in-flight reviews.
print("-- CC4: concurrency cap on _reviews (excess -> HUMAN, no worker) --")
reset()
_omr = bd.HESTIA_MAX_REVIEWS
bd.HESTIA_MAX_REVIEWS = 2
bd.threading.Thread = RealThread
_review_gate.clear(); _review_entered.clear(); _blocking_verdict[0] = "ALLOW"
_saved_review = bd._review
def _blocking_review_ok(req, tier):
    review_calls.append((req.get("argv"), tier)); _review_entered.set(); _review_gate.wait(5)
    return ("ALLOW", True)
bd._review = _blocking_review_ok
try:
    open_via_approve("cc4-intent")
    bd.HESTIA_MAX_REVIEWS = 2
    submit(req(["rm", "inflight1"]))
    submit(req(["rm", "inflight2"]))
    for _ in range(60):
        if len(bd._reviews) == 2: break
        time.sleep(0.02)
    ck("CC4: cap filled — 2 concurrent reviews in-flight", len(bd._reviews) == 2)
    _calls_at_cap = len(review_calls)
    submit(req(["rm", "overcap"]))
    ck("CC4: over-cap middle command spawned NO new worker (reviewer not consulted)",
       len(review_calls) == _calls_at_cap)
    ck("CC4: over-cap middle command went straight to a HUMAN button", len(bd._pending) == 1
       and list(bd._pending.values())[0]["kind"] == "command")
    ck("CC4: over-cap did NOT register a 3rd review (still at cap)", len(bd._reviews) == 2)
    _review_gate.set()
    for _ in range(60):
        if len(bd._reviews) == 0: break
        time.sleep(0.02)
finally:
    bd._review = _saved_review; bd.threading.Thread = InlineThread; _review_gate.set()
    bd.HESTIA_MAX_REVIEWS = _omr

# CC5: a legacy bare-STRING _review return is treated as a CLEAN success and never trips the breaker.
print("-- CC5: legacy bare-string _review return = clean success (backward-compatible) --")
reset()
_saved_review = bd._review
bd._review = lambda req, tier: (review_calls.append((req.get("argv"), tier)) or "HUMAN")   # bare string
try:
    for i in range(bd.HESTIA_REVIEWER_BREAKER_N + 1):
        opensess(); submit(req(["rm", "legacy%d" % i])); bd._pending.clear()
    ck("CC5: bare-string returns never trip the breaker (still CLOSED)", bd._breaker.allow() is True)
finally:
    bd._review = _saved_review

print("== DD: session-state writes under _lock (lock-discipline) ==")
# _session_phase / _session_intent are written under _lock discipline; the reentrant
# _flush_session_msg/session_log/write_result/_teardown_reviews calls stay OUTSIDE the hold to avoid a
# non-reentrant-_lock deadlock. We assert behavioural equivalence is preserved AND that no path deadlocks.

# DD1: on_approve(session_open) still opens the window correctly.
print("-- DD1: on_approve(session_open) opens the window (no deadlock, state correct) --")
reset()
p_open = {"kind": "session_open", "req": req_open("dd1-intent", 600), "intent": "dd1-intent", "secs": 600,
          "chat_id": bd.OWNER_ID, "msg_id": 7001, "deadline": bd.now() + bd.SESSION_ASK_SECS}
bd.on_approve(p_open)
ck("DD1: session is OPEN after on_approve", bd.session_open() and bd._session_phase == "open")
ck("DD1: intent anchor set to the approved canonical intent", bd._session_intent == "dd1-intent")
ck("DD1: session_open produced a session_opened result", (result_of(p_open["req"]["request_id"]) or {}).get("status") == "session_opened")

# DD2: _end_session sets phase='ended' and clears the anchor (no deadlock).
print("-- DD2: _end_session flips phase='ended' + clears intent (no deadlock) --")
reset(); open_via_approve("dd2-intent")
ck("DD2: precondition — window open", bd._session_phase == "open" and bd._session_intent == "dd2-intent")
bd._end_session("agent")
ck("DD2: phase flipped to 'ended'", bd._session_phase == "ended")
ck("DD2: session no longer open", not bd.session_open())
ck("DD2: intent anchor cleared", bd._session_intent == "")

# DD3: _teardown_reviews + phase flip happen without a worker slipping a dispatch into the closing window.
print("-- DD3: teardown+phase flip happen without a worker slipping a dispatch into the closing window --")
reset(); open_via_approve("dd3-intent")
bd.threading.Thread = RealThread
_review_gate.clear(); _review_entered.clear()
_saved_review = bd._review
def _blocking_review_dd3(req, tier):
    review_calls.append((req.get("argv"), tier)); _review_entered.set(); _review_gate.wait(5)
    return ("ALLOW", True)
bd._review = _blocking_review_dd3
try:
    rdd3 = req(["rm", "dd3foo"]); submit(rdd3)
    ck("DD3: review in-flight before close", _review_entered.wait(2) and len(bd._reviews) == 1)
    bd._end_session("agent")                                   # teardown flips phase='ended' under lock + refuses review
    ck("DD3: phase ended after close", bd._session_phase == "ended")
    _review_gate.set()
    for _ in range(60):
        if len(bd._reviews) == 0: break
        time.sleep(0.02)
    ck("DD3: torn-down review did NOT dispatch into the closing window", len(relay_calls) == 0)
    ck("DD3: torn-down review got a refused result (no dangling request)",
       (result_of(rdd3["request_id"]) or {}).get("status") == "refused")
finally:
    bd._review = _saved_review; bd.threading.Thread = InlineThread; _review_gate.set()

# DD4: full revoke_all path still works end-to-end (no deadlock, window closed, ⚪ rendered).
print("-- DD4: revoke_all closes the window cleanly (no deadlock from the lock rewrite) --")
reset(); open_via_approve("dd4-intent")
bd.revoke_all("dd4-revoke")
ck("DD4: revoke_all closed the session", not bd.session_open() and bd._session_phase == "ended")
ck("DD4: revoke_all cleared the intent anchor", bd._session_intent == "")

print("== UX: _shell shell-like rendering (display-only, injection-safe) ==")
ck("plain argv joined", bd._shell(["ls", "-la", "/home/owner"]) == "ls -la /home/owner")
ck("metachar token single-quoted", bd._shell(["python3", "-c", "print(6*7)"]) == "python3 -c 'print(6*7)'")
ck("shell-injection token rendered as ONE quoted arg", bd._shell(["echo", "; rm -rf ~"]) == "echo '; rm -rf ~'")
ck("embedded single-quote escaped", bd._shell(["echo", "a'b"]) == "echo 'a'\\''b'")
ck("control char never rendered raw", "\n" not in bd._shell(["cat", "x\ny"]))
ck("non-list argv falls back to a string", isinstance(bd._shell("weird"), str))

print("== UX: _fmt distinct 🔴 floor / 🔵 reviewer + reason; security facts preserved ==")
_uq = {"cwd": "/home/owner", "argv": ["curl", "-sS", "https://x"], "request_id": "x"}
_red = bd._fmt(_uq, "a" * 64, B.HARD_DENY, "EGRESS — sends bytes off-box")
ck("🔴 headline + Floor reason", "🔴" in _red and "Floor: EGRESS" in _red)
ck("🔴 keeps UNCONFINED + run-as identity + hash", "UNCONFINED" in _red and bd.ELEV_RUNAS in _red and "hash aaaa" in _red)
ck("🔴 command shell-rendered, not JSON argv", "curl -sS https://x" in _red and "['curl'" not in _red)
_blu = bd._fmt(_uq, "b" * 64, B.SOFT_DENY, "[Scope] reading /etc exceeds intent")
ck("🔵 headline + reviewer Reason surfaced", "🔵" in _blu and "Reason: [Scope] reading /etc exceeds intent" in _blu)
ck("🔵 generic fallback when no reason", "reviewer escalated" in bd._fmt(_uq, "c" * 64, B.SOFT_DENY, ""))
ck("🔴 label sourced from broker.hard_deny_reason", "EGRESS" in B.hard_deny_reason({"argv": ["curl", "x"], "cwd": "/h"})
   and "SECRETS" in B.hard_deny_reason({"argv": ["cat", "/home/owner/.ssh/id_x"], "cwd": "/h"})
   and "SUDO/ROOT" in B.hard_deny_reason({"argv": ["sudo", "id"], "cwd": "/h"})
   and B.hard_deny_reason({"argv": ["ls"], "cwd": "/h"}) == "")

print("== UX: N-running counter in the open session header ==")
reset(); bd._session_phase = "open"; bd._session_intent = "x"; bd._session_until_wall = time.time() + 600
bd._inflight["tok-ux"] = {"req": req(["ls"])}
ck("header shows the running counter when in-flight > 0", "· 1 running" in bd._render_session())
bd._inflight.clear()
ck("header hides the counter when nothing is in flight", "running" not in bd._render_session().split("enforcing")[0])

print("== UX: reviewer-BLOCK reason reaches the 🔵 button (e2e, inline worker) ==")
reset(); opensess()
_sr = bd._review
bd._review = lambda rq, tier: ("HUMAN", True, "[Off-Intent] not part of your stated session")
_before = len(sent)
submit(req(["mkdir", "newdir"]))                              # ALLOW-tier -> reviewer -> BLOCK+reason -> 🔵
bd._review = _sr
_texts = [s.get("text", "") for s in sent[_before:] if isinstance(s.get("text"), str)]
ck("e2e: the 🔵 button carries the reviewer's reason",
   any("🔵" in t and "[Off-Intent] not part of your stated session" in t for t in _texts))

print("== #2 startup preflight: probe + one audit record + alert ONLY on degradation ==")
# _preflight(): probe userns / reviewer-auth / elevation, write ONE BROKER_PREFLIGHT audit record, and DM
# the owner ONE warning ONLY on real degradation (all-green is SILENT). Stubs reviewer.review_outcome +
# reviewer.warm_up (no network) and captures broker.audit.
_audit_cap = []
_real_audit, _real_ro, _real_wu = bd.broker.audit, bd.reviewer.review_outcome, bd.reviewer.warm_up
bd.broker.audit = lambda rec: _audit_cap.append(rec)
_wu_calls = [0]
bd.reviewer.warm_up = lambda cfg: (_wu_calls.__setitem__(0, _wu_calls[0] + 1) or True)
def _set_reviewer(ok):
    bd.reviewer.review_outcome = lambda intent, argv, cwd, tier, cfg: (("ALLOW" if ok else "HUMAN"), ok, "")
def _last_pf():
    return next((r for r in reversed(_audit_cap) if r.get("decision") == "BROKER_PREFLIGHT"), None)

# all green -> reviewer 'ok', NO alert, one BROKER_PREFLIGHT, warm_up primed once
reset(); _audit_cap.clear(); _wu_calls[0] = 0
bd._userns_ok = lambda: True; bd.ELEV_KEY_FILE = _KF
bd.REVIEWER_ENABLED = True; bd.REVIEWER_KEY = "k"; bd.REVIEWER_BASE_URL = "https://r/v1/chat/completions"
_set_reviewer(True)
res = bd._preflight()
ck("all-green: reviewer 'ok' + userns + elevation", res["reviewer"] == "ok" and res["userns"] and res["elevation"])
ck("all-green: no down items", res["down"] == [])
ck("all-green: NO Telegram alert (silent healthy restart)", len(sent) == 0)
ck("all-green: one BROKER_PREFLIGHT audit record", _last_pf() and _last_pf()["userns"] is True and _last_pf()["reviewer"] == "ok")
ck("all-green: warm_up primed the TLS session once", _wu_calls[0] == 1)

# userns down -> exactly one alert naming confinement + degraded
reset(); _audit_cap.clear(); _set_reviewer(True); bd._userns_ok = lambda: False
bd._preflight()
ck("userns down: exactly one alert", len(sent) == 1)
ck("userns down: alert names userns/confinement", "userns" in sent[-1]["text"].lower() or "confinement" in sent[-1]["text"].lower())
ck("userns down: alert says degraded", "degraded" in sent[-1]["text"].lower())

# reviewer auth_failed (a real probe call that FAILS: ok=False) -> alert; catches the 403 class
reset(); _audit_cap.clear(); bd._userns_ok = lambda: True; _set_reviewer(False)
bd._preflight()
ck("auth_failed: state 'auth_failed'", _last_pf()["reviewer"] == "auth_failed")
ck("auth_failed: one alert naming reviewer", len(sent) == 1 and "reviewer" in sent[-1]["text"].lower())

# reviewer misconfigured (enabled but no base_url) -> alert, and NO probe token is spent
reset(); _audit_cap.clear(); bd._userns_ok = lambda: True
_ro_calls = [0]
bd.reviewer.review_outcome = lambda *a, **k: (_ro_calls.__setitem__(0, _ro_calls[0] + 1) or ("ALLOW", True, ""))
bd.REVIEWER_BASE_URL = ""
bd._preflight()
ck("misconfigured: state 'misconfigured'", _last_pf()["reviewer"] == "misconfigured")
ck("misconfigured: alert sent", len(sent) == 1)
ck("misconfigured: NO probe token spent (returned before the call)", _ro_calls[0] == 0)
bd.REVIEWER_BASE_URL = "https://r/v1/chat/completions"; _set_reviewer(True)

# reviewer intentionally disabled -> state 'disabled', NOT an alert
reset(); _audit_cap.clear(); bd._userns_ok = lambda: True; bd.REVIEWER_ENABLED = False
bd._preflight()
ck("disabled: state 'disabled'", _last_pf()["reviewer"] == "disabled")
ck("disabled: NO alert (deliberate config, not a degradation)", len(sent) == 0)
bd.REVIEWER_ENABLED = True

# elevation down -> alert names elevation
reset(); _audit_cap.clear(); bd._userns_ok = lambda: True; _set_reviewer(True)
bd.ELEV_KEY_FILE = "/nonexistent/elev.key"
bd._preflight()
ck("elevation down: alert names elevation", len(sent) == 1 and "elevation" in sent[-1]["text"].lower())
bd.ELEV_KEY_FILE = _KF

# ALL three down -> exactly ONE combined alert listing all three (never spam one-per-fault)
reset(); _audit_cap.clear(); bd._userns_ok = lambda: False; _set_reviewer(False)
bd.ELEV_KEY_FILE = "/nonexistent/elev.key"
bd._preflight()
ck("multi-down: exactly ONE alert (not one per fault)", len(sent) == 1)
ck("multi-down: alert lists all three", all(w in sent[-1]["text"].lower() for w in ("userns", "elevation", "reviewer")))
bd.ELEV_KEY_FILE = _KF

# _alert_owner NEVER raises, even if tg throws (startup must not die on a Telegram hiccup)
reset(); _realtg = bd.tg
bd.tg = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("telegram down"))
ck("_alert_owner swallows a tg failure (False, no raise)", bd._alert_owner("x") is False)
bd.tg = _realtg

# _preflight NEVER raises even if a probe throws -> PREFLIGHT_ERROR, startup continues
reset(); _audit_cap.clear()
bd._userns_ok = lambda: (_ for _ in ()).throw(RuntimeError("probe boom"))
_r = bd._preflight()
ck("_preflight contains a probe exception (no raise)", _r["reviewer"] == "error")
ck("_preflight audits PREFLIGHT_ERROR", any(r.get("decision") == "PREFLIGHT_ERROR" for r in _audit_cap))

# secret hygiene: neither the alert text nor ANY audit record may carry the reviewer key / base_url.
reset(); _audit_cap.clear()
bd.REVIEWER_KEY = "KEYSENTINEL_zzz"; bd.REVIEWER_BASE_URL = "https://URLSENTINEL.invalid/hidden"
bd._userns_ok = lambda: False; _set_reviewer(True)          # userns-down -> an alert fires
bd._preflight()
_blob = (sent[-1]["text"] if sent else "") + json.dumps(_audit_cap)
ck("secret hygiene: no reviewer key/base_url in the alert or audit records",
   "KEYSENTINEL_zzz" not in _blob and "URLSENTINEL" not in _blob)
bd.REVIEWER_KEY = "k"; bd.REVIEWER_BASE_URL = "https://r/v1/chat/completions"

# secret hygiene: a tg failure whose exception text embeds the bot-token URL must NOT be logged.
reset(); _audit_cap.clear(); _realtg2 = bd.tg
bd.tg = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("POST https://api.telegram.org/botBOTTOKEN_zzz/sendMessage failed"))
bd._alert_owner("x")
ck("secret hygiene: ALERT_FAILED logs the exception type, not the token-bearing URL",
   all("BOTTOKEN_zzz" not in json.dumps(r) for r in _audit_cap))
bd.tg = _realtg2

# restore everything the (now-finished) harness touched
bd.broker.audit, bd.reviewer.review_outcome, bd.reviewer.warm_up = _real_audit, _real_ro, _real_wu
bd._userns_ok = lambda: True; bd.ELEV_KEY_FILE = _KF

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
