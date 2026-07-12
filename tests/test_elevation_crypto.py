#!/usr/bin/env python3
"""test_elevation_crypto.py — proves the broker (_mint) and the target wrapper (exec-argv-elevated._verify)
agree on the HMAC ticket canon: a broker ticket verifies, and every tamper/forgery/expiry is REJECTED.
Runs the wrapper's _verify directly (no root needed — only _run/_kill do the privileged parts)."""
import os, sys, json, base64, tempfile, importlib.util
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
TD = tempfile.mkdtemp(prefix="elev-crypto-")
KEY = os.urandom(48)
KF = os.path.join(TD, "key"); open(KF, "wb").write(KEY)
os.environ["TELEGRAM_BROKER_BOT_TOKEN"] = "x"
os.environ["HESTIA_ELEVATION_KEY_FILE"] = KF

spec = importlib.util.spec_from_file_location("brokerd", os.path.join(HERE, "..", "broker", "brokerd.py"))
bd = importlib.util.module_from_spec(spec); spec.loader.exec_module(bd)
ev = SourceFileLoader("execargvelev", os.path.join(HERE, "..", "target", "exec-argv-elevated")).load_module()
ev.KEY_FILE = KF                                    # point the wrapper at the same key

npass = nfail = 0
def ck(name, cond):
    global npass, nfail
    if cond: npass += 1; print(f"  PASS: {name}")
    else: nfail += 1; print(f"  FAIL: {name}")
def verify_ok(tok, action):
    try: return ev._verify(tok, action), None
    except SystemExit as e: return None, e.code

SID = "11111111-1111-4111-8111-111111111111"
RID = "22222222-2222-4222-8222-222222222222"
ETK = "33333333-3333-4333-8333-333333333333"
FIELDS = {"session_id": SID, "request_id": RID, "cwd": "/home/owner", "run_as": "owner",
          "argv": ["cat", "resume.tex"], "exec_token": ETK}

print("== broker mint <-> wrapper verify interop ==")
ck("elevation_enabled with key present", bd.elevation_enabled() is True)
tok = bd._mint("run", FIELDS)
t, code = verify_ok(tok, "run")
ck("valid broker ticket verifies in the wrapper", t is not None and t["request_id"] == RID and t["run_as"] == "owner")
ck("verified argv matches", t and t["argv"] == ["cat", "resume.tex"])

print("== forgeries / tampering are REJECTED ==")
# tamper the argv after signing
d = json.loads(base64.b64decode(tok)); d["argv"] = ["cat", "/etc/shadow"]
tampered = base64.b64encode(json.dumps(d).encode()).decode()
_, code = verify_ok(tampered, "run"); ck("tampered argv -> bad signature (rejected)", code == ev.E_SIG)
# tamper run_as (privilege upgrade attempt)
d = json.loads(base64.b64decode(tok)); d["run_as"] = "root"
_, code = verify_ok(base64.b64encode(json.dumps(d).encode()).decode(), "run"); ck("tampered run_as -> rejected", code == ev.E_SIG)
# forge with a DIFFERENT key (attacker without the shared secret)
import hmac as _h, hashlib as _hh
d = {k: v for k, v in FIELDS.items()}; d.update({"v": 1, "action": "run", "issued": int(__import__("time").time())})
canon = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
d["sig"] = _h.new(b"attacker-key-attacker-key-attacker!!", canon, _hh.sha256).hexdigest()
_, code = verify_ok(base64.b64encode(json.dumps(d).encode()).decode(), "run"); ck("wrong-key forgery -> rejected", code == ev.E_SIG)
# wrong action (run ticket presented as kill)
_, code = verify_ok(tok, "kill"); ck("run ticket presented as kill -> rejected", code == ev.E_SCHEMA)
# expired ticket
d = json.loads(base64.b64decode(tok)); d2 = {k: v for k, v in d.items() if k != "sig"}; d2["issued"] = 1000000000
canon = json.dumps(d2, sort_keys=True, separators=(",", ":")).encode()
d2["sig"] = _h.new(KEY, canon, _hh.sha256).hexdigest()
_, code = verify_ok(base64.b64encode(json.dumps(d2).encode()).decode(), "run"); ck("expired ticket -> rejected", code == ev.E_TTL)

print("== kill ticket round-trip ==")
kt = bd._mint("kill", {"exec_token": ETK})
t, _ = verify_ok(kt, "kill"); ck("kill ticket verifies", t is not None and t["exec_token"] == ETK)

print("== no key -> elevation disabled, no ticket ==")
bd.ELEV_KEY_FILE = os.path.join(TD, "absent")       # patch the module constant (read at import, not per-call env)
ck("elevation_enabled False without key", bd.elevation_enabled() is False)
ck("_mint returns None without key", bd._mint("run", FIELDS) is None)

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
