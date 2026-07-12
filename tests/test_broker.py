#!/usr/bin/env python3
"""test_broker.py — Part 3 decision-engine proof. Pure logic; runs anywhere broker.py is importable.
Covers: free-zone auto-run, default-DENY-to-button, malformed REJECT, canon determinism + injection."""
import os, sys, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("broker", os.path.join(HERE, "..", "broker", "broker.py"))
broker = importlib.util.module_from_spec(spec)
os.environ["HESTIA_AUDIT"] = "/tmp/hestia-test-audit.log"   # don't touch the real audit log
spec.loader.exec_module(broker)

SID = "11111111-1111-4111-8111-111111111111"
RID = "22222222-2222-4222-8222-222222222222"
def req(**kw):
    base = {"v": 1, "session_id": SID, "request_id": RID, "cwd": "/srv/projects", "elevate": False, "argv": ["ls"]}
    base.update(kw); return base

npass = nfail = 0
def check(name, got, want):
    global npass, nfail
    if got == want: npass += 1; print(f"  PASS: {name} -> {got}")
    else: nfail += 1; print(f"  FAIL: {name}: got {got!r} want {want!r}")

def dec(r):
    """classify a well-formed req dict (bypasses JSON; policy only)."""
    return broker.classify(r)[0]

print("== free-zone (IN_SCOPE) ==")
check("ls -la in workspace", dec(req(argv=["ls","-la"])), broker.IN_SCOPE)
check("cat subdir/file", dec(req(argv=["cat","notes/readme.md"])), broker.IN_SCOPE)
check("find (benign)", dec(req(argv=["find",".","-name","*.py"])), broker.IN_SCOPE)
check("grep -r", dec(req(argv=["grep","-rn","TODO","."])), broker.IN_SCOPE)
check("head -n 5 (separate-token value)", dec(req(argv=["head","-n","5","f.txt"])), broker.IN_SCOPE)
check("ls --color (safe long)", dec(req(argv=["ls","--color"])), broker.IN_SCOPE)

print("== default-DENY-to-button (NEEDS_BUTTON) ==")
check("git status (git NOT free-zone)", dec(req(argv=["git","status"])), broker.NEEDS_BUTTON)
check("bash -c", dec(req(argv=["bash","-c","echo hi"])), broker.NEEDS_BUTTON)
check("python", dec(req(argv=["python3","x.py"])), broker.NEEDS_BUTTON)
check("cp (writer)", dec(req(argv=["cp","a","b"])), broker.NEEDS_BUTTON)
check("elevate+ls", dec(req(elevate=True, argv=["ls"])), broker.NEEDS_BUTTON)
check("cwd outside workspace", dec(req(cwd="/home/owner", argv=["ls"])), broker.NEEDS_BUTTON)
check("cwd lexical escape", dec(req(cwd="/srv/projects/../etc", argv=["ls"])), broker.NEEDS_BUTTON)
check("argv0 is a path", dec(req(argv=["/bin/ls"])), broker.NEEDS_BUTTON)
check("cat /etc/passwd (abs arg)", dec(req(argv=["cat","/etc/passwd"])), broker.NEEDS_BUTTON)
check("cat ../.. escape", dec(req(argv=["cat","../../etc/passwd"])), broker.NEEDS_BUTTON)
check("find -delete", dec(req(argv=["find",".","-delete"])), broker.NEEDS_BUTTON)
check("find -exec", dec(req(argv=["find",".","-exec","rm","{}",";"])), broker.NEEDS_BUTTON)
# --- IN_SCOPE-bypass fixes (fresh-eyes review 2026-07-09): all MUST button ---
check("rg --pre (exec) removed from allowlist", dec(req(argv=["rg","--pre=/usr/bin/id","x","f"])), broker.NEEDS_BUTTON)
check("sort --output (write) removed", dec(req(argv=["sort","--output=/etc/cron.d/x","f"])), broker.NEEDS_BUTTON)
check("grep --file=/etc/passwd (glued =)", dec(req(argv=["grep","--file=/etc/passwd","."])), broker.NEEDS_BUTTON)
check("grep -f /etc/passwd (-f not safe)", dec(req(argv=["grep","-f","/etc/passwd","."])), broker.NEEDS_BUTTON)
check("glued -f/etc/passwd", dec(req(argv=["grep","-f/etc/passwd","."])), broker.NEEDS_BUTTON)
check("cat --opt=/abs (any =)", dec(req(argv=["cat","--show-all=/etc/passwd"])), broker.NEEDS_BUTTON)
check("@argfile operand", dec(req(argv=["cat","@/etc/passwd"])), broker.NEEDS_BUTTON)
check("unlisted short flag -Z", dec(req(argv=["ls","-Z"])), broker.NEEDS_BUTTON)
check("head -n5 glued value (conservative button)", dec(req(argv=["head","-n5","f"])), broker.NEEDS_BUTTON)
check("ls --unlisted-long", dec(req(argv=["ls","--full-time"])), broker.NEEDS_BUTTON)
# --- audit fix (2026-07-09): zero-operand host-state leakers df/id removed from free-zone ---
check("df -h (target mount-table leak) now buttons", dec(req(argv=["df","-h"])), broker.NEEDS_BUTTON)
check("bare df now buttons", dec(req(argv=["df"])), broker.NEEDS_BUTTON)
check("id (agent recon) now buttons", dec(req(argv=["id"])), broker.NEEDS_BUTTON)
check("du -sh . still free-zone (scoped to cwd)", dec(req(argv=["du","-sh","."])), broker.IN_SCOPE)

print("== malformed (REJECT via validate) ==")
import json
def vrej(name, raw, eid=RID):
    global npass, nfail
    try:
        broker.validate_request(raw if isinstance(raw,bytes) else json.dumps(raw).encode(), eid)
        nfail += 1; print(f"  FAIL: {name}: did NOT reject")
    except broker.Reject as e:
        npass += 1; print(f"  PASS: {name} -> REJECT ({e})")
vrej("NUL in argv", req(argv=["ls","a\x00b"]))
vrej("missing key", {k:v for k,v in req().items() if k!="cwd"})
vrej("extra key", {**req(), "extra":1})
vrej("bad version", req(v=2))
vrej("non-uuid request_id", {**req(), "request_id":"nope"})
vrej("request_id != filename", req(), eid="33333333-3333-4333-8333-333333333333")
vrej("elevate not bool", req(elevate="yes"))
vrej("argv empty", req(argv=[]))
vrej("cwd not absolute", req(cwd="relative/path"))
vrej("non-dict json", b"[1,2,3]")
vrej("invalid json", b"{not json")
vrej("oversize", ("{"+" "*70000+"}").encode())

print("== canonicalization: determinism + injection-resistance ==")
h = broker.cmd_hash
check("deterministic", h(req(argv=["ls","-la"])) == h(req(argv=["ls","-la"])), True)
check("argv split ambiguity blocked", h(req(argv=["ls","-la"])) != h(req(argv=["ls -la"])), True)
check("['ab',''] != ['a','b']", h(req(argv=["ab",""])) != h(req(argv=["a","b"])), True)
check("cwd change -> new hash", h(req(cwd="/srv/projects")) != h(req(cwd="/srv/projects/x")), True)
check("elevate change -> new hash", h(req(elevate=False)) != h(req(elevate=True)), True)
check("session_id change -> new hash", h(req(session_id=SID)) != h(req(session_id=RID)), True)

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
