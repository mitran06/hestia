#!/usr/bin/env python3
"""test_confinement.py — Task 8 (2c §3): the exec-argv-elevated bwrap confinement branch + the JAIL PROOF.

Two kinds of test, both env-gated to skip-with-notice where the primitive is unavailable so CI stays green:

  (a) UNIT tests of the exec-argv-elevated confinement LOGIC — need NO root, run everywhere. They assert:
      - the confined branch builds the EXACT ordered bwrap arg vector (2c §3, order is load-bearing),
        via the importable pure helper `_bwrap_args(uid, home)`;
      - the exec dispatcher (refactored `_confined_exec_argv`) maps `confined is True` -> bwrap-wrapped argv,
        `confined is False` -> plain argv (today's execvpe), so the branch is decided ONLY by the strict bool;
      - a missing / non-bool `confined` already REFUSES (the Task-4 gate) — re-proven here so a refactor of
        the exec path cannot silently reintroduce a truthiness fallthrough;
      - C4: bwrap-absent + confined=True FAILS CLOSED (die E_EXEC), NEVER falls back to the plain argv —
        proven statically (single exec site + FileNotFoundError->E_EXEC handler, no plain-argv re-exec) AND
        at runtime (replicate the wrapper's execvpe('bwrap',...) on a bwrap-less PATH -> FileNotFoundError);
      - `--new-session` is NOT in the vector (breaks killpg revoke, C11); `--tmpfs /run` (WHOLE-tree mask),
        `--unshare-pid` and `--unshare-net` ARE (BLOCKER-1 user bus + system bus + docker.sock, C5, egress);
      - `_check_caller` / `ALLOWED_RUNAS` are BYTE-FOR-BYTE UNCHANGED (C12).

  (b) JAIL-PROOF integration tests — run the EXACT `_bwrap_args` vector via real `bwrap` DIRECTLY as the
      current unprivileged user (bwrap 0.11.0 + unprivileged userns on this host). They assert the
      confinement empirically holds: no AF_INET socket, no connect to ANY /run AF_UNIX control socket (the
      user bus, the SYSTEM D-Bus bus, systemd/private, docker.sock, libvirt-sock — all masked by the
      whole-tree --tmpfs /run, closing the docker-group + system-bus root+egress escapes), /proc shows only
      jail PIDs + /dev/null works (proves --bind / / BEFORE --dev/--proc arg-order), a setsid child dies on
      killpg revoke (C5), and a normal home-file read/write still works (full-fs access preserved, option B).

Custom harness (NOT pytest); run: python3 test_confinement.py
"""
import os, sys, json, time, signal, socket, shutil, subprocess, tempfile
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
# Load the wrapper as a module (it has no .py suffix). Only the pure helpers are exercised here — the
# privileged _run/_kill paths are never entered (no root, and we call the helpers directly).
ev = SourceFileLoader("execargvelev", os.path.join(HERE, "..", "target", "exec-argv-elevated")).load_module()

npass = nfail = 0
def ok(name, cond):
    global npass, nfail
    if cond: npass += 1; print(f"  PASS: {name}")
    else: nfail += 1; print(f"  FAIL: {name}")
def check(name, got, want):
    global npass, nfail
    if got == want: npass += 1; print(f"  PASS: {name} -> {got!r}")
    else: nfail += 1; print(f"  FAIL: {name}: got {got!r} want {want!r}")

UID  = os.getuid()
HOME = os.path.expanduser("~")

# ------------------------------------------------------------------------------------------------------
# (a) UNIT — the confinement logic, no root, no bwrap needed
# ------------------------------------------------------------------------------------------------------
print("== (a) UNIT: the EXACT ordered bwrap arg vector (2c §3, order is load-bearing) ==")
# The pure helper that both _run and the test build the vector from. Everything BETWEEN `bwrap` and `--`.
# Compute the BASE-CASE vector with $ZDOTDIR explicitly UNSET so the exact-vector assertion is deterministic
# regardless of the test host's env (the $ZDOTDIR branch is exercised separately below).
_saved_zdotdir = os.environ.pop("ZDOTDIR", None)
args = ev._bwrap_args(UID, HOME)
if _saved_zdotdir is not None: os.environ["ZDOTDIR"] = _saved_zdotdir

expected = [
    "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent",
    "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
    "--tmpfs", "/run", "--tmpfs", f"/run/user/{UID}",
    # persistence DIRS -> ephemeral --tmpfs (writes inside vanish with the jail); persistence FILES ->
    # RO /dev/null bind (uncreatable + unwritable). Masks WHETHER OR NOT the target pre-exists — closes the
    # finding-1 hole where --ro-bind-try silently no-op'd on a missing source, leaving --bind / / writable.
    "--tmpfs", f"{HOME}/.config/systemd/user",
    "--tmpfs", f"{HOME}/.config/autostart",
    "--tmpfs", f"{HOME}/.config/environment.d",
    # audit-fix M2-jail: the shell/login-rc set MATCHES broker.py's persistence floor (see _SHELL_RC_FILES)
    "--ro-bind", "/dev/null", f"{HOME}/.bashrc",
    "--ro-bind", "/dev/null", f"{HOME}/.zshrc",
    "--ro-bind", "/dev/null", f"{HOME}/.profile",
    "--ro-bind", "/dev/null", f"{HOME}/.bash_profile",
    "--ro-bind", "/dev/null", f"{HOME}/.bash_login",
    "--ro-bind", "/dev/null", f"{HOME}/.zprofile",
    "--ro-bind", "/dev/null", f"{HOME}/.zshenv",
    "--ro-bind", "/dev/null", f"{HOME}/.zlogin",
    "--ro-bind", "/dev/null", f"{HOME}/.zlogout",
    "--ro-bind", "/dev/null", f"{HOME}/.xsessionrc",
    "--ro-bind", "/dev/null", f"{HOME}/.xprofile",
    "--ro-bind", "/dev/null", f"{HOME}/.bash_logout",
]
check("_bwrap_args is the EXACT ordered vector", args, expected)

# order is load-bearing: --bind / / MUST come before --dev / --proc / --tmpfs (else they overmount & leak)
i_bind = args.index("--bind")
ok("--bind precedes --dev  (arg-order, C: no /dev overmount)", i_bind < args.index("--dev"))
ok("--bind precedes --proc (arg-order, C: no /proc overmount)", i_bind < args.index("--proc"))
ok("--bind precedes --tmpfs (arg-order)", i_bind < args.index("--tmpfs"))
# --bind maps / -> / (full fs, option B)
ok("--bind maps / to / (full-fs access)", args[i_bind + 1] == "/" and args[i_bind + 2] == "/")

print("== (a) UNIT: mandatory / forbidden flags ==")
ok("--unshare-net present (egress block, load-bearing)", "--unshare-net" in args)
ok("--unshare-pid present (setsid teardown, C5/C11)", "--unshare-pid" in args)
ok("--die-with-parent present", "--die-with-parent" in args)
ok("--tmpfs /run present (masks the WHOLE /run tree: closes docker.sock + system-bus + libvirt escapes)",
   "--tmpfs" in args and "/run" in args and args[args.index("/run") - 1] == "--tmpfs")
# The narrow --tmpfs /run/user/$UID ALONE was INSUFFICIENT (left docker.sock/system-bus reachable via
# --bind / / — CRITICAL escapes, empirically CONNECTED). The whole-tree --tmpfs /run closes those; the
# per-uid tmpfs is RETAINED (2c §3 BLOCKER-1 + the binding global constraint) as an explicit,
# refactor-resilient mask of the owner's session-bus path — nested on top of /run, harmless, AFTER /run.
ok("--tmpfs /run/user/$UID retained (2c §3 BLOCKER-1 explicit session-bus mask; global constraint)",
   f"/run/user/{UID}" in args and args[args.index(f"/run/user/{UID}") - 1] == "--tmpfs")
ok("--tmpfs /run precedes the nested --tmpfs /run/user/$UID (whole-tree mask first, per-uid on top)",
   args.index("/run") < args.index(f"/run/user/{UID}"))
ok("--new-session ABSENT (would break killpg revoke, C11)", "--new-session" not in args)
ok("--unshare-user ABSENT (would break owner file ownership, option B)", "--unshare-user" not in args)
# every persistence write-target is MASKED (delayed-exfil bypass close): dirs via ephemeral --tmpfs, files
# via a RO /dev/null bind — never a rw --bind, and CRUCIALLY never --ro-bind-try (which no-ops when the
# source is missing, the finding-1 hole). This holds even for not-yet-existing targets.
for pdir in (".config/systemd/user", ".config/autostart", ".config/environment.d"):
    p = f"{HOME}/{pdir}"
    ok(f"persistence DIR {pdir} is masked by --tmpfs (ephemeral; a plant cannot persist)",
       p in args and args[args.index(p) - 1] == "--tmpfs")
for pf in (".bashrc", ".zshrc", ".profile", ".bash_profile"):
    p = f"{HOME}/{pf}"
    idx = args.index(p)
    ok(f"persistence FILE {pf} is masked by (--ro-bind /dev/null {pf}) — uncreatable even if absent",
       idx >= 2 and args[idx - 1] == "/dev/null" and args[idx - 2] == "--ro-bind")
ok("NO persistence target is left as --ro-bind-try (the finding-1 no-op-on-missing hole is closed)",
   "--ro-bind-try" not in args)

print("== (a) UNIT: the confined-vs-plain exec argv selection (decided ONLY by strict bool) ==")
argv = ["cat", "/home/owner/resume.tex"]
# The refactored builder that _run calls: confined True -> bwrap-wrapped, False -> plain.
cA = ev._confined_exec_argv(True, argv, UID, HOME)
check("confined is True  -> execs bwrap", cA[0], "bwrap")
ok("confined True: vector is [bwrap, *BWRAP_ARGS, '--', *argv]",
   cA == ["bwrap", *ev._bwrap_args(UID, HOME), "--", *argv])
ok("confined True: the '--' separator precedes the user argv", "--" in cA and cA[cA.index("--")+1:] == argv)
cB = ev._confined_exec_argv(False, argv, UID, HOME)
check("confined is False -> plain argv (today's execvpe target)", cB, argv)

print("== (a) UNIT: C4 — bwrap absent + confined=True FAILS CLOSED to E_EXEC, never falls back to plain argv ==")
# C4 (2c §3 line 67, plan Task 8, RTM row C4): the WHOLE point is that only a test enforces the
# no-fallthrough guarantee against future refactors. Prove it three ways, statically, at the SINGLE exec site.
import inspect as _insp, re as _re
run_src = _insp.getsource(ev._run)
# 1) confined=True resolves argv[0]=='bwrap' — so an absent bwrap is what execvpe cannot find.
ok("C4: confined=True exec target is argv[0]=='bwrap' (bwrap-missing is the FileNotFoundError trigger)",
   ev._confined_exec_argv(True, argv, UID, HOME)[0] == "bwrap")
# 2) there is EXACTLY ONE os.execvpe in _run (single exec site — no alternate unconfined exec to fall to).
ok("C4: exactly ONE os.execvpe in _run (single exec site, no plain-argv fallback path)",
   len(_re.findall(r"os\.execvpe\(", run_src)) == 1)
# 3) that exec is guarded by a FileNotFoundError handler that die()s E_EXEC (fail-closed), and NOTHING
#    re-execs a plain argv after it. A refactor that turned bwrap-missing into an unconfined run would
#    have to either drop this handler or add a second execvpe — both are caught by (2)+(3).
_fnf = _re.search(r"except FileNotFoundError:\s*\n\s*die\(E_EXEC,", run_src)
ok("C4: bwrap-missing FileNotFoundError -> die(E_EXEC) (fail-closed; NEVER unconfined)", _fnf is not None)
ok("C4: no plain-argv re-exec after the confined exec (the confined branch cannot fall through to argv[0])",
   "os.execvpe(argv[0]" not in run_src and "execvpe(argv," not in run_src)

print("== (a) UNIT: strict-bool confined gate already REFUSES non-bool (Task-4, re-proven in exec path) ==")
def _validate(fields):
    """Run the wrapper's pure run-ticket schema validation on a field dict (no HMAC, no privilege)."""
    t = {"v": 1, "action": "run", **fields}
    try:
        ev._validate_run(t); return None
    except SystemExit as e:
        return e.code
BASE = {"session_id": "11111111-1111-4111-8111-111111111111",
        "request_id": "22222222-2222-4222-8222-222222222222",
        "exec_token": "33333333-3333-4333-8333-333333333333",
        "cwd": "/home/owner", "run_as": "@OWNER_RUNAS@", "argv": ["cat", "resume.tex"]}
ok("missing confined -> REFUSE (E_SCHEMA)", _validate({**BASE}) == ev.E_SCHEMA)
for bad in (0, 1, "", "false", "true", None, []):
    ok(f"confined={bad!r} (non-bool) -> REFUSE (E_SCHEMA, no truthiness)",
       _validate({**BASE, "confined": bad}) == ev.E_SCHEMA)
ok("confined=True  (bool) accepted by schema", _validate({**BASE, "confined": True}) is None)
ok("confined=False (bool) accepted by schema", _validate({**BASE, "confined": False}) is None)

print("== (a) UNIT: C12 — _check_caller + ALLOWED_RUNAS are byte-for-byte UNCHANGED ==")
import inspect
src = inspect.getsource(ev._check_caller)
EXPECT_CHECK_CALLER = (
    'def _check_caller():\n'
    '    try:\n'
    '        name = pwd.getpwuid(int(os.environ.get("SUDO_UID", "-1"))).pw_name\n'
    '    except (ValueError, KeyError):\n'
    '        name = None\n'
    '    if name != "hestia-agent":\n'
    '        die(E_CALLER, "caller is not hestia-agent")\n'
)
ok("_check_caller source is byte-for-byte unchanged (SUDO_UID -> hestia-agent gate, C12)",
   src == EXPECT_CHECK_CALLER)
check("ALLOWED_RUNAS unchanged == {'owner'} (C12)", ev.ALLOWED_RUNAS, {"@OWNER_RUNAS@"})

print("== (a) RUNTIME: C4 — with bwrap unresolvable, the confined exec raises FileNotFoundError (never runs argv) ==")
# Runtime companion to the static C4 proof: replicate the wrapper's EXACT final call — os.execvpe('bwrap',
# ['bwrap', *_bwrap_args, '--', *argv], env) — in a fresh child with a PATH that has NO bwrap, and assert the
# child dies with FileNotFoundError and NEVER execs the sentinel argv (which would print SHOULD_NOT_RUN). This
# is the confined branch's behavior when bwrap is absent; the wrapper's handler then die()s E_EXEC (C4).
_sentinel = os.path.join(tempfile.gettempdir(), "hestia_c4_should_not_run.marker")
try: os.unlink(_sentinel)
except OSError: pass
_exec_argv = ev._confined_exec_argv(True, ["sh", "-c", f"echo ran > {_sentinel!r}; echo SHOULD_NOT_RUN"], UID, HOME)
_child = (
    "import os, sys\n"
    "env = {'PATH': '/nonexistent-empty-dir'}\n"   # bwrap is unresolvable on this PATH
    f"exec_argv = {_exec_argv!r}\n"
    "try:\n"
    "    os.execvpe(exec_argv[0], exec_argv, env)\n"   # mirrors exec-argv-elevated._run's single exec site
    "except FileNotFoundError:\n"
    "    sys.exit(42)\n"                                # the wrapper maps this -> die(E_EXEC); we use 42 as a probe
    "sys.exit(0)\n"
)
_r = subprocess.run([sys.executable, "-c", _child], capture_output=True, timeout=15)
ok("C4 runtime: bwrap-unresolvable confined exec raises FileNotFoundError (exit 42, fail-closed)",
   _r.returncode == 42)
ok("C4 runtime: the plain argv NEVER ran (no fallback-to-unconfined; sentinel not created)",
   not os.path.exists(_sentinel) and b"SHOULD_NOT_RUN" not in _r.stdout)
try: os.unlink(_sentinel)
except OSError: pass

print("== (a) UNIT: M2-jail CROSS-CHECK — executor RO-binds EVERY shell-rc the broker floor HARD_DENYs ==")
# Single-source-of-truth sync (audit-fix M2-jail): the confinement RO-bind list in exec-argv-elevated MUST
# cover the SAME shell/login-rc set that broker.py's lexical persistence FLOOR (_PERSISTENCE_PATH_FRAGMENTS)
# HARD_DENYs — otherwise a rc-file the floor blocks by NAME could still be planted through a path the jail
# forgot to make read-only, and would then run UNCONFINED-with-network at next login (delayed-exfil bypass).
# We IMPORT broker and derive the set (never re-hardcode it here) so a future addition to broker's floor
# fails THIS test until the executor is updated too.
_broker = SourceFileLoader("brokerfloor", os.path.join(HERE, "..", "broker", "broker.py")).load_module()
# The shell/login-rc dotfile fragments are the leading-"/." single-component entries — this deliberately
# EXCLUDES the "/.config/..." persistence DIRS (already RO-bound + asserted above) and the "/etc/" system
# fragment (outside $HOME; not a per-user rc file the jail's $HOME-scoped ro-binds address).
_shellrc_frags = [f for f in _broker._PERSISTENCE_PATH_FRAGMENTS
                  if f.startswith("/.") and "/" not in f[1:]]
ok("broker floor exposes >= the 12 known shell/login-rc fragments (sanity on the source of truth)",
   len(_shellrc_frags) >= 12)
# every shell-rc fragment must appear in the executor vector masked as (--ro-bind /dev/null $HOME+frag) —
# a RO empty file, uncreatable/unwritable even when the real dotfile is absent (finding-1 fix).
_missing = []
for _frag in _shellrc_frags:
    _p = f"{HOME}{_frag}"          # e.g. /.zshenv -> $HOME/.zshenv
    _bound = any(args[k] == "--ro-bind" and args[k+1] == "/dev/null" and args[k+2] == _p
                 for k in range(len(args) - 2))
    if not _bound: _missing.append(_frag)
    ok(f"M2-jail: shell-rc {_frag} is /dev/null-masked in the executor vector", _bound)
ok("M2-jail: executor RO-bind set COVERS EVERY broker-floor shell-rc fragment (single-source sync)",
   _missing == [])

print("== (a) UNIT: M2-jail — $ZDOTDIR zsh rc files are ALSO RO-bound when $ZDOTDIR is set ==")
# zsh reads .zshenv/.zshrc/.zprofile/.zlogin/.zlogout from $ZDOTDIR when set; the jail must RO-bind those too.
_zd = "/home/owner/.zdot-test"
os.environ["ZDOTDIR"] = _zd
_args_zd = ev._bwrap_args(UID, HOME)
if _saved_zdotdir is not None: os.environ["ZDOTDIR"] = _saved_zdotdir
else: os.environ.pop("ZDOTDIR", None)
for _zrc in (".zshenv", ".zshrc", ".zprofile", ".zlogin", ".zlogout"):
    _zp = f"{_zd}/{_zrc}"
    _bound = any(_args_zd[k] == "--ro-bind" and _args_zd[k+1] == "/dev/null" and _args_zd[k+2] == _zp
                 for k in range(len(_args_zd) - 2))
    ok(f"M2-jail: $ZDOTDIR/{_zrc} is /dev/null-masked when $ZDOTDIR is set", _bound)
# a $ZDOTDIR equal to $HOME (or relative) must NOT add duplicate/garbage binds — same vector as base case
os.environ["ZDOTDIR"] = HOME
_args_home = ev._bwrap_args(UID, HOME)
os.environ["ZDOTDIR"] = "relative/not/abs"
_args_rel = ev._bwrap_args(UID, HOME)
if _saved_zdotdir is not None: os.environ["ZDOTDIR"] = _saved_zdotdir
else: os.environ.pop("ZDOTDIR", None)
ok("M2-jail: $ZDOTDIR==$HOME adds NO extra binds (vector == base case)", _args_home == expected)
ok("M2-jail: a non-absolute $ZDOTDIR is ignored (vector == base case)", _args_rel == expected)

# ------------------------------------------------------------------------------------------------------
# (b) JAIL PROOF — run the EXACT vector via real bwrap, directly as this user (env-gated)
# ------------------------------------------------------------------------------------------------------
print("== (b) JAIL PROOF: run the exact _bwrap_args vector via real bwrap ==")

def _bwrap_ok():
    if not shutil.which("bwrap"):
        return False, "bwrap not on PATH"
    try:
        r = subprocess.run(["bwrap", "--unshare-net", "--bind", "/", "/", "--", "true"],
                           capture_output=True, timeout=15)
        if r.returncode != 0:
            return False, "bwrap userns probe failed (unprivileged userns disabled?): " + r.stderr.decode(errors="replace").strip()
    except Exception as e:
        return False, f"bwrap probe raised {e!r}"
    return True, ""

_avail, _why = _bwrap_ok()
if not _avail:
    print(f"  SKIP: jail-proof tests — {_why} (this host cannot run the bwrap jail; UNIT tests above still ran)")
else:
    BWA = ev._bwrap_args(UID, HOME)  # the exact vector under test

    def jail_run(pyfile_src, timeout=20):
        """Write a probe script under $HOME (─ /tmp & /run/user are tmpfs-masked in-jail, so scripts + any
        shared files MUST live under the --bind / / home path) and run it as the SOLE argv inside the EXACT
        confined vector. Returns (returncode, stdout, stderr)."""
        d = tempfile.mkdtemp(prefix="jail-", dir=HOME)
        sp = os.path.join(d, "probe.py")
        open(sp, "w").write(pyfile_src)
        try:
            r = subprocess.run(["bwrap", *BWA, "--", "python3", sp],
                               capture_output=True, timeout=timeout)
            return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace"), d
        except subprocess.TimeoutExpired:
            return 124, "", "timeout", d

    # 1) AF_INET socket cannot connect out (the load-bearing egress block)
    rc, out, err, d = jail_run(
        "import socket, sys\n"
        "try:\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)\n"
        "    s.connect(('1.1.1.1', 80)); print('OPENED')\n"
        "except OSError as e:\n"
        "    print('BLOCKED', e.errno)\n"
    )
    ok("confined AF_INET connect is BLOCKED (--unshare-net; BLOCKER egress)", out.strip().startswith("BLOCKED"))
    shutil.rmtree(d, ignore_errors=True)

    # 2) cannot connect to ANY path-based AF_UNIX control socket under /run (--tmpfs /run whole-tree mask).
    # AF_UNIX sockets are NOT covered by --unshare-net, so a --bind / / jail otherwise leaks every /run
    # socket. The narrow --tmpfs /run/user/$UID left these reachable and they are UNCONDITIONAL escapes when
    # run_as is in host groups: /run/docker.sock (docker group -> `docker run --network=host -v /:/host` =
    # root+egress, holds HEADLESS) and /run/dbus/system_bus_socket (system-bus StartTransientUnit) — both
    # were empirically CONNECTED from the old jail. We assert connect() FAILS + the socket is MASKED AWAY
    # (errno ENOENT) for the user bus (BLOCKER-1) AND the system bus, systemd/private, and docker.sock.
    ENOENT = __import__("errno").ENOENT
    SOCKS = [
        ("user_bus",    f"/run/user/{UID}/bus"),        # BLOCKER-1 (session D-Bus)
        ("system_bus",  "/run/dbus/system_bus_socket"), # CRITICAL: system-bus StartTransientUnit escape
        ("systemd_priv","/run/systemd/private"),        # systemd manager private socket
        ("docker",      "/run/docker.sock"),            # CRITICAL: unconditional root+egress via docker group
        ("libvirt",     "/run/libvirt/libvirt-sock"),   # libvirt group escape
    ]
    for _name, _path in SOCKS:
        rc, out, err, d = jail_run(
            "import socket, os, errno\n"
            f"p = {_path!r}\n"
            "present = os.path.exists(p)\n"
            "try:\n"
            "    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3); s.connect(p)\n"
            "    print('CONNECTED', present, -1)\n"
            "except OSError as e:\n"
            "    print('BLOCKED', present, e.errno)\n"
        )
        parts = out.split()
        blocked = len(parts) == 3 and parts[0] == "BLOCKED"
        masked  = blocked and parts[1] == "False" and int(parts[2]) == ENOENT  # ENOENT == the tmpfs hid it
        ok(f"confined CANNOT connect to {_name} ({_path}) — --tmpfs /run masks it (blocked+absent)",
           blocked and masked)
        shutil.rmtree(d, ignore_errors=True)

    # 3) /proc shows ONLY jail PIDs (not the ~hundreds of host PIDs) and /dev/null works (arg-order proof)
    rc, out, err, d = jail_run(
        "import os\n"
        "pids = [int(n) for n in os.listdir('/proc') if n.isdigit()]\n"
        "open('/dev/null','w').write('x')\n"
        "print('PIDS', len(pids), max(pids))\n"
    )
    parts = out.split()
    proc_isolated = len(parts) == 3 and parts[0] == "PIDS" and int(parts[1]) <= 5 and int(parts[2]) <= 10
    ok("/proc shows ONLY jail PIDs (host PIDs hidden; --unshare-pid + --proc after --bind)", proc_isolated)
    ok("/dev/null works (proves --bind / / BEFORE --dev; no /dev overmount)", rc == 0)
    shutil.rmtree(d, ignore_errors=True)

    # 4) a normal home file read/write STILL works (full-fs access preserved, option B)
    d = tempfile.mkdtemp(prefix="jail-rw-", dir=HOME)
    target = os.path.join(d, "data.txt")
    open(target, "w").write("original\n")
    rc, out, err, d2 = jail_run(
        f"open({target!r}, 'a').write('appended-in-jail\\n')\n"
        f"print('READBACK', open({target!r}).read().count(chr(10)))\n"
    )
    wrote = os.path.exists(target) and "appended-in-jail" in open(target).read()
    ok("confined run CAN read+write a normal home file (full-fs access, option B)", "READBACK" in out and wrote)
    shutil.rmtree(d, ignore_errors=True); shutil.rmtree(d2, ignore_errors=True)

    # 5) a planted secret is READABLE but a socket is NOT (documents the owner-accepted residual, §7)
    d = tempfile.mkdtemp(prefix="jail-sec-", dir=HOME)
    secret = os.path.join(d, "id_test")
    open(secret, "w").write("SECRET-KEY-MATERIAL\n")
    rc, out, err, d2 = jail_run(
        f"import socket\n"
        f"read = 'SECRET-KEY-MATERIAL' in open({secret!r}).read()\n"
        f"try:\n"
        f"    socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(('1.1.1.1', 80)); sock='OPEN'\n"
        f"except OSError:\n"
        f"    sock='BLOCKED'\n"
        f"print('RESIDUAL', read, sock)\n"
    )
    ok("residual: a planted secret is READABLE but the socket is BLOCKED (§7 owner-accepted residual)",
       out.strip() == "RESIDUAL True BLOCKED")
    shutil.rmtree(d, ignore_errors=True); shutil.rmtree(d2, ignore_errors=True)

    # 5b) FINDING-1 REGRESSION — a confined run CANNOT PLANT a persistence payload into a target that does
    # NOT pre-exist. These rc/autostart/unit paths run code at the owner's next login/shell; the OLD
    # --ro-bind-try silently NO-OP'd on a MISSING source, leaving the --bind / / root writable there, so a
    # confined run could CREATE a fresh dotfile/unit that then ran UNCONFINED-with-network (delayed-exfil).
    # The fix masks each target regardless of existence: files -> RO /dev/null bind (uncreatable); dirs ->
    # ephemeral tmpfs (writes inside vanish with the jail). We test against a SCRATCH $HOME (NEVER the user's
    # real rc files) where every persistence target is guaranteed ABSENT — the exact case the old test missed.
    print("== (b) JAIL PROOF: FINDING-1 — confined run cannot PLANT into a MISSING persistence target ==")
    _sh = tempfile.mkdtemp(prefix="jail-scratchhome-", dir=HOME)     # scratch $HOME under --bind / / (real fs)
    _bwa_sh = ev._bwrap_args(UID, _sh)                               # the jail vector targeting the scratch home
    _PAY = "PLANTED-PAYLOAD-curl-evil-sh"
    try:
        for _rel in (".bashrc", ".config/autostart/evil.desktop", ".config/systemd/user/evil.service"):
            _tgt = os.path.join(_sh, _rel)
            ok(f"precondition: scratch ~/{_rel} is ABSENT before the jail run", not os.path.exists(_tgt))
            _probe = os.path.join(_sh, "plant_probe.py")
            open(_probe, "w").write(
                "import os\n"
                f"tgt = {_tgt!r}\n"
                "try:\n"
                "    os.makedirs(os.path.dirname(tgt), exist_ok=True)\n"
                f"    open(tgt, 'w').write({_PAY!r}); print('WROTE-IN-JAIL')\n"
                "except OSError as e:\n"
                "    print('BLOCKED', e.errno)\n"
            )
            subprocess.run(["bwrap", *_bwa_sh, "--", "python3", _probe], capture_output=True, timeout=20)
            _persisted = os.path.exists(_tgt) and _PAY in open(_tgt, errors="replace").read()
            ok(f"FINDING-1: confined plant into MISSING ~/{_rel} does NOT persist to the host", not _persisted)
    finally:
        shutil.rmtree(_sh, ignore_errors=True)

    # 6) C5 — a setsid child inside a confined run is KILLED when the bwrap parent's group is killpg'd
    print("== (b) JAIL PROOF: C5 setsid-child revoke (killpg + --unshare-pid teardown) ==")
    d = tempfile.mkdtemp(prefix="jail-c5-", dir=HOME)
    hb = os.path.join(d, "hb")
    gc = os.path.join(d, "gc.py")
    open(gc, "w").write(
        "import time\n"
        f"f = open({hb!r}, 'a')\n"
        "while True:\n"
        "    f.write('tick\\n'); f.flush(); time.sleep(0.1)\n"
    )
    inn = os.path.join(d, "inner.py")
    open(inn, "w").write(
        "import subprocess, time\n"
        f"subprocess.Popen(['setsid', 'python3', {gc!r}])\n"
        "time.sleep(60)\n"
    )
    # spawn bwrap in its OWN process group — mirrors the wrapper's os.setpgrp() before exec, so the whole
    # confined tree is revocable via os.killpg (exactly hestia-part7's kill path).
    p = subprocess.Popen(["bwrap", *BWA, "--", "python3", inn], start_new_session=True)
    pgid = os.getpgid(p.pid)
    time.sleep(1.3)
    c1 = sum(1 for _ in open(hb)) if os.path.exists(hb) else 0
    time.sleep(0.5)
    c2 = sum(1 for _ in open(hb)) if os.path.exists(hb) else 0
    ok("C5 setup: the setsid child heartbeat GROWS during the confined run", c2 > c1)
    # REVOKE via killpg (SIGTERM then SIGKILL the group) — the wrapper's revoke model
    for s in (signal.SIGTERM, signal.SIGKILL):
        try: os.killpg(pgid, s)
        except ProcessLookupError: break
        time.sleep(0.4)
    time.sleep(1.5)
    c3 = sum(1 for _ in open(hb))
    time.sleep(1.0)
    c4 = sum(1 for _ in open(hb))
    ok("C5: the setsid child is KILLED on revoke (heartbeat FROZEN post-killpg; --unshare-pid teardown)",
       c3 == c4 and c2 > c1)
    shutil.rmtree(d, ignore_errors=True)

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
