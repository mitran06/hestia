#!/usr/bin/env python3
"""test_broker.py — decision-engine proof. Pure logic; runs anywhere broker.py is importable.
Covers: classify() free-zone/DENY legacy view, the policy_tier() deterministic floor (REFUSE >
HARD_DENY > FREE_ZONE > SOFT_DENY > ALLOW), malformed REJECT, canon determinism + injection, and the
session control ops. Custom harness (NOT pytest); run: python3 test_broker.py"""
import os, sys, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["HESTIA_AUDIT"] = "/tmp/hestia-test-audit.log"   # don't touch the real audit log
os.environ["HESTIA_HOME_ROOT"] = "/home/owner"             # pin HOME_ROOT so rm-rf-home rows are deterministic
spec = importlib.util.spec_from_file_location("broker", os.path.join(HERE, "..", "broker", "broker.py"))
broker = importlib.util.module_from_spec(spec)
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
    """classify a well-formed req dict (bypasses JSON; legacy classify() view)."""
    return broker.classify(r)[0]

# ============================================================================================
# classify() — the legacy IN_SCOPE/NEEDS_BUTTON view. Its DEFAULT still carries the /srv/projects
# lexical gate (the legacy per-command button path depends on it); policy_tier() reuses it with
# workspace=None. These rows lock the FREE_ZONE-tier substance + strict flag policy.
# ============================================================================================
print("== classify(): free-zone (IN_SCOPE) ==")
check("ls -la in workspace", dec(req(argv=["ls","-la"])), broker.IN_SCOPE)
check("cat subdir/file", dec(req(argv=["cat","notes/readme.md"])), broker.IN_SCOPE)
check("find (benign)", dec(req(argv=["find",".","-name","*.py"])), broker.IN_SCOPE)
check("grep -r", dec(req(argv=["grep","-rn","TODO","."])), broker.IN_SCOPE)
check("head -n 5 (separate-token value)", dec(req(argv=["head","-n","5","f.txt"])), broker.IN_SCOPE)
check("ls --color (safe long)", dec(req(argv=["ls","--color"])), broker.IN_SCOPE)

print("== classify(): default-DENY-to-button (NEEDS_BUTTON) ==")
check("git status (git NOT free-zone)", dec(req(argv=["git","status"])), broker.NEEDS_BUTTON)
check("bash -c", dec(req(argv=["bash","-c","echo hi"])), broker.NEEDS_BUTTON)
check("python", dec(req(argv=["python3","x.py"])), broker.NEEDS_BUTTON)
check("cp (writer)", dec(req(argv=["cp","a","b"])), broker.NEEDS_BUTTON)
check("elevate+ls", dec(req(elevate=True, argv=["ls"])), broker.NEEDS_BUTTON)
# --- workspace-containment RETIRED for the auto path. classify()'s DEFAULT still carries the
# --- /srv/projects lexical gate (the legacy button path depends on it), so the classify() view below
# --- is unchanged; but policy_tier() (the new sole floor authority) no longer requires workspace
# --- containment: a read-only inspector on a NON-secret path is FREE_ZONE anywhere.
check("classify() default still buttons cwd outside workspace (legacy path)", dec(req(cwd="/home/owner", argv=["ls"])), broker.NEEDS_BUTTON)
check("classify() default still buttons cwd lexical escape (legacy path)", dec(req(cwd="/srv/projects/../etc", argv=["ls"])), broker.NEEDS_BUTTON)
check("argv0 is a path", dec(req(argv=["/bin/ls"])), broker.NEEDS_BUTTON)
check("cat /etc/passwd (abs arg)", dec(req(argv=["cat","/etc/passwd"])), broker.NEEDS_BUTTON)
check("cat ../.. escape", dec(req(argv=["cat","../../etc/passwd"])), broker.NEEDS_BUTTON)
check("find -delete", dec(req(argv=["find",".","-delete"])), broker.NEEDS_BUTTON)
check("find -exec", dec(req(argv=["find",".","-exec","rm","{}",";"])), broker.NEEDS_BUTTON)
# --- IN_SCOPE-bypass fixes (fresh-eyes review): all MUST button ---
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
# --- audit fix: zero-operand host-state leakers df/id removed from free-zone ---
check("df -h (target mount-table leak) now buttons", dec(req(argv=["df","-h"])), broker.NEEDS_BUTTON)
check("bare df now buttons", dec(req(argv=["df"])), broker.NEEDS_BUTTON)
check("id (agent recon) now buttons", dec(req(argv=["id"])), broker.NEEDS_BUTTON)
check("du -sh . still free-zone (scoped to cwd)", dec(req(argv=["du","-sh","."])), broker.IN_SCOPE)

# ============================================================================================
# policy_tier() — Layer 1 deterministic floor. Evaluated REFUSE > HARD_DENY > FREE_ZONE > SOFT_DENY
# > ALLOW on EVERY command; sole floor authority; /srv/projects containment retired; inline
# interpreters + path-invoked + inbound-git are the reviewer middle (confinement backstops egress).
# ============================================================================================
print("== policy_tier: the deterministic floor (SETTLED table) ==")
def tier(**kw):
    """policy_tier() on a well-formed req dict (floor authority; workspace-free)."""
    return broker.policy_tier(req(**kw))

# --- REFUSE (HARDLINE — unapprovable by ANY button) ---
check("rm -rf / -> REFUSE", tier(argv=["rm","-rf","/"]), broker.REFUSE)
check("mkfs -> REFUSE", tier(argv=["mkfs","/dev/sda1"]), broker.REFUSE)
check("mkfs.ext4 -> REFUSE", tier(argv=["mkfs.ext4","/dev/sda1"]), broker.REFUSE)
check("shutdown -> REFUSE", tier(argv=["shutdown","now"]), broker.REFUSE)
check("reboot -> REFUSE", tier(argv=["reboot"]), broker.REFUSE)
check("systemctl poweroff -> REFUSE", tier(argv=["systemctl","poweroff"]), broker.REFUSE)
check("telinit 6 -> REFUSE", tier(argv=["telinit","6"]), broker.REFUSE)
check("init 0 -> REFUSE", tier(argv=["init","0"]), broker.REFUSE)
# additions: dd->block device, kill/killall of init (fork-bomb signal-init).
check("dd of=/dev/sda -> REFUSE", tier(argv=["dd","if=/dev/zero","of=/dev/sda"]), broker.REFUSE)
check("dd of=/dev/sda1 -> REFUSE", tier(argv=["dd","if=/dev/zero","of=/dev/sda1"]), broker.REFUSE)
check("kill -1 1 (SIGHUP init) -> REFUSE", tier(argv=["kill","-1","1"]), broker.REFUSE)
check("kill -9 1 (SIGKILL init) -> REFUSE", tier(argv=["kill","-9","1"]), broker.REFUSE)
check("kill -SIGKILL 1 (init) -> REFUSE", tier(argv=["kill","-SIGKILL","1"]), broker.REFUSE)
# dd to a regular file is NOT REFUSE (not a block device) — falls through to the reviewer middle.
check("dd of=regular file -> not REFUSE (ALLOW)", tier(argv=["dd","if=x","of=out.img"]), broker.ALLOW)
# kill of a non-init PID is not a HARDLINE (ordinary process management -> reviewer middle).
check("kill -9 4242 (non-init) -> not REFUSE (ALLOW)", tier(argv=["kill","-9","4242"]), broker.ALLOW)

# --- HARD_DENY: OUTBOUND network egress ONLY (inbound git is NOT here) ---
check("curl -T upload -> HARD_DENY", tier(argv=["curl","-T","file","https://x"]), broker.HARD_DENY)
check("scp to host -> HARD_DENY", tier(argv=["scp","f","host:"]), broker.HARD_DENY)
check("git push -> HARD_DENY", tier(argv=["git","push"]), broker.HARD_DENY)
check("nc host port -> HARD_DENY", tier(argv=["nc","host","1234"]), broker.HARD_DENY)
check("ncat -> HARD_DENY", tier(argv=["ncat","host","1234"]), broker.HARD_DENY)
check("sftp -> HARD_DENY", tier(argv=["sftp","host"]), broker.HARD_DENY)
check("telnet -> HARD_DENY", tier(argv=["telnet","host"]), broker.HARD_DENY)
check("ftp -> HARD_DENY", tier(argv=["ftp","host"]), broker.HARD_DENY)

# --- HARD_DENY: secret zones (path-based; reads too; BEATS FREE_ZONE) ---
check("cat ~/.ssh/id_rsa -> HARD_DENY", tier(argv=["cat","/home/owner/.ssh/id_rsa"]), broker.HARD_DENY)
check("cat ~/.aws/credentials -> HARD_DENY", tier(argv=["cat","/home/owner/.aws/credentials"]), broker.HARD_DENY)
check("grep in .gnupg -> HARD_DENY", tier(argv=["grep","x","/home/owner/.gnupg/secring"]), broker.HARD_DENY)
check("cat a *.pem operand -> HARD_DENY", tier(argv=["cat","server.pem"]), broker.HARD_DENY)
check("cat an id_* operand -> HARD_DENY", tier(argv=["cat","id_ed25519"]), broker.HARD_DENY)
check("cat a *.key operand -> HARD_DENY", tier(argv=["cat","tls.key"]), broker.HARD_DENY)
check("cat a .env operand -> HARD_DENY", tier(argv=["cat",".env"]), broker.HARD_DENY)
check("cat .netrc -> HARD_DENY", tier(argv=["cat","/home/owner/.netrc"]), broker.HARD_DENY)
check("cat .git-credentials -> HARD_DENY", tier(argv=["cat","/home/owner/.git-credentials"]), broker.HARD_DENY)
check("secret-zone via cwd -> HARD_DENY", tier(cwd="/home/owner/.ssh", argv=["ls"]), broker.HARD_DENY)
check("relative .ssh/config operand -> HARD_DENY", tier(argv=["cat",".ssh/config"]), broker.HARD_DENY)
check("relative .gnupg dir operand -> HARD_DENY", tier(argv=["ls",".gnupg"]), broker.HARD_DENY)
check(".config/gcloud read -> HARD_DENY", tier(argv=["cat","/home/owner/.config/gcloud/creds.db"]), broker.HARD_DENY)
check("non-secret lookalike (.sshkeys) -> FREE_ZONE", tier(argv=["cat","/home/owner/proj/.sshkeys/note"]), broker.FREE_ZONE)
# --- audit-fix M1: new credential DIR zones (.docker/.kube/.config/rclone/.config/gh/.terraform.d) ---
check("cat ~/.docker/config.json -> HARD_DENY", tier(argv=["cat","/home/owner/.docker/config.json"]), broker.HARD_DENY)
check("cat ~/.kube/config -> HARD_DENY", tier(argv=["cat","/home/owner/.kube/config"]), broker.HARD_DENY)
check("cat ~/.config/rclone/rclone.conf -> HARD_DENY", tier(argv=["cat","/home/owner/.config/rclone/rclone.conf"]), broker.HARD_DENY)
check("cat ~/.config/gh/hosts.yml -> HARD_DENY", tier(argv=["cat","/home/owner/.config/gh/hosts.yml"]), broker.HARD_DENY)
check("ls under ~/.terraform.d -> HARD_DENY", tier(argv=["ls","/home/owner/.terraform.d/plugins"]), broker.HARD_DENY)
check("relative .docker/config operand -> HARD_DENY", tier(argv=["cat",".docker/config.json"]), broker.HARD_DENY)
# --- audit-fix M1: new secret BASENAMES (.npmrc, .pypirc) ---
check("cat ~/.npmrc -> HARD_DENY", tier(argv=["cat","/home/owner/.npmrc"]), broker.HARD_DENY)
check("cat ~/.pypirc -> HARD_DENY", tier(argv=["cat","/home/owner/.pypirc"]), broker.HARD_DENY)
check("cat bare .npmrc operand -> HARD_DENY", tier(argv=["cat",".npmrc"]), broker.HARD_DENY)
# --- audit-fix M1: .env is now a PREFIX rule (.env.local, .env.production, .env.* all secret) ---
check("write /srv/x/.env.local -> HARD_DENY", tier(argv=["tee","/srv/x/.env.local"]), broker.HARD_DENY)
check("read /srv/x/.env.local -> HARD_DENY", tier(argv=["cat","/srv/x/.env.local"]), broker.HARD_DENY)
check("read /srv/x/.env.production -> HARD_DENY", tier(argv=["cat","/srv/x/.env.production"]), broker.HARD_DENY)
check("cat bare .env.production operand -> HARD_DENY", tier(argv=["cat",".env.production"]), broker.HARD_DENY)
check("bare .env still secret -> HARD_DENY", tier(argv=["cat",".env"]), broker.HARD_DENY)
# negative: a NON-secret lookalike basename '.environment' must NOT match the .env prefix rule... but
# a prefix rule DOES match .environment (it startswith '.env'). We accept that as a conservative
# secret classification; assert the prefix behavior explicitly so it is a documented decision.
check("cat .environment (matches .env prefix, conservative) -> HARD_DENY", tier(argv=["cat","/srv/x/.environment"]), broker.HARD_DENY)

# --- HARD_DENY: sudo / root escalation ---
check("sudo -> HARD_DENY", tier(argv=["sudo","ls"]), broker.HARD_DENY)
check("pkexec -> HARD_DENY", tier(argv=["pkexec","ls"]), broker.HARD_DENY)
check("doas -> HARD_DENY", tier(argv=["doas","ls"]), broker.HARD_DENY)
check("su -> HARD_DENY", tier(argv=["su","-"]), broker.HARD_DENY)
check("chmod u+s (setuid) -> HARD_DENY", tier(argv=["chmod","u+s","f"]), broker.HARD_DENY)
check("chmod 4755 (numeric setuid) -> HARD_DENY", tier(argv=["chmod","4755","f"]), broker.HARD_DENY)
check("chmod g+s (setgid) -> HARD_DENY", tier(argv=["chmod","g+s","f"]), broker.HARD_DENY)
check("sudo wrapping a HARDLINE still denied (>= HARD_DENY)", tier(argv=["sudo","rm","-rf","/"]), broker.HARD_DENY)

# --- HARD_DENY: persistence ---
check("crontab -e -> HARD_DENY", tier(argv=["crontab","-e"]), broker.HARD_DENY)
check("at -> HARD_DENY", tier(argv=["at","now"]), broker.HARD_DENY)
check("systemctl enable -> HARD_DENY", tier(argv=["systemctl","enable","x"]), broker.HARD_DENY)
check("write to ~/.bashrc -> HARD_DENY", tier(argv=["tee","/home/owner/.bashrc"]), broker.HARD_DENY)
check("touch ~/.bashrc (persistence path) -> HARD_DENY", tier(argv=["touch","/home/owner/.bashrc"]), broker.HARD_DENY)
check("write under /etc -> HARD_DENY", tier(argv=["tee","/etc/hosts"]), broker.HARD_DENY)
check("~/.config/autostart -> HARD_DENY", tier(argv=["touch","/home/owner/.config/autostart/x.desktop"]), broker.HARD_DENY)
# persistence is a WRITE threat: a bare read-only inspector READING a persistence config is NOT
# persistence (secret-zone reads are still caught by the secret check, which runs first).
check("cat ~/.bashrc (read, not write) -> FREE_ZONE not persistence", tier(argv=["cat","/home/owner/.bashrc"]), broker.FREE_ZONE)
check("cat /etc/hostname (non-secret read) -> FREE_ZONE not persistence", tier(argv=["cat","/etc/hostname"]), broker.FREE_ZONE)
# --- audit-fix M2-floor: new shell/login rc persistence write-targets ---
check("write ~/.zshenv -> HARD_DENY", tier(argv=["tee","/home/owner/.zshenv"]), broker.HARD_DENY)
check("write ~/.zprofile -> HARD_DENY", tier(argv=["tee","/home/owner/.zprofile"]), broker.HARD_DENY)
check("write ~/.zlogin -> HARD_DENY", tier(argv=["tee","/home/owner/.zlogin"]), broker.HARD_DENY)
check("write ~/.zlogout -> HARD_DENY", tier(argv=["tee","/home/owner/.zlogout"]), broker.HARD_DENY)
check("write ~/.xsessionrc -> HARD_DENY", tier(argv=["tee","/home/owner/.xsessionrc"]), broker.HARD_DENY)
check("write ~/.xprofile -> HARD_DENY", tier(argv=["tee","/home/owner/.xprofile"]), broker.HARD_DENY)
check("write ~/.bash_logout -> HARD_DENY", tier(argv=["tee","/home/owner/.bash_logout"]), broker.HARD_DENY)
check("write ~/.bash_login -> HARD_DENY", tier(argv=["tee","/home/owner/.bash_login"]), broker.HARD_DENY)
check("touch ~/.zshenv (persistence path) -> HARD_DENY", tier(argv=["touch","/home/owner/.zshenv"]), broker.HARD_DENY)

# --- HARD_DENY: broker/approval-system's own files (reads too; BEATS FREE_ZONE) ---
check("cat broker audit.log -> HARD_DENY", tier(argv=["cat","/var/lib/hestia-broker/log/audit.log"]), broker.HARD_DENY)
check("ls broker spool -> HARD_DENY", tier(argv=["ls","/var/lib/hestia-spool"]), broker.HARD_DENY)
check("tail spool/incoming file -> HARD_DENY", tier(argv=["tail","/var/lib/hestia-spool/incoming/x.json"]), broker.HARD_DENY)
check("cat elevation key -> HARD_DENY", tier(argv=["cat","/etc/hestia-broker/elevation.key"]), broker.HARD_DENY)
check("broker root as cwd -> HARD_DENY", tier(cwd="/var/lib/hestia-broker", argv=["ls"]), broker.HARD_DENY)
# Negative: a NON-broker /var/lib path (and a sibling look-alike) stays FREE_ZONE.
check("cat /var/lib/other/x (non-broker) -> FREE_ZONE", tier(argv=["cat","/var/lib/other/x"]), broker.FREE_ZONE)
check("ls /var/lib/hestia-broker-notes (sibling look-alike) -> FREE_ZONE", tier(argv=["ls","/var/lib/hestia-broker-notes"]), broker.FREE_ZONE)

# --- HARD_DENY: rm -rf of a tree UNDER home (home ROOT itself is REFUSE; rm-rf-home) ---
check("rm -rf ~/proj (abs under home) -> HARD_DENY", tier(argv=["rm","-rf","/home/owner/proj"]), broker.HARD_DENY)
check("rm -rf ~/proj (literal tilde) -> HARD_DENY", tier(argv=["rm","-rf","~/proj"]), broker.HARD_DENY)
check("rm -rf /home/owner/a/b/c -> HARD_DENY", tier(argv=["rm","-rf","/home/owner/a/b/c"]), broker.HARD_DENY)
# home ROOT stays REFUSE (not HARD_DENY) — unapprovable by any button.
check("rm -rf /home/owner (home root) -> REFUSE", tier(argv=["rm","-rf","/home/owner"]), broker.REFUSE)
# relative / in-tree recursive deletes stay SOFT_DENY (no absolute home path).
check("rm -r ./localdir (relative in-tree) -> SOFT_DENY", tier(argv=["rm","-rf","./localdir"]), broker.SOFT_DENY)
check("rm -rf d (bare relative) -> SOFT_DENY", tier(argv=["rm","-rf","d"]), broker.SOFT_DENY)
check("rm f (plain) -> SOFT_DENY", tier(argv=["rm","f"]), broker.SOFT_DENY)

# --- ALLOW (reviewer middle): inline interpreters (MOVED here from HARD_DENY) ---
check("python3 -c -> ALLOW (reviewer middle)", tier(argv=["python3","-c","print(1)"]), broker.ALLOW)
check("bash -c -> ALLOW (reviewer middle)", tier(argv=["bash","-c","echo hi"]), broker.ALLOW)
check("node -e -> ALLOW (reviewer middle)", tier(argv=["node","-e","1"]), broker.ALLOW)

# --- ALLOW (reviewer middle): path-invoked binaries / project scripts ---
check("./build.sh -> ALLOW (path-invoked)", tier(argv=["./build.sh"]), broker.ALLOW)
check("node_modules/.bin/eslint -> ALLOW", tier(argv=["node_modules/.bin/eslint","f"]), broker.ALLOW)
check("python3 script.py -> ALLOW (path-invoked file)", tier(argv=["python3","script.py"]), broker.ALLOW)

# --- ALLOW (reviewer middle): inbound git ---
check("git fetch -> ALLOW", tier(argv=["git","fetch"]), broker.ALLOW)
check("git clone -> ALLOW", tier(argv=["git","clone","url"]), broker.ALLOW)
check("git pull -> ALLOW", tier(argv=["git","pull"]), broker.ALLOW)

# --- ALLOW: non-clobber writers + read-only git ---
check("mkdir -> ALLOW", tier(argv=["mkdir","d"]), broker.ALLOW)
check("touch f -> ALLOW", tier(argv=["touch","f"]), broker.ALLOW)
check("git status -> ALLOW", tier(argv=["git","status"]), broker.ALLOW)
check("git diff -> ALLOW", tier(argv=["git","diff"]), broker.ALLOW)
check("git log -> ALLOW", tier(argv=["git","log"]), broker.ALLOW)

# --- SOFT_DENY (destructive but recoverable; reviewer unlocks same-op-same-target) ---
check("sed -i (in-place overwrite) -> SOFT_DENY", tier(argv=["sed","-i","s/a/b/","f"]), broker.SOFT_DENY)
# GNU sed long synonym --in-place (and --in-place=SUFFIX) must also be SOFT_DENY, not ALLOW.
check("sed --in-place (GNU long form) -> SOFT_DENY", tier(argv=["sed","--in-place","s/a/b/","f"]), broker.SOFT_DENY)
check("sed --in-place=.bak (glued suffix) -> SOFT_DENY", tier(argv=["sed","--in-place=.bak","s/a/b/","f"]), broker.SOFT_DENY)
check("rm f -> SOFT_DENY", tier(argv=["rm","f"]), broker.SOFT_DENY)
check("rmdir d -> SOFT_DENY", tier(argv=["rmdir","d"]), broker.SOFT_DENY)
check("find . -delete -> SOFT_DENY", tier(argv=["find",".","-delete"]), broker.SOFT_DENY)
check("git reset --hard -> SOFT_DENY", tier(argv=["git","reset","--hard"]), broker.SOFT_DENY)
# Leading git global options/values must NOT defeat SOFT_DENY detection (positional-sub bug).
check("git -c x=y reset --hard -> SOFT_DENY", tier(argv=["git","-c","x=y","reset","--hard"]), broker.SOFT_DENY)
check("git -C /repo reset --hard -> SOFT_DENY", tier(argv=["git","-C","/repo","reset","--hard"]), broker.SOFT_DENY)
check("git --git-dir=x clean -fd -> SOFT_DENY", tier(argv=["git","--git-dir=x","clean","-fd"]), broker.SOFT_DENY)
check("git clean -fd -> SOFT_DENY", tier(argv=["git","clean","-fd"]), broker.SOFT_DENY)
check("mv a b -> SOFT_DENY (overwrite)", tier(argv=["mv","a","b"]), broker.SOFT_DENY)
check("cp a b -> SOFT_DENY (overwrite)", tier(argv=["cp","a","b"]), broker.SOFT_DENY)
check("chmod -> SOFT_DENY", tier(argv=["chmod","644","f"]), broker.SOFT_DENY)
check("chown -> SOFT_DENY", tier(argv=["chown","owner","f"]), broker.SOFT_DENY)
check("ln -s -> SOFT_DENY", tier(argv=["ln","-s","a","b"]), broker.SOFT_DENY)

# --- FREE_ZONE (auto, no LLM): read-only inspector on a NON-secret path, ANYWHERE ---
check("ls f -> FREE_ZONE", tier(argv=["ls","f"]), broker.FREE_ZONE)
check("cat f -> FREE_ZONE", tier(argv=["cat","notes/readme.md"]), broker.FREE_ZONE)
check("grep p f -> FREE_ZONE", tier(argv=["grep","TODO","f"]), broker.FREE_ZONE)
# /srv/projects containment retired: read-only inspector on a NON-secret path OUTSIDE the old
# workspace is FREE_ZONE now (this is the behavioral change from the old 3-way classifier).
check("ls in /home/owner (workspace retired) -> FREE_ZONE", tier(cwd="/home/owner", argv=["ls"]), broker.FREE_ZONE)
check("cat under /tmp (non-secret, outside workspace) -> FREE_ZONE", tier(argv=["cat","/tmp/x.log"]), broker.FREE_ZONE)

# --- Negative FREE_ZONE rows: prove the floor runs FIRST (FREE_ZONE never short-circuits it) ---
check("find . -delete beats FREE_ZONE (find is a FREE_BINARY) -> SOFT_DENY", tier(argv=["find",".","-delete"]), broker.SOFT_DENY)
check("cat of a secret beats FREE_ZONE -> HARD_DENY", tier(argv=["cat","/home/owner/.ssh/id_rsa"]), broker.HARD_DENY)
check("grep in secret-zone beats FREE_ZONE -> HARD_DENY", tier(argv=["grep","x","/home/owner/.aws/credentials"]), broker.HARD_DENY)

# --- policy_tier is a PURE function of {argv, cwd}: the TIER must NOT depend on `elevate` (confined-
# by-PATH: an escalation-lever command (elevate=True) and an ordinary auto command (elevate=False) with
# the SAME argv/cwd MUST yield the SAME tier). Regression for the elevate-leak where FREE_ZONE reuse of
# classify() let elevate=True fall through to ALLOW. NOTE: classify()'s OWN default (elevate=True ->
# NEEDS_BUTTON) is UNCHANGED — the legacy per-command button path depends on it (row "elevate+ls" above);
# only policy_tier's tier is elevate-independent. ---
check("FREE_ZONE ls f is elevate-independent (elevate=False)", tier(elevate=False, argv=["ls","f"]), broker.FREE_ZONE)
check("FREE_ZONE ls f is elevate-independent (elevate=True)",  tier(elevate=True,  argv=["ls","f"]), broker.FREE_ZONE)
check("FREE_ZONE cat notes.md elevate-independent (elevate=False)", tier(elevate=False, argv=["cat","notes.md"]), broker.FREE_ZONE)
check("FREE_ZONE cat notes.md elevate-independent (elevate=True)",  tier(elevate=True,  argv=["cat","notes.md"]), broker.FREE_ZONE)
check("REFUSE rm -rf / unchanged by elevate=True", tier(elevate=True, argv=["rm","-rf","/"]), broker.REFUSE)
check("HARD_DENY scp unchanged by elevate=True", tier(elevate=True, argv=["scp","f","host:"]), broker.HARD_DENY)
check("SOFT_DENY rm f unchanged by elevate=True", tier(elevate=True, argv=["rm","f"]), broker.SOFT_DENY)

# --- hard_deny_reason(): the owner-button "Floor:" label mirrors the HARD_DENY rule that fired ---
print("== hard_deny_reason: owner-button label mirrors the HARD_DENY category ==")
def hdr(**kw):
    return broker.hard_deny_reason(req(**kw))
check("egress reason", hdr(argv=["scp","f","host:"]).startswith("EGRESS"), True)
check("root reason", hdr(argv=["sudo","ls"]).startswith("SUDO/ROOT"), True)
check("secrets reason", hdr(argv=["cat","/home/owner/.ssh/id_rsa"]).startswith("SECRETS"), True)
check("broker-files reason", hdr(argv=["cat","/var/lib/hestia-spool/x"]).startswith("BROKER-FILES"), True)
check("persistence reason", hdr(argv=["tee","/etc/hosts"]).startswith("PERSISTENCE"), True)
check("rm-rf reason", hdr(argv=["rm","-rf","/home/owner/proj"]).startswith("RM-RF"), True)
check("non-HARD_DENY command -> empty reason", hdr(argv=["ls","f"]), "")

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

print("== control ops (session_open / session_close) ==")
def sopen(**kw):
    base = {"v": 1, "session_id": SID, "request_id": RID, "kind": "session_open",
            "intent": "run the test suite", "duration_secs": 1800}
    base.update(kw); return base
def sclose(**kw):
    base = {"v": 1, "session_id": SID, "request_id": RID, "kind": "session_close"}
    base.update(kw); return base
def vok(name, r):
    global npass, nfail
    try:
        out = broker.validate_request(json.dumps(r).encode(), r["request_id"])
        if out == r: npass += 1; print(f"  PASS: {name} -> accepted+echoed")
        else: nfail += 1; print(f"  FAIL: {name}: echo mismatch got {out!r}")
    except broker.Reject as e:
        nfail += 1; print(f"  FAIL: {name}: unexpected REJECT ({e})")

# --- accepted + echoed ---
vok("session_open valid", sopen())
vok("session_open intent len 1", sopen(intent="x"))
vok("session_open intent len 500", sopen(intent="a"*500))
vok("session_open dur 1", sopen(duration_secs=1))
vok("session_open dur 86400", sopen(duration_secs=86400))
vok("session_open dur above 24h (no ceiling)", sopen(duration_secs=100000))
vok("session_close valid", sclose())
vok("plain command still validates", req(argv=["ls","-la"]))
vok("command with kind:command still validates", {**req(argv=["ls"]), "kind": "command"})

# --- session_open rejects ---
vrej("intent empty", sopen(intent=""))
vrej("intent 501 chars", sopen(intent="a"*501))
vrej("intent has NUL", sopen(intent="a\x00b"))
vrej("intent non-str", sopen(intent=5))
vrej("dur 0", sopen(duration_secs=0))
vrej("dur negative", sopen(duration_secs=-1))
vrej("dur bool true", sopen(duration_secs=True))
vrej("dur str '5'", sopen(duration_secs="5"))
vrej("session_open missing intent", {k:v for k,v in sopen().items() if k!="intent"})
vrej("session_open missing duration", {k:v for k,v in sopen().items() if k!="duration_secs"})
vrej("session_open extra key", {**sopen(), "argv":["ls"]})
vrej("session_open bad version", sopen(v=2))
vrej("session_open non-uuid rid", {**sopen(), "request_id":"nope"})
vrej("session_open anti-swap", sopen(), eid="33333333-3333-4333-8333-333333333333")

# --- session_close rejects ---
vrej("session_close extra key (intent)", {**sclose(), "intent":"x"})
vrej("session_close missing kind treated as command", {k:v for k,v in sclose().items() if k!="kind"})
vrej("session_close bad version", sclose(v=2))

# --- unknown kind ---
vrej("unknown kind", {**req(argv=["ls"]), "kind":"teleport"})

# --- command with an extra key (regression: kind-aware allowed-set) ---
vrej("command extra key intent", {**req(argv=["ls"]), "intent":"x"})

print(f"\nRESULT: {npass} passed, {nfail} failed")
sys.exit(0 if nfail == 0 else 1)
