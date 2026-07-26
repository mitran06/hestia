#!/usr/bin/env python3
"""broker.py — Hestia capability broker (schema + canon + policy_tier floor + audit).

Runs as user `hestia-broker` (NO lxd/docker/sudo; holds policy + later the 2nd-bot token).
This module is the POLICY BRAIN only — NO Telegram, NO SSH, NO execution:

  request(JSON from box) --validate--> --canonicalize(length-prefixed)--> cmd_hash(sha256)
                                    --policy_tier--> {REFUSE|HARD_DENY|FREE_ZONE|SOFT_DENY|ALLOW}
                                    --> append-only audit log (chattr +a)

Security stance: the deterministic FLOOR (policy_tier) is the sole floor authority, evaluated in
STRICT priority order REFUSE > HARD_DENY > FREE_ZONE > SOFT_DENY > ALLOW on EVERY command. FREE_ZONE
auto-runs a bare read-only allowlisted inspector on a non-secret path; the reviewer middle
(SOFT_DENY/ALLOW) is an advisory tightening layer above the floor (brokerd). Malformed input is REJECT.

NOTE: the AUTHORITATIVE workspace-containment check is realpath-on-the-target (target/exec-argv); the
cwd/arg checks here are a lexical FIRST gate. Session lifecycle + Telegram approval live in brokerd.
"""
import json, hashlib, struct, os, sys, re, time

WORKSPACE      = "/srv/projects"          # the target free zone (paths refer to the target)
MAXSIZE        = 65536                     # 64 KiB, matches the mover cap
SCHEMA_VERSION = 1
MAX_ARGV       = 256                       # cap argv length
MAX_ARG_LEN    = 8192                      # cap a single arg
MAX_INTENT     = 500                       # cap session intent text (there is NO duration ceiling)
AUDIT_LOG      = os.environ.get("HESTIA_AUDIT", "/var/lib/hestia-broker/log/audit.log")
UUID_RE        = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

IN_SCOPE, NEEDS_BUTTON, REJECT = "IN_SCOPE", "NEEDS_BUTTON", "REJECT"

# ---------------------------------------------------------------------------------------------
# Layer 1 — policy_tier() deterministic floor tiers. Sole floor authority; evaluated in STRICT
# priority order on EVERY command:  REFUSE > HARD_DENY > FREE_ZONE > SOFT_DENY > ALLOW
# ---------------------------------------------------------------------------------------------
REFUSE, HARD_DENY, FREE_ZONE, SOFT_DENY, ALLOW = "REFUSE", "HARD_DENY", "FREE_ZONE", "SOFT_DENY", "ALLOW"

# SECRET_ZONES — the single source-of-truth set of credential/secret ZONE directories (home-relative,
# leading-'.'; also consumed by the bwrap secret mask). Any operand or cwd that lexically touches one
# of these directories -> HARD_DENY (reads too; BEATS FREE_ZONE). Browser profiles / keychains /
# wallets are covered by the broader home-dotfile posture + confinement; this set is the lexical
# floor's directory zones. Secret FILE patterns (basename) are matched separately below.
SECRET_ZONES = frozenset({
    ".ssh", ".aws", ".gnupg", ".config/gcloud",
    # audit-fix M1: credential DIR zones (Docker registry creds, kube contexts, rclone remotes,
    # gh OAuth tokens, terraform provider creds). Multi-segment zones (.config/rclone, .config/gh)
    # match as a whole path segment via _SECRET_DIR_FRAGMENTS, same as .config/gcloud.
    ".docker", ".kube", ".config/rclone", ".config/gh", ".terraform.d",
})
# Derived: a secret-zone directory is matched as a full path segment anywhere in a token — i.e. the
# token contains '/<zone>/' or ends in '/<zone>'. Derive the match fragments from SECRET_ZONES so it
# stays the one source of truth.
_SECRET_DIR_FRAGMENTS = tuple("/" + z for z in SECRET_ZONES)
# Basename patterns (final path segment) that mark a secret FILE (credential/secret zones).
# audit-fix M1: added .npmrc/.pypirc (registry auth tokens); .env moved from EXACT to a PREFIX rule
# (below) so .env, .env.local, .env.production, .env.* all match. Kept .netrc/.git-credentials.
_SECRET_BASENAME_EXACT = frozenset({".netrc", ".git-credentials", ".npmrc", ".pypirc"})
_SECRET_BASENAME_SUFFIX = (".pem", ".key")
_SECRET_BASENAME_PREFIX = ("id_", ".env")   # ".env" prefix -> .env / .env.local / .env.production / .env.*

# BROKER_PATHS — the single source-of-truth set of the broker/approval system's OWN files
# (broker/spool/audit/elevation paths). Any operand or cwd that lexically touches one of these
# directory roots -> HARD_DENY (reads too — the append-only audit trail, the spool, and the
# elevation HMAC key material must never reach the confined auto path with no LLM and no human tap).
# Derived so it tracks config: the audit-log root is `os.path.dirname(AUDIT_LOG)`'s parent (AUDIT_LOG
# lives at <root>/log/audit.log), plus the spool root and the elevation-key dir. Kept as explicit
# roots (not re-derived per-request) so a config override of AUDIT_LOG still yields its broker root.
_BROKER_ROOT_DEFAULTS = ("/var/lib/hestia-broker", "/etc/hestia-broker")


def _broker_roots():
    # Always cover the canonical deployed broker roots (the floor must protect the LIVE broker files
    # even under a test-time HESTIA_AUDIT override that points the log elsewhere).
    roots = {os.path.normpath(r) for r in _BROKER_ROOT_DEFAULTS}
    # Also cover a config-overridden audit tree, but ONLY when it fits the deployed <root>/log/<file>
    # shape — otherwise a test override like /tmp/hestia-test-audit.log would wrongly enroll /tmp.
    log_dir = os.path.dirname(os.path.normpath(AUDIT_LOG))        # .../hestia-broker/log
    if os.path.basename(log_dir) == "log":
        roots.add(os.path.dirname(log_dir))
    # Spool root (brokerd owns the live path; mirror the deployed default so the floor covers it even
    # though broker.py must not import brokerd — that would be circular).
    roots.add(os.path.normpath(os.environ.get("HESTIA_SPOOL", "/var/lib/hestia-spool")))
    elev = os.environ.get("HESTIA_ELEVATION_KEY_FILE", "/etc/hestia-broker/elevation.key")
    roots.add(os.path.dirname(os.path.normpath(elev)))            # /etc/hestia-broker
    return frozenset(roots)

BROKER_PATHS = _broker_roots()

# HARDLINE (REFUSE — unapprovable by any button). argv[0] basenames that are always catastrophic,
# plus the rm -rf-root / mkfs / shutdown-family patterns checked contextually below.
_HARDLINE_CMDS = frozenset({
    "shutdown", "reboot", "halt", "poweroff", "init", "telinit",
})
_MKFS_PREFIX = "mkfs"                     # mkfs, mkfs.ext4, mkfs.xfs, ...

# OUTBOUND egress binaries (HARD_DENY). Effect = send bytes off-box. Inbound git (fetch/clone/pull)
# is NOT here — it is reviewer middle. `git push` is handled contextually below.
_EGRESS_CMDS = frozenset({
    "scp", "sftp", "rsync", "ftp", "tftp", "telnet", "nc", "ncat", "netcat", "socat",
})
# curl/wget become egress on an upload; conservatively treated as OUTBOUND egress here (a fooled
# download is not the residual we defend — exfil is).
_EGRESS_UPLOAD_CMDS = frozenset({"curl", "wget"})

# sudo/root escalation (HARD_DENY).
_ROOT_CMDS = frozenset({"sudo", "doas", "pkexec", "su", "runuser"})

# Persistence binaries (HARD_DENY). systemctl is contextual (poweroff/reboot -> REFUSE).
_PERSISTENCE_CMDS = frozenset({"crontab", "at", "batch"})

# Persistence WRITE-TARGET path fragments (rc/profile, autostart, systemd-user units, environment.d,
# /etc). A command whose operand touches one of these is persistence -> HARD_DENY.
_PERSISTENCE_PATH_FRAGMENTS = (
    "/.bashrc", "/.zshrc", "/.profile", "/.bash_profile", "/.bash_login", "/.zprofile",
    # audit-fix M2-floor: remaining shell/login rc + logout hooks (each runs code at shell/login).
    "/.zshenv", "/.zlogin", "/.zlogout", "/.xsessionrc", "/.xprofile", "/.bash_logout",
    "/.config/autostart", "/.config/systemd/user", "/.config/environment.d",
    "/etc/",
)
# Documented residual: if $ZDOTDIR is set, zsh reads its rc files from $ZDOTDIR (not ~), so a write
# there would evade this lexical floor. The floor deliberately keys on the STANDARD ~ paths above;
# a non-default $ZDOTDIR write is a known residual, backstopped by confinement and the reviewer
# middle — it is not a bare read-only FREE_ZONE inspector, so it does not auto-run.

# SOFT_DENY (destructive but recoverable; reviewer unlocks same-op-same-target).
_SOFTDENY_CMDS = frozenset({
    "rm", "rmdir", "mv", "cp", "chmod", "chown", "ln", "shred", "truncate",
})

# Inline-interpreter forms: an interpreter basename + an inline-code flag => reviewer middle (ALLOW;
# confinement backstops egress). Invoking a named FILE is NOT here (that is path-invoked, also
# reviewer middle).
_INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "dash", "ksh", "python", "python2", "python3", "node", "nodejs",
    "perl", "ruby", "php", "lua", "deno", "bun",
})
_INLINE_FLAGS = frozenset({"-c", "-e", "--eval", "-E", "--exec"})
# NOTE: read-only git (status/diff/log/show) and inbound git (fetch/clone/pull) need no explicit
# membership set — they are neither egress (`push`), soft-deny (`reset --hard`/`clean -f`/…), nor a
# FREE_BINARY, so they fall through to the ALLOW catch-all (the reviewer middle).

# Free-zone = pure READ-ONLY inspectors. Deliberately EXCLUDES: git (arbitrary code exec via
# .git/config/hooks), ALL interpreters/shells (bash sh python node perl ruby awk...), env, and
# anything that writes/execs. Also EXCLUDED after review: `rg` (--pre=CMD executes arbitrary
# programs), `sort` (-o/--output= writes arbitrary files). Per-repo "recipes" are a later feature.
FREE_BINARIES = frozenset({
    "ls", "cat", "head", "tail", "wc", "stat", "file", "find", "grep", "egrep", "fgrep",
    "tree", "pwd", "du", "diff", "uniq", "cut", "basename", "dirname",
    "realpath", "echo", "date", "uname", "sha256sum", "md5sum", "cksum", "nl", "column",
})   # EXCLUDES df/id: zero-operand commands whose scope check is a no-op and that report GLOBAL
     # host state (df = full target mount table; id = agent identity) -> host-recon leak. Button them.
# `find` (unusual word-flag CLI) is handled specially: block primaries that write/exec/delete.
FIND_DANGEROUS = frozenset({
    "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls",
})
# STRICT flag policy for the auto-run path: a binary NOT listed here allows NO flags (any '-' token
# -> button). Short-flag clusters (e.g. -la) are OK iff every letter is in the set. Long flags must
# be listed in SAFE_LONG. ANY '=' token, '@' token, glued path, or unlisted flag -> NEEDS_BUTTON.
# This neutralizes flag-taking-a-path/command (rg --pre, sort -o, grep -f, --opt=/abs) regardless of
# the binary. Value-bearing flags must be passed as SEPARATE tokens (e.g. `-n 5`, not `-n5`).
SAFE_SHORT = {
    "ls": set("lahRtrS1dFi"), "cat": set("AnbETv"),
    "head": set("nc"), "tail": set("nc"),           # NOT -f (would hang the relay session)
    "wc": set("lwcmL"),
    "grep": set("rRnilLcwxvEFHoqes"), "egrep": set("rRnilLcwxvHoqes"), "fgrep": set("rRnilLcwxvHoqes"),  # NOT -f (reads arbitrary file)
    "stat": set("cLt"), "file": set("biL"),
    "du": set("shabckm"),
    "tree": set("adLC"), "diff": set("urqiwbN"),
    "uniq": set("cdui"), "cut": set("bcfds"),
    "nl": set("ba"), "column": set("tx"),
}
SAFE_LONG = {
    "ls": {"--color", "--group-directories-first", "--almost-all"},
    "grep": {"--color", "--recursive", "--line-number", "--ignore-case", "--with-filename"},
}


class Reject(Exception):
    """Raised for malformed/hostile input that fails schema validation."""


def _reject_keys(req: dict, allowed: set):
    """Raise Reject if req has any key outside `allowed` OR is missing any key in `allowed`."""
    keys = set(req)
    extra = keys - allowed
    if extra:
        raise Reject(f"unexpected keys: {sorted(extra)}")
    if keys != allowed:
        raise Reject(f"missing keys: {sorted(allowed - keys)}")


def _check_ids(req: dict, expected_id):
    """Shared identity checks: schema version, UUID ids, anti-swap against the filename id."""
    if req["v"] != SCHEMA_VERSION:
        raise Reject(f"bad schema version {req['v']!r}")
    for k in ("session_id", "request_id"):
        if not isinstance(req[k], str) or not UUID_RE.match(req[k]):
            raise Reject(f"{k} is not a UUID")
    if expected_id is not None and req["request_id"] != expected_id:
        raise Reject(f"request_id {req['request_id']} != filename {expected_id} (anti-swap)")


def validate_request(raw: bytes, expected_id):
    """Parse + strictly validate the request bytes. Returns the request dict or raises Reject.

    Dispatches on req['kind']: absent/'command' -> command schema; 'session_open' / 'session_close'
    -> control schemas. classify/cmd_hash are NEVER run on control ops (brokerd routes them first).
    """
    if len(raw) > MAXSIZE:
        raise Reject(f"oversize request ({len(raw)} > {MAXSIZE})")
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Reject(f"not valid utf-8 JSON: {e}")
    if not isinstance(req, dict):
        raise Reject("top-level JSON is not an object")

    kind = req.get("kind", "command")
    if kind == "command":
        allowed = {"v", "session_id", "request_id", "cwd", "elevate", "argv"}
        if "kind" in req:
            allowed.add("kind")            # kind is optional for commands; == "command" here
        _reject_keys(req, allowed)
        _check_ids(req, expected_id)
        if not isinstance(req["cwd"], str) or "\x00" in req["cwd"] or not req["cwd"].startswith("/"):
            raise Reject("cwd must be an absolute NUL-free string")
        if not isinstance(req["elevate"], bool):
            raise Reject("elevate must be a boolean")
        argv = req["argv"]
        if not isinstance(argv, list) or not argv or len(argv) > MAX_ARGV:
            raise Reject("argv must be a non-empty list within length cap")
        for a in argv:
            if not isinstance(a, str):
                raise Reject("argv entries must be strings")
            if "\x00" in a:
                raise Reject("argv entry contains NUL")
            if len(a) > MAX_ARG_LEN:
                raise Reject("argv entry too long")
        return req

    if kind == "session_open":
        _reject_keys(req, {"v", "session_id", "request_id", "kind", "intent", "duration_secs"})
        _check_ids(req, expected_id)
        intent = req["intent"]
        if not isinstance(intent, str) or not (1 <= len(intent) <= MAX_INTENT):
            raise Reject(f"intent must be a str of length 1..{MAX_INTENT}")
        if "\x00" in intent:
            raise Reject("intent contains NUL")
        d = req["duration_secs"]
        if isinstance(d, bool) or not isinstance(d, int):
            raise Reject("duration_secs must be an int")
        if d < 1:                                   # positive only; NO upper bound (expiry+Revoke are the backstop)
            raise Reject("duration_secs must be a positive int (>= 1)")
        return req

    if kind == "session_close":
        _reject_keys(req, {"v", "session_id", "request_id", "kind"})
        _check_ids(req, expected_id)
        return req

    raise Reject(f"unknown kind {kind!r}")


def _lp(b: bytes) -> bytes:
    """Length-prefix a byte string (4-byte big-endian length). Blocks delimiter/NUL ambiguity."""
    return struct.pack(">I", len(b)) + b


def canonicalize(req: dict) -> bytes:
    """Deterministic, unambiguous byte encoding of the security-relevant fields."""
    out = b"HESTIA-CANON-v1"
    out += _lp(req["session_id"].encode("utf-8"))
    out += _lp(req["request_id"].encode("utf-8"))
    out += _lp(req["cwd"].encode("utf-8"))
    out += _lp(b"1" if req["elevate"] else b"0")
    out += struct.pack(">I", len(req["argv"]))
    for a in req["argv"]:
        out += _lp(a.encode("utf-8"))
    return out


def cmd_hash(req: dict) -> str:
    return hashlib.sha256(canonicalize(req)).hexdigest()


def _within(path: str, base: str) -> bool:
    """Lexical containment (normpath collapses '..'); NOT symlink-resolved (that's target-side)."""
    np, nb = os.path.normpath(path), os.path.normpath(base)
    return np == nb or np.startswith(nb + os.sep)


def _operand_ok(a: str, workspace=WORKSPACE) -> bool:
    """A non-flag token must be a safe read operand (no argfile, no '..'). When `workspace` is a path
    the operand must also be lexically inside it (legacy classify() gate); when `workspace` is None
    the containment check is skipped (policy_tier's workspace-free FREE_ZONE determination)."""
    if a.startswith("@"):
        return False
    if ".." in a.split("/"):
        return False
    if workspace is not None and a.startswith("/") and not _within(a, workspace):
        return False
    return True


def _arg_ok_freezone(cmd: str, a: str, workspace=WORKSPACE) -> bool:
    """Strict per-arg gate for the auto-run path. Flags must be explicitly safe; no glued paths."""
    if a in ("-", "--") or not a.startswith("-"):
        return _operand_ok(a, workspace)
    # a is a flag token
    if "=" in a:
        return False                                   # blocks --opt=/abs, --pre=CMD, --output=FILE
    if a.startswith("--"):
        return a in SAFE_LONG.get(cmd, set())
    letters = a[1:]                                     # short cluster, e.g. -la ; also blocks -f/etc (‘/’ not a letter)
    return bool(letters) and all(c in SAFE_SHORT.get(cmd, set()) for c in letters)


def classify(req: dict, workspace=WORKSPACE):
    """Return (decision, reason). DEFAULT-DENY-TO-BUTTON.

    `workspace` is the lexical containment boundary. Default `WORKSPACE` preserves the legacy
    /srv/projects gate (the legacy button path depends on it). `policy_tier()` calls with
    `workspace=None` to reuse ONLY the read-only-inspector determination WITHOUT the /srv/projects
    containment (retired as a scope boundary)."""
    if req["elevate"]:
        return NEEDS_BUTTON, "elevation requested"
    argv = req["argv"]
    cmd = argv[0]
    if "/" in cmd:
        return NEEDS_BUTTON, "argv[0] is a path, not a bare allowlisted command"
    if cmd not in FREE_BINARIES:
        return NEEDS_BUTTON, f"'{cmd}' not in free-zone read-only allowlist"
    if workspace is not None and not _within(req["cwd"], workspace):
        return NEEDS_BUTTON, f"cwd {req['cwd']!r} outside workspace {workspace} (lexical)"
    if cmd == "find":
        # find has a word-flag CLI; block write/exec primaries + out-of-workspace/argfile operands.
        for a in argv[1:]:
            if a in FIND_DANGEROUS:
                return NEEDS_BUTTON, f"find with dangerous action {a}"
            if not _operand_ok(a, workspace) and not a.startswith("-"):
                return NEEDS_BUTTON, f"find operand not workspace-safe: {a!r}"
            if workspace is not None and a.startswith("/") and not _within(a, workspace):
                return NEEDS_BUTTON, f"find path arg outside workspace: {a!r}"
        return IN_SCOPE, "free-zone find within workspace"
    for a in argv[1:]:
        if not _arg_ok_freezone(cmd, a, workspace):
            return NEEDS_BUTTON, f"arg not free-zone-safe for {cmd}: {a!r}"
    return IN_SCOPE, "free-zone read-only command within workspace"


# =============================================================================================
# Layer 1 — policy_tier(): the deterministic floor (sole authority).
# =============================================================================================
def _basename(p: str) -> str:
    """Final path segment (lexical; matches bwrap/argv basename semantics)."""
    return p.rsplit("/", 1)[-1]


def _touches_secret_zone(tok: str) -> bool:
    """True if a token (operand or cwd) lexically touches a SECRET_ZONES path — reads too.
    Matches a zone dir as a full path SEGMENT: absolute (`/home/u/.ssh/…`), relative
    (`.ssh/config`), or the bare dir. normpath collapses `..` so `../../.ssh` still matches."""
    if tok.startswith("@"):
        tok = tok[1:]
    np = os.path.normpath(tok)
    # Pad both ends with '/' so a zone matches as a whole segment at the start, middle, or end.
    padded = "/" + np + "/"
    for frag in _SECRET_DIR_FRAGMENTS:                # frag = '/.ssh', match '/.ssh/' as a segment
        if frag + "/" in padded:
            return True
    base = _basename(np)
    if base in _SECRET_BASENAME_EXACT:
        return True
    if any(base.endswith(sfx) for sfx in _SECRET_BASENAME_SUFFIX):
        return True
    if any(base.startswith(pfx) for pfx in _SECRET_BASENAME_PREFIX):
        return True
    return False


def _touches_persistence(tok: str) -> bool:
    """True if a token lexically touches a persistence write-target (rc/profile/autostart/etc).
    Matches a fragment as a whole path segment (absolute, relative, or bare-dir)."""
    if tok.startswith("@"):
        tok = tok[1:]
    np = os.path.normpath(tok)
    padded = "/" + np + "/"
    for frag in _PERSISTENCE_PATH_FRAGMENTS:
        f = frag if frag.endswith("/") else frag + "/"
        if f in padded:
            return True
    return False


def _touches_broker_files(tok: str) -> bool:
    """True if a token (operand or cwd) lexically touches a BROKER_PATHS root — reads too
    (broker/spool/audit/elevation paths). Matches a broker root as a whole path SEGMENT so a
    look-alike sibling (e.g. /var/lib/hestia-broker-notes) does NOT match. normpath collapses `..`."""
    if tok.startswith("@"):
        tok = tok[1:]
    np = os.path.normpath(tok)
    for root in BROKER_PATHS:
        r = os.path.normpath(root)
        if np == r or np.startswith(r + os.sep):
            return True
    return False


# Home root — the retired /srv/projects workspace boundary is now vacuous, so a recursive+force
# delete of ANY tree under home is HARD_DENY (rm-rf-home: "recursive/forced delete rooted at ~
# or outside the workspace"). The home ROOT itself stays REFUSE (see _is_refuse). Derived from $HOME;
# matched as a whole path segment. If `~` is unresolvable the value is empty and _is_rm_rf_home
# simply matches nothing extra (the other REFUSE rules still hold).
HOME_ROOT = os.path.normpath(os.environ.get("HESTIA_HOME_ROOT", os.path.expanduser("~")))


def _rm_recursive_force(rest):
    """(recursive, force) flags for an rm argv tail — shared by REFUSE + rm-rf-home HARD_DENY."""
    flags = "".join(a[1:] for a in rest if a.startswith("-") and not a.startswith("--"))
    recursive = ("r" in flags or "R" in flags or "--recursive" in rest)
    force = ("f" in flags or "--force" in rest)
    return recursive, force


def _is_refuse(argv) -> bool:
    """HARDLINE (unapprovable). rm -rf /|system|home-root, mkfs, dd->block device, kill -1/init,
    shutdown/reboot/halt/poweroff, init 0/6, systemctl poweroff/reboot, telinit."""
    cmd = _basename(argv[0])
    rest = argv[1:]
    if cmd in _HARDLINE_CMDS:
        return True
    if cmd == "systemctl" and any(a in ("poweroff", "reboot", "halt", "kexec") for a in rest):
        return True
    if cmd.startswith(_MKFS_PREFIX):
        return True
    # dd writing to a block device -> HARDLINE (destroys the disk; unapprovable).
    if cmd == "dd" and any(a.startswith("of=/dev/") for a in rest):
        return True
    # kill/killall of PID 1 (init) with SIGHUP/SIGKILL -> local DoS, unapprovable.
    # (The classic `:(){ :|:& };:` fork bomb arrives as a shell STRING, not argv, so it is out of
    # policy_tier's argv scope — it is caught as an inline-interpreter -> reviewer middle, not here.)
    if cmd in ("kill", "killall"):
        sig_init = any(a in ("-1", "-9", "-HUP", "-KILL", "-SIGHUP", "-SIGKILL") for a in rest)
        if sig_init and any(a == "1" for a in rest):
            return True
    if cmd == "rm":
        # rm -rf / (or a system/home ROOT). recursive+force rooted at '/', '/home', '~' or a home root.
        recursive, force = _rm_recursive_force(rest)
        if recursive and force:
            for a in rest:
                if a.startswith("-"):
                    continue
                np = os.path.normpath(a)
                if np in ("/", "/home", "~") or (np.startswith("/home/") and np.count("/") == 2):
                    return True
    return False


def _is_rm_rf_home(argv) -> bool:
    """rm -rf of a tree UNDER home (not the home root itself, which is REFUSE) -> HARD_DENY.
    rm-rf-home: with /srv/projects retired, 'outside the workspace' is vacuous, so `rm -rf ~/<x>` is a
    human-tap unconfined delete, not a reviewer-unlockable SOFT_DENY. Relative in-tree deletes
    (`rm -r ./d`) do NOT normalize to an absolute home path and stay SOFT_DENY."""
    cmd = _basename(argv[0])
    if cmd != "rm":
        return False
    rest = argv[1:]
    recursive, force = _rm_recursive_force(rest)
    if not (recursive and force):
        return False
    home_pfx = HOME_ROOT + os.sep
    for a in rest:
        if a.startswith("-"):
            continue
        # '~/x' (unexpanded literal) or an absolute path under the home root -> HARD_DENY.
        if a.startswith("~/"):
            return True
        np = os.path.normpath(a)
        if np.startswith(home_pfx):                  # strictly UNDER home (root itself is REFUSE)
            return True
    return False


def _is_egress(argv) -> bool:
    """OUTBOUND network egress ONLY (inbound git is NOT here)."""
    cmd = _basename(argv[0])
    rest = argv[1:]
    if cmd in _EGRESS_CMDS or cmd in _EGRESS_UPLOAD_CMDS:
        return True
    if cmd == "git" and any(a == "push" for a in rest):
        return True
    return False


def _is_setuid_mode(a: str) -> bool:
    """A chmod mode token that confers setuid/setgid: symbolic `+s`/`u+s`/`g+s`, or a numeric mode
    with a leading special-bit digit >= 4 (4xxx setuid, 2xxx setgid, 6xxx both)."""
    if "+s" in a or a.endswith("s") and "+" in a:
        return True
    if a.isdigit() and len(a) == 4 and a[0] in ("2", "4", "6", "7"):
        return True
    return False


def _is_root(argv) -> bool:
    """sudo/root escalation, incl. setuid-conferring chmod."""
    cmd = _basename(argv[0])
    rest = argv[1:]
    if cmd in _ROOT_CMDS:
        return True
    if cmd == "chmod" and any(_is_setuid_mode(a) for a in rest if not a.startswith("-")):
        # chmod u+s / g+s / 4755 -> setuid/setgid conferral.
        return True
    return False


def _is_persistence(argv) -> bool:
    """crontab/at/systemctl-unit-writes/rc-profile/autostart/etc writes. Persistence is a WRITE
    threat, so a persistence PATH-touch is HARD_DENY only for a command that can write it — a bare
    read-only inspector (FREE_BINARIES) reading a persistence config is not a persistence action and
    stays FREE_ZONE (a persistence file that is ALSO secret is already caught by the secret-zone
    check, which runs first and covers reads)."""
    cmd = _basename(argv[0])
    rest = argv[1:]
    if cmd in _PERSISTENCE_CMDS:
        return True
    if cmd == "systemctl":
        # unit enable/disable/mask + edits are persistence (poweroff/reboot already handled by REFUSE).
        if any(a in ("enable", "disable", "mask", "unmask", "edit", "link", "set-default") for a in rest):
            return True
    if cmd == "loginctl":
        return True
    if cmd not in FREE_BINARIES:                     # a writer/interpreter touching a persistence path
        for a in rest:
            if not a.startswith("-") and _touches_persistence(a):
                return True
    return False


def _is_interpreter_inline(argv) -> bool:
    """Interpreter basename + an inline-code flag => reviewer middle (ALLOW).
    Invoking a named FILE is NOT here (path-invoked, also reviewer middle)."""
    cmd = _basename(argv[0])
    if cmd in _INTERPRETERS:
        for a in argv[1:]:
            if a in _INLINE_FLAGS:
                return True
            if cmd.startswith("python") and (a == "-m" or a == "-i"):
                return True
    return False


def _is_soft_deny(argv) -> bool:
    """Destructive-but-recoverable; reviewer unlocks same-op-same-target."""
    cmd = _basename(argv[0])
    rest = argv[1:]
    if cmd in _SOFTDENY_CMDS:
        return True
    # sed in-place overwrite: short -i / -i<glued> AND GNU long --in-place / --in-place=SUFFIX.
    if cmd == "sed" and any(
        a == "-i" or (a.startswith("-i") and not a.startswith("--"))
        or a == "--in-place" or a.startswith("--in-place=")
        for a in rest
    ):
        return True
    if cmd == "find" and "-delete" in rest:
        return True
    if cmd == "git":
        # Match the destructive intent over the WHOLE tail (like _is_egress' any(a=='push')),
        # so leading global options/values (`-c x=y`, `-C /repo`, `--git-dir=…`) can't defeat it.
        if "reset" in rest and "--hard" in rest:
            return True
        if "clean" in rest and any(a.startswith("-") and not a.startswith("--") and "f" in a for a in rest):
            return True
        if "checkout" in rest and "--" in rest:
            return True
        if "branch" in rest and "-D" in rest:
            return True
        if "stash" in rest and "drop" in rest:
            return True
    return False


def policy_tier(req: dict) -> str:
    """The deterministic floor. Returns a tier in {REFUSE, HARD_DENY, FREE_ZONE, SOFT_DENY, ALLOW},
    evaluated in STRICT priority order REFUSE > HARD_DENY > FREE_ZONE > SOFT_DENY > ALLOW on EVERY
    command. Sole floor authority; runs FIRST; absolute for REFUSE/HARD_DENY. Pure function of
    {argv, cwd} ONLY — the tier does NOT depend on `elevate` (nor any box free-text): the
    confined-by-PATH design requires an escalation-lever command (elevate=True) and its ordinary
    auto twin (elevate=False) with the SAME argv/cwd to yield the SAME tier."""
    argv = req["argv"]
    cwd = req.get("cwd", "")
    operands = [a for a in argv[1:] if not a.startswith("-")]

    # 1) REFUSE — HARDLINE, unapprovable by any button.
    if _is_refuse(argv):
        return REFUSE

    # 2) HARD_DENY — intent-proof (reviewer never sees it; human button, unconfined on approve).
    #    OUTBOUND egress · secret-zones · broker-files · sudo/root · persistence · rm-rf-home.
    if _is_egress(argv):
        return HARD_DENY
    if _is_root(argv):
        return HARD_DENY
    # secret zones — operands AND cwd; reads too; BEATS FREE_ZONE.
    if _touches_secret_zone(cwd) or any(_touches_secret_zone(a) for a in operands):
        return HARD_DENY
    # broker/approval-system's own files — operands AND cwd; reads too; BEATS FREE_ZONE.
    if _touches_broker_files(cwd) or any(_touches_broker_files(a) for a in operands):
        return HARD_DENY
    if _is_persistence(argv):
        return HARD_DENY
    # rm -rf of a tree UNDER home (home ROOT itself is REFUSE above).
    if _is_rm_rf_home(argv):
        return HARD_DENY

    # 3) FREE_ZONE — read-only inspector on a NON-secret path, ANYWHERE (workspace containment
    #    retired). Reuse classify() WITHOUT the /srv/projects gate. Runs AFTER the floor so a
    #    destructive find (-delete) or a secret read can never short-circuit it. The tier MUST be a
    #    pure function of {argv, cwd}, so strip `elevate` for the reuse: classify() returns
    #    NEEDS_BUTTON on elevate=True (legacy per-command button path), but the confined-by-PATH
    #    design requires an escalation-lever command (elevate=True) and its ordinary auto twin
    #    (elevate=False) with the SAME argv/cwd to share a tier. classify()'s default is UNCHANGED.
    if classify({**req, "elevate": False}, workspace=None)[0] == IN_SCOPE:
        return FREE_ZONE

    # 4) SOFT_DENY — destructive but recoverable; reviewer unlocks same-op-same-target.
    if _is_soft_deny(argv):
        return SOFT_DENY

    # 5) ALLOW — the broad reviewer middle (inline interpreters, path-invoked, inbound git, writers).
    return ALLOW


# Owner-facing labels for the 🔴 approval button's "Floor:" line — WHY the deterministic floor fired.
# Order MIRRORS policy_tier()'s HARD_DENY checks so the label matches the rule that actually fired.
def hard_deny_reason(req: dict) -> str:
    """The specific HARD_DENY category, as a short scannable label + gloss for the owner button, or ''
    if the command is not HARD_DENY. Deterministic, pure function of {argv, cwd} — NOT the LLM."""
    argv = req["argv"]
    cwd = req.get("cwd", "")
    operands = [a for a in argv[1:] if not a.startswith("-")]
    if _is_egress(argv):
        return "EGRESS — sends bytes off-box"
    if _is_root(argv):
        return "SUDO/ROOT — privilege escalation"
    if _touches_secret_zone(cwd) or any(_touches_secret_zone(a) for a in operands):
        return "SECRETS — touches a secret/credential path"
    if _touches_broker_files(cwd) or any(_touches_broker_files(a) for a in operands):
        return "BROKER-FILES — touches the approval system's own files"
    if _is_persistence(argv):
        return "PERSISTENCE — installs/enables something that outlives the session"
    if _is_rm_rf_home(argv):
        return "RM-RF — recursive delete under your home"
    return ""


def audit(record: dict):
    """Append one JSON line. Log file is chattr +a (append-only) so history can't be rewritten."""
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **record}
    line = json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n"
    fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def handle(raw: bytes, expected_id):
    """Full pipeline for one request. Returns (decision, reason, chash-or-None). Always audits."""
    try:
        req = validate_request(raw, expected_id)
    except Reject as e:
        audit({"decision": REJECT, "reason": str(e), "expected_id": expected_id})
        return REJECT, str(e), None
    chash = cmd_hash(req)
    decision, reason = classify(req)
    audit({"decision": decision, "reason": reason, "cmd_hash": chash,
           "session_id": req["session_id"], "request_id": req["request_id"],
           "cwd": req["cwd"], "elevate": req["elevate"], "argv": req["argv"]})
    return decision, reason, chash


def _cli_classify(path, expected_id):
    with open(path, "rb") as f:
        raw = f.read(MAXSIZE + 1)
    if expected_id is None:
        try:
            expected_id = json.loads(raw.decode("utf-8", "replace")).get("request_id")
        except Exception:
            expected_id = None
    decision, reason, chash = handle(raw, expected_id)
    print(f"decision={decision}\nreason={reason}\ncmd_hash={chash}")
    return 0 if decision != REJECT else 3


def main(argv):
    if len(argv) >= 2 and argv[1] == "classify":
        path = argv[2]
        expected = argv[3] if len(argv) > 3 else None
        return _cli_classify(path, expected)
    sys.stderr.write("usage: broker.py classify <request.json> [expected_request_id]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
