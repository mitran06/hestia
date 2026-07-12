#!/usr/bin/env python3
"""broker.py — Hestia capability broker (Part 3 SKELETON: schema + canon + decision + audit).

Runs as user `hestia-broker` (NO lxd/docker/sudo; holds policy + later the 2nd-bot token).
This part implements and proves the POLICY BRAIN only — NO Telegram, NO SSH, NO execution yet:

  request(JSON from box) --validate--> --canonicalize(length-prefixed)--> cmd_hash(sha256)
                                    --classify--> {IN_SCOPE | NEEDS_BUTTON | REJECT}
                                    --> append-only audit log (chattr +a)

Security stance: DEFAULT-DENY-TO-BUTTON. A command auto-runs (IN_SCOPE) ONLY if it provably is a
bare read-only allowlisted binary, non-elevated, with cwd + args lexically inside the workspace.
Everything else — interpreters/shells, git (arbitrary code via .git/config & hooks), elevation,
paths outside the workspace, anything ambiguous — is NEEDS_BUTTON. Malformed input is REJECT.

NOTE: the AUTHORITATIVE workspace-containment check is realpath-on-the-target (Part 4); the cwd/arg
checks here are a lexical FIRST gate. Session lifecycle + Telegram approval are Part 5.
"""
import json, hashlib, struct, os, sys, re, time

WORKSPACE      = "/srv/projects"          # the target free zone (paths refer to the target)
MAXSIZE        = 65536                     # 64 KiB, matches the mover cap
SCHEMA_VERSION = 1
MAX_ARGV       = 256                       # cap argv length
MAX_ARG_LEN    = 8192                      # cap a single arg
AUDIT_LOG      = os.environ.get("HESTIA_AUDIT", "/var/lib/hestia-broker/log/audit.log")
UUID_RE        = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

IN_SCOPE, NEEDS_BUTTON, REJECT = "IN_SCOPE", "NEEDS_BUTTON", "REJECT"

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


def validate_request(raw: bytes, expected_id):
    """Parse + strictly validate the request bytes. Returns the request dict or raises Reject."""
    if len(raw) > MAXSIZE:
        raise Reject(f"oversize request ({len(raw)} > {MAXSIZE})")
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Reject(f"not valid utf-8 JSON: {e}")
    if not isinstance(req, dict):
        raise Reject("top-level JSON is not an object")

    allowed = {"v", "session_id", "request_id", "cwd", "elevate", "argv"}
    extra = set(req) - allowed
    if extra:
        raise Reject(f"unexpected keys: {sorted(extra)}")
    if set(req) != allowed:
        raise Reject(f"missing keys: {sorted(allowed - set(req))}")

    if req["v"] != SCHEMA_VERSION:
        raise Reject(f"bad schema version {req['v']!r}")
    for k in ("session_id", "request_id"):
        if not isinstance(req[k], str) or not UUID_RE.match(req[k]):
            raise Reject(f"{k} is not a UUID")
    if expected_id is not None and req["request_id"] != expected_id:
        raise Reject(f"request_id {req['request_id']} != filename {expected_id} (anti-swap)")
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


def _lp(b: bytes) -> bytes:
    """Length-prefix a byte string (4-byte big-endian length). Blocks delimiter/NUL ambiguity."""
    return struct.pack(">I", len(b)) + b


def canonicalize(req: dict) -> bytes:
    """Deterministic, unambiguous byte encoding of the security-relevant fields."""
    out = b"HERMES-CANON-v1"
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


def _operand_ok(a: str) -> bool:
    """A non-flag token must be a workspace-relative path (no argfile, no '..', no abs-outside)."""
    if a.startswith("@"):
        return False
    if ".." in a.split("/"):
        return False
    if a.startswith("/") and not _within(a, WORKSPACE):
        return False
    return True


def _arg_ok_freezone(cmd: str, a: str) -> bool:
    """Strict per-arg gate for the auto-run path. Flags must be explicitly safe; no glued paths."""
    if a in ("-", "--") or not a.startswith("-"):
        return _operand_ok(a)
    # a is a flag token
    if "=" in a:
        return False                                   # blocks --opt=/abs, --pre=CMD, --output=FILE
    if a.startswith("--"):
        return a in SAFE_LONG.get(cmd, set())
    letters = a[1:]                                     # short cluster, e.g. -la ; also blocks -f/etc (‘/’ not a letter)
    return bool(letters) and all(c in SAFE_SHORT.get(cmd, set()) for c in letters)


def classify(req: dict):
    """Return (decision, reason). DEFAULT-DENY-TO-BUTTON."""
    if req["elevate"]:
        return NEEDS_BUTTON, "elevation requested"
    argv = req["argv"]
    cmd = argv[0]
    if "/" in cmd:
        return NEEDS_BUTTON, "argv[0] is a path, not a bare allowlisted command"
    if cmd not in FREE_BINARIES:
        return NEEDS_BUTTON, f"'{cmd}' not in free-zone read-only allowlist"
    if not _within(req["cwd"], WORKSPACE):
        return NEEDS_BUTTON, f"cwd {req['cwd']!r} outside workspace {WORKSPACE} (lexical)"
    if cmd == "find":
        # find has a word-flag CLI; block write/exec primaries + out-of-workspace/argfile operands.
        for a in argv[1:]:
            if a in FIND_DANGEROUS:
                return NEEDS_BUTTON, f"find with dangerous action {a}"
            if not _operand_ok(a) and not a.startswith("-"):
                return NEEDS_BUTTON, f"find operand not workspace-safe: {a!r}"
            if a.startswith("/") and not _within(a, WORKSPACE):
                return NEEDS_BUTTON, f"find path arg outside workspace: {a!r}"
        return IN_SCOPE, "free-zone find within workspace"
    for a in argv[1:]:
        if not _arg_ok_freezone(cmd, a):
            return NEEDS_BUTTON, f"arg not free-zone-safe for {cmd}: {a!r}"
    return IN_SCOPE, "free-zone read-only command within workspace"


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
