#!/usr/bin/env python3
"""Deterministic AUR security-audit collector.

Collects AUR metadata, the package git history, and the PKGBUILD/.install
snapshot, then applies static checks. It never sources, evals, or executes the
PKGBUILD. `--verify-sources` downloads declared sources and recomputes checksums.

Usage:
  audit.py <pkgname> [--json PATH] [--verify-sources] [--cache-dir DIR] [--no-history]
  audit.py --pkgbuild <dir-or-PKGBUILD> [--json PATH] [--verify-sources] [--cache-dir DIR]

Exit: 0 no HIGH findings, 2 HIGH findings present, 1 collector error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

if sys.version_info < (3, 12):
    raise SystemExit("aur-security-audit: needs Python 3.12+ (tarfile extraction filter)")

AUR = "https://aur.archlinux.org"
UA = "aur-security-audit/1.0 (+static PKGBUILD review)"
MAX_DOWNLOAD = 4 << 30  # refuse a source larger than 4 GiB instead of hashing forever
DOWNLOAD_TIMEOUT = 60   # seconds per network operation; a blocked host must not stall the audit
HIGH, MEDIUM, LOW, INFO = "HIGH", "MEDIUM", "LOW", "INFO"
RANK = {HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

SUMS = {"sha512sums": 128, "sha256sums": 64, "b2sums": 128, "sha1sums": 40, "md5sums": 32}
STRONG = ("sha512sums", "sha256sums", "b2sums")
SIG_SUFFIX = (".sig", ".asc", ".sign", ".gpg", ".pgp")
PATCH_SUFFIX = (".patch", ".diff")
VCS_PREFIX = ("git+", "svn+", "hg+", "bzr+")
# Bash function names may contain hyphens (`_package-headers()` is common).
NAME_RE = r"[A-Za-z_][A-Za-z0-9_-]*"
# A line containing any of these can run more than one command; never exempt it whole.
CHAIN_META = re.compile(r"[;&|`]|\$\(")
GITHUB_RELEASE_RE = re.compile(
    r"https://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/([^/]+)$")
NPM_TARBALL_RX = re.compile(r"^https://registry\.npmjs\.org/((?:@[^/]+/)?[^/]+)/-/")
# A download in one of these formats is an opaque prebuilt payload, not source.
BINARY_SOURCE_EXT = (".deb", ".rpm", ".appimage", ".run", ".7z")
IMAGE_SUFFIX = (".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp")
PRIVILEGE_RX = re.compile(
    r"chmod\s+(?:-[-a-zA-Z]+\s+)*(?:[ugoa]*\+[sStT]\b|(?<![0-7])[0-7]{0,2}[4-7][0-7]{3}(?![0-7]))"
    r"|\bsetcap\b")
SANDBOX_RX = re.compile(
    r"--(?:no-sandbox|disable-gpu-sandbox|disable-setuid-sandbox)\b|--in-process-gpu\b")
SUMS_CACHE: dict[str, tuple[dict[str, str] | None, str]] = {}
NPM_META_CACHE: dict[str, tuple[dict | None, str]] = {}
NPM_KEYS_CACHE: dict[str, str] | None = None


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    file: str = "PKGBUILD"
    line: int | None = None
    evidence: str | None = None


@dataclass
class Source:
    raw: str
    url: str
    line: int | None
    scheme: str
    vcs: bool
    sig: bool
    patch: bool
    sums: dict[str, str] = field(default_factory=dict)
    verify: str = "not-checked"
    resolved: str = ""
    provenance: str = ""
    filename: str = ""


@dataclass
class Report:
    package: str
    version: str | None = None
    maintainer: str | None = None
    submitted: str | None = None
    last_modified: str | None = None
    out_of_date: str | None = None
    votes: int | None = None
    popularity: float | None = None
    findings: list[Finding] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    authors: list[dict] = field(default_factory=list)
    commits: int | None = None
    last_change_diff: str | None = None
    history_note: str | None = None
    notes: list[str] = field(default_factory=list)
    snapshot: str | None = None
    sources_verified: bool = False
    verdict: str = "REVIEW"

    def add(self, severity: str, code: str, message: str, **kw) -> None:
        self.findings.append(Finding(severity, code, message, **kw))


def fetch(url: str, timeout: int = 40, attempts: int = 2) -> bytes:
    last: Exception | None = None
    for attempt in range(attempts):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            if attempt + 1 < attempts:
                time.sleep(2)
    raise SystemExit(f"aur-security-audit: request failed for {url}: {last}")


def line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def line_of(text: str, needle: str) -> int | None:
    pos = text.find(needle)
    return line_at(text, pos) if pos >= 0 else None


def sh(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout,
                          check=False, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})


def rpc_info(name: str) -> dict:
    raw = fetch(f"{AUR}/rpc/v5/info?arg[]={urllib.parse.quote(name)}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit(f"aur-security-audit: AUR RPC returned invalid JSON: {e}")
    if not isinstance(data, dict):
        raise SystemExit("aur-security-audit: AUR RPC returned an unexpected payload")
    results = data.get("results", [])
    if not results:
        raise SystemExit(f"aur-security-audit: no AUR package named {name!r}")
    for r in results:
        if r.get("Name") == name:
            return r
    return results[0]


def aur_maintainer_portfolio(name: str) -> str:
    """Context for a new or repack-heavy maintainer account."""
    try:
        raw = fetch(f"{AUR}/rpc/v5/search/{urllib.parse.quote(name)}?by=maintainer")
        data = json.loads(raw)
        results = data.get("results") or []
        count = data.get("resultcount", len(results))
        dates = [r["FirstSubmitted"] for r in results if r.get("FirstSubmitted")]
        earliest = time.strftime("%Y-%m-%d", time.gmtime(min(dates))) if dates else "unknown"
        return f"maintainer {name} has {count} AUR packages (earliest submitted {earliest})"
    except (SystemExit, ValueError, KeyError, TypeError):
        return "maintainer portfolio lookup failed"


def safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    root = os.path.realpath(dest)
    for m in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, m.name))
        if not target.startswith(root + os.sep) and target != root:
            raise SystemExit(f"snapshot member escapes destination: {m.name}")
    tar.extractall(dest, filter="data")


def load_snapshot(pkgbase: str, workdir: str) -> str:
    url = f"{AUR}/cgit/aur.git/snapshot/{urllib.parse.quote(pkgbase)}.tar.gz"
    blob = fetch(url)
    tar_path = os.path.join(workdir, f"{pkgbase}.tar.gz")
    with open(tar_path, "wb") as f:
        f.write(blob)
    with tarfile.open(tar_path) as tar:
        safe_extract(tar, workdir)
    snap = os.path.join(workdir, pkgbase)
    if not os.path.isdir(snap):
        raise SystemExit(f"snapshot layout unexpected for {pkgbase}")
    return snap


def git_history(pkgbase: str, workdir: str) -> tuple[list[dict], int, str | None, str | None]:
    repo = os.path.join(workdir, "git")
    cp = sh(["git", "clone", "--quiet", f"{AUR}/{pkgbase}.git", repo], timeout=180)
    if cp.returncode != 0:
        return [], 0, None, cp.stderr.strip()[:300]
    log = sh(["git", "-C", repo, "log", "--format=%h%x1f%an%x1f%ae%x1f%aI%x1f%s"], timeout=60)
    rows = [r.split("\x1f") for r in log.stdout.splitlines() if r.strip()]
    authors: dict[str, dict] = {}
    for _sha, name, email, date, subject in rows:  # rows are newest-first
        a = authors.setdefault(email, {"name": name, "email": email, "names": [],
                                       "commits": 0, "last": date, "first": date,
                                       "last_subject": subject})
        if name not in a["names"]:
            a["names"].append(name)
        a["commits"] += 1
        a["first"] = date
        if date > a["last"]:
            a["last"] = date
            a["last_subject"] = subject
            a["name"] = name
    ordered = sorted(authors.values(), key=lambda a: a["last"], reverse=True)
    diff = ""
    d = sh(["git", "-C", repo, "diff", "--unified=2", "HEAD~1", "HEAD", "--", "PKGBUILD", "*.install"], timeout=60)
    if d.returncode == 0:
        diff = d.stdout.strip()
    return ordered, len(rows), diff, None


def _match_paren(text: str, start: int) -> int:
    """Index just past the ')' matching the '(' at `start`, quote/comment aware."""
    depth, i, n = 0, start, len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n("):
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
            continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _unquote_word(raw: str) -> str:
    """Shell-unquote one array word: `"a"::"b"` -> `a::b`."""
    out: list[str] = []
    quote = None
    i = 0
    while i < len(raw):
        c = raw[i]
        if quote:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < len(raw):
                out.append(raw[i + 1])
                i += 2
                continue
            else:
                out.append(c)
        elif c in "'\"":
            quote = c
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _brace_end(word: str, open_index: int) -> int:
    depth, quote = 0, None
    i = open_index
    while i < len(word):
        c = word[i]
        if quote:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"':
                i += 1
        elif c in "'\"":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_alts(inner: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth, quote, i = 0, None, 0
    while i < len(inner):
        c = inner[i]
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < len(inner):
                cur.append(inner[i + 1])
                i += 1
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == "{":
            depth += 1
            cur.append(c)
        elif c == "}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def brace_expand(word: str) -> list[str]:
    """Expand one non-parameter, unquoted `{a,b}` group, as makepkg's array sees it."""
    quote = None
    i = 0
    while i < len(word):
        c = word[i]
        if quote:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"':
                i += 1
        elif c in "'\"":
            quote = c
        elif c == "{" and (i == 0 or word[i - 1] != "$"):
            j = _brace_end(word, i)
            if j < 0:
                return [word]
            inner = word[i + 1:j]
            if "," not in inner:
                return [word]
            out: list[str] = []
            for alt in _split_alts(inner):
                out.extend(brace_expand(word[:i] + alt + word[j + 1:]))
            return out
        i += 1
    return [word]


def _split_items(body: str, base_pos: int, text: str) -> list[tuple[str, int]]:
    items, buf, quote, i = [], [], None, 0
    while i < len(body):
        c = body[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(body):
                buf.append(c)
                buf.append(body[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            buf.append(c)
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c in " \t\n":
            if buf:
                items.append(("".join(buf), base_pos + i - len(buf)))
                buf = []
        elif c == "#" and not buf:
            nl = body.find("\n", i)
            i = len(body) if nl < 0 else nl
            continue
        else:
            buf.append(c)
        i += 1
    if buf:
        items.append(("".join(buf), base_pos + i - len(buf)))
    out = []
    for raw, pos in items:
        for variant in brace_expand(raw.strip()):
            out.append((_unquote_word(variant), line_at(text, pos)))
    return out


def parse_array(text: str, name: str) -> list[tuple[str, int]] | None:
    """Every `name=(...)`, `name+=(...)`, and `name[i]=value` assignment, in file order.

    Indexed assignments are applied to the array, so callers see the effective
    value (e.g. `sha512sums[4]='SKIP'` after the literal array). A non-literal
    index cannot be applied and is reported by `indexed_assignments()`.
    """
    events = []
    for m in re.finditer(rf"^[ \t]*{re.escape(name)}\+?=\s*\(", text, re.MULTILINE):
        open_paren = m.end() - 1
        end = _match_paren(text, open_paren)
        if end < 0:
            continue
        events.append((m.start(), "array",
                       _split_items(text[open_paren + 1:end - 1], open_paren + 1, text)))
    for m in re.finditer(
            rf"^[ \t]*{re.escape(name)}\[([^\]]+)\]([+]?)=\s*([^\n]*)", text, re.MULTILINE):
        value = strip_comment(m.group(3)).strip()
        events.append((m.start(), "index",
                       (m.group(1).strip(), m.group(2), _unquote_word(value),
                        line_at(text, m.start()))))
    if not events:
        return None
    events.sort(key=lambda e: e[0])
    items: list[tuple[str, int]] = []
    for _pos, kind, payload in events:
        if kind == "array":
            items.extend(payload)
            continue
        idx_raw, op, value, line = payload
        if not re.fullmatch(r"\d+", idx_raw):
            continue
        idx = int(idx_raw)
        while len(items) <= idx:
            items.append(("", line))
        items[idx] = ((items[idx][0] + value) if op == "+" else value, line)
    return items


def indexed_assignments(text: str, name: str) -> list[tuple[str, int]]:
    """Every `name[expr]=...` index expression and its line."""
    return [(m.group(1).strip(), line_at(text, m.start()))
            for m in re.finditer(
                rf"^[ \t]*{re.escape(name)}\[([^\]]+)\][+]?=\s*[^\n]*", text, re.MULTILINE)]


def array_is_static(text: str, name: str) -> bool:
    """False when `+=` or an indexed assignment makes the final array unknowable."""
    return not (
        re.search(rf"^[ \t]*{re.escape(name)}\+=", text, re.MULTILINE)
        or re.search(rf"^[ \t]*{re.escape(name)}\[", text, re.MULTILINE)
    )


def parse_array_head(text: str, name: str) -> list[tuple[str, int]]:
    """Only the first literal `name=(...)`, ignoring per-package overrides."""
    m = re.search(rf"^[ \t]*{re.escape(name)}=[ \t]*\(", text, re.MULTILINE)
    if not m:
        return []
    open_paren = m.end() - 1
    end = _match_paren(text, open_paren)
    if end < 0:
        return []
    return _split_items(text[open_paren + 1:end - 1], open_paren + 1, text)


def mask_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Blank out character ranges, preserving newlines so line numbers stay valid."""
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for i in range(max(0, start), min(len(chars), end)):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def first_diff(a: list[str], b: list[str]) -> tuple[str | None, str | None]:
    for x, y in zip(a, b):
        if x != y:
            return x, y
    if len(a) > len(b):
        return a[len(b)], None
    if len(b) > len(a):
        return None, b[len(a)]
    return None, None


def looks_prebuilt(funcs: list[tuple], sources: list[Source], pkgnames: list[str]) -> bool:
    """True when the package ships a downloaded binary rather than compiling source."""
    if not sources:
        return False
    if any((name or "").endswith("-bin") for name in pkgnames):
        return True
    remote = [s for s in sources if s.scheme == "https"]
    # All remote inputs are opaque binaries: prebuilt even if a build() exists.
    if remote and all(s.resolved.lower().endswith(BINARY_SOURCE_EXT) for s in remote):
        return True
    # A real build step means a source package; an optional binary source
    # (e.g. a vendor .run for one subpackage) does not make it prebuilt.
    if any(f[0] == "build" for f in funcs):
        return False
    if any(s.resolved.lower().endswith(BINARY_SOURCE_EXT) for s in remote):
        return True
    return any(re.search(r"\b(?:bsdtar|tar|unzip|ar|dpkg-deb|rpm2cpio|7z)\b", f[3])
               for f in funcs if f[0] == "package")


def parse_scalar(text: str, name: str) -> str | None:
    m = re.search(rf"^[ \t]*{re.escape(name)}=([^\n#]*)", text, re.MULTILINE)
    if not m:
        return None
    return m.group(1).strip().strip("'\"")


def function_bodies(text: str) -> list[tuple[str, int, int, str, int, int]]:
    """(name, start_line, end_line, body, body_start, body_end) for every function.

    Accepts `name() {`, `name () {`, `function name {` and `function name() {`,
    including a brace on the next line: all execute the same body. Names may
    contain hyphens, as bash allows. Every definition is returned, including
    duplicates, because a conditional branch may decide which one runs.
    """
    out: list[tuple[str, int, int, str, int, int]] = []
    pat = re.compile(
        r"^[ \t]*(?:function[ \t]+(" + NAME_RE + r")[ \t]*(?:\(\))?"
        r"|(" + NAME_RE + r")[ \t]*\(\))[ \t]*\n?[ \t]*\{",
        re.MULTILINE,
    )
    for m in pat.finditer(text):
        name = m.group(1) or m.group(2)
        body_start = m.end()
        depth, i, quote = 1, body_start, None
        while i < len(text):
            c = text[i]
            if quote:
                if c == "\\" and quote == '"':
                    i += 2
                    continue
                if c == quote:
                    quote = None
            elif c in "'\"":
                quote = c
            elif c == "#" and (i == 0 or text[i - 1] in " \t\n("):
                nl = text.find("\n", i)
                i = len(text) if nl < 0 else nl
                continue
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append((name, line_at(text, m.start()), line_at(text, i),
                                text[body_start:i], body_start, i))
                    break
            i += 1
    return out


BODY_RULES = [
    (re.compile(r"\b(?:curl|wget|aria2c|ncat|netcat|socat|rsync|scp|tftp)\b"
                r"|\bgit\s+(?:clone|fetch|pull|submodule\s+update)\b"
                r"|\b(?:hg\s+clone|svn\s+(?:checkout|co))\b"), HIGH, "net-fetch",
     "downloads at build time; content bypasses source checksums"),
    (re.compile(r"\|\s*(?:/usr)?/bin/(?:ba|z|k|da)?sh\b"
                r"|\|\s*(?:ba|z|k|da)?sh\b"
                r"|\|\s*(?:python[0-9.]*|perl|ruby|node)\b"), HIGH, "pipe-to-shell",
     "pipes downloaded or decoded content into an interpreter"),
    (re.compile(r"(?<![\w./-])(?:ba|z|k)?sh\s+<\(|"
                r"(?<![\w./-])(?:ba|z|k)?sh\s+[^\s;|&-][^\s;|&]*"
                r"|(?:^|[;&|])\s*(?:source|\.)\s+\S+"), MEDIUM, "script-exec",
     "runs a script shipped beside the PKGBUILD; the checksum binds the AUR upload, so read the script itself"),
    (re.compile(r"\b(?:ba|z|k)?sh\s+-c\b|\beval\b"), HIGH, "dynamic-shell",
     "evaluates a command string; the reviewed text is not the executed text"),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b|\bxxd\s+-r\b|\bopenssl\s+enc\s+-d\b"), HIGH, "decode-payload",
     "decodes an embedded payload"),
    (re.compile(r"\.ssh/|\.gnupg/|GITHUB_TOKEN|CI_JOB_TOKEN|NPM_TOKEN|\.netrc|credential\.helper|git\s+config\s+--global"), HIGH,
     "credential-access", "reads build-host credentials or rewrites git auth"),
    (re.compile(r"\bsudo\b|\bsu\s+-"), HIGH, "privilege",
     "escalates privileges"),
    (PRIVILEGE_RX, MEDIUM, "privilege",
     "sets SUID/SGID/capabilities; a deliberate design needs an upstream reason"),
    (SANDBOX_RX, MEDIUM, "sandbox-weakened",
     "disables the Chromium/Electron sandbox; rendered or remote content runs with the user's full privileges"),
    (re.compile(r"\bsystemctl\s+(?:enable|start)|\bcrontab\b|\.bashrc|\.profile|/autostart/"), MEDIUM, "persistence",
     "installs persistence outside the package payload"),
    (re.compile(r"\b(?:pacman\s+-[US]|pip[0-9.]*\s+install|npm\s+(?:i|install)|cargo\s+install|go\s+install|gem\s+install)\b"),
     MEDIUM, "pkgmgr-in-build", "installs packages during build, bypassing declared dependencies"),
    (re.compile(r"LD_PRELOAD|ld\.so\.preload"), HIGH, "dynamic-linker",
     "injects a dynamic linker preload"),
    (re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:--no-preserve-root\s+)?"
                r"(?:/(?:\s|$|\*)|/(?:home|root|etc|usr|var)\b|\$HOME|~)"
                r"|\bfind\s+/\s+[^\n]*-delete\b"), HIGH, "destructive",
     "recursively deletes an absolute or home path"),
    (re.compile(r">\s*/(?:etc|usr|var|boot|root|home)(?:/|\b)"), MEDIUM, "root-write",
     "writes outside the package tree"),
    (re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"), MEDIUM, "encoded-blob",
     "long base64-like blob; decode it before approving"),
]

INSTALL_SAFE = {
    "echo", "printf", "true", "false", "exit", "return", "local", "export", "test", "[", "[[",
    "if", "then", "else", "elif", "fi", "for", "do", "done", "while", "case", "esac", "in",
    "set", "shift", "unset", "read", ":", "break", "continue",
    "note", "msg", "msg2", "plain", "warning", "error",
}

# An .install function runs as root: any of these in one is a review item, not a style note.
INSTALL_ROOT_WRITE = re.compile(
    r"(?:^|\s)/(?:etc|usr|var|boot|root|home|opt|srv)/|\$HOME|~"
    r"|\bsed\s+-i\b|\b(?:rm|chmod|chown|mv|cp|dd|truncate)\b|>\s*/"
)


def strip_comment(line: str) -> str:
    """Drop a trailing shell comment, leaving quotes and ${x#y} alone."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(line):
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


ECHO_SAFE = {"echo", "printf", "msg", "msg2", "plain", "warning", "error", "note"}


def scan_body(report: Report, fname: str, body: str, first_line: int, where: str) -> None:
    for offset, raw in enumerate(body.splitlines()):
        line = first_line + offset
        s = strip_comment(raw).strip()
        if not s or s.startswith("#"):
            continue
        first = s.split()[0].strip("\"'")
        # An echo/printf line is inert only if it cannot chain or substitute.
        if first in ECHO_SAFE and not CHAIN_META.search(s) and ">" not in s:
            continue
        for rx, sev, code, why in BODY_RULES:
            if rx.search(s):
                report.add(sev, code, f"{where}: {why}", file=fname, line=line, evidence=s[:220])


def scan_local_source(report: Report, text: str, fname: str) -> None:
    """Review a shipped script/launcher for privilege and sandbox regressions.

    Only these two classes run here: applying the whole BODY_RULES set to an
    installed launcher would report its legitimate runtime network access as a
    build-time fetch. The SKILL still requires reading every local source.
    """
    for offset, raw in enumerate(text.splitlines()):
        s = strip_comment(raw).strip()
        if not s:
            continue
        if PRIVILEGE_RX.search(s):
            report.add(MEDIUM, "privilege",
                       "local build script sets SUID/SGID/capabilities; the installed binary "
                       "gains root-owned privilege if the build runs it",
                       file=fname, line=offset + 1, evidence=s[:220])
        if SANDBOX_RX.search(s):
            report.add(MEDIUM, "sandbox-weakened",
                       "local source disables the Chromium/Electron sandbox; content rendered "
                       "by the app runs with the user's full privileges",
                       file=fname, line=offset + 1, evidence=s[:220])


def scan_local_sources(report: Report, base: str) -> None:
    root_real = os.path.realpath(base)
    for src in report.sources:
        if src.scheme != "" or not src.resolved or src.patch or src.sig:
            continue
        if src.resolved.lower().endswith(IMAGE_SUFFIX):
            continue
        path = os.path.realpath(os.path.join(base, src.resolved))
        if path != root_real and not path.startswith(root_real + os.sep):
            continue
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                data = f.read(256 * 1024)
        except OSError:
            continue
        if b"\x00" in data[:8192]:
            continue
        scan_local_source(report, data.decode("utf-8", "replace"),
                          src.filename or os.path.basename(src.resolved))


def scan_install(report: Report, path: str) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    fname = os.path.basename(path)
    funcs = function_bodies(text)
    local_names = {f[0] for f in funcs}
    for name, start, _end, body, _bs, _be in funcs:
        scan_body(report, fname, body, start, f"{name}() runs as root at install/upgrade time")
        for offset, raw in enumerate(body.splitlines()):
            s = strip_comment(raw).strip()
            if not s or s in ("{", "}"):
                continue
            cmd = s.split()[0].strip("\"'")
            if (cmd in INSTALL_SAFE or cmd in local_names or cmd.endswith("=")
                    or cmd.startswith("$") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", s)):
                continue
            report.add(INFO, "install-script-command",
                       f"{name}() runs `{cmd}` as root; read the whole function", file=fname,
                       line=start + offset, evidence=s[:220])
            if INSTALL_ROOT_WRITE.search(s):
                report.add(MEDIUM, "install-script-root-write",
                           f"{name}() writes system paths or rewrites files as root", file=fname,
                           line=start + offset, evidence=s[:220])


def parse_sources(report: Report, text: str, vars_: dict[str, str]) -> list[Source]:
    suffixes = [""] + sorted({m.group(1) for m in re.finditer(
        r"^[ \t]*source_([A-Za-z0-9_]+)\+?=\s*\(", text, re.MULTILINE)})
    report.sources = []
    images: list[str] = []
    for suffix in suffixes:
        tag = f"_{suffix}" if suffix else ""
        entries = parse_array(text, "source" + tag) or []
        if not entries:
            continue
        sums_arrays = {alg: parse_array(text, alg + tag) for alg in SUMS}
        if not any(sums_arrays.values()):
            report.add(HIGH, "missing-checksums",
                       f"no {tag.lstrip('_') + ' ' if tag else ''}checksum array accompanies the sources",
                       line=line_of(text, "source" + tag + "="), evidence="")
        strong_present = any(sums_arrays.get(alg) for alg in STRONG)
        for alg in ("md5sums", "sha1sums"):
            if sums_arrays.get(alg):
                report.add(LOW if strong_present else HIGH, "weak-checksum",
                           f"{alg}{tag} is cryptographically broken for integrity review",
                           line=line_of(text, alg + tag))
        for alg, items in sums_arrays.items():
            if items and len(items) != len(entries):
                if array_is_static(text, alg + tag) and array_is_static(text, "source" + tag):
                    report.add(HIGH, "checksum-count-mismatch",
                               f"{alg}{tag} has {len(items)} entries for {len(entries)} sources",
                               line=line_of(text, alg + tag))
                else:
                    report.add(INFO, "checksum-count-unresolved",
                               f"{alg}{tag} has {len(items)} entries for {len(entries)} sources; "
                               "conditional or indexed assignments make the static count unreliable",
                               line=line_of(text, alg + tag))

        for idx, (raw, line) in enumerate(entries):
            name_part, _, url = raw.partition("::") if "::" in raw.split("://")[0] else ("", "", raw)
            dynamic = "$(" in raw or "`" in raw
            resolved, expanded_ok = expand_deep(url, vars_)
            m = re.match(r"^([A-Za-z0-9+]+)://", resolved)
            scheme = m.group(1) if m else ""
            low = resolved.lower()
            low_name = name_part.lower()
            name_resolved, name_ok = expand_deep(name_part.strip(), vars_) if name_part.strip() else ("", True)
            if not name_resolved:
                name_resolved = os.path.basename(
                    urllib.parse.urlsplit(resolved if expanded_ok else url).path)
            src = Source(raw=raw, url=url, line=line, scheme=scheme,
                         vcs=resolved.startswith(VCS_PREFIX) or scheme in ("git", "svn", "hg", "bzr"),
                         sig=low.endswith(SIG_SUFFIX) or low_name.endswith(SIG_SUFFIX),
                         patch=low.endswith(PATCH_SUFFIX) or low_name.endswith(PATCH_SUFFIX),
                         resolved=resolved if expanded_ok else "",
                         filename=name_resolved if name_ok else "")
            for alg, items in sums_arrays.items():
                if items and idx < len(items):
                    src.sums[alg] = items[idx][0]
            report.sources.append(src)

            if dynamic:
                report.add(HIGH, "dynamic-source",
                           "source entry is computed by a command substitution; the reviewed text is not the fetched URL",
                           line=line, evidence=raw[:220])
            elif not expanded_ok:
                src.verify = "unexpanded-variable"
                report.add(MEDIUM, "source-unresolved",
                           "source URL uses a variable the collector cannot expand; its real host was not reviewed",
                           line=line, evidence=raw[:220])
            if scheme in ("http", "git", "svn", "ftp", "tftp"):
                report.add(HIGH if scheme == "http" else MEDIUM, "insecure-scheme",
                           f"source uses unauthenticated {scheme}://; "
                           "checksums in the PKGBUILD do not authenticate the transport",
                           line=line, evidence=raw[:220])
            elif not scheme and expanded_ok and not dynamic and not src.vcs and not src.patch and not src.sig:
                if os.path.isabs(resolved) or ".." in resolved.split("/"):
                    src.verify = "local-escapes-snapshot"
                    report.add(MEDIUM, "source-unverified",
                               "local source path is absolute or escapes the snapshot; not read",
                               line=line, evidence=raw[:220])
                elif resolved.lower().endswith(IMAGE_SUFFIX):
                    images.append(os.path.basename(resolved))
                else:
                    report.add(INFO, "local-source",
                               "source is a file shipped in the AUR repo; read it with the PKGBUILD",
                               line=line, evidence=raw[:220])

            for alg, value in src.sums.items():
                v = value.strip()
                if v.upper() == "SKIP":
                    if src.vcs or src.sig:
                        continue
                    report.add(LOW if src.patch else HIGH, "skip-checksum",
                               f"{alg}{tag}=SKIP on a non-VCS, non-signature source",
                               line=line, evidence=raw[:220])
                    continue
                if not re.fullmatch(r"[0-9a-fA-F]+", v) or len(v) != SUMS[alg]:
                    report.add(HIGH, "malformed-checksum",
                               f"{alg}{tag} value is not {SUMS[alg]} hex characters",
                               line=line, evidence=f"{alg}={v[:80]}")

    if images:
        report.add(INFO, "local-source",
                   f"{len(images)} image assets shipped in the AUR repo; hashed but not executable")

    for suffix in suffixes:
        tag = f"_{suffix}" if suffix else ""
        for arr in ["source" + tag] + [alg + tag for alg in SUMS]:
            for idx_raw, line in indexed_assignments(text, arr):
                if not re.fullmatch(r"\d+", idx_raw):
                    report.add(MEDIUM, "array-index-unresolved",
                               f"{arr}[{idx_raw}] uses a non-literal index; "
                               "the source/checksum table may not reflect the build",
                               line=line, evidence=f"{arr}[{idx_raw}]")

    if any(s.sig for s in report.sources) and not parse_array(text, "validpgpkeys"):
        report.add(MEDIUM, "signature-not-verified",
                   "a signature source is declared but validpgpkeys is absent: any trusted key "
                   "in the user's keyring is accepted",
                   line=line_of(text, "source="), evidence="no validpgpkeys= in the PKGBUILD")
    pkgnames = vars_.get("_pkgnames") or []
    if looks_prebuilt(function_bodies(text), report.sources, pkgnames):
        report.add(MEDIUM, "prebuilt-payload",
                   "prebuilt payload: the package ships a downloaded binary or archive, so the "
                   "checksum binds the download, not its provenance; compare it with an "
                   "upstream-published hash or signature before PASS",
                   evidence=", ".join(pkgnames) or vars_.get("pkgname", ""))

    if not report.sources:
        report.add(INFO, "no-sources", "PKGBUILD declares no sources (meta or prebuilt package)")
    return report.sources


def expand_vars(value: str, vars_: dict[str, str]) -> tuple[str, bool]:
    ok = True

    def repl(m: re.Match) -> str:
        nonlocal ok
        key = m.group(1) or m.group(2)
        if key in vars_:
            return vars_[key]
        ok = False
        return m.group(0)

    # Only a complete `$name` or `${name}`; `${name/pat/rep}` is left intact and
    # reported as unresolved, never half-expanded.
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, value), ok


def expand_deep(value: str, vars_: dict[str, str]) -> tuple[str, bool]:
    """Expand nested `$url`/`${_tag}` references, with a cycle and depth cap."""
    cur, ok, seen = value, True, set()
    for _ in range(8):
        if cur in seen:
            break
        seen.add(cur)
        nxt, this_ok = expand_vars(cur, vars_)
        ok = ok and this_ok
        if nxt == cur:
            break
        cur = nxt
    return cur, ok


def _new_hash(alg: str):
    return hashlib.new(alg.replace("sums", "").replace("b2", "blake2b"))


def _digest_file(path: str, alg: str) -> str:
    h = _new_hash(alg)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _digest_file_multi(path: str, algs: list[str]) -> dict[str, str]:
    hs = {alg: _new_hash(alg) for alg in algs}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for h in hs.values():
                h.update(chunk)
    return {alg: h.hexdigest() for alg, h in hs.items()}


def _digest_url_multi(url: str, algs: list[str], cache_path: str | None = None) -> dict[str, str]:
    """Download once and hash the same bytes with every requested algorithm.

    With `cache_path`, reuse an already verified download or persist the bytes
    for the later build (`SRCDEST`), so the same payload is not fetched twice.
    """
    if cache_path and os.path.isfile(cache_path):
        return _digest_file_multi(cache_path, algs)
    hs = {alg: _new_hash(alg) for alg in algs}
    total = 0
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    part = cache_path + ".part" if cache_path else None
    out = open(part, "wb") if part else None
    try:
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as r:
            final = r.geturl()
            if urllib.parse.urlsplit(final).scheme != "https":
                raise ValueError(f"redirected to non-https: {final}")
            for chunk in iter(lambda: r.read(1 << 20), b""):
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise ValueError("larger than the 4 GiB audit cap")
                if out:
                    out.write(chunk)
                for h in hs.values():
                    h.update(chunk)
    except BaseException:
        if out:
            out.close()
            out = None
        if part:
            try:
                os.unlink(part)
            except OSError:
                pass
        raise
    finally:
        if out:
            out.close()
    if part:
        os.replace(part, cache_path)
    return {alg: h.hexdigest() for alg, h in hs.items()}


def upstream_sums(url: str) -> tuple[dict[str, str] | None, str]:
    """The SHA256SUMS beside a GitHub release asset, or (None, why)."""
    m = GITHUB_RELEASE_RE.match(url)
    if not m:
        return None, "not a GitHub release asset"
    owner, repo, tag, _asset = m.groups()
    sums_url = f"https://github.com/{owner}/{repo}/releases/download/{tag}/SHA256SUMS"
    if sums_url in SUMS_CACHE:
        return SUMS_CACHE[sums_url]
    try:
        req = urllib.request.Request(sums_url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read(1 << 20).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        SUMS_CACHE[sums_url] = (None, "no upstream SHA256SUMS reachable")
        return SUMS_CACHE[sums_url]
    entries: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            entries[parts[1].lstrip("*")] = parts[0].lower()
    SUMS_CACHE[sums_url] = (entries, "" if entries else "upstream SHA256SUMS is empty")
    return SUMS_CACHE[sums_url]


def npm_packument(url: str) -> tuple[dict | None, str]:
    """The npm version document whose dist.tarball is `url`, or (None, why)."""
    m = NPM_TARBALL_RX.match(url)
    if not m:
        return None, "not an npm registry tarball"
    if url in NPM_META_CACHE:
        return NPM_META_CACHE[url]
    pkg = m.group(1)
    try:
        doc = json.loads(fetch(f"https://registry.npmjs.org/{pkg}"))
    except (SystemExit, ValueError):
        NPM_META_CACHE[url] = (None, "npm metadata unreachable")
        return NPM_META_CACHE[url]
    for version, item in (doc.get("versions") or {}).items():
        dist = item.get("dist") or {}
        if dist.get("tarball") == url:
            meta = {
                "package": pkg,
                "version": version,
                "integrity": dist.get("integrity", ""),
                "shasum": dist.get("shasum", ""),
                "signatures": dist.get("signatures") or [],
            }
            NPM_META_CACHE[url] = (meta, "")
            return NPM_META_CACHE[url]
    NPM_META_CACHE[url] = (None, "tarball not listed in npm metadata")
    return NPM_META_CACHE[url]


def npm_verify_signatures(meta: dict) -> tuple[bool | None, str]:
    """Verify the registry's ECDSA signatures over name@version:integrity."""
    global NPM_KEYS_CACHE
    sigs = meta.get("signatures") or []
    if not sigs:
        return None, "no npm registry signatures"
    if not shutil.which("openssl"):
        return None, "openssl absent"
    if NPM_KEYS_CACHE is None:
        try:
            keys_doc = json.loads(fetch("https://registry.npmjs.org/-/npm/v1/keys"))
            NPM_KEYS_CACHE = {k["keyid"]: k["key"] for k in keys_doc.get("keys", [])}
        except (SystemExit, ValueError, KeyError, TypeError):
            return None, "npm keys unreachable"
    message = f'{meta["package"]}@{meta["version"]}:{meta["integrity"]}'.encode()
    verified = 0
    with tempfile.TemporaryDirectory() as tmp:
        msg_path = os.path.join(tmp, "msg.bin")
        with open(msg_path, "wb") as f:
            f.write(message)
        for index, sig in enumerate(sigs):
            key = NPM_KEYS_CACHE.get(sig.get("keyid", ""))
            if not key:
                continue
            key_path = os.path.join(tmp, f"key{index}.der")
            sig_path = os.path.join(tmp, f"sig{index}.der")
            with open(key_path, "wb") as f:
                f.write(base64.b64decode(key))
            with open(sig_path, "wb") as f:
                f.write(base64.b64decode(sig["sig"]))
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", key_path, "-keyform", "DER",
                 "-signature", sig_path, msg_path],
                capture_output=True,
            )
            verified += result.returncode == 0
    return verified == len(sigs), f"npm registry signatures {verified}/{len(sigs)} verified"


def _record_hash(report: Report, src: Source, alg: str, got: str, wanted: str, label: str) -> None:
    want = wanted.strip().lower()
    ok = (got.startswith(want) or want.startswith(got)) if alg == "b2sums" else got == want
    if ok:
        src.verify = "verified"
        return
    src.verify = f"MISMATCH {got[:16]}"
    report.add(HIGH, "checksum-mismatch",
               f"{label} does not match the declared {alg}",
               line=src.line, evidence=(src.resolved or src.url)[:200])


def _safe_cache_name(name: str) -> bool:
    return bool(name) and name not in (".", "..") and name == os.path.basename(name) and "/" not in name and "\\" not in name


def verify_sources(report: Report, vars_: dict[str, str], root: str, remote: bool = True,
                  cache_dir: str | None = None) -> tuple[int, int]:
    """Verify local snapshot files always, remote sources when `remote` is set.

    Returns (downloaded, cached): how many remote sources were fetched versus
    read back from `cache_dir`. The cache lets a later makepkg reuse the exact
    bytes under `SRCDEST`.
    """
    downloaded = 0
    cached = 0
    root_real = os.path.realpath(root)
    for src in report.sources:
        if src.vcs:
            src.verify = "not-applicable"
            continue
        # A remote signature is an attestation, not a file to hash here; a local
        # one is still a snapshot file and is hashed below.
        if src.sig and src.scheme != "":
            src.verify = "not-applicable"
            continue
        if src.verify in ("local-escapes-snapshot", "unexpanded-variable"):
            continue
        alg = next((a for a in STRONG if src.sums.get(a) and src.sums[a].upper() != "SKIP"), None)
        if not alg:
            # A signature with no hash is exempt by design; anything else is a gap.
            src.verify = "not-applicable" if src.sig else "no-strong-sum"
            continue
        if src.scheme == "":
            if not src.resolved:
                src.verify = "unexpanded-variable"
                report.add(MEDIUM, "source-unverified",
                           "local source name uses a variable the collector cannot expand; hash it by hand",
                           line=src.line, evidence=src.raw[:200])
                continue
            path = os.path.realpath(os.path.join(root, src.resolved))
            if path != root_real and not path.startswith(root_real + os.sep):
                src.verify = "local-escapes-snapshot"
                report.add(MEDIUM, "source-unverified",
                           f"local source {src.resolved!r} resolves outside the snapshot; not read",
                           line=src.line, evidence=src.raw[:200])
                continue
            if not os.path.isfile(path):
                src.verify = "local-missing"
                report.add(MEDIUM, "source-unverified",
                           f"local source {src.resolved!r} is absent from the snapshot",
                           line=src.line, evidence=src.raw[:200])
                continue
            _record_hash(report, src, alg, _digest_file(path, alg), src.sums[alg], "snapshot file")
            continue
        if src.scheme != "https":
            src.verify = "unverifiable"
            continue
        if not remote:
            continue
        if not src.resolved:
            src.verify = "unexpanded-variable"
            report.add(MEDIUM, "source-unverified",
                       "source URL uses a variable the collector cannot expand; verify by hand",
                       line=src.line, evidence=src.raw[:200])
            continue
        npm = bool(NPM_TARBALL_RX.match(src.resolved))
        want_upstream = bool(GITHUB_RELEASE_RE.match(src.resolved))
        algs = [alg]
        if want_upstream and alg != "sha256sums":
            algs.append("sha256sums")
        if npm:
            for extra in ("sha512sums", "sha1sums"):
                if extra not in algs:
                    algs.append(extra)
        cache_path = None
        if cache_dir and _safe_cache_name(src.filename):
            cache_path = os.path.join(cache_dir, src.filename)
        was_cached = bool(cache_path and os.path.isfile(cache_path))
        try:
            digests = _digest_url_multi(src.resolved, algs, cache_path)
        except (urllib.error.URLError, OSError, ValueError) as e:
            src.verify = f"download-failed: {str(e)[:120]}"
            report.add(MEDIUM, "source-unverified",
                       "source could not be downloaded for checksum verification "
                       f"({src.verify}); fetch it and compare by hand",
                       line=src.line, evidence=src.resolved[:200])
            continue
        if was_cached:
            cached += 1
        else:
            downloaded += 1
        got = digests[alg]
        _record_hash(report, src, alg, got, src.sums[alg], "downloaded source")
        if src.verify != "verified":
            if cache_path and os.path.isfile(cache_path):
                try:
                    os.unlink(cache_path)
                except OSError:
                    pass
            continue
        if npm:
            meta, why = npm_packument(src.resolved)
            if meta is None:
                src.provenance = ("npm metadata unreachable; integrity not compared"
                                  if why == "npm metadata unreachable"
                                  else f"npm provenance unavailable: {why}")
                continue
            integrity = meta.get("integrity", "")
            got512 = digests.get("sha512sums", "")
            ok512 = bool(integrity.startswith("sha512-") and got512) and (
                base64.b64encode(bytes.fromhex(got512)).decode() == integrity.split("-", 1)[1])
            got1 = digests.get("sha1sums", "")
            ok1 = bool(meta.get("shasum")) and got1 == meta.get("shasum")
            sig_ok, sig_msg = npm_verify_signatures(meta)
            if sig_msg == "no npm registry signatures":
                sig_text = "no registry signatures"
            elif sig_ok is None:
                sig_text = f"signatures not checked ({sig_msg})"
            else:
                sig_text = sig_msg
            src.provenance = (f"npm {meta['package']}@{meta['version']}: "
                              f"sha512 integrity {'matches' if ok512 else 'differs'}, "
                              f"sha1 shasum {'matches' if ok1 else 'differs'}, {sig_text}")
            if not ok512 or not ok1 or sig_ok is False:
                report.add(HIGH, "provenance-mismatch",
                           "npm metadata contradicts the downloaded tarball",
                           line=src.line, evidence=src.resolved[:200])
            continue
        if not want_upstream:
            src.provenance = "not a GitHub release asset"
            continue
        entries, why = upstream_sums(src.resolved)
        if entries is None:
            src.provenance = why
            continue
        asset = src.resolved.rsplit("/", 1)[-1]
        sha256_got = digests.get("sha256sums")
        if asset not in entries:
            src.provenance = "asset absent from upstream SHA256SUMS"
        elif sha256_got is not None and entries[asset] == sha256_got:
            src.provenance = "upstream SHA256SUMS matches"
        else:
            src.provenance = "upstream SHA256SUMS differs"
            report.add(HIGH, "provenance-mismatch",
                       "the file matches the PKGBUILD but not the checksum upstream published for it",
                       line=src.line, evidence=src.resolved[:200])
    return downloaded, cached

def scan_pkgbuild(report: Report, text: str) -> dict[str, str]:
    funcs = function_bodies(text)
    for name, start, _end, body, _bs, _be in funcs:
        scan_body(report, "PKGBUILD", body, start, f"{name}()")

    # Blank every function body so the top-level pass sees only code that runs
    # when the PKGBUILD is sourced. Newlines are preserved, and text before or
    # after a definition on the same line is still visible.
    top = mask_spans(text, [(bs, be) for _n, _s, _e, _b, bs, be in funcs])
    array_spans: list[tuple[int, int]] = []
    for m in re.finditer(rf"^[ \t]*{NAME_RE}\+?=\s*\(", top, re.MULTILINE):
        end = _match_paren(top, m.end() - 1)
        if end > 0:
            array_spans.append((line_at(top, m.start()), line_at(top, end)))
    echo_alt = "|".join(re.escape(x) for x in sorted(ECHO_SAFE))
    allowed = re.compile(
        r"^[ \t]*(?:"
        + NAME_RE + r"\+?=|"
        + NAME_RE + r"\[[^\]]+\]\+?=|"
        + NAME_RE + r"[ \t]*\(\)[ \t]*\{?|"
        r"function[ \t]+" + NAME_RE + r"[ \t]*(?:\(\))?[ \t]*\{?|"
        r"[A-Za-z0-9_*?|.-]+\)|"
        r"#|$|[{}]|"
        r"if\b|then\b|else\b|elif\b|fi\b|for\b|do\b|done\b|while\b|until\b|select\b|"
        r"case\b|esac\b|:(?:\s|$)|\[\[?|test\b|export\b|unset\b|"
        + echo_alt + r"\b)"
    )
    local_fn = {f[0] for f in funcs}
    dangerous_subst = re.compile(
        r"\$\([^)]*(?:\b(?:curl|wget|aria2c|ncat|socat|nc|sh|bash|zsh|eval|base64|"
        r"python[0-9.]*|perl|sudo|su)\b|[|;])"
        r"|`[^`]*(?:\b(?:curl|wget|sh|bash|eval)\b|[|;])"
    )
    for idx, raw in enumerate(top.splitlines(), start=1):
        s = strip_comment(raw).strip()
        if not s:
            continue
        substituted = "$(" in s or "`" in s
        if substituted:
            sev = HIGH if dangerous_subst.search(s) else MEDIUM
            code = "dynamic-shell" if sev == HIGH else "top-level-substitution"
            report.add(sev, code,
                       "top level: command substitution runs when the PKGBUILD is sourced",
                       line=idx, evidence=s[:220])
            continue
        first_match = re.match(r"^[ \t]*([A-Za-z_][A-Za-z0-9_-]*)", raw)
        first_name = first_match.group(1) if first_match else ""
        if allowed.match(raw) or first_name in local_fn:
            if (re.match(r"^[ \t]*(?:if|elif|while|until)\b", raw)
                    or CHAIN_META.search(s)):
                for rx, sev, code, why in BODY_RULES:
                    if rx.search(s):
                        report.add(sev, code, f"top level: {why}", line=idx, evidence=s[:220])
            continue
        if any(a <= idx <= b for a, b in array_spans):
            continue
        hits = [(sev, code, why) for rx, sev, code, why in BODY_RULES if rx.search(s)]
        if hits:
            for sev, code, why in hits:
                report.add(sev, code, f"top level: {why}", line=idx, evidence=s[:220])
        else:
            report.add(MEDIUM, "top-level-command",
                       "statement outside a function runs when the PKGBUILD is sourced",
                       line=idx, evidence=s[:220])

    pkgver, pkgrel = parse_scalar(text, "pkgver"), parse_scalar(text, "pkgrel")
    license_ = parse_array_head(text, "license")
    if not license_ or any(v.lower() in ("unknown", "custom") for v, _ in license_):
        report.add(MEDIUM, "license-unknown", "license is missing, 'unknown', or 'custom'",
                   line=line_of(text, "license="))
    arch = parse_array_head(text, "arch")
    if any(v == "any" for v, _ in arch) and any(f[0] in ("build", "package") for f in funcs):
        report.add(INFO, "arch-any", "arch=('any') on a package with build/package logic")

    return {"pkgver": pkgver or "", "pkgrel": pkgrel or "", "epoch": parse_scalar(text, "epoch") or ""}


def parse_srcinfo(path: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "=" in line:
                k, v = line.split("=", 1)
                out.setdefault(k.strip(), []).append(v.strip())
    return out


SRCINFO_ARRAYS = {"source", "depends", "makedepends", "checkdepends", "arch", "license"}
SRCINFO_ARRAYS |= set(SUMS)


def audit_pkgbuild_dir(report: Report, root: str, vars_: dict[str, str],
                       aur_mode: bool = False) -> str:
    pkgbuild = root if root.endswith("PKGBUILD") else os.path.join(root, "PKGBUILD")
    if not os.path.isfile(pkgbuild):
        raise SystemExit(f"aur-security-audit: no PKGBUILD at {pkgbuild}")
    with open(pkgbuild, encoding="utf-8", errors="replace") as f:
        text = f.read()
    if sh(["bash", "-n", pkgbuild]).returncode != 0:
        report.add(HIGH, "syntax-error", "bash -n rejects the PKGBUILD; reviewed text cannot be the executed text")
    vars_.update(scan_pkgbuild(report, text))
    for extra in ("pkgbase", "url", "pkgdesc", "install"):
        v = parse_scalar(text, extra)
        if v:
            vars_[extra] = v
    for m in re.finditer(r"^[ \t]*(_[A-Za-z0-9_]+)=([^\n#]*)", text, re.MULTILINE):
        vars_[m.group(1)] = m.group(2).strip().strip("'\"")
    pkgnames = [v for v, _ in (parse_array(text, "pkgname") or [])]
    if not pkgnames:
        scalar = parse_scalar(text, "pkgname")
        if scalar:
            pkgnames = [scalar]
    expanded_names = []
    for v in pkgnames:
        ev, ok = expand_deep(v, vars_)
        expanded_names.append(ev if ok else v)
    pkgnames = expanded_names
    if pkgnames:
        vars_["pkgname"] = pkgnames[0]
        vars_["_pkgnames"] = pkgnames
        vars_.setdefault("pkgbase", pkgnames[0])
    archs = [v for v, _ in parse_array_head(text, "arch")]
    if len(archs) == 1 and archs[0] != "any":
        vars_["CARCH"] = archs[0]
    parse_sources(report, text, vars_)
    scan_local_sources(report, os.path.dirname(pkgbuild))

    srcinfo = parse_srcinfo(os.path.join(os.path.dirname(pkgbuild), ".SRCINFO"))
    if not srcinfo and aur_mode:
        report.add(MEDIUM, "srcinfo-missing",
                   "the snapshot has no .SRCINFO; the AUR page and helpers show nothing verified",
                   file=".SRCINFO")
    for key in ("pkgver", "pkgrel", "epoch"):
        if srcinfo.get(key) and vars_.get(key):
            want, ok = expand_deep(vars_[key], vars_)
            if not ok or "$" in want:
                continue
            if srcinfo[key][0] != want:
                report.add(MEDIUM, "srcinfo-stale",
                           f".SRCINFO {key}={srcinfo[key][0]} disagrees with PKGBUILD {key}={want}",
                           file=".SRCINFO")
    is_split = len(pkgnames) > 1
    if is_split and srcinfo:
        report.add(INFO, "srcinfo-unchecked",
                   ".SRCINFO arrays not compared for a split package; per-package sections are flattened differently",
                   file=".SRCINFO")
    else:
        sum_prefixes = tuple(a + "_" for a in SUMS)
        for key, values in srcinfo.items():
            is_array = key in SRCINFO_ARRAYS or key.startswith(("source_", *sum_prefixes))
            if not is_array:
                continue
            if not array_is_static(text, key):
                report.add(INFO, "srcinfo-unchecked",
                           f".SRCINFO {key} not compared: conditional or indexed assignments "
                           "make the static array unreliable",
                           file=".SRCINFO")
                continue
            raw_items = [v for v, _ in (parse_array(text, key) or [])]
            expanded, unresolved = [], False
            for v in raw_items:
                ev, ok = expand_deep(v, vars_)
                unresolved = unresolved or not ok or "$" in ev
                expanded.append(ev)
            if raw_items == values or unresolved or expanded == values:
                continue
            src_item, pkg_item = first_diff(values, expanded)
            report.add(MEDIUM, "srcinfo-stale",
                       f".SRCINFO {key} disagrees with the PKGBUILD",
                       file=".SRCINFO",
                       evidence=f".SRCINFO={str(src_item)[:80]!r} "
                                f"PKGBUILD={str(pkg_item)[:80]!r}")

    declared_install = parse_scalar(text, "install")
    if declared_install:
        resolved, complete = expand_vars(declared_install, vars_)
        if complete and not os.path.isfile(os.path.join(os.path.dirname(pkgbuild), resolved)):
            report.add(MEDIUM, "install-missing", f"install={declared_install} resolves to {resolved}, absent from the snapshot")
    for name in sorted(os.listdir(os.path.dirname(pkgbuild))):
        if name.endswith(".install"):
            scan_install(report, os.path.join(os.path.dirname(pkgbuild), name))
    return pkgbuild


def human_report(report: Report) -> str:
    counts = {s: sum(1 for f in report.findings if f.severity == s) for s in (HIGH, MEDIUM, LOW, INFO)}
    if counts[HIGH]:
        verdict = "DO NOT BUILD"
    elif counts[MEDIUM]:
        verdict = "REVIEW"
    elif report.sources and not report.sources_verified:
        if any(s.vcs for s in report.sources):
            verdict = "REVIEW (VCS source: content not attested)"
        else:
            verdict = "REVIEW (sources unverified)"
    elif report.sources_verified:
        if any(s.sig for s in report.sources):
            verdict = "CLEAN (checksums verified; signatures not checked)"
        else:
            verdict = "CLEAN (sources verified)"
    else:
        verdict = "CLEAN (form only; no sources verified)"
    report.verdict = verdict
    head = f"AUR security audit: {report.package}" + (f" {report.version}" if report.version else "")
    if report.submitted or report.maintainer:
        meta = (f"Maintainer: {report.maintainer or 'ORPHAN'} | votes {report.votes} | "
                f"popularity {report.popularity} | submitted {report.submitted} | modified {report.last_modified}"
                + (f" | flagged out-of-date {report.out_of_date}" if report.out_of_date else ""))
    else:
        meta = "Metadata: AUR record not consulted (local PKGBUILD)"
    out = [head, meta,
           f"Verdict: {verdict}  (HIGH {counts[HIGH]} / MEDIUM {counts[MEDIUM]} / LOW {counts[LOW]} / INFO {counts[INFO]})",
           ""]
    if report.findings:
        out.append("Findings:")
        for f in sorted(report.findings, key=lambda f: (-RANK[f.severity], f.file, f.line or 0)):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            out.append(f"  [{f.severity:6}] {f.code:22} {loc:24} {f.message}")
            if f.evidence:
                out.append(f"           ↳ {f.evidence}")
        out.append("")
    if report.sources:
        out.append("Sources:")
        for s in report.sources:
            sums = ", ".join(f"{a}={'SKIP' if v.upper() == 'SKIP' else v[:12] + '…'}"
                             for a, v in s.sums.items()) or "no sums"
            kind = "vcs" if s.vcs else "sig" if s.sig else s.scheme or "local"
            shown = s.resolved or s.url
            out.append(f"  L{s.line or '?'} [{kind:4}] {shown[:110]}  ({sums}) verify={s.verify}")
            if s.provenance:
                out.append(f"           provenance: {s.provenance}")
        out.append("")
    if report.authors:
        out.append(f"History: {report.commits} commits")
        for a in report.authors[:6]:
            out.append(f"  {a['last'][:10]}  {a['commits']:4}  {a['name']} <{a['email']}>  {a['last_subject'][:70]}")
        out.append("")
    if report.last_change_diff:
        out.append("Last PKGBUILD/.install change:")
        out.extend("  " + ln for ln in report.last_change_diff.splitlines()[:60])
        out.append("")
    for n in report.notes:
        out.append(f"Note: {n}")
    return "\n".join(out)


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # usage errors must not look like HIGH findings
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: error: {message}\n")


def main() -> int:
    ap = Parser(description="Static security audit for an AUR package or local PKGBUILD.")
    ap.add_argument("package", nargs="?", help="AUR package name")
    ap.add_argument("--pkgbuild", help="local directory containing PKGBUILD, or a PKGBUILD path")
    ap.add_argument("--json", help="write machine-readable findings here")
    ap.add_argument("--verify-sources", action="store_true", help="download declared sources and recompute checksums")
    ap.add_argument("--cache-dir", metavar="DIR",
                    help="keep verified downloads here for reuse; makepkg can use the same directory via SRCDEST")
    ap.add_argument("--no-history", action="store_true", help="skip AUR git clone")
    ap.add_argument("--keep-snapshot", metavar="DIR",
                    help="keep the extracted snapshot and git clone under DIR for reading local sources")
    args = ap.parse_args()

    if not args.package and not args.pkgbuild:
        ap.error("give an AUR package name or --pkgbuild")

    keep = os.path.abspath(args.keep_snapshot) if args.keep_snapshot else None
    if args.pkgbuild:
        # A local audit reads the user's own directory; there is nothing to retain.
        workdir = tempfile.mkdtemp(prefix="aur-audit-")
    else:
        if keep:
            os.makedirs(keep, exist_ok=True)
        workdir = tempfile.mkdtemp(prefix="aur-audit-", dir=keep)
    try:
        vars_: dict[str, str] = {}
        if args.pkgbuild:
            root = args.pkgbuild
            name = os.path.basename(os.path.dirname(os.path.abspath(root))) if root.endswith("PKGBUILD") else os.path.basename(os.path.abspath(root))
            report = Report(package=name)
            pkgbuild = audit_pkgbuild_dir(report, root, vars_)
            source_root = os.path.dirname(os.path.abspath(pkgbuild))
            report.snapshot = source_root
        else:
            info = rpc_info(args.package)
            report = Report(package=info["Name"], version=info.get("Version"),
                            maintainer=info.get("Maintainer"),
                            submitted=time.strftime("%Y-%m-%d", time.gmtime(info["FirstSubmitted"])) if info.get("FirstSubmitted") else None,
                            last_modified=time.strftime("%Y-%m-%d", time.gmtime(info["LastModified"])) if info.get("LastModified") else None,
                            out_of_date=time.strftime("%Y-%m-%d", time.gmtime(info["OutOfDate"])) if info.get("OutOfDate") else None,
                            votes=info.get("NumVotes"), popularity=round(info.get("Popularity", 0.0), 2))
            pkgbase = info.get("PackageBase") or info["Name"]
            if not report.maintainer:
                report.add(MEDIUM, "orphan",
                           "package has no maintainer; anyone can adopt it, so audit the version you build "
                           "and re-audit on update")
            else:
                report.notes.append(aur_maintainer_portfolio(report.maintainer))
            snap = load_snapshot(pkgbase, workdir)
            report.snapshot = snap
            source_root = snap
            audit_pkgbuild_dir(report, snap, vars_, aur_mode=True)
            if not args.no_history:
                authors, commits, diff, err = git_history(pkgbase, workdir)
                if err:
                    report.history_note = err
                else:
                    report.authors, report.commits, report.last_change_diff = authors, commits, diff
                    if len(authors) >= 2 and authors[0]["email"] != authors[1]["email"] and authors[0]["commits"] <= 2:
                        report.add(MEDIUM, "committer-change",
                                   f"newest commits are by {authors[0]['name']!r} ({authors[0]['commits']} commit(s)); "
                                   f"previous author was {authors[1]['name']!r} ({authors[1]['commits']} commits)",
                                   file="git", evidence=f"{authors[0]['last'][:10]} {authors[0]['last_subject'][:120]}")
                    if commits <= 3:
                        report.add(INFO, "thin-history", f"only {commits} commits; little review trail")

        if args.cache_dir:
            os.makedirs(args.cache_dir, exist_ok=True)
        downloaded, cached = verify_sources(report, vars_, source_root,
                                            remote=args.verify_sources, cache_dir=args.cache_dir)
        verified_all = bool(report.sources) and all(
            s.verify == "verified" or (s.sig and s.verify == "not-applicable")
            for s in report.sources
        )
        report.sources_verified = verified_all and not any(s.vcs for s in report.sources)
        if args.pkgbuild:
            report.notes.append("local audit: AUR metadata and git history were not consulted")
        elif args.no_history:
            report.notes.append("AUR git history skipped (--no-history)")
        if not args.verify_sources:
            report.notes.append("remote sources were not downloaded (rerun with --verify-sources); "
                                "local snapshot files were hashed")
        elif args.cache_dir and (downloaded or cached):
            report.notes.append(f"downloaded {downloaded} sources into {args.cache_dir}; "
                                f"reuse with SRCDEST={args.cache_dir} makepkg -s")
            if cached:
                report.notes.append(f"{cached} sources were read from the cache")
        if keep:
            report.notes.append(f"snapshot kept at {report.snapshot or workdir}")
        elif not args.pkgbuild:
            report.snapshot = None  # the temporary extraction is deleted below
        print(human_report(report))
        if args.json:
            payload = {
                "package": report.package, "version": report.version, "maintainer": report.maintainer,
                "submitted": report.submitted, "last_modified": report.last_modified,
                "out_of_date": report.out_of_date, "votes": report.votes, "popularity": report.popularity,
                "commits": report.commits, "authors": report.authors, "history_note": report.history_note,
                "last_change_diff": report.last_change_diff, "notes": report.notes,
                "snapshot": report.snapshot, "sources_verified": report.sources_verified,
                "verdict": report.verdict,
                "sources": [s.__dict__ for s in report.sources],
                "findings": [f.__dict__ for f in report.findings],
            }
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        return 2 if any(f.severity == HIGH for f in report.findings) else 0
    finally:
        if args.pkgbuild or not keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
