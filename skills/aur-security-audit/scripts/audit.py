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
import http.client
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
from functools import lru_cache
from typing import IO, Any, NoReturn, cast

_v = sys.version_info[:3]
_TAR_FILTER_PATCHED = (
    _v >= (3, 14)
    or (3, 12, 11) <= _v < (3, 13)
    or (3, 13, 4) <= _v < (3, 14)
)
if not _TAR_FILTER_PATCHED:
    raise SystemExit(
        "aur-security-audit: needs Python 3.12.11+, 3.13.4+, or 3.14+ "
        "(tarfile data filter, CVE-2025-4517)"
    )

AUR = "https://aur.archlinux.org"
UA = "aur-security-audit/1.0 (+static PKGBUILD review)"
MAX_DOWNLOAD = 4 << 30  # refuse a source larger than 4 GiB instead of hashing forever
DOWNLOAD_TIMEOUT = 60   # seconds per network operation; a blocked host must not stall the audit
HIGH, MEDIUM, LOW, INFO = "HIGH", "MEDIUM", "LOW", "INFO"
RANK = {HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

SUMS = {"sha512sums": 128, "sha384sums": 96, "sha256sums": 64, "sha224sums": 56,
        "b2sums": 128, "sha1sums": 40, "md5sums": 32}
STRONG = ("sha512sums", "sha384sums", "sha256sums", "sha224sums", "b2sums")
# makepkg only treats these as detached signatures (verify_signature.sh).
SIG_SUFFIX = (".sig", ".asc", ".sign")
PATCH_SUFFIX = (".patch", ".diff")
VCS_PREFIX = ("git+", "svn+", "hg+", "bzr+", "fossil+")
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
INSTALL_MODE_RX = re.compile(
    r"\b(?:install|cp)\b[^\n]*?(?:-[A-Za-z]*m|--mode(?:=|\s+))\s*0?[1-7][0-7]{3}\b")
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
    authors: list[dict[str, Any]] = field(default_factory=list)
    pkgnames: list[str] = field(default_factory=list)
    commits: int | None = None
    last_change_diff: str | None = None
    history_note: str | None = None
    notes: list[str] = field(default_factory=list)
    snapshot: str | None = None
    sources_verified: bool = False
    verdict: str = "REVIEW"

    def add(self, severity: str, code: str, message: str, *,
            file: str = "PKGBUILD", line: int | None = None,
            evidence: str | None = None) -> None:
        self.findings.append(Finding(severity, code, message, file=file, line=line,
                                     evidence=evidence))


def fetch(url: str, timeout: int = 40, attempts: int = 2,
          max_bytes: int = 256 << 20) -> bytes:
    last: Exception | None = None
    for attempt in range(attempts):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                final = r.geturl()
                if urllib.parse.urlsplit(final).scheme != "https":
                    raise ValueError(f"redirected to non-https: {final}")
                data: bytes = r.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise ValueError(f"response larger than {max_bytes} bytes: {url}")
                return data
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            if attempt + 1 < attempts:
                time.sleep(2)
        except ValueError as e:
            raise SystemExit(f"aur-security-audit: {e}")
    raise SystemExit(f"aur-security-audit: request failed for {url}: {last}")


def line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def line_of(text: str, needle: str) -> int | None:
    pos = text.find(needle)
    return line_at(text, pos) if pos >= 0 else None


def sh(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout,
                          check=False, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})


def rpc_info(name: str) -> dict[str, Any]:
    raw = fetch(f"{AUR}/rpc/v5/info?arg[]={urllib.parse.quote(name)}")
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit(f"aur-security-audit: AUR RPC returned invalid JSON: {e}")
    if not isinstance(data, dict):
        raise SystemExit("aur-security-audit: AUR RPC returned an unexpected payload")
    results = data.get("results", [])
    if not results:
        raise SystemExit(f"aur-security-audit: no AUR package named {name!r}")
    for r in results:
        if r.get("Name") == name:
            return cast(dict[str, Any], r)
    return cast(dict[str, Any], results[0])


def aur_maintainer_portfolio(name: str) -> str:
    """Context for a new or repack-heavy maintainer account."""
    try:
        raw = fetch(f"{AUR}/rpc/v5/search/{urllib.parse.quote(name)}?by=maintainer")
        data: Any = json.loads(raw)
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
        if m.issym() or m.islnk():
            base = os.path.dirname(target) if m.issym() else root
            link = os.path.realpath(os.path.join(base, m.linkname))
            if not link.startswith(root + os.sep) and link != root:
                raise SystemExit(f"snapshot link escapes destination: {m.name} -> {m.linkname}")
    try:
        tar.extractall(dest, filter="data")
    except tarfile.TarError as e:
        raise SystemExit(f"snapshot extraction refused: {e}")


def load_snapshot(pkgbase: str, workdir: str) -> str:
    url = f"{AUR}/cgit/aur.git/snapshot/{urllib.parse.quote(pkgbase)}.tar.gz"
    blob = fetch(url)
    if not blob:
        raise SystemExit("aur-security-audit: AUR returned an empty snapshot; retry the audit")
    tar_path = os.path.join(workdir, f"{pkgbase}.tar.gz")
    with open(tar_path, "wb") as f:
        f.write(blob)
    try:
        with tarfile.open(tar_path) as tar:
            safe_extract(tar, workdir)
    except tarfile.TarError as e:
        raise SystemExit(f"aur-security-audit: snapshot is not a readable tarball: {e}")
    snap = os.path.join(workdir, pkgbase)
    if not os.path.isdir(snap):
        raise SystemExit(f"snapshot layout unexpected for {pkgbase}")
    return snap


def git_history(pkgbase: str, workdir: str) -> tuple[list[dict], int, str | None, str | None]:
    repo = os.path.join(workdir, "git")
    try:
        cp = sh(["git", "clone", "--quiet", f"{AUR}/{pkgbase}.git", repo], timeout=180)
    except subprocess.TimeoutExpired:
        return [], 0, None, "git clone timed out"
    if cp.returncode != 0:
        return [], 0, None, cp.stderr.strip()[:300]
    try:
        log = sh(["git", "-C", repo, "log", "--format=%h%x1f%an%x1f%ae%x1f%aI%x1f%s"], timeout=60)
    except subprocess.TimeoutExpired:
        return [], 0, None, "git log timed out"
    if log.returncode != 0:
        return [], 0, None, log.stderr.strip()[:300]
    rows = [r.split("\x1f", 4) for r in log.stdout.splitlines() if r.strip()]
    rows = [r for r in rows if len(r) == 5]  # a hostile ident must not crash the audit
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
    try:
        d = sh(["git", "-C", repo, "diff", "--unified=2", "HEAD~1", "HEAD",
                "--", "PKGBUILD", "*.install"], timeout=60)
        if d.returncode == 0:
            diff = d.stdout.strip()
    except subprocess.TimeoutExpired:
        pass
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


BRACE_LIMIT = 4096


class _BraceLimit(Exception):
    """Raised when a hostile expansion exceeds BRACE_LIMIT."""


def brace_expand(word: str) -> list[str]:
    """Expand one non-parameter, unquoted `{a,b}` or `{n..m}` group, as makepkg sees it.

    Expansions are capped: a hostile PKGBUILD must not be able to hang the audit
    with nested comma groups. An over-limit word is returned unexpanded.
    """
    try:
        return _brace_expand(word)
    except _BraceLimit:
        return [word]


def _brace_expand(word: str) -> list[str]:
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
            alts: list[str]
            if "," in inner:
                alts = _split_alts(inner)
            else:
                rng = re.fullmatch(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?", inner)
                if not rng:
                    return [word]
                a, b = int(rng.group(1)), int(rng.group(2))
                step = int(rng.group(3)) if rng.group(3) else (1 if b >= a else -1)
                if step == 0:
                    return [word]
                count = abs((b - a) // step) + 1
                if count > BRACE_LIMIT:
                    raise _BraceLimit
                alts = [str(n) for n in range(a, b + (1 if step > 0 else -1), step)]
            out: list[str] = []
            for alt in alts:
                out.extend(_brace_expand(word[:i] + alt + word[j + 1:]))
                if len(out) > BRACE_LIMIT:
                    raise _BraceLimit
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
        elif c == "\\" and i + 1 < len(body) and body[i + 1] == "\n":
            i += 2
            continue
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


def function_spans(text: str) -> list[tuple[int, int]]:
    """Character spans of every function body, so build-time assignments can be separated."""
    return [(f[4], f[5]) for f in function_bodies(text)]


def _mask_quotes(line: str) -> str:
    """Blank quoted spans so keyword detection does not see prose."""
    out: list[str] = []
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                out.append("  ")
                i += 2
                continue
            if c == quote:
                quote = None
            out.append(" ")
        elif c in "'\"":
            quote = c
            out.append(" ")
        else:
            out.append(c)
        i += 1
    return "".join(out)


@lru_cache(maxsize=16)
def conditional_lines(text: str) -> frozenset[int]:
    """Lines inside a conditional or loop block, where makepkg may never run the code."""
    top = mask_spans(text, function_spans(text))
    lines: set[int] = set()
    depth = 0
    paren = 0
    for no, line in enumerate(top.splitlines(), start=1):
        bare = _mask_quotes(strip_comment(line))
        before, paren_before = depth, paren
        words = re.findall(r"\b(if|case|for|while|until|select|fi|esac|done)\b", bare)
        for word in words:
            if word in ("if", "case", "for", "while", "until", "select"):
                depth += 1
            else:
                depth = max(0, depth - 1)
        paren = max(0, paren + bare.count("(") - bare.count(")"))
        if (before or paren_before or words or re.search(r"&&|\|\|", bare)):
            lines.add(no)
    return frozenset(lines)


def _scoped(pos: int, line: int, spans: list[tuple[int, int]],
            conds: frozenset[int]) -> bool:
    return line in conds or any(start <= pos < end for start, end in spans)


def scoped_assignments(text: str, name: str) -> list[tuple[str, int]]:
    """Assignments to `name` that live in a function body or conditional block."""
    spans, conds = function_spans(text), conditional_lines(text)
    out: list[tuple[str, int]] = []
    for m in re.finditer(rf"^[ \t]*{re.escape(name)}\+?=\s*\(", text, re.MULTILINE):
        line = line_at(text, m.start())
        if _scoped(m.start(), line, spans, conds):
            out.append(("array", line))
    for m in re.finditer(
            rf"^[ \t]*{re.escape(name)}\[[^\]]+\][+]?=\s*[^\n]*", text, re.MULTILINE):
        line = line_at(text, m.start())
        if _scoped(m.start(), line, spans, conds):
            out.append(("index", line))
    return out


def parse_any(text: str, name: str) -> list[tuple[str, int]] | None:
    """Array form when present, scalar fallback otherwise (both are valid bash)."""
    items = parse_array(text, name)
    if items:
        return items
    value = parse_scalar(text, name)
    if value is None or value == "":
        return None
    return [(value, line_of(text, name + "=") or 0)]


def parse_array(text: str, name: str) -> list[tuple[str, int]] | None:
    """Effective top-level `name=(...)`, `name+=(...)`, and `name[i]=value` assignments.

    Assignments inside a function body or a conditional block are skipped: makepkg
    verifies checksums before those run, so they never define the build-time array.
    A non-literal top-level index is reported by `indexed_assignments()`.
    """
    spans, conds = function_spans(text), conditional_lines(text)
    ArrayPayload = list[tuple[str, int]]
    IndexPayload = tuple[str, str, str, int]
    events: list[tuple[int, str, ArrayPayload | IndexPayload]] = []
    for m in re.finditer(rf"^[ \t]*{re.escape(name)}\+?=\s*\(", text, re.MULTILINE):
        if _scoped(m.start(), line_at(text, m.start()), spans, conds):
            continue
        open_paren = m.end() - 1
        end = _match_paren(text, open_paren)
        if end < 0:
            continue
        events.append((m.start(), "array",
                       _split_items(text[open_paren + 1:end - 1], open_paren + 1, text)))
    for m in re.finditer(
            rf"^[ \t]*{re.escape(name)}\[([^\]]+)\]([+]?)=\s*([^\n]*)", text, re.MULTILINE):
        if _scoped(m.start(), line_at(text, m.start()), spans, conds):
            continue
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
            items.extend(cast(ArrayPayload, payload))
            continue
        idx_raw, op, value, line = cast(IndexPayload, payload)
        if not re.fullmatch(r"\d+", idx_raw):
            continue
        idx = int(idx_raw)
        while len(items) <= idx:
            items.append(("", line))
        items[idx] = ((items[idx][0] + value) if op == "+" else value, line)
    return items


def indexed_assignments(text: str, name: str) -> list[tuple[str, int]]:
    """Every top-level `name[expr]=...` index expression and its line."""
    spans, conds = function_spans(text), conditional_lines(text)
    out: list[tuple[str, int]] = []
    for m in re.finditer(
            rf"^[ \t]*{re.escape(name)}\[([^\]]+)\][+]?=\s*[^\n]*", text, re.MULTILINE):
        line = line_at(text, m.start())
        if _scoped(m.start(), line, spans, conds):
            continue
        out.append((m.group(1).strip(), line))
    return out


def array_is_static(text: str, name: str) -> bool:
    """False when `+=`, an index, or a scoped assignment makes the final array unknowable."""
    return not (
        re.search(rf"^[ \t]*{re.escape(name)}\+=", text, re.MULTILINE)
        or re.search(rf"^[ \t]*{re.escape(name)}\[", text, re.MULTILINE)
        or scoped_assignments(text, name)
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
    raw_value = m.group(1).strip()
    if raw_value.startswith("("):  # `name=(...)` is an array, not a scalar
        return None
    return raw_value.strip("'\"")


@lru_cache(maxsize=16)
def function_bodies(text: str) -> list[tuple[str, int, int, str, int, int]]:
    """(name, start_line, end_line, body, body_start, body_end) for every function.

    Accepts `name() {`, `name () {`, `function name {` and `function name() {`,
    with any amount of whitespace, blank lines, or comments between `()` and `{`.
    Names may contain hyphens, as bash allows. Every definition is returned,
    including duplicates, because a conditional branch may decide which one runs.
    """
    out: list[tuple[str, int, int, str, int, int]] = []
    pat = re.compile(
        r"^[ \t]*(?:function[ \t]+(" + NAME_RE + r")[ \t]*(?:\(\))?"
        r"|(" + NAME_RE + r")[ \t]*\(\))",
        re.MULTILINE,
    )
    for m in pat.finditer(text):
        j = m.end()
        while True:
            while j < len(text) and text[j] in " \t\r":
                j += 1
            if j < len(text) and text[j] == "#":
                nl = text.find("\n", j)
                j = len(text) if nl < 0 else nl + 1
                continue
            if j < len(text) and text[j] == "\n":
                j += 1
                continue
            break
        if j >= len(text) or text[j] != "{":
            continue
        name = m.group(1) or m.group(2)
        body_start = j + 1
        depth, paren, param, i, quote = 1, 0, 0, body_start, None
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
            elif c == "(":
                paren += 1
            elif c == ")":
                paren = max(0, paren - 1)
            elif c == "{":
                if i > 0 and text[i - 1] == "$":
                    param += 1
                elif paren == 0:
                    depth += 1
            elif c == "}":
                if param:
                    param -= 1
                elif paren == 0:
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
    (INSTALL_MODE_RX, MEDIUM, "privilege",
     "installs a file with SUID/SGID/sticky bits; a deliberate design needs an upstream reason"),
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


def shell_words(line: str) -> str:
    """The line as bash word-splits it: unquote and resolve backslash escapes.

    `c\\url` and `"c"url` both become `curl`; a literal inside single quotes stays
    literal. Used for matching only; evidence keeps the original text.
    """
    out: list[str] = []
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote == "'":
            if c == "'":
                quote = None
            else:
                out.append(c)
        elif quote == '"':
            if c == "\\" and i + 1 < len(line) and line[i + 1] in '$`"\\\n':
                if line[i + 1] != "\n":
                    out.append(line[i + 1])
                i += 2
                continue
            if c == '"':
                quote = None
            else:
                out.append(c)
        else:
            if c == "\\" and i + 1 < len(line):
                if line[i + 1] != "\n":
                    out.append(line[i + 1])
                i += 2
                continue
            if c in "'\"":
                quote = c
            else:
                out.append(c)
        i += 1
    return "".join(out)


def has_unquoted_subst(line: str) -> bool:
    """True when `$(...)` or a backtick can execute (single quotes are literal)."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote == "'":
            if c == "'":
                quote = None
        elif quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
            elif c == "`" or (c == "$" and i + 1 < len(line) and line[i + 1] == "("):
                return True
        else:
            if c == "\\":
                i += 2
                continue
            if c in "'\"":
                quote = c
            elif c == "`" or (c == "$" and i + 1 < len(line) and line[i + 1] == "("):
                return True
        i += 1
    return False


def has_unquoted_meta(line: str) -> bool:
    """True when a chain, redirect, or substitution can run outside quotes.

    Quoted prose (`msg "run curl | bash"`) does not count; `$(...)` inside double
    quotes does, because bash executes it.
    """
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote == "'":
            if c == "'":
                quote = None
        elif quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
            elif c == "`" or (c == "$" and i + 1 < len(line) and line[i + 1] == "("):
                return True
        else:
            if c == "\\":
                i += 2
                continue
            if c in "'\"":
                quote = c
            elif c in ";&|`>" or (c == "$" and i + 1 < len(line) and line[i + 1] == "("):
                return True
        i += 1
    return False


def scan_body(report: Report, fname: str, body: str, first_line: int, where: str) -> None:
    for offset, raw in enumerate(body.splitlines()):
        line = first_line + offset
        bare = strip_comment(raw).strip()
        if not bare or bare.startswith("#"):
            continue
        s = shell_words(bare)
        if not s:
            continue
        first = s.split()[0]
        # An echo/printf line is inert only if nothing outside quotes can chain.
        if first in ECHO_SAFE and not has_unquoted_meta(bare.rstrip(" \t;")):
            continue
        for rx, sev, code, why in BODY_RULES:
            if rx.search(s):
                report.add(sev, code, f"{where}: {why}", file=fname, line=line, evidence=bare[:220])


def scan_local_source(report: Report, text: str, fname: str) -> None:
    """Review a shipped script/launcher for privilege and sandbox regressions.

    Only these two classes run here: applying the whole BODY_RULES set to an
    installed launcher would report its legitimate runtime network access as a
    build-time fetch. The SKILL still requires reading every local source.
    """
    for offset, raw in enumerate(text.splitlines()):
        s = shell_words(strip_comment(raw).strip())
        if not s:
            continue
        if PRIVILEGE_RX.search(s) or INSTALL_MODE_RX.search(s):
            report.add(MEDIUM, "privilege",
                       "local build script sets SUID/SGID/capabilities; the installed binary "
                       "gains root-owned privilege if the build runs it",
                       file=fname, line=offset + 1, evidence=raw.strip()[:220])
        if SANDBOX_RX.search(s):
            report.add(MEDIUM, "sandbox-weakened",
                       "local source disables the Chromium/Electron sandbox; content rendered "
                       "by the app runs with the user's full privileges",
                       file=fname, line=offset + 1, evidence=raw.strip()[:220])


def scan_local_sources(report: Report, base: str) -> None:
    root_real = os.path.realpath(base)
    for src in report.sources:
        if src.scheme != "" or not src.resolved or src.sig:
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


def _segments(line: str) -> list[str]:
    """Split a shell line into command segments, ignoring separators inside quotes."""
    out: list[str] = []
    buf: list[str] = []
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                buf.extend((c, line[i + 1] if i + 1 < len(line) else ""))
                i += 2
                continue
            if c == quote:
                quote = None
            buf.append(c)
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c in ";&|":
            if buf:
                out.append("".join(buf))
                buf = []
            if i + 1 < len(line) and line[i + 1] == c and c in "&|":
                i += 1
        else:
            buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf))
    return out


def _install_lines(report: Report, fname: str, text: str, first_line: int,
                   where: str, local_names: set[str]) -> None:
    for offset, raw in enumerate(text.splitlines()):
        line = first_line + offset
        scan_body(report, fname, raw, line, where)
        bare = strip_comment(raw).strip()
        if not bare or bare in ("{", "}"):
            continue
        for seg in _segments(bare):
            seg = seg.strip()
            seg = re.sub(r"^(?:if|elif|while|until|then|else|do|for)\b\s*", "", seg).strip()
            if not seg:
                continue
            words = shell_words(seg)
            cmd = words.split()[0].strip("\"'") if words.split() else ""
            if (cmd in INSTALL_SAFE or cmd in local_names or not cmd or cmd.endswith("=")
                    or cmd.startswith("$") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg)):
                continue
            report.add(INFO, "install-script-command",
                       f"{where}: `{cmd}` runs as root; read it", file=fname,
                       line=line, evidence=seg[:220])
            if INSTALL_ROOT_WRITE.search(seg):
                report.add(MEDIUM, "install-script-root-write",
                           f"{where}: writes system paths or rewrites files as root", file=fname,
                           line=line, evidence=seg[:220])


def scan_install(report: Report, path: str) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    fname = os.path.basename(path)
    funcs = function_bodies(text)
    local_names = {f[0] for f in funcs}
    for name, start, _end, body, _bs, _be in funcs:
        _install_lines(report, fname, body, start,
                       f"{name}() runs as root at install/upgrade time", local_names)
    # libalpm sources the scriptlet (`. <file>; <fn> ...`), so top-level code runs as root too.
    top = mask_spans(text, [(text.rfind("\n", 0, f[4]) + 1, f[5]) for f in funcs])
    _install_lines(report, fname, top, 1,
                   f"{fname} top-level code runs as root when pacman sources it", local_names)


def parse_sources(report: Report, text: str, vars_: dict[str, str]) -> list[Source]:
    suffixes = [""] + sorted({m.group(1) for m in re.finditer(
        r"^[ \t]*source_([A-Za-z0-9_]+)\+?=\s*\(", text, re.MULTILINE)})
    report.sources = []
    images: list[str] = []
    scoped_all: list[tuple[str, int]] = []
    for suffix in suffixes:
        tag = f"_{suffix}" if suffix else ""
        entries = parse_any(text, "source" + tag) or []
        sums_arrays = {alg: parse_any(text, alg + tag) for alg in SUMS}
        cksum_items = parse_any(text, "cksums" + tag)

        scoped: list[tuple[str, int]] = []
        for arr in ["source" + tag] + [alg + tag for alg in SUMS] + ["cksums" + tag]:
            scoped.extend((arr, line) for _kind, line in scoped_assignments(text, arr))
        scoped_all.extend(scoped)
        if not entries:
            continue
        unresolved: list[str] = []
        for raw, _line in entries:
            _, _, url = raw.partition("::") if "::" in raw.split("://")[0] else ("", "", raw)
            if "$(" in raw or "`" in raw:
                unresolved.append(raw)
                continue
            if not expand_deep(url, vars_)[1]:
                unresolved.append(raw)
        scope_unresolved = bool(scoped) or bool(unresolved)

        if not any(sums_arrays.values()) and not cksum_items:
            if scope_unresolved:
                report.add(INFO, "checksum-count-unresolved",
                           f"no static checksum array accompanies source{tag}; "
                           "a scoped or unexpandable assignment may supply it at build time",
                           line=line_of(text, "source" + tag + "="), evidence="")
            else:
                report.add(HIGH, "missing-checksums",
                           f"no {tag.lstrip('_') + ' ' if tag else ''}checksum array accompanies the sources",
                           line=line_of(text, "source" + tag + "="), evidence="")
        strong_present = any(sums_arrays.get(alg) for alg in STRONG)
        for alg in ("md5sums", "sha1sums"):
            if sums_arrays.get(alg):
                report.add(LOW if strong_present else HIGH, "weak-checksum",
                           f"{alg}{tag} is cryptographically broken for integrity review",
                           line=line_of(text, alg + tag))
        if cksum_items:
            report.add(LOW if strong_present else HIGH, "weak-checksum",
                       f"cksums{tag} is a CRC and cannot attest integrity",
                       line=line_of(text, "cksums" + tag))
        for alg, items in sums_arrays.items():
            if items and len(items) != len(entries):
                if (not scope_unresolved and array_is_static(text, alg + tag)
                        and array_is_static(text, "source" + tag)):
                    report.add(HIGH, "checksum-count-mismatch",
                               f"{alg}{tag} has {len(items)} entries for {len(entries)} sources",
                               line=line_of(text, alg + tag))
                else:
                    report.add(INFO, "checksum-count-unresolved",
                               f"{alg}{tag} has {len(items)} entries for {len(entries)} sources; "
                               "conditional, indexed, or unexpandable assignments make the static count unreliable",
                               line=line_of(text, alg + tag))
        if scoped:
            report.add(INFO, "checksum-count-unresolved",
                       f"source{tag} is reassigned in a function or conditional block; "
                       "the build-time source/checksum count cannot be derived statically",
                       line=scoped[0][1],
                       evidence=f"{scoped[0][0]} assignment ignored")

        for idx, (raw, line) in enumerate(entries):
            name_part, _, url = raw.partition("::") if "::" in raw.split("://")[0] else ("", "", raw)
            dynamic = "$(" in raw or "`" in raw
            resolved, expanded_ok = expand_deep(url, vars_)
            m = re.match(r"^([A-Za-z0-9+]+)://", resolved)
            scheme = m.group(1) if m else ""
            bare = re.sub(r"^(?:git|svn|hg|bzr|fossil)\+", "", scheme)
            low = resolved.lower()
            low_name = name_part.lower()
            name_resolved, name_ok = expand_deep(name_part.strip(), vars_) if name_part.strip() else ("", True)
            if not name_resolved:
                name_resolved = os.path.basename(
                    urllib.parse.urlsplit(resolved if expanded_ok else url).path)
            src = Source(raw=raw, url=url, line=line, scheme=scheme,
                         vcs=resolved.startswith(VCS_PREFIX) or scheme in ("git", "svn", "hg", "bzr", "fossil"),
                         sig=low.endswith(SIG_SUFFIX) or low_name.endswith(SIG_SUFFIX),
                         patch=low.endswith(PATCH_SUFFIX) or low_name.endswith(PATCH_SUFFIX),
                         resolved=resolved,
                         filename=name_resolved if name_ok else "")
            for alg, items in sums_arrays.items():
                if items and idx < len(items):
                    src.sums[alg] = items[idx][0]
            report.sources.append(src)

            if dynamic:
                src.verify = "dynamic-source"
                report.add(HIGH, "dynamic-source",
                           "source entry is computed by a command substitution; the reviewed text is not the fetched URL",
                           line=line, evidence=raw[:220])
            elif not expanded_ok:
                src.verify = "unexpanded-variable"
                report.add(MEDIUM, "source-unresolved",
                           "source URL uses a variable the collector cannot expand; its real host was not reviewed",
                           line=line, evidence=raw[:220])
            if bare in ("http", "git", "svn", "ftp", "tftp"):
                report.add(HIGH if bare == "http" else MEDIUM, "insecure-scheme",
                           f"source uses unauthenticated {bare}://; "
                           "checksums in the PKGBUILD do not authenticate the transport",
                           line=line, evidence=raw[:220])
            elif not scheme and expanded_ok and not dynamic and not src.vcs and not src.sig:
                if os.path.isabs(resolved) or ".." in resolved.split("/"):
                    src.verify = "local-escapes-snapshot"
                    report.add(MEDIUM, "source-unverified",
                               "local source path is absolute or escapes the snapshot; not read",
                               line=line, evidence=raw[:220])
                elif resolved.lower().endswith(IMAGE_SUFFIX):
                    images.append(os.path.basename(resolved))
                elif src.patch:
                    report.add(INFO, "local-source",
                               "source is a patch shipped in the AUR repo; read it before approving",
                               line=line, evidence=raw[:220])
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

    if scoped_all:
        for arr, line in sorted(set(scoped_all), key=lambda item: (item[1], item[0])):
            report.add(MEDIUM, "array-index-unresolved",
                       f"{arr} is reassigned inside a function or conditional block; "
                       "that assignment does not change the build-time array makepkg verifies",
                       line=line, evidence=f"{arr} assignment ignored")
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

    if any(s.sig for s in report.sources) and not parse_any(text, "validpgpkeys"):
        report.add(MEDIUM, "signature-not-verified",
                   "a signature source is declared but validpgpkeys is absent: any trusted key "
                   "in the user's keyring is accepted",
                   line=line_of(text, "source="), evidence="no validpgpkeys= in the PKGBUILD")
    pkgnames = report.pkgnames
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

    def repl(m: re.Match[str]) -> str:
        nonlocal ok
        key = m.group(1) or m.group(2)
        if key in vars_:
            return vars_[key]
        ok = False
        return m.group(0)

    # Only a complete `$name` or `${name}` is expanded. Anything left (`$`, `${x/…}`,
    # `${arr[@]…}`, `$(…)`) is unresolved: the real URL was never reviewed.
    expanded = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, value)
    if "$" in expanded:
        ok = False
    return expanded, ok


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


def _new_hash(alg: str) -> Any:
    return hashlib.new(alg.replace("sums", "").replace("b2", "blake2b"))


def _digest_file(path: str, alg: str) -> str:
    h = _new_hash(alg)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return str(h.hexdigest())


def _digest_file_multi(path: str, algs: list[str]) -> dict[str, str]:
    hs: dict[str, Any] = {alg: _new_hash(alg) for alg in algs}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for h in hs.values():
                h.update(chunk)
    return {alg: str(h.hexdigest()) for alg, h in hs.items()}


def _cache_url(cache_path: str) -> str | None:
    try:
        with open(cache_path + ".url", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def _cache_matches(cache_path: str | None, url: str) -> bool:
    """True only for a cache file this tool downloaded from the same URL."""
    return bool(cache_path and os.path.isfile(cache_path) and not os.path.islink(cache_path)
                and _cache_url(cache_path) == url)


def _write_cache_url(cache_path: str, url: str) -> None:
    marker = cache_path + ".url"
    tmp = marker + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(url + "\n")
    os.replace(tmp, marker)


def _drop_cache(cache_path: str) -> None:
    for path in (cache_path, cache_path + ".url"):
        try:
            os.unlink(path)
        except OSError:
            pass


def _open_part(part: str) -> IO[bytes]:
    """Open the cache staging file without following symlinks."""
    for _ in range(2):
        try:
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            return os.fdopen(fd, "wb")
        except FileExistsError:
            try:
                os.unlink(part)
            except OSError:
                pass
    raise ValueError("cache staging path is not a safe regular file")


def _digest_url_multi(url: str, algs: list[str], cache_path: str | None = None) -> dict[str, str]:
    """Download once and hash the same bytes with every requested algorithm.

    With `cache_path`, reuse bytes only when this tool recorded the same URL in
    the sidecar, then persist the download for the later build (`SRCDEST`).
    """
    if cache_path is not None and _cache_matches(cache_path, url):
        return _digest_file_multi(cache_path, algs)
    hs: dict[str, Any] = {alg: _new_hash(alg) for alg in algs}
    total = 0
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    part = cache_path + ".part" if cache_path else None
    out = _open_part(part) if part else None
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
    if part and cache_path:
        os.replace(part, cache_path)
        try:
            _write_cache_url(cache_path, url)
        except OSError:
            pass  # the bytes are still usable by makepkg; reuse is just disabled
    return {alg: str(h.hexdigest()) for alg, h in hs.items()}


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
                capture_output=True, check=False,
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
        if src.verify in ("local-escapes-snapshot", "unexpanded-variable", "dynamic-source"):
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
            alg = next((a for a in STRONG if src.sums.get(a) and src.sums[a].upper() != "SKIP"), None)
            if not alg:
                # A signature with no hash is exempt by design; anything else is a gap.
                src.verify = "not-applicable" if src.sig else "no-strong-sum"
                continue
            _record_hash(report, src, alg, _digest_file(path, alg), src.sums[alg], "snapshot file")
            continue
        alg = next((a for a in STRONG if src.sums.get(a) and src.sums[a].upper() != "SKIP"), None)
        if not alg:
            src.verify = "no-strong-sum"
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
        was_cached = _cache_matches(cache_path, src.resolved)
        if cache_path and os.path.isfile(cache_path) and not was_cached:
            # A same-named file we cannot attribute to this URL: never hash, reuse,
            # or overwrite it. Download without caching instead.
            cache_path = None
        try:
            digests = _digest_url_multi(src.resolved, algs, cache_path)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
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
            if cache_path:  # our cache record for this URL is stale; force a re-download
                _drop_cache(cache_path)
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
            if integrity.startswith("sha512-") and got512:
                ok512: bool | None = (
                    base64.b64encode(bytes.fromhex(got512)).decode()
                    == integrity.split("-", 1)[1])
            else:
                ok512 = None
            shasum = meta.get("shasum", "")
            got1 = digests.get("sha1sums", "")
            ok1: bool | None = (got1 == shasum) if (shasum and got1) else None
            sig_ok, sig_msg = npm_verify_signatures(meta)
            if sig_msg == "no npm registry signatures":
                sig_text = "no registry signatures"
            elif sig_ok is None:
                sig_text = f"signatures not checked ({sig_msg})"
            else:
                sig_text = sig_msg
            state = {None: "not published", True: "matches", False: "differs"}
            src.provenance = (f"npm {meta['package']}@{meta['version']}: "
                              f"sha512 integrity {state[ok512]}, "
                              f"sha1 shasum {state[ok1]}, {sig_text}")
            if ok512 is False or ok1 is False or sig_ok is False:
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
        r"#|$|[{}]|\(|\)|"
        r"if\b|then\b|else\b|elif\b|fi\b|for\b|do\b|done\b|while\b|until\b|select\b|"
        r"case\b|esac\b|:(?:\s|$)|\[\[?|test\b|export\b|unset\b|"
        + echo_alt + r"\b)"
    )
    dangerous_subst = re.compile(
        r"\$\([^)]*(?:\b(?:curl|wget|aria2c|ncat|socat|nc|sh|bash|zsh|eval|base64|"
        r"python[0-9.]*|perl|sudo|su)\b|[|;])"
        r"|`[^`]*(?:\b(?:curl|wget|sh|bash|eval)\b|[|;])"
    )
    for idx, raw in enumerate(top.splitlines(), start=1):
        s = strip_comment(raw).strip()
        if not s:
            continue
        substituted = has_unquoted_subst(s)
        if substituted:
            sev = HIGH if dangerous_subst.search(s) else MEDIUM
            code = "dynamic-shell" if sev == HIGH else "top-level-substitution"
            report.add(sev, code,
                       "top level: command substitution runs when the PKGBUILD is sourced",
                       line=idx, evidence=s[:220])
            continue
        if allowed.match(raw):
            control = bool(re.match(
                r"^(?:if|elif|while|until|for|case|then|else|do|fi|esac|done)\b", s))
            hits: list[tuple[str, str, str]] = []
            if (re.match(r"^[ \t]*(?:if|elif|while|until)\b", raw)
                    or CHAIN_META.search(s)):
                hits = [(sev, code, why) for rx, sev, code, why in BODY_RULES if rx.search(s)]
                for sev, code, why in hits:
                    report.add(sev, code, f"top level: {why}", line=idx, evidence=s[:220])
            if (not hits and not control and CHAIN_META.search(s)
                    and not any(a <= idx <= b for a, b in array_spans)):
                report.add(MEDIUM, "top-level-command",
                           "a command chained after a top-level assignment runs when the "
                           "PKGBUILD is sourced",
                           line=idx, evidence=s[:220])
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
    expanded_names: list[str] = []
    for v in pkgnames:
        ev, ok = expand_deep(v, vars_)
        expanded_names.append(ev if ok else v)
    pkgnames = expanded_names
    report.pkgnames = pkgnames
    if pkgnames:
        vars_["pkgname"] = pkgnames[0]
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
            is_array = (key in SRCINFO_ARRAYS or key.startswith(("source_", *sum_prefixes))
                        or key.split("_", 1)[0] in SRCINFO_ARRAYS)
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

    root = os.path.realpath(os.path.dirname(os.path.abspath(pkgbuild)))
    declared_install = parse_scalar(text, "install")
    install_target: str | None = None
    if declared_install:
        resolved, complete = expand_vars(declared_install, vars_)
        if not complete or "$" in resolved:
            report.add(MEDIUM, "install-missing",
                       f"install={declared_install} uses a variable the collector cannot expand; "
                       "locate and read the script it names")
        else:
            candidate = os.path.realpath(os.path.join(root, resolved))
            if candidate != root and not candidate.startswith(root + os.sep):
                report.add(MEDIUM, "install-missing",
                           f"install={declared_install} resolves outside the snapshot; not read",
                           evidence=resolved[:200])
            elif not os.path.isfile(candidate):
                report.add(MEDIUM, "install-missing",
                           f"install={declared_install} resolves to {resolved}, absent from the snapshot")
            else:
                install_target = candidate
    targets: list[str] = [install_target] if install_target else []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".install"):
                path = os.path.realpath(os.path.join(dirpath, name))
                if path == root or path.startswith(root + os.sep):
                    targets.append(path)
    seen: set[str] = set()
    for path in targets:
        if path not in seen:
            seen.add(path)
            scan_install(report, path)
    return pkgbuild


def _display(value: str) -> str:
    """Escape control characters so hostile package text cannot rewrite the terminal."""
    out: list[str] = []
    for ch in value:
        if ch.isprintable() and ch not in "\n\r\t":
            out.append(ch)
        else:
            out.append(ch.encode("unicode_escape").decode("ascii", "replace"))
    return "".join(out)


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
    if report.history_note and verdict.startswith("CLEAN"):
        verdict = "REVIEW (AUR git history unavailable)"
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
            cut = "…" if len(shown) > 110 else ""
            out.append(f"  L{s.line or '?'} [{kind:4}] {shown[:110]}{cut}  ({sums}) verify={s.verify}")
            if s.provenance:
                out.append(f"           provenance: {s.provenance}")
        out.append("")
    if report.authors:
        out.append(f"History: {report.commits} commits")
        for a in report.authors[:6]:
            out.append(f"  {a['last'][:10]}  {a['commits']:4}  {a['name']} <{a['email']}>  {a['last_subject'][:70]}")
        if len(report.authors) > 6:
            out.append(f"  … {len(report.authors) - 6} more authors (full list in --json)")
        out.append("")
    if report.history_note:
        out.append(f"Note: AUR git history unavailable: {report.history_note}")
        out.append("")
    if report.last_change_diff:
        out.append("Last PKGBUILD/.install change:")
        diff_lines = report.last_change_diff.splitlines()
        out.extend("  " + ln for ln in diff_lines[:60])
        if len(diff_lines) > 60:
            out.append(f"  … {len(diff_lines) - 60} more lines omitted (full diff in --json)")
        out.append("")
    for n in report.notes:
        out.append(f"Note: {n}")
    return "\n".join(_display(line) for line in out)


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:  # usage errors must not look like HIGH findings
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
    if args.package and args.pkgbuild:
        ap.error("give either an AUR package name or --pkgbuild, not both")
    if args.keep_snapshot and args.pkgbuild:
        ap.error("--keep-snapshot applies to AUR audits, not --pkgbuild")

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
            try:
                os.makedirs(args.cache_dir, mode=0o700, exist_ok=True)
                st = os.stat(args.cache_dir)
            except OSError as e:
                raise SystemExit(f"aur-security-audit: cache dir unusable: {e}")
            if st.st_uid != os.getuid():
                raise SystemExit(
                    f"aur-security-audit: cache dir {args.cache_dir} is not owned by the current user")
            if st.st_mode & 0o077:
                os.chmod(args.cache_dir, 0o700)
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
            if downloaded:
                report.notes.append(f"downloaded {downloaded} source(s) into {args.cache_dir}")
            if cached:
                report.notes.append(f"{cached} source(s) were read from the cache")
            report.notes.append(f"reuse with SRCDEST={args.cache_dir} makepkg -s")
        if keep:
            report.notes.append(f"snapshot kept at {report.snapshot or workdir}")
        else:
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
            target_dir = os.path.dirname(os.path.abspath(args.json)) or "."
            try:
                fd, tmp_json = tempfile.mkstemp(dir=target_dir, prefix=".aur-audit-", suffix=".json")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                os.replace(tmp_json, args.json)
            except OSError as e:
                raise SystemExit(f"aur-security-audit: could not write JSON report: {e}")
        return 2 if any(f.severity == HIGH for f in report.findings) else 0
    finally:
        if args.pkgbuild or not keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
