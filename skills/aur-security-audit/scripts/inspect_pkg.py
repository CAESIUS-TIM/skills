#!/usr/bin/env python3
"""Compact inventory of a built Arch package for the AUR audit gate.

Reads the package without extracting or installing it and prints the facts
step 5 of the audit needs: PKGINFO, file count/size, shipped SUID/SGID,
world-writable files, .INSTALL presence, launcher/desktop contents and sandbox
flags, plus namcap errors and missing-dependency warnings when namcap is
installed.

Reading prefers Python's tarfile (exact member names, no shell); bsdtar is the
fallback on interpreters without zstd support. A member that cannot be read is
reported as such, never as an empty file.

Usage: inspect_pkg.py <pkg.tar.zst> [--json PATH]
Exit: 0 report printed, 1 unreadable package or no tar reader available.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypedDict

SCAN_LIMIT = 16 * 1024       # launcher text examined for sandbox flags
READ_LIMIT = 64 * 1024 * 1024  # refuse to buffer a member larger than this
PKGINFO_LIMIT = 256 * 1024


def display(value: str) -> str:
    """Escape control characters so hostile names cannot rewrite the terminal."""
    return "".join(ch if ch.isprintable() and ch not in "\n\r\t"
                   else ch.encode("unicode_escape").decode("ascii", "replace")
                   for ch in value)


def load_audit() -> tuple[re.Pattern[str], Callable[[str], str]]:
    """Import the collector for the shared sandbox regex and comment stripper."""
    from audit import SANDBOX_RX, strip_comment
    return SANDBOX_RX, strip_comment


@dataclass
class Member:
    name: str
    mode: int
    size: int
    is_file: bool


class Launcher(TypedDict):
    path: str
    mode: str
    sha256: str | None
    flags: list[str]
    size: int
    unreadable: bool


class TarReader:
    """Read members through tarfile: exact names, no path interpretation."""

    def __init__(self, path: str):
        self.tar = tarfile.open(path, "r:*")  # noqa: SIM115 - reader keeps it open by design
        self.members: list[Member] = []
        for m in self.tar.getmembers():
            self.members.append(Member(m.name, m.mode, m.size, m.isfile()))

    def read(self, name: str, limit: int = READ_LIMIT) -> tuple[bytes, bool]:
        try:
            m = self.tar.getmember(name)
            f = self.tar.extractfile(m)
        except (KeyError, OSError, tarfile.TarError):
            return b"", False
        if f is None:
            return b"", False
        data = f.read(limit + 1)
        return data[:limit], len(data) > limit

    def close(self) -> None:
        self.tar.close()


class BsdtarReader:
    """Fallback for interpreters without zstd tarfile support."""

    def __init__(self, path: str):
        if not shutil.which("bsdtar"):
            raise SystemExit("inspect_pkg: neither tarfile nor bsdtar can read this package")
        self.path = path
        self.members: list[Member] = []
        result = subprocess.run(["bsdtar", "-tvf", path], capture_output=True, text=True,
                                check=False)
        if result.returncode != 0:
            raise SystemExit(f"inspect_pkg: bsdtar cannot read {path}: {result.stderr.strip()}")
        for line in result.stdout.splitlines():
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            text_mode, name = parts[0], parts[8]
            try:
                size = int(parts[4])
            except ValueError:
                size = 0
            mode = _mode_bits(text_mode)
            self.members.append(Member(name, mode, size, text_mode.startswith("-")))

    def read(self, name: str, limit: int = READ_LIMIT) -> tuple[bytes, bool]:
        # bsdtar escapes control bytes in names it prints, so a listed name cannot
        # always be passed back. Read what we can; callers report failures.
        proc = subprocess.Popen(["bsdtar", "-xOf", self.path, "--", name],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert proc.stdout is not None
        try:
            data = proc.stdout.read(limit + 1)
        finally:
            proc.stdout.close()
            proc.kill()
            proc.wait()
        return data[:limit], len(data) > limit

    def close(self) -> None:
        return None


def _mode_bits(text_mode: str) -> int:
    """Translate `-rwsr-xr-x` to the numeric mode bits the tarfile path uses."""
    if len(text_mode) < 10:
        return 0
    value = 0
    for offset, shift in ((1, 6), (4, 3), (7, 0)):
        for i in range(3):
            if text_mode[offset + i] in "rwxst":
                value |= 1 << (shift + 2 - i)
    for pos, bit in ((3, 0o4000), (6, 0o2000), (9, 0o1000)):
        if text_mode[pos] in "sStT":
            value |= bit
    return value


def parse_pkginfo(data: bytes) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if " = " in line:
            key, _, value = line.partition(" = ")
            meta[key.strip()] = value.strip()
    return meta


def sandbox_flags(data: bytes, desktop: bool) -> list[str]:
    if b"\x00" in data[:8192] or len(data) > SCAN_LIMIT:
        return []
    rx, strip_comment = load_audit()
    lines: list[str] = []
    for line in data.decode("utf-8", "replace").splitlines():
        if desktop:
            if line.lstrip().startswith("Exec="):
                lines.append(line)
            continue
        if line.lstrip().startswith("#"):
            continue
        lines.append(strip_comment(line))
    seen: list[str] = []
    for match in rx.finditer("\n".join(lines)):
        if match.group(0) not in seen:
            seen.append(match.group(0))
    return seen


def namcap_findings(pkg: str) -> list[str]:
    if not shutil.which("namcap"):
        return []
    result = subprocess.run(["namcap", pkg], capture_output=True, text=True, check=False)
    out = (result.stdout or "") + (result.stderr or "")
    keep = []
    for line in out.splitlines():
        if " E: " in line or ("W: Dependency " in line and " not included" in line):
            keep.append(line.strip())
    return keep


def open_package(path: str) -> TarReader | BsdtarReader:
    try:
        return TarReader(path)
    except (tarfile.TarError, OSError):
        return BsdtarReader(path)


def main() -> int:
    ap = argparse.ArgumentParser(description="Inventory a built Arch package for the AUR audit gate.")
    ap.add_argument("package", help="path to a .pkg.tar.zst")
    ap.add_argument("--json", help="write the same inventory as JSON here")
    args = ap.parse_args()

    if not os.path.isfile(args.package):
        raise SystemExit(f"inspect_pkg: no such package: {args.package}")

    reader = open_package(args.package)
    try:
        pkginfo_raw, pkginfo_cut = reader.read(".PKGINFO", PKGINFO_LIMIT)
        pkginfo = parse_pkginfo(pkginfo_raw)
        install_present = any(m.name == ".INSTALL" for m in reader.members)
        total = sum(m.size for m in reader.members)
        depends = sum(1 for line in pkginfo_raw.decode("utf-8", "replace").splitlines()
                      if line.startswith("depend = "))
        optdepends = sum(1 for line in pkginfo_raw.decode("utf-8", "replace").splitlines()
                         if line.startswith("optdepend = "))

        setuid = [(m.mode, m.name) for m in reader.members
                  if m.is_file and (m.mode & 0o4000 or m.mode & 0o2000)]
        world = [(m.mode, m.name) for m in reader.members
                 if m.is_file and m.mode & 0o002]
        launchers: list[Launcher] = []
        namcap_lines = namcap_findings(args.package)
        for member in reader.members:
            if not member.is_file:
                continue
            desktop = (member.name.startswith("usr/share/applications/")
                       and member.name.endswith(".desktop") and member.name.count("/") == 3)
            is_bin = member.name.startswith("usr/bin/") and member.name.count("/") == 2
            if not (is_bin or desktop):
                continue
            data, cut = reader.read(member.name)
            unreadable = bool(member.size and not data) or cut
            launchers.append({
                "path": member.name,
                "mode": f"{member.mode:04o}",
                "sha256": None if unreadable else hashlib.sha256(data).hexdigest(),
                "flags": [] if unreadable else sandbox_flags(data, desktop),
                "size": len(data),
                "unreadable": unreadable,
            })
    finally:
        reader.close()

    print(f"package: {display(os.path.basename(args.package))}")
    note = " (truncated)" if pkginfo_cut else ""
    print(f"pkgver: {display(pkginfo.get('pkgver', 'unknown'))}{note}")
    print(f"license: {display(pkginfo.get('license', 'unknown'))}{note}")
    print(f"depends: {depends} optdepends: {optdepends}")
    print(f"files: {len(reader.members)}, uncompressed: {total / 1048576:.1f} MiB")
    if setuid:
        print("setuid/setgid:")
        for mode, name in setuid:
            print(f"  {mode:04o} {display(name)}")
    else:
        print("setuid/setgid: none")
    if world:
        print("world-writable:")
        for mode, name in world:
            print(f"  {mode:04o} {display(name)}")
    else:
        print("world-writable: none")
    print(f".INSTALL: {'present (read it)' if install_present else 'absent'}")
    for launcher in launchers:
        shown = display(launcher["path"])
        if launcher["unreadable"]:
            print(f"launcher: {shown} sha256=unreadable (content not inspected)")
            continue
        print(f"launcher: {shown} sha256={launcher['sha256']}")
        if launcher["flags"]:
            print(f"  flags: {' '.join(launcher['flags'])}")
    if namcap_lines:
        print("namcap:")
        for line in namcap_lines:
            print(f"  {display(line)}")
    elif not shutil.which("namcap"):
        print("namcap: not installed")

    if args.json:
        payload = {
            "package": os.path.basename(args.package),
            "pkgver": pkginfo.get("pkgver"),
            "license": pkginfo.get("license"),
            "size": int(pkginfo["size"]) if pkginfo.get("size", "").isdigit() else None,
            "files": len(reader.members),
            "uncompressed": total,
            "setuid": [{"mode": f"{m:04o}", "path": n} for m, n in setuid],
            "world_writable": [{"mode": f"{m:04o}", "path": n} for m, n in world],
            "install_script": install_present,
            "launchers": launchers,
            "namcap": namcap_lines,
        }
        target_dir = os.path.dirname(os.path.abspath(args.json)) or "."
        try:
            fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".inspect-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, args.json)
        except OSError as e:
            raise SystemExit(f"inspect_pkg: could not write JSON report: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
