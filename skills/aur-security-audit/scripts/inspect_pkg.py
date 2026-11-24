#!/usr/bin/env python3
"""Compact inventory of a built Arch package for the AUR audit gate.

Reads the package with bsdtar (no extraction, no install) and prints the facts
step 5 of the audit needs: PKGINFO, file count/size, shipped SUID/SGID,
world-writable files, .INSTALL presence, launcher/desktop contents and sandbox
flags, plus namcap errors and missing-dependency warnings when namcap is
installed.

Usage: inspect_pkg.py <pkg.tar.zst> [--json PATH]
Exit: 0 report printed, 1 unreadable package or missing bsdtar.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

SANDBOX_RX = None


def load_sandbox_rx():
    global SANDBOX_RX
    if SANDBOX_RX is None:
        from audit import SANDBOX_RX as rx
        SANDBOX_RX = rx
    return SANDBOX_RX


def run(args: list[str], binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=not binary, check=False)


def read_member(pkg: str, name: str) -> bytes:
    result = run(["bsdtar", "-xOf", pkg, name], binary=True)
    return result.stdout if result.returncode == 0 else b""


def parse_pkginfo(data: bytes) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if " = " in line:
            key, _, value = line.partition(" = ")
            meta[key.strip()] = value.strip()
    return meta


def inventory(pkg: str) -> list[tuple[str, str, int]]:
    result = run(["bsdtar", "-tvf", pkg])
    if result.returncode != 0:
        raise SystemExit(f"inspect_pkg: bsdtar cannot read {pkg}: {result.stderr.strip()}")
    entries: list[tuple[str, str, int]] = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        mode, name = parts[0], parts[8]
        try:
            size = int(parts[4])
        except ValueError:
            size = 0
        entries.append((mode, name, size))
    return entries


def sandbox_flags(data: bytes) -> list[str]:
    if b"\x00" in data[:8192] or len(data) > 16 * 1024:
        return []
    rx = load_sandbox_rx()
    seen: list[str] = []
    for match in rx.finditer(data.decode("utf-8", "replace")):
        if match.group(0) not in seen:
            seen.append(match.group(0))
    return seen


def namcap_findings(pkg: str) -> list[str]:
    if not shutil.which("namcap"):
        return []
    result = run(["namcap", pkg])
    out = (result.stdout or "") + (result.stderr or "")
    keep = []
    for line in out.splitlines():
        if " E: " in line:
            keep.append(line.strip())
        elif "W: Dependency " in line and " not included" in line:
            keep.append(line.strip())
    return keep


def main() -> int:
    ap = argparse.ArgumentParser(description="Inventory a built Arch package for the AUR audit gate.")
    ap.add_argument("package", help="path to a .pkg.tar.zst")
    ap.add_argument("--json", help="write the same inventory as JSON here")
    args = ap.parse_args()

    if not os.path.isfile(args.package):
        raise SystemExit(f"inspect_pkg: no such package: {args.package}")
    if not shutil.which("bsdtar"):
        raise SystemExit("inspect_pkg: bsdtar not found (install libarchive)")

    entries = inventory(args.package)
    pkginfo_raw = read_member(args.package, ".PKGINFO")
    pkginfo = parse_pkginfo(pkginfo_raw)
    install_script = read_member(args.package, ".INSTALL")
    total = sum(size for _mode, _name, size in entries)
    depends = sum(1 for line in pkginfo_raw.decode("utf-8", "replace").splitlines()
                  if line.startswith("depend = "))
    optdepends = sum(1 for line in pkginfo_raw.decode("utf-8", "replace").splitlines()
                     if line.startswith("optdepend = "))

    setuid = [(mode, name) for mode, name, _size in entries
              if len(mode) == 10 and (mode[3] in "sS" or mode[6] in "sS")]
    world = [(mode, name) for mode, name, _size in entries
             if len(mode) == 10 and mode[0] == "-" and mode[8] == "w"]
    launchers = []
    namcap_lines = namcap_findings(args.package)
    for mode, name, _size in entries:
        is_bin = mode.startswith("-") and name.startswith("usr/bin/") and name.count("/") == 2
        is_desktop = (mode.startswith("-") and name.startswith("usr/share/applications/")
                      and name.endswith(".desktop") and name.count("/") == 3)
        if not (is_bin or is_desktop):
            continue
        data = read_member(args.package, name)
        digest = hashlib.sha256(data).hexdigest()
        launchers.append({"path": name, "mode": mode, "sha256": digest,
                          "flags": sandbox_flags(data), "size": len(data)})

    print(f"package: {os.path.basename(args.package)}")
    print(f"pkgver: {pkginfo.get('pkgver', 'unknown')}")
    print(f"license: {pkginfo.get('license', 'unknown')}")
    print(f"depends: {depends} optdepends: {optdepends}")
    print(f"files: {len(entries)}, uncompressed: {total / 1048576:.1f} MiB")
    if setuid:
        print("setuid/setgid:")
        for mode, name in setuid:
            print(f"  {mode} {name}")
    else:
        print("setuid/setgid: none")
    if world:
        print("world-writable:")
        for mode, name in world:
            print(f"  {mode} {name}")
    else:
        print("world-writable: none")
    print(f".INSTALL: {'present' if install_script else 'absent'}")
    for launcher in launchers:
        print(f"launcher: {launcher['path']} sha256={launcher['sha256']}")
        if launcher["flags"]:
            print(f"  flags: {' '.join(launcher['flags'])}")
    if namcap_lines:
        print("namcap:")
        for line in namcap_lines:
            print(f"  {line}")
    elif not shutil.which("namcap"):
        print("namcap: not installed")

    if args.json:
        payload = {
            "package": os.path.basename(args.package),
            "pkgver": pkginfo.get("pkgver"),
            "license": pkginfo.get("license"),
            "size": int(pkginfo["size"]) if pkginfo.get("size", "").isdigit() else None,
            "files": len(entries),
            "uncompressed": total,
            "setuid": [{"mode": m, "path": n} for m, n in setuid],
            "world_writable": [{"mode": m, "path": n} for m, n in world],
            "install_script": bool(install_script),
            "launchers": launchers,
            "namcap": namcap_lines,
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
