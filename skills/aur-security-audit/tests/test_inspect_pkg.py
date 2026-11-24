"""Tests for inspect_pkg.py against crafted packages."""

from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import inspect_pkg
import pytest


def make_pkg(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tar:
        def add(name: str, data: bytes, mode: int) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))

        add(".PKGINFO", b"pkgname = demo\npkgver = 1-1\nlicense = MIT\n", 0o644)
        add(".INSTALL", b"post_install() { :; }\n", 0o644)
        add("usr/bin/demo", b'#!/bin/sh\nexec /opt/demo --no-sandbox "$@"\n', 0o4755)
        add("usr/bin/demo\nevil", b'#!/bin/sh\nexec /opt/demo --no-sandbox "$@"\n', 0o755)
        add("usr/share/applications/demo.desktop",
            b"[Desktop Entry]\nExec=/usr/bin/demo\n# --no-sandbox is unsafe\n", 0o644)


def test_display() -> None:
    assert inspect_pkg.display("a\x1b]0;x\x07b") == "a\\x1b]0;x\\x07b"
    assert inspect_pkg.display("a\nb") == "a\\nb"


def test_mode_bits() -> None:
    assert inspect_pkg._mode_bits("-rwsr-xr-x") & 0o4000
    assert inspect_pkg._mode_bits("-rw-rw-rw-") & 0o002
    assert inspect_pkg._mode_bits("-rwsr-sr-t") & 0o7000
    assert inspect_pkg._mode_bits("short") == 0


def test_parse_pkginfo() -> None:
    meta = inspect_pkg.parse_pkginfo(b"pkgname = demo\npkgver = 1-1\nsize = 12\n")
    assert meta == {"pkgname": "demo", "pkgver": "1-1", "size": "12"}


def test_sandbox_flags() -> None:
    shell = b"#!/bin/sh\n# --no-sandbox in a comment\nexec /opt/x --no-sandbox\n"
    assert inspect_pkg.sandbox_flags(shell, desktop=False) == ["--no-sandbox"]
    desktop = b"[Desktop Entry]\nExec=/usr/bin/demo\n# --no-sandbox is unsafe\n"
    assert inspect_pkg.sandbox_flags(desktop, desktop=True) == []
    binary = b"\x00--no-sandbox"
    assert inspect_pkg.sandbox_flags(binary, desktop=False) == []


def test_tar_reader(tmp_path: Path) -> None:
    pkg = tmp_path / "demo.pkg.tar.gz"
    make_pkg(pkg)
    reader = inspect_pkg.open_package(str(pkg))
    try:
        assert isinstance(reader, inspect_pkg.TarReader)
        data, cut = reader.read("usr/bin/demo\nevil")
        assert b"--no-sandbox" in data and not cut
        data, cut = reader.read("usr/bin/demo", limit=4)
        assert len(data) == 4 and cut
        assert reader.read(".missing") == (b"", False)
    finally:
        reader.close()


def test_main_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                     capsys: pytest.CaptureFixture[str]) -> None:
    pkg = tmp_path / "demo.pkg.tar.gz"
    make_pkg(pkg)
    out = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["inspect_pkg.py", str(pkg), "--json", str(out)])
    assert inspect_pkg.main() == 0
    text = capsys.readouterr().out
    assert "setuid/setgid:" in text and "4755 usr/bin/demo" in text
    assert ".INSTALL: present" in text
    assert "usr/bin/demo\\nevil" in text
    assert text.count("flags:") == 2
    payload = json.loads(out.read_text())
    assert payload["install_script"] is True
    assert payload["setuid"] == [{"mode": "4755", "path": "usr/bin/demo"}]
    assert payload["files"] == 5


def test_main_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["inspect_pkg.py", str(tmp_path / "missing.pkg")])
    with pytest.raises(SystemExit):
        inspect_pkg.main()

    pkg = tmp_path / "demo.pkg.tar.gz"
    make_pkg(pkg)
    monkeypatch.setattr(sys, "argv", ["inspect_pkg.py", str(pkg), "--json",
                                      str(tmp_path / "missing" / "x.json")])
    with pytest.raises(SystemExit):
        inspect_pkg.main()


def test_namcap_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inspect_pkg.shutil, "which", lambda *a: None)
    assert inspect_pkg.namcap_findings("x") == []


def test_open_package_bsdtar_fallback(tmp_path: Path,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
    pkg = tmp_path / "demo.pkg.tar.gz"
    make_pkg(pkg)

    class Broken:
        def __init__(self, path: str) -> None:
            raise tarfile.ReadError("unsupported compression")

    monkeypatch.setattr(inspect_pkg, "TarReader", Broken)
    reader = inspect_pkg.open_package(str(pkg))
    try:
        assert isinstance(reader, inspect_pkg.BsdtarReader)
        assert any(m.name == "usr/bin/demo" for m in reader.members)
        data, cut = reader.read("usr/bin/demo", limit=4)
        assert data and cut
    finally:
        reader.close()


def test_main_unreadable_and_namcap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                    capsys: pytest.CaptureFixture[str]) -> None:
    pkg = tmp_path / "demo.pkg.tar.gz"
    with tarfile.open(pkg, "w:gz") as tar:
        def add(name: str, data: bytes, mode: int) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))

        add(".PKGINFO", b"pkgname = demo\n", 0o644)
        add("usr/bin/big", b"x" * 32, 0o755)

    original = inspect_pkg.TarReader.read

    def fake_read(self: inspect_pkg.TarReader, name: str,
                  limit: int = inspect_pkg.READ_LIMIT) -> tuple[bytes, bool]:
        if name == "usr/bin/big":
            return b"", False
        return original(self, name, limit)

    monkeypatch.setattr(inspect_pkg.TarReader, "read", fake_read)
    monkeypatch.setattr(inspect_pkg, "namcap_findings", lambda pkg: ["demo E: bad thing"])
    monkeypatch.setattr(sys, "argv", ["inspect_pkg.py", str(pkg)])
    assert inspect_pkg.main() == 0
    text = capsys.readouterr().out
    assert "sha256=unreadable" in text
    assert "namcap:" in text and "bad thing" in text
