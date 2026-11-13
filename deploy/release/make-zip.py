#!/usr/bin/env python3
"""Packs dist/<name>/ into dist/<name>.zip for the Windows release.

Usage: python -I deploy/release/make-zip.py <dist-dir> <name>

Members are written as <name>/<file> with forward slashes and fixed timestamps (the order is sorted), which is what
`dove upgrade` and install.ps1 expect. Windows PowerShell 5.1's Compress-Archive writes backslashes and is not used
for that reason. The result is checked after writing: no backslash, absolute path or `..` in any member name.
"""
import pathlib
import sys
import zipfile

dist, name = pathlib.Path(sys.argv[1]), sys.argv[2]
src = dist / name
out = dist / f"{name}.zip"
if not (src / "dove.exe").is_file():
    sys.exit(f"{src}/dove.exe is missing")

with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(src.iterdir()):
        if not f.is_file():
            sys.exit(f"unexpected entry {f}")
        info = zipfile.ZipInfo(f"{name}/{f.name}", date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, f.read_bytes())

with zipfile.ZipFile(out) as z:
    names = z.namelist()
    for n in names:
        print(n)
        if "\\" in n or n.startswith("/") or ".." in n.split("/") or not n.startswith(f"{name}/"):
            sys.exit(f"bad member name {n!r}")
    if f"{name}/dove.exe" not in names:
        sys.exit("dove.exe is not in the archive")
