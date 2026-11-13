import tarfile, io, gzip, sys, os, hashlib, zipfile

out = sys.argv[1]


def add(tf, name, data=None, typ=tarfile.REGTYPE, link=None, mode=0o755):
    ti = tarfile.TarInfo(name)
    ti.mtime = 1700000000
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    ti.mode = mode
    ti.type = typ
    if link:
        ti.linkname = link
    if data is not None:
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    else:
        tf.addfile(ti)


def archive(tag, target, entries):
    d = os.path.join(out, tag)
    os.makedirs(d, exist_ok=True)
    name = f"dove-{tag}-{target}.tar.gz"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        top = f"dove-{tag}-{target}"
        add(tf, top + "/", typ=tarfile.DIRTYPE)
        for e in entries:
            e(tf, top)
    gz = gzip.compress(raw.getvalue(), mtime=0)
    open(os.path.join(d, name), "wb").write(gz)
    return name, hashlib.sha256(gz).hexdigest()


def zip_archive(tag, target, files):
    """A Windows-style release: dove-<tag>-<target>.zip with dove-<tag>-<target>/dove.exe (no unix mode bits)."""
    d = os.path.join(out, tag)
    os.makedirs(d, exist_ok=True)
    name = f"dove-{tag}-{target}.zip"
    top = f"dove-{tag}-{target}"
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, data in files:
            zi = zipfile.ZipInfo(f"{top}/{fname}", date_time=(2023, 11, 14, 22, 13, 20))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data)
    data = raw.getvalue()
    open(os.path.join(d, name), "wb").write(data)
    return name, hashlib.sha256(data).hexdigest()


def binary(text):
    return lambda tf, top: add(tf, top + "/dove", text.encode())


def docs(tf, top):
    add(tf, top + "/LICENSE", b"Apache-2.0 (test fixture)\n", mode=0o644)
    add(tf, top + "/README.md", b"# Dove (test fixture)\n", mode=0o644)


def sums(tag, items):
    open(os.path.join(out, tag, "SHA256SUMS"), "w").write("".join(f"{h}  {n}\n" for n, h in items))


sums("v0.2.0", [
    archive("v0.2.0", "aarch64-apple-darwin", [binary("#!/bin/sh\necho 'dove 0.2.0 (darwin)'\n"), docs]),
    archive("v0.2.0", "x86_64-unknown-linux-gnu", [binary("#!/bin/sh\necho 'dove 0.2.0'\n"), docs]),
    archive("v0.2.0", "x86_64-unknown-linux-musl", [binary("#!/bin/sh\necho 'dove 0.2.0 (musl)'\n"), docs]),
    zip_archive("v0.2.0", "x86_64-pc-windows-msvc", [("dove.exe", b"MZ dove 0.2.0 (windows)\n"), ("README.md", b"# Dove (test fixture)\n")]),
])


def traversal(tf, top):
    add(tf, top + "/../../evil", b"#!/bin/sh\necho pwned\n")


sums("v0.3.0", [archive("v0.3.0", "x86_64-unknown-linux-gnu", [binary("#!/bin/sh\necho 'dove 0.3.0'\n"), docs, traversal])])


def symlink(tf, top):
    add(tf, top + "/dove", typ=tarfile.SYMTYPE, link="/bin/sh")


sums("v0.4.0", [archive("v0.4.0", "x86_64-unknown-linux-gnu", [symlink, docs])])


# A Windows zip whose dove.exe is a traversal: the names are plain, only the member path escapes.
def zip_traversal(tag, target):
    d = os.path.join(out, tag)
    os.makedirs(d, exist_ok=True)
    name = f"dove-{tag}-{target}.zip"
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"dove-{tag}-{target}/dove.exe", b"MZ")
        zf.writestr(f"dove-{tag}-{target}/../../evil.exe", b"MZ evil")
    open(os.path.join(d, name), "wb").write(raw.getvalue())
    return name, hashlib.sha256(raw.getvalue()).hexdigest()


sums("v0.5.0", [zip_traversal("v0.5.0", "x86_64-pc-windows-msvc")])
