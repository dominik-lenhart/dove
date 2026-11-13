import tarfile, io, gzip, sys, os, hashlib

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
])


def traversal(tf, top):
    add(tf, top + "/../../evil", b"#!/bin/sh\necho pwned\n")


sums("v0.3.0", [archive("v0.3.0", "x86_64-unknown-linux-gnu", [binary("#!/bin/sh\necho 'dove 0.3.0'\n"), docs, traversal])])


def symlink(tf, top):
    add(tf, top + "/dove", typ=tarfile.SYMTYPE, link="/bin/sh")


sums("v0.4.0", [archive("v0.4.0", "x86_64-unknown-linux-gnu", [symlink, docs])])
