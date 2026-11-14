#!/bin/sh
# Dove installer: downloads a release archive, verifies it, installs the `dove` binary.
#
#   curl -fsSL https://github.com/dominik-lenhart/dove/releases/latest/download/install.sh | sh
#
# Environment:
#   DOVE_VERSION       X.Y.Z (or vX.Y.Z); default: the latest release
#   DOVE_INSTALL_DIR   target directory; default: /usr/local/bin as root, otherwise ~/.local/bin
#
# On your own computer run it without sudo: a user-level install updates itself (`dove upgrade`) without root.
# On a server that runs the Dove service use `| sudo sh`: there the binary stays root-owned on purpose.
#   DOVE_LIBC          Linux only: gnu or musl; default: musl on musl systems (Alpine), gnu everywhere else
#   DOVE_DOWNLOAD_BASE testing only: replaces https://github.com/dominik-lenhart/dove/releases/download
#                      (files are fetched from <base>/<tag>/<file>; DOVE_VERSION is then required)
#
# The archive is only unpacked after its SHA-256 matches SHA256SUMS. SHA256SUMS is checked against the minisign
# signature when `minisign` is installed; without it only the checksum from the same release is verified (that
# protects against corruption, not against a compromised release). Nothing downloaded is ever run by this script.
set -eu

REPO="dominik-lenhart/dove"
# Release signing key (same as deploy/release/minisign.pub).
PUBKEY="RWQRx2ysvLhSBINGxR3uV9awNjRzHTcz6NUppfFhP2OBdhxTETjz+zGr"

say() { printf '%s\n' "$*"; }
die() { printf 'dove install: %s\n' "$*" >&2; exit 1; }

# ---- tools -------------------------------------------------------------------------------------------------
# HTTPS only, redirects included; plain HTTP only for a test server given with DOVE_DOWNLOAD_BASE.
proto='=https'
wget_https='--https-only'
if [ -n "${DOVE_DOWNLOAD_BASE:-}" ]; then proto='=https,http'; wget_https=''; fi
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto "$proto" -o "$2" "$1"; }
  final_url() { curl -fsSL --proto '=https' -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  # shellcheck disable=SC2086 # $wget_https is one flag or empty
  fetch() { wget -q $wget_https -O "$2" "$1"; }
  final_url() { wget -q --https-only --max-redirect=5 --spider -S "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
else
  die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
  die "sha256sum or shasum is required"
fi

command -v tar >/dev/null 2>&1 || die "tar is required"

# ---- platform ----------------------------------------------------------------------------------------------
# Linux ships two builds: glibc (gnu) and a static musl one. A musl system (Alpine, Void musl) cannot run the gnu build.
is_musl() {
  [ -e /etc/alpine-release ] && return 0
  command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl
}
case "$(uname -s)" in
  Linux)
    case "${DOVE_LIBC:-}" in
      gnu | musl) libc="$DOVE_LIBC" ;;
      "") if is_musl; then libc=musl; else libc=gnu; fi ;;
      *) die "DOVE_LIBC must be gnu or musl, not '$DOVE_LIBC'" ;;
    esac
    os="unknown-linux-$libc"
    ;;
  Darwin) os=apple-darwin ;;
  *) die "unsupported operating system: $(uname -s) (Linux and macOS only; on Windows use install.ps1)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) die "unsupported CPU architecture: $(uname -m) (x86_64 and aarch64 only)" ;;
esac
target="$arch-$os"

# ---- version -----------------------------------------------------------------------------------------------
version="${DOVE_VERSION:-}"
if [ -z "$version" ]; then
  [ -z "${DOVE_DOWNLOAD_BASE:-}" ] || die "DOVE_VERSION is required with DOVE_DOWNLOAD_BASE"
  loc=$(final_url "https://github.com/$REPO/releases/latest") || die "cannot resolve the latest release"
  version="${loc##*/}"
fi
version="${version#v}"
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
  || die "invalid version: $version"
tag="v$version"
name="dove-$tag-$target"
base="${DOVE_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}/$tag"

# ---- install directory -------------------------------------------------------------------------------------
if [ -n "${DOVE_INSTALL_DIR:-}" ]; then
  dir="$DOVE_INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
  dir=/usr/local/bin
else
  [ -n "${HOME:-}" ] || die "HOME is not set; set DOVE_INSTALL_DIR"
  dir="$HOME/.local/bin"
fi

# ---- download ----------------------------------------------------------------------------------------------
tmp=$(mktemp -d "${TMPDIR:-/tmp}/dove-install.XXXXXX") || die "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

say "Installing dove $version ($target) to $dir"
fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" || die "download failed: $base/$name.tar.gz"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"
fetch "$base/SHA256SUMS.minisig" "$tmp/SHA256SUMS.minisig" || die "download failed: $base/SHA256SUMS.minisig"

# ---- verify ------------------------------------------------------------------------------------------------
if command -v minisign >/dev/null 2>&1; then
  out=$(minisign -V -P "$PUBKEY" -m "$tmp/SHA256SUMS" -x "$tmp/SHA256SUMS.minisig" 2>&1) \
    || die "signature verification FAILED for SHA256SUMS; not installing"
  # The trusted comment must be exactly "dove <tag>": a substring match would accept "dove v1.2.3-rc.1" for v1.2.3.
  printf '%s\n' "$out" | tr -d '\r' | grep -qxF "Trusted comment: dove $tag" \
    || die "signature is valid but is not for dove $tag (wrong or replayed release); not installing"
  say "Signature OK (minisign, dove $tag)"
else
  say "Note: minisign is not installed, so the signature was NOT checked. Only the SHA-256 from the same release is"
  say "      verified. Install minisign and re-run, or verify by hand: see docs/releasing.md."
fi

expected=$(awk -v f="$name.tar.gz" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$name.tar.gz is not listed in SHA256SUMS"
[ "$(printf '%s\n' "$expected" | wc -l)" -eq 1 ] || die "SHA256SUMS lists $name.tar.gz more than once"
actual=$(sha256_of "$tmp/$name.tar.gz")
[ "$actual" = "$expected" ] || die "SHA-256 mismatch for $name.tar.gz (expected $expected, got $actual); not installing"
say "SHA-256 OK"

# ---- install -----------------------------------------------------------------------------------------------
# Extract the one member we need, nothing else.
mkdir "$tmp/x"
tar -xzf "$tmp/$name.tar.gz" -C "$tmp/x" "$name/dove" || die "the archive does not contain $name/dove"
[ -f "$tmp/x/$name/dove" ] && [ ! -L "$tmp/x/$name/dove" ] || die "unexpected archive content"

mkdir -p "$dir" || die "cannot create $dir"
# Write next to the target and rename, so a running dove is never overwritten in place.
cp "$tmp/x/$name/dove" "$dir/.dove.new.$$" || die "cannot write to $dir (set DOVE_INSTALL_DIR or run as root)"
chmod 0755 "$dir/.dove.new.$$"
mv -f "$dir/.dove.new.$$" "$dir/dove"

say "Installed $dir/dove"
case ":${PATH:-}:" in
  *":$dir:"*) ;;
  *)
    # Print the line, never edit the user's shell files.
    path_dir="$dir"
    [ -z "${HOME:-}" ] || [ "$dir" != "$HOME/.local/bin" ] || path_dir='$HOME/.local/bin'
    case "${SHELL:-}" in
      */zsh) rc='~/.zshrc'; line="export PATH=\"$path_dir:\$PATH\"" ;;
      */bash) rc='~/.bashrc'; line="export PATH=\"$path_dir:\$PATH\"" ;;
      */fish) rc='~/.config/fish/config.fish'; line="fish_add_path \"$path_dir\"" ;;
      *) rc='~/.profile'; line="export PATH=\"$path_dir:\$PATH\"" ;;
    esac
    say ""
    say "Note: $dir is not in your PATH, so your shell will not find dove yet. Add this line to $rc"
    say "and open a new terminal:"
    say ""
    say "  $line"
    ;;
esac

if [ "$(id -u)" -eq 0 ]; then
  upgrade="sudo dove upgrade   (on a server, then restart the service)"
else
  upgrade="dove upgrade   (no sudo needed, this install belongs to you)"
fi
cat <<EOF

Next steps:
  dove --version
  Set up the service:  https://github.com/$REPO/blob/main/docs/deployment.md
  Later upgrades:      $upgrade
EOF
