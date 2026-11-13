#!/bin/sh
# Prints the Homebrew formula for a release on stdout.
#
#   deploy/homebrew/render.sh <X.Y.Z> <SHA256SUMS>
#
# SHA256SUMS is the release's checksum list; every platform the formula installs must be listed exactly once.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
[ "$#" -eq 2 ] || { echo "usage: $0 <X.Y.Z> <SHA256SUMS>" >&2; exit 2; }
version=$1
sums=$2

printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "render.sh: '$version' is not a stable X.Y.Z version" >&2; exit 1; }
[ -r "$sums" ] || { echo "render.sh: cannot read $sums" >&2; exit 1; }

# The checksum of dove-v<version>-<target>.tar.gz; fails unless the list has exactly one valid line for it.
sha_of() {
  name="dove-v$version-$1.tar.gz"
  found=$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1 }' "$sums")
  count=$(printf '%s\n' "$found" | grep -c . || true)
  [ "$count" -eq 1 ] || { echo "render.sh: $name is listed $count times in $sums (expected once)" >&2; exit 1; }
  printf '%s' "$found" | grep -Eq '^[0-9a-f]{64}$' || { echo "render.sh: bad checksum for $name" >&2; exit 1; }
  printf '%s' "$found"
}

a_mac=$(sha_of aarch64-apple-darwin)
x_mac=$(sha_of x86_64-apple-darwin)
a_lin=$(sha_of aarch64-unknown-linux-gnu)
x_lin=$(sha_of x86_64-unknown-linux-gnu)

sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@SHA_AARCH64_APPLE_DARWIN@/$a_mac/" \
  -e "s/@SHA_X86_64_APPLE_DARWIN@/$x_mac/" \
  -e "s/@SHA_AARCH64_UNKNOWN_LINUX_GNU@/$a_lin/" \
  -e "s/@SHA_X86_64_UNKNOWN_LINUX_GNU@/$x_lin/" \
  "$here/dove.rb.in"
