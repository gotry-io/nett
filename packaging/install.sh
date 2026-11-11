#!/bin/sh
# Installs nett on Linux and macOS, so that `nett` is on the path:
#
#   curl -fsSL https://nett.gotry.io/install.sh | sh
#
# It downloads the archive for this system and architecture, checks it against the SHA-256 written
# below for this release, and installs only the nett program. It reads no token, contacts no Hub
# and writes no configuration: `sudo nett install` does that afterwards. Each release's archives
# and signatures are also published at https://github.com/gotry-io/nett/releases.
#
# On Linux the program goes to /usr/local/lib/nett/nett, linked from /usr/local/bin/nett: the
# services run it from its own directory, where nett-node replaces it when it upgrades itself.
# On macOS it goes to /usr/local/bin/nett.
set -eu

VERSION="@VERSION@"
BASE="https://nett.gotry.io/dl"
LINK="/usr/local/bin/nett"

fail() {
    printf 'nett install: %s\n' "$*" >&2
    exit 1
}

case "$(uname -s)" in
    Linux) os=linux program=/usr/local/lib/nett/nett ;;
    Darwin) os=darwin program="$LINK" ;;
    *) fail "nett runs on Linux and macOS, not on $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "nett is built for x86_64 and aarch64, not for $(uname -m)" ;;
esac
case "$os-$arch" in
    linux-x86_64) target=x86_64-unknown-linux-musl sum="@SHA256_X86_64_LINUX@" ;;
    linux-aarch64) target=aarch64-unknown-linux-musl sum="@SHA256_AARCH64_LINUX@" ;;
    darwin-x86_64) target=x86_64-apple-darwin sum="@SHA256_X86_64_DARWIN@" ;;
    darwin-aarch64) target=aarch64-apple-darwin sum="@SHA256_AARCH64_DARWIN@" ;;
esac

for tool in curl tar mktemp install ln; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is needed to install nett"
done
if command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
    fail "sha256sum or shasum is needed to check the download"
fi

if [ -L "$LINK" ] && [ "$(readlink "$LINK")" != "$program" ]; then
    fail "$LINK is a link made by another installer, probably Homebrew; upgrade it with \`brew upgrade nett\`"
fi
if [ "$(id -u)" -eq 0 ]; then
    as_root=""
elif command -v sudo >/dev/null 2>&1; then
    as_root="sudo"
else
    fail "run this as root: $(dirname "$program") is only writable by root"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
file="nett-$VERSION-$target.tar.gz"
printf 'Downloading nett %s for %s.\n' "$VERSION" "$target"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$file" "$BASE/$file" ||
    fail "downloading $BASE/$file failed"
[ "$(digest "$tmp/$file")" = "$sum" ] ||
    fail "$file does not match the checksum in this script; nothing was installed"
tar -xzf "$tmp/$file" -C "$tmp" nett || fail "unpacking $file failed"
$as_root mkdir -p "$(dirname "$program")" "$(dirname "$LINK")"
$as_root install -m 0755 "$tmp/nett" "$program" ||
    fail "copying nett to $program failed"
if [ "$program" != "$LINK" ]; then
    $as_root ln -sfn "$program" "$LINK" || fail "linking $LINK failed"
fi
printf 'Installed nett %s to %s.\n' "$VERSION" "$program"
