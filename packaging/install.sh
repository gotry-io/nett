#!/bin/sh
# 安装 nett（design/release.md 第 6 节）：判断系统与架构，从项目网站下载这个版本的压缩包，按下面写明的
# SHA-256 核对，放到 /usr/local/bin/nett。不读 token、不连接 Hub、不写配置：入网与服务由之后的
# `sudo nett install` 完成。这是模板，发布工作流填入版本与哈希之后部署到 https://nett.gotry.io/install.sh。
#
#   curl -fsSL https://nett.gotry.io/install.sh | sh
set -eu

VERSION="@VERSION@"
BASE="https://nett.gotry.io/dl"
TARGET_DIR="/usr/local/bin"

fail() {
    printf 'nett install: %s\n' "$*" >&2
    exit 1
}

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
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

for tool in curl tar mktemp install; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is needed to install nett"
done
if command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
    fail "sha256sum or shasum is needed to check the download"
fi

if [ -L "$TARGET_DIR/nett" ]; then
    fail "$TARGET_DIR/nett is a link, probably from Homebrew; upgrade it with \`brew upgrade nett\`"
fi
if [ "$(id -u)" -eq 0 ]; then
    as_root=""
elif command -v sudo >/dev/null 2>&1; then
    as_root="sudo"
else
    fail "run this as root: $TARGET_DIR is only writable by root"
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
$as_root mkdir -p "$TARGET_DIR"
$as_root install -m 0755 "$tmp/nett" "$TARGET_DIR/nett" ||
    fail "copying nett to $TARGET_DIR failed"
printf 'Installed nett %s to %s/nett.\n' "$VERSION" "$TARGET_DIR"
