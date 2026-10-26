#!/bin/sh
# Installs mx-detective on Linux (x86_64) or macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/mottipython/mx-detective/master/install.sh | sh
#
# A specific version, or another folder:
#
#   curl -fsSL .../install.sh | MX_DETECTIVE_VERSION=v1.0.0 sh
#   curl -fsSL .../install.sh | MX_DETECTIVE_DIR=/usr/local/bin sh
#
# It downloads the release archive, checks it against the release's SHA256SUMS.txt and
# installs the binary into ~/.local/bin (or /usr/local/bin when run as root). Run it
# again at any time to update.
set -eu

repo="mottipython/mx-detective"
version="${MX_DETECTIVE_VERSION:-latest}"
if [ "$(id -u)" -eq 0 ]; then default_dir=/usr/local/bin; else default_dir="$HOME/.local/bin"; fi
dir="${MX_DETECTIVE_DIR:-$default_dir}"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) asset="mx-detective-linux-x86_64.tar.gz" ;;
    Darwin-arm64) asset="mx-detective-aarch64-apple-darwin.tar.gz" ;;
    Darwin-x86_64) asset="mx-detective-x86_64-apple-darwin.tar.gz" ;;
    *) echo "install.sh: no build for $(uname -s) $(uname -m); see https://github.com/$repo/releases" >&2; exit 1 ;;
esac

if [ "$version" = latest ]; then
    base="https://github.com/$repo/releases/latest/download"
else
    base="https://github.com/$repo/releases/download/$version"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q "$1" -O "$2"; }
else
    echo "install.sh: needs curl or wget" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch "$base/$asset" "$tmp/$asset"
fetch "$base/SHA256SUMS.txt" "$tmp/SHA256SUMS.txt"

expected="$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS.txt")"
if [ -z "$expected" ]; then echo "install.sh: SHA256SUMS.txt has no entry for $asset" >&2; exit 1; fi
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$asset" | awk '{ print $1 }')"
else
    actual="$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')"
fi
if [ "$actual" != "$expected" ]; then
    echo "install.sh: checksum mismatch for $asset (expected $expected, got $actual). Nothing was installed." >&2
    exit 1
fi

tar -xzf "$tmp/$asset" -C "$tmp"
binary="$(find "$tmp" -type f -name mx-detective | head -n 1)"
mkdir -p "$dir"
install -m 755 "$binary" "$dir/mx-detective"

echo "Installed $("$dir/mx-detective" --version) to $dir"
case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "Note: $dir is not on your PATH. Add it with:  export PATH=\"$dir:\$PATH\"" ;;
esac
echo "Try:  mx-detective example.com"
