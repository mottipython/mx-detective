#!/usr/bin/env bash
# Rewrites the install section of README.md for a release, so the copy-paste commands
# on the front page always match the newest version. The release workflow runs it after
# publishing; run it by hand with the version number to preview:
#
#   scripts/update-readme.sh 1.0.0
set -euo pipefail

version="${1:?usage: update-readme.sh VERSION}"
version="${version#v}"
tag="v${version}"
repo="mottipython/mx-detective"
download="https://github.com/${repo}/releases/download/${tag}"
raw="https://raw.githubusercontent.com/${repo}/master"

cd "$(dirname "$0")/.."
block="$(mktemp)"
trap 'rm -f "$block"' EXIT

cat > "$block" <<BLOCK
Latest release: **${tag}**, see the [release page](https://github.com/${repo}/releases/tag/${tag}) for notes and checksums. This section is regenerated on every release.

**Windows installer.** Download [mx-detective-setup-windows-x86_64.exe](${download}/mx-detective-setup-windows-x86_64.exe) and run it: a Start menu entry for the window, an optional PATH entry, and an uninstaller in Settings. It installs for your user, no administrator rights needed. For scripts and RMM tools add \`/VERYSILENT\`.

**Windows** (PowerShell). Installs the portable executable for your user and adds it to your PATH, without an installer. Run the same line again to update.

\`\`\`powershell
irm ${raw}/install.ps1 | iex
\`\`\`

Or just download the single \`.exe\` and run it, nothing installed:

\`\`\`powershell
irm ${download}/mx-detective-windows-x86_64.exe -OutFile mx-detective.exe; .\\mx-detective.exe example.com
\`\`\`

**Linux and macOS.** Installs to \`~/.local/bin\` (or \`/usr/local/bin\` as root) after checking the checksum. Run the same line again to update.

\`\`\`bash
curl -fsSL ${raw}/install.sh | sh
\`\`\`

**Linux packages** for ${tag}:

\`\`\`bash
# Debian, Ubuntu
curl -fLO ${download}/mx-detective_${version}_amd64.deb && sudo apt install ./mx-detective_${version}_amd64.deb

# Fedora, RHEL, Rocky
sudo dnf install ${download}/mx-detective-${version}-1.x86_64.rpm

# Arch
curl -fLO ${download}/mx-detective-${version}-1-x86_64.pkg.tar.zst && sudo pacman -U mx-detective-${version}-1-x86_64.pkg.tar.zst
\`\`\`

**A specific version** (for example to keep a fleet on one release):

\`\`\`powershell
& ([scriptblock]::Create((irm ${raw}/install.ps1))) -Version ${tag}
\`\`\`

\`\`\`bash
curl -fsSL ${raw}/install.sh | MX_DETECTIVE_VERSION=${tag} sh
\`\`\`

**Check it worked:** \`mx-detective --version\`. **Uninstall:** Settings > Apps for the installer, or delete \`mx-detective.exe\` from \`%LOCALAPPDATA%\\Programs\\mx-detective\` (Windows) or \`mx-detective\` from \`~/.local/bin\`; packages are removed with your package manager.
BLOCK

{
    sed -n '1,/<!-- install:start -->/p' README.md
    cat "$block"
    sed -n '/<!-- install:end -->/,$p' README.md
} > README.md.new
mv README.md.new README.md
