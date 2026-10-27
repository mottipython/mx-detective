#!/usr/bin/env bash
# Writes the winget manifests for a published release into dist/winget/, ready to submit to
# microsoft/winget-pkgs (for example with `wingetcreate submit` or a pull request). It reads the
# installer's checksum from the release's SHA256SUMS.txt:
#
#   scripts/winget-manifest.sh 1.2.0
set -euo pipefail

version="${1:?usage: winget-manifest.sh VERSION}"
version="${version#v}"
repo="mottipython/mx-detective"
asset="mx-detective-setup-windows-x86_64.exe"
base="https://github.com/${repo}/releases/download/v${version}"

cd "$(dirname "$0")/.."
sha="$(curl -fsSL "${base}/SHA256SUMS.txt" | awk -v a="$asset" '$2 == a { print toupper($1) }')"
[ -n "$sha" ] || { echo "no checksum for $asset in v${version}" >&2; exit 1; }

out="dist/winget"
mkdir -p "$out"
id="mottipython.MXDetective"

cat > "$out/${id}.yaml" <<YAML
PackageIdentifier: ${id}
PackageVersion: ${version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
YAML

cat > "$out/${id}.locale.en-US.yaml" <<YAML
PackageIdentifier: ${id}
PackageVersion: ${version}
PackageLocale: en-US
Publisher: mottipython
PublisherUrl: https://github.com/mottipython
PackageName: MX Detective
PackageUrl: https://github.com/mottipython/mx-detective
License: MIT
LicenseUrl: https://github.com/mottipython/mx-detective/blob/master/LICENSE
ShortDescription: Checks a domain's mail setup from the outside, with a command line and a window.
Tags:
- dns
- email
- mx
- smtp
- spf
- dmarc
ManifestType: defaultLocale
ManifestVersion: 1.6.0
YAML

cat > "$out/${id}.installer.yaml" <<YAML
PackageIdentifier: ${id}
PackageVersion: ${version}
InstallerType: inno
Scope: user
InstallModes:
- interactive
- silent
- silentWithProgress
Installers:
- Architecture: x64
  InstallerUrl: ${base}/${asset}
  InstallerSha256: ${sha}
ManifestType: installer
ManifestVersion: 1.6.0
YAML

echo "Wrote $out/ for v${version}"
