#!/usr/bin/env bash
# ==============================================================================
# MX Detective - Multi-Platform Packaging Script
# Builds Release binary, RPM package (.rpm), Debian package (.deb),
# Arch Linux package (.pkg.tar.zst), Windows (.zip), and macOS (.tar.gz)
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="0.1.0"

echo -e "\033[1;96m╔═══════════════════════════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[1;96m║               MX DETECTIVE - PACKAGING & DISTRIBUTION BUILDER             ║\033[0m"
echo -e "\033[1;96m╚═══════════════════════════════════════════════════════════════════════════╝\033[0m"

mkdir -p "${DIST_DIR}"

# 1. Build Optimized Release Binary
echo -e "\n\033[1;94m[*] Compiling optimized release binary with cargo...\033[0m"
cd "${ROOT_DIR}"
cargo build --release

BIN_PATH="${ROOT_DIR}/target/release/mx-detective"
if [[ ! -f "${BIN_PATH}" ]]; then
    echo -e "\033[1;91m[!] Release binary not found at ${BIN_PATH}\033[0m"
    exit 1
fi
echo -e "\033[1;92m[✓] Release binary compiled successfully.\033[0m"

# 2. Build Linux Tarball (.tar.gz)
echo -e "\n\033[1;94m[*] Creating Linux x86_64 standalone tarball...\033[0m"
TARBALL_DIR="${DIST_DIR}/mx-detective-linux-x86_64"
rm -rf "${TARBALL_DIR}"
mkdir -p "${TARBALL_DIR}"
cp "${BIN_PATH}" "${TARBALL_DIR}/"
cp "${ROOT_DIR}/packaging/desktop/mx-detective.desktop" "${TARBALL_DIR}/"
cp "${ROOT_DIR}/README.md" "${TARBALL_DIR}/"
tar -czvf "${DIST_DIR}/mx-detective-v${VERSION}-linux-x86_64.tar.gz" -C "${DIST_DIR}" "mx-detective-linux-x86_64"
rm -rf "${TARBALL_DIR}"
echo -e "\033[1;92m[✓] Tarball created: ${DIST_DIR}/mx-detective-v${VERSION}-linux-x86_64.tar.gz\033[0m"

# 3. Build RPM Package (.rpm)
echo -e "\n\033[1;94m[*] Building Fedora / RHEL / CentOS RPM package (.rpm)...\033[0m"
RPM_TOP="${ROOT_DIR}/target/rpm_top"
rm -rf "${RPM_TOP}"
mkdir -p "${RPM_TOP}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp "${BIN_PATH}" "${RPM_TOP}/SOURCES/"
cp "${ROOT_DIR}/packaging/desktop/mx-detective.desktop" "${RPM_TOP}/SOURCES/"

rpmbuild \
    --define "_topdir ${RPM_TOP}" \
    --define "_tmppath /tmp" \
    -bb "${ROOT_DIR}/packaging/rpm/mx-detective.spec"

RPM_FILE=$(find "${RPM_TOP}/RPMS" -name "*.rpm" | head -n 1)
cp "${RPM_FILE}" "${DIST_DIR}/"
echo -e "\033[1;92m[✓] RPM Package created: ${DIST_DIR}/$(basename "${RPM_FILE}")\033[0m"

# 4. Build Debian / Ubuntu Package (.deb)
echo -e "\n\033[1;94m[*] Building Debian / Ubuntu package (.deb)...\033[0m"
DEB_BUILD="${ROOT_DIR}/target/deb_build"
rm -rf "${DEB_BUILD}"
mkdir -p "${DEB_BUILD}/data/usr/bin"
mkdir -p "${DEB_BUILD}/data/usr/share/applications"
mkdir -p "${DEB_BUILD}/control"

cp "${BIN_PATH}" "${DEB_BUILD}/data/usr/bin/mx-detective"
cp "${ROOT_DIR}/packaging/desktop/mx-detective.desktop" "${DEB_BUILD}/data/usr/share/applications/mx-detective.desktop"

cat << EOF > "${DEB_BUILD}/control/control"
Package: mx-detective
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Motti Schleider <motti.schleider@gmail.com>
Description: Public MX server, SMTP handshake and mail security diagnostic tool
 MX Detective is a comprehensive diagnostic tool with both GUI and CLI
 for testing public MX server connections, evaluating anti-spam tarpitting,
 detecting SMTP protocol misbehaviors, inspecting STARTTLS encryption,
 and auditing SPF, DMARC, and Reverse DNS (PTR/FCrDNS).
EOF

echo "2.0" > "${DEB_BUILD}/debian-binary"

cd "${DEB_BUILD}/control"
tar -czf ../control.tar.gz .

cd "${DEB_BUILD}/data"
tar -czf ../data.tar.gz .

cd "${DEB_BUILD}"
DEB_OUTPUT="${DIST_DIR}/mx-detective_${VERSION}_amd64.deb"
ar rcs "${DEB_OUTPUT}" debian-binary control.tar.gz data.tar.gz
echo -e "\033[1;92m[✓] DEB Package created: ${DEB_OUTPUT}\033[0m"

# 5. Build Arch Linux Package (.pkg.tar.zst)
echo -e "\n\033[1;94m[*] Building Arch Linux package (.pkg.tar.zst)...\033[0m"
ARCH_DIR="${ROOT_DIR}/target/arch_build"
rm -rf "${ARCH_DIR}"
mkdir -p "${ARCH_DIR}"/usr/bin
mkdir -p "${ARCH_DIR}"/usr/share/applications
mkdir -p "${ARCH_DIR}"/usr/share/doc/mx-detective
cp "${BIN_PATH}" "${ARCH_DIR}"/usr/bin/mx-detective
cp "${ROOT_DIR}/packaging/desktop/mx-detective.desktop" "${ARCH_DIR}"/usr/share/applications/
cp "${ROOT_DIR}/README.md" "${ARCH_DIR}"/usr/share/doc/mx-detective/
for s in 32 48 64 128 256; do
    mkdir -p "${ARCH_DIR}/usr/share/icons/hicolor/${s}x${s}/apps"
    cp "${ROOT_DIR}/packaging/icons/hicolor/${s}x${s}/apps/mx-detective.png" "${ARCH_DIR}/usr/share/icons/hicolor/${s}x${s}/apps/"
done
mkdir -p "${ARCH_DIR}/usr/share/icons/hicolor/scalable/apps"
cp "${ROOT_DIR}/packaging/icons/hicolor/scalable/apps/mx-detective.svg" "${ARCH_DIR}/usr/share/icons/hicolor/scalable/apps/"

TOTAL_SIZE=$(du -sb "${ARCH_DIR}" | awk '{print $1}')
BUILD_DATE=$(date +%s)
cat << EOF > "${ARCH_DIR}/.PKGINFO"
pkgname = mx-detective
pkgbase = mx-detective
pkgver = ${VERSION}-1
pkgdesc = Public MX server, SMTP handshake and mail security diagnostic tool
url = https://github.com/mottipython/mx-detective
builddate = ${BUILD_DATE}
packager = Motti Schleider <motti.schleider@gmail.com>
size = ${TOTAL_SIZE}
arch = x86_64
license = MIT
depend = openssl
depend = libx11
depend = libxcursor
depend = libxrandr
depend = libxi
EOF

cd "${ARCH_DIR}"
ARCH_OUTPUT="${DIST_DIR}/mx-detective-${VERSION}-1-x86_64.pkg.tar.zst"
tar --use-compress-program="zstd -19 -T0" -cf "${ARCH_OUTPUT}" .PKGINFO usr/
rm -rf "${ARCH_DIR}"
echo -e "\033[1;92m[✓] Arch Linux Package created: ${ARCH_OUTPUT}\033[0m"

# 6. Windows Package (.zip) if compiled
WIN_BIN="${ROOT_DIR}/target/x86_64-pc-windows-gnu/release/mx-detective.exe"
if [[ -f "${WIN_BIN}" ]]; then
    echo -e "\n\033[1;94m[*] Packaging Windows x86_64 release (.zip)...\033[0m"
    WIN_TMP="${ROOT_DIR}/target/win_pkg"
    rm -rf "${WIN_TMP}"
    mkdir -p "${WIN_TMP}/mx-detective-windows-x86_64"
    cp "${WIN_BIN}" "${WIN_TMP}/mx-detective-windows-x86_64/"
    cp "${ROOT_DIR}/README.md" "${WIN_TMP}/mx-detective-windows-x86_64/"
    (cd "${WIN_TMP}" && zip -r "${DIST_DIR}/mx-detective-v${VERSION}-windows-x86_64.zip" mx-detective-windows-x86_64)
    rm -rf "${WIN_TMP}"
    echo -e "\033[1;92m[✓] Windows package created: ${DIST_DIR}/mx-detective-v${VERSION}-windows-x86_64.zip\033[0m"
fi

# 7. macOS Packages (.tar.gz) if compiled
DARWIN_X86="${ROOT_DIR}/target/x86_64-apple-darwin/release/mx-detective"
if [[ -f "${DARWIN_X86}" ]]; then
    echo -e "\n\033[1;94m[*] Packaging macOS x86_64 release (.tar.gz)...\033[0m"
    MAC_TMP="${ROOT_DIR}/target/mac_x86_pkg"
    rm -rf "${MAC_TMP}"
    mkdir -p "${MAC_TMP}/mx-detective-macos-x86_64"
    cp "${DARWIN_X86}" "${MAC_TMP}/mx-detective-macos-x86_64/"
    cp "${ROOT_DIR}/README.md" "${MAC_TMP}/mx-detective-macos-x86_64/"
    tar -czvf "${DIST_DIR}/mx-detective-v${VERSION}-macos-x86_64.tar.gz" -C "${MAC_TMP}" mx-detective-macos-x86_64
    rm -rf "${MAC_TMP}"
    echo -e "\033[1;92m[✓] macOS x86_64 package created: ${DIST_DIR}/mx-detective-v${VERSION}-macos-x86_64.tar.gz\033[0m"
fi

DARWIN_ARM="${ROOT_DIR}/target/aarch64-apple-darwin/release/mx-detective"
if [[ -f "${DARWIN_ARM}" ]]; then
    echo -e "\n\033[1;94m[*] Packaging macOS Apple Silicon release (.tar.gz)...\033[0m"
    MAC_TMP="${ROOT_DIR}/target/mac_arm_pkg"
    rm -rf "${MAC_TMP}"
    mkdir -p "${MAC_TMP}/mx-detective-macos-aarch64"
    cp "${DARWIN_ARM}" "${MAC_TMP}/mx-detective-macos-aarch64/"
    cp "${ROOT_DIR}/README.md" "${MAC_TMP}/mx-detective-macos-aarch64/"
    tar -czvf "${DIST_DIR}/mx-detective-v${VERSION}-macos-aarch64.tar.gz" -C "${MAC_TMP}" mx-detective-macos-aarch64
    rm -rf "${MAC_TMP}"
    echo -e "\033[1;92m[✓] macOS aarch64 package created: ${DIST_DIR}/mx-detective-v${VERSION}-macos-aarch64.tar.gz\033[0m"
fi

echo -e "\n\033[1;96m═══════════════════════════════════════════════════════════════════════════\033[0m"
echo -e "\033[1;92m All packages built successfully in: ${DIST_DIR}\033[0m"
ls -lh "${DIST_DIR}"
echo -e "\033[1;96m═══════════════════════════════════════════════════════════════════════════\033[0m"
