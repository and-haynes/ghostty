#!/usr/bin/env bash
# Build libghostty-vt as an XCFramework and stage it for the iOS app.
#
# Upstream Ghostty no longer ships an iOS app target; libghostty-vt is the
# only part of the tree that builds for iOS (see src/build/Config.zig). This
# script builds it from the repo root and copies the result into
# ios/Frameworks/, which is gitignored because it is a build artifact.
#
# Usage:  ./build-libvt.sh [--force]
#   --force   rebuild even if zig-out already has an xcframework
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
XCF_SRC="${REPO_ROOT}/zig-out/lib/ghostty-vt.xcframework"
XCF_DST="${SCRIPT_DIR}/Frameworks/ghostty-vt.xcframework"

ZIG="${ZIG:-$(command -v zig || echo /opt/homebrew/bin/zig)}"
FORCE="${1:-}"

if [[ ! -x "${ZIG}" ]]; then
  echo "error: zig not found (set ZIG=/path/to/zig). Need zig 0.16.0." >&2
  exit 1
fi

if [[ "${FORCE}" == "--force" || ! -d "${XCF_SRC}" ]]; then
  echo "==> building ghostty-vt.xcframework with ${ZIG} ($(${ZIG} version))"
  echo "    this takes roughly 5-10 minutes"
  (cd "${REPO_ROOT}" && "${ZIG}" build \
      -Demit-lib-vt \
      -Demit-xcframework \
      -Doptimize=ReleaseFast)
else
  echo "==> reusing existing ${XCF_SRC} (pass --force to rebuild)"
fi

if [[ ! -d "${XCF_SRC}" ]]; then
  echo "error: ${XCF_SRC} was not produced by the zig build" >&2
  exit 1
fi

echo "==> staging into ${XCF_DST}"
mkdir -p "${SCRIPT_DIR}/Frameworks"
rm -rf "${XCF_DST}"
cp -R "${XCF_SRC}" "${XCF_DST}"

echo "==> slices:"
/usr/libexec/PlistBuddy -c 'Print :AvailableLibraries' "${XCF_DST}/Info.plist" \
  | grep -E 'LibraryIdentifier' || true
echo "done."
