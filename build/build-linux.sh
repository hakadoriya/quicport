#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:?Usage: $0 <target> <os_name> <arch>}"
OS_NAME="${2:?Usage: $0 <target> <os_name> <arch>}"
ARCH="${3:?Usage: $0 <target> <os_name> <arch>}"

BIN_NAME="quicport"

# glibc バージョンマッピング
case "$TARGET" in
  x86_64-unknown-linux-gnu)  GLIBC_VERSION=".2.17" ;;
  aarch64-unknown-linux-gnu) GLIBC_VERSION=".2.28" ;;
  *) echo "Error: Unknown Linux target: $TARGET" >&2; exit 1 ;;
esac

# ビルド
cargo zigbuild --release --locked --target "${TARGET}${GLIBC_VERSION}"

# パッケージング
STAGE="stage/${TARGET}"
OUT="out"

mkdir -p "${STAGE}" "${OUT}"
cp "target/${TARGET}/release/${BIN_NAME}" "${STAGE}/"
[[ -f README.md ]] && cp README.md "${STAGE}/"
[[ -f LICENSE ]] && cp LICENSE "${STAGE}/"

ARCHIVE="${BIN_NAME}_${OS_NAME}_${ARCH}.zip"
(cd "${STAGE}" && zip -r "../../${OUT}/${ARCHIVE}" .)
shasum -a 256 "${OUT}/${ARCHIVE}" > "${OUT}/${ARCHIVE}.sha256"

echo "Created: ${OUT}/${ARCHIVE}"
