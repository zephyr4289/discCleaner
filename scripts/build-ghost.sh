#!/usr/bin/env bash
# Build the discCleaner Ghost Boot EFI payload (v0.12.0, Miracle 3).
#
# Produces: target/x86_64-unknown-uefi/release/dc-ghost-efi.efi
# Deploy:   copy to /EFI/BOOT/BOOTX64.EFI on any FAT32 USB stick.
#
# Requirements: rustup toolchain with the x86_64-unknown-uefi target
#               (installed automatically when rustup is available).
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-uefi

if ! rustup target list --installed 2>/dev/null | grep -q "^${TARGET}$"; then
  echo "[ghost] installing ${TARGET} target via rustup…"
  rustup target add "${TARGET}"
fi

echo "[ghost] building dc-ghost-efi (release, opt-level=z, LTO)…"
cargo build -p dc-baremetal --target "${TARGET}" --profile ghost --features efi "$@"

OUT="target/${TARGET}/release/dc-ghost-efi.efi"
if [ ! -f "${OUT}" ]; then
  # cargo may name the artifact with a .efi or no extension depending
  # on the target spec; normalize.
  if [ -f "target/${TARGET}/release/dc-ghost-efi" ]; then
    cp "target/${TARGET}/release/dc-ghost-efi" "${OUT}"
  else
    echo "[ghost] build artifact not found" >&2
    exit 1
  fi
fi

SIZE=$(stat -c%s "${OUT}")
echo "[ghost] EFI payload: ${OUT} (${SIZE} bytes)"
if [ "${SIZE}" -gt 307200 ]; then
  echo "[ghost] WARNING: payload exceeds the 300 KB budget" >&2
  exit 2
fi
echo "[ghost] deploy: cp ${OUT} /media/USB/EFI/BOOT/BOOTX64.EFI (FAT32)"
