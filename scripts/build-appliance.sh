#!/usr/bin/env bash
# =============================================================================
# build-appliance.sh — the discCleaner standalone bare-metal micro-appliance
# (v0.7.0, Vector 3).
#
# Produces a zero-dependency, RAM-resident EFI boot kit (~15 MB class):
#
#   dc-boot.iso
#     \-- El Torito boot image (xorriso)
#           \-- bzImage (Linux kernel, EFI stub, embedded defconfig)
#               \-- initramfs (cpio newc, built by `dc boot pack`)
#                     /init  -> statically-linked musl `dc` binary (PID 1)
#
# When booted from USB or PXE, the entire OS runs from RAM: every physical
# NVMe/SATA/SAS drive is unmounted and sanitizable — including the disk the
# previous OS ran from. No shell, no package manager, no live-USB distro.
#
# Requirements (build host only — the appliance itself has zero deps):
#   rustup target x86_64-unknown-linux-musl, kernel sources + gcc, xorriso.
#
# Usage:
#   ./scripts/build-appliance.sh [kernel-version]     # default: 6.12
#   DC_KERNEL_BZIMAGE=/path/bzImage ./scripts/build-appliance.sh
#     (skip the kernel build entirely; use a prebuilt kernel)
# =============================================================================
set -euo pipefail

KERNEL_VERSION="${1:-6.12}"
WORK="$(pwd)/target/appliance/work"
OUT_DIR="$(pwd)/target/appliance"
OUT_ISO="$OUT_DIR/dc-boot.iso"
KERNEL_SRC="$WORK/linux-$KERNEL_VERSION"
KERNEL_BZIMAGE="${DC_KERNEL_BZIMAGE:-$KERNEL_SRC/arch/x86_64/boot/bzImage}"
STATIC_DC="$WORK/dc"
NPROC="$(nproc)"

log() { printf '\n\033[1;36m[dc-boot]\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m[dc-boot] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v xorriso >/dev/null 2>&1 || die "xorriso not found (apt install xorriso)"

mkdir -p "$WORK" "$OUT_DIR"

# -----------------------------------------------------------------------------
# 1. Statically-linked musl `dc` (the whole userspace).
# -----------------------------------------------------------------------------
if [[ ! -x "$STATIC_DC" ]]; then
    log "building the static musl dc binary (the entire appliance userspace)"
    rustup target add x86_64-unknown-linux-musl \
        || die "cannot add the musl target (rustup required)"
    ( RUSTFLAGS="-C target-feature=+crt-static" \
        cargo build --release -p dc-cli --target x86_64-unknown-linux-musl ) \
        || die "musl build failed"
    cp target/x86_64-unknown-linux-musl/release/dc "$STATIC_DC"
    file "$STATIC_DC" | grep -q 'statically linked' \
        || die "the dc binary is not static — the appliance cannot run it"
fi

# -----------------------------------------------------------------------------
# 2. Kernel: minimal EFI-stub build (skip when DC_KERNEL_BZIMAGE points at a
#    prebuilt kernel).
# -----------------------------------------------------------------------------
if [[ ! -f "$KERNEL_BZIMAGE" ]]; then
    log "building the kernel $KERNEL_VERSION (defconfig + storage/EFI set)"
    [[ -d "$KERNEL_SRC" ]] || {
        curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz" \
            -o "$WORK/linux-$KERNEL_VERSION.tar.xz" \
            || die "kernel download failed"
        tar -xf "$WORK/linux-$KERNEL_VERSION.tar.xz" -C "$WORK"
    }
    cd "$KERNEL_SRC"
    make -j"$NPROC" x86_64_defconfig
    # Sanitization-appliance requirements: EFI stub boot, all NVMe/SATA/SAS
    # controllers, devtmpfs (PID-1 /dev), hwmon thermal (Vector 2).
    ./scripts/config \
        -e EFI -e EFI_STUB \
        -e DEVTMPFS -e DEVTMPFS_MOUNT \
        -e BLK_DEV_NVME -e NVME_CORE -e NVME_MULTIPATH \
        -e SATA_AHCI -e ATA -e ATA_PIIX -e AHCI_XGENE \
        -e SCSI -e BLK_DEV_SD -e SCSI_SAS_ATA -e SCSI_MPT3SAS \
        -e USB_STORAGE -e USB_UAS \
        -e HWMON -e SENSORS_DRIVETEMP \
        -e TTY -e SERIAL_8250 -e VT \
        -d MODULES -e EMBEDDED \
        -e TMPFS -e PROC_FS -e SYSFS \
        -e X86_REROUTE_FOR_BROKEN_BOOT_IRQS
    make -j"$NPROC" -s bzImage || die "kernel build failed"
    cd - >/dev/null
fi
[[ -f "$KERNEL_BZIMAGE" ]] || die "no kernel bzImage at $KERNEL_BZIMAGE"

# -----------------------------------------------------------------------------
# 3. Initramfs: pure-Rust cpio via `dc boot pack` (deterministic, attested).
# -----------------------------------------------------------------------------
log "packing the appliance initramfs (cpio newc, constituents attested)"
INITRAMFS="$WORK/dc-appliance-initramfs.cpio"
"$STATIC_DC" boot pack \
    --dc-bin "$STATIC_DC" \
    --kernel "$KERNEL_BZIMAGE" \
    --out "$INITRAMFS" \
    || die "dc boot pack failed"
MANIFEST="${INITRAMFS%.cpio}.manifest.json"
[[ -s "$MANIFEST" ]] || die "constituents manifest missing"

# Boot-time attestation self-check: the verifier re-hashes every constituent.
log "verifying constituents: $MANIFEST"
"$STATIC_DC" boot pack \
    --dc-bin "$STATIC_DC" \
    --kernel "$KERNEL_BZIMAGE" \
    --verify-against "$MANIFEST" \
    --out "$WORK/verify.cpio" \
    || die "constituents verification FAILED — refusing to ship the image"

# -----------------------------------------------------------------------------
# 4. El Torito ISO (xorriso): the kernel image boots via BIOS El Torito and
#    its EFI stub handles UEFI; the initramfs travels appended.
# -----------------------------------------------------------------------------
log "assembling the El Torito ISO"
EFI_TREE="$WORK/efi-tree"
rm -rf "$EFI_TREE"; mkdir -p "$EFI_TREE/boot"
cp "$KERNEL_BZIMAGE" "$EFI_TREE/boot/vmlinuz-dc"
printf 'rdinit=/init console=tty0 console=ttyS0,115200 quiet\n' \
    > "$EFI_TREE/boot/cmdline-dc"

xorriso -as mkisofs \
    -quiet \
    -o "$OUT_ISO" \
    -b boot/vmlinuz-dc \
    -c boot/boot.cat \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -graft-points "boot=$EFI_TREE/boot" \
    || die "xorriso failed"

log "appliance ISO ready: $OUT_ISO ($(du -h "$OUT_ISO" | cut -f1))"
log "  dd it to a USB stick:  dd if=$OUT_ISO of=/dev/sdX bs=4M oflag=direct && sync"
log "  boot it, and the appliance runs `dc boot init` as PID 1 (RAM-resident,"
log "  every physical disk unmounted). The initramfs ships beside the ISO at"
log "  $INITRAMFS for PXE deployments (initrd=.../dc-appliance-initramfs.cpio)."
