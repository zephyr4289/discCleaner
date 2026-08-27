# diskCleaner

A small Rust CLI for securely wiping a block device (drive) before resale
or disposal.

Tries a firmware-level erase first (NVMe Sanitize / ATA Secure Erase), and
falls back to a full zero-fill overwrite if that isn't supported.

## What it does

1. Opens the target device and prints its size.
2. Asks for confirmation (`y`/`n`) before touching anything.
3. Tries NVMe Sanitize or ATA Secure Erase, depending on the device.
4. If that's unsupported, falls back to writing zeros across the entire
   device.

## What it does NOT guarantee

- Zero-fill defeats normal and forensic recovery software, but on SSDs it
  cannot reach the drive's reserved over-provisioned area (physical flash
  the controller hides from the OS). A successful Secure Erase/Sanitize
  closes this gap; a zero-fill fallback does not.
- This tool does not check whether the target is your OS drive. **Double
  and triple check the device path before confirming.**

## Requirements

- Linux (uses Linux-specific ioctls)
- Rust toolchain (`cargo`) to build
- `hdparm` and `nvme-cli` installed, for the Secure Erase / Sanitize paths:
  ```
  sudo apt install hdparm nvme-cli
  ```
- Root privileges to run (raw device access)

## Build

```bash
cargo build --release
```

The compiled binary will be at `target/release/diskCleaner`.

## Install (so you can run it as a normal command)

```bash
sudo cp target/release/diskCleaner /usr/local/bin/diskCleaner
sudo chmod +x /usr/local/bin/diskCleaner
```

`/usr/local/bin` is the standard place for locally-built binaries — it's
already on `PATH` on most Linux systems and won't get overwritten by
package manager updates the way `/bin` or `/usr/bin` might.

After this you can run it from anywhere as:

```bash
sudo diskCleaner --wipe /dev/sdX
```

## Usage

```bash
# List drives first to find the right device path
lsblk

# Wipe (replace /dev/sdX with your actual target)
sudo diskCleaner --wipe /dev/sdX
```

You'll be shown the device path and asked to confirm before anything is
written.

## Uninstall

```bash
sudo rm /usr/local/bin/diskCleaner
```

## Safety

This is a destructive, irreversible tool. Test it against a spare/disposable
drive first if you're unsure. Always confirm the device path with `lsblk`
before running — there is currently no built-in check preventing you from
targeting your boot/root drive.
