//! dc-boot appliance image assembly — pure-Rust initramfs builder +
//! constituents attestation (v0.7.0, Vector 3).
//!
//! The standalone sanitization appliance is:
//!
//! ```text
//!   EFI ISO (El Torito, ~15 MB)
//!     \-- bzImage (kernel, EFI stub)
//!         \-- initramfs (cpio newc, UNCOMPRESSED — deterministic bytes)
//!               /init   -> the static musl `dc` binary
//!               /docs   -> constituents manifest + build attestation
//! ```
//!
//! When booted (USB stick or PXE), the kernel runs `/init` as PID 1; `dc
//! boot init` performs the real bootstrap sequence (init.rs) and the
//! whole OS lives in RAM: every physical NVMe/SATA/SAS drive is
//! unmounted and sanitizable, including the disk the old OS ran from.
//!
//! This module owns the deterministic, testable parts:
//! - `build_initramfs_cpio`: assemble the cpio `newc` archive (the
//!   kernel's documented initramfs format) from staged files — zero
//!   external tools, byte-deterministic output (REG-APPLIANCE-IMAGE).
//! - `verify_constituents`: re-hash every constituent of a built image
//!   and compare against the signed manifest — the boot-time attestation
//!   gate (extends the v0.6.0 `ConstituentsManifest`).
//!
//! The El Torito ISO wrapper itself is one xorriso invocation in
//! `scripts/build-appliance.sh` (a build-time tool, deliberately outside
//! the shipped binary's trust boundary).

use crate::bootattest::ConstituentsManifest;
use dc_core::DcError;
use std::path::Path;

/// One staged file of the initramfs.
pub struct InitramfsFile<'a> {
    /// Absolute path inside the archive (must start with '/').
    pub path: &'a str,
    pub bytes: &'a [u8],
    /// Executable regular file (0755) vs read-only data (0444).
    pub executable: bool,
}

/// Encode one cpio `newc` header (110-byte ASCII magic+fields).
///
/// Format (kernel Documentation/driver-api/early-userspace/buffer-format.rst):
/// 6 x ASCII-hex fields padded to 8 chars, then namesize hex, then a final
/// checksum field. We emit zero checksum (the kernel ignores it).
fn cpio_newc_header(name: &str, filesize: u64, mode: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(110 + name.len() + 1);
    out.extend_from_slice(b"070701"); // newc magic (no checksum)
    let hex = |v: u64| format!("{:08x}", v).into_bytes();
    // ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
    // rdevmajor, rdevminor, namesize, check
    for value in [1u64, mode as u64, 0, 0, 1, 0, filesize, 0, 0, 0, 0] {
        out.extend_from_slice(&hex(value));
    }
    out.extend_from_slice(&hex((name.len() + 1) as u64));
    out.extend_from_slice(&hex(0)); // check
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    // Pad the header+name to a 4-byte boundary.
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Assemble the initramfs cpio archive (uncompressed `newc` — the kernel
/// accepts it directly; uncompressed keeps the archive byte-deterministic
/// for the constituents hash).
pub fn build_initramfs_cpio(files: &[InitramfsFile<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for file in files {
        let mode: u32 = if file.executable {
            0o100_755
        } else {
            0o100_444
        };
        out.extend_from_slice(&cpio_newc_header(file.path, file.bytes.len() as u64, mode));
        out.extend_from_slice(file.bytes);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    // TRAILER!!! entry terminates the archive.
    out.extend_from_slice(&cpio_newc_header("TRAILER!!!", 0, 0));
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Build the appliance initramfs from a kernel-checked staging set:
/// `/init` (the static dc binary) first, then the constituents manifest.
///
/// SELF-REFERENCE RULE: the embedded manifest carries a ZEROED
/// `initramfs_hash` — a hash cannot contain itself. `verify_constituents`
/// rebuilds the archive from the same zeroed projection and compares the
/// OUTER archive hash against the manifest's real digest.
pub fn build_appliance_initramfs(
    dc_static_binary: &[u8],
    manifest: &ConstituentsManifest,
) -> Vec<u8> {
    let mut embedded = manifest.clone();
    embedded.initramfs_hash = "0".repeat(64); // self-reference rule
    let manifest_json = serde_json::to_string_pretty(&embedded)
        .unwrap_or_default()
        .into_bytes();
    let files = [
        InitramfsFile {
            path: "/init",
            bytes: dc_static_binary,
            executable: true,
        },
        InitramfsFile {
            path: "/dc-constituents.json",
            bytes: &manifest_json,
            executable: false,
        },
    ];
    build_initramfs_cpio(&files)
}

/// Verify every constituent of an appliance build against its manifest
/// (boot-time gate): the kernel image, the dc binary and the initramfs
/// are re-hashed and compared; a mismatch refuses the boot attestation.
pub fn verify_constituents(
    manifest: &ConstituentsManifest,
    kernel_bzimage: &[u8],
    dc_static_binary: &[u8],
    initramfs: &[u8],
) -> Result<(), DcError> {
    // Kernel-less manifests (PXE userspace-only images) carry the zero
    // digest and skip the kernel check.
    if manifest.kernel_hash != "0".repeat(64) {
        let kernel_hash = blake3::hash(kernel_bzimage).to_hex().to_string();
        if kernel_hash != manifest.kernel_hash {
            return Err(DcError::Usage(format!(
                "APPLIANCE_ATTESTATION_FAILED: kernel image hash {} != manifest {}",
                kernel_hash, manifest.kernel_hash
            )));
        }
    }
    let binary_hash = blake3::hash(dc_static_binary).to_hex().to_string();
    if binary_hash != manifest.binary_hash {
        return Err(DcError::Usage(format!(
            "APPLIANCE_ATTESTATION_FAILED: dc binary hash {} != manifest {}",
            binary_hash, manifest.binary_hash
        )));
    }
    // The initramfs check: rebuild the archive from the same zeroed
    // projection (self-reference rule) and compare the OUTER hash.
    let rebuilt = build_appliance_initramfs(dc_static_binary, manifest);
    let rebuilt_hash = blake3::hash(&rebuilt).to_hex().to_string();
    let provided_hash = blake3::hash(initramfs).to_hex().to_string();
    if provided_hash != manifest.initramfs_hash || rebuilt_hash != manifest.initramfs_hash {
        return Err(DcError::Usage(format!(
            "APPLIANCE_ATTESTATION_FAILED: initramfs hash mismatch (file {}, rebuilt {}, \
             manifest {})",
            provided_hash, rebuilt_hash, manifest.initramfs_hash
        )));
    }
    Ok(())
}

/// CLI plumbing helper: read a file's bytes or map the error.
pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>, DcError> {
    std::fs::read(path)
        .map_err(|e| DcError::Usage(format!("cannot read '{}': {}", path.display(), e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpio_newc_header_layout_is_kernel_exact() {
        let header = cpio_newc_header("/init", 5, 0o100_755);
        // Magic.
        assert_eq!(&header[0..6], b"070701");
        // Field order after the magic: ino(6..14), mode(14..22), uid,
        // gid, nlink, mtime, filesize(54..62), devmajor, devminor,
        // rdevmajor, rdevminor, namesize(94..102), check(102..110).
        assert_eq!(&header[6..14], b"00000001"); // ino
        let mode = std::str::from_utf8(&header[14..22]).unwrap();
        // newc fields are ASCII hexadecimal: 0o100755 = 0x81ED.
        assert_eq!(mode, "000081ed"); // S_IFREG | 0755
        assert_eq!(&header[54..62], b"00000005"); // filesize
        assert_eq!(&header[94..102], b"00000006"); // namesize ("/init\0" = 6)
        // Header + name padded to 4.
        assert_eq!(header.len() % 4, 0);
    }

    #[test]
    fn initramfs_is_deterministic_and_parseable() {
        // REG-APPLIANCE-IMAGE: same inputs -> same bytes; TRAILER present;
        // /init first, executable mode encoded.
        let manifest = ConstituentsManifest {
            kernel_hash: "a".repeat(64),
            initramfs_hash: "b".repeat(64),
            binary_hash: "c".repeat(64),
            census_manifest_hash: "d".repeat(64),
        };
        let a = build_appliance_initramfs(b"#!/dc\n", &manifest);
        let b = build_appliance_initramfs(b"#!/dc\n", &manifest);
        assert_eq!(a, b, "initramfs build must be byte-deterministic");
        assert!(a.windows(6).any(|w| w == b"070701"));
        assert!(a.windows(10).any(|w| w == b"TRAILER!!!"));
        // /init appears before /dc-constituents.json.
        let init_pos = a
            .windows(b"/init\0".len())
            .position(|w| w == b"/init\0")
            .unwrap();
        let doc_pos = a
            .windows(b"/dc-constituents.json".len())
            .position(|w| w == b"/dc-constituents.json")
            .unwrap();
        assert!(init_pos < doc_pos);
    }

    #[test]
    fn constituents_verification_catches_tampering() {
        let dc_binary = b"static-musl-dc".as_slice();
        let kernel = b"bzImage-bytes".as_slice();
        let manifest = ConstituentsManifest {
            kernel_hash: blake3::hash(kernel).to_hex().to_string(),
            initramfs_hash: "0".repeat(64),
            binary_hash: blake3::hash(dc_binary).to_hex().to_string(),
            census_manifest_hash: "0".repeat(64),
        };
        let initramfs = build_appliance_initramfs(dc_binary, &manifest);
        // Correct binary + kernel: pass (initramfs hash field in the
        // manifest is a build-time digest; the verifier re-checks the
        // binary it will EXECUTE, so pass a manifest whose initramfs_hash
        // matches the rebuilt archive).
        let mut good = manifest.clone();
        good.initramfs_hash = blake3::hash(&initramfs).to_hex().to_string();
        assert!(verify_constituents(&good, kernel, dc_binary, &initramfs).is_ok());

        // Tampered kernel: refuse.
        let tampered = b"bzImage-EVIL".as_slice();
        assert!(verify_constituents(&good, tampered, dc_binary, &initramfs).is_err());
        // Tampered binary: refuse.
        assert!(verify_constituents(&good, kernel, b"backdoored-dc", &initramfs).is_err());
    }
}
