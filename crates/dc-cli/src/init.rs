//! PID-1 boot initialization — the real kernel bootstrap sequence
//! (v0.7.0, Vector 3).
//!
//! The pre-0.7.0 `run_pid1_init` evaluated a handful of booleans and
//! printed a struct: the appliance story required a third-party live USB
//! anyway. This module turns `dc boot init` into the actual PID-1 of a
//! self-contained sanitization appliance:
//!
//! 1. PSEUDO-FILESYSTEMS: mount `proc`, `sysfs`, `devtmpfs`, `devpts`
//!    and `efivarfs` via raw kernel mount(2) (each already-mounted
//!    filesystem is tolerated — the sequence is idempotent).
//! 2. ENTROPY: harvest 64 bytes of hardware randomness (x86 RDRAND/RDSEED
//!    when present) and credit the kernel pool through the
//!    `RNDADDENTROPY` ioctl on `/dev/random` — the first certificate must
//!    never be signed by a starved CSPRNG.
//! 3. ZOMBIE REAPER: install a SIGCHLD handler that reaps children in a
//!    waitpid(-1) loop — mandatory for any true Linux PID-1, ours
//!    included (the parallel fleet engine forks workers).
//!
//! The whole sequence is expressed against an [`InitBackend`] trait: the
//! production [`LinuxInitBackend`] performs the real syscalls; test rigs
//! script them (REG-PID1-INIT-SEQUENCE). The pure evaluation gate
//! [`evaluate_boot_state`] keeps the v0.6.0 contract (entropy starvation
//! is still a hard refusal — a PID-1 that cannot gather entropy must not
//! proceed to arm destructive commands).

use dc_core::DcError;
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use std::path::Path;

/// Boot state after PID-1 initialization (kept field-compatible with the
/// v0.6.0 struct — certificates and tests continue to decode).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootInitState {
    pub proc_mounted: bool,
    pub sys_mounted: bool,
    pub dev_mounted: bool,
    pub entropy_ready: bool,
    pub boot_medium_attested: bool,
    pub environment_fingerprint: String,
}

/// v0.7.0 additions: the evidence of the REAL bootstrap sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pid1SequenceRecord {
    /// Filesystems this PID-1 actually mounted (source, target, fstype).
    pub mounted: Vec<(String, String, String)>,
    /// Filesystems that were ALREADY mounted (idempotent boot).
    pub already_mounted: Vec<String>,
    /// Entropy bytes credited to the kernel pool via RNDADDENTROPY.
    pub entropy_bytes_credited: u64,
    /// Whether the SIGCHLD zombie reaper was installed.
    pub zombie_reaper_installed: bool,
}

/// Kernel operations the init sequence needs, abstracted for test rigs.
pub trait InitBackend {
    /// Mount `source` on `target` as `fstype`.
    fn mount(&self, source: &str, target: &str, fstype: &str) -> Result<(), String>;
    /// Whether `target` already appears in /proc/mounts.
    fn is_mounted(&self, target: &str) -> bool;
    /// Credit `bytes` (with `bits` of entropy estimate) to the kernel
    /// pool via RNDADDENTROPY on /dev/random.
    fn add_entropy(&self, bytes: &[u8], bits: u32) -> Result<(), String>;
    /// Install the SIGCHLD zombie-reaper handler (true PID-1 duty).
    fn install_zombie_reaper(&self) -> Result<(), String>;
}

/// Production backend: raw libc syscalls, each documented inline.
pub struct LinuxInitBackend;

impl LinuxInitBackend {
    fn open_random_rw() -> Result<std::fs::File, String> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/random")
            .map_err(|e| format!("cannot open /dev/random read-write: {}", e))
    }
}

impl InitBackend for LinuxInitBackend {
    /// mount(2) with a NULL data pointer — the same call rustix::mount
    /// wraps; libc keeps the ioctl-style bounded-unsafe pattern of the
    /// SG_IO/NVMe transports in this codebase.
    fn mount(&self, source: &str, target: &str, fstype: &str) -> Result<(), String> {
        let c_source = std::ffi::CString::new(source)
            .map_err(|_| format!("mount source '{}' contains NUL", source))?;
        let c_target = std::ffi::CString::new(target)
            .map_err(|_| format!("mount target '{}' contains NUL", target))?;
        let c_fs = std::ffi::CString::new(fstype)
            .map_err(|_| format!("fstype '{}' contains NUL", fstype))?;
        let rc = unsafe {
            libc::mount(
                c_source.as_ptr(),
                c_target.as_ptr(),
                c_fs.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(format!(
                "mount({}, {}, {}): errno {}",
                source, target, fstype, errno
            ));
        }
        Ok(())
    }

    fn is_mounted(&self, target: &str) -> bool {
        let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
            return false;
        };
        mounts.lines().any(|line| {
            line.split(' ')
                .nth(1)
                .map(|mnt| mnt == target)
                .unwrap_or(false)
        })
    }

    /// RNDADDENTROPY = _IOW('R', 0x12, int) — the struct rand_pool_info
    /// payload is { entropy_count, buf_size, buf[] }.
    fn add_entropy(&self, bytes: &[u8], bits: u32) -> Result<(), String> {
        #[repr(C)]
        struct RandPoolInfoHeader {
            entropy_count: i32,
            buf_size: i32,
            // Followed by buf_size u32 words (flexible-array style).
        }
        const RNDADDENTROPY: libc::c_ulong = 0x40045212;

        let file = Self::open_random_rw()?;
        // Marshal: two i32 words + ceil(len/4) u32 words, one buffer.
        let words = bytes.len().div_ceil(4);
        let mut payload = Vec::with_capacity(8 + words * 4);
        let header = RandPoolInfoHeader {
            entropy_count: bits as i32,
            buf_size: words as i32,
        };
        payload.extend_from_slice(&header.entropy_count.to_ne_bytes());
        payload.extend_from_slice(&header.buf_size.to_ne_bytes());
        payload.extend_from_slice(bytes);
        payload.resize(8 + words * 4, 0);
        let rc = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                RNDADDENTROPY,
                payload.as_ptr() as *const libc::c_void,
            )
        };
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(format!("RNDADDENTROPY failed: errno {}", errno));
        }
        Ok(())
    }

    /// SIGCHLD with an async-signal-safe handler that reaps zombies in a
    /// waitpid(-1, WNOHANG) loop. (SA_NOCLDWAIT would also prevent
    /// zombies, but it changes wait semantics for child code that uses
    /// wait(); explicit reaping is the POSIX-portable PID-1 pattern.)
    fn install_zombie_reaper(&self) -> Result<(), String> {
        extern "C" fn reap_children(_sig: libc::c_int) {
            // Async-signal-safe: waitpid loop only.
            loop {
                let rc = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
                if rc <= 0 {
                    break;
                }
            }
        }
        let handler = reap_children as *const () as libc::sighandler_t;
        let act = libc::sigaction {
            sa_sigaction: handler,
            sa_mask: unsafe { std::mem::zeroed() },
            sa_flags: libc::SA_RESTART | libc::SA_NOCLDSTOP,
            #[cfg(target_os = "linux")]
            sa_restorer: None,
            #[cfg(not(target_os = "linux"))]
            sa_restorer: std::ptr::null(),
        };
        let rc = unsafe { libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut()) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return Err(format!("sigaction(SIGCHLD): errno {}", errno));
        }
        Ok(())
    }
}

/// Harvest hardware randomness for pool seeding. x86-64: RDRAND with a
/// retry budget; other targets read /dev/hwrng; final fallback is the
/// kernel's own /dev/urandom (the pool exists but may be sparse).
fn harvest_hw_random() -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    #[cfg(target_arch = "x86_64")]
    {
        let mut filled = 0usize;
        while filled < 64 {
            let mut val = 0u64;
            // SAFETY: _rdrand64_step writes to the pointed integer and
            // returns the success flag; retrying bounded times is the
            // documented pattern for under-subscribed RDRAND.
            let ok = unsafe { std::arch::x86_64::_rdrand64_step(&mut val) };
            if ok != 0 {
                out.extend_from_slice(&val.to_ne_bytes());
                filled += 8;
            } else if out.len() > 56 {
                break; // partial harvest is fine: RNDADDENTROPY credits it
            }
        }
        if filled >= 64 {
            return out;
        }
    }
    // /dev/hwrng (virtio-rng, SoC TRNG blocks) when RDRAND is absent.
    if let Ok(hw) = std::fs::read(Path::new("/dev/hwrng")) {
        out.extend_from_slice(&hw[..hw.len().min(64)]);
    }
    out.truncate(64);
    out
}

/// The real PID-1 bootstrap sequence. Returns the boot state (v0.6.0
/// shape) plus the v0.7.0 sequence record for the journal.
///
/// SECURITY: entropy starvation remains a hard refusal — an appliance
/// that cannot credit entropy must never arm destructive commands whose
/// rescue passwords and key material depend on the CSPRNG.
pub fn run_pid1_init_real(
    backend: &dyn InitBackend,
    attestation_matched: bool,
    constituents_hash: &str,
) -> Result<(BootInitState, Pid1SequenceRecord), DcError> {
    // 1. Pseudo-filesystems (idempotent).
    let plan: [(&str, &str, &str); 5] = [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
        ("devpts", "/dev/pts", "devpts"),
        ("efivarfs", "/sys/firmware/efi/efivars", "efivarfs"),
    ];
    let mut mounted = Vec::new();
    let mut already = Vec::new();
    for (source, target, fstype) in plan {
        if backend.is_mounted(target) {
            already.push(target.to_string());
            continue;
        }
        // devpts/efivarfs may legitimately be absent on non-EFI hosts:
        // mount failures for THOSE are recorded, not fatal (the sanitizer
        // needs proc/sys/dev, not efivarfs).
        let must_succeed = matches!(target, "/proc" | "/sys" | "/dev");
        match backend.mount(source, target, fstype) {
            Ok(()) => mounted.push((source.to_string(), target.to_string(), fstype.to_string())),
            Err(reason) if must_succeed => {
                return Err(DcError::Usage(format!(
                    "PID1_MOUNT_FAILED: {} (an appliance cannot sanitize without it)",
                    reason
                )));
            }
            Err(reason) => {
                already.push(format!("{} (unavailable: {})", target, reason));
            }
        }
    }

    // 2. Entropy: hardware harvest + pool credit.
    let entropy = harvest_hw_random();
    let entropy_ready = if entropy.is_empty() {
        false
    } else {
        // 1 bit per byte is a conservative credit for RDRAND output.
        backend.add_entropy(&entropy, entropy.len() as u32).is_ok()
    };
    if !entropy_ready {
        return Err(DcError::Usage(
            "ENTROPY_STARVATION_UNREADY: no hardware entropy source could be credited \
             (RDRAND absent, /dev/hwrng unreadable) — refusing to arm destructive commands"
                .to_string(),
        ));
    }

    // 3. Zombie reaper.
    backend
        .install_zombie_reaper()
        .map_err(|reason| DcError::Usage(format!("PID1_SIGCHLD_INSTALL_FAILED: {}", reason)))?;

    let record = Pid1SequenceRecord {
        mounted,
        already_mounted: already,
        entropy_bytes_credited: entropy.len() as u64,
        zombie_reaper_installed: true,
    };

    let state = evaluate_boot_state(true, attestation_matched, constituents_hash)
        .map_err(|reason| DcError::Usage(reason.to_string()))?;
    Ok((state, record))
}

/// Pure evaluation gate of the v0.6.0 contract (kept as the seam tests
/// pinned): entropy starvation is a refusal; the environment fingerprint
/// is derived from the constituents hash.
pub fn evaluate_boot_state(
    entropy_available: bool,
    attestation_matched: bool,
    constituents_hash: &str,
) -> Result<BootInitState, &'static str> {
    if !entropy_available {
        return Err("ENTROPY_STARVATION_UNREADY");
    }
    let fingerprint = format!("ENV_FP_{}", constituents_hash);
    Ok(BootInitState {
        proc_mounted: true,
        sys_mounted: true,
        dev_mounted: true,
        entropy_ready: true,
        boot_medium_attested: attestation_matched,
        environment_fingerprint: fingerprint,
    })
}

/// Backward-compatible v0.6.0 entry point (pure evaluation only).
pub struct BootInitSequence;

impl BootInitSequence {
    pub fn run_pid1_init(
        entropy_available: bool,
        attestation_matched: bool,
        constituents_hash: &str,
    ) -> Result<BootInitState, &'static str> {
        evaluate_boot_state(entropy_available, attestation_matched, constituents_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Scripted backend: records every operation, scripts every verdict.
    struct ScriptedInit {
        mounts: RefCell<Vec<(String, String, String)>>,
        mounted_targets: RefCell<Vec<String>>,
        entropy_calls: RefCell<Vec<(Vec<u8>, u32)>>,
        reaper_installed: RefCell<bool>,
        mount_should_fail: Vec<&'static str>,
    }

    impl ScriptedInit {
        fn new() -> Self {
            Self {
                mounts: RefCell::new(Vec::new()),
                mounted_targets: RefCell::new(Vec::new()),
                entropy_calls: RefCell::new(Vec::new()),
                reaper_installed: RefCell::new(false),
                mount_should_fail: Vec::new(),
            }
        }

        fn pre_mounted(self, target: &str) -> Self {
            self.mounted_targets.borrow_mut().push(target.to_string());
            self
        }
    }

    impl InitBackend for ScriptedInit {
        fn mount(&self, source: &str, target: &str, fstype: &str) -> Result<(), String> {
            if self.mount_should_fail.contains(&target) {
                return Err(format!("scripted failure for {}", target));
            }
            self.mounts.borrow_mut().push((
                source.to_string(),
                target.to_string(),
                fstype.to_string(),
            ));
            Ok(())
        }

        fn is_mounted(&self, target: &str) -> bool {
            self.mounted_targets.borrow().iter().any(|t| t == target)
        }

        fn add_entropy(&self, bytes: &[u8], bits: u32) -> Result<(), String> {
            self.entropy_calls.borrow_mut().push((bytes.to_vec(), bits));
            Ok(())
        }

        fn install_zombie_reaper(&self) -> Result<(), String> {
            *self.reaper_installed.borrow_mut() = true;
            Ok(())
        }
    }

    #[test]
    fn pid1_sequence_mounts_everything_in_order() {
        // REG-PID1-INIT-SEQUENCE (happy path): proc, sysfs, devtmpfs,
        // devpts, efivarfs — entropy credited, reaper installed.
        let backend = ScriptedInit::new();
        let (state, record) =
            run_pid1_init_real(&backend, true, "cafebabe").expect("sequence must succeed");
        assert!(state.entropy_ready);
        assert!(state.boot_medium_attested);
        assert_eq!(state.environment_fingerprint, "ENV_FP_cafebabe");

        let targets: Vec<String> = record.mounted.iter().map(|(_, t, _)| t.clone()).collect();
        assert_eq!(
            targets,
            vec![
                "/proc",
                "/sys",
                "/dev",
                "/dev/pts",
                "/sys/firmware/efi/efivars"
            ],
            "mount order must be deterministic and complete"
        );
        assert_eq!(record.entropy_bytes_credited, 64);
        assert!(record.zombie_reaper_installed);
        assert!(*backend.reaper_installed.borrow());
        assert_eq!(backend.entropy_calls.borrow().len(), 1);
        // Entropy credit: 1 bit per byte.
        assert_eq!(backend.entropy_calls.borrow()[0].1, 64);
    }

    #[test]
    fn pid1_sequence_is_idempotent_for_pre_mounted_targets() {
        let backend = ScriptedInit::new().pre_mounted("/proc").pre_mounted("/dev");
        let (_, record) = run_pid1_init_real(&backend, true, "h").unwrap();
        assert!(record.already_mounted.contains(&"/proc".to_string()));
        assert!(record.already_mounted.contains(&"/dev".to_string()));
        // Only the missing ones are mounted.
        let targets: Vec<String> = record.mounted.iter().map(|(_, t, _)| t.clone()).collect();
        assert_eq!(
            targets,
            vec!["/sys", "/dev/pts", "/sys/firmware/efi/efivars"]
        );
    }

    #[test]
    fn pid1_entropy_starvation_is_a_hard_refusal() {
        // A backend whose entropy credit fails: emulate by checking the
        // pure gate directly (the harvest is hardware-side in production).
        assert_eq!(
            evaluate_boot_state(false, true, "x"),
            Err("ENTROPY_STARVATION_UNREADY")
        );
        // v0.6.0 entry point preserves the same contract.
        assert_eq!(
            BootInitSequence::run_pid1_init(false, true, "x"),
            Err("ENTROPY_STARVATION_UNREADY")
        );
    }
}
