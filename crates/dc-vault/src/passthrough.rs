//! VFIO group passthrough plumbing (v0.8.0 staging, Vector 2).
//!
//! The final vault design passes the *block device itself* into the
//! enclave: the controller is unbound from the host driver, its PCI group
//! is attached to the VM via the KVM VFIO device, and the guest drives
//! the disk directly — host kernels cannot see the traffic at all.
//!
//! This module implements the kernel-side plumbing that carries it:
//! - `VFIO_SET_CONTAINER` (attach a group to the VFIO container),
//! - `KVM_CREATE_DEVICE(KVM_DEV_TYPE_VFIO)` + `KVM_DEV_VFIO_GROUP_ADD`
//!   (hand the group to the VM).
//!
//! The guest-side virtio-blk/NVMe driver is the v0.9.0 milestone; v0.8.0
//! exercises this plumbing to the ioctl boundary and refuses (fail-closed)
//! on any error — the invariant being tested is that we never *claim*
//! passthrough that did not happen.

use crate::kvm::KVM_CREATE_DEVICE;
use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd};

/// `KVM_DEV_TYPE_VFIO` (linux/kvm.h).
pub const KVM_DEV_TYPE_VFIO: u32 = 6;
/// `VFIO_SET_CONTAINER` = `_IOW(';', 0x01, __s32)` = 0x40083B01.
pub const VFIO_SET_CONTAINER: libc::c_ulong = 0x4008_3B01;
/// `KVM_DEV_VFIO_GROUP_ADD` = `_IOW(KVMIO, 0xe3, __s32)` = 0x4008_AEE3.
pub const KVM_DEV_VFIO_GROUP_ADD: libc::c_ulong = 0x4008_AEE3;

#[derive(Debug, thiserror::Error)]
pub enum PassthroughError {
    #[error("VFIO unavailable: {0}")]
    Vfio(String),
    #[error("KVM device ioctls failed: {what}: errno {errno}")]
    KvmDevice { what: &'static str, errno: i32 },
    #[error("passthrough refused: {0}")]
    Refusal(String),
}

/// `struct kvm_create_device { __u32 type, fd, flags; }` (12 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KvmCreateDevice {
    pub type_: u32,
    pub fd: u32,
    pub flags: u32,
}

const _: () = assert!(std::mem::size_of::<KvmCreateDevice>() == 12);

/// An attached VFIO group (RAII: dropped groups are released by fd close).
#[derive(Debug)]
pub struct VfioGroup {
    group: OwnedFd,
}

impl VfioGroup {
    /// Open `/dev/vfio/<groupid>` and attach it to the container.
    pub fn open_and_attach(
        group_id: u32,
        container: BorrowedFd<'_>,
    ) -> Result<Self, PassthroughError> {
        let path = format!("/dev/vfio/{group_id}");
        let group_file = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| PassthroughError::Vfio(format!("open {path}: {e}")))?;
        let group: OwnedFd = group_file.into();
        let container_fd = container.as_raw_fd();
        let ret = unsafe {
            libc::ioctl(
                group.as_raw_fd(),
                VFIO_SET_CONTAINER,
                &container_fd as *const i32,
            )
        };
        if ret < 0 {
            return Err(PassthroughError::Vfio(format!(
                "VFIO_SET_CONTAINER(group {group_id}): errno {}",
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            )));
        }
        Ok(Self { group })
    }
}

/// Create the KVM in-VM VFIO device and register a group with it.
pub fn kvm_vfio_attach(vm: BorrowedFd<'_>, group: &VfioGroup) -> Result<(), PassthroughError> {
    // KVM_CREATE_DEVICE on the VM fd.
    let mut create = KvmCreateDevice {
        type_: KVM_DEV_TYPE_VFIO,
        fd: 0,
        flags: 0,
    };
    let ret = unsafe {
        libc::ioctl(
            vm.as_raw_fd(),
            KVM_CREATE_DEVICE,
            &mut create as *mut KvmCreateDevice,
        )
    };
    if ret < 0 {
        return Err(PassthroughError::KvmDevice {
            what: "KVM_CREATE_DEVICE(KVM_DEV_TYPE_VFIO)",
            errno: std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        });
    }
    // SAFETY: fd written by the kernel on success; we own it until drop.
    let device = unsafe { OwnedFd::from_raw_fd(create.fd as i32) };
    // KVM_DEV_VFIO_GROUP_ADD(device_fd, group_fd).
    let group_fd = group.group.as_raw_fd();
    let ret = unsafe {
        libc::ioctl(
            device.as_raw_fd(),
            KVM_DEV_VFIO_GROUP_ADD,
            &group_fd as *const i32,
        )
    };
    if ret < 0 {
        return Err(PassthroughError::KvmDevice {
            what: "KVM_DEV_VFIO_GROUP_ADD",
            errno: std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        });
    }
    std::mem::forget(device); // owned by the VM now; dropping the fd detaches
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_are_pinned() {
        assert_eq!(VFIO_SET_CONTAINER, 0x4008_3B01);
        assert_eq!(KVM_DEV_VFIO_GROUP_ADD, 0x4008_AEE3);
        assert_eq!(
            KVM_CREATE_DEVICE,
            (1u64 << 30) | (12u64 << 16) | (0xAE << 8) | 0xE0
        );
        assert_eq!(std::mem::size_of::<KvmCreateDevice>(), 12);
    }

    #[test]
    fn missing_vfio_group_is_a_clean_error() {
        // Group 99999 cannot exist: open must fail with Vfio, not panic.
        let container = File::open("/dev/null").ok();
        let borrow = container.as_ref().map(|c| unsafe {
            // SAFETY: transient borrow of a container fd for the error path.
            BorrowedFd::borrow_raw(c.as_raw_fd())
        });
        match VfioGroup::open_and_attach(99999, borrow.expect("dev/null open")) {
            Err(PassthroughError::Vfio(_)) => {}
            other => panic!("expected clean Vfio error, got {other:?}"),
        }
    }
}
