use serde::{Deserialize, Serialize};

/// Physical access class for an eMMC/SD target (Δ337).
///
/// Determines which purge vocabulary is honestly certifiable:
/// - `NativeController`: the kernel MMC subsystem is directly reachable
///   (e.g. `/dev/mmcblk0`), so boot-partition switching, secure trim and
///   CMD38 SANITIZE are executable.
/// - `ReaderMediated`: the media sits behind a USB reader that abstracts
///   the controller away; only user-area access is possible and the
///   certificate must reflect the degraded scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmcAccessClass {
    NativeController,
    ReaderMediated,
}
