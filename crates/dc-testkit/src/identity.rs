use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestIdentitySnapshot {
    pub name: String,
    pub dm_name: Option<String>,
    pub dm_uuid: Option<String>,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub size_bytes: u64,
}

pub struct TestIdentityReader;

impl TestIdentityReader {
    /// Read physical block device sysfs identity independently of tool logic.
    pub fn read_sysfs_identity(dev_path: &Path) -> Result<TestIdentitySnapshot, String> {
        let meta = fs::metadata(dev_path).map_err(|e| e.to_string())?;
        use std::os::unix::fs::MetadataExt;
        let rdev = meta.rdev();
        let maj = unsafe { libc::major(rdev) };
        let min = unsafe { libc::minor(rdev) };

        let sys_dev_dir = PathBuf::from(format!("/sys/dev/block/{}:{}", maj, min));
        let canon = fs::canonicalize(&sys_dev_dir).unwrap_or(sys_dev_dir.clone());
        let kernel_name = canon.file_name().unwrap_or_default().to_string_lossy().to_string();

        let dm_name = fs::read_to_string(canon.join("dm/name")).ok().map(|s| s.trim().to_string());
        let dm_uuid = fs::read_to_string(canon.join("dm/uuid")).ok().map(|s| s.trim().to_string());
        let serial = fs::read_to_string(canon.join("device/serial")).ok().map(|s| s.trim().to_string());
        let model = fs::read_to_string(canon.join("device/model")).ok().map(|s| s.trim().to_string());

        let size_str = fs::read_to_string(canon.join("size")).unwrap_or_default();
        let size_sectors: u64 = size_str.trim().parse().unwrap_or(0);
        let size_bytes = size_sectors * 512;

        Ok(TestIdentitySnapshot {
            name: kernel_name,
            dm_name,
            dm_uuid,
            serial,
            model,
            size_bytes,
        })
    }
}
