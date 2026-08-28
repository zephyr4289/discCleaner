use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub struct ArtifactsDumper;

impl ArtifactsDumper {
    pub fn dump_failure_bundle(
        cell_name: &str,
        scratch_dir: &Path,
        backing_path: &Path,
        stdout: &str,
        stderr: &str,
        mismatch_offset: Option<u64>,
    ) -> PathBuf {
        let bundle_dir = PathBuf::from("target/test-artifacts")
            .join(cell_name)
            .join(chrono_now_iso().replace(':', "-"));

        let _ = fs::create_dir_all(&bundle_dir);

        // Write stdout / stderr
        let _ = fs::write(bundle_dir.join("stdout.log"), stdout);
        let _ = fs::write(bundle_dir.join("stderr.log"), stderr);

        // Copy all journals and certs in scratch dir
        if let Ok(entries) = fs::read_dir(scratch_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    if ext == "dcj" || ext == "json" || ext == "log" {
                        let _ = fs::copy(&p, bundle_dir.join(p.file_name().unwrap()));
                    }
                }
            }
        }

        // Dump backing file excerpt (first 4K, last 4K, mismatch area)
        Self::dump_backing_excerpts(backing_path, &bundle_dir, mismatch_offset);

        bundle_dir
    }

    fn dump_backing_excerpts(backing_path: &Path, bundle_dir: &Path, mismatch_offset: Option<u64>) {
        if let Ok(file) = File::open(backing_path) {
            let mut f = file;
            let mut buf_4k = [0u8; 4096];

            // First 4K
            if f.read_exact(&mut buf_4k).is_ok() {
                let _ = fs::write(bundle_dir.join("backing_first_4k.bin"), &buf_4k);
            }

            // Last 4K
            if let Ok(len) = f.metadata().map(|m| m.len()) {
                if len >= 4096 {
                    let _ = f.seek(SeekFrom::Start(len - 4096));
                    if f.read_exact(&mut buf_4k).is_ok() {
                        let _ = fs::write(bundle_dir.join("backing_last_4k.bin"), &buf_4k);
                    }
                }
            }

            // Mismatch area (+- 2K)
            if let Some(off) = mismatch_offset {
                let start = off.saturating_sub(2048);
                let _ = f.seek(SeekFrom::Start(start));
                let mut buf_mismatch = [0u8; 4096];
                if f.read_exact(&mut buf_mismatch).is_ok() {
                    let _ = fs::write(
                        bundle_dir.join(format!("backing_mismatch_at_{}.bin", off)),
                        &buf_mismatch,
                    );
                }
            }
        }
    }
}

fn chrono_now_iso() -> String {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::gmtime_r(&ts.tv_sec, &mut tm) };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}
