use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct LvmSandbox {
    pub system_dir: PathBuf,
    pub locks_dir: PathBuf,
    pub system_id: String,
}

impl LvmSandbox {
    /// Stage a completely hermetic LVM2 sandbox with custom loop filter and private lock directory (Δ31).
    pub fn create(scratch_dir: &Path) -> Result<Self, String> {
        let system_dir = scratch_dir.join("etc-lvm");
        let locks_dir = scratch_dir.join("lvm-locks");
        fs::create_dir_all(&system_dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(&locks_dir).map_err(|e| e.to_string())?;

        let system_id = format!("dct5-{}", std::process::id());

        let lvm_conf_content = format!(
            r#"
devices {{
    filter = [ "a|^/dev/loop[0-9]+$|", "r|.*|" ]
}}
global {{
    locking_dir = "{}"
    use_lvmetad = 0
}}
"#,
            locks_dir.display()
        );

        let lvm_conf_path = system_dir.join("lvm.conf");
        let mut file = File::create(&lvm_conf_path).map_err(|e| e.to_string())?;
        file.write_all(lvm_conf_content.as_bytes()).map_err(|e| e.to_string())?;

        Ok(Self {
            system_dir,
            locks_dir,
            system_id,
        })
    }

    /// Run an LVM command strictly within the isolated sandbox environment.
    pub fn run_lvm(&self, args: &[&str]) -> Result<std::process::Output, String> {
        let output = Command::new("lvm")
            .args(args)
            .env("LVM_SYSTEM_DIR", &self.system_dir)
            .output()
            .map_err(|e| format!("Failed to execute lvm: {}", e))?;

        Ok(output)
    }

    pub fn pvcreate(&self, dev_path: &Path) -> Result<(), String> {
        let out = self.run_lvm(&["pvcreate", "-y", "-ff", &dev_path.to_string_lossy()])?;
        if !out.status.success() {
            return Err(format!(
                "pvcreate failed on {}: stderr: {}",
                dev_path.display(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }

    pub fn vgcreate(&self, vg_name: &str, dev_paths: &[&Path]) -> Result<(), String> {
        let mut args = vec!["vgcreate", "-y", "--systemid", &self.system_id, vg_name];
        let p_strings: Vec<String> = dev_paths.iter().map(|p| p.to_string_lossy().to_string()).collect();
        for p in &p_strings {
            args.push(p);
        }

        let out = self.run_lvm(&args)?;
        if !out.status.success() {
            return Err(format!(
                "vgcreate failed on {}: stderr: {}",
                vg_name,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }

    pub fn lvcreate(&self, vg_name: &str, lv_name: &str, size_mib: u64) -> Result<(), String> {
        let size_str = format!("{}M", size_mib);
        let out = self.run_lvm(&["lvcreate", "-y", "-L", &size_str, "-n", lv_name, vg_name])?;
        if !out.status.success() {
            return Err(format!(
                "lvcreate failed on {}/{}: stderr: {}",
                vg_name,
                lv_name,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }

    pub fn vgchange_ay(&self, vg_name: &str) -> Result<(), String> {
        let out = self.run_lvm(&["vgchange", "-ay", vg_name])?;
        if !out.status.success() {
            return Err(format!(
                "vgchange -ay failed on {}: stderr: {}",
                vg_name,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }

    pub fn vgchange_an(&self, vg_name: &str) -> Result<(), String> {
        let out = self.run_lvm(&["vgchange", "-an", vg_name])?;
        if !out.status.success() {
            return Err(format!(
                "vgchange -an failed on {}: stderr: {}",
                vg_name,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }

    pub fn vgremove(&self, vg_name: &str) -> Result<(), String> {
        let _ = self.vgchange_an(vg_name);
        let out = self.run_lvm(&["vgremove", "-f", "-y", vg_name])?;
        if !out.status.success() {
            return Err(format!(
                "vgremove failed on {}: stderr: {}",
                vg_name,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }
}
