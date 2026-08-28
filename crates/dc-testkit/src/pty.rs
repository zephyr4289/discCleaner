pub struct PtyRunner;

impl PtyRunner {
    /// Check if pseudo-terminals can be created in the current environment.
    pub fn is_pty_supported() -> bool {
        // Standard Linux PTY support check via /dev/ptmx
        std::path::Path::new("/dev/ptmx").exists()
    }
}
