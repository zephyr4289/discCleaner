use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct JournalWatchdog {
    stop_signal: Arc<AtomicBool>,
}

impl JournalWatchdog {
    pub fn spawn_watcher(journal_dir: PathBuf, max_stall_secs: u64) -> Self {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_signal);

        std::thread::spawn(move || {
            let start = Instant::now();
            let mut last_size = 0u64;
            let mut last_change = Instant::now();

            while !stop_clone.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));

                if start.elapsed().as_secs() < 10 {
                    continue; // Startup grace period
                }

                // Check newest journal file in directory
                if let Ok(entries) = std::fs::read_dir(&journal_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("dcj") {
                            if let Ok(meta) = path.metadata() {
                                let sz = meta.len();
                                if sz != last_size {
                                    last_size = sz;
                                    last_change = Instant::now();
                                }
                            }
                        }
                    }
                }

                if last_change.elapsed().as_secs() > max_stall_secs {
                    eprintln!(
                        "[WATCHDOG] STALL DETECTED: Journal has not grown for {} seconds",
                        last_change.elapsed().as_secs()
                    );
                    break;
                }
            }
        });

        Self { stop_signal }
    }
}

impl Drop for JournalWatchdog {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}
