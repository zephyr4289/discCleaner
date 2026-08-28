use crate::chacha_ref::ChaCha20Ref;
use std::time::Instant;

pub struct GenBench;

#[derive(Clone, Debug)]
pub struct GenBenchResult {
    pub single_core_gib_s: f64,
    pub estimated_host_capacity_gib_s: f64,
    pub num_threads: usize,
}

impl GenBench {
    /// Benchmark ChaCha20 generation throughput on this host.
    pub fn benchmark(duration_ms: u64) -> GenBenchResult {
        let seed = [0x42u8; 32];
        let nonce = [0u8; 12];
        let mut buf = vec![0u8; 2 * 1024 * 1024]; // 2 MiB buffer

        let start = Instant::now();
        let target_duration = std::time::Duration::from_millis(duration_ms);

        let mut cipher = ChaCha20Ref::new(&seed, &nonce, 0);
        let mut total_bytes = 0u64;

        while start.elapsed() < target_duration {
            cipher.apply_keystream(&mut buf);
            total_bytes += buf.len() as u64;
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        let single_core_gib_s = (total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)) / elapsed_secs;

        let num_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let effective_threads = (num_cpus.saturating_sub(1)).max(1);
        let estimated_host_capacity_gib_s = single_core_gib_s * effective_threads as f64;

        GenBenchResult {
            single_core_gib_s,
            estimated_host_capacity_gib_s,
            num_threads: effective_threads,
        }
    }
}
