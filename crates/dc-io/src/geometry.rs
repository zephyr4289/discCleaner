#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowGeometry {
    pub total_size_bytes: u64,
    pub block_size: u32,
    pub window_bytes: u64,
    pub total_windows: u64,
    pub short_window_bytes: Option<u64>,
}

impl WindowGeometry {
    pub fn new(total_size_bytes: u64, block_size: u32, window_bytes: u64) -> Result<Self, String> {
        if block_size == 0 || (block_size & (block_size - 1)) != 0 {
            return Err(format!("Invalid block size: {}", block_size));
        }

        if window_bytes == 0 || window_bytes % (block_size as u64) != 0 {
            return Err(format!(
                "Window size {} is not a multiple of block size {}",
                window_bytes, block_size
            ));
        }

        if total_size_bytes < window_bytes && total_size_bytes < (block_size as u64) {
            return Err(format!(
                "Total size {} is smaller than minimum block size {}",
                total_size_bytes, block_size
            ));
        }

        let full_windows = total_size_bytes / window_bytes;
        let remainder = total_size_bytes % window_bytes;

        let (total_windows, short_window_bytes) = if remainder == 0 {
            (full_windows, None)
        } else {
            (full_windows + 1, Some(remainder))
        };

        Ok(Self {
            total_size_bytes,
            block_size,
            window_bytes,
            total_windows,
            short_window_bytes,
        })
    }

    /// Return the byte length of window `index`.
    pub fn window_len_bytes(&self, index: u64) -> u64 {
        if index + 1 == self.total_windows {
            self.short_window_bytes.unwrap_or(self.window_bytes)
        } else {
            self.window_bytes
        }
    }

    /// Return starting byte offset for window `index`.
    pub fn window_offset_bytes(&self, index: u64) -> u64 {
        index * self.window_bytes
    }
}
