#[derive(Clone, Debug)]
pub struct FaultPlan {
    pub cell_name: String,
    pub size_bytes: u64,
    pub total_sectors: u64,
    pub fault_start_sector: u64,
    pub fault_start_byte: u64,
    pub fault_start_window: u64,
}

impl FaultPlan {
    pub fn for_cell(cell_name: &str) -> Self {
        match cell_name {
            "T2.core" | "T2.sync" => {
                let size_bytes = 1024 * 1024 * 1024 + 1536; // 1 GiB + 1536 B
                let total_sectors = size_bytes / 512;
                let fault_start_sector = 1_048_577; // Byte 512 MiB + 512 B
                let fault_start_byte = fault_start_sector * 512;
                let fault_start_window = fault_start_byte / (2 * 1024 * 1024);
                Self {
                    cell_name: cell_name.to_string(),
                    size_bytes,
                    total_sectors,
                    fault_start_sector,
                    fault_start_byte,
                    fault_start_window,
                }
            }
            "T2.head" => {
                let size_bytes = 1024 * 1024 * 1024; // 1 GiB
                let total_sectors = size_bytes / 512;
                let fault_start_sector = 1; // Fails immediately at window 0
                Self {
                    cell_name: cell_name.to_string(),
                    size_bytes,
                    total_sectors,
                    fault_start_sector,
                    fault_start_byte: 512,
                    fault_start_window: 0,
                }
            }
            "T2.tail" => {
                let size_bytes = 1024 * 1024 * 1024 + 1536; // 1 GiB + 1536 B
                let total_sectors = size_bytes / 512;
                let fault_start_sector = 2_097_152; // Exactly at 1 GiB boundary (window 512 start)
                Self {
                    cell_name: cell_name.to_string(),
                    size_bytes,
                    total_sectors,
                    fault_start_sector,
                    fault_start_byte: 1024 * 1024 * 1024,
                    fault_start_window: 512,
                }
            }
            "T2.slow" => {
                let size_bytes = 2 * 1024 * 1024 * 1024; // 2 GiB
                let total_sectors = size_bytes / 512;
                let fault_start_sector = 2_097_152; // 1 GiB
                Self {
                    cell_name: cell_name.to_string(),
                    size_bytes,
                    total_sectors,
                    fault_start_sector,
                    fault_start_byte: 1024 * 1024 * 1024,
                    fault_start_window: 512,
                }
            }
            _ => {
                let size_bytes = 1024 * 1024 * 1024;
                Self {
                    cell_name: cell_name.to_string(),
                    size_bytes,
                    total_sectors: size_bytes / 512,
                    fault_start_sector: 1_048_576,
                    fault_start_byte: 512 * 1024 * 1024,
                    fault_start_window: 256,
                }
            }
        }
    }
}
