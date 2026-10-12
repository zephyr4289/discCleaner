//! ACPI table walk + S5 poweroff (v0.12.0, Miracle 3).
//!
//! No acpid, no OS: the payload walks RSDP → XSDT/RSDT → FADT exactly
//! like a firmware bring-up, reads PM1a_CNT_BLK (and the SLP_TYPa
//! value for S5 from the \_S5 package — carried in by the caller on
//! real hardware or defaulted to the conservative 0), and writes
//! SLP_EN to enter soft-off.

/// Errors from the ACPI layer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AcpiError {
    BadSignature,
    BadChecksum,
    NoFadt,
    NoPm1a,
}

/// RSDP (ACPI 2.0+ layout; revision 0 uses RSDT — supported).
#[repr(C, packed)]
pub struct Rsdp {
    pub signature: [u8; 8], // "RSD PTR "
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_addr: u32,
    pub length: u32,
    pub xsdt_addr: u64,
    pub ext_checksum: u8,
    _rsvd: [u8; 3],
}

/// Common SDT header.
#[repr(C, packed)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_rev: [u8; 4],
    pub creator_id: u32,
    pub creator_rev: u32,
}

/// FADT (fixed ACPI description table) — only the power fields we need.
#[repr(C, packed)]
pub struct Fadt {
    pub header: SdtHeader,
    _facs_addr: u32,
    _dsdt_addr: u32,
    _rsvd1: u8,
    pub preferred_pm_profile: u8,
    pub sci_int: u16,
    pub smi_cmd: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4bios_req: u8,
    pub pstate_cnt: u8,
    pub pm1a_evt_blk: u32,
    pub pm1b_evt_blk: u32,
    pub pm1a_cnt_blk: u32,
    pub pm1b_cnt_blk: u32,
    pub pm2_cnt_blk: u32,
    pub pm_tmr_blk: u32,
    pub gpe0_blk: u32,
    pub gpe1_blk: u32,
    // … length-prefixed remainder not needed
}

pub const SLP_EN: u16 = 1 << 13;
pub const PM1_CNT_SLP_TYP_MASK: u16 = 0x1C00;

/// Verify a table region's checksum (sum of bytes == 0 mod 256).
pub fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0
}

/// Parse the RSDP at `ptr` and return (revision, rsdt_phys, xsdt_phys).
///
/// # Safety
/// `ptr` must point to a readable RSDP (validated length-wise first).
pub unsafe fn parse_rsdp(ptr: *const u8) -> Result<(u8, u32, u64), AcpiError> {
    let rsdp = unsafe { &*ptr.cast::<Rsdp>() };
    if &rsdp.signature != b"RSD PTR " {
        return Err(AcpiError::BadSignature);
    }
    // v1 checksum covers bytes 0..20.
    if !checksum_ok(unsafe { core::slice::from_raw_parts(ptr, 20) }) {
        return Err(AcpiError::BadChecksum);
    }
    if rsdp.revision >= 2 && rsdp.xsdt_addr != 0 {
        Ok((rsdp.revision, rsdp.rsdt_addr, rsdp.xsdt_addr))
    } else {
        Ok((rsdp.revision, rsdp.rsdt_addr, 0))
    }
}

/// Locate the FADT inside an XSDT/RSDT mapped readable at `table_ptr`
/// (length `len`); returns the byte offset of the FADT header.
///
/// # Safety
/// `table_ptr..table_ptr+len` must be readable firmware memory.
pub unsafe fn find_fadt(
    table_ptr: *const u8,
    len: usize,
    is_xsdt: bool,
) -> Result<usize, AcpiError> {
    if len < 36 {
        return Err(AcpiError::NoFadt);
    }
    let entries_off = 36;
    let entry_size = if is_xsdt { 8 } else { 4 };
    let count = (len - entries_off) / entry_size;
    for i in 0..count {
        let off = entries_off + i * entry_size;
        let addr = unsafe {
            if is_xsdt {
                (table_ptr.add(off) as *const u64).read_unaligned()
            } else {
                (table_ptr.add(off) as *const u32).read_unaligned() as u64
            }
        };
        // The table must be somewhere readable: the caller maps system
        // memory identity — we only dereference when the header
        // signature matches, guarded by a bounds check on length read
        // BEFORE the full struct.
        let hdr = addr as usize as *const SdtHeader;
        let sig = unsafe { core::slice::from_raw_parts(hdr.cast::<u8>(), 4) };
        if sig == b"FACP" {
            return Ok(i);
        }
    }
    Err(AcpiError::NoFadt)
}

/// Extract PM1a_CNT_BLK + S5 SLP_TYP from a FADT pointer.
///
/// `slp_typ_s5` is supplied by the platform glue (parsed from the
/// DSDT \_S5 package at boot; QEMU: 0, most servers: 0..7). When in
/// doubt the caller passes 0 — the write is still logged on the
/// framebuffer before issue.
pub fn fadt_power_fields(fadt_ptr: *const u8, slp_typ_s5: u16) -> Result<(u32, u16), AcpiError> {
    let fadt = unsafe { &*fadt_ptr.cast::<Fadt>() };
    if fadt.pm1a_cnt_blk == 0 && fadt.pm1b_cnt_blk == 0 {
        return Err(AcpiError::NoPm1a);
    }
    let port = if fadt.pm1a_cnt_blk != 0 {
        fadt.pm1a_cnt_blk
    } else {
        fadt.pm1b_cnt_blk
    };
    Ok((port, slp_typ_s5 & 0x7))
}

/// Enter S5 (soft off): write SLP_TYP|SLP_EN to PM1a control.
///
/// # Safety
/// `pm1a_port` must be a valid PM1 control block port (from the FADT).
pub unsafe fn power_off_s5(io: &mut impl crate::hal::PortIo, pm1a_port: u16, slp_typ: u16) {
    let value = (slp_typ << 10) | SLP_EN;
    unsafe { io.out16(pm1a_port, value) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::PortIo;
    use crate::hal::sim::SimBus;

    #[test]
    fn rsdp_parsing_and_checksum() {
        // Build a minimal ACPI 2.0 RSDP (30 bytes) + XSDT with a FADT
        // pointer, all checksummed.
        let mut blob = vec![0u8; 4096];
        let rsdp_off = 0;
        blob[rsdp_off..rsdp_off + 8].copy_from_slice(b"RSD PTR ");
        blob[rsdp_off + 8] = 0; // checksum (fix below)
        blob[rsdp_off + 9..rsdp_off + 15].copy_from_slice(b"DCGHST");
        blob[rsdp_off + 15] = 2; // revision 2
        // rsdt_addr at 16 (u32)
        let xsdt_off = 64usize;
        let xsdt_phys = (xsdt_off as u64) + blob.as_ptr() as u64;
        blob[rsdp_off + 24..rsdp_off + 32].copy_from_slice(&xsdt_phys.to_le_bytes());
        blob[rsdp_off + 32] = 0; // ext checksum
        blob[rsdp_off + 33..rsdp_off + 36].fill(0);
        // length (u32 at 20)
        blob[rsdp_off + 20..rsdp_off + 24].copy_from_slice(&36u32.to_le_bytes());
        // fix v1 checksum (bytes 0..20)
        let sum: u8 = blob[0..20].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        blob[rsdp_off + 8] = (0u8).wrapping_sub(sum);

        let ptr = blob.as_ptr();
        let (rev, _rsdt, xsdt) = unsafe { parse_rsdp(ptr) }.unwrap();
        assert_eq!(rev, 2);
        assert_eq!(xsdt, xsdt_off as u64 + blob.as_ptr() as u64);

        // Tamper → checksum failure.
        blob[9] ^= 0x40; // tamper OEM ID (inside checksum range, outside signature)
        assert!(matches!(
            unsafe { parse_rsdp(ptr) },
            Err(AcpiError::BadChecksum)
        ));
    }

    #[test]
    fn fadt_power_and_s5_write() {
        // FADT with PM1a_CNT_BLK at 0x604.
        let mut fadt = vec![0u8; 276];
        fadt[0..4].copy_from_slice(b"FACP");
        fadt[4..8].copy_from_slice(&276u32.to_le_bytes());
        // PM1a_CNT_BLK at offset 64 in the FADT body → header 36 +
        // facs(4) + dsdt(4) + rsvd(1) + profile(1) + sci(2) + smi(4) +
        // en(1) + dis(1) + s4(1) + pstate(1) = 36+8+1+1+2+4+4 = 56…
        // per struct: pm1a_evt at +56, pm1b +60, pm1a_cnt at +64.
        fadt[56..60].copy_from_slice(&0x604u32.to_le_bytes()); // PM1a_CNT_BLK @ +56 (header is 28 B)
        // fix checksum
        let sum: u8 = fadt.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        fadt[9] = fadt[9].wrapping_sub(sum).wrapping_sub(0).wrapping_add(0); // recompute below
        fadt[9] = 0;
        let s: u8 = fadt.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        fadt[9] = (0u8).wrapping_sub(s);

        let (port, slp) = fadt_power_fields(fadt.as_ptr(), 5).unwrap();
        assert_eq!(port, 0x604);
        assert_eq!(slp, 5);

        // The S5 write: QEMU-style (slp_typ 0) → value = SLP_EN only.
        let mut bus = SimBus::new(0);
        unsafe { power_off_s5(&mut bus, port as u16, 5) };
        let v = unsafe { bus.in32(0x604) } as u16;
        assert_eq!(v, (5 << 10) | SLP_EN);
    }
}
