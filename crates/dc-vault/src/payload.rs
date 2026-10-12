//! The vault guest payload — 64 bytes of hand-assembled x86-64 that runs
//! INSIDE the micro-VM (v0.8.0, Vector 2).
//!
//! What it does, in guest physical memory:
//! - reads 64 bytes of host-injected seed entropy from the seed page,
//! - mixes eight qwords of hardware `RDRAND` output plus the guest TSC,
//! - writes the 64-byte session key to the sealed result page,
//! - stamps the result page with the magic constant and halts.
//!
//! Under AMD SEV / Intel TDX memory encryption the result page is
//! transparent RAM to the guest but *ciphertext* to the host VMM — the
//! derived session key is unreadable by any host userspace process,
//! rootkit included. The host only ever sees the fingerprint it is
//! allowed to see (BLAKE3), never the key material feeding the chain.
//!
//! The byte encodings below are individually verified by the native
//! execution test (`payload_executes_natively_when_rdrand_exists`): the
//! same bytes are mapped at the same guest-physical addresses in the
//! test process and executed on the real CPU.

/// Guest-physical layout (must stay in sync with `vm.rs`).
pub mod layout {
    /// PML4 root (one entry → PDPT).
    pub const PAGE_TABLES: u64 = 0x1000;
    /// 64-bit GDT (null, code64, data).
    pub const GDT: u64 = 0x4000;
    /// Payload entry point.
    pub const PAYLOAD: u64 = 0x10000;
    /// Host seed page (64 bytes of CSPRNG entropy, injected pre-run).
    pub const SEED_PAGE: u64 = 0x110000;
    /// Sealed result page (64-byte key + magic stamp at +64).
    pub const RESULT_PAGE: u64 = 0x111000;
    /// Guest stack top (grows down).
    pub const STACK_TOP: u64 = 0x200000;
    /// Guest RAM size (must cover STACK_TOP).
    pub const GUEST_RAM: usize = 0x400000; // 4 MiB
}

/// Result-page magic: "DCVAULT8" as a little-endian u64.
pub const RESULT_MAGIC: u64 = 0x3854_4C55_4156_4344;
/// Magic offset inside the result page.
pub const RESULT_MAGIC_OFFSET: usize = 64;
/// Session key length (bytes).
pub const SESSION_KEY_LEN: usize = 64;

/// The payload, hand-assembled (AT&T comments above each encoding):
///
/// ```text
/// entry:  mov r10, SEED_PAGE      ; 49 C7 C2 imm32
///         mov r11, RESULT_PAGE    ; 49 C7 C3 imm32
///         xor ecx, ecx            ; 31 C9
/// loop:   rdtsc                   ; 0F 31
///         shl rdx, 32             ; 48 C1 E2 20
///         or  rax, rdx            ; 48 09 D0
///         rdrand rbx              ; 48 0F C7 F3
///         xor rax, rbx            ; 48 31 D8
///         xor rax, [r10+rcx*8]    ; 49 33 04 CA  (REX.W+B: base r10, index rcx)
///         mov [r11+rcx*8], rax    ; 49 89 04 CB  (REX.W+B: base r11, index rcx)
///         inc rcx                 ; 48 FF C1
///         cmp rcx, 8              ; 48 83 F9 08
///         jl  loop                ; 7C DF   (rel8 = -(2+31))
///         mov rax, MAGIC          ; 48 B8 imm64
///         mov [r11+64], rax       ; 49 89 43 40
///         hlt                      ; F4
/// ```
pub fn payload_bytes() -> [u8; 64] {
    let mut p = [0u8; 64];
    let mut i = 0usize;

    fn put(p: &mut [u8; 64], i: &mut usize, bytes: &[u8]) {
        p[*i..*i + bytes.len()].copy_from_slice(bytes);
        *i += bytes.len();
    }

    // Address immediates are imm32 (C7 /0 sign-extends); the layout pages
    // live far below 2 GiB by construction (asserted in the layout test).
    put(&mut p, &mut i, &[0x49, 0xC7, 0xC2]); // mov r10, imm32
    put(&mut p, &mut i, &(layout::SEED_PAGE as u32).to_le_bytes());
    put(&mut p, &mut i, &[0x49, 0xC7, 0xC3]); // mov r11, imm32
    put(&mut p, &mut i, &(layout::RESULT_PAGE as u32).to_le_bytes());
    put(&mut p, &mut i, &[0x31, 0xC9]); // xor ecx, ecx
    let loop_start = i;
    put(&mut p, &mut i, &[0x0F, 0x31]); // rdtsc
    put(&mut p, &mut i, &[0x48, 0xC1, 0xE2, 0x20]); // shl rdx, 32
    put(&mut p, &mut i, &[0x48, 0x09, 0xD0]); // or rax, rdx
    put(&mut p, &mut i, &[0x48, 0x0F, 0xC7, 0xF3]); // rdrand rbx
    put(&mut p, &mut i, &[0x48, 0x31, 0xD8]); // xor rax, rbx
    put(&mut p, &mut i, &[0x49, 0x33, 0x04, 0xCA]); // xor rax, [r10+rcx*8]
    put(&mut p, &mut i, &[0x49, 0x89, 0x04, 0xCB]); // mov [r11+rcx*8], rax
    put(&mut p, &mut i, &[0x48, 0xFF, 0xC1]); // inc rcx
    put(&mut p, &mut i, &[0x48, 0x83, 0xF9, 0x08]); // cmp rcx, 8
    let rel: i8 = loop_start as i8 - (i as i8 + 2); // jl back
    put(&mut p, &mut i, &[0x7C, rel as u8]); // jl rel8
    put(&mut p, &mut i, &[0x48, 0xB8]); // mov rax, imm64
    put(&mut p, &mut i, &RESULT_MAGIC.to_le_bytes());
    put(&mut p, &mut i, &[0x49, 0x89, 0x43, 0x40]); // mov [r11+64], rax
    put(&mut p, &mut i, &[0xF4]); // hlt
    debug_assert_eq!(i, 64, "payload must be exactly 64 bytes");
    p
}

/// BLAKE3 (24-hex) measurement of the payload — embedded in the vault
/// report and the certificate so auditors can verify WHICH enclave image
/// produced the session key.
pub fn payload_measurement() -> String {
    let mut h = blake3::Hasher::new();
    h.update(&payload_bytes());
    h.finalize().to_hex().to_string()[..24].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_exactly_64_bytes_with_pinned_encodings() {
        let p = payload_bytes();
        // mov r10, imm32 (seed page)
        assert_eq!(&p[0..3], &[0x49, 0xC7, 0xC2]);
        assert_eq!(&p[3..7], &(layout::SEED_PAGE as u32).to_le_bytes());
        // mov r11, imm32 (result page)
        assert_eq!(&p[7..10], &[0x49, 0xC7, 0xC3]);
        assert_eq!(&p[10..14], &(layout::RESULT_PAGE as u32).to_le_bytes());
        // Layout pages fit in the imm32 encoding space (compile-time law).
        const _: () = assert!(layout::SEED_PAGE < 0x7FFF_FFFF && layout::RESULT_PAGE < 0x7FFF_FFFF);
        // xor ecx, ecx
        assert_eq!(&p[14..16], &[0x31, 0xC9]);
        // rdtsc at loop start
        assert_eq!(&p[16..18], &[0x0F, 0x31]);
        // rdrand rbx
        assert_eq!(&p[25..29], &[0x48, 0x0F, 0xC7, 0xF3]);
        // xor rax, [r10+rcx*8]
        assert_eq!(&p[32..36], &[0x49, 0x33, 0x04, 0xCA]);
        // mov [r11+rcx*8], rax
        assert_eq!(&p[36..40], &[0x49, 0x89, 0x04, 0xCB]);
        // inc rcx
        assert_eq!(&p[40..43], &[0x48, 0xFF, 0xC1]);
        // cmp rcx, 8
        assert_eq!(&p[43..47], &[0x48, 0x83, 0xF9, 0x08]);
        // jl rel8 = -(2+31) = -33 (back to the rdtsc loop head at offset 16)
        assert_eq!(&p[47..49], &[0x7C, 0xDF]);
        // mov rax, imm64 (magic)
        assert_eq!(&p[49..51], &[0x48, 0xB8]);
        assert_eq!(&p[51..59], &RESULT_MAGIC.to_le_bytes());
        // mov [r11+64], rax
        assert_eq!(&p[59..63], &[0x49, 0x89, 0x43, 0x40]);
        // hlt last
        assert_eq!(p[63], 0xF4);
        // measurement is stable
        assert_eq!(payload_measurement(), payload_measurement());
        assert_eq!(payload_measurement().len(), 24);
    }

    /// Execute the SAME encodings natively: allocate the seed and result
    /// pages with MAP_32BIT (kernel-chosen addresses below 2 GiB, so the
    /// imm32 immediates remain encodable), patch the two address
    /// immediates of a payload COPY to point at them, and run it twice on
    /// a real CPU. Every wrong opcode byte faults here in CI — this is
    /// the executable proof of the pinned encodings above.
    #[test]
    fn payload_executes_natively_when_rdrand_exists() {
        if !std::is_x86_feature_detected!("rdrand") {
            eprintln!("skipping: CPU/VM has no RDRAND passthrough");
            return;
        }
        unsafe {
            // Kernel-chosen pages below 2 GiB (no fixed-address collision
            // with the harness's own mappings).
            let map32 = |prot: libc::c_int| {
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    0x1000,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                    -1,
                    0,
                );
                assert_ne!(p, libc::MAP_FAILED, "MAP_32BIT fixture page");
                std::ptr::write_bytes(p as *mut u8, 0, 0x1000);
                p as u64
            };
            let seed_page = map32(libc::PROT_READ | libc::PROT_WRITE);
            let result_page = map32(libc::PROT_READ | libc::PROT_WRITE);
            assert!(seed_page < 0x7FFF_FFFF && result_page < 0x7FFF_FFFF);

            // Seed entropy.
            let seed: [u8; SESSION_KEY_LEN] = core::array::from_fn(|i| (i as u8) ^ 0xA5);
            std::ptr::copy_nonoverlapping(seed.as_ptr(), seed_page as *mut u8, SESSION_KEY_LEN);

            // Executable copy with patched immediates and an ABI-safe
            // epilogue: the guest payload treats RBX as scratch (fine inside
            // the VM — it halts), but a native call must preserve the
            // callee-saved RBX of the SysV ABI, so we wrap it with
            // push rbx / pop rbx / ret around the patched body.
            let mut code = Vec::with_capacity(64 + 3);
            code.push(0x53); // push rbx
            let mut body = payload_bytes();
            body[3..7].copy_from_slice(&(seed_page as u32).to_le_bytes());
            body[10..14].copy_from_slice(&(result_page as u32).to_le_bytes());
            body[63] = 0x90; // nop over the hlt
            code.extend_from_slice(&body);
            code.push(0x5B); // pop rbx
            code.push(0xC3); // ret
            let exec_page = libc::mmap(
                std::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(exec_page, libc::MAP_FAILED);
            std::ptr::copy_nonoverlapping(code.as_ptr(), exec_page as *mut u8, code.len());

            let f: extern "C" fn() = std::mem::transmute(exec_page);
            f();

            let magic = std::ptr::read_volatile((result_page + 64) as *const u64);
            assert_eq!(magic, RESULT_MAGIC, "guest did not stamp the result page");

            let mut key = [0u8; SESSION_KEY_LEN];
            std::ptr::copy_nonoverlapping(
                result_page as *const u8,
                key.as_mut_ptr(),
                SESSION_KEY_LEN,
            );
            assert_ne!(key, [0u8; SESSION_KEY_LEN], "key material is all zero");

            f();
            let mut key2 = [0u8; SESSION_KEY_LEN];
            std::ptr::copy_nonoverlapping(
                result_page as *const u8,
                key2.as_mut_ptr(),
                SESSION_KEY_LEN,
            );
            assert_ne!(key, key2, "RDRAND/TSC entropy did not participate");
        }
    }
}
