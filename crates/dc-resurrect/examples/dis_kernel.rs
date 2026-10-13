fn main() {
    let profile =
        dc_resurrect::vendors::ControllerProfile::builtin_by_name("marvell-88ss1077").unwrap();
    let geo = dc_resurrect::nand::NandGeometry::new(512, 16, 8, 64, 2);
    let params = dc_resurrect::payload::PayloadParams {
        load_base: profile.sram_base,
        nand_mmio: profile.nand_mmio,
        dbg_mmio: profile.dbg_mmio,
        uart_mmio: Some(profile.uart_mmio),
        geometry: geo,
        verify: dc_resurrect::payload::VerifyMode::Sampled,
        read_id_word: 0x3294_DE98,
    };
    let p2 = dc_resurrect::payload::assemble_kernel(&params);
    let lines = dc_resurrect::payload::asm::disasm(&p2.blob, profile.sram_base);
    for l in &lines {
        let addr = u32::from_str_radix(&l[..8], 16).unwrap();
        if (0x1000_0030..=0x1000_00C8).contains(&addr) {
            println!("{}", l);
        }
    }
}
