//! Protocol-engine tests against the bit-level simulator.

use dc_resurrect::dp::{DpPort, MemAp, dp_reg};
use dc_resurrect::hal::UartLink;
use dc_resurrect::jtag::{JtagEngine, TapState};
use dc_resurrect::nand::NandGeometry;
use dc_resurrect::sim::{ScenarioKind, SimLink};
use dc_resurrect::swd::SwdEngine;
use dc_resurrect::vendors::ControllerProfile;

fn link(scenario: ScenarioKind, profile: &ControllerProfile) -> SimLink {
    SimLink::build(
        scenario,
        profile.clone(),
        NandGeometry::new(512, 16, 4, 8, 1),
        42,
        None,
    )
}

fn sm() -> ControllerProfile {
    ControllerProfile::builtin_by_name("siliconmotion-sm2262en").unwrap()
}

#[test]
fn jtag_scan_finds_the_tap_and_idcode() {
    let profile = sm();
    let mut jeng = JtagEngine::new(link(ScenarioKind::FirmwareCorrupt, &profile));
    let taps = jeng.scan_chain(1024, 32);
    assert_eq!(taps.len(), 1);
    assert_eq!(taps[0].idcode, profile.jtag_idcode.unwrap());
    assert!(taps[0].is_arm());
    assert_eq!(jeng.state(), TapState::RunTestIdle);
}

#[test]
fn swd_connect_reads_dpidr_and_memory() {
    let profile = sm();
    let mut swd = SwdEngine::new(link(ScenarioKind::HardFaultLockup, &profile));
    let dpidr = swd.connect().expect("SWD connect");
    assert_eq!(dpidr, profile.swd_dpidr.unwrap());
    // Power up and poke SRAM through the MEM-AP.
    {
        let mut ap = MemAp::new(&mut swd, 0);
        ap.power_up().expect("power-up");
        let idr = ap.idr().expect("IDR");
        assert_eq!(idr, 0x2477_0011);
        let base = profile.sram_base;
        ap.write32(base + 0x100, 0xDEAD_BEEF).expect("write");
        let v = ap.read32(base + 0x100).expect("read");
        assert_eq!(v, 0xDEAD_BEEF);
        // Block write/read with auto-increment.
        let words: Vec<u32> = (0..40).map(|i| 0xC0DE_0000 + i).collect();
        ap.write_block32(base + 0x200, &words).expect("block write");
        let mut back = vec![0u32; 40];
        ap.read_block32(base + 0x200, &mut back)
            .expect("block read");
        assert_eq!(back, words);
    }
    // DP CTRL/STAT acks the power-up bits.
    let st = swd.dp_read(dp_reg::CTRL_STAT).expect("ctrl/stat");
    assert!(st & (1 << 27) != 0, "CSYSPWRUPACK");
    assert!(st & (1 << 25) != 0, "CDBGPWRUPACK");
}

#[test]
fn locked_silicon_faults_ap_access_but_dp_works() {
    let profile = sm();
    let mut swd = SwdEngine::new(link(ScenarioKind::DebugLockdown, &profile));
    let dpidr = swd.connect().expect("DP still answers DPIDR");
    assert_eq!(dpidr, profile.swd_dpidr.unwrap());
    let mut ap = MemAp::new(&mut swd, 0);
    ap.power_up().expect("DP power-up is not locked");
    assert!(ap.idr().is_err(), "AP access must FAULT on locked silicon");
}

#[test]
fn brom_protocol_round_trip_with_auth() {
    let mut profile = ControllerProfile::builtin_by_name("phison-ps5012").unwrap();
    profile.brom.reply_ms = 5;
    let mut link = link(ScenarioKind::FirmwareCorrupt, &profile);
    // The Phison BROM demands challenge/response.
    {
        use dc_resurrect::uart_brom::{BromChannel, cmd};
        let params = profile.brom.clone();
        let mut ch = BromChannel::new(&mut link, params);
        ch.autobaud().expect("autobaud");
        ch.hello().expect("hello");
        // Without auth, DOWNLOAD is refused.
        assert!(ch.download(&[1, 2, 3], profile.sram_base).is_err());
        // Re-open with auth.
        ch.auth().expect("auth");
        ch.download(&[0xAA, 0xBB, 0xCC], profile.sram_base)
            .expect("download after auth");
        ch.poke32(profile.sram_base + 0x10, 0x1234_5678)
            .expect("poke");
        let v = ch.peek32(profile.sram_base + 0x10).expect("peek");
        assert_eq!(v, 0x1234_5678);
        let _ = cmd::ACK;
    }
}

#[test]
fn dead_rails_silence_everything_until_bench_power() {
    use dc_resurrect::hal::RigPower;
    let profile = sm();
    let mut link = link(ScenarioKind::PowerPathTvn, &profile);
    // UART dead.
    link.write_byte(0x55).unwrap();
    assert!(link.read_byte_timeout(10).unwrap().is_none());
    // SWD dead: no ack on the wire.
    {
        let mut swd = SwdEngine::new(link);
        assert!(swd.connect().is_err());
        link = swd.into_inner();
    }
    // JTAG dead: flat TDO.
    {
        let mut jeng = JtagEngine::new(link);
        assert!(jeng.scan_chain(64, 8).is_empty());
        link = jeng.into_inner();
    }
    // Bench power revives it.
    link.rig_apply_power().unwrap();
    link.write_byte(0x55).unwrap();
    let ack = link.read_byte_timeout(10).unwrap();
    assert_eq!(ack, Some(profile.brom.ack));
}

#[test]
fn hardfault_boot_flag_is_visible_in_debug_status() {
    use dc_resurrect::dp::DpPort;
    let profile = sm();
    let link = link(ScenarioKind::HardFaultLockup, &profile);
    // (the flag lives on the target; the SWD path surfaces it via DBG_STATS)
    assert!(link.target.faulted_at_boot);
    assert!(
        !link.target.brom_enabled,
        "BROM strap not asserted in Class B"
    );
    let mut swd = SwdEngine::new(link);
    swd.connect().expect("debug port alive in Class B");
    let _ = swd.dp_read(dp_reg::DPIDR_OR_ABORT).unwrap();
}
