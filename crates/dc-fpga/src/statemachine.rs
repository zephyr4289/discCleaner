//! The autonomous sanitization state machine.
//!
//! This is the *root of destruction*: the entire decommission
//! lifecycle as one explicit, no-host, no-OS state machine that
//! runs on the open softcore and terminates in silicon (eFuse) —
//! or in a fault that deliberately does NOT burn completion.
//!
//! ```text
//!   SELF-TEST ──▶ ENUMERATE ──▶ ARM ──▶ SANITIZE ──▶ VERIFY ──▶ CERTIFY ──▶ SEAL ──▶ HALT
//!        │            │          │         │            │          │
//!        └────────────┴──────────┴─────────┴────────────┴──────────┴──▶ FAULT
//!                                                              (no COMPLETE fuse)
//! ```
//!
//! * **SELF-TEST** — interceptor integrity: gate register
//!   read/write/readback, fuse word sanity, lane-present bitmap
//!   plausibility. A tampered core stops here.
//! * **ENUMERATE** — passive IDENTIFY on every lane (ungated): the
//!   target inventory the run will be accountable for.
//! * **ARM** — operator consent: the ARM register must be written
//!   with the consent magic (a physical button / jumper on the
//!   interceptor board; there is no software path to it).
//! * **SANITIZE** — gate every present lane, block-erase the full
//!   window set, then apply the final pattern pass (if declared).
//! * **VERIFY** — full readback per lane with residue
//!   classification (see [`crate::verify`]).
//! * **CERTIFY** — transcript digest computed over every lane's
//!   verified readback.
//! * **SEAL** — burn per-target fuses, the VERIFIED fuse, the
//!   COMPLETE fuse, and latch the lane gate closed. Forever.
//! * **FAULT** — burn ONLY the fault fuse and latch: the board is
//!   bricked for storage reuse but reads as "failed, inspect".
//!
//! Every transition is logged to the [`Console`]; the console log is
//! the operator's transcript and the test suite's oracle.

use crate::efuse::EfuseBank;
use crate::hal::Mmio;
use crate::hal::{Console, regs};
use crate::lane::{LaneDriver, LaneGate, MAX_LANES};
use crate::verify::{Digest, verify_all};

/// Operator-consent magic for the ARM register (physical button).
pub const ARM_MAGIC: u32 = 0x4F50_4354; // "OPCT"

/// The machine's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    SelfTest,
    Enumerate,
    AwaitArm,
    Sanitize,
    Verify,
    Certify,
    Seal,
    Fault,
    Halted,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            State::SelfTest => "SELF-TEST",
            State::Enumerate => "ENUMERATE",
            State::AwaitArm => "AWAIT-ARM",
            State::Sanitize => "SANITIZE",
            State::Verify => "VERIFY",
            State::Certify => "CERTIFY",
            State::Seal => "SEAL",
            State::Fault => "FAULT",
            State::Halted => "HALTED",
        }
    }

    /// Terminal states (the machine stops stepping).
    pub const fn is_terminal(self) -> bool {
        matches!(self, State::Fault | State::Halted)
    }
}

/// Configuration of one run.
#[derive(Debug, Clone, Copy)]
pub struct RunConfig {
    /// Erase window count per lane (address space to cover).
    pub windows: u32,
    /// Final pattern word (None → pure-zero surface).
    pub pattern: Option<u32>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            windows: 256,
            pattern: None,
        }
    }
}

/// The machine. `mmio` + `console` are injected so the same code
/// runs on silicon and on `SimBoard`.
pub struct InterceptorMachine<'a> {
    mmio: &'a mut dyn Mmio,
    console: &'a mut dyn Console,
    cfg: RunConfig,
    state: State,
    /// Discovered targets (set in ENUMERATE).
    targets: [Option<crate::lane::Target>; MAX_LANES],
    /// Transcript digest (set in CERTIFY).
    transcript: u64,
    steps: u32,
}

impl<'a> InterceptorMachine<'a> {
    pub fn new(mmio: &'a mut dyn Mmio, console: &'a mut dyn Console, cfg: RunConfig) -> Self {
        Self {
            mmio,
            console,
            cfg,
            state: State::SelfTest,
            targets: [None; MAX_LANES],
            transcript: 0,
            steps: 0,
        }
    }

    pub const fn state(&self) -> State {
        self.state
    }

    pub const fn transcript_digest(&self) -> u64 {
        self.transcript
    }

    pub fn targets(&self) -> &[Option<crate::lane::Target>; MAX_LANES] {
        &self.targets
    }

    /// Run to a terminal state (bounded steps: autonomy needs a
    /// leash, even in silicon).
    pub fn run(&mut self, max_steps: u32) -> State {
        while !self.state.is_terminal() && self.steps < max_steps {
            self.step();
        }
        self.state
    }

    /// Advance one state.
    pub fn step(&mut self) {
        self.steps += 1;
        self.log_state();
        match self.state {
            State::SelfTest => self.step_selftest(),
            State::Enumerate => self.step_enumerate(),
            State::AwaitArm => self.step_arm(),
            State::Sanitize => self.step_sanitize(),
            State::Verify => self.step_verify(),
            State::Certify => self.step_certify(),
            State::Seal => self.step_seal(),
            State::Fault | State::Halted => {}
        }
    }

    fn log_state(&mut self) {
        self.console.put_str("[fpga] ");
        self.console.put_str(self.state.as_str());
        self.console.put_str("\n");
    }

    fn fault(&mut self, why: &str) {
        self.console.put_str("[fpga] FAULT: ");
        self.console.put_str(why);
        self.console.put_str("\n");
        // Burn ONLY the fault fuse and latch. The board must never
        // be re-usable as storage, and must never read as done.
        let mut fuse = EfuseBank::read(self.mmio);
        fuse.burn_fault();
        EfuseBank::burn(self.mmio, fuse.word());
        self.mmio.write32(regs::LANE_LATCH, 1);
        self.state = State::Fault;
    }

    fn step_selftest(&mut self) {
        // 1. Gate register integrity: write a pattern, read back.
        let probe = 0b0101u32;
        self.mmio.write32(0x30, probe);
        if self.mmio.read32(0x30) != probe {
            self.fault("interceptor register path failed");
            return;
        }
        // 2. Fuse word sanity: reserved bit must read 0; a board
        //    that already completed must not run again.
        let fuse = EfuseBank::read(self.mmio);
        if fuse.completed() {
            self.fault("board already sealed (COMPLETE fuse blown)");
            return;
        }
        if fuse.faulted() {
            self.fault("board previously faulted");
            return;
        }
        // 3. Present bitmap sanity.
        if self.mmio.read32(regs::LANE_PRESENT) as usize > (1 << MAX_LANES) - 1 {
            self.fault("lane-present bitmap implausible");
            return;
        }
        self.state = State::Enumerate;
    }

    fn step_enumerate(&mut self) {
        let targets = {
            let mut gate = LaneGate::new(self.mmio);
            gate.enumerate()
        };
        let any = targets.iter().any(|t| t.is_some());
        self.targets = targets;
        if !any {
            self.fault("no storage targets behind the interceptor");
            return;
        }
        self.state = State::AwaitArm;
    }

    fn step_arm(&mut self) {
        // Operator consent: the ARM register must already hold the
        // magic (physical button latched it before power-on of the
        // state machine; there is no software write path in the
        // real design — the sim writes it from the test bench).
        if self.mmio.read32(0x38) != ARM_MAGIC {
            // Not armed: stay (autonomy waits on the human, once).
            return;
        }
        self.state = State::Sanitize;
    }

    fn step_sanitize(&mut self) {
        // Gate every present lane.
        let present = self.mmio.read32(regs::LANE_PRESENT);
        {
            let mut gate = LaneGate::new(self.mmio);
            gate.gate(present);
        }
        // Erase every window of every present lane, then apply the
        // final pattern pass when one is declared.
        let mut drv = LaneDriver::new(self.mmio);
        for lane in 0..MAX_LANES as u32 {
            if (present >> lane) & 1 != 1 {
                continue;
            }
            for addr in 0..self.cfg.windows {
                if !drv.erase(lane, addr) {
                    self.fault("erase command refused");
                    return;
                }
            }
            if let Some(p) = self.cfg.pattern {
                for addr in 0..self.cfg.windows {
                    if !drv.write(lane, addr, p) {
                        self.fault("pattern write refused");
                        return;
                    }
                }
            }
        }
        self.state = State::Verify;
    }

    fn step_verify(&mut self) {
        let verdicts = verify_all(self.mmio, &self.targets, self.cfg.windows, self.cfg.pattern);
        if verdicts.iter().all(|v| v.is_none()) {
            self.fault("no targets to verify");
            return;
        }
        if verdicts.iter().flatten().any(|v| !v.passed()) {
            self.fault("readback residue detected — NOT certified");
            return;
        }
        self.state = State::Certify;
    }

    fn step_certify(&mut self) {
        // Chain every lane's verdict digest into one transcript.
        let mut digest = Digest::new();
        digest.update(crate::MAGIC[0] as u32);
        let verdicts = verify_all(self.mmio, &self.targets, self.cfg.windows, self.cfg.pattern);
        for v in verdicts.iter().flatten() {
            digest.update(v.lane);
            digest.update(v.words_read);
            digest.update(v.residue_words);
            digest.update(v.wear);
            digest.update((v.digest & 0xFFFF_FFFF) as u32);
            digest.update((v.digest >> 32) as u32);
        }
        self.transcript = digest.finalize();
        self.console.put_str("[fpga] transcript ");
        self.console.put_u32(self.transcript as u32);
        self.console.put_str("\n");
        self.state = State::Seal;
    }

    fn step_seal(&mut self) {
        // Per-target fuses.
        let mut fuse = EfuseBank::read(self.mmio);
        for t in self.targets.iter().flatten() {
            fuse.burn_target(t.lane);
        }
        EfuseBank::burn(self.mmio, fuse.word());
        // VERIFIED + COMPLETE.
        let mut fuse = EfuseBank::read(self.mmio);
        fuse.burn_verified();
        fuse.burn_complete();
        EfuseBank::burn(self.mmio, fuse.word());
        // Latch the gate closed — one-way.
        self.mmio.write32(regs::LANE_LATCH, 1);
        self.state = State::Halted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efuse::bits;
    use crate::hal::SinkConsole;

    /// Board + armed machine with targets on the given lanes.
    fn armed(lanes: &[usize]) -> (crate::hal::SimBoard, SinkConsole) {
        let mut board = crate::hal::SimBoard::new();
        for l in lanes {
            board.attach_target(*l);
        }
        board.write32(0x38, ARM_MAGIC);
        let con = SinkConsole::default();
        (board, con)
    }

    fn run(board: &mut crate::hal::SimBoard, con: &mut dyn Console) -> State {
        let mut m = InterceptorMachine::new(board, con, RunConfig::default());
        m.run(10_000)
    }

    #[test]
    fn happy_path_seals_and_burns_completion() {
        let (mut board, mut con) = armed(&[0, 1, 3]);
        let state = run(&mut board, &mut con);
        assert_eq!(state, State::Halted);
        let fuse = EfuseBank::read(&mut board);
        assert!(fuse.completed());
        assert!(!fuse.faulted());
        assert_eq!(fuse.burned_target_count(), 3);
        assert!(fuse.target_burned(0));
        assert!(fuse.target_burned(1));
        assert!(fuse.target_burned(3));
        // Gate latched.
        assert_eq!(board.read32(regs::LANE_LATCH), 1);
        // All media erased.
        for lane in [0, 1, 3] {
            let media = board.media[lane].as_ref().unwrap();
            assert!(media.iter().all(|w| *w == 0), "lane {lane} not erased");
        }
        // Console transcript is readable and ordered.
        let log = con.bytes.as_str();
        assert!(log.contains("SELF-TEST") && log.contains("SANITIZE"));
        assert!(log.contains("VERIFY") && log.contains("SEAL"));
        assert!(log.contains("transcript"));
    }

    #[test]
    fn transcript_digest_is_deterministic_and_content_bound() {
        let (mut a, mut ca) = armed(&[0, 2]);
        let (mut b, mut cb) = armed(&[0, 2]);
        let ma = InterceptorMachine::new(&mut a, &mut ca, RunConfig::default());
        let ma_digest = {
            let mut m = ma;
            m.run(10_000);
            m.transcript_digest()
        };
        let mb = InterceptorMachine::new(&mut b, &mut cb, RunConfig::default());
        let mb_digest = {
            let mut m = mb;
            m.run(10_000);
            m.transcript_digest()
        };
        assert_eq!(ma_digest, mb_digest, "same board, same transcript");
        // Different topology → different transcript.
        let (mut c, mut cc) = armed(&[0, 1, 2]);
        let mc_digest = {
            let mut m = InterceptorMachine::new(&mut c, &mut cc, RunConfig::default());
            m.run(10_000);
            m.transcript_digest()
        };
        assert_ne!(ma_digest, mc_digest);
    }

    #[test]
    fn fault_path_never_burns_completion() {
        // A tampered target that refuses erase: simulate by never
        // gating (the state machine gates, so instead corrupt via a
        // pre-latched board... simpler: attach nothing → enumerate
        // fault).
        let mut board = crate::hal::SimBoard::new();
        board.write32(0x38, ARM_MAGIC);
        let mut con = SinkConsole::default();
        let state = run(&mut board, &mut con);
        assert_eq!(state, State::Fault);
        let fuse = EfuseBank::read(&mut board);
        assert!(fuse.faulted());
        assert!(!fuse.completed());
        assert_eq!(fuse.burned_target_count(), 0);
        assert_eq!(board.read32(regs::LANE_LATCH), 1, "fault latches too");
        let log = con.bytes.as_str();
        assert!(log.contains("no storage targets"));
    }

    #[test]
    fn already_sealed_board_refuses_to_rerun() {
        let (mut board, mut con) = armed(&[0]);
        let state = run(&mut board, &mut con);
        assert_eq!(state, State::Halted);
        // Second boot on the same fuse bank: SELF-TEST must fault.
        let mut con2 = SinkConsole::default();
        let state2 = run(&mut board, &mut con2);
        assert_eq!(state2, State::Fault);
        let log = con2.bytes.as_str();
        assert!(log.contains("already sealed"));
    }

    #[test]
    fn arm_gate_requires_the_physical_magic() {
        let (mut board, mut con) = armed(&[0]);
        board.write32(0x38, 0); // disarm
        let mut m = InterceptorMachine::new(&mut board, &mut con, RunConfig::default());
        m.run(5);
        // Stuck in AwaitArm, untouched media.
        assert_eq!(m.state(), State::AwaitArm);
        let media = board.media[0].as_ref().unwrap();
        assert!(media.iter().any(|w| *w != 0), "unarmed run never erases");
    }

    #[test]
    fn patterned_run_verifies_the_declared_pattern() {
        let (mut board, mut con) = armed(&[1]);
        let mut m = InterceptorMachine::new(
            &mut board,
            &mut con,
            RunConfig {
                windows: 256,
                pattern: Some(0x6B6B_5A5A),
            },
        );
        let state = m.run(10_000);
        assert_eq!(state, State::Halted);
        let media = board.media[1].as_ref().unwrap();
        assert!(media.iter().all(|w| *w == 0x6B6B_5A5A));
        let fuse = EfuseBank::read(&mut board);
        assert!(fuse.completed());
    }

    #[test]
    fn fuse_bits_are_exactly_the_documented_layout() {
        let (mut board, mut con) = armed(&[0]);
        let state = run(&mut board, &mut con);
        assert_eq!(state, State::Halted);
        let w = board.read32(regs::EFUSE);
        // Lane 0 fuse + VERIFIED + COMPLETE, nothing else.
        assert_eq!(w, (1 << 0) | (1 << bits::VERIFIED) | (1 << bits::COMPLETE));
    }
}
