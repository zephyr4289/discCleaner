pub mod freeze;
pub mod geometry;
pub mod purge;
pub mod security;

pub use freeze::{FreezeEvaluator, FreezeFinding};
pub use geometry::{FdGen, GeometryStage, GeometryTransaction};
pub use purge::{
    AtaCompletionEvidence, AtaMechanismFallback, AtaPurgeClient, AtaPurgeError,
    AtaPurgeExecutionSummary, AtaPurgeMechanism, AtaPurgePermit, LinuxSatPurge, SatPurgeTransport,
    SatReply, SatXfer,
};
pub use security::{AtaFsmOutcome, AtaLifeline, AtaSecurityFsm, AtaSecurityState};

#[cfg(test)]
mod unit_tests {
    use super::*;
    use dc_hw::AtaSecurityStatus;

    fn status(locked: bool, frozen: bool) -> AtaSecurityStatus {
        AtaSecurityStatus {
            supported: true,
            enabled: true,
            locked,
            frozen,
            enhanced_erase_supported: true,
            erase_time_minutes: Some(2),
            enhanced_erase_time_minutes: Some(4),
        }
    }

    #[test]
    fn security_fsm_refuses_locked_and_frozen_at_intake() {
        let mut fsm = AtaSecurityFsm::new();
        assert!(matches!(
            fsm.process_intake(&status(true, false)),
            Err(AtaFsmOutcome::RefusedPreLocked)
        ));
        assert!(matches!(
            fsm.state,
            AtaSecurityState::Terminal(AtaFsmOutcome::RefusedPreLocked)
        ));

        let mut fsm2 = AtaSecurityFsm::new();
        assert!(matches!(
            fsm2.process_intake(&status(false, true)),
            Err(AtaFsmOutcome::RefusedFrozen)
        ));
    }

    #[test]
    fn lifeline_is_voided_after_clean_erase() {
        let mut fsm = AtaSecurityFsm::new();
        fsm.process_intake(&status(false, false)).unwrap();
        fsm.arm("rescue-password", true);
        let outcome = fsm.on_erase_success(true);
        assert!(matches!(outcome, AtaFsmOutcome::Clean { enhanced: true }));
        if let AtaSecurityState::Terminal(AtaFsmOutcome::Clean { .. }) = fsm.state {
            // good
        } else {
            panic!("FSM must be terminal after clean erase");
        }
    }

    #[test]
    fn lifeline_void_destroys_plaintext() {
        let mut life = AtaLifeline::new("secret-123");
        assert_eq!(life.plaintext_password.as_deref(), Some("secret-123"));
        assert!(!life.voided);
        life.void();
        assert!(life.voided);
        assert!(
            life.plaintext_password.is_none(),
            "voiding must remove the plaintext"
        );
        assert!(!life.password_hash.is_empty(), "audit hash survives");
    }

    #[test]
    fn freeze_evaluator_gates_on_override() {
        assert!(
            FreezeEvaluator::evaluate(true, false).is_err(),
            "frozen without override refused"
        );
        assert!(
            FreezeEvaluator::evaluate(true, true).is_ok(),
            "explicit override proceeds"
        );
        assert!(FreezeEvaluator::evaluate(false, false).is_ok());
    }

    #[test]
    fn geometry_transaction_stages_are_ordered_and_frozen() {
        let mut tx = GeometryTransaction::begin(500_000, 1_000_000, 1_500_000);
        let gen = FdGen(1);

        // DCO restore lifts the native ceiling to the DCO max and advances gen.
        let next_gen = tx.stage_dco_restore(gen);
        assert_eq!(next_gen, FdGen(2));
        assert_eq!(tx.native_capacity, 1_500_000);

        // HPA unlock lifts visible capacity to native.
        tx.stage_hpa_unlock(next_gen);
        assert_eq!(tx.current_capacity, 1_500_000);

        assert!(!tx.committed);
        tx.commit();
        assert!(tx.committed);
        assert_eq!(tx.stages.len(), 2);
        assert_eq!(tx.stages[0].op, "DCO_RESTORE");
        assert_eq!(tx.stages[1].op, "HPA_UNLOCK");
    }
}
