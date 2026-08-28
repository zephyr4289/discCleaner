pub struct UfsSessionDiscriminator;

impl UfsSessionDiscriminator {
    /// Discriminate link-recovery events (same LU set) from session replacement (changed LU set) (Δ350).
    pub fn evaluate_link_event(
        initial_lus: &[String],
        current_lus: &[String],
    ) -> Result<&'static str, &'static str> {
        if initial_lus == current_lus {
            Ok("LINK_RECOVERY_PROCEED")
        } else {
            Err("SESSION_INVALIDATED_LU_CHANGED")
        }
    }
}
