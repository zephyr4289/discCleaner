use dc_core::StableIdentity;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityComparison {
    Match,
    MatchWithWarnings { absent_fields: Vec<String> },
    Contradiction { field: String, expected: String, observed: String },
    SizeMismatch { expected: u64, observed: u64 },
}

pub struct IdentityComparator;

impl IdentityComparator {
    /// Compare observed runtime target identity against stored journal/cert plan identity (Δ46).
    pub fn compare(expected: &StableIdentity, observed: &StableIdentity) -> IdentityComparison {
        // 1. Strict size check
        if expected.size_bytes != observed.size_bytes {
            return IdentityComparison::SizeMismatch {
                expected: expected.size_bytes,
                observed: observed.size_bytes,
            };
        }

        let mut absent = Vec::new();

        // 2. Serial comparison
        match (&expected.serial, &observed.serial) {
            (Some(e), Some(o)) => {
                if e != o {
                    return IdentityComparison::Contradiction {
                        field: "serial".to_string(),
                        expected: e.clone(),
                        observed: o.clone(),
                    };
                }
            }
            (Some(_), None) => absent.push("serial".to_string()),
            (None, Some(_)) => absent.push("serial".to_string()),
            (None, None) => {}
        }

        // 3. WWN comparison
        match (&expected.wwn, &observed.wwn) {
            (Some(e), Some(o)) => {
                if e != o {
                    return IdentityComparison::Contradiction {
                        field: "wwn".to_string(),
                        expected: e.clone(),
                        observed: o.clone(),
                    };
                }
            }
            (Some(_), None) => absent.push("wwn".to_string()),
            (None, Some(_)) => absent.push("wwn".to_string()),
            (None, None) => {}
        }

        // 4. Model comparison
        match (&expected.model, &observed.model) {
            (Some(e), Some(o)) => {
                if e != o {
                    return IdentityComparison::Contradiction {
                        field: "model".to_string(),
                        expected: e.clone(),
                        observed: o.clone(),
                    };
                }
            }
            (Some(_), None) => absent.push("model".to_string()),
            (None, Some(_)) => absent.push("model".to_string()),
            (None, None) => {}
        }

        // 5. DM name/UUID comparison
        if expected.dm_name.is_some() || observed.dm_name.is_some() {
            if expected.dm_name != observed.dm_name {
                return IdentityComparison::Contradiction {
                    field: "dm_name".to_string(),
                    expected: expected.dm_name.clone().unwrap_or_default(),
                    observed: observed.dm_name.clone().unwrap_or_default(),
                };
            }
        }

        if expected.dm_uuid.is_some() || observed.dm_uuid.is_some() {
            if expected.dm_uuid != observed.dm_uuid {
                return IdentityComparison::Contradiction {
                    field: "dm_uuid".to_string(),
                    expected: expected.dm_uuid.clone().unwrap_or_default(),
                    observed: observed.dm_uuid.clone().unwrap_or_default(),
                };
            }
        }

        if !absent.is_empty() {
            IdentityComparison::MatchWithWarnings { absent_fields: absent }
        } else {
            IdentityComparison::Match
        }
    }
}
