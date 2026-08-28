use crate::jcs_ref::JcsRef;
use dc_cert::OperatorKeyPair;
use serde_json::Value;

pub struct CertForge;

impl CertForge {
    /// Re-order keys of JSON object (reverses key order in text representation).
    pub fn reorder_keys(json_str: &str) -> Result<String, String> {
        let val: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
        if let Value::Object(map) = val {
            let mut out = String::from("{\n");
            let mut keys: Vec<&String> = map.keys().collect();
            keys.reverse(); // Reverse order

            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&format!("  \"{}\": {}", k, serde_json::to_string(&map[*k]).unwrap()));
            }
            out.push_str("\n}");
            Ok(out)
        } else {
            Err("Expected JSON object".to_string())
        }
    }

    /// Re-sign certificate with an ATTACK keypair (creates a self-consistent forgery).
    pub fn re_sign_with_attack_key(
        json_str: &str,
        attack_keypair: &OperatorKeyPair,
    ) -> Result<String, String> {
        let mut val: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;

        // 1. Update operator public key and fingerprint
        if let Some(op) = val.get_mut("operator") {
            if let Some(pk) = op.get_mut("public_key_ed25519") {
                *pk = Value::String(attack_keypair.public_key_hex());
            }
            if let Some(fp) = op.get_mut("key_fingerprint_blake3") {
                *fp = Value::String(attack_keypair.key_fingerprint_blake3());
            }
        }

        // 2. Remove existing signature
        if let Some(map) = val.as_object_mut() {
            map.remove("signature");
        }

        // 3. Compute JCS canonical bytes
        let canonical_str = JcsRef::canonicalize(&val)?;
        let sig_base64 = attack_keypair.sign_canonical_bytes(canonical_str.as_bytes());

        // 4. Attach new signature
        if let Some(map) = val.as_object_mut() {
            let mut sig_obj = serde_json::Map::new();
            sig_obj.insert("alg".to_string(), Value::String("Ed25519".to_string()));
            sig_obj.insert("value".to_string(), Value::String(sig_base64));
            map.insert("signature".to_string(), Value::Object(sig_obj));
        }

        serde_json::to_string_pretty(&val).map_err(|e| e.to_string())
    }

    /// Swap fingerprint with stale/fake value (K119 coherence test).
    pub fn swap_fingerprint(json_str: &str, fake_fp: &str) -> Result<String, String> {
        let mut val: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
        if let Some(op) = val.get_mut("operator") {
            if let Some(fp) = op.get_mut("key_fingerprint_blake3") {
                *fp = Value::String(fake_fp.to_string());
            }
        }
        serde_json::to_string_pretty(&val).map_err(|e| e.to_string())
    }

    /// Add UTF-8 BOM prefix (EF BB BF) to raw bytes.
    pub fn add_bom(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0xEF, 0xBB, 0xBF];
        out.extend_from_slice(bytes);
        out
    }

    /// Add trailing second JSON document.
    pub fn add_trailing_doc(json_str: &str) -> String {
        format!("{}\n{{\"trailing_second_document\": true}}", json_str)
    }

    /// Inject a duplicate key into the raw JSON text.
    pub fn add_duplicate_key(json_str: &str) -> String {
        json_str.replacen(
            "\"schema\": \"diskcleaner-cert/1\",",
            "\"schema\": \"diskcleaner-cert/1\",\n  \"schema\": \"diskcleaner-cert/1\",",
            1,
        )
    }
}
