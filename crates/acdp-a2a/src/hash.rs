//! The salt and the four record hashes (RFC-ACDP-0022 §5, §5.2).
//!
//! Exactly RFC-ACDP-0019 §4.3's construction, with no domain tag:
//! salted is `H(salt ‖ JCS(v))`, unsalted is `H(JCS(v))`, where `H(x)` is
//! `"sha256:"` followed by the lowercase hex SHA-256 of `x`.

use acdp::{crypto::canonicalize_value, AcdpError};
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The 32-byte per-body salt (§5.2). One fresh salt covers every salted
/// hash of one body; it is never in the body, only in the link.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt([u8; 32]);

impl Salt {
    /// Fresh salt from the operating system's CSPRNG.
    pub fn random() -> Result<Self, AcdpError> {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b)
            .map_err(|e| AcdpError::Serialization(format!("salt CSPRNG unavailable: {e}")))?;
        Ok(Self(b))
    }

    /// Wrap known bytes (known-answer tests).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Strict decode of the link form (§8 step 3): exactly 43 base64url
    /// characters, no padding, zero trailing bits (RFC 4648 §3.5).
    pub fn from_base64url(s: &str) -> Result<Self, AcdpError> {
        if s.len() != 43 {
            return Err(AcdpError::SchemaViolation(format!(
                "salt must be 43 base64url characters, got {}",
                s.len()
            )));
        }
        // URL_SAFE_NO_PAD rejects padding and non-zero trailing bits.
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| AcdpError::SchemaViolation(format!("salt is not base64url: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            AcdpError::SchemaViolation(format!("salt must be 32 bytes, got {}", b.len()))
        })?;
        Ok(Self(arr))
    }

    /// The link form: base64url without padding (43 characters).
    pub fn to_base64url(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Salt(..)")
    }
}

/// `H(bytes)`: `"sha256:"` ‖ lowercase hex SHA-256.
pub fn sha256_tagged(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// §5 salted hash `H(salt ‖ JCS(value))`.
pub fn salted(value: &Value, salt: &Salt) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(canonicalize_value(value));
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// §5 unsalted hash `H(JCS(value))` (an embedded record's `parts_hash`).
pub fn unsalted(value: &Value) -> String {
    sha256_tagged(&canonicalize_value(value))
}

/// `parts_hash` in the form `salt` names: salted when `Some`.
pub fn parts_hash(parts: &Value, salt: Option<&Salt>) -> String {
    match salt {
        Some(s) => salted(parts, s),
        None => unsalted(parts),
    }
}

/// The salted hash of an id string (`artifactId`, task `id`, `contextId`).
/// The id hashes are always salted (§5.2).
pub fn id_hash(id: &str, salt: &Salt) -> String {
    salted(&Value::String(id.to_owned()), salt)
}
