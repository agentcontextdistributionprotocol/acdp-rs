//! DID document types and key extraction.

use acdp_primitives::error::AcdpError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// The `verificationMethod` fragment prefix RFC-ACDP-0021 §4.2 reserves
/// for keyless key ids. No DID document may list a method under it, and
/// [`DidDocument::find_by_fragment`] never returns one.
pub const KEYLESS_FRAGMENT_PREFIX: &str = "acdp-kl-";

/// A minimal DID document (subset sufficient for ACDP §5.11).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,

    #[serde(rename = "verificationMethod", default)]
    pub verification_methods: Vec<VerificationMethod>,

    #[serde(rename = "assertionMethod", default)]
    pub assertion_method: Vec<AssertionMethodRef>,

    /// The `service` entries, kept as JSON. ACDP reads one service type,
    /// RFC-ACDP-0021's `AcdpKeylessSigning` (see
    /// `acdp_types::keyless::ListedIdentities`).
    #[serde(rename = "service", default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<serde_json::Value>,
}

impl DidDocument {
    /// The fragment (substring after the final `#`) of a DID-URL, or
    /// `None` if it carries no fragment.
    fn fragment_of(id: &str) -> Option<&str> {
        id.rsplit_once('#').map(|(_, frag)| frag)
    }

    /// Resolve a verification-method reference to an absolute DID URL. A
    /// relative `#fragment` ref is resolved against this document's `id`;
    /// an already-absolute ref is returned unchanged.
    fn absolutize(&self, vm_ref: &str) -> String {
        match vm_ref.strip_prefix('#') {
            Some(frag) => format!("{}#{frag}", self.id),
            None => vm_ref.to_string(),
        }
    }

    /// Find a verification method whose `#fragment` is **exactly** `fragment`.
    ///
    /// Compares the fragment for equality rather than `ends_with`: a
    /// loose suffix match would let an unlisted `…#evil-key-1` satisfy a
    /// lookup for `key-1` (authorization-scope escalation within a DID).
    ///
    /// A fragment under [`KEYLESS_FRAGMENT_PREFIX`] never resolves, even
    /// when the document lists a method for it (RFC-ACDP-0021 §4.2):
    /// keyless key ids are resolved through their key attestation, never
    /// through RFC-ACDP-0001 §5.11, so a pre-listed method cannot make a
    /// verifier accept what a keyless-aware verifier would refuse.
    pub fn find_by_fragment(&self, fragment: &str) -> Option<&VerificationMethod> {
        if fragment.starts_with(KEYLESS_FRAGMENT_PREFIX) {
            return None;
        }
        self.verification_methods
            .iter()
            .find(|m| Self::fragment_of(&m.id) == Some(fragment))
    }

    /// Returns `true` if `vm_id` is listed in `assertionMethod`.
    ///
    /// Both `vm_id` and each `assertionMethod` entry are normalized to
    /// absolute DID URLs and compared for **exact** equality. The prior
    /// `vm_id.ends_with(id)` form authorized any `…#evil-key-1` against a
    /// relative `#key-1` entry.
    pub fn is_assertion_method(&self, vm_id: &str) -> bool {
        let target = self.absolutize(vm_id);
        self.assertion_method.iter().any(|r| match r {
            AssertionMethodRef::Id(id) => self.absolutize(id) == target,
            AssertionMethodRef::Embedded(m) => self.absolutize(&m.id) == target,
        })
    }
}

/// A DID document verification method entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,

    /// JWK public key representation.
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,

    /// Multibase-encoded public key (`z` prefix = base58btc + multicodec).
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

impl VerificationMethod {
    /// Extract the raw 32-byte Ed25519 public key.
    ///
    /// Supports both `publicKeyJwk` (OKP / Ed25519) and
    /// `publicKeyMultibase` (base58btc, multicodec 0xed01 prefix).
    pub fn ed25519_public_key_bytes(&self) -> Result<[u8; 32], AcdpError> {
        if let Some(jwk) = &self.public_key_jwk {
            return extract_from_jwk(jwk);
        }
        if let Some(mb) = &self.public_key_multibase {
            return extract_from_multibase(mb);
        }
        Err(AcdpError::KeyResolution(
            "verification method has neither publicKeyJwk nor publicKeyMultibase".into(),
        ))
    }

    /// Extract the SEC1-uncompressed P-256 public key (65 bytes
    /// starting with `0x04`).
    pub fn ecdsa_p256_public_key_sec1(&self) -> Result<Vec<u8>, AcdpError> {
        if let Some(jwk) = &self.public_key_jwk {
            return extract_p256_from_jwk(jwk);
        }
        Err(AcdpError::KeyResolution(
            "ecdsa-p256 verification method requires publicKeyJwk \
             (publicKeyMultibase not yet supported for P-256)"
                .into(),
        ))
    }

    /// Best-effort algorithm declaration derived from the verification
    /// method's `type` and (when relevant) `publicKeyJwk` parameters.
    ///
    /// Returns the canonical lowercase algorithm string compatible with
    /// `signature.algorithm` (e.g. `"ed25519"`, `"ecdsa-p256"`), or
    /// `None` for verification methods whose declared algorithm cannot
    /// be inferred from `type` alone.
    ///
    /// Used by the high-level `Verifier::verify_body` to
    /// detect algorithm-downgrade attacks per RFC-ACDP-0008 §3.9.
    pub fn declared_algorithm(&self) -> Option<&'static str> {
        match self.method_type.as_str() {
            "Ed25519VerificationKey2020" | "Ed25519VerificationKey2018" => Some("ed25519"),
            "EcdsaSecp256r1VerificationKey2019" => Some("ecdsa-p256"),
            "JsonWebKey2020" => {
                let jwk = self.public_key_jwk.as_ref()?;
                let kty = jwk.get("kty").and_then(|v| v.as_str())?;
                let crv = jwk.get("crv").and_then(|v| v.as_str())?;
                match (kty, crv) {
                    ("OKP", "Ed25519") => Some("ed25519"),
                    ("EC", "P-256") => Some("ecdsa-p256"),
                    _ => None,
                }
            }
            // #21: for a `type` this version doesn't special-case (e.g. the
            // W3C 2023 `Multikey`), still derive the algorithm from the
            // `publicKeyMultibase` multicodec prefix when present, so the
            // algorithm-downgrade guard (RFC-ACDP-0008 §3.9) is not silently
            // skipped for multibase keys. `None` only when nothing carries an
            // algorithm signal.
            _ => self
                .public_key_multibase
                .as_deref()
                .and_then(multicodec_algorithm),
        }
    }
}

/// Map a `publicKeyMultibase` value to its canonical algorithm string via the
/// multicodec prefix of the decoded key. The prefix is the multicodec code in
/// unsigned-varint encoding: `ed25519-pub` (code `0xed`) → bytes `0xed 0x01`,
/// `p256-pub` (code `0x1200`) → bytes `0x80 0x24`. Returns `None` if the value
/// isn't base58btc or the codec is unrecognized.
fn multicodec_algorithm(mb: &str) -> Option<&'static str> {
    let rest = mb.strip_prefix('z')?;
    let decoded = bs58::decode(rest).into_vec().ok()?;
    match decoded.get(0..2) {
        Some([0xed, 0x01]) => Some("ed25519"),
        Some([0x80, 0x24]) => Some("ecdsa-p256"),
        _ => None,
    }
}

/// `assertionMethod` entries can be either an ID string or an embedded object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AssertionMethodRef {
    Id(String),
    Embedded(Box<VerificationMethod>),
}

// ── Key extraction helpers ────────────────────────────────────────────────────

fn extract_from_jwk(jwk: &serde_json::Value) -> Result<[u8; 32], AcdpError> {
    let kty = jwk["kty"].as_str().unwrap_or("");
    let crv = jwk["crv"].as_str().unwrap_or("");

    if kty != "OKP" || crv != "Ed25519" {
        return Err(AcdpError::KeyResolution(format!(
            "expected OKP/Ed25519 JWK, got kty={kty} crv={crv}"
        )));
    }

    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| AcdpError::KeyResolution("JWK missing 'x' parameter".into()))?;

    let bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| AcdpError::KeyResolution(format!("JWK 'x' base64url decode: {e}")))?;

    bytes
        .try_into()
        .map_err(|_| AcdpError::KeyResolution("JWK 'x' is not 32 bytes (not Ed25519)".into()))
}

fn extract_p256_from_jwk(jwk: &serde_json::Value) -> Result<Vec<u8>, AcdpError> {
    let kty = jwk["kty"].as_str().unwrap_or("");
    let crv = jwk["crv"].as_str().unwrap_or("");
    if kty != "EC" || crv != "P-256" {
        return Err(AcdpError::KeyResolution(format!(
            "expected EC/P-256 JWK, got kty={kty} crv={crv}"
        )));
    }
    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| AcdpError::KeyResolution("JWK missing 'x'".into()))?;
    let y = jwk["y"]
        .as_str()
        .ok_or_else(|| AcdpError::KeyResolution("JWK missing 'y'".into()))?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| AcdpError::KeyResolution(format!("JWK 'x' base64url: {e}")))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| AcdpError::KeyResolution(format!("JWK 'y' base64url: {e}")))?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(AcdpError::KeyResolution(format!(
            "P-256 JWK x/y must be 32 bytes each, got x={} y={}",
            x_bytes.len(),
            y_bytes.len()
        )));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x_bytes);
    sec1.extend_from_slice(&y_bytes);
    Ok(sec1)
}

fn extract_from_multibase(mb: &str) -> Result<[u8; 32], AcdpError> {
    if !mb.starts_with('z') {
        return Err(AcdpError::KeyResolution(
            "only 'z' (base58btc) multibase prefix is supported".into(),
        ));
    }

    let decoded = bs58::decode(&mb[1..])
        .into_vec()
        .map_err(|e| AcdpError::KeyResolution(format!("base58 decode: {e}")))?;

    // Multicodec prefix for Ed25519 is 0xed 0x01
    if decoded.len() < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(AcdpError::KeyResolution(
            "multibase key does not have Ed25519 multicodec prefix (0xed 0x01)".into(),
        ));
    }

    decoded[2..].try_into().map_err(|_| {
        AcdpError::KeyResolution("Ed25519 key must be 32 bytes after multicodec prefix".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    fn test_pub_bytes() -> [u8; 32] {
        hex::decode(TEST_PUB_HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn extracts_from_jwk() {
        let raw = test_pub_bytes();
        let x = URL_SAFE_NO_PAD.encode(raw);
        let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "JsonWebKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        };
        assert_eq!(vm.ed25519_public_key_bytes().unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_kty() {
        let jwk = json!({ "kty": "EC", "crv": "P-256", "x": "abc" });
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "JsonWebKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        };
        assert!(matches!(
            vm.ed25519_public_key_bytes(),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn extracts_from_multibase() {
        let raw = test_pub_bytes();
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&raw);
        let mb = format!("z{}", bs58::encode(&prefixed).into_string());
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "Ed25519VerificationKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: None,
            public_key_multibase: Some(mb),
        };
        assert_eq!(vm.ed25519_public_key_bytes().unwrap(), raw);
    }

    #[test]
    fn rejects_non_z_multibase() {
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "Ed25519VerificationKey2020".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: None,
            public_key_multibase: Some("uAAAA".into()),
        };
        assert!(matches!(
            vm.ed25519_public_key_bytes(),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn rejects_non_ed25519_multicodec() {
        // 0xe7 = secp256k1 multicodec, not Ed25519 (0xed 0x01)
        let mut prefixed = vec![0xe7, 0x01];
        prefixed.extend_from_slice(&[0u8; 32]);
        let mb = format!("z{}", bs58::encode(&prefixed).into_string());
        let vm = VerificationMethod {
            id: "did:web:example.com#key-1".into(),
            method_type: "X".into(),
            controller: "did:web:example.com".into(),
            public_key_jwk: None,
            public_key_multibase: Some(mb),
        };
        assert!(matches!(
            vm.ed25519_public_key_bytes(),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn assertion_method_authorization_by_full_id() {
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![AssertionMethodRef::Id("did:web:example.com#key-1".into())],
            services: vec![],
        };
        assert!(doc.is_assertion_method("did:web:example.com#key-1"));
        assert!(!doc.is_assertion_method("did:web:example.com#key-2"));
    }

    #[test]
    fn assertion_method_authorization_by_relative_fragment() {
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![AssertionMethodRef::Id("#key-1".into())],
            services: vec![],
        };
        assert!(doc.is_assertion_method("did:web:example.com#key-1"));
    }

    #[test]
    fn find_by_fragment() {
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![],
            services: vec![],
        };
        assert!(doc.find_by_fragment("key-1").is_some());
        assert!(doc.find_by_fragment("key-2").is_none());
    }

    #[test]
    fn keyless_fragment_never_resolves() {
        // RFC-ACDP-0021 §4.2 / kl-007 B: a listed acdp-kl- method is
        // refused, not used.
        let id = "did:web:example.com#acdp-kl-f7b7676c94df7e8fd9998e38f9fff04d8588b00d1801764e3f1877a3feae4477";
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: id.into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![AssertionMethodRef::Id(id.into())],
            services: vec![],
        };
        let frag = id.split_once('#').unwrap().1;
        assert!(doc.find_by_fragment(frag).is_none());
    }

    #[test]
    fn find_by_fragment_no_loose_suffix_match() {
        // P1-2: an unlisted `…#evil-key-1` MUST NOT satisfy a lookup for
        // `key-1` via `ends_with`.
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![VerificationMethod {
                id: "did:web:example.com#evil-key-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: None,
            }],
            assertion_method: vec![],
            services: vec![],
        };
        assert!(doc.find_by_fragment("key-1").is_none());
        assert!(doc.find_by_fragment("evil-key-1").is_some());
    }

    #[test]
    fn assertion_method_no_loose_suffix_match() {
        // P1-2: assertionMethod `#key-1` MUST NOT authorize `…#evil-key-1`.
        let doc = DidDocument {
            id: "did:web:example.com".into(),
            verification_methods: vec![],
            assertion_method: vec![AssertionMethodRef::Id("#key-1".into())],
            services: vec![],
        };
        assert!(doc.is_assertion_method("did:web:example.com#key-1"));
        assert!(!doc.is_assertion_method("did:web:example.com#evil-key-1"));
        // A different DID sharing the fragment must not match either.
        assert!(!doc.is_assertion_method("did:web:attacker.com#key-1"));
    }

    /// #21: the algorithm-downgrade guard must derive an algorithm from a
    /// `Multikey`/multibase verification method whose `type` isn't otherwise
    /// recognized. The prefix is the multicodec code in *unsigned-varint*
    /// encoding, so `p256-pub` (code `0x1200`) decodes to bytes `0x80 0x24`
    /// — a literal `0x12 0x00` would never match a real key, silently
    /// skipping the guard.
    #[test]
    fn declared_algorithm_from_multibase_multicodec() {
        let mk = |prefix: &[u8], body_len: usize| {
            let mut prefixed = prefix.to_vec();
            prefixed.resize(prefix.len() + body_len, 0u8);
            let mb = format!("z{}", bs58::encode(&prefixed).into_string());
            VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "Multikey".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: None,
                public_key_multibase: Some(mb),
            }
        };
        // ed25519-pub: varint(0xed) = [0xed, 0x01], 32-byte key.
        assert_eq!(mk(&[0xed, 0x01], 32).declared_algorithm(), Some("ed25519"));
        // p256-pub: varint(0x1200) = [0x80, 0x24], 33-byte compressed key.
        assert_eq!(
            mk(&[0x80, 0x24], 33).declared_algorithm(),
            Some("ecdsa-p256")
        );
        // The incorrect big-endian-code prefix must NOT be treated as p256.
        assert_eq!(mk(&[0x12, 0x00], 33).declared_algorithm(), None);
        // Unknown codec → no algorithm signal.
        assert_eq!(mk(&[0xe7, 0x01], 33).declared_algorithm(), None);
    }
}
