//! Producer-side signing — RFC-ACDP-0001 §5.8.
//!
//! Two algorithms are supported, matching the ACDP signature-algorithms
//! registry: `ed25519` (mandatory baseline) and `ecdsa-p256` (interop).
//!
//! For both, the signature input MUST be the ASCII bytes of the full
//! `content_hash` string (e.g. `sha256:5f8d…`), NOT the raw 32-byte
//! digest. The wire form is base64-encoded:
//!  - `ed25519` — 64 raw signature bytes → 88 base64 chars.
//!  - `ecdsa-p256` — IEEE 1363 `r‖s` (NOT DER) → 64 raw bytes → 88 base64 chars.
//!
//! Use [`AcdpSigningKey`] when you want a single key handle that selects
//! the algorithm at construction time; the producer builder treats both
//! variants uniformly. The concrete [`SigningKey`] / [`P256SigningKey`]
//! types remain available for callers that already know the algorithm.

use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::ContentHash;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer as _, SigningKey as DalekSigningKey};
use zeroize::ZeroizeOnDrop;

// ── Ed25519 ──────────────────────────────────────────────────────────────────

/// An Ed25519 signing key. Private bytes are zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey(DalekSigningKey);

impl SigningKey {
    /// Construct from a 32-byte raw private key seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(DalekSigningKey::from_bytes(bytes))
    }

    /// Try to construct from a slice. Returns an error if the length is wrong.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AcdpError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            AcdpError::InvalidSignature(format!(
                "signing key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self::from_bytes(&arr))
    }

    /// Generate a fresh Ed25519 key pair using the operating system RNG.
    ///
    /// Recommended for production callers; `from_bytes` is for loading
    /// previously-stored key material. Do not persist the raw 32-byte
    /// seed in cleartext — use a key vault or HSM.
    pub fn generate() -> Self {
        // `rand_core` 0.10 dropped `OsRng`; `getrandom::SysRng` is the
        // replacement, wrapped in `UnwrapErr` to get the infallible
        // `CryptoRng` this API requires (panics on OS RNG failure,
        // matching the old `OsRng`'s behavior).
        Self(DalekSigningKey::generate(&mut rand_core::UnwrapErr(
            getrandom::SysRng,
        )))
    }

    /// Sign the ASCII bytes of the full `content_hash` string per §5.8.
    ///
    /// Returns the signature as standard base64 (88 chars including
    /// padding for Ed25519).
    pub fn sign_content_hash(&self, hash: &ContentHash) -> String {
        // Sign the ASCII bytes of "sha256:<64-hex>", not the raw digest.
        let sig = self.0.sign(hash.as_str().as_bytes());
        STANDARD.encode(sig.to_bytes())
    }

    /// Raw public key bytes (32 bytes).
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Return the 32-byte raw private-key seed.
    ///
    /// Used by language bindings that need to store the key across
    /// FFI calls (the FFI surface holds a `[u8; 32]` and reconstructs
    /// the `SigningKey` per call, since `SigningKey` is
    /// [`ZeroizeOnDrop`] and not `Clone`).
    ///
    /// The seed is private-key material — treat it as a secret and
    /// route persistence through a key vault or HSM. The round-trip
    /// `SigningKey::from_bytes(&key.seed_bytes())` reconstructs an
    /// identical signing key.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Sign the UTF-8 bytes of an arbitrary string. Returns the
    /// signature as standard base64 (88 chars including padding).
    ///
    /// Distinct from [`Self::sign_content_hash`], which signs the
    /// ASCII bytes of the `"sha256:<hex>"` `content_hash` envelope per
    /// RFC-ACDP-0001 §5.8. Use this method when the protocol's signing
    /// input is *not* a `ContentHash` value — most notably the ACDP
    /// registry's bearer-token challenge flow, whose signing input is
    /// the namespaced ASCII string
    /// `"acdp-registry-auth:v1:{nonce}:{agent_id}:{authority}:{expires_at}"`.
    /// The registry verifies with
    /// [`crate::verify::verify_ed25519`]`(&pub_bytes, &sig, &input)`.
    pub fn sign_string(&self, input: &str) -> String {
        let sig = self.0.sign(input.as_bytes());
        STANDARD.encode(sig.to_bytes())
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(…)")
    }
}

// ── ECDSA-P256 ───────────────────────────────────────────────────────────────

/// An ECDSA-P256 signing key. Private scalar is zeroed on drop.
///
/// Wire form: 64 raw bytes IEEE 1363 (`r‖s`), base64-encoded with padding
/// for 88 characters — matching the verify path in
/// [`crate::verify::verify_ecdsa_p256`]. DER-encoded signatures
/// are NOT compatible with the ACDP registry entry for `ecdsa-p256`.
///
/// Signatures are emitted in **low-S** form (`s <= n/2`). ECDSA is
/// malleable — `(r, s)` and `(r, n - s)` both verify — so the signer
/// normalizes to give every signed value one canonical encoding. The
/// verifier ([`crate::verify::verify_ecdsa_p256`]) still accepts high-S
/// signatures from other producers; signature bytes are not identities.
pub struct P256SigningKey(p256::ecdsa::SigningKey);

impl P256SigningKey {
    /// Generate a fresh P-256 key pair using the OS RNG.
    ///
    /// Recommended for production callers; `from_bytes` is for loading
    /// previously-stored key material.
    pub fn generate() -> Self {
        use p256::elliptic_curve::Generate;
        // `SigningKey::random` is deprecated in favor of the `Generate`
        // trait (ecdsa 0.17); `rand_core` 0.10 also dropped `OsRng` — see
        // the sibling `SigningKey::generate` above for the `UnwrapErr`
        // rationale.
        Self(p256::ecdsa::SigningKey::generate_from_rng(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        ))
    }

    /// Construct from 32 raw scalar bytes (big-endian).
    ///
    /// Returns [`AcdpError::SchemaViolation`] when the scalar is invalid
    /// (e.g. zero or ≥ curve order). The error variant matches the
    /// shape used elsewhere for key-material parse failures
    /// (`AgentDid::parse_web`, `validate_signature_length`).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, AcdpError> {
        p256::ecdsa::SigningKey::from_bytes(bytes.into())
            .map(Self)
            .map_err(|e| AcdpError::SchemaViolation(format!("p256 key parse: {e}")))
    }

    /// Try to construct from a slice. Returns an error if the length is wrong.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AcdpError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            AcdpError::SchemaViolation(format!(
                "p256 signing key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Self::from_bytes(&arr)
    }

    /// Sign the ASCII bytes of the full `content_hash` string per §5.8.
    ///
    /// Uses RFC 6979 deterministic ECDSA (no `rng` parameter required).
    /// Returns the signature as standard base64 of the 64-byte IEEE 1363
    /// `r‖s` wire form (88 chars including padding), with `s` normalized
    /// to low-S (see the type-level docs).
    pub fn sign_content_hash(&self, hash: &ContentHash) -> String {
        self.sign_bytes_low_s(hash.as_str().as_bytes())
    }

    /// RFC 6979 sign, normalize to low-S, and encode as base64 of the
    /// 64-byte IEEE 1363 `r‖s` form. Shared by every P-256 sign path so
    /// none can skip the normalization.
    fn sign_bytes_low_s(&self, msg: &[u8]) -> String {
        use p256::ecdsa::{signature::Signer as _, Signature};
        let sig: Signature = self.0.sign(msg);
        // `normalize_s` replaces `s` with `n - s` when `s > n/2`
        // (constant-time conditional assign); a no-op for low-S.
        let sig = sig.normalize_s();
        // `Signature::to_bytes()` returns the fixed-size 64-byte IEEE 1363
        // form, exactly the wire shape ACDP requires.
        STANDARD.encode(sig.to_bytes())
    }

    /// Return the 32-byte raw private scalar (big-endian).
    ///
    /// P-256 analogue of [`SigningKey::seed_bytes`]. Language bindings
    /// hold this `[u8; 32]` and reconstruct the `P256SigningKey` per FFI
    /// call (the key zeroizes its scalar on drop and is not `Clone`). The
    /// round-trip `P256SigningKey::from_bytes(&k.seed_bytes())`
    /// reconstructs an identical signing key.
    ///
    /// The scalar is private-key material — treat it as a secret and
    /// route persistence through a key vault or HSM.
    pub fn seed_bytes(&self) -> [u8; 32] {
        // Wrap the temporary so the scalar copy is wiped on drop; only
        // the returned array (owned by the caller) keeps the secret.
        let fb = zeroize::Zeroizing::new(self.0.to_bytes());
        let mut out = [0u8; 32];
        // `AsRef<[u8]>` rather than the deprecated `GenericArray::as_slice`.
        out.copy_from_slice(fb.as_ref());
        out
    }

    /// Sign the UTF-8 bytes of an arbitrary string. Returns the
    /// signature as standard base64 of the 64-byte IEEE 1363 `r‖s`
    /// wire form (88 chars including padding).
    ///
    /// P-256 analogue of [`SigningKey::sign_string`] — uses RFC 6979
    /// deterministic ECDSA, so the output is reproducible. Use this for
    /// the ACDP registry's bearer-token challenge flow when the
    /// producer's key is ECDSA-P256; the registry verifies with
    /// [`crate::verify::verify_ecdsa_p256`]`(&sec1, &sig, input)`.
    ///
    /// Like [`Self::sign_content_hash`], the output is low-S.
    pub fn sign_string(&self, input: &str) -> String {
        self.sign_bytes_low_s(input.as_bytes())
    }

    /// SEC1-uncompressed public key (65 bytes: `0x04 || x || y`).
    ///
    /// Use this to populate a `did:web` verification method's
    /// `publicKeyJwk` (after splitting into the `x` / `y` halves) or
    /// `publicKeyMultibase` representation.
    pub fn verifying_key_sec1(&self) -> Vec<u8> {
        // `VerifyingKey::to_sec1_point` is delegated from the
        // `elliptic_curve::sec1::ToEncodedPoint` trait — inherent in the
        // crate's public surface, no extra `use` needed.
        self.0
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Return the public key as a P-256 JWK object suitable for
    /// embedding in a `did:web` verification method's `publicKeyJwk`
    /// field:
    ///
    /// ```json
    /// { "kty": "EC", "crv": "P-256",
    ///   "x": "<base64url-no-pad x>",
    ///   "y": "<base64url-no-pad y>" }
    /// ```
    ///
    /// FEAT-03: lets producers wire a published key into a DID
    /// document without manually splitting the SEC1 point and
    /// base64url-encoding each half.
    pub fn verifying_key_jwk(&self) -> serde_json::Value {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let sec1 = self.verifying_key_sec1();
        // SEC1 uncompressed = 0x04 || X(32) || Y(32) — slice off the
        // tag, split into halves, base64url-no-pad each.
        let x_b64 = URL_SAFE_NO_PAD.encode(&sec1[1..33]);
        let y_b64 = URL_SAFE_NO_PAD.encode(&sec1[33..65]);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
        })
    }

    /// Compose a complete `verificationMethod` entry for a `did:web`
    /// DID document. `method_id` is the full DID URL (e.g.
    /// `did:web:agents.example.com:alice#key-1`); `controller` is the
    /// containing DID (without fragment).
    ///
    /// Output uses the `JsonWebKey2020` type so consumers can resolve
    /// the algorithm via
    /// [`acdp_did::document::VerificationMethod::declared_algorithm`]
    /// (RFC-ACDP-0008 §3.9 algorithm-downgrade rejection).
    pub fn did_verification_method(&self, method_id: &str, controller: &str) -> serde_json::Value {
        serde_json::json!({
            "id": method_id,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": self.verifying_key_jwk(),
        })
    }
}

impl std::fmt::Debug for P256SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P256SigningKey(…)")
    }
}

// `p256::ecdsa::SigningKey` wraps a `Scalar` that implements
// `ZeroizeOnDrop`, so the private material is wiped automatically when
// `P256SigningKey` drops. No explicit `Drop` impl needed.

// ── Unified key handle ───────────────────────────────────────────────────────

/// Either-or signing key — selects the algorithm at construction time.
///
/// Producers normally use `acdp::producer::Producer::new_ed25519` or
/// `acdp::producer::Producer::new_p256` rather than constructing this
/// enum directly. The `acdp::producer::RequestBuilder` inspects the
/// variant to emit the matching `signature.algorithm` field.
#[derive(Debug)]
pub enum AcdpSigningKey {
    /// Ed25519 — mandatory baseline.
    Ed25519(SigningKey),
    /// ECDSA-P256 — interop variant.
    P256(P256SigningKey),
}

impl AcdpSigningKey {
    /// Returns `(algorithm_str, base64_signature)` for the wire envelope.
    ///
    /// The first element is the literal string ACDP requires in
    /// `signature.algorithm` (`"ed25519"` or `"ecdsa-p256"`).
    pub fn sign_content_hash(&self, hash: &ContentHash) -> (&'static str, String) {
        match self {
            Self::Ed25519(k) => ("ed25519", k.sign_content_hash(hash)),
            Self::P256(k) => ("ecdsa-p256", k.sign_content_hash(hash)),
        }
    }

    /// The ACDP algorithm string for the wrapped key, regardless of
    /// whether a signature has been produced yet.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ed25519",
            Self::P256(_) => "ecdsa-p256",
        }
    }
}

impl From<SigningKey> for AcdpSigningKey {
    fn from(k: SigningKey) -> Self {
        Self::Ed25519(k)
    }
}

impl From<P256SigningKey> for AcdpSigningKey {
    fn from(k: P256SigningKey) -> Self {
        Self::P256(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_from_slice_rejects_wrong_length() {
        let err = SigningKey::from_slice(&[0u8; 31]).unwrap_err();
        assert!(
            matches!(err, AcdpError::InvalidSignature(ref m) if m.contains("32 bytes")),
            "got {err:?}"
        );
        // Exactly 32 bytes is accepted.
        assert!(SigningKey::from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn p256_from_slice_rejects_wrong_length() {
        let err = P256SigningKey::from_slice(&[1u8; 33]).unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(ref m) if m.contains("32 bytes")),
            "got {err:?}"
        );
    }

    #[test]
    fn p256_from_bytes_rejects_invalid_scalar() {
        // An all-zero scalar is not a valid P-256 private key.
        let err = P256SigningKey::from_bytes(&[0u8; 32]).unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(ref m) if m.contains("p256 key parse")),
            "got {err:?}"
        );
    }

    #[test]
    fn ed25519_generate_produces_distinct_keys() {
        // Two fresh OsRng draws MUST produce different public keys.
        let a = SigningKey::generate();
        let b = SigningKey::generate();
        assert_ne!(
            a.verifying_key_bytes(),
            b.verifying_key_bytes(),
            "OsRng-backed generate() must not yield identical keys"
        );
    }

    #[test]
    fn p256_generate_produces_distinct_keys() {
        let a = P256SigningKey::generate();
        let b = P256SigningKey::generate();
        assert_ne!(
            a.verifying_key_sec1(),
            b.verifying_key_sec1(),
            "OsRng-backed P256 generate() must not yield identical keys"
        );
    }

    #[test]
    fn p256_sign_verify_round_trip() {
        use crate::verify::verify_ecdsa_p256;
        let key = P256SigningKey::generate();
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let sig = key.sign_content_hash(&hash);
        // 88 base64 chars (64 raw + padding).
        assert_eq!(sig.len(), 88, "p256 wire signature MUST be 88 base64 chars");
        let pub_sec1 = key.verifying_key_sec1();
        verify_ecdsa_p256(&pub_sec1, &sig, hash.as_str())
            .expect("round-trip p256 signature must verify");
    }

    /// FEAT-03: `verifying_key_jwk` produces an `EC/P-256` JWK whose
    /// `x`/`y` coordinates round-trip back to the SEC1 public key via
    /// `VerificationMethod::ecdsa_p256_public_key_sec1`. Pins the
    /// publish-side helper against the resolver-side extractor so a
    /// DID document populated via this helper verifies cleanly.
    #[test]
    fn p256_verifying_key_jwk_round_trips_to_sec1() {
        use acdp_did::document::VerificationMethod;
        let key = P256SigningKey::generate();
        let jwk = key.verifying_key_jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");

        // Build a VerificationMethod with this JWK and ask the extractor
        // for the SEC1 form — MUST equal what verifying_key_sec1
        // produced directly.
        let vm = VerificationMethod {
            id: "did:web:agents.example.com:test#key-1".into(),
            method_type: "JsonWebKey2020".into(),
            controller: "did:web:agents.example.com:test".into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        };
        let sec1_via_jwk = vm.ecdsa_p256_public_key_sec1().unwrap();
        assert_eq!(sec1_via_jwk, key.verifying_key_sec1());
        assert_eq!(vm.declared_algorithm(), Some("ecdsa-p256"));
    }

    /// FEAT-03: `did_verification_method` assembles a complete VM
    /// suitable for embedding in a DID document's `verificationMethod`
    /// array. Verifies the assembled object deserializes as
    /// `VerificationMethod` and exposes the right algorithm declaration.
    #[test]
    fn p256_did_verification_method_assembles() {
        use acdp_did::document::VerificationMethod;
        let key = P256SigningKey::generate();
        let vm_value = key.did_verification_method(
            "did:web:agents.example.com:alice#key-1",
            "did:web:agents.example.com:alice",
        );
        assert_eq!(vm_value["type"], "JsonWebKey2020");
        let vm: VerificationMethod = serde_json::from_value(vm_value).unwrap();
        assert_eq!(vm.id, "did:web:agents.example.com:alice#key-1");
        assert_eq!(vm.declared_algorithm(), Some("ecdsa-p256"));
        // Round-trip through the resolver-side extractor.
        let sec1 = vm.ecdsa_p256_public_key_sec1().unwrap();
        assert_eq!(sec1, key.verifying_key_sec1());
    }

    #[test]
    fn p256_sign_against_wrong_message_fails() {
        use crate::verify::verify_ecdsa_p256;
        let key = P256SigningKey::generate();
        let hash = ContentHash("sha256:".to_owned() + &"a".repeat(64));
        let sig = key.sign_content_hash(&hash);
        let pub_sec1 = key.verifying_key_sec1();
        let err =
            verify_ecdsa_p256(&pub_sec1, &sig, "sha256:0000000000000000").expect_err("must fail");
        assert!(matches!(err, AcdpError::InvalidSignature(_)));
    }

    #[test]
    fn p256_der_encoded_signature_rejected() {
        // The verifier requires IEEE 1363 r||s (64 bytes). A DER-encoded
        // signature is variable-length and starts with 0x30 — must be
        // rejected by length check.
        use crate::verify::verify_ecdsa_p256;
        let key = P256SigningKey::generate();
        let hash = ContentHash("sha256:".to_owned() + &"f".repeat(64));
        // Produce a DER-encoded signature using the lower-level API.
        use p256::ecdsa::signature::Signer as _;
        let der: p256::ecdsa::DerSignature = key.0.sign(hash.as_str().as_bytes());
        let sig_b64 = STANDARD.encode(der.as_bytes());
        let pub_sec1 = key.verifying_key_sec1();
        let err = verify_ecdsa_p256(&pub_sec1, &sig_b64, hash.as_str())
            .expect_err("DER-encoded p256 sig MUST be rejected");
        assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn acdp_signing_key_emits_correct_algorithm() {
        let ed = AcdpSigningKey::Ed25519(SigningKey::generate());
        let p2 = AcdpSigningKey::P256(P256SigningKey::generate());
        assert_eq!(ed.algorithm(), "ed25519");
        assert_eq!(p2.algorithm(), "ecdsa-p256");
        let hash = ContentHash("sha256:".to_owned() + &"a".repeat(64));
        let (alg_ed, _) = ed.sign_content_hash(&hash);
        let (alg_p2, _) = p2.sign_content_hash(&hash);
        assert_eq!(alg_ed, "ed25519");
        assert_eq!(alg_p2, "ecdsa-p256");
    }

    // ── Ed25519 golden vector regression (sig-001) ──────────────────────

    const ED25519_TEST_SEED: [u8; 32] = [0u8; 32];
    const ED25519_TEST_PUB_HEX: &str =
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    #[test]
    fn sign_and_verify_ed25519_golden() {
        use crate::verify::verify_ed25519;
        let key = SigningKey::from_bytes(&ED25519_TEST_SEED);
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let sig_b64 = key.sign_content_hash(&hash);
        assert_eq!(
            sig_b64,
            "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
        );
        let pub_bytes: [u8; 32] = hex::decode(ED25519_TEST_PUB_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        verify_ed25519(&pub_bytes, &sig_b64, hash.as_str()).unwrap();
    }

    /// `seed_bytes` returns the same 32-byte seed that `from_bytes`
    /// consumes — used by the FFI bindings to store the key across
    /// calls without holding the `ZeroizeOnDrop` handle.
    #[test]
    fn seed_bytes_round_trip() {
        let key = SigningKey::from_bytes(&ED25519_TEST_SEED);
        assert_eq!(key.seed_bytes(), ED25519_TEST_SEED);

        // Reconstruct from the exported seed and confirm it signs
        // identically — the signature is deterministic for Ed25519
        // given the same key and message.
        let rebuilt = SigningKey::from_bytes(&key.seed_bytes());
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        assert_eq!(
            key.sign_content_hash(&hash),
            rebuilt.sign_content_hash(&hash),
            "key reconstructed from seed_bytes must produce an identical signature"
        );
    }

    /// `sign_string` produces a base64-encoded Ed25519 signature over
    /// the UTF-8 bytes of the input and verifies via `verify_ed25519`
    /// against the same string. Pins the registry auth-challenge
    /// signing flow.
    #[test]
    fn sign_string_verifies_directly() {
        use crate::verify::verify_ed25519;
        let key = SigningKey::from_bytes(&ED25519_TEST_SEED);
        // Shape of the ACDP registry challenge `signing_input`.
        let signing_input = "acdp-registry-auth:v1:nonce-abc:\
                             did:web:agents.example.com:test-producer:\
                             registry.example.com:1748000000";
        let sig_b64 = key.sign_string(signing_input);
        // Ed25519 raw signature is 64 bytes → 88 base64 chars (padded).
        assert_eq!(sig_b64.len(), 88);

        let pub_bytes: [u8; 32] = hex::decode(ED25519_TEST_PUB_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        verify_ed25519(&pub_bytes, &sig_b64, signing_input).unwrap();

        // A different input must NOT verify against the same signature.
        verify_ed25519(&pub_bytes, &sig_b64, "different-input")
            .expect_err("sign_string output MUST be specific to the signed input");
    }

    // ── ECDSA-P256 binding-support + golden vector (sig-002) ─────────────

    /// `P256SigningKey::seed_bytes` round-trips through `from_bytes` and
    /// the reconstructed key signs identically (RFC 6979 deterministic).
    /// Pins the FFI key-storage contract used by the P256 bindings.
    #[test]
    fn p256_seed_bytes_round_trip() {
        // RFC 6979 P-256 example private scalar.
        let seed: [u8; 32] =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap()
                .try_into()
                .unwrap();
        let key = P256SigningKey::from_bytes(&seed).unwrap();
        assert_eq!(key.seed_bytes(), seed);

        let rebuilt = P256SigningKey::from_bytes(&key.seed_bytes()).unwrap();
        let hash = ContentHash("sha256:".to_owned() + &"a".repeat(64));
        assert_eq!(
            key.sign_content_hash(&hash),
            rebuilt.sign_content_hash(&hash),
            "key reconstructed from seed_bytes must produce an identical signature"
        );
    }

    /// `P256SigningKey::sign_string` produces an IEEE 1363 signature over
    /// the UTF-8 bytes of the input that verifies via `verify_ecdsa_p256`.
    /// Pins the P-256 registry auth-challenge signing flow.
    #[test]
    fn p256_sign_string_verifies_directly() {
        use crate::verify::verify_ecdsa_p256;
        let key = P256SigningKey::generate();
        let signing_input = "acdp-registry-auth:v1:nonce-abc:\
                             did:web:agents.example.com:test-producer:\
                             registry.example.com:1748000000";
        let sig_b64 = key.sign_string(signing_input);
        // P-256 IEEE 1363 r‖s is 64 bytes → 88 base64 chars (padded).
        assert_eq!(sig_b64.len(), 88);

        let sec1 = key.verifying_key_sec1();
        verify_ecdsa_p256(&sec1, &sig_b64, signing_input).unwrap();
        verify_ecdsa_p256(&sec1, &sig_b64, "different-input")
            .expect_err("sign_string output MUST be specific to the signed input");
    }

    // ── ECDSA-P256 low-S (#343) ──────────────────────────────────────────

    /// `n / 2` for P-256, big-endian. A signature is low-S iff
    /// `s <= HALF_N`; a byte-wise comparison of fixed-width big-endian
    /// arrays is a numeric comparison.
    const P256_HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];

    fn s_bytes(sig_b64: &str) -> [u8; 32] {
        let raw = STANDARD.decode(sig_b64).unwrap();
        raw[32..64].try_into().unwrap()
    }

    /// Re-encode a wire signature with `s` replaced by `n - s` — the
    /// third-party malleation #343 describes. Validity is unaffected.
    fn flip_s(sig_b64: &str) -> String {
        use p256::ecdsa::Signature;
        let raw = STANDARD.decode(sig_b64).unwrap();
        let sig = Signature::from_slice(&raw).unwrap();
        let flipped = Signature::from_scalars(sig.r(), -sig.s()).unwrap();
        STANDARD.encode(flipped.to_bytes())
    }

    /// Every P-256 signature this crate emits is low-S. RFC 6979 is
    /// deterministic, so the sample varies keys AND messages; 1000
    /// signatures leave a ~2^-1000 chance of passing without the
    /// normalization (about half of raw signatures are high-S).
    #[test]
    fn p256_signatures_are_always_low_s() {
        for i in 0u32..1000 {
            let mut seed = [0u8; 32];
            seed[0] = 1;
            seed[28..32].copy_from_slice(&(i / 10 + 1).to_be_bytes());
            let key = P256SigningKey::from_bytes(&seed).unwrap();
            let sig = if i % 2 == 0 {
                let hash = ContentHash(format!("sha256:{:064x}", i));
                key.sign_content_hash(&hash)
            } else {
                key.sign_string(&format!("acdp-registry-auth:v1:nonce-{i}"))
            };
            assert!(
                s_bytes(&sig) <= P256_HALF_N,
                "signature {i} is high-S: {sig}"
            );
        }
    }

    /// Low-S is an emit rule only: the verifier keeps accepting the
    /// high-S twin of a valid signature (other producers may not
    /// normalize, and the spec does not require consumers to reject).
    #[test]
    fn p256_verifier_accepts_high_s() {
        use crate::verify::verify_ecdsa_p256;
        let key = P256SigningKey::from_bytes(&[7u8; 32]).unwrap();
        let hash = ContentHash("sha256:".to_owned() + &"b".repeat(64));
        let low = key.sign_content_hash(&hash);
        let high = flip_s(&low);
        assert_ne!(low, high);
        assert!(s_bytes(&high) > P256_HALF_N, "flipped twin must be high-S");
        let sec1 = key.verifying_key_sec1();
        verify_ecdsa_p256(&sec1, &low, hash.as_str()).unwrap();
        verify_ecdsa_p256(&sec1, &high, hash.as_str())
            .expect("high-S signatures MUST still verify");
    }

    /// Golden vector regression for `ecdsa-p256` (sig-002). The test
    /// keypair's private scalar is 1 (public key = the P-256 generator);
    /// RFC 6979 makes the signature value reproducible. Drift here is a
    /// protocol break — keep in sync with
    /// `schemas/conformance/sig-002-ecdsa-p256-golden.json`.
    #[test]
    fn sign_and_verify_ecdsa_p256_golden() {
        use crate::verify::verify_ecdsa_p256;
        let mut seed = [0u8; 32];
        seed[31] = 1; // private scalar = 1
        let key = P256SigningKey::from_bytes(&seed).unwrap();
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let sig_b64 = key.sign_content_hash(&hash);
        assert_eq!(
            sig_b64,
            "O+b+E5OIecgwCnjDyTqsiwwy3VTdBHbVhiRR9k3FAPZHvLJ5dyYYVPPUWbl0dKDdgKMw2dWrnKWRANJVoS9vNw=="
        );
        // Public key MUST be the SEC1 generator point from the fixture.
        let sec1_hex = hex::encode(key.verifying_key_sec1());
        assert_eq!(
            sec1_hex,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        );
        verify_ecdsa_p256(&key.verifying_key_sec1(), &sig_b64, hash.as_str()).unwrap();
    }
}
