//! Keyless signing, producer side (RFC-ACDP-0021, 0.5.0 Draft).
//!
//! 1. Generate an [`EphemeralKey`].
//! 2. Build the `POST /key-attestations` request with
//!    [`EphemeralKey::attestation_request`]: the workload's identity token,
//!    the key as a JWK, and the proof of possession over the
//!    `acdp-key-attestation-pop/1` preimage.
//! 3. Send it (the client's `RegistryClient::request_key_attestation`)
//!    and get back the attestation context.
//! 4. Turn the key and the attestation into a [`Producer`] with
//!    [`EphemeralKey::into_producer`] and publish to the same registry
//!    before the window closes.
//!
//! The key never leaves the process and is dropped with the producer.

use acdp_crypto::fingerprint::{fingerprint_ed25519, fingerprint_p256_sec1};
use acdp_crypto::sign::{AcdpSigningKey, P256SigningKey};
use acdp_crypto::SigningKey;
use acdp_primitives::error::AcdpError;
use acdp_types::body::Body;
use acdp_types::keyless::{
    keyless_key_id, token_hash, IdentityDescriptor, Jwk, KeyAttestation, KeyAttestationRef,
    KeyAttestationRequest, REQUEST_VERSION,
};

use crate::Producer;

/// A freshly generated signing key for one attestation window.
pub struct EphemeralKey(AcdpSigningKey);

impl EphemeralKey {
    /// A new random Ed25519 key.
    pub fn generate() -> Self {
        Self(AcdpSigningKey::Ed25519(SigningKey::generate()))
    }

    /// A new random ECDSA-P256 key.
    pub fn generate_p256() -> Self {
        Self(AcdpSigningKey::P256(P256SigningKey::generate()))
    }

    /// Wrap an existing key (fixed test vectors, HSM-backed seeds).
    pub fn from_key(key: AcdpSigningKey) -> Self {
        Self(key)
    }

    pub(crate) fn into_inner(self) -> AcdpSigningKey {
        self.0
    }

    /// `ed25519` or `ecdsa-p256`.
    pub fn algorithm(&self) -> &'static str {
        self.0.algorithm()
    }

    /// The public key as an RFC 7638 JWK.
    pub fn jwk(&self) -> Result<Jwk, AcdpError> {
        match &self.0 {
            AcdpSigningKey::Ed25519(k) => Ok(Jwk::from_ed25519(&k.verifying_key_bytes())),
            AcdpSigningKey::P256(k) => Jwk::from_p256_sec1(&k.verifying_key_sec1()),
        }
    }

    /// The RFC-ACDP-0010 §6 fingerprint of the public key.
    pub fn fingerprint(&self) -> Result<String, AcdpError> {
        match &self.0 {
            AcdpSigningKey::Ed25519(k) => Ok(fingerprint_ed25519(&k.verifying_key_bytes())),
            AcdpSigningKey::P256(k) => fingerprint_p256_sec1(&k.verifying_key_sec1()),
        }
    }

    /// The keyless key id this key gets under `controller` (§6.1).
    pub fn key_id(&self, controller: &str) -> Result<String, AcdpError> {
        keyless_key_id(controller, &self.fingerprint()?)
    }

    fn sign(&self, message: &str) -> String {
        match &self.0 {
            AcdpSigningKey::Ed25519(k) => k.sign_string(message),
            AcdpSigningKey::P256(k) => k.sign_string(message),
        }
    }

    /// The proof of possession for `registry_did` (§5.1): this key's
    /// signature over the JCS bytes of the `acdp-key-attestation-pop/1`
    /// preimage.
    pub fn pop(
        &self,
        controller: &str,
        registry_did: &str,
        token: &str,
    ) -> Result<String, AcdpError> {
        let pre = acdp_types::keyless::pop_preimage(
            controller,
            registry_did,
            &token_hash(token),
            &self.fingerprint()?,
        )?;
        Ok(self.sign(&pre))
    }

    /// The `POST /key-attestations` body for `controller` at the registry
    /// `registry_did` (§5.1). The token in `identity` MUST have been
    /// minted with `registry_did` in its `aud` (§5.2 step 3), and SHOULD
    /// carry `cnf.jkt` = [`Jwk::thumbprint`] of this key.
    pub fn attestation_request(
        &self,
        controller: &str,
        registry_did: &str,
        identity: IdentityDescriptor,
        requested_ttl_seconds: Option<u32>,
    ) -> Result<KeyAttestationRequest, AcdpError> {
        let pop = self.pop(controller, registry_did, identity.token())?;
        let req = KeyAttestationRequest {
            request_version: REQUEST_VERSION.into(),
            controller: controller.into(),
            identity,
            algorithm: self.algorithm().into(),
            public_key_jwk: self.jwk()?,
            pop,
            requested_ttl_seconds,
        };
        req.validate()?;
        Ok(req)
    }

    /// A [`Producer`] signing with this key under the attestation `body`
    /// (as returned by `POST /key-attestations` or retrieved by `ctx_id`).
    /// Checks the attestation against §5.3 and that it attests this key.
    pub fn into_producer(self, body: &Body) -> Result<Producer, AcdpError> {
        let attestation = KeyAttestation::from_body(body)?;
        let reference = KeyAttestationRef {
            ctx_id: body.ctx_id.clone(),
            content_hash: body.content_hash.clone(),
        };
        Producer::keyless(self.0, &attestation, reference)
    }
}

impl std::fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROLLER: &str = "did:web:agents.example.com:ci";
    const REGISTRY: &str = "did:web:registry.example.com";
    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.TEST-ONLY-NOT-A-REAL-TOKEN.kl-001";

    #[test]
    fn pop_matches_kl_001_vector_3() {
        let key = EphemeralKey::from_key(SigningKey::from_bytes(&[0x66; 32]).into());
        assert_eq!(
            key.pop(CONTROLLER, REGISTRY, TOKEN).unwrap(),
            "wMkYJkQDDFPR4aWUtKkLNebbLaQxt+Qo0EYCYip81vBZVxCNcnoT2EVsOO2VaR9P9Wc4IJr4RG0dL9ImVJF8Ag=="
        );
        let req = key
            .attestation_request(
                CONTROLLER,
                REGISTRY,
                IdentityDescriptor::oidc(
                    "https://token.actions.githubusercontent.com",
                    "repo:example/pipeline:ref:refs/heads/main",
                    TOKEN,
                ),
                None,
            )
            .unwrap();
        req.verify_pop(REGISTRY).unwrap();
        // A pop bound to one registry does not verify at another.
        assert!(req.verify_pop("did:web:other.example").is_err());
    }

    #[test]
    fn p256_request_round_trips() {
        let key = EphemeralKey::generate_p256();
        let req = key
            .attestation_request(
                CONTROLLER,
                REGISTRY,
                IdentityDescriptor::spiffe_jwt("spiffe://prod.example.com/ns/a/sa/p", "a.b.c"),
                Some(300),
            )
            .unwrap();
        assert_eq!(req.algorithm, "ecdsa-p256");
        req.verify_pop(REGISTRY).unwrap();
        assert_eq!(
            req.public_key_jwk.fingerprint().unwrap(),
            key.fingerprint().unwrap()
        );
    }
}
