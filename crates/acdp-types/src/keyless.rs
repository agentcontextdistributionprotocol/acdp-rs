//! Keyless signing — RFC-ACDP-0021 (0.5.0; Final for the consumer side,
//! the registry side and its request/capabilities types Draft).
//!
//! A workload signs bodies with an ephemeral key that a registry has
//! attested for the producer DID (the *controller*) after checking the
//! workload's identity token. This module holds the offline, pure part:
//!
//! - the wire shapes: the `acdp-key-attestation/1` metadata
//!   ([`KeyAttestation`]), the `POST /key-attestations` request
//!   ([`KeyAttestationRequest`]), the body's `key_attestation` member
//!   ([`KeyAttestationRef`]) and the capabilities `keyless` member
//!   ([`KeylessCapabilities`]);
//! - the derived values: [`keyless_key_id`], [`token_hash`], the JWK
//!   fingerprint and thumbprint ([`Jwk`]), and the proof-of-possession
//!   preimage ([`pop_preimage`]);
//! - the controller's `AcdpKeylessSigning` service ([`ListedIdentities`]);
//! - the two decision tables: who may supersede whom (§7,
//!   [`may_supersede`]) and the key status of a keyless signature
//!   (§8.2, [`classify`]).
//!
//! Fetching attestations and verifying bodies against them needs the
//! network or a bundle and lives in `acdp_client` and `acdp_chain`
//! (feature `keyless`). Nothing here adds a key-authorization state or a
//! revocation trust class: [`KeylessStatus`] has exactly the three
//! statuses consumers already report.

use acdp_crypto::fingerprint::{fingerprint_ed25519, fingerprint_p256_sec1};
use acdp_did::DidDocument;
use acdp_primitives::error::AcdpError;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::body::{Body, Signature};
use crate::primitives::{AgentDid, ContentHash, CtxId};
use crate::serde_helpers::de_present;

pub use acdp_did::KEYLESS_FRAGMENT_PREFIX;
pub use acdp_primitives::keyless::KeylessReason;

/// The body `type` of a key attestation (§5.3).
pub const KEY_ATTESTATION_TYPE: &str = "acdp:key-attestation";
/// The `schema_uri` of a key attestation (§5.3).
pub const KEY_ATTESTATION_SCHEMA_URI: &str =
    "https://schemas.acdp.io/v0.1.0/acdp-key-attestation.schema.json";
/// `attestation_version` (§5.3).
pub const ATTESTATION_VERSION: &str = "acdp-key-attestation/1";
/// `request_version` (§5.1).
pub const REQUEST_VERSION: &str = "acdp-key-attestation-request/1";
/// `pop_version` of the proof-of-possession preimage (§5.1).
pub const POP_VERSION: &str = "acdp-key-attestation-pop/1";
/// The DID-document service type that lists authorized identities (§4.1).
pub const KEYLESS_SERVICE_TYPE: &str = "AcdpKeylessSigning";
/// The longest attestation window, in seconds (§5.2 step 7).
pub const MAX_WINDOW_SECONDS: i64 = 3600;
/// The window a registry mints when the request names none (§5.1).
pub const DEFAULT_TTL_SECONDS: u32 = 600;
/// The registry profile (§13.2).
pub const REGISTRY_PROFILE: &str = "acdp-registry-keyless";
/// The consumer profile (§13.2).
pub const CONSUMER_PROFILE: &str = "acdp-consumer-keyless";

fn invalid(msg: impl std::fmt::Display) -> AcdpError {
    AcdpError::SchemaViolation(format!("key attestation: {msg}"))
}

// ── §6.1 key ids and §5.1 hashes ───────────────────────────────────────────

/// True when `key_id`'s fragment begins `acdp-kl-` (§2, §6.1): the key
/// is resolved through a key attestation, never through RFC-ACDP-0001
/// §5.11.
pub fn is_keyless_key_id(key_id: &str) -> bool {
    key_id
        .split_once('#')
        .is_some_and(|(_, frag)| frag.starts_with(KEYLESS_FRAGMENT_PREFIX))
}

/// `<controller>#acdp-kl-<hex>` for an RFC-ACDP-0010 §6 fingerprint
/// (§6.1).
pub fn keyless_key_id(controller: &str, key_fingerprint: &str) -> Result<String, AcdpError> {
    let hex = key_fingerprint
        .strip_prefix("sha256:")
        .filter(|h| is_lower_hex_64(h))
        .ok_or_else(|| invalid(format!("'{key_fingerprint}' is not a sha256 fingerprint")))?;
    Ok(format!("{controller}#{KEYLESS_FRAGMENT_PREFIX}{hex}"))
}

/// `sha256:` + hex SHA-256 of the token's ASCII bytes (§5.1).
pub fn token_hash(token: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes())))
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha256(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(is_lower_hex_64)
}

fn is_did_web(s: &str) -> bool {
    s.strip_prefix("did:web:").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:%-".contains(&b))
    })
}

/// True when `v` is `major.minor.patch` at or above 0.5.0.
fn at_least_0_5(v: &str) -> bool {
    let parts: Vec<u64> = v.split('.').filter_map(|p| p.parse().ok()).collect();
    parts.len() == 3 && (parts[0], parts[1]) >= (0, 5)
}

// ── JWK (RFC 7517 / RFC 7638) ──────────────────────────────────────────────

/// An attested public key as a JWK with exactly the RFC 7638 members:
/// `{crv, kty, x}` for Ed25519, `{crv, kty, x, y}` for P-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jwk {
    /// `Ed25519` or `P-256`.
    pub crv: String,
    /// `OKP` or `EC`.
    pub kty: String,
    /// base64url (no padding) of the key, or of the P-256 x coordinate.
    pub x: String,
    /// base64url (no padding) of the P-256 y coordinate.
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub y: Option<String>,
}

/// A JWK decoded to key bytes.
enum KeyBytes {
    Ed25519([u8; 32]),
    /// SEC1 uncompressed: `0x04 || x || y`.
    P256(Vec<u8>),
}

fn b64u_32(field: &str, s: &str) -> Result<[u8; 32], AcdpError> {
    if s.len() != 43 {
        return Err(invalid(format!(
            "public_key_jwk.{field} is not 32 base64url bytes"
        )));
    }
    URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| invalid(format!("public_key_jwk.{field} is not 32 base64url bytes")))
}

impl Jwk {
    /// The JWK of a raw Ed25519 public key.
    pub fn from_ed25519(public_key: &[u8; 32]) -> Self {
        Jwk {
            crv: "Ed25519".into(),
            kty: "OKP".into(),
            x: URL_SAFE_NO_PAD.encode(public_key),
            y: None,
        }
    }

    /// The JWK of a SEC1 P-256 public key (compressed or uncompressed).
    pub fn from_p256_sec1(sec1: &[u8]) -> Result<Self, AcdpError> {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
            .map_err(|e| invalid(format!("P-256 key: {e}")))?;
        let point = vk.to_sec1_point(false);
        let raw = point.as_bytes();
        Ok(Jwk {
            crv: "P-256".into(),
            kty: "EC".into(),
            x: URL_SAFE_NO_PAD.encode(&raw[1..33]),
            y: Some(URL_SAFE_NO_PAD.encode(&raw[33..65])),
        })
    }

    fn key_bytes(&self) -> Result<KeyBytes, AcdpError> {
        match (self.kty.as_str(), self.crv.as_str(), &self.y) {
            ("OKP", "Ed25519", None) => Ok(KeyBytes::Ed25519(b64u_32("x", &self.x)?)),
            ("EC", "P-256", Some(y)) => {
                let mut sec1 = vec![0x04];
                sec1.extend_from_slice(&b64u_32("x", &self.x)?);
                sec1.extend_from_slice(&b64u_32("y", y)?);
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map_err(|e| invalid(format!("public_key_jwk is not a P-256 point: {e}")))?;
                Ok(KeyBytes::P256(sec1))
            }
            _ => Err(invalid(
                "public_key_jwk must be {kty: OKP, crv: Ed25519, x} or {kty: EC, crv: P-256, x, y}",
            )),
        }
    }

    /// The signature algorithm the key type implies (§5.2 step 5).
    pub fn algorithm(&self) -> Result<&'static str, AcdpError> {
        Ok(match self.key_bytes()? {
            KeyBytes::Ed25519(_) => "ed25519",
            KeyBytes::P256(_) => "ecdsa-p256",
        })
    }

    /// The RFC-ACDP-0010 §6 fingerprint: over the raw 32-byte Ed25519
    /// key, or the 33-byte SEC1-compressed P-256 point (§5.3).
    pub fn fingerprint(&self) -> Result<String, AcdpError> {
        match self.key_bytes()? {
            KeyBytes::Ed25519(k) => Ok(fingerprint_ed25519(&k)),
            KeyBytes::P256(sec1) => fingerprint_p256_sec1(&sec1),
        }
    }

    /// The RFC 7638 thumbprint: base64url SHA-256 of the JCS bytes of
    /// the required members (§5.2 step 3, `cnf.jkt`).
    pub fn thumbprint(&self) -> Result<String, AcdpError> {
        self.key_bytes()?;
        let canon = acdp_jcs::canonicalize(self)?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canon)))
    }

    /// Verify a base64 signature under `algorithm` over `message`'s
    /// bytes. `algorithm` must be the one the key type implies.
    pub fn verify(
        &self,
        algorithm: &str,
        signature_b64: &str,
        message: &str,
    ) -> Result<(), AcdpError> {
        match (self.key_bytes()?, algorithm) {
            (KeyBytes::Ed25519(k), "ed25519") => {
                acdp_crypto::verify_ed25519(&k, signature_b64, message)
            }
            (KeyBytes::P256(sec1), "ecdsa-p256") => {
                acdp_crypto::verify_ecdsa_p256(&sec1, signature_b64, message)
            }
            _ => Err(AcdpError::InvalidSignature(format!(
                "signature algorithm '{algorithm}' does not match the attested key type"
            ))),
        }
    }
}

// ── §4 workload identities ─────────────────────────────────────────────────

/// A workload identity: the RFC-AITP-0002 identity hint, with no proof
/// (§2, §4.1, §5.3). Equality is the §4.1 byte-for-byte comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum WorkloadIdentity {
    /// An OIDC issuer and `sub`.
    Oidc {
        /// The issuer URI (`https://`).
        issuer: String,
        /// The token's `sub`.
        subject: String,
    },
    /// A SPIFFE ID.
    Spiffe {
        /// The SPIFFE ID (`spiffe://<trust domain>/...`).
        subject: String,
    },
}

fn check_oidc(issuer: &str, subject: &str) -> Result<(), AcdpError> {
    let issuer_ok = issuer.len() <= 512
        && issuer.strip_prefix("https://").is_some_and(|r| {
            !r.is_empty() && !r.chars().any(|c| c.is_whitespace() || c == '#' || c == '?')
        });
    if !issuer_ok {
        return Err(invalid(format!(
            "identity.issuer '{issuer}' is not an https issuer URI"
        )));
    }
    if subject.is_empty() || subject.len() > 512 {
        return Err(invalid("identity.subject must be 1 to 512 characters"));
    }
    Ok(())
}

/// The SPIFFE trust domain of a SPIFFE ID, if it is one.
pub fn spiffe_trust_domain(subject: &str) -> Option<&str> {
    let rest = subject.strip_prefix("spiffe://")?;
    let domain = rest.split('/').next()?;
    let domain_ok = !domain.is_empty()
        && domain
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    let path_ok = rest[domain.len()..].split('/').skip(1).all(|seg| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~%!$&'()*+,;=:@-".contains(&b))
    });
    (domain_ok && path_ok && subject.len() <= 2048).then_some(domain)
}

fn check_spiffe(subject: &str) -> Result<(), AcdpError> {
    spiffe_trust_domain(subject)
        .map(|_| ())
        .ok_or_else(|| invalid(format!("identity.subject '{subject}' is not a SPIFFE ID")))
}

impl WorkloadIdentity {
    /// Check the schema patterns.
    pub fn validate(&self) -> Result<(), AcdpError> {
        match self {
            Self::Oidc { issuer, subject } => check_oidc(issuer, subject),
            Self::Spiffe { subject } => check_spiffe(subject),
        }
    }
}

/// An RFC-AITP-0002 identity descriptor with its token as `proof`
/// (§5.1). `Debug` never prints the token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum IdentityDescriptor {
    /// An OIDC ID token.
    Oidc {
        /// The issuer URI.
        issuer: String,
        /// The token's `sub`.
        subject: String,
        /// The ID token.
        proof: String,
    },
    /// A SPIFFE JWT-SVID.
    Spiffe {
        /// The SPIFFE ID.
        subject: String,
        /// Always `jwt-svid`: X509-SVIDs are not accepted.
        svid_type: String,
        /// The JWT-SVID.
        proof: String,
    },
}

impl std::fmt::Debug for IdentityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oidc {
                issuer, subject, ..
            } => f
                .debug_struct("Oidc")
                .field("issuer", issuer)
                .field("subject", subject)
                .field("proof", &"<redacted>")
                .finish(),
            Self::Spiffe {
                subject, svid_type, ..
            } => f
                .debug_struct("Spiffe")
                .field("subject", subject)
                .field("svid_type", svid_type)
                .field("proof", &"<redacted>")
                .finish(),
        }
    }
}

fn is_compact_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    s.len() <= 16384
        && parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

impl IdentityDescriptor {
    /// An OIDC descriptor.
    pub fn oidc(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self::Oidc {
            issuer: issuer.into(),
            subject: subject.into(),
            proof: token.into(),
        }
    }

    /// A SPIFFE JWT-SVID descriptor.
    pub fn spiffe_jwt(subject: impl Into<String>, svid: impl Into<String>) -> Self {
        Self::Spiffe {
            subject: subject.into(),
            svid_type: "jwt-svid".into(),
            proof: svid.into(),
        }
    }

    /// The token.
    pub fn token(&self) -> &str {
        match self {
            Self::Oidc { proof, .. } | Self::Spiffe { proof, .. } => proof,
        }
    }

    /// The identity without its proof.
    pub fn identity(&self) -> WorkloadIdentity {
        match self {
            Self::Oidc {
                issuer, subject, ..
            } => WorkloadIdentity::Oidc {
                issuer: issuer.clone(),
                subject: subject.clone(),
            },
            Self::Spiffe { subject, .. } => WorkloadIdentity::Spiffe {
                subject: subject.clone(),
            },
        }
    }

    /// Check the schema patterns: X509-SVIDs and malformed tokens are a
    /// `schema_violation`.
    pub fn validate(&self) -> Result<(), AcdpError> {
        match self {
            Self::Oidc {
                issuer,
                subject,
                proof,
            } => {
                check_oidc(issuer, subject)?;
                if !is_compact_jwt(proof) {
                    return Err(invalid("identity.proof is not a compact JWT"));
                }
            }
            Self::Spiffe {
                subject,
                svid_type,
                proof,
            } => {
                check_spiffe(subject)?;
                if svid_type != "jwt-svid" {
                    return Err(invalid(format!(
                        "identity.svid_type '{svid_type}' is not jwt-svid (X509-SVIDs are not accepted)"
                    )));
                }
                if !is_compact_jwt(proof) {
                    return Err(invalid("identity.proof is not a compact JWT-SVID"));
                }
            }
        }
        Ok(())
    }
}

/// One entry of the controller's `AcdpKeylessSigning` service (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedIdentity {
    /// The identity.
    pub identity: WorkloadIdentity,
    /// Whether its keys may supersede any of the controller's lineages.
    pub org_wide: bool,
}

/// The identities a controller's DID document authorizes (§4.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListedIdentities(Vec<ListedIdentity>);

impl ListedIdentities {
    /// Read the document's `AcdpKeylessSigning` service. None, or more
    /// than one, authorizes no identity. Entries of a type other than
    /// `oidc` or `spiffe`, and malformed entries, are ignored.
    pub fn of(doc: &DidDocument) -> Self {
        let mut services = doc
            .services
            .iter()
            .filter(|s| s.get("type").and_then(Value::as_str) == Some(KEYLESS_SERVICE_TYPE));
        let (Some(service), None) = (services.next(), services.next()) else {
            return Self::default();
        };
        let Some(entries) = service
            .get("serviceEndpoint")
            .and_then(|e| e.get("identities"))
            .and_then(Value::as_array)
        else {
            return Self::default();
        };
        Self(entries.iter().filter_map(listed_entry).collect())
    }

    /// The entry listing `identity`, compared byte for byte.
    pub fn find(&self, identity: &WorkloadIdentity) -> Option<&ListedIdentity> {
        self.0.iter().find(|e| &e.identity == identity)
    }

    /// Every listed entry.
    pub fn entries(&self) -> &[ListedIdentity] {
        &self.0
    }
}

fn listed_entry(entry: &Value) -> Option<ListedIdentity> {
    let obj = entry.as_object()?;
    let org_wide = match obj.get("org_wide") {
        None => false,
        Some(v) => v.as_bool()?,
    };
    let mut hint = obj.clone();
    hint.remove("org_wide");
    let identity: WorkloadIdentity = serde_json::from_value(Value::Object(hint)).ok()?;
    identity.validate().ok()?;
    Some(ListedIdentity { identity, org_wide })
}

// ── §5.3 the attestation ───────────────────────────────────────────────────

/// The `acdp-key-attestation/1` metadata of an `acdp:key-attestation`
/// body (§5.3). Closed at every level; build it with
/// [`KeyAttestation::from_metadata`] or [`KeyAttestation::from_body`],
/// which also check the rules the schema cannot express.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAttestation {
    /// Always [`ATTESTATION_VERSION`].
    pub attestation_version: String,
    /// The controller's `did:web` DID.
    pub controller: String,
    /// The verified workload identity.
    pub identity: WorkloadIdentity,
    /// Copied from the controller's DID-document entry.
    pub org_wide: bool,
    /// `<controller>#acdp-kl-<hex>` (§6.1).
    pub key_id: String,
    /// `ed25519` or `ecdsa-p256`.
    pub algorithm: String,
    /// The attested key.
    pub public_key_jwk: Jwk,
    /// The attested key's RFC-ACDP-0010 §6 fingerprint.
    pub key_fingerprint: String,
    /// Start of the window, inclusive.
    #[serde(with = "crate::trust_list::ms")]
    pub not_before: DateTime<Utc>,
    /// End of the window, exclusive.
    #[serde(with = "crate::trust_list::ms")]
    pub not_after: DateTime<Utc>,
    /// `sha256:` + hex SHA-256 of the token.
    pub token_hash: String,
}

impl KeyAttestation {
    /// Parse the metadata object and check §5.3: the closed schema, the
    /// fingerprint of `public_key_jwk`, the `key_id` derived from it, the
    /// algorithm matching the key type, and the window bound.
    pub fn from_metadata(metadata: &Value) -> Result<Self, AcdpError> {
        let att = Self::deserialize(metadata).map_err(invalid)?;
        att.validate()?;
        Ok(att)
    }

    fn validate(&self) -> Result<(), AcdpError> {
        if self.attestation_version != ATTESTATION_VERSION {
            return Err(invalid(format!(
                "attestation_version '{}' is not '{ATTESTATION_VERSION}'",
                self.attestation_version
            )));
        }
        if !is_did_web(&self.controller) {
            return Err(invalid(format!(
                "controller '{}' is not a did:web DID",
                self.controller
            )));
        }
        self.identity.validate()?;
        if self.public_key_jwk.algorithm()? != self.algorithm {
            return Err(invalid(format!(
                "algorithm '{}' does not match the public_key_jwk key type",
                self.algorithm
            )));
        }
        if !is_sha256(&self.key_fingerprint)
            || self.public_key_jwk.fingerprint()? != self.key_fingerprint
        {
            return Err(invalid(
                "key_fingerprint is not the fingerprint of public_key_jwk",
            ));
        }
        if self.key_id != keyless_key_id(&self.controller, &self.key_fingerprint)? {
            return Err(invalid(
                "key_id is not <controller>#acdp-kl-<fingerprint hex>",
            ));
        }
        let span = (self.not_after - self.not_before).num_milliseconds();
        if span <= 0 || span > MAX_WINDOW_SECONDS * 1000 {
            return Err(invalid(
                "the window must be non-empty and at most 3600 seconds",
            ));
        }
        if !is_sha256(&self.token_hash) {
            return Err(invalid("token_hash is not a sha256 digest"));
        }
        Ok(())
    }

    /// Check an attestation body against §5.3 and return its metadata:
    /// the body shape (type, `public`, version 1, no lineage or links),
    /// `agent_id` equal to `did:web:` plus the `ctx_id` authority, the
    /// `schema_uri`, `acdp_version` ≥ 0.5.0 and the metadata rules.
    ///
    /// The body's own hash, signature and receipt are the caller's to
    /// verify (§8.1 step 1).
    pub fn from_body(body: &Body) -> Result<Self, AcdpError> {
        if !matches!(&body.context_type, crate::primitives::ContextType::Custom(t) if t == KEY_ATTESTATION_TYPE)
        {
            return Err(invalid(format!("type is not {KEY_ATTESTATION_TYPE}")));
        }
        if body.visibility != crate::primitives::Visibility::Public {
            return Err(invalid("an attestation must be public"));
        }
        if body.version != 1
            || body.supersedes.is_some()
            || !body.data_refs.is_empty()
            || !body.derived_from.is_empty()
        {
            return Err(invalid(
                "an attestation is version 1 with no supersedes, data_refs or derived_from",
            ));
        }
        let registry = acdp_did::authority_to_did_web(body.ctx_id.authority());
        if body.agent_id.as_str() != registry {
            return Err(invalid(format!(
                "agent_id '{}' is not the attesting registry '{registry}' of its ctx_id",
                body.agent_id
            )));
        }
        if body.schema_uri.as_deref() != Some(KEY_ATTESTATION_SCHEMA_URI) {
            return Err(invalid(format!(
                "schema_uri is not {KEY_ATTESTATION_SCHEMA_URI}"
            )));
        }
        if !body.acdp_version.as_deref().is_some_and(at_least_0_5) {
            return Err(invalid("acdp_version must be at least 0.5.0"));
        }
        let metadata = body
            .metadata
            .as_ref()
            .ok_or_else(|| invalid("metadata is missing"))?;
        Self::from_metadata(metadata)
    }

    /// §6.2 / §8.1 step 3: `agent_id`, `signature.key_id` and
    /// `signature.algorithm` match this attestation.
    pub fn binds(&self, agent_id: &AgentDid, signature: &Signature) -> bool {
        agent_id.as_str() == self.controller
            && signature.key_id == self.key_id
            && signature.algorithm == self.algorithm
    }

    /// True when `t` lies in `[not_before, not_after)`.
    pub fn window_contains(&self, t: DateTime<Utc>) -> bool {
        self.not_before <= t && t < self.not_after
    }

    /// The signer this attestation makes of a body (§7).
    pub fn signer(&self) -> KeylessSigner {
        KeylessSigner::Keyless {
            identity: self.identity.clone(),
            org_wide: self.org_wide,
        }
    }
}

// ── §6.2 the body's key_attestation member ─────────────────────────────────

/// A keyless-signed body's `key_attestation` member (§6.2): names the
/// attestation and pins its bytes. Producer-signed (inside the
/// `content_hash`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAttestationRef {
    /// The attestation's `ctx_id`.
    pub ctx_id: CtxId,
    /// The attestation's `content_hash`.
    pub content_hash: ContentHash,
}

impl KeyAttestationRef {
    /// Check the member's identifier patterns.
    pub fn validate(&self) -> Result<(), AcdpError> {
        CtxId::parse(self.ctx_id.as_str())?;
        ContentHash::parse(self.content_hash.as_str())?;
        Ok(())
    }
}

/// The `key_attestation` member name.
pub const KEY_ATTESTATION_FIELD: &str = "key_attestation";

impl Body {
    /// The `key_attestation` member (§6.2), read from the forward-
    /// compatible extension fields where a stored body carries it.
    /// `Ok(None)` when absent; an error when present but malformed.
    pub fn key_attestation(&self) -> Result<Option<KeyAttestationRef>, AcdpError> {
        let Some(raw) = self.extensions.get(KEY_ATTESTATION_FIELD) else {
            return Ok(None);
        };
        let r = KeyAttestationRef::deserialize(raw)
            .map_err(|e| AcdpError::SchemaViolation(format!("key_attestation: {e}")))?;
        r.validate()?;
        Ok(Some(r))
    }
}

/// §6.2: `key_attestation` is present exactly when the signature's key
/// id is keyless. A keyless key id with no member is left to key
/// resolution (`attestation_missing`, §6.3 step 1); the member on a
/// non-keyless key id is a `schema_violation` (kl-003 I).
pub fn check_key_attestation_presence(key_id: &str, present: bool) -> Result<(), AcdpError> {
    if present && !is_keyless_key_id(key_id) {
        return Err(AcdpError::SchemaViolation(format!(
            "key_attestation is present but signature.key_id '{key_id}' is not a keyless key id \
             (RFC-ACDP-0021 §6.2)"
        )));
    }
    Ok(())
}

// ── §5.1 the request and its proof of possession ───────────────────────────

/// The JCS bytes of the `acdp-key-attestation-pop/1` preimage (§5.1),
/// which the ephemeral key signs as `pop`.
pub fn pop_preimage(
    controller: &str,
    registry_did: &str,
    token_hash: &str,
    key_fingerprint: &str,
) -> Result<String, AcdpError> {
    let pre = serde_json::json!({
        "pop_version": POP_VERSION,
        "controller": controller,
        "registry_did": registry_did,
        "token_hash": token_hash,
        "key_fingerprint": key_fingerprint,
    });
    String::from_utf8(acdp_jcs::canonicalize(&pre)?)
        .map_err(|e| AcdpError::Serialization(e.to_string()))
}

/// The body of `POST /key-attestations` (§5.1). Closed. `Debug` never
/// prints the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAttestationRequest {
    /// Always [`REQUEST_VERSION`].
    pub request_version: String,
    /// The controller's `did:web` DID.
    pub controller: String,
    /// The identity descriptor with the token as `proof`.
    pub identity: IdentityDescriptor,
    /// `ed25519` or `ecdsa-p256`.
    pub algorithm: String,
    /// The ephemeral public key.
    pub public_key_jwk: Jwk,
    /// Base64 signature by the ephemeral key over [`pop_preimage`].
    pub pop: String,
    /// The window length asked for, 1 to 3600 seconds (default 600).
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_ttl_seconds: Option<u32>,
}

impl KeyAttestationRequest {
    /// §5.2 step 1: the closed schema plus its patterns. A `did:key`
    /// controller and an X509-SVID are `schema_violation`.
    pub fn validate(&self) -> Result<(), AcdpError> {
        if self.request_version != REQUEST_VERSION {
            return Err(invalid(format!(
                "request_version '{}' is not '{REQUEST_VERSION}'",
                self.request_version
            )));
        }
        if !is_did_web(&self.controller) {
            return Err(invalid(format!(
                "controller '{}' is not a did:web DID",
                self.controller
            )));
        }
        self.identity.validate()?;
        if !matches!(self.algorithm.as_str(), "ed25519" | "ecdsa-p256") {
            return Err(invalid(format!(
                "algorithm '{}' is not supported",
                self.algorithm
            )));
        }
        self.public_key_jwk.algorithm()?;
        let pop_ok = !self.pop.is_empty() && STANDARD.decode(&self.pop).is_ok();
        if !pop_ok {
            return Err(invalid("pop is not base64"));
        }
        if self
            .requested_ttl_seconds
            .is_some_and(|t| t == 0 || i64::from(t) > MAX_WINDOW_SECONDS)
        {
            return Err(invalid("requested_ttl_seconds must be 1 to 3600"));
        }
        Ok(())
    }

    /// `sha256:` + hex SHA-256 of the token.
    pub fn token_hash(&self) -> String {
        token_hash(self.identity.token())
    }

    /// The preimage `pop` signs, for the registry `registry_did`.
    pub fn pop_preimage(&self, registry_did: &str) -> Result<String, AcdpError> {
        pop_preimage(
            &self.controller,
            registry_did,
            &self.token_hash(),
            &self.public_key_jwk.fingerprint()?,
        )
    }

    /// §5.2 step 4: `pop` verifies under `public_key_jwk`.
    pub fn verify_pop(&self, registry_did: &str) -> Result<(), AcdpError> {
        let pre = self.pop_preimage(registry_did)?;
        self.public_key_jwk
            .verify(&self.algorithm, &self.pop, &pre)
            .map_err(|e| KeylessReason::PopInvalid.error(e))
    }
}

// ── §5.4 listing ───────────────────────────────────────────────────────────

/// One item of `GET /key-attestations` (§5.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyAttestationListItem {
    /// The attestation's `ctx_id`.
    pub ctx_id: CtxId,
    /// The attestation's `content_hash`.
    pub content_hash: ContentHash,
    /// Its `acdp-key-attestation/1` metadata, as served: parse it with
    /// [`KeyAttestation::from_metadata`].
    pub metadata: Value,
}

/// A page of `GET /key-attestations` (§5.4), newest first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyAttestationList {
    /// The attestations on this page.
    pub items: Vec<KeyAttestationListItem>,
    /// The cursor of the next page, absent (or null) on the last.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

// ── §13.1 capabilities ─────────────────────────────────────────────────────

/// The capabilities document's `keyless` member (§13.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeylessCapabilities {
    /// OIDC issuers whose tokens the registry verifies.
    pub accepted_oidc_issuers: Vec<String>,
    /// SPIFFE trust domains whose JWT-SVIDs the registry verifies.
    pub accepted_spiffe_trust_domains: Vec<String>,
    /// The longest window the registry mints, 60 to 3600.
    pub max_attestation_ttl_seconds: u32,
}

impl crate::capabilities::CapabilitiesDocument {
    /// The `keyless` member, when the registry advertises one.
    pub fn keyless(&self) -> Result<Option<KeylessCapabilities>, AcdpError> {
        let Some(raw) = self.extensions.get("keyless") else {
            return Ok(None);
        };
        let caps = KeylessCapabilities::deserialize(raw)
            .map_err(|e| AcdpError::SchemaViolation(format!("capabilities.keyless: {e}")))?;
        if !(60..=3600).contains(&caps.max_attestation_ttl_seconds) {
            return Err(AcdpError::SchemaViolation(
                "capabilities.keyless.max_attestation_ttl_seconds must be 60 to 3600".into(),
            ));
        }
        Ok(Some(caps))
    }
}

// ── §7 supersession ────────────────────────────────────────────────────────

/// How a body is signed, for §7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeylessSigner {
    /// A key in the controller's DID document.
    Controller,
    /// A keyless key, with its attestation's identity and `org_wide`.
    Keyless {
        /// The attested identity.
        identity: WorkloadIdentity,
        /// The attestation's `org_wide`.
        org_wide: bool,
    },
}

/// §7: may a body signed by `successor` supersede (or carry a producer
/// lifecycle event on) one signed by `predecessor` under the same
/// `agent_id`? Refused with `keyless_identity_mismatch` otherwise.
pub fn may_supersede(
    predecessor: &KeylessSigner,
    successor: &KeylessSigner,
) -> Result<(), KeylessReason> {
    match (predecessor, successor) {
        (_, KeylessSigner::Controller) => Ok(()),
        (_, KeylessSigner::Keyless { org_wide: true, .. }) => Ok(()),
        (
            KeylessSigner::Keyless { identity: p, .. },
            KeylessSigner::Keyless { identity: s, .. },
        ) if p == s => Ok(()),
        _ => Err(KeylessReason::KeylessIdentityMismatch),
    }
}

// ── §8 the key status of a keyless signature ───────────────────────────────

/// The registry receipt that places a keyless signature, as §8.1 step 4
/// sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptFacts {
    /// The receipt verifies (RFC-ACDP-0010 §8).
    pub verified: bool,
    /// It was issued by the attesting registry.
    pub registry_is_attester: bool,
    /// Its `key_fingerprint` is the attested one.
    pub fingerprint_matches: bool,
    /// Its `created_at`: the only time that places the signature.
    pub created_at: DateTime<Utc>,
}

/// What §8.1 steps 1–8 found, in the form the decision runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeylessFacts {
    /// Step 1: the attestation verifies and meets §5.3.
    pub attestation_valid: bool,
    /// Step 2: the consumer accepts the attesting registry (§11).
    pub attester_accepted: bool,
    /// Step 3: `agent_id`, `key_id` and `algorithm` match.
    pub bindings_ok: bool,
    /// Step 4: the body's receipt, if any.
    pub receipt: Option<ReceiptFacts>,
    /// The attestation window's start (inclusive).
    pub not_before: DateTime<Utc>,
    /// The attestation window's end (exclusive).
    pub not_after: DateTime<Utc>,
    /// Step 6: the signature verifies under the attested key.
    pub signature_valid: bool,
    /// Step 7: the attesting registry retracted the attestation.
    pub retracted: bool,
    /// Step 8: `compromised_since` of every revocation that applies to
    /// the attested fingerprint.
    pub compromised_since: Vec<DateTime<Utc>>,
}

/// §8.1 step 9: the controller's current document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityNow {
    /// It lists the identity.
    Listed,
    /// It does not.
    NotListed,
    /// It could not be fetched.
    Unreachable,
}

/// The three key statuses (§8.2). A keyless key ends in one of them or
/// fails closed; there is no fourth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeylessStatus {
    /// The controller still lists the identity.
    CurrentlyAuthorized,
    /// Receipt-attested: the controller has since removed the identity.
    HistoricallyAuthorized,
    /// Pre-compromise, receipt-attested: a revocation names the key and
    /// the receipt places the signature before `compromised_since`.
    HistoricallyAuthorizedPreCompromise,
}

/// §8.1 steps 1–8 in their fixed order; the first failure decides.
/// `Ok(Some(_))` is the pre-compromise status (step 8 needs no current
/// document); `Ok(None)` means step 9 decides.
pub fn decide_until_identity(f: &KeylessFacts) -> Result<Option<KeylessStatus>, KeylessReason> {
    if !f.attestation_valid {
        return Err(KeylessReason::AttestationInvalid);
    }
    if !f.attester_accepted {
        return Err(KeylessReason::UntrustedAttester);
    }
    if !f.bindings_ok {
        return Err(KeylessReason::AttestationMismatch);
    }
    let r = match &f.receipt {
        Some(r) if r.verified && r.registry_is_attester && r.fingerprint_matches => r,
        _ => return Err(KeylessReason::Unplaceable),
    };
    if !(f.not_before <= r.created_at && r.created_at < f.not_after) {
        return Err(KeylessReason::OutsideAttestationWindow);
    }
    if !f.signature_valid {
        return Err(KeylessReason::InvalidSignature);
    }
    if f.retracted {
        return Err(KeylessReason::AttestationWithdrawn);
    }
    if let Some(t) = f.compromised_since.iter().min() {
        if r.created_at >= *t {
            return Err(KeylessReason::Revoked);
        }
        return Ok(Some(KeylessStatus::HistoricallyAuthorizedPreCompromise));
    }
    Ok(None)
}

/// §8.1 and §8.2: the key status of a keyless signature, or the reason
/// it fails closed.
pub fn classify(
    f: &KeylessFacts,
    identity_now: IdentityNow,
) -> Result<KeylessStatus, KeylessReason> {
    if let Some(status) = decide_until_identity(f)? {
        return Ok(status);
    }
    match identity_now {
        IdentityNow::Listed => Ok(KeylessStatus::CurrentlyAuthorized),
        IdentityNow::NotListed => Ok(KeylessStatus::HistoricallyAuthorized),
        IdentityNow::Unreachable => Err(KeylessReason::ControllerUnreachable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPH_PUB: &str = "34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746";

    fn eph() -> [u8; 32] {
        hex::decode(EPH_PUB).unwrap().try_into().unwrap()
    }

    #[test]
    fn jwk_fingerprint_thumbprint_and_key_id_match_kl_001() {
        let jwk = Jwk::from_ed25519(&eph());
        assert_eq!(jwk.x, "NLTZBDFWy23PC-sKKUm3VZyUDSvLbb6MU6mzAnjjp0Y");
        assert_eq!(
            jwk.fingerprint().unwrap(),
            "sha256:f7b7676c94df7e8fd9998e38f9fff04d8588b00d1801764e3f1877a3feae4477"
        );
        assert_eq!(
            jwk.thumbprint().unwrap(),
            "Gec-ct57Gwltw072qu-aed20Ju93h-m8Qv8yjNgvMOM"
        );
        let id =
            keyless_key_id("did:web:agents.example.com:ci", &jwk.fingerprint().unwrap()).unwrap();
        assert!(is_keyless_key_id(&id));
        assert!(!is_keyless_key_id("did:web:agents.example.com:ci#key-1"));
    }

    #[test]
    fn identity_entries_and_services() {
        let doc: DidDocument = serde_json::from_value(serde_json::json!({
            "id": "did:web:a.example",
            "service": [{
                "id": "did:web:a.example#acdp-keyless",
                "type": "AcdpKeylessSigning",
                "serviceEndpoint": {"identities": [
                    {"type": "oidc", "issuer": "https://issuer.example", "subject": "repo:x"},
                    {"type": "spiffe", "subject": "spiffe://prod.example/sa/p", "org_wide": true},
                    {"type": "x509", "subject": "ignored"},
                    {"type": "oidc", "subject": "missing issuer"}
                ]}
            }]
        }))
        .unwrap();
        let listed = ListedIdentities::of(&doc);
        assert_eq!(listed.entries().len(), 2);
        let spiffe = WorkloadIdentity::Spiffe {
            subject: "spiffe://prod.example/sa/p".into(),
        };
        assert!(listed.find(&spiffe).unwrap().org_wide);
        // Byte-for-byte: no case folding.
        let upper = WorkloadIdentity::Oidc {
            issuer: "https://issuer.example".into(),
            subject: "REPO:x".into(),
        };
        assert!(listed.find(&upper).is_none());

        // Two services authorize nothing.
        let mut two = doc.clone();
        two.services.push(two.services[0].clone());
        assert!(ListedIdentities::of(&two).entries().is_empty());
    }

    #[test]
    fn descriptor_debug_redacts_the_token() {
        let d = IdentityDescriptor::oidc("https://i.example", "s", "aaa.bbb.ccc");
        assert!(!format!("{d:?}").contains("aaa.bbb.ccc"));
        let x509 = IdentityDescriptor::Spiffe {
            subject: "spiffe://prod.example/sa/p".into(),
            svid_type: "x509-svid".into(),
            proof: "aaa.bbb.ccc".into(),
        };
        assert!(x509.validate().is_err());
    }

    #[test]
    fn presence_rule() {
        assert!(check_key_attestation_presence("did:web:a#key-1", true).is_err());
        assert!(check_key_attestation_presence("did:web:a#key-1", false).is_ok());
        assert!(check_key_attestation_presence("did:web:a#acdp-kl-00", true).is_ok());
        // A keyless key id without the member is left to key resolution.
        assert!(check_key_attestation_presence("did:web:a#acdp-kl-00", false).is_ok());
    }
}
