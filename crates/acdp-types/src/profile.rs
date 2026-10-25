//! ACDP conformance profiles (RFC-ACDP-0001 §9.1).
//!
//! Implementations declare their profile(s) in the capabilities document
//! `profiles` field. Each profile is a strict superset of its prerequisite.
//!
//! This crate's *consumer-side* claim is [`Profile::Consumer`]: it
//! verifies producer signatures end-to-end, resolves cross-registry
//! references, applies visibility rules client-side, and tolerates
//! unknown fields. The validation and SSRF building blocks
//! (`acdp::registry::PublishValidator`, `acdp::safe_http::SsrfPolicy`)
//! are designed for consumption by `acdp-registry-core` /
//! `acdp-registry-federated` registry implementations built on top.

use crate::capabilities::CapabilitiesDocument;

/// A conformance profile: the RFC-ACDP-0001 §9.1 set plus the receipt
/// profiles added by RFC-ACDP-0010 (0.2.0) and RFC-ACDP-0011 (0.3.0),
/// lifecycle (RFC-ACDP-0013) and retraction recall (RFC-ACDP-0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// `acdp-registry-core` — minimum profile for any registry.
    RegistryCore,
    /// `acdp-registry-discovery` — adds keyword search.
    RegistryDiscovery,
    /// `acdp-registry-federated` — adds cross-registry resolution.
    RegistryFederated,
    /// `acdp-registry-receipts` — mints registry-signed publication
    /// receipts (ACDP 0.2, RFC-ACDP-0010).
    RegistryReceipts,
    /// `acdp-registry-head-receipts` — mints registry-signed
    /// lineage-head receipts on `/current` (ACDP 0.3, RFC-ACDP-0011).
    /// Prerequisite: `acdp-registry-receipts` (same signing key, same
    /// DID-document plumbing, same key lifecycle).
    RegistryHeadReceipts,
    /// `acdp-registry-lifecycle` — lifecycle events & retraction (ACDP
    /// 0.3, RFC-ACDP-0013): the `/retract` + `/republish` endpoints,
    /// §7 status derivation (`retracted` dominating), §8
    /// retrieval/search/`/current` semantics, and the §4.1 append-only
    /// `lifecycle_events` discipline. Prerequisite:
    /// `acdp-registry-core`. Registries NOT advertising it MUST return
    /// `not_implemented` on both endpoints and never emit
    /// `lifecycle_events` or the `retracted` status.
    RegistryLifecycle,
    /// `acdp-registry-changes` — the `GET /changes` feed of
    /// reliance-changing changes (0.5.0 Draft, RFC-ACDP-0018 §3–§6).
    /// Prerequisites: `acdp-registry-lifecycle` and
    /// `acdp-registry-receipts`.
    RegistryChanges,
    /// `acdp-registry-events` — change-hint webhook subscriptions (0.5.0
    /// Draft, RFC-ACDP-0018 §8). Prerequisite: `acdp-registry-changes`.
    RegistryEvents,
    /// `acdp-consumer` — a consumer of contexts (not a registry).
    Consumer,
    /// `acdp-consumer-recall` — a consumer that verifies change entries
    /// before acting on them (0.5.0 Draft, RFC-ACDP-0018 §7).
    /// Prerequisite: `acdp-consumer`.
    ConsumerRecall,
}

impl Profile {
    /// Wire-form identifier as it appears in
    /// `capabilities.profiles` and prose references.
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::RegistryCore => "acdp-registry-core",
            Profile::RegistryDiscovery => "acdp-registry-discovery",
            Profile::RegistryFederated => "acdp-registry-federated",
            Profile::RegistryReceipts => "acdp-registry-receipts",
            Profile::RegistryHeadReceipts => "acdp-registry-head-receipts",
            Profile::RegistryLifecycle => "acdp-registry-lifecycle",
            Profile::RegistryChanges => "acdp-registry-changes",
            Profile::RegistryEvents => "acdp-registry-events",
            Profile::Consumer => "acdp-consumer",
            Profile::ConsumerRecall => "acdp-consumer-recall",
        }
    }
}

/// Profiles that this `acdp` crate is designed to satisfy on the
/// consumer side. A registry implementer building on top of the
/// crate's primitives (`PublishValidator`, `SsrfPolicy`,
/// `CrossRegistryResolver`) MAY claim additional profiles in their
/// own capabilities document.
pub const CLAIMED: &[Profile] = &[Profile::Consumer, Profile::ConsumerRecall];

impl CapabilitiesDocument {
    /// Returns `true` if the registry advertises the given profile.
    pub fn claims_profile(&self, profile: Profile) -> bool {
        self.profiles.iter().any(|p| p == profile.as_str())
    }

    /// Returns `Ok(())` if the registry advertises every profile in
    /// `required`. Returns the first missing profile in
    /// [`acdp_primitives::error::AcdpError::SchemaViolation`] otherwise.
    pub fn supports_required(
        &self,
        required: &[Profile],
    ) -> Result<(), acdp_primitives::error::AcdpError> {
        for p in required {
            if !self.claims_profile(*p) {
                return Err(acdp_primitives::error::AcdpError::SchemaViolation(format!(
                    "registry does not advertise required profile '{}'",
                    p.as_str()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Limits;

    fn caps_with(profiles: Vec<&str>) -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.1.0".into(),
            registry_did: "did:web:r.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: profiles.into_iter().map(String::from).collect(),
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: None,
                max_publish_per_minute: None,
                change_retention_seconds: None,
                max_change_filters: None,
                max_changes_page: None,
                max_subscriptions_per_requester: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads: true,
            supports_idempotency_key: false,
            extensions: Default::default(),
        }
    }

    #[test]
    fn claimed_profile_matches() {
        let caps = caps_with(vec!["acdp-registry-core", "acdp-registry-discovery"]);
        assert!(caps.claims_profile(Profile::RegistryCore));
        assert!(caps.claims_profile(Profile::RegistryDiscovery));
        assert!(!caps.claims_profile(Profile::RegistryFederated));
    }

    #[test]
    fn supports_required_returns_first_missing() {
        let caps = caps_with(vec!["acdp-registry-core"]);
        caps.supports_required(&[Profile::RegistryCore]).unwrap();
        let err = caps
            .supports_required(&[Profile::RegistryCore, Profile::RegistryFederated])
            .unwrap_err();
        match err {
            acdp_primitives::error::AcdpError::SchemaViolation(msg) => {
                assert!(msg.contains("acdp-registry-federated"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn claimed_includes_consumer() {
        assert!(CLAIMED.contains(&Profile::Consumer));
        assert!(CLAIMED.contains(&Profile::ConsumerRecall));
    }
}
