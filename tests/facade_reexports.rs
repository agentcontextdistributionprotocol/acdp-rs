//! Facade surface lock-in.
//!
//! The `acdp` crate is now a thin facade that re-exports the workspace
//! crates (`acdp-primitives`, `acdp-types`, `acdp-crypto`, `acdp-did`,
//! `acdp-validation`, `acdp-verify`, `acdp-producer`, `acdp-client`,
//! `acdp-server`). These tests assert the historical public paths still
//! resolve, so a future change to the re-export plumbing can't silently
//! drop part of the API.

// Module paths preserved across the split.
#[allow(unused_imports)]
use acdp::{
    crypto, did, error, limits, producer, profile, safe_http, time, types, validation, verify,
};

#[test]
fn protocol_constants_are_reexported() {
    assert_eq!(acdp::ACDP_VERSION, "0.4.0");
    assert!(acdp::ACDP_SCHEMA_NAMESPACE.starts_with("https://"));
}

#[test]
fn crate_root_convenience_reexports_resolve() {
    // Types re-exported at the crate root.
    let _t = acdp::ContextType::DataSnapshot;
    let _v = acdp::Visibility::Public;
    let did = acdp::AgentDid::new("did:web:agents.example.com:test");
    assert_eq!(did.as_str(), "did:web:agents.example.com:test");
    // Error vocabulary at the crate root.
    let e = acdp::AcdpError::NotFound("x".into());
    assert!(!e.is_transient());
}

#[test]
fn crypto_module_exposes_low_and_high_level_paths() {
    // Low-level byte verification lives in acdp-crypto, re-exported under
    // crate::crypto and crate::crypto::verify.
    let _f: fn(&[u8; 32], &str, &str) -> Result<(), acdp::AcdpError> = acdp::crypto::verify_ed25519;
    let _g: fn(&[u8; 32], &str, &str) -> Result<(), acdp::AcdpError> =
        acdp::crypto::verify::verify_ed25519;
    // High-level offline verification lives in acdp-verify, re-exported under
    // both crate::verify and (for back-compat) crate::crypto.
    let _h: fn(&acdp::types::body::Body) -> Result<(), acdp::AcdpError> =
        acdp::verify::verify_body_offline;
    let _i: fn(&acdp::types::body::Body) -> Result<(), acdp::AcdpError> =
        acdp::crypto::verify_body_offline;
    // JCS canonicalization re-exported under crate::crypto::jcs.
    let _j: fn(&serde_json::Value) -> Vec<u8> = acdp::crypto::jcs::canonicalize_value;
    // Historical module path acdp::crypto::verify::* must still resolve to
    // both the byte-level and the high-level verifiers.
    let _k: fn(&[u8; 32], &str, &str) -> Result<(), acdp::AcdpError> =
        acdp::crypto::verify::verify_ed25519;
    let _l: fn(&acdp::types::body::Body) -> Result<(), acdp::AcdpError> =
        acdp::crypto::verify::verify_body_offline;
}

#[cfg(feature = "client")]
#[test]
fn historical_verifier_path_resolves() {
    // `acdp::crypto::verify::Verifier` was the only public path to the
    // resolver-backed verifier before the split; keep it working.
    #[allow(unused_imports)]
    use acdp::crypto::verify::Verifier;
}

#[test]
fn producer_round_trip_through_facade() {
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::{ContextType, Visibility};

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let prod = Producer::new(
        key,
        acdp::AgentDid::new("did:web:agents.example.com:test"),
        "did:web:agents.example.com:test#key-1",
    );
    let req = prod
        .publish_request()
        .title("smoke")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("facade producer build");
    assert!(req.content_hash.as_str().starts_with("sha256:"));
}

#[cfg(feature = "client")]
#[test]
fn client_types_reexported() {
    // Compile-time path checks only.
    #[allow(unused_imports)]
    use acdp::client::{CrossRegistryResolver, RegistryClient, VerifiedContext};
    #[allow(unused_imports)]
    use acdp::did::WebResolver;
}

#[cfg(feature = "client")]
#[test]
fn revocation_surface_reexported() {
    // Compile-time path checks only: both `find_revocations` and its
    // §6 registry-attested counterpart resolve through the facade
    // exactly like the rest of the client surface.
    use acdp::client::{
        classify_under_revocation, find_registry_attested_revocations, find_revocations,
        verify_revocation_body, DiscoveryFailurePolicy, DiscoveryOutcome, RevocationDiscovery,
        RevocationPolicy,
    };
    use acdp::types::revocation::{KeyRevocation, RevocationTrustClass};

    // Binding the (async) fn items themselves proves the paths resolve
    // without needing to actually drive them over a live registry.
    let _a = find_revocations;
    let _b = find_registry_attested_revocations;
    let _c = classify_under_revocation;
    let _d = verify_revocation_body;
    let _e: fn(&KeyRevocation, &str, &str) -> Result<(), acdp::AcdpError> =
        KeyRevocation::cross_check_registry_binding;
    let _f = RevocationPolicy::default();
    let _g = RevocationTrustClass::ProducerSigned;

    // issue #248 Phase 2: the auto-discovery policy surface resolves
    // through the facade too. `DiscoveryOutcome` is `#[non_exhaustive]`
    // with no public constructor (nothing produces one yet — Phase 4's
    // job), so a type-position check is all that is available from
    // outside the crate; that's still a genuine compile-time proof that
    // the name resolves through `acdp::client`.
    let _h = RevocationDiscovery::producer_signed_only();
    let _i = RevocationDiscovery::all_trust_classes();
    let _j = DiscoveryFailurePolicy::default();
    fn _discovery_outcome_resolves(o: DiscoveryOutcome) -> DiscoveryOutcome {
        o
    }
}

#[cfg(feature = "client")]
#[test]
fn revocation_cache_reexported() {
    // Issue #257: `RevocationCache` resolves through the facade (the #248
    // discovery-surface precedent, extended), and its `RegistryClient`
    // builder knob compiles — both are the wave's permanent minimized
    // public shape.
    use acdp::client::{RegistryClient, RevocationCache};

    let cache = RevocationCache::new();
    let cache_for_clone = cache.clone();
    let _f: fn(&RegistryClient, RevocationCache) -> RegistryClient =
        RegistryClient::with_revocation_cache;
    drop(cache);
    drop(cache_for_clone);
}

#[cfg(feature = "client")]
#[test]
fn revocation_lineage_walk_reexported() {
    // `acdp::client::find_revocations_in_lineage` resolves through the
    // whole-crate umbrella re-export (`src/lib.rs:107-108`) with no
    // umbrella-level changes of its own — this is the compile-time
    // proof, in the same style as `revocation_surface_reexported`
    // above.
    use acdp::client::find_revocations_in_lineage;

    // Binding the (async) fn item itself proves the path resolves
    // without needing to actually drive it over a live registry.
    let _a = find_revocations_in_lineage;
}

#[cfg(feature = "server")]
#[test]
fn server_types_reexported() {
    #[allow(unused_imports)]
    use acdp::pagination;
    #[allow(unused_imports)]
    use acdp::registry::{InMemoryStore, PublishValidator, RegistryServer};
}
