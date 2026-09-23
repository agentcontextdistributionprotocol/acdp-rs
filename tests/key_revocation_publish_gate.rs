//! RFC-ACDP-0014 §5 step 2 on the `did:web` publish path (issue #207,
//! Phase 7 of `plans/issues-206-208-bindings-registry-release-gate.md`).
//!
//! `tests/key_revocation.rs` MUST NOT be edited by this file (it is a
//! separate integration-test crate); it already pins §5 step 2 for a
//! `did:key` signer at the parse level
//! (`rev_001_did_key_self_revocation_rejected_at_parse`, via
//! `KeyRevocation::from_body`) and the §4 shape table at the validator
//! level. This file additionally pins, at the `RegistryServer` level:
//!
//! - the new `did:web` hook in `publish_verified_in_tenant`: a resolved
//!   `did:web` signing key whose fingerprint equals the revocation's own
//!   `metadata.revoked_key_fingerprint` is rejected with
//!   `key_not_authorized`, only once `acdp_version >= 0.3.0`;
//! - the positive controls proving the version gate — not a blanket
//!   rejection — is what changes the outcome, and that a genuinely
//!   different signing key is accepted at both versions;
//! - that the `did:key` publish path (`publish_verified_did_key_in_tenant`)
//!   already enforces the identical rule with no code change in this
//!   phase, confirming Phase 5/6's claim that `PublishValidator::validate_post_schema`
//!   covers it for free;
//! - the fail-closed polarity on a malformed `capabilities.acdp_version`,
//!   consistent with Phase 6;
//! - that an ordinary (non-key-revocation) `did:web` publish is
//!   unaffected — no new rejection, no accidental invocation of
//!   `KeyRevocation::from_publish_request` on a body shape it was never
//!   meant to see.

mod common;

use acdp::crypto::{derive_lineage_id, fingerprint_ed25519, SigningKey};
use acdp::did::WebResolver;
use acdp::error::{AcdpError, SupersessionReason};
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, PublishCommitOutcome, RegistryServer, RegistryStore as _};
use acdp::types::capabilities::Limits;
use acdp::types::{
    AgentDid, Body, CapabilitiesDocument, ContextType, CtxId, PublishRequest, Status, Visibility,
};
use axum::{routing::get, Json, Router};
use common::TlsTestServer;
use serde_json::json;

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const PRODUCER_DID: &str = "did:web:localhost:producer";
const COMPROMISED_SINCE: &str = "2026-05-01T00:00:00.000Z";

fn caps_at(version: &str) -> CapabilitiesDocument {
    CapabilitiesDocument {
        acdp_version: version.into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            // Required whenever supports_idempotency_key is true
            // (RFC-ACDP-0007 §3.2), which it is unconditionally below.
            idempotency_key_ttl_seconds: Some(86_400),
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        // Required true once acdp_version >= 0.3.0 (RFC-ACDP-0007 §3.5
        // item 10); harmless at 0.2.0 too, so set unconditionally.
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

fn revocation_request(
    signing_key: SigningKey,
    key_fragment: &str,
    revoked_fingerprint: &str,
) -> PublishRequest {
    Producer::new(
        signing_key,
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#{key_fragment}"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title("Key revocation — test")
    .context_type(ContextType::KeyRevocation)
    .visibility(Visibility::Public)
    .metadata(json!({
        "revoked_key_fingerprint": revoked_fingerprint,
        "compromised_since": COMPROMISED_SINCE,
        "reason": "test compromise",
    }))
    .build()
    .expect("valid revocation publish request")
}

fn analysis_request(signing_key: SigningKey, key_fragment: &str) -> PublishRequest {
    Producer::new(
        signing_key,
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#{key_fragment}"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title("An ordinary context, not a revocation")
    .context_type(ContextType::Analysis)
    .visibility(Visibility::Public)
    .build()
    .expect("valid analysis publish request")
}

/// Build a v2+ **non-revocation** (`ContextType::Analysis`) publish request
/// that `supersedes` an existing ctx_id — used by the Phase 6 (RFC-ACDP-0014
/// §4 `supersedes`-row) tests below to attempt taking over a key-revocation
/// lineage with an ordinary body. `agent_did` is passed explicitly (rather
/// than hardcoded to `PRODUCER_DID` like `revocation_request`/`analysis_request`
/// above) so the same helper builds both the owner's and a hostile
/// non-owner's attempt.
fn analysis_supersede_request(
    signing_key: SigningKey,
    agent_did: &str,
    key_fragment: &str,
    supersedes: CtxId,
    version: u32,
) -> PublishRequest {
    Producer::new(
        signing_key,
        AgentDid::new(agent_did),
        format!("{agent_did}#{key_fragment}"),
    )
    .supersede(supersedes)
    .version(version)
    .acdp_version("0.3.0")
    .title("An ordinary context superseding a key-revocation")
    .context_type(ContextType::Analysis)
    .visibility(Visibility::Public)
    .build()
    .expect("valid analysis-supersedes publish request")
}

/// Serve `PRODUCER_DID`'s DID document (`did:web:localhost:producer` ⇒
/// `/producer/did.json`) over the in-process TLS harness and return a
/// resolver pinned to it.
async fn start_producer_harness(producer_pub: &[u8; 32]) -> (TlsTestServer, WebResolver) {
    let producer_doc = common::ed25519_did_doc(PRODUCER_DID, "key-1", producer_pub);
    let router = Router::new().route(
        "/producer/did.json",
        get(move || {
            let doc = producer_doc.clone();
            async move { Json(doc) }
        }),
    );
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    (tls, resolver)
}

// ── did:web, acceptance criterion 1 + 2 ──────────────────────────────────────

#[tokio::test]
async fn did_web_self_revocation_rejected_at_0_3_0() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = revocation_request(signing_key, "key-1", &fp);
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let err = server
        .publish_verified(&req, None, &resolver)
        .await
        .expect_err("a did:web revocation signed by the very key it revokes must be rejected");
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

#[tokio::test]
async fn did_web_self_revocation_accepted_at_0_2_0() {
    // Positive control for the test above: the identical request,
    // signed by the identical self-revoking key, against a registry
    // that has not turned the §4/§5 gate on yet. Proves the version
    // gate — not some other rejection — is what changed the outcome.
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = revocation_request(signing_key, "key-1", &fp);
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.2.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server
        .publish_verified(&req, None, &resolver)
        .await
        .expect("a 0.2.0 registry has not yet turned the RFC-ACDP-0014 gate on");
}

// ── did:web, acceptance criterion 3 ──────────────────────────────────────────

#[tokio::test]
async fn did_web_different_key_revocation_accepted_at_both_versions() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let other_key_fp =
        fingerprint_ed25519(&SigningKey::from_bytes(&[9u8; 32]).verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    for version in ["0.2.0", "0.3.0"] {
        let req = revocation_request(SigningKey::from_bytes(&[3u8; 32]), "key-1", &other_key_fp);
        let server =
            RegistryServer::try_new(InMemoryStore::new(), caps_at(version), REGISTRY_AUTHORITY)
                .expect("server");

        server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "a revocation signed by a DIFFERENT key must be accepted at {version} \
                 (this is the positive control proving the check isn't rejecting \
                 everything): {e:?}"
                )
            });
    }
}

// ── did:key, acceptance criterion 4 ──────────────────────────────────────────

/// Pins, at the `RegistryServer` level (not just the type-parse level
/// `tests/key_revocation.rs` already covers), that a `did:key` producer
/// "revoking" its own key is rejected by `publish_verified_did_key_in_tenant`
/// — via `PublishValidator::validate_post_schema` ⇒
/// `KeyRevocation::from_publish_request` ⇒ `from_parts`'s did:key
/// sub-case — with NO change from this phase. No network / TLS harness
/// needed: this path is pure and synchronous.
#[test]
fn did_key_self_revocation_rejected_at_registry_server_level() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let producer = Producer::new_did_key(signing_key);

    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("Key revocation — did:key self-revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": fp,
            "compromised_since": COMPROMISED_SINCE,
            "reason": "test compromise",
        }))
        .build()
        .expect("builder does not resolve keys; the publish shape itself is valid");

    let mut caps = caps_at("0.3.0");
    caps.registry_did = REGISTRY_DID.into();
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps, REGISTRY_AUTHORITY).expect("server");

    let err = server
        .publish_verified_did_key(&req, None)
        .expect_err("a did:key revocation signed by the very key it revokes must be rejected");
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

/// Facade-level regression: a bug fixed after issue #295's own fix landed.
/// Narrowing `PublishValidator::validate_post_schema`'s §4 gate to the
/// standard type only (#295) had the side effect of silently dropping the
/// did:key §5-step-2 self-sign sub-check for the §10 interim
/// `acdp:key-revocation` form too — since that sub-check used to run only
/// as a byproduct of full §4 parsing. §5 has no §10 interim-form carve-out
/// (unlike §4), so this must still be rejected. Proves the fix at the
/// `RegistryServer` facade, not just inside `PublishValidator`'s own unit
/// tests — see this file's header for why that distinction matters.
#[test]
fn did_key_interim_self_revocation_rejected_at_registry_server_level() {
    let signing_key = SigningKey::from_bytes(&[6u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let producer = Producer::new_did_key(signing_key);

    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("Key revocation — did:key interim-form self-revocation")
        .context_type(ContextType::Custom(
            ContextType::KEY_REVOCATION_INTERIM.into(),
        ))
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": fp,
            "compromised_since": COMPROMISED_SINCE,
            "reason": "test compromise",
        }))
        .build()
        .expect("builder does not resolve keys; the publish shape itself is valid");

    let mut caps = caps_at("0.3.0");
    caps.registry_did = REGISTRY_DID.into();
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps, REGISTRY_AUTHORITY).expect("server");

    let err = server.publish_verified_did_key(&req, None).expect_err(
        "an interim-form did:key revocation signed by the very key it revokes must \
             still be rejected — §5 step 2 has no §10 interim-form carve-out",
    );
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

// ── fail-closed on a malformed acdp_version ──────────────────────────────────

/// `RegistryServer::try_new`/`try_new_for_test_authority` validate
/// `capabilities.acdp_version` against the schema's semver pattern and
/// would refuse to construct a server with a malformed one at all — so
/// this test uses the unchecked `RegistryServer::new` (as tests
/// elsewhere in this crate use for fixtures with deliberately
/// non-conformant shapes) purely to exercise `key_revocation_gate_applies`'s
/// fail-closed polarity through the did:web hook, matching Phase 6's
/// validator-level coverage of the same predicate.
#[tokio::test]
async fn did_web_self_revocation_rejected_under_malformed_acdp_version() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = revocation_request(signing_key, "key-1", &fp);
    let mut caps = caps_at("0.2.0");
    caps.acdp_version = "0.3x.0".into(); // malformed: not MAJOR.MINOR.PATCH
    let server = RegistryServer::new(InMemoryStore::new(), caps, REGISTRY_AUTHORITY);

    let err = server
        .publish_verified(&req, None, &resolver)
        .await
        .expect_err(
            "a malformed acdp_version must turn the §5 step 2 gate ON, not OFF \
             (fail-closed, matching Phase 6's §4 gate)",
        );
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

// ── non-key-revocation publishes are unaffected ──────────────────────────────

#[tokio::test]
async fn ordinary_publish_unaffected_by_the_new_hook() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = analysis_request(signing_key, "key-1");
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server.publish_verified(&req, None, &resolver).await.expect(
        "an ordinary (non-key-revocation) publish must be unaffected by the new §5 \
         step 2 hook — it is gated on ContextType::is_key_revocation() and must not \
         fire, let alone fail, for any other context type",
    );
}

// ── pinned path (`publish_pinned_verified_in_tenant`) ───────────────────────
//
// This path resolves no DID at all — the caller has already verified the
// signature against `verified_public_key_b64` out of band (e.g. a
// playground registry's pinned-key allowlist) — so unlike the `did:web`
// tests above, none of these need a TLS harness or resolver; they call the
// (synchronous) pinned-publish method directly. Before this phase,
// `fingerprint_pinned_key` only ran when a receipt signer was configured;
// now it also runs whenever `revocation_check_needed` is true, so a
// key-revocation publish on the pinned path gets the same §5 step 2
// enforcement as the did:web and did:key paths above, at no added
// resolution cost (the pinned key is already in hand). None of this was
// tested anywhere before this phase.

/// Encode raw Ed25519 public key bytes the way `publish_pinned_verified_in_tenant`
/// expects them: standard base64, matching `fingerprint_pinned_key`'s decoder.
fn encode_pinned_key(public_key_bytes: &[u8; 32]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(public_key_bytes)
}

#[test]
fn pinned_self_revocation_rejected_at_0_3_0() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let pinned_pub_b64 = encode_pinned_key(&signing_key.verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let err = server
        .publish_pinned_verified_in_tenant(&req, None, None, &pinned_pub_b64, "ed25519")
        .expect_err(
            "a pinned-path revocation signed by the very key it revokes must be \
             rejected, matching the did:web and did:key paths",
        );
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "expected KeyNotAuthorized, got {err:?}"
    );
}

#[test]
fn pinned_self_revocation_accepted_at_0_2_0() {
    // Positive control for the test above: the identical request and
    // pinned key, against a registry that has not turned the §4/§5 gate
    // on yet. Proves the version gate — not some other rejection — is
    // what changes the outcome.
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let pinned_pub_b64 = encode_pinned_key(&signing_key.verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.2.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server
        .publish_pinned_verified_in_tenant(&req, None, None, &pinned_pub_b64, "ed25519")
        .expect("a 0.2.0 registry has not yet turned the RFC-ACDP-0014 gate on");
}

#[test]
fn pinned_different_key_revocation_accepted() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let pinned_pub_b64 = encode_pinned_key(&signing_key.verifying_key_bytes());
    let other_key_fp =
        fingerprint_ed25519(&SigningKey::from_bytes(&[12u8; 32]).verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &other_key_fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    server
        .publish_pinned_verified_in_tenant(&req, None, None, &pinned_pub_b64, "ed25519")
        .unwrap_or_else(|e| {
            panic!(
                "a revocation pinned-signed by a DIFFERENT key must be accepted (this \
                 is the positive control proving the check isn't rejecting \
                 everything): {e:?}"
            )
        });
}

#[test]
fn pinned_malformed_verified_public_key_b64_fails_closed_on_key_revocation() {
    // Pins the new rejection this phase introduced: before this phase,
    // `fingerprint_pinned_key` (and therefore its base64/length
    // validation) only ran when a receipt signer was configured. Now a
    // key-revocation at >= 0.3.0 always fingerprints the pinned key —
    // including validating its shape — so a malformed
    // `verified_public_key_b64` fails the publish instead of silently
    // skipping the check.
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let fp = fingerprint_ed25519(&signing_key.verifying_key_bytes());
    let req = revocation_request(signing_key, "key-1", &fp);

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let err = server
        .publish_pinned_verified_in_tenant(&req, None, None, "not-valid-base64!!!", "ed25519")
        .expect_err(
            "a malformed pinned public key on a key-revocation publish must fail \
             closed, not silently skip the §5 step 2 check",
        );
    assert!(
        matches!(err, AcdpError::KeyResolution(_)),
        "expected KeyResolution (base64 decode failure), got {err:?}"
    );
}

// ── RFC-ACDP-0014 §4 `supersedes`-row enforcement (Phase 6) ──────────────────
//
// Phase 5 (already merged) added `check_revocation_supersession` — the type
// + signer-class rule for what may supersede a `key-revocation` context —
// but nothing called it. This section pins Phase 6's wiring:
// `RegistryServer::commit_via_store` threads a `predecessor_admission` hook
// through `RegistryStore::commit_publish`, gated identically to the §5
// step 2 hook above (`key_revocation_gate_applies(&caps.acdp_version) &&
// req.supersedes.is_some()`), and `InMemoryStore::commit_publish` invokes it
// AFTER producer-continuity, lineage/version coherence, and
// `AlreadySuperseded` — never before.
//
// Every test below builds a v1 key-revocation whose `revoked_key_fingerprint`
// names a DIFFERENT key than the one signing it, specifically so these tests
// exercise ONLY the §4 supersedes-row rule and never trip the unrelated §5
// step 2 self-revocation checks pinned earlier in this file.

/// did:web path (`publish_verified`/`publish_verified_in_tenant`) —
/// acceptance criterion 4, one of the four entry points.
#[tokio::test]
async fn did_web_revocation_superseded_by_non_revocation_rejected_at_0_3_0() {
    let seed = [21u8; 32];
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[22u8; 32]).verifying_key_bytes());
    let (_tls, resolver) =
        start_producer_harness(&SigningKey::from_bytes(&seed).verifying_key_bytes()).await;
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &other_fp);
    let v1 = server
        .publish_verified(&v1_req, None, &resolver)
        .await
        .expect("v1 key-revocation publish must succeed");

    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&seed),
        PRODUCER_DID,
        "key-1",
        v1.ctx_id.clone(),
        2,
    );
    let err = server
        .publish_verified(&v2_req, None, &resolver)
        .await
        .expect_err(
            "RFC-ACDP-0014 §4: a key-revocation context MAY only be superseded by \
             another key-revocation context",
        );
    assert!(
        matches!(err, AcdpError::SchemaViolation(_)),
        "expected SchemaViolation (arm 3), got {err:?}"
    );
}

/// did:key path (`publish_verified_did_key`/`_in_tenant`) — acceptance
/// criterion 4.
#[test]
fn did_key_revocation_superseded_by_non_revocation_rejected_at_0_3_0() {
    let seed = [23u8; 32];
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[24u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = Producer::new_did_key(SigningKey::from_bytes(&seed))
        .publish_request()
        .acdp_version("0.3.0")
        .title("Key revocation — did:key")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": other_fp,
            "compromised_since": COMPROMISED_SINCE,
            "reason": "test compromise",
        }))
        .build()
        .expect("valid revocation publish request");
    let v1 = server
        .publish_verified_did_key(&v1_req, None)
        .expect("v1 key-revocation publish must succeed");

    // Same seed ⇒ same did:key DID ⇒ same owner as v1.
    let v2_req = Producer::new_did_key(SigningKey::from_bytes(&seed))
        .supersede(v1.ctx_id.clone())
        .version(2)
        .acdp_version("0.3.0")
        .title("An ordinary context superseding a key-revocation")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("valid analysis-supersedes publish request");

    let err = server
        .publish_verified_did_key(&v2_req, None)
        .expect_err("RFC-ACDP-0014 §4 arm 3 must reject on the did:key path too");
    assert!(
        matches!(err, AcdpError::SchemaViolation(_)),
        "expected SchemaViolation (arm 3), got {err:?}"
    );
}

/// `publish_unverified_for_tests` — acceptance criterion 4 explicitly calls
/// this one out: issue #207's §5 step 2 wiring left it unhooked, and Phase 6
/// must not repeat that gap, since all four entry points funnel through the
/// same `commit_via_store` construction site.
#[test]
fn unverified_for_tests_revocation_superseded_by_non_revocation_rejected_at_0_3_0() {
    let seed = [25u8; 32];
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[26u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &other_fp);
    let v1 = server
        .publish_unverified_for_tests(&v1_req)
        .expect("v1 key-revocation publish must succeed");

    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&seed),
        PRODUCER_DID,
        "key-1",
        v1.ctx_id.clone(),
        2,
    );
    let err = server.publish_unverified_for_tests(&v2_req).expect_err(
        "RFC-ACDP-0014 §4 arm 3 must reject on publish_unverified_for_tests too — \
         #207 left this entry point unhooked for the §5 step 2 rule",
    );
    assert!(
        matches!(err, AcdpError::SchemaViolation(_)),
        "expected SchemaViolation (arm 3), got {err:?}"
    );
}

/// Pinned path (`publish_pinned_verified_in_tenant`) — acceptance
/// criterion 4.
#[test]
fn pinned_revocation_superseded_by_non_revocation_rejected_at_0_3_0() {
    let seed = [27u8; 32];
    let pinned_pub_b64 = encode_pinned_key(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[28u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &other_fp);
    let v1 = server
        .publish_pinned_verified_in_tenant(&v1_req, None, None, &pinned_pub_b64, "ed25519")
        .expect("v1 key-revocation publish must succeed");

    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&seed),
        PRODUCER_DID,
        "key-1",
        v1.ctx_id.clone(),
        2,
    );
    let err = server
        .publish_pinned_verified_in_tenant(&v2_req, None, None, &pinned_pub_b64, "ed25519")
        .expect_err("RFC-ACDP-0014 §4 arm 3 must reject on the pinned path too");
    assert!(
        matches!(err, AcdpError::SchemaViolation(_)),
        "expected SchemaViolation (arm 3), got {err:?}"
    );
}

/// **The anti-oracle test — acceptance criterion 3, the most important test
/// in this phase.** A non-owner (a completely different DID) attempts to
/// supersede a victim's key-revocation with an ordinary body. If
/// `predecessor_admission` ran BEFORE producer-continuity, this would
/// surface `SchemaViolation` — a live existence-and-type oracle telling any
/// caller "the ctx_id you don't own is a key-revocation". Because
/// `InMemoryStore::commit_publish` invokes the hook only after
/// producer-continuity has already rejected the request, the non-owner
/// instead gets the SAME uniform `SupersededTarget::NotFound` a non-owner
/// gets against any other predecessor type — mirrors
/// `hostile_supersession_by_non_owner_rejected_predecessor_unchanged` in
/// `crates/acdp-server/src/registry/server.rs`.
#[test]
fn hostile_supersession_of_revocation_by_non_owner_rejected_not_schema_violation() {
    let seed = [41u8; 32];
    let owner_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[42u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &owner_fp);
    let v1 = server
        .publish_unverified_for_tests(&v1_req)
        .expect("v1 key-revocation publish must succeed");

    // Attacker: an entirely different DID, publishing a non-revocation v2
    // that names the victim's revocation as its `supersedes`.
    const ATTACKER_DID: &str = "did:web:evil.example.com:attacker";
    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&[43u8; 32]),
        ATTACKER_DID,
        "key-1",
        v1.ctx_id.clone(),
        2,
    );

    let err = server
        .publish_unverified_for_tests(&v2_req)
        .expect_err("a non-owner must never be allowed to supersede another producer's context");
    match err {
        AcdpError::SupersededTarget { reason, .. } => {
            assert_eq!(
                reason,
                SupersessionReason::NotFound,
                "a non-owner must get the uniform NotFound reason, never a \
                 type-revealing one — this is the anti-oracle property"
            );
        }
        other => panic!(
            "expected uniform SupersededTarget::NotFound (anti-oracle), got {other:?} — a \
             SchemaViolation here would leak to a non-owner that the predecessor is a \
             key-revocation"
        ),
    }

    // Predecessor MUST be untouched by the rejected attacker publish.
    let cur = server
        .current(&v1.lineage_id, None)
        .unwrap()
        .expect("predecessor must still be current");
    assert_eq!(cur.body.ctx_id, v1.ctx_id);
    assert_eq!(
        cur.registry_state.status,
        Status::Active,
        "predecessor must remain Active, not disturbed by the rejected attacker publish"
    );
}

/// Positive control for the four entry-point tests above (acceptance
/// criterion 5): the identical request shape, at a registry that has not
/// turned the RFC-ACDP-0014 §4 gate on yet, is ACCEPTED — proving
/// `predecessor_admission` is `None`/skipped below 0.3.0, not merely that
/// something else happened to let it through.
#[test]
fn revocation_superseded_by_non_revocation_accepted_at_0_2_0() {
    let seed = [45u8; 32];
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[46u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.2.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &other_fp);
    let v1 = server
        .publish_unverified_for_tests(&v1_req)
        .expect("v1 key-revocation publish must succeed");

    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&seed),
        PRODUCER_DID,
        "key-1",
        v1.ctx_id.clone(),
        2,
    );
    server.publish_unverified_for_tests(&v2_req).expect(
        "a 0.2.0 registry has not turned the RFC-ACDP-0014 §4 gate on — \
         predecessor_admission must be None and this publish must succeed",
    );
}

/// Fail-closed on a malformed `acdp_version` (acceptance criterion 6),
/// matching Phase 6's `check_revocation_supersession` carry-forward
/// requirement and #207's identical polarity test for §5 step 2 above.
#[test]
fn revocation_superseded_by_non_revocation_rejected_under_malformed_acdp_version() {
    let seed = [47u8; 32];
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[48u8; 32]).verifying_key_bytes());
    let mut caps = caps_at("0.2.0");
    caps.acdp_version = "0.3x.0".into(); // malformed: not MAJOR.MINOR.PATCH
    let server = RegistryServer::new(InMemoryStore::new(), caps, REGISTRY_AUTHORITY);

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &other_fp);
    let v1 = server
        .publish_unverified_for_tests(&v1_req)
        .expect("v1 key-revocation publish must succeed even under a malformed acdp_version");

    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&seed),
        PRODUCER_DID,
        "key-1",
        v1.ctx_id.clone(),
        2,
    );
    let err = server.publish_unverified_for_tests(&v2_req).expect_err(
        "a malformed acdp_version must turn the RFC-ACDP-0014 §4 gate ON, not OFF \
         (fail-closed, matching Phase 6's carry-forward requirement)",
    );
    assert!(
        matches!(err, AcdpError::SchemaViolation(_)),
        "expected SchemaViolation (arm 3), got {err:?}"
    );
}

// ── RFC-ACDP-0014 §4/§10 (0.5.0) registry amendments — rev-003 O/P/Q/R,
// facade level (Phase 6) ──────────────────────────────────────────────────
//
// The supersedes-row tests above pin Arm 3's unconditional rejection at
// 0.3.0/0.2.0 through all four publish entry points; `validator.rs`'s own
// unit test module pins the 0.5.0-specific logic (the new error code, the
// §10 retirement gate, the interim-predecessor case, the same-type positive
// control) directly against `PublishValidator`/`check_revocation_supersession`.
// Neither proves the *facade* (`acdp::registry::RegistryServer`, the surface
// a downstream registry actually calls) carries the 0.5.0 boundary's new
// behavior end to end — this file's own header explains why that matters:
// a unit test inside `acdp-server` passes even if the facade stopped
// re-exporting the right thing. rev-003's A-N/Q obligations predate this
// wave and add no new normative requirement (per the fixture's own
// description), so they are not re-proven here at the facade level too —
// only O/P/Q/R, the genuinely new 0.5.0 logic, get a dedicated facade test.

fn interim_revocation_request(
    signing_key: SigningKey,
    key_fragment: &str,
    revoked_fingerprint: &str,
) -> PublishRequest {
    Producer::new(
        signing_key,
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#{key_fragment}"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title("Key revocation — interim §10 form")
    .context_type(ContextType::Custom(
        ContextType::KEY_REVOCATION_INTERIM.into(),
    ))
    .visibility(Visibility::Public)
    .metadata(json!({
        "revoked_key_fingerprint": revoked_fingerprint,
        "compromised_since": COMPROMISED_SINCE,
        "reason": "test compromise",
    }))
    .build()
    .expect("valid interim-form revocation publish request")
}

/// rev-003 O: a non-revocation supersedes a standard-typed key-revocation
/// target, at a registry advertising acdp_version >= 0.5.0 — the wire code
/// is now `SupersededTarget`/`revocation_type_mismatch`, not the historical
/// `schema_violation` the 0.3.0-boundary tests above pin.
#[test]
fn revocation_superseded_by_non_revocation_rejected_as_revocation_type_mismatch_at_0_5_0() {
    let seed = [61u8; 32];
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[62u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.5.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &other_fp);
    let v1 = server
        .publish_unverified_for_tests(&v1_req)
        .expect("v1 key-revocation publish must succeed");

    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&seed),
        PRODUCER_DID,
        "key-1",
        v1.ctx_id.clone(),
        2,
    );
    let err = server
        .publish_unverified_for_tests(&v2_req)
        .expect_err("a >= 0.5.0 registry must reject a non-revocation supersession");
    assert!(
        matches!(
            err,
            AcdpError::SupersededTarget {
                reason: SupersessionReason::RevocationTypeMismatch,
                ..
            }
        ),
        "expected SupersededTarget/RevocationTypeMismatch, got {err:?}"
    );
}

/// rev-003 P: same as O, but the predecessor is published under the §10
/// interim `acdp:key-revocation` form — `is_key_revocation()` treats it as
/// an equally triggering predecessor type, so this must reject the same way.
///
/// The fixture's own precondition frames this as a predecessor published
/// while the registry advertised BELOW 0.5.0 (interim form still
/// accepted), with the registry having since upgraded to 0.5.0 by the time
/// v2 is attempted — a single fixed-`caps` `RegistryServer` can't model
/// that upgrade directly (and publishing v1 through this 0.5.0 server would
/// itself hit Q's own §10 retirement gate), so v1 is inserted straight into
/// the store, mirroring how the otherwise-unpublishable rev-002 scenario G
/// lineage is constructed in `tests/key_revocation.rs`.
#[test]
fn revocation_interim_predecessor_superseded_by_non_revocation_rejected_at_0_5_0() {
    let seed = [63u8; 32];
    let other_fp = fingerprint_ed25519(&SigningKey::from_bytes(&[64u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.5.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = interim_revocation_request(SigningKey::from_bytes(&seed), "key-1", &other_fp);
    let v1_ctx_id = CtxId("acdp://localhost/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e70".into());
    let v1_lineage_id = derive_lineage_id(&v1_ctx_id);
    let v1_body = Body::from_publish_request(
        &v1_req,
        v1_ctx_id.clone(),
        v1_lineage_id,
        REGISTRY_AUTHORITY,
        chrono::DateTime::parse_from_rfc3339("2026-01-15T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    server
        .store()
        .put(v1_body)
        .expect("v1 interim-form key-revocation insert must succeed");

    let v2_req = analysis_supersede_request(
        SigningKey::from_bytes(&seed),
        PRODUCER_DID,
        "key-1",
        v1_ctx_id.clone(),
        2,
    );
    let err = server
        .publish_unverified_for_tests(&v2_req)
        .expect_err("an interim-typed predecessor must reject a non-revocation successor too");
    assert!(
        matches!(
            err,
            AcdpError::SupersededTarget {
                reason: SupersessionReason::RevocationTypeMismatch,
                ..
            }
        ),
        "expected SupersededTarget/RevocationTypeMismatch, got {err:?}"
    );
}

/// rev-003 Q: a *fresh* (non-superseding) publish under the §10 interim
/// type is rejected outright at a registry advertising acdp_version >=
/// 0.5.0 — the retirement gate, distinct from Arm 3's supersession rule
/// above (no predecessor is involved at all).
#[test]
fn fresh_interim_form_publish_rejected_at_0_5_0() {
    let seed = [65u8; 32];
    let fp = fingerprint_ed25519(&SigningKey::from_bytes(&[66u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.5.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let req = interim_revocation_request(SigningKey::from_bytes(&seed), "key-1", &fp);
    let err = server
        .publish_unverified_for_tests(&req)
        .expect_err("a >= 0.5.0 registry must reject a new interim-form publish outright");
    assert!(
        matches!(err, AcdpError::SchemaViolation(_)),
        "expected SchemaViolation (§10 retirement gate), got {err:?}"
    );
}

/// rev-003 Q's positive control, at exactly 0.4.0 — the current default
/// `ACDP_VERSION` this crate ships with (see `CLAUDE.md`), so this is the
/// specific version a registry gets by not overriding it at all. Q's own
/// fixture text is explicit about the whole `[0.3.0, 0.5.0)` band: "a
/// registry advertising acdp_version in [0.3.0, 0.5.0) MUST NOT reject
/// this publish." Before this test, that band's boundary was only
/// exercised as a raw boolean via `key_revocation_gate_truth_table`
/// (`"0.4.9" -> false` for the §4/§10 gate helpers) — nothing drove an
/// actual publish through the full facade at 0.4.0 to prove the interim
/// form is genuinely *accepted*, not merely "the gate function returns
/// false in isolation." `fresh_interim_form_publish_rejected_at_0_5_0`
/// above only proves the opposite edge (>= 0.5.0 rejects); this is its
/// missing sibling for the accepting side, at the version that matters
/// most because it's the one this crate ships with by default.
#[test]
fn fresh_interim_form_publish_accepted_at_0_4_0() {
    let seed = [69u8; 32];
    let fp = fingerprint_ed25519(&SigningKey::from_bytes(&[70u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.4.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let req = interim_revocation_request(SigningKey::from_bytes(&seed), "key-1", &fp);
    server.publish_unverified_for_tests(&req).expect(
        "a 0.4.0 registry (this crate's shipped default) must accept a fresh interim-form publish",
    );
}

/// rev-003 R: the positive control, at 0.5.0 specifically — a
/// key-revocation properly superseding a key-revocation (same signer
/// class, widening the boundary) is still accepted. Without this, a
/// registry that (incorrectly) rejected every supersession of a
/// key-revocation target once acdp_version >= 0.5.0 — not only
/// non-revocation ones — would pass O/P for the wrong reason.
#[test]
fn revocation_superseded_by_revocation_still_accepted_at_0_5_0() {
    let seed = [67u8; 32];
    let fp = fingerprint_ed25519(&SigningKey::from_bytes(&[68u8; 32]).verifying_key_bytes());
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.5.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let v1_req = revocation_request(SigningKey::from_bytes(&seed), "key-1", &fp);
    let v1 = server
        .publish_unverified_for_tests(&v1_req)
        .expect("v1 key-revocation publish must succeed");

    let v2_req = Producer::new(
        SigningKey::from_bytes(&seed),
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#key-1"),
    )
    .supersede(v1.ctx_id.clone())
    .version(2)
    .acdp_version("0.5.0")
    .title("Key revocation — widened boundary")
    .context_type(ContextType::KeyRevocation)
    .visibility(Visibility::Public)
    .metadata(json!({
        "revoked_key_fingerprint": fp,
        "compromised_since": "2026-04-01T00:00:00.000Z", // earlier — widening
        "reason": "test compromise, corrected",
    }))
    .build()
    .expect("valid v2 key-revocation publish request");

    server.publish_unverified_for_tests(&v2_req).expect(
        "a same-class key-revocation supersession must still be accepted at 0.5.0 — the \
         (0.5.0) rule targets non-revocation successors only",
    );
}

// ── did:web insert-vs-replay (U-564) ─────────────────────────────────────────
//
// The production `did:web` path had NO test on this file's
// `publish_verified_in_tenant` family at all before U-564 — not merely no
// replay test. That matters because it is the branch a real registry serves
// on, and because `commit_via_store` used to flatten
// `PublishCommitOutcome::{Inserted, IdempotentReplay}` into one
// `PublishResponse`, making `201 Created` vs `200 OK` undecidable for the
// front-end. RFC-ACDP-0003's idem-002 requires 200 on a same-hash retry and
// says explicitly NOT 201.
//
// Deliberately sited in this file rather than in `acdp-server`'s unit tests:
// this is a test target of the root `acdp` FACADE package, so it compiles
// against `acdp::registry::…` — the re-export path a downstream registry
// actually consumes — rather than the crate-internal one. If the facade ever
// stopped re-exporting the type or the methods, a unit test inside
// `acdp-server` would still pass and every consumer would still be broken.

/// First publish inserts; the same request with the same `Idempotency-Key`
/// replays. Asserted through the outcome-preserving entry point, on the
/// did:web path, over a live TLS resolver harness.
#[tokio::test]
async fn did_web_publish_reports_inserted_then_idempotent_replay() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = analysis_request(signing_key, "key-1");
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let first = server
        .publish_verified_in_tenant_with_outcome(&req, Some("k-did-web"), &resolver, None)
        .await
        .expect("first did:web publish must succeed");
    assert!(
        !first.is_replay(),
        "a first publish is an insert, not a replay — a registry reading this \
         answers 200 where idem-001 requires 201 Created"
    );
    assert!(matches!(first, PublishCommitOutcome::Inserted(_)));

    let second = server
        .publish_verified_in_tenant_with_outcome(&req, Some("k-did-web"), &resolver, None)
        .await
        .expect("same-hash retry with the same key must succeed");
    assert!(
        second.is_replay(),
        "a same-key same-hash did:web retry is a replay — answering 201 here \
         violates idem-002, which says 200 OK and NOT 201"
    );
    assert!(matches!(second, PublishCommitOutcome::IdempotentReplay(_)));

    // idem-002 also requires the replay to return the ORIGINAL response, so
    // assert identity rather than merely that it replayed.
    assert_eq!(
        first.response().ctx_id,
        second.response().ctx_id,
        "a replay must return the original response verbatim"
    );
}

/// The bare `publish_verified` must keep returning exactly what it returned
/// before U-564 — it is now a delegate two levels down
/// (`publish_verified` → `publish_verified_in_tenant` →
/// `publish_verified_in_tenant_with_outcome`), and this pins that the
/// delegation is lossless on the did:web path rather than assuming it.
///
/// Compared across a replay on one server, not across two inserts: the store
/// assigns a fresh `ctx_id` per insert and derives `lineage_id` from it, so an
/// insert-vs-insert comparison could only check the few request-determined
/// fields — the weakened assertion that passes while the interesting field
/// differs.
#[tokio::test]
async fn did_web_bare_entry_point_matches_its_outcome_twin() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let (_tls, resolver) = start_producer_harness(&signing_key.verifying_key_bytes()).await;

    let req = analysis_request(signing_key, "key-1");
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps_at("0.3.0"), REGISTRY_AUTHORITY)
            .expect("server");

    let via_twin = server
        .publish_verified_in_tenant_with_outcome(&req, Some("k-same"), &resolver, None)
        .await
        .expect("insert")
        .into_response();

    let via_bare = server
        .publish_verified(&req, Some("k-same"), &resolver)
        .await
        .expect("replay through the bare entry point");

    // `PublishResponse` has no `PartialEq`, and hand-picking a subset of
    // fields is how a delegate that drops one goes unnoticed. Compare the
    // serialized form: it is the whole wire surface, which is what this
    // contract is about.
    assert_eq!(
        serde_json::to_value(&via_twin).unwrap(),
        serde_json::to_value(&via_bare).unwrap(),
        "the bare did:web entry point must return the replayed record verbatim"
    );
}
