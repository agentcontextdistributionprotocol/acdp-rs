//! Lifecycle events & retraction (ACDP 0.3, RFC-ACDP-0013) — behavioral
//! bindings for the `lc-001..003` conformance fixtures, plus the §7
//! precedence / §6 alternation / §7.3 tolerance unit coverage.
//!
//! The fixtures are behavioral (they describe endpoint scenarios, not
//! golden bytes), and this SDK has no HTTP layer — the invariants are
//! bound at the [`RegistryServer`] API level, exactly one adapter below
//! the wire: `retract_verified*` / `republish_verified*` are the logical
//! handlers behind `POST /contexts/{ctx_id}/retract|republish`, and
//! [`acdp::registry::parse_lifecycle_request`] is the closed-envelope /
//! `immutable_field` check an HTTP binding runs on the raw request body
//! (fixture `lc-002` — the HTTP status mapping itself lives in the
//! registry repo). Signature-verified paths use `did:key` producers so
//! the full §5 verification pipeline runs offline, without a TLS mock.
//!
//! Fixture JSONs are loaded from the spec checkout (`ACDP_SPEC_DIR`,
//! sibling fallback) and skip gracefully when absent, like
//! `tests/conformance.rs`; `ACDP_REQUIRE_CONFORMANCE=1` makes an absent
//! fixture a hard failure.

use std::path::{Path, PathBuf};

use acdp::crypto::SigningKey;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{
    parse_lifecycle_request, InMemoryStore, LifecycleCommitOutcome, LifecycleEndpoint,
    RegistryServer,
};
use acdp::types::capabilities::Limits;
use acdp::types::lifecycle::{retraction_state, LifecycleEvent, LifecycleEventType};
use acdp::types::receipt::{LineageHeadReceipt, ReceiptSigner};
use acdp::types::{
    AgentDid, CapabilitiesDocument, ContextType, CtxId, SearchParams, Status, Visibility,
};

const REGISTRY_AUTHORITY: &str = "registry.example.com";
const REGISTRY_DID: &str = "did:web:registry.example.com";
const PRODUCER_SEED: [u8; 32] = [9u8; 32];
const STRANGER_SEED: [u8; 32] = [13u8; 32];
const RECEIPT_SEED: [u8; 32] = [0x11u8; 32];

// ── Spec fixture location (same contract as tests/conformance.rs) ────────────

fn spec_root() -> Option<PathBuf> {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR '{}' does not exist",
            p.display()
        );
    } else {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR is not"
        );
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(sibling) = manifest_dir
        .parent()
        .map(|p| p.join("agentcontextdistributionprotocol"))
    {
        if sibling.exists() {
            return Some(sibling);
        }
    }
    assert!(
        !require,
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
    None
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

fn fixture(name: &str) -> Option<serde_json::Value> {
    let root = spec_root()?;
    let path = root.join("schemas/conformance").join(name);
    if !path.exists() {
        assert!(
            std::env::var("ACDP_REQUIRE_CONFORMANCE").is_err(),
            "ACDP_REQUIRE_CONFORMANCE is set but published fixture {} is missing",
            path.display()
        );
        eprintln!("fixture {} not present; skipping", path.display());
        return None;
    }
    Some(read_json(&path))
}

// ── Test registry harness ─────────────────────────────────────────────────────

fn caps() -> CapabilitiesDocument {
    CapabilitiesDocument {
        acdp_version: "0.3.0".into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec![
            "acdp-registry-core".into(),
            "acdp-registry-discovery".into(),
        ],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: Some(86_400),
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        // Required at acdp_version >= 0.3.0 (idem-007).
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

/// A lifecycle-advertising registry (RFC-ACDP-0013 §10).
fn lifecycle_server() -> RegistryServer<InMemoryStore> {
    RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .expect("server")
        .with_lifecycle()
        .expect("lifecycle enabled")
}

fn did_key_producer(seed: &[u8; 32]) -> Producer {
    Producer::new_did_key(SigningKey::from_bytes(seed))
}

fn did_key_identity(seed: &[u8; 32]) -> (AgentDid, String) {
    let key = SigningKey::from_bytes(seed);
    let did = acdp::did::key::did_key_from_ed25519(&key.verifying_key_bytes());
    let key_id = acdp::did::key::did_key_url(&did).expect("did:key URL");
    (AgentDid::new(did), key_id)
}

/// Build a signed lifecycle event for a did:key actor (RFC-ACDP-0013 §5).
fn signed_event(
    seed: &[u8; 32],
    ctx_id: &CtxId,
    event_type: LifecycleEventType,
    event_id: &str,
    reason: Option<&str>,
) -> LifecycleEvent {
    let (actor, key_id) = did_key_identity(seed);
    LifecycleEvent::new(
        event_id,
        ctx_id.clone(),
        event_type,
        chrono::Utc::now(),
        actor,
        reason.map(String::from),
    )
    .expect("valid event")
    .sign_with(SigningKey::from_bytes(seed), key_id)
    .expect("signed event")
}

/// Publish a v1 public context by the [`PRODUCER_SEED`] did:key producer
/// through the RFC-conformant offline pipeline.
fn publish_v1(server: &RegistryServer<InMemoryStore>, title: &str) -> acdp::PublishResponse {
    let req = did_key_producer(&PRODUCER_SEED)
        .publish_request()
        .title(title)
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("valid request");
    server
        .publish_verified_did_key(&req, None)
        .expect("v1 publish accepted")
}

fn search_titles(server: &RegistryServer<InMemoryStore>, params: &SearchParams) -> Vec<String> {
    server
        .search(params, None)
        .expect("search ok")
        .matches
        .into_iter()
        .map(|m| m.title)
        .collect()
}

const EV1: &str = "018f6d0a-0001-4c4d-9e1f-3a5b7c9d1e2f";
const EV2: &str = "018f6d0a-0002-4c4d-9e1f-3a5b7c9d1e2f";
const EV3: &str = "018f6d0a-0003-4c4d-9e1f-3a5b7c9d1e2f";

// ── lc-001 — retraction flow ─────────────────────────────────────────────────

/// lc-001 scenarios A/B/C/F plus the §6 retry-idempotency rule, end to
/// end through the signature-verified did:key pipeline.
#[test]
fn lc_001_retraction_flow() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "golden retraction flow");
    let body_before = serde_json::to_value(
        server
            .retrieve(&v1.ctx_id, None)
            .unwrap()
            .unwrap()
            .body
            .clone(),
    )
    .unwrap();

    // A — retract succeeds and appends the signed event verbatim.
    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        Some("underlying data source found to be fabricated"),
    );
    let after = server
        .retract_verified_did_key(&retract, None)
        .expect("retract accepted");
    assert_eq!(after.registry_state.status, Status::Retracted);
    let events = after.registry_state.lifecycle_events.as_deref().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], retract, "event stored verbatim incl. signature");

    // The stored event still verifies against the actor key (§5) —
    // typed round-trip preserved the signed bytes.
    events[0]
        .verify_signature_with_key(
            Some(&SigningKey::from_bytes(&PRODUCER_SEED).verifying_key_bytes()),
            None,
        )
        .expect("appended event signature verifies");

    // B — mark-not-delete: body retrievable, byte-identical, and the
    // producer signature still verifies (retraction never touches a
    // body byte).
    let ctx = server.retrieve(&v1.ctx_id, None).unwrap().expect("200");
    assert_eq!(ctx.registry_state.status, Status::Retracted);
    assert_eq!(serde_json::to_value(&ctx.body).unwrap(), body_before);
    acdp::verify::verify_body_offline(&ctx.body).expect("body verification unaffected");
    let bare = server
        .retrieve_body(&v1.ctx_id, None)
        .unwrap()
        .expect("body-only endpoint unaffected");
    assert_eq!(serde_json::to_value(&bare).unwrap(), body_before);

    // §6 retry idempotency: byte-identical event_id retry → 200 with
    // current state, nothing appended.
    let replay = server
        .retract_verified_did_key(&retract, None)
        .expect("byte-identical retry is idempotent, not a 409");
    assert_eq!(
        replay
            .registry_state
            .lifecycle_events
            .as_deref()
            .unwrap()
            .len(),
        1,
        "idempotent retry must append nothing"
    );

    // C — double retract (fresh event_id) → invalid_lifecycle_transition,
    // and NO event appended.
    let double = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV2,
        None,
    );
    let err = server.retract_verified_did_key(&double, None).unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidLifecycleTransition(_)),
        "got {err:?}"
    );
    let ctx = server.retrieve(&v1.ctx_id, None).unwrap().unwrap();
    assert_eq!(
        ctx.registry_state
            .lifecycle_events
            .as_deref()
            .unwrap()
            .len(),
        1,
        "rejected transition must not append"
    );

    // F — republish reverses; status re-derives to active; history is
    // append-only and retains BOTH events in order.
    let republish = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Republished,
        EV3,
        None,
    );
    let after = server
        .republish_verified_did_key(&republish, None)
        .expect("republish accepted");
    assert_eq!(after.registry_state.status, Status::Active);
    let events = after.registry_state.lifecycle_events.as_deref().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, LifecycleEventType::Retracted);
    assert_eq!(events[1].event_type, LifecycleEventType::Republished);

    // Spurious second republish → invalid_lifecycle_transition.
    let spurious = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Republished,
        "018f6d0a-0004-4c4d-9e1f-3a5b7c9d1e2f",
        None,
    );
    let err = server
        .republish_verified_did_key(&spurious, None)
        .unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidLifecycleTransition(_)),
        "got {err:?}"
    );
}

/// lc-001 scenarios D/E — the search `status` filter under §7.2/§8.2:
/// a retracted context falls out of the default (`status=active`)
/// search, does NOT match `superseded`/`expired`, and returns under an
/// explicit `status=retracted`; republication restores the default
/// match.
#[test]
fn lc_001_search_exclusion_and_explicit_retracted_filter() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "golden search exclusion");

    assert_eq!(
        search_titles(&server, &SearchParams::default()).len(),
        1,
        "active context surfaces before retraction"
    );

    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    server.retract_verified_did_key(&retract, None).unwrap();

    // D — excluded from the default search and from every other
    // dominated status value.
    assert!(search_titles(&server, &SearchParams::default()).is_empty());
    for dominated in ["superseded", "expired"] {
        assert!(
            search_titles(
                &server,
                &SearchParams {
                    status: Some(dominated.into()),
                    ..Default::default()
                },
            )
            .is_empty(),
            "retracted context must not match status={dominated}"
        );
    }

    // E — explicit status=retracted returns it.
    let hits = search_titles(
        &server,
        &SearchParams {
            status: Some("retracted".into()),
            ..Default::default()
        },
    );
    assert_eq!(hits, vec!["golden search exclusion".to_string()]);

    // F (tail) — republication restores the default match.
    let republish = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Republished,
        EV2,
        None,
    );
    server.republish_verified_did_key(&republish, None).unwrap();
    assert_eq!(search_titles(&server, &SearchParams::default()).len(), 1);
}

// ── lc-002 — immutable_field & endpoint authentication ──────────────────────

/// lc-002 scenarios A/B (envelope level): a lifecycle request carrying
/// a `body` member or a body-field-named member is `immutable_field`,
/// NOT generic `schema_violation` — bound against the fixture's own
/// request bodies.
#[test]
fn lc_002_immutable_field_bound_to_fixture_requests() {
    let Some(fx) = fixture("lc-002-immutable-field.json") else {
        return;
    };
    let scenarios = fx["scenarios"].as_array().expect("scenarios array");

    for (name, expected_code) in [
        ("A — request carries a body member", "immutable_field"),
        (
            "B — request carries a body-field-named member",
            "immutable_field",
        ),
    ] {
        let scenario = scenarios
            .iter()
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("scenario '{name}' present in fixture"));
        assert_eq!(scenario["expected"]["error_code"], expected_code);
        let raw = &scenario["request"]["body"];
        let err = parse_lifecycle_request(raw).unwrap_err();
        assert!(
            matches!(err, AcdpError::ImmutableField(_)),
            "scenario '{name}': expected ImmutableField ('{expected_code}'), got {err:?}"
        );
    }

    // The distinction lc-002 pins: an unknown member NOT naming body
    // content is a plain schema_violation against the closed envelope.
    let mut with_note = fx["scenarios"][0]["request"]["body"].clone();
    with_note.as_object_mut().unwrap().remove("body");
    with_note
        .as_object_mut()
        .unwrap()
        .insert("note".into(), serde_json::json!("hello"));
    let err = parse_lifecycle_request(&with_note).unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    // The lc-001 golden retract request parses cleanly through the
    // envelope layer.
    if let Some(lc1) = fixture("lc-001-retraction-flow.json") {
        let (event, _raw) =
            parse_lifecycle_request(&lc1["input"]["retract_request"]["body"]).expect("lc-001 ok");
        assert_eq!(event.event_type, LifecycleEventType::Retracted);
        assert_eq!(
            event.actor.as_str(),
            "did:web:agents.example.com:test-producer"
        );
    }
}

/// lc-002 scenario C — actor ≠ `body.agent_id` → `not_authorized`
/// (the RFC-ACDP-0003 §3.1 step 3 rule), with visibility checked FIRST
/// so an unauthorized caller never learns existence; scenario D — an
/// unsigned producer event → `schema_violation`.
#[test]
fn lc_002_actor_and_signature_authentication() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "auth failures");

    // C — a different (valid, correctly signed) actor is refused.
    let foreign = signed_event(
        &STRANGER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    let err = server.retract_verified_did_key(&foreign, None).unwrap_err();
    assert!(matches!(err, AcdpError::NotAuthorized(_)), "got {err:?}");

    // D — unsigned producer event → schema_violation (§5: producer
    // events MUST be signed).
    let (actor, _) = did_key_identity(&PRODUCER_SEED);
    let unsigned = LifecycleEvent::new(
        EV2,
        v1.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        actor,
        None,
    )
    .unwrap();
    let err = server
        .retract_verified_did_key(&unsigned, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    // No state changed by any of the failures.
    let ctx = server.retrieve(&v1.ctx_id, None).unwrap().unwrap();
    assert_eq!(ctx.registry_state.status, Status::Active);
    assert!(ctx.registry_state.lifecycle_events.is_none());

    // Visibility is checked FIRST (§6 step 1 / §14): a requester who
    // could not retrieve a private context gets not_found — never a
    // distinguishable not_authorized.
    let private_req = did_key_producer(&PRODUCER_SEED)
        .publish_request()
        .title("private target")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Private)
        .build()
        .unwrap();
    let private = server.publish_verified_did_key(&private_req, None).unwrap();
    let (stranger_did, _) = did_key_identity(&STRANGER_SEED);
    let probe = signed_event(
        &STRANGER_SEED,
        &private.ctx_id,
        LifecycleEventType::Retracted,
        EV3,
        None,
    );
    let err = server
        .retract_verified_did_key(&probe, Some(&stranger_did))
        .unwrap_err();
    assert!(
        matches!(err, AcdpError::NotFound(_)),
        "existence must not leak: expected NotFound, got {err:?}"
    );
}

// ── lc-003 — retracted head & /current ───────────────────────────────────────

/// lc-003 scenarios A/B/C on a plain lifecycle registry: retracting the
/// head takes the lineage off `/current` entirely (no fallback to the
/// superseded v1), the full lineage remains the record, and publishing
/// v3 over the retracted v2 restores a servable head while v2 keeps
/// `retracted` per §7.2 precedence.
#[test]
fn lc_003_retracted_head_current_semantics() {
    let server = lifecycle_server();
    let producer = did_key_producer(&PRODUCER_SEED);
    let v1 = publish_v1(&server, "v1");
    let v2_req = producer
        .supersede(v1.ctx_id.clone())
        .version(2)
        .title("v2")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let v2 = server.publish_verified_did_key(&v2_req, None).unwrap();

    // Precondition: v2 is the head.
    let head = server.current(&v1.lineage_id, None).unwrap().unwrap();
    assert_eq!(head.body.ctx_id, v2.ctx_id);

    // Retract the head.
    let retract = signed_event(
        &PRODUCER_SEED,
        &v2.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    server.retract_verified_did_key(&retract, None).unwrap();

    // A — no eligible head remains: v1 is superseded (retraction does
    // not un-supersede it), v2 is retracted → not_found, no fallback.
    assert!(
        server.current(&v1.lineage_id, None).unwrap().is_none(),
        "retracted head must take the lineage off /current (lc-003 A)"
    );

    // B — the lineage array remains the record, per-version statuses
    // reflecting the §7.2 precedence; v2 stays retrievable.
    let lineage = server.lineage(&v1.lineage_id, None).unwrap();
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage[0].registry_state.status, Status::Superseded);
    assert_eq!(lineage[1].registry_state.status, Status::Retracted);
    assert!(server.retrieve(&v2.ctx_id, None).unwrap().is_some());

    // C — recovery by superseding the retracted head (permitted; every
    // RFC-ACDP-0003 §3.1 constraint unchanged).
    let v3_req = producer
        .supersede(v2.ctx_id.clone())
        .version(3)
        .title("v3")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let v3 = server.publish_verified_did_key(&v3_req, None).unwrap();
    let head = server.current(&v1.lineage_id, None).unwrap().unwrap();
    assert_eq!(head.body.ctx_id, v3.ctx_id);
    assert_eq!(head.registry_state.status, Status::Active);
    // v2 keeps `retracted` — precedence over its new superseded fact.
    let v2_ctx = server.retrieve(&v2.ctx_id, None).unwrap().unwrap();
    assert_eq!(v2_ctx.registry_state.status, Status::Retracted);
}

/// lc-003 scenario D — head-receipt interaction (RFC-ACDP-0011 as
/// amended): no receipt is minted when `/current` is 404 (no head claim
/// to attest), the post-recovery receipt names v3 with an eligible
/// `head_status`, and a receipt can never name a retracted head.
#[test]
fn lc_003_head_receipts_never_name_a_retracted_head() {
    let server = RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .expect("server")
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&RECEIPT_SEED),
                REGISTRY_DID,
                format!("{REGISTRY_DID}#receipt-key-1"),
            )
            .expect("signer"),
        )
        .expect("receipts enabled")
        .with_lineage_head_receipts()
        .expect("head receipts enabled")
        .with_lifecycle()
        .expect("lifecycle enabled");

    let producer = did_key_producer(&PRODUCER_SEED);
    let v1_req = producer
        .publish_request()
        .title("v1")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let v1 = server.publish_verified_did_key(&v1_req, None).unwrap();
    let v2_req = producer
        .supersede(v1.ctx_id.clone())
        .version(2)
        .title("v2")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let v2 = server.publish_verified_did_key(&v2_req, None).unwrap();

    let retract = signed_event(
        &PRODUCER_SEED,
        &v2.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    server.retract_verified_did_key(&retract, None).unwrap();

    // A-side: 404 carries no head claim, so no receipt is minted.
    assert!(server.current(&v1.lineage_id, None).unwrap().is_none());

    // C-side: v3 restores the head; the /current response carries a
    // receipt naming v3 with head_status 'active'.
    let v3_req = producer
        .supersede(v2.ctx_id.clone())
        .version(3)
        .title("v3")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let v3 = server.publish_verified_did_key(&v3_req, None).unwrap();
    let head = server.current(&v1.lineage_id, None).unwrap().unwrap();
    let receipt_value = head.lineage_head_receipt.expect("receipt on /current");
    let receipt = LineageHeadReceipt::from_value(&receipt_value).expect("receipt parses");
    assert_eq!(receipt.head_ctx_id, v3.ctx_id);
    assert_eq!(receipt.head_version, 3);
    assert_eq!(receipt.head_status, "active");

    // The signer refuses to mint for a retracted head outright
    // (RFC-ACDP-0011 §4 as amended by RFC-ACDP-0013 §8.3).
    let signer = ReceiptSigner::new(
        SigningKey::from_bytes(&RECEIPT_SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap();
    assert!(signer
        .mint_lineage_head(
            &v1.lineage_id,
            &v2.ctx_id,
            2,
            &Status::Retracted,
            chrono::Utc::now(),
        )
        .is_err());
}

// ── §7.2 precedence / profile gating / registry-initiated events ────────────

/// §7.2 — `retracted` dominates `expired` (and re-derivation after
/// republish surfaces the dominated fact again).
#[test]
fn precedence_retracted_dominates_expired() {
    let server = lifecycle_server();
    let req = did_key_producer(&PRODUCER_SEED)
        .publish_request()
        .title("already expired")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .expires_at(chrono::Utc::now() - chrono::Duration::hours(1))
        .build()
        .unwrap();
    let v1 = server.publish_verified_did_key(&req, None).unwrap();
    let ctx = server.retrieve(&v1.ctx_id, None).unwrap().unwrap();
    assert_eq!(ctx.registry_state.status, Status::Expired);

    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    let after = server.retract_verified_did_key(&retract, None).unwrap();
    assert_eq!(
        after.registry_state.status,
        Status::Retracted,
        "retracted > expired (RFC-ACDP-0013 §7.2)"
    );

    // Republication removes the retraction from the derivation only:
    // status re-derives to expired, not active.
    let republish = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Republished,
        EV2,
        None,
    );
    let after = server.republish_verified_did_key(&republish, None).unwrap();
    assert_eq!(after.registry_state.status, Status::Expired);
}

/// A registry NOT advertising `acdp-registry-lifecycle` refuses both
/// operations with `not_implemented` (§6) — and never emits
/// `lifecycle_events` or `retracted`.
#[test]
fn non_advertising_registry_returns_not_implemented() {
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY).expect("server"); // no with_lifecycle()
    let v1 = publish_v1(&server, "no lifecycle here");
    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    let err = server.retract_verified_did_key(&retract, None).unwrap_err();
    assert!(matches!(err, AcdpError::NotImplemented(_)), "got {err:?}");
    let err = server
        .republish_verified_did_key(&retract, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::NotImplemented(_)), "got {err:?}");
    assert!(!server
        .capabilities()
        .profiles
        .iter()
        .any(|p| p == "acdp-registry-lifecycle"));
}

/// Registry-initiated events (§6: policy/legal) bypass the producer
/// endpoints: actor MUST be the registry's own DID; the transition and
/// append-only rules apply unchanged.
#[test]
fn registry_initiated_retraction() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "policy takedown");

    // Wrong actor (the producer's DID) through the registry path.
    let (producer_did, _) = did_key_identity(&PRODUCER_SEED);
    let wrong = LifecycleEvent::new(
        EV1,
        v1.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        producer_did,
        None,
    )
    .unwrap();
    let err = server.record_registry_lifecycle_event(&wrong).unwrap_err();
    assert!(matches!(err, AcdpError::NotAuthorized(_)), "got {err:?}");

    // The registry's own DID, unsigned (tolerated without a receipts
    // profile — SHOULD, not MUST, sign).
    let event = LifecycleEvent::new(
        EV2,
        v1.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        AgentDid::new(REGISTRY_DID),
        Some("removed by deployment policy".into()),
    )
    .unwrap();
    let after = server.record_registry_lifecycle_event(&event).unwrap();
    assert_eq!(after.registry_state.status, Status::Retracted);
    // The body stays served — the protocol-visible form of "removed by
    // policy" (docs/data-protection.md §5), never a silent 404.
    assert!(server.retrieve(&v1.ctx_id, None).unwrap().is_some());
}

/// Unknown-event tolerance (§7.3) end to end at the retrieval shape:
/// an unrecognized `event_type` inside `registry_state.lifecycle_events`
/// parses, has no status effect, and re-serializes verbatim — while the
/// §6 endpoints refuse to ACCEPT one.
#[test]
fn unknown_event_type_tolerated_on_read_rejected_on_write() {
    // Read side: a future registry emits an unknown event type.
    let wire = serde_json::json!({
        "status": "active",
        "lifecycle_events": [{
            "event_id": EV1,
            "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
            "event_type": "annotated",
            "occurred_at": "2026-07-04T09:15:42.000Z",
            "actor": "did:web:agents.example.com:test-producer"
        }],
        "some_future_field": {"x": 1}
    });
    let state: acdp::RegistryState = serde_json::from_value(wire.clone()).unwrap();
    assert!(
        !state.is_retracted(),
        "unknown events have no status effect"
    );
    let events = state.lifecycle_events.as_deref().unwrap();
    assert!(!retraction_state(events));
    // Verbatim re-serialization — including the unknown event type AND
    // the unknown registry-state extension field.
    assert_eq!(serde_json::to_value(&state).unwrap(), wire);

    // An event violating the CLOSED object schema is malformed registry
    // state and fails the parse (§7.3).
    let mut bad = wire.clone();
    bad["lifecycle_events"][0]
        .as_object_mut()
        .unwrap()
        .insert("severity".into(), serde_json::json!("high"));
    assert!(serde_json::from_value::<acdp::RegistryState>(bad).is_err());

    // Write side: the endpoints refuse unregistered event types.
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "no free-form events");
    let unknown = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Other("annotated".into()),
        EV2,
        None,
    );
    let err = server.retract_verified_did_key(&unknown, None).unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}

/// Store-contract details of `commit_lifecycle_event`: duplicate
/// `event_id` with different content is `schema_violation`; a rejected
/// transition changes nothing; the append happens at array end.
#[test]
fn store_commit_contract_duplicate_event_ids() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "store contract");
    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        Some("first"),
    );
    server.retract_verified_did_key(&retract, None).unwrap();

    // Same event_id, different content (reason changed, re-signed) —
    // NOT an idempotent retry: schema_violation (§4 uniqueness).
    let conflicting = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        Some("second, different"),
    );
    let err = server
        .retract_verified_did_key(&conflicting, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    // Republish with a REUSED event_id but different content — also
    // schema_violation, before any transition logic.
    let reused = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Republished,
        EV1,
        None,
    );
    let err = server
        .republish_verified_did_key(&reused, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    let ctx = server.retrieve(&v1.ctx_id, None).unwrap().unwrap();
    assert_eq!(
        ctx.registry_state
            .lifecycle_events
            .as_deref()
            .unwrap()
            .len(),
        1
    );
}

/// The lc-001..003 fixture files themselves parse and carry the pinned
/// error codes this implementation maps to.
#[test]
fn lc_fixture_files_parse_and_pin_expected_codes() {
    let Some(lc1) = fixture("lc-001-retraction-flow.json") else {
        return;
    };
    assert_eq!(lc1["id"], "lc-001");
    let scenario_c = lc1["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"].as_str().unwrap().starts_with("C"))
        .unwrap();
    assert_eq!(
        scenario_c["expected"]["error_code"],
        "invalid_lifecycle_transition"
    );
    // The pinned wire code round-trips into the typed variant this
    // implementation raises for the lc-001 C scenario.
    let wire: acdp::WireError = serde_json::from_value(serde_json::json!({
        "error": { "code": "invalid_lifecycle_transition", "message": "x" }
    }))
    .unwrap();
    assert!(matches!(
        AcdpError::from_wire_error(wire),
        AcdpError::InvalidLifecycleTransition(_)
    ));

    if let Some(lc3) = fixture("lc-003-retracted-head.json") {
        assert_eq!(lc3["id"], "lc-003");
        let a = &lc3["scenarios"].as_array().unwrap()[0];
        assert_eq!(a["expected"]["error_code"], "not_found");
    }
}

// ── prove / commit split (#337) ──────────────────────────────────────────────

/// Prove + commit through the split API, returning the post-transition
/// context — the split equivalent of `retract_verified_did_key` /
/// `republish_verified_did_key`.
fn split_did_key(
    server: &RegistryServer<InMemoryStore>,
    event: &LifecycleEvent,
    endpoint: LifecycleEndpoint,
    requester: Option<&AgentDid>,
) -> Result<acdp::types::body::FullContext, AcdpError> {
    let proven = server.prove_lifecycle_identity_did_key(event, endpoint, requester)?;
    server
        .commit_lifecycle_proven(proven)
        .map(LifecycleCommitOutcome::into_context)
}

/// Appended-event count, read as the producer (so private targets count).
fn event_count(server: &RegistryServer<InMemoryStore>, ctx_id: &CtxId) -> usize {
    let (producer, _) = did_key_identity(&PRODUCER_SEED);
    server
        .retrieve(ctx_id, Some(&producer))
        .unwrap()
        .unwrap()
        .registry_state
        .lifecycle_events
        .map_or(0, |e| e.len())
}

/// Registry state with the registry-assigned `ctx_id` (and the signature,
/// which covers it) removed from each event, so two contexts driven
/// through the same sequence on two servers compare equal.
fn normalized(ctx: acdp::types::body::FullContext) -> serde_json::Value {
    let mut state = serde_json::to_value(&ctx.registry_state).unwrap();
    for e in state["lifecycle_events"].as_array_mut().unwrap() {
        let e = e.as_object_mut().unwrap();
        e.remove("ctx_id");
        e.remove("signature");
    }
    state
}

/// The split API yields exactly what the bundled entry points yield, for
/// both endpoints, and reports `Applied` on a fresh append.
#[test]
fn split_did_key_prove_commit_matches_bundled_both_endpoints() {
    let bundled = lifecycle_server();
    let split = lifecycle_server();
    let b = publish_v1(&bundled, "split parity");
    let s = publish_v1(&split, "split parity");

    let at = chrono::Utc::now();
    let (actor, key_id) = did_key_identity(&PRODUCER_SEED);
    let ev = |ctx: &CtxId, ty: LifecycleEventType, id: &str| {
        LifecycleEvent::new(id, ctx.clone(), ty, at, actor.clone(), None)
            .unwrap()
            .sign_with(SigningKey::from_bytes(&PRODUCER_SEED), key_id.clone())
            .unwrap()
    };

    // Retract.
    let rb = ev(&b.ctx_id, LifecycleEventType::Retracted, EV1);
    let rs = ev(&s.ctx_id, LifecycleEventType::Retracted, EV1);
    let via_bundled = bundled.retract_verified_did_key(&rb, None).unwrap();
    let proven = split
        .prove_lifecycle_identity_did_key(&rs, LifecycleEndpoint::Retract, None)
        .unwrap();
    assert_eq!(proven.endpoint(), LifecycleEndpoint::Retract);
    assert_eq!(proven.event(), &rs);
    assert_eq!(proven.actor(), &actor);
    let outcome = split.commit_lifecycle_proven(proven).unwrap();
    assert!(matches!(outcome, LifecycleCommitOutcome::Applied(_)));
    let via_split = outcome.into_context();
    assert_eq!(via_split.registry_state.status, Status::Retracted);
    assert_eq!(normalized(via_bundled), normalized(via_split));

    // Republish.
    let pb = ev(&b.ctx_id, LifecycleEventType::Republished, EV2);
    let ps = ev(&s.ctx_id, LifecycleEventType::Republished, EV2);
    let via_bundled = bundled.republish_verified_did_key(&pb, None).unwrap();
    let via_split = split_did_key(&split, &ps, LifecycleEndpoint::Republish, None).unwrap();
    assert_eq!(via_split.registry_state.status, Status::Active);
    assert_eq!(normalized(via_bundled), normalized(via_split));
}

/// No `ProvenLifecycle` is produced for any request the bundled path
/// would reject before the store — and none of the failures writes.
#[test]
fn prove_lifecycle_identity_produces_no_token_on_failure() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "no token");
    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );

    // Lifecycle disabled on this instance.
    let disabled =
        RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY).unwrap();
    let dv1 = publish_v1(&disabled, "disabled");
    let dev = signed_event(
        &PRODUCER_SEED,
        &dv1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    let err = disabled
        .prove_lifecycle_identity_did_key(&dev, LifecycleEndpoint::Retract, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::NotImplemented(_)), "got {err:?}");

    // Wrong endpoint: a `retracted` event on /republish.
    let err = server
        .prove_lifecycle_identity_did_key(&retract, LifecycleEndpoint::Republish, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    // Actor ≠ producer.
    let foreign = signed_event(
        &STRANGER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV2,
        None,
    );
    let err = server
        .prove_lifecycle_identity_did_key(&foreign, LifecycleEndpoint::Retract, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::NotAuthorized(_)), "got {err:?}");

    // Unsigned producer event.
    let (actor, _) = did_key_identity(&PRODUCER_SEED);
    let unsigned = LifecycleEvent::new(
        EV3,
        v1.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        actor,
        None,
    )
    .unwrap();
    let err = server
        .prove_lifecycle_identity_did_key(&unsigned, LifecycleEndpoint::Retract, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    // Tampered after signing: the signature no longer covers the event.
    let mut tampered = retract.clone();
    tampered.reason = Some("edited after signing".into());
    assert!(server
        .prove_lifecycle_identity_did_key(&tampered, LifecycleEndpoint::Retract, None)
        .is_err());

    // Invisible context: a stranger probing a private context gets
    // not_found, never a token.
    let private_req = did_key_producer(&PRODUCER_SEED)
        .publish_request()
        .title("private target")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Private)
        .build()
        .unwrap();
    let private = server.publish_verified_did_key(&private_req, None).unwrap();
    let (stranger_did, _) = did_key_identity(&STRANGER_SEED);
    let probe = signed_event(
        &STRANGER_SEED,
        &private.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );
    let err = server
        .prove_lifecycle_identity_did_key(&probe, LifecycleEndpoint::Retract, Some(&stranger_did))
        .unwrap_err();
    assert!(matches!(err, AcdpError::NotFound(_)), "got {err:?}");

    // A did:web actor through the did:key prover → key_resolution_failed.
    let web_did = AgentDid::new("did:web:agents.example.com:web-producer");
    let web_key_id = format!("{}#key-1", web_did.as_str());
    let web_producer = Producer::new(
        SigningKey::from_bytes(&PRODUCER_SEED),
        web_did.clone(),
        web_key_id.clone(),
    );
    let web_req = web_producer
        .publish_request()
        .title("did:web target")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let web_ctx = server.publish_unverified_for_tests(&web_req).unwrap();
    let web_event = LifecycleEvent::new(
        EV1,
        web_ctx.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        web_did,
        None,
    )
    .unwrap()
    .sign_with(SigningKey::from_bytes(&PRODUCER_SEED), web_key_id)
    .unwrap();
    let err = server
        .prove_lifecycle_identity_did_key(&web_event, LifecycleEndpoint::Retract, None)
        .unwrap_err();
    assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");

    assert_eq!(event_count(&server, &v1.ctx_id), 0);
    assert_eq!(event_count(&server, &private.ctx_id), 0);
    assert_eq!(event_count(&server, &web_ctx.ctx_id), 0);
}

/// Commit refuses a token proved against a different authority, and a
/// token committed on an instance that has lifecycle disabled.
#[test]
fn commit_lifecycle_proven_rejects_foreign_and_disabled_instances() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "foreign commit");
    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        None,
    );

    let mut other_caps = caps();
    other_caps.registry_did = "did:web:other.example.com".into();
    let other = RegistryServer::try_new(InMemoryStore::new(), other_caps, "other.example.com")
        .unwrap()
        .with_lifecycle()
        .unwrap();
    let proven = server
        .prove_lifecycle_identity_did_key(&retract, LifecycleEndpoint::Retract, None)
        .unwrap();
    let err = other.commit_lifecycle_proven(proven).unwrap_err();
    assert!(matches!(err, AcdpError::RegistryInternal(_)), "got {err:?}");

    // Same authority, lifecycle disabled.
    let disabled =
        RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY).unwrap();
    let proven = server
        .prove_lifecycle_identity_did_key(&retract, LifecycleEndpoint::Retract, None)
        .unwrap();
    let err = disabled.commit_lifecycle_proven(proven).unwrap_err();
    assert!(matches!(err, AcdpError::NotImplemented(_)), "got {err:?}");

    assert_eq!(event_count(&server, &v1.ctx_id), 0);
}

/// Prove never consults alternation or the stored events; the store's
/// locked check at commit is the only authoritative one.
#[test]
fn split_commit_is_the_authoritative_transition_and_replay_check() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "authoritative commit");

    // Two tokens for the same transition, different event_ids: both
    // prove, the second commit is an illegal double retract.
    let first = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        Some("first"),
    );
    let second = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV2,
        None,
    );
    let p1 = server
        .prove_lifecycle_identity_did_key(&first, LifecycleEndpoint::Retract, None)
        .unwrap();
    let p2 = server
        .prove_lifecycle_identity_did_key(&second, LifecycleEndpoint::Retract, None)
        .unwrap();
    assert!(matches!(
        server.commit_lifecycle_proven(p1).unwrap(),
        LifecycleCommitOutcome::Applied(_)
    ));
    let err = server.commit_lifecycle_proven(p2).unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidLifecycleTransition(_)),
        "got {err:?}"
    );

    // Same content proved again after it was appended: prove succeeds
    // (it never touches the store), commit reports IdempotentReplay.
    let again = server
        .prove_lifecycle_identity_did_key(&first, LifecycleEndpoint::Retract, None)
        .expect("prove does not consult stored events");
    match server.commit_lifecycle_proven(again).unwrap() {
        LifecycleCommitOutcome::IdempotentReplay(ctx) => {
            assert_eq!(ctx.registry_state.lifecycle_events.unwrap().len(), 1)
        }
        other => panic!("expected IdempotentReplay, got {other:?}"),
    }

    // Same event_id, different content → schema_violation at commit.
    let conflicting = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        Some("different"),
    );
    let p = server
        .prove_lifecycle_identity_did_key(&conflicting, LifecycleEndpoint::Retract, None)
        .unwrap();
    let err = server.commit_lifecycle_proven(p).unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    assert_eq!(event_count(&server, &v1.ctx_id), 1);
}

/// lc-001 A/C/F and the §6 retry rule driven through the split API.
#[test]
fn lc_001_retraction_flow_through_split_api() {
    let server = lifecycle_server();
    let v1 = publish_v1(&server, "golden retraction flow (split)");

    let retract = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV1,
        Some("underlying data source found to be fabricated"),
    );
    let after = split_did_key(&server, &retract, LifecycleEndpoint::Retract, None).unwrap();
    assert_eq!(after.registry_state.status, Status::Retracted);
    assert_eq!(
        after.registry_state.lifecycle_events.unwrap(),
        vec![retract.clone()]
    );

    let replay = split_did_key(&server, &retract, LifecycleEndpoint::Retract, None)
        .expect("byte-identical retry is idempotent");
    assert_eq!(replay.registry_state.lifecycle_events.unwrap().len(), 1);

    let double = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Retracted,
        EV2,
        None,
    );
    let err = split_did_key(&server, &double, LifecycleEndpoint::Retract, None).unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidLifecycleTransition(_)),
        "got {err:?}"
    );

    let republish = signed_event(
        &PRODUCER_SEED,
        &v1.ctx_id,
        LifecycleEventType::Republished,
        EV3,
        None,
    );
    let after = split_did_key(&server, &republish, LifecycleEndpoint::Republish, None).unwrap();
    assert_eq!(after.registry_state.status, Status::Active);
    let events = after.registry_state.lifecycle_events.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_type, LifecycleEventType::Republished);
}
