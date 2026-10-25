//! Concurrency contract tests for the atomic publish commit (SDK-2.4).
//!
//! The `RegistryStore` docs state two safety-critical contracts that only
//! show up under concurrency:
//!
//! 1. **Idempotency atomicity** — the idempotency record and the body
//!    persistence commit atomically, so N concurrent publishes sharing an
//!    `(agent_id, idempotency_key)` mint exactly ONE `ctx_id`
//!    (RFC-ACDP-0003 §6.2.2; the concurrent variant of fixture idem-006).
//! 2. **Supersession serialization** — N concurrent v2 publishes racing
//!    to supersede the same target produce exactly ONE winner; every
//!    loser gets `superseded_target` (RFC-ACDP-0003 §3.1 step 6,
//!    RFC-ACDP-0008 §3.10).
//!
//! Written against the public `RegistryServer` + `RegistryStore` surface
//! (offline did:key publishes — full crypto, no network) so the same
//! scenarios can be replayed against any backend; the registry repo's
//! SQL stores are the second consumer (implementation plan REG-3.3).

#![cfg(feature = "server")]

use std::sync::Arc;

use acdp::crypto::SigningKey;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer};
use acdp::types::capabilities::{CapabilitiesDocument, Limits};
use acdp::types::publish::PublishRequest;
use acdp::types::{ContextType, Visibility};

const THREADS: usize = 16;

fn caps(supports_idempotency_key: bool) -> CapabilitiesDocument {
    CapabilitiesDocument {
        acdp_version: "0.2.0".into(),
        registry_did: "did:web:registry.example.com".into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: if supports_idempotency_key {
                Some(86_400)
            } else {
                None
            },
            max_publish_per_minute: None,
            change_retention_seconds: None,
            max_change_filters: None,
            max_changes_page: None,
            max_subscriptions_per_requester: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key,
        extensions: Default::default(),
    }
}

fn server(supports_idempotency_key: bool) -> Arc<RegistryServer<InMemoryStore>> {
    Arc::new(RegistryServer::new(
        InMemoryStore::new(),
        caps(supports_idempotency_key),
        "registry.example.com",
    ))
}

fn producer(seed: u8) -> Producer {
    Producer::new_did_key(SigningKey::from_bytes(&[seed; 32]))
}

fn request(p: &Producer, title: &str) -> PublishRequest {
    p.publish_request()
        .title(title)
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("valid publish request")
}

/// Race N identical publishes sharing one idempotency key: exactly one
/// context is minted; every thread observes the winner's exact response.
#[test]
fn concurrent_identical_idempotency_key_mints_exactly_one_ctx_id() {
    let server = server(true);
    let p = producer(21);
    let req = request(&p, "idempotent-under-race");

    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let server = Arc::clone(&server);
                let req = req.clone();
                s.spawn(move || server.publish_verified_did_key(&req, Some("contract-key")))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let responses: Vec<_> = results
        .into_iter()
        .map(|r| r.expect("every replay of an identical publish must succeed"))
        .collect();
    let winner = &responses[0];
    for r in &responses {
        assert_eq!(r.ctx_id, winner.ctx_id, "all threads observe one ctx_id");
        assert_eq!(r.lineage_id, winner.lineage_id);
        assert_eq!(r.created_at, winner.created_at, "replay is byte-identical");
        assert_eq!(r.version, winner.version);
    }
    // Exactly one context persisted under the lineage.
    let lineage = server
        .lineage(&winner.lineage_id, None)
        .expect("lineage query");
    assert_eq!(lineage.len(), 1, "exactly one persisted context");
}

/// Without idempotency support, the same N racing publishes all mint
/// distinct contexts — the header is ignored, not half-honored.
#[test]
fn concurrent_publishes_without_idempotency_all_mint_distinct() {
    let server = server(false);
    let p = producer(22);
    let req = request(&p, "no-idem-under-race");

    let responses: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let server = Arc::clone(&server);
                let req = req.clone();
                s.spawn(move || server.publish_verified_did_key(&req, Some("contract-key")))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap().expect("publish succeeds"))
            .collect()
    });

    let mut ctx_ids: Vec<_> = responses.iter().map(|r| r.ctx_id.0.clone()).collect();
    ctx_ids.sort();
    ctx_ids.dedup();
    assert_eq!(
        ctx_ids.len(),
        THREADS,
        "every racing publish mints its own ctx_id when idempotency is unsupported"
    );
}

/// Race N distinct v2 publishes superseding the same v1: exactly one
/// winner; every loser fails with `superseded_target` and the stored
/// lineage is exactly [v1, winning v2].
#[test]
fn concurrent_supersession_has_exactly_one_winner() {
    let server = server(false);
    let p = producer(23);

    let v1_resp = server
        .publish_verified_did_key(&request(&p, "v1"), None)
        .expect("v1 publish");
    let v1_body = server
        .retrieve(&v1_resp.ctx_id, None)
        .expect("retrieve ok")
        .expect("v1 present")
        .body;

    // N DISTINCT v2 requests (different titles → different content
    // hashes), all targeting the same predecessor.
    let v2_reqs: Vec<PublishRequest> = (0..THREADS)
        .map(|i| {
            p.supersede_body(&v1_body)
                .title(format!("v2-candidate-{i}"))
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .build()
                .expect("valid v2 request")
        })
        .collect();

    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = v2_reqs
            .into_iter()
            .map(|req| {
                let server = Arc::clone(&server);
                s.spawn(move || server.publish_verified_did_key(&req, None))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let (winners, losers): (Vec<_>, Vec<_>) = results.into_iter().partition(|r| r.is_ok());
    assert_eq!(winners.len(), 1, "exactly one supersession wins the race");
    for loser in &losers {
        let err = loser.as_ref().unwrap_err();
        assert!(
            matches!(err, acdp::AcdpError::SupersededTarget { .. }),
            "losers MUST fail with superseded_target, got {err:?}"
        );
    }

    let winner = winners.into_iter().next().unwrap().unwrap();
    assert_eq!(winner.version, 2);
    assert_eq!(winner.lineage_id, v1_resp.lineage_id, "same lineage");

    // Lineage is exactly [v1 superseded, winning v2 active].
    let lineage = server
        .lineage(&v1_resp.lineage_id, None)
        .expect("lineage query");
    assert_eq!(lineage.len(), 2, "exactly v1 + the single winning v2");
    assert_eq!(lineage[1].body.ctx_id, winner.ctx_id);
    let current = server
        .current(&v1_resp.lineage_id, None)
        .expect("current query")
        .expect("current exists");
    assert_eq!(current.body.ctx_id, winner.ctx_id);
}
