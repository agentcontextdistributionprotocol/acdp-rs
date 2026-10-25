//! Builders for RFC-ACDP-0017 bundles made of real signed bodies, real
//! registry receipts and real event receipts, from fixed seeds:
//!
//! - did:key producer: the sig-001 seed `[0; 32]` (its did:key is the
//!   `z6MkiTBz…` DID the chain fixtures name; sig-003's `0x42` seed is
//!   `z6MkghLt…`);
//! - did:web producer `did:web:agents.example.com:test-producer`:
//!   `key-1` = the sig-001 seed `[0; 32]`, `key-2` = `0x02 × 32`;
//! - registry `did:web:registry.example.com`, `#receipt-key-1`: the
//!   rcpt-001 seed `0x11 × 32`.
#![allow(dead_code)]

pub mod schema;

use acdp_chain::{ContextEvidence, DidSnapshot, DiscoveryOutcome, DiscoveryRecord, Evidence};
use acdp_crypto::SigningKey;
use acdp_producer::Producer;
use acdp_types::body::Body;
use acdp_types::lifecycle::{LifecycleEvent, LifecycleEventType};
use acdp_types::primitives::{AgentDid, ContextType, CtxId, Visibility};
use acdp_types::receipt::ReceiptSigner;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

pub const T: &str = "2026-10-01T00:00:00.000Z";
pub const REGISTRY: &str = "registry.example.com";
pub const REGISTRY_DID: &str = "did:web:registry.example.com";
pub const WEB_PRODUCER: &str = "did:web:agents.example.com:test-producer";
pub const KEY_PRODUCER: &str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
/// When the bundle observed the registry's DID document: before every
/// receipt in every scenario.
pub const REGISTRY_OBSERVED: &str = "2026-08-01T00:00:00.000Z";

pub const KEY1: [u8; 32] = [0; 32];
pub const KEY2: [u8; 32] = [0x02; 32];
pub const DID_KEY_SEED: [u8; 32] = [0; 32];
pub const REGISTRY_SEED: [u8; 32] = [0x11; 32];

pub fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

pub fn t() -> DateTime<Utc> {
    at(T)
}

/// `acdp://registry.example.com/<l×8>-<l×4>-4<l×3>-8<l×3>-<l×12>`.
pub fn ctx(l: char) -> String {
    let r = |n: usize| l.to_string().repeat(n);
    format!(
        "acdp://{REGISTRY}/{}-{}-4{}-8{}-{}",
        r(8),
        r(4),
        r(3),
        r(3),
        r(12)
    )
}

pub fn fingerprint(seed: &[u8; 32]) -> String {
    acdp_crypto::fingerprint::fingerprint_ed25519(
        &SigningKey::from_bytes(seed).verifying_key_bytes(),
    )
}

/// A producer identity: how it signs and what fingerprint receipts record.
pub struct Signer {
    pub did: String,
    pub seed: [u8; 32],
    pub key_id: String,
}

impl Signer {
    pub fn did_key() -> Self {
        let p = Producer::new_did_key(SigningKey::from_bytes(&DID_KEY_SEED));
        let key_id = p
            .publish_request()
            .title("x")
            .context_type(ContextType::Analysis)
            .build()
            .unwrap()
            .signature
            .key_id;
        assert_eq!(key_id.split_once('#').unwrap().0, KEY_PRODUCER);
        Self {
            did: KEY_PRODUCER.into(),
            seed: DID_KEY_SEED,
            key_id,
        }
    }

    pub fn web(seed: [u8; 32], fragment: &str) -> Self {
        Self {
            did: WEB_PRODUCER.into(),
            seed,
            key_id: format!("{WEB_PRODUCER}#{fragment}"),
        }
    }

    pub fn producer(&self) -> Producer {
        if self.did.starts_with("did:key:") {
            Producer::new_did_key(SigningKey::from_bytes(&self.seed))
        } else {
            Producer::new(
                SigningKey::from_bytes(&self.seed),
                AgentDid::new(&self.did),
                &self.key_id,
            )
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.seed)
    }
}

pub fn registry() -> ReceiptSigner {
    ReceiptSigner::new(
        SigningKey::from_bytes(&REGISTRY_SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap()
}

fn jwk_x(seed: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(SigningKey::from_bytes(seed).verifying_key_bytes())
}

/// A DID document with `methods` (fragment, seed) in
/// `verificationMethod` and `assertion` fragments in `assertionMethod`.
pub fn did_doc(did: &str, methods: &[(&str, [u8; 32])], assertion: &[&str]) -> Map<String, Value> {
    let vms: Vec<Value> = methods
        .iter()
        .map(|(frag, seed)| {
            json!({
                "id": format!("{did}#{frag}"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": jwk_x(seed) }
            })
        })
        .collect();
    let am: Vec<Value> = assertion
        .iter()
        .map(|f| json!(format!("{did}#{f}")))
        .collect();
    let v = json!({ "id": did, "verificationMethod": vms, "assertionMethod": am });
    v.as_object().unwrap().clone()
}

pub fn registry_doc() -> Map<String, Value> {
    did_doc(
        REGISTRY_DID,
        &[("receipt-key-1", REGISTRY_SEED)],
        &["receipt-key-1"],
    )
}

/// A signed body for `id` with `derived_from`, as the registry stores it
/// (created_at = the receipt time).
pub fn body(who: &Signer, id: char, derived: &[char], created_at: &str) -> Body {
    body_with(who, id, derived, created_at, |b| b)
}

pub fn body_with(
    who: &Signer,
    id: char,
    derived: &[char],
    created_at: &str,
    f: impl FnOnce(acdp_producer::RequestBuilder<'_>) -> acdp_producer::RequestBuilder<'_>,
) -> Body {
    let producer = who.producer();
    let builder = producer
        .publish_request()
        .title(format!("Context {}", id.to_ascii_uppercase()))
        .context_type(ContextType::Analysis)
        .derived_from(
            derived
                .iter()
                .map(|c| CtxId::parse(ctx(*c)).unwrap())
                .collect(),
        );
    let req = f(builder).build().unwrap();
    let ctx_id = CtxId::parse(ctx(id)).unwrap();
    let lineage = acdp_crypto::hash::derive_lineage_id(&ctx_id);
    Body::from_publish_request(&req, ctx_id, lineage, REGISTRY, at(created_at))
}

pub fn receipt_for(body: &Body, fp: &str) -> Value {
    serde_json::to_value(
        registry()
            .mint(
                &body.ctx_id,
                &body.lineage_id,
                &body.origin_registry,
                body.created_at,
                &body.content_hash,
                fp,
            )
            .unwrap(),
    )
    .unwrap()
}

/// Context evidence: the body plus a receipt minted at its created_at.
pub fn receipted(who: &Signer, id: char, derived: &[char], created_at: &str) -> ContextEvidence {
    let b = body(who, id, derived, created_at);
    let mut ce = ContextEvidence::new(serde_json::to_value(&b).unwrap());
    ce.registry_receipt = Some(receipt_for(&b, &who.fingerprint()));
    ce
}

/// A producer-signed key revocation of `revoked_seed`, signed by `who`.
pub fn revocation(
    who: &Signer,
    id: char,
    revoked_seed: &[u8; 32],
    compromised_since: &str,
    created_at: &str,
) -> ContextEvidence {
    let b = body_with(who, id, &[], created_at, |r| {
        r.context_type(ContextType::KeyRevocation)
            .visibility(Visibility::Public)
            .metadata(json!({
                "revoked_key_fingerprint": fingerprint(revoked_seed),
                "compromised_since": compromised_since,
            }))
    });
    let mut ce = ContextEvidence::new(serde_json::to_value(&b).unwrap());
    ce.registry_receipt = Some(receipt_for(&b, &who.fingerprint()));
    ce
}

/// A lifecycle event signed by `who` (the producer).
pub fn event(who: &Signer, id: char, n: u8, kind: LifecycleEventType, occurred_at: &str) -> Value {
    let event_id = format!("0000000{n}-0000-4000-8000-{:012}", id as u32);
    let e = LifecycleEvent::new(
        event_id,
        CtxId::parse(ctx(id)).unwrap(),
        kind,
        at(occurred_at),
        AgentDid::new(&who.did),
        None,
    )
    .unwrap()
    .sign_with(SigningKey::from_bytes(&who.seed), &who.key_id)
    .unwrap();
    serde_json::to_value(e).unwrap()
}

pub fn event_receipt(id: char, raw_event: &Value, index: u64, accepted_at: &str) -> Value {
    serde_json::to_value(
        registry()
            .mint_event_receipt(
                &CtxId::parse(ctx(id)).unwrap(),
                raw_event,
                index,
                at(accepted_at),
            )
            .unwrap(),
    )
    .unwrap()
}

pub fn discovery(completed_at: &str) -> DiscoveryRecord {
    DiscoveryRecord::new(REGISTRY, DiscoveryOutcome::NotRevokedComplete, completed_at)
}

/// A bundle with the registry document observed at [`REGISTRY_OBSERVED`].
pub fn bundle() -> Evidence {
    let mut e = Evidence::new();
    e.did_documents = Some(
        [(
            REGISTRY_DID.to_string(),
            vec![DidSnapshot::new(registry_doc(), REGISTRY_OBSERVED)],
        )]
        .into(),
    );
    e
}

pub fn add_snapshot(e: &mut Evidence, did: &str, doc: Map<String, Value>, observed_at: &str) {
    e.did_documents
        .get_or_insert_with(Default::default)
        .entry(did.to_string())
        .or_default()
        .push(DidSnapshot::new(doc, observed_at));
}

pub fn add_discovery(e: &mut Evidence, did: &str, record: DiscoveryRecord) {
    e.revocation_discovery
        .get_or_insert_with(Default::default)
        .entry(did.to_string())
        .or_default()
        .push(record);
}

pub fn put(e: &mut Evidence, id: char, ce: ContextEvidence) {
    e.contexts.insert(ctx(id), ce);
}

/// Round-trip through bytes, as an auditor would receive the bundle.
pub fn reparse(e: &Evidence) -> Evidence {
    Evidence::from_slice(&serde_json::to_vec(e).unwrap()).unwrap()
}
