//! Typed external anchors (ACDP 0.5.0, RFC-ACDP-0016) — anc-001..005
//! fixture bindings.
//!
//! anc-004 (the executed content-hash golden vector) lives in
//! `tests/conformance.rs`, alongside the other `can-*`-equivalent
//! golden vectors and their typed round-trip companion. This file
//! covers the four behavioral scenarios, each exercised directly
//! against this crate's actual validation/registry/verification code
//! (not fixture-JSON-driven — RS-8's own scope note treats these as
//! "behavioral," unlike RS-5's rev-002 fixture-matrix requirement):
//!
//! - anc-001 — a well-formed anchor publishes and verifies normally
//!   through an in-process registry (`RegistryServer::publish_verified_did_key`,
//!   no network, no TLS harness needed), and round-trips byte-identically
//!   on retrieval.
//! - anc-002 — a malformed `anchors[].content_hash` is rejected
//!   `schema_violation` at builder/`validate_publish_request` time.
//! - anc-003 — `anchors: []` is rejected `schema_violation` (the
//!   absent-when-empty convention, RFC-ACDP-0016 §4).
//! - anc-005 — a verifier that doesn't recognize the anchor's `scheme`
//!   still verifies the body's signature and `content_hash` normally
//!   (RFC-ACDP-0016 §6).
//!
//! Plus a structural guard (RFC-ACDP-0016 §6, NORMATIVE): no
//! anchor-touching source file in this workspace ever constructs an
//! HTTP client or opens a raw network connection — `anchors[].uri` MUST
//! NOT be dereferenced by any ACDP-level verification code path.

use acdp::crypto::SigningKey;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::types::anchor::AnchorEntry;
use acdp::types::primitives::ContentHash;
use acdp::types::publish::PublishRequest;
use acdp::types::{ContextType, Visibility};

#[cfg(feature = "server")]
fn well_formed_anchor() -> AnchorEntry {
    AnchorEntry {
        scheme: "macp.commitment".into(),
        content_hash: ContentHash::parse(
            "sha256:fa8fe6b9143b469866d31de09b81928cc44d226ed935162cd346ae80d14fd200",
        )
        .unwrap(),
        uri: None,
        extensions: Default::default(),
    }
}

fn anchored_request(anchors: Vec<AnchorEntry>) -> Result<PublishRequest, AcdpError> {
    Producer::new_did_key(SigningKey::from_bytes(&[3u8; 32]))
        .publish_request()
        .acdp_version("0.5.0")
        .title("settlement finalized")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .anchors(anchors)
        .build()
}

/// anc-001 — accept: a body carrying one well-formed `macp.commitment`
/// anchor publishes and verifies normally, and the retrieved body's
/// recomputed `content_hash` (anchors included) matches the stored one.
#[cfg(feature = "server")]
#[test]
fn anc_001_well_formed_anchor_publishes_and_round_trips() {
    use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
    use acdp::types::capabilities::Limits;
    use acdp::types::CapabilitiesDocument;

    let caps = CapabilitiesDocument {
        acdp_version: "0.5.0".into(),
        registry_did: "did:web:registry.example.com".into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: None,
            max_publish_per_minute: None,
            change_retention_seconds: None,
            max_change_filters: None,
            max_changes_page: None,
            max_subscriptions_per_requester: None,
            max_reads_per_minute: None,
            max_anonymous_reads_per_minute: None,
            extensions: Default::default(),
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: false,
        extensions: Default::default(),
    };
    let server = RegistryServer::new(InMemoryStore::new(), caps, "registry.example.com");

    let req = anchored_request(vec![well_formed_anchor()]).expect("well-formed anchor builds");
    let resp = server
        .publish_verified_did_key(&req, None)
        .expect("anc-001: a well-formed anchor MUST be accepted");

    let stored = server
        .store()
        .get(&resp.ctx_id)
        .expect("get")
        .expect("present");
    assert_eq!(
        stored.body.anchors.as_deref(),
        Some([well_formed_anchor()].as_slice()),
        "anc-001: retrieved body must carry anchors byte-identical to what was signed"
    );

    let recomputed =
        acdp::crypto::compute_content_hash(&serde_json::to_value(&stored.body).unwrap())
            .expect("recompute content_hash over the retrieved body");
    assert_eq!(
        recomputed, stored.body.content_hash,
        "anc-001: content_hash recomputed over the retrieved body (anchors included) \
         must match the stored content_hash"
    );
}

/// anc-002 — reject `schema_violation`: an anchor whose `content_hash`
/// does not match the `"sha256:" + 64-lowercase-hex` shape.
#[test]
fn anc_002_malformed_content_hash_rejected() {
    let bad_anchor = AnchorEntry {
        scheme: "macp.commitment".into(),
        // Bypass `ContentHash::parse` deliberately to construct a
        // shape violation the way an untrusted wire payload could.
        content_hash: ContentHash("not-a-valid-hash".into()),
        uri: None,
        extensions: Default::default(),
    };
    match anchored_request(vec![bad_anchor]) {
        Err(AcdpError::SchemaViolation(_)) => {}
        other => panic!(
            "anc-002: a malformed anchor content_hash must be rejected schema_violation, \
             got {other:?}"
        ),
    }
}

/// anc-003 — reject `schema_violation`: `anchors: []`. The field MUST
/// be omitted when there is nothing to anchor, never sent as an empty
/// array (RFC-ACDP-0016 §4).
#[test]
fn anc_003_empty_anchors_array_rejected() {
    match anchored_request(vec![]) {
        Err(AcdpError::SchemaViolation(_)) => {}
        other => panic!("anc-003: anchors:[] must be rejected schema_violation, got {other:?}"),
    }
}

/// anc-005 — a verifier that does not understand an anchor's `scheme`
/// MUST ignore it for resolution purposes while still treating the
/// body as fully verified: core verification never branches on
/// `scheme` at all, so this is true by construction, but pinned here
/// as an explicit behavioral test per RFC-ACDP-0016 §6.
#[test]
fn anc_005_scheme_unaware_verifier_ignores_anchor() {
    use acdp::types::{Body, CtxId, LineageId};

    let unrecognized = AnchorEntry {
        scheme: "a-scheme.this-verifier.does-not-recognize".into(),
        content_hash: ContentHash::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
        uri: None,
        extensions: Default::default(),
    };
    let req = anchored_request(vec![unrecognized.clone()]).expect("well-formed anchor builds");
    let body = Body::from_publish_request(
        &req,
        CtxId("acdp://registry.example.com/11111111-1111-4111-8111-111111111111".into()),
        LineageId(format!("lin:sha256:{}", "b".repeat(64))),
        "registry.example.com",
        chrono::Utc::now(),
    );

    acdp::verify::verify_body_offline(&body)
        .expect("anc-005: an unrecognized anchor scheme must not affect verification");
    assert_eq!(
        body.anchors.as_deref(),
        Some([unrecognized].as_slice()),
        "the anchor must still be retained and re-served byte-exactly"
    );
}

/// RFC-ACDP-0016 §6 (NORMATIVE): `anchors[].uri` MUST NOT be
/// dereferenced by any ACDP-level verification code path. Structural
/// guard: no source file in this workspace's crates/`src` that mentions
/// "anchor" also constructs an HTTP client or opens a raw network
/// connection. If a future change wires up scheme-aware anchor
/// resolution, this test forces that to be a conscious, reviewed
/// decision rather than an accidental dereference of an untrusted
/// producer-supplied URI (the SSRF surface this RFC closes by
/// construction).
#[test]
fn no_anchor_handling_code_constructs_an_http_client() {
    // Fully-qualified only — a bare `Client::new(`/`Client::builder(`
    // would also match this crate's own `RegistryClient::new(...)` doc
    // examples, which have nothing to do with HTTP transport.
    const NETWORK_MARKERS: &[&str] = &[
        "reqwest::Client",
        "hyper::Client",
        "TcpStream::connect",
        "UnixStream::connect",
    ];

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "target" || name == ".git" {
                    continue;
                }
                rs_files(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for root in [manifest_dir.join("src"), manifest_dir.join("crates")] {
        if root.exists() {
            rs_files(&root, &mut files);
        }
    }
    assert!(
        !files.is_empty(),
        "expected to scan at least one source file under src/ or crates/"
    );

    let mut offending = Vec::new();
    for path in files {
        let content = std::fs::read_to_string(&path).unwrap();
        if !content.to_ascii_lowercase().contains("anchor") {
            continue;
        }
        for marker in NETWORK_MARKERS {
            if content.contains(marker) {
                offending.push(format!("{}: contains `{marker}`", path.display()));
            }
        }
    }
    assert!(
        offending.is_empty(),
        "a source file mentioning \"anchor\" also constructs an HTTP client/socket \
         (RFC-ACDP-0016 \u{a7}6 forbids dereferencing anchors[].uri):\n{}",
        offending.join("\n")
    );
}
