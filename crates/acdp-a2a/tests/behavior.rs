//! The behavioral fixtures a2a-002..008, as far as they apply to an SDK:
//! the [`Agent`] in front of a wiremock registry, and the holder's §8
//! verification over the a2a-001 body.

mod common;

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use acdp::{
    client::RegistryClient,
    crypto::{canonicalize_value, SigningKey},
    producer::Producer,
    types::{
        primitives::{AgentDid, ContextType, Status, Visibility},
        CtxId,
    },
};
use acdp_a2a::{
    agent::strip_link,
    card::{self, aid_matches_did_key, card_pointer, CardParams},
    hash, inputs,
    link::{self, LINK_KEY},
    parts::normalize_part,
    record::{self, BodyTemplate, Completion, Embedding, RECORD_KEY},
    verify::{verify_offline, CardContext, HeldArtifact, HolderPolicy, TrustedAgents},
    Agent, ArtifactPolicy, ChunkOutput, FailureKind, Salt, TaskSession,
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, Request, Respond, ResponseTemplate,
};

const REGISTRY: &str = "registry.example.com";

fn ctx(n: usize) -> String {
    format!("acdp://{REGISTRY}/00000000-0000-4000-8000-{n:012}")
}

fn cid(n: usize) -> CtxId {
    CtxId::parse(ctx(n)).unwrap()
}

/// A registry that assigns `ctx(1)`, `ctx(2)`, … and echoes the
/// request's version, returning the same `ctx_id` for a repeated
/// Idempotency-Key.
struct Registry {
    n: AtomicUsize,
    seen: std::sync::Mutex<Vec<(String, usize)>>,
}

impl Respond for Registry {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let key = req
            .headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let mut seen = self.seen.lock().unwrap();
        let n = match seen.iter().find(|(k, _)| *k == key) {
            Some((_, n)) => *n,
            None => {
                let n = self.n.fetch_add(1, Ordering::SeqCst) + 1;
                seen.push((key, n));
                n
            }
        };
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        ResponseTemplate::new(201).set_body_json(json!({
            "ctx_id": ctx(n),
            "lineage_id": "lin:sha256:53269327c5284c8d8389e5687a6604e81c64e81587e6518687cb41a7f3ea5647",
            "version": body["version"].as_u64().unwrap_or(1),
            "created_at": "2026-11-06T09:15:42.400Z",
            "status": "active"
        }))
    }
}

async fn registry() -> (MockServer, RegistryClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(Registry {
            n: AtomicUsize::new(0),
            seen: Default::default(),
        })
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    (server, client)
}

fn wire_error(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(json!({ "error": { "code": code, "message": code } }))
}

async fn registry_failing(t: ResponseTemplate) -> (MockServer, RegistryClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(t)
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    (server, client)
}

async fn bodies(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

fn producer() -> Producer {
    Producer::new_did_key(SigningKey::from_bytes(&[0u8; 32]))
}

fn template() -> BodyTemplate {
    let mut t =
        BodyTemplate::new(serde_json::from_value::<ContextType>(json!("analysis")).unwrap());
    t.domain = Some("payments.fraud".into());
    t
}

fn agent(client: RegistryClient) -> Agent {
    Agent::new(producer(), client, "1.0", ArtifactPolicy::new(template()))
        .with_publish_timeout(Duration::from_secs(5))
        .with_max_attempts(2)
}

/// The a2a-001 vector-1 inputs.
fn v1() -> Option<Value> {
    let dir = common::spec_dir()?;
    Some(common::fixture(&dir, "a2a-001-artifact-golden.json")["vectors"][0].clone())
}

fn chunks(v: &Value) -> Vec<Value> {
    v["inputs"]["chunks"].as_array().unwrap().clone()
}

fn session(v: &Value) -> TaskSession {
    TaskSession::new(
        v["inputs"]["task_id"].as_str().unwrap(),
        v["inputs"]["context_id"].as_str().unwrap(),
    )
}

fn chunk(task: &str, ctxid: &str, id: &str, parts: Value, append: bool, last: bool) -> Value {
    json!({
        "taskId": task, "contextId": ctxid, "append": append, "lastChunk": last,
        "artifact": { "artifactId": id, "parts": parts }
    })
}

fn emitted(o: ChunkOutput) -> Value {
    match o {
        ChunkOutput::Emit(c) => c,
        ChunkOutput::Withhold { artifact_id, .. } => panic!("withheld {artifact_id}"),
    }
}

async fn run_task(a: &Agent, s: &mut TaskSession, cs: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for c in cs {
        out.push(emitted(a.on_chunk(s, c.clone()).await.unwrap()));
    }
    out
}

// ---------------------------------------------------------------- a2a-002

#[tokio::test]
async fn a2a_002_a_one_body_per_completed_artifact() {
    let Some(v) = v1() else { return };
    let (reg, client) = registry().await;
    let a = agent(client);
    let mut s = session(&v);
    let cs = chunks(&v);
    let first = emitted(a.on_chunk(&mut s, cs[0].clone()).await.unwrap());
    assert_eq!(first, cs[0], "a pending chunk passes unchanged");
    assert!(bodies(&reg).await.is_empty(), "no body per chunk");
    let last = emitted(a.on_chunk(&mut s, cs[1].clone()).await.unwrap());
    let b = bodies(&reg).await;
    assert_eq!(b.len(), 1);
    assert_eq!(
        b[0]["metadata"][RECORD_KEY]["parts_hash"]
            .as_str()
            .unwrap()
            .len(),
        71
    );
    assert_eq!(last["artifact"]["metadata"][LINK_KEY]["ctx_id"], ctx(1));
    // A later Task snapshot publishes nothing more.
    let task = json!({ "id": s.assembly().task_id(), "status": { "state": "TASK_STATE_COMPLETED" },
        "artifacts": [ v["expected"]["task_snapshot_artifact"].clone() ] });
    let mut snap = task.clone();
    strip_link(&mut snap["artifacts"][0]);
    a.on_task(&mut s, snap).await.unwrap();
    assert_eq!(bodies(&reg).await.len(), 1, "no body per Task");
}

#[tokio::test]
async fn a2a_002_b_completion_by_terminal_state() {
    for (state, publishes) in [
        ("TASK_STATE_INPUT_REQUIRED", false),
        ("TASK_STATE_AUTH_REQUIRED", false),
        ("TASK_STATE_COMPLETED", true),
        ("TASK_STATE_FAILED", true),
        ("TASK_STATE_CANCELED", true),
        ("TASK_STATE_REJECTED", true),
    ] {
        let (reg, client) = registry().await;
        let a = agent(client);
        let mut s = TaskSession::new("t1", "c1");
        let c = chunk(
            "t1",
            "c1",
            "a1",
            json!([{ "text": "partial" }]),
            false,
            false,
        );
        let out = emitted(a.on_chunk(&mut s, c.clone()).await.unwrap());
        assert_eq!(out, c, "{state}: no link on a chunk");
        let task = json!({ "id": "t1", "contextId": "c1", "status": { "state": state },
            "artifacts": [{ "artifactId": "a1", "parts": [{ "text": "partial" }] },
                          { "artifactId": "a2", "parts": [{ "text": "snapshot only" }] }] });
        let got = a.on_task(&mut s, task).await.unwrap().task;
        let n = bodies(&reg).await.len();
        if publishes {
            assert_eq!(n, 2, "{state}");
            for art in got["artifacts"].as_array().unwrap() {
                assert!(art["metadata"][LINK_KEY]["ctx_id"].is_string(), "{state}");
            }
        } else {
            assert_eq!(n, 0, "{state}");
            assert!(got["artifacts"][0].get("metadata").is_none(), "{state}");
        }
    }
}

#[tokio::test]
async fn a2a_002_c_d_re_emission_supersedes() {
    let (reg, client) = registry().await;
    let a = agent(client);
    let mut s = TaskSession::new("t1", "c1");
    let p1 = json!([{ "text": "one" }]);
    let l1 = emitted(
        a.on_chunk(&mut s, chunk("t1", "c1", "a1", p1, false, true))
            .await
            .unwrap(),
    );
    let salt1 = l1["artifact"]["metadata"][LINK_KEY]["salt"].clone();

    // C: append false replaces the parts.
    let p2 = json!([{ "text": "two" }]);
    let l2 = emitted(
        a.on_chunk(&mut s, chunk("t1", "c1", "a1", p2.clone(), false, true))
            .await
            .unwrap(),
    );
    // D: append true covers all parts as now assembled.
    let p3 = json!([{ "text": "three" }]);
    let l3 = emitted(
        a.on_chunk(&mut s, chunk("t1", "c1", "a1", p3, true, true))
            .await
            .unwrap(),
    );

    let b = bodies(&reg).await;
    assert_eq!(b.len(), 3);
    assert_eq!(b[1]["version"], 2);
    assert_eq!(b[1]["supersedes"], ctx(1));
    assert_eq!(b[2]["version"], 3);
    assert_eq!(b[2]["supersedes"], ctx(2));
    for x in &b[1..] {
        assert_eq!(x["agent_id"], b[0]["agent_id"]);
    }
    let link2 = &l2["artifact"]["metadata"][LINK_KEY];
    assert_ne!(link2["salt"], salt1, "fresh salt per body");
    let salt2 = Salt::from_base64url(link2["salt"].as_str().unwrap()).unwrap();
    assert_eq!(
        b[1]["metadata"][RECORD_KEY]["parts_hash"],
        hash::parts_hash(&p2, Some(&salt2))
    );
    let salt3 = Salt::from_base64url(
        l3["artifact"]["metadata"][LINK_KEY]["salt"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let all = json!([{ "text": "two" }, { "text": "three" }]);
    assert_eq!(
        b[2]["metadata"][RECORD_KEY]["parts_hash"],
        hash::parts_hash(&all, Some(&salt3))
    );
}

#[tokio::test]
async fn a2a_002_e_prior_publish_failed_gives_version_1() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(wire_error(400, "schema_violation"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(Registry {
            n: AtomicUsize::new(0),
            seen: Default::default(),
        })
        .mount(&server)
        .await;
    let a = agent(RegistryClient::with_test_transport(&server.uri()).unwrap());
    let mut s = TaskSession::new("t1", "c1");
    let l1 = emitted(
        a.on_chunk(
            &mut s,
            chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true),
        )
        .await
        .unwrap(),
    );
    assert_eq!(l1["artifact"]["metadata"][LINK_KEY]["failed"], true);
    a.on_chunk(
        &mut s,
        chunk("t1", "c1", "a1", json!([{ "text": "y" }]), false, true),
    )
    .await
    .unwrap();
    let b = bodies(&server).await;
    assert_eq!(b[1]["version"], 1);
    assert!(b[1]["supersedes"].is_null());

    // already_superseded (wire superseded_target) is a publish failure.
    let (_r, client) = registry_failing(wire_error(409, "superseded_target")).await;
    let a = agent(client);
    let mut s = TaskSession::new("t1", "c1");
    let out = emitted(
        a.on_chunk(
            &mut s,
            chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true),
        )
        .await
        .unwrap(),
    );
    assert_eq!(out["artifact"]["metadata"][LINK_KEY]["failed"], true);
}

#[tokio::test]
async fn a2a_002_f_continuation_in_a_new_task() {
    let (reg, client) = registry().await;
    let a = agent(client).with_salt_source(Salt::random);
    let mut s1 = TaskSession::new("t1", "c1");
    a.on_chunk(
        &mut s1,
        chunk("t1", "c1", "a1", json!([{ "text": "v1" }]), false, true),
    )
    .await
    .unwrap();
    let earlier = s1.published("a1").unwrap().ctx_id.clone();

    let mut s2 = TaskSession::new("t2", "c1");
    s2.observe_client_message(&json!({ "metadata": { "io.acdp/inputs": [ctx(77)] } }));
    s2.mark_inputs_verified([cid(77)]);
    s2.hints_mut("a1").continues = Some(earlier.clone());
    a.on_chunk(
        &mut s2,
        chunk("t2", "c1", "a1", json!([{ "text": "v2" }]), false, true),
    )
    .await
    .unwrap();
    let b = bodies(&reg).await;
    assert_eq!(b[1]["version"], 1, "never supersedes across tasks");
    assert!(b[1]["supersedes"].is_null());
    assert_eq!(b[1]["derived_from"], json!([earlier.as_str(), ctx(77)]));
}

#[tokio::test]
async fn a2a_002_g_snapshots_agree() {
    let Some(v) = v1() else { return };
    let (_reg, client) = registry().await;
    let a = agent(client);
    let mut s = session(&v);
    let last = run_task(&a, &mut s, &chunks(&v)).await.pop().unwrap();
    let task = json!({ "id": s.assembly().task_id(), "status": { "state": "TASK_STATE_WORKING" },
        "artifacts": [{ "artifactId": "fraud-summary", "parts": [] }] });
    for _ in 0..2 {
        let got = a.on_task(&mut s, task.clone()).await.unwrap().task;
        let art = &got["artifacts"][0];
        assert_eq!(art["parts"], v["expected"]["assembled_parts"]);
        assert_eq!(
            art["metadata"][LINK_KEY],
            last["artifact"]["metadata"][LINK_KEY]
        );
    }
}

#[tokio::test]
async fn a2a_002_h_not_the_agents_artifact() {
    let (reg, client) = registry().await;
    let a = agent(client);
    let mut s = TaskSession::new("t1", "c1");
    s.hints_mut("relayed").relayed = true;
    let c = chunk("t1", "c1", "relayed", json!([{ "text": "x" }]), false, true);
    assert_eq!(emitted(a.on_chunk(&mut s, c.clone()).await.unwrap()), c);
    let mut u = chunk("t1", "c1", "user", json!([{ "text": "x" }]), false, true);
    u["artifact"]["role"] = "ROLE_USER".into();
    assert_eq!(emitted(a.on_chunk(&mut s, u.clone()).await.unwrap()), u);
    assert!(bodies(&reg).await.is_empty());
}

#[test]
fn a2a_002_labels_survive_an_append_false_restart() {
    // Spec #134, §4.2: append false replaces the parts, not the labels.
    let mut asm = acdp_a2a::assembly::TaskAssembly::new("t1", "c1");
    let mut c = chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, false);
    c["artifact"]["name"] = "Report".into();
    c["artifact"]["description"] = "Q3".into();
    asm.ingest_chunk(&c).unwrap();
    asm.ingest_chunk(&chunk(
        "t1",
        "c1",
        "a1",
        json!([{ "text": "y" }]),
        false,
        true,
    ))
    .unwrap();
    let art = asm.artifact("a1").unwrap();
    assert_eq!(art.name.as_deref(), Some("Report"));
    assert_eq!(art.description.as_deref(), Some("Q3"));
    assert_eq!(art.parts, vec![json!({ "text": "y" })]);
    let mut c = chunk("t1", "c1", "a1", json!([{ "text": "z" }]), false, true);
    c["artifact"]["name"] = "Report v2".into();
    asm.ingest_chunk(&c).unwrap();
    assert_eq!(
        asm.artifact("a1").unwrap().name.as_deref(),
        Some("Report v2")
    );
}

// ---------------------------------------------------------------- a2a-003

fn did() -> AgentDid {
    let a = art(json!([{ "text": "x" }]));
    prep(&a, &template(), &Embedding::Never)
        .unwrap()
        .request
        .agent_id
}

#[test]
fn a2a_003_a_d_f_card_pointer() {
    let p = CardParams {
        registry: REGISTRY.into(),
        agent_id: did(),
    };
    let ext = card::card_extension(&p, None);
    assert_eq!(ext["uri"], card::EXTENSION_URI);
    assert_eq!(ext["required"], false);
    assert_eq!(
        ext["params"],
        json!({ "registry": REGISTRY, "agentId": did().as_str() })
    );
    // D: coexistence with AITP, byte comparison of the URI.
    let aitp = json!({ "uri": card::AITP_EXTENSION_URI, "params": { "aid": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik" } });
    let mut near = ext.clone();
    near["uri"] = format!("{}/", card::EXTENSION_URI).into();
    assert_eq!(card_pointer(&[aitp.clone(), ext.clone()]), Some(p.clone()));
    assert_eq!(card_pointer(&[aitp.clone(), near]), None);
    // F: a holder ignores `required` when deciding trust.
    let mut req = ext.clone();
    req["required"] = true.into();
    assert_eq!(card_pointer(&[req]), Some(p));
}

#[test]
fn a2a_003_c_aitp_key_binding() {
    let k = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
    assert!(aid_matches_did_key(&format!("aid:pubkey:{k}"), &did()));
    assert!(aid_matches_did_key(
        &format!("aid:pubkey:ed25519:{k}"),
        &did()
    ));
    let other =
        AgentDid::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    assert!(!aid_matches_did_key(&format!("aid:pubkey:{k}"), &other));
    assert!(!aid_matches_did_key(
        "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &did()
    ));
}

/// The a2a-001 vector-1 holder setup.
struct Held {
    body: Value,
    artifact: Value,
    exts: Vec<Value>,
}

fn held_v1() -> Option<Held> {
    let v = v1()?;
    let mut body = v["expected"]["publish_request_body"].clone();
    for k in ["ctx_id", "origin_registry", "created_at", "lineage_id"] {
        body[k] = v["registry_assigned"][k].clone();
    }
    Some(Held {
        body,
        artifact: v["expected"]["task_snapshot_artifact"].clone(),
        exts: v["inputs"]["agent_card_extensions"]
            .as_array()
            .unwrap()
            .clone(),
    })
}

fn policy(exts: &[Value]) -> HolderPolicy {
    HolderPolicy {
        trusted: TrustedAgents::Only(vec![did()]),
        card: Some(CardContext::from_extensions(exts)),
    }
}

fn check(h: &Held, artifact: &Value, exts: &[Value]) -> Result<(), FailureKind> {
    verify_offline(
        &h.body,
        None,
        &HeldArtifact::forwarded(artifact),
        &policy(exts),
    )
    .map(|_| ())
    .map_err(|e| e.kind)
}

fn set_params(exts: &[Value], params: Value) -> Vec<Value> {
    exts.iter()
        .map(|e| {
            let mut e = e.clone();
            if e["uri"] == card::EXTENSION_URI {
                e["params"] = params.clone();
            }
            e
        })
        .collect()
}

#[test]
fn a2a_003_b_mismatched_agent_id() {
    let Some(h) = held_v1() else { return };
    let exts = set_params(
        &h.exts,
        json!({ "registry": REGISTRY,
        "agentId": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }),
    );
    assert_eq!(
        check(&h, &h.artifact, &exts),
        Err(FailureKind::CardMismatch)
    );
}

#[test]
fn a2a_003_e_duplicate_or_malformed_entry_drops_only_the_pointer() {
    let Some(h) = held_v1() else { return };
    let wrong = json!({ "registry": REGISTRY,
        "agentId": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" });
    // Two entries (one wrong): no pointer, so no card mismatch.
    let mut dup = h.exts.clone();
    dup.push(
        set_params(&h.exts, wrong.clone())
            .into_iter()
            .find(|e| e["uri"] == card::EXTENSION_URI)
            .unwrap(),
    );
    assert!(card_pointer(&dup).is_none());
    assert_eq!(check(&h, &h.artifact, &dup), Ok(()));
    // params missing agentId: no pointer.
    let malformed = set_params(&h.exts, json!({ "registry": REGISTRY }));
    assert!(card_pointer(&malformed).is_none());
    assert_eq!(check(&h, &h.artifact, &malformed), Ok(()));
    // Spec #134 §9: the AITP AID on the Card is still checked.
    let mut bad_aid = set_params(&dup, json!({ "registry": REGISTRY }));
    for e in &mut bad_aid {
        if e["uri"] == card::AITP_EXTENSION_URI {
            e["params"]["aid"] = "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        }
    }
    assert!(card_pointer(&bad_aid).is_none());
    assert_eq!(
        check(&h, &h.artifact, &bad_aid),
        Err(FailureKind::AidMismatch)
    );
}

#[tokio::test]
async fn a2a_003_g_untrusted_pointer_is_not_fetched() {
    let Some(h) = held_v1() else { return };
    // A resolver whose allowlist omits the link's registry refuses to fetch.
    let resolver = acdp::client::CrossRegistryResolver::new().with_allowlist(["other.example.org"]);
    let held = HeldArtifact::forwarded(&h.artifact);
    let err = acdp_a2a::verify::resolve_and_verify(&resolver, &held, &policy(&h.exts))
        .await
        .unwrap_err();
    assert_eq!(err.kind, FailureKind::BodyUnverified);
    // A link naming a registry other than params.registry is not by itself a failure.
    let other = set_params(
        &h.exts,
        json!({ "registry": "elsewhere.example.net", "agentId": did().as_str() }),
    );
    assert_eq!(check(&h, &h.artifact, &other), Ok(()));
}

// ---------------------------------------------------------------- a2a-004

#[test]
fn a2a_004_a_accept() {
    let Some(h) = held_v1() else { return };
    assert_eq!(check(&h, &h.artifact, &h.exts), Ok(()));
}

#[test]
fn a2a_004_b_changed_content() {
    let Some(h) = held_v1() else { return };
    let mut a = h.artifact.clone();
    let t = a["parts"][0]["text"].as_str().unwrap().to_owned();
    a["parts"][0]["text"] = format!("{}!", &t[..t.len() - 1]).into();
    assert_eq!(check(&h, &a, &h.exts), Err(FailureKind::PartsMismatch));
    let mut a = h.artifact.clone();
    a["parts"].as_array_mut().unwrap().reverse();
    assert_eq!(check(&h, &a, &h.exts), Err(FailureKind::PartsMismatch));
    let mut a = h.artifact.clone();
    let p = a["parts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.get("mediaType").is_some())
        .unwrap();
    p.as_object_mut().unwrap().remove("mediaType");
    assert_eq!(check(&h, &a, &h.exts), Err(FailureKind::PartsMismatch));
}

#[test]
fn a2a_004_c_wrong_missing_or_non_canonical_salt() {
    let Some(h) = held_v1() else { return };
    let with_salt = |s: Option<&str>| {
        let mut a = h.artifact.clone();
        let l = a["metadata"][LINK_KEY].as_object_mut().unwrap();
        match s {
            Some(s) => l.insert("salt".into(), s.into()),
            None => l.remove("salt"),
        };
        a
    };
    let other = Salt::from_bytes([7u8; 32]).to_base64url();
    assert_eq!(
        check(&h, &with_salt(Some(&other)), &h.exts),
        Err(FailureKind::PartsMismatch)
    );
    let good = h.artifact["metadata"][LINK_KEY]["salt"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        check(&h, &with_salt(Some(&format!("{good}="))), &h.exts),
        Err(FailureKind::SaltInvalid)
    );
    assert_eq!(
        check(&h, &with_salt(Some(&good[..42])), &h.exts),
        Err(FailureKind::SaltInvalid)
    );
    // Non-zero trailing bits: the last char's low 2 bits set.
    let mut nz = good.clone();
    let last = nz.pop().unwrap();
    let alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let i = alpha.find(last).unwrap();
    nz.push(alpha.as_bytes()[i | 1] as char);
    if i & 3 == 0 {
        assert_eq!(
            check(&h, &with_salt(Some(&nz)), &h.exts),
            Err(FailureKind::SaltInvalid)
        );
    }
    assert_eq!(
        check(&h, &with_salt(None), &h.exts),
        Err(FailureKind::SaltInvalid)
    );
}

#[test]
fn a2a_004_d_copied_link() {
    let Some(h) = held_v1() else { return };
    let mut a = json!({ "artifactId": "other", "parts": [{ "text": "something else" }] });
    a["metadata"] = json!({ LINK_KEY: h.artifact["metadata"][LINK_KEY].clone() });
    assert_eq!(check(&h, &a, &h.exts), Err(FailureKind::PartsMismatch));
    let mut a = h.artifact.clone();
    a["metadata"][LINK_KEY]["content_hash"] = format!("sha256:{}", "0".repeat(64)).into();
    assert_eq!(check(&h, &a, &h.exts), Err(FailureKind::LinkMismatch));
}

#[test]
fn a2a_004_e_unknown_record_member() {
    let rec = held_v1().map(|h| h.body["metadata"][RECORD_KEY].clone());
    let Some(mut rec) = rec else { return };
    acdp_a2a::verify::check_record(&rec).unwrap();
    rec["extra"] = true.into();
    assert!(acdp_a2a::verify::check_record(&rec).is_err());
}

#[test]
fn a2a_004_f_task_ids() {
    let Some(h) = held_v1() else { return };
    let v = v1().unwrap();
    let (t, c) = (
        v["inputs"]["task_id"].as_str().unwrap(),
        v["inputs"]["context_id"].as_str().unwrap(),
    );
    let run = |t, c| {
        verify_offline(
            &h.body,
            None,
            &HeldArtifact {
                artifact: &h.artifact,
                task_id: t,
                context_id: c,
            },
            &policy(&h.exts),
        )
    };
    let ok = run(None, None).unwrap();
    assert!(!ok.task_checked && !ok.context_checked);
    assert!(run(Some(t), Some(c)).is_ok());
    assert_eq!(
        run(Some("wrong"), None).unwrap_err().kind,
        FailureKind::TaskMismatch
    );
    assert_eq!(
        run(None, Some("wrong")).unwrap_err().kind,
        FailureKind::ContextMismatch
    );
}

#[test]
fn a2a_004_g_json_normalization() {
    // raw re-encoded, empty filename/mediaType and null members dropped.
    let p =
        normalize_part(&json!({ "raw": "-_8", "filename": "", "mediaType": "", "metadata": null }))
            .unwrap();
    assert_eq!(p, json!({ "raw": "+/8=" }));
    // Spec #134 §5.1: data null leaves no content member: invalid.
    assert!(normalize_part(&json!({ "data": null })).is_err());
    // A member outside the hashed form is a mismatch, never dropped.
    assert!(normalize_part(&json!({ "kind": "text", "text": "x" })).is_err());
    let Some(h) = held_v1() else { return };
    let mut a = h.artifact.clone();
    a["parts"][0]["kind"] = "text".into();
    assert_eq!(check(&h, &a, &h.exts), Err(FailureKind::PartsMismatch));
    // Absent role and ROLE_UNSPECIFIED read as ROLE_AGENT (vector 2 P1–P2
    // are run by conformance::a2a_001_holder_positives_and_negatives).
    let mut a = h.artifact.clone();
    a["role"] = "ROLE_UNSPECIFIED".into();
    assert_eq!(check(&h, &a, &h.exts), Ok(()));
}

#[test]
fn a2a_004_label_without_a_held_label_is_a_mismatch() {
    // Spec #134 §8 step 4.
    let Some(h) = held_v1() else { return };
    assert!(h.body["metadata"][RECORD_KEY].get("name").is_some());
    let mut a = h.artifact.clone();
    a.as_object_mut().unwrap().remove("name");
    assert_eq!(check(&h, &a, &h.exts), Err(FailureKind::LabelMismatch));
}

#[test]
fn a2a_004_h_status_is_reported() {
    let Some(h) = held_v1() else { return };
    for st in [Status::Retracted, Status::Superseded] {
        let v = verify_offline(
            &h.body,
            Some(&st),
            &HeldArtifact::forwarded(&h.artifact),
            &policy(&h.exts),
        )
        .unwrap();
        assert_eq!(v.status, Some(st));
    }
}

#[test]
fn a2a_004_i_failed_link() {
    let Some(h) = held_v1() else { return };
    let mut a = h.artifact.clone();
    a["metadata"][LINK_KEY] = link::failed(Some("rate_limited"));
    let e = verify_offline(
        &h.body,
        None,
        &HeldArtifact::forwarded(&a),
        &policy(&h.exts),
    )
    .unwrap_err();
    assert_eq!(e.kind, FailureKind::FailedLink);
    assert!(e.is_unrecognised());
}

// ---------------------------------------------------------------- a2a-005

#[test]
fn a2a_005_a_order_and_deduplication() {
    let (x, y) = (ctx(1), ctx(2));
    let msgs = [
        json!({ "metadata": { "io.acdp/inputs": [x, y] } }),
        json!({ "metadata": { "io.acdp/inputs": [x] } }),
    ];
    let cited = inputs::cited_inputs(msgs.iter());
    assert_eq!(cited, vec![cid(1), cid(2)]);
}

#[tokio::test]
async fn a2a_005_b_verified_and_used_only() {
    let (reg, client) = registry().await;
    let a = agent(client);
    let mut s = TaskSession::new("t1", "c1");
    s.observe_client_message(
        &json!({ "metadata": { "io.acdp/inputs": [ctx(50), ctx(51), ctx(52)] } }),
    );
    s.mark_inputs_verified([cid(50), cid(51)]);
    s.hints_mut("a1").used_inputs = Some(vec![cid(51)]);
    a.on_chunk(
        &mut s,
        chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true),
    )
    .await
    .unwrap();
    a.on_chunk(
        &mut s,
        chunk("t1", "c1", "a2", json!([{ "text": "y" }]), false, true),
    )
    .await
    .unwrap();
    let b = bodies(&reg).await;
    assert_eq!(b[0]["derived_from"], json!([ctx(51)]));
    assert_eq!(
        b[1]["derived_from"],
        json!([ctx(50), ctx(51)]),
        "unverified 52 left out"
    );
}

#[test]
fn a2a_005_c_invalid_value_ignored() {
    for bad in [
        json!({ "x": [ctx(1)] }),
        json!([]),
        json!(["nope"]),
        json!(ctx(1)),
    ] {
        assert!(
            inputs::parse_inputs(&json!({ inputs::INPUTS_KEY: bad })).is_none(),
            "{bad}"
        );
    }
    // Under io.acdp/provenance it is not read.
    let m = json!({ LINK_KEY: { inputs::INPUTS_KEY: [ctx(1)] } });
    assert!(inputs::parse_inputs(&m).is_none());
}

#[test]
fn a2a_005_d_cap() {
    let cited: Vec<CtxId> = (1..=1200).map(cid).collect();
    let d = inputs::derived_from(None, &cited, |_| true, &[]);
    assert_eq!(d.len(), inputs::MAX_DERIVED_FROM);
    assert_eq!(d[0], cid(1));
}

#[tokio::test]
async fn a2a_005_e_no_scraping() {
    let (reg, client) = registry().await;
    let a = agent(client);
    let mut s = TaskSession::new("t1", "c1");
    s.observe_client_message(&json!({ "parts": [{ "text": ctx(9) }], "metadata": {} }));
    let parts = json!([{ "text": format!("see {}", ctx(9)) }, { "data": { "ref": ctx(9) } }]);
    a.on_chunk(&mut s, chunk("t1", "c1", "a1", parts, false, true))
        .await
        .unwrap();
    assert_eq!(bodies(&reg).await[0]["derived_from"], json!([]));
}

#[test]
fn a2a_005_f_continuation_first() {
    let d = inputs::derived_from(
        Some(&cid(9)),
        &[cid(1), cid(9), cid(2)],
        |_| true,
        &[cid(3)],
    );
    assert_eq!(d, vec![cid(9), cid(1), cid(2), cid(3)]);
}

// ---------------------------------------------------------------- a2a-006

#[tokio::test]
async fn a2a_006_only_metadata_gains_the_link() {
    let Some(v) = v1() else { return };
    let (_reg, client) = registry().await;
    let a = agent(client);
    let mut s = session(&v);
    let cs = chunks(&v);
    let out = run_task(&a, &mut s, &cs).await;
    let mut last = out[1].clone();
    assert!(last["artifact"].get("extensions").is_none());
    // Only io.acdp/provenance was added.
    strip_link(&mut last["artifact"]);
    let mut want = cs[1].clone();
    if want["artifact"].get("metadata").is_none() {
        want["artifact"]["metadata"] = json!({});
    }
    assert_eq!(last, want);
    let task = json!({ "id": s.assembly().task_id(), "status": { "state": "TASK_STATE_COMPLETED" },
        "artifacts": [{ "artifactId": "fraud-summary", "name": cs[0]["artifact"]["name"], "parts": [] }] });
    let got = a.on_task(&mut s, task).await.unwrap().task;
    assert!(got["artifacts"][0].get("extensions").is_none());
}

// ---------------------------------------------------------------- a2a-007

#[tokio::test]
async fn a2a_007_a_fail_open_registry_error() {
    let (reg, client) = registry_failing(wire_error(429, "rate_limited")).await;
    let a = agent(client);
    let mut s = TaskSession::new("t1", "c1");
    let c = chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true);
    let mut out = emitted(a.on_chunk(&mut s, c.clone()).await.unwrap());
    assert_eq!(
        out["artifact"]["metadata"][LINK_KEY],
        json!({ "failed": true, "error": "rate_limited" })
    );
    strip_link(&mut out["artifact"]);
    out["artifact"].as_object_mut().unwrap().remove("metadata");
    assert_eq!(out, c, "emitted unchanged");
    assert_eq!(reg.received_requests().await.unwrap().len(), 2, "retried");
}

#[tokio::test]
async fn a2a_007_b_fail_open_unreachable_or_timeout() {
    let a = agent(RegistryClient::with_test_transport("http://127.0.0.1:1").unwrap());
    let mut s = TaskSession::new("t1", "c1");
    let out = emitted(
        a.on_chunk(
            &mut s,
            chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        out["artifact"]["metadata"][LINK_KEY],
        json!({ "failed": true })
    );

    let (_reg, client) =
        registry_failing(ResponseTemplate::new(201).set_delay(Duration::from_secs(5))).await;
    let a = agent(client).with_publish_timeout(Duration::from_millis(200));
    let mut s = TaskSession::new("t1", "c1");
    let out = emitted(
        a.on_chunk(
            &mut s,
            chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        out["artifact"]["metadata"][LINK_KEY],
        json!({ "failed": true })
    );
}

#[tokio::test]
async fn a2a_007_c_fail_closed() {
    let (_reg, client) = registry_failing(wire_error(400, "schema_violation")).await;
    let mut p = ArtifactPolicy::new(template());
    p.fail_closed = true;
    let a = Agent::new(producer(), client, "1.0", p).with_max_attempts(1);
    let mut s = TaskSession::new("t1", "c1");
    let out = a
        .on_chunk(
            &mut s,
            chunk("t1", "c1", "a1", json!([{ "text": "secret" }]), false, true),
        )
        .await
        .unwrap();
    let ChunkOutput::Withhold {
        artifact_id,
        failure,
    } = out
    else {
        panic!("emitted")
    };
    assert_eq!(artifact_id, "a1");
    assert_eq!(
        failure,
        json!({ "failed": true, "error": "schema_violation" })
    );
    let task = json!({ "id": "t1", "status": { "state": "TASK_STATE_COMPLETED" },
        "artifacts": [{ "artifactId": "a1", "parts": [{ "text": "secret" }] }] });
    let got = a.on_task(&mut s, task).await.unwrap();
    assert!(
        got.task["artifacts"].as_array().unwrap().is_empty(),
        "parts never emitted"
    );
    assert_eq!(got.withheld, vec![("a1".to_owned(), failure)]);
}

#[tokio::test]
async fn a2a_007_d_idempotent_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(wire_error(429, "rate_limited"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(Registry {
            n: AtomicUsize::new(0),
            seen: Default::default(),
        })
        .mount(&server)
        .await;
    let a = agent(RegistryClient::with_test_transport(&server.uri()).unwrap());
    let mut s = TaskSession::new("t1", "c1");
    let out = emitted(
        a.on_chunk(
            &mut s,
            chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true),
        )
        .await
        .unwrap(),
    );
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].body, reqs[1].body, "byte-identical body");
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    let key = format!(
        "acdp-a2a-{}",
        body["content_hash"]
            .as_str()
            .unwrap()
            .strip_prefix("sha256:")
            .unwrap()
    );
    for r in &reqs {
        assert_eq!(
            r.headers.get("idempotency-key").unwrap().to_str().unwrap(),
            key
        );
    }
    assert_eq!(out["artifact"]["metadata"][LINK_KEY]["ctx_id"], ctx(1));
}

#[tokio::test]
async fn a2a_007_e_publish_before_the_final_chunk() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_millis(500)).set_body_json(json!({
            "ctx_id": ctx(1),
            "lineage_id": "lin:sha256:53269327c5284c8d8389e5687a6604e81c64e81587e6518687cb41a7f3ea5647",
            "version": 1, "created_at": "2026-11-06T09:15:42.400Z", "status": "active"
        })))
        .mount(&server)
        .await;
    let a = agent(RegistryClient::with_test_transport(&server.uri()).unwrap());
    let mut s = TaskSession::new("t1", "c1");
    let t = std::time::Instant::now();
    let out = emitted(
        a.on_chunk(
            &mut s,
            chunk("t1", "c1", "a1", json!([{ "text": "x" }]), false, true),
        )
        .await
        .unwrap(),
    );
    assert!(
        t.elapsed() >= Duration::from_millis(500),
        "final chunk delayed"
    );
    assert_eq!(out["artifact"]["metadata"][LINK_KEY]["ctx_id"], ctx(1));
}

// ---------------------------------------------------------------- a2a-008

fn art(parts: Value) -> acdp_a2a::assembly::AssembledArtifact {
    let mut asm = acdp_a2a::assembly::TaskAssembly::new("t1", "c1");
    asm.ingest_chunk(&chunk("t1", "c1", "a1", parts, false, true))
        .unwrap();
    asm.artifact("a1").unwrap().clone()
}

fn prep(
    a: &acdp_a2a::assembly::AssembledArtifact,
    t: &BodyTemplate,
    e: &Embedding,
) -> Result<record::Prepared, acdp::AcdpError> {
    let urls = Default::default();
    let c = Completion {
        a2a_protocol_version: "1.0",
        task_id: "t1",
        context_id: "c1",
        artifact: a,
        completed_at: "2026-11-06T09:15:42.318Z".parse().unwrap(),
        derived_from: vec![],
        previous: None,
        map_url_parts: true,
        url_contents: &urls,
        a2a_artifact_hash: None,
    };
    record::prepare(&producer(), &c, t, e, Salt::random)
}

#[test]
fn a2a_008_a_b_salting_and_embedding() {
    let parts = json!([{ "text": "hello" }]);
    let a = art(parts.clone());
    let p = prep(&a, &template(), &Embedding::Never).unwrap();
    let rec = &p.request.metadata.as_ref().unwrap()[RECORD_KEY];
    assert_eq!(rec["salted"], true);
    assert_eq!(rec["embedded"], false);
    assert_eq!(rec["task_id_hash"], hash::id_hash("t1", &p.salt));
    let body = serde_json::to_string(&p.request).unwrap();
    assert!(
        !body.contains(&p.salt.to_base64url()),
        "salt never in the body"
    );
    assert_eq!(p.link(&cid(1))["salt"], p.salt.to_base64url());

    let emb = Embedding::Allowlisted {
        external_base: None,
    };
    let p = prep(&a, &template(), &emb).unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    let rec = &req["metadata"][RECORD_KEY];
    assert_eq!(
        (rec["salted"].clone(), rec["embedded"].clone()),
        (json!(false), json!(true))
    );
    assert_eq!(rec["parts_hash"], hash::parts_hash(&parts, None));
    assert_eq!(
        rec["artifact_id_hash"],
        hash::id_hash("a1", &p.salt),
        "ids still salted"
    );
    let dr = &req["data_refs"][0];
    assert_eq!(
        (dr["type"].clone(), dr["format"].clone()),
        (json!("primary_result"), json!("json"))
    );
    assert_eq!(
        dr["embedded"],
        json!({ "encoding": "json", "content": parts })
    );

    // Over the 64 KB cap: a location DataRef with H(JCS(parts)).
    let big = json!([{ "text": "x".repeat(70_000) }]);
    let a = art(big.clone());
    let p = prep(
        &a,
        &template(),
        &Embedding::Allowlisted {
            external_base: Some("https://agent.example.com/parts".into()),
        },
    )
    .unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    let ext = p.external.as_ref().unwrap();
    assert_eq!(req["data_refs"][0]["location"], ext.location);
    assert_eq!(
        req["data_refs"][0]["content_hash"],
        hash::sha256_tagged(&canonicalize_value(&big))
    );
    assert_eq!(ext.bytes, canonicalize_value(&big));
    assert_eq!(req["metadata"][RECORD_KEY]["embedded"], true);
}

#[test]
fn a2a_008_c_url_parts() {
    let plain = "https://agent.example.com/report.pdf";
    let signed = "https://agent.example.com/report.pdf?X-Amz-Signature=abc";
    assert!(record::mappable_url(plain));
    assert!(!record::mappable_url(signed));
    assert!(!record::mappable_url("http://agent.example.com/r.pdf"));
    assert!(!record::mappable_url("https://u:p@agent.example.com/r.pdf"));
    let a = art(json!([{ "url": signed }]));
    let p = prep(&a, &template(), &Embedding::Never).unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    assert_eq!(req["data_refs"], json!([]), "signed URL gives no DataRef");
    assert_eq!(
        req["metadata"][RECORD_KEY]["parts_hash"],
        hash::parts_hash(&json!([{ "url": signed }]), Some(&p.salt))
    );
}

#[tokio::test]
async fn a2a_008_c_plain_url_part_gives_a_data_ref() {
    let (reg, client) = registry().await;
    let a = agent(client);
    let plain = "https://agent.example.com/report.pdf";
    let mut s = TaskSession::new("t1", "c1");
    s.know_url_content(plain, b"%PDF-1.7 bytes");
    a.on_chunk(
        &mut s,
        chunk("t1", "c1", "a1", json!([{ "url": plain }]), false, true),
    )
    .await
    .unwrap();
    let dr = &bodies(&reg).await[0]["data_refs"][0];
    assert_eq!(dr["type"], "primary_result");
    assert_eq!(dr["location"], plain);
    assert_eq!(dr["content_hash"], hash::sha256_tagged(b"%PDF-1.7 bytes"));
}

#[test]
fn a2a_008_d_raw_parts() {
    let a = art(json!([{ "raw": "aGk", "filename": "", "mediaType": "" }]));
    assert_eq!(a.parts, vec![json!({ "raw": "aGk=" })]);
}

#[test]
fn a2a_008_e_anchor() {
    let a = art(json!([{ "text": "x" }]));
    let h = acdp::types::primitives::ContentHash(format!("sha256:{}", "a".repeat(64)));
    let urls = Default::default();
    let mk = |vis: Visibility, emb: &Embedding| {
        let mut t = template();
        t.visibility = vis;
        let c = Completion {
            a2a_protocol_version: "1.0",
            task_id: "t1",
            context_id: "c1",
            artifact: &a,
            completed_at: "2026-11-06T09:15:42.318Z".parse().unwrap(),
            derived_from: vec![],
            previous: None,
            map_url_parts: true,
            url_contents: &urls,
            a2a_artifact_hash: Some(h.clone()),
        };
        record::prepare(&producer(), &c, &t, emb, Salt::random)
    };
    let p = mk(Visibility::Private, &Embedding::Never).unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    assert_eq!(
        req["anchors"],
        json!([{ "scheme": "a2a.artifact", "content_hash": h.as_str() }])
    );
    assert!(
        mk(Visibility::Public, &Embedding::Never).is_err(),
        "never on a salted public body"
    );
    assert!(mk(
        Visibility::Public,
        &Embedding::Allowlisted {
            external_base: None
        }
    )
    .is_ok());
}

#[test]
fn a2a_008_f_metadata_member_and_type() {
    let a = art(json!([{ "text": "x" }]));
    let mut t = template();
    t.metadata.insert("com.example/own".into(), json!(1));
    let p = prep(&a, &t, &Embedding::Never).unwrap();
    let m = p.request.metadata.as_ref().unwrap();
    assert_eq!(m["com.example/own"], 1);
    assert!(m.get(RECORD_KEY).is_some());
    assert_eq!(
        serde_json::to_value(&p.request).unwrap()["type"],
        "analysis"
    );
    for ty in record::FORBIDDEN_TYPES {
        let t = BodyTemplate::new(serde_json::from_value::<ContextType>(json!(ty)).unwrap());
        assert!(prep(&a, &t, &Embedding::Never).is_err(), "{ty}");
    }
    let mut t = template();
    t.metadata.insert(RECORD_KEY.into(), json!({}));
    assert!(prep(&a, &t, &Embedding::Never).is_err(), "reserved key");
}
