//! RFC-ACDP-0022 known answers: both a2a-001 vectors byte for byte
//! (producer side), its holder positives and negatives (holder side),
//! and the fixture-binding guard. The behavioral fixtures a2a-002..008
//! run in `tests/behavior.rs`.

mod common;

use std::collections::{HashMap, HashSet};

use acdp::{
    crypto::{canonicalize_value, SigningKey},
    producer::Producer,
    types::{
        primitives::{AgentDid, ContextType, Visibility},
        CtxId,
    },
};
use acdp_a2a::{
    assembly::{ChunkEffect, TaskAssembly},
    card::{self, aid_matches_did_key, aitp_aids, card_pointer},
    hash, inputs, link,
    record::{self, BodyTemplate, Completion, Embedding, UrlContent, RECORD_KEY},
    verify::{verify_offline, CardContext, HeldArtifact, HolderPolicy, TrustedAgents},
    Salt,
};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

fn zero_seed_producer() -> Producer {
    Producer::new_did_key(SigningKey::from_bytes(&[0u8; 32]))
}

/// The agent's own template, as the vector's ProducerContent shows it.
fn template_of(pc: &Value) -> BodyTemplate {
    let mut t =
        BodyTemplate::new(serde_json::from_value::<ContextType>(pc["type"].clone()).unwrap());
    let mut meta = pc["metadata"].as_object().unwrap().clone();
    meta.remove(RECORD_KEY);
    t.metadata = meta;
    t.domain = pc["domain"].as_str().map(str::to_owned);
    t.visibility = serde_json::from_value::<Visibility>(pc["visibility"].clone()).unwrap();
    t
}

fn assemble(v: &Value) -> TaskAssembly {
    let i = &v["inputs"];
    let mut a = TaskAssembly::new(
        i["task_id"].as_str().unwrap(),
        i["context_id"].as_str().unwrap(),
    );
    let chunks = i["chunks"].as_array().unwrap();
    for (n, c) in chunks.iter().enumerate() {
        let effect = a.ingest_chunk(c).unwrap();
        let want = if n + 1 == chunks.len() {
            ChunkEffect::Completed
        } else {
            ChunkEffect::Pending
        };
        assert_eq!(effect, want, "chunk {n}");
    }
    a
}

fn url_contents(v: &Value) -> HashMap<String, UrlContent> {
    v["inputs"]["url_contents_hex"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(u, h)| {
            (
                u.clone(),
                UrlContent::of(&hex::decode(h.as_str().unwrap()).unwrap()),
            )
        })
        .collect()
}

fn registered_body(v: &Value) -> Value {
    let mut body = v["expected"]["publish_request_body"].clone();
    for k in ["ctx_id", "origin_registry", "created_at", "lineage_id"] {
        body[k] = v["registry_assigned"][k].clone();
    }
    body
}

fn holder_policy(f: &Value, extensions: &[Value]) -> HolderPolicy {
    HolderPolicy {
        trusted: TrustedAgents::Only(vec![AgentDid::parse(
            f["test_keypair"]["did_key"].as_str().unwrap(),
        )
        .unwrap()]),
        card: Some(CardContext::from_extensions(extensions)),
    }
}

#[test]
fn a2a_001_vectors_reproduce_byte_for_byte() {
    let Some(dir) = common::spec_dir() else {
        eprintln!("skipping a2a-001: no spec checkout");
        return;
    };
    let f = common::fixture(&dir, "a2a-001-artifact-golden.json");
    let schemas = common::Schemas::load(&dir);
    let vectors = f["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 2);
    let producer = zero_seed_producer();
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let i = &v["inputs"];
        let exp = &v["expected"];
        let pc = &v["producer_content"];
        let rec_exp = &pc["metadata"][RECORD_KEY];

        let salt = Salt::from_base64url(i["salt"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(salt.as_bytes()), exp["salt_hex"], "{name}");

        // §4.2 assembly and §5.1 form.
        let a = assemble(v);
        let art = a
            .artifact(
                exp["final_chunk"]["artifact"]["artifactId"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let parts = Value::Array(art.parts.clone());
        assert_eq!(parts, exp["assembled_parts"], "{name}: assembled parts");

        // §5 preimage and hashes.
        let salted = rec_exp["salted"] == true;
        let mut pre = Vec::new();
        if salted {
            pre.extend_from_slice(salt.as_bytes());
        }
        pre.extend(canonicalize_value(&parts));
        assert_eq!(
            hex::encode(&pre),
            exp["parts_preimage_hex"],
            "{name}: preimage"
        );
        assert_eq!(
            hash::parts_hash(&parts, salted.then_some(&salt)),
            exp["parts_hash"]
        );
        assert_eq!(
            hash::id_hash(&art.artifact_id, &salt),
            exp["artifact_id_hash"]
        );
        assert_eq!(hash::id_hash(a.task_id(), &salt), exp["task_id_hash"]);
        assert_eq!(hash::id_hash(a.context_id(), &salt), exp["context_id_hash"]);

        // §7 derived_from.
        let cited = inputs::cited_inputs([&json!({ "metadata": i["message_metadata"] })]);
        let verified: HashSet<CtxId> = i["verified_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| CtxId::parse(s.as_str().unwrap()).unwrap())
            .collect();
        let derived = inputs::derived_from(None, &cited, |c| verified.contains(c), &[]);
        let derived_v: Vec<Value> = derived.iter().map(|c| c.as_str().into()).collect();
        assert_eq!(
            Value::from(derived_v),
            exp["derived_from"],
            "{name}: derived_from"
        );

        // The body, signed.
        let embedding = if i["embed"] == true {
            Embedding::Allowlisted {
                external_base: None,
            }
        } else {
            Embedding::Never
        };
        let urls = url_contents(v);
        let completed_at: DateTime<Utc> =
            rec_exp["completed_at"].as_str().unwrap().parse().unwrap();
        let c = Completion {
            a2a_protocol_version: i["a2a_protocol_version"].as_str().unwrap(),
            task_id: a.task_id(),
            context_id: a.context_id(),
            artifact: art,
            completed_at,
            derived_from: derived,
            previous: None,
            map_url_parts: true,
            url_contents: &urls,
            a2a_artifact_hash: None,
        };
        let prepared = record::prepare(&producer, &c, &template_of(pc), &embedding, || {
            Ok(salt.clone())
        })
        .unwrap();
        let req = serde_json::to_value(&prepared.request).unwrap();
        assert_eq!(req["agent_id"], f["test_keypair"]["did_key"]);
        assert_eq!(req["metadata"][RECORD_KEY], *rec_exp, "{name}: record");
        schemas
            .validate("record", &req["metadata"][RECORD_KEY])
            .unwrap();
        let mut producer_content = req.as_object().unwrap().clone();
        producer_content.remove("content_hash");
        producer_content.remove("signature");
        assert_eq!(
            Value::Object(producer_content.clone()),
            *pc,
            "{name}: ProducerContent"
        );
        assert_eq!(
            String::from_utf8(canonicalize_value(&Value::Object(producer_content))).unwrap(),
            exp["canonical_form"].as_str().unwrap(),
            "{name}: canonical form"
        );
        assert_eq!(req["content_hash"], exp["content_hash"], "{name}");
        assert_eq!(
            req["signature"]["value"], exp["signature_value_base64"],
            "{name}"
        );
        assert_eq!(
            hex::encode(
                base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    req["signature"]["value"].as_str().unwrap()
                )
                .unwrap()
            ),
            exp["signature_value_hex"]
        );
        assert_eq!(req, exp["publish_request_body"], "{name}: publish request");
        assert_eq!(prepared.idempotency_key, exp["idempotency_key"]);

        // §6 link on the final chunk and the snapshot.
        let ctx_id = CtxId::parse(v["registry_assigned"]["ctx_id"].as_str().unwrap()).unwrap();
        let l = prepared.link(&ctx_id);
        assert_eq!(l["registry"], v["registry_assigned"]["origin_registry"]);
        schemas.validate("link", &l).unwrap();
        let mut final_chunk = i["chunks"].as_array().unwrap().last().unwrap().clone();
        assert!(link::attach(&mut final_chunk["artifact"], l.clone()));
        assert_eq!(final_chunk, exp["final_chunk"], "{name}: final chunk");
        assert_eq!(
            art.to_snapshot(Some(&l)),
            exp["task_snapshot_artifact"],
            "{name}: snapshot"
        );

        // §9 Card pointer and the §3.1 AITP binding.
        let exts = i["agent_card_extensions"].as_array().unwrap();
        let ptr = card_pointer(exts).expect("one well-formed pointer");
        assert_eq!(ptr.agent_id.as_str(), req["agent_id"]);
        schemas.validate("card_params", &exts[1]["params"]).unwrap();
        assert_eq!(
            aitp_aids(exts),
            vec![exp["aitp_aid"].as_str().unwrap().to_owned()]
        );
        assert!(aid_matches_did_key(
            exp["aitp_aid"].as_str().unwrap(),
            &ptr.agent_id
        ));
        assert_eq!(card::card_extension(&ptr, None)["required"], false);

        // §8 accepts the snapshot artifact, with the task ids known.
        let body = registered_body(v);
        let policy = holder_policy(&f, exts);
        let held = HeldArtifact {
            artifact: &exp["task_snapshot_artifact"],
            task_id: Some(a.task_id()),
            context_id: Some(a.context_id()),
        };
        let verdict = verify_offline(&body, None, &held, &policy).unwrap();
        assert_eq!(verdict.ctx_id, ctx_id);
        assert!(verdict.task_checked && verdict.context_checked);
    }
}

#[test]
fn a2a_001_holder_positives_and_negatives() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let f = common::fixture(&dir, "a2a-001-artifact-golden.json");
    let mut positives = 0;
    let mut negatives = 0;
    for v in f["vectors"].as_array().unwrap() {
        let exts = v["inputs"]["agent_card_extensions"].as_array().unwrap();
        let body = registered_body(v);
        for p in v["expected"]["holder_positives"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let held = HeldArtifact::forwarded(&p["held_artifact"]);
            verify_offline(&body, None, &held, &holder_policy(&f, exts))
                .unwrap_or_else(|e| panic!("{}: {e}", p["name"]));
            positives += 1;
        }
        for n in v["expected"]["holder_negatives"].as_array().unwrap() {
            let name = n["name"].as_str().unwrap();
            let mut ext: Vec<Value> = exts.clone();
            if let Some(cp) = n.get("card_params") {
                for e in &mut ext {
                    if e["uri"] == card::EXTENSION_URI {
                        e["params"] = cp.clone();
                    }
                }
            }
            let held = HeldArtifact {
                artifact: &n["held_artifact"],
                task_id: n["known_task_id"].as_str(),
                context_id: n["known_context_id"].as_str(),
            };
            let err = verify_offline(&body, None, &held, &holder_policy(&f, &ext)).expect_err(name);
            assert_eq!(err.kind.code(), n["expected_failure"], "{name}: {err}");
            negatives += 1;
        }
    }
    // Vector 1: ten negatives; vector 2: two positives and six negatives.
    assert_eq!((positives, negatives), (2, 16));
}

#[test]
fn a2a_001_bodies_verify_offline() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let f = common::fixture(&dir, "a2a-001-artifact-golden.json");
    for v in f["vectors"].as_array().unwrap() {
        acdp::crypto::verify_body_value_offline(&registered_body(v)).unwrap();
    }
}

#[test]
fn a2a_001_example_record_matches() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let f = common::fixture(&dir, "a2a-001-artifact-golden.json");
    let ex: Value = serde_json::from_slice(
        &std::fs::read(dir.join("examples/a2a-artifact/golden-record.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ex,
        f["vectors"][0]["producer_content"]["metadata"][RECORD_KEY]
    );
    common::Schemas::load(&dir).validate("record", &ex).unwrap();
    // §4.5: "a2a-001's first record ... is 534" bytes of JCS.
    assert_eq!(canonicalize_value(&ex).len(), 534);
}

#[test]
fn inputs_schema_agrees_with_parse_inputs() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let schemas = common::Schemas::load(&dir);
    let ok = json!(["acdp://registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d"]);
    schemas.validate("inputs", &ok).unwrap();
    assert!(inputs::parse_inputs(&json!({ inputs::INPUTS_KEY: ok })).is_some());
    for bad in [json!([]), json!({ "inputs": ok }), json!(["not-a-ctx-id"])] {
        assert!(schemas.validate("inputs", &bad).is_err(), "{bad}");
        assert!(inputs::parse_inputs(&json!({ inputs::INPUTS_KEY: bad })).is_none());
    }
    let mut big = Map::new();
    big.insert(
        inputs::INPUTS_KEY.into(),
        Value::Array(vec![ok[0].clone(); 1001]),
    );
    assert!(inputs::parse_inputs(&Value::Object(big)).is_none());
}

/// Every `a2a-*` fixture the spec ships is bound to a test here or in
/// `tests/behavior.rs`; a new fixture fails this until it is.
#[test]
fn a2a_fixtures_each_have_tests() {
    const BOUND: &[(&str, &str)] = &[
        (
            "a2a-001",
            "conformance::a2a_001_vectors_reproduce_byte_for_byte",
        ),
        ("a2a-002", "behavior::a2a_002_*"),
        ("a2a-003", "behavior::a2a_003_*"),
        ("a2a-004", "behavior::a2a_004_*"),
        ("a2a-005", "behavior::a2a_005_*"),
        ("a2a-006", "behavior::a2a_006_*"),
        ("a2a-007", "behavior::a2a_007_*"),
        ("a2a-008", "behavior::a2a_008_*"),
    ];
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let mut ids: Vec<String> = std::fs::read_dir(dir.join("schemas/conformance"))
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.starts_with("a2a-").then(|| name[..7].to_owned())
        })
        .collect();
    ids.sort();
    let bound: Vec<&str> = BOUND.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, bound, "unbound a2a fixtures");
}
