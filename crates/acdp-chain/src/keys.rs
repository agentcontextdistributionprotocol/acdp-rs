//! Key material from the bundle only (RFC-ACDP-0017 §6.2, §6.3).
//!
//! `did:web` keys come from DID-document snapshots (the bundle's own,
//! plus the caller's pinned ones); `did:key` keys decode arithmetically.
//! Nothing here touches the network or a clock.

use std::collections::BTreeMap;

use acdp_did::DidDocument;
use acdp_types::body::Signature;
use acdp_types::primitives::ContentHash;
use chrono::{DateTime, Utc};

use crate::evidence::Parsed;
use crate::options::Pinned;
use crate::syntax::parse_ts;
use crate::verdict::Basis;

/// One snapshot that takes part in §6.2 selection.
struct Candidate {
    time: DateTime<Utc>,
    pinned: bool,
    /// Position within its source list; a later entry wins a tie.
    index: usize,
    /// `None` when the document cannot be evaluated under RFC-ACDP-0001
    /// §5.11: it does not parse, or its `id` is not the DID.
    doc: Option<DidDocument>,
}

/// Why no key could be located for a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Missing {
    /// No snapshot (≤ T in the as-of pass), an unevaluable one, or a
    /// fragment the chosen document does not carry.
    NoEvidence,
    /// The `key_id` itself is unusable: not under the expected DID, no
    /// fragment, or a `did:key` that does not decode.
    Malformed,
}

/// A located key and what checking the signature under it gave.
#[derive(Debug, Clone)]
pub(crate) struct KeyCheck {
    pub basis: Basis,
    /// The chosen snapshot's `observed_at` (or pinned `instant`);
    /// `None` for `did:key`.
    pub evidence_time: Option<DateTime<Utc>>,
    /// Listed in the chosen document's `assertionMethod` (always true
    /// for `did:key`).
    pub in_assertion: bool,
    /// The RFC-ACDP-0010 §6 fingerprint of the located key.
    pub fingerprint: Option<String>,
    /// The signature verifies under the located key (with
    /// algorithm-downgrade rejection).
    pub valid: bool,
}

/// The bundle's (and the caller's pinned) DID-document history.
pub(crate) struct BundleKeys {
    by_did: BTreeMap<String, Vec<Candidate>>,
}

impl BundleKeys {
    pub(crate) fn new(parsed: &Parsed<'_>, pinned: &Pinned) -> Self {
        let mut by_did: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
        for (did, list) in &parsed.snapshots {
            let entry = by_did.entry(did.to_string()).or_default();
            for (index, (time, doc)) in list.iter().enumerate() {
                entry.push(Candidate {
                    time: *time,
                    pinned: false,
                    index,
                    doc: evaluate(did, doc),
                });
            }
        }
        for (index, s) in pinned.snapshots.iter().enumerate() {
            let Some(time) = parse_ts(&s.instant) else {
                continue; // rejected by Options::check before we get here
            };
            by_did.entry(s.did.clone()).or_default().push(Candidate {
                time,
                pinned: true,
                index,
                doc: evaluate(&s.did, &s.document),
            });
        }
        Self { by_did }
    }

    /// §6.2: the snapshot with the greatest time (≤ `at` when given).
    /// Ties go to the later array entry; a pinned snapshot wins a tie
    /// with an observed one.
    fn select(&self, did: &str, at: Option<DateTime<Utc>>) -> Option<&Candidate> {
        self.by_did
            .get(did)?
            .iter()
            .filter(|c| at.is_none_or(|t| c.time <= t))
            .max_by_key(|c| (c.time, c.pinned, c.index))
    }

    /// The DID document chosen for `did` in a pass, with its basis and
    /// evidence time. `None` when there is no evaluable snapshot.
    pub(crate) fn document(
        &self,
        did: &str,
        at: Option<DateTime<Utc>>,
    ) -> Option<(&DidDocument, Basis, DateTime<Utc>)> {
        let c = self.select(did, at)?;
        let basis = if c.pinned {
            Basis::Pinned
        } else {
            Basis::Observed
        };
        c.doc.as_ref().map(|d| (d, basis, c.time))
    }

    /// Locate the key `signature.key_id` names under `expected_did` and
    /// check `signature` over `hash` with it. Authorization
    /// (`assertionMethod`) is reported, not enforced: callers decide.
    pub(crate) fn check(
        &self,
        signature: &Signature,
        hash: &ContentHash,
        expected_did: &str,
        at: Option<DateTime<Utc>>,
    ) -> Result<KeyCheck, Missing> {
        let (did, fragment) = signature
            .key_id
            .split_once('#')
            .filter(|(did, frag)| *did == expected_did && !frag.is_empty())
            .ok_or(Missing::Malformed)?;
        if did.starts_with("did:key:") {
            let material = acdp_did::key::resolve_did_key_url(&signature.key_id)
                .map_err(|_| Missing::Malformed)?;
            return Ok(KeyCheck {
                basis: Basis::SelfEvident,
                evidence_time: None,
                in_assertion: true,
                fingerprint: acdp_crypto::fingerprint::fingerprint_did_key_material(&material).ok(),
                valid: acdp_verify::verify_did_key_envelope(signature, hash).is_ok(),
            });
        }
        let (doc, basis, time) = self.document(did, at).ok_or(Missing::NoEvidence)?;
        let method = doc.find_by_fragment(fragment).ok_or(Missing::NoEvidence)?;
        Ok(KeyCheck {
            basis,
            evidence_time: Some(time),
            in_assertion: doc.is_assertion_method(&method.id),
            fingerprint: acdp_crypto::fingerprint::fingerprint_verification_method(
                method,
                &signature.algorithm,
            )
            .ok(),
            valid: acdp_verify::verify_signature_with_method(method, signature, hash).is_ok(),
        })
    }
}

fn evaluate(did: &str, doc: &serde_json::Map<String, serde_json::Value>) -> Option<DidDocument> {
    let parsed: DidDocument =
        serde_json::from_value(serde_json::Value::Object(doc.clone())).ok()?;
    (parsed.id == did).then_some(parsed)
}
