//! Issue #257: a cache for RFC-ACDP-0014 §7/§8 revocation discovery.
//!
//! This is deliberately **two objects sharing one lock**, not one:
//!
//! - **Facts** — verified [`KeyRevocation`]s. RFC-ACDP-0014 §7:114 licenses
//!   caching these *indefinitely* ("the statement is permanent"). They are
//!   **always unioned** into classification by
//!   [`crate::verified::VerifiedContext`]'s internal `verify_retrieved` —
//!   never used to replace or subset a discovery result. A revocation is
//!   monotone (more revocations ⇒ an earlier effective boundary ⇒ strictly
//!   more fail-closed verdicts), so seeding from the fact store can only
//!   *tighten* a verdict, never loosen one. That makes the fact store an
//!   **anti-rollback security control**: without it, a registry that serves
//!   a revocation on one call and hides it on the next causes the client to
//!   forget it ever saw it. See `RevocationCache::facts_for` (read) and
//!   `RevocationCache::record_success` (write) — both crate-private.
//! - **Freshness markers** — "vantage V was asked about producer/controller
//!   P for trust class C, and a full, untruncated discovery completed at
//!   time T." This is a cached *absence*, which §7:114 does **not** license
//!   and which §8 explicitly warns about: "a malicious registry can hide a
//!   revocation … absence of search results is not evidence of absence." So
//!   a marker is TTL-bounded ([`crate::verified::RevocationDiscovery::freshness`],
//!   default [`std::time::Duration::ZERO`] — i.e. off), per-vantage, and
//!   read via `RevocationCache::marker_fresh` (crate-private) — the only
//!   method in this module that can cause a lookup to be skipped rather
//!   than merely supplemented.
//!
//! Both objects live in the same per-producer `CacheEntry` (crate-private)
//! so eviction is whole-entry: facts and markers for one producer always leave together,
//! which makes "a fresh marker over an evicted (or fact-capped) set" —
//! stale-absence-over-nothing — structurally unrepresentable rather than
//! merely guarded against.
//!
//! **Never call anything here holding the lock across an `.await`** — every
//! method in this module is synchronous and returns before its caller does
//! any network I/O.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use acdp_types::revocation::{KeyRevocation, RevocationTrustClass};

/// Capacity-triggered bound on the number of distinct producer/controller
/// entries this cache holds. Deliberately **not** an LRU (no recency
/// tracking) — per the wave plan (issue #257), eviction here can only ever
/// lose caching, never safety (a missing entry just means discovery runs
/// again), so plain capacity-triggered eviction of an arbitrary entry is
/// sufficient.
const MAX_CACHE_ENTRIES: usize = 1000;

/// Per-entry cap on stored facts. Reached only by a producer with a
/// genuinely large revocation history, or (defensively) a registry padding
/// results — either way, once hit this entry stops accepting new facts and
/// drops its markers, degrading to plain pass-through (full discovery,
/// every call) rather than to false completeness. `KeyRevocation` is not
/// `Hash` (`acdp_types::revocation`), so dedup on insert is a linear `Eq`
/// scan — trivial at this bound.
const MAX_FACTS_PER_ENTRY: usize = 256;

/// One producer/controller's cached state: verified facts (both trust
/// classes, filtered by class on read) plus per-vantage freshness markers.
#[derive(Default)]
struct CacheEntry {
    facts: Vec<KeyRevocation>,
    /// Keyed by `(authority, is_registry_attested)` — never by trust class
    /// alone (a producer-signed and a registry-attested marker for the same
    /// authority are independent) and never by the search identity used
    /// internally by the registry-attested lookup (that would let one
    /// marker suppress discovery for every producer at that registry — see
    /// `crate::revocation::find_registry_attested_revocations`, which keys
    /// its marker by the `controller` parameter, not by
    /// `capabilities.registry_did`). Plain `bool` rather than
    /// `RevocationTrustClass` because that type is not `Hash`.
    markers: HashMap<(String, bool), Instant>,
    /// Set once `facts.len()` has reached [`MAX_FACTS_PER_ENTRY`]; once
    /// true, new facts are dropped and no further marker is ever minted for
    /// this entry, so it degrades to pass-through rather than silently
    /// claiming completeness it can no longer track.
    at_cap: bool,
}

fn class_key(class: RevocationTrustClass) -> bool {
    matches!(class, RevocationTrustClass::RegistryAttested)
}

/// A cache of RFC-ACDP-0014 revocation facts and discovery-freshness
/// markers, injectable into a [`crate::RegistryClient`] via
/// [`crate::RegistryClient::with_revocation_cache`].
///
/// `Clone`, cheap (an `Arc` handle around a `Mutex<HashMap<..>>>`, following
/// the same hand-rolled-bound pattern `CrossRegistryResolver` already uses
/// for `client_cache`/`caps_cache` — see `crate::cross_registry`). Sharing
/// one clone across multiple `RegistryClient`s (or multiple producers'
/// verify calls) is the point: it is how a caller amortizes discovery
/// across many `verify_retrieved` calls against the same producer, and how
/// issue #260's cross-registry walk will later share one cache across the
/// per-authority clients it builds.
///
/// Attaching a cache changes nothing observable by itself: with the default
/// `freshness: Duration::ZERO` (both `RevocationDiscovery` named
/// constructors), markers never suppress a lookup — see
/// `marker_fresh`'s fast path (crate-private). The only behavioral change from
/// attaching a cache at the default is anti-rollback (facts persisting
/// across an induced discovery failure); saving requests is a *further*,
/// opt-in step that requires setting `freshness` above zero.
#[derive(Clone)]
pub struct RevocationCache {
    inner: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl RevocationCache {
    /// A new, empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Recover from a poisoned lock rather than propagate the panic. A
    /// poisoned cache must degrade to *running discovery* (the safe
    /// direction), never to silently skipping it — recovering the guard
    /// and continuing achieves exactly that: the stale/possibly-torn data
    /// underneath can, at worst, cause an unnecessary re-discovery (a
    /// missed marker) or an unnecessary fact write, never a false skip of
    /// a lookup that was never actually run.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, CacheEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Read cached facts for `agent_id`, filtered to the trust classes the
    /// CURRENT discovery configuration opted into — never all classes ever
    /// cached. A `producer_signed_only()` caller must not have a
    /// registry-attested fact (cached from some earlier `all_trust_classes()`
    /// run against the same producer) silently applied to it; that would
    /// apply a trust class this call explicitly declined, per RFC-ACDP-0014
    /// §6.
    ///
    /// Returns an empty `Vec` when no entry exists yet — a cache miss is
    /// indistinguishable from "no facts found," which is correct: either
    /// way discovery proceeds unseeded.
    pub(crate) fn facts_for(
        &self,
        agent_id: &str,
        include_registry_attested: bool,
    ) -> Vec<KeyRevocation> {
        let map = self.lock();
        match map.get(agent_id) {
            Some(entry) => entry
                .facts
                .iter()
                .filter(|r| {
                    include_registry_attested
                        || r.trust_class == RevocationTrustClass::ProducerSigned
                })
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Check whether a marker minted for `(authority, agent_id, class)` is
    /// still within `freshness` — the only method that can cause a lookup
    /// to be skipped. `freshness == Duration::ZERO` (the default) always
    /// returns `false` without even touching the lock: a zero TTL can
    /// never be "still fresh," and this fast path is what keeps the
    /// default behavior request-for-request identical to no cache at all
    /// (issue #257 AC3).
    pub(crate) fn marker_fresh(
        &self,
        authority: &str,
        agent_id: &str,
        class: RevocationTrustClass,
        freshness: Duration,
    ) -> bool {
        if freshness.is_zero() {
            return false;
        }
        let map = self.lock();
        match map
            .get(agent_id)
            .and_then(|e| e.markers.get(&(authority.to_string(), class_key(class))))
        {
            Some(minted_at) => minted_at.elapsed() < freshness,
            None => false,
        }
    }

    /// Record a fully successful, untruncated discovery lookup: dedup-merge
    /// `facts` into the entry (via `KeyRevocation`'s derived `Eq` — it is
    /// not `Hash`) and, unless the per-entry fact cap has just been
    /// reached, mint a fresh marker for `(authority, agent_id, class)`.
    ///
    /// Called ONLY from the tail of `find_revocations` /
    /// `find_registry_attested_revocations`, immediately before each
    /// returns `Ok` — i.e. only on a call that neither errored nor hit
    /// `AcdpError::SearchTruncated`, both of which return early via `?`
    /// before ever reaching here. This is what makes "marker minted only on
    /// full, untruncated success" structural rather than a discipline: a
    /// truncated or failed call simply never calls this method, so it can
    /// neither corrupt the fact set (facts are additive-only regardless)
    /// nor mint a marker that would silently suppress the next attempt.
    ///
    /// At the per-entry fact cap, new facts are dropped (not merely this
    /// call's — the entry is permanently past caching new information) and
    /// existing markers for the entry are cleared, so it degrades to
    /// pass-through: every future call re-discovers from scratch for this
    /// producer, rather than risk a marker outliving a set that can no
    /// longer track completeness.
    pub(crate) fn record_success(
        &self,
        authority: &str,
        agent_id: &str,
        class: RevocationTrustClass,
        facts: &[KeyRevocation],
    ) {
        let mut map = self.lock();
        if !map.contains_key(agent_id) && map.len() >= MAX_CACHE_ENTRIES {
            // Capacity-triggered eviction of an arbitrary existing entry —
            // no LRU recency tracking (see MAX_CACHE_ENTRIES doc). Losing
            // an entry can only cost a future re-discovery, never safety.
            if let Some(victim) = map.keys().next().cloned() {
                map.remove(&victim);
            }
        }
        let entry = map.entry(agent_id.to_string()).or_default();
        if !entry.at_cap {
            for f in facts {
                if entry.facts.len() >= MAX_FACTS_PER_ENTRY {
                    entry.at_cap = true;
                    break;
                }
                if !entry.facts.iter().any(|existing| existing == f) {
                    entry.facts.push(f.clone());
                }
            }
        }
        if entry.at_cap {
            entry.markers.clear();
        } else {
            entry
                .markers
                .insert((authority.to_string(), class_key(class)), Instant::now());
        }
    }
}

impl Default for RevocationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RevocationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationCache").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn rev(fp: &str, class: RevocationTrustClass) -> KeyRevocation {
        KeyRevocation {
            revoked_key_fingerprint: fp.into(),
            compromised_since: "2026-05-01T00:00:00.000Z".parse::<DateTime<Utc>>().unwrap(),
            reason: None,
            revoked_key_id: None,
            revoked_key_controller: acdp_types::primitives::AgentDid::new(
                "did:web:agents.example.com:p",
            ),
            publisher: acdp_types::primitives::AgentDid::new("did:web:agents.example.com:p"),
            trust_class: class,
        }
    }

    /// AC4 (dedup): recording the same fact repeatedly does not grow the
    /// entry.
    #[test]
    fn record_success_dedups_identical_facts() {
        let cache = RevocationCache::new();
        let r = rev("sha256:aaaa", RevocationTrustClass::ProducerSigned);
        for _ in 0..5 {
            cache.record_success(
                "reg.example",
                "did:web:p",
                RevocationTrustClass::ProducerSigned,
                std::slice::from_ref(&r),
            );
        }
        assert_eq!(cache.facts_for("did:web:p", true).len(), 1);
    }

    /// Per-entry fact cap: once reached, new distinct facts are dropped and
    /// markers are cleared (never a fresh marker over a set that stopped
    /// growing).
    #[test]
    fn record_success_caps_facts_and_drops_markers_at_cap() {
        let cache = RevocationCache::new();
        for i in 0..(MAX_FACTS_PER_ENTRY + 5) {
            let fp = format!("sha256:{i:064x}");
            let r = rev(&fp, RevocationTrustClass::ProducerSigned);
            cache.record_success(
                "reg.example",
                "did:web:p",
                RevocationTrustClass::ProducerSigned,
                &[r],
            );
        }
        assert_eq!(
            cache.facts_for("did:web:p", true).len(),
            MAX_FACTS_PER_ENTRY
        );
        assert!(!cache.marker_fresh(
            "reg.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            Duration::from_secs(3600)
        ));
    }

    /// `facts_for` filters registry-attested facts out for a
    /// producer-signed-only caller, and in for an all-trust-classes one.
    #[test]
    fn facts_for_filters_by_trust_class() {
        let cache = RevocationCache::new();
        let attested = rev("sha256:bbbb", RevocationTrustClass::RegistryAttested);
        cache.record_success(
            "reg.example",
            "did:web:p",
            RevocationTrustClass::RegistryAttested,
            &[attested],
        );
        assert!(cache.facts_for("did:web:p", false).is_empty());
        assert_eq!(cache.facts_for("did:web:p", true).len(), 1);
    }

    /// Markers are per-vantage: minting one for authority A does not make
    /// `marker_fresh` true for authority B.
    #[test]
    fn markers_are_per_vantage() {
        let cache = RevocationCache::new();
        cache.record_success(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            &[],
        );
        assert!(cache.marker_fresh(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            Duration::from_secs(60)
        ));
        assert!(!cache.marker_fresh(
            "b.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            Duration::from_secs(60)
        ));
    }

    /// Markers are per trust class too.
    #[test]
    fn markers_are_per_trust_class() {
        let cache = RevocationCache::new();
        cache.record_success(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            &[],
        );
        assert!(!cache.marker_fresh(
            "a.example",
            "did:web:p",
            RevocationTrustClass::RegistryAttested,
            Duration::from_secs(60)
        ));
    }

    /// `freshness: ZERO` never reports a marker as fresh, regardless of how
    /// recently it was minted.
    #[test]
    fn zero_freshness_never_suppresses() {
        let cache = RevocationCache::new();
        cache.record_success(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            &[],
        );
        assert!(!cache.marker_fresh(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            Duration::ZERO
        ));
    }

    /// AC10: eviction cannot desync — an evicted entry loses its fact and
    /// its marker TOGETHER, never one without the other. Whole-entry
    /// eviction (`record_success`'s capacity check keys on the outer
    /// `agent_id` map, never on facts/markers separately) makes this
    /// unrepresentable rather than merely guarded: insert one more
    /// distinct producer than `MAX_CACHE_ENTRIES` allows and confirm
    /// fact-presence and marker-presence agree for every surviving and
    /// evicted entry alike.
    #[test]
    fn eviction_at_capacity_removes_facts_and_markers_together() {
        let cache = RevocationCache::new();
        for i in 0..MAX_CACHE_ENTRIES {
            let agent = format!("did:web:p{i}");
            let fp = format!("sha256:{i:064x}");
            cache.record_success(
                "reg.example",
                &agent,
                RevocationTrustClass::ProducerSigned,
                &[rev(&fp, RevocationTrustClass::ProducerSigned)],
            );
        }
        for i in 0..MAX_CACHE_ENTRIES {
            let agent = format!("did:web:p{i}");
            assert_eq!(
                cache.facts_for(&agent, true).len(),
                1,
                "entry {i} must have its fact before eviction pressure"
            );
        }

        // One more distinct entry forces capacity-triggered eviction of
        // some existing entry.
        let overflow_agent = "did:web:overflow";
        cache.record_success(
            "reg.example",
            overflow_agent,
            RevocationTrustClass::ProducerSigned,
            &[rev(
                "sha256:overff0000000000000000000000000000000000000000000000000000000",
                RevocationTrustClass::ProducerSigned,
            )],
        );

        let mut evicted = 0;
        for i in 0..MAX_CACHE_ENTRIES {
            let agent = format!("did:web:p{i}");
            let has_fact = !cache.facts_for(&agent, true).is_empty();
            let has_marker = cache.marker_fresh(
                "reg.example",
                &agent,
                RevocationTrustClass::ProducerSigned,
                Duration::from_secs(3600),
            );
            assert_eq!(
                has_fact, has_marker,
                "entry {i}: fact presence ({has_fact}) and marker presence \
                 ({has_marker}) must never disagree — eviction must remove both \
                 together, never a fresh marker over an emptied fact set"
            );
            if !has_fact {
                evicted += 1;
            }
        }
        assert_eq!(
            evicted, 1,
            "capacity-triggered eviction must remove exactly one existing entry \
             to make room for the new one"
        );
        assert!(
            !cache.facts_for(overflow_agent, true).is_empty(),
            "the newly-inserted entry must itself survive"
        );
    }
}
