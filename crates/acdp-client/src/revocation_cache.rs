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
//!
//!   **Every stored fact carries the vantage that minted it** (its
//!   `origin`, set from `record_success`'s `authority` parameter — see
//!   `StoredFact`). RFC-ACDP-0014 §6 draws a real distinction here: a
//!   *producer-signed* fact is self-contained and "verifies identically
//!   wherever it came from" (§8), so it is never filtered by origin — this
//!   is what makes it correct for it to cross vantages (see
//!   `crate::verified`'s anti-rollback tests). A *registry-attested* fact is
//!   one specific registry's claim, and §6 licenses applying it only "for
//!   contexts served by or receipted by that same registry" — so a read
//!   filters registry-attested facts to `origin == current vantage`.
//!   Storing only `trust_class` (as an earlier revision of this cache did)
//!   answers a different question than "was this claim made by the
//!   registry now serving this context" — collapsing the two let a fact
//!   minted at a hostile or deceived registry A fail-close a producer's
//!   contexts at every OTHER authority, for the cache's lifetime: a
//!   targeted cross-registry DoS exactly bounded by §6's scoping default.
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

/// A cached, verified [`KeyRevocation`] plus the vantage that minted it.
///
/// BLOCKER-1 (fresh-Opus review of the #257/#258/#260 wave): the origin is
/// consulted only for [`RevocationTrustClass::RegistryAttested`] facts —
/// `facts_for` filters those to `origin == current vantage`, per
/// RFC-ACDP-0014 §6 ("apply it ... for contexts served by or receipted by
/// that same registry"). A [`RevocationTrustClass::ProducerSigned`] fact is
/// self-contained (§8) and is never filtered by origin regardless of what
/// this field holds.
struct StoredFact {
    rev: KeyRevocation,
    /// [`crate::RegistryClient::authority`] at the moment [`RevocationCache::record_success`]
    /// stored this fact. Both call sites (`crate::revocation::find_revocations`,
    /// `crate::revocation::find_registry_attested_revocations`) gate the
    /// call on a `Some(vantage)`, so this is always the vantage that
    /// genuinely served/attested the fact, never a placeholder.
    origin: String,
}

/// One producer/controller's cached state: verified facts (both trust
/// classes, filtered by class AND, for registry-attested facts, by origin
/// on read) plus per-vantage freshness markers.
#[derive(Default)]
struct CacheEntry {
    facts: Vec<StoredFact>,
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

/// N5: an exhaustive `match`, not `matches!`, so a future third
/// `RevocationTrustClass` variant fails to compile here instead of
/// silently aliasing onto the `ProducerSigned` marker bucket.
fn class_key(class: RevocationTrustClass) -> bool {
    match class {
        RevocationTrustClass::ProducerSigned => false,
        RevocationTrustClass::RegistryAttested => true,
    }
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
    /// BLOCKER-1: a registry-attested fact is ADDITIONALLY filtered to
    /// `origin == current_vantage` — a registry-attested claim is one
    /// specific registry's claim (§6), so a fact minted while talking to
    /// authority A must not apply while talking to a different authority
    /// B, even under `all_trust_classes()`. `current_vantage: None` (no
    /// resolvable authority on this call's client) excludes every
    /// registry-attested fact, fail-closed toward "don't apply," never
    /// toward "apply everywhere." A producer-signed fact is never filtered
    /// by origin — it is self-contained (§8) and correct to cross vantages.
    ///
    /// Returns an empty `Vec` when no entry exists yet — a cache miss is
    /// indistinguishable from "no facts found," which is correct: either
    /// way discovery proceeds unseeded.
    pub(crate) fn facts_for(
        &self,
        agent_id: &str,
        include_registry_attested: bool,
        current_vantage: Option<&str>,
    ) -> Vec<KeyRevocation> {
        let map = self.lock();
        match map.get(agent_id) {
            Some(entry) => entry
                .facts
                .iter()
                .filter(|f| match f.rev.trust_class {
                    RevocationTrustClass::ProducerSigned => true,
                    RevocationTrustClass::RegistryAttested => {
                        include_registry_attested && current_vantage.is_some_and(|v| v == f.origin)
                    }
                })
                .map(|f| f.rev.clone())
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
    ///
    /// N4: matches the raw `lock()` result directly rather than recovering
    /// via `poisoned.into_inner()` — a marker present at poison time must
    /// not suppress discovery. A poisoned lock (`Err(_)`) returns `false`
    /// unconditionally, degrading to "run discovery" (the safe direction),
    /// never to a false skip. Recovering via `into_inner` is reserved for
    /// `facts_for`/`record_success` below, where recovering can only ever
    /// tighten a verdict or cost an extra future write, never cause a
    /// false skip.
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
        let map = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => return false,
        };
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
                // N6: check for a duplicate BEFORE consulting the cap. A
                // re-discovery of facts already known must never itself
                // trip `at_cap` (and clear this entry's markers) merely
                // because the entry happens to sit exactly at the limit —
                // only a genuinely NEW fact that would overflow the cap
                // does that.
                if entry.facts.iter().any(|existing| existing.rev == *f) {
                    continue;
                }
                if entry.facts.len() >= MAX_FACTS_PER_ENTRY {
                    entry.at_cap = true;
                    break;
                }
                entry.facts.push(StoredFact {
                    rev: f.clone(),
                    origin: authority.to_string(),
                });
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

    /// Test-only introspection (MATERIAL-2, fresh-Opus review of Phase 2):
    /// the number of facts currently stored for `agent_id`, unfiltered by
    /// trust class or origin. Exists so an integration test can prove
    /// dedup holds across independently-run, real discoveries — not just
    /// across clones of one in-memory value, which is all the unit test
    /// `record_success_dedups_identical_facts` below can show.
    ///
    /// `#[doc(hidden)]` and gated behind `test-transport`, the same
    /// feature that already gates `RegistryClient::with_test_endpoint` for
    /// exactly this reason: a tiny, harmless, read-only accessor that must
    /// never be mistaken for part of the real public surface.
    #[doc(hidden)]
    #[cfg(feature = "test-transport")]
    #[must_use]
    pub fn fact_count(&self, agent_id: &str) -> usize {
        self.lock().get(agent_id).map_or(0, |e| e.facts.len())
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
        assert_eq!(
            cache
                .facts_for("did:web:p", true, Some("reg.example"))
                .len(),
            1
        );
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
            cache
                .facts_for("did:web:p", true, Some("reg.example"))
                .len(),
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
    /// producer-signed-only caller, and in for an all-trust-classes one
    /// reading from the SAME vantage that minted the fact.
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
        assert!(cache
            .facts_for("did:web:p", false, Some("reg.example"))
            .is_empty());
        assert_eq!(
            cache
                .facts_for("did:web:p", true, Some("reg.example"))
                .len(),
            1
        );
    }

    /// BLOCKER-1: a registry-attested fact minted at vantage A must NOT be
    /// returned when reading at a DIFFERENT vantage B, even under
    /// `include_registry_attested: true` — RFC-ACDP-0014 §6 scopes a
    /// registry-attested claim to the registry that made it. `None` (no
    /// resolvable vantage on the reading call) must behave the same as a
    /// mismatched vantage: exclude the fact, never include it.
    #[test]
    fn facts_for_filters_registry_attested_facts_by_origin() {
        let cache = RevocationCache::new();
        let attested = rev("sha256:cccc", RevocationTrustClass::RegistryAttested);
        cache.record_success(
            "a.example",
            "did:web:p",
            RevocationTrustClass::RegistryAttested,
            &[attested],
        );
        assert_eq!(
            cache.facts_for("did:web:p", true, Some("a.example")).len(),
            1,
            "reading from the SAME vantage that minted the fact must include it"
        );
        assert!(
            cache
                .facts_for("did:web:p", true, Some("b.example"))
                .is_empty(),
            "reading from a DIFFERENT vantage must exclude a registry-attested fact"
        );
        assert!(
            cache.facts_for("did:web:p", true, None).is_empty(),
            "reading with no resolvable current vantage must exclude a registry-attested \
             fact, not include it by default"
        );
    }

    /// BLOCKER-1's other direction: a producer-signed fact is
    /// self-contained (RFC-ACDP-0014 §8) and is NEVER filtered by origin —
    /// it must be returned when read from a vantage other than the one
    /// that minted it.
    #[test]
    fn facts_for_never_filters_producer_signed_facts_by_origin() {
        let cache = RevocationCache::new();
        let signed = rev("sha256:dddd", RevocationTrustClass::ProducerSigned);
        cache.record_success(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            &[signed],
        );
        assert_eq!(
            cache.facts_for("did:web:p", false, Some("b.example")).len(),
            1
        );
        assert_eq!(cache.facts_for("did:web:p", false, None).len(), 1);
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
                cache.facts_for(&agent, true, Some("reg.example")).len(),
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
            let has_fact = !cache
                .facts_for(&agent, true, Some("reg.example"))
                .is_empty();
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
            !cache
                .facts_for(overflow_agent, true, Some("reg.example"))
                .is_empty(),
            "the newly-inserted entry must itself survive"
        );
    }
}
