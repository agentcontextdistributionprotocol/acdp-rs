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
//!   default 300 s — RFC-ACDP-0014 §8's RECOMMENDED bound), per-vantage,
//!   per-trust-class, and read via `RevocationCache::fresh_marker`
//!   (crate-private) — the only
//!   method in this module that can cause a lookup to be skipped rather
//!   than merely supplemented.
//!
//! **The two objects are stored separately and have different lifetimes**
//! (0.15.0, RFC-ACDP-0014 §8 "Caching", 0.5.0):
//!
//! - Facts are **never evicted**. A fact can only leave the cache with the
//!   cache itself. Admission is capped per producer
//!   ([`MAX_FACTS_PER_CLASS`] per trust class, and per origin for the
//!   registry-attested class); a fact refused at the cap still applies to
//!   the call that found it, and the capped slot stops minting markers so
//!   that lookup runs in full on every later call rather than claiming a
//!   completeness the cache can no longer track.
//! - Markers live in a bounded map ([`MAX_MARKERS`]). Losing a marker only
//!   costs a re-discovery, so the oldest is evicted at capacity. Each one
//!   records the wall-clock time the absence was observed, which the
//!   verdict reports (`RevocationVerdict::NotRevoked::observed_at`).
//!
//! Only a complete, untruncated lookup mints a marker. Every `unknown`
//! outcome (truncated, unanswerable, transient, unverifiable candidate)
//! returns `Err` before `record_success` is reached, so `unknown` is never
//! cached as not-revoked.
//!
//! **Never call anything here holding the lock across an `.await`** — every
//! method in this module is synchronous and returns before its caller does
//! any network I/O.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use acdp_types::revocation::{KeyRevocation, RevocationTrustClass};

/// Bound on the number of freshness markers held. Markers are a pure
/// optimization, so at capacity the oldest one is evicted.
pub const MAX_MARKERS: usize = 4096;

/// Admission cap on stored facts per producer for the producer-signed
/// class, and per `(producer, origin)` for the registry-attested class.
/// Reached only by a producer with a genuinely large revocation history, or
/// a registry padding results. Stored facts are never removed; a fact
/// refused here still applies to the call that found it, and the slot stops
/// minting markers.
pub const MAX_FACTS_PER_CLASS: usize = 256;

/// A cached, verified [`KeyRevocation`] plus the vantage that minted it.
///
/// The origin is consulted only for
/// [`RevocationTrustClass::RegistryAttested`] facts — `facts_for` filters
/// those to `origin == current vantage`, per RFC-ACDP-0014 §6 ("apply it
/// ... for contexts served by or receipted by that same registry"). A
/// [`RevocationTrustClass::ProducerSigned`] fact is self-contained (§8) and
/// is never filtered by origin.
#[derive(Clone)]
struct StoredFact {
    rev: KeyRevocation,
    /// The [`crate::RegistryClient::authority`] whose complete discovery
    /// stored this fact.
    origin: String,
}

/// One producer's verified facts. Never evicted.
#[derive(Default)]
struct FactSet {
    facts: Vec<StoredFact>,
    /// The producer-signed slot reached [`MAX_FACTS_PER_CLASS`].
    producer_signed_full: bool,
    /// Origins whose registry-attested slot reached [`MAX_FACTS_PER_CLASS`].
    attested_full: HashSet<String>,
}

impl FactSet {
    fn count(&self, class: RevocationTrustClass, origin: &str) -> usize {
        self.facts
            .iter()
            .filter(|f| {
                f.rev.trust_class == class
                    && (class == RevocationTrustClass::ProducerSigned || f.origin == origin)
            })
            .count()
    }

    fn full(&self, class: RevocationTrustClass, origin: &str) -> bool {
        match class {
            RevocationTrustClass::ProducerSigned => self.producer_signed_full,
            RevocationTrustClass::RegistryAttested => self.attested_full.contains(origin),
        }
    }

    fn mark_full(&mut self, class: RevocationTrustClass, origin: &str) {
        match class {
            RevocationTrustClass::ProducerSigned => self.producer_signed_full = true,
            RevocationTrustClass::RegistryAttested => {
                self.attested_full.insert(origin.to_string());
            }
        }
    }
}

/// `(agent_id, authority, is_registry_attested)`. Never keyed by the search
/// identity the registry-attested lookup uses internally (that would let
/// one marker suppress discovery for every producer at that registry).
type MarkerKey = (String, String, bool);

/// A cached complete absence: when it was observed, on both clocks.
#[derive(Clone, Copy)]
struct Marker {
    /// Monotonic — drives the freshness comparison.
    minted: Instant,
    /// Wall clock — reported as the verdict's `observed_at`.
    observed: SystemTime,
}

#[derive(Default)]
struct Inner {
    facts: HashMap<String, FactSet>,
    markers: HashMap<MarkerKey, Marker>,
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
/// `Clone`, cheap (an `Arc` handle). Sharing one clone across multiple
/// `RegistryClient`s (or a `CrossRegistryResolver`'s per-authority clients)
/// is the point: it is how a caller amortizes discovery across many
/// verifications of the same producer.
///
/// Facts (verified revocations) are held for the cache's lifetime and are
/// always unioned into classification. Markers (complete absences) suppress
/// a lookup only while younger than
/// [`RevocationDiscovery::freshness`](crate::RevocationDiscovery::freshness)
/// — 300 s from both named constructors
/// ([`crate::RECOMMENDED_NEGATIVE_FRESHNESS`]), `Duration::ZERO` to never
/// suppress.
#[derive(Clone)]
pub struct RevocationCache {
    inner: Arc<Mutex<Inner>>,
}

impl RevocationCache {
    /// A new, empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Recover from a poisoned lock rather than propagate the panic. Used
    /// only by the fact read/write paths, where recovering can at worst
    /// tighten a verdict or cost an extra write — never skip a lookup.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Read cached facts for `agent_id`, filtered to the trust classes the
    /// CURRENT discovery configuration opted into, with the vantage each
    /// was first verified at. A registry-attested fact is additionally
    /// filtered to `origin == current_vantage` (§6); `current_vantage:
    /// None` excludes every registry-attested fact. A producer-signed fact
    /// is never filtered by origin (§8).
    pub(crate) fn facts_for(
        &self,
        agent_id: &str,
        include_registry_attested: bool,
        current_vantage: Option<&str>,
    ) -> Vec<(KeyRevocation, String)> {
        let inner = self.lock();
        let Some(set) = inner.facts.get(agent_id) else {
            return Vec::new();
        };
        set.facts
            .iter()
            .filter(|f| match f.rev.trust_class {
                RevocationTrustClass::ProducerSigned => true,
                RevocationTrustClass::RegistryAttested => {
                    include_registry_attested && current_vantage.is_some_and(|v| v == f.origin)
                }
            })
            .map(|f| (f.rev.clone(), f.origin.clone()))
            .collect()
    }

    /// When a marker for `(authority, agent_id, class)` is younger than
    /// `freshness`, the wall-clock time its absence was observed; else
    /// `None`. The only method that can cause a lookup to be skipped.
    /// `freshness == Duration::ZERO` never touches the lock.
    ///
    /// A poisoned lock returns `None` (run discovery) rather than recover
    /// a marker present at poison time.
    pub(crate) fn fresh_marker(
        &self,
        authority: &str,
        agent_id: &str,
        class: RevocationTrustClass,
        freshness: Duration,
    ) -> Option<SystemTime> {
        if freshness.is_zero() {
            return None;
        }
        let inner = self.inner.lock().ok()?;
        let key = (
            agent_id.to_string(),
            authority.to_string(),
            class_key(class),
        );
        inner
            .markers
            .get(&key)
            .filter(|m| m.minted.elapsed() < freshness)
            .map(|m| m.observed)
    }

    /// Whether a fresh marker exists — `fresh_marker(..).is_some()`.
    #[cfg(test)]
    fn marker_fresh(
        &self,
        authority: &str,
        agent_id: &str,
        class: RevocationTrustClass,
        freshness: Duration,
    ) -> bool {
        self.fresh_marker(authority, agent_id, class, freshness)
            .is_some()
    }

    /// Record a complete, untruncated discovery lookup: admit new `facts`
    /// (dedup via `KeyRevocation`'s `Eq`) and, unless this slot is at its
    /// admission cap, mint a marker for `(authority, agent_id, class)`.
    ///
    /// Called ONLY from the tail of `find_revocations` /
    /// `find_registry_attested_revocations`, immediately before each
    /// returns `Ok` — a truncated, failed, or otherwise `unknown` lookup
    /// returns early and never reaches here, so it can neither mint a
    /// marker nor lose a fact.
    pub(crate) fn record_success(
        &self,
        authority: &str,
        agent_id: &str,
        class: RevocationTrustClass,
        facts: &[KeyRevocation],
    ) {
        let mut inner = self.lock();
        let set = inner.facts.entry(agent_id.to_string()).or_default();
        for f in facts {
            // Dedup BEFORE the cap: re-finding a known fact must never trip
            // the cap.
            if set.facts.iter().any(|existing| existing.rev == *f) {
                continue;
            }
            let fact_origin = authority;
            if set.count(f.trust_class, fact_origin) >= MAX_FACTS_PER_CLASS {
                set.mark_full(f.trust_class, fact_origin);
                continue;
            }
            set.facts.push(StoredFact {
                rev: f.clone(),
                origin: fact_origin.to_string(),
            });
        }
        let full = set.full(class, authority);
        let key = (
            agent_id.to_string(),
            authority.to_string(),
            class_key(class),
        );
        if full {
            inner.markers.remove(&key);
            return;
        }
        if !inner.markers.contains_key(&key) && inner.markers.len() >= MAX_MARKERS {
            if let Some(oldest) = inner
                .markers
                .iter()
                .min_by_key(|(_, m)| m.minted)
                .map(|(k, _)| k.clone())
            {
                inner.markers.remove(&oldest);
            }
        }
        inner.markers.insert(
            key,
            Marker {
                minted: Instant::now(),
                observed: SystemTime::now(),
            },
        );
    }

    /// Test-only introspection: the number of facts stored for `agent_id`,
    /// unfiltered by trust class or origin.
    #[doc(hidden)]
    #[cfg(feature = "test-transport")]
    #[must_use]
    pub fn fact_count(&self, agent_id: &str) -> usize {
        self.lock().facts.get(agent_id).map_or(0, |s| s.facts.len())
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
            ctx_id: None,
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

    /// Admission cap: once a producer-signed slot is full, new distinct
    /// facts are not admitted, already-stored ones stay, and the slot
    /// stops minting markers (never a fresh marker over a set that stopped
    /// growing).
    #[test]
    fn record_success_caps_admission_and_drops_markers_at_cap() {
        let cache = RevocationCache::new();
        for i in 0..(MAX_FACTS_PER_CLASS + 5) {
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
            MAX_FACTS_PER_CLASS
        );
        assert!(!cache.marker_fresh(
            "reg.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            Duration::from_secs(3600)
        ));
    }

    /// A full registry-attested slot at one origin does not stop markers
    /// for the producer-signed class or for another origin.
    #[test]
    fn attested_cap_is_per_origin() {
        let cache = RevocationCache::new();
        for i in 0..=MAX_FACTS_PER_CLASS {
            let fp = format!("sha256:{i:064x}");
            cache.record_success(
                "a.example",
                "did:web:p",
                RevocationTrustClass::RegistryAttested,
                &[rev(&fp, RevocationTrustClass::RegistryAttested)],
            );
        }
        let fresh = |auth: &str, class| {
            cache.marker_fresh(auth, "did:web:p", class, Duration::from_secs(3600))
        };
        assert!(!fresh("a.example", RevocationTrustClass::RegistryAttested));
        cache.record_success(
            "b.example",
            "did:web:p",
            RevocationTrustClass::RegistryAttested,
            &[],
        );
        cache.record_success(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            &[],
        );
        assert!(fresh("b.example", RevocationTrustClass::RegistryAttested));
        assert!(fresh("a.example", RevocationTrustClass::ProducerSigned));
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

    /// RFC-ACDP-0014 §8 "Caching" (0.5.0): verified revocations are
    /// retained for the cache's lifetime — marker pressure evicts markers
    /// only, never a fact, and facts are stored separately from markers.
    #[test]
    fn facts_are_never_evicted_by_marker_pressure() {
        let cache = RevocationCache::new();
        let revoked = rev(
            "sha256:aaaa000000000000000000000000000000000000000000000000000000000000",
            RevocationTrustClass::ProducerSigned,
        );
        cache.record_success(
            "reg.example",
            "did:web:revoked",
            RevocationTrustClass::ProducerSigned,
            std::slice::from_ref(&revoked),
        );
        // Far more distinct producers than the marker bound.
        for i in 0..(MAX_MARKERS * 2) {
            cache.record_success(
                "reg.example",
                &format!("did:web:p{i}"),
                RevocationTrustClass::ProducerSigned,
                &[],
            );
        }
        let facts = cache.facts_for("did:web:revoked", false, None);
        assert_eq!(facts.len(), 1, "the verified revocation must survive");
        assert_eq!(facts[0].0, revoked);
        assert_eq!(facts[0].1, "reg.example");
        // Its marker was the oldest, so it went — the absence is
        // re-discovered, the fact is not forgotten.
        assert!(!cache.marker_fresh(
            "reg.example",
            "did:web:revoked",
            RevocationTrustClass::ProducerSigned,
            Duration::from_secs(3600)
        ));
        assert!(cache.lock().markers.len() <= MAX_MARKERS);
    }

    /// Marker eviction removes the oldest marker.
    #[test]
    fn marker_eviction_removes_oldest() {
        let cache = RevocationCache::new();
        for i in 0..=MAX_MARKERS {
            cache.record_success(
                "reg.example",
                &format!("did:web:p{i}"),
                RevocationTrustClass::ProducerSigned,
                &[],
            );
        }
        let fresh = |agent: &str| {
            cache.marker_fresh(
                "reg.example",
                agent,
                RevocationTrustClass::ProducerSigned,
                Duration::from_secs(3600),
            )
        };
        assert!(!fresh("did:web:p0"));
        assert!(fresh("did:web:p1"));
        assert!(fresh(&format!("did:web:p{MAX_MARKERS}")));
    }

    /// The observed wall-clock time is reported with a fresh marker.
    #[test]
    fn fresh_marker_reports_observed_time() {
        let cache = RevocationCache::new();
        let before = SystemTime::now();
        cache.record_success(
            "a.example",
            "did:web:p",
            RevocationTrustClass::ProducerSigned,
            &[],
        );
        let after = SystemTime::now();
        let observed = cache
            .fresh_marker(
                "a.example",
                "did:web:p",
                RevocationTrustClass::ProducerSigned,
                Duration::from_secs(60),
            )
            .expect("fresh");
        assert!(observed >= before && observed <= after);
    }
}
