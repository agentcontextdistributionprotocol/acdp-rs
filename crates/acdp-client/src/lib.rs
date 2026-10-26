//! # acdp-client — consumer client for the Agent Context Distribution Protocol
//!
//! Implements the `acdp-consumer` profile: [`RegistryClient`]
//! (publish/retrieve/search/capabilities with RFC-aligned timeouts, body
//! caps, and same-authority redirect limits), [`VerifiedContext`]
//! (one-shot fetch + verify), [`CrossRegistryResolver`] (RFC-ACDP-0006
//! §4.1), and DataRef fetching with hash verification.

pub mod auth;
#[cfg(feature = "blocking")]
pub mod blocking;
pub mod cross_registry;
pub mod data_ref;
pub mod log;
pub mod recall;
pub mod receipt;
pub mod registry;
pub mod revocation;
pub mod revocation_cache;
pub mod revocation_verdict;
pub mod transparency;
pub mod trust;
pub mod verified;
pub mod witness;

pub use auth::{AuthFuture, AuthProvider, BearerToken, PerAuthorityTokens, StaticBearerToken};
pub use cross_registry::{CrossRegistryResolver, ResolverOptions};
pub use data_ref::{
    fetch_and_verify_data_ref, DataRefFetcher, HttpsDataRefFetcher, DEFAULT_MAX_BYTES,
};
pub use log::{verify_log_checkpoint_value, verify_log_inclusion_value};
pub use recall::{
    verify_change, ChangeEffect, ChangeFeed, ChangeVerdict, HeldContext, LifecycleSource,
    SeenChanges, Since,
};
pub use receipt::{
    verify_event_receipt_value, verify_lineage_head_receipt_value, verify_receipt_value,
    verify_receipt_value_since, verify_receipt_value_with_status_since,
};
pub use registry::{RegistryClient, RegistryClientBuilder, ACDP_ACCEPT};
pub use revocation::{
    classify_under_revocation, classify_under_revocation_placed,
    find_registry_attested_revocations, find_revocations, find_revocations_in_lineage,
    verify_revocation_body, verify_revocation_candidate, verify_revocation_context,
};
pub use revocation_cache::RevocationCache;
pub use revocation_verdict::{
    find_revocations_verdict, RevocationAssessment, RevocationEffect, RevocationRefusal,
    RevocationSource, RevocationVerdict, SourcedRevocation, UnknownReason,
    RECOMMENDED_NEGATIVE_FRESHNESS,
};
pub use transparency::{
    CannotVerifyReason, LogInclusionPolicy, LogInclusionVerdict, WitnessEnforcement,
    WitnessQuorumPolicy, DEFAULT_LOG_MAX_CLOCK_SKEW_SECONDS,
};
pub use verified::{
    DiscoveryFailurePolicy, DiscoveryOutcome, HistoricalKeyPolicy, KeyAuthorization,
    LineageHeadPolicy, ReceiptPolicy, RevocationDiscovery, RevocationPolicy, VerificationPolicy,
    VerificationReport, VerifiedContext,
};
pub use witness::{
    evaluate_witness_quorum, mint_cosignature_checked, verify_witness_cosignature_value,
    WitnessConsistencyCheck, WitnessPolicy, WitnessQuorumReport, DEFAULT_WITNESS_MAX_AGE_SECONDS,
    DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECONDS,
};
