//! # acdp-client — consumer client for the Agent Context Distribution Protocol
//!
//! Implements the `acdp-consumer` profile: [`RegistryClient`]
//! (publish/retrieve/search/capabilities with RFC-aligned timeouts, body
//! caps, and same-authority redirect limits), [`VerifiedContext`]
//! (one-shot fetch + verify), [`CrossRegistryResolver`] (RFC-ACDP-0006
//! §4.1), and DataRef fetching with hash verification.

pub mod cross_registry;
pub mod data_ref;
pub mod log;
pub mod receipt;
pub mod registry;
pub mod revocation;
pub mod verified;
pub mod witness;

pub use cross_registry::{CrossRegistryResolver, ResolverOptions};
pub use data_ref::{
    fetch_and_verify_data_ref, DataRefFetcher, HttpsDataRefFetcher, DEFAULT_MAX_BYTES,
};
pub use log::{verify_log_checkpoint_value, verify_log_inclusion_value};
pub use receipt::{verify_lineage_head_receipt_value, verify_receipt_value};
pub use registry::{RegistryClient, RegistryClientBuilder};
pub use revocation::{
    classify_under_revocation, find_registry_attested_revocations, find_revocations,
    find_revocations_in_lineage, verify_revocation_body,
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
