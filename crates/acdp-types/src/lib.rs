//! # acdp-types — wire types for the Agent Context Distribution Protocol
//!
//! The protocol's JSON wire shapes: the immutable [`body::Body`],
//! [`publish::PublishRequest`]/[`publish::PublishResponse`], data
//! references, capabilities documents, registry receipts, and search
//! parameters/results — plus the [`profile`] vocabulary. The opaque
//! identifier primitives and error vocabulary live in
//! [`acdp-primitives`](https://docs.rs/acdp-primitives) and are re-exported
//! here under the historical `primitives` path.

pub mod anchor;
pub mod body;
pub mod capabilities;
pub mod change;
pub mod cosignature;
pub mod data_ref;
pub mod event_receipt;
pub mod keyless;
pub mod lifecycle;
pub mod log;
pub mod profile;
pub mod publish;
pub mod receipt;
pub mod revocation;
pub mod search;
pub mod trust_list;

// `primitives` / `serde_helpers` / `wire_error` live in acdp-primitives;
// re-export so the historical `crate::types::*` paths keep resolving in the
// umbrella crate and inside this crate's own modules.
pub use acdp_primitives::primitives;
pub(crate) use acdp_primitives::serde_helpers;

pub use acdp_primitives::wire_error::{WireError, WireErrorBody};
pub use anchor::AnchorEntry;
pub use body::{Body, DataPeriod, FullContext, RegistryState, Signature};
pub use capabilities::{CapabilitiesDocument, Limits};
pub use change::{
    Change, ChangeEvidence, ChangeHint, ChangeKind, ChangesResponse, Subscription,
    SubscriptionRequest, SubscriptionStatus, WatchFilter,
};
pub use cosignature::{LogCosignature, WitnessSigner, WitnessedCheckpoint, COSIGNATURE_VERSION};
pub use data_ref::{DataRef, DataRefType, EmbeddedContent, EmbeddedEncoding, Location};
pub use event_receipt::EventReceipt;
pub use lifecycle::{LifecycleEvent, LifecycleEventType};
pub use log::{LogCheckpoint, LogConsistencyProof, LogInclusion, LogLeaf};
pub use primitives::{AgentDid, ContentHash, ContextType, CtxId, LineageId, Status, Visibility};
pub use publish::{PublishRequest, PublishResponse};
pub use receipt::{ReceiptKeyStatus, ReceiptSigner, RegistryReceipt};
pub use revocation::{KeyRevocation, RevocationTrustClass};
pub use search::{SearchParams, SearchParamsBuilder, SearchResponse, SearchResult};
