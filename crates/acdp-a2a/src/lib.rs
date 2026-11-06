//! # acdp-a2a — A2A artifact provenance (RFC-ACDP-0022, 0.5.0 Draft)
//!
//! An A2A server agent publishes each artifact it completes as a body it
//! signs itself, and returns the `acdp://` link inside the artifact.
//! Anyone who later holds the artifact can prove that the agent
//! published exactly this content, check whether it has since been
//! superseded or retracted, and follow its inputs.
//!
//! **Agent side** (profile `acdp-producer-a2a`):
//!
//! - [`assembly`] assembles each artifact from its chunks, or from a
//!   terminal Task snapshot (§4.2), and reopens it on re-emission (§4.3);
//! - [`record`] builds the closed `acdp-a2a-artifact/1` record at
//!   `metadata["acdp:a2a"]` of a body of the agent's own type, with the
//!   salted hashes (§5), embedding (§5.3), `url` part DataRefs (§5.4)
//!   and the optional `a2a.artifact` anchor (§10), and signs it;
//! - [`inputs`] turns `Message.metadata["io.acdp/inputs"]` into
//!   `derived_from` (§7);
//! - [`link`] is the `Artifact.metadata["io.acdp/provenance"]` value and
//!   its fail-open form (§6);
//! - [`agent`] runs it end to end: publish (with the Idempotency-Key)
//!   before the completing chunk is emitted, supersede on re-emission,
//!   fail open by default.
//!
//! **Holder side** (profile `acdp-consumer-a2a`): [`verify`] runs §8
//! against the retrieved body, with the [`card`] pointer
//! `https://acdp.io/ext/a2a/v1` as an untrusted hint and the AITP key
//! binding (§3.1).
//!
//! Nothing here adds to ACDP's trust machinery (§3.2): a re-emission is
//! an ordinary `supersedes`, a continuation an ordinary `derived_from`,
//! and the agent is verified like any `did:web` or `did:key` producer.
//! A verified body is authored content, never an accepted result (§11).

pub mod agent;
pub mod assembly;
pub mod card;
pub mod hash;
pub mod inputs;
pub mod link;
pub mod parts;
pub mod record;
pub mod verify;

pub use agent::{Agent, ArtifactHints, ArtifactPolicy, ChunkOutput, TaskOutput, TaskSession};
pub use hash::Salt;
pub use record::BodyTemplate;
pub use verify::{FailureKind, HeldArtifact, HolderPolicy, HolderVerdict, VerifyFailure};

/// The agent-side profile identifier (RFC-ACDP-0022 §12.1).
pub const PRODUCER_PROFILE: &str = "acdp-producer-a2a";
/// The holder-side profile identifier (RFC-ACDP-0022 §12.2).
pub const CONSUMER_PROFILE: &str = "acdp-consumer-a2a";
