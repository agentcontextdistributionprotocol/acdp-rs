//! # acdp-producer — publish-request builder for the Agent Context Distribution Protocol
//!
//! [`Producer`] and [`RequestBuilder`] construct, validate, hash, and sign
//! a [`acdp_types::PublishRequest`] per RFC-ACDP-0001 §5. The builder
//! enforces the v1-vs-v2+ rules, ms-truncates timestamps, runs structural
//! validation, computes `content_hash`, then signs.

pub mod builder;
#[cfg(feature = "keyless")]
pub mod keyless;

pub use builder::{Producer, RequestBuilder};
