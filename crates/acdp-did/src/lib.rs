//! # acdp-did — DID resolution for the Agent Context Distribution Protocol
//!
//! `did:web` (HTTPS-resolved, SSRF-guarded, LRU-cached) and `did:key`
//! (pure) support per RFC-ACDP-0001 §5.11. v0.1.0 producers MUST use
//! `did:web`.

pub mod document;
pub mod key;
pub mod web;

pub use document::{AssertionMethodRef, DidDocument, VerificationMethod, KEYLESS_FRAGMENT_PREFIX};
pub use key::{
    did_key_document, did_key_from_ed25519, did_key_from_p256_sec1, did_key_url, resolve_did_key,
    resolve_did_key_url, DidKeyMaterial,
};
pub use web::{authority_to_did_web, did_web_to_authority, did_web_to_url};

#[cfg(feature = "client")]
pub use web::{FreshResolution, ResolvedDidDocument, WebResolver, DEFAULT_FORCED_REFRESH_INTERVAL};
