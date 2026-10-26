//! # acdp-mcp-proxy — the MCP signing proxy (RFC-ACDP-0019, Draft)
//!
//! Sits between an MCP client and any stdio MCP server, relays every
//! message unchanged, and for each `tools/call` publishes one signed
//! `acdp:mcp-tool-result` body to an ACDP registry under the operator's
//! own key. The result goes back to the client with one `_meta` key
//! added, `io.acdp/provenance`, linking it to that record.
//!
//! - [`record`] builds the body: salted call hashes (§4.3), the
//!   `derived_from` extraction (§4.4), the embedding allowlist (§5).
//! - [`provenance`] is the `_meta` value and the §7 failure forms.
//! - [`relay`] is the newline-delimited JSON-RPC relay.
//! - [`config`] is the operator's config file.
//!
//! The proxy is the producer: its signature says *the operator observed
//! this call and this result*, never that the upstream server vouches
//! for it (§3). Consumers scope trust per proxy `agent_id`.

pub mod config;
pub mod provenance;
pub mod record;
pub mod relay;

pub use config::Config;
pub use relay::Proxy;
