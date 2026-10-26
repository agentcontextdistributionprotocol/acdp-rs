//! The operator's JSON config file.
//!
//! ```json
//! {
//!   "upstream": {
//!     "command": "npx",
//!     "args": ["-y", "@example/fraud-stats-mcp@1.4.2", "--token", "s3cret"],
//!     "env": { "FRAUD_API_KEY": "..." },
//!     "redact_args": [3]
//!   },
//!   "registry": "https://registry.example.com",
//!   "key": { "seed_file": "/etc/acdp/proxy.seed" },
//!   "visibility": "private",
//!   "publish_timeout_ms": 15000,
//!   "max_attempts": 4,
//!   "external": { "dir": "/srv/acdp-results", "base_url": "https://results.example.com" },
//!   "default": { "fail_closed": false },
//!   "tools": {
//!     "regional_fraud_rate": { "embed": true },
//!     "transfer_funds": { "fail_closed": true }
//!   }
//! }
//! ```
//!
//! `key` is a 32-byte Ed25519 seed as 64 hex characters, read from
//! `seed_file` or the environment variable named by `seed_env`. Without
//! `did` the operator identity is the seed's `did:key`; for `did:web`
//! give `did` and `key_id`. `upstream.env` is passed to the server and
//! never enters a record; `redact_args` lists the indices of launch
//! arguments replaced by `<redacted>` before `endpoint_hash` (§4.2).

use std::{collections::HashMap, path::PathBuf, time::Duration};

use acdp::{
    client::RegistryClient,
    crypto::SigningKey,
    producer::Producer,
    types::primitives::{AgentDid, Visibility},
    AcdpError,
};
use serde::Deserialize;

use crate::{
    record::{self, BodyOptions, Embedding, Transport},
    relay::{ExternalStore, Proxy, ToolPolicy},
};

/// Top-level config file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The MCP server to launch.
    pub upstream: Upstream,
    /// Registry base URL (HTTPS).
    pub registry: String,
    /// Operator signing key.
    pub key: KeyConfig,
    /// Default `visibility` (§8.3); `private` when absent.
    #[serde(default)]
    pub visibility: Option<Visibility>,
    /// Default `audience` for `restricted`.
    #[serde(default)]
    pub audience: Vec<String>,
    /// Bound on one publish including retries, in ms (default 15000).
    #[serde(default)]
    pub publish_timeout_ms: Option<u64>,
    /// Publish attempts for transient failures (default 4).
    #[serde(default)]
    pub max_attempts: Option<u32>,
    /// Where allowlisted results over the 64 KB cap go (§5).
    #[serde(default)]
    pub external: Option<External>,
    /// Policy for tools without an entry in `tools`.
    #[serde(default)]
    pub default: ToolConfig,
    /// Per-tool policy.
    #[serde(default)]
    pub tools: HashMap<String, ToolConfig>,
}

/// Upstream stdio server.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Executable.
    pub command: String,
    /// Launch arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment for the server (never recorded).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Working directory.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Indices of `args` that carry credentials.
    #[serde(default)]
    pub redact_args: Vec<usize>,
}

/// Operator key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// File holding the 64-hex seed.
    #[serde(default)]
    pub seed_file: Option<PathBuf>,
    /// Environment variable holding the 64-hex seed.
    #[serde(default)]
    pub seed_env: Option<String>,
    /// Operator DID (`did:web`); the seed's `did:key` when absent.
    #[serde(default)]
    pub did: Option<String>,
    /// Verification method DID URL; required with `did`.
    #[serde(default)]
    pub key_id: Option<String>,
}

/// External result store.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct External {
    /// Directory the proxy writes `<hex>.json` into.
    pub dir: PathBuf,
    /// URL prefix that serves `dir`.
    pub base_url: String,
}

/// Per-tool policy as written in the file.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConfig {
    /// Do not publish records for this tool.
    #[serde(default)]
    pub skip: bool,
    /// Withhold the result when publishing fails.
    #[serde(default)]
    pub fail_closed: bool,
    /// Allowlist the result for embedding (§5).
    #[serde(default)]
    pub embed: bool,
    /// Overrides the top-level `visibility`.
    #[serde(default)]
    pub visibility: Option<Visibility>,
    /// Overrides the top-level `audience`.
    #[serde(default)]
    pub audience: Option<Vec<String>>,
}

fn bad(msg: impl Into<String>) -> AcdpError {
    AcdpError::SchemaViolation(msg.into())
}

impl Config {
    /// Parse a config file.
    pub fn load(path: &std::path::Path) -> Result<Self, AcdpError> {
        let bytes =
            std::fs::read(path).map_err(|e| bad(format!("cannot read {}: {e}", path.display())))?;
        serde_json::from_slice(&bytes).map_err(|e| bad(format!("{}: {e}", path.display())))
    }

    fn signing_key(&self) -> Result<SigningKey, AcdpError> {
        let k = &self.key;
        let hex_seed = match (&k.seed_file, &k.seed_env) {
            (Some(f), None) => std::fs::read_to_string(f)
                .map_err(|e| bad(format!("cannot read seed_file {}: {e}", f.display())))?,
            (None, Some(v)) => {
                std::env::var(v).map_err(|_| bad(format!("seed_env {v} is not set")))?
            }
            _ => return Err(bad("key: give exactly one of seed_file, seed_env")),
        };
        let seed =
            hex::decode(hex_seed.trim()).map_err(|_| bad("key seed must be 64 hex characters"))?;
        SigningKey::from_slice(&seed)
    }

    /// The operator DID every record carries as `agent_id`.
    pub fn operator_did(&self) -> Result<String, AcdpError> {
        match &self.key.did {
            Some(did) => Ok(did.clone()),
            None => Ok(acdp::did::key::did_key_from_ed25519(
                &self.signing_key()?.verifying_key_bytes(),
            )),
        }
    }

    /// The operator's producer identity.
    pub fn producer(&self) -> Result<Producer, AcdpError> {
        let key = self.signing_key()?;
        match (&self.key.did, &self.key.key_id) {
            (None, None) => Ok(Producer::new_did_key(key)),
            (Some(did), Some(key_id)) => Ok(Producer::new(key, AgentDid::new(did), key_id)),
            _ => Err(bad("key: did and key_id go together")),
        }
    }

    fn body_options(&self, t: &ToolConfig) -> Result<BodyOptions, AcdpError> {
        let audience = t
            .audience
            .as_ref()
            .unwrap_or(&self.audience)
            .iter()
            .map(AgentDid::new)
            .collect();
        Ok(BodyOptions {
            visibility: t
                .visibility
                .clone()
                .or_else(|| self.visibility.clone())
                .unwrap_or(Visibility::Private),
            audience,
            embedding: if t.embed {
                Embedding::Allowlisted {
                    external_base: self.external.as_ref().map(|e| e.base_url.clone()),
                }
            } else {
                Embedding::Never
            },
        })
    }

    fn policy(&self, t: &ToolConfig) -> Result<ToolPolicy, AcdpError> {
        Ok(ToolPolicy {
            skip: t.skip,
            fail_closed: t.fail_closed,
            body: self.body_options(t)?,
        })
    }

    /// The unsalted `endpoint_hash` of the upstream descriptor.
    pub fn endpoint_hash(&self) -> String {
        let u = &self.upstream;
        record::endpoint_hash(&record::stdio_descriptor(
            &u.command,
            &u.args,
            &u.redact_args,
        ))
    }

    /// Build the relay around `registry` (production callers pass
    /// `RegistryClient::new(&config.registry)`).
    pub fn proxy(&self, registry: RegistryClient) -> Result<Proxy, AcdpError> {
        // Consumers fetch external results under the RFC-ACDP-0008 rules.
        if let Some(e) = &self.external {
            if !e.base_url.starts_with("https://") {
                return Err(bad("external.base_url must be a public https URL"));
            }
        }
        let tools = self
            .tools
            .iter()
            .map(|(name, t)| Ok((name.clone(), self.policy(t)?)))
            .collect::<Result<_, AcdpError>>()?;
        Ok(Proxy {
            producer: self.producer()?,
            registry,
            transport: Transport::Stdio,
            endpoint_hash: self.endpoint_hash(),
            default_policy: self.policy(&self.default)?,
            tools,
            publish_timeout: Duration::from_millis(self.publish_timeout_ms.unwrap_or(15_000)),
            max_attempts: self.max_attempts.unwrap_or(4),
            external: self
                .external
                .as_ref()
                .map(|e| ExternalStore { dir: e.dir.clone() }),
        })
    }
}
