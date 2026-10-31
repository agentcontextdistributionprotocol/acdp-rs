//! Rate-limiting hook for [`RegistryServer`](super::server::RegistryServer)
//! (RFC-ACDP-0008 §4.3).
//!
//! The protocol does not prescribe a specific algorithm — token bucket,
//! sliding window, per-tenant quotas are all conformant. This trait lets
//! a registry plug a policy in without the core library taking a
//! dependency on a specific store. The default [`NoopRateLimiter`] is a
//! pass-through and is wired into
//! [`RegistryServer`](super::server::RegistryServer) unless the operator
//! supplies their own.
//!
//! Rate-limit decisions surface as [`AcdpError::RateLimited`], which
//! `from_wire_error` maps to the `rate_limited` wire code
//! (RFC-ACDP-0007 §5).

use acdp_primitives::error::AcdpError;
use acdp_types::primitives::AgentDid;

/// Implement this trait to plug a rate-limiting policy into
/// [`RegistryServer`](super::server::RegistryServer).
///
/// `check_publish` is called BEFORE expensive operations (DID resolution,
/// signature verification, persistence). Returning
/// `Err(AcdpError::RateLimited { .. })` stops the publish flow; any other
/// error is propagated as-is.
pub trait RateLimiter: Send + Sync {
    /// Check whether `agent_id` may publish right now. The default impl
    /// is a no-op so a plain `RegistryServer<S>` compiles without
    /// requiring callers to wire a limiter.
    fn check_publish(&self, _agent_id: &AgentDid) -> Result<(), AcdpError> {
        Ok(())
    }
}

/// Default pass-through limiter — every publish is allowed.
///
/// Construct via `NoopRateLimiter` or use `RegistryServer::default_limiter()`
/// implicitly.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRateLimiter;

impl RateLimiter for NoopRateLimiter {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: the noop limiter accepts every call.
    #[test]
    fn noop_accepts_every_publish() {
        let n = NoopRateLimiter;
        n.check_publish(&AgentDid::new("did:web:agents.example.com:test"))
            .unwrap();
    }

    /// A test-only limiter that rejects a specific agent — used by the
    /// `RegistryServer` integration tests to exercise the
    /// `AcdpError::RateLimited` branch.
    struct DenyAgent {
        deny: String,
    }
    impl RateLimiter for DenyAgent {
        fn check_publish(&self, agent_id: &AgentDid) -> Result<(), AcdpError> {
            if agent_id.as_str() == self.deny {
                Err(AcdpError::rate_limited(
                    format!("deny-list: {}", agent_id),
                    None,
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn deny_agent_blocks_listed_did() {
        let l = DenyAgent {
            deny: "did:web:agents.example.com:noisy".into(),
        };
        let err = l
            .check_publish(&AgentDid::new("did:web:agents.example.com:noisy"))
            .unwrap_err();
        assert!(matches!(err, AcdpError::RateLimited { .. }));
        l.check_publish(&AgentDid::new("did:web:agents.example.com:quiet"))
            .unwrap();
    }
}
