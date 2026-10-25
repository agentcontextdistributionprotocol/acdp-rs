//! Schema-level string forms shared by the evidence, options and
//! verdict types, implemented to the exact `acdp-common.schema.json`
//! patterns.

use acdp_types::primitives::CtxId;
use chrono::{DateTime, Utc};

/// Parse a timestamp in the one form RFC-ACDP-0017 accepts:
/// `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`, and a real instant.
pub(crate) fn parse_ts(raw: &str) -> Option<DateTime<Utc>> {
    let b = raw.as_bytes();
    let shape = b.len() == 24
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'.',
            23 => c == b'Z',
            _ => c.is_ascii_digit(),
        });
    if !shape {
        return None;
    }
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// The canonical rendering of an instant (three fractional digits, `Z`).
pub(crate) fn fmt_ts(t: DateTime<Utc>) -> String {
    acdp_primitives::time::fmt_rfc3339_ms(t)
}

/// `acdp-common.schema.json#/$defs/hostname`.
pub(crate) fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.iter()
                    .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

/// `acdp-common.schema.json#/$defs/did`: `^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$`,
/// 7..=2048 characters.
pub(crate) fn is_did(s: &str) -> bool {
    if s.len() < 7 || s.len() > 2048 {
        return false;
    }
    let Some(rest) = s.strip_prefix("did:") else {
        return false;
    };
    let Some((method, id)) = rest.split_once(':') else {
        return false;
    };
    !method.is_empty()
        && method
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !id.is_empty()
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:%-".contains(&c))
}

/// `acdp-common.schema.json#/$defs/ctx_id`.
pub(crate) fn is_ctx_id(s: &str) -> bool {
    CtxId::parse(s).is_ok_and(|c| c.as_str() == s)
}

/// `^sha256:[0-9a-f]{64}$`.
pub(crate) fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

/// `sha256:` + hex(SHA-256(JCS(value))): the digest form of §9.
pub(crate) fn jcs_digest<T: serde::Serialize>(value: &T) -> String {
    use sha2::{Digest, Sha256};
    let bytes = acdp_jcs::canonicalize(value).expect("verdict objects canonicalize");
    format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_form_is_exact() {
        assert!(parse_ts("2026-10-01T00:00:00.000Z").is_some());
        assert!(parse_ts("2026-10-01T00:00:00Z").is_none());
        assert!(parse_ts("2026-10-01T00:00:00.000+00:00").is_none());
        assert!(parse_ts("2026-13-01T00:00:00.000Z").is_none());
    }

    #[test]
    fn hostname_and_did_patterns() {
        assert!(is_hostname("registry.example.com"));
        assert!(!is_hostname("Registry.example.com"));
        assert!(!is_hostname("-a.example.com"));
        assert!(!is_hostname("did:web:x"));
        assert!(is_did("did:web:agents.example.com:test-producer"));
        assert!(is_did(
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        ));
        assert!(!is_did("did:web:x#frag"));
        assert!(!is_did("did:Web:x.example"));
    }
}
