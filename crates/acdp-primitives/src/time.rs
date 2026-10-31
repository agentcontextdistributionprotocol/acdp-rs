//! Time helpers shared by the producer builder and search-params formatter.
//!
//! ACDP timestamps in publish requests are part of the JCS-canonicalized
//! body (RFC-ACDP-0001 §5.3). Producers MUST emit canonical millisecond
//! precision so the resulting `content_hash` is reproducible across
//! implementations. `chrono::DateTime<Utc>` defaults to nanosecond
//! precision; this module centralizes the truncation and the canonical
//! string format used everywhere on the producer path.

use chrono::{DateTime, Utc};

/// Truncate to millisecond precision per RFC-ACDP-0001 §5.3.
///
/// Returns the input unchanged if `timestamp_millis()` cannot round-trip
/// (extremely far-future timestamps).
pub fn trunc_ms(dt: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(dt.timestamp_millis()).unwrap_or(dt)
}

/// Format as the canonical RFC 3339 string with explicit `Z` suffix
/// and millisecond precision, e.g. `2026-04-16T10:30:15.123Z`.
pub fn fmt_rfc3339_ms(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Render a timestamp in canonical form when it is representable, and
/// losslessly otherwise.
///
/// A millisecond-aligned instant (every value the producer path emits,
/// since [`trunc_ms`] runs first) is rendered with exactly three
/// fractional digits — `…:59.000Z`, never chrono's default `…:59Z`
/// (RFC-ACDP-0001 §5.3 "MUST emit timestamps in canonical form";
/// spec fixture `can-013`). A finer-grained instant received on input
/// (`can-006` nanosecond, `can-012` microsecond) keeps its full
/// precision so a typed re-serialization does not silently truncate it.
pub fn fmt_rfc3339_canonical(dt: DateTime<Utc>) -> String {
    if dt.timestamp_subsec_nanos().is_multiple_of(1_000_000) {
        fmt_rfc3339_ms(dt)
    } else {
        dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    }
}

/// `#[serde(with = "…")]` adapter emitting [`fmt_rfc3339_canonical`].
/// Deserialization accepts any RFC 3339 date-time (§5.3 "MUST accept
/// any valid RFC 3339 date-time on input").
pub mod canonical_rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize in canonical form.
    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::fmt_rfc3339_canonical(*dt))
    }

    /// Deserialize any RFC 3339 date-time, normalized to UTC.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        DateTime::<Utc>::deserialize(d)
    }
}

/// Parse an HTTP `Retry-After` header value (RFC 9110 §10.2.3, formerly
/// RFC 7231 §7.1.3) into the delay it asks for, measured from `now`.
///
/// Both forms are accepted: `delay-seconds` (a non-negative decimal
/// integer) and an `HTTP-date`. All three HTTP-date formats a recipient
/// MUST accept are parsed: IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`),
/// the obsolete RFC 850 form (`Sunday, 06-Nov-94 08:49:37 GMT`) and
/// asctime (`Sun Nov  6 08:49:37 1994`). A date in the past yields
/// [`std::time::Duration::ZERO`]. Anything else (empty, negative,
/// fractional, garbage) yields `None`, so a caller falls back to its own
/// backoff, as RFC-ACDP-0008 §4.3 requires when the header is unusable.
///
/// ACDP consumers on the 0.5.0 line MUST honor `Retry-After` on every 429
/// (RFC-ACDP-0008 §4.3, fixture `rate-002`); `RegistryClient` reads it
/// into [`crate::AcdpError::RateLimited`]'s `retry_after`.
pub fn parse_retry_after(value: &str, now: DateTime<Utc>) -> Option<std::time::Duration> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if v.bytes().all(|b| b.is_ascii_digit()) {
        // Saturate absurd values rather than rejecting them: a huge delay
        // is still a "do not retry yet" instruction.
        let secs = v.parse::<u64>().unwrap_or(u64::MAX);
        return Some(std::time::Duration::from_secs(secs));
    }
    let at = parse_http_date(v)?;
    Some((at - now).to_std().unwrap_or(std::time::Duration::ZERO))
}

fn parse_http_date(v: &str) -> Option<DateTime<Utc>> {
    use chrono::NaiveDateTime;
    // IMF-fixdate. RFC 2822 parsing also accepts it (GMT is a valid zone).
    if let Ok(dt) = DateTime::parse_from_rfc2822(v) {
        return Some(dt.with_timezone(&Utc));
    }
    // Obsolete RFC 850 form: two-digit year, interpreted per RFC 9110
    // §5.6.7 (chrono's %y maps 00-68 to 20xx, 69-99 to 19xx).
    if let Some(rest) = v.strip_suffix(" GMT") {
        if let Some((_, tail)) = rest.split_once(", ") {
            if let Ok(dt) = NaiveDateTime::parse_from_str(tail, "%d-%b-%y %H:%M:%S") {
                return Some(dt.and_utc());
            }
        }
    }
    // asctime: `Sun Nov  6 08:49:37 1994` (day space-padded).
    let collapsed = v.split_whitespace().collect::<Vec<_>>().join(" ");
    NaiveDateTime::parse_from_str(&collapsed, "%a %b %e %H:%M:%S %Y")
        .ok()
        .map(|dt| dt.and_utc())
}

/// `Option` twin of [`canonical_rfc3339`]. Pair with
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`.
pub mod canonical_rfc3339_option {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize in canonical form (`None` serializes as `null`; callers
    /// skip it with `skip_serializing_if`).
    pub fn serialize<S: Serializer>(dt: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        match dt {
            Some(dt) => s.serialize_str(&super::fmt_rfc3339_canonical(*dt)),
            None => s.serialize_none(),
        }
    }

    /// Deserialize an optional RFC 3339 date-time, normalized to UTC.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        Option::<DateTime<Utc>>::deserialize(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_keeps_zero_millis() {
        let dt: DateTime<Utc> = "2026-12-31T23:59:59.000Z".parse().unwrap();
        assert_eq!(fmt_rfc3339_canonical(dt), "2026-12-31T23:59:59.000Z");
        let dt: DateTime<Utc> = "2026-12-31T23:59:59Z".parse().unwrap();
        assert_eq!(fmt_rfc3339_canonical(dt), "2026-12-31T23:59:59.000Z");
    }

    #[test]
    fn canonical_is_lossless_above_millis() {
        for s in [
            "2026-04-16T10:30:15.123Z",
            "2026-04-16T10:30:15.123456Z",
            "2026-04-16T10:30:15.123456789Z",
        ] {
            let dt: DateTime<Utc> = s.parse().unwrap();
            assert_eq!(fmt_rfc3339_canonical(dt), s);
        }
    }

    #[test]
    fn ms_truncation_drops_sub_ms() {
        let dt = DateTime::from_timestamp_nanos(1_700_000_000_123_456_789);
        let truncated = trunc_ms(dt);
        assert_eq!(truncated.timestamp_subsec_nanos() % 1_000_000, 0);
    }

    #[test]
    fn fmt_emits_canonical_form() {
        let dt = DateTime::from_timestamp_millis(1_700_000_000_123).unwrap();
        let s = fmt_rfc3339_ms(dt);
        assert!(s.ends_with("Z"), "got {s}");
        assert!(s.contains(".123"), "got {s}");
    }

    #[test]
    fn retry_after_delay_seconds() {
        let now = Utc::now();
        assert_eq!(
            parse_retry_after("120", now),
            Some(std::time::Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after(" 0 ", now),
            Some(std::time::Duration::ZERO)
        );
        assert_eq!(
            parse_retry_after("99999999999999999999999", now),
            Some(std::time::Duration::from_secs(u64::MAX))
        );
        for bad in ["", "-1", "1.5", "+3", "soon", "1 2"] {
            assert_eq!(parse_retry_after(bad, now), None, "{bad:?}");
        }
    }

    #[test]
    fn retry_after_http_date_all_three_formats() {
        let now: DateTime<Utc> = "1994-11-06T08:49:00Z".parse().unwrap();
        let want = Some(std::time::Duration::from_secs(37));
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", now),
            want
        );
        assert_eq!(
            parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", now),
            want
        );
        assert_eq!(parse_retry_after("Sun Nov  6 08:49:37 1994", now), want);
    }

    #[test]
    fn retry_after_past_date_is_zero() {
        let now: DateTime<Utc> = "2026-10-31T00:00:00Z".parse().unwrap();
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", now),
            Some(std::time::Duration::ZERO)
        );
    }
}
