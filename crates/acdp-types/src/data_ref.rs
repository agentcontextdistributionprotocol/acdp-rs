//! Data references — `acdp-data-ref.schema.json`.
//!
//! Each `DataRef` MUST contain exactly one of `location` (URI string or
//! structured locator object) or `embedded` (inline payload, ≤ 64 KB
//! decoded). The `type` field is a closed enum identifying the role of the
//! reference within the context.

use acdp_primitives::primitives::ContentHash;
use serde::{Deserialize, Serialize};

/// Role of a data reference. Closed enum per
/// `acdp-data-ref.schema.json` `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataRefType {
    /// The principal output of the context.
    PrimaryResult,
    /// Source data the context describes or refers back to.
    RawData,
    /// Auxiliary material that supports the context (notes, plots, etc.).
    SupportingInfo,
    /// Output computed/derived from the primary result.
    DerivedData,
}

/// A reference to a piece of data the context describes.
///
/// Per `acdp-data-ref.schema.json` `oneOf`: exactly one of `location` or
/// `embedded` MUST be present. The struct does not enforce this at
/// construction time; runtime validation is done by `validate_data_ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRef {
    /// Role of this reference within the context.
    #[serde(rename = "type")]
    pub ref_type: DataRefType,

    /// Human-readable description (≤ 1000 chars).
    ///
    /// Optional and absent-or-string in `acdp-data-ref.schema.json` — not
    /// nullable. `de_present` rejects an explicit `"description": null`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub description: Option<String>,

    /// Size of the referenced or embedded data in bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub size_bytes: Option<u64>,

    /// Producer-defined format identifier (e.g. `parquet`, `csv`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub format: Option<String>,

    /// Producer-specific schema version for this data.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub schema_version: Option<String>,

    /// Optional SHA-256 hash for verifying data integrity at fetch time.
    /// For embedded data, computed over the decoded bytes per
    /// `acdp-data-ref.schema.json`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub content_hash: Option<ContentHash>,

    /// Where the data resides — either a URI string or a structured
    /// locator object with a dotted-namespace `scheme` field.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub location: Option<Location>,

    /// Inline embedded payload. Decoded size MUST NOT exceed 64 KB.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub embedded: Option<EmbeddedContent>,

    /// Unknown producer-controlled `DataRef` fields, preserved verbatim.
    ///
    /// `acdp-data-ref.schema.json` has NO `additionalProperties: false`
    /// at its root — the object is open by design. A `DataRef` lives
    /// inside `ProducerContent` (the `content_hash` preimage), so a
    /// future ACDP minor version that adds a producer-controlled DataRef
    /// field must round-trip through this map: without it an older
    /// consumer would silently drop the new field on deserialization and
    /// recompute a different `content_hash`, falsely failing verification.
    /// Mirrors the [`crate::body::Body::extensions`] pattern
    /// (RFC-ACDP-0001 §5.7, conformance fixture can-010).
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// Locator for `DataRef.location` — either a URI string or a structured
/// locator object. See `acdp-data-ref.schema.json` `location.oneOf`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Location {
    /// URI form: scheme + authority + path. MUST NOT contain credentials in
    /// the userinfo component (the body is signed and immutable, so leaked
    /// secrets cannot be redacted later).
    Uri(String),
    /// Structured locator: object with a required dotted-namespace `scheme`
    /// (e.g. `kafka.offset`, `ipfs.cid`, `db.row`). Additional keys are
    /// permitted by schema.
    Structured(serde_json::Map<String, serde_json::Value>),
}

impl DataRef {
    /// URI-form data reference (no integrity hash).
    pub fn uri(ref_type: DataRefType, uri: impl Into<String>) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Uri(uri.into())),
            embedded: None,
            extensions: serde_json::Map::new(),
        }
    }

    /// URI-form data reference with a SHA-256 integrity hash.
    pub fn uri_verified(ref_type: DataRefType, uri: impl Into<String>, hash: ContentHash) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: Some(hash),
            location: Some(Location::Uri(uri.into())),
            embedded: None,
            extensions: serde_json::Map::new(),
        }
    }

    /// Structured-locator data reference. `scheme` MUST match
    /// `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`. Additional fields go in `extra`.
    ///
    /// In debug builds, an invalid scheme triggers a `debug_assert!`
    /// to surface the bug at construction time. Release builds accept
    /// the malformed value silently — pair this constructor with
    /// `acdp::validation::validate_data_ref` (called automatically
    /// by `RequestBuilder::build`) for runtime rejection. For a
    /// fallible variant, use [`Self::try_structured`].
    pub fn structured(
        ref_type: DataRefType,
        scheme: impl Into<String>,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        let scheme: String = scheme.into();
        debug_assert!(
            is_dotted_namespace_scheme(&scheme),
            "DataRef::structured: scheme '{scheme}' does not match \
             ^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$ — pass a dotted-namespace identifier \
             like 'kafka.offset' or use try_structured for runtime checking"
        );
        let mut map = extra;
        map.insert("scheme".into(), serde_json::Value::String(scheme));
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(map)),
            embedded: None,
            extensions: serde_json::Map::new(),
        }
    }

    /// Fallible structured-locator constructor. Returns
    /// [`acdp_primitives::error::AcdpError::SchemaViolation`] if `scheme` does
    /// not match the dotted-namespace pattern.
    pub fn try_structured(
        ref_type: DataRefType,
        scheme: impl Into<String>,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, acdp_primitives::error::AcdpError> {
        let scheme: String = scheme.into();
        if !is_dotted_namespace_scheme(&scheme) {
            return Err(acdp_primitives::error::AcdpError::SchemaViolation(format!(
                "structured locator scheme '{scheme}' must match \
                 ^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$"
            )));
        }
        let mut map = extra;
        map.insert("scheme".into(), serde_json::Value::String(scheme));
        Ok(Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(map)),
            embedded: None,
            extensions: serde_json::Map::new(),
        })
    }

    /// Embedded JSON data reference.
    pub fn embedded_json(ref_type: DataRefType, content: serde_json::Value) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: Some("application/json".into()),
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Json,
                content,
                content_hash: None,
            }),
            extensions: serde_json::Map::new(),
        }
    }

    /// Embedded UTF-8 text data reference. The text is stored as a JSON string.
    pub fn embedded_utf8(ref_type: DataRefType, text: impl Into<String>) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Utf8,
                content: serde_json::Value::String(text.into()),
                content_hash: None,
            }),
            extensions: serde_json::Map::new(),
        }
    }

    /// Embedded base64 binary data reference. `b64` is stored as a JSON string.
    pub fn embedded_base64(ref_type: DataRefType, b64: impl Into<String>) -> Self {
        Self {
            ref_type,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Base64,
                content: serde_json::Value::String(b64.into()),
                content_hash: None,
            }),
            extensions: serde_json::Map::new(),
        }
    }

    // ── Type-bound URI shortcuts ─────────────────────────────────────────────
    //
    // The four DataRefType variants come up frequently; these one-liners
    // save a `DataRefType::PrimaryResult` mention at every call site.

    /// `DataRef::uri(DataRefType::PrimaryResult, uri)`.
    pub fn primary_result_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::PrimaryResult, uri)
    }
    /// `DataRef::uri(DataRefType::RawData, uri)`.
    pub fn raw_data_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::RawData, uri)
    }
    /// `DataRef::uri(DataRefType::SupportingInfo, uri)`.
    pub fn supporting_info_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::SupportingInfo, uri)
    }
    /// `DataRef::uri(DataRefType::DerivedData, uri)`.
    pub fn derived_data_uri(uri: impl Into<String>) -> Self {
        Self::uri(DataRefType::DerivedData, uri)
    }

    /// `DataRef::embedded_json(DataRefType::PrimaryResult, content)`.
    pub fn primary_result_json(content: serde_json::Value) -> Self {
        Self::embedded_json(DataRefType::PrimaryResult, content)
    }
    /// `DataRef::embedded_json(DataRefType::DerivedData, content)`.
    pub fn derived_data_json(content: serde_json::Value) -> Self {
        Self::embedded_json(DataRefType::DerivedData, content)
    }
}

/// Inline embedded data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedContent {
    /// Content encoding / interpretation.
    pub encoding: EmbeddedEncoding,
    /// The actual content. For `json` encoding this is any JSON value.
    /// For `utf8` / `base64` it MUST be a JSON string.
    pub content: serde_json::Value,
    /// Optional SHA-256 hash of the *decoded* content bytes (RFC-ACDP-0002
    /// §6.3/§6.6), distinct from `DataRef.content_hash` on the enclosing
    /// ref — a `DataRef` MAY carry both over the same decoded bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::de_present"
    )]
    pub content_hash: Option<ContentHash>,
}

/// Validate dotted-namespace scheme pattern.
fn is_dotted_namespace_scheme(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// How the `content` field of an embedded data reference is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmbeddedEncoding {
    /// Any JSON value (object, array, number, …).
    Json,
    /// A UTF-8 text payload encoded as a JSON string.
    Utf8,
    /// Binary data encoded as standard base64, stored as a JSON string.
    Base64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── is_dotted_namespace_scheme ─────────────────────────────────────────

    #[test]
    fn dotted_namespace_scheme_accepts_valid() {
        for s in [
            "kafka.offset",
            "ipfs.cid",
            "db.row",
            "a.b",
            "a1.b2.c3",
            "with-hyphen.part-two",
        ] {
            assert!(is_dotted_namespace_scheme(s), "should accept {s:?}");
        }
    }

    #[test]
    fn dotted_namespace_scheme_rejects_invalid() {
        for s in [
            "",              // empty
            "nodot",         // missing separator
            "Kafka.offset",  // uppercase first char
            "kafka.Offset",  // uppercase in second segment
            "kafka..offset", // empty middle segment
            ".leading",      // empty leading segment
            "trailing.",     // empty trailing segment
            "1kafka.offset", // segment must start with a letter
            "kafka.1offset", // second segment must start with a letter
            "kafka.off_set", // underscore not permitted
        ] {
            assert!(!is_dotted_namespace_scheme(s), "should reject {s:?}");
        }
    }

    // ── try_structured / structured ────────────────────────────────────────

    #[test]
    fn try_structured_ok_inserts_scheme_and_extra() {
        let mut extra = serde_json::Map::new();
        extra.insert("offset".into(), json!(42));
        let dr = DataRef::try_structured(DataRefType::RawData, "kafka.offset", extra).unwrap();
        match dr.location {
            Some(Location::Structured(map)) => {
                assert_eq!(map["scheme"], json!("kafka.offset"));
                assert_eq!(map["offset"], json!(42));
            }
            other => panic!("expected structured location, got {other:?}"),
        }
        assert!(dr.embedded.is_none(), "structured locator has no embedded");
    }

    #[test]
    fn try_structured_rejects_bad_scheme() {
        let err = DataRef::try_structured(DataRefType::RawData, "nodot", serde_json::Map::new())
            .unwrap_err();
        assert!(
            matches!(err, acdp_primitives::error::AcdpError::SchemaViolation(_)),
            "bad scheme must be SchemaViolation, got {err:?}"
        );
    }

    #[test]
    fn structured_inserts_scheme_for_valid_input() {
        // Valid scheme: avoids the debug_assert! in `structured`.
        let dr = DataRef::structured(DataRefType::RawData, "ipfs.cid", serde_json::Map::new());
        match dr.location {
            Some(Location::Structured(map)) => assert_eq!(map["scheme"], json!("ipfs.cid")),
            other => panic!("expected structured location, got {other:?}"),
        }
    }

    // ── URI constructors ───────────────────────────────────────────────────

    #[test]
    fn uri_constructor_sets_location_without_hash() {
        let dr = DataRef::uri(DataRefType::PrimaryResult, "https://x.example/d");
        assert_eq!(dr.ref_type, DataRefType::PrimaryResult);
        assert!(matches!(dr.location, Some(Location::Uri(ref u)) if u == "https://x.example/d"));
        assert!(dr.content_hash.is_none());
        assert!(dr.embedded.is_none());
    }

    #[test]
    fn uri_verified_carries_content_hash() {
        let hash = ContentHash(
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
        );
        let dr = DataRef::uri_verified(DataRefType::RawData, "https://x/d", hash.clone());
        assert_eq!(dr.content_hash, Some(hash));
        assert!(matches!(dr.location, Some(Location::Uri(_))));
    }

    #[test]
    fn type_bound_uri_shortcuts_pick_the_right_type() {
        assert_eq!(
            DataRef::primary_result_uri("u").ref_type,
            DataRefType::PrimaryResult
        );
        assert_eq!(DataRef::raw_data_uri("u").ref_type, DataRefType::RawData);
        assert_eq!(
            DataRef::supporting_info_uri("u").ref_type,
            DataRefType::SupportingInfo
        );
        assert_eq!(
            DataRef::derived_data_uri("u").ref_type,
            DataRefType::DerivedData
        );
    }

    // ── Embedded constructors ──────────────────────────────────────────────

    #[test]
    fn embedded_json_sets_json_encoding_and_format() {
        let dr = DataRef::embedded_json(DataRefType::PrimaryResult, json!({"k": 1}));
        let e = dr.embedded.expect("embedded set");
        assert_eq!(e.encoding, EmbeddedEncoding::Json);
        assert_eq!(e.content, json!({"k": 1}));
        assert_eq!(dr.format.as_deref(), Some("application/json"));
        assert!(dr.location.is_none(), "embedded ref has no location");
    }

    #[test]
    fn embedded_utf8_stores_text_as_json_string() {
        let dr = DataRef::embedded_utf8(DataRefType::SupportingInfo, "hello");
        let e = dr.embedded.expect("embedded set");
        assert_eq!(e.encoding, EmbeddedEncoding::Utf8);
        assert_eq!(e.content, json!("hello"));
    }

    #[test]
    fn embedded_base64_stores_payload_as_json_string() {
        let dr = DataRef::embedded_base64(DataRefType::DerivedData, "aGVsbG8=");
        let e = dr.embedded.expect("embedded set");
        assert_eq!(e.encoding, EmbeddedEncoding::Base64);
        assert_eq!(e.content, json!("aGVsbG8="));
    }

    #[test]
    fn type_bound_json_shortcuts_pick_the_right_type() {
        assert_eq!(
            DataRef::primary_result_json(json!(1)).ref_type,
            DataRefType::PrimaryResult
        );
        assert_eq!(
            DataRef::derived_data_json(json!(1)).ref_type,
            DataRefType::DerivedData
        );
    }

    // ── Wire shape ─────────────────────────────────────────────────────────

    #[test]
    fn data_ref_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(DataRefType::PrimaryResult).unwrap(),
            json!("primary_result")
        );
        assert_eq!(
            serde_json::to_value(DataRefType::RawData).unwrap(),
            json!("raw_data")
        );
        assert_eq!(
            serde_json::to_value(DataRefType::SupportingInfo).unwrap(),
            json!("supporting_info")
        );
        assert_eq!(
            serde_json::to_value(DataRefType::DerivedData).unwrap(),
            json!("derived_data")
        );
    }

    #[test]
    fn embedded_content_rejects_unknown_field() {
        // EmbeddedContent is `deny_unknown_fields`.
        let raw = json!({"encoding": "utf8", "content": "x", "surprise": 1});
        let parsed: Result<EmbeddedContent, _> = serde_json::from_value(raw);
        assert!(parsed.is_err(), "unknown field must be rejected");
    }

    #[test]
    fn constructed_uri_ref_round_trips_through_json() {
        let dr = DataRef::uri(DataRefType::PrimaryResult, "https://x/d");
        let v = serde_json::to_value(&dr).unwrap();
        // `type` rename and omitted-None fields.
        assert_eq!(v["type"], json!("primary_result"));
        assert_eq!(v["location"], json!("https://x/d"));
        assert!(v.as_object().unwrap().get("embedded").is_none());
        let back: DataRef = serde_json::from_value(v).unwrap();
        assert_eq!(back.ref_type, DataRefType::PrimaryResult);
    }
}
