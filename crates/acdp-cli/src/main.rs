//! `acdp` — command-line front-end to the ACDP library.
//!
//! Subcommands:
//!
//! ```text
//! acdp capabilities <registry-url>
//! acdp retrieve     <registry-url> <ctx_id>
//! acdp body         <registry-url> <ctx_id>
//! acdp search       <registry-url> [--q QUERY] [--limit N] [--type T]
//!                                   [--tags A,B] [--domain D] [--status S]
//!                                   [--agent-id DID] [--cursor C]
//! acdp publish      <registry-url> --key-seed <64-hex>
//!                                   [--key-algorithm ed25519|ecdsa-p256]
//!                                   --agent-id <DID> --key-id <DID-URL>
//!                                   --title T --type CT (or via stdin) [--domain D]
//!                                   [--visibility V] [--audience DID,DID]
//!                                   [--summary S] [--description D]
//!                                   [--tags A,B,C]
//!                                   [--idempotency-key UUID]
//!                                   < producer_content.json   # stdin overlay (optional)
//! acdp validate     <file.json>              # offline validate_publish_request
//! acdp resolve      <acdp-ctx-id-uri> [--max-depth N]
//! acdp canonicalize                          # JCS bytes from stdin JSON
//! acdp hash                                  # content_hash from stdin JSON
//! acdp verify       <body.json>              # verify a stored body via DID resolution
//! acdp sign         <seed-hex> <key-id>      # hash + Ed25519-sign ProducerContent from stdin
//! ```
//!
//! Output is JSON (the resource on success, an error envelope on
//! failure) so the tool composes with `jq`. Exit code is 0 on success,
//! 1 on user / argument errors, 2 on protocol / verification failures.
//!
//! No CLI parser dependency: the binary uses `std::env::args` directly.
//! That keeps the dep graph identical to the library — adding `clap`
//! would pull in 30+ transitive crates for what is ~200 lines of
//! parsing.

use std::process::ExitCode;

use acdp::{
    client::{CrossRegistryResolver, RegistryClient, VerifiedContext},
    crypto::{canonicalize, compute_content_hash, SigningKey},
    did::WebResolver,
    producer::Producer,
    types::{
        primitives::{AgentDid, ContentHash, ContextType, Visibility},
        Body, CtxId, PublishRequest, SearchParams,
    },
    AcdpError,
};

fn print_usage() {
    eprintln!(
        "acdp — Agent Context Distribution Protocol CLI\n\
         \n\
         USAGE:\n\
         \tacdp capabilities <registry-url>\n\
         \tacdp retrieve     <registry-url> <ctx_id>\n\
         \tacdp body         <registry-url> <ctx_id>\n\
         \tacdp search       <registry-url> [--q QUERY] [--limit N] [--type T]\n\
         \t                                  [--tags A,B] [--domain D] [--status S]\n\
         \t                                  [--agent-id DID] [--cursor C]\n\
         \tacdp publish      <registry-url> --key-seed <64-hex>\n\
         \t                                  [--key-algorithm ed25519|ecdsa-p256]\n\
         \t                                  --agent-id <DID> --key-id <DID-URL>\n\
         \t                                  --title T --type CT (or via stdin) [--domain D]\n\
         \t                                  [--visibility V] [--audience DID,DID]\n\
         \t                                  [--summary S] [--description D]\n\
         \t                                  [--tags A,B,C]\n\
         \t                                  [--idempotency-key UUID]\n\
         \t                                  < producer_content.json (stdin overlay; optional)\n\
         \tacdp validate     <file.json>              # offline schema validation\n\
         \tacdp resolve      <ctx-id> [--max-depth N] # walk derived_from\n\
         \tacdp canonicalize                          # JCS bytes from stdin JSON\n\
         \tacdp hash                                  # content_hash from stdin JSON\n\
         \tacdp verify       <body.json>              # verify a stored body\n\
         \tacdp sign         <seed-hex> <key-id>      # hash + Ed25519-sign ProducerContent from stdin\n\
         "
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(1);
    };
    let rest = &args[1..];
    let result: Result<(), CliError> = match cmd {
        "capabilities" => cmd_capabilities(rest).await,
        "retrieve" => cmd_retrieve(rest).await,
        "body" => cmd_body(rest).await,
        "search" => cmd_search(rest).await,
        "publish" => cmd_publish(rest).await,
        "validate" => cmd_validate(rest),
        "resolve" => cmd_resolve(rest).await,
        "canonicalize" => cmd_canonicalize(),
        "hash" => cmd_hash(),
        "verify" => cmd_verify(rest).await,
        "sign" => cmd_sign(rest),
        "--help" | "-h" | "help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("acdp: unknown subcommand '{other}'\n");
            print_usage();
            return ExitCode::from(1);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(msg)) => {
            eprintln!("acdp: {msg}\n");
            print_usage();
            ExitCode::from(1)
        }
        Err(CliError::Acdp(e)) => {
            // Output a wire-shaped error envelope on stdout so a script
            // can `jq .error.code` to dispatch.
            let envelope = serde_json::json!({
                "error": {
                    "code": classify(&e),
                    "message": e.to_string(),
                }
            });
            println!("{envelope}");
            ExitCode::from(2)
        }
        Err(CliError::Io(msg)) => {
            eprintln!("acdp: {msg}");
            ExitCode::from(1)
        }
    }
}

enum CliError {
    Usage(String),
    Acdp(AcdpError),
    Io(String),
}

impl From<AcdpError> for CliError {
    fn from(e: AcdpError) -> Self {
        Self::Acdp(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        Self::Io(format!("invalid JSON: {e}"))
    }
}

fn classify(e: &AcdpError) -> &'static str {
    match e {
        AcdpError::HashMismatch { .. } | AcdpError::RemoteHashMismatch(_) => "hash_mismatch",
        AcdpError::DataRefHashMismatch(_) => "data_ref_hash_mismatch",
        AcdpError::InvalidSignature(_) => "invalid_signature",
        AcdpError::SchemaViolation(_) => "schema_violation",
        AcdpError::NotFound(_) => "not_found",
        AcdpError::NotAuthorized(_) => "not_authorized",
        AcdpError::KeyNotAuthorized(_) => "key_not_authorized",
        AcdpError::KeyResolution(_) => "key_resolution_failed",
        AcdpError::KeyResolutionUnreachable(_) => "key_resolution_unreachable",
        AcdpError::CrossRegistryResolutionFailed(_) => "cross_registry_resolution_failed",
        AcdpError::InvalidReceipt(_) => "invalid_receipt",
        AcdpError::PayloadTooLarge(_) => "payload_too_large",
        AcdpError::EmbeddedTooLarge(_) => "embedded_too_large",
        AcdpError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        AcdpError::RateLimited(_) => "rate_limited",
        AcdpError::Http(_) => "http_error",
        AcdpError::ContextIdMismatch { .. } => "context_id_mismatch",
        _ => "internal_error",
    }
}

// ── Subcommand implementations ───────────────────────────────────────────────

/// Build the registry transport client.
///
/// Production applies the full RFC-ACDP-0006 §7 / RFC-ACDP-0008 SSRF +
/// HTTPS-only + DNS-rebinding posture via [`RegistryClient::new`]. The
/// `ACDP_INSECURE_TRANSPORT=1` escape hatch downgrades to a permissive
/// transport (plain HTTP, IP literals, loopback) and exists **only** so
/// the crate's subprocess integration tests can drive an in-process HTTP
/// mock registry. It is intentionally undocumented in `--help`; never set
/// it outside tests.
fn registry_client(url: &str) -> Result<RegistryClient, AcdpError> {
    #[cfg(feature = "test-transport")]
    if std::env::var_os("ACDP_INSECURE_TRANSPORT").is_some() {
        return RegistryClient::with_test_transport(url);
    }
    RegistryClient::new(url)
}

async fn cmd_capabilities(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`capabilities` requires <registry-url>".into()))?;
    let client = registry_client(url)?;
    let caps = client.capabilities().await?;
    println!("{}", serde_json::to_string_pretty(&caps)?);
    Ok(())
}

async fn cmd_retrieve(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`retrieve` requires <registry-url> <ctx_id>".into()))?;
    let id = rest
        .get(1)
        .ok_or_else(|| CliError::Usage("`retrieve` requires <ctx_id>".into()))?;
    let client = registry_client(url)?;
    let resolver = WebResolver::new();
    let ctx_id = CtxId::parse(id.clone())?;
    let ctx = VerifiedContext::fetch(&client, &resolver, &ctx_id).await?;
    println!("{}", serde_json::to_string_pretty(ctx.full_context())?);
    Ok(())
}

async fn cmd_body(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`body` requires <registry-url> <ctx_id>".into()))?;
    let id = rest
        .get(1)
        .ok_or_else(|| CliError::Usage("`body` requires <ctx_id>".into()))?;
    let client = registry_client(url)?;
    let ctx_id = CtxId::parse(id.clone())?;
    let body = client.retrieve_body(&ctx_id).await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn cmd_search(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`search` requires <registry-url>".into()))?;
    let mut params = SearchParams::default();
    let mut i = 1;
    while i < rest.len() {
        match rest[i].as_str() {
            "--q" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--q requires a value".into()))?;
                params.q = Some(v.clone());
                i += 2;
            }
            "--limit" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--limit requires a value".into()))?;
                params.limit = Some(
                    v.parse()
                        .map_err(|_| CliError::Usage(format!("invalid --limit value: {v}")))?,
                );
                i += 2;
            }
            "--type" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--type requires a value".into()))?;
                params.context_type = Some(v.clone());
                i += 2;
            }
            "--tags" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--tags requires a value".into()))?;
                params.tags = Some(v.clone());
                i += 2;
            }
            "--domain" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--domain requires a value".into()))?;
                params.domain = Some(v.clone());
                i += 2;
            }
            "--status" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--status requires a value".into()))?;
                params.status = Some(v.clone());
                i += 2;
            }
            "--agent-id" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--agent-id requires a value".into()))?;
                params.agent_id = Some(v.clone());
                i += 2;
            }
            "--cursor" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--cursor requires a value".into()))?;
                params.cursor = Some(v.clone());
                i += 2;
            }
            other => return Err(CliError::Usage(format!("unknown search flag '{other}'"))),
        }
    }
    let client = registry_client(url)?;
    let resp = client.search(&params).await?;
    println!("{}", serde_json::to_string_pretty(&resp.matches)?);
    Ok(())
}

fn cmd_canonicalize() -> Result<(), CliError> {
    let v: serde_json::Value = read_stdin_json()?;
    let bytes = canonicalize(&v)?;
    use std::io::Write;
    std::io::stdout().write_all(&bytes)?;
    println!();
    Ok(())
}

fn cmd_hash() -> Result<(), CliError> {
    let v: serde_json::Value = read_stdin_json()?;
    let h = compute_content_hash(&v)?;
    println!("{h}");
    Ok(())
}

async fn cmd_verify(rest: &[String]) -> Result<(), CliError> {
    let path = rest
        .first()
        .ok_or_else(|| CliError::Usage("`verify` requires <body.json>".into()))?;
    let text = std::fs::read_to_string(path)?;
    let body: Body = serde_json::from_str(&text)?;
    let resolver = WebResolver::new();
    let verifier = acdp::verify::Verifier::new(&resolver);
    verifier.verify_body(&body).await?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "ctx_id": body.ctx_id,
            "agent_id": body.agent_id,
            "content_hash": body.content_hash,
        })
    );
    Ok(())
}

fn cmd_sign(rest: &[String]) -> Result<(), CliError> {
    let seed_hex = rest
        .first()
        .ok_or_else(|| CliError::Usage("`sign` requires <seed-hex> <key-id>".into()))?;
    let key_id = rest
        .get(1)
        .ok_or_else(|| CliError::Usage("`sign` requires <key-id>".into()))?;
    let seed =
        hex::decode(seed_hex).map_err(|e| CliError::Usage(format!("invalid hex seed: {e}")))?;
    if seed.len() != 32 {
        return Err(CliError::Usage(format!(
            "seed must be 32 bytes, got {} bytes",
            seed.len()
        )));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let key = SigningKey::from_bytes(&seed_arr);

    let v: serde_json::Value = read_stdin_json()?;
    // The stdin payload should be ProducerContent (the hash preimage).
    let h = compute_content_hash(&v)?;
    let sig = key.sign_content_hash(&h);

    println!(
        "{}",
        serde_json::json!({
            "content_hash": h,
            "signature": {
                "algorithm": "ed25519",
                "key_id": key_id,
                "value": sig,
            }
        })
    );
    let _: ContentHash = h; // silence unused-import on some feature combos
    Ok(())
}

fn read_stdin_json() -> Result<serde_json::Value, CliError> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let v: serde_json::Value = serde_json::from_str(&buf)?;
    Ok(v)
}

/// Like `read_stdin_json` but returns `None` when stdin is closed /
/// empty / whitespace-only, so callers can decide whether the JSON
/// overlay is mandatory.
fn try_read_stdin_json() -> Result<Option<serde_json::Value>, CliError> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&buf)?))
}

// ── publish ──────────────────────────────────────────────────────────────────

async fn cmd_publish(rest: &[String]) -> Result<(), CliError> {
    let url = rest
        .first()
        .ok_or_else(|| CliError::Usage("`publish` requires <registry-url>".into()))?;

    let mut key_seed: Option<String> = None;
    let mut key_algorithm: Option<String> = None;
    let mut agent_id: Option<String> = None;
    let mut key_id: Option<String> = None;
    let mut idempotency_key: Option<String> = None;
    let mut title: Option<String> = None;
    let mut context_type: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut visibility: Option<String> = None;
    let mut audience_csv: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut description: Option<String> = None;
    let mut tags_csv: Option<String> = None;
    // IMP-01: stdin-overlay-only fields (no CLI flag).
    let mut acdp_version: Option<String> = None;
    let mut schema_uri: Option<String> = None;
    let mut expires_at: Option<chrono::DateTime<chrono::Utc>> = None;

    let mut i = 1;
    while i < rest.len() {
        let take = |name: &str, idx: usize, rest: &[String]| -> Result<String, CliError> {
            rest.get(idx + 1)
                .cloned()
                .ok_or_else(|| CliError::Usage(format!("{name} requires a value")))
        };
        match rest[i].as_str() {
            "--key-seed" => {
                key_seed = Some(take("--key-seed", i, rest)?);
                i += 2;
            }
            "--key-algorithm" => {
                key_algorithm = Some(take("--key-algorithm", i, rest)?);
                i += 2;
            }
            "--agent-id" => {
                agent_id = Some(take("--agent-id", i, rest)?);
                i += 2;
            }
            "--key-id" => {
                key_id = Some(take("--key-id", i, rest)?);
                i += 2;
            }
            "--idempotency-key" => {
                idempotency_key = Some(take("--idempotency-key", i, rest)?);
                i += 2;
            }
            "--title" => {
                title = Some(take("--title", i, rest)?);
                i += 2;
            }
            "--type" => {
                context_type = Some(take("--type", i, rest)?);
                i += 2;
            }
            "--domain" => {
                domain = Some(take("--domain", i, rest)?);
                i += 2;
            }
            "--visibility" => {
                visibility = Some(take("--visibility", i, rest)?);
                i += 2;
            }
            "--audience" => {
                audience_csv = Some(take("--audience", i, rest)?);
                i += 2;
            }
            "--summary" => {
                summary = Some(take("--summary", i, rest)?);
                i += 2;
            }
            "--description" => {
                description = Some(take("--description", i, rest)?);
                i += 2;
            }
            "--tags" => {
                tags_csv = Some(take("--tags", i, rest)?);
                i += 2;
            }
            other => return Err(CliError::Usage(format!("unknown publish flag '{other}'"))),
        }
    }

    let seed_hex =
        key_seed.ok_or_else(|| CliError::Usage("`publish` requires --key-seed".into()))?;
    let agent_id =
        agent_id.ok_or_else(|| CliError::Usage("`publish` requires --agent-id".into()))?;
    let key_id = key_id.ok_or_else(|| CliError::Usage("`publish` requires --key-id".into()))?;
    let seed_bytes: [u8; 32] = hex::decode(&seed_hex)
        .map_err(|e| CliError::Usage(format!("invalid --key-seed hex: {e}")))?
        .try_into()
        .map_err(|v: Vec<u8>| {
            CliError::Usage(format!("--key-seed must be 32 bytes, got {}", v.len()))
        })?;

    // FEAT-02: select signing algorithm. Default `ed25519` matches the
    // historical CLI behavior; `ecdsa-p256` is the interop algorithm
    // in the ACDP signature-algorithms registry.
    let algorithm = key_algorithm.as_deref().unwrap_or("ed25519");
    let producer = match algorithm {
        "ed25519" => Producer::new_ed25519(
            SigningKey::from_bytes(&seed_bytes),
            AgentDid::new(agent_id),
            key_id,
        ),
        "ecdsa-p256" => {
            let p256_key = acdp::crypto::P256SigningKey::from_bytes(&seed_bytes)
                .map_err(|e| CliError::Usage(format!("invalid p256 key seed: {e}")))?;
            Producer::new_p256(p256_key, AgentDid::new(agent_id), key_id)
        }
        other => {
            return Err(CliError::Usage(format!(
                "--key-algorithm '{other}' not supported; use 'ed25519' or 'ecdsa-p256'"
            )));
        }
    };

    let mut builder = producer.publish_request();

    // ProducerContent JSON overlay from stdin lets users supply the
    // structured fields (data_refs, metadata, data_period) that have no
    // CLI flag. Top-level keys map to builder setters where they exist;
    // unrecognized keys are passed through to the validator for a
    // clearer error.
    let stdin_overlay = try_read_stdin_json()?;
    if let Some(serde_json::Value::Object(map)) = stdin_overlay {
        for (k, v) in map {
            match k.as_str() {
                // CLI flags win over stdin overlay (per the docstring), so
                // each field is only adopted from stdin if the matching
                // flag wasn't supplied — encoded as a match guard so
                // clippy's `collapsible_if` (stable on 1.95+) is happy.
                // When the guard fails the arm doesn't match and falls
                // through to the catch-all, which is the correct no-op
                // semantic. Let-chains would be cleaner but aren't
                // stable until 1.88 (MSRV is 1.86).
                "title" if title.is_none() => {
                    title = v.as_str().map(str::to_string);
                }
                "type" if context_type.is_none() => {
                    context_type = v.as_str().map(str::to_string);
                }
                "summary" if summary.is_none() => {
                    summary = v.as_str().map(str::to_string);
                }
                "description" if description.is_none() => {
                    description = v.as_str().map(str::to_string);
                }
                "domain" if domain.is_none() => {
                    domain = v.as_str().map(str::to_string);
                }
                "data_refs" => {
                    let drs: Vec<acdp::types::DataRef> = serde_json::from_value(v)
                        .map_err(|e| CliError::Usage(format!("invalid data_refs JSON: {e}")))?;
                    builder = builder.data_refs(drs);
                }
                "metadata" => {
                    builder = builder.metadata(v);
                }
                "tags" => {
                    if let Some(arr) = v.as_array() {
                        let vs: Vec<String> = arr
                            .iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect();
                        builder = builder.tags(vs);
                    }
                }
                "visibility" if visibility.is_none() => {
                    visibility = v.as_str().map(str::to_string);
                }
                "acdp_version" if acdp_version.is_none() => {
                    acdp_version = v.as_str().map(str::to_string);
                }
                "schema_uri" if schema_uri.is_none() => {
                    schema_uri = v.as_str().map(str::to_string);
                }
                "expires_at" if expires_at.is_none() => {
                    let s = v.as_str().ok_or_else(|| {
                        CliError::Usage("expires_at must be an RFC 3339 string".into())
                    })?;
                    let dt = s
                        .parse::<chrono::DateTime<chrono::Utc>>()
                        .map_err(|e| CliError::Usage(format!("invalid expires_at '{s}': {e}")))?;
                    expires_at = Some(dt);
                }
                "data_period" => {
                    let dp: acdp::types::DataPeriod = serde_json::from_value(v)
                        .map_err(|e| CliError::Usage(format!("invalid data_period JSON: {e}")))?;
                    builder = builder.data_period(dp);
                }
                "derived_from" => {
                    let refs: Vec<CtxId> = serde_json::from_value(v)
                        .map_err(|e| CliError::Usage(format!("invalid derived_from JSON: {e}")))?;
                    builder = builder.derived_from(refs);
                }
                "contributors" => {
                    let dids: Vec<AgentDid> = serde_json::from_value(v)
                        .map_err(|e| CliError::Usage(format!("invalid contributors JSON: {e}")))?;
                    builder = builder.contributors(dids);
                }
                "audience" if audience_csv.is_none() => {
                    let dids: Vec<AgentDid> = serde_json::from_value(v)
                        .map_err(|e| CliError::Usage(format!("invalid audience JSON: {e}")))?;
                    builder = builder.audience(dids);
                }
                _ => {
                    return Err(CliError::Usage(format!(
                        "unknown publish overlay field '{k}'; supported: title, type, \
                         summary, description, domain, visibility, audience, contributors, \
                         derived_from, data_refs, metadata, tags, data_period, schema_uri, \
                         expires_at, acdp_version"
                    )));
                }
            }
        }
    }

    let title = title.ok_or_else(|| CliError::Usage("--title is required".into()))?;
    let context_type = context_type.ok_or_else(|| CliError::Usage("--type is required".into()))?;
    let context_type: ContextType =
        serde_json::from_value(serde_json::Value::String(context_type.clone()))
            .map_err(|e| CliError::Usage(format!("invalid context type '{context_type}': {e}")))?;

    builder = builder.title(title).context_type(context_type);
    if let Some(d) = domain {
        builder = builder.domain(d);
    }
    if let Some(s) = summary {
        builder = builder.summary(s);
    }
    if let Some(d) = description {
        builder = builder.description(d);
    }
    if let Some(t) = tags_csv {
        let vs: Vec<String> = t.split(',').map(|s| s.trim().to_string()).collect();
        builder = builder.tags(vs);
    }
    if let Some(v) = visibility {
        let vis: Visibility = serde_json::from_value(serde_json::Value::String(v.clone()))
            .map_err(|e| CliError::Usage(format!("invalid --visibility '{v}': {e}")))?;
        builder = builder.visibility(vis);
    }
    if let Some(csv) = audience_csv {
        let dids: Vec<AgentDid> = csv.split(',').map(|s| AgentDid::new(s.trim())).collect();
        builder = builder.audience(dids);
    }
    if let Some(v) = acdp_version {
        builder = builder.acdp_version(v);
    }
    if let Some(u) = schema_uri {
        builder = builder.schema_uri(u);
    }
    if let Some(e) = expires_at {
        builder = builder.expires_at(e);
    }

    let req: PublishRequest = builder.build()?;

    let client = registry_client(url)?;
    let resp = if let Some(key) = idempotency_key {
        client.publish_idempotent(&req, &key).await?
    } else {
        client.publish(&req).await?
    };
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

// ── validate ─────────────────────────────────────────────────────────────────

fn cmd_validate(rest: &[String]) -> Result<(), CliError> {
    let path = rest
        .first()
        .ok_or_else(|| CliError::Usage("`validate` requires <file.json>".into()))?;
    let text = std::fs::read_to_string(path)?;
    let req: PublishRequest = serde_json::from_str(&text)?;
    acdp::validation::validate_publish_request(&req)?;
    // Optional: recompute and compare the content_hash so users can see
    // whether the producer-controlled portion matches the declared
    // hash. Doesn't change the validation outcome — just informative.
    let req_value = serde_json::to_value(&req)?;
    let computed = compute_content_hash(&req_value)?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "ctx_id_declared": "(registry-assigned at publish-time)",
            "content_hash_declared": req.content_hash,
            "content_hash_recomputed": computed,
            "hash_matches": computed == req.content_hash,
        })
    );
    Ok(())
}

// ── resolve ──────────────────────────────────────────────────────────────────

async fn cmd_resolve(rest: &[String]) -> Result<(), CliError> {
    let id = rest
        .first()
        .ok_or_else(|| CliError::Usage("`resolve` requires <ctx-id>".into()))?;
    let mut max_depth: Option<usize> = None;
    let mut i = 1;
    while i < rest.len() {
        match rest[i].as_str() {
            "--max-depth" => {
                let v = rest
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--max-depth requires a value".into()))?;
                max_depth = Some(
                    v.parse()
                        .map_err(|_| CliError::Usage(format!("invalid --max-depth: {v}")))?,
                );
                i += 2;
            }
            other => return Err(CliError::Usage(format!("unknown resolve flag '{other}'"))),
        }
    }

    let mut resolver = CrossRegistryResolver::new();
    if let Some(d) = max_depth {
        resolver = resolver.with_max_depth(d);
    }

    let ctx_id = CtxId::parse(id.clone())?;
    let root = resolver.resolve(&ctx_id).await?;
    let ancestors = resolver.walk_derived_from(root.body()).await?;

    let mut all: Vec<&Body> = Vec::with_capacity(1 + ancestors.len());
    all.push(root.body());
    for a in &ancestors {
        all.push(a.body());
    }
    println!("{}", serde_json::to_string_pretty(&all)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error → wire-code mapping printed in the failure envelope
    /// (main's `CliError::Acdp` arm) is the CLI's scriptable contract:
    /// callers `jq .error.code` to dispatch. Pin representative variants
    /// plus the catch-all so a reshuffle of the match can't silently
    /// change a code.
    #[test]
    fn classify_maps_representative_variants() {
        let cases: &[(AcdpError, &str)] = &[
            (AcdpError::InvalidSignature("x".into()), "invalid_signature"),
            (AcdpError::SchemaViolation("x".into()), "schema_violation"),
            (AcdpError::NotFound("x".into()), "not_found"),
            (AcdpError::NotAuthorized("x".into()), "not_authorized"),
            (
                AcdpError::KeyNotAuthorized("x".into()),
                "key_not_authorized",
            ),
            (
                AcdpError::KeyResolution("x".into()),
                "key_resolution_failed",
            ),
            (
                AcdpError::UnsupportedAlgorithm("x".into()),
                "unsupported_algorithm",
            ),
            (AcdpError::InvalidReceipt("x".into()), "invalid_receipt"),
            (AcdpError::PayloadTooLarge("x".into()), "payload_too_large"),
            // Issue #189: a substituted body must not be reported as an
            // internal error.
            (
                AcdpError::ContextIdMismatch {
                    requested: "a".into(),
                    served: "b".into(),
                },
                "context_id_mismatch",
            ),
            // A variant not enumerated in classify falls through to the
            // internal-error catch-all.
            (AcdpError::Canonicalization("x".into()), "internal_error"),
        ];
        for (err, code) in cases {
            assert_eq!(classify(err), *code, "{err:?}");
        }
    }
}
