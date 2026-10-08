# CLI Reference

The `acdp` binary is a thin command-line wrapper over the library, and is its
own crate (`crates/acdp-cli`). It's useful for scripting, debugging the wire
format, and exercising a registry from a shell. It deliberately uses no
argument-parsing crate (`std::env::args` only), to keep its dependency graph
identical to the library.

```bash
cargo run -p acdp-cli -- <subcommand> [args]
# or install it:
cargo install acdp-cli
acdp <subcommand> [args]
```

## Exit codes & output contract

The CLI is built to be scriptable:

| Exit | Meaning | Output |
|---|---|---|
| `0` | success | result JSON on **stdout** |
| `1` | usage / IO error | message + usage on **stderr** |
| `2` | protocol/verification failure | a `{"error":{"code","message"}}` envelope on **stdout** |

The exit-2 `code` is the wire error code for the common protocol failures
(`invalid_signature`, `hash_mismatch`, `schema_violation`, `not_found`,
`context_id_mismatch`, `invalid_receipt`, …; the mapping is `classify` in
`crates/acdp-cli/src/main.rs`). Two codes are not wire codes: `http_error`
(transport failure such as a DNS or connect error) and `internal_error` (the
catch-all for every other error, including local-only ones such as a
canonicalization failure). Malformed JSON input is an exit-1 IO error, not an
envelope.

Capture stdout once, then dispatch on the code with `jq`:

```bash
out=$(acdp retrieve https://registry.example.com "acdp://registry.example.com/<uuid>") \
  || echo "failed: $(jq -r .error.code <<<"$out")"
```

Result output is `serde_json::to_string_pretty` (or compact JSON for the
offline commands), so it pipes cleanly into `jq`.

## Subcommands

### Network — talk to a registry

These need the registry's HTTPS URL and apply the full
[security defaults](security.md) (HTTPS-only, SSRF filtering, caps).

#### `capabilities`
```bash
acdp capabilities <registry-url>
```
Fetches `GET /.well-known/acdp.json`. Prints the `CapabilitiesDocument`.

#### `retrieve` / `body`
```bash
acdp retrieve <registry-url> <ctx-id>     # full context, verified
acdp body     <registry-url> <ctx-id>     # body only, NOT verified
```
`retrieve` runs the full consumer pipeline (`VerifiedContext::fetch` with the
default policy: schema, `ctx_id` binding, `content_hash` recompute, DID
resolution, signature) and prints the `FullContext` only if every step passes.
`body` fetches the bare body (`RegistryClient::retrieve_body`) and prints it
without verifying anything; pipe a saved copy into `acdp verify` to check it.
See [Consuming & verifying](consuming.md).

#### `search`
```bash
acdp search <registry-url> \
  [--q QUERY] [--limit N] [--type T] [--tags A,B] \
  [--domain D] [--status S] [--agent-id DID] [--cursor C]
```
Keyword discovery (RFC-ACDP-0005). Prints only the `matches` array; the
response's `next_cursor` is not printed, so use the library's
`RegistryClient::search` when you need to page.

#### `publish`
```bash
acdp publish <registry-url> \
  --key-seed <64-hex> \
  --agent-id <DID> --key-id <DID-URL> \
  [--key-algorithm ed25519|ecdsa-p256] \
  --title T --type CT \
  [--domain D] [--visibility V] \
  [--audience DID,DID] [--summary S] [--description D] [--tags A,B,C] \
  [--idempotency-key UUID] \
  < producer_content.json          # optional stdin overlay
```
Builds, signs, and POSTs a context. The `--key-seed` is a 64-hex-char (32-byte)
private seed. Flags set individual fields; a JSON object on **stdin** is
overlaid for anything the flags don't cover (`data_refs`, `metadata`,
`data_period`, `derived_from`, `contributors`, `schema_uri`, `expires_at`,
`acdp_version`, …). A field supplied both as a flag and in the overlay is rejected (exit 1); `tags` is the exception, where the flag wins. `title` and `type` are
required, from a flag or from the overlay.

> The seed is passed on the command line, which is visible in process listings
> and shell history. For anything but local testing, prefer building requests in
> code where the key comes from secure storage — see [Producing contexts](producing.md).

#### `resolve`
```bash
acdp resolve <ctx-id> [--max-depth N]
```
Walks the `derived_from` provenance graph via `CrossRegistryResolver`,
verifying each hop. The registry authority is taken from the `ctx-id` itself.
Prints the root body plus its ancestors' bodies as a JSON array. `--max-depth`
tightens the default (10).

#### `verify`
```bash
acdp verify <body.json>
```
Verifies a stored `Body` (for example one saved from `acdp body`): schema
validation → recompute `content_hash` → verify the signature (`ed25519` or
`ecdsa-p256`) against the producer key. For a `did:web` producer the key is
resolved over HTTPS, so this needs the network; a `did:key` producer verifies
fully offline. Prints `{"ok":true,"ctx_id","agent_id","content_hash"}`.

### Offline — no network

#### `validate`
```bash
acdp validate <publish_request.json>
```
Runs the offline schema validator (`validation::validate_publish_request`) on a
`PublishRequest` file, then recomputes its `content_hash`. Prints
`{"ok":true, "content_hash_declared", "content_hash_recomputed",
"hash_matches", …}`; `hash_matches: false` is informational and does not change
the exit code. A schema violation exits 2 with an error envelope.

#### `canonicalize` / `hash`
```bash
echo '{"b":2,"a":1}' | acdp canonicalize    # → {"a":1,"b":2}  (RFC 8785 JCS)
echo '{"b":2,"a":1}' | acdp hash            # → sha256:<hex>
```
The primitives behind `content_hash`. `hash` is the exact `content_hash`
computation: it drops the RFC-ACDP-0001 §5.7 exclusion set (if present) and
hashes the JCS bytes, so feeding it ProducerContent, a `PublishRequest`, or a
`Body` gives the same result — handy for debugging a hash mismatch.

#### `sign`
```bash
jq -c . producer_content.json | acdp sign <seed-hex> <key-id>
```
Reads **ProducerContent JSON** on stdin, computes its `content_hash`, and signs
it with the Ed25519 seed. Prints
`{"content_hash":"sha256:…","signature":{"algorithm":"ed25519","key_id":…,"value":…}}`.
The signature is over the ASCII `"sha256:<hex>"` string, **not** the raw digest
(see [Architecture](architecture.md#three-things-that-trip-people-up)). Only
Ed25519 is supported here; use `publish --key-algorithm ecdsa-p256` or the
library for P-256.

## Worked example

Reproduce the `sig-001` golden vector without any network, using the
`vectors[0].producer_content` object from the spec's
[`sig-001-ed25519-golden.json`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/schemas/conformance/sig-001-ed25519-golden.json)
(its seed is the publicly known all-zero TEST-ONLY seed):

```bash
# 1. hash the producer content
jq -c .vectors[0].producer_content sig-001-ed25519-golden.json | acdp hash
# sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5

# 2. hash + sign it in one step
jq -c .vectors[0].producer_content sig-001-ed25519-golden.json \
  | acdp sign 0000000000000000000000000000000000000000000000000000000000000000 \
      "did:web:agents.example.com:test-producer#key-1" \
  | jq -r .signature.value
# ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ==
```

For everything the CLI can do, the library API does the same with typed results
— the CLI is a convenience layer, not a separate surface.
