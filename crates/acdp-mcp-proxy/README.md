# acdp-mcp-proxy

The MCP signing proxy of [RFC-ACDP-0019](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0019-mcp-tool-result-provenance.md) (0.5.0 **Draft**), profile `acdp-producer-mcp-proxy`.

It sits between an MCP client and any stdio MCP server and relays every message unchanged. For each `tools/call` it publishes one signed `acdp:mcp-tool-result` body to an ACDP registry, signed with **your** key. It then returns the result with one key added to `_meta`:

```json
"_meta": {
  "io.acdp/provenance": {
    "ctx_id": "acdp://registry.example.com/3c2b1a09-8f7e-4d6c-9b5a-4e3d2c1b0a9f",
    "content_hash": "sha256:3b2b…634f",
    "registry": "registry.example.com",
    "salt": "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
  }
}
```

The signature means *the operator observed this call and this result*. It does **not** mean the upstream server vouches for the result. Consumers decide which proxies to trust by `agent_id`.

## Install and run

```bash
cargo install acdp-mcp-proxy
acdp-mcp-proxy --config proxy.json --print-did   # the agent_id your records carry
```

Point your MCP client at the proxy instead of at the server:

```json
{ "mcpServers": { "fraud-stats": {
    "command": "acdp-mcp-proxy", "args": ["--config", "/etc/acdp/proxy.json"] } } }
```

## Config

```json
{
  "upstream": {
    "command": "npx",
    "args": ["-y", "@example/fraud-stats-mcp@1.4.2", "--token", "s3cret"],
    "env": { "FRAUD_API_KEY": "…" },
    "redact_args": [3]
  },
  "registry": "https://registry.example.com",
  "key": { "seed_file": "/etc/acdp/proxy.seed" },
  "visibility": "private",
  "publish_timeout_ms": 15000,
  "max_attempts": 4,
  "external": { "dir": "/srv/acdp-results", "base_url": "https://results.example.com" },
  "default": { "fail_closed": false },
  "tools": {
    "regional_fraud_rate": { "embed": true },
    "transfer_funds": { "fail_closed": true },
    "debug_dump": { "skip": true }
  }
}
```

| Key | Meaning |
|---|---|
| `upstream` | The stdio server to launch. `env` is passed to the server and never enters a record. `redact_args` lists the indices of arguments that carry credentials. Each one is replaced by `<redacted>` before `endpoint_hash` is computed (§4.2). |
| `key` | A 32-byte Ed25519 seed as 64 hex characters, read from `seed_file` or from the environment variable named by `seed_env`. Without `did`, the identity is the seed's `did:key`. For `did:web`, also set `did` and `key_id`. Use a dedicated key for the proxy (§8.1). |
| `visibility` / `audience` | Defaults to `private` (§8.3). You can override it per tool. |
| `publish_timeout_ms`, `max_attempts` | Each publish, retries included, is bounded by `publish_timeout_ms`. Every retry sends the byte-identical body with `Idempotency-Key: acdp-mcp-<content_hash hex>` (§7). |
| `tools.<name>.embed` | Allowlists the tool for publishing the result itself (§5). The result is embedded when it is ≤ 64 KB. Over that, it goes to `external` when configured, otherwise the record is unembedded and salted. |
| `tools.<name>.fail_closed` | When publishing fails, the result is withheld and an `isError` result is returned instead. The default is fail-open: the result is returned with `{"failed": true, "error"?}`. |
| `tools.<name>.skip` | The tool is relayed without a record. The default is to cover every tool. |

When `external` is set, the proxy writes `<dir>/<content-hash hex>.json` before it publishes. The bytes it writes are the JCS of the hashed result. Your web server is expected to serve `dir` at `base_url`.

## Behaviour

- **No change to results.** `content`, `structuredContent`, `isError` and every other `_meta` key are left exactly as the server sent them. If the server already set `io.acdp/provenance`, the proxy leaves that value in place and still publishes its own record.
- **Salted by default.** The arguments, the hashed result and the request id are hashed as `H(salt ‖ JCS(v))`. The salt is a fresh 32-byte value per call and is revealed only to the client, in `_meta`. Only embedded records are unsalted.
- **`derived_from`** lists the `acdp://` ids that appear as whole string values in the arguments. They are collected in JCS order, without duplicates, up to 1000.
- **No link before the publish response.** A `tools/call` result is held until its publish succeeds or fails. All other messages pass through byte for byte.
- stdout carries only the relayed protocol. Diagnostics go to stderr.

Only the stdio transport is supported. The record format already covers `streamable-http` and `sse`, and `record::http_descriptor` builds their endpoint descriptor.

## Conformance

`tests/conformance.rs` reproduces `mcp-001` byte for byte: every hash, the canonical form, the `content_hash`, the Ed25519 signature, the Idempotency-Key and the returned result. `tests/relay.rs` runs the relayed scenarios of `mcp-002`..`mcp-007` against a stub MCP server and a mock registry. Point `ACDP_SPEC_DIR` at a spec checkout to run them.

License: MIT OR Apache-2.0.
