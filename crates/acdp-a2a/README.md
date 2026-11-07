# acdp-a2a

A2A artifact provenance, per [RFC-ACDP-0022](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0022-a2a-artifact-provenance.md). The RFC is on the **0.5.0 Draft** line.

An A2A server agent publishes each artifact it completes as a body it signs itself, with its own `did:web` or `did:key`. The link goes back inside the artifact:

```json
"metadata": {
  "io.agentcontextdistributionprotocol/provenance": {
    "ctx_id": "acdp://registry.example.com/3f6a2b1c-9d8e-4f7a-8b6c-5d4e3f2a1b0c",
    "content_hash": "sha256:…",
    "registry": "registry.example.com",
    "salt": "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
  }
}
```

A later holder of the artifact uses the link to check three things:

- the agent published exactly these parts;
- whether the agent has since superseded or retracted them;
- which ACDP contexts the agent used as inputs.

A verified body shows what the agent authored. It does not mean anyone accepted the result.

## Agent side (`acdp-producer-a2a`)

```rust,ignore
use acdp_a2a::{Agent, ArtifactPolicy, BodyTemplate, ChunkOutput, TaskSession};

let mut template = BodyTemplate::new(ContextType::parse("analysis")?);
template.domain = Some("payments.fraud".into());
let agent = Agent::new(producer, registry_client, "1.0", ArtifactPolicy::new(template));

let mut task = TaskSession::new(task_id, context_id);
task.observe_client_message(&message);               // io.agentcontextdistributionprotocol/inputs → derived_from
for chunk in chunks {
    match agent.on_chunk(&mut task, chunk).await? {
        ChunkOutput::Emit(c) => send(c),              // link on the completing chunk
        ChunkOutput::Withhold { failure, .. } => fail_task(failure),
    }
}
let out = agent.on_task(&mut task, snapshot).await?; // terminal state completes the rest
send(out.task);
```

- **One body per completed artifact.** The agent completes an artifact on its `lastChunk: true` chunk or when the task reaches a terminal state. It never publishes a body per chunk or per Task. The completing chunk is returned only after the publish has settled, so a link never names an unpublished body.
- **Your own type.** The record sits at `metadata["acdp:a2a"]` beside your own metadata. The body type is yours; the type names that RFC-ACDP-0022 reserves are refused.
- **Salted.** The artifact, task and context ids are always hashed with a fresh 32-byte salt. The parts hash is salted too, unless the parts are embedded. Embedding is opt-in per artifact (`Embedding::Allowlisted`). The salt only ever appears in the link.
- **Re-emission.** If the same artifact is re-emitted in the same task, the new body supersedes the previous one. A continuation in a new task starts at version 1, with the earlier body first in `derived_from` (`ArtifactHints::continues`).
- **Inputs.** `derived_from` takes the ctx_ids from `Message.metadata["io.agentcontextdistributionprotocol/inputs"]`. They are deduplicated and capped at 1000, and only inputs that were verified and used count. Ids are never scraped from Parts.
- **Fail-open.** By default a failed publish still emits the artifact, carrying `{"failed": true, "error"?}`. With `fail_closed` set, the artifact is withheld instead. Retries reuse the Idempotency-Key `acdp-a2a-<content_hash hex>`.
- **Card.** `card::card_extension` builds the `https://agentcontextdistributionprotocol.io/ext/a2a/v1` AgentExtension, with `required: false` and `params {registry, agentId}`.

## Holder side (`acdp-consumer-a2a`)

```rust,ignore
use acdp_a2a::verify::{resolve_and_verify, CardContext, HeldArtifact, HolderPolicy, TrustedAgents};

let policy = HolderPolicy {
    trusted: TrustedAgents::Only(vec![agent_did]),
    card: Some(CardContext::from_extensions(card_extensions)),
};
let held = HeldArtifact { artifact: &artifact, task_id: Some(&task.id), context_id: Some(&task.context_id) };
let verdict = resolve_and_verify(&cross_registry_resolver, &held, &policy).await?;
// verdict.status: Superseded / Retracted are reported, not failures.
```

The verification runs the six steps of RFC-ACDP-0022 §8. A failed check returns a `VerifyFailure`. Its `kind.code()` uses the same vocabulary as the `a2a-001` holder negatives. `is_unrecognised()` returns true when the link or record is not one to rely on (steps 1–3). It returns false when the body is valid but does not match the held artifact (steps 4–5). There are four entry points:

- `verify_offline`: verifies a `did:key` body exactly as received.
- `fetch_and_verify`: fetches the body through a `RegistryClient`, then verifies it.
- `resolve_and_verify`: fetches through the `CrossRegistryResolver`, with its allowlist and SSRF policy. The Card never widens either.
- `verify_against_body`: runs the checks against a body you have already verified.

## Conformance

`a2a-001` runs byte for byte in `tests/conformance.rs`:

- both executable vectors;
- the 2 holder positives;
- all 16 holder negatives.

`tests/behavior.rs` covers `a2a-002`..`a2a-008` against a wiremock registry. With `ACDP_SPEC_DIR=../agentcontextdistributionprotocol ACDP_REQUIRE_CONFORMANCE=1`, a missing spec checkout is a failure.
