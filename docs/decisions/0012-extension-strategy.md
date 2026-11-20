# Decision 0012: Traits first, webhooks second, WebAssembly plugins last

Status: Proposed

## Context

The specification wants a plugin architecture for ten kinds of extension and asks to evaluate WebAssembly and the WebAssembly System Interface. A plugin system designed before the core exists tends to freeze the wrong interfaces.

## Decision

1. From Phase 1, every variable behavior is a trait with more than one in-tree implementation, registered in the composition root. These traits are internal and may change.
2. From Phase 5, outbound extension is offered through signed webhooks over the domain event stream.
3. In Phase 8, `plugin-runtime` runs WebAssembly components on Wasmtime for a chosen subset of extension points (authentication actions, claims mappers, risk signals, event handlers, notification channels). Interfaces are WIT worlds versioned independently of internal traits. Plugins get no ambient authority; capabilities are declared in a manifest and approved per tenant.
4. Security-critical points (credential verification, key providers, authorization engines) are never exposed to sandboxed plugins. External authorization engines integrate as adapter crates.
5. No dynamic loading of native code.

## Consequences

- The WIT interface is designed after two or more real in-tree implementations exist for each point, so it reflects actual needs.
- Users needing custom logic before Phase 8 use webhooks or contribute an in-tree implementation.
- The sandbox adds per-call overhead; acceptable for the chosen points, which run at most a few times per request.

## Alternatives considered

- **WebAssembly from the start**: stable interface committed before the domain settles.
- **Embedded scripting (JavaScript, Lua, Rhai)**: easy to adopt, harder to sandbox and to limit; one language imposed on everyone.
- **Native dynamic libraries**: no stable binary interface, full process authority.
- **Out-of-process plugins over gRPC**: strong isolation, but an operational burden for each plugin; webhooks already cover the remote case.
