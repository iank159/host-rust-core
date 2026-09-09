# TrUAPI proc macros

This crate provides TrUAPI wire annotations and versioned envelopes, plus
server-specific macros for inter-host SSO contracts.

Each macro has its own implementation module. [`lib.rs`](src/lib.rs) contains
the thin public entry points, which Rust requires at the proc-macro crate root.

| Macro | Input | Generated code |
| --- | --- | --- |
| [`service`](src/service.rs) | TrUAPI service trait | Required middleware metadata for codegen |
| [`wire`](src/wire.rs) | TrUAPI method | Wire IDs and flags for codegen |
| [`versioned_type!`](src/versioned_type.rs) | Versioned envelope declarations | SCALE enums and version conversion traits |
| [`SsoWire`](src/sso_wire.rs) | Hand-written `v1::RemoteMessage` enum | Request classification and wrapping, message names, and correlation helpers |
| [`sso_service`](src/sso_service.rs) | Dedicated inherent impl of SSO handlers | Request/response variant conversion, exhaustive dispatch, and handler reply conversion |

## Handler contract

Every method in the annotated impl is an endpoint. Its name selects a wire
request variant, its parameter declares the payload, and its return type names
the response's `Result` payload:

```rust
pub type GetAccountAliasResponse = Result<HostAccountGetAliasResponse, RingVrfError>;

#[truapi_macros::sso_service]
impl SigningHostSsoService {
    async fn get_account_alias(
        &self,
        cx: &SsoRequestContext,
        request: ProductRequest<HostAccountGetAliasRequest>,
    ) -> GetAccountAliasResponse {
        self.signing_host
            .account_alias(&cx.call, &cx.session, request)
            .await
    }
}
```

The method `get_account_alias` selects `GetAccountAliasRequest`; parameter types
can be canonical payloads or generic wrappers without request aliases.
The return type's name selects the wire response
variant, including when two handlers share one variant. Distinct variants may
carry identical result types; conversion belongs to the request, so those
responses remain distinguishable. Constructors and helpers belong in a separate impl.

Handler signatures expand to native async methods returning `SsoReply<Payload>`.
Bodies return the named `Result` or an explicit reply with a local transcript
outcome. Shared Rust code adds `Response<P> { responding_to, payload }`;
the generated request contract selects its wire variant. An inner async block
preserves `?` and early returns.

The generated `dispatch(&self, session, message)` method classifies the message,
creates context from the supplied signing session, and exhaustively selects a
handler. Without a session it returns the response's typed disconnected error.
Shared reply finishing supplies correlation and defaults the transcript outcome
to success or error; handlers classify operation-specific outcomes. Missing
handlers, undeclared wire variants, and incompatible payloads fail compilation.

The wire enum contains requests, responses, and disconnects in one SCALE tag
space. `SsoWire` projects its requests into `AnyRequest` through `classify()`.
Dispatch matches that request-only enum exhaustively, so a new wire request
cannot silently fall through without a handler.

## Server integration

These macros target contracts in `crate::host_logic::sso::{messages, wire}` and
`crate::runtime::{authority, sso_service}`. They are intended for invocation inside
`truapi-server`; the canonical `truapi` crate uses the other macros and has no
server runtime dependency. Wire encoding remains owned by the enum and payload
codec derives. Transport, consent, session revalidation, and business logic belong
to the server implementation.

The [compiler tests](tests/sso.rs) exercise the macros against minimal versions of
those contracts. They cover valid handlers, shared and explicit response pairing,
boxed requests, independent wire helpers, and invalid declarations:

```sh
cargo test -p truapi-macros --locked
```
