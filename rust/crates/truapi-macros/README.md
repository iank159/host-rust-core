# TrUAPI proc macros

This crate provides TrUAPI wire annotations and versioned envelopes, plus
server-specific macros for inter-host SSO contracts.

| Macro | Input | Generated code |
| --- | --- | --- |
| `SsoWire` | Hand-written `v1::RemoteMessage` enum | Request classification and wrapping, message names, and correlation helpers |
| `SsoResponse` | Response struct with `responding_to: String` followed by one `Result<Ok, Err>` field | Payload types and accessors, response construction, wire wrapping, and transcript outcome |
| `sso_service` | Dedicated inherent impl of SSO handlers | Request/response pairing, exhaustive dispatch, and handler reply conversion |

## Handler contract

Every method in the annotated impl is an endpoint. Its parameter names a wire
request type and its return type names the corresponding wire response:

```rust
#[truapi_macros::sso_service]
impl SigningHostSsoService {
    async fn get_account_alias(
        &self,
        cx: &SsoRequestContext,
        request: GetAccountAliasRequest,
    ) -> GetAccountAliasResponse {
        self.signing_host
            .account_alias(&cx.call, &cx.session, request)
            .await
    }
}
```

The method name is the request type's snake-case stem: `GetAccountAliasRequest`
requires `get_account_alias`. The named response defines the pairing, including
when two handlers share one response type. Constructors and internal helpers
belong in a separate, unannotated impl.

Handler signatures expand to native async methods returning `SsoReply<Response>`.
Bodies return the response's ordinary `Result` payload or an explicit `SsoReply`
with a local transcript outcome. An inner async block preserves `?` and early
returns; `.into()` performs the reply conversion.

The generated `dispatch(&self, session, message)` method classifies the message,
creates context from the supplied signing session, and exhaustively selects a
handler. Without a session it returns the response's typed disconnected error.
Shared reply finishing supplies correlation and the transcript outcome. Missing
handlers, undeclared wire variants, and incompatible payloads fail compilation.

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
