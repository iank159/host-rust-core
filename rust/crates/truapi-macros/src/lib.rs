//! Proc macros for TrUAPI annotations, versioned envelopes, and inter-host SSO.
//!
//! Each macro's implementation lives in its own module. Rust requires the
//! public proc-macro entry points to be defined at the crate root.

mod service;
mod sso_service;
mod sso_wire;
mod versioned_type;
mod wire;

use proc_macro::TokenStream;

/// Declare connection-scoped middleware required by a TrUAPI service trait.
///
/// The metadata is preserved in rustdoc JSON for `truapi-codegen`.
#[proc_macro_attribute]
pub fn service(args: TokenStream, item: TokenStream) -> TokenStream {
    service::expand(args, item)
}

/// Mark a TrUAPI trait method with its wire-protocol discriminant id.
///
/// ```ignore
/// #[wire(request_id = 4)]
/// async fn host_account_get(...) -> ...;
///
/// #[wire(start_id = 42)]
/// async fn host_account_connection_status_subscribe(...) -> ...;
///
/// // Classify a method whose payloads carry key material or bearer secrets.
/// // The flag is folded into the wire schema-hash fingerprint, so a change in a
/// // frame's sensitivity classification is caught as contract drift. It is a
/// // classification only, and grants no confidentiality: it reaches neither the
/// // generated TypeScript nor any runtime, and nothing suppresses decoding of
/// // the payload.
/// #[wire(request_id = 114, sensitive)]
/// async fn sign_raw(...) -> ...;
/// ```
///
/// Expands to the original method plus hidden doc tags that `truapi-codegen`
/// extracts from rustdoc JSON to build the wire table and versioned clients.
#[proc_macro_attribute]
pub fn wire(args: TokenStream, item: TokenStream) -> TokenStream {
    wire::expand(args, item)
}

/// Generate versioned message envelopes.
///
/// ```ignore
/// versioned_type! {
///     pub enum HostFooRequest { V1 => v01::HostFooRequest }
///     pub enum HostFooResponse { V1 }
/// }
/// ```
///
/// Each declaration becomes a SCALE enum with positional codec indices and an
/// `impl Versioned` exposing `Latest`, `LATEST`, and `version()`. Single-version
/// envelopes also get trivial `IntoLatest`/`FromLatest` impls; multi-version
/// envelopes leave those to be written by hand, since the conversion is bespoke.
///
/// The enum and every variant receive generated doc comments; a variant keeps
/// its own doc attributes when the declaration provides them.
///
/// The declared visibility (`pub`, `pub(crate)`, or none) carries through to the
/// generated enum.
///
/// The generated impls name `crate::versioned::*` traits, so invoke this from
/// within the `truapi` crate.
#[proc_macro]
pub fn versioned_type(item: TokenStream) -> TokenStream {
    versioned_type::expand(item)
}

/// Classify the SSO wire enum's request, response, and disconnect variants.
///
/// Emits crate-private `AnyRequest`, `Incoming`, `classify()`, request wrapping,
/// and the enum's `name()`, `responding_to()`, and `with_responding_to()` next to
/// the enum. Request/response pairing comes from `#[sso_service]`. Only valid
/// inside `truapi-server`.
#[proc_macro_derive(SsoWire)]
pub fn derive_sso_wire(item: TokenStream) -> TokenStream {
    sso_wire::expand(item)
}

/// Define SSO handlers in a dedicated inherent implementation.
///
/// Every method must be `async fn name(&self, cx: &SsoRequestContext, request:
/// <Request>) -> <Response>`, where the named response aliases its `Result`
/// payload and selects the wire variant. The method name selects the request
/// variant; its payload type can be generic. Each signature supplies `SsoRequest` pairing;
/// the macro generates an exhaustive `dispatch` method on the service type.
/// Handler return types expand to `SsoReply<Payload>`, and bodies return
/// ordinary `Result` payloads or explicit replies with a transcript outcome.
/// An inner async block preserves `return` and `?` semantics. Constructors and
/// other helpers belong in a separate, unannotated implementation.
///
/// The macro uses native async methods and refers to the context and reply
/// types in `crate::runtime::sso_service`. It only works inside `truapi-server`.
#[proc_macro_attribute]
pub fn sso_service(args: TokenStream, item: TokenStream) -> TokenStream {
    sso_service::expand(args, item)
}
