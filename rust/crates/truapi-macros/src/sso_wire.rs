//! Classification, request wrapping, and correlation helpers for the SSO wire enum.

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Fields, GenericArgument, PathArguments, Type, Variant, parse_macro_input,
};

use crate::sso_common::{snake_case, wire_path};

const DISCONNECT_VARIANT: &str = "Disconnected";

/// Parse the macro input and emit generated code or a compiler diagnostic.
pub(super) fn expand(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(item as syn::DeriveInput);
    match derive_sso_wire(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Expand `#[derive(SsoWire)]`.
fn derive_sso_wire(input: DeriveInput) -> syn::Result<TokenStream> {
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "SsoWire is derived on the wire enum",
        ));
    };
    let enum_ident = &input.ident;
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    let mut saw_disconnect = false;
    for variant in &data.variants {
        let name = variant.ident.to_string();
        if name == DISCONNECT_VARIANT {
            if !matches!(variant.fields, Fields::Unit) {
                return Err(syn::Error::new_spanned(
                    variant,
                    "`Disconnected` carries no payload",
                ));
            }
            saw_disconnect = true;
        } else if name.ends_with("Request") {
            requests.push(RequestVariant::parse(variant)?);
        } else if name.ends_with("Response") {
            responses.push(ResponseVariant::parse(variant)?);
        } else {
            return Err(syn::Error::new_spanned(
                &variant.ident,
                "variant must end in `Request` or `Response`, or be `Disconnected`",
            ));
        }
    }
    if !saw_disconnect {
        return Err(syn::Error::new_spanned(
            enum_ident,
            "missing `Disconnected` variant",
        ));
    }

    let wire = wire_path();
    let disconnect = format_ident!("{DISCONNECT_VARIANT}");
    let mut any_variants = Vec::new();
    let mut classify_arms = Vec::new();
    let mut wrap_arms = Vec::new();
    for request in &requests {
        let variant = &request.variant;
        let payload = &request.payload;
        let (wrap, unwrap) = if request.boxed {
            (quote!(Box::new(payload)), quote!(*payload))
        } else {
            (quote!(payload), quote!(payload))
        };
        wrap_arms.push(quote! {
            AnyRequest::#variant(payload) => #enum_ident::#variant(#wrap)
        });
        let doc = format!("Payload of [`{enum_ident}::{variant}`].");
        any_variants.push(quote! { #[doc = #doc] #variant(#payload) });
        classify_arms.push(quote! {
            #enum_ident::#variant(payload) => Incoming::Request(AnyRequest::#variant(#unwrap))
        });
    }
    let mut retarget_arms = Vec::new();
    let mut name_arms = vec![quote! { #enum_ident::#disconnect => #DISCONNECT_VARIANT }];
    let mut responding_to_arms = Vec::new();
    for request in &requests {
        let variant = &request.variant;
        let variant_name = variant.to_string();
        let stem = variant_name
            .strip_suffix("Request")
            .expect("request variant");
        let name = snake_case(stem);
        name_arms.push(quote! { #enum_ident::#variant(_) => #name });
    }
    for response in &responses {
        let variant = &response.variant;
        let payload = &response.payload;
        let name = variant.to_string();
        classify_arms.push(quote! { #enum_ident::#variant(_) => Incoming::Response(#name) });
        name_arms.push(quote! { #enum_ident::#variant(_) => #name });
        responding_to_arms.push(quote! {
            #enum_ident::#variant(response) => Some(#wire::SsoResponse::responding_to(response))
        });
        retarget_arms.push(quote! {
            #enum_ident::#variant(response) => #enum_ident::#variant(
                <#payload as #wire::SsoResponse>::new(
                    responding_to,
                    #wire::SsoResponse::into_payload(response),
                ),
            )
        });
    }
    Ok(quote! {
        /// Every request payload the wire can carry, unwrapped from its variant.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) enum AnyRequest {
            #(#any_variants,)*
        }

        impl From<AnyRequest> for #enum_ident {
            fn from(request: AnyRequest) -> Self {
                match request {
                    #(#wrap_arms,)*
                }
            }
        }

        /// Role of one decoded wire message.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) enum Incoming {
            /// A request to dispatch.
            Request(AnyRequest),
            /// A response variant, named; requests never arrive as responses.
            Response(&'static str),
            /// The peer ended the session.
            Disconnected,
        }

        /// Sort a wire message into request, response, or disconnect.
        pub(crate) fn classify(message: #enum_ident) -> Incoming {
            match message {
                #enum_ident::#disconnect => Incoming::Disconnected,
                #(#classify_arms,)*
            }
        }

        impl #enum_ident {
            /// Service method name for requests; variant name for other messages.
            pub(crate) fn name(&self) -> &'static str {
                match self {
                    #(#name_arms,)*
                }
            }

            /// `message_id` of the request a response answers; `None` for
            /// requests and `Disconnected`.
            pub(crate) fn responding_to(&self) -> Option<&str> {
                match self {
                    #(#responding_to_arms,)*
                    _ => None,
                }
            }

            /// Re-address a response to the request sent as `responding_to`;
            /// requests and `Disconnected` pass through unchanged.
            pub(crate) fn with_responding_to(self, responding_to: String) -> Self {
                match self {
                    #(#retarget_arms,)*
                    other => other,
                }
            }
        }
    })
}

struct RequestVariant {
    variant: Ident,
    payload: Type,
    boxed: bool,
}

impl RequestVariant {
    fn parse(variant: &Variant) -> syn::Result<Self> {
        let payload = single_payload(variant)?;
        let (payload, boxed) = match box_inner(payload) {
            Some(inner) => (inner.clone(), true),
            None => (payload.clone(), false),
        };
        Ok(Self {
            variant: variant.ident.clone(),
            payload,
            boxed,
        })
    }
}

struct ResponseVariant {
    variant: Ident,
    payload: Type,
}

impl ResponseVariant {
    fn parse(variant: &Variant) -> syn::Result<Self> {
        Ok(Self {
            variant: variant.ident.clone(),
            payload: single_payload(variant)?.clone(),
        })
    }
}

fn single_payload(variant: &Variant) -> syn::Result<&Type> {
    match &variant.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Ok(&fields.unnamed[0].ty),
        _ => Err(syn::Error::new_spanned(
            variant,
            "expected exactly one tuple payload",
        )),
    }
}

fn box_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if segment.ident != "Box" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    match args.args.first()? {
        GenericArgument::Type(inner) if args.args.len() == 1 => Some(inner),
        _ => None,
    }
}
