//! Derives for the inter-host SSO protocol in `truapi-server`.
//!
//! `SsoWire` reads the hand-written `v1::RemoteMessage` enum and classifies
//! its variants. `sso_service` pairs requests with the wire responses named
//! in the handler signatures. `SsoResponse` reads a response's payload field.
//! These macros emit `crate::host_logic::sso::...` paths and only work inside
//! `truapi-server`.

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Fields, FnArg, GenericArgument, ImplItem, ItemImpl, Pat, PathArguments,
    Signature, Type, Variant,
};

const DISCONNECT_VARIANT: &str = "Disconnected";

fn wire_path() -> TokenStream {
    quote!(crate::host_logic::sso::wire)
}

fn enum_path() -> TokenStream {
    quote!(crate::host_logic::sso::messages::v1::RemoteMessage)
}

fn reply_path() -> TokenStream {
    quote!(crate::runtime::sso_service::SsoReply)
}

/// Expand `#[derive(SsoWire)]`.
pub(crate) fn derive_sso_wire(input: DeriveInput) -> syn::Result<TokenStream> {
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

fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Expand `#[derive(SsoResponse)]`.
pub(crate) fn derive_sso_response(input: DeriveInput) -> syn::Result<TokenStream> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "SsoResponse is derived on a response struct",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "expected named fields",
        ));
    };
    let mut payload = None;
    let mut saw_responding_to = false;
    for field in &fields.named {
        let ident = field.ident.as_ref().expect("named field");
        if ident == "responding_to" {
            saw_responding_to = true;
        } else if payload.replace((ident.clone(), &field.ty)).is_some() {
            return Err(syn::Error::new_spanned(
                ident,
                "a response has `responding_to` and exactly one payload field",
            ));
        }
    }
    if !saw_responding_to {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "missing `responding_to: String`",
        ));
    }
    let first_is_responding_to = fields
        .named
        .first()
        .and_then(|field| field.ident.as_ref())
        .is_some_and(|ident| ident == "responding_to");
    if !first_is_responding_to {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`responding_to` must be the first field: SCALE encodes fields positionally",
        ));
    }
    let Some((payload_field, payload_ty)) = payload else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "missing the payload field",
        ));
    };
    let (ok, err) = result_args(payload_ty).ok_or_else(|| {
        syn::Error::new_spanned(payload_ty, "the payload field must be a `Result<Ok, Err>`")
    })?;
    let mut outcome_fn = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("sso") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("outcome") {
                outcome_fn = Some(meta.value()?.parse::<syn::Path>()?);
                Ok(())
            } else {
                Err(meta.error("expected `outcome = <path>`"))
            }
        })?;
    }

    let name = &input.ident;
    let wire = wire_path();
    let message = enum_path();
    let outcome = match outcome_fn {
        Some(path) => quote! { #path(&self.#payload_field) },
        None => quote! { #wire::ResponseOutcome::from_payload(&self.#payload_field) },
    };
    Ok(quote! {
        impl #wire::SsoResponse for #name {
            fn outcome(&self) -> #wire::ResponseOutcome {
                #outcome
            }
            type Ok = #ok;
            type Err = #err;
            fn new(responding_to: String, payload: Result<#ok, #err>) -> Self {
                Self { responding_to, #payload_field: payload }
            }
            fn responding_to(&self) -> &str {
                &self.responding_to
            }
            fn into_payload(self) -> Result<#ok, #err> {
                self.#payload_field
            }
            fn into_message(self) -> #message {
                #message::#name(self)
            }
            fn from_message(message: #message) -> Option<Self> {
                match message {
                    #message::#name(response) => Some(response),
                    _ => None,
                }
            }
        }
    })
}

fn result_args(ty: &Type) -> Option<(&Type, &Type)> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if segment.ident != "Result" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    let mut types = args.args.iter().filter_map(|arg| match arg {
        GenericArgument::Type(ty) => Some(ty),
        _ => None,
    });
    let ok = types.next()?;
    let err = types.next()?;
    types.next().is_none().then_some((ok, err))
}

/// Pair and dispatch the handlers in one inherent implementation.
pub(crate) fn expand_sso_service(mut item: ItemImpl) -> syn::Result<TokenStream> {
    if item.trait_.is_some() {
        return Err(syn::Error::new_spanned(
            &item,
            "sso_service requires an inherent implementation",
        ));
    }
    if !item.generics.params.is_empty() || item.generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            &item.generics,
            "SSO handlers require a concrete service type",
        ));
    }
    let wire = wire_path();
    let message = enum_path();
    let reply = reply_path();
    let runtime = quote!(crate::runtime::sso_service);
    let mut impls = Vec::new();
    let mut arms = Vec::new();
    for entry in &mut item.items {
        let ImplItem::Fn(method) = entry else {
            return Err(syn::Error::new_spanned(
                entry,
                "the annotated implementation holds only SSO handler methods",
            ));
        };
        let (request_ty, response_ty) = method_types(&method.sig)?;
        method.sig.output = syn::parse_quote!(-> #reply<#response_ty>);
        let body = &method.block;
        method.block = syn::parse_quote!({
            (async move #body).await.into()
        });
        let variant = last_segment(&request_ty)?;
        let name = &method.sig.ident;
        let variant_name = variant.to_string();
        let stem = variant_name.strip_suffix("Request").ok_or_else(|| {
            syn::Error::new_spanned(&request_ty, "request type must end in `Request`")
        })?;
        let expected_name = snake_case(stem);
        if name != &expected_name {
            return Err(syn::Error::new_spanned(
                name,
                format!("the method for `{variant}` must be named `{expected_name}`"),
            ));
        }
        impls.push(quote! {
            impl #wire::SsoRequest for #request_ty {
                const NAME: &'static str = #expected_name;
                type Response = #response_ty;

                fn into_message(self) -> #message {
                    use crate::host_logic::sso::messages::v1::AnyRequest;
                    AnyRequest::#variant(self).into()
                }

                fn from_message(message: #message) -> Option<Self> {
                    use crate::host_logic::sso::messages::v1::{AnyRequest, Incoming, classify};
                    match classify(message) {
                        Incoming::Request(AnyRequest::#variant(request)) => Some(request),
                        _ => None,
                    }
                }
            }
        });
        arms.push(quote! {
            AnyRequest::#variant(request) => {
                let reply = match &cx {
                    Some(cx) => self.#name(cx, request).await,
                    None => Err(#wire::SsoError::not_connected()).into(),
                };
                reply.finish(&message_id)
            }
        });
    }
    if arms.is_empty() {
        return Err(syn::Error::new_spanned(
            &item.self_ty,
            "the annotated implementation declares no SSO handlers",
        ));
    }

    item.items.push(syn::parse_quote! {
        /// Answer one wire message with this service.
        ///
        /// `session` is the signing host's current session; without one every
        /// request is answered with its error type's `not_connected()`.
        pub(crate) async fn dispatch(
            &self,
            session: Option<crate::runtime::authority::AuthoritySession>,
            message: crate::host_logic::sso::messages::RemoteMessage,
        ) -> #runtime::Dispatch {
            use crate::host_logic::sso::messages::v1::{AnyRequest, Incoming, classify};
            let crate::host_logic::sso::messages::RemoteMessageData::V1(data) = message.data;
            let request = match classify(data) {
                Incoming::Request(request) => request,
                Incoming::Response(name) => return #runtime::Dispatch::NotARequest(name),
                Incoming::Disconnected => return #runtime::Dispatch::Disconnected,
            };
            let message_id = message.message_id;
            let cx = session.map(|session| #runtime::SsoRequestContext::new(&message_id, session));
            let answer = match request {
                #(#arms)*
            };
            #runtime::Dispatch::Response(Box::new(answer))
        }
    });
    Ok(quote! {
        #item
        #(#impls)*
    })
}

fn method_types(sig: &Signature) -> syn::Result<(Type, Type)> {
    let mut inputs = sig.inputs.iter();
    let shape_error = || {
        syn::Error::new_spanned(
            sig,
            "expected `async fn name(&self, cx: &SsoRequestContext, request: <Request>) -> <Response>`",
        )
    };
    let Some(FnArg::Receiver(receiver)) = inputs.next() else {
        return Err(shape_error());
    };
    if receiver.reference.is_none()
        || receiver.mutability.is_some()
        || receiver.colon_token.is_some()
    {
        return Err(shape_error());
    }
    let Some(FnArg::Typed(context)) = inputs.next() else {
        return Err(shape_error());
    };
    let Type::Reference(context_ty) = context.ty.as_ref() else {
        return Err(shape_error());
    };
    if last_segment(&context_ty.elem)? != "SsoRequestContext" {
        return Err(shape_error());
    }
    let Some(FnArg::Typed(request)) = inputs.next() else {
        return Err(shape_error());
    };
    if inputs.next().is_some()
        || sig.asyncness.is_none()
        || !sig.generics.params.is_empty()
        || sig.generics.where_clause.is_some()
    {
        return Err(shape_error());
    }
    let Pat::Ident(_) = request.pat.as_ref() else {
        return Err(shape_error());
    };
    let syn::ReturnType::Type(_, output) = &sig.output else {
        return Err(shape_error());
    };
    let Type::Path(path) = output.as_ref() else {
        return Err(shape_error());
    };
    let Some(segment) = path.path.segments.last() else {
        return Err(shape_error());
    };
    if !segment.ident.to_string().ends_with("Response") {
        return Err(shape_error());
    }
    Ok(((*request.ty).clone(), output.as_ref().clone()))
}

fn last_segment(ty: &Type) -> syn::Result<Ident> {
    match ty {
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.clone())
            .ok_or_else(|| syn::Error::new_spanned(ty, "expected a request type")),
        _ => Err(syn::Error::new_spanned(ty, "expected a request type path")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stems_become_method_names() {
        assert_eq!(snake_case("GetAccountAlias"), "get_account_alias");
        assert_eq!(snake_case("Sign"), "sign");
        assert_eq!(
            snake_case("CreateTransactionWithLegacyAccount"),
            "create_transaction_with_legacy_account"
        );
    }

    #[test]
    fn service_method_names_cannot_drift_from_client_actions() {
        let item = syn::parse_quote! {
            impl Service {
                async fn sign_raw_legacy(&self, cx: &SsoRequestContext, request: SignRawWithLegacyAccountRequest)
                    -> SignRawWithLegacyAccountResponse { Ok(vec![]) }
            }
        };
        let error = expand_sso_service(item).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the method for `SignRawWithLegacyAccountRequest` must be named `sign_raw_with_legacy_account`"
        );
    }

    #[test]
    fn service_requires_an_explicit_wire_response() {
        let item = syn::parse_quote! {
            impl Service {
                async fn sign(&self, cx: &SsoRequestContext, request: SignRequest)
                    -> Result<Vec<u8>, String> { Ok(vec![]) }
            }
        };
        let error = expand_sso_service(item).unwrap_err();
        assert_eq!(
            error.to_string(),
            "expected `async fn name(&self, cx: &SsoRequestContext, request: <Request>) -> <Response>`"
        );
    }

    #[test]
    fn response_correlation_must_remain_first_on_the_wire() {
        let input = syn::parse_quote! {
            struct SignResponse {
                payload: Result<Vec<u8>, String>,
                responding_to: String,
            }
        };
        let error = derive_sso_response(input).unwrap_err();
        assert_eq!(
            error.to_string(),
            "`responding_to` must be the first field: SCALE encodes fields positionally"
        );
    }
}
