//! Payload access and wire wrapping for SSO response structs.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, GenericArgument, PathArguments, Type, parse_macro_input};

use crate::sso_common::{enum_path, wire_path};

/// Parse the macro input and emit generated code or a compiler diagnostic.
pub(super) fn expand(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(item as syn::DeriveInput);
    match derive_sso_response(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Expand `#[derive(SsoResponse)]`.
fn derive_sso_response(input: DeriveInput) -> syn::Result<TokenStream> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
