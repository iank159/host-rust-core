//! Shared names and server paths used by the SSO macros.

use proc_macro2::TokenStream;
use quote::quote;

/// Server traits implemented by the SSO derives.
pub(super) fn wire_path() -> TokenStream {
    quote!(crate::host_logic::sso::wire)
}

/// Hand-written wire enum shared by SSO requests and responses.
pub(super) fn enum_path() -> TokenStream {
    quote!(crate::host_logic::sso::messages::v1::RemoteMessage)
}

/// Convert a request variant stem to its handler and client action name.
pub(super) fn snake_case(name: &str) -> String {
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
}
