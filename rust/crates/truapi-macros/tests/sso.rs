//! Compiler contracts for the SSO derives and handler attribute.

#[test]
fn sso_handler_contracts() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/ui/sso/pass/*.rs");
    cases.compile_fail("tests/ui/sso/fail/*.rs");
}
