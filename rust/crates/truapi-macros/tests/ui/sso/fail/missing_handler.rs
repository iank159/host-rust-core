include!("../support/wire.rs");
include!("../support/runtime.rs");

use host_logic::sso::messages::{FooRequest, FooResponse};
use runtime::sso_service::SsoRequestContext;

struct Service;

#[truapi_macros::sso_service]
impl Service {
    async fn foo(&self, _: &SsoRequestContext, _request: FooRequest) -> FooResponse {
        Ok(1)
    }
}

fn main() {}
