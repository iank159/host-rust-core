include!("../support/wire.rs");
include!("../support/runtime.rs");

use host_logic::sso::messages::*;
use runtime::sso_service::SsoRequestContext;

struct Service;
struct BazRequest;

#[truapi_macros::sso_service]
impl Service {
    async fn foo(&self, _: &SsoRequestContext, _request: Request<u32>) -> FooResponse {
        Ok(1)
    }

    async fn bar(&self, _: &SsoRequestContext, _request: BarRequest) -> BarResponse {
        Ok(2)
    }

    async fn baz(&self, _: &SsoRequestContext, _request: BazRequest) -> FooResponse {
        Ok(3)
    }
}

fn main() {}
