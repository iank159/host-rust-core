include!("../support/wire.rs");
include!("../support/runtime.rs");

use host_logic::sso::messages::*;
use runtime::sso_service::{SsoReply, SsoRequestContext};

struct Service;

#[truapi_macros::sso_service]
impl Service {
    async fn foo(&self, _: &SsoRequestContext, _request: FooRequest) -> BarResponse {
        SsoReply::<FooResponse>::from(Ok(1))
    }

    async fn bar(&self, _: &SsoRequestContext, _request: BarRequest) -> BarResponse {
        Ok(2)
    }
}

fn main() {}
