include!("../support/wire.rs");
include!("../support/runtime.rs");

use host_logic::sso::{messages::*, wire::SsoRequest};
use runtime::sso_service::SsoRequestContext;

struct Service;

#[truapi_macros::sso_service]
impl Service {
    async fn foo(&self, _: &SsoRequestContext, _request: Request<u32>) -> FooResponse {
        Ok(1)
    }

    async fn bar(&self, _: &SsoRequestContext, _request: BarRequest) -> FooResponse {
        Ok(2)
    }
}

fn main() {
    fn check<R: SsoRequest<Response = FooResponse>>() {}
    check::<Request<u32>>();
    check::<BarRequest>();
    let response = BarRequest::response_into_message(Response {
        responding_to: "m-1".into(),
        payload: Ok(7),
    });
    assert!(matches!(response, v1::RemoteMessage::FooResponse(_)));
    assert!(Request::<u32>::response_from_message(response).is_some());
}
