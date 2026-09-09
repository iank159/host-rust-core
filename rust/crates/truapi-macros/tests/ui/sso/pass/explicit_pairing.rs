include!("../support/wire.rs");
include!("../support/runtime.rs");

use host_logic::sso::{messages::*, wire::SsoRequest};
use runtime::sso_service::SsoRequestContext;

struct Service;

#[truapi_macros::sso_service]
impl Service {
    async fn foo(&self, _: &SsoRequestContext, _request: Request<u32>) -> BarResponse {
        Ok(1)
    }

    async fn bar(&self, _: &SsoRequestContext, _request: BarRequest) -> FooResponse {
        Ok(2)
    }
}

fn main() {
    fn check<R: SsoRequest<Response = BarResponse>>() {}
    check::<Request<u32>>();
    let response = Request::<u32>::response_into_message(Response {
        responding_to: "m-1".into(),
        payload: Ok(7),
    });
    assert!(matches!(response, v1::RemoteMessage::BarResponse(_)));
    assert!(BarRequest::response_from_message(response).is_none());
}
