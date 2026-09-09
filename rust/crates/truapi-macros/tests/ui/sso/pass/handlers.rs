include!("../support/wire.rs");
include!("../support/runtime.rs");

use host_logic::sso::{
    messages::*,
    wire::{ResponseOutcome, SsoRequest},
};
use runtime::sso_service::{SsoReply, SsoRequestContext};

struct Service;

impl Service {
    fn new() -> Self {
        Self
    }

    async fn value(&self, value: u32) -> Result<u32, String> {
        Ok(value)
    }
}

#[truapi_macros::sso_service]
impl Service {
    async fn r#foo(&self, _: &SsoRequestContext, Request(value): Request<u32>) -> BarResponse {
        let value = self.value(value).await?;
        if value == 0 {
            return Err("zero".into());
        }
        Ok(value)
    }

    async fn bar(&self, _: &SsoRequestContext, _: BarRequest) -> FooResponse {
        SsoReply::<FooResponse>::from(Ok(2)).with_outcome(ResponseOutcome)
    }
}

fn main() {
    // The return type selects the variant, even when its name differs from the handler's.
    let response = Request::<u32>::response_into_message(Response {
        responding_to: "m-1".into(),
        payload: Ok(7),
    });
    assert!(matches!(response, v1::RemoteMessage::BarResponse(_)));
    assert!(BarRequest::response_from_message(response).is_none());

    fn require_send(_: impl core::future::Future + Send) {}
    let service = Service::new();
    require_send(service.dispatch(
        None,
        RemoteMessage {
            message_id: "m-1".into(),
            data: RemoteMessageData::V1(v1::RemoteMessage::FooRequest(Box::new(Request(1)))),
        },
    ));
}
