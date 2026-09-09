include!("../support/wire.rs");
include!("../support/runtime.rs");

use host_logic::sso::{messages::*, wire::ResponseOutcome};
use runtime::sso_service::{SsoReply, SsoRequestContext};

struct Service;

impl Service {
    fn new() -> Self {
        Self
    }

    async fn value(&self, request: Request<u32>) -> Result<u32, String> {
        Ok(request.0)
    }
}

#[truapi_macros::sso_service]
impl Service {
    async fn foo(&self, _: &SsoRequestContext, request: Request<u32>) -> FooResponse {
        let value = self.value(request).await?;
        if value == 0 {
            return Err("zero".into());
        }
        Ok(value)
    }

    async fn bar(&self, _: &SsoRequestContext, _request: BarRequest) -> BarResponse {
        SsoReply::<BarResponse>::from(Ok(2)).with_outcome(ResponseOutcome)
    }
}

fn main() {
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
