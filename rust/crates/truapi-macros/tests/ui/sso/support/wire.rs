// Minimal server wire contract for testing macro expansions independently of runtime I/O.
#[allow(dead_code)]
mod host_logic {
    pub mod sso {
        pub mod wire {
            use super::messages::v1::RemoteMessage;

            pub trait SsoRequest: Sized {
                const NAME: &'static str;
                type Response: SsoResponse;
                fn into_message(self) -> RemoteMessage;
                fn from_message(message: RemoteMessage) -> Option<Self>;
            }

            pub trait SsoResponse: Sized {
                type Ok;
                type Err: SsoError;
                fn new(responding_to: String, payload: ResponsePayload<Self>) -> Self;
                fn responding_to(&self) -> &str;
                fn into_payload(self) -> ResponsePayload<Self>;
                fn into_message(self) -> RemoteMessage;
                fn from_message(message: RemoteMessage) -> Option<Self>;
                fn outcome(&self) -> ResponseOutcome;
            }

            pub type ResponsePayload<R> = Result<<R as SsoResponse>::Ok, <R as SsoResponse>::Err>;

            pub trait SsoError {
                fn not_connected() -> Self;
            }

            impl SsoError for String {
                fn not_connected() -> Self {
                    "disconnected".into()
                }
            }

            pub struct ResponseOutcome;

            impl ResponseOutcome {
                pub fn from_payload<T, E>(_: &Result<T, E>) -> Self {
                    Self
                }
            }
        }

        pub mod messages {
            #[derive(Debug, Clone, PartialEq, Eq)]
            pub struct FooRequest(pub u32);

            #[derive(Debug, Clone, PartialEq, Eq)]
            pub struct BarRequest;

            #[derive(truapi_macros::SsoResponse)]
            pub struct FooResponse {
                pub responding_to: String,
                pub payload: Result<u32, String>,
            }

            #[derive(truapi_macros::SsoResponse)]
            pub struct BarResponse {
                pub responding_to: String,
                pub payload: Result<u32, String>,
            }

            pub struct RemoteMessage {
                pub message_id: String,
                pub data: RemoteMessageData,
            }

            pub enum RemoteMessageData {
                V1(v1::RemoteMessage),
            }

            pub mod v1 {
                use super::*;

                #[derive(truapi_macros::SsoWire)]
                pub enum RemoteMessage {
                    Disconnected,
                    FooRequest(Box<FooRequest>),
                    FooResponse(FooResponse),
                    BarRequest(BarRequest),
                    BarResponse(BarResponse),
                }
            }
        }
    }
}
