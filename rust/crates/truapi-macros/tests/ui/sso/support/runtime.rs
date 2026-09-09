// Context and reply operations consumed by generated dispatch.
#[allow(dead_code)]
mod runtime {
    pub mod authority {
        pub struct AuthoritySession;
    }

    pub mod sso_service {
        use crate::host_logic::sso::messages::{Response, v1};
        use crate::host_logic::sso::wire::{ResponseOutcome, SsoError};

        pub struct SsoRequestContext;

        impl SsoRequestContext {
            pub fn new(_: &str, _: super::authority::AuthoritySession) -> Self {
                Self
            }
        }

        pub enum Dispatch {
            Response(Box<Answer>),
            Disconnected,
            NotARequest(&'static str),
        }

        pub struct Answer;

        pub struct SsoReply<P> {
            payload: P,
            outcome: Option<ResponseOutcome>,
        }

        impl<P> From<P> for SsoReply<P> {
            fn from(payload: P) -> Self {
                Self {
                    payload,
                    outcome: None,
                }
            }
        }

        impl<P> SsoReply<P> {
            pub fn with_outcome(mut self, outcome: ResponseOutcome) -> Self {
                self.outcome = Some(outcome);
                self
            }
        }

        impl<T, E: SsoError> SsoReply<Result<T, E>> {
            pub fn finish(
                self,
                id: &str,
                wrap: impl FnOnce(Response<Result<T, E>>) -> v1::RemoteMessage,
            ) -> Answer {
                let _outcome = self
                    .outcome
                    .unwrap_or_else(|| ResponseOutcome::from_payload(&self.payload));
                let _message = wrap(Response {
                    responding_to: id.to_string(),
                    payload: self.payload,
                });
                Answer
            }
        }
    }
}
