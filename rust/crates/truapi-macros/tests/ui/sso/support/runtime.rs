// Context and reply operations consumed by generated dispatch.
#[allow(dead_code)]
mod runtime {
    pub mod authority {
        pub struct AuthoritySession;
    }

    pub mod sso_service {
        use crate::host_logic::sso::wire::{ResponseOutcome, ResponsePayload, SsoResponse};

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

        pub struct SsoReply<R: SsoResponse> {
            payload: ResponsePayload<R>,
            outcome: Option<ResponseOutcome>,
        }

        impl<R: SsoResponse> From<ResponsePayload<R>> for SsoReply<R> {
            fn from(payload: ResponsePayload<R>) -> Self {
                Self {
                    payload,
                    outcome: None,
                }
            }
        }

        impl<R: SsoResponse> SsoReply<R> {
            pub fn with_outcome(mut self, outcome: ResponseOutcome) -> Self {
                self.outcome = Some(outcome);
                self
            }

            pub fn finish(self, id: &str) -> Answer {
                let response = R::new(id.to_string(), self.payload);
                let _outcome = self.outcome.unwrap_or_else(|| response.outcome());
                let _message = response.into_message();
                Answer
            }
        }
    }
}
