include!("../support/wire.rs");

fn main() {
    use host_logic::sso::messages::{BarRequest, Request, Response, v1};
    use v1::{AnyRequest, Incoming, classify};

    for (request, name) in [
        (AnyRequest::FooRequest(Request(1)), "foo"),
        (AnyRequest::BarRequest(BarRequest), "bar"),
    ] {
        let message: v1::RemoteMessage = request.clone().into();
        assert_eq!(message.name(), name);
        assert_eq!(classify(message), Incoming::Request(request));
    }
    assert_eq!(
        classify(v1::RemoteMessage::FooResponse(Response {
            responding_to: "m-1".into(),
            payload: Ok(7),
        })),
        Incoming::Response("FooResponse")
    );
    assert_eq!(
        classify(v1::RemoteMessage::Disconnected),
        Incoming::Disconnected
    );
}
