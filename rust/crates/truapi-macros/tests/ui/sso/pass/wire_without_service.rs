include!("../support/wire.rs");

fn main() {
    use host_logic::sso::messages::{Request, v1};
    let request = v1::RemoteMessage::FooRequest(Box::new(Request(1)));
    assert_eq!(request.name(), "foo");
    assert!(matches!(v1::classify(request), v1::Incoming::Request(_)));
}
