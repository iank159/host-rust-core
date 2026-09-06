//! `subxt-rpcs` client adapter for host-provided JSON-RPC pipes.
//!
//! The platform owns the physical chain connection. This module owns only the
//! generic JSON-RPC mechanics needed to expose that pipe as a
//! [`subxt_rpcs::RpcClientT`]: request correlation, subscription routing, and
//! best-effort unsubscribe on subscription drop.

use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, pin_mut};
use futures::{Stream, StreamExt};
use serde::{Serialize, Serializer};
use serde_json::value::RawValue;
use subxt_rpcs::client::{RawRpcFuture, RawRpcSubscription, RpcClientT};
use subxt_rpcs::{Error as RpcError, UserError};
use tracing::instrument;
use truapi_platform::JsonRpcConnection;

use crate::subscription::Spawner;

const MAX_PENDING_REQUESTS: usize = 1024;
const MAX_BUFFERED_SUBSCRIPTIONS: usize = 64;
const MAX_BUFFERED_ITEMS_PER_SUBSCRIPTION: usize = 256;

/// JSON-RPC client backed by a host-owned [`JsonRpcConnection`].
pub(crate) struct HostRpcClient {
    inner: Arc<HostRpcClientInner>,
}

struct HostRpcClientInner {
    connection: Arc<dyn JsonRpcConnection>,
    request_ids: AtomicU64,
    user_handles: AtomicUsize,
    closed: AtomicBool,
    stop_response_loop: Mutex<Option<oneshot::Sender<()>>>,
    pending: Mutex<HashMap<String, PendingRequest>>,
    subscriptions: Mutex<HashMap<String, SubscriptionSink>>,
    buffered_subscription_items: Mutex<HashMap<String, Vec<Box<RawValue>>>>,
}

struct HostRpcClientLease {
    inner: Arc<HostRpcClientInner>,
}

struct PendingRequest {
    tx: oneshot::Sender<Result<RpcReply, RpcError>>,
    unsubscribe_method: Option<String>,
}

/// Ordinary cancellation removes its registration immediately. A cancelled
/// subscribe retains only a bounded tombstone until its acknowledgement arrives,
/// because that reply owns the identifier needed to release the remote resource.
struct RequestRegistration<'a> {
    client: &'a HostRpcClientInner,
    id: String,
}

impl Drop for RequestRegistration<'_> {
    fn drop(&mut self) {
        let mut pending = self.client.pending.lock().unwrap();
        if pending
            .get(&self.id)
            .is_some_and(|p| p.unsubscribe_method.is_none())
        {
            pending.remove(&self.id);
        }
    }
}

struct RpcReply {
    raw: Option<Box<RawValue>>,
    cleanup: Option<(Arc<HostRpcClientInner>, String)>,
}

impl Drop for RpcReply {
    fn drop(&mut self) {
        if let Some((client, method)) = self.cleanup.take()
            && let Some(raw) = &self.raw
            && let Ok(id) = subscription_id_from_raw(raw)
        {
            client.unsubscribe(&id, &method, raw);
        }
    }
}

struct SubscriptionSink {
    tx: mpsc::Sender<Result<Box<RawValue>, RpcError>>,
    terminal_error: Arc<Mutex<Option<String>>>,
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("{}", _0)]
struct HostRpcClientError(#[error(not(source))] String);

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'a str,
    #[serde(serialize_with = "serialize_json_rpc_params")]
    params: Option<&'a RawValue>,
}

fn serialize_json_rpc_params<S>(
    params: &Option<&RawValue>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match params {
        Some(params) => params.serialize(serializer),
        None => <[(); 0]>::default().serialize(serializer),
    }
}

impl HostRpcClient {
    /// Wrap `connection` and start the response pump on `spawner`.
    pub(crate) fn new(connection: Arc<dyn JsonRpcConnection>, spawner: Spawner) -> Self {
        let (stop_response_tx, stop_response_rx) = oneshot::channel();
        let client = Self {
            inner: Arc::new(HostRpcClientInner {
                connection,
                request_ids: AtomicU64::new(1),
                user_handles: AtomicUsize::new(1),
                closed: AtomicBool::new(false),
                stop_response_loop: Mutex::new(Some(stop_response_tx)),
                pending: Mutex::new(HashMap::new()),
                subscriptions: Mutex::new(HashMap::new()),
                buffered_subscription_items: Mutex::new(HashMap::new()),
            }),
        };
        client.spawn_response_loop(spawner, stop_response_rx);
        client
    }

    /// Whether the underlying response stream has ended or failed.
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }

    /// Send a JSON-RPC request without waiting for its response.
    ///
    /// Used by best-effort notifications where the caller must not block on
    /// the remote endpoint acknowledging the request.
    pub(crate) fn send_fire_and_forget(
        &self,
        method: &str,
        params: Option<Box<RawValue>>,
    ) -> Result<(), RpcError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(client_error("json-rpc connection is closed"));
        }
        let id = self.inner.next_request_id();
        self.inner.send_request(&id, method, params.as_deref())
    }

    fn spawn_response_loop(&self, spawner: Spawner, stop_rx: oneshot::Receiver<()>) {
        let inner = self.inner.clone();
        let fut = async move {
            let mut responses = inner.connection.responses();
            let stop = stop_rx.fuse();
            pin_mut!(stop);
            loop {
                futures::select! {
                    _ = stop => return,
                    frame = responses.next().fuse() => match frame {
                        Some(frame) => {
                            if let Err(error) = inner.handle_frame(&frame) {
                                inner.close_with_error(error);
                                return;
                            }
                        }
                        None => {
                            inner.close_with_error(client_error("json-rpc response stream ended"));
                            return;
                        }
                    }
                }
            }
        };
        (spawner)(fut.boxed());
    }
}

impl Clone for HostRpcClient {
    fn clone(&self) -> Self {
        self.inner.retain_user_handle();
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for HostRpcClient {
    fn drop(&mut self) {
        self.inner.release_user_handle();
    }
}

impl HostRpcClientInner {
    fn retain_user_handle(&self) {
        self.user_handles.fetch_add(1, Ordering::Relaxed);
    }

    fn acquire_lease(self: &Arc<Self>) -> HostRpcClientLease {
        self.retain_user_handle();
        HostRpcClientLease {
            inner: self.clone(),
        }
    }

    fn release_user_handle(&self) {
        let previous = self.user_handles.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "host rpc client handle count underflow");
        if previous == 1 {
            self.close_with_error(client_error("json-rpc client dropped"));
        }
    }

    fn next_request_id(&self) -> String {
        format!(
            "truapi:{}",
            self.request_ids.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn send_request(
        &self,
        id: &str,
        method: &str,
        params: Option<&RawValue>,
    ) -> Result<(), RpcError> {
        let normalized_params = normalize_outbound_params(method, params)?;
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params: normalized_params.as_deref().or(params),
        };
        let encoded = serde_json::to_string(&request).map_err(RpcError::Serialization)?;
        self.connection.send(encoded);
        Ok(())
    }

    async fn request(
        self: &Arc<Self>,
        method: &str,
        params: Option<Box<RawValue>>,
    ) -> Result<Box<RawValue>, RpcError> {
        let mut reply = self.request_reply(method, params, None).await?;
        Ok(reply
            .raw
            .take()
            .expect("successful reply contains a result"))
    }

    async fn request_reply(
        self: &Arc<Self>,
        method: &str,
        params: Option<Box<RawValue>>,
        unsubscribe_method: Option<&str>,
    ) -> Result<RpcReply, RpcError> {
        let id = self.next_request_id();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if self.closed.load(Ordering::Relaxed) {
                return Err(client_error("json-rpc connection is closed"));
            }
            if pending.len() >= MAX_PENDING_REQUESTS {
                return Err(client_error("too many pending json-rpc requests"));
            }
            pending.insert(
                id.clone(),
                PendingRequest {
                    tx,
                    unsubscribe_method: unsubscribe_method.map(str::to_owned),
                },
            );
        }
        let _registration = RequestRegistration {
            client: self,
            id: id.clone(),
        };
        if let Err(error) = self.send_request(&id, method, params.as_deref()) {
            self.pending.lock().unwrap().remove(&id);
            return Err(error);
        }
        rx.await
            .map_err(|_| client_error("json-rpc request was cancelled"))?
    }

    async fn subscribe(
        self: Arc<Self>,
        method: &str,
        params: Option<Box<RawValue>>,
        unsubscribe_method: &str,
        lease: HostRpcClientLease,
    ) -> Result<RawRpcSubscription, RpcError> {
        let mut reply = self
            .request_reply(method, params, Some(unsubscribe_method))
            .await?;
        let subscription_id = subscription_id_from_raw(reply.raw.as_deref().unwrap())?;
        let (mut tx, rx) = mpsc::channel(MAX_BUFFERED_ITEMS_PER_SUBSCRIPTION);
        let terminal_error = Arc::new(Mutex::new(None));
        {
            // Notification delivery takes these locks in the same order. Keep
            // the buffered-items lock across activation and replay so a new
            // live notification cannot overtake an older buffered one.
            let mut buffered = self.buffered_subscription_items.lock().unwrap();
            let mut subscriptions = self.subscriptions.lock().unwrap();
            if self.closed.load(Ordering::Relaxed) {
                return Err(client_error("json-rpc connection is closed"));
            }
            for item in buffered.remove(&subscription_id).unwrap_or_default() {
                tx.try_send(Ok(item))
                    .map_err(|_| client_error("subscription replay queue full"))?;
            }
            subscriptions.insert(
                subscription_id.clone(),
                SubscriptionSink {
                    tx,
                    terminal_error: terminal_error.clone(),
                },
            );
        }

        reply.cleanup = None;
        let stream = SubscriptionStream {
            inner: rx,
            terminal_error,
            client: self,
            _lease: lease,
            subscription_id: subscription_id.clone(),
            raw_id: reply.raw.take().unwrap(),
            unsubscribe_method: unsubscribe_method.to_string(),
            closed: false,
        };
        Ok(RawRpcSubscription {
            stream: Box::pin(stream),
            id: Some(subscription_id),
        })
    }

    fn unsubscribe(&self, subscription_id: &str, unsubscribe_method: &str, raw_id: &RawValue) {
        self.subscriptions.lock().unwrap().remove(subscription_id);
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let id = self.next_request_id();
        let params = RawValue::from_string(format!("[{}]", raw_id.get()));
        if let Ok(params) = params {
            let _ = self.send_request(&id, unsubscribe_method, Some(params.as_ref()));
        }
    }

    #[instrument(skip_all, fields(runtime.method = "host_rpc_client.handle_frame"))]
    fn handle_frame(self: &Arc<Self>, frame: &str) -> Result<(), RpcError> {
        let value: serde_json::Value =
            serde_json::from_str(frame).map_err(RpcError::Deserialization)?;

        if value.get("method").is_some() && value.get("params").is_some() {
            self.handle_notification(&value)?;
            return Ok(());
        }

        let Some(request_id) = value.get("id").and_then(json_id) else {
            return Ok(());
        };
        let Some(pending) = self.pending.lock().unwrap().remove(&request_id) else {
            return Ok(());
        };

        if let Some(result) = value.get("result") {
            let raw = raw_value_from_json(result)?;
            let reply = RpcReply {
                raw: Some(raw),
                cleanup: pending
                    .unsubscribe_method
                    .map(|method| (self.clone(), method)),
            };
            // On cancellation, either send fails or the receiver drops the
            // buffered reply. Both paths drop the acknowledgement's cleanup.
            let _ = pending.tx.send(Ok(reply));
            return Ok(());
        }

        if let Some(error) = value.get("error") {
            let _ = pending.tx.send(Err(user_error_from_json(error)));
            return Ok(());
        }

        let _ = pending.tx.send(Err(client_error(
            "json-rpc response missing result and error",
        )));
        Ok(())
    }

    fn handle_notification(&self, value: &serde_json::Value) -> Result<(), RpcError> {
        let Some(params) = value.get("params") else {
            return Ok(());
        };
        let Some(subscription_id) = params.get("subscription").and_then(json_id) else {
            return Ok(());
        };
        let Some(result) = params.get("result") else {
            return Ok(());
        };
        let raw = raw_value_from_json(result)?;
        self.deliver_or_buffer_subscription_item(subscription_id, raw)
    }

    fn deliver_or_buffer_subscription_item(
        &self,
        subscription_id: String,
        item: Box<RawValue>,
    ) -> Result<(), RpcError> {
        let mut buffered = self.buffered_subscription_items.lock().unwrap();
        let mut subscriptions = self.subscriptions.lock().unwrap();
        if let Some(sink) = subscriptions.get_mut(&subscription_id) {
            return sink
                .tx
                .try_send(Ok(item))
                .map_err(|_| client_error("subscription consumer stalled or disconnected"));
        }
        let known = buffered.contains_key(&subscription_id);
        if !known && buffered.len() >= MAX_BUFFERED_SUBSCRIPTIONS {
            return Err(client_error("too many unclaimed subscriptions"));
        }
        let items = buffered.entry(subscription_id).or_default();
        if items.len() >= MAX_BUFFERED_ITEMS_PER_SUBSCRIPTION {
            return Err(client_error("unclaimed subscription queue full"));
        }
        items.push(item);
        Ok(())
    }

    fn close_with_error(&self, error: RpcError) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(stop) = self.stop_response_loop.lock().unwrap().take() {
            let _ = stop.send(());
        }
        self.connection.close();

        let pending = {
            let mut pending = self.pending.lock().unwrap();
            mem::take(&mut *pending)
        };
        for (_, pending) in pending {
            let _ = pending.tx.send(Err(client_error(format!(
                "json-rpc connection closed: {error}"
            ))));
        }

        let subscriptions = mem::take(&mut *self.subscriptions.lock().unwrap());
        for (_, sink) in subscriptions {
            *sink.terminal_error.lock().unwrap() =
                Some(format!("json-rpc connection closed: {error}"));
        }
        self.buffered_subscription_items.lock().unwrap().clear();
    }
}

impl Drop for HostRpcClientLease {
    fn drop(&mut self) {
        self.inner.release_user_handle();
    }
}

impl RpcClientT for HostRpcClient {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        Box::pin(async move { self.inner.request(method, params).await })
    }

    fn subscribe_raw<'a>(
        &'a self,
        sub: &'a str,
        params: Option<Box<RawValue>>,
        unsub: &'a str,
    ) -> RawRpcFuture<'a, RawRpcSubscription> {
        let lease = self.inner.acquire_lease();
        Box::pin(async move {
            self.inner
                .clone()
                .subscribe(sub, params, unsub, lease)
                .await
        })
    }
}

struct SubscriptionStream {
    inner: mpsc::Receiver<Result<Box<RawValue>, RpcError>>,
    terminal_error: Arc<Mutex<Option<String>>>,
    client: Arc<HostRpcClientInner>,
    _lease: HostRpcClientLease,
    subscription_id: String,
    raw_id: Box<RawValue>,
    unsubscribe_method: String,
    closed: bool,
}

impl Drop for SubscriptionStream {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            self.client.unsubscribe(
                &self.subscription_id,
                &self.unsubscribe_method,
                &self.raw_id,
            );
        }
    }
}

impl Stream for SubscriptionStream {
    type Item = Result<Box<RawValue>, RpcError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(None) => {
                this.closed = true;
                Poll::Ready(
                    this.terminal_error
                        .lock()
                        .unwrap()
                        .take()
                        .map(|error| Err(client_error(error))),
                )
            }
            other => other,
        }
    }
}

fn raw_value_from_json(value: &serde_json::Value) -> Result<Box<RawValue>, RpcError> {
    RawValue::from_string(value.to_string()).map_err(RpcError::Deserialization)
}

/// PAPI's modern middleware requires the array variant even though Subxt emits
/// the protocol's valid single-hash unpin form.
fn normalize_outbound_params(
    method: &str,
    params: Option<&RawValue>,
) -> Result<Option<Box<RawValue>>, RpcError> {
    if method != "chainHead_v1_unpin" {
        return Ok(None);
    }
    let Some(params) = params else {
        return Ok(None);
    };
    let mut params: Vec<serde_json::Value> =
        serde_json::from_str(params.get()).map_err(RpcError::Serialization)?;
    let Some(hash_slot @ serde_json::Value::String(_)) = params.get_mut(1) else {
        return Ok(None);
    };
    let hash = mem::take(hash_slot);
    *hash_slot = serde_json::Value::Array(vec![hash]);
    let encoded = serde_json::to_string(&params).map_err(RpcError::Serialization)?;
    RawValue::from_string(encoded)
        .map(Some)
        .map_err(RpcError::Serialization)
}

fn subscription_id_from_raw(raw: &RawValue) -> Result<String, RpcError> {
    let value: serde_json::Value =
        serde_json::from_str(raw.get()).map_err(RpcError::Deserialization)?;
    json_id(&value).ok_or_else(|| client_error("json-rpc subscription id is not a string"))
}

fn json_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn user_error_from_json(value: &serde_json::Value) -> RpcError {
    match serde_json::from_value::<UserError>(value.clone()) {
        Ok(error) => RpcError::User(error),
        Err(error) => RpcError::Deserialization(error),
    }
}

fn client_error(reason: impl Into<String>) -> RpcError {
    RpcError::Client(Box::new(HostRpcClientError(reason.into())))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use futures::executor::block_on;
    use futures::stream::BoxStream;
    use serde_json::{Value, json};
    use subxt_rpcs::RpcClient;
    use subxt_rpcs::client::rpc_params;

    use crate::subscription::thread_per_subscription_spawner;

    struct TrackingConnection {
        sender: Mutex<Option<mpsc::UnboundedSender<String>>>,
        receiver: Mutex<Option<mpsc::UnboundedReceiver<String>>>,
        sent: Mutex<Vec<Value>>,
        close_count: AtomicUsize,
    }

    impl TrackingConnection {
        fn new() -> Arc<Self> {
            let (tx, rx) = mpsc::unbounded();
            Arc::new(Self {
                sender: Mutex::new(Some(tx)),
                receiver: Mutex::new(Some(rx)),
                sent: Mutex::new(Vec::new()),
                close_count: AtomicUsize::new(0),
            })
        }

        fn close_count(&self) -> usize {
            self.close_count.load(Ordering::SeqCst)
        }

        fn sent(&self) -> Vec<Value> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl JsonRpcConnection for TrackingConnection {
        fn send(&self, request: String) {
            let Ok(value) = serde_json::from_str::<Value>(&request) else {
                return;
            };
            self.sent.lock().unwrap().push(value.clone());
            let Some(id) = value.get("id").cloned() else {
                return;
            };
            if value.get("method").and_then(Value::as_str) == Some("sub") {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": "sub-1",
                });
                if let Some(sender) = self.sender.lock().unwrap().as_ref() {
                    let _ = sender.unbounded_send(response.to_string());
                }
            }
        }

        fn responses(&self) -> BoxStream<'static, String> {
            self.receiver
                .lock()
                .unwrap()
                .take()
                .expect("responses called twice")
                .boxed()
        }

        fn close(&self) {
            self.close_count.fetch_add(1, Ordering::SeqCst);
            self.sender.lock().unwrap().take();
        }
    }

    fn poll_pending<F: std::future::Future + Unpin>(future: &mut F) {
        let waker = futures::task::noop_waker();
        assert!(
            Pin::new(future)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }

    #[test]
    fn cancelled_requests_release_their_registrations_without_a_response() {
        let connection = TrackingConnection::new();
        let client = HostRpcClient::new(connection, Arc::new(|_| {}));
        for _ in 0..100 {
            let mut request = client.request_raw("silent", None);
            poll_pending(&mut request);
            assert_eq!(client.inner.pending.lock().unwrap().len(), 1);
            drop(request);
            assert!(client.inner.pending.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn cancelled_subscription_unsubscribes_on_late_acknowledgement() {
        let connection = TrackingConnection::new();
        let client = HostRpcClient::new(connection.clone(), Arc::new(|_| {}));
        let mut request = client.subscribe_raw("silent-subscribe", None, "unsubscribe");
        poll_pending(&mut request);
        drop(request);
        let id = connection.sent()[0]["id"].clone();
        client
            .inner
            .handle_frame(&json!({"id":id,"result":17}).to_string())
            .unwrap();
        assert!(client.inner.pending.lock().unwrap().is_empty());
        assert_eq!(connection.sent()[1]["method"], "unsubscribe");
        assert_eq!(connection.sent()[1]["params"], json!([17]));
    }

    #[test]
    fn cancellation_after_acknowledgement_still_unsubscribes() {
        let connection = TrackingConnection::new();
        let client = HostRpcClient::new(connection.clone(), Arc::new(|_| {}));
        let mut request = client.subscribe_raw("silent-subscribe", None, "unsubscribe");
        poll_pending(&mut request);
        let id = connection.sent()[0]["id"].clone();
        client
            .inner
            .handle_frame(&json!({"id":id,"result":"late"}).to_string())
            .unwrap();
        drop(request);
        assert_eq!(connection.sent()[1]["params"], json!(["late"]));
    }

    #[test]
    fn cancelled_subscription_tombstones_are_bounded() {
        let connection = TrackingConnection::new();
        let client = HostRpcClient::new(connection, Arc::new(|_| {}));
        for _ in 0..MAX_PENDING_REQUESTS {
            let mut request = client.subscribe_raw("silent", None, "unsubscribe");
            poll_pending(&mut request);
        }
        assert!(block_on(client.subscribe_raw("silent", None, "unsubscribe")).is_err());
        assert_eq!(
            client.inner.pending.lock().unwrap().len(),
            MAX_PENDING_REQUESTS
        );
    }

    #[test]
    fn active_queue_overflow_ends_the_stream_with_an_error() {
        let connection = TrackingConnection::new();
        let client = HostRpcClient::new(connection.clone(), Arc::new(|_| {}));
        let mut request = client.subscribe_raw("silent-subscribe", None, "unsubscribe");
        poll_pending(&mut request);
        let id = connection.sent()[0]["id"].clone();
        client
            .inner
            .handle_frame(&json!({"id":id,"result":"slow"}).to_string())
            .unwrap();
        let mut subscription = block_on(request).unwrap();
        let mut overflowed = false;
        for _ in 0..MAX_BUFFERED_ITEMS_PER_SUBSCRIPTION + 2 {
            let result = client.inner.handle_frame(
                &json!({"method":"item","params":{
                    "subscription":"slow","result":0
                }})
                .to_string(),
            );
            if let Err(error) = result {
                client.inner.close_with_error(error);
                overflowed = true;
                break;
            }
        }
        assert!(overflowed);
        let mut saw_error = false;
        while let Some(item) = block_on(subscription.stream.next()) {
            if item.is_err() {
                saw_error = true;
            }
        }
        assert!(saw_error);
        assert_eq!(connection.close_count(), 1);
    }

    #[test]
    fn dropping_one_shot_client_closes_connection_lease() {
        let connection = TrackingConnection::new();
        let spawner: Spawner = Arc::new(|_| {});

        {
            let client = HostRpcClient::new(connection.clone(), spawner);
            client
                .send_fire_and_forget("statement_submit", None)
                .unwrap();
        }

        assert_eq!(connection.close_count(), 1);
    }

    #[test]
    fn requests_without_arguments_serialize_empty_params() {
        let connection = TrackingConnection::new();
        let spawner: Spawner = Arc::new(|_| {});
        let client = HostRpcClient::new(connection.clone(), spawner);

        client
            .send_fire_and_forget("chainSpec_v1_chainName", None)
            .unwrap();

        assert_eq!(connection.sent()[0]["params"], json!([]));
    }

    #[test]
    fn subxt_single_hash_unpin_is_normalized_for_host_providers() {
        let connection = TrackingConnection::new();
        let spawner: Spawner = Arc::new(|_| {});
        let client = HostRpcClient::new(connection.clone(), spawner);
        let params = RawValue::from_string(r#"["follow-id","0x1234"]"#.to_string()).unwrap();

        client
            .send_fire_and_forget("chainHead_v1_unpin", Some(params))
            .unwrap();

        assert_eq!(
            connection.sent()[0]["params"],
            json!(["follow-id", ["0x1234"]]),
        );
    }

    #[test]
    fn subscription_stream_holds_connection_lease_until_dropped() {
        let connection = TrackingConnection::new();
        let client = HostRpcClient::new(connection.clone(), thread_per_subscription_spawner());
        let rpc_client = RpcClient::new(client.clone());

        let subscription = block_on(rpc_client.subscribe::<Value>("sub", rpc_params![], "unsub"))
            .expect("subscription should start");

        drop(rpc_client);
        drop(client);
        assert_eq!(connection.close_count(), 0);

        drop(subscription);
        assert_eq!(connection.close_count(), 1);
    }

    #[test]
    fn notification_that_races_subscription_activation_is_delivered() {
        let connection = TrackingConnection::new();
        let spawner: Spawner = Arc::new(|_| {});
        let client = HostRpcClient::new(connection, spawner);
        let (tx, mut rx) = mpsc::channel(MAX_BUFFERED_ITEMS_PER_SUBSCRIPTION);
        client.inner.subscriptions.lock().unwrap().insert(
            "sub-1".to_string(),
            SubscriptionSink {
                tx,
                terminal_error: Arc::new(Mutex::new(None)),
            },
        );
        let item = RawValue::from_string(r#"{"event":"initialized"}"#.to_string()).unwrap();

        client
            .inner
            .deliver_or_buffer_subscription_item("sub-1".to_string(), item)
            .unwrap();

        assert!(
            !client
                .inner
                .buffered_subscription_items
                .lock()
                .unwrap()
                .contains_key("sub-1"),
            "a notification observed before activation must not be stranded after activation"
        );
        let received = block_on(rx.next())
            .expect("activated subscription should receive the raced notification")
            .expect("raced notification should be successful");
        assert_eq!(received.get(), r#"{"event":"initialized"}"#);
    }
}
