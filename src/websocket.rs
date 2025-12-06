use http_kit::{
    HttpError, StatusCode,
    utils::{ByteStr, Bytes},
};
use serde::Serialize;

/// Message transmitted over a websocket connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebSocketMessage {
    /// UTF-8 text payload.
    Text(ByteStr),
    /// Binary payload.
    Binary(Bytes),
}

/// Errors returned by websocket operations.
#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    /// Failed to encode a payload for transmission.
    #[error("Fail to encode payload: {0}")]
    FailToEncodePayload(serde_json::Error),

    /// Unsupported websocket URI scheme encountered.
    #[error("Unsupported websocket scheme: {0}")]
    UnsupportedScheme(String),

    /// Provided websocket URI was invalid.
    #[error("Invalid URI: {0}")]
    InvalidUri(#[from] url::ParseError),

    /// Underlying websocket connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl HttpError for WebSocketError {
    fn status(&self) -> Option<StatusCode> {
        None
    }
}

// Convert WebSocketError to unified zenwave::Error
impl From<WebSocketError> for crate::Error {
    fn from(err: WebSocketError) -> Self {
        use crate::error::WebSocketErrorKind;

        match err {
            WebSocketError::FailToEncodePayload(e) => {
                Self::WebSocket(WebSocketErrorKind::EncodeFailed(e))
            }
            WebSocketError::UnsupportedScheme(s) => {
                Self::WebSocket(WebSocketErrorKind::UnsupportedScheme(s))
            }
            WebSocketError::InvalidUri(e) => {
                Self::InvalidUri(e.to_string())
            }
            WebSocketError::ConnectionFailed(e) => {
                Self::WebSocket(WebSocketErrorKind::ConnectionFailed(e.to_string()))
            }
        }
    }
}

/// Configuration applied when establishing a websocket connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WebSocketConfig {
    /// Maximum incoming websocket message size in bytes.
    /// `None` means no limit.
    pub max_message_size: Option<usize>,

    /// Maximum incoming websocket frame size in bytes.
    /// `None` means no limit.
    pub max_frame_size: Option<usize>,
}

const DEFAULT_MAX_MESSAGE_SIZE: Option<usize> = Some(64 << 20);
const DEFAULT_MAX_FRAME_SIZE: Option<usize> = Some(16 << 20);

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

impl WebSocketConfig {
    /// Override the maximum incoming websocket message size in bytes.
    ///
    /// `None` means no limit.
    ///
    /// Defaults to 64 MiB.
    #[must_use]
    pub const fn with_max_message_size(mut self, max_message_size: Option<usize>) -> Self {
        self.max_message_size = max_message_size;
        self
    }

    /// Override the maximum incoming websocket frame size in bytes.
    ///
    /// `None` means no limit.
    ///
    /// Defaults to 16 MiB.
    #[must_use]
    pub const fn with_max_frame_size(mut self, max_frame_size: Option<usize>) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }
}

impl WebSocketMessage {
    /// Construct a text message.
    #[must_use]
    pub fn text(value: impl Into<ByteStr>) -> Self {
        Self::Text(value.into())
    }

    /// Construct a binary message.
    #[must_use]
    pub fn binary(value: impl Into<Bytes>) -> Self {
        Self::Binary(value.into())
    }

    /// Returns the payload as text when possible.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Binary(_) => None,
        }
    }

    /// Returns the payload as raw bytes when possible.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Text(_) => None,
            Self::Binary(bytes) => Some(bytes),
        }
    }

    /// Converts the payload into owned text when possible.
    #[must_use]
    pub fn into_text(self) -> Option<ByteStr> {
        match self {
            Self::Text(text) => Some(text),
            Self::Binary(_) => None,
        }
    }

    /// Converts the payload into owned bytes when possible.
    #[must_use]
    pub fn into_bytes(self) -> Option<Bytes> {
        match self {
            Self::Text(_) => None,
            Self::Binary(bytes) => Some(bytes),
        }
    }
}

impl From<String> for WebSocketMessage {
    fn from(value: String) -> Self {
        Self::Text(value.into())
    }
}

impl From<ByteStr> for WebSocketMessage {
    fn from(value: ByteStr) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for WebSocketMessage {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned().into())
    }
}

impl From<Bytes> for WebSocketMessage {
    fn from(value: Bytes) -> Self {
        Self::Binary(value)
    }
}

impl From<Vec<u8>> for WebSocketMessage {
    fn from(value: Vec<u8>) -> Self {
        Self::Binary(value.into())
    }
}

impl From<&[u8]> for WebSocketMessage {
    fn from(value: &[u8]) -> Self {
        Self::Binary(value.to_vec().into())
    }
}

#[allow(clippy::result_large_err)]
fn serialize_payload<T>(value: &T) -> Result<String, WebSocketError>
where
    T: Serialize,
{
    serde_json::to_string(value).map_err(WebSocketError::FailToEncodePayload)
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use async_lock::Mutex;
    use async_tungstenite::{
        WebSocketReceiver as AsyncReceiver, WebSocketSender as AsyncSender, WebSocketStream,
        tungstenite::{
            Message as TungsteniteMessage, Utf8Bytes,
            protocol::WebSocketConfig as TungsteniteConfig,
        },
    };
    use futures_util::StreamExt;
    use http_kit::utils::{ByteStr, Bytes};
    use std::{fmt, sync::Arc};
    use url::Url;

    use super::{WebSocketConfig, WebSocketError, WebSocketMessage, serialize_payload};

    type NativeSocket = WebSocketStream<async_tungstenite::async_std::ConnectStream>;
    type NativeSender = AsyncSender<async_tungstenite::async_std::ConnectStream>;
    type NativeReceiver = AsyncReceiver<async_tungstenite::async_std::ConnectStream>;

    #[derive(Debug)]
    struct SharedSocket {
        sender: Mutex<NativeSender>,
        receiver: Mutex<NativeReceiver>,
    }

    /// A websocket connection backed by async-io + Tungstenite.
    pub struct WebSocket {
        sender: WebSocketSender,
        receiver: WebSocketReceiver,
    }

    impl fmt::Debug for WebSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WebSocket").finish()
        }
    }

    /// Sending half of a websocket connection.
    pub struct WebSocketSender {
        inner: Arc<SharedSocket>,
    }

    impl fmt::Debug for WebSocketSender {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WebSocketSender").finish()
        }
    }

    impl Clone for WebSocketSender {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
            }
        }
    }

    /// Receiving half of a websocket connection.
    pub struct WebSocketReceiver {
        inner: Arc<SharedSocket>,
    }

    impl fmt::Debug for WebSocketReceiver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WebSocketReceiver").finish()
        }
    }

    /// Establish a websocket connection to the provided URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is invalid or the connection attempt fails.
    pub async fn connect(uri: impl AsRef<str>) -> Result<WebSocket, WebSocketError> {
        connect_with_config(uri, WebSocketConfig::default()).await
    }

    /// Establish a websocket connection to the provided URI with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is invalid or the connection attempt fails.
    pub async fn connect_with_config(
        uri: impl AsRef<str>,
        websocket_config: WebSocketConfig,
    ) -> Result<WebSocket, WebSocketError> {
        let url = Url::parse(uri.as_ref())?;
        match url.scheme() {
            "ws" | "wss" => {}
            other => return Err(WebSocketError::UnsupportedScheme(other.to_string())),
        }
        let request: String = url.into();
        let mut config = TungsteniteConfig::default();
        config.max_message_size = websocket_config.max_message_size;
        config.max_frame_size = websocket_config.max_frame_size;
        let (ws_stream, _) =
            async_tungstenite::async_std::connect_async_with_config(request, Some(config))
                .await
                .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))?;

        Ok(WebSocket::from_socket(ws_stream))
    }

    impl WebSocket {
        fn from_socket(socket: NativeSocket) -> Self {
            let (sender, receiver) = socket.split();
            let shared = Arc::new(SharedSocket {
                sender: Mutex::new(sender),
                receiver: Mutex::new(receiver),
            });

            Self {
                sender: WebSocketSender {
                    inner: Arc::clone(&shared),
                },
                receiver: WebSocketReceiver { inner: shared },
            }
        }

        /// Send a websocket message serialized as JSON.
        ///
        /// # Errors
        ///
        /// Returns an error if serialization fails or when the underlying socket cannot
        /// write the resulting frame.
        pub async fn send<T>(&self, value: T) -> Result<(), WebSocketError>
        where
            T: serde::Serialize,
        {
            let payload = serialize_payload(&value)?;
            self.send_text(payload).await
        }

        /// Send a text websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot write the frame.
        pub async fn send_text(&self, text: impl Into<String>) -> Result<(), WebSocketError> {
            self.sender.send_text(text).await
        }

        /// Send a binary websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot write the frame.
        pub async fn send_binary(&self, bytes: impl Into<Bytes>) -> Result<(), WebSocketError> {
            self.sender.send_binary(bytes).await
        }

        /// Receive the next websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot read the next frame.
        pub async fn recv(&self) -> Result<Option<WebSocketMessage>, WebSocketError> {
            self.receiver.recv().await
        }

        /// Close the websocket connection gracefully.
        ///
        /// # Errors
        ///
        /// Returns an error when the close frame cannot be sent.
        pub async fn close(self) -> Result<(), WebSocketError> {
            self.sender.close().await
        }

        /// Split the websocket into sending and receiving halves.
        #[must_use]
        pub fn split(self) -> (WebSocketSender, WebSocketReceiver) {
            (self.sender, self.receiver)
        }
    }

    impl WebSocketSender {
        /// Send a websocket message serialized as JSON.
        ///
        /// # Errors
        ///
        /// Returns an error if serialization fails or when the underlying socket cannot
        /// write the resulting frame.
        pub async fn send<T>(&self, value: T) -> Result<(), WebSocketError>
        where
            T: serde::Serialize,
        {
            let payload = serialize_payload(&value)?;
            self.send_text(payload).await
        }

        /// Send a text websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot write the frame.
        pub async fn send_text(&self, text: impl Into<String>) -> Result<(), WebSocketError> {
            self.send_message(WebSocketMessage::text(text)).await
        }

        /// Send a binary websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot write the frame.
        pub async fn send_binary(&self, bytes: impl Into<Bytes>) -> Result<(), WebSocketError> {
            self.send_message(WebSocketMessage::binary(bytes)).await
        }

        async fn send_message(&self, message: WebSocketMessage) -> Result<(), WebSocketError> {
            let mut sender = self.inner.sender.lock().await;
            sender
                .send(to_tungstenite_message(message))
                .await
                .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))
        }

        /// Close the websocket connection gracefully.
        ///
        /// # Errors
        ///
        /// Returns an error when the close frame cannot be sent.
        pub async fn close(&self) -> Result<(), WebSocketError> {
            let mut sender = self.inner.sender.lock().await;
            sender
                .close(None)
                .await
                .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))
        }
    }

    impl WebSocketReceiver {
        /// Receive the next websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot read the next frame.
        pub async fn recv(&self) -> Result<Option<WebSocketMessage>, WebSocketError> {
            loop {
                let message = {
                    let mut receiver = self.inner.receiver.lock().await;
                    receiver.next().await
                };

                let Some(message) = message else {
                    return Ok(None);
                };

                let message = message.map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))?;

                match message {
                    TungsteniteMessage::Text(text) => {
                        return Ok(Some(WebSocketMessage::Text(unsafe {
                            ByteStr::from_utf8_unchecked(text.into())
                        })));
                    }
                    TungsteniteMessage::Binary(bytes) => {
                        return Ok(Some(WebSocketMessage::Binary(bytes)));
                    }
                    TungsteniteMessage::Close(_) => return Ok(None),
                    TungsteniteMessage::Ping(payload) => {
                        self.respond_pong(payload).await?;
                    }
                    TungsteniteMessage::Pong(_) | TungsteniteMessage::Frame(_) => {}
                }
            }
        }

        async fn respond_pong(&self, payload: Bytes) -> Result<(), WebSocketError> {
            let mut sender = self.inner.sender.lock().await;
            sender
                .send(TungsteniteMessage::Pong(payload))
                .await
                .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))
        }
    }

    fn to_tungstenite_message(value: WebSocketMessage) -> TungsteniteMessage {
        match value {
            WebSocketMessage::Text(text) => TungsteniteMessage::Text(unsafe {
                Utf8Bytes::from_bytes_unchecked(text.into_bytes())
            }),
            WebSocketMessage::Binary(bytes) => TungsteniteMessage::Binary(bytes),
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::{cell::RefCell, fmt, rc::Rc, sync::Arc};

    use async_lock::Mutex;
    use futures_channel::{mpsc, oneshot};
    use futures_util::StreamExt;
    use http_kit::utils::Bytes;
    use std::io;
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use web_sys::{
        BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket as BrowserWebSocket,
    };

    use super::{WebSocketConfig, WebSocketError, WebSocketMessage, serialize_payload};

    type Result<T> = core::result::Result<T, WebSocketError>;

    enum WsEvent {
        Message(WebSocketMessage),
        Error(String),
        Closed,
    }

    /// Browser/wasm websocket connection backed by `web_sys`.
    pub struct WebSocket {
        sender: WebSocketSender,
        receiver: WebSocketReceiver,
    }

    impl fmt::Debug for WebSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WebSocket").finish()
        }
    }

    #[derive(Debug)]
    struct SharedSocket {
        socket: BrowserWebSocket,
        receiver: Mutex<mpsc::UnboundedReceiver<WsEvent>>,
        _on_message: Closure<dyn FnMut(MessageEvent)>,
        _on_error: Closure<dyn FnMut(ErrorEvent)>,
        _on_close: Closure<dyn FnMut(CloseEvent)>,
    }

    /// Sending half of a websocket connection.
    pub struct WebSocketSender {
        inner: Arc<SharedSocket>,
    }

    impl fmt::Debug for WebSocketSender {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WebSocketSender").finish()
        }
    }

    impl Clone for WebSocketSender {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
            }
        }
    }

    /// Receiving half of a websocket connection.
    pub struct WebSocketReceiver {
        inner: Arc<SharedSocket>,
    }

    impl fmt::Debug for WebSocketReceiver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WebSocketReceiver").finish()
        }
    }

    /// Establish a websocket connection from the browser environment.
    ///
    /// # Errors
    ///
    /// Returns an error if the browser reports an error or the connection fails.
    pub async fn connect(uri: impl AsRef<str>) -> Result<WebSocket> {
        connect_with_config(uri, WebSocketConfig::default()).await
    }

    /// Establish a websocket connection from the browser environment using the provided config.
    ///
    /// # Errors
    ///
    /// Returns an error if the browser reports an error or the connection fails.
    pub async fn connect_with_config(
        uri: impl AsRef<str>,
        _config: WebSocketConfig,
    ) -> Result<WebSocket> {
        let socket = BrowserWebSocket::new(uri.as_ref())
            .map_err(|e| connection_failed(format_js_value(&e)))?;
        socket.set_binary_type(BinaryType::Arraybuffer);

        let (event_tx, event_rx) = mpsc::unbounded::<WsEvent>();
        let (ready_tx, ready_rx) = oneshot::channel::<core::result::Result<(), String>>();
        let pending = Rc::new(RefCell::new(Some(ready_tx)));

        let onopen_pending = Rc::clone(&pending);
        let on_open = Closure::wrap(Box::new(move || {
            if let Some(sender) = onopen_pending.borrow_mut().take() {
                let _ = sender.send(Ok(()));
            }
        }) as Box<dyn FnMut()>);
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        let on_message_tx = event_tx.clone();
        let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = event.data();
            if let Some(text) = data.as_string() {
                let _ =
                    on_message_tx.unbounded_send(WsEvent::Message(WebSocketMessage::from(text)));
                return;
            }

            if let Ok(array) = data.clone().dyn_into::<js_sys::ArrayBuffer>() {
                let view = js_sys::Uint8Array::new(&array);
                let mut bytes = vec![0; view.length() as usize];
                view.copy_to(&mut bytes[..]);
                let _ =
                    on_message_tx.unbounded_send(WsEvent::Message(WebSocketMessage::from(bytes)));
                return;
            }

            if let Ok(view) = data.dyn_into::<js_sys::Uint8Array>() {
                let mut bytes = vec![0; view.length() as usize];
                view.copy_to(&mut bytes[..]);
                let _ =
                    on_message_tx.unbounded_send(WsEvent::Message(WebSocketMessage::from(bytes)));
                return;
            }

            let _ = on_message_tx.unbounded_send(WsEvent::Error(
                "Unsupported websocket message type".to_string(),
            ));
        }) as Box<dyn FnMut(MessageEvent)>);
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let on_error_pending = Rc::clone(&pending);
        let on_error_tx = event_tx.clone();
        let on_error = Closure::wrap(Box::new(move |event: ErrorEvent| {
            let message = event.message();
            if let Some(sender) = on_error_pending.borrow_mut().take() {
                let _ = sender.send(Err(message.clone()));
            }
            let _ = on_error_tx.unbounded_send(WsEvent::Error(message));
        }) as Box<dyn FnMut(ErrorEvent)>);
        socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        let on_close_pending = Rc::clone(&pending);
        let on_close_tx = event_tx.clone();
        let on_close = Closure::wrap(Box::new(move |event: CloseEvent| {
            if let Some(sender) = on_close_pending.borrow_mut().take() {
                let reason = event.reason();
                let message = if reason.is_empty() {
                    format!("Connection closed (code {})", event.code())
                } else {
                    reason
                };
                let _ = sender.send(Err(message));
            }
            let _ = on_close_tx.unbounded_send(WsEvent::Closed);
        }) as Box<dyn FnMut(CloseEvent)>);
        socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        match ready_rx.await {
            Ok(Ok(())) => {
                socket.set_onopen(None);
                drop(on_open);
            }
            Ok(Err(message)) => {
                return Err(connection_failed(message));
            }
            Err(_) => {
                return Err(connection_failed("WebSocket connection cancelled"));
            }
        }

        let shared = Arc::new(SharedSocket {
            socket,
            receiver: Mutex::new(event_rx),
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
        });

        Ok(WebSocket {
            sender: WebSocketSender {
                inner: Arc::clone(&shared),
            },
            receiver: WebSocketReceiver { inner: shared },
        })
    }

    impl WebSocket {
        /// Send a websocket message serialized as JSON.
        ///
        /// # Errors
        ///
        /// Returns an error if serialization fails or the browser cannot queue the frame.
        pub async fn send<T>(&self, value: T) -> Result<()>
        where
            T: serde::Serialize,
        {
            let payload = serialize_payload(&value)?;
            self.send_text(payload).await
        }

        /// Send a text websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser fails to queue the frame.
        pub async fn send_text(&self, text: impl Into<String>) -> Result<()> {
            self.sender.send_text(text).await
        }

        /// Send a binary websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser fails to queue the frame.
        pub async fn send_binary(&self, bytes: impl Into<Bytes>) -> Result<()> {
            self.sender.send_binary(bytes).await
        }

        /// Receive the next websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the websocket reports an error event.
        pub async fn recv(&self) -> Result<Option<WebSocketMessage>> {
            self.receiver.recv().await
        }

        /// Close the websocket connection gracefully.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser refuses to close the socket.
        pub async fn close(self) -> Result<()> {
            self.sender.close().await
        }

        /// Split the websocket into sending and receiving halves.
        #[must_use]
        pub fn split(self) -> (WebSocketSender, WebSocketReceiver) {
            (self.sender, self.receiver)
        }
    }

    impl WebSocketSender {
        /// Send a websocket message serialized as JSON.
        ///
        /// # Errors
        ///
        /// Returns an error if serialization fails or the browser cannot queue the frame.
        pub async fn send<T>(&self, value: T) -> Result<()>
        where
            T: serde::Serialize,
        {
            let payload = serialize_payload(&value)?;
            self.send_text(payload).await
        }

        /// Send a text websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser fails to queue the frame.
        pub async fn send_text(&self, text: impl Into<String>) -> Result<()> {
            self.send_message(WebSocketMessage::text(text)).await
        }

        /// Send a binary websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser fails to queue the frame.
        pub async fn send_binary(&self, bytes: impl Into<Bytes>) -> Result<()> {
            self.send_message(WebSocketMessage::binary(bytes)).await
        }

        async fn send_message(&self, message: WebSocketMessage) -> Result<()> {
            match message {
                WebSocketMessage::Text(text) => self
                    .inner
                    .socket
                    .send_with_str(&text)
                    .map_err(|e| connection_failed(format_js_value(&e)))?,
                WebSocketMessage::Binary(bytes) => self
                    .inner
                    .socket
                    .send_with_u8_array(&bytes)
                    .map_err(|e| connection_failed(format_js_value(&e)))?,
            }
            Ok(())
        }

        /// Close the websocket connection gracefully.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser refuses to close the socket.
        pub async fn close(&self) -> Result<()> {
            self.inner
                .socket
                .close()
                .map_err(|e| connection_failed(format_js_value(&e)))
        }
    }

    impl WebSocketReceiver {
        /// Receive the next websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the websocket reports an error event.
        pub async fn recv(&self) -> Result<Option<WebSocketMessage>> {
            let mut receiver = self.inner.receiver.lock().await;
            match receiver.next().await {
                Some(WsEvent::Message(message)) => Ok(Some(message)),
                Some(WsEvent::Closed) | None => Ok(None),
                Some(WsEvent::Error(message)) => Err(connection_failed(message)),
            }
        }
    }

    fn connection_failed(message: impl Into<String>) -> WebSocketError {
        WebSocketError::ConnectionFailed(Box::new(io::Error::new(
            io::ErrorKind::Other,
            message.into(),
        )))
    }

    fn format_js_value(value: &JsValue) -> String {
        value.as_string().unwrap_or_else(|| format!("{value:?}"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{WebSocket, WebSocketReceiver, WebSocketSender, connect, connect_with_config};

#[cfg(target_arch = "wasm32")]
pub use wasm::{WebSocket, WebSocketReceiver, WebSocketSender, connect, connect_with_config};
