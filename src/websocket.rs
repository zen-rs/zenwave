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
impl From<WebSocketMessage> for async_tungstenite::tungstenite::Message {
    fn from(value: WebSocketMessage) -> Self {
        match value {
            WebSocketMessage::Text(text) => Self::Text(unsafe {
                use async_tungstenite::tungstenite::Utf8Bytes;

                Utf8Bytes::from_bytes_unchecked(text.into_bytes())
            }),
            WebSocketMessage::Binary(bytes) => Self::Binary(bytes),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use async_tungstenite::{WebSocketStream, tungstenite::Message as TungsteniteMessage};
    use futures_util::StreamExt;
    use http_kit::utils::{ByteStr, Bytes};
    use url::Url;

    use super::{WebSocketError, WebSocketMessage, serialize_payload};

    type NativeSocket = WebSocketStream<async_tungstenite::async_std::ConnectStream>;

    /// A websocket connection backed by async-io + Tungstenite.
    pub struct WebSocket {
        inner: NativeSocket,
    }

    impl core::fmt::Debug for WebSocket {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("WebSocket").finish()
        }
    }

    /// Establish a websocket connection to the provided URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is invalid or the connection attempt fails.
    pub async fn connect(uri: impl AsRef<str>) -> Result<WebSocket, WebSocketError> {
        let url = Url::parse(uri.as_ref())?;
        match url.scheme() {
            "ws" | "wss" => {}
            other => return Err(WebSocketError::UnsupportedScheme(other.to_string())),
        }
        let request: String = url.into();
        let (ws_stream, _) = async_tungstenite::async_std::connect_async(request)
            .await
            .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))?;

        Ok(WebSocket { inner: ws_stream })
    }

    impl WebSocket {
        /// Send a websocket message serialized as JSON.
        ///
        /// # Errors
        ///
        /// Returns an error if serialization fails or when the underlying socket cannot
        /// write the resulting frame.
        pub async fn send<T>(&mut self, value: T) -> Result<(), WebSocketError>
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
        pub async fn send_text(&mut self, text: impl Into<String>) -> Result<(), WebSocketError> {
            self.send_message(WebSocketMessage::text(text)).await
        }

        /// Send a binary websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot write the frame.
        pub async fn send_binary(&mut self, bytes: impl Into<Bytes>) -> Result<(), WebSocketError> {
            self.send_message(WebSocketMessage::binary(bytes)).await
        }

        async fn send_message(&mut self, message: WebSocketMessage) -> Result<(), WebSocketError> {
            self.inner
                .send(message.into())
                .await
                .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))
        }

        /// Receive the next websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error when the underlying socket cannot read the next frame.
        pub async fn recv(&mut self) -> Result<Option<WebSocketMessage>, WebSocketError> {
            while let Some(message) = self.inner.next().await {
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
                        self.inner
                            .send(TungsteniteMessage::Pong(payload))
                            .await
                            .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))?;
                    }
                    TungsteniteMessage::Pong(_) | TungsteniteMessage::Frame(_) => {}
                }
            }

            Ok(None)
        }

        /// Close the websocket connection gracefully.
        ///
        /// # Errors
        ///
        /// Returns an error when the close frame cannot be sent.
        pub async fn close(mut self) -> Result<(), WebSocketError> {
            self.inner
                .close(None)
                .await
                .map_err(|e| WebSocketError::ConnectionFailed(Box::new(e)))
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::{cell::RefCell, fmt, rc::Rc};

    use anyhow::anyhow;
    use futures_channel::{mpsc, oneshot};
    use futures_util::StreamExt;
    use http_kit::{Result, StatusCode};
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use web_sys::{
        BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket as BrowserWebSocket,
    };

    use super::{Error, WebSocketMessage, serialize_payload};

    enum WsEvent {
        Message(WebSocketMessage),
        Error(String),
        Closed,
    }

    /// Browser/wasm websocket connection backed by `web_sys`.
    pub struct WebSocket {
        socket: BrowserWebSocket,
        receiver: mpsc::UnboundedReceiver<WsEvent>,
        _on_message: Closure<dyn FnMut(MessageEvent)>,
        _on_error: Closure<dyn FnMut(ErrorEvent)>,
        _on_close: Closure<dyn FnMut(CloseEvent)>,
    }

    impl fmt::Debug for WebSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WebSocket")
                .field("ready_state", &self.socket.ready_state())
                .finish()
        }
    }

    /// Establish a websocket connection from the browser environment.
    ///
    /// # Errors
    ///
    /// Returns an error if the browser reports an error or the connection fails.
    pub async fn connect(uri: impl AsRef<str>) -> Result<WebSocket> {
        let socket = BrowserWebSocket::new(uri.as_ref())
            .map_err(|e| Error::new(anyhow!(format_js_value(&e)), StatusCode::BAD_REQUEST))?;
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
                    on_message_tx.unbounded_send(WsEvent::Message(WebSocketMessage::Text(text)));
                return;
            }

            if let Ok(array) = data.clone().dyn_into::<js_sys::ArrayBuffer>() {
                let view = js_sys::Uint8Array::new(&array);
                let mut bytes = vec![0; view.length() as usize];
                view.copy_to(&mut bytes[..]);
                let _ =
                    on_message_tx.unbounded_send(WsEvent::Message(WebSocketMessage::Binary(bytes)));
                return;
            }

            if let Ok(view) = data.dyn_into::<js_sys::Uint8Array>() {
                let mut bytes = vec![0; view.length() as usize];
                view.copy_to(&mut bytes[..]);
                let _ =
                    on_message_tx.unbounded_send(WsEvent::Message(WebSocketMessage::Binary(bytes)));
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
                return Err(Error::new(anyhow!(message), StatusCode::BAD_GATEWAY));
            }
            Err(_) => {
                return Err(Error::new(
                    anyhow!("WebSocket connection cancelled"),
                    StatusCode::BAD_GATEWAY,
                ));
            }
        }

        Ok(WebSocket {
            socket,
            receiver: event_rx,
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
        })
    }

    impl WebSocket {
        /// Send a websocket message serialized as JSON.
        ///
        /// # Errors
        ///
        /// Returns an error if serialization fails or the browser cannot queue the frame.
        pub async fn send<T>(&mut self, value: T) -> Result<()>
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
        pub async fn send_text(&mut self, text: impl Into<String>) -> Result<()> {
            self.send_message(WebSocketMessage::text(text)).await
        }

        /// Send a binary websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser fails to queue the frame.
        pub async fn send_binary(&mut self, bytes: impl Into<Bytes>) -> Result<()> {
            self.send_message(WebSocketMessage::binary(bytes)).await
        }

        async fn send_message(&mut self, message: WebSocketMessage) -> Result<()> {
            match message {
                WebSocketMessage::Text(text) => self.socket.send_with_str(&text).map_err(|e| {
                    Error::new(anyhow!(format_js_value(&e)), StatusCode::BAD_GATEWAY)
                })?,
                WebSocketMessage::Binary(bytes) => {
                    self.socket.send_with_u8_array(&bytes).map_err(|e| {
                        Error::new(anyhow!(format_js_value(&e)), StatusCode::BAD_GATEWAY)
                    })?
                }
            }
            Ok(())
        }

        /// Receive the next websocket message.
        ///
        /// # Errors
        ///
        /// Returns an error if the websocket reports an error event.
        pub async fn recv(&mut self) -> Result<Option<WebSocketMessage>> {
            match self.receiver.next().await {
                Some(WsEvent::Message(message)) => Ok(Some(message)),
                Some(WsEvent::Closed) | None => Ok(None),
                Some(WsEvent::Error(message)) => {
                    Err(Error::new(anyhow!(message), StatusCode::BAD_GATEWAY))
                }
            }
        }

        /// Close the websocket connection gracefully.
        ///
        /// # Errors
        ///
        /// Returns an error if the browser refuses to close the socket.
        pub async fn close(self) -> Result<()> {
            self.socket
                .close()
                .map_err(|e| Error::new(anyhow!(format_js_value(&e)), StatusCode::BAD_GATEWAY))
        }
    }

    fn format_js_value(value: &JsValue) -> String {
        value.as_string().unwrap_or_else(|| format!("{value:?}"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{WebSocket, connect};

#[cfg(target_arch = "wasm32")]
pub use wasm::{WebSocket, connect};
