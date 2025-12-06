//! A simple WebSocket echo client example.

use zenwave::websocket::{self, WebSocketMessage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    async_io::block_on(async {
        // Public echo servers are great for demos.
        let socket = websocket::connect("wss://echo.websocket.events").await?;

        socket.send_text("hello from zenwave").await?;

        if let Some(message) = socket.recv().await? {
            match message {
                WebSocketMessage::Text(text) => println!("Received text: {text}"),
                WebSocketMessage::Binary(bytes) => println!("Received {} bytes", bytes.len()),
            }
        } else {
            println!("Server closed the connection");
        }

        socket.close().await?;
        Ok(())
    })
}
