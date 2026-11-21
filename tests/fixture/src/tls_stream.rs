//! The futures-io rustls adapter the fixtures drive: the thin slice of
//! `futures-rustls` the test servers and test-side clients use, written in
//! tree so the crate does not resolve into the parent's dev-dependency graph
//! (a resolved-but-inactive copy there reads as an unused dependency under
//! `cargo::unused_dependencies`).

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

/// A rustls session over a futures-io byte stream, client or server side.
pub struct TlsStream<S> {
    io: S,
    conn: Connection,
}

impl<S> TlsStream<S> {
    /// The inner stream and the rustls session, as `futures-rustls` exposes
    /// them through `get_ref`.
    pub fn get_ref(&self) -> (&S, &Connection) {
        (&self.io, &self.conn)
    }
}

impl<S> Unpin for TlsStream<S> {}

/// `AsyncRead`/`AsyncWrite` presented to rustls's synchronous IO hooks: a
/// pending poll surfaces as `WouldBlock`, which the drive loops above turn
/// back into `Poll::Pending`.
struct Sync<'a, 'b, T>(&'a mut T, &'a mut Context<'b>);

impl<T: AsyncRead + Unpin> Read for Sync<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.0).poll_read(self.1, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for Sync<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.0).poll_write(self.1, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.0).poll_flush(self.1) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

fn tls_error(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Pull ciphertext in until the peer stalls, then fold it into the session.
fn drive_in<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    conn: &mut Connection,
    cx: &mut Context<'_>,
) -> io::Result<bool> {
    let mut progressed = false;
    while conn.wants_read() {
        match conn.read_tls(&mut Sync(io, cx)) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(_) => {
                conn.process_new_packets().map_err(tls_error)?;
                progressed = true;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(progressed)
}

/// Push every TLS record the session has queued.
fn drive_out<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    conn: &mut Connection,
    cx: &mut Context<'_>,
) -> io::Result<bool> {
    let mut progressed = false;
    while conn.wants_write() {
        match conn.write_tls(&mut Sync(io, cx)) {
            Ok(_) => progressed = true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(progressed)
}

fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    conn: &mut Connection,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    loop {
        let wrote = drive_out(io, conn, cx)?;
        let read = drive_in(io, conn, cx)?;
        if !conn.is_handshaking() {
            return Poll::Ready(Ok(()));
        }
        if !wrote && !read {
            return Poll::Pending;
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            match this.conn.reader().read(buf) {
                Ok(0) => {}
                r => return Poll::Ready(r),
            }
            if this.conn.is_handshaking() {
                match handshake(&mut this.io, &mut this.conn, cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            drive_out(&mut this.io, &mut this.conn, cx)?;
            match this.conn.read_tls(&mut Sync(&mut this.io, cx)) {
                Ok(0) => return Poll::Ready(Ok(0)),
                Ok(_) => {
                    this.conn.process_new_packets().map_err(tls_error)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let wrote = this.conn.writer().write(buf)?;
        match drive_out(&mut this.io, &mut this.conn, cx) {
            Ok(_) => Poll::Ready(Ok(wrote)),
            // The plaintext is already in the session's outgoing queue: the
            // record lands on the next drive, so the write still counts.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Ready(Ok(wrote)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.conn.wants_write() {
            match this.conn.write_tls(&mut Sync(&mut this.io, cx)) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.conn.send_close_notify();
        while this.conn.wants_write() {
            match this.conn.write_tls(&mut Sync(&mut this.io, cx)) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut this.io).poll_close(cx)
    }
}

/// Accepts TLS sessions on a futures-io stream, built from an `Arc`-shared
/// server config (`TlsAcceptor::from(arc)`).
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

impl TlsAcceptor {
    pub async fn accept<S>(&self, mut io: S) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn =
            Connection::Server(ServerConnection::new(Arc::clone(&self.config)).map_err(tls_error)?);
        std::future::poll_fn(|cx| handshake(&mut io, &mut conn, cx)).await?;
        Ok(TlsStream { io, conn })
    }
}

/// Opens TLS sessions on a futures-io stream, built from an `Arc`-shared
/// client config (`TlsConnector::from(arc)`).
#[derive(Clone)]
pub struct TlsConnector {
    config: Arc<ClientConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl TlsConnector {
    pub async fn connect<S>(
        &self,
        domain: ServerName<'static>,
        mut io: S,
    ) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn = Connection::Client(
            ClientConnection::new(Arc::clone(&self.config), domain).map_err(tls_error)?,
        );
        std::future::poll_fn(|cx| handshake(&mut io, &mut conn, cx)).await?;
        Ok(TlsStream { io, conn })
    }
}
